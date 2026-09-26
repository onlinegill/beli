# Scheduled AI Tasks — Design

Owner requirements: reminders + scheduled AI tasks; the agent can check/update
registered SSH servers and multiple Home Assistant instances; every AI action
is permission-gated; updates/mutations require a successful backup first; the
owner can securely save SSH usernames/passwords, SSH keys, and Home Assistant
credentials.

## What already existed (reused, not reinvented)

- `packages/domain/src/cron.ts` — dependency-free 5-field cron parser with
  IANA timezone support (`nextCronRun`). Reused for due/next calculations.
- `AgentService.createSchedule` / `TaskWorker` / `runSchedule` /
  `executeModelTask` — the existing scheduled/delegated execution path.
  Scheduled tasks run as `AgentTask` records through the same worker, lease,
  checkpoint, and notification machinery as delegated tasks.
- `apps/server/src/engine/tool-policy.ts` — the fixed five-stage policy
  chain (loop admission → deterministic trusted policies → owner approvals →
  narrowing hooks → final owner approval). Unknown tools are denied by
  default; approvals hash-pin the exact tool call.
- `packages/integrations/src/vault.ts` — AES-256-GCM envelope encryption.
  Reused for target credentials.

## New tables (raw SQL via `Store.raw`)

`scheduled_tasks` — the owner-facing store, owned by `SchedulerService`:

| column | notes |
|---|---|
| id, owner, name | identity |
| kind | `'agent'` (worker runs the prompt) or `'reminder'` (notify only) |
| cron | 5-field cron; null for one-shots |
| prompt | agent instruction, or the reminder message |
| enabled, status | status: `active` / `paused` / `fired` (one-shot consumed) |
| timezone | IANA name, default America/Chicago |
| created_by | `chat` / `api` |
| last_run_at, next_run_at, run_count | bookkeeping; `next_run_at` from `nextCronRun` |
| allowed_tools | JSON array; subset of `ssh_exec`, `ha_check_updates`, `ha_apply_update`, `target_backup` |
| allowed_targets | JSON `{ssh: string[], ha: string[]}` — registered aliases only |
| one_shot, run_at | one-shot agent run or reminder at an exact time |

`task_run_log` — audit of every scheduled run and tool-call verdict:

| column | notes |
|---|---|
| id, run_id, owner, schedule_id, task_id | correlation |
| tool_name | null for run start/finish entries |
| verdict | `started` / `finished` / `allow` / `deny` / `requireApproval` |
| reason | short human reason (≤500 chars) |
| created_at | |

The audit log NEVER stores commands, arguments, prompts, tokens,
passwords, key material, or secret-bearing responses — only tool names,
target aliases, verdicts, and short reasons.

## Target registry (`scheduler/targets.ts`)

Owner-registered aliases for SSH hosts and Home Assistant instances,
stored as plain records (`scheduler-targets`). No secrets, ever:
- SSH: host, port, username hint, `keyPath` (absolute path to an
  owner-managed 0600 key file), and `backupCommand`.
- Home Assistant: `baseUrl` only.
- Registration validates alias shape, host characters, and key-file
  existence/readability at write time.

## Credential store (`scheduler/credentials.ts`)

- Saved via `POST /api/target-credentials` (admin-only) or replaced there;
  listed (metadata only) and deleted via API or chat tools.
- Plaintext is AES-256-GCM encrypted before it touches the database.
  The master key (`TOKEN_ENCRYPTION_KEY`) lives in `/root/openmuse/.env`
  (0600, outside the repo) and never enters the DB, logs, or tool results.
- The agent and tools only ever see the ALIAS. Plaintext is decrypted in
  memory only inside the final SSH/HA operation (`useSecrets`), used once,
  and wiped in a `finally` block.
- There is deliberately NO chat tool that accepts a secret:
  `target_credential_setup` only explains the secure owner-only API flow.
  Passwords/tokens must never pass through the model.

## SSH execution (`scheduler/ssh.ts`)

- Key auth is preferred when the target configures `keyPath`; otherwise the
  stored password is used via an `SSH_ASKPASS` helper: a 0600 temp script
  that prints a process-only env var, deleted immediately after spawn. The
  password never appears in argv, logs, or tool results.
- SSH is spawned with an argument array (`/usr/bin/ssh … -- <command>`);
  no shell-built local command line. `BatchMode=yes` for key auth only
  (it would suppress the askpass helper on the password path).
- Host keys: `StrictHostKeyChecking=accept-new` (TOFU on first scheduled
  run; the owner registered the host explicitly).

## Command classification (`scheduler/ssh.ts`)

Deterministic and fail-closed: anything not recognizably read-only is
`mutating`. Package upgrades (`apt install/upgrade…`), reboots, service
start/stop/restart/enable, `ha core update`, `docker run/rm/stop`,
`rm/mv/cp/chmod`, redirects (`>`/`>>`), `curl`/`wget`, etc. are mutating.
Recognized read-only shapes (`apt update`, `systemctl status`,
`docker ps`, `ha core check`, …) stay read-only.

## Capability tools (`scheduler/worker-tools.ts`, `scheduler/capabilities.ts`)

Registered in `executeModelTask` ONLY when the run carries a scheduled-task
grant (`opts.scheduled`). Worker-only — they are never chat tools.

- `ssh_exec {target, command, timeoutMs?}` — run a command on a registered
  SSH alias. Returns a bounded, redacted summary.
- `target_backup {target}` — performs AND verifies a backup, then marks
  the run+target as backed up. SSH: runs the owner-configured
  `backupCommand` (must be read-only from this host's view — it points at a
  host-side script whose exit code IS the verification; the agent cannot
  self-assert). Home Assistant: creates a full Supervisor backup via the HA
  API and polls until it appears in the backup list.
- `ha_check_updates {instance}` — read-only: list `update.*` entities.
- `ha_apply_update {instance, entityId}` — installs one update via
  `update.install`.

Tool handlers re-check the backup gate unconditionally, so even an
owner-approved exact call can never run a mutation without a verified
backup in the same run.

## Permission gate (`scheduler/policy.ts` → `scheduledGrantGate`)

A new deterministic policy stage inserted right after `loopAdmission`
(stage 1); the existing five stages keep their relative order.
`trustedPolicies` abstains for capability tools (the gate already decided);
later stages may still narrow via hooks.

Per tool call:

1. No scheduled run context → DENY (capability tools never run in chat or
   ad-hoc delegated tasks).
2. Tool not in `grant.tools` → DENY.
3. Target alias missing → DENY.
4. Target not in `grant.ssh`/`grant.ha`:
   - mutating → `requireApproval` (new/untrusted target goes through the
     existing exact-call owner-approval flow; the handler still enforces
     the backup gate);
   - read-only → DENY.
5. Mutating without a verified backup for that target in this run → DENY.
   Hard deny — owner approval cannot bypass a missing backup.
6. Otherwise → ALLOW (read-only checks run autonomously within grants;
   in-grant mutations run after their backup).

Run-scoped state: the grant travels `scheduled_tasks` row →
`AgentService.runCapabilityScheduledTask` → `executeModelTask(...,
{scheduled: {runId, grant}})` → policy context `scheduledRun`. Backup
completions live in server memory keyed by `runId` (minted per firing, TTL
24h, cleared at run end) — a backup from a previous run can never
authorize this run's update.

## Reminders

`scheduler/service.ts` ticks every 30s. Due `reminder` rows are delivered
directly — in-app notification (`agent.notify`, deduped by key) plus a
Telegram message when the bot is configured — then marked `fired`. No
agent run, no tool calls. Due `agent` rows get an idempotent-per-slot
`AgentTask` so the existing `TaskWorker` executes them.

## API (all under `/api/*`, dashboard-authenticated)

- `GET/POST /api/scheduler-targets`, `PATCH/DELETE /api/scheduler-targets/:alias` — admin only
- `GET/POST /api/target-credentials`, `DELETE /api/target-credentials/:id` — admin only, metadata-only responses
- `GET/POST /api/scheduled-tasks`, `GET /api/scheduled-tasks/:id`, `POST .../:id/pause|resume`, `DELETE .../:id` — owner-scoped
- `GET /api/scheduled-tasks-runs?limit=` — audit rows, owner-scoped

## Chat tools (owner chat)

`scheduler_target_register/update/delete/list`, `target_credential_setup`
(instructions only — never collects secrets), `target_credential_list`,
`target_credential_delete`, `scheduled_task_create/list/control/detail`,
`scheduled_task_runs`. Read-only ones are policy allow-listed; config ones
are standard tools like `create_goal`. There is no chat path for submitting
secrets.

## Secret flow (summary)

Owner → admin API (`POST /api/target-credentials`) → AES-256-GCM encrypt
(master key in 0600 `.env`, outside repo) → DB stores ciphertext only →
agent sees alias → tool decrypts in memory inside the final SSH/HA call →
wiped in `finally`. Plaintext never appears in chat, tool results, logs,
the audit table, or API responses.

## Tests (`apps/server/test/scheduler.test.ts`)

- cron due/next calculation via `nextCronRun`
- target-grant denial (tool/target outside grant)
- backup-required denial (mutating without backup; approval cannot bypass — handler re-check)
- mutation allowed after `target_backup` in the same run
- new/untrusted mutation target → `requireApproval`
- command classifier: read-only vs mutating shapes, fail-closed on unknown
- audit log writes metadata only
