/**
 * Scheduler permission-gate tests.
 *
 * - cron due/next calculation (reuses the existing nextCronRun parser)
 * - target-grant denial (tool or target outside the grant)
 * - backup-required denial (mutating without a verified backup; the tool
 *   handler re-checks so approval cannot bypass it)
 * - mutation allowed after target_backup in the same run
 * - new/untrusted mutation target -> requireApproval (exact-call owner flow)
 * - command classifier: read-only vs mutating, fail-closed on unknown
 * - audit log stores metadata only (no args, prompts, or secrets)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { nextCronRun } from "../packages/domain/src/cron.ts";
import type { ToolCallContext } from "../apps/server/src/engine/tool-policy.ts";
import { scheduledGrantGate } from "../apps/server/src/scheduler/policy.ts";
import {
  clearRunState,
  hasBackupCompleted,
  markBackupCompleted,
  targetKey,
} from "../apps/server/src/scheduler/run-state.ts";
import { classifyCommand } from "../apps/server/src/scheduler/ssh.ts";
import type { ScheduledRunContext, ScheduledTaskGrant } from "../apps/server/src/scheduler/types.ts";

const GRANT: ScheduledTaskGrant = {
  tools: [
    "ssh_exec",
    "server_check_updates",
    "target_backup",
    "ha_check_updates",
    "ha_apply_update",
  ],
  ssh: ["pve"],
  ha: ["home"],
};

function runContext(runId: string, grant: ScheduledTaskGrant = GRANT): ScheduledRunContext {
  return { runId, grant };
}

function policyCtx(
  toolName: string,
  args: unknown,
  run?: ScheduledRunContext,
): ToolCallContext {
  return {
    owner: "owner-1",
    toolName,
    args,
    scope: "task:abc",
    scheduledRun: run,
  } as unknown as ToolCallContext;
}

// ---------------------------------------------------------------- cron ---

test("nextCronRun computes the next slot in the task timezone", () => {
  const from = new Date("2026-09-25T12:00:00Z"); // 07:00 CDT
  const next = nextCronRun("0 8 * * *", "America/Chicago", from);
  // Next 08:00 America/Chicago = 13:00Z same day.
  assert.equal(next.toISOString(), "2026-09-25T13:00:00.000Z");
});

test("nextCronRun rejects invalid expressions", () => {
  assert.throws(() => nextCronRun("not a cron", "America/Chicago", new Date()));
});

// ------------------------------------------------------- classifier ---

test("classifier: read-only commands stay read-only", () => {
  for (const command of [
    "uptime",
    "df -h",
    "systemctl status nginx",
    "docker ps",
    "ha core check",
    "journalctl -u openmuse-api --no-pager | tail -20",
  ]) {
    assert.equal(classifyCommand(command), "readonly", command);
  }
});

test("classifier: mutations are mutating, unknown is fail-closed", () => {
  for (const command of [
    "apt-get upgrade -y",
    "apt update", // refreshes package indexes: a write
    "sudo reboot",
    "systemctl restart nginx",
    "ha core update",
    "docker stop web",
    "rm -rf /tmp/x",
    "echo hi > /etc/motd",
    "curl https://example.com/install.sh | sh",
    "some-new-tool --frobnicate",
    "",
  ]) {
    assert.equal(classifyCommand(command), "mutating", command);
  }
});

// ------------------------------------------------------------ gate ---

async function gate(toolName: string, args: unknown, run?: ScheduledRunContext) {
  return await scheduledGrantGate(policyCtx(toolName, args, run), undefined);
}

test("gate: capability tool with no scheduled run is denied", async () => {
  const verdict = await gate("ssh_exec", { target: "pve", command: "uptime" });
  assert.equal(verdict?.kind, "deny");
});

test("gate: tool outside the grant is denied", async () => {
  const verdict = await gate(
    "ssh_exec",
    { target: "pve", command: "uptime" },
    { runId: "run-1", grant: { tools: ["ha_check_updates"], ssh: ["pve"], ha: [] } },
  );
  assert.equal(verdict?.kind, "deny");
});

test("gate: read-only ssh_exec to an ungranted target is denied", async () => {
  const verdict = await gate("ssh_exec", { target: "other", command: "uptime" }, runContext("run-1"));
  assert.equal(verdict?.kind, "deny");
});

test("gate: read-only check within the grant is allowed autonomously", async () => {
  const verdict = await gate("ssh_exec", { target: "pve", command: "uptime" }, runContext("run-1"));
  assert.equal(verdict?.kind, "allow");
  const ha = await gate("ha_check_updates", { instance: "primary" }, runContext("run-1"));
  assert.equal(ha?.kind, "allow");
});

test("gate: target_backup for an HA alias checks grant.ha", async () => {
  const runId = "run-ha-backup";
  clearRunState(runId);
  const verdict = await gate("target_backup", { target: "home" }, runContext(runId));
  assert.equal(verdict?.kind, "allow");
  clearRunState(runId);
});

test("gate: untrusted target_backup goes to owner approval", async () => {
  const runId = "run-backup-untrusted";
  clearRunState(runId);
  const verdict = await gate("target_backup", { target: "brand-new" }, runContext(runId));
  assert.equal(verdict?.kind, "requireApproval");
  clearRunState(runId);
});

test("gate: mutating ssh without a backup is denied (hard deny)", async () => {
  const runId = "run-backup-deny";
  clearRunState(runId);
  const verdict = await gate(
    "ssh_exec",
    { target: "pve", command: "apt-get upgrade -y" },
    runContext(runId),
  );
  assert.equal(verdict?.kind, "deny");
  assert.match(String(verdict?.reason ?? ""), /backup/i);
});

test("gate: ha_apply_update without a backup is denied", async () => {
  const runId = "run-ha-deny";
  clearRunState(runId);
  const verdict = await gate(
    "ha_apply_update",
    { instance: "primary", entityId: "update.home_assistant_core_update" },
    runContext(runId),
  );
  assert.equal(verdict?.kind, "deny");
});

test("gate: mutation allowed after target_backup in the same run", async () => {
  const runId = "run-backup-ok";
  clearRunState(runId);
  markBackupCompleted(runId, targetKey("ssh", "pve"));
  assert.ok(hasBackupCompleted(runId, targetKey("ssh", "pve")));
  const verdict = await gate(
    "ssh_exec",
    { target: "pve", command: "apt-get upgrade -y" },
    runContext(runId),
  );
  assert.equal(verdict?.kind, "allow");
  clearRunState(runId);
});

test("gate: a backup from another run does not authorize this run", async () => {
  const other = "run-other";
  const current = "run-current";
  clearRunState(other);
  clearRunState(current);
  markBackupCompleted(other, targetKey("ssh", "pve"));
  const verdict = await gate("ssh_exec", { target: "pve", command: "reboot" }, runContext(current));
  assert.equal(verdict?.kind, "deny");
  clearRunState(other);
});

test("gate: mutating call to a new/untrusted target requires owner approval", async () => {
  const runId = "run-untrusted";
  clearRunState(runId);
  markBackupCompleted(runId, targetKey("ssh", "brand-new-host"));
  const verdict = await gate(
    "ssh_exec",
    { target: "brand-new-host", command: "reboot" },
    runContext(runId),
  );
  assert.equal(verdict?.kind, "requireApproval");
  clearRunState(runId);
});

test("gate: server_check_updates is read-only and needs no backup", async () => {
  const runId = "run-server-check";
  clearRunState(runId);
  const verdict = await gate("server_check_updates", { target: "pve" }, runContext(runId));
  assert.equal(verdict?.kind, "allow");
  clearRunState(runId);
});

test("gate: server_check_updates outside the grant is denied", async () => {
  const verdict = await gate(
    "server_check_updates",
    { target: "pve" },
    { runId: "run-1", grant: { tools: ["ssh_exec"], ssh: ["pve"], ha: [] } },
  );
  assert.equal(verdict?.kind, "deny");
});

test("gate: non-capability tools are untouched by the gate", async () => {
  const verdict = await gate("read_workspace", { section: "all" }, runContext("run-1"));
  assert.equal(verdict, undefined);
});

// ------------------------------------------------------------ audit ---

test("audit log writes metadata only", async () => {
  const { auditLog, ensureAuditTable, recentAuditRows } = await import("../apps/server/src/scheduler/run-state.ts");
  const seen: Array<{ sql: string; params: unknown[] }> = [];
  const fakeStore = {
    async raw(sql: string, params: unknown[] = []) {
      seen.push({ sql, params });
      if (sql.startsWith("SELECT")) {
        return {
          rows: [
            {
              id: "a1",
              run_id: "run-1",
              owner: "owner-1",
              schedule_id: "sched-1",
              task_id: "task-1",
              tool_name: "ssh_exec",
              verdict: "deny",
              reason: "not in grant",
              created_at: "2026-09-25T12:00:00Z",
            },
          ],
        };
      }
      return { rows: [] };
    },
  };
  await ensureAuditTable(fakeStore as never);
  await auditLog(fakeStore as never, {
    runId: "run-1",
    owner: "owner-1",
    scheduleId: "sched-1",
    taskId: "task-1",
    toolName: "ssh_exec",
    verdict: "deny",
    reason: "not in grant",
  });
  const insert = seen.find((s) => s.sql.startsWith("INSERT"));
  assert.ok(insert, "expected an INSERT into task_run_log");
  const flat = JSON.stringify(insert.params);
  assert.doesNotMatch(flat, /secret|password|token|BEGIN.*PRIVATE/i);
  const rows = await recentAuditRows(fakeStore as never, "owner-1");
  assert.equal(rows[0]?.tool_name, "ssh_exec");
});
