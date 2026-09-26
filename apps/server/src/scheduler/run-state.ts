/**
 * Run-scoped permission-gate state + the audit log.
 *
 * Backup-before-update is enforced as run-scoped state: a mutating tool
 * (ha_apply_update, or an ssh_exec command classified as mutating) is denied
 * unless target_backup succeeded for the same target earlier in the SAME
 * run. State lives in server memory keyed by the run id minted per
 * executeModelTask invocation, so a backup from a previous scheduled run can
 * never authorize this run's update. Entries are pruned after 24h.
 *
 * The audit log (task_run_log table) records every scheduled run and every
 * tool-call verdict. It never stores args, prompts, keys, tokens, or
 * passwords — only tool names, verdicts, and short reasons.
 */
import type { Store } from "../db.ts";
import type { AuditVerdict } from "./types.ts";

interface RunGateState {
  backups: Set<string>;
  createdAt: number;
}

const RUN_STATE_TTL_MS = 24 * 60 * 60 * 1000;
const runStates = new Map<string, RunGateState>();

function pruneRunStates(): void {
  const cutoff = Date.now() - RUN_STATE_TTL_MS;
  for (const [runId, state] of runStates) {
    if (state.createdAt < cutoff) runStates.delete(runId);
  }
}

/** Target key, e.g. "ssh:pve" or "ha:home-assistant". */
export function targetKey(kind: "ssh" | "ha", alias: string): string {
  return `${kind}:${alias}`;
}

/** Record a successful backup for this run + target. Called by target_backup. */
export function markBackupCompleted(runId: string, key: string): void {
  pruneRunStates();
  let state = runStates.get(runId);
  if (!state) {
    state = { backups: new Set(), createdAt: Date.now() };
    runStates.set(runId, state);
  }
  state.backups.add(key);
}

/** True when target_backup succeeded for this run + target. */
export function hasBackupCompleted(runId: string, key: string): boolean {
  pruneRunStates();
  return runStates.get(runId)?.backups.has(key) ?? false;
}

/** Drop a run's gate state (best-effort cleanup at run end). */
export function clearRunState(runId: string): void {
  runStates.delete(runId);
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

export async function ensureAuditTable(store: Store): Promise<void> {
  await store.raw(`CREATE TABLE IF NOT EXISTS task_run_log(
    id text PRIMARY KEY,
    run_id text NOT NULL,
    owner text NOT NULL,
    schedule_id text,
    task_id text,
    tool_name text,
    target_alias text,
    verdict text,
    reason text,
    created_at timestamptz NOT NULL DEFAULT now()
  )`);
  await store.raw(
    `CREATE INDEX IF NOT EXISTS task_run_log_run_idx ON task_run_log(run_id, created_at)`,
  );
  await store.raw(
    `ALTER TABLE task_run_log ADD COLUMN IF NOT EXISTS target_alias text`,
  );
}

export interface AuditEntry {
  runId: string;
  owner: string;
  scheduleId?: string;
  taskId?: string;
  /** Undefined for run start/finish entries. */
  toolName?: string;
  /** Target alias only (never hostnames, args, or secrets). */
  targetAlias?: string;
  /** "started" | "finished" for run entries, otherwise the policy verdict. */
  verdict: AuditVerdict | "started" | "finished";
  reason?: string;
}

function shortReason(reason: string | undefined): string | null {
  if (!reason) return null;
  return reason.slice(0, 500);
}

/** Never logs args, prompts, keys, tokens, or passwords. */
export async function auditLog(
  store: Store,
  entry: AuditEntry,
): Promise<void> {
  const { randomUUID } = await import("node:crypto");
  await store.raw(
    `INSERT INTO task_run_log(id, run_id, owner, schedule_id, task_id, tool_name, target_alias, verdict, reason)
     VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      randomUUID(),
      entry.runId,
      entry.owner,
      entry.scheduleId ?? null,
      entry.taskId ?? null,
      entry.toolName ?? null,
      entry.targetAlias ?? null,
      entry.verdict,
      shortReason(entry.reason),
    ],
  );
}

export interface AuditRow {
  id: string;
  run_id: string;
  owner: string;
  schedule_id: string | null;
  task_id: string | null;
  tool_name: string | null;
  target_alias: string | null;
  verdict: string;
  reason: string | null;
  created_at: string;
}

export async function recentAuditRows(
  store: Store,
  owner: string,
  limit = 100,
): Promise<AuditRow[]> {
  const result = await store.raw<AuditRow>(
    `SELECT id, run_id, owner, schedule_id, task_id, tool_name, target_alias, verdict, reason,
            created_at::text AS created_at
     FROM task_run_log WHERE owner=$1 ORDER BY created_at DESC LIMIT $2`,
    [owner, limit],
  );
  return result.rows;
}
