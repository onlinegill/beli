/**
 * The scheduled_tasks table: the owner-facing store for scheduled AI tasks
 * and reminders. The SchedulerService (service.ts) owns this table; the
 * TaskWorker executes due rows through the normal agent-task machinery with
 * the row's grant injected into the policy context.
 */
import { randomUUID } from "node:crypto";
import { nextCronRun } from "../../../../packages/domain/src/cron.ts";
import type { Store } from "../db.ts";
import { AppError } from "../errors.ts";
import type { ScheduledTaskGrant } from "./types.ts";
import { CAPABILITY_TOOL_SET } from "./types.ts";

export type ScheduledTaskKind = "agent" | "reminder";

export interface ScheduledTaskRow {
  id: string;
  owner: string;
  name: string;
  kind: ScheduledTaskKind;
  cron: string | null;
  prompt: string;
  enabled: boolean;
  timezone: string;
  createdBy: string;
  lastRunAt: string | null;
  nextRunAt: string | null;
  runCount: number;
  allowedTools: string[];
  allowedTargets: { ssh: string[]; ha: string[] };
  oneShot: boolean;
  runAt: string | null;
  /** active | paused | fired (one-shot consumed) */
  status: string;
}

export async function ensureScheduledTasksTable(store: Store): Promise<void> {
  await store.raw(`CREATE TABLE IF NOT EXISTS scheduled_tasks(
    id text PRIMARY KEY,
    owner text NOT NULL,
    name text NOT NULL,
    kind text NOT NULL DEFAULT 'agent',
    cron text,
    prompt text NOT NULL DEFAULT '',
    enabled boolean NOT NULL DEFAULT true,
    timezone text NOT NULL DEFAULT 'America/Chicago',
    created_by text NOT NULL DEFAULT '',
    last_run_at timestamptz,
    next_run_at timestamptz,
    run_count integer NOT NULL DEFAULT 0,
    allowed_tools jsonb NOT NULL DEFAULT '[]',
    allowed_targets jsonb NOT NULL DEFAULT '{"ssh":[],"ha":[]}',
    one_shot boolean NOT NULL DEFAULT false,
    run_at timestamptz,
    status text NOT NULL DEFAULT 'active'
  )`);
  await store.raw(
    `CREATE INDEX IF NOT EXISTS scheduled_tasks_due_idx
     ON scheduled_tasks(owner, status, next_run_at) WHERE status = 'active'`,
  );
  await store.raw(
    `CREATE INDEX IF NOT EXISTS scheduled_tasks_oneshot_idx
     ON scheduled_tasks(owner, status, run_at) WHERE one_shot = true AND status = 'active'`,
  );
}

function toRow(raw: Record<string, unknown>): ScheduledTaskRow {
  return {
    id: String(raw.id),
    owner: String(raw.owner),
    name: String(raw.name),
    kind: raw.kind === "reminder" ? "reminder" : "agent",
    cron: raw.cron == null ? null : String(raw.cron),
    prompt: String(raw.prompt ?? ""),
    enabled: raw.enabled === true,
    timezone: String(raw.timezone ?? "America/Chicago"),
    createdBy: String(raw.created_by ?? ""),
    lastRunAt: raw.last_run_at == null ? null : new Date(String(raw.last_run_at)).toISOString(),
    nextRunAt: raw.next_run_at == null ? null : new Date(String(raw.next_run_at)).toISOString(),
    runCount: Number(raw.run_count ?? 0),
    allowedTools: Array.isArray(raw.allowed_tools)
      ? (raw.allowed_tools as unknown[]).map(String)
      : JSON.parse(String(raw.allowed_tools ?? "[]")) as string[],
    allowedTargets: (() => {
      const parsed =
        typeof raw.allowed_targets === "string"
          ? (JSON.parse(raw.allowed_targets) as { ssh?: unknown; ha?: unknown })
          : ((raw.allowed_targets as { ssh?: unknown; ha?: unknown } | null) ?? {});
      return {
        ssh: Array.isArray(parsed.ssh) ? parsed.ssh.map(String) : [],
        ha: Array.isArray(parsed.ha) ? parsed.ha.map(String) : [],
      };
    })(),
    oneShot: raw.one_shot === true,
    runAt: raw.run_at == null ? null : new Date(String(raw.run_at)).toISOString(),
    status: String(raw.status ?? "active"),
  };
}

export interface CreateScheduledTaskInput {
  name: string;
  kind?: ScheduledTaskKind;
  /** Required for kind=agent with oneShot=false. */
  cron?: string;
  prompt: string;
  timezone?: string;
  createdBy?: string;
  allowedTools?: string[];
  allowedTargets?: { ssh?: string[]; ha?: string[] };
  /** One-shot agent run or reminder at an exact time (ISO). */
  runAt?: string;
}

const ALIAS_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

function validateGrantTools(tools: string[]): void {
  for (const tool of tools) {
    if (!CAPABILITY_TOOL_SET.has(tool))
      throw new AppError(
        `Unknown capability tool "${tool}". Allowed: ${[...CAPABILITY_TOOL_SET].join(", ")}.`,
        422,
      );
  }
}

function validateAliases(aliases: string[], label: string): void {
  for (const alias of aliases) {
    if (!ALIAS_RE.test(alias))
      throw new AppError(`Invalid ${label} target alias "${alias}".`, 422);
  }
}

export function grantOf(row: ScheduledTaskRow): ScheduledTaskGrant {
  return {
    tools: [...row.allowedTools],
    ssh: [...row.allowedTargets.ssh],
    ha: [...row.allowedTargets.ha],
  };
}

export async function createScheduledTask(
  store: Store,
  owner: string,
  input: CreateScheduledTaskInput,
): Promise<ScheduledTaskRow> {
  const name = input.name.trim();
  if (!name || name.length > 160) throw new AppError("Name is required (max 160 chars).", 422);
  const kind: ScheduledTaskKind = input.kind === "reminder" ? "reminder" : "agent";
  const timezone = (input.timezone ?? "America/Chicago").trim() || "America/Chicago";
  const allowedTools = [...new Set(input.allowedTools ?? [])];
  const allowedTargets = {
    ssh: [...new Set(input.allowedTargets?.ssh ?? [])],
    ha: [...new Set(input.allowedTargets?.ha ?? [])],
  };
  validateGrantTools(allowedTools);
  validateAliases(allowedTargets.ssh, "SSH");
  validateAliases(allowedTargets.ha, "Home Assistant");

  let cron: string | null = null;
  let nextRunAt: string | null = null;
  let runAt: string | null = null;
  let oneShot = false;
  const now = new Date();

  if (input.runAt) {
    oneShot = true;
    const at = new Date(input.runAt);
    if (Number.isNaN(at.getTime())) throw new AppError("runAt must be a valid ISO timestamp.", 422);
    if (at.getTime() <= now.getTime() - 60000)
      throw new AppError("runAt must be in the future.", 422);
    runAt = at.toISOString();
    if (kind === "reminder" && !input.prompt.trim())
      throw new AppError("Reminders need a message.", 422);
  } else {
    if (kind === "reminder") throw new AppError("Reminders need runAt (an exact time).", 422);
    if (!input.cron?.trim()) throw new AppError("Cron expression is required.", 422);
    cron = input.cron.trim();
    try {
      nextRunAt = nextCronRun(cron, timezone, now).toISOString();
    } catch (error) {
      throw new AppError(
        `Invalid cron/timezone: ${error instanceof Error ? error.message : String(error)}`,
        422,
      );
    }
  }
  if (kind === "agent" && !input.prompt.trim())
    throw new AppError("Agent tasks need a prompt.", 422);

  const id = randomUUID();
  await store.raw(
    `INSERT INTO scheduled_tasks(
       id, owner, name, kind, cron, prompt, enabled, timezone, created_by,
       next_run_at, run_count, allowed_tools, allowed_targets,
       one_shot, run_at, status
     ) VALUES($1,$2,$3,$4,$5,$6,true,$7,$8,$9,0,$10,$11,$12,$13,'active')`,
    [
      id,
      owner,
      name,
      kind,
      cron,
      input.prompt,
      timezone,
      input.createdBy ?? "owner",
      nextRunAt,
      JSON.stringify(allowedTools),
      JSON.stringify(allowedTargets),
      oneShot,
      runAt,
    ],
  );
  const row = await getScheduledTask(store, owner, id);
  if (!row) throw new AppError("Failed to create scheduled task.", 500);
  return row;
}

export async function getScheduledTask(
  store: Store,
  owner: string,
  id: string,
): Promise<ScheduledTaskRow | null> {
  const result = await store.raw<Record<string, unknown>>(
    `SELECT * FROM scheduled_tasks WHERE id=$1 AND owner=$2`,
    [id, owner],
  );
  const raw = result.rows[0];
  return raw ? toRow(raw) : null;
}

export async function listScheduledTasks(
  store: Store,
  owner: string,
): Promise<ScheduledTaskRow[]> {
  const result = await store.raw<Record<string, unknown>>(
    `SELECT * FROM scheduled_tasks WHERE owner=$1 ORDER BY created_by, name`,
    [owner],
  );
  return result.rows.map(toRow);
}

/** Rows whose cron slot (or one-shot time) is due. Reminders included. */
export async function dueScheduledTasks(
  store: Store,
  now: Date,
): Promise<ScheduledTaskRow[]> {
  const result = await store.raw<Record<string, unknown>>(
    `SELECT * FROM scheduled_tasks
     WHERE status='active' AND enabled AND (
       (one_shot = false AND next_run_at IS NOT NULL AND next_run_at <= $1)
       OR (one_shot = true AND run_at IS NOT NULL AND run_at <= $1)
     )`,
    [now.toISOString()],
  );
  return result.rows.map(toRow);
}

export async function setTaskEnabled(
  store: Store,
  owner: string,
  id: string,
  enabled: boolean,
): Promise<ScheduledTaskRow> {
  const row = await getScheduledTask(store, owner, id);
  if (!row) throw new AppError("Scheduled task not found.", 404);
  await store.raw(
    `UPDATE scheduled_tasks SET enabled=$1, status=CASE WHEN $1 THEN 'active' ELSE 'paused' END
     WHERE id=$2 AND owner=$3 AND status != 'fired'`,
    [enabled, id, owner],
  );
  const next = await getScheduledTask(store, owner, id);
  if (!next) throw new AppError("Scheduled task not found.", 404);
  return next;
}

export async function deleteScheduledTask(store: Store, owner: string, id: string): Promise<void> {
  const result = await store.raw(
    `DELETE FROM scheduled_tasks WHERE id=$1 AND owner=$2`,
    [id, owner],
  );
  void result;
}

/** Record a finished agent run: advance the cron slot or consume the one-shot. */
export async function recordTaskRun(
  store: Store,
  owner: string,
  id: string,
  ranAt: Date,
): Promise<ScheduledTaskRow | null> {
  const row = await getScheduledTask(store, owner, id);
  if (!row) return null;
  if (row.oneShot) {
    await store.raw(
      `UPDATE scheduled_tasks
       SET last_run_at=$1, run_count=run_count+1, status='fired', enabled=false
       WHERE id=$2 AND owner=$3`,
      [ranAt.toISOString(), id, owner],
    );
  } else if (row.cron) {
    const anchor = Math.max(
      ranAt.getTime(),
      row.nextRunAt ? Date.parse(row.nextRunAt) : ranAt.getTime(),
    );
    const nextRunAt = nextCronRun(row.cron, row.timezone, new Date(anchor)).toISOString();
    await store.raw(
      `UPDATE scheduled_tasks
       SET last_run_at=$1, next_run_at=$2, run_count=run_count+1
       WHERE id=$3 AND owner=$4`,
      [ranAt.toISOString(), nextRunAt, id, owner],
    );
  }
  return getScheduledTask(store, owner, id);
}

/** Mark a one-shot reminder delivered (no agent run). */
export async function markReminderDelivered(
  store: Store,
  owner: string,
  id: string,
  at: Date,
): Promise<void> {
  await store.raw(
    `UPDATE scheduled_tasks
     SET last_run_at=$1, run_count=run_count+1, status='fired', enabled=false
     WHERE id=$2 AND owner=$3`,
    [at.toISOString(), id, owner],
  );
}
