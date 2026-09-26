/**
 * Scheduled tasks + capability gate: shared types.
 *
 * The scheduler reuses the engine's existing Schedule records
 * (packages/domain/src/agent.ts): the TaskWorker already polls due
 * "scheduled" tasks, runSchedule already invokes the agent, and the cron
 * parser already exists. This subsystem adds capability targets, an
 * encrypted credential store, and the permission gate on top.
 */

/** Capability tools gated by scheduled-task grants. Exact names only. */
export const CAPABILITY_TOOLS = [
  "ssh_exec",
  "server_check_updates",
  "ha_check_updates",
  "ha_apply_update",
  "target_backup",
] as const;
export type CapabilityTool = (typeof CAPABILITY_TOOLS)[number];
export const CAPABILITY_TOOL_SET: ReadonlySet<string> = new Set(CAPABILITY_TOOLS);

/**
 * Per-scheduled-task grant. Declared by the owner when the task is created.
 * A scheduled run may call a capability tool only when the tool is listed in
 * `tools` AND its target alias is listed in `ssh`/`ha`. Anything else is
 * denied by the policy chain.
 */
export interface ScheduledTaskGrant {
  tools: string[];
  ssh: string[];
  ha: string[];
}

export function emptyGrant(): ScheduledTaskGrant {
  return { tools: [], ssh: [], ha: [] };
}

/** Registered SSH host / Home Assistant instance. No secrets here — ever. */
export type TargetKind = "ssh" | "ha";
export interface SchedulerTarget {
  /** Alias used by the agent, e.g. "pve", "home-assistant". */
  alias: string;
  kind: TargetKind;
  ssh?: {
    host: string;
    port: number;
    /** Fallback username when no credential stores one for the alias. */
    username?: string;
    /** Absolute path to a private key file (0600, owner-managed). */
    keyPath?: string;
    /** Command run by target_backup on this host (owner-configured). */
    backupCommand?: string;
  };
  ha?: {
    baseUrl: string;
  };
  createdAt: string;
  updatedAt: string;
}

/** Metadata for a stored credential. Never carries secret material. */
export interface TargetCredentialMeta {
  id: string;
  alias: string;
  kind: TargetKind;
  /** Redacted username hint, e.g. "ro***". Empty when none stored. */
  usernameHint: string;
  hasSecret: boolean;
  createdAt: string;
  updatedAt: string;
  lastUsedAt?: string;
}

/** Run-scoped gate context injected into the policy chain for scheduled runs. */
export interface ScheduledRunContext {
  runId: string;
  grant: ScheduledTaskGrant;
}

/** Audit verdicts recorded in the task_run_log table. */
export type AuditVerdict = "allow" | "deny" | "requireApproval";
