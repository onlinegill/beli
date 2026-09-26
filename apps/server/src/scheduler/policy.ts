/**
 * Scheduled-task permission gate, invoked at the top of trustedPolicies
 * (stage 2) for capability tools. The five policy stages keep their
 * exact order; this gate is not a separate stage.
 *
 * Rules:
 * - Capability tools (ssh_exec, ha_check_updates, ha_apply_update,
 *   target_backup) are denied unless the run carries a scheduled-task
 *   grant. The grant is minted server-side from the scheduled_tasks row —
 *   prompt text can never forge it.
 * - The tool must be listed in grant.tools and the target alias in the
 *   matching grant.ssh / grant.ha list, or the call is denied.
 * - A mutating call to a target NOT in the grant returns requireApproval so
 *   a new/untrusted target goes through the existing exact-call
 *   owner-approval flow. Read-only calls to ungranted targets are denied.
 * - Mutating calls (ha_apply_update, or ssh_exec commands classified as
 *   mutating) are DENIED unless target_backup succeeded for the same target
 *   earlier in the same run. This is a hard deny: owner approval cannot
 *   bypass a missing backup (the tool handler re-checks unconditionally).
 * - Calls that pass every check return allow, so read-only checks run
 *   autonomously within their grants. trustedPolicies abstains for
 *   capability tools (the gate already decided); later stages may still
 *   narrow via hooks.
 */
import type { PolicyStage, ToolCallContext } from "../engine/tool-policy.ts";
import { hasBackupCompleted, targetKey } from "./run-state.ts";
import { classifyCommand } from "./ssh.ts";
import {
  CAPABILITY_TOOL_SET,
  type ScheduledRunContext,
  type ScheduledTaskGrant,
} from "./types.ts";

export type { ScheduledRunContext };

function targetOf(
  toolName: string,
  args: unknown,
  grant: ScheduledTaskGrant,
): { kind: "ssh" | "ha"; alias: string } | null {
  const record = (args ?? {}) as Record<string, unknown>;
  const alias =
    typeof record.target === "string"
      ? record.target
      : typeof record.instance === "string"
        ? record.instance
        : null;
  if (!alias) return null;
  if (toolName === "ssh_exec" || toolName === "server_check_updates")
    return { kind: "ssh", alias };
  if (toolName === "ha_check_updates" || toolName === "ha_apply_update")
    return { kind: "ha", alias };
  if (toolName === "target_backup") {
    // The backup tool serves both target kinds: resolve from the grant so an
    // HA alias is checked against grant.ha, not grant.ssh. Unknown aliases
    // fall through to the untrusted-target path below (owner approval).
    if (grant.ha.includes(alias)) return { kind: "ha", alias };
    return { kind: "ssh", alias };
  }
  return null;
}

function isMutatingCall(toolName: string, args: unknown): boolean {
  if (toolName === "ha_apply_update") return true;
  if (toolName === "ssh_exec") {
    const command = (args as { command?: unknown } | null)?.command;
    return classifyCommand(typeof command === "string" ? command : "") === "mutating";
  }
  return false;
}

export const scheduledGrantGate: PolicyStage = (ctx: ToolCallContext) => {
  const name = ctx.toolName;
  if (!CAPABILITY_TOOL_SET.has(name)) return undefined;

  const run = ctx.scheduledRun;
  if (!run) {
    return {
      kind: "deny",
      reason: `"${name}" is only available inside a scheduled run carrying a task grant.`,
    };
  }
  const grant = run.grant ?? { tools: [], ssh: [], ha: [] };
  if (!grant.tools.includes(name)) {
    return {
      kind: "deny",
      reason: `"${name}" is not in this scheduled task's allowed tools.`,
    };
  }
  const target = targetOf(name, ctx.args, grant);
  if (!target) {
    return { kind: "deny", reason: `"${name}" needs a registered target alias.` };
  }
  const allowed = target.kind === "ssh" ? grant.ssh : grant.ha;
  const mutating = isMutatingCall(name, ctx.args);

  if (!allowed.includes(target.alias)) {
    // New/untrusted target: backups and mutations go through the existing
    // exact-call owner-approval flow; read-only checks stay hard-denied.
    // The tool handler still enforces the backup gate unconditionally.
    if (name === "target_backup" || mutating) {
      return {
        kind: "requireApproval",
        reason: `"${target.alias}" is not in this task's allowed targets; owner approval is required for this exact call.`,
      };
    }
    return {
      kind: "deny",
      reason: `"${target.alias}" is not in this scheduled task's allowed ${target.kind} targets.`,
    };
  }
  if (mutating && !hasBackupCompleted(run.runId, targetKey(target.kind, target.alias))) {
    return {
      kind: "deny",
      reason:
        `Backup required: run target_backup for "${target.alias}" successfully first. ` +
        `A missing backup cannot be bypassed by approval.`,
    };
  }
  return { kind: "allow" };
};
