/**
 * Worker tool specs for the scheduler capability tools. These are registered
 * in executeModelTask ONLY for runs carrying a scheduled-task grant
 * (opts.scheduled). The policy gate (scheduler/policy.ts) already enforced
 * the grant + backup rules before the handler runs; the handlers re-check
 * the backup gate unconditionally so even an owner-approved exact call can
 * never run a mutation without a verified backup in the same run.
 *
 * Results are redacted summaries: command output is bounded and never
 * includes secret material; aliases are echoed, never hostnames or
 * usernames.
 */
import { z } from "zod";
import { AppError } from "../errors.ts";
import { CapabilityService } from "./capabilities.ts";
import { hasBackupCompleted, targetKey } from "./run-state.ts";
import { classifyCommand } from "./ssh.ts";
import type { ScheduledRunContext } from "./types.ts";

export interface SchedulerToolSpec {
  name: string;
  description: string;
  parameters: z.ZodType;
  execute: (args: unknown) => Promise<unknown>;
}

interface ToolDeps {
  owner: string;
  run: ScheduledRunContext;
  capability: CapabilityService;
}

// NOTE: no handler-side grant check. The policy gate (scheduledGrantGate)
// already enforced the grant before the handler runs; re-checking would
// deny an owner-approved exact call for a new/untrusted target. The
// backup gate (requireBackup) is still re-checked unconditionally.

function requireBackup(run: ScheduledRunContext, kind: "ssh" | "ha", alias: string): void {
  if (!hasBackupCompleted(run.runId, targetKey(kind, alias)))
    throw new AppError(
      `Backup required: run target_backup for "${alias}" successfully first.`,
      403,
    );
}

export function schedulerWorkerToolSpecs(deps: ToolDeps): SchedulerToolSpec[] {
  const { owner, run, capability } = deps;
  const runCtx = { runId: run.runId, owner };
  return [
    {
      name: "ssh_exec",
      description:
        "Run a command on a registered SSH target (alias only; host and credentials stay server-side). " +
        "Read-only commands run within the task's grant. Mutating commands (upgrades, reboots, service changes, file writes) " +
        "need target_backup to have succeeded for the same target earlier in this run.",
      parameters: z.object({
        target: z.string().min(1).max(64).describe("Registered SSH target alias"),
        command: z.string().min(1).max(4000).describe("Command to run on the target"),
        timeoutMs: z.number().int().min(1000).max(120000).optional(),
      }),
      execute: async (args: unknown) => {
        const { target, command, timeoutMs } = (args ?? {}) as {
          target: string;
          command: string;
          timeoutMs?: number;
        };
        // Grant already enforced by the policy gate.
        if (classifyCommand(command) === "mutating") requireBackup(run, "ssh", target);
        return capability.sshExec(runCtx, target, command, timeoutMs);
      },
    },
    {
      name: "target_backup",
      description:
        "Perform and verify a backup for a registered target, unlocking mutating tools for the rest of this run. " +
        "SSH: runs the owner-configured backup command on the host (must exit 0 only on a verified backup). " +
        "Home Assistant: creates and verifies a full Supervisor backup via the HA API.",
      parameters: z.object({
        target: z.string().min(1).max(64).describe("Registered target alias"),
      }),
      execute: async (args: unknown) => {
        const { target } = (args ?? {}) as { target: string };
        // Grant already enforced by the policy gate (either kind).
        return capability.targetBackup(runCtx, target);
      },
    },
    {
      name: "server_check_updates",
      description:
        "Read-only: list upgradable OS packages on a registered SSH server (alias only). " +
        "Uses the last package-index refresh; it never refreshes indexes itself.",
      parameters: z.object({
        target: z.string().min(1).max(64).describe("Registered SSH target alias"),
      }),
      execute: async (args: unknown) => {
        const { target } = (args ?? {}) as { target: string };
        // Read-only: no backup needed. Grant enforced by the policy gate.
        return capability.serverCheckUpdates(runCtx, target);
      },
    },
    {
      name: "ha_check_updates",
      description:
        "Read-only: list available updates on a registered Home Assistant instance (alias only).",
      parameters: z.object({
        instance: z.string().min(1).max(64).describe("Registered Home Assistant alias"),
      }),
      execute: async (args: unknown) => {
        const { instance } = (args ?? {}) as { instance: string };
        // Grant already enforced by the policy gate.
        return capability.haCheckUpdates(runCtx, instance);
      },
    },
    {
      name: "ha_apply_update",
      description:
        "Install an update on a registered Home Assistant instance (alias only). " +
        "Requires target_backup to have succeeded for the same instance earlier in this run.",
      parameters: z.object({
        instance: z.string().min(1).max(64).describe("Registered Home Assistant alias"),
        entityId: z
          .string()
          .regex(/^update\.[a-z0-9_]+$/)
          .describe("Update entity id, e.g. update.home_assistant_core_update"),
      }),
      execute: async (args: unknown) => {
        const { instance, entityId } = (args ?? {}) as {
          instance: string;
          entityId: string;
        };
        // Grant already enforced by the policy gate.
        requireBackup(run, "ha", instance);
        return capability.haApplyUpdate(runCtx, instance, entityId);
      },
    },
  ];
}
