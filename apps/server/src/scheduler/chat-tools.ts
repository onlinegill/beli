/**
 * Chat tools for managing the scheduler: targets, credentials (metadata
 * only), scheduled tasks, and run history.
 *
 * SECURITY: there is deliberately NO chat tool that accepts a password,
 * token, or key. target_credential_setup only explains the secure
 * owner-only flow (admin-authenticated API); secrets must never pass
 * through the model. Saving credentials happens exclusively via
 * POST /api/target-credentials.
 */
import { defineTool } from "@copilotkit/runtime/v2";
import { z } from "zod";
import type { AgentService } from "../engine/service.ts";
import {
  deleteScheduledTask,
  getScheduledTask,
  listScheduledTasks,
  setTaskEnabled,
  createScheduledTask as createTaskRow,
} from "./scheduled-tasks.ts";
import {
  deleteTarget,
  listTargets,
  registerTarget,
  updateTarget,
} from "./targets.ts";
import { TargetCredentialStore } from "./credentials.ts";
import { recentAuditRows } from "./run-state.ts";
import { CAPABILITY_TOOL_SET } from "./types.ts";

interface ChatDeps {
  service: AgentService;
  owner: string;
}

const aliasSchema = z
  .string()
  .regex(/^[a-z0-9][a-z0-9_-]{0,63}$/, "lowercase alias, max 64 chars");

function summarizeRow(row: {
  id: string;
  name: string;
  kind: string;
  cron: string | null;
  enabled: boolean;
  timezone: string;
  lastRunAt: string | null;
  nextRunAt: string | null;
  runCount: number;
  allowedTools: string[];
  allowedTargets: { ssh: string[]; ha: string[] };
  oneShot: boolean;
  runAt: string | null;
  status: string;
}) {
  return {
    id: row.id,
    name: row.name,
    kind: row.kind,
    cron: row.cron,
    enabled: row.enabled,
    status: row.status,
    timezone: row.timezone,
    lastRunAt: row.lastRunAt,
    nextRunAt: row.nextRunAt,
    runAt: row.runAt,
    runCount: row.runCount,
    allowedTools: row.allowedTools,
    allowedTargets: row.allowedTargets,
    oneShot: row.oneShot,
  };
}

export function schedulerChatTools({ service, owner }: ChatDeps) {
  const db = service.db;
  const credentialStore = new TargetCredentialStore(db, service.config);
  return [
    defineTool({
      name: "scheduler_target_register",
      description:
        "Register an SSH host or Home Assistant instance as a capability target (metadata only, no secrets). " +
        "SSH: host, port, username, and either a keyPath (preferred) or a saved password credential. " +
        "backupCommand should run a host-side backup script that exits 0 only on a verified backup. " +
        "Secrets are never passed here — use target_credential_setup for the secure flow.",
      parameters: z.object({
        alias: aliasSchema,
        kind: z.enum(["ssh", "ha"]),
        host: z.string().max(253).optional(),
        port: z.number().int().min(1).max(65535).optional(),
        username: z.string().max(128).optional(),
        keyPath: z.string().max(512).optional(),
        backupCommand: z.string().max(2000).optional(),
        baseUrl: z.string().max(512).optional(),
      }),
      execute: async (args) => registerTarget(db, owner, args),
    }),
    defineTool({
      name: "scheduler_target_update",
      description: "Update a registered capability target's metadata (no secrets).",
      parameters: z.object({
        alias: aliasSchema,
        host: z.string().max(253).optional(),
        port: z.number().int().min(1).max(65535).optional(),
        username: z.string().max(128).optional(),
        keyPath: z.string().max(512).optional(),
        backupCommand: z.string().max(2000).optional(),
        baseUrl: z.string().max(512).optional(),
      }),
      execute: async (args) => {
        const { alias, ...patch } = args;
        return updateTarget(db, owner, alias, patch);
      },
    }),
    defineTool({
      name: "scheduler_target_delete",
      description: "Delete a registered capability target. Scheduled tasks granting it will deny calls to it.",
      parameters: z.object({ alias: aliasSchema }),
      execute: async ({ alias }) => {
        await deleteTarget(db, owner, alias);
        return { deleted: alias };
      },
    }),
    defineTool({
      name: "scheduler_target_list",
      description: "List registered capability targets (metadata only, no secrets).",
      parameters: z.object({}),
      execute: async () => listTargets(db, owner),
    }),
    defineTool({
      name: "target_credential_setup",
      description:
        "Explain the secure owner-only flow for saving an SSH password or Home Assistant token. " +
        "Call this when the owner wants the agent to use a password/token: it returns instructions, never collects the secret. " +
        "NEVER ask for, accept, or repeat passwords, tokens, or keys in chat.",
      parameters: z.object({
        alias: aliasSchema.describe("Target alias the credential is for"),
        kind: z.enum(["ssh", "ha"]),
      }),
      execute: async ({ alias, kind }) => ({
        alias,
        kind,
        secureFlow:
          "Secrets are saved only through the owner-authenticated admin API, never in chat. " +
          "As the server admin, run: " +
          `curl -X POST http://localhost:8787/api/target-credentials ` +
          `-H "Authorization: Bearer <dashboard-admin-token>" -H "Content-Type: application/json" ` +
          `-d '{"alias":"${alias}","kind":"${kind}","username":"<login>","secret":"<password-or-token>"}'. ` +
          "The secret is AES-256-GCM encrypted at rest; the agent only ever sees the alias. " +
          "List saved credentials (metadata only) with target_credential_list.",
      }),
    }),
    defineTool({
      name: "target_credential_list",
      description: "List saved target credentials (metadata only: alias, redacted username hint, timestamps). Never shows secrets.",
      parameters: z.object({}),
      execute: async () => credentialStore.list(owner),
    }),
    defineTool({
      name: "target_credential_delete",
      description: "Delete a saved target credential by id (from target_credential_list).",
      parameters: z.object({ id: z.string().min(1).max(128) }),
      execute: async ({ id }) => {
        await credentialStore.remove(owner, id);
        return { deleted: id };
      },
    }),
    defineTool({
      name: "scheduled_task_create",
      description:
        "Create a scheduled AI task or a one-shot reminder. " +
        "Agent task: cron (5 fields) + prompt; the worker runs the prompt on schedule. " +
        "Reminder: runAt (ISO timestamp) + prompt as the message; delivered in-app and via Telegram when configured, no agent run. " +
        "allowedTools is a subset of: " + [...CAPABILITY_TOOL_SET].join(", ") + ". " +
        "allowedTargets names registered target aliases, e.g. {ssh:['pve'], ha:['home']}. " +
        "Grants are fixed at creation: read-only checks run autonomously within the grant; mutations need a verified backup first.",
      parameters: z.object({
        name: z.string().min(1).max(160),
        kind: z.enum(["agent", "reminder"]).default("agent"),
        cron: z.string().max(100).optional(),
        runAt: z.string().max(64).optional().describe("ISO timestamp for one-shot tasks/reminders"),
        prompt: z.string().min(1).max(12000),
        timezone: z.string().max(80).optional(),
        allowedTools: z.array(z.string()).max(8).optional(),
        allowedSsh: z.array(aliasSchema).max(16).optional(),
        allowedHa: z.array(aliasSchema).max(16).optional(),
      }),
      execute: async (args) =>
        summarizeRow(
          await createTaskRow(db, owner, {
            name: args.name,
            kind: args.kind,
            cron: args.cron,
            runAt: args.runAt,
            prompt: args.prompt,
            timezone: args.timezone,
            createdBy: "chat",
            allowedTools: args.allowedTools,
            allowedTargets: { ssh: args.allowedSsh, ha: args.allowedHa },
          }),
        ),
    }),
    defineTool({
      name: "scheduled_task_list",
      description: "List scheduled tasks and reminders with their grants and next run times.",
      parameters: z.object({}),
      execute: async () => (await listScheduledTasks(db, owner)).map(summarizeRow),
    }),
    defineTool({
      name: "scheduled_task_control",
      description: "Pause, resume, or delete a scheduled task (by id from scheduled_task_list).",
      parameters: z.object({
        id: z.string().min(1).max(128),
        action: z.enum(["pause", "resume", "delete"]),
      }),
      execute: async ({ id, action }) => {
        if (action === "delete") {
          await deleteScheduledTask(db, owner, id);
          return { deleted: id };
        }
        return summarizeRow(await setTaskEnabled(db, owner, id, action === "resume"));
      },
    }),
    defineTool({
      name: "scheduled_task_runs",
      description:
        "Show recent scheduled-run audit entries: run starts, finishes, and every tool-call verdict. " +
        "Never contains commands, arguments, or secrets — only tool names, targets, and verdicts.",
      parameters: z.object({ limit: z.number().int().min(1).max(200).optional() }),
      execute: async ({ limit }) => {
        const rows = await recentAuditRows(db, owner, limit ?? 50);
        return rows.map((r) => ({
          runId: r.run_id,
          scheduleId: r.schedule_id,
          tool: r.tool_name,
          verdict: r.verdict,
          reason: r.reason,
          at: r.created_at,
        }));
      },
    }),
    defineTool({
      name: "scheduled_task_detail",
      description: "Show one scheduled task with its full grant and timing state.",
      parameters: z.object({ id: z.string().min(1).max(128) }),
      execute: async ({ id }) => {
        const row = await getScheduledTask(db, owner, id);
        if (!row) return { error: "Scheduled task not found." };
        return summarizeRow(row);
      },
    }),
  ];
}
