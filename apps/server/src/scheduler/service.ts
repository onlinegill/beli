/**
 * SchedulerService: the tick loop for scheduled_tasks.
 *
 * - Agent rows due (cron slot reached, or one-shot runAt reached) get an
 *   AgentTask record (idempotent per slot) so the existing TaskWorker picks
 *   them up. The worker dispatches kind="scheduled" tasks carrying
 *   input.scheduledTaskId to AgentService.runCapabilityScheduledTask, which
 *   injects the row's grant into the policy context.
 * - Reminder rows due are delivered directly: an in-app notification plus a
 *   Telegram message when the bot is configured. No agent run.
 * - Every scheduled run and every tool-call verdict is audited to
 *   task_run_log (metadata only — never args, prompts, or secrets).
 */
import { randomUUID } from "node:crypto";
import type { Config } from "../config.ts";
import type { Store } from "../db.ts";
import type { AgentService } from "../engine/service.ts";
import type { PluginRegistry } from "../plugins/registry.ts";
import { backgroundFailure } from "../log.ts";
import {
  auditLog,
  ensureAuditTable,
} from "./run-state.ts";
import {
  dueScheduledTasks,
  ensureScheduledTasksTable,
  markReminderDelivered,
  type ScheduledTaskRow,
} from "./scheduled-tasks.ts";

export interface SchedulerDeps {
  db: Store;
  config: Config;
  agent: AgentService;
  plugins?: PluginRegistry;
  pollMs?: number;
}

async function sendTelegram(
  plugins: PluginRegistry | undefined,
  owner: string,
  text: string,
): Promise<boolean> {
  try {
    const telegram = plugins?.service<{ sendMessage(owner: string, text: string): Promise<{ ok: boolean }> }>(
      "telegram",
    );
    if (!telegram) return false;
    const result = await telegram.sendMessage(owner, text);
    return result.ok;
  } catch {
    return false;
  }
}

export class SchedulerService {
  private timer?: ReturnType<typeof setInterval>;
  private ticking = false;
  private stopping = false;

  constructor(private readonly deps: SchedulerDeps) {}

  async start(): Promise<void> {
    await ensureScheduledTasksTable(this.deps.db);
    await ensureAuditTable(this.deps.db);
    if (this.timer) return;
    this.stopping = false;
    this.timer = setInterval(() => {
      void this.tick().catch((error) => backgroundFailure("scheduler tick", error));
    }, this.deps.pollMs ?? 30000);
    // Don't let the scheduler keep the process alive on its own.
    this.timer.unref?.();
    void this.tick().catch((error) => backgroundFailure("scheduler initial tick", error));
  }

  async stop(): Promise<void> {
    this.stopping = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    while (this.ticking) await new Promise((r) => setTimeout(r, 10));
  }

  private async tick(): Promise<void> {
    if (this.stopping || this.ticking) return;
    this.ticking = true;
    try {
      const due = await dueScheduledTasks(this.deps.db, new Date());
      for (const row of due) {
        try {
          if (row.kind === "reminder") await this.deliverReminder(row);
          else await this.enqueueAgentRun(row);
        } catch (error) {
          backgroundFailure(`scheduler row ${row.id}`, error);
        }
      }
    } finally {
      this.ticking = false;
    }
  }

  private async deliverReminder(row: ScheduledTaskRow): Promise<void> {
    const at = new Date();
    const runId = randomUUID();
    await auditLog(this.deps.db, {
      runId,
      owner: row.owner,
      scheduleId: row.id,
      verdict: "started",
      reason: `Reminder: ${row.name}`,
    });
    const text = `Reminder: ${row.name}\n${row.prompt}`;
    await this.deps.agent.notify(row.owner, `Reminder: ${row.name}`, row.prompt, undefined, `reminder:${row.id}`);
    const telegramOk = await sendTelegram(this.deps.plugins, row.owner, text);
    await markReminderDelivered(this.deps.db, row.owner, row.id, at);
    await auditLog(this.deps.db, {
      runId,
      owner: row.owner,
      scheduleId: row.id,
      verdict: "finished",
      reason: telegramOk ? "Delivered in-app and via Telegram." : "Delivered in-app (Telegram not configured).",
    });
  }

  /**
   * Enqueue one agent run for the row's current slot. The task id is derived
   * from the slot so a second tick while the run is still queued/running
   * reuses the same record instead of double-firing.
   */
  private async enqueueAgentRun(row: ScheduledTaskRow): Promise<void> {
    const slot = row.oneShot ? row.runAt : row.nextRunAt;
    if (!slot) return;
    await this.deps.agent.createTask(
      row.owner,
      {
        kind: "scheduled",
        title: row.name,
        prompt: row.prompt,
        input: { scheduledTaskId: row.id },
      },
      `schedtask:${row.id}:${slot}`,
      false,
    );
  }
}
