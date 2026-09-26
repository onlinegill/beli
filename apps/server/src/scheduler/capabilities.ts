/**
 * Capability service: the scheduler's worker tool implementations.
 *
 * The agent always names a target by ALIAS. Hostnames, usernames, key
 * paths, and credential references stay server-side; plaintext secrets are
 * decrypted in memory only inside the final SSH/HA operation and are never
 * returned, logged, or stored.
 */
import type { Config } from "../config.ts";
import type { Store } from "../db.ts";
import { AppError } from "../errors.ts";
import { getTarget } from "./targets.ts";
import { TargetCredentialStore } from "./credentials.ts";
import { classifyCommand, sshExec, type SshTarget } from "./ssh.ts";
import { hasBackupCompleted, markBackupCompleted, targetKey } from "./run-state.ts";

export interface CapabilityDeps {
  db: Store;
  config: Config;
}

/** Run-scoped context the policy chain hands to worker tools. */
export interface WorkerRunContext {
  runId: string;
  owner: string;
}

/** Secrets are wiped in finally blocks; results carry no secret material. */
function wipe(value: string | undefined): void {
  void value;
}

export class CapabilityService {
  private readonly credentials: TargetCredentialStore;

  constructor(private readonly deps: CapabilityDeps) {
    this.credentials = new TargetCredentialStore(deps.db, deps.config);
  }

  private async sshTarget(owner: string, alias: string): Promise<SshTarget> {
    const target = await getTarget(this.deps.db, owner, alias);
    if (target.kind !== "ssh" || !target.ssh)
      throw new AppError(`Target "${alias}" is not an SSH target.`, 422);
    const username = target.ssh.username;
    return {
      host: target.ssh.host,
      port: target.ssh.port,
      username: username ?? "",
      keyPath: target.ssh.keyPath,
    };
  }

  /**
   * Run an SSH command on a registered target. `policy` has already been
   * checked by the tool-policy chain (grant gate, backup gate). Returns a
   * redacted summary — never the command output beyond a bounded excerpt,
   * and never any secret material.
   */
  async sshExec(
    ctx: WorkerRunContext,
    alias: string,
    command: string,
    timeoutMs?: number,
  ): Promise<{ ok: boolean; exitCode: number | null; output: string }> {
    const target = await this.sshTarget(ctx.owner, alias);
    const classification = classifyCommand(command);
    if (classification === "mutating" && !hasBackupCompleted(ctx.runId, targetKey("ssh", alias)))
      throw new AppError(
        `Mutating command on "${alias}" needs a completed backup first (target_backup).`,
        403,
      );
    let username = target.username;
    let password: string | undefined;
    try {
      if (!target.keyPath) {
        await this.credentials.useSecrets(ctx.owner, alias, "ssh", async (secrets) => {
          if (secrets.username) username = secrets.username;
          if (secrets.secret) password = secrets.secret;
        });
      }
      if (!username)
        throw new AppError(
          `No SSH username for "${alias}". Register one or save a credential.`,
          422,
        );
      const result = await sshExec(
        { host: target.host, port: target.port, username, keyPath: target.keyPath },
        command,
        { password, timeoutMs },
      );
      const output = (result.ok ? result.stdout : result.stderr).trim();
      return {
        ok: result.ok,
        exitCode: result.exitCode,
        output: output || "(no output)",
      };
    } finally {
      username = "";
      password = undefined;
      wipe(password);
    }
  }

  /**
   * Perform and verify a backup for a target, then mark the run+target as
   * backed up so mutating tools unlock for the rest of this run.
   *
   * SSH: runs the owner-configured backupCommand on the host. The command
   * must be read-only from this host's view (it must point at a host-side
   * script that performs and verifies the backup, exiting 0 only on
   * success) — the agent cannot self-assert a backup; the script's exit
   * code is the verification.
   *
   * Home Assistant: creates a full Supervisor backup via the HA API and
   * polls until it shows up in the backup list, so the backup is performed
   * and verified rather than asserted.
   */
  async targetBackup(
    ctx: WorkerRunContext,
    alias: string,
  ): Promise<{ ok: boolean; detail: string }> {
    const target = await getTarget(this.deps.db, ctx.owner, alias);
    if (target.kind === "ha") return this.haBackup(ctx, alias);
    if (target.kind !== "ssh" || !target.ssh)
      throw new AppError(`Unknown target kind for "${alias}".`, 422);
    const backupCommand = target.ssh.backupCommand;
    if (!backupCommand)
      throw new AppError(
        `No backupCommand configured for "${alias}". Add one when registering the target.`,
        422,
      );
  // The backup wrapper is expected to perform writes (snapshots,
  // dumps); safety comes from exact owner configuration plus a
  // verified exit/result below, not from command classification.
    const sshTarget = await this.sshTarget(ctx.owner, alias);
    let username = sshTarget.username;
    let password: string | undefined;
    try {
      if (!sshTarget.keyPath) {
        await this.credentials.useSecrets(ctx.owner, alias, "ssh", async (secrets) => {
          if (secrets.username) username = secrets.username;
          if (secrets.secret) password = secrets.secret;
        });
      }
      if (!username) throw new AppError(`No SSH username for "${alias}".`, 422);
      const result = await sshExec(
        {
          host: sshTarget.host,
          port: sshTarget.port,
          username,
          keyPath: sshTarget.keyPath,
        },
        backupCommand,
        { password, timeoutMs: 600000 },
      );
      if (!result.ok) {
        return {
          ok: false,
          detail: `Backup command failed (exit ${result.exitCode ?? "?"}): ${result.stderr.trim().slice(0, 2000) || "(no output)"}`,
        };
      }
      markBackupCompleted(ctx.runId, targetKey("ssh", alias));
      return {
        ok: true,
        detail: `Backup verified for "${alias}": ${result.stdout.trim().slice(0, 2000) || "(no output)"}`,
      };
    } finally {
      username = "";
      password = undefined;
      wipe(password);
    }
  }

  /** HA backup: create a full Supervisor backup and verify it landed. */
  private async haBackup(
    ctx: WorkerRunContext,
    alias: string,
  ): Promise<{ ok: boolean; detail: string }> {
    const startedAt = new Date();
    const created = (await this.haFetch(ctx.owner, alias, "/api/hassio/backups/new/full", {
      method: "POST",
      body: { name: `openmuse-${ctx.runId.slice(0, 8)}` },
    })) as { data?: { slug?: string } };
    const slug = created?.data?.slug;
    const deadline = Date.now() + 10 * 60 * 1000;
    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 15000));
      const backups = (await this.haFetch(ctx.owner, alias, "/api/hassio/backups")) as {
        data?: { backups?: Array<{ slug: string; date: string }> };
      };
      const list = backups?.data?.backups ?? [];
      const found = slug
        ? list.find((b) => b.slug === slug)
        : list.find((b) => new Date(b.date) >= startedAt);
      if (found) {
        markBackupCompleted(ctx.runId, targetKey("ha", alias));
        return {
          ok: true,
          detail: `Home Assistant backup verified for "${alias}" (slug ${found.slug}, created ${found.date}).`,
        };
      }
    }
    return {
      ok: false,
      detail: `Home Assistant backup for "${alias}" did not appear within 10 minutes.`,
    };
  }

  /**
   * Read-only update check for an SSH server: lists upgradable
   * packages from the last index refresh. Deliberately avoids
   * `apt update` (refreshing indexes is a write) — scheduling index
   * refreshes is the owner's job, outside this tool.
   */
  async serverCheckUpdates(
    ctx: WorkerRunContext,
    alias: string,
  ): Promise<{ ok: boolean; detail: string }> {
    const command = "apt list --upgradable 2>/dev/null";
    // Belt and braces: this fixed command must never classify as
    // mutating; refuse rather than run something unexpected.
    if (classifyCommand(command) !== "readonly")
      throw new AppError(
        "server_check_updates command no longer classifies read-only; refusing.",
        500,
      );
    const result = await this.sshExec(ctx, alias, command, 60000);
    const lines = result.output
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("Listing"));
    return {
      ok: result.ok,
      detail:
        lines.length === 0
          ? `No pending package updates on "${alias}".`
          : `${lines.length} upgradable package(s) on "${alias}":\n` +
            lines.slice(0, 50).join("\n"),
    };
  }

  /**
   * Resolve an HA target's base URL (for the update handler).
   */
  async haBaseUrl(
    owner: string,
    alias: string,
  ): Promise<{ baseUrl: string }> {
    const target = await getTarget(this.deps.db, owner, alias);
    if (target.kind !== "ha" || !target.ha)
      throw new AppError(`Target "${alias}" is not a Home Assistant target.`, 422);
    return { baseUrl: target.ha.baseUrl };
  }

  private async haBase(owner: string, alias: string): Promise<{ baseUrl: string }> {
    const target = await getTarget(this.deps.db, owner, alias);
    if (target.kind !== "ha" || !target.ha)
      throw new AppError(`Target "${alias}" is not a Home Assistant target.`, 422);
    return { baseUrl: target.ha.baseUrl };
  }

  private async haFetch(
    owner: string,
    alias: string,
    path: string,
    options: { method?: string; body?: unknown } = {},
  ): Promise<unknown> {
    const { baseUrl } = await this.haBase(owner, alias);
    return this.credentials.useSecrets(owner, alias, "ha", async (secrets) => {
      const token = secrets.secret ?? "";
      if (!token)
        throw new AppError(
          `No saved token for Home Assistant target "${alias}". Save one first.`,
          422,
        );
      let response: Response;
      try {
        response = await fetch(`${baseUrl}${path}`, {
          method: options.method ?? "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
          signal: AbortSignal.timeout(30000),
        });
      } catch (error) {
        throw new AppError(
          `Home Assistant "${alias}" is unreachable: ${(error as Error).message}`,
          502,
        );
      }
      if (!response.ok)
        throw new AppError(
          `Home Assistant "${alias}" returned ${response.status} for ${path}.`,
          502,
        );
      return (await response.json()) as unknown;
    });
  }

  /** Read-only: list update entities and their current status. */
  async haCheckUpdates(
    ctx: WorkerRunContext,
    alias: string,
  ): Promise<{ updates: Array<{ entityId: string; state: string; title?: string; latestVersion?: string }> }> {
    const states = (await this.haFetch(ctx.owner, alias, "/api/states")) as Array<{
      entity_id: string;
      state: string;
      attributes?: { friendly_name?: string; latest_version?: string };
    }>;
    const updates = states
      .filter((s) => s.entity_id.startsWith("update."))
      .map((s) => ({
        entityId: s.entity_id,
        state: s.state,
        title: s.attributes?.friendly_name,
        latestVersion: s.attributes?.latest_version,
      }));
    return { updates };
  }

  /** Mutating: install an update on a Home Assistant entity. Needs a backup first. */
  async haApplyUpdate(
    ctx: WorkerRunContext,
    alias: string,
    entityId: string,
  ): Promise<{ ok: boolean; entityId: string }> {
    if (!/^update\.[a-z0-9_]+$/.test(entityId))
      throw new AppError(`Invalid update entity id "${entityId}".`, 422);
    if (!hasBackupCompleted(ctx.runId, targetKey("ha", alias)))
      throw new AppError(
        `ha_apply_update on "${alias}" needs a completed backup first (target_backup).`,
        403,
      );
    await this.haFetch(ctx.owner, alias, "/api/services/update/install", {
      method: "POST",
      body: { entity_id: entityId },
    });
    return { ok: true, entityId };
  }
}
