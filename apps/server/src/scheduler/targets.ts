/**
 * Registered capability targets: SSH hosts and Home Assistant instances.
 *
 * Targets are registered by the OWNER only (admin API routes + chat tools
 * that require owner approval). The agent can name a target by alias but can
 * never add hosts, and this registry holds NO secrets: SSH private keys stay
 * as owner-managed 0600 files referenced by path, and passwords/tokens live
 * in the encrypted credential store (credentials.ts).
 */
import { existsSync, statSync } from "node:fs";
import type { Store } from "../db.ts";
import { AppError } from "../errors.ts";
import type { SchedulerTarget, TargetKind } from "./types.ts";

const KIND = "scheduler-targets";
const ALIAS_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

export interface TargetInput {
  alias: string;
  kind: TargetKind;
  host?: string;
  port?: number;
  username?: string;
  keyPath?: string;
  backupCommand?: string;
  baseUrl?: string;
}

function validateAlias(alias: string): void {
  if (!ALIAS_RE.test(alias))
    throw new AppError(
      "Alias must be lowercase letters, digits, - or _, starting with a letter or digit (max 64 chars).",
      422,
    );
}

function normalizeUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new AppError("baseUrl must be a valid URL, e.g. https://ha.example.com", 422);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:")
    throw new AppError("baseUrl must be http(s)", 422);
  return url.toString().replace(/\/+$/, "");
}

export function buildTarget(input: TargetInput, now: string): SchedulerTarget {
  validateAlias(input.alias);
  if (input.kind === "ssh") {
    const host = (input.host ?? "").trim();
    if (!host) throw new AppError("SSH targets need a host.", 422);
    if (/[\s;|&$`'"\\]/.test(host))
      throw new AppError("Host contains characters that are not allowed.", 422);
    const port = input.port ?? 22;
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      throw new AppError("Port must be 1-65535.", 422);
    if (input.keyPath) {
      if (!input.keyPath.startsWith("/"))
        throw new AppError("keyPath must be an absolute path.", 422);
      if (!existsSync(input.keyPath))
        throw new AppError(`Key file does not exist: ${input.keyPath}`, 422);
      try {
        const st = statSync(input.keyPath);
        if (!st.isFile()) throw new Error("not a file");
        if ((st.mode & 0o777) & 0o077)
          console.warn(
            `[scheduler] key file ${input.keyPath} is readable beyond its owner; chmod 600 is recommended.`,
          );
      } catch {
        throw new AppError(`Key file is not readable: ${input.keyPath}`, 422);
      }
    }
    return {
      alias: input.alias,
      kind: "ssh",
      ssh: {
        host,
        port,
        username: input.username?.trim() || undefined,
        keyPath: input.keyPath || undefined,
        backupCommand: input.backupCommand?.trim() || undefined,
      },
      createdAt: now,
      updatedAt: now,
    };
  }
  if (!input.baseUrl) throw new AppError("Home Assistant targets need a baseUrl.", 422);
  return {
    alias: input.alias,
    kind: "ha",
    ha: { baseUrl: normalizeUrl(input.baseUrl) },
    createdAt: now,
    updatedAt: now,
  };
}

/** Metadata-only list: safe to show the agent and the dashboard. */
export async function listTargets(store: Store, owner: string): Promise<SchedulerTarget[]> {
  return store.list<SchedulerTarget>(owner, KIND);
}

export async function getTarget(
  store: Store,
  owner: string,
  alias: string,
): Promise<SchedulerTarget> {
  const target = await store.get<SchedulerTarget>(owner, KIND, alias);
  if (!target) throw new AppError(`Unknown target "${alias}". Register it first.`, 404);
  return target;
}

export async function registerTarget(
  store: Store,
  owner: string,
  input: TargetInput,
): Promise<SchedulerTarget> {
  const existing = await store.get<SchedulerTarget>(owner, KIND, input.alias);
  if (existing)
    throw new AppError(
      `Target "${input.alias}" already exists. Update or delete it first.`,
      409,
    );
  const target = buildTarget(input, new Date().toISOString());
  await store.put(owner, KIND, { ...target, id: target.alias });
  return target;
}

export async function updateTarget(
  store: Store,
  owner: string,
  alias: string,
  patch: Partial<Omit<TargetInput, "alias" | "kind">> & { baseUrl?: string },
): Promise<SchedulerTarget> {
  const existing = await getTarget(store, owner, alias);
  const merged: TargetInput = {
    alias: existing.alias,
    kind: existing.kind,
    host: patch.host ?? existing.ssh?.host,
    port: patch.port ?? existing.ssh?.port,
    username: patch.username ?? existing.ssh?.username,
    keyPath: patch.keyPath ?? existing.ssh?.keyPath,
    backupCommand: patch.backupCommand ?? existing.ssh?.backupCommand,
    baseUrl: patch.baseUrl ?? existing.ha?.baseUrl,
  };
  const next = buildTarget(merged, existing.createdAt);
  next.updatedAt = new Date().toISOString();
  await store.put(owner, KIND, { ...next, id: next.alias });
  return next;
}

export async function deleteTarget(store: Store, owner: string, alias: string): Promise<void> {
  await getTarget(store, owner, alias);
  await store.remove(owner, KIND, alias);
}
