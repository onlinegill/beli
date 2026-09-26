/**
 * Encrypted credential store for capability targets (SSH + Home Assistant).
 *
 * Owner requirement: the owner can save SSH usernames AND passwords (not
 * just key files) so the agent can use them.
 *
 * Security design:
 * 1. Encrypted at rest with AES-256-GCM (the existing vault in
 *    packages/integrations/src/vault.ts). The master key is
 *    TOKEN_ENCRYPTION_KEY, which lives in /root/openmuse/.env — a 0600 file
 *    outside the repo. The key never enters the DB, logs, or tool results.
 * 2. The agent and tools only ever see a credential by ALIAS. Plaintext is
 *    decrypted in memory only at the moment of use inside the ssh/ha tool
 *    implementations, used once, and wiped in a finally block. Tool results,
 *    logs, and the audit table carry the alias only — never the secret.
 * 3. Owner-only management: admin-gated API routes plus chat tools
 *    (target_credential_save/list/delete). List returns metadata only.
 * 4. SSH prefers key auth when the target has a keyPath configured, and
 *    falls back to the stored password (see ssh.ts).
 */
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { decryptSecret, encryptSecret } from "../../../../packages/integrations/src/vault.ts";
import type { Config } from "../config.ts";
import type { Store } from "../db.ts";
import { AppError } from "../errors.ts";
import type { TargetCredentialMeta, TargetKind } from "./types.ts";

const KIND = "target-credentials";

/**
 * Dedicated scheduler vault key: a 32-byte base64 key in a 0600 file
 * outside the repository. Never the shared config encryption key, never
 * in chat, DB, logs, or the repo.
 */
const VAULT_KEY_PATH = "/root/.openmuse/scheduler-vault.key";

let cachedVaultKey: string | null = null;

function loadVaultKey(): string {
  if (cachedVaultKey) return cachedVaultKey;
  let raw: string;
  try {
    raw = readFileSync(VAULT_KEY_PATH, "utf8").trim();
  } catch {
    throw new AppError(
      "Scheduler vault key missing at " + VAULT_KEY_PATH + ". " +
        "Create it with: head -c 32 /dev/urandom | base64 > " +
        VAULT_KEY_PATH + " && chmod 600 " + VAULT_KEY_PATH,
      503,
    );
  }
  if (!raw) throw new AppError("Scheduler vault key is empty.", 503);
  cachedVaultKey = raw;
  return raw;
}

/** Show just enough of the username to recognize it. Never the secret. */
function usernameHint(username: string): string {
  const at = username.indexOf("@");
  if (at > 0) return `${username.slice(0, Math.min(2, at))}***@${username.slice(at + 1)}`;
  return username ? `${username.slice(0, 1)}***` : "";
}

interface StoredTargetCredential {
  id: string;
  alias: string;
  kind: TargetKind;
  /** Vault envelope of JSON { username?, secret }. Never leaves this file decrypted. */
  vault: string;
  /** Redacted username hint, stored at save time so listing never decrypts. */
  usernameHint: string;
  createdAt: string;
  updatedAt: string;
  lastUsedAt?: string;
}

interface CredentialSecrets {
  username?: string;
  /** SSH password or HA long-lived token. */
  secret?: string;
}

export class TargetCredentialStore {
  constructor(
    private readonly db: Store,
    private readonly config: Config,
  ) {}

  private requireKey(): string {
    return loadVaultKey();
  }

  private async meta(stored: StoredTargetCredential): Promise<TargetCredentialMeta> {
    // Metadata only: the redacted hint was stored at save time, so
    // listing never decrypts the vault envelope.
    return {
      id: stored.id,
      alias: stored.alias,
      kind: stored.kind,
      usernameHint: stored.usernameHint ?? "",
      hasSecret: true,
      createdAt: stored.createdAt,
      updatedAt: stored.updatedAt,
      lastUsedAt: stored.lastUsedAt,
    };
  }

  /** Metadata only — safe for the agent and the dashboard. */
  async list(owner: string): Promise<TargetCredentialMeta[]> {
    const stored = await this.db.list<StoredTargetCredential>(owner, KIND);
    return Promise.all(stored.map((item) => this.meta(item)));
  }

  /**
   * Create or replace the credential for an alias+kind. The plaintext secret
   * is encrypted before it touches the database; the response is metadata.
   */
  async save(
    owner: string,
    input: { alias: string; kind: TargetKind; username?: string; secret?: string },
  ): Promise<TargetCredentialMeta> {
    const alias = input.alias.trim();
    if (!alias) throw new AppError("Alias is required.", 422);
    if (!input.secret && !input.username)
      throw new AppError("Provide a username and/or secret.", 422);
    const now = new Date().toISOString();
    const existing = (
      await this.db.list<StoredTargetCredential>(owner, KIND)
    ).find((item) => item.alias === alias && item.kind === input.kind);
    const stored: StoredTargetCredential = {
      id: existing?.id ?? randomUUID(),
      alias,
      kind: input.kind,
      usernameHint: usernameHint(input.username ?? ""),
      vault: encryptSecret(
        JSON.stringify({ username: input.username ?? "", secret: input.secret ?? "" }),
        this.requireKey(),
      ),
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    await this.db.put(owner, KIND, stored);
    return this.meta(stored);
  }

  async remove(owner: string, id: string): Promise<void> {
    const stored = await this.db.get<StoredTargetCredential>(owner, KIND, id);
    if (!stored) throw new AppError("Credential not found", 404);
    await this.db.remove(owner, KIND, id);
  }

  private async find(
    owner: string,
    alias: string,
    kind: TargetKind,
  ): Promise<StoredTargetCredential | null> {
    const stored = await this.db.list<StoredTargetCredential>(owner, KIND);
    return stored.find((item) => item.alias === alias && item.kind === kind) ?? null;
  }

  /**
   * Decrypt for one immediate use. The callback receives the plaintext and
   * the secret is wiped afterwards. Plaintext never leaves this method
   * except into the callback's arguments.
   */
  async useSecrets<T>(
    owner: string,
    alias: string,
    kind: TargetKind,
    fn: (secrets: CredentialSecrets) => Promise<T>,
  ): Promise<T> {
    const stored = await this.find(owner, alias, kind);
    if (!stored)
      throw new AppError(`No saved credential for ${kind} target "${alias}".`, 404);
    let secrets: CredentialSecrets = {};
    try {
      secrets = JSON.parse(
        decryptSecret(stored.vault, this.requireKey()),
      ) as CredentialSecrets;
      const result = await fn({
        username: typeof secrets.username === "string" ? secrets.username : "",
        secret: typeof secrets.secret === "string" ? secrets.secret : "",
      });
      return result;
    } finally {
      secrets = {};
      await this.db
        .put(owner, KIND, { ...stored, lastUsedAt: new Date().toISOString() })
        .catch(() => undefined);
    }
  }
}
