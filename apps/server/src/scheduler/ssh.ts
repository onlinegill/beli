/**
 * SSH execution for the scheduler capability tools.
 *
 * Auth order: key file when the target configures keyPath, otherwise the
 * stored password (SSH_ASKPASS). The password lives only in a 0600 temp
 * askpass script for the duration of the spawn and is deleted immediately
 * after; it never appears in logs, tool results, or the audit table.
 *
 * Command classification is deterministic and fail-closed: anything that is
 * not recognizably read-only counts as mutating, and mutating commands need
 * a completed backup (policy gate) plus owner approval in chat.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export type CommandClass = "readonly" | "mutating";

/** First token of the command, lowercased, without sudo prefix. */
function firstWord(command: string): string {
  const trimmed = command.trim().replace(/^sudo\s+/, "");
  const match = /^([a-zA-Z0-9_.\-/]+)/.exec(trimmed);
  const base = (match?.[1] ?? "").split("/").pop() ?? "";
  return base.toLowerCase();
}

/**
 * Substrings that make a command mutating regardless of the leading tool.
 * Conservative on purpose: unknown shapes fail closed to "mutating".
 */
const MUTATING_FRAGMENTS = [
  "apt-get install",
  "apt-get remove",
  "apt-get purge",
  "apt-get upgrade",
  "apt-get dist-upgrade",
  "apt install",
  "apt remove",
  "apt purge",
  "apt upgrade",
  "apt full-upgrade",
  "reboot",
  "shutdown",
  "poweroff",
  "halt",
  "systemctl start",
  "systemctl stop",
  "systemctl restart",
  "systemctl reload",
  "systemctl enable",
  "systemctl disable",
  "systemctl mask",
  "service ",
  "ha core update",
  "ha core restart",
  "ha core rebuild",
  "ha host reboot",
  "ha host shutdown",
  "ha host update",
  "ha supervisor update",
  "ha backups restore",
  "docker run",
  "docker rm",
  "docker rmi",
  "docker stop",
  "docker restart",
  "docker update",
  "docker compose up",
  "docker-compose up",
  "rm ",
  "rmdir",
  "mv ",
  "cp ",
  "ln ",
  "chmod",
  "chown",
  "chgrp",
  "tee ",
  "dd ",
  "mkfs",
  "mount ",
  "umount",
  "useradd",
  "usermod",
  "userdel",
  "passwd",
  "crontab",
  "wget ",
  "curl ",
  "pip install",
  "npm install",
  "npm uninstall",
  ">",
  ">>",
];

/** Commands that are read-only by shape even though fragments above match. */
const READONLY_ALLOW = [
  // NOTE: `apt update` is intentionally NOT here: refreshing the
  // package index is a write. The read-only update checker
  // (server_check_updates) uses `apt list --upgradable` instead.
  /^apt(-get)?\s+(list|show|search|policy)\b/,
  /^systemctl\s+(status|is-active|is-enabled|list-units|show)\b/,
  /^service\s+\S+\s+status\b/,
  /^curl\s+.*--head\b/,
  /^wget\s+--spider\b/,
];

const READONLY_COMMANDS = new Set([
  "apt",
  "apt-get",
  "cat",
  "df",
  "docker", // narrowed below: only ps/images/inspect/version/info
  "du",
  "echo",
  "env",
  "free",
  "grep",
  "ha", // narrowed below
  "head",
  "id",
  "ip",
  "journalctl",
  "ls",
  "lscpu",
  "lsblk",
  "ps",
  "pwd",
  "ss",
  "stat",
  "systemctl", // narrowed below
  "tail",
  "top",
  "uname",
  "uptime",
  "wc",
  "which",
  "whoami",
]);

function readonlyByShape(command: string): boolean {
  const word = firstWord(command);
  if (!READONLY_COMMANDS.has(word)) return false;
  const stripped = command.trim().replace(/^sudo\s+/, "");
  const lowered = ` ${stripped.toLowerCase()} `;
  for (const fragment of MUTATING_FRAGMENTS) {
    if (lowered.includes(fragment)) {
      // Explicit read-only shapes win back their allow-listing.
      if (READONLY_ALLOW.some((re) => re.test(stripped))) return true;
      return false;
    }
  }
  if (word === "docker" && !/^docker\s+(ps|images|inspect|version|info)\b/.test(stripped))
    return false;
  if (
    word === "ha" &&
    !/^ha\s+(core\s+(check|info|logs)|host\s+info|supervisor\s+info|backups\s+list|info)\b/.test(
      stripped,
    )
  )
    return false;
  if (
    word === "systemctl" &&
    !/^systemctl\s+(status|is-active|is-enabled|list-units|show)\b/.test(stripped)
  )
    return false;
  if (
    (word === "apt" || word === "apt-get") &&
    !/^apt(-get)?\s+(list|show|search|policy)\b/.test(stripped)
  )
    return false;
  return true;
}

export function classifyCommand(command: string): CommandClass {
  if (!command || !command.trim()) return "mutating";
  return readonlyByShape(command) ? "readonly" : "mutating";
}

export interface SshTarget {
  host: string;
  port: number;
  username: string;
  keyPath?: string;
}

export interface SshResult {
  ok: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

const MAX_OUTPUT = 8192;

function truncate(text: string): string {
  if (text.length <= MAX_OUTPUT) return text;
  return text.slice(0, MAX_OUTPUT) + `\n…[truncated to ${MAX_OUTPUT} chars]`;
}

function spawnAndWait(
  argv0: string,
  argv: string[],
  env: NodeJS.ProcessEnv,
  timeoutMs: number,
): Promise<SshResult> {
  return new Promise((resolve) => {
    const child = spawn(argv0, argv, { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    timer.unref?.();
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({
        ok: false,
        exitCode: null,
        stdout: "",
        stderr: `ssh failed: ${error.message}`,
        timedOut,
      });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        ok: !timedOut && code === 0,
        exitCode: code,
        stdout: truncate(stdout),
        stderr: truncate(stderr),
        timedOut,
      });
    });
  });
}

/**
 * Run a command over SSH. Prefers key auth; falls back to the stored
 * password via SSH_ASKPASS when no keyPath is configured.
 */
export async function sshExec(
  target: SshTarget,
  command: string,
  options: { password?: string; timeoutMs?: number } = {},
): Promise<SshResult> {
  const timeoutMs = Math.min(Math.max(options.timeoutMs ?? 30000, 1000), 120000);
  const usePassword = !target.keyPath && !!options.password;
  const argv = [
    "-p",
    String(target.port),
    "-o",
    "ConnectTimeout=10",
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    "LogLevel=ERROR",
  ];
  // BatchMode stays on for key auth only: it would suppress the askpass
  // helper on the password path.
  if (!usePassword) argv.push("-o", "BatchMode=yes");
  if (target.keyPath) argv.push("-i", target.keyPath);
  argv.push(`${target.username}@${target.host}`, "--", command);

  if (!usePassword) {
    return spawnAndWait("/usr/bin/ssh", argv, { ...process.env }, timeoutMs);
  }
  // Password fallback: a 0600 askpass script holding the password, deleted
  // immediately after the spawn. `setsid` detaches from any tty so OpenSSH
  // actually consults the askpass helper.
  const dir = mkdtempSync(join(tmpdir(), "om-ssh-askpass-"));
  const script = join(dir, "askpass.sh");
  try {
    writeFileSync(script, `#!/bin/sh\nprintf '%s' "$OM_SSH_ASKPASS_PASSWORD"\n`, {
      mode: 0o700,
    });
    const env = {
      ...process.env,
      SSH_ASKPASS: script,
      SSH_ASKPASS_REQUIRE: "force",
      OM_SSH_ASKPASS_PASSWORD: options.password,
      DISPLAY: "",
    };
    return await spawnAndWait("setsid", ["/usr/bin/ssh", ...argv], env, timeoutMs);
  } finally {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // best effort cleanup
    }
  }
}
