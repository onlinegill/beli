/**
 * Owner API for the scheduler subsystem.
 *
 * - /api/scheduler-targets/* and /api/target-credentials/* are admin-only
 *   (see ADMIN_PATHS in app.ts): they manage infrastructure access.
 * - POST /api/target-credentials is the ONLY place a plaintext secret may
 *   be submitted. It is encrypted with AES-256-GCM before it touches the
 *   database, and the response carries metadata only.
 * - /api/scheduled-tasks/* is owner-scoped: the signed-in owner manages
 *   their own tasks.
 */
import { createHash } from "node:crypto";
import { Hono } from "hono";
import { z } from "zod";
import type { Config } from "../config.ts";
import type { Store } from "../db.ts";
import { TargetCredentialStore } from "./credentials.ts";
import { recentAuditRows } from "./run-state.ts";
import {
  createScheduledTask,
  deleteScheduledTask,
  getScheduledTask,
  listScheduledTasks,
  setTaskEnabled,
} from "./scheduled-tasks.ts";
import {
  deleteTarget,
  listTargets,
  registerTarget,
  updateTarget,
} from "./targets.ts";

const aliasSchema = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/);

const targetInputSchema = z.object({
  alias: aliasSchema,
  kind: z.enum(["ssh", "ha"]),
  host: z.string().max(253).optional(),
  port: z.number().int().min(1).max(65535).optional(),
  username: z.string().max(128).optional(),
  keyPath: z.string().max(512).optional(),
  backupCommand: z.string().max(2000).optional(),
  baseUrl: z.string().max(512).optional(),
});

const credentialInputSchema = z.object({
  alias: aliasSchema,
  kind: z.enum(["ssh", "ha"]),
  username: z.string().max(256).optional(),
  secret: z.string().max(4096).optional(),
});

const scheduledTaskInputSchema = z.object({
  name: z.string().min(1).max(160),
  kind: z.enum(["agent", "reminder"]).optional(),
  cron: z.string().max(100).optional(),
  runAt: z.string().max(64).optional(),
  prompt: z.string().min(1).max(12000),
  timezone: z.string().max(80).optional(),
  allowedTools: z.array(z.string()).max(8).optional(),
  allowedTargets: z
    .object({ ssh: z.array(aliasSchema).max(16).optional(), ha: z.array(aliasSchema).max(16).optional() })
    .optional(),
});

export function schedulerRoutes(
  db: Store,
  config: Config,
): Hono<{ Variables: { owner: string } }> {
  const app = new Hono<{ Variables: { owner: string } }>();
  const credentials = new TargetCredentialStore(db, config);

  // ---- Targets (admin only via ADMIN_PATHS) ----
  app.get("/api/scheduler-targets", async (c) =>
    c.json({ targets: await listTargets(db, c.get("owner")) }),
  );
  app.post("/api/scheduler-targets", async (c) => {
    const input = targetInputSchema.parse(await c.req.json());
    return c.json({ target: await registerTarget(db, c.get("owner"), input) }, 201);
  });
  app.patch("/api/scheduler-targets/:alias", async (c) => {
    const input = targetInputSchema.omit({ alias: true, kind: true }).parse(await c.req.json());
    return c.json({
      target: await updateTarget(db, c.get("owner"), c.req.param("alias"), input),
    });
  });
  app.delete("/api/scheduler-targets/:alias", async (c) => {
    await deleteTarget(db, c.get("owner"), c.req.param("alias"));
    return c.json({ deleted: c.req.param("alias") });
  });

  // ---- Credentials (admin only via ADMIN_PATHS; metadata-only responses) ----
  app.get("/api/target-credentials", async (c) =>
    c.json({ credentials: await credentials.list(c.get("owner")) }),
  );
  app.post("/api/target-credentials", async (c) => {
    const input = credentialInputSchema.parse(await c.req.json());
    return c.json({ credential: await credentials.save(c.get("owner"), input) }, 201);
  });
  app.delete("/api/target-credentials/:id", async (c) => {
    await credentials.remove(c.get("owner"), c.req.param("id"));
    return c.json({ deleted: c.req.param("id") });
  });

  // ---- Scheduled tasks (owner-scoped) ----
  app.get("/api/scheduled-tasks", async (c) =>
    c.json({ tasks: await listScheduledTasks(db, c.get("owner")) }),
  );
  app.post("/api/scheduled-tasks", async (c) => {
    const input = scheduledTaskInputSchema.parse(await c.req.json());
    return c.json(
      {
        task: await createScheduledTask(db, c.get("owner"), {
          ...input,
          createdBy: "api",
        }),
      },
      201,
    );
  });
  app.get("/api/scheduled-tasks/:id", async (c) => {
    const row = await getScheduledTask(db, c.get("owner"), c.req.param("id"));
    if (!row) return c.json({ error: "Scheduled task not found" }, 404);
    return c.json({ task: row });
  });
  app.post("/api/scheduled-tasks/:id/pause", async (c) =>
    c.json({ task: await setTaskEnabled(db, c.get("owner"), c.req.param("id"), false) }),
  );
  app.post("/api/scheduled-tasks/:id/resume", async (c) =>
    c.json({ task: await setTaskEnabled(db, c.get("owner"), c.req.param("id"), true) }),
  );
  app.delete("/api/scheduled-tasks/:id", async (c) => {
    await deleteScheduledTask(db, c.get("owner"), c.req.param("id"));
    return c.json({ deleted: c.req.param("id") });
  });
  app.get("/api/scheduled-tasks-runs", async (c) => {
    const limit = Math.min(Math.max(Number(c.req.query("limit") ?? 50), 1), 200);
    return c.json({ runs: await recentAuditRows(db, c.get("owner"), limit) });
  });


  // ---- One-time credential setup links ----
  // Public by token, single-use, 30-minute expiry. The owner mints a link
  // server-side; the setup page posts the secret straight into the encrypted
  // vault. Secrets never pass through chat or the model.
  const SETUP_KIND = "credential-setup-tokens";

  function setupPage(label: string, error?: string): string {
    const err = error ? `<p style="color:#b00">${error}</p>` : "";
    return `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Save credential</title></head><body style="font-family:sans-serif;max-width:440px;margin:40px auto;padding:0 16px"><h2>Save credential</h2><p>Paste the token for <b>${label}</b>. It is encrypted on save and never shown again.</p>${err}<form method="post"><input type="password" name="secret" autocomplete="off" placeholder="Paste token here" style="width:100%;padding:12px;font-size:16px;box-sizing:border-box" required><br><br><button type="submit" style="padding:12px 24px;font-size:16px">Save securely</button></form></body></html>`;
  }

  async function getSetupToken(c: { req: { param: (k: string) => string } }) {
    const id = createHash("sha256").update(c.req.param("token")).digest("hex");
    const rec = await db
      .get<{
        id: string;
        owner: string;
        alias: string;
        kind: "ssh" | "ha";
        label: string;
        expiresAt: string;
      }>("admin", SETUP_KIND, id)
      .catch(() => null);
    if (!rec || Date.parse(rec.expiresAt) < Date.now()) return null;
    return { id, rec };
  }

  app.get("/setup/credential/:token", async (c) => {
    const found = await getSetupToken(c);
    if (!found) return c.html("<h1>Link expired or invalid</h1><p>Ask for a fresh setup link.</p>", 410);
    return c.html(setupPage(found.rec.label));
  });

  app.post("/setup/credential/:token", async (c) => {
    const found = await getSetupToken(c);
    if (!found) return c.html("<h1>Link expired or invalid</h1><p>Ask for a fresh setup link.</p>", 410);
    const body = await c.req.parseBody();
    const secret = String(body["secret"] ?? "").trim();
    if (!secret) return c.html(setupPage(found.rec.label, "Paste the token before saving."), 422);
    try {
      await credentials.save(found.rec.owner, { alias: found.rec.alias, kind: found.rec.kind, secret });
    } catch (e) {
      return c.html(setupPage(found.rec.label, e instanceof Error ? e.message : "Save failed."), 500);
    }
    await db.remove("admin", SETUP_KIND, found.id).catch(() => undefined);
    return c.html("<h1>Saved</h1><p>The credential is encrypted and stored. You can close this page.</p>");
  });

  return app;
}
