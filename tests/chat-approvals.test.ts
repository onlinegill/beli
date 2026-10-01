import assert from "node:assert/strict";
import { test } from "node:test";
import type { ToolDefinition } from "@copilotkit/runtime/v2";
import { z } from "zod";
import {
  awaitChatApproval,
  decideHeldApproval,
  describeApproval,
  listHeldApprovals,
  withPolicy,
} from "../apps/server/src/engine/tool-policy.ts";

function stubTool(
  name: string,
  schema: z.ZodType,
  calls: { count: number; lastArgs: unknown },
): ToolDefinition {
  return {
    name,
    description: `${name} tool`,
    parameters: schema,
    execute: async (raw: unknown) => {
      calls.count += 1;
      calls.lastArgs = raw;
      return { ok: true };
    },
  };
}

function base(owner: string, threadId: string) {
  return {
    owner,
    scope: `chat:test`,
    threadId,
    awaitChatApproval,
  };
}

/** Wait until the held record for an in-flight execute appears. */
async function heldId(owner: string, threadId: string): Promise<string> {
  for (let i = 0; i < 200; i++) {
    const found = listHeldApprovals(owner, threadId);
    if (found.length > 0) return found[0].id;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("held approval never appeared");
}

test("chat approval: Approve replays the exact proposed call once", async () => {
  const calls = { count: 0, lastArgs: undefined as unknown };
  const wrapped = withPolicy(
    stubTool("run_computer_command", z.object({ command: z.string() }), calls),
    base("chat-owner-1", "thread-1"),
  );
  const execute = wrapped.execute as (args: unknown) => Promise<unknown>;
  const pending = execute({ command: "ls -la" });
  const id = await heldId("chat-owner-1", "thread-1");
  const [listed] = listHeldApprovals("chat-owner-1", "thread-1");
  assert.equal(listed.id, id);
  assert.match(listed.summary, /ls -la/);
  assert.equal(decideHeldApproval("chat-owner-1", id, "approved"), true);
  const result = (await pending) as { ok?: boolean; error?: string };
  assert.equal(result.ok, true);
  assert.equal(calls.count, 1);
  // The held call ran with its ORIGINAL arguments — nothing re-issued.
  assert.deepEqual(calls.lastArgs, { command: "ls -la" });
  assert.equal(listHeldApprovals("chat-owner-1", "thread-1").length, 0);
});

test("chat approval: Deny never runs the handler", async () => {
  const calls = { count: 0, lastArgs: undefined as unknown };
  const wrapped = withPolicy(
    stubTool("run_computer_command", z.object({ command: z.string() }), calls),
    base("chat-owner-2", "thread-2"),
  );
  const execute = wrapped.execute as (args: unknown) => Promise<unknown>;
  const pending = execute({ command: "rm -rf /" });
  const id = await heldId("chat-owner-2", "thread-2");
  assert.equal(decideHeldApproval("chat-owner-2", id, "denied"), true);
  const result = (await pending) as { error?: string };
  assert.match(result.error ?? "", /denied/i);
  assert.equal(calls.count, 0);
});

test("chat approval: only the owning owner can decide; unknown ids fail", async () => {
  const calls = { count: 0, lastArgs: undefined as unknown };
  const wrapped = withPolicy(
    stubTool("run_computer_command", z.object({ command: z.string() }), calls),
    base("chat-owner-3", "thread-3"),
  );
  const execute = wrapped.execute as (args: unknown) => Promise<unknown>;
  const pending = execute({ command: "ls" });
  const id = await heldId("chat-owner-3", "thread-3");
  assert.equal(decideHeldApproval("someone-else", id, "approved"), false);
  assert.equal(decideHeldApproval("chat-owner-3", "no-such-id", "approved"), false);
  // Still held, still undecided — the rightful owner can still approve.
  assert.equal(listHeldApprovals("chat-owner-3", "thread-3").length, 1);
  assert.equal(decideHeldApproval("chat-owner-3", id, "approved"), true);
  assert.equal(((await pending) as { ok?: boolean }).ok, true);
  assert.equal(calls.count, 1);
});

test("chat approval: duplicate identical calls share one card", async () => {
  const calls = { count: 0, lastArgs: undefined as unknown };
  const wrapped = withPolicy(
    stubTool("run_computer_command", z.object({ command: z.string() }), calls),
    base("chat-owner-4", "thread-4"),
  );
  const execute = wrapped.execute as (args: unknown) => Promise<unknown>;
  const first = execute({ command: "ls" });
  const second = execute({ command: "ls" });
  const id = await heldId("chat-owner-4", "thread-4");
  // One card, not two.
  assert.equal(listHeldApprovals("chat-owner-4", "thread-4").length, 1);
  assert.equal(decideHeldApproval("chat-owner-4", id, "approved"), true);
  assert.equal(((await first) as { ok?: boolean }).ok, true);
  assert.equal(((await second) as { ok?: boolean }).ok, true);
  assert.equal(calls.count, 2);
});

test("describeApproval: summaries name the action and redact secrets", () => {
  assert.match(
    describeApproval("browser_login", { label: "Lok Sanjh", sessionId: "s1" }),
    /Lok Sanjh/,
  );
  // Typed text is never echoed — it may be a password or code.
  const typed = describeApproval("browser_input", {
    sessionId: "s1",
    type: "type",
    text: "s3cr3t-p4ssw0rd",
  });
  assert.ok(!typed.includes("s3cr3t-p4ssw0rd"), "typed text must not appear");
  assert.match(
    describeApproval("browser_input", { sessionId: "s1", type: "key", key: "Enter" }),
    /Enter/,
  );
  const email = describeApproval("email_send", {
    to: ["a@example.com"],
    subject: "Hello",
    body: "secret body text",
  });
  assert.match(email, /a@example.com/);
  assert.match(email, /Hello/);
  assert.ok(!email.includes("secret body text"), "email body must not appear");
  const cmd = describeApproval("run_computer_command", { command: "ls" });
  assert.match(cmd, /ls/);
});
