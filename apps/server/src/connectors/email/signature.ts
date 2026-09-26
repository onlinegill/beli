/**
 * Work-email identity rule: mail sent from the configured work address is
 * always signed with the configured work signature, never the personal one.
 *
 * Configure via environment:
 *   WORK_EMAIL_ADDRESS   e.g. "you@company.com"  (default "work@example.com")
 *   WORK_SIGNATURE       e.g. "Your Name"         (default "Work Signature")
 *   PERSONAL_SIGNATURE   e.g. "Nickname"          (default "Personal Name")
 *
 * Applied inside the send path (EmailService.send and the Gmail send branch),
 * so every transport — the agent's email.send tool, the reviewed action flow,
 * and calendar invites — carries the right signature without the caller
 * having to remember it.
 */
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export const WORK_EMAIL_ADDRESS = (
  process.env.WORK_EMAIL_ADDRESS ?? "work@example.com"
).trim().toLowerCase();
const WORK_SIGNATURE = (process.env.WORK_SIGNATURE ?? "Work Signature").trim();
const PERSONAL_SIGNATURE = (
  process.env.PERSONAL_SIGNATURE ?? "Personal Name"
).trim();

/**
 * Enforce the work-email signature on an outgoing body. Non-work senders are
 * returned untouched. For the work address: a trailing personal sign-off is
 * replaced, an existing work sign-off is kept, otherwise the signature
 * is appended. Only the signature position (last non-empty line) is ever
 * touched — mentions of the personal name elsewhere in the body are left alone.
 */
export function applyWorkSignature(body: string, fromAddress: string): string {
  if (fromAddress.trim().toLowerCase() !== WORK_EMAIL_ADDRESS) return body;
  const lines = body.split("\n");
  let last = lines.length - 1;
  while (last >= 0 && lines[last].trim() === "") last--;
  if (last >= 0) {
    const signature = lines[last].trim();
    if (new RegExp(`^${escapeRegExp(WORK_SIGNATURE)}$`, "i").test(signature))
      return body;
    if (
      new RegExp(`^${escapeRegExp(PERSONAL_SIGNATURE)}(\\s+\\S+)?$`, "i").test(
        signature,
      )
    ) {
      lines[last] = WORK_SIGNATURE;
      return lines.join("\n");
    }
  }
  return `${body.replace(/\s+$/, "")}\n\n${WORK_SIGNATURE}`;
}
