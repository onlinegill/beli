/**
 * Work-email identity rule: mail sent from support@prosperanetworks.com is
 * always signed "Paul Gill", never "Sukhpal".
 *
 * Applied inside the send path (EmailService.send and the Gmail send branch),
 * so every transport — the agent's email.send tool, the reviewed action flow,
 * and calendar invites — carries the right signature without the caller
 * having to remember it.
 */
export const WORK_EMAIL_ADDRESS = "support@prosperanetworks.com";
const WORK_SIGNATURE = "Paul Gill";

/**
 * Enforce the work-email signature on an outgoing body. Non-work senders are
 * returned untouched. For the work address: a trailing "Sukhpal" sign-off is
 * replaced, an existing "Paul Gill" sign-off is kept, otherwise the signature
 * is appended. Only the signature position (last non-empty line) is ever
 * touched — mentions of Sukhpal elsewhere in the body are left alone.
 */
export function applyWorkSignature(body: string, fromAddress: string): string {
  if (fromAddress.trim().toLowerCase() !== WORK_EMAIL_ADDRESS) return body;
  const lines = body.split("\n");
  let last = lines.length - 1;
  while (last >= 0 && lines[last].trim() === "") last--;
  if (last >= 0) {
    const signature = lines[last].trim();
    if (/^paul gill$/i.test(signature)) return body;
    if (/^sukhpal(\s+gill)?$/i.test(signature)) {
      lines[last] = WORK_SIGNATURE;
      return lines.join("\n");
    }
  }
  return `${body.replace(/\s+$/, "")}\n\n${WORK_SIGNATURE}`;
}
