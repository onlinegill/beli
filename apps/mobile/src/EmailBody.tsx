import { Text } from "react-native";
import { s } from "./ui";
import { cleanPlainText } from "./emailText";

/**
 * Native fallback: HTML email rendering is web-only, so show cleaned plain
 * text -- `>` quote markers become indentation, blank lines collapse,
 * `*` emphasis markers and delimiter rows are tidied up.
 */
export default function EmailBody({ text }: { html?: string; text: string }) {
  if (!text?.trim()) return null;
  return (
    <Text selectable style={[s.text, { lineHeight: 25 }]}>
      {cleanPlainText(text)}
    </Text>
  );
}
