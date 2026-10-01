import type { ReactNode } from "react";
import Markdown from "react-native-markdown-display";
import { colors } from "./ui";

/**
 * Renders an assistant chat message as markdown so lists, bold, code and
 * links show formatted instead of raw. User messages stay plain text.
 */
export function AssistantMarkdown({ text }: { text: string }): ReactNode {
  return (
    <Markdown
      style={{
        body: { fontSize: 15, lineHeight: 23, color: colors.text },
        paragraph: { marginTop: 0, marginBottom: 10 },
        heading1: { fontSize: 19, lineHeight: 26, color: colors.text, marginBottom: 8 },
        heading2: { fontSize: 17, lineHeight: 24, color: colors.text, marginBottom: 8 },
        heading3: { fontSize: 16, lineHeight: 23, color: colors.text, marginBottom: 6 },
        strong: { fontWeight: "700", color: colors.text },
        em: { fontStyle: "italic", color: colors.text },
        bullet_list: { marginBottom: 10 },
        ordered_list: { marginBottom: 10 },
        list_item: { flexDirection: "row", marginBottom: 4 },
        bullet_list_content: { flex: 1 },
        ordered_list_content: { flex: 1 },
        code_inline: {
          fontFamily: "monospace",
          backgroundColor: "#F1F2F4",
          borderRadius: 4,
          paddingHorizontal: 4,
          color: colors.text,
        },
        fence: {
          fontFamily: "monospace",
          fontSize: 13,
          lineHeight: 19,
          backgroundColor: "#F1F2F4",
          borderRadius: 8,
          padding: 10,
          marginBottom: 10,
          color: colors.text,
        },
        blockquote: {
          borderLeftWidth: 3,
          borderLeftColor: colors.line,
          paddingLeft: 10,
          marginBottom: 10,
        },
        link: { color: colors.blueDark, textDecorationLine: "underline" },
        hr: { backgroundColor: colors.line, height: 1, marginVertical: 10 },
      }}
    >
      {text}
    </Markdown>
  );
}
