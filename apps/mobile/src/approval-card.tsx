import { ShieldAlert } from "lucide-react-native";
import { useEffect, useRef, useState } from "react";
import { Text, View } from "react-native";
import type { MuseApi } from "./api";
import { Button, Card, colors, s } from "./ui";

export interface PendingApproval {
  id: string;
  toolName: string;
  summary: string;
  createdAt: number;
  expiresAt: number;
}

/**
 * In-chat approval cards. While a chat turn is blocked on owner approval,
 * the server holds the exact proposed tool call and this polls
 * /api/chat/approvals to render an Approve/Deny card for each held call.
 * Approving replays the held call with its original arguments — the agent
 * never re-issues it, so approvals cannot drift onto changed arguments.
 */
export function PendingApprovals({
  api,
  threadId,
  active,
}: {
  api: MuseApi;
  threadId: string;
  active: boolean;
}) {
  const [approvals, setApprovals] = useState<PendingApproval[]>([]);
  const [deciding, setDeciding] = useState<string | null>(null);
  const decidingRef = useRef<string | null>(null);

  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    const load = async () => {
      try {
        const res = await api.request<{ approvals: PendingApproval[] }>(
          `/api/chat/approvals?threadId=${encodeURIComponent(threadId)}`,
        );
        if (!cancelled) setApprovals(res.approvals ?? []);
      } catch {
        // Transient network error — keep the last known cards.
      }
    };
    void load();
    const timer = setInterval(() => {
      void load();
    }, 2500);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [api, threadId, active]);

  if (approvals.length === 0) return null;

  const decide = (id: string, decision: "approve" | "deny") => {
    if (decidingRef.current) return;
    decidingRef.current = id;
    setDeciding(id);
    // Optimistic: drop the card immediately; the next poll confirms.
    setApprovals((prev) => prev.filter((approval) => approval.id !== id));
    void api
      .request(`/api/chat/approvals/${id}/${decision}`, {}, "POST")
      .catch(() => {
        // The decide failed (already settled/expired) — the next poll
        // refreshes the true state.
      })
      .finally(() => {
        decidingRef.current = null;
        setDeciding(null);
      });
  };

  return (
    <View style={{ gap: 8, marginBottom: 10 }}>
      {approvals.map((approval) => (
        <Card
          key={approval.id}
          style={{ borderColor: colors.blueDark, borderWidth: 1 }}
        >
          <View style={[s.row, { gap: 8 }]}>
            <ShieldAlert size={18} color={colors.blueDark} />
            <Text style={[s.heading, { flex: 1 }]}>Approval needed</Text>
          </View>
          <Text style={[s.text, { marginTop: 6 }]}>{approval.summary}</Text>
          <Text style={[s.small, { marginTop: 4 }]}>{approval.toolName}</Text>
          <View style={[s.row, { gap: 8, marginTop: 10 }]}>
            <Button
              primary
              small
              busy={deciding === approval.id}
              onPress={() => decide(approval.id, "approve")}
            >
              Approve
            </Button>
            <Button
              danger
              small
              disabled={deciding === approval.id}
              onPress={() => decide(approval.id, "deny")}
            >
              Deny
            </Button>
          </View>
        </Card>
      ))}
    </View>
  );
}
