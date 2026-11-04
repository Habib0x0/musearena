import { useEffect, useState } from "react";
import { supabase } from "../lib/supabase";

export interface LiveEvent { at: string; kind: "progress" | "alert" | "score"; text: string; }

/** Real Supabase Realtime subscription on the runs table for one run_id. */
export function useLiveRun(runId: string, active: boolean) {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  useEffect(() => {
    if (!active || !runId) return;
    const channel = supabase()
      .channel(`run:${runId}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "runs", filter: `run_id=eq.${runId}` },
        (payload) => {
          const row = (payload.new ?? {}) as { score?: unknown };
          setEvents((e) => [...e, {
            at: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
            kind: "score",
            text: row.score ? `score updated: ${JSON.stringify(row.score).slice(0, 120)}` : `${payload.eventType} on run ${runId}`,
          }]);
        })
      .subscribe();
    return () => { void supabase().removeChannel(channel); };
  }, [runId, active]);
  return events;
}

/**
 * Realtime deployment progress (Req §6.5): invalidates the deployment queries
 * on every row change so status/drift/access re-render without polling, and
 * keeps a short local history of status transitions for the logs tab.
 */
export function useLiveDeployment(deploymentId: string, onChange: () => void) {
  const [history, setHistory] = useState<LiveEvent[]>([]);
  useEffect(() => {
    if (!deploymentId) return;
    const channel = supabase()
      .channel(`deployment:${deploymentId}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "deployments", filter: `id=eq.${deploymentId}` },
        (payload) => {
          const row = (payload.new ?? {}) as { status?: string; drift_status?: string | null };
          setHistory((h) => [...h, { at: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }), kind: "progress", text: `status ${row.status ?? "?"}${row.drift_status ? ` · drift ${row.drift_status}` : ""}` }]);
          onChange();
        })
      .subscribe();
    return () => { void supabase().removeChannel(channel); };
  }, [deploymentId, onChange]);
  return history;
}
