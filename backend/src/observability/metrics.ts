import { createServer, type Server } from "node:http";

/**
 * Worker metrics (Prometheus text exposition). Counters are process-level and
 * incremented where work actually happens, so per-run event stores (which are
 * discarded after export) still show up here.
 */
const counters = new Map<string, number>();

export function incr(name: string, labels: Record<string, string> = {}, by = 1): void {
  const key = `${name}${Object.keys(labels).length ? `{${Object.entries(labels).map(([k, v]) => `${k}="${v.replace(/["\\\n]/g, "_")}"`).join(",")}}` : ""}`;
  counters.set(key, (counters.get(key) ?? 0) + by);
}

const HELP: Record<string, string> = {
  arena_exercises_total: "Live exercises completed",
  arena_objectives_achieved_total: "Objectives achieved by red (verified)",
  arena_alerts_total: "Promoted-rule alerts raised by blue",
  arena_false_positives_total: "Alerts on benign telemetry",
  arena_telemetry_events_total: "Collected out-of-band telemetry events",
  arena_gate_decisions_total: "Canary/proof gate decisions",
};

export function prometheusMetrics(): string {
  const lines: string[] = [];
  const names = [...new Set([...Object.keys(HELP), ...[...counters.keys()].map((k) => k.split("{")[0])])];
  for (const n of names) {
    lines.push(`# HELP ${n} ${HELP[n] ?? n}`, `# TYPE ${n} counter`);
    const series = [...counters.entries()].filter(([k]) => k === n || k.startsWith(`${n}{`));
    if (!series.length) lines.push(`${n} 0`);
    for (const [k, v] of series) lines.push(`${k} ${v}`);
  }
  return lines.join("\n") + "\n";
}

/**
 * /metrics must bind an address the platform Prometheus can reach: it scrapes
 * `host.docker.internal:<port>`, which is the host bridge — never loopback.
 * Binding 127.0.0.1 left the `musearena-worker` target permanently down.
 */
export function metricsServer(port = Number(process.env.WORKER_METRICS_PORT ?? 9464), host = process.env.WORKER_METRICS_HOST ?? "0.0.0.0"): Server {
  const s = createServer((req, res) => {
    if (req.url !== "/metrics") { res.writeHead(404).end(); return; }
    res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4" }).end(prometheusMetrics());
  });
  s.listen(port, host);
  return s;
}
