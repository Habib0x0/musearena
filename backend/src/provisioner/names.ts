// Pure naming helpers (no Node imports: safe inside the Temporal workflow bundle).
// One run → one network and one container per host, all derived from run_id.

const safe = (s: string) => s.toLowerCase().replace(/[^a-z0-9_.-]/g, "-");

export function runShortId(runId: string): string {
  return safe(runId.replace(/^run-/, "").slice(0, 8));
}

export function containerName(runId: string, hostId: string): string {
  return `ma-${runShortId(runId)}-${safe(hostId)}`;
}

export function networkName(runId: string): string {
  return `ma-${runShortId(runId)}-net`;
}

/** Red vantage: lives on the env network only, never on the host network. */
export const ATTACKER_HOST_ID = "attacker";
