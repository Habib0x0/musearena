export type Tone = "signal" | "mint" | "gold" | "danger" | "cyber" | "dim";

export function statusTone(status: string): Tone {
  if (["ready", "succeeded", "complete", "completed", "healthy"].includes(status)) return "mint";
  if (["failed", "quarantined", "blocked", "error"].includes(status)) return "danger";
  if (["exercising", "provisioning", "configuring", "verifying", "destroying"].includes(status)) return "gold";
  if (status === "pending") return "signal";
  return "dim";
}

export function formatDate(value?: string): string {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString([], { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function shortId(value?: string, chars = 12): string {
  if (!value) return "—";
  return value.length <= chars ? value : `${value.slice(0, chars)}…`;
}

export function percent(value?: number | null): string {
  return value === undefined || value === null || Number.isNaN(value) ? "—" : `${Math.round(value * 100)}%`;
}
