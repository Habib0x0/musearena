import type { EnvironmentSpec } from "@musearena/shared";

// Deterministic pre-flight estimate (live pricing APIs replace the table in
// T-10; the shape — $/hour per instance + buffer — stays).
const HOURLY: Record<string, number> = { vm: 0.42, container: 0.09 };
// Per-role VM estimate (T-17): a gateway or log collector is much cheaper than
// a web/db tier. Unknown roles fall back to the flat VM rate.
const VM_ROLE_HOURLY: Record<string, number> = {
  gateway: 0.26, dc: 0.32, mail: 0.34, web: 0.44, db: 0.52, sensor: 0.24, workstation: 0.30, attacker: 0.40,
};
const DB_HOURLY = 0.18;

export function estimateCostPerHour(spec: EnvironmentSpec): number {
  let total = 0;
  for (const inst of spec.instances) {
    total += inst.runtime === "vm" ? (VM_ROLE_HOURLY[inst.role] ?? HOURLY.vm) : HOURLY.container;
    total += inst.databases.length * DB_HOURLY;
  }
  // 20% buffer per design doc provisioning defaults.
  return Math.round(total * 1.2 * 100) / 100;
}

export function estimateCost(spec: EnvironmentSpec): { perHour: number; ttlTotal: number } {
  const perHour = estimateCostPerHour(spec);
  return { perHour, ttlTotal: Math.round(perHour * spec.budgets.ttlHours * 100) / 100 };
}
