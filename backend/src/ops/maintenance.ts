import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { EnvironmentSpec } from "@musearena/shared";
import { serviceClient } from "../lib/supabase.js";
import { audit } from "../lib/audit.js";
import { teardownEnvironment, vmLifecycleFor, vmStateRoot } from "../provisioner/deploy.js";
import { ttlExpiredDeployments } from "../observability/recorder.js";
import { runDriftJob } from "./jobs.js";
import type { ObservedInstance } from "./drift.js";
import { containerName } from "../provisioner/names.js";
import { destroyRunVms, listVmRuns, readVmRunState, type VmRunState } from "../provisioner/vm-lifecycle.js";
import { checkSpecReadiness } from "../configurator/readiness.js";
import { deploymentOwnedByWorker, workerRoutingConfig, type WorkerRoutingConfig } from "../lib/worker-routing.js";
import type { AccessInfo } from "../provisioner/deployment-status.js";

const run = promisify(execFile);

/**
 * Hourly maintenance (design: orphan sweeper; Req §2.5 TTL, §6.4 drift).
 *
 * Source of truth for "what exists" is the runtime itself (Docker labels the
 * provisioner stamps on every resource), compared against the deployments
 * table — never the DB alone, which cannot see leaks.
 */
interface LiveResource { kind: "container" | "network"; id: string; runId: string; org: string; ttlHours: number; createdMs: number }

async function dockerJson(docker: string, args: string[]): Promise<string[]> {
  const { stdout } = await run(docker, args, { timeout: 30_000 }).catch(() => ({ stdout: "" }));
  return stdout.split("\n").filter(Boolean);
}

export async function liveArenaResources(docker = "docker"): Promise<LiveResource[]> {
  const out: LiveResource[] = [];
  const containers = await dockerJson(docker, ["ps", "-a", "--filter", "label=arena.run_id", "--format", "{{.ID}}"]);
  const networks = await dockerJson(docker, ["network", "ls", "--filter", "label=arena.run_id", "--format", "{{.ID}}"]);
  for (const [kind, ids] of [["container", containers], ["network", networks]] as const) {
    if (!ids.length) continue;
    const { stdout } = await run(docker, [kind === "container" ? "inspect" : "network", ...(kind === "network" ? ["inspect"] : []), ...ids], { maxBuffer: 32 * 1024 * 1024 });
    for (const o of JSON.parse(stdout) as { Id: string; Created: string; Config?: { Labels?: Record<string, string> }; Labels?: Record<string, string> }[]) {
      const labels = o.Config?.Labels ?? o.Labels ?? {};
      out.push({ kind, id: o.Id, runId: labels["arena.run_id"], org: labels["arena.org"], ttlHours: Number(labels["arena.ttl_hours"]), createdMs: Date.parse(o.Created) });
    }
  }
  return out;
}

export interface SweepReport { orphans: { runId: string; reason: string; removed: string[] }[] }

/**
 * Orphans = labelled runtime resources whose run has no live deployment row
 * (destroyed/failed/missing), or that are past their stamped TTL. Removed
 * directly at the runtime and audited — the DB said they should not exist.
 */
export async function sweepOrphanResources(opts: { docker?: string; now?: number; dryRun?: boolean; routing?: WorkerRoutingConfig } = {}): Promise<SweepReport> {
  const docker = opts.docker ?? "docker";
  const now = opts.now ?? Date.now();
  const routing = opts.routing ?? workerRoutingConfig();
  const resources = await liveArenaResources(docker);
  const runIds = [...new Set(resources.map((r) => r.runId))];
  if (!runIds.length) return { orphans: [] };
  const sb = serviceClient();
  const depIds = runIds.map((r) => r.replace(/^run-/, ""));
  const { data, error } = await sb.from("deployments").select("id, status, access_info").in("id", depIds.filter((d) => /^[0-9a-f-]{36}$/.test(d)));
  if (error) throw new Error(`sweep: deployment lookup failed: ${error.message}`);
  const deployments = new Map((data ?? []).map((d) => [`run-${d.id}`, d as { status: string; access_info?: AccessInfo | null }]));
  const report: SweepReport = { orphans: [] };
  for (const runId of runIds) {
    const res = resources.filter((r) => r.runId === runId);
    const dep = deployments.get(runId);
    const st = dep?.status;
    const ttlExpired = res.some((r) => Number.isFinite(r.ttlHours) && now - r.createdMs > r.ttlHours * 3_600_000);
    // Terminal/missing rows are local orphans here. A merely TTL-expired live
    // row belongs to its stamped owner, whose workflow performs teardown.
    const reason = !st ? "no deployment row" : st === "destroyed" || st === "failed" ? `deployment ${st}` : ttlExpired && deploymentOwnedByWorker(dep?.access_info ?? {}, routing) ? "past TTL" : "";
    if (!reason) continue;
    const removed: string[] = [];
    if (!opts.dryRun) {
      for (const r of res.filter((x) => x.kind === "container")) if (await run(docker, ["rm", "-f", r.id]).then(() => true, () => false)) removed.push(r.id.slice(0, 12));
      for (const r of res.filter((x) => x.kind === "network")) if (await run(docker, ["network", "rm", r.id]).then(() => true, () => false)) removed.push(r.id.slice(0, 12));
      const org = res[0].org ?? "unknown";
      await audit({ orgId: org, actor: "sweeper", action: "DEPLOYMENT_DESTROY", subjectType: "run", subjectId: runId, detail: { orphan: true, reason, removed } });
    }
    report.orphans.push({ runId, reason, removed });
  }
  return report;
}

/** Observed state for drift: per container host, the services actually listening. */
export async function observeDockerState(spec: EnvironmentSpec, runId: string, docker = "docker"): Promise<ObservedInstance[]> {
  const out: ObservedInstance[] = [];
  for (const i of spec.instances.filter((x) => x.runtime === "container")) {
    const name = containerName(runId, i.hostId);
    const { stdout: state } = await run(docker, ["inspect", "-f", "{{.State.Running}}", name]).catch(() => ({ stdout: "false" }));
    if (state.trim() !== "true") continue; // missing host → reported as drift
    const services: string[] = [];
    // Probe the canonical listener for each declared service; only what answers is observed.
    for (const svc of i.services) {
      const probe = svc === "http" ? ["sh", "-c", "curl -s -o /dev/null http://127.0.0.1/ || wget -q -O /dev/null http://127.0.0.1/"]
        : svc === "postgres" ? ["pg_isready", "-h", "127.0.0.1"]
        : null;
      if (!probe) continue;
      if (await run(docker, ["exec", name, ...probe], { timeout: 10_000 }).then(() => true, () => false)) services.push(svc);
    }
    out.push({ hostId: i.hostId, services, packages: [] });
  }
  return out;
}

/**
 * Observed state for VM hosts (T-16): a declared service counts as running
 * only when its readiness probe answers inside the guest over SSH. A host
 * missing from the registry (or a missing registry) contributes nothing, so
 * `detectDrift` reports it as drifted rather than assuming a clean bill of
 * health. `services` must use the catalog-kind vocabulary (`http`, `db`, …),
 * which is what org specs declare.
 */
export async function observeVmState(
  spec: EnvironmentSpec,
  runId: string,
  opts: { exec?: (hostId: string, command: string, timeoutMs?: number) => Promise<string>; state?: VmRunState | null } = {},
): Promise<ObservedInstance[]> {
  const state = opts.state === undefined ? await readVmRunState(vmLifecycleFor({ runId })) : opts.state;
  if (!state) return []; // registry gone: every guest is gone
  const present = spec.instances.filter((i) => i.runtime === "vm" && state.instances[i.hostId]);
  const exec = opts.exec ?? (async (hostId, command, timeoutMs) => {
    const inst = state.instances[hostId];
    if (!inst) throw new Error(`no VM ${hostId} in the run registry`);
    const { execInGuest } = await import("../configurator/vm-ssh.js");
    return (await execInGuest(inst, command, { timeoutMs })).stdout;
  });
  const readiness = present.length
    ? await checkSpecReadiness({ spec, runId, sshUserOf: (h) => state.instances[h]?.ssh?.user ?? "arena", exec })
    : [];
  return spec.instances.filter((i) => i.runtime === "vm").map((i) => {
    const passing = new Set((readiness.find((r) => r.hostId === i.hostId)?.checks ?? []).filter((c) => c.ok).map((c) => c.kind.split("/")[0]));
    return { hostId: i.hostId, services: i.services.filter((s) => passing.has(s)), packages: [] };
  });
}

interface VmDeploymentRow { id: string; org_id: string; status: string; access_info?: Record<string, unknown> | null }

/**
 * A persistent guest run that outlived its deployment record is a leak: QEMU
 * has no Docker label the orphan sweeper can find. `minAgeMs` protects a run
 * started outside the workflow (a debug run has no row yet but is in use).
 */
export function vmOrphanReason(
  run: VmRunState,
  dep: VmDeploymentRow | undefined,
  now: number,
  minAgeMs: number,
): string | null {
  const starts = Object.values(run.instances).map((i) => Date.parse(i.startedAt)).filter(Number.isFinite);
  const startedAt = starts.length ? Math.min(...starts) : NaN;
  if (!Number.isFinite(startedAt) || now - startedAt < minAgeMs) return null;
  if (!dep) return "no deployment row";
  if (dep.status === "destroyed") return "deployment destroyed";
  if (dep.status === "failed" && dep.access_info?.resourcesDestroyed === true) return "deployment failed and cleanup was recorded";
  return null;
}

export interface VmSweepReport { removed: { runId: string; reason: string }[] }

/** Destroy guest runs whose deployment is gone; the Docker sweeper cannot see them. */
export async function sweepVmOrphans(opts: { root?: string; now?: number; minAgeMs?: number } = {}): Promise<VmSweepReport> {
  const root = opts.root ?? vmStateRoot();
  const now = opts.now ?? Date.now();
  const minAgeMs = opts.minAgeMs ?? 30 * 60_000;
  const runs = await listVmRuns(root).catch(() => []);
  if (!runs.length) return { removed: [] };
  const sb = serviceClient();
  const ids = runs.map((r) => r.runId.replace(/^run-/, "")).filter((id) => /^[0-9a-f-]{36}$/i.test(id));
  const { data, error } = await sb.from("deployments").select("id, org_id, status, access_info").in("id", ids);
  if (error) throw new Error(`vm sweep lookup failed: ${error.message}`);
  const byRun = new Map((data ?? []).map((d) => [`run-${d.id}`, d as VmDeploymentRow]));
  const removed: { runId: string; reason: string }[] = [];
  for (const run of runs) {
    const dep = byRun.get(run.runId);
    const reason = vmOrphanReason(run, dep, now, minAgeMs);
    if (!reason) continue;
    const ok = await destroyRunVms({ stateRoot: root, runId: run.runId }).then(() => true, () => false);
    if (!ok) continue;
    removed.push({ runId: run.runId, reason });
    await audit({
      orgId: dep?.org_id ?? "unknown", actor: "sweeper", action: "DEPLOYMENT_DESTROY",
      subjectType: "run", subjectId: run.runId, detail: { orphan: true, kind: "vm", reason },
    });
  }
  return { removed };
}

export interface MaintenanceReport {
  sweep: SweepReport;
  vmOrphans: VmSweepReport;
  ttl: string[];
  drift: Record<string, string>;
  errors: string[];
}

/** One maintenance pass: TTL teardown through the real destroy path, drift per live deployment, orphan sweep. */
export async function maintenancePass(opts: { docker?: string; now?: Date; routing?: WorkerRoutingConfig } = {}): Promise<MaintenanceReport> {
  const routing = opts.routing ?? workerRoutingConfig();
  const sb = serviceClient();
  const ttl: string[] = [];
  const errors: string[] = [];
  // Per-deployment isolation: one stack that refuses to die must not stop TTL
  // for every other expired environment (or the pass itself).
  for (const d of await ttlExpiredDeployments(opts.now, routing)) {
    try {
      // A ready run that reached TTL ended cleanly. Any other status at TTL
      // did not complete (stranded provisioning, failed cleanup, a run the
      // cap killed); record that instead of rewriting it to `destroyed`.
      const outcome = d.status === "ready" ? undefined : {
        status: "failed" as const,
        failure: (d.failure as { stage: string; error: string; at?: string } | undefined)
          ?? { stage: d.status, error: `TTL expired while ${d.status}` },
      };
      await teardownEnvironment({
        deploymentId: d.id, orgId: d.orgId,
        stackName: d.stackId.includes("/") ? d.stackId.split("/").pop()! : d.stackId,
        spec: d.spec, runId: `run-${d.id}`, outcome,
      });
      ttl.push(d.id);
    } catch (err) {
      errors.push(`ttl ${d.id}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  const drift: Record<string, string> = {};
  const { data } = await sb.from("deployments").select("id, org_id, access_info, environments(spec)").in("status", ["ready", "exercising"]);
  for (const row of (data ?? []) as unknown as { id: string; org_id: string; access_info?: AccessInfo | null; environments?: { spec: EnvironmentSpec } | null }[]) {
    // Drift is observed through host-local Docker/VM state. Observing another
    // worker's deployment here would report its guests missing and poison
    // the row with a false drift verdict.
    if (!deploymentOwnedByWorker(row.access_info ?? {}, routing)) continue;
    const spec = row.environments?.spec;
    if (!spec) continue;
    try {
      const container = spec.instances.every((i) => i.runtime === "container");
      const allVm = spec.instances.length > 0 && spec.instances.every((i) => i.runtime === "vm");
      const observed = container
        ? await observeDockerState(spec, `run-${row.id}`, opts.docker)
        : allVm
          ? await observeVmState(spec, `run-${row.id}`).catch(() => undefined)
          : undefined; // mixed runtimes have no single observer: record unobserved
      drift[row.id] = await runDriftJob({ deploymentId: row.id, orgId: row.org_id, spec, observed });
    } catch (err) {
      drift[row.id] = "error";
      errors.push(`drift ${row.id}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  const sweep = await sweepOrphanResources({ docker: opts.docker, now: opts.now?.getTime(), routing });
  const vmOrphans = await sweepVmOrphans({ now: opts.now?.getTime() }).catch((err) => {
    errors.push(`vm sweep: ${err instanceof Error ? err.message : String(err)}`);
    return { removed: [] };
  });
  return { sweep, vmOrphans, ttl, drift, errors };
}
