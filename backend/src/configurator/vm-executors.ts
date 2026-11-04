import type { EnvironmentSpec, PlantedVuln } from "@musearena/shared";
import { ingest } from "../observability/collector.js";
import { localStore, type EventStore } from "../observability/events.js";
import { execInGuest } from "./vm-ssh.js";
import { readVmRunState, type VmInstanceState, type VmRunState } from "../provisioner/vm-lifecycle.js";
import { vmLifecycleFor } from "../provisioner/deploy.js";
import type { GateOptions } from "./gates.js";
import { WEAK_DB_PASSWORD } from "../provisioner/roles.js";
import { bindStep, vulnTargetFor } from "./vuln-targets.js";

/**
 * LIVE gate executors for the VM runtime (T-18a).
 *
 * The action runs inside the guest over the run's SSH endpoint; verification
 * reads the guest's own sensor output (auditd, Apache error log) from the
 * management plane. Exit codes are never trusted — only a marker observed in
 * the guest's telemetry becomes ground truth, exactly like the Docker path.
 */

export interface VmExecOptions {
  runId: string;
  store?: EventStore;
  /** Injected registry/exec for tests; default reads the run registry. */
  state?: VmRunState;
  exec?: (inst: VmInstanceState, command: string, timeoutMs?: number) => Promise<string>;
  settleMs?: number;
  attempts?: number;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const shq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

async function observe(
  inst: VmInstanceState,
  command: string,
  match: (line: string) => boolean,
  attempts: number,
  settleMs: number,
  exec: NonNullable<VmExecOptions["exec"]>,
): Promise<string | undefined> {
  for (let i = 0; i < attempts; i++) {
    const out = await exec(inst, command, 15_000).catch(() => "");
    const hit = out.split("\n").find(match);
    if (hit) return hit;
    if (i + 1 < attempts) await sleep(settleMs);
  }
  return undefined;
}

export function vmGateOptions(spec: EnvironmentSpec, opts: VmExecOptions): GateOptions {
  const store = opts.store ?? localStore;
  const settleMs = opts.settleMs ?? 1_000;
  const attempts = opts.attempts ?? 5;
  const exec = opts.exec ?? (async (inst, command, timeoutMs) => (await execInGuest(inst, command, { timeoutMs })).stdout);

  const registry = async (): Promise<VmRunState> => {
    if (opts.state) return opts.state;
    const state = await readVmRunState(vmLifecycleFor({ runId: opts.runId }));
    if (!state) throw new Error(`no VM registry for ${opts.runId}; cannot execute gates`);
    return state;
  };
  const instOf = async (hostId: string) => {
    const inst = (await registry()).instances[hostId];
    if (!inst) throw new Error(`no VM ${hostId} in the run registry`);
    return inst;
  };

  return {
    store,
    executeCanary: async (runId, hostId, marker) => {
      const inst = await instOf(hostId);
      // auditd user message: a real kernel-audit record, not a file we write.
      await exec(inst, `sudo -n auditctl -m ${shq(marker)}`, 15_000).catch(() => undefined);
      const line = await observe(inst, "sudo -n tail -n 400 /var/log/audit/audit.log", (l) => l.includes(marker), attempts, settleMs, exec);
      if (!line) return;
      ingest({
        runId, hostId, kind: marker, actor: "platform", at: new Date().toISOString(),
        detail: { executor: "vm", source: "auditd", line: line.slice(0, 300) },
      }, { store });
    },

    executeProof: async (vuln: PlantedVuln, runId: string) => {
      const role = spec.instances.find((i) => i.hostId === vuln.targetHostId)?.role ?? "";
      const proofMarker = `arena-proof-${vuln.proofAtomicGuid}-${runId.replace(/^run-/, "").slice(0, 8)}`.replace(/[^a-zA-Z0-9-]/g, "");
      const ingestProof = (line: string) => ingest({
        runId, hostId: vuln.targetHostId, kind: "process", actor: "proof",
        techniqueId: vuln.techniqueId, stepId: vuln.proofAtomicGuid, outcome: "succeeded",
        at: new Date().toISOString(), detail: { executor: "vm", vulnId: vuln.id, line: line.slice(0, 300) },
      }, { store });

      if (vuln.type === "code-flaw" && role === "web") {
        const inst = await instOf(vuln.targetHostId);
        const payload = encodeURIComponent(`x;echo ${proofMarker} 1>&2`);
        await exec(inst, `curl -s -o /dev/null --max-time 20 "http://127.0.0.1/diag.php?host=${payload}"`, 30_000).catch(() => undefined);
        // Only the bare marker line proves the shell ran; the request line
        // alone would pass even if the injection never executed.
        const line = await observe(inst, "sudo -n tail -n 200 /var/log/apache2/error.log", (l) => l.trim() === proofMarker, attempts, settleMs, exec);
        if (line) ingestProof(line);
        return;
      }
      if (vuln.type === "weak-cred" && role === "db") {
        const inst = await instOf(vuln.targetHostId);
        // Authenticate over TCP with the planted weak password; the statement
        // only reaches the postgres log if the login succeeded.
        await exec(inst, `PGPASSWORD=${shq(WEAK_DB_PASSWORD)} psql -h 127.0.0.1 -U app -d app -tAc ${shq(`SELECT '${proofMarker}'`)}`, 15_000).catch(() => undefined);
        const line = await observe(inst, "sudo -n tail -n 300 /var/log/postgresql/postgresql-*-main.log", (l) => l.includes(`SELECT '${proofMarker}'`), attempts, settleMs, exec);
        if (line) ingestProof(line);
        return;
      }
      if (vuln.type === "cve") {
        // Registry-driven CVE proof: run the target's exploit steps in the
        // guest, then observe the marker in the target's own telemetry.
        // Unknown targets fall through to the fail-closed throw below.
        const inst = await instOf(vuln.targetHostId);
        const target = vulnTargetFor(vuln);
        if (target) {
          for (const step of target.exploitSteps) {
            await exec(inst, bindStep(step, "127.0.0.1", proofMarker), 30_000).catch(() => undefined);
          }
          const line = await observe(inst, target.proofLog, (l) => l.includes(proofMarker), attempts, settleMs, exec);
          if (line) ingestProof(line);
          return;
        }
      }
      // Fail closed: a type the VM runtime cannot plant/prove must not
      // silently pass the gate.
      throw new Error(`vuln type ${vuln.type}${vuln.type === "cve" ? ` (${vuln.id})` : ""} is not provable on the VM runtime (role ${role || "?"})`);
    },
  };
}
