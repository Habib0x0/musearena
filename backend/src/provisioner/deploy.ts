import { LocalWorkspace, type Stack } from "@pulumi/pulumi/automation/index.js";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { allocateCidr } from "./cidr.js";
import { program } from "./generate.js";
import { bootEnvironment } from "./kvm.js";
import { destroyRunVms, guestImagePins, startRunVms, type LifecycleOpts } from "./vm-lifecycle.js";
import { labPlanFor } from "./lab-network.js";
import { normalizeOrg } from "../designer/org-topology.js";
import { probeGuestIdentity } from "../configurator/vm-ssh.js";
import { serviceClient } from "../lib/supabase.js";
import { audit } from "../lib/audit.js";
import { failureRecord, markDeployment, readAccessInfo } from "./deployment-status.js";
import type { EnvironmentSpec } from "@musearena/shared";

// Pulumi Automation API from Temporal activities. Local file state backend
// (locked decision); provider plugins pre-bundled in worker images
// (Phase 0 finding — runtime downloads fail through the proxy).

// Anchored to this package, never the cwd: the worker runs from backend/
// while RUNBOOK scripts run from the repo root, and a cwd-relative root
// split Pulumi state across both — a root-run teardown destroyed an empty
// stack and leaked the real containers (found live, T-41 follow-up).
const backendRoot = () => process.env.PULUMI_STATE_DIR ?? path.join(path.dirname(new URL(import.meta.url).pathname), "../../.pulumi-state");
/** CrossGuard deploy gate (backend/policy). Mandatory: preview must pass it before up. */
export const POLICY_PACK_DIR = process.env.MUSEARENA_POLICY_PACK ?? path.join(path.dirname(new URL(import.meta.url).pathname), "../../policy");
const projectName = "musearena-env";

/**
 * Passphrase for environment stacks. One stable value per state root: Pulumi
 * encrypts the state with it at create time and refuses to read history under
 * a different one, so a per-call or per-worker value breaks teardown later
 * (found live: destroy deleted the resources, then failed reading history).
 * The platform stack has its own passphrase under ~/.musearena; this is the
 * environment plane's.
 */
function envPassphrase(): string {
  const fromEnv = process.env.PULUMI_CONFIG_PASSPHRASE ?? process.env.PULUMI_PASSPHRASE;
  if (fromEnv) return fromEnv;
  const file = path.join(backendRoot(), "passphrase");
  if (existsSync(file)) return readFileSync(file, "utf8").trim();
  mkdirSync(backendRoot(), { recursive: true, mode: 0o700 });
  const generated = randomBytes(24).toString("hex");
  writeFileSync(file, generated, { mode: 0o600 });
  return generated;
}

async function getStack(orgId: string, stackName: string, spec: EnvironmentSpec, runId: string, octet: number): Promise<Stack> {
  const dir = path.join(backendRoot(), orgId);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const passphrase = envPassphrase();
  // Pulumi's automation API also shells out for history/outputs; those
  // subprocesses read process.env, not this workspace's envVars. All
  // environment stacks share one passphrase, so exporting it once is safe.
  if (!process.env.PULUMI_CONFIG_PASSPHRASE) process.env.PULUMI_CONFIG_PASSPHRASE = passphrase;
  const stack = await LocalWorkspace.createOrSelectStack(
    { stackName, projectName, program: async () => program({ spec, orgId, runId, cidrOctet: octet }) },
    { envVars: { PULUMI_BACKEND_URL: `file://${dir}`, PULUMI_CONFIG_PASSPHRASE: passphrase } },
  );
  return stack;
}

export interface DeployResult { stackId: string; outputs: Record<string, string>; cidr: string }

/**
 * Pulumi returns every output wrapped in `{value}`. Host outputs are strings;
 * the topology is an array, and `String(array)` is "[object Object]" — which
 * is how the deployment record lost the network it had just built.
 */
export function flattenOutputs(raw: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw)) {
    const value = (v as { value?: unknown }).value;
    out[k] = typeof value === "string" ? value : JSON.stringify(value ?? null);
  }
  return out;
}

/** Root of the persistent guest registries (beside Pulumi state unless overridden). */
export const vmStateRoot = (): string => process.env.VM_STATE_DIR ?? path.join(backendRoot(), "vm-state");

/** VM lifecycle options for a deploy/teardown. */
export function vmLifecycleFor(input: { runId: string; stateRoot?: string }): LifecycleOpts {
  return { stateRoot: input.stateRoot ?? vmStateRoot(), runId: input.runId };
}

export async function deployEnvironment(input: {
  deploymentId: string;
  orgId: string;
  runId: string;
  spec: EnvironmentSpec;
}): Promise<DeployResult> {
  const sb = serviceClient();
  const { data: active } = await sb
    .from("deployments")
    .select("access_info")
    .eq("org_id", input.orgId)
    .neq("status", "destroyed");
  const used: number[] = (active ?? []).map((d: { access_info?: { cidrOctet?: number } }) => d.access_info?.cidrOctet).filter((x): x is number => typeof x === "number");

  const claim = allocateCidr(used);
  const stackName = `dev-${input.deploymentId.slice(0, 8)}`;
  const stack = await getStack(input.orgId, stackName, input.spec, input.runId, claim.octet);

  await markDeployment(input.deploymentId, { status: "provisioning" });
  // Deploy gate: preview with the policy pack. A violation throws here, before
  // any resource exists, so there is nothing to roll back.
  try {
    await stack.preview({ policyPacks: [POLICY_PACK_DIR], onOutput: () => undefined });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const violations = [...new Set([...msg.matchAll(/\[mandatory\]\s+(\S+)\s+\(([^)]*)\)/g)].map((m) => `${m[1]} (${m[2]})`))];
    const detail = `deploy gate: ${violations.join("; ") || msg.slice(0, 400)}`;
    await markDeployment(input.deploymentId, { status: "failed", accessInfo: { error: detail, failure: failureRecord("deploy", detail) } });
    await audit({ orgId: input.orgId, actor: "provisioner", action: "PROOF_GATE_DECISION", subjectType: "deployment", subjectId: input.deploymentId, detail: { gate: "crossguard", pass: false, violations } });
    throw err;
  }
  await audit({ orgId: input.orgId, actor: "provisioner", action: "PROOF_GATE_DECISION", subjectType: "deployment", subjectId: input.deploymentId, detail: { gate: "crossguard", pass: true } });
  try {
    const up = await stack.up({ onOutput: console.log, policyPacks: [POLICY_PACK_DIR] });
    const outputs = flattenOutputs(up.outputs as Record<string, unknown>);
    let guestImages: Record<string, { name: string; digest: string }> = {};
    if (input.spec.instances.some((i) => i.runtime === "vm")) {
      // Persistent guests: start every planned VM and prove SSH identity
      // before the deploy may call itself ready. A guest that does not come
      // up fails here and the rollback below destroys what started.
      const lifecycle = vmLifecycleFor(input);
      const started = await startRunVms(input.spec, lifecycle, (hostId, pubKey) => ({
        hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: input.runId, HOST_ID: hostId },
      }));
      guestImages = guestImagePins(started.state);
      for (const inst of Object.values(started.state.instances)) {
        const identity = await probeGuestIdentity(inst, { runId: input.runId });
        outputs[inst.hostId] = `vm:${inst.accel}:${identity.hostname}`;
      }
    } else if (input.spec.provider === "kvm") {
      // Legacy boot proof (Alpine probe guests) for container-only kvm specs.
      const boots = await bootEnvironment(input.spec, { stateDir: path.join(backendRoot(), "kvm"), runId: input.runId });
      for (const b of boots) {
        if (!b.serialLog.includes("MUSEARENA-LINUX-BOOT")) throw new Error(`VM ${b.hostId} failed Linux boot proof (accel ${b.accel})`);
        outputs[b.hostId] = `vm:booted:${b.accel}`;
      }
    }
    // The record must describe the network that actually exists: VM guests use
    // the designed topology verbatim; container runs use the allocated /16.
    // v2 org runs record the derived org addresses (the router's primary .1);
    // v1 flat runs record the single-segment plan.
    const vmRun = input.spec.instances.some((i) => i.runtime === "vm");
    const isOrgV2 = (input.spec.topology.sites?.length ?? 0) > 0 || (input.spec.topology.zones?.length ?? 0) > 0;
    const addresses = vmRun
      ? isOrgV2
        ? Object.fromEntries(normalizeOrg(input.spec).endpoints.map((e) => [e.hostId, `${e.address}/${e.prefix}`]))
        : Object.fromEntries(labPlanFor(input.spec, input.runId).map((e) => [e.hostId, `${e.address}/${e.prefix}`]))
      : {};
    // `cidr` is the environment network the design declared; `subnet` is the
    // segment the guests actually sit on. Both are recorded, never conflated.
    const cidr = vmRun ? (input.spec.topology.cidr ?? claim.envCidr) : claim.envCidr;
    const subnet = vmRun ? input.spec.topology.subnets[0]?.cidr : undefined;
    // `ready` is written only after configuration, readiness and scoring have
    // passed. At this point the guests exist, nothing more.
    await markDeployment(input.deploymentId, {
      stackId: `${projectName}/${stackName}`,
      accessInfo: { cidrOctet: claim.octet, cidr, ...(subnet ? { subnet } : {}), outputs, ...(vmRun ? { addresses } : {}), ...(Object.keys(guestImages).length ? { guestImages } : {}) },
    });
    await audit({ orgId: input.orgId, actor: "provisioner", action: "DEPLOYMENT_START", subjectType: "deployment", subjectId: input.deploymentId, detail: { cidr } });
    return { stackId: `${projectName}/${stackName}`, outputs, cidr };
  } catch (err) {
    // Rollback: destroy any persistent VMs first, then the stack. The failure
    // is recorded before either attempt so the TTL sweep can retry cleanup
    // when a destroy fails; `resourcesDestroyed` stays false until it succeeds.
    const message = err instanceof Error ? err.message : String(err);
    await markDeployment(input.deploymentId, { status: "failed", accessInfo: { failure: failureRecord("deploy", message), resourcesDestroyed: false } }).catch(() => undefined);
    const vm = await destroyRunVms(vmLifecycleFor(input)).then(() => null, (e: Error) => e);
    const stackErr = await stack.destroy({ onOutput: console.log }).then(() => null, (e: Error) => e);
    if (!vm && !stackErr) {
      await markDeployment(input.deploymentId, { accessInfo: { resourcesDestroyed: true, destroyedAt: new Date().toISOString() } }).catch(() => undefined);
    } else {
      await sb.from("deployments").update({ drift_status: "orphan-suspected" }).eq("id", input.deploymentId);
    }
    await audit({ orgId: input.orgId, actor: "provisioner", action: "DEPLOYMENT_DESTROY", subjectType: "deployment", subjectId: input.deploymentId, detail: { rollback: true } });
    throw err;
  }
}

export interface TeardownOutcome {
  /** `destroyed` for a normal TTL teardown; `failed` when the run did not complete. */
  status: "destroyed" | "failed";
  failure?: { stage: string; error: string; at?: string };
}

export async function teardownEnvironment(input: {
  deploymentId: string; orgId: string; stackName: string; spec: EnvironmentSpec; runId: string; outcome?: TeardownOutcome;
}): Promise<void> {
  // Never replace access_info: the failure that caused this teardown and the
  // stack outputs are the only record of what existed.
  const prior: Record<string, unknown> = await readAccessInfo(input.deploymentId).catch(() => ({}));
  if (prior.resourcesDestroyed === true) {
    // The workflow already tore this down; a second Pulumi destroy on an
    // empty stack is not free (it re-reads history) and must not be able to
    // rewrite the outcome or fail the caller.
    await markDeployment(input.deploymentId, {
      status: input.outcome?.status ?? "destroyed",
      accessInfo: { ...(input.outcome?.failure ? { failure: input.outcome.failure } : {}) },
    });
    return;
  }
  await markDeployment(input.deploymentId, { status: "destroying" });
  const errors: string[] = [];
  // Persistent VMs are destroyed before the stack so no guest outlives its
  // deployment record; a missing registry is a no-op (container runs).
  const vmError = await destroyRunVms(vmLifecycleFor(input)).then(() => null, (e: Error) => e);
  if (vmError) errors.push(`vm teardown: ${vmError.message}`);
  // A row that never reached deploy has stack_id "pending" (the UI and smoke
  // insert that placeholder). There is no Pulumi stack to destroy for it.
  // Callers pass either "musearena-env/dev-x" or the short "dev-x".
  const shortStack = input.stackName.includes("/") ? input.stackName.split("/").pop()! : input.stackName;
  if (shortStack && shortStack !== "pending") {
    const stackErr = await getStack(input.orgId, shortStack, input.spec, input.runId, 0)
      .then((s) => s.destroy({ onOutput: console.log })).then(() => null, (e: Error) => e);
    if (stackErr) errors.push(`stack destroy: ${stackErr.message}`);
  }
  if (errors.length) {
    const error = errors.join("; ");
    await markDeployment(input.deploymentId, {
      status: "failed",
      accessInfo: {
        failure: input.outcome?.failure ?? { stage: "teardown", error, at: new Date().toISOString() },
        cleanupError: error,
        resourcesDestroyed: false,
      },
    }).catch(() => undefined);
    throw new Error(`teardown failed for ${input.deploymentId}: ${error}`);
  }
  await markDeployment(input.deploymentId, {
    status: input.outcome?.status ?? "destroyed",
    accessInfo: {
      ...(input.outcome?.failure ? { failure: input.outcome.failure } : {}),
      resourcesDestroyed: true,
      destroyedAt: new Date().toISOString(),
    },
  });
  await audit({ orgId: input.orgId, actor: "provisioner", action: "DEPLOYMENT_DESTROY", subjectType: "deployment", subjectId: input.deploymentId });
}

/** Orphan sweeper: destroys stacks whose DB record says destroyed/unknown. */
export async function sweepOrphans(orgId: string, knownStacks: Set<string>): Promise<string[]> {
  const sb = serviceClient();
  const { data } = await sb.from("deployments").select("id, stack_id, status").eq("org_id", orgId).in("status", ["failed", "destroyed"]);
  const flagged: string[] = [];
  for (const d of data ?? []) {
    if (d.stack_id && !knownStacks.has(d.stack_id)) flagged.push(d.id as string);
  }
  return flagged;
}
