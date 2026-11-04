import type { EnvironmentSpec } from "@musearena/shared";
import type { AccessInfo } from "../provisioner/deployment-status.js";
import type { GuestArch } from "../provisioner/kvm.js";
import type { HostCapabilities } from "../provisioner/host-capabilities.js";
import { isWindowsOs, windowsImagePath } from "../provisioner/images.js";

/**
 * Multi-host worker routing.
 *
 * Pulumi state, VM registries, and the Docker daemon are host-local, so a
 * deployment must stay on one execution host from claim through teardown.
 * The trigger therefore claims only deployments this worker is eligible to
 * run, stamps the owner into `access_info`, and starts the workflow on that
 * worker's own Temporal task queue. Maintenance uses the same ownership
 * stamp before it touches TTL/drift state.
 *
 * With no `MUSEARENA_WORKER_ID`, behavior is the legacy single-worker mode:
 * queue `musearena`, every route accepted, and unowned deployments handled.
 */
export const WORKER_ROUTES = ["kvm", "vm", "container"] as const;
export type WorkerRoute = (typeof WORKER_ROUTES)[number];

export interface WorkerRoutingConfig {
  workerId: string | null;
  taskQueue: string;
  routes: WorkerRoute[];
  ownsUnrouted: boolean;
}

const WORKER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const TRUE_VALUES = new Set(["1", "true", "yes", "on"]);
const FALSE_VALUES = new Set(["0", "false", "no", "off"]);

function parseRoutes(raw: string | undefined): WorkerRoute[] {
  if (!raw?.trim()) return [...WORKER_ROUTES];
  const routes: WorkerRoute[] = [];
  for (const part of raw.split(",")) {
    const route = part.trim().toLowerCase();
    if (!route) continue;
    if (!WORKER_ROUTES.includes(route as WorkerRoute)) {
      throw new Error(`unknown worker route "${route}" in MUSEARENA_WORKER_ROUTES (expected ${WORKER_ROUTES.join(", ")})`);
    }
    if (!routes.includes(route as WorkerRoute)) routes.push(route as WorkerRoute);
  }
  if (!routes.length) throw new Error("MUSEARENA_WORKER_ROUTES must name at least one route");
  return routes;
}

function parseBoolean(name: string, raw: string | undefined, fallback: boolean): boolean {
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = raw.trim().toLowerCase();
  if (TRUE_VALUES.has(value)) return true;
  if (FALSE_VALUES.has(value)) return false;
  throw new Error(`${name} must be a boolean value (1/0, true/false, yes/no, on/off)`);
}

export function workerRoutingConfig(env: NodeJS.ProcessEnv = process.env): WorkerRoutingConfig {
  const workerIdRaw = env.MUSEARENA_WORKER_ID?.trim();
  const workerId = workerIdRaw ? workerIdRaw : null;
  if (workerId && !WORKER_ID_PATTERN.test(workerId)) {
    throw new Error("MUSEARENA_WORKER_ID must start with a letter or digit and contain only letters, digits, dot, underscore, or hyphen (max 64 chars)");
  }

  const taskQueueRaw = env.MUSEARENA_WORKER_TASK_QUEUE?.trim();
  if (taskQueueRaw && (/\s/.test(taskQueueRaw) || taskQueueRaw.length > 128)) {
    throw new Error("MUSEARENA_WORKER_TASK_QUEUE must be a non-empty task queue name without whitespace (max 128 chars)");
  }
  const taskQueue = taskQueueRaw || (workerId ? `musearena-${workerId}` : "musearena");

  return {
    workerId,
    taskQueue,
    routes: parseRoutes(env.MUSEARENA_WORKER_ROUTES),
    ownsUnrouted: parseBoolean(
      "MUSEARENA_WORKER_OWNS_UNROUTED",
      env.MUSEARENA_WORKER_OWNS_UNROUTED,
      workerId === null,
    ),
  };
}

export function maintenanceWorkflowIdFor(routing: WorkerRoutingConfig): string {
  return routing.workerId ? `musearena-maintenance-${routing.workerId}` : "musearena-maintenance";
}

type SpecRoutingShape = Pick<EnvironmentSpec, "truthLayer" | "platform" | "instances">;

export function requiredWorkerRoute(spec: SpecRoutingShape): WorkerRoute {
  if (spec.truthLayer === "kvm-vmi") return "kvm";
  if (spec.platform?.runtimeTarget === "vm" || spec.instances.some((i) => i.runtime === "vm")) return "vm";
  return "container";
}

function explicitWorkerRoute(accessInfo: AccessInfo | null | undefined): { route?: WorkerRoute; invalid?: string } {
  const raw = accessInfo?.workerRoute;
  if (raw === undefined || raw === null || raw === "") return {};
  if (typeof raw === "string" && WORKER_ROUTES.includes(raw as WorkerRoute)) return { route: raw as WorkerRoute };
  return { invalid: `deployment workerRoute ${JSON.stringify(raw)} is not a known worker route` };
}

export function workerRouteForDeployment(spec: SpecRoutingShape, accessInfo?: AccessInfo | null): WorkerRoute {
  return explicitWorkerRoute(accessInfo).route ?? requiredWorkerRoute(spec);
}

function explicitGuestArch(os: string): GuestArch | null {
  if (/\b(aarch64|arm64|arm)\b/i.test(os)) return "aarch64";
  if (/\b(x86_64|amd64|x64)\b/i.test(os)) return "x86_64";
  return null;
}

export interface WorkerEligibility {
  eligible: boolean;
  route: WorkerRoute;
  reason?: string;
}

export function workerCanRunDeployment(input: {
  spec: SpecRoutingShape;
  accessInfo?: AccessInfo | null;
  routing: WorkerRoutingConfig;
  caps: HostCapabilities;
  windowsImageConfigured?: boolean;
}): WorkerEligibility {
  const required = requiredWorkerRoute(input.spec);
  const explicit = explicitWorkerRoute(input.accessInfo);
  if (explicit.invalid) return { eligible: false, route: required, reason: explicit.invalid };
  const route = explicit.route ?? required;

  const targetedWorker = input.accessInfo?.workerId;
  if (targetedWorker !== undefined && targetedWorker !== null && targetedWorker !== "") {
    if (typeof targetedWorker !== "string" || !WORKER_ID_PATTERN.test(targetedWorker)) {
      return { eligible: false, route, reason: "deployment workerId is not a valid worker id" };
    }
    if (input.routing.workerId !== targetedWorker) {
      return { eligible: false, route, reason: `deployment is targeted to worker "${targetedWorker}"` };
    }
  }

  if (!input.routing.routes.includes(route)) {
    return { eligible: false, route, reason: `worker does not accept route "${route}"` };
  }
  if (input.spec.instances.length > input.caps.maxVmInstances) {
    return { eligible: false, route, reason: `instances ${input.spec.instances.length} > this worker's lab limit ${input.caps.maxVmInstances}` };
  }
  if (route === "kvm" && input.caps.accel !== "kvm") {
    return { eligible: false, route, reason: `truthLayer kvm-vmi requires a KVM worker; this worker offers ${input.caps.accel}` };
  }
  if (input.spec.instances.some((i) => i.runtime === "vm") && !input.caps.vmRuns) {
    return { eligible: false, route, reason: `VM guests cannot boot on this worker (acceleration ${input.caps.accel})` };
  }
  if (input.spec.instances.some((i) => i.runtime === "container") && !input.caps.container) {
    return { eligible: false, route, reason: "container labs need docker, which this worker does not have" };
  }

  const arches = new Set<GuestArch>();
  for (const inst of input.spec.instances) {
    if (inst.runtime !== "vm") continue;
    const arch = explicitGuestArch(inst.os);
    if (arch) arches.add(arch);
  }
  if (arches.size > 1) {
    return { eligible: false, route, reason: "deployment mixes explicit aarch64 and x86_64 guests; no single native worker can run it" };
  }
  const [guestArch] = [...arches];
  if (guestArch && guestArch !== input.caps.guestArch) {
    return { eligible: false, route, reason: `deployment requires a ${guestArch} guest; this worker is ${input.caps.guestArch}` };
  }

  const windowsConfigured = input.windowsImageConfigured ?? Boolean(windowsImagePath());
  if (!windowsConfigured && input.spec.instances.some((i) => i.runtime === "vm" && isWindowsOs(i.os))) {
    return { eligible: false, route, reason: "Windows VM needs a licensed image (KVM_WINDOWS_IMAGE), which this worker does not have" };
  }

  return { eligible: true, route };
}

export function deploymentOwnedByWorker(
  accessInfo: AccessInfo | null | undefined,
  routing: WorkerRoutingConfig,
): boolean {
  const owner = accessInfo?.workerId;
  if (typeof owner === "string" && owner) return routing.workerId === owner;
  return routing.ownsUnrouted;
}

export function claimAccessInfo(
  accessInfo: AccessInfo | null | undefined,
  routing: WorkerRoutingConfig,
  route: WorkerRoute,
  claimedAt = new Date().toISOString(),
): AccessInfo {
  const merged: AccessInfo = { ...(accessInfo ?? {}) };
  if (!routing.workerId) return merged;
  return {
    ...merged,
    workerId: routing.workerId,
    workerRoute: route,
    workerTaskQueue: routing.taskQueue,
    workerClaimedAt: claimedAt,
  };
}
