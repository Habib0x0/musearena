import { z } from "zod";

// Canonical enums — the provider-neutral vocabulary (spec §2, §8).
export const Provider = z.enum(["aws", "gcp", "kvm"]);
export type Provider = z.infer<typeof Provider>;

export const Runtime = z.enum(["vm", "container"]);
export type Runtime = z.infer<typeof Runtime>;

export const ModelSurface = z.enum(["meta", "meta-modal"]);
export type ModelSurface = z.infer<typeof ModelSurface>;

export const ExerciseEngine = z.enum(["scripted", "agents"]);
export type ExerciseEngine = z.infer<typeof ExerciseEngine>;

/** Operator-selected runtime/model/exercise platform, pinned with the spec. */
export const PlatformSelection = z.object({
  runtimeTarget: Runtime,
  modelSurface: ModelSurface,
  exerciseEngine: ExerciseEngine,
});
export type PlatformSelection = z.infer<typeof PlatformSelection>;

export const TruthLayer = z.enum(["xen-vmi", "kvm-vmi", "mirror-only"]);
export type TruthLayer = z.infer<typeof TruthLayer>;

export const RunMode = z.enum(["blind", "adaptive"]);
export type RunMode = z.infer<typeof RunMode>;

export const Actor = z.enum(["red", "blue", "proof", "noise", "platform"]);
export type Actor = z.infer<typeof Actor>;

export const Outcome = z.enum([
  "attempted",
  "succeeded",
  "failed",
  "detected",
  "contained",
]);
export type Outcome = z.infer<typeof Outcome>;

export const Difficulty = z.enum(["noisy", "standard", "stealth"]);
export type Difficulty = z.infer<typeof Difficulty>;

// Personas — the cast designed with the org (spec: "little Muses").
export const Persona = z.object({
  id: z.string(),
  role: z.string(),
  workstation: z.string(), // host_id of the persona's machine
  access: z.array(z.string()),
  credentialsProfile: z.string(),
  riskProfile: z.enum(["low", "medium", "high"]),
  routine: z.string(),
  relationships: z.array(z.string()),
});
export type Persona = z.infer<typeof Persona>;

export const Objective = z.object({
  id: z.string(),
  asset: z.string(),
  techniqueId: z.string(), // ATT&CK, e.g. T1003.001
  successSignal: z.string(), // verifiable ground-truth signal (canary hash, sinkhole bytes, service state)
  points: z.number(),
});
export type Objective = z.infer<typeof Objective>;

/**
 * Structured service declaration (spec §3/§8): what must actually run on the
 * host. `kind`/`impl` come from the closed runtime catalog; free-text service
 * descriptions live in `Instance.services` for display only and are not
 * provisionable on the VM runtime.
 */
export const ServiceKind = z.enum(["dns", "dhcp", "ldap", "smtp", "imap", "http", "db", "ssh", "log", "router", "git"]);
export type ServiceKind = z.infer<typeof ServiceKind>;

export const ServiceDecl = z.object({
  kind: ServiceKind,
  impl: z.string(),
  port: z.number().int().min(1).max(65535),
  readyWhen: z.enum(["tcp", "dns-query", "dhcp-lease", "ldap-bind", "smtp-imap-roundtrip", "http-2xx", "sql-select", "ssh-login", "git-ldap-login"]),
});
export type ServiceDecl = z.infer<typeof ServiceDecl>;

/** Tiny-VM resource profile; host capacity is checked against these at design/deploy time. */
export const ResourceProfile = z.object({
  vcpu: z.number().int().min(1).max(8),
  memoryMb: z.number().int().min(128).max(16384),
  diskGb: z.number().int().min(1).max(64),
});
export type ResourceProfile = z.infer<typeof ResourceProfile>;

export const Instance = z.object({
  hostId: z.string(),
  name: z.string(),
  role: z.string(),
  runtime: Runtime,
  os: z.string(),
  stack: z.array(z.string()),
  services: z.array(z.string()),
  databases: z.array(z.string()).default([]),
  // Org-lab fields (all optional; existing container specs validate unchanged).
  subnet: z.string().optional(),
  /** Org topology placement (v2); derived from `subnet` when omitted. */
  site: z.string().optional(),
  zone: z.string().optional(),
  serviceDecls: z.array(ServiceDecl).optional(),
  dependsOn: z.array(z.string()).optional(),
  resources: ResourceProfile.optional(),
});
export type Instance = z.infer<typeof Instance>;

export const PlantedVuln = z.object({
  id: z.string(),
  type: z.enum(["cve", "misconfig", "weak-cred", "code-flaw"]),
  techniqueId: z.string(),
  targetHostId: z.string(),
  pinnedVersion: z.string(),
  proofAtomicGuid: z.string(),
  difficulty: Difficulty,
});
export type PlantedVuln = z.infer<typeof PlantedVuln>;

export const Budget = z.object({
  maxInstances: z.number(),
  maxDollarsPerHour: z.number(),
  ttlHours: z.number(),
});
export type Budget = z.infer<typeof Budget>;

// EnvironmentSpec — the provider-neutral environment contract (spec §1, §8).
export const Site = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  kind: z.enum(["hq", "branch", "datacenter"]),
});
export type Site = z.infer<typeof Site>;

export const Zone = z.object({
  id: z.string().min(1),
  site: z.string().min(1),
  kind: z.enum(["edge", "dmz", "corp", "server", "ot", "mgmt"]),
});
export type Zone = z.infer<typeof Zone>;

export const WanLink = z.object({
  from: z.string().min(1),
  to: z.string().min(1),
  allowed: z.array(z.object({ proto: z.string(), port: z.number().int().min(1).max(65535) })),
});
export type WanLink = z.infer<typeof WanLink>;

export const FirewallPolicy = z.object({
  from: z.string().min(1),   // "site/zone", "*/zone", "site/*", "any"
  to: z.string().min(1),
  proto: z.enum(["tcp", "udp", "icmp"]),
  port: z.number().int().min(1).max(65535).optional(),
  action: z.enum(["allow", "deny"]),
  reason: z.string().min(1),
});
export type FirewallPolicy = z.infer<typeof FirewallPolicy>;

export const EnvironmentSpec = z.object({
  version: z.union([z.literal(1), z.literal(2)]),
  name: z.string(),
  provider: Provider,
  seed: z.string(),
  difficulty: Difficulty,
  truthLayer: TruthLayer,
  topology: z.object({
    cidr: z.string(),
    subnets: z.array(z.object({ name: z.string(), cidr: z.string(), zone: z.string(), site: z.string().optional() })),
    /** Legacy display strings; structured enforcement lives in `policies`. */
    firewallRules: z.array(z.string()).default([]),
    // Org topology (v2). Optional so every v1 spec validates unchanged.
    sites: z.array(Site).optional(),
    zones: z.array(Zone).optional(),
    links: z.array(WanLink).optional(),
    policies: z.array(FirewallPolicy).optional(),
  }),
  instances: z.array(Instance).min(1),
  personas: z.array(Persona).default([]),
  objectives: z.array(Objective).min(1),
  requiredTelemetry: z.array(z.string()),
  plantedVulns: z.array(PlantedVuln).default([]),
  budgets: Budget,
  /** Optional for pre-platform-selection specs; new approved specs pin it. */
  platform: PlatformSelection.optional(),
});
export type EnvironmentSpec = z.infer<typeof EnvironmentSpec>;

export const DeploymentStatus = z.enum([
  "pending",
  "provisioning",
  "configuring",
  "verifying",
  "ready",
  "exercising",
  "quarantined",
  "destroying",
  "destroyed",
  "failed",
]);
export type DeploymentStatus = z.infer<typeof DeploymentStatus>;

export const Deployment = z.object({
  id: z.string(),
  orgId: z.string(),
  specDigest: z.string(),
  stackId: z.string(),
  status: DeploymentStatus,
  accessInfo: z.record(z.string()).default({}),
  costEstimatePerHour: z.number().optional(),
  driftStatus: z.string().optional(),
  createdAt: z.string(),
});
export type Deployment = z.infer<typeof Deployment>;

export const RunScore = z.object({
  analyticCoverage: z.number(),
  exactTechniqueCoverage: z.number(),
  visibilityCoverage: z.number(),
  mttdMinutesP50: z.number().optional(),
  containmentCorrectness: z.number().optional(),
  falsePositiveRate: z.number().optional(),
  objectivesAchieved: z.number().optional(),
  objectivesTotal: z.number().optional(),
  pointsEarned: z.number().optional(),
  pointsTotal: z.number().optional(),
  mttrMinutesP50: z.number().optional(),
});
export type RunScore = z.infer<typeof RunScore>;

export const DeploymentPin = z.object({
  alias: z.string(),
  modelId: z.string(),
  trafficPct: z.number(),
  deploymentId: z.string().optional(),
  trafficHit: z.boolean().optional(),
});
export type DeploymentPin = z.infer<typeof DeploymentPin>;

export const Run = z.object({
  runId: z.string(),
  orgId: z.string(),
  deploymentId: z.string(),
  mode: RunMode,
  specDigest: z.string(),
  techniquePackVersion: z.string(),
  modelIds: z.record(z.string()),
  deployments: z.record(DeploymentPin).optional(),
  truthLayer: TruthLayer,
  backend: Provider,
  score: RunScore.optional(),
  simStartedAt: z.string().optional(),
});
export type Run = z.infer<typeof Run>;

export const Label = z.object({
  techniqueId: z.string(),
  stepId: z.string(), // Atomic GUID
  actor: Actor,
  outcome: Outcome,
});
export type Label = z.infer<typeof Label>;

export const TraceMeta = z.object({
  runId: z.string(),
  formatVersion: z.literal(1),
  contentHash: z.string(),
  split: z.enum(["train", "val", "test"]),
  redactionPolicyVersion: z.string(),
});
export type TraceMeta = z.infer<typeof TraceMeta>;

/**
 * External capture contract (Req §2.1.3, design §4). Versioned by the
 * `/capture/v1` path and strict about unknown fields: a harness cannot smuggle
 * a column the platform does not understand.
 */
export const CaptureActor = z.enum(["red", "blue", "persona"]);
export type CaptureActor = z.infer<typeof CaptureActor>;

const isoTimestamp = z.string().refine((value) => Number.isFinite(Date.parse(value)), "not an ISO timestamp");

export const CaptureTrace = z.object({
  runId: z.string().min(1),
  stepIndex: z.number().int().nonnegative(),
  at: isoTimestamp,
  hostId: z.string().default(""),
  actor: CaptureActor,
  techniqueId: z.string().optional(),
  observation: z.string().optional(),
  reasoning: z.string().optional(),
  toolCall: z.string().optional(),
  action: z.string().optional(),
  outcome: Outcome.optional(),
  matched: z.boolean().default(false),
  split: z.enum(["train", "val", "test"]).default("train"),
  /** Provenance of the step: an exported agent run or a real field observation. */
  source: z.enum(["imported", "field"]).default("imported"),
  /** Caller-named source system (never interpreted by the platform). */
  framework: z.string().trim().min(1).max(120).optional(),
  detail: z.record(z.unknown()).optional(),
}).strict();
export type CaptureTrace = z.infer<typeof CaptureTrace>;
