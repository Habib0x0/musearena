# Design — Prompt-Driven Environment Generation

> Revised 2026-10-27: designer-built full-org labs on Linux VMs are the
> primary shape. The working Docker web/db loop is preserved as a dev/regression
> runtime. Nothing in this document claims a capability is built — status and
> evidence live in `tasks.md` / `progress.md`.

## Architecture overview

```
User prompt ("a 12-person clinic: gateway, directory, mail, intranet, DB…")
   │
   ▼
┌──────────────┐   fan-out     ┌─────────────────────────────────┐
│ Orchestrator ├──────────────▶│ Designer → IaC gen → Provisioner │
│ (PRA loop)   │               │ → Profile resolver → Configurator│
└──────┬───────┘               └───────────────┬─────────────────┘
       │ budgets/approvals                     │ deploy + configure
       ▼                                       ▼
┌──────────────┐               ┌─────────────────────────────────┐
│ Evaluator    │◀── traces ────│ Linux/KVM org lab (tiny VMs)     │
│              │   Langfuse    │  red ⇄ ground truth ⇄ blue      │
└──────────────┘               └─────────────────────────────────┘
```

Agents run on Meta's ecosystem: Meta Model API (Muse family) as the model
layer. The platform is agent-orchestrator driven with minimal human oversight:
the orchestrator auto-approves within policy (budgets, TTLs, CrossGuard policy
pack, ROE) and escalates to humans only on policy violations, proof-gate
failures, or budget exceptions. Every auto-decision is audit-logged.

### Agentic stack (orchestration & traces)
- **Model layer:** Meta Model API (Muse family) for designer, red, blue, and
  evaluator assistance; per-role model IDs pinned per run (§8). Model IDs not
  verified for tool use fail closed at selection.
- **Durable execution:** Temporal workflows own long-running lifecycles
  (provisioning, exercise runs, TTL timers) and invoke agent/exercise logic as
  activities. Temporal is durability, not agent logic.
- **Traces:** Langfuse records LLM/agent spans (prompts, tool calls, tokens)
  keyed by `run_id`; ground truth stays in the append-only event store; the
  evaluator joins them at export. Agent text is never ground truth.

## Monorepo layout

```
MuseArena/
├── backend/        Worker services only (agents, provisioner, configurator,
│                   evaluator, designer) — no bespoke API server
├── frontend/       Product app: React + Clerk + TanStack Query; Supabase
│                   Realtime for live state
├── marketing/      Public marketing website (separate deployable)
├── shared/         zod schemas: EnvironmentSpec, Run, Trace; API contracts
└── deployment/     IaC for platform services (Temporal, Langfuse, Prometheus)
```

Modularity rule: independent packages, no cross-imports except through
`shared/` contracts and `backend/lib`; the frontend never imports backend code.

## Components

### Orchestrator agent
Parses prompts, decomposes work, routes to specialist agents, enforces budget
caps and approval gates, maintains the run state machine.

### Designer agent
Produces the provider-neutral **EnvironmentSpec** (`shared/`): org archetype,
network topology (subnets, CIDR plan from the collision-safe allocator),
instances with subnet placement, structured services and dependencies,
machine-profile hints, personas (the org's cast), business data, planted
vulnerabilities (with intended exploit path), objectives, and a monitoring
plan. Renders a visual topology map.

Design-time honesty is a feature: the designer is constrained by the
**runtime catalog** (§ Machine profiles and the service catalog). It may only
emit roles, service kinds/implementations, vuln types and objectives the
runtime can install and verify. Anything outside the catalog is blocked with
the reason — never approximated, renamed, or quietly downgraded.

### Designer surface (chat + artifact pane)
Conversational chat thread with the designer agent plus a live artifact pane
holding the EnvironmentSpec, topology map, cast, planted vulns, service graph,
and cost estimate. Artifact actions: approve design, deploy, fork version.
For org labs the pane surfaces per-host machine profiles and readiness state,
so a design that cannot be built is visible before deploy, not after.

### IaC generator
Compiles EnvironmentSpec → Pulumi program. Canonical resource types defined
in application code; the generator never emits raw Pulumi URNs into app code.
Container environments use the existing Docker program; VM environments use
the Linux/KVM branch described below.

### Provisioner — Linux/KVM primary runtime
The org-lab runtime is QEMU/KVM on a Linux host:

- **Host gate.** A preflight records OS/arch, QEMU binaries, `/dev/kvm`
  availability, Docker, and Ansible. Scored VM runs require native KVM
  acceleration on the host architecture; emulation (tcg) is never silently
  used for a scored run. Truth is `mirror-only` until a real VMI layer
  exists — KVM alone does not justify a `kvm-vmi` claim.
- **Guests.** One pinned golden image (Debian 12 minimal; § Guest images)
  with a content digest. Each run clones it into per-host copy-on-write
  overlays. Each guest gets a stable identity: `run_id`, `host_id`, hostname,
  subnet address, and resource profile.
- **Lifecycle.** Start/stop/destroy per guest, with pidfile, serial console
  log, and state directory per run. Deploy fails if a guest does not reach
  its boot marker; teardown kills QEMU and removes overlays, bridges, and
  tap devices. The hourly sweeper treats stale QEMU processes, bridges,
  taps, and overlays as orphans alongside Docker resources.
- **Networking.** A per-run Linux bridge per subnet from the spec (allocated
  from the existing 10.0.0.0/8 pool). The gateway VM provides DNS/DHCP and
  default-deny egress; guests have no route to the internet or the host
  management plane. A second, isolated management/telemetry network reaches
  the collector; the attacker host is attached only to lab networks, never
  to the management network.
- **Ordering.** Resources are created in dependency order (network →
  guests → gateway services → dependents), and readiness (§ Readiness) is
  part of provisioning completion, not a later hope.

The existing Docker container runtime (`php:8.2-apache` / `postgres:16-alpine`
+ attacker on an internal network) stays as a fast dev/regression runtime
for the web/db scenario. Scores are never ranked across runtimes.

### Guest images
One golden image per architecture, built once and pinned by digest:

- Debian 12 minimal, systemd, no desktop, ~1 vCPU / 512 MB–1 GB per guest.
- Baked in: openssh-server, auditd, osquery, rsyslog, chrony, common
  diagnostics (curl, jq, dnsutils), and the package set for the service
  catalog, so a lab with no internet egress can still be configured.
  Where a package is not baked in, it comes from a host-local mirror on the
  management plane — never from the public internet inside the lab.
- Per-run identity and secrets are injected at first boot via a seed
  (config-drive or equivalent): hostname, address, users, run-scoped
  credentials. Planted weak credentials are training content, labelled as
  such, and rotated away when a vuln is not declared (existing behaviour).

Alpine's netboot kernel/minirootfs remains the boot-probe guest only; it is
not an org-lab guest (musl makes auditd/osquery packaging painful).

### Machine profiles and the service catalog
A host is not real because it booted; it is real because its services run.
Between the spec and Ansible sits a deterministic **profile resolver**:

- **Closed service vocabulary.** Each service is `{kind, impl, port}` from a
  versioned catalog, e.g. `dns/dnsmasq`, `dhcp/dnsmasq`, `ldap/openldap`,
  `smtp/postfix`, `imap/dovecot`, `http/apache-php`, `db/postgres`,
  `ssh/openssh`, `log/rsyslog-collector`. Free-text services are rejected
  at design validation.
- **Profiles.** `role + services` resolves to ordered task groups, each
  `install → configure → seed → enable → verify`:
  - `server-base` (every host): users/groups, SSH, auditd, osquery, log
    forwarding to the sensor, time sync, diagnostics.
  - `gateway`: dnsmasq (DNS+DHCP), nftables default-deny.
  - `directory`: OpenLDAP with the persona cast seeded as real entries.
  - `mail`: Postfix + Dovecot (+ webmail when http is declared), mailboxes
    and seeded messages; binds against the directory when declared.
  - `web`: Apache/PHP app, business data, planted flaw when declared.
  - `db`: Postgres, business schema/rows, planted weak cred when declared.
  - `workstation`: desktop-less user host with client tools for the
    services its personas use (mail, web, DB, directory clients).
  - `sensor`: rsyslog collector receiving every host's logs out-of-band.
  - `attacker`: red toolbox (the network/DB/web clients red legitimately
    needs), no telemetry NIC, never on the management network.
- **Tooling is declared, not guessed.** The resolver pins per-host client
  and server tools into the profile; a persona or agent brief lists only
  tools the profile installed.
- **Versioning.** Catalog and profile versions are pinned into the run
  record with the image digest and spec digest.

### Configurator (Ansible)
Ansible applies the resolved profiles. Inventory is generated from
provisioner outputs — VMs over SSH on the management plane, containers over
the Docker connection — never hand-maintained. Tasks stay plain, auditable
commands; spec-derived content is passed encoded so untrusted strings never
reach a shell unquoted. Per-host, per-service results come from the PLAY
RECAP and the readiness probes, not from "the playbook exited 0".
Re-application is idempotent; drift detection reuses the same probes.

### Readiness gate (before ready, before exercise)
Configuration success is not readiness. An environment becomes `ready`
only when, for every instance:

1. every declared service answers a protocol-level probe from its intended
   consumer (DNS answer, DHCP lease, LDAP bind/search, SMTP→IMAP round
   trip, HTTP status/body, SQL result, SSH login);
2. every declared cross-service integration passes (workstation
   resolves/leases via gateway; mail authenticates via directory; web app
   reads DB; logs from the host arrive at the sensor);
3. the sensor canary for the host appears in collected telemetry;
4. every planted vuln on the host passes its proof check from the attacker
   vantage, verified in the target's own telemetry — never by exit code.

Any failure names the host/service/probe and fails closed: the env is
destroyed or quarantined unscored. There is no "ready-ish".

### Observability plane (out-of-band)
Guests forward audit, auth, and service logs over the management/telemetry
network to the collector; a compromised guest cannot reach or suppress
that plane. Events are normalized (process, network, file, auth, DNS/DHCP,
directory, mail, web, DB) and attributed by source (attacker address → red,
host-local → noise/platform, sensor-verified canary → platform), never by
payload self-description. The event store remains append-only and
hash-chained; Langfuse holds agent trajectories only. The Docker runtime's
`docker logs` collector is the same idea for containers.

### Runtime adapter (one seam for exercise/gates)
Exercise and gate code talks to a small runtime-adapter interface —
`execOnAttacker`, `execOnTarget`, `collectTelemetry`, `isolateHost`,
`blockSource` — implemented for Docker and for VMs. Scripted red/blue and
the model-agent loops use the adapter, so a scenario runs unchanged on
either runtime; enforcement that a runtime cannot do (e.g. "disable
account" on Docker) is audited as unenforced and earns nothing.

### Red / blue agents (autonomous adversary simulation)
Red attacks from the design-defined position through the lab's real
services, within ROE, step/token/wall budgets, and a pinned technique
pack. Objectives are proven by platform-planted, per-run random proof
values that must return through real tool output **and** be seen in
independent telemetry. Blue reads only collected telemetry, detects via
promoted Sigma rules, and responds from the allowlist; model-driven blue
must cite telemetry rows it was shown (host + source match) with a
technique from the pinned ATT&CK pack. Deterministic guardrails reject
unsupported claims and count them per run. A scripted baseline adversary
proves each objective is solvable without any model, so lab validity
never depends on model availability.

### Persona agents — "little Muses" inside every environment
Each generated organization is populated with characteristic personas who
use the lab's real services: named employees with roles (CEO, HR, IT
admin, intern), workstations, credentials (some weak/reused — planted
realism, labelled), routines, and relationships. Personas send mail, use
the web app/DB, resolve names, and make mistakes through the actual
protocols; their traffic is real noise in the same telemetry blue reads,
labelled `actor=noise` for scoring only. Personas are also
social-engineering surface within ROE. Cost control: routine traffic is
templated/deterministic; a model is used only for variation where it
earns its cost.

### Evaluator and trace pipeline
Run-scoped correlation: one `run_id` joins Langfuse trajectory ↔ ground
truth → export. The evaluator computes the locked rubric (ATT&CK
visibility vs analytic coverage, MTTD/MTTR, containment, FP rate) from
ground truth only, excluding `proof`/`noise`/`platform` rows, and emits
the Navigator layer from the pinned ATT&CK STIX bundle. Scores carry
mode, backend, truth layer, per-role model IDs, and guardrail counters.

## Data model (first slice)

- `EnvironmentSpec` (shared/): version, provider, org/archetype, topology
  (subnets/firewall), instances (hostId, subnet, role, runtime, OS,
  resource profile, structured services, dependencies, profile ref),
  personas, objectives, required telemetry, planted vulns, budgets,
  difficulty, truth layer, seed.
- `Deployment`: lifecycle status, Pulumi stack identity, access info, cost
  estimate, drift status, per-host readiness evidence.
- `Run`: exercise; links environment version, technique-pack version,
  catalog/profile/image versions, per-role model IDs, guardrail counters,
  scores.
- `Trace`: joined trajectory + ground truth per run; exportable dataset
  version (content-hashed, proof rows excluded).

## API surface (first slice)

Supabase-first surface: PostgREST for sync APIs (`environments`,
`deployments`, `runs`, `traces`, `datasets`), Storage for artifacts,
Realtime channels per deployment/run. Auth: Clerk session → Supabase
third-party auth (RLS keyed on Clerk JWT claims).

## Lock-in design amendments

### Scoring and coverage
Evaluator computes MITRE-style visibility vs analytic coverage from
held-out ground truth; the coverage artifact is an ATT&CK Navigator layer
from the pinned ATT&CK STIX bundle per run. Scores carry `run_mode`,
`backend`, `truth_layer`; cross-class ranking is disallowed.

### EnvironmentSpec extensions
`objectives[]` {asset, technique_id, success_signal, points},
`required_telemetry[]`, `seed`, `difficulty`, `truth_layer`
(`xen-vmi | kvm-vmi | mirror-only`), per-instance `runtime`
(`vm | container`), `personas[]` as first-class spec citizens, and (per
this revision) per-instance `subnet`, structured `services[]`
{kind, impl, port, readyWhen}, `dependsOn[]`, resource profile, and
machine-profile reference. Hybrid rule: org labs are VMs; containers are
the small dev scenario. Design validation rejects objectives without a
verifiable signal and services outside the catalog.

### Run identity
One `run_id` minted at run creation, propagated to Langfuse traces,
event-store rows, Pulumi stack tags, guest metadata, osquery/Zeek logs,
and exports. Join keys: (`run_id`, `host_id`, timestamp within declared
skew tolerance). Late/out-of-order/dropped events are recorded;
over-skew windows are marked unscorable. `host_id` is the single instance
identity across every plane.

### Detection system
Sigma (SigmaHQ) is the detection interchange, compiled to the normalized
event store. Detections are versioned, tested by offline replay over
stored telemetry, and promoted before live scoring. Response allowlist:
isolate host, block IP/domain, kill process tree, disable account,
snapshot — each audited; unenforceable responses earn no containment.

### Labels and datasets
Taxonomy: `technique_id`, `step_id` (Atomic GUID), `actor`
(red/blue/proof/noise/platform), `outcome`
(attempted/succeeded/failed/detected/contained). Adjudication overrides
are versioned. Exports are content-hashed immutable snapshots, split by
scenario family with leakage checks, proof rows excluded, redaction
policy version recorded, and per-example pins (spec digest, pack,
catalog/profile/image, model/tool versions).

### Persona agents
See "Persona agents" above. Persona actions are labelled `actor=noise`
(persona ID attached), hidden from blue as ground truth but visible as
ordinary telemetry — blue must separate persona behaviour from red
behaviour, which is what makes the FP budget meaningful. A compromised
persona account is a legitimate attack step with ground-truth labelling.
Persona reports are never scorer truth.

### Mandatory prerequisites (run-start gates)
auditd/eBPF (Linux) for process lineage + osquery state (osquery alone
never satisfies the gate); service readiness (§ Readiness gate); sensor
canary must appear in telemetry before scoring unlocks; benign noise
generation (`actor=noise`, hidden from blue). Deploy gate: Pulumi
preview + CrossGuard policy pack (mandatory tags, deny open egress,
require TTL).

### Decided defaults — provisioning, proof, red, telemetry, exercise, training, ops
- **Provisioning:** TypeScript + Pulumi Automation API; local file state
  backend (per-org encrypted dirs, worker single-writer locking);
  digest-pinned golden guest image and container images; hourly orphan
  sweeper covering Docker and QEMU/bridge/disk artifacts; pre-flight cost
  estimate × spec, blocked over cap.
- **Proof & config:** Proof = live exploit from red vantage with
  non-destructive planted proof, verified in telemetry (never exit-code
  alone). Fail → quarantine/destroy, never scorable until green. Vuln
  catalog is versioned per vuln (technique, pinned version, placement,
  proof GUID, difficulty).
- **Red runtime:** planted-proof objectives as ground-truth steps; ROE
  machine-enforced (egress deny + argv pre-check as defence in depth —
  the network is the real boundary). Difficulty presets (noisy/standard/
  stealth) shape red traffic and noise rates.
- **Telemetry completeness:** auditd + service logs default-on,
  normalized, shipped out-of-band with drop counters; a canary window
  with sensor blindness is unscorable.
- **Exercise control:** platform sinkhole (DNS+HTTPS) inside the env,
  byte-counted, never forwarded — the only definition of exfil success.
- **Training consumer:** SFT trajectories + preference pairs first;
  step-level reward fields stubbed for later RL.
- **Platform ops:** per-run credentials destroyed at teardown; datasets
  immutable per org; default-deny egress. Correctness principle: verified
  by telemetry/policy, never asserted by the actor that did the work.

## Technology choices

TypeScript strict, ES modules, Node ≥ 18; Clerk (identity/orgs) + Supabase
(Postgres+RLS keyed on Clerk JWT, Storage, Realtime); TypeScript workers
for agents/Pulumi/Ansible/evaluator; Temporal for durable execution;
Pulumi in TypeScript via Automation API + CrossGuard, **local file state
backend**; QEMU/KVM on Linux for org-lab guests (Debian golden image
pinned by digest; Packer recipe versioned in-repo), Docker for the
dev/regression runtime and the platform plane; Ansible for configuration;
Langfuse for LLM agent trajectories only (ground truth in the append-only
hash-chained event store); Prometheus metrics; auditd + osquery + service
logs for endpoint/service telemetry (Zeek/Suricata/Velociraptor and
DRAKVUF/LibVMI remain later options, not claims). Agent-orchestrator
driven with minimal human oversight (policy auto-approval, escalation
only on violations).

## Alternatives considered

- Fixed template library only (reliable, but contradicts the prompt-driven
  goal; archetypes are a catalog input to the designer, not a replacement
  for it).
- Fully generative with no verification (rejected: environments may be
  unsolvable or unexploitable; readiness + exploitability proof required).
- Single provider (rejected: provider-neutral spec contains this
  complexity; AWS/GCP branches stay behind the same spec).
- Containers as the org-lab runtime (rejected as primary: shared host
  kernel cannot provide auditd/eBPF process lineage per host; kept as the
  dev/regression runtime where it is already verified).
