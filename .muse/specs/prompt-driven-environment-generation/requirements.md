# Requirements — Prompt-Driven Environment Generation

> Revised 2026-10-27 (operator direction): the designer-built **full virtual
> organization on Linux VMs** is the primary product shape, not a follow-on.
> A lab is only real when every machine actually runs its services — packages
> installed, services enabled, data seeded, tools present — so personas, red
> and blue have something real to interact with. Implementation status and
> evidence live in `tasks.md` / `progress.md`, never in this file.

## Overview

A user describes a cybersecurity training environment in natural language
("a 12-person clinic: gateway, directory, mail, intranet, patient-record DB,
logging, two plausible weaknesses"). The platform designs the full virtual
organization (network topology, instances, **machine profiles and services**,
personas, business data, planted vulnerabilities), provisions it as tiny
Linux VMs on a Linux/KVM host, configures and **verifies every service**,
then runs an autonomous adversary simulation (red attacks through the real
services, blue detects and responds from real telemetry) and records the
exercise as exportable, ground-truth-scored traces for training and
evaluation.

## 1. Environment design from prompt (full virtual organization)

**As a** security researcher **I want** to describe an environment in natural language **so that** I don't design infrastructure by hand.

#### Acceptance Criteria (EARS)

1. WHEN a user submits a natural-language environment prompt THE SYSTEM SHALL return a structured environment design (org archetype, network topology, instance list, per-instance machine profile/services, personas, databases/business data, planted vulnerabilities, objectives) within 2 minutes.
2. WHEN a design is generated THE SYSTEM SHALL present a visual topology map (subnets, routes, firewall boundaries, per-instance services and service dependencies) for review and natural-language refinement.
3. WHEN a user refines the design THE SYSTEM SHALL regenerate only the affected portions and preserve unaffected parts of the design.
4. WHEN a user opens the Designer THE SYSTEM SHALL present a conversational chat interface (Muse pattern) with a live artifact pane (EnvironmentSpec, topology map, cost); the chat thread is the primary control surface.
5. WHEN a design exceeds user budget caps (max instances, max $/hour, TTL) THE SYSTEM SHALL block provisioning and explain which constraint is exceeded.
6. WHEN a design is generated THE SYSTEM SHALL only emit roles, service kinds, implementations, planted-vuln types and objectives that the runtime catalog can actually install, configure and verify; anything else SHALL be blocked at design time with the reason (never silently approximated or substituted).
7. WHEN a design is generated THE SYSTEM SHALL validate org coherence: every objective binds to a host and service in the graph with a proof path; every declared dependency exists; every persona's workstation exists and has the client tools for the services that persona uses; dependency cycles are rejected.

## 2. Infrastructure generation and provisioning (Linux-first)

**As a** platform operator **I want** the design compiled to infrastructure-as-code **so that** environments are reproducible and versioned.

#### Acceptance Criteria (EARS)

1. WHEN a design is approved THE SYSTEM SHALL generate a Pulumi program using canonical resource types (never raw Pulumi URN strings in application code).
2. WHEN provisioning org labs THE SYSTEM SHALL use the local Linux host backend (QEMU/KVM) behind the provider-neutral environment spec; AWS/GCP branches remain deferred behind the same spec and are not required for org labs. Per-instance runtime is `vm` for org-lab hosts; the existing `container` runtime remains a small dev/regression runtime and scores SHALL NOT be ranked across runtimes.
3. WHEN an instance is defined THE SYSTEM SHALL declare a tiny-VM resource profile (vCPU, memory, disk) and THE SYSTEM SHALL check host capacity before provisioning; designs that exceed host capacity SHALL be blocked with the reason.
4. WHEN provisioning completes THE SYSTEM SHALL return access info (endpoints, credentials, connection instructions) per instance, reachable only from the management plane.
5. WHEN provisioning fails partway THE SYSTEM SHALL roll back all created resources or register orphaned resources for cleanup (VMs, bridges, disks included).
6. WHEN an environment reaches its TTL THE SYSTEM SHALL terminate all of its resources automatically.
7. WHEN an environment is versioned/pinned THE SYSTEM SHALL record archetype/catalog/image versions, seed, and Pulumi stack identity so any trace can be replayed against an identical environment.

## 3. Machine configuration, services and readiness

**As a** platform operator **I want** every instance configured to match its design — services installed, enabled, seeded and verified — **so that** the environment actually behaves as specified and can be interacted with.

#### Acceptance Criteria (EARS)

1. WHEN an instance is designed THE SYSTEM SHALL assign it a machine profile: base OS image, packages, users/groups, services (kind, implementation, port), configuration, data seeds, client/server tooling and sensors. The profile SHALL be resolved deterministically from role + declared services; unknown service kinds/implementations SHALL be rejected at design time.
2. WHEN instances boot THE SYSTEM SHALL install, configure, seed and enable every declared service per its profile. Because labs have no public-internet egress, packages SHALL come from the pinned golden image or a host-local package mirror on the management plane; configuration SHALL NOT depend on internet access from inside the lab.
3. WHEN a host is configured THE SYSTEM SHALL install the base tooling on every host (SSH, auditd, osquery, log forwarding, time sync, diagnostic tools), the declared red toolbox on the attacker host, and the client tools for each service a persona host uses (mail, web, DB, directory clients) — an agent or persona SHALL never have to guess whether a tool exists.
4. WHEN configuration completes THE SYSTEM SHALL report per-instance, per-service success/failure and remediate failed instances automatically where possible; an instance with a failed declared service SHALL NOT be marked ready.
5. WHEN configuration completes THE SYSTEM SHALL run a readiness gate before the environment is ready: every declared service SHALL pass a protocol-level probe from its intended consumer (DNS query answered, DHCP lease granted, LDAP bind/search, SMTP send + IMAP login, HTTP response, SQL query), and every declared cross-service integration SHALL pass (workstation resolves/leases via the gateway, mail authenticates against the directory, the web app reads the DB, host logs reach the sensor collector).
6. WHEN a planted vulnerability is configured THE SYSTEM SHALL verify exploitability with a lightweight proof check before marking the environment ready.
7. WHEN configuration is re-applied THE SYSTEM SHALL be idempotent (same declared state), and drift detection SHALL reuse the readiness probes.

## 4. Observation and traces

**As an** AI lab **I want** complete interaction traces **so that** I can train and evaluate agents.

#### Acceptance Criteria (EARS)

1. WHEN any agent interacts with an environment THE SYSTEM SHALL record its trajectory (observations, reasoning, tool calls, actions) to Langfuse under a shared run ID.
2. WHEN environment state changes THE SYSTEM SHALL record ground-truth events (process, network, file, auth, and service events: DNS/DHCP, directory, mail, web, DB) to the out-of-band observability plane.
3. WHEN a run ends THE SYSTEM SHALL join agent trajectories with ground truth into one trace record keyed by run ID.
4. WHEN a user requests training data THE SYSTEM SHALL export traces as versioned datasets (pinned environment version + technique-pack version).
5. WHEN an exploit attempt is observed THE SYSTEM SHALL label it with the corresponding MITRE ATT&CK technique where one exists.

## 5. Autonomous adversary simulation (offensive and defensive agents)

**As a** trainer **I want** agents to exercise the environment **so that** skills can be taught and measured.

#### Acceptance Criteria (EARS)

1. WHEN an environment is ready THE SYSTEM SHALL allow red-team agents to attack it from a network position defined by the design (attacker host, or a design-declared compromised persona/workstation), acting through the environment's real services and protocols; multi-step and multi-host paths within the rules of engagement and step/token/time budgets SHALL be supported.
2. WHEN the red team acts THE SYSTEM SHALL capture every action with ground truth (attack success/failure against intended vulnerabilities); success SHALL be established only by platform-planted proof values returning through real tool output and independent telemetry — never by agent self-report.
3. WHEN telemetry is available THE SYSTEM SHALL allow blue-team agents to detect, investigate, and (if enabled) respond (isolate host, block source, remediate) from a restricted allowlist; responses the runtime cannot enforce SHALL be audited as unenforced and earn no containment.
4. WHEN a red/blue exercise completes THE SYSTEM SHALL score agent performance (objectives achieved, time-to-detect, time-to-respond) and attach scores to the run.
5. WHEN model-driven agents run THE SYSTEM SHALL pin per-role model IDs into the run record and enforce deterministic guardrails: blue responses must cite telemetry rows actually shown (host + source match), technique IDs must exist in the pinned ATT&CK pack, and unverified claims (asserting a proof never retrieved, announcing a response never requested) SHALL be logged and counted.
6. WHEN an objective is scored THE SYSTEM SHALL have a scripted baseline adversary able to attempt it, so lab solvability is proven independent of model availability.

## 6. Platform fundamentals

#### Acceptance Criteria (EARS)

1. WHEN any API request arrives THE SYSTEM SHALL enforce tenant context and row-level security so no tenant can read another tenant's data.
2. WHEN a security-sensitive operation occurs THE SYSTEM SHALL write a hash-chained, tamper-evident audit log entry.
3. WHEN a deployment starts THE SYSTEM SHALL display cost estimates and require acknowledgment above configured thresholds.
4. WHEN infrastructure drifts from desired state THE SYSTEM SHALL detect and report drift per environment.
5. WHEN any deployment event occurs THE SYSTEM SHALL stream progress to connected clients in realtime (Supabase Realtime channels per deployment/run).

## 7. Scoring rubric (lock-in)

**As an** AI lab **I want** a fixed, measurable definition of agent quality **so that** training and evaluation are comparable across runs.

#### Acceptance Criteria (EARS)

1. WHEN an exercise completes THE SYSTEM SHALL compute ATT&CK analytic coverage (Technique/Tactic/General per MITRE Evaluations), visibility coverage, MTTD percentiles, containment correctness, false-positive rate, and calibration from held-out ground truth.
2. WHEN scoring THE SYSTEM SHALL exclude proof-check traffic (`actor=proof`), benign noise (`actor=noise`), and platform operations from red/blue scores.
3. WHEN scores are reported THE SYSTEM SHALL record run mode (blind/adaptive), backend, and truth layer with every score, and SHALL NOT rank scores across different modes/truth layers as directly comparable.
4. V1 quality bars: analytic coverage ≥70% (≥40% exact Technique), visibility ≥90%, MTTD ≤15 min simulated (interactive) / ≤60 min (C2/exfil), containment correctness ≥80%, FP rate ≤10% on benign control runs.

## 8. EnvironmentSpec lock-in fields

#### Acceptance Criteria (EARS)

1. WHEN a design is generated THE SYSTEM SHALL include `objectives[]` (machine-readable: target asset, ATT&CK technique, success condition, points), `required_telemetry[]` per technique, `seed`, `difficulty`, and `truth_layer` in the EnvironmentSpec.
2. WHEN an objective is defined THE SYSTEM SHALL bind it to a verifiable ground-truth signal (canary file hash, sinkhole exfil bytes, service state) — objectives without a signal SHALL be rejected at design validation.
3. WHEN a run starts THE SYSTEM SHALL pin EnvironmentSpec digest, technique-pack version (ATT&CK STIX release), scenario/archetype version, machine-profile and service-catalog versions, guest-image digest, model IDs, and tool versions into the run record.
4. WHEN a design is generated THE SYSTEM SHALL include `personas[]` (role, workstation, access, credentials profile, risk profile, routine, relationships) as first-class EnvironmentSpec fields, pinned per run; persona actions SHALL be labelled `actor=noise` with persona ID.
5. WHEN an instance is defined THE SYSTEM SHALL include its subnet placement, machine profile, structured services (kind, implementation, port, readiness probe), dependencies on other hosts/services, and resource profile — free-text-only service descriptions SHALL NOT be provisionable.

## 9. Run identity and correlation (lock-in)

#### Acceptance Criteria (EARS)

1. WHEN a run is created THE SYSTEM SHALL mint one `run_id` propagated to Langfuse, the event store, Pulumi stack tags, cloud/KVM metadata, Zeek/osquery logs, and dataset exports.
2. WHEN events are joined THE SYSTEM SHALL join on (`run_id`, `host_id`, timestamp within declared clock-skew tolerance) and SHALL record late/out-of-order/dropped events explicitly — silent drops are forbidden.
3. WHEN clocks exceed max skew tolerance THE SYSTEM SHALL flag affected windows as unscorable rather than emitting misleading MTTD values.

## 10. Detection system (lock-in)

**As a** blue team **I want** versioned, testable detections **so that** my performance is measurable and improvable.

#### Acceptance Criteria (EARS)

1. WHEN blue authors a detection THE SYSTEM SHALL accept Sigma rules (SigmaHQ format) as the detection interchange, compiled via pySigma to the event-store backend.
2. WHEN a detection changes THE SYSTEM SHALL version it, run it against stored telemetry (offline replay), and require promotion before it scores live runs.
3. WHEN an alert fires THE SYSTEM SHALL emit (`run_id`, `host_id`, technique ID, Sigma rule ID/version, timestamp, confidence) so MTTD and calibration are computable.
4. WHEN blue responds THE SYSTEM SHALL restrict responses to an allowlist (isolate host, block IP/domain, kill process tree, disable account, snapshot) with per-action audit records.

## 11. Ground truth, labels, and datasets (lock-in)

#### Acceptance Criteria (EARS)

1. WHEN telemetry is ingested THE SYSTEM SHALL label it with the taxonomy: `technique_id`, `step_id` (Atomic GUID), `actor` (red/blue/proof/noise/platform), `outcome` (attempted/succeeded/failed/detected/contained).
2. WHEN labels are disputed THE SYSTEM SHALL route them to an adjudication queue; adjudicated labels supersede auto-labels and the change is versioned.
3. WHEN a dataset is exported THE SYSTEM SHALL emit content-hashed, immutable snapshots with format version, split by scenario family (train/val/test) with near-duplicate/leakage checks, and per-example pins (spec digest, pack version, model/tool versions).
4. WHEN traces are exported THE SYSTEM SHALL redact secrets, credentials, and honey-token values per redaction policy, and record the policy version used.

## 12. Mandatory run prerequisites (lock-in)

#### Acceptance Criteria (EARS)

1. WHEN an environment is built THE SYSTEM SHALL install Sysmon (Windows) or auditd/eBPF (Linux) for process lineage in addition to osquery state collection — osquery alone SHALL NOT satisfy the telemetry gate.
2. WHEN a run starts THE SYSTEM SHALL generate benign background activity (logins, mail, file-share, browsing, admin scripts) labelled `actor=noise`, hidden from blue, for false-positive measurement; where the services exist this SHALL be real protocol traffic generated by personas, not synthetic events alone.
3. WHEN a run starts THE SYSTEM SHALL execute a sensor canary (one known Atomic action) and SHALL block scoring until the canary appears in telemetry within the skew window.
4. WHEN a run starts THE SYSTEM SHALL have passed the §3.5 readiness gate for every declared service; an environment with an unverified service SHALL NOT be exercised or scored.

## Non-functional requirements

- **Isolation:** every generated environment runs isolated (dedicated network, no outbound internet unless explicitly enabled); telemetry ships to an out-of-band observability plane attackers cannot reach.
- **Safety:** offensive training content only runs inside generated environments; no public exposure of vulnerable services; lab data is synthetic only.
- **Reproducibility:** environment spec, seed, archetype/catalog/image/profile versions pinned per run; traces replayable.
- **Cost:** hard caps per design; automatic teardown at TTL.
- **Performance:** design returned ≤ 2 min; a single org lab (≤ 8 tiny VMs) provisioned and readiness-verified ≤ 15 min on the reference Linux host, without public-internet access inside the lab.

## Out of scope

Windows/AD guests until a licensed image is supplied (such designs are blocked, not approximated); AWS/GCP provider branches (deferred by operator decision); KVM-VMI truth claims until a real introspection layer exists (KVM runs are stamped `mirror-only`); template marketplace/versioning UI; compliance reporting pack; RL training harness; public scenario sharing; production use with real organizational data.
