---
name: musearena-exercise-lifecycle
description: The deployment pipeline from approval to teardown — claim, provision, configure, readiness, gates, exercise, score, publish, TTL — and where evidence is produced at each stage. Use this skill when changing worker activities, gate executors, scoring, or diagnosing where a run failed and why.
---

# Exercise lifecycle

One deployment moves through checked stages; each stage is pass/fail with an
audit row, never best-effort. The worker (Temporal) owns the machine from
claim through teardown — a deployment never migrates hosts.

## Stages

| Stage | Status | What must be true to advance |
|---|---|---|
| Claim | pending → provisioning | worker eligible (routes, arch, caps, org limits) |
| Provision | provisioning | guests started (QEMU/Docker), registry written |
| Configure | configuring | Ansible/tasks applied per host; seeds planted |
| Readiness | verifying | probes pass guest-to-guest, not from host logs |
| Gates | verifying | canary on every host + live proof per planted vuln |
| Exercise | exercising | red acts toward objectives; blue monitors |
| Score | ready | every number joined to matched ground truth |
| Publish | ready | dataset content-hashed, traces append-only |
| Teardown | destroying → destroyed | TTL or operator delete; same path |

## Gates (the trust anchor)

`configurator/gates.ts` — the gate can never pass itself:

- **Canary**: a known action executed on the host must appear in
  independent telemetry (fresh nonce per run — a stale log line can't pass).
- **Proof**: each planted vuln's exploit is executed and the marker must
  appear in the target's own log. Exit codes never count. No executor
  configured → the gate FAILS, it does not skip.

Executors per runtime: `vm-executors.ts` (in-guest, QEMU/SSH),
`docker-executors.ts` (from the attacker container, across the internal
network). Unknown vuln types / CVE registry ids throw — fail closed.

## Scoring

A score is computed from the joined export: trajectory steps matched to
ground-truth events (time-skew tolerant). An agent's claim about itself
never counts; `matched` is the join outcome. Blue containment only counts
when the block actually cuts the attacker off (ROE-enforced).

## Where evidence lands

- Traces: append-only, hash-chained (0011), verified by `trace_chain_verify`
- Datasets: content-hashed, immutable snapshots in private storage
- Audit: append-only, hash-chained, names the actor for every write
- Score detail: the `SCORE_COMPUTED` audit entry (mode, models, campaigns)

## Common failures

| Symptom | Cause |
|---|---|
| Stuck in `pending` | worker down, DB unreachable, or not eligible for the route |
| Readiness fails | probe ran from the host, not guest-to-guest — always probe from inside |
| Gate fails "proof NOT seen" | exploit didn't fire or sensor is blind; check the proofLog tail and the sensor |
| Score 0/0 | red reached nothing OR join found no matches — a valid result with clean evidence |
| Training parks `awaiting_trainer` | no META_TRAINER_URL; honest parking, never reported as success |

## Delete semantics

Operator delete of a live environment cancels its workflow (same teardown as
TTL), then marks `destroyed` with who/when. Evidence survives — see the
`musearena-learning-crud` skill.
