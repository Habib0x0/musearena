# Tasks — Follow-on Platform

> Revised 2026-11-03. F-4…F-16 are **ready**: requirements and design are
> accepted (`design.md` §12 records every decision). No task may be marked
> `completed` without an observed verification line, and live verification
> needs an applied migration.

## Existing tasks

### F-1: Template registry
- **Status**: partial · **Wired**: yes · **Verified**: partial — in-memory registry unit-verified 2026-10-27; backend registry↔Supabase persistence was wired 2026-11-04 (org-scoped load, digest-verified rows, max-version allocation, retry on unique-version conflict) with focused tests 5/5 and a read-only live store probe (0 rows for two orgs). Migration 0016's unique org/name/version guard is authored and disposable-Postgres verified but not yet applied to production, and no live template write has been observed
- **Requirements**: §1
- **Description**: Versioned, family-grouped EnvironmentSpec registry with pinned digests.
- **Acceptance**: Register two versions of one template; latest fetch returns v2; family listing filters correctly.

### F-2: Training pairs surface
- **Status**: partial · **Wired**: yes · **Verified**: partial — unit-verified 2026-10-27: exactly one pair for one success+one distinct failure per technique; success labels from ground truth only (blue containment no longer counts); RL step-rewards still stubbed by design
- **Requirements**: §2.4
- **Description**: SFT examples + preference pairs derived from DatasetExport.
- **Acceptance**: Export with one succeeded and one failed attempt on one technique yields exactly one preference pair.

### F-3: Marketing site build
- **Status**: completed · **Wired**: n/a · **Verified**: partial — `npm run build` emits marketing/dist/index.html (re-verified 2026-10-27); no automated test asserts the Designer link
- **Requirements**: §3
- **Description**: Static marketing page with a real build emitting dist/index.html.
- **Acceptance**: `npm run build` in marketing emits dist/index.html containing the Designer link.

---

## Accepted tasks (ready to implement)

### F-16: Learning API host
- **Status**: in_progress · **Wired**: yes · **Verified**: partial — live 2026-11-03 on local Supabase: the host booted on `MUSEARENA_API_PORT=8788`, `/health` returned the service payload, `/design` was 404 on this server, and a missing capture key was 401 and logged. Unit (`test/api.test.mjs` 5/5): 404/405, invalid/no-role sessions, 403 naming the required role, org-from-token-not-body, key format. The live smoke also proved the Supabase `capture_keys` lookup and role refusal. **Not met**: `.platform.env` carrying the port (the CLI path was changed but not exercised — it needs a Pulumi `up`), and a real Clerk-issued session token
- **Requirements**: §2.1, §2.10
- **Depends on**: design §4, §4.1
- **Description**: The process that owns every §4 route. Health endpoint, Clerk verification via `lib/clerk-jwt.ts`, a separate capture-key verifier, org resolution before any row access, one JSON error contract, and a host-process entry (`api/main.ts`) whose port the deployment CLI writes to `.platform.env`. Design-only routes stay in `designer/server.ts`.
- **Acceptance**:
  1. The server boots on `MUSEARENA_API_PORT` (8788) and `/health` answers 200.
  2. A Clerk-authenticated call takes its org from the verified token, never from the request body.
  3. A capture-key call with a missing or malformed key is 401 and logged; an unknown key is 401 and logged; a revoked key is 401 and audited against its owning org.
  4. The designer server is unchanged and exposes no learning route.
  5. `.platform.env` carries `MUSEARENA_API_PORT` (default 8788) and the server starts with it; it is a host process, not a Pulumi container.
  6. A caller without the required org role gets 403 naming the role; a role claim cannot be asserted from the request body.
- **Verification**: boot test; a foreign-org body field ignored; a revoked-key refusal; a role-refusal test; designer route inventory unchanged.
- **Note**: no other task may add a route to this server before it exists; F-4 is the first consumer.

### F-4: Trace record and capture
- **Status**: completed (live-verified 2026-11-03 on local Supabase 2.117, migrations 0001–0006) · **Wired**: yes · **Verified**: yes — `scripts/learning-smoke.mjs` 13/13: a real publish wrote one trace row per joined step; a second publish left exactly one row and the same content hash; a capture key posted an external step for its own org; a body `orgId` was rejected 400; a revoked key was 401 and audited. Schema checks on Postgres 16: upsert idempotency, org RLS isolation, member insert refused, `key_hash` unreadable while `name` is readable. Unit: `test/traces.test.mjs` 4/4. Not claimed: production Supabase apply (deployment step, not code)
- **Requirements**: §2.1
- **Depends on**: F-16, design §3.1, §4
- **Description**: Persist one trace row per joined step; add the versioned capture endpoint and one-time capture keys.
- **Acceptance**:
  1. An exercise publish writes one row per step, idempotent on `(org, run, step index)`.
  2. A capture key can submit a trace for its own org and nothing else.
  3. Re-publishing a run does not duplicate rows.
  4. A revoked key is rejected and the attempt is audited.
- **Verification**: unit test for the row mapping; live publish against a migrated database; a rejected foreign-org capture.

### F-5: Corrections and label adjudication
- **Status**: completed (live-verified 2026-11-03 on local Supabase 2.117, migrations 0001–0006) · **Wired**: yes · **Verified**: yes — `scripts/learning-smoke.mjs`: a correction was recorded with before/after and reviewer; a dispute was filed once (duplicate refused 409); a reviewer's adjudication was 403 naming the operator role; an operator adjudication moved the row to version 2 and `adjudicated`; re-publish changed the snapshot hash and the trace outcome; the stored `export.json.gz` contains the adjudicated label; `CORRECTION_RECORDED`, `LABEL_DISPUTE_FILED` and `LABEL_ADJUDICATED` audit rows are present. Unit: `test/review.test.mjs` 5/5 including instant matching. Postgres: unique `(org, run, step_at)` and the status trigger. Not claimed: production Supabase apply
- **Requirements**: §2.2
- **Depends on**: F-4, design §3.2, §3.11
- **Description**: Reviewer actions on traces; versioned disputes; adjudicated labels applied before dataset hashing.
- **Acceptance**:
  1. `approve|reject|edit|reprompt|label` rows carry before/after and reviewer.
  2. A dispute is filed once per `(org, run, step)` and resolved with a version bump.
  3. An export after adjudication is re-hashed and contains the adjudicated label.
  4. Every action writes an audit entry.
- **Verification**: pure tests for instant matching and re-hash; live row inspection.

### F-6: Signals and graders
- **Status**: completed · **Wired**: yes · **Verified**: live — 2026-11-03 on local Supabase (migrations 0007 + 0009): a rule signal was defined at version 1, hit exactly one trace, and re-running it left exactly one hit; a model signal without `definition.model` is refused 400, a valid one runs and every result row carries `label.model_id` (the pinned judge) plus `score`; an enabled `continual` rule signal graded a newly captured trace through the capture route with no manual run. The judge client is injected in the smoke (no Meta call); production resolves it through `resolveModel("judge", org, definition.model)`, which re-checks the Meta allowlist. Unit: `test/signals.test.mjs` 4/4 (all/any, ops, model definition pinning)
- **Requirements**: §2.3
- **Depends on**: F-4, design §3.3, §3.8
- **Description**: Signal definitions and hits; rubric/deterministic/model graders, versioned.
- **Acceptance**:
  1. A rule signal produces one hit per matching trace and is idempotent.
  2. A model grader pins the judge model ID in every result.
  3. A grader can be applied to a new trace automatically (continual grading).
- **Verification**: signal replay test; judge result carries `model_id`.

### F-7: Role-aware dataset builder
- **Status**: completed · **Wired**: yes · **Verified**: live — 2026-11-03 on local Supabase (migration 0010): a selection over two runs built one snapshot with red and blue files (`counts.redSft=1`, `blueSft=1`), recorded `family/split/roles/filters/runIds` plus the applied correction and adjudication ids; a reviewer correction changed the exported completion to `pg_dump --schema-only` while the trace row still reads `pg_dump`; `sft.jsonl` is byte-equal to `red-sft.jsonl`; rebuilding the same selection reused the row/hash; the same family refused a `test` split (409); a signal-hit + correction-kind filter selected exactly one trace; `GET /datasets` returned hash, roles and leakage. Unit: `test/datasets.test.mjs` 6/6, including byte-identical legacy red SFT/pairs vs `training/pairs.ts` when no corrections/adjudications exist. Interpretation: `family` is supplied explicitly by the build request (and persisted), not inferred from the spec.
- **Requirements**: §2.4
- **Depends on**: F-4, F-5, F-6
- **Description**: Build red and blue datasets from a recorded selection; emit per-role SFT and preference files.
- **Acceptance**:
  1. Selection filters are recorded in dataset metadata.
  2. Red and blue files are separate; legacy red-only files stay red-only.
  3. Family/split and content-hash leakage rules are enforced.
  4. Proof/noise/platform rows are absent.
  5. A correction on a selected trace changes the exported completion and its id is recorded in `selection`; the original action stays readable.
  6. A dataset with no corrections and no adjudications exports byte-identically to one built before those features existed.
- **Verification**: builder test over a crafted trace set; manifest role counts; leakage refusal; a corrected-trace export diff.

### F-8: Meta-only model registry
- **Status**: completed (live-verified 2026-11-03 on local Supabase, migration 0008) · **Wired**: yes · **Verified**: yes — registered a red base model (`served_model` muse-spark-1.3); `role=red` resolved to the registry row and `role=blue` fell back to its base; an unapproved provider value and an unapproved served ID were both refused 400; `GET /models?role=red` returned the row. Unit: `test/models.test.mjs` 3/3 (allowlist, Modal path, four roles, strict input). Not claimed: a trained row becoming `ready` only after a succeeded run (needs F-9). 2026-11-04: the `meta-modal` allowlist now also admits Muse Glimmer (`glimmer` served name / `meta-models/Muse-Glimmer-30B`) for small agents, canonicalizes the repository ID to the served name, and routes it to `ep-glimmer`; surface-unset base resolution chooses Spark for primary roles and Glimmer for personas when Modal is configured.
- **Requirements**: §2.5
- **Depends on**: design §3.5, §6; Req §2.11
- **Description**: Register base and trained models; resolve per role; fail closed on non-Meta surfaces.
- **Acceptance**:
  1. Registration records name/version/base/provider/status/artifact.
  2. Role resolution returns only approved models for that role.
  3. A non-Meta model ID is refused at construction.
- **Verification**: registry test; resolution test; refusal test.

### F-9: Training runs
- **Status**: in_progress · **Wired**: yes · **Verified**: partial — lifecycle, budget gate, no-trainer parking, fake-trainer success/failure and migration 0012 are unit/local-rollback verified 2026-11-03; the live schema was operator-applied and re-probed present 2026-11-03, but no real trainer run has been observed yet (`META_TRAINER_URL` unset)
- **Requirements**: §2.6
- **Depends on**: F-7, F-8, design §5, §6
- **Description**: Role-specific SFT/DPO/LoRA/GRPO runs with approval, manifest export and trainer adapter.
- **Acceptance**:
  1. A run pins dataset, base model, role, method and config.
  2. Production-targeted runs require approval before `running`.
  3. No trainer ⇒ `awaiting_trainer` with a manifest, not success.
  4. Success creates a `ready` model with an artifact hash; failure/cancel creates none.
  5. A run created without `budget_usd` is refused; `spent_usd > budget_usd` transitions to `cancelled` and is audited.
- **Verification**: lifecycle test with a fake trainer; manifest inspection; failure path; an over-budget cancellation.

### F-10: Evaluations and calibration
- **Status**: in_progress · **Wired**: yes · **Verified**: partial — suite pinning, paired means/spreads, inconclusive deltas, clock-skew exclusion, Brier/ECE, Wilson intervals, leaderboard grouping and migration 0013 are unit/local-rollback verified 2026-11-03; the production trial runner is injected, not yet wired to deployment execution, so API runs fail honestly until one is configured
- **Requirements**: §2.7
- **Depends on**: F-8, F-14, design §7 (including the Baseline rule: a candidate is compared with the untrained base model for its role)
- **Description**: Held-out suites; red and blue metric panels; calibration (Brier/ECE); clock-skew exclusion.
- **Acceptance**:
  1. The suite pins spec and technique-pack digests.
  2. Blue reports MTTD, containment, FP, evidence correctness, Brier and ECE.
  3. A skew-window technique is excluded from MTTD and calibration.
  4. Candidate-vs-baseline deltas are paired on the same suite.
  5. Three trials by default; metrics report mean and min/max spread; a delta inside the spread is `inconclusive`.
- **Verification**: crafted-join calibration test; suite digest mismatch refusal; a trials test where the spread straddles the delta.

### F-11: Model deployments
- **Status**: in_progress · **Wired**: yes · **Verified**: partial — promotion gate/refusal audit, one-active alias, rollback/restore, traffic pinning into the run record, exercise-start client pinning and migration 0014 are unit/local-rollback verified 2026-11-03; the production deployment table is now present, but no live promotion/rollback row has been observed
- **Requirements**: §2.8
- **Depends on**: F-10, F-14 (the alias must resolve to a pinned model at exercise start)
- **Description**: Alias promotion per role with evaluation gate, approval, traffic percentage and rollback.
- **Acceptance**:
  1. Promotion without a passing evaluation is refused and audited.
  2. Exactly one active deployment per `(org, alias, environment)`.
  3. Rollback restores the previous target and audits both.
  4. Exercise start pins `{alias, modelId, trafficPct}` into the run record; an evaluation uses 100% of the candidate.
- **Verification**: promotion/rollback test; active-uniqueness check; a run-record assertion for the pinned tuple.

### F-12: Continual loop
- **Status**: in_progress · **Wired**: yes · **Verified**: partial — trigger drafting, open-proposal dedupe, approval-to-queued-run conversion, rejection, audits and migration 0015 are unit/local-rollback verified 2026-11-03; server-derived aggregates and an opt-in scheduled worker sweep were added 2026-11-04 (watermarked labelled traces/corrections, model-agent-only regression, newest built-dataset/approved-base selection, proposals only) with unit tests and a read-only live Supabase probe. The sweep is enabled on the detached Linux worker (PID 104476) and its first live pass reported `orgs=5 proposals=0 skipped=0 errors=0`; no live proposal has been observed because production currently has no agent traces/corrections/agent-mode runs or eligible built-dataset/base defaults
- **Requirements**: §2.9
- **Depends on**: F-6, F-9, F-10, F-11
- **Description**: Propose (never auto-start) training from new traces, corrections or regression; enforce the eval gate.
- **Acceptance**:
  1. Each trigger produces a proposal naming role/dataset/base/method.
  2. No training starts without approval.
  3. A failed candidate leaves production untouched.
- **Verification**: trigger test; failed-candidate test.

### F-13: Learning UI
- **Status**: in_progress · **Wired**: yes · **Verified**: partial — tabbed learning console (overview/data/signals/datasets/models/training/evaluations/graders/deployments/proposals) reads the learning API with real empty/error states and lifecycle actions; frontend typecheck/lint/build and HTTP route checks pass 2026-11-03 and the live learning tables are now present. Not verified in a browser (no Chromium; Clerk secret/org roles still gated)
- **Requirements**: §2.1–§2.9
- **Depends on**: F-4…F-11
- **Description**: Learning navigation group with Overview, Data, Signals, Datasets, Models, Training, Evaluations, Graders, Deployments.
- **Acceptance**:
  1. Every listed surface renders real data and empty states, no mock data.
  2. Lifecycle states and approvals are visible.
  3. A failed request shows the server's reason.
- **Verification**: typecheck/build; live data on each page.

### F-14: Meta model-plane enforcement
- **Status**: completed · **Wired**: yes · **Verified**: live — `learning/models.ts` holds `resolveServedModel`/`resolveModel` (registry `ready` row, else verified base) and `resolveAgentClients`, the one red/blue factory both exercise modules call. Every ID is re-checked against the Meta allowlist; a `meta-modal` row is refused for an agent role; `judge` is a real `ModelRole`. Tests may inject clients explicitly; production cannot construct an agent client any other way. The resolved served ID lands in `Run.modelIds` (`red`/`blue`/`persona`). Live: registry red + base blue, Modal-row refusal, unapproved provider/ID refused, 17/17 smoke checks; backend 186/186. Superseded in part 2026-11-04: Modal Spark/Glimmer tool turns are verified, so approved Modal registry rows now resolve to Modal agent clients; an explicit Meta surface rejects a Modal pin instead of substituting it, and unresolved personas use Glimmer on Modal.
- **Requirements**: §2.11
- **Depends on**: design §12.9
- **Description**: One client factory; Meta Model API + Meta's Modal Muse Spark Open; fail closed otherwise; pin resolved IDs.
- **Acceptance**:
  1. Every production role resolves to an approved Meta surface.
  2. Failover stays inside Meta surfaces.
  3. The resolved model ID is pinned in the run/result.
- **Verification**: resolution test for every role; refusal test.

### F-15: Environment-spec calibration and adjudication filing
- **Status**: in_progress · **Wired**: yes · **Verified**: partial — Brier/ECE calibration now replaces the FP-derived value in rubric/evaluation paths and a trace with no Atomic GUID step can file a dispute under its trace identity (unit-verified 2026-11-03); the live schema is now applied and a real Linux/KVM host has passed the full direct scripted VM exercise smoke, multi-host routing (F-22) and the routed Linux production worker/platform are now deployed and scripted-workflow verified, but the environment-spec §7.1/§11.2 model-agent production live runs remain gated by Meta billing and the still-unverified trainer/evaluation/browser paths
- **Requirements**: §2.2, §2.7
- **Depends on**: F-5, F-10
- **Description**: Bring the environment spec's §7.1 calibration and §11.2 dispute filing to a complete state (the queue exists; filing and calibration are missing).
- **Acceptance**:
  1. A conflicting auto-label can be filed without a manual SQL insert.
  2. Calibration is computed from held-out ground truth, not from 1 − FP rate.
- **Verification**: filing test; calibration test.

### F-17: Platform selection and provisioning repair

- **Status**: in_progress · **Wired**: yes · **Verified**: no (unit + live in-process design verified; browser design run and Meta-agent path still blocked below)
- **Requirements**: §2.12 (platform selection), environment spec gates
- **Description**: Add the shared platform-selection contract; make
  deployability and wiring-plan failures enter the designer's one bounded
  semantic repair; let the operator choose runtime target, designer model
  surface, and exercise engine; refuse unavailable/unverified combinations
  before spending or provisioning and ask for an explicit alternative; pin the
  selection through approval, trigger, workflow, exercise, and run records.
- **Acceptance**:
  1. A generated FreeIPA-on-Debian and vuln/objective-on-mail design receives
     one repair quoting the exact deployability reasons; a corrected reply is
     returned provisionable, and a stubborn reply is never repaired twice.
  2. The Designer shows runtime, model-surface, and exercise-engine controls;
     unavailable selections stop with named alternatives and no silent switch.
  3. An approved deployment records the selection, and the worker chooses the
     scripted or model-agent exercise from that record rather than only from a
     worker-global environment switch.
- **Verification**: focused designer repair test; designer endpoint contract
  test; frontend typecheck/build; one browser design run with the selected
  platform visible on the artifact.
- **Dependencies**: none.

### F-18: Red-team, blue-team, and monitoring operations UI

- **Status**: in_progress · **Wired**: yes · **Verified**: no (build/typecheck + HTTP + real export verified; interactive browser check pending)
- **Requirements**: §2.12 (red path, blue dashboard, monitoring, dataset provenance)
- **Description**: Build run-scoped Red Team, Blue Team, and Monitoring pages
  plus a Learning shell with honest empty states. Planned paths derive from
  the approved spec; executed paths, detections, and dataset provenance derive
  from the real joined dataset export and run/deployment rows. Scripted runs
  are labelled as deterministic harness runs, never as model-agent behaviour.
- **Acceptance**:
  1. Selecting a scored run renders its planned attack paths and, when its
     export is readable, the executed red steps in order with outcomes and
     matched telemetry.
  2. The blue view renders detections/responses and score metrics from the same
     joined evidence; missing exports produce an explicit unavailable state.
  3. Monitoring renders live deployment/exercise/dataset state and updates via
     the existing realtime deployment/run subscriptions.
  4. Dataset provenance names source run, engine, split, hash, actor counts,
     matched steps, and dropped steps; no page fabricates a trajectory.
- **Verification**: frontend typecheck/build; browser check of all three pages
  against an existing scored run and its real dataset export.
- **Dependencies**: F-17 for platform labels; existing runs/datasets read paths.

### F-19: Orchestrated red campaign and blue log-monitor agent loops

- **Status**: in_progress · **Wired**: yes · **Verified**: partial — unit/regression verified 2026-11-03; 2026-11-04: the first live two-objective Modal-agent VM exercise completed cleanly (red/blue Spark-based Modal defaults, personas on Glimmer) with 0 false positives and a verified 26-step dataset, but scored 0/2 with no alerts, so no successful multi-objective model-agent run is claimed (Meta model agents remain blocked by billing outside this codebase, and no Chromium is available for the interactive UI check)
- **Requirements**: §2.12 items red-4 and blue-5
- **Description**: Replace the sequential red-objective for-loop with a red
  orchestrator loop: the coordinator delegates one remaining objective at a
  time with a directive, receives only the platform-verified retrieved/not
  outcome and executed-attempt count, then adapts the next tasking. It cannot
  execute commands or see proof values; invalid/premature tasking is refused
  deterministically, and platform fallback attempts any objective the
  coordinator fails to task. Replace blue's single post-hoc paging pass with a
  log-monitoring loop: deterministic anomaly candidates (auth bursts, remote
  database access, execution-shaped rows, sensitive access, volume spikes) are
  computed from telemetry content, surfaced through `monitor_anomalies`, and
  annotated on fetched telemetry pages. Candidates stay triage leads; scored
  detections still require cited rows plus promoted-rule confirmation and the
  existing enforceable-response read-back.
- **Acceptance**:
  1. A scripted coordinator can delegate objectives out of spec order; a
     delegation to a non-existent objective is refused before execution, and
     the second directive can reflect the first objective's verified miss.
  2. Repeated remote authentication failures and remote database access become
     monitor candidates with evidence row ids, while ordinary local work does
     not; monitor IDs are leads only — a row becomes citable and counted as
     examined only when blue pages the underlying telemetry.
  3. `SCORE_COMPUTED` records `redCampaign` (order/decisions/summary) and
     `blueMonitoring` (rows/events/pages/anomalies), and `/red` and `/blue`
     render them with honest empty states for older/scripted runs.
- **Verification**: `backend/test/detection.test.mjs` — “red campaign:
  orchestrator delegates objectives in its chosen order…” and “blue monitor:
  deterministic anomaly candidates…”; root typecheck; full workspace tests;
  frontend oxlint and production build; HTTP checks for `/red`, `/blue`, and
  `/monitoring`. Live model verification waits on Meta billing and a browser.
- **Dependencies**: F-18 operations pages; existing red/blue operator loops.

### F-20: Spec-conformance hardening from the full audit

- **Status**: in_progress · **Wired**: yes · **Verified**: partial — the P0
  code fixes below are unit/regression verified 2026-11-03; production
  closure still waits on the external gates named in progress (live
  migrations 0005–0011 through an operator-approved SQL channel, valid
  Supabase/Clerk credentials, Meta billing, a browser, and a Linux/KVM host).
- **Requirements**: cross-cutting — §2.1 capture integrity, §2.4/§2.5 dataset
  and correction semantics, §2.12 operations honesty, and the exercise,
  platform-selection, and runtime rules in the env-generation spec.
- **Description**: A seven-area read-only audit (six primaries plus an
  adversarial critic) compared every spec area with implementation and test
  owners. Confirmed code defects fixed in this pass: deep secret/proof
  redaction across exports, capture rows, trace rows, dataset shaping and
  legacy pairs, with platform rows excluded; external capture is insert-only
  (identical retry idempotent, differing rewrite `409`) and preserves the
  pinned split; red ROE flattens shell strings and allowlists every explicit
  network target; blue rejects localhost blocks and missing `why`, never
  defends the attacker host, reserves a final verdict turn, and treats monitor
  IDs as non-citable leads; VM scripted enforcement ingests `contained`;
  agent alerts require the same host **and** technique (no host-only Sigma
  fallback) and promotion requires replay evidence for the rule's technique;
  scoring/rubric pairing is host- and objective-scoped with Brier/ECE
  calibration instead of `1 − FP`; provider/mixed-runtime/FreeIPA/
  vuln/objective gates fail closed at deployability and in the Pulumi program;
  unavailable platform combinations (including imported specs and
  agents+Modal) return `409 platform_unavailable` before any designer model
  spend; label corrections change effective outcome/technique in selection
  and shaping; model-signal non-matches are no longer stored or counted as
  hits and graders skip ground-truth-only rows; the blue Detections stat no
  longer falls back to blue step count; run `model_ids` and built-dataset
  rows are parsed honestly; Clerk sessions require an active org and a real
  membership role; Monitoring renders pre-run deployments and ops pages
  subscribe to Realtime invalidations; Temporal defaults match the managed
  platform port; `.env.example` names the configuration surface. Migration
  `0011_trace_integrity_hardening.sql` authors (does not apply) the per-run
  trace hash chain, raw-trajectory append-only trigger, append-only
  corrections, no-delete disputes, and direct-client write revocation.
- **Acceptance**:
  1. `backend/test/spec-conformance.test.mjs` proves deep redaction, capture
     split pinning, ROE bypass closure, blue guardrails, host-scoped scoring,
     technique-bound Sigma promotion, and fail-closed platform gates.
  2. Focused regressions prove label-correction overlays and VM proof-path
     telemetry attribution; the full workspace build/typecheck/test/lint
     gates pass on the final tree.
  3. Migration 0011 applies and verifies a two-row chain in a rolled-back
     local transaction; a label-only update is allowed and a raw-trajectory
     rewrite is refused.
  4. Everything not code-fixable from this session stays named as an external
     blocker; no task is flipped to verified from unit evidence alone.
- **Verification**: root build + typecheck; backend 205/205 and marketing 1/1;
  frontend oxlint clean and production build clean; live health checks for
  Langfuse, Prometheus (`musearena-worker: up`), worker metrics, learning API
  `/health`, and the three ops routes over HTTP; read-only PostgREST probes
  confirm the live learning schema is still absent (`PGRST205`/`42703`).
- **Dependencies**: F-17/F-18/F-19; operator actions for production closure.

### F-21: Real-operation provenance and tradecraft realism

- **Status**: completed · **Wired**: yes · **Verified**: live — 2026-11-03 on
  local Supabase (migrations 0011 harden traces; 0016 adds provenance): an
  exported external agent run (two steps, `source=imported`, caller-named
  framework) and a field blue step (`source=field`) were imported through the
  capture key and stored with their provenance; a blended dataset recorded
  `counts.sources = {synthetic:1, imported:2, field:1}`, `realShare=0.75`,
  `realism.share=1` (all red actions use recognisably real field tooling) and
  `datasets.sources=[field,imported,synthetic]`; a synthetic-only selection
  with `minRealShare=0.5` was refused 422; a `sources=[field]` selection
  returned only the field trace. Unit: `external-runs` 3/3, `tradecraft` 4/4.
- **Requirements**: §2.4 (datasets and provenance), §2.12 (real operations)
- **Depends on**: F-7, F-17
- **Description**: Stop treating synthetic exercises as the only data. A trace
  carries a provenance (`synthetic`, `imported` from an exported external agent
  run, or `field` from a real observation) and an optional caller-named
  framework. The capture contract accepts imported/field steps; a source-neutral
  importer maps an external export to capture bodies; the dataset builder can
  filter by source, reports the source mix and a real-share floor, and reports
  how much red activity uses recognisably real field tooling. The red prompt
  gains a phased field-tradecraft playbook and the blue prompt a field-detection
  playbook.
- **Acceptance**:
  1. An external agent-run export imports through the capture path with
     provenance and is selectable by the dataset builder.
  2. A dataset records in `selection` the source counts, real share and
     real-tool share, and persists `datasets.sources`.
  3. A `minRealShare` floor refuses a selection that is too synthetic (422).
  4. A `sources` filter selects only the requested provenance.
  5. Red/blue prompts describe phased real tradecraft without naming any
     vendor or framework.
- **Verification**: importer and tradecraft unit tests; live import + blended
  build + gates; backend build/tests.
- **Dependencies**: F-7.

### F-22: Multi-host worker routing

- **Status**: completed · **Wired**: yes · **Verified**: yes — routing,
  claim-stamp, task-queue, and maintenance-ownership code is unit/build
  verified locally and on the Linux KVM host 2026-11-03, and corrected
  targeted deployment `3270200b-…` completed the real Temporal/Supabase
  workflow under owner `linux-kvm` with a 3/3 score and TTL teardown (see
  Verification).
- **Requirements**: §2.12 operations; environment-generation worker lifecycle.
- **Description**: Let Mac and Linux workers share one Supabase deployment
  queue without sharing host-local state. Each routed worker has a stable
  `MUSEARENA_WORKER_ID`, accepted routes (`kvm`, `vm`, `container`), and its
  own Temporal task queue (`musearena-<worker-id>` by default). The trigger
  derives the required route from the spec, checks explicit
  `access_info.workerId`/`workerRoute` targeting plus host capabilities
  (acceleration, guest architecture, Windows image, and lab limit), leaves
  another host's row pending, and stamps the owner on the conditional claim.
  Maintenance TTL/drift and live-row TTL orphan handling act only on rows
  owned by the local worker; legacy unowned rows require a legacy worker or
  an explicitly designated `MUSEARENA_WORKER_OWNS_UNROUTED=1` worker.
- **Acceptance**:
  1. A `kvm-vmi` deployment is claimable only by a native KVM worker; an HVF
     worker leaves it pending instead of failing it.
  2. An explicitly targeted deployment is claimed only by that worker and
     starts on that worker's task queue with the owner stamped in
     `access_info`.
  3. Routed maintenance cannot TTL-teardown or drift-mark another worker's
     deployment.
  4. Legacy single-worker mode keeps queue `musearena` and existing claim
     behavior when no worker identity is configured.
  5. A scripted VM deployment targeted to `linux-kvm` completes through the
     real Temporal/Supabase workflow on the Linux host and records that owner.
- **Verification**: `backend/test/worker-routing.test.mjs` (8 tests); root
  build/typecheck/test + frontend oxlint pass (backend 240/240, marketing
  1/1, oxlint 0/0). Linux shared/backend/deployment build, routing tests,
  Pulumi 3.272.0 + Docker plugin 5.2.0, policy-pack install, platform health,
  both routed workers' metrics/Prometheus targets, and strengthened
  `host-preflight --require-kvm` pass. Live acceptance: deployment
  `3270200b-…` was claimed by `linux-kvm` on `musearena-linux-kvm`, reached
  ready after configure/readiness/gates, scored 3/3 and 30/30 with 0 false
  positives, exported a hash-verified 16-step dataset, was observed in
  Langfuse, drift was in sync, and the workflow TTL timer destroyed it with
  `resourcesDestroyed: true` and no leaked QEMU (`VM WORKFLOW OK`).
- **Dependencies**: F-17; Linux Docker daemon access for the platform plane.

---

## Build order

Tasks are accepted, not simultaneous. This follows the milestone table in
`design.md` §14; a task starts only when every task it depends on is `completed`
with its live verification line observed.

| Milestone | Order |
|---|---|
| **M0 Operations** | F-17 → F-18 → F-19 → F-20 → F-22 (operator-priority; does not unblock or replace M1–M6) |
| **M1 Capture** | F-16 → F-4 |
| **M2 Review** | F-5 and F-6 in parallel, once F-4 lands |
| **M3 Data and models** | F-8 and F-14, then F-7 (the builder resolves roles through both) |
| **M4 Train and evaluate** | F-9 → F-10, with F-15's calibration |
| **M5 Deploy and loop** | F-11 → F-12 |
| **M6 Learning UI** | F-13, after M1–M5 |

Cross-cutting: F-1's registry↔DB persistence and F-2's role-aware extension close
inside M3. Every database-backed acceptance line requires `0005` and later
migrations to be applied; until then M1 stays open even if the code is written.

## Reconciliation of unapproved working-tree code

**Resolution 2026-11-03: reverted.** The operator chose "revert it all — rebuild
F-4…F-15 clean from the spec". All learning-platform artifacts listed below were
removed from the working tree: the two migrations, `training/traces.ts`,
`traces/adjudication.ts`, the role-aware `pairs.ts`/`exporter.ts`, the trace row
mapping, adjudication-in-publish, family refusal, run pins, `unscorableWindows`,
the structured `detail` payload, and the shared learning contracts. Backend tests
after the revert: **162/162 pass** (the five learning tests were removed with the
code), typecheck clean. F-2 is back to its 2026-10-27 red-only state. Nothing
outside this spec was touched (T-40 GSSAPI, T-41 workflow, designer, frontend).

The table below is kept as the **rebuild inventory**: it names the task that must
produce each artifact and the verification that closes it. The pre-audit copy is
at `/tmp/arena-prespec-backup/` — reference only, never a source of truth.

Audit evidence: `backend/test/honesty.test.mjs` 17/17 and `tsc --noEmit` clean
at the time of audit. A unit test is not the task's verification line, and every
database-backed acceptance requires an applied migration.

| Working-tree artifact | Authorised by | State at audit (pre-revert) | What closes it |
|---|---|---|---|
| `migrations/0005_learning_platform.sql` (traces, corrections, signals, signal_hits, models, training_runs, evaluations, graders, model_deployments, capture_keys) | F-4…F-11 schema | Written, **unapplied**. Missing the design's §3.4–3.6 columns: `datasets.selection`, `datasets.roles`, `models.role`, `models.training_run_id`, `training_runs.role`. `capture_keys` has no revocation column. | Apply, then add the missing columns in `0007` (never edit an applied migration). |
| `training/traces.ts` (`traceRowsFor`, `persistRunTraces`) | F-4.1, F-4.3, F-4.5 | Unit-verified (`trace rows keep red and blue separate…`). Live idempotency unproven. | Publish the same run twice against a migrated DB → same row count. |
| `traces/adjudication.ts` + `label_disputes` | F-5.1–F-5.4 | Unit-verified filing, adjudication, instant matching. No corrections code; no filing/adjudication endpoint. | Corrections + dispute APIs, then live row inspection. |
| `observability/publish.ts` adjudication-before-hash + family refusal | F-5.3, F-7.3 | Unit-verified; live refusal unproven. | Live: re-export after adjudication re-hashes; a second split is refused. |
| `training/pairs.ts` + `training/exporter.ts` per-role files | F-7.2 (extends F-2) | Unit-verified red/blue separation; legacy `sft.jsonl`/`preference-pairs.jsonl` stay red-only. The F-7 *builder* (selection → counts → build) does not exist. | F-7 builder + manifest role counts. |
| `shared` `RunPins` + `trigger.ts` pins | Environment spec T-13 (§8.3) | Unit-verified, but `TOOL_VERSIONS` is the hard-coded string `musearena/0.1.0` rather than a resolved version. | Resolve from `package.json`; live run row carries the pins. |
| `observability/export.ts` `unscorableWindows` | Environment spec T-13 (§9.3), needed by F-10.3 | Unit-verified. **T-13's "verified live 2026-10-27" line predates this behaviour.** | Reopen T-13's verification line and re-run cold reproduction. |
| `traces/integrity.ts` `applyAdjudications` instant match | F-5.3 | Unit-verified. | Covered by the live export check above. |
| `configurator/ansible.ts` + `readiness.ts` (GSSAPI keytabs/probes) | T-40 (environment spec) | Consistent with T-40, already marked completed/live-verified; the work is simply uncommitted. | Not part of this spec — commit or leave, it does not gate training. |

**Rule that survives the audit:** no new code in these areas until the owning
task's live verification line is observed. Unit green ≠ verified.

### Spec gaps the audit exposed — resolved

All four were decisions, not implementation details, and all four are now
recorded in `design.md` §12:

1. **Corrections → training examples** — §12.7: applied at dataset-build time,
   ids recorded in `datasets.selection`. Acceptance added to F-7.
2. **Evaluation runner** — §12.8: the platform runs the suite itself in the
   worker. There is no `META_EVAL_URL` and no `awaiting_evaluator`; that
   proposal was withdrawn because the platform already owns the runtime.
3. **Runtime model resolution** — §12.9: `resolveModel(role, orgId)` in
   `lib/model.ts` is the single boundary.
4. **Capture-key revocation** — §12.10: `revoked_at` plus
   `POST /capture/v1/keys/:id/revoke`.

The same pass resolved the remaining questions (trainer endpoint, artifact
storage, blue prompts, split policy, persona, baseline, API host,
authorization, budget, traffic, trials, retention). Nothing in this spec is
waiting on a decision.
