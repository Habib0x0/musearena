# Design — Follow-on Platform

> Revised 2026-11-03. This design covers the offensive/defensive model-training
> platform. The exercise/environment contract stays in
> `prompt-driven-environment-generation/`; this surface consumes its traces,
> scores and dataset exports and turns them into a role-specific training loop.

## 1. Product shape

```
exercise run ──► traces ──► feedback/signals ──► datasets ──► training run
     ▲                                                            │
     │                                                            ▼
model deployment ◄── approval ◄── evaluation ◄── candidate model ──┘
```

Two roles are trained independently and share only the exercise vocabulary:

| Role | Learns | Success signal |
|---|---|---|
| **red** | recon → access → exploit → exfil actions | joined ground truth `outcome=succeeded` (planted proof returned through real tool output) |
| **blue** | detect → investigate → respond | joined ground truth `detected` / `contained`, evidence rows actually shown |

Persona models are a later role; judges are models too, but a judge never
labels its own run's ground truth.

## 2. Reuse, don't duplicate

| Existing primitive | Used for |
|---|---|
| `observability/events.ts` (`EventStore`) | append-only trace + ground-truth source |
| `observability/export.ts` (`DatasetExport`) | join, redaction, proof/noise exclusion, content hash |
| `observability/publish.ts` | immutable dataset snapshot + storage |
| `training/pairs.ts` | SFT/preference derivation |
| `evaluator/rubric.ts` | exercise rubric, Navigator layer |
| `exercise/evaluator.ts` | per-run scorecard |
| `lib/audit.ts` | hash-chained audit |
| Supabase RLS | org isolation |
| Langfuse | full transcripts (the platform stores the joined record, not the prompt log) |

The platform does **not** add a second event store and does **not** train on
free-text summaries. Structured `detail` on a trajectory step is the training
input; prose stays for humans and search.

## 3. Data model

All tables are org-scoped with `org_id = (auth.jwt() -> 'o' ->> 'id')`.
Member-writable tables are marked `W`; worker-only tables are `S` (service
role). Existing tables are extended, not replaced.

### 3.1 `traces` (S writes, W reads)

One row per joined step.

| column | meaning |
|---|---|
| `id`, `org_id`, `run_id`, `dataset_id`, `step_index` | identity; unique `(org, run, step)` for idempotent publish |
| `at`, `host_id`, `technique_id` | join keys |
| `actor` | `red` / `blue` / `persona` / `proof` / `noise` / `platform` |
| `observation`, `reasoning`, `tool_call` | human-readable record |
| `action`, `outcome`, `matched` | the labelled action |
| `split` | dataset split at capture time |
| `payload jsonb` | full structured step (trajectory + ground truth + `detail`), **redacted exactly as the dataset snapshot is** |

`run_id` is deliberately **not** a foreign key to `runs`: an external harness may
submit a run the platform never provisioned (Req §2.1.3), and capture must not
require a provisioning row. Org scope, not referential integrity, is what makes
the row safe.

### 3.2 `corrections` (W)

`kind ∈ approve | reject | edit | reprompt | label`, `before jsonb`,
`after jsonb`, `reviewer`, `note`. A correction is append-only in spirit:
edits are new rows, the original action is never overwritten.

### 3.3 `signals` / `signal_hits` (W definitions, S hits)

`signals`: `name`, `kind ∈ rule | model | human`, `definition jsonb`,
`version`, `enabled`.
`signal_hits`: unique `(signal_id, trace_id)`, `label jsonb`, `score`.

### 3.4 `datasets` (S writes, W reads) — extended

Add `family text`, `selection jsonb`, `roles text[]`.
`selection` records the filters, the resulting counts, and the ids of every
correction and adjudication that changed the snapshot, so a dataset can be
explained without re-deriving it.
Existing: `content_hash`, `format_version`, `split`, `redaction_policy_version`,
`storage_path`. Unique `(org, content_hash)`; one family may not straddle splits.

### 3.5 `models` (S writes, W reads)

`name`, `version`, `base_model`, `provider ∈ meta | meta-modal`, `status ∈
available | training | ready | failed | deprecated`, `artifact_path`,
`metrics jsonb`, `role text[]`, `training_run_id`.

### 3.6 `training_runs` (S writes, W reads)

`dataset_id`, `base_model_id`, `output_model_id`, `role ∈ red | blue`,
`method ∈ sft | dpo | lora | grpo`, `config jsonb`, `status ∈ queued | running |
succeeded | failed | cancelled | awaiting_trainer`, `metrics jsonb`, `error`,
`budget_usd numeric not null`, `spent_usd numeric not null default 0`,
`approved_by`, `approved_at`, timestamps. A run cannot be created without a
budget; `spent_usd > budget_usd` is a cancellation, not a warning.

### 3.7 `evaluations` (S writes, W reads)

`model_id`, `baseline_model_id`, `suite jsonb`, `status`, `metrics jsonb`,
`comparison jsonb`, `error`. `suite` pins the held-out specs and their digests.

### 3.8 `graders` (W definitions)

`kind ∈ rubric | deterministic | model`, `spec jsonb`, `version`, `enabled`.
A `model` grader pins the judge model ID in every result.

### 3.9 `model_deployments` (S writes, W reads)

`model_id`, `alias`, `environment ∈ staging | production`, `status ∈ pending |
active | rolled_back | retired`, `traffic_pct`, `approved_by`, `approved_at`.

### 3.10 `capture_keys` (S writes, W reads metadata only)

`name`, `key_prefix`, `key_hash`, `last_used_at`, `revoked_at`. The raw key is
returned once. A revoked key is rejected before any row is read, and the
attempt is audited.

Key format: `muse_ck_` + 32 random bytes base64url. `key_prefix` is the first
12 characters (display only); `key_hash` is `sha256(raw)`. The org is resolved
from the stored row, never from the key, so a key cannot claim a tenant.

### 3.11 `label_disputes` (W)

Created by the learning-platform migration in F-5 (the pre-spec migration was
reverted, so nothing defines it today). `step_at`, `auto_label`,
`adjudicated_label`, `version`, `status`, both actors. Unique
`(org, run, step_at)`; a version bump on every adjudication.

## 4. APIs

Two auth modes: Clerk session (human actions) and capture key (machine
ingestion). Both are org-scoped; the server uses the service role only after
verifying the caller's org matches the target row.

Every Clerk route additionally requires an org role:

| Role | May |
|---|---|
| `reviewer` | read traces, write corrections, file disputes |
| `trainer` | everything a reviewer may, plus build datasets, create runs, request evaluations, define signals and graders |
| `operator` | everything a trainer may, plus adjudicate disputes, approve runs, promote or roll back deployments, issue and revoke capture keys |

Roles come from the verified Clerk claims and are checked server-side on every
mutating route. RLS remains the backstop, not the authorization model. A
missing role is a 403 with the required role named.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/capture/v1/traces` | capture key | external harness trace + feedback |
| POST | `/capture/v1/keys` | Clerk (operator) | issue a one-time capture key |
| GET | `/capture/v1/keys` | Clerk (reviewer) | names, prefixes, last use, revocation |
| POST | `/capture/v1/keys/:id/revoke` | Clerk (operator) | revoke a key; later use is 401 + audited |
| GET | `/traces` | Clerk (reviewer) | filter by role/run/technique/outcome |
| GET | `/traces/:id` | Clerk (reviewer) | one trace with payload and corrections |
| POST | `/traces/:id/corrections` | Clerk (reviewer) | approve/reject/edit/reprompt/label |
| POST | `/traces/:id/disputes` | Clerk (reviewer) | file a label dispute |
| GET | `/disputes` | Clerk (reviewer) | list disputes by status |
| POST | `/disputes/:id/adjudicate` | Clerk (operator) | resolve a dispute |
| GET | `/signals` | Clerk (reviewer) | definitions and hit counts |
| POST | `/signals` | Clerk (trainer) | define or version a signal |
| POST | `/signals/:id/run` | Clerk (trainer) | evaluate a rule signal over traces; hits are idempotent |
| GET | `/graders` | Clerk (reviewer) | definitions and versions |
| POST | `/graders` | Clerk (trainer) | define or version a grader |
| POST | `/datasets` | Clerk (trainer) | build a dataset from a selection |
| GET | `/datasets` | Clerk (reviewer) | snapshots with hashes, splits, leakage status |
| POST | `/training-runs` | Clerk (trainer) | create a run (approval required for prod) |
| GET | `/training-runs` | Clerk (reviewer) | runs with status and metrics |
| POST | `/training-runs/:id/approve` | Clerk (operator) | approve and submit |
| POST | `/training-runs/:id/cancel` | Clerk (operator) | cancel a queued or running run |
| POST | `/evaluations` | Clerk (trainer) | run a held-out suite |
| GET | `/evaluations` | Clerk (reviewer) | results and comparisons |
| GET | `/models` | Clerk (reviewer) | registry by role |
| GET | `/models/resolve?role=` | Clerk (reviewer) | the ID the role resolves to (registry, else base) |
| POST | `/models/:id/deploy` | Clerk (operator) | promote to an alias |
| GET | `/model-deployments` | Clerk (reviewer) | aliases, environments, traffic |
| POST | `/model-deployments/:id/rollback` | Clerk (operator) | restore the previous target |
| GET | `/overview` | Clerk (reviewer) | counts for the Learning overview |

Read routes are required by F-13; without them the UI would have to query
Supabase directly and re-implement the role check in the browser.

All mutating actions write an audit entry. The capture endpoint is versioned
and rejects unknown fields (schema pinned by a zod contract).

### 4.1 Service boundary

These routes do not belong to an existing process. The backend today has three
servers — `provisioner/lab-hub.ts` (per-lab), `observability/metrics.ts`
(Prometheus), and `designer/server.ts` (design only) — and none of them is the
learning platform's host.

A new **`backend/src/api/server.ts`** owns every route in §4:

- its own port (`MUSEARENA_API_PORT`, default `8788`) and health endpoint;
- Clerk verification through the existing `lib/clerk-jwt.ts`;
- one capture-key verifier (hash lookup → org → revoke → audit) as a distinct
  middleware, never a Clerk fallback;
- the same service-role discipline: resolve the caller's org first, then touch
  a row, and never trust an `org_id` in a request body;
- a host process like the worker, **not** a Pulumi container;
  `deployment/src/cli.ts` writes `MUSEARENA_API_PORT` into `.platform.env` so
  the launcher and the server agree.

`designer/server.ts` stays design-only. Adding learning routes to it would make
its name and its auth model wrong, and would put a training-data surface behind
the designer's model credentials.

This boundary is a **prerequisite for F-4**: the capture endpoint is F-4's first
acceptance line, and it needs a process to live in.

## 5. State machines

### Training run

```
queued ──approve──► running ──ok──► succeeded ──► model ready
   │                   │
   │                   ├──error──► failed
   │                   └──cancel──► cancelled
   └──no trainer──► awaiting_trainer
```

Rules:
- `awaiting_trainer` is a parked state, not a success. It ships the manifest
  and dataset reference; approval can be retried after a trainer is configured.
- Only a `succeeded` run may create a `ready` model.
- A production-targeted run needs `approved_by`/`approved_at` before `running`.
- A run that exceeds its budget is `cancelled`, never left `running`.

### Evaluation

```
queued ──► running ──► succeeded | failed
```

A failed evaluation leaves the current production model active. The gate is
per role; a red pass does not promote a blue model.

### Model deployment

```
pending ──approve──► active ──rollback──► rolled_back
                          └──retire──► retired
```

Only one `active` deployment per `(org, alias, environment)`. Promotion
requires a passing evaluation for the same role and model. The previous active
row is retained for rollback.

At exercise start the runtime resolves `alias → (modelId, trafficPct)` from the
role's active deployment and pins that tuple into the run record
(Req 2.8.4). An evaluation run always uses 100% of the candidate; it never
evaluates a traffic split.

## 6. Training execution boundary

The platform owns the control plane; it does not claim to implement gradient
training. A trainer adapter is configured by `META_TRAINER_URL` (and
credentials in the platform secret store). Contract:

```
POST <META_TRAINER_URL>/v1/jobs
{
  "run_id", "role", "method", "base_model", "dataset": { "hash", "urls": [...] },
  "config": { ... }, "callback_url"
}
→ { "job_id" }
```

The adapter is Meta-only: the base model and the training image resolve from
the Meta model registry. If the adapter is absent, runs stay
`awaiting_trainer`; the platform never fabricates metrics or artifacts.

Artifacts are stored under `<org>/models/<model_id>/` with a content hash in
the `models` row. Only the trainer or the service role may write them.

## 7. Evaluation methodology

### Red

Per objective: achieved (ground-truth success), points, steps used, tokens
used, guardrail violations, and whether the planted proof returned through
real tool output. Aggregate: objectives achieved, exact-technique coverage,
steps/objective, tokens/objective, unverified-claim count.

### Blue

Per exercise: MTTD (clock-skew-scoped), containment correctness, false-positive
rate on benign control runs, evidence-citation correctness (cited rows exist
and belong to the host), guardrail rejections, and calibration.

Calibration = reliability of the detection confidence against joined ground
truth:

- `brier = mean((confidence - correct)^2)`, `correct ∈ {0,1}` from ground truth;
- `ece` = weighted mean gap between confidence and accuracy over 10 bins;
- report `calibration = 1 - brier` and `calibrationEce = ece`;
- a technique with an unscorable clock-skew window is excluded from timing and
  from calibration.

### Comparison

Candidate vs baseline is a paired delta on the same held-out suite. Scores
across different `mode` (blind/adaptive) or `truthLayer` are reported
separately, never ranked together.

A single trial is a noisy sample, so a suite runs `config.trials` times
(default 3). The evaluation reports the mean and the min/max spread per metric.
A promotion claim must show the candidate's mean above the baseline's mean by
more than the combined spread; a delta inside the noise is recorded as
`inconclusive`, not as a win. Trial count and every trial's model ID are pinned
in `evaluations.suite`/`comparison`.

### Baseline

A delta needs a reference point. Every `evaluations` row carries
`baseline_model_id`, so the baseline is a registered model, never an implicit
"whatever was there".

The baseline is the **untrained Meta base model for that role** — the exact
`muse-*` ID the role pins today — evaluated on the same held-out suite before
any candidate is promoted. A deployed trained model can later become the
comparison point for a newer candidate, but it is never the baseline for
deciding whether training helped at all.

This makes the first useful milestone measurable: *does a trained red/blue
candidate beat the base model on held-out objectives, same suite, same mode?*
Until that number exists, the training surface is plumbing.

The held-out suite itself is authored from scenario families assigned to the
`test` split (see §3.4) and pinned by digest in `evaluations.suite`; it is not
reusable for training.

## 8. Continual loop

Triggers, evaluated in order, all proposing rather than auto-starting:

1. **New labelled traces** — every captured run with ground truth increments
   the role's labelled count.
2. **Correction volume** — N corrections on the same technique in a window.
3. **Score regression** — a role's rolling MTTD/containment or objectives
   drops below its bar.
4. **Scheduled cadence** — an operator-set interval.

A proposal names the role, dataset selection, base model and method. It
becomes a training run only after approval. After training, the evaluation
gate runs; only a pass may be promoted. The current production model stays
active throughout a failed candidate's lifecycle.

## 9. UI surfaces

New "Learning" navigation group:

- **Overview** — labelled traces, corrections, open disputes, active models
  per role, last evaluation, production alias.
- **Data** — traces (filters by role/outcome/technique), trace detail with
  corrections and dispute actions.
- **Signals** — signal definitions, hit counts, continual grading toggle.
- **Datasets** — builder (selection → preview counts → build), snapshots with
  hashes and splits, leakage status.
- **Models** — registry by role, lineage, artifact hash.
- **Training** — runs, approval, metrics, logs/manifest, `awaiting_trainer`
  state.
- **Evaluations** — suites, candidate vs baseline, red/blue metric panels.
- **Graders** — rubric/deterministic/model judge definitions and versions.
- **Deployments** — aliases per role, staging/production, traffic, rollback.

The existing Environments/Exercises/Designer pages stay unchanged.

## 10. Failure modes

| Failure | Signal | Handling |
|---|---|---|
| Capture key leaked/abused | unexpected trace volume, unknown org | revoke key; traces are append-only and auditable |
| Trace write fails mid-exercise | publish error | dataset publish fails closed; run is not marked complete |
| Family split collision | publish refusal | operator chooses the existing split or a new family |
| Adjudication applied twice | same dispute version | export uses the latest version; hash recomputed |
| Trainer absent | `awaiting_trainer` | parked with manifest; no fake success |
| Trainer callback lost | run stuck `running` | lease/timeout marks `failed`; no model is created |
| Evaluation suite drift | spec digest mismatch | evaluation refused before spending compute |
| Promotion without eval | approval check | refused and audited |
| Third-party model ID | registry resolution | fail closed at construction |
| Clock skew | unscorable window | excluded from MTTD/calibration and audited |

## 11. Security and governance

- RLS on every table; the capture endpoint verifies the key's org before any
  write and never trusts an `org_id` in the body.
- Org roles (`reviewer`, `trainer`, `operator`) are checked server-side on every
  mutating route. RLS isolates orgs; roles separate duties within one.
- Datasets and model artifacts share one private bucket pattern
  (`<org>/...`); no public URLs.
- Training data boundaries are enforced at dataset build time (roles, runs,
  splits), not only in the UI.
- Every approval (training run, promotion) records the approver and time.
- Audit entries are hash-chained; dataset/run/model lineage is immutable.
- Retention: traces, datasets and evaluations are kept for 90 days by default
  (per-org override); model artifacts are kept while any deployment references
  them. Org deletion removes rows, storage objects and artifacts. The trace
  `payload` is stored redacted, exactly as the snapshot is.

## 12. Decisions

> Resolved 2026-11-03. Each entry records the choice, its reason, and when to
> reopen it. These are binding on F-4…F-16; changing one means editing this
> section first, not deciding it mid-implementation.

1. **Trainer endpoint.** No Meta training service is assumed to exist.
   `META_TRAINER_URL` is the only accepted surface; when it is unset or
   unreachable a run is created `awaiting_trainer` with an exported manifest and
   no metrics. Nothing fabricates a job id, a metric or an artifact.
   *Reopen when* Meta publishes a training contract; the adapter shape is §6.
2. **Artifact storage.** Reuse the private `datasets` bucket under
   `<org>/models/<model_id>/`. Artifact and dataset lineage then share one
   private namespace and one policy model; a second bucket is premature.
3. **Blue prompts.** Self-contained. Evidence-row text is copied into
   `TrajectoryStep.detail` at capture time (redacted), not referenced by a
   Langfuse span id. A dataset must stay reproducible if Langfuse is pruned;
   Langfuse remains the human debugging surface, not a training dependency.
4. **Split policy.** The invariant is one family → one split, enforced at build
   time. When the operator does not choose, the builder proposes 80/10/10 by
   family count and records the proposal in `selection`; it never enforces a
   ratio the family set cannot support.
5. **Persona role.** Deferred. `persona` stays a valid registry role and trace
   actor, but no dataset, run or evaluation targets it in this slice: the
   exercise's persona signal is routine compliance, not a success objective.
6. **Existing unapproved code.** Reverted 2026-11-03; `tasks.md`
   §Reconciliation keeps the audit as the rebuild inventory.
7. **Corrections into training data.** Applied at dataset-build time, like
   adjudication. The builder loads corrections for the selected traces, uses the
   latest `edit`/`reprompt` `after` as the completion, records correction ids
   and kinds in `datasets.selection`, and never overwrites the original action.
8. **Evaluation runner.** The platform runs the suite itself, in the worker,
   with the pinned candidate model, through the existing exercise runner and
   joined ground truth. There is no external evaluator adapter and no
   `META_EVAL_URL`. *Reopen if* evaluation must run outside the platform runtime.
9. **Runtime model resolution.** `resolveModel(role, orgId)` is the single
   entry point for red, blue, persona and judge. It returns a client pinned to
   the role's `ready` model, else the role's base `muse-*` model, and validates
   against the Meta allowlist. It lives in `learning/models.ts`, not
   `lib/model.ts`: the registry lookup needs the database, and the client
   module must stay free of data access. Unknown or non-Meta IDs fail closed.
10. **Capture-key revocation.** `revoked_at` on `capture_keys` plus
    `POST /capture/v1/keys/:id/revoke`. The verifier rejects a revoked key
    before any row access and audits the attempt.
11. **Baseline.** The untrained Meta base model for the role, on the same
    held-out suite (§7). Confirmed.
12. **Learning-API host.** `backend/src/api/server.ts`, `MUSEARENA_API_PORT`
    default 8788, own deployment entry (§4.1). Task F-16.
13. **Authorization.** Three org roles — `reviewer`, `trainer`, `operator` —
    from verified Clerk claims, checked server-side on every mutating route
    (§4, §11). RLS remains the backstop, not the authorization model.
14. **Training budget.** `budget_usd` is required at creation; `spent_usd` is
    trainer-reported. Exceeding the budget cancels the run and audits it; a run
    that exceeds its budget is never left `running`.
15. **Traffic percentage.** At exercise start, resolve `alias → (modelId,
    trafficPct)` and pin the tuple into the run record. Evaluation always uses
    100% of the candidate and never a split.
16. **Evaluation repetition.** `config.trials` defaults to 3; report mean and
    min/max spread. A delta inside the spread is `inconclusive`; promotion needs
    a mean improvement beyond it.
17. **Retention and redaction.** 90 days by default for traces, datasets and
    evaluations (per-org override); artifacts retained while deployed; org
    deletion removes rows and objects. `traces.payload` stores the redacted
    payload, never the raw action.
18. **Rule signal language.** A rule signal is a closed predicate over trace
    columns, not an expression language: `{ match: "all" | "any", conditions:
    [{ field, op, value }] }` with fields `actor | techniqueId | outcome |
    hostId | action | observation | matched` and ops `eq | ne | in | prefix |
    exists`. Unknown fields and ops are rejected at definition time, so a stored
    signal cannot become a query. *Reopen if* a rule needs arithmetic,
    cross-row joins or payload access.
19. **Served model ID.** A registry row carries `served_model` — the exact ID
    handed to the Meta surface. For a base model it equals `base_model`; a
    training run must return it before a model may become `ready`. Without it,
    resolution knows what was trained but not what to call.

## 13. Explicitly not in this spec

- A second agent framework or model provider.
- A general-purpose MLOps suite (experiment tracking beyond the tables above).
- Public dataset/model marketplaces.
- Automatic promotion.
- Windows/AD and AWS/GCP environment branches.

## 14. Definition of done for this slice

"Fully implemented" was undefined, which made it impossible to say when the
platform is finished. It means these milestones, each closed by live evidence:

| Milestone | Tasks | Closes when |
|---|---|---|
| **M1 Capture** | F-16, F-4 | An internal publish writes trace rows idempotently, and an external harness posts one trace with a capture key; a revoked key is refused. |
| **M2 Review** | F-5, F-6 | A correction, a dispute adjudication, a rule signal and a model grader are recorded on real traces and re-exported. |
| **M3 Data and models** | F-7, F-8, F-14 | One red and one blue snapshot, family-split refusal proven, and a registry row per role with a resolved Meta model ID. |
| **M4 Train and evaluate** | F-9, F-10, F-15 | One run per role ends in a real artifact or honestly in `awaiting_trainer`; a candidate-vs-base evaluation reports both metric panels and a spread. |
| **M5 Deploy and loop** | F-11, F-12 | Promotion without a passing evaluation is refused; a proposal is created and never auto-started. |
| **M6 Learning UI** | F-13 | Every learning surface renders real data and real empty states. |

M1–M5 verified live is "the training platform works". M6 is the surface over it.
Anything not in this table is not part of this slice.

## 15. Platform selection and exercise operations

### 15.1 Selection contract

The Designer and deployment approval share one selection value:

```ts
interface PlatformSelection {
  runtimeTarget: "vm" | "container";
  modelSurface: "meta" | "meta-modal";
  exerciseEngine: "scripted" | "agents";
}
```

- `runtimeTarget` is a design gate, not a display preference. The generated
  `EnvironmentSpec` must use that runtime for every instance. Budget,
  coherence, deployability, plan gaps, and the runtime-target mismatch all
  enter the same one-shot semantic repair in `designer/pipeline.ts`.
- `modelSurface` chooses the designer client per request. `meta-modal`
  currently has a verified designer (`generateObject`) client but no verified
  agent tool-turn client (§12.9/F-14). Selecting `agents` on an unverified
  surface is refused before deployment; the UI asks the operator to choose
  the verified Meta agent surface or `scripted`. There is no silent fallback.
- The full selection is stored on the generated spec and copied to deployment
  `access_info.platform`. The trigger passes it to the workflow, and
  `exerciseActivity` uses `exerciseEngine` in preference to the worker-global
  `MUSEARENA_AGENT_RUNTIME` switch. Older deployments without a selection keep
  the environment-variable behaviour.
- Deployment remains automatic once approved: claim → deploy → configure →
  readiness → proof gates → exercise → score → dataset → `ready` → TTL
  teardown. The UI names those stages rather than implying that `ready`
  means "waiting for an exercise".

### 15.2 Operations read model

The Red Team, Blue Team, and Monitoring pages are read models over data the
platform already persists; they do not invent a second event store:

| Surface | Source of truth | Renders |
|---|---|---|
| Planned attack path | approved `EnvironmentSpec` (`plantedVulns`, `objectives`, service declarations, dependencies) | entry host → weakness → service → objective |
| Executed red path | joined `DatasetExport.join.steps` (and `traces` rows once 0005 is live) | red trajectory and ground truth in step order |
| Red orchestrator loop | `SCORE_COMPUTED.detail.redCampaign` plus `delegate_attack` trajectory steps | objective order, coordinator directives/reasons, verified outcome and executed-attempt count per objective |
| Blue log-monitor loop | `SCORE_COMPUTED.detail.blueMonitoring` plus `monitor_anomalies` trajectory steps | collapsed rows/events, fetched monitor pages, deterministic anomaly candidates with evidence row ids (leads, not detections) |
| Blue dashboard | the same joined steps plus `runs.score` | detections, responses, unmatched telemetry, coverage, MTTD/containment/FP |
| Monitoring | `deployments`, `runs`, `datasets`, Realtime | lifecycle, exercise/dataset state, drift, recent scores |
| Dataset provenance | dataset row + export manifest/steps | source run, split, hash, actor counts, matched/dropped counts, model/runtime labels |

Dataset exports are read from the private `datasets` bucket through the
user-scoped Supabase client and decoded in the browser. If the export cannot
be read, the pages keep the score summary and show the trajectory as
unavailable; they never synthesize steps from the score.

### 15.3 Milestone

| Milestone | Tasks | Closes when |
|---|---|---|
| **M0 Operations** | F-17, F-18, F-19 | A blocked FreeIPA/VM design is repaired or refused with the exact provisioning reasons; platform choices are visible and pinned; one scored run renders its planned path, orchestrated red tasking, executed red steps, blue log-monitor candidates, blue detections, and dataset provenance from the real export/audit. |
