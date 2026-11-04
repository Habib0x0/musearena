# Progress Log: follow-on-platform

> Append-only session log. Do NOT edit previous entries.

---

## 2026-10-27 — Audit + fixes (first entry; log was empty despite all tasks marked verified)

- F-1 registry: canonical full-length digest; unit-verified (latest/family).
  Supabase persistence still not wired to the registry class.
- F-2 pairs: success labels now ground-truth-only (blue "contained" excluded);
  preference pairs require a distinct failed completion; unit-verified.
- F-3 marketing: build re-verified; still no test asserting the Designer link.
Details: see prompt-driven-environment-generation progress log, same date.


## 2026-11-03 — spec-first reset for offensive/defensive training

Operator direction: the training surface is the primary product shape, and it
must be specified before it is implemented. `requirements.md` and `design.md`
now define the full loop (capture → traces → corrections/adjudication →
signals/graders → datasets → models → training runs → evaluations →
deployments → continual loop), and `tasks.md` carries proposed tasks F-4…F-15.

**No implementation is accepted from this point until the tasks are ratified.**
The working tree currently contains code written before this revision:

- migrations `0005_learning_platform.sql`, `0006_run_pins_adjudication.sql`
- shared `RunPins` and learning-platform contracts
- run provenance pins, clock-skew unscorable windows, adjudication store/apply,
  dataset family leakage, bounded configuration remediation
- role-aware red/blue training pairs, per-role export files, trace row mapping

These changes are listed in `tasks.md` §Reconciliation and must be mapped to
the task that authorises them, then either ratified with a verification line
or reverted. The environment-spec task/progress entries that described them
were removed so the two specs do not disagree.

Open decisions blocking implementation are in `design.md` §12: trainer
endpoint, artifact bucket, blue prompt source (row text vs Langfuse reference),
split policy, whether persona training is in this slice, and the reconciliation
above.

## 2026-11-03 — reconciliation audit (read-only, no code changed)

Mapped every unapproved working-tree artifact to the task that authorises it
(`tasks.md` §Reconciliation). Evidence: `test/honesty.test.mjs` 17/17, typecheck
clean. Result: the pre-spec code is unit-verified but **not** task-verified —
migrations 0005/0006 are unapplied and every DB-backed acceptance line is
therefore unobserved. Migration 0005 also lacks the design's §3.4–3.6 columns
(`datasets.selection`/`roles`, `models.role`/`training_run_id`,
`training_runs.role`), and `capture_keys` has no revocation.

The audit exposed four design gaps, now recorded as `design.md` §12 items 7–10:
where corrections enter training data, the evaluation runner boundary, runtime
model resolution per role, and capture-key revocation.

## 2026-11-03 — reconciliation resolved by revert

Operator decision: revert the pre-spec learning-platform code and rebuild F-4…F-15
from this spec. Removed from the working tree: migrations
`0005_learning_platform.sql` / `0006_run_pins_adjudication.sql`,
`training/traces.ts`, `traces/adjudication.ts`, role-aware `pairs.ts`/`exporter.ts`,
trace row mapping, adjudication-in-publish, family refusal, run pins,
`unscorableWindows`, the structured `detail` payload, and the shared learning
contracts. Backup (reference only): `/tmp/arena-prespec-backup/`.

Post-revert evidence: backend **162/162** tests pass, build/typecheck clean.
F-2 is back to its 2026-10-27 red-only state. T-40/T-41 GSSAPI and workflow work,
the designer, and the frontend were not touched.

Implementation remains paused on `design.md` §12 items 1–5 and 7–10. No task is
accepted until its own verification line is observed.

## 2026-11-03 — two gaps that were only in conversation, now in the spec

An operator review found two items discussed verbally but absent from the
documents. Both are now written:

- **§4.1 Service boundary.** No existing server owns the §4 routes. The design
  now names `backend/src/api/server.ts` (port 8788), reuses `lib/clerk-jwt.ts`,
  requires a separate capture-key verifier, and makes this a prerequisite for
  F-4. Open as §12.12.
- **§7 Baseline.** `evaluations.baseline_model_id` had no definition. The
  design now fixes the baseline as the untrained Meta base model for the role,
  on the same held-out suite, and states the first measurable milestone. Open
  as §12.11.

F-4 and F-10 dependency lines were updated to cite both.

## 2026-11-03 — second specification pass (requirements re-read)

Re-reading `requirements.md` §2.7–2.10 against the design and tasks exposed five
more holes, all now recorded:

- **F-16 Learning API host** added. §4.1 had declared a prerequisite that no
  task owned.
- **§12.13 Authorization model** — "reviewer/trainer/operator" had no permission
  matrix; RLS gives isolation, not separation.
- **§12.14 Training budget** — the NFR requires it, `training_runs` has no
  column, no task asserts it.
- **§12.15 Traffic percentage** — Req 2.8.4 requires recording it; the run
  record has no field.
- **§12.16 Evaluation repetition** — one trial per suite makes the delta a
  single noisy sample.
- **§12.17 Retention and redaction scope** — no retention period, and
  `traces.payload` raw-vs-redacted was undefined.

Also fixed the dependency graph: F-10 and F-11 now depend on F-14 (a candidate
cannot be evaluated or an alias resolved without per-role model resolution), and
F-4 depends on F-16. Added `design.md` §14, the definition of done (M1–M6), so
"fully implemented" has a boundary. Still no implementation.

## 2026-11-03 — spec accepted; decisions resolved

`design.md` §12 is now **Decisions**, not open questions: 17 entries, each with
the choice and when to reopen. Nothing in the spec is waiting on an answer.

What changed in this pass:

- **Data model** — `training_runs.budget_usd`/`spent_usd`,
  `capture_keys.revoked_at`, the contents of `datasets.selection`, the redacted
  `traces.payload`, and `label_disputes` now created by F-5 (the environment
  spec's migration was reverted, so nothing defined it).
- **API** — reviewer/trainer/operator role matrix; the capture-key revoke route;
  and the read/definition routes F-13 needs (`GET /traces`, `/disputes`,
  `/signals`, `/graders`, `/datasets`, `/training-runs`, `/evaluations`,
  `/models`, `/model-deployments`, `/overview`). Without them the UI would query
  Supabase directly and duplicate the role check in the browser.
- **Evaluation** — `config.trials` (default 3) with mean/spread and an
  `inconclusive` verdict; baseline is the untrained Meta base model for the role.
- **Governance** — org roles, 90-day default retention, and trace payloads stored
  redacted.
- **Requirements** — §2.6.6 budget cancellation, §2.7.6 trials, §2.10.5–7 roles,
  revocation and retention.
- **Tasks** — F-1…F-16 carry requirement links; F-4…F-16 are `ready` (accepted,
  not started); acceptance added for corrections-in-builder (F-7), budget
  (F-9), trials (F-10), traffic pinning (F-11) and role refusal (F-16); a build
  order and the M1–M6 milestone mapping are explicit.
- **Withdrawn** — `META_EVAL_URL` / `awaiting_evaluator`. The platform already
  owns the exercise runtime, so evaluation runs in the worker; a second phantom
  endpoint was unnecessary.

The spec is complete for this slice. Implementation has not started: M1 begins
with F-16, and no database-backed acceptance line can close until migrations are
applied.

## 2026-11-03 — F-16 built (unit-verified)

M1 started. `backend/src/api/` now holds the learning API host:

- `auth.ts` — `reviewer < trainer < operator` rank, org/role read only from
  verified Clerk claims, `403` names the required role.
- `keys.ts` — `muse_ck_` + 32 random bytes; only the 12-char display prefix and
  `sha256(raw)` are stored; a revoked key is refused before any handler and
  audited against its owning org. Supabase store is lazy so boot does not need
  database credentials.
- `server.ts` — route → auth → body order; `/health`; JSON error contract;
  CORS allowlist; `:param` matching for the §4 paths.
- `main.ts` — host-process entry; `deployment/src/cli.ts` writes
  `MUSEARENA_API_PORT` (8788) to `.platform.env`.

Spec corrections made while building: §4.1 now says host process, not a Pulumi
container (the worker has no Pulumi entry either), and §3.10 pins the key format.
F-16 acceptance 3 was narrowed to what is implementable: malformed/unknown keys
are logged, a revoked key is audited against a known org.

Evidence: `backend/test/api.test.mjs` 5/5, backend **170/170**, typecheck clean
for shared/deployment/backend. Frontend typecheck is red on unused symbols in
`App.tsx`; that file was being written by another process during this session
(mtime seconds before the check, diff grew 1661 → 2297 lines), so it is not
F-16's regression and was not touched.

Not met: live boot behind a real Clerk issuer, the Supabase `capture_keys`
lookup, and the `.platform.env` write. All three need the database/migration
access that is still missing.

## 2026-11-03 — F-4 built (unit-verified)

- `backend/supabase/migrations/0005_traces_capture.sql` — `traces` (unique
  `(org, run, step)`, RLS read for the org) and `capture_keys` (hash + prefix,
  `revoked_at`, column grants so members can read metadata but never the hash).
  `run_id` has no FK: external harnesses may submit runs the platform never
  provisioned; the design now says so.
- `shared` — `CaptureTrace`, strict on unknown fields, actor required, timestamp
  validated, `hostId`/`matched` defaults.
- `training/traces.ts` — one row per joined step with a uniform
  `{trajectory, groundTruth, matched}` payload; upsert idempotent per
  `(org, run, step)`.
- `observability/publish.ts` — persists traces after the dataset row and returns
  `traceCount`. **This makes publish fail closed until 0005 is applied** — by
  design (design §10), but it is a deployment prerequisite.
- `api/traces.ts` — `POST /capture/v1/traces`, key issue/list/revoke; org always
  from the key or the session, never the body. `CAPTURE_KEY_ISSUED` /
  `CAPTURE_KEY_REVOKED` added to the audit vocabulary.
- `TrajectoryStep.detail` is back (Req §2.1.2) so a structured action can be
  persisted; producers land with F-7 where examples are built.

Evidence: `test/traces.test.mjs` 4/4, backend **174/174**, typecheck clean for
backend/shared/deployment. Not met: live publish/idempotency and a real capture
round trip — both need 0005 applied.

Operational consequence: applying `0005` is now required before the next live
exercise, because a publish that cannot write traces fails rather than silently
dropping the reviewable record.

Schema verification (same entry): `0005_traces_capture.sql` was applied to a
throwaway Postgres 16 with Supabase's `auth.jwt()` and `authenticated` role
stubbed. Observed: the migration parses and applies; `on conflict (org, run,
step) do update` keeps one row and refreshes the payload; with `o.id = org-a`
the member sees only `org-a`'s row; a member insert is refused; and
`has_column_privilege('authenticated','capture_keys','key_hash','select')` is
false while `name` is true. Explicit `grant select on traces to authenticated`
was added so the migration does not depend on ambient Supabase defaults.

## 2026-11-03 — F-5 built (unit + schema verified)

- `0006_corrections_disputes.sql` — append-only `corrections` (select/insert
  grants only) and `label_disputes` with `unique (org, run, step_at)` and a
  touch trigger that sets `status = adjudicated` and `updated_at`.
- `traces/adjudication.ts` — file/list/adjudicate, rebuild the pure queue from
  rows, typed `DuplicateDispute` (409) and `DisputeNotFound` (404).
- `traces/integrity.ts` — `applyAdjudications` now compares instants, not
  strings, so a `timestamptz` round-trip matches the export.
- `api/review.ts` — `GET /traces/:id` (trace + corrections + disputes),
  `POST /traces/:id/corrections`, `POST /traces/:id/disputes`,
  `GET /disputes`, `POST /disputes/:id/adjudicate`. Reviewer/operator roles
  enforced by the host; the trace is always resolved inside the caller's org.
- `observability/publish.ts` — adjudications are loaded and applied before the
  snapshot is hashed.

Evidence: `test/review.test.mjs` 5/5, backend **180/180**, typecheck clean.
On Postgres 16: a duplicate dispute is refused by the unique key, adjudication
bumps to version 2 and flips the status, `org-a` reads only its own
corrections, and a member update is denied. Not met: Supabase apply, a live
export carrying an adjudicated label, and the audit rows.

Deployment note: publish now reads `label_disputes` on every run, so `0005`
**and** `0006` must be applied before the next live exercise.

Process note: F-5 was started while F-4 is unit/schema-verified but not
live-verified. The build order requires a dependency to be `completed`; with
Supabase still unreachable, every database-backed task would stall at the same
gate, so implementation proceeds at unit level and the ledger keeps each task
`in_progress`. No task is marked complete, and none will be until its live line
is observed.

## 2026-11-03 — local Supabase + live verification (M1 closed)

Operator chose a local stack over production credentials. `supabase init` added
`backend/supabase/config.toml`; `supabase start` brought up Postgres/PostgREST/
Storage/Auth on `127.0.0.1:54321` and applied **all six migrations** (0001–0006)
on first boot — no stubs, real Supabase roles, `auth.jwt()`, and the realtime
publication.

`scripts/learning-smoke.mjs` then drove the real routes against the real
database, **13/13 checks**:

1. publish writes one trace row per joined step
2. re-publish is idempotent (one row, same hash)
3. correction recorded with before/after and reviewer
4. dispute filed against the trace's ground-truth label
5. duplicate dispute refused (409)
6. reviewer cannot adjudicate (403 names the operator role)
7. operator adjudicates at version 2
8. adjudication re-hashes the export and updates the trace row
9. the stored `export.json.gz` contains the adjudicated label
10. correction, dispute and adjudication are audited
11. a capture key ingests an external step for its own org
12. a capture body cannot claim another org (strict contract, 400)
13. a revoked key is refused (401) and audited

The API host was also booted on `MUSEARENA_API_PORT=8788`: `/health` returned
the service payload, `/design` was 404, and a missing capture key was 401 and
logged.

Ledger: **F-4 and F-5 are completed** with observed live lines. F-16 is 5/6 —
only `.platform.env` carrying the port is unobserved (it needs a Pulumi `up`),
and no real Clerk token exists locally, so the smoke injects the session
verifier while keeping the real org/role logic below it.

Not claimed: production Supabase apply. The local stack is a dev environment —
it binds 0.0.0.0 with shared default keys, and the smoke leaves audit rows and
storage objects (append-only by design; DB rows are cleaned up).

## 2026-11-03 — F-6 started (signals + grader definitions, live-verified)

- Design gained the missing contract: **§12.18 rule signal language** — a closed
  predicate over trace columns (`match: all|any`, `field`, `op`,
  `eq|ne|in|prefix|exists`), rejected at definition time. No expression
  language, so a stored signal cannot become a query. `POST /signals/:id/run`
  was added to §4.
- `0007_signals_graders.sql` — `signals` (unique `(org, name, version)`),
  `signal_hits` (unique `(signal, trace)`), `graders` (unique
  `(org, name, version)`), RLS and grants. Applied to the local stack.
- `learning/signals.ts` — rule matching, versioned definitions, idempotent hit
  upsert, per-signal hit counts.
- `api/signals.ts` / `api/graders.ts` — define/list/run; a model grader must
  name `spec.model` at definition time so a judge cannot be chosen later.

Live smoke is now **15/15**, adding: a rule signal hits once and re-running it
does not duplicate; a model grader without `spec.model` is refused and a
redefinition versions to 2. Backend **183/183**.

F-6 stays `in_progress`: model-grader *execution* (pin the judge ID in each
result) and continual grading of new traces are not built. Those need F-14's
`resolveModel`, so they are scheduled with M3.

### Concurrent-edit incident

Mid-task the tree changed under this session: `shared/src/index.ts` (00:28),
`backend/src/designer/pipeline.ts`, `provisioner/capability.ts`,
`lib/model.ts` and `activities/index.ts` (00:28–00:32) gained
`PlatformSelection` / `ModelSurface` / `spec.platform` from another process.
`shared/dist` was stale, which briefly broke the backend compile; rebuilding
shared resolved it. My additions (CaptureTrace, learning API, migrations) were
not overwritten, but the repo is being edited concurrently — verify before
assuming a clean tree.

## 2026-11-03 — F-8 completed, F-14 core (M3 started)

Design additions: **§12.19 served model ID** — a row carries the exact ID handed
to the Meta surface; for a base model it equals `base_model`, and a training run
must return it before a model can be `ready`. §12.9 was corrected: resolution
lives in `learning/models.ts`, not `lib/model.ts`, because the registry lookup
needs the database and the client module must stay data-free.

- `0008_models.sql` — registry with `served_model`, `role text[]` constrained to
  red/blue/persona/judge, status set, unique `(org, name, version)`. Applied.
- `learning/models.ts` — registration (versioned), listing, `resolveServedModel`
  (newest `ready` row for the role, else the verified base), `resolveModel`
  (tool-use client pinned to the resolved ID). Every ID is re-checked against
  the Meta allowlist; a `meta-modal` row is refused for agent roles until tool
  turns are verified there.
- `api/models.ts` — `GET /models`, `GET /models/resolve?role=`, `POST /models`
  (operator). `judge` added to `ModelRole`.

Live smoke is now **16/16**, adding: registry resolves red from the registry and
blue from its base, an unapproved provider value and an unapproved served ID are refused.
Backend **186/186**.

F-8 is **completed**. F-14 stays `in_progress`: the exercise agents still build
`MetaModelClient` directly in `vm-agents.ts`/`agents-live.ts`, and the resolved
ID is not pinned into the run yet. That wiring is the next step, and it is also
what unblocks F-6's model-grader execution.

## 2026-11-03 — F-14 completed (agent clients come from the registry)

- `learning/models.ts` gained `resolveAgentClients(orgId, overrides)` — the one
  red/blue factory. It resolves each role through `resolveModel`, which reads
  the registry, re-checks the Meta allowlist and refuses a `meta-modal` row for
  an agent role. Overrides remain for tests and injected harnesses; production
  passes none.
- `exercise/agents-live.ts:65` and `exercise/vm-agents.ts:200` no longer call
  `new MetaModelClient({ modelId: modelForRole(...) })`. They call the factory,
  so an exercise cannot construct an agent client that skipped the registry.
- Pinning: both exercise paths already wrote client IDs into `Run.modelIds`;
  with the factory that record now carries the **served** ID (registry or
  verified base). VM adds `persona` when a persona client is injected. Unit
  test asserts `{ red: "scripted-1", blue: "scripted-1" }` from injected clients.
- Live smoke is now **17/17**, adding: a ready Modal-hosted row is accepted by
  `POST /models` but `resolveModel("red")` refuses it, and `resolveAgentClients`
  returns the registry red ID plus blue's verified base. Backend **186/186**;
  backend build/typecheck clean.
- `META_API_KEY` is still required to construct a client; the smoke sets a
  throwaway value because it asserts the resolved ID and sends no turn.

F-14 is **completed**. F-6's two remaining halves (model-grader execution with a
pinned judge ID, continual grading of newly captured traces) are now unblocked
and are next.

## 2026-11-03 — F-6 completed (model judge execution + continual grading)

- `0009_signals_continual.sql` — `signals.continual boolean not null default
  false` plus a partial index. Opt-in per signal; a model signal opts in to one
  judge call per new trace. Applied to the local stack.
- `learning/signals.ts` — `ModelDefinition` (`model` + `question`, strict) is
  validated at definition, so the judge is pinned before any run.
  `runModelSignal` resolves the judge through `resolveModel("judge", org,
  definition.model)` (Meta allowlist re-checked) and persists one hit per
  graded trace with `label.model_id`, `label.matched`, `label.rationale` and
  `score`. `runSignal` dispatches by kind; the manual route now runs either.
- `applyContinualGraders(scope)` applies enabled `continual` signals to a
  required scope (a run or explicit trace ids — never the whole org by
  accident). `publishRunDataset` calls it for the published run; the capture
  route calls it for the single new trace. Hits stay idempotent on
  `(signal, trace)`.
- `resolveModel` gained an optional pinned judge ID: still allowlist-checked,
  so "pinned at definition time" cannot smuggle in a non-Meta model.

Live smoke is now **19/19**, adding: a model signal without `definition.model`
is refused; a valid model signal records `label.model_id = muse-spark-1.3`,
`matched` and `score`; an enabled continual rule signal grades a newly captured
trace through the capture route with no manual run. The judge client is injected
in the smoke (no Meta call); DB persistence, scope and pinning are production
code. Backend **187/187**, build/typecheck clean.

F-6 is **completed**; M2 Review closes with F-5. Next is F-7 (role-aware
dataset builder).

## 2026-11-03 — F-7 completed (role-aware dataset builder)

- `0010_datasets_builder.sql` — `datasets.family`, `datasets.selection`,
  `datasets.roles`, a family index, and `runs.model_ids` so a built snapshot can
  name the models its source runs pinned. Applied to the local stack.
- `learning/datasets.ts` — `DatasetSelection` (family, split, roles, run ids,
  technique ids, outcomes, signal hit, correction kind, limit), `selectRows`
  (adjudications applied before the role/technique/outcome filters), per-role
  SFT + preference shaping, and `buildDataset`.
- Corrections are applied at build time, newest first; a correction carrying
  `action`/`completion`/`observation`/`prompt`/`toolCall` changes the exported
  example and its id is recorded in `selection.corrections`. The trace row is
  never mutated, so the original action stays readable.
- Adjudicated labels are applied before shaping and their dispute ids are
  recorded in `selection.adjudications`.
- Files: legacy `sft.jsonl`/`preference-pairs.jsonl` are red-only and byte-equal
  to `red-sft.jsonl`/`red-preference-pairs.jsonl`; `blue-sft.jsonl` and
  `blue-preference-pairs.jsonl` are separate. Proof/noise/platform rows never
  enter a role file.
- Leakage: `family → split` is persisted; a family with a snapshot in another
  split is refused 409. Rebuilding identical content reuses the existing
  row/hash instead of duplicating it. The stored `export.json.gz` is re-hashed
  after upload before the row is written.
- Meta pins: `formatVersion: 2`, redaction policy `v1`, catalog/profile/image
  versions from the real catalog constants, spec digests and technique-pack
  versions from `runs`, model IDs by run.
- `api/datasets.ts` + `api/main.ts` — `POST /datasets` (trainer),
  `GET /datasets` (reviewer, with leakage status). `DATASET_BUILT` audit action.

Live smoke is now **25/25**, adding: red+blue build with the selection recorded;
corrected completion exported while the original stays readable; legacy red
file equals the red file; duplicate build reused; family/split 409; signal-hit
+ correction-kind filter; list with hash/roles/leakage. Unit
`test/datasets.test.mjs` 6/6 includes the byte-identical legacy comparison.
Backend **194/194**, build/typecheck clean.

F-7 is **completed**. M3 Data and models closes (F-8, F-14, F-7). Next is M4:
F-9 training runs.

## 2026-11-03 — F-21 real-operation provenance and tradecraft realism

Operator direction: red/blue training data must resemble real agentic offensive
operations, not synthetic-only. No vendor or framework name is used in the
codebase.

- `0016_trace_provenance.sql` — `traces.source ∈ synthetic|imported|field`,
  `traces.framework` (caller-named, never interpreted), a source index, and
  `datasets.sources text[]`. Renumbered from 0011 after a concurrent session
  landed `0011_trace_integrity_hardening.sql`; 0012–0015 also arrived
  concurrently and were applied.
- Trace hardening reconciliation: `persistRunTraces` now upserts with
  `ignoreDuplicates` because 0011 makes the raw trajectory append-only. A
  re-publish inserts only missing steps; a label change is a build-time
  adjudication overlay. The smoke's old "trace row carries the adjudicated
  outcome" assertion was updated to the new invariant: the raw row stays
  `succeeded` and the stored snapshot carries the adjudicated `failed`.
- `shared` capture contract gained `source` (default `imported`) and
  `framework`; `captureRow` persists both.
- `learning/external-runs.ts` — source-neutral `ExternalRunExport` schema and
  `toCaptureTraces`; `scripts/import-external-run.mjs` posts an export through
  the capture key. No vendor format is parsed directly.
- `exercise/tradecraft.ts` — a field-tool corpus by phase, shell unwrapping, and
  `realismShare`. The dataset builder records
  `selection.counts.realism` over red actions.
- Dataset selection gained `sources` and `minRealShare`; `datasets.sources` is
  persisted and returned by the list; a synthetic-only selection below the floor
  is refused 422.
- Prompts: `red.md` gained a phased field-tradecraft section; `blue.md` gained a
  field-detection section. Both stay inside the existing ROE and citation rules.

Live smoke is now **29/29**, adding: an imported external run with provenance;
a blended build with `sources={synthetic:1,imported:2,field:1}`,
`realShare=0.75`, `realism.share=1` and `sources=[field,imported,synthetic]`;
a synthetic-only selection refused by `minRealShare`; a field-only selection.
Unit: `external-runs` 3/3, `tradecraft` 4/4; backend **232/232**.

F-21 is **completed**. The next build-order item is still M4/F-9, which a
concurrent session is already implementing (0012–0015 and training-run tests
are in the tree).

## 2026-11-03 — M0 operations wired (F-17/F-18, live verification partial)

- Provisioning repair: deployability and wiring-plan failures now enter the
  designer's one bounded semantic repair with the exact blocker text. A mock
  FreeIPA-on-Debian + code-flaw-on-mail draft is repaired once and never twice
  (`designer: provisioning blockers enter the bounded semantic repair`). The
  capability catalog now states the FreeIPA Rocky/resource constraints and the
  role-exact VM vuln/objective placements it enforces.
- Platform selection: shared `platform` (runtime target, model surface,
  exercise engine) is pinned on the spec, offered in the Designer, carried to
  the deployment, and read by `exerciseActivity` ahead of the worker-global
  agent switch. Unavailable designer surfaces/runtimes return a structured
  `409 platform_unavailable` with alternatives; the UI asks and never silently
  substitutes. Meta Modal + model agents is refused until its tool-turn client
  is verified (F-14).
- Operations UI: `/red`, `/blue`, `/monitoring`, and `/learning` are wired.
  Planned paths derive from the approved spec; executed trajectories,
  detections, and provenance read the immutable joined dataset export. The
  latest live export verified out-of-band: run `5de5ff61`, 6 joined steps
  (4 matched, red 4/blue 2), hash matches its dataset row.
- Rollout compatibility: when the additive learning tables are not installed,
  dataset publish now records zero trace rows with a loud warning instead of
  bricking the core exercise/score path; real trace write errors still fail.
  The live cloud DB still has no `traces` table, so F-4 capture remains
  inactive there until 0005–0008 are applied by an operator-approved channel.
- Live design: Modal + scripted produced a provisionable 8-host FreeIPA org
  (Rocky DC, vulns/objectives on web/db, T1110 on mail). The Meta surface
  currently returns billing 402 (`billing_not_configured`), so Meta model
  agents are blocked outside this codebase until billing is resolved. The
  console default is therefore the verified-working Modal + scripted path;
  Meta + agents remains selectable once billing is fixed.
- Gates at this entry: root typecheck clean; workspace tests backend 188/188
  and marketing 1/1 including both new regression tests; frontend production
  build clean. Interactive browser verification is pending: no Chromium
  executable is available in this session, so routes/modules were verified
  over HTTP only.

## 2026-11-03 — Agent loops: red orchestrator + blue log monitor (F-19, unit-verified)

- Red campaign: `runRedCampaign` now coordinates model-agent exercises on both
  the container and VM paths. The orchestrator delegates one objective at a
  time through `delegate_attack`, receives only retrieved/not plus executed
  attempt count, and cannot run attack commands or see proof values. Invalid
  and premature tasking is refused with the remaining objectives named;
  platform fallback attempts anything the coordinator fails to task. Each
  delegation is a `delegate_attack` trajectory step, and the score audit now
  carries `redCampaign` order/decisions/summary plus a `red:orchestrator`
  agent state.
- Blue monitoring: `blueInvestigate` now starts from deterministic
  `detectTelemetryAnomalies` candidates over collapsed telemetry (auth bursts,
  remote database access, execution-shaped rows, sensitive access, volume
  spikes), exposes them through `monitor_anomalies`, annotates fetched pages,
  and counts each row once across monitor + paging. The score audit carries
  `blueMonitoring` rows/events/pages/anomalies. Candidates remain leads:
  alerts still require cited rows and promoted-rule confirmation, and
  containment still requires enforceable read-back.
- UI: `/red` renders the orchestrator order/directives/outcomes and `/blue`
  renders monitor rows/events/pages/candidates from the score audit, with
  explicit “no record” states for older or scripted runs. Run context badges
  identify orchestrated red and blue log-monitor evidence when present.
- Gates observed for this entry: focused loop tests pass (including the two
  new F-19 regressions); root typecheck clean; full workspace tests backend
  196/196 and marketing 1/1; frontend oxlint 0 warnings/errors; frontend
  production build clean; worker restarted on the final build and metrics
  answered 200; `/red`, `/blue`, and `/monitoring` answered 200 over HTTP.
  Not observed: a live multi-objective Meta-agent exercise (billing still
  blocks that surface) or an interactive browser session (`command -v
  chromium` still exits 1).

## 2026-11-03 — Full spec-conformance audit and P0 hardening (F-20, partial)

- Audit: six read-only area audits (spec ledger; designer/provisioning;
  exercise agents; data/learning; frontend wiring; runtime verification)
  plus an adversarial critic and backlog synthesis mapped requirements to
  implementation and test owners. Roll-up stays **partial**: the operator core
  is real, but production closure is still blocked outside this codebase (see
  the last bullet). The critic confirmed the P0 order used here: redaction,
  ROE, trace/capture integrity, VM contained/Sigma semantics, host-scoped
  scoring/calibration, platform substitution gates, and the blue Detections
  fabrication.
- Fixed and regression-tested in `backend/test/spec-conformance.test.mjs`
  (new), `backend/test/datasets.test.mjs`, and `backend/test/runtime.test.mjs`:
  deep fail-closed redaction (exports, capture rows, trace rows, builder and
  legacy pairs) with platform rows excluded; capture split pinning and
  insert-only external capture (identical retry idempotent, differing
  rewrite `409`); shell/absolute-path/URI/external-target ROE bypasses;
  blue localhost/missing-why guardrails, attacker-host exclusion, final-page
  verdict turn, and non-citable monitor leads; VM scripted `contained`
  ingestion; same-host+technique agent alerts and technique-bound Sigma
  promotion; host/objective-scoped MTTD, exact coverage and false positives
  with Brier/ECE calibration and unscorable-window counting;
  provider/mixed-runtime/exact-Rocky-9+dc/service-exact deployment gates in
  both `deployability()` and the Pulumi program; pre-spend
  `409 platform_unavailable` for unavailable combinations on designed,
  refined, and imported specs; label corrections changing effective
  outcome/technique in selection and shaping; model-signal non-matches no
  longer stored/counted as hits and ground-truth-only rows skipped by
  graders; VM attacker proof-path telemetry kept while exact gate-proof
  artifacts stay excluded.
- Frontend/runtime: the blue Detections stat now reads only exported detected
  outcomes or the audit alert count; run `model_ids` are parsed from the row;
  built training snapshots are never presented as joined run exports; Clerk
  sessions require an active organization and a real membership role (no
  fabricated `personal`/`member`); Monitoring renders before the first run
  exists; ops pages invalidate on Supabase Realtime run/deployment changes;
  Temporal defaults match the managed platform (`localhost:7234`);
  `.env.example` now names the configuration surface.
- Migration `0011_trace_integrity_hardening.sql` is **authored, not applied**:
  per-run hash chain over raw trajectory fields, raw-trajectory append-only
  trigger (label-only platform updates still allowed), append-only
  corrections, no-delete disputes, and direct-client write revocation. It was
  exercised in a rolled-back local Supabase transaction: two inserted rows
  linked and verified (`chain_breaks 0`), a label update succeeded, and a raw
  action rewrite was refused.
- Gates observed on the final tree: `npm run build`, `npm run typecheck`,
  `npm test` (backend **205/205**, marketing **1/1**),
  `npm run lint -w frontend` (0 warnings/errors), and the frontend production
  build all pass. Live read-only checks: Langfuse health 200
  (`{"status":"OK","version":"3.221.1"}`), Prometheus healthy with
  `musearena-worker: up`, worker metrics 200, learning API `/health` 200,
  designer `:8787/design` 405 to GET (listening), and `/red`, `/blue`,
  `/monitoring` 200 over HTTP. This session's worker was restarted on the
  final build and the learning API started on `:8788`; the other session's
  designer/Vite processes were left untouched (the designer process predates
  this build, so its new pre-spend refusal needs that process restarted by
  its owner).
- Still blocked or unbuilt — not claimed: live Supabase schema is absent by
  direct PostgREST probe this session (`traces`, `capture_keys`,
  `corrections`, `label_disputes`, `signals`, `signal_hits`, `graders`,
  `models` → `404 PGRST205`; `datasets.family/selection/roles`,
  `runs.model_ids`, `datasets.run_id` → `400 42703`), so migrations
  0005–0011 need an operator-approved SQL channel (the configured access
  token is still invalid and this session cannot run DDL); Meta billing still
  blocks model-agent runs; `CLERK_SECRET_KEY` is still invalid and no
  Chromium is installed, so interactive Clerk/browser verification remains
  open; F-9→F-13/F-15 and the older open env-generation items (for example
  T-15 Linux/KVM segments and L2 DHCP) remain unbuilt; approval-time model-ID
  pinning (F-14) and a platform-required spec decision remain deferred
  design choices, not silent defaults.

## 2026-11-03 — Learning milestones F-9→F-13/F-15 implemented in code (live gates unchanged)

- F-9 training runs: control plane pins dataset/base/role/method/config,
  requester and budget, refuses a missing budget, parks honestly in
  `awaiting_trainer` when `META_TRAINER_URL` is unset, creates exactly one
  ready model only on a within-budget trainer success with artifact hash +
  allowlisted served ID, and audits create/approve/success/failure/cancel.
- F-10 evaluations: test-split suites are digest-pinned; candidate-vs-base
  panels carry mean/min/max/spread/count; primary-metric deltas inside
  combined spread are `inconclusive`; clock-skewed windows are unscorable and
  excluded from MTTD/calibration; calibration is Brier/ECE; Wilson intervals
  are reported and the leaderboard never ranks across mode/truth-layer
  groups. The production trial runner remains an injected boundary — with
  none configured an evaluation fails instead of fabricating metrics.
- F-11 deployments: passing-evaluation promotion gate with audited refusals,
  one active alias/environment, rollback restoring the previous target,
  traffic percentages, and `{alias, modelId, trafficPct}` pinned onto the run
  record and agent clients at exercise start (missing learning schema
  degrades to the previous resolution with a warning).
- F-12 continual loop: new-trace/correction/regression/schedule triggers
  draft deduped proposals only; operator approval converts one to a queued
  training run without approving training spend; rejection is terminal and
  audited. Trigger aggregates are caller-supplied — no scheduled trigger
  worker consumes this yet.
- F-13 learning UI: the `/learning` console now has real learning-API tabs
  (overview/data/signals/datasets/models/training/evaluations/graders/
  deployments/proposals) with empty states, server-reason errors, and
  lifecycle actions, plus new `GET /overview` and trace-list reads. A later
  headless Google Chrome app-bundle run reached the MuseArena sign-in page
  and produced a screenshot; the authenticated console was not exercised
  because the temporary browser profile has no Clerk session.
- F-15 slices: rubric/evaluation calibration is Brier-based with ECE
  reported, and dispute filing falls back to the trace row identity when a
  ground-truth row carries no Atomic GUID `stepId`.
- Migrations authored (not applied): 0012 training runs (+ `models.artifact_hash`),
  0013 evaluations, 0014 model deployments (+ `runs.deployments`), 0015
  training proposals. 0011–0015 were exercised only in rolled-back local
  Supabase transactions (0011 chain verify `0` breaks, raw rewrite refused).
- Gates observed: root build + typecheck pass; backend **225/225**,
  marketing **1/1**; frontend oxlint clean and production build pass;
  this session's worker and learning API were restarted on the final build
  (metrics + `/health` 200, Prometheus `musearena-worker: up`); `/overview`
  without a token is 401 as designed.
- Operator gates were re-probed after the operator chose to apply SQL,
  rotate credentials/fix billing, and provide hosts — **unchanged so far**:
  live learning tables still `404 PGRST205` and builder columns `400 42703`;
  Supabase access token still `401 Invalid access token`; Clerk secret still
  `401` invalid; `META_TRAINER_URL` still unset; `command -v chromium` still
  exits 1; host is still Darwin with no `/dev/kvm`. A combined operator
  script is prepared at `/tmp/apply_0005_0015.sql` (658 lines). Until those
  actions land, F-9→F-13/F-15 stay **in_progress / verified partial**, and
  older env-generation items (for example T-15 Linux/KVM, L2 DHCP) plus the
  F-14 approval-time pinning and platform-required decisions remain open.

## 2026-11-03 — Operator applied the live Supabase schema (0005–0015 confirmed)

- Read-only PostgREST re-probe after the operator reported Supabase done:
  `traces`, `capture_keys`, `corrections`, `label_disputes`, `signals`,
  `signal_hits`, `graders`, and `models` now return **200** (previously
  `404 PGRST205`); `datasets.family/selection/roles` and `runs.model_ids`
  now return **200** (previously `400 42703`). The 0011–0015 objects also
  probe present: `traces.chain_seq/prev_hash/entry_hash`,
  `models.artifact_hash`, `training_runs`, `evaluations`,
  `model_deployments`, `runs.deployments`, and `training_proposals` all
  **200**, and `trace_chain_verify` RPC answers **200** with zero rows for a
  probe org/run. (`datasets.run_id` remains `42703` by design — no migration
  adds that column; built datasets identify runs through their selection.)
- Remaining gates are unchanged on the same re-probe: Supabase access token
  still `401 Invalid access token` (no longer needed for schema application,
  still needed for management-API checks such as `platform-check.mjs`),
  Clerk secret still `401` invalid, `META_TRAINER_URL` still unset,
  `command -v chromium` still exits 1, and the host is still Darwin with no
  `/dev/kvm`. No live write/smoke was run against production in this check,
  so F-9→F-13/F-15 remain **in_progress / verified partial**.

## 2026-11-03 — Operator reported remaining gates done; workspace re-probe unchanged

- Credential endpoints re-probed with the workspace files: Supabase access
  token still `401 Invalid access token`; Clerk secret still `401` invalid.
  File metadata shows those values have not been rotated in this workspace
  (`.env` last modified 2026-11-02, `.env.local` 2026-10-27).
- Meta billing was checked with one minimal configured-key model call and
  still returns `402 billing_not_configured` for that key's team;
  `META_TRAINER_URL` is still unset.
- Browser: `command -v chromium` still exits 1 and no Chrome/Chromium binary
  is on `PATH`, but the installed Google Chrome app bundle was run headless
  against `/learning`; it redirected to the MuseArena sign-in page
  (screenshot inspected). The authenticated learning console remains
  unverified without a Clerk session in the automation profile.
- Host is still `Darwin studio.local` (arm64) with no `/dev/kvm`; no Linux/KVM
  host is reachable from this session.
- No task status flips follow from this re-probe. Updating the local env
  files with the rotated values (and, for KVM, running/attaching this work
  on the Linux host) is the missing operator step.
- Operator decision: keep the current state for now. The remaining
  credential, Meta, authenticated-browser, and Linux/KVM gates are accepted
  deferrals; affected tasks remain honestly marked partial rather than being
  reclassified as verified.

## 2026-11-03 — Linux/KVM host verified with real MuseArena VM lifecycle

- SSH access works with the operator-supplied key:
  `ssh -i ~/.ssh/local b0x@192.168.0.188`. The host is `agent`, Linux
  x86_64 (Omarchy/Arch kernel 7.2.3), 8 CPUs, 31 GiB RAM, 406 GiB free.
- Raw capability probe: `/dev/kvm` exists and is read/write for `b0x`, CPU
  exposes `vmx`, QEMU x86_64 11.1.1 and Docker 29.7.2 are installed.
  `ansible-playbook` is missing.
- Current backend build was staged in a disposable remote check directory.
  MuseArena `host-preflight.mjs --json` reports `accel: "kvm"`,
  `scoredAccel: "kvm"`, `canKvmVmiClaim: true`, `kvmWritable: true`; its
  verdict is `blocked` solely for missing Ansible.
- A MuseArena KVM boot probe ran with `accel: "kvm"`, the `kvm-vmi` gate
  accepted the host, and the guest printed `MUSEARENA-KVM-BOOT`.
- Full lifecycle proof: `vm-lifecycle-smoke.mjs` downloaded and verified the
  pinned Debian 12 amd64 image (`sha512:ba6073af…/arena-golden-debian12-1`),
  created `web-01` and `db-01`, observed userspace on serial, confirmed SSH
  hostname/user/seed identity for both, then destroyed the run. Final remote
  check found zero QEMU processes and the disposable state removed.
- Honest boundary: this verifies Linux/KVM machine creation and lifecycle.
  It does not yet verify a full configured/scored red-blue exercise on that
  host, bridge/tap networking, DHCP, or production worker deployment.
  Installing Ansible and running the full VM config/exercise smoke there is
  the next KVM step.
- Continuation: Ansible Core 2.22.0 was installed in the Linux user's
  `uv` tool environment (`/home/b0x/.local/bin/ansible-playbook`). The
  current MuseArena source was staged at `~/AgenticArena-kvm` without local
  secret files, backend/shared dependencies installed, and both packages
  built successfully. `host-preflight.mjs --require-kvm` now exits 0 with
  verdict `scored-vm-labs-ok` and no blockers.
- Full scripted VM exercise then passed on that host with `accel=kvm`:
  `web-01`, `db-01`, and `atk-01` became SSH-ready; Ansible finished with
  `failed=0` on all three; readiness passed SSH, HTTP, SQL, and lab TCP/HTTP
  probes; both sensor canaries and both planted-vulnerability proofs passed.
  The deterministic scripted red/blue exercise scored **2/2 objectives,
  20/20 points**, produced 3 alerts, 0 false positives over 117 benign
  events, enforced `block IP` against `10.2.32.12` on the guests, and
  exported an 11-step integrity-checked dataset
  `sha256:4b47991793e7e4a437bc…`. It ended `VM EXERCISE SMOKE OK`, with state
  removed and no leaked QEMU.
- Remaining boundary: this is a direct scripted smoke on the Linux host, not
  yet a production Temporal/Pulumi/Supabase worker deployment or a
  model-driven agent exercise there. Those still need the platform services,
  environment/secrets, and worker process deliberately deployed and verified
  on the host; bridge/tap networking and lab DHCP also remain unimplemented.

## 2026-11-03 — F-22 multi-host worker routing implemented; Linux platform awaits Docker group

- Operator chose **Build multi-host routing** and **Add b0x to docker**.
  Local inventory found the Mac platform/worker live and no pending or
  in-flight deployments in the latest 200 rows (`destroyed: 71, failed: 6`).
  The other session's local QEMU/designer/Vite processes were left untouched.
- New `backend/src/lib/worker-routing.ts` defines stable worker identity,
  route allowlists (`kvm|vm|container`), host eligibility, claim stamps, and
  maintenance ownership. The trigger now leaves another host's row pending,
  conditionally stamps `workerId`/`workerRoute`/`workerTaskQueue` on claim,
  and starts each workflow on the owner's queue. Worker maintenance uses a
  per-worker workflow ID; TTL, drift, and live-row TTL orphan handling are
  owner-scoped. Legacy mode remains queue `musearena` with no worker ID.
- Workflow smoke scripts accept `MUSEARENA_TARGET_WORKER_ID`; `vm-workflow`
  asserts the ready row's stamped owner. Runbook and `.env.example` document
  the routing configuration and the one-unrouted-owner rule.
- Verification: the new routing test first failed with
  `ERR_MODULE_NOT_FOUND`, then passed (8/8). Focused lifecycle/journey/runtime
  plus routing passed 55/55. Root build and typecheck pass; full tests pass
  backend 240/240 and marketing 1/1; frontend oxlint is 0/0 (the production
  build still emits the pre-existing single-chunk >500 kB warning).
- Linux sync/build: current source was rsynced to `~/AgenticArena-kvm`
  without secret files; shared/backend/deployment build there, routing tests
  pass 8/8, Pulumi CLI 3.272.0 and Docker resource plugin 5.2.0 are installed
  user-locally, and `host-preflight --require-kvm` again reports
  `scored-vm-labs-ok`.
- Exact remaining platform blocker: SSH re-probe still shows
  `id -nG` = `b0x wheel` (no `docker` group), and `docker info` returns
  `permission denied while trying to connect to the docker API at
  unix:///var/run/docker.sock`. Non-interactive sudo returns
  `sudo: a password is required`, so this session cannot grant the group.
  The operator must run `sudo usermod -aG docker b0x` on the Linux host;
  after that, deploy the platform, start the `linux-kvm` routed worker, and
  run the targeted real workflow smoke. No secrets or long-lived production
  services were copied/started before that gate.

## 2026-11-03 — Linux platform and routed workers deployed; targeted workflow passed

- Docker re-probe after the operator action: `id -nG` includes `docker`, and
  `docker info` reports server 29.7.2 on host `agent`. The pre-existing
  unrelated `ctfbox` container was left untouched.
- Current source was re-synced without generated state or secret files; the
  worker `.env` was then copied separately and verified mode `600` (the
  Clerk/API `.env.local` was not copied). Shared/backend/deployment build on
  Linux and routing tests pass 8/8 there.
- `npm run up -w @musearena/deployment` completed on Linux. Temporal,
  Langfuse web/worker, ClickHouse, Postgres services, Redis, MinIO, and
  Prometheus are up under the `musearena.plane=platform` label on loopback
  ports 7234/3100/9095. Langfuse `/api/public/health` and Prometheus
  `/-/healthy` return 200; `deployment/.platform.env` is mode `600`.
- The verified current-session Mac worker was stopped only after confirming
  its PID/parent/cwd and no in-flight deployment rows; it was restarted as
  `mac-hvf` with routes `container`, legacy task queue `musearena`, and
  `MUSEARENA_WORKER_OWNS_UNROUTED=1`. Metrics are 200 and Prometheus reports
  `musearena-worker: up`. The Syndicate worker and other-session QEMU guests
  were not touched.
- The Linux worker runs detached under PID 1 as `linux-kvm` on queue
  `musearena-linux-kvm` with routes `kvm,vm`; its maintenance workflow is
  `musearena-maintenance-linux-kvm`, metrics are 200, and Prometheus reports
  the worker target up.
- Targeted-workflow attempts failed honestly before acceptance: deployment
  `dbd50e8c-…` stopped at the deploy gate because the fresh Linux checkout
  lacked `backend/policy/node_modules/@pulumi/policy`; `npm ci` in that
  separate package fixed it. Deployment `3c50ca5c-…` then proved the owner
  stamp/queue but the smoke's 0.08 h TTL and five-minute ready window
  terminated it during first-boot package installation. Two- and three-guest
  diagnostics proved gw/dc/mail configuration passes on the same base image.
  The smoke now accepts explicit TTL/ready-timeout overrides and waits for
  the remaining TTL; the direct config smoke now orders every non-gateway
  after `gw-01`. Host preflight now blocks on Docker-daemon reachability,
  Pulumi, and missing policy dependencies instead of reporting a false pass.
- Deployment `a71cbb62-…` then completed deploy/configure/readiness/gates/
  exercise/dataset under owner `linux-kvm`, but the smoke correctly failed
  its solvability assertion at 2/3 objectives (20/30). Stored-trace
  inspection showed o2/o3 succeeded and o1 was observed but unverified: the
  web guest's `getent hosts x` inside `diag.php` takes 7.9 s on the Linux
  base image, while scripted red allowed only a five-second HTTP request.
  A disposable gw/dc/web diagnostic reproduced curl exit 28 at 5 s and HTTP
  200 with the marker at 8.0 s under a 20 s budget. The VM/container red and
  proof-gate diag requests now use 20 s HTTP / 30 s outer budgets, with a
  regression assertion in the VM exercise test (first observed failing on
  `--max-time 5`, then passing). Both workers were restarted on the fixed
  build. Deployment `b9712e43-…` then reached 5/6 on its first configure
  attempt (only `log-01` failed), but the smoke's 12-minute ready window
  terminated it during remediation. A direct six-guest
  `vm-config-smoke.mjs` run on Linux subsequently passed every config recap
  and readiness probe (`VM CONFIG + READINESS SMOKE OK`), proving the log
  failure was transient rather than a deterministic task failure.
  `applyConfig` now persists `ansible.log` beside the playbook and audits
  the first failed task name per host. Corrected deployment `3270200b-…`,
  with a 0.4 h TTL and 20-minute ready window, then passed end to end:
  claimed at `2026-11-03T22:01:42Z` by `linux-kvm` on
  `musearena-linux-kvm`, CrossGuard pass, six `vm:x86_64:kvm` outputs,
  configured 6/6 with no remediation, readiness and canary/proof gates pass,
  scripted score **3/3 objectives, 30/30 points**, 7 alerts, 0 false
  positives over 199 benign events, three enforced host isolations, stored
  16-step dataset hash-verified as
  `sha256:21fb6a870fd0172f…`, 6 Langfuse spans observed by the smoke, drift
  in sync, destroyed by the workflow TTL timer at
  `2026-11-03T22:25:47Z`, `resourcesDestroyed: true`, no leaked QEMU, and
  final output `VM WORKFLOW OK`. Final re-probe: Linux worker PID 3413960
  remains detached under PID 1 with metrics/Langfuse/Prometheus 200 and all
  platform containers up; the Mac `mac-hvf` worker remains metrics-200 in
  this Muse session. This was a deterministic scripted run, not a
  model-agent run.

## 2026-11-04 — F-12 server-derived continual aggregates and scheduled sweep

- Deferred gates were re-probed before selecting work: the live learning
  schema remains present, but `SUPABASE_ACCESS_TOKEN` still returns
  `401 Invalid access token`, `CLERK_SECRET_KEY` still returns `401` invalid,
  Meta still returns `402 billing_not_configured`, and
  `META_TRAINER_URL` remains unset. Google Chrome is installed on the Mac,
  but no authenticated browser session was exercised.
- `learning/continual.ts` now derives trigger aggregates from persisted
  traces, corrections, runs, and prior proposals. Labelled traces and
  corrections count only after the last proposal watermark for the same
  role/subject; corrections also obey the configured rolling window.
  Regression uses only `mode="agents"` runs, so deterministic scripted
  harness runs can never masquerade as model performance. Schedule triggers
  can name both roles while preserving the legacy single-object input.
- `runContinualSweep` selects the newest built train dataset and approved
  ready/available base model per triggered role, skips a role honestly when
  either default is unavailable, and creates proposals only. The worker has
  an opt-in hourly sweep (`MUSEARENA_CONTINUAL_SWEEP=1`, enable on exactly
  one worker) with env thresholds/bars/budget/method; it never approves a
  proposal or training run.
- Focused continual tests first failed on the missing exports and on a
  scripted run contaminating regression, then passed **8/8**. A read-only
  live Supabase probe scanned 5 orgs: 0 agent traces/corrections/agent-mode
  runs, 0 drafts after the scripted-run exclusion, and no built dataset/base
  defaults. Full local gates pass: root build/typecheck, backend **244/244**,
  marketing **1/1**, frontend oxlint **0/0**. The code was synced and built
  on Linux with continual tests 8/8 there.
- Activation boundary: deployment `4d99da0e-…` was actively `configuring`
  under `linux-kvm` with eight QEMU guests when the sweep was ready, so the
  Linux worker was deliberately not restarted. That deployment later failed
  on its own at the gateway `dns-resolver` task and was torn down with QEMU
  count 0; only then was the verified Linux worker restarted as PID 104476
  with `MUSEARENA_CONTINUAL_SWEEP=1`. Its first live pass reported
  `continual sweep: orgs=5 proposals=0 skipped=0 errors=0`, with
  metrics/Langfuse/Prometheus all 200. No live proposal is claimed because
  the current production rows contain no eligible agent evidence/defaults.

## 2026-11-04 — F-1 template registry persistence wired

- `templates/registry.ts` now has an org-scoped `TemplateStore` port and a
  service-role Supabase implementation. `TemplateRegistry.load` replaces the
  in-memory view from persisted rows; `registerPersistent` parses the spec,
  pins the canonical digest, allocates `max(persisted, local) + 1`, inserts,
  and reloads/retries on a unique-version race. Loading refuses rows for a
  different org, duplicate org/name/version rows, invalid specs, and digest
  mismatches.
- The in-memory registry now also allocates by maximum existing version and
  returns latest by version regardless of row/insertion order. The frontend
  direct-Supabase save path now parses the spec and allocates from the
  org-scoped maximum (with the same unique-conflict retry) instead of a
  global visible-row count; template reads parse stored specs rather than
  casting them unchecked.
- Migration `0016_template_version_unique.sql` adds the
  `(org_id, name, version)` unique guard and an org/family lookup index.
  It was applied with migration 0002 in a disposable Postgres 16 container:
  the first insert passed and a duplicate org/name/version insert failed
  with the named unique constraint. It has **not** been applied to
  production in this session.
- Focused template tests first failed on the missing persistence export,
  then passed **5/5**; the pre-existing registry test still passes. Full
  gates pass: root build/typecheck, backend **249/249**, marketing **1/1**,
  frontend oxlint **0/0**, and the production frontend build. A read-only
  live store probe returned 0 rows for `vm-workflow-org` and the current
  Clerk org. No live template write is claimed until migration 0016 is
  applied and a real save/load is observed.

## 2026-11-04 — Modal agent default and Glimmer small-agent tier

- Agent resolution now mirrors designer surface precedence: explicit
  `meta` / `meta-modal` wins; an unset platform surface selects Modal
  when either Modal proxy token is present (client construction still
  requires the pair, so a half-set pair fails loudly) and Meta
  otherwise. Registry lookup, pinned model IDs, deployment fallbacks,
  and direct VM/container fallbacks are all surface-aware.
- Muse Spark remains the primary Modal model for red, blue, judge,
  and designer work. Personas use Muse Glimmer 30B on the separate
  `ep-glimmer` SGLang application. Both `glimmer` and
  `meta-models/Muse-Glimmer-30B` are allowlisted for `meta-modal`;
  the repository ID canonicalizes to the served name `glimmer`, and
  endpoint selection prevents Spark/Glimmer cross-routing. Glimmer
  requests use its deployed contract (`reasoning: {enabled: true}`,
  `tool_choice: "auto"`, `top_p: 0.9`) and optional distinct proxy
  tokens/base URL/model/reasoning environment overrides.
- Tests first failed on the missing `baseModelFor` export, then the
  model and detection suites passed, including a mocked Glimmer tool
  turn asserting endpoint, model, reasoning shape, and tool choice.
  The stale learning-smoke expectation that a ready Modal row must be
  refused was updated to the verified Modal agent-client behavior.
- Live production-client probe against `ep-glimmer`: wake succeeded
  after 207 seconds from cold; JSON-schema output returned Ada/36/
  London exactly; the model emitted `get_weather({"city":"London"})`
  and then answered “sunny … 21°C” from the supplied tool result.
- Full gates pass: root build/typecheck, backend **263/263**,
  marketing **1/1**, frontend oxlint **0/0**. The Linux worker was
  rebuilt/restarted onto the routing code (PID **745124**, queue
  `musearena-linux-kvm`, routes `kvm,vm`, QEMU 0).
- The prior T-17 live check also completed in this cycle: clinic run
  `run-6f5df34c-…` stores pinned digest `sha256:6782bc9df574…`,
  distinct from the environment row's bare digest.
- Not claimed: a full scored model-agent campaign using the new
  default routing, a real trainer run, production migration 0016, or
  authenticated browser verification. Those gates remain as recorded.

## 2026-11-04 — First live Modal model-agent VM exercise

- `vm-exercise-smoke.mjs` now defaults persona shifts to Glimmer on
  Modal and warms that endpoint in parallel with provisioning. A live
  three-guest KVM run completed cleanly: configure 15/15, readiness
  8/8, canaries and gate proofs pass, exercised dataset verified
  (`sha256:2117066d…`, 26 steps), no false positives, and no leaked
  QEMU.
- The agent loops ran against live Modal endpoints: persona shifts in
  agent mode on `glimmer`; red and blue on the resolved Spark-based
  Modal defaults. Guardrails rejected 0 and had 0 unverified claims.
  The run scored **0/2 objectives, 0/20 points** with no alerts: the
  loop and audit plumbing are verified, but this is not a scored
  model-agent success.
- I updated `vm-exercise-smoke.mjs` to log each agent's resolved
  model ID so later runs preserve that evidence. Full gates remain
  root build/typecheck, backend **263/263**, marketing **1/1**, and
  frontend oxlint **0/0**.

## 2026-11-04 — CRUD closure: edit/archive/delete across the learning surface

- The application was create/read-only: zero PATCH/DELETE handlers. Added
  the update/edit/delete surface with the append-only evidence invariants
  kept intact (0011 hash-chained traces are tombstoned, never removed).
- New routes (all audited): `PATCH /datasets/:id` (rename, `?action=archive`
  / `?action=restore`; snapshots stay immutable, content hash never moves),
  `PATCH /models/:id` (metadata + deprecate-only status; readiness stays
  training-pipeline-owned; active-deployment guard), `PATCH`/`DELETE
  /signals/:id` (in-place flags; changed definitions re-version; delete
  cascades hits), `PATCH`/`DELETE /graders/:id` (same pattern), `DELETE
  /traces/:id` + `PATCH /traces/:id/restore` (synthetic-only tombstones;
  imported/field provenance refused 409), `DELETE /runs/:id` (tombstones the
  run's traces, removes the runs row; `trace_chain_verify` stays clean).
- Migration `0018_datasets_archive.sql`: `datasets.archived_at` +
  `traces.tombstoned_at/tombstone_reason`; datasets policy hardened to
  member read-only (writes via audited service-role routes only).
- Builder and signal scope exclude tombstoned traces (`selectRows`,
  `tracesInScope`); traces list returns `source`/`tombstoned_at`.
- Learning console: per-row Rename/Archive/Restore, Deprecate,
  Enable/Disable, Delete (guarded), Restore-trace actions with method/body
  support, archived/deleted badges, and a datasets "show archived" toggle.
- Verified live: backend **276/276** unit, learning-smoke **36/36** against
  local Supabase (29 prior + 7 new CRUD checks incl. chain-intact after run
  delete), frontend build clean. Not claimed: production migration apply.
