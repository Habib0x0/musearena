# Requirements — Follow-on Platform (templates, training, marketing)

> Revised 2026-11-03 (operator direction): the model-training surface is the
> primary product shape, not a helper for dataset export. AgenticArena exists
> to train **offensive (red) and defensive (blue) models** on exercises that
> actually ran, with ground truth the model cannot author. This file defines
> what the platform must do; implementation status lives in `tasks.md` and
> `progress.md`, never here.

## 1. Template library

**As a** researcher **I want** versioned, reusable environment templates **so that** proven designs can be rerun without re-prompting.

1. WHEN a template is registered THE SYSTEM SHALL version it, group it by scenario family, and pin a spec digest.
2. WHEN a template is fetched without a version THE SYSTEM SHALL return the latest version.

## 2. Offensive/defensive model training

### 2.1 Capture and trace record

**As an** AI lab **I want** every red, blue and persona action recorded as a queryable trace **so that** training and evaluation use what the model actually did.

1. WHEN an exercise runs THE SYSTEM SHALL record one trace row per agent step with `run_id`, `step_index`, `actor` (red/blue/persona), `host_id`, `technique_id`, observation, reasoning, tool call, action, and the joined ground-truth `outcome`.
2. WHEN a trajectory step carries a structured action THE SYSTEM SHALL persist it as machine-readable `detail` (tool argv, blue response, cited evidence rows, guardrail verdict) and SHALL use that field, not free-text prose, as the source of a training example.
3. WHEN an external agent harness submits a trace THE SYSTEM SHALL accept it through a versioned capture endpoint authenticated by a one-time capture key, with the same schema as an internal exercise trace.
4. WHEN a trace is captured THE SYSTEM SHALL keep the raw event chain intact (append-only, hash-linked) and SHALL NOT allow a client to rewrite an existing trace row.
5. WHEN a dataset is published THE SYSTEM SHALL materialise the traces it contains, idempotently per `(org, run, step)`.

### 2.2 Review, corrections and adjudication

**As a** reviewer **I want** to correct, accept, reject and re-prompt agent actions **so that** model behaviour is steered by expert judgement, not only by success/failure.

1. WHEN a reviewer acts on a trace THE SYSTEM SHALL record a correction with `kind` (`approve`, `reject`, `edit`, `reprompt`, `label`), the before/after values, the reviewer and a timestamp.
2. WHEN two labels disagree THE SYSTEM SHALL file a label dispute in a versioned queue; the adjudicated label SHALL supersede the auto-label in every subsequent dataset export.
3. WHEN a label is adjudicated THE SYSTEM SHALL write a tamper-evident audit entry containing the previous value, the new value and the version.
4. WHEN a dataset is exported THE SYSTEM SHALL apply adjudications before hashing, so the stored snapshot is the adjudicated one.
5. WHEN a reviewer edits or re-prompts a step THE SYSTEM SHALL store the corrected completion as a training example without destroying the original action.

### 2.3 Signals and grading

**As a** trainer **I want** programmatic and model-based signals over traces **so that** good behaviour is recognised at scale.

1. WHEN a signal is defined THE SYSTEM SHALL version it and support three kinds: deterministic `rule`, `model` judge, and `human`.
2. WHEN a signal runs over traces THE SYSTEM SHALL persist a hit per `(signal, trace)` with a label and optional score; re-running an unchanged signal SHALL NOT duplicate hits.
3. WHEN a grader is defined THE SYSTEM SHALL support the existing exercise rubric, deterministic checks, and a model judge, each versioned and independently enabled.
4. WHEN grading is applied to a subset of traces THE SYSTEM SHALL be able to apply the same grader to new traces automatically (continual grading).
5. WHEN a model judge is used THE SYSTEM SHALL pin the judge model ID into the result and SHALL NOT let the judge's own prose override joined ground truth for red success or blue containment.

### 2.4 Datasets

**As an** AI lab **I want** immutable, role-specific, leakage-checked datasets **so that** training and evaluation are reproducible and honest.

1. WHEN a dataset is built THE SYSTEM SHALL select from traces by filters (role, run, technique, outcome, signal hit, correction kind) and record the selection in the dataset metadata.
2. WHEN a dataset is exported THE SYSTEM SHALL emit a content-hashed immutable snapshot with format version, redaction policy version, spec digest, technique-pack version, catalog/profile/image versions, and model IDs.
3. WHEN a dataset is split THE SYSTEM SHALL assign one scenario family to exactly one split (`train`, `val`, `test`) and SHALL refuse a family that already has a snapshot in another split.
4. WHEN a dataset contains proof, noise or platform rows THE SYSTEM SHALL exclude them from training and evaluation exports.
5. WHEN a credential, secret or honey-token appears in a trace THE SYSTEM SHALL redact it and record the redaction policy version.
6. WHEN the same content is published twice THE SYSTEM SHALL reuse the existing snapshot and SHALL NOT create a duplicate row or object.
7. WHEN role-specific training files are written THE SYSTEM SHALL emit red SFT/preference files and blue SFT/preference files separately; the legacy red-only filenames SHALL remain red-only.

### 2.5 Model registry

**As an** operator **I want** one registry of base and trained models **so that** every run and evaluation names an exact artifact.

1. WHEN a model is registered THE SYSTEM SHALL record its name, version, base model, provider, status and artifact path.
2. WHEN a model is produced by a training run THE SYSTEM SHALL record the training run that produced it and SHALL NOT mark it `ready` before the run succeeds.
3. WHEN a model is selected for a role THE SYSTEM SHALL resolve only models approved for that role (red, blue, persona, judge).

### 2.6 Training runs

**As a** trainer **I want** one-click, role-specific training runs **so that** improving red and blue does not require a separate ML pipeline.

1. WHEN a training run is created THE SYSTEM SHALL pin the dataset, base model, method (`sft`, `dpo`, `lora`, `grpo`), configuration and requesting user.
2. WHEN a training run starts THE SYSTEM SHALL require an explicit approval for any run that targets a production alias.
3. WHEN training completes THE SYSTEM SHALL record metrics, the output model artifact and a content hash; a failed or cancelled run SHALL NOT produce a `ready` model.
4. WHEN the trainer is not configured THE SYSTEM SHALL park the run in `awaiting_trainer` with the exported manifest, rather than pretending it trained.
5. WHEN a run is created THE SYSTEM SHALL be able to target either red or blue, and SHALL keep their datasets and artifacts separate.
6. WHEN a training run's reported spend exceeds its budget THE SYSTEM SHALL cancel the run, record the spend, and audit the cancellation.

### 2.7 Evaluations

**As a** trainer **I want** held-out, reproducible evaluations **so that** a model change is accepted or rejected on evidence.

1. WHEN an evaluation runs THE SYSTEM SHALL execute a pinned held-out suite of exercise specs against the candidate model.
2. WHEN red is evaluated THE SYSTEM SHALL report objectives achieved, points, exact-technique coverage, steps and tokens per objective, and guardrail violations.
3. WHEN blue is evaluated THE SYSTEM SHALL report MTTD, containment correctness, false-positive rate, evidence-citation correctness and calibration (Brier score and expected calibration error), with clock-skew windows excluded.
4. WHEN a baseline exists THE SYSTEM SHALL report the candidate-vs-baseline delta and SHALL NOT compare scores across different run modes or truth layers as directly comparable.
5. WHEN clock skew exceeds tolerance THE SYSTEM SHALL mark the affected window unscorable and SHALL NOT emit an MTTD derived from it.
6. WHEN an evaluation runs THE SYSTEM SHALL execute the configured number of trials and SHALL report the mean and spread of each metric; a candidate-vs-baseline delta inside that spread SHALL be recorded as inconclusive, not as an improvement.

### 2.8 Model deployments

**As an** operator **I want** approved promotion and rollback **so that** a trained model reaches exercises only after it passes evaluation.

1. WHEN a model is promoted THE SYSTEM SHALL require a passing evaluation, an approver and a target alias.
2. WHEN a model is active THE SYSTEM SHALL resolve the alias per role (red, blue, persona) at exercise start and SHALL pin the resolved model ID into the run record.
3. WHEN a deployment is rolled back THE SYSTEM SHALL restore the previous alias target and SHALL audit both actions.
4. WHEN a deployment is staged THE SYSTEM SHALL support a traffic percentage and SHALL record which percentage a run used.

### 2.9 Continual improvement

**As an** AI lab **I want** the loop to keep running **so that** models improve with each exercise, not only at launch.

1. WHEN new traces arrive THE SYSTEM SHALL apply enabled continual graders and materialise their hits.
2. WHEN a configured threshold is met (new labelled traces, correction volume or score regression) THE SYSTEM SHALL propose a training run; it SHALL NOT start one without approval.
3. WHEN a candidate model fails its evaluation gate THE SYSTEM SHALL keep the current production model active and SHALL record the rejection.

### 2.10 Governance and audit

1. WHEN any training-relevant state changes THE SYSTEM SHALL write a hash-chained audit entry (dataset built, run started/approved/failed, model promoted/rolled back).
2. WHEN an operator configures data boundaries THE SYSTEM SHALL restrict which runs, roles and splits may train, and SHALL enforce the boundary at dataset build time.
3. WHEN a model is trained or deployed THE SYSTEM SHALL record the dataset hash, spec pins and model lineage so a result can be reproduced.
4. WHEN a capture key is issued THE SYSTEM SHALL show it once and store only a hash and prefix.
5. WHEN a user acts on training state THE SYSTEM SHALL require the org role that action needs — `reviewer` to correct or file a dispute, `trainer` to build a dataset, create a run or request an evaluation, `operator` to adjudicate, approve, promote or manage capture keys — and SHALL refuse a missing role by naming the required one.
6. WHEN a captured key is revoked THE SYSTEM SHALL reject subsequent use and audit the attempt.
7. WHEN an organization is deleted THE SYSTEM SHALL remove its traces, datasets, evaluations and model artifacts; traces, datasets and evaluations SHALL be retained for 90 days by default with a per-org override.

### 2.11 Model plane constraint (Meta-only)

1. WHEN any production agent or judge is constructed THE SYSTEM SHALL use a Meta-provided model surface: the Meta Model API (`muse-*`) or Meta's Modal-hosted Muse Spark Open endpoint.
2. WHEN a model ID is resolved THE SYSTEM SHALL fail closed on any ID not verified for tool use or not in the Meta registry.
3. WHEN a provider fails THE SYSTEM SHALL fail over across Meta surfaces, never to a third-party provider.
4. WHEN a model is used for red, blue, persona, training or judging THE SYSTEM SHALL pin its exact model ID into the run or result record.

### 2.12 Platform selection and exercise operations

**As an** operator **I want** to choose the environment runtime and model surface before design and deployment **so that** the platform never silently builds or exercises a different lab from the one I approved.

1. WHEN a design starts THE SYSTEM SHALL let the operator select the environment runtime (`vm` for the KVM organization lab or `container` for the Docker lab), the designer model surface (`meta` or `meta-modal`), and the exercise engine (`scripted` or `agents`).
2. WHEN a runtime is selected THE SYSTEM SHALL constrain and validate every generated instance against that runtime; a mixed-runtime design SHALL enter the bounded repair flow rather than being silently rewritten.
3. WHEN the selected model surface or runtime is unavailable THE SYSTEM SHALL stop before spending on a substitute, name the unavailable selection and the available alternatives, and SHALL switch only after the operator chooses an alternative.
4. WHEN a deployment is approved THE SYSTEM SHALL pin the selected runtime, model surface, exercise engine, and resolved model IDs into the deployment and run records.
5. WHEN model agents are selected on a surface without a verified tool-turn client THE SYSTEM SHALL refuse that combination before provisioning and SHALL offer the verified Meta agent surface or the scripted engine as explicit choices; it SHALL NOT silently fall back.

**As a** red-team operator **I want** the planned and executed attack paths **so that** I can see how each objective was attempted, where it landed, and what evidence proved it.

1. WHEN a run is selected THE SYSTEM SHALL show each planned attack path from its entry host through the planted weakness and target service to the objective asset.
2. WHEN trajectory data exists THE SYSTEM SHALL show the red steps in time order with technique, host, action, outcome, matched telemetry, token/step usage when recorded, and objective outcome.
3. WHEN the run used the scripted exercise engine THE SYSTEM SHALL label it as a deterministic scripted harness and SHALL NOT present its steps as model-agent behaviour.
4. WHEN model agents run multiple objectives THE SYSTEM SHALL use a red orchestrator loop that delegates one objective at a time, receives only the platform-verified outcome, and records its tasking order and directives; the orchestrator SHALL NOT execute attack commands or receive proof values.

**As a** blue-team operator **I want** a monitoring dashboard **so that** I can see detections, response, false positives, and environment health while the exercise runs and after it finishes.

1. WHEN a run is selected THE SYSTEM SHALL show blue detections, response actions, matched and unmatched telemetry, MTTD, containment, false-positive rate, and coverage from the same joined evidence used for scoring.
2. WHEN deployments change state THE SYSTEM SHALL update the monitoring view with deployment stage, exercise state, score state, dataset state, drift, and TTL state.
3. WHEN no run, trace, or dataset exists THE SYSTEM SHALL show an explicit empty state and SHALL NOT fabricate activity from a score or a design.
4. WHEN a dataset is shown THE SYSTEM SHALL identify its source run, exercise engine, model IDs when present, joined-step count, actor counts, dropped-step count, split, and content hash before offering it as trajectory evidence.
5. WHEN the blue model agent runs THE SYSTEM SHALL monitor telemetry in batches, compute deterministic anomaly candidates from telemetry content only, and record the candidates and fetched batch counts; an anomaly candidate SHALL remain a triage lead until blue cites the underlying rows and a promoted rule confirms a detection.

## 3. Marketing site

**As a** visitor **I want** a public page explaining the product **so that** I can reach the Designer.

1. WHEN the marketing package builds THE SYSTEM SHALL emit a static `dist/index.html` describing design, deploy, and exercise, linking to the Designer.

## Non-functional requirements

- **Isolation:** training data is org-scoped by row-level security; no tenant reads another tenant's traces, corrections, datasets, models or runs.
- **Reproducibility:** every dataset, training run, evaluation and deployment pins its inputs and hashes its artifacts.
- **Honesty:** success and containment come only from joined ground truth; a model's self-report is never a label.
- **Cost:** training runs carry an explicit budget; a run that exceeds it is cancelled, not silently continued.
- **Safety:** offensive training data stays inside the platform; no public exposure of exercise artifacts or model weights.
- **Latency:** trace capture is asynchronous and must not add more than one second to an exercise step.

## Out of scope for this slice

- Third-party model providers (the model plane is Meta-only).
- RL environment serving at scale (GRPO is an accepted method value, not a promised trainer).
- Public dataset or model sharing.
- Automatic promotion without human approval.
- Windows/AD guests and AWS/GCP provider branches (unchanged from the environment spec).
