# Learning API

The learning API stores exercise evidence and controls the training loop. It
runs as one Node process on port 8788. The console, the worker, and external
harnesses talk to it over HTTP.

This document lists what each route does, who may call it, and what the
platform guarantees.

## Start

```sh
node backend/dist/api/main.js
```

The process reads its port from `MUSEARENA_API_PORT` and its host from
`MUSEARENA_API_HOST`. The default is `127.0.0.1:8788`.

## Sign-in

Every route except `/health` needs a caller identity.

- Console routes need a session token. The token carries an org id and a role.
  Roles are `reviewer`, `trainer`, and `operator`. Each role can do what the
  roles below it do.
- Capture routes need a capture key. An external harness uses a key to submit
  traces for its own org. A key can never write to another org.

The org always comes from the verified token or key. A body field that names
an org is never read.

## Roles

| Role | May do |
|---|---|
| `reviewer` | Read all learning data for the org |
| `trainer` | Build datasets, define signals and graders, start training runs |
| `operator` | Register models, approve training, adjudicate, delete runs and traces |

## Traces

A trace is one agent step: what the agent saw, what it did, and what outcome
the ground truth gave it. Traces are the base for all datasets.

Rules:

- Traces are append-only. No one can change or remove a stored row.
- Each row is hash-chained to the row before it. The chain can be verified
  with `trace_chain_verify`.
- Each trace carries a source: `synthetic` (platform exercise), `imported`
  (export from an external harness), or `field` (real observation).

| Method and path | Role | What it does |
|---|---|---|
| `POST /capture/v1/traces` | capture key | Store one step from an external harness |
| `GET /traces` | reviewer | List the last 100 traces, with filters |
| `GET /traces/:id` | reviewer | Read one trace with its corrections and disputes |
| `DELETE /traces/:id` | operator | Tombstone a synthetic trace. Imported and field traces are refused. |
| `PATCH /traces/:id/restore` | operator | Remove a tombstone |
| `DELETE /runs/:id` | operator | Tombstone all traces of a run and remove its runs row |

A tombstoned trace stays stored and chained. Dataset builds and signal runs
skip it.

## Review

| Method and path | Role | What it does |
|---|---|---|
| `POST /traces/:id/corrections` | reviewer | Record a correction on a trace |
| `POST /traces/:id/disputes` | reviewer | File a dispute against an auto-label |
| `GET /disputes` | reviewer | List disputes, with filters |
| `POST /disputes/:id/adjudicate` | operator | Set the final label |

Rules:

- A correction is a new row. The trace itself never changes.
- A changed label applies at dataset build time. The stored trace stays as it
  was.
- Each adjudication raises the dispute version. The old label stays readable.

## Signals and graders

A signal finds traces that match a rule or a model question. A grader defines
how a run is scored.

| Method and path | Role | What it does |
|---|---|---|
| `POST /signals` | trainer | Define a signal |
| `GET /signals` | reviewer | List signals with hit counts |
| `POST /signals/:id/run` | trainer | Run a signal now |
| `PATCH /signals/:id` | trainer | Change flags or definition |
| `DELETE /signals/:id` | trainer | Delete a signal and its hits |
| `POST /graders` | trainer | Define a grader |
| `GET /graders` | reviewer | List graders |
| `PATCH /graders/:id` | trainer | Change flags or spec |
| `DELETE /graders/:id` | trainer | Delete a grader |

Rules:

- A rule signal is a fixed set of conditions. It is not a query language, so
  a stored signal cannot read arbitrary data.
- A model signal names its judge at definition time. Every result records
  that judge id.
- A signal marked `continual` runs when new traces arrive.
- A changed definition creates the next version and disables the old one.
  Both versions never grade the same trace.

## Datasets

A dataset is a read-only snapshot of selected traces, stored as gzip files.

| Method and path | Role | What it does |
|---|---|---|
| `POST /datasets` | trainer | Build a snapshot |
| `GET /datasets` | reviewer | List snapshots. Add `?archived=1` to include archived ones. |
| `PATCH /datasets/:id` | trainer | Rename. Use `?action=archive` or `?action=restore` for the lifecycle. |

Rules:

- Each snapshot has a content hash. The same selection always makes the same
  hash, and an unchanged hash reuses the stored files.
- One scenario family cannot appear in two splits. This stops leakage.
- A build can refuse a dataset with too little real data. Set `minRealShare`.
- Rename and archive change metadata only. The hash never moves.

## Models

The registry lists the models an org can use. The platform calls Meta models
only.

| Method and path | Role | What it does |
|---|---|---|
| `POST /models` | operator | Register a model |
| `GET /models` | reviewer | List models. Add `?role=red` to filter. |
| `GET /models/resolve` | reviewer | Show which model a role resolves to now |
| `PATCH /models/:id` | operator | Rename, edit metrics, or deprecate |

Rules:

- A model id is checked against the approved list before it is stored. A row
  cannot point an agent at a provider that is not approved.
- A role resolves to its newest `ready` model, or to the verified base model.
- Only a training run can set `ready`. A manual edit can only deprecate.
- A model served by an active deployment cannot be deprecated. Roll back
  first.

## Training and evaluation

| Method and path | Role | What it does |
|---|---|---|
| `POST /training-runs` | trainer | Create a training run |
| `GET /training-runs` | reviewer | List training runs |
| `POST /training-runs/:id/approve` | operator | Approve and submit to the trainer |
| `POST /training-runs/:id/cancel` | operator | Cancel a run |
| `POST /evaluations` | trainer | Create an evaluation |
| `GET /evaluations` | reviewer | List evaluations |
| `POST /evaluations/:id/run` | trainer | Run an evaluation |

Rules:

- A training run pins its dataset, base model, method, and budget before
  anything starts.
- Without a trainer endpoint the run stops in `awaiting_trainer`. It never
  reports success without a real artifact hash.
- Spend above the budget cancels the run.
- An evaluation compares a trained model against the registered base model
  on a held-out suite. A model that never won never reaches production.

## Deployment of models

| Method and path | Role | What it does |
|---|---|---|
| `POST /models/:id/deploy` | operator | Deploy a model to an alias |
| `POST /model-deployments/:id/rollback` | operator | Roll back to the prior target |
| `GET /model-deployments` | reviewer | List deployments |

Rules:

- Production deployment needs a passing evaluation.
- A failed candidate leaves the current production target untouched.

## Capture keys

| Method and path | Role | What it does |
|---|---|---|
| `POST /capture/v1/keys` | operator | Issue a key. The raw key shows once. |
| `GET /capture/v1/keys` | reviewer | List keys with prefixes |
| `POST /capture/v1/keys/:id/revoke` | operator | Revoke a key |

## Audit

Every write action writes one row to the audit log. The log is append-only
and hash-chained. A broken link proves that someone changed history.

## Error codes

| Code | Meaning |
|---|---|
| `400` | The request body is not valid |
| `401` | No token, no key, or an invalid one |
| `403` | The role is too low for this action. The response names the role needed. |
| `404` | The object does not exist in your org |
| `405` | The path exists, but not with this method |
| `409` | The action conflicts with the current state |
| `413` | The body is too large |
| `422` | The request is valid, but the platform refuses it. Example: a dataset with too little real data. |
