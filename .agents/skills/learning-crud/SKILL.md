---
name: musearena-learning-crud
description: Edit and delete learning objects (datasets, models, signals, graders, traces, runs, environments) through the learning API while keeping the append-only evidence rules intact. Use this skill when a task asks to rename, archive, restore, deprecate, disable, tombstone, or delete any platform object, or touches backend/src/api write paths.
---

# Learning CRUD

Every object supports edit and delete after creation. The rules below are
guarantees about the evidence, not preferences — every change must keep them.

## Hard rules

1. Traces, corrections, disputes, and the audit log are append-only. Never
   DELETE or UPDATE a stored trace row's payload.
2. Trace deletion is tombstoning: set `tombstoned_at`. The row stays stored
   and hash-chained; `trace_chain_verify` must stay clean. Only `synthetic`
   traces can be tombstoned — `imported`/`field` are provenance evidence
   (409).
3. A dataset snapshot never changes its content hash. Rename and archive
   touch metadata only. Builds reuse by hash; archived snapshots are hidden
   from builders, restorable.
4. Only a training run sets a model to `ready`. Manual edits may only
   deprecate; a model served by an active deployment cannot be deprecated.
5. A changed signal/grader definition mints the next version AND disables
   the previous row — two versions must never grade the same trace.
6. Environment (deployment) delete is teardown-first: a live lab is torn
   down through its own workflow (cancel → same path as TTL), then marked
   `destroyed`. Runs/traces/datasets survive as evidence (runs.deployment_id
   has no cascade — that is why it is a status mark, not a row delete).
7. Every write action writes an audit row; the action name must exist in
   `AuditAction` (backend/src/lib/audit.ts).

## Route map

| Object | Edit | Delete |
|---|---|---|
| Dataset | `PATCH /datasets/:id` (rename; `?action=archive`/`restore`) | — (archive) |
| Model | `PATCH /models/:id` (name, role, metrics, deprecate-only) | — (deprecate) |
| Signal | `PATCH /signals/:id` (flags in place; definition re-versions) | `DELETE` (hits cascade) |
| Grader | `PATCH /graders/:id` | `DELETE` |
| Trace | `PATCH /traces/:id/restore` | `DELETE` (tombstone, synthetic only) |
| Run | — | `DELETE /runs/:id` (tombstones traces) |
| Environment | — | `DELETE /deployments/:id` (teardown-first) |

Roles: reviewer < trainer < operator. Datasets/signals/graders need trainer;
models, traces, runs, environments need operator.

## Where the code lives

- Services: `backend/src/learning/{datasets,models,signals}.ts`
- Routes: `backend/src/api/{datasets,models,signals,graders,runs,deployments}.ts`
- Tombstone filtering: `selectRows` (datasets.ts), `tracesInScope` (signals.ts)
- Console actions: `frontend/src/components/LearningConsole.tsx`, `App.tsx` DeploymentTable

## Verify a change

Unit green is not done. After `npm run build && npm test`, run the live
smoke (36 checks) against a local Supabase stack — see the
`musearena-learning-smoke` skill. Restart the API host on 8788 if dist
changed.
