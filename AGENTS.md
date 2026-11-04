# AGENTS.md

npm-workspace monorepo (root `package.json`): `backend/` (Node/TS, compiles to
`dist/` and runs from there), `frontend/` (React/Vite), `shared/` (Zod
contracts), `marketing/` (static HTML, built by `node build.mjs`),
`deployment/` (platform IaC). `backend` and `frontend` both depend on
`@musearena/shared`; the frontend never imports backend code — cross-package
types flow through `shared/src/index.ts` only.

## Commands

```sh
npm run build              # root: builds every workspace
npm test                   # root: every workspace
cd backend && npm test     # backend: builds first, then node --test
node --test test/models.test.mjs      # focused test (run from backend/, needs a prior build)
cd frontend && npm run lint           # oxlint
cd backend && node scripts/learning-smoke.mjs   # live 36-check smoke (see below)
```

Backend tests import from `../dist/` — always `npm run build` in `backend/`
before running a focused test after edits, or you test stale output.

## Non-negotiable invariants

Breaking any of these is a wrong change, not a style choice:

1. **Append-only evidence.** `traces`, `corrections`, `label_disputes`,
   `audit_log` are hash-chained; DB triggers (migration 0011) refuse
   UPDATE/DELETE even for service_role. Trace deletion is tombstoning
   (`tombstoned_at`), never row removal; `trace_chain_verify` must stay
   clean. Only `synthetic` traces can be tombstoned — `imported`/`field`
   are provenance evidence (refuse with 409).
2. **Meta-only model plane.** `AGENT_MODELS` + Modal Muse list in
   `backend/src/lib/model.ts` is fail-closed; every registry row and env
   override is re-checked against it. No other provider, ever. There is no
   default Modal endpoint URL — deployments set `MODAL_BASE_URL` /
   `MODAL_GLIMMER_BASE_URL`.
3. **Evidence-backed scores.** A score comes from trajectory-to-ground-truth
   joins (`matched`), never agent self-report. Gates (`configurator/gates.ts`)
   can never pass themselves: proof = exploit fired + marker observed in the
   target's own telemetry; no executor configured → gate FAILS.
4. **Fail closed, no silent substitution.** Unknown service kinds, vuln
   types, CVE registry ids, model ids → hard error with the reason. The
   catalog never approximates (`SERVICE_CATALOG` in `configurator/catalog.ts`
   is the closed vocabulary; bump `CATALOG_VERSION` when semantics change).
5. **Every write is audited.** New mutation routes need an action in
   `AuditAction` (`backend/src/lib/audit.ts`) and an `audit()` call.

## Layout worth knowing

- `backend/src/api/` — the learning API host (`main.ts`, port 8788); route
  modules per resource. Roles: reviewer < trainer < operator (checked in
  `auth.ts`, org/role always from verified Clerk claims, never body fields).
- `backend/src/designer/` — prompt → EnvironmentSpec pipeline; coherence
  validation rejects designs referencing unknown host ids.
- `backend/src/configurator/` — catalog, Ansible task generation, gates,
  readiness. `vuln-targets.ts` is the CVE registry: each entry pairs a
  planted vulnerable app + exploit steps + a Sigma rule with the same id in
  `backend/detections/`. Adding one: registry entry + Sigma + tests in
  `test/vuln-targets.test.mjs` (the Sigma parser supports
  contains/startswith/endswith and and/or/`1 of x*` — no regex).
- `backend/src/learning/` — datasets/signals/models/training services.
- `backend/src/worker.ts` — Temporal worker (needs Temporal on :7234;
  `temporal server start-dev --port 7234`). A deployment is owned by one
  worker host from claim through teardown (Pulumi state/VM registry are
  host-local).
- `backend/supabase/migrations/` — numbered; apply locally with
  `supabase db push`. 0011 added the append-only triggers; 0018 added
  tombstone/archive columns.
- `.muse/specs/` — the specs this repo is built against. Read the relevant
  section before changing behavior.
- `.agents/skills/` — deeper task guides (designer, vuln-targets,
  learning-crud, learning-smoke, exercise-lifecycle). Consult these before
  working in those areas.

## Workflow quirks

- **Unit green ≠ done.** Learning-surface changes require the live smoke:
  `supabase start && supabase db push`, then from `backend/`:
  `SUPABASE_URL=http://127.0.0.1:54321 SUPABASE_SERVICE_ROLE_KEY=<key>
  MODAL_PROXY_TOKEN_ID=x MODAL_PROXY_TOKEN_SECRET=x
  node scripts/learning-smoke.mjs` — expect 36 passes, `"ok": true`.
  The smoke uses a fresh org per run (`org-smoke-<ts>`); cleanup-by-delete
  is impossible by design. Never "fix" a failing cleanup by disabling
  append-only triggers.
- Long-running services load code from `backend/dist/` at process start —
  after rebuilding, restart the API host (default :8788) or you probe stale
  routes.
- `.mjs` test files must not use TypeScript-only syntax (no
  `import type`); they run under plain node against `dist/`.
- Env: secrets live in `.env` / `.env.local` (gitignored). The smoke accepts
  either `SUPABASE_SERVICE_ROLE_KEY` or `SUPABASE_SECRET_KEY`. The service
  key from `supabase status` may be `sb_secret_...` or a JWT depending on
  CLI version.
- Org/tenant isolation is Clerk claims + Postgres RLS; capture keys resolve
  to an org, and a capture body naming an org field is rejected (strict
  schema) — the org always comes from the verified credential.
- No third-party AI product names in code, comments, docs, or UI (use
  provider-neutral wording; the model plane is Meta/Muse only). No Chinese
  anywhere in the repo.
