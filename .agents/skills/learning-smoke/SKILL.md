---
name: musearena-learning-smoke
description: Run and extend the live 36-check smoke against a local Supabase stack — the "unit green is not done" gate for every learning-surface change. Use this skill when verifying captures, review flows, datasets, training runs, CRUD lifecycle, or when adding smoke checks.
---

# Live learning smoke

`backend/scripts/learning-smoke.mjs` drives the real HTTP routes against a
real database. It is the gate that separates "tests pass" from "works".

## Run it

```sh
cd backend
supabase start                     # local stack up
supabase db push                   # migrations applied
SUPABASE_URL=http://127.0.0.1:54321 \
SUPABASE_SERVICE_ROLE_KEY=<key> \
MODAL_PROXY_TOKEN_ID=x MODAL_PROXY_TOKEN_SECRET=x \
node scripts/learning-smoke.mjs
```

Expect `36` check marks and `"ok": true`. The service key: `supabase status`
prints it (the `sb_secret_...` value works on current CLI builds; the JWT
`eyJ...` form on older ones).

## What it covers

Publish/idempotency, corrections, disputes, adjudication re-hash, signals
(rule + model, hit-once), graders versioning, registry fail-closed, capture
keys (issue → ingest → revoke → audit), imported runs with provenance,
dataset builds (roles, splits, real-share floor, source filters, family
collision 409), and the full CRUD lifecycle including: rename never rehashes,
archive hides/restores, deprecate-only status, definition re-version
supersedes, tombstone + restore, chain-intact after run delete.

## Conventions that matter

- **Fresh org per run**: the smoke uses `org-smoke-<timestamp>`. Traces are
  append-only (0011), so cleanup-by-delete is impossible; isolation comes
  from a new org each time. Never "fix" this by disabling triggers.
- **Clerk is substituted** — the session verifier is injected; org/role
  resolution below it is production code. Do not add Clerk-dependent checks.
- **Fail closed**: every refusal path (403 role, 409 conflict, 400 allowlist)
  is asserted with its reason, not just its status.

## Adding a check

1. Follow the existing shape: `call(path, token, init)` → assert status →
   assert body → `pass("one-line what-was-proven")`.
2. Assert the invariant, not the implementation: "a rename never moves the
   content hash", not "the update statement ran".
3. Negative tests belong here too: the refused path is part of the contract.
4. Update the count in docs (`README.md`, `docs/learning-api.md`) if you
   add checks — they cite 36.
5. Re-run twice in a row; the fresh-org design must make that idempotent.
