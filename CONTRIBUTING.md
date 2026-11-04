# Contributing to MuseArena

Thanks for your interest in making MuseArena better.

## Read the spec first

MuseArena is a spec-driven project. The requirements, design, and task
list live in `.muse/specs/`. Before you change behavior, read the part of
the spec your change touches. If your change contradicts the spec, open an
issue first so we can decide whether the spec or the code is wrong.

## What we accept

- Bug fixes with a failing test that proves the bug.
- Features that line up with the spec's task list.
- New detection rules (Sigma), catalog services, and persona scripts —
  these are data, not code, and are the easiest way to contribute.
- Documentation fixes.

## What we will not accept

- A score that is not backed by matched evidence. If a change makes a
  number look better without a proof path, it will be refused.
- Weakening of the append-only guarantees (traces, corrections, audit
  log) or of the model allowlist.
- New outbound network calls that are not documented and opt-in.

## Development setup

```sh
npm install
npm run build
npm test
```

Backend tests run unit-level. A full check needs a local Supabase stack:

```sh
cd backend
supabase start
supabase db push
SUPABASE_URL=http://127.0.0.1:54321 \
SUPABASE_SERVICE_ROLE_KEY=<key> \
node scripts/learning-smoke.mjs
```

See `docs/getting-started.md` for the full walkthrough.

## Rules for code

- Keep the package borders: `frontend` never imports `backend`; both
  talk through `shared/` contracts.
- Match the existing style of the file you touch. Do not reformat code
  you did not change.
- Every write path in the learning API writes an audit row. If your
  change writes without auditing, it is wrong.
- No third-party AI provider names in code, comments, docs, or UI. The
  model plane is Meta-only and the docs say so in provider-neutral terms.

## Commit style

One line, imperative, describes the outcome. Look at `git log` for
examples.

## Reporting security issues

Do not open a public issue for a security problem. Use the private
vulnerability reporting in this repository's Security tab.
