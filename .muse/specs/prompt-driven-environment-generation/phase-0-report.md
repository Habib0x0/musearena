# Phase 0 Spike Report — MuseArena

Date: 2026-10-26. All three spikes resolved; blockers for T-1 cleared.

## Spike A: Pulumi Automation API from TypeScript + local file state — PASS (live run)

Ran on this machine (Docker daemon, Pulumi CLI, Node 22) from `/tmp/pulumi-spike`:
`preview → up (Stack + RemoteImage + Container, change summary create:3) →
destroy`, driven by `@pulumi/pulumi/automation` `LocalWorkspace.createOrSelectStack`
with a `file://` backend and passphrase secrets. Post-run: `docker ps -a`
shows zero leftover containers; state persisted under `state/.pulumi/`.

Findings to carry into T-5:
- Pin TypeScript to v5 in worker images: TS6 (current latest) violates
  `@pulumi/pulumi`'s `typescript >=3.8.3 <7` peer range.
- Pre-create the file-backend state dir; `stack init` fails on missing dir.
- Pulumi CLI plugin download ignores/fails through this proxy (`get.pulumi.com`
  dial timeout) — worker images must **pre-bundle provider plugins**
  (`pulumi plugin install -f`) instead of downloading at runtime.
- Labels (`arena.run_id/org/ttl`) attach cleanly to resources for the sweeper.

## Spike B: Clerk JWT → Supabase RLS — VIABLE (researched, needs credentials)

Native third-party auth: add Clerk as provider in Supabase
(Auth → Third-Party Auth → Clerk domain); Supabase validates session tokens
via Clerk JWKS, no shared secret. RLS policies use `auth.jwt()->>'sub'`
(a `auth.uid()` variant does not apply with Clerk).
Source: [Clerk × Supabase guide](https://clerk.com/docs/guides/development/integrations/databases/supabase).
Live proof needs Clerk + Supabase project credentials — outstanding action
for the user before T-2 completes.

## Spike C: Agent runtime bar — LangGraph baseline documented

Replacement bar for any Meta-ecosystem framework: checkpointing
(SQLite/Postgres savers), interrupts for human review, streaming,
native subgraphs/multi-agent handoff.
(meta-model-cookbook patterns + Meta agent-frameworks docs remain the
primary target; LangGraph is the fallback, never a co-runtime.)

## Gate verdict

Phase 0 complete. T-1 (monorepo scaffold) may start. T-2 blocked only on
Clerk/Supabase project credentials for the live RLS proof.
