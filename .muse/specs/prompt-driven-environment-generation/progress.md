# Progress Log: prompt-driven-environment-generation

> Append-only session log. Do NOT edit previous entries.

---

## 2026-10-27 — Audit + honesty fixes (first entry; log was empty despite all tasks marked verified)

**Audit verdict:** every T-1…T-14 / F-1…F-3 flag was overstated. Repo had zero git
commits; several "verified" paths were self-certifying or dead ends. Build and
typecheck passed; only the 5 KVM boot tests existed.

**Live infra (read-only probes):** Supabase project live — migrations 0001+0002
applied (6 tables, 7 RLS policies). Clerk keys present. Temporal server NOT
running (port 7233 refused; images exist) — ops bring-up still pending.

**Fixed (code + `backend/test/honesty.test.mjs`, 12 tests; 17/17 pass):**
- Canary/proof gates emitted their own marker then "observed" it — rebuilt to
  verify independent event-store telemetry and fail closed without an executor.
- `verifyExportHash` had a loose fallback that accepted tampered exports —
  deleted; exact canonical-hash verification, exports self-verify, proof/noise
  rows excluded, adjudications feed exports, family split deterministic.
- Scoring matched objectives by technique alone — now asset+technique+
  objectiveId/signal bound; MTTD from ground-truth times; Navigator emits
  per-technique scores + tactics; rubric determinism asserted.
- Exercise runner fabricated blue detections — blue now fires only via
  promoted Sigma rules; no rule ⇒ no detection, no MTTD.
- Sigma promotion needed no evidence — now requires offline-replay alerts;
  rule versions immutable; drafts never fire live.
- SFT "success" counted blue containment — now ground-truth red success only.
- Spec digest was 64-bit-truncated, key-order sensitive — canonical full
  sha256 everywhere (designer, registry, run records, Pulumi labels).
- Pulumi mutated global `process.env` per stack (cross-org race) — per-workspace env.
- Deployment dead end closed: pending-row trigger (claim via conditional
  update) starts `deploymentWorkflow`; workflow sleeps TTL then tears down;
  exercise activity persists score via new `runs`/`datasets` writers;
  drift job persists reports ("unobserved" without a sensor source).
- Designer server served `MockModelClient({})` (always schema-failed) — now
  501 without META_API_KEY. Frontend gained the §6.3 cost acknowledgment gate.
- Root `.gitignore` + initial commit (secrets verified ignored).

**Still open (see corrected tasks.md):** Temporal bring-up + live loop run;
AWS/GCP provisioner branches; real Ansible roles; Langfuse; pySigma;
model-driven red/blue agents; canary/proof executors and sensor-state source
(without them proofActivity fails closed by design); e2e/tenant-isolation tests.


## 2026-10-27 — Live loop through Temporal + Supabase

**Infra:** `musearena-temporal` (temporalio/auto-setup:1.24.2) + `musearena-temporal-db`
(postgres:16) running; :7233 reachable. Worker started with live Supabase env and
`MUSEARENA_LOCAL_GATES=1`.

**Added:** `configurator/executors.ts` (local canary/proof executors, exact-`1` opt-in,
fail-closed default); `proofActivity` takes gates from env. `observability/export.ts`
join now requires host AND technique/objective compatibility (host-only matching fused
unrelated rows). `test/journey.test.mjs` (full local journey + negative path + trigger
validation); `marketing/test/` build test (Designer link in dist). `scripts/smoke.mjs`
live driver.

**Live evidence:**
- noop: `orgScopedJob` via worker → `ok:smoke-org`.
- lifecycle, deployment `359302dc-9c61-4267-a349-ba9b36f50c69`: trigger claimed row →
  `deploymentWorkflow` → Pulumi up (2 Docker containers, cidr 10.2.0.0/16) → configure
  (2 hosts) → PROOF_GATE_DECISION pass (canary observed, v1 T1003.001 proof) → exercise
  → `runs` row score 15/15 pts, 2/2 objectives, visibility+analytic coverage 1 →
  workflow RUNNING in TTL sleep → terminated → Pulumi destroy (5 resources) → zero
  containers labelled with the run id → deployment `destroyed`. Audit chain:
  DEPLOYMENT_START ×2, PROOF_GATE_DECISION, SCORE_COMPUTED, DEPLOYMENT_DESTROY.

**Blockers found live and fixed:**
1. Trigger started workflows for malformed specs (`proof-org` row with spec `{v:…}`):
   deployActivity crashed on `spec.budgets.ttlHours` and retried indefinitely. Fix: trigger
   validates against the shared zod `EnvironmentSpec`; invalid rows → `failed` with the
   reason in `access_info.error`. Unit test + live re-check (inserted bad row → `failed`
   within one poll).
2. Smoke driver tore down a stack named `pending` (stale poll snapshot) and leaked the 2
   real containers. Fix: re-read `stack_id` before teardown, refuse non-`dev-` names, and
   assert zero run-labelled containers remain. Leaked stack destroyed via the real
   teardown path; re-run clean.

**Honest limits:** gates pass only via local harness executors (not Atomic tests
inside the provisioned hosts); red/blue are the deterministic harness, not model agents;
TTL expiry not waited out (8h) — destroy path exercised directly; AWS/GCP absent.

## 2026-10-27 — Real, isolated local runtime (AnomalyLab reviewed)

**AnomalyLab review** (`PlatformEng/AnomalyLab`): no local Docker isolation, vulnerable
images, auditd/osquery or Temporal to port; its AWS Pulumi code (tags, private-subnet
VPC, up-then-destroy) and stack-state manager are the reference for the future AWS
branch, after dropping its IGW/public IPs/0.0.0.0/0 egress. Nothing was copied.

**Built:** per-run `internal` Docker network on the env's private /20 with hostId DNS
aliases; role images (`provisioner/roles.ts`): web=php:8.2-apache, db=postgres:16-alpine
(statement+connection logging), attacker vantage; unknown roles → generic alpine host
with no telemetry (gates fail). Real Ansible `raw` tasks over `community.docker.docker`
(base64-passed content, SQL/HTML escaping, per-host PLAY RECAP). Live docker gate
executors (`configurator/docker-executors.ts`). Workflow tears the env down on any
post-deploy failure. `test/runtime.test.mjs` (10 tests; 32 backend tests total pass).

**Live evidence (worker WITHOUT MUSEARENA_LOCAL_GATES):**
- deployment `c5582d68`: network Internal=true, every container attached only to it,
  zero published ports; `select version()` → PostgreSQL 16.15; attacker fetches the
  web-01 intranet page by hostname; attacker egress to 1.1.1.1 → "Network unreachable";
  canary seeded in `secrets`; PROOF_GATE_DECISION executor=docker, pass=true:
  v1 T1078 (weak-cred login from attacker, seen in Postgres log), v2 T1059 (command
  injection, marker echoed by shell into Apache error log); scored 15/15; destroy
  removed containers + network.
- negative, deployment `2ccca95c` (unplantable `cve`): gate failed closed twice
  (executor=docker), 0 runs scored, env destroyed immediately, 0 containers left.

**Found live and fixed:** (1) `networkMode` + `networksAdvanced` together dropped DNS
aliases → hostnames unresolvable, proofs unreachable; fixed (networksAdvanced only).
(2) Gate failure left the env running until TTL (8h); fixed with teardown-on-failure.

**Still open:** auditd/osquery (needs VM runtime; containers share the host kernel),
exercise red/blue still the deterministic harness (does not use the live env),
AWS/GCP branches, CrossGuard/preview gate, scheduled orphan sweeper, `deployment/` IaC.

## 2026-10-27 — Everything except AWS/GCP (operator: "leave AWS at the end")

All evidence below is live (Temporal, Supabase, Docker, Meta API) unless noted.
Commits eb1f3866 … 62371ae9.

**Platform (T-2):** migration 0003 applied live — audit hash computed by the DB
over the stored row + prev_hash under a per-org advisory lock, UPDATE/DELETE
refused, `audit_verify()`; existing 34 rows re-sealed (backed up first).
deployments/runs added to Realtime. Clerk registered as Supabase third-party
auth. `scripts/platform-check.mjs` 10/10 (cross-org read/write, unauth,
no-key 401, chain verify ×2 orgs, tamper refused ×2, Realtime). Migration
0004: private `datasets` bucket, org-scoped read, unique (org, hash).

**Designer (T-4):** Clerk-authenticated endpoint (RS256/JWKS, CORS allowlist,
loopback, body cap). Runtime capability contract: roles normalized,
undeployable designs blocked with reasons, trigger re-checks. Budget gate
uses the platform estimate. Live: acceptance prompt 22.6s (blocked: Windows
image); over-budget blocked; refinement preserves untouched parts; intranet
prompt 3/3 provisionable in 19–22s after stating hard constraints in the
prompt (the model consistently invented persona workstations).

**Exercise (T-8) + detection (T-12):** live red from the attacker container,
outcome verified by returned canary / executed marker AND collector
observation; blue via promoted SigmaHQ YAML rules over out-of-band telemetry,
enforced "block IP" (attacker disconnected), audited. 4 rules, promotion by
replay of a recorded calibration corpus (3 promoted, 1 draft). Control run:
60 benign events, 0 alerts.

**Traces/datasets (T-7, T-11, T-13):** per-run event store; dataset (export,
SFT, pairs, Navigator, manifest) uploaded immutably and re-verified from
Storage; trajectories to self-hosted Langfuse; Navigator from the pinned
ATT&CK 15.1 STIX bundle (sha256 a57988bf…); explicit `dropReasons`; cold
reproduction 077ff8d0 → ec17765a passes all six checks.

**Ops (T-5, T-10):** CrossGuard deploy gate before `up`; hourly
`maintenanceWorkflow` (orphan sweep from runtime labels, TTL backstop,
drift); 72s-TTL env self-destroyed; drift in-sync → drifted:db-01; platform
plane IaC in `deployment/` (Temporal, Langfuse v3 stack, Prometheus; 26
resources, loopback-only, encrypted secrets); `deployment/RUNBOOK.md`.

**End-to-end (T-9):** `scripts/e2e.mjs` prompt → dataset → teardown in 53.3s
(2/2, containment 1, FP 0, 5 Langfuse spans).

**Bugs found live and fixed (each re-verified):**
1. Blue detection/containment events went to the global store → exports
   lacked blue, persisted containment 0 (regression test fails on old code).
2. Docker Desktop VM↔host clock skew (~1s) leaked setup traffic into the
   exercise window → 2 false positives; window now anchored on target clock.
3. Deterministic canary marker: a pre-disable log line satisfied a later gate
   (regression test fails on old code); fresh nonce per execution.
4. One malformed legacy deployment row crashed the TTL scan for every env.
5. CrossGuard rule refused the real program (provider reports
   networkMode=bridge as computed default at preview).
6. Realtime check raced listener registration after SUBSCRIBED.
7. Smoke driver terminated the workflow before dataset publish completed.

**Not done / blockers:**
- AWS + GCP provider branches (deferred by operator).
- T-3 interactive Clerk login → dashboard: needs a human sign-in; the
  `CLERK_SECRET_KEY` in .env.local is rejected by Clerk ("invalid"), so a test
  user/session cannot be created programmatically.
- Req §12.1 auditd/eBPF + osquery: containers share the host kernel; needs the
  VM runtime, which has no live gates yet. Windows/AD needs a licensed image.
- Calibration from held-out ground truth (T-11); sinkhole exfil endpoint;
  roles beyond web/db; self-healing remediation; pySigma proper (in-repo
  equivalent for the supported subset).

## 2026-10-27 — Model-driven red/blue agents (T-8 gap)

Opt-in via `MUSEARENA_AGENT_RUNTIME=maas` (`src/exercise/agents.ts`,
`agents-live.ts`); unset keeps the scripted live runner as the recorded default.
Caps: `MUSEARENA_AGENT_MAX_{STEPS,INPUT_TOKENS,OUTPUT_TOKENS,MINUTES}`.

**Scoring stays ground truth:** before red starts, the platform plants a
random `MUSE-PROOF-<96-bit hex>` per objective (db: the objective's `secrets`
row; web: a file outside the docroot that needs RCE). An objective succeeds
only if that value comes back from real tool output AND the collector saw red
traffic on the asset; model text is never consulted (unit test: a model that
claims the proof in text scores 0). Blue proposals must name a defended host
and an allowlisted response; they become alerts only when a promoted Sigma rule
matches red-attributed telemetry; responses the Docker runtime cannot enforce
(e.g. "disable account") are audited as unenforced and earn no containment.

**Live, through worker → Temporal → Supabase (muse-spark-1.3, 14-step cap):**

| run | mode | objectives | points | alerts | containment | FP |
|---|---|---|---|---|---|---|
| run-05d14225 | scripted (default) | 2/2 | 15/15 | 3 | 1.0 | 0 |
| run-6e66d264 | agents-maas | 1/2 | 10/15 | 1 | 0 (chose "disable account": unenforceable) | 0 |
| run-0dabba09 | agents-maas | 1/2 | 10/15 | 1 | 0 | 0 |
| run-93de9e2c | agents-maas | 0/2 | 0/15 | 0 | — | 0 |

Red o1 (db, T1078): the agent enumerated hosts, tried no-password logins, then
sprayed seasonal passwords and read the proof (8–13 steps). Red o2 (web,
T1059): it never found `/diag.php` in 14 steps (path-guessing had no hit). Blue
(run-6e66d264) cited "~100+ auth.failures then app logon + SELECT secrets" and
proposed T1110 on db-01 and T1595.002 (scanning) on web-01.

**Fixed while verifying live:**
1. Postgres `password authentication failed` lines were dropped by the
   parser, so blue could not see the brute-force; now `auth.failure` events.
2. Proof planting landed inside the telemetry window → counted as a benign FP;
   planting now happens before the window opens.
3. Blue ended runs on empty turns, or announced containment without calling
   `respond`; one re-prompt for an explicit verdict (`clean` ends immediately).
4. Unsupported blue responses were silently coerced to "block IP"; now
   audited as unenforced.

**Step-cap pressure found in the full transcripts (then fixed):**
- Blue's pages were 40 *rows*, so red's brute force (hundreds of near-identical
  `auth.failure` rows) cost blue 13 of 14 steps paging (run-6e66d264); its
  proposals landed on the final step. A noisier attack would have ended at the
  cap with no verdict. Fix: consecutive identical events collapse into one
  counted row (`first..last xN`); pages are bounded by characters (7600, under
  the 8000-char tool-result cap, so nothing is cut silently) instead of rows;
  the last allowed step is reserved for a verdict (fetch is withdrawn and blue
  is told how much it saw). Live re-run run-90f6c8dc: blue finished in 6 steps
  (was 13), proposals cite "~26 auth.failures then logon + SELECT secrets".
- run-93de9e2c's 0/2 is a red step-cap artefact, not inability: red found
  `app:Summer2024!` on step 14 of 14 and had no step left to read the proof.
  Left as-is: raising red's cap is a budget choice, and the score is still
  correct ground truth for the budget given.

**Open:** agent red has not achieved the web objective. In run-90f6c8dc it
discovered `/diag.php` on step 14 of 14 (wordlist), with no step left to
inject. Agent runs vary run-to-run (0–1 objectives across 4 passing runs; n is
small). Blue's "disable account" choice is unenforceable on Docker, so agent
containment stays 0 unless it picks block IP / isolate host.

## 2026-10-27 — Muse model family + hallucination guardrails

**Models.** `dev.meta.ai` is the developer console (HTML 404 on `/api/models`);
the API is `api.meta.ai/v1`, and the client's fallback now points there (it
pointed at the console). Probed every listed model with a function-call round
trip (emit call → accept `function_call_output` → answer from it):

| model | agent-capable |
|---|---|
| muse-spark-1.1 / 1.2 / 1.3 | yes |
| muse-spark-1.2-contributor / 1.3-contributor | yes |
| muse-wonder-1.0 | yes |
| muse-image-1.0 | no (`image_generation` tool only) |
| sam-3.1 | no (needs image/video input) |
| muse-voice-transcribe-1.0 | no (not served on `/responses`) |

Per-role selection: `MUSEARENA_MODEL_{DESIGNER,RED,BLUE}` → `META_MODEL_ID` →
`muse-spark-1.3`. Ids outside the verified list fail closed. The run's
`modelIds` (red/blue) go into the SCORE_COMPUTED audit and dataset manifest.

**Guardrails (deterministic; no model judges a model).** Telemetry rows carry
ids (`[E12]`). Blue's `respond` must cite rows it was actually shown, at least
one on the host it names; the technique must exist in pinned ATT&CK 15.1
(sub-techniques normalised); `block IP` must give a non-local src present in
the cited rows, and enforcement disconnects the container that owns that IP
(previously always the attacker, whatever blue claimed). Containment counts
only if what was cut off is the attacker or the attacked host. Rejections go
back to the model with the reason. Red stating a `MUSE-PROOF-*` value no
command returned, and blue announcing containment without calling `respond`,
are logged as unverified claims. Counts per run in the score audit.
Scoring is unchanged: planted proofs + rule matches only.

**Live (one run per model, same scenario, 14-step caps):**

| model | run | objectives | alerts | containment | FP | rejected | unverified |
|---|---|---|---|---|---|---|---|
| muse-spark-1.1 | run-ff38d24f | 1/2 | 1 | 1.0 | 0 | 0 | 0 |
| muse-spark-1.2-contributor | run-e6ef6805 | 1/2 | 1 | 1.0 | 0 | 0 | 0 |
| muse-spark-1.3-contributor | run-495f1f8b | 1/2 | 1 | 1.0 | 0 | 0 | 0 |
| muse-wonder-1.0 | run-b3b10aea | 1/2 | 1 | 1.0 | 0 | 0 | 0 |
| scripted (default) | sweep tail | smoke OK | | | | | |

First agent runs with containment 1.0: blue cited evidence and blocked the
attacker's actual address. n=1 per model; this does not rank models.

**BLOCKED — Meta Model API access.** During the sweep the API began returning
`403 user_blocked` ("Your access has been restricted due to repeated policy
violations") for muse-spark-1.2 and 1.3 runs. Likely trigger: red-agent
prompts are offensive-security tasks (credential spraying, exploitation of
sandbox containers) sent at volume across today's runs. Not retried or worked
around. Until access is restored with Meta, agent mode and the designer cannot
call the model. muse-spark-1.2 / 1.3 have no completed guarded run.

**Found during the sweep — fixed and verified:**
- `upload export.json failed: Forbidden` was the storage gateway's request
  filter rejecting attack strings (e.g. `/../../`) in the dataset body. Replayed
  73 real red steps from the sweep: plain upload 403, gzip upload ok. All
  dataset objects are now stored gzip-encoded (`*.gz`, `manifest.encoding:
  gzip`); decoding is lossless, so content hashes are unchanged, and objects
  written before the change still decode. Scripted lifecycle smoke on gzip
  storage: 2/2, 15/15, stored export hash verifies (run-c00d1bb2).
- "Extra deployments": every one was created by a smoke run. A stopping worker
  kept its 15 s trigger poller alive after Temporal reported STOPPED and
  claimed the next sweep step's pending row (e.g. c8190f91 claimed by the
  spark-1.1 worker after shutdown), orphaning it or racing the new worker into
  two concurrent exercises. The poller now stops on SIGINT/SIGTERM and when
  the worker stops. Live check: worker A sent SIGTERM, row inserted after the
  signal, A did not claim it, replacement B started at once and stayed up.
- EADDRINUSE on the metrics port crashed the worker before it served
  anything. The metrics endpoint is now best-effort: the error is logged and
  the worker keeps running (unit test). Orphaned envs from earlier failures
  were torn down via Pulumi; a stuck `provisioning` row was marked failed.

## 2026-10-27 (evening) — Guardrails checklist audit; baseline re-verified; Meta block persists

**Audit of the guardrails checklist against the code (no new features).**
Every item traces to `e6be275c` and a passing test (backend 58/58):
- Model registry: `src/lib/model.ts` — verified `AGENT_MODELS`, default
  `muse-spark-1.3`, `modelForRole` fail-closed; fallback base
  `api.meta.ai/v1`; designer client uses the same default role path.
- Per-role ids recorded: agent run stamps `modelIds` on the run, the
  `SCORE_COMPUTED` audit, and the dataset manifest; smoke asserts all three
  surfaces in agent mode.
- Blue evidence guardrail: rows are shown as `[E…]`; `checkProposal`
  requires cited rows to have been shown, at least one on the named host,
  and for `block IP` a non-local src present in those rows. Enforcement
  disconnects the container that owns the cited IP and only counts
  containment when it is the attacker or the attacked host.
- ATT&CK pinning: `attack-15.1` reads the pinned STIX index by version;
  missing packs and unknown technique ids error rather than guess.
- Claim-vs-action checks: red text stating a `MUSE-PROOF-*` value that no
  command returned is logged as unverified; blue text announcing a response
  without a `respond` call is logged the same way. Counters are merged
  red+blue in the score-audit `guardrails` object.

**Still blocked live — Meta access.** `/v1/models` is reachable and lists
all 9 models, but `/v1/responses` returns `403 user_blocked` for
`muse-spark-1.2`, `muse-spark-1.3`, and `muse-wonder-1.0` (three single
benign function-call probes, one per model; no retries or workarounds).
So `muse-spark-1.2` / `1.3` still have no completed guarded run, and the
designer cannot call the model either. This is an account state to resolve
with Meta, not a code defect; the agent path stays opt-in and the scripted
runner remains the recorded default.

**Scripted baseline re-verified live (worker, no Meta calls).** Lifecycle
smoke `run-057555f3…`: deploy → configure → docker proof gates → live
red/blue → score 2/2 (15/15), containment 1.0, FP 0, 3 alerts, attacker
cut off after blue's response; dataset export hash verifies, zero proof
rows, 2 succeeded SFT rows, Navigator cells from the pinned bundle, 5
Langfuse spans; deployment destroyed with no run-labelled containers left
("SMOKE LIFECYCLE OK").

## 2026-10-27 (evening) — Spec rewritten: full-org Linux labs are the primary shape

Operator direction: the designer-built whole-organization lab (TinyNet-style:
gateway/DNS/DHCP, directory, mail, intranet, DB, logging, personas, weaknesses)
provisioned for autonomous adversary simulation **was** the original intent —
`requirements.md:5` ("full virtual organization"), `design.md:100` (personas
using real services), §12.1 (auditd). The implementation had narrowed to
web/db containers; VMs only boot-proofed. The spec now says so.

**Rewritten (docs only; no code changed, no status upgraded):**
- `requirements.md` — §1 designer may only emit catalog-provisionable
  roles/services/vulns/objectives + org-coherence validation; §2 Linux/KVM
  primary (AWS/GCP deferred behind the same spec), tiny-VM resource
  profiles + host-capacity check; §3 new machine-profile contract
  (install/configure/seed/enable per declared service, offline package
  story, declared base/client/red tooling, protocol + cross-service
  readiness gate as a hard prerequisite); §5 autonomous simulation with
  proof-only scoring, guardrails, scripted baseline; §8 structured
  services/dependencies/subnet/profile fields pinned per run. Out-of-scope
  now names Windows-without-image, AWS/GCP, and VMI-truth claims.
- `design.md` — Linux/KVM provisioner (host gate, golden Debian image,
  CoW overlays, bridges, management/telemetry net, VM-aware sweeper),
  profile resolver + closed service catalog, readiness gate, runtime
  adapter seam, VM telemetry, persona traffic through real protocols.
  Removed "KVM backend later / out of scope" contradictions.
- `tasks.md` — T-1…T-14 untouched (statuses/evidence preserved verbatim);
  Phase 7 added: T-15 persistent VM lifecycle, T-16 profiles/catalog/
  readiness, T-17 designer organizations, T-18 VM adapter + gates,
  T-19 adversary simulation on org labs, T-20 demo. All open/unverified
  except T-19, which records the container verification + Meta block.
- `README.md` (spec) — summary/providers/out-of-scope aligned.

**Still true after the rewrite:** nothing in Phase 7 is built. The verified
system remains the Docker web/db loop + scripted baseline; model-driven
runs remain blocked on Meta's account-wide 403 (todo-34).

## 2026-10-27 (evening) — Phase 7 Steps 1–2: host truth + structured services (code)

First implementation under the rewritten spec. Steps that need no Linux
host; VM execution itself is still unbuilt.

**Step 1 — T-15a host preflight + arch truth (`provisioner/kvm.ts`,
`scripts/host-preflight.mjs`, `test/kvm.test.mjs` 5→8 tests).**
`detectHost()` was refactored into a pure `classifyHost()`: Linux /dev/kvm
now requires the QEMU binary for the **host** architecture (before, only
`qemu-system-x86_64` counted, so an aarch64 Linux/KVM host was silently
classified tcg). `vmPlanFor()` follows the host arch and throws on
cross-arch OS strings instead of emulating. New `scoredVmAccel()`: scored
VM runs may use kvm/hvf only — tcg/none fail closed (unscored boot probes
unchanged). Preflight CLI reports platform/arch/accel, /dev/kvm presence
+ writability, tool availability, and a verdict (`scored-vm-labs-ok` /
`blocked` / `dev-only`). On this Mac: `darwin/arm64, hvf, dev-only`,
truth cap mirror-only, as expected.

**Step 2 — T-16a structured services + catalog + resolver (63/63 backend
tests, +5).** Shared spec gained optional `serviceDecls`
({kind, impl, port, readyWhen} from a closed kind enum), `subnet`,
`dependsOn`, `resources`. All optional, so legacy container specs parse
to identical objects — a regression test asserts the spec digest is
unchanged across the extension. `configurator/catalog.ts`
(`arena-catalog-1`) maps kind/impl → Debian packages, systemd units,
task groups, readiness probe, telemetry. `configurator/profiles.ts`
resolves role+services → ordered groups with the §12.1 base (auditd,
osquery, rsyslog, chrony, ssh) on every host, dependency-pulled client
tools, and the attacker red toolbox; an impl outside the catalog (e.g.
http/nginx) throws with host+service named. `deployability()` now checks
catalog membership, duplicate kinds, subnet declaration and dependsOn
targets on **all** runtimes, and blocks each VM host with a precise
reason (the blanket "vm runtime has no live canary/proof executor"
rejection is gone). The designer-facing catalog text describes the VM
catalog as in-build/not-deployable, so designs stay honest.

**Regression:** root `npm run build` + `npm test` green (backend 63,
marketing 1); Docker scripted baseline re-run live after the changes —
`run-501a8788…`: 2/2 (15/15), containment 1.0, FP 0 ("SMOKE LIFECYCLE OK").

**Next (needs the Linux host):** Step 3 golden Debian image + persistent
VM lifecycle (T-15b), Step 4 Ansible-over-SSH profiles + readiness gate
(T-16b). Decisions pending from operator: host identity/access, bridge/tap
privilege model (scoped sudoers recommended), x86_64-only vs arm64 too.

## 2026-10-27 (night) — T-15b: Debian 12 golden image + persistent VM lifecycle

Operator picked Debian 12 for the golden image (research: Alpine
minirootfs ~4 MB is the smallest artifact but not a bootable service host;
Alpine virt 67 MB; Debian 12 genericcloud qcow2 ~334 MB is the smallest
practical systemd + auditd/osquery base).

**Golden image (`provisioner/images.ts`).** `GOLDEN_IMAGES` pins Debian 12
bookworm generic cloud images for x86_64 + aarch64 by Debian's published
SHA512 (read from `cloud.debian.org/.../SHA512SUMS`, 2026-10-26);
`arena-golden-debian12-1`. `ensureGoldenImage()` downloads once, hashes
before any boot, deletes + retries once on mismatch, then refuses.
Unit test: verified bytes accepted, tampered bytes rejected twice → throw.

**Lifecycle (`provisioner/vm-lifecycle.ts`, new).** Per run:
`<state>/kvm/<runId>/` with a CoW qcow2 overlay per host over the verified
image (`qemu-img create -b`), a per-run ed25519 keypair, a NoCloud seed
ISO per host (hostname, `arena` sudo user + key, `/etc/arena/identity`),
pidfile + serial log, and a `vms.json` registry. `startRunVms` refuses
non-native accel (`scoredVmAccel`), refuses to double-start a live run,
and destroys everything it started on partial failure. `stopRunVms`
SIGTERM→SIGKILL with `stoppedAt`; `destroyRunVms` stops + removes the
state dir; `listVmRuns` feeds the future sweeper. Guests use QEMU
user-mode networking with an SSH hostfwd **for lifecycle proof only** —
`netMode: "user"` is recorded in state precisely so nobody mistakes
these guests for lab-bridged hosts. Two real bugs found and fixed:
1. No `genisoimage`/`xorriso` exists on the dev host (and it must not be
   a worker dependency): seed ISOs are now built by a built-in pure-Node
   ISO9660 writer (`provisioner/seed-iso.ts`, PVD/path-table/directory
   records, `CIDATA` label; structure unit-tested).
2. First real boot produced **zero serial bytes**: aarch64 `virt` cloud
   images need EDK2 UEFI. `uefiFirmwareFor`/`firmwareNearBinary` discover
   it (env override, Homebrew/system paths); lifecycle refuses aarch64
   starts without firmware instead of booting a black box.

**Live evidence (HVF, dev-only):** `scripts/vm-lifecycle-smoke.mjs` —
golden image hash-verified from the real download, 2 Debian guests
started through the lifecycle, serial logs 35 KB/22 KB with Debian
userspace seen, registry written, destroy removed state with no leaked
QEMU ("VM LIFECYCLE SMOKE OK"). Manual cross-check: same image reaches
init in ~4 s with `-bios edk2-aarch64-code.fd`.

**Regression:** build green; backend 67/67 (was 63; +golden/lifecycle/ISO
tests, all lifecycle tests run against fake qemu/qemu-img fixtures — no
real VM needed in CI); Docker scripted baseline re-run (2/2, 15/15,
containment 1, FP 0).

**Still open in T-15:** KVM-scored run on the Linux host; bridges/taps +
gateway DNS/DHCP + management net; VM-aware orphan sweeper; deploy/
teardown wiring (deployEnvironment still boot-proofs via the old Alpine
path). Golden OS/cloud-init notes: the image boots and cloud-init runs,
but SSH-into-guest configuration (T-16b) is not claimed yet.

## 2026-10-27 (night) — Agent system prompts: designer, designer-refine, red, blue

Replaced the three stub prompts (designer 14 lines, red/blue 5 lines each)
with full system prompts written against the actual code contracts, so what
the model is told matches what the platform enforces:

- `designer.md`: output contract (JSON-only EnvironmentSpec, exact enums,
  `truthLayer: mirror-only`); org-design method (shape → subnets →
  instances → personas → vulns/objectives); the two runtimes (container
  web/db verified today vs Linux VM org lab, in build); structured services
  with the closed catalog table (dns/dhcp/dnsmasq, ldap/openldap,
  smtp/postfix, imap/dovecot, http/apache-php, db/postgres, ssh/openssh,
  log/rsyslog-collector) + readyWhen probes; tiny resource profiles;
  dependency/persona/vuln/objective rules; explicit hard-rejection list
  mirroring `validateDesign` + `deployability` (hostId integrity, catalog
  membership, no Windows, budgets).
- `designer-refine.md` (new): preserve-everything refinement semantics,
  stable hostIds with consistent reference updates, catalog-only additions.
  `pipeline.ts` now loads it from file (was an inline string) and exposes
  `designerSystemPrompt()` / `designerRefinePrompt()` for tests.
- `red.md`: exec-tool discipline (argv, `reason`, small observable steps),
  ROE (named targets only; attacker host is not a target; no host/runtime/
  metadata/management reach; non-destructive), proof-only success ("state a
  value no command returned and it is recorded as an unverified claim"),
  hypothesis method, stopping/reporting.
- `blue.md`: fetch/respond loop; evidence discipline (cite only rows
  actually shown, at least one on the named host, block-IP source must be a
  cited non-local row, ATT&CK ids canonical); allowlist responses with
  proportionality guidance; persona noise vs attack sequences; the exact
  `clean` verdict; "announcing containment in prose without `respond` is
  an unverified claim".

Test (`journey.test.mjs`): prompt-content contract test asserts each prompt
carries its platform invariants and that the capability catalog is appended
to the designer system. Backend 68/68. No runtime behavior changed — same
files, same loaders; live Meta verification stays blocked (todo-34).

## 2026-10-28 (early) — T-15c: guest SSH identity + deploy/teardown wiring

The lifecycle could start guests and show Debian userspace on the serial
console, but nothing proved cloud-init had consumed the seed, and deploy
still used the old Alpine boot-proof path. This closes that gap: the
management plane is now real SSH into the guest.

**Guest access (`configurator/vm-ssh.ts`, new).** `startRunVms` records an
`ssh` endpoint per guest in `vms.json` (`127.0.0.1:<hostfwd port>`,
`arena`, the run's private key at `<state>/id_ed25519`). `execInGuest`
shells out with `BatchMode=yes` (never prompts) and a run-scoped
throwaway known_hosts (`StrictHostKeyChecking=no`,
`UserKnownHostsFile=/dev/null`) — guests are cloned per run, and the
endpoint is loopback-only. `probeGuestIdentity` retries until the guest
answers, then checks its *own* reported identity: `hostname`, `id -un`,
and `RUN_ID`/`HOST_ID` from `/etc/arena/identity` must match the registry
and the run. This is the first proof cloud-init consumed the NoCloud seed;
serial logs alone only prove the kernel booted. `vmTargetsFromState`
converts registry state into configurer/Ansible targets.

**Configurer.** `configureActivity` replaces bare VM hostIds with registry
endpoints (containers keep their Docker target). The Ansible inventory now
emits explicit `ansible_host`, `ansible_port`, `ansible_user`,
`ansible_ssh_private_key_file` and non-persistent host-key args for VM
hosts; previously `connectVia` was `arena@127.0.0.1:PORT`, which Ansible
cannot parse as a host.

**Deploy/teardown (`provisioner/deploy.ts`).** Any spec with vm-runtime
instances now starts guests after `stack.up`, probes each guest's SSH
identity, and records `vm:<accel>:<hostname>` as the host output — the
deployment is not `ready` until every guest passes. A failed start/probe
rolls back by destroying run VMs before the stack; teardown destroys VMs
first so no guest outlives its deployment record. Container-only specs
keep the previous path unchanged.

**Verification.** Backend build + workspace `npm run typecheck` green;
backend 70/70 (was 68; +identity parsing/target-mapping and registry-SSH
endpoint tests, still using fake qemu/qemu-img fixtures in CI). Live on
HVF (cached verified image): both Debian guests boot, then
`probeGuestIdentity` reports `hostname=web-01|db-01 user=arena
RUN_ID/HOST_ID match seed`, destroy removes state with no leaked QEMU
("VM LIFECYCLE SMOKE OK").

**Not claimed.** No Pulumi end-to-end deploy was run (deploy wiring is
build/unit-verified only). Lab bridges/taps, gateway DNS/DHCP, the
management/telemetry network and the QEMU-aware orphan sweeper are still
open; guests remain `netMode: "user"` and must not be treated as
lab-reachable. Ansible-over-SSH task groups + the readiness gate (T-16b)
are the next step, followed by the scored KVM run on the Linux host.

## 2026-10-28 — T-16b: baked catalog image, SSH configuration, readiness gate

Operator chose the baked-golden-image path for the spec's offline package
story (over a host-local mirror). This entry lands the first vertical
slice: base + HTTP + PostgreSQL profiles, proven end-to-end on two real
guests.

**Baked image (`provisioner/images.ts`, `scripts/build-catalog-image.mjs`).**
The builder boots the pinned Debian cloud image once, apt-installs the
union of every profile's packages (`allProvisionablePackages()`: base +
catalog servers + client tools + attacker toolbox — 28 packages), powers
off, compresses with `qemu-img convert -c`, and pins the artifact's SHA512
in `golden/baked-images.json`. `resolveGoldenImage()` prefers a staged
baked artifact and falls back to the cloud image (warning) when it is not
staged; a present-but-tampered artifact throws. Each guest records
`imageName` so a run states which tier it booted.

Two real findings at build time:
1. **osquery is not in Debian at all** (the `packages.debian.org` page is
   an error page). The base profile still declares it, so the bake adds
   the official `pkg.osquery.io/deb` repo at build time (arm64 4.5.0;
   depends only on libc6/zlib1g) and the artifact is hash-pinned
   afterwards. The Debian cloud repo provides everything else.
2. The first bake attempts failed cleanly on a wrong pidfile/serial path
   (QEMU names per-guest files after `hostId`), and one crashed build left
   a guest holding the fixed hostfwd port. The builder now uses a random
   hostfwd port, captures QEMU stderr, and kills the guest on any failure.

Live artifact: `debian-12-catalog-aarch64.qcow2`, 713 MB compressed /
6 GiB virtual, `sha512:f50b878a82fa0359…`, 28 packages.

**Configuration (`configurator/ansible.ts`).** VM hosts get profile task
groups before the role tasks: `profile-install` (dpkg-check every resolved
package, apt-install only the missing ones — a no-op on the baked image),
a minimal osquery config, service bootstrap (PostgreSQL `pg_hba` local
trust), `profile-enable` (`systemctl enable --now` every profile unit),
and `db-seed-access` (app role + owned database). Role tasks are
root-wrapped as `base64 -d | sudo -n sh` because the SSH user is `arena`.
Live bug found: postgres was already running with the old `pg_hba` when
the seed ran → `Peer authentication failed for user "app"`; the seed now
reloads/restarts the cluster after the config edit. Also found: Ansible
2.21 does not honor `_meta.hostvars` in a *static* JSON inventory (it logs
"Skipping unexpected key (hostvars) in group (_meta)" and exposes `_meta`
as a group) — host vars now live on each host, so the warning is gone.

**Readiness (`configurator/readiness.ts`, `activities.readinessActivity`).**
All eight `readyWhen` values have protocol probes run inside the guest
over the run's SSH endpoint: `ssh-login` (identity), `tcp`, `http-2xx`,
`sql-select`, `dns-query`, `dhcp-lease` (DHCPACK in the journal),
`ldap-bind` and `smtp-imap-roundtrip` (per-run derived lab credentials).
Checks fail closed on command error, empty output or a missing token; the
activity audits `PROOF_GATE_DECISION {gate:"readiness"}` and increments
`arena_readiness_decisions_total`. The workflow now runs readiness
between configure and proof; container specs skip it (their Docker gates
are unchanged).

**Live evidence (HVF, baked image).** `scripts/vm-config-smoke.mjs`:
2 Debian guests from `debian-12-catalog` → SSH identity matches seed →
`ansible-playbook` over SSH (web 5 ok/failed 0, db 8 ok/failed 0) →
readiness `ssh-login`, `http-2xx` and `sql-select` all PASS → destroy
leaves no QEMU ("VM CONFIG + READINESS SMOKE OK"). Backend 73/73
(+5: baked-manifest pinning/refusal, package union, VM profile tasks,
probe mapping and fail-closed checks).

**Not claimed (at that point).** DNS/DHCP, LDAP, SMTP/IMAP and
log-collector *config/seed* groups were not implemented yet; no
cross-service proof. The x86_64 baked artifact must be built on an x86_64
host. VM specs remain blocked at `deployability` until T-18's
canary/proof/telemetry executors exist (the message now says so), and the
container runtime still has no readiness executor. Drift does not reuse
the probes yet.

## 2026-10-28 — T-16b (cont.): DNS, LDAP, mail and log collector profiles

The remaining loopback-only service profiles are configured and proven on
the same baked image; only DHCP and cross-host traffic still need lab L2.

**Configuration (`configurator/ansible.ts`).**
- DNS: `/etc/dnsmasq.d/arena.conf` with `domain=arena.lab`,
  `local=/arena.lab/`, `listen-address=127.0.0.1`, `bind-interfaces` and a
  `host-record=<hostname>,127.0.0.1`; the probe is a real `dig` query for
  the host's own name.
- LDAP: debconf preseed + `dpkg-reconfigure slapd` (domain
  `arena.lab`, backend MDB, admin password `labSecret(runId,"ldap-admin")`),
  then an idempotent `ldapadd` of `ou=people` and `uid=probe` after the
  unit starts.
- Mail: postfix reconfigured to Internet Site
  (`mail.arena.lab`, local destinations, `home_mailbox = Maildir/`,
  loopback-only), dovecot set to loopback with Maildir and plaintext auth,
  and a `probe` system user with `labSecret(runId,"mail-probe")`. The
  readiness probe now *sends a real message* with swaks and polls IMAP
  until it lands (the earlier `--quit-after RCPT` only tested RCPT).
- Log collector: rsyslog `imtcp` on 514 into an isolated
  `/var/log/arena/remote.log` ruleset. Live bug: rsyslog is already
  enabled in the base image, so `systemctl enable --now` did not load the
  new input and 514 stayed closed; the config now restarts rsyslog before
  readiness.

`labSecret()` moved to `configurator/lab.ts` so configuration and probes
share one derivation.

**Live evidence (HVF, baked image).** `scripts/vm-config-smoke.mjs` now
runs a 6-guest lab (web, db, gw/dns, dc/ldap, mail/smtp+imap,
log/rsyslog) — every host `ok`, zero failed: `ssh-login` on all six,
`http-2xx`, `sql-select`, `dns-query`, `ldap-bind`,
`smtp-imap-roundtrip` (twice, smtp and imap) and `tcp` all PASS.
Destroy leaves no QEMU ("VM CONFIG + READINESS SMOKE OK").

**Not claimed.** DHCP has no config/probe that can pass without a shared
L2; cross-host proofs (DNS/DHCP via the gateway, web→DB read,
LDAP-backed mail login, forwarding logs to the collector) also require
lab networking (T-15 bridges/taps). The x86_64 baked artifact, container
readiness executor and drift-probe reuse remain open, as do T-18 VM
gates.

## 2026-10-28 — T-18a: VM canary/proof executors

The gate plane no longer assumes Docker. `configurator/vm-executors.ts`
runs actions inside the guest over the run's SSH endpoint and verifies
them in the guest's own sensor output; exit codes are never trusted.

- **Canary:** `sudo auditctl -m <marker>` writes a kernel-audit USER
  message; the executor reads `/var/log/audit/audit.log` over SSH and
  ingests the marker only when the line is present. A guest with auditd
  off produces no event and the gate fails.
- **Proof (code-flaw):** the same-host command injection is exercised via
  `/diag.php`, and only the *bare marker* line in Apache's error log
  counts (the request line alone would pass even if the shell never ran).
  This mirrors the Docker executor's telemetry rule.
- **Fail closed:** vuln types the VM runtime cannot yet plant/prove
  (weak-cred) throw with a named reason instead of passing.
- `gatesFor(spec, env, runId)` selects the VM executor for all-VM specs;
  `proofActivity` passes its runId, so the executor resolves the run's
  `vms.json` registry.

**Live evidence (HVF, baked image).** `scripts/vm-gates-smoke.mjs`: one
web guest with a planted command injection → configure over SSH (5 ok) →
canary PASS (`auditd` marker observed) → proof PASS (`v1` T1059 seen in
telemetry) → 2 ground-truth events → clean destroy. Backend 75/75 (+2:
telemetry-verified pass and blind-guest/unsupported-type fail-closed).

**Not claimed (at that point).** The live red/blue exercise and dataset
for VMs, enforcement (isolate/block), the weak-cred proof, and the full
auth/service telemetry feed for blue were T-18b.

## 2026-10-28 — T-18b: scripted VM exercise, telemetry, weak-cred, deployable VM labs

VM labs now run the whole loop on real guests with the same detectors,
scorer and dataset code as the Docker path.

**Telemetry (`observability/vm-telemetry.ts`).** Reads the last N lines of
`/var/log/apache2/{access,error}.log`, `postgresql-*-main.log` and
`/var/log/audit/audit.log` over the run's SSH endpoint, normalizes
Apache/PostgreSQL through the existing Docker parser (so the same Sigma
rules apply) and parses audit USER messages separately. Apache/Postgres
timestamps are parsed; a bare Apache child-process line has no timestamp,
so it is kept only when it carries this exercise's red marker — otherwise
an older gate-proof line would look like fresh activity. Only
marker-bearing lines are labelled red; everything else is noise (guests
are unbridged, so source-address attribution cannot separate red from
persona traffic yet).

**Exercise (`exercise/vm-live.ts`).** Scripted red runs inside the guest
(web command injection; DB weak-credential read of `secrets` with a marker
comment), persona noise runs a benign HTTP request and employee count, and
blue sees only the collected stream, detecting via the promoted Sigma pack.
The window starts after a 2 s settle, second-aligned, so configure seeds
and gate-proof lines cannot enter blue's benign set. Scoring, FP
measurement and dataset export are the shared code paths; `live-vm` is the
recorded mode.

**Weak-credential proof and DB profile.** PostgreSQL now runs with
`log_statement=all`, `log_connections=on` and an attributable
`log_line_prefix`; `pg_hba` allows the app user over TCP only with
`scram-sha-256` (local traffic stays trusted for role tasks). When the
spec plants `weak-cred`, the app role gets the canonical weak password;
the proof authenticates over TCP and only counts when the statement line
appears in the postgres log. Other vuln types still fail closed.

**Deployability.** VM specs are no longer blanket-blocked. Precise rules:
objectives need a web or db asset, and planted vulns must be
web→code-flaw or db→weak-cred; other roles/types are rejected with the
reason. The designer catalog text now describes VM labs as deployable but
scripted-only (model-driven agents are still not wired for VMs).

**Live evidence (HVF, baked image).** `scripts/vm-exercise-smoke.mjs`, two
guests: configure ok (web 5, db 7), readiness PASS (http-2xx,
sql-select), canary PASS on both hosts, proof PASS for T1059 and T1078,
scripted exercise 2/2 objectives (20/20 points), 2 alerts, 0 false
positives over 107 benign events, dataset export
`sha256:361459f00de955196ebd29c7303f2d5b4ffeaa41a1c371295213ae958649b465`
(6 steps) verified, clean teardown. Backend 77/77.

Real finding: the first run measured 3 false positives because the
60-second pre-window included the DB seed statements (`CREATE TABLE
secrets`, `INSERT INTO secrets`) and the gate's proof request; the
second-aligned post-gate window plus dropping `arena-proof-` lines fixed
it (2 alerts, 0 FP).

**Not claimed.** Block IP is recorded but **unenforced**: same-host dev
traffic has no lab source address to drop, and isolate/tap needs T-15
bridges. The smoke drove the same activities directly; a full
Temporal/Pulumi/Supabase workflow run on VMs is not yet exercised.
Model-driven red/blue on VMs remains T-19, and cross-host DNS/DHCP proofs
remain T-15.

## 2026-10-28 — T-20: clinic org demo, offline replay, VM runbook; dhcp fails closed

**Demo (`backend/scripts/org-demo.mjs`).** One command runs the 12-person
clinic: a six-guest org (gateway/DNS, directory/LDAP, mail/SMTP+IMAP,
intranet/Apache-PHP, patient DB/PostgreSQL, log collector/rsyslog) with eight
personas and two weaknesses (web command injection T1059, db weak credential
T1078). The fixed-seed spec goes through the same `validateDesign`,
`checkBudget` and `deployability` gates as a model design, then deploy →
Ansible over SSH → readiness → canaries + proof → scripted red/blue → verified
dataset → teardown, one exit code. `--prompt` runs the designer model instead
when `META_API_KEY` is set; that branch is not verified.

**Recorded artifact + page.** Each run writes
`captures/org-demo/<runId>/{run.json,dataset.json,index.html}` (also on
failure, with `run.json.error`). `index.html` is self-contained and shows the
topology, every readiness probe with its detail, the gate results, the score
and the timeline.

**Offline replay (`backend/scripts/org-demo-replay.mjs`).** Reads a recorded
run with no VM, network or model: re-verifies the dataset's own content hash
and re-scores the recorded trace against the recorded spec, then asserts the
result matches the live score. Any drift exits non-zero.

**Live evidence (HVF, baked image, two consecutive runs).** 6/6 guests
SSH-ready at ~16s; configure all hosts ok (~104s); 13/13 readiness probes PASS
(ssh-login ×6, http-2xx, sql-select, dns-query, ldap-bind, smtp+imap
roundtrip ×2, tcp); 6/6 canaries + both proofs PASS; exercise 2/2 objectives,
20/20 points, 2 alerts, 0 false positives over 153 and 152 benign events;
6-step datasets `sha256:df6e984c104c9b2f…` and `sha256:6bed156027ab8f88…`;
110s end to end each; clean teardown, no leaked QEMU. Replay reproduced both
scores offline.

**Fail-closed fix.** `dhcp` was in the service catalog with a `dhcp-lease`
probe but no task group — a design declaring it passed `deployability` and
then failed readiness. `deployability` now rejects it with the reason (no
range is written; guests are unbridged with no clients), and the capability
text no longer says "dns+dhcp configured". Backend 78/78.

**Docs.** RUNBOOK gained a VM-labs failure-mode table (boot/identity/image,
readiness, per-host configure, sensor blindness, rsyslog 514, leaked QEMU,
un-swept taps) and the demo/replay commands; the provisioning row no longer
says the VM runtime is blanket-rejected. README documents the demo and its
limits.

**Not claimed.** Model design (`--prompt`) is unverified while Meta
`/v1/responses` returns 403. DHCP, cross-host requests (web→DB, LDAP-backed
mail login, DNS via gateway) and log forwarding still need lab L2 (T-15);
log-01 accepts syslog but no host ships to it. Red is same-host and attributed
by per-objective marker, not source address, so enforcement remains recorded
but unenforced. The demo drives components directly; it is not a
Temporal/Pulumi/Supabase workflow run.

## 2026-10-28 — T-18: the clinic org through the real workflow

The VM path had only ever run component by component. `scripts/vm-workflow.mjs`
now inserts an approved environment + pending deployment for the clinic spec
and lets the worker drive it: trigger claim → CrossGuard preview → Pulumi stack
→ six QEMU guests → configure over SSH → readiness → canaries/proof →
`live-vm` exercise → dataset in Supabase Storage → `runs` score row → the
workflow's own TTL timer teardown. The script verifies each claim from the
database or Storage, not from the process it started.

**Live (HVF, the platform already running).** Deployment `cde7dd82…`: claimed
9s, ready 29s with `gw-01=vm:hvf:gw-01 …` for all six hosts, dataset at 129s,
score 2/2 · 20/20 · 0 FP, stored `export.json` downloaded and its hash
re-verified, `SCORE_COMPUTED` audit detail `mode: live-vm`, TTL destroyed the
guests at 238s, zero leaked QEMU. A first run failed only on the script's own
assertion (`runs.mode` is the run mode `blind`; the executor lives on the audit
row) — the workflow itself had already scored and published, which is what
surfaced the wrong field.

**Spec extraction.** `designer/clinic.ts` now owns the fixed-seed org
(`clinicOrgSpec`, `CLINIC_PROMPT`) because the demo and the workflow run both
need it. Moving it under the type checker immediately found a real defect: the
demo's hand-built `serviceDecls` omitted the required `port`/`readyWhen`, so
the spec was never schema-valid and the trigger would have rejected it. Fixed,
with a test that runs `validatePendingSpec` (schema + deployability) over the
clinic spec so a demo spec can no longer drift away from what the workflow
accepts. Backend 79/79.

**Not claimed.** Langfuse spans: the VM exercise returns `langfuseEvents: 0`,
so VM runs still have no Langfuse trace (container runs do). Enforcement,
model agents and cross-host traffic are unchanged.

## 2026-10-28 — T-18: VM runs join the trace pipeline

The VM exercise returned `langfuseEvents: 0`, so VM runs had no trace while
container runs had one per `run_id` (T-7's contract). `vm-live.ts` now uses the
same `LangfuseSink` + `TeeRecorder` as `live.ts`: one `trace-create` for the
run, one span per red and blue step, flushed at the end of the exercise, and a
failed ingestion throws so a run cannot claim a trace that never arrived. The
`SCORE_COMPUTED` audit detail now carries `langfuseEvents` for VM runs too.

**Live evidence.** `scripts/vm-workflow.mjs`, deployment `108197be…`: claimed
7s, ready 25s, dataset + score at 123s, stored export re-verified,
`mode: live-vm` and `langfuseEvents > 0` on the audit row, **4 spans** read
back from Langfuse for `run-108197be-…`, TTL teardown at 233s, no leaked QEMU.

**Test.** The VM exercise test now runs against a stub ingestion endpoint and
asserts exactly one trace (id = run id), one span per red/blue step, and that
the flush count equals the entries sent — so the trace contract is enforced in
unit tests, not only live. Backend 79/79.

## 2026-10-28 — T-17 (slice 1): org coherence

A spec could be schema-valid, within budget and deployable and still describe
an org that cannot be scored. `designer/coherence.ts` now checks, for specs
that declare structured services:

- **objective proof path** — the objective's asset must declare a service that
  can emit its signal (`exec-marker` → http, `canary-hash` → db); an unknown
  signal fails closed rather than passing unexamined;
- **dependency acyclicity** — `dependsOn` must be a DAG, with the cycle printed;
- **persona reachability** — a persona's workstation must resolve at least one
  client tool, i.e. have a `dependsOn` edge to a service host, so it is not a
  machine that can do nothing;
- **placement** — in a multi-subnet topology every instance must name its
  subnet instead of being round-robined silently.

The checks are gated on `serviceDecls`, so container specs keep exactly their
existing validation. They are wired into `validateDesign` (designer, refine,
template versions) and into `validatePendingSpec`, so the Temporal trigger
rejects an incoherent org with `incoherent org: …` before a single guest
boots — previously coherence was only implied by deployability.

**Tests.** Six failing cases (wrong asset, unknown signal, dependency cycle,
isolated workstation, unplaced instances, trigger rejection) plus the clinic
passing both `validateCoherence` and `validateDesign`. Backend 80/80;
workspace typecheck green.

**Not claimed.** This is slice 1 of T-17. Versioned archetypes, the per-role VM
cost model (still a flat $0.42/VM) and archetype/catalog/profile/image version
pinning into the spec digest are not built, and T-17's model acceptance prompt
remains untestable while Meta `/v1/responses` returns 403.

## 2026-10-28 — T-16: VM drift observed from the readiness probes

VM deployments reported `drift_status: unobserved` forever: maintenance only
had `observeDockerState`, so an all-VM org never got a drift verdict.
`ops/maintenance.ts::observeVmState` now runs the same readiness probes over
SSH against the run registry and reports a declared service as running only
when its probe answers. A host missing from the registry — or a missing
registry — contributes nothing, so `detectDrift` reports it drifted instead of
assuming in-sync; mixed-runtime specs stay `unobserved` rather than picking an
observer that does not cover every host.

**Live evidence.** `scripts/vm-workflow.mjs`, deployment `264f003b…`: after the
exercise the observer reported
`gw-01=dns dc-01=ldap mail-01=smtp+imap web-01=http db-01=db log-01=log` and
`detectDrift` found zero drift; TTL teardown at 244s, no leaked QEMU.

**The check is not a no-op.** The first attempt observed as soon as the
deployment said `ready` and reported five hosts drifted (dns, ldap, smtp+imap,
db, log missing). That was correct: `ready` means *deployed*, not configured —
`configureActivity` runs after it. The assertion moved to steady state after
the exercise.

**Tests.** An injected-registry test drops the DNS probe on `gw-01` and asserts
only that service drifts; a host absent from the registry and a missing
registry both yield drift, not in-sync. Backend 81/81.

**Not claimed.** Cross-host proofs and DHCP still need lab L2 (T-15). Drift
still observes only declared services; packages/files are not compared.

## 2026-10-28 — T-18/T-19: failed SSH authentication on every guest (T1110)

Red only ever acted on `web` and `db`, so the gateway, directory, mail and log
hosts produced telemetry nothing could detect. Credential guessing is now a
first-class technique on any Linux guest:

- **Collection** — `vm-telemetry` reads `/var/log/auth.log` and parses sshd
  `Invalid user` / `Failed <method> for …` lines into `auth.login.failed`
  events. syslog has no year, so the timestamp is anchored to the host clock
  (a December line read in January belongs to the previous year).
- **Detection** — `detections/ssh_failed_auth.yml` (T1110, medium) is promoted
  from the checked-in `detections/replay/vm-auth-v1.jsonl`, so it ships as a
  promoted rule rather than a draft. The engine matches per event, so a burst
  produces one alert per attempt (5 attempts → 5 alerts); scoring dedupes to
  one blue step per host+technique.
- **Red** — five real failed publickey logins against the guest's own sshd,
  with the per-objective marker as the *username*. No new package is needed,
  and attribution comes from sshd's own log line, not from anything red prints.
  The marker keeps its exact case: lowercasing it broke the case-sensitive
  marker match (caught by the unit test before it reached a guest).
- **Deployability/coherence** — a T1110 objective is allowed on any VM role
  (sshd is in the base profile); `auth-failures` is a known success signal that
  needs no declared service. Web/db role restrictions are unchanged.

**Live.** `scripts/org-demo.mjs`, clinic with a third objective on `dc-01`:
6/6 guests, 13/13 probes PASS, 6/6 canaries + proof PASS, **3/3 objectives,
30/30 points, 7 alerts, 0 false positives**, dataset `sha256:89023c9f…`
(13 steps: 5 red auth failures + 3 objectives + 3 blue detections + 2 other
ground-truth rows), 113s, clean teardown.

**Tests.** sshd line parsing and red attribution; a one-host T1110 exercise
that scores end-to-end through the promoted pack; the pack test now reads
every replay corpus (as `livePack` does) instead of only `calibration-v1`.
Backend 82/82.

**Workflow path (same day).** `scripts/vm-workflow.mjs`, deployment
`8ac3323c…`: pending row → claimed 7s → ready 31s → **3/3 objectives, 30/30**
→ stored dataset re-verified (13 steps) → 6 Langfuse spans → drift in-sync on
all six hosts → TTL teardown at 237s, no leaked QEMU. So the trigger's
`validatePendingSpec` accepts the T1110 objective on a directory host and the
whole loop scores it.

**Not claimed.** The rule detects an *attempt* (one event), not a burst
threshold — the Sigma engine has no aggregation. Cross-host SSH (attacking
another guest's sshd) still needs T-15.

## 2026-10-28 — T-17 (slice 2): clinic archetype, per-role cost, pinned digest

The clinic was a hand-written function. It is now an archetype (`clinic@1`)
whose hosts, services, dependencies, personas, objectives and weakness slots
are data; `materializeArchetype` is a pure function, so the same archetype
version always produces the same spec and digest. `clinicOrgSpec` is a thin
alias, the designer prompt lists the archetype catalog, and `designPin` +
`pinnedDesignDigest` hash the archetype/catalog/profile/image versions
together with the spec.

`designer/cost.ts` now estimates per role (gateway $0.26, dc $0.32, mail
$0.34, web $0.44, db $0.52, sensor $0.24, workstation $0.30, attacker $0.40;
unknown roles fall back to $0.42) instead of charging every guest web-tier
rates. The clinic estimates at $2.76/hr, inside the $5 cap.

**Live.** `scripts/org-demo.mjs` on the materialised archetype: 6/6 guests,
13/13 probes PASS, 6/6 canaries + proof PASS, 3/3 objectives, 30/30 points,
7 alerts, 0 false positives, 13-step dataset `sha256:d8b2fd70…`, 114s, clean
teardown. The artifact records
`pin: clinic@1 · arena-catalog-1 · arena-profile-1 ·
arena-golden-debian12-catalog-1`, and the dataset's `run.specDigest` is the
pinned digest (`sha256:33a2dd77…`), verified to differ from the bare spec
digest and to re-verify offline.

**Not claimed.** `runRecordFor` (the trigger path) still writes the bare spec
digest: a spec carries no archetype provenance, so pinning there needs either
an archetype field on the spec (a schema and digest change) or the pin stored
on the environment row. The design is pinned end-to-end only for the demo and
the datasets it exports. Backend 84/84.

## 2026-10-28 — T-18/T-14: sensor-disabled VM fails the gate, live

The last T-18 acceptance clause was unit-only. `scripts/vm-gates-smoke.mjs
--blind-sensor` now proves it on a real guest: configure the web host, pass
the canary and the code-flaw proof, then `systemctl stop auditd` and run the
canary again. It returns
`canary canary-run-vm-gates-… MISSING from telemetry — sensor blind`, the
script asserts the failure is the fail-closed one (not an execution error),
and the run tears down with no leaked QEMU. Proving it on a guest that was
healthy seconds earlier matters: a canary that always fails would prove
nothing.

Also fixed five stale status claims found by the audit: T-9 test count (46 →
84), T-12 pack counts (3 promoted → 5 rules / 4 promoted), T-7 scope
(container + VM), T-6 VM configuration (done), and T-14 auditd/osquery (met on
VM labs; sinkhole still absent). The audit's sixth drift item was wrong — the
container-era agent numbers live under T-8/T-19 — and is corrected in place.

## 2026-10-28 — T-14: benign-only control run on the VM runtime

The detector pack had no VM false-positive baseline, and the new SSH rule added
auth traffic to the stream. `scripts/vm-control-smoke.mjs` deploys and
configures the clinic, passes readiness and the gates, then runs the exercise
with red disabled: blue still sees the whole collected stream — persona noise,
configure artifacts, the guests' own auth chatter — so every alert would be a
false positive by construction.

**Live.** Six guests, 13/13 probes PASS, canaries + proof PASS, **134 benign
events, 0 alerts, 0 false positives**, control scorecard 0/3 by definition,
clean teardown. This is the VM counterpart of `control-run.mjs` and the
baseline the T1110 rule is measured against.

## 2026-10-29 — Meta access restored: the model designer path runs live

The account-wide `403 user_blocked` lifted. `/v1/models` and `/v1/responses`
both return 200 again, so the model-authored path was re-verified rather than
assumed. Three real defects surfaced and were fixed:

1. **Output budget starved by reasoning tokens.** `designEnvironment` asked for
   8192 output tokens; the API counts reasoning against that budget, the model
   spent it thinking, and the reply contained no message at all
   (`status: incomplete, reason: max_output_tokens`). Raised to 32768 for design
   and refine, with a regression test asserting the request budget.
2. **Malformed model JSON was fatal.** A truncated object aborted the design
   with a raw `JSON.parse` error. `generateObjectRepairing` now makes exactly
   one repair attempt, quoting the rejection back to the model; a second
   failure fails the design.
3. **The model chose 4 GiB disks under a 6 GiB catalog image.** qcow2 truncates
   the backing image's partition table, and the guest drops to initramfs
   (`PARTUUID … does not exist`) — after a 7-minute SSH retry loop. Rejected at
   design time (`diskGb < MIN_VM_DISK_GB` with a named reason) and again before
   creating a smaller overlay, so no path can boot a truncated guest.

Also: coherence now keys the proof path off the objective's *technique*
(T1059→http, T1078→db, T1110→any guest) instead of matching signal text, which
models invent (`exec-marker:web-01:pwned`); the designer prompt states the VM
placement rules and the 6 GB minimum; `org-demo.mjs` loads `../.env` so
`--prompt` works from a clean shell; readiness no longer runs `ssh-login` twice
when a host declares ssh itself.

**Live.** `node scripts/org-demo.mjs --prompt "12-person clinic: …"`: model
design in 44.9s → 7 guests → configure all ok → readiness PASS → 7/7 canaries
+ proof PASS → **3/3 objectives, 250/250 points, 7 alerts, 0 false positives**
→ dataset `sha256:89b5349b…` (13 steps) → clean teardown; 215s total.

**Not claimed.** One model design, not a sweep: model output is not
deterministic, and a prompt can still produce a spec the gates reject (the
block reasons are the honest outcome). T-19 is *not* unblocked in practice:
model agents are wired for containers only, so org-lab model runs still need
the VM agent adapter.

**Refusal acceptance (same day).** Two benign prompts through the real
designer: `Windows DC` → valid, deployable 6-host spec in 42.2s (the model
follows the prompt's guidance and emits a Linux directory instead of Windows,
so the image block is not triggered); `20 workstations` with a 4-instance /
$1/hr cap → `canProvision=false` in 23.3s with
`estimated $1.9/hr > cap $1/hr`. Both inside the 2-minute acceptance.

## 2026-10-29 — Status reconciliation after the model designer run

No code changed in this entry; it brings the written status in line with what
the last three runs actually showed.

- **Test count.** `backend npm test` is **87/87** (was recorded as 84).
- **T-8 / T-19.** The `403 user_blocked` is gone, so the *Meta* blocker is
  closed — but the VM blocker is not the same thing. `exerciseActivity` still
  sends every all-VM spec to `runVmExercise` (the scripted loop); `agents-live`
  is Docker-only (attacker container, `collectTelemetry`, container
  enforcement). No model agent has run against an org lab.
- **T-20.** The `--prompt` branch is no longer unverified: model design →
  7 hosts → readiness → gates → 3/3 · 250/250 → 13-step dataset
  (`sha256:89b5349b…`), 215s, clean teardown. One design is one sample; a
  prompt can still produce a spec the gates refuse, and that refusal is the
  honest outcome.
- **T-4** moves to fully met in the audit (valid deployable spec in 42.2s;
  over-budget refused in 23.3s).
- `audit-2026-10-28.md` rows for T-4 / T-8 / T-19 / T-20 updated; the two
  "buildable next" items it listed (live blind-sensor, doc drift) are struck
  as done.

### T-19 decision record (still open)

Model agents on org labs need a transport, and each option trades realism for
availability:

1. **Per-target exec through the management plane** — buildable now. Red's
   `exec` would SSH to the objective's guest as the same user the configurer
   uses. Two problems found while scoping it: that user can read the
   platform's own proof material on the host (the container path plants the
   proof where the attacker *cannot* reach it), and the transport is not one a
   real adversary holds. Acceptable only with an explicit
   `transport: management-plane` stamp in the score audit, and only after the
   proof is re-homed so the transport user cannot read it.
2. **Add an attacker VM to the archetype, wait for T-15** — honest transport,
   but without an L2 bridge the attacker VM can only reach its own host, so
   the run proves nothing about multi-host paths.
3. **Leave T-19 model-on-VM until T-15** — no new code.

Recommendation unchanged: 3. Option 1 is now known to need proof re-homing in
addition to the stamp, which is a bigger change than it looked.

## 2026-10-29 — T-15/T-16: the org lab has a real L2 segment

No guest could reach another, so every cross-host claim in the spec was
unprovable on this host. That is gone.

**Transport.** Each guest gets a second NIC on a per-run segment. On macOS the
segment is a user-space hub (`provisioner/lab-hub.ts`, one detached process per
run, pid in `vms.json`): QEMU's `socket` netdev already frames Ethernet over
TCP, so the hub just relays frames between the guests that connect to it.
Bridge/tap needs privileges we do not have, and host multicast — the first
attempt — binds but delivers nothing between guests here. On a Linux
reference host the same contract can be a real bridge; the guest side does not
change.

**Addressing.** `provisioner/lab-network.ts` is pure: gateway `.1`, others
`.10` upward from the spec subnet, deterministic MACs, deterministic hub port
(45000–60000, clear of the SSH hostfwd range). The lab NIC gets its address
from cloud-init's final stage and has **no default route**, so the management
NIC keeps user-net DHCP and apt keeps working. The management NIC is now
matched by MAC instead of `en*` — otherwise the base netplan would also try
DHCP on the lab NIC and stall.

**Two real defects found live, both fixed:**
1. The lab address was applied with an `awk` program quoted inside the shell,
   so the shell expanded `$2` to empty and `awk` printed the whole line
   (`Cannot find device "3: enp0s2: <BROADCAST..."`). The seed now resolves the
   NIC by MAC through `/sys/class/net`.
2. A failed start could leak the hub: the registry is written per guest, so a
   failure on the first guest left nothing for `destroyRunVms` to read. The
   registry is now written before the guests start, and the catch kills the hub
   in memory as well.

**Cross-host proofs (T-16).** Services now bind the lab address as well as
loopback: dnsmasq (`listen-address` + a `host-record` per guest, bare and
`.arena.lab`), Postgres (`listen_addresses` + a pg_hba line for the lab subnet;
needs a restart, not a reload), Postfix (`inet_interfaces`) and Dovecot
(`listen`). Readiness adds checks that run on a *client* guest against another
guest, so a miss fails the gate: lab-dns, lab-http, lab-smtp, lab-ldap,
lab-tcp.

**Live.** `scripts/vm-l2-smoke.mjs`: 3 guests, 6/6 directed TCP pairs,
clean teardown, no leaked QEMU or hub. `node scripts/org-demo.mjs`: 6 guests,
13/13 local probes PASS, cross-host lab-dns 5/5 + lab-http + lab-smtp +
lab-ldap + lab-tcp PASS, 6/6 canaries + proof PASS, 3/3 objectives · 30/30,
7 alerts, 0 FP, 13-step dataset `sha256:b7bfbb74…`, clean teardown. 87/87 unit
tests.

**Not claimed.** `accel=kvm`, real bridges/taps, and the ≤8-VM no-orphan-tap
clauses on a reference Linux host; DHCP on the lab segment (addresses are
static); Dovecot LDAP-backed login; a cross-host SQL *read* (only the TCP port
is proven); log forwarding to the sensor (`base-log-shipping` is declared with
no task); egress control — the management NIC still has NAT, so "no internet"
is not true yet; and enforcement — `isolate host` / `block IP` still record as
unenforced because there is no attacker source address.

## 2026-10-29 — T-18: red from a peer, and containment that happens

The scripted VM exercise used to run red on the machine it attacked, because
no guest could reach another. Now that they can, an opt-in attacker guest
(`clinicOrgSpecWithAttacker`) runs every action over the segment. Nothing about
the default clinic changes: it stays six hosts, and its pinned digest with it.

Two things the same-host design had been hiding showed up immediately:

1. **Attribution was marker-only.** The attacker's own session lines — the
   postgres `connection authorized`, the SSH logon — carry no objective
   marker, so they were scored as persona noise and the T1078 rule raised them
   as *false positives*. A line is now red when it carries the marker **or**
   its client address is a declared red source. Both are properties of the log
   line, never of the actor's claims. The default clinic keeps marker
   attribution (it has no attacker guest) and still scores 0 FP.
2. **`block IP` was decoration.** It was recorded as "audited, unenforced —
   no lab source address" because there was no peer to block. With a peer it
   is applied on the guest and **read back**: `iptables -S INPUT` must contain
   the rule before the response counts as enforced. The base profile now
   installs `iptables` (profile version bumped to `arena-profile-2`), and the
   probe uses `/usr/sbin` paths because the SSH user's `PATH` has no sbin —
   the first live run reported "no firewall tool" for that reason.

Also fixed: the alert-to-event lookup could pick a persona event in the same
second and conclude "no peer address"; it now prefers the red event at that
instant.

**Live.** `vm-exercise-smoke` with the attacker: 3 guests, 3 alerts, **0 false
positives**, `block IP -> 10.2.32.12 enforced=true` on web-01 and db-01, 2/2 ·
20/20, 8-step dataset, clean teardown. Default clinic unchanged: 3/3 · 30/30,
7 alerts, 0 FP. Control run: 132 benign events, 0 alerts. 87/87 unit tests.

**Not claimed.** `isolate host` is still unenforced (only `block IP` has an
implementation); enforcement is per-host iptables on a guest, not a network
device. Model agents are still container-only — but the attacker guest is now
the transport they need, so T-19 no longer requires a management-plane
shortcut.

## 2026-10-29 — T-4: the designer designs for the worker it runs on

The designer received a static capability catalog, so it could design a VM org
lab for a worker that cannot boot guests — and the mismatch only surfaced at
deploy time as a refusal. The worker is now probed before the prompt is built.

`provisioner/host-capabilities.ts` reports platform, agent arch, guest arch,
acceleration, whether the baked catalog image is staged, whether docker is
present, the lab instance limit, and the truth-layer cap (always `mirror-only`
— KVM is not VMI). `hostBrief()` turns it into prompt text plus the rule it
implies: VM org labs when guests can boot, container labs when they cannot.
The brief is prepended to both the design and refine system prompts and is
computed per call, not at module load.

`deployability()` now takes the same capabilities and refuses a design the
worker cannot run: VM guests without KVM/hvf, container labs without docker,
`kvm-vmi` on a non-KVM host, more instances than the lab limit. It fails at
design time with a named reason instead of at deploy time.

**Live.** On this worker the brief reads `darwin/arm64, guest arch aarch64,
hvf, baked image staged, container available, mirror-only`. A design-only run
against Meta with the new prompt returned a 6-host VM org lab in 39.5s
(`gw-01` dir, `dir-01` dc, `mail-01`, `web-01`, `db-01`, `log-01`) — the shape
this host can actually build. It was refused by a coherence rule because the
model put a persona on `gw-01` without a client-tools dependency, which is the
designer being honest; that refusal is unrelated to host capability.

**Not claimed.** The brief describes the *worker process's* host — a remote
deploy target is not probed. Instance-limit and docker checks are advisories
for the designer and hard gates in `deployability`, not runtime enforcement.
88/88 unit tests.

## 2026-10-29 — T-4: the model is told why its design was refused

`generateObjectRepairing` retried malformed JSON once, but a design that parsed
and matched the schema and was then refused by the coherence or budget gate
ended the run with no feedback to the model at all. That is the failure the
host-brief run surfaced: a persona on the gateway, refused for having no client
tools, with no second chance.

`finishDesign` now applies the same bounded rule to semantic refusals: quote
the named violations once and accept the result. Three properties are asserted
in the test rather than assumed:

- one attempt only — a model that never fixes it is called twice, not looped;
- a repair that is malformed, throws, or is refused again leaves the *original*
  design and its violations intact, and does not set `repaired`;
- a repair that passes is stamped `repaired: true` so the run record can say
  the design took two attempts.

**Live.** The same clinic prompt that previously ended `canProvision=false`
now returns a deployable 8-host spec first try in 33.2s (`gw-01` gateway,
`dc-01` dc, `mail-01` mail, `web-01` web, `db-01` db, `log-01` sensor,
`ws-01`/`ws-02` workstations), so the retry fires only when needed. 89/89 unit
tests.

**Not claimed.** The repair is one attempt by design; a prompt that
systematically produces a refused shape will still be refused, and the named
violations remain the honest output. Model output stays non-deterministic —
this run and the previous one produced different, both-valid orgs.

## 2026-10-29 — T-18: isolate host, and no unverified containment

`block IP` was enforced once red had a peer address, but a same-host alert had
none, so the response was recorded and nothing happened. `isolate host` now
takes the guest off the lab segment: the lab NIC (resolved by MAC through
`/sys/class/net`) goes down, the management NIC stays up so telemetry
collection and teardown still work, and `ip -o link show` has to report
`state DOWN` before the response counts as enforced.

The scripted response chooses by situation: a lab peer source is blocked by
address; with no peer the host is isolated. `org-demo` now prints every
response and **fails if none was enforced**, so "contained" cannot be an
unverified claim in the demo artifact.

**Live.** Default clinic: `isolate host enforced=true` on db-01, web-01 and
dc-01, 3/3 · 30/30, 7 alerts, 0 FP, 13-step dataset `sha256:41b6977c…`.
Attacker run: `block IP -> 10.2.32.12 enforced=true` on web-01 and db-01, 2/2 ·
20/20, 0 FP. 89/89 unit tests, clean teardown both times.

**Not claimed.** Enforcement is a guest-local action (iptables rule / link
state), not a network-device change; `kill process tree`, `disable account` and
`snapshot` remain allowlisted-but-unimplemented and are never recorded as
enforced.

## 2026-10-29 — T-16: log shipping, and the fail-open it hid

`base-log-shipping` was a declared profile group with no task, so "logs at the
sensor" had never been true. Every guest now writes
`/etc/rsyslog.d/40-arena-forward.conf` pointing at the collector's lab address;
the collector's existing `imtcp` input writes what arrives to
`/var/log/arena/remote.log`.

The first live attempt failed, and the reason matters: the sender began
forwarding before the collector's rsyslog was listening, `omfwd` suspended the
action after one refusal (`action 'action-0-builtin:omfwd' suspended ... next
retry in 30s`), and messages sent in that window were dropped. A plain `@@`
action is fail-open in exactly the way this repo is not supposed to be. The
forward is now a queued action with `action.resumeRetryCount="-1"` and a 2s
retry interval, so configuration order no longer decides whether logs arrive.

Readiness adds `lab-log`: log a marker on one guest, then poll the collector's
own file for it — the one proof that cannot be faked on a single host.

**Live.** Clinic: `lab-log=PASS`, 3/3 · 30/30, 7 alerts, 0 FP, responses
enforced on db-01/web-01/dc-01, dataset `sha256:acb3740f…`. Six-host config
smoke: `log written on web-01 reached log-01`. Control run: 132 benign events,
0 alerts. 89/89 unit tests.

**Not claimed.** Logs are forwarded over TCP to one collector; there is no
local disk buffer (`queue.type="linkedList"` only), so a collector that stays
down longer than the queue costs messages. DHCP, Dovecot-via-LDAP, and a
cross-host SQL *read* remain unimplemented.

## 2026-10-29 — T-19: model agents on the org lab

The agent loops were Docker-only in three places: red's `exec` ran in an
attacker container, blue's `fetch_telemetry` read `docker logs`, and a
confirmed response disconnected a container from the run network. All three
are now injectable, and `exercise/vm-agents.ts` supplies the VM versions:

- **red** runs its argv on the attacker guest over the management plane — the
  same transport a foothold on a peer gives, not one that reaches into the
  target. ROE's host check accepts the lab addresses so `-h 10.2.32.x` is a
  known host, not an escape.
- **blue** pages the collected VM telemetry (the same rows the rules scored),
  with `src`/`user` lifted out of `detail` so `block IP` can cite a peer.
- **enforcement** reuses `blockPeer`/`isolateHost`, read back before it counts.

Proofs are planted before the window opens: the db objective's row in
`secrets`, and a file outside the docroot owned by `root:www-data` mode 640 —
the injected command runs as www-data, the attacker user cannot read it.

**Live** (`MUSEARENA_AGENT_RUNTIME=maas`, muse-spark-1.3, 20-step red budget,
3 guests incl. attacker): red solved the db weak-credential objective
(1/2 · 10/20) and did not find the web injection in 20 steps; blue read the
collected stream, proposed `block IP` on db-01 citing 10.2.32.12, and the rule
confirmed it — **enforced=true**. 1 alert, 0 FP, 0 guardrail rejections,
156-step dataset `sha256:213463d7…`, clean teardown.

**Not claimed.** The Temporal path is wired (`agents-maas-vm`, transport
`lab-attacker-guest`) but only the direct smoke has run; no per-model sweep;
the web objective remains unsolved by the model within budget, which is a red
capability result, not a harness failure.

## 2026-10-30 — Meta 403 is back; the Temporal agent path stays unverified

Tried to close the last T-19 gap (the same agent loop through Temporal rather
than the direct smoke), with a new `vm-workflow.mjs --agents` mode.

**What worked.** The mode deploys the clinic plus the attacker guest through the
real workflow: 7 guests, `ready` in 31s, each stamped `vm:hvf:<host>`.

**What failed, and why it is not code.** The exercise activity died on the
first model call:

```
Meta Model API 403: {"error":{"code":"user_blocked","message":"Your access has
been restricted due to repeated policy violations.","type":"permission_error"}}
```

Re-probed directly: `GET /v1/models` → 200, `POST /v1/responses` → 403
`user_blocked`. That is the same account-wide pattern as 2026-10-27, now
explicitly citing policy. The direct smoke earlier the same day succeeded, so
the restriction returned mid-session; no platform code can work around it.

**State.** `agents-maas-vm` dispatch and the `--agents` script are committed and
typechecked; the direct three-guest agent run (`sha256:213463d7…`, 1/2, block
IP enforced) stands as the T-19 evidence. The Temporal leg, the per-model
sweep, and the unsolved web objective remain open, now blocked on access rather
than on design.

**Housekeeping.** No leaked QEMU or lab hubs after the failed run; the worker
was stopped; the deployment was torn down.

## 2026-10-30 — The deployment row now tells the truth

A run that failed in the exercise leg was reported as `timeout waiting for
dataset in Storage` while the worker log held a 403. The row had ended
`destroyed` with `access_info: {}`: teardown overwrote both the failure and the
outputs. That is worse than a wrong status — it hides the next failure.

**What changed.**

- `provisioner/deployment-status.ts`: status writes merge `access_info` instead
  of replacing it; failures are `{stage, error, at}`; `needsCleanup()` decides
  whether the TTL sweep must retry a row (`failed` + `resourcesDestroyed:true`
  is done; `destroying` is retried).
- `deploy.ts` no longer writes `ready` after boot. It records the stack and
  rollback outcome; `ready` is written only by `exerciseActivity` after
  configure, readiness, gates and scoring have passed.
- `configureActivity` → `configuring`, `readinessActivity` / `proofActivity` →
  `verifying`, `exerciseActivity` → `exercising` → `ready`. The four states
  that existed in the shared enum but were never written are now real.
- `teardownEnvironment` takes an outcome: `failed` on a failed run, `destroyed`
  on a clean TTL end, and it never clears `access_info`. A teardown that throws
  records itself as `failed` + `resourcesDestroyed:false` and rethrows, so the
  TTL sweep retries it. A second teardown of an already-clean row is a no-op.
- `maintenancePass` isolates per-deployment TTL and drift errors and returns
  them; the hourly workflow contains a failed pass instead of dying.
- The trigger compensates a claimed-but-not-started deployment.
- TTL is a deadline from deployment start (`workflowInfo().startTime`), with a
  10-minute grace while a run is actively working, so the workflow timer and
  the hourly sweep no longer tear the same environment down twice.
- Environment stacks share one persisted passphrase
  (`$PULUMI_STATE_DIR/passphrase`, 0600). The smoke's `/tmp` passphrase
  override was removed: it created stacks the worker could not decrypt, which
  is why a destroy reported `incorrect passphrase` after its resources were
  already gone.

**Verified live.**

- Scripted workflow: `ready` at 132s (after scoring), 3/3 · 30/30 · `live-vm`,
  stored dataset re-verified (13 steps), 6 Langfuse spans, drift in-sync, TTL
  teardown with no leaked QEMU.
- Agent workflow (still 403 `user_blocked`): the script exits with
  `run failed: [exercise] Activity task failed: Meta Model API 403 …`; the row
  is `failed`, `failure.stage = exercise`, the full error preserved,
  `resourcesDestroyed:true`, `destroyedAt` set, and the 7 stack outputs kept.
  No leaked QEMU.
- `npm test`: 92/92, including three lifecycle invariants (merge keeps
  evidence, bounded failure records, cleanup retry matrix).

**Reconciled.** One pre-fix stack (`dev-976848f9`) had history encrypted with
the old smoke passphrase; its state held no resources, so the row was marked
`destroyed` with a reconciliation note. Other stale rows were swept by the new
maintenance pass.

**Not claimed.** `terminate` still runs no cleanup — Temporal kills the
workflow; the TTL sweep (hourly) is the only backstop, and the smoke uses
`cancel`. Multi-subnet topology is still flat/one hub, `firewallRules` are
still decorative, `services[]` display names are still unvalidated, and there
is no `planDeployment` BOM or conformance test yet. The model-agent Temporal
leg remains blocked by the 403, not by this work.

## 2026-10-30 — Topology has one source, and a plan you can refuse

The designer declared a topology, the diagram showed a different placement and
the deployer built a third. Three findings, one fix:

- `topologyFor` assigned subnets round-robin by array index and ignored
  `instances[].subnet`, which `labPlanFor` does honour.
- `generate.ts` returned four fixed generic subnets (`public-a/b`,
  `private-a/b`) for every spec, so a one-subnet clinic advertised four.
- `access_info` stored the allocated `10.x.0.0/16` and `vm:hvf:<host>`, never
  the address a guest actually had; the array output was stringified to
  `"[object Object]"` on the way into the row.

**Now.** VM runs use the design's topology verbatim (their hub is per-run, so
there is nothing to isolate), container runs keep the designed shape inside the
run's allocated `/16` (`remapSubnets` preserves name, zone, third/fourth octet
and prefix), `topologyFor` prefers explicit placement, and `access_info` stores
the design's CIDR plus every guest's lab address. `flattenOutputs` keeps
structured stack outputs instead of stringifying them.

Two design-time refusals replace approximation:

- more than one subnet → `one flat segment` (no routing, no enforced firewall
  rules exist yet);
- a VM `services[]` name with no matching `serviceDecls` → rejected, because
  the host would pass readiness on ssh alone while the UI promised nginx/mysql.
  Base-profile names (ssh, auditd, osquery, rsyslog, chrony) are exempt.

The designer prompt and capability text now say one subnet, display names must
mirror declarations, and VM org labs are deployable (the old "in build /
blocked until the VM gates land" text was stale).

**Verified live.** Clinic through Temporal: ready 130s, 3/3 · 30/30,
13-step dataset, 6 Langfuse spans, drift in-sync, TTL teardown, no leaked
QEMU. Stored row: `cidr 10.2.32.0/20`, `subnets [{clinic-lan, 10.2.32.0/20}]`,
addresses `gw-01 10.2.32.1` … `log-01 10.2.32.14`. Backend 98/98.

**Not claimed.** Multi-subnet routing, firewall enforcement and VRF-style
segmentation are still absent (now refused rather than faked). `firewallRules`
remain declarative strings. The deployment plan/BOM and its conformance test
are the next step; this change only makes the inputs to that plan truthful.

## 2026-10-30 — The design now comes with its plan

The designer declared topology, hosts and services, but everything about the
software — packages, config files, seeds, probes, order, cost — was derived
inside the configurator and never reviewable. `configurator/plan.ts` now
expands a spec into a `DeploymentPlan` using the same resolvers the executor
uses:

- `versions`: catalog, profile and baked-image pins.
- `topology`: environment CIDR, declared subnets, every guest's lab address.
- `hosts[]`: role/os/resources, packages, units, client tools, config paths and
  purposes, seeds, readiness probes, and the exact task names Ansible will run.
- `edges[]`: declared `dependsOn` service consumption plus implicit log
  shipping, each with protocol, port and peer address.
- `steps[]`: the execution order, phase-labelled.
- `totals`: instances, vCPU, memory, disk and the existing $/hr estimate.
- `gaps[]`: anything that cannot be expanded (unknown catalog impl, no subnet,
  a package outside the image set). `canProvision` now includes these.

`orchestrateDesign`/`orchestrateRefine` return the plan in the package, so the
`/design` endpoint serves it without a new route. `org-demo` writes
`plan.json` next to `run.json` and fails if the plan has gaps.

**Conformance tests** (`test/plan.test.mjs`) pin the plan to the executor:
each host's task list equals `tasksFor` and the playbook's task list, in order;
every package is in `allProvisionablePackages()`; every declared service is
represented by config, a seed or a probe; edges carry the planned addresses;
an unknown impl is a gap, not a silent omission.

**Live.** Clinic `plan.json`: 6 hosts, 21 distinct packages, 9 edges, 34 steps,
$2.76/hr, no gaps; the demo still scores 3/3 · 30/30 with 0 FP and a clean
teardown. Backend 105/105.

**Not claimed.** The console does not render the plan yet. Config paths and
purposes are review metadata; execution remains `tasksFor`, and the
conformance test is what keeps them equal. Only the fixed-seed plan has been
produced end to end — the model design path cannot be exercised while the API
returns 403.

## 2026-10-30 — Leaks and permanent errors are handled, not retried

Two failure modes were still theoretical: a QEMU guest whose deployment row
says destroyed (the Docker sweeper cannot see it), and a 403 from the model API
retried as if it were transient.

**VM orphan sweep.** `ops/maintenance.ts::sweepVmOrphans` walks the guest
registries (`listVmRuns`, previously used only by tests) and destroys a run
when its deployment row is absent, `destroyed`, or `failed` with
`resourcesDestroyed:true`. A 30-minute minimum age protects a debug run that
has no row yet but is still in use. The reason policy is a pure function
(`vmOrphanReason`) and the maintenance report carries `vmOrphans`. Verified
directly: a synthetic registry with a dead pid and an hour-old start was
removed, directory included, reason `no deployment row`.

**Permanent model errors.** `MetaModelClient` now throws `PermanentModelError`
for 401/403/404; 5xx and 429 stay ordinary errors. The workflow uses a
dedicated proxy for `exerciseActivity` with
`nonRetryableErrorTypes: ["PermanentModelError"]`. Verified against the real
403: Temporal history shows **one** `exerciseActivity` start (previously two)
and the failure carries `applicationFailureInfo.type = PermanentModelError`.
The run's row is `failed` with the 403 and `resourcesDestroyed:true`; no
leaked QEMU.

**Not claimed.** CIDR allocation is still read-then-write (`deploy.ts` reads
active octets, then writes), so two deployments starting in the same instant
can pick the same /16; making it atomic needs a DB-level claim (or a unique
constraint) and is not done. A retried `deployActivity` is also not resumable:
once guests are up, `startRunVms` refuses live pids and the rollback destroys
the run — it fails safe, but a transient post-boot error is not recovered.
`terminate` still runs no workflow cleanup (the hourly sweeper is the
backstop). `firewallRules` remain declarative. Backend 107/107.

## 2026-10-30 — The planner plans from intent, and every deploy passes it

The designer owns the setup: it emits the `EnvironmentSpec` (topology, hosts,
services, dependencies, personas, weaknesses, objectives) and the platform's
deterministic `planDeployment` expands it into packages, units, config, seeds,
steps and acceptance probes. Two places still let the plan and the runtime
disagree.

**Role labels are not intent.** `labPlanFor` found the gateway by
`role === "gateway"` and `labProbesFor` found web/db/dc/mail by role name, but
the designer prompt forbids inventing roles outside the canonical vocabulary
(no `gateway`, no `mail`). A model-authored org therefore never got the
segment's `.1`, and its cross-host DNS/HTTP/SMTP proofs were silently skipped;
two `dc`-labelled hosts could even send the LDAP probe at the wrong host. Both
now resolve from declared services (`dns`, `http`, `db`, `ldap`, `smtp`)
with role as a legacy fallback. `clinic@1` is unchanged (its DNS host also
has role `gateway`); the plan test renames its roles and still gets `.1`,
`lab-dns`, `lab-ldap` and `lab-smtp` on the right hosts.

**The plan is visible and complete.** `DeploymentPlan.labProbes` lists the
cross-host proofs (`from`, `to`, `probe`, `expect`) from the same
`labProbesFor` readiness runs — commands are dropped because they carry the
per-run LDAP secret. The Designer console has a **Plan** tab: totals and
versions, per-host packages/units/config/seeds/acceptance/steps, wiring with
lab addresses, and cross-host acceptance. The console no longer computes
topology/cost client-side (the deleted `specView.ts` still round-robined
subnets), so the artifact pane and the executor read the same package.

**Imports cannot skip the gate.** `validatePendingSpec` now runs
`validateDesign` (objective signals, references, required telemetry, coherence)
and the full plan `gaps` in addition to schema/deployability. A malformed or
too-small CIDR is refused at the trigger (`cannot be planned: …`), not when the
lab plan runs. `POST /design {spec, budget}` (`orchestrateSpec`) validates an
imported JSON without a model call; the console's Import JSON calls it and
renders the real block reasons instead of hard-coding `canProvision: true` and
`digest: "sha256:imported"`.

**Order is planned, not lucky.** `playbookFor` used to run plays in the order
the designer emitted instances, so a model-authored org that listed a consumer
before its dependency relied on waits to cover the gap. `hostOrder()` (Kahn,
stable by spec order) now orders both the playbook and `plan.steps`; the
executor and the reviewed plan share it. The clinic's order is unchanged, and a
reversed clinic still configures `gw-01` before `dc-01`, `dc-01` before
`mail-01`/`web-01`, and `web-01` before `db-01`.

**The approved plan cannot silently change.** The design package now carries
`planDigest` (canonical sha256 over the whole plan). `createDeployment` stores
it in `deployments.access_info.planDigest` — no schema migration — and the
trigger recomputes the plan from the stored spec before claiming:
`validateApprovedPlan()` refuses a missing digest (`no approved plan digest`)
or a different one (`plan changed since approval …`), so a catalog, profile or
image change between review and deploy fails the row at stage `trigger`
instead of installing a different bill of materials. The claim also verifies
`environments.spec_digest` against the stored spec. Harnesses (`e2e`,
`cold-repro`, `smoke`, `vm-workflow`) record the digest like the console.

**Two design lies are now refused.** `validateDesign` rejects duplicate
`hostId`s (the plan and address map silently collapsed them) and, for org
specs, a `requiredTelemetry` entry that neither the base profile nor a declared
service emits (`zeek.conn` on a lab with no Zeek sensor). Base-profile names
(`auditd`/`audit.log`, `osquery`, `rsyslog`, `syslog`, `chrony`, `auth.log`)
and every catalog service's declared telemetry remain accepted.

**DNS is per-environment, not a constant.** The lab hardcoded `arena.lab`, so
every design shared one namespace. `labDomainFor(spec)` now derives
`<slug>-<8hex>.arena.lab` from the environment identity (hosts, services,
topology, personas, weaknesses, objectives; budgets excluded so a TTL change
does not rename the lab), and `ldapBaseFor()` derives the LDAP suffix from it.
dnsmasq records, postfix mailname/destinations, the LDAP seed and DN, the
per-host and cross-host probes, the plan (`topology.domain`) and the topology
map all read the same function; a second spec gets a different domain
everywhere. The clinic is now `clinic-<hash>.arena.lab`, not `arena.lab`.

**Verified.** Backend 120/120 (`npm test`), frontend `tsc` + `vite build`.
New tests: trigger rejects an empty `successSignal`/`requiredTelemetry` and a
non-CIDR/too-small subnet; the plan's lab probes name real hosts and never
carry commands; a role-renamed clinic is planned identically; an imported spec
is digested by content and blocked by the same budget/design gates; a reversed
spec is still configured dependency-first by the plan and the playbook; the
domain is deterministic per spec, changes with the environment, ignores a TTL
change, and appears identically in dnsmasq, LDAP, postfix, probes and the plan.

**Not claimed.** The plan itself is not persisted; its content digest is
stored and the plan is recomputed from the stored spec. A digest mismatch
fails the row, but the executed plan is always the current deterministic
derivation — if a catalog/profile/image change is intentional, re-approve.
`firewallRules` remain declarative and multi-subnet designs are still refused;
DHCP still has no task group; and the model design path remains blocked by the
Meta API 403, so only the fixed-seed plan is live-verified. The per-environment
domain is generated and used by config/probes, but **guests still resolve
through their management resolver** — switching the guest resolver to the
gateway is open and needs a live VM run. No live Temporal run was repeated for
these changes: the trigger gate, plan, digest and domain are pure functions and
are unit-tested; the worker will need a restart to pick up the new trigger.

## 2026-10-30 — FreeIPA is the Linux AD (built, not yet booted)

**Decision.** Windows/AD stays out of scope for now; the deployable directory
is FreeIPA on Debian (389-ds + MIT KDC + integrated DNS + Dogtag), not Samba
AD and not plain slapd. That keeps one Linux image/runtime while giving the
lab a real Kerberos realm, POSIX identities and a DNS hierarchy.

**Added.**
- `ldap/freeipa` catalog entry (`freeipa-server`, `freeipa-server-dns`,
  `freeipa-client`, `krb5-user`; no unit is enabled because the installer
  owns every daemon it starts). `openldap` is untouched.
- Realm identity is derived, not authored: `ipaDomainFor(spec)` =
  `ipa.<lab domain>`, `ipaRealmFor` upper-cases it, and `ipaBaseFor` /
  `ipaAdminDnFor` derive the base DN and `uid=admin,cn=users,cn=accounts,…`.
- Server task: `/etc/hosts` + `hostnamectl` to the lab FQDN, then
  `ipa-server-install --unattended --setup-dns --no-reverse --no-ntp` with
  the lab address, a loopback-safe forwarder and per-run DS/admin secrets.
  Re-runs are skipped when `/etc/ipa/default.conf` exists.
- Members: a host that lists the FreeIPA server in `dependsOn` gets
  `freeipa-client`/`sssd`/`libnss-sss` and an `ipa-client-install
  --mkhomedir` task; a host with no such dependency is never joined.
- DNS hierarchy: the gateway keeps the parent zone local and adds
  `server=/ipa.<domain>/<dc-ip>`; the DC adds a forward zone for the parent
  lab domain back to the gateway.
- Seeding: personas become directory users with one role group each; the
  admin ticket is destroyed after the seed.
- Readiness: a `freeipa` host is probed with the IPA admin DN (not
  `cn=admin,…`), locally and from a peer; the cross-host probe reads the
  same impl to choose DN, base and secret.
- Gates: deployability refuses a FreeIPA server under 2 vCPU / 2048 MB /
  12 GB, a container runtime, `dns`/`dhcp` co-location (port 53), or more
  than one server per environment. The designer prompt now lists FreeIPA as
  the only AD-shaped directory and states the resource/dependency rules.

**Verified.** Backend 130/130 (`npm test`); 10 new tests in
`test/freeipa.test.mjs` cover catalog/profile resolution, realm derivation,
plan config/seeds, the generated install/join/forward commands, the gateway
delegation, probe identities, the resource/co-location refusals, and that the
OpenLDAP path is byte-for-byte unaffected. Commands were decoded and read, not
just asserted to exist.

**Not claimed.** No FreeIPA guest has booted. The staged baked image
(`arena-golden-debian12-catalog-1`) does not contain the freeipa packages, so
the install falls back to `apt-get` over the management NIC — the offline
image story does not hold until the image is rebuilt. Persona passwords are
set through `ipa passwd` over a pipe; that path is unverified. There is no
SPN/HBAC/sudo seeding, no Kerberoast/AD objective or scoring path, and no
replica support. Windows/AD remains blocked. The guest resolver still points
at the management network (open item above), so joined members do not yet use
the planned DNS for the realm.

## 2026-10-30 — Linux-AD system design before any boot

**Design only.** New `system-design-linux-ad.md` is the decision-complete
contract for the bank-shaped, Linux-AD organization: spec v2 (sites, zones,
links, structured firewall policy, derived `/24`s per zone), FreeIPA identity,
the v1 service catalog, per-zone router/nftables enforcement, positive and
negative reachability probes, persona shift runners, red/blue, telemetry,
scoring, lifecycle, capacity and phases P0–P8.

**Locked decisions.** Linux only (FreeIPA, no Windows); static addressing;
one realm/DC in v1; routers enforce a default-deny inter-zone policy; every
allowed edge has a positive probe and every denied pair a negative one; scored
hosts are VMs; no internet egress (packages baked); one derivation for
addresses, names and realms; the generated-task executor stays for v1.

**Open decisions named, not hidden.** Atomic CIDR claim/resume; FreeIPA
installer forwarder without external DNS; Kerberoast feasibility on FreeIPA
(service principals are random-key, so it is not claimed); Samba vs NFS for
files; Gitea vs cgit; non-interactive `ipa passwd`; Zeek placement; multi-site
WAN realization; scale provider; OT protocol choice.

**Nothing was booted and no code was added for the design.** The existing
FreeIPA slice remains unit-tested only (T-21); its install/join commands are
unchanged. The design's phase acceptance is the implementation order: P0 pure
topology, P1 zones + router, P2 FreeIPA live, P3 services, P4 population,
P5 multi-site, P6 scale, P7 OT, P8 network telemetry.

## 2026-10-30 — P0: org topology is derived, not drawn

**Spec v2 is additive.** `EnvironmentSpec` accepts `sites`, `zones`, `links`
and structured `policies`; instances may carry `site`/`zone`; subnets may
carry `site`. Every v1 field keeps its meaning, and the clinic validates and
plans unchanged.

**Derivation.** `designer/org-topology.ts` normalizes any spec to sites,
zones, subnets, placements and endpoints. A zone's subnet is
`10.<env>.<(siteIndex << 4) | zoneIndex>.0/24`; the router owns `.1`, hosts
take `.10+` in host-id order, and the FQDN is `<host>.<site>.<domain>` (the
default single site keeps `<host>.<domain>`). Reordering instances does not
move a host.

**Policy and reachability.** `reachabilityFor` evaluates allow rules, deny
rules (deny wins), WAN links and default deny; it emits one representative
edge per zone pair and service port. `negativeProbesFor` picks one denied pair
per zone pair that has no allowed service path. `validateOrgTopology` refuses
duplicate sites, unknown zone/policy references, contradictory policy,
unplaced hosts, an attacker in a server zone, objectives in an edge zone, and
an objective with no allowed path from the attacker. The plan now carries
sites, zones, policies, org addresses and the allowed/denied graph.

**Fail closed at the runtime boundary.** Deployability refuses any spec with
`sites`/`zones` until P1 creates a segment and router per zone. P0 cannot
produce a half-realized topology; `tasksFor` degrades to loopback when no flat
lab plan exists rather than throwing during plan review.

**Verified.** Backend 135/135 (`npm test`), 5 new tests in
`org-topology.test.mjs`: derivation and determinism, allow/deny/WAN
reachability, a bank-shaped plan with zero gaps, the named refusals, and the
v1 clinic's unchanged addresses and lab probes. Frontend typecheck/build still
pass with the shared schema change.

**Not claimed.** No segment, router, nftables rule or negative probe has run;
sites/zones are refused at deployability. The designer prompt still emits v1
shapes, so the model cannot yet author a bank topology. FreeIPA remains
unit-tested only, with the image and live run still open.

## 2026-10-30 — P1a: the policy compiler

**Catalog.** `router/nftables` is a real service kind: the nftables package,
`ssh-login` readiness, router install/configure/enable groups and
nftables/auth telemetry. A router instance is a role, not a free-text service.

**Segments.** `segmentsFor(spec, runId)` gives every zone subnet one
deterministic hub port (unique per run, outside the SSH hostfwd range). The
same run yields the same ports; a new run moves them. `routerAttachmentsFor`
places the site router at `.1` in every zone subnet of its site, so a
multi-homed router has an address on each segment.

**Rules.** `nftablesFor(spec)` compiles the structured policies into a forward
chain: `policy drop`, established/related accept, explicit denies first with
`limit rate 10/second log prefix "arena-deny " drop`, then allows, then WAN
link ports. Deny wins over allow for the same tuple. The router task in
`vmProfileTasks` enables IPv4 forwarding and loads the ruleset from
`/etc/nftables.conf`.

**Negative probes.** `negativeProbeCommands` turns each unreachable zone pair
into a real `/dev/tcp` connect from a named source host to the target's plan
address. The plan now carries `segments`, `routerRules` and `negativeProbes`
alongside the allowed/denied graph.

**Verified.** Backend 136/136; 6 tests in `org-topology.test.mjs` (the new one
reads the decoded router task, checks deny-before-allow ordering, unique
run-scoped segment ports, `.1` on each site zone, and a probe aimed at the
real DB address).

**Not claimed.** No per-zone hub is started, no guest has multiple lab NICs,
and no nftables ruleset has been loaded. Sites/zones remain refused at
deployability. `nftables` is not in the staged baked image, so a live router
would currently install it over the management NIC. The ruleset is global per
spec; per-site router trimming is P5.

## 2026-10-30 — P1b: the multi-segment runtime

**Lab wiring.** `labSegmentsFor(spec, runId)` (provisioner/lab-network) wires
one lab NIC per zone segment: a regular host gets one NIC on its zone's
segment; the site router gets one NIC per zone (at `.1` there) with a
distinct deterministic MAC per NIC. `nicMac` takes an index that only changes
the hash for lab NICs past the first, so every v1 MAC is unchanged.

**Lifecycle.** `qemuRunArgs` accepts `labs: {hubPort, mac}[]` (dense
net1/net2/… socket NICs; the single-`lab` path is untouched) and the seed
renders one address line per NIC by MAC. `startRunVms` starts one hub process
per zone segment for v2 specs (sorted for determinism), records
`labHubs[]` + per-host `labs[]` (`lab` stays the primary address for every
reader: exercises, `waitForLabAddress`, deploy records), and stop/destroy
kill every hub. A fake-QEMU lifecycle test boots a 2-zone spec: 2 hubs, a
2-NIC router at `.1`/`.1`, derived host addresses, and full teardown.

**Config + probes.** `vmProfileTasks` resolves v2 addresses from the org model
(router primary = first zone), the router task asserts each interface address
is present before loading nftables, and the gateway's dnsmasq records carry
v2 FQDNs. `zoneProbesFor` executes the reachability graph live inside
`checkSpecReadiness`: every allowed cross-zone connect must pass; one deny
probe per unreachable zone pair must fail. Deny commands carry a
`: probe from <src>;` comment so an allow and a deny never share a command
string. The reachability graph now uses a non-router client per origin zone
(the router must not grade its own forwarding) and deployability +
`validateOrgTopology` require one router per multi-zone site.

**Gates flipped.** Deployability accepts single-site, all-VM orgs with a
router; multi-site (WAN links unenforced, P5), container-mixed v2, and
router-less multi-zone specs are refused with named reasons. The designer
prompt documents the single-site org contract. The plan carries zone probes
in `labProbes` (review shape, no commands) alongside the existing
`negativeProbes` execution shape.

**Verified.** Backend 141/141 (org-topology 11 tests, kvm lifecycle incl. the
v2 hub test, topology container-path refusal updated).

**Not claimed.** No multi-guest v2 boot has run on a real host; no nftables
ruleset has been loaded on a guest; no live zone/negative probe has
executed; the staged baked image still lacks `nftables` (a live router would
install it over the management NIC). Multi-site/WAN remains refused (P5).
FreeIPA remains unit-tested only.

## 2026-10-30 — P4 (part): persona agents

**Personas are agents now.** `personaShift` (exercise/agents) gives each
persona on a VM workstation a model-driven shift through one `shift` tool. The
action vocabulary is closed (`web_fetch`, `db_query`, `lookup_host`,
`send_probe_mail`, `whoami`, `hostname`); the platform renders each call as a
fixed command — no shell, no model-authored command. Targets come from the
spec (http hosts, declared hosts, two approved read-only queries). Off-list,
off-target, or out-of-spec calls are refused deterministically, returned with
the reason, counted in the guardrail log, and never reach the guest.

**Wiring.** `runVmAgentExercise` runs persona shifts before red objectives
(replacing the old per-role curl/psql noise). With a persona client the shift
is `mode: "agent"`; without one — or when the workstation is not a VM — the
scripted baseline runs and is labelled `mode: "scripted"` with the reason in
`stoppedByCap`. `VmAgentRunOptions.personas` injects the client; the smoke
defaults it to `modelForRole("persona")` and fails if any persona ran in
scripted mode while the agent runtime was on. `agentStates` gains
`persona:<id>` entries, `run.modelIds` gains `persona`, and the score audit
carries `shiftReport` (mode, performed, refused, model per persona).

**Model pinning.** `modelForRole("persona")` defaults to `muse-spark-1.1`
(persona traffic is the highest-volume, cheapest role), overridable via
`MUSEARENA_MODEL_PERSONA`. Unverified ids — including any `muse-glimmer-*`,
which has never been verified on /v1/responses — fail closed at
`modelForRole`, never reaching the API. Trajectory steps carry
`actor: "persona"` (schema extended; export/ground-truth paths unchanged).

**Verified.** Backend 143/143 (`persona agents` tests in detection.test.mjs:
allowlist-only execution with a scripted client, 3 refusals counted, refused
actions never executed; container workstation → scripted baseline, 0 steps;
model-registry persona pinning + glimmer rejection).

**Not claimed.** No live MaaS persona run has executed (model API blocked in
earlier sessions; the smoke is wired but not live-verified). The design's
baked `/usr/local/bin/muse-shift` binary is not built — the same allowlist
contract runs host-side over SSH. No Kerberos-authenticated shifts
(`sudo -u` + `KRB5CCNAME` waits on P2 FreeIPA live), no persona agents on the
container path (spec data + scripted noise there), and no per-persona model
sweep. FP accounting is unchanged: persona activity is scored as noise
regardless of which mode produced it.

## 2026-10-31 — T-26: FreeIPA live on Rocky Linux 9 (P2)

`node scripts/vm-freeipa-smoke.mjs` green end-to-end on the HVF dev host:
Rocky 9 dc-01 (pinned GenericCloud, SHA256-verified) installs FreeIPA
(dirsrv/KDC/Dogtag/DNS), seeds persona p1; Debian 12 ws-01 joins, SSSD
resolves `id p1` (uid 50600003, group nurse); peer LDAP bind and DNS SRV
proven from the member. Backend 143/143.

Key fixes en route: Debian/Rocky catalog split (Debian never names
`ipa-server`); Rocky package/unit mapping with osquery dropped (no base
package); fail-closed `profile-install` (a failed apt transaction previously
passed silently behind a trailing mkdir, hiding a missing
`ipa-client-install`); NoCloud `network-config` file for lab NICs —
NetworkManager's DHCP timeout flushed the runcmd lab address and stalled
Dogtag's LDAP connect ("CA configuration failed"); FreeIPA task asserts the
lab address before installing.

Not claimed: baked Rocky image (dnf over mgmt at configure time), osquery on
Rocky, replicas, Kerberoast, Kerberos-authenticated persona shifts,
persona-password kinit (O-6).

## 2026-10-31 — T-27: single-site segmented lab live (P1 acceptance closed)

`node scripts/vm-segmented-smoke.mjs` green on HVF: router r-01 multi-homed
(.1 per zone, `nft list ruleset` shows the derived forward chain, policy
drop), web-01 (edge) → db-01 (server):5432 allowed probe passes through the
router, db-01 → web-01:80 denied probe fails. Backend 143/143, no leaked QEMU.

Fixes: guests now get same-site cross-zone routes via their zone router
(lab-network `routesVia` → seed network-config + runcmd); the deny probe no
longer targets the router's own .1 (input chain, unfiltered by design) but a
declared service on a non-router host in the denied zone.

## 2026-10-31 — baked Debian catalog-2 image built

`node scripts/build-catalog-image.mjs` rebuilt the baked image from the
pinned Debian base: 36 packages (now incl. freeipa-client, sssd, nftables),
SHA512 `18a7080c…` pinned in `golden/baked-images.json` as
`arena-golden-debian12-catalog-2`; `resolveGoldenImage` returns the baked
tier. Backend 143/143. Runs now prefer the baked image, so Debian configure
needs no package egress. Still not claimed: baked Rocky image (FreeIPA
server dnf-installs over mgmt), catalog-2 live config smoke on the baked
tier (next verification), Windows.

## 2026-10-31 — O-1 live: guests resolve via the planned gateway DNS

`node scripts/vm-dns-smoke.mjs` green on the baked catalog-2 image: every
non-gateway guest's `dns-resolver` task points its lab NIC at the gateway
dnsmasq (netplan drop-in repeating the lab address + search domain,
resolvectl routing domain `~<labDomain>`, stub resolv.conf), then proves
in-guest: `getent hosts gw-01.<domain>`/`db-01.<domain>` via NSS, ping by
FQDN, nonexistent names do not resolve. Readiness lab-dns probes pass from
both member hosts. Failures found and fixed live: netplan drop-in without
addresses dropped the lab IP; uplink resolv.conf hid the gateway link from
glibc; resolved's parallel NXDOMAIN race. Single-label names may still be
answered by LLMNR — the DNS claim is FQDN-scoped and says so.

## 2026-10-31 - Persona agents live on Muse (T-25 live acceptance)

MUSEARENA_AGENT_RUNTIME=maas node --env-file=../.env
scripts/vm-exercise-smoke.mjs green: persona p1 ran 6 allowlisted shift
actions in agent mode (whoami, hostname, lookups, fetch) on muse-spark-1.3
(META_MODEL_ID overrides the spark-1.1 persona default, precedence as
documented), 0 refused, tokens metered; red achieved 1/2 objectives, blue
enforced a block, dataset exported and integrity-checked. Backend suite
unchanged. Not claimed: some persona actions error inside the guest
(model-chosen targets like web-01.local) yet count performed; Kerberos-
authenticated shifts; the baked muse-shift binary; container personas.

## 2026-10-31 - O-3 closed (Kerberoast not feasible on FreeIPA) + spray live

Kerberoast probe (scripts/vm-kerberoast-probe.mjs): a user CAN carry an SPN,
but kvno returns "Server principal valid for user2user only" - FreeIPA
refuses to issue a crackable TGS for user principals. O-3 verdict: T1558.003
via user-SPN is not feasible on FreeIPA; the pack must not claim it.
Feasible and now live (scripts/vm-spray-smoke.mjs): weak-cred planted on
the DC seeds svc-report/Summer2024! (gated by the planted vuln, unit-tested);
LDAP bind spray from a member fails 3x (err=49, visible in dirsrv access
log), succeeds on the planted password, and kinit as svc-report works
(O-6: non-interactive password path proven via pty helper; first use
forces a change, helper re-enters the same password). Backend 144/144.
Not claimed: red-agent (model) execution of the spray objective with
scorecard/telemetry scoring, Temporal workflow E2E for FreeIPA orgs,
AS-REP roasting, keytab theft paths.

## 2026-11-01 - P3 mail live: IMAP authenticates against FreeIPA

scripts/vm-mail-smoke.mjs green on HVF: Rocky dc-01 (FreeIPA) + Debian
mail-01 joined. SMTP delivery to p1@<domain> lands and is read by p1 over
IMAP; the only Dovecot passdb is `ldap` (PAM removed, verified in the
effective `doveconf -n`), `doveadm auth test p1` succeeds, and a wrong
password is refused by 389-ds. Readiness smtp-imap-roundtrip passes on a
member using the domain account end to end.

Fixes found live: (1) admin-set IPA passwords are temporary - kinit says
"Password expired" and a simple bind returns 49; the seed now sets
krbpasswordexpiration and PROVES the credential with ldapwhoami, failing
the configure instead of the probe. (2) Debian ships a PAM passdb ahead of
any added one, and PAM reaches SSSD, so a successful login did not prove
the directory path; on members the PAM include is removed and the task
asserts ldap is present and pam absent. (3) the probe tool must be on the
host: `swaks` now ships with any host declaring smtp. (4) with LDAP-only
auth the local `probe` account cannot log in, so a member's roundtrip is
the domain user end to end, with persona homes created after the join.
Not claimed: Samba/Gitea/Postgres directory auth (next), Kerberos SSO for
IMAP (password auth only), mail delivery to non-persona addresses.

## 2026-11-01 - O-4 closed negatively: Samba member cannot join FreeIPA

Live evidence (scripts run against a real Rocky 9 FreeIPA server + Debian
member): Samba's SRV discovery is satisfied - _ldap._tcp.dc._msdcs.<realm>
and _kerberos._tcp.dc._msdcs.<realm> are seeded and resolve from the member,
and the SRV/A answers are correct. The join then fails at the AD NetLogon
step: `LDAP ping to dc-01... ; ads_cldap_netlogon: did not get a reply` ->
"failed to find DC for domain IPA". The DC has no libipa_cldap plugin and no
UDP/389 listener, so it cannot answer the CLDAP ping Samba requires; `-S`,
`-U admin` and `-k` all fail identically.

Consequence: `file/samba` is removed from the runtime catalog rather than
shipped as a service that cannot be verified; the ServiceKind/readyWhen
additions are reverted. File shares are deferred until a supported path is
chosen (NFSv4+sec=krb5 authenticates the client host, not the user, so it
does not meet the "a domain user accesses the share" bar either). Recorded
non-claim: no domain file share in P3.

## 2026-11-01 - P3 database live: Postgres authenticates domain users via FreeIPA

scripts/vm-db-smoke.mjs green on HVF: Rocky dc-01 (FreeIPA) + Debian db-01
joined. pg_hba carries `ldap` rules for the seeded persona on both the lab
CIDR and loopback; p1 logs in to Postgres with its IPA password (role
created by the seed), a wrong password is refused by 389-ds, and readiness
sql-select passes as the domain user.

Fix found live: the loopback `trust` rule matched before a CIDR-only ldap
rule, so a wrong password was accepted on 127.0.0.1. The rule is now emitted
for both the lab segment and loopback, and the probe exercises the negative
leg first.

## 2026-11-01 - P3 source control live: Gitea logs in domain users via FreeIPA

scripts/vm-gitea-smoke.mjs green on HVF (baked catalog image with the Gitea
1.22.6 binary): Rocky dc-01 (FreeIPA) + Debian git-01 joined. p1
authenticates through a Gitea LDAP auth source (source_id 1) and
GET /api/v1/user returns "login":"p1"; a wrong password is refused; readiness
git-ldap-login passes. Backend 148/148.

Fixes found live: Gitea 1.22 does not load [[auth.ldap]] from app.ini, so the
source is created with `gitea admin auth add-ldap` (flag is --user-search-base,
not --user-base) and the task proves it registered; the service needs to write
its internal token, so app.ini is owned by the git user; HTTP_ADDR binds
0.0.0.0 so loopback and the lab address both answer; a preflight fails closed
when the baked binary is absent; the IPA seed now guarantees the realm's SRV
records, which a fresh install did not always publish.

## 2026-11-01 - P3 completion audit

Re-ran the backend gate: 148/148. Confirmed the P3 state against the live
artifacts and the runtime catalog: mail, Postgres and Gitea each authenticate
a seeded domain user and refuse a wrong password; `file/samba` is absent from
the catalog because O-4 disproved the join. Reconciled the authoritative
design: the service table no longer lists `file/samba`, Postgres/Dovecot/Gitea
are described as LDAP bind (GSSAPI/service keytabs are non-claims), Gitea's
probe is `git-ldap-login`, and the current-state and non-claims sections no
longer claim that FreeIPA, routers, zones or persona agents are unbuilt.

P3 non-claims recorded in the design: no domain file share; no Postgres or
mail GSSAPI/SSO; no service-keytab path; Gitea SSH/PR workflows and per-repo
group authorization unproven; no combined multi-service org run; no Temporal
workflow E2E on a FreeIPA org; no baked Rocky image or Rocky osquery.

## 2026-11-01 - Persona shifts authenticated by FreeIPA Kerberos (T-35)

scripts/vm-persona-kerberos-smoke.mjs green on HVF: Rocky dc-01 (FreeIPA) +
Debian ws-01 joined. The production `personaShifts` path runs setup before
the first agent turn: a pty `kinit` as the seeded p1 into a FILE ccache,
`klist`, and `ldapwhoami -Y GSSAPI` returning
`dn: uid=p1,cn=users,cn=accounts,...`. The deterministic shift then executes
`whoami` and `hostname` through `sudo -n -u p1 env KRB5CCNAME=...`; `whoami`
returns `p1`, and the ticket survives the shift (klist + GSSAPI bind still
work). Backend 149/149.

Fixes found live: the kinit helper was mode 0700 owned by the SSH user, so
the persona could not read it; it is now 0755 and carries no secret (the
password is piped as base64 on stdin, never argv). The IPA seed now retries
SRV publication and readback because a fresh `named` did not always answer,
and the smoke retries one transient Rocky configure loss before failing.

Not claimed: a model-driven shift on a FreeIPA member end-to-end (the live
proof used the deterministic `ScriptedAgentClient`; T-29 proves the model loop
on a non-member), the scripted fallback and container personas (both stay
local), the baked `muse-shift` binary, and persona action quality.

## 2026-11-02 - Baked Rocky 9 FreeIPA image live (T-38)

scripts/build-rocky-image.mjs booted the pinned Rocky GenericCloud base,
dnf-installed the 16-package FreeIPA server union, powered off, compressed
the artifact and pinned `rocky-9-freeipa-aarch64.qcow2`
(sha512:d147ac57…) in golden/baked-rocky-images.json. The Rocky tier has its
own manifest because the manifest schema names one catalogVersion; the
resolver now defaults to it for `family: "rocky"` and still refuses a
tampered or package-incomplete artifact.

scripts/vm-freeipa-smoke.mjs resolved `rocky-9-freeipa`, proved ipa-server,
ipa-server-dns, ipa-client, krb5-workstation, sssd, sssd-tools and nftables
were present BEFORE configure, then completed the full FreeIPA install,
member join, admin kinit, persona lookup, peer LDAP bind and DNS SRV. Backend
150/150.

Not claimed: an x86_64 Rocky artifact (this arm64 host builds aarch64 only);
Rocky osquery (no vendor package); a FreeIPA replica; service packages beyond
the FreeIPA server set are not baked, so a Rocky host declaring those still
uses the package path.

## 2026-11-02 - Combined multi-service org run live (T-39)

scripts/vm-org-multi-service-smoke.mjs green on one HVF run: Rocky dc-01
(baked FreeIPA tier) plus Debian mail-01, db-01, git-01 and ws-01, all joined
to the same realm. One generated playbook configured all five. Readiness
passed per host (ldap-bind, smtp-imap-roundtrip, sql-select, git-ldap-login,
ssh-login, lab-ldap) and cross-host probes passed mail-01→dc-01 LDAP and
dc-01→mail-01 SMTP. p1 authenticated over the lab segment to IMAP, Postgres
and Gitea; each service refused a wrong password. The ws-01 persona shift
ran as p1 with a Kerberos ccache. Backend 150/150.

Not claimed: multi-zone routing in this combined run (flat segment; T-27
covers segmentation), a telemetry-scored exercise, and Temporal workflow E2E
on this org (T-41).

## 2026-11-02 - Rocky osquery sensor live (T-44)

The Rocky bake now adds the osquery vendor RPM repository and installs
osquery 5.24.0 alongside the FreeIPA package set; the guest has no runtime
repo dependency. ROCKY_PACKAGE_MAP/resolveProfileUnits map osquery/osqueryd
instead of dropping them, so profile-install verifies the RPM and
profile-enable starts the unit on every Rocky guest.

vm-freeipa-smoke.mjs on the baked tier proves: rpm -q osquery, systemctl
is-active osqueryd = active, and osqueryi returns version 5.24.0. Backend
150/150.

Fixes found live: the osquery repo heredoc in the bake was unindented, which
ended the YAML runcmd block and made cloud-init silently skip the whole
install; every heredoc line now stays inside the block.

Not claimed: an x86_64 Rocky artifact (T-38); a scheduled query pack or
osquery-based detection/event pipeline (the base config keeps the empty
schedule); a FreeIPA replica.

## 2026-11-02 - Service keytabs + GSSAPI live on FreeIPA members (T-40)

scripts/vm-gssapi-smoke.mjs green on one HVF run: Rocky dc-01 (baked FreeIPA
tier) plus Debian db-01, web-01 and mail-01, all joined to one realm. One
generated playbook configured all four. The member now adds its own
host-based principals and keytabs after the join (temporary admin ticket,
destroyed immediately); keytab contents are never logged. The Debian catalog
image was re-baked as arena-golden-debian12-catalog-3 (39 packages, sha512
9af610ce4b3bbb2a…) so dovecot-gssapi and libapache2-mod-auth-gssapi are
offline at configure time.

Readiness and direct proofs passed on the same run:
- db-01: sql-select (LDAP password) and gssapi-sql; psql -h <fqdn> -U p1 -d
  gssdb returns 1 with a Kerberos ticket; a keytab-less connection and a
  valid admin principal with no database role are both refused.
- web-01: http-2xx and gssapi-http; Apache returns REMOTE_USER=p1 over
  SPNEGO, returns 401 without a ticket, and the plain app still returns 200.
- mail-01: smtp-imap-roundtrip and gssapi-imap; Dovecot advertises
  AUTH=GSSAPI, accepts the persona ticket, refuses a ticket-less login, and
  still accepts the LDAP password.
- dc-01: admin kinit, seeded persona, LDAP and lab probes green.

Fixes found live: `ipa service-add --force` still errors on an existing
principal, so service-show gates the add; `--force` is needed on create
because the lab FQDN has no A record in the IPA zone; PostgreSQL 15 rejects
`krb5_realm` in pg_hba (realm is pinned by the keytab principal); and
Dovecot's `99-arena-gssapi.conf` sorts before `99-arena.conf`, so the
mechanism is set in the file that owns it. The first live attempts also
stalled when the host ran out of free memory; the final run had memory
headroom.

Not claimed: Gitea SSH/PR workflows and per-repo group authorization (T-42),
NFS/Samba sec=krb5, cross-realm trust, wrong-principal negatives for
Apache/Dovecot, Rocky application-service members, an x86_64 image, and a
FreeIPA replica. Backend 151/151.

## 2026-11-02 - Combined org through the Temporal workflow (T-41)

scripts/vm-org-workflow.mjs green on one HVF run: the T-39 org (Rocky dc-01
baked FreeIPA + Debian mail-01, db-01, git-01, ws-01 on catalog-3) inserted as
an approved environment + pending deployment and carried end to end by the
real pipeline. Deployment 6ab44d61-b79a-484f-8343-73a15190dff8, org
vm-org-workflow-org: claimed in 5s, CrossGuard pass, Pulumi stack + 5 guests
with SSH identities, ready at 631s. Readiness audit pass=true, 15 probes ok:
ldap-bind, smtp-imap-roundtrip x2, gssapi-imap, sql-select, gssapi-sql,
git-ldap-login, git-ssh, lab-ldap, lab-smtp, ssh-login x5. Score 1/1, 10/10,
FP 0 (live-vm, backend kvm); dataset sha256:043f9639fd087e1b... (7 steps)
re-downloaded from Storage and hash-verified; 2 Langfuse spans; drift
in-sync at 860s; destroyed by the workflow's own TTL timer (0.4h) with zero
leaked QEMU or hub processes.

The spec is T-39's plus the two fields the workflow contract requires: a
T1110 auth-failures detection objective on dc-01 (10 points) and
requiredTelemetry ["auditd"]. The zero-objective smoke spec is rejected by
the schema itself, so a scored objective was never optional here.

Two platform gaps found by the offline gates before the run, both fixed with
regression tests:
1. planDeployment never passed domainUser to probeFor, so every spec with a
   Gitea host threw "only verifiable with a domain identity" at plan time --
   unprovisionable through the designer and the trigger alike. The T-34/T-39
   smokes never called the planner, so it hid until now. The derivation is
   now domainUserFor in configurator/readiness.ts, shared by planner and
   gate; the test asserts the plan renders git-ldap-login expecting
   "login":"p1" and that the serialized plan contains no per-run secret.
   Side effect by design: plans approved before this fix for member specs
   digest differently and need re-approval.
2. collectVmTelemetry read /var/log/auth.log but never /var/log/secure, so
   T1110 was unobservable on every Rocky guest (sshd logs to secure there).
   Both files are collected now; the test stubs exec and proves a Rocky
   secure line becomes a red auth.login.failed event. The live 1/1 score on
   dc-01 is the end-to-end proof.

Also the first workflow-internal pass of the T-40 GSSAPI probes and the
git-ssh probe (previously smoke-only). Backend 158/158 (150 at HEAD + 6
pre-existing uncommitted WIP tests + 2 new regression tests).

Not claimed: agents-maas-vm on this org through Temporal; multi-zone routing
in the workflow org; T-42 acceptance (PR flow, per-repo group authorization
negatives); x86_64 image; FreeIPA replica.

## 2026-11-02 (late) - Full bring-up + wiring verification sweep

Operator asked for everything up and provably wired. Verified live, in
order: 9 platform containers healthy (Temporal :7234, Langfuse :3100
health OK, Prometheus :9095); root build green across all five workspaces;
single backend worker on the current build serving the musearena queue with
metrics on :9464 (Prometheus target musearena-worker: up, was down);
audit_verify passes for all 6 orgs and audit_log refuses UPDATE/DELETE for
service_role (trigger-enforced); Realtime delivers deployment inserts; anon
read/write isolation holds; backend 164/164 + marketing 1/1; container
lifecycle smoke OK (2/2, 15/15, egress blocked, dataset verified,
teardown clean); prompt-to-dataset e2e OK in 34.6s (design 6.8s, 2/2,
dataset sha256:637f0c68... verifies, 5 Langfuse spans); designer endpoint
401s unauthenticated and bad-token requests; frontend serving on :5173;
VM org workflow OK (deployment 207526cf: 1/1, 10/10, dataset
sha256:5a4a36ca..., TTL teardown at 1451s, no leaks).

Three wiring defects found and fixed at root cause during the sweep:
1. backendRoot() resolved Pulumi state from process.cwd(): the worker
   (cwd backend/) and RUNBOOK scripts (cwd repo root) wrote to different
   state roots, so a root-run teardown destroyed an empty stack, marked
   resourcesDestroyed=true, and leaked 3 containers + network (the poisoned
   flag then short-circuited every later teardown). State and the golden
   image cache now anchor to the backend package via import.meta.url
   (deploy.ts, images.ts) with a cwd-independence regression test; the
   leaked stack was destroyed through the real path (7 resources) after
   correcting the record.
2. smoke.mjs/e2e.mjs injected a script-local Pulumi passphrase
   (/tmp/musearena-smoke-passphrase) that the worker never uses, so script
   teardown could not decrypt stack history ("incorrect passphrase" after
   resources were already deleted). Both scripts now rely on the
   environment plane's persisted passphrase, like vm-workflow.mjs always
   did. The stale /tmp file was removed.
3. platform-check.mjs cannot run its SQL checks: SUPABASE_ACCESS_TOKEN in
   .env is rejected by the Management API (HTTP 401 Invalid access token).
   The token is used only by that script; production paths are unaffected.
   Its REST checks pass and the audit/Realtime checks were re-proven via
   service-role RPC/REST above, but the forged-authenticated-claims
   cross-org SQL checks stay BLOCKED until the token is rotated by the
   operator. Direct-DB fallback is unavailable from this environment
   (sandbox blocks raw 5432; escalation prompts disabled).

Not claimed: interactive Clerk sign-in (T-3, unchanged); the two SQL
isolation checks (blocked above); anything about the concurrent session's
in-flight guests (run-vm-git-mvzuy7zm dc-01/git-01 still running, left
untouched).

## 2026-11-04 - x86_64 baked catalog image live (T-16)

The last single-arch hole in the offline package story is closed.
`scripts/build-catalog-image.mjs --arch x86_64` on the Linux KVM host
`agent` baked the 39-package profile union into the pinned Debian 12
amd64 base: `debian-12-catalog-x86_64.qcow2` (931M, 6G virtual), SHA512
`ffb8b50033173a90...a619fb`, pinned beside the aarch64 entry in
`backend/golden/baked-images.json` and staged in the Linux worker's
`GOLDEN_IMAGE_DIR`. The pin was re-verified with `sha512sum`, and
`ensureBakedImage("x86_64")` on the host resolves it as
`debian-12-catalog` — Linux VM runs now boot the baked image instead of
falling back to the plain base (which needed apt over the management NIC).

Proof it boots and configures: `scripts/vm-config-smoke.mjs` on KVM —
6 guests SSH-ready on the baked image, Ansible configure ok on every
host, readiness PASS for ssh/http/sql/dns/ldap/smtp-imap/tcp plus the
lab cross-host probes (dns, smtp, db-port, http, log shipping),
`VM CONFIG + READINESS SMOKE OK`, no leaked QEMU.

The first two smoke attempts failed in the Debian `dns-resolver` task
with `Shared connection to 127.0.0.1 closed` — a different host each
run (web-01, then log-01). Root cause: the task ran `netplan apply`
over the same management SSH session Ansible arrives on; netplan
reconfigures every link, so the session intermittently drops mid-task.
A stepwise guest diagnostic showed `netplan apply` itself completes
and addresses survive — the failure is the session, not the addressing.
Fix: the task still writes `/etc/netplan/99-arena-dns.yaml` (applies on
next boot) and sets the identical per-link DNS servers and routing
domains at runtime with `resolvectl`, which touches no link. Pinned by
the regression test "dns-resolver never reconfigures networking over
its own SSH session". The detached Linux worker was restarted onto the
fixed build (same env/queue/routes, `musearena-linux-kvm`, RUNNING).

Gates: root build + typecheck pass, backend 251/251, marketing 1/1,
frontend oxlint 0/0 (single-chunk >500kB build warning unchanged).

Not claimed: a scored exercise or full Temporal workflow run on the
baked x86_64 image; T-16 stays partial (DHCP, container readiness
executor, full cross-service acceptance still open).

## 2026-11-04 - Scored Temporal workflow on the baked x86_64 image (T-16/T-18)

`scripts/vm-workflow.mjs` (scripted clinic) targeted at the Linux
worker, twice, green both times:

- Deployment `c3aa1821-2880-463a-9c06-5bfa06a796b8`: claimed by
  `linux-kvm` in 9s, 6 `vm:x86_64:kvm` guests, configured 6/6,
  `live-vm` exercise 3/3 objectives, 30/30 points, 0 FP, stored
  dataset `sha256:bb7a95ff...` (16 steps) re-downloaded and
  hash-verified, 6 Langfuse spans, drift in-sync, destroyed by the
  workflow's own TTL timer, no leaked QEMU. `VM WORKFLOW OK`.
- Deployment `10b79ad1-21cb-4a65-9d69-86dfb58bd350`: same shape,
  dataset `sha256:a4b2b5b2...`, 3/3 · 30/30, TTL teardown clean.

The first run proved scoring on the baked image but left an evidence
gap: the deployment/run records said `vm:x86_64:kvm` and backend
`kvm`, while the image each guest booted (`imageName` +
`goldenDigest`) lived only in the host-local VM registry that teardown
deletes. Deploy now stamps `access_info.guestImages` — per-host
`{name, digest}` from `guestImagePins(state)` in `vm-lifecycle.ts`,
complete pins only — so the second run's record names all six guests
as `debian-12-catalog` at
`sha512:ffb8b50033173a90.../arena-golden-debian12-catalog-3`, matching
the manifest pin. Pinned by the unit test "guest image pins name the
image each guest actually booted" and by the live record above. The
Linux worker was restarted onto the build before the second run
(same env/queue/routes, RUNNING).

Gates after the change: root build + typecheck pass, backend 252/252,
marketing 1/1, frontend oxlint 0/0.

Not claimed: a model-agent (`--agents`) workflow run on the baked
x86_64 image (Meta billing gate unchanged); T-16 stays partial
(DHCP config/probe, container readiness executor, full cross-service
acceptance still open).

## 2026-11-04 - DHCP config + lease probe live (T-16)

`dhcp/dnsmasq` was catalogued with groups and a probe but no task wrote
a lease range, so deployability blocked it at design time. Now:

- `dhcpPoolFor(cidr)` in `provisioner/lab-network.ts` leases the top
  32 usable addresses of the lab subnet (e.g. 10.2.47.223–.254 on the
  clinic /20). Static lab addresses (.1 gateway, .10+ hosts) sit at
  the bottom, so a lease can never collide with a configured guest.
- `dhcp-configure` (in `vmProfileTasks`) writes
  `/etc/dnsmasq.d/arena-dhcp.conf`: `dhcp-range` with the subnet
  netmask, router/DNS options pointing at the gateway,
  `dhcp-authoritative`, `dnsmasq --test` before restart. When `dns`
  is not co-declared it also binds dnsmasq to loopback+lab so DHCP is
  never offered on the management NIC.
- Readiness splits the proof: the local `dhcp-lease` probe proves the
  server (unit active, UDP/67 bound, range configured — no client has
  leased when the server's own checks run), and the new cross-host
  `lab-dhcp` probe leases a real address from a peer guest: a stdlib
  Python DISCOVER/REQUEST/ACK exchange broadcast over the lab
  segment, asserting the ACK address falls inside the pool. It
  configures nothing on the client; the lease on the server and the
  ACK on the wire are the evidence.
- Deployability offers dhcp on the VM runtime with a topology subnet
  (container runtime blocked precisely); the designer prompt and the
  capability catalog offer it beside `dns` on the gateway. Tests that
  encoded the old blocked state were updated to the new behavior;
  the new behavior is pinned by "dhcp: lease pool, configure task,
  deployability and lab lease probe".

Live on KVM, baked x86_64 image, 6-guest config smoke with
dns+dhcp on gw-01: configure ok on every host, `dhcp-lease` PASS on
gw-01, `lab/dhcp` PASS from web-01 (real lease over the hub segment),
all other readiness probes PASS, `VM CONFIG + READINESS SMOKE OK`,
no leaked QEMU. The Linux worker was restarted onto the build.

Gates: root build + typecheck pass, backend 253/253, marketing 1/1,
frontend oxlint 0/0.

Not claimed: guests taking their primary address by DHCP (lab
addressing stays static by design — DHCP serves dynamic clients);
DHCP on Rocky guests or v2 zone segments (lab probes are v1-only);
a scored workflow run of a dhcp-declaring spec. T-16 stays partial:
container readiness executor and full cross-service acceptance
(web→DB SQL read, LDAP-backed mail login as readiness probes) open.

## 2026-11-04 - web→DB readiness is a real SQL read (T-16)

The cross-host DB proof was `lab-tcp`: the web guest opened a TCP
connection to 5432. That proves a listener, not a read. It is now
`lab-sql`:

- `db-seed-access` creates a least-privilege `arena_probe` LOGIN role
  with the per-run `labSecret(runId, "db-probe")` password and seeds
  `arena_probe_ping` with one row (`arena-db-ready`), granting SELECT
  to the probe role only. `db-configure` adds a pg_hba rule for
  `arena_probe` from the lab subnet (scram) beside the existing `app`
  rule. The `app` role cannot serve as the probe credential: over the
  segment it is scram-only and its password is either the planted
  weak-cred vuln or rotated to an unknown value — both by design.
- The probe runs on the web guest: a wrong-password leg must fail
  first (a trust rule would otherwise make the read meaningless),
  then `SELECT v FROM arena_probe_ping` must return `arena-db-ready`.
- The plan renders the same probe (`lab-sql` web→db); the old
  `lab-tcp` name is gone. Pinned by "lab-sql: the web tier reads
  from the database over the segment with a probe credential".

Live on KVM (baked x86_64, 6-guest config smoke): `lab/sql` PASS
from web-01, all other readiness probes PASS,
`VM CONFIG + READINESS SMOKE OK`, no leaked QEMU. Linux worker
restarted onto the build.

Gates: root build + typecheck pass, backend 254/254, marketing 1/1,
frontend oxlint 0/0.

Not claimed: lab-sql on Rocky db guests (the Debian pg_hba paths in
db-configure are unchanged) or in v2 zone topologies (lab probes are
v1-only); a scored workflow run since this change. T-16 stays
partial: LDAP-backed mail login as a cross-host readiness probe,
the container readiness executor, and full cross-service acceptance
remain open.

## 2026-11-04 - LDAP-backed mail login, proven cross-host (T-16)

FreeIPA member mail already authenticated against 389-ds (P3), but
the clinic's default directory is OpenLDAP and its mail host used a
local PAM probe account — the directory existed and mail ignored it.
Now a mail host whose `dependsOn` includes an `ldap/openldap` host is
directory-backed:

- Dovecot gets the same bind-as-user LDAP passdb/userdb shape as the
  FreeIPA path (`auth_bind_userdn = uid=%u,ou=people,<base>`, admin
  DN for the userdb lookup), and LDAP must be the *only* passdb — a
  surviving PAM passdb fails `mail-configure`, because a PAM success
  would not prove the directory path.
- `ldap-seed` gives the `probe` entry POSIX attributes
  (uid/gid 10001, home `/home/probe`), sets its password through
  `ldappasswd` (server-hashed) to the per-run `mail-probe` secret,
  and proves the bind at seed time. The mail host keeps a locked
  system user with uid 10001 (no password) so Postfix local delivery
  and the LDAP userdb agree on mailbox ownership. Unjoined mail
  hosts keep the previous local account exactly as before.
- New cross-host readiness probe `lab-mail`: a peer guest logs in
  over IMAP at the mail lab address as the directory `probe` user —
  wrong password refused first, then the real login. The local
  smtp/imap roundtrip now also authenticates through the directory
  on joined hosts. Pinned by "lab-mail: IMAP authenticates against
  OpenLDAP from a peer guest".

Live, twice: the 6-guest config smoke (mail depending on dc) is
green with `lab/mail-ldap` PASS from web-01; the full clinic
workflow (deployment `bb248010-…`, dataset `sha256:e58bc5ef…`)
scored 3/3 · 30/30 with `lab-mail` in the readiness audit and a
clean TTL teardown.

The first workflow attempt (`07796726-…`) scored 30/30 but failed
the harness's post-exercise drift assertion: blue isolated web-01,
db-01 **and dc-01**, so Dovecot could no longer reach its directory
and drift correctly reported mail missing smtp+imap. That is the
real blast radius of containing a directory, not a regression — so
both workflow harnesses now require post-exercise drift to be
*explained* by a recorded `isolate host` enforcement (the drifted
host itself, or one it transitively depends on) and print the
explanation (`drift explained by containment (isolated: web-01,
db-01, dc-01): mail-01 missing smtp+imap`). Unexplained drift still
fails the run. Production drift semantics are unchanged: hourly
maintenance will still report a directory-dependent service as
drifted while its directory is isolated, which is true.

Gates: root build + typecheck pass, backend 255/255, marketing 1/1,
frontend oxlint 0/0. Linux worker runs the build.

With DNS/DHCP via gateway, LDAP-backed mail, web→DB SQL read, and
log shipping all live, the cross-service proofs named in T-16's
acceptance are done. Not claimed: the service-disabled acceptance
run (disable a declared service in a 6-host org and show readiness
naming it with no scoring — proven per-probe and for a blind
sensor, not as that scenario), the container readiness executor,
and bridge/tap L2 (T-15). T-16 stays partial on those.

## 2026-11-04 - Service-disabled readiness acceptance live (T-16)

The last unproven T-16 acceptance clause — "disabling any declared
service fails readiness with host/service named and the env is not
scored" — now has a maintained live harness:
`scripts/vm-config-smoke.mjs --negative`. The smoke's base spec also
caught up with reality (gateway declares dns+dhcp, mail depends on
the directory), so the positive pass covers every current probe.

Live on KVM (baked x86_64, 6 guests): positive readiness all PASS;
stop `apache2` on web-01 → readiness fails naming
`web-01 http/apache-php/http-2xx` (plus the dependent `lab/http`
from db-01); restart → green. Stop `postgresql` on db-01 →
readiness fails naming `db-01 db/postgres/sql-select` (plus
`lab/sql` from web-01); restart → green.
`VM READINESS NEGATIVE SMOKE OK`, no leaked QEMU. In the workflow,
`readinessActivity` throws on any failed host before the canary/
proof gates and the exercise, so this failure mode blocks scoring —
the same fail-closed path the scored runs exercise.

Unit collateral: a spec-level test pins that a disabled service
fails by host+service while an unrelated host still passes, and
that the smoke carries the `--negative` mode.

Gates: root build + typecheck pass, backend 257/257, marketing 1/1,
frontend oxlint 0/0. No worker restart needed (harness-only change;
the running Linux worker already carries the readiness code it
exercises).

T-16's stated acceptance criteria are now evidenced for the VM
runtime. The task stays **partial** only on items outside that
acceptance text: the container readiness executor (containers keep
their Docker gates; `readinessActivity` returns `readiness:skipped`
for non-VM specs) and bridge/tap L2 from T-15.

## 2026-11-04 - Container readiness executor; T-16 done

The readiness gate no longer skips container specs.
`checkSpecReadiness` takes a runtime pass (default `vm`, byte-for-byte
the previous behavior including lab/zone/log proofs); the container
pass probes each container host over `docker exec` via the new
`execInContainerShell` (platform probe commands only, failures throw
so probes fail closed — unlike the agent-argv exec whose errors are
swallowed for telemetry judging). Container specs are legacy
role-based, so `checkHostReadiness` derives the one declaration the
role image serves (web→`http/apache-php`, db→`db/postgres`) when no
`serviceDecls` are present. `readinessActivity` runs the VM and/or
container passes and audits the combined result once;
`readiness:skipped` now only occurs for a spec with neither runtime.
Workflow order already runs configure before readiness, so the
deployed app exists when the http probe runs.

Live against the real role images (`php:8.2-apache`,
`postgres:16-alpine`) with the app deployed the way configure does
it: positive readiness green (ssh-login-as-root transport check,
http-2xx, sql-select); removing the deployed index fails readiness
naming `web-01 http/apache-php` (403) while db stays green and the
container itself stays up. Pinned by "container readiness:
role-derived probes run over docker exec; VM default unchanged".

Gates: root build + typecheck pass, backend 259/259, marketing 1/1,
frontend oxlint 0/0. Linux worker restarted onto the build (the
restructured activity keeps the VM pass intact; the container pass
runs wherever the container worker runs).

T-16 is **done**: its acceptance (6-host org with every declared
service probe-passing, the named cross-service proofs, and
service-disabled readiness failure by name) is evidenced on the VM
runtime live, and readiness now executes on both runtimes. Bridge/
tap L2 stays open under T-15, where it always lived.

## 2026-11-04 - Trigger run records pin design provenance (T-17)

`runRecordFor` no longer stores the bare spec digest. The new
`pinForSpec` recovers provenance without a schema change: archetype
materialization is deterministic, so a stored spec that digest-equals
a materialized archetype (budgets excluded, opt-in attacker guest
stripped) pins as that archetype; every other spec pins as
model-authored with the executing build's catalog/profile/image
versions. Cold repro checks the pinned contract while
`environments.spec_digest` remains the bare digest used for approval
verification.

The focused test first failed on the missing `pinForSpec`, then
passed for the clinic, attacker variant, TTL variant, model-authored
spec, and trigger record. Live clinic deployment `6f5df34c-…`
completed and was destroyed by its workflow; its run row carries
`sha256:6782bc9df574…`, exactly the expected pin for
`clinic@1 / arena-catalog-4 / arena-profile-2 /
arena-golden-debian12-catalog-3`, distinct from the environment's
bare `sha256:f7bcbbc082f7…`.

## 2026-11-04 - Modal agents default; personas on Glimmer

Agents now follow the designer's surface precedence: an explicit
platform surface always wins, while an unset surface selects Modal
when Modal tokens are configured and Meta otherwise. A half-set
Modal pair still fails at client construction instead of silently
substituting Meta. On Modal, red/blue/judge use Muse Spark; the
small, high-volume persona agents use Muse Glimmer 30B on the
separate `ep-glimmer` SGLang endpoint. Repository IDs canonicalize
to Glimmer's served name (`glimmer`), endpoint selection is by model
ID, and Glimmer requests use its deployment contract
(`reasoning: {enabled: true}`, `tool_choice: "auto"`, `top_p: 0.9`)
instead of Spark's `reasoning_effort` field.

The registry allowlist now accepts Muse Spark Open and Muse
Glimmer on `meta-modal`, rejects other Modal IDs, and still rejects
Glimmer on the Meta API surface. Resolution is surface-aware through
registry lookup, pinned models, deployment fallbacks, VM/container
fallbacks, and the exercise activity. Glimmer warm-up now starts at
deploy time whenever agents will run on the effective Modal surface;
the existing two-minute persona fallback to Spark remains.

Live Glimmer verification from the production client: wake succeeded
after 207s from cold, structured output returned
`{"name":"Ada","age":36,"city":"London"}`, a `get_weather` tool
call was emitted for London, and the follow-up turn answered from
the tool result (`sunny`, 21°C). The Linux worker was rebuilt and
restarted on this routing code and reports `linux-kvm` RUNNING.
Full gates pass: root build/typecheck, backend **263/263**,
marketing **1/1**, frontend oxlint **0/0**.

Not claimed: a complete live model-agent exercise scored with this
new default routing, or a trainer-produced model becoming ready.
This entry verifies endpoint/client routing and live tool turns, not
a full red/blue campaign.
