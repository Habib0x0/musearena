# MuseArena runbook

Every failure mode the T-5 (provisioning) and T-6 (configuration and proof)
paths can hit, what the system does on its own, and what an operator does.
"Signal" is where it shows up. Commands assume the repo root.

## Bring-up and health

```sh
npm run up -w deployment                      # platform: Temporal :7234, Langfuse :3100, Prometheus :9095
npm ci --prefix backend/policy               # CrossGuard policy pack deps (separate package)
npm run build -w backend
cd backend && set -a && source ../.env && source ../deployment/.platform.env && set +a \
  && node dist/worker.js                      # worker: trigger poll, maintenance workflow, /metrics :9464
node backend/scripts/platform-check.mjs       # RLS isolation, audit chain, Realtime (10 checks)
node backend/scripts/smoke.mjs lifecycle      # full live lifecycle with isolation/proof/dataset/Langfuse assertions
```

Prometheus target `musearena-worker` should be `up`. The `musearena-maintenance`
workflow should be RUNNING in Temporal.

### Model surfaces

An explicit platform `modelSurface` always wins. When a spec leaves it
unset, configured Modal tokens select Modal (a half-set token pair fails
loudly at client construction rather than silently substituting Meta);
otherwise agents use the Meta API. On Modal, red/blue/judge/designer use
Muse Spark (`ep-muse-spark-open`), while the small, high-volume persona
agents use Muse Glimmer 30B (`ep-glimmer`, served model name `glimmer`).
Glimmer requests use `reasoning: {enabled: true}`, `tool_choice: "auto"`,
and the endpoint's `muse` tool-call parser. Both applications scale to
zero: Persona Glimmer warm-up starts during VM deploy, retries the initial
503s, and falls back to Spark for that run only if it does not wake inside
two minutes. A cold Glimmer request can therefore return 503 for several
minutes even though the configuration is correct; a 401 is a token problem,
not a cold start. Override the small tier with `MODAL_GLIMMER_BASE_URL`,
`MODAL_GLIMMER_MODEL_ID`, optional distinct
`MODAL_GLIMMER_PROXY_TOKEN_ID/SECRET`, and
`MODAL_GLIMMER_REASONING_EFFORT` (defaults are in `.env.example`).

### Multi-host workers

Pulumi state, VM registries, and Docker are host-local. Run at most one
worker identity per execution host and give every routed worker a stable
identity before starting it:

```sh
# Linux KVM host
MUSEARENA_WORKER_ID=linux-kvm MUSEARENA_WORKER_ROUTES=kvm,vm node dist/worker.js

# Mac container/HVF host (example policy: leave VM org labs to Linux)
MUSEARENA_WORKER_ID=mac-hvf MUSEARENA_WORKER_ROUTES=container node dist/worker.js
```

The trigger derives the required route from the spec, skips rows owned or
targeted elsewhere, stamps `workerId` / `workerRoute` / `workerTaskQueue`
into `access_info` on the conditional claim, and starts the workflow on
`musearena-<worker-id>`. Maintenance TTL/drift act only on rows owned by
that worker. Existing unowned rows are handled only by a legacy worker or a
worker started with `MUSEARENA_WORKER_OWNS_UNROUTED=1`; designate at most one
such worker. Smoke scripts can force a host with
`MUSEARENA_TARGET_WORKER_ID=<worker-id>`. Before starting a Linux worker,
require `node backend/scripts/host-preflight.mjs --require-kvm` to pass; it
checks the Docker daemon (not just the CLI), Pulumi, Ansible, and the policy
pack dependencies. On an unbaked base image, first-boot package installs can
outlast the VM workflow smoke's baked-image timing, so run it with e.g.
`VM_WORKFLOW_TTL_HOURS=0.25 VM_WORKFLOW_READY_TIMEOUT_MS=720000`.

The continual-training sweep is disabled unless
`MUSEARENA_CONTINUAL_SWEEP=1` is set. Enable it on exactly one worker. It
periodically derives labelled-trace, correction, schedule, and
model-agent-run regression aggregates from Supabase, selects the newest built
train dataset and approved ready/available base model for each triggered
role, and creates proposals only. It never approves a proposal or training
run. Scripted runs are excluded from regression. Tune thresholds with the
`MUSEARENA_CONTINUAL_*` variables in the environment example; the worker log
prints `continual sweep: orgs=… proposals=… skipped=… errors=…` each pass.

## Provisioning (T-5)

| Failure | Signal | Automatic handling | Operator action |
|---|---|---|---|
| Spec fails the schema | trigger log `rejected deployment`; row `failed`, `access_info.error` | The row is never claimed, so no workflow starts | Fix the spec in the designer and create a new deployment |
| Spec not deployable (role without telemetry, unplantable vuln, Windows without image, a VM vuln/role outside web→code-flaw / db→weak-cred, or a catalogued service with no task group such as dhcp) | Same as above, reason starts `not deployable:` | Rejected before any resource exists | Change the design, or add a runtime capability (`provisioner/roles.ts`, `capability.ts`) |
| Spec or plan changed since approval | Row `failed`, `access_info.failure.stage=trigger`; reason `stored spec does not match its digest` or `unapproved plan: plan changed since approval …` | Rejected before any resource exists; the approved `planDigest` stays in `access_info` as evidence | Re-approve from the Designer. A catalog/profile/image change moved the plan, or the row was inserted without a plan digest (scripts must record it) |
| CrossGuard deploy gate violation | Row `failed`, `access_info.error` = `deploy gate: <rule> (<resource>)`; audit `PROOF_GATE_DECISION` with `gate: crossguard` | Preview fails **before** `up`, so nothing to roll back | The generator emitted a non-compliant resource. Fix `provisioner/generate.ts`; never weaken `backend/policy` to pass |
| CrossGuard policy pack does not start | Deploy fails with `policy pack not started` and `Cannot find module '@pulumi/policy'` | Preview fails before any resource is created | The policy pack is a separate package. Run `npm ci --prefix backend/policy`, then `node backend/scripts/host-preflight.mjs --require-kvm` on Linux workers |
| `pulumi up` fails partway | Activity failure in the worker log; row `failed` | `stack.destroy()` rollback. If destroy also fails: `drift_status=orphan-suspected` | Let the hourly sweeper reap the labelled resources, or run `maintenancePass()` now (see below) |
| Missing passphrase | `PULUMI_PASSPHRASE ... not set in worker env` | Activity fails, no resources created | Export `PULUMI_PASSPHRASE` (the same value every time, or existing stacks become unreadable) |
| Image pull / provider plugin download blocked | `pulumi up` error mentioning the registry or `get.pulumi.com` | Rollback as above | Pre-pull images (`docker pull`) and pre-install plugins (`pulumi plugin install`). Phase 0 found runtime downloads fail behind the proxy |
| CIDR pool exhausted | `CIDR pool exhausted` | Deploy fails before any resource | Destroy stale deployments. Each live env holds one /16 in 10.2-254 |
| Orphaned containers or networks (a crash between up and DB write, a manual run) | Sweeper audit `DEPLOYMENT_DESTROY` with `orphan: true` | Hourly sweep removes `arena.run_id`-labelled resources whose deployment is missing, destroyed, failed or past TTL | None. To force it now: `node -e "import('./backend/dist/ops/maintenance.js').then(m=>m.maintenancePass()).then(r=>console.log(JSON.stringify(r)))"` |
| TTL expired | Workflow result `...\|ttl-teardown`; row `destroyed` | The workflow timer destroys the env. The hourly maintenance pass is the backstop if the workflow was lost | None |
| Teardown fails | Worker log `destroy` error; row stuck in `destroying` | The maintenance backstop retries hourly; the sweeper removes labelled leftovers | Inspect with `docker ps --filter label=arena.run_id=<run>` |
| Drift (service down, manual change) | `deployments.drift_status = drifted:<hosts>` (Realtime to the UI) | Detected hourly by probing declared services | Re-run configuration, or destroy and redeploy. Drifted envs are not trustworthy for scoring |

## Configuration and proof (T-6)

| Failure | Signal | Automatic handling | Operator action |
|---|---|---|---|
| Ansible task fails on a host | `configuration failed for: <host> (ansible: <recap>; failed task <name>)`; audit `CONFIG_REMEDIATION` carries the same task name | One bounded full re-run, then the workflow tears the env down; not scored | Read `.ansible/<deployment>/ansible.log` beside `playbook.yml`. Every task is a plain `raw` command and can be replayed in the guest/container |
| Sensor canary missing | audit `PROOF_GATE_DECISION` `pass:false`, detail `MISSING from telemetry — sensor blind` | Gate fails closed. Activity retries once with a fresh nonce, then the env is destroyed, unscored | Check the host's service log is reaching `docker logs` (Apache access log, Postgres `log_statement=all`) |
| Planted vuln not proven | `<vuln> proof NOT seen — unsolvable or sensor gap` | Gate fails closed and the env is destroyed | Run the proof by hand from the attacker container (see `configurator/docker-executors.ts`). Check `diag.php` exists (code-flaw) or the weak credential was not rotated (weak-cred) |
| Vuln type not plantable on role | `type <t> is not plantable on role <r>` | Should already be rejected at trigger. The gate fails closed if it is not | Extend `PLANTABLE` together with a real plant and proof, never one without the other |
| Local harness gates enabled by mistake | audit `executor: "local-harness"` | Only VM specs can use them, and only with exactly `MUSEARENA_LOCAL_GATES=1` | Unset the variable on production workers |

## VM labs (T-15/T-16/T-18)

Guests are QEMU VMs on the baked Debian catalog image. Each guest has two
NICs: a **management** NIC on QEMU user-mode networking (SSH hostfwd on
loopback; DHCP, so apt works) and a **lab** NIC on the run's L2 segment
(`backend/src/provisioner/lab-hub.ts`). On the macOS dev host the segment is a
per-run user-space hub — QEMU `socket` netdevs carry frames, the hub relays —
because there is no bridge/tap privilege and host multicast did not deliver
between guests. A Linux reference host still needs the bridge/tap variant.
Lab addresses are static from the spec subnet (gateway `.1`, others `.10+`);
DHCP on the lab segment is not implemented. Run these from `backend/`.

| Failure | Signal | Automatic handling | Operator action |
|---|---|---|---|
| Guest never boots / no SSH | `ssh to <host> (arena@127.0.0.1:<port>) failed` during the identity probe | Deploy rolls back and destroys the run's guests | Read `.disposable/<run>/<host>-serial.log`; check the EDK2 firmware path. Re-check the host with `node scripts/vm-lifecycle-smoke.mjs` |
| Guest has the wrong identity | `guest identity mismatch` (RUN_ID / HOST_ID / hostname) | Fail closed; the run is torn down | Stale overlay or reused seed ISO. Destroy and retry; never reuse a run directory |
| Baked image missing or tampered | `resolveGoldenImage` throws `does not match pinned sha512` | Nothing starts | Rebuild with `node scripts/build-catalog-image.mjs`, then update `golden/baked-images.json` with the new hash |
| Readiness probe fails | `readiness failed: [{hostId, checks:[…ok:false]}]` | Env destroyed, unscored | Run the probe's command by hand over SSH; check the unit and config. A service with no task group (dhcp) is rejected at design time, not here |
| Configure fails on one host | PLAY RECAP for that host has `failed>0` | Env destroyed, unscored | Replay the host's task from `.disposable/ansible/<run>/playbook.yml` over SSH; every task is a plain `raw` command |
| Sensor blind on a VM | canary `MISSING from telemetry` | Gate fails closed | `systemctl status auditd`; the canary is an `auditctl -m` user message that must appear in `/var/log/audit/audit.log` |
| Log collector refuses 514 | readiness `log/rsyslog-collector/tcp` fails | Env destroyed, unscored | `systemctl restart rsyslog` — enabling a unit that is already running does not reload a new `imtcp` input |
| Leaked QEMU after teardown | `pgrep -f musearena-<runId>-` returns pids | `destroyRunVms` kills by pidfile; the smokes fail on a leak | Kill the pids, then remove `.disposable/<run>` |
| Leaked lab hub | `pgrep -f "lab-hub-main.js"` shows a hub with no run | The hub pid is in `vms.json`; `stopRunVms`/`destroyRunVms` signal it, and a failed start kills it in memory | `kill <pid>`; the hub only listens on loopback |
| Lab NIC has no address | `waitForLabAddress` throws; `ip -4 -o addr show` on the guest lacks the lab address | Deploy fails closed (cloud-init final stage did not apply) | Check `/var/log/cloud-init-output.log` on the guest; the seed resolves the NIC by MAC through `/sys/class/net` |
| Cross-host probe fails | readiness `lab-dns` / `lab-http` / `lab-ldap` / `lab-smtp` / `lab-tcp` `ok:false` | Readiness fails closed; env destroyed, unscored | The probe names its client host. Check the listener is bound to the lab address (`ss -ltn`), the gateway's dnsmasq has a `host-record`, and `ip addr` on both guests |
| Orphaned taps/bridges (Linux bridge variant only) | `ip -br link` shows `arena*` devices with no running qemu | **Not swept yet** — that sweeper belongs to the Linux host variant | Remove the device by hand |

Verification sequence (each script deploys and destroys its own guests):

```sh
node scripts/vm-lifecycle-smoke.mjs             # boot, identity, destroy
node scripts/vm-l2-smoke.mjs                    # guest-to-guest TCP over the lab segment
node scripts/vm-config-smoke.mjs                # 6 guests, configure + readiness
node scripts/vm-gates-smoke.mjs                 # canary + proof
node scripts/vm-gates-smoke.mjs --blind-sensor  # sensor-disabled guest fails closed
node scripts/vm-exercise-smoke.mjs              # scripted red/blue + dataset
node scripts/vm-control-smoke.mjs               # benign-only: must raise 0 alerts
node scripts/org-demo.mjs                       # the clinic, one command
node scripts/org-demo-replay.mjs                # offline: verify hash + re-score
node scripts/vm-workflow.mjs                    # the clinic through Temporal
```

## Org-lab demo (T-20)

```sh
cd backend
node scripts/org-demo.mjs                         # live: 6 guests, ~2 min on HVF
node scripts/org-demo.mjs --prompt "<text>"       # model design; needs MODAL_PROXY_TOKEN_* or META_API_KEY
node scripts/org-demo-replay.mjs [captures/org-demo/<runId>]   # offline: verify hash + re-score
node scripts/vm-workflow.mjs                      # same org through Temporal (needs platform + worker)
```

The live run writes `captures/org-demo/<runId>/{run.json,dataset.json,index.html}`
even when it fails (`run.json.error`). Replay needs no VM, network or model and
exits non-zero if the recorded dataset hash or score does not reproduce.

## Exercise, datasets, traces

| Failure | Signal | Automatic handling | Operator action |
|---|---|---|---|
| Alerts on benign traffic | `SCORE_COMPUTED.detail.falsePositiveDetail`; Prometheus `arena_false_positives_total` | FP rate is recorded per run | Tune the rule in `backend/detections/*.yml` (the content hash gives it a new version) and re-record the replay with `scripts/record-replay.mjs`. Check `scripts/control-run.mjs` shows 0 |
| Rule never promoted | `livePack()` lists it under `draft` | Draft rules never score | Add replay evidence (a calibration run that exercises the technique) |
| Dataset upload or verification fails | Activity error `stored export unreadable` / `hash mismatch` | No dataset row is written (rows exist only for verified objects) | Check the `datasets` bucket and the service key |
| Langfuse ingestion fails | `Langfuse ingestion failed (...)` | The exercise activity fails loudly, so a run never claims trajectories that did not arrive | `npm run status -w deployment`; check Langfuse health, then re-run |
| Audit chain broken | `select * from audit_verify('<org>')` returns a row | UPDATE and DELETE on `audit_log` are refused by trigger | Treat as tampering, and investigate with the Supabase SQL editor |

## Recovery commands

```sh
node backend/scripts/cold-repro.mjs <deployment-id>   # redeploy from the stored spec and verify the join/export
node backend/scripts/control-run.mjs 10               # benign-only FP baseline for the current rule pack
docker ps -a --filter label=arena.run_id              # everything the platform ever created for targets
npm run destroy -w deployment                          # remove the platform plane (volumes included)
```

Pulumi destroys the resources but keeps each stack (and its history) under
`.pulumi-state/<org>/` for audit and cold repro. Leaving them is safe — they
hold no live resources — but the directory grows with every deployment, so
prune it only after the corresponding `environments` rows are gone.
