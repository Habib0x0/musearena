# MuseArena

Turn a prompt into a live cyber range. Run scored attack and defense
exercises in it. Turn the results into training data for language models.

You describe an organization — a clinic network, a directory service, a
patient database, a weak web server. MuseArena designs the range, starts
real virtual machines, configures real services, and plants real
weaknesses. A red agent attacks. A blue agent defends. When it is over,
you get a score backed by evidence you can verify yourself, and a dataset
built from what actually happened.

Every number has a proof path. A claim without evidence does not count —
not in the score, not in the dataset, not anywhere.

## Contents

- [How it works](#how-it-works)
- [What a run looks like](#what-a-run-looks-like)
- [Quickstart](#quickstart)
- [Architecture](#architecture)
- [The training loop](#the-training-loop)
- [Evidence and integrity](#evidence-and-integrity)
- [Safety rules](#safety-rules)
- [Telemetry](#telemetry)
- [Contributing](#contributing)
- [License](#license)

## How it works

1. **Design.** You describe a scenario in a prompt. The designer makes a
   topology, picks services and weaknesses, and checks the cost against a
   budget. You can change the design before you approve it.
2. **Deploy.** The worker starts the machines on QEMU or Docker, configures
   them, and runs readiness checks. Nothing runs before the checks pass.
3. **Exercise.** A red agent tries to reach its objectives. A blue agent
   watches the logs and responds. Both act inside the range only.
4. **Score.** The platform matches each red action to ground truth. It
   counts objectives, points, detections, and false positives. The score
   comes from matched evidence, not from what an agent says about itself.
5. **Publish.** The platform stores a joined dataset of the run. The dataset
   is content-hashed and read-only. Raw traces are append-only and
   hash-chained, so no one can change history without detection.
6. **Learn.** You review traces, correct labels, build training datasets,
   and send them to a training run. A trained model must beat the base
   model on a held-out suite before it is deployed.

## What a run looks like

The six-guest clinic lab that ships with the demo (`backend/scripts/org-demo.mjs`):

| | |
|---|---|
| **Machines** | gateway/DNS, directory (FreeIPA), mail, intranet, patient DB, log collector |
| **People** | eight personas acting on the network — staff, admins, an outsider |
| **Attack** | red agent works toward three objectives mapped to MITRE ATT&CK techniques |
| **Defense** | blue agent watches auth and request logs, raises detections, blocks |
| **Output** | score report, joined trajectory dataset, Sigma detections, provenance |

A run takes about two minutes on an HVF-accelerated laptop, longer on
pure emulation. Every step of the pipeline — provision, configure,
readiness, gates, exercise, score, publish — is a checked stage with a
pass/fail state, not a best-effort attempt.

## Quickstart

Requirements: Node.js 18+, npm 9+, the Supabase CLI, QEMU + Ansible for
VM ranges (HVF on macOS, KVM on Linux).

```sh
git clone https://github.com/Habib0x0/musearena.git && cd musearena
npm install
npm run build
```

Start a database and apply migrations:

```sh
cd backend
supabase start
supabase db push
```

Copy `.env.example` to `.env` and `.env.local` and fill in the keys you
have (a Clerk sign-in key, a Supabase URL + service key; model keys only
if you want model-driven agents).

Start the services (each in its own terminal):

```sh
temporal server start-dev --port 7234        # worker dependency
node backend/dist/designer/server.js         # designer,   port 8787
node backend/dist/api/main.js                # learning,   port 8788
node backend/dist/worker.js                  # worker
cd frontend && npm run dev                   # console,    port 5173
```

Open `http://localhost:5173`, sign in, and run the six-guest demo from
the Designer — or headless:

```sh
cd backend
node scripts/org-demo.mjs          # full run
node scripts/org-demo-replay.mjs   # offline: verify the dataset hash
```

Full walkthrough with troubleshooting: [`docs/getting-started.md`](docs/getting-started.md).

## Architecture

```
            ┌────────────┐   prompt   ┌────────────┐
            │  console   │───────────▶│  designer  │ spec + plan + cost
            │ (React/Vite)│◀───────────│ (port 8787)│ digest-pinned
            └─────┬──────┘  design    └────────────┘
                  │ approve
                  ▼
            ┌────────────┐   claim    ┌────────────┐
            │  Supabase  │◀──────────▶│   worker   │ QEMU/Docker guests
            │ (Postgres, │            │ (Temporal) │ configure → gates →
            │  RLS,      │            └─────┬──────┘ exercise → score →
            │  storage)  │                  │        publish
            └─────┬──────┘                  ▼
                  │            traces · datasets · models
                  ▼
            ┌────────────┐
            │ learning   │  review · datasets · training · evaluation
            │ API (8788) │  append-only, hash-chained evidence
            └────────────┘
```

| Folder | Purpose |
|---|---|
| `backend/` | All server code: designer, worker, learning API, provisioner |
| `frontend/` | The web console that operators use |
| `shared/` | Contracts that both frontend and backend use |
| `deployment/` | Infrastructure code for platform services |
| `agent-guard/` | Local approval gateway for agent traffic and tool calls |

Packages are independent. They talk through `shared/` contracts only;
the frontend never imports backend code.

## The training loop

The part that makes it more than a range generator:

1. **Capture** traces from exercises — or import runs from an external
   harness with a capture key, tagged `imported` or `field` provenance.
2. **Review** — correct a label, or file a dispute and adjudicate it.
   Edits are overlays; the stored trace never changes.
3. **Build** a dataset by role (red/blue), technique, outcome, signal
   hit, or correction. Enforce a minimum share of real (non-synthetic)
   data. One scenario family cannot straddle train and test splits.
4. **Train** — a run pins its dataset, base model, and budget before it
   starts. No trainer connected? It parks in `awaiting_trainer` until one is.
5. **Evaluate** the candidate against the untrained base on a held-out
   suite. A model that never beat the base never reaches production.
6. **Deploy** with traffic pinning and rollback, or keep promoting
   manually — nothing auto-promotes.

Models come from Meta's surfaces only (the Meta model API and
Modal-hosted Muse endpoints), enforced in code by a fail-closed
allowlist. The point of the loop is that a trained candidate must beat
the untrained base on real exercises — and prove it.

## Evidence and integrity

- **Hash-chained traces.** Each trace row links to the previous one;
  `trace_chain_verify` finds the first broken link. Deleting is
  tombstoning — the chain stays intact and verifiable.
- **Content-hashed datasets.** The same selection always produces the
  same hash; an unchanged hash reuses the stored files.
- **Append-only corrections and audit.** Review history and the audit
  log cannot be rewritten. A broken chain is itself evidence.
- **Split hygiene.** Families cannot appear in two splits; the builder
  refuses leakage rather than warning about it.
- **Redaction.** Secrets are stripped at capture time by a versioned
  policy, before anything is stored.

## Safety rules

- Agents act only inside their range. Traffic that would leave it is
  rejected.
- Rules of engagement refuse installers and privilege escalation by
  default, and a blue "block" must actually cut the attacker off before
  it counts as containment.
- The audit log names who did what, on every write action.
- Org isolation is enforced by Clerk claims + Postgres RLS, not by
  convention.

## Telemetry

MuseArena makes **no network calls for analytics by default**. The
console ships without a key, and without a key the analytics module is a
no-op. If you want to share anonymous usage data, set `VITE_POSTHOG_KEY`
— what is sent is page views and (if you sign in) a user identifier, and
nothing else. See `frontend/src/analytics/posthog.tsx` for the exact
code path.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) first — especially the "what
we will not accept" section, because the evidence guarantees are the
product.

## Verification

```sh
cd backend && npm test          # unit suite
cd backend && node scripts/learning-smoke.mjs   # 36 live checks
                                # against a local Supabase stack
```

The live smoke covers capture, review, adjudication, signals, dataset
builds with provenance, training-run parking, and the CRUD lifecycle —
each check hits real routes and a real database.

## Spec

The specification lives in `.muse/specs/`: requirements, design, tasks, and
a progress log for each platform generation.

## License

Apache License 2.0 — see [LICENSE](LICENSE). The name "MuseArena" is a
trademark of the project; the code is yours to use under the license.
