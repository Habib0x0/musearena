# Getting started

This guide takes you from a clean checkout to a scored exercise.

## Before you start

Install these tools:

- Node.js 18 or newer
- Supabase CLI 2.117 or newer
- QEMU and Ansible, if you want VM ranges

Check that you have the keys you need:

- A Supabase project, or a local stack from the CLI
- A sign-in key from the identity provider
- A Meta model API key, if you want model agents

## Step 1: Build

```sh
npm install
npm run build
```

## Step 2: Start the database

```sh
cd backend
supabase start
supabase db push
```

The command prints the local addresses. You need the API URL and the service
key for the next step.

## Step 3: Set the environment

Copy `.env.example` to `.env` at the repo root. Fill in:

- `SUPABASE_URL` — the API URL from step 2
- `SUPABASE_SERVICE_ROLE_KEY` — the service key from step 2
- `VITE_CLERK_PUBLISHABLE_KEY` — your sign-in key

## Step 4: Start the services

The worker needs a Temporal server. If you do not run one, start a local
development server first:

```sh
temporal server start-dev --port 7234
```

Open three terminals:

```sh
node backend/dist/designer/server.js   # designer, port 8787
node backend/dist/api/main.js          # learning API, port 8788
node backend/dist/worker.js            # worker; needs Temporal on 7234
```

## Step 5: Open the console

```sh
cd frontend
npm run dev
```

The console opens at `http://localhost:5173`. Sign in with an account that
has an org role.

## Step 6: Run an exercise

1. Go to **Designer**.
2. Write a prompt that describes a scenario. Example: a clinic network with a
   patient database and a weak web server.
3. Review the design. Check the topology, the cost per hour, and the planned
   objectives.
4. Approve the design. The worker starts the machines, configures them, and
   runs the readiness checks.
5. When the checks pass, the exercise starts on its own. Red attacks. Blue
   defends.
6. When the exercise ends, open **Monitoring** to see the score. Open **Red
   team** or **Blue team** to see the evidence behind it.

## Step 7: Work with the results

Open **Learning** to see what the exercise produced:

- **Data** — every trace step, with its source and outcome.
- **Datasets** — the joined snapshot of the run.
- **Signals** — what the monitors found.

From here you can correct labels, build training datasets, and start the
training loop. See `docs/learning-api.md` for the full route list.

## Common problems

**The console shows "not configured".**
Set `VITE_DESIGN_API_URL` and `VITE_LEARNING_API_URL`, or run the services on
their default ports.

**A deployment stays in `pending`.**
The worker is not running, or it cannot reach the database. Check the worker
terminal.

**The exercise scored 0/0.**
The red agent did not reach an objective, or the join found no matched
evidence. Open the red team page and read the trajectory. A score of zero
with clean evidence is a valid result.

**Training stops in `awaiting_trainer`.**
No trainer endpoint is set. Set `META_TRAINER_URL`, or leave the run parked.
A parked run never reports success.

**A delete is refused.**
The platform refuses to delete imported or field traces, because they are
provenance evidence. A trace inside a chain is tombstoned, not removed.

## Next steps

- Read `docs/learning-api.md` for the route reference.
- Run `cd backend && node scripts/org-demo.mjs` for a full VM demo.
- Read `.muse/specs/follow-on-platform/progress.md` for the state of each
  feature.
