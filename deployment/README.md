# deployment/

Platform plane IaC (TypeScript + Pulumi Automation API, local file state).
Target environments are provisioned by `backend/src/provisioner`, not here.

## What `up` creates (single host, Docker)

| Service | Image | Host port |
|---|---|---|
| Temporal (+ Postgres) | temporalio/auto-setup:1.24.2 | 127.0.0.1:7234 |
| Langfuse v3 web / worker (+ Postgres, ClickHouse, Redis, MinIO) | langfuse/langfuse:3 | 127.0.0.1:3100 |
| Prometheus (scrapes worker `/metrics` on :9464) | prom/prometheus:v2.55.1 | 127.0.0.1:9095 |

All published ports bind to loopback. Data stores have no published ports.
Secrets are generated on first `up` and kept as encrypted stack config
(passphrase: `PULUMI_CONFIG_PASSPHRASE` or `~/.musearena/platform-passphrase`).
Langfuse is initialised headlessly with org `musearena`, project
`musearena-runs`, and project API keys for the workers.

## Run

```sh
npm run up -w deployment       # create/update; waits for Langfuse health
npm run status -w deployment   # print endpoints; rewrites .platform.env
npm run destroy -w deployment  # remove everything (volumes included)
```

`up`/`status` write `deployment/.platform.env` (0600, gitignored) with
`TEMPORAL_ADDRESS`, `LANGFUSE_*` and `WORKER_METRICS_PORT`. Start the worker
with it:

```sh
cd backend && set -a && source ../.env && source ../deployment/.platform.env && set +a && node dist/worker.js
```
