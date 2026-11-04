# backend/

Containerized worker services only — no bespoke API server. One service per
directory (`orchestrator/`, `designer/`, `provisioner/`, `configurator/`,
`evaluator/`), shared helpers in `lib/` only. Imports `@musearena/shared`
contracts; never imports frontend code.
