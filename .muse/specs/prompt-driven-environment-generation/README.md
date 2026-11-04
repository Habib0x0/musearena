# MuseArena — Prompt-Driven Environment Generation

Status: draft · Spec: prompt-driven-environment-generation (revised 2026-10-27)

## Summary

MuseArena is a full-stack platform where teams and AI labs describe a cybersecurity training environment in natural language and receive a complete, deployable, intentionally vulnerable virtual organization: tiny Linux VMs with real services (gateway/DNS/DHCP, directory, mail, intranet, databases), personas who use them, and planted weaknesses — each machine's services installed, seeded, and readiness-verified before anything runs. Offensive and defensive agents then exercise the organization autonomously; every action is observed (Langfuse trajectories joined with environment ground truth), scored from evidence only, and traces feed model/agent training and evaluation.

This spec's primary shape is the designer-built full-org lab on a Linux/KVM host (tasks Phase 7). The earlier container web/db loop remains as a verified dev/regression runtime.

## Key project decisions

- Monorepo: `backend/`, `frontend/`, `shared/`, `deployment/` (npm workspaces, TypeScript everywhere).
- Stack: Clerk (identity) + Supabase (Postgres/RLS, Storage, Edge Functions, Realtime, Vault); containerized TypeScript workers for agents/Pulumi/Ansible; Temporal for durable execution; one agent framework on Meta Model API (Muse); Langfuse for agent traces.
- Multi-tenancy from day one: tenant context enforcement, PostgreSQL RLS, hash-chained audit logs, encrypted credentials.
- Lifecycle: create/stop/start/destroy with drift detection; cost estimates up front with budget acknowledgment.
- Providers: local Linux/KVM (Pulumi) is the primary org-lab backend, per-instance runtime `vm`; the Docker `container` runtime stays for the dev scenario; AWS/GCP are deferred behind the same provider-neutral spec.
- MITRE ATT&CK technique library as the versioned basis for attack/defense content.
- Platform agents: orchestrator → designer → IaC generator → provisioner → infra designer → configurator → observability → evaluator. Agent runtime: Meta agentic API (meta-model-cookbook). Trajectories: Langfuse.
- Infrastructure discipline: canonical resource types (never Pulumi URN strings in app code), tenant-isolated Pulumi stack state, collision-safe CIDR allocation (10.0.0.0/8 → /16 blocks).

## Out of scope for this slice

- Windows/AD guests (need a licensed image; such designs are blocked, not approximated); AWS/GCP provider branches; KVM-VMI truth claims (KVM runs are `mirror-only`); template marketplace/versioning UI; SOC2/compliance pack; RL training harness (traces are captured and exportable; training pipelines are a later spec); production use with real organizational data.
