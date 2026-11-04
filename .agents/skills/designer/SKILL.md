---
name: musearena-designer
description: Design MuseArena environments — the prompt-to-spec pipeline, the closed capability catalog, archetypes, personas, planted vulns, and the CVE target registry. Use this skill when a task changes what the designer may emit, adds services or archetypes, wires new prompt context, or debugs why a design was rejected at validation.
---

# MuseArena designer

The designer turns a natural-language prompt into an `EnvironmentSpec`. It is
a closed system: the model may only emit what the runtime can install,
configure, and verify. Anything outside the catalog is rejected at design
time with the reason — never silently approximated.

## Pipeline

`backend/src/designer/pipeline.ts` is the entry. The system prompt is
assembled from four sources, in this order:

1. `agents/prompts/designer.md` (or the inline fallback)
2. Capability catalog — `configurator/catalog.ts` (`SERVICE_CATALOG`)
3. Org archetypes — `designer/archetypes.ts` (`archetypeCatalogText()`)
4. CVE targets — `configurator/vuln-targets.ts` (`vulnTargetCatalogText()`)

A design that passes the model still passes through `coherence.ts`
validation: every persona.workstation, plantedVuln.targetHostId, and
objective.asset must be a real instance hostId; every objective needs a
non-empty successSignal and techniqueId.

## What the designer may emit

| Concept | Source of truth | Rule |
|---|---|---|
| Service kinds | `ServiceKind` enum in `shared/src/index.ts` | closed set: dns, dhcp, ldap, smtp, imap, http, db, ssh, log, router, git |
| Service impls | `SERVICE_CATALOG` | each kind has approved impls with packages/units/probes |
| Personas | `Persona` schema | generated per environment; live inside `spec.personas` |
| Objectives | `Objective` schema | need techniqueId + successSignal + points |
| Planted vulns | `PlantedVuln` schema | types: `cve`, `misconfig`, `weak-cred`, `code-flaw` |
| CVE targets | `VULN_TARGETS` registry | `type: "cve"` must reference a registry id or pinnedVersion |

## Adding a capability

1. Add the catalog entry in `configurator/catalog.ts` (packages, units,
   readyWhen probe, telemetry, task groups).
2. Implement the task groups in `configurator/profiles.ts` or `ansible.ts`.
3. Bump `CATALOG_VERSION` if semantics changed — the version is pinned per
   run, so old runs stay reproducible.
4. Add the readiness probe if `readyWhen` is new.
5. Test: the designer rejects the design if any declared service is outside
   the catalog, so a catalog entry without tasks fails at configure time —
   never ship one half.

## Personas

Personas are per-environment, generated at design time from the archetype or
the model's spec. They are stored inside the environment's spec. The console
groups them by environment (`api.personasByEnvironment()`); never merge
casts across environments — a persona exists only inside its design.

## CVE targets in designs

The prompt lists registry targets like:

```
- cve-2018-9205-jquery-file-upload (CVE-2018-9205, T1190, role web): ...
```

The designer references them as `plantedVulns: [{ id: "cve-2018-9205-jquery-file-upload", type: "cve", ... }]`.
The configurator plants the files; the gate executor runs the exploit; the
exercise cannot be scored unless the exploit actually fired. See the
`musearena-vuln-targets` skill for adding registry entries.

## Files

- `backend/src/designer/pipeline.ts` — prompt assembly, streaming
- `backend/src/designer/coherence.ts` — validation rules
- `backend/src/designer/archetypes.ts` — versioned org shapes
- `backend/src/configurator/catalog.ts` — the closed service catalog
- `backend/src/configurator/vuln-targets.ts` — CVE registry
- `shared/src/index.ts` — the EnvironmentSpec contract
