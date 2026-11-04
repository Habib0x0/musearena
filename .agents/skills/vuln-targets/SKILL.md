---
name: musearena-vuln-targets
description: Add or modify gate-verified vulnerable targets (CVE registry) that exercises train against — registry entries, planting, exploit proofs, and the Sigma detections blue is graded on. Use this skill when a task adds a CVE or vuln class, changes exploit/proof steps, or touches backend/src/configurator/vuln-targets.ts or the proof executors.
---

# Vulnerable-target registry

The CVE training substrate. Each entry is a vulnerability the platform can
plant, exploit, and prove — before an exercise counts, the gate executor
fires the exploit and observes the marker in the target's own telemetry.
The platform never claims a CVE it cannot fire.

## The flywheel this serves

fresh CVE → planted machine → red exploits it → traces of the real exploit
→ blue detects (or misses) → joined ground truth → labeled pairs → both
models train → next CVE batch is a fresh held-out suite.

## Registry shape (`backend/src/configurator/vuln-targets.ts`)

```ts
{
  id: "cve-2018-9205-jquery-file-upload",  // also the Sigma rule id
  cveId: "CVE-2018-9205",
  summary: "...",
  os: "Debian 12",
  role: "web",                            // host role that carries it
  techniqueId: "T1190",                   // ATT&CK technique scored
  vulnerableVersion: "upload-9.22.0",     // the pin; never substitute a patch
  install: ["...shell prep..."],          // configure-time prep
  files: [{ path, body }],                // the vulnerable app, planted verbatim
  exploitSteps: ["...{host}...{marker}..."], // multi-step, run by the gate
  proofLog: "sudo -n tail -n 200 /var/log/apache2/error.log",
}
```

Step templates: `{host}` is the vantage address (127.0.0.1 in-guest, the
host id from the attacker container); `{marker}` is the per-run proof
marker. The marker MUST appear in `proofLog` — exit codes never count.

## Hard rules

1. Plant the vulnerable version. Never substitute a patched build; if the
   version cannot be sourced, the deployment fails loudly.
2. The exploit must be observable: marker in a service log, not an exit code.
3. A Sigma rule with the same id must exist in `backend/detections/`.
   The parser (sigma.ts) supports contains/startswith/endswith modifiers
   and and/or/not/parens/`1 of x*` conditions — no regex.
4. Unknown registry ids fail closed in both executors (vm, docker): the
   gate throws, the exercise never scores on an unproven vuln.
5. Sigma conditions must not false-positive on benign use. Test the benign
   case explicitly (see test/vuln-targets.test.mjs).

## Where things wire

| Concern | File |
|---|---|
| Registry + binding | `backend/src/configurator/vuln-targets.ts` |
| Planting (VM/Ansible) | `backend/src/configurator/ansible.ts` `tasksFor` |
| VM proof executor | `backend/src/configurator/vm-executors.ts` |
| Docker proof executor | `backend/src/configurator/docker-executors.ts` |
| Role/type allowlist | `backend/src/provisioner/roles.ts` `PLANTABLE` |
| Designer prompt | `backend/src/designer/pipeline.ts` (`vulnTargetCatalogText`) |
| Blue's detections | `backend/detections/*.yml` |

## Adding an entry — checklist

1. Write the registry entry (id, cveId, techniqueId, files, exploitSteps,
   proofLog). Use `writeFileTask`-friendly paths under /var/www/html.
2. Add `backend/detections/<id>.yml` — same id, same techniqueId.
3. Extend `backend/test/vuln-targets.test.mjs`: resolve by id and by
   pinnedVersion, exploit steps bind host+marker, Sigma fires on the
   exploit telemetry, Sigma stays silent on benign use.
4. `cd backend && npm run build && npm test` — all green before commit.
5. The designer picks it up automatically via the prompt catalog text.

## Honest limits

- `pinnedVersion` is currently a label for app-file targets; true apt
  version pinning needs a package snapshot mirror (old debs vanish from
  live repos). Do not claim "real old package" until that exists.
- Supply-chain simulation (trojaned packages) is not in scope; the
  implant-side pattern (backdoored file + beacon behavior + Sigma) is the
  supported shape.
