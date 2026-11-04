import type { EnvironmentSpec } from "@musearena/shared";
import { ipaDomainFor } from "../configurator/dns.js";
import { ipaUserIdFor, ipaUserSecret } from "../configurator/lab.js";

/**
 * Kerberos identity for a persona shift on a FreeIPA member (P4 follow-up).
 *
 * The persona is a real directory user; the workstation is a member when it
 * `dependsOn` the FreeIPA server. The shift then runs every rendered command
 * through `sudo -u <uid>` with a per-persona FILE ccache, obtained with a
 * non-interactive `kinit` (O-6). The setup proves the credential with a
 * GSSAPI bind before the shift starts, so a failed kinit or missing ticket
 * fails closed instead of quietly running as the SSH user.
 */
export interface PersonaKerberos {
  user: string;
  ccache: string;
  ldapUri: string;
  /** Host-side setup: install the pty helper, kinit, verify klist + GSSAPI. */
  setupCommand: string;
}

const KINIT_HELPER = [
  "import os,pty,sys",
  "user,ccache=sys.argv[1],sys.argv[2]",
  "pw=sys.stdin.readline().rstrip('\\n')",
  "os.environ['KRB5CCNAME']='FILE:'+ccache",
  "def read(fd):",
  "    d=os.read(fd,1024)",
  "    if b'assword' in d: os.write(fd,(pw+'\\n').encode())",
  "    return d",
  "pty.spawn(['kinit',user],read)",
].join("\n");

const shq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/**
 * The persona's Kerberos context when its workstation is a FreeIPA member,
 * otherwise null. A member with an unusable persona id throws: silently
 * falling back to a non-directory user would make the shift claim false.
 */
export function personaKerberosFor(
  spec: EnvironmentSpec,
  runId: string,
  persona: EnvironmentSpec["personas"][number],
): PersonaKerberos | null {
  const ipaHost = spec.instances.find((i) =>
    (i.serviceDecls ?? []).some((d) => d.kind === "ldap" && d.impl === "freeipa"));
  const ws = spec.instances.find((i) => i.hostId === persona.workstation);
  if (!ipaHost || !ws || ws.runtime !== "vm" || !(ws.dependsOn ?? []).includes(ipaHost.hostId)) {
    return null;
  }
  const user = ipaUserIdFor(persona.id);
  if (!user) throw new Error(`persona ${persona.id}: no usable directory uid for a Kerberos shift`);

  const tag = runId.replace(/[^A-Za-z0-9._-]/g, "").slice(0, 48) || "run";
  const ccache = `/tmp/arena-krb5-${tag}-${user}.ccache`;
  const helper = `/tmp/arena-kinit-${tag}-${user}.py`;
  const ldapUri = `ldap://${ipaHost.hostId}.${ipaDomainFor(spec)}`;
  const password = Buffer.from(ipaUserSecret(runId, persona.id), "utf8").toString("base64");
  const helperB64 = Buffer.from(KINIT_HELPER, "utf8").toString("base64");

  const runAs = (command: string) =>
    `sudo -n -u ${shq(user)} env KRB5CCNAME=${shq(`FILE:${ccache}`)} ${command}`;

  const setupCommand = [
    "set -eu",
    `rm -f ${shq(helper)} ${shq(ccache)}`,
    `printf '%s' ${shq(helperB64)} | base64 -d > ${shq(helper)}`,
    // The helper has no secret (the password arrives on stdin); it must be
    // readable by the persona, not just the SSH user.
    `chmod 755 ${shq(helper)}`,
    // The password is piped as base64 on stdin, never in argv: the helper
    // reads one line and feeds the pty prompt.
    `printf '%s' ${shq(password)} | base64 -d | ${runAs(`python3 ${shq(helper)} ${shq(user)} ${shq(ccache)}`)}`,
    `${runAs("klist >/dev/null")}`,
    `out=$(${runAs(`ldapwhoami -Y GSSAPI -H ${shq(ldapUri)}`)})`,
    `printf '%s\\n' "$out"`,
    `printf '%s' "$out" | grep -q ${shq(`dn: uid=${user},`)} || { echo ${shq(`persona ${user}: GSSAPI bind did not return the directory user`)}; exit 1; }`,
    "echo kerberos-ready",
  ].join("\n");

  return { user, ccache, ldapUri, setupCommand };
}
