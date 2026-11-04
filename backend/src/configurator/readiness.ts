import type { EnvironmentSpec, ServiceDecl } from "@musearena/shared";
import { catalogEntry } from "./catalog.js";
import { labSecret, ipaUserIdFor, ipaUserSecret } from "./lab.js";
import { labDomainFor, ldapBaseFor, ipaBaseFor, ipaAdminDnFor } from "./dns.js";
import { dhcpPoolFor, labPlanFor } from "../provisioner/lab-network.js";
import { normalizeOrg, reachabilityFor, negativeProbesFor } from "../designer/org-topology.js";

/**
 * Readiness gate (T-16b): a declared service is ready only when its protocol
 * answers, not when a package installed or a unit is active. Probes run
 * inside the guest over the run's SSH endpoint (see `vm-ssh.ts`), so they
 * exercise the same path a persona or attacker would. Every probe fails
 * closed: a command error, empty output or a missing expected token is a
 * failure, never a warning.
 */

export type ReadyWhen = ServiceDecl["readyWhen"];
export type GuestExec = (hostId: string, command: string, timeoutMs?: number) => Promise<string>;

/**
 * T-40 GSSAPI proofs. These are additive to the declared `readyWhen` probe:
 * a member database still proves LDAP password auth, and additionally proves
 * the Kerberos path against `gssdb`; Dovecot keeps its LDAP passdb and adds
 * the GSSAPI SASL mechanism; Apache keeps its 2xx probe and adds a
 * `--negotiate` location.
 */
export type AdditiveProbe = "gssapi-sql" | "gssapi-http" | "gssapi-imap" | "git-ssh";

export interface ProbeCheck {
  probe: ReadyWhen | AdditiveProbe;
  kind: string;
  command: string;
  /** Token the output must contain; absent means exit status alone decides. */
  expect?: string;
  timeoutMs: number;
}

export type LabProbe = "lab-dns" | "lab-http" | "lab-ldap" | "lab-smtp" | "lab-sql" | "lab-log" | "lab-allow" | "lab-deny" | "lab-dhcp" | "lab-mail";

export interface CheckResult {
  probe: ReadyWhen | LabProbe | AdditiveProbe;
  kind: string;
  ok: boolean;
  detail: string;
}

export interface HostReadiness { hostId: string; ok: boolean; checks: CheckResult[] }

const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/**
 * One protocol probe for a declared service. Ports come from the declaration
 * when present, else the catalog entry, so a moved service is probed where it
 * actually listens.
 */
export interface ProbeContext {
  hostId: string;
  runId: string;
  sshUser: string;
  services: ServiceDecl[];
  /** The environment's derived DNS namespace (`labDomainFor`). */
  domain: string;
  /**
   * When this host is a FreeIPA member and the spec seeds personas, the probe
   * authenticates as a real domain user, not only the local probe account.
   * Absent on unjoined hosts and on specs without personas.
   */
  domainUser?: { uid: string; password: string };
}

export function probeFor(decl: ServiceDecl, ctx: ProbeContext): ProbeCheck {
  const entry = catalogEntry(decl);
  if (!entry) throw new Error(`${ctx.hostId}: service ${decl.kind}/${decl.impl} is not in the runtime catalog`);
  const port = decl.port ?? entry.defaultPort;
  const kind = `${decl.kind}/${decl.impl}`;
  switch (entry.readyWhen) {
    case "ssh-login":
      // The transport already authenticated; a login shell proves the account.
      return { probe: entry.readyWhen, kind, command: "id -un", expect: ctx.sshUser, timeoutMs: 10_000 };
    case "tcp":
      return { probe: entry.readyWhen, kind, command: `timeout 3 bash -c '</dev/tcp/127.0.0.1/${port}'`, timeoutMs: 8_000 };
    case "http-2xx":
      return { probe: entry.readyWhen, kind, command: `curl -fsS --max-time 5 -o /dev/null http://127.0.0.1:${port}/`, timeoutMs: 10_000 };
    case "sql-select": {
      // On a realm member the probe authenticates as a directory user, using
      // Postgres' `ldap` method (a bind as that user against 389-ds). The
      // negative leg matters: a password-less or trust rule would pass without
      // ever consulting the directory.
      if (!ctx.domainUser) {
        return { probe: entry.readyWhen, kind, command: `psql -U app -d app -tAc 'SELECT 1'`, expect: "1", timeoutMs: 10_000 };
      }
      const { uid, password } = ctx.domainUser;
      const good = `PGPASSWORD=${q(password)} psql -h 127.0.0.1 -U ${q(uid)} -d app -tAc 'SELECT 1'`;
      const bad = `PGPASSWORD=${q(`not-${password}`)} psql -h 127.0.0.1 -U ${q(uid)} -d app -tAc 'SELECT 1'`;
      return {
        probe: entry.readyWhen, kind, timeoutMs: 30_000,
        command: `${bad} >/dev/null 2>&1 && { echo 'database accepted a wrong domain password'; exit 1; }; ${good}`,
        expect: "1",
      };
    }
    case "dns-query":
      // dnsmasq serves /etc/hosts; the host must resolve its own name.
      return { probe: entry.readyWhen, kind, command: `dig +short -p ${port} @127.0.0.1 ${q(ctx.hostId)}`, timeoutMs: 10_000 };
    case "dhcp-lease":
      // Local leg: the server is up, bound to UDP/67, and configured with the
      // pool. The lease itself is proven cross-host by the lab-dhcp probe —
      // no client has leased yet when the server's own checks run.
      return {
        probe: entry.readyWhen, kind, timeoutMs: 10_000, expect: "active",
        command: `systemctl is-active dnsmasq && ss -uln | grep -q ':67 ' && sudo -n grep -q '^dhcp-range=' /etc/dnsmasq.d/arena-dhcp.conf`,
      };
    case "ldap-bind": {
      // FreeIPA is Kerberos-backed but still answers a simple bind; its admin
      // DN lives under cn=users,cn=accounts, not cn=admin.
      if (decl.impl === "freeipa") {
        const pw = labSecret(ctx.runId, "ipa-admin");
        return {
          probe: entry.readyWhen, kind, timeoutMs: 15_000,
          command: `ldapsearch -x -H ldap://127.0.0.1:${port} -D ${ipaAdminDnFor(ctx.domain)} -w ${q(pw)} -b ${ipaBaseFor(ctx.domain)} -s base dn`,
          expect: "dn:",
        };
      }
      const pw = labSecret(ctx.runId, "ldap-admin");
      const base = ldapBaseFor(ctx.domain);
      return {
        probe: entry.readyWhen, kind, timeoutMs: 10_000,
        command: `ldapsearch -x -H ldap://127.0.0.1:${port} -D cn=admin,${base} -w ${q(pw)} -b ${base} -s base dn`,
        expect: "dn:",
      };
    }
    case "git-ldap-login": {
      // Directory login through Gitea's LDAP auth source: the API returns the
      // authenticated user, and the same account with a wrong password must
      // fail. A local Gitea account would also answer 200, so the negative leg
      // is what makes this a directory claim.
      if (!ctx.domainUser) {
        throw new Error(`${ctx.hostId}: a Gitea LDAP login is only verifiable with a domain identity (declare dependsOn the FreeIPA server)`);
      }
      const { uid, password } = ctx.domainUser;
      const good = `curl -fsS --max-time 8 -u ${q(`${uid}:${password}`)} http://127.0.0.1:${port}/api/v1/user`;
      const bad = `curl -fsS --max-time 8 -u ${q(`${uid}:not-${password}`)} http://127.0.0.1:${port}/api/v1/user`;
      return {
        probe: entry.readyWhen, kind, timeoutMs: 40_000,
        command: `${bad} >/dev/null 2>&1 && { echo 'gitea accepted a wrong password'; exit 1; }; ${good}`,
        expect: `"login":"${uid}"`,
      };
    }
    case "smtp-imap-roundtrip": {
      const pw = labSecret(ctx.runId, "mail-probe");
      const smtp = ctx.services.find((s) => s.kind === "smtp");
      const imap = ctx.services.find((s) => s.kind === "imap");
      const smtpPort = smtp?.port ?? catalogEntry(smtp ?? { kind: "smtp", impl: "postfix" })?.defaultPort ?? 25;
      const imapPort = imap?.port ?? catalogEntry(imap ?? { kind: "imap", impl: "dovecot" })?.defaultPort ?? 143;
      // Local delivery proof (the message actually lands), then — on a domain
      // member — the directory-auth proof: a seeded persona logs in with its
      // IPA password, and the *same* account with a wrong password must be
      // refused. Two claims, one fail-closed command: any failing leg fails.
      // No `exit` inside the legs: chained with `&&`, an early `exit 0` would
      // report success before the directory proof ever ran.
      if (!ctx.domainUser) {
        const local = `swaks --to probe@${ctx.domain} --server 127.0.0.1 --port ${smtpPort} --silent 3 && ok=0 && for i in $(seq 1 15); do curl -fsS --max-time 5 -u probe:${q(pw)} imap://127.0.0.1:${imapPort}/INBOX >/dev/null && { ok=1; break; }; sleep 1; done; [ "$ok" = 1 ]; exit $?`;
        return { probe: entry.readyWhen, kind, timeoutMs: 30_000, command: local };
      }
      const user = ctx.domainUser.uid;
      const good = `${user}:${ctx.domainUser.password}`;
      const bad = `${user}:not-${ctx.domainUser.password}`;
      // On a member there is no local mailbox user: the message goes to the
      // domain address and is read by the same domain account, so delivery and
      // authentication are both directory-backed.
      const local = `swaks --to ${user}@${ctx.domain} --server 127.0.0.1 --port ${smtpPort} --silent 3 && ok=0 && for i in $(seq 1 20); do curl -fsS --max-time 5 -u ${q(good)} imap://127.0.0.1:${imapPort}/INBOX >/dev/null && { ok=1; break; }; sleep 1; done; [ "$ok" = 1 ]`;
      const directory = `curl -fsS --max-time 5 -u ${q(bad)} imap://127.0.0.1:${imapPort}/INBOX >/dev/null 2>&1 && { echo 'domain account accepted a wrong password'; exit 1; }; true`;
      return {
        probe: entry.readyWhen, kind, timeoutMs: 60_000,
        command: `${local} && ${directory}`,
      };
    }
    default:
      throw new Error(`${ctx.hostId}: no probe implementation for ${String(entry.readyWhen)}`);
  }
}

/**
 * T-40: an additive Kerberos proof for a member service. Returns null on a
 * host without a domain identity (unjoined or no seeded persona), so the
 * existing `readyWhen` contract is unchanged there. Each probe obtains a
 * persona ticket with `kinit` in a private ccache; a missing ticket is a
 * failure, not a fallback to the password path.
 */
export function gssapiProbeFor(decl: ServiceDecl, ctx: ProbeContext): ProbeCheck | null {
  if (!ctx.domainUser) return null;
  const entry = catalogEntry(decl);
  if (!entry) return null;
  const port = decl.port ?? entry.defaultPort;
  const { uid, password } = ctx.domainUser;
  const cc = `/tmp/arena-gss-${ctx.hostId}-${decl.kind}`;
  // The keytab holds a host-based principal (postgres/<fqdn>, HTTP/<fqdn>,
  // imap/<fqdn>), so the client must request that name. Connecting to
  // 127.0.0.1 would ask for */127.0.0.1 and fail with "server not found in
  // Kerberos database" even though the keytab is correct.
  const fqdn = `${ctx.hostId}.${ctx.domain}`;
  const kinit = `printf '%s\\n' ${q(password)} | KRB5CCNAME=${cc} kinit ${q(uid)} >/dev/null 2>&1`;
  const kind = `${decl.kind}/${decl.impl}`;
  switch (decl.kind) {
    case "db":
      return {
        probe: "gssapi-sql", kind, timeoutMs: 30_000,
        command: `${kinit} && KRB5CCNAME=${cc} psql -h ${q(fqdn)} -U ${q(uid)} -d gssdb -tAc 'SELECT 1'`,
        expect: "1",
      };
    case "http":
      return {
        probe: "gssapi-http", kind, timeoutMs: 30_000,
        command: `${kinit} && KRB5CCNAME=${cc} curl -fsS --max-time 8 --negotiate -u : http://${fqdn}:${port}/gssapi/`,
        expect: uid,
      };
    case "imap":
      return {
        probe: "gssapi-imap", kind, timeoutMs: 30_000,
        command: `${kinit} && KRB5CCNAME=${cc} curl -fsS --max-time 8 --negotiate -u : imap://${fqdn}:${port}/INBOX >/dev/null`,
      };
    default:
      return null;
  }
}

/**
 * T-42: Gitea SSH transport as the domain user. The probe clones the public
 * repository over Gitea's built-in SSH server, so it proves the LDAP-backed
 * account, the uploaded key, and the SSH listener together. Per-repo group
 * authorization is a separate smoke proof against the private repository.
 */
export function giteaSshProbeFor(decl: ServiceDecl, ctx: ProbeContext): ProbeCheck | null {
  if (!ctx.domainUser || decl.kind !== "git") return null;
  const entry = catalogEntry(decl);
  if (!entry) return null;
  const port = decl.port ?? entry.defaultPort;
  const { uid, password } = ctx.domainUser;
  const fqdn = `${ctx.hostId}.${ctx.domain}`;
  const dir = `/tmp/arena-git-ssh-${ctx.hostId}`;
  const user = q(`${uid}:${password}`);
  return {
    probe: "git-ssh", kind: `${decl.kind}/${decl.impl}`, timeoutMs: 60_000,
    command: [
      `rm -rf ${dir} && mkdir -p ${dir}`,
      `ssh-keygen -q -t ed25519 -N '' -f ${dir}/key >/dev/null`,
      `curl -fsS --max-time 8 -u ${user} http://127.0.0.1:${port}/api/v1/user >/dev/null`,
      `printf '{"title":"%s","key":"%s"}' "arena-probe-$(date +%s%N)" "$(cat ${dir}/key.pub)" > ${dir}/key.json`,
      `curl -fsS --max-time 8 -u ${user} -X POST -H 'Content-Type: application/json' --data-binary @${dir}/key.json http://127.0.0.1:${port}/api/v1/user/keys >/dev/null`,
      `GIT_SSH_COMMAND="ssh -i ${dir}/key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222" git clone -q ssh://git@${fqdn}:2222/arena/public.git ${dir}/repo`,
      `test -f ${dir}/repo/README.md && echo ARENA-GIT-SSH-OK`,
    ].join(" && "),
    expect: "ARENA-GIT-SSH-OK",
  };
}

const detailOf = (err: unknown) => (err instanceof Error ? err.message : String(err)).slice(0, 300);

/**
 * The directory identity probes authenticate as on this host: the first
 * persona, when the host joins the spec's FreeIPA realm by declared
 * dependency. Undefined for unjoined hosts, the server itself, and specs
 * without personas. Shared by the gate and the planner so the plan renders
 * the same probes readiness will run.
 */
export function domainUserFor(spec: EnvironmentSpec, hostId: string, runId: string): { uid: string; password: string } | undefined {
  const inst = spec.instances.find((i) => i.hostId === hostId);
  const ipaHost = spec.instances.find((i) => (i.serviceDecls ?? []).some((d) => d.kind === "ldap" && d.impl === "freeipa"));
  const isMember = !!inst && !!ipaHost && ipaHost.hostId !== hostId && (inst.dependsOn ?? []).includes(ipaHost.hostId);
  const persona = isMember ? (spec.personas ?? [])[0] : undefined;
  return persona && ipaUserIdFor(persona.id)
    ? { uid: ipaUserIdFor(persona.id), password: ipaUserSecret(runId, persona.id) }
    : undefined;
}

/** Run one host's probes: the SSH login plus every declared service's protocol. */
export async function checkHostReadiness(input: {
  spec: EnvironmentSpec;
  runId: string;
  hostId: string;
  sshUser: string;
  exec: GuestExec;
}): Promise<HostReadiness> {
  const inst = input.spec.instances.find((i) => i.hostId === input.hostId);
  if (!inst) throw new Error(`readiness: unknown host ${input.hostId}`);
  // Container specs are legacy role-based (no serviceDecls): the role image
  // is the service, so derive the one declaration its probe needs.
  const CONTAINER_ROLE_DECLS: Record<string, ServiceDecl> = {
    web: { kind: "http", impl: "apache-php", port: 80, readyWhen: "http-2xx" },
    db: { kind: "db", impl: "postgres", port: 5432, readyWhen: "sql-select" },
  };
  const decls = inst.serviceDecls?.length
    ? inst.serviceDecls
    : inst.runtime === "container" && CONTAINER_ROLE_DECLS[inst.role]
      ? [CONTAINER_ROLE_DECLS[inst.role]]
      : [];
  const checks: CheckResult[] = [];

  const runProbe = async (probe: ProbeCheck) => {
    try {
      const stdout = await input.exec(input.hostId, probe.command, probe.timeoutMs);
      const out = String(stdout ?? "");
      const ok = probe.expect === undefined ? true : out.includes(probe.expect);
      checks.push({
        probe: probe.probe, kind: probe.kind, ok,
        detail: ok ? `${probe.probe} answered` : `${probe.probe} output missing ${JSON.stringify(probe.expect)}: ${out.trim().slice(0, 120)}`,
      });
    } catch (err) {
      checks.push({ probe: probe.probe, kind: probe.kind, ok: false, detail: `${probe.probe} failed: ${detailOf(err)}` });
    }
  };

  // The transport check is implicit; a host that declares ssh itself gets the
  // same probe from the loop below, so do not run it twice.
  if (!decls.some((d) => d.kind === "ssh")) {
    await runProbe({ probe: "ssh-login", kind: "ssh/openssh", command: "id -un", expect: input.sshUser, timeoutMs: 10_000 });
  }
  // A domain member is probed as a real directory user: the same persona the
  // FreeIPA seed created. Derived from the spec, so the probe name and the
  // seeded name cannot drift apart.
  const domainUser = domainUserFor(input.spec, input.hostId, input.runId);
  for (const decl of decls) {
    const ctx = {
      ...input, services: decls, domain: labDomainFor(input.spec),
      ...(domainUser ? { domainUser } : {}),
    };
    await runProbe(probeFor(decl, ctx));
    const gss = gssapiProbeFor(decl, ctx);
    if (gss) await runProbe(gss);
    const gitSsh = giteaSshProbeFor(decl, ctx);
    if (gitSsh) await runProbe(gitSsh);
  }
  return { hostId: input.hostId, ok: checks.every((c) => c.ok), checks };
}

/**
 * Cross-host proofs (T-15/T-16): a service is not lab-ready because the host
 * can reach itself. Each check runs on a *client* guest against another
 * guest's lab address, so it exercises the L2 segment, the listener binding
 * and the protocol together. Addresses and names come from the same pure plan
 * the guests were configured from.
 */
export interface LabProbePlan {
  from: string;
  to: string;
  probe: LabProbe;
  kind: string;
  command: string;
  expect?: string;
  timeoutMs: number;
}

/**
 * Minimal DHCP client (stdlib only) for the lab-dhcp probe: broadcast
 * DISCOVER on the client's lab NIC, REQUEST the offer, print the ACK's
 * leased address. It configures nothing — the lease in the server and the
 * ACK on the wire are the evidence. Args: IF POOL_START POOL_END.
 */
const DHCP_CLIENT_PY = [
  "import socket, struct, sys",
  "IF, LO, HI = sys.argv[1], sys.argv[2], sys.argv[3]",
  "def ipn(s): return struct.unpack('!I', socket.inet_aton(s))[0]",
  "MAC = bytes.fromhex('026172656e61')",
  "xid = 0x4152454e",
  "def pkt(msg, extra=b''):",
  "    p = struct.pack('!BBBBIHH', 1, 1, 6, 0, xid, 0, 0x8000) + bytes(16) + MAC + bytes(74) + bytes(128) + struct.pack('!I', 0x63825363)",
  "    return p + bytes([53, 1, msg]) + extra + b'\\xff'",
  "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
  "s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)",
  "s.setsockopt(socket.SOL_SOCKET, 25, IF.encode() + b'\\x00')",
  "s.bind(('', 68)); s.settimeout(8)",
  "def recv(want):",
  "    while True:",
  "        d, _ = s.recvfrom(2048)",
  "        if len(d) < 240 or struct.unpack('!I', d[4:8])[0] != xid: continue",
  "        yi = socket.inet_ntoa(d[16:20]); opts = {}; i = 240",
  "        while i < len(d) and d[i] != 255:",
  "            if d[i] == 0: i += 1; continue",
  "            opts[d[i]] = d[i+2:i+2+d[i+1]]; i += 2 + d[i+1]",
  "        if opts.get(53, b'\\x00')[0] == want: return yi, opts",
  "s.sendto(pkt(1), ('255.255.255.255', 67))",
  "yi, opts = recv(2)",
  "extra = bytes([50, 4]) + socket.inet_aton(yi)",
  "if 54 in opts: extra += bytes([54, 4]) + opts[54]",
  "s.sendto(pkt(3, extra), ('255.255.255.255', 67))",
  "yi, _ = recv(5)",
  "assert ipn(LO) <= ipn(yi) <= ipn(HI), 'lease %s outside pool %s-%s' % (yi, LO, HI)",
  "print('DHCPACK ' + yi)",
].join("\n");

export function labProbesFor(spec: EnvironmentSpec, runId: string): LabProbePlan[] {
  if ((spec.topology.sites?.length ?? 0) > 0 || (spec.topology.zones?.length ?? 0) > 0) {
    return [];
  }
  const plan = labPlanFor(spec, runId);
  if (plan.length < 2) return [];
  const domain = labDomainFor(spec);
  const ldapBase = ldapBaseFor(domain);
  const roleOf = (hostId: string) => spec.instances.find((i) => i.hostId === hostId)?.role;
  // What a host *does* is its declared services, not its role label. A model
  // design may only use the canonical role vocabulary (no `gateway`/`mail`),
  // so keying probes off role names silently skipped them for every design
  // that was not the hand-written archetype.
  const declares = (hostId: string, kind: string) =>
    (spec.instances.find((i) => i.hostId === hostId)?.serviceDecls ?? []).some((d) => d.kind === kind);
  const endpointFor = (kind: string, fallbackRole: string) =>
    plan.find((e) => declares(e.hostId, kind)) ?? plan.find((e) => roleOf(e.hostId) === fallbackRole);
  const gw = plan.find((e) => e.gateway);
  const web = endpointFor("http", "web");
  const db = endpointFor("db", "db");
  const dc = endpointFor("ldap", "dc");
  const mail = endpointFor("smtp", "mail") ?? endpointFor("imap", "mail");
  const out: LabProbePlan[] = [];
  const clients = plan.filter((e) => !e.gateway);

  // DNS: every other guest resolves this host's name through the gateway.
  if (gw) {
    for (const to of plan.filter((e) => !e.gateway)) {
      const from = clients.find((e) => e.hostId !== to.hostId) ?? clients[0];
      if (!from || from.hostId === to.hostId) continue;
      out.push({
        from: from.hostId, to: to.hostId, probe: "lab-dns", kind: "lab/dns", timeoutMs: 10_000,
        command: `dig +short +time=3 +tries=1 @${gw.address} ${to.hostId}.${domain}`,
        expect: to.address,
      });
    }
  }
  // DHCP: a peer guest leases an address from the server over the segment.
  // No role fallback — only a declared dhcp service makes this claim.
  const dhcp = plan.find((e) => declares(e.hostId, "dhcp"));
  if (dhcp) {
    const from = plan.find((e) => e.hostId !== dhcp.hostId);
    if (from) {
      const pool = dhcpPoolFor(dhcp.cidr);
      out.push({
        from: from.hostId, to: dhcp.hostId, probe: "lab-dhcp", kind: "lab/dhcp", expect: "DHCPACK", timeoutMs: 25_000,
        command: [
          `IF=$(ip -4 -o addr show | grep -F ' ${from.address}/' | awk '{print $2}' | head -1)`,
          `[ -n "$IF" ] || { echo "lab-dhcp: no lab interface for ${from.address}"; exit 1; }`,
          `sudo -n python3 - "$IF" ${pool.start} ${pool.end} <<'PY'`,
          DHCP_CLIENT_PY,
          "PY",
        ].join("\n"),
      });
    }
  }
  // HTTP: another guest fetches the intranet over the segment.
  if (web) {
    const from = plan.find((e) => e.hostId !== web.hostId && !e.gateway);
    if (from) out.push({ from: from.hostId, to: web.hostId, probe: "lab-http", kind: "lab/http", timeoutMs: 10_000, command: `curl -fsS --max-time 5 -o /dev/null http://${web.address}/` });
  }
  // LDAP: a guest that declares the client tools binds against the directory.
  if (dc) {
    const from = plan.find((e) => e.hostId !== dc.hostId && (spec.instances.find((i) => i.hostId === e.hostId)?.dependsOn ?? []).includes(dc.hostId));
    if (from) {
      const dcInst = spec.instances.find((i) => i.hostId === dc.hostId);
      const isIpa = (dcInst?.serviceDecls ?? []).some((d) => d.kind === "ldap" && d.impl === "freeipa");
      const base = isIpa ? ipaBaseFor(domain) : ldapBaseFor(domain);
      const bindDn = isIpa ? ipaAdminDnFor(domain) : `cn=admin,${base}`;
      const pw = labSecret(runId, isIpa ? "ipa-admin" : "ldap-admin");
      out.push({
        from: from.hostId, to: dc.hostId, probe: "lab-ldap", kind: "lab/ldap", expect: "dn:", timeoutMs: 15_000,
        command: `ldapsearch -x -H ldap://${dc.address}:389 -D ${bindDn} -w ${q(pw)} -b ${base} -s base dn`,
      });
    }
  }
  // SMTP: another guest reads the greeting over the segment.
  if (mail) {
    const from = plan.find((e) => e.hostId !== mail.hostId && !e.gateway);
    if (from) out.push({
      from: from.hostId, to: mail.hostId, probe: "lab-smtp", kind: "lab/smtp", expect: "220", timeoutMs: 10_000,
      command: `timeout 5 bash -c 'exec 3<>/dev/tcp/${mail.address}/25; head -c 3 <&3'`,
    });
  }
  // Mail: on an OpenLDAP-backed mail host, a peer guest logs in over IMAP
  // with the directory probe account. Dovecot's only passdb binds as the
  // user against the directory, so the good leg proves LDAP-backed mail
  // auth over the segment and the bad leg proves the directory refuses.
  if (mail && dc) {
    const mailInst = spec.instances.find((i) => i.hostId === mail.hostId);
    const dcInst = spec.instances.find((i) => i.hostId === dc.hostId);
    const openLdapBacked = (dcInst?.serviceDecls ?? []).some((d) => d.kind === "ldap" && d.impl === "openldap")
      && (mailInst?.dependsOn ?? []).includes(dc.hostId);
    const from = openLdapBacked ? plan.find((e) => e.hostId !== mail.hostId && !e.gateway) : undefined;
    if (from) {
      const pw = labSecret(runId, "mail-probe");
      const imapPort = (mailInst?.serviceDecls ?? []).find((d) => d.kind === "imap")?.port ?? 143;
      const good = `curl -fsS --max-time 5 -u ${q(`probe:${pw}`)} imap://${mail.address}:${imapPort}/INBOX >/dev/null`;
      const bad = `curl -fsS --max-time 5 -u ${q(`probe:not-${pw}`)} imap://${mail.address}:${imapPort}/INBOX >/dev/null 2>&1`;
      out.push({
        from: from.hostId, to: mail.hostId, probe: "lab-mail", kind: "lab/mail-ldap", timeoutMs: 20_000,
        command: `${bad} && { echo 'directory mail account accepted a wrong password'; exit 1; }; ${good}`,
      });
    }
  }
  // DB: the app tier reads a seeded row over the segment with the probe
  // credential. `app` itself cannot be used (its segment password is the
  // planted vuln or rotated unknown), so db-seed-access creates the
  // least-privilege arena_probe role. The wrong-password leg must fail
  // first, or a trust rule would make the read meaningless.
  if (db && web) {
    const pw = labSecret(runId, "db-probe");
    const good = `PGPASSWORD=${q(pw)} PGCONNECT_TIMEOUT=5 psql -h ${db.address} -U arena_probe -d app -tAc 'SELECT v FROM arena_probe_ping'`;
    const bad = `PGPASSWORD=${q(`not-${pw}`)} PGCONNECT_TIMEOUT=5 psql -h ${db.address} -U arena_probe -d app -tAc 'SELECT 1'`;
    out.push({
      from: web.hostId, to: db.hostId, probe: "lab-sql", kind: "lab/sql", expect: "arena-db-ready", timeoutMs: 20_000,
      command: `${bad} >/dev/null 2>&1 && { echo 'database accepted a wrong probe password'; exit 1; }; ${good}`,
    });
  }
  return out;
}

export interface ZoneProbe {
  from: string;
  to: string;
  probe: "lab-allow" | "lab-deny";
  kind: string;
  command: string;
  /** "pass" = the connect must succeed; "fail" = it must be refused/timed out. */
  expect: "pass" | "fail";
  timeoutMs: number;
}

/**
 * Zone probes (P1b, v2 only): every allowed cross-zone edge becomes a TCP
 * connect that must pass through the router; every denied edge becomes one
 * that must fail. Same-zone traffic never crosses the router, so only
 * cross-zone edges are probed. v1 flat labs return [] (their `labProbesFor`
 * path already covers the single segment).
 */
export function zoneProbesFor(spec: EnvironmentSpec): ZoneProbe[] {
  if ((spec.topology.sites?.length ?? 0) === 0 && (spec.topology.zones?.length ?? 0) === 0) return [];
  let model;
  try {
    model = normalizeOrg(spec);
  } catch { return []; }
  let reach;
  try {
    reach = reachabilityFor(spec, model);
  } catch { return []; }
  const out: ZoneProbe[] = [];
  // Allowed cross-zone edges traverse the router: the connect from the source
  // zone to the target's segment address must pass. Same-zone edges never
  // cross the router (one hub), so they are the v1 path's job, not this one.
  // The reachability graph emits at most one representative source host per
  // origin zone; that host is the probe client.
  const probed = new Set<string>();
  for (const e of reach.allowed) {
    if (e.fromZone === e.toZone) continue;
    const key = `${e.from}->${e.to}:${e.port}`;
    if (probed.has(key)) continue;
    probed.add(key);
    const target = model.byHost.get(e.to);
    if (!target) continue;
    out.push({
      from: e.from, to: e.to, probe: "lab-allow", kind: "lab/zone-allow",
      command: `timeout 3 bash -c '</dev/tcp/${target.address}/${e.port}'`,
      expect: "pass", timeoutMs: 8_000,
    });
  }
  // Denied edges reuse the negative-probe list, which picks exactly one
  // denied edge per unreachable zone pair (no allowed service path at all).
  // An allow edge and a deny edge can name the same address:port string (one
  // client zone is allowed, another is denied), so the fail probes carry the
  // client in the command: a comment line naming the source host makes the
  // string unique per (client, target, port) and keeps the gate's pass/fail
  // sets disjoint. The shell ignores the comment; the TCP connect is the test.
  // The target must be a service on a non-router host in the denied zone:
  // the router's own address is input-chain (unfiltered by design), so a
  // connect there proves nothing about forwarding policy.
  for (const e of negativeProbesFor(spec, model)) {
    if (e.fromZone === e.toZone || e.to === e.from) continue;
    const target = model.byHost.get(e.to);
    if (!target || target.router) continue;
    out.push({
      from: e.from, to: e.to, probe: "lab-deny", kind: "lab/zone-deny",
      command: `timeout 3 bash -c ': probe from ${e.from}; </dev/tcp/${target.address}/${e.port}'`,
      expect: "fail", timeoutMs: 8_000,
    });
  }
  // Fallback: if every denied target was the router, probe the first declared
  // service port of a non-router host in a denied zone. A zone pair with no
  // non-router service has no forwarding claim to falsify, so it is skipped
  // rather than probed vacuously.
  if (!out.some((p) => p.probe === "lab-deny")) {
    for (const e of reach.denied) {
      if (e.fromZone === e.toZone) continue;
      const target = model.byHost.get(e.to);
      if (!target || target.router || e.to === e.from) continue;
      out.push({
        from: e.from, to: e.to, probe: "lab-deny", kind: "lab/zone-deny",
        command: `timeout 3 bash -c ': probe from ${e.from}; </dev/tcp/${target.address}/${e.port}'`,
        expect: "fail", timeoutMs: 8_000,
      });
      break;
    }
  }
  return out;
}

/** READINESS for every host of one runtime in the spec (VM default; containers via docker exec). */
export async function checkSpecReadiness(input: {
  spec: EnvironmentSpec;
  runId: string;
  sshUserOf: (hostId: string) => string;
  exec: GuestExec;
  runtime?: "vm" | "container";
}): Promise<HostReadiness[]> {
  const runtime = input.runtime ?? "vm";
  const results: HostReadiness[] = [];
  for (const inst of input.spec.instances) {
    if (inst.runtime !== runtime) continue;
    results.push(await checkHostReadiness({ ...input, hostId: inst.hostId, sshUser: input.sshUserOf(inst.hostId) }));
  }
  // Lab/zone/log cross-host proofs are VM-segment concepts; the container
  // runtime's cross-service evidence is its Docker gate + exercise path.
  if (runtime === "container") return results;
  // Cross-host probes attach to the client host's report: a failure fails
  // readiness, exactly like a local probe.
  for (const probe of labProbesFor(input.spec, input.runId)) {
    const host = results.find((r) => r.hostId === probe.from);
    if (!host) continue;
    try {
      const out = await input.exec(probe.from, probe.command, probe.timeoutMs);
      const ok = probe.expect === undefined ? true : String(out).includes(probe.expect);
      host.checks.push({
        probe: probe.probe, kind: probe.kind, ok,
        detail: ok ? `${probe.kind} answered from ${probe.from}` : `${probe.kind} output missing ${JSON.stringify(probe.expect)}: ${String(out).trim().slice(0, 120)}`,
      });
    } catch (err) {
      host.checks.push({ probe: probe.probe, kind: probe.kind, ok: false, detail: `${probe.kind} failed from ${probe.from}: ${detailOf(err)}` });
    }
    host.ok = host.checks.every((c) => c.ok);
  }
  // Zone probes (P1b, v2 only): allowed cross-zone flows must pass through the
  // router; denied flows must fail. Each attaches to the client host's report.
  for (const probe of zoneProbesFor(input.spec)) {
    const host = results.find((r) => r.hostId === probe.from);
    if (!host) continue;
    try {
      await input.exec(probe.from, probe.command, probe.timeoutMs);
      // The TCP connect succeeded.
      host.checks.push({
        probe: probe.probe, kind: probe.kind, ok: probe.expect === "pass",
        detail: probe.expect === "pass"
          ? `${probe.kind} allowed flow passed from ${probe.from}`
          : `${probe.kind} denied flow unexpectedly passed from ${probe.from}`,
      });
    } catch {
      // The TCP connect failed (refused or timed out).
      host.checks.push({
        probe: probe.probe, kind: probe.kind, ok: probe.expect === "fail",
        detail: probe.expect === "fail"
          ? `${probe.kind} denied flow failed as required from ${probe.from}`
          : `${probe.kind} allowed flow failed from ${probe.from}`,
      });
    }
    host.ok = host.checks.every((c) => c.ok);
  }
  // Log shipping end to end: a message logged on one guest must appear in the
  // collector's own file. This is the one proof that cannot run on a single
  // host — the write and the read are on different guests.
  const collector = input.spec.instances.find((i) => (i.serviceDecls ?? []).some((d) => d.kind === "log"));
  const sender = input.spec.instances.find((i) => i.runtime === "vm" && i.hostId !== collector?.hostId);
  const target = results.find((r) => r.hostId === collector?.hostId);
  if (collector && sender && target) {
    const marker = `ARENA-LOG-${input.runId}`;
    let ok = false;
    let detail = `marker from ${sender.hostId} missing on ${collector.hostId}`;
    try {
      await input.exec(sender.hostId, `logger -t arena-l2 ${marker}`, 10_000);
      for (let i = 0; i < 12 && !ok; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        const out = await input.exec(collector.hostId, `sudo -n grep -c ${marker} /var/log/arena/remote.log 2>/dev/null || true`, 10_000);
        ok = Number(String(out).trim()) > 0;
      }
      if (ok) detail = `log written on ${sender.hostId} reached ${collector.hostId}`;
    } catch (err) {
      detail = `log shipping check failed: ${detailOf(err)}`;
    }
    target.checks.push({ probe: "lab-log", kind: "lab/log", ok, detail });
    target.ok = target.checks.every((c) => c.ok);
  }
  return results;
}
