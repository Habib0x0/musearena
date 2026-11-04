import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { EnvironmentSpec } from "@musearena/shared";
import { dhcpPoolFor, labPlanFor } from "../provisioner/lab-network.js";
import { serviceClient } from "../lib/supabase.js";
import { audit } from "../lib/audit.js";
import { resolveProfile, resolveProfilePackages, resolveProfileUnits } from "./profiles.js";
import { labSecret, ipaUserIdFor, ipaUserSecret } from "./lab.js";
import { labDomainFor, ldapBaseFor, ipaDomainFor, ipaRealmFor, ipaBaseFor } from "./dns.js";
import { normalizeOrg, nftablesFor, routerAttachmentsFor } from "../designer/org-topology.js";
import { guestOsFamily } from "../provisioner/images.js";
import { WEAK_DB_PASSWORD, WEAK_IPA_USER, WEAK_IPA_PASSWORD } from "../provisioner/roles.js";
import { vulnTargetFor } from "./vuln-targets.js";

// Per-instance Ansible configuration: dynamic inventory is derived from the
// spec + provisioner outputs — never hand-maintained. Roles per instance role.
const run = promisify(execFile);

export interface InstanceTarget { hostId: string; name: string; connectVia: string }

// Role pipelines are real `raw` tasks executed inside each container over the
// docker connection (no Python needed in targets). Content is passed base64
// encoded so spec-derived strings never reach a shell unquoted.
const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");
const writeFileTask = (name: string, dest: string, content: string) =>
  ({ name, raw: `printf '%s' '${b64(content)}' | base64 -d > ${dest}` });
const sqlLit = (s: string) => `'${s.replace(/'/g, "''")}'`;
const html = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

/** Canary data an objective's success signal is checked against (Req §8.2). */
export function canaryValue(runId: string, objectiveId: string): string {
  return `MUSE-CANARY-${runId.replace(/^run-/, "").slice(0, 8)}-${objectiveId}`;
}

export interface Task { name: string; raw: string }

/** Run a VM task as root: the management user is `arena` with NOPASSWD sudo. */
const asRoot = (cmd: string) => `printf '%s' '${b64(cmd)}' | base64 -d | sudo -n sh`;

/**
 * Machine-profile tasks for a VM host (T-16b): install the resolved package
 * set (a no-op when the baked image already carries it), apply service
 * bootstrap that must precede unit start, enable the profile units, then seed
 * data that needs a running server. Service-specific config groups land here
 * as the catalog expands.
 */
export function vmProfileTasks(spec: EnvironmentSpec, runId: string, hostId: string): Task[] {
  const profile = resolveProfile(spec, hostId);
  // One derived namespace per environment; see `labDomainFor`.
  const domain = labDomainFor(spec);
  const ldapBase = ldapBaseFor(domain);
  const hostInst = spec.instances.find((i) => i.hostId === hostId);
  const isRockyGuest = !!hostInst && guestOsFamily(hostInst.os) === "rocky";
  const packages = isRockyGuest
    ? resolveProfilePackages(profile, hostInst!.os)
    : profile.packages;
  // Lab addresses (T-15): services bind the guest's static lab address, not
  // only loopback, so a cross-host proof exercises the same path an org member
  // does. v2 org specs derive addresses from the org model (one NIC per zone
  // segment); v1 flat labs use the single-segment plan. A missing plan
  // degrades to loopback instead of throwing, so the reviewed plan still renders.
  interface Endpoint { address: string; prefix: number; cidr: string }
  let lab = new Map<string, Endpoint>();
  let fqdnOf = (id: string) => `${id}.${domain}`;
  try {
    if ((spec.topology.sites?.length ?? 0) > 0 || (spec.topology.zones?.length ?? 0) > 0) {
      const model = normalizeOrg(spec);
      for (const e of model.endpoints) lab.set(e.hostId, { address: e.address, prefix: e.prefix, cidr: e.cidr });
      for (const r of routerAttachmentsFor(spec, model)) {
        // The router is multi-homed; its primary endpoint is the first zone.
        if (!lab.has(r.hostId) && r.interfaces.length) {
          lab.set(r.hostId, { address: r.interfaces[0].address, prefix: r.interfaces[0].prefix, cidr: r.interfaces[0].cidr });
        }
      }
      fqdnOf = (id: string) => model.byHost.get(id)?.fqdn ?? `${id}.${domain}`;
    } else {
      lab = new Map(labPlanFor(spec, runId).map((e) => [e.hostId, { address: e.address, prefix: e.prefix, cidr: e.cidr }]));
    }
  } catch { lab = new Map(); }
  const self = lab.get(hostId);
  const inst = spec.instances.find((i) => i.hostId === hostId);
  const ipaHost = spec.instances.find((i) => (i.serviceDecls ?? []).some((d) => d.kind === "ldap" && d.impl === "freeipa"));
  const ipaEndpoint = ipaHost ? lab.get(ipaHost.hostId) : undefined;
  const gwHost = spec.instances.find((i) => (i.serviceDecls ?? []).some((d) => d.kind === "dns"));
  const gwEndpoint = gwHost ? lab.get(gwHost.hostId) : undefined;
  const isFreeipaServer = profile.catalogEntries.some((e) => e.kind === "ldap" && e.impl === "freeipa");
  // Realm membership is a declared dependency, not an inference from role.
  const joinsIpa = !!ipaHost && ipaHost.hostId !== hostId && (inst?.dependsOn ?? []).includes(ipaHost.hostId);
  const openLdapHost = spec.instances.find((i) => (i.serviceDecls ?? []).some((d) => d.kind === "ldap" && d.impl === "openldap"));
  const openLdapEndpoint = openLdapHost ? lab.get(openLdapHost.hostId) : undefined;
  const joinsOpenLdap = !!openLdapHost && openLdapHost.hostId !== hostId && (inst?.dependsOn ?? []).includes(openLdapHost.hostId);
  const tasks: Task[] = [];
  // Fail-closed: a package manager failure used to be masked by the trailing
  // mkdir, so a host could report configured while its tools were absent.
  // After any install attempt, every requested package is re-verified.
  const install = isRockyGuest ? [
    'missing=""',
    `for p in ${packages.join(" ")}; do rpm -q "$p" >/dev/null 2>&1 || missing="$missing $p"; done`,
    'if [ -n "$missing" ]; then echo "profile-install:$missing"; dnf install -y $missing || exit 1; fi',
    `still=""; for p in ${packages.join(" ")}; do rpm -q "$p" >/dev/null 2>&1 || still="$still $p"; done`,
    'if [ -n "$still" ]; then echo "profile-install still missing:$still"; exit 1; fi',
    'mkdir -p /etc/arena /var/log/arena',
    'if command -v osqueryd >/dev/null 2>&1 && [ ! -s /etc/osquery/osquery.conf ]; then mkdir -p /etc/osquery; printf \'{"options":{"disable_events":"true"},"schedule":{}}\\n\' > /etc/osquery/osquery.conf; fi',
  ].join("\n") : [
    'missing=""',
    `for p in ${profile.packages.join(" ")}; do dpkg -s "$p" >/dev/null 2>&1 || missing="$missing $p"; done`,
    'if [ -n "$missing" ]; then',
    '  echo "profile-install:$missing"',
    // osquery is vendor-repo only (same source the bake uses); without it the
    // whole apt transaction fails and no package installs.
    '  case " $missing " in *" osquery "*) curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg -o /etc/apt/trusted.gpg.d/osquery.asc && echo "deb [signed-by=/etc/apt/trusted.gpg.d/osquery.asc] https://pkg.osquery.io/deb deb main" > /etc/apt/sources.list.d/osquery.list || exit 1;; esac',
    '  apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 update || exit 1',
    '  DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 install -y $missing || exit 1',
    'fi',
    `still=""; for p in ${profile.packages.join(" ")}; do dpkg -s "$p" >/dev/null 2>&1 || still="$still $p"; done`,
    'if [ -n "$still" ]; then echo "profile-install still missing:$still"; exit 1; fi',
    'mkdir -p /etc/arena /var/log/arena',
    'if command -v osqueryd >/dev/null 2>&1 && [ ! -s /etc/osquery/osquery.conf ]; then mkdir -p /etc/osquery; printf \'{"options":{"disable_events":"true"},"schedule":{}}\\n\' > /etc/osquery/osquery.conf; fi',
  ].join("\n");
  tasks.push({ name: "profile-install", raw: asRoot(install) });

  const kinds = new Set(profile.catalogEntries.map((e) => e.kind));
  const configure: Task[] = [];

  // Resolver (O-1 + P3 join): lab names go to the gateway, and the realm's
  // own zone goes to the FreeIPA server. Both matter for a member: Samba and
  // Kerberos discover the DC through SRV records in the IPA zone, and the lab
  // zone is what resolves peers by name. One drop-in carries every server and
  // domain, so two netplan files cannot fight over the same interface.
  // Implemented through netplan/resolved on Debian and nmcli on Rocky —
  // writing resolv.conf by hand would be reverted by the renderer.
  const resolverServers = [
    ...(gwEndpoint && gwHost && gwHost.hostId !== hostId ? [gwEndpoint.address] : []),
    ...(ipaEndpoint && ipaHost && ipaHost.hostId !== hostId && !isFreeipaServer ? [ipaEndpoint.address] : []),
  ];
  const resolverDomains = [
    ...(gwEndpoint && gwHost && gwHost.hostId !== hostId ? [domain] : []),
    ...(ipaEndpoint && ipaHost && ipaHost.hostId !== hostId && !isFreeipaServer ? [ipaDomainFor(spec)] : []),
  ];
  if (resolverServers.length && self && !isFreeipaServer) {
    const resolver = isRockyGuest ? [
      `for c in $(nmcli -t -f NAME connection show); do nmcli connection modify "$c" ipv4.ignore-auto-dns yes ipv4.dns "${resolverServers.join(" ")}" 2>/dev/null || true; done`,
      "systemctl restart NetworkManager 2>/dev/null || nmcli connection reload 2>/dev/null || true",
    ].join("\n") : [
      // The lab interface name is discovered by its address, like the seed.
      "IF=$(ip -4 -o addr show | grep -F ' " + self.address + "/' | awk '{print $2}' | head -1)",
      '[ -n "$IF" ] || { echo "dns-resolver: lab interface for ' + self.address + ' not found"; ip -4 addr show; exit 1; }',
      // Netplan merges per-interface keys across files, but a file that
      // re-declares the interface without its addresses leaves the renderer
      // free to drop them (seen live: lab address vanished). Repeat the lab
      // address in the drop-in so the interface definition is total.
      'cat > /etc/netplan/99-arena-dns.yaml <<EOF',
      "network:",
      "  version: 2",
      "  ethernets:",
      '    "$IF":',
      "      dhcp4: false",
      "      addresses:",
      `        - ${self.address}/${self.prefix}`,
      "      nameservers:",
      `        addresses: [${resolverServers.join(", ")}]`,
      `        search: [${resolverDomains.join(", ")}]`,
      "EOF",
      "chmod 600 /etc/netplan/99-arena-dns.yaml",
      // No `netplan apply`: it reconfigures every link, including the
      // management NIC this Ansible SSH session arrives on, and drops the
      // session mid-task (observed live on KVM). The drop-in applies on the
      // next boot; the resolvectl calls below set the same per-link DNS and
      // domains at runtime without touching the links.
      // Routing-only domains at runtime: these names always go to their own
      // server, never racing the mgmt resolver (which NXDOMAINs faster and
      // wins the parallel query). Netplan's search list alone can't express `~`.
      `resolvectl domain "$IF" ${resolverDomains.map((d) => `"~${d}" "${d}"`).join(" ")} 2>/dev/null || true`,
      `resolvectl dns "$IF" ${resolverServers.join(" ")} 2>/dev/null || true`,
      // Debian cloud images point /etc/resolv.conf at resolved's *uplink*
      // file, which omits non-default-route links — glibc would never ask the
      // lab servers. The stub routes NSS through resolved properly, but
      // Samba's own DNS client ignores a loopback resolver, so the concrete
      // lab servers follow it in a static file: stub first for NSS, lab
      // servers for the AD discovery path.
      "if [ -L /etc/resolv.conf ]; then rm -f /etc/resolv.conf; fi",
      "{",
      "  echo 'nameserver 127.0.0.53'",
      ...resolverServers.map((srv) => `  echo 'nameserver ${srv}'`),
      ...resolverDomains.map((d) => `  echo 'search ${d}'`),
      "  echo 'options edns0 trust-ad'",
      "} > /etc/resolv.conf",
      "chmod 644 /etc/resolv.conf",
    ].join("\n");
    const verify: string[] = [];
    if (gwEndpoint && gwHost && gwHost.hostId !== hostId) {
      verify.push(
        `for i in $(seq 1 20); do dig +short +time=2 +tries=1 @${gwEndpoint.address} ${hostId} 2>/dev/null | grep -q '${self.address}' && break; sleep 1; done`,
        `dig +short +time=2 +tries=1 @${gwEndpoint.address} ${hostId} 2>/dev/null | grep -q '${self.address}' || { echo 'dns-resolver: gateway DNS ${gwEndpoint.address} does not answer for ${hostId}'; exit 1; }`,
        `for i in $(seq 1 20); do timeout 5 getent hosts ${gwHost.hostId}.${domain} 2>/dev/null | grep -q '${gwEndpoint.address}' && break; sleep 1; done`,
        `timeout 5 getent hosts ${gwHost.hostId}.${domain} 2>/dev/null | grep -q '${gwEndpoint.address}' || { echo 'dns-resolver: system resolver does not resolve ${gwHost.hostId}.${domain} via gateway'; cat /etc/resolv.conf; resolvectl status 2>/dev/null | head -30; exit 1; }`,
      );
    }
    // A host the directory itself depends on (the DNS gateway) is configured
    // before the directory exists, so it cannot prove the realm answers yet.
    // It forwards the realm zone via dnsmasq; members verify it once IPA is up.
    const directoryDependsOnThisHost = !!ipaHost && (ipaHost.dependsOn ?? []).includes(hostId);
    if (ipaEndpoint && ipaHost && ipaHost.hostId !== hostId && !isFreeipaServer && !directoryDependsOnThisHost) {
      // The realm's SRV records are the DC-discovery contract; a member that
      // cannot resolve them cannot join Samba or use Kerberos services.
      verify.push(
        `for i in $(seq 1 20); do dig +short +time=2 +tries=1 @${ipaEndpoint.address} _kerberos._udp.${ipaDomainFor(spec)} SRV 2>/dev/null | grep -q . && break; sleep 1; done`,
        `dig +short +time=2 +tries=1 @${ipaEndpoint.address} _kerberos._udp.${ipaDomainFor(spec)} SRV 2>/dev/null | grep -q . || { echo 'dns-resolver: realm SRV records not served by ${ipaEndpoint.address}'; exit 1; }`,
        `for i in $(seq 1 20); do timeout 5 getent hosts ${ipaHost.hostId}.${ipaDomainFor(spec)} 2>/dev/null | grep -q '${ipaEndpoint.address}' && break; sleep 1; done`,
        `timeout 5 getent hosts ${ipaHost.hostId}.${ipaDomainFor(spec)} 2>/dev/null | grep -q '${ipaEndpoint.address}' || { echo 'dns-resolver: system resolver does not resolve the realm DC'; cat /etc/resolv.conf; resolvectl status 2>/dev/null | head -30; exit 1; }`,
      );
    }
    configure.push({ name: "dns-resolver", raw: asRoot([resolver, ...verify].join("\n")) });
  }

  if (kinds.has("db")) {
    // app over TCP must use its password (weak-cred), other local traffic
    // stays trusted for the role tasks; log statements so the proof and the
    // exercise can read them out of band.
    const db = [
      "for f in /etc/postgresql/*/main/pg_hba.conf; do",
      '  [ -f "$f" ] || continue',
      '  grep -qE \'^local[[:space:]]+all[[:space:]]+all[[:space:]]+trust\' "$f" || sed -i \'1i local all all trust\' "$f"',
      '  grep -qE \'^host[[:space:]]+all[[:space:]]+all[[:space:]]+127.0.0.1/32[[:space:]]+trust\' "$f" || sed -i \'1i host all all 127.0.0.1/32 trust\' "$f"',
      '  grep -qE \'^host[[:space:]]+all[[:space:]]+app[[:space:]]+127.0.0.1/32[[:space:]]+scram-sha-256\' "$f" || sed -i \'1i host all app 127.0.0.1/32 scram-sha-256\' "$f"',
      ...(self ? [
        `  grep -qE '^host[[:space:]]+all[[:space:]]+app[[:space:]]+${self.cidr.replace(".", "\\.").replace("/", "\\/")}[[:space:]]+scram-sha-256' "$f" || sed -i '1i host all app ${self.cidr} scram-sha-256' "$f"`,
        // The readiness probe role may authenticate from the lab segment
        // only; it is seeded in db-seed-access with the per-run secret.
        `  grep -qE '^host[[:space:]]+all[[:space:]]+arena_probe[[:space:]]+${self.cidr.replace(".", "\\.").replace("/", "\\/")}[[:space:]]+scram-sha-256' "$f" || sed -i '1i host all arena_probe ${self.cidr} scram-sha-256' "$f"`,
        // Employee (persona) reads come from workstations on the segment with
        // their own read-only role, never the shared `app` account.
        `  grep -qE '^host[[:space:]]+all[[:space:]]+arena_staff[[:space:]]+${self.cidr.replace(".", "\\.").replace("/", "\\/")}[[:space:]]+scram-sha-256' "$f" || sed -i '1i host all arena_staff ${self.cidr} scram-sha-256' "$f"`,
      ] : []),
      // P3: on a realm member, domain users authenticate against FreeIPA with
      // a *bind as the user* (pg's ldap method), so Postgres never stores a
      // domain password. Placed first so it is evaluated before catch-alls.
      ...(joinsIpa && ipaEndpoint && self ? (() => {
        const users = (spec.personas ?? []).map((p) => ipaUserIdFor(p.id)).filter(Boolean).join(",") || "all";
        const base = `cn=users,cn=accounts,${ipaBaseFor(domain)}`;
        const suffix = `ldap ldapserver=${ipaEndpoint.address} ldapport=389 ldapscheme=ldap ldapprefix="uid=" ldapsuffix=",${base}"`;
        // Both the lab segment and loopback: the local probe connects over
        // 127.0.0.1, and a loopback `trust` rule would otherwise accept any
        // password before the directory is ever consulted (seen live).
        return [
          `  grep -q 'ldap ldapserver=${ipaEndpoint.address}' "$f" || sed -i '1i host all ${users} ${self.cidr} ${suffix}' "$f"`,
          `  grep -q 'ldap ldapserver=${ipaEndpoint.address}.*127.0.0.1' "$f" || sed -i '1i host all ${users} 127.0.0.1/32 ${suffix}' "$f"`,
        ];
      })() : []),
      "done",
      "for f in /etc/postgresql/*/main/postgresql.conf; do",
      '  [ -f "$f" ] || continue',
      '  grep -q "arena-lab logging" "$f" || printf "\\n# arena-lab logging\\nlog_statement = \'all\'\\nlog_connections = on\\nlog_line_prefix = \'%%m [%%p] user=%%u db=%%d client=%%h \'\\n" >> "$f"',
      ...(self ? [
        `  grep -q "arena-lab listen" "$f" || printf "\\n# arena-lab listen\\nlisten_addresses = \'localhost,${self.address}\'\\n" >> "$f"`,
      ] : []),
      "done",
      // listen_addresses is not reloadable: a reload would leave the lab
      // address unbound and the cross-host port proof refused.
      ...(self ? ["systemctl restart postgresql"] : []),
    ].join("\n");
    configure.push({ name: "db-configure", raw: asRoot(db) });
  }
  if (kinds.has("router")) {
    // The forward chain is derived from the spec's policies; deny rules are
    // emitted before allows and the chain ends in policy drop. Input/output
    // stay unfiltered so the management NIC can still reach the guest.
    // The router owns .1 in every zone of its site. The seed already
    // configured one NIC per segment by MAC; this asserts every expected
    // address is present and fails closed when one is missing.
    const routerIps = (() => {
      try {
        if ((spec.topology.sites?.length ?? 0) > 0) {
          return routerAttachmentsFor(spec).find((r) => r.hostId === hostId)?.interfaces ?? [];
        }
      } catch { /* fall through to the single lab address */ }
      return [];
    })();
    const router = [
      "mkdir -p /var/log/arena",
      "printf 'net.ipv4.ip_forward=1\\n' > /etc/sysctl.d/99-arena-forward.conf",
      "sysctl -q --system",
      ...routerIps.map((iface) =>
        `ip -4 -o addr show | grep -q "${iface.address}/${iface.prefix}" || { echo "router ${hostId}: missing ${iface.address}/${iface.prefix} on ${iface.segment}"; exit 1; }`),
      "cat > /etc/nftables.conf <<'EOF'",
      ...nftablesFor(spec).trimEnd().split("\n"),
      "EOF",
      "nft -f /etc/nftables.conf",
    ].join("\n");
    configure.push({ name: "router-configure", raw: asRoot(router) });
  }
  if (kinds.has("dns")) {
    // Serves the gateway's own name on loopback and every guest's lab name on
    // the lab address, so a cross-host DNS proof is a real query.
    const dns = [
      "{",
      "  echo 'domain-needed'",
      "  echo 'bogus-priv'",
      `  echo 'domain=${domain}'`,
      `  echo 'local=/${domain}/'`,
      // The directory owns a subdomain; a more specific server= overrides the
      // parent local= rule, so members resolve SRV/A records from FreeIPA.
      ...(ipaEndpoint && ipaHost && ipaHost.hostId !== hostId
        ? [`  echo 'server=/${ipaDomainFor(spec)}/${ipaEndpoint.address}'`]
        : []),
      "  echo 'expand-hosts'",
      "  echo 'bind-interfaces'",
      ...(self ? [`  echo "listen-address=127.0.0.1,${self.address}"`] : ['  echo "listen-address=127.0.0.1"']),
      '  echo "host-record=$(hostname),127.0.0.1"',
      // Every guest's lab name resolves through the gateway's DNS, bare and
      // fully qualified, so a client can use whichever the spec names.
      ...[...lab.entries()].map(([id, e]) => `  echo "host-record=${id},${fqdnOf(id)},${e.address}"`),
      "} > /etc/dnsmasq.d/arena.conf",
      // enable --now does not reload a unit that is already running, so the
      // new records would never be served.
      "systemctl restart dnsmasq 2>/dev/null || true",
    ].join("\n");
    configure.push({ name: "dns-configure", raw: asRoot(dns) });
  }
  if (kinds.has("dhcp")) {
    // dnsmasq serves leases from the top of the lab subnet (statics live at
    // the bottom). Without a dns declaration on the same host, dnsmasq would
    // also offer DHCP on the management NIC, so bind it to loopback + lab.
    if (!self) throw new Error(`dhcp on ${hostId} needs a lab address (no lab plan endpoint)`);
    const pool = dhcpPoolFor(self.cidr);
    const dhcp = [
      "{",
      ...(kinds.has("dns") ? [] : [
        "  echo 'bind-interfaces'",
        `  echo 'listen-address=127.0.0.1,${self.address}'`,
        `  echo 'domain=${domain}'`,
      ]),
      `  echo 'dhcp-range=${pool.start},${pool.end},${pool.netmask},12h'`,
      `  echo 'dhcp-option=option:router,${self.address}'`,
      `  echo 'dhcp-option=option:dns-server,${self.address}'`,
      "  echo 'dhcp-authoritative'",
      "} > /etc/dnsmasq.d/arena-dhcp.conf",
      "dnsmasq --test",
      "systemctl restart dnsmasq 2>/dev/null || true",
    ].join("\n");
    configure.push({ name: "dhcp-configure", raw: asRoot(dhcp) });
  }
  if (kinds.has("ldap") && !isFreeipaServer) {
    const pw = labSecret(runId, "ldap-admin");
    const ldap = [
      "cat <<EOF | debconf-set-selections",
      "slapd slapd/no_configuration boolean false",
      `slapd slapd/domain string ${domain}`,
      "slapd shared/organization string Arena",
      `slapd slapd/password1 password ${pw}`,
      `slapd slapd/password2 password ${pw}`,
      "slapd slapd/backend select MDB",
      "slapd slapd/purge_database boolean true",
      "slapd slapd/move_old_database boolean true",
      "EOF",
      "DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive slapd",
    ].join("\n");
    configure.push({ name: "ldap-configure", raw: asRoot(ldap) });
  }
  if (isFreeipaServer) {
    const fqdn = `${hostId}.${ipaDomainFor(spec)}`;
    const dsPw = labSecret(runId, "ipa-ds");
    const adminPw = labSecret(runId, "ipa-admin");
    const server = [
      `FQDN='${fqdn}'`,
      ...(self ? [`IP='${self.address}'`, `grep -q " $FQDN" /etc/hosts || echo "$IP $FQDN ${hostId}" >> /etc/hosts`] : []),
      // FreeIPA refuses a hostname that only resolves to loopback and requires
      // the FQDN it will serve; the lab address is that identity.
      'hostnamectl set-hostname "$FQDN"',
      "mkdir -p /var/log/arena",
      "if [ ! -f /etc/ipa/default.conf ]; then",
      // The Dogtag CA connects back to LDAP at the FQDN; if the lab address
      // is not yet configured the installer stalls there and reports only
      // "CA configuration failed". Fail here with the real cause instead.
      ...(self ? [`  ip -4 addr show | grep -q '${self.address}/${self.prefix}' || { echo 'lab address ${self.address} missing before ipa-server-install'; ip -4 addr show; exit 1; }`] : []),
      "  FW=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf)",
      // A loopback stub resolver cannot forward for named; the QEMU user-net
      // resolver is the only upstream the management NIC currently offers.
      '  case "$FW" in ""|127.*) FW=10.0.2.3;; esac',
      `  ipa-server-install --unattended --realm='${ipaRealmFor(spec)}' --domain='${ipaDomainFor(spec)}' --hostname="$FQDN"` +
        `${self ? ' --ip-address="$IP"' : ""} --setup-dns --forwarder="$FW" --no-reverse --no-ntp` +
        ` --ds-password='${dsPw}' --admin-password='${adminPw}' > /var/log/arena/ipa-install.log 2>&1` +
        " || { tail -n 60 /var/log/arena/ipa-install.log; exit 1; }",
      "fi",
    ].join("\n");
    configure.push({ name: "freeipa-install", raw: asRoot(server) });
  }
  if (kinds.has("smtp") || kinds.has("imap")) {
    const pw = labSecret(runId, "mail-probe");
    // P3: on a FreeIPA member, IMAP authenticates against the directory, not
    // only the local probe account. The passdb binds *as the user*
    // (auth_bind_userdn), so Dovecot never holds a user password and a wrong
    // password is refused by 389-ds itself. The service account DN is used for
    // the userdb lookup (uid/gid/home), which anonymous search cannot do.
    const ipaUsers = `cn=users,cn=accounts,${ipaBaseFor(domain)}`;
    const ldapConfExt = joinsIpa && ipaEndpoint ? [
      "cat > /etc/dovecot/dovecot-ldap.conf.ext <<'EOF'",
      `hosts = ${ipaEndpoint.address}:389`,
      `base = ${ipaUsers}`,
      `dn = uid=admin,${ipaUsers}`,
      `dnpass = ${labSecret(runId, "ipa-admin")}`,
      "auth_bind = yes",
      `auth_bind_userdn = uid=%u,${ipaUsers}`,
      "ldap_version = 3",
      "user_attrs = uidNumber=uid,gidNumber=gid,homeDirectory=home",
      `user_filter = (&(objectClass=posixAccount)(uid=%u))`,
      `pass_filter = (&(objectClass=posixAccount)(uid=%u))`,
      "EOF",
      "chmod 600 /etc/dovecot/dovecot-ldap.conf.ext",
    ] : joinsOpenLdap && openLdapEndpoint ? [
      // OpenLDAP member (T-16): same bind-as-user shape against the clinic
      // directory. The userdb returns the seeded POSIX attrs; the mailbox
      // system user below exists with the same uid so delivery and IMAP
      // agree on ownership.
      "cat > /etc/dovecot/dovecot-ldap.conf.ext <<'EOF'",
      `hosts = ${openLdapEndpoint.address}:389`,
      `base = ou=people,${ldapBase}`,
      `dn = cn=admin,${ldapBase}`,
      `dnpass = ${labSecret(runId, "ldap-admin")}`,
      "auth_bind = yes",
      `auth_bind_userdn = uid=%u,ou=people,${ldapBase}`,
      "ldap_version = 3",
      "user_attrs = uidNumber=uid,gidNumber=gid,homeDirectory=home",
      `user_filter = (&(objectClass=posixAccount)(uid=%u))`,
      `pass_filter = (&(objectClass=posixAccount)(uid=%u))`,
      "EOF",
      "chmod 600 /etc/dovecot/dovecot-ldap.conf.ext",
    ] : null;
    const ipaLdap = ldapConfExt ? [
      ...ldapConfExt,
      "cat > /etc/dovecot/conf.d/99-arena-ldap.conf <<'EOF'",
      // Accept `p1` and `p1@<domain>`; IPA names are case-sensitive otherwise.
      "auth_username_format = %Ln",
      "passdb {",
      "  driver = ldap",
      "  args = /etc/dovecot/dovecot-ldap.conf.ext",
      "}",
      "userdb {",
      "  driver = ldap",
      "  args = /etc/dovecot/dovecot-ldap.conf.ext",
      "}",
      "EOF",
      // Debian enables a PAM passdb ahead of anything we add, and PAM reaches
      // SSSD — so a successful login would NOT prove the directory path. On a
      // member the LDAP passdb must be the only one; the effective config is
      // then checked, and a surviving PAM passdb fails the task.
      "if grep -q '^!include auth-system.conf.ext' /etc/dovecot/conf.d/10-auth.conf 2>/dev/null; then sed -i 's|^!include auth-system.conf.ext|# arena: ldap-only (P3)|' /etc/dovecot/conf.d/10-auth.conf; fi",
      "doveconf -n 2>/dev/null | grep -q 'driver = pam' && { echo 'mail: PAM passdb still active — directory auth would be ambiguous'; exit 1; }",
      "doveconf -n 2>/dev/null | grep -q 'driver = ldap' || { echo 'mail: LDAP passdb missing from the effective config'; exit 1; }",
    ] : [];
    const mail = [
      "cat <<EOF | debconf-set-selections",
      "postfix postfix/main_mailer_type select Internet Site",
      `postfix postfix/mailname string ${hostId}.${domain}`,
      `postfix postfix/destinations string ${hostId}.${domain}, ${domain}, localhost`,
      "EOF",
      "DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive postfix",
      "postconf -e 'home_mailbox = Maildir/'",
      ...(self ? [`postconf -e 'inet_interfaces = ${self.address},127.0.0.1'`] : ["postconf -e 'inet_interfaces = loopback-only'"]),
      `postconf -e 'mydestination = ${hostId}.${domain}, ${domain}, localhost'`,
      // On a member only the directory can authenticate (LDAP is the sole
      // passdb), so the local `probe` account exists solely on unjoined
      // hosts. An OpenLDAP member still needs the system user (locked, no
      // password) so Postfix delivery and the LDAP userdb agree on the
      // mailbox owner (uid 10001, matching the seeded directory entry).
      ...(joinsIpa ? [] : joinsOpenLdap ? [
        "id probe >/dev/null 2>&1 || useradd -m -u 10001 -s /bin/bash probe",
        "mkdir -p /home/probe/Maildir && chown -R probe:probe /home/probe/Maildir",
      ] : [
        "id probe >/dev/null 2>&1 || useradd -m -s /bin/bash probe",
        `echo 'probe:${pw}' | chpasswd`,
      ]),
      "cat > /etc/dovecot/conf.d/99-arena.conf <<'EOF'",
      ...(self ? [`listen = 127.0.0.1,${self.address}`] : ["listen = 127.0.0.1"]),
      "mail_location = maildir:~/Maildir",
      "disable_plaintext_auth = no",
      ...(joinsIpa ? ["auth_mechanisms = plain login gssapi"] : ["auth_mechanisms = plain login"]),
      "EOF",
      ...ipaLdap,
      "systemctl restart postfix 2>/dev/null || true",
      "systemctl restart dovecot 2>/dev/null || true",
    ].join("\n");
    configure.push({ name: "mail-configure", raw: asRoot(mail) });
  }
  if (kinds.has("log")) {
    const log = [
      "mkdir -p /var/log/arena",
      "cat > /etc/rsyslog.d/50-arena.conf <<'EOF'",
      'module(load="imtcp")',
      'ruleset(name="arena-remote") {',
      '  action(type="omfile" file="/var/log/arena/remote.log")',
      '}',
      'input(type="imtcp" port="514" ruleset="arena-remote")',
      "EOF",
      // rsyslog is enabled in the base image; enable --now would not reload
      // the new input, so restart here to bind 514 before readiness runs.
      "systemctl restart rsyslog 2>/dev/null || true",
    ].join("\n");
    configure.push({ name: "log-configure", raw: asRoot(log) });
  }
  // Log shipping (T-16): every guest forwards to the collector over the lab
  // segment. The collector writes what it receives to /var/log/arena/remote.log
  // (configured above); a host that has no collector forwards nowhere.
  const collector = [...lab.keys()].map((id) => spec.instances.find((i) => i.hostId === id)).find((inst) =>
    (inst?.serviceDecls ?? []).some((d) => d.kind === "log"));
  if (self && collector && collector.hostId !== hostId) {
    // The collector's rsyslog may not be listening yet when this host is
    // configured; a plain `@@` action suspends after one refusal and the
    // messages sent meanwhile are lost. Queue them and retry until it is up.
    const collectorAddr = lab.get(collector.hostId)?.address;
    if (!collectorAddr) throw new Error(`log shipping: collector ${collector.hostId} has no lab address`);
    const fwd = [
      "cat > /etc/rsyslog.d/40-arena-forward.conf <<'EOF'",
      `*.* action(type="omfwd" target="${collectorAddr}" port="514" protocol="tcp" action.resumeRetryCount="-1" action.resumeInterval="2" queue.type="linkedList" queue.size="10000")`,
      "EOF",
      "systemctl restart rsyslog 2>/dev/null || true",
    ].join("\n");
    configure.push({ name: "log-forward", raw: asRoot(fwd) });
  }
  // P3 source control: Gitea with a directory auth source. Configured after
  // the IPA join (it binds to 389-ds), and pinned to a loopback+lab listener
  // so the same probe path works from the host.
  let gitConfigure: Task[] = [];
  if (kinds.has("git")) {
    const ipaUsersDn = `cn=users,cn=accounts,${ipaBaseFor(domain)}`;
    const ipaGroupsDn = `cn=groups,cn=accounts,${ipaBaseFor(domain)}`;
    const gitFqdn = `${hostId}.${labDomainFor(spec)}`;
    // Three staged tasks, matching the catalog's git-configure/git-seed
    // groups. Keeping them separate matters: one combined script exceeds the
    // OpenSSH ControlMaster sendmsg limit ("Message too long") on a long run.
    const gitBase = [
      // Preflight: the binary is baked (Debian has no package). A guest that
      // booted the plain base image must say so, not restart-loop.
      "[ -x /usr/local/bin/gitea ] || { echo 'git: gitea binary missing — this host needs the baked catalog image'; exit 1; }",
      "id git >/dev/null 2>&1 || useradd --system --shell /bin/bash --home /var/lib/gitea git",
      "mkdir -p /var/lib/gitea/{custom,data,log} /etc/gitea",
      "chown -R git:git /var/lib/gitea",
      "chmod 750 /var/lib/gitea/{custom,data,log}",
      ...(ipaEndpoint ? [
        "cat > /etc/gitea/app.ini <<'EOF'",
        "APP_NAME = Arena",
        "RUN_USER = git",
        "WORK_PATH = /var/lib/gitea",
        "[server]",
        // 0.0.0.0 so the same endpoint answers on loopback (local probe)
        // and on the lab address (peers). The management plane is trusted.
        "HTTP_ADDR = 0.0.0.0",
        "HTTP_PORT = 3000",
        "ROOT_URL = http://localhost:3000/",
        "DISABLE_SSH = false",
        "START_SSH_SERVER = true",
        `SSH_DOMAIN = ${gitFqdn}`,
        "SSH_PORT = 2222",
        "SSH_LISTEN_HOST = 0.0.0.0",
        "SSH_LISTEN_PORT = 2222",
        "[database]",
        "DB_TYPE = sqlite3",
        "PATH = /var/lib/gitea/data/gitea.db",
        "[security]",
        "INSTALL_LOCK = true",
        "DISABLE_GIT_HOOKS = true",
        "[service]",
        "DISABLE_REGISTRATION = true",
        "[log]",
        "MODE = file",
        "FILE_NAME = /var/lib/gitea/log/gitea.log",
        "EOF",
        "chown git:git /etc/gitea/app.ini && chmod 640 /etc/gitea/app.ini",
      ] : []),
      "cat > /etc/systemd/system/gitea.service <<'EOF'",
      "[Unit]",
      "Description=Gitea",
      "After=network.target",
      "[Service]",
      "User=git",
      "Group=git",
      "WorkingDirectory=/var/lib/gitea",
      "ExecStart=/usr/local/bin/gitea web --config /etc/gitea/app.ini",
      "Restart=always",
      "Environment=USER=git HOME=/var/lib/gitea",
      "[Install]",
      "WantedBy=multi-user.target",
      "EOF",
      "systemctl daemon-reload",
      "systemctl enable --now gitea >/dev/null 2>&1 || true",
      "systemctl restart gitea",
    ].join("\n");
    // Gitea 1.22 does not read [[auth.ldap]] from app.ini and its CLI has no
    // group flags, so the source is created through the admin CLI and its
    // stored config is extended with the LDAP group→team map (the fields the
    // 1.22 source struct already understands). Users link to this source on
    // first LDAP login, and Gitea syncs their group membership into teams.
    const gitLdap = ipaEndpoint ? [
      `for i in $(seq 1 30); do curl -fsS --max-time 3 http://127.0.0.1:3000/api/v1/version >/dev/null 2>&1 && break; sleep 2; done`,
      `EXISTING_ID=$(sudo -n -u git gitea admin auth list --config /etc/gitea/app.ini 2>/dev/null | awk '/FreeIPA/ {print $1; exit}')`,
      `[ -z "$EXISTING_ID" ] || sudo -n -u git gitea admin auth delete --config /etc/gitea/app.ini --id "$EXISTING_ID" >/dev/null 2>&1 || true`,
      `sudo -n -u git gitea admin auth add-ldap --config /etc/gitea/app.ini --name FreeIPA --host ${ipaEndpoint.address} --port 389 --security-protocol unencrypted --bind-dn 'uid=admin,${ipaUsersDn}' --bind-password '${labSecret(runId, "ipa-admin")}' --user-search-base '${ipaUsersDn}' --user-filter '(&(objectClass=posixAccount)(uid=%s))' --username-attribute uid --email-attribute mail --firstname-attribute givenName --surname-attribute sn || { echo 'git: could not register the LDAP auth source'; exit 1; }`,
      `sudo -n -u git gitea admin auth list --config /etc/gitea/app.ini 2>/dev/null | grep -q FreeIPA || { echo 'git: LDAP auth source not registered'; exit 1; }`,
      `sudo -n -u git python3 - <<'PY'`,
      "import json, sqlite3",
      "db = sqlite3.connect('/var/lib/gitea/data/gitea.db')",
      "row = db.execute(\"select id, cfg from login_source where name='FreeIPA'\").fetchone()",
      "if not row: raise SystemExit('git: FreeIPA source missing from the Gitea database')",
      "cfg = json.loads(row[1])",
      `cfg.update({"GroupsEnabled": True, "GroupDN": "${ipaGroupsDn}", "GroupFilter": "(objectClass=posixGroup)", "GroupMemberUID": "member", "UserUID": "dn", "GroupTeamMap": json.dumps({"cn=nurse,${ipaGroupsDn}": {"arena": ["nurse"]}, "cn=physician,${ipaGroupsDn}": {"arena": ["physician"]}}), "GroupTeamMapRemoval": True})`,
      "db.execute('update login_source set cfg=? where id=?', (json.dumps(cfg), row[0]))",
      "db.commit()",
      "PY",
      "systemctl restart gitea",
    ].join("\n") : "";
    // The org, teams and repos are ordinary Gitea objects created through
    // the admin API, after the LDAP source and before any user login. The
    // group→team map above is what grants access; the repo is private.
    const gitSeed = ipaEndpoint ? [
      `for i in $(seq 1 30); do curl -fsS --max-time 3 http://127.0.0.1:3000/api/v1/version >/dev/null 2>&1 && break; sleep 2; done`,
      `ADMIN_PW='${labSecret(runId, "gitea-admin")}'`,
      `sudo -n -u git gitea admin user create --config /etc/gitea/app.ini --username arena-admin --password "$ADMIN_PW" --email arena-admin@${domain} --admin --must-change-password=false >/dev/null 2>&1 || true`,
      `TOKEN=$(sudo -n -u git gitea admin user generate-access-token --config /etc/gitea/app.ini --username arena-admin --token-name arena-admin-$$ --scopes all --raw 2>/dev/null | tail -n 1)`,
      `[ -n "$TOKEN" ] || { echo 'git: could not mint the admin token'; exit 1; }`,
      `api() { curl -fsS --max-time 10 -H "Authorization: token $TOKEN" -H 'Content-Type: application/json' "$@"; }`,
      `api http://127.0.0.1:3000/api/v1/orgs/arena >/dev/null 2>&1 || api -X POST http://127.0.0.1:3000/api/v1/orgs -d '{"username":"arena","full_name":"Arena","visibility":"private"}' >/dev/null`,
      `team_id() { api http://127.0.0.1:3000/api/v1/orgs/arena/teams | jq -r --arg n "$1" '.[] | select(.name==$n) | .id' | head -1; }`,
      `NURSE_ID=$(team_id nurse); [ -n "$NURSE_ID" ] || NURSE_ID=$(api -X POST http://127.0.0.1:3000/api/v1/orgs/arena/teams -d '{"name":"nurse","permission":"write","units":["repo.code","repo.issues","repo.pulls"]}' | jq -r .id)`,
      `PHYS_ID=$(team_id physician); [ -n "$PHYS_ID" ] || PHYS_ID=$(api -X POST http://127.0.0.1:3000/api/v1/orgs/arena/teams -d '{"name":"physician","permission":"read","units":["repo.code","repo.issues","repo.pulls"]}' | jq -r .id)`,
      `[ -n "$NURSE_ID" ] && [ -n "$PHYS_ID" ] || { echo 'git: teams not created'; exit 1; }`,
      `api http://127.0.0.1:3000/api/v1/repos/arena/public >/dev/null 2>&1 || api -X POST http://127.0.0.1:3000/api/v1/orgs/arena/repos -d '{"name":"public","private":false,"auto_init":true,"default_branch":"main"}' >/dev/null`,
      `api http://127.0.0.1:3000/api/v1/repos/arena/patient-records >/dev/null 2>&1 || api -X POST http://127.0.0.1:3000/api/v1/orgs/arena/repos -d '{"name":"patient-records","private":true,"auto_init":true,"default_branch":"main"}' >/dev/null`,
      `api -X PUT "http://127.0.0.1:3000/api/v1/teams/$NURSE_ID/repos/arena/patient-records" >/dev/null`,
      `api -X PUT "http://127.0.0.1:3000/api/v1/teams/$PHYS_ID/repos/arena/patient-records" >/dev/null`,
      `api http://127.0.0.1:3000/api/v1/repos/arena/patient-records | jq -e '.name=="patient-records"' >/dev/null || { echo 'git: private repo not created'; exit 1; }`,
      `for i in $(seq 1 30); do bash -c '</dev/tcp/127.0.0.1/2222' >/dev/null 2>&1 && break; sleep 1; done`,
      `bash -c '</dev/tcp/127.0.0.1/2222' >/dev/null 2>&1 || { echo 'git: Gitea SSH did not start'; exit 1; }`,
    ].join("\n") : "";
    gitConfigure = [
      { name: "git-configure", raw: asRoot(gitBase) },
      ...(gitLdap ? [{ name: "git-ldap-source", raw: asRoot(gitLdap) }] : []),
      ...(gitSeed ? [{ name: "git-seed", raw: asRoot(gitSeed) }] : []),
    ];
  }

  // Domain membership is a declared dependency, not an inference from role:
  // a host that depends on the FreeIPA server joins the realm it serves.
  if (ipaHost && ipaHost.hostId !== hostId && (inst?.dependsOn ?? []).includes(ipaHost.hostId)) {
    const serverFqdn = `${ipaHost.hostId}.${ipaDomainFor(spec)}`;
    const fqdn = `${hostId}.${labDomainFor(spec)}`;
    const adminPw = labSecret(runId, "ipa-admin");
    const join = [
      `SRV='${serverFqdn}'`,
      `FQDN='${fqdn}'`,
      ...(ipaEndpoint ? [`grep -q " $SRV" /etc/hosts || echo "${ipaEndpoint.address} $SRV ${ipaHost.hostId}" >> /etc/hosts`] : []),
      ...(self ? [`grep -q " $FQDN" /etc/hosts || echo "${self.address} $FQDN ${hostId}" >> /etc/hosts`] : []),
      'hostnamectl set-hostname "$FQDN"',
      "mkdir -p /var/log/arena",
      "if [ ! -f /etc/ipa/default.conf ]; then",
      `  ipa-client-install --unattended --domain='${ipaDomainFor(spec)}' --server="$SRV" --principal=admin --password='${adminPw}' --mkhomedir --no-ntp --force-join > /var/log/arena/ipa-client.log 2>&1 || { tail -n 60 /var/log/arena/ipa-client.log; exit 1; }`,
      "fi",
      // A mail host delivers to domain users through postfix local(8), which
      // needs a resolvable account and an existing home before Dovecot (LDAP
      // userdb) can serve the same Maildir. Created after the join, when SSSD
      // resolves the directory ids; a persona that does not resolve fails here.
      ...((kinds.has("smtp") || kinds.has("imap"))
        ? (spec.personas ?? []).map((p) => ipaUserIdFor(p.id)).filter(Boolean).map((uid) =>
            `id '${uid}' >/dev/null 2>&1 || { echo 'mail: persona ${uid} does not resolve through SSSD'; exit 1; }; install -d -o '${uid}' -g '${uid}' -m 0700 "/home/${uid}"`)
        : []),
    ].join("\n");
    configure.push({ name: "ipa-client-join", raw: asRoot(join) });
  }
  // T-40: service keytabs. The host keytab from ipa-client-install identifies
  // the host, not a service. A member that terminates a Kerberized service
  // gets its own principal and keytab, created once with the admin ticket and
  // destroyed immediately. Keytab contents are never logged or read back.
  if (joinsIpa && ipaEndpoint && ipaHost) {
    const fqdn = `${hostId}.${labDomainFor(spec)}`;
    const serverFqdn = `${ipaHost.hostId}.${ipaDomainFor(spec)}`;
    const adminPw = labSecret(runId, "ipa-admin");
    const keytabs = [
      ...(kinds.has("db") ? [{ svc: "postgres", path: "/etc/postgresql/postgres.keytab", owner: "postgres:postgres" }] : []),
      ...(kinds.has("imap") ? [{ svc: "imap", path: "/etc/dovecot/dovecot.keytab", owner: "dovecot:dovecot" }] : []),
      ...(kinds.has("http") ? [{ svc: "HTTP", path: "/etc/apache2/http.keytab", owner: "www-data:www-data" }] : []),
    ];
    if (keytabs.length) {
      const keytabScript = [
        "set -e",
        `FQDN='${fqdn}'`,
        `SRV='${serverFqdn}'`,
        `printf '%s\\n' '${adminPw}' | kinit admin >/dev/null 2>&1 || { echo 'gssapi: kinit admin failed'; exit 1; }`,
        `ipa host-show "$FQDN" >/dev/null 2>&1 || ipa host-add "$FQDN" --force${self ? ` --ip-address='${self.address}'` : ""} >/dev/null 2>&1 || { echo 'gssapi: host entry $FQDN is missing'; exit 1; }`,
        ...keytabs.map((k) => [
          `if ! ipa service-show "${k.svc}/$FQDN" >/dev/null 2>&1; then ipa service-add --force "${k.svc}/$FQDN" >/tmp/arena-service-add.err 2>&1 || { echo 'gssapi: service-add ${k.svc}/$FQDN failed'; cat /tmp/arena-service-add.err; kdestroy || true; exit 1; }; fi`,
          `install -d -m 0755 "$(dirname '${k.path}')"`,
          `if ! ipa-getkeytab -s "$SRV" -p "${k.svc}/$FQDN" -k '${k.path}' >/tmp/arena-getkeytab.err 2>&1; then echo 'gssapi: getkeytab ${k.svc}/$FQDN failed'; cat /tmp/arena-getkeytab.err; kdestroy || true; exit 1; fi`,
          `chown '${k.owner}' '${k.path}' && chmod 0600 '${k.path}'`,
          `klist -k '${k.path}' >/dev/null 2>&1 || { echo 'gssapi: keytab ${k.svc} is not readable'; kdestroy || true; exit 1; }`,
        ].join("\n")),
        "kdestroy || true",
      ].join("\n");
      configure.push({ name: "ipa-service-keytabs", raw: asRoot(keytabScript) });
    }

    // Postgres: GSSAPI lives on its own database. pg_hba is first-match, so a
    // catch-all `gss` rule would shadow the LDAP rule that proves directory
    // password auth. `app` keeps T-33/T-39 exactly as they were; `gssdb` is
    // the Kerberos path and is created by db-seed-access below.
    if (kinds.has("db") && self) {
      const dbGss = [
        "for f in /etc/postgresql/*/main/pg_hba.conf; do",
        '  [ -f "$f" ] || continue',
        `  grep -q 'gssdb.*gss include_realm=0' "$f" || sed -i '1i host gssdb all ${self.cidr} gss include_realm=0' "$f"`,
        `  grep -q 'gssdb.*127.0.0.1/32.*gss' "$f" || sed -i '1i host gssdb all 127.0.0.1/32 gss include_realm=0' "$f"`,
        "done",
        "for f in /etc/postgresql/*/main/postgresql.conf; do",
        '  [ -f "$f" ] || continue',
        '  grep -q "arena-lab gssapi" "$f" || printf "\\n# arena-lab gssapi\\nkrb_server_keyfile = \'/etc/postgresql/postgres.keytab\'\\n" >> "$f"',
        "done",
        "systemctl restart postgresql || true",
        "for i in $(seq 1 30); do pg_isready -h 127.0.0.1 -U app -d app >/dev/null 2>&1 && break; sleep 1; done",
        "pg_isready -h 127.0.0.1 -U app -d app >/dev/null 2>&1 || { echo 'gssapi: postgres did not restart'; pg_lsclusters; journalctl -u postgresql --no-pager -n 80; tail -n 80 /var/log/postgresql/*.log 2>/dev/null; exit 1; }",
      ].join("\n");
      configure.push({ name: "db-gssapi", raw: asRoot(dbGss) });
    }

    // Dovecot: GSSAPI joins the existing LDAP passdb as an SASL mechanism, so
    // the password path (T-31/T-39) still works and Kerberos is additive.
    if (kinds.has("imap")) {
      const imapGss = [
        "cat > /etc/dovecot/conf.d/99-arena-gssapi.conf <<'EOF'",
        `auth_gssapi_hostname = ${fqdn}`,
        "auth_krb5_keytab = /etc/dovecot/dovecot.keytab",
        "EOF",
        "chmod 644 /etc/dovecot/conf.d/99-arena-gssapi.conf",
        "doveconf -n 2>/dev/null | grep -q 'auth_mechanisms = plain login gssapi' || { echo 'gssapi: dovecot did not enable the GSSAPI mechanism'; exit 1; }",
        "doveconf -n 2>/dev/null | grep -q 'auth_krb5_keytab' || { echo 'gssapi: dovecot did not load the service keytab'; exit 1; }",
        "doveconf -n 2>/dev/null | grep -q 'driver = ldap' || { echo 'gssapi: LDAP passdb disappeared from dovecot'; exit 1; }",
        "systemctl restart dovecot",
      ].join("\n");
      configure.push({ name: "imap-gssapi", raw: asRoot(imapGss) });
    }

    // Apache: mod_auth_gssapi on a /gssapi location. The page echoes
    // REMOTE_USER, so a 200 with the persona uid proves the authenticated
    // principal, not merely that the module answered.
    if (kinds.has("http")) {
      const httpGss = [
        "mkdir -p /var/www/html/gssapi",
        "cat > /var/www/html/gssapi/index.php <<'EOF'",
        "<?php echo $_SERVER['REMOTE_USER'] ?? 'NO-USER'; ?>",
        "EOF",
        "chmod 644 /var/www/html/gssapi/index.php",
        "a2enmod auth_gssapi >/dev/null",
        "cat > /etc/apache2/conf-available/arena-gssapi.conf <<'EOF'",
        '<Location "/gssapi">',
        "  AuthType GSSAPI",
        '  AuthName "Arena Kerberos"',
        "  GssapiCredStore keytab:/etc/apache2/http.keytab",
        "  GssapiLocalName On",
        "  Require valid-user",
        "</Location>",
        "EOF",
        "a2enconf arena-gssapi >/dev/null",
        "apache2ctl configtest",
        "systemctl restart apache2",
      ].join("\n");
      configure.push({ name: "http-gssapi", raw: asRoot(httpGss) });
    }
  }
  // Gitea's LDAP source needs the realm reachable (join + resolver above).
  if (gitConfigure.length) configure.push(...gitConfigure);

  tasks.push(...configure);

  const units = resolveProfileUnits(profile, hostInst?.os ?? "").map((u) => `systemctl enable --now ${u} || exit 1`).join("\n");
  tasks.push({ name: "profile-enable", raw: asRoot(units) });

  if (kinds.has("db")) {
    const dbRoles = joinsIpa
      ? (spec.personas ?? []).map((p) => ipaUserIdFor(p.id)).filter(Boolean).map((uid) =>
          `runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${uid}'" | grep -q 1 || runuser -u postgres -- psql -c 'CREATE ROLE "${uid}" LOGIN'`)
      : [];
    const seed = [
      // The baked image may already have postgres running with the old
      // pg_hba; reload after the config edit, then seed over local trust.
      "systemctl reload postgresql || systemctl restart postgresql",
      "runuser -u postgres -- psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='app'\" | grep -q 1 || runuser -u postgres -- psql -c \"CREATE ROLE app LOGIN CREATEDB\"",
      "runuser -u postgres -- psql -tAc \"SELECT 1 FROM pg_database WHERE datname='app'\" | grep -q 1 || runuser -u postgres -- createdb -O app app",
      ...(joinsIpa ? ["runuser -u postgres -- psql -tAc \"SELECT 1 FROM pg_database WHERE datname='gssdb'\" | grep -q 1 || runuser -u postgres -- createdb -O app gssdb"] : []),
      "runuser -u postgres -- psql -c \"ALTER ROLE app CREATEDB\" >/dev/null",
      // Readiness probe credential: `app` over the segment is scram-only and
      // its password is the planted vuln (or rotated unknown), so the
      // cross-host SQL proof gets its own least-privilege role + table.
      `runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='arena_probe'" | grep -q 1 || runuser -u postgres -- psql -c "CREATE ROLE arena_probe LOGIN"`,
      `runuser -u postgres -- psql -c "ALTER ROLE arena_probe PASSWORD '${labSecret(runId, "db-probe")}'" >/dev/null`,
      `runuser -u postgres -- psql -d app -c "CREATE TABLE IF NOT EXISTS arena_probe_ping (v text); DELETE FROM arena_probe_ping; INSERT INTO arena_probe_ping VALUES ('arena-db-ready'); GRANT SELECT ON arena_probe_ping TO arena_probe;" >/dev/null`,
      // Read-only role for employee agents; SELECT on employees is granted after the seed creates it.
      `runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='arena_staff'" | grep -q 1 || runuser -u postgres -- psql -c "CREATE ROLE arena_staff LOGIN"`,
      `runuser -u postgres -- psql -c "ALTER ROLE arena_staff PASSWORD '${labSecret(runId, "db-staff")}'" >/dev/null`,
      ...(spec.plantedVulns.some((v) => v.targetHostId === hostId && v.type === "weak-cred")
        ? [`runuser -u postgres -- psql -c "ALTER ROLE app PASSWORD '${WEAK_DB_PASSWORD}'"`]
        : []),
      ...dbRoles,
    ].join("\n");
    tasks.push({ name: "db-seed-access", raw: asRoot(seed) });
  }
  if (kinds.has("ldap") && !isFreeipaServer) {
    const pw = labSecret(runId, "ldap-admin");
    const seed = [
      `PW='${pw}'`,
      `for i in $(seq 1 20); do ldapsearch -x -H ldap://127.0.0.1 -D cn=admin,${ldapBase} -w "$PW" -b ${ldapBase} -s base dn >/dev/null 2>&1 && break; sleep 1; done`,
      `ldapsearch -x -H ldap://127.0.0.1 -D cn=admin,${ldapBase} -w "$PW" -b ${ldapBase} -s base dn >/dev/null 2>&1 || exit 1`,
      `ldapsearch -x -H ldap://127.0.0.1 -D cn=admin,${ldapBase} -w "$PW" -b ou=people,${ldapBase} -s base dn >/dev/null 2>&1 || ldapadd -x -H ldap://127.0.0.1 -D cn=admin,${ldapBase} -w "$PW" <<'EOF'`,
      `dn: ou=people,${ldapBase}`,
      "objectClass: organizationalUnit",
      "ou: people",
      "",
      `dn: uid=probe,ou=people,${ldapBase}`,
      "objectClass: inetOrgPerson",
      "objectClass: posixAccount",
      "uid: probe",
      "cn: Probe User",
      "sn: User",
      "gecos: Probe User",
      "uidNumber: 10001",
      "gidNumber: 10001",
      "homeDirectory: /home/probe",
      "loginShell: /bin/bash",
      `mail: probe@${domain}`,
      "EOF",
      // The directory probe account backs IMAP login on mail hosts that
      // depend on this directory; set its password through the modify exop
      // (server-hashed) and prove the bind here, not at probe time.
      `ldappasswd -x -H ldap://127.0.0.1 -D cn=admin,${ldapBase} -w "$PW" -s '${labSecret(runId, "mail-probe")}' 'uid=probe,ou=people,${ldapBase}'`,
      `ldapwhoami -x -H ldap://127.0.0.1 -D 'uid=probe,ou=people,${ldapBase}' -w '${labSecret(runId, "mail-probe")}' >/dev/null 2>&1 || { echo 'ldap-seed: probe user cannot bind with the seeded password'; exit 1; }`,
    ].join("\n");
    tasks.push({ name: "ldap-seed", raw: asRoot(seed) });
  }
  if (isFreeipaServer) {
    const adminPw = labSecret(runId, "ipa-admin");
    // Planted weakness (labelled, never silent): a weak-cred vuln on the DC
    // seeds a service account with a known-weak, sprayable password. Without
    // the vuln the account does not exist.
    const weakSvc = spec.plantedVulns.some((v) => v.targetHostId === hostId && v.type === "weak-cred")
      ? [
          `ipa user-show '${WEAK_IPA_USER}' >/dev/null 2>&1 || ipa user-add '${WEAK_IPA_USER}' --first='Service' --last='Report' --shell=/bin/bash`,
          `printf '%s\\n%s\\n' '${WEAK_IPA_PASSWORD}' '${WEAK_IPA_PASSWORD}' | ipa passwd '${WEAK_IPA_USER}'`,
          `ipa user-show '${WEAK_IPA_USER}' | grep -q 'Password: True' || { echo 'weak svc password not set'; exit 1; }`,
        ]
      : [];
    // Personas become real directory users; a group per role gives the org
    // chart an object to hang access and sudo policy from later.
    const users = (spec.personas ?? []).map((p) => {
      const uid = ipaUserIdFor(p.id);
      if (!uid) return "";
      const first = (p.role || uid).replace(/[^A-Za-z0-9]/g, "").slice(0, 32) || "User";
      const group = (p.role || "staff").toLowerCase().replace(/[^a-z0-9._-]/g, "").slice(0, 32) || "staff";
      const pw = ipaUserSecret(runId, p.id);
      return [
        `ipa user-show '${uid}' >/dev/null 2>&1 || ipa user-add '${uid}' --first='${first}' --last='User' --gecos='${first}' --shell=/bin/bash`,
        `printf '%s\\n%s\\n' '${pw}' '${pw}' | ipa passwd '${uid}' >/dev/null 2>&1 || true`,
        // An admin-set IPA password is a *temporary* credential: Kerberos and
        // 389-ds both refuse it until it is changed (observed live: kinit says
        // "Password expired"; a simple bind returns 49). Lab personas need a
        // usable credential, so expiry is pushed out and then PROVEN by an
        // actual directory bind — a seeded user that cannot authenticate fails
        // here, not silently at probe time.
        `ipa user-mod '${uid}' --setattr=krbpasswordexpiration=20380101000000Z >/dev/null 2>&1 || true`,
        `ldapwhoami -x -H ldap://127.0.0.1 -D 'uid=${uid},cn=users,cn=accounts,${ipaBaseFor(domain)}' -w '${pw}' >/dev/null 2>&1 || { echo 'persona ${uid}: seeded password cannot bind to the directory'; exit 1; }`,
        `ipa group-show '${group}' >/dev/null 2>&1 || ipa group-add '${group}' --desc='${group}'`,
        `ipa group-add-member '${group}' --users='${uid}' >/dev/null 2>&1 || true`,
      ].join("\n");
    }).filter(Boolean);
    const seed = [
      // The installer returns before every daemon is answering on slow guests;
      // wait for the admin ticket instead of failing the first kinit.
      `for i in $(seq 1 30); do printf '%s\\n' '${adminPw}' | kinit admin >/dev/null 2>&1 && break; sleep 2; done`,
      "klist >/dev/null 2>&1 || { echo 'kinit admin failed after ipa-server-install'; exit 1; }",
      // The realm's own DNS only knows the IPA subdomain; delegate the parent
      // lab zone back to the gateway so members and the DC resolve each other.
      ...(gwEndpoint ? [`ipa dnsforwardzone-show '${domain}.' >/dev/null 2>&1 || ipa dnsforwardzone-add '${domain}.' --forwarder=${gwEndpoint.address} --forward-policy=only`] : []),
      ...users,
      ...weakSvc,
      // Members discover the realm through SRV records; a fresh install does
      // not always publish the full set (observed live: zone authoritative,
      // _kerberos._udp NXDOMAIN). The platform guarantees them and proves
      // them, so a member's resolver check cannot fail on installer variance.
      ...(() => {
        const fqdn = `${hostId}.${ipaDomainFor(spec)}`;
        const recs: Array<[string, string]> = [
          ["_kerberos._udp", "0 100 88"],
          ["_kerberos._tcp", "0 100 88"],
          ["_ldap._tcp", "0 100 389"],
          ["_kpasswd._udp", "0 100 464"],
        ];
        // The installer returns before named always answers; retry the add and
        // the readback so a slow DNS start does not fail a correct seed.
        return [
          "for i in $(seq 1 20); do",
          ...recs.map(([name, w]) => `  ipa dnsrecord-add '${ipaDomainFor(spec)}' '${name}' --srv-rec="${w} ${fqdn}." >/dev/null 2>&1 || true`),
          '  missing=""',
          `  for r in ${recs.map(([n]) => n).join(" ")}; do dig +short @127.0.0.1 "$r.${ipaDomainFor(spec)}" SRV | grep -q . || missing="$missing $r"; done`,
          '  [ -z "$missing" ] && break',
          "  sleep 1",
          "done",
          '[ -z "$missing" ] || { echo "ipa-seed: missing SRV$missing"; exit 1; }',
        ];
      })(),
      "kdestroy || true",
    ].join("\n");
    tasks.push({ name: "ipa-seed", raw: asRoot(seed) });
  }
  return tasks;
}

export function tasksFor(spec: EnvironmentSpec, runId: string, hostId: string): Task[] {
  const inst = spec.instances.find((i) => i.hostId === hostId);
  if (!inst) return [];
  const vulns = spec.plantedVulns.filter((v) => v.targetHostId === hostId);
  const personas = spec.personas ?? [];
  const roleTasks: Task[] = [];
  if (inst.role === "web") {
    const rows = personas.map((p) => `<li>${html(p.id)} — ${html(p.role)}</li>`).join("");
    roleTasks.push(writeFileTask("deploy_app", "/var/www/html/index.php",
      `<?php header('X-Arena-Host: ${html(hostId)}'); ?><h1>${html(spec.name)} intranet</h1><ul>${rows}</ul>\n`));
    if (vulns.some((v) => v.type === "code-flaw" || v.type === "cve")) {
      // Planted command injection (T1059): host param concatenated into a shell.
      roleTasks.push(writeFileTask("plant_code_flaw", "/var/www/html/diag.php",
        `<?php $h = $_GET['host'] ?? 'localhost'; echo "<pre>" . shell_exec("getent hosts " . $h) . "</pre>";\n`));
    } else {
      roleTasks.push({ name: "ensure_no_code_flaw", raw: "rm -f /var/www/html/diag.php" });
    }
    // CVE registry targets: install prep + the vulnerable app files verbatim.
    for (const v of vulns.filter((x) => x.type === "cve")) {
      const t = vulnTargetFor(v);
      if (!t) continue; // the gate fails closed later; plant nothing silently
      for (const task of t.install) roleTasks.push({ name: `cve_prep_${t.id}`, raw: task });
      for (const f of t.files) roleTasks.push(writeFileTask(`cve_plant_${t.id}`, f.path, f.body));
    }
    roleTasks.push({ name: "verify_web", raw: "test -s /var/www/html/index.php && apache2ctl -t" });
  } else if (inst.role === "db") {
    roleTasks.push({ name: "wait_postgres", raw: "for i in $(seq 1 60); do pg_isready -U app -d app -h 127.0.0.1 >/dev/null && exit 0; sleep 1; done; exit 1" });
    for (const d of inst.databases.map((d) => d.replace(/[^a-zA-Z0-9_]/g, "")).filter((d) => d && d !== "app")) {
      roleTasks.push({ name: `create_db_${d}`, raw: `psql -U app -d app -tAc "SELECT 1 FROM pg_database WHERE datname='${d}'" | grep -q 1 || createdb -U app ${d}` });
    }
    const seed = [
      "CREATE TABLE IF NOT EXISTS employees (id text PRIMARY KEY, role text, credentials_profile text, risk text);",
      ...personas.map((p) => `INSERT INTO employees VALUES (${sqlLit(p.id)}, ${sqlLit(p.role)}, ${sqlLit(p.credentialsProfile)}, ${sqlLit(p.riskProfile)}) ON CONFLICT (id) DO NOTHING;`),
      "CREATE TABLE IF NOT EXISTS secrets (objective_id text PRIMARY KEY, value text);",
      ...spec.objectives.filter((o) => o.asset === hostId).map((o) => `INSERT INTO secrets VALUES (${sqlLit(o.id)}, ${sqlLit(canaryValue(runId, o.id))}) ON CONFLICT (objective_id) DO UPDATE SET value = EXCLUDED.value;`),
    ].join("\n");
    roleTasks.push(writeFileTask("write_seed", "/tmp/arena-seed.sql", seed));
    roleTasks.push({ name: "seed_data", raw: "psql -v ON_ERROR_STOP=1 -U app -d app -f /tmp/arena-seed.sql && rm -f /tmp/arena-seed.sql" });
    if (inst.runtime === "vm") {
      roleTasks.push({ name: "grant_staff_read", raw: `psql -v ON_ERROR_STOP=1 -U app -d app -c "GRANT SELECT ON employees TO arena_staff"` });
    }
    if (!vulns.some((v) => v.type === "weak-cred")) {
      // Not planted: the image's weak password must not survive configuration.
      roleTasks.push({ name: "rotate_credentials", raw: `psql -v ON_ERROR_STOP=1 -U app -d app -c "ALTER USER app PASSWORD '$(head -c 18 /dev/urandom | base64 | tr -dc A-Za-z0-9)'"` });
    }
  } else {
    roleTasks.push({ name: "seed_marker", raw: `echo ${b64(hostId)} | base64 -d > /etc/arena-host` });
  }
  const vm = inst.runtime === "vm";
  const profileTasks = vm ? vmProfileTasks(spec, runId, hostId) : [];
  // VM role tasks were written for Docker (root); the SSH user needs sudo.
  const wrapped = vm ? roleTasks.map((t) => ({ name: t.name, raw: asRoot(t.raw) })) : roleTasks;
  return [...profileTasks, ...wrapped];
}

export function inventoryFor(spec: EnvironmentSpec, targets: InstanceTarget[]): string {
  const runtimeOf = new Map(spec.instances.map((i) => [i.hostId, i.runtime]));
  const instOf = new Map(spec.instances.map((i) => [i.hostId, i]));
  // Host vars live on each host: a static JSON inventory has no supported
  // `_meta.hostvars` (Ansible treats `_meta` as a group and drops the key).
  const hostVars = (hostId: string) => {
    const i = instOf.get(hostId);
    if (!i) return {};
    return { role: i.role, stack: i.stack, services: i.services, vulns: spec.plantedVulns.filter((v) => v.targetHostId === hostId).map((v) => v.id) };
  };
  return JSON.stringify({
    // VM guests are reached over SSH (registry endpoint, e.g.
    // arena@127.0.0.1:23001 with the run key); containers via docker.
    all: { hosts: Object.fromEntries(targets.map((t) => {
      const vars = hostVars(t.hostId);
      const ssh = (t as InstanceTarget & { ssh?: { user: string; host: string; port: number; privateKeyPath: string } }).ssh;
      if (runtimeOf.get(t.hostId) === "vm" && ssh) {
        return [t.hostId, {
          ...vars,
          ansible_connection: "ssh", ansible_host: ssh.host, ansible_port: ssh.port, ansible_user: ssh.user,
          ansible_ssh_private_key_file: ssh.privateKeyPath,
          ansible_ssh_common_args: "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        }];
      }
      return [t.hostId, { ...vars, ansible_connection: runtimeOf.get(t.hostId) === "vm" ? "ssh" : "community.docker.docker", ansible_host: t.connectVia }];
    })) },
  });
}

/**
 * Hosts in dependency order (a dependency is configured before its consumer),
 * stable by spec order among hosts that do not depend on each other. The
 * designer may emit instances in any order; the executor must not rely on a
 * lucky order or on waits to cover for it. Cycles are rejected by
 * `validateDesign`; if one reaches here, the remaining hosts are appended
 * rather than dropped.
 */
export function hostOrder(spec: EnvironmentSpec): string[] {
  const index = new Map(spec.instances.map((i, n) => [i.hostId, n]));
  const indegree = new Map<string, number>();
  const dependents = new Map<string, string[]>();
  for (const inst of spec.instances) {
    const deps = (inst.dependsOn ?? []).filter((d) => index.has(d));
    indegree.set(inst.hostId, deps.length);
    for (const dep of deps) dependents.set(dep, [...(dependents.get(dep) ?? []), inst.hostId]);
  }
  const ready = spec.instances.filter((i) => (indegree.get(i.hostId) ?? 0) === 0).map((i) => i.hostId);
  const out: string[] = [];
  while (ready.length) {
    ready.sort((a, b) => (index.get(a) ?? 0) - (index.get(b) ?? 0));
    const id = ready.shift()!;
    out.push(id);
    for (const dependent of dependents.get(id) ?? []) {
      const left = (indegree.get(dependent) ?? 0) - 1;
      indegree.set(dependent, left);
      if (left === 0) ready.push(dependent);
    }
  }
  for (const inst of spec.instances) if (!out.includes(inst.hostId)) out.push(inst.hostId);
  return out;
}

export function playbookFor(spec: EnvironmentSpec, runId: string): string {
  // JSON is valid YAML; serialising avoids hand-built YAML quoting bugs.
  return JSON.stringify(hostOrder(spec).map((hostId) => ({
    hosts: hostId,
    gather_facts: false,
    tasks: tasksFor(spec, runId, hostId).map((t) => ({ name: t.name, "ansible.builtin.raw": t.raw })),
  })), null, 2) + "\n";
}

/** Per-host success from the PLAY RECAP — one failed host never marks others failed. */
export function parseRecap(stdout: string, hostIds: string[]): Map<string, { ok: boolean; line: string }> {
  const out = new Map<string, { ok: boolean; line: string }>();
  for (const h of hostIds) {
    const line = stdout.split("\n").find((l) => new RegExp(`^${h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s+:`).test(l));
    if (!line) { out.set(h, { ok: false, line: "no recap line (host never ran)" }); continue; }
    const n = (k: string) => Number(new RegExp(`${k}=(\\d+)`).exec(line)?.[1] ?? "1");
    out.set(h, { ok: n("unreachable") === 0 && n("failed") === 0, line: line.trim() });
  }
  return out;
}

/**
 * The first failed/unreachable task per host from Ansible's default callback.
 * Reports carry the task name (never task output) so a remediation audit can
 * name the failing step without leaking guest command output into Supabase.
 */
export function failedAnsibleTasks(stdout: string): Map<string, string> {
  const out = new Map<string, string>();
  let task = "";
  for (const line of stdout.split("\n")) {
    const taskMatch = /^TASK \[([^\]]+)\]/.exec(line);
    if (taskMatch) { task = taskMatch[1].trim(); continue; }
    const fatal = /^fatal: \[([^\]]+)\]: (?:FAILED|UNREACHABLE)!/.exec(line);
    if (fatal && task && !out.has(fatal[1])) out.set(fatal[1], task);
  }
  return out;
}

export interface ConfigReport { instance: string; ok: boolean; detail: string }

export async function applyConfig(input: {
  deploymentId: string;
  orgId: string;
  spec: EnvironmentSpec;
  targets: InstanceTarget[];
  runId: string;
  checkOnly?: boolean;
}): Promise<ConfigReport[]> {
  const dir = path.join(process.cwd(), ".ansible", input.deploymentId);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "inventory.json"), inventoryFor(input.spec, input.targets));
  await writeFile(path.join(dir, "playbook.yml"), playbookFor(input.spec, input.runId));

  const result = await run("ansible-playbook", [
    path.join(dir, "playbook.yml"),
    "-i", path.join(dir, "inventory.json"),
    ...(input.checkOnly ? ["--check"] : []),
  ]).catch((e: Error & { stdout?: string; stderr?: string }) => ({ stdout: e.stdout ?? "", stderr: `${e.stderr ?? ""}\n${e.message}` }));
  const stdout = String(result.stdout ?? "");
  const combined = [stdout, String(result.stderr ?? "")].filter(Boolean).join("\n");
  // Keep the complete run beside the generated playbook for operator replay;
  // audit rows below carry only host/task names, not guest output.
  await writeFile(path.join(dir, "ansible.log"), combined.endsWith("\n") ? combined : `${combined}\n`);

  const recap = parseRecap(stdout, input.spec.instances.map((i) => i.hostId));
  const failedTasks = failedAnsibleTasks(stdout);
  const reports: ConfigReport[] = input.spec.instances.map((i) => {
    const r = recap.get(i.hostId)!;
    const task = failedTasks.get(i.hostId);
    return { instance: i.hostId, ok: r.ok, detail: r.ok ? "configured" : `ansible: ${r.line}${task ? `; failed task ${task}` : ""}` };
  });

  const sb = serviceClient();
  await sb.from("deployments").update({}).eq("id", input.deploymentId); // touch (status set by gate)
  await audit({
    orgId: input.orgId, actor: "configurator", action: "DEPLOYMENT_START", subjectType: "deployment",
    subjectId: input.deploymentId,
    detail: {
      configured: reports.filter((r) => r.ok).length,
      failed: reports.filter((r) => !r.ok).map((r) => ({ instance: r.instance, detail: r.detail })),
    },
  });
  return reports;
}
