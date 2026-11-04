# Linux-AD Organization System Design

Status: **design draft; P0 (pure topology) implemented, nothing booted** · 2026-10-30
Scope: the full system that turns a prompt like "mimic a bank network" into a
running, observable, attackable Linux organization with a FreeIPA directory.
This is an addendum to `design.md`; where the two disagree, the newer decision
here wins and `design.md` is corrected in the same change.

Nothing in this document is a verification claim. The only verified behavior in
the repo is what `tasks.md` records as live, and the FreeIPA code path added on
2026-10-30 is unit-tested only.

---

## 1. Purpose and non-goals

**Purpose.** A user describes an organization. The platform produces a
multi-site, multi-zone Linux organization with:

- real hosts, real services, real identities (FreeIPA realm), real routing and
  enforced firewalls;
- employees (persona agents) producing ordinary traffic;
- red agents attacking through the allowed paths;
- blue agents defending from telemetry only;
- a live console showing topology, telemetry, attack paths and defenses;
- scores and datasets computed from independent telemetry.

**Non-goals for this design.**

- Windows, Active Directory, SQL Server, Exchange, AD CS, Zerologon,
  PrintNightmare, RDP. They need a licensed image pipeline and a second
  telemetry model; they are explicitly out.
- Real internet access or real organizational data.
- Kernel-level VMI truth (`kvm-vmi`). The truth layer remains `mirror-only`:
  guest auditd + service logs, shipped out of band.
- Production multi-tenancy hardening beyond the existing RLS/audit design.

---

## 2. Design principles

1. **The model declares intent; the platform derives realization.** The
   designer names sites, zones, hosts, services, people, objectives and policy.
   It never writes addresses, package names, config files, nftables rules or
   shell commands.
2. **One derivation, many consumers.** Addresses, names, realms, task order and
   probes come from single functions. A plan cannot describe a different
   machine than the one that boots.
3. **A gate cannot pass itself.** Readiness is a protocol answer observed over
   the same path a user takes. Proof is independent telemetry.
4. **Fail closed.** Unknown service, unknown technique, missing sensor, missing
   dependency, undersized host: rejected before provisioning or failed at the
   gate. Never approximated.
5. **No egress.** The lab cannot reach the host, the platform plane, other
   runs, metadata endpoints or the internet. Package sets are baked.
6. **Everything is reproducible.** Same spec → same addresses, names, plan,
   tasks and probes. Randomness is limited to run nonces, proof values and
   per-run secrets.
7. **Name what is not true.** Every phase ends with an explicit not-claimed
   list in `tasks.md` and `progress.md`.

---

## 3. System map

```
prompt
  │
  ▼
Designer (LLM) ──► EnvironmentSpec (intent)
  │
  ├─ schema ─► deployability ─► coherence ─► plan (derivation)
  │                                             │
  │                                             ├─ address/name/realm map
  │                                             ├─ packages/tasks/seeds
  │                                             ├─ reachability graph
  │                                             └─ positive + negative probes
  ▼
plan digest ──► human approval ──► deploy grant
  │
  ▼
Provisioner ──► segments + routers + guests (golden images, overlays)
  │
  ▼
Configurator ──► dependency-ordered tasks per host
  │
  ▼
Readiness ──► per-host protocol + cross-host + denied-path probes
  │
  ▼
Gates ──► sensor canary + planted-proof exploit, verified in telemetry
  │
  ▼
Exercise ──► persona shifts + red objectives + blue investigation
  │
  ▼
Score + dataset + teardown
```

Planes:

| Plane | Owns | Never |
|---|---|---|
| Design | intent, coherence, plan | addresses written by the model |
| Control | approval, lifecycle, budgets | trusting the actor's claims |
| Data | segments, routers, guests, images | host or platform reachability |
| Identity | realm, users, groups, policy | passwords in the spec |
| Telemetry | sensor output, normalization, drop accounting | red/blue self-reports |
| Exercise | persona/red/blue behavior | writing ground truth |
| Evaluation | scores, datasets | scoring from actor prose |

---

## 4. Environment model (spec v2)

The current `EnvironmentSpec` is flat: one `cidr`, a list of `subnets`, a list
of `instances`. A bank needs sites, zones, links and structured policy. The
extension is additive; v1 specs normalize to a single default site.

```ts
type EnvironmentSpecV2 = {
  version: 2;
  name: string;
  provider: "kvm" | "aws" | "gcp";
  seed: string;
  difficulty: "noisy" | "standard" | "stealth";
  truthLayer: "mirror-only";              // VMI is out
  topology: {
    cidr?: string;                        // derived when absent
    sites: Site[];                        // >= 1, stable order
    zones: Zone[];                        // site-scoped
    subnets?: Subnet[];                   // derived when absent
    links: Link[];                        // WAN policy, no links for 1 site
    policies: FirewallPolicy[];           // structured, default []
  };
  instances: Instance[];
  personas: Persona[];
  objectives: Objective[];
  requiredTelemetry: string[];
  plantedVulns: PlantedVuln[];
  budgets: Budget;
};

type Site = { id: string; name: string; kind: "hq" | "branch" | "datacenter" };
type Zone = { id: string; site: string; kind: ZoneKind };
type ZoneKind = "edge" | "dmz" | "corp" | "server" | "ot" | "mgmt";
type Subnet = { name: string; site: string; zone: string; cidr: string };
type Link = { from: string; to: string; allowed: { proto: string; port: number }[] };
type ZoneRef = string; // "site/zone", "*/zone", "site/*", or "any"
type FirewallPolicy = {
  from: ZoneRef; to: ZoneRef;
  proto: "tcp" | "udp" | "icmp";
  port?: number;                        // absent = all
  action: "allow" | "deny";
  reason: string;                       // human rationale, shown in the plan
};
```

**Instance placement.** `instance.subnet` remains the join key. `instance.site`
and `instance.zone` are optional and derived from the subnet. A host with no
subnet in a multi-zone topology is a design error (already enforced).

**Compatibility.** A v1 spec with `topology.subnets[{name,cidr,zone}]` and no
`sites` normalizes to `sites:[{id:"default",kind:"hq"}]`, each subnet's `zone`
becomes a zone id, and its kind is inferred (`public`→`dmz`, else `corp`).
`firewallRules` remains a legacy display list; structured enforcement lives in
`policies`. A v1 spec has neither and keeps the flat-lab behaviour.

**Derived, not authored.**

- `cidr`: the deployment's allocated `/16`.
- `subnets`: `10.<env>.<(siteIndex << 4) | zoneIndex>.0/24` for every zone that
  has instances. Third octets 240–255 are reserved for WAN/mgmt, so the
  design allows at most 15 sites (0–14) × 16 zones (0–15); a larger design is
  refused.
- Addresses within a subnet: `.1` router, `.10+` hosts in `hostId` sort order,
  `.255` broadcast. `.2–.9` reserved.
- FQDNs: `<hostId>.<site>.<env-domain>`. Host ids are globally unique, so the
  zone is not in the name; the zone is the subnet.
- Directory: domain `ipa.<env-domain>`, realm upper-cased, base
  `dc=ipa,dc=…`, admin `uid=admin,cn=users,cn=accounts,<base>`.
- WAN: one `wan` segment `10.<env>.250.0/24`; each site router takes `.1 +
  siteIndex`; only router-to-router traffic is allowed by default.

**Example (bank intent, addresses omitted because they are derived).**

```json
{
  "version": 2,
  "name": "meridian-bank",
  "provider": "kvm",
  "topology": {
    "sites": [
      { "id": "hq", "name": "Headquarters", "kind": "hq" },
      { "id": "north", "name": "North Branch", "kind": "branch" },
      { "id": "south", "name": "South Branch", "kind": "branch" }
    ],
    "zones": [
      { "id": "edge", "site": "hq", "kind": "edge" },
      { "id": "dmz", "site": "hq", "kind": "dmz" },
      { "id": "corp", "site": "hq", "kind": "corp" },
      { "id": "server", "site": "hq", "kind": "server" },
      { "id": "corp", "site": "north", "kind": "corp" },
      { "id": "ot", "site": "north", "kind": "ot" }
    ],
    "links": [
      { "from": "hq", "to": "north", "allowed": [
        { "proto": "tcp", "port": 53 }, { "proto": "udp", "port": 53 },
        { "proto": "tcp", "port": 88 }, { "proto": "tcp", "port": 389 },
        { "proto": "tcp", "port": 445 },
        { "proto": "tcp", "port": 464 }, { "proto": "udp", "port": 464 }
      ] }
    ],
    "policies": [
      { "from": "*/edge", "to": "hq/dmz", "proto": "tcp", "port": 443, "action": "allow", "reason": "public site" },
      { "from": "hq/dmz", "to": "hq/server", "proto": "tcp", "port": 5432, "action": "deny", "reason": "only the app tier reaches the DB" },
      { "from": "hq/corp", "to": "hq/server", "proto": "tcp", "port": 5432, "action": "allow", "reason": "staff tools" }
    ]
  }
}
```

The designer prompt must say: do not write CIDRs; name sites/zones and place
hosts. Any address written by the model is ignored and re-derived.

**Designer emission contract.**

- May emit: sites, zones, instance placement, catalog services, `dependsOn`,
  personas, objectives, structured firewall policy with a reason, budgets.
- Must not emit: addresses, realm/domain strings, package names, config file
  contents, nftables syntax, shell commands, passwords, or proof values.
- May not place an attacker in `server`, an objective in `edge`, or a service
  on a host whose profile cannot install it.
- Every objective, persona, dependency and policy rule is checked; a spec that
  fails the contract is repaired once, then refused.

**Bank mapping.** The user's vocabulary maps onto the model without special
cases:

| User concept | Spec object |
|---|---|
| City / branch / worldwide node | `Site` (`hq`, `branch`, `datacenter`) |
| Department (Executive, HR, Engineering, Research) | FreeIPA group + `corp` placement |
| Executive devices and staff workstations | `Persona` + workstation instances |
| DMZ / public web | `dmz` zone + `http/apache-php` |
| Internal dev systems (git, DB, file, SSH) | `server` zone + `git`, `db`, `file`, `ssh` |
| IoT / OT devices | `ot` zone + device kinds (phase 7) |
| Firewalls between nodes | `topology.links` + structured `policies` |
| Branch-to-HQ connectivity | `links` + router policy |
| Employees doing work | persona shift routines |
| Hackbots / red team | attacker instance + red objectives |
| SOC watching | blue agent + telemetry console |

A bank is therefore a *shape of spec*, not a hardcoded template; the same
generator can produce a clinic, a university or a factory.

---

## 5. Identity plane (FreeIPA)

**Shape.** One realm per environment, one server for v1, in the `server` zone
of the HQ site. Branches authenticate across the WAN. A single DC is a single
point of failure; that failure is in scope for realism, not hidden. Replicas
are a later phase and are never claimed before they exist.

**Directory content.**

| Object | Content | Created by |
|---|---|---|
| Users | one per persona, POSIX attrs, shell, password | persona seed |
| Groups | `dept-exec`, `dept-hr`, `dept-eng`, `dept-research`, `dept-it`, `site-<id>` | persona/org seed |
| Hosts | every joined member, `host/<fqdn>` principal | client install |
| Services | `HTTP/<host>`, `git/<git>`, `postgres/<db>` (design target; the live P3 services authenticate by LDAP bind, not a service keytab) | service seed |
| HBAC | `sshd` allowed for staff groups to corp/server hostgroups; no external | policy seed |
| Sudo | IT admins on server hosts; engineering on build hosts; none for exec/HR | policy seed |
| Password policy | FreeIPA default (8+, classes), weak values only where planted | seed |

**Enrollment.** A host joins only when it declares the FreeIPA server in
`dependsOn`. Joining installs `freeipa-client`, `sssd`, `krb5-user`, writes
`/etc/ipa/default.conf`, and registers the host. No dependency, no join.

**After join (implemented in T-40).** Each member that terminates a
Kerberized service adds its own principals (`postgres/<fqdn>`, `imap/<fqdn>`,
`HTTP/<fqdn>`) and fetches keytabs with owner-only permissions, using a
temporary admin ticket that is destroyed afterwards. It does this itself, so
there is no global post-join step and no ordering hole. The password/LDAP
paths remain in place and are still probed; GSSAPI is additive.
Every guest runs chrony; Kerberos tolerates minutes, not hours, so the join
task checks `kinit`/`klist` before it reports success.

**Credentials.** Per-run deterministic secrets from `labSecret(runId,label)`;
never persisted in the spec. Persona passwords are seeded per persona; weak
and reused profiles are deliberate and labelled. Service keytabs live on their
host under root-only permissions.

**Kerberoast caveat (must be validated, not assumed).** FreeIPA service
principals get random keys; the classic AD Kerberoast target is a *user*
account carrying an SPN. The design does not claim Kerberoast until a live
crack succeeds. The v1 Linux-AD technique set instead uses: LDAP enumeration,
password spray, valid accounts, AS-REP roasting where pre-auth can be disabled,
keytab/ccache theft, pass-the-ticket, SSH/SMB lateral use, and share/DB/mail
data access. If a crackable SPN path is proven, it is added to the pack with a
gate.

---

## 6. Service catalog (v1)

Every service the model may name is here. Anything else is rejected.

| kind/impl | role | ports | configuration | seed | readyWhen | telemetry |
|---|---|---|---|---|---|---|
| `router/nftables` | site router + resolver | 53 | forwarding, per-zone interfaces, default-deny forward chain, logged drops | — | `tcp` on router admin | nftables drops |
| `ldap/freeipa` | directory | 88, 389, 636, 464 | realm, integrated DNS, admin/DS secrets | users, groups, hostgroups, HBAC/sudo, SPNs | `ldap-bind` | ipa, krb5kdc, dirsrv access |
| `dns/dnsmasq` | site resolver (if not on router) | 53 | all lab A records, IPA delegation, no external | — | `dns-query` | dnsmasq queries |
| `http/apache-php` | intranet / DMZ site | 80, 443 | vhost, PHP, GSSAPI SSO on /gssapi (T-40) | app files, personas | `http-2xx` | access/error |
| `db/postgres` | records / app DB | 5432 | `pg_hba` LDAP bind-as-user on the lab CIDR and loopback; listen on lab IP; `log_statement=all` | app role, persona role, schemas, canaries | `sql-select` | postgres log |
| `smtp/postfix` | mail | 25, 587 | mailname, destinations, lab interface; local probe mailbox on unjoined hosts | probe mailbox | `smtp-imap-roundtrip` | maillog |
| `imap/dovecot` | mail access | 143, 993 | Maildir, LDAP-only passdb on members, lab interface | mailboxes | `smtp-imap-roundtrip` | mail log |
| `git/gitea` | source control | 3000 | LDAP auth source, HTTP on lab address/loopback, SSH disabled | repos with secrets | `git-ldap-login` | gitea log |
| `log/rsyslog-collector` | collector | 514 | imtcp, per-host files | — | `tcp` | collector log |

Deferred, explicitly not in v1: `sensor/zeek`, `device/mqtt`, `device/modbus`,
`dhcp/dnsmasq`, `proxy/nginx`, `nfs`. They are phases, not promises.

The catalog's `ServiceKind` enum grows by two values: `router` and `git`.
A third (`file`) was designed but removed when O-4 closed negatively: a Samba
member cannot join FreeIPA because the DC does not answer the CLDAP NetLogon
ping, and NFSv4 `sec=krb5` authenticates the client host, not the domain user,
so file shares are deferred. The existing `dns`, `ldap`, `smtp`, `imap`,
`http`, `db`, `ssh` and `log` values keep their meaning. A design naming a
kind outside this table is rejected at deployability time, never approximated.

**PKI and transport.** FreeIPA's Dogtag CA issues host certificates. Services
that support it (389-ds, Apache, Dovecot) use them. Postgres, Dovecot and
Apache now also accept a Kerberos service ticket from a host-based service
keytab (T-40); their password/LDAP paths remain and are still probed, so the
keytab path is additive rather than a replacement. Gitea still authenticates
by LDAP bind, and its SSH/PR workflows and per-repo group authorization are
not claimed (T-42). Every plaintext service is a named non-claim, not an
oversight, and the TCP port is still the readiness proof.

**Authentication matrix.**

| Service | Authentication | Readiness client |
|---|---|---|
| SSH | GSSAPI or password through SSSD | `ssh` as a domain user |
| Apache intranet | GSSAPI (`mod_auth_gssapi`) on `/gssapi` (T-40), plus the plain 2xx app | `curl --negotiate` |
| Postgres | LDAP bind as the domain user on `app`; additive GSSAPI on `gssdb` (T-40) | `psql` (password and GSSAPI) |
| Dovecot | LDAP bind for the mailbox user; additive GSSAPI SASL (T-40) | `mutt` / `curl imap://` / `curl --negotiate` |
| Gitea | LDAP bind | web login / `GET /api/v1/user` |
| FreeIPA admin | Kerberos or simple bind | `ldapsearch` / `kinit` |

HBAC and sudo rules are seeded by the directory seed; a rule that fails to
apply fails the seed. HBAC denial is a later negative probe (a user without
the rule must not log in); it is not claimed until that probe exists.

**Profiles.** Base on every VM: `openssh-server`, `auditd`, `osquery`,
`rsyslog`, `chrony`, `curl`, `jq`, `dnsutils`, `iputils-ping`, `iptables`
(routers add `nftables`).
Client tooling comes from declared dependencies (`ldap-utils`, `swaks`, `mutt`,
`postgresql-client`, `freeipa-client`, `sssd`). The attacker gets the red
toolbox.

**Sensors are configured, not just installed.** auditd watches `/etc/passwd`,
`/etc/shadow`, `/etc/sudoers`, `/etc/krb5.keytab`, `/etc/ipa`, the web root and
the share roots, and records `execve`. osquery runs a fixed schedule
(processes, users, listening ports, mounts) instead of the empty default.
`profile-enable` fails if auditd or osquery is not running; the canary proves
the record actually reaches the collector.

**Configuration invariants.**

- Every service binds the lab address and loopback, never `0.0.0.0` by
  accident.
- Every service log is shipped to the collector; the collector is a different
  host from the service.
- Every seed is idempotent and re-runnable.
- Tasks run in dependency order (`hostOrder`), never spec order by luck.

---

## 7. Network realization and enforcement

**Segments.** One L2 segment per zone (bridge on Linux/KVM; per-zone user-space
hub on macOS dev). One WAN segment per environment. Routers are VMs with one
interface per zone plus WAN.

**Routing.** The site router forwards between its zones and to the WAN. The
default route is the router; the router has no route to the host, the
management plane or the internet. The management NIC (SSH hostfwd) is a
separate device and is not part of any lab zone.

**Policy.** Firewall rules are structured in the spec and compiled to nftables
on the routers. Default deny in the forward chain; allow established/related;
intra-zone traffic is L2 and not filtered by the router. Every drop is logged
at a bounded rate.

**Reachability is a plan artifact.** `reachabilityFor(spec)` returns:

```ts
{ allowed: Edge[], denied: Edge[], unreachableService: string[] }
Edge = { fromHost, toHost, proto, port, via: site|zone, rule }
```

- `allowed` is derived from policy × declared services.
- `denied` is a representative sample of cross-zone pairs with no allow rule.
- An objective whose asset has no allowed path from the entry is a design
  error.
- The plan and the console render the graph; red's planner consumes it.

**Probes.**

- Positive: from a real client host in the source zone to the service port.
- Negative: from a real host in the denied zone; must fail within a short
  timeout (refused or dropped, never unexpectedly succeed).
- A negative probe that succeeds fails the deployment: the firewall does not
  match the model.

**DHCP.** Not in v1. Static addresses are deterministic, observable and
reproducible. A DHCP client VLAN is a later phase with its own lease telemetry.

**DNS hierarchy.**

- Each site router/resolver serves A records for every lab host (static) and
  forwards `ipa.<env-domain>` to the DC.
- The DC serves the realm zone and forwards the parent lab zone to the site
  resolver.
- External names are refused. The FreeIPA installer's forwarder is the site
  resolver; if the installer insists on an external resolver, that is a build
  finding, not a silent fallback to the management network.
- Guests use the site resolver, not the management resolver. The
  implementation must close the existing guest-resolver gap; until it does,
  this remains a design requirement, not a fact.

**Record ownership.** The site resolver is the only writer of A/PTR records for
lab hosts; they are static and derived from the same address plan. FreeIPA owns
only `ipa.<env-domain>` and accepts no dynamic updates from members in v1.
That prevents two DNS writers for the same name and makes a wrong record a
plan diff, not a runtime accident.

---

## 8. Provisioning and configuration pipeline

1. **Design gates** (pure): schema → deployability → coherence → plan. A plan
   gap blocks provisioning.
2. **Approval.** The plan digest is stored with the deployment. The trigger
   recomputes the plan and refuses a missing or changed digest.
3. **Provision.** Allocate the `/16` (atomic claim is still an open item),
   create overlays from the digest-pinned image, start one hub/bridge per
   segment, start routers first, then infrastructure, then end hosts.
4. **Configure.** Dependency order from `hostOrder`. Each task is derived,
   idempotent and reports per host.
5. **Readiness.** Per-host protocol probes, cross-host allowed probes, denied
   probes. Any failure fails the deployment.
6. **Gates.** Sensor canary on every host; planted proof per vulnerability.
   Both read independent telemetry.
7. **Exercise.** Persona shifts, then red objectives, then blue investigation.
8. **Teardown.** Stop guests, hubs, routers; delete overlays; verify no
   orphan processes, disks or segments; record `resourcesDestroyed`.

**Executor decision (open, D-3).** The current executor is a generated
Ansible playbook of `raw` tasks. The design requires only the invariants
above; the runner is swappable. Default for v1: keep the existing executor,
because it is live-verified for the clinic; migrate to modules or a direct
transport only when the catalog grows enough to justify it. This does not
change the environment design.

**Image decision.** All packages in `allProvisionablePackages()` must be baked
into the pinned image. A package installed at configure time over the
management NIC is a design violation (no egress), not a fallback. FreeIPA is
currently in the recipe but not in the staged artifact; the image must be
rebuilt before any FreeIPA boot.

---

## 9. Population and agents

### Persona (employee) agents

- One persona = one directory user + one workstation + a routine.
- A **shift runner** on each workstation executes the routine as the persona
  (`sudo -u`, per-persona `KRB5CCNAME`), using real clients: `mutt`/`swaks`,
  `curl`, `git`, `psql`, `dig`.
  On a FreeIPA member the runner first obtains the persona's FILE ccache with
  a non-interactive `kinit` (pty helper) and proves it with
  `ldapwhoami -Y GSSAPI`; a failed setup aborts the shift instead of running
  as the SSH user. Non-member and container workstations stay local, which is
  a named non-claim.
- The runner is a baked, signed script (`/usr/local/bin/muse-shift`) plus a
  per-run routine file. It accepts only the declared routine actions; it never
  executes an arbitrary model-authored command.
- Routines are deterministic templates with seeded variation; no model is
  required for baseline noise. A model may vary content where it earns its
  cost.
- Traffic is ordinary telemetry, labelled `actor=noise` with the persona id for
  scoring only. Blue never sees the label.
- Routines are bounded: no destructive actions, no password changes, no
  persistence.
- A persona credentials profile (`strong`/`standard`/`weak`/`reused`) maps to a
  real seeded password and, for weak/reused, a real attack path.

### Red agent

- Starts on the attacker host in a declared entry zone (`edge`, `dmz` or
  `corp`, never `server`). `edge` models an external hackbot; `corp` models an
  insider or a compromised workstation.
- The spec declares one `attacker` instance with its `site` and `zone`; the
  designer cannot place it in a zone that already holds an objective. The
  entry zone determines the initial reachability set.
- Receives an objective and the reachability graph, not a map of secrets.
- Acts only through `exec` on the attacker host; ROE forbids the host,
  metadata, other runs and the internet.
- Success = platform-planted proof returned in tool output **and** observed in
  independent telemetry.
- Step/token/wall budgets; guardrails reject unverified claims.

### Blue agent

- Reads normalized telemetry only, paged.
- Detects via promoted Sigma rules plus model judgement; every claim cites a
  row it was shown.
- Responds from an allowlist (isolate, block IP/domain, kill process, disable
  account, snapshot); an unenforceable response earns nothing.
- Benign control run establishes the false-positive baseline.

### Schedule

Temporal workflow: readiness → canary/proof → persona warm-up → red objective
window → blue investigation → score. Deterministic seeds; wall-clock bounds.

---

## 10. Telemetry and truth

**Sources (v1).**

| Source | Hosts | What it proves |
|---|---|---|
| auditd | all VMs | exec, file access, user/group changes, keytab reads, log tampering |
| auth.log / sshd | all VMs | SSH attempts, accepted logins, sudo |
| postgres log | DB | connections, client address, statements |
| Apache access/error | web | requests, injection markers |
| mail log | mail | SMTP/IMAP auth and delivery |
| Gitea log | git | LDAP logins, repo access |
| FreeIPA logs | DC | binds, KDC activity, admin actions |
| nftables log | routers | denied flows, scans |
| rsyslog collector | collector | shipping health, drop counters |
| osquery | all VMs | process/user/listener state at collection time |

**Normalized row.**

```ts
{ runId, hostId, site, zone, source, kind, actor, techniqueId?, stepId?,
  outcome?, at, detail, raw? }
```

`actor ∈ red|blue|proof|noise|platform`. Ground truth is the event store, not
the agent's prose.

**Completeness.** Every source has a canary; a missing marker fails the run.
The collector records received/dropped/queue depth per host. A host with a
telemetry gap is unscorable for the window, never silently "clean".

**Known blind spots (named, not hidden).**

- SSH and TLS payloads are not visible; only connection metadata and endpoints.
- No EDR/process memory; Linux credential access is keytab/ccache/shadow, not
  LSASS.
- No network flow record unless Zeek is added (phase 2).
- No Windows event IDs; detections are Linux-native.
- A root attacker can disable sensors; the canary and collector gap make that
  visible, but it cannot be prevented inside the guest.

---

## 11. Attack paths and technique pack

A technique record (data, not prose):

```ts
{
  id: "T1110.003", name: "Password Spraying", phase: "credential-access",
  prerequisites: { zones: ["dmz","corp"], services: ["ssh","ldap"], creds: false },
  action: "spray a bounded candidate list against SSH/LDAP",
  telemetry: [{ source: "auth.log", event: "failed-password" },
              { source: "freeipa", event: "bind-failure" }],
  proof: "valid session as a seeded weak user",
  detection: "N failures across M accounts from one source in T",
  defense: "lockout policy, HBAC, MFA (not modelled)"
}
```

**v1 Linux-AD set (expressible, not all yet implemented):**

- Discovery: T1595, T1046, T1087, T1069, T1018.
- Credential: T1110.003, T1078, T1552.001 (keytabs/ccache/config), T1550.003
  (pass-the-ticket).
- Execution: T1190 + T1059.004 (web injection to shell), T1059.006 (Python on
  the attacker host).
- Lateral: T1021.004 (SSH), T1039 (SMB share), T1213 (git/wiki).
- Collection: T1005, T1039, T1114 (mail).
- Priv esc: T1548.003 (sudo), T1068 (only when a planted CVE exists; none in
  v1).
- Persistence: T1136.001, T1053.003.
- Defense evasion: T1562.001, T1070.002, T1070.003.
- Exfil: T1048 (SMTP/DNS), T1572 (tunnel), T1090 (proxy/pivot).

**Explicitly not expressible on Linux/FreeIPA:** T1021.002 (Windows admin
shares), T1550.002 (NTLM pass-the-hash), T1558.003 (Kerberoast — FreeIPA
refuses a crackable user-SPN TGS, O-3), T1003.001/.006 (LSASS/DCSync),
T1021.001 (RDP), T1649 (AD CS),
T1210 against Windows services.

**Entry conditions.** Reachability is not a path. The entry must yield a first
credential or execution: a planted code flaw on a DMZ web host, a weak/reused
persona credential reachable by a bounded spray, a public share, or a seeded
credential in a config file. `validateDesign` rejects a design whose entry
zone has no seeded route to any objective. Without this rule a bank can be
"reachable" and still unsolvable.

**Proof sinks.** A proof value may live in a DB row, a file outside the web
root, an SMB share, a mailbox, a git blob, or a directory attribute. The sink
must sit on the objective asset and be readable only through the service being
exercised; the value is random per run and appears nowhere in the spec.

**Path rule.** Every objective must have a path of allowed edges from the
entry host to the asset and a service that can produce the proof. A denied
edge on the path is a design error, not a challenge.

---

## 12. Defense model

- **Hardening baseline** per service (SSH, sudo, file permissions, service
  TLS, password policy, HBAC, SMB signing, auditd rules).
- **Detections** are Sigma rules compiled to the normalized store, versioned
  and promoted only after offline replay. Linux-AD rules must be authored; the
  existing four rules do not transfer.
- **Response enforcement**: isolate = nftables drop on the host/router; block
  IP = router rule; disable account = FreeIPA; kill process = guest; snapshot =
  VM. Each response is audited; a response that cannot be enforced scores zero.
- **False positives** are measured against persona noise, not against an empty
  lab.

---

## 13. Scoring

- Objective success: proof value observed in tool output **and** in telemetry
  on the target.
- Detection: promoted rule + cited rows; MTTD from first red ground-truth event
  to detection.
- Containment: an enforced response that stops the path.
- Visibility/analytic coverage: ATT&CK layer from the pinned pack.
- FP rate: benign control window.
- Guardrails: rejected claims and unverified prose counted per run.
- Cross-class ranking is forbidden; scores carry mode, backend, truth layer,
  catalog/profile/image versions and model ids.

---

## 14. Lifecycle, failure and scale

**Failure stages**: design, deploy, configure, readiness, gates, exercise,
teardown. Each writes a typed failure to the deployment row; a failed lab is
never scorable and never outlives the failure.

**Concurrency**: CIDR claim is not atomic today (open item). The design
requires a DB-level claim or unique constraint before concurrent deploys are
allowed.

**Resume**: not supported. A partial deploy is destroyed and retried; the
design does not pretend to resume until overlay/registry reconciliation is
specified.

**Capacity.** One VM per scored host. `maxVmInstances` is derived from host
RAM (conservative default 8). A bank branch with router + file + git + web +
DB + mail + log + 4 workstations is 11; a three-branch lab is ~25 and does not
fit a laptop. Scale options, in order:

1. single site, 8–12 VMs on a 32–64 GB host (v1 target);
2. remote KVM host (same QEMU path, larger capacity) — provider seam exists;
3. containers for unscored workstations only (truth layer degrades; never for
   scored hosts).

**Cost**: per-role estimate × hours, blocked above the budget cap before
provisioning.

---

## 15. Console

- Topology: sites → zones → hosts, with allowed/denied edges.
- Plan: packages, tasks, seeds, probes, positive/negative results.
- Live: telemetry stream filtered by host/zone/actor, attack-path overlay,
  defense decisions, score.
- History: runs, datasets, digests, failures with stage and cause.

---

## 16. Current implementation vs this design

| Design element | Repo today | Gap |
|---|---|---|
| Sites/zones/links | schema + derivation done (P0); single-site multi-zone orgs realized with routers and per-zone segments (P1) | multi-site/WAN (P5) |
| Multi-segment realization | one hub per segment, router `.1` attachments, nftables forwarding; live allowed/denied zone probes (T-24/T-27) | multi-site (P5) |
| Address derivation | per-site/zone plan derived (P0); org-v2 VM runtime uses per-segment addresses, legacy specs use the flat plan | container path remains flat |
| Firewall | structured `policies` + allowed/denied graph (P0); nftables enforcement on router VMs with live positive/negative probes (T-23/T-27) | multi-site policy (P5) |
| Reachability | allowed/denied graph + executable negative probes (T-23/T-27) | multi-site paths (P5) |
| FreeIPA | catalog, install, join, probes, gates; live Rocky 9 server + Debian member (T-26); spray and persona kinit proven (T-30); baked Rocky FreeIPA tier live (T-38); Rocky osquery active (T-44) | replica |
| Services | dns, ldap, smtp, imap, http, db, ssh, log, router, git; mail, Postgres and Gitea authenticate domain users live (T-31/T-33/T-34); one combined 5-guest org run proves all four (T-39) | file share (Samba disproven, O-4); DHCP blocked at design time |
| Personas | schema + allowlisted shift runner; model-driven persona agents live on Muse (T-29); Kerberos-authenticated member shifts live (T-35) | action-quality scoring; baked muse-shift; container personas |
| Red | db/web objectives; T1110.003 spray live and T1558.003 refused (T-30) | model-executed spray objective + scorecard, path planner |
| Blue | telemetry-only agents + 4 Sigma rules | Linux-AD rules, response enforcement |
| Network telemetry | none | Zeek (phase 2) |
| Guest resolver | gateway resolver live for members (T-28) | multi-site forwarding (P5) |
| Scale | 8 VM cap | capacity derivation, remote provider |
| Image | Debian catalog image baked (FreeIPA client, Gitea); Rocky 9 FreeIPA image baked (T-38) | x86_64 Rocky artifact not built on this arm64 host |

---

## 17. Build phases and acceptance

**P0 — Pure topology. DONE 2026-10-30.** Spec v2 schema, normalization,
address/name derivation, reachability graph, plan text; 5 tests (backend
135/135). Deployment still refuses sites/zones, so nothing can boot into a
half-realized topology.

**P1 — One site, three zones.** Router VM + nftables, per-zone segments,
positive and negative probes on the clinic. No FreeIPA change.
**Compiler done 2026-10-30:** `router/nftables` catalogued; segment ports,
router `.1` attachments, the deny-first nftables ruleset and executable
negative probes are derived and planned (T-23).
**Runtime done 2026-10-30 (T-24, unit-verified):** one hub per segment,
multi-NIC guests (router included), nftables execution through the
router-configure task, and live allowed/denied zone probes in
`checkSpecReadiness` (backend 141/141, incl. a fake-QEMU lifecycle test that
starts two hubs and tears both down). Deployability accepts single-site VM
orgs with one router per multi-zone site; multi-site stays refused (P5).
Acceptance remaining: a denied flow fails from a real guest and an allowed
flow passes on a live boot (mock-exec unit tests only so far); teardown
removes every segment (unit-verified).

**P2 — FreeIPA live. Done 2026-10-31 (T-26, live on HVF).** The server runs
on Rocky Linux 9 (Debian ships only the FreeIPA client; deployability refuses
a non-Rocky server). `scripts/vm-freeipa-smoke.mjs` boots Rocky `dc-01` +
Debian `ws-01` and proves, in-guest: `kinit admin`, seeded persona in
`ipa user-find`, member join + SSSD `id p1`, peer LDAP bind, DNS SRV via the
DC. `profile-install` is fail-closed (transaction status checked, packages
re-verified) and lab NICs are declared in the NoCloud `network-config` file
(NetworkManager flushed runcmd addresses, stalling Dogtag CA spawn).
Not claimed: replicas. The baked Rocky FreeIPA tier landed in T-38
(aarch64 artifact pinned in `golden/baked-rocky-images.json`); Rocky
osquery is baked and active (T-44).
Kerberoast (O-3) and the persona-password `kinit` path (O-6) were closed later
by T-30; O-3 negatively, because FreeIPA refuses a crackable user-SPN TGS.
Kerberos-authenticated persona shifts landed in T-35.

**P3 — Services. Mail, Postgres and Gitea done live 2026-11-01 (T-31, T-33,
T-34); Samba disproven (T-32, O-4).** Dovecot IMAP authenticates against
389-ds (LDAP-only passdb), Postgres uses pg_hba `ldap` bind-as-user, and Gitea
logs in through an LDAP auth source; each probe is fail-closed with a
wrong-password leg, and each was proven on a real FreeIPA member. File shares
remain open: Samba cannot join (no CLDAP responder) and NFSv4 sec=krb5 proves
the client host, not the user.
Acceptance met for the three realized services: each live smoke proves a
domain-user login, refuses a wrong password, and passes the readiness probe.
A combined five-guest org run is live (T-39); a telemetry-scored exercise
remains open.

**P4 — Population and exercise.** Shift runner, persona routines, Linux-AD
technique pack, red path planner, blue rules, benign control.
**Persona agents live 2026-10-31 (T-25/T-29); Kerberos-authenticated shifts
live 2026-11-01 (T-35):** `personaShift` runs model-driven shifts through a
closed allowlist (no shell, fixed rendered commands, spec-derived targets)
with `modelForRole("persona")` pinning (unverified ids — incl.
`muse-glimmer-*` — fail closed); shifts run before red objectives in
`runVmAgentExercise` with `shiftReport` + `agentStates` in the audit and a
labelled scripted fallback. On a FreeIPA member the runner obtains a
per-persona FILE ccache with a non-interactive `kinit` and proves a GSSAPI
bind before the first action; every rendered command then runs through
`sudo -u <uid>` with that ccache. The baked `muse-shift` binary and
container-path personas remain open.
Acceptance: an objective crosses a zone boundary only through an allowed edge;
proof is seen in telemetry; FP baseline is measured.

**P5 — Multi-site.** Sites/links/WAN routing, cross-site auth and file access,
branch failure modes.
Acceptance: branch→HQ allowed flows pass, branch→branch denied flows fail.

**P6 — Scale.** Capacity derivation, remote KVM provider, cost.
**P7 — OT/IoT.** MQTT/Modbus device runtime, OT zone policy.
**P8 — Network telemetry.** Zeek sensor, flow-based detections.

---

## 18. Decisions

**Locked.**

- D-1 Linux only; FreeIPA is the directory. Windows/AD is out.
- D-2 Static addressing in v1; no DHCP.
- D-3 Keep the existing generated-task executor for v1; the runner is an
  implementation detail behind the task interface.
- D-4 One realm, one DC in v1; replicas later.
- D-5 Structured firewall policy; enforcement on router VMs; default deny.
- D-6 Positive and negative probes are mandatory plan artifacts.
- D-7 Persona and red traffic runs inside the lab hosts; blue reads telemetry
  only.
- D-8 Scored hosts are VMs; containers are dev-only.
- D-9 No internet egress; bake all packages.
- D-10 One derivation for names, addresses, realms and probes.

**Open (must be closed before the phase that needs them).**

- O-1 Atomic CIDR claim + resume semantics (P0/P1).
- O-2 FreeIPA installer forwarder without external DNS (P2).
- O-3 CLOSED 2026-10-31 (T-30): Kerberoast (T1558.003 user-SPN) refused by FreeIPA ("user2user only"); pack excludes it. Spray (T1110.003) is the gated technique.
- O-4 CLOSED 2026-11-01 (T-32): Samba member join is not realizable against FreeIPA — SRV discovery is satisfied but the AD CLDAP NetLogon ping gets no reply (no libipa_cldap, no UDP/389), so `net ads join` fails. `file/samba` removed from the catalog. NFSv4 sec=krb5 authenticates the host, not the user, so it does not meet the domain-user bar either; file shares deferred.
- O-5 Gitea vs cgit; Gitea is assumed (P3).
- O-6 CLOSED 2026-10-31 (T-30): non-interactive kinit proven via pty helper + FILE ccache.
- O-7 Zeek placement (router span vs sensor host) (P8).
- O-8 Multi-site WAN realization: shared hub vs point-to-point (P5).
- O-9 Scale provider (remote KVM vs cloud) (P6).
- O-10 OT protocol choice (MQTT + Modbus first) (P7).

---

## 19. Invariant → gate matrix

These are the properties "no gaps" means. Each has a place it is enforced and
a way to observe it. An invariant with no test is a design bug.

| # | Invariant | Enforced at | Evidence |
|---|---|---|---|
| 1 | Every declared service is catalogued and has a config task + probe | deployability, plan | plan gaps + catalog test |
| 2 | Every service binds its lab address and loopback, never accidental `0.0.0.0` | task templates | config diff + readiness |
| 3 | Addresses, names and realm derive from one function; same spec → same plan | derivation | determinism test |
| 4 | Every allowed cross-zone edge has a positive probe | plan, readiness | probe result |
| 5 | Every denied cross-zone pair has a negative probe that fails | plan, readiness | probe result |
| 6 | Every objective has an allowed path and a proof sink | validateDesign | design rejection |
| 7 | Every persona maps to a real directory user and workstation | seed + coherence | login in readiness |
| 8 | Dependencies are a DAG; configuration is topological | validateDesign, hostOrder | plan order test |
| 9 | No guest reaches the host, platform plane, other runs or the internet | router policy | negative probes + host test |
| 10 | Host ids and addresses are unique and complete | schema, address plan | plan test |
| 11 | A gate cannot pass itself; proof is independent telemetry | gates | blind-sensor test |
| 12 | A telemetry gap makes the window unscorable | collector + canary | gap counters |
| 13 | No deploy without the approved plan digest | trigger | digest rejection test |
| 14 | Teardown removes every VM, segment, overlay and process | teardown + sweeper | orphan sweep |
| 15 | Every claim is live or unit verified, else listed as not claimed | review | tasks/progress |

---

## 20. Non-claims

- Rocky FreeIPA is baked on aarch64 and pinned in
  `golden/baked-rocky-images.json`; an x86_64 artifact is not built on this
  arm64 host. Rocky osquery is baked and active (T-44), but the base config
  has an empty schedule and there is no FreeIPA replica.
- No domain file share. Samba member join cannot work against FreeIPA (no
  CLDAP responder, O-4), and NFSv4 `sec=krb5` authenticates the client host,
  not the user. `file/samba` is not catalogued.
- P3 password authentication remains LDAP bind. T-40 adds additive
  service-keytab/GSSAPI paths for Postgres (database `gssdb`), Dovecot
  (GSSAPI SASL) and Apache (`mod_auth_gssapi` on `/gssapi`); the password
  paths are still probed and green. The Postgres GSS rule is a separate
  database because `pg_hba.conf` is first-match and a catch-all `gss` rule
  would shadow the LDAP rule; PostgreSQL 15 rejects `krb5_realm`, so realm
  restriction is implicit in the service principal in the keytab. Gitea's
  SSH/PR workflows and per-repo directory-group authorization remain
  unproven (T-42); no NFS/Samba `sec=krb5` user path exists.
- Kerberos-authenticated shifts are proven only for the agent path on a
  FreeIPA member; the scripted fallback and container-path personas still run
  locally. A model-driven shift on a member has not been run end-to-end
  (T-35 used a deterministic agent; T-29 proves the model loop on a
  non-member).
- T1558.003 Kerberoast is refused by FreeIPA and excluded from the pack.
  AS-REP roasting, pass-the-ticket, keytab theft and model-executed spray
  scoring are not proven; T-30's spray is scripted.
- No Temporal workflow E2E on a FreeIPA org.
- DHCP is catalogued but blocked at design time (no L2 client network).
  Multi-site/WAN, OT/IoT, Zeek and Windows are not implemented.
