import type { EnvironmentSpec } from "@musearena/shared";
import { digestOfSpec } from "../lib/digest.js";

/**
 * Per-environment DNS namespace (T-17). The lab used to hardcode
 * `arena.lab`, so every environment shared one namespace. The name is
 * derived from the spec itself: a readable slug plus a short content hash,
 * under the platform's `arena.lab` parent. The same spec always yields the
 * same domain (approval/plan digests stay stable); any change to the
 * environment yields a different one, so two labs never share a namespace.
 *
 * DNS names appear in generated config (dnsmasq, postfix), LDAP DNs, mail
 * addresses and readiness commands. They must all read this one function.
 */
export function labDomainFor(spec: EnvironmentSpec): string {
  const slug = spec.name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 24) || "org";
  // Budgets are deployment policy, not environment shape: changing the TTL
  // must not rename the lab. Everything else (hosts, services, topology,
  // personas, weaknesses, objectives) identifies it.
  const identity = {
    version: spec.version, name: spec.name, provider: spec.provider, seed: spec.seed,
    difficulty: spec.difficulty, truthLayer: spec.truthLayer, topology: spec.topology,
    instances: spec.instances, personas: spec.personas, objectives: spec.objectives,
    requiredTelemetry: spec.requiredTelemetry, plantedVulns: spec.plantedVulns,
  };
  const hash = digestOfSpec(identity).replace(/^sha256:/, "").slice(0, 8);
  return `${slug}-${hash}.arena.lab`;
}

/** `clinic-88e5a2d0.arena.lab` → `dc=clinic-88e5a2d0,dc=arena,dc=lab`. */
export function ldapBaseFor(domain: string): string {
  return domain.split(".").map((label) => `dc=${label}`).join(",");
}

/**
 * FreeIPA lives in a subdomain of the environment's namespace, so the realm
 * is unique per environment and never collides with the gateway's zone.
 * `clinic-88e5a2d0.arena.lab` → `ipa.clinic-88e5a2d0.arena.lab`.
 */
export function ipaDomainFor(spec: EnvironmentSpec): string {
  return `ipa.${labDomainFor(spec)}`;
}

/** Realm is the upper-cased DNS domain, as FreeIPA requires. */
export function ipaRealmFor(spec: EnvironmentSpec): string {
  return ipaDomainFor(spec).toUpperCase();
}

/** Base DN of the FreeIPA domain, derived from the lab domain. */
export function ipaBaseFor(labDomain: string): string {
  return ldapBaseFor(`ipa.${labDomain}`);
}

/** FreeIPA's admin user lives under cn=users,cn=accounts (not cn=admin). */
export function ipaAdminDnFor(labDomain: string): string {
  return `uid=admin,cn=users,cn=accounts,${ipaBaseFor(labDomain)}`;
}
