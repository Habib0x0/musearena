// Collision-safe CIDR allocation from the 10.0.0.0/8 pool.
// Each environment owns one /16 (second octet); subnets carve /20s inside it.
// Pure functions — callers persist the claim (deployment record / stack tags).

export interface CidrClaim { envCidr: string; octet: number }

const pool = (used: number[]): number => {
  const taken = new Set(used);
  for (let o = 2; o <= 254; o++) if (!taken.has(o)) return o; // 0,1 reserved; 255 broadcast-adjacent
  throw new Error("CIDR pool exhausted");
};

export function allocateCidr(usedOctets: number[]): CidrClaim {
  const octet = pool(usedOctets);
  return { envCidr: `10.${octet}.0.0/16`, octet };
}

export function subnetsFor(octet: number): { name: string; cidr: string; zone: string }[] {
  return [
    { name: "public-a", cidr: `10.${octet}.0.0/20`, zone: "a" },
    { name: "public-b", cidr: `10.${octet}.16.0/20`, zone: "b" },
    { name: "private-a", cidr: `10.${octet}.32.0/20`, zone: "a" },
    { name: "private-b", cidr: `10.${octet}.48.0/20`, zone: "b" },
  ];
}

/**
 * Keep the designed topology shape, move it into this run's allocated /16.
 * Container networks collide on the host, so a design's 10.2.32.0/20 cannot be
 * used verbatim by two runs; the third/fourth octets and prefix survive, only
 * the run's second octet changes. VM users never need this: their segment is
 * a per-run user-space hub, so they use the spec's addresses as written.
 */
export function remapSubnets<T extends { cidr: string }>(subnets: T[], octet: number): T[] {
  return subnets.map((s) => {
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(s.cidr.trim());
    if (!m || Number(m[1]) !== 10) return s;
    return { ...s, cidr: `10.${octet}.${m[3]}.${m[4]}/${m[5]}` };
  });
}
