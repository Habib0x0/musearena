/**
 * Field-tradecraft reference (no vendor is named).
 *
 * The red agent is prompted to operate like a real operator: a phased kill
 * chain, real tooling, and observable command forms. This module is the
 * deterministic side of that — it classifies an action against a corpus of
 * commonly deployed offensive tools so a dataset can report how much of its
 * red activity looks like real field work rather than arbitrary commands.
 */
export const TRADECRAFT_PHASES = ["recon", "enumeration", "access", "execution", "collection", "exfiltration"] as const;
export type TradecraftPhase = (typeof TRADECRAFT_PHASES)[number];

interface ToolClass { phase: TradecraftPhase; techniques: string[] }

/** Common field tooling by phase. Presence in this map means "recognisably real". */
export const FIELD_TOOLS: Record<string, ToolClass> = {
  // Reconnaissance and target validation.
  nmap: { phase: "recon", techniques: ["T1046"] },
  masscan: { phase: "recon", techniques: ["T1046"] },
  ping: { phase: "recon", techniques: ["T1018"] },
  dig: { phase: "recon", techniques: ["T1590"] },
  nslookup: { phase: "recon", techniques: ["T1590"] },
  host: { phase: "recon", techniques: ["T1590"] },
  whois: { phase: "recon", techniques: ["T1590"] },
  curl: { phase: "recon", techniques: ["T1595"] },
  wget: { phase: "recon", techniques: ["T1105"] },
  whoami: { phase: "recon", techniques: ["T1033"] },
  id: { phase: "recon", techniques: ["T1033"] },
  uname: { phase: "recon", techniques: ["T1082"] },
  // Service enumeration.
  whatweb: { phase: "enumeration", techniques: ["T1592"] },
  httpx: { phase: "enumeration", techniques: ["T1595"] },
  ffuf: { phase: "enumeration", techniques: ["T1595"] },
  gobuster: { phase: "enumeration", techniques: ["T1595"] },
  feroxbuster: { phase: "enumeration", techniques: ["T1595"] },
  nikto: { phase: "enumeration", techniques: ["T1595"] },
  nuclei: { phase: "enumeration", techniques: ["T1595"] },
  sqlmap: { phase: "enumeration", techniques: ["T1190"] },
  smbclient: { phase: "enumeration", techniques: ["T1135"] },
  rpcclient: { phase: "enumeration", techniques: ["T1135"] },
  enum4linux: { phase: "enumeration", techniques: ["T1087"] },
  ldapsearch: { phase: "enumeration", techniques: ["T1087"] },
  snmpwalk: { phase: "enumeration", techniques: ["T1046"] },
  // Access and execution.
  ssh: { phase: "access", techniques: ["T1021.004"] },
  scp: { phase: "access", techniques: ["T1021.004"] },
  sftp: { phase: "access", techniques: ["T1021.004"] },
  psql: { phase: "collection", techniques: ["T1005"] },
  mysql: { phase: "collection", techniques: ["T1005"] },
  "redis-cli": { phase: "collection", techniques: ["T1005"] },
  mongo: { phase: "collection", techniques: ["T1005"] },
  mongosh: { phase: "collection", techniques: ["T1005"] },
  hydra: { phase: "access", techniques: ["T1110"] },
  john: { phase: "access", techniques: ["T1110"] },
  hashcat: { phase: "access", techniques: ["T1110"] },
  socat: { phase: "execution", techniques: ["T1059"] },
  chisel: { phase: "execution", techniques: ["T1090"] },
  nc: { phase: "execution", techniques: ["T1090"] },
  netcat: { phase: "execution", techniques: ["T1090"] },
  python3: { phase: "execution", techniques: ["T1059.006"] },
  bash: { phase: "execution", techniques: ["T1059.004"] },
  sh: { phase: "execution", techniques: ["T1059.004"] },
  tar: { phase: "exfiltration", techniques: ["T1560"] },
  gzip: { phase: "exfiltration", techniques: ["T1560"] },
  base64: { phase: "exfiltration", techniques: ["T1132"] },
  // Data access on the target.
  cat: { phase: "collection", techniques: ["T1005"] },
  grep: { phase: "collection", techniques: ["T1005"] },
  awk: { phase: "collection", techniques: ["T1005"] },
  find: { phase: "collection", techniques: ["T1083"] },
  ls: { phase: "recon", techniques: ["T1083"] },
  pg_dump: { phase: "collection", techniques: ["T1005"] },
  pg_dumpall: { phase: "collection", techniques: ["T1005"] },
  mysqldump: { phase: "collection", techniques: ["T1005"] },
};

const SHELLS = new Set(["sh", "bash", "zsh", "dash"]);

function base(token: string): string {
  return (token.split("/").at(-1) ?? token).toLowerCase();
}

function firstWord(command: string): string {
  return command.trim().split(/\s+/)[0] ?? "";
}

/**
 * The program a trace action ran. `action` is the platform's program field;
 * `toolCall` is the full command and is used only when `action` is absent.
 * A shell wrapper is unwrapped so `sh -c "curl ..."` classifies as curl.
 */
export function programOf(action: string | null | undefined, toolCall: string | null | undefined): string {
  const direct = action ? base(action) : "";
  if (direct && !SHELLS.has(direct)) return direct;
  if (!toolCall) return direct;
  const tokens = toolCall.match(/"([^"\\]|\\.)*"|'[^']*'|[^\s]+/g)?.map((t) => t.replace(/^['"]|['"]$/g, "")) ?? [];
  if (!tokens.length) return direct;
  if (SHELLS.has(base(tokens[0])) && tokens[1] === "-c" && tokens[2]) return base(firstWord(tokens[2]));
  return base(tokens[0]);
}

export interface TradecraftClass {
  tool: string;
  phase: TradecraftPhase | null;
  known: boolean;
  techniques: string[];
}

export function classifyAction(action: string | null | undefined, toolCall: string | null | undefined): TradecraftClass {
  const tool = programOf(action, toolCall);
  const cls = FIELD_TOOLS[tool];
  return { tool, phase: cls?.phase ?? null, known: Boolean(cls), techniques: cls?.techniques ?? [] };
}

export interface RealismReport { actions: number; knownToolActions: number; share: number }

/** Share of actions that use recognisably real field tooling. */
export function realismShare(rows: { action: string | null; tool_call: string | null }[]): RealismReport {
  const known = rows.filter((row) => classifyAction(row.action, row.tool_call).known).length;
  return { actions: rows.length, knownToolActions: known, share: rows.length ? known / rows.length : 0 };
}
