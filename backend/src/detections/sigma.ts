import { load as loadYaml } from "js-yaml";
import { createHash } from "node:crypto";
import type { GroundTruthEvent } from "../observability/events.js";

/** Sigma lifecycle (Req §10, T-12): author → version → offline replay → promote → live. */
export interface SigmaRule {
  id: string;
  version: number;
  title: string;
  techniqueId: string;
  /** Legacy single-field matcher (kept for hand-built rules). */
  field?: "kind" | "signal";
  contains?: string;
  /** SigmaHQ detection block (from YAML): named selections + condition. */
  detection?: Record<string, unknown>;
  /** Sigma level → alert confidence (§10.3). */
  level?: "informational" | "low" | "medium" | "high" | "critical";
  status: "draft" | "promoted";
}

const LEVEL_CONFIDENCE: Record<string, number> = { informational: 0.2, low: 0.4, medium: 0.6, high: 0.8, critical: 0.95 };

export interface Alert {
  runId: string; hostId: string; techniqueId: string;
  ruleId: string; ruleVersion: number; at: string; confidence: number;
}

/** Event field lookup: top-level fields first, then detail.* (normalized telemetry). */
function fieldValue(e: GroundTruthEvent, name: string): unknown {
  if (name in e) return (e as unknown as Record<string, unknown>)[name];
  return e.detail?.[name];
}

type Matcher = (e: GroundTruthEvent) => boolean;

function valueMatch(actual: unknown, expected: unknown, mod: string | undefined): boolean {
  if (actual === undefined || actual === null) return expected === null;
  const a = String(actual).toLowerCase();
  const x = String(expected).toLowerCase();
  switch (mod) {
    case undefined: return a === x;
    case "contains": return a.includes(x);
    case "startswith": return a.startsWith(x);
    case "endswith": return a.endsWith(x);
    default: throw new Error(`unsupported Sigma modifier |${mod}`);
  }
}

/** One selection: map → AND of fields (list values OR'd, |all → AND'd); list of maps → OR. */
function compileSelection(sel: unknown): Matcher {
  if (Array.isArray(sel)) {
    const subs = sel.map(compileSelection);
    return (e) => subs.some((m) => m(e));
  }
  if (!sel || typeof sel !== "object") throw new Error("Sigma selection must be a map or list of maps");
  const checks = Object.entries(sel as Record<string, unknown>).map(([key, val]) => {
    const [field, ...mods] = key.split("|");
    const all = mods.includes("all");
    const mod = mods.find((m) => m !== "all");
    if (mods.filter((m) => m !== "all").length > 1 || (mod && !["contains", "startswith", "endswith"].includes(mod))) {
      throw new Error(`unsupported Sigma modifier |${mods.join("|")} on ${field}`);
    }
    const vals = Array.isArray(val) ? val : [val];
    return (e: GroundTruthEvent) => {
      const actual = fieldValue(e, field);
      return all ? vals.every((v) => valueMatch(actual, v, mod)) : vals.some((v) => valueMatch(actual, v, mod));
    };
  });
  return (e) => checks.every((c) => c(e));
}

/** Condition grammar: and / or / not / parentheses / "1 of x*" / "all of x*" / "1 of them". */
function compileCondition(cond: string, sels: Record<string, Matcher>): Matcher {
  const tokens = cond.match(/\(|\)|[^\s()]+/g) ?? [];
  let i = 0;
  const peek = () => tokens[i];
  const names = (pat: string) => {
    const keys = Object.keys(sels).filter((k) => pat === "them" || (pat.endsWith("*") ? k.startsWith(pat.slice(0, -1)) : k === pat));
    if (!keys.length) throw new Error(`Sigma condition references no selection: ${pat}`);
    return keys.map((k) => sels[k]);
  };
  const primary = (): Matcher => {
    const t = tokens[i++];
    if (t === "(") { const m = or(); if (tokens[i++] !== ")") throw new Error("unbalanced parentheses"); return m; }
    if (t === "not") { const m = primary(); return (e) => !m(e); }
    if (t === "1" || t === "all") {
      if (tokens[i++] !== "of") throw new Error(`expected "of" after ${t}`);
      const ms = names(tokens[i++]);
      return t === "1" ? (e) => ms.some((m) => m(e)) : (e) => ms.every((m) => m(e));
    }
    if (!t || !(t in sels)) throw new Error(`unknown selection in condition: ${t}`);
    return sels[t];
  };
  const and = (): Matcher => { let l = primary(); while (peek() === "and") { i++; const r = primary(); const a = l; l = (e) => a(e) && r(e); } return l; };
  const or = (): Matcher => { let l = and(); while (peek() === "or") { i++; const r = and(); const a = l; l = (e) => a(e) || r(e); } return l; };
  const m = or();
  if (i !== tokens.length) throw new Error(`trailing tokens in condition: ${tokens.slice(i).join(" ")}`);
  return m;
}

/** Compiles a rule to a matcher over the normalized event store (pySigma-equivalent backend for the supported subset). */
export function compileRule(rule: SigmaRule): Matcher {
  if (rule.detection) {
    const { condition, ...rest } = rule.detection as { condition?: unknown } & Record<string, unknown>;
    if (typeof condition !== "string") throw new Error(`rule ${rule.id}: detection.condition must be a single string`);
    const sels = Object.fromEntries(Object.entries(rest).map(([k, v]) => [k, compileSelection(v)]));
    return compileCondition(condition, sels);
  }
  if (!rule.field || rule.contains === undefined) throw new Error(`rule ${rule.id} has neither detection nor field/contains`);
  return (e) => {
    const hay = rule.field === "kind" ? e.kind : String(e.detail?.signal ?? "");
    return hay.toLowerCase().includes(rule.contains!.toLowerCase());
  };
}

/**
 * Parse a SigmaHQ YAML rule. Version is derived from the rule body hash so an
 * edited rule is a NEW version (immutability, §10.2) without manual bumps.
 * Technique = first attack.tNNNN tag.
 */
export function parseSigmaYaml(text: string): SigmaRule {
  const doc = loadYaml(text) as Record<string, unknown>;
  if (!doc || typeof doc !== "object") throw new Error("not a Sigma rule");
  const id = String(doc.id ?? "");
  if (!id) throw new Error("Sigma rule needs an id");
  const tags = (doc.tags as string[] | undefined) ?? [];
  const tech = tags.map((t) => /^attack\.(t\d{4}(?:\.\d{3})?)$/i.exec(t)?.[1]).find(Boolean);
  if (!tech) throw new Error(`rule ${id}: needs an attack.tNNNN tag`);
  const detection = doc.detection as Record<string, unknown> | undefined;
  if (!detection) throw new Error(`rule ${id}: no detection block`);
  const rule: SigmaRule = {
    id, title: String(doc.title ?? id), techniqueId: tech.toUpperCase(), detection, status: "draft",
    level: (["informational", "low", "medium", "high", "critical"].includes(String(doc.level)) ? doc.level : "medium") as SigmaRule["level"],
    version: parseInt(createHash("sha256").update(JSON.stringify(detection)).digest("hex").slice(0, 8), 16),
  };
  compileRule(rule); // fail at load, not at replay
  return rule;
}

/** Offline replay over stored telemetry — how a rule earns promotion. */
export function replay(rule: SigmaRule, events: GroundTruthEvent[]): Alert[] {
  const match = compileRule(rule);
  return events.filter(match).map((e) => ({
    runId: e.runId, hostId: e.hostId, techniqueId: rule.techniqueId,
    ruleId: rule.id, ruleVersion: rule.version, at: e.at, confidence: LEVEL_CONFIDENCE[rule.level ?? "medium"],
  }));
}

export interface PromotionEvidence { ruleId: string; ruleVersion: number; replayAlerts: number; replayedAt: string }

export class DetectionStore {
  private rules = new Map<string, SigmaRule>();
  private evidence = new Map<string, PromotionEvidence>();

  add(rule: SigmaRule): SigmaRule {
    const key = `${rule.id}@${rule.version}`;
    const existing = this.rules.get(key);
    const body = (r: SigmaRule) => JSON.stringify([r.title, r.techniqueId, r.field, r.contains, r.detection]);
    if (existing && body(existing) !== body(rule)) {
      throw new Error(`rule ${key} already exists with different content — versions are immutable; bump the version`);
    }
    const stored: SigmaRule = existing ?? { ...rule, status: "draft" };
    this.rules.set(key, stored);
    return stored;
  }
  get(id: string, version: number): SigmaRule | undefined { return this.rules.get(`${id}@${version}`); }
  promotionEvidence(id: string, version: number): PromotionEvidence | undefined { return this.evidence.get(`${id}@${version}`); }

  /**
   * Promotion gate (§10.2): a rule earns "promoted" only by replaying stored
   * telemetry and producing at least one alert for its own technique.
   * No replay evidence → no promotion → the rule can never score a live run.
   */
  promote(id: string, version: number, replayEvents: GroundTruthEvent[]): SigmaRule {
    const r = this.get(id, version);
    if (!r) throw new Error(`unknown rule ${id}@${version}`);
    const alerts = replay(r, replayEvents).filter((a) => a.runId && a.at &&
      replayEvents.some((event) => event.runId === a.runId && event.hostId === a.hostId && event.at === a.at &&
        (!event.techniqueId || event.techniqueId === r.techniqueId)));
    if (alerts.length === 0) throw new Error(`rule ${id}@${version} produced no alerts in offline replay for technique ${r.techniqueId} — promotion refused`);
    r.status = "promoted";
    this.evidence.set(`${id}@${version}`, { ruleId: id, ruleVersion: version, replayAlerts: alerts.length, replayedAt: new Date().toISOString() });
    return r;
  }

  /** Only promoted rules may score live runs (§10.2). Alerts carry the firing rule's id+version (§10.3). */
  liveAlerts(events: GroundTruthEvent[]): Alert[] {
    return [...this.rules.values()].filter((r) => r.status === "promoted").flatMap((r) => replay(r, events));
  }
}

/** Load every *.yml rule in a directory (the versioned detection pack). */
export async function loadSigmaDir(dir: string): Promise<SigmaRule[]> {
  const { readdir, readFile } = await import("node:fs/promises");
  const path = await import("node:path");
  const files = (await readdir(dir)).filter((f) => /\.ya?ml$/.test(f)).sort();
  return Promise.all(files.map(async (f) => parseSigmaYaml(await readFile(path.join(dir, f), "utf8"))));
}
