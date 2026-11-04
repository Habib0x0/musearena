import { EnvironmentSpec, type EnvironmentSpec as SpecT } from "@musearena/shared";
import { validateDesign } from "../designer/pipeline.js";
import { digestOfSpec } from "../lib/digest.js";
import { serviceClient } from "../lib/supabase.js";

/** Template library (follow-on): versioned, family-grouped EnvironmentSpecs. */
export interface Template {
  id: string;
  version: number;
  family: string;
  spec: SpecT;
  digest: string;
  semver?: string;
  changelog?: string;
  rowId?: string;
  orgId?: string;
  shared?: boolean;
  shareToken?: string | null;
  createdAt?: string;
}

/** The persisted `templates` row shape (migration 0002). */
export interface TemplateRow {
  id: string;
  org_id: string;
  name: string;
  family: string;
  version: number;
  spec: unknown;
  digest: string;
  shared: boolean;
  share_token: string | null;
  created_at: string;
}

export type TemplateInsert = Omit<TemplateRow, "id" | "created_at" | "shared" | "share_token"> & {
  shared?: boolean;
  share_token?: string | null;
};

export interface TemplateStore {
  list(orgId: string): Promise<TemplateRow[]>;
  insert(row: TemplateInsert): Promise<TemplateRow>;
}

const templateKey = (id: string, version: number) => `${id}@${version}`;
const byIdThenVersion = (a: Template, b: Template) => a.id.localeCompare(b.id) || a.version - b.version;

function isUniqueConflict(err: unknown): boolean {
  const e = err as { code?: unknown; message?: unknown };
  return e?.code === "23505" || /duplicate key|unique constraint/i.test(String(e?.message ?? err));
}

/**
 * Map a persisted row into the registry shape, failing closed on a row whose
 * spec does not parse or whose pinned digest no longer matches its bytes.
 */
export function templateFromRow(row: TemplateRow): Template {
  if (!row.name) throw new Error(`template row ${row.id} has no name`);
  if (!row.family) throw new Error(`template ${row.name} has no family`);
  if (!Number.isInteger(row.version) || row.version < 1) {
    throw new Error(`template ${row.name} has invalid version ${row.version}`);
  }
  const spec = EnvironmentSpec.parse(row.spec);
  const digest = digestOfSpec(spec);
  if (digest !== row.digest) {
    throw new Error(`template ${row.name}@${row.version} digest mismatch: stored ${row.digest}, computed ${digest}`);
  }
  return {
    id: row.name,
    version: row.version,
    family: row.family,
    spec,
    digest,
    rowId: row.id,
    orgId: row.org_id,
    shared: row.shared,
    shareToken: row.share_token,
    createdAt: row.created_at,
  };
}

export function templateToRow(orgId: string, template: Template): TemplateInsert {
  const spec = EnvironmentSpec.parse(template.spec);
  const digest = digestOfSpec(spec);
  if (digest !== template.digest) {
    throw new Error(`template ${template.id}@${template.version} digest mismatch: supplied ${template.digest}, computed ${digest}`);
  }
  return {
    org_id: orgId,
    name: template.id,
    family: template.family,
    version: template.version,
    spec,
    digest,
    shared: template.shared ?? false,
    share_token: template.shareToken ?? null,
  };
}

export class TemplateRegistry {
  private items = new Map<string, Template>();
  private loadedOrgId: string | null = null;

  register(id: string, family: string, specInput: SpecT): Template {
    const spec = EnvironmentSpec.parse(specInput);
    const version = Math.max(0, ...[...this.items.values()].filter((t) => t.id === id).map((t) => t.version)) + 1;
    const digest = digestOfSpec(spec);
    const tpl: Template = { id, version, family, spec, digest };
    this.items.set(templateKey(id, version), tpl);
    return tpl;
  }

  get(id: string, version?: number): Template | undefined {
    if (version) return this.items.get(templateKey(id, version));
    return [...this.items.values()]
      .filter((t) => t.id === id)
      .sort((a, b) => b.version - a.version)[0];
  }

  byFamily(family: string): Template[] {
    return [...this.items.values()].filter((t) => t.family === family).sort(byIdThenVersion);
  }

  list(): Template[] { return [...this.items.values()].sort(byIdThenVersion); }

  /** Load one org's persisted templates, replacing this registry's contents. */
  async load(orgId: string, store: TemplateStore = supabaseTemplateStore()): Promise<this> {
    const rows = await store.list(orgId);
    const templates = rows.map(templateFromRow);
    const next = new Map<string, Template>();
    for (const tpl of templates) {
      if (tpl.orgId !== orgId) throw new Error(`template store returned ${tpl.id} for a different org (${tpl.orgId})`);
      const key = templateKey(tpl.id, tpl.version);
      if (next.has(key)) throw new Error(`duplicate template version ${key} for org ${orgId}`);
      next.set(key, tpl);
    }
    this.items = next;
    this.loadedOrgId = orgId;
    return this;
  }

  static async load(orgId: string, store: TemplateStore = supabaseTemplateStore()): Promise<TemplateRegistry> {
    return new TemplateRegistry().load(orgId, store);
  }

  /**
   * Persist a new version. The next version is max(persisted, local)+1 — not
   * a row count — and a unique-version race reloads and retries so two
   * writers cannot silently claim the same version.
   */
  async registerPersistent(
    orgId: string,
    id: string,
    family: string,
    specInput: SpecT,
    store: TemplateStore = supabaseTemplateStore(),
  ): Promise<Template> {
    if (this.loadedOrgId && this.loadedOrgId !== orgId) {
      throw new Error(`template registry is loaded for a different org (${this.loadedOrgId})`);
    }
    const spec = EnvironmentSpec.parse(specInput);
    const digest = digestOfSpec(spec);
    let lastError: unknown;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const persisted = (await store.list(orgId)).map(templateFromRow);
      for (const tpl of persisted) {
        if (tpl.orgId !== orgId) throw new Error(`template store returned ${tpl.id} for a different org (${tpl.orgId})`);
      }
      const version = Math.max(
        0,
        ...persisted.filter((t) => t.id === id).map((t) => t.version),
        ...[...this.items.values()].filter((t) => t.id === id).map((t) => t.version),
      ) + 1;
      try {
        const saved = templateFromRow(await store.insert({
          org_id: orgId, name: id, family, version, spec, digest, shared: false, share_token: null,
        }));
        for (const tpl of persisted) this.items.set(templateKey(tpl.id, tpl.version), tpl);
        this.items.set(templateKey(saved.id, saved.version), saved);
        this.loadedOrgId = orgId;
        return saved;
      } catch (err) {
        lastError = err;
        if (!isUniqueConflict(err) || attempt === 2) throw err;
      }
    }
    throw lastError;
  }

  /** AnomalyLab-pattern versioning: validated, semver-bumped, diff-summarized. */
  createVersion(id: string, spec: SpecT, bump: "major" | "minor" | "patch", changelog: string): Template & { changes: { added: string[]; removed: string[] } } {
    const errors = validateDesign(spec);
    if (errors.length) throw new Error(`template validation failed: ${errors.join("; ")}`);
    EnvironmentSpec.parse(spec);
    const prev = this.get(id);
    const [maj, min, pat] = (prev?.semver ?? "0.0.0").split(".").map(Number);
    const semver = bump === "major" ? `${maj + 1}.0.0` : bump === "minor" ? `${maj}.${min + 1}.0` : `${maj}.${min}.${pat + 1}`;
    const prevHosts = new Set(prev?.spec.instances.map((i) => i.hostId) ?? []);
    const nextHosts = new Set(spec.instances.map((i) => i.hostId));
    const tpl = this.register(id, prev?.family ?? "general", spec);
    tpl.semver = semver; tpl.changelog = changelog;
    return { ...tpl, changes: { added: [...nextHosts].filter((h) => !prevHosts.has(h)), removed: [...prevHosts].filter((h) => !nextHosts.has(h)) } };
  }
}

/** Service-role Supabase store. Every query is explicitly org-scoped. */
export function supabaseTemplateStore(): TemplateStore {
  const sb = () => serviceClient();
  return {
    async list(orgId) {
      const { data, error } = await sb().from("templates")
        .select("*")
        .eq("org_id", orgId)
        .order("name", { ascending: true })
        .order("version", { ascending: true });
      if (error) throw new Error(`templates unreadable: ${error.message}`);
      return (data ?? []) as TemplateRow[];
    },
    async insert(row) {
      const { data, error } = await sb().from("templates").insert(row).select("*").single();
      if (error) {
        throw Object.assign(new Error(`template insert failed: ${error.message}`), { code: error.code });
      }
      return data as TemplateRow;
    },
  };
}
