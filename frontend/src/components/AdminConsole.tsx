import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@clerk/clerk-react";
import { CheckCircle2, Download, Octagon, ShieldCheck, XCircle } from "lucide-react";
import { Badge, EmptyState, ErrorState, LoadingState, PageHeader, Panel, PanelHeader, StatCard } from "./ui";
import { formatDate, shortId, statusTone } from "../lib/format";
import { clerkEnabled } from "../auth/clerk-config";
import { learningApiUrl, learningFetch } from "../lib/learning-api";

/**
 * Admin console: audit log, fleet control, limits, usage, members and
 * integrations. Every view reads the admin API; changes go through audited
 * operator routes. A missing permission or configuration shows the server's
 * reason, never placeholder data.
 */

type Section = "audit" | "fleet" | "limits" | "usage" | "members" | "integrations";
const SECTIONS: { id: Section; label: string }[] = [
  { id: "fleet", label: "Fleet" },
  { id: "usage", label: "Usage & cost" },
  { id: "limits", label: "Budgets & quotas" },
  { id: "audit", label: "Audit log" },
  { id: "members", label: "Members" },
  { id: "integrations", label: "Integrations" },
];

function useApi() {
  const { getToken } = useAuth();
  return <T,>(path: string, init?: RequestInit) => learningFetch<T>(() => getToken(), path, init);
}

const Btn = ({ children, onClick, tone = "dim", disabled }: { children: ReactNode; onClick: () => void; tone?: "dim" | "danger" | "signal"; disabled?: boolean }) => (
  <button
    type="button"
    disabled={disabled}
    onClick={onClick}
    className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition disabled:opacity-50 ${
      tone === "danger" ? "border-dangerline bg-dangersurface text-dangertext hover:bg-dangersurface"
        : tone === "signal" ? "border-line bg-signal text-signalcontrast hover:opacity-90"
          : "border-line bg-panel2 text-paper hover:bg-panel"}`}
  >
    {children}
  </button>
);

const Mono = ({ children }: { children: ReactNode }) => <span className="font-mono text-[11px] text-muted">{children}</span>;

// ---- Fleet ----

interface Lab { id: string; status: string; createdAt: string; name: string; vms: number; dollarsPerHour: number | null; expiresAt: string | null; ageMinutes: number; worker: string | null }
interface Ended { id: string; status: string; createdAt: string; name: string; failure: { stage?: string; error?: string } | null }

function Fleet() {
  const api = useApi();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["admin", "fleet"], queryFn: () => api<{ labs: Lab[]; recent: Ended[] }>("/admin/fleet"), refetchInterval: 10_000 });
  const stop = useMutation({
    mutationFn: (id: string) => api<{ how: string }>(`/admin/fleet/${id}/stop`, { method: "POST", body: "{}" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin", "fleet"] }),
  });
  if (q.isLoading) return <LoadingState what="fleet" />;
  if (q.error) return <ErrorState title="Fleet unavailable" error={q.error} />;
  const { labs, recent } = q.data!;
  const burn = labs.reduce((s, l) => s + (l.dollarsPerHour ?? 0), 0);
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard label="Live labs" value={String(labs.length)} detail="pending, provisioning, running or tearing down" tone={labs.length ? "cyber" : "dim"} />
        <StatCard label="VMs running" value={String(labs.reduce((s, l) => s + l.vms, 0))} detail="across all live labs" />
        <StatCard label="Estimated burn" value={`$${burn.toFixed(2)}/hr`} detail="from the platform cost table" tone={burn ? "gold" : "dim"} />
      </div>
      {stop.error && <ErrorState title="Stop failed" error={stop.error} />}
      <Panel>
        <PanelHeader title="Live labs" description="Stop sends the lab through its own teardown path (the same one as TTL expiry). Every stop is audited." />
        {labs.length === 0 ? <div className="p-4"><EmptyState title="No live labs">Nothing is provisioned or running for this organization.</EmptyState></div> : (
          <ul className="divide-y divide-line">
            {labs.map((l) => (
              <li key={l.id} className="flex flex-wrap items-center gap-3 px-5 py-3">
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-paper">{l.name} <Mono>{shortId(l.id)}</Mono></p>
                  <p className="text-xs text-muted">{l.vms} VMs · {l.dollarsPerHour !== null ? `$${l.dollarsPerHour}/hr` : "—"} · up {l.ageMinutes} min{l.expiresAt ? ` · TTL ends ${formatDate(l.expiresAt)}` : ""}{l.worker ? ` · worker ${l.worker}` : ""}</p>
                </div>
                <Badge tone={statusTone(l.status)}>{l.status}</Badge>
                <Btn tone="danger" disabled={stop.isPending || l.status === "destroying"}
                  onClick={() => { if (window.confirm(`Stop and destroy "${l.name}" (${shortId(l.id)})? Running exercises end now.`)) stop.mutate(l.id); }}>
                  <Octagon size={13} /> Stop
                </Btn>
              </li>
            ))}
          </ul>
        )}
      </Panel>
      <Panel>
        <PanelHeader title="Recently ended" />
        <ul className="divide-y divide-line">
          {recent.map((r) => (
            <li key={r.id} className="flex flex-wrap items-center gap-3 px-5 py-2.5">
              <p className="min-w-0 flex-1 text-xs text-paper">{r.name} <Mono>{shortId(r.id)}</Mono> <span className="text-muted">· {formatDate(r.createdAt)}</span>
                {r.failure?.error && <span className="block truncate text-dangertext">{r.failure.stage}: {r.failure.error}</span>}</p>
              <Badge tone={statusTone(r.status)}>{r.status}</Badge>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}

// ---- Usage ----

interface Usage {
  period: { labs: number; vmHours: number; estimatedUsd: number };
  monthToDate: { labs: number; vmHours: number; estimatedUsd: number };
  monthlyBudgetUsd: number | null;
  daily: { day: string; vmHours: number; estimatedUsd: number; labs: number }[];
  tokensByModel: Record<string, { input: number; output: number; runs: number }>;
  note: string;
}

const fmt = (n: number) => n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : String(n);

function UsageView() {
  const api = useApi();
  const [days, setDays] = useState(30);
  const q = useQuery({ queryKey: ["admin", "usage", days], queryFn: () => api<Usage>(`/admin/usage?days=${days}`) });
  if (q.isLoading) return <LoadingState what="usage" />;
  if (q.error) return <ErrorState title="Usage unavailable" error={q.error} />;
  const u = q.data!;
  const max = Math.max(1, ...u.daily.map((d) => d.estimatedUsd));
  const budget = u.monthlyBudgetUsd;
  return (
    <div className="space-y-4">
      <div className="flex gap-2">{[7, 30, 90].map((d) => <Btn key={d} tone={d === days ? "signal" : "dim"} onClick={() => setDays(d)}>{d} days</Btn>)}</div>
      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard label="Month to date" value={`$${u.monthToDate.estimatedUsd.toFixed(2)}`} detail={budget !== null ? `of $${budget} monthly budget` : "no monthly budget set"}
          tone={budget !== null && u.monthToDate.estimatedUsd > budget * 0.8 ? "danger" : "mint"} progress={budget ? (u.monthToDate.estimatedUsd / budget) * 100 : undefined} />
        <StatCard label={`VM hours · ${days}d`} value={u.period.vmHours.toFixed(1)} detail={`${u.period.labs} labs`} />
        <StatCard label={`Estimated spend · ${days}d`} value={`$${u.period.estimatedUsd.toFixed(2)}`} detail="estimate, not an invoice" />
      </div>
      <Panel>
        <PanelHeader title="Daily estimated spend" description={u.note} />
        <div className="flex h-36 items-end gap-[2px] px-5 py-4" role="img" aria-label="Daily estimated spend">
          {u.daily.map((d) => (
            <div key={d.day} title={`${d.day}: $${d.estimatedUsd} · ${d.vmHours} VM-h · ${d.labs} labs`}
              className="min-w-[3px] flex-1 rounded-t bg-signal/70 hover:bg-signal" style={{ height: `${Math.max(2, (d.estimatedUsd / max) * 100)}%` }} />
          ))}
        </div>
      </Panel>
      <Panel>
        <PanelHeader title="Model tokens by model" description="Summed from agent runs in this period." />
        {Object.keys(u.tokensByModel).length === 0 ? <div className="p-4"><EmptyState title="No agent runs in this period" /></div> : (
          <ul className="divide-y divide-line">
            {Object.entries(u.tokensByModel).sort((a, b) => b[1].input - a[1].input).map(([model, t]) => (
              <li key={model} className="flex flex-wrap items-center gap-3 px-5 py-2.5 text-xs">
                <span className="min-w-0 flex-1 font-mono text-paper">{model}</span>
                <span className="text-muted">{fmt(t.input)} in · {fmt(t.output)} out · {t.runs} runs</span>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

// ---- Limits ----

interface Limits { max_concurrent_labs: number | null; max_vms_per_lab: number | null; max_dollars_per_hour: number | null; monthly_budget_usd: number | null; max_ttl_hours: number | null; paused: boolean }
const LIMIT_FIELDS: { key: Exclude<keyof Limits, "paused">; label: string; hint: string; step: string }[] = [
  { key: "max_concurrent_labs", label: "Concurrent labs", hint: "labs running at the same time", step: "1" },
  { key: "max_vms_per_lab", label: "VMs per lab", hint: "largest lab that may start", step: "1" },
  { key: "max_dollars_per_hour", label: "$ per hour per lab", hint: "estimated cost of one lab", step: "0.01" },
  { key: "monthly_budget_usd", label: "Monthly budget ($)", hint: "estimated spend this calendar month", step: "1" },
  { key: "max_ttl_hours", label: "Max TTL (hours)", hint: "longest a lab may live", step: "0.5" },
];

function LimitsView() {
  const api = useApi();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["admin", "limits"], queryFn: () => api<{ limits: Limits }>("/admin/limits") });
  const [draft, setDraft] = useState<Partial<Record<keyof Limits, string>>>({});
  const save = useMutation({
    mutationFn: (patch: Partial<Limits>) => api<{ limits: Limits }>("/admin/limits", { method: "PUT", body: JSON.stringify(patch) }),
    onSuccess: () => { setDraft({}); qc.invalidateQueries({ queryKey: ["admin", "limits"] }); },
  });
  if (q.isLoading) return <LoadingState what="limits" />;
  if (q.error) return <ErrorState title="Limits unavailable" error={q.error} />;
  const l = q.data!.limits;
  const submit = () => {
    const patch: Partial<Limits> = {};
    for (const f of LIMIT_FIELDS) {
      const v = draft[f.key];
      if (v === undefined) continue;
      (patch as Record<string, number | null>)[f.key] = v.trim() === "" ? null : Number(v);
    }
    save.mutate(patch);
  };
  return (
    <div className="space-y-4">
      <Panel>
        <PanelHeader title="Emergency stop"
          description="While paused, no new lab starts for this organization. Running labs are not affected; stop them from Fleet."
          action={<Btn tone={l.paused ? "signal" : "danger"} disabled={save.isPending}
            onClick={() => { if (window.confirm(l.paused ? "Resume new labs?" : "Pause all new labs for this organization?")) save.mutate({ paused: !l.paused }); }}>
            {l.paused ? "Resume" : "Pause new labs"}</Btn>} />
        <div className="px-5 py-3"><Badge tone={l.paused ? "danger" : "mint"}>{l.paused ? "Paused" : "Accepting new labs"}</Badge></div>
      </Panel>
      <Panel>
        <PanelHeader title="Quotas" description="Checked by the worker before a lab gets any resources. A refused lab is failed with the limit named, and the refusal is audited. Leave a field empty for no limit." />
        <div className="grid gap-4 p-5 sm:grid-cols-2">
          {LIMIT_FIELDS.map((f) => (
            <label key={f.key} className="block text-xs">
              <span className="font-medium text-paper">{f.label}</span>
              <input type="number" min="0" step={f.step}
                className="mt-1 w-full rounded-md border border-line bg-panel px-2.5 py-1.5 text-sm text-paper"
                placeholder="no limit"
                value={draft[f.key] ?? (l[f.key] === null ? "" : String(l[f.key]))}
                onChange={(e) => setDraft((d) => ({ ...d, [f.key]: e.target.value }))} />
              <span className="mt-1 block text-faint">{f.hint}</span>
            </label>
          ))}
        </div>
        {save.error && <div className="px-5 pb-3"><ErrorState title="Save failed" error={save.error} /></div>}
        <div className="flex gap-2 border-t border-line px-5 py-3">
          <Btn tone="signal" disabled={save.isPending || Object.keys(draft).length === 0} onClick={submit}>Save limits</Btn>
          {Object.keys(draft).length > 0 && <Btn onClick={() => setDraft({})}>Discard</Btn>}
        </div>
      </Panel>
    </div>
  );
}

// ---- Audit ----

interface AuditEntry { id: number; actor: string; action: string; subject_type: string; subject_id: string; detail: Record<string, unknown> | null; entry_hash: string; created_at: string }

function AuditView() {
  const api = useApi();
  const { getToken } = useAuth();
  const [action, setAction] = useState("");
  const list = useQuery({ queryKey: ["admin", "audit", action], queryFn: () => api<{ entries: AuditEntry[] }>(`/admin/audit?limit=200${action ? `&action=${encodeURIComponent(action)}` : ""}`) });
  const verify = useQuery({ queryKey: ["admin", "audit", "verify"], queryFn: () => api<{ valid: boolean; broken: { brokenId: number; reason: string } | null; checkedAt: string }>("/admin/audit/verify"), enabled: false });
  const exportCsv = useMutation({
    mutationFn: async () => {
      const token = await getToken();
      const res = await fetch(`${learningApiUrl()}/admin/audit/export`, { headers: { Authorization: `Bearer ${token}` } });
      if (!res.ok) throw new Error(((await res.json().catch(() => null)) as { error?: string } | null)?.error ?? `export failed (${res.status})`);
      const url = URL.createObjectURL(await res.blob());
      const a = Object.assign(document.createElement("a"), { href: url, download: `musearena-audit-${new Date().toISOString().slice(0, 10)}.csv` });
      a.click();
      URL.revokeObjectURL(url);
    },
  });
  return (
    <div className="space-y-4">
      <Panel>
        <PanelHeader title="Tamper evidence"
          description="Each entry stores the hash of the previous one, and the database refuses edits and deletes. Verify recomputes every hash on the server."
          action={<div className="flex gap-2">
            <Btn onClick={() => verify.refetch()} disabled={verify.isFetching}><ShieldCheck size={13} /> {verify.isFetching ? "Verifying…" : "Verify chain"}</Btn>
            <Btn onClick={() => exportCsv.mutate()} disabled={exportCsv.isPending}><Download size={13} /> Export CSV</Btn>
          </div>} />
        <div className="px-5 py-3 text-xs">
          {verify.error ? <ErrorState title="Verify failed" error={verify.error} />
            : verify.data ? (verify.data.valid
              ? <span className="inline-flex items-center gap-1.5 text-minttext"><CheckCircle2 size={14} /> Chain intact · checked {formatDate(verify.data.checkedAt)}</span>
              : <span className="inline-flex items-center gap-1.5 text-dangertext"><XCircle size={14} /> Chain broken at entry {verify.data.broken?.brokenId}: {verify.data.broken?.reason}</span>)
              : <span className="text-muted">Not verified in this session.</span>}
          {exportCsv.error && <div className="mt-2"><ErrorState title="Export failed" error={exportCsv.error} /></div>}
        </div>
      </Panel>
      <Panel>
        <PanelHeader title="Entries" description="Newest first."
          action={<input value={action} onChange={(e) => setAction(e.target.value.trim().toUpperCase())} placeholder="filter by action, e.g. ADMIN_LAB_STOPPED"
            className="w-72 rounded-md border border-line bg-panel px-2.5 py-1 text-xs" />} />
        {list.isLoading ? <div className="p-4"><LoadingState what="audit log" /></div>
          : list.error ? <div className="p-4"><ErrorState title="Audit log unavailable" error={list.error} /></div>
            : (list.data!.entries.length === 0 ? <div className="p-4"><EmptyState title="No entries" /></div> : (
              <ul className="divide-y divide-line">
                {list.data!.entries.map((e) => (
                  <li key={e.id} className="grid gap-1 px-5 py-2.5 text-xs sm:grid-cols-[4rem_10rem_1fr_9rem]">
                    <Mono>#{e.id}</Mono>
                    <span className="font-medium text-paper">{e.action}</span>
                    <span className="min-w-0 truncate text-muted" title={JSON.stringify(e.detail ?? {})}>
                      {e.subject_type} {e.subject_id.length > 24 ? shortId(e.subject_id) : e.subject_id} · by {e.actor}
                    </span>
                    <span className="text-faint">{formatDate(e.created_at)}</span>
                  </li>
                ))}
              </ul>
            ))}
      </Panel>
    </div>
  );
}

// ---- Members ----

interface Member { userId: string; email: string; name: string; role: string; joinedAt: string | null }

function MembersView() {
  const api = useApi();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["admin", "members"], queryFn: () => api<{ members: Member[]; invitations: { id: string; email: string; role: string }[]; roles: string[] }>("/admin/members") });
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("reviewer");
  const refresh = () => qc.invalidateQueries({ queryKey: ["admin", "members"] });
  const invite = useMutation({ mutationFn: () => api("/admin/members/invite", { method: "POST", body: JSON.stringify({ email, role }) }), onSuccess: () => { setEmail(""); refresh(); } });
  const change = useMutation({ mutationFn: (v: { userId: string; role: string }) => api(`/admin/members/${v.userId}`, { method: "PATCH", body: JSON.stringify({ role: v.role }) }), onSuccess: refresh });
  const remove = useMutation({ mutationFn: (userId: string) => api(`/admin/members/${userId}`, { method: "DELETE" }), onSuccess: refresh });
  if (q.isLoading) return <LoadingState what="members" />;
  if (q.error) return <ErrorState title="Members unavailable" error={q.error} />;
  const { members, invitations, roles } = q.data!;
  const err = invite.error ?? change.error ?? remove.error;
  return (
    <div className="space-y-4">
      <Panel>
        <PanelHeader title="Invite" description="Reviewer reads; trainer also builds datasets and training runs; operator also deploys, stops labs and manages members." />
        <div className="flex flex-wrap gap-2 p-5">
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@company.com" className="min-w-64 flex-1 rounded-md border border-line bg-panel px-2.5 py-1.5 text-sm" />
          <select value={role} onChange={(e) => setRole(e.target.value)} className="rounded-md border border-line bg-panel px-2 py-1.5 text-sm">
            {roles.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <Btn tone="signal" disabled={!email || invite.isPending} onClick={() => invite.mutate()}>Send invite</Btn>
        </div>
        {err && <div className="px-5 pb-4"><ErrorState title="Member change failed" error={err} /></div>}
      </Panel>
      <Panel>
        <PanelHeader title={`Members (${members.length})`} />
        <ul className="divide-y divide-line">
          {members.map((m) => (
            <li key={m.userId} className="flex flex-wrap items-center gap-3 px-5 py-2.5 text-xs">
              <div className="min-w-0 flex-1"><p className="font-medium text-paper">{m.name || m.email}</p><p className="text-muted">{m.email}</p></div>
              <select value={m.role} disabled={change.isPending} onChange={(e) => change.mutate({ userId: m.userId, role: e.target.value })}
                className="rounded-md border border-line bg-panel px-2 py-1 text-xs">
                {roles.map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
              <Btn tone="danger" disabled={remove.isPending} onClick={() => { if (window.confirm(`Remove ${m.email} from this organization?`)) remove.mutate(m.userId); }}>Remove</Btn>
            </li>
          ))}
        </ul>
        {invitations.length > 0 && (
          <div className="border-t border-line px-5 py-3 text-xs text-muted">Pending invitations: {invitations.map((i) => `${i.email} (${i.role})`).join(", ")}</div>
        )}
      </Panel>
    </div>
  );
}

// ---- Integrations ----

interface Integration { name: string; kind: string; configured: boolean; endpoint: string | null; detail: string }

function IntegrationsView() {
  const api = useApi();
  const [probe, setProbe] = useState(false);
  const q = useQuery({ queryKey: ["admin", "integrations", probe], queryFn: () => api<{ integrations: Integration[]; checks: Record<string, { ok: boolean; status: number | null; ms: number; detail?: string }>; rotation: string }>(`/admin/integrations${probe ? "?probe=1" : ""}`) });
  if (q.isLoading) return <LoadingState what="integrations" />;
  if (q.error) return <ErrorState title="Integrations unavailable" error={q.error} />;
  const { integrations, checks, rotation } = q.data!;
  return (
    <Panel>
      <PanelHeader title="Integrations" description={rotation}
        action={<Btn onClick={() => setProbe(true)} disabled={q.isFetching}>{q.isFetching && probe ? "Testing…" : "Test model endpoints"}</Btn>} />
      <ul className="divide-y divide-line">
        {integrations.map((i) => {
          const c = checks[i.name];
          return (
            <li key={i.name} className="flex flex-wrap items-center gap-3 px-5 py-3 text-xs">
              <div className="min-w-0 flex-1">
                <p className="font-medium text-paper">{i.name} <span className="text-faint">· {i.kind}</span></p>
                <p className="truncate text-muted">{i.detail}{i.endpoint ? ` · ${i.endpoint}` : ""}</p>
              </div>
              {c && <Badge tone={c.ok ? "mint" : "danger"}>{c.ok ? `reachable · ${c.ms} ms` : `failed${c.status ? ` (${c.status})` : ""}`}</Badge>}
              <Badge tone={i.configured ? "mint" : "dim"}>{i.configured ? "configured" : "not configured"}</Badge>
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

const VIEWS: Record<Section, () => ReactNode> = {
  audit: AuditView, fleet: Fleet, limits: LimitsView, usage: UsageView, members: MembersView, integrations: IntegrationsView,
};

export function AdminPage() {
  const [section, setSection] = useState<Section>("fleet");
  const View = VIEWS[section];
  return (
    <div>
      <PageHeader title="Admin" description="Fleet control, spend, quotas, the tamper-evident audit log, members and integrations for this organization." />
      {!clerkEnabled ? (
        <EmptyState title="Clerk is not configured in this frontend">Admin needs a verified Clerk session; no data is shown without one.</EmptyState>
      ) : (
        <>
          <nav className="mb-4 flex flex-wrap gap-1.5" aria-label="Admin sections">
            {SECTIONS.map((s) => (
              <button key={s.id} type="button" onClick={() => setSection(s.id)} aria-current={s.id === section ? "page" : undefined}
                className={`rounded-md border px-3 py-1.5 text-xs font-medium transition ${s.id === section ? "border-signal bg-signal text-signalcontrast" : "border-line bg-panel2 text-muted hover:text-paper"}`}>
                {s.label}
              </button>
            ))}
          </nav>
          <View />
        </>
      )}
    </div>
  );
}
