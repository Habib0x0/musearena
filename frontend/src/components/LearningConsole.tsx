import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@clerk/clerk-react";
import { BrainCircuit } from "lucide-react";
import { Badge, EmptyState, ErrorState, LoadingState, Panel, PanelHeader, StatCard } from "./ui";
import { formatDate, shortId } from "../lib/format";
import { clerkEnabled } from "../auth/clerk-config";
import { learningFetch } from "../lib/learning-api";

/**
 * Learning console (F-13): every tab reads the learning API and renders the
 * rows it returns — an empty list is an empty state, a failed request shows
 * the server's reason, and lifecycle actions call the same audited routes an
 * operator would use from the CLI. Nothing here is mock data.
 */
type Row = Record<string, unknown>;

interface TabDef {
  id: string;
  label: string;
  path: string;
  rowsKey?: string;
  fields: string[];
}

const TABS: TabDef[] = [
  { id: "overview", label: "Overview", path: "/overview", fields: [] },
  { id: "traces", label: "Data", path: "/traces", rowsKey: "traces", fields: ["run_id", "host_id", "technique_id", "outcome", "split", "at"] },
  { id: "signals", label: "Signals", path: "/signals", rowsKey: "signals", fields: ["kind", "version", "enabled", "hits"] },
  { id: "datasets", label: "Datasets", path: "/datasets", rowsKey: "datasets", fields: ["split", "content_hash", "family", "example_count", "created_at"] },
  { id: "models", label: "Models", path: "/models", rowsKey: "models", fields: ["served_model", "provider", "status", "artifact_hash", "version"] },
  { id: "training", label: "Training", path: "/training-runs", rowsKey: "trainingRuns", fields: ["role", "method", "status", "budget_usd", "spent_usd", "approved_by", "error"] },
  { id: "evaluations", label: "Evaluations", path: "/evaluations", rowsKey: "evaluations", fields: ["role", "status", "error", "created_at"] },
  { id: "graders", label: "Graders", path: "/graders", rowsKey: "graders", fields: ["kind", "version", "enabled"] },
  { id: "deployments", label: "Deployments", path: "/model-deployments", rowsKey: "deployments", fields: ["alias", "environment", "role", "status", "traffic_pct", "approved_by"] },
  { id: "proposals", label: "Proposals", path: "/training-proposals", rowsKey: "proposals", fields: ["trigger", "role", "method", "status", "reason"] },
];

function str(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(str).join(", ");
  return JSON.stringify(value).slice(0, 160);
}

function titleOf(row: Row): string {
  for (const key of ["name", "alias", "id"]) {
    if (typeof row[key] === "string" && row[key]) return key === "id" ? shortId(row[key] as string) : row[key] as string;
  }
  return "row";
}

interface RowAction {
  label: string;
  path: string;
  method?: "POST" | "PATCH" | "DELETE";
  body?: unknown;
  /** Ask before running (destructive actions). */
  confirm?: string;
  /** Prompt for a single string field (renames); its value becomes the body. */
  prompt?: { label: string; field: string };
}

function actionsFor(tab: string, row: Row): RowAction[] {
  const id = typeof row.id === "string" ? row.id : "";
  if (!id) return [];
  const status = typeof row.status === "string" ? row.status : "";
  if (tab === "training" && ["queued", "awaiting_trainer"].includes(status)) {
    return [
      { label: "Approve", path: `/training-runs/${id}/approve` },
      { label: "Cancel", path: `/training-runs/${id}/cancel` },
    ];
  }
  if (tab === "training" && status === "running") return [{ label: "Cancel", path: `/training-runs/${id}/cancel` }];
  if (tab === "evaluations" && status === "queued") return [{ label: "Run", path: `/evaluations/${id}/run` }];
  if (tab === "deployments" && status === "active") return [{ label: "Roll back", path: `/model-deployments/${id}/rollback` }];
  if (tab === "proposals" && status === "proposed") {
    return [
      { label: "Approve", path: `/training-proposals/${id}/approve` },
      { label: "Reject", path: `/training-proposals/${id}/reject` },
    ];
  }
  const archived = row.archived_at !== null && row.archived_at !== undefined;
  if (tab === "datasets") {
    return [
      { label: "Rename", path: `/datasets/${id}`, method: "PATCH", prompt: { label: "New dataset name", field: "name" } },
      archived
        ? { label: "Restore", path: `/datasets/${id}?action=restore`, method: "PATCH", body: {} }
        : { label: "Archive", path: `/datasets/${id}?action=archive`, method: "PATCH", body: {}, confirm: "Archive this dataset snapshot? It stays stored but hidden from builders." },
    ];
  }
  if (tab === "models") {
    const actions: RowAction[] = [
      { label: "Rename", path: `/models/${id}`, method: "PATCH", prompt: { label: "New model name", field: "name" } },
    ];
    if (status !== "deprecated") {
      actions.push({
        label: "Deprecate", path: `/models/${id}`, method: "PATCH", body: { status: "deprecated" },
        confirm: "Deprecate this model? Roles will resolve to the next ready model or the verified base.",
      });
    }
    return actions;
  }
  if (tab === "signals") {
    const enabled = row.enabled === true;
    return [
      { label: enabled ? "Disable" : "Enable", path: `/signals/${id}`, method: "PATCH", body: { enabled: !enabled } },
      { label: "Delete", path: `/signals/${id}`, method: "DELETE", confirm: "Delete this signal and its recorded hits?" },
    ];
  }
  if (tab === "graders") {
    const enabled = row.enabled === true;
    return [
      { label: enabled ? "Disable" : "Enable", path: `/graders/${id}`, method: "PATCH", body: { enabled: !enabled } },
      { label: "Delete", path: `/graders/${id}`, method: "DELETE", confirm: "Delete this grader definition?" },
    ];
  }
  if (tab === "traces") {
    const tombstoned = row.tombstoned_at !== null && row.tombstoned_at !== undefined;
    const runId = typeof row.run_id === "string" ? row.run_id : "";
    const actions: RowAction[] = tombstoned
      ? [{ label: "Restore", path: `/traces/${id}/restore`, method: "PATCH", body: {} }]
      : typeof row.source === "string" && row.source !== "synthetic" ? [] : [{
          label: "Delete", path: `/traces/${id}`, method: "DELETE",
          confirm: "Tombstone this trace? It is excluded from builds and signals; imported/field evidence is refused.",
        }];
    if (runId) {
      actions.push({
        label: "Delete run", path: `/runs/${encodeURIComponent(runId)}`, method: "DELETE",
        confirm: `Delete run ${runId}? Its traces are tombstoned and its runs row removed; chained evidence stays verifiable.`,
      });
    }
    return actions;
  }
  return [];
}

function OverviewPanel({ data }: { data: Row }) {
  const numeric = ["traces", "corrections", "openDisputes", "datasets", "trainingRuns", "openProposals"];
  return (
    <div className="space-y-4 p-5">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {numeric.map((key) => (
          <StatCard key={key} label={key} value={str(data[key])} detail="Live org count from the learning API" tone="cyber" />
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <p className="text-[13px] font-semibold text-paper">Production deployments</p>
          {Array.isArray(data.productionDeployments) && data.productionDeployments.length > 0 ? (
            <ul className="mt-2 space-y-2">
              {(data.productionDeployments as Row[]).map((row, i) => (
                <li key={i} className="rounded-md bg-panel2 px-3 py-2 font-mono text-[11px] text-muted">
                  {str(row.alias)} · {str(row.role)} · {str(row.traffic_pct)}% · model {str(row.model_id)}
                </li>
              ))}
            </ul>
          ) : <p className="mt-2 text-sm text-muted">No active production deployment is recorded.</p>}
        </div>
        <div>
          <p className="text-[13px] font-semibold text-paper">Last evaluation</p>
          <p className="mt-2 break-words rounded-md bg-panel2 px-3 py-2 font-mono text-[11px] leading-5 text-muted">
            {data.lastEvaluation ? str(data.lastEvaluation) : "No evaluation has been recorded yet."}
          </p>
        </div>
      </div>
    </div>
  );
}

function LearningConsoleInner() {
  const { getToken, isLoaded, isSignedIn } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const queryClient = useQueryClient();
  const [actionError, setActionError] = useState<string | null>(null);
  const [showArchived, setShowArchived] = useState(false);
  const tabId = searchParams.get("tab") ?? "overview";
  const tab = TABS.find((t) => t.id === tabId) ?? TABS[0];

  const query = useQuery({
    queryKey: ["learning", tab.id, tab.id === "datasets" && showArchived ? "archived" : "active"],
    queryFn: () => learningFetch<Row>(() => getToken(), tab.id === "datasets" && showArchived ? `${tab.path}?archived=1` : tab.path),
    enabled: Boolean(isLoaded && isSignedIn),
  });
  const leaderboardQuery = useQuery({
    queryKey: ["learning", "leaderboard"],
    queryFn: () => learningFetch<{ leaderboard: unknown }>(() => getToken(), "/evaluations/leaderboard"),
    enabled: Boolean(isLoaded && isSignedIn && tab.id === "evaluations"),
  });
  const action = useMutation({
    mutationFn: (a: RowAction) => {
      let body = a.body ?? {};
      if (a.prompt) {
        const value = window.prompt(a.prompt.label, "");
        if (value === null) return Promise.resolve(null);
        body = { [a.prompt.field]: value.trim() };
      }
      if (a.confirm && !window.confirm(a.confirm)) return Promise.resolve(null);
      return learningFetch<Row>(() => getToken(), a.path, {
        method: a.method ?? "POST",
        body: JSON.stringify(body),
      });
    },
    onSuccess: async () => {
      setActionError(null);
      await queryClient.invalidateQueries({ queryKey: ["learning"] });
    },
    onError: (err) => setActionError(err instanceof Error ? err.message : String(err)),
  });

  const rows: Row[] = tab.rowsKey && Array.isArray(query.data?.[tab.rowsKey])
    ? query.data[tab.rowsKey] as Row[]
    : [];

  return (
    <Panel>
      <PanelHeader
        title="Learning console"
        description="Live learning-API surfaces. Empty tabs are real empty states; failures show the server's reason. Lifecycle buttons call the audited operator routes."
        action={<BrainCircuit size={17} className="text-faint" />}
      />
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-3">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setSearchParams({ tab: t.id })}
            className={`rounded-md px-3 py-1.5 text-[12px] font-medium ${t.id === tab.id ? "bg-signal text-signalcontrast" : "bg-panel2 text-muted hover:text-paper"}`}
          >
            {t.label}
          </button>
        ))}
        {tab.id === "datasets" && (
          <label className="ml-auto flex items-center gap-1.5 text-[11px] text-muted">
            <input
              type="checkbox"
              checked={showArchived}
              onChange={(event) => setShowArchived(event.target.checked)}
              className="accent-[var(--signal)]"
            />
            show archived
          </label>
        )}
      </div>
      {actionError && (
        <p className="border-b border-line px-5 py-3 text-sm text-dangertext">Action failed: {actionError}</p>
      )}
      {!isLoaded || query.isPending ? (
        <LoadingState what={tab.label.toLowerCase()} rows={4} />
      ) : !isSignedIn ? (
        <div className="p-4"><EmptyState title="Sign in with an organization role">The learning API requires a Clerk session whose verified claims carry an org and a reviewer/trainer/operator role.</EmptyState></div>
      ) : query.isError ? (
        <div className="p-4"><ErrorState title={`${tab.label} could not be loaded`} error={query.error} /></div>
      ) : tab.id === "overview" && query.data ? (
        <OverviewPanel data={query.data} />
      ) : rows.length === 0 ? (
        <div className="p-4"><EmptyState title={`No ${tab.label.toLowerCase()} recorded yet`}>This tab renders only rows returned by the learning API for your organization.</EmptyState></div>
      ) : (
        <ul className="divide-y divide-line">
          {rows.map((row, index) => (
            <li key={typeof row.id === "string" ? row.id : index} className="px-5 py-4">
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-mono text-[13px] font-medium text-paper">{titleOf(row)}</p>
                {typeof row.status === "string" && <Badge tone="cyber">{row.status}</Badge>}
                {row.archived_at !== null && row.archived_at !== undefined && <Badge tone="danger">archived</Badge>}
                {row.tombstoned_at !== null && row.tombstoned_at !== undefined && <Badge tone="danger">deleted</Badge>}
                {typeof row.role === "string" && <Badge>{row.role}</Badge>}
                {Array.isArray(row.role) && row.role.map((r) => <Badge key={String(r)}>{String(r)}</Badge>)}
                {typeof row.created_at === "string" && <span className="font-mono text-[11px] text-faint">{formatDate(row.created_at)}</span>}
              </div>
              <div className="mt-2 grid gap-1 font-mono text-[11px] leading-5 text-muted sm:grid-cols-2">
                {tab.fields.filter((f) => row[f] !== undefined && row[f] !== null && f !== "status" && f !== "role").map((f) => (
                  <p key={f} className="break-words">{f}: {str(row[f])}</p>
                ))}
              </div>
              {tab.id === "evaluations" && row.comparison !== undefined && (
                <p className="mt-2 break-words rounded-md bg-panel2 px-3 py-2 font-mono text-[11px] leading-5 text-muted">comparison: {str(row.comparison)}</p>
              )}
              {actionsFor(tab.id, row).length > 0 && (
                <div className="mt-3 flex flex-wrap gap-2">
                  {actionsFor(tab.id, row).map((a) => (
                    <button
                      key={a.path + a.label}
                      type="button"
                      disabled={action.isPending}
                      onClick={() => action.mutate(a)}
                      className={`rounded-md border px-3 py-1.5 text-[12px] font-medium disabled:opacity-50 ${
                        a.method === "DELETE"
                          ? "border-dangerline bg-dangersurface text-dangertext hover:bg-dangerline/40"
                          : "border-line bg-panel text-paper hover:bg-panel2"
                      }`}
                    >
                      {a.label}
                    </button>
                  ))}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {tab.id === "evaluations" && leaderboardQuery.data && (
        <div className="border-t border-line px-5 py-4">
          <p className="text-[13px] font-semibold text-paper">Leaderboard</p>
          <p className="mt-2 break-words font-mono text-[11px] leading-5 text-muted">{str(leaderboardQuery.data.leaderboard)}</p>
        </div>
      )}
    </Panel>
  );
}

export function LearningConsole() {
  if (!clerkEnabled) {
    return (
      <Panel>
        <PanelHeader title="Learning console" description="The learning API authenticates with Clerk session tokens." />
        <div className="p-4">
          <EmptyState title="Clerk is not configured in this frontend">
            Set a Clerk publishable key to load live learning surfaces; no data is shown without a verified session.
          </EmptyState>
        </div>
      </Panel>
    );
  }
  return <LearningConsoleInner />;
}
