import { useEffect } from "react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity, ArrowRight, CheckCircle2, Crosshair, Database, Eye, Route as RouteIcon,
  Shield, XCircle,
} from "lucide-react";
import type { Deployment, EnvironmentSpec, PlatformSelection, Run } from "@musearena/shared";
import {
  api, type AuditEntry, type DatasetExportView, type JoinedStepView,
} from "../lib/api";
import { Badge, EmptyState, ErrorState, LoadingState, PageHeader, Panel, PanelHeader, StatCard } from "./ui";
import { formatDate, percent, shortId } from "../lib/format";
import { TopologyGraph, type TopologyFlowInput, type TopologyGroupInput } from "./TopologyGraph";
import { supabase } from "../lib/supabase";
import { LearningConsole } from "./LearningConsole";

type ScoreDetail = Record<string, unknown>;

function scoreAudit(audit: AuditEntry[] | undefined): ScoreDetail {
  return audit?.find((entry) => entry.action === "SCORE_COMPUTED")?.detail ?? {};
}

function auditPlatform(detail: ScoreDetail): PlatformSelection | undefined {
  const value = detail.platform;
  if (!value || typeof value !== "object") return undefined;
  const candidate = value as Partial<PlatformSelection>;
  return candidate.runtimeTarget && candidate.modelSurface && candidate.exerciseEngine
    ? candidate as PlatformSelection
    : undefined;
}

function engineLabel(run: Run | undefined, detail: ScoreDetail): { label: string; modelBacked: boolean } {
  const mode = typeof detail.mode === "string" ? detail.mode : "";
  if (mode.startsWith("agents")) return { label: "Model agents", modelBacked: true };
  if (mode === "live-vm") return { label: "Scripted live VM harness", modelBacked: false };
  if (mode === "live-docker") return { label: "Scripted live container harness", modelBacked: false };
  if (mode === "deterministic-harness") return { label: "Deterministic harness", modelBacked: false };
  const ids = detail.modelIds;
  if (ids && typeof ids === "object" && Object.keys(ids).length > 0) return { label: "Model agents", modelBacked: true };
  return { label: run ? "Scripted or pre-platform run" : "No run", modelBacked: false };
}

function actorOf(step: JoinedStepView): string {
  return step.groundTruth?.actor ?? step.trajectory?.actor ?? "telemetry";
}

function stepTitle(step: JoinedStepView): string {
  if (step.trajectory?.action) return step.trajectory.action;
  if (step.groundTruth) return `${step.groundTruth.kind} · ${step.groundTruth.outcome}`;
  return "Telemetry event";
}

function stepEvidence(step: JoinedStepView): string {
  const detail = step.groundTruth?.detail ?? step.trajectory?.detail;
  const signal = detail?.signal ?? detail?.objectiveId ?? detail?.ruleId ?? detail?.source;
  if (typeof signal === "string" && signal) return signal;
  return step.matched ? "matched trajectory + ground truth" : step.trajectory ? "trajectory only" : "ground truth only";
}

function actorCounts(exp: DatasetExportView | undefined): { actor: string; count: number }[] {
  if (!exp) return [];
  const counts = new Map<string, number>();
  for (const step of exp.join.steps) counts.set(actorOf(step), (counts.get(actorOf(step)) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([actor, count]) => ({ actor, count }));
}

function groupsFor(spec: EnvironmentSpec): TopologyGroupInput[] {
  const subnets = spec.topology.subnets.length
    ? spec.topology.subnets
    : [{ name: "lab", cidr: spec.topology.cidr, zone: "lab" }];
  return subnets.map((subnet, index) => ({
    id: subnet.name,
    name: subnet.name,
    cidr: subnet.cidr,
    zone: subnet.zone,
    instances: spec.instances.filter((instance) =>
      instance.subnet ? instance.subnet === subnet.name : index === 0),
  }));
}

function plannedFlows(spec: EnvironmentSpec): TopologyFlowInput[] {
  const attacker = spec.instances.find((instance) => instance.role === "attacker");
  if (!attacker) return [];
  return spec.objectives
    .filter((objective) => objective.asset !== attacker.hostId)
    .map((objective) => ({
      from: attacker.hostId,
      to: objective.asset,
      label: objective.techniqueId,
      detail: objective.id,
      kind: "service" as const,
    }));
}

function useOpsSelection() {
  const [searchParams, setSearchParams] = useSearchParams();
  const queryClient = useQueryClient();
  useEffect(() => {
    let client: ReturnType<typeof supabase>;
    try {
      client = supabase();
    } catch {
      return;
    }
    const invalidateRuns = () => {
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      void queryClient.invalidateQueries({ queryKey: ["run-audit"] });
      void queryClient.invalidateQueries({ queryKey: ["datasets"] });
    };
    const invalidateDeployments = () => {
      void queryClient.invalidateQueries({ queryKey: ["deployments"] });
      void queryClient.invalidateQueries({ queryKey: ["deployment"] });
    };
    const channel = client
      .channel("exercise-ops-live")
      .on("postgres_changes", { event: "*", schema: "public", table: "runs" }, invalidateRuns)
      .on("postgres_changes", { event: "*", schema: "public", table: "deployments" }, invalidateDeployments)
      .subscribe();
    return () => { void client.removeChannel(channel); };
  }, [queryClient]);
  const runsQuery = useQuery({ queryKey: ["runs"], queryFn: api.runs, refetchInterval: 10_000 });
  const deploymentsQuery = useQuery({ queryKey: ["deployments"], queryFn: api.deployments, refetchInterval: 10_000 });
  const datasetsQuery = useQuery({ queryKey: ["datasets"], queryFn: api.datasets, refetchInterval: 10_000 });

  const runs = runsQuery.data ?? [];
  const deployments = deploymentsQuery.data ?? [];
  const datasets = datasetsQuery.data ?? [];
  const requestedRun = searchParams.get("run") ?? undefined;
  const requestedDeployment = searchParams.get("deployment") ?? undefined;
  const run = runs.find((candidate) => candidate.runId === requestedRun)
    ?? runs.find((candidate) => candidate.deploymentId === requestedDeployment)
    ?? runs.find((candidate) => candidate.score)
    ?? runs[0];
  const deployment = deployments.find((candidate) => candidate.id === run?.deploymentId)
    ?? deployments.find((candidate) => candidate.id === requestedDeployment);
  const dataset = run ? datasets.find((candidate) => candidate.runId === run.runId) : undefined;

  const detailQuery = useQuery({
    queryKey: ["deployment", deployment?.id],
    queryFn: () => api.deployment(deployment!.id),
    enabled: Boolean(deployment?.id),
  });
  const auditQuery = useQuery({
    queryKey: ["run-audit", run?.runId],
    queryFn: () => api.runAudit(run!.runId),
    enabled: Boolean(run?.runId),
    retry: false,
  });
  const exportQuery = useQuery({
    queryKey: ["dataset-export", dataset?.id, dataset?.contentHash],
    queryFn: () => api.datasetExport(dataset!),
    enabled: Boolean(dataset),
    retry: false,
  });

  const setRun = (runId: string) => {
    const next = new URLSearchParams(searchParams);
    next.set("run", runId);
    next.delete("deployment");
    setSearchParams(next);
  };

  return {
    runs, deployments, datasets, run, deployment, dataset,
    spec: detailQuery.data?.spec,
    audit: auditQuery.data ?? [],
    datasetExport: exportQuery.data,
    exportError: exportQuery.error,
    loading: runsQuery.isLoading || deploymentsQuery.isLoading || datasetsQuery.isLoading,
    error: runsQuery.error ?? deploymentsQuery.error ?? datasetsQuery.error,
    detailLoading: detailQuery.isLoading,
    exportLoading: exportQuery.isLoading,
    setRun,
  };
}

type OpsSelection = ReturnType<typeof useOpsSelection>;

function RunPicker({ ops }: { ops: OpsSelection }) {
  if (ops.runs.length === 0) return null;
  return (
    <label className="flex items-center gap-2 text-xs font-medium text-muted">
      Run
      <select
        value={ops.run?.runId ?? ""}
        onChange={(event) => ops.setRun(event.target.value)}
        className="max-w-[340px] rounded-lg border border-line bg-panel px-3 py-2 font-mono text-xs text-paper shadow-sm outline-none focus:border-linestrong"
        aria-label="Select exercise run"
      >
        {ops.runs.map((run) => (
          <option key={run.runId} value={run.runId}>
            {run.runId} · {run.score ? `${run.score.objectivesAchieved ?? "?"}/${run.score.objectivesTotal ?? "?"} objectives` : "unscored"}
          </option>
        ))}
      </select>
    </label>
  );
}

function RunContext({ ops }: { ops: OpsSelection }) {
  const detail = scoreAudit(ops.audit);
  const engine = engineLabel(ops.run, detail);
  const platform = auditPlatform(detail) ?? ops.spec?.platform;
  const counts = actorCounts(ops.datasetExport);
  const campaign = recordOf(detail.redCampaign);
  const monitoring = recordOf(detail.blueMonitoring);
  const anomalyCount = Array.isArray(monitoring?.anomalies) ? monitoring.anomalies.length : 0;
  return (
    <Panel>
      <PanelHeader
        title={ops.run ? ops.run.runId : "No exercise selected"}
        description={ops.run
          ? "Automatic pipeline: deploy → configure → readiness → proof gates → exercise → score → dataset → ready → TTL teardown."
          : "Exercise evidence appears after an approved deployment is claimed by the worker."}
        action={<RunPicker ops={ops} />}
      />
      {ops.run && (
        <div className="flex flex-wrap items-center gap-2 px-5 py-4">
          <Badge tone={engine.modelBacked ? "cyber" : "signal"}>{engine.label}</Badge>
          <Badge>{ops.run.backend}</Badge>
          <Badge>{ops.run.techniquePackVersion}</Badge>
          {platform && <Badge tone="mint">{platform.runtimeTarget} · {platform.modelSurface} · {platform.exerciseEngine}</Badge>}
          {campaign && <Badge tone="danger">Orchestrated red loop</Badge>}
          {monitoring && <Badge tone="cyber">Blue log monitor · {anomalyCount} candidates</Badge>}
          {ops.deployment && <Badge tone="gold">Deployment {ops.deployment.status}</Badge>}
          {ops.dataset
            ? <Badge tone="mint">Dataset {shortId(ops.dataset.contentHash, 18)}</Badge>
            : <Badge tone="danger">No dataset export</Badge>}
          {counts.map(({ actor, count }) => <Badge key={actor}>{actor}: {count}</Badge>)}
          <span className="ml-auto font-mono text-[11px] text-faint">spec {shortId(ops.run.specDigest, 18)}</span>
        </div>
      )}
    </Panel>
  );
}

function StepTimeline({ steps, emptyTitle }: { steps: JoinedStepView[]; emptyTitle: string }) {
  if (steps.length === 0) {
    return <EmptyState title={emptyTitle}>No joined steps are present in the selected run export. The page does not synthesize activity from the score.</EmptyState>;
  }
  return (
    <ol className="divide-y divide-line">
      {steps.map((step, index) => {
        const actor = actorOf(step);
        const outcome = step.groundTruth?.outcome;
        const success = outcome === "succeeded" || outcome === "detected" || outcome === "contained";
        return (
          <li key={`${step.at}-${index}`} className="grid gap-3 px-5 py-4 md:grid-cols-[34px_1fr_auto]">
            <span className={`flex h-8 w-8 items-center justify-center rounded-full border ${success ? "border-mintline bg-mintsurface text-minttext" : "border-line bg-panel2 text-muted"}`}>
              {success ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
            </span>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-mono text-[13px] font-medium text-paper">{stepTitle(step)}</p>
                <Badge tone={actor === "red" ? "danger" : actor === "blue" ? "cyber" : "dim"}>{actor}</Badge>
                {step.techniqueId && <Badge>{step.techniqueId}</Badge>}
                <Badge tone={step.matched ? "mint" : "gold"}>{step.matched ? "matched" : "unmatched"}</Badge>
              </div>
              <p className="mt-1 break-words text-sm leading-6 text-muted">
                {step.hostId || "unknown host"} · {stepEvidence(step)}
              </p>
              {step.trajectory?.observation && (
                <p className="mt-2 line-clamp-3 break-words rounded-md bg-panel2 px-3 py-2 font-mono text-[11px] leading-5 text-muted">
                  {step.trajectory.observation}
                </p>
              )}
              {step.trajectory?.tokenUsage && (
                <p className="mt-1 font-mono text-[10px] text-faint">
                  tokens in {step.trajectory.tokenUsage.inputTokens} · out {step.trajectory.tokenUsage.outputTokens}
                </p>
              )}
            </div>
            <time className="font-mono text-[11px] text-faint" dateTime={step.at}>{formatDate(step.at)}</time>
          </li>
        );
      })}
    </ol>
  );
}

function DatasetProvenance({ ops }: { ops: OpsSelection }) {
  const exp = ops.datasetExport;
  const detail = scoreAudit(ops.audit);
  const engine = engineLabel(ops.run, detail);
  const modelIds = detail.modelIds && typeof detail.modelIds === "object"
    ? Object.entries(detail.modelIds as Record<string, unknown>).filter(([, value]) => typeof value === "string")
    : [];
  const sources = ops.dataset?.sources ?? [];
  const sourceCounts = ops.dataset?.selection?.counts?.sources ?? {};
  const realShare = ops.dataset?.selection?.counts?.realShare;
  const realism = ops.dataset?.selection?.counts?.realism?.share;
  const syntheticOnly = sources.length > 0 && sources.every((source) => source === "synthetic");
  const sourceText = sources.length
    ? sources.map((source) => `${source}${sourceCounts[source] !== undefined ? ` ${sourceCounts[source]}` : ""}`).join(" · ")
    : "not recorded (legacy snapshot)";
  return (
    <Panel>
      <PanelHeader
        title="Dataset provenance"
        description="What this dataset actually is, before anyone trains on it."
        action={<Database size={17} className="text-faint" />}
      />
      {!ops.dataset ? (
        <div className="p-4"><EmptyState title="No dataset for this run">A dataset is created only after a live exercise publishes its joined trajectory and ground truth. Deterministic local exercises and unscored deployments do not create one.</EmptyState></div>
      ) : (
        <dl className="grid gap-4 p-5 text-sm sm:grid-cols-2 xl:grid-cols-4">
          <div><dt className="text-xs text-faint">Source run</dt><dd className="mt-1 break-all font-mono text-xs text-paper">{ops.dataset.runId}</dd></div>
          <div><dt className="text-xs text-faint">Exercise engine</dt><dd className="mt-1 text-paper">{engine.label}</dd></div>
          <div><dt className="text-xs text-faint">Split / hash</dt><dd className="mt-1 break-all font-mono text-xs text-paper">{ops.dataset.split} · {shortId(ops.dataset.contentHash, 22)}</dd></div>
          <div>
            <dt className="text-xs text-faint">Data sources</dt>
            <dd className="mt-1 flex flex-wrap items-center gap-2 font-mono text-xs text-paper">
              {sourceText}
              {sources.length > 0 && <Badge tone={syntheticOnly ? "gold" : "mint"}>{syntheticOnly ? "synthetic only" : "blended"}</Badge>}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-faint">Real share / field tooling</dt>
            <dd className="mt-1 font-mono text-xs text-paper">
              {realShare !== undefined ? `${Math.round(realShare * 100)}% real` : "not recorded"}
              {realism !== undefined ? ` · ${Math.round(realism * 100)}% known tooling` : ""}
            </dd>
          </div>
          <div><dt className="text-xs text-faint">Created</dt><dd className="mt-1 text-paper">{formatDate(ops.dataset.createdAt)}</dd></div>
          <div><dt className="text-xs text-faint">Joined steps</dt><dd className="mt-1 font-mono text-paper">{exp ? `${exp.join.steps.length} (${exp.join.matched} matched)` : ops.exportLoading ? "loading…" : "unavailable"}</dd></div>
          <div><dt className="text-xs text-faint">Trajectory / truth only</dt><dd className="mt-1 font-mono text-paper">{exp ? `${exp.join.trajectoryOnly} / ${exp.join.groundTruthOnly}` : "—"}</dd></div>
          <div><dt className="text-xs text-faint">Dropped</dt><dd className="mt-1 font-mono text-paper">{exp ? exp.join.dropped : "—"}</dd></div>
          <div><dt className="text-xs text-faint">Models</dt><dd className="mt-1 break-words font-mono text-xs text-paper">{modelIds.length ? modelIds.map(([role, id]) => `${role}: ${String(id)}`).join(" · ") : "none recorded (scripted)"}</dd></div>
        </dl>
      )}
      {ops.exportError && <div className="px-4 pb-4"><ErrorState title="Trajectory export could not be read" error={ops.exportError} /></div>}
    </Panel>
  );
}

function PlannedAttackPaths({ ops }: { ops: OpsSelection }) {
  const spec = ops.spec;
  if (!spec) {
    return <Panel><PanelHeader title="Planned attack paths" description="The approved spec is required to derive planned paths." /><div className="p-4">{ops.detailLoading ? <LoadingState what="approved specification" /> : <EmptyState title="Specification unavailable">The selected run has no readable deployment specification.</EmptyState>}</div></Panel>;
  }
  const byHost = new Map(spec.instances.map((instance) => [instance.hostId, instance]));
  const attacker = spec.instances.find((instance) => instance.role === "attacker");
  const entry = attacker?.hostId ?? (spec.platform?.runtimeTarget === "container" ? "platform attacker container" : "scripted red harness");
  const succeeded = new Set((ops.datasetExport?.join.steps ?? [])
    .filter((step) => step.groundTruth?.actor === "red" && step.groundTruth.outcome === "succeeded")
    .map((step) => `${step.hostId}:${step.techniqueId ?? step.groundTruth?.techniqueId ?? ""}`));
  const serviceFor = (objective: EnvironmentSpec["objectives"][number]) => {
    const target = byHost.get(objective.asset);
    const kind = objective.techniqueId === "T1059" ? "http" : objective.techniqueId === "T1078" ? "db" : objective.techniqueId === "T1110" ? "ssh" : undefined;
    const decl = target?.serviceDecls?.find((candidate) => candidate.kind === kind) ?? target?.serviceDecls?.[0];
    return decl ? `${decl.kind}/${decl.impl}:${decl.port}` : "base profile";
  };
  return (
    <Panel>
      <PanelHeader title="Planned attack paths" description="Derived from planted weaknesses and objectives in the approved spec. Executed evidence is shown only when the joined export contains it." action={<RouteIcon size={17} className="text-faint" />} />
      <div className="divide-y divide-line">
        {spec.objectives.map((objective) => {
          const target = byHost.get(objective.asset);
          const vuln = spec.plantedVulns.find((candidate) => candidate.targetHostId === objective.asset && candidate.techniqueId === objective.techniqueId)
            ?? spec.plantedVulns.find((candidate) => candidate.targetHostId === objective.asset);
          const hit = succeeded.has(`${objective.asset}:${objective.techniqueId}`);
          const nodes = [entry, vuln ? `${vuln.type} (${vuln.id})` : "no planted weakness", serviceFor(objective), `${objective.asset}${target ? ` · ${target.role}` : ""}`, objective.successSignal];
          return (
            <div key={objective.id} className="px-5 py-4">
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-mono text-[13px] font-medium text-paper">{objective.id} · {objective.techniqueId}</p>
                <Badge tone={hit ? "mint" : "gold"}>{hit ? "executed + succeeded" : ops.datasetExport ? "not proven in export" : "planned"}</Badge>
                <Badge>{objective.points} pts</Badge>
              </div>
              <div className="mt-3 flex flex-wrap items-center gap-2" aria-label={`Planned path for ${objective.id}`}>
                {nodes.map((node, index) => (
                  <span key={`${objective.id}-${index}`} className="inline-flex items-center gap-2">
                    <span className="rounded-md border border-line bg-panel2 px-2.5 py-1.5 font-mono text-[11px] text-paper">{node}</span>
                    {index < nodes.length - 1 && <ArrowRight size={14} className="text-faint" />}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

function recordOf(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function stringOf(record: Record<string, unknown> | undefined, key: string): string {
  const value = record?.[key];
  return typeof value === "string" ? value : "";
}

function numberOf(record: Record<string, unknown> | undefined, key: string): number | undefined {
  const value = record?.[key];
  return typeof value === "number" ? value : undefined;
}

function RedOrchestratorPanel({ ops }: { ops: OpsSelection }) {
  const detail = scoreAudit(ops.audit);
  const campaign = recordOf(detail.redCampaign);
  const decisions = Array.isArray(campaign?.decisions) ? campaign.decisions.map(recordOf).filter(Boolean) as Record<string, unknown>[] : [];
  const order = Array.isArray(campaign?.order) ? campaign.order.filter((x): x is string => typeof x === "string") : [];
  const orchestratorState = recordOf(recordOf(detail.agentStates)?.["red:orchestrator"]);
  return (
    <Panel>
      <PanelHeader title="Red orchestrator loop" description="Coordinator tasking from the score audit. The orchestrator delegates one objective at a time and receives only whether the planted proof was verified—not the proof value." action={<RouteIcon size={17} className="text-faint" />} />
      {decisions.length === 0 ? (
        <div className="p-4"><EmptyState title="No orchestrator record for this run">Older and scripted runs predate the campaign loop. Their trajectories below are still shown exactly as recorded; no coordination is inferred.</EmptyState></div>
      ) : (
        <>
          <div className="flex flex-wrap gap-2 border-b border-line px-5 py-3">
            <Badge tone="danger">Order: {order.join(" → ") || decisions.map((d) => stringOf(d, "objectiveId")).join(" → ")}</Badge>
            {numberOf(orchestratorState, "steps") !== undefined && <Badge>{numberOf(orchestratorState, "steps")} coordinator turns</Badge>}
            {stringOf(campaign, "summary") && <Badge tone="mint">{stringOf(campaign, "summary")}</Badge>}
          </div>
          <ol className="divide-y divide-line">
            {decisions.map((decision, index) => {
              const retrieved = stringOf(decision, "outcome") === "retrieved";
              return (
                <li key={`${stringOf(decision, "objectiveId")}-${index}`} className="px-5 py-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs text-faint">#{index + 1}</span>
                    <p className="font-mono text-[13px] font-medium text-paper">{stringOf(decision, "objectiveId") || "objective"} → {stringOf(decision, "asset")}</p>
                    {stringOf(decision, "techniqueId") && <Badge>{stringOf(decision, "techniqueId")}</Badge>}
                    <Badge tone={retrieved ? "mint" : "gold"}>{stringOf(decision, "outcome") || "attempted"}</Badge>
                    <Badge tone={stringOf(decision, "source") === "platform" ? "signal" : "cyber"}>{stringOf(decision, "source") || "orchestrator"}</Badge>
                    {numberOf(decision, "attempts") !== undefined && <Badge>{numberOf(decision, "attempts")} executed attempts</Badge>}
                  </div>
                  {stringOf(decision, "reason") && <p className="mt-2 text-sm leading-6 text-muted">Why next: {stringOf(decision, "reason")}</p>}
                  {stringOf(decision, "directive") && <p className="mt-1 break-words rounded-md bg-panel2 px-3 py-2 font-mono text-[11px] leading-5 text-muted">Directive: {stringOf(decision, "directive")}</p>}
                </li>
              );
            })}
          </ol>
        </>
      )}
    </Panel>
  );
}

function BlueMonitorPanel({ ops }: { ops: OpsSelection }) {
  const detail = scoreAudit(ops.audit);
  const monitoring = recordOf(detail.blueMonitoring);
  const anomalies = Array.isArray(monitoring?.anomalies) ? monitoring.anomalies.map(recordOf).filter(Boolean) as Record<string, unknown>[] : [];
  return (
    <Panel>
      <PanelHeader title="Blue log-monitor loop" description="Deterministic anomaly candidates from the score audit. Candidates are triage leads; a scored detection still requires cited telemetry and a promoted rule confirmation." action={<Activity size={17} className="text-faint" />} />
      {!monitoring ? (
        <div className="p-4"><EmptyState title="No log-monitor record for this run">Older and scripted runs do not carry monitor candidates. The joined blue timeline below remains the source of truth for this run.</EmptyState></div>
      ) : (
        <>
          <div className="grid gap-3 border-b border-line p-5 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard label="Telemetry rows" value={String(numberOf(monitoring, "rows") ?? "—")} detail="Collapsed monitor rows" tone="cyber" />
            <StatCard label="Events" value={String(numberOf(monitoring, "events") ?? "—")} detail="Underlying events represented" tone="signal" />
            <StatCard label="Monitor pages" value={String(numberOf(monitoring, "pages") ?? "—")} detail="Batches actually fetched by blue" tone="mint" />
            <StatCard label="Anomaly candidates" value={String(anomalies.length)} detail="Leads to corroborate, not detections" tone={anomalies.length ? "gold" : "mint"} />
          </div>
          {anomalies.length === 0 ? <div className="p-4"><EmptyState title="Monitor found no anomaly candidates">Blue still paged the telemetry; no auth burst, remote database access, execution-shaped, sensitive-access, or volume candidate crossed the monitor thresholds.</EmptyState></div> : (
            <ul className="divide-y divide-line">
              {anomalies.slice(0, 20).map((anomaly, index) => {
                const evidence = Array.isArray(anomaly.evidence) ? anomaly.evidence.filter((x): x is string => typeof x === "string") : [];
                return (
                  <li key={`${stringOf(anomaly, "id")}-${index}`} className="px-5 py-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-mono text-[13px] font-medium text-paper">{stringOf(anomaly, "id") || `A${index + 1}`} · {stringOf(anomaly, "signal")}</p>
                      <Badge tone={stringOf(anomaly, "severity") === "high" ? "danger" : "gold"}>{stringOf(anomaly, "severity") || "candidate"}</Badge>
                      {stringOf(anomaly, "techniqueId") && <Badge>candidate {stringOf(anomaly, "techniqueId")}</Badge>}
                      {numberOf(anomaly, "count") !== undefined && <Badge>{numberOf(anomaly, "count")} events</Badge>}
                    </div>
                    <p className="mt-2 text-sm leading-6 text-muted">{stringOf(anomaly, "summary")}</p>
                    <p className="mt-1 font-mono text-[11px] text-faint">host {stringOf(anomaly, "hostId")} · src {stringOf(anomaly, "src")} · evidence {evidence.join(", ") || "—"}</p>
                  </li>
                );
              })}
            </ul>
          )}
        </>
      )}
    </Panel>
  );
}

function OpsShell({ title, description, ops, children, allowWithoutRun = false }: {
  title: string; description: string; ops: OpsSelection; children: React.ReactNode; allowWithoutRun?: boolean;
}) {
  const runParam = ops.run ? `?run=${encodeURIComponent(ops.run.runId)}` : "";
  const { pathname } = useLocation();
  // The three views share this shell; the active one must be legible, so the
  // current page's button is highlighted and the others stay navigable.
  const navLink = (page: "red" | "blue" | "monitoring", label: string, Icon: typeof Crosshair) => {
    const active = pathname === `/${page}`;
    return (
      <Link
        to={`/${page}${runParam}`}
        aria-current={active ? "page" : undefined}
        className={`inline-flex items-center gap-2 rounded-lg border px-3.5 py-2 text-sm font-medium shadow-sm ${
          active
            ? "border-signal bg-signal text-signalcontrast hover:bg-signalhover"
            : "border-line bg-panel text-paper hover:bg-panel2"
        }`}
      >
        <Icon size={15} /> {label}
      </Link>
    );
  };
  return (
    <div>
      <PageHeader
        title={title}
        description={description}
        actions={<>
          {navLink("red", "Red team", Crosshair)}
          {navLink("blue", "Blue team", Shield)}
          {navLink("monitoring", "Monitoring", Activity)}
        </>}
        meta={<><Badge tone="cyber">Real run data</Badge><Badge>Automatic exercise after proof gates</Badge></>}
      />
      {ops.error ? <ErrorState title="Operations data could not be loaded" error={ops.error} /> : ops.loading ? <LoadingState what="exercise operations" rows={5} /> : !ops.run && !allowWithoutRun ? (
        <EmptyState title="No exercise runs yet" action={<Link to="/designer" className="inline-flex items-center gap-2 rounded-lg bg-signal px-4 py-2.5 text-sm font-medium text-signalcontrast shadow-sm hover:bg-signalhover">Design and deploy <ArrowRight size={15} /></Link>}>
          Approve a deployment and the worker will provision, verify, exercise, score, and publish its dataset automatically.
        </EmptyState>
      ) : (
        <div className="space-y-4">
          <RunContext ops={ops} />
          {children}
        </div>
      )}
    </div>
  );
}

export function RedTeamPage() {
  const ops = useOpsSelection();
  const steps = ops.datasetExport?.join.steps ?? [];
  const redSteps = steps.filter((step) => actorOf(step) === "red");
  const score = ops.run?.score;
  const domain = ops.spec ? (ops.spec.topology as unknown as { domain?: string }).domain ?? ops.spec.topology.cidr : "";
  return (
    <OpsShell title="Red team" description="Planned attack paths and the executed red trajectory, joined to ground-truth evidence from the scored exercise." ops={ops}>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Objectives" value={score ? `${score.objectivesAchieved ?? "—"}/${score.objectivesTotal ?? "—"}` : "—"} detail="Achieved from joined ground truth" tone="danger" />
        <StatCard label="Points" value={score ? `${score.pointsEarned ?? "—"}/${score.pointsTotal ?? "—"}` : "—"} detail="Objective points earned" tone="signal" />
        <StatCard label="Red steps" value={String(redSteps.length)} detail={ops.datasetExport ? "Rows in the joined export" : "Export not readable"} tone="cyber" />
        <StatCard label="Matched evidence" value={ops.datasetExport ? String(ops.datasetExport.join.matched) : "—"} detail="Trajectory rows matched to telemetry" tone="mint" />
      </div>
      {ops.spec && (
        <Panel>
          <PanelHeader title="Cyber-range attack map" description="Topology with planned objective flows from the attacker entry point. Badges mark planted weaknesses and objective assets." />
          <div className="p-4"><TopologyGraph spec={ops.spec} groups={groupsFor(ops.spec)} flows={plannedFlows(ops.spec)} domain={domain} /></div>
        </Panel>
      )}
      <PlannedAttackPaths ops={ops} />
      <RedOrchestratorPanel ops={ops} />
      <Panel>
        <PanelHeader title="Executed red trajectory" description={ops.exportLoading ? "Reading the immutable dataset export…" : "Only rows present in the joined export are shown."} action={<Crosshair size={17} className="text-faint" />} />
        {ops.exportLoading ? <div className="p-4"><LoadingState what="red trajectory" rows={4} /></div> : <StepTimeline steps={redSteps} emptyTitle="No red trajectory in this export" />}
      </Panel>
      <DatasetProvenance ops={ops} />
    </OpsShell>
  );
}

function detailCount(detail: ScoreDetail, key: string): number | undefined {
  const value = detail[key];
  if (typeof value === "number") return value;
  if (Array.isArray(value)) return value.length;
  return undefined;
}

function detailList(detail: ScoreDetail, key: string): unknown[] {
  const value = detail[key];
  return Array.isArray(value) ? value : [];
}

function summarizeUnknown(value: unknown): string {
  if (typeof value === "string") return value;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const parts = ["hostId", "techniqueId", "ruleId", "action", "verdict", "outcome", "status"]
      .flatMap((key) => typeof record[key] === "string" ? [`${key}: ${record[key]}`] : []);
    if (parts.length) return parts.join(" · ");
  }
  return JSON.stringify(value).slice(0, 240);
}

export function BlueTeamPage() {
  const ops = useOpsSelection();
  const steps = ops.datasetExport?.join.steps ?? [];
  const blueSteps = steps.filter((step) => actorOf(step) === "blue");
  const unmatched = steps.filter((step) => !step.matched);
  const detected = steps.filter((step) => step.groundTruth?.outcome === "detected");
  const contained = steps.filter((step) => step.groundTruth?.outcome === "contained");
  const detail = scoreAudit(ops.audit);
  const score = ops.run?.score;
  const auditAlerts = detailCount(detail, "alerts");
  const falsePositives = detailCount(detail, "falsePositives");
  const proposals = detailList(detail, "blueProposals");
  const enforcement = detailList(detail, "enforcement");
  return (
    <OpsShell title="Blue team" description="Detections, response actions, false positives, and telemetry coverage from the same joined evidence that produced the score." ops={ops}>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Detections" value={ops.datasetExport ? String(detected.length) : auditAlerts !== undefined ? String(auditAlerts) : "—"} detail={ops.datasetExport ? "Ground-truth detected outcomes in the export" : auditAlerts !== undefined ? "Rule-confirmed alerts recorded in the score audit" : "No detection count recorded"} tone="cyber" />
        <StatCard label="Contained" value={String(contained.length)} detail={score?.containmentCorrectness !== undefined ? `${percent(score.containmentCorrectness)} containment correctness` : "No containment score recorded"} tone="mint" />
        <StatCard label="MTTD p50" value={score?.mttdMinutesP50 !== undefined ? `${score.mttdMinutesP50.toFixed(2)} min` : "—"} detail="First red attempt to first blue detection" tone="signal" />
        <StatCard label="False positives" value={falsePositives !== undefined ? String(falsePositives) : score?.falsePositiveRate !== undefined ? percent(score.falsePositiveRate) : "—"} detail={score?.falsePositiveRate !== undefined ? `${percent(score.falsePositiveRate)} false-positive rate` : "No FP detail recorded"} tone={falsePositives ? "gold" : "mint"} />
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        <StatCard label="Analytic coverage" value={percent(score?.analyticCoverage)} detail="Objectives with a matching analytic" progress={(score?.analyticCoverage ?? 0) * 100} tone="cyber" />
        <StatCard label="Exact technique" value={percent(score?.exactTechniqueCoverage)} detail="Detections naming the exact technique" progress={(score?.exactTechniqueCoverage ?? 0) * 100} tone="mint" />
        <StatCard label="Visibility" value={percent(score?.visibilityCoverage)} detail="Joined steps with telemetry evidence" progress={(score?.visibilityCoverage ?? 0) * 100} tone="signal" />
      </div>
      <BlueMonitorPanel ops={ops} />
      <Panel>
        <PanelHeader title="Detection and response timeline" description={ops.exportLoading ? "Reading the immutable dataset export…" : "Blue trajectory and ground-truth detections in time order."} action={<Shield size={17} className="text-faint" />} />
        {ops.exportLoading ? <div className="p-4"><LoadingState what="blue timeline" rows={4} /></div> : <StepTimeline steps={[...blueSteps, ...detected.filter((step) => !blueSteps.includes(step)), ...contained.filter((step) => !blueSteps.includes(step) && !detected.includes(step))].sort((a, b) => a.at.localeCompare(b.at))} emptyTitle="No blue activity in this export" />}
      </Panel>
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel>
          <PanelHeader title="Blue proposals" description="Recorded in the score audit for model-agent runs. Scripted Sigma runs may have none." />
          {proposals.length === 0 ? <div className="p-4"><EmptyState title="No blue proposals recorded">This run either used the scripted detector or its audit detail carries no proposals.</EmptyState></div> : (
            <ul className="divide-y divide-line">{proposals.slice(0, 12).map((item, index) => <li key={index} className="break-words px-5 py-3 font-mono text-xs leading-5 text-muted">{summarizeUnknown(item)}</li>)}</ul>
          )}
        </Panel>
        <Panel>
          <PanelHeader title="Enforcement" description="Response actions recorded with the score; proposed-only actions are not presented as enforced." />
          {enforcement.length === 0 ? <div className="p-4"><EmptyState title="No enforcement record">No block/isolate/rotate enforcement was recorded for this run.</EmptyState></div> : (
            <ul className="divide-y divide-line">{enforcement.slice(0, 12).map((item, index) => <li key={index} className="break-words px-5 py-3 font-mono text-xs leading-5 text-muted">{summarizeUnknown(item)}</li>)}</ul>
          )}
        </Panel>
      </div>
      <Panel>
        <PanelHeader title="Unmatched telemetry" description="Rows the join could not pair. These are visibility gaps or benign activity, not silently dropped evidence." action={<Eye size={17} className="text-faint" />} />
        {ops.exportLoading ? <div className="p-4"><LoadingState what="unmatched telemetry" rows={3} /></div> : <StepTimeline steps={unmatched.slice(0, 30)} emptyTitle="No unmatched rows" />}
      </Panel>
      <DatasetProvenance ops={ops} />
    </OpsShell>
  );
}

const LIFECYCLE_STAGES = [
  { label: "Claim", statuses: ["pending", "provisioning"] },
  { label: "Deploy + configure", statuses: ["configuring"] },
  { label: "Verify gates", statuses: ["verifying"] },
  { label: "Exercise + score", statuses: ["exercising"] },
  { label: "Ready / scored", statuses: ["ready"] },
  { label: "Teardown", statuses: ["destroying", "destroyed"] },
  { label: "Needs attention", statuses: ["failed", "quarantined"] },
];

export function MonitoringPage() {
  const ops = useOpsSelection();
  const active = ops.deployments.filter((deployment) => ["pending", "provisioning", "configuring", "verifying", "exercising", "destroying"].includes(deployment.status));
  const scored = ops.runs.filter((run) => run.score);
  const runLink = (run: Run, page: "red" | "blue") => `/${page}?run=${encodeURIComponent(run.runId)}`;
  return (
    <OpsShell title="Monitoring" description="Live deployment lifecycle, automatic exercise state, scores, and dataset publication for the selected run." ops={ops} allowWithoutRun>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Deployments" value={String(ops.deployments.length)} detail={`${active.length} active right now`} tone="cyber" />
        <StatCard label="Exercising" value={String(ops.deployments.filter((d) => d.status === "exercising").length)} detail="Automatic after proof gates pass" tone="gold" />
        <StatCard label="Scored runs" value={String(scored.length)} detail={`${ops.runs.length} run rows recorded`} tone="mint" />
        <StatCard label="Dataset exports" value={String(ops.datasets.length)} detail="Immutable joined exports in private storage" tone="signal" />
      </div>

      <Panel>
        <PanelHeader title="Automatic deployment pipeline" description="Approval starts the worker lifecycle. Exercise, scoring, and dataset publication happen before a deployment is marked ready; TTL teardown follows automatically." action={<Activity size={17} className="text-faint" />} />
        <div className="grid gap-3 p-5 md:grid-cols-2 xl:grid-cols-4">
          {LIFECYCLE_STAGES.map((stage) => {
            const count = ops.deployments.filter((deployment) => stage.statuses.includes(deployment.status)).length;
            return (
              <div key={stage.label} className="rounded-lg border border-line bg-panel2 px-4 py-3">
                <p className="text-xs font-medium text-muted">{stage.label}</p>
                <p className="mt-1 font-display text-2xl font-semibold text-paper">{count}</p>
                <p className="mt-1 font-mono text-[10px] text-faint">{stage.statuses.join(" · ")}</p>
              </div>
            );
          })}
          <div className="rounded-lg border border-line bg-panel2 px-4 py-3">
            <p className="text-xs font-medium text-muted">Dataset published</p>
            <p className="mt-1 font-display text-2xl font-semibold text-paper">{ops.datasets.length}</p>
            <p className="mt-1 font-mono text-[10px] text-faint">only after a live exercise joins evidence</p>
          </div>
        </div>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel>
          <PanelHeader title="Recent runs" description="Open the same run in the red or blue evidence view." />
          {ops.runs.length === 0 ? <div className="p-4"><EmptyState title="No runs recorded" /></div> : (
            <ul className="divide-y divide-line">
              {ops.runs.slice(0, 10).map((run) => (
                <li key={run.runId} className="flex flex-wrap items-center gap-3 px-5 py-3">
                  <div className="min-w-0 flex-1">
                    <p className="break-all font-mono text-xs font-medium text-paper">{run.runId}</p>
                    <p className="mt-0.5 text-xs text-muted">{run.score ? `${run.score.objectivesAchieved ?? "—"}/${run.score.objectivesTotal ?? "—"} objectives · ${percent(run.score.visibilityCoverage)} visibility` : "unscored"}</p>
                  </div>
                  <Link to={runLink(run, "red")} className="inline-flex items-center gap-1.5 rounded-md border border-line bg-panel px-2.5 py-1.5 text-xs font-medium text-paper hover:bg-panel2"><Crosshair size={13} /> Red</Link>
                  <Link to={runLink(run, "blue")} className="inline-flex items-center gap-1.5 rounded-md border border-line bg-panel px-2.5 py-1.5 text-xs font-medium text-paper hover:bg-panel2"><Shield size={13} /> Blue</Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel>
          <PanelHeader title="Recent deployments" description="Lifecycle and drift state from persisted deployment rows (10-second refresh plus realtime detail subscriptions)." />
          {ops.deployments.length === 0 ? <div className="p-4"><EmptyState title="No deployments recorded" /></div> : (
            <ul className="divide-y divide-line">
              {ops.deployments.slice(0, 10).map((deployment: Deployment) => (
                <li key={deployment.id} className="flex flex-wrap items-center gap-3 px-5 py-3">
                  <div className="min-w-0 flex-1">
                    <Link to={`/environments/${deployment.id}`} className="break-all font-mono text-xs font-medium text-paper hover:text-signal">{deployment.id}</Link>
                    <p className="mt-0.5 text-xs text-muted">{deployment.stackId || "no stack yet"} · drift {deployment.driftStatus ?? "unknown"}</p>
                  </div>
                  <Badge tone={deployment.status === "ready" ? "mint" : deployment.status === "failed" ? "danger" : "gold"}>{deployment.status}</Badge>
                  <span className="font-mono text-[10px] text-faint">{formatDate(deployment.createdAt)}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
      <DatasetProvenance ops={ops} />
    </OpsShell>
  );
}

export function LearningPage() {
  const ops = useOpsSelection();
  const rows = [
    ["Capture", "F-16/F-4", "Live capture-key ingest writes hash-chained, redacted trace rows; the operations pages also read immutable dataset exports. Raw traces are append-only evidence."],
    ["Review", "F-5/F-6", "Corrections, versioned label disputes, and adjudication are live, with rule and model signals grading new traces continually. Edits are overlays; history is never rewritten."],
    ["Datasets", "F-7/F-8", "Role-aware snapshots are built from the traces table with provenance (synthetic / imported / field), real-share floors, and rename/archive lifecycle. Snapshots stay immutable."],
    ["Training", "F-9", "Training-run control plane exists: a run ends in a real artifact or honestly in awaiting_trainer when META_TRAINER_URL is unset."],
    ["Evaluation", "F-10/F-15", "Held-out candidate-vs-base evaluation, Brier/ECE calibration, and dispute filing exist in code; production trial execution still needs the worker runner and live schema."],
    ["Model deployments", "F-11/F-12", "Promotion gating, rollback, traffic pinning, and continual proposals exist in code; nothing auto-promotes or auto-starts training."],
  ] as const;
  return (
    <div>
      <PageHeader
        title="Learning"
        description="The learning platform shell: what is real today, what remains gated, and the evidence already available from scored exercises."
        meta={<><Badge tone="mint">Capture live</Badge><Badge tone="mint">Export evidence live</Badge></>}
      />
      <div className="space-y-4">
        <LearningConsole />
        <Panel>
          <PanelHeader title="Learning milestones" description="These states mirror the follow-on platform spec. Empty means not built or not live-verified, not simulated." />
          <div className="divide-y divide-line">
            {rows.map(([name, task, state]) => (
              <div key={name} className="grid gap-2 px-5 py-4 md:grid-cols-[170px_90px_1fr]">
                <p className="text-sm font-semibold text-paper">{name}</p>
                <p><Badge>{task}</Badge></p>
                <p className="text-sm leading-6 text-muted">{state}</p>
              </div>
            ))}
          </div>
        </Panel>
        {ops.run ? <DatasetProvenance ops={ops} /> : (
          <EmptyState title="No exercise evidence yet">Once a deployment is exercised and scored, its real joined export and provenance appear here and in the Red/Blue views.</EmptyState>
        )}
        <Panel>
          <PanelHeader title="Available evidence surfaces" description="Operational views for shipped behavior; the learning console above carries the audited write actions (rename, archive, deprecate, enable/disable, tombstone)." />
          <div className="flex flex-wrap gap-2 p-5">
            <Link to="/red" className="inline-flex items-center gap-2 rounded-lg border border-line bg-panel px-3.5 py-2 text-sm font-medium text-paper hover:bg-panel2"><Crosshair size={15} /> Red trajectories</Link>
            <Link to="/blue" className="inline-flex items-center gap-2 rounded-lg border border-line bg-panel px-3.5 py-2 text-sm font-medium text-paper hover:bg-panel2"><Shield size={15} /> Blue dashboard</Link>
            <Link to="/monitoring" className="inline-flex items-center gap-2 rounded-lg border border-line bg-panel px-3.5 py-2 text-sm font-medium text-paper hover:bg-panel2"><Activity size={15} /> Monitoring</Link>
            <Link to="/traces" className="inline-flex items-center gap-2 rounded-lg border border-line bg-panel px-3.5 py-2 text-sm font-medium text-paper hover:bg-panel2"><Database size={15} /> Dataset rows</Link>
          </div>
        </Panel>
      </div>
    </div>
  );
}
