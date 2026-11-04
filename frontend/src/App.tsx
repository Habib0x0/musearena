import { Link, Navigate, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity, ArrowRight, ArrowUp, Boxes, Braces, CheckCircle2, ChevronDown, CircleDot, Clock3,
  Crosshair, Database, Download, FileCode2, GitBranch, KeyRound, LayoutDashboard,
  BrainCircuit, Library, ListChecks, LogOut, Network, PanelLeftClose, PanelLeftOpen, Route as RouteIcon, Save, Search, Server, Settings2, Shield,
  ShieldAlert, Moon, Sun, MonitorSmartphone, Square, Trash2, Upload, Users, X, XCircle, type LucideIcon,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useSession } from "./auth/AuthContext";
import { ClerkAuthProvider, ClerkControls } from "./auth/ClerkAuth";
import { clerkEnabled, clerkKey } from "./auth/clerk-config";
import { api, PlatformUnavailableError, type DesignPackage, type DesignerRunEvent } from "./lib/api";
import { learningFetch } from "./lib/learning-api";
import { useAuth } from "@clerk/clerk-react";
import { useLiveDeployment, useLiveRun } from "./hooks/useLiveRun";
import { useTheme, type ThemePreference } from "./hooks/useTheme";
import { EnvironmentSpec, type Budget, type Deployment, type Persona, type PlatformSelection, type Run } from "@musearena/shared";
import {
  Badge, EmptyState, ErrorState, LoadingState, PageHeader, Panel, PanelHeader, StatCard,
} from "./components/ui";
import { formatDate, percent, shortId, statusTone } from "./lib/format";
import { TopologyGraph, type TopologyFlowInput, type TopologyGroupInput } from "./components/TopologyGraph";
import { ThinkingState, type DetailLine, type TraceNode } from "./components/ui/ai-thinking-and-tool-calls";
import { BlueTeamPage, LearningPage, MonitoringPage, RedTeamPage } from "./components/ExerciseOps";
import { AdminPage } from "./components/AdminConsole";

const primaryButton = "inline-flex items-center justify-center gap-2 rounded-lg bg-signal px-4 py-2.5 text-sm font-medium text-signalcontrast shadow-sm transition-colors hover:bg-signalhover disabled:cursor-not-allowed disabled:opacity-45";
const secondaryButton = "inline-flex items-center justify-center gap-2 rounded-lg border border-line bg-panel px-4 py-2.5 text-sm font-medium text-paper shadow-sm transition-colors hover:bg-panel2 disabled:cursor-not-allowed disabled:opacity-45";
const compactButton = "inline-flex items-center justify-center gap-1.5 rounded-md border border-line bg-panel px-2.5 py-1.5 text-xs font-medium text-paper shadow-sm transition-colors hover:bg-panel2 disabled:cursor-not-allowed disabled:opacity-45";

function average(values: number[]): number | null {
  return values.length ? values.reduce((a, b) => a + b, 0) / values.length : null;
}

function prettify(value: string): string {
  return value.replace(/[-_]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function Status({ value }: { value: string }) {
  return <Badge tone={statusTone(value)}><span className="h-1.5 w-1.5 rounded-full bg-current" />{prettify(value)}</Badge>;
}

function SegmentedTabs({ values, value, onChange, label, labels = {} }: {
  values: readonly string[];
  value: string;
  onChange: (value: string) => void;
  label: string;
  labels?: Record<string, string>;
}) {
  return (
    <div className="inline-flex max-w-full gap-1 overflow-x-auto rounded-lg bg-panel2 p-1" role="tablist" aria-label={label}>
      {values.map((item) => (
        <button
          key={item}
          role="tab"
          aria-selected={value === item}
          onClick={() => onChange(item)}
          className={`whitespace-nowrap rounded-md px-3.5 py-2 text-sm capitalize transition-colors ${value === item ? "bg-panel font-semibold text-paper shadow-sm" : "text-muted hover:text-paper"}`}
        >
          {labels[item] ?? item}
        </button>
      ))}
    </div>
  );
}

function Progress({ value, tone = "signal" }: { value: number; tone?: "signal" | "mint" | "gold" | "danger" | "cyber" }) {
  const color = tone === "mint" ? "bg-mint" : tone === "gold" ? "bg-gold" : tone === "danger" ? "bg-danger" : tone === "cyber" ? "bg-cyber" : "bg-signal";
  return (
    <div className="h-1.5 overflow-hidden rounded-full bg-panel2" aria-hidden="true">
      <div className={`h-full rounded-full transition-[width] duration-500 ease-out ${color}`} style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
    </div>
  );
}

function BrandMark({ size = 38 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" role="img" aria-label="MuseArena logo" className="shrink-0">
      <rect x={1} y={1} width={38} height={38} rx={10} fill="var(--signal)" />
      <path d="M11 27V13l9 8 9-8v14" fill="none" stroke="var(--paper)" strokeWidth={2.4} strokeLinecap="square" strokeLinejoin="miter" />
      <circle cx={11} cy={13} r={2.4} fill="var(--cyber)" />
      <circle cx={20} cy={21} r={2.4} fill="var(--mint)" />
      <circle cx={29} cy={13} r={2.4} fill="var(--gold)" />
    </svg>
  );
}

interface NavItem { to: string; label: string; icon: LucideIcon }

const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: "Operate",
    items: [
      { to: "/", label: "Overview", icon: LayoutDashboard },
      { to: "/designer", label: "Designer", icon: FileCode2 },
      { to: "/environments", label: "Environments", icon: Boxes },
      { to: "/runs", label: "Exercises", icon: Crosshair },
      { to: "/red", label: "Red Team", icon: Crosshair },
      { to: "/blue", label: "Blue Team", icon: Shield },
      { to: "/monitoring", label: "Monitoring", icon: Activity },
    ],
  },
  {
    label: "Library",
    items: [
      { to: "/personas", label: "Personas", icon: Users },
      { to: "/templates", label: "Templates", icon: Library },
      { to: "/traces", label: "Traces & Datasets", icon: Database },
      { to: "/learning", label: "Learning", icon: BrainCircuit },
    ],
  },
  {
    label: "Workspace",
    items: [
      { to: "/admin", label: "Admin", icon: ShieldAlert },
      { to: "/settings", label: "Settings", icon: Settings2 },
    ],
  },
];

const ALL_NAV = NAV_GROUPS.flatMap((g) => g.items);

function currentNav(pathname: string) {
  return [...ALL_NAV].sort((a, b) => b.to.length - a.to.length).find((item) => item.to === "/" ? pathname === "/" : pathname.startsWith(item.to)) ?? ALL_NAV[0];
}

function NavSearchDialog({ onClose }: { onClose: () => void }) {
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  useEffect(() => { inputRef.current?.focus(); }, []);

  const needle = query.trim().toLowerCase();
  const matches = needle ? ALL_NAV.filter((item) => item.label.toLowerCase().includes(needle)) : ALL_NAV;

  return (
    <div className="animate-fade-in fixed inset-0 z-50 flex items-start justify-center bg-overlay p-4 pt-[12vh] backdrop-blur-sm" onClick={onClose} role="presentation">
      <div role="dialog" aria-modal="true" aria-label="Search pages" onClick={(e) => e.stopPropagation()} className="animate-scale-in w-full max-w-lg overflow-hidden rounded-xl border border-line bg-panel shadow-pop">
        <div className="flex items-center gap-2 border-b border-line px-4">
          <Search size={16} className="text-faint" aria-hidden />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && matches[0]) { navigate(matches[0].to); onClose(); }
            }}
            placeholder="Go to a page…"
            aria-label="Go to a page"
            className="h-12 w-full bg-transparent text-sm text-paper outline-none placeholder:text-faint"
          />
          <kbd className="rounded border border-line px-1.5 py-0.5 font-mono text-[10px] text-faint">ESC</kbd>
        </div>
        <ul className="max-h-72 overflow-y-auto p-2">
          {matches.length ? matches.map((item) => {
            const Icon = item.icon;
            return (
              <li key={item.to}>
                <button onClick={() => { navigate(item.to); onClose(); }} className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm text-paper transition-colors hover:bg-panel2">
                  <Icon size={16} className="text-faint" aria-hidden />
                  {item.label}
                  <span className="ml-auto font-mono text-[10px] text-faint">{item.to === "/" ? "/" : item.to}</span>
                </button>
              </li>
            );
          }) : <li className="px-3 py-6 text-center text-sm text-muted">No pages match “{query}”.</li>}
        </ul>
      </div>
    </div>
  );
}

const THEME_OPTIONS: { value: ThemePreference; label: string; icon: typeof Sun }[] = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
  { value: "system", label: "System", icon: MonitorSmartphone },
];

function ThemeToggle() {
  const { preference, resolved, setPreference } = useTheme();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const ActiveIcon = resolved === "dark" ? Moon : Sun;

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onPointer); document.removeEventListener("keydown", onKey); };
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Theme: ${preference === "system" ? `system (${resolved})` : preference}`}
        title="Change theme"
        className="flex h-8 w-8 items-center justify-center rounded-md border border-line bg-panel text-muted shadow-sm hover:bg-panel2 hover:text-paper"
      >
        <ActiveIcon size={16} />
      </button>
      {open && (
        <div role="menu" aria-label="Theme" className="animate-scale-in absolute right-0 z-50 mt-2 w-44 rounded-xl border border-line bg-panel p-1.5 shadow-pop">
          {THEME_OPTIONS.map(({ value, label, icon: Icon }) => (
            <button
              key={value}
              role="menuitemradio"
              aria-checked={preference === value}
              onClick={() => { setPreference(value); setOpen(false); }}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm transition-colors ${preference === value ? "bg-panel2 font-medium text-paper" : "text-muted hover:bg-panel2 hover:text-paper"}`}
            >
              <Icon size={15} className="text-faint" />
              {label}
              {preference === value && <CheckCircle2 size={14} className="ml-auto text-cyber" />}
              {value === "system" && preference !== "system" && <span className="ml-auto font-mono text-[10px] text-faint">OS</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function Layout({ children }: { children: ReactNode }) {
  const loc = useLocation();
  const { session, signOut } = useSession();
  const active = currentNav(loc.pathname);
  const [collapsed, setCollapsed] = useState(() => {
    try { return localStorage.getItem("muse.sidebar") === "collapsed"; } catch { return false; }
  });
  const [searchOpen, setSearchOpen] = useState(false);

  useEffect(() => {
    try { localStorage.setItem("muse.sidebar", collapsed ? "collapsed" : "open"); } catch { /* storage may be unavailable */ }
  }, [collapsed]);

  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });
  }, [loc.pathname]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setSearchOpen(true); }
      if (event.key === "Escape") setSearchOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const navLink = (item: NavItem, mobile = false) => {
    const Icon = item.icon;
    const isActive = item.to === "/" ? loc.pathname === "/" : loc.pathname.startsWith(item.to);
    if (!mobile && collapsed) {
      return (
        <Link
          key={item.to}
          to={item.to}
          title={item.label}
          aria-label={item.label}
          aria-current={isActive ? "page" : undefined}
          className={`flex h-10 items-center justify-center rounded-lg transition-colors ${isActive ? "bg-control text-paper" : "text-faint hover:bg-raised hover:text-paper"}`}
        >
          <Icon size={18} />
        </Link>
      );
    }
    return (
      <Link
        key={item.to}
        to={item.to}
        aria-current={isActive ? "page" : undefined}
        className={`${mobile ? "shrink-0 rounded-full px-3 py-2" : "rounded-lg px-3 py-2"} flex items-center gap-2.5 text-sm transition-colors ${isActive ? "bg-control font-medium text-paper" : "text-muted hover:bg-raised hover:text-paper"}`}
      >
        <Icon size={17} className={isActive ? "text-paper" : "text-faint"} />
        <span>{item.label}</span>
        {isActive && !mobile && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-paper" aria-hidden="true" />}
      </Link>
    );
  };

  return (
    <div className={`min-h-dvh bg-ink text-paper transition-[padding] duration-200 ${collapsed ? "lg:pl-[76px]" : "lg:pl-[276px]"}`}>
      <aside className={`fixed inset-y-0 left-0 z-40 hidden flex-col border-r border-line bg-ink transition-[width] duration-200 lg:flex ${collapsed ? "w-[76px]" : "w-[276px]"}`} aria-label="Application sidebar">
        <div className={`flex items-center gap-3 border-b border-line py-4 ${collapsed ? "justify-center px-0" : "px-5"}`}>
          <BrandMark size={collapsed ? 36 : 38} />
          {!collapsed && (
            <div className="min-w-0">
              <p className="font-display text-[20px] font-semibold leading-none tracking-[-0.01em]">MuseArena</p>
              <p className="mt-1.5 text-[11px] font-medium text-faint">Adversarial ops</p>
            </div>
          )}
        </div>

        {!collapsed && (
          <div className="border-b border-line px-5 py-4">
            <p className="text-[11px] font-medium text-faint">Workspace</p>
            <p className="mt-1.5 truncate text-sm font-medium text-paper">{session?.orgName ?? "No workspace"}</p>
            <p className="truncate text-xs text-faint">{session?.email || "Clerk session required"}</p>
          </div>
        )}

        <nav className={`flex-1 overflow-y-auto py-4 ${collapsed ? "space-y-2 px-3" : "space-y-6 px-3"}`} aria-label="Primary">
          {NAV_GROUPS.map((group) => (
            <div key={group.label}>
              {!collapsed && <p className="px-3 pb-2 text-[11px] font-medium text-faint">{group.label}</p>}
              <div className="space-y-1">{group.items.map((item) => navLink(item))}</div>
            </div>
          ))}
        </nav>

        <div className={`border-t border-line ${collapsed ? "flex justify-center p-3" : "p-4"}`}>
          {collapsed ? (
            <button onClick={signOut} title="Sign out" aria-label="Sign out" className="flex h-9 w-9 items-center justify-center rounded-lg text-faint transition-colors hover:bg-panel2 hover:text-paper">
              <LogOut size={16} />
            </button>
          ) : clerkEnabled ? <ClerkControls /> : (
            <div className="text-xs leading-5 text-muted">
              {session ? <>{session.orgName} · {session.role}<br /><button onClick={signOut} className="font-medium text-paper underline underline-offset-4">Sign out</button></> : "Signed out"}
            </div>
          )}
        </div>
      </aside>

      <div className="min-w-0">
        <header className="sticky top-0 z-30 border-b border-line bg-panel/85 backdrop-blur-md">
          <div className="flex h-14 w-full items-center gap-3 px-4 sm:px-6 xl:px-8 2xl:px-10">
            <div className="flex items-center gap-3 lg:hidden">
              <BrandMark size={34} />
              <span className="font-display text-lg font-semibold">MuseArena</span>
            </div>
            <button
              onClick={() => setCollapsed((value) => !value)}
              className="hidden h-8 w-8 items-center justify-center rounded-md text-muted transition-colors hover:bg-panel2 hover:text-paper lg:flex"
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              {collapsed ? <PanelLeftOpen size={17} /> : <PanelLeftClose size={17} />}
            </button>
            <div className="hidden min-w-0 items-center gap-2 text-sm text-faint lg:flex">
              <span>MuseArena</span><span aria-hidden="true">/</span><span className="font-medium text-paper">{active.label}</span>
            </div>
            <button onClick={() => setSearchOpen(true)} className="ml-1 hidden items-center gap-2 rounded-lg border border-line bg-panel px-2.5 py-1.5 text-xs text-faint shadow-sm transition-colors hover:bg-panel2 hover:text-muted md:flex" aria-label="Search pages">
              <Search size={14} aria-hidden />
              <span>Search</span>
              <kbd className="ml-4 rounded border border-line bg-panel2 px-1.5 py-0.5 font-mono text-[10px]">⌘K</kbd>
            </button>
            <div className="ml-auto flex items-center gap-2">
              <ThemeToggle />
              <span className="hidden items-center gap-2 rounded-lg border border-line bg-panel px-3 py-1.5 text-xs font-medium text-muted md:inline-flex">
                <span className="h-1.5 w-1.5 rounded-full bg-mint" /> Operations console
              </span>
              {loc.pathname !== "/designer" && <Link to="/designer" className={`${primaryButton} px-3.5 py-2`}><FileCode2 size={16} /> New design</Link>}
            </div>
          </div>
          <nav className="flex gap-1 overflow-x-auto px-3 pb-3 lg:hidden" aria-label="Mobile primary">
            {ALL_NAV.map((item) => navLink(item, true))}
          </nav>
        </header>
        <main className="w-full px-4 py-6 sm:px-6 lg:py-8 xl:px-8 2xl:px-10"><div key={loc.pathname} className="animate-fade-in">{children}</div></main>
      </div>
      {searchOpen && <NavSearchDialog onClose={() => setSearchOpen(false)} />}
    </div>
  );
}

function Protected({ children }: { children: ReactNode }) {
  const { session } = useSession();
  if (!session) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function OverviewPage() {
  const deploymentsQuery = useQuery({ queryKey: ["deployments"], queryFn: api.deployments });
  const runsQuery = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const deployments: Deployment[] = deploymentsQuery.data ?? [];
  const runs: Run[] = runsQuery.data ?? [];
  const scored = runs.filter((r) => r.score);
  const activeStatuses = new Set(["pending", "provisioning", "configuring", "verifying", "destroying"]);
  const ready = deployments.filter((d) => d.status === "ready").length;
  const active = deployments.filter((d) => activeStatuses.has(d.status)).length;
  const exercising = deployments.filter((d) => d.status === "exercising").length;
  const failed = deployments.filter((d) => ["failed", "quarantined"].includes(d.status)).length;

  const analytic = average(scored.map((r) => r.score!.analyticCoverage));
  const visibility = average(scored.map((r) => r.score!.visibilityCoverage));
  const mttd = average(scored.flatMap((r) => r.score?.mttdMinutesP50 !== undefined ? [r.score.mttdMinutesP50] : []));
  const fp = average(scored.flatMap((r) => r.score?.falsePositiveRate !== undefined ? [r.score.falsePositiveRate] : []));
  const metrics = [
    { label: "Analytic coverage", value: percent(analytic), detail: "Target at least 70%", progress: analytic === null ? 0 : analytic * 100, meets: analytic !== null && analytic >= 0.7, tone: analytic !== null && analytic >= 0.7 ? "mint" as const : "gold" as const },
    { label: "Visibility coverage", value: percent(visibility), detail: "Target at least 90%", progress: visibility === null ? 0 : visibility * 100, meets: visibility !== null && visibility >= 0.9, tone: visibility !== null && visibility >= 0.9 ? "mint" as const : "gold" as const },
    { label: "Median detection time", value: mttd === null ? "—" : `${Math.round(mttd)} min`, detail: "Target 15 min or less", progress: mttd === null ? 0 : Math.min(100, (15 / Math.max(mttd, 0.1)) * 100), meets: mttd !== null && mttd <= 15, tone: mttd !== null && mttd <= 15 ? "mint" as const : "gold" as const },
    { label: "False-positive rate", value: percent(fp), detail: "Target 10% or less", progress: fp === null ? 0 : Math.min(100, (0.1 / Math.max(fp, 0.001)) * 100), meets: fp !== null && fp <= 0.1, tone: fp !== null && fp <= 0.1 ? "mint" as const : "gold" as const },
  ];

  const statusOrder = ["ready", "exercising", "pending", "provisioning", "configuring", "verifying", "failed", "quarantined", "destroying", "destroyed"];
  const distribution = statusOrder.map((status) => ({ status, count: deployments.filter((d) => d.status === status).length })).filter((x) => x.count > 0);

  return (
    <div>
      <PageHeader
        title="Operations overview"
        description="Current environment fleet, exercise quality, and the next operational action across the workspace."
        actions={<Link to="/designer" className={primaryButton}><FileCode2 size={16} /> Design environment</Link>}
        meta={<><Badge tone="mint">Live workspace data</Badge><Badge>{deployments.length} environments</Badge><Badge>{scored.length} scored exercises</Badge></>}
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Environments" value={String(deployments.length)} detail={`${ready} ready · ${exercising} exercising`} tone="cyber" />
        <StatCard label="Active pipelines" value={String(active)} detail="Pending, building, verifying, or tearing down" tone={active ? "gold" : "dim"} />
        <StatCard label="Needs attention" value={String(failed)} detail="Failed or quarantined deployments" tone={failed ? "danger" : "mint"} />
        <StatCard label="Exercise evidence" value={String(scored.length)} detail={`${runs.length} total runs recorded`} tone="signal" />
      </div>

      {(deploymentsQuery.error || runsQuery.error) && (
        <div className="mt-4 grid gap-3 lg:grid-cols-2">
          {deploymentsQuery.error && <ErrorState title="Environments could not be loaded" error={deploymentsQuery.error} />}
          {runsQuery.error && <ErrorState title="Exercise results could not be loaded" error={runsQuery.error} />}
        </div>
      )}

      <div className="mt-4 grid gap-4 xl:grid-cols-12">
        <Panel className="xl:col-span-7">
          <PanelHeader title="Exercise quality" description={scored.length ? `Averages across ${scored.length} scored run${scored.length === 1 ? "" : "s"}.` : "Targets appear here after the first scored exercise."} />
          {runsQuery.isLoading ? <div className="p-4"><LoadingState what="exercise scores" rows={4} /></div> : scored.length === 0 ? (
            <div className="p-4"><EmptyState title="No scored exercises yet" action={<Link to="/runs" className={secondaryButton}>Open exercises <ArrowRight size={15} /></Link>}>Scores will populate this view after a completed run is written back to the workspace.</EmptyState></div>
          ) : (
            <div className="divide-y divide-line">
              {metrics.map((m) => (
                <div key={m.label} className="grid gap-3 px-4 py-4 sm:grid-cols-[1fr_110px_150px] sm:items-center sm:px-5">
                  <div><p className="text-sm font-medium text-paper">{m.label}</p><p className="mt-0.5 text-xs text-faint">{m.detail}</p></div>
                  <p className="font-display text-[27px] font-semibold leading-none text-paper">{m.value}</p>
                  <div><Progress value={m.progress} tone={m.tone} /><p className={`mt-2 text-[11px] font-medium ${m.meets ? "text-mint" : "text-gold"}`}>{m.meets ? "Within target" : "Below target"}</p></div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel className="xl:col-span-5">
          <PanelHeader title="Deployment pipeline" description="Current distribution by lifecycle state." />
          {deploymentsQuery.isLoading ? <div className="p-4"><LoadingState what="deployment states" /></div> : distribution.length === 0 ? (
            <div className="p-4"><EmptyState title="Pipeline is empty">Create a design to start the first deployment record.</EmptyState></div>
          ) : (
            <div className="space-y-4 p-4 sm:p-5">
              {distribution.map(({ status, count }) => (
                <div key={status} className="grid grid-cols-[118px_1fr_28px] items-center gap-3">
                  <Status value={status} />
                  <Progress value={(count / Math.max(1, deployments.length)) * 100} tone={status === "ready" ? "mint" : status === "failed" || status === "quarantined" ? "danger" : status === "exercising" ? "signal" : "gold"} />
                  <span className="text-right font-mono text-sm text-paper">{count}</span>
                </div>
              ))}
              <div className="border-t border-line pt-4 text-sm leading-6 text-muted">
                {failed ? `${failed} deployment${failed === 1 ? "" : "s"} need review before the next exercise.` : ready ? `${ready} environment${ready === 1 ? " is" : "s are"} ready for an exercise.` : "No environment is ready yet."}
              </div>
            </div>
          )}
        </Panel>
      </div>

      <Panel className="mt-4 overflow-hidden">
        <PanelHeader title="Environment fleet" description="Most recent deployment records in this workspace." action={<Link to="/environments" className={compactButton}>View all <ArrowRight size={14} /></Link>} />
        {deploymentsQuery.isLoading ? <div className="p-4"><LoadingState what="environments" rows={4} /></div> : deployments.length === 0 ? (
          <div className="p-4"><EmptyState title="No environments yet" action={<Link to="/designer" className={primaryButton}><FileCode2 size={16} /> Design the first environment</Link>}>Designs you approve will appear here with lifecycle, drift, stack, and cost state.</EmptyState></div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-left text-sm">
              <thead className="bg-track text-xs font-medium text-muted">
                <tr><th className="px-5 py-3 font-medium">Environment</th><th className="px-4 py-3 font-medium">Status</th><th className="px-4 py-3 font-medium">Stack</th><th className="px-4 py-3 font-medium">Drift</th><th className="px-4 py-3 font-medium">Created</th><th className="px-4 py-3 text-right font-medium">Cost</th><th className="w-12 px-4 py-3" /></tr>
              </thead>
              <tbody className="divide-y divide-line">
                {deployments.slice(0, 8).map((d) => (
                  <tr key={d.id} className="hover:bg-track">
                    <td className="px-5 py-3.5"><Link to={`/environments/${d.id}`} className="font-mono text-[13px] font-medium text-paper hover:text-signal" title={d.id}>{shortId(d.id, 18)}</Link><p className="mt-0.5 font-mono text-[10px] text-faint">{shortId(d.specDigest, 24)}</p></td>
                    <td className="px-4 py-3.5"><Status value={d.status} /></td>
                    <td className="px-4 py-3.5 font-mono text-xs text-muted">{d.stackId || "—"}</td>
                    <td className="px-4 py-3.5 text-muted">{d.driftStatus ? prettify(d.driftStatus) : "Unknown"}</td>
                    <td className="px-4 py-3.5 text-muted">{formatDate(d.createdAt)}</td>
                    <td className="px-4 py-3.5 text-right font-mono text-paper">{d.costEstimatePerHour ? `$${d.costEstimatePerHour}/hr` : "—"}</td>
                    <td className="px-4 py-3.5 text-right"><Link to={`/environments/${d.id}`} aria-label={`Open environment ${d.id}`} className="inline-flex rounded-md border border-line p-1.5 text-muted hover:border-linestrong hover:text-paper"><ArrowRight size={15} /></Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

function groupsForPackage(pkg: DesignPackage): TopologyGroupInput[] {
  const byHost = new Map(pkg.spec.instances.map((i) => [i.hostId, i]));
  return pkg.topology.subnets.map((subnet) => ({
    id: subnet.name,
    name: subnet.name,
    cidr: subnet.cidr,
    zone: subnet.zone,
    instances: subnet.nodes.flatMap((node) => byHost.get(node.hostId) ? [byHost.get(node.hostId)!] : []),
  }));
}

function groupsForSpec(spec: EnvironmentSpec): TopologyGroupInput[] {
  const groups = new Map<string, TopologyGroupInput>();
  for (const subnet of spec.topology.subnets) {
    groups.set(subnet.name, { id: subnet.name, name: subnet.name, cidr: subnet.cidr, zone: subnet.zone, instances: [] });
  }
  if (groups.size === 0) groups.set("default", { id: "default", name: "Lab segment", cidr: spec.topology.cidr, zone: "default", instances: [] });

  spec.instances.forEach((instance, index) => {
    const fallback = spec.topology.subnets[index % Math.max(1, spec.topology.subnets.length)]?.name ?? "default";
    const name = instance.subnet ?? fallback;
    if (!groups.has(name)) groups.set(name, { id: name, name, cidr: spec.topology.cidr, zone: instance.zone ?? "declared", instances: [] });
    groups.get(name)!.instances.push(instance);
  });
  return [...groups.values()];
}

function dependencyFlows(spec: EnvironmentSpec): TopologyFlowInput[] {
  return spec.instances.flatMap((instance) => (instance.dependsOn ?? []).map((to) => ({
    from: instance.hostId,
    to,
    label: "depends on",
    kind: "dependency" as const,
  })));
}

function TopologyView({ pkg }: { pkg: DesignPackage }) {
  const flows: TopologyFlowInput[] = pkg.plan.edges.map((edge) => ({
    from: edge.from,
    to: edge.to,
    label: `${edge.protocol}/${edge.port}`,
    detail: edge.purpose,
    kind: "service",
  }));

  return (
    <div className="space-y-4">
      <Panel className="animate-fade-up overflow-hidden">
        <PanelHeader
          title="Network topology"
          description="Hosts, network segments, declared service flows, planted weaknesses, and objective assets."
          action={<Badge tone="cyber"><Network size={12} /> Static graph</Badge>}
        />
        <div className="p-4 sm:p-5">
          <TopologyGraph spec={pkg.spec} groups={groupsForPackage(pkg)} flows={flows} addresses={pkg.plan.topology.addresses} domain={pkg.topology.domain} />
        </div>
      </Panel>

      <div className="grid animate-fade-up gap-4 delay-2 xl:grid-cols-2">
        <Panel className="overflow-hidden">
          <PanelHeader title="Declared flows" description="Edges realized by the deployment plan." />
          {flows.length === 0 ? <div className="p-4"><EmptyState title="No declared flows">This design has no service dependency edges.</EmptyState></div> : (
            <div className="grid gap-3 p-4 sm:grid-cols-2 sm:p-5">
              {pkg.plan.edges.map((edge, i) => (
                <div key={`${edge.from}-${edge.to}-${edge.protocol}-${i}`} className="rounded-lg border border-line bg-panel p-3.5 shadow-sm transition-colors hover:border-linestrong">
                  <div className="flex items-center justify-between gap-2">
                    <Badge tone="cyber">{edge.protocol}/{edge.port}</Badge>
                    {edge.address && <span className="truncate font-mono text-[11px] text-faint">{edge.address}</span>}
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
                    <span className="font-mono font-medium text-paper">{edge.from}</span>
                    <ArrowRight size={14} className="shrink-0 text-faint" aria-hidden />
                    <span className="font-mono font-medium text-paper">{edge.to}</span>
                  </div>
                  <p className="mt-2 break-words text-sm leading-5 text-muted">{edge.purpose}</p>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel>
          <PanelHeader title="Adversary design" description="Weaknesses and measurable objectives attached to real hosts." />
          <div className="divide-y divide-line">
            <div className="p-4 sm:p-5">
              <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-paper"><ShieldAlert size={16} className="text-danger" /> Planted weaknesses</h3>
              {pkg.spec.plantedVulns.length === 0 ? <p className="text-sm text-muted">No planted weaknesses in this design.</p> : (
                <div className="space-y-2">
                  {pkg.spec.plantedVulns.map((v) => (
                    <div key={v.id} className="flex flex-wrap items-center gap-2 rounded-md border border-line bg-track px-3 py-2.5 text-sm">
                      <span className="font-mono text-xs text-paper">{v.id}</span><span className="text-faint">→</span><span className="font-mono text-xs text-paper">{v.targetHostId}</span>
                      <Badge tone="danger">{v.type}</Badge><Badge>{v.techniqueId}</Badge><span className="ml-auto font-mono text-[10px] text-faint">proof {shortId(v.proofAtomicGuid, 16)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="p-4 sm:p-5">
              <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-paper"><Crosshair size={16} className="text-gold" /> Objectives</h3>
              <div className="space-y-2">
                {pkg.spec.objectives.map((o) => (
                  <div key={o.id} className="flex flex-wrap items-center gap-2 rounded-md border border-line bg-track px-3 py-2.5 text-sm">
                    <span className="font-mono text-xs text-paper">{o.id}</span><span className="text-faint">→</span><span className="font-mono text-xs text-paper">{o.asset}</span>
                    <Badge tone="gold">{o.techniqueId}</Badge><span className="text-muted">{o.successSignal}</span><span className="ml-auto font-mono text-xs text-paper">{o.points} pts</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Panel>
      </div>

      {pkg.spec.topology.firewallRules.length > 0 && (
        <Panel className="animate-fade-up delay-3">
          <PanelHeader title="Declared firewall rules" description="Design intent carried in the specification." />
          <div className="flex flex-wrap gap-2 p-4 sm:p-5">{pkg.spec.topology.firewallRules.map((rule) => <span key={rule} className="rounded-md border border-line bg-track px-2.5 py-1.5 font-mono text-xs text-muted">{rule}</span>)}</div>
        </Panel>
      )}
    </div>
  );
}

function ChipList({ values, empty = "None" }: { values: string[]; empty?: string }) {
  if (values.length === 0) return <p className="text-sm text-faint">{empty}</p>;
  return <div className="flex flex-wrap gap-1.5">{values.map((value) => <span key={value} className="rounded border border-line bg-track px-2 py-1 font-mono text-[11px] text-muted">{value}</span>)}</div>;
}

function PlanView({ pkg }: { pkg: DesignPackage }) {
  const { plan } = pkg;
  const packageCount = new Set(plan.hosts.flatMap((h) => h.packages)).size;
  const phases = plan.steps.reduce<{ phase: string; count: number; hosts: Set<string> }[]>((acc, step) => {
    const found = acc.find((p) => p.phase === step.phase);
    if (found) { found.count += 1; found.hosts.add(step.hostId); }
    else acc.push({ phase: step.phase, count: 1, hosts: new Set([step.hostId]) });
    return acc;
  }, []);

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <StatCard label="Hosts" value={String(plan.totals.instances)} detail={`${plan.totals.vcpu} vCPU · ${plan.totals.memoryMb} MB`} tone="cyber" />
        <StatCard label="Packages" value={String(packageCount)} detail="Unique packages across all hosts" tone="dim" />
        <StatCard label="Service edges" value={String(plan.edges.length)} detail={`${plan.labProbes.length} cross-host acceptance probes`} tone="mint" />
        <StatCard label="Execution steps" value={String(plan.steps.length)} detail={`${phases.length} ordered phases`} tone="gold" />
        <StatCard label="Plan estimate" value={`$${plan.totals.dollarsPerHour}/hr`} detail={`${plan.totals.diskGb} GB aggregate disk`} tone="signal" />
      </div>

      {plan.gaps.length > 0 && (
        <div role="alert" className="rounded-lg border border-dangerline bg-dangersurface p-4">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-dangertext"><XCircle size={16} /> Plan gaps</h2>
          <ul className="mt-2 space-y-1 font-mono text-xs leading-5 text-dangertext">{plan.gaps.map((gap) => <li key={gap}>{gap}</li>)}</ul>
        </div>
      )}

      <Panel>
        <PanelHeader title="Execution sequence" description={`Catalog ${plan.versions.catalog} · profile ${plan.versions.profile} · image ${plan.versions.image}`} />
        <div className="grid gap-px overflow-hidden rounded-b-lg bg-line md:grid-cols-2 xl:grid-cols-4">
          {phases.map((phase, index) => (
            <div key={phase.phase} className="bg-panel p-4">
              <div className="flex items-center gap-3">
                <span className="flex h-8 w-8 items-center justify-center rounded-md border border-line bg-panel2 font-mono text-xs font-semibold text-muted">{String(index + 1).padStart(2, "0")}</span>
                <div><p className="text-sm font-semibold capitalize text-paper">{prettify(phase.phase)}</p><p className="text-xs text-faint">{phase.count} steps · {phase.hosts.size} hosts</p></div>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel className="overflow-hidden">
        <PanelHeader title="Host build sheets" description="Packages, configuration, seeds, readiness, and task order for each machine." />
        <div className="divide-y divide-line">
          {plan.hosts.map((host) => (
            <details key={host.hostId} className="group">
              <summary className="flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-3.5 hover:bg-track sm:px-5">
                <Server size={17} className="text-cyber" />
                <span className="font-mono text-sm font-medium text-paper">{host.hostId}</span>
                <span className="text-sm text-muted">{host.role} · {host.runtime} · {host.os}</span>
                <Badge>{host.address ?? host.subnet ?? "unaddressed"}</Badge>
                <span className="ml-auto flex items-center gap-3 font-mono text-[11px] text-faint">
                  <span>{host.resources.vcpu} vCPU / {host.resources.memoryMb} MB / {host.resources.diskGb} GB</span>
                  <ChevronDown size={16} className="group-open:rotate-180" />
                </span>
              </summary>
              <div className="grid gap-x-6 gap-y-5 border-t border-line bg-track px-4 py-4 sm:px-5 lg:grid-cols-2">
                <div><h3 className="mb-2 text-xs font-semibold text-muted">Packages</h3><ChipList values={host.packages} /></div>
                <div><h3 className="mb-2 text-xs font-semibold text-muted">System units & client tools</h3><ChipList values={[...host.units, ...host.clientTools]} /></div>
                <div><h3 className="mb-2 text-xs font-semibold text-muted">Configuration</h3><div className="space-y-2">{host.config.length ? host.config.map((c) => <p key={c.path} className="text-sm text-muted"><span className="font-mono text-xs text-paper">{c.path}</span><br />{c.purpose}</p>) : <p className="text-sm text-faint">No host-specific configuration.</p>}</div></div>
                <div><h3 className="mb-2 text-xs font-semibold text-muted">Seeds & readiness</h3><div className="space-y-2">{host.seeds.map((s) => <p key={s.target} className="text-sm text-muted"><span className="font-mono text-xs text-paper">{s.target}</span> — {s.purpose}</p>)}{host.readiness.map((p, i) => <p key={`${p.probe}-${i}`} className="text-sm text-muted"><span className="font-mono text-xs text-mint">{p.probe}</span> · {p.kind}{p.expect ? ` → ${p.expect}` : ""}</p>)}</div></div>
                <div className="lg:col-span-2"><h3 className="mb-2 text-xs font-semibold text-muted">Task sequence</h3><div className="flex flex-wrap items-center gap-1.5">{host.tasks.map((task, i) => <span key={`${task}-${i}`} className="flex items-center gap-1.5"><span className="rounded border border-line bg-panel px-2 py-1 font-mono text-[11px] text-muted">{task}</span>{i < host.tasks.length - 1 && <ArrowRight size={12} className="text-faint" />}</span>)}</div></div>
              </div>
            </details>
          ))}
        </div>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel className="overflow-hidden">
          <PanelHeader title="Service wiring" description="Dependencies the configurator will realize." />
          {plan.edges.length === 0 ? <div className="p-4"><EmptyState title="No service wiring">No declared service dependencies in this plan.</EmptyState></div> : (
            <div className="divide-y divide-line">{plan.edges.map((edge, i) => <div key={`${edge.from}-${edge.to}-${i}`} className="flex flex-wrap items-center gap-2 px-4 py-3 text-sm sm:px-5"><span className="font-mono text-xs text-paper">{edge.from}</span><ArrowRight size={14} className="text-cyber" /><span className="font-mono text-xs text-paper">{edge.to}</span><Badge tone="cyber">{edge.protocol}/{edge.port}</Badge><span className="text-muted">{edge.purpose}</span></div>)}</div>
          )}
        </Panel>
        <Panel className="overflow-hidden">
          <PanelHeader title="Cross-host acceptance" description="Proofs required before the environment is considered ready." />
          {plan.labProbes.length === 0 ? <div className="p-4"><EmptyState title="No cross-host probes">This design has no plan-level cross-host proof.</EmptyState></div> : (
            <div className="divide-y divide-line">{plan.labProbes.map((probe, i) => <div key={`${probe.probe}-${i}`} className="flex flex-wrap items-center gap-2 px-4 py-3 text-sm sm:px-5"><CheckCircle2 size={16} className="text-mint" /><span className="font-mono text-xs text-paper">{probe.from} → {probe.to}</span><span className="text-muted">{probe.probe}{probe.expect ? ` → ${probe.expect}` : ""}</span></div>)}</div>
          )}
        </Panel>
      </div>
    </div>
  );
}

interface ChatMsg { role: "user" | "assistant"; text: string }

type DesignerRunStatus = "running" | "completed" | "blocked" | "failed" | "cancelled";

interface DesignerRunResult {
  canProvision: boolean;
  blockReasons: string[];
  specDigest: string;
  detail?: string;
}

type ChatItem =
  | { id: string; kind: "message"; role: "user" | "assistant"; text: string }
  | { id: string; kind: "run"; operation: string; status: DesignerRunStatus; events: DesignerRunEvent[]; result?: DesignerRunResult };

function newChatId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
}

function BudgetField({ label, value, min, step = 1, suffix, onChange }: {
  label: string;
  value: number;
  min: number;
  step?: number;
  suffix: string;
  onChange: (value: number) => void;
}) {
  return (
    <label className="block">
      <span className="mb-1.5 flex items-center justify-between text-[11px] font-medium text-muted">{label}<span className="font-mono text-[10px] text-faint">{suffix}</span></span>
      <input type="number" min={min} step={step} value={value} onChange={(e) => onChange(Number(e.target.value))} className="ops-input px-2.5 py-2 font-mono text-sm" />
    </label>
  );
}

function DesignSummary({ pkg }: { pkg: DesignPackage }) {
  const items = [
    { icon: Server, label: "Hosts", value: String(pkg.spec.instances.length), tone: "cyber" as const },
    { icon: Users, label: "Personas", value: String(pkg.spec.personas.length), tone: "dim" as const },
    { icon: Crosshair, label: "Objectives", value: String(pkg.spec.objectives.length), tone: "gold" as const },
    { icon: ShieldAlert, label: "Weaknesses", value: String(pkg.spec.plantedVulns.length), tone: "danger" as const },
    { icon: Network, label: "Segments", value: String(pkg.topology.subnets.length), tone: "dim" as const },
    { icon: Clock3, label: "Estimate", value: `$${pkg.cost.perHour}/hr`, tone: "mint" as const },
  ];
  return (
    <div className="flex flex-wrap gap-2" aria-label="Design summary">
      {items.map(({ icon: Icon, label, value, tone }, index) => (
        <span
          key={label}
          className="animate-fade-up inline-flex items-center gap-1.5 rounded-lg border border-line bg-panel2 px-2.5 py-1 text-xs text-muted"
          style={{ animationDelay: `${120 + index * 60}ms` }}
        >
          <Icon size={13} className={tone === "cyber" ? "text-cyber" : tone === "gold" ? "text-gold" : tone === "danger" ? "text-danger" : tone === "mint" ? "text-mint" : "text-faint"} />
          <strong className="font-semibold text-paper">{value}</strong> {label.toLowerCase()}
        </span>
      ))}
    </div>
  );
}

function CostView({ pkg, budget }: { pkg: DesignPackage; budget: Budget }) {
  const rows = [
    { label: "Instances", actual: `${pkg.spec.instances.length}`, cap: `${budget.maxInstances}`, value: (pkg.spec.instances.length / Math.max(1, budget.maxInstances)) * 100 },
    { label: "Estimated hourly cost", actual: `$${pkg.cost.perHour}/hr`, cap: `$${budget.maxDollarsPerHour}/hr`, value: (pkg.cost.perHour / Math.max(0.01, budget.maxDollarsPerHour)) * 100 },
    { label: "Time to live", actual: `${pkg.spec.budgets.ttlHours}h`, cap: `${budget.ttlHours}h`, value: (pkg.spec.budgets.ttlHours / Math.max(1, budget.ttlHours)) * 100 },
  ];
  return (
    <Panel>
      <PanelHeader title="Cost & budget" description="Platform estimate against the constraints used for this design." />
      <div className="grid gap-px bg-line sm:grid-cols-3">
        <div className="bg-panel p-5"><p className="text-xs text-muted">Hourly estimate</p><p className="mt-2 font-display text-4xl font-semibold text-paper">${pkg.cost.perHour}<span className="text-base text-faint">/hr</span></p></div>
        <div className="bg-panel p-5"><p className="text-xs text-muted">TTL exposure</p><p className="mt-2 font-display text-4xl font-semibold text-paper">${pkg.cost.ttlTotal}</p><p className="mt-1 text-xs text-faint">Over {pkg.spec.budgets.ttlHours} hours</p></div>
        <div className="bg-panel p-5"><p className="text-xs text-muted">Budget state</p><div className="mt-3">{pkg.withinBudget ? <Badge tone="mint">Within budget</Badge> : <Badge tone="danger">Budget violation</Badge>}</div><p className="mt-2 text-xs text-faint">{pkg.violations.length ? pkg.violations.join(" · ") : "All declared caps pass."}</p></div>
      </div>
      <div className="space-y-5 p-5">
        {rows.map((row) => (
          <div key={row.label}>
            <div className="mb-2 flex flex-wrap items-baseline gap-2 text-sm"><span className="font-medium text-paper">{row.label}</span><span className="ml-auto font-mono text-xs text-muted">{row.actual} <span className="text-faint">/ cap {row.cap}</span></span></div>
            <Progress value={row.value} tone={row.value > 100 ? "danger" : row.value > 85 ? "gold" : "mint"} />
          </div>
        ))}
      </div>
    </Panel>
  );
}

type RunStepStatus = "running" | "done" | "failed" | "blocked";

interface RunStep {
  id: string;
  phase: string;
  title: string;
  detail?: string;
  status: RunStepStatus;
  startedAt?: number;
  endedAt?: number;
  reasoning: string;
  output: string;
  reasoningChars: number;
  contentChars: number;
  data: Record<string, unknown>;
}

/** Fold the streamed lifecycle into ordered, per-step state for rendering. */
function foldRunEvents(events: DesignerRunEvent[]): RunStep[] {
  const steps = new Map<string, RunStep>();
  const order: string[] = [];
  for (const event of events) {
    if (event.type === "run.started" || event.type === "run.completed" || event.type === "run.failed" || event.type === "run.cancelled") continue;
    let step = steps.get(event.stepId);
    if (!step) {
      step = { id: event.stepId, phase: event.phase, title: event.title, status: "running", reasoning: "", output: "", reasoningChars: 0, contentChars: 0, data: {} };
      steps.set(event.stepId, step);
      order.push(event.stepId);
    }
    step.phase = event.phase;
    if (event.data) {
      const { text: _streamText, package: _pkg, ...rest } = event.data;
      step.data = { ...step.data, ...rest };
      if (typeof event.data.reasoningChars === "number") step.reasoningChars = event.data.reasoningChars;
      if (typeof event.data.contentChars === "number") step.contentChars = event.data.contentChars;
    }
    const at = Date.parse(event.at);
    switch (event.type) {
      case "step.started":
        step.status = "running";
        step.title = event.title;
        step.detail = event.detail;
        step.startedAt = Number.isFinite(at) ? at : Date.now();
        break;
      case "step.completed":
      case "step.failed":
      case "step.blocked":
        step.status = event.type === "step.completed" ? "done" : event.type === "step.failed" ? "failed" : "blocked";
        step.title = event.title;
        step.detail = event.detail;
        step.endedAt = Number.isFinite(at) ? at : Date.now();
        break;
      case "model.reasoning":
        step.reasoning += String(event.data?.text ?? "");
        break;
      case "model.progress":
        step.output += String(event.data?.text ?? "");
        break;
      case "artifact.ready":
        step.status = "done";
        step.title = event.title;
        step.detail = event.detail;
        step.endedAt = Number.isFinite(at) ? at : Date.now();
        break;
    }
  }
  return order.map((id) => steps.get(id)!);
}

function tail(text: string, max = 4000): string {
  return text.length > max ? `…${text.slice(-max)}` : text;
}

const STEP_LIST_KEYS: Record<string, string> = {
  violations: "Budget violations",
  designErrors: "Design errors",
  blockReasons: "Blocking reasons",
  issues: "Issues sent for repair",
  normalizedRoles: "Roles canonicalized",
  gaps: "Plan gaps",
  deployabilityReasons: "Deployability blocks",
};

const STEP_SCALAR_LABELS: Record<string, string> = {
  attempt: "attempt", modelId: "model", maxTokens: "max tokens",
  hosts: "hosts", personas: "personas", objectives: "objectives",
  weaknesses: "weaknesses", subnets: "segments", edges: "flows",
  probes: "probes", steps: "steps", perHour: "$/hr", ttlTotal: "TTL $",
  systemChars: "context chars", schemaChars: "schema chars",
  requestChars: "request chars", instructionChars: "instruction chars",
  domain: "domain", cidr: "CIDR",
};

/** Scalar gate data + issue lists as trace detail lines. */
function stepDetailLines(step: RunStep): DetailLine[] {
  const lines: DetailLine[] = [];
  for (const [key, label] of Object.entries(STEP_SCALAR_LABELS)) {
    const value = step.data[key];
    if (typeof value === "string" || typeof value === "number") lines.push({ text: `${label}: ${value}`, tone: "muted" });
  }
  for (const [key, label] of Object.entries(STEP_LIST_KEYS)) {
    const values = Array.isArray(step.data[key]) ? (step.data[key] as unknown[]).map(String) : [];
    if (!values.length) continue;
    lines.push({ text: `${label}:`, tone: key === "normalizedRoles" ? "ctx" : "error" });
    for (const value of values) lines.push({ text: value, tone: key === "normalizedRoles" ? "ctx" : "error" });
  }
  return lines;
}

/** Split streamed reasoning into sentence/paragraph units for the thought chip. */
function splitSentences(text: string): string[] {
  return text
    .split(/\n+/)
    .map((p) => p.trim())
    .filter(Boolean)
    .flatMap((p) => p.match(/[^.!?]+[.!?]+["')\]]*\s*/g)?.map((s) => s.trim()).filter(Boolean) ?? [p]);
}

function phaseIcon(phase: string): ReactNode {
  const cls = "h-3.5 w-3.5";
  switch (phase) {
    case "context": return <Search className={cls} />;
    case "model": return <BrainCircuit className={cls} />;
    case "repair": return <ShieldAlert className={cls} />;
    case "validation": return <Shield className={cls} />;
    case "packaging": return <Boxes className={cls} />;
    case "artifact": return <CheckCircle2 className={cls} />;
    default: return <FileCode2 className={cls} />;
  }
}

/** Fold designer run steps into ThinkingState trace nodes (thought + tool chips). */
function traceNodesForRun(steps: RunStep[]): TraceNode[] {
  const nodes: TraceNode[] = [];
  for (const step of steps) {
    const status: TraceNode["status"] = step.status === "running" ? "running"
      : step.status === "done" ? "completed" : "failed";
    if (step.reasoning) {
      nodes.push({
        id: `${step.id}-thought`,
        type: "reasoning",
        sentences: splitSentences(step.reasoning),
        status,
        durationSeconds: step.startedAt ? Math.max(0, ((step.endedAt ?? Date.now()) - step.startedAt) / 1000) : undefined,
      });
    }
    nodes.push({
      id: step.id,
      type: "tool",
      primary: step.title,
      secondary: step.detail,
      icon: phaseIcon(step.phase),
      status,
      durationMs: step.startedAt ? Math.max(0, (step.endedAt ?? Date.now()) - step.startedAt) : undefined,
      details: stepDetailLines(step),
      codeSnippet: step.output ? tail(step.output, 6000) : undefined,
    });
  }
  return nodes;
}

const BUILD_PHASES: { label: string; match: (step: RunStep) => boolean }[] = [
  { label: "Context", match: (s) => s.phase === "context" },
  { label: "Model", match: (s) => s.phase === "model" || s.phase === "repair" },
  { label: "Normalize", match: (s) => s.phase === "normalize" },
  { label: "Design gates", match: (s) => s.phase === "validation" },
  { label: "Package", match: (s) => s.phase === "packaging" },
];

/** Right-canvas live state while a run is streaming and no artifact exists yet. */
function DesignBuildingPane({ steps }: { steps: RunStep[] }) {
  const output = steps.map((s) => s.output).join("");
  const reasoning = steps.map((s) => s.reasoning).join("");
  const streamText = output || reasoning;
  const streamRef = useRef<HTMLPreElement>(null);
  useEffect(() => {
    if (streamRef.current) streamRef.current.scrollTop = streamRef.current.scrollHeight;
  }, [streamText]);

  return (
    <div className="min-h-0 flex-1 overflow-y-auto p-5 sm:p-7">
      <div className="mx-auto max-w-4xl">
        <p className="font-mono text-[11px] font-medium uppercase tracking-[0.12em] text-cyber">Live build</p>
        <h2 className="mt-2 font-display text-[30px] font-semibold leading-tight text-paper">Building your environment</h2>
        <p className="mt-2 max-w-xl text-sm leading-6 text-muted">
          The designer is streaming its thinking and structured output on the left. This canvas becomes the reviewable design as soon as every gate has run.
        </p>

        <ol className="mt-7">
          {BUILD_PHASES.map((phase, i) => {
            const relevant = steps.filter(phase.match);
            const status = relevant.some((s) => s.status === "failed") ? "failed"
              : relevant.some((s) => s.status === "blocked") ? "blocked"
              : relevant.some((s) => s.status === "running") ? "running"
              : relevant.length ? "done" : "pending";
            const detail = [...relevant].reverse().find((s) => s.detail)?.detail;
            return (
              <li key={phase.label} className="relative flex gap-3.5 pb-5 last:pb-0">
                {i < BUILD_PHASES.length - 1 && <span className="absolute left-[13px] top-8 h-[calc(100%-24px)] w-px bg-line" aria-hidden />}
                <span className={`z-[1] flex h-7 w-7 shrink-0 items-center justify-center rounded-full border ${status === "done" ? "border-mintline bg-mintsurface text-minttext" : status === "running" ? "border-cyberline bg-cybersurface text-cybertext" : status === "pending" ? "border-line bg-panel2 text-faint" : "border-dangerline bg-dangersurface text-dangertext"}`}>
                  {status === "done" ? <CheckCircle2 size={15} /> : status === "failed" || status === "blocked" ? <XCircle size={15} /> : <CircleDot size={15} />}
                </span>
                <div className="min-w-0 pt-0.5">
                  <p className={`text-sm font-medium ${status === "pending" ? "text-faint" : "text-paper"}`}>{phase.label}</p>
                  {detail && <p className="mt-0.5 break-words text-xs leading-5 text-muted">{detail}</p>}
                </div>
                <span className="ml-auto pt-1 font-mono text-[10px] uppercase tracking-[0.08em] text-faint">{status}</span>
              </li>
            );
          })}
        </ol>

        <div className="mt-7 overflow-hidden rounded-xl bg-terminal shadow-sm">
          <div className="flex items-center gap-2 border-b border-linestrong px-4 py-2.5">
            <Braces size={14} className="text-faint" />
            <span className="font-mono text-[11px] text-muted">{output ? "Structured output" : "Model stream"}</span>
            <span className="ml-auto font-mono text-[10px] tabular-nums text-faint">{streamText.length.toLocaleString()} chars</span>
          </div>
          <pre ref={streamRef} className="max-h-[360px] min-h-36 overflow-auto whitespace-pre-wrap break-words p-4 font-mono text-[11px] leading-5 text-muted">
            {streamText ? tail(streamText, 12000) : "Waiting for the first model output…"}
          </pre>
        </div>
      </div>
    </div>
  );
}

function DesignerRunTimeline({ run, isCurrentArtifact, onViewArtifact }: {
  run: Extract<ChatItem, { kind: "run" }>;
  isCurrentArtifact: boolean;
  onViewArtifact: () => void;
}) {
  const steps = useMemo(() => foldRunEvents(run.events), [run.events]);
  const done = steps.filter((s) => s.status === "done").length;
  const started = run.events.find((e) => e.type === "run.started");
  const modelId = typeof started?.data?.modelId === "string" ? started.data.modelId : undefined;
  const firstAt = run.events.length ? Date.parse(run.events[0].at) : NaN;
  const lastAt = run.events.length ? Date.parse(run.events[run.events.length - 1].at) : NaN;
  const elapsed = Number.isFinite(firstAt) && Number.isFinite(lastAt) && lastAt >= firstAt
    ? `${((lastAt - firstAt) / 1000).toFixed(lastAt - firstAt < 10_000 ? 1 : 0)}s`
    : "";
  const statusText = run.status === "running" ? "Running"
    : run.status === "completed" ? "Completed"
    : run.status === "blocked" ? "Blocked"
    : run.status === "cancelled" ? "Cancelled" : "Failed";
  const operationLabel = run.operation === "refine" ? "Refinement" : run.operation === "validate" ? "Import validation" : "Design";

  const nodes = useMemo(() => traceNodesForRun(steps), [steps]);
  const title = `Designer agent · ${operationLabel} — ${statusText.toLowerCase()}${elapsed ? ` · ${elapsed}` : ""} · ${done}/${steps.length} steps`;

  return (
    <section aria-label={`Agent ${operationLabel.toLowerCase()} run`} aria-live="polite">
      <div className="rounded-lg border border-line bg-panel px-2.5 py-1.5">
        <ThinkingState live autoPlay={false} nodes={nodes} workingLabel={title} />
      </div>
      {modelId && modelId !== "none" && (
        <p className="mt-1.5 truncate px-1 font-mono text-[10px] text-faint" title={modelId}>{modelId}</p>
      )}
      {steps.length === 0 && (
        <p className="px-1 py-2 text-xs text-muted">{run.status === "running" ? "Connecting to the designer…" : "No steps were recorded for this run."}</p>
      )}
      {run.result && (
        <footer className="mt-2 flex flex-wrap items-center gap-2 rounded-lg border border-line bg-panel px-3.5 py-3">
          {run.result.canProvision
            ? <span className="inline-flex items-center gap-1.5 text-xs font-medium text-minttext"><CheckCircle2 size={14} /> Artifact ready — every gate passed</span>
            : <span className="inline-flex items-center gap-1.5 text-xs font-medium text-goldtext"><ShieldAlert size={14} /> Artifact blocked · {run.result.blockReasons.length} reason{run.result.blockReasons.length === 1 ? "" : "s"}</span>}
          {isCurrentArtifact && (
            <button type="button" onClick={onViewArtifact} className="ml-auto inline-flex items-center gap-1.5 rounded-md border border-line bg-panel px-2.5 py-1.5 text-xs font-medium text-paper hover:bg-panel2">
              View artifact <ArrowRight size={13} />
            </button>
          )}
        </footer>
      )}
    </section>
  );
}

const DESIGNER_STORAGE_KEY = "muse.designer.v1";
const DESIGNER_INTRO = "Describe the organization, its systems, its people, and the weakness the exercise should make provable. I will produce a deployable specification, topology, wiring plan, and costed build sheet.";
const DEFAULT_BUDGET: Budget = { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 };
const DEFAULT_PLATFORM: PlatformSelection = { runtimeTarget: "vm", modelSurface: "meta-modal", exerciseEngine: "scripted" };
const DEFAULT_BRIEF = "Vulnerable small business: gateway DNS, FreeIPA directory, mail, PHP intranet on Postgres, and four employee workstations";

interface DesignerSnapshot {
  budget: Budget;
  platform?: PlatformSelection;
  items: ChatItem[];
  draft: string;
  pkg: DesignPackage | null;
  deployed: string | null;
  costAck: boolean;
  /** Legacy v1 fields, still read for migration. */
  messages?: ChatMsg[];
  events?: DesignerRunEvent[];
  hasRun?: boolean;
  runFailed?: string | null;
}

/** Restore the designer workspace or an empty one; never fail the page on bad storage. */
function loadDesignerSnapshot(key: string): Partial<DesignerSnapshot> {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Partial<DesignerSnapshot>;
    if (!parsed || typeof parsed !== "object") return {};
    const snapshot: Partial<DesignerSnapshot> = {};
    if (parsed.budget && typeof parsed.budget.maxInstances === "number" && typeof parsed.budget.maxDollarsPerHour === "number" && typeof parsed.budget.ttlHours === "number") snapshot.budget = parsed.budget;
    if (parsed.platform && ["vm", "container"].includes(parsed.platform.runtimeTarget) && ["meta", "meta-modal"].includes(parsed.platform.modelSurface) && ["scripted", "agents"].includes(parsed.platform.exerciseEngine)) snapshot.platform = parsed.platform;
    if (Array.isArray(parsed.messages)) snapshot.messages = parsed.messages.filter((message) => message && (message.role === "user" || message.role === "assistant") && typeof message.text === "string");
    if (Array.isArray(parsed.items)) snapshot.items = parsed.items.filter((item) => item && typeof item.id === "string" && (item.kind === "message" || item.kind === "run"));
    if (typeof parsed.draft === "string") snapshot.draft = parsed.draft;
    if (parsed.pkg && typeof parsed.pkg === "object" && parsed.pkg.spec) snapshot.pkg = parsed.pkg;
    if (typeof parsed.deployed === "string") snapshot.deployed = parsed.deployed;
    if (parsed.costAck === true) snapshot.costAck = true;
    if (Array.isArray(parsed.events)) snapshot.events = parsed.events.filter((event) => event && typeof event.type === "string" && typeof event.stepId === "string");
    if (parsed.hasRun === true) snapshot.hasRun = true;
    if (typeof parsed.runFailed === "string") snapshot.runFailed = parsed.runFailed;
    return snapshot;
  } catch {
    return {};
  }
}

/** Bound persisted event size: drop the embedded package (kept once as `pkg`) and tail long streams. */
function compactDesignerEvent(event: DesignerRunEvent): DesignerRunEvent {
  if (!event.data) return event;
  const data = { ...event.data };
  if (event.type === "artifact.ready") delete data.package;
  if ((event.type === "model.reasoning" || event.type === "model.progress") && typeof data.text === "string" && data.text.length > 600) {
    data.text = data.text.slice(-600);
  }
  return { ...event, data };
}

function DesignerPage() {
  const { session } = useSession();
  const storageKey = `${DESIGNER_STORAGE_KEY}:${session?.userId ?? "anonymous"}:${session?.orgId ?? "personal"}`;
  const [restored] = useState(() => loadDesignerSnapshot(storageKey));
  const [budget, setBudget] = useState<Budget>(restored.budget ?? DEFAULT_BUDGET);
  const [platform, setPlatform] = useState<PlatformSelection>(restored.platform ?? DEFAULT_PLATFORM);
  const [platformIssue, setPlatformIssue] = useState<PlatformUnavailableError | null>(null);
  const [items, setItems] = useState<ChatItem[]>(() => {
    if (restored.items?.length) {
      // A refresh mid-run cannot resume the stream; never restore a run as live.
      return restored.items.map((item) => item.kind === "run" && item.status === "running" ? { ...item, status: "cancelled" as const } : item);
    }
    const migrated: ChatItem[] = (restored.messages?.length ? restored.messages : [{ role: "assistant" as const, text: DESIGNER_INTRO }])
      .map((message, i) => ({ id: `restored-msg-${i}`, kind: "message" as const, ...message }));
    if (restored.events?.length) {
      migrated.push({ id: "restored-run", kind: "run", operation: "design", status: restored.runFailed ? "failed" : "completed", events: restored.events });
    }
    return migrated;
  });
  const [draft, setDraft] = useState(restored.draft ?? DEFAULT_BRIEF);
  const [pkg, setPkg] = useState<DesignPackage | null>(restored.pkg ?? null);
  const [sending, setSending] = useState(false);
  const [deployed, setDeployed] = useState<string | null>(restored.deployed ?? null);
  const [costAck, setCostAck] = useState(restored.costAck ?? false);
  const [artifactClosed, setArtifactClosed] = useState(false);
  const [artifactTab, setArtifactTab] = useState<"topology" | "plan" | "cost" | "spec">("topology");
  const [showConstraints, setShowConstraints] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const chatScrollRef = useRef<HTMLDivElement>(null);
  const COST_ACK_THRESHOLD_PER_HOUR = 2;

  const appendMessage = useCallback((role: "user" | "assistant", text: string) => {
    setItems((prev) => [...prev, { id: newChatId(), kind: "message", role, text }]);
  }, []);

  const appendRunEvent = useCallback((runId: string, event: DesignerRunEvent) => {
    setItems((prev) => prev.map((item) => {
      if (item.kind !== "run" || item.id !== runId) return item;
      const result: DesignerRunResult | undefined = event.type === "artifact.ready" ? {
        canProvision: Boolean(event.data?.canProvision),
        blockReasons: Array.isArray(event.data?.blockReasons) ? (event.data!.blockReasons as unknown[]).map(String) : [],
        specDigest: typeof event.data?.specDigest === "string" ? event.data.specDigest : "",
        detail: event.detail,
      } : item.result;
      const status: DesignerRunStatus = event.type === "run.failed" ? "failed"
        : event.type === "run.cancelled" ? "cancelled"
        : item.status;
      return { ...item, status, result, events: [...item.events, event] };
    }));
  }, []);

  const finishRun = useCallback((runId: string, status: DesignerRunStatus) => {
    setItems((prev) => prev.map((item) => item.kind === "run" && item.id === runId ? { ...item, status } : item));
  }, []);

  useEffect(() => {
    if (sending) return;
    const snapshot: DesignerSnapshot = {
      budget, platform, draft, pkg, deployed, costAck,
      items: items.slice(-60).map((item) => item.kind === "run"
        ? { ...item, events: item.events.slice(-400).map(compactDesignerEvent) }
        : item),
    };
    // Debounced writes keep streaming renders cheap; the unload flush covers a refresh
    // that lands before the debounce fires.
    const save = () => { try { localStorage.setItem(storageKey, JSON.stringify(snapshot)); } catch { /* quota or private mode */ } };
    const id = window.setTimeout(save, 250);
    window.addEventListener("beforeunload", save);
    return () => { window.clearTimeout(id); window.removeEventListener("beforeunload", save); };
  }, [budget, platform, items, draft, pkg, deployed, costAck, sending, storageKey]);

  const chatEventCount = items.reduce((n, item) => n + (item.kind === "run" ? item.events.length : 1), 0);
  useEffect(() => {
    const node = chatScrollRef.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [chatEventCount]);

  async function send() {
    const text = draft.trim();
    if (!text || sending) return;
    setPlatformIssue(null);
    setArtifactClosed(false);
    setArtifactClosing(false);
    const runId = newChatId();
    const operation = pkg ? "refine" : "design";
    setItems((prev) => [
      ...prev,
      { id: newChatId(), kind: "message", role: "user", text },
      { id: runId, kind: "run", operation, status: "running", events: [] },
    ]);
    setDraft("");
    setSending(true);
    const controller = new AbortController();
    abortRef.current = controller;
    const opts = {
      signal: controller.signal,
      platform,
      onEvent: (event: DesignerRunEvent) => appendRunEvent(runId, event),
    };
    try {
      const next = pkg ? await api.refineDesign(pkg.spec, text, budget, opts) : await api.submitDesign(text, budget, opts);
      setPkg(next);
      setDeployed(null);
      setCostAck(false);
      setArtifactTab("topology");
      setArtifactClosed(false);
      setArtifactClosing(false);
      finishRun(runId, next.canProvision ? "completed" : "blocked");
      appendMessage("assistant", next.canProvision
        ? `Design ready: ${next.spec.instances.length} instances, ${next.spec.personas.length} personas, ${next.spec.plantedVulns.length} planted weaknesses, and ${next.spec.objectives.length} objectives at $${next.cost.perHour}/hr. Review the graph and build plan before approval.`
        : `Design generated, but provisioning is blocked: ${next.blockReasons.join("; ")}. Refine the design or adjust the constraints.`);
    } catch (err) {
      const aborted = controller.signal.aborted;
      finishRun(runId, aborted ? "cancelled" : "failed");
      if (err instanceof PlatformUnavailableError) {
        setPlatformIssue(err);
        setShowConstraints(true);
        setDraft((current) => current || text);
        appendMessage("assistant", `Platform unavailable: ${err.message}. Nothing was substituted or generated. Choose an available alternative below, then send again.`);
      } else {
        appendMessage("assistant", aborted
          ? "Run stopped. The draft is unchanged; send a new instruction when you are ready."
          : `Designer error: ${err instanceof Error ? err.message : String(err)}`);
      }
    } finally {
      abortRef.current = null;
      setSending(false);
    }
  }

  async function deploy() {
    if (!pkg) return;
    try {
      const result = await api.createDeployment(pkg.spec, pkg.digest, pkg.planDigest, session?.orgId ?? "");
      setDeployed(result.deploymentId);
      appendMessage("assistant", `Deployment ${result.deploymentId} created. The worker will automatically provision, configure, pass readiness/proof gates, run the exercise, score it, publish the dataset, mark it ready, and tear it down at TTL. Watch it under Monitoring, Red Team, and Blue Team.`);
    } catch (err) {
      appendMessage("assistant", `Deploy failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  async function saveTemplate() {
    if (!pkg) return;
    try {
      await api.saveTemplate(pkg.spec, pkg.digest, session?.orgId ?? "");
      appendMessage("assistant", "Saved as a versioned template for this workspace.");
    } catch (err) {
      appendMessage("assistant", `Save template failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  function exportSpec() {
    if (!pkg) return;
    const blob = new Blob([JSON.stringify(pkg.spec, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${pkg.spec.name.replace(/[^a-z0-9]+/gi, "-")}.spec.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  async function importSpec(file?: File) {
    if (!file || sending) return;
    let spec: EnvironmentSpec;
    try {
      spec = EnvironmentSpec.parse(JSON.parse(await file.text()));
    } catch (err) {
      appendMessage("assistant", `Import failed: ${err instanceof Error ? err.message : String(err)}`);
      return;
    }
    setArtifactClosed(false);
    setArtifactClosing(false);
    const runId = newChatId();
    setItems((prev) => [
      ...prev,
      { id: newChatId(), kind: "message", role: "user", text: `Import specification — ${file.name}` },
      { id: runId, kind: "run", operation: "validate", status: "running", events: [] },
    ]);
    setSending(true);
    const controller = new AbortController();
    abortRef.current = controller;
    const opts = {
      signal: controller.signal,
      onEvent: (event: DesignerRunEvent) => appendRunEvent(runId, event),
    };
    try {
      const next = await api.validateDesign(spec, budget, opts);
      setPkg(next);
      setDeployed(null);
      setCostAck(false);
      setArtifactTab("topology");
      setArtifactClosed(false);
      setArtifactClosing(false);
      finishRun(runId, next.canProvision ? "completed" : "blocked");
      appendMessage("assistant", next.canProvision
        ? `Imported "${spec.name}" and validated it through the same deployment gates. Review the build plan before approval.`
        : `Imported "${spec.name}", but provisioning is blocked: ${next.blockReasons.join("; ")}.`);
    } catch (err) {
      const aborted = controller.signal.aborted;
      finishRun(runId, aborted ? "cancelled" : "failed");
      appendMessage("assistant", aborted ? "Import cancelled." : `Import failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      abortRef.current = null;
      setSending(false);
    }
  }

  const designState = deployed ? { label: "Deployment pending", tone: "gold" as const } : pkg ? (pkg.canProvision ? { label: "Ready to approve", tone: "mint" as const } : { label: "Blocked", tone: "danger" as const }) : { label: "Awaiting brief", tone: "dim" as const };

  const latestRun = [...items].reverse().find((item): item is Extract<ChatItem, { kind: "run" }> => item.kind === "run");
  const liveSteps = useMemo(
    () => (sending && latestRun ? foldRunEvents(latestRun.events) : []),
    [sending, latestRun],
  );
  const artifactOpen = sending || Boolean(pkg && !artifactClosed);
  // Exit animation state: only ever set by the close button, cleared when the
  // artifact reopens or when the timer finishes. No derived flag can get stuck.
  const [artifactClosing, setArtifactClosing] = useState(false);
  const artifactVisible = artifactOpen || artifactClosing;
  useEffect(() => {
    if (artifactOpen || !artifactClosing) return;
    const timer = window.setTimeout(() => setArtifactClosing(false), 460);
    return () => window.clearTimeout(timer);
  }, [artifactOpen, artifactClosing]);
  const hasUserMessage = items.some((item) => item.kind === "message" && item.role === "user");
  const openArtifact = () => {
    setArtifactClosed(false);
    setArtifactClosing(false);
    requestAnimationFrame(() => document.getElementById("design-artifact")?.scrollIntoView({ block: "start" }));
  };

  return (
    <div>
      {/* One workspace card: conversation, agent runs, composer, and artifact
          review share a single surface, split internally like Muse. */}
      <section className="ops-panel flex flex-col overflow-hidden shadow-panel xl:h-[calc(100dvh-7.5rem)]" aria-label="Designer workspace">
        <header className="flex min-h-14 flex-wrap items-center gap-3 border-b border-line px-4 py-2.5 sm:px-5">
          <div className="flex min-w-0 flex-1 items-center gap-3">
            <BrandMark size={32} />
            <div className="min-w-0">
              <h1 className="truncate text-[15px] font-semibold leading-tight text-paper">
                {pkg ? pkg.spec.name : sending ? "Building your environment" : "Environment designer"}
              </h1>
              <p className="truncate text-[11px] leading-4 text-faint">
                {pkg ? "Checked, costed, deployable design — review before approval." : "Describe an organization. Get a deployable adversarial lab."}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={designState.tone}>{designState.label}</Badge>
            <span className="max-md:hidden"><Badge tone="cyber">Schema gated</Badge></span>
            {pkg && artifactClosed && !sending && (
              <button type="button" onClick={openArtifact} className={compactButton}><Network size={14} /> Open design</button>
            )}
          </div>
        </header>

        <div className="flex min-h-0 flex-1 flex-col xl:flex-row">
          <div className={`flex h-[72dvh] min-h-[440px] w-full shrink-0 flex-col overflow-hidden border-line transition-[width] duration-500 ease-[cubic-bezier(0.16,1,0.3,1)] max-xl:border-b xl:h-auto xl:min-h-0 ${artifactOpen ? "xl:w-[480px] xl:border-r 2xl:w-[520px]" : "xl:w-full"}`}>
          <div className="flex h-12 shrink-0 items-center gap-2 border-b border-line/70 px-4">
            <span className="text-xs font-semibold text-paper">Brief</span>
            <span className="truncate text-[11px] text-faint">{sending ? "Agent is working — watch it think on the right" : pkg ? "Refine the design or fork a variant" : "New design"}</span>
            <span className="ml-auto shrink-0"><Badge tone="signal">Agent</Badge></span>
          </div>
          <div ref={chatScrollRef} className={`flex-1 space-y-5 overflow-y-auto px-4 py-5 sm:px-5 ${!artifactOpen ? "[&>*]:mx-auto [&>*]:w-full [&>*]:max-w-4xl" : ""}`} aria-live="polite">
            {items.map((item) => item.kind === "message" ? (
              item.role === "user" ? (
                <article key={item.id} className="ml-auto w-fit max-w-[88%] rounded-xl rounded-br-sm bg-signal px-4 py-3 shadow-sm">
                  <p className="whitespace-pre-wrap break-words text-sm leading-6 text-signalcontrast">{item.text}</p>
                </article>
              ) : (
                <article key={item.id} className="flex gap-3 pr-2">
                  <span className="mt-0.5 shrink-0"><BrandMark size={26} /></span>
                  <div className="min-w-0 pt-0.5">
                    <p className="mb-1 text-xs font-semibold text-paper">Designer agent</p>
                    <p className="whitespace-pre-wrap break-words text-sm leading-6 text-paper/90">{item.text}</p>
                  </div>
                </article>
              )
            ) : (
              <DesignerRunTimeline
                key={item.id}
                run={item}
                isCurrentArtifact={Boolean(pkg && item.result && item.result.specDigest === pkg.digest)}
                onViewArtifact={openArtifact}
              />
            ))}
            {!hasUserMessage && !sending && (
              <div className="flex flex-wrap gap-2 pt-1" aria-label="Example briefs">
                {[
                  "12-person clinic with FreeIPA, mail, intranet, and a patient database",
                  "8-person software shop with Gitea on FreeIPA and a Postgres weak credential",
                  "Tiny PHP/Postgres office with one workstation and a database objective",
                ].map((example) => (
                  <button key={example} type="button" onClick={() => setDraft(example)} className="rounded-lg border border-line bg-panel px-3 py-1.5 text-left text-xs leading-5 text-muted shadow-sm transition-colors hover:border-linestrong hover:text-paper">
                    {example}
                  </button>
                ))}
              </div>
            )}
          </div>

          <div className="shrink-0 px-3 pb-3 pt-2 sm:px-4 sm:pb-4">
            <div className={`${!artifactOpen ? "mx-auto w-full max-w-4xl" : ""} overflow-hidden rounded-xl border border-linestrong/70 bg-panel shadow-composer transition-colors focus-within:border-linestrong`}>
              {platformIssue && (
                <div role="alert" className="border-b border-goldline bg-goldsurface px-4 py-3">
                  <p className="flex items-center gap-2 text-xs font-semibold text-goldtext"><ShieldAlert size={14} /> Platform choice required</p>
                  <p className="mt-1 text-xs leading-5 text-goldtext">{platformIssue.message}. Nothing was substituted. Choose an available platform, then send again.</p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {platformIssue.alternatives.map((alternative) => (
                      <button
                        key={`${alternative.runtimeTarget}-${alternative.modelSurface}-${alternative.exerciseEngine}`}
                        type="button"
                        onClick={() => { setPlatform(alternative); setPlatformIssue(null); appendMessage("assistant", `Platform set to ${alternative.runtimeTarget} runtime · ${alternative.modelSurface} models · ${alternative.exerciseEngine} exercise. Send when ready.`); }}
                        className="rounded-lg border border-goldline bg-panel px-3 py-1.5 font-mono text-[11px] font-medium text-goldtext shadow-sm transition-colors hover:bg-goldsurface"
                      >
                        Use {alternative.runtimeTarget} · {alternative.modelSurface} · {alternative.exerciseEngine}
                      </button>
                    ))}
                    <button type="button" onClick={() => setPlatformIssue(null)} className="rounded-lg px-3 py-1.5 text-[11px] font-medium text-goldtext hover:bg-goldsurface">Keep current</button>
                  </div>
                </div>
              )}
              {showConstraints && (
                <div className="border-b border-line/70 bg-track px-4 py-3">
                  <p className="mb-2.5 flex items-center gap-2 text-xs font-medium text-muted"><ListChecks size={13} /> Run constraints</p>
                  <div className="grid grid-cols-3 gap-2">
                    <BudgetField label="Instances" suffix="max" min={1} value={budget.maxInstances} onChange={(v) => setBudget((b) => ({ ...b, maxInstances: v }))} />
                    <BudgetField label="Cost" suffix="$/hr" min={0} step={0.5} value={budget.maxDollarsPerHour} onChange={(v) => setBudget((b) => ({ ...b, maxDollarsPerHour: v }))} />
                    <BudgetField label="Lifetime" suffix="hours" min={1} value={budget.ttlHours} onChange={(v) => setBudget((b) => ({ ...b, ttlHours: v }))} />
                  </div>
                  <div className="mt-3 space-y-2.5 border-t border-line/70 pt-3" aria-label="Platform selection">
                    <div>
                      <p className="mb-1 text-[11px] font-medium text-muted">Environment platform</p>
                      <SegmentedTabs label="Environment platform" values={["vm", "container"]} labels={{ vm: "VM org lab", container: "Container lab" }} value={platform.runtimeTarget} onChange={(value) => setPlatform((p) => ({ ...p, runtimeTarget: value as PlatformSelection["runtimeTarget"] }))} />
                    </div>
                    <div>
                      <p className="mb-1 text-[11px] font-medium text-muted">Model surface</p>
                      <SegmentedTabs label="Model surface" values={["meta", "meta-modal"]} labels={{ meta: "Meta API", "meta-modal": "Meta Modal" }} value={platform.modelSurface} onChange={(value) => setPlatform((p) => ({ ...p, modelSurface: value as PlatformSelection["modelSurface"] }))} />
                    </div>
                    <div>
                      <p className="mb-1 text-[11px] font-medium text-muted">Exercise engine</p>
                      <SegmentedTabs label="Exercise engine" values={["agents", "scripted"]} labels={{ agents: "Model agents", scripted: "Scripted live" }} value={platform.exerciseEngine} onChange={(value) => setPlatform((p) => ({ ...p, exerciseEngine: value as PlatformSelection["exerciseEngine"] }))} />
                    </div>
                    <p className="text-[10px] leading-4 text-faint">Pinned into the spec and deployment. Meta Modal runs Muse Spark Open for the designer and, with model agents, for red, blue and the employees.</p>
                  </div>
                </div>
              )}
              <label className="block px-4 pt-3">
                <span className="sr-only">Message the designer</span>
                <textarea
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void send(); } }}
                  rows={pkg ? 2 : 3}
                  placeholder={pkg ? "Ask for a change to this design…" : "Describe the organization and exercise…"}
                  className="max-h-48 w-full resize-none bg-transparent text-sm leading-6 text-paper outline-none placeholder:text-faint"
                />
              </label>
              <div className="flex items-center gap-1.5 px-2.5 pb-2.5 pt-1">
                <button
                  type="button"
                  aria-expanded={showConstraints}
                  onClick={() => setShowConstraints((v) => !v)}
                  className="inline-flex h-8 shrink-0 items-center gap-1.5 rounded-lg border border-line px-2.5 font-mono text-[11px] text-muted transition-colors hover:bg-panel2 hover:text-paper"
                >
                  <Settings2 size={13} />
                  {budget.maxInstances} hosts · ${budget.maxDollarsPerHour}/hr · {budget.ttlHours}h · {platform.runtimeTarget}
                  <ChevronDown size={12} className={`transition-transform ${showConstraints ? "rotate-180" : ""}`} />
                </button>
                <label title="Import an EnvironmentSpec JSON" className="inline-flex h-8 w-8 shrink-0 cursor-pointer items-center justify-center rounded-lg text-muted transition-colors hover:bg-panel2 hover:text-paper">
                  <Upload size={15} />
                  <input type="file" accept="application/json,.json" className="sr-only" onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ""; if (f) void importSpec(f); }} />
                </label>
                <p className="min-w-0 flex-1 truncate text-right font-mono text-[10px] text-faint max-sm:hidden">{sending ? "Streaming — stop to cancel" : "Enter to send"}</p>
                {sending ? (
                  <button type="button" onClick={() => abortRef.current?.abort()} aria-label="Stop generation" className="ml-auto flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-signal text-signalcontrast transition hover:bg-raised focus-visible:outline-2 focus-visible:outline-offset-2">
                    <Square size={12} fill="currentColor" />
                  </button>
                ) : (
                  <button type="button" disabled={!draft.trim()} onClick={() => void send()} aria-label={pkg ? "Send refinement" : "Generate design"} className="ml-auto flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-signal text-signalcontrast transition hover:bg-raised focus-visible:outline-2 focus-visible:outline-offset-2 disabled:cursor-not-allowed disabled:opacity-25">
                    <ArrowUp size={16} />
                  </button>
                )}
              </div>
            </div>
            {!artifactOpen && <p className="mt-2 text-center text-[10px] leading-4 text-faint">Every design is schema-checked, capability-gated, and costed before it can deploy.</p>}
          </div>
          </div>

          {artifactVisible && (
          <section id="design-artifact" key={pkg?.digest ?? "building"} className={`${artifactClosing ? "animate-slide-out-right" : "animate-slide-in-right"} flex min-w-0 flex-1 flex-col scroll-mt-24 xl:min-h-0`} aria-label="Design artifact">
            {pkg ? <>
            <header className="shrink-0 border-b border-line bg-panel/95 px-4 pt-4 sm:px-5">
              <div className="flex items-start gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex min-w-0 flex-wrap items-center gap-2.5">
                    <h2 className="truncate font-display text-[24px] font-semibold leading-tight text-paper">{pkg.spec.name}</h2>
                    <Badge tone={pkg.canProvision ? "mint" : "danger"}>{pkg.canProvision ? "Deployable" : "Blocked"}</Badge>
                    {pkg.spec.platform && <Badge tone="cyber">{pkg.spec.platform.runtimeTarget} · {pkg.spec.platform.modelSurface} · {pkg.spec.platform.exerciseEngine}</Badge>}
                  </div>
                  <p className="mt-1 truncate font-mono text-[10px] text-faint" title={`${pkg.digest} · ${pkg.planDigest}`}>spec {shortId(pkg.digest, 18)} · plan {shortId(pkg.planDigest, 18)}</p>
                  <div className="mt-2.5"><DesignSummary pkg={pkg} /></div>
                </div>
                <button type="button" onClick={() => { setArtifactClosed(true); setArtifactClosing(true); }} aria-label="Close design canvas" className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-muted transition-colors hover:bg-panel2 hover:text-paper">
                  <X size={16} />
                </button>
              </div>
              <div className="mt-3.5 overflow-x-auto pb-3">
                <SegmentedTabs
                  label="Design views"
                  values={["topology", "plan", "cost", "spec"]}
                  labels={{ topology: "Topology", plan: "Build plan", cost: "Cost", spec: "Spec JSON" }}
                  value={artifactTab}
                  onChange={(value) => setArtifactTab(value as typeof artifactTab)}
                />
              </div>
            </header>

            <div className="min-h-0 flex-1 xl:overflow-y-auto">
            <div className="space-y-4 p-4 sm:p-5">

              {!pkg.canProvision && (
                <div role="alert" className="rounded-lg border border-dangerline bg-dangersurface p-4">
                  <h3 className="flex items-center gap-2 text-sm font-semibold text-dangertext"><XCircle size={16} /> Provisioning blocked</h3>
                  <ul className="mt-2 space-y-1 font-mono text-xs leading-5 text-dangertext">{pkg.blockReasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
                </div>
              )}

              <div key={`${pkg.digest}-${artifactTab}`} className="animate-fade-up">
                {artifactTab === "topology" && <TopologyView pkg={pkg} />}
                {artifactTab === "plan" && <PlanView pkg={pkg} />}
                {artifactTab === "cost" && <CostView pkg={pkg} budget={budget} />}
                {artifactTab === "spec" && (
                  <Panel className="overflow-hidden">
                    <PanelHeader title="EnvironmentSpec" description="Canonical JSON produced and validated by the designer." action={<button onClick={exportSpec} className={compactButton}><Download size={14} /> Export</button>} />
                    <pre className="max-h-[720px] overflow-auto bg-track p-5 font-mono text-[12px] leading-5 text-muted">{JSON.stringify(pkg.spec, null, 2)}</pre>
                  </Panel>
                )}
              </div>

              {pkg.canProvision && pkg.cost.perHour > COST_ACK_THRESHOLD_PER_HOUR && !deployed && (
                <label className="flex items-start gap-3 rounded-lg border border-goldline bg-goldsurface p-4 text-sm leading-6 text-goldtext">
                  <input type="checkbox" checked={costAck} onChange={(e) => setCostAck(e.target.checked)} className="mt-1.5 h-4 w-4 shrink-0 accent-[var(--signal)]" />
                  <span>I acknowledge the estimated cost of <strong className="font-mono">${pkg.cost.perHour}/hr</strong> — about <strong className="font-mono">${pkg.cost.ttlTotal}</strong> over the {pkg.spec.budgets.ttlHours}h TTL. Acknowledgment is required above ${COST_ACK_THRESHOLD_PER_HOUR}/hr.</span>
                </label>
              )}

            </div>
            </div>

            <footer className="flex shrink-0 flex-wrap items-center gap-2 border-t border-line bg-panel px-4 py-3 sm:px-5">
              <div className="mr-auto min-w-0">
                <p className="font-mono text-[12px] text-paper">${pkg.cost.perHour}/hr · ${pkg.cost.ttlTotal} over {pkg.spec.budgets.ttlHours}h</p>
                {deployed
                  ? <Link to={`/environments/${deployed}`} className="mt-0.5 inline-flex items-center gap-1.5 text-xs font-medium text-cyber hover:text-paper">Deployment {shortId(deployed, 10)} pending — open it <ArrowRight size={13} /></Link>
                  : !pkg.canProvision
                    ? <p className="mt-0.5 font-mono text-[10px] text-danger">Resolve every block to enable deploy</p>
                    : pkg.cost.perHour > COST_ACK_THRESHOLD_PER_HOUR && !costAck
                      ? <p className="mt-0.5 font-mono text-[10px] text-gold">Cost acknowledgment required — it appears at the bottom of the design</p>
                      : <p className="mt-0.5 text-[10px] text-faint">Nothing provisions until you approve.</p>}
              </div>
              <button type="button" onClick={() => void saveTemplate()} className={secondaryButton}><Save size={15} /> Save template</button>
              <button type="button" onClick={exportSpec} className={secondaryButton}><Download size={15} /> Export</button>
              <button type="button" onClick={() => { setPkg(null); setDeployed(null); setCostAck(false); setArtifactClosed(false); setArtifactClosing(false); setArtifactTab("topology"); appendMessage("assistant", "Started a new design. The transcript above stays as history; describe the variant as a fresh brief."); }} className={secondaryButton}><GitBranch size={15} /> Fork</button>
              <button type="button" disabled={!pkg.canProvision || Boolean(deployed) || (pkg.cost.perHour > COST_ACK_THRESHOLD_PER_HOUR && !costAck)} onClick={() => void deploy()} className="inline-flex items-center justify-center gap-2 rounded-lg bg-success px-4 py-2.5 text-sm font-medium text-successcontrast shadow-sm transition-colors hover:bg-successhover disabled:cursor-not-allowed disabled:opacity-45">
                <CheckCircle2 size={16} /> {deployed ? "Deployment pending" : "Approve & deploy"}
              </button>
            </footer>
            </> : <DesignBuildingPane steps={liveSteps} />}
          </section>
          )}
        </div>
      </section>
    </div>
  );
}

function DeploymentTable({ deployments }: { deployments: Deployment[] }) {
  const qc = useQueryClient();
  const { getToken } = useAuth();
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const del = useMutation({
    mutationFn: async (id: string) => {
      const res = await learningFetch(() => getToken(), `/deployments/${id}`, { method: "DELETE" });
      return res as { id: string; how: string };
    },
    onSuccess: async () => {
      setDeleteError(null);
      await qc.invalidateQueries({ queryKey: ["deployments"] });
    },
    onError: (err) => setDeleteError(err instanceof Error ? err.message : String(err)),
  });
  return (
    <div className="overflow-x-auto">
      {deleteError && <p className="border-b border-line px-5 py-3 text-sm text-danger">Delete failed: {deleteError}</p>}
      <table className="w-full min-w-[900px] text-left text-sm">
        <thead className="bg-track text-xs font-medium text-muted">
          <tr><th className="px-5 py-3 font-medium">Environment</th><th className="px-4 py-3 font-medium">Status</th><th className="px-4 py-3 font-medium">Stack</th><th className="px-4 py-3 font-medium">Created</th><th className="px-4 py-3 font-medium">Drift</th><th className="px-4 py-3 text-right font-medium">Cost</th><th className="w-24 px-4 py-3" /></tr>
        </thead>
        <tbody className="divide-y divide-line">
          {deployments.map((d) => (
            <tr key={d.id} className="hover:bg-track">
              <td className="px-5 py-4">
                <Link to={`/environments/${d.id}`} className="flex items-center gap-3">
                  <span className="flex h-9 w-9 items-center justify-center rounded-md border border-line bg-panel2 text-cyber"><Boxes size={17} /></span>
                  <span><span className="block font-mono text-[13px] font-medium text-paper" title={d.id}>{shortId(d.id, 20)}</span><span className="mt-0.5 block font-mono text-[10px] text-faint">spec {shortId(d.specDigest, 24)}</span></span>
                </Link>
              </td>
              <td className="px-4 py-4"><Status value={d.status} /></td>
              <td className="px-4 py-4 font-mono text-xs text-muted">{d.stackId || "—"}</td>
              <td className="px-4 py-4 text-muted">{formatDate(d.createdAt)}</td>
              <td className="px-4 py-4">{d.driftStatus ? <Badge tone={d.driftStatus.toLowerCase().includes("drift") ? "gold" : "dim"}>{d.driftStatus}</Badge> : <span className="text-muted">Unknown</span>}</td>
              <td className="px-4 py-4 text-right font-mono text-paper">{d.costEstimatePerHour ? `$${d.costEstimatePerHour}/hr` : "—"}</td>
              <td className="px-4 py-4 text-right">
                <span className="inline-flex items-center justify-end gap-1.5">
                  {d.status !== "destroyed" && (
                    <button
                      type="button"
                      disabled={del.isPending}
                      aria-label={`Delete environment ${d.id}`}
                      title={["pending", "provisioning", "configuring", "verifying", "ready", "exercising", "destroying"].includes(d.status) ? "Tear down and delete" : "Delete from registry"}
                      onClick={() => {
                        if (window.confirm(`Delete environment ${shortId(d.id, 12)}?${["pending", "provisioning", "configuring", "verifying", "ready", "exercising", "destroying"].includes(d.status) ? " Live guests are torn down first; runs and datasets stay as evidence." : " Its records stay as evidence."}`)) del.mutate(d.id);
                      }}
                      className="inline-flex rounded-md border border-dangerline bg-dangersurface p-1.5 text-dangertext hover:bg-dangertext/20 disabled:opacity-50"
                    >
                      <Trash2 size={15} />
                    </button>
                  )}
                  <Link to={`/environments/${d.id}`} aria-label={`Open environment ${d.id}`} className="inline-flex rounded-md border border-line p-1.5 text-muted hover:border-linestrong hover:text-paper"><ArrowRight size={15} /></Link>
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EnvironmentsPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ["deployments"], queryFn: api.deployments });
  const deployments = data ?? [];
  const ready = deployments.filter((d) => d.status === "ready").length;
  const exercising = deployments.filter((d) => d.status === "exercising").length;
  const attention = deployments.filter((d) => ["failed", "quarantined"].includes(d.status)).length;

  return (
    <div>
      <PageHeader
        title="Environments"
        description="Deployment records, lifecycle state, drift, and operating cost for every approved environment."
        actions={<Link to="/designer" className={primaryButton}><FileCode2 size={16} /> New environment</Link>}
        meta={<><Badge tone="mint">{ready} ready</Badge><Badge tone="signal">{exercising} exercising</Badge><Badge tone={attention ? "danger" : "dim"}>{attention} need attention</Badge></>}
      />
      {error ? <ErrorState title="Environments could not be loaded" error={error} /> : isLoading ? <LoadingState what="environments" rows={5} /> : deployments.length === 0 ? (
        <EmptyState title="No environments in this workspace" action={<Link to="/designer" className={primaryButton}><FileCode2 size={16} /> Design an environment</Link>}>Approved designs become deployment records here, with live lifecycle and drift state.</EmptyState>
      ) : (
        <Panel className="overflow-hidden">
          <PanelHeader title="Deployment registry" description={`${deployments.length} records, newest first.`} />
          <DeploymentTable deployments={deployments} />
        </Panel>
      )}
    </div>
  );
}

const DEP_TABS = ["overview", "infrastructure", "access", "security", "automation", "logs"] as const;
const LIFECYCLE = ["pending", "provisioning", "configuring", "verifying", "ready", "exercising"] as const;

function Lifecycle({ status }: { status: string }) {
  const terminalFailure = ["failed", "quarantined"].includes(status);
  const current = LIFECYCLE.indexOf(status as (typeof LIFECYCLE)[number]);
  return (
    <div className="overflow-x-auto pb-1" aria-label={`Deployment lifecycle: ${status}`}>
      <div className="flex min-w-[720px] items-center">
        {LIFECYCLE.map((step, index) => {
          const complete = current > index;
          const isCurrent = current === index;
          return (
            <div key={step} className={`flex items-center ${index < LIFECYCLE.length - 1 ? "flex-1" : ""}`}>
              <div className="flex items-center gap-2.5">
                <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full border ${complete ? "border-mintline bg-mintsurface text-minttext" : isCurrent ? "border-signal bg-signal text-signalcontrast" : "border-line bg-panel2 text-faint"}`}>
                  {complete ? <CheckCircle2 size={15} /> : <span className="font-mono text-[10px] font-semibold">{index + 1}</span>}
                </span>
                <span className={`whitespace-nowrap text-xs ${isCurrent ? "font-semibold text-paper" : "text-muted"}`}>{prettify(step)}</span>
              </div>
              {index < LIFECYCLE.length - 1 && <span className={`mx-3 h-px min-w-8 flex-1 ${complete ? "bg-mint/50" : "bg-line"}`} />}
            </div>
          );
        })}
      </div>
      {terminalFailure && <p className="mt-3 flex items-center gap-2 text-sm text-danger"><XCircle size={16} /> Terminal state: {prettify(status)}. Review access information and logs for the recorded failure context.</p>}
      {status === "destroyed" && <p className="mt-3 text-sm text-muted">This deployment has been destroyed. Its specification and records remain available for audit.</p>}
      {status === "destroying" && <p className="mt-3 text-sm text-gold">Teardown is in progress.</p>}
    </div>
  );
}

function DetailGrid({ items }: { items: { label: string; value: ReactNode; mono?: boolean }[] }) {
  return (
    <dl className="grid gap-px overflow-hidden rounded-lg border border-line bg-line sm:grid-cols-2 xl:grid-cols-4">
      {items.map((item) => (
        <div key={item.label} className="min-w-0 bg-panel p-4">
          <dt className="text-xs text-faint">{item.label}</dt>
          <dd className={`mt-1.5 break-words text-sm font-medium text-paper ${item.mono ? "font-mono text-xs leading-5" : ""}`}>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function EnvironmentDetailPage() {
  const { id } = useParams();
  const [tab, setTab] = useState<(typeof DEP_TABS)[number]>("overview");
  // Realtime pushes status changes when it is enabled for the table; while a
  // deployment is still moving, poll as well so the page never sits stale.
  const { data, isLoading, error } = useQuery({
    queryKey: ["deployment", id],
    queryFn: () => api.deployment(id ?? ""),
    refetchInterval: (q) => {
      const status = (q.state.data as { status?: string } | undefined)?.status;
      return status && ["pending", "provisioning", "configuring", "verifying", "exercising", "destroying"].includes(status) ? 5000 : false;
    },
  });
  const qc = useQueryClient();
  const refresh = useCallback(() => {
    void qc.invalidateQueries({ queryKey: ["deployment", id] });
    void qc.invalidateQueries({ queryKey: ["deployments"] });
  }, [qc, id]);
  const live = useLiveDeployment(id ?? "", refresh);

  if (isLoading) return <LoadingState what="environment" rows={5} />;
  if (error) return <ErrorState title="Environment could not be loaded" error={error} />;
  if (!data) return <EmptyState title="Environment not found" action={<Link to="/environments" className={secondaryButton}>Back to environments</Link>}>No deployment record exists for `{id}` in this workspace.</EmptyState>;

  const { deployment: d, spec } = data;
  const accessEntries = Object.entries(d.accessInfo ?? {});

  return (
    <div>
      <Link to="/environments" className="mb-4 inline-flex items-center gap-2 text-sm font-medium text-muted hover:text-paper"><ArrowRight size={15} className="rotate-180" /> Environments</Link>
      <PageHeader
        title={spec?.name ?? "Environment"}
        description={spec ? `${spec.instances.length} hosts · ${spec.personas.length} personas · ${spec.objectives.length} objectives · ${spec.provider}` : "Deployment record without an attached environment specification."}
        meta={<><Status value={d.status} /><Badge tone="cyber">{d.stackId || "No stack"}</Badge><Badge>Created {formatDate(d.createdAt)}</Badge></>}
        actions={<span className="max-w-full break-all font-mono text-[11px] text-faint" title={d.id}>{d.id}</span>}
      />

      <Panel className="mb-4 p-4 sm:p-5"><Lifecycle status={d.status} /></Panel>
      <SegmentedTabs values={DEP_TABS} value={tab} onChange={(value) => setTab(value as (typeof DEP_TABS)[number])} label="Deployment detail" />

      <div className="mt-4" role="tabpanel">
        {tab === "overview" && (
          <div className="space-y-4">
            <DetailGrid items={[
              { label: "Lifecycle status", value: <Status value={d.status} /> },
              { label: "Stack", value: d.stackId || "—", mono: true },
              { label: "Estimated cost", value: d.costEstimatePerHour ? `$${d.costEstimatePerHour}/hr` : "—" },
              { label: "Drift", value: d.driftStatus ? prettify(d.driftStatus) : "Unknown" },
              { label: "Provider", value: spec?.provider ?? "—" },
              { label: "Truth layer", value: spec?.truthLayer ?? "—", mono: true },
              { label: "Specification digest", value: d.specDigest || "—", mono: true },
              { label: "Created", value: formatDate(d.createdAt) },
            ]} />
            {spec && (
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <StatCard label="Hosts" value={String(spec.instances.length)} detail="Machines declared in the approved specification" tone="cyber" />
                <StatCard label="Personas" value={String(spec.personas.length)} detail="People who inhabit the organization" tone="dim" />
                <StatCard label="Objectives" value={String(spec.objectives.length)} detail="Measurable red-team goals" tone="gold" />
                <StatCard label="Planted weaknesses" value={String(spec.plantedVulns.length)} detail="Intentional, provable attack paths" tone="danger" />
              </div>
            )}
          </div>
        )}

        {tab === "infrastructure" && (!spec ? <EmptyState title="No specification attached">Infrastructure cannot be reconstructed from this deployment record alone.</EmptyState> : (
          <div className="space-y-4">
            <Panel>
              <PanelHeader title="Network graph" description="Approved host placement and declared dependencies." />
              <div className="p-4 sm:p-5"><TopologyGraph spec={spec} groups={groupsForSpec(spec)} flows={dependencyFlows(spec)} domain={spec.topology.cidr} /></div>
            </Panel>
            <Panel className="overflow-hidden">
              <PanelHeader title="Host inventory" description="Every machine in the approved specification." />
              <div className="overflow-x-auto">
                <table className="w-full min-w-[860px] text-left text-sm">
                  <thead className="bg-track text-xs font-medium text-muted"><tr><th className="px-5 py-3 font-medium">Host</th><th className="px-4 py-3 font-medium">Role</th><th className="px-4 py-3 font-medium">Runtime / OS</th><th className="px-4 py-3 font-medium">Placement</th><th className="px-4 py-3 font-medium">Services</th><th className="px-4 py-3 font-medium">Resources</th></tr></thead>
                  <tbody className="divide-y divide-line">
                    {spec.instances.map((instance) => (
                      <tr key={instance.hostId} className="hover:bg-track">
                        <td className="px-5 py-3.5"><span className="block font-mono text-xs font-medium text-paper">{instance.hostId}</span><span className="mt-0.5 block text-xs text-faint">{instance.name}</span></td>
                        <td className="px-4 py-3.5 text-muted">{prettify(instance.role)}</td>
                        <td className="px-4 py-3.5 text-muted">{instance.runtime} · {instance.os}</td>
                        <td className="px-4 py-3.5 font-mono text-xs text-muted">{instance.subnet ?? [instance.site, instance.zone].filter(Boolean).join("/") ?? "—"}</td>
                        <td className="px-4 py-3.5"><ChipList values={(instance.serviceDecls ?? []).map((s) => `${s.kind}/${s.impl}`)} empty={instance.services.join(", ") || "Base profile"} /></td>
                        <td className="px-4 py-3.5 font-mono text-xs text-muted">{instance.resources ? `${instance.resources.vcpu} vCPU · ${instance.resources.memoryMb} MB · ${instance.resources.diskGb} GB` : "Runtime default"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          </div>
        ))}

        {tab === "access" && (
          accessEntries.length === 0 ? <EmptyState title="No access information recorded">Connection details, failure context, and plan approval records will appear here when the worker writes them.</EmptyState> : (
            <Panel className="overflow-hidden">
              <PanelHeader title="Access & worker records" description="Values recorded against this deployment. Treat connection data as sensitive." action={<KeyRound size={18} className="text-gold" />} />
              <dl className="divide-y divide-line">
                {accessEntries.map(([key, value]) => (
                  <div key={key} className="grid gap-1 px-4 py-3.5 sm:grid-cols-[220px_1fr] sm:px-5">
                    <dt className="font-mono text-xs text-faint">{key}</dt>
                    <dd className="min-w-0 break-words font-mono text-xs leading-5 text-paper">{String(value)}</dd>
                  </div>
                ))}
              </dl>
            </Panel>
          )
        )}

        {tab === "security" && (!spec ? <EmptyState title="No specification attached">Security design cannot be reconstructed from this deployment record alone.</EmptyState> : (
          <div className="grid gap-4 xl:grid-cols-2">
            <Panel>
              <PanelHeader title="Planted weaknesses" description="Intentional flaws and their proof atoms." />
              <div className="divide-y divide-line">
                {spec.plantedVulns.length === 0 ? <p className="p-5 text-sm text-muted">No planted weaknesses.</p> : spec.plantedVulns.map((v) => (
                  <div key={v.id} className="p-4 sm:p-5">
                    <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-sm text-paper">{v.id}</span><Badge tone="danger">{v.type}</Badge><Badge>{v.techniqueId}</Badge><span className="ml-auto font-mono text-xs text-faint">{v.difficulty}</span></div>
                    <dl className="mt-3 grid gap-2 text-xs text-muted sm:grid-cols-3"><div><dt className="text-faint">Target</dt><dd className="mt-0.5 font-mono text-paper">{v.targetHostId}</dd></div><div><dt className="text-faint">Pinned version</dt><dd className="mt-0.5 font-mono text-paper">{v.pinnedVersion}</dd></div><div><dt className="text-faint">Proof atom</dt><dd className="mt-0.5 break-all font-mono text-paper">{v.proofAtomicGuid}</dd></div></dl>
                  </div>
                ))}
              </div>
            </Panel>
            <Panel>
              <PanelHeader title="Objectives & telemetry" description="Signals the exercise can actually score." />
              <div className="divide-y divide-line">
                <div className="space-y-2 p-4 sm:p-5">
                  {spec.objectives.map((o) => <div key={o.id} className="rounded-md border border-line bg-track p-3.5"><div className="flex flex-wrap items-center gap-2"><span className="font-mono text-sm text-paper">{o.id}</span><Badge tone="gold">{o.techniqueId}</Badge><span className="ml-auto font-mono text-xs text-paper">{o.points} pts</span></div><p className="mt-2 text-sm text-muted">Asset <span className="font-mono text-paper">{o.asset}</span> · Signal <span className="text-paper">{o.successSignal}</span></p></div>)}
                </div>
                <div className="p-4 sm:p-5"><h3 className="mb-2 text-sm font-semibold text-paper">Required telemetry</h3><ChipList values={spec.requiredTelemetry} /></div>
              </div>
            </Panel>
          </div>
        ))}

        {tab === "automation" && (
          <div className="space-y-4">
            <DetailGrid items={[
              { label: "Provider", value: spec?.provider ?? "—" },
              { label: "TTL", value: spec ? `${spec.budgets.ttlHours} hours` : "—" },
              { label: "Instance cap", value: spec ? String(spec.budgets.maxInstances) : "—" },
              { label: "Budget cap", value: spec ? `$${spec.budgets.maxDollarsPerHour}/hr` : "—" },
              { label: "Drift status", value: d.driftStatus ? prettify(d.driftStatus) : "Unknown" },
              { label: "Stack", value: d.stackId || "—", mono: true },
              { label: "Seed", value: spec?.seed ?? "—", mono: true },
              { label: "Difficulty", value: spec ? prettify(spec.difficulty) : "—" },
            ]} />
            <Panel className="p-5">
              <div className="flex items-start gap-3"><RouteIcon size={19} className="mt-0.5 text-cyber" /><div><h2 className="text-sm font-semibold text-paper">Lifecycle automation</h2><p className="mt-1 max-w-3xl text-sm leading-6 text-muted">The worker owns provisioning, configuration, verification, the automatic exercise, scoring, dataset publication, TTL teardown, and drift reporting. This console reflects each persisted transition in real time; it does not simulate a successful deployment.</p></div></div>
            </Panel>
          </div>
        )}

        {tab === "logs" && (
          <Panel>
            <PanelHeader title="Lifecycle log" description="Recorded deployment state plus status transitions received while this page is open." action={<Badge tone="cyber">Realtime</Badge>} />
            <div className="p-4 sm:p-5">
              <ol className="relative space-y-5 border-l border-line pl-6">
                <li className="relative"><span className="absolute -left-[31px] flex h-5 w-5 items-center justify-center rounded-full border border-line bg-panel2 text-cyber"><CircleDot size={12} /></span><p className="font-mono text-[11px] text-faint">{formatDate(d.createdAt)}</p><p className="mt-1 text-sm text-paper">Deployment created with status <strong>{prettify(d.status)}</strong> on stack <span className="font-mono">{d.stackId || "—"}</span>.</p></li>
                {live.length === 0 ? <li className="relative"><span className="absolute -left-[31px] flex h-5 w-5 items-center justify-center rounded-full border border-line bg-panel2 text-faint"><Activity size={12} /></span><p className="text-sm text-muted">Listening for live status changes.</p></li> : live.map((event, i) => (
                  <li key={i} className="relative"><span className="absolute -left-[31px] flex h-5 w-5 items-center justify-center rounded-full border border-mintline bg-mintsurface text-minttext"><Activity size={12} /></span><p className="font-mono text-[11px] text-faint">{event.at}</p><p className="mt-1 text-sm text-paper">{event.text}</p></li>
                ))}
              </ol>
            </div>
          </Panel>
        )}
      </div>
    </div>
  );
}

function ScoreMetric({ label, value, progress, target, inverse = false }: {
  label: string;
  value: string;
  progress?: number;
  target: string;
  inverse?: boolean;
}) {
  const good = progress !== undefined && (inverse ? progress >= 100 : progress >= 70);
  return (
    <div className="bg-panel p-4">
      <p className="text-xs text-muted">{label}</p>
      <p className="mt-2 font-display text-[30px] font-semibold leading-none text-paper">{value}</p>
      <div className="mt-3"><Progress value={progress ?? 0} tone={progress === undefined ? "signal" : good ? "mint" : "gold"} /></div>
      <p className="mt-2 font-mono text-[10px] uppercase tracking-[0.08em] text-faint">{target}</p>
    </div>
  );
}

function RunsPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const runs: Run[] = data ?? [];
  const run = runs[0];
  const events = useLiveRun(run?.runId ?? "", Boolean(run));
  const scored = runs.filter((r) => r.score);

  return (
    <div>
      <PageHeader
        title="Exercises"
        description="Adversarial run evidence, scoring quality, and score updates received through the realtime channel."
        meta={run ? <><Badge tone="cyber">Latest run {shortId(run.runId, 18)}</Badge><Badge tone={run.mode === "adaptive" ? "gold" : "signal"}>{prettify(run.mode)} mode</Badge><Badge>{run.score ? "Scored" : "Awaiting score"}</Badge></> : <Badge>No runs recorded</Badge>}
      />

      {error ? <ErrorState title="Exercises could not be loaded" error={error} /> : isLoading ? <LoadingState what="exercises" rows={5} /> : !run ? (
        <EmptyState title="No exercise runs yet" action={<Link to="/environments" className={secondaryButton}>Open environments <ArrowRight size={15} /></Link>}>Run records will appear here after an environment enters an exercise and writes its first result.</EmptyState>
      ) : (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard label="Recorded runs" value={String(runs.length)} detail="Across this workspace" tone="cyber" />
            <StatCard label="Scored runs" value={String(scored.length)} detail="Runs with complete score records" tone="mint" />
            <StatCard label="Latest mode" value={prettify(run.mode)} detail={run.mode === "blind" ? "Red sees only its own tool output" : "Delayed detection feed enabled"} tone="signal" />
            <StatCard label="Truth / backend" value={run.truthLayer} detail={`Backend ${run.backend} · pack ${run.techniquePackVersion || "—"}`} tone="dim" />
          </div>

          <Panel>
            <PanelHeader
              title="Latest exercise"
              description={<>Run <span className="font-mono text-muted">{run.runId}</span> · deployment <span className="font-mono text-muted">{shortId(run.deploymentId, 20)}</span></>}
              action={<Badge tone={run.score ? "mint" : "gold"}>{run.score ? "Score recorded" : "Awaiting score"}</Badge>}
            />
            {run.score ? (
              <div className="grid gap-px bg-line sm:grid-cols-2 xl:grid-cols-3">
                <ScoreMetric label="Analytic coverage" value={percent(run.score.analyticCoverage)} progress={run.score.analyticCoverage * 100} target="Target ≥ 70%" />
                <ScoreMetric label="Exact technique coverage" value={percent(run.score.exactTechniqueCoverage)} progress={run.score.exactTechniqueCoverage * 100} target="Technique-level match" />
                <ScoreMetric label="Visibility coverage" value={percent(run.score.visibilityCoverage)} progress={run.score.visibilityCoverage * 100} target="Target ≥ 90%" />
                <ScoreMetric label="Median detection time" value={run.score.mttdMinutesP50 === undefined ? "—" : `${run.score.mttdMinutesP50} min`} progress={run.score.mttdMinutesP50 === undefined ? undefined : Math.min(100, (15 / Math.max(run.score.mttdMinutesP50, 0.1)) * 100)} target="Target ≤ 15 min" inverse />
                <ScoreMetric label="Containment correctness" value={percent(run.score.containmentCorrectness)} progress={run.score.containmentCorrectness === undefined ? undefined : run.score.containmentCorrectness * 100} target="Correct response actions" />
                <ScoreMetric label="False-positive rate" value={percent(run.score.falsePositiveRate)} progress={run.score.falsePositiveRate === undefined ? undefined : Math.min(100, (0.1 / Math.max(run.score.falsePositiveRate, 0.001)) * 100)} target="Target ≤ 10%" inverse />
              </div>
            ) : (
              <div className="p-4"><EmptyState title="Score not recorded yet">The latest run exists, but its score has not been written back. The realtime feed below will surface the update.</EmptyState></div>
            )}
          </Panel>

          <div className="grid items-start gap-4 xl:grid-cols-12">
            <Panel className="xl:col-span-5">
              <PanelHeader title="Realtime score feed" description="Only changes received after this page opened. Historical events are not replayed here." action={<Badge tone="cyber">Subscribed</Badge>} />
              <div className="p-4 sm:p-5">
                {events.length === 0 ? (
                  <div className="flex items-start gap-3 text-sm leading-6 text-muted"><Activity size={18} className="mt-0.5 shrink-0 text-cyber" /><p>Listening for updates to run <span className="font-mono text-paper">{shortId(run.runId, 20)}</span>. New score writes will appear in this timeline.</p></div>
                ) : (
                  <ol className="relative space-y-5 border-l border-line pl-6">
                    {events.map((event, i) => (
                      <li key={i} className="relative"><span className="absolute -left-[31px] flex h-5 w-5 items-center justify-center rounded-full border border-mintline bg-mintsurface text-minttext"><Activity size={12} /></span><p className="font-mono text-[11px] text-faint">{event.at}</p><p className="mt-1 break-words text-sm leading-6 text-paper">{event.text}</p></li>
                    ))}
                  </ol>
                )}
              </div>
            </Panel>

            <Panel className="overflow-hidden xl:col-span-7">
              <PanelHeader title="Run registry" description="All exercise records available to this workspace." />
              <div className="overflow-x-auto">
                <table className="w-full min-w-[760px] text-left text-sm">
                  <thead className="bg-track text-xs font-medium text-muted"><tr><th className="px-5 py-3 font-medium">Run</th><th className="px-4 py-3 font-medium">Mode</th><th className="px-4 py-3 font-medium">Backend</th><th className="px-4 py-3 font-medium">Analytic</th><th className="px-4 py-3 font-medium">Visibility</th><th className="px-4 py-3 font-medium">MTTD</th></tr></thead>
                  <tbody className="divide-y divide-line">
                    {runs.map((r) => (
                      <tr key={r.runId} className="hover:bg-track">
                        <td className="px-5 py-3.5"><span className="block font-mono text-xs font-medium text-paper" title={r.runId}>{shortId(r.runId, 20)}</span><span className="mt-0.5 block font-mono text-[10px] text-faint">deployment {shortId(r.deploymentId, 16)}</span></td>
                        <td className="px-4 py-3.5"><Badge tone={r.mode === "adaptive" ? "gold" : "signal"}>{r.mode}</Badge></td>
                        <td className="px-4 py-3.5 font-mono text-xs text-muted">{r.backend}</td>
                        <td className="px-4 py-3.5 font-mono text-paper">{percent(r.score?.analyticCoverage)}</td>
                        <td className="px-4 py-3.5 font-mono text-paper">{percent(r.score?.visibilityCoverage)}</td>
                        <td className="px-4 py-3.5 font-mono text-paper">{r.score?.mttdMinutesP50 === undefined ? "—" : `${r.score.mttdMinutesP50} min`}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          </div>
        </div>
      )}
    </div>
  );
}

function riskTone(risk: Persona["riskProfile"]) {
  return risk === "high" ? "danger" as const : risk === "medium" ? "gold" as const : "mint" as const;
}

function PersonasPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ["personas-by-env"], queryFn: api.personasByEnvironment });
  const groups = data ?? [];
  const [envFilter, setEnvFilter] = useState<string>("all");
  const selected = envFilter === "all" ? groups : groups.filter((g) => g.environmentId === envFilter);
  const personas = selected.flatMap((g) => g.personas);
  const highRisk = personas.filter((p) => p.riskProfile === "high").length;
  const weakCreds = personas.filter((p) => ["weak", "reused"].includes(p.credentialsProfile.toLowerCase())).length;
  const workstations = new Set(personas.map((p) => p.workstation)).size;

  return (
    <div>
      <PageHeader
        title="Personas"
        description="The people who inhabit generated organizations — grouped by the environment that generated them, since every cast belongs to one design."
        meta={<><Badge tone="cyber">{personas.length} personas</Badge><Badge tone="dim">{groups.length} environments</Badge><Badge tone={highRisk ? "danger" : "dim"}>{highRisk} high risk</Badge><Badge tone={weakCreds ? "gold" : "dim"}>{weakCreds} weak/reused credentials</Badge></>}
      />
      {error ? <ErrorState title="Personas could not be loaded" error={error} /> : isLoading ? <LoadingState what="personas" rows={5} /> : personas.length === 0 ? (
        <EmptyState title="No personas found" action={<Link to="/designer" className={primaryButton}><FileCode2 size={16} /> Design an organization</Link>}>Personas are derived from environment specifications saved in this workspace.</EmptyState>
      ) : (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-4">
            <StatCard label="Cast size" value={String(personas.length)} detail={envFilter === "all" ? "Across all recent environments" : "In the selected environment"} tone="cyber" />
            <StatCard label="Environments" value={String(selected.length)} detail="Designs with a persona cast" tone="dim" />
            <StatCard label="Workstations" value={String(workstations)} detail="Hosts with at least one assigned persona" tone="dim" />
            <StatCard label="Credential exposure" value={String(weakCreds)} detail="Weak or reused credential profiles" tone={weakCreds ? "danger" : "mint"} />
          </div>
          <label className="flex items-center gap-2 text-xs font-medium text-muted">
            Environment
            <select value={envFilter} onChange={(e) => setEnvFilter(e.target.value)} className="max-w-[420px] rounded-lg border border-line bg-panel px-3 py-2 font-mono text-xs text-paper shadow-sm outline-none focus:border-linestrong" aria-label="Filter personas by environment">
              <option value="all">All environments ({groups.length})</option>
              {groups.map((g) => (<option key={g.environmentId} value={g.environmentId}>{g.specName || "unnamed"} · {shortId(g.environmentId, 8)} ({g.personas.length})</option>))}
            </select>
          </label>
          {selected.map((group) => (
          <Panel key={group.environmentId} className="overflow-hidden">
            <PanelHeader title={group.specName || "Unnamed environment"} description={`${group.personas.length} personas · created ${formatDate(group.createdAt)} · spec ${shortId(group.environmentId, 12)}`} />
            <div className="overflow-x-auto">
              <table className="w-full min-w-[980px] text-left text-sm">
                <thead className="bg-track text-xs font-medium text-muted"><tr><th className="px-5 py-3 font-medium">Persona</th><th className="px-4 py-3 font-medium">Workstation</th><th className="px-4 py-3 font-medium">Access</th><th className="px-4 py-3 font-medium">Credentials</th><th className="px-4 py-3 font-medium">Routine</th><th className="px-4 py-3 font-medium">Risk</th></tr></thead>
                <tbody className="divide-y divide-line">
                  {group.personas.map((persona) => (
                    <tr key={persona.id} className="hover:bg-track">
                      <td className="px-5 py-4"><div className="flex items-center gap-3"><span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-line bg-panel2 font-mono text-[11px] font-semibold text-cyber">{persona.role.split(/\s+/).slice(0, 2).map((w) => w[0]).join("").toUpperCase() || "P"}</span><span><span className="block font-medium text-paper">{prettify(persona.role)}</span><span className="mt-0.5 block font-mono text-[10px] text-faint">{persona.id} · {persona.relationships.length} relationships</span></span></div></td>
                      <td className="px-4 py-4 font-mono text-xs text-muted">{persona.workstation}</td>
                      <td className="px-4 py-4"><ChipList values={persona.access} empty="No declared access" /></td>
                      <td className="px-4 py-4"><Badge tone={["weak", "reused"].includes(persona.credentialsProfile.toLowerCase()) ? "gold" : "dim"}>{persona.credentialsProfile}</Badge></td>
                      <td className="max-w-[280px] px-4 py-4 leading-6 text-muted">{persona.routine}</td>
                      <td className="px-4 py-4"><Badge tone={riskTone(persona.riskProfile)}>{persona.riskProfile}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
          ))}
        </div>
      )}
    </div>
  );
}

function TemplatesPage() {
  const { data, isLoading, error, refetch } = useQuery({ queryKey: ["templates"], queryFn: api.templates });
  const [open, setOpen] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const templates = data ?? [];
  const shared = templates.filter((t) => t.shared).length;

  async function share(id: string, digest: string) {
    setActionError(null);
    try {
      await api.shareTemplate(id, digest.replace("sha256:", ""));
      await refetch();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    }
  }

  async function remove(id: string) {
    setActionError(null);
    try {
      await api.deleteTemplate(id);
      setConfirmDelete(null);
      await refetch();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div>
      <PageHeader
        title="Template library"
        description="Versioned, reusable environment designs saved from checked Designer artifacts."
        actions={<Link to="/designer" className={primaryButton}><FileCode2 size={16} /> Create template</Link>}
        meta={<><Badge tone="cyber">{templates.length} templates</Badge><Badge tone={shared ? "gold" : "dim"}>{shared} shared</Badge></>}
      />
      {error ? <ErrorState title="Templates could not be loaded" error={error} /> : isLoading ? <LoadingState what="templates" rows={4} /> : templates.length === 0 ? (
        <EmptyState title="No templates saved" action={<Link to="/designer" className={primaryButton}><FileCode2 size={16} /> Open Designer</Link>}>Save a validated design as a template and it will be versioned here for reuse and sharing.</EmptyState>
      ) : (
        <div className="space-y-4">
          {actionError && <ErrorState title="Template action failed" error={new Error(actionError)} />}
          <div className="grid gap-4 xl:grid-cols-2">
            {templates.map((template) => (
              <Panel key={template.id} className="overflow-hidden">
                <div className="p-5">
                  <div className="flex items-start gap-3">
                    <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-line bg-panel2 text-signal"><Library size={18} /></span>
                    <div className="min-w-0 flex-1">
                      <h2 className="truncate text-base font-semibold text-paper">{template.name}</h2>
                      <p className="mt-1 font-mono text-[11px] text-faint">v{template.version} · {template.family} · {formatDate(template.createdAt)}</p>
                    </div>
                    <Badge tone={template.shared ? "gold" : "dim"}>{template.shared ? "Shared" : "Workspace"}</Badge>
                  </div>

                  <dl className="mt-5 grid grid-cols-3 gap-3 border-y border-line py-4 text-center">
                    <div><dt className="text-[11px] text-faint">Hosts</dt><dd className="mt-1 font-display text-2xl font-semibold text-paper">{template.spec.instances.length}</dd></div>
                    <div><dt className="text-[11px] text-faint">Personas</dt><dd className="mt-1 font-display text-2xl font-semibold text-paper">{template.spec.personas.length}</dd></div>
                    <div><dt className="text-[11px] text-faint">Objectives</dt><dd className="mt-1 font-display text-2xl font-semibold text-paper">{template.spec.objectives.length}</dd></div>
                  </dl>
                  <p className="mt-4 break-all font-mono text-[11px] leading-5 text-faint" title={template.digest}>Digest {shortId(template.digest, 42)}</p>
                  {template.shared && template.shareToken && (
                    <div className="mt-3 rounded-md border border-goldline bg-goldsurface px-3 py-2.5">
                      <p className="text-[11px] font-medium text-gold">Share token</p>
                      <p className="mt-1 break-all font-mono text-xs text-goldtext">{template.shareToken}</p>
                    </div>
                  )}

                  <div className="mt-5 flex flex-wrap gap-2">
                    <button onClick={() => setOpen(open === template.id ? null : template.id)} className={compactButton}><Braces size={14} /> {open === template.id ? "Hide spec" : "View spec"}</button>
                    {!template.shared && <button onClick={() => void share(template.id, template.digest)} className={compactButton}>Share</button>}
                    {confirmDelete === template.id ? (
                      <>
                        <button onClick={() => void remove(template.id)} className="inline-flex items-center justify-center gap-1.5 rounded-md bg-danger px-2.5 py-1.5 text-xs font-semibold text-dangercontrast">Confirm delete</button>
                        <button onClick={() => setConfirmDelete(null)} className={compactButton}>Cancel</button>
                      </>
                    ) : (
                      <button onClick={() => setConfirmDelete(template.id)} className="inline-flex items-center justify-center gap-1.5 rounded-md border border-dangerline bg-dangersurface px-2.5 py-1.5 text-xs font-medium text-dangertext">Delete</button>
                    )}
                  </div>
                </div>
                {open === template.id && <pre className="max-h-[420px] overflow-auto border-t border-line bg-track p-4 font-mono text-[11px] leading-5 text-muted">{JSON.stringify(template.spec, null, 2)}</pre>}
              </Panel>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function TracesPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ["datasets"], queryFn: api.datasets });
  const datasets = data ?? [];
  const splits = new Set(datasets.map((d) => d.split)).size;
  const latest = datasets[0];

  return (
    <div>
      <PageHeader
        title="Traces & datasets"
        description="Immutable exercise exports with provenance, redaction policy, split, and content identity."
        meta={<><Badge tone="cyber">{datasets.length} exports</Badge><Badge>{splits} splits represented</Badge>{latest && <Badge tone="mint">Latest {formatDate(latest.createdAt)}</Badge>}</>}
      />
      {error ? <ErrorState title="Dataset exports could not be loaded" error={error} /> : isLoading ? <LoadingState what="dataset exports" rows={5} /> : datasets.length === 0 ? (
        <EmptyState title="No dataset exports yet">Completed and exported exercises will appear here as immutable dataset records.</EmptyState>
      ) : (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-3">
            <StatCard label="Exports" value={String(datasets.length)} detail="Immutable dataset records" tone="cyber" />
            <StatCard label="Splits" value={String(splits)} detail={[...new Set(datasets.map((d) => d.split))].join(" · ") || "No split recorded"} tone="dim" />
            <StatCard label="Latest export" value={latest ? formatDate(latest.createdAt).split(",")[0] : "—"} detail={latest ? `Format v${latest.formatVersion} · ${latest.name}` : "No export recorded"} tone="mint" />
          </div>

          <Panel className="overflow-hidden">
            <PanelHeader title="Dataset registry" description="Exports are treated as evidence artifacts, not mutable files." />
            <div className="overflow-x-auto">
              <table className="w-full min-w-[980px] text-left text-sm">
                <thead className="bg-track text-xs font-medium text-muted"><tr><th className="px-5 py-3 font-medium">Dataset</th><th className="px-4 py-3 font-medium">Split</th><th className="px-4 py-3 font-medium">Format</th><th className="px-4 py-3 font-medium">Redaction</th><th className="px-4 py-3 font-medium">Created</th><th className="px-4 py-3 font-medium">Content hash</th></tr></thead>
                <tbody className="divide-y divide-line">
                  {datasets.map((dataset) => (
                    <tr key={dataset.id} className="hover:bg-track">
                      <td className="px-5 py-4"><div className="flex items-center gap-3"><span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-line bg-panel2 text-mint"><Database size={17} /></span><span className="min-w-0"><span className="block truncate font-medium text-paper">{dataset.name}</span><span className="mt-0.5 block max-w-[360px] truncate font-mono text-[10px] text-faint" title={dataset.storagePath}>{dataset.storagePath}</span></span></div></td>
                      <td className="px-4 py-4"><Badge tone="cyber">{dataset.split}</Badge></td>
                      <td className="px-4 py-4 font-mono text-xs text-muted">v{dataset.formatVersion}</td>
                      <td className="px-4 py-4 font-mono text-xs text-muted">{dataset.redactionPolicyVersion}</td>
                      <td className="px-4 py-4 text-muted">{formatDate(dataset.createdAt)}</td>
                      <td className="px-4 py-4"><span className="break-all font-mono text-[11px] text-mint" title={dataset.contentHash}>{shortId(dataset.contentHash, 28)}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel className="p-5">
            <div className="flex items-start gap-3">
              <Shield size={19} className="mt-0.5 shrink-0 text-mint" />
              <div>
                <h2 className="text-sm font-semibold text-paper">Evidence model</h2>
                <p className="mt-1 max-w-4xl text-sm leading-6 text-muted">Trajectories live in Langfuse, ground truth in the hash-chained store, and both join by run ID at export. Proof and noise rows remain labelled rather than silently dropped.</p>
              </div>
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}

function SettingRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-2 px-5 py-3.5">
      <dt className="text-sm text-muted">{label}</dt>
      <dd className={`max-w-[62%] break-all text-right text-sm text-paper ${mono ? "font-mono text-xs" : ""}`}>{value}</dd>
    </div>
  );
}

function SettingsPage() {
  const { session, signOut } = useSession();
  const designerUrl = (import.meta as { env?: Record<string, string> }).env?.VITE_DESIGN_API_URL ?? "Not configured";

  return (
    <div>
      <PageHeader
        title="Settings"
        description="Workspace identity, console configuration, and access for this session."
        meta={<><Badge tone={clerkEnabled ? "mint" : "danger"}>{clerkEnabled ? "Authentication enabled" : "Authentication not configured"}</Badge><Badge>Designer connected at build time</Badge></>}
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel>
          <PanelHeader title="Workspace" description="The organization that owns designs, deployments, and datasets." />
          <dl className="divide-y divide-line">
            <SettingRow label="Organization" value={session?.orgName ?? "No workspace"} />
            <SettingRow label="Organization ID" value={session?.orgId ?? "—"} mono />
            <SettingRow label="Role" value={session?.role ?? "—"} />
            <SettingRow label="Signed-in email" value={session?.email || "—"} />
            <SettingRow label="User ID" value={session?.userId ?? "—"} mono />
          </dl>
        </Panel>

        <Panel>
          <PanelHeader title="Console" description="Runtime configuration baked into this build." />
          <dl className="divide-y divide-line">
            <SettingRow label="Designer endpoint" value={designerUrl} mono />
            <SettingRow label="Authentication" value={clerkEnabled ? "Clerk session" : "Not configured"} />
            <SettingRow label="Access model" value="Session-scoped workspace data" />
            <SettingRow label="Interface" value="Light operations console" />
          </dl>
          <div className="flex flex-wrap items-center gap-2 border-t border-line px-5 py-4">
            <button onClick={signOut} className={secondaryButton}><LogOut size={16} /> Sign out</button>
            <p className="text-xs leading-5 text-faint">Signing out clears the Clerk session for this browser.</p>
          </div>
        </Panel>
      </div>
    </div>
  );
}

function LoginPage() {
  const { session } = useSession();
  if (session) return <Navigate to="/" replace />;

  return (
    <main className="grid min-h-dvh bg-ink text-paper lg:grid-cols-[1.15fr_0.85fr]">
      <section className="relative hidden overflow-hidden border-r border-line bg-panel2 p-10 lg:flex lg:flex-col xl:p-14">
        <div className="flex items-center gap-3"><BrandMark size={42} /><div><p className="font-display text-[23px] font-semibold leading-none">MuseArena</p><p className="mt-1.5 text-[11px] font-medium text-faint">Adversarial operations</p></div></div>

        <div className="my-auto max-w-2xl py-16">
          <h1 className="font-display text-[46px] font-semibold leading-[1.02] tracking-[-0.035em]">Environments designed to be attacked. Evidence built to be trusted.</h1>
          <p className="mt-5 max-w-xl text-base leading-7 text-muted">Generate complete virtual organizations, review the exact build plan, run adversarial exercises, and export trace datasets with verifiable ground truth.</p>

          <svg viewBox="0 0 680 230" className="mt-10 w-full" role="img" aria-label="Static network topology illustration">
            <rect x={8} y={8} width={664} height={214} rx={12} fill="var(--panel)" stroke="var(--line)" />
            <text x={24} y={34} fontSize={11} fill="var(--faint)" className="mono">LAB SEGMENT · 10.42.0.0/20</text>
            <line x1={58} y1={66} x2={622} y2={66} stroke="var(--linestrong)" strokeWidth={1.5} />
            {[
              { x: 42, code: "AT", name: "attacker", color: "var(--gold)" },
              { x: 190, code: "GW", name: "gateway", color: "var(--cyber)" },
              { x: 338, code: "DC", name: "directory", color: "var(--violet-text)" },
              { x: 486, code: "DB", name: "records", color: "var(--mint)" },
            ].map((node) => (
              <g key={node.code}>
                <line x1={node.x + 66} y1={66} x2={node.x + 66} y2={112} stroke="var(--linestrong)" />
                <circle cx={node.x + 66} cy={66} r={3} fill="var(--cyber)" />
                <rect x={node.x} y={112} width={132} height={66} rx={8} fill="var(--panel)" stroke="var(--line)" />
                <rect x={node.x + 12} y={128} width={34} height={34} rx={6} fill={node.color} fillOpacity={0.12} stroke={node.color} strokeOpacity={0.4} />
                <text x={node.x + 29} y={150} textAnchor="middle" fontSize={11} fontWeight={700} fill={node.color} className="mono">{node.code}</text>
                <text x={node.x + 56} y={141} fontSize={11.5} fontWeight={650} fill="var(--paper)">{node.name}</text>
                <text x={node.x + 56} y={157} fontSize={9.5} fill="var(--faint)">verified host</text>
              </g>
            ))}
            <path d="M 174 145 C 220 112, 250 112, 322 145" fill="none" stroke="var(--cyber)" strokeOpacity={0.7} />
            <path d="M 470 145 C 500 120, 512 120, 486 145" fill="none" stroke="var(--gold)" strokeDasharray="5 4" />
            <text x={24} y={205} fontSize={9.5} fill="var(--faint)" className="mono">STATIC TOPOLOGY · DECLARED FLOWS · PROVABLE OBJECTIVES</text>
          </svg>
        </div>

        <div className="grid grid-cols-4 gap-px overflow-hidden rounded-lg border border-line bg-line text-center">
          {["Design", "Deploy", "Exercise", "Export"].map((step, i) => <div key={step} className="bg-panel px-3 py-3"><p className="font-mono text-[10px] text-muted">0{i + 1}</p><p className="mt-1 text-xs font-semibold text-paper">{step}</p></div>)}
        </div>
      </section>

      <section className="flex items-center justify-center px-5 py-10 sm:px-10">
        <div className="w-full max-w-md">
          <div className="mb-8 flex items-center gap-3 lg:hidden"><BrandMark size={40} /><div><p className="font-display text-xl font-semibold leading-none">MuseArena</p><p className="mt-1 text-[11px] font-medium text-faint">Adversarial operations</p></div></div>
          <Panel className="p-6 shadow-panel sm:p-8">
            <p className="text-xs font-medium text-muted">Secure console</p>
            <h2 className="mt-2 text-2xl font-semibold leading-tight tracking-[-0.02em]">Sign in</h2>
            <p className="mt-3 text-sm leading-6 text-muted">Use your Clerk account to access the workspace. Designer calls, deployment records, and realtime updates are scoped to your session.</p>
            <div className="mt-7">
              {clerkEnabled ? <ClerkControls /> : (
                <div role="alert" className="rounded-lg border border-dangerline bg-dangersurface p-4 text-sm leading-6 text-dangertext">Authentication is not configured. Set `VITE_CLERK_PUBLISHABLE_KEY` and restart the application. There is no demo sign-in.</div>
              )}
            </div>
            <div className="mt-8 border-t border-line pt-5">
              <p className="flex items-start gap-2 text-xs leading-5 text-faint"><Shield size={15} className="mt-0.5 shrink-0 text-mint" /> Access is verified before model calls or workspace data are served.</p>
            </div>
          </Panel>
        </div>
      </section>
    </main>
  );
}

function AuthBoundary({ children }: { children: ReactNode }) {
  return clerkEnabled ? <ClerkAuthProvider publishableKey={clerkKey}>{children}</ClerkAuthProvider> : <>{children}</>;
}

export default function App() {
  return (
    <AuthBoundary>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/*" element={<Protected><Layout>
          <Routes>
            <Route index element={<OverviewPage />} />
            <Route path="designer" element={<DesignerPage />} />
            <Route path="environments" element={<EnvironmentsPage />} />
            <Route path="environments/:id" element={<EnvironmentDetailPage />} />
            <Route path="runs" element={<RunsPage />} />
            <Route path="red" element={<RedTeamPage />} />
            <Route path="blue" element={<BlueTeamPage />} />
            <Route path="monitoring" element={<MonitoringPage />} />
            <Route path="personas" element={<PersonasPage />} />
            <Route path="traces" element={<TracesPage />} />
            <Route path="learning" element={<LearningPage />} />
            <Route path="templates" element={<TemplatesPage />} />
            <Route path="admin" element={<AdminPage />} />
            <Route path="settings" element={<SettingsPage />} />
          </Routes>
        </Layout></Protected>} />
      </Routes>
    </AuthBoundary>
  );
}
