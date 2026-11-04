import type { ReactNode } from "react";
import { AlertTriangle, Inbox } from "lucide-react";
import type { Tone } from "../lib/format";

const toneClasses: Record<Tone, string> = {
  signal: "border-line bg-panel2 text-paper",
  mint: "border-mintline bg-mintsurface text-minttext",
  gold: "border-goldline bg-goldsurface text-goldtext",
  danger: "border-dangerline bg-dangersurface text-dangertext",
  cyber: "border-cyberline bg-cybersurface text-cybertext",
  dim: "border-line bg-track text-muted",
};

export function Badge({ children, tone = "dim" }: { children: ReactNode; tone?: Tone }) {
  return <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-2 py-0.5 text-[11px] font-medium ${toneClasses[tone]}`}>{children}</span>;
}

export function PageHeader({ title, description, actions, meta }: {
  title: string;
  description?: string;
  actions?: ReactNode;
  meta?: ReactNode;
}) {
  return (
    <header className="animate-fade-up mb-6 flex flex-wrap items-end gap-4">
      <div className="min-w-0 flex-1">
        <h1 className="text-2xl font-semibold leading-tight tracking-[-0.02em] text-paper max-sm:text-xl">{title}</h1>
        {description && <p className="mt-1.5 max-w-3xl text-sm leading-6 text-muted">{description}</p>}
        {meta && <div className="mt-3 flex flex-wrap gap-2">{meta}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

export function Panel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`ops-panel transition-shadow duration-200 ${className}`}>{children}</section>;
}

export function PanelHeader({ title, description, action }: { title: string; description?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start gap-3 border-b border-line px-5 py-4">
      <div className="min-w-0 flex-1">
        <h2 className="text-sm font-semibold text-paper">{title}</h2>
        {description && <p className="mt-0.5 text-xs leading-5 text-muted">{description}</p>}
      </div>
      {action}
    </div>
  );
}

export function StatCard({ label, value, detail, tone = "dim", progress }: {
  label: string;
  value: string;
  detail: string;
  tone?: Tone;
  progress?: number;
}) {
  const bar = tone === "mint" ? "bg-mint" : tone === "danger" ? "bg-danger" : tone === "gold" ? "bg-gold" : tone === "cyber" ? "bg-cyber" : "bg-signal";
  return (
    <div className="ops-panel min-w-0 p-5">
      <div className="flex items-start justify-between gap-3">
        <p className="text-xs font-medium text-muted">{label}</p>
        <span className={`mt-1 h-1.5 w-1.5 rounded-full ${bar}`} aria-hidden="true" />
      </div>
      <p className="mt-2 text-3xl font-semibold leading-none tracking-[-0.03em] text-paper">{value}</p>
      <p className="mt-2 text-xs leading-5 text-faint">{detail}</p>
      {progress !== undefined && (
        <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-panel2" aria-hidden="true">
          <div className={`h-full rounded-full ${bar}`} style={{ width: `${Math.max(0, Math.min(100, progress))}%` }} />
        </div>
      )}
    </div>
  );
}

export function LoadingState({ what, rows = 3 }: { what: string; rows?: number }) {
  return (
    <div className="ops-panel p-5" role="status" aria-label={`Loading ${what}`}>
      <p className="mb-4 text-xs font-medium text-muted">Loading {what}</p>
      <div className="space-y-2">
        {Array.from({ length: rows }, (_, i) => <div key={i} className="h-10 animate-pulse rounded-md bg-panel2" />)}
      </div>
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="ops-panel animate-fade-up flex min-h-52 flex-col items-start justify-center p-8">
      <span className="mb-4 flex h-10 w-10 items-center justify-center rounded-lg border border-line bg-panel2 text-faint"><Inbox size={18} /></span>
      <h2 className="text-base font-semibold text-paper">{title}</h2>
      {children && <div className="mt-1 max-w-xl text-sm leading-6 text-muted">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorState({ title, error }: { title: string; error: unknown }) {
  return (
    <div role="alert" className="animate-fade-up rounded-xl border border-dangerline bg-dangersurface p-4 text-sm">
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 shrink-0 text-dangertext" size={18} />
        <div>
          <h2 className="font-semibold text-dangertext">{title}</h2>
          <p className="mt-1 break-words leading-6 text-dangertext">{error instanceof Error ? error.message : String(error)}</p>
        </div>
      </div>
    </div>
  );
}

export function PrimaryLink({ href, children }: { href: string; children: ReactNode }) {
  return <a href={href} className="inline-flex items-center gap-2 rounded-lg bg-signal px-3.5 py-2 text-sm font-medium text-signalcontrast shadow-sm hover:bg-signalhover">{children}</a>;
}
