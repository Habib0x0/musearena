import React, { useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  Loader2,
  Check,
  Search,
  FileText,
  BrainCircuit,
  AlertTriangle,
  Code,
  TerminalSquare,
} from "lucide-react";

/**
 * AgentPlanning — collapsible agent run timeline (integrated from the supplied
 * shadcn-style component; adapted to this app's Tailwind tokens and to live
 * streaming: steps arriving after first render still get sensible expansion).
 */

export type PlanStepStatus = "pending" | "active" | "success" | "error";

export interface PlanStep {
  id: string;
  title: string;
  content?: React.ReactNode;
  status: PlanStepStatus;
  icon?: React.ReactNode;
  duration?: string;
  defaultExpanded?: boolean;
}

export interface AgentPlanningProps {
  title?: string;
  steps?: PlanStep[];
}

const DEFAULT_STEPS: PlanStep[] = [
  {
    id: "1",
    title: "Analyze request and extract constraints",
    status: "success",
    duration: "0.4s",
    icon: <Search className="h-3.5 w-3.5" />,
    content: (
      <div className="mt-2 space-y-2 font-mono text-[11px] text-muted">
        <div className="flex items-start gap-2 font-medium text-minttext">
          <Check className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>Parsed user intent: Build minimalist UI Component</span>
        </div>
        <div className="mt-3 grid grid-cols-[80px_1fr] gap-1.5 rounded-md border border-line bg-panel2 p-2.5">
          <span className="font-medium text-faint">Language:</span>
          <span className="text-paper">TypeScript, React</span>
          <span className="font-medium text-faint">Styling:</span>
          <span className="text-paper">Tailwind CSS</span>
          <span className="font-medium text-faint">Constraints:</span>
          <span className="text-goldtext">Single-file, Interactive, No Overlaps</span>
        </div>
      </div>
    ),
  },
  {
    id: "2",
    title: "Search UI knowledge base",
    status: "success",
    duration: "1.2s",
    icon: <FileText className="h-3.5 w-3.5" />,
    content: (
      <div className="mt-2 space-y-3 font-mono text-[11px]">
        <div className="flex items-center gap-2">
          <span className="text-muted">Executing tool:</span>
          <span className="flex items-center gap-1 rounded-md border border-violetline bg-violetsurface px-1.5 py-0.5 font-semibold text-violettext">
            <TerminalSquare className="h-3 w-3" />
            vector_search
          </span>
        </div>
        <div className="rounded-md border border-line bg-panel p-3 text-muted shadow-sm">
          <div className="mb-2 font-semibold text-minttext">Success: Retrieved 3 semantic patterns</div>
          <ul className="list-inside list-disc space-y-1.5">
            <li>Muse reasoning panel layout</li>
            <li>Tailwind flex-timeline micro-interactions</li>
            <li>React state-driven accordions</li>
          </ul>
        </div>
      </div>
    ),
  },
  {
    id: "3",
    title: "Synthesize component logic",
    status: "active",
    duration: "...",
    icon: <BrainCircuit className="h-3.5 w-3.5" />,
    defaultExpanded: true,
    content: (
      <div className="mt-2 space-y-3 font-mono text-[11px]">
        <div className="flex items-center gap-2 font-medium text-cybertext">
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          <span>Generating structured timeline layout...</span>
        </div>
        <div className="relative overflow-hidden rounded-md border border-line bg-terminal p-3.5 shadow-inner">
          <div className="space-y-1.5 leading-relaxed text-faint">
            <div><span className="text-violettext">const</span> <span className="text-cybertext">timelineLayout</span> = <span className="text-goldtext">useMemo</span>(...)</div>
            <div className="pl-4">- Fixing absolute positioning overlaps</div>
            <div className="pl-4">- Applying distinct icon columns</div>
          </div>
        </div>
      </div>
    ),
  },
  {
    id: "4",
    title: "Review dependency conflicts",
    status: "error",
    duration: "0.8s",
    icon: <AlertTriangle className="h-3.5 w-3.5" />,
    content: (
      <div className="mt-2 space-y-2 font-mono text-[11px]">
        <div className="rounded-md border border-dangerline bg-dangersurface p-3">
          <div className="mb-1 flex items-center gap-1.5 font-bold text-dangertext">
            <AlertTriangle className="h-3.5 w-3.5" />
            Warning: Component styling deviation
          </div>
          <div className="leading-relaxed text-dangertext">
            Previous absolute positioning caused icon overlaps. Sub-agent is resolving layout tree to a strict flex-row grid before continuing execution.
          </div>
        </div>
      </div>
    ),
  },
  {
    id: "5",
    title: "Execute final rendering",
    status: "pending",
    icon: <Code className="h-3.5 w-3.5" />,
  },
];

export const AgentPlanning: React.FC<AgentPlanningProps> = ({
  title = "Agent is planning",
  steps = DEFAULT_STEPS,
}) => {
  const [isMainExpanded, setIsMainExpanded] = useState(true);

  // Track expanded state of individual step details. Steps that arrive after
  // first render (live streams) fall back to their own default below.
  const [expandedSteps, setExpandedSteps] = useState<Record<string, boolean>>(
    steps.reduce((acc, step) => {
      acc[step.id] = step.defaultExpanded || false;
      return acc;
    }, {} as Record<string, boolean>),
  );

  const toggleStep = (id: string, currentlyExpanded: boolean, e: React.MouseEvent) => {
    e.stopPropagation();
    setExpandedSteps((prev) => ({ ...prev, [id]: !currentlyExpanded }));
  };

  const hasActive = steps.some((s) => s.status === "active");
  const hasError = steps.some((s) => s.status === "error");
  const allSuccess = steps.length > 0 && steps.every((s) => s.status === "success");

  const getStatusColor = (status: PlanStepStatus) => {
    switch (status) {
      case "success": return "bg-mintsurface text-minttext ring-mintline";
      case "active": return "bg-cybersurface text-cybertext ring-cyberline";
      case "error": return "bg-dangersurface text-dangertext ring-dangerline";
      case "pending": return "bg-panel2 text-muted ring-line";
    }
  };

  return (
    <div className="w-full font-sans text-paper">
      <div className="overflow-hidden rounded-xl border border-line bg-panel shadow-sm">
        {/* Header / trigger */}
        <div
          onClick={() => setIsMainExpanded(!isMainExpanded)}
          className={`flex cursor-pointer select-none items-center justify-between px-4 py-3.5 ${
            isMainExpanded ? "border-b border-line bg-panel2/60" : "hover:bg-panel2/60"
          }`}
        >
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-5 w-5 shrink-0 items-center justify-center">
              {hasActive ? (
                <Loader2 className="h-4 w-4 animate-spin text-cybertext" />
              ) : allSuccess ? (
                <Check className="h-4 w-4 text-minttext" />
              ) : hasError ? (
                <AlertTriangle className="h-4 w-4 text-goldtext" />
              ) : (
                <BrainCircuit className="h-4 w-4 text-muted" />
              )}
            </div>
            <span className="truncate text-[15px] font-semibold tracking-tight text-paper">{title}</span>
          </div>
          <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md text-muted hover:bg-panel2">
            {isMainExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </div>
        </div>

        {/* Expandable timeline */}
        <div className={`grid bg-panel ${isMainExpanded ? "grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0"}`}>
          <div className="overflow-hidden">
            <div className="flex flex-col p-5">
              {steps.map((step, index) => {
                const isStepExpanded = expandedSteps[step.id] ?? (step.defaultExpanded || step.status === "active");
                const isLast = index === steps.length - 1;
                return (
                  <div
                    key={step.id}
                    className={`relative flex gap-4 ${step.status === "pending" ? "opacity-60" : "opacity-100"}`}
                  >
                    {!isLast && <div className="absolute bottom-[-10px] left-[11px] top-7 z-0 w-[2px] bg-line" />}

                    <div className="relative z-10 mt-0.5 h-6 w-6 flex-none">
                      <div className={`flex h-full w-full items-center justify-center rounded-full ring-4 ring-panel ${getStatusColor(step.status)}`}>
                        {step.status === "success" ? (
                          <Check className="h-3.5 w-3.5" />
                        ) : step.status === "active" ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          step.icon || <div className="h-1.5 w-1.5 rounded-full bg-current" />
                        )}
                      </div>
                    </div>

                    <div className="min-w-0 flex-1 pb-6">
                      <div
                        className={`group -mx-2 flex items-center justify-between gap-2 rounded-md px-2 py-1 ${step.content ? "cursor-pointer hover:bg-panel2" : ""}`}
                        onClick={(e) => step.content && toggleStep(step.id, isStepExpanded, e)}
                      >
                        <span className={`text-[14px] tracking-tight ${
                          step.status === "active" ? "font-semibold text-paper"
                          : step.status === "error" ? "font-semibold text-dangertext"
                          : "font-medium text-paper/80 group-hover:text-paper"
                        }`}>
                          {step.title}
                        </span>
                        <div className="flex shrink-0 items-center gap-3">
                          {step.duration && (
                            <span className="font-mono text-[11px] tabular-nums text-muted">{step.duration}</span>
                          )}
                          {step.content && (
                            <div className="text-faint group-hover:text-muted">
                              {isStepExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                            </div>
                          )}
                        </div>
                      </div>

                      {step.content && (
                        <div className={`grid ${isStepExpanded ? "mt-2 grid-rows-[1fr] opacity-100" : "mt-0 grid-rows-[0fr] opacity-0"}`}>
                          <div className="overflow-hidden">
                            <div className="pb-2 pt-1">{step.content}</div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AgentPlanning;

