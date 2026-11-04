import type { EnvironmentSpec } from "@musearena/shared";

type Instance = EnvironmentSpec["instances"][number];

export interface TopologyGroupInput {
  id: string;
  name: string;
  cidr: string;
  zone: string;
  instances: Instance[];
}

export interface TopologyFlowInput {
  from: string;
  to: string;
  label: string;
  detail?: string;
  kind: "service" | "dependency";
}

interface PositionedNode {
  instance: Instance;
  groupId: string;
  x: number;
  y: number;
}

const NODE_W = 190;
const NODE_H = 68;
const COL_GAP = 34;
const ROW_GAP = 28;
const OUTER_X = 18;
const HEADER_H = 58;

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

function nodeKind(instance: Instance): { code: string; rank: number; color: string } {
  const role = instance.role.toLowerCase();
  const kinds = new Set([...(instance.serviceDecls ?? []).map((d) => d.kind), ...instance.services.map((s) => s.toLowerCase())]);
  if (role === "attacker") return { code: "AT", rank: 0, color: "var(--gold)" };
  if (role === "router" || kinds.has("router")) return { code: "RT", rank: 1, color: "var(--cyber)" };
  if (role === "gateway" || kinds.has("dns")) return { code: "GW", rank: 2, color: "var(--cyber)" };
  if (role === "dc" || kinds.has("ldap")) return { code: "DC", rank: 3, color: "var(--violet-text)" };
  if (role === "mail" || kinds.has("smtp") || kinds.has("imap")) return { code: "ML", rank: 4, color: "var(--gold-text)" };
  if (kinds.has("git")) return { code: "GT", rank: 5, color: "var(--violet-text)" };
  if (role === "db" || kinds.has("db")) return { code: "DB", rank: 7, color: "var(--mint)" };
  if (role === "web" || kinds.has("http")) return { code: "WB", rank: 6, color: "var(--cyber)" };
  if (role === "sensor" || kinds.has("log")) return { code: "SN", rank: 8, color: "var(--muted)" };
  if (role === "workstation") return { code: "WS", rank: 9, color: "var(--faint)" };
  return { code: "SV", rank: 8, color: "var(--faint)" };
}

function sortedInstances(instances: Instance[]): Instance[] {
  return [...instances].sort((a, b) => nodeKind(a).rank - nodeKind(b).rank || a.hostId.localeCompare(b.hostId));
}

function edgePath(from: PositionedNode, to: PositionedNode): { d: string; lx: number; ly: number } {
  const fromCx = from.x + NODE_W / 2;
  const fromCy = from.y + NODE_H / 2;
  const toCx = to.x + NODE_W / 2;
  const toCy = to.y + NODE_H / 2;
  const dx = toCx - fromCx;
  const dy = toCy - fromCy;

  if (Math.abs(dx) >= Math.abs(dy)) {
    const dir = dx >= 0 ? 1 : -1;
    const sx = fromCx + dir * (NODE_W / 2);
    const ex = toCx - dir * (NODE_W / 2);
    const bend = Math.max(44, Math.abs(ex - sx) * 0.42);
    return {
      d: `M ${sx} ${fromCy} C ${sx + dir * bend} ${fromCy}, ${ex - dir * bend} ${toCy}, ${ex} ${toCy}`,
      lx: (sx + ex) / 2,
      ly: (fromCy + toCy) / 2 - 6,
    };
  }

  const dir = dy >= 0 ? 1 : -1;
  const sy = fromCy + dir * (NODE_H / 2);
  const ey = toCy - dir * (NODE_H / 2);
  const bend = Math.max(40, Math.abs(ey - sy) * 0.42);
  return {
    d: `M ${fromCx} ${sy} C ${fromCx} ${sy + dir * bend}, ${toCx} ${ey - dir * bend}, ${toCx} ${ey}`,
    lx: (fromCx + toCx) / 2,
    ly: (sy + ey) / 2 - 6,
  };
}

export function TopologyGraph({ spec, groups, flows, addresses = {}, domain }: {
  spec: EnvironmentSpec;
  groups: TopologyGroupInput[];
  flows: TopologyFlowInput[];
  addresses?: Record<string, string>;
  domain: string;
}) {
  const maxNodes = Math.max(1, ...groups.map((g) => g.instances.length));
  const columns = Math.min(4, maxNodes);
  const width = Math.max(820, OUTER_X * 2 + 36 + columns * NODE_W + (columns - 1) * COL_GAP);
  const vulnsByHost = new Map<string, number>();
  const objectivesByHost = new Map<string, number>();
  for (const v of spec.plantedVulns) vulnsByHost.set(v.targetHostId, (vulnsByHost.get(v.targetHostId) ?? 0) + 1);
  for (const o of spec.objectives) objectivesByHost.set(o.asset, (objectivesByHost.get(o.asset) ?? 0) + 1);

  const positioned = new Map<string, PositionedNode>();
  const renderedGroups: { group: TopologyGroupInput; y: number; height: number; backboneY: number; nodes: PositionedNode[] }[] = [];
  let cursorY = HEADER_H + 14;

  for (const group of groups) {
    const sorted = sortedInstances(group.instances);
    const rows = Math.max(1, Math.ceil(sorted.length / columns));
    const groupHeight = sorted.length === 0 ? 92 : 72 + rows * NODE_H + (rows - 1) * ROW_GAP + 20;
    const backboneY = cursorY + 43;
    const nodes = sorted.map((instance, index) => {
      const col = index % columns;
      const row = Math.floor(index / columns);
      const node = {
        instance,
        groupId: group.id,
        x: OUTER_X + 22 + col * (NODE_W + COL_GAP),
        y: cursorY + 58 + row * (NODE_H + ROW_GAP),
      };
      positioned.set(instance.hostId, node);
      return node;
    });
    renderedGroups.push({ group, y: cursorY, height: groupHeight, backboneY, nodes });
    cursorY += groupHeight + 16;
  }

  const height = Math.max(250, cursorY + 8);
  const visibleFlows = flows.filter((f, index, arr) => positioned.has(f.from) && positioned.has(f.to)
    && arr.findIndex((x) => x.from === f.from && x.to === f.to && x.label === f.label) === index);

  return (
    <div>
      <div className="max-h-[70vh] overflow-auto rounded-lg border border-line bg-panel">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          preserveAspectRatio="xMidYMid meet"
          style={{ minWidth: Math.min(width, 560), maxHeight: "70vh" }}
          className="block h-auto w-full"
          role="img"
          aria-label={`Network topology graph for ${spec.name}. ${spec.instances.length} hosts in ${groups.length} network segments, with ${visibleFlows.length} declared flows.`}
        >
          <defs>
            <marker id="topology-arrow-service" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--cyber)" />
            </marker>
            <marker id="topology-arrow-dependency" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--gold)" />
            </marker>
          </defs>

          <rect x={8} y={8} width={width - 16} height={height - 16} rx={12} fill="var(--panel)" stroke="var(--line)" />
          <text x={28} y={34} fontSize={14} fontWeight={650} fill="var(--paper)">{truncate(spec.name, 42)}</text>
          <text x={28} y={51} fontSize={10} fill="var(--faint)" className="mono">{domain} · {spec.topology.cidr} · {spec.provider} · v{spec.version}</text>
          <text x={width - 28} y={34} textAnchor="end" fontSize={10} fill="var(--faint)" className="mono">{spec.instances.length} HOSTS · {visibleFlows.length} FLOWS</text>
          <line x1={28} y1={HEADER_H} x2={width - 28} y2={HEADER_H} stroke="var(--line)" />

          {renderedGroups.length > 1 && (
            <line
              x1={52}
              y1={renderedGroups[0].backboneY}
              x2={52}
              y2={renderedGroups[renderedGroups.length - 1].backboneY}
              stroke="var(--linestrong)"
              strokeWidth={1.4}
            />
          )}

          {renderedGroups.map(({ group, y, height: groupHeight, backboneY, nodes }, groupIndex) => (
            <g key={group.id} className="topo-segment" style={{ animationDelay: `${groupIndex * 90}ms` }}>
              <rect x={OUTER_X} y={y} width={width - OUTER_X * 2} height={groupHeight} rx={9} fill="var(--track)" stroke="var(--line)" strokeDasharray="5 4" />
              <text x={OUTER_X + 16} y={y + 22} fontSize={11.5} fontWeight={650} fill="var(--paper)">{group.name}</text>
              <text x={OUTER_X + 16} y={y + 37} fontSize={9.5} fill="var(--faint)" className="mono">{group.cidr} · zone {group.zone}</text>
              <text x={width - OUTER_X - 16} y={y + 22} textAnchor="end" fontSize={9} fill="var(--faint)" className="mono">NETWORK SEGMENT</text>
              {nodes.length > 0 ? (
                <>
                  <line x1={52} y1={backboneY} x2={Math.max(...nodes.map((n) => n.x + NODE_W / 2))} y2={backboneY} stroke="var(--linestrong)" strokeWidth={1.4} />
                  {nodes.map((node) => {
                    const cx = node.x + NODE_W / 2;
                    return (
                      <g key={`bus-${node.instance.hostId}`} stroke="var(--linestrong)">
                        <line x1={cx} y1={backboneY} x2={cx} y2={node.y} strokeWidth={1} />
                        <circle cx={cx} cy={backboneY} r={2.5} fill="var(--cyber)" stroke="none" />
                      </g>
                    );
                  })}
                </>
              ) : (
                <text x={OUTER_X + 16} y={y + 66} fontSize={11} fill="var(--faint)">No hosts placed in this segment.</text>
              )}
            </g>
          ))}

          {visibleFlows.map((flow, index) => {
            const from = positioned.get(flow.from)!;
            const to = positioned.get(flow.to)!;
            const path = edgePath(from, to);
            const color = flow.kind === "service" ? "var(--cyber)" : "var(--gold)";
            return (
              <g key={`${flow.from}-${flow.to}-${flow.label}-${index}`} className="topo-edge" style={{ animationDelay: `${350 + index * 60}ms` }}>
                <path d={path.d} fill="none" stroke={color} strokeWidth={1.35} strokeOpacity={0.82} strokeDasharray={flow.kind === "dependency" ? "6 4" : undefined} markerEnd={`url(#topology-arrow-${flow.kind})`} />
                <text x={path.lx} y={path.ly} textAnchor="middle" fontSize={8.5} fill={color} stroke="var(--panel)" strokeWidth={3} paintOrder="stroke" className="mono">{truncate(flow.label, 22)}</text>
              </g>
            );
          })}

          {renderedGroups.flatMap(({ nodes }, groupIndex) => nodes.map((node, nodeIndex) => {
            const inst = node.instance;
            const kind = nodeKind(inst);
            const vulnCount = vulnsByHost.get(inst.hostId) ?? 0;
            const objectiveCount = objectivesByHost.get(inst.hostId) ?? 0;
            const services = inst.services.length ? inst.services.join(" · ") : "base profile";
            const address = addresses[inst.hostId];
            return (
              <g key={inst.hostId} className="topo-node" style={{ animationDelay: `${200 + (groupIndex * 6 + nodeIndex) * 60}ms` }}>
                <rect x={node.x} y={node.y} width={NODE_W} height={NODE_H} rx={7} fill="var(--panel)" stroke={vulnCount ? "var(--danger)" : inst.role === "attacker" ? "var(--gold)" : "var(--linestrong)"} strokeWidth={vulnCount || inst.role === "attacker" ? 1.6 : 1.1} />
                <rect x={node.x + 10} y={node.y + 16} width={36} height={36} rx={6} fill={kind.color} fillOpacity={0.13} stroke={kind.color} strokeOpacity={0.45} />
                <text x={node.x + 28} y={node.y + 39} textAnchor="middle" fontSize={11} fontWeight={700} fill={kind.color} className="mono">{kind.code}</text>
                <text x={node.x + 56} y={node.y + 22} fontSize={11.5} fontWeight={650} fill="var(--paper)">{truncate(inst.name || inst.hostId, 17)}</text>
                <text x={node.x + 56} y={node.y + 38} fontSize={9.5} fill="var(--faint)">{truncate(`${inst.role} · ${inst.runtime} · ${inst.os}`, 25)}</text>
                <text x={node.x + 56} y={node.y + 53} fontSize={8.8} fill="var(--faint)" className="mono">{truncate(address ? `${address} · ${services}` : services, 25)}</text>
                {objectiveCount > 0 && (
                  <g transform={`translate(${node.x + NODE_W - 16} ${node.y + 15})`} stroke="var(--gold-text)" fill="none" strokeWidth={1.2}>
                    <circle r={6} /><line x1={-9} y1={0} x2={-3} y2={0} /><line x1={3} y1={0} x2={9} y2={0} /><line x1={0} y1={-9} x2={0} y2={-3} /><line x1={0} y1={3} x2={0} y2={9} />
                  </g>
                )}
                {vulnCount > 0 && (
                  <g transform={`translate(${node.x + NODE_W - 15} ${node.y + NODE_H - 15})`}>
                    <circle r={8} fill="var(--danger)" />
                    <text y={3.2} textAnchor="middle" fontSize={10} fontWeight={800} fill="var(--panel)">!</text>
                  </g>
                )}
              </g>
            );
          }))}
        </svg>
      </div>
      <div className="topo-legend mt-3 flex flex-wrap gap-x-5 gap-y-2 px-1 text-xs text-muted" style={{ animationDelay: "600ms" }} aria-label="Topology legend">
        <span><span className="mr-2 inline-block h-px w-7 bg-cyber align-middle" />Service flow</span>
        <span><span className="mr-2 inline-block h-px w-7 bg-gold align-middle" />Dependency</span>
        <span><span className="mr-2 inline-block h-2 w-2 rounded-full bg-danger align-middle" />Planted weakness</span>
        <span><span className="mr-2 inline-block h-2 w-2 rounded-full border border-gold align-middle" />Objective asset</span>
        <span>Dashed region = network segment</span>
      </div>
    </div>
  );
}

