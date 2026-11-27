"use client";

import { useMemo, useState } from "react";
import { Dot, ErrorNote, Pill, Skeleton } from "@/components/ui/atoms";
import { ALL, SelectBox } from "@/components/ui/fields";
import { describeError } from "@/lib/api/client";
import { type LiveState, type LiveTopology, useLiveTopology } from "@/lib/api/observability";
import { cn } from "@/lib/cn";
import { HEALTH_LABEL, HEALTH_STROKE, HEALTH_TONE, Panel, ScorePill, SourceNote, bytes, clock } from "./shared";

const SITE_BANDS = [
  { site: "NYC", label: "New York", x: 20, y: 60, w: 250, h: 100 },
  { site: "SIN", label: "Singapore", x: 20, y: 250, w: 250, h: 100 },
  { site: "BLR", label: "Bengaluru", x: 20, y: 440, w: 250, h: 100 },
  { site: "CORE", label: "Core · London", x: 345, y: 40, w: 255, h: 470 },
  { site: "DC1", label: "Data centre · Slough", x: 640, y: 30, w: 345, h: 560 },
];
const SHAPE: Record<string, string> = { router: "R", switch: "S", firewall: "F", server: "V" };

type Edge = LiveTopology["edges"][number];

/** The freshest streamed value for a link: the worse of its two ends (lowest status, highest utilisation). */
function liveValue(live: LiveState, edge: Edge, metric: string) {
  let best: number | null = null;
  for (const [device, name] of Object.entries(edge.interfaces)) {
    const hit = live.latest.get(`${device}|${name}|${metric}`);
    if (!hit) continue;
    best = best === null ? hit.v : metric === "oper_status" ? Math.min(best, hit.v) : Math.max(best, hit.v);
  }
  return best;
}

export function LiveTopologyPanel({ scenario, live }: { scenario: string; live: LiveState }) {
  const topology = useLiveTopology(scenario);
  const [selected, setSelected] = useState<string | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [site, setSite] = useState<string>(ALL);
  const data = topology.data;
  const nodes = useMemo(() => new Map((data?.nodes ?? []).map((n) => [n.id, n])), [data]);

  if (topology.isPending) return <Skeleton className="h-[520px]" />;
  if (topology.isError) return <ErrorNote message={describeError(topology.error)} onRetry={() => topology.refetch()} />;
  if (!data) return null;

  const focusNode = selected ? nodes.get(selected) : undefined;
  const focusEdge = hovered ? data.edges.find((e) => e.id === hovered) : undefined;
  const visible = (id: string) => site === ALL || nodes.get(id)?.site_id === site;
  const liveCount = data.edges.filter((e) => e.data_source === "live").length;

  return (
    <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_300px]">
      <Panel
        title="Live network topology"
        aside={
          <span className="inline-flex items-center gap-2">
            <Dot tone={live.status === "live" ? "green" : live.status === "offline" ? "red" : "amber"} />
            {live.status === "live" ? `Streaming · ${liveCount} of ${data.edges.length} links live` : live.status === "offline" ? "Stream offline" : "Connecting"}
          </span>
        }
      >
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <SelectBox
            size="sm"
            ariaLabel="Site filter"
            className="w-[170px]"
            value={site}
            onValueChange={setSite}
            options={[{ value: ALL, label: "All sites" }, ...data.sites.map((s) => ({ value: s.site_id, label: s.name }))]}
          />
          <span className="text-[12px] text-ink-3">Line weight shows utilisation; colour shows link health. Select a device for details.</span>
        </div>
        <svg viewBox="0 0 1000 600" role="img" aria-label="Network topology with link health" className="h-auto w-full">
          {SITE_BANDS.map((band) => (
            <g key={band.site} opacity={site === ALL || site === band.site ? 1 : 0.35}>
              <rect x={band.x} y={band.y} width={band.w} height={band.h} rx={10} fill="var(--panel)" stroke="var(--line-soft)" />
              <text x={band.x + 10} y={band.y + 18} fontSize={12} fill="var(--ink-3)">
                {band.label}
              </text>
            </g>
          ))}
          {data.edges.map((edge) => {
            const a = nodes.get(edge.source);
            const b = nodes.get(edge.target);
            if (!a || !b) return null;
            const utilisation = liveValue(live, edge, "utilization_percent") ?? edge.utilization_percent ?? 0;
            const down = edge.status === "down" || liveValue(live, edge, "oper_status") === 0;
            const colour = down ? "var(--red)" : HEALTH_STROKE[edge.health];
            const dim = !(visible(edge.source) || visible(edge.target));
            return (
              <g key={edge.id} opacity={dim ? 0.2 : 1}>
                <line
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke={colour}
                  strokeWidth={1.5 + (utilisation / 100) * 7}
                  strokeLinecap="round"
                  strokeDasharray={down ? "6 6" : undefined}
                  opacity={hovered && hovered !== edge.id ? 0.45 : 0.9}
                />
                <line
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke="transparent"
                  strokeWidth={16}
                  onMouseEnter={() => setHovered(edge.id)}
                  onMouseLeave={() => setHovered(null)}
                >
                  <title>{`${edge.id}: ${down ? "down" : `${Math.round(utilisation)}% utilised`}`}</title>
                </line>
              </g>
            );
          })}
          {data.nodes.map((node) => {
            const tone = HEALTH_STROKE[node.status];
            const active = selected === node.id;
            return (
              <g
                key={node.id}
                transform={`translate(${node.x} ${node.y})`}
                opacity={visible(node.id) ? 1 : 0.25}
                role="button"
                tabIndex={0}
                aria-label={`${node.label}: health ${Math.round(node.score)}, ${HEALTH_LABEL[node.status]}`}
                onClick={() => setSelected(active ? null : node.id)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") setSelected(active ? null : node.id);
                }}
                className="cursor-pointer outline-none"
              >
                <circle r={active ? 19 : 16} fill="var(--surface)" stroke={tone} strokeWidth={active ? 3 : 2} />
                <text textAnchor="middle" dy={4} fontSize={11} fontWeight={600} fill="var(--ink-2)">
                  {SHAPE[node.device_type] ?? "?"}
                </text>
                <text textAnchor="middle" y={32} fontSize={10.5} fill="var(--ink-3)" stroke="var(--panel)" strokeWidth={4} paintOrder="stroke" className="font-mono">
                  {node.label}
                </text>
              </g>
            );
          })}
        </svg>
        <div className="mt-2 flex flex-wrap items-center gap-3 text-[12px] text-ink-3">
          {(["healthy", "degraded", "critical"] as const).map((status) => (
            <span key={status} className="inline-flex items-center gap-1.5">
              <Dot tone={HEALTH_TONE[status]} />
              {HEALTH_LABEL[status]}
            </span>
          ))}
          <span>R router · S switch · F firewall · V server</span>
          <span className="ml-auto">Refreshed {clock(data.generated_at)} UTC</span>
        </div>
        <SourceNote>
          Live values come from the telemetry simulator (or ingested telemetry when a collector sends it); links without live values show
          the scenario&apos;s latest sample.
        </SourceNote>
      </Panel>

      <div className="space-y-3">
        <Panel title={focusNode ? focusNode.label : "Network"} aside={focusNode ? <span className="font-mono">{focusNode.id}</span> : null}>
          {focusNode ? (
            <div className="space-y-2.5">
              <ScorePill score={focusNode.score} status={focusNode.status} />
              <p className="text-[12.5px] text-ink-3">
                {focusNode.device_type} · {focusNode.role.replaceAll("_", " ")} · {focusNode.site_id}
              </p>
              {focusNode.reasons.length ? (
                <ul className="space-y-1 text-[12.5px] text-ink-2">
                  {focusNode.reasons.map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-[12.5px] text-ink-3">No deductions: every check passed.</p>
              )}
              <ul className="space-y-1.5 pt-1">
                {data.edges
                  .filter((e) => e.source === focusNode.id || e.target === focusNode.id)
                  .map((edge) => (
                    <li key={edge.id} className="flex items-center gap-2 text-[12px]">
                      <Dot tone={edge.status === "down" ? "red" : HEALTH_TONE[edge.health]} />
                      <span className="truncate font-mono text-ink-2">{edge.id}</span>
                      <span className="ml-auto text-ink-3">{edge.status === "down" ? "down" : `${edge.utilization_percent ?? "—"}%`}</span>
                    </li>
                  ))}
              </ul>
            </div>
          ) : (
            <div className="space-y-2">
              <ScorePill score={data.network.score} status={data.network.status} />
              <ul className="space-y-1.5 pt-1">
                {data.sites.map((s) => (
                  <li key={s.site_id} className="flex items-center gap-2 text-[12.5px]">
                    <Dot tone={HEALTH_TONE[s.status]} />
                    <span className="text-ink-2">{s.city}</span>
                    <span className="ml-auto font-mono text-ink-3">{s.score ?? "—"}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Panel>
        <Panel title="Link" aside={focusEdge ? <span className="font-mono">{focusEdge.id}</span> : "Hover a link"}>
          {focusEdge ? (
            <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-[12.5px]">
              <dt className="text-ink-3">Status</dt>
              <dd className={cn(focusEdge.status === "down" ? "text-red" : "text-ink-2")}>{focusEdge.status}</dd>
              <dt className="text-ink-3">Utilisation</dt>
              <dd className="font-mono text-ink-2">{focusEdge.utilization_percent ?? "—"}%</dd>
              <dt className="text-ink-3">Loss</dt>
              <dd className="font-mono text-ink-2">{focusEdge.loss_percent ?? "—"}%</dd>
              <dt className="text-ink-3">Latency</dt>
              <dd className="font-mono text-ink-2">{focusEdge.latency_ms ?? "—"} ms</dd>
              <dt className="text-ink-3">Health</dt>
              <dd className="text-ink-2">{focusEdge.score ?? "—"}</dd>
              <dt className="text-ink-3">Flows (window)</dt>
              <dd className="font-mono text-ink-2">{bytes(focusEdge.flow_bytes)}</dd>
              <dt className="text-ink-3">Source</dt>
              <dd>
                <Pill tone={focusEdge.data_source === "live" ? "accent" : "muted"}>{focusEdge.data_source === "live" ? "Live (simulated)" : "Scenario sample"}</Pill>
              </dd>
            </dl>
          ) : (
            <p className="text-[12.5px] text-ink-3">Utilisation, loss, latency and attributed flow volume appear here.</p>
          )}
        </Panel>
      </div>
    </div>
  );
}
