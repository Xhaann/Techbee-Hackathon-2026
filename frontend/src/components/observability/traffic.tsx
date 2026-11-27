"use client";

import { useMemo, useState } from "react";
import { ErrorNote, Pill, Skeleton } from "@/components/ui/atoms";
import { ALL, SelectBox } from "@/components/ui/fields";
import { describeError } from "@/lib/api/client";
import { type TrafficSummary, useTraffic } from "@/lib/api/observability";
import { Cell, Empty, Panel, SERVICE_NAME, SourceNote, Table, bytes, clock, plural } from "./shared";

const SITES = [
  { value: ALL, label: "All sites" },
  { value: "NYC", label: "New York" },
  { value: "SIN", label: "Singapore" },
  { value: "BLR", label: "Bengaluru" },
];

/** Site to service flows as a two-column Sankey: band width is bytes, the red share is dropped flows. */
function Sankey({ data }: { data: TrafficSummary["sankey"] }) {
  const [active, setActive] = useState<string | null>(null);
  const layout = useMemo(() => {
    const left = data.nodes.filter((n) => !n.startsWith("service:"));
    const right = data.nodes.filter((n) => n.startsWith("service:"));
    const total = data.links.reduce((sum, l) => sum + l.bytes, 0) || 1;
    const height = 300;
    const gap = 10;
    const place = (names: string[], weight: (name: string) => number) => {
      const usable = height - gap * Math.max(0, names.length - 1);
      let y = 0;
      return new Map(
        names.map((name) => {
          const h = Math.max(14, (weight(name) / total) * usable);
          const entry = { y, h, used: 0 };
          y += h + gap;
          return [name, entry];
        }),
      );
    };
    const leftPos = place(left, (n) => data.links.filter((l) => l.source === n).reduce((s, l) => s + l.bytes, 0));
    const rightPos = place(right, (n) => data.links.filter((l) => l.target === n).reduce((s, l) => s + l.bytes, 0));
    const ribbons = [...data.links]
      .sort((a, b) => a.source.localeCompare(b.source) || a.target.localeCompare(b.target))
      .map((link) => {
        const a = leftPos.get(link.source)!;
        const b = rightPos.get(link.target)!;
        const thickness = Math.max(1.5, (link.bytes / total) * (height - gap * 4));
        const y0 = a.y + a.used + thickness / 2;
        const y1 = b.y + b.used + thickness / 2;
        a.used += thickness;
        b.used += thickness;
        return { link, y0, y1, thickness };
      });
    return { left, right, leftPos, rightPos, ribbons, height };
  }, [data]);

  return (
    <svg viewBox={`0 0 760 ${layout.height + 70}`} role="img" aria-label="Traffic from sites to services" className="h-auto w-full">
      {layout.ribbons.map(({ link, y0, y1, thickness }) => {
        const key = `${link.source}>${link.target}`;
        const share = link.flows ? link.dropped / link.flows : 0;
        return (
          <path
            key={key}
            d={`M 130 ${y0 + 10} C 380 ${y0 + 10}, 380 ${y1 + 10}, 620 ${y1 + 10}`}
            fill="none"
            stroke={share > 0.2 ? "var(--red)" : "var(--chart)"}
            strokeWidth={thickness}
            opacity={active === null ? 0.45 : active === key ? 0.85 : 0.15}
            onMouseEnter={() => setActive(key)}
            onMouseLeave={() => setActive(null)}
          >
            <title>{`${link.source} → ${SERVICE_NAME[link.target.slice(8)] ?? link.target}: ${bytes(link.bytes)}, ${link.flows} flows, ${link.dropped} dropped`}</title>
          </path>
        );
      })}
      {layout.left.map((name) => {
        const p = layout.leftPos.get(name)!;
        return (
          <g key={name}>
            <rect x={118} y={p.y + 10} width={12} height={p.h} rx={3} fill="var(--ink-3)" />
            <text x={110} y={p.y + 10 + p.h / 2 + 4} textAnchor="end" fontSize={12} fill="var(--ink-2)">
              {name}
            </text>
          </g>
        );
      })}
      {layout.right.map((name) => {
        const p = layout.rightPos.get(name)!;
        return (
          <g key={name}>
            <rect x={620} y={p.y + 10} width={12} height={p.h} rx={3} fill="var(--ink-3)" />
            <text x={640} y={p.y + 10 + p.h / 2 + 4} fontSize={12} fill="var(--ink-2)">
              {SERVICE_NAME[name.slice(8)] ?? name.slice(8)}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

/** Bytes per minute across the window, with the incident onset marked. */
function Timeline({ data }: { data: TrafficSummary }) {
  const series = data.timeline;
  const totals = series.map((row) => Object.entries(row).reduce((sum, [k, v]) => (k === "minute" ? sum : sum + Number(v)), 0));
  const max = Math.max(1, ...totals);
  const onset = series.findIndex((row) => row.minute >= data.window.onset);
  const width = 760;
  const step = width / Math.max(1, series.length);
  return (
    <svg viewBox={`0 0 ${width} 140`} role="img" aria-label="Traffic volume per minute" className="h-auto w-full">
      {totals.map((value, index) => (
        <rect key={series[index].minute} x={index * step + 1} y={120 - (value / max) * 110} width={Math.max(1, step - 2)} height={(value / max) * 110} rx={2} fill="var(--chart)" opacity={0.8}>
          <title>{`${clock(series[index].minute)} UTC: ${bytes(value)}`}</title>
        </rect>
      ))}
      {onset >= 0 ? (
        <g>
          <line x1={onset * step} x2={onset * step} y1={4} y2={124} stroke="var(--amber)" strokeDasharray="4 4" />
          <text x={onset * step + 4} y={14} fontSize={8.5} fill="var(--amber)">
            onset {clock(data.window.onset)}
          </text>
        </g>
      ) : null}
      <text x={0} y={138} fontSize={8.5} fill="var(--ink-4)">
        {clock(data.window.start)}
      </text>
      <text x={width} y={138} fontSize={8.5} fill="var(--ink-4)" textAnchor="end">
        {clock(data.window.end)} UTC
      </text>
    </svg>
  );
}

export function TrafficPanel({ scenario }: { scenario: string }) {
  const [site, setSite] = useState<string>(ALL);
  const traffic = useTraffic(scenario, site === ALL ? undefined : site);
  const data = traffic.data;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <SelectBox size="sm" ariaLabel="Traffic site" className="w-[170px]" value={site} onValueChange={setSite} options={SITES} />
        {data ? (
          <span className="text-[12.5px] text-ink-3">
            {data.totals.flows.toLocaleString("en-US")} flows · {bytes(data.totals.bytes)} · {data.totals.dropped_flows} dropped by policy
          </span>
        ) : null}
      </div>
      {traffic.isPending ? <Skeleton className="h-[360px]" /> : null}
      {traffic.isError ? <ErrorNote message={describeError(traffic.error)} onRetry={() => traffic.refetch()} /> : null}
      {data ? (
        <>
          <div className="grid gap-3 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
            <Panel title="Where traffic goes" aside="Band width is bytes; red bands carry mostly dropped flows">
              <Sankey data={data.sankey} />
            </Panel>
            <div className="space-y-3">
              <Panel title="Dropped by policy">
                {data.dropped_by_policy.length ? (
                  <ul className="space-y-2 text-[12.5px]">
                    {data.dropped_by_policy.slice(0, 5).map((drop) => (
                      <li key={`${drop.device_id}${drop.service}`} className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <Pill tone="red">{plural(drop.flows, "flow")}</Pill>
                          <span className="text-ink-2">
                            {SERVICE_NAME[drop.service] ?? drop.service} from {drop.sources.join(", ")}
                          </span>
                        </div>
                        <p className="text-[12px] text-ink-3">
                          {drop.device_id} · {drop.rules.map((r) => r.name ?? r.rule_id).join(", ") || "rule not logged"} · since {clock(drop.first_seen)}
                        </p>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <Empty>No flows dropped by policy in this window.</Empty>
                )}
              </Panel>
              <Panel title="Traffic that stopped">
                {data.traffic_shifts.length ? (
                  <ul className="space-y-1.5 text-[12.5px] text-ink-2">
                    {data.traffic_shifts.map((shift) => (
                      <li key={`${shift.site_id}${shift.service}`}>
                        {shift.site_id} {SERVICE_NAME[shift.service] ?? shift.service}: {shift.flows_per_minute_before} → {shift.flows_per_minute_after} flows/min after onset
                      </li>
                    ))}
                  </ul>
                ) : (
                  <Empty>No site lost a service&apos;s traffic after the onset.</Empty>
                )}
              </Panel>
            </div>
          </div>
          <Panel title="Volume per minute">
            <Timeline data={data} />
          </Panel>
          <div className="grid gap-3 md:grid-cols-2">
            <Panel title="Top talkers">
              <Table head={["Source", "Bytes"]} minWidth={240}>
                {data.top_talkers.slice(0, 8).map((row) => (
                  <tr key={row.key}>
                    <Cell mono>{row.key}</Cell>
                    <Cell mono className="text-right">{bytes(row.bytes)}</Cell>
                  </tr>
                ))}
              </Table>
            </Panel>
            <Panel title="Applications">
              <Table head={["Service", "Bytes"]} minWidth={240}>
                {data.applications.map((row) => (
                  <tr key={row.key}>
                    <Cell>{SERVICE_NAME[row.key] ?? row.key}</Cell>
                    <Cell mono className="text-right">{bytes(row.bytes)}</Cell>
                  </tr>
                ))}
              </Table>
            </Panel>
          </div>
          <SourceNote>{`${data.source}.`}</SourceNote>
        </>
      ) : null}
    </div>
  );
}
