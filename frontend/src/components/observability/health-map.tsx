"use client";

import { useState } from "react";
import { Dot, ErrorNote, Skeleton } from "@/components/ui/atoms";
import { describeError } from "@/lib/api/client";
import { type HealthReport, useObsHealth } from "@/lib/api/observability";
import { cn } from "@/lib/cn";
import { HEALTH_LABEL, HEALTH_STROKE, HEALTH_TONE, Meter, Panel, ScorePill, SERVICE_NAME, SourceNote } from "./shared";

// Equirectangular projection cropped to the sites' span (New York to Singapore).
const BOUNDS = { west: -95, east: 125, north: 62, south: -8 };
const WIDTH = 1000;
const HEIGHT = 380;
// London and Slough sit 30 km apart; nudge the data centre so both markers stay legible.
const NUDGE: Record<string, { x: number; y: number }> = { DC1: { x: 18, y: 22 } };
const project = (lat: number, lon: number, site?: string) => ({
  x: ((lon - BOUNDS.west) / (BOUNDS.east - BOUNDS.west)) * WIDTH + (NUDGE[site ?? ""]?.x ?? 0),
  y: ((BOUNDS.north - lat) / (BOUNDS.north - BOUNDS.south)) * HEIGHT + (NUDGE[site ?? ""]?.y ?? 0),
});
// Branch sites reach the core over a WAN circuit; the data centre over the metro fibre.
const UPLINK: Record<string, string> = { NYC: "CORE", SIN: "CORE", BLR: "CORE", DC1: "CORE" };

// Different curvature per circuit keeps the two eastbound arcs apart.
const LIFT: Record<string, number> = { NYC: 0.22, BLR: 0.2, SIN: 0.06, DC1: 0 };
function arc(a: { x: number; y: number }, b: { x: number; y: number }, site: string) {
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2 - Math.min(110, Math.abs(a.x - b.x) * (LIFT[site] ?? 0.15));
  return `M ${a.x} ${a.y} Q ${mx} ${my} ${b.x} ${b.y}`;
}

export function HealthMapPanel({ scenario }: { scenario: string }) {
  const health = useObsHealth(scenario);
  const [focus, setFocus] = useState<string | null>(null);
  if (health.isPending) return <Skeleton className="h-[460px]" />;
  if (health.isError) return <ErrorNote message={describeError(health.error)} onRetry={() => health.refetch()} />;
  const data = health.data!;
  const sites = new Map(data.sites.map((s) => [s.site_id, s]));
  const chosen = focus ? sites.get(focus) : undefined;

  return (
    <div className="space-y-3">
      <Panel title="Multi-site health map" aside={<ScorePill score={data.network.score} status={data.network.status} />}>
        <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role="img" aria-label="Map of site health" className="h-auto w-full">
          <rect width={WIDTH} height={HEIGHT} rx={10} fill="var(--panel)" />
          {[-60, -30, 0, 30, 60, 90, 120].map((lon) => {
            const { x } = project(0, lon);
            return <line key={`lon${lon}`} x1={x} x2={x} y1={0} y2={HEIGHT} stroke="var(--line-soft)" strokeDasharray="2 6" />;
          })}
          {[0, 20, 40, 60].map((lat) => {
            const { y } = project(lat, 0);
            return (
              <g key={`lat${lat}`}>
                <line x1={0} x2={WIDTH} y1={y} y2={y} stroke="var(--line-soft)" strokeDasharray="2 6" />
                <text x={6} y={y - 4} fontSize={10} fill="var(--ink-4)">
                  {lat}°N
                </text>
              </g>
            );
          })}
          {data.sites.map((site) => {
            const target = sites.get(UPLINK[site.site_id] ?? "");
            if (!target) return null;
            const a = project(site.latitude, site.longitude, site.site_id);
            const b = project(target.latitude, target.longitude, target.site_id);
            const status = site.services.some((s) => s.down_links.length) ? "critical" : site.status;
            return (
              <path
                key={`arc${site.site_id}`}
                d={arc(a, b, site.site_id)}
                fill="none"
                stroke={HEALTH_STROKE[status]}
                strokeWidth={2}
                strokeDasharray={status === "critical" ? "6 6" : undefined}
                opacity={0.8}
              />
            );
          })}
          {data.sites.map((site) => {
            const { x, y } = project(site.latitude, site.longitude, site.site_id);
            const left = site.site_id === "CORE";
            const near = site.site_id === "DC1";
            return (
              <g
                key={site.site_id}
                transform={`translate(${x} ${y})`}
                role="button"
                tabIndex={0}
                aria-label={`${site.city}: ${site.score ?? "no"} health, ${HEALTH_LABEL[site.status]}`}
                onClick={() => setFocus(focus === site.site_id ? null : site.site_id)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") setFocus(focus === site.site_id ? null : site.site_id);
                }}
                className="cursor-pointer outline-none"
              >
                <circle r={focus === site.site_id ? 13 : 10} fill="var(--surface)" stroke={HEALTH_STROKE[site.status]} strokeWidth={3} />
                <text x={left ? -16 : 16} y={near ? 14 : 4} textAnchor={left ? "end" : "start"} fontSize={12} fill="var(--ink)">
                  {site.city}
                </text>
                <text x={left ? -16 : 16} y={near ? 28 : 18} textAnchor={left ? "end" : "start"} fontSize={11} fill="var(--ink-3)" className="font-mono">
                  {site.score ?? "—"}
                </text>
              </g>
            );
          })}
        </svg>
        <SourceNote>Schematic projection (no coastlines). Scores blend each site&apos;s devices with a traced packet journey for every service it uses.</SourceNote>
      </Panel>

      <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
        {data.sites.map((site) => (
          <li key={site.site_id}>
            <button
              type="button"
              onClick={() => setFocus(focus === site.site_id ? null : site.site_id)}
              className={cn("card flex w-full flex-col items-start gap-2 px-3.5 py-3 text-left hover:bg-hover", focus === site.site_id && "bg-selected")}
            >
              <span className="flex w-full items-center gap-2">
                <span className="truncate text-[13.5px] font-medium text-ink">{site.city}</span>
                <span className="ml-auto font-mono text-[11px] text-ink-4">{site.site_id}</span>
              </span>
              <ScorePill score={site.score} status={site.status} />
              <Meter value={site.score} tone={HEALTH_TONE[site.status]} />
              <span className="text-[11.5px] text-ink-3">{siteCaption(site)}</span>
            </button>
          </li>
        ))}
      </ul>

      {chosen ? <SiteDetail site={chosen} report={data} /> : null}
    </div>
  );
}

function siteCaption(site: HealthReport["sites"][number]) {
  const failing = site.services.filter((s) => s.status === "critical").map((s) => SERVICE_NAME[s.service] ?? s.service);
  if (failing.length) return `${failing.join(", ")} critical`;
  if (site.critical_devices) return `${site.critical_devices} critical device${site.critical_devices === 1 ? "" : "s"}`;
  if (site.degraded_devices) return `${site.degraded_devices} degraded device${site.degraded_devices === 1 ? "" : "s"}`;
  return "All devices healthy";
}

function SiteDetail({ site, report }: { site: HealthReport["sites"][number]; report: HealthReport }) {
  const devices = report.devices.filter((d) => d.site_id === site.site_id);
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Panel title={`${site.name} services`} aside={site.notes.length ? site.notes[0] : null}>
        {site.services.length ? (
          <ul className="space-y-2">
            {site.services.map((service) => (
              <li key={service.service} className="grid grid-cols-[140px_1fr_auto] items-center gap-3 text-[12.5px]">
                <span className="text-ink-2">{SERVICE_NAME[service.service] ?? service.service}</span>
                <Meter value={service.score} tone={HEALTH_TONE[service.status]} />
                <span className="w-10 text-right font-mono text-ink-3">{service.score ?? "—"}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[12.5px] text-ink-3">This site hosts shared infrastructure; it starts no service paths.</p>
        )}
      </Panel>
      <Panel title="Devices" aside={`${devices.length} at ${site.site_id}`}>
        <ul className="space-y-2.5">
          {devices.map((device) => (
            <li key={device.device_id}>
              <div className="flex items-center gap-2 text-[12.5px]">
                <Dot tone={HEALTH_TONE[device.status]} />
                <span className="font-mono text-ink-2">{device.device_id}</span>
                <span className="ml-auto font-mono text-ink-3">{device.score}</span>
              </div>
              {device.factors.slice(0, 2).map((factor) => (
                <p key={factor.detail} className="mt-0.5 pl-4 text-[12px] text-ink-3">
                  −{factor.penalty} {factor.detail}
                </p>
              ))}
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}
