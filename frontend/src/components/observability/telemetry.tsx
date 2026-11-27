"use client";

import { Dot, ErrorNote, Pill, Skeleton } from "@/components/ui/atoms";
import { describeError } from "@/lib/api/client";
import { type LiveState, useBaselines, useSnmp, useSources, useSyslog, useTraps } from "@/lib/api/observability";
import type { Tone } from "@/lib/labels";
import { Cell, Empty, Panel, SourceNote, Table, clock } from "./shared";

const MODE_TONE: Record<string, Tone> = { simulated: "accent", ingest_api: "green", udp_receiver: "green", not_bundled: "muted" };
const SEVERITY_NAME = ["emerg", "alert", "crit", "error", "warn", "notice", "info", "debug"];

function Sparkline({ values }: { values: number[] }) {
  if (values.length < 2) return <span className="text-[11px] text-ink-4">waiting</span>;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const path = values.map((v, i) => `${(i / (values.length - 1)) * 120} ${28 - ((v - min) / Math.max(1e-6, max - min)) * 24}`).join(" L ");
  return (
    <svg viewBox="0 0 120 30" className="h-[30px] w-[120px]" aria-hidden>
      <path d={`M ${path}`} fill="none" stroke="var(--chart)" strokeWidth={1.5} />
    </svg>
  );
}

export function TelemetryPanel({ scenario, live }: { scenario: string; live: LiveState }) {
  const sources = useSources();
  const syslog = useSyslog(scenario);
  const traps = useTraps(scenario);
  const snmp = useSnmp(scenario);
  const baselines = useBaselines(scenario);
  const wan = [...live.recent.entries()].filter(([key]) => key.endsWith("|utilization_percent") && /RTR-0\d\|Gi0\/0\/[0-3]\|/.test(key)).slice(0, 8);

  return (
    <div className="space-y-3">
      <Panel
        title="Streaming metrics"
        aside={
          <span className="inline-flex items-center gap-2">
            <Dot tone={live.status === "live" ? "green" : live.status === "offline" ? "red" : "amber"} />
            {live.status} · {live.messages} messages{live.dropped ? ` · ${live.dropped} dropped (slow client)` : ""}
          </span>
        }
      >
        {wan.length ? (
          <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            {wan.map(([key, values]) => {
              const [device, name] = key.split("|");
              return (
                <li key={key} className="rounded-[8px] bg-panel px-3 py-2 shadow-[0_0_0_1px_var(--line-soft)]">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="truncate font-mono text-[11.5px] text-ink-2">
                      {device} {name}
                    </span>
                    <span className="font-mono text-[12px] text-ink">{values[values.length - 1]?.toFixed(1)}%</span>
                  </div>
                  <Sparkline values={values} />
                </li>
              );
            })}
          </ul>
        ) : (
          <Empty>Waiting for the first samples from the stream…</Empty>
        )}
        <div className="mt-2">
          <SourceNote>Samples arrive over server-sent events from the telemetry simulator, which continues each scenario&apos;s last state in real time.</SourceNote>
        </div>
      </Panel>

      <Panel title="Telemetry sources" aside={sources.data ? `hub: ${sources.data.hub.series} series · ${sources.data.hub.subscribers} streams` : null}>
        {sources.isPending ? <Skeleton className="h-32" /> : null}
        {sources.isError ? <ErrorNote message={describeError(sources.error)} onRetry={() => sources.refetch()} /> : null}
        {sources.data ? (
          <Table head={["Source", "Mode", "What it does"]} minWidth={720}>
            {sources.data.sources.map((source) => (
              <tr key={source.id}>
                <Cell className="whitespace-nowrap text-ink">{source.name}</Cell>
                <Cell>
                  <span className="flex flex-wrap gap-1">
                    {source.mode.split("+").map((mode) => (
                      <Pill key={mode} tone={MODE_TONE[mode] ?? "muted"}>
                        {mode.replace("_", " ")}
                      </Pill>
                    ))}
                    {source.live_transport === "not_bundled" ? <Pill tone="muted">live transport not bundled</Pill> : null}
                  </span>
                </Cell>
                <Cell className="text-[12px]">
                  {source.detail}
                  {source.udp ? ` · UDP: ${source.udp}` : ""}
                </Cell>
              </tr>
            ))}
          </Table>
        ) : null}
      </Panel>

      <div className="grid gap-3 lg:grid-cols-2">
        <Panel title="Syslog intelligence" aside={syslog.data ? `${syslog.data.total} messages · ${syslog.data.templates_total} templates` : null}>
          {syslog.isPending ? <Skeleton className="h-40" /> : null}
          {syslog.data ? (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(syslog.data.by_severity).map(([level, count]) => (
                  <Pill key={level} tone={Number(level) <= 3 ? "red" : Number(level) === 4 ? "amber" : "muted"}>
                    {SEVERITY_NAME[Number(level)]} {count}
                  </Pill>
                ))}
              </div>
              <h4 className="text-[12.5px] font-medium text-ink-2">Notable templates</h4>
              {syslog.data.notable.length ? (
                <ul className="space-y-1.5">
                  {syslog.data.notable.slice(0, 8).map((t) => (
                    <li key={t.template_id} className="text-[12px]">
                      <span className="font-mono text-ink-2">{t.template}</span>
                      <div className="text-ink-4">
                        ×{t.count} · {t.devices.join(", ")} · {clock(t.first_seen)}
                        {t.rare ? " · rare" : ""}
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <Empty>No error-level or rare messages.</Empty>
              )}
              {syslog.data.security_flags.length ? <p className="text-[12px] text-amber">{syslog.data.security_flags.join(" ")}</p> : null}
            </div>
          ) : null}
        </Panel>
        <div className="space-y-3">
          <Panel title="SNMP traps" aside={traps.data ? `${traps.data.total} traps` : null}>
            {traps.data ? (
              <div className="space-y-2 text-[12.5px]">
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(traps.data.by_type).map(([type, count]) => (
                    <Pill key={type}>
                      {type.toLowerCase().replaceAll("_", " ")} {count}
                    </Pill>
                  ))}
                </div>
                {traps.data.flaps.map((flap) => (
                  <p key={`${flap.device_id}${flap.down_at}`} className="text-ink-2">
                    Flap: {flap.device_id} {flap.interface} down {clock(flap.down_at)} → up {clock(flap.up_at)} ({Math.round(flap.seconds / 60)} min)
                  </p>
                ))}
                {traps.data.still_down.map((down) => (
                  <p key={`${down.device_id}${down.since}`} className="text-red">
                    Still down: {down.device_id} {down.interface ?? ""} since {clock(down.since)}
                  </p>
                ))}
                {!traps.data.total ? <Empty>No traps in this window.</Empty> : null}
              </div>
            ) : (
              <Skeleton className="h-20" />
            )}
          </Panel>
          <Panel title="SNMP polling" aside="IF-MIB counter rates">
            {snmp.data ? (
              <Table head={["Device", "Polls", "Interfaces", "Down", "Wraps handled"]} minWidth={380}>
                {snmp.data.devices.map((row) => (
                  <tr key={row.device_id}>
                    <Cell mono>{row.device_id}</Cell>
                    <Cell mono>{row.polls}</Cell>
                    <Cell mono>{row.interfaces}</Cell>
                    <Cell mono className={row.down ? "text-red" : undefined}>
                      {row.down}
                    </Cell>
                    <Cell mono>{row.wraps_handled}</Cell>
                  </tr>
                ))}
              </Table>
            ) : (
              <Skeleton className="h-20" />
            )}
          </Panel>
        </div>
      </div>

      <Panel title="Performance baselines" aside={baselines.data ? `${baselines.data.anomalous} interfaces outside their baseline` : null}>
        {baselines.isPending ? <Skeleton className="h-24" /> : null}
        {baselines.data ? (
          baselines.data.items.some((b) => b.anomalies.length) ? (
            <Table head={["Interface", "Metric", "Deviation", "Value", "Expected", "From"]} minWidth={640}>
              {baselines.data.items.flatMap((b) =>
                b.anomalies.map((a) => (
                  <tr key={`${b.interface_id}${a.metric}${a.kind}`}>
                    <Cell mono>{b.interface_id}</Cell>
                    <Cell>{a.metric.replace("_", " ")}</Cell>
                    <Cell>
                      <Pill tone={a.kind === "down" ? "red" : a.kind === "gap" ? "muted" : "amber"}>{a.kind === "gap" ? "no data" : a.kind}</Pill>
                    </Cell>
                    <Cell mono>{a.value ?? "—"}</Cell>
                    <Cell mono>{a.expected}</Cell>
                    <Cell mono>{clock(a.first_seen)}</Cell>
                  </tr>
                )),
              )}
            </Table>
          ) : (
            <Empty>Every interface is within its learned baseline.</Empty>
          )
        ) : null}
        <div className="mt-2">
          <SourceNote>Baselines: median and MAD per local half-hour over 14 days of simulated history, weekdays and weekends apart, trend-adjusted.</SourceNote>
        </div>
      </Panel>
    </div>
  );
}
