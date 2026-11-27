"use client";

import { useState } from "react";
import { ErrorNote, Pill, Skeleton } from "@/components/ui/atoms";
import { SelectBox } from "@/components/ui/fields";
import { describeError } from "@/lib/api/client";
import { type Forecast, useCongestion, useForecast, useForecasts } from "@/lib/api/observability";
import { Cell, Panel, RISK_TONE, SourceNote, Table } from "./shared";

const W = 760;
const H = 240;
const PAD = { left: 36, right: 12, top: 12, bottom: 26 };

/** Weekday busy-hour peaks (dots), the fitted trend with its 95% prediction band, and the 80%/90% thresholds. */
function ForecastChart({ forecast }: { forecast: Forecast }) {
  const points = [...forecast.observed.map((o) => ({ day: o.day, value: o.peak, weekend: o.weekend, kind: "observed" as const }))];
  const future = forecast.forecast.filter((f) => !f.weekend);
  const days = [...points.map((p) => p.day), ...future.map((f) => f.day)];
  const x = (day: string) => PAD.left + (days.indexOf(day) / Math.max(1, days.length - 1)) * (W - PAD.left - PAD.right);
  const y = (value: number) => PAD.top + (1 - value / 100) * (H - PAD.top - PAD.bottom);
  const band = future.length
    ? `M ${future.map((f) => `${x(f.day)} ${y(f.high)}`).join(" L ")} L ${[...future].reverse().map((f) => `${x(f.day)} ${y(f.low)}`).join(" L ")} Z`
    : "";
  const line = future.length ? `M ${future.map((f) => `${x(f.day)} ${y(f.peak)}`).join(" L ")}` : "";
  return (
    <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Utilisation forecast for ${forecast.interface_id}`} className="h-auto w-full">
      {[0, 25, 50, 75, 100].map((tick) => (
        <g key={tick}>
          <line x1={PAD.left} x2={W - PAD.right} y1={y(tick)} y2={y(tick)} stroke="var(--line-soft)" />
          <text x={PAD.left - 6} y={y(tick) + 3} textAnchor="end" fontSize={10} fill="var(--ink-4)">
            {tick}%
          </text>
        </g>
      ))}
      {[80, 90].map((threshold) => (
        <g key={threshold}>
          <line x1={PAD.left} x2={W - PAD.right} y1={y(threshold)} y2={y(threshold)} stroke={threshold === 90 ? "var(--red)" : "var(--amber)"} strokeDasharray="4 4" />
          <text x={W - PAD.right} y={y(threshold) - 4} textAnchor="end" fontSize={10} fill={threshold === 90 ? "var(--red)" : "var(--amber)"}>
            {threshold}%
          </text>
        </g>
      ))}
      {band ? <path d={band} fill="var(--chart)" opacity={0.14} /> : null}
      {line ? <path d={line} fill="none" stroke="var(--chart)" strokeWidth={2} strokeDasharray="5 4" /> : null}
      {points.map((point) => (
        <circle key={point.day} cx={x(point.day)} cy={y(point.value)} r={point.weekend ? 2.5 : 3.5} fill={point.weekend ? "var(--ink-4)" : "var(--chart)"}>
          <title>{`${point.day}: busy-hour peak ${point.value}%${point.weekend ? " (weekend, not fitted)" : ""}`}</title>
        </circle>
      ))}
      <text x={PAD.left} y={H - 6} fontSize={10} fill="var(--ink-4)">
        {days[0]}
      </text>
      <text x={W - PAD.right} y={H - 6} fontSize={10} fill="var(--ink-4)" textAnchor="end">
        {days[days.length - 1]}
      </text>
    </svg>
  );
}

export function CapacityPanel({ scenario }: { scenario: string }) {
  const forecasts = useForecasts(scenario);
  const congestion = useCongestion(scenario);
  const options = (forecasts.data?.items ?? []).map((f) => ({ value: f.interface_id, label: `${f.interface_id} (${f.link_id ?? "no link"})` }));
  const [chosen, setChosen] = useState<string | null>(null);
  const selected = chosen ?? options.find((o) => o.value.startsWith("NYC"))?.value ?? options[0]?.value ?? null;
  const forecast = useForecast(scenario, selected);
  const data = forecast.data;

  return (
    <div className="space-y-3">
      <Panel
        title="Interface utilisation forecast"
        aside={
          options.length ? <SelectBox size="sm" ariaLabel="Interface" className="w-[320px]" value={selected} onValueChange={setChosen} options={options} /> : null
        }
      >
        {forecast.isPending ? <Skeleton className="h-60" /> : null}
        {forecast.isError ? <ErrorNote message={describeError(forecast.error)} onRetry={() => forecast.refetch()} /> : null}
        {data ? (
          data.status !== "ok" ? (
            <p className="text-[12.5px] text-ink-3">Not enough history to forecast this interface.</p>
          ) : (
            <>
              <div className="mb-2 flex flex-wrap gap-4 text-[12.5px] text-ink-2">
                <span>
                  Busy-hour peak today <span className="font-mono">{data.current_peak}%</span>
                </span>
                <span>
                  Trend <span className="font-mono">{data.trend_per_day! >= 0 ? "+" : ""}{data.trend_per_day}</span> points/day
                </span>
                <span>
                  80% in <span className="font-mono">{data.days_to?.["80"] ?? "—"}</span> days
                </span>
                <span>
                  90% in <span className="font-mono">{data.days_to?.["90"] ?? "—"}</span> days
                </span>
                {data.next_24h_peak ? (
                  <span>
                    Next 24 h peak <span className="font-mono">{data.next_24h_peak.expected}%</span> at {String(data.next_24h_peak.local_hour).padStart(2, "0")}:00 local
                  </span>
                ) : null}
              </div>
              <ForecastChart forecast={data} />
              <SourceNote>{data.method}. History is 14 days of simulated 5-minute samples ending with the scenario window.</SourceNote>
            </>
          )
        ) : null}
      </Panel>

      <Panel title="Congestion risk" aside={congestion.data ? `${congestion.data.summary.high} high · ${congestion.data.summary.medium} medium` : null}>
        {congestion.isPending ? <Skeleton className="h-40" /> : null}
        {congestion.isError ? <ErrorNote message={describeError(congestion.error)} onRetry={() => congestion.refetch()} /> : null}
        {congestion.data ? (
          <Table head={["Link", "Risk", "Now", "Drivers", "Advice"]} minWidth={820}>
            {congestion.data.items.map((row) => (
              <tr key={row.link_id}>
                <Cell mono>
                  <button type="button" className="hover:underline" onClick={() => row.interface_id && setChosen(row.interface_id)} disabled={!row.interface_id}>
                    {row.link_id}
                  </button>
                </Cell>
                <Cell>
                  <Pill tone={RISK_TONE[row.level]}>{row.level}</Pill>
                  {row.probability !== null ? <div className="mt-0.5 text-[11px] text-ink-4">24 h &gt; 90%: {Math.round(row.probability * 100)}%</div> : null}
                </Cell>
                <Cell mono>{row.current_utilization ?? "—"}%</Cell>
                <Cell className="max-w-[360px] text-[12px]">{row.drivers.join("; ")}</Cell>
                <Cell className="text-[12px] text-ink-3">{row.recommendation ?? "—"}</Cell>
              </tr>
            ))}
          </Table>
        ) : null}
        <div className="mt-2">
          <SourceNote>&ldquo;24 h &gt; 90%&rdquo; is the modelled chance that the next day&apos;s peak exceeds 90%. Advice is advisory: nothing is changed on any device.</SourceNote>
        </div>
      </Panel>
    </div>
  );
}
