"use client";

import { Download } from "lucide-react";
import { useState } from "react";
import { Dot, ErrorNote, Pill, Skeleton } from "@/components/ui/atoms";
import { Button } from "@/components/ui/button";
import { StatBar } from "@/components/ui/charts";
import { Segmented } from "@/components/ui/controls";
import { SelectBox } from "@/components/ui/fields";
import { notify } from "@/components/ui/toaster";
import { describeError } from "@/lib/api/client";
import { downloadReliability, useReliability } from "@/lib/api/observability";
import { SCENARIOS } from "@/lib/scenarios";
import { Cell, Meter, SERVICE_NAME, SourceNote, Table } from "./shared";

const percent = (value: number | null) => (value === null ? "—" : `${value.toFixed(value >= 99.9 ? 3 : 2)}%`);

export function ReliabilitySection() {
  const [scenario, setScenario] = useState("BASELINE");
  const [period, setPeriod] = useState<"7d" | "14d">("14d");
  const report = useReliability(scenario, period);
  const data = report.data;
  const exportAs = (format: "json" | "markdown" | "csv") =>
    downloadReliability(scenario, period, format).catch((error) => notify.error("Export failed", error));

  return (
    <section aria-labelledby="reliability-heading" className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 id="reliability-heading" className="text-[15px] font-semibold tracking-[-0.015em] text-ink">
          Network reliability
        </h2>
        <div className="flex flex-wrap items-center gap-2">
          <SelectBox size="sm" ariaLabel="Reliability dataset" className="w-[260px]" value={scenario} onValueChange={setScenario} options={SCENARIOS.map((s) => ({ value: s.id, label: s.name }))} />
          <Segmented
            size="sm"
            ariaLabel="Report period"
            value={period}
            onValueChange={setPeriod}
            options={[
              { value: "7d", label: "7 days" },
              { value: "14d", label: "14 days" },
            ]}
          />
          <Button size="sm" onClick={() => exportAs("csv")} disabled={!data}>
            <Download className="size-3.5" aria-hidden />
            CSV
          </Button>
          <Button size="sm" onClick={() => exportAs("markdown")} disabled={!data}>
            Markdown
          </Button>
          <Button size="sm" onClick={() => exportAs("json")} disabled={!data}>
            JSON
          </Button>
        </div>
      </div>
      {report.isError ? <ErrorNote message={describeError(report.error)} onRetry={() => report.refetch()} /> : null}
      <StatBar
        loading={report.isPending}
        stats={[
          { key: "links", label: "Links measured", value: data?.summary.links },
          { key: "services", label: "Service paths", value: data?.summary.services },
          { key: "outages", label: "Link outages", value: data?.summary.total_outages, tone: "amber" },
          { key: "breaches", label: "SLA breaches", value: data?.summary.breaches.length, tone: "red" },
        ]}
      />
      {report.isPending ? <Skeleton className="h-48" /> : null}
      {data ? (
        <div className="space-y-3">
          <div className="card px-4 py-3">
            <Table head={["Link", "Availability", "Outages", "MTBF", "MTTR", "SLA"]} minWidth={620}>
              {data.links.map((row) => (
                <tr key={row.link_id}>
                  <Cell mono>
                    {row.link_id}
                    {row.provider ? <div className="text-[11px] text-ink-4">{row.provider}</div> : null}
                  </Cell>
                  <Cell>
                    <span className="font-mono text-[12px]">{percent(row.availability_percent)}</span>
                    <div className="mt-1 w-24">
                      <Meter value={row.error_budget_used_percent ?? 0} tone={row.sla_met === false ? "red" : "amber"} />
                    </div>
                  </Cell>
                  <Cell mono>{row.outages}</Cell>
                  <Cell mono>{row.mtbf_hours === null ? "—" : `${row.mtbf_hours} h`}</Cell>
                  <Cell mono>{row.mttr_minutes === null ? "—" : `${row.mttr_minutes} min`}</Cell>
                  <Cell>
                    <Pill tone={row.sla_met === false ? "red" : "green"}>
                      {row.sla_met === false ? "breached" : "met"} · {row.sla_target_percent}%
                    </Pill>
                  </Cell>
                </tr>
              ))}
            </Table>
            <p className="mt-2 text-[11.5px] text-ink-4">The bar under each figure is the share of the error budget used.</p>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <div className="card px-4 py-3">
              <h3 className="text-[14px] font-semibold tracking-[-0.01em] text-ink">Sites</h3>
              <ul className="mt-2 space-y-1.5">
                {data.sites.map((site) => (
                  <li key={site.site_id} className="flex items-center gap-2 text-[12.5px]">
                    <Dot tone={site.sla_met ? "green" : "red"} />
                    <span className="text-ink-2">{site.name}</span>
                    <span className="ml-auto font-mono text-ink-3">{percent(site.availability_percent)}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="card px-4 py-3">
              <h3 className="text-[14px] font-semibold tracking-[-0.01em] text-ink">Services below 100%</h3>
              <ul className="mt-2 space-y-1.5 text-[12.5px]">
                {data.services
                  .filter((s) => (s.availability_percent ?? 100) < 100)
                  .map((service) => (
                    <li key={service.path_id} className="flex items-center gap-2">
                      <span className="text-ink-2">
                        {service.site_id} {SERVICE_NAME[service.service] ?? service.service}
                      </span>
                      <span className="ml-auto font-mono text-ink-3">{percent(service.availability_percent)}</span>
                    </li>
                  ))}
                {data.services.every((s) => (s.availability_percent ?? 100) >= 100) ? <li className="text-ink-3">Every service path was available throughout.</li> : null}
              </ul>
            </div>
          </div>
        </div>
      ) : null}
      {data ? <SourceNote>{`${data.source}. ${data.method}`}</SourceNote> : null}
    </section>
  );
}
