"use client";

import { Download } from "lucide-react";
import Link from "next/link";
import { Topbar } from "@/components/shell/topbar";
import { ErrorNote, Skeleton } from "@/components/ui/atoms";
import { Button } from "@/components/ui/button";
import { BarList, StatBar, toBars } from "@/components/ui/charts";
import { describeError } from "@/lib/api/client";
import { useDiagnosisReport, useFaultDomainReport, useReportIncidents, useReportSummary } from "@/lib/api/hooks";
import type { FaultDomain, IncidentReportRow } from "@/lib/api/types";
import {
  CONFIDENCE_LABEL,
  DIAGNOSIS_STATUS_LABEL,
  FAULT_LABEL,
  humanize,
  METHOD_LABEL,
  PRIORITY_LABEL,
  SEVERITY_LABEL,
  STATUS_LABEL,
} from "@/lib/labels";
import { stamp } from "@/lib/time";

const fault = (key: string) => FAULT_LABEL[key as FaultDomain] ?? humanize(key);
const pick = (map: Record<string, string>) => (key: string) => map[key] ?? humanize(key);

function toCsv(rows: IncidentReportRow[]) {
  const header = ["incident_id", "title", "status", "severity", "priority", "fault_domain", "confirmed_fault_domain", "diagnoses", "escalations", "resolution_verification", "created_at", "closed_at"];
  const escape = (value: unknown) => {
    const text = value === null || value === undefined ? "" : String(value);
    return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
  };
  return [header.join(","), ...rows.map((row) => header.map((key) => escape(row[key as keyof IncidentReportRow])).join(","))].join("\n");
}

export function ReportsView() {
  const summary = useReportSummary();
  const domains = useFaultDomainReport();
  const diagnosis = useDiagnosisReport();
  const rows = useReportIncidents();
  const records = summary.data?.counts.records;

  const download = () => {
    const blob = new Blob([toCsv(rows.data?.items ?? [])], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "incident-report.csv";
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const failed = [summary, domains, diagnosis].find((q) => q.isError);

  return (
    <>
      <Topbar
        crumbs={[{ label: "Reports" }]}
        actions={
          <Button size="sm" onClick={download} disabled={!rows.data?.items.length}>
            <Download className="size-3.5" aria-hidden />
            Download CSV
          </Button>
        }
      />
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[1120px] space-y-6 px-5 pt-6 pb-16 md:px-8">
          <StatBar
            loading={summary.isPending}
            comparison="Every incident on record, from open to closed"
            stats={[
              { key: "incidents", label: "Incidents", value: summary.data?.total },
              { key: "diagnoses", label: "Diagnoses attached", value: records?.diagnoses },
              { key: "escalations", label: "Escalations recorded", value: records?.escalations },
              { key: "resolutions", label: "Resolutions proposed", value: records?.resolutions },
            ]}
          />
          {failed ? <ErrorNote message={describeError(failed.error)} onRetry={() => failed.refetch()} /> : null}

          <section aria-labelledby="incidents-mix" className="space-y-3">
            <h2 id="incidents-mix" className="text-[15px] font-semibold tracking-[-0.015em] text-ink">
              Where incidents stand
            </h2>
            {summary.isPending ? (
              <Skeleton className="h-40" />
            ) : (
              <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                <BarList title="Status" bars={toBars(summary.data?.counts.status, pick(STATUS_LABEL))} />
                <BarList title="Severity" bars={toBars(summary.data?.counts.severity, pick(SEVERITY_LABEL))} />
                <BarList title="Priority" bars={toBars(summary.data?.counts.priority, pick(PRIORITY_LABEL))} />
              </div>
            )}
          </section>

          <section aria-labelledby="domains" className="space-y-3">
            <h2 id="domains" className="text-[15px] font-semibold tracking-[-0.015em] text-ink">
              Fault domains
            </h2>
            {domains.isPending ? (
              <Skeleton className="h-40" />
            ) : (
              <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                <BarList title="Current classification" bars={toBars(domains.data?.counts.current, fault)} />
                <BarList title="Confirmed by a person" bars={toBars(domains.data?.counts.human_confirmed, fault)} empty="No classification confirmed yet" />
                <BarList title="Probable, from diagnosis" bars={toBars(domains.data?.counts.probable_from_diagnosis, fault)} empty="No diagnosis attached yet" />
              </div>
            )}
          </section>

          <section aria-labelledby="diagnoses" className="space-y-3">
            <h2 id="diagnoses" className="text-[15px] font-semibold tracking-[-0.015em] text-ink">
              Diagnoses
            </h2>
            {diagnosis.isPending ? (
              <Skeleton className="h-40" />
            ) : (
              <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                <BarList title="Method" unit="diagnosis" plural="diagnoses" bars={toBars(diagnosis.data?.counts.method, pick(METHOD_LABEL))} />
                <BarList title="Confidence" unit="diagnosis" plural="diagnoses" bars={toBars(diagnosis.data?.counts.confidence, pick(CONFIDENCE_LABEL))} />
                <BarList title="Outcome" unit="diagnosis" plural="diagnoses" bars={toBars(diagnosis.data?.counts.status, pick(DIAGNOSIS_STATUS_LABEL))} />
                <BarList title="Current or superseded" unit="diagnosis" plural="diagnoses" bars={toBars(diagnosis.data?.counts.superseded, humanize)} />
                <BarList
                  title="Person agreed with the diagnosis"
                  bars={toBars(diagnosis.data?.counts.human_confirmation, (k) => (k === "matches_diagnosis" ? "Agreed" : "Chose a different domain"))}
                  empty="No confirmed classification to compare"
                />
              </div>
            )}
          </section>

          <section aria-labelledby="table-heading">
            <h2 id="table-heading" className="text-[15px] font-semibold tracking-[-0.015em] text-ink">
              All incidents
            </h2>
            {rows.isPending ? (
              <Skeleton className="mt-3 h-40" />
            ) : rows.isError ? (
              <div className="mt-3">
                <ErrorNote message={describeError(rows.error)} onRetry={() => rows.refetch()} />
              </div>
            ) : (
              <div className="card mt-3 overflow-x-auto">
                <table className="w-full min-w-[900px] text-left text-[12.5px]">
                  <thead>
                    <tr className="text-[12px] text-ink-3 shadow-[inset_0_-1px_0_var(--line-soft)]">
                      <th className="px-4 py-2.5 font-normal">Incident</th>
                      <th className="px-3 py-2.5 font-normal">Status</th>
                      <th className="px-3 py-2.5 font-normal">Priority</th>
                      <th className="px-3 py-2.5 font-normal">Fault domain</th>
                      <th className="px-3 py-2.5 font-normal">Confirmed</th>
                      <th className="px-3 py-2.5 text-right font-normal">Diagnoses</th>
                      <th className="px-3 py-2.5 text-right font-normal">Escalations</th>
                      <th className="px-3 py-2.5 font-normal">Resolution</th>
                      <th className="px-4 py-2.5 font-normal">Opened</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line-soft">
                    {(rows.data?.items ?? []).map((row) => (
                      <tr key={row.incident_id} className="hover:bg-hover">
                        <td className="max-w-[280px] px-4 py-2.5">
                          <Link href={`/diagnose/${row.incident_id}`} className="block truncate text-ink hover:underline">
                            {row.title}
                          </Link>
                          <span className="font-mono text-[11px] text-ink-3">{row.incident_id}</span>
                        </td>
                        <td className="px-3 py-2.5 text-ink-2">{pick(STATUS_LABEL)(row.status)}</td>
                        <td className="px-3 py-2.5 text-ink-2">
                          {pick(PRIORITY_LABEL)(row.priority)} · {pick(SEVERITY_LABEL)(row.severity)}
                        </td>
                        <td className="px-3 py-2.5 text-ink-2">{row.fault_domain ? fault(row.fault_domain) : "—"}</td>
                        <td className="px-3 py-2.5 text-ink-2">{row.confirmed_fault_domain ? fault(row.confirmed_fault_domain) : "—"}</td>
                        <td className="px-3 py-2.5 text-right font-mono tabular-nums text-ink-2">{row.diagnoses}</td>
                        <td className="px-3 py-2.5 text-right font-mono tabular-nums text-ink-2">{row.escalations}</td>
                        <td className="px-3 py-2.5 text-ink-2">{row.resolution_verification ? humanize(row.resolution_verification) : "—"}</td>
                        <td className="px-4 py-2.5 font-mono text-[11.5px] whitespace-nowrap text-ink-3">{stamp(row.created_at)}</td>
                      </tr>
                    ))}
                    {!rows.data?.items.length ? (
                      <tr>
                        <td colSpan={9} className="px-4 py-6 text-center text-ink-3">
                          No incidents yet.
                        </td>
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      </div>
    </>
  );
}
