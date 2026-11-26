"use client";

import { ArrowRight, ChevronLeft, ChevronRight, Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Topbar } from "@/components/shell/topbar";
import { Dot, ErrorNote, Pill, Skeleton } from "@/components/ui/atoms";
import { StatBar } from "@/components/ui/charts";
import { ALL, SelectBox } from "@/components/ui/fields";
import { describeError } from "@/lib/api/client";
import { useDashboardSummary, useIncidents, useTopology } from "@/lib/api/hooks";
import type { FaultDomain, IncidentFilters, IncidentSeverity, LifecycleStatus } from "@/lib/api/types";
import { useCan } from "@/lib/auth";
import {
  FAULT_DOMAINS,
  FAULT_LABEL,
  PRIORITY_LABEL,
  SEVERITY_LABEL,
  severityTone,
  STATUS_LABEL,
  STATUS_ORDER,
  statusTone,
} from "@/lib/labels";
import { ago, stamp } from "@/lib/time";

const PAGE = 25;

export function IncidentsView() {
  const can = useCan();
  const router = useRouter();
  const summary = useDashboardSummary();
  const topology = useTopology();
  const [status, setStatus] = useState<LifecycleStatus | typeof ALL>(ALL);
  const [severity, setSeverity] = useState<IncidentSeverity | typeof ALL>(ALL);
  const [site, setSite] = useState<string>(ALL);
  const [domain, setDomain] = useState<FaultDomain | typeof ALL>(ALL);
  const [offset, setOffset] = useState(0);

  const filters: IncidentFilters = {
    status: status === ALL ? undefined : status,
    severity: severity === ALL ? undefined : severity,
    site_id: site === ALL ? undefined : site,
    fault_domain: domain === ALL ? undefined : domain,
    limit: PAGE,
    offset,
  };
  const list = useIncidents(filters);
  const counts = summary.data?.counts.status ?? {};
  const active = Object.entries(counts)
    .filter(([key]) => key !== "resolved" && key !== "closed")
    .reduce((sum, [, n]) => sum + n, 0);

  const reset = <T,>(setter: (v: T) => void) => (value: T) => {
    setter(value);
    setOffset(0);
  };

  const items = list.data?.items ?? [];
  const total = list.data?.total ?? 0;

  return (
    <>
      <Topbar
        crumbs={[{ label: "Incidents" }]}
        actions={
          can("create_incidents") ? (
            <Link
              href="/diagnose"
              className="inline-flex h-8 items-center gap-1.5 rounded-[7px] bg-accent-strong px-2.5 text-[13px] font-medium text-accent-fg hover:bg-accent-strong-hover"
            >
              <Plus className="size-3.5" aria-hidden />
              Open incident
            </Link>
          ) : null
        }
      />
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[1120px] space-y-5 px-5 pt-6 pb-16 md:px-8">
          <StatBar
            loading={summary.isPending}
            comparison={summary.data ? `${summary.data.total} incidents on record` : undefined}
            stats={[
              { key: "active", label: "Active", value: summary.data ? active : undefined },
              { key: "new", label: "Waiting to be acknowledged", value: summary.data ? (counts.new ?? 0) : undefined, tone: "amber" },
              { key: "escalated", label: "Escalated", value: summary.data ? (counts.escalated ?? 0) : undefined, tone: "amber" },
              { key: "monitoring", label: "Monitoring a fix", value: summary.data ? (counts.monitoring ?? 0) : undefined },
              { key: "done", label: "Resolved or closed", value: summary.data ? (counts.resolved ?? 0) + (counts.closed ?? 0) : undefined },
            ]}
          />

          <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filters">
            <SelectBox
              size="sm"
              ariaLabel="Status"
              className="w-[160px]"
              value={status}
              onValueChange={reset(setStatus)}
              options={[{ value: ALL, label: "Any status" }, ...STATUS_ORDER.map((s) => ({ value: s, label: STATUS_LABEL[s] }))]}
            />
            <SelectBox
              size="sm"
              ariaLabel="Severity"
              className="w-[140px]"
              value={severity}
              onValueChange={reset(setSeverity)}
              options={[{ value: ALL, label: "Any severity" }, ...(Object.keys(SEVERITY_LABEL) as IncidentSeverity[]).map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))]}
            />
            <SelectBox
              size="sm"
              ariaLabel="Site"
              className="w-[160px]"
              value={site}
              onValueChange={reset(setSite)}
              options={[{ value: ALL, label: "Any site" }, ...(topology.data?.sites ?? []).map((s) => ({ value: s.site_id, label: s.name }))]}
            />
            <SelectBox
              size="sm"
              ariaLabel="Fault domain"
              className="w-[200px]"
              value={domain}
              onValueChange={reset(setDomain)}
              options={[{ value: ALL, label: "Any fault domain" }, ...FAULT_DOMAINS.map((d) => ({ value: d, label: FAULT_LABEL[d] }))]}
            />
            {list.isFetching && !list.isPending ? <span className="text-[12px] text-ink-4">Updating</span> : null}
          </div>

          {list.isPending ? (
            <div className="space-y-2">
              {[0, 1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-12" />
              ))}
            </div>
          ) : list.isError ? (
            <ErrorNote message={describeError(list.error)} onRetry={() => list.refetch()} />
          ) : items.length === 0 ? (
            <div className="card px-5 py-8 text-center">
              <p className="text-[13.5px] text-ink-2">No incident matches these filters.</p>
              {can("create_incidents") ? (
                <Link href="/diagnose" className="mt-2 inline-flex items-center gap-1 text-[13px] text-accent hover:underline">
                  Open one from a user report <ArrowRight className="size-3.5" aria-hidden />
                </Link>
              ) : null}
            </div>
          ) : (
            <div className="card overflow-x-auto">
              <table className="w-full min-w-[820px] text-left text-[13px]">
                <thead>
                  <tr className="text-[12px] text-ink-3 shadow-[inset_0_-1px_0_var(--line-soft)]">
                    <th className="px-4 py-2.5 font-normal">Incident</th>
                    <th className="px-3 py-2.5 font-normal">Priority</th>
                    <th className="px-3 py-2.5 font-normal">Status</th>
                    <th className="px-3 py-2.5 font-normal">Fault domain</th>
                    <th className="px-3 py-2.5 font-normal">Sites</th>
                    <th className="px-4 py-2.5 text-right font-normal">Updated</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-soft">
                  {items.map((incident) => (
                    <tr
                      key={incident.incident_id}
                      onClick={() => router.push(`/diagnose/${incident.incident_id}`)}
                      className="cursor-default hover:bg-hover"
                    >
                      <td className="max-w-[360px] px-4 py-3">
                        <Link href={`/diagnose/${incident.incident_id}`} className="block truncate font-medium text-ink hover:underline">
                          {incident.title}
                        </Link>
                        <span className="mt-0.5 block font-mono text-[11px] text-ink-3">{incident.incident_id}</span>
                      </td>
                      <td className="px-3 py-3">
                        <Pill tone={severityTone(incident.severity)} dot>
                          {PRIORITY_LABEL[incident.priority]} · {SEVERITY_LABEL[incident.severity]}
                        </Pill>
                      </td>
                      <td className="px-3 py-3">
                        <span className="inline-flex items-center gap-2 text-ink-2">
                          <Dot tone={statusTone(incident.status)} />
                          {STATUS_LABEL[incident.status]}
                        </span>
                      </td>
                      <td className="px-3 py-3 text-ink-2">{incident.fault_domain ? FAULT_LABEL[incident.fault_domain] : <span className="text-ink-4">Not classified</span>}</td>
                      <td className="px-3 py-3 font-mono text-[12px] text-ink-2">{incident.site_ids.join(", ")}</td>
                      <td className="px-4 py-3 text-right text-[12px] whitespace-nowrap text-ink-3" title={stamp(incident.updated_at, incident.site_ids[0])}>
                        {ago(incident.updated_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {total > PAGE ? (
            <nav aria-label="Pages" className="flex items-center justify-end gap-3 text-[12.5px] text-ink-3">
              <span className="tabular-nums">
                {offset + 1}–{Math.min(offset + PAGE, total)} of {total}
              </span>
              <button
                type="button"
                aria-label="Previous page"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE))}
                className="grid size-8 place-items-center rounded-[7px] shadow-[0_0_0_1px_var(--line)] hover:bg-hover disabled:opacity-40"
              >
                <ChevronLeft className="size-4" aria-hidden />
              </button>
              <button
                type="button"
                aria-label="Next page"
                disabled={offset + PAGE >= total}
                onClick={() => setOffset(offset + PAGE)}
                className="grid size-8 place-items-center rounded-[7px] shadow-[0_0_0_1px_var(--line)] hover:bg-hover disabled:opacity-40"
              >
                <ChevronRight className="size-4" aria-hidden />
              </button>
            </nav>
          ) : null}
        </div>
      </div>
    </>
  );
}
