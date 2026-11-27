"use client";

import Link from "next/link";
import { NewIncident } from "@/components/diagnose/new-incident";
import { Topbar } from "@/components/shell/topbar";
import { DemoTag, Dot, ErrorNote, Skeleton } from "@/components/ui/atoms";
import { Flow } from "@/components/ui/flow";
import { describeError } from "@/lib/api/client";
import { useActiveIncidents } from "@/lib/api/hooks";
import type { IncidentSeverity } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { PRIORITY_LABEL, STATUS_LABEL, statusTone } from "@/lib/labels";
import { ago } from "@/lib/time";

const SHOWN = 12;

export function DiagnoseView() {
  return (
    <>
      <Topbar crumbs={[{ label: "Network diagnosis" }]} />
      {/* relative: form controls keep visually hidden inputs absolutely positioned; this keeps them inside the scroll area */}
      <div className="scroll-thin relative min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[1200px] px-5 pt-7 pb-16 md:px-8 md:pt-9">
          <header className="max-w-[680px]">
            <h1 className="text-[26px] leading-[1.08] font-semibold tracking-[-0.035em] text-balance text-ink sm:text-[32px] sm:leading-[1.06]">
              Find what broke before users call again
            </h1>
            <p className="mt-2.5 text-[14.5px] leading-[1.5] text-ink-3 text-pretty">
              Describe what users report. Read-only checks on reachability, interfaces, routing, firewall, DHCP and DNS telemetry find the
              cause without touching a device.
            </p>
          </header>
          <div className="mt-6 grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_340px]">
            <section aria-label="Open an incident" className="min-w-0">
              <NewIncident />
            </section>
            <ActiveIncidents />
          </div>
        </div>
      </div>
    </>
  );
}

/** Priority is coloured by what it means: the two most urgent levels stand out, the rest stay neutral. */
function priorityTone(severity: IncidentSeverity) {
  return severity === "critical" ? "text-red" : severity === "high" ? "text-amber" : "text-ink-3";
}

function ActiveIncidents() {
  const active = useActiveIncidents();
  const items = [...(active.data?.items ?? [])].sort((a, b) => b.updated_at.localeCompare(a.updated_at));
  return (
    <aside
      aria-labelledby="active-heading"
      className="card flex min-w-0 flex-col overflow-hidden xl:sticky xl:top-6 xl:max-h-[calc(100dvh-57px-48px)]"
    >
      <div className="flex h-12 shrink-0 items-center justify-between gap-3 px-4 shadow-[inset_0_-1px_0_var(--line-soft)]">
        <h2 id="active-heading" className="text-[14px] font-semibold tracking-[-0.015em] text-ink">
          Active incidents
        </h2>
        {active.data ? <Flow value={active.data.total} className="text-[12.5px] font-medium text-ink-3 tabular-nums" /> : null}
      </div>
      {active.isPending ? (
        <div className="space-y-2 p-4">
          <Skeleton className="h-12" />
          <Skeleton className="h-12" />
          <Skeleton className="h-12" />
        </div>
      ) : active.isError ? (
        <div className="p-4">
          <ErrorNote message={describeError(active.error)} onRetry={() => active.refetch()} />
        </div>
      ) : items.length === 0 ? (
        <p className="px-4 py-5 text-[13px] leading-[1.5] text-ink-3">Nothing is open. Incidents you open appear here until they&apos;re resolved.</p>
      ) : (
        <ul className="scroll-thin min-h-0 flex-1 divide-y divide-line-soft overflow-y-auto">
          {items.slice(0, SHOWN).map((incident) => (
            <li key={incident.incident_id}>
              <Link
                href={`/diagnose/${incident.incident_id}`}
                className="block px-4 py-3 transition-colors duration-150 outline-offset-[-2px] hover:bg-hover"
              >
                <span className="flex items-start gap-2">
                  <span className="line-clamp-2 min-w-0 flex-1 text-[13.5px] leading-[1.38] font-medium tracking-[-0.01em] text-ink">
                    {incident.title}
                  </span>
                  {incident.demo ? <DemoTag className="mt-px" /> : null}
                </span>
                <span className="mt-1.5 flex items-center gap-2.5 text-[12px] text-ink-3">
                  <span className={cn("font-medium tabular-nums", priorityTone(incident.severity))}>{PRIORITY_LABEL[incident.priority]}</span>
                  <span className="inline-flex shrink-0 items-center gap-1.5">
                    <Dot tone={statusTone(incident.status)} />
                    {STATUS_LABEL[incident.status]}
                  </span>
                  <span className="min-w-0 truncate font-mono text-[11px] text-ink-4">{incident.site_ids.join(" ")}</span>
                  <span className="ml-auto shrink-0 text-[11.5px] text-ink-4 tabular-nums">{ago(incident.updated_at)}</span>
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
      {active.data && active.data.total > SHOWN ? (
        <Link
          href="/incidents"
          className="block shrink-0 px-4 py-3 text-[12.5px] text-ink-3 shadow-[inset_0_1px_0_var(--line-soft)] hover:bg-hover hover:text-ink"
        >
          All {active.data.total} active incidents
        </Link>
      ) : null}
    </aside>
  );
}
