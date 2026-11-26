"use client";

import Link from "next/link";
import { NewIncident } from "@/components/diagnose/new-incident";
import { Topbar } from "@/components/shell/topbar";
import { Dot, ErrorNote, Skeleton } from "@/components/ui/atoms";
import { describeError } from "@/lib/api/client";
import { useActiveIncidents } from "@/lib/api/hooks";
import { PRIORITY_LABEL, STATUS_LABEL, statusTone } from "@/lib/labels";
import { ago } from "@/lib/time";

export function DiagnoseView() {
  return (
    <>
      <Topbar crumbs={[{ label: "Network diagnosis" }]} />
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto grid w-full max-w-[1120px] gap-10 px-5 pt-8 pb-16 md:px-8 lg:grid-cols-[minmax(0,1fr)_300px]">
          <section aria-labelledby="new-heading" className="min-w-0">
            <h1 id="new-heading" className="text-[30px] leading-[1.08] font-semibold tracking-[-0.035em] text-balance text-ink">
              Find what broke before users call again
            </h1>
            <p className="mt-2.5 max-w-[560px] text-[14.5px] leading-[1.5] text-ink-3 text-pretty">
              Describe the problem. The diagnosis checks reachability, interfaces, routing, firewall, DHCP and DNS from telemetry, without
              touching a device.
            </p>
            <div className="mt-7">
              <NewIncident />
            </div>
          </section>
          <ActiveIncidents />
        </div>
      </div>
    </>
  );
}

function ActiveIncidents() {
  const active = useActiveIncidents();
  const items = [...(active.data?.items ?? [])].sort((a, b) => b.updated_at.localeCompare(a.updated_at));
  return (
    <aside aria-labelledby="active-heading" className="lg:pt-1">
      <div className="flex items-baseline justify-between">
        <h2 id="active-heading" className="text-[15px] font-semibold tracking-[-0.015em] text-ink">
          Active incidents
        </h2>
        {active.data ? <span className="text-[12px] tabular-nums text-ink-3">{active.data.total}</span> : null}
      </div>
      {active.isPending ? (
        <div className="mt-3 space-y-2">
          <Skeleton className="h-14" />
          <Skeleton className="h-14" />
        </div>
      ) : active.isError ? (
        <div className="mt-3">
          <ErrorNote message={describeError(active.error)} onRetry={() => active.refetch()} />
        </div>
      ) : items.length === 0 ? (
        <p className="mt-3 text-[12.5px] leading-[1.5] text-ink-3">Nothing is open. Incidents you open appear here until they&apos;re resolved.</p>
      ) : (
        <ul className="mt-3 space-y-1">
          {items.slice(0, 12).map((incident) => (
            <li key={incident.incident_id}>
              <Link href={`/diagnose/${incident.incident_id}`} className="flex gap-2.5 rounded-[8px] px-2.5 py-2.5 hover:bg-hover">
                <Dot tone={statusTone(incident.status)} className="mt-[7px]" />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-[13.5px] font-medium tracking-[-0.01em] text-ink">{incident.title}</span>
                  <span className="mt-0.5 block truncate text-[12px] text-ink-3">
                    {PRIORITY_LABEL[incident.priority]} · {STATUS_LABEL[incident.status]} · {incident.site_ids.join(", ")} · {ago(incident.updated_at)}
                  </span>
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
      {active.data && active.data.total > 12 ? (
        <Link href="/incidents" className="mt-2 block px-2.5 text-[12.5px] text-ink-3 hover:text-ink">
          All {active.data.total} active incidents
        </Link>
      ) : null}
    </aside>
  );
}
