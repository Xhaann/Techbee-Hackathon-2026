"use client";

import { BrickWall, ChevronRight, EthernetPort, Router, Server } from "lucide-react";
import { Fragment, type ComponentType } from "react";
import { Skeleton } from "@/components/ui/atoms";
import { Tip } from "@/components/ui/tip";
import type { DeviceType, FaultDomain } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { ROLE_LABEL } from "@/lib/labels";
import { FAULT_POINT_TEXT, type Hop } from "./model";

const ICON: Record<DeviceType, ComponentType<{ className?: string }>> = {
  router: Router,
  switch: EthernetPort,
  firewall: BrickWall,
  server: Server,
};

const NODE = {
  fault: { ring: "shadow-[0_0_0_1px_var(--amber-line)] bg-amber-soft", icon: "text-amber", label: "text-amber", sub: "text-amber" },
  down: { ring: "shadow-[0_0_0_1px_var(--red-line)] bg-red-soft", icon: "text-red", label: "text-red", sub: "text-red" },
  ok: { ring: "shadow-[0_0_0_1px_var(--green-line)] bg-green-soft", icon: "text-green", label: "text-ink", sub: "text-green" },
  unknown: { ring: "shadow-[0_0_0_1px_var(--line-strong)] bg-surface", icon: "text-ink-3", label: "text-ink", sub: "text-ink-3" },
} as const;

const LINE = { ok: "bg-line-strong text-ink-3", degraded: "bg-amber-line text-amber", failed: "bg-red-line text-red" } as const;

export function AffectedPath({
  hops,
  domain,
  circuit,
  reachability,
  loading,
}: {
  hops: Hop[];
  domain: FaultDomain;
  circuit?: string;
  reachability?: string;
  loading: boolean;
}) {
  return (
    <section aria-labelledby="path-heading" className="card px-4 pt-3.5 pb-4">
      <div className="flex items-baseline justify-between gap-4">
        <h2 id="path-heading" className="text-[15px] font-semibold tracking-[-0.015em] text-ink">
          Affected path
        </h2>
        <div className="flex items-center gap-3 font-mono text-[11.5px] text-ink-3">
          {reachability && reachability !== "reachable" ? <span className="text-red">{reachability}</span> : null}
          {circuit ? <span className="truncate">{circuit}</span> : null}
        </div>
      </div>

      {loading && !hops.length ? (
        <div className="mt-5 flex items-center gap-4">
          {[0, 1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-14 flex-1" />
          ))}
        </div>
      ) : !hops.length ? (
        <p className="mt-3 text-[12.5px] text-ink-3">The diagnosis didn&apos;t trace a path for this incident.</p>
      ) : (
        <ol className="scroll-thin -mx-1 mt-4 flex items-start overflow-x-auto px-1 pb-1">
          {hops.map((hop) => {
            const style = NODE[hop.state];
            const Icon = hop.device ? ICON[hop.device.device_type] : Server;
            const sub =
              hop.state === "fault" ? (hop.breaks ? "Path breaks here" : FAULT_POINT_TEXT[domain]) : hop.state === "down" ? "Unavailable" : hop.state === "ok" ? "Available" : "Not checked";
            return (
              <Fragment key={hop.deviceId}>
                <li className="flex w-[100px] shrink-0 flex-col items-center text-center">
                  <Tip
                    label={
                      hop.device ? (
                        <span className="block">
                          <span className="block text-ink">{ROLE_LABEL[hop.device.role]} · {hop.device.site_id}</span>
                          <span className="block">
                            {hop.device.vendor} {hop.device.model}, {hop.device.hostname}
                          </span>
                          {hop.health?.finding_codes.length ? <span className="block font-mono text-[11px]">{hop.health.finding_codes.join(", ")}</span> : null}
                        </span>
                      ) : (
                        hop.deviceId
                      )
                    }
                  >
                    <span tabIndex={0} aria-label={`${hop.deviceId}: ${sub}`} className="relative z-10 rounded-full bg-surface">
                      <span className={cn("grid size-[32px] place-items-center rounded-full", style.ring)}>
                        <Icon className={cn("size-[16px]", style.icon)} />
                      </span>
                    </span>
                  </Tip>
                  <span className={cn("mt-2.5 max-w-full truncate font-mono text-[11.5px] font-medium", style.label)}>{hop.deviceId}</span>
                  <span className={cn("mt-1 max-w-full truncate text-[11.5px]", style.sub)}>{sub}</span>
                </li>
                {hop.linkToNext ? (
                  <li aria-hidden className="relative -mx-[34px] mt-[15.5px] min-w-[86px] flex-1">
                    <Tip label={hop.linkToNext.id ? `${hop.linkToNext.id}${hop.linkToNext.link?.provider ? ` · ${hop.linkToNext.link.provider}` : ""}${hop.linkToNext.state !== "ok" ? ` · ${hop.linkToNext.state}` : ""}` : "Link"}>
                      <span className={cn("block h-px w-full", LINE[hop.linkToNext.state].split(" ")[0])} />
                    </Tip>
                    <ChevronRight
                      className={cn("absolute top-1/2 left-1/2 size-3 -translate-x-1/2 -translate-y-1/2 rounded-sm bg-surface", LINE[hop.linkToNext.state].split(" ")[1])}
                    />
                  </li>
                ) : null}
              </Fragment>
            );
          })}
        </ol>
      )}
    </section>
  );
}
