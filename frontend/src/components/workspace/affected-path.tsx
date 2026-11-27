"use client";

import { BrickWall, ChevronRight, CircleHelp, EthernetPort, RadioTower, Router, Server, Split, Wifi } from "lucide-react";
import { Fragment, useEffect, useRef, useState, type ComponentType, type CSSProperties } from "react";
import { Skeleton } from "@/components/ui/atoms";
import { Tip } from "@/components/ui/tip";
import type { DeviceType, FaultDomain } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { deviceTypeLabel, ROLE_LABEL } from "@/lib/labels";
import { FAULT_POINT_TEXT, type Hop } from "./model";

type Icon = ComponentType<{ className?: string }>;

const ICON: Record<DeviceType, Icon> = {
  router: Router,
  switch: EthernetPort,
  firewall: BrickWall,
  server: Server,
};

/** Icons for categories the inventory may add later; anything else (or no record at all) gets a neutral marker. */
const EXTRA_ICON: Record<string, Icon> = {
  access_point: Wifi,
  wireless_access_point: Wifi,
  wireless_controller: RadioTower,
  controller: RadioTower,
  load_balancer: Split,
};

export function deviceIcon(type: string | null | undefined): Icon {
  if (!type) return CircleHelp;
  return (ICON as Record<string, Icon>)[type] ?? EXTRA_ICON[type] ?? CircleHelp;
}

const NODE = {
  fault: { ring: "shadow-[0_0_0_1px_var(--amber-line)] bg-amber-soft", icon: "text-amber", label: "text-amber", sub: "text-amber" },
  down: { ring: "shadow-[0_0_0_1px_var(--red-line)] bg-red-soft", icon: "text-red", label: "text-red", sub: "text-red" },
  ok: { ring: "shadow-[0_0_0_1px_var(--green-line)] bg-green-soft", icon: "text-green", label: "text-ink", sub: "text-green" },
  unknown: { ring: "shadow-[0_0_0_1px_var(--line-strong)] bg-surface", icon: "text-ink-3", label: "text-ink", sub: "text-ink-3" },
} as const;

const LINE = { ok: "bg-line-strong text-ink-3", degraded: "bg-amber-line text-amber", failed: "bg-red-line text-red" } as const;

/**
 * Which ends of the path are scrolled out of view. Nodes are sized from the card's own width (a container query), so the path
 * fits whenever the card is wide enough, with or without the agent panel; when it cannot fit it scrolls instead of shrinking,
 * and a soft fade marks the side that has more nodes, so no node looks cut off.
 */
function useOverflowEdges(deps: unknown) {
  const ref = useRef<HTMLOListElement>(null);
  const [edges, setEdges] = useState({ start: false, end: false });
  useEffect(() => {
    const list = ref.current;
    if (!list) return;
    const update = () => {
      const start = list.scrollLeft > 1;
      const end = list.scrollLeft + list.clientWidth < list.scrollWidth - 1;
      setEdges((prev) => (prev.start === start && prev.end === end ? prev : { start, end }));
    };
    update();
    list.addEventListener("scroll", update, { passive: true });
    const observer = new ResizeObserver(update);
    observer.observe(list);
    return () => {
      list.removeEventListener("scroll", update);
      observer.disconnect();
    };
  }, [deps]);
  return { ref, edges };
}

function fade(edges: { start: boolean; end: boolean }): CSSProperties | undefined {
  if (!edges.start && !edges.end) return undefined;
  const mask = `linear-gradient(to right, ${edges.start ? "transparent 0, #000 28px" : "#000 0"}, ${edges.end ? "#000 calc(100% - 28px), transparent 100%" : "#000 100%"})`;
  return { maskImage: mask, WebkitMaskImage: mask };
}

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
  const { ref, edges } = useOverflowEdges(hops.length);
  return (
    <section aria-labelledby="path-heading" className="card @container px-4 pt-3.5 pb-4">
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
        <ol
          ref={ref}
          style={fade(edges)}
          data-overflow={edges.start || edges.end ? "scroll" : "fit"}
          className="scroll-thin -mx-1 mt-3 flex snap-x snap-proximity scroll-px-1 items-start overflow-x-auto px-1 pt-1 pb-1"
        >
          {hops.map((hop) => {
            const style = NODE[hop.state];
            const Icon = deviceIcon(hop.device?.device_type);
            const type = deviceTypeLabel(hop.device?.device_type);
            const sub =
              hop.state === "fault" ? (hop.breaks ? "Path breaks here" : FAULT_POINT_TEXT[domain]) : hop.state === "down" ? "Unavailable" : hop.state === "ok" ? "Available" : "Not checked";
            return (
              <Fragment key={hop.deviceId}>
                <li className="flex w-[88px] shrink-0 snap-start flex-col items-center text-center @[46rem]:w-[100px]">
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
                        `${hop.deviceId} · not in the inventory`
                      )
                    }
                  >
                    <span tabIndex={0} aria-label={`${hop.deviceId}, ${type}: ${sub}`} className="relative z-10 rounded-full bg-surface">
                      <span className={cn("grid size-[32px] place-items-center rounded-full", style.ring)}>
                        <Icon className={cn("size-[16px]", style.icon)} />
                      </span>
                    </span>
                  </Tip>
                  <span title={hop.deviceId} className={cn("mt-2.5 max-w-full truncate font-mono text-[11.5px] font-medium", style.label)}>
                    {hop.deviceId}
                  </span>
                  <span title={type} data-device-type className="mt-0.5 max-w-full truncate text-[11px] text-ink-3">
                    {type}
                  </span>
                  <span className={cn("mt-1 max-w-full truncate text-[11.5px]", style.sub)}>{sub}</span>
                </li>
                {hop.linkToNext ? (
                  <li aria-hidden className="relative -mx-[28px] mt-[15.5px] min-w-[64px] flex-1 @[46rem]:-mx-[34px] @[46rem]:min-w-[72px]">
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
