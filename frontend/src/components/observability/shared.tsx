"use client";

import type { ReactNode } from "react";
import { Pill } from "@/components/ui/atoms";
import type { HealthStatus } from "@/lib/api/observability";
import { cn } from "@/lib/cn";
import type { Tone } from "@/lib/labels";

export const HEALTH_TONE: Record<HealthStatus, Tone> = { healthy: "green", degraded: "amber", critical: "red", unknown: "muted" };
export const HEALTH_LABEL: Record<HealthStatus, string> = { healthy: "Healthy", degraded: "Degraded", critical: "Critical", unknown: "No data" };
export const HEALTH_STROKE: Record<HealthStatus, string> = {
  healthy: "var(--green)",
  degraded: "var(--amber)",
  critical: "var(--red)",
  unknown: "var(--ink-4)",
};
export const RISK_TONE: Record<string, Tone> = { high: "red", medium: "amber", low: "green", unavailable: "muted", unknown: "muted" };
export const SEVERITY_TONE: Record<string, Tone> = { critical: "red", high: "red", medium: "amber", low: "muted" };
export const SERVICE_NAME: Record<string, string> = {
  application: "ERP application",
  internet: "Internet",
  dns: "DNS",
  dhcp: "DHCP",
  authentication: "Authentication",
  other: "Other",
};

export function ScorePill({ score, status }: { score: number | null | undefined; status: HealthStatus }) {
  return (
    <Pill tone={HEALTH_TONE[status]} dot>
      {score === null || score === undefined ? HEALTH_LABEL[status] : `${Math.round(score)} · ${HEALTH_LABEL[status]}`}
    </Pill>
  );
}

export function bytes(value: number) {
  if (value >= 1e9) return `${(value / 1e9).toFixed(1)} GB`;
  if (value >= 1e6) return `${(value / 1e6).toFixed(1)} MB`;
  if (value >= 1e3) return `${(value / 1e3).toFixed(1)} kB`;
  return `${value} B`;
}

export function clock(iso: string | null | undefined) {
  return iso ? iso.slice(11, 16) : "—";
}

/** A card with a heading row, used for every panel on the observability page. */
export function Panel({ title, aside, children, className }: { title: ReactNode; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cn("card px-4 pt-3.5 pb-4", className)}>
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h3 className="text-[14px] font-semibold tracking-[-0.01em] text-ink">{title}</h3>
        {aside ? <div className="text-[12px] text-ink-3">{aside}</div> : null}
      </div>
      <div className="mt-3">{children}</div>
    </section>
  );
}

/** States where a value came from, so simulated data is never mistaken for a live device. */
export function SourceNote({ children }: { children: ReactNode }) {
  const text = typeof children === "string" && children ? children[0].toUpperCase() + children.slice(1) : children;
  return <p className="text-[12px] leading-[1.45] text-ink-4">{text}</p>;
}

export const plural = (count: number, word: string, many = `${word}s`) => `${count} ${count === 1 ? word : many}`;

export function Empty({ children }: { children: ReactNode }) {
  return <p className="text-[12.5px] text-ink-3">{children}</p>;
}

export function Table({ head, children, minWidth = 640 }: { head: ReactNode[]; children: ReactNode; minWidth?: number }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[12.5px]" style={{ minWidth }}>
        <thead>
          <tr className="text-[12px] text-ink-3 shadow-[inset_0_-1px_0_var(--line-soft)]">
            {head.map((cell, index) => (
              <th key={index} className="px-2.5 py-2 font-normal first:pl-0 last:pr-0">
                {cell}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-line-soft">{children}</tbody>
      </table>
    </div>
  );
}

export function Cell({ children, mono, className }: { children: ReactNode; mono?: boolean; className?: string }) {
  return <td className={cn("px-2.5 py-2 align-top text-ink-2 first:pl-0 last:pr-0", mono && "font-mono text-[11.5px]", className)}>{children}</td>;
}

/** A thin horizontal meter for a 0-100 value. */
export function Meter({ value, tone = "chart" }: { value: number | null | undefined; tone?: "chart" | Tone }) {
  const width = value === null || value === undefined || value <= 0 ? 0 : Math.max(2, Math.min(100, value));
  const colour = tone === "chart" ? "bg-chart" : { amber: "bg-amber", green: "bg-green", red: "bg-red", accent: "bg-accent", muted: "bg-ink-4" }[tone];
  return (
    <span className="block h-1.5 w-full rounded-full bg-hover">
      <span className={cn("block h-1.5 rounded-r-full", colour)} style={{ width: `${width}%` }} />
    </span>
  );
}
