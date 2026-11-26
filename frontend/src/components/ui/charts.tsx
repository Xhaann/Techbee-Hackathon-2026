"use client";

import { useState, type ReactNode } from "react";
import { cn } from "@/lib/cn";
import { Flow } from "./flow";
import { Skeleton } from "./atoms";

export type Stat = { key: string; label: string; value: number | undefined; caption?: ReactNode; tone?: "amber" | "green" | "red" };

/** Several figures that share one comparison: one flush bar split by hairline seams. */
export function StatBar({ stats, loading, comparison }: { stats: Stat[]; loading?: boolean; comparison?: string }) {
  return (
    <section aria-label={comparison ?? "Summary"}>
      {comparison ? <p className="mb-2 text-[12.5px] text-ink-3">{comparison}</p> : null}
      <div className="card grid grid-cols-2 divide-line-soft sm:flex sm:divide-x">
        {stats.map((stat) => (
          <div key={stat.key} className="min-w-0 flex-1 px-4 py-3.5">
            <div className="truncate text-[12.5px] text-ink-2">{stat.label}</div>
            {loading || stat.value === undefined ? (
              <Skeleton className="mt-2 h-6 w-12" />
            ) : (
              <Flow
                value={stat.value}
                format={(v) => v.toLocaleString("en-US")}
                className={cn(
                  "mt-1.5 font-mono text-[24px] leading-none font-medium tracking-[-0.02em] tabular-nums",
                  stat.tone === "amber" && stat.value > 0 ? "text-amber" : stat.tone === "red" && stat.value > 0 ? "text-red" : stat.tone === "green" && stat.value > 0 ? "text-green" : "text-ink",
                )}
              />
            )}
            {stat.caption ? <div className="mt-2 truncate text-[11.5px] text-ink-3">{stat.caption}</div> : null}
          </div>
        ))}
      </div>
    </section>
  );
}

export type Bar = { key: string; label: string; value: number };

/**
 * One series of counts across categories: thin bars grown from one baseline, 4px rounded data end,
 * the value at the tip, and a readout with the share on hover or focus.
 */
export function BarList({
  title,
  bars,
  unit = "incident",
  plural = `${unit}s`,
  empty = "No records yet",
}: {
  title: string;
  bars: Bar[];
  unit?: string;
  plural?: string;
  empty?: string;
}) {
  const units = (n: number) => `${n} ${n === 1 ? unit : plural}`;
  const [active, setActive] = useState<string | null>(null);
  const total = bars.reduce((sum, bar) => sum + bar.value, 0);
  const max = Math.max(1, ...bars.map((bar) => bar.value));
  const sorted = [...bars].sort((a, b) => b.value - a.value);
  const focus = sorted.find((bar) => bar.key === active);

  return (
    <section className="card px-4 pt-3.5 pb-4" aria-label={title}>
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="text-[14px] font-semibold tracking-[-0.01em] text-ink">{title}</h3>
        <span className="min-h-[18px] text-right text-[12px] text-ink-3" aria-live="polite">
          {focus ? `${focus.label}: ${units(focus.value)} · ${total ? Math.round((focus.value / total) * 100) : 0}%` : units(total)}
        </span>
      </div>
      {sorted.length === 0 || total === 0 ? (
        <p className="mt-3 text-[12.5px] text-ink-3">{empty}</p>
      ) : (
        <ul className="mt-3 space-y-[2px]">
          {sorted.map((bar) => (
            <li
              key={bar.key}
              tabIndex={0}
              aria-label={`${bar.label}: ${units(bar.value)}, ${Math.round((bar.value / total) * 100)}% of ${total}`}
              onMouseEnter={() => setActive(bar.key)}
              onMouseLeave={() => setActive(null)}
              onFocus={() => setActive(bar.key)}
              onBlur={() => setActive(null)}
              className={cn("grid grid-cols-[minmax(90px,38%)_1fr] items-center gap-3 rounded-[6px] px-1.5 py-[5px] outline-none", active === bar.key && "bg-hover")}
            >
              <span className="truncate text-[12.5px] text-ink-2">{bar.label}</span>
              <span className="flex items-center gap-2">
                <span
                  className="h-2 rounded-r-[4px] bg-chart transition-[width] duration-[860ms] ease-(--ease-spring)"
                  style={{ width: bar.value ? `${Math.max(2, (bar.value / max) * 100)}%` : 0, maxWidth: "calc(100% - 36px)" }}
                />
                <span className="font-mono text-[11.5px] tabular-nums text-ink-2">{bar.value}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function toBars(counts: Record<string, number> | undefined, label: (key: string) => string): Bar[] {
  return Object.entries(counts ?? {}).map(([key, value]) => ({ key, label: label(key), value }));
}
