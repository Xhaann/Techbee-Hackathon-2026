"use client";

import { Skeleton } from "@/components/ui/atoms";
import { Flow } from "@/components/ui/flow";
import { Tip } from "@/components/ui/tip";
import { cn } from "@/lib/cn";
import { stamp } from "@/lib/time";
import type { Signal } from "./model";

const TONE_TEXT = { amber: "text-amber", red: "text-red", neutral: "text-ink" } as const;
const TONE_DOT = { amber: "bg-amber", red: "bg-red", neutral: "" } as const;

/** Measured readings in one flush bar, split by hairline seams. */
export function SignalStrip({ signals, loading, siteId, failed }: { signals: Signal[]; loading: boolean; siteId?: string; failed?: boolean }) {
  if (loading && !signals.length) {
    return (
      <div className="card grid grid-cols-1 divide-y divide-line-soft sm:grid-cols-3 sm:divide-x sm:divide-y-0">
        {[0, 1, 2].map((i) => (
          <div key={i} className="px-4 py-3.5">
            <Skeleton className="h-3 w-20" />
            <Skeleton className="mt-3 h-6 w-24" />
            <Skeleton className="mt-3 h-2.5 w-28" />
          </div>
        ))}
      </div>
    );
  }
  if (!signals.length) {
    return failed ? <p className="card px-4 py-3.5 text-[12.5px] text-ink-3">Telemetry readings aren&apos;t available for this diagnosis.</p> : null;
  }

  return (
    <section
      aria-label="Measured signals"
      className={cn(
        "card grid grid-cols-1 divide-y divide-line-soft sm:divide-x sm:divide-y-0",
        signals.length === 3 ? "sm:grid-cols-3" : signals.length === 2 ? "sm:grid-cols-2" : "",
      )}
    >
      {signals.map((signal) => {
        const numeric = signal.value !== null;
        const when = signal.at ? stamp(signal.at, siteId) : null;
        return (
          <div key={signal.key} className="flex min-w-0 items-end gap-3 px-4 py-3.5">
            <div className="min-w-0 flex-1">
              <div className="text-[12.5px] whitespace-nowrap text-ink-2">{signal.label}</div>
              <div className="mt-1.5 flex min-h-[26px] items-center gap-2">
                {numeric ? (
                  <Flow
                    value={signal.value!}
                    format={signal.format}
                    className={cn("font-mono text-[26px] leading-none font-medium tracking-[-0.02em] tabular-nums", TONE_TEXT[signal.tone])}
                  />
                ) : (
                  <span className={cn("text-[16px] leading-[1.25] font-semibold tracking-[-0.015em] text-pretty", TONE_TEXT[signal.tone])}>{signal.text}</span>
                )}
                {signal.tone !== "neutral" ? <span aria-hidden className={cn("size-[6px] shrink-0 rounded-full", TONE_DOT[signal.tone])} /> : null}
              </div>
              <div className="mt-2 truncate text-[11.5px] text-ink-3">
                {signal.caption}
                {!numeric && signal.asset ? <span className="font-mono"> · {signal.asset}</span> : null}
              </div>
            </div>
            {numeric && signal.asset ? (
              <Tip label={when ? `First crossed the threshold ${when}` : "Where it was measured"}>
                <div tabIndex={0} aria-label={`Measured on ${signal.asset}`} className="hidden max-w-[48%] min-w-0 shrink pb-px text-right lg:block">
                  <div className="truncate font-mono text-[11px] text-ink-3">{signal.asset}</div>
                  {when ? <div className="mt-1 truncate font-mono text-[11px] text-ink-4">{when}</div> : null}
                </div>
              </Tip>
            ) : null}
          </div>
        );
      })}
    </section>
  );
}
