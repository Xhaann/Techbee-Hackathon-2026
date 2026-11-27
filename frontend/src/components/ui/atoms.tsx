import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import type { Tone } from "@/lib/labels";

const TONE_TEXT: Record<Tone, string> = {
  amber: "text-amber",
  green: "text-green",
  red: "text-red",
  accent: "text-accent",
  muted: "text-ink-3",
};

const TONE_BG: Record<Tone, string> = {
  amber: "bg-amber-soft",
  green: "bg-green-soft",
  red: "bg-red-soft",
  accent: "bg-accent-soft",
  muted: "bg-hover",
};

const TONE_DOT: Record<Tone, string> = {
  amber: "bg-amber",
  green: "bg-green",
  red: "bg-red",
  accent: "bg-accent",
  muted: "bg-ink-4",
};

export function Dot({ tone, className }: { tone: Tone; className?: string }) {
  return <span aria-hidden className={cn("inline-block size-[6px] shrink-0 rounded-full", TONE_DOT[tone], className)} />;
}

export function Pill({ tone = "muted", dot, children, className }: { tone?: Tone; dot?: boolean; children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-[22px] items-center gap-1.5 rounded-[6px] px-2 text-[12px] font-medium whitespace-nowrap",
        TONE_BG[tone],
        TONE_TEXT[tone],
        className,
      )}
    >
      {dot ? <Dot tone={tone} /> : null}
      {children}
    </span>
  );
}

/** Marks an incident seeded from a synthetic demo scenario, so it is never mistaken for a reported one. */
export function DemoTag({ className }: { className?: string }) {
  return (
    <span
      title="Demo incident seeded from a synthetic scenario"
      className={cn("inline-flex h-[18px] shrink-0 items-center rounded-[5px] bg-hover px-1.5 text-[11px] font-medium text-ink-3", className)}
    >
      Demo
    </span>
  );
}

export function toneText(tone: Tone) {
  return TONE_TEXT[tone];
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="font-mono text-[11px] text-ink-4">{children}</kbd>;
}

export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cn("animate-pulse rounded-[6px] bg-hover", className)} />;
}

export function SectionTitle({ children, aside }: { children: ReactNode; aside?: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4">
      <h2 className="text-[18px] font-semibold tracking-[-0.02em] text-ink">{children}</h2>
      {aside ? <div className="shrink-0 font-mono text-[11.5px] text-ink-3">{aside}</div> : null}
    </div>
  );
}

/** For a request that failed: what happened and how to retry. */
export function ErrorNote({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex items-start gap-3 rounded-[8px] bg-red-soft px-3 py-2.5 text-[13px] leading-[1.45] text-red shadow-[0_0_0_1px_var(--red-line)]">
      <span className="flex-1 text-pretty">{message}</span>
      {onRetry ? (
        <button type="button" onClick={onRetry} className="shrink-0 font-medium underline underline-offset-2 hover:no-underline">
          Retry
        </button>
      ) : null}
    </div>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("font-mono text-[12.5px]", className)}>{children}</span>;
}
