"use client";

import { Archive, ArrowRight, BadgeCheck, Clock, Eye, ListChecks, RotateCcw, ShieldCheck, Stethoscope, UserCheck, Users, Wrench } from "lucide-react";
import type { ComponentType } from "react";
import { Spinner } from "@/components/ui/button";
import { Tip } from "@/components/ui/tip";
import type { Diagnosis } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { useIncidentActions } from "./actions";
import { nextStep, type NextStep } from "./model";

const ICON: Record<NextStep["key"], ComponentType<{ className?: string }>> = {
  acknowledge: UserCheck,
  diagnose: Stethoscope,
  checks: ListChecks,
  confirm: BadgeCheck,
  escalate: Users,
  "update-escalation": Users,
  propose: Wrench,
  monitor: Eye,
  verify: ShieldCheck,
  close: Archive,
  reopen: RotateCcw,
  wait: Clock,
  edit: Wrench,
  severity: Wrench,
  priority: Wrench,
  status: Wrench,
};

export function NextStepBar({ diagnosis }: { diagnosis?: Diagnosis }) {
  const { incident, states, trigger, busy } = useIncidentActions();
  const step = nextStep(incident, diagnosis, states);
  const Icon = ICON[step.key];
  const state = step.key === "wait" ? undefined : states[step.key];
  const blocked = state && !state.allowed;
  const running = busy !== null && busy === step.key;

  const button = step.cta ? (
    <button
      type="button"
      disabled={blocked || running}
      onClick={() => {
        if (step.key !== "wait") void trigger(step.key);
      }}
      className="inline-flex h-9 shrink-0 items-center gap-2 rounded-[8px] bg-accent-strong px-3.5 text-[13.5px] font-medium tracking-[-0.01em] text-accent-fg shadow-[inset_0_1px_0_rgb(255_255_255/0.14),0_1px_2px_rgb(0_0_0/0.3)] transition-[background-color,translate] duration-150 hover:bg-accent-strong-hover active:translate-y-px disabled:opacity-45"
    >
      {running ? <Spinner /> : null}
      {running ? "Working" : step.cta}
      {!running ? <ArrowRight className="size-3.5" aria-hidden /> : null}
    </button>
  ) : null;

  return (
    <section aria-label="Next step" className="card-raised flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:gap-3.5 sm:px-5">
      <div className="flex min-w-0 flex-1 items-center gap-3.5">
        <Icon className={cn("size-[18px] shrink-0", step.key === "wait" ? "text-ink-3" : "text-ink-2")} aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="text-[14.5px] font-semibold tracking-[-0.015em] text-ink sm:truncate">{step.title}</div>
          <div className="mt-0.5 line-clamp-2 text-[12.5px] leading-[1.45] text-ink-2">{step.detail}</div>
        </div>
      </div>
      {button && blocked && state?.reason ? <Tip label={state.reason}>{<span tabIndex={0} aria-label={`${step.cta}: ${state.reason}`}>{button}</span>}</Tip> : button}
    </section>
  );
}
