"use client";

import { BadgeCheck } from "lucide-react";
import { Skeleton } from "@/components/ui/atoms";
import type { Diagnosis, DiagnosisRecord, Incident } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { CONFIDENCE_LABEL, CONFIDENCE_STEPS, FAULT_LABEL, inSentence, METHOD_LABEL, faultHeadline } from "@/lib/labels";

export function RootCauseCard({ incident, record, diagnosis }: { incident: Incident; record?: DiagnosisRecord; diagnosis?: Diagnosis }) {
  if (!record || !diagnosis) {
    return (
      <section aria-label="Likely root cause" className="card-raised px-5 py-4">
        <div className="text-[12.5px] text-ink-3">Likely root cause</div>
        <div className="mt-1 text-[22px] font-semibold tracking-[-0.025em] text-ink">Not diagnosed yet</div>
        <p className="mt-1 text-[12.5px] text-ink-2">
          {incident.dataset_scenario_id
            ? "Run a diagnosis to collect evidence from telemetry, routing, firewall, DHCP and DNS."
            : "This incident isn't linked to a telemetry dataset, so it can't be diagnosed automatically."}
        </p>
      </section>
    );
  }

  const domain = diagnosis.fault.fault_domain;
  const confirmed = incident.classification?.confirmed_fault_domain;
  const steps = CONFIDENCE_STEPS[diagnosis.confidence.level];
  const meta = [
    confirmed ? `Confirmed as ${inSentence(FAULT_LABEL[confirmed])} by ${incident.classification?.confirmed_by?.actor_id}` : "Awaiting human confirmation",
    diagnosis.escalation.team ? `Escalation: ${diagnosis.escalation.team}` : null,
    METHOD_LABEL[record.method],
  ].filter(Boolean);

  return (
    <section aria-label="Likely root cause" className="card-raised flex flex-col gap-4 px-5 py-4 sm:flex-row sm:items-center">
      <div className="min-w-0 flex-1">
        <div className="text-[12.5px] text-ink-3">Likely root cause</div>
        <div className="mt-1 flex items-center gap-2">
          <h2 className="text-[22px] leading-[1.15] font-semibold tracking-[-0.025em] text-ink">{faultHeadline(domain, diagnosis.fault.root_cause)}</h2>
          {confirmed ? <BadgeCheck className="size-[18px] shrink-0 text-green" aria-label="Confirmed by a person" /> : null}
        </div>
        <p className="mt-1.5 text-[13px] leading-[1.45] text-ink-2 text-pretty">{diagnosis.fault.root_cause}</p>
        <p className="mt-1 text-[12px] text-ink-3">{meta.join(" · ")}</p>
      </div>
      <div className="shrink-0 sm:w-[168px] sm:border-l sm:border-line-strong sm:pl-5" title={diagnosis.confidence.explanation}>
        <div className="flex items-baseline gap-2">
          <span className="text-[24px] leading-none font-semibold tracking-[-0.03em] text-ink">{CONFIDENCE_LABEL[diagnosis.confidence.level]}</span>
          <span className="text-[12.5px] text-ink-3">confidence</span>
        </div>
        <div className="mt-3 flex gap-1" role="meter" aria-label="Confidence" aria-valuemin={0} aria-valuemax={3} aria-valuenow={steps}>
          {[1, 2, 3].map((step) => (
            <span
              key={step}
              className={cn(
                "h-1 flex-1 rounded-full transition-colors duration-700",
                step <= steps ? (steps === 1 ? "bg-amber" : "bg-accent") : "bg-line-strong",
              )}
            />
          ))}
        </div>
      </div>
    </section>
  );
}

export function RootCauseSkeleton() {
  return (
    <div className="card-raised px-5 py-4">
      <Skeleton className="h-3 w-24" />
      <Skeleton className="mt-3 h-6 w-64" />
      <Skeleton className="mt-3 h-3 w-96 max-w-full" />
    </div>
  );
}
