"use client";

import { ChevronRight } from "lucide-react";
import { useState, type ReactNode } from "react";
import { CopyButton } from "@/components/ui/copy-button";
import { cn } from "@/lib/cn";

export type ProtocolCommand = { device_id: string; platform: string; command: string; purpose: string; healthy: string; faulty: string };
export type ProtocolFinding = {
  finding_id: string;
  evidence_id?: string | null;
  engine: string;
  code: string;
  status: "confirmed_fault" | "suspicious_indicator" | "possible_explanation" | "insufficient_evidence";
  severity: string;
  title: string;
  summary: string;
  basis: string;
  confidence: number | null;
  confidence_label: string | null;
  device_id: string | null;
  affected_sites: string[];
  root_cause: boolean;
  explained_by: string[];
  correlations: (string | { kind: string; detail: string })[];
  commands: ProtocolCommand[];
  evidence: { collection: string; record_id: string }[];
  injection_ignored: boolean;
};

const STATUS: Record<ProtocolFinding["status"], { label: string; tone: string }> = {
  confirmed_fault: { label: "Confirmed", tone: "bg-red-soft text-red" },
  suspicious_indicator: { label: "Suspicious · not confirmed", tone: "bg-amber-soft text-amber" },
  possible_explanation: { label: "Possible", tone: "bg-hover text-ink-2" },
  insufficient_evidence: { label: "Not enough data", tone: "bg-hover text-ink-3" },
};

export const ENGINE_STATUS: Record<string, { label: string; tone: string }> = {
  fault: { label: "Fault", tone: "bg-red-soft text-red" },
  suspicious: { label: "Suspicious", tone: "bg-amber-soft text-amber" },
  possible: { label: "Possible", tone: "bg-hover text-ink-2" },
  healthy: { label: "Healthy", tone: "bg-green-soft text-green" },
  insufficient: { label: "No data", tone: "bg-hover text-ink-3" },
  error: { label: "Error", tone: "bg-amber-soft text-amber" },
};

export function Tag({ tone, children }: { tone: string; children: ReactNode }) {
  return <span className={cn("inline-flex h-[20px] shrink-0 items-center rounded-[5px] px-1.5 text-[11px] font-medium", tone)}>{children}</span>;
}

export function StatusTag({ status }: { status: ProtocolFinding["status"] }) {
  const s = STATUS[status];
  return <Tag tone={s.tone}>{s.label}</Tag>;
}

function detail(c: string | { kind: string; detail: string }) {
  return typeof c === "string" ? c : c.detail;
}

export function FindingRow({ finding, compact = false }: { finding: ProtocolFinding; compact?: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <li className="rounded-[7px] bg-surface px-2.5 py-2 shadow-[0_0_0_1px_var(--line-soft)]">
      <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} className="flex w-full items-start gap-2 text-left">
        <ChevronRight className={cn("mt-[3px] size-3 shrink-0 text-ink-4 transition-transform", open && "rotate-90")} aria-hidden />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-1.5">
            <StatusTag status={finding.status} />
            {finding.root_cause ? <Tag tone="bg-accent-soft text-accent-strong">Likely cause</Tag> : null}
            {!finding.root_cause && finding.explained_by.length ? <Tag tone="bg-hover text-ink-3">Effect</Tag> : null}
          </span>
          <span className="mt-1 block text-[12.5px] font-medium text-ink">{finding.title}</span>
          {compact && !open ? <span className="mt-0.5 block truncate text-[11.5px] text-ink-3">{finding.summary}</span> : null}
        </span>
        <span className="shrink-0 text-right font-mono text-[11px] text-ink-3">
          {finding.confidence !== null ? `${finding.confidence_label} ${finding.confidence.toFixed(2)}` : "—"}
          {finding.evidence_id ? <span className="block text-ink-4">{finding.evidence_id}</span> : null}
        </span>
      </button>
      {open ? (
        <div className="mt-2 space-y-2 pl-5 text-[12px] leading-[1.5] text-ink-2">
          <p>{finding.summary}</p>
          <p className="text-[11.5px] text-ink-3">Why this status: {finding.basis}.</p>
          {finding.injection_ignored ? (
            <p className="text-[11.5px] text-amber">Device text that looked like instructions was withheld and ignored.</p>
          ) : null}
          {finding.correlations.length ? (
            <div>
              <p className="text-[11.5px] font-medium text-ink-2">Correlated with</p>
              <ul className="mt-0.5 list-disc space-y-0.5 pl-4 text-[11.5px] text-ink-3">
                {finding.correlations.slice(0, 5).map((c) => (
                  <li key={detail(c)}>{detail(c)}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {finding.commands.length ? (
            <div>
              <p className="text-[11.5px] font-medium text-ink-2">Verify (read-only)</p>
              <ul className="mt-1 space-y-1.5">
                {finding.commands.map((c) => (
                  <li key={`${c.device_id}|${c.command}`} className="text-[11.5px]">
                    <span className="flex items-center gap-1.5">
                      <code className="min-w-0 flex-1 truncate rounded-[5px] bg-sunken px-1.5 py-0.5 font-mono text-[11.5px] text-ink">{c.command}</code>
                      <CopyButton text={c.command} label={`Copy command for ${c.device_id}`} />
                    </span>
                    <span className="mt-0.5 block text-ink-3">
                      On {c.device_id} ({c.platform}). Healthy: {c.healthy}. Faulty: {c.faulty}.
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {finding.evidence.length ? (
            <p className="font-mono text-[10.5px] text-ink-4">
              Evidence: {finding.evidence.map((e) => `${e.collection}:${e.record_id}`).join(" · ")}
            </p>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}

export function FindingList({ findings, compact = false }: { findings: ProtocolFinding[]; compact?: boolean }) {
  const order = { confirmed_fault: 0, suspicious_indicator: 1, possible_explanation: 2, insufficient_evidence: 3 };
  const sorted = [...findings].sort((a, b) => Number(b.root_cause) - Number(a.root_cause) || order[a.status] - order[b.status]);
  return (
    <ul className="space-y-1.5">
      {sorted.map((f) => (
        <FindingRow key={f.finding_id} finding={f} compact={compact} />
      ))}
    </ul>
  );
}

export function Counts({ counts }: { counts: Record<string, number> }) {
  const items = [
    ["confirmed_fault", "confirmed"],
    ["suspicious_indicator", "suspicious"],
    ["possible_explanation", "possible"],
    ["insufficient_evidence", "no data"],
  ] as const;
  return (
    <span className="flex flex-wrap gap-1.5">
      {items.map(([key, label]) => (
        <Tag key={key} tone={counts[key] ? STATUS[key].tone : "bg-hover text-ink-4"}>
          {counts[key] ?? 0} {label}
        </Tag>
      ))}
    </span>
  );
}
