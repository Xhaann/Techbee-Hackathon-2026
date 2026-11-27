"use client";

import { ChevronRight } from "lucide-react";
import { useState, type ReactNode } from "react";
import { CopyButton } from "@/components/ui/copy-button";
import { cn } from "@/lib/cn";
import { Counts, FindingList, type ProtocolFinding } from "@/components/protocols/findings";

export type Attachment = { kind: string; title: string; data: Record<string, unknown> };

type Step = {
  number: number;
  device_id: string;
  platform: string;
  title: string;
  command: string;
  expected_healthy: string;
  expected_fault: string;
  if_fault: string;
  if_healthy: string;
};
type CommandRow = { device_id: string; command: string; platform: string; purpose: string; expected_healthy: string; expected_fault: string };
type Hypothesis = { domain: string; label: string; probability: number; status: string; supporting_evidence_ids: string[] };
type SpecialistRow = { agent: string; title: string; verdict: string; probability: number; statement: string };

/** Artifacts the reply carries in full; the chat bubble shows only their lead sentence and renders the card instead. */
export const ARTIFACTS = new Set(["email_draft", "customer_update", "troubleshooting_guide", "commands"]);

const VERDICT_TONE: Record<string, string> = {
  implicated: "bg-red-soft text-red",
  possible: "bg-amber-soft text-amber",
  cleared: "bg-green-soft text-green",
  inconclusive: "bg-hover text-ink-3",
  healthy: "bg-green-soft text-green",
  fault: "bg-red-soft text-red",
  error: "bg-amber-soft text-amber",
  unclear: "bg-hover text-ink-3",
};

function Tag({ tone, children }: { tone: string; children: ReactNode }) {
  return <span className={cn("inline-flex h-[20px] items-center rounded-[5px] px-1.5 text-[11px] font-medium", tone)}>{children}</span>;
}

function Card({ title, aside, children }: { title: ReactNode; aside?: ReactNode; children: ReactNode }) {
  return (
    <div className="mt-2.5 rounded-[8px] bg-sunken px-3 py-2.5 shadow-[0_0_0_1px_var(--line-soft)]">
      <div className="flex items-center gap-2">
        <span className="min-w-0 flex-1 truncate text-[12.5px] font-medium text-ink">{title}</span>
        {aside}
      </div>
      <div className="mt-2">{children}</div>
    </div>
  );
}

function Draft({ data, update }: { data: Record<string, unknown>; update?: boolean }) {
  const subject = String(data.subject ?? data.title ?? "");
  const body = String(data.body ?? "");
  const placeholders = (data.placeholders as string[]) ?? [];
  const facts = (data.facts_used as { statement: string; source: string }[]) ?? [];
  const [open, setOpen] = useState(false);
  const full = update ? body : `Subject: ${subject}\n\n${body}`;
  return (
    <Card
      title={update ? subject : `Subject: ${subject}`}
      aside={
        <>
          <Tag tone="bg-amber-soft text-amber">Draft · not sent</Tag>
          <CopyButton text={full} label={update ? "Copy update" : "Copy email"} />
        </>
      }
    >
      <pre className="font-sans text-[12.5px] leading-[1.55] whitespace-pre-wrap text-ink-2">{body.replaceAll("**", "")}</pre>
      {placeholders.length ? (
        <p className="mt-2 text-[11.5px] text-ink-3">Fill in before sending: {placeholders.join(", ")}. Nothing is sent automatically.</p>
      ) : (
        <p className="mt-2 text-[11.5px] text-ink-3">Nothing is sent automatically.</p>
      )}
      {facts.length ? (
        <div className="mt-1.5">
          <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} className="flex items-center gap-1 text-[11.5px] text-ink-3 hover:text-ink">
            <ChevronRight className={cn("size-3 transition-transform", open && "rotate-90")} aria-hidden />
            Where each statement comes from
          </button>
          {open ? (
            <ul className="mt-1 space-y-0.5 pl-4 text-[11.5px] text-ink-3">
              {facts.map((f) => (
                <li key={f.statement}>
                  <span className="text-ink-2">{f.statement}</span>: {f.source}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}

function Guide({ data }: { data: Record<string, unknown> }) {
  const steps = (data.steps as Step[]) ?? [];
  return (
    <Card title={String(data.title ?? "Troubleshooting steps")} aside={<Tag tone="bg-green-soft text-green">Read-only</Tag>}>
      <ol className="space-y-2.5">
        {steps.map((step) => (
          <li key={step.number} className="flex gap-2.5">
            <span className="mt-[1px] grid size-5 shrink-0 place-items-center rounded-full bg-raised font-mono text-[11px] text-ink-2 shadow-[0_0_0_1px_var(--line)]">
              {step.number}
            </span>
            <div className="min-w-0 flex-1 text-[12.5px] leading-[1.5]">
              <p className="text-ink">
                {step.title} <span className="text-ink-3">on</span> <span className="font-mono text-[11.5px]">{step.device_id}</span>
              </p>
              <div className="mt-1 flex items-center gap-1">
                <code className="min-w-0 flex-1 truncate rounded-[5px] bg-raised px-1.5 py-1 font-mono text-[11.5px] text-ink-2 shadow-[0_0_0_1px_var(--line-soft)]">
                  {step.command}
                </code>
                <CopyButton text={step.command} label={`Copy step ${step.number} command`} />
              </div>
              <p className="mt-1 text-ink-3">
                <span className="text-green">Healthy:</span> {step.expected_healthy}
              </p>
              <p className="text-ink-3">
                <span className="text-red">Faulty:</span> {step.expected_fault}. {step.if_fault}
              </p>
              <p className="text-ink-3">
                <span className="text-ink-2">If healthy:</span> {step.if_healthy}
              </p>
            </div>
          </li>
        ))}
      </ol>
      <p className="mt-2 text-[11.5px] text-ink-3">Paste any output into the chat and I&apos;ll read it.</p>
    </Card>
  );
}

function Commands({ data, title }: { data: Record<string, unknown>; title: string }) {
  const rows = (data.commands as CommandRow[]) ?? [];
  return (
    <Card title={title} aside={<Tag tone="bg-green-soft text-green">Read-only</Tag>}>
      <ul className="space-y-1.5">
        {rows.map((row) => (
          <li key={`${row.device_id}-${row.command}`} className="text-[12px]">
            <div className="flex items-center gap-1">
              <code className="min-w-0 flex-1 truncate font-mono text-[11.5px] text-ink-2">{row.command}</code>
              <span className="font-mono text-[10.5px] text-ink-4">{row.device_id}</span>
              <CopyButton text={row.command} label="Copy command" className="size-6" />
            </div>
            <p className="text-ink-3">
              {row.purpose}. Healthy: {row.expected_healthy}
            </p>
          </li>
        ))}
      </ul>
    </Card>
  );
}

function Output({ data }: { data: Record<string, unknown> }) {
  const verdict = String(data.verdict ?? "unclear");
  const lines = (data.evidence_lines as string[]) ?? [];
  return (
    <Card title={`Reading of ${String(data.command ?? "the output")}`} aside={<Tag tone={VERDICT_TONE[verdict] ?? VERDICT_TONE.unclear}>{verdict}</Tag>}>
      {lines.length ? (
        <pre className="font-mono text-[11px] leading-[1.5] whitespace-pre-wrap text-ink-3">{lines.join("\n")}</pre>
      ) : (
        <p className="text-[12px] text-ink-3">No key lines to quote.</p>
      )}
    </Card>
  );
}

function Specialists({ rows }: { rows: SpecialistRow[] }) {
  return (
    <ul className="space-y-1">
      {rows.map((row) => (
        <li key={row.agent} className="flex items-start gap-2 text-[12px]">
          <Tag tone={VERDICT_TONE[row.verdict] ?? VERDICT_TONE.inconclusive}>{row.verdict}</Tag>
          <span className="min-w-0 flex-1 text-ink-2">
            <span className="text-ink">{row.title}:</span> {row.statement}
          </span>
        </li>
      ))}
    </ul>
  );
}

function Reasoning({ data }: { data: Record<string, unknown> }) {
  const [open, setOpen] = useState(false);
  const hypotheses = (data.hypotheses as Hypothesis[]) ?? [];
  const specialists = (data.specialists as SpecialistRow[]) ?? [];
  const chain = (data.chain as { evidence_id: string; code: string; device_id: string | null }[]) ?? [];
  const contradictions = (data.contradictions as { statement: string }[]) ?? [];
  const evaluation = data.self_evaluation as { verdict: string; calibrated_confidence: string; checks: { name: string; passed: boolean; detail: string }[] };
  const uncertainty = data.uncertainty as { level: string; statement: string };
  const related = (data.related_incidents as { incident_id: string; relation: string }[]) ?? [];
  return (
    <div className="mt-2.5">
      <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} className="flex items-center gap-1 text-[12px] text-ink-3 hover:text-ink">
        <ChevronRight className={cn("size-3 transition-transform", open && "rotate-90")} aria-hidden />
        How I reached this
        {evaluation ? <span className="text-[11px] text-ink-4">· self-check {evaluation.verdict}</span> : null}
      </button>
      {open ? (
        <div className="mt-1.5 space-y-2.5 rounded-[8px] bg-sunken px-3 py-2.5 shadow-[0_0_0_1px_var(--line-soft)]">
          <div>
            <p className="text-[11.5px] font-medium text-ink-2">Fault probabilities</p>
            <ul className="mt-1 space-y-1">
              {hypotheses.map((h) => (
                <li key={h.domain} className="grid grid-cols-[120px_1fr_36px] items-center gap-2 text-[11.5px]">
                  <span className="truncate text-ink-2">{h.label}</span>
                  <span className="h-1.5 rounded-full bg-hover">
                    <span className={cn("block h-1.5 rounded-full", h.status === "leading" ? "bg-chart" : "bg-ink-4")} style={{ width: `${Math.max(2, h.probability * 100)}%` }} />
                  </span>
                  <span className="text-right font-mono text-ink-3">{h.probability >= 0.995 ? "99%+" : `${Math.round(h.probability * 100)}%`}</span>
                </li>
              ))}
            </ul>
            {uncertainty ? <p className="mt-1 text-[11.5px] text-ink-3">Uncertainty {uncertainty.level}: {uncertainty.statement}</p> : null}
          </div>
          {chain.length ? (
            <div>
              <p className="text-[11.5px] font-medium text-ink-2">Causal chain</p>
              <p className="mt-0.5 text-[11.5px] leading-[1.5] text-ink-3">
                {chain.map((c) => `${c.evidence_id} ${c.code.toLowerCase().replaceAll("_", " ")}${c.device_id ? ` (${c.device_id})` : ""}`).join(" → ")}
              </p>
            </div>
          ) : null}
          {specialists.length ? (
            <div>
              <p className="mb-1 text-[11.5px] font-medium text-ink-2">Specialist reviews</p>
              <Specialists rows={specialists} />
            </div>
          ) : null}
          {contradictions.length ? (
            <div>
              <p className="text-[11.5px] font-medium text-ink-2">Contradictions</p>
              <ul className="mt-0.5 space-y-0.5 text-[11.5px] text-amber">
                {contradictions.map((c) => (
                  <li key={c.statement}>{c.statement}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {evaluation ? (
            <div>
              <p className="text-[11.5px] font-medium text-ink-2">
                Self-check: {evaluation.verdict} · calibrated confidence {evaluation.calibrated_confidence}
              </p>
              <ul className="mt-0.5 space-y-0.5 text-[11.5px]">
                {evaluation.checks.map((c) => (
                  <li key={c.name} className={c.passed ? "text-ink-3" : "text-amber"}>
                    {c.passed ? "✓" : "!"} {c.detail}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {related.length ? (
            <p className="text-[11.5px] text-ink-3">Possibly related: {related.map((r) => `${r.incident_id} (${r.relation})`).join("; ")}</p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function Protocol({ data, title }: { data: Record<string, unknown>; title: string }) {
  const findings = (data.findings as ProtocolFinding[]) ?? [];
  const notes = (data.notes as string[]) ?? [];
  const missing = (data.missing as string[]) ?? [];
  return (
    <Card title={title} aside={<Tag tone="bg-hover text-ink-3">Read-only · synthetic</Tag>}>
      <Counts counts={(data.counts as Record<string, number>) ?? {}} />
      {findings.length ? (
        <div className="mt-2">
          <FindingList findings={findings} compact />
        </div>
      ) : (
        <p className="mt-2 text-[12px] text-ink-3">Nothing wrong found in these checks.</p>
      )}
      {notes.length ? <p className="mt-2 text-[11.5px] leading-[1.5] text-ink-3">{notes.slice(0, 3).join(" ")}</p> : null}
      {missing.length ? <p className="mt-1 text-[11.5px] text-amber">Missing data: {missing.slice(0, 2).join("; ")}</p> : null}
    </Card>
  );
}

export function AttachmentView({ attachment }: { attachment: Attachment }) {
  switch (attachment.kind) {
    case "email_draft":
      return <Draft data={attachment.data} />;
    case "customer_update":
      return <Draft data={attachment.data} update />;
    case "troubleshooting_guide":
      return <Guide data={attachment.data} />;
    case "commands":
      return <Commands data={attachment.data} title={attachment.title} />;
    case "output_interpretation":
      return <Output data={attachment.data} />;
    case "reasoning":
      return <Reasoning data={attachment.data} />;
    case "protocol":
      return <Protocol data={attachment.data} title={attachment.title} />;
    case "specialists":
      return (
        <Card title={attachment.title}>
          <Specialists rows={(attachment.data.specialists as SpecialistRow[]) ?? []} />
        </Card>
      );
    default:
      return null;
  }
}
