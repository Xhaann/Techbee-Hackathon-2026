"use client";

import { ArrowRight, BookOpen, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { Dot, ErrorNote, Pill, SectionTitle, Skeleton } from "@/components/ui/atoms";
import { Button } from "@/components/ui/button";
import { Segmented } from "@/components/ui/controls";
import { CopyButton } from "@/components/ui/copy-button";
import { SelectBox } from "@/components/ui/fields";
import { describeError } from "@/lib/api/client";
import { useDiagnosisEvidence, useDiagnosisRecord, useEscalations, useIncidentEvidence, useTimeline } from "@/lib/api/hooks";
import type { AdvancedDiagnosis, Diagnosis, EvidenceItem, Incident } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import {
  CONFIDENCE_LABEL,
  ESCALATION_STATUS_LABEL,
  EVENT_LABEL,
  FAULT_LABEL,
  LAYER_LABEL,
  METHOD_LABEL,
  PRIORITY_LABEL,
  RELEVANCE_LABEL,
  SERVICE_LABEL,
  humanize,
} from "@/lib/labels";
import { stamp } from "@/lib/time";
import { useIncidentActions } from "./actions";

type Base = { incident: Incident; diagnosis?: Diagnosis; advanced?: AdvancedDiagnosis };

// ---------- Summary ----------

export function SummaryPanel({ incident, diagnosis, advanced, onShowEvidence }: Base & { onShowEvidence: () => void }) {
  const siteId = incident.site_ids[0];
  const services = useMemo(() => {
    const fromImpact = (advanced?.blast_radius.items ?? [])
      .filter((item) => item.asset_type === "service")
      .map((item) => item.asset_id.split(":")[1] as keyof typeof SERVICE_LABEL);
    const fromAssets = (incident.affected_assets ?? []).filter((a) => a.asset_type === "service").map((a) => a.asset_id.split(":").pop() as keyof typeof SERVICE_LABEL);
    return [...new Set([...fromImpact, ...fromAssets])].map((s) => SERVICE_LABEL[s] ?? humanize(s));
  }, [advanced, incident]);

  const layers = (advanced?.cross_layer.layers ?? []).filter((layer) => layer.status !== "no_evidence").slice(0, 3);

  const findings = useMemo(() => {
    if (!diagnosis) return [];
    const supporting = new Set(diagnosis.fault.supporting_evidence_ids);
    const picked = diagnosis.evidence.filter((e) => supporting.has(e.evidence_id));
    return (picked.length ? picked : diagnosis.evidence.filter((e) => e.evidence_type !== "record")).slice(0, 4);
  }, [diagnosis]);

  const questions = useMemo(() => {
    if (!diagnosis) return [];
    return [...new Set([...diagnosis.escalation.unknowns, ...diagnosis.limitations])].filter((q) => !q.startsWith("The hypothesis requires human")).slice(0, 4);
  }, [diagnosis]);

  return (
    <div className="space-y-5">
      <div>
        <SectionTitle aside={`Updated ${stamp(incident.updated_at, siteId)}`}>Incident summary</SectionTitle>
        <p className="mt-2.5 text-[14.5px] leading-[1.55] text-ink-2 text-pretty">{diagnosis?.explanation.summary ?? incident.description}</p>
        <div className="mt-3 flex flex-wrap items-center justify-between gap-x-6 gap-y-2 text-[12.5px]">
          <div className="flex min-w-0 items-baseline gap-2.5">
            <span className="text-ink-3">Affected services</span>
            <span className="text-ink-2">{services.length ? services.join(" · ") : (incident.symptoms ?? []).slice(0, 3).join(" · ") || "Not assessed yet"}</span>
          </div>
          {layers.length ? (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
              {layers.map((layer) => (
                <span key={layer.layer} className={cn("inline-flex items-center gap-1.5", layer.status === "fault_indicated" ? "text-amber" : "text-green")}>
                  <Dot tone={layer.status === "fault_indicated" ? "amber" : "green"} />
                  {LAYER_LABEL[layer.layer]} {layer.status === "fault_indicated" ? "fault" : "healthy"}
                </span>
              ))}
            </div>
          ) : null}
        </div>
      </div>

      {findings.length ? (
        <section aria-labelledby="findings-heading" className="card">
          <div className="flex items-center justify-between px-3.5 pt-3 pb-2">
            <h3 id="findings-heading" className="text-[14.5px] font-semibold tracking-[-0.01em] text-ink">
              Key findings
            </h3>
            <button type="button" onClick={onShowEvidence} className="inline-flex items-center gap-1 text-[12px] text-ink-3 hover:text-ink">
              All {diagnosis!.evidence.length} evidence items
              <ArrowRight className="size-3" aria-hidden />
            </button>
          </div>
          <ul className="divide-y divide-line-soft border-t border-line-soft">
            {findings.map((item) => (
              <li key={item.evidence_id} className="flex gap-3 px-3.5 py-2.5">
                <span className="w-7 shrink-0 font-mono text-[11.5px] leading-[20px] text-accent">{item.evidence_id}</span>
                <span className="text-[13px] leading-[1.5] text-ink-soft text-pretty">{item.summary}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {questions.length ? (
        <section aria-labelledby="questions-heading">
          <h3 id="questions-heading" className="text-[13px] font-medium text-ink-2">
            What the diagnosis couldn&apos;t establish
          </h3>
          <ul className="mt-2 space-y-1.5">
            {questions.map((question) => (
              <li key={question} className="flex gap-2.5 text-[12.5px] leading-[1.5] text-ink-3">
                <Dot tone="muted" className="mt-[7px]" />
                {question}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {!diagnosis && incident.symptoms?.length ? (
        <section>
          <h3 className="text-[13px] font-medium text-ink-2">Reported symptoms</h3>
          <ul className="mt-2 space-y-1.5">
            {incident.symptoms.map((symptom) => (
              <li key={symptom} className="flex gap-2.5 text-[13px] text-ink-2">
                <Dot tone="amber" className="mt-[7px]" />
                {symptom}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}

// ---------- Evidence ----------

export function EvidencePanel({ incident }: { incident: Incident }) {
  const [kind, setKind] = useState<"all" | "observed" | "inferred">("all");
  const [selected, setSelected] = useState(incident.active_diagnosis_id ?? "");
  const isCurrent = selected === incident.active_diagnosis_id;
  const current = useIncidentEvidence(incident.incident_id, incident.active_diagnosis_id);
  const older = useDiagnosisEvidence(isCurrent ? null : selected);
  const olderRecord = useDiagnosisRecord(isCurrent ? null : selected);
  const page = isCurrent ? current : older;
  const siteId = incident.site_ids[0];

  if (!incident.active_diagnosis_id) return <EmptyPanel text="Evidence appears here once a diagnosis is attached." />;

  const items = (page.data?.items ?? []).filter((view) =>
    kind === "all" ? true : kind === "observed" ? view.evidence.evidence_type.startsWith("observed") : !view.evidence.evidence_type.startsWith("observed"),
  );
  const diagnoses = [...(incident.diagnoses ?? [])].reverse();

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Segmented
          ariaLabel="Evidence type"
          size="sm"
          value={kind}
          onValueChange={setKind}
          options={[
            { value: "all", label: "All" },
            { value: "observed", label: "Observed" },
            { value: "inferred", label: "Inferred" },
          ]}
        />
        {diagnoses.length > 1 ? (
          <SelectBox
            size="sm"
            ariaLabel="Diagnosis"
            className="w-[300px]"
            value={selected}
            onValueChange={setSelected}
            options={diagnoses.map((record) => ({
              value: record.diagnosis_id,
              label: `${record.diagnosis_id}${record.diagnosis_id === incident.active_diagnosis_id ? " (current)" : " (superseded)"}`,
            }))}
          />
        ) : null}
      </div>

      {!isCurrent && olderRecord.data ? (
        <p className="text-[12.5px] text-ink-3">
          {METHOD_LABEL[olderRecord.data.method]} · {FAULT_LABEL[olderRecord.data.probable_fault_domain]} · {CONFIDENCE_LABEL[olderRecord.data.confidence]} confidence ·
          superseded by <span className="font-mono">{olderRecord.data.superseded_by}</span>
        </p>
      ) : null}

      {page.data && !page.data.provenance_verified ? (
        <p className="flex items-start gap-2 rounded-[8px] bg-amber-soft px-3 py-2.5 text-[12.5px] text-amber">
          <ShieldAlert className="mt-px size-4 shrink-0" aria-hidden />
          Provenance didn&apos;t verify for {page.data.unverified_diagnosis_ids.join(", ")}, so its evidence is hidden.
        </p>
      ) : null}

      {page.isPending ? (
        <div className="space-y-2">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-12" />
          ))}
        </div>
      ) : page.isError ? (
        <ErrorNote message={describeError(page.error)} onRetry={() => page.refetch()} />
      ) : (
        <ul className="card divide-y divide-line-soft">
          {items.map((view) => (
            <EvidenceRow key={`${view.diagnosis_id}-${view.evidence.evidence_id}`} item={view.evidence} siteId={siteId} />
          ))}
          {!items.length ? <li className="px-4 py-6 text-center text-[12.5px] text-ink-3">No {kind} evidence in this diagnosis.</li> : null}
        </ul>
      )}
    </div>
  );
}

function EvidenceRow({ item, siteId }: { item: EvidenceItem; siteId?: string }) {
  const observed = item.evidence_type.startsWith("observed");
  return (
    <li>
      <details className="group">
        <summary className="flex cursor-default list-none gap-3 px-3.5 py-2.5 hover:bg-hover [&::-webkit-details-marker]:hidden">
          <span className="w-8 shrink-0 font-mono text-[11.5px] leading-[20px] text-accent">{item.evidence_id}</span>
          <span className="min-w-0 flex-1">
            <span className="block text-[13px] leading-[1.5] text-ink-soft text-pretty">{item.summary}</span>
            <span className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11.5px] text-ink-3">
              <span className={observed ? "text-green" : "text-amber"}>{observed ? "Observed" : "Inferred"}</span>
              <span className="font-mono">{item.code}</span>
              {item.device_id ? <span className="font-mono">{item.device_id}</span> : null}
              <span className="font-mono">{item.tool}</span>
              {item.timestamp ? <span className="font-mono">{stamp(item.timestamp, siteId)}</span> : null}
            </span>
          </span>
        </summary>
        {item.references?.length ? (
          <div className="px-3.5 pb-3 pl-[58px]">
            <div className="text-[11.5px] text-ink-4">Source records</div>
            <ul className="mt-1 space-y-0.5">
              {item.references.map((ref) => (
                <li key={`${ref.collection}-${ref.record_id}`} className="font-mono text-[11px] text-ink-3">
                  {ref.collection} · {ref.record_id}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </details>
    </li>
  );
}

// ---------- Next checks ----------

export function ChecksPanel({ diagnosis, advanced }: Base) {
  if (!diagnosis) return <EmptyPanel text="Recommended checks appear once a diagnosis is attached." />;
  const playbooks = advanced?.playbooks ?? [];
  return (
    <div className="space-y-5">
      <p className="text-[12.5px] leading-[1.5] text-ink-3">
        Read-only commands to run on the device yourself. They&apos;re illustrative; adjust interface names to your platform.
      </p>
      <ol className="space-y-3">
        {diagnosis.next_checks.map((check, index) => (
          <li key={`${check.device_id}-${check.command}`} className="card px-4 py-3.5">
            <div className="flex items-baseline gap-2.5">
              <span className="font-mono text-[11.5px] text-ink-4">{index + 1}</span>
              <span className="text-[14px] font-medium tracking-[-0.01em] text-ink">{check.purpose}</span>
              <span className="ml-auto font-mono text-[11.5px] text-ink-3">{check.device_id}</span>
            </div>
            <div className="mt-2.5 flex items-center gap-2 rounded-[7px] bg-sunken py-1 pr-1 pl-3 shadow-[0_0_0_1px_var(--line-soft)]">
              <code className="min-w-0 flex-1 truncate font-mono text-[12.5px] text-ink">
                <span className="text-ink-4">{check.device_id.toLowerCase()}# </span>
                {check.command}
              </code>
              <CopyButton text={check.command} label={`Copy ${check.command}`} />
            </div>
            <dl className="mt-3 grid gap-x-6 gap-y-2 text-[12.5px] sm:grid-cols-2">
              <div>
                <dt className="text-ink-3">Expect</dt>
                <dd className="mt-0.5 text-ink-2">{check.expected_observation}</dd>
              </div>
              <div>
                <dt className="text-ink-3">Why</dt>
                <dd className="mt-0.5 text-ink-2">{check.reason}</dd>
              </div>
            </dl>
          </li>
        ))}
      </ol>
      {playbooks.length ? (
        <section>
          <h3 className="text-[13px] font-medium text-ink-2">Guidance that matches this diagnosis</h3>
          <ul className="mt-2 grid gap-2 sm:grid-cols-2">
            {playbooks.slice(0, 4).map((playbook) => (
              <li key={playbook.record_id}>
                <Link href={`/knowledge?record=${playbook.record_id}`} className="card flex items-start gap-2.5 px-3.5 py-3 hover:bg-hover">
                  <BookOpen className="mt-0.5 size-4 shrink-0 text-accent" aria-hidden />
                  <span className="min-w-0">
                    <span className="block text-[13px] font-medium text-ink">{playbook.title}</span>
                    <span className="mt-0.5 block font-mono text-[11px] text-ink-3">
                      {playbook.record_id} · {playbook.match_type} match
                    </span>
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}

// ---------- Alternatives ----------

export function AlternativesPanel({ diagnosis, advanced }: Base) {
  if (!diagnosis) return <EmptyPanel text="Alternative explanations appear once a diagnosis is attached." />;
  const candidates = (advanced?.root_cause_candidates ?? []).filter((c) => c.status !== "suspected" || c.rank > 1);
  const alternatives = diagnosis.alternatives;

  if (!candidates.length && !alternatives.length) {
    return (
      <EmptyPanel
        text={`No other fault domain is supported by the evidence. ${diagnosis.fault.contradictory_evidence_ids.length ? `${diagnosis.fault.contradictory_evidence_ids.length} items contradict the main hypothesis.` : "Nothing contradicts the main hypothesis."}`}
      />
    );
  }
  return (
    <ul className="space-y-3">
      {candidates.map((candidate) => (
        <li key={`c-${candidate.rank}-${candidate.fault_domain}`} className="card px-4 py-3.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[14px] font-medium text-ink">{FAULT_LABEL[candidate.fault_domain]}</span>
            <Pill tone={candidate.status === "contradicted" ? "red" : candidate.status === "human_confirmed" ? "green" : "muted"}>{humanize(candidate.status)}</Pill>
            <span className="ml-auto text-[12px] text-ink-3">{CONFIDENCE_LABEL[candidate.confidence]} confidence</span>
          </div>
          <p className="mt-1.5 text-[13px] leading-[1.5] text-ink-2">{candidate.hypothesis}</p>
          <EvidenceIds support={candidate.supporting_evidence_ids} against={candidate.contradicting_evidence_ids} />
          {candidate.verification_checks.length ? (
            <p className="mt-2 font-mono text-[11.5px] text-ink-3">{candidate.verification_checks.join(" · ")}</p>
          ) : null}
        </li>
      ))}
      {alternatives.map((alternative) => (
        <li key={`a-${alternative.fault_domain}-${alternative.hypothesis}`} className="card px-4 py-3.5">
          <span className="text-[14px] font-medium text-ink">{FAULT_LABEL[alternative.fault_domain]}</span>
          <p className="mt-1.5 text-[13px] leading-[1.5] text-ink-2">{alternative.hypothesis}</p>
          <EvidenceIds support={alternative.supporting_evidence_ids} against={alternative.contradictory_evidence_ids} />
          <p className="mt-2 text-[12.5px] text-ink-3">To rule it out: {alternative.verification}</p>
        </li>
      ))}
    </ul>
  );
}

function EvidenceIds({ support, against }: { support: string[]; against: string[] }) {
  if (!support.length && !against.length) return null;
  return (
    <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[12px]">
      {support.length ? (
        <span className="text-ink-3">
          Supports <span className="font-mono text-accent">{support.join(" ")}</span>
        </span>
      ) : null}
      {against.length ? (
        <span className="text-ink-3">
          Contradicts <span className="font-mono text-red">{against.join(" ")}</span>
        </span>
      ) : null}
    </div>
  );
}

// ---------- Timeline ----------

export function TimelinePanel({ incident, diagnosis, advanced }: Base) {
  const activity = useTimeline(incident.incident_id, incident.version);
  const siteId = incident.site_ids[0];
  const events = [...(activity.data?.items ?? [])].reverse();

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <section aria-labelledby="telemetry-heading">
        <h3 id="telemetry-heading" className="text-[13px] font-medium text-ink-2">
          What the telemetry shows
        </h3>
        {diagnosis?.timeline.length ? (
          <ol className="mt-3 space-y-0">
            {diagnosis.timeline.map((entry) => (
              <li key={`${entry.evidence_id}-${entry.timestamp}`} className="relative flex gap-3 pb-4 last:pb-0">
                <span aria-hidden className="absolute top-3 bottom-0 left-[3px] w-px bg-line-soft" />
                <Dot tone={entry.relevance === "fault_onset" ? "amber" : entry.relevance === "background" ? "muted" : "accent"} className="relative mt-[6px]" />
                <div className="min-w-0">
                  <div className="flex flex-wrap items-baseline gap-x-2 text-[11.5px] text-ink-3">
                    <span className="font-mono">{stamp(entry.timestamp, siteId)}</span>
                    <span className={entry.relevance === "fault_onset" ? "text-amber" : undefined}>{RELEVANCE_LABEL[entry.relevance]}</span>
                    <span className="font-mono text-accent">{entry.evidence_id}</span>
                  </div>
                  <p className="mt-0.5 text-[13px] leading-[1.5] text-ink-2">{entry.event}</p>
                </div>
              </li>
            ))}
          </ol>
        ) : (
          <p className="mt-2 text-[12.5px] text-ink-3">No telemetry timeline yet.</p>
        )}
        {advanced ? (
          <div className="mt-5 space-y-1.5 text-[12.5px] text-ink-3">
            <p>Changes: {advanced.changes.message}</p>
            <p>History: {advanced.history.message}</p>
          </div>
        ) : null}
      </section>

      <section aria-labelledby="activity-heading">
        <h3 id="activity-heading" className="text-[13px] font-medium text-ink-2">
          Incident activity
        </h3>
        {activity.isPending ? (
          <Skeleton className="mt-3 h-24" />
        ) : activity.isError ? (
          <div className="mt-3">
            <ErrorNote message={describeError(activity.error)} onRetry={() => activity.refetch()} />
          </div>
        ) : (
          <ol className="mt-3">
            {events.map((event) => (
              <li key={event.event_id} className="relative flex gap-3 pb-4 last:pb-0">
                <span aria-hidden className="absolute top-3 bottom-0 left-[3px] w-px bg-line-soft" />
                <Dot tone={event.actor.kind === "human" ? "green" : "accent"} className="relative mt-[6px]" />
                <div className="min-w-0">
                  <div className="flex flex-wrap items-baseline gap-x-2 text-[11.5px] text-ink-3">
                    <span className="font-mono">{stamp(event.timestamp, siteId)}</span>
                    <span className="text-ink-2">{EVENT_LABEL[event.event_type]}</span>
                    <span>{event.actor.actor_id}</span>
                  </div>
                  <p className="mt-0.5 text-[13px] leading-[1.5] break-words text-ink-3">{event.description}</p>
                </div>
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  );
}

// ---------- Escalations ----------

export function EscalationsPanel({ incident }: { incident: Incident }) {
  const escalations = useEscalations(incident.incident_id, incident.version);
  const { states, trigger } = useIncidentActions();
  const siteId = incident.site_ids[0];
  const items = escalations.data?.items ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-[12.5px] text-ink-3">Escalations are recorded here with a handover summary. This workspace never sends them.</p>
        <div className="flex gap-2">
          {states["update-escalation"].allowed ? (
            <Button size="sm" onClick={() => trigger("update-escalation")}>
              Update escalation
            </Button>
          ) : null}
          {states.escalate.allowed ? (
            <Button size="sm" onClick={() => trigger("escalate")}>
              Recommend escalation
            </Button>
          ) : null}
        </div>
      </div>
      {escalations.isPending ? (
        <Skeleton className="h-24" />
      ) : escalations.isError ? (
        <ErrorNote message={describeError(escalations.error)} onRetry={() => escalations.refetch()} />
      ) : items.length === 0 ? (
        <EmptyPanel
          text={
            activeDiagnosisTeam(incident)
              ? `The diagnosis recommends ${activeDiagnosisTeam(incident)}. Nothing is recorded yet.`
              : "No escalation is recorded for this incident."
          }
        />
      ) : (
        <ul className="space-y-3">
          {items.map((escalation) => (
            <li key={escalation.escalation_id} className="card px-4 py-3.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[12px] text-ink-2">{escalation.escalation_id}</span>
                <Pill tone={escalation.status === "recommended" ? "amber" : escalation.status === "assigned" ? "accent" : "muted"}>
                  {ESCALATION_STATUS_LABEL[escalation.status]}
                </Pill>
                <span className="ml-auto font-mono text-[11.5px] text-ink-3">{stamp(escalation.created_at, siteId)}</span>
              </div>
              <div className="mt-2 text-[14px] font-medium text-ink">
                {escalation.assigned_team ?? escalation.recommended_team} · {PRIORITY_LABEL[escalation.priority]}
              </div>
              <p className="mt-1 text-[13px] leading-[1.5] text-ink-2">{escalation.reason}</p>
              <details className="mt-2">
                <summary className="cursor-default text-[12px] text-ink-3 hover:text-ink">Handover summary</summary>
                <pre className="mt-2 rounded-[7px] bg-sunken p-3 font-mono text-[11.5px] leading-[1.55] whitespace-pre-wrap text-ink-2 shadow-[0_0_0_1px_var(--line-soft)]">
                  {escalation.handover_summary}
                </pre>
              </details>
              {escalation.status_notes?.length ? (
                <ul className="mt-2 space-y-1 text-[12px] text-ink-3">
                  {escalation.status_notes.map((note) => (
                    <li key={note}>{note}</li>
                  ))}
                </ul>
              ) : null}
              <p className="mt-2 text-[11.5px] text-ink-4">Recorded by {escalation.created_by.actor_id} · delivery {escalation.delivery_status.replace("_", " ")}</p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function activeDiagnosisTeam(incident: Incident) {
  return (incident.diagnoses ?? []).find((d) => d.diagnosis_id === incident.active_diagnosis_id)?.diagnosis.escalation.team;
}

function EmptyPanel({ text }: { text: string }) {
  return <p className="rounded-[10px] px-4 py-8 text-center text-[13px] text-ink-3 shadow-[var(--ring-card)]">{text}</p>;
}
