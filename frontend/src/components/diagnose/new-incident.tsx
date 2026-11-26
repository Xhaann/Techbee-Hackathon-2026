"use client";

import { Toggle as ToggleButton } from "@ui-sdk/react/toggle";
import { ArrowRight } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Dot, ErrorNote, Pill } from "@/components/ui/atoms";
import { Button, Spinner } from "@/components/ui/button";
import { Toggle } from "@/components/ui/controls";
import { ALL, FieldGroup, SelectBox, TextAreaField, TextField } from "@/components/ui/fields";
import { notify } from "@/components/ui/toaster";
import { describeError } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import { settleIncident, useCreateIncident, useQuickDiagnosis, useTopology } from "@/lib/api/hooks";
import type { CreationOutcome, Diagnosis, IncidentPriority, IncidentSource } from "@/lib/api/types";
import { useCan } from "@/lib/auth";
import { cn } from "@/lib/cn";
import { CONFIDENCE_LABEL, PRIORITY_LABEL, SOURCE_LABEL, faultHeadline } from "@/lib/labels";
import { SCENARIOS, type Scenario } from "@/lib/scenarios";
import { useQueryClient } from "@tanstack/react-query";

type Draft = {
  title: string;
  description: string;
  siteIds: string[];
  scenarioId: string;
  priority: IncidentPriority | typeof ALL;
  source: IncidentSource;
  symptoms: string;
};

const EMPTY: Draft = { title: "", description: "", siteIds: [], scenarioId: "PACKET-LOSS", priority: ALL, source: "user_report", symptoms: "" };

export function NewIncident() {
  const can = useCan();
  const router = useRouter();
  const queryClient = useQueryClient();
  const topology = useTopology();
  const create = useCreateIncident();
  const quick = useQuickDiagnosis();
  const [draft, setDraft] = useState<Draft>(EMPTY);
  const [diagnoseNow, setDiagnoseNow] = useState(true);
  const [duplicate, setDuplicate] = useState<CreationOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stage, setStage] = useState<string | null>(null);
  const [preview, setPreview] = useState<Diagnosis | null>(null);

  const update = (patch: Partial<Draft>) => {
    setDraft((current) => ({ ...current, ...patch }));
    setDuplicate(null);
    setError(null);
  };

  const startFrom = (scenario: Scenario) => {
    if (!scenario.report) return;
    update({
      title: scenario.report.title,
      description: scenario.report.description,
      siteIds: scenario.report.siteIds,
      scenarioId: scenario.id,
      priority: scenario.report.priority,
      symptoms: scenario.report.symptoms.join("\n"),
    });
    setPreview(null);
  };

  const valid = draft.title.trim().length >= 3 && draft.description.trim().length > 0 && draft.siteIds.length > 0;
  const canCreate = can("create_incidents");
  const canDiagnose = can("run_diagnostics");

  async function open(force = false) {
    setError(null);
    try {
      setStage("Opening the incident");
      const outcome = await create.mutateAsync({
        title: draft.title.trim(),
        description: draft.description.trim(),
        site_ids: draft.siteIds,
        dataset_scenario_id: draft.scenarioId,
        priority: draft.priority === ALL ? null : draft.priority,
        source: draft.source,
        symptoms: draft.symptoms
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean)
          .slice(0, 20),
        force_new: force,
      });
      if (!outcome.created) {
        setDuplicate(outcome);
        return;
      }
      let incident = outcome.incident;
      if (diagnoseNow && canDiagnose) {
        try {
          setStage("Acknowledging");
          incident = await api.incidents.patch(incident.incident_id, { expected_version: incident.version, status: "acknowledged" });
          setStage("Running read-only checks");
          incident = await api.incidents.diagnose(incident.incident_id, incident.version);
          settleIncident(queryClient, incident);
        } catch (stepError) {
          notify.warning("Opened, but the diagnosis didn't run", describeError(stepError));
        }
      }
      notify.success(`${incident.incident_id} opened`);
      router.push(`/diagnose/${incident.incident_id}`);
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setStage(null);
    }
  }

  async function quickCheck() {
    setError(null);
    setPreview(null);
    try {
      const result = await quick.mutateAsync({
        scenario_id: draft.scenarioId,
        description: [draft.title, draft.description].filter((s) => s.trim()).join(". "),
        site_ids: draft.siteIds,
      });
      setPreview(result);
    } catch (caught) {
      setError(describeError(caught));
    }
  }

  if (!canCreate) {
    return (
      <p className="card px-4 py-4 text-[13.5px] text-ink-3">
        Your role can view incidents but not open them. Pick an active incident to follow its diagnosis.
      </p>
    );
  }

  const sites = topology.data?.sites ?? [];

  return (
    <form
      onSubmit={(event: FormEvent) => {
        event.preventDefault();
        void open();
      }}
      className="space-y-5"
    >
      <div>
        <div className="mb-2 text-[12.5px] text-ink-3">Start from a reported problem</div>
        <div className="flex flex-wrap gap-1.5">
          {SCENARIOS.filter((s) => s.report).map((scenario) => (
            <button
              key={scenario.id}
              type="button"
              onClick={() => startFrom(scenario)}
              className={cn(
                "h-7 rounded-[7px] px-2.5 text-[12.5px] transition-colors",
                draft.scenarioId === scenario.id && draft.title === scenario.report?.title
                  ? "bg-selected text-ink shadow-[0_0_0_1px_var(--accent-ring)]"
                  : "bg-surface text-ink-2 shadow-[0_0_0_1px_var(--line)] hover:bg-hover hover:text-ink",
              )}
            >
              {scenario.name}
            </button>
          ))}
        </div>
      </div>

      <TextField label="Title" value={draft.title} onChange={(title) => update({ title })} required minLength={3} maxLength={200} placeholder="Singapore office cannot reach any corporate service" />
      <TextAreaField
        label="What users report"
        value={draft.description}
        onChange={(description) => update({ description })}
        required
        maxLength={4000}
        placeholder="Who is affected, what fails, since when. Name the site or city; the planner reads it."
      />

      <FieldGroup label="Sites">
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Sites">
          {(sites.length ? sites : [{ site_id: "SIN", city: "Singapore" }, { site_id: "NYC", city: "New York" }, { site_id: "BLR", city: "Bengaluru" }]).map((site) => (
            <ToggleButton
              key={site.site_id}
              pressed={draft.siteIds.includes(site.site_id)}
              onPressedChange={(pressed) =>
                update({ siteIds: pressed ? [...draft.siteIds, site.site_id] : draft.siteIds.filter((id) => id !== site.site_id) })
              }
              className="inline-flex h-8 items-center gap-1.5 rounded-[7px] bg-surface px-2.5 text-[12.5px] text-ink-2 shadow-[0_0_0_1px_var(--line)] transition-colors hover:text-ink data-pressed:bg-selected data-pressed:text-ink data-pressed:shadow-[0_0_0_1px_var(--accent-ring)]"
            >
              <span className="font-mono text-[11px] text-ink-3">{site.site_id}</span>
              {site.city}
            </ToggleButton>
          ))}
        </div>
      </FieldGroup>

      <div className="grid gap-4 sm:grid-cols-3">
        <FieldGroup label="Telemetry dataset">
          <SelectBox ariaLabel="Telemetry dataset" value={draft.scenarioId} onValueChange={(scenarioId) => update({ scenarioId })} options={SCENARIOS.map((s) => ({ value: s.id, label: s.name }))} />
        </FieldGroup>
        <FieldGroup label="Priority">
          <SelectBox
            ariaLabel="Priority"
            value={draft.priority}
            onValueChange={(priority) => update({ priority })}
            options={[{ value: ALL, label: "Derive from severity" }, ...(Object.keys(PRIORITY_LABEL) as IncidentPriority[]).map((p) => ({ value: p, label: PRIORITY_LABEL[p] }))]}
          />
        </FieldGroup>
        <FieldGroup label="Reported through">
          <SelectBox
            ariaLabel="Reported through"
            value={draft.source}
            onValueChange={(source) => update({ source })}
            options={(["user_report", "monitoring", "service_desk"] as IncidentSource[]).map((s) => ({ value: s, label: SOURCE_LABEL[s] }))}
          />
        </FieldGroup>
      </div>

      <TextAreaField label="Symptoms" hint="Optional. One per line." rows={3} value={draft.symptoms} onChange={(symptoms) => update({ symptoms })} />

      {duplicate ? <DuplicateNotice outcome={duplicate} onOpenAnyway={() => void open(true)} onGo={(id) => router.push(`/diagnose/${id}`)} /> : null}
      {error ? <ErrorNote message={error} /> : null}

      <div className="flex flex-wrap items-center gap-x-5 gap-y-3 pt-1">
        <button
          type="submit"
          disabled={!valid || !!stage}
          className="inline-flex h-10 items-center gap-2 rounded-[8px] bg-accent-strong px-4 text-[14px] font-medium tracking-[-0.01em] text-accent-fg shadow-[inset_0_1px_0_rgb(255_255_255/0.14),0_1px_2px_rgb(0_0_0/0.3)] transition-[background-color,translate] duration-150 hover:bg-accent-strong-hover active:translate-y-px disabled:opacity-45"
        >
          {stage ? <Spinner /> : null}
          {stage ?? (diagnoseNow && canDiagnose ? "Open and diagnose" : "Open incident")}
          {!stage ? <ArrowRight className="size-4" aria-hidden /> : null}
        </button>
        {canDiagnose ? <Toggle checked={diagnoseNow} onCheckedChange={setDiagnoseNow} label="Acknowledge and diagnose right away" /> : null}
        {canDiagnose ? (
          <button
            type="button"
            disabled={!valid || quick.isPending}
            onClick={() => void quickCheck()}
            className="text-[13px] text-ink-3 underline decoration-line-strong underline-offset-4 hover:text-ink disabled:opacity-45 disabled:no-underline"
          >
            {quick.isPending ? "Checking" : "Check without saving"}
          </button>
        ) : null}
      </div>

      {preview ? <QuickResult diagnosis={preview} /> : null}
    </form>
  );
}

function sentence(text: string) {
  const trimmed = text.trim();
  return /[.!?]$/.test(trimmed) ? trimmed : `${trimmed}.`;
}

function DuplicateNotice({ outcome, onOpenAnyway, onGo }: { outcome: CreationOutcome; onOpenAnyway: () => void; onGo: (id: string) => void }) {
  const match = outcome.duplicate_of;
  return (
    <div className="rounded-[10px] bg-amber-soft px-4 py-3 shadow-[0_0_0_1px_var(--amber-line)]">
      <div className="text-[13.5px] font-medium text-amber">
        This looks like {outcome.incident.incident_id}, which is already open
      </div>
      <p className="mt-1 text-[12.5px] leading-[1.45] text-ink-2">
        {sentence(outcome.duplicate_reason ?? "The report matches an active incident")}
        {match ? ` Match strength: ${match.strength}.` : ""}
      </p>
      <div className="mt-2.5 flex gap-2">
        <Button size="sm" variant="primary" type="button" onClick={() => onGo(outcome.incident.incident_id)}>
          Open {outcome.incident.incident_id}
        </Button>
        <Button size="sm" variant="ghost" type="button" onClick={onOpenAnyway}>
          Open a new one anyway
        </Button>
      </div>
    </div>
  );
}

function QuickResult({ diagnosis }: { diagnosis: Diagnosis }) {
  return (
    <section aria-label="Quick check result" className="card-raised px-5 py-4">
      <div className="flex items-center gap-2 text-[12px] text-ink-3">
        <Dot tone="muted" />
        Not saved · {diagnosis.tool_calls.length} tool calls · {diagnosis.evidence.length} evidence items
      </div>
      <h3 className="mt-2 text-[18px] font-semibold tracking-[-0.02em] text-ink">{faultHeadline(diagnosis.fault.fault_domain, diagnosis.fault.root_cause)}</h3>
      <p className="mt-1 text-[13px] leading-[1.5] text-ink-2">{diagnosis.fault.root_cause}</p>
      <div className="mt-2 flex flex-wrap gap-2">
        <Pill tone={diagnosis.confidence.level === "high" ? "accent" : "muted"}>{CONFIDENCE_LABEL[diagnosis.confidence.level]} confidence</Pill>
        {diagnosis.affected_path ? <Pill>{diagnosis.affected_path.reachability}</Pill> : null}
      </div>
      <ul className="mt-3 space-y-1.5 border-t border-line-soft pt-3">
        {diagnosis.evidence.slice(0, 4).map((item) => (
          <li key={item.evidence_id} className="flex gap-2.5 text-[12.5px] leading-[1.45] text-ink-soft">
            <span className="w-6 shrink-0 font-mono text-[11px] leading-[18px] text-accent">{item.evidence_id}</span>
            {item.summary}
          </li>
        ))}
      </ul>
      <p className="mt-3 text-[12px] text-ink-3">Open it as an incident to keep this result, run the agent and track the fix.</p>
    </section>
  );
}
