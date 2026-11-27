"use client";

import { Toggle as ToggleButton } from "@ui-sdk/react/toggle";
import { ArrowRight, Check } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, type CSSProperties, type FormEvent } from "react";
import { Dot, ErrorNote, Pill } from "@/components/ui/atoms";
import { Button, Spinner } from "@/components/ui/button";
import { Segmented, Toggle } from "@/components/ui/controls";
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
  const missing = [
    draft.title.trim().length < 3 ? "a title" : null,
    draft.description.trim() ? null : "what users report",
    draft.siteIds.length ? null : "a site",
  ].filter((part): part is string => part !== null);

  return (
    <form
      onSubmit={(event: FormEvent) => {
        event.preventDefault();
        void open();
      }}
      className="card @container relative overflow-hidden"
    >
      <ScenarioPicker
        selectedId={draft.scenarioId}
        isSelected={(scenario) => draft.scenarioId === scenario.id && draft.title === scenario.report?.title}
        onPick={startFrom}
      />

      <div className="space-y-4 px-5 py-5 shadow-[inset_0_1px_0_var(--line-soft)]">
        <TextField label="Title" value={draft.title} onChange={(title) => update({ title })} required minLength={3} maxLength={200} placeholder="Singapore office cannot reach any corporate service" />
        <div className="grid gap-4 @xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
          <TextAreaField
            label="What users report"
            value={draft.description}
            onChange={(description) => update({ description })}
            required
            rows={4}
            maxLength={4000}
            placeholder="Who is affected, what fails, since when. Name the site or city; the planner reads it."
          />
          <TextAreaField
            label={
              <span className="flex items-baseline justify-between gap-3">
                Symptoms
                <span className="font-normal text-ink-4">One per line, optional</span>
              </span>
            }
            rows={4}
            value={draft.symptoms}
            onChange={(symptoms) => update({ symptoms })}
            placeholder={"Slow ERP response\nCalls drop"}
          />
        </div>
      </div>

      <div className="space-y-4 px-5 py-5 shadow-[inset_0_1px_0_var(--line-soft)]">
        <FieldGroup label="Sites">
          <div className="flex flex-wrap gap-2" role="group" aria-label="Sites">
            {(sites.length ? sites : [{ site_id: "SIN", city: "Singapore" }, { site_id: "NYC", city: "New York" }, { site_id: "BLR", city: "Bengaluru" }]).map((site) => (
              <ToggleButton
                key={site.site_id}
                pressed={draft.siteIds.includes(site.site_id)}
                onPressedChange={(pressed) =>
                  update({ siteIds: pressed ? [...draft.siteIds, site.site_id] : draft.siteIds.filter((id) => id !== site.site_id) })
                }
                className="inline-flex h-10 items-center gap-2 rounded-[8px] bg-sunken px-3 text-[13px] text-ink-2 shadow-[0_0_0_1px_var(--line)] transition-[background-color,color,box-shadow] duration-150 hover:text-ink data-pressed:bg-selected data-pressed:text-ink data-pressed:shadow-[0_0_0_1px_var(--accent-ring)]"
              >
                <span className="font-mono text-[11px] text-ink-4">{site.site_id}</span>
                {site.city}
              </ToggleButton>
            ))}
          </div>
        </FieldGroup>
        <div className="grid gap-4 @lg:grid-cols-2 @2xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1.1fr)_minmax(0,1fr)]">
          <div className="@lg:col-span-2 @2xl:col-span-1">
            <FieldGroup label="Telemetry dataset">
              <SelectBox ariaLabel="Telemetry dataset" value={draft.scenarioId} onValueChange={(scenarioId) => update({ scenarioId })} options={SCENARIOS.map((s) => ({ value: s.id, label: s.name }))} />
            </FieldGroup>
          </div>
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
      </div>

      {duplicate || error ? (
        <div className="space-y-3 px-5 pb-5">
          {duplicate ? <DuplicateNotice outcome={duplicate} onOpenAnyway={() => void open(true)} onGo={(id) => router.push(`/diagnose/${id}`)} /> : null}
          {error ? <ErrorNote message={error} /> : null}
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-x-6 gap-y-3 bg-panel px-5 py-3.5 shadow-[inset_0_1px_0_var(--line-soft)]">
        {canDiagnose ? <Toggle checked={diagnoseNow} onCheckedChange={setDiagnoseNow} label="Acknowledge and diagnose right away" /> : null}
        <div className="ml-auto flex w-full flex-col gap-1.5 sm:w-auto sm:items-end">
          <div className="flex items-center justify-end gap-5">
          {canDiagnose ? (
            <button
              type="button"
              disabled={!valid || quick.isPending}
              onClick={() => void quickCheck()}
              className="text-[13px] text-ink-3 underline decoration-line-strong underline-offset-4 transition-colors hover:text-ink disabled:opacity-45 disabled:no-underline"
            >
              {quick.isPending ? "Checking" : "Check without saving"}
            </button>
          ) : null}
          <button
            type="submit"
            disabled={!valid || !!stage}
            className="inline-flex h-10 flex-1 items-center justify-center gap-2 rounded-[8px] bg-accent-strong px-4 sm:flex-none text-[14px] font-medium tracking-[-0.01em] text-accent-fg shadow-[inset_0_1px_0_rgb(255_255_255/0.14),0_1px_2px_rgb(0_0_0/0.3)] transition-[background-color,translate,opacity] duration-150 hover:bg-accent-strong-hover active:translate-y-px disabled:opacity-45"
          >
            {stage ? <Spinner /> : null}
            {stage ?? (diagnoseNow && canDiagnose ? "Open and diagnose" : "Open incident")}
            {!stage ? <ArrowRight className="size-4" aria-hidden /> : null}
          </button>
          </div>
          {missing.length && !stage ? (
            <span className="text-[12px] text-ink-4 sm:text-right">
              Add {missing.length === 1 ? missing[0] : `${missing.slice(0, -1).join(", ")} and ${missing.at(-1)}`} to open it
            </span>
          ) : null}
        </div>
      </div>

      {preview ? <QuickResult diagnosis={preview} /> : null}
    </form>
  );
}

type Family = "outages" | "protocols" | "incidents";
const FAMILIES: { value: Family; label: string; short: string }[] = [
  { value: "outages", label: "Outages", short: "Outages" },
  { value: "protocols", label: "Protocol & security", short: "Protocols" },
  { value: "incidents", label: "Incident set", short: "Incidents" },
];

/** Datasets fall into three families by id: the core outages, the protocol and security set, and the incident set. */
function familyOf(id: string): Family {
  return id.startsWith("P3-") ? "protocols" : id.startsWith("SCN-") ? "incidents" : "outages";
}

/** The name without the set prefix it repeats ("Phase 3 · ", "Scenario 05 · "); the incident set keeps its number. */
function displayName(scenario: Scenario): { number?: string; name: string } {
  const numbered = scenario.name.match(/^Scenario (\d+) · (.+)$/);
  if (numbered) return { number: numbered[1], name: numbered[2] };
  return { name: scenario.name.replace(/^Phase 3 · /, "") };
}

/** Which ends of a scrolling list hide items, for a fade that says there is more. */
function useScrollEdges(deps: unknown) {
  const ref = useRef<HTMLDivElement>(null);
  const [edges, setEdges] = useState({ top: false, bottom: false });
  useEffect(() => {
    const list = ref.current;
    if (!list) return;
    const update = () => {
      const top = list.scrollTop > 1;
      const bottom = list.scrollTop + list.clientHeight < list.scrollHeight - 1;
      setEdges((prev) => (prev.top === top && prev.bottom === bottom ? prev : { top, bottom }));
    };
    update();
    list.addEventListener("scroll", update, { passive: true });
    const observer = new ResizeObserver(update);
    observer.observe(list);
    return () => {
      list.removeEventListener("scroll", update);
      observer.disconnect();
    };
  }, [deps]);
  const mask = edges.top || edges.bottom
    ? `linear-gradient(to bottom, ${edges.top ? "transparent 0, #000 20px" : "#000 0"}, ${edges.bottom ? "#000 calc(100% - 24px), transparent 100%" : "#000 100%"})`
    : undefined;
  return { ref, style: mask ? ({ maskImage: mask, WebkitMaskImage: mask } as CSSProperties) : undefined };
}

function ScenarioPicker({
  selectedId,
  isSelected,
  onPick,
}: {
  selectedId: string;
  isSelected: (scenario: Scenario) => boolean;
  onPick: (scenario: Scenario) => void;
}) {
  const reported = SCENARIOS.filter((s) => s.report);
  const [family, setFamily] = useState<Family>(() => familyOf(selectedId));
  const shown = reported.filter((s) => familyOf(s.id) === family);
  const { ref, style } = useScrollEdges(family);
  const count = (value: Family) => reported.filter((s) => familyOf(s.id) === value).length;

  return (
    <div className="px-5 pt-4 pb-5">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-3">
        <h2 className="text-[13.5px] font-medium tracking-[-0.01em] text-ink">Start from a reported problem</h2>
        <Segmented
          size="sm"
          ariaLabel="Scenario family"
          value={family}
          onValueChange={setFamily}
          options={FAMILIES.map((option) => ({
            value: option.value,
            label: (
              <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
                <span className="@md:hidden">{option.short}</span>
                <span className="hidden @md:inline">{option.label}</span>
                <span className="text-ink-4 tabular-nums">{count(option.value)}</span>
              </span>
            ),
          }))}
        />
      </div>
      <div ref={ref} style={style} className="scroll-thin -mx-1 mt-3.5 max-h-[252px] overflow-y-auto px-1 py-1">
        <div role="group" aria-label={`${FAMILIES.find((f) => f.value === family)?.label} scenarios`} className="grid gap-2 @lg:grid-cols-2 @3xl:grid-cols-3">
          {shown.map((scenario) => {
            const selected = isSelected(scenario);
            const { number, name } = displayName(scenario);
            return (
              <button
                key={scenario.id}
                type="button"
                aria-pressed={selected}
                title={scenario.name}
                onClick={() => onPick(scenario)}
                className={cn(
                  "group flex min-h-[56px] w-full items-start gap-2.5 rounded-[8px] px-3 py-2.5 text-left transition-[background-color,box-shadow] duration-150",
                  selected ? "bg-selected shadow-[0_0_0_1px_var(--accent-ring)]" : "bg-sunken shadow-[0_0_0_1px_var(--line-soft)] hover:bg-hover",
                )}
              >
                {number ? <span className="mt-[2px] w-4 shrink-0 font-mono text-[11px] text-ink-4 tabular-nums">{number}</span> : null}
                <span className="min-w-0 flex-1">
                  <span className={cn("line-clamp-2 text-[13px] leading-[1.35] tracking-[-0.005em]", selected ? "text-ink" : "text-ink-2 group-hover:text-ink")}>
                    {name}
                  </span>
                  {scenario.report ? (
                    <span className="mt-1 flex items-center gap-1.5 text-[11.5px] text-ink-4">
                      <span className="font-mono text-[11px]">{scenario.report.siteIds.join(" ")}</span>
                      <span aria-hidden>·</span>
                      <span className="tabular-nums">{PRIORITY_LABEL[scenario.report.priority]}</span>
                    </span>
                  ) : null}
                </span>
                <Check aria-hidden className={cn("mt-[2px] size-3.5 shrink-0 text-accent", selected ? "opacity-100" : "opacity-0")} />
              </button>
            );
          })}
        </div>
      </div>
    </div>
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
    <section aria-label="Quick check result" className="px-5 py-5 shadow-[inset_0_1px_0_var(--line-soft)]">
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
