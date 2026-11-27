"use client";

import { Tabs, TabsIndicator, TabsList, TabsPanel, TabsTab } from "@ui-sdk/react/tabs";
import { Share, SquareActivity } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { AgentPanel, type WorkspaceTab } from "@/components/agent/agent-panel";
import { Topbar } from "@/components/shell/topbar";
import { Skeleton } from "@/components/ui/atoms";
import { Button } from "@/components/ui/button";
import { Tip } from "@/components/ui/tip";
import { notify } from "@/components/ui/toaster";
import { describeError, isApiError } from "@/lib/api/client";
import { useAdvanced, useIncident, useNetworkHealth, useTopology } from "@/lib/api/hooks";
import { useCan } from "@/lib/auth";
import type { Incident } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { setPrefs, usePrefs } from "@/lib/prefs";
import { scenarioById } from "@/lib/scenarios";
import { zoneAbbr } from "@/lib/time";
import { IncidentActions } from "./actions";
import { AffectedPath } from "./affected-path";
import { downloadText, incidentReport } from "./export";
import { IncidentHeader } from "./header";
import { activeRecord, buildPath, buildSignals } from "./model";
import { NextStepBar } from "./next-step";
import { AlternativesPanel, ChecksPanel, EscalationsPanel, EvidencePanel, SummaryPanel, TimelinePanel } from "./panels";
import { RootCauseCard, RootCauseSkeleton } from "./root-cause";
import { SignalStrip } from "./signals";

type Tab = WorkspaceTab;

/** The incident page's content grid: the same width cap as the Diagnose page, with the padding inside it, so the header, cards,
 * affected path, tabs and the sticky next-step bar all share one left and right edge. */
const COLUMN = "mx-auto w-full max-w-[1200px] px-5 md:px-8";

export function IncidentWorkspace({ incidentId }: { incidentId: string }) {
  const query = useIncident(incidentId);

  if (query.isPending) return <WorkspaceSkeleton incidentId={incidentId} />;
  if (query.isError) {
    const missing = isApiError(query.error) && query.error.status === 404;
    return (
      <>
        <Topbar crumbs={[{ label: "Network diagnosis", href: "/diagnose" }, { label: incidentId, mono: true }]} />
        <div className="mx-auto w-full max-w-[560px] px-6 pt-16">
          <h1 className="text-[22px] font-semibold tracking-[-0.025em] text-ink">{missing ? `${incidentId} doesn't exist` : "This incident didn't load"}</h1>
          <p className="mt-2 text-[14px] text-ink-3">{missing ? "It may have been opened against another backend." : describeError(query.error)}</p>
          <div className="mt-5 flex gap-2">
            {!missing ? <Button onClick={() => query.refetch()}>Try again</Button> : null}
            <Link href="/incidents" className="inline-flex h-9 items-center rounded-[8px] px-3.5 text-[13.5px] font-medium text-ink-2 shadow-[0_0_0_1px_var(--line)] hover:bg-hover">
              See all incidents
            </Link>
          </div>
        </div>
      </>
    );
  }
  return <Loaded incident={query.data} />;
}

function Loaded({ incident }: { incident: Incident }) {
  const topology = useTopology();
  const can = useCan();
  // Signal analysis re-runs read-only diagnostic tools, so it never starts on page load; it runs when asked.
  const [analysisFor, setAnalysisFor] = useState<string | null>(null);
  const analysisRequested = !!incident.active_diagnosis_id && analysisFor === incident.active_diagnosis_id;
  const advanced = useAdvanced(incident, can("run_diagnostics"), analysisRequested);
  const canAnalyse = can("run_diagnostics") && !!incident.dataset_scenario_id && !!incident.active_diagnosis_id;
  const health = useNetworkHealth(incident.dataset_scenario_id);
  const { agentOpen } = usePrefs();
  const [sheetOpen, setSheetOpen] = useState(false);
  const [tab, setTab] = useState<Tab>("summary");

  const record = activeRecord(incident);
  const diagnosis = record?.diagnosis;
  const siteId = incident.site_ids[0];
  const site = topology.data?.sites.find((s) => s.site_id === siteId);
  const scenario = scenarioById(incident.dataset_scenario_id);

  const hops = useMemo(() => buildPath(diagnosis, advanced.data, topology.data, health.data?.devices), [diagnosis, advanced.data, topology.data, health.data]);
  const signals = useMemo(() => buildSignals(advanced.data, diagnosis), [advanced.data, diagnosis]);

  const faultLink = topology.data?.links.find((link) => diagnosis?.fault.link_ids.includes(link.link_id));
  const circuit = faultLink
    ? [faultLink.provider, faultLink.circuit_id].filter(Boolean).join(" · ") || faultLink.link_id
    : advanced.data?.paths[0]?.modelled_path_id
      ? (topology.data?.paths.find((p) => p.path_id === advanced.data?.paths[0]?.modelled_path_id)?.name ?? undefined)
      : undefined;
  const subtitle = faultLink
    ? `${faultLink.link_type.toUpperCase()} circuit ${faultLink.circuit_id ?? faultLink.link_id}`
    : diagnosis?.fault.device_ids[0]
      ? diagnosis.fault.device_ids[0]
      : scenario
        ? scenario.name
        : "";

  const toggleAgent = () => {
    if (window.matchMedia("(min-width: 1280px)").matches) setPrefs({ agentOpen: !agentOpen });
    else setSheetOpen(true);
  };

  const evidenceCount = diagnosis?.evidence.length ?? 0;
  const escalationCount = incident.escalations?.length ?? 0;

  return (
    <>
      <Topbar
        crumbs={[
          { label: "Network diagnosis", href: "/diagnose" },
          { label: incident.incident_id, mono: true },
        ]}
        actions={
          <>
            {incident.dataset_scenario_id ? (
              <Tip
                label={`${incident.demo ? "Demo incident seeded from a synthetic scenario. " : ""}Telemetry comes from the synthetic ${incident.dataset_scenario_id} dataset${scenario ? `: ${scenario.summary}` : ""}`}
              >
                <span tabIndex={0} aria-label={incident.demo ? "Demo incident" : "Demo data"} className="hidden h-6 items-center gap-1.5 rounded-[6px] bg-hover px-2 text-[12px] text-ink-3 md:inline-flex">
                  <span className="size-[5px] rounded-full bg-ink-3" aria-hidden />
                  {incident.demo ? "Demo incident" : "Demo data"}
                </span>
              </Tip>
            ) : null}
            <span className="hidden text-[12.5px] text-ink-3 md:inline">
              {site?.city ?? siteId} · {zoneAbbr(siteId)}
            </span>
            <Button
              size="sm"
              onClick={() => {
                downloadText(`${incident.incident_id}.md`, incidentReport(incident, advanced.data));
                notify.success("Report downloaded", `${incident.incident_id}.md`);
              }}
            >
              <Share className="size-3.5" aria-hidden />
              <span className="hidden sm:inline">Export report</span>
            </Button>
            <Tip label={agentOpen ? "Hide diagnosis agent" : "Show diagnosis agent"}>
              <button
                type="button"
                aria-label="Diagnosis agent"
                aria-pressed={agentOpen}
                onClick={toggleAgent}
                className={cn("grid size-8 place-items-center rounded-[7px] text-ink-3 hover:bg-hover hover:text-ink", agentOpen && "xl:bg-hover xl:text-ink-2")}
              >
                <SquareActivity className="size-[17px]" aria-hidden />
              </button>
            </Tip>
          </>
        }
      />

      <IncidentActions incident={incident} onViewChecks={() => setTab("checks")}>
        <div className="flex min-h-0 flex-1">
          <div className="scroll-thin flex min-w-0 flex-1 flex-col overflow-y-auto">
            <div className={cn(COLUMN, "flex flex-1 flex-col gap-4 pt-6")}>
              <IncidentHeader incident={incident} site={site} subtitle={subtitle} />
              <div className="mt-1.5">
                <RootCauseCard incident={incident} record={record} diagnosis={diagnosis} />
              </div>
              {record ? (
                analysisRequested || !canAnalyse ? (
                  <SignalStrip signals={signals} loading={advanced.isLoading} failed={advanced.isError} siteId={siteId} />
                ) : (
                  <section aria-label="Signal analysis" className="card flex flex-col gap-3 px-4 py-3.5 sm:flex-row sm:items-center">
                    <div className="min-w-0 flex-1">
                      <div className="text-[13px] font-medium text-ink-2">Measured signals and blast radius</div>
                      <p className="mt-0.5 text-[12.5px] leading-[1.45] text-ink-3">
                        This analysis re-runs read-only checks on the telemetry, so it starts only when you ask.
                      </p>
                    </div>
                    <Button size="sm" onClick={() => setAnalysisFor(incident.active_diagnosis_id ?? null)}>
                      Analyse signals
                    </Button>
                  </section>
                )
              ) : null}
              {record ? (
                <AffectedPath
                  hops={hops}
                  domain={diagnosis!.fault.fault_domain}
                  circuit={circuit}
                  reachability={diagnosis!.affected_path?.reachability}
                  loading={topology.isPending}
                />
              ) : null}

              <Tabs value={tab} onValueChange={(value) => value && setTab(value as Tab)} className="mt-1.5">
                <TabsList aria-label="Incident details" className="scroll-thin relative flex gap-1 overflow-x-auto shadow-[inset_0_-1px_0_var(--line)]">
                  <WorkspaceTab value="summary">Summary</WorkspaceTab>
                  <WorkspaceTab value="evidence" count={evidenceCount}>
                    Evidence
                  </WorkspaceTab>
                  <WorkspaceTab value="checks">Next checks</WorkspaceTab>
                  <WorkspaceTab value="alternatives">Alternatives</WorkspaceTab>
                  <WorkspaceTab value="timeline">Timeline</WorkspaceTab>
                  <WorkspaceTab value="escalations" count={escalationCount}>
                    Escalations
                  </WorkspaceTab>
                  <TabsIndicator className="absolute bottom-0 left-(--active-tab-left) h-[2px] w-(--active-tab-width) rounded-full bg-accent transition-[left,width] duration-[480ms] ease-(--ease-spring)" />
                </TabsList>
                <TabsPanel value="summary" className="pt-5 outline-none">
                  <SummaryPanel incident={incident} diagnosis={diagnosis} advanced={advanced.data} onShowEvidence={() => setTab("evidence")} />
                </TabsPanel>
                <TabsPanel value="evidence" className="pt-5 outline-none">
                  <EvidencePanel incident={incident} />
                </TabsPanel>
                <TabsPanel value="checks" className="pt-5 outline-none">
                  <ChecksPanel incident={incident} diagnosis={diagnosis} advanced={advanced.data} />
                </TabsPanel>
                <TabsPanel value="alternatives" className="pt-5 outline-none">
                  <AlternativesPanel incident={incident} diagnosis={diagnosis} advanced={advanced.data} />
                </TabsPanel>
                <TabsPanel value="timeline" className="pt-5 outline-none">
                  <TimelinePanel incident={incident} diagnosis={diagnosis} advanced={advanced.data} />
                </TabsPanel>
                <TabsPanel value="escalations" className="pt-5 outline-none">
                  <EscalationsPanel incident={incident} />
                </TabsPanel>
              </Tabs>
              {advanced.isError ? (
                <p className="text-[12px] text-ink-4">Advanced analysis didn&apos;t load: {describeError(advanced.error)}</p>
              ) : null}
              <div className="flex-1" />
            </div>
            <div className="sticky bottom-0 z-10 bg-page pt-4 pb-5">
              <div className={COLUMN}>
                <NextStepBar diagnosis={diagnosis} />
              </div>
            </div>
          </div>

          {agentOpen ? (
            <div className="hidden w-[360px] shrink-0 shadow-[inset_1px_0_0_var(--line)] xl:block">
              <AgentPanel key={incident.incident_id} incident={incident} onClose={() => setPrefs({ agentOpen: false })} onShowTab={setTab} />
            </div>
          ) : null}
        </div>

        {sheetOpen ? (
          <div className="fixed inset-0 z-40 xl:hidden">
            <button type="button" aria-label="Close diagnosis agent" className="absolute inset-0 bg-[var(--scrim)]" onClick={() => setSheetOpen(false)} />
            <div className="absolute inset-y-0 right-0 w-[min(380px,100vw)] shadow-[var(--shadow-pop)]">
              <AgentPanel
                key={incident.incident_id}
                incident={incident}
                onClose={() => setSheetOpen(false)}
                onShowTab={(next) => {
                  setTab(next);
                  setSheetOpen(false);
                }}
              />
            </div>
          </div>
        ) : null}
      </IncidentActions>
    </>
  );
}

function WorkspaceTab({ value, count, children }: { value: Tab; count?: number; children: React.ReactNode }) {
  return (
    <TabsTab
      value={value}
      className="relative flex h-10 shrink-0 items-center gap-1.5 px-3 text-[14px] text-ink-2 outline-none transition-colors duration-150 hover:text-ink focus-visible:rounded-[6px] focus-visible:shadow-[0_0_0_2px_var(--accent-ring)] data-selected:text-accent"
    >
      {children}
      {count ? <span className="text-[11.5px] tabular-nums text-ink-4">{count}</span> : null}
    </TabsTab>
  );
}

function WorkspaceSkeleton({ incidentId }: { incidentId: string }) {
  return (
    <>
      <Topbar crumbs={[{ label: "Network diagnosis", href: "/diagnose" }, { label: incidentId, mono: true }]} />
      <div className={cn(COLUMN, "space-y-4 pt-6")} aria-busy="true">
        <Skeleton className="h-5 w-40" />
        <Skeleton className="h-9 w-[420px] max-w-full" />
        <Skeleton className="h-4 w-60" />
        <RootCauseSkeleton />
        <Skeleton className="h-24" />
        <Skeleton className="h-32" />
      </div>
    </>
  );
}

