"use client";

import { Tabs, TabsIndicator, TabsList, TabsPanel, TabsTab } from "@ui-sdk/react/tabs";
import { useState, type ReactNode } from "react";
import { CapacityPanel } from "@/components/observability/capacity";
import { ConfigurationPanel, DependenciesPanel } from "@/components/observability/configuration";
import { HealthMapPanel } from "@/components/observability/health-map";
import { JourneyPanel } from "@/components/observability/journey";
import { LiveTopologyPanel } from "@/components/observability/live-topology";
import { TelemetryPanel } from "@/components/observability/telemetry";
import { TrafficPanel } from "@/components/observability/traffic";
import { Topbar } from "@/components/shell/topbar";
import { ErrorNote } from "@/components/ui/atoms";
import { StatBar } from "@/components/ui/charts";
import { SelectBox } from "@/components/ui/fields";
import { describeError } from "@/lib/api/client";
import { useActiveIncidents, useIncident } from "@/lib/api/hooks";
import { useCongestion, useDrift, useLiveStream, useObsHealth, useTraffic } from "@/lib/api/observability";
import { SCENARIOS, scenarioById } from "@/lib/scenarios";

type Tab = "topology" | "map" | "traffic" | "journey" | "capacity" | "configuration" | "dependencies" | "telemetry";

function ObsTab({ value, children }: { value: Tab; children: ReactNode }) {
  return (
    <TabsTab
      value={value}
      className="relative flex h-10 shrink-0 items-center gap-1.5 px-3 text-[14px] text-ink-2 outline-none transition-colors duration-150 hover:text-ink focus-visible:rounded-[6px] focus-visible:shadow-[0_0_0_2px_var(--accent-ring)] data-selected:text-accent"
    >
      {children}
    </TabsTab>
  );
}

export function ObservabilityView() {
  const active = useActiveIncidents();
  const latest = [...(active.data?.items ?? [])].sort((a, b) => b.updated_at.localeCompare(a.updated_at))[0];
  const latestIncident = useIncident(latest?.incident_id ?? null);
  const [chosen, setChosen] = useState<string | null>(null);
  const scenario = chosen ?? latestIncident.data?.dataset_scenario_id ?? "BASELINE";
  const [tab, setTab] = useState<Tab>("topology");
  const live = useLiveStream(scenario, tab === "topology" || tab === "telemetry");

  const health = useObsHealth(scenario);
  const drift = useDrift(scenario);
  const congestion = useCongestion(scenario);
  const traffic = useTraffic(scenario);
  const failed = [health, drift, congestion, traffic].find((q) => q.isError);

  return (
    <>
      <Topbar crumbs={[{ label: "Observability" }]} />
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[1200px] space-y-5 px-5 pt-6 pb-16 md:px-8">
          <div className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <h1 className="text-[24px] font-semibold tracking-[-0.03em] text-ink">Network intelligence</h1>
              <p className="mt-1 max-w-[640px] text-[13px] text-ink-3">{scenarioById(scenario)?.summary ?? "Synthetic telemetry"}</p>
            </div>
            <SelectBox
              ariaLabel="Telemetry dataset"
              className="w-[300px]"
              value={scenario}
              onValueChange={setChosen}
              options={SCENARIOS.map((s) => ({ value: s.id, label: s.name }))}
            />
          </div>

          <StatBar
            loading={health.isPending}
            comparison="Computed from simulated telemetry for the selected dataset"
            stats={[
              { key: "score", label: "Network health", value: health.data?.network.score ?? undefined, tone: health.data && health.data.network.status !== "healthy" ? "amber" : undefined },
              { key: "critical", label: "Critical sites", value: health.data ? health.data.sites.filter((s) => s.status === "critical").length : undefined, tone: "red" },
              { key: "drift", label: "Drifted config lines", value: drift.data?.summary.items, tone: "amber" },
              { key: "congestion", label: "Links at congestion risk", value: congestion.data ? congestion.data.summary.high + congestion.data.summary.medium : undefined, tone: "amber" },
              { key: "dropped", label: "Flows dropped by policy", value: traffic.data?.totals.dropped_flows, tone: "red" },
            ]}
          />
          {failed ? <ErrorNote message={describeError(failed.error)} onRetry={() => failed.refetch()} /> : null}

          <Tabs value={tab} onValueChange={(value) => value && setTab(value as Tab)}>
            <TabsList aria-label="Observability views" className="scroll-thin relative flex gap-1 overflow-x-auto shadow-[inset_0_-1px_0_var(--line)]">
              <ObsTab value="topology">Live topology</ObsTab>
              <ObsTab value="map">Health map</ObsTab>
              <ObsTab value="traffic">Traffic flows</ObsTab>
              <ObsTab value="journey">Packet journey</ObsTab>
              <ObsTab value="capacity">Capacity</ObsTab>
              <ObsTab value="configuration">Configuration</ObsTab>
              <ObsTab value="dependencies">Dependencies</ObsTab>
              <ObsTab value="telemetry">Telemetry</ObsTab>
              <TabsIndicator className="absolute bottom-0 left-(--active-tab-left) h-[2px] w-(--active-tab-width) rounded-full bg-accent transition-[left,width] duration-[480ms] ease-(--ease-spring)" />
            </TabsList>
            <TabsPanel value="topology" className="pt-5 outline-none">
              <LiveTopologyPanel scenario={scenario} live={live} />
            </TabsPanel>
            <TabsPanel value="map" className="pt-5 outline-none">
              <HealthMapPanel scenario={scenario} />
            </TabsPanel>
            <TabsPanel value="traffic" className="pt-5 outline-none">
              <TrafficPanel scenario={scenario} />
            </TabsPanel>
            <TabsPanel value="journey" className="pt-5 outline-none">
              <JourneyPanel scenario={scenario} />
            </TabsPanel>
            <TabsPanel value="capacity" className="pt-5 outline-none">
              <CapacityPanel scenario={scenario} />
            </TabsPanel>
            <TabsPanel value="configuration" className="pt-5 outline-none">
              <ConfigurationPanel scenario={scenario} />
            </TabsPanel>
            <TabsPanel value="dependencies" className="pt-5 outline-none">
              <DependenciesPanel scenario={scenario} />
            </TabsPanel>
            <TabsPanel value="telemetry" className="pt-5 outline-none">
              <TelemetryPanel scenario={scenario} live={live} />
            </TabsPanel>
          </Tabs>
        </div>
      </div>
    </>
  );
}
