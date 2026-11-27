"use client";

import { useState } from "react";
import { Dot, ErrorNote, Pill, Skeleton } from "@/components/ui/atoms";
import { describeError } from "@/lib/api/client";
import { useConfigDiff, useDependencies, useDiscovery, useDrift } from "@/lib/api/observability";
import { cn } from "@/lib/cn";
import { Cell, Empty, Panel, SEVERITY_TONE, SourceNote, Table, clock, plural } from "./shared";

const DEVICE_STATUS_TONE = { compliant: "green", drifted: "red", unverified: "amber" } as const;

export function ConfigurationPanel({ scenario }: { scenario: string }) {
  const drift = useDrift(scenario);
  const discovery = useDiscovery(scenario);
  const [device, setDevice] = useState<string | null>(null);
  const drifted = drift.data?.devices.find((d) => d.status === "drifted")?.device_id ?? null;
  const chosen = device ?? drifted;
  const diff = useConfigDiff(scenario, chosen);

  return (
    <div className="space-y-3">
      <Panel
        title="Configuration drift"
        aside={drift.data ? `${plural(drift.data.summary.items, "line")} on ${plural(drift.data.summary.drifted, "device")} · ${drift.data.summary.unattributed} unattributed` : null}
      >
        {drift.isPending ? <Skeleton className="h-40" /> : null}
        {drift.isError ? <ErrorNote message={describeError(drift.error)} onRetry={() => drift.refetch()} /> : null}
        {drift.data ? (
          <div className="grid gap-4 lg:grid-cols-[240px_minmax(0,1fr)]">
            <ul className="space-y-1">
              {drift.data.devices.map((entry) => (
                <li key={entry.device_id}>
                  <button
                    type="button"
                    onClick={() => setDevice(entry.device_id)}
                    className={cn("flex w-full items-center gap-2 rounded-[6px] px-2 py-1.5 text-left text-[12.5px] hover:bg-hover", chosen === entry.device_id && "bg-selected")}
                  >
                    <Dot tone={DEVICE_STATUS_TONE[entry.status]} />
                    <span className="font-mono text-ink-2">{entry.device_id}</span>
                    <span className="ml-auto text-[11.5px] text-ink-3">{entry.status === "drifted" ? `${entry.drift_items} lines` : entry.status}</span>
                  </button>
                </li>
              ))}
            </ul>
            <div className="min-w-0 space-y-3">
              {drift.data.items.filter((i) => i.device_id === chosen).length ? (
                <Table head={["Change", "Line", "Severity", "Logged change"]} minWidth={620}>
                  {drift.data.items
                    .filter((i) => i.device_id === chosen)
                    .map((item) => (
                      <tr key={`${item.section}${item.change}${item.line}`}>
                        <Cell>
                          <span className={item.change === "added" ? "text-green" : "text-red"}>{item.change === "added" ? "+ added" : "− removed"}</span>
                          <div className="text-[11.5px] text-ink-4">{item.section}</div>
                        </Cell>
                        <Cell mono className="max-w-[320px] break-all">
                          {item.line}
                        </Cell>
                        <Cell>
                          <Pill tone={SEVERITY_TONE[item.severity] ?? "muted"}>{item.severity}</Pill>
                          <div className="mt-0.5 text-[11.5px] text-ink-4">{item.category.replaceAll("_", " ")}</div>
                        </Cell>
                        <Cell className="text-[12px]">
                          {item.attributed ? (
                            <>
                              {item.event_id} at {clock(item.changed_at)}
                              {item.changed_by ? ` by ${item.changed_by}` : ""}
                              {item.ticket ? ` · ${item.ticket}` : ""}
                            </>
                          ) : (
                            <span className="text-amber">No logged change explains this</span>
                          )}
                        </Cell>
                      </tr>
                    ))}
                </Table>
              ) : (
                <Empty>
                  {chosen ? `${chosen} matches its golden configuration.` : "Every device matches its golden configuration."}{" "}
                  {drift.data.devices.find((d) => d.device_id === chosen)?.notes.join(" ")}
                </Empty>
              )}
              {diff.data && diff.data.unified_diff.length ? (
                <pre className="scroll-thin max-h-[260px] overflow-auto rounded-[8px] bg-sunken p-3 font-mono text-[11.5px] leading-[1.55] shadow-[0_0_0_1px_var(--line-soft)]">
                  {diff.data.unified_diff.map((line, index) => (
                    <div key={index} className={cn(line.startsWith("+") && !line.startsWith("+++") ? "text-green" : line.startsWith("-") && !line.startsWith("---") ? "text-red" : "text-ink-3")}>
                      {line}
                    </div>
                  ))}
                </pre>
              ) : null}
            </div>
          </div>
        ) : null}
        <div className="mt-2">
          {drift.data ? <SourceNote>{`${drift.data.source}. Nothing is pushed to any device.`}</SourceNote> : null}
        </div>
      </Panel>

      <Panel title="Topology discovery" aside={discovery.data ? `${discovery.data.coverage_percent}% of documented links confirmed` : null}>
        {discovery.isPending ? <Skeleton className="h-32" /> : null}
        {discovery.isError ? <ErrorNote message={describeError(discovery.error)} onRetry={() => discovery.refetch()} /> : null}
        {discovery.data ? (
          <div className="grid gap-4 md:grid-cols-3">
            <div>
              <h4 className="text-[12.5px] font-medium text-ink-2">Missing adjacencies ({discovery.data.missing.length})</h4>
              {discovery.data.missing.length ? (
                <ul className="mt-1.5 space-y-1.5 text-[12px]">
                  {discovery.data.missing.map((m) => (
                    <li key={m.link_id}>
                      <span className="font-mono text-red">{m.link_id}</span>
                      <div className="text-ink-3">{m.reason}</div>
                    </li>
                  ))}
                </ul>
              ) : (
                <Empty>Every documented link was seen.</Empty>
              )}
            </div>
            <div>
              <h4 className="text-[12.5px] font-medium text-ink-2">Not in inventory ({discovery.data.unexpected.length})</h4>
              {discovery.data.unexpected.length ? (
                <ul className="mt-1.5 space-y-1.5 text-[12px]">
                  {discovery.data.unexpected.map((u) => (
                    <li key={`${u.local_device_id}${u.local_port}`}>
                      <span className="font-mono text-amber">{u.remote_system}</span> on {u.local_device_id} {u.local_port}
                      <div className="text-ink-3">
                        {u.capabilities}
                        {u.remote_management ? ` · ${u.remote_management}` : ""}
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <Empty>No undocumented neighbours.</Empty>
              )}
            </div>
            <div>
              <h4 className="text-[12.5px] font-medium text-ink-2">Changed since baseline ({discovery.data.changes_since_baseline.length})</h4>
              {discovery.data.changes_since_baseline.length ? (
                <ul className="mt-1.5 space-y-1 text-[12px] text-ink-2">
                  {discovery.data.changes_since_baseline.map((c) => (
                    <li key={c.link_id}>
                      <span className="font-mono">{c.link_id}</span> {c.change.replaceAll("_", " ")}
                    </li>
                  ))}
                </ul>
              ) : (
                <Empty>Same adjacencies as the healthy baseline.</Empty>
              )}
            </div>
          </div>
        ) : null}
        <div className="mt-2">
          {discovery.data ? <SourceNote>{`${discovery.data.source}.`}</SourceNote> : null}
        </div>
      </Panel>
    </div>
  );
}

export function DependenciesPanel({ scenario }: { scenario: string }) {
  const graph = useDependencies(scenario);
  const [focus, setFocus] = useState<string | null>(null);
  if (graph.isPending) return <Skeleton className="h-72" />;
  if (graph.isError) return <ErrorNote message={describeError(graph.error)} onRetry={() => graph.refetch()} />;
  const data = graph.data!;
  const spof = new Map(data.single_points_of_failure.map((s) => [s.id, s]));
  const chosen = focus ?? data.criticality[0]?.id ?? null;
  const observed = data.edges.filter((e) => e.kind === "observed_traffic");
  const max = Math.max(1, ...data.criticality.map((c) => c.services));

  return (
    <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <Panel title="Dependency criticality" aside="Site services that traverse each device">
        <ul className="space-y-[2px]">
          {data.criticality.map((row) => (
            <li key={row.id}>
              <button
                type="button"
                onClick={() => setFocus(row.id)}
                className={cn("grid w-full grid-cols-[150px_1fr_auto] items-center gap-3 rounded-[6px] px-1.5 py-[5px] text-left hover:bg-hover", chosen === row.id && "bg-selected")}
              >
                <span className="truncate font-mono text-[12px] text-ink-2">{row.id}</span>
                <span className="h-2 rounded-r-[4px] bg-chart" style={{ width: `${Math.max(3, (row.services / max) * 100)}%` }} />
                <span className="flex items-center gap-1.5 font-mono text-[11.5px] text-ink-3">
                  {row.services}
                  {spof.has(row.id) ? <Pill tone="amber">SPOF</Pill> : null}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </Panel>
      <div className="space-y-3">
        <Panel title={chosen ? `Blast radius: ${chosen}` : "Blast radius"}>
          {chosen ? (
            <div className="space-y-2 text-[12.5px]">
              <p className="text-ink-2">
                {spof.get(chosen)?.services_at_risk.length
                  ? `If ${chosen} fails, ${spof.get(chosen)!.services_at_risk.length} site services lose their only path:`
                  : `${chosen} has an alternative path for every service that crosses it.`}
              </p>
              <div className="flex flex-wrap gap-1.5">
                {(spof.get(chosen)?.services_at_risk ?? []).map((service) => (
                  <Pill key={service} tone="red">
                    {service}
                  </Pill>
                ))}
              </div>
            </div>
          ) : null}
        </Panel>
        <Panel title="Single points of failure" aside={`${data.single_points_of_failure.length} nodes and links`}>
          <ul className="space-y-1 text-[12.5px]">
            {data.single_points_of_failure.slice(0, 10).map((row) => (
              <li key={row.id} className="flex items-center gap-2">
                <Dot tone={row.impact >= 10 ? "red" : "amber"} />
                <button type="button" className="font-mono text-ink-2 hover:underline" onClick={() => setFocus(row.id)}>
                  {row.id}
                </button>
                <span className="text-ink-4">{row.kind}</span>
                <span className="ml-auto font-mono text-ink-3">{row.impact}</span>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Observed in flows" aside="Dependencies confirmed by traffic in this window">
          <Table head={["Site", "Service", "Flows", "Dropped"]} minWidth={320}>
            {observed.map((edge) => (
              <tr key={`${edge.source}${edge.target}`}>
                <Cell>{edge.source}</Cell>
                <Cell>{edge.target.replace("service:", "")}</Cell>
                <Cell mono>{edge.flows}</Cell>
                <Cell mono className={edge.dropped ? "text-red" : undefined}>
                  {edge.dropped}
                </Cell>
              </tr>
            ))}
          </Table>
        </Panel>
      </div>
    </div>
  );
}
