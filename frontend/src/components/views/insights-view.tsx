"use client";

import { Building2, Router } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Topbar } from "@/components/shell/topbar";
import { Dot, ErrorNote, Pill, Skeleton } from "@/components/ui/atoms";
import { StatBar } from "@/components/ui/charts";
import { ALL, SelectBox } from "@/components/ui/fields";
import { Modal } from "@/components/ui/modal";
import { describeError } from "@/lib/api/client";
import {
  useActiveIncidents,
  useDevice,
  useDevices,
  useIncident,
  useInterfaces,
  useLinks,
  useNetworkHealth,
  useServicePaths,
  useSiteTopology,
  useTopology,
} from "@/lib/api/hooks";
import type { DeviceType, PathService } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { DEVICE_TYPE_LABEL, ROLE_LABEL, SERVICE_LABEL } from "@/lib/labels";
import { SCENARIOS, scenarioById } from "@/lib/scenarios";

type SiteData = {
  dependencies?: Record<string, { upstream: string[]; downstream: string[]; depends_on: string[] }>;
  external_dependencies?: string[];
  shared_infrastructure?: { device_id: string; site_id: string; path_ids: string[]; sites_using: string[] }[];
  paths?: { path_id: string; name: string; service: string }[];
};

export function InsightsView() {
  const topology = useTopology();
  const active = useActiveIncidents();
  const latest = [...(active.data?.items ?? [])].sort((a, b) => b.updated_at.localeCompare(a.updated_at))[0];
  const latestIncident = useIncident(latest?.incident_id ?? null);
  const [chosen, setChosen] = useState<string | null>(null);
  const scenario = chosen ?? latestIncident.data?.dataset_scenario_id ?? "BASELINE";
  const health = useNetworkHealth(scenario);

  const [siteFilter, setSiteFilter] = useState<string>(ALL);
  const [typeFilter, setTypeFilter] = useState<DeviceType | typeof ALL>(ALL);
  const devices = useDevices({ site_id: siteFilter === ALL ? undefined : siteFilter, device_type: typeFilter === ALL ? undefined : typeFilter });
  const wan = useLinks();
  const [serviceFilter, setServiceFilter] = useState<PathService | typeof ALL>(ALL);
  const paths = useServicePaths({ site_id: siteFilter === ALL ? undefined : siteFilter, service: serviceFilter === ALL ? undefined : serviceFilter });

  const [device, setDevice] = useState<string | null>(null);
  const [site, setSite] = useState<string | null>(null);

  // Deep link from the command palette: /insights?device=NYC-RTR-01
  useEffect(() => {
    const requested = new URLSearchParams(window.location.search).get("device");
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (requested) setDevice(requested);
  }, []);

  const healthById = useMemo(() => new Map((health.data?.devices ?? []).map((d) => [d.device_id, d])), [health.data]);
  const unavailable = (health.data?.devices ?? []).filter((d) => d.status !== "available");
  const sites = topology.data?.sites ?? [];

  return (
    <>
      <Topbar crumbs={[{ label: "Network insights" }]} />
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[1120px] space-y-6 px-5 pt-6 pb-16 md:px-8">
          <div className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <h1 className="text-[24px] font-semibold tracking-[-0.03em] text-ink">Device availability</h1>
              <p className="mt-1 text-[13px] text-ink-3">{scenarioById(scenario)?.summary ?? "Synthetic telemetry"}</p>
            </div>
            <SelectBox
              ariaLabel="Telemetry dataset"
              className="w-[260px]"
              value={scenario}
              onValueChange={setChosen}
              options={SCENARIOS.map((s) => ({ value: s.id, label: s.name }))}
            />
          </div>

          <StatBar
            loading={health.isPending}
            stats={[
              { key: "devices", label: "Devices checked", value: health.data?.device_count },
              { key: "available", label: "Available", value: health.data?.status_counts.available ?? (health.data ? 0 : undefined), tone: "green" },
              { key: "down", label: "Not available", value: health.data ? unavailable.length : undefined, tone: "red" },
              { key: "sites", label: "Sites", value: topology.data?.sites.length },
              { key: "wan", label: "WAN circuits", value: topology.data ? topology.data.links.filter((l) => l.link_type === "wan").length : undefined },
            ]}
          />
          {health.isError ? <ErrorNote message={describeError(health.error)} onRetry={() => health.refetch()} /> : null}

          <section aria-labelledby="sites-heading">
            <h2 id="sites-heading" className="text-[15px] font-semibold tracking-[-0.015em] text-ink">
              Sites
            </h2>
            <ul className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
              {sites.map((s) => {
                const counts = health.data?.sites[s.site_id] ?? {};
                const total = Object.values(counts).reduce((a, b) => a + b, 0);
                const down = total - (counts.available ?? 0);
                return (
                  <li key={s.site_id}>
                    <button type="button" onClick={() => setSite(s.site_id)} className="card flex w-full flex-col items-start px-3.5 py-3 text-left hover:bg-hover">
                      <span className="flex w-full items-center gap-2">
                        <Building2 className="size-4 text-ink-3" aria-hidden />
                        <span className="truncate text-[13.5px] font-medium text-ink">{s.city}</span>
                        <span className="ml-auto font-mono text-[11px] text-ink-4">{s.site_id}</span>
                      </span>
                      <span className={cn("mt-2 inline-flex items-center gap-1.5 text-[12px]", down ? "text-red" : "text-green")}>
                        <Dot tone={down ? "red" : "green"} />
                        {health.data ? (down ? `${down} of ${total} not available` : `${total} of ${total} available`) : "Checking"}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </section>

          <section aria-labelledby="devices-heading">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 id="devices-heading" className="text-[15px] font-semibold tracking-[-0.015em] text-ink">
                Devices
              </h2>
              <div className="flex gap-2">
                <SelectBox
                  size="sm"
                  ariaLabel="Site"
                  className="w-[170px]"
                  value={siteFilter}
                  onValueChange={setSiteFilter}
                  options={[{ value: ALL, label: "All sites" }, ...sites.map((s) => ({ value: s.site_id, label: s.name }))]}
                />
                <SelectBox
                  size="sm"
                  ariaLabel="Device type"
                  className="w-[140px]"
                  value={typeFilter}
                  onValueChange={setTypeFilter}
                  options={[{ value: ALL, label: "All types" }, ...(Object.keys(DEVICE_TYPE_LABEL) as DeviceType[]).map((t) => ({ value: t, label: DEVICE_TYPE_LABEL[t] }))]}
                />
              </div>
            </div>
            {devices.isPending ? (
              <Skeleton className="mt-3 h-40" />
            ) : devices.isError ? (
              <div className="mt-3">
                <ErrorNote message={describeError(devices.error)} onRetry={() => devices.refetch()} />
              </div>
            ) : (
              <div className="card mt-3 overflow-x-auto">
                <table className="w-full min-w-[760px] text-left text-[13px]">
                  <thead>
                    <tr className="text-[12px] text-ink-3 shadow-[inset_0_-1px_0_var(--line-soft)]">
                      <th className="px-4 py-2.5 font-normal">Device</th>
                      <th className="px-3 py-2.5 font-normal">Role</th>
                      <th className="px-3 py-2.5 font-normal">Platform</th>
                      <th className="px-3 py-2.5 font-normal">Management IP</th>
                      <th className="px-4 py-2.5 font-normal">Availability</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line-soft">
                    {(devices.data?.items ?? []).map((d) => {
                      const h = healthById.get(d.device_id);
                      const ok = h?.status === "available";
                      return (
                        <tr key={d.device_id} className="hover:bg-hover">
                          <td className="px-4 py-2.5">
                            <button type="button" onClick={() => setDevice(d.device_id)} className="font-mono text-[12.5px] text-ink hover:underline">
                              {d.device_id}
                            </button>
                          </td>
                          <td className="px-3 py-2.5 text-ink-2">{ROLE_LABEL[d.role]}</td>
                          <td className="px-3 py-2.5 text-ink-2">
                            {d.vendor} {d.model}
                          </td>
                          <td className="px-3 py-2.5 font-mono text-[12px] text-ink-3">{d.management_ip}</td>
                          <td className="px-4 py-2.5">
                            {h ? (
                              <span className={cn("inline-flex items-center gap-1.5", ok ? "text-green" : "text-red")}>
                                <Dot tone={ok ? "green" : "red"} />
                                {ok ? "Available" : h.status.replaceAll("_", " ")}
                                {h.finding_codes.length ? <span className="font-mono text-[11px] text-ink-3">{h.finding_codes.join(", ")}</span> : null}
                              </span>
                            ) : (
                              <span className="text-ink-4">{health.isPending ? "Checking" : "Not checked"}</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <div className="grid gap-6 lg:grid-cols-2">
            <section aria-labelledby="links-heading">
              <h2 id="links-heading" className="text-[15px] font-semibold tracking-[-0.015em] text-ink">
                WAN and metro circuits
              </h2>
              {wan.isPending ? (
                <Skeleton className="mt-3 h-32" />
              ) : (
                <ul className="card mt-3 divide-y divide-line-soft">
                  {(wan.data?.items ?? [])
                    .filter((l) => l.link_type !== "lan")
                    .map((link) => (
                      <li key={link.link_id} className="flex items-center gap-3 px-4 py-2.5">
                        <span className="min-w-0 flex-1">
                          <span className="block font-mono text-[12.5px] text-ink">{link.link_id}</span>
                          <span className="mt-0.5 block truncate text-[12px] text-ink-3">
                            {[link.provider, link.circuit_id].filter(Boolean).join(" · ") || link.link_type.toUpperCase()}
                          </span>
                        </span>
                        <span className="text-right text-[12px] text-ink-2 tabular-nums">
                          {link.bandwidth_mbps.toLocaleString()} Mbps
                          <span className="block text-ink-3">
                            {link.latency_ms} ms{link.routing_protocol ? ` · ${link.routing_protocol.toUpperCase()}` : ""}
                          </span>
                        </span>
                      </li>
                    ))}
                </ul>
              )}
            </section>

            <section aria-labelledby="paths-heading">
              <div className="flex items-center justify-between gap-3">
                <h2 id="paths-heading" className="text-[15px] font-semibold tracking-[-0.015em] text-ink">
                  Service paths
                </h2>
                <SelectBox
                  size="sm"
                  ariaLabel="Service"
                  className="w-[150px]"
                  value={serviceFilter}
                  onValueChange={setServiceFilter}
                  options={[{ value: ALL, label: "All services" }, ...(Object.keys(SERVICE_LABEL) as PathService[]).map((s) => ({ value: s, label: SERVICE_LABEL[s] }))]}
                />
              </div>
              {paths.isPending ? (
                <Skeleton className="mt-3 h-32" />
              ) : (
                <ul className="card scroll-thin mt-3 max-h-[360px] divide-y divide-line-soft overflow-y-auto">
                  {(paths.data?.items ?? []).map((path) => (
                    <li key={path.path_id} className="px-4 py-2.5">
                      <div className="flex items-center gap-2">
                        <span className="truncate text-[13px] text-ink">{path.name}</span>
                        <Pill className="ml-auto">{SERVICE_LABEL[path.service]}</Pill>
                      </div>
                      <div className="mt-1 truncate font-mono text-[11px] text-ink-3">{path.device_ids.join(" › ")}</div>
                    </li>
                  ))}
                  {!paths.data?.items.length ? <li className="px-4 py-5 text-center text-[12.5px] text-ink-3">No paths match.</li> : null}
                </ul>
              )}
            </section>
          </div>
        </div>
      </div>

      {device ? <DeviceDialog deviceId={device} onClose={() => setDevice(null)} status={healthById.get(device)?.status} /> : null}
      {site ? <SiteDialog siteId={site} onClose={() => setSite(null)} /> : null}
    </>
  );
}

function DeviceDialog({ deviceId, onClose, status }: { deviceId: string; onClose: () => void; status?: string }) {
  const device = useDevice(deviceId);
  const interfaces = useInterfaces(deviceId);
  const d = device.data;
  return (
    <Modal open onOpenChange={(open) => !open && onClose()} title={deviceId} description={d ? `${ROLE_LABEL[d.role]} at ${d.site_id} · ${d.vendor} ${d.model}` : undefined} width={620}>
      {device.isPending ? (
        <Skeleton className="h-32" />
      ) : device.isError ? (
        <ErrorNote message={describeError(device.error)} />
      ) : d ? (
        <div className="space-y-4">
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2.5 text-[12.5px] sm:grid-cols-3">
            {[
              ["Hostname", d.hostname],
              ["OS", d.os_version],
              ["Management IP", d.management_ip],
              ["Router ID", d.router_id ?? "None"],
              ["BGP ASN", d.bgp_asn ? String(d.bgp_asn) : "None"],
              ["Availability", status ?? "Not checked"],
            ].map(([label, value]) => (
              <div key={label}>
                <dt className="text-ink-3">{label}</dt>
                <dd className="mt-0.5 font-mono text-[12px] text-ink-2">{value}</dd>
              </div>
            ))}
          </dl>
          <div>
            <h3 className="flex items-center gap-2 text-[13px] font-medium text-ink-2">
              <Router className="size-3.5 text-ink-3" aria-hidden />
              Interfaces
            </h3>
            {interfaces.isPending ? (
              <Skeleton className="mt-2 h-20" />
            ) : (
              <ul className="mt-2 divide-y divide-line-soft rounded-[8px] shadow-[var(--ring-card)]">
                {(interfaces.data?.items ?? []).map((i) => (
                  <li key={i.interface_id} className="flex items-center gap-3 px-3 py-2 text-[12.5px]">
                    <span className="w-[86px] shrink-0 font-mono text-ink">{i.name}</span>
                    <span className="min-w-0 flex-1 truncate text-ink-3">{i.description}</span>
                    <span className="shrink-0 font-mono text-[11px] text-ink-3">{i.ip_address ?? i.mode}</span>
                    <span className="shrink-0 text-[11.5px] text-ink-4 tabular-nums">{i.speed_mbps.toLocaleString()} Mbps</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      ) : null}
    </Modal>
  );
}

function SiteDialog({ siteId, onClose }: { siteId: string; onClose: () => void }) {
  const site = useSiteTopology(siteId);
  const data = (site.data?.data ?? {}) as SiteData & { site?: { name: string; city: string; country: string } };
  return (
    <Modal
      open
      onOpenChange={(open) => !open && onClose()}
      title={data.site?.name ?? siteId}
      description={data.site ? `${data.site.city}, ${data.site.country}` : undefined}
      width={640}
    >
      {site.isPending ? (
        <Skeleton className="h-40" />
      ) : site.isError ? (
        <ErrorNote message={describeError(site.error)} />
      ) : (
        <div className="space-y-4 text-[12.5px]">
          <section>
            <h3 className="text-[13px] font-medium text-ink-2">Depends on outside this site</h3>
            <p className="mt-1 font-mono text-[12px] text-ink-3">{(data.external_dependencies ?? []).join(", ") || "Nothing"}</p>
          </section>
          <section>
            <h3 className="text-[13px] font-medium text-ink-2">Shared infrastructure on its paths</h3>
            <ul className="mt-1.5 space-y-1">
              {(data.shared_infrastructure ?? []).map((item) => (
                <li key={item.device_id} className="flex gap-3">
                  <span className="w-[120px] shrink-0 font-mono text-ink">{item.device_id}</span>
                  <span className="text-ink-3">
                    shared with {item.sites_using.filter((s) => s !== siteId).join(", ") || "no other site"} · {item.path_ids.length} paths
                  </span>
                </li>
              ))}
            </ul>
          </section>
          <section>
            <h3 className="text-[13px] font-medium text-ink-2">Devices and what they rely on</h3>
            <ul className="mt-1.5 space-y-1">
              {Object.entries(data.dependencies ?? {}).map(([id, dep]) => (
                <li key={id} className="flex gap-3">
                  <span className="w-[120px] shrink-0 font-mono text-ink">{id}</span>
                  <span className="text-ink-3">
                    upstream {dep.upstream.join(", ") || "none"} · needs {dep.depends_on.join(", ") || "nothing"}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        </div>
      )}
    </Modal>
  );
}
