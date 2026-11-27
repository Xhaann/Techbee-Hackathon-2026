"use client";

// Network intelligence and observability (/api/v1/observability). The backend returns computed summaries as JSON
// objects, so their shapes are typed here rather than in the generated schema.
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { get, openStream, readEvents, request } from "./client";

export type HealthStatus = "healthy" | "degraded" | "critical" | "unknown";
export type EvidenceRef = { collection: string; record_id: string; timestamp?: string };
export type Factor = { factor: string; penalty: number; detail: string; evidence: EvidenceRef[] };

export type HealthReport = {
  scenario_id: string;
  evaluated_at: string | null;
  method: string;
  network: { score: number | null; status: HealthStatus; worst_site: string };
  sites: {
    site_id: string;
    name: string;
    city: string;
    country: string;
    site_type: string;
    latitude: number;
    longitude: number;
    utc_offset_hours: number;
    score: number | null;
    status: HealthStatus;
    devices: number;
    critical_devices: number;
    degraded_devices: number;
    services: { service: string; score: number | null; status: HealthStatus; down_links: string[] }[];
    worst_device: string | null;
    notes: string[];
  }[];
  devices: {
    device_id: string;
    hostname: string;
    site_id: string;
    device_type: string;
    role: string;
    score: number;
    status: HealthStatus;
    confidence: string;
    factors: Factor[];
  }[];
  links: { link_id: string; link_type: string; endpoints: string[]; score: number | null; status: HealthStatus; factors: Factor[] }[];
  services: {
    path_id: string;
    site_id: string;
    service: string;
    score: number | null;
    status: HealthStatus;
    down_links: string[];
    journey: { verdict: string; hop: number; latency_ms: number };
    notes: string[];
    weakest: string;
  }[];
};

export type LiveTopology = {
  scenario_id: string;
  nodes: { id: string; label: string; site_id: string; device_type: string; role: string; x: number; y: number; score: number; status: HealthStatus; reasons: string[] }[];
  edges: {
    id: string;
    source: string;
    target: string;
    link_type: string;
    /** Interface name at each end, keyed by device id. */
    interfaces: Record<string, string>;
    bandwidth_mbps: number;
    provider: string | null;
    status: "up" | "down" | "unknown";
    utilization_percent: number | null;
    loss_percent: number | null;
    latency_ms: number | null;
    score: number | null;
    health: HealthStatus;
    /** "live" (simulator or ingested) or "scenario" (the dataset's latest sample). */
    data_source: "live" | "scenario";
    updated_at: string | null;
    flow_bytes: number;
  }[];
  sites: { site_id: string; name: string; city: string; score: number | null; status: HealthStatus; latitude: number; longitude: number }[];
  network: HealthReport["network"];
  cursor: number;
  generated_at: string;
};

export type TrafficSummary = {
  source: string;
  window: { start: string; onset: string; end: string };
  totals: { flows: number; bytes: number; dropped_flows: number; unanswered_flows: number };
  top_talkers: { key: string; bytes: number }[];
  top_destinations: { key: string; bytes: number }[];
  applications: { key: string; bytes: number }[];
  protocols: { key: string; bytes: number }[];
  matrix: { site_id: string; service: string; bytes: number; flows: number; dropped: number }[];
  sankey: { nodes: string[]; links: { source: string; target: string; bytes: number; flows: number; dropped: number }[] };
  dropped_by_policy: { device_id: string; service: string; flows: number; sources: string[]; first_seen: string; last_seen: string; rules: { rule_id: string; name: string | null }[] }[];
  traffic_shifts: { site_id: string; service: string; flows_per_minute_before: number; flows_per_minute_after: number; change: string }[];
  timeline: ({ minute: string } & Record<string, number | string>)[];
};

export type JourneyHop = {
  index: number;
  device_id: string;
  hostname: string;
  site_id: string;
  device_type: string;
  role: string;
  ingress_interface?: string;
  route?: { prefix: string; protocol: string; next_hop: string | null };
  policy?: { rule_id: string | null; name: string; action: string };
  egress?: { interface_id: string; link_id: string; link_type: string; status: string; mtu: number; utilization_percent: number | null; loss_percent: number | null; latency_ms: number; measured: boolean };
  cumulative_latency_ms: number;
};

export type Journey = {
  request: { source: string; destination: string; protocol: string; port: number | null; size_bytes: number };
  source: { device_id: string | null; address: string };
  destination: { device_id: string | null; address: string };
  verdict: "delivered" | "dropped_by_policy" | "link_down" | "no_route" | "leaves_network" | "indeterminate";
  verdict_text: string;
  verdict_hop: number;
  hops: JourneyHop[];
  total_latency_ms: number;
  path_mtu: number | null;
  mtu_note: string | null;
  observed_flows: { matching: number; forwarded: number; dropped: number; examples: string[] };
  notes: string[];
  limitations: string[];
  evaluated_at: string;
};

export type Forecast = {
  interface_id: string;
  device_id: string;
  site_id: string;
  link_id: string | null;
  status: string;
  method: string;
  trend_per_day: number | null;
  current_peak?: number;
  residual_sd?: number;
  observed: { day: string; peak: number; weekend: boolean }[];
  forecast: { day: string; peak: number; low: number; high: number; weekend: boolean }[];
  days_to: Record<"80" | "90", number | null> | null;
  next_24h: { timestamp: string; local_hour: number; expected: number; high: number }[];
  next_24h_peak?: { timestamp: string; local_hour: number; expected: number; high: number };
};

export type CongestionRow = {
  link_id: string;
  link_type: string;
  interfaces: string[];
  bandwidth_mbps: number;
  current_utilization: number | null;
  events: string[];
  level: "high" | "medium" | "low" | "unavailable" | "unknown";
  probability: number | null;
  drivers: string[];
  recommendation: string | null;
  interface_id?: string;
  days_to?: Record<"80" | "90", number | null>;
  trend_per_day?: number;
};

export type DriftReport = {
  source: string;
  summary: { devices: number; drifted: number; unverified: number; items: number; unattributed: number; by_severity: Record<string, number> };
  devices: { device_id: string; site_id: string; device_type: string; status: "compliant" | "drifted" | "unverified"; drift_items: number; highest_severity: string | null; unattributed: number; notes: string[] }[];
  items: { device_id: string; section: string; change: "added" | "removed"; line: string; category: string; severity: string; attributed: boolean; event_id: string | null; changed_at: string | null; changed_by: string | null; ticket: string | null }[];
};

export type ConfigDiff = { device_id: string; golden: string[]; running: string[]; unified_diff: string[] };

export type Discovery = {
  source: string;
  collected_at: string | null;
  neighbors: number;
  documented_links: number;
  coverage_percent: number;
  matched: { link_id: string; a: string; b: string; link_type: string }[];
  missing: { link_id: string; a: string; b: string; link_type: string; reason: string }[];
  one_sided: { link_id: string; a: string; b: string; seen_from: string }[];
  unexpected: { local_device_id: string; local_port: string; remote_system: string; remote_port: string; remote_management: string | null; capabilities: string; note: string }[];
  changes_since_baseline: { link_id: string; change: string }[];
};

export type Dependencies = {
  nodes: { id: string; kind: "site" | "device" | "service"; label: string; site_id?: string; device_type?: string; role?: string }[];
  edges: { source: string; target: string; kind: string; id: string | null; flows?: number; bytes?: number; dropped?: number }[];
  criticality: { id: string; label: string; site_id: string; services: number; dependents: string[] }[];
  single_points_of_failure: { id: string; kind: "device" | "link"; services_at_risk: string[]; impact: number }[];
  link_usage: Record<string, string[]>;
};

export type Sources = {
  modes: Record<string, string>;
  sources: { id: string; name: string; mode: string; detail: string; udp?: string; live_transport?: string; enabled?: boolean; running?: boolean }[];
  hub: { sequence: number; series: number; events_buffered: number; flows_buffered: number; subscribers: number; stats: Record<string, number>; limits: Record<string, number> };
};

export type SyslogReport = {
  total: number;
  templates_total: number;
  by_severity: Record<string, number>;
  formats: string[];
  templates: { template_id: string; template: string; count: number; devices: string[]; severity: number; mnemonic: string | null; first_seen: string; last_seen: string; rare: boolean }[];
  notable: SyslogReport["templates"];
  cross_device: SyslogReport["templates"];
  storms: { device_id: string; minute: string; messages: number }[];
  security_flags: string[];
  recent: { device_id: string; timestamp: string; severity: number; mnemonic: string | null; text: string }[];
  ingested: number;
};

export type TrapReport = {
  total: number;
  by_type: Record<string, number>;
  flaps: { device_id: string; interface: string | null; down_at: string; up_at: string; seconds: number }[];
  still_down: { device_id: string; interface: string | null; since: string }[];
  storms: { device_id: string; minute: string; traps: number }[];
  authentication_failures: number;
};

export type SnmpOverview = {
  devices: { device_id: string; polls: number; interfaces: number; down: number; wraps_handled: number; discontinuities: number; notes: string[] }[];
};

export type Baselines = {
  items: { interface_id: string; device_id: string; site_id: string; link_id: string | null; window_status: string; anomalies: { metric: string; kind: string; value: number | string | null; expected: number | string; first_seen: string; points: number }[]; current: Record<string, { value: number; expected: number; band: [number, number]; within_band: boolean }> }[];
  anomalous: number;
};

export type Reliability = {
  scenario_id: string;
  period: "7d" | "14d";
  period_start: string;
  period_end: string;
  source: string;
  method: string;
  summary: { links: number; services: number; breaches: string[]; worst_link: string | null; total_outages: number };
  links: { link_id: string; link_type: string; provider: string | null; circuit_id: string | null; availability_percent: number | null; coverage_percent: number; outages: number; mtbf_hours: number | null; mttr_minutes: number | null; sla_target_percent: number; sla_met: boolean | null; error_budget_used_percent: number | null; down_minutes: number }[];
  services: { path_id: string; site_id: string; service: string; availability_percent: number | null; outages: number; sla_met: boolean | null; sla_target_percent: number }[];
  sites: { site_id: string; name: string; services: number; availability_percent: number | null; outages: number; sla_met: boolean }[];
};

export type LiveSample = { s: number; d: string; i: string | null; m: string; t: string; v: number };
export type LiveMessage =
  | { type: "hello"; cursor: number; simulator: boolean; interval_seconds: number }
  | { type: "metrics"; namespace: string; samples: LiveSample[] }
  | { type: "event"; sequence: number; event: { device_id: string; event_type: string; message: string; severity: number; timestamp: string } }
  | { type: "flows"; count: number; bytes: number }
  | { type: "heartbeat"; cursor: number; dropped: number }
  | { type: "end"; cursor: number; dropped: number }
  | { type: "error"; code: string; message: string };

const base = "/observability";
const scenarioQuery = (scenario: string, extra: Record<string, string | number | undefined> = {}) => ({ query: { scenario_id: scenario, ...extra } });

export const observability = {
  sources: () => get<Sources>(`${base}/sources`),
  health: (scenario: string) => get<HealthReport>(`${base}/health`, scenarioQuery(scenario)),
  liveTopology: (scenario: string) => get<LiveTopology>(`${base}/topology/live`, scenarioQuery(scenario)),
  traffic: (scenario: string, site?: string) => get<TrafficSummary>(`${base}/traffic`, scenarioQuery(scenario, { site_id: site })),
  journey: (scenario: string, params: { source: string; destination: string; protocol: string; port?: number }) =>
    get<Journey>(`${base}/journey`, scenarioQuery(scenario, params)),
  forecast: (scenario: string, interfaceId: string) => get<Forecast>(`${base}/forecast`, scenarioQuery(scenario, { interface_id: interfaceId })),
  forecasts: (scenario: string) => get<{ items: Forecast[] }>(`${base}/forecast`, scenarioQuery(scenario)),
  congestion: (scenario: string) => get<{ items: CongestionRow[]; summary: Record<string, number> }>(`${base}/congestion`, scenarioQuery(scenario)),
  drift: (scenario: string) => get<DriftReport>(`${base}/drift`, scenarioQuery(scenario)),
  diff: (scenario: string, device: string) => get<ConfigDiff>(`${base}/drift/${encodeURIComponent(device)}/diff`, scenarioQuery(scenario)),
  discovery: (scenario: string) => get<Discovery>(`${base}/discovery`, scenarioQuery(scenario)),
  dependencies: (scenario: string) => get<Dependencies>(`${base}/dependencies`, scenarioQuery(scenario)),
  syslog: (scenario: string) => get<SyslogReport>(`${base}/syslog`, scenarioQuery(scenario)),
  traps: (scenario: string) => get<TrapReport>(`${base}/traps`, scenarioQuery(scenario)),
  snmp: (scenario: string) => get<SnmpOverview>(`${base}/snmp`, scenarioQuery(scenario)),
  baselines: (scenario: string) => get<Baselines>(`${base}/baselines`, scenarioQuery(scenario)),
  reliability: (scenario: string, period: "7d" | "14d") => get<Reliability>(`${base}/reliability`, scenarioQuery(scenario, { period })),
  /** The markdown or CSV export, as text, sent with the session's bearer token. */
  reliabilityExport: async (scenario: string, period: "7d" | "14d", format: "markdown" | "csv") => {
    // The export answers with text/markdown or text/csv; openStream sends the bearer token and returns the raw response.
    const response = await openStream("GET", `${base}/reliability`, { query: { scenario_id: scenario, period, format } });
    return response.text();
  },
};

const scenarioKey = (name: string, scenario: string, ...rest: unknown[]) => ["observability", name, scenario, ...rest] as const;
const STEADY = { staleTime: 60_000, placeholderData: keepPreviousData } as const;

export const useObsHealth = (scenario: string) => useQuery({ queryKey: scenarioKey("health", scenario), queryFn: () => observability.health(scenario), ...STEADY });
export const useLiveTopology = (scenario: string) =>
  useQuery({ queryKey: scenarioKey("topology", scenario), queryFn: () => observability.liveTopology(scenario), refetchInterval: 20_000, placeholderData: keepPreviousData });
export const useTraffic = (scenario: string, site?: string) =>
  useQuery({ queryKey: scenarioKey("traffic", scenario, site ?? "all"), queryFn: () => observability.traffic(scenario, site), ...STEADY });
export const useForecasts = (scenario: string) => useQuery({ queryKey: scenarioKey("forecasts", scenario), queryFn: () => observability.forecasts(scenario), ...STEADY });
export const useForecast = (scenario: string, interfaceId: string | null) =>
  useQuery({ queryKey: scenarioKey("forecast", scenario, interfaceId), queryFn: () => observability.forecast(scenario, interfaceId!), enabled: !!interfaceId, ...STEADY });
export const useCongestion = (scenario: string) => useQuery({ queryKey: scenarioKey("congestion", scenario), queryFn: () => observability.congestion(scenario), ...STEADY });
export const useDrift = (scenario: string) => useQuery({ queryKey: scenarioKey("drift", scenario), queryFn: () => observability.drift(scenario), ...STEADY });
export const useConfigDiff = (scenario: string, device: string | null) =>
  useQuery({ queryKey: scenarioKey("diff", scenario, device), queryFn: () => observability.diff(scenario, device!), enabled: !!device, ...STEADY });
export const useDiscovery = (scenario: string) => useQuery({ queryKey: scenarioKey("discovery", scenario), queryFn: () => observability.discovery(scenario), ...STEADY });
export const useDependencies = (scenario: string) =>
  useQuery({ queryKey: scenarioKey("dependencies", scenario), queryFn: () => observability.dependencies(scenario), ...STEADY });
export const useSyslog = (scenario: string) => useQuery({ queryKey: scenarioKey("syslog", scenario), queryFn: () => observability.syslog(scenario), ...STEADY });
export const useTraps = (scenario: string) => useQuery({ queryKey: scenarioKey("traps", scenario), queryFn: () => observability.traps(scenario), ...STEADY });
export const useSnmp = (scenario: string) => useQuery({ queryKey: scenarioKey("snmp", scenario), queryFn: () => observability.snmp(scenario), ...STEADY });
export const useBaselines = (scenario: string) => useQuery({ queryKey: scenarioKey("baselines", scenario), queryFn: () => observability.baselines(scenario), ...STEADY });
export const useSources = () => useQuery({ queryKey: ["observability", "sources"], queryFn: observability.sources, refetchInterval: 30_000 });
export const useReliability = (scenario: string, period: "7d" | "14d") =>
  useQuery({ queryKey: scenarioKey("reliability", scenario, period), queryFn: () => observability.reliability(scenario, period), ...STEADY });
export const useJourney = (scenario: string, params: { source: string; destination: string; protocol: string; port?: number } | null) =>
  useQuery({
    queryKey: scenarioKey("journey", scenario, params),
    queryFn: () => observability.journey(scenario, params!),
    enabled: !!params,
    retry: false,
    ...STEADY,
  });

export type LiveState = {
  status: "connecting" | "live" | "reconnecting" | "offline";
  /** Latest value per "device|interface|metric". */
  latest: Map<string, { t: string; v: number }>;
  /** Recent values for sparklines, bounded per key. */
  recent: Map<string, number[]>;
  messages: number;
  dropped: number;
  lastEventAt: string | null;
  events: { device_id: string; event_type: string; message: string; timestamp: string }[];
};

const RECENT_POINTS = 60;
const MAX_EVENTS = 30;

/**
 * Subscribes to /observability/stream for a scenario. The stream closes on the server after a few minutes and is
 * reopened here with a short back-off; state is bounded (a fixed number of points per series and events).
 */
export function useLiveStream(scenario: string, enabled = true): LiveState {
  const [state, setState] = useState<LiveState>(() => ({ status: "connecting", latest: new Map(), recent: new Map(), messages: 0, dropped: 0, lastEventAt: null, events: [] }));
  const generation = useRef(0);

  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    const mine = ++generation.current;
    let attempt = 0;
    const latest = new Map<string, { t: string; v: number }>();
    const recent = new Map<string, number[]>();
    let events: LiveState["events"] = [];
    let messages = 0;
    let dropped = 0;
    let lastEventAt: string | null = null;
    let pending = false;

    const publish = (status: LiveState["status"]) => {
      if (generation.current !== mine) return;
      setState({ status, latest: new Map(latest), recent: new Map(recent), messages, dropped, lastEventAt, events: [...events] });
    };
    const schedule = () => {
      // Coalesce bursts of frames into one render per animation frame.
      if (pending) return;
      pending = true;
      requestAnimationFrame(() => {
        pending = false;
        publish("live");
      });
    };

    const run = async () => {
      while (!controller.signal.aborted) {
        try {
          const response = await openStream("GET", `${base}/stream`, { query: { scenario_id: scenario }, signal: controller.signal });
          attempt = 0;
          publish("live");
          await readEvents<LiveMessage>(response, (message) => {
            messages += 1;
            if (message.type === "metrics") {
              for (const sample of message.samples) {
                const key = `${sample.d}|${sample.i ?? "-"}|${sample.m}`;
                latest.set(key, { t: sample.t, v: sample.v });
                const series = recent.get(key) ?? [];
                series.push(sample.v);
                if (series.length > RECENT_POINTS) series.splice(0, series.length - RECENT_POINTS);
                recent.set(key, series);
                lastEventAt = sample.t;
              }
            } else if (message.type === "event") {
              events = [{ ...message.event }, ...events].slice(0, MAX_EVENTS);
            } else if (message.type === "heartbeat" || message.type === "end") {
              dropped = message.dropped;
            }
            schedule();
          });
        } catch (error) {
          if ((error as Error).name === "AbortError") return;
        }
        if (controller.signal.aborted) return;
        attempt += 1;
        publish(attempt > 3 ? "offline" : "reconnecting");
        await new Promise((resolve) => setTimeout(resolve, Math.min(15_000, 1_000 * 2 ** Math.min(attempt, 4))));
      }
    };
    void run();
    return () => controller.abort();
  }, [scenario, enabled]);

  return state;
}

export async function downloadReliability(scenario: string, period: "7d" | "14d", format: "json" | "markdown" | "csv") {
  const text =
    format === "json"
      ? JSON.stringify(await request<Reliability>("GET", `${base}/reliability`, { query: { scenario_id: scenario, period } }), null, 2)
      : await observability.reliabilityExport(scenario, period, format);
  const type = { json: "application/json", markdown: "text/markdown", csv: "text/csv" }[format];
  const extension = { json: "json", markdown: "md", csv: "csv" }[format];
  const url = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `reliability-${scenario}-${period}.${extension}`;
  anchor.click();
  URL.revokeObjectURL(url);
}
