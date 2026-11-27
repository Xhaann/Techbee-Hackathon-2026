"use client";

// Protocol and security intelligence (/api/v1/protocols). The report is computed in code from synthetic telemetry; its
// shape is typed here, like the other analytics summaries.
import { useMutation, useQuery } from "@tanstack/react-query";
import type { ProtocolFinding } from "@/components/protocols/findings";
import { get, post } from "./client";

export type EngineName =
  | "bgp" | "ospf" | "stp" | "arp" | "vlan" | "nat" | "ipsec" | "tcp" | "mtu" | "qos" | "ipv6" | "wireless" | "multicast" | "tls"
  | "threats" | "traffic" | "lateral";

export type EngineInfo = { name: EngineName; feature: number; title: string; specialist: string; category: "protocol" | "security"; checks: string };
export type ProtocolScenario = {
  scenario_id: string;
  name: string;
  description: string;
  kind: "normal" | "failure" | "edge" | "adversarial";
  features: string[];
  incident_title: string | null;
  site_ids: string[];
};
export type EngineCatalog = { synthetic: true; engines: EngineInfo[]; scenarios: ProtocolScenario[] };

export type ReportFinding = Omit<ProtocolFinding, "correlations"> & { correlations: { kind: string; detail: string }[]; layer: string };
export type ProtocolReport = {
  scenario_id: string;
  synthetic: true;
  data_source: string;
  scope: { site_id: string | null; device_id: string | null };
  engines: { engine: EngineName; feature: number; title: string; specialist: string; status: string; checked: string[]; notes: string[]; missing: string[]; finding_ids: string[] }[];
  findings: ReportFinding[];
  counts: Record<string, number>;
  headline: string;
  root_causes: string[];
  causal_edges: { cause: string; effect: string; mechanism: string; reason: string }[];
  causal_chain: string[];
  hypotheses: { domain: string; label: string; probability: number; shown: string }[];
  uncertainty: string;
  threats: string[];
  notes: string[];
  missing: string[];
  next_checks: { engine: EngineName; title: string; reason: string }[];
  related_incidents: { incident_id: string; title: string; relation: string; score: number }[];
  validation: { grounded: boolean; references_checked: number; issues: string[] };
};

export type AnalyzeRequest = { scenario_id?: string; incident_id?: string; engines: EngineName[]; site_id?: string | null; symptoms?: string };

export const protocols = {
  catalog: () => get<EngineCatalog>("/protocols/engines"),
  analyze: (body: AnalyzeRequest) => post<ProtocolReport>("/protocols/analyze", body),
};

export const useProtocolCatalog = () => useQuery({ queryKey: ["protocols", "catalog"], queryFn: protocols.catalog, staleTime: 5 * 60_000 });
export const useProtocolAnalysis = () => useMutation({ mutationFn: protocols.analyze });
