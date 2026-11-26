"use client";

import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from "@tanstack/react-query";
import { isApiError } from "./client";
import { api } from "./endpoints";
import type {
  AgentDiagnoseBody,
  DeviceType,
  DiagnosisRequest,
  EscalationBody,
  EscalationUpdateBody,
  FaultDomain,
  Incident,
  IncidentCreateBody,
  IncidentFilters,
  IncidentPatchBody,
  KnowledgeCategory,
  LinkType,
  PathService,
  ResolutionBody,
} from "./types";

const STATIC = { staleTime: Infinity, gcTime: Infinity } as const;

export const keys = {
  health: (base: string) => ["health", base] as const,
  dashboardSummary: ["dashboard", "summary"] as const,
  dashboardIncidents: ["dashboard", "incidents"] as const,
  networkHealth: (scenario: string) => ["network-health", scenario] as const,
  topology: ["topology"] as const,
  site: (siteId: string) => ["topology", "site", siteId] as const,
  devices: (filters: object) => ["topology", "devices", filters] as const,
  device: (deviceId: string) => ["topology", "device", deviceId] as const,
  interfaces: (deviceId: string) => ["topology", "interfaces", deviceId] as const,
  links: (type?: string) => ["topology", "links", type ?? "all"] as const,
  services: (filters: object) => ["topology", "services", filters] as const,
  incidents: (filters: object) => ["incidents", filters] as const,
  incident: (id: string) => ["incident", id] as const,
  timeline: (id: string) => ["incident", id, "timeline"] as const,
  incidentEvidence: (id: string) => ["incident", id, "evidence"] as const,
  escalations: (id: string) => ["incident", id, "escalations"] as const,
  diagnosis: (id: string) => ["diagnosis", id] as const,
  diagnosisEvidence: (id: string) => ["diagnosis", id, "evidence"] as const,
  advanced: (incidentId: string, diagnosisId: string | null | undefined) => ["advanced", incidentId, diagnosisId ?? "none"] as const,
  knowledge: (...parts: unknown[]) => ["knowledge", ...parts] as const,
  reports: (...parts: unknown[]) => ["reports", ...parts] as const,
};

// ---------- Reads ----------

export const useHealth = (base: string) =>
  useQuery({
    queryKey: keys.health(base),
    queryFn: () => api.health(base),
    refetchInterval: 60_000,
    retry: false,
    staleTime: 30_000,
  });

export const useDashboardSummary = () => useQuery({ queryKey: keys.dashboardSummary, queryFn: api.dashboard.summary });

export const useActiveIncidents = () =>
  useQuery({ queryKey: keys.dashboardIncidents, queryFn: () => api.dashboard.incidents({ limit: 100 }) });

export const useNetworkHealth = (scenario: string | null | undefined) =>
  useQuery({
    queryKey: keys.networkHealth(scenario ?? ""),
    queryFn: () => api.dashboard.networkHealth(scenario!),
    enabled: !!scenario,
    ...STATIC,
  });

export const useTopology = () => useQuery({ queryKey: keys.topology, queryFn: api.topology.all, ...STATIC });

export const useSiteTopology = (siteId: string | null) =>
  useQuery({ queryKey: keys.site(siteId ?? ""), queryFn: () => api.topology.site(siteId!), enabled: !!siteId, ...STATIC });

export const useDevices = (filters: { site_id?: string; device_type?: DeviceType }) =>
  useQuery({ queryKey: keys.devices(filters), queryFn: () => api.topology.devices({ limit: 100, ...filters }), ...STATIC });

export const useDevice = (deviceId: string | null) =>
  useQuery({ queryKey: keys.device(deviceId ?? ""), queryFn: () => api.topology.device(deviceId!), enabled: !!deviceId, ...STATIC });

export const useInterfaces = (deviceId: string | null) =>
  useQuery({
    queryKey: keys.interfaces(deviceId ?? ""),
    queryFn: () => api.topology.interfaces(deviceId!),
    enabled: !!deviceId,
    ...STATIC,
  });

export const useLinks = (linkType?: LinkType) =>
  useQuery({ queryKey: keys.links(linkType), queryFn: () => api.topology.links({ limit: 100, link_type: linkType }), ...STATIC });

export const useServicePaths = (filters: { site_id?: string; service?: PathService }) =>
  useQuery({ queryKey: keys.services(filters), queryFn: () => api.topology.services({ limit: 100, ...filters }), ...STATIC });

export const useIncidents = (filters: IncidentFilters) =>
  useQuery({
    queryKey: keys.incidents(filters),
    queryFn: () => api.incidents.list(filters),
    placeholderData: keepPreviousData,
  });

export const useIncident = (incidentId: string | null) =>
  useQuery({
    queryKey: keys.incident(incidentId ?? ""),
    queryFn: () => api.incidents.get(incidentId!),
    enabled: !!incidentId,
    refetchInterval: 45_000,
  });

export const useTimeline = (incidentId: string, version?: number) =>
  useQuery({ queryKey: [...keys.timeline(incidentId), version], queryFn: () => api.incidents.timeline(incidentId), placeholderData: keepPreviousData });

export const useIncidentEvidence = (incidentId: string, diagnosisId?: string | null) =>
  useQuery({
    queryKey: [...keys.incidentEvidence(incidentId), diagnosisId ?? "none"],
    queryFn: () => api.incidents.evidence(incidentId),
  });

export const useEscalations = (incidentId: string, version?: number) =>
  useQuery({
    queryKey: [...keys.escalations(incidentId), version],
    queryFn: () => api.incidents.escalations(incidentId),
    placeholderData: keepPreviousData,
  });

export const useDiagnosisRecord = (diagnosisId: string | null) =>
  useQuery({ queryKey: keys.diagnosis(diagnosisId ?? ""), queryFn: () => api.diagnosis.get(diagnosisId!), enabled: !!diagnosisId, ...STATIC });

export const useDiagnosisEvidence = (diagnosisId: string | null) =>
  useQuery({
    queryKey: keys.diagnosisEvidence(diagnosisId ?? ""),
    queryFn: () => api.diagnosis.evidence(diagnosisId!),
    enabled: !!diagnosisId,
    ...STATIC,
  });

/**
 * Advanced analysis (anomalies, path analysis, blast radius, candidates) for the incident's
 * current diagnosis. It is a read-only POST that re-runs diagnostic tools, so it starts only when the
 * person asks (requested) and is then cached per diagnosis. The endpoint needs run_diagnostics, so
 * viewers skip it and see evidence-based readings.
 */
export const useAdvanced = (incident: Incident | undefined, allowed = true, requested = true) =>
  useQuery({
    queryKey: keys.advanced(incident?.incident_id ?? "", incident?.active_diagnosis_id),
    queryFn: () =>
      api.diagnosis.advanced({
        incident_id: incident!.incident_id,
        diagnosis: {
          scenario_id: incident!.dataset_scenario_id!,
          description: incident!.description,
          incident_id: incident!.incident_id,
          site_ids: incident!.site_ids,
        },
      }),
    enabled: requested && allowed && !!incident?.dataset_scenario_id && !!incident?.active_diagnosis_id,
    ...STATIC,
    retry: false,
  });

export const usePlaybooks = (filters: { fault_domain?: FaultDomain; category?: KnowledgeCategory }) =>
  useQuery({ queryKey: keys.knowledge("playbooks", filters), queryFn: () => api.knowledge.playbooks({ limit: 100, ...filters }), ...STATIC });

export const usePlaybook = (playbookId: string | null) =>
  useQuery({
    queryKey: keys.knowledge("playbook", playbookId),
    queryFn: () => api.knowledge.playbook(playbookId!),
    enabled: !!playbookId,
    ...STATIC,
  });

export const useRunbooks = (siteId?: string) =>
  useQuery({ queryKey: keys.knowledge("runbooks", siteId ?? "all"), queryFn: () => api.knowledge.runbooks({ limit: 100, site_id: siteId }), ...STATIC });

export const useProcedures = (faultDomain?: FaultDomain) =>
  useQuery({
    queryKey: keys.knowledge("procedures", faultDomain ?? "all"),
    queryFn: () => api.knowledge.procedures({ limit: 100, fault_domain: faultDomain }),
    ...STATIC,
  });

export const useKnowledgeSearch = (params: { q: string; fault_domain?: FaultDomain; site_id?: string }) =>
  useQuery({
    queryKey: keys.knowledge("search", params),
    queryFn: () => api.knowledge.search({ ...params, limit: 10 }),
    enabled: params.q.trim().length > 0 || !!params.fault_domain || !!params.site_id,
    placeholderData: keepPreviousData,
    ...STATIC,
  });

export const useReportSummary = () => useQuery({ queryKey: keys.reports("summary"), queryFn: api.reports.summary });
export const useReportIncidents = () => useQuery({ queryKey: keys.reports("incidents"), queryFn: () => api.reports.incidents({ limit: 100 }) });
export const useFaultDomainReport = () => useQuery({ queryKey: keys.reports("fault-domains"), queryFn: api.reports.faultDomains });
export const useDiagnosisReport = () => useQuery({ queryKey: keys.reports("diagnosis"), queryFn: api.reports.diagnosis });

// ---------- Writes ----------

/** After any incident write: store the returned incident and refresh everything derived from it. */
export function settleIncident(queryClient: QueryClient, incident: Incident) {
  queryClient.setQueryData(keys.incident(incident.incident_id), incident);
  queryClient.invalidateQueries({ queryKey: keys.timeline(incident.incident_id) });
  queryClient.invalidateQueries({ queryKey: keys.incidentEvidence(incident.incident_id) });
  queryClient.invalidateQueries({ queryKey: keys.escalations(incident.incident_id) });
  queryClient.invalidateQueries({ queryKey: ["incidents"] });
  queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  queryClient.invalidateQueries({ queryKey: ["reports"] });
}

function refreshOnConflict(queryClient: QueryClient, incidentId: string, error: unknown) {
  if (isApiError(error) && error.status === 409) {
    queryClient.invalidateQueries({ queryKey: keys.incident(incidentId) });
  }
}

export function useCreateIncident() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: IncidentCreateBody) => api.incidents.create(body),
    onSuccess: (outcome) => settleIncident(queryClient, outcome.incident),
  });
}

/** Wraps any write that returns the updated incident. */
export function useIncidentWrite<TVars>(incidentId: string, write: (vars: TVars) => Promise<Incident>) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: write,
    onSuccess: (incident) => settleIncident(queryClient, incident),
    onError: (error) => refreshOnConflict(queryClient, incidentId, error),
  });
}

export const usePatchIncident = (incidentId: string) =>
  useIncidentWrite(incidentId, (body: IncidentPatchBody) => api.incidents.patch(incidentId, body));

export const useRunIncidentDiagnosis = (incidentId: string) =>
  useIncidentWrite(incidentId, (version: number) => api.incidents.diagnose(incidentId, version));

export const useClassify = (incidentId: string) =>
  useIncidentWrite(incidentId, (body: { expected_version: number; fault_domain: FaultDomain; reason: string }) =>
    api.incidents.classify(incidentId, body),
  );

export const useResolution = (incidentId: string) =>
  useIncidentWrite(incidentId, (body: ResolutionBody) => api.incidents.resolution(incidentId, body));

export const useCloseIncident = (incidentId: string) =>
  useIncidentWrite(incidentId, (body: { expected_version: number; note: string }) => api.incidents.close(incidentId, body));

export const useReopenIncident = (incidentId: string) =>
  useIncidentWrite(incidentId, (body: { expected_version: number; reason: string }) => api.incidents.reopen(incidentId, body));

export function useEscalate(incidentId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: EscalationBody) => api.incidents.escalate(incidentId, body),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: keys.incident(incidentId) });
      settleRelated(queryClient, incidentId);
    },
    onError: (error) => refreshOnConflict(queryClient, incidentId, error),
  });
}

export function useUpdateEscalation(incidentId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ escalationId, body }: { escalationId: string; body: EscalationUpdateBody }) =>
      api.incidents.updateEscalation(incidentId, escalationId, body),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: keys.incident(incidentId) });
      settleRelated(queryClient, incidentId);
    },
    onError: (error) => refreshOnConflict(queryClient, incidentId, error),
  });
}

/** After a write made outside these hooks (a saved conversation diagnosis): reload the incident and what derives from it. */
export async function refreshIncident(queryClient: QueryClient, incidentId: string) {
  await queryClient.invalidateQueries({ queryKey: keys.incident(incidentId) });
  queryClient.invalidateQueries({ queryKey: keys.incidentEvidence(incidentId) });
  settleRelated(queryClient, incidentId);
}

function settleRelated(queryClient: QueryClient, incidentId: string) {
  queryClient.invalidateQueries({ queryKey: keys.timeline(incidentId) });
  queryClient.invalidateQueries({ queryKey: keys.escalations(incidentId) });
  queryClient.invalidateQueries({ queryKey: ["incidents"] });
  queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  queryClient.invalidateQueries({ queryKey: ["reports"] });
}

export function useAgentDiagnose() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: AgentDiagnoseBody) => api.agent.diagnose(body),
    onSuccess: async (response, body) => {
      if (response.incident && body.incident_id) {
        await queryClient.invalidateQueries({ queryKey: keys.incident(body.incident_id) });
        settleRelated(queryClient, body.incident_id);
      }
    },
  });
}

export const useQuickDiagnosis = () => useMutation({ mutationFn: (body: DiagnosisRequest) => api.diagnosis.run(body) });
