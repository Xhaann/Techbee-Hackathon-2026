// One function per backend operation (52 operations under /api/v1 plus /health); the observability operations are in observability.ts.
import { del, get, openStream, patch, post } from "./client";
import type {
  LoginRequest,
  LoginResponse,
  AdvancedDiagnosis,
  AdvancedBody,
  AgentDiagnoseBody,
  AgentDiagnoseResponse,
  AttachedIncident,
  ConversationContext,
  ConversationSummary,
  ConversationView,
  CountSummary,
  Investigation,
  MessageBody,
  TurnResult,
  CreationOutcome,
  Device,
  DiagnosisRecord,
  DiagnosticProcedure,
  Diagnosis,
  DiagnosisRequest,
  EscalationBody,
  EscalationUpdateBody,
  EscalationView,
  EvidencePage,
  FaultDomain,
  Incident,
  IncidentCreateBody,
  IncidentFilters,
  IncidentPatchBody,
  IncidentReportRow,
  IncidentSummary,
  Interface,
  KnowledgeCategory,
  Link,
  LinkType,
  NetworkHealth,
  NetworkPath,
  NetworkTopology,
  Page,
  PathService,
  Playbook,
  PrincipalView,
  ResolutionBody,
  RetrievalResult,
  Runbook,
  Site,
  TimelineEvent,
  ToolResult,
  DeviceType,
} from "./types";

type Paging = { limit?: number; offset?: number };
const id = encodeURIComponent;

export const api = {
  health: (baseUrl?: string) => get<{ status: "healthy" }>("/health", { raw: true, baseUrl }),

  auth: {
    verify: (token?: string, baseUrl?: string) => post<PrincipalView>("/auth/verify", undefined, { token, baseUrl }),
    // token: "" sends no Authorization header and keeps a 401 here from ending another session.
    login: (body: LoginRequest, baseUrl?: string) => post<LoginResponse>("/auth/login", body, { token: "", baseUrl }),
    // Revokes the presented token. Passing it explicitly keeps a 401 here from re-triggering sign-out.
    logout: (token: string) => post<void>("/auth/logout", undefined, { token }),
  },

  dashboard: {
    summary: () => get<CountSummary>("/dashboard/summary"),
    incidents: (paging: Paging = {}) => get<Page<IncidentSummary>>("/dashboard/incidents", { query: paging }),
    networkHealth: (scenarioId: string) => get<NetworkHealth>("/dashboard/network-health", { query: { scenario_id: scenarioId } }),
  },

  topology: {
    all: () => get<NetworkTopology>("/topology"),
    sites: (paging: Paging = { limit: 100 }) => get<Page<Site>>("/topology/sites", { query: paging }),
    site: (siteId: string) => get<ToolResult>(`/topology/sites/${id(siteId)}`),
    devices: (filters: Paging & { site_id?: string; device_type?: DeviceType } = { limit: 100 }) =>
      get<Page<Device>>("/topology/devices", { query: filters }),
    device: (deviceId: string) => get<Device>(`/topology/devices/${id(deviceId)}`),
    interfaces: (deviceId: string, paging: Paging = { limit: 100 }) =>
      get<Page<Interface>>(`/topology/devices/${id(deviceId)}/interfaces`, { query: paging }),
    links: (filters: Paging & { link_type?: LinkType } = { limit: 100 }) => get<Page<Link>>("/topology/links", { query: filters }),
    services: (filters: Paging & { site_id?: string; service?: PathService } = { limit: 100 }) =>
      get<Page<NetworkPath>>("/topology/services", { query: filters }),
  },

  diagnosis: {
    run: (body: DiagnosisRequest) => post<Diagnosis>("/diagnosis", body),
    advanced: (body: AdvancedBody) => post<AdvancedDiagnosis>("/diagnosis/advanced", body),
    get: (diagnosisId: string) => get<DiagnosisRecord>(`/diagnosis/${id(diagnosisId)}`),
    evidence: (diagnosisId: string, paging: Paging = { limit: 100 }) =>
      get<EvidencePage>(`/diagnosis/${id(diagnosisId)}/evidence`, { query: paging }),
  },

  agent: {
    diagnose: (body: AgentDiagnoseBody, signal?: AbortSignal) => post<AgentDiagnoseResponse>("/agent/diagnose", body, { signal }),
  },

  conversations: {
    create: (body: { incident_id?: string; scenario_id?: string; mode?: "auto" | "rule_based" }) =>
      post<ConversationView>("/conversations", body),
    list: (filters: Paging & { incident_id?: string } = {}) => get<Page<ConversationSummary>>("/conversations", { query: filters }),
    get: (conversationId: string) => get<ConversationView>(`/conversations/${id(conversationId)}`),
    remove: (conversationId: string) => del<void>(`/conversations/${id(conversationId)}`),
    /** Sends a message and waits for the whole turn (no streaming). */
    send: (conversationId: string, body: MessageBody) => post<TurnResult>(`/conversations/${id(conversationId)}/messages`, body),
    /** Sends a message and returns the SSE stream of the turn. */
    stream: (conversationId: string, body: MessageBody, signal?: AbortSignal) =>
      openStream("POST", `/conversations/${id(conversationId)}/messages`, { body: { ...body, stream: true }, signal }),
    /** Replays events after a sequence number and follows a running turn to its end. */
    events: (conversationId: string, after: number, signal?: AbortSignal) =>
      openStream("GET", `/conversations/${id(conversationId)}/events`, { query: { after }, signal }),
    cancel: (conversationId: string) =>
      post<{ cancelled: boolean; turn_id: string | null; investigation_id: string | null }>(`/conversations/${id(conversationId)}/cancel`),
    context: (conversationId: string) => get<ConversationContext>(`/conversations/${id(conversationId)}/context`),
    resetContext: (conversationId: string) => del<ConversationContext>(`/conversations/${id(conversationId)}/context`),
    investigation: (conversationId: string, investigationId: string) =>
      get<Investigation>(`/conversations/${id(conversationId)}/investigations/${id(investigationId)}`),
    /** Human-approved: saves a conversation diagnosis to the linked incident. */
    attach: (conversationId: string, investigationId: string, expectedVersion: number) =>
      post<AttachedIncident>(`/conversations/${id(conversationId)}/investigations/${id(investigationId)}/attach`, {
        expected_version: expectedVersion,
      }),
  },

  incidents: {
    create: (body: IncidentCreateBody) => post<CreationOutcome>("/incidents", body),
    list: (filters: IncidentFilters = {}) => get<Page<IncidentSummary>>("/incidents", { query: filters }),
    get: (incidentId: string) => get<Incident>(`/incidents/${id(incidentId)}`),
    patch: (incidentId: string, body: IncidentPatchBody) => patch<Incident>(`/incidents/${id(incidentId)}`, body),
    timeline: (incidentId: string, paging: Paging = { limit: 100 }) =>
      get<Page<TimelineEvent>>(`/incidents/${id(incidentId)}/timeline`, { query: paging }),
    diagnose: (incidentId: string, expectedVersion: number) =>
      post<Incident>(`/incidents/${id(incidentId)}/diagnosis`, { expected_version: expectedVersion }),
    classify: (incidentId: string, body: { expected_version: number; fault_domain: FaultDomain; reason: string }) =>
      post<Incident>(`/incidents/${id(incidentId)}/classification`, body),
    resolution: (incidentId: string, body: ResolutionBody) => post<Incident>(`/incidents/${id(incidentId)}/resolution`, body),
    close: (incidentId: string, body: { expected_version: number; note: string }) =>
      post<Incident>(`/incidents/${id(incidentId)}/close`, body),
    reopen: (incidentId: string, body: { expected_version: number; reason: string }) =>
      post<Incident>(`/incidents/${id(incidentId)}/reopen`, body),
    evidence: (incidentId: string, paging: Paging = { limit: 100 }) =>
      get<EvidencePage>(`/incidents/${id(incidentId)}/evidence`, { query: paging }),
    escalations: (incidentId: string, paging: Paging = { limit: 100 }) =>
      get<Page<EscalationView>>(`/incidents/${id(incidentId)}/escalations`, { query: paging }),
    escalate: (incidentId: string, body: EscalationBody) => post<EscalationView>(`/incidents/${id(incidentId)}/escalations`, body),
    updateEscalation: (incidentId: string, escalationId: string, body: EscalationUpdateBody) =>
      patch<EscalationView>(`/incidents/${id(incidentId)}/escalations/${id(escalationId)}`, body),
  },

  knowledge: {
    playbooks: (filters: Paging & { fault_domain?: FaultDomain; category?: KnowledgeCategory } = { limit: 100 }) =>
      get<Page<Playbook>>("/knowledge/playbooks", { query: filters }),
    playbook: (playbookId: string) => get<Playbook>(`/knowledge/playbooks/${id(playbookId)}`),
    runbooks: (filters: Paging & { site_id?: string } = { limit: 100 }) => get<Page<Runbook>>("/knowledge/runbooks", { query: filters }),
    procedures: (filters: Paging & { fault_domain?: FaultDomain } = { limit: 100 }) =>
      get<Page<DiagnosticProcedure>>("/knowledge/procedures", { query: filters }),
    search: (params: { q?: string; fault_domain?: FaultDomain; site_id?: string; limit?: number }) =>
      get<RetrievalResult>("/knowledge/search", { query: params }),
  },

  reports: {
    summary: () => get<CountSummary>("/reports/summary"),
    incidents: (paging: Paging = { limit: 100 }) => get<Page<IncidentReportRow>>("/reports/incidents", { query: paging }),
    faultDomains: () => get<CountSummary>("/reports/fault-domains"),
    diagnosis: () => get<CountSummary>("/reports/diagnosis"),
  },
};
