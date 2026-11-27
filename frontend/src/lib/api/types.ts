// Friendly names for the generated OpenAPI types (npm run gen:api regenerates schema.ts).
import type { components } from "./schema";

type S = components["schemas"];

export type ErrorDetail = S["ErrorDetail"];
export type ErrorResponse = S["ErrorResponse"];

export type PrincipalView = S["PrincipalView"];
export type LoginRequest = S["LoginRequest"];
export type LoginResponse = S["LoginResponse"];

export type Incident = S["Incident"];
export type IncidentSummary = S["app__incidents__models__IncidentSummary"];
export type IncidentCreateRequest = S["IncidentCreateRequest"];
export type CreationOutcome = S["CreationOutcome"];
export type SimilarIncident = S["SimilarIncident"];
export type TimelineEvent = S["TimelineEvent"];
export type EventType = S["EventType"];
export type DiagnosisRecord = S["DiagnosisRecord"];
export type Classification = S["Classification"];
export type Resolution = S["Resolution"];
export type EscalationRecord = S["EscalationRecord"];
export type EscalationView = S["app__api__schemas__EscalationView"];
export type EscalationStatus = S["EscalationStatus"];
export type LifecycleStatus = S["LifecycleStatus"];
export type IncidentSeverity = S["IncidentSeverity"];
export type IncidentPriority = S["IncidentPriority"];
export type IncidentSource = S["IncidentSource"];
export type FaultDomain = S["FaultDomain"];
export type Actor = S["Actor"];
export type AffectedAsset = S["AffectedAsset"];
export type KnowledgeReference = S["KnowledgeReference"];

export type Diagnosis = S["Diagnosis"];
export type DiagnosisRequest = S["DiagnosisRequest"];
export type EvidenceItem = S["EvidenceItem"];
export type EvidenceRef = S["EvidenceRef"];
export type EvidencePage = S["EvidencePage"];
export type EvidenceView = S["EvidenceView"];
export type TimelineEntry = S["TimelineEntry"];
export type TimelineRelevance = S["TimelineRelevance"];
export type FaultAssessment = S["FaultAssessment"];
export type Confidence = S["Confidence"];
export type Alternative = S["Alternative"];
export type NextCheck = S["NextCheck"];
export type OutstandingCheck = S["OutstandingCheck"];
export type AffectedPath = S["AffectedPath"];
export type DiagnosisMethod = S["DiagnosisMethod"];
export type DiagnosisStatus = S["DiagnosisStatus"];

export type AdvancedRequest = S["AdvancedRequest"];
export type AdvancedDiagnosis = S["AdvancedDiagnosis"];
export type RootCauseCandidate = S["RootCauseCandidate"];
export type Anomaly = S["Anomaly"];
export type PathAnalysis = S["PathAnalysis"];
export type BlastRadius = S["BlastRadius"];
export type ImpactItem = S["ImpactItem"];
export type CrossLayerAnalysis = S["CrossLayerAnalysis"];
export type LayerSummary = S["LayerSummary"];
export type Layer = S["Layer"];
export type ChangeAnalysis = S["ChangeAnalysis"];
export type HistoricalComparison = S["HistoricalComparison"];
export type GuidanceReference = S["app__advanced__schema__GuidanceReference"];

export type AgentDiagnoseResponse = S["AgentDiagnoseResponse"];
export type AgentReport = S["AgentReport"];
export type AgentExecution = S["AgentExecution"];
export type AttachedIncident = S["AttachedIncident"];
export type VerifiedFact = S["VerifiedFact"];

export type NetworkTopology = S["NetworkTopology"];
export type Site = S["Site"];
export type Device = S["Device"];
export type DeviceType = S["DeviceType"];
export type DeviceRole = S["DeviceRole"];
export type Interface = S["Interface"];
export type Link = S["Link"];
export type LinkType = S["LinkType"];
export type NetworkPath = S["NetworkPath"];
export type PathService = S["PathService"];
export type ToolResult = S["ToolResult"];
export type NetworkHealth = S["NetworkHealth"];
export type DeviceHealth = S["DeviceHealth"];

export type Playbook = S["Playbook"];
export type Runbook = S["Runbook"];
export type DiagnosticProcedure = S["DiagnosticProcedure"];
export type DiagnosticStep = S["DiagnosticStep"];
export type CommandSpec = S["CommandSpec"];
export type RetrievalResult = S["RetrievalResult"];
export type KnowledgeMatch = S["KnowledgeMatch"];
export type KnowledgeCategory = S["KnowledgeCategory"];

export type CountSummary = S["CountSummary"];
export type IncidentReportRow = S["IncidentReportRow"];

export type Page<T> = { items: T[]; total: number; limit: number; offset: number };

// Request bodies: the generator marks server defaults as required, so these are written by hand.
export type AdvancedBody = { diagnosis: DiagnosisRequest; incident_id?: string | null; supplementary_tool_calls?: number };

export type AgentDiagnoseBody = {
  description: string;
  scenario_id?: string | null;
  site_ids?: string[];
  device_ids?: string[];
  services?: PathService[];
  incident_id?: string | null;
  mode?: "agent" | "rule_based";
  attach_to_incident?: boolean;
  expected_version?: number | null;
};

export type IncidentCreateBody = {
  title: string;
  description: string;
  site_ids: string[];
  device_ids?: string[];
  services?: PathService[];
  symptoms?: string[];
  severity?: IncidentSeverity | null;
  priority?: IncidentPriority | null;
  source?: IncidentSource;
  dataset_scenario_id?: string | null;
  reported_at?: string | null;
  force_new?: boolean;
};

export type IncidentPatchBody = {
  expected_version: number;
  title?: string;
  description?: string;
  assigned_team?: string;
  assigned_owner?: string;
  severity?: IncidentSeverity;
  priority?: IncidentPriority;
  status?: LifecycleStatus;
  reason?: string;
};

export type ResolutionBody =
  | {
      expected_version: number;
      action: "propose";
      summary: string;
      fault_domain: FaultDomain;
      notes?: string[];
      responsible_team?: string;
    }
  | {
      expected_version: number;
      action: "verify";
      approved: boolean;
      note: string;
      responsible_team?: string;
    };

export type EscalationBody = {
  expected_version: number;
  team?: string;
  priority?: IncidentPriority;
  reason?: string;
};

export type EscalationUpdateBody = {
  expected_version: number;
  status: EscalationStatus;
  note: string;
  assigned_team?: string;
};

export type IncidentFilters = {
  site_id?: string;
  device_id?: string;
  severity?: IncidentSeverity;
  status?: LifecycleStatus;
  fault_domain?: FaultDomain;
  start?: string;
  end?: string;
  limit?: number;
  offset?: number;
};

export type Permission =
  | "view_diagnostics"
  | "run_diagnostics"
  | "view_incidents"
  | "create_incidents"
  | "update_incidents"
  | "propose_resolutions"
  | "confirm_classification"
  | "change_severity_priority"
  | "verify_resolutions"
  | "close_reopen_incidents"
  | "update_escalations"
  | "manage_knowledge";

// ---------- Conversations ----------

export type ConversationView = S["ConversationView"];
export type ConversationSummary = S["ConversationSummary"];
export type ConversationContext = S["ConversationContext"];
export type ConversationMessage = S["Message"];
/** One server-sent event (SSE frames carry it as JSON; it isn't in the OpenAPI schema). */
export type ConversationEvent = {
  seq: number;
  event: string;
  conversation_id: string;
  turn_id: string | null;
  at: string;
  data: Record<string, unknown>;
};
export type ConversationIntent = S["Intent"];
export type TurnResult = S["TurnResult"];
export type ToolStep = S["ToolStep"];
export type EvidenceReference = S["EvidenceReference"];
export type SuggestedAction = S["SuggestedAction"];
export type Clarification = S["Clarification"];
export type HumanConfirmation = S["HumanConfirmation"];
export type Investigation = S["Investigation"];
export type InvestigationSummary = S["InvestigationSummary"];

export type QuickActionBody = {
  kind: "full_diagnosis" | "targeted_check" | "explain_evidence" | "status" | "run_plan" | "multi_agent" | "protocol";
  tool?: string;
  arguments?: Record<string, unknown>;
  evidence_ids?: string[];
  calls?: { tool: string; arguments: Record<string, unknown> }[];
  label?: string;
};
export type GeneratedBy = S["GeneratedBy"];

export type MessageBody = { content?: string; action?: QuickActionBody; stream?: boolean };
