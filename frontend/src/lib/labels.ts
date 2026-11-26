import type {
  Confidence,
  DeviceRole,
  DeviceType,
  DiagnosisMethod,
  DiagnosisStatus,
  EscalationStatus,
  EventType,
  FaultDomain,
  IncidentPriority,
  IncidentSeverity,
  IncidentSource,
  Layer,
  LifecycleStatus,
  PathService,
  TimelineRelevance,
} from "./api/types";

export const STATUS_LABEL: Record<LifecycleStatus, string> = {
  new: "New",
  acknowledged: "Acknowledged",
  investigating: "Investigating",
  diagnosed: "Diagnosed",
  escalated: "Escalated",
  monitoring: "Monitoring",
  resolved: "Resolved",
  closed: "Closed",
};

export const STATUS_ORDER: LifecycleStatus[] = [
  "new",
  "acknowledged",
  "investigating",
  "diagnosed",
  "escalated",
  "monitoring",
  "resolved",
  "closed",
];

/** Tone for a lifecycle status: what it asks of the team. */
export function statusTone(status: LifecycleStatus): Tone {
  if (status === "new" || status === "escalated") return "amber";
  if (status === "resolved" || status === "closed") return "muted";
  if (status === "monitoring") return "green";
  return "accent";
}

export type Tone = "amber" | "green" | "red" | "accent" | "muted";

export const SEVERITY_LABEL: Record<IncidentSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export const PRIORITY_LABEL: Record<IncidentPriority, string> = { p1: "P1", p2: "P2", p3: "P3", p4: "P4" };

export function severityTone(severity: IncidentSeverity): Tone {
  if (severity === "critical") return "red";
  if (severity === "high") return "amber";
  if (severity === "medium") return "accent";
  return "muted";
}

export const SOURCE_LABEL: Record<IncidentSource, string> = {
  user_report: "User report",
  monitoring: "Monitoring",
  service_desk: "Service desk",
  diagnosis_engine: "Diagnosis engine",
};

export const FAULT_LABEL: Record<FaultDomain, string> = {
  wan_isp: "WAN or ISP circuit",
  routing: "Routing",
  switching: "Switching",
  firewall: "Firewall policy",
  vlan_authentication: "VLAN or 802.1X authentication",
  dhcp: "DHCP",
  dns: "DNS",
  network_device_failure: "Network device failure",
  interface_link: "Interface or link",
  shared_infrastructure: "Shared infrastructure",
  unknown: "Unknown",
};

/** Headline for the root-cause card: what is broken, said plainly. */
export const FAULT_HEADLINE: Record<FaultDomain, string> = {
  wan_isp: "ISP link degradation",
  routing: "Routing adjacency failure",
  switching: "Switching fault",
  firewall: "Firewall rule blocking traffic",
  vlan_authentication: "802.1X authentication failure",
  dhcp: "DHCP scope exhausted",
  dns: "Internal DNS resolution failure",
  network_device_failure: "Network device down",
  interface_link: "Interface or link fault",
  shared_infrastructure: "Shared infrastructure failure",
  unknown: "No root cause supported yet",
};

/** The headline, sharpened by what the root cause says: a circuit that is down isn't "degraded". */
export function faultHeadline(domain: FaultDomain, rootCause = "") {
  const down = /\b(is down|went down|operational status down|loss of signal|isolat)/i.test(rootCause);
  if (domain === "wan_isp" && down) return "WAN circuit down";
  if (domain === "interface_link" && down) return "Link down";
  return FAULT_HEADLINE[domain];
}

/** Short tag for the sidebar list ("Bengaluru · WAN"). */
export const FAULT_SHORT: Record<FaultDomain, string> = {
  wan_isp: "WAN",
  routing: "Routing",
  switching: "Switching",
  firewall: "Firewall",
  vlan_authentication: "802.1X",
  dhcp: "DHCP",
  dns: "DNS",
  network_device_failure: "Device down",
  interface_link: "Link",
  shared_infrastructure: "Shared core",
  unknown: "Unknown",
};

export const FAULT_DOMAINS = Object.keys(FAULT_LABEL) as FaultDomain[];

/** A label for use mid-sentence: lowercases a leading capital but keeps acronyms ("WAN", "DHCP"). */
export function inSentence(label: string) {
  return /^[A-Z][a-z]/.test(label) ? label.charAt(0).toLowerCase() + label.slice(1) : label;
}

export const CONFIDENCE_LABEL: Record<Confidence, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
  insufficient_evidence: "Insufficient",
};

/** Filled steps on a three-step confidence meter. */
export const CONFIDENCE_STEPS: Record<Confidence, number> = { high: 3, medium: 2, low: 1, insufficient_evidence: 0 };

export const METHOD_LABEL: Record<DiagnosisMethod, string> = {
  model: "Model",
  rule_based: "Rule-based",
  rule_based_fallback: "Rule-based fallback",
};

export const DIAGNOSIS_STATUS_LABEL: Record<DiagnosisStatus, string> = {
  completed: "Completed",
  partial: "Partial",
  no_fault_identified: "No fault identified",
  insufficient_evidence: "Insufficient evidence",
  failed: "Failed",
};

export const ESCALATION_STATUS_LABEL: Record<EscalationStatus, string> = {
  recommended: "Recommended, not sent",
  assigned: "Assigned",
  closed: "Closed",
  cancelled: "Cancelled",
};

export const SERVICE_LABEL: Record<PathService, string> = {
  application: "Applications",
  authentication: "Authentication",
  dhcp: "DHCP",
  dns: "DNS",
  internet: "Internet",
};

export const DEVICE_TYPE_LABEL: Record<DeviceType, string> = {
  router: "Router",
  switch: "Switch",
  firewall: "Firewall",
  server: "Server",
};

export const ROLE_LABEL: Record<DeviceRole, string> = {
  wan_edge: "WAN edge",
  core_router: "Core router",
  core_switch: "Core switch",
  distribution_switch: "Distribution switch",
  access_switch: "Access switch",
  perimeter_firewall: "Perimeter firewall",
  data_centre_firewall: "Data centre firewall",
  dns_server: "DNS server",
  dhcp_server: "DHCP server",
  authentication_server: "Authentication server",
  application_server: "Application server",
};

export const LAYER_LABEL: Record<Layer, string> = {
  physical_interface: "Physical interface",
  switching_vlan: "Switching and VLAN",
  routing: "Routing",
  wan_connectivity: "WAN connectivity",
  firewall_security: "Firewall",
  dhcp: "DHCP",
  dns: "DNS",
  shared_infrastructure: "Shared infrastructure",
  background: "Background",
};

export const RELEVANCE_LABEL: Record<TimelineRelevance, string> = {
  fault_onset: "Fault onset",
  precedes_fault: "Before the fault",
  correlated: "Correlated",
  concurrent: "Concurrent",
  background: "Background",
};

export const EVENT_LABEL: Record<EventType, string> = {
  created: "Opened",
  acknowledged: "Acknowledged",
  investigation_started: "Investigation started",
  status_changed: "Status changed",
  details_updated: "Details updated",
  related_report_linked: "Related report linked",
  diagnostic_tools_executed: "Diagnostic tools ran",
  diagnosis_completed: "Diagnosis attached",
  diagnosis_superseded: "Diagnosis superseded",
  classification_changed: "Classification changed",
  severity_changed: "Severity changed",
  priority_changed: "Priority changed",
  assets_updated: "Affected assets updated",
  escalation_created: "Escalation recommended",
  escalation_updated: "Escalation updated",
  monitoring_started: "Monitoring started",
  resolution_proposed: "Resolution proposed",
  resolution_verified: "Resolution verified",
  resolution_rejected: "Resolution rejected",
  resolved: "Resolved",
  closed: "Closed",
  reopened: "Reopened",
  knowledge_linked: "Knowledge linked",
};

export const ROLE_TITLE: Record<string, string> = {
  viewer: "Viewer",
  operator: "Network engineer",
  incident_manager: "Incident manager",
  knowledge_manager: "Knowledge manager",
  system_service: "System service",
  ai_assistant: "AI assistant",
};

export function humanize(value: string) {
  const text = value.replaceAll("_", " ").toLowerCase();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function initials(subject: string) {
  const parts = subject.split(/[._@-]+/).filter(Boolean);
  const letters = parts.length >= 2 ? parts[0][0] + parts[1][0] : subject.slice(0, 2);
  return letters.toUpperCase();
}
