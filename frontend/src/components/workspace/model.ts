import { FAULT_LABEL, inSentence } from "@/lib/labels";
import type {
  AdvancedDiagnosis,
  Anomaly,
  Device,
  DeviceHealth,
  Diagnosis,
  DiagnosisRecord,
  EscalationRecord,
  FaultDomain,
  Incident,
  LifecycleStatus,
  Link,
  NetworkTopology,
  Permission,
} from "@/lib/api/types";

// Mirrors backend/app/incidents/models.py TRANSITIONS.
export const TRANSITIONS: Record<LifecycleStatus, LifecycleStatus[]> = {
  new: ["acknowledged"],
  acknowledged: ["investigating"],
  investigating: ["diagnosed", "escalated", "monitoring"],
  diagnosed: ["investigating", "escalated", "monitoring"],
  escalated: ["investigating", "diagnosed", "monitoring"],
  monitoring: ["investigating", "escalated", "resolved"],
  resolved: ["closed", "investigating"],
  closed: ["investigating"],
};

/** Targets a plain PATCH may set; escalated, resolved and closed have their own endpoints. */
export function patchableTargets(incident: Incident): LifecycleStatus[] {
  if (incident.status === "resolved" || incident.status === "closed") return [];
  return TRANSITIONS[incident.status].filter(
    (target) =>
      target !== "escalated" && target !== "resolved" && target !== "closed" && (target !== "diagnosed" || !!incident.active_diagnosis_id),
  );
}

export const OPEN_ESCALATION: EscalationRecord["status"][] = ["recommended", "assigned"];

export function activeRecord(incident: Incident): DiagnosisRecord | undefined {
  return (incident.diagnoses ?? []).find((record) => record.diagnosis_id === incident.active_diagnosis_id);
}

export function currentResolution(incident: Incident) {
  const list = incident.resolutions ?? [];
  return list.length ? list[list.length - 1] : undefined;
}

export function openEscalations(incident: Incident) {
  return (incident.escalations ?? []).filter((e) => OPEN_ESCALATION.includes(e.status));
}

const DIAGNOSABLE: LifecycleStatus[] = ["acknowledged", "investigating", "diagnosed", "escalated", "monitoring"];
const PROPOSABLE: LifecycleStatus[] = ["investigating", "diagnosed", "escalated", "monitoring"];

export type ActionKey =
  | "acknowledge"
  | "diagnose"
  | "checks"
  | "confirm"
  | "escalate"
  | "update-escalation"
  | "propose"
  | "monitor"
  | "verify"
  | "close"
  | "reopen"
  | "edit"
  | "severity"
  | "priority"
  | "status";

export type ActionState = { allowed: boolean; reason?: string };

/** Whether each action is possible now, by role and by the incident's state. */
export function actionStates(incident: Incident, can: (p: Permission) => boolean): Record<ActionKey, ActionState> {
  const s = incident.status;
  const resolution = currentResolution(incident);
  const pending = resolution?.verification === "pending";
  const open = openEscalations(incident);
  const role = (permission: Permission, label: string): ActionState | null =>
    can(permission) ? null : { allowed: false, reason: `Your role can't ${label}` };
  const ok: ActionState = { allowed: true };
  const no = (reason: string): ActionState => ({ allowed: false, reason });

  const closeBlockers = [
    s !== "resolved" && "the incident must be resolved",
    resolution?.verification !== "verified" && "a verified resolution is required",
    !incident.classification?.confirmed_fault_domain && "the fault domain must be confirmed",
    open.length > 0 && `open escalations must be closed (${open.map((e) => e.escalation_id).join(", ")})`,
  ].filter(Boolean) as string[];

  return {
    acknowledge: role("update_incidents", "acknowledge incidents") ?? (s === "new" ? ok : no("Already acknowledged")),
    diagnose:
      role("run_diagnostics", "run diagnostics") ??
      (!incident.dataset_scenario_id
        ? no("The incident isn't linked to a telemetry dataset")
        : DIAGNOSABLE.includes(s)
          ? ok
          : no(s === "new" ? "Acknowledge the incident first" : "Reopen the incident to diagnose again")),
    checks: incident.active_diagnosis_id ? ok : no("Run a diagnosis first"),
    confirm:
      role("confirm_classification", "confirm classifications") ??
      (s === "closed" ? no("The incident is closed") : ok),
    escalate:
      role("update_incidents", "escalate incidents") ??
      (s === "escalated" || TRANSITIONS[s].includes("escalated") ? ok : no(`Can't escalate while ${s}`)),
    "update-escalation":
      role("update_escalations", "update escalations") ?? (open.length ? ok : no("No open escalations")),
    propose:
      role("propose_resolutions", "propose resolutions") ??
      (pending ? no(`${resolution!.resolution_id} is still awaiting verification`) : PROPOSABLE.includes(s) ? ok : no(`Can't propose while ${s}`)),
    monitor: role("update_incidents", "change status") ?? (TRANSITIONS[s].includes("monitoring") && s !== "resolved" && s !== "closed" ? ok : no(`Can't move to monitoring from ${s}`)),
    verify:
      role("verify_resolutions", "verify resolutions") ?? (pending ? ok : no("There's no resolution awaiting verification")),
    close: role("close_reopen_incidents", "close incidents") ?? (closeBlockers.length ? no(`Before closing: ${closeBlockers.join("; ")}`) : ok),
    reopen: role("close_reopen_incidents", "reopen incidents") ?? (s === "resolved" || s === "closed" ? ok : no("Only resolved or closed incidents reopen")),
    edit: role("update_incidents", "edit incidents") ?? (s === "closed" ? no("The incident is closed") : ok),
    severity: role("change_severity_priority", "change severity") ?? ok,
    priority: role("change_severity_priority", "change priority") ?? ok,
    status: role("update_incidents", "change status") ?? (patchableTargets(incident).length ? ok : no("No status change is available")),
  };
}

export type NextStep = {
  key: ActionKey | "wait";
  title: string;
  detail: string;
  cta?: string;
};

/** The one thing the incident needs next, said as an outcome. */
export function nextStep(incident: Incident, diagnosis: Diagnosis | undefined, states: Record<ActionKey, ActionState>): NextStep {
  const s = incident.status;
  const resolution = currentResolution(incident);
  const open = openEscalations(incident);
  const sites = incident.site_ids.join(", ");

  if (s === "new") {
    return { key: "acknowledge", title: "Acknowledge this incident", detail: "Tells the team someone owns it and lets the investigation start.", cta: "Acknowledge" };
  }
  if (s === "closed") {
    return {
      key: "reopen",
      title: "This incident is closed",
      detail: incident.closure?.notes ? `Closure note: ${incident.closure.notes}` : "Reopen it if the problem comes back.",
      cta: states.reopen.allowed ? "Reopen" : undefined,
    };
  }
  if (s === "resolved") {
    if (open.length) {
      return {
        key: "update-escalation",
        title: `Close ${open[0].escalation_id} before closing`,
        detail: `${open.length === 1 ? "An escalation is" : `${open.length} escalations are`} still open with ${open[0].assigned_team ?? open[0].recommended_team}.`,
        cta: states["update-escalation"].allowed ? "Update escalation" : undefined,
      };
    }
    return {
      key: "close",
      title: "Close the incident",
      detail: resolution?.verified_by ? `Resolution verified by ${resolution.verified_by.actor_id}.` : "The resolution is verified.",
      cta: states.close.allowed ? "Close incident" : undefined,
    };
  }
  if (!incident.active_diagnosis_id) {
    return {
      key: "diagnose",
      title: "Run a read-only diagnosis",
      detail: `Checks reachability, interfaces, routing, firewall, DHCP and DNS for ${sites}. Nothing on the network changes.`,
      cta: "Run diagnosis",
    };
  }
  if (resolution?.verification === "pending") {
    if (s !== "monitoring") {
      return {
        key: "monitor",
        title: "Watch the fix before it's verified",
        detail: `${resolution.resolution_id} is proposed. Move to monitoring so a manager can verify it.`,
        cta: "Start monitoring",
      };
    }
    if (states.verify.allowed) {
      return { key: "verify", title: "Verify the resolution", detail: resolution.summary, cta: "Verify" };
    }
    return { key: "wait", title: "Waiting for verification", detail: `An incident manager needs to verify ${resolution.resolution_id}.` };
  }
  if (!incident.classification?.confirmed_fault_domain && states.confirm.allowed) {
    const domain = incident.classification?.probable_fault_domain;
    return {
      key: "confirm",
      title: "Confirm the fault domain",
      detail: domain
        ? `The diagnosis points to ${domainName(domain)}. Only a person can record it as the classification.`
        : "Record what you believe the fault domain is.",
      cta: "Review and confirm",
    };
  }
  if (s === "escalated" && open.some((e) => e.status === "recommended") && states["update-escalation"].allowed) {
    const escalation = open.find((e) => e.status === "recommended")!;
    return {
      key: "update-escalation",
      title: `Hand over to ${escalation.recommended_team}`,
      detail: `${escalation.escalation_id} is recommended but not sent. Assign it once the team accepts.`,
      cta: "Update escalation",
    };
  }
  if (!incident.classification?.confirmed_fault_domain && diagnosis?.next_checks.length) {
    const first = diagnosis.next_checks[0];
    return {
      key: "checks",
      title: `${first.purpose} on ${first.device_id}`,
      detail: `Run ${diagnosis.next_checks.length} read-only ${diagnosis.next_checks.length === 1 ? "check" : "checks"} and compare with the expected output.`,
      cta: "View checks",
    };
  }
  return {
    key: "propose",
    title: "Propose the fix",
    detail: "Describe what resolved it. A manager verifies it before the incident can close.",
    cta: states.propose.allowed ? "Propose resolution" : undefined,
  };
}

function domainName(domain: FaultDomain) {
  return domain === "unknown" ? "an unknown domain" : inSentence(FAULT_LABEL[domain]);
}

// ---------- Path model ----------

export type HopState = "fault" | "down" | "ok" | "unknown";
export type LinkState = "failed" | "degraded" | "ok";

export type Hop = {
  deviceId: string;
  device?: Device;
  state: HopState;
  /** The path stops here (a failed link or no route), rather than degrading. */
  breaks: boolean;
  health?: DeviceHealth;
  linkToNext?: { id: string | null; state: LinkState; link?: Link };
};

function linkBetween(topology: NetworkTopology | undefined, a: string, b: string) {
  return topology?.links.find((link) => {
    const ends = [link.a_interface_id.split(":")[0], link.b_interface_id.split(":")[0]];
    return ends.includes(a) && ends.includes(b);
  });
}

export function buildPath(
  diagnosis: Diagnosis | undefined,
  advanced: AdvancedDiagnosis | undefined,
  topology: NetworkTopology | undefined,
  health: DeviceHealth[] | undefined,
): Hop[] {
  const analysed = advanced?.paths?.[0];
  const ids = diagnosis?.affected_path?.path?.length
    ? diagnosis.affected_path.path
    : (analysed?.hops.map((hop) => hop.device_id) ?? []);
  if (!ids.length) return [];

  const faultDevices = new Set([...(diagnosis?.fault.device_ids ?? []), ...(analysed?.earliest_affected_point ? [analysed.earliest_affected_point] : [])]);
  const failed = new Set(analysed?.failed_links ?? []);
  const degraded = new Set([...(analysed?.degraded_links ?? []), ...(diagnosis?.fault.link_ids ?? [])]);
  const domainKnown = diagnosis && diagnosis.fault.fault_domain !== "unknown";

  return ids.map((deviceId, index) => {
    const device = topology?.devices.find((d) => d.device_id === deviceId);
    const deviceHealth = health?.find((h) => h.device_id === deviceId);
    const down = deviceHealth && deviceHealth.status !== "available";
    const state: HopState = domainKnown && faultDevices.has(deviceId) ? "fault" : down ? "down" : deviceHealth ? "ok" : "unknown";
    const next = ids[index + 1];
    let linkToNext: Hop["linkToNext"];
    if (next) {
      const hopLink = analysed?.hops.find((hop) => hop.device_id === deviceId)?.link_to_next ?? null;
      const link = (hopLink ? topology?.links.find((l) => l.link_id === hopLink) : undefined) ?? linkBetween(topology, deviceId, next);
      const id = link?.link_id ?? hopLink;
      const linkState: LinkState = id && failed.has(id) ? "failed" : id && degraded.has(id) ? "degraded" : "ok";
      linkToNext = { id, state: linkState, link };
    }
    const breaks = state === "fault" && (failed.size > 0 || analysed?.status === "unreachable" || diagnosis?.affected_path?.reachability === "unreachable");
    return { deviceId, device, state, breaks, health: deviceHealth, linkToNext };
  });
}

export const FAULT_POINT_TEXT: Record<FaultDomain, string> = {
  wan_isp: "Loss starts here",
  routing: "Adjacency fails here",
  switching: "Switching fault here",
  firewall: "Traffic blocked here",
  vlan_authentication: "Authentication fails here",
  dhcp: "No leases here",
  dns: "Names fail here",
  network_device_failure: "Device down",
  interface_link: "Link fault here",
  shared_infrastructure: "Shared failure here",
  unknown: "Suspected",
};

// ---------- Signals ----------

export type Signal = {
  key: string;
  label: string;
  value: number | null;
  text: string;
  format?: (value: number) => string;
  caption: string;
  asset?: string;
  at?: string | null;
  tone: "amber" | "red" | "neutral";
};

const CATEGORY_LABEL: Record<Anomaly["category"], string> = {
  packet_loss: "Packet loss",
  interface_errors: "Interface errors",
  utilization: "Utilisation",
  availability: "Availability",
  routing_adjacency: "Routing adjacency",
  dns: "DNS",
  dhcp: "DHCP",
};

const CATEGORY_ORDER: Anomaly["category"][] = ["packet_loss", "availability", "routing_adjacency", "dns", "dhcp", "interface_errors", "utilization"];

const ACRONYMS = /\b(bgp|ospf|dns|dhcp|crc|mtu|vlan|wan|lan|rtt|nxdomain|servfail)\b/gi;

/** "bgp adjacency failed" -> "BGP adjacency failed" */
export function readable(text: string) {
  const fixed = text.replace(ACRONYMS, (m) => m.toUpperCase());
  return fixed.charAt(0).toUpperCase() + fixed.slice(1);
}

function parseReading(text: string): { value: number; unit: string } | null {
  const match = text.match(/(-?\d[\d,]*(?:\.\d+)?)\s*(%|ms|errors?|drops?)?/i);
  if (!match) return null;
  return { value: Number.parseFloat(match[1].replaceAll(",", "")), unit: (match[2] ?? "").toLowerCase() };
}

function formatterFor(category: Anomaly["category"], unit: string) {
  if (unit === "%" || category === "packet_loss" || category === "utilization") return (v: number) => `${v.toFixed(v < 10 ? 2 : 1)}%`;
  if (unit === "ms") return (v: number) => `${Math.round(v)} ms`;
  return (v: number) => v.toLocaleString("en-US");
}

/** Up to two measured anomalies (worst per category) plus the blast radius. */
export function buildSignals(advanced: AdvancedDiagnosis | undefined, diagnosis: Diagnosis | undefined): Signal[] {
  const signals: Signal[] = [];
  const anomalies = advanced?.anomalies.anomalies ?? [];
  for (const category of CATEGORY_ORDER) {
    if (signals.length >= 2) break;
    const matches = anomalies.filter((a) => a.category === category);
    if (!matches.length) continue;
    const scored = matches
      .map((anomaly) => ({ anomaly, reading: parseReading(anomaly.observed) }))
      .sort((a, b) => (b.reading?.value ?? 0) - (a.reading?.value ?? 0));
    const worst = scored[0];
        signals.push({
      key: category,
      label: CATEGORY_LABEL[category],
      value: worst.reading?.value ?? null,
      text: readable(worst.anomaly.observed),
      format: worst.reading ? formatterFor(category, worst.reading.unit) : undefined,
      caption: `Baseline ${worst.anomaly.baseline.replace(/ in the first (measured )?sample$/, "")}`,
      asset: worst.anomaly.asset_id,
      at: worst.anomaly.timestamp,
      tone: category === "availability" ? "red" : "amber",
    });
  }

  if (!signals.length && diagnosis) {
    const observed = diagnosis.evidence.filter((e) => e.evidence_type.startsWith("observed")).length;
    signals.push({
      key: "evidence",
      label: "Evidence collected",
      value: diagnosis.evidence.length,
      text: String(diagnosis.evidence.length),
      caption: `${observed} observed, ${diagnosis.evidence.length - observed} inferred`,
      tone: "neutral",
    });
    signals.push({
      key: "tools",
      label: "Diagnostic tool calls",
      value: diagnosis.tool_calls.length,
      text: String(diagnosis.tool_calls.length),
      caption: `${new Set(diagnosis.tool_calls.map((c) => c.tool)).size} different tools`,
      tone: "neutral",
    });
  }

  if (advanced) {
    const radius = advanced.blast_radius;
    const paths = radius.items.filter((item) => item.asset_type === "path").length;
    const potential = radius.potentially_affected_sites.length;
    signals.push({
      key: "impact",
      label: "Service paths affected",
      value: paths,
      text: String(paths),
      caption: `${radius.affected_sites.join(", ") || "No site"}${potential ? ` · ${potential} more may be` : ""}`,
      tone: "neutral",
    });
  }
  return signals.slice(0, 3);
}
