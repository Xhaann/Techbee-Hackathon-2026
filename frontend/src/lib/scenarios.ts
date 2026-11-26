import type { IncidentPriority } from "./api/types";

// The backend selects synthetic telemetry by dataset id but has no endpoint that lists them.
// This mirrors backend/app/network/data/scenarios/*.json (scenario + reference incident report).
export type Scenario = {
  id: string;
  name: string;
  summary: string;
  report?: { title: string; description: string; siteIds: string[]; symptoms: string[]; priority: IncidentPriority };
};

export const SCENARIOS: Scenario[] = [
  {
    id: "PACKET-LOSS",
    name: "Packet loss on WAN circuit",
    summary: "The New York WAN circuit degrades with CRC errors, packet loss and high latency.",
    report: {
      title: "New York users report slow applications and choppy calls",
      description: "Users in New York report that ERP pages load slowly and voice calls drop intermittently.",
      siteIds: ["NYC"],
      symptoms: ["Slow ERP response", "Choppy voice calls", "Slow name resolution"],
      priority: "p2",
    },
  },
  {
    id: "WAN-FAILURE",
    name: "WAN connectivity failure",
    summary: "The Singapore WAN circuit loses signal and the branch is isolated from the core.",
    report: {
      title: "Singapore office cannot reach any corporate service",
      description: "All users in the Singapore branch report that ERP, e-mail and internet access stopped working.",
      siteIds: ["SIN"],
      symptoms: ["No access to ERP", "No internet access", "Branch router unreachable from monitoring"],
      priority: "p1",
    },
  },
  {
    id: "OSPF-ADJACENCY-FAILURE",
    name: "OSPF adjacency failure",
    summary: "An MTU change on the Bengaluru WAN edge leaves the OSPF adjacency stuck in EXSTART.",
    report: {
      title: "Bengaluru office lost access to data centre applications",
      description: "Bengaluru users cannot reach ERP or the internet although the WAN circuit shows as up.",
      siteIds: ["BLR"],
      symptoms: ["No access to ERP", "No internet access", "WAN circuit reported up by carrier"],
      priority: "p1",
    },
  },
  {
    id: "FIREWALL-BLOCKING",
    name: "Firewall blocking application traffic",
    summary: "A new data centre firewall rule unintentionally denies HTTPS from Singapore to the server VLAN.",
    report: {
      title: "Singapore users cannot open the ERP portal",
      description: "ERP times out for Singapore users while internet access and other sites work normally.",
      siteIds: ["SIN"],
      symptoms: ["ERP portal connection timeout", "Internet access works", "Other branches unaffected"],
      priority: "p2",
    },
  },
  {
    id: "DHCP-ALLOCATION-FAILURE",
    name: "DHCP allocation failure",
    summary: "The Bengaluru user DHCP scope is exhausted and new clients receive no address.",
    report: {
      title: "New laptops in Bengaluru cannot obtain an IP address",
      description: "Recently connected laptops in Bengaluru show a self-assigned address; existing users are unaffected.",
      siteIds: ["BLR"],
      symptoms: ["Self-assigned 169.254.x.x address", "Existing users unaffected", "Only wired user VLAN affected"],
      priority: "p3",
    },
  },
  {
    id: "DNS-RESOLUTION-FAILURE",
    name: "DNS resolution failure",
    summary: "The primary DNS server fails to load the internal zone and returns SERVFAIL for internal names.",
    report: {
      title: "Users cannot reach internal sites by name",
      description: "Users at all branches report that internal web sites and ERP fail to open by name; internet sites work.",
      siteIds: ["NYC", "SIN", "BLR"],
      symptoms: ["Internal host names do not resolve", "Internet sites work", "Access by IP address works"],
      priority: "p2",
    },
  },
  {
    id: "VLAN-AUTHENTICATION-FAILURE",
    name: "VLAN authentication failure",
    summary: "802.1X authentication fails on the New York user VLAN after a RADIUS key change on the access switch.",
    report: {
      title: "New York users cannot connect wired desktops to the network",
      description: "Wired desktops in New York show 'authentication failed' and get no network access; phones work.",
      siteIds: ["NYC"],
      symptoms: ["802.1X authentication failed", "No network on wired desktops", "IP phones unaffected"],
      priority: "p2",
    },
  },
  {
    id: "SHARED-DEVICE-FAILURE",
    name: "Shared core router failure",
    summary: "CORE-RTR-01 loses both power supplies, cutting the New York and Singapore paths that share it.",
    report: {
      title: "New York and Singapore offices are both offline",
      description: "Two branches lost all corporate and internet connectivity at the same time; Bengaluru is unaffected.",
      siteIds: ["NYC", "SIN"],
      symptoms: ["Two branches offline simultaneously", "Bengaluru unaffected", "Core router not responding to monitoring"],
      priority: "p1",
    },
  },
  {
    id: "BASELINE",
    name: "Healthy baseline",
    summary: "Normal operation across all sites with no active incident.",
  },
];

export const scenarioById = (id: string | null | undefined) => SCENARIOS.find((s) => s.id === id);
