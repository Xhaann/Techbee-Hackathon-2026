"""Network threat correlation: security-relevant findings from every engine (ARP, TLS, IPv6 RAs, rogue APs, BGP origin,
suspicious traffic, lateral movement) and IDS alerts are grouped by the hosts they share and their timing, ordered into
behaviour stages, and scored with the same log-odds arithmetic as the Phase 2 fault reasoning.

The score is calibrated against the synthetic scenarios and capped below certainty: correlated indicators make activity
more or less likely to be malicious, but only an analyst confirms an attack. Nothing here names who is responsible."""
import math
from collections import defaultdict
from datetime import timedelta

from app.protocols.engines.base import Context, Draft, EngineOutput, ref

PRIOR = 0.02
CAP = 0.9
JOIN = timedelta(minutes=45)
# Log-likelihood ratios: how much more often each indicator appears during real malicious activity than in benign traffic.
WEIGHT = {"SUSPICIOUS_PORT_SCAN": 1.4, "SUSPICIOUS_BEACONING": 1.8, "SUSPICIOUS_LARGE_UPLOAD": 1.6, "SUSPICIOUS_DNS_TUNNELING": 2.0,
          "SUSPICIOUS_THREAT_INTEL_MATCH": 1.6, "LATERAL_ADMIN_FANOUT": 1.6, "LATERAL_CREDENTIAL_SPRAY": 1.8, "LATERAL_MOVEMENT_CHAIN": 1.8,
          "LATERAL_SEGMENTATION_GAP": 0.8, "ARP_GATEWAY_SPOOFING": 2.5, "ARP_MAC_MULTI_IP": 1.2, "ARP_GRATUITOUS_FLOOD": 0.6,
          "TLS_UNEXPECTED_CERTIFICATE": 2.0, "IPV6_ROGUE_RA": 1.6, "WIFI_ROGUE_AP": 1.2, "BGP_ORIGIN_HIJACK_SUSPECTED": 1.5,
          "STP_ROOT_UNEXPECTED": 0.6}
ALERT_WEIGHT = {"low": 0.3, "medium": 0.7, "high": 1.0}
STAGE = {"SUSPICIOUS_PORT_SCAN": "recon", "LATERAL_CREDENTIAL_SPRAY": "credential_access", "LATERAL_ADMIN_FANOUT": "lateral_movement",
         "LATERAL_MOVEMENT_CHAIN": "lateral_movement", "SUSPICIOUS_BEACONING": "command_and_control", "SUSPICIOUS_THREAT_INTEL_MATCH": "command_and_control",
         "SUSPICIOUS_LARGE_UPLOAD": "exfiltration", "SUSPICIOUS_DNS_TUNNELING": "exfiltration", "ARP_GATEWAY_SPOOFING": "interception",
         "TLS_UNEXPECTED_CERTIFICATE": "interception", "IPV6_ROGUE_RA": "interception", "WIFI_ROGUE_AP": "initial_access",
         "LATERAL_SEGMENTATION_GAP": "lateral_movement"}
ORDER = ["recon", "initial_access", "credential_access", "interception", "lateral_movement", "command_and_control", "exfiltration"]
STAGE_TEXT = {"recon": "reconnaissance", "initial_access": "access", "credential_access": "credential access", "interception": "traffic interception",
              "lateral_movement": "lateral movement", "command_and_control": "remote control (beaconing)", "exfiltration": "data leaving the network"}
SOURCES = ("arp", "tls", "ipv6", "wireless", "bgp", "stp", "traffic", "lateral")


def label(probability: float) -> str:
    return "likely" if probability >= 0.7 else "possible" if probability >= 0.4 else "weak"


def analyze(ctx: Context) -> EngineOutput:
    sec = ctx.telemetry.security
    out = EngineOutput(checked=["security findings from every protocol engine", "IDS alerts", "shared hosts and timing", "authorised activity"])
    indicators = [(engine, d) for engine in SOURCES for d in ctx.prior.get(engine, []) if d.code in WEIGHT]
    alerts = list(sec.alerts) if sec else []
    allow = sec.allowlist if sec else None
    trusted = ({str(a) for a in allow.scanners} | {str(a) for a in allow.jump_hosts} | {str(a) for a in allow.backup_servers}) if allow else set()
    host_name = {str(h.ip): h.hostname for h in sec.hosts} if sec else {}
    benign_alerts = [a for a in alerts if str(a.src_ip) in trusted]
    alerts = [a for a in alerts if str(a.src_ip) not in trusted]
    # Union-find over indicators that share a host, plus alerts on those hosts.
    parent = list(range(len(indicators)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i, (_, a) in enumerate(indicators):
        for j in range(i):
            b = indicators[j][1]
            close = a.timestamp is None or b.timestamp is None or abs(a.timestamp - b.timestamp) <= JOIN
            if set(a.hosts) & set(b.hosts) and close:
                parent[find(i)] = find(j)
            elif a.code in ("ARP_GATEWAY_SPOOFING", "TLS_UNEXPECTED_CERTIFICATE") and b.code in ("ARP_GATEWAY_SPOOFING", "TLS_UNEXPECTED_CERTIFICATE") \
                    and a.code != b.code and a.site_id == b.site_id and close:
                parent[find(i)] = find(j)
    clusters = defaultdict(list)
    for i, item in enumerate(indicators):
        clusters[find(i)].append(item)
    for members in clusters.values():
        counts = defaultdict(int)
        first_seen = {}
        for _, d in sorted(members, key=lambda m: m[1].timestamp or ctx.window_end):
            for h in d.hosts:
                counts[h] += 1
                first_seen.setdefault(h, d.timestamp or ctx.window_end)
        # The host behind the most indicators comes first; ties go to whoever acted first.
        hosts = sorted(counts, key=lambda h: (-counts[h], first_seen[h], h))
        related_alerts = [a for a in alerts if str(a.src_ip) in hosts or str(a.dst_ip) in hosts]
        logit = math.log(PRIOR / (1 - PRIOR))
        per_engine = defaultdict(list)
        per_code = defaultdict(list)
        for engine, draft in members:
            per_engine[engine].append(draft.code)
            per_code[draft.code].append(WEIGHT[draft.code] + (0.5 if draft.facts.get("intel") else 0))
        for weights in per_code.values():
            weights.sort(reverse=True)
            logit += sum(w * (0.5 ** k) for k, w in enumerate(weights))  # the same behaviour seen again adds less each time
        logit += sum(ALERT_WEIGHT[a.severity] * (0.5 ** k) for k, a in enumerate(sorted(related_alerts, key=lambda a: -ALERT_WEIGHT[a.severity])))
        probability = min(CAP, 1 / (1 + math.exp(-logit)))
        stages = sorted({STAGE.get(d.code, "recon") for _, d in members} | {a.category for a in related_alerts if a.category in ORDER},
                        key=ORDER.index)
        times = [d.timestamp for _, d in members if d.timestamp] + [a.timestamp for a in related_alerts]
        sources = sorted(per_engine) + (["ids"] if related_alerts else [])
        site = next((d.site_id for _, d in members if d.site_id), None)
        main = hosts[0] if hosts else None
        names = [f"{h} ({host_name[h]})" if h in host_name else h for h in hosts[:3]]
        refs = [r for _, d in members for r in d.evidence[:1]] + [ref("ids_alerts", a.alert_id, a.timestamp) for a in related_alerts][:2]
        single = len(sources) == 1 and len(members) == 1
        out.drafts.append(Draft(
            "THREAT_CORRELATED_ACTIVITY", "suspicious_indicator", "threat_indicator", "critical" if probability >= 0.7 else "major",
            f"{label(probability).title()} malicious activity around {names[0] if names else site}",
            f"{len(members)} indicator(s) from {len(sources)} independent source(s) ({', '.join(sources)}) involve {', '.join(names) or 'the same segment'}"
            + (f", in the order {' → '.join(STAGE_TEXT[s] for s in stages)}" if len(stages) > 1 else f" ({STAGE_TEXT[stages[0]]})" if stages else "")
            + (f" between {min(times):%H:%M} and {max(times):%H:%M} UTC" if times else "") + f". Correlated likelihood {probability:.0%}"
            + (" from a single indicator, so treat it as weak." if single else ".")
            + " This describes behaviour only: it needs an analyst to confirm, and it says nothing about who is responsible.",
            "inferred", refs[:8], "independent indicators that share hosts and timing, scored with log-odds and capped below certainty",
            site_id=site, timestamp=min(times) if times else None, affected_sites=sorted({d.site_id for _, d in members if d.site_id}),
            hosts=hosts, corroboration=len(sources) - 1,
            facts={"probability": round(probability, 2), "likelihood": label(probability), "stages": stages, "sources": sources, "hosts": hosts,
                   "indicators": [d.code for _, d in members], "alerts": [a.alert_id for a in related_alerts], "main_host": main}))
    if benign_alerts:
        out.notes.append(f"{len(benign_alerts)} IDS alert(s) came from authorised hosts (scanner, jump host or backup) and were not counted.")
    for engine in ("traffic", "lateral"):
        for note in ctx.prior.get(f"{engine}:notes", []):
            if note.startswith("Suppressed"):
                out.notes.append(note)
    if not indicators:
        out.notes.append("No security indicators from any engine" + (f"; {len(alerts)} IDS alert(s) stand alone and were not escalated" if alerts else "")
                         + ". No correlated threat.")
    return out
