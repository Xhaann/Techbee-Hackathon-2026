"""Suspicious traffic detection over flow records and DNS logs: port sweeps, periodic beaconing, large uploads to
outside addresses, DNS tunnelling and contact with (synthetic) threat-intelligence indicators. Authorised scanners,
backup servers and allowlisted periodic destinations are recognised and reported as suppressed, not as findings."""
from collections import defaultdict
from statistics import pstdev

from app.protocols.engines.base import Context, Draft, EngineOutput, has_injection, internal, mean, ref

SWEEP_TARGETS = 50
SWEEP_FAILED = 0.7
BEACON_MIN = 6
BEACON_JITTER = 0.1
UPLOAD_BYTES = 500_000_000
TUNNEL_QUERIES = 100
TUNNEL_LABEL = 30


def registered(qname: str) -> str:
    return ".".join(qname.split(".")[-2:])


def analyze(ctx: Context) -> EngineOutput:
    sec = ctx.telemetry.security
    allow = sec.allowlist
    scanners = {str(a) for a in allow.scanners}
    backups = {str(a) for a in allow.backup_servers}
    periodic = set(allow.periodic_destinations)
    intel = {i.indicator: i for i in sec.intel}
    host_name = {str(h.ip): h.hostname for h in sec.hosts}
    out = EngineOutput(checked=["fan-out to many hosts and ports", "connection timing regularity", "outbound volume", "DNS query names",
                                "threat-intelligence indicators (synthetic)"])
    suppressed = []

    def who(ip: str) -> str:
        return f"{ip} ({host_name[ip]})" if ip in host_name else ip

    # ---- sweeps
    by_src = defaultdict(list)
    for flow in sec.flows:
        by_src[str(flow.src_ip)].append(flow)
    for src, flows in sorted(by_src.items()):
        targets = {(str(f.dst_ip), f.dst_port) for f in flows if f.dst_port}
        failed = [f for f in flows if f.state in ("rejected", "no_reply")]
        if len(targets) < SWEEP_TARGETS or len(failed) / max(len(flows), 1) < SWEEP_FAILED:
            continue
        hosts = len({t[0] for t in targets})
        ports = sorted({t[1] for t in targets})
        if src in scanners:
            suppressed.append(f"{who(src)} swept {hosts} hosts on ports {', '.join(map(str, ports[:6]))}: it is the authorised vulnerability scanner")
            continue
        first = min(f.start for f in flows)
        site = ctx.site_of_ip(src)
        out.drafts.append(Draft(
            "SUSPICIOUS_PORT_SCAN", "suspicious_indicator", "threat_indicator", "major", f"{who(src)} swept {hosts} hosts",
            f"{who(src)} tried {len(targets)} host/port combinations on {hosts} hosts (ports {', '.join(map(str, ports[:8]))}) from "
            f"{first:%H:%M} UTC; {len(failed)} of {len(flows)} attempts were refused or unanswered. It is not an authorised scanner.",
            "behavioural", [ref("security_flows", f.flow_id, f.start) for f in failed][:6], "a burst of short failed connections to many hosts and admin ports",
            site_id=site, timestamp=first, affected_sites=[site] if site else [], hosts=[src],
            facts={"source": src, "hosts": hosts, "ports": ports, "attempts": len(flows), "failed": len(failed), "stage": "recon"}))
    # ---- beaconing
    by_pair = defaultdict(list)
    for flow in sec.flows:
        if not internal(flow.dst_ip):
            by_pair[(str(flow.src_ip), str(flow.dst_ip), flow.dst_port)].append(flow)
    for (src, dst, port), flows in sorted(by_pair.items()):
        if len(flows) < BEACON_MIN:
            continue
        starts = sorted(f.start for f in flows)
        gaps = [(b - a).total_seconds() for a, b in zip(starts, starts[1:])]
        average = mean(gaps)
        if average <= 0 or pstdev(gaps) / average > BEACON_JITTER:
            continue
        if dst in periodic:
            suppressed.append(f"{who(src)} contacts {dst} every {average / 60:.0f} min: an allowlisted update service")
            continue
        listed = intel.get(dst)
        site = ctx.site_of_ip(src)
        out.drafts.append(Draft(
            "SUSPICIOUS_BEACONING", "suspicious_indicator", "threat_indicator", "critical" if listed else "major",
            f"{who(src)} beacons to {dst} every {average:.0f} s",
            f"{who(src)} opened {len(flows)} connections to {dst}:{port} at a near-constant {average:.0f}-second interval (jitter "
            f"{100 * pstdev(gaps) / average:.0f}%), each small. Regular, automated contact with an outside address is how remote-control "
            "software checks in." + (f" {dst} is on the threat list: {listed.label}." if listed else " The address is not allowlisted."),
            "behavioural", [ref("security_flows", f.flow_id, f.start) for f in flows][:6], "machine-regular connections to an outside address",
            site_id=site, timestamp=starts[0], affected_sites=[site] if site else [], hosts=[src], corroboration=int(bool(listed)),
            facts={"source": src, "destination": dst, "port": port, "interval_seconds": round(average), "connections": len(flows),
                   "intel": listed.label if listed else None, "stage": "command_and_control"}))
    # ---- large uploads
    for flow in sec.flows:
        src, dst = str(flow.src_ip), str(flow.dst_ip)
        if flow.bytes_out < UPLOAD_BYTES or internal(dst):
            continue
        if src in backups or dst in periodic:
            suppressed.append(f"{who(src)} sent {flow.bytes_out / 1e9:.1f} GB to {dst}: an authorised backup or allowlisted destination")
            continue
        listed = intel.get(dst)
        site = ctx.site_of_ip(src)
        out.drafts.append(Draft(
            "SUSPICIOUS_LARGE_UPLOAD", "suspicious_indicator", "threat_indicator", "critical", f"{who(src)} uploaded {flow.bytes_out / 1e9:.1f} GB externally",
            f"{who(src)} sent {flow.bytes_out / 1e9:.1f} GB to {dst}:{flow.dst_port} in {flow.duration_seconds / 60:.0f} minutes at "
            f"{flow.start:%H:%M} UTC" + (f"; {dst} is on the threat list ({listed.label})" if listed else "") + ". Workstations rarely upload this much.",
            "behavioural", [ref("security_flows", flow.flow_id, flow.start)], "outbound volume far above what a workstation sends",
            site_id=site, timestamp=flow.start, affected_sites=[site] if site else [], hosts=[src], corroboration=int(bool(listed)),
            facts={"source": src, "destination": dst, "bytes": flow.bytes_out, "intel": listed.label if listed else None, "stage": "exfiltration"}))
    # ---- DNS tunnelling
    by_client = defaultdict(lambda: defaultdict(list))
    injected = 0
    for log in sec.dns_logs:
        if has_injection(log.qname.replace("-", " ")):
            injected += 1
        by_client[str(log.client_ip)][registered(log.qname)].append(log)
    for client, domains in sorted(by_client.items()):
        for domain, logs in sorted(domains.items()):
            labels = [len(log.qname.split(".")[0]) for log in logs]
            txt = sum(1 for log in logs if log.qtype in ("TXT", "NULL")) / len(logs)
            if len(logs) < TUNNEL_QUERIES or (mean(labels) < TUNNEL_LABEL and txt < 0.5):
                continue
            listed = intel.get(domain)
            site = ctx.site_of_ip(client)
            out.drafts.append(Draft(
                "SUSPICIOUS_DNS_TUNNELING", "suspicious_indicator", "threat_indicator", "critical", f"{who(client)} tunnels through DNS to {domain}",
                f"{who(client)} sent {len(logs)} queries under {domain} in {(logs[-1].timestamp - logs[0].timestamp).total_seconds() / 60:.0f} minutes, "
                f"with random-looking labels averaging {mean(labels):.0f} characters and {100 * txt:.0f}% TXT records. That is data carried "
                "inside DNS names, not normal lookups." + (f" {domain} is on the threat list ({listed.label})." if listed else ""),
                "behavioural", [ref("dns_logs", log.log_id, log.timestamp) for log in logs][:6], "many long random subdomains of one domain, mostly TXT",
                site_id=site, timestamp=logs[0].timestamp, affected_sites=[site] if site else [], hosts=[client], corroboration=int(bool(listed)),
                facts={"client": client, "domain": domain, "queries": len(logs), "average_label": round(mean(labels)), "txt_share": round(txt, 2),
                       "intel": listed.label if listed else None, "stage": "exfiltration"}))
    # ---- intel contact not already covered above
    reported = {(d.facts.get("source") or d.facts.get("client"), d.facts.get("destination") or d.facts.get("domain")) for d in out.drafts}
    for flow in sec.flows:
        listed = intel.get(str(flow.dst_ip))
        if listed and (str(flow.src_ip), str(flow.dst_ip)) not in reported:
            reported.add((str(flow.src_ip), str(flow.dst_ip)))
            site = ctx.site_of_ip(flow.src_ip)
            out.drafts.append(Draft(
                "SUSPICIOUS_THREAT_INTEL_MATCH", "suspicious_indicator", "threat_indicator", "major", f"{who(str(flow.src_ip))} contacted a listed address",
                f"{who(str(flow.src_ip))} connected to {flow.dst_ip}:{flow.dst_port}, listed as: {listed.label}.", "behavioural",
                [ref("security_flows", flow.flow_id, flow.start)], "contact with a listed indicator", site_id=site, timestamp=flow.start,
                affected_sites=[site] if site else [], hosts=[str(flow.src_ip)], facts={"destination": str(flow.dst_ip), "intel": listed.label,
                                                                                        "stage": "command_and_control"}))
    if injected:
        out.notes.append(f"{injected} DNS name(s) contained instruction-like text; they were treated as data and ignored.")
    for line in suppressed[:5]:
        out.notes.append(f"Suppressed: {line}.")
    if len(sec.collected_from) < 3:
        out.missing.append(f"Flow records come only from {', '.join(sec.collected_from)}; traffic inside a site is not visible.")
    return out
