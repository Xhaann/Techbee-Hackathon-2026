"""Lateral movement indicators from internal flows and authentication events: one host opening admin sessions to many
others, credential spraying that ends in a success, a second host that starts doing the same after being reached (a
chain), and admin traffic crossing from user to server segments. Jump hosts and scanners are recognised and suppressed.
Without east-west sensors the engine says it cannot see this traffic instead of reporting nothing."""
from collections import defaultdict
from datetime import timedelta

from app.protocols.engines.base import Context, Draft, EngineOutput, internal, ref

ADMIN_PORTS = {22, 135, 139, 445, 3389, 5985, 5986}
FANOUT = 3
SPRAY_HOSTS = 5
SPRAY_FAILURES = 10
WINDOW = timedelta(minutes=20)


def analyze(ctx: Context) -> EngineOutput:
    sec = ctx.telemetry.security
    allow = sec.allowlist
    trusted = {str(a) for a in allow.jump_hosts} | {str(a) for a in allow.scanners} | {str(a) for a in allow.backup_servers}
    host_name = {str(h.ip): h.hostname for h in sec.hosts}
    out = EngineOutput(checked=["admin-protocol sessions between internal hosts", "failed then successful authentications", "hop chains",
                                "user-to-server segmentation", "east-west sensor coverage"])

    def who(ip: str) -> str:
        return f"{ip} ({host_name[ip]})" if ip in host_name else ip

    switches = {f"{s}-SW-01" for s in ("NYC", "SIN", "BLR")}
    blind = sorted(switches - set(sec.collected_from))
    if blind:
        out.drafts.append(Draft(
            "LATERAL_VISIBILITY_GAP", "insufficient_evidence", "coverage", "info", "East-west traffic not visible",
            f"No flow records from {', '.join(blind)}: host-to-host traffic inside those sites cannot be checked, so the absence of lateral-movement "
            "findings there means nothing.", "none", [ref("security_flows", f.flow_id, f.start) for f in sec.flows][:1],
            "sensor coverage is missing for internal segments", facts={"missing_sensors": blind}))
    admin = [f for f in sec.flows if f.dst_port in ADMIN_PORTS and internal(f.src_ip) and internal(f.dst_ip)]
    established = [f for f in admin if f.state == "established"]
    suppressed = sorted({who(str(f.src_ip)) for f in established if str(f.src_ip) in trusted})
    by_src = defaultdict(list)
    for flow in established:
        if str(flow.src_ip) not in trusted:
            by_src[str(flow.src_ip)].append(flow)
    fanout_hosts = {}
    for src, flows in sorted(by_src.items()):
        flows.sort(key=lambda f: f.start)
        targets = sorted({str(f.dst_ip) for f in flows if f.start - flows[0].start <= WINDOW})
        if len(targets) < FANOUT:
            continue
        site = ctx.site_of_ip(src)
        fanout_hosts[src] = (targets, flows[0].start)
        out.drafts.append(Draft(
            "LATERAL_ADMIN_FANOUT", "suspicious_indicator", "threat_indicator", "critical", f"{who(src)} opened admin sessions to {len(targets)} hosts",
            f"{who(src)} opened {', '.join(sorted({f'{f.dst_port}' for f in flows}))} sessions to {len(targets)} internal hosts "
            f"({', '.join(targets[:4])}) from {flows[0].start:%H:%M} UTC. It is not a jump host; a workstation administering its peers is a "
            "lateral-movement pattern.", "behavioural", [ref("security_flows", f.flow_id, f.start) for f in flows][:6],
            "established admin-protocol sessions from one non-admin host to several others", site_id=site, timestamp=flows[0].start,
            affected_sites=[site] if site else [], hosts=[src],
            facts={"source": src, "targets": targets, "ports": sorted({f.dst_port for f in flows}), "stage": "lateral_movement"}))
    auth_by_src = defaultdict(list)
    for event in sec.auth:
        auth_by_src[str(event.src_ip)].append(event)
    for src, events in sorted(auth_by_src.items()):
        if src in trusted:
            continue
        events.sort(key=lambda e: e.timestamp)
        failures = [e for e in events if e.result == "failure"]
        hosts = {e.dst_host for e in failures}
        if len(failures) < SPRAY_FAILURES or len(hosts) < SPRAY_HOSTS:
            continue
        later = [e for e in events if e.result == "success" and e.timestamp > failures[0].timestamp]
        accounts = sorted({e.account for e in failures})
        site = ctx.site_of_ip(src)
        out.drafts.append(Draft(
            "LATERAL_CREDENTIAL_SPRAY", "suspicious_indicator", "threat_indicator", "critical", f"{who(src)} sprayed credentials at {len(hosts)} hosts",
            f"{who(src)} failed {len(failures)} {failures[0].protocol.upper()} logons across {len(hosts)} hosts with {', '.join(accounts[:3])}"
            + (f", then succeeded as {', '.join(sorted({e.account for e in later}))} on {len({e.dst_host for e in later})} host(s)." if later else "."),
            "behavioural", [ref("auth_events", e.auth_id, e.timestamp) for e in failures][:4] + [ref("auth_events", e.auth_id, e.timestamp) for e in later][:2],
            "many failed logons across hosts followed by success", site_id=site, timestamp=failures[0].timestamp, affected_sites=[site] if site else [],
            hosts=[src], corroboration=int(bool(later)),
            facts={"source": src, "failures": len(failures), "hosts": len(hosts), "accounts": accounts, "succeeded_as": sorted({e.account for e in later}),
                   "stage": "credential_access"}))
    reached = defaultdict(list)
    for flow in established:
        reached[str(flow.dst_ip)].append(flow)
    for victim, inbound in sorted(reached.items()):
        sources = {str(f.src_ip) for f in inbound} - trusted
        if not sources:
            continue
        first_in = min(f.start for f in inbound if str(f.src_ip) in sources)
        onward = [f for f in sec.flows if str(f.src_ip) == victim and f.dst_port in ADMIN_PORTS and f.start > first_in]
        if not onward:
            continue
        origin = sorted(sources)[0]
        hops = [origin, victim] + sorted({str(f.dst_ip) for f in onward})[:3]
        site = ctx.site_of_ip(victim)
        out.drafts.append(Draft(
            "LATERAL_MOVEMENT_CHAIN", "suspicious_indicator", "threat_indicator", "critical", f"Movement chain {who(origin)} → {who(victim)} → …",
            f"{who(victim)} was reached over admin protocols by {who(origin)} at {first_in:%H:%M} UTC and then itself opened admin sessions to "
            f"{', '.join(hops[2:])} ({sum(1 for f in onward if f.state == 'established')} established, "
            f"{sum(1 for f in onward if f.state != 'established')} blocked).", "behavioural",
            [ref("security_flows", f.flow_id, f.start) for f in inbound][:2] + [ref("security_flows", f.flow_id, f.start) for f in onward][:4],
            "a host starts the same behaviour right after being reached", site_id=site, timestamp=first_in, affected_sites=[site] if site else [],
            hosts=hops[:2], facts={"chain": hops, "stage": "lateral_movement"}))
    user_nets = [(net, site) for net, site, vlan in ctx.site_networks if vlan == 10]
    server_net = next((net for net, site, vlan in ctx.site_networks if vlan == 100), None)
    crossing = [f for f in admin if server_net and f.dst_ip in server_net and any(f.src_ip in n for n, _ in user_nets) and str(f.src_ip) not in trusted]
    allowed = [f for f in crossing if f.state == "established" and f.dst_port != 22]
    blocked = [f for f in crossing if f.state != "established"]
    if allowed:
        out.drafts.append(Draft(
            "LATERAL_SEGMENTATION_GAP", "suspicious_indicator", "threat_indicator", "major", "Admin traffic from user VLANs reaches servers",
            f"{len(allowed)} admin-protocol session(s) from user VLANs to the server VLAN were allowed; segmentation should stop these.",
            "behavioural", [ref("security_flows", f.flow_id, f.start) for f in allowed][:4], "admin protocols cross from user to server segments",
            hosts=sorted({str(f.src_ip) for f in allowed})[:3], facts={"sessions": len(allowed)}))
    elif blocked:
        out.notes.append(f"Segmentation held: {len(blocked)} admin-protocol attempt(s) from user VLANs to servers were blocked.")
    if suppressed:
        out.notes.append(f"Suppressed: admin sessions from {', '.join(suppressed[:3])} (authorised jump host or scanner).")
    return out
