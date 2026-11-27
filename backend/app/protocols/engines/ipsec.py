"""IPsec VPN tunnel analysis: the two ends' IKE proposals and traffic selectors compared field by field, tunnels down
because the peer stopped answering (dead-peer detection), one-way tunnels and authentication failures.

Evidence is scoped to one tunnel: a log line counts for a tunnel only when it names both of that tunnel's endpoints (the
device and its peer) and falls inside the incident window. A hub terminates many tunnels, so a hub log about one peer
says nothing about the others."""
import re
from datetime import timedelta
from ipaddress import IPv4Network

from app.protocols.engines.base import Context, Draft, EngineOutput, ref

FIELDS = ("encryption", "integrity", "dh_group", "lifetime_seconds")
LABEL = {"encryption": "encryption", "integrity": "integrity", "dh_group": "DH group", "lifetime_seconds": "lifetime"}
CHANGE_TYPES = {"CONFIG_CHANGE", "CONFIG_COMMAND_LOGGED", "POLICY_CHANGE"}
ROUTE_REMOVED = re.compile(r"\b(?:static )?route\b.*\b(?:deleted|removed)\b|\bno ip route\b|\bdelete\b.*\broute\b", re.I)
PREFIX = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")
CHANGE_LOOKBACK = timedelta(hours=2)


def tunnel_events(events: list, device: str, peer: str, start, end, hubs: set[str]) -> list:
    """Log lines about this tunnel: both endpoints named, or (no peer logged) the logging device has no other tunnel."""
    ends = {device, peer}
    return [e for e in events if start <= e.timestamp <= end
            and ((e.peer is not None and {e.device_id, e.peer} == ends) or (e.peer is None and e.device_id in ends and e.device_id not in hubs))]


def return_route_changes(ctx: Context, far_end: str, protected: list, before) -> list:
    """Changes on the far end, shortly before the tunnel went one-way, that removed a route to the networks it protects."""
    nets = [IPv4Network(str(n)) for n in protected]
    found = []
    for event in ctx.dataset.events:
        if event.device_id != far_end or event.event_type not in CHANGE_TYPES or not ROUTE_REMOVED.search(event.message):
            continue
        if not (before - CHANGE_LOOKBACK <= event.timestamp <= ctx.window_end):
            continue
        prefixes = [IPv4Network(p, strict=False) for p in PREFIX.findall(event.message)]
        if any(a.overlaps(b) for a in prefixes for b in nets):
            found.append(event)
    return found


def analyze(ctx: Context) -> EngineOutput:
    data = ctx.telemetry.ipsec
    out = EngineOutput(checked=["phase 1 and phase 2 state", "IKE proposals on both ends", "traffic selectors on both ends", "dead-peer detection",
                                "encapsulation and decapsulation counters"])
    events = [e for e in ctx.telemetry.events if e.protocol == "ipsec"]
    by_pair = {(t.device_id, t.peer_device_id): t for t in data.tunnels}
    peers: dict[str, set[str]] = {}
    for device, peer in by_pair:
        peers.setdefault(device, set()).add(peer)
        peers.setdefault(peer, set()).add(device)
    hubs = {d for d, others in peers.items() if len(others) > 1}  # a log line on these that names no peer is ambiguous
    seen = set()
    mismatches: dict[tuple[str, tuple[str, ...]], list] = {}
    for (device, peer), tunnel in sorted(by_pair.items()):
        pair = frozenset((device, peer))
        if pair in seen:
            continue
        seen.add(pair)
        other = by_pair.get((peer, device))
        branch = device if ctx.site_of.get(device) != "CORE" else peer
        hub = peer if branch == device else device
        site = ctx.site_of.get(branch)
        refs = [ref("ipsec_tunnels", tunnel.tunnel_id, tunnel.last_change)] + ([ref("ipsec_tunnels", other.tunnel_id, other.last_change)] if other else [])
        logs = tunnel_events(events, device, peer, ctx.window_start - CHANGE_LOOKBACK, ctx.window_end, hubs)
        far = other.local_proposal if other else tunnel.peer_proposal
        mine = tunnel.local_proposal
        if far is not None:
            differs = [f for f in FIELDS if getattr(mine, f) != getattr(far, f)]
            if differs and tunnel.phase1 != "up":
                hub_tunnel = tunnel if tunnel.device_id == hub else other
                hub_value = {f: getattr(hub_tunnel.local_proposal, f) for f in differs} if hub_tunnel else {}
                branch_tunnel = other if hub_tunnel is tunnel else tunnel
                branch_value = {f: getattr(branch_tunnel.local_proposal, f) for f in differs} if branch_tunnel else {}
                proposal_logs = [e for e in logs if "PROPOSAL" in e.kind]
                mismatches.setdefault((hub, tuple(differs)), []).append((branch, site, refs, proposal_logs, tunnel, hub_value, branch_value))
                continue
        if other and (sorted(map(str, tunnel.local_selectors)) != sorted(map(str, (other.peer_selectors or [])))
                      or sorted(map(str, other.local_selectors)) != sorted(map(str, (tunnel.peer_selectors or [])))):
            out.drafts.append(Draft(
                "IPSEC_SELECTOR_MISMATCH", "confirmed_fault", "misconfiguration", "major", f"Traffic selector mismatch {hub} ↔ {branch}",
                f"{device} protects {', '.join(map(str, tunnel.local_selectors))} ↔ {', '.join(map(str, tunnel.peer_selectors or []))} but {peer} "
                f"protects {', '.join(map(str, other.local_selectors))} ↔ {', '.join(map(str, other.peer_selectors or []))}; phase 2 cannot agree.",
                "two_sided", refs, "the two ends' proxy IDs are not mirror images", device_id=hub, site_id=ctx.site_of.get(hub),
                timestamp=tunnel.last_change, affected_sites=[site] if site else [], facts={"device": device, "peer": peer}))
            continue
        auth_logs = [e for e in logs if "AUTH" in e.kind]
        if auth_logs:
            out.drafts.append(Draft(
                "IPSEC_AUTH_FAILURE", "confirmed_fault", "misconfiguration", "major", f"IKE authentication failing {hub} ↔ {branch}",
                f"{auth_logs[0].device_id} logged {sum(e.count for e in auth_logs)} IKE authentication failures with its peer.", "direct",
                refs + [ref("protocol_events", e.event_id, e.timestamp) for e in auth_logs][:2], "the device reports authentication failures",
                device_id=hub, site_id=ctx.site_of.get(hub), timestamp=auth_logs[0].timestamp, affected_sites=[site] if site else []))
            continue
        dpd = max(tunnel.dpd_timeouts, other.dpd_timeouts if other else 0)
        down = tunnel.phase1 != "up" or (other is not None and other.phase1 != "up")
        if down and dpd:
            dpd_logs = [e for e in logs if e.kind == "DPD_TIMEOUT"]
            underlay = tunnel.underlay_interface_id if tunnel.device_id == branch else (other.underlay_interface_id if other else None)
            out.drafts.append(Draft(
                "IPSEC_PEER_UNREACHABLE", "confirmed_fault", "dependency", "major", f"{tunnel.role.title()} tunnel {hub} ↔ {branch} down: peer unreachable",
                f"Dead-peer detection timed out {dpd} time(s) and the tunnel is down; the proposals match, so the tunnel is a casualty of "
                f"lost reachability" + (f" over {underlay}" if underlay else "") + ", not a VPN configuration problem.", "measured",
                refs + [ref("protocol_events", e.event_id, e.timestamp) for e in dpd_logs][:2],
                "DPD timeouts with matching configuration point at the underlay", device_id=branch, site_id=site,
                timestamp=min([tunnel.last_change] + [e.timestamp for e in dpd_logs]), affected_sites=[site] if site else [],
                facts={"dpd_timeouts": dpd, "underlay": underlay, "role": tunnel.role}))
            continue
        if down:
            out.drafts.append(Draft(
                "IPSEC_TUNNEL_DOWN", "possible_explanation", "anomaly", "major", f"Tunnel {hub} ↔ {branch} down, cause not logged",
                f"The {tunnel.role} tunnel is {tunnel.phase1} with {tunnel.phase2_sas} phase 2 SAs; no proposal, selector, authentication or DPD "
                "evidence explains it.", "measured", refs, "the tunnel is down but the collected data does not say why", device_id=hub,
                site_id=ctx.site_of.get(hub), timestamp=tunnel.last_change, affected_sites=[site] if site else []))
            continue
        for view in (tunnel, other):
            if view and view.phase1 == "up" and view.encaps > 100 and view.decaps == 0:
                far_end = view.peer_device_id
                far = other if view is tunnel else tunnel
                refs_one_way = [ref("ipsec_tunnels", view.tunnel_id, view.last_change)]
                if far is not None:
                    refs_one_way.append(ref("ipsec_tunnels", far.tunnel_id, far.last_change))
                removed = return_route_changes(ctx, far_end, view.local_selectors, view.last_change)
                refs_one_way += [ref("events", e.event_id, e.timestamp) for e in removed[:2]]
                protected = ", ".join(map(str, view.local_selectors))
                if removed:
                    title = f"One-way tunnel {view.tunnel_id}: {far_end} has no return route to {protected}"
                    summary = (f"{view.device_id} has sent {view.encaps:,} packets into the tunnel and received none back"
                               + (f", while {far_end} decrypted {far.decaps:,}" if far is not None and far.decaps else "")
                               + f". {far_end} logged a change at {removed[0].timestamp:%H:%M} UTC removing its route to {protected} through the "
                               "tunnel, so replies have no way back. Check the route on the far end before anything else.")
                else:
                    title = f"One-way traffic on {view.tunnel_id}"
                    summary = (f"{view.device_id} has sent {view.encaps:,} packets into the tunnel and received none back: return routing, a filter or "
                               "NAT on the far side is likely.")
                out.drafts.append(Draft(
                    "IPSEC_ONE_WAY", "possible_explanation", "anomaly", "major", title, summary, "measured", refs_one_way,
                    "encapsulation counters rise while decapsulation stays at zero", device_id=view.device_id,
                    # The counters say traffic is one-way now, not since when; a route removal on the far end dates it better.
                    site_id=ctx.site_of.get(view.device_id), timestamp=removed[0].timestamp if removed else view.last_change,
                    affected_sites=[site] if site else [], corroboration=int(bool(removed)),
                    facts={"tunnel": view.tunnel_id, "hub": far_end, "sent": view.encaps, "received": view.decaps,
                           "protected": [str(n) for n in view.local_selectors],
                           "return_route_removed": [e.event_id for e in removed]}))
    for (hub, differs), rows in sorted(mismatches.items()):
        branches = [r[0] for r in rows]
        hub_value, branch_value = rows[0][5], rows[0][6]
        detail = "; ".join(f"{LABEL[f]} {hub_value.get(f)} on {hub} vs {branch_value.get(f)} on the branches" for f in differs)
        logs = [e for r in rows for e in r[3]]
        out.drafts.append(Draft(
            "IPSEC_PROPOSAL_MISMATCH", "confirmed_fault", "misconfiguration", "major", f"IKE proposal mismatch on {hub} ({len(branches)} tunnel(s))",
            f"The {rows[0][4].role} tunnels from {hub} to {', '.join(branches)} are down because the proposals differ: {detail}."
            + (f" {hub} logged {sum(e.count for e in logs)} NO_PROPOSAL_CHOSEN failures." if logs else ""),
            "two_sided", [x for r in rows for x in r[2]][:6] + [ref("protocol_events", e.event_id, e.timestamp) for e in logs][:2],
            "both ends' proposals are known and they share no acceptable combination", device_id=hub, site_id=ctx.site_of.get(hub),
            timestamp=min([r[4].last_change for r in rows] + [e.timestamp for e in logs]), affected_sites=sorted({r[1] for r in rows if r[1]}),
            corroboration=int(bool(logs)), facts={"fields": list(differs), "hub": hub_value, "branch": branch_value, "branches": branches}))
    return out
