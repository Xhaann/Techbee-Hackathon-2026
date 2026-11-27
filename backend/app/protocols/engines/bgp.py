"""BGP route anomaly detection: origin validation against the prefix registry, more-specific leaks, withdrawal bursts,
route flaps, unreachable next hops and sessions whose two ends disagree."""
from collections import defaultdict
from datetime import timedelta
from ipaddress import IPv4Address, IPv4Network

from app.protocols.engines.base import Context, Draft, EngineOutput, ref

BURST = timedelta(seconds=60)
BURST_MIN = 3
FLAP_CYCLES = 3


def authorization(ctx: Context, prefix: IPv4Network):
    covering = [a for a in ctx.telemetry.bgp.authorizations if prefix.subnet_of(a.prefix)]
    return max(covering, key=lambda a: a.prefix.prefixlen, default=None)


def hosts_in(ctx: Context, prefix: IPv4Network) -> list[str]:
    return sorted(d.device_id for d in ctx.topology.devices if d.management_ip in prefix)


def analyze(ctx: Context) -> EngineOutput:
    bgp = ctx.telemetry.bgp
    out = EngineOutput(checked=["sessions (both ends)", "origin AS and prefix length against the prefix registry", "update history",
                                "next-hop reachability"])
    # ---- sessions: down, or the two ends disagree
    by_pair = {(s.device_id, s.peer_device_id): s for s in bgp.sessions}
    seen = set()
    down_pairs = []
    for (a, b), session in sorted(by_pair.items()):
        pair = frozenset((a, b))
        if pair in seen:
            continue
        seen.add(pair)
        reverse = by_pair.get((b, a))
        states = [session.state] + ([reverse.state] if reverse else [])
        refs = [ref("bgp_sessions", session.session_id, session.last_change)] + ([ref("bgp_sessions", reverse.session_id, reverse.last_change)] if reverse else [])
        up = [s == "established" for s in states]
        if reverse and any(up) and not all(up):
            down_side = a if session.state != "established" else b
            out.drafts.append(Draft(
                "BGP_SESSION_STATE_CONFLICT", "possible_explanation", "conflicting_state", "minor",
                f"BGP session {a} ↔ {b}: the two ends disagree",
                f"{a} reports the session {session.state} and {b} reports it {reverse.state}. One view is stale or the session is half-open; "
                "routes may still be held on one side.", "measured", refs,
                "two collections of the same session contradict each other, so neither can be taken as the truth yet",
                device_id=down_side, site_id=ctx.site_of.get(down_side), timestamp=max(session.last_change, reverse.last_change),
                affected_sites=sorted({ctx.site_of.get(a), ctx.site_of.get(b)} - {None, "CORE"}),
                facts={"states": {a: session.state, b: reverse.state}}))
        elif not any(up):
            down_pairs.append((a, b, session, reverse, states, refs))
    involvement = defaultdict(list)
    for row in down_pairs:
        involvement[row[0]].append(row)
        involvement[row[1]].append(row)
    hub = max(involvement, key=lambda d: len(involvement[d]), default=None)
    if hub and len(involvement[hub]) >= 2 and len(involvement[hub]) == len(down_pairs):
        peers = sorted({r[1] if r[0] == hub else r[0] for r in down_pairs})
        out.drafts.append(Draft(
            "BGP_SESSION_DOWN", "confirmed_fault", "anomaly", "major", f"{hub} lost BGP to {len(peers)} peers",
            f"Every BGP session of {hub} is down ({', '.join(peers)}) since {min(r[2].last_change for r in down_pairs):%H:%M} UTC: the common "
            f"end, {hub}, is the place to look.", "two_sided", [x for r in down_pairs for x in r[5]][:6],
            "all sessions that share one router are down at once", device_id=hub, site_id=ctx.site_of.get(hub),
            timestamp=min(r[2].last_change for r in down_pairs), affected_sites=sorted({ctx.site_of.get(p) for p in peers} - {None, "CORE"}),
            facts={"device": hub, "peers": peers}))
        down_pairs = []
    for a, b, session, reverse, states, refs in down_pairs:
        branch = b if ctx.site_of.get(a) == "CORE" else a
        out.drafts.append(Draft(
            "BGP_SESSION_DOWN", "confirmed_fault", "anomaly", "major", f"BGP session {a} ↔ {b} is down",
            f"The BGP session between {a} and {b} is {session.state}" + (" on both ends" if reverse else "") +
            f" since {session.last_change:%H:%M} UTC.", "two_sided" if reverse else "direct", refs,
            "both ends report the session not established" if reverse else "the device reports the session not established",
            device_id=branch, site_id=ctx.site_of.get(branch), timestamp=session.last_change,
            affected_sites=sorted({ctx.site_of.get(a), ctx.site_of.get(b)} - {None, "CORE"}), facts={"states": [str(s) for s in states]}))
    # ---- origin validation and more-specific leaks, grouped per prefix
    routes_by_prefix = defaultdict(list)
    for route in bgp.routes:
        routes_by_prefix[route.prefix].append(route)
    for prefix, routes in sorted(routes_by_prefix.items(), key=lambda item: (item[0].network_address, item[0].prefixlen)):
        auth = authorization(ctx, prefix)
        if auth is None:
            continue
        bad_origin = [r for r in routes if r.origin_asn != auth.origin_asn]
        too_long = prefix.prefixlen > auth.max_length
        if not bad_origin and not too_long:
            continue
        origin = (bad_origin or routes)[0].origin_asn
        internal_origin = origin in ctx.asns
        seen_on = sorted({r.device_id for r in routes})
        originator = next((r.device_id for r in routes if r.peer_device_id is None), None)
        servers = hosts_in(ctx, prefix)
        # Whose traffic the route steals: the users of the servers it covers, else the site that owns those addresses (a
        # more-specific of a branch subnet hurts that branch, not the site where the route is announced), else where it is seen.
        owners = sorted({site for network, site, _ in ctx.site_networks if network.overlaps(prefix)} - {"CORE", "DC1"})
        affected = (ctx.sites_served_by(servers) if servers else owners
                    or sorted({ctx.site_of.get(d) for d in seen_on} - {None, "CORE"}))
        problems = []
        if bad_origin:
            problems.append(f"originated by AS{origin} instead of the registered AS{auth.origin_asn}")
        if too_long:
            problems.append(f"a /{prefix.prefixlen}, longer than the registered maximum /{auth.max_length} for {auth.prefix}")
        refs = [ref("bgp_routes", r.route_id, r.learned_at) for r in routes][:6]
        refs += [ref("bgp_updates", u.update_id, u.timestamp) for u in bgp.updates if u.prefix == prefix][:2]
        services = f"; it covers {', '.join(servers)}" if servers else ""
        if internal_origin:
            out.drafts.append(Draft(
                "BGP_ROUTE_LEAK", "confirmed_fault", "misconfiguration", "critical", f"BGP leak of {prefix} from AS{origin}",
                f"{prefix} is {' and '.join(problems)}. It is in the routing table of {', '.join(seen_on)}{services}, so longest-prefix "
                "match pulls that traffic towards " + (originator or f"AS{origin}") + ".",
                "two_sided" if len(seen_on) > 1 else "direct", refs,
                f"the route is present in {len(seen_on)} routing table(s) with an origin and length the registry does not allow, from one of "
                "our own ASes, which makes it a configuration leak rather than an outside hijack",
                device_id=originator or seen_on[0], site_id=ctx.site_of.get(originator or seen_on[0]),
                timestamp=min(r.learned_at for r in routes), affected_sites=affected,
                facts={"prefix": str(prefix), "origin_asn": origin, "registered_origin": auth.origin_asn, "registered_prefix": str(auth.prefix),
                       "max_length": auth.max_length, "seen_on": seen_on, "covers": servers,
                       "as_paths": sorted({" ".join(map(str, r.as_path)) or "local" for r in routes})}))
        else:
            out.drafts.append(Draft(
                "BGP_ORIGIN_HIJACK_SUSPECTED", "suspicious_indicator", "threat_indicator", "critical", f"Unexpected origin AS{origin} for {prefix}",
                f"{prefix} is {' and '.join(problems)}; AS{origin} is not one of ours. This matches a hijack or an upstream leak; the data "
                "cannot tell which, and says nothing about who is behind it.", "direct", refs,
                "the origin AS is outside our network and not authorised for the prefix", device_id=seen_on[0],
                site_id=ctx.site_of.get(seen_on[0]), timestamp=min(r.learned_at for r in routes), affected_sites=affected,
                facts={"prefix": str(prefix), "origin_asn": origin, "registered_origin": auth.origin_asn, "seen_on": seen_on}))
    # ---- update history: withdrawal bursts and flaps
    by_peer = defaultdict(list)
    for update in bgp.updates:
        by_peer[(update.device_id, update.peer_device_id)].append(update)
    for (device, peer), updates in sorted(by_peer.items()):
        updates.sort(key=lambda u: u.timestamp)
        withdrawals = [u for u in updates if u.action == "withdraw"]
        burst = [u for u in withdrawals if u.timestamp - withdrawals[0].timestamp <= BURST] if withdrawals else []
        cycles = defaultdict(int)
        last = {}
        for update in updates:
            if last.get(update.prefix) == "withdraw" and update.action == "announce":
                cycles[update.prefix] += 1
            last[update.prefix] = update.action
        flapping = sorted((p for p, n in cycles.items() if n >= FLAP_CYCLES), key=str)
        branch = peer if ctx.site_of.get(device) == "CORE" else device
        affected = sorted({ctx.site_of.get(peer), ctx.site_of.get(device)} - {None, "CORE"})
        if flapping:
            refs = [ref("bgp_updates", u.update_id, u.timestamp) for u in updates if u.prefix in flapping][:8]
            out.drafts.append(Draft(
                "BGP_ROUTE_FLAP", "confirmed_fault", "anomaly", "major", f"{len(flapping)} BGP route(s) flapping from {peer}",
                f"{device} saw {', '.join(map(str, flapping))} withdrawn and re-announced by {peer} at least {FLAP_CYCLES} times.",
                "measured", refs, f"at least {FLAP_CYCLES} withdraw/announce cycles per prefix in the window", device_id=branch,
                site_id=ctx.site_of.get(branch), timestamp=updates[0].timestamp, affected_sites=affected,
                facts={"prefixes": [str(p) for p in flapping], "cycles": {str(p): cycles[p] for p in flapping}}))
        elif len(burst) >= BURST_MIN:
            restored = [u for u in updates if u.action == "announce" and u.timestamp > burst[-1].timestamp and u.prefix in {b.prefix for b in burst}]
            refs = [ref("bgp_updates", u.update_id, u.timestamp) for u in burst][:6] + [ref("bgp_updates", u.update_id, u.timestamp) for u in restored][:2]
            back = (f" They were re-announced at {restored[-1].timestamp:%H:%M} UTC, after "
                    f"{int((restored[0].timestamp - burst[0].timestamp).total_seconds() // 60)} minutes.") if restored else " They have not come back."
            out.drafts.append(Draft(
                "BGP_WITHDRAWAL_BURST", "confirmed_fault", "anomaly", "major", f"{len(burst)} routes withdrawn at once by {peer}",
                f"{device} lost {len(burst)} prefixes from {peer} within a minute at {burst[0].timestamp:%H:%M} UTC.{back}", "measured", refs,
                "several prefixes withdrawn by one peer at the same moment points at the session or the link under it, not the prefixes",
                device_id=branch, site_id=ctx.site_of.get(branch), timestamp=burst[0].timestamp, affected_sites=affected,
                facts={"withdrawn": len(burst), "restored": len(restored), "prefixes": sorted({str(u.prefix) for u in burst})}))
    # ---- next hops
    connected = defaultdict(list)
    for interface in ctx.topology.interfaces:
        if interface.ip_address is not None:
            connected[interface.device_id].append(interface.ip_address.network)
    for route in bgp.routes:
        if route.peer_device_id is None or route.next_hop == IPv4Address("0.0.0.0"):
            continue
        if not any(route.next_hop in network for network in connected[route.device_id]):
            out.drafts.append(Draft(
                "BGP_NEXT_HOP_UNREACHABLE", "confirmed_fault", "misconfiguration", "major", f"Unreachable BGP next hop on {route.device_id}",
                f"{route.device_id} holds {route.prefix} via {route.next_hop}, which is not on any of its connected networks.", "direct",
                [ref("bgp_routes", route.route_id, route.learned_at)], "the next hop is not directly reachable from the router",
                device_id=route.device_id, site_id=ctx.site_of.get(route.device_id), timestamp=route.learned_at,
                facts={"prefix": str(route.prefix), "next_hop": str(route.next_hop)}))
    prepended = sorted({f"{r.prefix} (AS path {' '.join(map(str, r.as_path))})" for r in bgp.routes if len(r.as_path) != len(set(r.as_path))})
    if prepended:
        out.notes.append(f"AS-path prepending seen on {len(prepended)} route(s), for example {prepended[0]}: normal traffic engineering, not an anomaly.")
    return out
