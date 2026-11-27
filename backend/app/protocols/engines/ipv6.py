"""IPv6 routing diagnosis: OSPFv3 adjacencies (and whether IPv4 OSPF on the same link disagrees), missing default and
site routes, dual-stack probes where IPv6 fails while IPv4 works, and router advertisements from unknown sources or with
broken parameters."""
from app.protocols.engines.base import Context, Draft, EngineOutput, ref


def analyze(ctx: Context) -> EngineOutput:
    v6 = ctx.telemetry.ipv6
    out = EngineOutput(checked=["OSPFv3 adjacencies against IPv4 OSPF on the same links", "default and site routes", "dual-stack probes",
                                "router advertisements"])
    events = [e for e in ctx.telemetry.events if e.protocol == "ipv6"]
    v4 = {(n.device_id, n.neighbor_device_id): n.state.value for n in ctx.dataset.routing.ospf_neighbors}
    seen = set()
    for neighbour in v6.neighbors:
        pair = frozenset((neighbour.device_id, neighbour.neighbor_device_id))
        if neighbour.state == "full" or pair in seen:
            continue
        seen.add(pair)
        other = next((n for n in v6.neighbors if n.device_id == neighbour.neighbor_device_id and n.neighbor_device_id == neighbour.device_id), None)
        branch = neighbour.device_id if ctx.site_of.get(neighbour.device_id) != "CORE" else neighbour.neighbor_device_id
        v4_state = v4.get((neighbour.device_id, neighbour.neighbor_device_id))
        divergence = f" IPv4 OSPF on the same link is still {v4_state.upper()}, so only IPv6 is affected." if v4_state == "full" else ""
        logs = [e for e in events if e.device_id in pair or e.peer in pair]
        out.drafts.append(Draft(
            "IPV6_OSPFV3_ADJACENCY_DOWN", "confirmed_fault", "anomaly", "major",
            f"OSPFv3 {neighbour.device_id} ↔ {neighbour.neighbor_device_id} is {neighbour.state.upper()}",
            f"The OSPFv3 adjacency on {neighbour.interface_id} is {neighbour.state.upper()} since {neighbour.last_change:%H:%M} UTC." + divergence,
            "two_sided" if other and other.state != "full" else "direct",
            [ref("ospfv3_neighbors", neighbour.neighbor_id, neighbour.last_change)] + ([ref("ospfv3_neighbors", other.neighbor_id, other.last_change)] if other else [])
            + [ref("protocol_events", e.event_id, e.timestamp) for e in logs][:1],
            "the IPv6 routing adjacency is not FULL" + ("; IPv4 OSPF on the same link is" if v4_state == "full" else ""), device_id=branch,
            site_id=ctx.site_of.get(branch), timestamp=neighbour.last_change, affected_sites=[s for s in [ctx.site_of.get(branch)] if s and s != "CORE"],
            facts={"interface": neighbour.interface_id, "state": neighbour.state, "ipv4_ospf": v4_state}))
    routes = {(r.device_id, str(r.prefix)) for r in v6.routes}
    branches = sorted({p.site_id for p in v6.site_prefixes if p.site_id in ("NYC", "SIN", "BLR")})
    for site in branches:
        router = f"{site}-RTR-01"
        if (router, "::/0") not in routes:
            out.drafts.append(Draft(
                "IPV6_DEFAULT_ROUTE_MISSING", "confirmed_fault", "anomaly", "major", f"{router} has no IPv6 default route",
                f"{router} holds no ::/0 route, so IPv6 traffic from {site} has nowhere to go beyond the site.", "direct",
                [ref("ipv6_routes", r.route_id) for r in v6.routes if r.device_id == router][:3], "the route table lacks ::/0",
                device_id=router, site_id=site, affected_sites=[site], facts={"router": router}))
        core = "CORE-RTR-02" if site == "BLR" else "CORE-RTR-01"
        prefixes = [str(p.prefix) for p in v6.site_prefixes if p.site_id == site]
        lost = [p for p in prefixes if (core, p) not in routes]
        if lost:
            out.drafts.append(Draft(
                "IPV6_PREFIX_UNREACHABLE", "confirmed_fault", "anomaly", "major", f"{core} has no route to {site}'s IPv6 prefixes",
                f"{core} is missing {', '.join(lost)}, so return IPv6 traffic to {site} is dropped at the core.", "direct",
                [ref("ipv6_routes", r.route_id) for r in v6.routes if r.device_id == core][:3], "the core route table lacks the site prefixes",
                device_id=core, site_id="CORE", affected_sites=[site], facts={"missing": lost}))
    for site in sorted({p.site_id for p in v6.probes}):
        probes = [p for p in v6.probes if p.site_id == site]
        v6_only = [p for p in probes if p.ipv4_ok and not p.ipv6_ok]
        both = [p for p in probes if not p.ipv4_ok and not p.ipv6_ok]
        if v6_only:
            out.drafts.append(Draft(
                "IPV6_REACHABILITY_LOSS", "confirmed_fault", "anomaly", "major", f"IPv6 fails from {site} while IPv4 works",
                f"Dual-stack probes from {site} to {', '.join(p.service for p in v6_only)} succeed over IPv4 and fail over IPv6; dual-stack clients "
                "wait for IPv6 to time out before falling back, which feels like slow connections.", "measured",
                [ref("ipv6_probes", p.probe_id, p.timestamp) for p in v6_only][:3], "the same targets answer on IPv4 and not on IPv6",
                site_id=site, timestamp=v6_only[0].timestamp, affected_sites=[site], facts={"services": [p.service for p in v6_only]}))
        elif both:
            out.notes.append(f"Probes from {site} fail over both IPv4 and IPv6: a general reachability problem, not an IPv6-specific one.")
    prefixes = {(p.site_id, p.vlan_id): p.prefix for p in v6.site_prefixes}
    for advert in v6.adverts:
        expected = prefixes.get((advert.site_id, advert.vlan_id))
        if advert.router_device_id is None:
            out.drafts.append(Draft(
                "IPV6_ROGUE_RA", "suspicious_indicator", "threat_indicator", "major", f"Router advertisement from an unknown source at {advert.site_id}",
                f"VLAN {advert.vlan_id} at {advert.site_id} received a router advertisement for {advert.prefix} from {advert.source_mac}, which is not "
                "a known router: clients may send IPv6 traffic through that host.", "direct", [ref("router_adverts", advert.ra_id, advert.timestamp)],
                "an RA came from a source that is not one of our routers", site_id=advert.site_id, timestamp=advert.timestamp,
                affected_sites=[advert.site_id], facts={"source_mac": advert.source_mac, "prefix": str(advert.prefix)}))
        elif advert.router_lifetime == 0 or (expected is not None and advert.prefix != expected):
            out.drafts.append(Draft(
                "IPV6_RA_MISCONFIG", "confirmed_fault", "misconfiguration", "minor", f"Router advertisement problem at {advert.site_id} VLAN {advert.vlan_id}",
                f"{advert.router_device_id} advertises {advert.prefix} with router lifetime {advert.router_lifetime}"
                + (f" (expected prefix {expected})" if expected and advert.prefix != expected else "") + ".", "direct",
                [ref("router_adverts", advert.ra_id, advert.timestamp)], "the RA parameters do not match the site plan",
                device_id=advert.router_device_id, site_id=advert.site_id, timestamp=advert.timestamp, affected_sites=[advert.site_id]))
    return out
