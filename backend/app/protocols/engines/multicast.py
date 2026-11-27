"""Multicast routing diagnosis: rendezvous-point agreement, RPF checks against the unicast routing table (so a unicast
change that moves the route to a source is caught), PIM neighbours on the distribution tree, receivers that joined but get
no traffic, and VLANs with no IGMP querier."""
from collections import defaultdict
from ipaddress import IPv4Address

from app.protocols.engines.base import Context, Draft, EngineOutput, ref


def rpf_interface(ctx: Context, device: str, source: IPv4Address) -> str | None:
    table = next((t for t in ctx.dataset.routing.routing_tables if t.device_id == device), None)
    if table is None:
        return None
    matches = [r for r in table.routes if source in r.prefix]
    if not matches:
        return None
    best = max(matches, key=lambda r: (r.prefix.prefixlen, -r.admin_distance))
    return best.interface_id


def analyze(ctx: Context) -> EngineOutput:
    m = ctx.telemetry.multicast
    out = EngineOutput(checked=["RP mapping on every router", "RPF interface against the unicast route to each source", "PIM neighbours",
                                "receivers against delivered traffic", "IGMP queriers"])
    wrong_rp = [r for r in m.rp_mappings if r.group_range == m.group_range and r.rp_address != m.expected_rp]
    for mapping in wrong_rp:
        out.drafts.append(Draft(
            "MCAST_RP_MISMATCH", "confirmed_fault", "misconfiguration", "major", f"{mapping.device_id} uses RP {mapping.rp_address}",
            f"{mapping.device_id} maps {mapping.group_range} to RP {mapping.rp_address}; every other router uses {m.expected_rp}. Joins from "
            f"receivers behind {mapping.device_id} go to the wrong RP and never meet the source.", "two_sided",
            [ref("rp_mappings", mapping.mapping_id)] + [ref("rp_mappings", r.mapping_id) for r in m.rp_mappings if r.rp_address == m.expected_rp][:1],
            "this router disagrees with the rest of the domain on the RP", device_id=mapping.device_id, site_id=ctx.site_of.get(mapping.device_id),
            affected_sites=[s for s in ctx.sites_through(mapping.device_id) if s != "CORE" and s in {x for st in m.streams for x in st.receiver_sites}],
            facts={"rp": str(mapping.rp_address), "expected": str(m.expected_rp), "group_range": str(m.group_range)}))
    failures = []
    for mroute in m.mroutes:
        if mroute.source is None or mroute.incoming_interface_id is None:
            continue
        expected = rpf_interface(ctx, mroute.device_id, mroute.source)
        if (expected and expected != mroute.incoming_interface_id) or mroute.rpf_failures > 100:
            failures.append((mroute, expected))
    if failures:
        devices = [f[0].device_id for f in failures]
        detail = "; ".join(f"{mr.device_id} receives on {mr.incoming_interface_id} but its unicast route to {mr.source} points out {exp}"
                           if exp and exp != mr.incoming_interface_id else f"{mr.device_id} counts {mr.rpf_failures} RPF failures" for mr, exp in failures[:3])
        streams = [s for s in m.streams if any(str(s.source_ip) == str(f[0].source) for f in failures)]
        out.drafts.append(Draft(
            "MCAST_RPF_FAILURE", "confirmed_fault", "anomaly", "critical", f"Multicast RPF check failing on {len(failures)} router(s)",
            f"{detail}. Packets failing the RPF check are dropped, so the stream stops there.", "measured",
            [ref("mroutes", mr.mroute_id) for mr, _ in failures][:6], "the incoming interface is not the interface towards the source in the unicast table",
            device_id=devices[0], site_id=ctx.site_of.get(devices[0]), affected_sites=sorted({x for s in streams for x in s.receiver_sites}),
            corroboration=int(any(mr.rpf_failures > 100 for mr, _ in failures)), facts={"routers": devices,
                                                                                        "source": str(failures[0][0].source)}))
    tree = {mr.device_id for mr in m.mroutes}
    down = [n for n in m.neighbors if n.state == "down" and n.device_id in tree and n.device_id < n.neighbor_device_id]
    involvement = defaultdict(list)
    for neighbour in down:
        involvement[neighbour.device_id].append(neighbour)
        involvement[neighbour.neighbor_device_id].append(neighbour)
    hub = max(involvement, key=lambda d: len(involvement[d]), default=None)
    groups = [(hub, involvement[hub])] if hub and len(involvement[hub]) >= 2 and len(involvement[hub]) == len(down) else \
        [(n.neighbor_device_id, [n]) for n in down]
    for device, links in groups:
        peers = sorted({n.neighbor_device_id if n.device_id == device else n.device_id for n in links})
        out.drafts.append(Draft(
            "MCAST_PIM_NEIGHBOR_DOWN", "confirmed_fault", "anomaly", "major",
            f"{device} lost PIM to {len(peers)} neighbour(s)" if len(links) > 1 else f"PIM neighbour {links[0].device_id} ↔ {links[0].neighbor_device_id} down",
            f"PIM adjacencies between {device} and {', '.join(peers)} went down at {min(n.last_change for n in links):%H:%M} UTC; those branches of the "
            "distribution tree are cut.", "direct", [ref("pim_neighbors", n.neighbor_id, n.last_change) for n in links][:6],
            "PIM neighbours on tree links are down", device_id=device, site_id=ctx.site_of.get(device), timestamp=min(n.last_change for n in links),
            affected_sites=sorted({ctx.site_of.get(p) for p in peers + [device]} - {None, "CORE", "DC1"}), facts={"device": device, "peers": peers}))
    for stream in m.streams:
        starved = []
        for site in stream.receiver_sites:
            members = sum(g.members for g in m.groups if ctx.site_of.get(g.device_id) == site and str(g.group) == str(stream.group))
            router = next((mr for mr in m.mroutes if mr.device_id == f"{site}-RTR-01" and str(mr.group) == str(stream.group)), None)
            if members and (router is None or router.packets_per_second == 0):
                starved.append((site, members, router))
        if starved:
            sites = [s for s, _, _ in starved]
            out.drafts.append(Draft(
                "MCAST_NO_TRAFFIC", "confirmed_fault", "anomaly", "major", f"{stream.name} not reaching {', '.join(sites)}",
                f"Receivers joined {stream.group} ({stream.name}) at {', '.join(f'{s} ({n})' for s, n, _ in starved)} but the site routers forward "
                "no packets for it.", "measured",
                [ref("mroutes", r.mroute_id) for _, _, r in starved if r][:4] + [ref("igmp_groups", g.group_id) for g in m.groups
                                                                                 if ctx.site_of.get(g.device_id) in sites][:2],
                "receivers are joined but the site routers deliver nothing", device_id=f"{sites[0]}-RTR-01" if len(sites) == 1 else None,
                site_id=sites[0] if len(sites) == 1 else None, affected_sites=sites,
                facts={"stream": stream.name, "group": str(stream.group), "sites": sites}))
    for group in m.groups:
        if not group.querier_present and group.members:
            out.drafts.append(Draft(
                "MCAST_NO_QUERIER", "confirmed_fault", "misconfiguration", "minor", f"No IGMP querier on {group.device_id} VLAN {group.vlan_id}",
                f"VLAN {group.vlan_id} on {group.device_id} has no IGMP querier, so snooping entries age out and receivers lose the stream.", "direct",
                [ref("igmp_groups", group.group_id)], "no querier is present on the VLAN", device_id=group.device_id,
                site_id=ctx.site_of.get(group.device_id), affected_sites=[ctx.site_of.get(group.device_id)]))
    return out
