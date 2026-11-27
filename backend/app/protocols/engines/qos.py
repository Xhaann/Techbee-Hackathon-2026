"""QoS and packet-priority analysis: expected policies missing from WAN edges, DSCP re-marking located to the hop where
it happens, priority traffic that no longer matches its class, drops in the priority queue and congestion drops in
business classes. Drops in scavenger and best-effort classes under congestion are by design and reported as such.

It also checks capacity: a link whose utilisation rose to saturation with output-queue drops at the onset is the cause of
the congestion drops, retransmissions and long round trips behind it (those are effects). When the flow records seen on
that link show one source carrying most of the bytes, the finding names it, with its inventory role and whether a
maintenance window covers the transfer. Flow records are sampled, so the share is of recorded bytes, not of the link."""
from collections import defaultdict
from datetime import timedelta

from app.protocols.engines.base import Context, Draft, EngineOutput, mean, pct, ref

PRIORITY_DROPS = 0.5
CONGESTION = 1.0
ORDER = {"output": 0, "input": 1}
SATURATED = 90.0        # % utilisation over a measurement interval
RISE = 20.0             # points above the level before the onset: a link that was always this busy is not a new problem
DROP_GROWTH = 10        # output drops after the onset at least this many times the level before
DOMINANT = 0.5          # share of the recorded bytes that makes one source the driver
BULK_BYTES = 1_000_000_000
WORKDAY = (8, 18)       # local hours


def local_time(moment, site: str | None):
    from app.observability.simulation import SITE_GEO  # site UTC offsets, shared with the observability layer
    geo = SITE_GEO.get(site or "")
    return (moment + timedelta(hours=geo.utc_offset_hours), geo.city) if geo else (None, None)


LINK_WORD = {"wan": "WAN", "lan": "LAN", "metro": "metro"}


def site_of_host(ctx: Context, address, hosts: dict) -> str | None:
    host = hosts.get(str(address))
    return host.site_id if host else ctx.site_of_ip(address)


def crosses(ctx: Context, flow, ends: set[str], hosts: dict) -> bool:
    """Whether a flow travels over the link: its sensor is on the link, or the modelled paths between its two sites
    pass through both ends."""
    if flow.sensor_device_id in ends:
        return True
    a, b = site_of_host(ctx, flow.src_ip, hosts), site_of_host(ctx, flow.dst_ip, hosts)
    for path in ctx.topology.paths:
        sites = {path.source_site_id, ctx.site_of.get(path.device_ids[-1])}
        if {a, b} <= sites and ends <= set(path.device_ids):
            return True
    return False


def saturated_links(ctx: Context, stats: dict) -> list[tuple]:
    found = []
    for link in ctx.topology.links:
        measured = []
        for interface in (link.a_interface_id, link.b_interface_id):
            rows = stats.get(interface, [])
            before = [r for r in rows if r.timestamp < ctx.onset]
            after = [r for r in rows if r.timestamp >= ctx.onset and r.oper_status.value == "up"]
            if not after or not before:
                continue  # without a before and after there is no change to attribute
            level, base = mean([r.utilization_percent for r in after]), mean([r.utilization_percent for r in before])
            drops, drops_before = mean([r.out_drops for r in after]), mean([r.out_drops for r in before])
            if level >= SATURATED and level - base >= RISE and drops >= DROP_GROWTH * max(drops_before, 1):
                measured.append({"interface": interface, "level": level, "base": base, "drops": drops, "after": after, "before": before})
        if measured:
            found.append((link, max(measured, key=lambda m: m["level"]), measured))
    return found


def link_label(link) -> str:
    return f"{LINK_WORD.get(link.link_type.value, link.link_type.value)} link {link.link_id}"


def link_saturation(ctx: Context) -> list[Draft]:
    stats = defaultdict(list)
    for row in ctx.dataset.interface_statistics:
        stats[row.interface_id].append(row)
    sec = ctx.telemetry.security
    hosts = {str(h.ip): h for h in sec.hosts} if sec else {}
    allow = sec.allowlist if sec else None
    groups: dict[str | None, list] = defaultdict(list)
    for link, worst, measured in saturated_links(ctx, stats):
        ends = {link.a_interface_id.split(":")[0], link.b_interface_id.split(":")[0]}
        start = min(r.timestamp for m in measured for r in m["after"]) - timedelta(minutes=15)
        flows = [f for f in (sec.flows if sec else []) if f.start <= ctx.window_end and f.start + timedelta(seconds=f.duration_seconds) >= start
                 and crosses(ctx, f, ends, hosts)]
        by_source = defaultdict(list)
        for f in flows:
            by_source[str(f.src_ip)].append(f)
        total = sum(f.bytes_out for f in flows)
        source, mine = max(by_source.items(), key=lambda kv: sum(f.bytes_out for f in kv[1]), default=(None, []))
        sent = sum(f.bytes_out for f in mine)
        driver = source if total and sent / total >= DOMINANT and sent >= BULK_BYTES else None
        groups[driver if driver else f"link:{link.link_id}"].append((link, worst, measured, ends, mine if driver else [], total))
    drafts = []
    for key, members in groups.items():
        members.sort(key=lambda m: -m[1]["level"])
        link, worst, _, _, _, _ = members[0]
        device = worst["interface"].split(":")[0]
        ends = set().union(*(m[3] for m in members))
        sites = sorted({s for d in ends for s in ctx.sites_through(d) if s not in ("CORE", "DC1")})
        refs = [ref("interface_statistics", f"{r.interface_id}@{r.timestamp.isoformat()}", r.timestamp) for m in members for r in m[1]["after"][:1]]
        refs += [ref("interface_statistics", f"{worst['interface']}@{worst['before'][-1].timestamp.isoformat()}", worst["before"][-1].timestamp)]
        links = "; ".join(f"{m[1]['interface']} {m[1]['level']:.0f}% (was {m[1]['base']:.0f}%), {m[1]['drops']:,.0f} output drops per interval"
                          for m in members[:4])
        named = link_label(link) + (f" and {len(members) - 1} more link{'s' if len(members) > 2 else ''}" if len(members) > 1 else "")
        facts = {"links": [m[0].link_id for m in members], "interface": worst["interface"], "utilization_percent": round(worst["level"], 1),
                 "before_percent": round(worst["base"], 1), "out_drops": round(worst["drops"]), "bandwidth_mbps": link.bandwidth_mbps}
        title = f"{named[0].upper() + named[1:]} saturated at {worst['level']:.0f}%"
        summary = (f"Utilisation rose to saturation at the onset with the output queue overflowing: {links}. Traffic through "
                   f"{', '.join(sorted(ends))} is delayed and dropped.")
        hosts_involved: list[str] = []
        if not key.startswith("link:"):
            source = key
            mine = list({f.flow_id: f for m in members for f in m[4]}.values())
            sent = sum(f.bytes_out for f in mine)
            share = max(sum(f.bytes_out for f in m[4]) / m[5] for m in members if m[5])
            host = hosts.get(source)
            name = f"{host.hostname} ({source}, {host.role})" if host else source
            ports = sorted({f"{f.protocol}/{f.dst_port}" for f in mine if f.dst_port})
            targets = sorted({site_of_host(ctx, f.dst_ip, hosts) or "external" for f in mine})
            first = min(f.start for f in mine)
            when, city = local_time(first, host.site_id if host else None)
            workday = when is not None and when.weekday() < 5 and WORKDAY[0] <= when.hour < WORKDAY[1]
            windows = [w for w in (allow.maintenance if allow else []) if w.start <= first <= w.end
                       and (not w.hosts or any(str(h) == source for h in w.hosts))]
            allowlisted = allow is not None and any(str(a) == source for a in allow.backup_servers)
            title += f" by bulk transfer from {host.hostname if host else source}"
            summary += (f" Flow records on these links put up to {pct(share * 100)} of the recorded bytes on one source: {name} sent "
                        f"{sent / 1e9:.1f} GB over {', '.join(ports) or 'several ports'} in {len(mine)} transfers to {', '.join(targets)}, starting "
                        f"{first:%H:%M} UTC" + (f" ({when:%H:%M} in {city}, {'inside' if workday else 'outside'} working hours)" if when else "")
                        + (". No maintenance window covers it." if not windows else f". It falls inside the maintenance window '{windows[0].reason}'.")
                        + (" The host is an authorised backup server, so this is a scheduling and capacity problem, not a security one."
                           if allowlisted else ""))
            refs += [ref("security_flows", f.flow_id, f.start) for f in mine[:2]]
            refs += [ref("events", e.event_id, e.timestamp) for e in ctx.dataset.events
                     if e.device_id in ends and source in e.message and e.timestamp >= first - timedelta(minutes=15)][:1]
            hosts_involved = [source]
            facts |= {"driver": source, "driver_name": host.hostname if host else None, "driver_role": host.role if host else None,
                      "driver_share": round(share, 3), "driver_bytes": sent, "transfers": len(mine), "ports": ports, "destinations": targets,
                      "started": first.isoformat(), "local_start": when.strftime("%H:%M") if when else None, "working_hours": workday,
                      "maintenance_window": bool(windows), "authorised_host": allowlisted}
        drafts.append(Draft(
            "QOS_LINK_SATURATION", "confirmed_fault", "performance", "major", title, summary, "measured", refs[:8],
            "utilisation rose to saturation with output-queue drops at the onset", device_id=device, site_id=ctx.site_of.get(device),
            timestamp=min(r.timestamp for m in members for r in m[1]["after"]), affected_sites=sites,
            corroboration=int(bool(hosts_involved)) + (len(members) > 1), facts=facts,
            benign=["capacity, not an attack"] if hosts_involved else []))
    return drafts


def analyze(ctx: Context) -> EngineOutput:
    qos = ctx.telemetry.qos
    out = EngineOutput(checked=["expected policies applied on each WAN edge", "DSCP marking at each point on the path", "class traffic and drops",
                                "priority queue drops"])
    applied = {(p.interface_id, p.direction, p.name) for p in qos.policies if p.applied}
    for expected in qos.expected:
        if (expected.interface_id, expected.direction, expected.name) not in applied:
            device = expected.interface_id.split(":")[0]
            out.drafts.append(Draft(
                "QOS_POLICY_MISSING", "confirmed_fault", "misconfiguration", "major", f"No {expected.name} on {expected.interface_id}",
                f"{expected.interface_id} should apply {expected.name} ({expected.direction}) but no such policy is applied, so voice gets no "
                "priority there.", "direct", [ref("qos_policies", f"{expected.interface_id}|{expected.direction}")],
                "the expected policy is absent from the interface", device_id=device, site_id=ctx.site_of.get(device),
                affected_sites=[s for s in ctx.sites_through(device) if s != "CORE"][:1], facts={"interface": expected.interface_id}))
    # ---- re-marking, located to the first point where the marking is wrong
    far_end = {}
    for link in ctx.topology.links:
        far_end[link.a_interface_id], far_end[link.b_interface_id] = link.b_device_id, link.a_device_id

    def branch(interface: str) -> str:
        site = ctx.site_of.get(interface.split(":")[0], "")
        return ctx.site_of.get(far_end.get(interface, ""), site) if site == "CORE" else site

    by_traffic = defaultdict(list)
    for marking in qos.markings:
        by_traffic[(marking.traffic, branch(marking.interface_id))].append(marking)
    role_order = {"access_switch": 0, "wan_edge": 1}
    for (traffic, site), marks in sorted(by_traffic.items()):
        marks.sort(key=lambda m: (role_order.get(ctx.devices[m.interface_id.split(":")[0]].role.value, 2), ORDER[m.direction]))
        wrong = [m for m in marks if m.observed_dscp != m.expected_dscp]
        if not wrong:
            continue
        first = wrong[0]
        index = marks.index(first)
        previous = marks[index - 1] if index else None
        device = first.interface_id.split(":")[0]
        out.drafts.append(Draft(
            "QOS_REMARKING", "confirmed_fault", "misconfiguration", "major", f"{traffic.title()} re-marked to DSCP {first.observed_dscp} at {device}",
            f"{traffic.title()} leaves {previous.interface_id if previous else 'the access layer'} marked DSCP {first.expected_dscp} but is seen as "
            f"DSCP {first.observed_dscp} at {first.interface_id} ({first.direction}); every hop after that treats it as best effort.",
            "two_sided" if previous else "direct",
            ([ref("qos_markings", previous.observation_id, previous.timestamp)] if previous else []) + [ref("qos_markings", m.observation_id, m.timestamp) for m in wrong][:3],
            "the marking is correct before this hop and wrong from it onwards", device_id=device, site_id=ctx.site_of.get(device),
            timestamp=first.timestamp, affected_sites=[site] if site else [],
            facts={"traffic": traffic, "expected_dscp": first.expected_dscp, "observed_dscp": first.observed_dscp, "first_wrong": first.interface_id,
                   "last_correct": previous.interface_id if previous else None}))
    # ---- class statistics
    classes = {(p.interface_id, c.name): c for p in qos.policies for c in p.classes}
    samples = defaultdict(list)
    for sample in qos.samples:
        samples[(sample.interface_id, sample.class_name)].append(sample)
    by_design = []
    for (interface, name), group in sorted(samples.items()):
        spec = classes.get((interface, name))
        before = [s for s in group if s.timestamp < ctx.onset]
        after = [s for s in group if s.timestamp >= ctx.onset]
        device = interface.split(":")[0]
        site = ctx.site_of.get(device)
        refs = [ref("qos_samples", s.sample_id, s.timestamp) for s in after][:3] + [ref("qos_samples", s.sample_id, s.timestamp) for s in before][:1]
        drop = mean([s.drop_percent for s in after])
        if spec and spec.priority and mean([s.offered_kbps for s in before]) > 50 and mean([s.offered_kbps for s in after]) < 1:
            default = samples.get((interface, "class-default"), [])
            grew = mean([s.offered_kbps for s in default if s.timestamp >= ctx.onset]) - mean([s.offered_kbps for s in default if s.timestamp < ctx.onset])
            out.drafts.append(Draft(
                "QOS_CLASSIFICATION_FAILURE", "confirmed_fault", "misconfiguration", "critical", f"{name} class empty on {interface}",
                f"The {name} priority class on {interface} carried {mean([s.offered_kbps for s in before]):.0f} kbps before and nothing since, while "
                f"class-default grew by about {max(grew, 0):.0f} kbps: priority traffic no longer matches its class.", "measured", refs,
                "the priority class went empty while best effort grew by the same amount", device_id=device, site_id=site, timestamp=after[0].timestamp if after else None,
                affected_sites=[s for s in [site] if s and s != "CORE"], facts={"class": name, "before_kbps": round(mean([s.offered_kbps for s in before]))}))
            continue
        if spec and spec.priority and drop > PRIORITY_DROPS:
            out.drafts.append(Draft(
                "QOS_PRIORITY_DROPS", "confirmed_fault", "performance", "critical", f"{name} dropped in the priority queue on {interface}",
                f"The priority class {name} drops {pct(drop)} on {interface}: it is exceeding its {spec.bandwidth_percent}% allocation.", "measured",
                refs, "priority traffic is being policed or dropped", device_id=device, site_id=site, timestamp=after[0].timestamp,
                affected_sites=[s for s in [site] if s and s != "CORE"], facts={"class": name, "drop_percent": round(drop, 2)}))
        elif drop > CONGESTION:
            misclassified = any(d.code == "QOS_CLASSIFICATION_FAILURE" and d.device_id == device for d in out.drafts)
            if spec and spec.drops_expected and not misclassified:
                by_design.append(f"{name} on {interface} ({pct(drop)})")
                continue
            out.drafts.append(Draft(
                "QOS_CONGESTION_DROPS", "confirmed_fault", "performance", "major", f"{name} dropping {pct(drop)} on {interface}",
                f"{name} on {interface} drops {pct(drop)} of packets since the onset"
                + (", and that class now carries the misclassified priority traffic." if misclassified else "."), "measured", refs,
                "drops above the class's normal level", device_id=device, site_id=site, timestamp=after[0].timestamp if after else None,
                affected_sites=[s for s in [site] if s and s != "CORE"], facts={"class": name, "drop_percent": round(drop, 2)}))
    if by_design:
        out.notes.append(f"Drops in {', '.join(by_design[:3])} are in classes built to absorb congestion: expected, not a fault.")
    out.drafts += link_saturation(ctx)
    out.checked.append("link utilisation and output drops before and after the onset")
    return out
