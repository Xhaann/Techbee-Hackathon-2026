"""MTU and fragmentation diagnosis: MTU mismatches between link ends, path-MTU black holes found by don't-fragment
probes (large sizes lost, no fragmentation-needed reply), encapsulation overhead without MSS clamping and reassembly
failures. When every probe size fails the problem is reachability, not MTU, and the engine says so."""
from collections import defaultdict

from app.protocols.engines.base import Context, Draft, EngineOutput, ref


def analyze(ctx: Context) -> EngineOutput:
    mtu = ctx.telemetry.mtu
    out = EngineOutput(checked=["IP MTU on both ends of every link", "don't-fragment probes by size", "encapsulation overhead and MSS clamping",
                                "ICMP fragmentation-needed handling", "fragmentation counters"])
    configured = {i.interface_id: i for i in mtu.interfaces}

    def ip_mtu(interface_id: str) -> int | None:
        if interface_id in configured:
            return configured[interface_id].ip_mtu
        interface = ctx.interfaces.get(interface_id)
        return interface.mtu if interface and interface.ip_address is not None else None

    for link in ctx.topology.links:
        a, b = ip_mtu(link.a_interface_id), ip_mtu(link.b_interface_id)
        if a and b and a != b:
            low = link.a_interface_id if a < b else link.b_interface_id
            out.drafts.append(Draft(
                "MTU_MISMATCH", "confirmed_fault", "misconfiguration", "major", f"MTU mismatch on {link.link_id}",
                f"{link.a_interface_id} uses IP MTU {a} and {link.b_interface_id} uses {b}. Routing protocols that check MTU (OSPF) will not "
                "form an adjacency, and full-size packets from the larger side are dropped.", "two_sided",
                [ref("mtu_interfaces", link.a_interface_id), ref("mtu_interfaces", link.b_interface_id)], "the two ends report different IP MTUs",
                device_id=low.split(":")[0], site_id=ctx.site_of.get(low.split(":")[0]), affected_sites=[s for s in ctx.sites_through(low.split(":")[0]) if s != "CORE"][:1],
                facts={"link": link.link_id, "mtu": {link.a_interface_id: a, link.b_interface_id: b}}))
    groups = defaultdict(list)
    for probe in mtu.probes:
        if probe.df:
            groups[(probe.source_device_id, str(probe.destination_ip))].append(probe)
    events = [e for e in ctx.telemetry.events if e.protocol == "mtu"]
    for (source, destination), probes in sorted(groups.items()):
        ok = [p for p in probes if p.result == "ok"]
        lost = [p for p in probes if p.result == "timeout"]
        frag = [p for p in probes if p.result == "frag_needed"]
        site = ctx.site_of.get(source)
        refs = [ref("mtu_probes", p.probe_id, p.timestamp) for p in sorted(probes, key=lambda p: -p.size)][:6]
        if lost and not ok:
            out.notes.append(f"Every don't-fragment probe from {source} to {destination} failed, at every size: that is a reachability problem, "
                             "not an MTU problem.")
            continue
        if not lost:
            continue
        largest_ok = max(p.size for p in ok)
        smallest_lost = min(p.size for p in lost)
        if smallest_lost <= largest_ok:
            out.notes.append(f"Probes from {source} to {destination} fail at mixed sizes (lost at {smallest_lost}, passed at {largest_ok}): "
                             "intermittent loss rather than a size limit.")
            continue
        filtered = [d for d in mtu.icmp_filtered_on]
        sent = [c for c in mtu.counters if c.device_id == source and c.frag_needed_sent and c.timestamp >= ctx.onset]
        corroboration = int(bool(filtered)) + int(bool(sent))
        if not frag:
            out.drafts.append(Draft(
                "MTU_BLACK_HOLE", "confirmed_fault", "anomaly", "critical", f"Path-MTU black hole from {source}",
                f"Don't-fragment probes from {source} to {destination} pass up to {largest_ok} bytes and vanish from {smallest_lost} bytes, "
                "with no 'fragmentation needed' reply ever arriving"
                + (f"; {', '.join(filtered)} filters those ICMP messages" if filtered else "") + ". Hosts keep sending full-size packets that are "
                "silently dropped, so large transfers stall while ping and small pages work.", "measured",
                refs + [ref("protocol_events", e.event_id, e.timestamp) for e in events][:1] + [ref("mtu_counters", c.counter_id, c.timestamp) for c in sent][:1],
                "large DF probes are lost without any fragmentation-needed reply while small probes pass", device_id=source, site_id=site,
                timestamp=min(p.timestamp for p in probes), affected_sites=[site] if site else [], corroboration=corroboration,
                facts={"source": source, "destination": destination, "effective_mtu": largest_ok, "lost_from": smallest_lost,
                       "icmp_filtered_on": filtered}))
        else:
            out.drafts.append(Draft(
                "MTU_PATH_REDUCED", "possible_explanation", "anomaly", "minor", f"Path MTU from {source} is {largest_ok} bytes",
                f"Probes above {largest_ok} bytes get a fragmentation-needed reply, so path-MTU discovery works; only applications that ignore it "
                "are affected.", "measured", refs, "the path MTU is reduced but signalled correctly", device_id=source, site_id=site,
                timestamp=min(p.timestamp for p in probes), affected_sites=[site] if site else [], facts={"effective_mtu": largest_ok}))
    for interface in mtu.interfaces:
        if interface.tunnel_overhead and interface.mss_clamp is None and interface.ip_mtu - interface.tunnel_overhead < 1500:
            device = interface.interface_id.split(":")[0]
            effective = interface.ip_mtu - interface.tunnel_overhead
            changes = [e for e in ctx.dataset.events if e.device_id == device and e.event_type in ("MTU_CHANGE", "CONFIG_CHANGE", "CONFIG_COMMAND_LOGGED")]
            out.drafts.append(Draft(
                "MTU_OVERHEAD_NO_MSS_CLAMP", "confirmed_fault", "misconfiguration", "major", f"{interface.interface_id} adds {interface.tunnel_overhead} bytes without MSS clamping",
                f"{interface.interface_id} encapsulates traffic ({interface.tunnel_overhead} bytes of overhead, effective MTU {effective}) but does "
                f"not clamp the TCP MSS, so TCP still sends segments sized for 1500 bytes.", "direct",
                [ref("mtu_interfaces", interface.interface_id)] + [ref("events", e.event_id, e.timestamp) for e in changes][:1],
                "overhead is configured and MSS clamping is not", device_id=device, site_id=ctx.site_of.get(device),
                timestamp=min((e.timestamp for e in changes), default=None), affected_sites=[ctx.site_of.get(device)] if ctx.site_of.get(device) else [],
                facts={"overhead": interface.tunnel_overhead, "effective_mtu": effective}))
    for counter in mtu.counters:
        if counter.reassembly_failures > 50:
            out.drafts.append(Draft(
                "MTU_FRAGMENTATION", "possible_explanation", "performance", "minor", f"Reassembly failures on {counter.device_id}",
                f"{counter.device_id} failed to reassemble {counter.reassembly_failures} fragmented packets in one interval.", "measured",
                [ref("mtu_counters", counter.counter_id, counter.timestamp)], "fragments are being lost", device_id=counter.device_id,
                site_id=ctx.site_of.get(counter.device_id), timestamp=counter.timestamp, facts={"reassembly_failures": counter.reassembly_failures}))
    return out
