"""Spanning-tree loop and topology-change detection: loop indicators (MAC flapping, topology-change storms, broadcast
storms, saturated uplinks, unguarded edge ports), unexpected root bridges and BPDU-guard shutdowns. Planned work inside a
maintenance window is reported as such instead of as a fault."""
from collections import defaultdict

from app.protocols.engines.base import Context, Draft, EngineOutput, ref

FLAP_MIN = 10
TC_STORM = 20
SATURATED = 95.0


def analyze(ctx: Context) -> EngineOutput:
    stp = ctx.telemetry.stp
    out = EngineOutput(checked=["root bridge per VLAN against the intended root", "topology-change counters and events", "MAC flapping",
                                "broadcast storms", "edge ports without BPDU guard", "uplink utilisation"])
    if ctx.stale(stp.collected_at):
        hours = (ctx.window_start - stp.collected_at).total_seconds() / 3600
        out.drafts.append(Draft(
            "STP_DATA_STALE", "insufficient_evidence", "coverage", "info", "Spanning-tree data is stale",
            f"The spanning-tree state was collected {hours:.0f} hours before the incident window, so it cannot show what happened during it.",
            "none", [ref("stp_vlans", v.state_id) for v in stp.vlans][:2], "state collected before the window cannot confirm or rule out a loop",
            facts={"collected_at": stp.collected_at.isoformat()}))
        return out
    events = [e for e in ctx.telemetry.events if e.protocol == "stp"]
    bridge_of = {v.device_id: v.bridge_mac for v in stp.vlans}
    known_bridges = set(bridge_of.values())
    states = {(v.device_id, v.vlan_id): v for v in stp.vlans}
    # ---- unexpected roots
    for expected in stp.expected_roots:
        state = states.get((expected.device_id, expected.vlan_id))
        intended = bridge_of.get(expected.device_id)
        if state is None or intended is None or state.root_mac == intended:
            continue
        rogue = state.root_mac not in known_bridges
        out.drafts.append(Draft(
            "STP_ROOT_UNEXPECTED", "suspicious_indicator" if rogue else "confirmed_fault", "threat_indicator" if rogue else "misconfiguration",
            "major", f"Unexpected root bridge for VLAN {expected.vlan_id} at {expected.site_id}",
            f"VLAN {expected.vlan_id} on {expected.device_id} elects {state.root_mac} (priority {state.root_priority}) as root instead of "
            f"{expected.device_id}" + (": that bridge is not one of ours, which suggests an unmanaged or rogue switch." if rogue else "."),
            "direct", [ref("stp_vlans", state.state_id)], "the elected root differs from the intended root bridge",
            device_id=expected.device_id, site_id=expected.site_id, timestamp=state.last_topology_change, affected_sites=[expected.site_id],
            facts={"vlan": expected.vlan_id, "root_mac": state.root_mac, "intended": intended}))
    # ---- loops and topology-change storms, per switch and VLAN
    by_key = defaultdict(list)
    for event in events:
        by_key[(event.device_id, event.vlan_id)].append(event)
    utilization = {}
    for sample in ctx.dataset.interface_statistics:
        if sample.timestamp >= ctx.onset:
            utilization[sample.interface_id] = max(utilization.get(sample.interface_id, 0), sample.utilization_percent)
    for state in stp.vlans:
        key = (state.device_id, state.vlan_id)
        group = by_key.get(key, [])
        flaps = sum(e.count for e in group if e.kind == "MAC_FLAP")
        tcs = sum(e.count for e in group if e.kind == "TOPOLOGY_CHANGE")
        storms = [e for e in group if e.kind == "BROADCAST_STORM"]
        unguarded = [p for p in stp.ports if p.device_id == state.device_id and p.vlan_id == state.vlan_id and p.edge and not p.bpdu_guard
                     and p.state == "forwarding"]
        recent_tc = state.last_topology_change is not None and state.last_topology_change >= ctx.window_start
        uplinks = [i for i, value in utilization.items() if i.startswith(f"{state.device_id}:") and value >= SATURATED]
        indicators = []
        if flaps >= FLAP_MIN:
            indicators.append(f"{flaps} MAC-flap notifications")
        if tcs >= TC_STORM and recent_tc:
            indicators.append(f"{tcs} topology changes in the window")
        if storms:
            indicators.append(storms[0].detail if not ctx.text(storms[0].detail).startswith("[device") else "a broadcast storm")
        if len(unguarded) >= 2:
            indicators.append(f"{len(unguarded)} edge ports forwarding without BPDU guard ({', '.join(p.port for p in unguarded)})")
        if uplinks:
            indicators.append(f"{', '.join(uplinks)} saturated at {max(utilization[u] for u in uplinks):.0f}%")
        refs = [ref("protocol_events", e.event_id, e.timestamp) for e in group][:4] + [ref("stp_vlans", state.state_id, state.last_topology_change)]
        refs += [ref("stp_ports", p.port_id) for p in unguarded][:2]
        refs += [ref("interface_statistics", f"{s.interface_id}@{s.timestamp.isoformat()}", s.timestamp) for s in ctx.dataset.interface_statistics
                 if s.interface_id in uplinks and s.timestamp >= ctx.onset][:2]
        planned = ctx.maintenance(state.device_id, state.last_topology_change)
        site = ctx.site_of.get(state.device_id)
        if len(indicators) >= 3:
            source = state.tc_source_port or (storms[0].port if storms else None)
            out.drafts.append(Draft(
                "STP_LOOP", "confirmed_fault", "anomaly", "critical", f"Layer-2 loop on VLAN {state.vlan_id} at {state.device_id}",
                f"VLAN {state.vlan_id} on {state.device_id} shows {len(indicators)} independent loop indicators: {'; '.join(indicators)}."
                + (f" The topology changes come from {source}." if source else ""), "measured", refs,
                "a loop is the one explanation that produces MAC flapping, a topology-change storm and a broadcast storm together",
                device_id=state.device_id, site_id=site, timestamp=min((e.timestamp for e in group), default=state.last_topology_change),
                affected_sites=[site] if site else [], corroboration=len(indicators) - 1,
                facts={"vlan": state.vlan_id, "indicators": indicators, "source_port": source, "mac_flaps": flaps, "topology_changes": tcs,
                       "unguarded_ports": [p.port for p in unguarded]}))
        elif tcs >= TC_STORM and recent_tc and not planned:
            out.drafts.append(Draft(
                "STP_TC_STORM", "confirmed_fault", "anomaly", "major", f"Topology-change storm on VLAN {state.vlan_id} at {state.device_id}",
                f"{tcs} topology changes on VLAN {state.vlan_id}" + (f" from {state.tc_source_port}" if state.tc_source_port else "") +
                "; each one flushes MAC tables and floods traffic.", "measured", refs, "topology changes far above the normal rate",
                device_id=state.device_id, site_id=site, timestamp=state.last_topology_change, affected_sites=[site] if site else [],
                facts={"vlan": state.vlan_id, "topology_changes": tcs}))
        elif len(indicators) == 2 and not planned:
            out.drafts.append(Draft(
                "STP_LOOP", "possible_explanation", "anomaly", "major", f"Possible loop on VLAN {state.vlan_id} at {state.device_id}",
                f"Two loop indicators on VLAN {state.vlan_id}: {'; '.join(indicators)}. Not enough on their own to confirm a loop.",
                "behavioural", refs, "two indicators are consistent with a loop but also with other causes", device_id=state.device_id,
                site_id=site, timestamp=state.last_topology_change, affected_sites=[site] if site else [], facts={"indicators": indicators}))
        elif (tcs or recent_tc) and planned:
            injected = any(ctx.text(e.detail).startswith("[device") for e in group)
            out.notes.append(f"{tcs or 'Some'} topology change(s) on {state.device_id} VLAN {state.vlan_id} fall inside a planned maintenance "
                             f"window ({planned}); expected, not a fault." + (" One event's text contained instruction-like content and was "
                                                                               "ignored." if injected else ""))
    for port in stp.ports:
        if port.state == "err-disabled":
            out.drafts.append(Draft(
                "STP_BPDU_GUARD_ERRDISABLE", "possible_explanation", "anomaly", "minor", f"{port.device_id} {port.port} shut by BPDU guard",
                f"BPDU guard disabled {port.port} after receiving a BPDU on an edge port: a switch was plugged in where a host belongs.", "direct",
                [ref("stp_ports", port.port_id)], "the port is err-disabled by BPDU guard", device_id=port.device_id,
                site_id=ctx.site_of.get(port.device_id), facts={"port": port.port, "vlan": port.vlan_id}))
    return out
