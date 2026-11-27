"""VLAN and trunk mismatch detection: both ends of each trunk compared for mode, native VLAN and allowed VLANs; site
VLANs missing from a switch's database; and trunks whose configuration contradicts the spanning-tree state."""
from collections import defaultdict

from app.protocols.engines.base import Context, Draft, EngineOutput, ref


def analyze(ctx: Context) -> EngineOutput:
    trunks = ctx.telemetry.vlan
    out = EngineOutput(checked=["mode, native VLAN and allowed VLANs on both ends of each trunk", "VLAN databases against the site's VLANs",
                                "trunk configuration against spanning-tree forwarding state"])
    events = [e for e in ctx.telemetry.events if e.protocol == "vlan"]
    by_link = defaultdict(list)
    for port in trunks.ports:
        by_link[port.link_id].append(port)
    vlan_names = {(v.site_id, v.vlan_id): v.name for v in ctx.topology.vlans}
    pools = defaultdict(list)
    for pool in ctx.dataset.dhcp.pools:
        pools[(pool.site_id, pool.vlan_id)].append(pool.pool_id)
    for link_id, ends in sorted(by_link.items()):
        if len(ends) != 2:
            out.missing.append(f"Only one end of {link_id} was collected")
            continue
        a, b = sorted(ends, key=lambda p: p.device_id)
        site = ctx.site_of.get(a.device_id)
        refs = [ref("trunk_ports", a.port_id), ref("trunk_ports", b.port_id)]
        trunk_like = {"trunk", "dot1q_subinterfaces"}
        if (a.mode in trunk_like) != (b.mode in trunk_like):
            out.drafts.append(Draft(
                "VLAN_MODE_MISMATCH", "confirmed_fault", "misconfiguration", "critical", f"Trunk/access mismatch on {link_id}",
                f"{a.interface_id} is {a.mode} but {b.interface_id} is {b.mode}; tagged VLANs cannot cross this link.", "two_sided", refs,
                "the two ends of the link are configured in incompatible modes", device_id=a.device_id if a.mode == "access" else b.device_id,
                site_id=site, affected_sites=[site] if site else [], facts={"modes": {a.interface_id: a.mode, b.interface_id: b.mode}}))
            continue
        if a.native_vlan != b.native_vlan:
            logs = [e for e in events if e.kind == "NATIVE_VLAN_MISMATCH" and e.device_id in (a.device_id, b.device_id)]
            changed = b if b.native_vlan != 1 else a
            out.drafts.append(Draft(
                "VLAN_NATIVE_MISMATCH", "confirmed_fault", "misconfiguration", "major", f"Native VLAN mismatch on {link_id}",
                f"{a.interface_id} uses native VLAN {a.native_vlan} and {b.interface_id} uses {b.native_vlan}; untagged frames land in the "
                "wrong VLAN on the far side.", "two_sided", refs + [ref("protocol_events", e.event_id, e.timestamp) for e in logs][:2],
                "the two ends report different native VLANs", device_id=changed.device_id, site_id=site, affected_sites=[site] if site else [],
                timestamp=min((e.timestamp for e in logs), default=None), corroboration=int(bool(logs)),
                facts={"native": {a.interface_id: a.native_vlan, b.interface_id: b.native_vlan}}))
        required = sorted(set(a.allowed_vlans) | set(b.allowed_vlans))
        for vlan in required:
            missing_on = [p for p in (a, b) if vlan not in p.allowed_vlans]
            if not missing_on:
                continue
            port = missing_on[0]
            other = b if port is a else a
            name = vlan_names.get((site, vlan), f"VLAN {vlan}")
            affected_pools = pools.get((site, vlan), [])
            after = [e for e in ctx.dataset.dhcp.events if e.pool_id in affected_pools and e.timestamp >= ctx.onset]
            dependency = f" DHCP for that VLAN ({', '.join(affected_pools)}) has had no transactions since the onset." if affected_pools and not after else ""
            out.drafts.append(Draft(
                "VLAN_PRUNED", "confirmed_fault", "misconfiguration", "critical", f"VLAN {vlan} ({name}) not allowed on {port.interface_id}",
                f"{other.interface_id} carries VLAN {vlan} ({name}) but {port.interface_id} does not allow it, so hosts in that VLAN at {site} "
                f"cannot reach their gateway.{dependency}", "two_sided", refs,
                "one end allows the VLAN and the other end does not", device_id=port.device_id, site_id=site,
                affected_sites=[site] if site else [], facts={"vlan": vlan, "name": name, "allowed": {a.interface_id: a.allowed_vlans,
                                                                                                     b.interface_id: b.allowed_vlans},
                                                              "dhcp_pools": affected_pools}))
    databases = {d.device_id: set(d.vlans) for d in trunks.databases}
    for device, vlans in sorted(databases.items()):
        site = ctx.site_of.get(device)
        needed = {v.vlan_id for v in ctx.topology.vlans if v.site_id == site}
        for vlan in sorted(needed - vlans):
            out.drafts.append(Draft(
                "VLAN_MISSING_FROM_DATABASE", "confirmed_fault", "misconfiguration", "major", f"VLAN {vlan} missing on {device}",
                f"{device} has no VLAN {vlan} in its database although {site} uses it.", "direct", [ref("vlan_databases", device)],
                "the switch's VLAN database lacks a VLAN the site needs", device_id=device, site_id=site, affected_sites=[site] if site else [],
                facts={"vlan": vlan}))
    # ---- trunk configuration against spanning-tree state
    stp = ctx.telemetry.stp
    if stp is not None:
        stale = ctx.stale(stp.collected_at)
        for port in trunks.ports:
            name = port.interface_id.split(":", 1)[1]
            for vlan in port.allowed_vlans:
                state = next((p for p in stp.ports if p.device_id == port.device_id and p.port == name and p.vlan_id == vlan), None)
                if state is None or state.state == "forwarding":
                    continue
                site = ctx.site_of.get(port.device_id)
                out.drafts.append(Draft(
                    "VLAN_STP_CONFLICT", "insufficient_evidence" if stale else "possible_explanation", "conflicting_state", "minor",
                    f"VLAN {vlan} allowed but not forwarding on {port.interface_id}",
                    f"The trunk allows VLAN {vlan} but spanning tree shows {name} {state.role}/{state.state} for it; on a single uplink that "
                    "would cut the VLAN off." + (" The spanning-tree data is stale, so this may be an old state: recollect before acting." if stale else ""),
                    "none" if stale else "measured", [ref("trunk_ports", port.port_id), ref("stp_ports", state.port_id)],
                    "configuration and forwarding state contradict each other", device_id=port.device_id, site_id=site,
                    affected_sites=[site] if site else [], facts={"vlan": vlan, "stp_state": state.state, "stp_data_stale": stale}))
    native_one = [p.interface_id for p in trunks.ports if p.native_vlan == 1 and p.mode == "trunk"]
    if native_one:
        out.notes.append(f"{len(native_one)} trunk(s) use VLAN 1 as native; consider an unused native VLAN (hardening, not a fault).")
    return out
