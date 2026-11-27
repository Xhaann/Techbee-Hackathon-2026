"""Packet journey: the hop-by-hop path one packet takes, with routing, policy, link health, latency and MTU at each hop."""
import re
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from app.diagnostics.common import ToolInputError, invalid, load_dataset, sample_ref, samples_for
from app.diagnostics.topology import Forwarding, resolve_endpoint, vlan_for
from app.network.models import DeviceRole, DeviceType, LinkStatus, LinkType, TransportProtocol, match_firewall_rule
from app.observability.simulation import running_config, scenario_flows

LAN_HOP_MS = 0.3
INTERNAL = [IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]
MTU_LINE = re.compile(r"^ mtu (\d+)$")
VERDICT_TEXT = {
    "delivered": "The packet reaches its destination",
    "dropped_by_policy": "A firewall rule drops the packet",
    "link_down": "A link on the path is down",
    "no_route": "A router has no route to the destination",
    "leaves_network": "The packet leaves the modelled network toward the internet",
    "indeterminate": "The path cannot be fully determined from the available telemetry",
}


def interface_mtu(scenario_id: str, interface_id: str, documented: int) -> int:
    device_id, name = interface_id.split(":", 1)
    lines = running_config(scenario_id, device_id)
    try:
        start = lines.index(f"interface {name}") + 1
    except ValueError:
        return documented
    for line in lines[start:]:
        if not line.startswith(" "):
            break
        if match := MTU_LINE.match(line):
            return int(match.group(1))
    return documented


def resolve_destination(topology, value: Any):
    try:
        return resolve_endpoint(topology, value, "destination")
    except ToolInputError as error:
        try:
            address = IPv4Address(value)
        except (ValueError, TypeError):
            raise error from None
        if not any(address in network for network in INTERNAL) and not address.is_multicast and not address.is_unspecified:
            return None, address, [f"{address} is outside the modelled network; the journey is traced to the internet edge"]
        raise


def trace(scenario_id: str, source: Any, destination: Any, protocol: str = "tcp", port: int | None = None,
          size_bytes: int = 1500) -> dict[str, Any]:
    topology, dataset = load_dataset(scenario_id)
    try:
        transport = TransportProtocol(protocol)
    except ValueError:
        raise invalid(f"protocol must be one of: {', '.join(p.value for p in TransportProtocol)}") from None
    if port is not None and (isinstance(port, bool) or not isinstance(port, int) or not 0 < port <= 65535):
        raise invalid("port must be an integer between 1 and 65535")
    if not isinstance(size_bytes, int) or not 64 <= size_bytes <= 9216:
        raise invalid("size_bytes must be between 64 and 9216")
    source_device, source_address, notes = resolve_endpoint(topology, source, "source")
    destination_device, destination_address, more = resolve_destination(topology, destination)
    devices = {d.device_id: d for d in topology.devices}
    interfaces = {i.interface_id: i for i in topology.interfaces}
    links = {l.link_id: l for l in topology.links}
    forwarding = Forwarding(topology, dataset)
    routed = source_device is not None and any(l.routing_protocol is not None and source_device.device_id in (l.a_device_id, l.b_device_id)
                                               for l in topology.links)
    access_prefix: list[tuple[str, str]] = []
    if routed:
        start, failure = source_device.device_id, None
    else:
        vlan = vlan_for(topology, source_address)
        if vlan is None:
            raise invalid(f"source {source_address} has no gateway VLAN")
        start = vlan.gateway_interface_id.split(":", 1)[0]
        if source_device is not None:
            failure = forwarding.layer2(source_device.device_id, start)
        else:
            # A host on a user VLAN enters through its site's access switch.
            switch = next((d for d in topology.devices if d.site_id == vlan.site_id and d.role == DeviceRole.ACCESS_SWITCH), None)
            link = next((l for l in topology.links if switch and {l.a_device_id, l.b_device_id} == {switch.device_id, start}), None)
            if switch and link:
                access_prefix = [(switch.device_id, link.link_id)]
            failure = None
    status = "unreachable"
    if failure is None:
        status, failure = forwarding.run(start, destination_device, destination_address)
    hop_routes = {}
    for hop in forwarding.hops:
        hop_routes.setdefault(hop["device_id"], hop)
    sequence: list[tuple[str, str | None]] = list(access_prefix)
    for hop in forwarding.hops:
        sequence.append((hop["device_id"], hop.get("link_id") if hop.get("next_device_id") else None))
    if forwarding.hops and forwarding.hops[-1].get("next_device_id"):
        sequence.append((forwarding.hops[-1]["next_device_id"], None))
    # Collapse consecutive entries for the same device (delivery and layer-2 hops on one switch).
    ordered: list[list[Any]] = []
    for device_id, link_id in sequence:
        if ordered and ordered[-1][0] == device_id:
            ordered[-1][1] = ordered[-1][1] or link_id
        else:
            ordered.append([device_id, link_id])
    if failure and failure.get("device_id") and failure["device_id"] not in {entry[0] for entry in ordered}:
        ordered.append([failure["device_id"], None])
    elif not ordered:
        ordered.append([start, None])
    hops, cumulative, verdict, verdict_hop, path_mtu, evidence = [], 0.0, None, None, None, []
    previous_link = None
    for index, (device_id, link_id) in enumerate(ordered):
        device = devices[device_id]
        route = hop_routes.get(device_id, {})
        hop: dict[str, Any] = {"index": index + 1, "device_id": device_id, "hostname": device.hostname, "site_id": device.site_id,
                               "device_type": device.device_type.value, "role": device.role.value}
        if previous_link is not None:
            hop["ingress_interface"] = next(i for i in (previous_link.a_interface_id, previous_link.b_interface_id)
                                            if interfaces[i].device_id == device_id)
        if route.get("route"):
            hop["route"] = {"prefix": route["route"], "protocol": route["protocol"], "next_hop": route.get("next_hop")}
        if device.device_type == DeviceType.FIREWALL:
            rule = match_firewall_rule(dataset.firewall.rules, device_id, source_address, destination_address, transport, port,
                                       dataset.scenario.window_end)
            hop["policy"] = {"rule_id": rule.rule_id, "name": rule.name, "action": rule.action.value} if rule else \
                {"rule_id": None, "name": "implicit", "action": "no matching rule"}
            if rule is not None:
                evidence.append({"collection": "firewall_rules", "record_id": rule.rule_id, "timestamp": rule.last_modified.isoformat()})
                if rule.action.value == "deny" and verdict is None:
                    verdict, verdict_hop = "dropped_by_policy", index + 1
        if link_id:
            link = links[link_id]
            egress = next(i for i in (link.a_interface_id, link.b_interface_id) if interfaces[i].device_id == device_id)
            mtu = interface_mtu(scenario_id, egress, interfaces[egress].mtu)
            samples = samples_for(dataset, egress) or samples_for(dataset, link.b_interface_id if egress == link.a_interface_id else link.a_interface_id)
            latest = samples[-1] if samples else None
            down = latest is not None and latest.oper_status == LinkStatus.DOWN
            latency = (latest.latency_ms if latest and latest.latency_ms is not None and not down else
                       link.latency_ms if link.link_type == LinkType.WAN else LAN_HOP_MS)
            cumulative += 0 if down else latency
            path_mtu = mtu if path_mtu is None else min(path_mtu, mtu)
            hop["egress"] = {"interface_id": egress, "link_id": link_id, "link_type": link.link_type.value,
                             "status": "down" if down else ("up" if latest else "unknown"), "mtu": mtu,
                             "utilization_percent": latest.utilization_percent if latest else None,
                             "loss_percent": latest.packet_loss_percent if latest else None,
                             "latency_ms": round(latency, 2), "measured": bool(latest and latest.latency_ms is not None)}
            if latest is not None:
                evidence.append({"collection": "interface_statistics", "record_id": sample_ref(latest).record_id,
                                 "timestamp": latest.timestamp.isoformat()})
            if down and verdict is None:
                verdict, verdict_hop = "link_down", index + 1
            previous_link = link
        hop["cumulative_latency_ms"] = round(cumulative, 2)
        hops.append(hop)
        if verdict is not None:
            break
    if verdict is None:
        reason = (failure or {}).get("reason")
        if status == "reachable":
            verdict = "delivered"
        elif reason == "link_down":
            verdict = "link_down"
        elif reason == "no_route":
            verdict = "no_route"
        elif reason == "unknown_next_hop" and destination_device is None and not any(destination_address in n for n in INTERNAL):
            verdict = "leaves_network"
        else:
            verdict = "indeterminate"
        verdict_hop = next((h["index"] for h in hops if failure and h["device_id"] == failure.get("device_id")), len(hops))
    observed = [f for f in scenario_flows(scenario_id) if f.src_ip == str(source_address) and f.dst_ip == str(destination_address)
                and (port is None or f.dst_port == port)]
    flows = {"matching": len(observed), "forwarded": sum(f.action == "forwarded" for f in observed),
             "dropped": sum(f.action == "dropped" for f in observed), "examples": [f.flow_id for f in observed[:5]]}
    mtu_note = None
    if path_mtu is not None and size_bytes > path_mtu:
        mtu_note = f"Path MTU is {path_mtu} bytes; a {size_bytes}-byte packet needs fragmentation (or is dropped when DF is set)"
    stop = next((h for h in hops if h["index"] == verdict_hop), None)
    if stop is not None and verdict in ("no_route", "link_down", "indeterminate"):
        # Where forwarding stops, compare the MTU at both ends of each routed link: a mismatch keeps OSPF from forming.
        stop["attached_links"] = []
        for link in topology.links:
            if stop["device_id"] not in (link.a_device_id, link.b_device_id) or link.routing_protocol is None:
                continue
            ends = {i: interface_mtu(scenario_id, i, interfaces[i].mtu) for i in (link.a_interface_id, link.b_interface_id)}
            stop["attached_links"].append({"link_id": link.link_id, "mtu": ends, "mismatch": len(set(ends.values())) > 1})
            if len(set(ends.values())) > 1:
                described = " vs ".join(f"{i} {m}" for i, m in ends.items())
                mtu_note = f"MTU mismatch on {link.link_id} ({described}); routing adjacencies cannot form across it"
    return {
        "scenario_id": dataset.scenario.scenario_id,
        "request": {"source": source, "destination": destination, "protocol": transport.value, "port": port, "size_bytes": size_bytes},
        "source": {"device_id": source_device.device_id if source_device else None, "address": str(source_address)},
        "destination": {"device_id": destination_device.device_id if destination_device else None, "address": str(destination_address)},
        "verdict": verdict, "verdict_text": VERDICT_TEXT[verdict], "verdict_hop": verdict_hop, "failure": failure,
        "hops": hops, "total_latency_ms": round(cumulative, 2), "path_mtu": path_mtu, "mtu_note": mtu_note,
        "observed_flows": flows, "evidence": evidence[:40], "notes": notes + more,
        "evaluated_at": dataset.scenario.window_end.isoformat(),
        "limitations": ["Forward path only, evaluated at the end of the scenario window",
                        "Latency is the latest measured value per WAN link, or the documented figure when unmeasured"],
    }
