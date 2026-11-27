"""Loads the synthetic protocol telemetry for a scenario and checks every reference against the topology.

Telemetry is generated deterministically from the scenario dataset when first requested (app.protocols.scenarios) and
cached, so it always agrees with the core dataset it overlays. Integrity failures raise DatasetIntegrityError, like the
core datasets, and are reported to callers as unavailable data rather than half-trusted results.
"""
from functools import lru_cache

from app.network.models import NetworkTopology
from app.network.repository import DatasetIntegrityError, load_scenario, load_topology
from app.protocols.models import ProtocolTelemetry
from app.protocols.scenarios import build_telemetry_dict


@lru_cache(maxsize=48)
def load_telemetry(scenario_id: str) -> ProtocolTelemetry:
    dataset = load_scenario(scenario_id)
    try:
        telemetry = ProtocolTelemetry.model_validate(build_telemetry_dict(dataset))
    except ValueError as exc:
        raise DatasetIntegrityError(f"Protocol telemetry for {scenario_id} failed validation") from exc
    errors = reference_errors(load_topology(), telemetry) + duplicate_ids(telemetry)
    if errors:
        raise DatasetIntegrityError("; ".join(errors[:5]))
    return telemetry


def reference_errors(topology: NetworkTopology, t: ProtocolTelemetry) -> list[str]:
    devices = {d.device_id for d in topology.devices}
    interfaces = {i.interface_id for i in topology.interfaces}
    links = {link.link_id for link in topology.links}
    sites = {s.site_id for s in topology.sites}
    synthetic = set()
    if t.wireless is not None:
        synthetic |= {ap.ap_id for ap in t.wireless.access_points} | {c.controller_id for c in t.wireless.controllers}
    device_refs, interface_refs, site_refs = [], [], []
    device_refs += [e.device_id for e in t.events]
    if t.bgp:
        device_refs += [r.device_id for r in t.bgp.routes] + [r.peer_device_id for r in t.bgp.routes if r.peer_device_id]
        device_refs += [u.device_id for u in t.bgp.updates] + [s.device_id for s in t.bgp.sessions]
    if t.ospf:
        device_refs += [l.observed_by for l in t.ospf.lsas] + list(t.ospf.router_ids)
    if t.stp:
        device_refs += [v.device_id for v in t.stp.vlans] + [p.device_id for p in t.stp.ports]
        site_refs += [r.site_id for r in t.stp.expected_roots]
    if t.arp:
        device_refs += [e.device_id for e in t.arp.entries] + [g.device_id for g in t.arp.gateways]
    if t.vlan:
        device_refs += [p.device_id for p in t.vlan.ports]
        interface_refs += [p.interface_id for p in t.vlan.ports]
        if any(p.link_id not in links for p in t.vlan.ports):
            return ["trunk port references an unknown link"]
    if t.nat:
        device_refs += [p.device_id for p in t.nat.pools] + [r.device_id for r in t.nat.rules]
    if t.ipsec:
        device_refs += [x.device_id for x in t.ipsec.tunnels] + [x.peer_device_id for x in t.ipsec.tunnels]
        interface_refs += [x.underlay_interface_id for x in t.ipsec.tunnels if x.underlay_interface_id]
    if t.tcp:
        site_refs += [s.site_id for s in t.tcp.samples]
    if t.mtu:
        device_refs += [p.source_device_id for p in t.mtu.probes] + [c.device_id for c in t.mtu.counters] + list(t.mtu.icmp_filtered_on)
        interface_refs += [i.interface_id for i in t.mtu.interfaces]
    if t.qos:
        interface_refs += [p.interface_id for p in t.qos.policies] + [s.interface_id for s in t.qos.samples] + [m.interface_id for m in t.qos.markings]
        interface_refs += [e.interface_id for e in t.qos.expected]
    if t.ipv6:
        interface_refs += [a.interface_id for a in t.ipv6.addresses] + [r.interface_id for r in t.ipv6.routes] + [n.interface_id for n in t.ipv6.neighbors]
        device_refs += [n.neighbor_device_id for n in t.ipv6.neighbors] + [a.router_device_id for a in t.ipv6.adverts if a.router_device_id]
    if t.wireless:
        device_refs += [ap.switch_device_id for ap in t.wireless.access_points] + [s.ap_id for s in t.wireless.samples]
        site_refs += [ap.site_id for ap in t.wireless.access_points]
    if t.multicast:
        device_refs += [n.device_id for n in t.multicast.neighbors] + [n.neighbor_device_id for n in t.multicast.neighbors]
        interface_refs += [n.interface_id for n in t.multicast.neighbors] + [m.incoming_interface_id for m in t.multicast.mroutes if m.incoming_interface_id]
        interface_refs += [i for m in t.multicast.mroutes for i in m.outgoing_interface_ids]
        device_refs += [g.device_id for g in t.multicast.groups] + [s.source_device_id for s in t.multicast.streams]
    if t.tls:
        device_refs += [c.device_id for c in t.tls.certificates] + [p.device_id for p in t.tls.inspection]
    if t.security:
        device_refs += [f.sensor_device_id for f in t.security.flows] + [a.sensor_device_id for a in t.security.alerts]
        site_refs += [h.site_id for h in t.security.hosts]
    errors = [f"unknown device reference: {d}" for d in sorted(set(device_refs) - devices - synthetic)]
    errors += [f"unknown interface reference: {i}" for i in sorted(set(interface_refs) - interfaces)]
    errors += [f"unknown site reference: {s}" for s in sorted(set(site_refs) - sites)]
    return errors


def duplicate_ids(t: ProtocolTelemetry) -> list[str]:
    """Every record id must be unique in its collection, or a citation could point at two different records."""
    lists = {"protocol_events": [e.event_id for e in t.events]}
    if t.bgp:
        lists |= {"bgp_routes": [r.route_id for r in t.bgp.routes], "bgp_updates": [u.update_id for u in t.bgp.updates]}
    if t.ospf:
        lists |= {"ospf_lsas": [l.lsa_id for l in t.ospf.lsas], "lsa_updates": [u.update_id for u in t.ospf.updates]}
    if t.stp:
        lists |= {"stp_vlans": [v.state_id for v in t.stp.vlans], "stp_ports": [p.port_id for p in t.stp.ports]}
    if t.arp:
        lists |= {"arp_entries": [e.entry_id for e in t.arp.entries]}
    if t.ipsec:
        lists |= {"ipsec_tunnels": [x.tunnel_id for x in t.ipsec.tunnels]}
    if t.tcp:
        lists |= {"tcp_samples": [s.sample_id for s in t.tcp.samples]}
    if t.mtu:
        lists |= {"mtu_probes": [p.probe_id for p in t.mtu.probes]}
    if t.qos:
        lists |= {"qos_samples": [s.sample_id for s in t.qos.samples], "qos_markings": [m.observation_id for m in t.qos.markings]}
    if t.ipv6:
        lists |= {"ipv6_routes": [r.route_id for r in t.ipv6.routes], "router_adverts": [a.ra_id for a in t.ipv6.adverts]}
    if t.wireless:
        lists |= {"radio_samples": [s.sample_id for s in t.wireless.samples]}
    if t.multicast:
        lists |= {"mroutes": [m.mroute_id for m in t.multicast.mroutes], "pim_neighbors": [n.neighbor_id for n in t.multicast.neighbors]}
    if t.tls:
        lists |= {"tls_handshakes": [h.handshake_id for h in t.tls.handshakes]}
    if t.security:
        lists |= {"security_flows": [f.flow_id for f in t.security.flows], "auth_events": [a.auth_id for a in t.security.auth],
                  "dns_logs": [d.log_id for d in t.security.dns_logs], "ids_alerts": [a.alert_id for a in t.security.alerts]}
    return [f"duplicate {name} id: {value}" for name, values in lists.items() for value in sorted({v for v in values if values.count(v) > 1})]


def record_index(t: ProtocolTelemetry) -> dict[str, set[str]]:
    """Every record id a protocol finding may cite, by collection, for provenance checks."""
    index: dict[str, set[str]] = {"protocol_events": {e.event_id for e in t.events}}
    if t.bgp:
        index |= {"bgp_routes": {r.route_id for r in t.bgp.routes}, "bgp_updates": {u.update_id for u in t.bgp.updates},
                  "bgp_sessions": {s.session_id for s in t.bgp.sessions}}
    if t.ospf:
        index |= {"ospf_lsas": {l.lsa_id for l in t.ospf.lsas}, "lsa_updates": {u.update_id for u in t.ospf.updates},
                  "ospf_router_ids": set(t.ospf.router_ids)}
    if t.stp:
        index |= {"stp_vlans": {v.state_id for v in t.stp.vlans}, "stp_ports": {p.port_id for p in t.stp.ports}}
    if t.arp:
        index |= {"arp_entries": {e.entry_id for e in t.arp.entries}}
    if t.vlan:
        index |= {"trunk_ports": {p.port_id for p in t.vlan.ports}, "vlan_databases": {d.device_id for d in t.vlan.databases}}
    if t.nat:
        index |= {"nat_pools": {p.pool_id for p in t.nat.pools}, "nat_rules": {r.rule_id for r in t.nat.rules},
                  "nat_samples": {s.sample_id for s in t.nat.samples}, "nat_talkers": {x.talker_id for x in t.nat.top_talkers}}
    if t.ipsec:
        index |= {"ipsec_tunnels": {x.tunnel_id for x in t.ipsec.tunnels}}
    if t.tcp:
        index |= {"tcp_samples": {s.sample_id for s in t.tcp.samples}}
    if t.mtu:
        index |= {"mtu_probes": {p.probe_id for p in t.mtu.probes}, "mtu_interfaces": {i.interface_id for i in t.mtu.interfaces},
                  "mtu_counters": {c.counter_id for c in t.mtu.counters}}
    if t.qos:
        index |= {"qos_policies": {p.policy_id for p in t.qos.policies} | {f"{e.interface_id}|{e.direction}" for e in t.qos.expected},
                  "qos_samples": {s.sample_id for s in t.qos.samples}, "qos_markings": {m.observation_id for m in t.qos.markings}}
    if t.ipv6:
        index |= {"ipv6_routes": {r.route_id for r in t.ipv6.routes}, "ospfv3_neighbors": {n.neighbor_id for n in t.ipv6.neighbors},
                  "router_adverts": {a.ra_id for a in t.ipv6.adverts}, "ipv6_probes": {p.probe_id for p in t.ipv6.probes}}
    if t.wireless:
        index |= {"radio_samples": {s.sample_id for s in t.wireless.samples}, "rogue_aps": {r.rogue_id for r in t.wireless.rogues}}
    if t.multicast:
        index |= {"pim_neighbors": {n.neighbor_id for n in t.multicast.neighbors}, "rp_mappings": {r.mapping_id for r in t.multicast.rp_mappings},
                  "mroutes": {m.mroute_id for m in t.multicast.mroutes}, "igmp_groups": {g.group_id for g in t.multicast.groups}}
    if t.tls:
        index |= {"certificates": {c.certificate_id for c in t.tls.certificates}, "tls_handshakes": {h.handshake_id for h in t.tls.handshakes}}
    if t.security:
        index |= {"security_flows": {f.flow_id for f in t.security.flows}, "auth_events": {a.auth_id for a in t.security.auth},
                  "dns_logs": {d.log_id for d in t.security.dns_logs}, "ids_alerts": {a.alert_id for a in t.security.alerts}}
    return index


from app.security.provenance import PROTOCOL_COLLECTIONS  # noqa: E402,F401  (one list, defined with the provenance checks)
