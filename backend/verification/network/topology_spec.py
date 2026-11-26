from collections import deque

from app.network.models import DeviceType, InterfaceMode, LinkType, NetworkTopology, PathService, SiteType

BRANCHES = ("NYC", "SIN", "BLR")


def test_multiple_sites_of_each_kind(topology: NetworkTopology) -> None:
    site_types = {site.site_id: site.site_type for site in topology.sites}
    assert site_types == {
        "CORE": SiteType.CORE, "DC1": SiteType.DATA_CENTRE,
        "NYC": SiteType.BRANCH, "SIN": SiteType.BRANCH, "BLR": SiteType.BRANCH,
    }
    for site_id in site_types:
        assert any(device.site_id == site_id for device in topology.devices)


def test_all_device_types_present(topology: NetworkTopology) -> None:
    counts = {device_type: 0 for device_type in DeviceType}
    for device in topology.devices:
        counts[device.device_type] += 1
    assert counts == {DeviceType.ROUTER: 5, DeviceType.SWITCH: 5, DeviceType.FIREWALL: 2, DeviceType.SERVER: 5}


def test_device_identifiers_are_consistent(topology: NetworkTopology) -> None:
    sites = {site.site_id for site in topology.sites}
    for device in topology.devices:
        assert device.device_id.split("-")[0] == device.site_id
        assert device.hostname == device.device_id.lower()
        assert device.site_id in sites
    for interface in topology.interfaces:
        assert interface.interface_id == f"{interface.device_id}:{interface.name}"


def test_every_device_has_interfaces_and_links(topology: NetworkTopology) -> None:
    linked = {device for link in topology.links for device in (link.a_device_id, link.b_device_id)}
    owners = {interface.device_id for interface in topology.interfaces}
    assert owners == linked == {device.device_id for device in topology.devices}


def test_topology_is_fully_connected(topology: NetworkTopology) -> None:
    adjacency: dict[str, set[str]] = {}
    for link in topology.links:
        adjacency.setdefault(link.a_device_id, set()).add(link.b_device_id)
        adjacency.setdefault(link.b_device_id, set()).add(link.a_device_id)
    seen, queue = {"CORE-SW-01"}, deque(["CORE-SW-01"])
    while queue:
        for neighbor in adjacency[queue.popleft()] - seen:
            seen.add(neighbor)
            queue.append(neighbor)
    assert seen == {device.device_id for device in topology.devices}


def test_link_integrity(topology: NetworkTopology) -> None:
    interfaces = {interface.interface_id: interface for interface in topology.interfaces}
    for link in topology.links:
        a, b = interfaces[link.a_interface_id], interfaces[link.b_interface_id]
        assert a.mode != InterfaceMode.VIRTUAL and b.mode != InterfaceMode.VIRTUAL
        assert link.bandwidth_mbps <= min(a.speed_mbps, b.speed_mbps)
        if a.mode == InterfaceMode.ROUTED and b.mode == InterfaceMode.ROUTED and link.routing_protocol is not None:
            assert a.ip_address.network == b.ip_address.network
        if a.mode == InterfaceMode.TRUNK or b.mode == InterfaceMode.TRUNK:
            assert a.vlan_ids == b.vlan_ids


def test_each_branch_has_wan_link_and_vlans(topology: NetworkTopology) -> None:
    wan_links = [link for link in topology.links if link.link_type == LinkType.WAN]
    assert sorted(link.link_id for link in wan_links) == sorted(f"LNK-WAN-{site}" for site in BRANCHES)
    assert all(link.provider and link.circuit_id for link in wan_links)
    for site in BRANCHES:
        assert sorted(vlan.vlan_id for vlan in topology.vlans if vlan.site_id == site) == [10, 20, 99]
    assert [vlan.segment_id for vlan in topology.vlans if vlan.site_id == "DC1"] == ["DC1-VLAN100"]


def test_vlan_gateways_match_interfaces(topology: NetworkTopology) -> None:
    interfaces = {interface.interface_id: interface for interface in topology.interfaces}
    for vlan in topology.vlans:
        gateway = interfaces[vlan.gateway_interface_id]
        assert gateway.ip_address.ip == vlan.gateway
        assert gateway.ip_address.network == vlan.subnet


def test_routing_attributes(topology: NetworkTopology) -> None:
    devices = {device.device_id: device for device in topology.devices}
    for link in topology.links:
        if link.routing_protocol is not None and link.routing_protocol.value in ("ospf", "bgp"):
            assert devices[link.a_device_id].router_id is not None
            assert devices[link.b_device_id].router_id is not None
        if link.routing_protocol is not None and link.routing_protocol.value == "bgp":
            assert devices[link.a_device_id].bgp_asn != devices[link.b_device_id].bgp_asn


def test_paths_cover_every_branch_service(topology: NetworkTopology) -> None:
    assert {(path.source_site_id, path.service) for path in topology.paths} == {
        (site, service) for site in BRANCHES for service in PathService
    }
    devices = {device.device_id: device for device in topology.devices}
    for path in topology.paths:
        assert path.device_ids[0] == f"{path.source_site_id}-SW-01"
        assert devices[path.device_ids[-1]].site_id in ("DC1", "CORE")


def test_shared_devices_identify_common_failure_points(topology: NetworkTopology) -> None:
    def devices_for(site: str) -> set[str]:
        return {device for path in topology.paths if path.source_site_id == site for device in path.device_ids}

    nyc, sin, blr = devices_for("NYC"), devices_for("SIN"), devices_for("BLR")
    assert "CORE-RTR-01" in nyc & sin
    assert "CORE-RTR-01" not in blr
    assert {"CORE-SW-01", "DC1-FW-01", "DC1-SW-01"} <= nyc & sin & blr


def test_relationships(topology: NetworkTopology) -> None:
    triples = {(r.source_device_id, r.target_device_id, r.relationship_type.value) for r in topology.relationships}
    assert ("NYC-SW-01", "DC1-SRV-AUTH-01", "depends_on") in triples
    assert ("SIN-RTR-01", "CORE-RTR-01", "upstream") in triples
    assert ("BLR-RTR-01", "CORE-RTR-02", "upstream") in triples
    assert ("CORE-RTR-01", "CORE-RTR-02", "redundant_peer") in triples
