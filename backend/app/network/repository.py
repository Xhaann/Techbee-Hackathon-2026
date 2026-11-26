from functools import lru_cache
from pathlib import Path

from app.network.models import NetworkTopology, ScenarioDataset

DATA_DIR = Path(__file__).resolve().parent / "data"
TOPOLOGY_FILE = "topology.json"
SCENARIOS_DIR = "scenarios"
MAX_DATASET_BYTES = 5_000_000


class DatasetNotFoundError(LookupError):
    pass


class DatasetIntegrityError(ValueError):
    pass


@lru_cache
def read_dataset(path: Path) -> str:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_DATASET_BYTES:
        raise DatasetIntegrityError(f"Dataset file {path.name} is missing, linked or exceeds the size limit")
    return path.read_text(encoding="utf-8")


def load_topology(data_dir: Path = DATA_DIR) -> NetworkTopology:
    return NetworkTopology.model_validate_json(read_dataset(data_dir / TOPOLOGY_FILE))


def list_scenario_ids(data_dir: Path = DATA_DIR) -> list[str]:
    return sorted(path.stem for path in (data_dir / SCENARIOS_DIR).glob("*.json"))


@lru_cache
def load_scenario(scenario_id: str, data_dir: Path = DATA_DIR) -> ScenarioDataset:
    if scenario_id not in list_scenario_ids(data_dir):
        raise DatasetNotFoundError(f"unknown scenario: {scenario_id}")
    path = data_dir / SCENARIOS_DIR / f"{scenario_id}.json"
    dataset = ScenarioDataset.model_validate_json(read_dataset(path))
    errors = find_reference_errors(load_topology(data_dir), dataset)
    if dataset.scenario.scenario_id != scenario_id:
        errors.insert(0, f"file {path.name} contains scenario {dataset.scenario.scenario_id}")
    if errors:
        raise DatasetIntegrityError("; ".join(errors))
    return dataset


def find_reference_errors(topology: NetworkTopology, dataset: ScenarioDataset) -> list[str]:
    devices = {device.device_id: device for device in topology.devices}
    interface_ids = {interface.interface_id for interface in topology.interfaces}
    vlans = {(vlan.site_id, vlan.vlan_id): vlan for vlan in topology.vlans}
    routing, firewall, dhcp, dns = dataset.routing, dataset.firewall, dataset.dhcp, dataset.dns

    references = {
        "device": [event.device_id for event in dataset.events]
        + [sample.device_id for sample in dataset.interface_statistics]
        + [table.device_id for table in routing.routing_tables]
        + [neighbor.device_id for neighbor in routing.ospf_neighbors + routing.bgp_neighbors]
        + [neighbor.neighbor_device_id for neighbor in routing.ospf_neighbors + routing.bgp_neighbors]
        + [change.device_id for change in routing.route_changes]
        + [item.device_id for item in firewall.rules + firewall.events]
        + [pool.server_device_id for pool in dhcp.pools]
        + [server.device_id for server in dns.servers],
        "interface": [event.interface_id for event in dataset.events if event.interface_id]
        + [sample.interface_id for sample in dataset.interface_statistics]
        + [route.interface_id for table in routing.routing_tables for route in table.routes]
        + [neighbor.interface_id for neighbor in routing.ospf_neighbors],
        "site": [pool.site_id for pool in dhcp.pools],
    }
    if dataset.incident is not None:
        references["site"] += dataset.incident.affected_site_ids
    if dataset.ground_truth is not None:
        references["device"] += dataset.ground_truth.root_cause_device_ids
        references["site"] += dataset.ground_truth.affected_site_ids
        references["link"] = dataset.ground_truth.root_cause_link_ids
        references["path"] = dataset.ground_truth.affected_path_ids

    known = {
        "device": set(devices),
        "interface": interface_ids,
        "site": {site.site_id for site in topology.sites},
        "link": {link.link_id for link in topology.links},
        "path": {path.path_id for path in topology.paths},
    }
    errors = [
        f"unknown {label} reference: {value}"
        for label, values in references.items()
        for value in sorted(set(values) - known[label])
    ]

    for neighbor in routing.ospf_neighbors:
        remote = devices.get(neighbor.neighbor_device_id)
        if remote is not None and remote.router_id != neighbor.neighbor_router_id:
            errors.append(f"OSPF neighbor router id mismatch for {neighbor.neighbor_device_id}")
    for neighbor in routing.bgp_neighbors:
        local, remote = devices.get(neighbor.device_id), devices.get(neighbor.neighbor_device_id)
        if local is not None and remote is not None and (local.bgp_asn, remote.bgp_asn) != (neighbor.local_asn, neighbor.remote_asn):
            errors.append(f"BGP ASN mismatch between {neighbor.device_id} and {neighbor.neighbor_device_id}")
    for pool in dhcp.pools:
        vlan = vlans.get((pool.site_id, pool.vlan_id))
        if vlan is None or vlan.subnet != pool.subnet or vlan.gateway != pool.gateway:
            errors.append(f"DHCP pool {pool.pool_id} does not match a site VLAN")
    for server in dns.servers:
        device = devices.get(server.device_id)
        if device is not None and device.management_ip != server.ip_address:
            errors.append(f"DNS server {server.device_id} address does not match the device")
    return errors
