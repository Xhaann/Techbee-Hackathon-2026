from datetime import datetime

from app.engine.schema import Diagnosis
from app.incidents.errors import IncidentValidationError
from app.incidents.models import IMPACT_RANK, AffectedAsset, AssetType, ImpactBasis
from app.network.models import NetworkTopology, PathService


class TopologyIndex:
    def __init__(self, topology: NetworkTopology) -> None:
        self.topology = topology
        self.sites = {site.site_id for site in topology.sites}
        self.devices = {device.device_id: device for device in topology.devices}
        self.interfaces = {interface.interface_id for interface in topology.interfaces}
        self.links = {link.link_id: link for link in topology.links}
        self.paths = {path.path_id: path for path in topology.paths}
        self.connected = {frozenset((link.a_device_id, link.b_device_id)) for link in topology.links}
        self.known = {
            AssetType.SITE: self.sites,
            AssetType.DEVICE: set(self.devices),
            AssetType.SHARED_DEPENDENCY: set(self.devices),
            AssetType.INTERFACE: self.interfaces,
            AssetType.LINK: set(self.links),
            AssetType.PATH: set(self.paths),
            AssetType.SERVICE: {service.value for service in PathService},
        }

    def require_sites(self, site_ids: list[str]) -> None:
        unknown = sorted(set(site_ids) - self.sites)
        if unknown:
            raise IncidentValidationError(f"Unknown site identifiers: {', '.join(unknown)}")

    def require_devices(self, device_ids: list[str]) -> None:
        unknown = sorted(set(device_ids) - set(self.devices))
        if unknown:
            raise IncidentValidationError(f"Unknown device identifiers: {', '.join(unknown)}")

    def require_asset(self, asset_type: AssetType, asset_id: str) -> None:
        if asset_id not in self.known[asset_type]:
            raise IncidentValidationError(f"Unknown {asset_type.value} '{asset_id[:96]}'")

    def require_path(self, path: list[str]) -> None:
        self.require_devices(path)
        if any(frozenset(pair) not in self.connected for pair in zip(path, path[1:])):
            raise IncidentValidationError("Affected path is not consistent with topology links")


def merge_assets(existing: list[AffectedAsset], updates: list[AffectedAsset]) -> tuple[list[AffectedAsset], list[str]]:
    merged = {asset.key: asset for asset in existing}
    changes = []
    for update in updates:
        current = merged.get(update.key)
        if current is None:
            merged[update.key] = update
            changes.append(f"added {update.asset_type.value} {update.asset_id} ({update.basis.value})")
            continue
        basis = current.basis if IMPACT_RANK[current.basis] >= IMPACT_RANK[update.basis] else update.basis
        sources = list(dict.fromkeys(current.sources + update.sources))[:20]
        evidence = list(dict.fromkeys(current.evidence_ids + update.evidence_ids))[:50]
        if (basis, sources, evidence) != (current.basis, current.sources, current.evidence_ids):
            merged[update.key] = current.model_copy(update={"basis": basis, "sources": sources, "evidence_ids": evidence})
            if basis != current.basis:
                changes.append(f"{update.asset_type.value} {update.asset_id} upgraded to {basis.value}")
    ordered = sorted(merged.values(), key=lambda asset: (asset.asset_type.value, asset.asset_id))
    return ordered, changes


def asset(asset_type: AssetType, asset_id: str, basis: ImpactBasis, source: str, moment: datetime,
          evidence_ids: list[str] | None = None) -> AffectedAsset:
    return AffectedAsset(asset_type=asset_type, asset_id=asset_id, basis=basis, sources=[source],
                         evidence_ids=evidence_ids or [], first_recorded_at=moment)


def diagnosis_assets(index: TopologyIndex, diagnosis: Diagnosis, site_ids: list[str], source: str,
                     moment: datetime) -> list[AffectedAsset]:
    evidence = diagnosis.fault.supporting_evidence_ids[:20]
    inferred = ImpactBasis.INFERRED
    assets = [asset(AssetType.DEVICE, device, inferred, source, moment, evidence) for device in diagnosis.fault.device_ids]
    for link_id in diagnosis.fault.link_ids:
        link = index.links[link_id]
        assets.append(asset(AssetType.LINK, link_id, inferred, source, moment, evidence))
        assets += [asset(AssetType.INTERFACE, interface, inferred, source, moment, evidence)
                   for interface in (link.a_interface_id, link.b_interface_id)]
    if diagnosis.affected_path:
        assets += [asset(AssetType.DEVICE, device, inferred, source, moment) for device in diagnosis.affected_path.affected_devices]
        assets += [asset(AssetType.LINK, link, inferred, source, moment) for link in diagnosis.affected_path.affected_links]
        assets += [asset(AssetType.SHARED_DEPENDENCY, device, inferred, source, moment)
                   for device in diagnosis.affected_path.shared_dependencies]
    faulty = set(diagnosis.fault.device_ids) | set(diagnosis.fault.link_ids)
    for path in index.topology.paths:
        if path.source_site_id in site_ids and faulty & (set(path.device_ids) | set(path.link_ids)):
            assets.append(asset(AssetType.PATH, path.path_id, inferred, source, moment, evidence))
            assets.append(asset(AssetType.SERVICE, path.service.value, inferred, source, moment, evidence))
    for item in assets:
        index.require_asset(item.asset_type, item.asset_id)
    return assets
