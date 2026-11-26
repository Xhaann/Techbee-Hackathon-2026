from app.advanced.schema import BlastRadius, EvidenceRole, ImpactCategory, ImpactItem, PathAnalysis
from app.engine.schema import Diagnosis, EvidenceItem, EvidenceType
from app.incidents.models import AssetType, ImpactBasis, Incident
from app.network.models import NetworkTopology, SiteType

OBSERVED_ROLES = {EvidenceRole.PRIMARY_FAULT, EvidenceRole.SHARED_DEPENDENCY_FAILURE, EvidenceRole.SECONDARY_SYMPTOM}
OBSERVED_TYPES = {EvidenceType.OBSERVED_FINDING, EvidenceType.OBSERVED_RESULT, EvidenceType.RECORD}
INTERFACE_CODES = {"INTERFACE_DOWN", "HIGH_ERROR_COUNT", "HIGH_DROP_COUNT", "PACKET_LOSS_MEASURED", "HIGH_LATENCY",
                   "LINK_DOWN_AT_FAILURE_POINT", "PEER_LINKS_DOWN", "ERROR_COUNT_INCREASE"}
PATH_CODES = {"PATH_REACHABLE", "PATH_UNREACHABLE", "PATH_INDETERMINATE"}
PRECEDENCE = {ImpactCategory.OBSERVED: 0, ImpactCategory.REPORTED: 1, ImpactCategory.INFERRED: 2, ImpactCategory.POTENTIAL: 3}
NOTE = ("Business, customer, financial and SLA impact are not assessed; only synthetic network evidence is available. "
        "Inferred and potential impact are derived from topology and remain unverified.")


def interfaces_of(item: EvidenceItem) -> set[str]:
    return {ref.record_id.split("@", 1)[0] for ref in item.references if ref.collection == "interface_statistics"}


def blast_radius(diagnosis: Diagnosis, catalog: list[EvidenceItem], roles: dict[str, EvidenceRole], paths: list[PathAnalysis],
                 topology: NetworkTopology, incident: Incident | None) -> BlastRadius:
    items: dict[tuple[str, str], ImpactItem] = {}

    def add(asset_type: AssetType, asset_id: str, category: ImpactCategory, basis: str, evidence_ids: list[str]) -> None:
        key = (asset_type.value, asset_id)
        current = items.get(key)
        if current is None or PRECEDENCE[category] < PRECEDENCE[current.category]:
            merged = sorted(set(evidence_ids) | set(current.evidence_ids if current else []), key=lambda value: int(value[1:]))
            items[key] = ImpactItem(asset_type=asset_type, asset_id=asset_id, category=category, basis=basis, evidence_ids=merged)
        else:
            merged = sorted(set(current.evidence_ids) | set(evidence_ids), key=lambda value: int(value[1:]))
            items[key] = current.model_copy(update={"evidence_ids": merged})

    devices = {device.device_id: device for device in topology.devices}
    branches = {site.site_id for site in topology.sites if site.site_type == SiteType.BRANCH}
    for item in catalog:
        if roles.get(item.evidence_id) not in OBSERVED_ROLES or item.evidence_type not in OBSERVED_TYPES or item.code in PATH_CODES:
            continue
        if item.device_id:
            add(AssetType.DEVICE, item.device_id, ImpactCategory.OBSERVED, f"{item.code} observed by {item.tool}", [item.evidence_id])
        if item.code in INTERFACE_CODES:
            for interface in sorted(interfaces_of(item)):
                add(AssetType.INTERFACE, interface, ImpactCategory.OBSERVED, f"{item.code} on interface", [item.evidence_id])
    for analysis in paths:
        for link_id in analysis.failed_links + analysis.degraded_links:
            state = "down" if link_id in analysis.failed_links else "degraded"
            add(AssetType.LINK, link_id, ImpactCategory.OBSERVED, f"link {state} on the evaluated path", [])
    fault = diagnosis.fault
    support = fault.supporting_evidence_ids[:20]
    for device_id in fault.device_ids:
        add(AssetType.DEVICE, device_id, ImpactCategory.INFERRED, "suspected fault location (unverified)", support)
    for link_id in fault.link_ids:
        add(AssetType.LINK, link_id, ImpactCategory.INFERRED, "suspected fault location (unverified)", support)
    shared = sorted({d for analysis in paths for d in analysis.shared_devices} |
                    (set(diagnosis.affected_path.shared_dependencies) if diagnosis.affected_path else set()))
    for device_id in shared:
        add(AssetType.SHARED_DEPENDENCY, device_id, ImpactCategory.INFERRED, "device common to the affected paths", [])
    sites = set(diagnosis.incident.site_ids)
    faulty = set(fault.device_ids) | set(fault.link_ids)
    potential_sites = set()
    for path in topology.paths:
        if not faulty & (set(path.device_ids) | set(path.link_ids)):
            continue
        category = ImpactCategory.INFERRED if path.source_site_id in sites else ImpactCategory.POTENTIAL
        basis = ("modelled path traverses the suspected fault" if category == ImpactCategory.INFERRED
                 else "modelled path traverses the suspected fault but no evidence was collected for this site")
        add(AssetType.PATH, path.path_id, category, basis, [])
        add(AssetType.SERVICE, f"{path.source_site_id}:{path.service.value}", category, basis, [])
        if category == ImpactCategory.POTENTIAL:
            potential_sites.add(path.source_site_id)
    if incident is not None:
        for asset in incident.affected_assets:
            if asset.basis == ImpactBasis.REPORTED:
                add(asset.asset_type, asset.asset_id, ImpactCategory.REPORTED, "reported in the incident", [])
            elif asset.basis == ImpactBasis.CONFIRMED:
                add(asset.asset_type, asset.asset_id, ImpactCategory.OBSERVED, "confirmed by a human in the incident", [])
    affected_sites = sorted(sites | {devices[d].site_id for (kind, d), item in items.items()
                                     if kind == AssetType.DEVICE.value and item.category == ImpactCategory.OBSERVED and d in devices
                                     and devices[d].site_id in branches})
    ordered = sorted(items.values(), key=lambda i: (PRECEDENCE[i.category], i.asset_type.value, i.asset_id))
    return BlastRadius(items=ordered, affected_sites=affected_sites, potentially_affected_sites=sorted(potential_sites - sites),
                       shared_dependencies=shared, note=NOTE)


def incident_asset_updates(radius: BlastRadius, topology: NetworkTopology) -> list[tuple[AssetType, str]]:
    known = {AssetType.DEVICE: {d.device_id for d in topology.devices}, AssetType.LINK: {l.link_id for l in topology.links},
             AssetType.INTERFACE: {i.interface_id for i in topology.interfaces}, AssetType.PATH: {p.path_id for p in topology.paths},
             AssetType.SHARED_DEPENDENCY: {d.device_id for d in topology.devices}}
    return [(item.asset_type, item.asset_id) for item in radius.items
            if item.category in (ImpactCategory.OBSERVED, ImpactCategory.INFERRED) and item.asset_id in known.get(item.asset_type, set())]
