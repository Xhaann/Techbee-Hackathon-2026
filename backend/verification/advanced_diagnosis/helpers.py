from functools import lru_cache

from app.advanced import AdvancedDiagnosis, AdvancedDiagnosisEngine, AdvancedRequest
from app.engine.schema import FaultDomain
from app.knowledge import KnowledgeService
from verification.engine.helpers import incident_request

KNOWLEDGE = KnowledgeService()
EXPECTED = {
    "WAN-FAILURE": (FaultDomain.WAN_ISP, ["SIN-RTR-01"]),
    "PACKET-LOSS": (FaultDomain.WAN_ISP, ["NYC-RTR-01"]),
    "OSPF-ADJACENCY-FAILURE": (FaultDomain.ROUTING, ["BLR-RTR-01", "CORE-RTR-02"]),
    "FIREWALL-BLOCKING": (FaultDomain.FIREWALL, ["DC1-FW-01"]),
    "DHCP-ALLOCATION-FAILURE": (FaultDomain.DHCP, ["DC1-SRV-DHCP-01"]),
    "DNS-RESOLUTION-FAILURE": (FaultDomain.DNS, ["DC1-SRV-DNS-01"]),
    "VLAN-AUTHENTICATION-FAILURE": (FaultDomain.VLAN_AUTHENTICATION, ["DC1-SRV-AUTH-01", "NYC-SW-01"]),
    "SHARED-DEVICE-FAILURE": (FaultDomain.SHARED_INFRASTRUCTURE, ["CORE-RTR-01"]),
}


@lru_cache
def analysis(scenario_id: str, supplementary: int = 3) -> AdvancedDiagnosis:
    engine = AdvancedDiagnosisEngine(knowledge=KNOWLEDGE)
    return engine.analyze(AdvancedRequest(diagnosis=incident_request(scenario_id), supplementary_tool_calls=supplementary))


def items(result: AdvancedDiagnosis, category: str, asset_type: str | None = None) -> set[str]:
    return {i.asset_id for i in result.blast_radius.items
            if i.category.value == category and (asset_type is None or i.asset_type.value == asset_type)}
