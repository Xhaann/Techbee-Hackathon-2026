import json

import pytest
from pydantic import ValidationError

from app.engine.schema import FaultDomain
from app.knowledge import KnowledgeQuery, KnowledgeRetriever, MatchType, PlaybookRetriever, RecordType
from app.network.models import DeviceType, PathService
from app.network.repository import load_scenario

RETRIEVER = KnowledgeRetriever()


def search(**values: object):
    return RETRIEVER.search(KnowledgeQuery(**values))


def test_exact_match_from_domain_and_findings() -> None:
    result = search(fault_domain=FaultDomain.ROUTING, finding_codes=["ADJACENCY_STALLED", "CONTROL_PLANE_FAILURE_SUSPECTED"],
                    record_types=[RecordType.PLAYBOOK])
    top = result.matches[0]
    assert top.record_id == "PB-OSPF-ADJACENCY-FAILURE" and top.match_type == MatchType.EXACT
    assert top.matched_codes == ["ADJACENCY_STALLED", "CONTROL_PLANE_FAILURE_SUSPECTED"]
    assert any("fault domain routing" in reason for reason in top.reasons)
    assert top.sources[0].source_id == "SRC-SYNTHETIC-PLAYBOOKS" and "Guidance only" in top.notice


def test_partial_match_from_text_only() -> None:
    result = search(text="New laptops cannot obtain an IP address and show a self-assigned address")
    top = result.matches[0]
    assert top.record_id == "PB-DHCP-ALLOCATION-FAILURE" and top.match_type == MatchType.PARTIAL
    assert {"address", "laptop"} <= set(top.matched_terms) and top.matched_codes == []


@pytest.mark.parametrize("scenario_id, expected", [
    ("WAN-FAILURE", "PB-WAN-FAILURE"), ("PACKET-LOSS", "PB-PACKET-LOSS"), ("FIREWALL-BLOCKING", "PB-FIREWALL-BLOCKING"),
    ("DHCP-ALLOCATION-FAILURE", "PB-DHCP-ALLOCATION-FAILURE"), ("DNS-RESOLUTION-FAILURE", "PB-DNS-RESOLUTION-FAILURE"),
    ("VLAN-AUTHENTICATION-FAILURE", "PB-VLAN-AUTHENTICATION-FAILURE"), ("OSPF-ADJACENCY-FAILURE", "PB-OSPF-ADJACENCY-FAILURE"),
])
def test_incident_text_ranks_the_relevant_playbook_first(scenario_id: str, expected: str) -> None:
    incident = load_scenario(scenario_id).incident
    playbooks = search(text=incident.description, symptoms=incident.symptoms, record_types=[RecordType.PLAYBOOK]).matches
    assert playbooks[0].record_id == expected


def test_multiple_matching_playbooks_are_ranked() -> None:
    result = search(text="branch offline WAN circuit down", finding_codes=["NO_ROUTE_TO_DESTINATION"],
                    record_types=[RecordType.PLAYBOOK])
    ids = [m.record_id for m in result.matches]
    assert ids[0] == "PB-WAN-FAILURE" and len(ids) >= 2
    points = [m.points for m in result.matches]
    assert points == sorted(points, reverse=True)


def test_fault_domain_filter_excludes_other_domains() -> None:
    result = search(text="names do not resolve and the firewall denies", fault_domain=FaultDomain.DNS)
    assert result.matches and all(not RETRIEVER.repository.get(m.record_id).fault_domains
                                  or FaultDomain.DNS in RETRIEVER.repository.get(m.record_id).fault_domains for m in result.matches)
    assert "PB-FIREWALL-BLOCKING" not in [m.record_id for m in result.matches]


def test_site_specific_runbooks() -> None:
    result = search(site_id="BLR", fault_domain=FaultDomain.ROUTING, record_types=[RecordType.RUNBOOK])
    assert [m.record_id for m in result.matches] == ["RB-BLR-BRANCH"]
    assert any("site BLR" in reason for reason in result.matches[0].reasons)
    other = search(site_id="NYC", fault_domain=FaultDomain.ROUTING, record_types=[RecordType.RUNBOOK])
    assert "RB-BLR-BRANCH" not in [m.record_id for m in other.matches]


def test_device_and_service_filters() -> None:
    server = search(text="pool exhausted dhcp lease", device_type=DeviceType.SERVER)
    assert server.matches[0].record_id == "PB-DHCP-ALLOCATION-FAILURE"
    assert all(m.record_id != "PB-WAN-FAILURE" for m in server.matches)
    dns = search(text="servfail zone dns", service=PathService.DNS)
    assert "PB-DHCP-ALLOCATION-FAILURE" not in [m.record_id for m in dns.matches]


def test_ranking_is_deterministic() -> None:
    query = KnowledgeQuery(text="Two branches lost connectivity at the same time", symptoms=["core router not responding"])
    first = json.dumps(RETRIEVER.search(query).model_dump(mode="json"), sort_keys=True)
    assert all(json.dumps(KnowledgeRetriever().search(query).model_dump(mode="json"), sort_keys=True) == first for _ in range(3))


def test_no_match_is_explicit_and_limits_are_not_filled() -> None:
    result = search(text="The coffee machine in the kitchen is broken", limit=10)
    assert result.no_match and result.matches == [] and "No knowledge records" in result.message
    weak = search(text="interface", limit=10)
    assert weak.no_match
    assert search(text="pool lease").no_match
    assert search(finding_codes=["HIGH_LATENCY"]).no_match
    narrow = search(fault_domain=FaultDomain.FIREWALL, limit=10)
    assert len(narrow.matches) < 10 and all(m.points >= 3 for m in narrow.matches)


@pytest.mark.parametrize("values", [{}, {"text": "   "}, {"limit": 0}, {"limit": 50}, {"fault_domain": "satellite"},
                                    {"text": "x", "site_id": "../etc"}, {"text": "x", "finding_codes": ["not a code"]},
                                    {"text": "x" * 4001}, {"text": "x", "unexpected": 1}, {"text": "x", "device_type": "toaster"}])
def test_unsupported_inputs_are_rejected(values: dict) -> None:
    with pytest.raises(ValidationError):
        KnowledgeQuery(**values)


def test_scores_are_points_not_probabilities() -> None:
    match = search(fault_domain=FaultDomain.DNS, finding_codes=["DNS_SERVFAIL"]).matches[0]
    assert isinstance(match.points, int) and match.points > 1
    assert "probab" not in json.dumps(match.model_dump(mode="json")).lower()


def test_phase4_retriever_adapter() -> None:
    documents = PlaybookRetriever(RETRIEVER).search("Wired desktops show authentication failed", 3)
    assert documents[0].document_id == "PB-VLAN-AUTHENTICATION-FAILURE"
    assert "Guidance only" in documents[0].content and "[illustrative, read-only]" in documents[0].content
    assert documents[0].source == "SRC-SYNTHETIC-PLAYBOOKS" and len(documents[0].content) <= 4000
    assert PlaybookRetriever(RETRIEVER).search("", 3) == [] and PlaybookRetriever(RETRIEVER).search("coffee machine broken", 3) == []
