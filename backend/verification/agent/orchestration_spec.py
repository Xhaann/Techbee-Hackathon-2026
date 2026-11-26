import json

from app.agent.tools import MAX_KNOWLEDGE_CALLS, ToolBudget
from app.engine.executor import ToolExecutor
from app.knowledge import KnowledgeService
from verification.agent.helpers import answer, call, cite, raw_call, scripted_agent
from verification.engine.helpers import draft

SINGAPORE = "Users at the Singapore branch cannot access internal applications."


def test_tools_execute_through_tool_executor() -> None:
    agent, model = scripted_agent([call("check_network_reachability", source="SIN-SW-01", destination="DC1-SRV-APP-01"),
                                   answer(cite("LINK_DOWN_AT_FAILURE_POINT", "NO_ROUTE_TO_DESTINATION"))])
    run = agent.run("WAN-FAILURE", SINGAPORE)
    assert [(r.call_id, r.tool, r.status) for r in run.records] == [("C1", "check_network_reachability", "executed")]
    result = json.loads(model.tool_messages()[0])
    assert result["call_id"] == "C1" and {e["evidence_id"] for e in result["evidence"]} >= {"E1"}
    assert run.diagnosis.method.value == "model" and run.agent_completed


def test_invalid_and_unknown_tool_calls_never_execute() -> None:
    agent, model = scripted_agent([raw_call("check_device_availability", '{"device_id": 42}'), call("run_shell", command="id"),
                                   call("get_routing_state", device_id="NOT-A-DEVICE"), raw_call("get_topology", "not-json"),
                                   answer("not json")])
    run = agent.run("WAN-FAILURE", SINGAPORE)
    messages = model.tool_messages()
    assert len(messages) == 4 and "Argument parsing failed" in messages[0] and "not found" in messages[1]
    assert json.loads(messages[2])["error"]["code"] == "NOT_FOUND"
    assert not any(r.tool == "run_shell" for r in run.records)


def test_duplicate_calls_are_rejected() -> None:
    agent, model = scripted_agent([call("analyze_routing_adjacency", device_id="SIN-RTR-01"),
                                   call("analyze_routing_adjacency", device_id="SIN-RTR-01"),
                                   call("search_knowledge", query="wan circuit down"), call("search_knowledge", query="WAN   circuit down"),
                                   answer("not json")])
    run = agent.run("WAN-FAILURE", SINGAPORE)
    statuses = [(r.tool, r.status, r.error_code) for r in run.records][:2]
    assert statuses == [("analyze_routing_adjacency", "executed", None), ("analyze_routing_adjacency", "duplicate", "DUPLICATE_CALL")]
    assert json.loads(model.tool_messages()[3])["error"]["code"] == "DUPLICATE_CALL"


def test_global_budget_spans_turns_tools_and_knowledge() -> None:
    devices = ["SIN-RTR-01", "SIN-SW-01", "CORE-RTR-01", "CORE-RTR-02", "BLR-RTR-01", "BLR-SW-01", "NYC-RTR-01", "NYC-SW-01",
               "DC1-FW-01", "DC1-SW-01", "CORE-SW-01"]
    steps = [call("search_knowledge", query="wan circuit down")] + [call("check_device_availability", device_id=d) for d in devices]
    agent, model = scripted_agent(steps + [answer("not json")])
    run = agent.run("WAN-FAILURE", SINGAPORE)
    assert run.budget.attempts == 10 and len(run.budget.order) == 10
    assert len([r for r in run.records if r.status == "executed"]) == 9
    assert not any(r.arguments.get("device_id") in ("DC1-SW-01", "CORE-SW-01") for r in run.records)
    assert len(model.requests) <= 13


def test_budget_refusals_are_reported_to_model() -> None:
    steps = [call("check_device_availability", device_id=d) for d in
             ["SIN-RTR-01", "SIN-SW-01", "CORE-RTR-01", "CORE-RTR-02", "BLR-RTR-01", "BLR-SW-01", "NYC-RTR-01", "NYC-SW-01", "DC1-FW-01"]]
    steps += [call("get_device_logs", device_id="SIN-RTR-01"), call("get_device_logs", device_id="CORE-RTR-01")]
    agent, model = scripted_agent(steps + [answer("not json")])
    run = agent.run("WAN-FAILURE", SINGAPORE)
    assert run.budget.attempts == 10
    assert all(len([m for m in r["messages"] if m["role"] == "tool"]) <= 10 for r in model.requests)


def test_tools_run_sequentially() -> None:
    agent, model = scripted_agent([{"tool_calls": [("check_device_availability", {"device_id": "SIN-RTR-01"}),
                                                   ("check_device_availability", {"device_id": "CORE-RTR-01"})]},
                                   answer("not json")])
    run = agent.run("WAN-FAILURE", SINGAPORE)
    assert run.budget.peak_concurrency == 1 and [r.call_id for r in run.records][:2] == ["C1", "C2"]


def test_knowledge_is_retrieved_as_unverified_guidance() -> None:
    agent, model = scripted_agent([call("search_knowledge", query="wan circuit down"),
                                   call("check_network_reachability", source="SIN-SW-01", destination="DC1-SRV-APP-01"),
                                   answer(cite("LINK_DOWN_AT_FAILURE_POINT", "NO_ROUTE_TO_DESTINATION"))])
    run = agent.run("WAN-FAILURE", SINGAPORE)
    guidance = json.loads(model.tool_messages()[0])
    assert guidance["status"] == "guidance_only" and "not diagnostic evidence" in guidance["notice"]
    assert "PB-WAN-FAILURE" in {d["reference_id"] for d in guidance["untrusted_reference_documents"]}
    assert "PB-WAN-FAILURE" in run.diagnosis.retrieved_document_ids
    assert all(not e.evidence_id.startswith("PB-") for e in run.diagnosis.evidence)
    assert not any(r.tool == "search_knowledge" for r in run.records)


def test_knowledge_cannot_be_cited_as_evidence() -> None:
    agent, _ = scripted_agent([call("search_knowledge", query="wan circuit down"),
                               answer(draft(supporting_evidence_ids=["PB-WAN-FAILURE"]))])
    run = agent.run("WAN-FAILURE", SINGAPORE)
    assert run.diagnosis.method.value == "rule_based_fallback" and not run.agent_completed
    assert any("PB-WAN-FAILURE" in issue for issue in run.diagnosis.validation_issues)


def test_knowledge_search_limits() -> None:
    queries = ["wan circuit down", "ospf adjacency down", "dns resolution failure"]
    agent, model = scripted_agent([call("search_knowledge", query=q) for q in queries] + [call("search_knowledge", query="x"),
                                                                                           answer("not json")])
    agent.run("WAN-FAILURE", SINGAPORE)
    replies = [json.loads(m) for m in model.tool_messages()]
    assert [r.get("status") for r in replies[:MAX_KNOWLEDGE_CALLS]] == ["guidance_only"] * MAX_KNOWLEDGE_CALLS
    assert replies[2]["error"]["code"] == "KNOWLEDGE_LIMIT" and replies[3]["error"]["code"] == "INVALID_ARGUMENTS"


def test_budget_gate_refuses_calls_beyond_the_limit_on_its_own() -> None:
    budget = ToolBudget(ToolExecutor("WAN-FAILURE"), KnowledgeService().diagnosis_retriever())
    devices = ["SIN-RTR-01", "SIN-SW-01", "CORE-RTR-01", "CORE-RTR-02", "BLR-RTR-01", "BLR-SW-01", "NYC-RTR-01", "NYC-SW-01", "DC1-FW-01"]
    replies = [budget.diagnostic("check_device_availability", {"device_id": d}) for d in devices]
    replies.append(budget.knowledge("wan circuit down"))
    replies += [budget.diagnostic("get_device_logs", {"device_id": "SIN-RTR-01"}), budget.knowledge("dns failure")]
    assert budget.attempts == 10 and [json.loads(r).get("error", {}).get("code") for r in replies[-2:]] == ["BUDGET_EXHAUSTED"] * 2
    assert len(budget.executor.executed) == 9 and len(budget.knowledge_queries) == 1
