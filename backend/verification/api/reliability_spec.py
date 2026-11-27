"""Model-backed endpoints share a concurrency limit, failures recover, and duplicate runs are refused. No network is used:
the provider is a local fake that blocks or fails on demand."""
import threading
from concurrent.futures import ThreadPoolExecutor

from app.engine import DiagnosisEngine
from app.engine.providers import ProviderError, ProviderErrorKind
from verification.api.helpers import ApiHarness

DIAGNOSIS = {"scenario_id": "WAN-FAILURE", "description": "Singapore users cannot reach internal applications.", "site_ids": ["SIN"]}
MODEL = {"ai_provider": "openai", "ai_model": "scripted-model", "openai_api_key": "sk-test-not-a-real-key-000000"}


class BlockingProvider:
    name, model = "scripted", "scripted-model"

    def __init__(self) -> None:
        self.entered, self.release = threading.Event(), threading.Event()

    def complete(self, messages, tools):
        self.entered.set()
        self.release.wait(10)
        raise ProviderError(ProviderErrorKind.TIMEOUT, "Provider did not respond in time")


class FailingProvider:
    name, model = "scripted", "scripted-model"

    def complete(self, messages, tools):
        raise ProviderError(ProviderErrorKind.HTTP, "Provider returned HTTP 503: busy")


def services(api: ApiHarness):
    return api.client.app.state.services


def test_model_backed_endpoints_share_the_run_limit(tmp_path) -> None:
    api = ApiHarness(tmp_path, max_concurrent_agent_runs=1, **MODEL)
    provider = BlockingProvider()
    services(api).provider = lambda: provider
    with ThreadPoolExecutor(1) as pool:
        first = pool.submit(api.post, "/diagnosis", DIAGNOSIS, "operator")
        assert provider.entered.wait(10)
        busy = api.post("/diagnosis", DIAGNOSIS, as_="operator")
        assert busy.status_code == 503 and busy.json()["error"]["code"] == "AGENT_BUSY" and busy.headers["retry-after"]
        advanced = api.post("/diagnosis/advanced", {"diagnosis": DIAGNOSIS}, as_="operator")
        assert advanced.status_code == 503
        provider.release.set()
        finished = first.result(30)
    assert finished.status_code == 200 and finished.json()["method"] == "rule_based_fallback"
    assert any("timeout" in item for item in finished.json()["limitations"])
    assert services(api).agent_runs.active == 0


def test_failed_model_runs_release_their_slot_and_still_answer(tmp_path) -> None:
    api = ApiHarness(tmp_path, max_concurrent_agent_runs=1, **MODEL)
    services(api).provider = lambda: FailingProvider()
    for _ in range(3):
        response = api.post("/diagnosis", DIAGNOSIS, as_="operator")
        assert response.status_code == 200
        body = response.json()
        assert body["method"] == "rule_based_fallback" and body["fault"]["fault_domain"] == "wan_isp"
        assert any("HTTP 503" in item for item in body["limitations"])
    assert services(api).agent_runs.active == 0


def test_rule_based_runs_need_no_model_slot(tmp_path) -> None:
    api = ApiHarness(tmp_path, max_concurrent_agent_runs=1)
    services(api).agent_runs.acquire()
    assert api.post("/diagnosis", DIAGNOSIS, as_="operator").status_code == 200


def test_a_second_concurrent_diagnosis_of_one_incident_is_refused(tmp_path) -> None:
    api = ApiHarness(tmp_path)
    incident = api.acknowledge(api.create_incident())
    entered, release = threading.Event(), threading.Event()

    class SlowEngine:
        def diagnose(self, request):
            entered.set()
            release.wait(10)
            return DiagnosisEngine().diagnose(request)

    services(api).diagnosis_engine = lambda: SlowEngine()
    path = f"/incidents/{incident['incident_id']}/diagnosis"
    with ThreadPoolExecutor(1) as pool:
        first = pool.submit(api.post, path, {"expected_version": incident["version"]}, "operator")
        assert entered.wait(10)
        duplicate = api.post(path, {"expected_version": incident["version"]}, as_="operator")
        assert duplicate.status_code == 409 and duplicate.json()["error"]["code"] == "ALREADY_RUNNING"
        release.set()
        assert first.result(30).status_code == 200
    assert len(api.incident(incident["incident_id"])["diagnoses"]) == 1


def test_the_duplicate_guard_is_released_after_an_unexpected_error(tmp_path) -> None:
    api = ApiHarness(tmp_path)
    incident = api.acknowledge(api.create_incident())

    class BrokenEngine:
        def diagnose(self, request):
            raise RuntimeError("engine crashed")

    services(api).diagnosis_engine = lambda: BrokenEngine()
    path = f"/incidents/{incident['incident_id']}/diagnosis"
    crashed = api.post(path, {"expected_version": incident["version"]}, as_="operator")
    assert crashed.status_code == 500 and "engine crashed" not in crashed.text
    del services(api).diagnosis_engine
    retried = api.post(path, {"expected_version": incident["version"]}, as_="operator")
    assert retried.status_code == 200, retried.text
    assert services(api).in_flight.keys == set()
