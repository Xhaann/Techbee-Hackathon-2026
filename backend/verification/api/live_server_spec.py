"""End-to-end over real HTTP against a Uvicorn process, not the in-process test client.

The server runs from a temporary working directory (so no .env is read), with the AI provider disabled and temporary
token, user and incident stores. Nothing leaves the machine.
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from app.security.tokens import load_token_records
from app.security.users import add_user

BACKEND = Path(__file__).resolve().parents[2]
USERS = {"alice": ("alice-password-1", ["operator"]), "bob": ("bob-password-22", ["operator"]),
         "carol": ("carol-password-3", ["incident_manager"])}
SIMULTANEOUS = 50


class Server:
    def __init__(self, root: Path) -> None:
        auth = root / "auth"
        for username, (password, roles) in USERS.items():
            add_user(auth / "users.json", username, password, roles)
        add_user(auth / "users.json", "load.user", "load-test-password-1", ["viewer"])
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.tokens_file = auth / "tokens.json"
        env = {key: value for key, value in os.environ.items() if not key.startswith(("AI_", "OPENAI_", "FOUNDRY_"))}
        env |= {"PYTHONPATH": str(BACKEND), "AI_PROVIDER": "disabled", "AUTH_TOKENS_FILE": str(self.tokens_file),
                "AUTH_USERS_FILE": str(auth / "users.json"), "INCIDENT_STORE_DIR": str(root / "incidents"),
                "MAX_CONCURRENT_REQUESTS": "64", "RATE_LIMIT_REQUESTS": "10000"}
        work = root / "cwd"
        work.mkdir()
        self.process = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(self.port),
                                         "--log-level", "warning"], cwd=work, env=env, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.PIPE)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if self.call("GET", "/health", raw=True)[0] == 200:
                    return
            except OSError:
                time.sleep(0.2)
        self.stop()
        raise RuntimeError("the server did not start")

    def call(self, method: str, path: str, body: dict | None = None, token: str | None = None, raw: bool = False):
        url = self.base + (path if raw else f"/api/v1{path}")
        request = urllib.request.Request(url, method=method, data=None if body is None else json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json",
                                                  **({"Authorization": f"Bearer {token}"} if token else {})})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                text = response.read().decode()
                return response.status, json.loads(text) if text else None
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode() or "{}")

    def login(self, username: str) -> str:
        status, body = self.call("POST", "/auth/login", {"username": username, "password": USERS[username][0]})
        assert status == 200, body
        return body["token"]

    def stop(self) -> None:
        self.process.terminate()
        self.process.wait(timeout=10)


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    running = Server(tmp_path_factory.mktemp("live"))
    yield running
    running.stop()


def test_fifty_simultaneous_logins_over_http_lose_no_session(server: Server) -> None:
    barrier = threading.Barrier(SIMULTANEOUS)

    def attempt(_):
        barrier.wait()
        return server.call("POST", "/auth/login", {"username": "load.user", "password": "load-test-password-1"})

    with ThreadPoolExecutor(SIMULTANEOUS) as pool:
        results = list(pool.map(attempt, range(SIMULTANEOUS)))
    assert [status for status, _ in results] == [200] * SIMULTANEOUS
    tokens = [body["token"] for _, body in results]
    assert len(set(tokens)) == SIMULTANEOUS
    with ThreadPoolExecutor(10) as pool:
        verified = list(pool.map(lambda token: server.call("POST", "/auth/verify", token=token), tokens))
    assert all(status == 200 and body["subject"] == "load.user" for status, body in verified)
    assert sum(record.principal.subject == "load.user" for record in load_token_records(server.tokens_file)) == SIMULTANEOUS


def test_users_cannot_reach_each_others_incidents_or_conversations(server: Server) -> None:
    alice, bob, carol = server.login("alice"), server.login("bob"), server.login("carol")
    status, created = server.call("POST", "/incidents", {"title": "Singapore cannot reach ERP", "description": "All users affected.",
                                                         "site_ids": ["SIN"], "dataset_scenario_id": "WAN-FAILURE"}, alice)
    assert status == 201
    incident_id = created["incident"]["incident_id"]
    assert server.call("GET", f"/incidents/{incident_id}", token=bob)[0] == 404
    assert server.call("GET", f"/incidents/{incident_id}", token=carol)[0] == 200
    assert incident_id not in {i["incident_id"] for i in server.call("GET", "/incidents", token=bob)[1]["items"]}
    status, conversation = server.call("POST", "/conversations", {"scenario_id": "WAN-FAILURE", "mode": "rule_based"}, alice)
    assert status == 201
    assert server.call("GET", f"/conversations/{conversation['conversation_id']}", token=bob)[0] == 404
    assert server.call("GET", f"/conversations/{conversation['conversation_id']}", token=carol)[0] == 404


def test_streamed_diagnosis_completes_over_sse(server: Server) -> None:
    token = server.login("alice")
    _, conversation = server.call("POST", "/conversations", {"scenario_id": "ADV-NYC-WAN-FLAP", "mode": "rule_based"}, token)
    request = urllib.request.Request(
        f"{server.base}/api/v1/conversations/{conversation['conversation_id']}/messages", method="POST",
        data=json.dumps({"content": "Diagnose the New York outage", "stream": True}).encode(),
        headers={"Content-Type": "application/json", "Accept": "text/event-stream", "Authorization": f"Bearer {token}"})
    events, result = [], None
    with urllib.request.urlopen(request, timeout=60) as response:
        assert response.headers["content-type"].startswith("text/event-stream")
        for line in response:
            text = line.decode().strip()
            if text.startswith("event: "):
                events.append(text[7:])
            if text.startswith("data: ") and events and events[-1] == "turn.completed":
                result = json.loads(text[6:])["data"]["result"]
                break
    assert "investigation.started" in events and "tool.completed" in events and events[-1] == "turn.completed"
    assert result["intent"]["name"] == "full_diagnosis" and "New York WAN link" in result["response"]
    assert "LNK-WAN-NYC" in result["details"]
    assert "recovered" in result["response"]


def test_logout_revokes_the_session_over_http(server: Server) -> None:
    token = server.login("bob")
    assert server.call("POST", "/auth/logout", token=token)[0] == 204
    assert server.call("POST", "/auth/verify", token=token)[0] == 401
