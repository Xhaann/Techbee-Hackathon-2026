import io
import json
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.security.users import UserStoreError, add_user, load_users, main as users_cli, update_user

API = "/api/v1"
ALICE = ("alice", "alice-password-1")
BOB = ("bob", "bob-password-22")


def client(tmp_path: Path, accounts: bool = True, **overrides) -> TestClient:
    auth = tmp_path / "auth"
    if accounts:
        add_user(auth / "users.json", ALICE[0], ALICE[1], ["incident_manager", "knowledge_manager"])
        add_user(auth / "users.json", BOB[0], BOB[1], ["operator"])
    values = {"auth_tokens_file": str(auth / "tokens.json"), "incident_store_dir": str(tmp_path / "incidents")}
    return TestClient(create_app(Settings(_env_file=None, **(values | overrides))))


def login(api: TestClient, username: str, password: str):
    return api.post(f"{API}/auth/login", json={"username": username, "password": password})


def test_each_account_signs_in_as_itself(tmp_path) -> None:
    api = client(tmp_path)
    alice, bob = login(api, *ALICE), login(api, *BOB)
    assert alice.status_code == bob.status_code == 200
    assert alice.json()["principal"]["subject"] == "alice" and bob.json()["principal"]["subject"] == "bob"
    assert "close_reopen_incidents" in alice.json()["principal"]["permissions"]
    assert "close_reopen_incidents" not in bob.json()["principal"]["permissions"]
    verified = api.post(f"{API}/auth/verify", headers={"Authorization": f"Bearer {bob.json()['token']}"})
    assert verified.status_code == 200 and verified.json()["subject"] == "bob" and verified.json()["roles"] == ["operator"]


def test_usernames_are_case_insensitive(tmp_path) -> None:
    api = client(tmp_path)
    assert login(api, "ALICE", ALICE[1]).json()["principal"]["subject"] == "alice"


def test_passwords_are_stored_only_as_scrypt_hashes(tmp_path) -> None:
    client(tmp_path)
    store = tmp_path / "auth" / "users.json"
    text = store.read_text(encoding="utf-8")
    assert ALICE[1] not in text and BOB[1] not in text
    assert all(record["password_hash"].startswith("scrypt$") for record in json.loads(text))
    assert stat.S_IMODE(store.stat().st_mode) == 0o600


def test_login_rejects_wrong_credentials(tmp_path) -> None:
    api = client(tmp_path)
    for username, password in (("alice", "wrong-password"), ("alice", BOB[1]), ("someone", ALICE[1])):
        response = login(api, username, password)
        assert response.status_code == 401
        assert response.json()["error"]["message"] == "Invalid username or password"
        assert password not in response.text
    assert not (tmp_path / "auth" / "tokens.json").exists()


def test_login_unconfigured_returns_503(tmp_path) -> None:
    assert login(client(tmp_path, accounts=False), *ALICE).status_code == 503
    no_tokens = TestClient(create_app(Settings(_env_file=None)))
    assert login(no_tokens, *ALICE).status_code == 503


def test_login_rejects_unknown_fields(tmp_path) -> None:
    api = client(tmp_path)
    assert api.post(f"{API}/auth/login", json={"username": "alice", "password": ALICE[1], "role": "x"}).status_code == 422


def test_disabled_accounts_cannot_sign_in(tmp_path) -> None:
    api = client(tmp_path)
    update_user(tmp_path / "auth" / "users.json", "bob", disabled=True)
    assert login(api, *BOB).status_code == 401


def test_repeated_failures_throttle_the_account(tmp_path) -> None:
    api = client(tmp_path, login_max_failures=3, login_lockout_seconds=60)
    for _ in range(3):
        assert login(api, "bob", "wrong-password").status_code == 401
    throttled = login(api, *BOB)
    assert throttled.status_code == 429 and throttled.json()["error"]["code"] == "LOGIN_THROTTLED"
    assert int(throttled.headers["retry-after"]) >= 1
    assert login(api, *ALICE).status_code == 200


def test_success_clears_earlier_failures(tmp_path) -> None:
    api = client(tmp_path, login_max_failures=3)
    for _ in range(2):
        login(api, "bob", "wrong-password")
    assert login(api, *BOB).status_code == 200
    for _ in range(2):
        login(api, "bob", "wrong-password")
    assert login(api, *BOB).status_code == 200


def test_logout_revokes_only_the_presented_token(tmp_path) -> None:
    api = client(tmp_path)
    first, second = login(api, *BOB).json()["token"], login(api, *BOB).json()["token"]
    assert api.post(f"{API}/auth/logout", headers={"Authorization": f"Bearer {first}"}).status_code == 204
    assert api.post(f"{API}/auth/verify", headers={"Authorization": f"Bearer {first}"}).status_code == 401
    assert api.post(f"{API}/auth/verify", headers={"Authorization": f"Bearer {second}"}).status_code == 200
    assert api.post(f"{API}/auth/logout").status_code == 401


def test_password_policy_and_human_roles_are_enforced(tmp_path) -> None:
    store = tmp_path / "users.json"
    for password in ("short", " padded-password ", "aaaaaaaaaaaa"):
        with pytest.raises(UserStoreError):
            add_user(store, "carol", password, ["viewer"])
    with pytest.raises(UserStoreError):
        add_user(store, "robot", "robot-password-1", ["system_service"])
    with pytest.raises(UserStoreError):
        add_user(store, "Not Valid!", "carol-password-1", ["viewer"])
    add_user(store, "carol", "carol-password-1", ["viewer"])
    with pytest.raises(UserStoreError):
        add_user(store, "CAROL", "carol-password-2", ["viewer"])
    assert [user.username for user in load_users(store)] == ["carol"]


def test_cli_never_prints_passwords_and_revokes_sessions_on_change(tmp_path, monkeypatch, capsys) -> None:
    api = client(tmp_path)
    token = login(api, *BOB).json()["token"]
    monkeypatch.setattr("app.security.users.get_settings",
                        lambda: Settings(_env_file=None, auth_tokens_file=str(tmp_path / "auth" / "tokens.json")))
    monkeypatch.setattr("sys.stdin", io.StringIO("bob-new-password-3\n"))
    assert users_cli(["passwd", "--username", "bob", "--password-stdin"]) == 0
    users_cli(["list"])
    output = capsys.readouterr().out
    assert "bob-new-password-3" not in output and "scrypt$" not in output and "1 session(s) revoked" in output
    assert api.post(f"{API}/auth/verify", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert login(api, "bob", "bob-new-password-3").status_code == 200
