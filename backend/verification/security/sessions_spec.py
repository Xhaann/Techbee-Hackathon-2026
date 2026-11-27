import threading
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from multiprocessing import get_context
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.security.permissions import Principal, hash_token
from app.security.tokens import issue_token, load_token_records, revoke_token
from app.security.users import add_user

API = "/api/v1"
SIMULTANEOUS = 50


def issue_many(store: str, prefix: str, count: int) -> list[str]:
    return [issue_token(Path(store), Principal(subject=f"{prefix}.{index}", kind="human", roles=["viewer"]), 1)
            for index in range(count)]


def test_concurrent_issuance_in_one_process_loses_no_token(tmp_path: Path) -> None:
    store = tmp_path / "tokens.json"
    barrier = threading.Barrier(SIMULTANEOUS)

    def one(index: int) -> str:
        barrier.wait()
        return issue_token(store, Principal(subject=f"user.{index}", kind="human", roles=["viewer"]), 1)

    with ThreadPoolExecutor(SIMULTANEOUS) as pool:
        tokens = list(pool.map(one, range(SIMULTANEOUS)))
    stored = {record.token_hash for record in load_token_records(store)}
    assert len(set(tokens)) == SIMULTANEOUS and {hash_token(token) for token in tokens} == stored
    assert sorted(p.name for p in tmp_path.iterdir()) == ["tokens.json"]


def test_concurrent_issuance_across_processes_loses_no_token(tmp_path: Path) -> None:
    store = str(tmp_path / "tokens.json")
    with ProcessPoolExecutor(4, mp_context=get_context("spawn")) as pool:
        batches = list(pool.map(issue_many, [store] * 4, [f"p{i}" for i in range(4)], [10] * 4))
    tokens = [token for batch in batches for token in batch]
    assert {hash_token(token) for token in tokens} == {record.token_hash for record in load_token_records(Path(store))}
    assert len(tokens) == 40


def test_revocation_during_issuance_keeps_every_other_token(tmp_path: Path) -> None:
    store = tmp_path / "tokens.json"
    doomed = issue_many(str(store), "doomed", 10)
    with ThreadPoolExecutor(20) as pool:
        kept = pool.submit(issue_many, str(store), "kept", 20)
        list(pool.map(lambda token: revoke_token(store, token), doomed))
        survivors = kept.result()
    assert {record.token_hash for record in load_token_records(store)} == {hash_token(token) for token in survivors}


def simultaneous_logins(tmp_path: Path, **settings) -> tuple[TestClient, list]:
    auth = tmp_path / "auth"
    add_user(auth / "users.json", "shared.load", "load-test-password-1", ["operator"])
    app = create_app(Settings(_env_file=None, auth_tokens_file=str(auth / "tokens.json"), rate_limit_requests=10_000,
                              incident_store_dir=str(tmp_path / "incidents"), **settings))
    api = TestClient(app)
    barrier = threading.Barrier(SIMULTANEOUS)

    def attempt(_: int):
        barrier.wait()
        return api.post(f"{API}/auth/login", json={"username": "shared.load", "password": "load-test-password-1"})

    with api, ThreadPoolExecutor(SIMULTANEOUS) as pool:
        responses = list(pool.map(attempt, range(SIMULTANEOUS)))
    return api, responses


def test_fifty_simultaneous_logins_all_produce_working_sessions(tmp_path: Path) -> None:
    api, responses = simultaneous_logins(tmp_path, max_concurrent_requests=64)
    assert [response.status_code for response in responses] == [200] * SIMULTANEOUS
    tokens = [response.json()["token"] for response in responses]
    assert len(set(tokens)) == SIMULTANEOUS
    for token in tokens:
        verified = api.post(f"{API}/auth/verify", headers={"Authorization": f"Bearer {token}"})
        assert verified.status_code == 200 and verified.json()["subject"] == "shared.load"
    assert len(load_token_records(tmp_path / "auth" / "tokens.json")) == SIMULTANEOUS


def test_logins_over_the_concurrency_limit_are_refused_never_lost(tmp_path: Path) -> None:
    api, responses = simultaneous_logins(tmp_path, max_concurrent_requests=8)
    granted = [response.json()["token"] for response in responses if response.status_code == 200]
    refused = [response for response in responses if response.status_code != 200]
    assert granted and all(response.status_code == 503 and response.json()["error"]["code"] == "SERVER_BUSY" for response in refused)
    for token in granted:
        assert api.post(f"{API}/auth/verify", headers={"Authorization": f"Bearer {token}"}).status_code == 200
