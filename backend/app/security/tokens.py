import argparse
import fcntl
import json
import os
import secrets
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from app.core.config import get_settings
from app.security.permissions import Principal, TokenRecord, hash_token

MAX_TOKEN_FILE_BYTES = 1_000_000
MAX_EXPIRY_HOURS = 2160
TOKEN_BYTES = 32
RECORDS = TypeAdapter(list[TokenRecord])
_PROCESS_LOCKS: dict[str, threading.Lock] = {}
_PROCESS_LOCKS_GUARD = threading.Lock()


class TokenStoreError(ValueError):
    pass


@contextmanager
def store_lock(path: Path) -> Iterator[None]:
    """Serialises every read-modify-write of a JSON store, across threads and across processes.

    Threads in this process share one lock per file; other processes (the token and user CLIs, a second server) are
    excluded with an advisory lock on the store's directory, so no lock file is left behind. Without it, concurrent
    writers each append to the same snapshot and the last rename silently drops the others' records.
    """
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = str(path.resolve())
    with _PROCESS_LOCKS_GUARD:
        lock = _PROCESS_LOCKS.setdefault(key, threading.Lock())
    with lock:
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def load_token_records(path: Path) -> list[TokenRecord]:
    path = Path(path)
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_TOKEN_FILE_BYTES:
        raise TokenStoreError("Token store is not a regular file within the size limit")
    try:
        return RECORDS.validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, ValidationError):
        raise TokenStoreError("Token store failed validation") from None


def write_json_atomically(path: Path, payload: str) -> None:
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.stem}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def write_token_records(path: Path, records: list[TokenRecord]) -> None:
    write_json_atomically(path, json.dumps([record.model_dump(mode="json") for record in records], indent=2) + "\n")


def update_token_records(path: Path, change: Callable[[list[TokenRecord]], list[TokenRecord]],
                         now: datetime | None = None) -> None:
    """Applies `change` to the live records under the store lock; expired records are pruned on every write."""
    moment = now or datetime.now(timezone.utc)
    with store_lock(path):
        records = [record for record in load_token_records(path) if record.expires_at is None or record.expires_at > moment]
        write_token_records(path, change(records))


def issue_token(path: Path, principal: Principal, expires_in_hours: int, now: datetime | None = None) -> str:
    if not 1 <= expires_in_hours <= MAX_EXPIRY_HOURS:
        raise TokenStoreError(f"Token expiry must be between 1 and {MAX_EXPIRY_HOURS} hours")
    moment = now or datetime.now(timezone.utc)
    token = secrets.token_urlsafe(TOKEN_BYTES)
    record = TokenRecord(token_hash=hash_token(token), principal=principal,
                         expires_at=moment.replace(microsecond=0) + timedelta(hours=expires_in_hours))
    update_token_records(path, lambda records: records + [record], now=moment)
    return token


def revoke_token(path: Path, token: str) -> bool:
    digest = hash_token(token)
    removed = False

    def drop(records: list[TokenRecord]) -> list[TokenRecord]:
        nonlocal removed
        kept = [record for record in records if record.token_hash != digest]
        removed = len(kept) != len(records)
        return kept

    update_token_records(path, drop)
    return removed


def revoke_subject(path: Path, subject: str) -> int:
    count = 0

    def drop(records: list[TokenRecord]) -> list[TokenRecord]:
        nonlocal count
        kept = [record for record in records if record.principal.subject != subject]
        count = len(records) - len(kept)
        return kept

    update_token_records(path, drop)
    return count


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.security.tokens")
    commands = parser.add_subparsers(dest="command", required=True)
    issue = commands.add_parser("issue", help="issue a bearer token for a service or test principal")
    issue.add_argument("--subject", required=True)
    issue.add_argument("--kind", required=True, choices=["human", "system", "ai"])
    issue.add_argument("--role", required=True, action="append")
    issue.add_argument("--expires-hours", type=int, default=24)
    issue.add_argument("--file")
    revoke = commands.add_parser("revoke", help="revoke every token held by a subject")
    revoke.add_argument("--subject", required=True)
    revoke.add_argument("--file")
    listing = commands.add_parser("list", help="list live tokens by subject and expiry (never the tokens themselves)")
    listing.add_argument("--file")
    options = parser.parse_args(arguments)
    target = options.file or get_settings().auth_tokens_file
    if not target:
        parser.error("set AUTH_TOKENS_FILE or pass --file")
    try:
        if options.command == "issue":
            principal = Principal(subject=options.subject, kind=options.kind, roles=options.role)
            token = issue_token(Path(target), principal, options.expires_hours)
            sys.stdout.write(f"{token}\nThis token is shown once and is not stored; only its hash was saved.\n")
        elif options.command == "revoke":
            sys.stdout.write(f"Revoked {revoke_subject(Path(target), options.subject)} token(s) for {options.subject}\n")
        else:
            moment = datetime.now(timezone.utc)
            for record in load_token_records(Path(target)):
                if record.expires_at is None or record.expires_at > moment:
                    roles = ",".join(role.value for role in record.principal.roles)
                    sys.stdout.write(f"{record.principal.subject}\t{roles}\texpires {record.expires_at}\n")
    except (ValidationError, TokenStoreError) as exc:
        parser.error(str(exc).splitlines()[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
