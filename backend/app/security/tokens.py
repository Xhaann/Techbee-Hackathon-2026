import argparse
import json
import os
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from app.core.config import get_settings
from app.security.permissions import Principal, TokenRecord, hash_token

MAX_TOKEN_FILE_BYTES = 1_000_000
MAX_EXPIRY_HOURS = 2160
TOKEN_BYTES = 32
RECORDS = TypeAdapter(list[TokenRecord])


class TokenStoreError(ValueError):
    pass


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


def write_token_records(path: Path, records: list[TokenRecord]) -> None:
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps([record.model_dump(mode="json") for record in records], indent=2) + "\n"
    handle, temporary = tempfile.mkstemp(prefix=".tokens.", suffix=".tmp", dir=path.parent)
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


def issue_token(path: Path, principal: Principal, expires_in_hours: int, now: datetime | None = None) -> str:
    if not 1 <= expires_in_hours <= MAX_EXPIRY_HOURS:
        raise TokenStoreError(f"Token expiry must be between 1 and {MAX_EXPIRY_HOURS} hours")
    moment = now or datetime.now(timezone.utc)
    records = [record for record in load_token_records(path) if record.expires_at is None or record.expires_at > moment]
    token = secrets.token_urlsafe(TOKEN_BYTES)
    record = TokenRecord(token_hash=hash_token(token), principal=principal,
                         expires_at=moment.replace(microsecond=0) + timedelta(hours=expires_in_hours))
    write_token_records(path, records + [record])
    return token


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.security.tokens")
    commands = parser.add_subparsers(dest="command", required=True)
    issue = commands.add_parser("issue")
    issue.add_argument("--subject", required=True)
    issue.add_argument("--kind", required=True, choices=["human", "system", "ai"])
    issue.add_argument("--role", required=True, action="append")
    issue.add_argument("--expires-hours", type=int, default=24)
    issue.add_argument("--file")
    options = parser.parse_args(arguments)
    target = options.file or get_settings().auth_tokens_file
    if not target:
        parser.error("set AUTH_TOKENS_FILE or pass --file")
    try:
        principal = Principal(subject=options.subject, kind=options.kind, roles=options.role)
        token = issue_token(Path(target), principal, options.expires_hours)
    except (ValidationError, TokenStoreError) as exc:
        parser.error(str(exc).splitlines()[0])
    sys.stdout.write(f"{token}\nThis token is shown once and is not stored; only its hash was saved.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
