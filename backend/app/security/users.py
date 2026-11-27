"""Individual user accounts: one record per person, scrypt-hashed passwords, roles per account.

Accounts live in a JSON file next to the token store (AUTH_USERS_FILE, default `<tokens dir>/users.json`). Passwords are
never stored or printed; the CLI reads them with getpass or from standard input.
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import secrets
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, field_validator

from app.core.config import Settings, get_settings
from app.incidents.models import ActorKind
from app.network.models import UtcDatetime
from app.security.permissions import ROLE_KINDS, Principal, Role
from app.security.tokens import revoke_subject, store_lock, write_json_atomically

MAX_USERS_FILE_BYTES = 1_000_000
MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 256
SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_LENGTH, SALT_BYTES = 2 ** 14, 8, 1, 32, 16
Username = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._@-]{0,63}$")]
HUMAN_ROLES = [role for role, kind in ROLE_KINDS.items() if kind == ActorKind.HUMAN]


class UserStoreError(ValueError):
    pass


class UserRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    username: Username
    password_hash: Annotated[str, Field(pattern=r"^scrypt\$\d+\$\d+\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$")]
    roles: list[Role] = Field(min_length=1, max_length=6)
    disabled: bool = False
    created_at: UtcDatetime

    @field_validator("roles")
    @classmethod
    def human_roles_only(cls, roles: list[Role]) -> list[Role]:
        if any(ROLE_KINDS[role] != ActorKind.HUMAN for role in roles):
            raise ValueError("user accounts can hold only human roles")
        return list(dict.fromkeys(roles))

    def principal(self) -> Principal:
        return Principal(subject=self.username, kind=ActorKind.HUMAN, roles=self.roles)


USERS = TypeAdapter(list[UserRecord])


def normalise(username: str) -> str:
    return username.strip().lower()


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(SALT_BYTES)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_LENGTH)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64(salt)}${b64(digest)}"


def password_matches(password: str, encoded: str) -> bool:
    try:
        _, n, r, p, salt, expected = encoded.split("$")
        digest = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                                dklen=len(base64.b64decode(expected)))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, base64.b64decode(expected))


# Verified when the username is unknown, so a miss costs the same time as a wrong password.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
# Each scrypt verification holds 16 MiB; bounding concurrent verifications bounds memory under a burst of sign-ins.
_VERIFICATIONS = threading.BoundedSemaphore(8)


def check_password_policy(password: str) -> None:
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise UserStoreError(f"Passwords must be {MIN_PASSWORD_LENGTH} to {MAX_PASSWORD_LENGTH} characters")
    if password.strip() != password or len(set(password)) < 4:
        raise UserStoreError("Passwords must not start or end with spaces and need at least 4 distinct characters")


def users_file(settings: Settings) -> Path | None:
    if settings.auth_users_file:
        return Path(settings.auth_users_file)
    if settings.auth_tokens_file:
        return Path(settings.auth_tokens_file).with_name("users.json")
    return None


def load_users(path: Path) -> list[UserRecord]:
    path = Path(path)
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_USERS_FILE_BYTES:
        raise UserStoreError("User store is not a regular file within the size limit")
    try:
        records = USERS.validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, ValidationError):
        raise UserStoreError("User store failed validation") from None
    names = [record.username for record in records]
    if len(set(names)) != len(names):
        raise UserStoreError("User store holds duplicate usernames")
    return records


def write_users(path: Path, records: list[UserRecord]) -> None:
    write_json_atomically(path, json.dumps([record.model_dump(mode="json") for record in records], indent=2) + "\n")


def add_user(path: Path, username: str, password: str, roles: list[Role | str], now: datetime | None = None) -> UserRecord:
    check_password_policy(password)
    try:
        record = UserRecord(username=normalise(username), password_hash=hash_password(password), roles=[Role(r) for r in roles],
                            created_at=(now or datetime.now(timezone.utc)).replace(microsecond=0))
    except (ValidationError, ValueError) as exc:
        raise UserStoreError(str(exc).splitlines()[0]) from None
    with store_lock(path):
        records = load_users(path)
        if any(existing.username == record.username for existing in records):
            raise UserStoreError(f"User '{record.username}' already exists")
        write_users(path, records + [record])
    return record


def update_user(path: Path, username: str, *, password: str | None = None, roles: list[Role | str] | None = None,
                disabled: bool | None = None) -> UserRecord:
    name = normalise(username)
    if password is not None:
        check_password_policy(password)
    with store_lock(path):
        records = load_users(path)
        current = next((record for record in records if record.username == name), None)
        if current is None:
            raise UserStoreError(f"No user '{name}'")
        changes: dict = {}
        if password is not None:
            changes["password_hash"] = hash_password(password)
        if roles is not None:
            changes["roles"] = [Role(role) for role in roles]
        if disabled is not None:
            changes["disabled"] = disabled
        try:
            updated = UserRecord.model_validate(current.model_dump() | changes)
        except ValidationError as exc:
            raise UserStoreError(str(exc).splitlines()[0]) from None
        write_users(path, [updated if record.username == name else record for record in records])
    return updated


def remove_user(path: Path, username: str) -> None:
    name = normalise(username)
    with store_lock(path):
        records = load_users(path)
        if all(record.username != name for record in records):
            raise UserStoreError(f"No user '{name}'")
        write_users(path, [record for record in records if record.username != name])


def authenticate_user(path: Path, username: str, password: str) -> Principal | None:
    """Returns the account's principal when the password matches an enabled account; otherwise None, in constant work."""
    name = normalise(username)
    record = next((item for item in load_users(path) if item.username == name), None)
    with _VERIFICATIONS:
        matched = password_matches(password, record.password_hash if record else _DUMMY_HASH)
    if record is None or record.disabled or not matched:
        return None
    return record.principal()


def read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass("Password: ")
    if getpass.getpass("Repeat password: ") != first:
        raise UserStoreError("Passwords do not match")
    return first


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.security.users", description="Manage individual user accounts")
    parser.add_argument("--file", help="user store (default: AUTH_USERS_FILE, or users.json beside AUTH_TOKENS_FILE)")
    commands = parser.add_subparsers(dest="command", required=True)
    add = commands.add_parser("add", help="create an account; the password is prompted for, never passed as an argument")
    add.add_argument("--username", required=True)
    add.add_argument("--role", required=True, action="append", choices=[role.value for role in HUMAN_ROLES])
    add.add_argument("--password-stdin", action="store_true", help="read the password from the first line of stdin")
    password = commands.add_parser("passwd", help="set a new password and sign the account out everywhere")
    password.add_argument("--username", required=True)
    password.add_argument("--password-stdin", action="store_true")
    roles = commands.add_parser("roles", help="replace an account's roles and sign it out everywhere")
    roles.add_argument("--username", required=True)
    roles.add_argument("--role", required=True, action="append", choices=[role.value for role in HUMAN_ROLES])
    for name, text in (("disable", "block sign-in and revoke sessions"), ("enable", "allow sign-in again"),
                       ("remove", "delete the account and revoke its sessions")):
        command = commands.add_parser(name, help=text)
        command.add_argument("--username", required=True)
    commands.add_parser("list", help="list accounts and roles (never password hashes)")
    options = parser.parse_args(arguments)
    settings = get_settings()
    target = Path(options.file) if options.file else users_file(settings)
    if target is None:
        parser.error("set AUTH_USERS_FILE or AUTH_TOKENS_FILE, or pass --file")
    tokens = Path(settings.auth_tokens_file) if settings.auth_tokens_file else None

    def sign_out(username: str) -> str:
        return f"; {revoke_subject(tokens, normalise(username))} session(s) revoked" if tokens else ""

    try:
        if options.command == "add":
            record = add_user(target, options.username, read_password(options.password_stdin), options.role)
            sys.stdout.write(f"Created {record.username} with roles {', '.join(r.value for r in record.roles)}\n")
        elif options.command == "passwd":
            update_user(target, options.username, password=read_password(options.password_stdin))
            sys.stdout.write(f"Password changed{sign_out(options.username)}\n")
        elif options.command == "roles":
            record = update_user(target, options.username, roles=options.role)
            sys.stdout.write(f"Roles set to {', '.join(r.value for r in record.roles)}{sign_out(options.username)}\n")
        elif options.command in ("disable", "enable"):
            update_user(target, options.username, disabled=options.command == "disable")
            suffix = sign_out(options.username) if options.command == "disable" else ""
            sys.stdout.write(f"Account {options.command}d{suffix}\n")
        elif options.command == "remove":
            remove_user(target, options.username)
            sys.stdout.write(f"Removed {normalise(options.username)}{sign_out(options.username)}\n")
        else:
            for record in load_users(target):
                state = "disabled" if record.disabled else "active"
                sys.stdout.write(f"{record.username}\t{','.join(r.value for r in record.roles)}\t{state}\n")
    except UserStoreError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
