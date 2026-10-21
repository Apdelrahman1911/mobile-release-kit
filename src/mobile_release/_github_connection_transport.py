"""Fixed, bounded GitHub.com GET profile and its inert response/schedule seams.

No socket/http.client/ssl import occurs at module import. Only the private live
factory loads them, from the original private engine entry after channel custody.
The finite readers below are the delegates of that factory's HTTPResponse
subclass, not a general HTTP client, URL dispatcher or alternative TLS stack.
"""
from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Protocol

from ._desktop_github_engine import (MAX_COOLDOWN_SECONDS, READ_SECONDS, ReadRequest,
                                    _JsonError, _JsonLimit, _check_control, _check_values,
                                    _decode_json)

MAX_BODY_BYTES = 256 * 1024
MAX_BODY_TOTAL = 1024 * 1024
MAX_HEADER_BYTES = 32 * 1024
MAX_HEADER_FIELDS = 64
MAX_HEADER_LINE = 8 * 1024
MAX_FRAMING_BYTES = 32 * 1024
MAX_METADATA_TOTAL = 320 * 1024
MAX_CHUNK_LINE = 128
MAX_CHUNKS = 4096  # Includes the terminal zero chunk.
MAX_TRAILER_FIELDS = 16
MAX_TRAILER_BYTES = 8 * 1024
MAX_TRAILER_LINE = 2 * 1024
MAX_CA_BYTES = 512 * 1024
_READ_CHUNK = 4096
_TCHAR = frozenset(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_CONTROL_NAMES = frozenset({"github-authentication-token-expiration", "retry-after",
                            "x-ratelimit-remaining", "x-ratelimit-reset"})
_FORBIDDEN_TRAILERS = _CONTROL_NAMES | frozenset({
    "authorization", "proxy-authorization", "www-authenticate", "proxy-authenticate",
    "authentication-info", "proxy-authentication-info",
    "host", "connection", "upgrade", "content-length", "transfer-encoding", "te",
    "trailer", "content-encoding", "content-type", "cookie", "set-cookie",
})
_LONG = object()
_EPOCH_LIMIT = 2**63 - 1
_FATAL = frozenset({"unauthorized", "target-changed", "response-invalid", "expired"})


class _ExchangeProfile(Enum):
    STANDARD = "standard"
    RELEASE_PREPARE = "release-prepare"
    SETUP = "setup"
    PUBLICATION = "publication"
    HOSTED_VERSION = "hosted-version"
    VERSION_ALLOCATION = "version-allocation"
    VERSION_ENROLLMENT = "version-enrollment"
    REPOSITORY_CREATE = "repository-create"
    ACTIVITY = "activity"
    PULL_REQUEST = "pull-request"
    ACTIONS_RETRY = "actions-retry"
    PLAY_CLEANUP = "play-cleanup"
    GIT_REMOTE = "git-remote"
    GIT_PUSH = "git-push"


class _ResponseRole(Enum):
    HOSTED_VERSION_READ = "hosted-version-read"
    HOSTED_VERSION_HISTORY = "hosted-version-history"
    HOSTED_VERSION_JOURNAL_READ = "hosted-version-journal-read"
    HOSTED_VERSION_JOURNAL_WRITE = "hosted-version-journal-write"
    HOSTED_VERSION_LEDGER_WRITE = "hosted-version-ledger-write"
    GIT_PUSH_ACCOUNT = "git-push-account"
    GIT_PUSH_REPOSITORY = "git-push-repository"
    GIT_PUSH_ADVERTISEMENT = "git-push-advertisement"
    GIT_PUSH_SEND = "git-push-send"
    GIT_REMOTE_ACCOUNT = "git-remote-account"
    GIT_REMOTE_REPOSITORY = "git-remote-repository"
    GIT_REMOTE_ADVERTISEMENT = "git-remote-advertisement"
    GIT_REMOTE_LS_REFS = "git-remote-ls-refs"
    GIT_REMOTE_FETCH = "git-remote-fetch"
    PLAY_CLEANUP_READ = "play-cleanup-read"
    PLAY_CLEANUP_CONFIG = "play-cleanup-config"
    PLAY_CLEANUP_WRITE = "play-cleanup-write"
    ACTIONS_RETRY_READ = "actions-retry-read"
    ACTIONS_RETRY_WRITE = "actions-retry-write"
    PULL_REQUEST_OBJECT = "pull-request-object"
    PULL_REQUEST_LIST = "pull-request-list"
    PULL_REQUEST_WRITE = "pull-request-write"
    ACTIVITY_OBJECT = "activity-object"
    ACTIVITY_LIST = "activity-list"
    REPOSITORY_CREATE_ACCOUNT = "repository-create-account"
    REPOSITORY_CREATE_OWNER = "repository-create-owner"
    REPOSITORY_CREATE_LOOKUP = "repository-create-lookup"
    REPOSITORY_CREATE_WRITE = "repository-create-write"
    VERSION_ENROLLMENT_ACCOUNT = "version-enrollment-account"
    VERSION_ENROLLMENT_REPOSITORY = "version-enrollment-repository"
    VERSION_ENROLLMENT_PROTECTION = "version-enrollment-protection"
    VERSION_ENROLLMENT_REF = "version-enrollment-ref"
    VERSION_ENROLLMENT_LEDGER = "version-enrollment-ledger"
    VERSION_ENROLLMENT_COMPARE = "version-enrollment-compare"
    VERSION_ALLOCATION_REPOSITORY = "version-allocation-repository"
    VERSION_ALLOCATION_REF = "version-allocation-ref"
    VERSION_ALLOCATION_COMPARE = "version-allocation-compare"
    VERSION_ALLOCATION_LEDGER_READ = "version-allocation-ledger-read"
    VERSION_ALLOCATION_LEDGER_WRITE = "version-allocation-ledger-write"
    PUBLICATION_READ = "publication-read"
    PUBLICATION_CREATE = "publication-create"
    PUBLICATION_LIST = "publication-list"
    STANDARD = "standard"
    RELEASE_CONFIG = "release-config"
    RELEASE_VERSION = "release-version"
    SETUP_ACTIONS_WRITE = "setup-actions-write"
    SETUP_WORKFLOW_WRITE = "setup-workflow-write"
    SETUP_ENVIRONMENT_READ = "setup-environment-read"
    SETUP_ENVIRONMENT_LIST = "setup-environment-list"
    SETUP_ENVIRONMENT_CUSTOM_READ = "setup-environment-custom-read"
    SETUP_ENVIRONMENT_REVIEWER_READ = "setup-environment-reviewer-read"
    SETUP_ENVIRONMENT_WRITE = "setup-environment-write"
    SETUP_SECRET_METADATA_READ = "setup-secret-metadata-read"
    SETUP_SECRET_KEY_READ = "setup-secret-key-read"
    SETUP_SECRET_METADATA_AFTER = "setup-secret-metadata-after"
    SETUP_SECRET_WRITE = "setup-secret-write"
    SETUP_VARIABLE_READ = "setup-variable-read"
    SETUP_VARIABLE_CREATE = "setup-variable-create"
    SETUP_VARIABLE_REPLACE = "setup-variable-replace"


_HOSTED_VERSION_ROLES = frozenset({_ResponseRole.HOSTED_VERSION_READ, _ResponseRole.HOSTED_VERSION_HISTORY,
    _ResponseRole.HOSTED_VERSION_JOURNAL_READ, _ResponseRole.HOSTED_VERSION_JOURNAL_WRITE,
    _ResponseRole.HOSTED_VERSION_LEDGER_WRITE})

_GIT_PUSH_ROLES = frozenset({_ResponseRole.GIT_PUSH_ACCOUNT, _ResponseRole.GIT_PUSH_REPOSITORY,
    _ResponseRole.GIT_PUSH_ADVERTISEMENT, _ResponseRole.GIT_PUSH_SEND})
_GIT_PUSH_BINARY = frozenset({_ResponseRole.GIT_PUSH_ADVERTISEMENT, _ResponseRole.GIT_PUSH_SEND})


_GIT_REMOTE_ROLES = frozenset({_ResponseRole.GIT_REMOTE_ACCOUNT, _ResponseRole.GIT_REMOTE_REPOSITORY,
    _ResponseRole.GIT_REMOTE_ADVERTISEMENT, _ResponseRole.GIT_REMOTE_LS_REFS, _ResponseRole.GIT_REMOTE_FETCH})
_GIT_REMOTE_BINARY = frozenset({_ResponseRole.GIT_REMOTE_ADVERTISEMENT,
    _ResponseRole.GIT_REMOTE_LS_REFS, _ResponseRole.GIT_REMOTE_FETCH})


_REPOSITORY_CREATE_ROLES = frozenset({_ResponseRole.REPOSITORY_CREATE_ACCOUNT, _ResponseRole.REPOSITORY_CREATE_OWNER,
    _ResponseRole.REPOSITORY_CREATE_LOOKUP, _ResponseRole.REPOSITORY_CREATE_WRITE})

_ENROLLMENT_ROLES = frozenset({_ResponseRole.VERSION_ENROLLMENT_ACCOUNT, _ResponseRole.VERSION_ENROLLMENT_REPOSITORY,
    _ResponseRole.VERSION_ENROLLMENT_PROTECTION, _ResponseRole.VERSION_ENROLLMENT_REF,
    _ResponseRole.VERSION_ENROLLMENT_LEDGER, _ResponseRole.VERSION_ENROLLMENT_COMPARE})

_PUBLICATION_ROLES = frozenset({_ResponseRole.PUBLICATION_READ, _ResponseRole.PUBLICATION_CREATE, _ResponseRole.PUBLICATION_LIST})
_ALLOCATION_ROLES = frozenset({_ResponseRole.VERSION_ALLOCATION_REPOSITORY, _ResponseRole.VERSION_ALLOCATION_REF,
    _ResponseRole.VERSION_ALLOCATION_COMPARE, _ResponseRole.VERSION_ALLOCATION_LEDGER_READ,
    _ResponseRole.VERSION_ALLOCATION_LEDGER_WRITE})


_VARIABLE_ROLES = frozenset({_ResponseRole.SETUP_VARIABLE_READ, _ResponseRole.SETUP_VARIABLE_CREATE, _ResponseRole.SETUP_VARIABLE_REPLACE})
_SECRET_READ_ROLES = frozenset({_ResponseRole.SETUP_SECRET_METADATA_READ, _ResponseRole.SETUP_SECRET_KEY_READ, _ResponseRole.SETUP_SECRET_METADATA_AFTER})
_ENVIRONMENT_READ_ROLES = frozenset({_ResponseRole.SETUP_ENVIRONMENT_READ, _ResponseRole.SETUP_ENVIRONMENT_LIST,
    _ResponseRole.SETUP_ENVIRONMENT_CUSTOM_READ, _ResponseRole.SETUP_ENVIRONMENT_REVIEWER_READ})
_ENVIRONMENT_ROLES = _ENVIRONMENT_READ_ROLES | {_ResponseRole.SETUP_ENVIRONMENT_WRITE}


def _role_limits(profile: _ExchangeProfile, role: _ResponseRole) -> tuple[int, int]:
    """Closed private roles, never caller-provided numeric limits."""
    if type(profile) is not _ExchangeProfile or type(role) is not _ResponseRole:
        raise ValueError("Invalid fixed GitHub response role")
    if role in _HOSTED_VERSION_ROLES:
        if profile is not _ExchangeProfile.HOSTED_VERSION:
            raise ValueError("Fixed hosted version role belongs to another action")
        return MAX_BODY_BYTES, 1024
    if role in _GIT_PUSH_ROLES:
        if profile is not _ExchangeProfile.GIT_PUSH:
            raise ValueError("Fixed Push role belongs to another action")
        return MAX_BODY_BYTES, 256
    if role in _GIT_REMOTE_ROLES:
        if profile is not _ExchangeProfile.GIT_REMOTE:
            raise ValueError("Fixed Git remote role belongs to another action")
        return (32 * 1024 * 1024 if role is _ResponseRole.GIT_REMOTE_FETCH else MAX_BODY_BYTES, 256)
    if role in {_ResponseRole.PLAY_CLEANUP_READ, _ResponseRole.PLAY_CLEANUP_CONFIG, _ResponseRole.PLAY_CLEANUP_WRITE}:
        if profile is not _ExchangeProfile.PLAY_CLEANUP:
            raise ValueError("Fixed Play cleanup role belongs to another action")
        return (768 * 1024 if role is _ResponseRole.PLAY_CLEANUP_CONFIG else MAX_BODY_BYTES, 2048)
    if role in {_ResponseRole.ACTIONS_RETRY_READ, _ResponseRole.ACTIONS_RETRY_WRITE}:
        if profile is not _ExchangeProfile.ACTIONS_RETRY:
            raise ValueError("Fixed Actions retry role belongs to another action")
        return 256 * 1024, 1024
    if role in {_ResponseRole.PULL_REQUEST_OBJECT, _ResponseRole.PULL_REQUEST_LIST, _ResponseRole.PULL_REQUEST_WRITE}:
        if profile is not _ExchangeProfile.PULL_REQUEST:
            raise ValueError("Fixed draft-PR role belongs to another action")
        return 256 * 1024, 1024
    if role in {_ResponseRole.ACTIVITY_OBJECT, _ResponseRole.ACTIVITY_LIST}:
        if profile is not _ExchangeProfile.ACTIVITY:
            raise ValueError("Fixed activity role belongs to another action")
        return MAX_BODY_BYTES, 1024
    if role in _REPOSITORY_CREATE_ROLES:
        if profile is not _ExchangeProfile.REPOSITORY_CREATE:
            raise ValueError("Fixed repository creation role belongs to another action")
        return 256 * 1024, 256
    if role in _ENROLLMENT_ROLES:
        if profile is not _ExchangeProfile.VERSION_ENROLLMENT:
            raise ValueError("Fixed version enrollment role belongs to another action")
        return MAX_BODY_BYTES, 1024
    if role in _ALLOCATION_ROLES:
        if profile is not _ExchangeProfile.VERSION_ALLOCATION:
            raise ValueError("Fixed version allocation role belongs to another action")
        return MAX_BODY_BYTES, 1024
    if role in _PUBLICATION_ROLES:
        if profile is not _ExchangeProfile.PUBLICATION:
            raise ValueError("Fixed publication role belongs to another action")
        return (384 * 1024, 2048)
    if (role in {_ResponseRole.RELEASE_CONFIG, _ResponseRole.RELEASE_VERSION}
            and profile is not _ExchangeProfile.RELEASE_PREPARE
            or role in ({_ResponseRole.SETUP_ACTIONS_WRITE, _ResponseRole.SETUP_WORKFLOW_WRITE} | _ENVIRONMENT_ROLES | _SECRET_READ_ROLES | {_ResponseRole.SETUP_SECRET_WRITE} | _VARIABLE_ROLES)
            and profile is not _ExchangeProfile.SETUP):
        raise ValueError("Fixed GitHub response role belongs to another action")
    return (768 * 1024 if role is _ResponseRole.RELEASE_CONFIG else MAX_BODY_BYTES,
            2048 if role is _ResponseRole.RELEASE_VERSION else 1024)


def _request_limits(profile: _ExchangeProfile, role: _ResponseRole, method: str, path: str) -> tuple[int, int]:
    limits = _role_limits(profile, role)
    if profile is _ExchangeProfile.HOSTED_VERSION:
        from .version_hosted import validate_endpoint
        validate_endpoint(role.value, method, path)
        return limits
    if profile is _ExchangeProfile.GIT_PUSH:
        from .git_push_transport import validate_endpoint
        validate_endpoint(role.value, method, path)
        return limits
    if profile is _ExchangeProfile.GIT_REMOTE:
        from .git_remote_transport import validate_endpoint
        validate_endpoint(role.value, method, path)
        return limits
    if profile is _ExchangeProfile.PLAY_CLEANUP:
        from ._github_play_cleanup_transport import validate_endpoint
        validate_endpoint(role, method, path)
        return limits
    if profile is _ExchangeProfile.ACTIONS_RETRY:
        from ._github_actions_retry_transport import validate_endpoint
        validate_endpoint(role, method, path)
        return limits
    if profile is _ExchangeProfile.PULL_REQUEST:
        from ._github_pull_request_transport import validate_endpoint
        validate_endpoint(role, method, path)
        return limits
    if profile is _ExchangeProfile.ACTIVITY:
        from ._github_activity_transport import validate_endpoint
        validate_endpoint(role, method, path)
        return limits
    if profile is _ExchangeProfile.REPOSITORY_CREATE:
        from ._github_repository_create_transport import validate_endpoint
        validate_endpoint(role, method, path)
        return limits
    if profile is _ExchangeProfile.VERSION_ENROLLMENT:
        from .version_enrollment import validate_endpoint
        validate_endpoint(role.value, method, path)
        return limits
    if profile is _ExchangeProfile.VERSION_ALLOCATION:
        from .version_allocation_transport import validate_endpoint
        validate_endpoint(role.value, method, path)
        return limits
    if profile is _ExchangeProfile.PUBLICATION:
        from ._github_setup_publication_transport import validate_endpoint
        validate_endpoint(role, method, path)
        return limits
    if profile is _ExchangeProfile.SETUP:
        from .api._github_connection import _coordinate

        if type(path) is not str:
            raise ValueError("Invalid fixed Setup path")
        if path == "/user":
            valid = role is _ResponseRole.STANDARD and method == "GET"
        else:
            parts = path.split("/")
            if len(parts) < 4 or parts[:2] != ["", "repos"]:
                raise ValueError("Invalid fixed Setup path")
            _coordinate(parts[2] + "/" + parts[3])
            tail = parts[4:]
            if role is _ResponseRole.STANDARD:
                valid = method == "GET" and tail in ([], ["actions", "permissions"], ["actions", "permissions", "workflow"])
            elif role in _VARIABLE_ROLES:
                from .github_setup_variables import VARIABLE_FIELDS, ENVIRONMENT_NAMES
                collection = len(tail) in (3, 4) and tail[0] == "environments" and tail[1] in ENVIRONMENT_NAMES.values() and tail[2] == "variables"
                if role is _ResponseRole.SETUP_VARIABLE_CREATE:
                    valid = collection and len(tail) == 3 and method == "POST"
                else:
                    valid = (collection and len(tail) == 4 and tail[3] in {row[0] for row in VARIABLE_FIELDS}
                             and method == ("GET" if role is _ResponseRole.SETUP_VARIABLE_READ else "PATCH"))
            elif role in _SECRET_READ_ROLES | {_ResponseRole.SETUP_SECRET_WRITE}:
                from .github_setup_remote import SECRET_REQUIREMENTS, ENVIRONMENT_NAMES
                valid = (method == ("PUT" if role is _ResponseRole.SETUP_SECRET_WRITE else "GET") and len(tail) == 4 and tail[0] == "environments"
                         and tail[1] in ENVIRONMENT_NAMES.values() and tail[2] == "secrets"
                         and (tail[3] == "public-key" if role is _ResponseRole.SETUP_SECRET_KEY_READ
                              else tail[3] in SECRET_REQUIREMENTS))
            elif role in _ENVIRONMENT_ROLES:
                from .github_setup_remote import _ENVIRONMENT_NAMES, _environment_login
                names = dict(_ENVIRONMENT_NAMES).values()
                if role is _ResponseRole.SETUP_ENVIRONMENT_LIST:
                    valid = method == "GET" and tail == ["environments?per_page=100&page=1"]
                elif role is _ResponseRole.SETUP_ENVIRONMENT_REVIEWER_READ:
                    valid = method == "GET" and len(tail) == 3 and tail[0] == "collaborators" and tail[2] == "permission"
                    if valid:
                        _environment_login(tail[1])
                elif role is _ResponseRole.SETUP_ENVIRONMENT_CUSTOM_READ:
                    valid = method == "GET" and len(tail) == 3 and tail[0] == "environments" and tail[1] in names and tail[2] == "deployment_protection_rules"
                else:
                    valid = method == ("PUT" if role is _ResponseRole.SETUP_ENVIRONMENT_WRITE else "GET") and len(tail) == 2 and tail[0] == "environments" and tail[1] in names
            else:
                expected = ["actions", "permissions"] + (["workflow"] if role is _ResponseRole.SETUP_WORKFLOW_WRITE else [])
                valid = method == "PUT" and tail == expected
        if not valid:
            raise ValueError("Fixed Setup method/path/role differs")
    prefix = r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/contents/"
    if role is _ResponseRole.RELEASE_CONFIG:
        if method != "GET" or type(path) is not str or re.fullmatch(prefix + r"release/mobile-release\.json\?ref=[0-9a-f]{40}", path) is None:
            raise ValueError("Fixed release config response role differs")
    elif role is _ResponseRole.RELEASE_VERSION:
        component = r"(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+"
        if method != "GET" or type(path) is not str or re.fullmatch(prefix + component + r"(?:/" + component + r"){0,11}\?ref=[0-9a-f]{40}", path) is None:
            raise ValueError("Fixed release version response role differs")
    return limits


def _allocation_body(profile: _ExchangeProfile, role: _ResponseRole, body: object, *, path: str) -> None:
    _role_limits(profile, role)
    if profile is not _ExchangeProfile.VERSION_ALLOCATION or role not in _ALLOCATION_ROLES:
        raise ValueError("Invalid fixed version allocation body role")
    from .version_allocation_transport import validate_body
    validate_body(role.value, body, path=path)


def _setup_body(profile: _ExchangeProfile, role: _ResponseRole, body: object, *, path: str | None = None) -> None:
    _role_limits(profile, role)
    if role is _ResponseRole.STANDARD or role in _ENVIRONMENT_READ_ROLES | _SECRET_READ_ROLES | {_ResponseRole.SETUP_VARIABLE_READ}:
        if body is not None:
            raise ValueError("Fixed Setup GET has a body")
        return
    if profile is _ExchangeProfile.SETUP and role in {_ResponseRole.SETUP_VARIABLE_CREATE, _ResponseRole.SETUP_VARIABLE_REPLACE}:
        from .github_setup_variables import MAX_BODY_BYTES as MAX_VARIABLE_BODY, VARIABLE_FIELDS, _desired
        creating = role is _ResponseRole.SETUP_VARIABLE_CREATE
        _request_limits(profile, role, "POST" if creating else "PATCH", path)
        if type(body) is not bytes or not 1 <= len(body) <= MAX_VARIABLE_BODY:
            raise ValueError("Invalid fixed variable body bound")
        value = _decode_json(body, limit=MAX_VARIABLE_BODY, nodes=8, depth=2, exact=True)
        if type(value) is not dict or set(value) != ({"name", "value"} if creating else {"value"}):
            raise ValueError("Invalid fixed variable body")
        name = value["name"] if creating else path.rsplit("/", 1)[1]
        if type(name) is not str or name not in {row[0] for row in VARIABLE_FIELDS}:
            raise ValueError("Invalid fixed variable name")
        _desired(name, value["value"])
        return
    if profile is _ExchangeProfile.SETUP and role is _ResponseRole.SETUP_SECRET_WRITE:
        from .github_setup_remote import SECRET_WRITE_BYTES, secret_write_policy
        if type(body) is not bytes or not 1 <= len(body) <= SECRET_WRITE_BYTES:
            raise ValueError("Invalid fixed secret body bound")
        secret_write_policy(_decode_json(body, limit=SECRET_WRITE_BYTES, nodes=8, depth=2, exact=True))
        return
    if profile is not _ExchangeProfile.SETUP or role not in {
            _ResponseRole.SETUP_ACTIONS_WRITE, _ResponseRole.SETUP_WORKFLOW_WRITE, _ResponseRole.SETUP_ENVIRONMENT_WRITE}:
        raise ValueError("Invalid fixed Setup body role")
    from .github_setup_remote import MAX_BODY_BYTES as MAX_SETUP_BODY, Policy, environment_put_policy

    if type(body) is not bytes or not 1 <= len(body) <= MAX_SETUP_BODY:
        raise ValueError("Invalid fixed Setup body bound")
    if role is _ResponseRole.SETUP_ENVIRONMENT_WRITE:
        value = _decode_json(body, limit=MAX_SETUP_BODY, nodes=64, depth=3, exact=True)
        environment_put_policy(value)
        return
    value = _decode_json(body, limit=MAX_SETUP_BODY, nodes=32, depth=3, exact=True)
    kind = "actions_enabled" if role is _ResponseRole.SETUP_ACTIONS_WRITE else "workflow_token_policy"
    Policy.parse(kind, value)


class ReadFailure(Exception):
    def __init__(self, reason: str) -> None:
        if reason not in {"network-unavailable", "tls-failed", "response-invalid", "response-limit", "cancelled"}:
            raise ValueError("Invalid fixed GitHub failure")
        self.reason = reason
        super().__init__("The fixed GitHub read was unavailable")


class _CloseFailure(RuntimeError):
    pass


def _control(reason: str = "none", delay: int | None = None, blocked: bool = False) -> dict[str, Any]:
    # No wire expiry grammar has been established. Never synthesize a server
    # timestamp from the native ceiling or parse a plausible-looking header.
    return {"reason": reason, "credentialExpiresAt": None,
            "cooldownSeconds": delay, "cooldownBlocked": blocked}


def _refuse(control: dict[str, Any], reason: str) -> dict[str, Any]:
    delay, blocked = control["cooldownSeconds"], control["cooldownBlocked"]
    if delay is not None or blocked:
        # A known not-before must survive body/identity/header refusal. The
        # reviewed response-invalid path also retires credential use natively.
        return _control("rate-limited" if reason == "rate-limited" else "response-invalid", delay, blocked)
    if control["reason"] in _FATAL and reason != "response-invalid":
        reason = control["reason"]
    return _control(reason)


@dataclass(slots=True, repr=False)
class ReadResult:
    observation: dict[str, Any]
    control: dict[str, Any]


def _failed(reason: str, control: dict[str, Any] | None = None) -> ReadResult:
    # These are failed/unsent observations, not invented HTTP responses.
    return ReadResult({"status": None, "body": None, "failure": reason},
                      _refuse(control or _control(), reason))


class _Reader(Protocol):
    def read(self, step: str) -> ReadResult: ...


class _Budget:
    def __init__(self, started: float, *, monotonic: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time, _profile: _ExchangeProfile = _ExchangeProfile.STANDARD) -> None:
        _role_limits(_profile, _ResponseRole.STANDARD)
        if type(started) not in (int, float):
            raise ReadFailure("network-unavailable")
        self.started = started
        self.end = started + (45.0 if _profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH} else 60.0 if _profile in {_ExchangeProfile.HOSTED_VERSION, _ExchangeProfile.PUBLICATION, _ExchangeProfile.VERSION_ALLOCATION, _ExchangeProfile.VERSION_ENROLLMENT, _ExchangeProfile.REPOSITORY_CREATE, _ExchangeProfile.ACTIVITY, _ExchangeProfile.PULL_REQUEST, _ExchangeProfile.ACTIONS_RETRY, _ExchangeProfile.PLAY_CLEANUP} else READ_SECONDS)
        self.monotonic = monotonic
        self.wall = wall
        self.body_bytes = 0
        self.metadata_bytes = 0
        self.profile = _profile
        self.requests = 0
        self.body_total_limit = (10 * 1024 * 1024 if _profile is _ExchangeProfile.HOSTED_VERSION else
                                 2 * 1024 * 1024 if _profile is _ExchangeProfile.GIT_PUSH else
                                 34 * 1024 * 1024 if _profile is _ExchangeProfile.GIT_REMOTE else
                                 4 * 1024 * 1024 if _profile is _ExchangeProfile.PUBLICATION else
                                 2 * 1024 * 1024 if _profile in {_ExchangeProfile.RELEASE_PREPARE, _ExchangeProfile.REPOSITORY_CREATE, _ExchangeProfile.ACTIVITY, _ExchangeProfile.PULL_REQUEST, _ExchangeProfile.ACTIONS_RETRY, _ExchangeProfile.PLAY_CLEANUP} else MAX_BODY_TOTAL)
        if not math.isfinite(started) or not math.isfinite(self.end):
            raise ReadFailure("network-unavailable")

    def claim_request(self) -> None:
        # Other existing profiles retain their own original finite schedules.
        # Allocation adds a second private bound, never a logical retry owner.
        if self.profile in {_ExchangeProfile.HOSTED_VERSION, _ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH, _ExchangeProfile.VERSION_ALLOCATION, _ExchangeProfile.VERSION_ENROLLMENT, _ExchangeProfile.REPOSITORY_CREATE, _ExchangeProfile.ACTIVITY, _ExchangeProfile.PULL_REQUEST, _ExchangeProfile.ACTIONS_RETRY, _ExchangeProfile.PLAY_CLEANUP}:
            self.remaining()
            if self.requests >= (19 if self.profile is _ExchangeProfile.PLAY_CLEANUP else 44 if self.profile is _ExchangeProfile.HOSTED_VERSION else 7 if self.profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH} else 12 if self.profile is _ExchangeProfile.PULL_REQUEST else 8 if self.profile in {_ExchangeProfile.REPOSITORY_CREATE, _ExchangeProfile.ACTIVITY, _ExchangeProfile.ACTIONS_RETRY} else 10):
                raise ReadFailure("response-limit")
            self.requests += 1

    def remaining(self) -> float:
        now = self.monotonic()
        if type(now) not in (int, float) or not math.isfinite(now) or now < self.started or now >= self.end:
            # A helper budget is NOT proof that the credential expired.
            raise ReadFailure("network-unavailable")
        return self.end - now

    def wall_seconds(self) -> int | None:
        try:
            value = self.wall()
            if type(value) not in (int, float) or not math.isfinite(value):
                return None
            whole = math.floor(value)
            return whole if -_EPOCH_LIMIT <= whole <= _EPOCH_LIMIT else None
        except Exception:
            return None


@dataclass(slots=True, repr=False)
class _Head:
    status: int
    version: int
    headers: dict[str, list[str | None]]
    invalid: bool = False
    framing: str = "eof"
    length: int | None = None
    error: str | None = None


def _field(line: bytes) -> tuple[str | None, str | None]:
    name, separator, value = line[:-2].partition(b":")
    if not separator or not name or any(byte not in _TCHAR for byte in name):
        return None, None
    key = name.decode("ascii").lower()
    if any(not 0x20 <= byte <= 0x7e for byte in value):
        return key, None
    return key, value.decode("ascii").strip(" ")


def _single(headers: dict[str, list[str | None]], name: str) -> tuple[str | None, bool, bool]:
    values = headers.get(name)
    if values is None:
        return None, False, True
    if len(values) != 1 or values[0] is None:
        return None, True, False
    return values[0], True, True


def _decimal(value: str, maximum: int) -> int | object:
    if not value or any(not "0" <= char <= "9" for char in value):
        raise ValueError("Invalid bounded decimal")
    significant = value.lstrip("0") or "0"
    bound = str(maximum)
    if len(significant) > len(bound) or len(significant) == len(bound) and significant > bound:
        return _LONG
    return int(significant)


def _framing(head: _Head, maximum: int = MAX_BODY_BYTES, *,
             _role: _ResponseRole = _ResponseRole.STANDARD) -> None:
    length, has_length, length_ok = _single(head.headers, "content-length")
    coding, has_coding, coding_ok = _single(head.headers, "transfer-encoding")
    encoding, has_encoding, encoding_ok = _single(head.headers, "content-encoding")
    if (head.invalid or not length_ok or not coding_ok or not encoding_ok
            or has_length and has_coding or has_coding and coding.lower() != "chunked"
            or has_encoding and encoding.lower() != "identity"
            or "upgrade" in head.headers
            or any(value is not None and "upgrade" in (part.strip(" ").lower() for part in value.split(","))
                   for value in head.headers.get("connection", []))):
        head.error = "response-invalid"
        return
    if has_coding:
        head.framing = "chunked"
    elif has_length:
        try:
            size = _decimal(length, maximum)
        except ValueError:
            head.error = "response-invalid"
            return
        head.framing = "length"
        head.length = maximum + 1 if size is _LONG else size
        if size is _LONG and head.status == 200:
            head.error = "response-limit"
    if head.status == 200:
        media, present, valid = _single(head.headers, "content-type")
        if _role in _GIT_PUSH_BINARY:
            from .git_push_transport import response_media
            if not present or not valid or media != response_media(_role.value):
                head.error = "response-invalid"
        elif _role in _GIT_REMOTE_BINARY:
            from .git_remote_transport import response_media
            if not present or not valid or media != response_media(_role.value):
                head.error = "response-invalid"
        elif (not present or not valid or re.fullmatch(
                r"application/(?:json|vnd\.github\+json)(?: *; *charset=utf-8)?", media, re.ASCII | re.IGNORECASE) is None):
            head.error = "response-invalid"


def _chunk_size(line: bytes, maximum: int = MAX_BODY_BYTES) -> int:
    body = line[:-2]
    index = 0
    while index < len(body) and body[index] in b"0123456789abcdefABCDEF":
        index += 1
    if index == 0:
        raise ReadFailure("response-invalid")
    digits = body[:index].lstrip(b"0") or b"0"
    bound = format(maximum, "x").encode("ascii")
    if len(digits) > len(bound) or len(digits) == len(bound) and digits.lower() > bound:
        raise ReadFailure("response-limit")
    size = int(digits, 16)
    # The supported finite extension subset is ;token[=token/quoted-string].
    # Discarded extensions still count toward every raw framing bound.
    while index < len(body):
        if body[index] != ord(";"):
            raise ReadFailure("response-invalid")
        index += 1
        start = index
        while index < len(body) and body[index] in _TCHAR:
            index += 1
        if index == start:
            raise ReadFailure("response-invalid")
        if index < len(body) and body[index] == ord("="):
            index += 1
            if index < len(body) and body[index] == ord('"'):
                index += 1
                closed = False
                while index < len(body):
                    byte = body[index]
                    index += 1
                    if byte == ord('"'):
                        closed = True
                        break
                    if byte == ord("\\"):
                        if index >= len(body) or not 0x20 <= body[index] <= 0x7e:
                            raise ReadFailure("response-invalid")
                        index += 1
                    elif not 0x20 <= byte <= 0x7e:
                        raise ReadFailure("response-invalid")
                if not closed:
                    raise ReadFailure("response-invalid")
            else:
                start = index
                while index < len(body) and body[index] in _TCHAR:
                    index += 1
                if index == start:
                    raise ReadFailure("response-invalid")
    return size


class _ResponseBody:
    """Narrow finite delegate used by the live HTTPResponse subclass.

    Inert tests supply BytesIO, not an HTTP/TLS/socket factory. Each raw read is
    sized and rechecks the original budget. Header/framing accounting happens
    during reads, not after http.client/email has allocated unbounded metadata.
    """
    def __init__(self, source: Any, budget: _Budget, *, before_read: Callable[[float], None] | None = None,
                 _role: _ResponseRole = _ResponseRole.STANDARD) -> None:
        self.source = source
        self.budget = budget
        self.maximum, _ = _role_limits(budget.profile, _role)
        self.role = _role
        self.before_read = before_read
        self.header_bytes = 0
        self.framing_bytes = 0
        self.trailer_bytes = 0
        self.body_bytes = 0
        self.chunks = 0
        self.chunk_left: int | None = None
        self.done = False
        self.control: dict[str, Any] | None = None
        self.head = self._head()
        self.length_left = self.head.length

    def _raw(self, size: int) -> bytes:
        remaining = self.budget.remaining()
        if self.before_read is not None:
            self.before_read(remaining)
        # One finite buffered/raw operation; never read() with no size.
        reader = getattr(self.source, "read1", self.source.read)
        block = reader(size)
        self.budget.remaining()  # A late return cannot renew the helper budget.
        if type(block) is not bytes or len(block) > size:
            raise ReadFailure("response-invalid")
        return block

    def _allow_meta(self, size: int, kind: str) -> None:
        local, limit = ((self.header_bytes, MAX_HEADER_BYTES) if kind == "headers"
                        else (self.framing_bytes, MAX_FRAMING_BYTES))
        if (local + size > limit or self.budget.metadata_bytes + size > MAX_METADATA_TOTAL
                or kind == "trailers" and self.trailer_bytes + size > MAX_TRAILER_BYTES):
            raise ReadFailure("response-limit")

    def _charge_meta(self, size: int, kind: str) -> None:
        self.budget.metadata_bytes += size
        if kind == "headers":
            self.header_bytes += size
        else:
            self.framing_bytes += size
            if kind == "trailers":
                self.trailer_bytes += size

    def _line(self, limit: int, kind: str) -> bytes:
        line = bytearray()
        while len(line) < limit:
            self._allow_meta(1, kind)
            block = self._raw(1)
            if not block:
                raise ReadFailure("response-invalid")
            self._charge_meta(1, kind)
            line.extend(block)
            if block == b"\n":
                if not line.endswith(b"\r\n"):
                    raise ReadFailure("response-invalid")
                return bytes(line)
        raise ReadFailure("response-limit")

    def _fixed_meta(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            self._allow_meta(size - len(data), "framing")
            block = self._raw(size - len(data))
            if not block:
                raise ReadFailure("response-invalid")
            self._charge_meta(len(block), "framing")
            data.extend(block)
        return bytes(data)

    def _head(self) -> _Head:
        status_line = self._line(MAX_HEADER_LINE, "headers")
        match = re.fullmatch(rb"HTTP/1\.([01]) ([1-5][0-9]{2})(?: [\x20-\x7e]*)?\r\n", status_line)
        if match is None:
            raise ReadFailure("response-invalid")
        status = int(match[2])
        if status < 200:  # No stdlib informational-loop or protocol upgrade.
            raise ReadFailure("response-invalid")
        head = _Head(status, 10 if match[1] == b"0" else 11, {})
        previous: str | None = None
        count = 0
        while True:
            line = self._line(MAX_HEADER_LINE if count < MAX_HEADER_FIELDS else 2, "headers")
            if line == b"\r\n":
                break
            count += 1
            if line[:1] in (b" ", b"\t"):
                head.invalid = True
                if previous is not None:
                    head.headers[previous][-1] = None
                continue
            name, value = _field(line)
            previous = name
            if name is None:
                head.invalid = True
                continue
            head.headers.setdefault(name, []).append(value)
            if value is None:
                head.invalid = True
        _framing(head, self.maximum, _role=self.role)
        return head

    def _trailers(self) -> None:
        fields = 0
        while True:
            line = self._line(MAX_TRAILER_LINE if fields < MAX_TRAILER_FIELDS else 2, "trailers")
            if line == b"\r\n":
                return
            fields += 1
            name, value = _field(line)
            if name is None or value is None or name in _FORBIDDEN_TRAILERS:
                raise ReadFailure("response-invalid")

    def _next_chunk(self) -> None:
        if self.chunk_left == 0 and self._fixed_meta(2) != b"\r\n":
            raise ReadFailure("response-invalid")
        if self.chunks >= MAX_CHUNKS:
            raise ReadFailure("response-limit")
        line = self._line(MAX_CHUNK_LINE, "framing")
        self.chunks += 1
        size = _chunk_size(line, self.maximum)
        if size > self.maximum - self.body_bytes or size > self.budget.body_total_limit - self.budget.body_bytes:
            raise ReadFailure("response-limit")
        if size == 0:
            self._trailers()  # Missing terminal CRLF/trailers are NOT EOF success.
            self.done = True
        self.chunk_left = size

    def read(self, maximum: int) -> bytes:
        if type(maximum) is not int or not 1 <= maximum <= _READ_CHUNK:
            raise ReadFailure("response-invalid")
        if self.head.error is not None:
            raise ReadFailure(self.head.error)
        if self.done:
            return b""
        if self.head.framing == "chunked":
            if self.chunk_left in (None, 0):
                self._next_chunk()
            if self.done:
                return b""
            maximum = min(maximum, self.chunk_left)
        elif self.head.framing == "length":
            if self.length_left == 0:
                self.done = True
                return b""
            maximum = min(maximum, self.length_left)
        # A one-byte overflow probe is permitted for unknown-length bodies.
        maximum = min(maximum, self.maximum + 1 - self.body_bytes,
                      self.budget.body_total_limit + 1 - self.budget.body_bytes)
        if maximum <= 0:
            raise ReadFailure("response-limit")
        block = self._raw(maximum)
        if not block:
            if self.head.framing != "eof":
                raise ReadFailure("response-invalid")
            self.done = True
            return b""
        self.body_bytes += len(block)
        self.budget.body_bytes += len(block)
        if self.body_bytes > self.maximum or self.budget.body_bytes > self.budget.body_total_limit:
            raise ReadFailure("response-limit")
        if self.head.framing == "chunked":
            self.chunk_left -= len(block)
        elif self.head.framing == "length":
            self.length_left -= len(block)
        return block


_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _http_date(value: str) -> int:
    # Strict IMF-fixdate is client policy, not a claim GitHub emits date-form
    # Retry-After. No email/dateutil/locale parser or obsolete HTTP date forms.
    match = re.fullmatch(r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun), ([0-9]{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) GMT", value, re.ASCII)
    if match is None:
        raise ValueError("Invalid fixed HTTP date")
    date = datetime(int(match[4]), _MONTHS.index(match[3]) + 1, int(match[2]),
                    int(match[5]), int(match[6]), int(match[7]), tzinfo=timezone.utc)
    if _WEEKDAYS[date.weekday()] != match[1]:
        raise ValueError("Invalid fixed HTTP date")
    delta = date - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return delta.days * 86400 + delta.seconds


def _status_reason(status: int) -> str:
    return {200: "none", 401: "unauthorized", 403: "forbidden", 404: "not-found-or-inaccessible", 429: "rate-limited"}.get(
        status, "network-unavailable" if status >= 500 else "response-invalid")


def _header_control(head: _Head, budget: _Budget, *,
                    _role: _ResponseRole = _ResponseRole.STANDARD) -> dict[str, Any]:
    _role_limits(budget.profile, _role)
    expiry, has_expiry, expiry_ok = _single(head.headers, "github-authentication-token-expiration")
    retry, has_retry, retry_ok = _single(head.headers, "retry-after")
    remaining, has_remaining, remaining_ok = _single(head.headers, "x-ratelimit-remaining")
    reset, has_reset, reset_ok = _single(head.headers, "x-ratelimit-reset")
    invalid = has_expiry or not expiry_ok or head.invalid
    exhausted = False
    hints: list[tuple[str, int | object]] = []
    if has_remaining and remaining_ok:
        try:
            exhausted = _decimal(remaining, 0) == 0
        except ValueError:
            remaining_ok = False
    if has_retry and retry_ok:
        try:
            if retry and all("0" <= char <= "9" for char in retry):
                hints.append(("delta", _decimal(retry, MAX_COOLDOWN_SECONDS)))
            else:
                hints.append(("absolute", _http_date(retry)))
        except (ValueError, OverflowError):
            retry_ok = False
    if has_reset and reset_ok:
        try:
            parsed_reset = _decimal(reset, _EPOCH_LIMIT)
            if exhausted:
                hints.append(("absolute", parsed_reset))
        except ValueError:
            reset_ok = False
    invalid = invalid or not retry_ok or not remaining_ok or not reset_ok
    recognized = head.status == 429 or exhausted or head.status == 403 and has_retry and retry_ok
    # One wall-clock sample per response, only when needed. Integer conversion
    # includes the reviewed conservative second and never rounds a delay down.
    wall = budget.wall_seconds() if any(kind == "absolute" for kind, _ in hints) else None
    delays: list[int] = []
    blocked = False
    for kind, value in hints:
        if value is _LONG or kind == "absolute" and wall is None:
            blocked = True
            continue
        difference = value if kind == "delta" else value - wall + 1
        if not -_EPOCH_LIMIT <= difference <= _EPOCH_LIMIT:
            blocked = True
            continue
        delay = max(1, difference)
        if delay > MAX_COOLDOWN_SECONDS:
            blocked = True
        else:
            delays.append(delay)
    delay = None if blocked else max(delays) if delays else 60 if recognized else None
    base = _status_reason(head.status)
    if (head.status in {201, 409, 422} and _role is _ResponseRole.HOSTED_VERSION_JOURNAL_WRITE
            or head.status in {409, 422} and _role is _ResponseRole.HOSTED_VERSION_LEDGER_WRITE
            or head.status == 404 and _role is _ResponseRole.HOSTED_VERSION_JOURNAL_READ
            or head.status == 204 and _role is _ResponseRole.PLAY_CLEANUP_WRITE
            or head.status in {201, 409, 422} and _role is _ResponseRole.ACTIONS_RETRY_WRITE
            or head.status in {201, 409, 422} and _role is _ResponseRole.PULL_REQUEST_WRITE
            or head.status in {201, 409, 422} and _role is _ResponseRole.REPOSITORY_CREATE_WRITE
            or head.status == 404 and _role is _ResponseRole.REPOSITORY_CREATE_LOOKUP
            or head.status == 201 and _role is _ResponseRole.PUBLICATION_CREATE
            or head.status == 404 and _role is _ResponseRole.PUBLICATION_READ
            or head.status == 204 and _role in {_ResponseRole.SETUP_ACTIONS_WRITE, _ResponseRole.SETUP_WORKFLOW_WRITE}
            or head.status in {201, 204} and _role is _ResponseRole.SETUP_SECRET_WRITE
            or head.status == 201 and _role is _ResponseRole.SETUP_VARIABLE_CREATE
            or head.status == 204 and _role is _ResponseRole.SETUP_VARIABLE_REPLACE
            or head.status == 404 and _role is _ResponseRole.SETUP_VARIABLE_READ
            or head.status == 409 and _role is _ResponseRole.SETUP_WORKFLOW_WRITE
            or head.status == 422 and _role is _ResponseRole.SETUP_ENVIRONMENT_WRITE
            or head.status in {409, 422} and _role is _ResponseRole.VERSION_ALLOCATION_LEDGER_WRITE
            or head.status == 404 and _role is _ResponseRole.SETUP_SECRET_METADATA_READ):
        base = "none"  # Only these already-bound response roles admit the status.
    if invalid:
        reason = "response-invalid"
    elif delay is not None or blocked:
        # In particular, a 401 can NEVER become retryable just because it also
        # has quota metadata. Preserve the hint using the retiring refusal path.
        reason = "rate-limited" if recognized and head.status in {200, 403, 429} else "response-invalid"
    else:
        reason = base
    return _control(reason, delay, blocked)


def _response_result(response: _ResponseBody, budget: _Budget, *, _remote_delivery=None, _remote_failure=None, _push_delivery=None) -> ReadResult:
    head = response.head
    # GitRemote's original FixedResponse parses this before stdlib can close
    # inside getresponse. Reuse that exact wall-clock sample, not a later one.
    control = (response.control if budget.profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH} and response.control is not None
               else _header_control(head, budget, _role=response.role))
    response.control = control  # Retain a validated hint if a later IO read fails.
    if head.error is not None:
        return _failed(head.error, control)
    if control["reason"] == "response-invalid":
        return _failed("response-invalid", control)
    if budget.profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH} and control["reason"] != "none":
        # The same Entry has already observed its first failure. No error body
        # read may use a failed work clock or turn a known limit into new work.
        return _failed(control["reason"], control)
    if response.role in _GIT_PUSH_BINARY:
        from .git_push_transport import stream_response
        if control["reason"] != "none":
            if control["reason"] == "rate-limited":
                return _failed("rate-limited", control)
            return ReadResult({"status": head.status, "body": None, "failure": "none"}, control)
        if head.status != 200:
            return ReadResult({"status": head.status, "body": None, "failure": "none"}, control)
        return stream_response(response, budget, _push_delivery, failure=_remote_failure)
    if _push_delivery is not None:
        raise ValueError("Push response sink belongs to another role")
    if response.role in _GIT_REMOTE_BINARY:
        # This private delegate streams only inside THIS original exchange.
        # No full pack body, response generator or socket can escape finally.
        from .git_remote_transport import stream_response
        if control["reason"] != "none":
            if control["reason"] == "rate-limited":
                return _failed("rate-limited", control)
            return ReadResult({"status": head.status, "body": None, "failure": "none"}, control)
        if head.status != 200:
            return ReadResult({"status": head.status, "body": None, "failure": "none"}, control)
        return stream_response(response, budget, _remote_delivery, failure=_remote_failure)
    if head.status == 204 and response.role in {_ResponseRole.PLAY_CLEANUP_WRITE, _ResponseRole.SETUP_ACTIONS_WRITE, _ResponseRole.SETUP_WORKFLOW_WRITE, _ResponseRole.SETUP_SECRET_WRITE, _ResponseRole.SETUP_VARIABLE_REPLACE}:
        try:
            # No body/chunk stream is allowed by this exact successful role.
            # Even CL0 must observe the same original's clean TLS EOF once.
            if "transfer-encoding" in head.headers or head.length not in (None, 0):
                raise ReadFailure("response-invalid")
            block = response._raw(1)  # Existing one-byte overflow-probe allowance.
            response.body_bytes += len(block)
            budget.body_bytes += len(block)
            if budget.body_bytes > budget.body_total_limit:
                raise ReadFailure("response-limit")
            if block:
                raise ReadFailure("response-invalid")
            response.done = True
            return ReadResult({"status": 204, "body": None, "failure": "none"}, control)
        except ReadFailure as error:
            return _failed(error.reason, control)
    if head.status == 201 and response.role is _ResponseRole.ACTIONS_RETRY_WRITE:
        try:
            # Documented empty acceptance, not PR creation JSON or workflow
            # success. Observe the original framed body and clean TLS EOF.
            if head.length not in (None, 0):
                raise ReadFailure("response-invalid")
            media, present, valid = _single(head.headers, "content-type")
            if not valid or present and re.fullmatch(
                    r"application/(?:json|vnd\.github\+json)(?: *; *charset=utf-8)?", media, re.ASCII | re.IGNORECASE) is None:
                raise ReadFailure("response-invalid")
            if response.read(1):
                raise ReadFailure("response-invalid")
            if head.framing != "eof":
                probe = response._raw(1)
                response.body_bytes += len(probe); budget.body_bytes += len(probe)
                if budget.body_bytes > budget.body_total_limit:
                    raise ReadFailure("response-limit")
                if probe:
                    raise ReadFailure("response-invalid")
            budget.remaining()
            return ReadResult({"status": 201, "body": None, "failure": "none"}, control)
        except ReadFailure as error:
            return _failed(error.reason, control)
    if head.status == 201 and response.role in {_ResponseRole.SETUP_SECRET_WRITE, _ResponseRole.SETUP_VARIABLE_CREATE}:
        try:
            # The documented response is absent or the empty JSON object, not
            # arbitrary success JSON. Bound retained spelling before every read.
            if head.length is not None and head.length > 64:
                raise ReadFailure("response-invalid")
            body = bytearray()
            while True:
                block = response.read(min(64 + 1 - len(body), _READ_CHUNK))
                if not block: break
                if len(block) > 64 - len(body): raise ReadFailure("response-invalid")
                body.extend(block)
            if head.framing != "eof":
                probe = response._raw(1)
                response.body_bytes += len(probe); budget.body_bytes += len(probe)
                if budget.body_bytes > budget.body_total_limit: raise ReadFailure("response-limit")
                if probe: raise ReadFailure("response-invalid")
            if body:
                media, present, valid = _single(head.headers, "content-type")
                if (not present or not valid or re.fullmatch(
                        r"application/(?:json|vnd\.github\+json)(?: *; *charset=utf-8)?", media, re.ASCII | re.IGNORECASE) is None):
                    raise ReadFailure("response-invalid")
                value = _decode_json(bytes(body), limit=64, nodes=1, depth=1, exact=True)
                if type(value) is not dict or value: raise ReadFailure("response-invalid")
            else:
                # Empty EOF with an optional well-formed JSON type, never a
                # conflicting/duplicate or unsupported content-type claim.
                media, present, valid = _single(head.headers, "content-type")
                if not valid or present and re.fullmatch(
                        r"application/(?:json|vnd\.github\+json)(?: *; *charset=utf-8)?", media, re.ASCII | re.IGNORECASE) is None:
                    raise ReadFailure("response-invalid")
                value = None
            budget.remaining()
            return ReadResult({"status": 201, "body": value, "failure": "none"}, control)
        except (_JsonLimit, _JsonError):
            return _failed("response-invalid", control)
        except ReadFailure as error:
            return _failed(error.reason, control)
    if head.status != 200 and not (head.status == 201 and response.role in {_ResponseRole.HOSTED_VERSION_JOURNAL_WRITE, _ResponseRole.PUBLICATION_CREATE, _ResponseRole.REPOSITORY_CREATE_WRITE, _ResponseRole.PULL_REQUEST_WRITE}):
        # Never read/parse/retain arbitrary error bodies, even JSON-looking ones.
        if head.status == 403 and control["reason"] == "rate-limited":
            return _failed("rate-limited", control)
        return ReadResult({"status": head.status, "body": None, "failure": "none"}, control)
    try:
        if head.length is not None and head.length > budget.body_total_limit - budget.body_bytes:
            raise ReadFailure("response-limit")
        chunks: list[bytes] = []
        while True:
            block = response.read(_READ_CHUNK)
            if not block:
                break
            chunks.append(block)
        raw = b"".join(chunks)
        if budget.profile is _ExchangeProfile.PLAY_CLEANUP:
            from .github_setup_secret_inputs import _json_prelude_checked, SecretConfigurationError
            try:
                _json_prelude_checked(raw, budget.remaining)
            except SecretConfigurationError as error:
                raise ReadFailure("response-limit" if error.reason == "resources-unavailable" else "response-invalid") from None
        body = _decode_json(raw, limit=response.maximum, nodes=20_000, depth=24)
        expected = list if response.role in {_ResponseRole.HOSTED_VERSION_HISTORY, _ResponseRole.PUBLICATION_LIST, _ResponseRole.ACTIVITY_LIST, _ResponseRole.PULL_REQUEST_LIST} else dict
        maximum_rows = 1 if response.role is _ResponseRole.HOSTED_VERSION_HISTORY else 30 if response.role is _ResponseRole.ACTIVITY_LIST else 2
        if type(body) is not expected or expected is list and len(body) > maximum_rows:
            raise ReadFailure("response-invalid")
        if response.role in {_ResponseRole.PULL_REQUEST_LIST, _ResponseRole.HOSTED_VERSION_HISTORY} and body == []:
            _, present, valid = _single(head.headers, "link")
            if present or not valid:
                # An empty page with any continuation/ambiguous Link cannot
                # become the draft-PR pre-send empty-window observation.
                raise ReadFailure("response-limit")
        return ReadResult({"status": head.status, "body": body, "failure": "none"}, control)
    except _JsonLimit:
        return _failed("response-limit", control)
    except _JsonError:
        return _failed("response-invalid", control)
    except ReadFailure as error:
        return _failed(error.reason, control)


def observe(request: ReadRequest, reader: _Reader, *, observed_at: str) -> dict[str, Any]:
    """Fixed at-most-five-read schedule; the fake seam is not a runtime option."""
    from .api._github_connection import (_account, _automation, _read, _repository, _utc,
                                         project_github_observations)
    from .api._json import bounded_json_text
    from .api.contracts import ApiError
    from .errors import ConfigurationError

    _utc(observed_at)
    unavailable = lambda: {"status": None, "body": None, "failure": "cancelled"}
    values: dict[str, Any] = {
        "repository": request.repository, "observedAt": observed_at,
        "expectedAccountId": request.expected_account_id, "expectedRepositoryId": request.expected_repository_id,
        "account": unavailable(), "repositoryBefore": unavailable(), "workflowPages": [], "repositoryAfter": unavailable(),
    }
    control = _control()

    def take(step: str) -> ReadResult:
        admitted_control: dict[str, Any] | None = None
        try:
            result = reader.read(step)
            if type(result) is not ReadResult:
                raise ValueError("Invalid fixed read result")
            admitted_control = _check_control(result.control)
            _read(result.observation)
            trial = dict(values)
            if step in {"workflows-1", "workflows-2"}:
                trial["workflowPages"] = [*values["workflowPages"], result.observation]
            else:
                trial[{"account": "account", "repository-before": "repositoryBefore",
                       "repository-after": "repositoryAfter"}[step]] = result.observation
            # Stop BEFORE another dependent GET if the combined bodies/envelope
            # exceed bounds, not only when finally encoding the result.
            _check_values(trial, nodes=20_000, depth=24)
            bounded_json_text(trial, max_bytes=MAX_BODY_TOTAL, max_nodes=20_000, max_depth=24)
            return result
        except ReadFailure as error:
            return _failed(error.reason, admitted_control)
        except (_JsonLimit, ConfigurationError):
            return _failed("response-limit", admitted_control)
        except (ValueError, TypeError, UnicodeError, OverflowError):
            return _failed("response-invalid", admitted_control)

    def finish() -> dict[str, Any]:
        nonlocal control
        try:
            # Account for ALL supplied bodies plus keys/wrappers before the
            # unchanged projector. Per-response admission alone is insufficient.
            _check_values(values, nodes=20_000, depth=24)
            bounded_json_text(values, max_bytes=MAX_BODY_TOTAL, max_nodes=20_000, max_depth=24)
        except (_JsonError, ConfigurationError, ValueError, TypeError, UnicodeError, OverflowError):
            control = _refuse(control, "response-limit")
            reduced = {**values, "account": {"status": None, "body": None, "failure": "response-limit"},
                       "repositoryBefore": unavailable(), "workflowPages": [], "repositoryAfter": unavailable()}
            facts = project_github_observations(reduced)
        else:
            try:
                facts = project_github_observations(values)
            except ApiError:
                control = _refuse(control, "response-invalid")
                reduced = {**values, "account": {"status": None, "body": None, "failure": "response-invalid"},
                           "repositoryBefore": unavailable(), "workflowPages": [], "repositoryAfter": unavailable()}
                facts = project_github_observations(reduced)
        if control["reason"] == "none":
            for name in ("account", "repository", "automation"):
                if facts[name]["state"] != "observed":
                    control = _refuse(control, facts[name]["reason"])
                    break
        return {"facts": facts, "control": control}

    account = take("account")
    values["account"], control = account.observation, account.control
    body, _ = _read(account.observation)
    if body is None:
        return finish()
    try:
        identity = _account(body)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        values["account"] = _failed("response-invalid").observation
        control = _refuse(control, "response-invalid")
        return finish()
    if request.expected_account_id is not None and identity["id"] != request.expected_account_id:
        control = _refuse(control, "target-changed")
        return finish()
    if control["reason"] != "none":
        return finish()

    before = take("repository-before")
    values["repositoryBefore"], control = before.observation, before.control
    body, _ = _read(before.observation)
    if body is None:
        return finish()
    try:
        initial = _repository(body)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        values["repositoryBefore"] = _failed("response-invalid").observation
        control = _refuse(control, "response-invalid")
        return finish()
    if (initial["fullName"].lower() != request.repository.lower()
            or request.expected_repository_id is not None and initial["id"] != request.expected_repository_id):
        control = _refuse(control, "target-changed")
        return finish()
    if control["reason"] != "none":
        return finish()

    for step in ("workflows-1", "workflows-2"):
        page = take(step)
        values["workflowPages"].append(page.observation)
        control = page.control
        body, _ = _read(page.observation)
        if body is not None:
            try:
                # Reuse the existing page/row validator, including ambiguous
                # listings. This is NOT a made-up repository identity bracket.
                _automation([_read(item) for item in values["workflowPages"]], observed_at)
            except (ValueError, TypeError, UnicodeError, OverflowError):
                values["workflowPages"][-1] = _failed("response-invalid").observation
                control = _refuse(control, "response-invalid")
                return finish()
        if control["reason"] in {"unauthorized", "rate-limited", "target-changed", "response-invalid", "expired", "cancelled"}:
            return finish()
        if body is None:
            code = page.observation["status"]
            # Ordinary listing 403/404/5xx may still bracket the target. A
            # transport refusal, limit or authorization failure never does.
            if code not in {403, 404} and not (type(code) is int and 500 <= code <= 599):
                return finish()
            break
        if step == "workflows-2" or len(body["workflows"]) != 100 or body["total_count"] <= 100:
            break

    listing_control = control
    after = take("repository-after")
    values["repositoryAfter"] = after.observation
    control = after.control if after.control["reason"] != "none" else listing_control
    body, _ = _read(after.observation)
    if body is not None:
        try:
            ending = _repository(body)
        except (ValueError, TypeError, UnicodeError, OverflowError):
            values["repositoryAfter"] = _failed("response-invalid").observation
            control = _refuse(control, "response-invalid")
        else:
            if (ending["fullName"].lower() != request.repository.lower() or ending["id"] != initial["id"]
                    or request.expected_repository_id is not None and ending["id"] != request.expected_repository_id):
                control = _refuse(control, "target-changed")
    return finish()


def _fixed_ca(runtime_dir: str, budget: _Budget, *, _failure=None) -> str:
    # This is a fixed sibling input, not a discovery/API/file-picker interface.
    # Byte/identity checks are defense in depth, NOT immutable runtime custody.
    import os
    import stat

    if type(runtime_dir) is not str or not os.path.isabs(runtime_dir):
        raise ValueError("Fixed GitHub trust is unavailable")
    path = os.path.join(runtime_dir, "github-ca.pem")
    budget.remaining()
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= MAX_CA_BYTES:
        raise ValueError("Fixed GitHub trust is unavailable")
    owned = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.set_inheritable(owned, False)
        state = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                               value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if state(os.fstat(owned)) != state(before):
            raise ValueError("Fixed GitHub trust is unavailable")
        chunks: list[bytes] = []
        size = 0
        while size <= before.st_size:
            budget.remaining()
            block = os.read(owned, min(_READ_CHUNK, before.st_size + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
        if (size != before.st_size or state(os.fstat(owned)) != state(before)
                or state(os.lstat(path)) != state(before)):
            raise ValueError("Fixed GitHub trust is unavailable")
        return b"".join(chunks).decode("ascii", errors="strict")
    except BaseException:
        if _failure is not None:
            _failure("cleanup-unknown")  # SAME Entry, before the sole input close.
        raise
    finally:
        retired, owned = owned, -1
        os.close(retired)  # Sole close; failure cannot be reported as success.


def _wrap_fixed_tls(context: Any, source: Any, *, ignore_eof_option: int,
                    _git_remote_role: _ResponseRole | None = None) -> Any:
    """One fixed documented wrap, with no suppressed unexpected TLS EOF.

    The live caller supplies the actual SSLContext/option/socket. Inert tests
    supply recording DATA doubles; they cannot establish TLS close integrity.
    An unavailable option API refuses instead of choosing a version's defaults.
    """
    option = int(ignore_eof_option)
    if option <= 0:
        raise ReadFailure("tls-failed")
    context.options = int(context.options) & ~option
    if int(context.options) & option:
        raise ReadFailure("tls-failed")
    fixed_host = "api.github.com"
    if _git_remote_role is not None:
        if type(_git_remote_role) is not _ResponseRole or _git_remote_role not in (_GIT_REMOTE_ROLES | _GIT_PUSH_ROLES):
            raise ValueError("Invalid fixed Git remote TLS role")
        if _git_remote_role in _GIT_PUSH_ROLES:
            from .git_push_transport import host
        else:
            from .git_remote_transport import host
        fixed_host = host(_git_remote_role.value)
    return context.wrap_socket(source, server_hostname=fixed_host, suppress_ragged_eofs=False)


def _make_live_exchange(token: str, *, started: float, runtime_dir: str, api_version: str,
                        _profile: _ExchangeProfile = _ExchangeProfile.STANDARD,
                        _setup_budget: _Budget | None = None,
                        _git_remote_login: str | None = None,
                        _git_remote_current: Callable[[], None] | None = None,
                        _git_remote_failure: Callable[[str], None] | None = None,
                        _git_remote_control: Callable[[dict[str, Any]], None] | None = None,
                        _hosted_ca_sha256: str | None = None) -> Callable[..., ReadResult]:
    """Private bounded TLS/framing shared by two closed native action profiles.

    This is not a renderer/API URL interface. The calling profile separately
    claims each fixed endpoint once; this layer cannot grant or retry an action.
    """
    if (api_version not in {"2022-11-28", "2026-03-10"} or type(token) is not str
            or not 1 <= len(token) <= 4096 or any(not 0x21 <= ord(c) <= 0x7e for c in token)):
        raise ValueError("Invalid fixed GitHub transport input")
    _role_limits(_profile, _ResponseRole.STANDARD)
    if _profile is _ExchangeProfile.HOSTED_VERSION:
        if type(_hosted_ca_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", _hosted_ca_sha256) is None:
            raise ValueError("Pinned hosted GitHub trust is unavailable")
    elif _hosted_ca_sha256 is not None:
        raise ValueError("Hosted trust belongs to another profile")
    if _profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH, _ExchangeProfile.SETUP, _ExchangeProfile.HOSTED_VERSION, _ExchangeProfile.PUBLICATION, _ExchangeProfile.VERSION_ALLOCATION, _ExchangeProfile.VERSION_ENROLLMENT, _ExchangeProfile.REPOSITORY_CREATE, _ExchangeProfile.ACTIVITY, _ExchangeProfile.PULL_REQUEST, _ExchangeProfile.ACTIONS_RETRY, _ExchangeProfile.PLAY_CLEANUP} and api_version != "2026-03-10":
        raise ValueError("Fixed Setup API version differs")
    if _profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH}:
        from .git_remote_transport import _LOGIN
        if (_setup_budget is None or type(_git_remote_login) is not str
                or _LOGIN.fullmatch(_git_remote_login) is None or not callable(_git_remote_current)
                or not callable(_git_remote_failure) or not callable(_git_remote_control)):
            raise ValueError("Original Git remote clock/account is unavailable")
        _git_remote_current()
    elif _git_remote_login is not None or _git_remote_current is not None or _git_remote_failure is not None or _git_remote_control is not None:
        raise ValueError("Git remote inputs belong to another action")
    if _setup_budget is not None:
        if (type(_setup_budget) is not _Budget or _profile not in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH, _ExchangeProfile.SETUP, _ExchangeProfile.PUBLICATION, _ExchangeProfile.REPOSITORY_CREATE, _ExchangeProfile.ACTIVITY, _ExchangeProfile.PULL_REQUEST, _ExchangeProfile.ACTIONS_RETRY, _ExchangeProfile.PLAY_CLEANUP}
                or _setup_budget.profile is not _profile
                or _setup_budget.started != started
                or (_profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH} and not started < _setup_budget.end <= started + 45.0
                    or _profile not in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH} and _setup_budget.end != started + (60.0 if _profile in {_ExchangeProfile.PUBLICATION, _ExchangeProfile.REPOSITORY_CREATE, _ExchangeProfile.ACTIVITY, _ExchangeProfile.PULL_REQUEST, _ExchangeProfile.ACTIONS_RETRY, _ExchangeProfile.PLAY_CLEANUP} else READ_SECONDS))
                or getattr(_setup_budget, "_secret_exchange_claimed", False)):
            raise ValueError("Invalid same-original Setup budget")
        _setup_budget._secret_exchange_claimed = True
    # http.client itself imports ssl. Both must stay inside this original live
    # entry, not at pure frame/schedule import or fixture construction time.
    import http.client
    import ssl
    import sys

    # SAME instance and absolute endpoint; optional owner was claimed once
    # before even the lazy network module imports above.
    budget = _Budget(started, _profile=_profile) if _setup_budget is None else _setup_budget
    budget.remaining()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.keylog_filename = None
    context.set_alpn_protocols(["http/1.1"])
    fixed_ca = (_fixed_ca(runtime_dir, budget, _failure=_git_remote_failure)
        if _profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH} else _fixed_ca(runtime_dir, budget))
    if _profile is _ExchangeProfile.HOSTED_VERSION:
        import hashlib
        if hashlib.sha256(fixed_ca.encode("ascii")).hexdigest() != _hosted_ca_sha256:
            raise ValueError("Pinned hosted GitHub trust changed")
    context.load_verify_locations(cadata=fixed_ca)
    # Never create_default_context/load_default_certs/default_verify_paths;
    # never urllib, proxies, netrc, environment credentials or workflow clients.

    def exchange(method: str, path: str, body: bytes | None = None, *,
                 _role: _ResponseRole = _ResponseRole.STANDARD, _remote_delivery=None,
                 _push_body=None, _push_delivery=None) -> ReadResult:
        _, path_limit = _request_limits(_profile, _role, method, path)
        fixed_host = "api.github.com"
        if _profile is _ExchangeProfile.GIT_PUSH:
            from .git_push_transport import _Delivery, host, private_headers, validate_body
            validate_body(_role.value, body, _push_body)
            fixed_host = host(_role.value)
            if _remote_delivery is not None:
                raise ValueError("Fetch response sink belongs to another action")
            if _role in _GIT_PUSH_BINARY:
                if type(_push_delivery) is not _Delivery:
                    raise ValueError("Original Push response sink is unavailable")
                _push_delivery.claim(_role.value, _push_body)
            elif _push_delivery is not None:
                raise ValueError("Invalid Push response sink role")
        elif _push_body is not None or _push_delivery is not None:
            raise ValueError("Push body/response belongs to another action")
        if _profile is _ExchangeProfile.GIT_REMOTE:
            from .git_remote_transport import _Delivery, host, private_headers, validate_body
            validate_body(_role.value, body)
            fixed_host = host(_role.value)
            if _role in _GIT_REMOTE_BINARY:
                if type(_remote_delivery) is not _Delivery:
                    raise ValueError("Original Git remote response sink is unavailable")
                _remote_delivery.claim(_role.value, body)
            elif _remote_delivery is not None:
                raise ValueError("Invalid Git remote response sink role")
        elif _remote_delivery is not None:
            raise ValueError("Git remote response sink belongs to another action")
        if _profile is _ExchangeProfile.HOSTED_VERSION:
            from .version_hosted import validate_body
            validate_body(_role.value, body, path=path)
        if _profile is _ExchangeProfile.SETUP:
            _setup_body(_profile, _role, body, path=path)
        elif _profile is _ExchangeProfile.VERSION_ALLOCATION:
            _allocation_body(_profile, _role, body, path=path)
        elif _profile is _ExchangeProfile.PLAY_CLEANUP:
            from ._github_play_cleanup_transport import validate_body
            validate_body(_role, body)
        elif _profile is _ExchangeProfile.ACTIONS_RETRY:
            from ._github_actions_retry_transport import validate_body
            validate_body(_role, body)
        elif _profile is _ExchangeProfile.PULL_REQUEST:
            from ._github_pull_request_transport import validate_body
            validate_body(_role, body)
        elif _profile is _ExchangeProfile.REPOSITORY_CREATE:
            from ._github_repository_create_transport import validate_body
            validate_body(_role, body)
        elif _profile is _ExchangeProfile.VERSION_ENROLLMENT:
            from .version_enrollment import validate_body
            validate_body(_role.value, body, path=path)
        methods = {"GET", "PUT"} if _profile in {_ExchangeProfile.HOSTED_VERSION, _ExchangeProfile.SETUP, _ExchangeProfile.VERSION_ALLOCATION} else {"GET", "POST"}
        if _profile in {_ExchangeProfile.VERSION_ENROLLMENT, _ExchangeProfile.ACTIVITY}:
            methods = {"GET"}
        if _profile is _ExchangeProfile.SETUP and _role in _VARIABLE_ROLES:
            methods = {"GET", "POST", "PATCH"}  # Exact method/path was already checked above.
        if (method not in methods or type(path) is not str or not path.startswith("/")
                or len(path) > path_limit or any(not 0x21 <= ord(c) <= 0x7e for c in path)
                or "#" in path or "\\" in path
                or method == "GET" and body is not None
                or method == "POST" and _profile not in {_ExchangeProfile.SETUP, _ExchangeProfile.GIT_PUSH}
                and (type(body) is not bytes or not 1 <= len(body) <= (64 * 1024 if _profile is _ExchangeProfile.GIT_REMOTE else 384 * 1024 if _profile is _ExchangeProfile.PUBLICATION else 32 * 1024 if _profile is _ExchangeProfile.PULL_REQUEST else 2048))):
            raise ValueError("Invalid fixed GitHub transport request")
        budget.claim_request()  # Before any native/socket send, including a failed one.
        original_response: list[Any] = [None]
        close_failed = [False]
        original_socket: list[Any] = [None]
        observing = [False]
        control_observing = [False]

        def observe_failure(reason: str) -> None:
            # GitRemote alone carries the SAME Entry's first-F recorder. A
            # callback cannot replace cleanup or prevent a claimed close.
            if _profile not in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH}:
                return
            if observing[0]:
                close_failed[0] = True
                return
            observing[0] = True
            try:
                _git_remote_failure(reason)
            except BaseException:
                close_failed[0] = True
            finally:
                observing[0] = False

        def observe_control(control: dict[str, Any] | None) -> None:
            # Same private owner, before any original response/socket close.
            # Unknown closure cannot erase a known cooldown/credential refusal.
            if _profile not in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH} or control is None:
                return
            if control_observing[0]:
                close_failed[0] = True
                observe_failure("cleanup-unknown")
                return
            control_observing[0] = True
            try:
                _git_remote_control(dict(_check_control(control)))
            except BaseException:
                close_failed[0] = True
                observe_failure("cleanup-unknown")
            finally:
                control_observing[0] = False

        def observe_exception(error: BaseException) -> None:
            if isinstance(error, ReadFailure):
                reason = error.reason
            elif isinstance(error, ssl.SSLError):
                reason = "tls-failed"
            elif isinstance(error, http.client.HTTPException):
                reason = "response-invalid"
            elif isinstance(error, OSError):
                reason = "network-unavailable"
            elif _profile is _ExchangeProfile.GIT_PUSH:
                from .git_push_transport import failure_reason
                reason = failure_reason(error)
            elif _profile is _ExchangeProfile.GIT_REMOTE:
                from .git_remote_transport import failure_reason
                reason = failure_reason(error)
            else:
                return
            observe_failure(reason)

        def timeout(remaining: float) -> None:
            if _profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH}:
                _git_remote_current()
            if original_socket[0] is None:
                raise ReadFailure("network-unavailable")
            original_socket[0].settimeout(remaining)

        def prior_control() -> dict[str, Any] | None:
            response = original_response[0]
            bounded = getattr(response, "bounded", None)
            return None if bounded is None else bounded.control

        class FixedResponse(http.client.HTTPResponse):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self._close_claimed = False
                original_response[0] = self
                super().__init__(*args, **kwargs)

            def begin(self) -> None:
                if self.headers is not None:
                    return
                try:
                    self.bounded = _ResponseBody(self.fp, budget, before_read=timeout, _role=_role)
                    if _profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH}:
                        self.bounded.control = _header_control(self.bounded.head, budget, _role=_role)
                        observe_control(self.bounded.control)
                        if self.bounded.control["reason"] != "none":
                            observe_failure(self.bounded.control["reason"])
                except BaseException as error:
                    observe_exception(error)
                    raise
                head = self.bounded.head
                self.code = self.status = head.status
                self.reason = ""  # Raw upstream reason phrases are discarded.
                self.version = head.version
                self.headers = self.msg = http.client.HTTPMessage()
                for name, values in head.headers.items():
                    for value in values:
                        if value is not None:
                            self.headers[name] = value
                self.chunked = head.framing == "chunked"
                self.chunk_left = None
                self.length = head.length
                self.will_close = head.framing == "eof" or self._check_close()

            def read(self, amt: int | None = None) -> bytes:
                try:
                    return self.bounded.read(amt)
                except BaseException as error:
                    observe_exception(error)
                    raise

            def close(self) -> None:
                if self._close_claimed:
                    return
                self._close_claimed = True  # Includes stdlib failure closes.
                observe_control(prior_control())
                active = sys.exception()
                if active is not None:
                    observe_exception(active)
                try:
                    super().close()
                except BaseException:
                    close_failed[0] = True
                    observe_failure("cleanup-unknown")
                    raise

        class FixedConnection(http.client.HTTPSConnection):
            def __init__(self) -> None:
                self._close_claimed = False
                super().__init__(fixed_host, 443, timeout=budget.remaining(), context=context)
                self.response_class = FixedResponse
                self.set_debuglevel(0)

            def connect(self) -> None:
                # HTTPSConnection's default wrap suppresses ragged EOF.
                # Use the ordinary base TCP connect, then one explicit TLS
                # wrap. No tunnel/host override or second owner is added.
                if _profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH}:
                    _git_remote_current()
                http.client.HTTPConnection.connect(self)
                self.sock.settimeout(budget.remaining())
                self.sock = _wrap_fixed_tls(context, self.sock,
                                           ignore_eof_option=getattr(ssl, "OP_IGNORE_UNEXPECTED_EOF", 0),
                                           _git_remote_role=_role if _profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH} else None)

            def close(self) -> None:
                if self._close_claimed:
                    return
                self._close_claimed = True
                observe_control(prior_control())
                active = sys.exception()
                if active is not None:
                    observe_exception(active)
                try:
                    super().close()
                except BaseException:
                    close_failed[0] = True
                    observe_failure("cleanup-unknown")
                    raise

        connection: Any = None
        result = None
        try:
            connection = FixedConnection()
            connection.connect()
            original_socket[0] = connection.sock
            timeout(budget.remaining())
            connection.auto_open = 0  # No implicit reconnect after our connect.
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            headers = private_headers(_role.value, token, _git_remote_login, api_version) if _profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH} else (
                ("Host", "api.github.com"), ("User-Agent", "MobileReleaseKit-Desktop/0.3.0"),
                ("Accept", "application/vnd.github+json"), ("X-GitHub-Api-Version", api_version),
                ("Accept-Encoding", "identity"), ("Connection", "close"),
                ("Authorization", "Bearer " + token),
            )
            for name, value in headers:
                connection.putheader(name, value)
            timeout(budget.remaining())
            if _push_body is not None:
                # Exact concrete original body, already consumed for this
                # single send. No file-like/generic iterable body is enabled.
                connection.putheader("Content-Type", "application/x-git-receive-pack-request")
                connection.putheader("Content-Length", str(_push_body.digest.body_bytes))
                connection.endheaders()
                _push_body.send(connection.send, lambda: timeout(budget.remaining()))
            else:
                if body is not None:
                    connection.putheader("Content-Type", "application/x-git-upload-pack-request" if _role in _GIT_REMOTE_BINARY else "application/json")
                    connection.putheader("Content-Length", str(len(body)))
                connection.endheaders(body)
            timeout(budget.remaining())
            response = connection.getresponse()
            result = _response_result(response.bounded, budget, _remote_delivery=_remote_delivery,
                _remote_failure=observe_failure if _profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH} else None,
                _push_delivery=_push_delivery)
            if _profile in {_ExchangeProfile.GIT_REMOTE, _ExchangeProfile.GIT_PUSH}:
                reason = result.control["reason"]
                if reason == "none":
                    reason = result.observation["failure"]
                if reason != "none":
                    observe_failure(reason)  # Converted failure, before finally.
        except ReadFailure as error:
            observe_failure(error.reason)
            result = _failed(error.reason, prior_control())
        except ssl.SSLError:
            observe_failure("tls-failed")
            result = _failed("tls-failed", prior_control())
        except http.client.HTTPException:
            observe_failure("response-invalid")
            result = _failed("response-invalid", prior_control())
        except OSError:
            observe_failure("network-unavailable")
            result = _failed("network-unavailable", prior_control())
        except BaseException as error:
            observe_exception(error)
            raise
        finally:
            observe_control(result.control if result is not None else prior_control())
            # Each original response/connection has one synchronous close
            # claim, even if stdlib already closed it on its own failure path.
            # No retry, scan, replacement joiner or cleanup timeout is added.
            for original in (original_response[0], connection):
                if original is not None:
                    try:
                        original.close()
                    except BaseException:
                        close_failed[0] = True
                        observe_failure("cleanup-unknown")
            if close_failed[0]:
                raise _CloseFailure("Original GitHub close did not return") from None
        return result

    return exchange


def _make_live_reader(request: ReadRequest, *, started: float, runtime_dir: str) -> _Reader:
    """Unchanged at-most-five-GET Connect/Refresh profile, never a POST grant."""
    exchange = _make_live_exchange(request.token, started=started, runtime_dir=runtime_dir,
                                   api_version="2022-11-28")

    class FixedReader:
        def __init__(self) -> None:
            self.steps: list[str] = []

        def read(self, step: str) -> ReadResult:
            expected = ("account" if not self.steps else "repository-before" if self.steps == ["account"]
                        else "workflows-1" if self.steps == ["account", "repository-before"] else None)
            if expected is not None:
                valid = step == expected
            elif self.steps == ["account", "repository-before", "workflows-1"]:
                valid = step in {"workflows-2", "repository-after"}
            else:
                valid = self.steps == ["account", "repository-before", "workflows-1", "workflows-2"] and step == "repository-after"
            if not valid or len(self.steps) >= 5:
                raise ValueError("Invalid fixed GitHub schedule")
            self.steps.append(step)  # Never retry a claimed logical read.
            prefix = "/repos/" + request.repository
            path = ("/user" if step == "account" else prefix if step in {"repository-before", "repository-after"}
                    else prefix + "/actions/workflows?per_page=100&page=" + ("1" if step == "workflows-1" else "2"))
            return exchange("GET", path, None)

    return FixedReader()
