"""Closed source-only allocation input DATA, not native or Git authority.

No credential, state path, caller command or build permission exists here. The
actual Document supplies the registered root and original saved-input binding.
The first native source profile supports only an ordinary selected branch.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import stat
from typing import TYPE_CHECKING

from . import _desktop_version_allocation_protocol as allocation_wire
from . import version_policy as policy
from ._desktop_github_engine import ProtocolError, _ID
from .config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES

if TYPE_CHECKING:
    from ._desktop_version_allocation_source_provider import Provider

PROTOCOL = "mrk-version-allocation-source/1"
REQUEST_LIMIT = 8192
READY_LIMIT = GO_LIMIT = 512
RESPONSE_LIMIT = 2048
WORK_SECONDS = allocation_wire.WORK_SECONDS
FINALITY_SECONDS = allocation_wire.FINALITY_SECONDS
MAX_SOURCE_CALLS = 8
SOURCE_ONLY_CALLS = 7
FIN_REASONS = frozenset({"none", "source-refused", "cancelled"})


def require(condition: bool) -> None:
    if not condition:
        raise ProtocolError("The original version source could not be verified")


def _number(value: object, *, nonzero: bool = False) -> int:
    require(type(value) is str and value.isascii() and value.isdecimal()
            and 1 <= len(value) <= 20 and (value == "0" or not value.startswith("0")))
    number = int(value)
    require(int(nonzero) <= number <= (1 << 64) - 1)
    return number


def _relative(value: object) -> str:
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= 512
            and "\\" not in value and "\0" not in value)
    parts = value.split("/")
    require(len(parts) <= 16 and all(part not in {"", ".", "..", ".git"}
            and len(part.encode("utf-8")) <= 255 for part in parts))
    require(value != "release/mobile-release.json")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class SourceRequest:
    project_id: str
    root: Path
    identity: tuple[int, int, int, int, int]
    configuration_size: int
    configuration_sha256: str
    version_path: str
    version_size: int
    version_sha256: str
    ref: str

    @classmethod
    def parse(cls, value: object) -> SourceRequest:
        row = policy._object(value, {"projectId", "projectRoot", "rootIdentity", "savedConfig", "savedVersion", "ref"})
        project_id = policy._match(row["projectId"], _ID)
        root = row["projectRoot"]
        require(type(root) is str and 0 < len(root.encode("utf-8")) <= 4096 and "\0" not in root
                and "\\" not in root and root.startswith("/") and not root.startswith("//"))
        path = Path(root)
        require(path.is_absolute() and str(path) == root and ".." not in path.parts and 1 < len(path.parts) <= 24)
        identity = policy._object(row["rootIdentity"], {"device", "inode", "mode", "uid", "gid"})
        mode = policy._integer(identity["mode"], (1 << 32) - 1)
        require(stat.S_ISDIR(mode))
        original = (_number(identity["device"]), _number(identity["inode"], nonzero=True), mode,
                    policy._integer(identity["uid"], (1 << 32) - 1), policy._integer(identity["gid"], (1 << 32) - 1))
        config = policy._object(row["savedConfig"], {"bytes", "sha256"})
        version = policy._object(row["savedVersion"], {"source", "bytes", "sha256"})
        ref = policy.source_ref(row["ref"])
        require(ref.startswith("refs/heads/"))  # No inferred tag or detached HEAD support.
        result = cls(project_id, path, original,
            policy._integer(config["bytes"], MAX_CONFIG_BYTES, 1), policy._match(config["sha256"], policy._DIGEST),
            _relative(version["source"]), policy._integer(version["bytes"], MAX_VERSION_BYTES, 1),
            policy._match(version["sha256"], policy._DIGEST), ref)
        require(len(policy.canonical(result.value())) <= REQUEST_LIMIT)
        return result

    def value(self) -> dict:
        device, inode, mode, uid, gid = self.identity
        return {"projectId": self.project_id, "projectRoot": str(self.root),
                "rootIdentity": {"device": str(device), "inode": str(inode), "mode": mode, "uid": uid, "gid": gid},
                "savedConfig": {"bytes": self.configuration_size, "sha256": self.configuration_sha256},
                "savedVersion": {"source": self.version_path, "bytes": self.version_size, "sha256": self.version_sha256},
                "ref": self.ref}

    def matches(self, source: policy.SourceBinding) -> bool:
        return (type(source) is policy.SourceBinding and source.configuration_sha256 == self.configuration_sha256
                and source.version_sha256 == self.version_sha256 and source.ref == self.ref)


@dataclass(frozen=True, slots=True, repr=False)
class Initial:
    id: str
    source: SourceRequest
    provider: Provider
    clock: dict
    digest: str


def parse_initial(raw: bytes) -> Initial:
    from ._desktop_version_allocation_source_provider import Provider
    row = policy._object(allocation_wire.frame(raw, REQUEST_LIMIT, nodes=256, depth=8), {"protocol", "id", "action"})
    require(row["protocol"] == PROTOCOL)
    action = policy._object(row["action"], {"source", "provider", "clock"})
    source = SourceRequest.parse(action["source"])
    return Initial(policy._match(row["id"], _ID), source, Provider.parse(action["provider"], source),
                   allocation_wire._clock(action["clock"]), hashlib.sha256(raw).hexdigest())


def ready_frame(initial: Initial) -> bytes:
    require(type(initial) is Initial)
    return allocation_wire.encoded({"protocol": PROTOCOL, "id": initial.id,
                                   "ready": {"requestSha256": initial.digest}}, READY_LIMIT)


def parse_go(raw: bytes, initial: Initial) -> None:
    row = policy._object(allocation_wire.frame(raw, GO_LIMIT, nodes=32, depth=4), {"protocol", "id", "go"})
    go = policy._object(row["go"], {"requestSha256"})
    require(row["protocol"] == PROTOCOL and row["id"] == initial.id and go["requestSha256"] == initial.digest)


def finish_frame(initial: Initial, source: policy.SourceBinding | None, *, reason: str,
                 commands: int, first_failure_ns: int | None) -> bytes:
    require(type(initial) is Initial and type(reason) is str and reason in FIN_REASONS
            and type(commands) is int and 0 <= commands <= SOURCE_ONLY_CALLS)
    require((source is not None) == (reason == "none"))
    if source is not None:
        require(initial.source.matches(source) and commands == SOURCE_ONLY_CALLS and first_failure_ns is None)
    else:
        require(type(first_failure_ns) is int and 0 < first_failure_ns < int(initial.clock["hardEndNs"]))
    # Only DATA. The sole caller checks its ACTUAL originals before encoding;
    # the parent still needs bootstrap/child/IO/native/management joins.
    return allocation_wire.encoded({"protocol": PROTOCOL, "id": initial.id,
        "finished": {"requestSha256": initial.digest, "source": source.value() if source is not None else None,
            "reason": reason, "firstFailureNs": str(first_failure_ns) if first_failure_ns is not None else None,
            "lifetime": {"originalsClosed": True, "borrowEnded": True, "handlersRestored": True,
                         "commands": commands, "profileCalls": 0}}}, RESPONSE_LIMIT)
