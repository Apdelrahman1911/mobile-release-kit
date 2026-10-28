"""Closed private GitRead DATA frames, never a tool/project admission.

Only the original installed native owner supplies the source snapshots and
clock endpoints. There is no renderer path, argv, environment, remote request,
write action or interchangeable saved-command domain in this protocol.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Any

from .errors import ValidationError
from . import git_service as core
from . import git_repository_read as read

PROTOCOL = "mrk-git-read/1"
WORK_SECONDS, FINALITY_SECONDS = 45, 55
COMMAND_SECONDS = 10
REQUEST_LIMIT, READY_LIMIT, RESPONSE_LIMIT = 96 * 1024, 512, 2 * 1024 * 1024
TOOL_LIMIT = 128 * 1024 * 1024
TOOL_PATH = Path("/Library/Developer/CommandLineTools/usr/bin/git")
STATUSES = ("ok", "refused", "cancelled", "timed-out", "cleanup-unknown")
REASONS = core._REASONS
_ERROR = "The original read-only Git request or result was refused."


class ProtocolError(ValidationError):
    pass


def require(condition: bool) -> None:
    if not condition:
        raise ProtocolError(_ERROR)


def _keys(value: Any, names: tuple[str, ...]) -> dict[str, Any]:
    require(type(value) is dict and set(value) == set(names))
    return value


def _text(value: Any, limit: int) -> str:
    require(type(value) is str)
    try:
        require(0 < len(value.encode("utf-8")) <= limit
                and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    except UnicodeError:
        raise ProtocolError(_ERROR) from None
    return value


def _id(value: Any) -> str:
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", _text(value, 64)) is not None)
    return value


def _hex(value: Any) -> str:
    require(type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None)
    return value


def _integer(value: Any, low: int, high: int) -> int:
    require(type(value) is int and low <= value <= high)
    return value


def _path(value: Any) -> Path:
    _text(value, 4096)
    require(value.startswith("/") and value != "/" and "\\" not in value
            and all(0 < len(p.encode("utf-8")) <= 255 and p not in (".", "..", ".git")
                    for p in value[1:].split("/")))
    return Path(value)


def _pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result)
        result[key] = value
    return result


def _decode(raw: bytes, limit: int) -> dict[str, Any]:
    require(type(raw) is bytes and 0 < len(raw) <= limit and raw.endswith(b"\n") and raw.count(b"\n") == 1)
    try:
        def reject(_):
            require(False)
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=reject, parse_float=reject)
        pending, nodes = [(value, 0)], 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            require(nodes <= 8192 and depth <= 8)
            if type(item) is dict:
                pending.extend((v, depth + 1) for v in item.values())
            elif type(item) is list:
                pending.extend((v, depth + 1) for v in item)
        require(type(value) is dict)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ProtocolError(_ERROR) from None


def _encode(value: dict[str, Any], limit: int) -> bytes:
    try:
        raw = (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                          separators=(",", ":")) + "\n").encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ProtocolError(_ERROR) from None
    require(len(raw) <= limit and raw.count(b"\n") == 1)
    return raw


@dataclass(frozen=True, slots=True, repr=False)
class Action:
    kind: str
    expected_revision: str | None
    paths: tuple[str, ...]
    staged: bool

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "expectedRevision": self.expected_revision,
                "paths": list(self.paths), "staged": self.staged}


def action(value: Any) -> Action:
    row = _keys(value, ("kind", "expectedRevision", "paths", "staged"))
    require(type(row["kind"]) is str and row["kind"] in ("observe", "diff", "history", "branches")
            and type(row["staged"]) is bool and type(row["paths"]) is list)
    revision = row["expectedRevision"]
    require(revision is None if row["kind"] == "observe" else type(revision) is str)
    if revision is not None:
        _hex(revision)
    paths = ()
    if row["kind"] == "diff":
        try:
            paths = core._paths(row["paths"])
            require(list(paths) == row["paths"] and all(len(path.split("/")) <= read.MAX_REF_DEPTH for path in paths))
        except (core.GitError, UnicodeError):
            raise ProtocolError(_ERROR) from None
    else:
        require(row["paths"] == [] and row["staged"] is False)
    return Action(row["kind"], revision, paths, row["staged"])


def identity(value) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def directory_identity(value) -> tuple[int, ...]:
    return identity(value)[:5]


def _directory(value: Any, uid: int) -> tuple[int, ...]:
    require(type(value) is list and len(value) == 5)
    result = tuple(_integer(v, 0, (1 << 64) - 1) for v in value)
    require(result[0] > 0 and result[1] > 0 and stat.S_ISDIR(result[2]) and result[3] == uid
            and not result[2] & 0o7022)
    return result


@dataclass(frozen=True, slots=True, repr=False)
class FileSnapshot:
    path: Path
    identity: tuple[int, ...]
    sha256: str


def _snapshot(path: Path, value: Any, uid: int, maximum: int, *, executable=False) -> FileSnapshot:
    row = _keys(value, ("identity", "sha256"))
    fields = row["identity"]
    require(type(fields) is list and len(fields) == 9)
    result = tuple(_integer(v, 0 if i < 7 else -(1 << 63), (1 << (64 if i < 7 else 63)) - 1)
                   for i, v in enumerate(fields))
    require(result[0] > 0 and result[1] > 0 and stat.S_ISREG(result[2]) and result[3] == uid
            and result[5] == 1 and 0 <= result[6] <= maximum and not result[2] & 0o7022)
    if executable:
        require(result[2] & 0o111 != 0 and result[6] > 0)
    return FileSnapshot(path, result, _hex(row["sha256"]))


@dataclass(frozen=True, slots=True, repr=False)
class Request:
    id: str
    action: Action
    project_id: str
    generation: int
    revision: str
    uid: int
    gid: int
    root: Path
    directories: tuple[tuple[Path, tuple[int, ...]], ...]
    tool: FileSnapshot
    files: tuple[FileSnapshot, ...]
    index_absent: bool
    work_end_ns: int
    hard_end_ns: int
    digest: str


def parse_request(raw: bytes) -> Request:
    row = _keys(_decode(raw, REQUEST_LIMIT), ("protocol", "id", "action", "context", "native", "clock"))
    require(row["protocol"] == PROTOCOL)
    context = _keys(row["context"], ("projectId", "generation", "revision"))
    native = _keys(row["native"], ("uid", "gid", "root", "directories", "tool", "files"))
    uid, gid = _integer(native["uid"], 1, (1 << 32) - 1), _integer(native["gid"], 0, (1 << 32) - 1)
    root = _path(native["root"])
    directories = _keys(native["directories"], ("root", "git", "objects"))
    directories = tuple((root / relative, _directory(directories[name], uid))
                        for name, relative in (("root", ""), ("git", ".git"), ("objects", ".git/objects")))
    tool = _snapshot(TOOL_PATH, native["tool"], 0, TOOL_LIMIT, executable=True)
    files = _keys(native["files"], ("HEAD", "config", "index"))
    snapshots = tuple(_snapshot(root / ".git" / name, files[name], uid, limit)
                      for name, limit in (("HEAD", 2048), ("config", 65536), ("index", core.MAX_INDEX_BYTES))
                      if name != "index" or files[name] is not None)
    require(snapshots[0].identity[6] > 0)
    clock = _keys(row["clock"], ("workEndNs", "hardEndNs"))
    work, hard = (_integer(clock[name], 1, (1 << 63) - 1) for name in ("workEndNs", "hardEndNs"))
    require(hard - work == (FINALITY_SECONDS - WORK_SECONDS) * 1_000_000_000)
    return Request(_id(row["id"]), action(row["action"]), _id(context["projectId"]),
                   _integer(context["generation"], 0, (1 << 32) - 1), _id(context["revision"]),
                   uid, gid, root, directories, tool, snapshots, files["index"] is None,
                   work, hard, hashlib.sha256(raw).hexdigest())


def ready(request: Request) -> bytes:
    return _encode({"protocol": PROTOCOL, "id": request.id, "digest": request.digest}, READY_LIMIT)


def go(request: Request) -> bytes:
    return b"MRK-GIT-READ-GO/1 " + request.digest.encode("ascii") + b"\n"


COMMAND_FAILURE_REASONS = (
    "incomplete-output", "original-deadline", "output-bound", "protocol-or-ownership",
    "command-failed-or-incomplete", "cleanup-unconfirmed", "exec-rejected",
    "stopped-before-exec", "parent-ended", "observer-ended", "fence-collision", "unknown",
)
COMMAND_FAILURE_KINDS = ("configuration", "version", "revision", "index", "status", "symbolic-ref", "references", "diff", "walk", "unknown")


def command_failure(value: dict) -> dict:
    """Closed first-command error DATA; no output, command inputs or authority."""
    require(type(value) is dict and set(value) == {
        "category", "reason", "command", "ordinal", "dispatched", "contained",
        "cleanupComplete", "failureMask", "ownerFinality",
    })
    require(type(value["category"]) is str and value["category"] in (
        "process", "process-cleanup", "process-outcome-unknown")
        and type(value["reason"]) is str and value["reason"] in COMMAND_FAILURE_REASONS
        and type(value["command"]) is str and value["command"] in COMMAND_FAILURE_KINDS)
    _integer(value["ordinal"], 1, core.MAX_CALLS)
    require(all(value[key] is None or type(value[key]) is bool
                for key in ("dispatched", "contained", "cleanupComplete")))
    mask = value["failureMask"]
    require(mask is None or type(mask) is int and (mask == 32 or 48 <= mask <= 63))
    observed = value["ownerFinality"]
    require(observed is None or type(observed) is list and len(observed) == 5
            and all(type(n) is int for n in observed[:4]) and observed[0] == 1
            and observed[1] in (0, 1) and 0 <= observed[2] <= (1023 if observed[1] == 0 else 1048575)
            and 0 <= observed[3] <= 15 and (observed[4] is None or type(observed[4]) is int
            and observed[1] == 1 and (observed[4] in (0, 32) or 48 <= observed[4] <= 63)))
    return value


def terminal(request: Request, status: str, *, reason: str | None, result=None,
             first_failure_ns: int | None, cleanup_end_ns: int, command_failure_data=None) -> bytes:
    require(type(request) is Request and status in STATUSES and (reason is None or reason in REASONS))
    _integer(cleanup_end_ns, 1, request.hard_end_ns)
    if first_failure_ns is not None:
        _integer(first_failure_ns, 1, cleanup_end_ns)
        require(cleanup_end_ns - first_failure_ns <= 10_000_000_000)
    if status == "ok":
        from .git_repository_branches import Branches
        expected_type = {"observe": read.ReadObservation, "diff": core.Diff, "history": read.History,
                         "branches": Branches}[request.action.kind]
        require(type(result) is expected_type and reason is None and first_failure_ns is None
                and cleanup_end_ns == request.hard_end_ns)
        if request.action.kind != "observe":
            require(result.revision == request.action.expected_revision)
        if request.action.kind == "diff":
            require(result.paths == request.action.paths and result.staged is request.action.staged)
        result = result.as_dict()
    else:
        require(result is None and reason is not None and (first_failure_ns is not None or status == "cleanup-unknown"))
    row = {"protocol": PROTOCOL, "id": request.id, "digest": request.digest,
                    "action": request.action.kind, "status": status, "reason": reason, "result": result,
                    "firstFailureNs": first_failure_ns, "cleanupEndNs": cleanup_end_ns}
    if command_failure_data is not None:
        require(status == "refused" and reason == "command-failed")
        row["commandFailure"] = command_failure(command_failure_data)
    return _encode(row, RESPONSE_LIMIT - READY_LIMIT)
