"""Fixed PRIVATE gh-auth frames. Parsed native input is DATA, not admission.

Only the registered original native invocation may provide these paths and
snapshots. They are never a renderer/CLI arbitrary-command or output interface.
The binary terminal is provisional until the original Supervisor settles.
"""
from __future__ import annotations

import hashlib
import json
import re
import stat
import struct
from dataclasses import dataclass
from pathlib import Path

from .errors import ValidationError

PROTOCOL = "mrk-gh-auth/1"
WORK_SECONDS, FINALITY_SECONDS = 20, 30
COMMAND_SECONDS, COMMAND_OUTPUT_LIMIT = 15, 8192
REQUEST_LIMIT, READY_LIMIT, RESPONSE_LIMIT = 32768, 512, 8192
TOKEN_LIMIT, TOOL_LIMIT, CONFIG_LIMIT = 4098, 128 * 1024 * 1024, 64 * 1024
MAGIC = b"MRK-GH-AUTH/1\0"
STATUSES = ("ok", "refused", "cancelled", "timed-out", "cleanup-unknown")


class ProtocolError(ValidationError):
    pass


def require(condition: bool) -> None:
    if not condition:
        raise ProtocolError("The private gh-auth request or result was refused")


def _keys(value, names):
    require(type(value) is dict and set(value) == set(names))
    return value


def _text(value, maximum):
    require(type(value) is str)
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise ProtocolError("The private gh-auth text was refused") from None
    require(0 < size <= maximum and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    return value


def _id(value):
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", _text(value, 64)) is not None)
    return value


def _hex(value):
    require(type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None)
    return value


def _path(value):
    _text(value, 4096)
    require(value.startswith("/") and value != "/" and "\\" not in value
            and all(0 < len(p.encode("utf-8")) <= 255 and p not in (".", "..") for p in value[1:].split("/")))
    return Path(value)


def login(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", value) is not None
            and "--" not in value)
    return value


def _integer(value, low, high):
    require(type(value) is int and low <= value <= high)
    return value


def _pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result)
        result[key] = value
    return result


def _decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= REQUEST_LIMIT and raw.endswith(b"\n") and raw.count(b"\n") == 1)
    try:
        def reject(_):
            require(False)
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=reject, parse_float=reject)
        pending, nodes = [(value, 0)], 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            require(nodes <= 256 and depth <= 6)
            if type(item) is dict:
                pending.extend((v, depth + 1) for v in item.values())
            elif type(item) is list:
                pending.extend((v, depth + 1) for v in item)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ProtocolError("The private gh-auth frame was refused") from None


@dataclass(frozen=True, slots=True, repr=False)
class FileSnapshot:
    path: Path
    identity: tuple[int, ...]
    sha256: str


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _snapshot(path, value, *, maximum, executable=False):
    row = _keys(value, ("identity", "sha256"))
    fields = row["identity"]
    require(type(fields) is list and len(fields) == 9)
    fields = tuple(_integer(v, 0 if i < 7 else -(1 << 63), (1 << (64 if i < 7 else 63)) - 1)
                   for i, v in enumerate(fields))
    require(fields[0] > 0 and fields[1] > 0 and stat.S_ISREG(fields[2]) and fields[5] == 1
            and 0 < fields[6] <= maximum and not fields[2] & 0o7022)
    require(fields[2] & 0o111 != 0 if executable else fields[2] & 0o777 == 0o600)
    return FileSnapshot(path, fields, _hex(row["sha256"]))


@dataclass(frozen=True, slots=True, repr=False)
class Request:
    id: str
    role: str
    login: str
    project_id: str
    repository: str
    generation: int
    revision: str
    uid: int
    gid: int
    home: Path
    config: Path
    tool: FileSnapshot
    files: tuple[FileSnapshot, FileSnapshot]
    work_end_ns: int
    hard_end_ns: int
    digest: str

    def arguments(self) -> tuple[str, ...]:
        if self.role == "version":
            return (str(self.tool.path), "--version")
        require(self.role == "token")
        return (str(self.tool.path), "auth", "token", "--hostname", "github.com", "--user", self.login)

    def environment(self) -> dict[str, str]:
        # Construct, do not inherit. No ambient tokens/routing/debug/loader,
        # enterprise, proxy, pager shell, Git, SSH, editor or extension settings.
        return {"PATH": "/usr/bin:/bin", "HOME": str(self.home), "GH_CONFIG_DIR": str(self.config),
                "LANG": "C", "LC_ALL": "C", "GH_HOST": "github.com", "GH_PAGER": "cat",
                "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1",
                "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1", "NO_COLOR": "1"}


def parse_request(raw: bytes) -> Request:
    row = _keys(_decode(raw), ("protocol", "id", "role", "login", "projectId", "repository", "generation", "revision", "native", "clock"))
    require(row["protocol"] == PROTOCOL and row["role"] in ("version", "token"))
    repository = _text(row["repository"], 201)
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", repository) is not None
            and all(v not in (".", "..") for v in repository.split("/")))
    native = _keys(row["native"], ("uid", "gid", "home", "config", "executable", "tool", "files"))
    uid, gid = _integer(native["uid"], 1, (1 << 32) - 1), _integer(native["gid"], 0, (1 << 32) - 1)
    home, config, executable = (_path(native[key]) for key in ("home", "config", "executable"))
    require(executable.name == "gh" and executable != config and not executable.is_relative_to(config))
    # This first profile supports the actual user's conventional config only;
    # no inherited GH_CONFIG_DIR/XDG fallback or implicit alternate account.
    require(config == home / ".config" / "gh")
    tool = _snapshot(executable, native["tool"], maximum=TOOL_LIMIT, executable=True)
    require(tool.identity[3] in (0, uid))
    files = _keys(native["files"], ("config.yml", "hosts.yml"))
    files = tuple(_snapshot(config / name, files[name], maximum=CONFIG_LIMIT) for name in ("config.yml", "hosts.yml"))
    require(all(f.identity[3] == uid for f in files))
    clock = _keys(row["clock"], ("workEndNs", "hardEndNs"))
    work, hard = (_integer(clock[key], 1, (1 << 63) - 1) for key in ("workEndNs", "hardEndNs"))
    require(hard - work == (FINALITY_SECONDS - WORK_SECONDS) * 1_000_000_000)
    return Request(_id(row["id"]), row["role"], login(row["login"]), _id(row["projectId"]), repository,
                   _integer(row["generation"], 0, (1 << 32) - 1), _id(row["revision"]), uid, gid, home, config,
                   tool, files, work, hard, hashlib.sha256(raw).hexdigest())


def ready(request: Request) -> bytes:
    return (json.dumps({"protocol": PROTOCOL, "id": request.id, "digest": request.digest},
                       sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def go(request: Request) -> bytes:
    return b"MRK-GH-AUTH-GO/1 " + request.digest.encode("ascii") + b"\n"


def terminal(request: Request, status: str, output: bytes = b"") -> bytes:
    require(type(request) is Request and status in STATUSES and type(output) is bytes)
    require((status == "ok" and 0 < len(output) <= (1024 if request.role == "version" else TOKEN_LIMIT))
            or (status != "ok" and output == b""))
    # The token is not JSON/base64/a public DTO. No stderr bytes are forwarded.
    return MAGIC + bytes.fromhex(request.digest) + bytes((STATUSES.index(status),)) + struct.pack(">H", len(output)) + output


def parse_terminal(raw: bytes, request: Request) -> tuple[str, bytes]:
    prefix = len(MAGIC) + 32
    require(type(raw) is bytes and prefix + 3 <= len(raw) <= RESPONSE_LIMIT and raw.startswith(MAGIC)
            and raw[len(MAGIC):prefix] == bytes.fromhex(request.digest) and raw[prefix] < len(STATUSES))
    status, length = STATUSES[raw[prefix]], struct.unpack(">H", raw[prefix + 1:prefix + 3])[0]
    output = raw[prefix + 3:]
    require(length == len(output) and terminal(request, status, output) == raw)
    return status, output
