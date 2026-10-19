"""Closed PRIVATE upload-key transport; parsed data is never native admission.

Only an original GenerateUploadKey SavedCommandOwner may supply the request.
The result is raw binary on its retained stdout, NOT JSON/base64/public frames.
A complete terminal is provisional until that SAME native owner joins every
original process, pipe, reader/writer, runtime and Android tool-lease tail.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import stat
import struct
from dataclasses import dataclass
from pathlib import Path

from .errors import ValidationError

PROTOCOL = "mrk-android-upload-key/1"
WORK_SECONDS, FINALITY_SECONDS = 180, 190
COMMAND_SECONDS = 120
EXPORT_SECONDS = 30
REQUEST_LIMIT = 16 * 1024
COMMAND_OUTPUT_LIMIT = 64 * 1024
JKS_LIMIT, CERTIFICATE_LIMIT = 64 * 1024, 16 * 1024
PRIVATE_BACKING_LIMIT = 96 * 1024
TOOL_LIMIT = 256 * 1024 * 1024
PASSWORD_LENGTH = 64
READY_MAGIC = b"MRK-UK-READY/1\0"
GO_MAGIC = b"MRK-UK-GO/1\0"
END_MAGIC = b"MRK-UK-END/1\0"
READY_LENGTH = len(READY_MAGIC) + 32 + 32 + 32
GO_LENGTH = len(GO_MAGIC) + 32 + 2 * PASSWORD_LENGTH
END_HEADER_LENGTH = len(END_MAGIC) + 32 + 32 + 1 + 4 + 4
RESPONSE_LIMIT = READY_LENGTH + END_HEADER_LENGTH + JKS_LIMIT + CERTIFICATE_LIMIT
STATUSES = ("ok", "refused", "cancelled", "timed-out", "cleanup-unknown")
STORE_PASSWORD_ENV = "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD"
KEY_PASSWORD_ENV = "MOBILE_RELEASE_ANDROID_KEY_PASSWORD"
ALIAS = "upload"


class ProtocolError(ValidationError):
    pass


def require(condition: bool) -> None:
    if not condition:
        raise ProtocolError("The private upload-key operation was refused")


def _id(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value) is not None
            and value != "0" * 32)
    return value


def _sha(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None)
    return value


def _keys(value, names):
    require(type(value) is dict and set(value) == set(names))
    return value


def _integer(value, low, high):
    require(type(value) is int and low <= value <= high)
    return value


def _path(value):
    require(type(value) is str)
    try:
        require(0 < len(value.encode("utf-8")) <= 4096 and value.startswith("/")
                and "\\" not in value and not any(ord(c) < 32 or ord(c) == 127 for c in value)
                and all(p not in ("", ".", "..") and len(p.encode("utf-8")) <= 255
                        for p in value[1:].split("/")))
    except UnicodeError:
        raise ProtocolError("The private upload-key source was refused") from None
    return Path(value)


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def _decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= REQUEST_LIMIT
            and raw.endswith(b"\n") and raw.count(b"\n") == 1)
    try:
        def reject(_):
            require(False)
        value = json.loads(raw, object_pairs_hook=_pairs, parse_float=reject, parse_constant=reject)
        stack, count = [(value, 0)], 0
        while stack:
            item, depth = stack.pop()
            count += 1
            require(depth <= 4 and count <= 128)
            if type(item) is dict:
                stack.extend((v, depth + 1) for v in item.values())
            elif type(item) is list:
                stack.extend((v, depth + 1) for v in item)
        return value
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise ProtocolError("The private upload-key request was refused") from None


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


@dataclass(frozen=True, slots=True, repr=False)
class FileSnapshot:
    path: Path
    identity: tuple[int, ...]
    sha256: str


@dataclass(frozen=True, slots=True, repr=False)
class SavedProject:
    root: Path
    root_identity: tuple[int, ...]
    config_bytes: int
    config_sha256: str
    draft_sha256: str
    app_identity_sha256: str


@dataclass(frozen=True, slots=True, repr=False)
class Request:
    id: str
    generation: str
    context_sha256: str
    uid: int
    gid: int
    tool: FileSnapshot
    saved: SavedProject
    work_end_ns: int
    hard_end_ns: int
    digest: bytes

    def arguments(self, scratch: Path, *, export: bool) -> tuple[str, ...]:
        require(type(export) is bool and isinstance(scratch, Path))
        # Only the operation's ORIGINAL private scratch is accepted at the
        # run_owned seam. A Path passed to this pure formatter is not authority.
        vm = ("-J-Xms16m", "-J-Xmx256m", "-J-XX:MaxMetaspaceSize=128m",
              "-J-XX:-UsePerfData", "-J-Dfile.encoding=UTF-8",
              "-J-Duser.home=" + str(scratch), "-J-Djava.io.tmpdir=" + str(scratch))
        base = (str(self.tool.path), *vm)
        store = ("-storetype", "JKS", "-keystore", str(scratch / "upload.jks"), "-alias", ALIAS)
        passwords = ("-storepass:env", STORE_PASSWORD_ENV, "-keypass:env", KEY_PASSWORD_ENV)
        if export:
            return (*base, "-exportcert", *store, *passwords)
        return (*base, "-genkeypair", "-noprompt", *store, "-keyalg", "RSA", "-keysize", "3072",
                "-sigalg", "SHA256withRSA", "-validity", "10000", "-dname", "CN=Android Upload Key",
                *passwords)


def parse_request(raw: bytes) -> Request:
    row = _keys(_decode(raw), ("protocol", "id", "generation", "contextSha256", "native", "clock"))
    require(row["protocol"] == PROTOCOL)
    native = _keys(row["native"], ("uid", "gid", "executable", "tool", "saved"))
    uid = _integer(native["uid"], 1, (1 << 32) - 1)
    gid = _integer(native["gid"], 0, (1 << 32) - 1)
    path = _path(native["executable"])
    require(path.name == "keytool" and path.parent.name == "bin")
    tool = _keys(native["tool"], ("identity", "sha256"))
    values = tool["identity"]
    require(type(values) is list and len(values) == 9)
    values = tuple(_integer(v, 0 if n < 7 else -(1 << 63), (1 << (64 if n < 7 else 63)) - 1)
                   for n, v in enumerate(values))
    require(values[0] > 0 and values[1] > 0 and stat.S_ISREG(values[2])
            and values[3] == 0 and values[5] == 1 and 0 < values[6] <= TOOL_LIMIT
            and values[2] & 0o111 != 0 and values[2] & 0o7022 == 0)
    saved = _keys(native["saved"], ("root", "identity", "configBytes", "configSha256", "draftSha256", "appIdentitySha256"))
    root = _path(saved["root"])
    root_values = saved["identity"]
    require(type(root_values) is list and len(root_values) == 5)
    root_values = tuple(_integer(v, 0, (1 << 64) - 1) for v in root_values)
    require(root_values[0] > 0 and root_values[1] > 0 and stat.S_ISDIR(root_values[2])
            and root_values[2] <= 0xffff and root_values[3] < 1 << 32 and root_values[4] < 1 << 32)
    captured = SavedProject(root, root_values, _integer(saved["configBytes"], 1, 512*1024),
                            _sha(saved["configSha256"]), _sha(saved["draftSha256"]), _sha(saved["appIdentitySha256"]))
    clock = _keys(row["clock"], ("workEndNs", "hardEndNs"))
    work = _integer(clock["workEndNs"], 1, (1 << 63) - 1)
    hard = _integer(clock["hardEndNs"], 1, (1 << 63) - 1)
    require(hard - work == (FINALITY_SECONDS - WORK_SECONDS) * 1_000_000_000)
    return Request(_id(row["id"]), _id(row["generation"]), _sha(row["contextSha256"]), uid, gid,
                   FileSnapshot(path, values, _sha(tool["sha256"])), captured, work, hard, hashlib.sha256(raw).digest())


def ready(request: Request) -> bytes:
    require(type(request) is Request)
    return READY_MAGIC + request.id.encode("ascii") + request.generation.encode("ascii") + request.digest


class Passwords:
    """Private helper backing only. No repr/serde/error value or public result."""
    __slots__ = ("_bytes", "_closed")

    def __init__(self, raw: bytearray, request: Request) -> None:
        require(type(raw) is bytearray and len(raw) == GO_LENGTH and type(request) is Request)
        self._bytes, self._closed = raw, False  # Retain BEFORE validating private body.
        require(raw[:len(GO_MAGIC)] == GO_MAGIC
                and hmac.compare_digest(raw[len(GO_MAGIC):len(GO_MAGIC) + 32], request.digest))
        start = len(GO_MAGIC) + 32
        require(all(c in b"0123456789abcdef" for c in memoryview(raw)[start:])
                and raw[start:start + PASSWORD_LENGTH] != raw[start + PASSWORD_LENGTH:])

    def environment(self, scratch: Path) -> dict[str, str]:
        require(not self._closed)
        start = len(GO_MAGIC) + 32
        # Fresh CHILD-only map. Never install values in os.environ, argv,
        # request JSON, public projection, logs or shell text.
        return {"PATH": "/usr/bin:/bin", "HOME": str(scratch), "TMPDIR": str(scratch),
                "LANG": "C", "LC_ALL": "C",
                STORE_PASSWORD_ENV: self._bytes[start:start + PASSWORD_LENGTH].decode("ascii"),
                KEY_PASSWORD_ENV: self._bytes[start + PASSWORD_LENGTH:].decode("ascii")}

    def store(self) -> memoryview:
        require(not self._closed)
        start = len(GO_MAGIC) + 32
        return memoryview(self._bytes)[start:start + PASSWORD_LENGTH]

    def close(self) -> None:
        self._closed = True
        for i in range(len(self._bytes)):
            self._bytes[i] = 0


def terminal_header(request: Request, status: str, jks_length: int = 0, certificate_length: int = 0) -> bytes:
    require(type(request) is Request and type(status) is str and status in STATUSES)
    if status == "ok":
        require(32 < jks_length <= JKS_LIMIT and 0 < certificate_length <= CERTIFICATE_LIMIT)
    else:
        require(jks_length == certificate_length == 0)
    return (END_MAGIC + request.id.encode("ascii") + request.generation.encode("ascii")
            + struct.pack(">BII", STATUSES.index(status), jks_length, certificate_length))


assert RESPONSE_LIMIT <= PRIVATE_BACKING_LIMIT
