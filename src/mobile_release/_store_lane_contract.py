"""Closed Store-lane transport data; no process, filesystem or Store operation.

Clock admission is explicit when called, never performed by import. Decoded
values are not original-reader, process-finality or filesystem capabilities.
"""
from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


PREFIX = "MOBILE_RELEASE_STORE_LANE_"
RUN_NS = 3_600_000_000_000
CLEANUP_NS = 3_000_000_000
MAX_TIME = (1 << 63) - 1
MAX_ID = (1 << 64) - 1
MAX_FRAME = 65_536
MAX_DOCUMENT = 4 * 1024**2
SUCCESS, SETTLED_FAILURE, UNKNOWN = 0, 75, 76
IDENTITY_KEYS = frozenset(("device", "inode", "uid", "gid", "mode"))
FRAME_KEYS = frozenset((
    "version", "nonce", "lane", "mode", "output", "clock", "run_deadline_ns",
    "hard_deadline_ns", "outcome", "launches_closed", "adapter_settled",
    "nested_settled", "terminal_identity", "receipt", "inventory",
))
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
ROLE_RULES = {
    "pilot-root": (("tmp",), "directory", r"pilot-[0-9a-f]{32}"),
    "package": (("pilot-root",), "directory", r"[0-9]+-" + UUID + r"\.itmsp"),
    "package-ipa": (("package", "pilot-root"), "file", r"[0-9a-f]{64}\.ipa"),
    "package-metadata": (("package",), "file", r"metadata\.xml"),
    "package-appstore-info": (("pilot-root",), "file", r"AppStoreInfo\.plist"),
    "upload-asset": (("tmp",), "file", UUID + r"\.ipa"),
    "key-dir": (("tmp",), "directory", r"deliver-[0-9a-f]{32}"),
    "key": (("key-dir", "shell-keys"), "file", r"AuthKey_[A-Za-z0-9]+\.p8"),
}


def need(condition: bool) -> None:
    if not condition:
        raise ValueError("Store lane transport contract is incomplete")


def integer(value: object, low: int = 0, high: int = MAX_ID) -> bool:
    return type(value) is int and low <= value <= high


def absolute(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeError:
        return False
    return (0 < size <= 4096 and not value.startswith("//")
            and not any(ord(c) < 32 or ord(c) == 127 for c in value)
            and Path(value).is_absolute() and str(Path(value)) == value
            and ".." not in Path(value).parts and len(Path(value).parts) <= 64)


def clock_label() -> str:
    """Only the supported CPython clock domain; Ruby must admit its peer."""
    info = time.get_clock_info("monotonic")
    expected = {"linux": ("clock_gettime(CLOCK_MONOTONIC)", "linux-monotonic-v1"),
                "darwin": ("mach_absolute_time()", "darwin-uptime-raw-v1")}
    need(sys.implementation.name == "cpython" and sys.platform in expected)
    implementation, label = expected[sys.platform]
    need(info.monotonic is True and info.adjustable is False and info.implementation == implementation)
    return label


def decimal(value: object, *, low: int = 0, high: int = MAX_TIME) -> int:
    need(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is not None)
    number = int(value)
    need(integer(number, low, high))
    return number


@dataclass(frozen=True, slots=True)
class Timing:
    clock: str
    run: int
    hard: int

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> Timing:
        label = clock_label()
        need(environment.get(PREFIX + "CLOCK") == label)
        run = decimal(environment.get(PREFIX + "RUN_DEADLINE_NS"), low=1)
        hard = decimal(environment.get(PREFIX + "HARD_DEADLINE_NS"), low=1)
        now = time.monotonic_ns()
        need(integer(now, 0, MAX_TIME) and now < run <= now + RUN_NS and hard - run == CLEANUP_NS)
        return cls(label, run, hard)


@dataclass(frozen=True, slots=True)
class Identity:
    device: int
    inode: int
    uid: int
    gid: int
    mode: int

    @classmethod
    def decode(cls, value: object, *, mode: int) -> Identity:
        need(type(value) is dict and value.keys() == IDENTITY_KEYS
             and all(integer(v) for v in value.values())
             and value["inode"] > 0 and value["mode"] == mode)
        return cls(**value)


@dataclass(frozen=True, slots=True)
class Entry:
    role: str
    parent: str
    name: str
    kind: str
    identity: Identity


@dataclass(frozen=True, slots=True)
class Document:
    identity: Identity
    size: int
    sha256: bytes


@dataclass(frozen=True, slots=True)
class Terminal:
    identity: Identity
    document: Document | None
    inventory: tuple[Entry, ...]


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        need(key not in value)
        value[key] = item
    return value


def _depth(value: object, depth: int = 0) -> None:
    need(depth <= 8)
    if type(value) is dict:
        for key, item in value.items():
            _depth(key, depth + 1)
            _depth(item, depth + 1)
    elif type(value) is list:
        for item in value:
            _depth(item, depth + 1)
    elif type(value) is str:
        need(not any(ord(c) < 32 or ord(c) == 127 for c in value))
        value.encode("utf-8", errors="strict")


def decode_terminal(content: bytes, *, lane: str, mode: str, output: str,
                    nonce: bytes, timing: Timing, code: int, device: int,
                    uid: int, shell_home: bool, app_id: str | None = None,
                    key_id: str | None = None) -> Terminal:
    need(type(content) is bytes and 0 < len(content) <= MAX_FRAME
         and content.endswith(b"\n") and not content.endswith(b"\n\n")
         and type(code) is int and code in (SUCCESS, SETTLED_FAILURE))
    text = content[:-1].decode("utf-8", errors="strict")
    need(text.startswith("{") and text.endswith("}") and "\0" not in text)
    value = json.loads(text, object_pairs_hook=_pairs,
                       parse_constant=lambda _: need(False))
    _depth(value)
    need(type(value) is dict and value.keys() == FRAME_KEYS
         and type(value["version"]) is int and value["version"] == 1
         and value["nonce"] == nonce.hex() and value["lane"] == lane
         and value["mode"] == mode and value["output"] == output
         and value["clock"] == timing.clock
         and type(value["run_deadline_ns"]) is int and value["run_deadline_ns"] == timing.run
         and type(value["hard_deadline_ns"]) is int and value["hard_deadline_ns"] == timing.hard
         and value["launches_closed"] is True and value["adapter_settled"] is True
         and value["nested_settled"] is True
         and value["outcome"] == ("success" if code == SUCCESS else "failed"))
    identity = Identity.decode(value["terminal_identity"], mode=0o600)
    need(identity.device == device and identity.uid == uid)
    document = None
    raw = value["receipt"]
    if code == SUCCESS:
        need(type(raw) is dict and raw.keys() == IDENTITY_KEYS | {"size", "sha256"}
             and integer(raw["size"], 1, MAX_DOCUMENT) and type(raw["sha256"]) is str
             and re.fullmatch(r"[0-9a-f]{64}", raw["sha256"]) is not None)
        original = Identity.decode({key: raw[key] for key in IDENTITY_KEYS}, mode=0o600)
        need(original.uid == uid)
        document = Document(original, raw["size"], bytes.fromhex(raw["sha256"]))
    else:
        need(raw is None)
    rows = value["inventory"]
    need(type(rows) is list and len(rows) <= 32)
    entries, seen, paths = [], set(), set()
    for row in rows:
        need(type(row) is dict and row.keys() == IDENTITY_KEYS | {"role", "parent", "name", "kind"}
             and all(type(row[key]) is str for key in ("role", "parent", "name", "kind")))
        role, parent, name, kind = (row[key] for key in ("role", "parent", "name", "kind"))
        need(role in ROLE_RULES and role not in seen and name not in ("", ".", "..")
             and len(name.encode("utf-8")) <= 512 and "/" not in name)
        parents, expected_kind, pattern = ROLE_RULES[role]
        need(parent in parents and kind == expected_kind and re.fullmatch(pattern, name) is not None
             and (parent != "shell-keys" or shell_home) and (parent, name) not in paths)
        if role == "package":
            need(type(app_id) is str and re.fullmatch(r"[1-9][0-9]*", app_id) is not None
                 and name.startswith(app_id + "-"))
        if role == "key":
            need(type(key_id) is str and re.fullmatch(r"[A-Za-z0-9]+", key_id) is not None
                 and name == f"AuthKey_{key_id}.p8"
                 and (parent == "shell-keys") is shell_home)
        if role == "key-dir":
            need(not shell_home)
        if timing.clock == "darwin-uptime-raw-v1":
            need(role != "package-appstore-info" and (role != "package-ipa" or parent == "package"))
        else:
            need(role not in ("package", "package-metadata", "upload-asset")
                 and (role != "package-ipa" or parent == "pilot-root"))
        original = Identity.decode({key: row[key] for key in IDENTITY_KEYS},
                                   mode=0o700 if kind == "directory" else 0o600)
        need(original.device == device and original.uid == uid)
        entries.append(Entry(role, parent, name, kind, original))
        seen.add(role); paths.add((parent, name))
    need(not entries or lane == "ios_testflight_internal" and mode == "execute")
    need(all(item.parent in ("tmp", "shell-keys") or item.parent in seen for item in entries))
    return Terminal(identity, document, tuple(entries))
