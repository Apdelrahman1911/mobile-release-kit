"""Small private preflight intent journal, owned by the original helper.

Only immutable create-only intent and exact-run-identity leaves are supported.
There is no update, replace, delete, credential, arbitrary file or retry API.
An intent grants only reconciliation after fresh native authentication. Even a
known run leaf does not assert its outcome or authorize another dispatch.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from typing import Any

from ._desktop_github_engine import _decode_json
from .github_preflight import PROTOCOL, Prepared, _DIGEST, _id, _match, _object, _require

MAX_RECORDS = 64
MAX_ENTRIES = MAX_RECORDS * 2
MAX_INTENT_BYTES = 8192
MAX_RUN_BYTES = 512
MAX_TOTAL_BYTES = MAX_RECORDS * (MAX_INTENT_BYTES + MAX_RUN_BYTES)
MAX_PATH_COMPONENTS = 128
MAX_PATH_BYTES = 4096
_LEAF = re.compile(r"([0-9a-f]{32})\.(intent|run)\.json\Z", re.ASCII)
_SUFFIX = (".local", "share", "mobile-release-kit", "github-preflight")


class JournalError(ValueError):
    """Fixed diagnostic only; private paths and record bytes never escape."""


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def intent_bytes(prepared: Prepared) -> bytes:
    raw = canonical({"schemaVersion": 1, "protocol": PROTOCOL, "prepared": prepared.value()}) + b"\n"
    _require(len(raw) <= MAX_INTENT_BYTES)
    return raw


def parse_intent(raw: bytes) -> Prepared:
    _require(type(raw) is bytes and raw.endswith(b"\n") and raw.count(b"\n") == 1)
    row = _object(_decode_json(raw[:-1], limit=MAX_INTENT_BYTES - 1, nodes=512, depth=8, exact=True),
                  {"schemaVersion", "protocol", "prepared"})
    _require(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1 and row["protocol"] == PROTOCOL)
    prepared = Prepared.parse(row["prepared"])
    _require(intent_bytes(prepared) == raw)
    return prepared


def run_bytes(intent_sha256: str, run_id: str) -> bytes:
    return canonical({"schemaVersion": 1, "intentSha256": _match(intent_sha256, _DIGEST),
                      "runId": _id(run_id), "attempt": 1}) + b"\n"


def parse_run(raw: bytes, intent_sha256: str) -> str:
    _require(type(raw) is bytes and raw.endswith(b"\n") and raw.count(b"\n") == 1)
    row = _object(_decode_json(raw[:-1], limit=MAX_RUN_BYTES - 1, nodes=32, depth=3, exact=True),
                  {"schemaVersion", "intentSha256", "runId", "attempt"})
    _require(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1
             and type(row["attempt"]) is int and row["attempt"] == 1)
    _require(row["intentSha256"] == intent_sha256)
    result = _id(row["runId"])
    _require(raw == run_bytes(intent_sha256, result))
    return result


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _directory(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


class Journal:
    """One finite original helper operation; no background writer or cleaner.

    The native application selects the account home; the helper traverses it
    no-follow and creates only the fixed application suffix. Existing ancestors
    may not be writable by another user/group. The application and journal
    directories must be private. Descriptor-backed relative calls, one non-
    waiting namespace lock, finite enumeration and postconditions cover every
    write; a collision or malformed unrelated record is preserved and refused.
    """
    def __init__(self, home: str, *, end: float) -> None:
        # Construction is DATA only. open() is called after the helper itself is
        # registered in the original native Supervisor's resource roster.
        if (type(home) is not str or not home.startswith("/") or home == "/"
                or len(home.encode("utf-8")) > MAX_PATH_BYTES - 80
                or any(ord(char) < 32 or ord(char) == 127 for char in home)):
            raise JournalError("Private preflight journal is unavailable")
        self.parts = home.split("/")[1:]
        if (not self.parts or len(self.parts) + len(_SUFFIX) > MAX_PATH_COMPONENTS
                or any(part in {"", ".", ".."} for part in self.parts)):
            raise JournalError("Private preflight journal is unavailable")
        self.end = end
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.ancestors: list[tuple[int, int | None, str | None, tuple[int, ...] | None]] = []
        self.leaves: dict[str, tuple[tuple[int, ...], bytes]] = {}
        self.records: dict[str, tuple[Prepared, str | None, str]] = {}
        self.root: int | None = None
        self.opened = False
        self.closed = False

    def _time(self) -> None:
        if time.monotonic() >= self.end:
            raise JournalError("Private preflight journal deadline elapsed")

    def _close(self, fd: int) -> None:
        # A close claim is never retried. The enclosing original helper exit
        # and its native parent retain the actual outcome even on error.
        os.close(fd)

    def _dir(self, value: os.stat_result, *, owned: bool = False, private: bool = False) -> None:
        if (not stat.S_ISDIR(value.st_mode) or value.st_mode & 0o7022
                or value.st_uid not in ({self.uid} if owned else {0, self.uid})
                or private and stat.S_IMODE(value.st_mode) != 0o700):
            raise JournalError("Private preflight directory custody differs")

    def _file(self, value: os.stat_result, maximum: int) -> None:
        if (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_uid != self.uid
                or stat.S_IMODE(value.st_mode) != 0o400 or not 0 < value.st_size <= maximum):
            raise JournalError("Private preflight record custody differs")

    def open(self) -> Journal:
        self._time()
        if self.opened or self.closed or self.uid == 0 or self.uid != os.getuid() or self.gid != os.getgid():
            raise JournalError("Private preflight account is unavailable")
        self.opened = True
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        root = os.open("/", flags)
        self.ancestors.append((root, None, None, None))
        state = os.fstat(root)
        self.ancestors[-1] = (root, None, None, _directory(state))
        self._dir(state)
        parent = root
        all_parts = [*self.parts, *_SUFFIX]
        for index, name in enumerate(all_parts):
            self._time()
            create = index >= len(self.parts)
            private = index >= len(self.parts) + 2
            try:
                fd = os.open(name, flags, dir_fd=parent)
            except FileNotFoundError:
                if not create:
                    raise JournalError("Private account home is unavailable") from None
                # Only these four fixed names can be created. Existing
                # directories are never chmodded, replaced or deleted.
                os.mkdir(name, mode=0o700, dir_fd=parent)
                os.fsync(parent)
                fd = os.open(name, flags, dir_fd=parent)
            self.ancestors.append((fd, parent, name, None))
            state = os.fstat(fd)
            self.ancestors[-1] = (fd, parent, name, _directory(state))
            self._dir(state, owned=index >= len(self.parts) - 1, private=private)
            if _directory(os.stat(name, dir_fd=parent, follow_symlinks=False)) != _directory(state):
                raise JournalError("Private preflight directory changed")
            parent = fd
        self.root = parent
        import fcntl

        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # No waiting/retry and no user-visible lock-file repair. Closing this
        # exact original directory releases only our own namespace lock.
        self._load()
        self._post()
        return self

    def _names(self) -> set[str]:
        self._time()
        if self.root is None:
            raise JournalError("Private preflight journal is unopened")
        names: set[str] = set()
        with os.scandir(self.root) as entries:
            for entry in entries:
                self._time()
                if len(names) >= MAX_ENTRIES or _LEAF.fullmatch(entry.name) is None or entry.name in names:
                    raise JournalError("Private preflight journal inventory differs")
                names.add(entry.name)
        return names

    def _read(self, name: str) -> bytes:
        self._time()
        maximum = MAX_INTENT_BYTES if name.endswith(".intent.json") else MAX_RUN_BYTES
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=self.root)
        try:
            before = os.fstat(fd)
            self._file(before, maximum)
            if _identity(os.stat(name, dir_fd=self.root, follow_symlinks=False)) != _identity(before):
                raise JournalError("Private preflight record changed")
            data = bytearray()
            while len(data) <= before.st_size:
                self._time()
                block = os.read(fd, min(4096, before.st_size + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            if (len(data) != before.st_size or _identity(os.fstat(fd)) != _identity(before)
                    or _identity(os.stat(name, dir_fd=self.root, follow_symlinks=False)) != _identity(before)):
                raise JournalError("Private preflight record changed")
            result = bytes(data)
            self.leaves[name] = (_identity(before), result)
            return result
        finally:
            self._close(fd)

    def _load(self) -> None:
        names = self._names()
        intents = sorted(name for name in names if name.endswith(".intent.json"))
        if len(intents) > MAX_RECORDS or any(name[:-9] + ".intent.json" not in names
                                           for name in names if name.endswith(".run.json")):
            raise JournalError("Private preflight journal identity is incomplete")
        total = 0
        for name in intents:
            raw = self._read(name)
            total += len(raw)
            prepared = parse_intent(raw)
            marker = name[:32]
            if prepared.target.marker != marker:
                raise JournalError("Private preflight intent identity differs")
            digest = hashlib.sha256(raw).hexdigest()
            run_name = marker + ".run.json"
            run_id = None
            if run_name in names:
                run_raw = self._read(run_name)
                total += len(run_raw)
                run_id = parse_run(run_raw, digest)
            if total > MAX_TOTAL_BYTES:
                raise JournalError("Private preflight journal byte limit exceeded")
            self.records[marker] = prepared, run_id, digest
        if self._names() != names:
            raise JournalError("Private preflight journal changed during reading")

    def _post(self) -> None:
        self._time()
        for fd, parent, name, expected in self.ancestors:
            if expected is None or _directory(os.fstat(fd)) != expected:
                raise JournalError("Private preflight original directory changed")
            named = os.stat("/", follow_symlinks=False) if parent is None else os.stat(name, dir_fd=parent, follow_symlinks=False)
            if _directory(named) != expected:
                raise JournalError("Private preflight directory name changed")
        if self.root is not None:
            if self._names() != set(self.leaves):
                raise JournalError("Private preflight journal inventory changed")
            for name, (expected, _) in self.leaves.items():
                self._time()
                if _identity(os.stat(name, dir_fd=self.root, follow_symlinks=False)) != expected:
                    raise JournalError("Private preflight original record changed")

    def _create(self, name: str, raw: bytes) -> None:
        self._post()
        if (self.root is None or _LEAF.fullmatch(name) is None or name in self.leaves
                or len(self.leaves) >= MAX_ENTRIES or len(raw) + sum(len(row[1]) for row in self.leaves.values()) > MAX_TOTAL_BYTES):
            raise JournalError("Private preflight journal collision or capacity limit")
        maximum = MAX_INTENT_BYTES if name.endswith(".intent.json") else MAX_RUN_BYTES
        if not 0 < len(raw) <= maximum:
            raise JournalError("Private preflight record size differs")
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400, dir_fd=self.root)
        try:
            # This is only our create-only original. Never change an existing
            # user's mode, overwrite a collision, truncate or unlink a partial.
            os.fchmod(fd, 0o400)
            count = 0
            while count < len(raw):
                self._time()
                written = os.write(fd, raw[count:count + 4096])
                if written <= 0:
                    raise JournalError("Private preflight record write failed")
                count += written
            os.fsync(fd)
            state = os.fstat(fd)
            self._file(state, maximum)
            os.lseek(fd, 0, os.SEEK_SET)
            checked = bytearray()
            while len(checked) <= len(raw):
                self._time()
                part = os.read(fd, min(4096, len(raw) + 1 - len(checked)))
                if not part:
                    break
                checked.extend(part)
            if (bytes(checked) != raw or _identity(os.fstat(fd)) != _identity(state)
                    or _identity(os.stat(name, dir_fd=self.root, follow_symlinks=False)) != _identity(state)):
                raise JournalError("Private preflight durable record changed")
            self.leaves[name] = (_identity(state), raw)
        finally:
            self._close(fd)
        os.fsync(self.root)
        self._post()

    def create_intent(self, prepared: Prepared) -> str:
        marker = prepared.target.marker
        if marker in self.records or len(self.records) >= MAX_RECORDS:
            raise JournalError("Private preflight request was already used or capacity is full")
        raw = intent_bytes(prepared)
        digest = hashlib.sha256(raw).hexdigest()
        self._create(marker + ".intent.json", raw)
        self.records[marker] = prepared, None, digest
        return digest

    def match_intent(self, prepared: Prepared, run_id: str | None = None) -> str:
        self._post()
        original = self.records.get(prepared.target.marker)
        if original is None or original[0] != prepared or run_id is not None and original[1] != run_id:
            raise JournalError("Private preflight original intent does not match")
        return original[2]

    def bind_run(self, prepared: Prepared, run_id: str) -> None:
        digest = self.match_intent(prepared)
        old = self.records[prepared.target.marker][1]
        run_id = _id(run_id)
        if old is not None:
            if old != run_id:
                raise JournalError("Private preflight exact run identity collides")
            return
        self._create(prepared.target.marker + ".run.json", run_bytes(digest, run_id))
        self.records[prepared.target.marker] = prepared, run_id, digest

    def pending(self, scope: dict[str, str]) -> list[dict[str, Any]]:
        self._post()
        selected = []
        for prepared, run_id, _ in self.records.values():
            target = prepared.target
            if (target.project_binding == scope["projectBinding"] and target.repository == scope["repository"]
                    and target.account_id == scope["accountId"] and target.repository_id == scope["repositoryId"]):
                selected.append({"prepared": prepared.value(), "runId": run_id})
        return selected

    def close(self) -> None:
        if self.closed:
            raise JournalError("Private preflight originals already closed")
        self.closed = True
        errors = []
        try:
            if self.root is not None:
                self._post()
        except BaseException as error:
            errors.append(error)
        while self.ancestors:
            fd, _, _, _ = self.ancestors.pop()
            try:
                self._close(fd)
            except OSError as error:
                errors.append(error)
        self.root = None
        if errors:
            raise JournalError("Private preflight original cleanup is unconfirmed") from None
