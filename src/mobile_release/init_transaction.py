"""A recoverable local init transaction, not a general filesystem database.

Only Linux/macOS local filesystems with flock, fsync and atomic exclusive rename
are supported for mutation. Imports/capability checks are lazy so preview and
unrelated commands remain portable. A lock coordinates init, not hostile peers
with the same UID or arbitrary namespace/old-file-descriptor manipulation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .errors import ValidationError

PREPARING = ".mobile-release-init-prepare"
READY = ".mobile-release-init"
CLEANUP = ".mobile-release-init-cleanup"
STATE_NAMES = (PREPARING, READY, CLEANUP)
IGNORE_LINES = (".mobile-release/", *(name + "/" for name in STATE_NAMES))
MAX_FILES = 256
MAX_FILE_BYTES = 8 * 1024**2
MAX_TOTAL_BYTES = 64 * 1024**2
MAX_CONTROL_BYTES = 512 * 1024
MAX_DIRECTORY_ENTRIES = 100_000
CONTROLS = {"header.json", "header.tmp", "plan.json", "plan.tmp",
            "commit.pending", "rollback.pending", "COMMITTED", "ROLLED_BACK"}
PROBES = {"probe-a", "probe-b", "probe-c"}


class InitInterrupted(KeyboardInterrupt):
    """An interrupt with an explicit rollback/recovery outcome."""


class InitConflict(ValidationError):
    """An observed user/namespace change must not be adopted by automatic retry."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(f"init transaction: {message}")


def _key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def is_state_name(value: str) -> bool:
    return _key(value) in STATE_NAMES


def validate_paths(paths: list[str]) -> None:
    """Validate files and every implicit directory, including portable aliases."""
    _require(0 < len(paths) <= MAX_FILES, "invalid destination count")
    components: dict[str, tuple[str, bool]] = {}
    for name in paths:
        try:
            parts = name.split("/")
            valid = len(name.encode("utf-8")) <= 4096 and len(parts) <= 64 and all(
                part not in {"", ".", ".."} and len(part.encode("utf-8")) <= 255
                and not part.endswith((" ", "."))
                and not any(ord(c) < 32 or ord(c) == 127 or c in "\\:" for c in part)
                for part in parts
            )
        except (AttributeError, UnicodeError):
            valid = False
        _require(valid, "unsafe destination path")
        _require(_key(parts[0]) not in {_key(n) for n in (*STATE_NAMES, ".git")},
                 "destination uses a reserved transaction or Git path")
        for count in range(1, len(parts) + 1):
            path = "/".join(parts[:count])
            value = (path, count < len(parts))
            previous = components.get(_key(path))
            _require(previous is None or (value[1] and previous == value),
                     "duplicate init destination, portable alias, or file/ancestor conflict")
            components[_key(path)] = value
    _require(sum(is_dir for _, is_dir in components.values()) <= MAX_FILES,
             "too many destination directories")


def _json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        _require(key not in result, "duplicate recovery JSON key")
        result[key] = value
    return result


def _parse(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data, object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValidationError("init transaction: malformed recovery JSON; preserve the journal") from error
    _require(type(value) is dict, "recovery control must be an object")
    return value


def _dir_identity(value: os.stat_result) -> dict[str, int]:
    _require(stat.S_ISDIR(value.st_mode), "expected a real directory, not a symbolic link or special file")
    _require(not stat.S_IMODE(value.st_mode) & 0o7000, "special directory permission bits are unsupported")
    return {"device": value.st_dev, "inode": value.st_ino, "mode": stat.S_IMODE(value.st_mode)}


def _stat(fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _raw_identity(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _list(fd: int) -> list[str]:
    names = os.listdir(fd)
    _require(len(names) <= MAX_DIRECTORY_ENTRIES, "directory entry bound exceeded")
    return names


def _alias(fd: int, name: str) -> None:
    _require(not any(item != name and _key(item) == _key(name) for item in _list(fd)),
             "existing path has a case/Unicode alias")


def _read(fd: int, name: str, limit: int = MAX_FILE_BYTES) -> tuple[dict[str, Any], bytes] | None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        handle = os.open(name, flags, dir_fd=fd)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(handle)
        _require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                 "input must be a bounded regular file, not a symbolic link or special file")
        _require(not stat.S_IMODE(before.st_mode) & 0o7000, "special file permission bits are unsupported")
        chunks, size = [], 0
        while data := os.read(handle, min(1024**2, limit + 1 - size)):
            chunks.append(data)
            size += len(data)
            _require(size <= limit, "input exceeded its byte bound")
        _require(size == before.st_size and _raw_identity(before) == _raw_identity(os.fstat(handle)),
                 "input changed during its bounded read")
        data = b"".join(chunks)
        return ({"device": before.st_dev, "inode": before.st_ino,
                 "mode": stat.S_IMODE(before.st_mode), "size": size,
                 "sha256": hashlib.sha256(data).hexdigest()}, data)
    finally:
        os.close(handle)


def _binding(fd: int, name: str, *, directory: bool = False, limit: int = MAX_FILE_BYTES) -> dict[str, Any] | None:
    if directory:
        value = _stat(fd, name)
        return _dir_identity(value) if value else None
    value = _read(fd, name, limit)
    return value[0] if value else None


def _fsync(fd: int) -> None:
    os.fsync(fd)


def _write(fd: int, name: str, data: bytes, mode: int = 0o600, *, preserve_mode: bool = False) -> None:
    _require(len(data) <= MAX_FILE_BYTES, "staged file exceeds its byte bound")
    handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=fd)
    try:
        view = memoryview(data)
        while view:
            size = os.write(handle, view[:1024**2])
            _require(size > 0, "staged write made no progress")
            view = view[size:]
        if preserve_mode:
            os.fchmod(handle, mode)
        _fsync(handle)
    finally:
        os.close(handle)


def _rename_function() -> Any:
    # Never import POSIX-only modules or bind native symbols during CLI import.
    import ctypes

    _require(sys.platform == "darwin" or sys.platform.startswith("linux"),
             "apply/recover requires a supported local Linux or macOS filesystem")
    library = ctypes.CDLL(None, use_errno=True)
    name = "renameatx_np" if sys.platform == "darwin" else "renameat2"
    _require(hasattr(library, name), "atomic exclusive rename is unavailable; no unsafe fallback is allowed")
    function = getattr(library, name)
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int

    def rename(source_fd: int, source: str, destination_fd: int, destination: str) -> None:
        result = function(source_fd, os.fsencode(source), destination_fd, os.fsencode(destination),
                          4 if sys.platform == "darwin" else 1)
        if result:
            code = ctypes.get_errno()
            raise OSError(code, "exclusive transaction rename failed")

    return rename


@dataclass(frozen=True)
class ObservedFile:
    path: str
    before: dict[str, Any] | None
    data: bytes | None


class InitWorkspace:
    def __init__(self, root: Path):
        self.root = root
        self.fd = -1
        self.parents: dict[str, dict[str, Any] | None] = {}
        self.root_identity: dict[str, int] = {}
        self.private_identity: dict[str, int] | None = None
        self.observed_bytes = 0

    def __enter__(self) -> InitWorkspace:
        _require(sys.platform == "darwin" or sys.platform.startswith("linux"),
                 "apply/recover requires Linux/macOS local filesystem semantics")
        import fcntl

        self.rename = _rename_function()
        self.flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        self.fd = os.open(self.root, self.flags)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.root_identity = _dir_identity(os.fstat(self.fd))
            self._root_check()
        except BaseException as error:
            os.close(self.fd)
            self.fd = -1
            if isinstance(error, BlockingIOError):
                raise ValidationError("init transaction: another init/recovery owns this project; wait for it to finish") from error
            raise
        return self

    def __exit__(self, *_args: Any) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def _root_check(self) -> None:
        _require(_dir_identity(os.stat(self.root, follow_symlinks=False)) == self.root_identity,
                 "project root changed; preserve transaction state")

    def state(self) -> str | None:
        self._root_check()
        for name in STATE_NAMES:
            _alias(self.fd, name)
        found = [name for name in STATE_NAMES if _stat(self.fd, name) is not None]
        _require(len(found) <= 1, "inconsistent simultaneous transaction directories; preserve them")
        return found[0] if found else None

    def require_clean(self) -> None:
        _require(self.state() is None,
                 "pending transaction; run mobile-release init --root <project> --recover before applying again")

    @contextmanager
    def _private(self, name: str) -> Iterator[int]:
        self._root_check()
        handle = os.open(name, self.flags, dir_fd=self.fd)
        try:
            value = os.fstat(handle)
            _require(value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700
                     and value.st_dev == self.root_identity["device"],
                     "journal must be a private, owned, same-filesystem directory")
            self._private_check(handle, name)
            yield handle
        finally:
            os.close(handle)

    def _private_check(self, fd: int, name: str) -> None:
        try:
            self._root_check()
            _alias(self.fd, name)
            value = os.fstat(fd)
            identity = _dir_identity(value)
            _require(value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700
                     and identity == _binding(self.fd, name, directory=True)
                     and (self.private_identity is None or identity == self.private_identity),
                     "private transaction namespace changed")
        except (OSError, ValidationError) as error:
            raise InitConflict("init transaction: private namespace changed or cannot be verified; preserve all captured objects") from error
        self.private_identity = identity

    @contextmanager
    def _parent(self, path: str, *, planning: bool = False) -> Iterator[int | None]:
        self._root_check()
        handle, opened, current, missing = self.fd, [], [], False
        try:
            for part in path.split("/")[:-1]:
                current.append(part)
                relative = "/".join(current)
                if not missing:
                    _alias(handle, part)
                    value = _stat(handle, part)
                    identity = _dir_identity(value) if value else None
                    if identity:
                        _require(identity["device"] == self.root_identity["device"]
                                 and not os.path.ismount(self.root / relative),
                                 "nested mount or different filesystem is unsupported")
                    if planning and relative not in self.parents:
                        self.parents[relative] = identity
                    _require(relative in self.parents and identity == self.parents[relative],
                             "destination ancestor changed or is unsafe")
                    if value is None:
                        missing = True
                    else:
                        child = os.open(part, self.flags, dir_fd=handle)
                        opened.append(child)
                        _require(_dir_identity(os.fstat(child)) == identity, "ancestor changed while opening")
                        handle = child
                elif planning and relative not in self.parents:
                    self.parents[relative] = None
            if not missing:
                _alias(handle, path.split("/")[-1])
            yield None if missing else handle
        finally:
            for handle in reversed(opened):
                os.close(handle)

    def observe(self, path: str, *, limit: int = MAX_FILE_BYTES) -> ObservedFile:
        validate_paths([path])
        with self._parent(path, planning=True) as parent:
            value = _read(parent, path.split("/")[-1], min(limit, MAX_TOTAL_BYTES - self.observed_bytes)) if parent is not None else None
        self.observed_bytes += value[0]["size"] if value else 0
        return ObservedFile(path, value[0] if value else None, value[1] if value else None)

    def _current(self, path: str, *, directory: bool = False) -> dict[str, Any] | None:
        with self._parent(path) as parent:
            return _binding(parent, path.split("/")[-1], directory=directory) if parent is not None else None

    def _namespace_check(self, *, changing: str | None = None) -> None:
        self._root_check()
        for path, expected in self.parents.items():
            if changing is not None and (path == changing or path.startswith(changing + "/")):
                continue
            _require(self._current(path, directory=True) == expected, "destination namespace changed")

    def _move(self, source_fd: int, source: str, destination_fd: int, destination: str,
              expected: dict[str, Any], *, directory: bool = False, directory_path: str | None = None) -> None:
        self._namespace_check()
        _require(_binding(source_fd, source, directory=directory) == expected, "move source changed")
        _require(_stat(destination_fd, destination) is None, "exclusive move destination appeared")
        failure: BaseException | None = None
        try:
            self.rename(source_fd, source, destination_fd, destination)
        except BaseException as error:
            failure = error
        captured = _stat(destination_fd, destination)
        if captured is not None and _stat(source_fd, source) is None:
            try:
                _require(_binding(destination_fd, destination, directory=directory) == expected,
                         "move captured a changed source")
                if directory:
                    handle = os.open(destination, self.flags, dir_fd=destination_fd)
                    try:
                        _require(not _list(handle), "moved directory gained unrelated contents")
                    finally:
                        os.close(handle)
            except BaseException:
                # Restore the captured object, not an assumed precheck inode.
                # If either location changed again, preserve both as a conflict.
                self._namespace_check(changing=directory_path)
                if _stat(source_fd, source) is None and _raw_identity(captured) == _raw_identity(
                    os.stat(destination, dir_fd=destination_fd, follow_symlinks=False)
                ):
                    self.rename(destination_fd, destination, source_fd, source)
                    _fsync(source_fd)
                    _fsync(destination_fd)
                raise ValidationError("init transaction: source changed during move; captured user object preserved, reconcile before recovery")
        if failure is not None:
            raise failure
        _require(captured is not None and _binding(destination_fd, destination, directory=directory) == expected,
                 "exclusive move did not produce its exact expected object")
        self._namespace_check(changing=directory_path)
        _fsync(source_fd)
        _fsync(destination_fd)

    def _state_move(self, old: str, new: str) -> None:
        self._root_check()
        expected = _binding(self.fd, old, directory=True)
        _require(expected is not None, "transaction directory disappeared")
        _require(self.private_identity is None or expected == self.private_identity,
                 "transaction directory changed before handoff")
        failure: BaseException | None = None
        try:
            self.rename(self.fd, old, self.fd, new)
        except BaseException as error:
            failure = error
        captured = _stat(self.fd, new)
        if captured is not None and _stat(self.fd, old) is None and (
            not stat.S_ISDIR(captured.st_mode)
            or (captured.st_dev, captured.st_ino, stat.S_IMODE(captured.st_mode))
            != (expected["device"], expected["inode"], expected["mode"])
        ):
            self._root_check()
            _require(_raw_identity(captured) == _raw_identity(os.stat(new, dir_fd=self.fd, follow_symlinks=False)),
                     "captured transaction object changed; preserve both namespaces")
            self.rename(self.fd, new, self.fd, old)
            _fsync(self.fd)
            raise ValidationError("init transaction: journal namespace changed; captured object restored")
        if failure is not None:
            raise failure
        _require(_binding(self.fd, new, directory=True) == expected, "transaction directory changed during handoff")
        _fsync(self.fd)

    def _header(self, fd: int) -> dict[str, Any]:
        item = _read(fd, "header.json", MAX_CONTROL_BYTES)
        _require(item is not None, "missing recovery header")
        header = _parse(item[1])
        _require(set(header) == {"schemaVersion", "transactionId", "root"}
                 and type(header["schemaVersion"]) is int and header["schemaVersion"] == 1
                 and isinstance(header["transactionId"], str)
                 and re.fullmatch(r"[0-9a-f]{32}", header["transactionId"]) is not None
                 and self._valid_identity(header["root"], directory=True)
                 and header["root"] == self.root_identity, "invalid recovery header/root binding")
        return header

    @staticmethod
    def _valid_identity(value: Any, *, directory: bool = False) -> bool:
        keys = {"device", "inode", "mode"} | (set() if directory else {"size", "sha256"})
        return (type(value) is dict and set(value) == keys
                and all(type(value[k]) is int and 0 <= value[k] < 2**64 for k in keys - {"sha256"})
                and value["inode"] > 0 and value["mode"] <= 0o777
                and (directory or (value["size"] <= MAX_FILE_BYTES and isinstance(value["sha256"], str)
                                    and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None)))

    def _load(self, fd: int) -> dict[str, Any]:
        header = self._header(fd)
        item = _read(fd, "plan.json", MAX_CONTROL_BYTES)
        _require(item is not None, "missing READY plan; preserve journal, do not guess")
        plan = _parse(item[1])
        _require(set(plan) == {*header, "directories", "files"}
                 and _json({k: plan[k] for k in header}) == _json(header), "plan/header binding differs")
        _require(type(plan["files"]) is list and type(plan["directories"]) is list
                 and 0 < len(plan["files"]) <= MAX_FILES and len(plan["directories"]) <= MAX_FILES,
                 "invalid recovery inventory")
        for entry in plan["files"]:
            _require(type(entry) is dict and set(entry) == {"path", "before", "after"}
                     and type(entry["path"]) is str, "invalid recovery file entry")
            _require((entry["before"] is not None or entry["after"] is not None)
                     and all(v is None or self._valid_identity(v) for v in (entry["before"], entry["after"])),
                     "invalid recovery file identity")
        validate_paths([entry["path"] for entry in plan["files"]])
        expected_dirs = {"/".join(e["path"].split("/")[:i]) for e in plan["files"]
                         for i in range(1, len(e["path"].split("/")))}
        seen = set()
        for entry in plan["directories"]:
            _require(type(entry) is dict and set(entry) == {"path", "before", "after"}
                     and type(entry["path"]) is str and entry["path"] not in seen,
                     "invalid recovery directory entry")
            seen.add(entry["path"])
            _require((entry["before"] is None) != (entry["after"] is None)
                     and self._valid_identity(entry["before"] or entry["after"], directory=True),
                     "invalid directory identity")
        _require(seen == expected_dirs, "recovery directory inventory differs from file ancestors")
        _require([e["path"] for e in plan["directories"]] == sorted(expected_dirs, key=lambda p: (p.count("/"), p)),
                 "recovery directory order is invalid")
        _require(all(v["device"] == self.root_identity["device"] for section in ("directories", "files")
                     for e in plan[section] for v in (e["before"], e["after"]) if v is not None),
                 "recovery inode belongs to another filesystem")
        _require(sum(v["size"] for e in plan["files"] for v in (e["before"], e["after"]) if v) <= MAX_TOTAL_BYTES,
                 "recovery byte bound exceeded")
        self.parents = {e["path"]: e["before"] or e["after"] for e in plan["directories"]}
        return plan

    @staticmethod
    def _marker(plan: dict[str, Any], state: str) -> bytes:
        return _json({"schemaVersion": 1, "transactionId": plan["transactionId"],
                      "planSha256": hashlib.sha256(_json(plan)).hexdigest(), "state": state})

    def _terminal(self, fd: int, plan: dict[str, Any]) -> str | None:
        present = []
        for state, pending in (("COMMITTED", "commit.pending"), ("ROLLED_BACK", "rollback.pending")):
            item, staged = _read(fd, state, MAX_CONTROL_BYTES), _read(fd, pending, MAX_CONTROL_BYTES)
            _require((item is None) != (staged is None), "missing or duplicated terminal-marker location")
            _require((item or staged)[1] == self._marker(plan, state), "terminal marker binding differs")
            if item:
                present.append(state)
        _require(len(present) <= 1, "contradictory terminal states")
        return present[0] if present else None

    def _publish_terminal(self, fd: int, plan: dict[str, Any], state: str) -> None:
        _require(self._terminal(fd, plan) is None, "transaction is already terminal")
        pending = "commit.pending" if state == "COMMITTED" else "rollback.pending"
        identity = _binding(fd, pending)
        assert identity is not None
        self._move(fd, pending, fd, state, identity)

    def _inventory(self, fd: int, plan: dict[str, Any]) -> None:
        allowed = {"header.json", "plan.json", "commit.pending", "rollback.pending", "COMMITTED", "ROLLED_BACK"}
        allowed |= {f"{prefix}-{i}" for i, e in enumerate(plan["files"]) if e["after"]
                    for prefix in ("new", "old") if prefix == "new" or e["before"]}
        allowed |= {f"directory-{i}" for i, e in enumerate(plan["directories"]) if e["after"]}
        _require(set(_list(fd)) <= allowed, "unexpected journal contents; preserve them")

    def _locations(self, fd: int, plan: dict[str, Any], *, final: str | None = None) -> None:
        self._inventory(fd, plan)
        # Missing new parents are valid only while their recorded empty inode is staged.
        self.parents = {}
        for i, entry in enumerate(plan["directories"]):
            path, before, after = entry["path"], entry["before"], entry["after"]
            current = self._current(path, directory=True)
            staged = _binding(fd, f"directory-{i}", directory=True) if after else None
            if before:
                _require(current == before, "original destination directory changed")
                self.parents[path] = before
            else:
                _require((current == after and staged is None) or (current is None and staged == after),
                         "created directory has missing, duplicated or changed identity")
                if staged:
                    child = os.open(f"directory-{i}", self.flags, dir_fd=fd)
                    try:
                        _require(not _list(child), "staged directory has unexpected contents")
                    finally:
                        os.close(child)
                _require(final is None or (final == "new" and current == after) or (final == "old" and staged == after),
                         "directory set does not match final state")
                self.parents[path] = current
        for i, entry in enumerate(plan["files"]):
            current = self._current(entry["path"])
            before, after = entry["before"], entry["after"]
            if after is None:
                _require(current == before, "preserved input changed")
                continue
            staged, backup = _binding(fd, f"new-{i}"), _binding(fd, f"old-{i}")
            old = current == before and staged == after and backup is None
            between = bool(before) and current is None and staged == after and backup == before
            new = current == after and staged is None and backup == before
            _require(old or between or new, "file state changed or original backup is missing; preserve user edits and journal")
            _require(final is None or (final == "old" and old) or (final == "new" and new),
                     "file set does not match final state")
        # Never retire an owned directory containing an unrelated editor's file.
        expected = {e["path"] for section in ("directories", "files") for e in plan[section]}
        for entry in plan["directories"]:
            if entry["after"] and self.parents[entry["path"]] is not None:
                with self._parent(entry["path"] + "/placeholder") as parent:
                    assert parent is not None
                    _require(all(entry["path"] + "/" + name in expected for name in _list(parent)),
                             "created directory contains unrelated user content; preserve it")

    def _prepare(self, changes: list[tuple[ObservedFile, bytes | None]]) -> dict[str, Any]:
        self.require_clean()
        _require(sum(len(payload or b"") + (item.before or {}).get("size", 0)
                     for item, payload in changes) <= MAX_TOTAL_BYTES, "total input/staging byte bound exceeded")
        for item, _ in changes:
            _require(item.before is None or item.before["device"] == self.root_identity["device"],
                     "input belongs to another filesystem")
            _require(self._current(item.path) == item.before, "input changed after planning")
        os.mkdir(PREPARING, 0o700, dir_fd=self.fd)
        with self._private(PREPARING) as fd:
            header = {"schemaVersion": 1, "transactionId": uuid.uuid4().hex, "root": self.root_identity}
            _write(fd, "header.tmp", _json(header))
            self.rename(fd, "header.tmp", fd, "header.json")
            _fsync(fd)
            _fsync(self.fd)
            # Exercise actual local filesystem semantics before touching destinations.
            os.mkdir("probe-a", 0o700, dir_fd=fd)
            os.mkdir("probe-b", 0o700, dir_fd=fd)
            try:
                self.rename(fd, "probe-a", fd, "probe-b")
            except FileExistsError:
                pass
            else:
                raise ValidationError("init transaction: filesystem did not enforce exclusive rename")
            self.rename(fd, "probe-a", fd, "probe-c")
            os.rmdir("probe-c", dir_fd=fd)
            os.rmdir("probe-b", dir_fd=fd)
            directories = []
            for i, path in enumerate(sorted(self.parents, key=lambda p: (p.count("/"), p))):
                before, after = self.parents[path], None
                if before is None:
                    os.mkdir(f"directory-{i}", 0o755, dir_fd=fd)
                    after = _binding(fd, f"directory-{i}", directory=True)
                directories.append({"path": path, "before": before, "after": after})
            files = []
            for i, (item, payload) in enumerate(changes):
                after = None
                if payload is not None:
                    mode = item.before["mode"] if item.before else 0o644
                    _write(fd, f"new-{i}", payload, mode, preserve_mode=item.before is not None)
                    after = _binding(fd, f"new-{i}")
                files.append({"path": item.path, "before": item.before, "after": after})
            plan = {**header, "directories": directories, "files": files}
            _require(len(_json(plan)) <= MAX_CONTROL_BYTES, "recovery plan exceeds its byte bound")
            _write(fd, "plan.tmp", _json(plan))
            self.rename(fd, "plan.tmp", fd, "plan.json")
            _write(fd, "commit.pending", self._marker(plan, "COMMITTED"))
            _write(fd, "rollback.pending", self._marker(plan, "ROLLED_BACK"))
            _fsync(fd)
            for item, _ in changes:
                _require(self._current(item.path) == item.before, "input changed during staging")
            # Creation and recovery must accept exactly the same contract.
            # Validate serialized bytes/locations before publishing READY.
            self._locations(fd, self._load(fd), final="old")
            _require(self._terminal(fd, plan) is None, "staged transaction cannot already be terminal")
        self._state_move(PREPARING, READY)
        return plan

    def _install(self, fd: int, plan: dict[str, Any]) -> None:
        self._locations(fd, plan, final="old")
        for i, entry in enumerate(plan["directories"]):
            if entry["after"]:
                with self._parent(entry["path"]) as parent:
                    _require(parent is not None, "new directory parent is missing")
                    self._move(fd, f"directory-{i}", parent, entry["path"].split("/")[-1],
                               entry["after"], directory=True, directory_path=entry["path"])
                self.parents[entry["path"]] = entry["after"]
        for i, entry in enumerate(plan["files"]):
            if entry["after"]:
                with self._parent(entry["path"]) as parent:
                    _require(parent is not None, "file parent is missing")
                    leaf = entry["path"].split("/")[-1]
                    _require(_binding(parent, leaf) == entry["before"], "destination changed before installation")
                    if entry["before"]:
                        self._move(parent, leaf, fd, f"old-{i}", entry["before"])
                    self._move(fd, f"new-{i}", parent, leaf, entry["after"])
        self._locations(fd, plan, final="new")
        self._publish_terminal(fd, plan, "COMMITTED")

    def _rollback(self, fd: int, plan: dict[str, Any]) -> None:
        _require(self._terminal(fd, plan) is None, "a terminal transaction cannot be rolled back")
        self._locations(fd, plan)
        for i, entry in reversed(list(enumerate(plan["files"]))):
            if entry["after"]:
                with self._parent(entry["path"]) as parent:
                    if parent is None:
                        continue
                    leaf = entry["path"].split("/")[-1]
                    current = _binding(parent, leaf)
                    if current == entry["after"]:
                        self._move(parent, leaf, fd, f"new-{i}", entry["after"])
                    if _binding(fd, f"old-{i}") is not None:
                        self._move(fd, f"old-{i}", parent, leaf, entry["before"])
        for i, entry in reversed(list(enumerate(plan["directories"]))):
            if entry["after"] and self.parents[entry["path"]] is not None:
                with self._parent(entry["path"]) as parent:
                    assert parent is not None
                    self._move(parent, entry["path"].split("/")[-1], fd, f"directory-{i}",
                               entry["after"], directory=True, directory_path=entry["path"])
                self.parents[entry["path"]] = None
        self._locations(fd, plan, final="old")
        self._publish_terminal(fd, plan, "ROLLED_BACK")

    def _preparing_inventory(self, fd: int) -> None:
        names = set(_list(fd))
        def slot(name: str, prefix: str) -> bool:
            match = re.fullmatch(prefix + r"-(0|[1-9][0-9]{0,2})", name)
            return match is not None and int(match[1]) < MAX_FILES

        if "header.json" not in names:
            _require(names <= {"header.tmp"}, "unrecognized preparation; preserve it for inspection")
        else:
            self._header(fd)
        staged_bytes = 0
        for name in names:
            value = _stat(fd, name)
            assert value is not None
            if slot(name, "directory") or name in PROBES:
                _require(stat.S_ISDIR(value.st_mode), "unsafe preparation directory")
                child = os.open(name, self.flags, dir_fd=fd)
                try:
                    _require(not _list(child), "preparation directory has unexpected contents")
                finally:
                    os.close(child)
            else:
                _require(name in CONTROLS - {"COMMITTED", "ROLLED_BACK"}
                         or slot(name, "new"),
                         "unrecognized preparation content; no original backup is legal here")
                item = _read(fd, name, MAX_CONTROL_BYTES if name in CONTROLS else MAX_FILE_BYTES)
                if name not in CONTROLS and item is not None:
                    staged_bytes += item[0]["size"]
                    _require(staged_bytes <= MAX_TOTAL_BYTES, "preparation byte bound exceeded")
        _require(len(names) <= 2 * MAX_FILES + len(CONTROLS) + len(PROBES), "preparation inventory bound exceeded")

    def _cleanup(self) -> None:
        with self._private(CLEANUP) as fd:
            names = set(_list(fd))
            _require(len(names) <= 2 * MAX_FILES + len(CONTROLS) + len(PROBES), "cleanup inventory bound exceeded")
            # Capture before validating the phase/content, not afterward: a
            # later read must not adopt an intervening editor's replacement.
            entries: dict[str, tuple[bool, dict[str, Any]]] = {}
            observed_bytes = 0
            for name in names:
                value = _stat(fd, name)
                _require(value is not None, "cleanup entry disappeared")
                directory = stat.S_ISDIR(value.st_mode)
                if directory:
                    binding = _dir_identity(value)
                else:
                    item = _read(fd, name, MAX_CONTROL_BYTES if name in CONTROLS else MAX_FILE_BYTES)
                    _require(item is not None, "cleanup entry disappeared")
                    binding = item[0]
                    observed_bytes += binding["size"]
                    _require(observed_bytes <= MAX_TOTAL_BYTES + len(CONTROLS) * MAX_CONTROL_BYTES,
                             "cleanup byte bound exceeded")
                entries[name] = (directory, binding)

            def verify_entry(name: str) -> bool:
                try:
                    self._private_check(fd, CLEANUP)
                    directory, expected = entries[name]
                    _require(_binding(fd, name, directory=directory,
                                      limit=MAX_CONTROL_BYTES if name in CONTROLS else MAX_FILE_BYTES) == expected,
                             "cleanup entry changed")
                except (OSError, ValidationError) as error:
                    raise InitConflict("init transaction: cleanup entry changed or cannot be verified; preserve private state and user edits") from error
                return directory

            data = names - CONTROLS
            terminal = bool(names & {"COMMITTED", "ROLLED_BACK"})
            plan = None
            if terminal:
                # Cleanup deletes data before control proof, and the terminal
                # marker after the plan. Accept only those exact suffixes.
                if "plan.json" in names:
                    plan = self._load(fd)
                    self._inventory(fd, plan)
                    states = names & {"COMMITTED", "ROLLED_BACK"}
                    _require(len(states) == 1, "contradictory cleanup terminal states")
                    state = next(iter(states))
                    _require(_read(fd, state, MAX_CONTROL_BYTES)[1] == self._marker(plan, state),
                             "cleanup terminal marker binding differs")
                    for state, pending in (("COMMITTED", "commit.pending"), ("ROLLED_BACK", "rollback.pending")):
                        item = _read(fd, pending, MAX_CONTROL_BYTES)
                        _require(not (item is not None and state in states), "duplicated cleanup marker")
                        _require(item is None or item[1] == self._marker(plan, state), "cleanup pending marker differs")
                    if data:
                        self._terminal(fd, plan)
                    for i, entry in enumerate(plan["files"]):
                        for prefix, binding in (("new", entry["after"]), ("old", entry["before"])):
                            name = f"{prefix}-{i}"
                            if name in data:
                                _require(binding is not None and _binding(fd, name) == binding,
                                         "cleanup captured file changed; preserve it")
                    for i, entry in enumerate(plan["directories"]):
                        name = f"directory-{i}"
                        if name in data:
                            _require(entry["after"] is not None and _binding(fd, name, directory=True) == entry["after"],
                                     "cleanup directory identity changed")
                            child = os.open(name, self.flags, dir_fd=fd)
                            try:
                                _require(not _list(child), "cleanup directory contains unrelated content")
                            finally:
                                os.close(child)
                else:
                    _require(not data and len(names & {"COMMITTED", "ROLLED_BACK"}) == 1
                             and names <= {"COMMITTED", "ROLLED_BACK", "header.json"},
                             "invalid cleanup control suffix; preserve it")
                    header = self._header(fd)
                    state = next(iter(names & {"COMMITTED", "ROLLED_BACK"}))
                    marker = _parse(_read(fd, state, MAX_CONTROL_BYTES)[1])
                    _require(set(marker) == {"schemaVersion", "transactionId", "planSha256", "state"}
                             and type(marker["schemaVersion"]) is int and marker["schemaVersion"] == 1
                             and marker["transactionId"] == header["transactionId"] and marker["state"] == state
                             and isinstance(marker["planSha256"], str)
                             and re.fullmatch(r"[0-9a-f]{64}", marker["planSha256"]) is not None,
                             "invalid cleanup terminal marker")
            else:
                self._preparing_inventory(fd)
                if "plan.json" in names:
                    self._load(fd)  # An atomically published plan is never partial.
            # Data first, then control objects. The cleanup pathname remains
            # irreversible even after the final marker/header has been removed.
            for name in sorted(data):
                if verify_entry(name):
                    os.rmdir(name, dir_fd=fd)  # Empty only; never recursive.
                else:
                    os.unlink(name, dir_fd=fd)
                _fsync(fd)
            for name in ("header.tmp", "plan.tmp", "commit.pending", "rollback.pending",
                         "plan.json", "COMMITTED", "ROLLED_BACK", "header.json"):
                if name in names:
                    _require(not verify_entry(name), "unsafe cleanup control")
                    os.unlink(name, dir_fd=fd)
                    _fsync(fd)
            self._private_check(fd, CLEANUP)
            _require(not _list(fd), "cleanup directory gained unrelated content")
            os.rmdir(CLEANUP, dir_fd=self.fd)
        _fsync(self.fd)

    def recover(self) -> str:
        state = self.state()
        if state is None:
            return "no-op"
        if state == PREPARING:
            with self._private(state) as fd:
                self._preparing_inventory(fd)
            result = "preparing-cleanup"
        elif state == READY:
            with self._private(state) as fd:
                plan = self._load(fd)
                terminal = self._terminal(fd, plan)
                self._inventory(fd, plan)
                if terminal is None:
                    self._rollback(fd, plan)
                    result = "rolled-back"
                else:
                    result = "committed-cleanup" if terminal == "COMMITTED" else "rolled-back-cleanup"
        else:
            result = "cleanup-only"
        if state != CLEANUP:
            self._state_move(state, CLEANUP)
        self._cleanup()
        return result

    def apply(self, changes: list[tuple[ObservedFile, bytes | None]]) -> None:
        validate_paths([item.path for item, _ in changes])
        _require(all(payload is None or type(payload) is bytes for _, payload in changes), "invalid staged content")
        self.require_clean()
        for item, _ in changes:
            _require(self._current(item.path) == item.before, "input changed after it was read")
        if all(payload is None for _, payload in changes):
            return
        terminal_seen = False
        try:
            plan = self._prepare(changes)
            with self._private(READY) as fd:
                self._install(fd, plan)
                terminal_seen = True
            self.recover()  # Committed cleanup only, never continuation/rebuild.
        except BaseException as original:
            if isinstance(original, InitConflict):
                raise ValidationError("init failed; recovery conflict: preserve private state and user edits before init --recover") from original
            detail = "original files restored"
            try:
                state = self.state()
                if state == READY:
                    with self._private(READY) as fd:
                        current_plan = self._load(fd)
                        terminal_seen = terminal_seen or self._terminal(fd, current_plan) == "COMMITTED"
                if state == CLEANUP or terminal_seen:
                    detail = "integration is terminal; cleanup/recovery may be incomplete"
                outcome = self.recover()
                if terminal_seen or outcome == "committed-cleanup":
                    detail = "complete integration was committed; inspect it, recovery is cleanup-only"
            except BaseException:
                detail = "automatic recovery incomplete; preserve the private transaction and user edits, then run init --recover"
            if isinstance(original, KeyboardInterrupt):
                raise InitInterrupted(f"init interrupted; {detail}") from original
            if not isinstance(original, Exception):
                raise
            raise ValidationError(f"init failed; {detail}") from original
