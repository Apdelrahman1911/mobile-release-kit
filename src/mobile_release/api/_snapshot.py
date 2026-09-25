"""Finite passive observations and shared policy/DTO assembly.

Only the selected root is admitted. No repository inference, project execution,
credential probing or arbitrary file-content export occurs here. Independent
reads are NOT an atomic snapshot or hostile-same-user containment. Windows uses
the original-parent reader and retains its separate native ABI/platform refusal.
"""
from __future__ import annotations

import hashlib
import os
import stat
import sys
import time
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Iterator

from ..config import parse_config_text
from ..discovery import IGNORED_PARTS, PRIVATE_PREFIXES, parse_project_sources
from ..errors import ConfigurationError
from ..init_transaction import is_state_name
from ._json import bounded_json_text
from .contracts import ApiError, ConfigObservation, Issue, ScanCounts, SnapshotResult, assurance, issue

MAX_DEPTH = 12
MAX_ENTRIES = 10_000
MAX_SOURCE_FILES = 128
MAX_SOURCE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_ROOT_BYTES = 4096
MAX_RELATIVE_BYTES = 512
MAX_ROOT_COMPONENTS = 128
MAX_ISSUES = 64
MAX_HINT_NODES = 4096
MAX_HINT_STRING = 512
MAX_HINT_ITEMS = 128
MAX_CONFIG_OUTPUT_NODES = 8000
SCAN_SECONDS = 5.0  # Cooperative margin inside the supervisor's absolute 10s endpoint.

LIMITS = {
    "maxDepth": MAX_DEPTH, "maxEntries": MAX_ENTRIES,
    "maxSourceFiles": MAX_SOURCE_FILES, "maxSourceFileBytes": MAX_SOURCE_BYTES,
    "maxTotalSourceBytes": MAX_TOTAL_BYTES, "maxRootBytes": MAX_ROOT_BYTES,
    "maxRelativePathBytes": MAX_RELATIVE_BYTES, "maxIssues": MAX_ISSUES,
    "maxHintNodes": MAX_HINT_NODES, "maxHintStringCharacters": MAX_HINT_STRING,
    "maxHintItems": MAX_HINT_ITEMS, "scanSeconds": SCAN_SECONDS,
    "maxConfigOutputNodes": MAX_CONFIG_OUTPUT_NODES,
}
_EXCLUDED = {name.casefold() for name in IGNORED_PARTS} | {
    ".venv", "venv", ".tox", ".cache", ".swiftpm", ".build", "dist", "target",
    ".mobile-release-signing", "__pycache__",
    "private", "secrets", "credentials",
}
_SOURCE_NAMES = {"build.gradle", "build.gradle.kts", "project.pbxproj", "project.yml"}
# Fixed successor activation, never an environment/request opt-in. This source
# bit is not a receipt for packaged-core, GUI or native-platform verification.
# The compiled desktop selector and original runtime owner gate its UI use;
# the native reader still independently admits the actual ABI/architecture.
_WINDOWS_SNAPSHOT_QUALIFIED = True


def posix_snapshot_available() -> bool:
    return (
        (sys.platform.startswith("linux") or sys.platform == "darwin")
        and os.name == "posix"
        and all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
        and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
        and os.scandir in os.supports_fd
    )


def windows_snapshot_available() -> bool:
    # Capability discovery never imports ctypes, probes a DLL or opens a path.
    return _WINDOWS_SNAPSHOT_QUALIFIED and sys.platform == "win32" and os.name == "nt"


def snapshot_available() -> bool:
    return posix_snapshot_available() or windows_snapshot_available()


def _safe_component(name: str) -> bool:
    try:
        return (name not in {"", ".", ".."} and len(name.encode("utf-8")) <= 255
                and not any(ord(c) < 32 or ord(c) == 127 or c in "\\:" for c in name))
    except UnicodeError:
        return False


def _excluded(parts: tuple[str, ...]) -> bool:
    lowered = tuple(part.casefold() for part in parts)
    return any(part.startswith(".") or part.casefold() in _EXCLUDED or is_state_name(part) for part in parts) or any(
        lowered[:len(prefix)] == prefix for prefix in PRIVATE_PREFIXES
    )


def validate_root(root: object) -> str:
    if type(root) is not str:
        raise ApiError("invalid_params", "root must be an explicitly selected absolute folder path")
    try:
        valid_size = 1 < len(root.encode("utf-8")) <= MAX_ROOT_BYTES
    except UnicodeError:
        valid_size = False
    # Do not normalize dot components or a leading // into a different root.
    parts = root.split("/")
    if (not valid_size or not root.startswith("/") or root.startswith("//")
            or len(parts) - 1 > MAX_ROOT_COMPONENTS
            or not all(_safe_component(part) for part in parts[1:])):
        raise ApiError("unsafe_path", "root must be a bounded absolute path without dot or link aliases")
    return root


def validate_config_path(value: object) -> str:
    if type(value) is not str:
        raise ApiError("invalid_params", "configPath must be a repository-relative JSON path")
    try:
        valid_size = 0 < len(value.encode("utf-8")) <= MAX_RELATIVE_BYTES
    except UnicodeError:
        valid_size = False
    parts = tuple(value.split("/"))
    if (not valid_size or len(parts) > MAX_DEPTH or not all(_safe_component(part) for part in parts)
            or _excluded(parts) or parts[-1] != "mobile-release.json"):
        raise ApiError("unsafe_path", "configPath must name mobile-release.json inside the selected nonprivate project tree")
    return value


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _same_directory(left: os.stat_result, right: os.stat_result) -> bool:
    return (stat.S_ISDIR(left.st_mode) and stat.S_ISDIR(right.st_mode)
            and left.st_dev == right.st_dev and left.st_ino == right.st_ino)


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)


class _DescriptorCleanupError(RuntimeError):
    """Do not downgrade descriptor uncertainty into an ordinary partial scan."""


def _close_handles(handles: list[int], *, budget=None) -> None:
    """Retire each slot before its only close; attempt all independent closes.

    A close exception may have followed a successful kernel close. Never retry
    that descriptor number or let another success hide the unknown disposition.
    """
    first_error: BaseException | None = None
    failures = 0
    while handles:
        descriptor = handles.pop()
        try:
            if budget is None:
                os.close(descriptor)
            else:
                budget.close_fd(descriptor)
        except BaseException as error:
            failures += 1
            if first_error is None:
                first_error = error
    if first_error is not None:
        first_error.add_note(f"Static snapshot descriptor cleanup had {failures} unproven close outcome(s); no successful observation is returned.")
        raise _DescriptorCleanupError("Static snapshot descriptor cleanup did not settle") from first_error


@dataclass
class _Inventory:
    sources: dict[str, str] = field(default_factory=dict)
    directories: set[str] = field(default_factory=set)
    issues: list[Issue] = field(default_factory=list)
    counts: ScanCounts = field(default_factory=lambda: {
        "entries": 0, "sourceFiles": 0, "sourceBytes": 0, "excludedEntries": 0,
    })
    partial: bool = False
    stopped: bool = False
    deadline: float = field(default_factory=lambda: time.monotonic() + SCAN_SECONDS)
    # Uncapped positive original ancestry/close settlement, not issue inference.
    root_settled: bool = False
    budget: object = None  # Only borrowed_preflight_reads installs the exact type.

    def note(self, code: str, message: str) -> None:
        self.partial = True
        if len(self.issues) < MAX_ISSUES:
            self.issues.append(issue(code, message, partial=True))

    def tick(self) -> bool:
        if self.budget is not None:
            self.budget.check()
        if not self.stopped and time.monotonic() >= self.deadline:
            self.note("snapshot.deadline", "Static scan reached its cooperative time limit; observations are incomplete.")
            self.stopped = True
        return not self.stopped


@contextmanager
def _root_handles(root: str, inventory: _Inventory) -> Iterator[int]:
    handles: list[int] = []
    links: list[tuple[int, str, int]] = []
    rechecked = False
    try:
        descriptor = os.open("/", _directory_flags())
        handles.append(descriptor)
        for part in root.split("/")[1:]:
            if not inventory.tick():
                raise ApiError("snapshot_unavailable", "Selected folder admission exceeded the static scan deadline")
            parent = descriptor
            before = os.stat(part, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise ApiError("unsafe_path", "Selected folder must not traverse a symbolic link or special file")
            descriptor = os.open(part, _directory_flags(), dir_fd=parent)
            handles.append(descriptor)
            if not _same_directory(before, os.fstat(descriptor)):
                raise ApiError("unsafe_path", "Selected folder changed during admission")
            links.append((parent, part, descriptor))
        yield descriptor
        rechecked = True
        for parent, part, child in links:
            try:
                if not _same_directory(os.stat(part, dir_fd=parent, follow_symlinks=False), os.fstat(child)):
                    rechecked = False
                    inventory.note("snapshot.changed", "Selected folder or an ancestor changed during this non-atomic observation.")
            except OSError:
                rechecked = False
                inventory.note("snapshot.changed", "Selected folder or an ancestor is no longer observable at its original path.")
    except ApiError:
        raise
    except OSError as error:
        raise ApiError("snapshot_unavailable", "Selected folder could not be opened safely; no alternate path was used") from error
    finally:
        _close_handles(handles)
    inventory.root_settled = rechecked


class _ReadProblem(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def _named_identity(value: os.stat_result) -> tuple[int, ...]:
    # The narrower named editor additionally retains ownership facts without
    # widening or changing the existing generic snapshot reader contract.
    return (*_identity(value), value.st_uid, value.st_gid)


def _read_file(parent: int, name: str, relative: str, inventory: _Inventory, *,
               limit: int = MAX_SOURCE_BYTES,
               receipts: list[tuple[int, str, tuple[int, ...] | None]] | None = None,
               binary: bool = False) -> str | bytes:
    if not inventory.tick():
        raise _ReadProblem("snapshot.deadline", "Static read was not attempted after its scan deadline.")
    if inventory.counts["sourceFiles"] >= MAX_SOURCE_FILES:
        inventory.stopped = True
        raise _ReadProblem("snapshot.file-limit", "Static source-file count limit reached.")
    inventory.counts["sourceFiles"] += 1
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise _ReadProblem("snapshot.unsafe-file", f"Skipped nonordinary, linked or symbolic source path: {relative}")
    if before.st_size > limit:
        raise _ReadProblem("snapshot.file-size", f"Static source file exceeds its byte limit: {relative}")
    total_limit = MAX_TOTAL_BYTES if inventory.budget is None else 64 * 1024 * 1024
    if before.st_size > total_limit - inventory.counts["sourceBytes"]:
        inventory.stopped = True
        raise _ReadProblem("snapshot.byte-limit", "Static aggregate source-byte limit reached.")
    try:
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        descriptor = (os.open(name, flags, dir_fd=parent) if inventory.budget is None
                      else inventory.budget.open_fd(name, flags, parent=parent))
    except FileNotFoundError as error:
        raise _ReadProblem("snapshot.changed", f"Source path disappeared after initial observation: {relative}") from error
    try:
        opened = os.fstat(descriptor)
        if _identity(before) != _identity(opened):
            raise _ReadProblem("snapshot.changed", f"Source path changed before its read: {relative}")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            if not inventory.tick():
                raise _ReadProblem("snapshot.deadline", "Static file read exceeded the scan deadline.")
            remaining = total_limit - inventory.counts["sourceBytes"]
            if remaining <= 0:
                inventory.stopped = True
                raise _ReadProblem("snapshot.byte-limit", "Static aggregate source-byte limit reached before EOF was observed.")
            requested = min(64 * 1024, limit + 1 - consumed, remaining)
            if inventory.budget is not None:
                inventory.budget.read_request(requested)
            chunk = os.read(descriptor, requested)
            inventory.counts["sourceBytes"] += len(chunk)
            consumed += len(chunk)
            if consumed > limit:
                raise _ReadProblem("snapshot.file-size", f"Static source grew beyond its byte limit: {relative}")
            if not chunk:
                break
            chunks.append(chunk)
        ending = os.fstat(descriptor)
        try:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            raise _ReadProblem("snapshot.changed", f"Source path disappeared after reading: {relative}") from error
        if (_identity(opened) != _identity(ending) or _identity(ending) != _identity(current)
                or consumed != ending.st_size):
            raise _ReadProblem("snapshot.changed", f"Source path or bytes changed during reading: {relative}")
        try:
            raw = b"".join(chunks)
            text = raw if binary else raw.decode("utf-8")
        except UnicodeError as error:
            raise _ReadProblem("snapshot.encoding", f"Static source is not UTF-8 text: {relative}") from error
        if receipts is not None:
            receipts.append((parent, name, _named_identity(ending)))
        return text
    finally:
        _close_handles([descriptor], budget=inventory.budget)


class _NamedTextReads:
    """Small named-reader seam retaining original parents until final recheck.

    It does not enumerate a metadata tree, supply new native write authority or
    reopen a replacement root. Only the fixed caller-derived names are read.
    Immediate names are inspected under the shared entry/deadline budget solely
    to reject portable aliases; no sibling contents are opened.
    """

    def __init__(self, root: int, inventory: _Inventory):
        self.root, self.inventory = root, inventory
        self.handles: list[int] = []
        self.links: list[tuple[int, str, int, tuple[int, ...]]] = []
        self.leaves: list[tuple[int, str, tuple[int, ...] | None]] = []
        original = os.fstat(root)
        self.root_identity = _named_identity(original)
        self.device, self.owner = original.st_dev, original.st_uid
        self._admit(original, directory=True)

    def _admit(self, value: os.stat_result, *, directory: bool) -> None:
        ordinary = stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode) and value.st_nlink == 1
        if (not ordinary or value.st_dev != self.device or value.st_uid != self.owner
                or stat.S_IMODE(value.st_mode) & 0o7000):
            raise _ReadProblem("snapshot.unsafe-file", "Named observation requires ordinary same-device, same-owner objects.")

    def _alias(self, parent: int, name: str) -> None:
        key = unicodedata.normalize("NFC", name).casefold()
        if self.inventory.budget is not None:
            with self.inventory.budget.entries(parent) as entries:
                for entry in entries:
                    if not self.inventory.tick():
                        raise _ReadProblem("snapshot.deadline", "Named observation exhausted its deadline.")
                    if entry.name != name and unicodedata.normalize("NFC", entry.name).casefold() == key:
                        raise _ReadProblem("snapshot.unsafe-file", "Named observation found a portable alias.")
            return
        entries = os.scandir(parent)
        try:
            for entry in entries:
                if not self.inventory.tick() or self.inventory.counts["entries"] >= MAX_ENTRIES:
                    raise _ReadProblem("snapshot.entry-limit", "Named observation exhausted its entry budget.")
                self.inventory.counts["entries"] += 1
                if entry.name != name and unicodedata.normalize("NFC", entry.name).casefold() == key:
                    raise _ReadProblem("snapshot.unsafe-file", "Named observation found a portable alias.")
        finally:
            try:
                entries.close()  # The original iterator, once only; no retry.
            except BaseException as error:
                raise _DescriptorCleanupError("Named observation directory iterator cleanup did not settle") from error

    def read(self, relative: str, *, limit: int, binary: bool = False) -> str | bytes | None:
        if self.inventory.budget is not None:
            limit = self.inventory.budget.file_admission(self.inventory.budget.root / relative, limit)
        parent = self.root
        parts = relative.split("/")
        for index, name in enumerate(parts):
            if not self.inventory.tick():
                raise _ReadProblem("snapshot.deadline", "Named observation exhausted its deadline.")
            self._alias(parent, name)
            try:
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                self.leaves.append((parent, name, None))
                return None
            self._admit(before, directory=index != len(parts) - 1)
            if index == len(parts) - 1:
                try:
                    text = _read_file(parent, name, relative, self.inventory,
                                      limit=limit, receipts=self.leaves, binary=binary)
                except FileNotFoundError as error:
                    raise _ReadProblem("snapshot.changed", "Named file disappeared during admission.") from error
                if self.leaves[-1][2] != _named_identity(before):
                    raise _ReadProblem("snapshot.changed", "Named file changed before reading.")
                return text
            try:
                child = (os.open(name, _directory_flags(), dir_fd=parent) if self.inventory.budget is None
                         else self.inventory.budget.open_fd(name, _directory_flags(), parent=parent))
            except FileNotFoundError as error:
                raise _ReadProblem("snapshot.changed", "Named parent disappeared during admission.") from error
            self.handles.append(child)
            if _named_identity(before) != _named_identity(os.fstat(child)):
                raise _ReadProblem("snapshot.changed", "Named parent changed during admission.")
            self.links.append((parent, name, child, _named_identity(before)))
            parent = child
        raise _ReadProblem("snapshot.unsafe-file", "Named path is empty.")

    def directory(self, relative: str) -> int:
        """Borrowed preflight traversal only; same named-parent admission rules."""
        if self.inventory.budget is None:
            raise _ReadProblem("snapshot.unsafe-file", "Directory borrowing requires the original preflight domain.")
        checked = self.inventory.budget.relative(self.inventory.budget.root / relative)
        if checked != "." and len(checked.split("/")) > 32:
            self.inventory.budget.fail()  # Before any parent/iterator acquisition.
        parent = self.root
        if relative == ".":
            return parent
        for name in relative.split("/"):
            self.inventory.budget.check()
            self._alias(parent, name)
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            self._admit(before, directory=True)
            child = self.inventory.budget.open_fd(name, _directory_flags(), parent=parent)
            self.handles.append(child)
            if _named_identity(before) != _named_identity(os.fstat(child)):
                raise _ReadProblem("snapshot.changed", "Named parent changed during admission.")
            self.links.append((parent, name, child, _named_identity(before)))
            parent = child
        return parent

    def check(self) -> None:
        if not self.inventory.tick():
            raise _ReadProblem("snapshot.deadline", "Named observation exhausted its deadline.")
        if _named_identity(os.fstat(self.root)) != self.root_identity:
            raise _ReadProblem("snapshot.changed", "Named root changed during observation.")
        for parent, name, child, expected in self.links:
            self._alias(parent, name)
            try:
                current, opened = os.stat(name, dir_fd=parent, follow_symlinks=False), os.fstat(child)
            except OSError as error:
                raise _ReadProblem("snapshot.changed", "Original named parent cannot be rechecked.") from error
            if (_named_identity(current) != expected or _named_identity(opened) != expected):
                raise _ReadProblem("snapshot.changed", "Original named parent changed.")
        for parent, name, expected in self.leaves:
            self._alias(parent, name)
            try:
                current = _named_identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
            except FileNotFoundError:
                current = None
            if current != expected:
                raise _ReadProblem("snapshot.changed", "Original named file or absence changed.")


@contextmanager
def _named_text_reads(root: int, inventory: _Inventory) -> Iterator[_NamedTextReads]:
    reader = _NamedTextReads(root, inventory)
    try:
        yield reader
        reader.check()
    finally:
        _close_handles(reader.handles, budget=inventory.budget)


@contextmanager
def borrowed_preflight_reads(budget) -> Iterator[_NamedTextReads]:
    """No root reopen: borrow the actual original non-signing project custody."""
    from .._desktop_preflight_budget import OfflinePreflightBudget
    if type(budget) is not OfflinePreflightBudget or budget.invocation is None:
        raise ValueError("Named reader has no original offline preflight invocation")
    budget.checkpoint()
    root, _ = budget.invocation._offline_preflight_root(budget.guard)
    inventory = _Inventory(budget=budget)
    try:
        with _named_text_reads(root, inventory) as reader:
            yield reader
    except _DescriptorCleanupError as error:
        budget.guard._abort(error)
        raise
    budget.checkpoint()


def _config(root: int, relative: str, inventory: _Inventory) -> ConfigObservation:
    result: ConfigObservation = {"path": relative, "state": "unavailable", "data": None, "content": None, "issues": []}
    handles: list[int] = []
    links: list[tuple[int, str, int]] = []
    parent = root
    try:
        for part in relative.split("/")[:-1]:
            if not inventory.tick():
                raise _ReadProblem("snapshot.deadline", "Configuration path was not opened after the scan deadline.")
            before = os.stat(part, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise _ReadProblem("snapshot.unsafe-file", "Configuration parents must be real directories, not symbolic links.")
            try:
                child = os.open(part, _directory_flags(), dir_fd=parent)
            except FileNotFoundError as error:
                raise _ReadProblem("snapshot.changed", "Configuration parent disappeared during admission.") from error
            handles.append(child)
            if not _same_directory(before, os.fstat(child)):
                raise _ReadProblem("snapshot.changed", "Configuration parent changed during admission.")
            links.append((parent, part, child))
            parent = child
        raw = _read_file(parent, relative.split("/")[-1], relative, inventory)
        for parent, name, child in links:
            try:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except OSError as error:
                raise _ReadProblem("snapshot.changed", "Configuration parent disappeared after reading.") from error
            if not _same_directory(current, os.fstat(child)):
                raise _ReadProblem("snapshot.changed", "Configuration parent moved during reading.")
        try:
            data = parse_config_text(raw)
        except ConfigurationError as error:
            result["state"] = "invalid"
            result["issues"].append(issue("config.invalid", str(error)))
        else:
            try:
                bounded_json_text(data, max_nodes=MAX_CONFIG_OUTPUT_NODES)
            except ConfigurationError:
                message = "Configuration exceeds the passive snapshot output budget; no configuration data was returned."
                inventory.note("snapshot.config-output-limit", message)
                result["issues"].append(issue("snapshot.config-output-limit", message, partial=True))
            else:
                result["data"] = data
                result["state"] = "format-valid"
                exact = raw.encode("utf-8")
                if exact:
                    result["content"] = {"bytes": len(exact), "sha256": hashlib.sha256(exact).hexdigest()}
    except FileNotFoundError:
        result["state"] = "missing"
        result["issues"].append(issue("config.missing", "No configuration was observed at the selected path.", partial=True))
    except _ReadProblem as error:
        inventory.note(error.code, error.message)
        result["issues"].append(issue(error.code, error.message, partial=True))
    except OSError:
        message = "Configuration could not be read safely; its contents were not returned."
        inventory.note("snapshot.unreadable", message)
        result["issues"].append(issue("snapshot.unreadable", message, partial=True))
    finally:
        _close_handles(handles)
    return result


def _source_candidate(relative: str) -> bool:
    path = PurePosixPath(relative)
    return (path.name in _SOURCE_NAMES or relative == "gradle/libs.versions.toml"
            or path.suffix in {".xcconfig", ".xcscheme"}
            or (path.suffix == ".properties" and "version" in path.name.lower()))


def _walk(descriptor: int, parts: tuple[str, ...], inventory: _Inventory, config_path: str) -> None:
    if not inventory.tick():
        return
    before = os.fstat(descriptor)
    try:
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if not inventory.tick():
                    break
                if inventory.counts["entries"] >= MAX_ENTRIES:
                    inventory.note("snapshot.entry-limit", "Static directory-entry limit reached.")
                    inventory.stopped = True
                    break
                inventory.counts["entries"] += 1
                child_parts = (*parts, entry.name)
                relative = "/".join(child_parts)
                if not _safe_component(entry.name) or len(relative.encode("utf-8")) > MAX_RELATIVE_BYTES:
                    inventory.note("snapshot.path-limit", "An unsafe or oversized project path was excluded.")
                    inventory.counts["excludedEntries"] += 1
                    continue
                # Prune names BEFORE examining or enumerating their subtrees.
                if _excluded(child_parts):
                    inventory.counts["excludedEntries"] += 1
                    continue
                try:
                    observed = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
                    if stat.S_ISLNK(observed.st_mode):
                        inventory.counts["excludedEntries"] += 1
                        inventory.note("snapshot.link-excluded", f"Symbolic link was not followed: {relative}")
                    elif stat.S_ISDIR(observed.st_mode):
                        if len(child_parts) > MAX_DEPTH:
                            inventory.note("snapshot.depth-limit", "Static directory-depth limit reached.")
                            inventory.counts["excludedEntries"] += 1
                            continue
                        child = os.open(entry.name, _directory_flags(), dir_fd=descriptor)
                        try:
                            if not _same_directory(observed, os.fstat(child)):
                                inventory.note("snapshot.changed", f"Directory changed before traversal: {relative}")
                                continue
                            if relative.endswith((".xcodeproj", ".xcworkspace")):
                                if len(inventory.directories) >= MAX_SOURCE_FILES:
                                    inventory.note("snapshot.container-limit", "Static project-container hint limit reached.")
                                else:
                                    inventory.directories.add(relative)
                            _walk(child, child_parts, inventory, config_path)
                            if not _same_directory(os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False), os.fstat(child)):
                                inventory.note("snapshot.changed", f"Directory moved during traversal: {relative}")
                        finally:
                            _close_handles([child])
                    elif relative != config_path and _source_candidate(relative):
                        inventory.sources[relative] = _read_file(descriptor, entry.name, relative, inventory)
                except _ReadProblem as error:
                    inventory.note(error.code, error.message)
                except OSError:
                    inventory.note("snapshot.unreadable", f"Project entry could not be read safely: {relative}")
    except OSError:
        inventory.note("snapshot.unreadable", "A project directory could not be enumerated safely.")
    finally:
        if _identity(before) != _identity(os.fstat(descriptor)):
            inventory.note("snapshot.changed", "Directory entries changed during this non-atomic observation.")


def _bound_hints(value: object, inventory: _Inventory) -> object:
    """Discard oversized hints, never truncate an identifier into another value."""
    remaining = MAX_HINT_NODES

    def visit(item: object) -> object:
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            inventory.note("snapshot.hint-limit", "Static hint output limit reached.")
            return None
        if isinstance(item, str) and len(item) > MAX_HINT_STRING:
            inventory.note("snapshot.hint-limit", "An oversized static hint was omitted.")
            return None
        if isinstance(item, dict):
            return {key: checked for key, val in item.items() if (checked := visit(val)) is not None}
        if isinstance(item, list):
            if len(item) > MAX_HINT_ITEMS:
                inventory.note("snapshot.hint-limit", "Static hint list limit reached.")
            return [checked for val in item[:MAX_HINT_ITEMS] if (checked := visit(val)) is not None]
        return item

    return visit(value)


def project_snapshot(root: object, config_path: object = "release/mobile-release.json") -> SnapshotResult:
    if windows_snapshot_available():
        from ._snapshot_windows import project_snapshot as windows_snapshot
        return windows_snapshot(root, config_path)
    if not posix_snapshot_available():
        raise ApiError("platform_unavailable", "Static filesystem snapshots are unavailable on this platform/profile")
    selected_root = validate_root(root)
    selected_config = validate_config_path(config_path)
    observed_at = datetime.now(timezone.utc).isoformat()
    inventory = _Inventory()
    with _root_handles(selected_root, inventory) as descriptor:
        config = _config(descriptor, selected_config, inventory)
        _walk(descriptor, (), inventory, selected_config)
    return _assemble_snapshot(selected_root, observed_at, inventory, config)


def _assemble_snapshot(selected_root: str, observed_at: str, inventory: _Inventory,
                       config: ConfigObservation) -> SnapshotResult:
    if not inventory.root_settled:
        config["content"] = None
    try:
        hints = parse_project_sources(inventory.sources, inventory.directories)
        bounded = _bound_hints(hints, inventory)
    except (ValueError, RecursionError):
        inventory.note("snapshot.parse-limit", "Static source parsing could not produce a bounded hint set.")
        bounded = {}
    # Cooperative parsing over finite input may use the remaining scan allowance.
    inventory.tick()
    return {
        "root": selected_root, "observedAt": observed_at,
        "observationScope": "single-request-non-atomic", "config": config,
        "discovery": {"state": "unverified", "partial": inventory.partial,
                      "hints": bounded if isinstance(bounded, dict) else {},
                      "scan": inventory.counts, "limits": dict(LIMITS)},
        "assurance": assurance("static-text"), "issues": inventory.issues,
    }
