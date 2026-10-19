"""Fixed saved-source capture for the original tool-acquisition child.

No discovery walk, environment lookup, project code or executable is used.
The containing native owner retains the registered root and validates this
private footprint before intent/GO; these bytes alone do not grant admission.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat

from .build_inputs import _Directory, _FD
from .cancellation import DefaultCancellation
from .config import parse_config_text
from .errors import ConfigurationError
from .tool_requirements import FILE_LIMIT, TOTAL_LIMIT, observe_tool_requirements
from ._tool_acquisition_spec import AcquisitionError, CHUNK, require

FIXED = ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
         "gradle.properties", "gradle/libs.versions.toml", "gradle/wrapper/gradle-wrapper.properties")
CONFIG = "release/mobile-release.json"


def module_files(module: object) -> tuple[str, str]:
    """Validate before deriving a path: config's broader dotted grammar isn't IO authority."""
    require(type(module) is str and module.startswith(":"), "input")
    parts = [] if module == ":" else module[1:].split(":")
    require(len(parts) <= 12 and all(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", part, re.ASCII) for part in parts), "input")
    prefix = "/".join(parts)
    first = (prefix + "/" if prefix else "") + "build.gradle"
    require(len(first) + 4 <= 256, "input")
    return first, first + ".kts"


def directory_identity(value: os.stat_result) -> dict:
    require(stat.S_ISDIR(value.st_mode), "stale")
    return {"device": str(value.st_dev), "inode": str(value.st_ino), "mode": value.st_mode,
            "uid": value.st_uid, "gid": value.st_gid}


def file_identity(value: os.stat_result) -> dict:
    require(stat.S_ISREG(value.st_mode) and 0 <= value.st_size <= FILE_LIMIT, "input")
    return {"device": str(value.st_dev), "inode": str(value.st_ino), "mode": value.st_mode,
            "uid": value.st_uid, "gid": value.st_gid, "links": value.st_nlink,
            "bytes": value.st_size, "mtimeNs": str(value.st_mtime_ns), "ctimeNs": str(value.st_ctime_ns)}


def _named(parent: int, name: str):
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None


class Capture:
    """Original, finite no-follow descriptors plus observed absences, never a path grant."""
    def __init__(self, root: Path, identity: dict, config: dict, guard: DefaultCancellation):
        require(type(guard) is DefaultCancellation and type(identity) is dict and type(config) is dict)
        self.guard, self.expected_root, self.expected_config = guard, identity, config
        self.root = _Directory(root, guard, system_root_aliases=True)
        self.slots: list[_FD] = []
        self.directories: dict[str, tuple[int, int, str, dict]] = {}
        self.missing: dict[str, tuple[int, str]] = {}
        self.files: dict[str, tuple[int, int, str, dict, str]] = {}
        self.texts: dict[str, str] = {}
        self.total, self.entered, self.closed = 0, False, False
        self.module: str | None = None
        self.selected: str | None = None
        self.hints: dict | None = None

    def _open(self, parent: int, name: str, directory: bool) -> int:
        self.guard.check()
        require(len(self.slots) < 144, "limit")
        slot = _FD(self.guard)
        self.slots.append(slot)  # Same original rooted before the acquiring call.
        slot.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if directory else 0), dir_fd=parent)
        require(slot.number is not None, "unknown")
        return slot.number

    def _hash(self, fd: int, expected: dict, *, collect: bool) -> tuple[str, bytes]:
        self.guard.check()
        require(file_identity(os.fstat(fd)) == expected, "stale")
        os.lseek(fd, 0, os.SEEK_SET)
        digest, size, chunks = hashlib.sha256(), 0, []
        while True:
            self.guard.check()
            raw = os.read(fd, min(CHUNK, expected["bytes"] - size + 1))
            if not raw:
                break
            size += len(raw)
            require(size <= expected["bytes"], "stale")
            digest.update(raw)
            if collect:
                chunks.append(raw)
        require(size == expected["bytes"] and file_identity(os.fstat(fd)) == expected, "stale")
        return digest.hexdigest(), b"".join(chunks)

    def _read(self, relative: str) -> str | None:
        self.guard.check()
        parts = relative.split("/")
        require(len(parts) <= 14 and all(part and part not in (".", "..") for part in parts), "input")
        parent = self.root.fd
        for index, name in enumerate(parts):
            path = "/".join(parts[:index + 1])
            if path in self.missing:
                return None
            if index < len(parts) - 1 and path in self.directories:
                parent = self.directories[path][0]
                continue
            before = _named(parent, name)
            if before is None:
                self.missing[path] = parent, name
                return None
            if index < len(parts) - 1:
                identity = directory_identity(before)
                fd = self._open(parent, name, True)
                require(directory_identity(os.fstat(fd)) == identity
                        and directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity, "stale")
                self.directories[path] = fd, parent, name, identity
                parent = fd
                continue
            identity = file_identity(before)
            self.total += identity["bytes"]
            require(self.total <= TOTAL_LIMIT + FILE_LIMIT, "limit")  # Config has its own 512KiB cap.
            fd = self._open(parent, name, False)
            self.files[relative] = fd, parent, name, identity, ""
            digest, raw = self._hash(fd, identity, collect=True)
            require(file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity, "stale")
            self.files[relative] = fd, parent, name, identity, digest
            require(b"\0" not in raw, "input")
            try:
                return raw.decode("utf-8")
            except UnicodeError:
                raise AcquisitionError("input") from None
        raise AcquisitionError("input")

    def run(self) -> dict:
        require(not self.entered and not self.closed, "already-used")
        self.entered = True
        self.root.acquire()
        require(directory_identity(os.fstat(self.root.fd)) == self.expected_root, "stale")
        saved = self._read(CONFIG)
        require(saved is not None, "stale")
        metadata = self.files[CONFIG]
        require({"bytes": metadata[3]["bytes"], "sha256": metadata[4]} == self.expected_config, "stale")
        try:
            config = parse_config_text(saved)
        except (ConfigurationError, ValueError, TypeError, RecursionError):
            raise AcquisitionError("input") from None
        require(config.get("android", {}).get("enabled") is True, "unsupported")
        self.module = config["android"].get("module")
        candidates = module_files(self.module)  # BEFORE any module path is opened.
        for name in sorted(set(FIXED) | set(candidates)):
            value = self._read(name)
            if value is not None:
                self.texts[name] = value
        # The same pure parser rejects absent/both siblings and dynamic hints.
        self.selected = candidates[1] if candidates[1] in self.texts and candidates[0] not in self.texts else candidates[0]
        self.hints = observe_tool_requirements(self.texts, platform="android", android_build_file=self.selected, complete=True)
        self.check()
        return self.hints

    def check(self) -> None:
        self.guard.check()
        require(self.entered and not self.closed, "stale")
        self.root.check()
        require(directory_identity(os.fstat(self.root.fd)) == self.expected_root, "stale")
        for fd, parent, name, expected in self.directories.values():
            self.guard.check()
            require(directory_identity(os.fstat(fd)) == expected
                    and directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected, "stale")
        for parent, name in self.missing.values():
            self.guard.check()
            require(_named(parent, name) is None, "stale")
        for fd, parent, name, expected, digest in self.files.values():
            require(digest and file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected
                    and self._hash(fd, expected, collect=False)[0] == digest, "stale")

    def footprint(self) -> dict:
        require(self.hints is not None and self.module is not None and self.selected is not None, "input")
        return {"module": self.module, "buildFile": self.selected,
                "sourcesSha256": self.hints["sourcesSha256"],
                "directories": [{"relative": path, "identity": data[3]} for path, data in sorted(self.directories.items())],
                "missing": sorted(self.missing),
                "files": [{"relative": path, "identity": data[3], "sha256": data[4]} for path, data in sorted(self.files.items())]}

    def close(self) -> None:
        if self.closed:
            return
        first = None
        for close in [*(slot.close for slot in reversed(self.slots)), self.root.close]:
            try:
                close()
            except BaseException as error:
                if first is None:
                    first = error
                self.guard._abort(error)
        self.closed = (first is None and all(slot.close_state == "CLOSED" for slot in self.slots)
                       and all(slot.close_state == "CLOSED" for slot in self.root.slots))
        if first is not None:
            raise first
        require(self.closed, "unknown")
