"""Actual saved/selected originals for the one artifact-inspection operation.

The native tuple is comparison DATA.  This reader acquires its own nofollow
originals and keeps them until the same operation's consumers have settled.
Neither an input path nor an already parsed configuration lends an FD.
"""
from __future__ import annotations

import hashlib
import os
import stat
import sys
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from ._desktop_artifact_inspection_protocol import require
from .api._release_version import _source_path
from .artifact_inspection import GIB, KIB, MIB, MAX_NAMESPACE_ENTRIES, MAX_NAMESPACE_NAMES
from .build_inputs import _Directory, _FD, _cleanup_failure
from .config import (MAX_CONFIG_BYTES, MAX_VERSION_BYTES, ReleaseConfig, ReleaseVersion,
                     parse_config_text, parse_key_value_text, release_version_from_values)
from .errors import ConfigurationError, ValidationError
from .metadata import check_metadata_text


class ArtifactInspectionRefused(ValidationError):
    def __init__(self, reason: str) -> None:
        from ._desktop_artifact_inspection_protocol import REASONS
        require(reason in REASONS and reason != "none")
        self.reason = reason
        super().__init__("The selected artifact observation was refused")


def _identity(value: os.stat_result) -> dict:
    modified = divmod(value.st_mtime_ns, 1_000_000_000)
    changed = divmod(value.st_ctime_ns, 1_000_000_000)
    return {"device": str(value.st_dev), "inode": str(value.st_ino), "mode": value.st_mode,
            "uid": value.st_uid, "gid": value.st_gid, "nlink": str(value.st_nlink),
            "bytes": str(value.st_size), "mtimeSeconds": str(modified[0]), "mtimeNanos": modified[1],
            "ctimeSeconds": str(changed[0]), "ctimeNanos": changed[1], "flags": getattr(value, "st_flags", 0)}


@dataclass(frozen=True, slots=True)
class ArtifactInspectionInputs:
    config: ReleaseConfig
    release: ReleaseVersion
    config_raw: bytes
    version_raw: bytes
    version_source: str

    def used_config(self) -> dict:
        return {"bytes": len(self.config_raw), "sha256": hashlib.sha256(self.config_raw).hexdigest()}

    def used_version(self) -> dict:
        return {"bytes": len(self.version_raw), "sha256": hashlib.sha256(self.version_raw).hexdigest(),
                "name": self.release.name, "build": self.release.build}


class _SelectedOriginal:
    def __init__(self, files: ArtifactInspectionFiles, path: Path, kind: str,
                 expected: dict | None, role: str, maximum: int) -> None:
        self.files, self.path, self.kind, self.expected = files, path, kind, expected
        self.role, self.maximum = role, maximum
        self.parent = _Directory(path.parent, files.guard, edit_checkpoints=True)
        self.slot = _FD(files.guard)
        self.identity: dict | None = None
        self.acquired = False
        self.raw: bytes | None = None
        self.digest: str | None = None

    def acquire(self) -> None:
        self.files.point()
        require(not self.acquired and self.identity is None)
        self.parent.acquire()
        self.files.point()
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if self.kind == "directory":
            flags |= os.O_DIRECTORY
        try:
            named = os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)
        except FileNotFoundError:
            raise ArtifactInspectionRefused(self.role + "-missing") from None
        expected_type = stat.S_ISDIR if self.kind == "directory" else stat.S_ISREG
        if (not expected_type(named.st_mode) or self.kind == "file" and named.st_nlink != 1
                or named.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
                or self.kind == "file" and named.st_size > self.maximum):
            reason = ("input-limit" if self.role == "selection" and named.st_size > self.maximum else
                      self.role + ("-too-large" if named.st_size > self.maximum else "-unsafe"))
            raise ArtifactInspectionRefused(reason)
        before = _identity(named)
        if self.expected is not None and before != self.expected:
            raise ArtifactInspectionRefused(self.role + "-changed")
        number = self.slot.open(self.path.name, flags, dir_fd=self.parent.fd)
        if _identity(os.fstat(number)) != before:
            raise ArtifactInspectionRefused(self.role + "-changed")
        self.identity, self.acquired = before, True
        self.check()

    def check(self) -> None:
        self.files.point()
        require(self.acquired and self.slot.number is not None and self.identity is not None)
        self.parent.check()
        try:
            same = (_identity(os.fstat(self.slot.number)) == self.identity
                    and _identity(os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)) == self.identity)
        except OSError:
            same = False
        if not same:
            raise ArtifactInspectionRefused(self.role + "-changed")
        self.files.point()

    def read(self) -> bytes:
        self.check()
        require(self.kind == "file" and self.raw is None)
        size = int(self.identity["bytes"])
        require(size <= self.maximum <= MAX_CONFIG_BYTES)
        number = self.slot.number
        require(number is not None)
        self.files.operation.charge("saved-read-capacity", 2 * size + 64 * KIB, 4 * MIB)
        value = bytearray()
        os.lseek(number, 0, os.SEEK_SET)
        while len(value) < size:
            self.files.point()
            block = os.read(number, min(64 * KIB, size - len(value)))
            if not block:
                raise ArtifactInspectionRefused(self.role + "-changed")
            value.extend(block)
        if os.read(number, 1):
            raise ArtifactInspectionRefused(self.role + "-changed")
        self.check()
        self.raw = bytes(value)
        self.digest = hashlib.sha256(self.raw).hexdigest()
        return self.raw

    def content_post(self) -> None:
        self.check()
        if self.digest is not None:
            number = self.slot.number
            require(number is not None)
            os.lseek(number, 0, os.SEEK_SET)
            digest, count = hashlib.sha256(), 0
            size = int(self.identity["bytes"])
            while count < size:
                self.files.point()
                block = os.read(number, min(64 * KIB, size - count))
                if not block:
                    raise ArtifactInspectionRefused(self.role + "-changed")
                count += len(block)
                digest.update(block)
            if os.read(number, 1) or digest.hexdigest() != self.digest:
                raise ArtifactInspectionRefused(self.role + "-changed")
            self.check()

    @contextmanager
    def root(self):
        self.check()
        try:
            if self.kind == "file":
                os.lseek(self.slot.number, 0, os.SEEK_SET)
            yield self.slot.number
        finally:
            try:
                with self.files.guard.deferred(check_on_exit=False):
                    self.check()
            except BaseException as error:
                self.files.operation.remember(error)
                raise

    def close(self) -> None:
        first = None
        for original in (self.slot, *reversed(self.parent.slots)):
            try:
                original.close()
            except BaseException as error:
                self.files.operation.remember(error, fatal=True)
                if first is None:
                    first = error
        if first is not None:
            raise first


class _ArtifactReader:
    """One actual private-snapshot loan, no descriptor escape or read-all."""
    def __init__(self, artifact: ArtifactInspectionArtifact, number: int) -> None:
        self.artifact, self.number, self.position, self.closed = artifact, number, 0, False

    def _check(self) -> None:
        try:
            require(not self.closed and self.artifact._reader is self)
            self.artifact.check()
        except BaseException as error:
            self.artifact.files.operation.remember(error)
            raise

    def tell(self) -> int:
        self._check()
        return self.position

    def seek(self, offset: int, whence: int = 0) -> int:
        self._check()
        require(type(offset) is int and type(whence) is int and whence in (0, 1, 2))
        after = (0, self.position, self.artifact.size)[whence] + offset
        require(0 <= after <= self.artifact.size)
        self.position = after
        return after

    def readable(self) -> bool:
        self._check()
        return True

    def seekable(self) -> bool:
        self._check()
        return True

    def read(self, amount: int = -1) -> bytes:
        self._check()
        require(type(amount) is int and amount >= -1)
        remaining = self.artifact.size - self.position
        requested = remaining if amount == -1 else min(amount, remaining)
        require(requested <= 8 * MIB)
        try:
            os.lseek(self.number, self.position, os.SEEK_SET)
        except OSError as error:
            self.artifact.files.operation.remember(error)
            raise
        chunks, consumed = [], 0
        while consumed < requested:
            self._check()
            try:
                chunk = os.read(self.number, min(MIB, requested - consumed))
                require(bool(chunk))
            except BaseException as error:
                self.artifact.files.operation.remember(error)
                raise
            consumed += len(chunk)
            self.position += len(chunk)
            chunks.append(chunk)
        self._check()
        return b"".join(chunks)


class ArtifactInspectionArtifact:
    """The one captured main artifact of this byte-observation operation."""
    def __init__(self, files: ArtifactInspectionFiles, path: Path, size: int, sha256: str) -> None:
        require(files.artifact is None and files.operation.snapshot is not None)
        self.files, self._path, self.size, self.sha256 = files, path, size, sha256
        self._reader: _ArtifactReader | None = None
        self._native = False

    @property
    def path(self) -> Path:
        self.check()
        return self._path

    def check(self) -> None:
        self.files.point()
        operation = self.files.operation
        require(type(self) is ArtifactInspectionArtifact and self.files.artifact is self
                and operation._artifact is self and operation.snapshot is not None
                and not self.files.close_claimed)
        operation.snapshot_binding.origin(operation.snapshot._owner, operation.guard)
        self.files.selected[0].check()
        operation.check_private_file(self._path, self.size, self.sha256, content=False)

    def verify_bytes(self) -> None:
        self.check()
        self.files.operation.check_private_file(self._path, self.size, self.sha256, content=True)

    @contextmanager
    def reader(self):
        self.check()
        require(self._reader is None and not self._native)
        self.files.operation.charge("artifact-reader-borrows", 1, 128)
        with self.files.operation.inspection_deadline.descriptor(self._path) as number:
            reader = _ArtifactReader(self, number)
            self._reader = reader
            first = None
            try:
                yield reader
            except BaseException as error:
                first = error
                # A parser's closed negative DATA result is not an original IO
                # failure. The reader methods latch actual read/binding faults;
                # this scope still owes its own POST and consuming close.
                raise
            finally:
                require(self._reader is reader)
                reader.closed, self._reader = True, None
                try:
                    with self.files.guard.deferred(check_on_exit=False):
                        self.check()
                except BaseException as error:
                    self.files.operation.remember(error)
                    if first is None:
                        raise

    @contextmanager
    def native_input(self):
        self.check()
        require(not self._native and self._reader is None)
        self.verify_bytes()
        self._native = True
        first = None
        try:
            yield self._path
        except BaseException as error:
            first = error
            self.files.operation.remember(error)
            raise
        finally:
            try:
                # A returning Python scope never stands in for actual C/A/W.
                require(self.files.operation.dependents_settled())
                self._native = False
                with self.files.guard.deferred(check_on_exit=False):
                    self.verify_bytes()
            except BaseException as error:
                self.files.operation.remember(error, fatal=not self.files.operation.dependents_settled())
                if first is None:
                    raise


class ArtifactInspectionFiles:
    def __init__(self, operation) -> None:
        from .desktop_artifact_inspection import ArtifactInspectionOperation
        require(type(operation) is ArtifactInspectionOperation and operation.files is None)
        self.operation, self.guard = operation, operation.guard
        self.originals: list[_SelectedOriginal] = []
        self.selected: list[_SelectedOriginal] = []
        self.iterators = []
        self.artifact: ArtifactInspectionArtifact | None = None
        self.close_claimed = self.close_complete = False
        self._work_record = None
        self._work_directory: _Directory | None = None

    def point(self) -> None:
        if self.operation.close_claimed or self.guard.depth:
            self.operation.cleanup_checkpoint()
        else:
            self.operation.checkpoint()

    def known_number(self, number: int) -> None:
        require(type(number) is int and any(slot.number == number and slot.open_state == "OPEN"
                                           for slot in self.operation.live_slots))

    @contextmanager
    def entries(self, number: int):
        from .ios_archive_operation import _IOSIterator
        self.point()
        self.known_number(number)
        self.operation.reserve_descriptors(1)
        self.operation.charge("directory-iterator-originals", 1, 65536)
        iterator = _IOSIterator(self)
        self.iterators.append(iterator)  # Its original duplicate is charged before acquisition.
        first = None
        try:
            iterator.open(number)
            yield iterator
        except BaseException as error:
            first = error
            self.operation.remember(error, fatal=iterator.state == "UNKNOWN")
            raise
        finally:
            try:
                iterator.close()
            except BaseException as error:
                self.operation.remember(error, fatal=True)
                if first is None:
                    raise
            finally:
                if iterator.close_state == "CLOSED":
                    self.iterators.remove(iterator)

    def names(self, number: int, *, limit: int = MAX_NAMESPACE_ENTRIES) -> list[str]:
        self.point()
        require(type(limit) is int and 0 < limit <= MAX_NAMESPACE_ENTRIES)
        before = _identity(os.fstat(number))
        names, keys, total, normalized = [], set(), 0, 0
        with self.entries(number) as entries:
            for entry in entries:
                name = entry.name
                require(type(name) is str and 0 < len(name) <= 255 and name not in (".", "..")
                        and not any(ord(char) < 32 or 127 <= ord(char) <= 159 or char in "/\\:" for char in name)
                        and not name.endswith((".", " ")))
                raw = name.encode("utf-8", "strict")
                key = unicodedata.normalize("NFC", name).casefold()
                key_bytes = key.encode("utf-8", "strict")
                require(len(raw) <= 255 and len(names) < limit and key not in keys
                        and total + len(raw) <= MAX_NAMESPACE_NAMES
                        and normalized + len(key_bytes) <= MAX_NAMESPACE_NAMES)
                total += len(raw)
                normalized += len(key_bytes)
                self.operation.charge("directory-name-observations", len(raw) + len(key_bytes), 64 * MIB)
                keys.add(key)
                names.append(name)
        require(_identity(os.fstat(number)) == before)
        self.point()
        return names

    def _capture(self, path: Path, *, role: str, maximum: int, kind: str = "file", expected=None) -> _SelectedOriginal:
        self.point()
        require(len(self.originals) < 5 and not self.close_claimed)
        original = _SelectedOriginal(self, path, kind, expected, role, maximum)
        self.originals.append(original)  # Before any acquisition or lost constructor return.
        try:
            original.acquire()
        except ArtifactInspectionRefused:
            raise
        except OSError:
            raise ArtifactInspectionRefused(role + "-unsafe") from None
        return original

    def saved(self) -> ArtifactInspectionInputs:
        self.point()
        operation = self.operation
        require(operation.inputs is None and not self.originals)
        config_original = self._capture(operation.root / "release/mobile-release.json",
                                        role="saved-config", maximum=MAX_CONFIG_BYTES)
        raw = config_original.read()
        if not raw or {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} != operation.request.context["savedConfig"]:
            raise ArtifactInspectionRefused("saved-config-changed")
        try:
            text = raw.decode("utf-8", "strict")
            if any(code == "metadata.secret-pattern" for code, _ in check_metadata_text("saved-artifact-inspection", text).issues):
                raise ArtifactInspectionRefused("saved-config-sensitive")
            data = parse_config_text(text)
        except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
            raise ArtifactInspectionRefused("saved-config-invalid") from None
        platform = "android" if operation.request.context["format"] == "aab" else "ios"
        if data[platform].get("enabled") is not True:
            raise ArtifactInspectionRefused("platform-disabled")
        spec = data["version"]
        if not _source_path(spec["source"]):
            raise ArtifactInspectionRefused("saved-version-unsafe")
        version_original = self._capture(operation.root / spec["source"], role="saved-version", maximum=MAX_VERSION_BYTES)
        version_raw = version_original.read()
        if not version_raw:
            raise ArtifactInspectionRefused("saved-version-invalid")
        try:
            release = release_version_from_values(parse_key_value_text(version_raw.decode("utf-8", "strict")),
                name_key=spec["nameKey"], build_key=spec["buildKey"], ios_enabled=data["ios"].get("enabled") is True,
                source_label=spec["source"])
        except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
            raise ArtifactInspectionRefused("saved-version-invalid") from None
        return ArtifactInspectionInputs(ReleaseConfig(config_original.path, operation.root, data),
                                        release, raw, version_raw, spec["source"])

    def capture_selected(self) -> None:
        self.point()
        require(not self.selected and self.operation.inputs is not None)
        format = self.operation.request.context["format"]
        for row in self.operation.request.native["originals"]:
            maximum = GIB if format == "aab" else 4 * GIB
            original = self._capture(Path(row["path"]), role="selection", maximum=maximum,
                                     kind=row["kind"], expected=row["identity"])
            self.selected.append(original)

    def source_at(self, path: Path) -> _SelectedOriginal | None:
        return next((item for item in self.selected if item.path == path), None)

    def post(self) -> None:
        for original in self.originals:
            original.content_post()

    def bind_work(self, record) -> None:
        self.point()
        require(self._work_record is None and self._work_directory is None
                and self.operation.has_scratch(record) and record[1] is self.guard and record[2]["acquired"])
        self._work_record = record
        directory = _Directory(Path(record[0].name), self.guard, system_root_aliases=True, edit_checkpoints=True)
        self._work_directory = directory
        directory.acquire()
        require(record[0].state["identity"] is not None)
        value = os.fstat(directory.fd)
        expected = record[0].state["identity"]
        require((value.st_dev, value.st_ino) == tuple(expected[:2]))

    @property
    def work_path(self) -> Path:
        self.point()
        require(self._work_record is not None and self._work_directory is not None
                and self.operation.has_scratch(self._work_record) and not self._work_record[2]["removed"])
        self._work_directory.check()
        return self._work_directory.path

    def close_work_handles(self) -> None:
        if self._work_directory is not None:
            require(self.operation.dependents_settled())
            self._work_directory.close()

    def close(self) -> None:
        if self.close_claimed:
            require(self.close_complete)
            return
        require(self.operation.dependents_settled())
        self.close_claimed = True
        first = None
        with self.guard.deferred(check_on_exit=False):
            try:
                self.post()
            except BaseException as error:
                first = error
                self.operation.remember(error)
            for original in (*reversed(self.iterators), *reversed(self.originals)):
                try:
                    original.close()
                except BaseException as error:
                    self.operation.remember(error, fatal=True)
                    if first is None:
                        first = error
            self.close_work_handles()
        self.close_complete = (not self.iterators and all(item.slot.close_state == "CLOSED"
            and all(slot.close_state == "CLOSED" for slot in item.parent.slots) for item in self.originals))
        if not self.close_complete:
            raise _cleanup_failure(self.guard, first or ArtifactInspectionRefused("cleanup-unknown"))
        if first is not None:
            raise first
