"""Read-only correspondence of a private iOS artifact snapshot.

No application code runs here. These structural/content checks complement (not
replace) native signing validation and authenticated whole-artifact provenance.
"""
from __future__ import annotations

import hashlib
import math
import os
import plistlib
import stat
import struct
import tempfile
import unicodedata
import zipfile
import zlib
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Mapping
from xml.parsers.expat import ExpatError

from .config import ReleaseVersion
from .errors import ValidationError
from .inspection import InspectionDeadline
from .macho import MACHO_MAGICS, MachOSlice, inspect_macho

MAX_FILES = 100_000
MAX_DEPTH = 64
MAX_FILE_BYTES = 4 * 1024**3
MAX_TOTAL_BYTES = 16 * 1024**3
MAX_ZIP_DIRECTORY = 32 * 1024**2
MAX_PLIST_BYTES = 4 * 1024**2
CHUNK = 1024**2
IOS_ARTIFACT_NAMES = frozenset({"ios-ipa", "ios-archive", "ios-dsyms"})


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(f"iOS artifact correspondence: {message}")


def _parts(value: str) -> tuple[str, ...]:
    parts = tuple(value.split("/"))
    try:
        encoded_length = len(value.encode("utf-8"))
    except UnicodeError as error:
        raise ValidationError("iOS artifact path is not valid Unicode") from error
    _require(bool(value) and encoded_length <= 2048 and len(parts) <= MAX_DEPTH,
             "path length/depth exceeds its bound")
    _require(all(part not in {"", ".", ".."} and len(part.encode("utf-8")) <= 255 and
                 not part.endswith((" ", ".")) and not any(ord(c) < 32 or ord(c) == 127 or c in "\\:" for c in part)
                 for part in parts), "unsafe path component")
    return parts


class _Paths:
    def __init__(self) -> None:
        self.paths: dict[str, tuple[str, bool]] = {}

    def add(self, name: str, directory: bool) -> None:
        parts = _parts(name)
        for index in range(1, len(parts) + 1):
            path = "/".join(parts[:index])
            is_directory = directory or index < len(parts)
            key = unicodedata.normalize("NFC", path).casefold()
            previous = self.paths.get(key)
            _require(previous is None or previous == (path, is_directory),
                     "case/Unicode collision or file/directory conflict")
            self.paths[key] = (path, is_directory)
        _require(len(self.paths) <= MAX_FILES, "file/directory count exceeds its bound")


class _Budget:
    def __init__(self, deadline: InspectionDeadline) -> None:
        self.deadline, self.count, self.size = deadline, 0, 0

    def tick(self, size: int = 0, *, entry: bool = False) -> None:
        self.deadline.check()
        self.size += size
        self.count += int(entry)
        _require(self.count <= MAX_FILES and self.size <= MAX_TOTAL_BYTES,
                 "inspection exceeds its count/size bound")


@dataclass(frozen=True)
class _File:
    size: int
    sha256: str
    magic: bytes


Inventory = dict[str, _File | None]


def _attributes(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _copy_file(fd: int, target: Path | None, budget: _Budget) -> _File:
    budget.tick()
    before = os.fstat(fd)
    _require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE_BYTES,
             "input must be a bounded regular file")
    digest, count, magic = hashlib.sha256(), 0, b""
    output = target.open("xb") if target is not None else None
    try:
        while data := os.read(fd, CHUNK):
            budget.tick(len(data))
            count += len(data)
            _require(count <= before.st_size, "input grew during snapshotting")
            if count == len(data):
                magic = data[:4]
            digest.update(data)
            if output is not None:
                output.write(data)
    finally:
        if output is not None:
            output.close()
    _require(count == before.st_size and _attributes(before) == _attributes(os.fstat(fd)),
             "input changed during snapshotting")
    if target is not None:
        target.chmod(0o555 if before.st_mode & 0o111 else 0o444)
    budget.tick()
    return _File(count, digest.hexdigest(), magic)


def _tree(path: Path, target: Path | None = None, *, deadline: InspectionDeadline) -> Inventory:
    """Anchored descriptor traversal: never follow an input entry's symlink."""
    inventory: Inventory = {}
    paths, budget = _Paths(), _Budget(deadline)
    budget.tick()

    def walk(fd: int, relative: str, destination: Path | None) -> None:
        before = os.fstat(fd)
        _require(stat.S_ISDIR(before.st_mode), "tree input is not a directory")
        entries = []
        with os.scandir(fd) as iterator:
            for entry in iterator:
                budget.tick(entry=True)
                entries.append((entry.name, entry.stat(follow_symlinks=False)))
        for name, observed in sorted(entries):
            budget.tick()
            value = f"{relative}/{name}" if relative else name
            directory = stat.S_ISDIR(observed.st_mode)
            _require(directory or stat.S_ISREG(observed.st_mode), "symlink or special file in artifact tree")
            paths.add(value, directory)
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                            (os.O_DIRECTORY if directory else 0), dir_fd=fd)
            try:
                _require(_attributes(observed) == _attributes(os.fstat(child)), "tree entry changed during snapshotting")
                output = destination / name if destination is not None else None
                if directory:
                    inventory[value] = None
                    if output is not None:
                        output.mkdir(mode=0o700)
                    walk(child, value, output)
                    if output is not None:
                        output.chmod(0o500)
                else:
                    inventory[value] = _copy_file(child, output, budget)
            finally:
                os.close(child)
        _require(_attributes(before) == _attributes(os.fstat(fd)), "tree layout changed during snapshotting")
        budget.tick()

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_DIRECTORY)
        try:
            if target is not None:
                target.mkdir(mode=0o700)
            walk(fd, "", target)
            if target is not None:
                target.chmod(0o500)
        finally:
            os.close(fd)
    except OSError as error:
        raise ValidationError("iOS artifact tree could not be read safely") from error
    return inventory


def _input(path: Path, target: Path | None = None, *, deadline: InspectionDeadline) -> _File | Inventory:
    deadline.check()
    try:
        attributes = path.lstat()
        if stat.S_ISDIR(attributes.st_mode):
            return _tree(path, target, deadline=deadline)
        _require(stat.S_ISREG(attributes.st_mode), "input is not a regular file/directory")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            _require(_attributes(attributes) == _attributes(os.fstat(fd)), "input path changed during snapshotting")
            return _copy_file(fd, target, _Budget(deadline))
        finally:
            os.close(fd)
    except OSError as error:
        raise ValidationError("iOS artifact input could not be read safely") from error


@dataclass
class IOSArtifactSnapshot:
    paths: dict[str, Path]
    originals: dict[str, Path]
    bindings: dict[str, _File | Inventory]
    temporary: Path
    deadline: InspectionDeadline
    unpacked: dict[str, Path] = field(default_factory=dict)

    def assert_unchanged(self) -> None:
        self.deadline.check()
        for name, original in self.originals.items():
            _require(_input(original, deadline=self.deadline) == self.bindings[name], "original artifact changed after snapshotting")
            _require(_input(self.paths[name], deadline=self.deadline) == self.bindings[name], "private snapshot changed during inspection")
        self.deadline.check()

    def unpack(self, name: str) -> Path:
        self.deadline.check()
        if name in self.unpacked:
            return self.unpacked[name]
        path = self.paths[name]
        if path.is_dir():
            return path
        destination = self.temporary / (name + "-unpacked")
        safe_extract_zip(path, destination, deadline=self.deadline)
        if name == "ios-ipa":
            self.unpacked[name] = destination
            return destination
        root_name = "archive.xcarchive" if name == "ios-archive" else "dsyms"
        _require({item.name for item in destination.iterdir()} == {root_name} and
                 (destination / root_name).is_dir(), "packed archive/symbol root must be archive.xcarchive/ or dsyms/")
        self.unpacked[name] = destination / root_name
        return self.unpacked[name]


@contextmanager
def snapshot_ios_artifacts(artifacts: Mapping[str, Path]) -> Iterator[IOSArtifactSnapshot]:
    """Only the yielded private copies may be passed to native/content checks.

    Compare the originals again before sealing or uploading. This defends against
    mutable input-path/ABA races, not a compromised same-user runner.
    """
    deadline = InspectionDeadline()
    selected = {name: path for name, path in artifacts.items() if name in IOS_ARTIFACT_NAMES}
    with tempfile.TemporaryDirectory(prefix="mobile-release-ios-snapshot-") as directory:
        temporary = Path(directory)
        copies, bindings = {}, {}
        for name, path in selected.items():
            _parts(path.name)
            parent = temporary / name
            parent.mkdir(mode=0o700)
            copies[name] = parent / path.name
            bindings[name] = _input(path, copies[name], deadline=deadline)
            if name == "ios-ipa":
                _require(isinstance(bindings[name], _File), "IPA must be a regular ZIP file")
        snapshot = IOSArtifactSnapshot(copies, selected, bindings, temporary, deadline)
        deadline.check()
        yield snapshot


def _zip_entry_offset(header: tuple[Any, ...], extra: bytes, *, deadline: InspectionDeadline) -> int:
    """Read only the ZIP64 fields needed to establish a single-disk offset."""
    offset, disk = header[16], header[13]
    if offset != 0xFFFFFFFF and disk != 0xFFFF:
        _require(disk == 0, "artifact ZIP must be single-disk")
        return offset
    position = 0
    zip64 = None
    while position < len(extra):
        deadline.check()
        _require(position + 4 <= len(extra), "artifact ZIP extra field is truncated")
        kind, length = struct.unpack_from("<HH", extra, position)
        position += 4
        _require(position + length <= len(extra), "artifact ZIP extra field exceeds its record")
        if kind == 1:
            _require(zip64 is None, "artifact ZIP has duplicate ZIP64 fields")
            zip64 = extra[position:position + length]
        position += length
    _require(zip64 is not None, "artifact ZIP is missing its ZIP64 offset")
    assert zip64 is not None
    position = 8 * ((header[9] == 0xFFFFFFFF) + (header[8] == 0xFFFFFFFF))
    if offset == 0xFFFFFFFF:
        _require(position + 8 <= len(zip64), "artifact ZIP64 offset is truncated")
        offset = struct.unpack_from("<Q", zip64, position)[0]
        position += 8
    if disk == 0xFFFF:
        _require(position + 4 <= len(zip64), "artifact ZIP64 disk is truncated")
        disk = struct.unpack_from("<I", zip64, position)[0]
    _require(disk == 0, "artifact ZIP must be single-disk")
    return offset


def _zip_directory_bound(archive: Path, *, deadline: InspectionDeadline) -> int:
    """Bound the directory *before* stdlib's unbounded ZipInfo allocation.

    This is an allocation/layout gate, not a substitute for ZipFile's member
    validation, CRCs, complete inventory or authenticated evidence. The normalized iOS ZIP profile supports one disk, no prefix/trailer, and standard
    56-byte ZIP64 end records. Payload bytes are never read here.
    """
    deadline.check()
    with archive.open("rb") as source:
        size = os.fstat(source.fileno()).st_size
        _require(22 <= size <= MAX_FILE_BYTES, "artifact ZIP end record is missing")
        tail_size = min(size, 22 + 65535)
        source.seek(size - tail_size)
        tail = source.read(tail_size)
        # Match the exact EOCD selection used by ZipFile. A signature embedded
        # after the real EOCD must not let the two parsers disagree.
        # Match ZipFile's ordinary no-comment fast path. The offset/size fields
        # of a valid EOCD can themselves contain its signature byte sequence.
        end_index = (
            len(tail) - 22
            if len(tail) >= 22 and tail[-22:-18] == b"PK\x05\x06" and tail[-2:] == b"\0\0"
            else tail.rfind(b"PK\x05\x06")
        )
        _require(end_index >= 0 and end_index + 22 <= len(tail), "artifact ZIP end record is truncated")
        end = struct.unpack_from("<4s4H2IH", tail, end_index)
        _require(end_index + 22 + end[7] == len(tail), "artifact ZIP has trailing or ambiguous end data")
        end_offset = size - tail_size + end_index
        _require(end[1] == end[2] == 0 and end[3] == end[4], "artifact ZIP must be single-disk with consistent counts")
        count, directory_size, directory_offset = end[4:7]
        directory_end = end_offset
        source.seek(max(0, end_offset - 20))
        locator = source.read(20)
        if len(locator) == 20 and locator[:4] == b"PK\x06\x07":
            _, disk, zip64_offset, disks = struct.unpack("<4sIQI", locator)
            _require(disk == 0 and disks == 1 and zip64_offset + 56 == end_offset - 20, "artifact ZIP64 locator has an unsupported extent or disk")
            source.seek(zip64_offset)
            prefix = source.read(12)
            _require(len(prefix) == 12 and prefix[:4] == b"PK\x06\x06", "artifact ZIP64 end record is missing")
            # This bounded artifact profile deliberately excludes
            # extended records, even where ZipFile can support them. Never
            # allocate/read an extension from its untrusted 64-bit length.
            _require(struct.unpack_from("<Q", prefix, 4)[0] == 44, "artifact ZIP64 extended end records are unsupported")
            body = source.read(44)
            _require(len(body) == 44, "artifact ZIP64 end record is truncated")
            large = struct.unpack("<2H2I4Q", body)
            _require(large[2] == large[3] == 0 and large[4] == large[5], "artifact ZIP64 must be single-disk with consistent counts")
            for declared, actual, sentinel in zip((count, directory_size, directory_offset), large[5:8], (0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF)):
                _require(declared == sentinel or declared == actual, "artifact ZIP and ZIP64 directory records disagree")
            count, directory_size, directory_offset = large[5:8]
            directory_end = zip64_offset
        else:
            _require(count != 0xFFFF and directory_size != 0xFFFFFFFF and directory_offset != 0xFFFFFFFF, "artifact ZIP64 locator is missing")
        _require(0 < count <= MAX_FILES, "artifact ZIP member count is invalid")
        _require(46 * count <= directory_size <= MAX_ZIP_DIRECTORY, "artifact ZIP central directory exceeds its bounded size")
        _require(0 < directory_offset < directory_end and directory_offset + directory_size == directory_end, "artifact ZIP central directory extent is invalid")
        source.seek(0)
        _require(source.read(4) == b"PK\x03\x04", "artifact ZIP prefixes are unsupported")
        position, actual_count, first_local = directory_offset, 0, directory_offset
        while position < directory_end:
            deadline.check()
            _require(actual_count < MAX_FILES and position + 46 <= directory_end, "artifact ZIP central directory has excess or truncated entries")
            source.seek(position)
            fixed = source.read(46)
            _require(len(fixed) == 46 and fixed[:4] == b"PK\x01\x02", "artifact ZIP central directory record is invalid")
            header = struct.unpack("<4s6H3I5H2I", fixed)
            name_size, extra_size, comment_size = header[10:13]
            _require(0 < name_size <= 2048, "artifact ZIP filename exceeds its bounded size")
            following = position + 46 + name_size + extra_size + comment_size
            _require(following <= directory_end, "artifact ZIP central directory record exceeds its extent")
            source.seek(position + 46 + name_size)
            extra = source.read(extra_size)
            _require(len(extra) == extra_size, "artifact ZIP central directory extra field is truncated")
            local_offset = _zip_entry_offset(header, extra, deadline=deadline)
            _require(0 <= local_offset < directory_offset, "artifact ZIP local header offset is outside the payload")
            first_local = min(first_local, local_offset)
            actual_count += 1
            position = following
        _require(actual_count == count and first_local == 0, "artifact ZIP directory count or first header disagrees")
        deadline.check()
        return count


def safe_extract_zip(path: Path, destination: Path, *, deadline: InspectionDeadline | None = None) -> None:
    """Extract untrusted bytes into a new toolkit-owned directory, never app paths."""
    deadline = deadline if deadline is not None else InspectionDeadline()
    try:
        _zip_directory_bound(path, deadline=deadline)
        with zipfile.ZipFile(path) as archive:
            deadline.check()
            entries = archive.infolist()
            _require(0 < len(entries) <= MAX_FILES, "ZIP entry count exceeds its bound")
            paths, seen, total = _Paths(), set(), 0
            for entry in entries:
                deadline.check()
                directory = entry.is_dir()
                name = entry.filename[:-1] if directory else entry.filename
                _require(entry.orig_filename == entry.filename and name not in seen, "duplicate or NUL-containing ZIP entry")
                seen.add(name)
                paths.add(name, directory)
                mode = stat.S_IFMT(entry.external_attr >> 16)
                _require(mode in ({0, stat.S_IFDIR} if directory else {0, stat.S_IFREG}) and
                         not entry.flag_bits & 1 and entry.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED},
                         "ZIP contains links, special files, encryption or unsupported compression")
                total += entry.file_size
                _require(0 <= entry.file_size <= MAX_FILE_BYTES and total <= MAX_TOTAL_BYTES and
                         (not directory or entry.file_size == 0) and
                         entry.file_size <= max(1, entry.compress_size) * 1000,
                         "ZIP member expansion exceeds its bound")
            destination.mkdir(mode=0o700)
            budget = _Budget(deadline)
            for entry in entries:
                budget.tick(entry=True)
                target = destination.joinpath(*_parts(entry.filename.rstrip("/")))
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                size = 0
                with archive.open(entry) as source, target.open("xb") as output:
                    while data := source.read(CHUNK):
                        budget.tick(len(data))
                        size += len(data)
                        _require(size <= entry.file_size, "ZIP member exceeds its declared size")
                        output.write(data)
                _require(size == entry.file_size, "ZIP member size differs from its declaration")
                target.chmod(0o555 if (entry.external_attr >> 16) & 0o111 else 0o444)
            deadline.check()
    except (OSError, EOFError, ValueError, struct.error, zipfile.BadZipFile, NotImplementedError, zlib.error) as error:
        raise ValidationError("iOS artifact ZIP could not be extracted safely") from error


class _UniqueDict(dict):
    def __setitem__(self, key: Any, value: Any) -> None:
        _require(isinstance(key, str) and key not in self, "plist has a non-string or duplicate key")
        super().__setitem__(key, value)


def typed_plist(path: Path, *, deadline: InspectionDeadline | None = None) -> Any:
    """Reject duplicate keys in XML *and* binary plists and preserve value types."""
    deadline = deadline if deadline is not None else InspectionDeadline()
    deadline.check()
    try:
        _require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_PLIST_BYTES,
                 "Info.plist must be a bounded regular file")
        data = path.read_bytes()
        if data.startswith(b"bplist00"):
            _require(len(data) >= 40 and int.from_bytes(data[-24:-16], "big") <= MAX_FILES,
                     "binary plist object count exceeds its bound")
        value = plistlib.loads(data, dict_type=_UniqueDict)
        deadline.check()
        remaining = MAX_FILES

        def convert(item: Any, depth: int = 0) -> Any:
            nonlocal remaining
            deadline.check()
            remaining -= 1
            _require(depth <= MAX_DEPTH and remaining >= 0, "plist complexity exceeds its bound")
            if isinstance(item, dict):
                return ("dict", tuple((key, convert(val, depth + 1)) for key, val in sorted(item.items())))
            if type(item) is list:
                return ("list", tuple(convert(val, depth + 1) for val in item))
            _require(type(item) in {str, bytes, int, bool, float, datetime}, "plist contains an unsupported value type")
            _require(type(item) is not float or math.isfinite(item), "plist contains a nonfinite number")
            return (type(item).__name__, item)

        _require(isinstance(value, dict), "Info.plist root must be a dictionary")
        return convert(value)
    except (OSError, ValueError, TypeError, OverflowError, RecursionError, plistlib.InvalidFileException, ExpatError) as error:
        raise ValidationError("iOS artifact Info.plist is malformed or exceeds its bounds") from error


@dataclass
class _Application:
    inventory: Inventory
    binaries: dict[str, tuple[MachOSlice, ...]]
    main: tuple[MachOSlice, ...]
    plists: dict[str, Any]


def _application(root: Path, expected_bundle_id: str, release: ReleaseVersion, *, deadline: InspectionDeadline) -> _Application:
    inventory = _tree(root, deadline=deadline)
    bundles = {""} | {name for name, value in inventory.items() if value is None and
                         PurePosixPath(name).suffix in {".app", ".appex", ".framework", ".xpc", ".bundle"}}
    plists, excluded, executables = {}, set(), {}
    for bundle in sorted(bundles):
        deadline.check()
        prefix = bundle + "/" if bundle else ""
        path = root / bundle
        info_name = prefix + "Info.plist"
        if info_name not in inventory and path.suffix == ".bundle":
            continue  # A plain resource directory is compared byte-for-byte.
        info = typed_plist(path / "Info.plist", deadline=deadline)
        plists[info_name] = info
        values = dict(info[1])
        executable = values.get("CFBundleExecutable")
        if path.suffix != ".bundle" or executable is not None:
            _require(executable is not None and executable[0] == "str" and len(_parts(executable[1])) == 1,
                     "bundle executable must be a safe basename")
            executables[bundle] = prefix + executable[1]
        identity = values.get("CFBundleIdentifier")
        _require(identity is not None and identity[0] == "str" and bool(identity[1]), "bundle lacks a string identity")
        for key in ("CFBundleVersion", "CFBundleShortVersionString"):
            _require(key not in values or values[key][0] == "str", "bundle version must be a string")
        if not bundle:
            _require(identity == ("str", expected_bundle_id), "primary Bundle ID differs from committed configuration")
        if not bundle or path.suffix in {".app", ".appex", ".xpc"}:
            _require(values.get("CFBundleVersion") == ("str", str(release.build)) and
                     values.get("CFBundleShortVersionString") == ("str", release.name),
                     "application/extension version differs from committed configuration")
        signature = prefix + "_CodeSignature"
        if signature in inventory:
            _require(inventory[signature] is None and
                     {name for name in inventory if name.startswith(signature + "/")} == {signature + "/CodeResources"} and
                     isinstance(inventory[signature + "/CodeResources"], _File), "signature directory contains unrecognized payload")
            excluded.update({signature, signature + "/CodeResources"})
        profile = prefix + "embedded.mobileprovision"
        if path.suffix in {".app", ".appex"} and profile in inventory:
            _require(isinstance(inventory[profile], _File), "embedded profile is not a regular file")
            excluded.add(profile)
    binaries = {}
    for name, value in inventory.items():
        deadline.check()
        if value is None:
            continue
        if value.magic in MACHO_MAGICS:
            _require(name not in excluded and "_CodeSignature" not in PurePosixPath(name).parts,
                     "native payload cannot hide in signature/profile exclusions")
            binaries[name] = inspect_macho(root / name, deadline=deadline)
        elif name.endswith(".dylib"):
            raise ValidationError("iOS artifact dylib is not a supported Mach-O image")
        if name.endswith("/Info.plist") or name == "Info.plist":
            plists[name] = typed_plist(root / name, deadline=deadline)
    _require(set(executables.values()) <= binaries.keys(), "declared bundle executable is not a supported Mach-O")
    return _Application({name: value for name, value in inventory.items() if name not in excluded},
                        binaries, binaries[executables[""]], plists)


def _identities(application: _Application, *, deadline: InspectionDeadline) -> dict[tuple[int, int, str], MachOSlice]:
    identities = {}
    for slices in application.binaries.values():
        deadline.check()
        for value in slices:
            _require(value.key not in identities or identities[value.key] == value,
                     "one UUID/architecture labels conflicting binary contents")
            identities[value.key] = value
    return identities


def _archive_application(archive: Path, expected_bundle_id: str, release: ReleaseVersion, *, deadline: InspectionDeadline) -> tuple[Path, _Application]:
    inventory = _tree(archive, deadline=deadline)
    _require({PurePosixPath(name).parts[0] for name in inventory} <= {"Info.plist", "Products", "dSYMs", "SwiftSupport"},
             "unsupported archive root (Watch/ODR/bitcode/recompiled or unknown ancillary content)")
    if "Info.plist" in inventory:
        typed_plist(archive / "Info.plist", deadline=deadline)
    apps = list((archive / "Products/Applications").iterdir())
    _require(len(apps) == 1 and apps[0].is_dir() and apps[0].suffix == ".app" and
             {item.name for item in (archive / "Products").iterdir()} == {"Applications"},
             "archive must contain exactly one Products/Applications app")
    return apps[0], _application(apps[0], expected_bundle_id, release, deadline=deadline)


def validate_present_symbols(archive: Path, application: _Application, *, require_main: bool, deadline: InspectionDeadline) -> int:
    """Check every retained symbol; MRK-009 separately enforces nested coverage."""
    identities, symbols = _identities(application, deadline=deadline), set()
    directory = archive / "dSYMs"
    inventory = _tree(directory, deadline=deadline) if directory.is_dir() else {}
    owners = {PurePosixPath(name).parts[0] for name in inventory}
    _require(all(name.endswith(".dSYM") and inventory.get(name) is None for name in owners),
             "dSYMs must contain only regular dSYM bundles")
    for owner in sorted(owners):
        deadline.check()
        typed_plist(directory / owner / "Contents/Info.plist", deadline=deadline)
        prefix = owner + "/Contents/Resources/DWARF/"
        dwarf = [name for name, value in inventory.items() if name.startswith(prefix) and isinstance(value, _File)]
        _require(bool(dwarf), "retained dSYM lacks a DWARF object")
        for name in dwarf:
            _require("/" not in name[len(prefix):], "DWARF objects must be direct regular children")
            for value in inspect_macho(directory / name, dsym=True, deadline=deadline):
                _require(value.key in identities and value.key not in symbols,
                         "retained dSYM is unknown, substituted or duplicated")
                symbols.add(value.key)
    for name, value in inventory.items():
        deadline.check()
        if isinstance(value, _File) and value.magic in MACHO_MAGICS:
            _require("/Contents/Resources/DWARF/" in name, "native object outside retained DWARF inventory")
    if require_main:
        _require({value.key for value in application.main} <= symbols, "retained main-app dSYM slices are missing")
    return len(symbols)


def inspect_archive_symbols(archive: Path, *, expected_bundle_id: str, release: ReleaseVersion,
                            require_main: bool, deadline: InspectionDeadline | None = None) -> int:
    deadline = deadline if deadline is not None else InspectionDeadline()
    _path, application = _archive_application(archive, expected_bundle_id, release, deadline=deadline)
    return validate_present_symbols(archive, application, require_main=require_main, deadline=deadline)


def _support(root: Path, application: _Application, *, deadline: InspectionDeadline) -> dict[str, tuple[MachOSlice, ...]]:
    deadline.check()
    if not root.exists():
        return {}
    inventory = _tree(root, deadline=deadline)
    _require(inventory.get("iphoneos", False) is None and all(name == "iphoneos" or
             (len(PurePosixPath(name).parts) == 2 and name.startswith("iphoneos/") and
              name.endswith(".dylib") and isinstance(value, _File)) for name, value in inventory.items()),
             "SwiftSupport must contain only iphoneos dylibs")
    result = {}
    for name, value in inventory.items():
        deadline.check()
        if value is None:
            continue
        support = inspect_macho(root / name, deadline=deadline)
        shipped = [slices for path, slices in application.binaries.items() if PurePosixPath(path).name == PurePosixPath(name).name]
        _require(bool(shipped), "SwiftSupport library has no shipped counterpart")
        for slices in shipped:
            _require(set(slices) <= set(support), "shipped runtime slices differ from SwiftSupport")
        result[name] = support
    _require(bool(result), "SwiftSupport must not be an empty ancillary root")
    return result


def inspect_ios_artifact_set(snapshot: IOSArtifactSnapshot, *, expected_bundle_id: str,
                             release: ReleaseVersion, symbols_policy: str) -> dict[str, int]:
    """Inspect the complete pair before any new intent/Store preparation."""
    deadline = snapshot.deadline
    deadline.check()
    _require(symbols_policy in {"disabled", "retain", "required"}, "unknown symbol policy")
    _require({"ios-ipa", "ios-archive"} <= snapshot.paths.keys(), "signed IPA validation requires its retained xcarchive")
    try:
        archive = snapshot.unpack("ios-archive")
        ipa = snapshot.unpack("ios-ipa")
        app_path, original = _archive_application(archive, expected_bundle_id, release, deadline=deadline)
        _require({item.name for item in ipa.iterdir()} <= {"Payload", "SwiftSupport"},
                 "unsupported IPA root (Watch/ODR/bitcode/recompiled or unknown ancillary content)")
        apps = list((ipa / "Payload").iterdir())
        _require(len(apps) == 1 and apps[0].name == app_path.name and apps[0].is_dir(),
                 "IPA and archive primary application paths differ")
        exported = _application(apps[0], expected_bundle_id, release, deadline=deadline)
        _require(original.inventory.keys() == exported.inventory.keys(), "IPA/archive file or nested bundle inventory differs")
        _require(original.binaries == exported.binaries, "IPA/archive Mach-O identity/content differs (recompiled, stripped, thinned or substituted)")
        _require(original.plists == exported.plists, "IPA/archive typed Info.plist contents differ")
        for name, value in original.inventory.items():
            deadline.check()
            if name not in original.binaries and name not in original.plists:
                _require(value == exported.inventory[name], "IPA/archive non-signature resources differ")
        symbols = validate_present_symbols(archive, original, require_main=symbols_policy in {"retain", "required"}, deadline=deadline)
        if "ios-dsyms" in snapshot.paths:
            detached = snapshot.unpack("ios-dsyms")
            _require((archive / "dSYMs").is_dir() and _tree(detached, deadline=deadline) == _tree(archive / "dSYMs", deadline=deadline),
                     "detached dSYMs differ from the retained archive")
        _require(_support(archive / "SwiftSupport", original, deadline=deadline) == _support(ipa / "SwiftSupport", exported, deadline=deadline),
                 "IPA/archive SwiftSupport inventories or contents differ")
        snapshot.assert_unchanged()
        return {"nativePaths": len(original.binaries), "nativeIdentities": len(_identities(original, deadline=deadline)),
                "presentSymbolSlices": symbols}
    except OSError as error:
        raise ValidationError("iOS artifact pair has a missing or unreadable required path") from error
