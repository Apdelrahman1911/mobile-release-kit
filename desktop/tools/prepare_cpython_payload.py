"""Offline, data-only publisher transformation of one frozen CPython candidate.

The production entry point is deliberately CLOSED: public notices (including a
shipped Python change summary) and original static-link provenance still need
independent acceptance and source-pinned hashes. Caller assertions cannot open
that gate. Private policy parameters exist only for inert algorithm tests, not
as a CLI escape hatch. This is not acquisition, installation, legal clearance,
native runtime qualification, or an immutable-runtime custody implementation.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
from typing import NamedTuple
import zlib

TARGET = "x86_64-unknown-linux-gnu"
PROFILE = "pbs-20260901-cpython-3.14.7-linux-x86_64-subset-v1"
ARCHIVE_BYTES = 35_945_651
ARCHIVE_SHA256 = "3959f92825141e04adf44982d3a83ee57af0877e893b0796e04c1468749d9b04"
PBS_COMMIT = "4bb01f09aaf362c71e891be4a41cb6d6ddf830b3"
CPYTHON_COMMIT = "823f0323ee6ec1402088b73bce1a38473cac36dc"

# Both remain unavailable. Do not substitute hashes of private proposals or a
# caller's `complete: true`. A later, separately reviewed source delta must bind
# the actual accepted inventory bytes and original libatomic link provenance.
APPROVED_NOTICE_INVENTORY_SHA256: str | None = None
APPROVED_STATIC_LINK_PROVENANCE_SHA256: str | None = None

# Intersection with prepare_runtime.py / the runtime inspector. The existing
# preparer alone writes core.zip, all six bootstraps, github-ca.pem and manifest.json.
MAX_FILES = 2048
MAX_ENTRIES = 8192
MAX_PATH_PARTS = 16
MAX_PATH_BYTES = 512
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
RESERVED_PAYLOAD_FILES = (
    "core.zip", "engine_bootstrap.py", "config_edit_bootstrap.py", "github_connection_bootstrap.py",
    "environment_bootstrap.py", "offline_preflight_bootstrap.py", "android_build_bootstrap.py", "github-ca.pem",
)
RESERVED_ENTRIES = len(RESERVED_PAYLOAD_FILES) + 1
# Unchanged aggregate reserve: core plus ZIP overhead, six bounded bootstraps,
# the fixed CA and final manifest. This is not a larger supplier byte budget.
RESOURCE_BYTE_HEADROOM = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_MANIFEST_NODES = 20_000
MANIFEST_METADATA_HEADROOM = 4096

MAX_TAR_BYTES = 128 * 1024 * 1024
MAX_TAR_HEADERS = 8192  # Includes PAX/GNU metadata, not just logical members.
MAX_METADATA_BYTES = 64 * 1024
MAX_TOTAL_METADATA_BYTES = 1024 * 1024
MAX_METADATA_CHAIN = 8  # Bounds stdlib's recursive long-name/PAX processing.
MAX_NOTICE_FILES = 128
MAX_NOTICE_ENTRIES = 512
MAX_NOTICE_BYTES = 2 * 1024 * 1024
MAX_NOTICE_INVENTORY_BYTES = 128 * 1024
MAX_PROVENANCE_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
_BLOCK = 512
_ZERO_BLOCK = b"\0" * _BLOCK
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
             *(f"lpt{i}" for i in range(1, 10))}
_STDLIB = "python/lib/python3.14/"
_EXEC_SOURCE = "python/bin/python3.14"
_EXEC_DESTINATION = "python/bin/python3"
_LIBPYTHON = frozenset({"libpython3.so", "libpython3.14.so", "libpython3.14.so.1.0"})
_DROPPED_EXTENSIONS = frozenset({
    "_dbm.cpython-314-x86_64-linux-gnu.so",
    "_tkinter.cpython-314-x86_64-linux-gnu.so",
})
_REQUIRED = (
    (_EXEC_SOURCE, 32_207_448,
     "241bf774a81580bb760adf960b48df7e6b23b1de026c9c912d4ca6be1a08241e"),
    ("python/lib/libpython3.14.so.1.0", 33_163_040,
     "938327ebe31592dc386714eeb3776b72f95f793b7bd53347349655b97f42f2a6"),
    ("python/LICENSE.txt", 13_804,
     "b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231"),
)
_REQUIRED_STDLIB = frozenset({_STDLIB + "os.py", _STDLIB + "encodings/__init__.py"})
_GENERATED = (
    ("python/lib/python3.14/lib-dynload/README.mobile-release-kit.txt",
     b"MobileReleaseKit preserves this directory as a Python layout landmark.\n"
     b"This marker does not qualify Python path or native loader behavior.\n",
     "lib-dynload-marker-v1"),
    ("python/lib/python314.zip", b"PK\x05\x06" + b"\0" * 18, "empty-zip-v1"),
)
_SENTINEL = b"INCOMPLETE publisher output; not an admitted runtime or handoff.\n"
_METADATA_TYPES = frozenset({tarfile.XHDTYPE, tarfile.XGLTYPE,
                            tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK})
_MEMBER_TYPES = frozenset({tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE})
_PAX_KEYS = frozenset({b"path", b"linkpath", b"size", b"uid", b"gid", b"uname", b"gname",
                       b"mtime", b"atime", b"ctime"})


class PayloadError(ValueError):
    pass


class _Policy(NamedTuple):
    archive_size: int
    archive_sha256: str
    required: tuple[tuple[str, int, str], ...]
    notice_inventory_sha256: str | None
    provenance_sha256: str | None


# Identity, not a caller-controlled profile label, distinguishes the production
# policy in reports. Any other private policy is always an inert test fixture.
_PRODUCTION_POLICY = _Policy(ARCHIVE_BYTES, ARCHIVE_SHA256, _REQUIRED,
                             APPROVED_NOTICE_INVENTORY_SHA256,
                             APPROVED_STATIC_LINK_PROVENANCE_SHA256)


class _Item(NamedTuple):
    path: str
    content: bytes
    origin: dict[str, object]


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def _sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _safe_name(name: str) -> bool:
    return (re.fullmatch(r"[A-Za-z0-9._+\-]+", name, flags=re.ASCII) is not None
            and name not in {".", ".."} and not name.endswith(".")
            and name.split(".", 1)[0].lower() not in _RESERVED)


def _relative(name: str, *, source: bool = False) -> tuple[str, ...]:
    parts = tuple(name.split("/"))
    if (not name or len(name) > MAX_PATH_BYTES or len(parts) > MAX_PATH_PARTS
            or any(not _safe_name(part) for part in parts)
            or (source and parts[0] != "python")):
        raise PayloadError("Unsafe or over-limit portable archive/payload path")
    return parts


def _state(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _ordinary(path: Path, *, directory: bool = False) -> os.stat_result:
    value = path.lstat()
    if (getattr(value, "st_file_attributes", 0) & 0x400
            or (not stat.S_ISDIR(value.st_mode) if directory else
                not stat.S_ISREG(value.st_mode) or value.st_nlink != 1)):
        raise PayloadError("Only ordinary directories and single-link files are admitted")
    return value


def _absolute(path: Path) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise PayloadError("Explicit absolute local input/output paths are required")
    return path


def _directory(path: Path) -> Path:
    _absolute(path)
    for ancestor in reversed((path, *path.parents)):
        _ordinary(ancestor, directory=True)
    return path


def _absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise PayloadError("Output/report must be absent; no overwrite or adoption")


def _read_checked(path: Path, *, limit: int) -> bytes:
    _directory(path.parent)
    before = _ordinary(path)
    if before.st_size < 0 or before.st_size > limit:
        raise PayloadError("Input file byte limit exceeded")
    with path.open("rb") as stream:
        if _state(os.fstat(stream.fileno())) != _state(before):
            raise PayloadError("Input changed before reading")
        content = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    if (len(content) != before.st_size or _state(after) != _state(before)
            or _state(path.lstat()) != _state(before)):
        raise PayloadError("Input changed during reading")
    return content


def _checked_digest(path: Path, *, limit: int, expected: str, size: int | None = None) -> bytes:
    content = _read_checked(path, limit=limit)
    if (size is not None and len(content) != size) or _digest(content) != expected:
        raise PayloadError("Input size or SHA256 does not match its pinned inventory")
    return content


def _require_policy(policy: _Policy) -> None:
    # This happens before any file read, parsing or output creation. Even the
    # private algorithm path may not use an incomplete policy.
    if policy.notice_inventory_sha256 is None or policy.provenance_sha256 is None:
        raise PayloadError("Production preparation is closed: accepted notice and static-link anchors are missing")
    if (type(policy.archive_size) is not int or not 0 < policy.archive_size <= MAX_TAR_BYTES
            or not all(_sha256(value) for value in (policy.archive_sha256,
                       policy.notice_inventory_sha256, policy.provenance_sha256))
            or len(policy.required) != len(_REQUIRED)
            or {item[0] for item in policy.required} != {item[0] for item in _REQUIRED}
            or any(type(size) is not int or not 0 < size <= MAX_FILE_BYTES or not _sha256(sha)
                   for _, size, sha in policy.required)):
        raise PayloadError("Invalid fixed transformation policy")


def _decode_gzip(compressed: bytes) -> bytes:
    """One complete gzip stream; zlib checks its CRC/length, not just tar EOF."""
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    decoded = bytearray()
    try:
        for position in range(0, len(compressed), 64 * 1024):
            chunk = compressed[position:position + 64 * 1024]
            last = position + len(chunk) == len(compressed)
            while chunk:
                decoded.extend(decoder.decompress(chunk, min(64 * 1024, MAX_TAR_BYTES - len(decoded) + 1)))
                if len(decoded) > MAX_TAR_BYTES:
                    raise PayloadError("Decompressed archive ceiling exceeded")
                chunk = decoder.unconsumed_tail
                if decoder.eof:
                    if decoder.unused_data or chunk or not last:
                        raise PayloadError("Trailing bytes or a second gzip stream are forbidden")
                    return bytes(decoded)
    except zlib.error as error:
        raise PayloadError("Invalid gzip data or checksum") from error
    raise PayloadError("Truncated gzip stream")


def _check_pax(data: bytes) -> None:
    """Validate bounded framing/keys before stdlib sees semantic metadata."""
    position = 0
    seen: set[bytes] = set()
    while position < len(data):
        separator = data.find(b" ", position, min(len(data), position + 12))
        if separator < 0 or not data[position:separator].isdigit():
            raise PayloadError("Invalid PAX record length")
        length = int(data[position:separator])
        end = position + length
        if length < 5 or end > len(data) or end <= separator or data[end - 1:end] != b"\n":
            raise PayloadError("Invalid PAX record framing")
        key, equals, value = data[separator + 1:end - 1].partition(b"=")
        if equals != b"=" or key not in _PAX_KEYS or key in seen or b"\0" in value:
            raise PayloadError("Unsupported, duplicate or sparse PAX metadata")
        seen.add(key)
        try:
            value.decode("utf-8", "strict")
        except UnicodeError as error:
            raise PayloadError("Invalid PAX text encoding") from error
        if key == b"size" and (not value.isdigit() or len(value) > 10 or int(value) > MAX_FILE_BYTES):
            raise PayloadError("PAX size exceeds regular-file bounds")
        if key == b"path":
            _relative(value.decode("utf-8").removesuffix("/"), source=True)
        position = end


def _raw_tar(data: bytes) -> tuple[dict[int, tuple[int, bytes]], int]:
    """Bound raw framing before tarfile may consume PAX/GNU advertised sizes."""
    if len(data) > MAX_TAR_BYTES or len(data) < 2 * _BLOCK or len(data) % _BLOCK:
        raise PayloadError("Tar must have complete aligned blocks and an EOF trailer")
    position = headers = metadata_bytes = chain = 0
    records: dict[int, tuple[int, bytes]] = {}
    while position < len(data):
        block = data[position:position + _BLOCK]
        if block == _ZERO_BLOCK:
            if len(data) - position < 2 * _BLOCK or any(memoryview(data)[position:]) or chain:
                raise PayloadError("Invalid tar terminator, nonzero tail or second archive")
            return records, position
        headers += 1
        if headers > MAX_TAR_HEADERS:
            raise PayloadError("Tar header count exceeded")
        try:
            info = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
        except (tarfile.HeaderError, UnicodeError, ValueError) as error:
            raise PayloadError("Invalid raw tar header") from error
        if info.type not in _METADATA_TYPES | _MEMBER_TYPES or info.size < 0:
            raise PayloadError("Sparse, hard-link, special or unsupported tar entry")
        metadata = info.type in _METADATA_TYPES
        limit = MAX_METADATA_BYTES if metadata else MAX_FILE_BYTES
        if info.size > limit:
            raise PayloadError("Tar declared file/metadata size exceeded")
        if not metadata and info.type not in {tarfile.REGTYPE, tarfile.AREGTYPE} and info.size:
            raise PayloadError("Non-regular tar member has a data body")
        start = position + _BLOCK
        end = start + ((info.size + _BLOCK - 1) // _BLOCK) * _BLOCK
        if end > len(data):
            raise PayloadError("Truncated tar member body")
        if metadata:
            metadata_bytes += info.size
            chain += 1
            if metadata_bytes > MAX_TOTAL_METADATA_BYTES or chain > MAX_METADATA_CHAIN:
                raise PayloadError("Tar metadata aggregate/chain bound exceeded")
            body = data[start:start + info.size]
            if info.type in {tarfile.XHDTYPE, tarfile.XGLTYPE}:
                _check_pax(body)
            else:
                value, terminator, padding = body.partition(b"\0")
                if not terminator or any(padding):
                    raise PayloadError("Invalid GNU long-name/link metadata")
                try:
                    value.decode("utf-8", "strict")
                except UnicodeError as error:
                    raise PayloadError("Invalid GNU metadata encoding") from error
                if info.type == tarfile.GNUTYPE_LONGNAME:
                    _relative(value.decode("utf-8").removesuffix("/"), source=True)
        else:
            # A preceding long-name/PAX record can replace a truncated fallback
            # name. Every final logical source path is validated below instead.
            _, terminator_byte, padding = block[:100].partition(b"\0")
            if terminator_byte and any(padding):
                raise PayloadError("Hidden bytes after the tar name terminator")
            # TarInfo normalizes directory suffixes. Do not let that silently
            # admit an empty raw path component in a directory header.
            if info.isdir() and block[:100].split(b"\0", 1)[0].endswith(b"//"):
                raise PayloadError("Noncanonical directory source path")
            records[start] = (info.size, info.type)
            chain = 0
        position = end
    raise PayloadError("Missing tar EOF blocks")


class _TarReader(io.BytesIO):
    def read(self, size: int = -1) -> bytes:
        if size < 0 or size > MAX_METADATA_BYTES + _BLOCK:
            raise PayloadError("Unbounded stdlib tar metadata read refused")
        return super().read(size)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_CUR:
            offset += self.tell()
        elif whence == os.SEEK_END:
            offset += self.getbuffer().nbytes
        elif whence != os.SEEK_SET:
            raise PayloadError("Unsupported tar seek")
        if not 0 <= offset <= self.getbuffer().nbytes:
            raise PayloadError("Tar seek exceeds admitted bytes")
        return super().seek(offset)


def _selection(name: str) -> tuple[str | None, str]:
    if name == _EXEC_SOURCE:
        return _EXEC_DESTINATION, "executable-byte-mapping"
    if name == _EXEC_DESTINATION or name in {entry[0] for entry in _GENERATED}:
        raise PayloadError("Archive regular file occupies a reserved generated destination")
    if name == "python/LICENSE.txt":
        return name, "original-python-license"
    if name.startswith(_STDLIB):
        tail = name[len(_STDLIB):]
        parts = tail.split("/")
        if "__pycache__" in parts or tail.lower().endswith((".pyc", ".pyo")):
            return None, "bytecode-cache"
        if parts[0] in {"site-packages", "ensurepip"}:
            return None, "package-installation-material"
        if parts[0] in {"tkinter", "idlelib", "turtledemo", "turtle.py"}:
            return None, "interactive-tcl-tk-material"
        if parts[0] == "config-3.14-x86_64-linux-gnu":
            return None, "build-configuration"
        if parts[0] == "lib-dynload":
            if len(parts) == 2 and parts[1] in _DROPPED_EXTENSIONS:
                return None, "excluded-db-or-tk-extension"
            raise PayloadError("Unexpected lib-dynload member")
        return name, "ordinary-stdlib"
    parts = name.split("/")
    if len(parts) == 3 and parts[1] == "lib" and parts[2] in _LIBPYTHON:
        return name, "regular-libpython"
    if len(parts) > 2 and parts[1] == "bin":
        return None, "other-bin-entry"
    if len(parts) > 2 and parts[1] == "include":
        return None, "development-headers"
    if len(parts) > 2 and parts[1] == "share":
        return None, "terminfo" if parts[2] == "terminfo" else "distributor-share-data"
    if len(parts) > 2 and parts[1] == "lib":
        if parts[2] == "pkgconfig":
            return None, "development-pkgconfig"
        if parts[2].startswith(("tcl", "tk", "itcl", "thread", "libtcl", "libtk")):
            return None, "tcl-tk-library-or-data"
        if len(parts) == 3 and parts[2].endswith(".a"):
            return None, "development-static-library"
    raise PayloadError("Unexpected source category outside the frozen subset recipe")


def _archive_items(data: bytes, policy: _Policy) -> tuple[list[_Item], list[dict[str, object]]]:
    raw, terminator = _raw_tar(data)
    remaining = dict(raw)
    selected: list[_Item] = []
    omissions: list[dict[str, object]] = []
    seen: set[str] = set()
    retained_sources: dict[str, tuple[int, str]] = {}
    try:
        with tarfile.open(fileobj=_TarReader(data), mode="r:", encoding="utf-8", errors="strict",
                          errorlevel=2) as archive:
            for member in archive:
                if (member.offset_data not in remaining or member.sparse is not None
                        or remaining.pop(member.offset_data) != (member.size, member.type)):
                    raise PayloadError("Logical tar member disagrees with bounded raw framing")
                _relative(member.name, source=True)
                if member.name in seen:
                    raise PayloadError("Duplicate source tar path")
                seen.add(member.name)
                if member.issym() or member.isdir():
                    omissions.append({"path": member.name, "size": member.size,
                                      "reason": "symbolic-link" if member.issym() else "directory-header"})
                    continue  # Never read, follow, flatten or emit a link target.
                destination, reason = _selection(member.name)
                if destination is None:
                    omissions.append({"path": member.name, "size": member.size, "reason": reason})
                    continue
                content = data[member.offset_data:member.offset_data + member.size]
                sha = _digest(content)
                retained_sources[member.name] = (len(content), sha)
                selected.append(_Item(destination, content,
                                      {"kind": "archive-member", "member": member.name,
                                       "selection": reason, "sha256": sha}))
            # tarfile normally stops at the FIRST zero block and can also stop
            # on an invalid later header. Raw framing and full consumption must
            # agree; neither behavior alone constitutes strict archive EOF.
            if remaining or archive.offset != terminator:
                raise PayloadError("Stdlib tar stopped before the validated terminator")
    except PayloadError:
        raise
    except (tarfile.TarError, UnicodeError, ValueError, OverflowError) as error:
        raise PayloadError("Invalid bounded tar archive") from error
    if any(retained_sources.get(name) != (size, sha) for name, size, sha in policy.required):
        raise PayloadError("Required executable, libpython or license is missing or changed")
    if not _REQUIRED_STDLIB <= retained_sources.keys():
        raise PayloadError("Required stdlib layout landmark is missing")
    return selected, sorted(omissions, key=lambda item: str(item["path"]))


def _tree(root: Path, *, max_files: int, max_entries: int) -> tuple[dict[str, Path], set[str]]:
    _directory(root)
    files: dict[str, Path] = {}
    directories: set[str] = set()
    seen: set[str] = set()
    pending = [root]
    while pending:
        parent = pending.pop()
        with os.scandir(parent) as children:
            for child in children:
                path = parent / child.name
                relative = path.relative_to(root).as_posix()
                _relative(relative)
                folded = relative.lower()
                if folded in seen or len(seen) >= max_entries:
                    raise PayloadError("Input/output tree has aliased paths or too many entries")
                seen.add(folded)
                value = path.lstat()
                if stat.S_ISDIR(value.st_mode):
                    _ordinary(path, directory=True)
                    directories.add(relative)
                    pending.append(path)
                else:
                    _ordinary(path)
                    files[relative] = path
                    if len(files) > max_files:
                        raise PayloadError("Input/output tree file count exceeded")
    required = _ancestors(files)
    if directories != required:
        raise PayloadError("Empty or uninventoried input/output directory")
    return files, directories


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PayloadError("Duplicate notice inventory key")
        result[key] = value
    return result


def _notice_items(root: Path, inventory: bytes, inventory_sha256: str) -> list[_Item]:
    if len(inventory) > MAX_NOTICE_INVENTORY_BYTES:
        raise PayloadError("Notice inventory byte ceiling exceeded")
    try:
        manifest = json.loads(inventory, object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise PayloadError("Invalid bounded notice inventory JSON") from error
    if (type(manifest) is not dict or set(manifest) != {"schemaVersion", "pythonChangeSummary", "files"}
            or type(manifest["schemaVersion"]) is not int or manifest["schemaVersion"] != 1
            or type(manifest["files"]) is not list or not 0 < len(manifest["files"]) <= MAX_NOTICE_FILES
            or type(manifest["pythonChangeSummary"]) is not str):
        raise PayloadError("Notice inventory schema/count mismatch")
    expected: dict[str, tuple[int, str]] = {}
    total = 0
    for entry in manifest["files"]:
        if (type(entry) is not dict or set(entry) != {"path", "size", "sha256"}
                or type(entry["path"]) is not str or type(entry["size"]) is not int
                or not 0 < entry["size"] <= MAX_NOTICE_BYTES or not _sha256(entry["sha256"])):
            raise PayloadError("Invalid notice inventory file record")
        path = entry["path"]
        _relative("python/licenses/" + path, source=True)
        if path in expected:
            raise PayloadError("Duplicate notice inventory file")
        expected[path] = (entry["size"], entry["sha256"])
        total += entry["size"]
    if manifest["pythonChangeSummary"] not in expected or total > MAX_NOTICE_BYTES:
        raise PayloadError("Shipped Python change-summary notice missing or notice bytes exceeded")
    actual, _ = _tree(root, max_files=MAX_NOTICE_FILES, max_entries=MAX_NOTICE_ENTRIES)
    if actual.keys() != expected.keys():
        raise PayloadError("Notice files are extra, missing or renamed")
    result: list[_Item] = []
    for path in sorted(expected):
        size, sha = expected[path]
        content = _checked_digest(actual[path], limit=size, size=size, expected=sha)
        result.append(_Item("python/licenses/" + path, content,
                            {"kind": "notice-file", "path": path,
                             "inventorySha256": inventory_sha256,
                             "pythonChangeSummary": path == manifest["pythonChangeSummary"]}))
    return result


def _ancestors(paths: Iterable[str]) -> set[str]:
    result: set[str] = set()
    for path in paths:
        parts = path.split("/")
        result.update("/".join(parts[:index]) for index in range(1, len(parts)))
    return result


def _inventory(items: list[_Item]) -> list[dict[str, object]]:
    return [{"path": item.path, "size": len(item.content), "sha256": _digest(item.content)}
            for item in sorted(items, key=lambda item: item.path)]


def _preflight_items(items: list[_Item]) -> set[str]:
    namespace: dict[str, tuple[str, str]] = {}
    total = 0
    for item in items:
        parts = _relative(item.path, source=True)
        if len(parts) < 2:
            raise PayloadError("Payload files must be below the python directory")
        for index in range(1, len(parts) + 1):
            name = "/".join(parts[:index])
            kind = "file" if index == len(parts) else "directory"
            previous = namespace.get(name.lower())
            if previous is not None and (previous != (name, kind) or kind == "file"):
                raise PayloadError("Retained/generated/notice path or ancestor collision")
            namespace[name.lower()] = (name, kind)
        if len(item.content) > MAX_FILE_BYTES:
            raise PayloadError("Selected payload file byte ceiling exceeded")
        total += len(item.content)
    if (len(items) + len(RESERVED_PAYLOAD_FILES) > MAX_FILES
            or len(namespace) + RESERVED_ENTRIES > MAX_ENTRIES
            or total + RESOURCE_BYTE_HEADROOM > MAX_TOTAL_BYTES):
        raise PayloadError("Selected payload leaves insufficient final resource headroom")
    # Check a conservative final-manifest envelope without emitting a runtime
    # manifest or claiming the later preparer's actual core metadata is admitted.
    inventory = _inventory(items)
    inventory.extend({"path": path, "size": RESOURCE_BYTE_HEADROOM, "sha256": "0" * 64}
                     for path in RESERVED_PAYLOAD_FILES)
    if (len(_canonical(inventory)) + MANIFEST_METADATA_HEADROOM > MAX_MANIFEST_BYTES
            or 7 * len(inventory) + 32 > MAX_MANIFEST_NODES):
        raise PayloadError("Selected payload exceeds final manifest envelope")
    return {name for name, kind in namespace.values() if kind == "directory"}


def _report(policy: _Policy, items: list[_Item], omissions: list[dict[str, object]]) -> bytes:
    profile = ({"kind": "frozen-production-candidate", "id": PROFILE, "target": TARGET,
                "pbsCommit": PBS_COMMIT, "cpythonCommit": CPYTHON_COMMIT}
               if policy is _PRODUCTION_POLICY else
               {"kind": "inert-test-fixture", "id": "not-a-production-profile"})
    document = {
        "schemaVersion": 1,
        "evidenceKind": "descriptive-transform-mapping",
        "notACompletionOrHandoffReceipt": True,
        "qualification": "no-native-supply-or-legal-qualification",
        "profile": profile,
        "archive": {"size": policy.archive_size, "sha256": policy.archive_sha256},
        "noticeInventorySha256": policy.notice_inventory_sha256,
        "staticLinkProvenanceSha256": policy.provenance_sha256,
        "files": [dict(record, origin=item.origin) for item, record in
                  zip(sorted(items, key=lambda item: item.path), _inventory(items))],
        "omissions": sorted(omissions, key=lambda item: str(item["path"])),
        "reservedPayloadFiles": list(RESERVED_PAYLOAD_FILES),
        "reservedEntriesIncludingManifest": RESERVED_ENTRIES,
        "resourceByteHeadroom": RESOURCE_BYTE_HEADROOM,
    }
    encoded = _canonical(document) + b"\n"
    if len(encoded) > MAX_REPORT_BYTES:
        raise PayloadError("Transform mapping report byte ceiling exceeded")
    return encoded


def _write_file(path: Path, content: bytes, mode: int) -> None:
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), mode)
        if stream.write(content) != len(content):
            raise PayloadError("Short publisher output write")


def _verify_output(root: Path, items: list[_Item], directories: set[str]) -> None:
    files, actual_directories = _tree(root, max_files=MAX_FILES, max_entries=MAX_ENTRIES)
    expected = {item.path: item.content for item in items}
    expected["INCOMPLETE"] = _SENTINEL
    if files.keys() != expected.keys() or actual_directories != directories:
        raise PayloadError("Written output inventory differs from preflight")
    for name, content in expected.items():
        if _read_checked(files[name], limit=len(content)) != content:
            raise PayloadError("Written output bytes differ from preflight")
        wanted = 0o600 if name == "INCOMPLETE" else (0o755 if name == _EXEC_DESTINATION else 0o644)
        if stat.S_IMODE(_ordinary(files[name]).st_mode) != wanted:
            raise PayloadError("Written output mode differs from fixed policy")


def _write_payload(output: Path, report_path: Path, items: list[_Item], directories: set[str], report: bytes) -> None:
    _directory(output.parent)
    _directory(report_path.parent)
    _absent(output)
    _absent(report_path)
    output.mkdir(mode=0o700)
    _write_file(output / "INCOMPLETE", _SENTINEL, 0o600)
    for directory in sorted(directories, key=lambda name: (name.count("/"), name)):
        (output / directory).mkdir(mode=0o755)
    for item in sorted(items, key=lambda item: item.path):
        _write_file(output / item.path, item.content, 0o755 if item.path == _EXEC_DESTINATION else 0o644)
    _verify_output(output, items, directories)
    # A report can remain after failure, so its contents explicitly disavow being
    # a completion receipt. Only the final sentinel removal completes this call.
    _write_file(report_path, report, 0o600)
    if _read_checked(report_path, limit=MAX_REPORT_BYTES) != report:
        raise PayloadError("Written report bytes differ from preflight")
    if _read_checked(output / "INCOMPLETE", limit=len(_SENTINEL)) != _SENTINEL:
        raise PayloadError("Incomplete-output sentinel changed")
    (output / "INCOMPLETE").unlink()


def _prepare_with_policy(archive: Path, notices: Path, notice_inventory: Path,
                         static_link_provenance: Path, output: Path, report: Path,
                         policy: _Policy) -> dict[str, str]:
    _require_policy(policy)
    for path in (archive, notices, notice_inventory, static_link_provenance, output, report):
        _absolute(path)
    if report == output or output in report.parents:
        raise PayloadError("Separate report must be outside the output subtree")
    if any(path == notices or notices in path.parents for path in (output, report)):
        raise PayloadError("Outputs cannot mutate the notice input tree")
    _directory(output.parent)
    _directory(report.parent)
    _absent(output)
    _absent(report)
    # Verify ALL pinned input bytes before decompression; no runtime is imported.
    compressed = _checked_digest(archive, limit=policy.archive_size, size=policy.archive_size,
                                 expected=policy.archive_sha256)
    inventory = _checked_digest(notice_inventory, limit=MAX_NOTICE_INVENTORY_BYTES,
                                expected=policy.notice_inventory_sha256)
    _checked_digest(static_link_provenance, limit=MAX_PROVENANCE_BYTES,
                    expected=policy.provenance_sha256)
    notices_to_copy = _notice_items(notices, inventory, policy.notice_inventory_sha256)
    items, omissions = _archive_items(_decode_gzip(compressed), policy)
    items.extend(notices_to_copy)
    items.extend(_Item(path, content, {"kind": "generated", "recipe": recipe})
                 for path, content, recipe in _GENERATED)
    directories = _preflight_items(items)
    mapping = _report(policy, items, omissions)
    _write_payload(output, report, items, directories, mapping)
    return {"operation": "publisher-transform-completed", "reportSha256": _digest(mapping),
            "profileKind": "frozen-production-candidate" if policy is _PRODUCTION_POLICY else "inert-test-fixture",
            "qualification": "no-native-supply-or-legal-qualification"}


def prepare(archive: Path, notices: Path, notice_inventory: Path, static_link_provenance: Path,
            output: Path, report: Path) -> dict[str, str]:
    """Closed production entry point; there is deliberately no policy override."""
    return _prepare_with_policy(archive, notices, notice_inventory, static_link_provenance,
                                output, report, _PRODUCTION_POLICY)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--notices", required=True, type=Path)
    parser.add_argument("--notice-inventory", required=True, type=Path)
    parser.add_argument("--static-link-provenance", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.archive, args.notices, args.notice_inventory,
                                 args.static_link_provenance, args.output, args.report), sort_keys=True))
    except (OSError, ValueError, UnicodeError, RecursionError):
        parser.exit(1, "CPython payload preparation refused or failed. Inputs and partial output were preserved; "
                       "no native, supply, or legal qualification was performed.\n")


if __name__ == "__main__":
    main()
