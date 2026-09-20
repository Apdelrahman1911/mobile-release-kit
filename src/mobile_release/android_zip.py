"""Bounded Android ZIP metadata policy over already-captured byte ranges.

No file, ZipFile, decompressor, callback, process or artifact owner is created.
These immutable values are DATA, not proof of custody, CRCs, native AAB validity,
source freshness, signing or release authority. The original owner must supply
exact reads, retain/recheck their original objects, and bound actual member work.

First profile: single-disk ZIP32, no prefix/trailer, STORED or DEFLATED. ZIP64
and Unicode-path overrides are explicitly unsupported, never a fallback that
lets ZipFile choose different offsets, allocate larger names or add members.
"""
from __future__ import annotations

from dataclasses import dataclass
import stat
import struct
from typing import NoReturn

# Shared limits and entry policy for the CLI and original-artifact inspection.
MAX_ENTRY_SIZE = 512 * 1024 * 1024
MAX_TOTAL_SIZE = 2 * 1024 * 1024 * 1024
MAX_ENTRY_COUNT = 100_000
MAX_AAB_BYTES = 1024 * 1024 * 1024
MAX_CENTRAL_DIRECTORY_BYTES = 16 * 1024 * 1024
MAX_ENTRY_NAME_BYTES = 4096
EOCD_BYTES = 22
CENTRAL_HEADER_BYTES = 46
LOCAL_HEADER_BYTES = 30
# The extra20 bytes expose a ZIP64 locator even with the maximum65535B comment.
MAX_TAIL_BYTES = EOCD_BYTES + 0xFFFF + 20

_EOCD = b"PK\x05\x06"
_CENTRAL = b"PK\x01\x02"
_ZIP64_LOCATOR = b"PK\x06\x07"
_MESSAGES = {
    "input": "Android ZIP inspection requires exact bounded metadata bytes.",
    "limit": "The Android ZIP exceeds supported inspection limits.",
    "end": "The Android ZIP end record is missing, truncated or ambiguous.",
    "directory": "The Android ZIP central directory is inconsistent or malformed.",
    "zip64": "ZIP64 Android bundles are not supported by this inspection profile.",
    "multidisk": "Multi-disk Android ZIP bundles are not supported.",
    "entry": "The Android ZIP contains an unsafe or unsupported entry.",
    "name": "The Android ZIP contains an unsafe or ambiguous entry name.",
    "duplicate": "The Android ZIP contains duplicate entry names or offsets.",
    "encryption": "Encrypted Android ZIP entries are not supported.",
    "compression": "The Android ZIP uses unsupported compression metadata.",
    "layout": "The Android ZIP local-entry layout is inconsistent or unsupported.",
    "content": "The Android ZIP lacks required AAB content names.",
}


class AndroidZipError(ValueError):
    """Fixed reason/message only; never expose an entry name or parser text."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(_MESSAGES[reason])


def _reject(reason: str) -> NoReturn:
    raise AndroidZipError(reason) from None


@dataclass(frozen=True, slots=True)
class ZipReadRange:
    offset: int
    length: int


@dataclass(frozen=True, slots=True)
class ZipDirectoryPlan:
    archive_bytes: int
    end_offset: int
    entry_count: int
    central_directory: ZipReadRange


@dataclass(frozen=True, slots=True)
class AndroidZipEntry:
    name: str
    raw_name: bytes
    flag_bits: int
    compression: int
    crc32: int
    compressed_size: int
    file_size: int
    local_header_offset: int
    external_attr: int
    create_system: int
    extract_version: int


@dataclass(frozen=True, slots=True)
class AndroidZipMetadata:
    plan: ZipDirectoryPlan
    entries: tuple[AndroidZipEntry, ...]
    declared_expanded_bytes: int


def zip_tail_range(archive_bytes: int) -> ZipReadRange:
    """First exact read proposal, after the owner establishes its original size."""
    if type(archive_bytes) is not int:
        _reject("input")
    if not EOCD_BYTES <= archive_bytes <= MAX_AAB_BYTES:
        _reject("limit")
    length = min(archive_bytes, MAX_TAIL_BYTES)
    return ZipReadRange(archive_bytes - length, length)


def _check_plan(plan: ZipDirectoryPlan) -> None:
    # A public dataclass is not an unforgeable admission token. Recheck hard
    # limits before reading/retaining a caller-supplied directory, even if the
    # caller constructed a plan instead of using plan_zip_directory().
    if type(plan) is not ZipDirectoryPlan or type(plan.central_directory) is not ZipReadRange:
        _reject("input")
    zip_tail_range(plan.archive_bytes)
    count, end = plan.entry_count, plan.end_offset
    offset, length = plan.central_directory.offset, plan.central_directory.length
    if any(type(value) is not int for value in (count, end, offset, length)):
        _reject("input")
    if count == 0xFFFF or offset == 0xFFFFFFFF or length == 0xFFFFFFFF:
        _reject("zip64")
    # ZIP32 cannot represent65535 unambiguously; the existing100000 maximum
    # is not raised or used to justify an unchecked ZIP64 layout.
    if not 0 < count < 0xFFFF or count > MAX_ENTRY_COUNT:
        _reject("limit")
    if not CENTRAL_HEADER_BYTES * count + count <= length <= MAX_CENTRAL_DIRECTORY_BYTES:
        _reject("limit")
    if not 0 <= plan.archive_bytes - end - EOCD_BYTES <= 0xFFFF:
        _reject("end")
    if not LOCAL_HEADER_BYTES < offset < end or offset + length != end:
        _reject("directory")


def plan_zip_directory(archive_bytes: int, tail: bytes) -> ZipDirectoryPlan:
    """Admit EOCD/layout bounds, then propose the one exact central-directory read.

    The bytes must be the original range returned by zip_tail_range(). No seek,
    read retry, prefix compensation, ZIP64 read or ZipFile allocation occurs.
    """
    requested = zip_tail_range(archive_bytes)
    if type(tail) is not bytes:
        _reject("input")
    if len(tail) != requested.length:
        _reject("end")
    # Match ZipFile's no-comment fast path before its last-signature search.
    # A valid size/offset field can itself contain the EOCD signature bytes.
    index = (len(tail) - EOCD_BYTES
             if tail[-EOCD_BYTES:-EOCD_BYTES + 4] == _EOCD and tail[-2:] == b"\0\0"
             else tail.rfind(_EOCD))
    if index < 0 or index + EOCD_BYTES > len(tail):
        _reject("end")
    end = struct.unpack_from("<4s4H2IH", tail, index)
    if index + EOCD_BYTES + end[7] != len(tail):
        _reject("end")  # No trailing bytes, truncated comment or signature fallback.
    # Refuse two end records whose declared comments both terminate at EOF.
    # The finite tail bounds this scan; no candidate list or arbitrary search.
    earlier = tail.find(_EOCD, 0, index)
    while earlier >= 0:
        if (earlier + EOCD_BYTES <= len(tail)
                and earlier + EOCD_BYTES + struct.unpack_from("<H", tail, earlier + 20)[0] == len(tail)):
            _reject("end")
        earlier = tail.find(_EOCD, earlier + 4, index)
    if index >= 20 and tail[index - 20:index - 16] == _ZIP64_LOCATOR:
        _reject("zip64")
    if end[3] == 0xFFFF or end[4] == 0xFFFF or end[5] == 0xFFFFFFFF or end[6] == 0xFFFFFFFF:
        _reject("zip64")
    if end[1] != 0 or end[2] != 0 or end[3] != end[4]:
        _reject("multidisk")
    plan = ZipDirectoryPlan(archive_bytes, requested.offset + index, end[4], ZipReadRange(end[6], end[5]))
    _check_plan(plan)
    return plan


def validate_zip_entry_policy(
    name: str, *, flag_bits: int, external_attr: int, file_size: int,
) -> None:
    """Shared extraction of android.py's path/type/encryption/member-size policy.

    Directory parsing checks the raw name byte limit before decoding. This
    predicate also bounds direct callers; it never truncates/normalizes names.
    NULs, drive roots and conflicting type markers are refused rather than
    allowing ZipInfo or a platform-specific consumer to change their meaning.
    """
    if (type(name) is not str or any(type(value) is not int for value in (flag_bits, external_attr, file_size))
            or not 0 <= flag_bits <= 0xFFFF or not 0 <= external_attr <= 0xFFFFFFFF or file_size < 0):
        _reject("input")
    if len(name) > MAX_ENTRY_NAME_BYTES or file_size > MAX_ENTRY_SIZE:
        _reject("limit")
    if flag_bits & (0x0001 | 0x0040 | 0x2000):
        _reject("encryption")
    directory = name.endswith("/")
    parts = name.split("/")
    path_parts = parts[:-1] if directory else parts
    # Original Core raw-part checks, not normalized PurePosixPath.parts.
    if (not name or name.startswith("/") or "\\" in name or "\0" in name
            or (len(name) >= 2 and name[1] == ":")
            or any(part in {"", ".", ".."} for part in path_parts)
            or any(0xD800 <= ord(char) <= 0xDFFF for char in name)):
        _reject("name")
    mode = stat.S_IFMT(external_attr >> 16)
    if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
        _reject("entry")
    if (mode == stat.S_IFDIR and not directory) or (mode == stat.S_IFREG and directory):
        _reject("entry")
    if external_attr & 0x08 or (external_attr & 0x10 and not directory):
        _reject("entry")  # DOS volume labels/conflicting directory markers.
    if directory and file_size != 0:
        _reject("entry")


def _check_extra(data: bytes, start: int, length: int) -> None:
    end = start + length
    while start < end:
        if start + 4 > end:
            _reject("directory")
        tag, size = struct.unpack_from("<HH", data, start)
        start += 4
        if start + size > end:
            _reject("directory")
        if tag == 0x0001:
            _reject("zip64")
        if tag == 0x7075:
            # Modern ZipFile honors this field and may sanitize/replace the
            # bounded central-header name. Do not admit that second name view.
            _reject("name")
        if tag in (0x0017, 0x9901):
            _reject("encryption")
        start += size


def inspect_zip_directory(plan: ZipDirectoryPlan, data: bytes) -> AndroidZipMetadata:
    """Parse bounded central metadata BEFORE the owner may construct ZipFile.

    No local header/payload, actual expanded byte or CRC claim follows. Entries
    are retained in central order; only a finite offset list is sorted to reject
    duplicate/obviously overlapping local records and unsupported prefixes.
    """
    _check_plan(plan)
    if type(data) is not bytes:
        _reject("input")
    if len(data) != plan.central_directory.length:
        _reject("directory")
    entries: list[AndroidZipEntry] = []
    names: set[str] = set()
    extents: list[tuple[int, int]] = []
    position = total = 0
    for _index in range(plan.entry_count):
        if position + CENTRAL_HEADER_BYTES > len(data):
            _reject("directory")
        header = struct.unpack_from("<4s6H3I5H2I", data, position)
        if header[0] != _CENTRAL:
            _reject("directory")
        made, needed, flags, compression = header[1:5]
        crc, compressed, expanded = header[7:10]
        name_size, extra_size, comment_size, disk = header[10:14]
        external, local = header[15:17]
        if name_size == 0:
            _reject("name")
        if name_size > MAX_ENTRY_NAME_BYTES:
            _reject("limit")
        following = position + CENTRAL_HEADER_BYTES + name_size + extra_size + comment_size
        if following > len(data):
            _reject("directory")
        if needed == 45 or disk == 0xFFFF or 0xFFFFFFFF in (compressed, expanded, local):
            _reject("zip64")
        if disk != 0:
            _reject("multidisk")
        if flags & (0x0001 | 0x0040 | 0x2000):
            _reject("encryption")
        if compression not in (0, 8):
            _reject("compression")
        if (needed not in (10, 20) or (compression == 8 and needed != 20)
                or flags & ~(0x0006 | 0x0008 | 0x0800) or (compression == 0 and flags & 0x0006)):
            _reject("entry")
        if expanded > MAX_ENTRY_SIZE:
            _reject("limit")
        total += expanded
        if total > MAX_TOTAL_SIZE:
            _reject("limit")
        if (compression == 0 and compressed != expanded) or (compression == 8 and compressed < 2):
            _reject("compression")
        if expanded == 0 and crc != 0:
            _reject("entry")
        # Even without local-header bytes these extents must fit. Actual extra
        # lengths/data descriptors and all local/CD fields still need matching.
        minimum_end = local + LOCAL_HEADER_BYTES + name_size + compressed + (12 if flags & 0x0008 else 0)
        if not 0 <= local < minimum_end <= plan.central_directory.offset:
            _reject("layout")
        name_start = position + CENTRAL_HEADER_BYTES
        _check_extra(data, name_start + name_size, extra_size)
        raw_name = data[name_start:name_start + name_size]
        try:
            name = raw_name.decode("utf-8" if flags & 0x0800 else "cp437", errors="strict")
        except UnicodeError:
            _reject("name")
        validate_zip_entry_policy(name, flag_bits=flags, external_attr=external, file_size=expanded)
        if name in names:
            _reject("duplicate")
        names.add(name)
        entries.append(AndroidZipEntry(name, raw_name, flags, compression, crc, compressed,
                                       expanded, local, external, made >> 8, needed))
        extents.append((local, minimum_end))
        position = following
    if position != len(data):
        _reject("directory")  # Count disagreement, extra records or a digital-signature trailer.
    extents.sort()
    if extents[0][0] != 0:
        _reject("layout")
    previous_start, previous_end = -1, 0
    for start, end in extents:
        if start == previous_start:
            _reject("duplicate")
        if start < previous_end:
            _reject("layout")
        previous_start, previous_end = start, end
    return AndroidZipMetadata(plan, tuple(entries), total)


def require_aab_content_names(names: list[str] | tuple[str, ...]) -> None:
    """The shared three required-name rules; not protobuf or DEX validation."""
    if type(names) not in (list, tuple):
        _reject("input")
    if not 0 < len(names) <= MAX_ENTRY_COUNT:
        _reject("limit")
    manifest = dex = bundle_config = False
    for name in names:
        if type(name) is not str:
            _reject("input")
        if len(name) > MAX_ENTRY_NAME_BYTES:
            _reject("limit")
        manifest = manifest or name.startswith("base/manifest/")
        dex = dex or name.startswith("base/dex/")
        bundle_config = bundle_config or name == "BundleConfig.pb"
    if not (manifest and dex and bundle_config):
        _reject("content")


def require_aab_content(metadata: AndroidZipMetadata) -> None:
    """Retain Core's exact three required-name rules, not protobuf/DEX validity.

    Prefix observations alone (including directory entries) keep their existing
    meaning. Only later actual bounded reads/CRCs and same-byte pinned bundletool
    inspection can establish further structure or manifest identity findings.
    """
    if type(metadata) is not AndroidZipMetadata or type(metadata.entries) is not tuple:
        _reject("input")
    if not 0 < len(metadata.entries) <= MAX_ENTRY_COUNT:
        _reject("limit")
    for entry in metadata.entries:
        if type(entry) is not AndroidZipEntry or type(entry.name) is not str:
            _reject("input")
    require_aab_content_names(tuple(entry.name for entry in metadata.entries))
