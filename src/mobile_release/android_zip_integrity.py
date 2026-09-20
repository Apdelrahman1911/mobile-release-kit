"""Bounded ZIP32 integrity inspection through an original-owner-borrowed reader.

Only seek/tell/read are used; this helper never opens, owns, closes or publishes a
file, builds ZipFile, extracts members, or launches a tool. The required checkpoint
must enforce the original owner's cancellation AND absolute deadline by raising.
Reader/owner/checkpoint failures propagate unchanged. A checkpoint cannot preempt
one active OS read or zlib call; both input and output work per call are bounded.

The return is immutable observation DATA, not custody, authenticity, native AAB
validity, source freshness, signing or cleanup authority. The owner must keep the
same borrowed object live and exclusive to this work, perform its original file/
parent/digest rechecks, and settle its own closes. Reader position is not restored.
"""
from __future__ import annotations

import binascii
from dataclasses import dataclass
import struct
from typing import BinaryIO, Callable, NoReturn
import zlib

from .android_zip import (
    AndroidZipEntry,
    AndroidZipError,
    AndroidZipMetadata,
    LOCAL_HEADER_BYTES,
    MAX_CENTRAL_DIRECTORY_BYTES,
    MAX_ENTRY_NAME_BYTES,
    MAX_ENTRY_SIZE,
    MAX_TOTAL_SIZE,
    ZipReadRange,
    _check_extra,
    inspect_zip_directory,
    plan_zip_directory,
    zip_tail_range,
)

READ_CHUNK_BYTES = 64 * 1024
EXPANDED_CHUNK_BYTES = 64 * 1024
_LOCAL = b"PK\x03\x04"
_DESCRIPTOR = b"PK\x07\x08"
_DATA_MESSAGES = {
    "input": "Android ZIP integrity inspection requires a bounded binary reader and checkpoint.",
    "read": "The Android ZIP reader did not supply the exact requested bytes or position.",
    "compression": "An Android ZIP entry contains malformed or unsupported compressed data.",
    "size": "An Android ZIP entry does not match its declared expanded size.",
    "crc": "An Android ZIP entry failed its CRC integrity check.",
    "changed": "The Android ZIP size or inspected metadata changed during inspection.",
}


class AndroidZipIntegrityError(AndroidZipError):
    """Ordinary fixed DATA error; the existing AndroidZipError catch also covers it."""

    def __init__(self, reason: str) -> None:
        if reason in _DATA_MESSAGES:
            self.reason = reason
            ValueError.__init__(self, _DATA_MESSAGES[reason])
        else:
            super().__init__(reason)


def _reject(reason: str) -> NoReturn:
    raise AndroidZipIntegrityError(reason) from None


@dataclass(frozen=True, slots=True)
class AndroidZipIntegrity:
    metadata: AndroidZipMetadata
    expanded_bytes: int


def _check(checkpoint: Callable[[], None]) -> None:
    # Returning false is not a cancellation/deadline check. A caller that uses
    # a boolean API must adapt it explicitly, without replacing its owner.
    if checkpoint() is not None:
        _reject("input")


def _seek(reader: BinaryIO, offset: int, check: Callable[[], None]) -> None:
    check()
    position = reader.seek(offset, 0)
    check()
    if type(position) is not int or position != offset:
        _reject("read")


def _read_at(
    reader: BinaryIO, offset: int, length: int, archive_bytes: int,
    check: Callable[[], None],
) -> bytes:
    # Internal requests are bounded even if a future caller miscomputes a range.
    if not 0 < length <= READ_CHUNK_BYTES or not 0 <= offset <= archive_bytes - length:
        _reject("input")
    _seek(reader, offset, check)
    check()
    data = reader.read(length)
    check()
    if type(data) is not bytes or len(data) != length:
        _reject("read")  # No retry, read-all, replacement object or path fallback.
    check()
    position = reader.tell()
    check()
    if type(position) is not int or position != offset + length:
        _reject("read")
    return data


def _read_range(
    reader: BinaryIO, requested: ZipReadRange, archive_bytes: int,
    check: Callable[[], None],
) -> bytes:
    if (not 0 <= requested.length <= MAX_CENTRAL_DIRECTORY_BYTES
            or not 0 <= requested.offset <= archive_bytes - requested.length):
        _reject("input")
    parts: list[bytes] = []
    for consumed in range(0, requested.length, READ_CHUNK_BYTES):
        length = min(READ_CHUNK_BYTES, requested.length - consumed)
        parts.append(_read_at(reader, requested.offset + consumed, length, archive_bytes, check))
    check()
    data = b"".join(parts)
    check()
    return data


def _require_eof(reader: BinaryIO, archive_bytes: int, check: Callable[[], None]) -> None:
    # Only this one-byte EOF probe may ask past the owner's originally supplied
    # size. It does not measure/adopt a larger file or refresh that size.
    _seek(reader, archive_bytes, check)
    check()
    data = reader.read(1)
    check()
    if type(data) is not bytes or len(data) > 1:
        _reject("read")
    if data:
        _reject("changed")
    check()
    position = reader.tell()
    check()
    if type(position) is not int or position != archive_bytes:
        _reject("read")


def _require_same_range(
    reader: BinaryIO, requested: ZipReadRange, expected: bytes, archive_bytes: int,
    check: Callable[[], None],
) -> None:
    for consumed in range(0, len(expected), READ_CHUNK_BYTES):
        length = min(READ_CHUNK_BYTES, len(expected) - consumed)
        data = _read_at(reader, requested.offset + consumed, length, archive_bytes, check)
        check()
        equal = data == expected[consumed:consumed + length]
        check()
        if not equal:
            _reject("changed")


def _local_payload(
    reader: BinaryIO, entry: AndroidZipEntry, boundary: int, archive_bytes: int,
    check: Callable[[], None],
) -> ZipReadRange:
    start = entry.local_header_offset
    if start + LOCAL_HEADER_BYTES > boundary:
        _reject("layout")
    data = _read_range(reader, ZipReadRange(start, LOCAL_HEADER_BYTES), archive_bytes, check)
    check()
    header = struct.unpack("<4s5H3I2H", data)
    check()
    if header[0] != _LOCAL:
        _reject("layout")
    needed, flags, method = header[1:4]
    values = header[6:9]
    name_size, extra_size = header[9:11]
    if needed == 45 or 0xFFFFFFFF in values[1:]:
        _reject("zip64")
    if flags & (0x0001 | 0x0040 | 0x2000):
        _reject("encryption")
    if (needed, flags, method) != (entry.extract_version, entry.flag_bits, entry.compression):
        _reject("layout")
    if name_size > MAX_ENTRY_NAME_BYTES:
        _reject("limit")
    if name_size != len(entry.raw_name):
        _reject("layout")
    expected = (entry.crc32, entry.compressed_size, entry.file_size)
    if flags & 0x0008:
        # Support ordinary streaming zero placeholders or fully specified local
        # values, not mixed/inconsistent placeholders or unknown ZIP64 sizes.
        if values not in ((0, 0, 0), expected):
            _reject("layout")
    elif values != expected:
        _reject("layout")
    name_start = start + LOCAL_HEADER_BYTES
    extra_start = name_start + name_size
    payload_start = extra_start + extra_size
    payload_end = payload_start + entry.compressed_size
    if payload_end > boundary:
        _reject("layout")
    descriptor_size = boundary - payload_end
    if (flags & 0x0008 and descriptor_size not in (12, 16)) or (not flags & 0x0008 and descriptor_size != 0):
        _reject("layout")  # No gaps, unlisted locals, overlaps, prefixes or ZIP64 descriptors.
    raw_name = _read_range(reader, ZipReadRange(name_start, name_size), archive_bytes, check)
    if raw_name != entry.raw_name:
        _reject("name")  # No second decoding/normalization or local-only name view.
    extra = _read_range(reader, ZipReadRange(extra_start, extra_size), archive_bytes, check)
    check()
    try:
        # Reuse the FROZEN central policy for local TLV framing and critical
        # ZIP64/Unicode-path/encryption refusals; opaque local/CD extras may
        # legitimately differ. No second extra-field interpretation is added.
        _check_extra(extra, 0, len(extra))
    except AndroidZipError as error:
        if type(error) is AndroidZipError and error.reason == "directory":
            _reject("layout")
        raise
    check()
    if flags & 0x0008:
        descriptor = _read_range(reader, ZipReadRange(payload_end, descriptor_size), archive_bytes, check)
        check()
        if descriptor_size == 16:
            if descriptor[:4] != _DESCRIPTOR:
                _reject("layout")
            observed = struct.unpack("<3I", descriptor[4:])
        else:
            # An unsigned CRC equal to the optional signature is refused. Do
            # not let a signature-first consumer choose a different boundary.
            if descriptor[:4] == _DESCRIPTOR:
                _reject("layout")
            observed = struct.unpack("<3I", descriptor)
        check()
        if observed != expected:
            _reject("layout")
    return ZipReadRange(payload_start, entry.compressed_size)


def _output_allowance(entry: AndroidZipEntry, expanded: int, total: int) -> int:
    # max_length=0 means UNLIMITED to zlib, so it is never used. At most one
    # refusal-detection byte may exceed the smallest remaining declared/fixed
    # quota; no such byte is accepted, retained as content, or emitted.
    allowance = min(EXPANDED_CHUNK_BYTES, entry.file_size - expanded + 1,
                    MAX_ENTRY_SIZE - expanded + 1, MAX_TOTAL_SIZE - total + 1)
    if allowance <= 0:
        _reject("limit")
    return allowance


def _charge(
    data: bytes, entry: AndroidZipEntry, expanded: int, total: int, crc: int,
    check: Callable[[], None],
) -> tuple[int, int, int]:
    expanded += len(data)
    total += len(data)
    if expanded > MAX_ENTRY_SIZE or total > MAX_TOTAL_SIZE:
        _reject("limit")
    if expanded > entry.file_size:
        _reject("size")
    check()
    crc = binascii.crc32(data, crc)
    check()
    return expanded, total, crc


def _inspect_payload(
    reader: BinaryIO, entry: AndroidZipEntry, payload: ZipReadRange, archive_bytes: int,
    total: int, check: Callable[[], None],
) -> int:
    expanded = crc = consumed = 0
    if entry.compression == 0:
        while consumed < payload.length:
            length = min(READ_CHUNK_BYTES, payload.length - consumed, _output_allowance(entry, expanded, total))
            data = _read_at(reader, payload.offset + consumed, length, archive_bytes, check)
            consumed += length
            expanded, total, crc = _charge(data, entry, expanded, total, crc, check)
    else:
        check()
        try:
            stream = zlib.decompressobj(-zlib.MAX_WBITS)
        except zlib.error:
            _reject("compression")
        check()
        pending = b""
        while True:
            check()
            if not pending and consumed < payload.length:
                length = min(READ_CHUNK_BYTES, payload.length - consumed)
                pending = _read_at(reader, payload.offset + consumed, length, archive_bytes, check)
                consumed += length
            allowance = _output_allowance(entry, expanded, total)
            check()
            try:
                data = stream.decompress(pending, allowance)
            except zlib.error:
                _reject("compression")
            check()  # Deliberately outside the zlib.error conversion region.
            tail = stream.unconsumed_tail
            if (type(data) is not bytes or len(data) > allowance or type(tail) is not bytes
                    or len(tail) > len(pending) or (tail and not pending.endswith(tail))
                    or stream.unused_data):
                _reject("compression")
            expanded, total, crc = _charge(data, entry, expanded, total, crc, check)
            if stream.eof:
                if tail or consumed != payload.length:
                    _reject("compression")  # No trailing bytes or concatenated streams.
                break
            if not data and len(tail) == len(pending):
                _reject("compression")  # No progress, or truncated after final empty-input drain.
            pending = tail
            # Empty input is allowed after all compressed bytes were supplied:
            # drain only through the same positive max_length calls. Never use
            # flush(), whose length parameter is not a maximum output bound.
    check()
    if expanded != entry.file_size:
        _reject("size")
    if crc != entry.crc32:
        _reject("crc")
    return total


def inspect_zip_integrity(
    reader: BinaryIO, *, archive_bytes: int, checkpoint: Callable[[], None],
) -> AndroidZipIntegrity:
    """Admit metadata, reconcile full local extents, then verify bounded bytes/CRCs.

    Supply an already-borrowed blocking binary seekable reader that gives exact
    read(n) bytes or EOF, and its ORIGINAL captured size; no path/size refresh.
    The mandatory checkpoint returns None or raises the original stop/failure.
    Before/after checks surround bounded reads, native decompression/CRC work,
    and finite metadata parsing/sorting. Mechanical/owner exceptions are not
    translated to ordinary ZIP findings. No lock or cleanup resource is acquired.

    The frozen metadata module remains the single name/feature/size policy.
    DOS timestamps and bounded opaque extras/comments are not content identity
    claims. AAB required-name rules and native manifest inspection are separate.
    Later consumers must use result.metadata rather than reopen/reinterpret a
    pathname. No ZipFile is necessary for this layer or that directory view.
    """
    if not callable(checkpoint):
        _reject("input")

    def check() -> None:
        _check(checkpoint)

    check()
    tail_range = zip_tail_range(archive_bytes)
    check()
    _require_eof(reader, archive_bytes, check)
    tail = _read_range(reader, tail_range, archive_bytes, check)
    check()
    plan = plan_zip_directory(archive_bytes, tail)
    check()
    directory = _read_range(reader, plan.central_directory, archive_bytes, check)
    check()
    metadata = inspect_zip_directory(plan, directory)
    check()
    entries = sorted(metadata.entries, key=lambda entry: entry.local_header_offset)
    check()
    total = 0
    for index, entry in enumerate(entries):
        check()
        boundary = (entries[index + 1].local_header_offset
                    if index + 1 < len(entries) else plan.central_directory.offset)
        payload = _local_payload(reader, entry, boundary, archive_bytes, check)
        total = _inspect_payload(reader, entry, payload, archive_bytes, total, check)
        check()
    if total != metadata.declared_expanded_bytes:
        _reject("size")
    # Exact metadata-byte rechecks detect more than dataclass equality (which
    # intentionally excludes comments/times/opaque extras). They are NOT a full
    # body digest, atomic snapshot, or replacement for the owner's original
    # custody/identity/digest checks through later native consumption and close.
    _require_same_range(reader, plan.central_directory, directory, archive_bytes, check)
    _require_same_range(reader, tail_range, tail, archive_bytes, check)
    _require_eof(reader, archive_bytes, check)
    check()
    return AndroidZipIntegrity(metadata, total)
