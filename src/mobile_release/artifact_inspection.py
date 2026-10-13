"""Fixed artifact-inspection DATA bounds and canonical inventory encoding.

There are no acquisitions, commands, cleanup callbacks or original-owner
constructors here.  A caller must separately prove the bytes/entries came from
its same held originals.  Parsed records and successful quotations do not lend
filesystem, signature or lifecycle authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
import unicodedata


KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB
CONTROL_LIMIT = GIB
CONTROL_FIXED = 512 * MIB
PARSER_RESERVE = 32 * MIB
PROFILE_CONTROL = 64 * MIB
PROFILE_CREATIONS = 8
PROFILE_DESCRIPTORS = 64
PROFILE_DISK = 40 * MIB
# Existing4MiB completion body + fixed framing (<128B) + one64KiB read.
# This is deliberately a prequote, not a copied framing parser or actual size.
PROFILE_CAPTURE = 4 * MIB + 64 * KIB + 128
MAX_CALL_UNITS = 4096
MAX_CAPTURE_RAW = 32 * MIB
MAX_DECODE_CALLS = 128
MAX_DECODE_RAW = 4 * MIB
MAX_DECODE_INPUT = 256 * KIB
MAX_DECODE_NODES = 4096
MAX_DECODE_DEPTH = 32
MAX_NAMESPACE_ENTRIES = 8192
MAX_NAMESPACE_NAMES = 2 * MIB
MAX_SLICES = 8192
MAX_SELECTED_BYTES = 16 * GIB
MAX_DESCRIPTORS = 192
TREE_DOMAIN = b"mrk-artifact-tree-v1\0"


class ArtifactInspectionLimitError(ValueError):
    """A fixed DATA shape or conservative bound refused; not a close verdict."""


def _need(condition: bool) -> None:
    if not condition:
        raise ArtifactInspectionLimitError("artifact inspection data exceeds its fixed bounds")


def _integer(value: object, maximum: int, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= maximum


def aab_directory_data(entries: int, central_bytes: int, raw_bytes: int, expanded_bytes: int) -> None:
    """Check an existing bounded ZIP prelude before its larger allocations."""
    _need(_integer(entries, 32768) and _integer(central_bytes, 8 * MIB)
          and _integer(raw_bytes, GIB) and _integer(expanded_bytes, 2 * GIB))


def namespace_data(entries: int, path_bytes: int, normalized_bytes: int) -> None:
    _need(_integer(entries, MAX_NAMESPACE_ENTRIES, 1)
          and _integer(path_bytes, MAX_NAMESPACE_NAMES)
          and _integer(normalized_bytes, MAX_NAMESPACE_NAMES))


def control_quote_data(*, decode_calls: int, decode_raw: int, capture_raw: int,
                       max_capture_cap: int, profile_loads: int) -> int:
    """Prospective retained-capacity quote, never an OS RSS measurement."""
    _need(_integer(decode_calls, MAX_DECODE_CALLS)
          and _integer(decode_raw, MAX_DECODE_RAW)
          and _integer(capture_raw, MAX_CAPTURE_RAW)
          and _integer(max_capture_cap, 8 * MIB)
          and _integer(profile_loads, MAX_DECODE_CALLS))
    _need(decode_calls != 0 or decode_raw == 0)
    quote = (CONTROL_FIXED + PARSER_RESERVE
             + decode_calls * MAX_DECODE_NODES * 256 + decode_raw * 16
             + capture_raw * 5 + max_capture_cap * 4
             + profile_loads * PROFILE_CONTROL)
    _need(quote <= CONTROL_LIMIT)
    return quote


def decode_budget_data(calls: int, total_raw: int, next_raw: int) -> tuple[int, int]:
    """Count repeated decodes too; the owner must then check control_quote_data."""
    _need(_integer(calls, MAX_DECODE_CALLS) and _integer(total_raw, MAX_DECODE_RAW)
          and _integer(next_raw, MAX_DECODE_INPUT))
    after = calls + 1, total_raw + next_raw
    _need(after[0] <= MAX_DECODE_CALLS and after[1] <= MAX_DECODE_RAW)
    return after


def slice_budget_data(retained: int, next_count: int) -> int:
    _need(_integer(retained, MAX_SLICES) and _integer(next_count, 32))
    after = retained + next_count
    _need(after <= MAX_SLICES)
    return after


def descriptor_quote_data(parent_reserved: int, core_live: int, additional: int) -> int:
    _need(all(_integer(value, MAX_DESCRIPTORS) for value in
              (parent_reserved, core_live, additional)))
    total = parent_reserved + core_live + additional
    _need(total <= MAX_DESCRIPTORS)
    return total


def capture_quote_data(captured_raw: int, role: str) -> int:
    """One fixed pending capture's peak reservation; not bytes already read."""
    limits = {"aab": 2 * MIB, "ipa": 8 * MIB, "profile": PROFILE_CAPTURE}
    _need(type(role) is str and role in limits and _integer(captured_raw, MAX_CAPTURE_RAW))
    limit = limits[role]
    _need(captured_raw + limit <= MAX_CAPTURE_RAW)
    return limit


def captured_bytes_data(captured_raw: int, observed_raw: int, admitted: int) -> int:
    """A known actual read count; unknown callers must charge their full quote."""
    _need(_integer(captured_raw, MAX_CAPTURE_RAW) and _integer(admitted, 8 * MIB, 1)
          and _integer(observed_raw, admitted))
    after = captured_raw + observed_raw
    _need(after <= MAX_CAPTURE_RAW)
    return after


@dataclass(frozen=True, slots=True)
class ProfileQuoteData:
    profile_loads: int
    call_units: int
    control_bytes: int
    live_descriptors: int
    private_disk_bytes: int


def profile_quote_data(*, profile_loads: int, call_units: int, decode_calls: int,
                       decode_raw: int, capture_raw: int, max_capture_cap: int,
                       parent_reserved: int, core_live: int) -> ProfileQuoteData:
    """Prequote the existing two-CMS chain; not eight observed child returns."""
    _need(_integer(profile_loads, MAX_DECODE_CALLS) and _integer(call_units, MAX_CALL_UNITS))
    control_quote_data(decode_calls=decode_calls, decode_raw=decode_raw, capture_raw=capture_raw,
                       max_capture_cap=max_capture_cap, profile_loads=profile_loads)
    after_profiles, after_calls = profile_loads + 1, call_units + PROFILE_CREATIONS
    _need(after_calls <= MAX_CALL_UNITS)
    quote = control_quote_data(decode_calls=decode_calls, decode_raw=decode_raw,
                              capture_raw=capture_raw, max_capture_cap=max(max_capture_cap, PROFILE_CAPTURE),
                              profile_loads=after_profiles)
    live = descriptor_quote_data(parent_reserved, core_live, PROFILE_DESCRIPTORS)
    # Each actual CMS capture independently checks its then-current output peak.
    capture_quote_data(capture_raw, "profile")
    return ProfileQuoteData(after_profiles, after_calls, quote, live, PROFILE_DISK)


@dataclass(frozen=True, slots=True)
class TreeEntryData:
    kind: str
    path: str
    size: int
    sha256: str | None


def tree_identity_data(rows: tuple[TreeEntryData, ...]) -> tuple[str, int, int]:
    """Return (digest, entries-including-root, bytes) for bounded canonical DATA.

    Uses the existing path grammar.  The encoder neither walks a path nor proves
    its supplied hashes: the original reader owns source/namespace/content POST.
    """
    from .ios_artifacts import _parts

    _need(type(rows) is tuple and 1 <= len(rows) <= MAX_NAMESPACE_ENTRIES)
    root = rows[0]
    _need(type(root) is TreeEntryData and type(root.kind) is str and root.kind == "directory"
          and type(root.path) is str and root.path == "" and type(root.size) is int
          and root.size == 0 and root.sha256 is None)
    digest = hashlib.sha256()
    digest.update(TREE_DOMAIN)
    digest.update(struct.pack(">Q", len(rows)))
    previous = None
    kinds: dict[str, str] = {}
    normalized: set[str] = set()
    path_bytes = key_bytes = total = 0
    for index, row in enumerate(rows):
        _need(type(row) is TreeEntryData and type(row.kind) is str
              and row.kind in {"file", "directory"} and type(row.path) is str
              and len(row.path) <= 2048 and _integer(row.size, MAX_SELECTED_BYTES))
        if index:
            # The actual shared grammar throws its ordinary validation error;
            # do not repair unsupported spellings before hashing.
            _parts(row.path)
        else:
            _need(row.path == "")
        spelling = row.path.encode("utf-8", "strict")
        _need(previous is None or previous < spelling)
        previous = spelling
        key = unicodedata.normalize("NFC", row.path).casefold()
        _need(key not in normalized)
        path_bytes += len(spelling)
        key_bytes += len(key.encode("utf-8", "strict"))
        namespace_data(index + 1, path_bytes, key_bytes)
        if index:
            parent = row.path.rpartition("/")[0]
            _need(kinds.get(parent) == "directory")
        if row.kind == "directory":
            _need(row.size == 0 and row.sha256 is None)
            tag = b"D"
        else:
            _need(row.size <= 4 * GIB and type(row.sha256) is str and len(row.sha256) == 64
                  and all(char in "0123456789abcdef" for char in row.sha256))
            tag = b"F"
            total += row.size
            _need(total <= MAX_SELECTED_BYTES)
        digest.update(tag)
        digest.update(struct.pack(">I", len(spelling)))
        digest.update(spelling)
        if row.kind == "file":
            digest.update(struct.pack(">Q", row.size))
            digest.update(bytes.fromhex(row.sha256))
        kinds[row.path] = row.kind
        normalized.add(key)
    return digest.hexdigest(), len(rows), total
