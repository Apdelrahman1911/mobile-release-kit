"""Original Windows required-note primitives for the existing transaction.

No native load, path acquisition or platform selection occurs at import. The
installed bootstrap owns stdio/DLL admission; this module receives that exact
Notes-purpose binding and never creates a second library or transaction engine.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
import struct
import threading
from typing import Any

from ._required_notes_windows_contract import PLATFORM, canonical_u64, material, registered_root

_VERSION = 1
_LAYOUT_TAG = 0x4E573131
_INPUT_MAX = _OUTPUT_MAX = 65_536
_OK, _EOF, _REFUSED, _FAILED, _UNKNOWN, _EXPECTED_COLLISION = range(6)
_INFO_FIELDS = (
    320, 1, 64, 80, 8, 8, 65536, 65536, 42, 0x4E573131,
    3, 38, 38, 20, 38, 4096, 2048, 2048, 128, 524288, 32768,
    65536, 32768, 32768, 15360, 7680, 7680, 33554432, 1114112,
    524288, 131072, 1073741824, 536870912, 536870912, 536870912,
    524288, 65536, 48, 42, 154, 23, 5, 11, 44, 12, 512, 255,
    0, 0, 132096, 65536, 65536, 1024, 0,  # 47/48 reserved, never descriptor/ACE caps.
)
_REQUEST_OFFSETS = (0, 4, 8, 12, 16, 24, 32, 40, 48, 52, 56, 60)
_REPLY_OFFSETS = (0, 4, 8, 12, 16, 24, 32, 40, 48, 52, 56, 60, 64, 68)
_MATERIAL_OPERATIONS = frozenset({9, 15, 16, 27, 30})
_ZERO_DIGEST = b"\0" * 32


class NotesRefused(RuntimeError):
    """A closed refusal, not a successful native effect or settlement."""


class NotesFailure(RuntimeError):
    """A known failure; original recovery and original finality stay separate."""


class NotesUnknown(RuntimeError):
    """Absorbing custody/effect uncertainty; never replacement or retry authority."""


def _require(condition: bool) -> None:
    if not condition:
        raise NotesUnknown("The original required-note native DATA did not match.") from None


def _types(c: Any) -> tuple[type, type, type]:
    class Request(c.Structure):
        _fields_ = [
            ("size", c.c_uint32), ("version", c.c_uint32),
            ("operation", c.c_uint32), ("reserved", c.c_uint32),
            ("owner", c.c_uint64), ("a", c.c_uint64), ("b", c.c_uint64), ("c", c.c_uint64),
            ("number", c.c_uint32), ("count", c.c_uint32),
            ("input_len", c.c_uint32), ("output_capacity", c.c_uint32),
        ]

    class Reply(c.Structure):
        _fields_ = [
            ("size", c.c_uint32), ("version", c.c_uint32),
            ("status", c.c_uint32), ("error", c.c_uint32),
            ("owner", c.c_uint64), ("token", c.c_uint64),
            ("sequence", c.c_uint64), ("epoch", c.c_uint64),
            ("output_len", c.c_uint32), ("count", c.c_uint32),
            ("total", c.c_uint32), ("flags", c.c_uint32),
            ("first_failure", c.c_uint32), ("reserved", c.c_uint32 * 3),
        ]

    class Info(c.Structure):
        _fields_ = [("fields", c.c_uint32 * 54), ("request_offsets", c.c_uint32 * 12),
                    ("reply_offsets", c.c_uint32 * 14)]

    _require((c.sizeof(Request), c.sizeof(Reply), c.sizeof(Info),
              c.alignment(Request), c.alignment(Reply), c.alignment(Info)) == (64, 80, 320, 8, 8, 4))
    _require(tuple(getattr(Request, name).offset for name, _ in Request._fields_) == _REQUEST_OFFSETS)
    _require(tuple(getattr(Reply, name).offset for name, _ in Reply._fields_) == _REPLY_OFFSETS)
    return Request, Reply, Info


def _component(raw: bytes, *, root: bool = False) -> str:
    _require(type(raw) is bytes and (root and not raw or 0 < len(raw) <= 255))
    try:
        value = raw.decode("utf-8", "strict")
        units = len(value.encode("utf-16-le", "strict")) // 2
    except UnicodeError:
        raise NotesUnknown("The original required-note native name was not UTF-8.") from None
    _require(units <= 255 and not value.endswith((" ", "."))
             and value not in {".", ".."}
             and not any(ord(c) < 32 or ord(c) == 127 or c in '/\\:<>"|?*' for c in value))
    return value


@dataclass(frozen=True, slots=True, repr=False)
class _ObservationData:
    # Detached decoded DATA is not a material receipt. The original bridge
    # separately retains the exact object/pass/return association.
    tag: int
    owner: int
    scope: int
    flags: int
    object_key: int
    observation_key: int
    logical_key: int
    namespace_epoch: int
    security_epoch: int
    security_facts_ref: int
    security_transition_key: int
    accepted_effect_sequence: int
    completed_pass_key: int
    volume_serial: int
    file_id: bytes
    kind: int
    attributes: int
    size: int
    allocation_size: int
    links: int
    creation: int
    write: int
    change: int
    canonical_security_sha256: bytes
    raw_descriptor_sha256: bytes
    content_sha256: bytes
    roster_sha256: bytes
    original_capture: int
    parent_object_key: int
    parent_observation_key: int
    parent_namespace_epoch: int
    causing_effect_key: int
    name: str

    def source_facts(self) -> tuple[tuple[str, int | str], ...]:
        # Fresh scope/object/pass/observation keys and raw descriptor layout do
        # not replace canonical complete security equality. Native op15 still
        # compares the retained complete facts, not only these DATA scalars.
        return tuple(sorted({
            "logicalObjectKey": str(self.logical_key),
            "volumeSerial": format(self.volume_serial, "016x"), "fileId": self.file_id.hex(),
            "kind": self.kind, "attributes": self.attributes, "size": str(self.size),
            "allocationSize": str(self.allocation_size), "links": self.links,
            "creation": str(self.creation), "write": str(self.write), "change": str(self.change),
            "canonicalSecuritySha256": self.canonical_security_sha256.hex(),
            "contentSha256": self.content_sha256.hex(), "rosterSha256": self.roster_sha256.hex(),
            "securityTransitionKey": str(self.security_transition_key),
        }.items()))


def _decode_observation(raw: bytes, *, owner: int, scope: int) -> _ObservationData:
    _require(type(raw) is bytes and 320 <= len(raw) <= 615 and raw[:8] == b"MRKNOB1\0")
    prefix, tag = struct.unpack_from("<II", raw, 8)
    returned_owner, returned_scope, flags = struct.unpack_from("<QII", raw, 16)
    keys = struct.unpack_from("<10Q", raw, 32)
    (object_key, observation_key, logical_key, namespace_epoch, security_epoch,
     security_facts_ref, security_transition_key, accepted_effect_sequence,
     completed_pass_key, volume_serial) = keys
    file_id = raw[112:128]
    kind, attributes, size, allocation_size, links, reserved = struct.unpack_from("<IIQQII", raw, 128)
    creation, write, change = struct.unpack_from("<qqq", raw, 160)
    canonical_security, raw_descriptor = raw[184:216], raw[216:248]
    content, roster = raw[248:280], raw[280:312]
    original_capture, = struct.unpack_from("<Q", raw, 312)
    _require(prefix == 320 and tag in (1, 2, 3) and returned_owner == owner and owner != 0
             and returned_scope == scope and scope in (0, 1, 2, 3) and flags & ~255 == 0
             and object_key != 0 and observation_key != 0 and logical_key != 0
             and reserved == 0 and kind in (1, 2))
    parent_key = parent_observation = parent_epoch = effect_key = 0
    name = ""
    if tag == 2:
        _require(scope != 0 and len(raw) >= 360)
        parent_key, parent_observation, parent_epoch, effect_key, length, reserved = struct.unpack_from("<4QII", raw, 320)
        _require(reserved == 0 and len(raw) == 360 + length)
        name = _component(raw[360:], root=parent_key == 0)
        _require((parent_key == 0) == (not name)
                 and (parent_key == 0 or parent_observation != 0 and parent_epoch != 0))
    else:
        _require(len(raw) == 320)
    if tag == 3:
        _require(scope == 0 and not flags and not completed_pass_key and not original_capture
                 and not any((canonical_security != _ZERO_DIGEST, raw_descriptor != _ZERO_DIGEST,
                              content != _ZERO_DIGEST, roster != _ZERO_DIGEST)))
    else:
        _require(scope != 0 and completed_pass_key != 0 and security_facts_ref != 0
                 and security_transition_key != 0
                 and flags & 3 == (2 if kind == 1 else 1)
                 and flags & (16 | 32 | 64) in (16, 32, 64)
                 and (content == _ZERO_DIGEST if kind == 1 else roster == _ZERO_DIGEST))
        if tag == 1:
            _require(not flags & 8)
        else:
            _require(not flags & 4)
    return _ObservationData(
        tag, owner, scope, flags, object_key, observation_key, logical_key,
        namespace_epoch, security_epoch, security_facts_ref, security_transition_key,
        accepted_effect_sequence, completed_pass_key, volume_serial, file_id,
        kind, attributes, size, allocation_size, links, creation, write, change,
        canonical_security, raw_descriptor, content, roster, original_capture,
        parent_key, parent_observation, parent_epoch, effect_key, name,
    )


@dataclass(frozen=True, slots=True, repr=False)
class _PresenceData:
    owner: int
    scope: int
    tag: int
    proof: int
    fact_key: int
    object_key: int
    parent_object_key: int
    parent_observation_key: int
    namespace_epoch: int
    completed_roster_key: int
    edge_key: int
    roster_sha256: bytes
    file_id: bytes
    kind: int
    attributes: int
    original_parent_absent_key: int
    name: str


def _decode_presence(raw: bytes, *, owner: int, scope: int) -> _PresenceData:
    _require(type(raw) is bytes and 160 < len(raw) <= 415 and raw[:8] == b"MRKNPF1\0")
    prefix, tag, returned_owner, returned_scope, proof = struct.unpack_from("<IIQII", raw, 8)
    fact, object_key, parent, parent_observation, epoch, roster_pass, edge = struct.unpack_from("<7Q", raw, 32)
    roster_sha, file_id = raw[88:120], raw[120:136]
    kind, attributes, length, reserved, parent_absent = struct.unpack_from("<4IQ", raw, 136)
    _require(prefix == 160 and tag in (1, 2) and returned_owner == owner and owner != 0
             and returned_scope == scope and scope in (1, 2, 3) and proof in (1, 2)
             and fact != 0 and object_key != 0 and parent != 0 and edge != 0
             and reserved == 0 and len(raw) == 160 + length)
    name = _component(raw[160:])
    if proof == 1:
        _require(parent_observation != 0 and roster_pass != 0 and parent_absent == 0)
    else:
        _require(tag == 2 and parent_observation == 0 and roster_pass == 0 and parent_absent != 0)
    if tag == 1:
        _require(kind in (1, 2))
    else:
        _require(file_id == b"\0" * 16 and kind == attributes == 0)
    return _PresenceData(owner, scope, tag, proof, fact, object_key, parent, parent_observation,
                         epoch, roster_pass, edge, roster_sha, file_id, kind, attributes, parent_absent, name)


def _decode_observation_batch(raw: bytes, *, owner: int, scope: int,
                              operation: int, expected_count: int) -> tuple[_ObservationData, ...]:
    _require(operation in _MATERIAL_OPERATIONS and type(raw) is bytes and 8 <= len(raw) <= _OUTPUT_MAX)
    count, total = struct.unpack_from("<II", raw, 0)
    _require(count == expected_count and total == len(raw) and count in (1, 2, 3)
             and (operation in (27, 30) or count == 1))
    offset, values = 8, []
    for _ in range(count):
        _require(offset + 4 <= len(raw))
        length, = struct.unpack_from("<I", raw, offset)
        offset += 4
        _require(320 <= length <= 615 and offset + length <= len(raw))
        observed = _decode_observation(raw[offset:offset + length], owner=owner, scope=scope)
        _require(observed.tag != 3)
        if operation == 9:
            _require(observed.tag == 1 and not observed.flags & 4)
            if observed.original_capture == 0:
                # Created readback is Source DATA, not a fabricated Capture
                # baseline/material. Only current-epoch16 may promote it.
                _require(scope == 3 and not observed.flags & 128)
            else:
                _require(scope == 1 and observed.original_capture == observed.observation_key
                         and observed.flags & 128 != 0)
        elif operation == 15:
            _require(observed.tag == 1 and observed.original_capture != 0
                     and observed.flags & (4 | 128) == 4 | 128)
        elif operation == 16:
            _require(observed.tag == 2 and observed.flags & (8 | 128) == 8 | 128)
        else:
            _require(observed.tag == 2 and observed.flags & 128 != 0)
        values.append(observed)
        offset += length
    _require(offset == len(raw) and len({value.object_key for value in values}) == count)
    return tuple(values)



@dataclass(frozen=True, slots=True, repr=False)
class _FactoryData:
    operation: int
    owner: int
    scope: int
    row_count: int
    factory_key: int
    lease_key: int
    root_key: int
    logical_data_key: int
    mappings_data_key: int
    moves_data_key: int
    deletes_data_key: int
    security_data_key: int
    schedule_data_key: int
    files: int
    parents: int
    missing: int
    backups: int
    known_counts: int


def _decode_factory(raw: bytes, *, operation: int, owner: int | None,
                    scope: int) -> _FactoryData:
    _require(type(raw) is bytes and len(raw) == 128 and raw[:8] == b"MRKNFG1\0")
    prefix, returned_operation, returned_owner, returned_scope, row_count = struct.unpack_from("<IIQII", raw, 8)
    keys = struct.unpack_from("<9Q", raw, 32)
    files, parents, missing, backups, known, reserved = struct.unpack_from("<6I", raw, 104)
    _require(prefix == 128 and returned_operation == operation and operation in (1, 4, 5, 6, 7, 18)
             and returned_owner != 0 and (owner is None or returned_owner == owner)
             and returned_scope == scope and scope in (0, 1, 2, 3)
             and 1 <= row_count <= 38 and keys[0] != 0 and keys[1] != 0 and keys[3] != 0 and keys[8] != 0
             and reserved == 0 and known in (0, 3, 15)
             and (scope != 0 or operation == 1))
    _require((keys[2] == 0) == (scope == 0) and (keys[4] == 0) == (scope == 0))
    _require(files <= 5 and parents <= 23 and missing <= 11 and backups <= 1)
    for index, value in enumerate((files, parents, missing, backups)):
        _require(known & (1 << index) != 0 or value == 0)
    if operation in (1, 5, 6):
        _require(known == 0)
    elif operation == 4:
        _require(scope in (1, 2, 3) and known == (0 if scope == 1 else 3))
    elif operation == 7:
        _require(scope == 1 and known == 3)
    elif operation == 18:
        _require(scope == 3 and known == 15)
    _require(operation not in (5, 6, 7) or scope == 1)
    return _FactoryData(operation, returned_owner, scope, row_count, *keys,
                        files, parents, missing, backups, known)


def _relative(raw: bytes, *, root: bool = False) -> str:
    _require(type(raw) is bytes and (root and not raw or 0 < len(raw) <= 512))
    if root and not raw:
        return ""
    parts = raw.split(b"/")
    _require(1 <= len(parts) <= 12)
    return "/".join(_component(part) for part in parts)



def _input_path(value: str) -> bytes:
    # A core/user configuration refusal is not a malformed returning ABI cell.
    if type(value) is not str:
        raise NotesRefused("The required-note path is not text.")
    try:
        raw = value.encode("utf-8", "strict")
        _require(_relative(raw) == value)
    except (UnicodeError, NotesUnknown):
        raise NotesRefused("The required-note path is outside its supported form.") from None
    return raw

@dataclass(frozen=True, slots=True, repr=False)
class _LogicalData:
    role: int
    logical_key: int
    parent_logical_key: int
    content_limit: int
    flags: int
    selected_ancestor_index: int | None
    material_security_key: int
    path: str
    name: str


def _decode_logical(raw: bytes) -> _LogicalData:
    _require(type(raw) is bytes and 56 <= len(raw) <= 823)
    extent, role, logical, parent, limit, flags, index, path_length, name_length, security = struct.unpack_from(
        "<II3Q4IQ", raw, 0)
    _require(extent == len(raw) and role in range(1, 17) and logical != 0 and security != 0
             and flags & ~127 == 0 and index in (*range(11), 0xFFFFFFFF)
             and len(raw) == 56 + path_length + name_length)
    is_root = role == 1
    path = _relative(raw[56:56 + path_length], root=is_root)
    name = _component(raw[56 + path_length:], root=is_root)
    _require((parent == 0) == is_root and (not path) == is_root and (not name) == is_root
             and (is_root or name == path.rsplit("/", 1)[-1]))
    directory = role in (1, 2, 3, 9, 14, 15)
    _require(bool(flags & 1) == directory and (limit == 0 if directory else 0 < limit <= 1_048_576))
    _require(index == 0xFFFFFFFF or role == 3)
    return _LogicalData(role, logical, parent, limit, flags,
                        None if index == 0xFFFFFFFF else index, security, path, name)


@dataclass(frozen=True, slots=True, repr=False)
class _MappingData:
    logical_key: int
    source_object_key: int
    create_object_key: int
    capture_object_key: int
    scope: int
    source_state: int
    create_state: int


def _decode_mapping(raw: bytes, *, scope: int) -> _MappingData:
    _require(type(raw) is bytes and len(raw) == 48)
    logical, source, created, capture, returned_scope, source_state, create_state, reserved = struct.unpack(
        "<4Q4I", raw)
    _require(logical != 0 and returned_scope == scope and scope in (1, 2, 3)
             and source_state in range(6) and create_state in range(6) and reserved == 0
             and (source == 0) == (source_state == 0) and (created == 0) == (create_state == 0)
             and (source == 0 or source != created))
    return _MappingData(logical, source, created, capture, scope, source_state, create_state)


@dataclass(frozen=True, slots=True, repr=False)
class _DataPage:
    kind: int
    owner: int
    scope: int
    data_key: int
    offset: int
    total: int
    content: bytes


def _decode_data_page(raw: bytes, *, owner: int, scope: int, kind: int,
                      key: int, offset: int, requested: int) -> _DataPage:
    _require(type(raw) is bytes and 64 <= len(raw) <= _OUTPUT_MAX and raw[:8] == b"MRKNDP1\0"
             and type(requested) is int and 1 <= requested <= 65_472)
    prefix, returned_kind, returned_owner, returned_scope, reserved = struct.unpack_from("<IIQII", raw, 8)
    returned_key, returned_offset, total, length, reserved2 = struct.unpack_from("<3QII", raw, 32)
    _require(prefix == 64 and returned_kind == kind and kind in range(1, 9)
             and returned_owner == owner and owner != 0 and returned_scope == scope and scope in (0, 1, 2, 3)
             and returned_key == key and key != 0 and returned_offset == offset
             and 0 <= offset <= total <= 33_554_432 and not reserved and not reserved2
             and length == min(total - offset, requested) and len(raw) == 64 + length)
    return _DataPage(kind, owner, scope, key, offset, total, raw[64:])


@dataclass(frozen=True, slots=True, repr=False)
class _MoveData:
    move_key: int
    logical_key: int
    object_key: int
    from_parent_logical_key: int
    to_parent_logical_key: int
    inverse_move_key: int
    forward_move_key: int
    restore_action_key: int
    publish_action_key: int
    kind: int
    flags: int
    from_name: str
    to_name: str


def _decode_move(raw: bytes) -> _MoveData:
    _require(type(raw) is bytes and 90 <= len(raw) <= 598)
    keys = struct.unpack_from("<9Q", raw, 0)
    from_length, to_length, kind, flags = struct.unpack_from("<4I", raw, 72)
    _require(all(keys[index] != 0 for index in range(5)) and kind in range(1, 17)
             and flags & ~31 == 0 and len(raw) == 88 + from_length + to_length)
    source = _component(raw[88:88 + from_length])
    destination = _component(raw[88 + from_length:])
    _require(keys[3] != keys[4] or source != destination)
    _require(not (flags & 2 and flags & 4))
    if kind in (15, 16):
        _require(keys[5] == keys[6] == keys[7] == keys[8] == 0
                 and flags & (2 | 4) == (2 if kind == 15 else 4))
    if flags & 1:
        _require(kind == 3)
    return _MoveData(*keys, kind, flags, source, destination)


@dataclass(frozen=True, slots=True, repr=False)
class _DeleteData:
    delete_key: int
    logical_key: int
    object_key: int
    kind: int
    edges: tuple[tuple[int, str], ...]


def _decode_delete(raw: bytes) -> _DeleteData:
    _require(type(raw) is bytes and 49 <= len(raw) <= 845)
    delete, logical, original, kind, count = struct.unpack_from("<3QII", raw, 0)
    _require(delete != 0 and logical != 0 and original != 0 and kind in range(1, 7) and 1 <= count <= 3)
    offset, edges = 32, []
    for _ in range(count):
        _require(offset + 16 < len(raw))
        parent, length, reserved = struct.unpack_from("<QII", raw, offset)
        offset += 16
        _require(parent != 0 and reserved == 0 and offset + length <= len(raw))
        name = _component(raw[offset:offset + length])
        edges.append((parent, name))
        offset += length
    _require(offset == len(raw) and len(set(edges)) == len(edges))
    return _DeleteData(delete, logical, original, kind, tuple(edges))


@dataclass(frozen=True, slots=True, repr=False)
class _SecurityData:
    action_key: int
    logical_key: int
    object_key: int
    paired_action_key: int
    related_move_key: int
    policy_source_reference: int
    material_security_key: int
    purpose: int
    order: int


def _decode_security(raw: bytes) -> _SecurityData:
    _require(type(raw) is bytes and len(raw) == 64)
    keys = struct.unpack_from("<7Q", raw, 0)
    purpose, order = struct.unpack_from("<II", raw, 56)
    _require(all(key != 0 for key in keys) and purpose in (1, 2)
             and order == purpose and keys[0] != keys[3])
    return _SecurityData(*keys, purpose, order)


@dataclass(frozen=True, slots=True, repr=False)
class _ScheduleData:
    stage: int
    pool: int
    passes: int
    frames: int
    user_checks: int
    acquisitions: int
    records: int
    bridge_calls: int
    read_bytes: int
    roster_entries: int
    retained_heap: int


# Exact unchanged Info fields: global limit followed by producer/recovery/finality
# pool limits where the ABI defines them. A per-roster or per-original limit is
# deliberately not substituted for an aggregate allocation pool.
_SCHEDULE_LIMITS = (
    ("passes", 15, 16, 17, None),
    ("frames", 21, 22, 23, None),
    ("user_checks", 24, 25, 26, None),
    ("acquisitions", 39, None, None, None),
    ("records", 20, None, None, None),
    ("bridge_calls", 49, 50, 51, 52),
    ("read_bytes", 31, 32, 33, None),
    ("roster_entries", 35, None, None, None),
    ("retained_heap", 27, None, None, None),
)


def _decode_schedule(raw: bytes) -> _ScheduleData:
    _require(type(raw) is bytes and len(raw) == 64)
    values = struct.unpack("<8I4Q", raw)
    stage, pool, passes, frames, checks, acquisitions, records, calls, reads, entries, heap, reserved = values
    _require(stage in range(1, 17) and reserved == 0
             and pool == (1 if stage <= 12 else 2 if stage <= 15 else 3))
    value = _ScheduleData(*values[:-1])
    _require(all(getattr(value, name) <= _INFO_FIELDS[total]
                 for name, total, *_ in _SCHEDULE_LIMITS))
    if stage == 16:
        _require(not any((passes, frames, checks, acquisitions, records, reads, entries)))
    return value


def _admit_schedule(values: tuple[_ScheduleData, ...],
                    previous: tuple[_ScheduleData, ...] | None = None) -> tuple[_ScheduleData, ...]:
    _require(len(values) == 16 and all(type(value) is _ScheduleData for value in values)
             and {value.stage for value in values} == set(range(1, 17)))
    # Native wire order is not authority. Stage identity, pool and checked sums
    # are; Python integers cannot wrap a malicious aggregate back into a limit.
    ordered = tuple(sorted(values, key=lambda value: value.stage))
    for name, total, *pools in _SCHEDULE_LIMITS:
        _require(sum(getattr(value, name) for value in ordered) <= _INFO_FIELDS[total])
        for pool, index in enumerate(pools, 1):
            if index is not None:
                _require(sum(getattr(value, name) for value in ordered if value.pool == pool)
                         <= _INFO_FIELDS[index])
    if previous is not None:
        _require(all(getattr(value, name) >= getattr(old, name)
                     for old, value in zip(previous, ordered)
                     for name, *_ in _SCHEDULE_LIMITS))
    # These are cumulative ALLOCATED credits, including this factory's prepaid
    # pages. They are neither executed work nor a forecast/guarantee that future
    # work fits. Every actual native route still spends its own original ticket.
    return ordered


def _decode_table(raw: bytes, *, kind: int, scope: int) -> tuple[Any, ...]:
    limits = {1: 38, 2: 38, 3: 38, 4: 20, 5: 24, 6: 16}
    _require(type(raw) is bytes and kind in limits and 8 <= len(raw) <= 65_536)
    count, extent = struct.unpack_from("<II", raw, 0)
    _require(count <= limits[kind] and extent == len(raw))
    offset, values = 8, []
    for _ in range(count):
        _require(offset + 4 <= len(raw))
        length, = struct.unpack_from("<I", raw, offset)
        offset += 4
        _require(length != 0 and offset + length <= len(raw))
        record = raw[offset:offset + length]
        if kind == 1:
            value = _decode_logical(record)
        elif kind == 2:
            value = _decode_mapping(record, scope=scope)
        elif kind == 3:
            value = _decode_move(record)
        elif kind == 4:
            value = _decode_delete(record)
        elif kind == 5:
            value = _decode_security(record)
        else:
            value = _decode_schedule(record)
        values.append(value)
        offset += length
    _require(offset == len(raw))
    return _admit_schedule(tuple(values)) if kind == 6 else tuple(values)



def _single_record(raw: bytes, *, minimum: int, maximum: int) -> bytes:
    _require(type(raw) is bytes and 12 + minimum <= len(raw) <= 12 + maximum)
    count, extent, length = struct.unpack_from("<3I", raw, 0)
    _require(count == 1 and extent == len(raw) and length == len(raw) - 12)
    return raw[12:]


def _decode_lease(raw: bytes, *, owner: int) -> _ObservationData:
    value = _decode_observation(_single_record(raw, minimum=320, maximum=320), owner=owner, scope=0)
    _require(value.tag == 3 and value.kind == 1)
    return value


def _decode_presence_batch(raw: bytes, *, owner: int, scope: int) -> _PresenceData:
    return _decode_presence(_single_record(raw, minimum=161, maximum=415), owner=owner, scope=scope)


@dataclass(frozen=True, slots=True, repr=False)
class _RosterEntry:
    file_id: bytes
    kind: int
    attributes: int
    name: str


def _decode_roster(raw: bytes, *, expected_count: int) -> tuple[_RosterEntry, ...]:
    _require(type(raw) is bytes and 8 <= len(raw) <= _OUTPUT_MAX)
    count, extent = struct.unpack_from("<II", raw, 0)
    _require(count == expected_count and 0 <= count <= 128 and extent == len(raw))
    values, offset = [], 8
    for _ in range(count):
        _require(offset + 4 <= len(raw))
        length, = struct.unpack_from("<I", raw, offset)
        offset += 4
        _require(33 <= length <= 287 and offset + length <= len(raw))
        original_id = raw[offset:offset + 16]
        kind, attributes, name_length, reserved = struct.unpack_from("<4I", raw, offset + 16)
        _require(kind in (1, 2) and name_length == length - 32 and reserved == 0)
        # Roster kind1 FILE / kind2 DIRECTORY, unlike Observation's closed
        # Dir1/File2 enum. Do not silently interchange these ABI meanings.
        name = _component(raw[offset + 32:offset + length])
        values.append(_RosterEntry(original_id, kind, attributes, name))
        offset += length
    _require(offset == len(raw) and len({value.name for value in values}) == count)
    return tuple(values)


@dataclass(frozen=True, slots=True, repr=False)
class _EffectData:
    kind: int
    owner: int
    object_key: int
    sequence: int
    namespace_epoch: int
    operation_key: int
    return_kind: int
    return_bits: int
    last_error: int
    flags: int
    information: int


def _decode_effect(raw: bytes, *, owner: int, operation: int) -> _EffectData:
    kinds = {22: 1, 23: 2, 25: 3, 26: 4, 28: 5, 29: 6, 31: 7}
    _require(type(raw) is bytes and len(raw) == 80 and raw[:8] == b"MRKNEF1\0" and operation in kinds)
    prefix, kind, returned_owner, original, sequence, epoch, operation_key = struct.unpack_from("<II5Q", raw, 8)
    returned, bits, last_error, flags, information = struct.unpack_from("<4IQ", raw, 56)
    _require(prefix == 80 and kind == kinds[operation] and returned_owner == owner and owner != 0
             and original != 0 and sequence != 0 and operation_key != 0
             and returned in (0, 1, 2, 3) and flags & ~15 == 0 and flags & 1 != 0)
    _require(bool(flags & 2) == (returned != 0))
    if returned == 0:
        _require(bits == last_error == information == 0 and flags & (4 | 8) == 0)
    if returned != 2 or bits != 0:
        _require(last_error == 0)
    # BOOL retains its actual i32 bitpattern; every nonzero value is true.
    _require(operation in (22, 23) or information == 0)
    _require(not flags & 8 or operation == 26)
    return _EffectData(kind, owner, original, sequence, epoch, operation_key,
                       returned, bits, last_error, flags, information)


@dataclass(frozen=True, slots=True, repr=False)
class _ScopeStatus:
    owner: int
    scope: int
    root_key: int
    settlement_key: int
    handles: int
    frames: int
    foreign_outputs: int
    flags: int

    @property
    def settled(self) -> bool:
        return bool(self.flags & 2)


def _decode_scope_status(raw: bytes, *, owner: int, scope: int) -> _ScopeStatus:
    _require(type(raw) is bytes and len(raw) == 64 and raw[:8] == b"MRKNSC1\0")
    prefix, returned_scope, returned_owner, root, settlement, reserved = struct.unpack_from("<II4Q", raw, 8)
    handles, frames, outputs, flags = struct.unpack_from("<4I", raw, 48)
    _require(prefix == 64 and returned_scope == scope and scope in (1, 2, 3)
             and returned_owner == owner and owner != 0 and reserved == 0 and flags & ~7 == 0
             and handles <= 42 and frames <= 65536 and outputs <= 32768)
    if flags & 2:
        _require(flags & 1 != 0 and not flags & 4 and settlement != 0
                 and handles == frames == outputs == 0)
    else:
        _require(settlement == 0)
    return _ScopeStatus(owner, scope, root, settlement, handles, frames, outputs, flags)


@dataclass(frozen=True, slots=True, repr=False)
class _DeletionData:
    owner: int
    scope: int
    delete_key: int
    object_key: int
    sequence: int
    namespace_epoch: int
    absent_fact_key: int
    parent_observation_key: int


def _decode_deletion(raw: bytes, *, owner: int, scope: int) -> _DeletionData:
    _require(type(raw) is bytes and len(raw) == 72 and raw[:8] == b"MRKNDL1\0")
    prefix, returned_scope, returned_owner = struct.unpack_from("<IIQ", raw, 8)
    keys = struct.unpack_from("<6Q", raw, 24)
    _require(prefix == 72 and returned_scope == scope == 3 and returned_owner == owner and owner != 0
             and all(key != 0 for key in keys))
    return _DeletionData(owner, scope, *keys)


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class _Key:
    """A local borrow of one original native token, never an OS handle."""
    owner: _Bridge
    value: int
    kind: str
    scope: int
    logical: int
    object_key: int = 0




@dataclass(frozen=True, slots=True, repr=False)
class _FactoryResult:
    report: _FactoryData
    logical: tuple[_LogicalData, ...]
    mappings: tuple[_MappingData, ...]
    moves: tuple[_MoveData, ...] = ()
    deletes: tuple[_DeleteData, ...] = ()
    security: tuple[_SecurityData, ...] = ()
    schedule: tuple[_ScheduleData, ...] = ()


@dataclass(slots=True, repr=False)
class _Pass:
    key: _Key
    object: _Key
    directory: bool
    total: int = 0
    complete: bool = False



@dataclass(frozen=True, slots=True, repr=False)
class _NativeObservation:
    key: _Key
    object: _Key
    data: _ObservationData

    def material(self, *, limit: int | None = None) -> dict[str, Any]:
        _require(self.data.flags & 128 != 0 and self.data.tag in (1, 2)
                 and self.data.object_key == self.object.value
                 and self.key.value == self.data.observation_key)
        value: dict[str, Any] = {
            "platform": PLATFORM,
            "volumeSerial": format(self.data.volume_serial, "016x"),
            "fileId": self.data.file_id.hex(),
            "kind": "directory" if self.data.kind == 1 else "file",
            "attributes": self.data.attributes,
            "securityTransitionKey": str(self.data.security_transition_key),
        }
        if self.data.kind == 2:
            value.update(size=str(self.data.size), sha256=self.data.content_sha256.hex())
        return material(value, directory=self.data.kind == 1, limit=limit)


@dataclass(frozen=True, slots=True, repr=False)
class _NativePresence:
    key: _Key
    object: _Key
    data: _PresenceData

    @property
    def present(self) -> bool:
        return self.data.tag == 1


@dataclass(frozen=True, slots=True, repr=False)
class _PendingEffect:
    key: _Key
    effect: _EffectData


@dataclass(frozen=True, slots=True, repr=False)
class _ReplyData:
    status: int
    error: int
    owner: int
    token: int
    sequence: int
    epoch: int
    output_len: int
    count: int
    total: int
    flags: int
    first_failure: int


class _CallFrame:
    """Constructor-predeclared ABI storage; never replaced after a lost call."""
    __slots__ = ("request", "source", "reply", "destination", "returned")

    def __init__(self, c: Any, request_type: type, reply_type: type, *, finality: bool) -> None:
        self.request, self.reply = request_type(), reply_type()
        self.source = (c.c_ubyte * (0 if finality else _INPUT_MAX))()
        self.destination = (c.c_ubyte * _OUTPUT_MAX)()
        self.returned = False

    def arm(self, operation: int, owner: int, a: int, b: int, c_key: int,
            number: int, count: int, payload: bytes, capacity: int) -> None:
        r, output = self.request, self.reply
        r.size, r.version, r.operation, r.reserved = 64, _VERSION, operation, 0
        r.owner, r.a, r.b, r.c = owner, a, b, c_key
        r.number, r.count, r.input_len, r.output_capacity = number, count, len(payload), capacity
        if payload:
            self.source[:len(payload)] = payload
        (output.size, output.version, output.status, output.error, output.owner,
         output.token, output.sequence, output.epoch, output.output_len, output.count,
         output.total, output.flags, output.first_failure) = (0,) * 13
        output.reserved[:] = (0, 0, 0)
        self.returned = False


_ERRORS = frozenset((*range(17), 18, 19, *range(32, 37)))
_FINALITY_OPERATIONS = frozenset({17, 34, 35, 39, 40, 41, 42})
_RECOVERY_ENTRY_OPERATIONS = frozenset({36, 38})
_EFFECT_OPERATIONS = frozenset({22, 23, 25, 26, 28, 29, 31})

class _Bridge:
    def __init__(self, original_input: Any, guard: Any, c: Any, dll: Any) -> None:
        # No native entry in construction: the owning lease is published to the
        # existing engine before acquire() can enter Info/prepare/acquisition.
        self._input, self._guard = original_input, guard
        self._ctypes, self._dll = c, dll
        self._Request, self._Reply, self._Info = _types(c)
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self._owner_key = 0
        self._info_claimed = self._abi_checked = False
        self._prepare_claimed = self._prepared = False
        self._retire_claimed = self._retired = False
        self._unknown = self._failed = False
        self._info_pending = None
        self._pending = None
        self._observation_pending = None
        self._active = False
        self._last_reply = None
        self._last_payload = b""
        self._last_effect: _EffectData | None = None
        self._returned_status = None
        self._keys: dict[tuple[str, int, int], _Key] = {}
        self._source_keys: dict[int, _Key] = {}
        self._latest_source: dict[int, _Key] = {}
        self._latest_pass: dict[int, _Key] = {}
        self._passes: dict[int, _Pass] = {}
        self._latest_epoch: dict[int, _Key] = {}
        self._presence_keys: dict[int, _Key] = {}
        self._pending_epochs: dict[int, _Key] = {}
        self._data_keys: dict[tuple[int, str], _Key] = {}
        self._schedule_snapshot: tuple[_ScheduleData, ...] | None = None
        self._claims: set[tuple[int, int, int]] = set()
        self._joined_exit_objects: frozenset[int] = frozenset()
        self._move_facts: dict[int, _MoveData] = {}
        self._security_facts: dict[int, _SecurityData] = {}
        # Populated only by a fully decoded actual PRIMARY security return.
        # A Python attempted call, pending setter, or intended DACL is not an
        # effect receipt and cannot authorize its inverse setter.
        self._security_effects: dict[int, _EffectData] = {}
        self._lease_key = 0
        self._registered: tuple[int, bytes] | None = None
        self._producer_calls = self._recovery_calls = self._finality_calls = 0
        self._scope_number = 0
        self._collision_candidates: set[int] = set()
        self._sequence = self._first_failure = self._terminal_bits = 0
        self._first_failure_return = None
        self._known_unknown_error: NotesUnknown | None = None
        self._wire_lost = False
        self._recovery_entered = self._recovery_joined = False
        self._recovery_mode = "none"
        self._recovery_choice_claimed = False
        self._corrective_pair: tuple[_Key, _Key] | None = None
        self._corrective_objects: frozenset[int] = frozenset()
        self._corrective_restore_key = 0
        self._corrective_inverse_returned = self._corrective_inverse_finished = False
        self._finality_pending = None
        self._last_frame = None
        # Both original cells exist BEFORE any native admission/acquisition.
        # Finality has no input DATA and never borrows the ordinary call cell.
        self._ordinary_frame = _CallFrame(c, self._Request, self._Reply, finality=False)
        self._finality_frame = _CallFrame(c, self._Request, self._Reply, finality=True)
        self._call = dll.mrk_notes_v1_call
        self._info = dll.mrk_notes_v1_info
        self._call.argtypes = [c.POINTER(self._Request), c.POINTER(c.c_ubyte),
                              c.POINTER(self._Reply), c.POINTER(c.c_ubyte)]
        self._call.restype = c.c_uint32
        self._info.argtypes = [c.POINTER(self._Info), c.c_uint32]
        self._info.restype = c.c_uint32

    def _context(self) -> None:
        from ._desktop_edit_control import EditInput
        if (type(self._input) is not EditInput or self._input.guard is not self._guard
                or self._pid != os.getpid() or self._thread is not threading.current_thread()
                or self._thread is not threading.main_thread()):
            self._unknown = True
            raise NotesUnknown("The original Notes primitive changed context.")
        self._guard._check_owner()

    def _check_abi(self) -> None:
        self._context()
        if self._info_claimed or self._info_pending is not None:
            raise NotesRefused("The original Notes ABI admission is one-use.")
        self._info_claimed = True
        self._input.before_notes_entry()
        c = self._ctypes
        result = self._Info()
        self._info_pending = result
        try:
            status = self._info(c.byref(result), c.sizeof(result))
            # An original frame stays reachable until complete positive return.
            _require(status == _OK and tuple(result.fields) == _INFO_FIELDS
                     and tuple(result.request_offsets) == _REQUEST_OFFSETS
                     and tuple(result.reply_offsets) == _REPLY_OFFSETS)
        except BaseException:
            self._unknown = True
            raise NotesUnknown("The original Notes ABI admission did not settle.") from None
        self._abi_checked = True
        self._info_pending = None

    def _key(self, key: _Key, kind: str | tuple[str, ...], *, scope: int | None = None) -> int:
        kinds = (kind,) if type(kind) is str else kind
        if (type(key) is not _Key or key.owner is not self or key.kind not in kinds
                or type(key.value) is not int or not 0 < key.value < 2**64
                or scope is not None and key.scope != scope):
            raise NotesRefused("The Notes primitive key is not from this original owner.")
        if key.kind == "pass":
            original = self._latest_pass.get(key.logical)
        elif key.kind == "source":
            original = self._source_keys.get(key.logical)
        elif key.kind == "current_source":
            original = self._latest_source.get(key.logical)
        elif key.kind == "epoch":
            original = self._latest_epoch.get(key.logical)
        elif key.kind == "presence":
            original = self._presence_keys.get(key.object_key)
        elif key.kind == "pending":
            original = self._pending_epochs.get(key.object_key)
        elif key.kind.startswith("data:"):
            original = self._data_keys.get((key.scope, key.kind))
        else:
            original = self._keys.get((key.kind, key.scope, key.value))
        if original is not key:
            raise NotesRefused("The Notes primitive key is not the retained original borrow.")
        return key.value


    def _capture_reply(self, reply: Any, status: int, operation: int, capacity: int) -> _ReplyData:
        # Scalars are read only from the actual returning predeclared cell.
        # A sequence acknowledges a bridge frame, not a primitive or an effect.
        _require(type(status) is int and status in range(6)
                 and reply.size == 80 and reply.version == _VERSION and reply.status == status
                 and reply.error in _ERRORS and reply.first_failure in _ERRORS
                 and not any(reply.reserved) and reply.flags & ~8191 == 0
                 and 0 <= reply.output_len <= capacity <= _OUTPUT_MAX
                 and reply.sequence <= 132096
                 and (not reply.flags & 16 or reply.flags & 8 != 0)
                 and not (reply.flags & 1024 and reply.flags & 4096)
                 and (not reply.flags & 2 or reply.flags & 2048 != 0)
                 and (not reply.flags & 128 or operation in (17, 42)))
        _require((reply.error == 0) == (status in (_OK, _EOF, _EXPECTED_COLLISION))
                 and (status in (_OK, _EOF, _EXPECTED_COLLISION) or reply.first_failure != 0))
        _require(status != _EOF or operation in (11, 13))
        _require(status != _EXPECTED_COLLISION or operation == 26)
        _require(status != _REFUSED or reply.flags & (8 | 16) == 0)
        _require(status != _UNKNOWN or reply.flags & (1 | 32) != 0)
        if self._first_failure:
            _require(reply.first_failure == self._first_failure)
        if operation == 1:
            if status == _OK:
                _require(self._owner_key == self._sequence == 0
                         and reply.owner != 0 and reply.sequence == 1
                         and reply.first_failure == 0 and reply.flags & (8 | 16 | 64) == 0)
            else:
                _require(self._owner_key == self._sequence == 0
                         and reply.owner == reply.sequence == reply.token == 0
                         and reply.output_len == reply.count == reply.total == 0
                         and reply.first_failure != 0 and reply.flags & (8 | 16 | 64) == 0)
        else:
            _require(self._owner_key != 0 and reply.owner == self._owner_key)
            if reply.sequence == self._sequence:
                # Pre-admission refusal consumes this Python attempt too. It
                # must never be interpreted as permission to retry a key.
                _require(status == _REFUSED and reply.error in (1, 3, 15)
                         and reply.flags & (8 | 16) == 0)
            else:
                _require(reply.sequence == self._sequence + 1)
        terminal = reply.flags & (1024 | 4096)
        _require((not self._terminal_bits or terminal == self._terminal_bits)
                 and (not terminal or self._terminal_bits or operation == 27))
        # Preserve irreversibility and the original reason before any payload
        # decoder/guard callback. These facts do not assert that DATA is valid.
        self._terminal_bits |= terminal
        self._first_failure = reply.first_failure
        self._sequence = reply.sequence
        if operation == 1 and status == _OK:
            self._owner_key = reply.owner
        return _ReplyData(status, reply.error, reply.owner, reply.token, reply.sequence,
                          reply.epoch, reply.output_len, reply.count, reply.total,
                          reply.flags, reply.first_failure)

    def _invoke(self, operation: int, *, decode: Any, a: int = 0, b: int = 0,
                c_key: int = 0, number: int = 0, count: int = 0,
                payload: bytes = b"", capacity: int = _OUTPUT_MAX) -> Any:
        self._context()
        if (type(operation) is not int or not 1 <= operation <= 42
                or type(payload) is not bytes or len(payload) > _INPUT_MAX
                or type(capacity) is not int or not 0 <= capacity <= _OUTPUT_MAX
                or not callable(decode)):
            raise NotesRefused("The required-note primitive is outside its closed bounds.")
        if (any(type(value) is not int or not 0 <= value < 2**64 for value in (a, b, c_key))
                or any(type(value) is not int or not 0 <= value < 2**32 for value in (number, count))):
            raise NotesRefused("The required-note primitive has invalid scalar DATA.")
        # No opcode can bypass a genuinely unreturned, malformed, or otherwise
        # uncertain ABI cell. Native per-resource finality cannot prove that an
        # unreturned caller frame is quiescent.
        if (self._active or self._wire_lost or self._info_pending is not None
                or self._pending is not None or self._finality_pending is not None):
            raise NotesUnknown("The original required-note call frame is not settled.")
        finality = operation in _FINALITY_OPERATIONS and (
            operation != 39 or self._failed or self._unknown or self._retired)
        if finality and payload:
            raise NotesRefused("Required-note finality never accepts an input body.")
        if self._unknown and not finality:
            raise NotesUnknown("Unknown required-note custody cannot restart ordinary work.")
        if self._retired and operation not in (39, 41, 42):
            raise NotesRefused("The original required-note retirement is final.")
        if operation != 1 and not self._prepared:
            raise NotesRefused("The original required-note owner was not prepared.")
        if operation == 1 and (self._owner_key or self._prepared):
            raise NotesRefused("The original required-note owner cannot be replaced.")
        recovery = (not finality and
                    (self._recovery_entered or operation in _RECOVERY_ENTRY_OPERATIONS))
        if self._failed and not finality and not recovery:
            raise NotesRefused("The failed required-note producer cannot enter again.")
        if recovery and operation not in (
                3, 9, 10, 11, 12, 13, 14, 15, 16, 25, 26, 27, 29, 30, 31, 32, 33,
                36, 37, 38, 39):
            raise NotesRefused("This primitive is not part of the original fixed recovery.")
        if recovery and self._scope_number != 3:
            raise NotesRefused("The original required-note recovery cannot be reopened.")
        corrective = recovery and (self._recovery_mode == "corrective"
                                   or operation == 36 and number == 2)
        if corrective and operation != 36:
            pair = self._corrective_pair
            admitted = False
            if operation in (10, 12, 16):
                admitted = a in self._corrective_objects
            elif operation in (11, 13):
                admitted = any(stream.key.value == a and stream.object.value in self._corrective_objects
                               and stream.object.scope == 3 and not stream.complete
                               for stream in self._passes.values())
            elif operation in (26, 27):
                admitted = pair is not None and a == pair[1].value and not self._corrective_inverse_finished
            elif operation in (29, 30):
                admitted = (a == self._corrective_restore_key and a != 0
                            and not self._corrective_inverse_returned)
            if not admitted:
                raise NotesRefused("Corrective work belongs only to the original frozen inverse and its originals.")
        joined_exit = recovery and self._recovery_joined
        if joined_exit:
            admitted = operation == 3
            if operation in (12, 16):
                admitted = a in self._joined_exit_objects
            elif operation == 13:
                admitted = any(stream.key.value == a and stream.object.value in self._joined_exit_objects
                               and stream.object.scope == 3 and not stream.complete
                               for stream in self._passes.values())
            if not admitted:
                raise NotesRefused("Joined cleanup permits only original root/metadata exit validation.")
        counter = "_finality_calls" if finality else "_recovery_calls" if recovery else "_producer_calls"
        ceiling = 1024 if finality else 65536
        if getattr(self, counter) >= ceiling:
            self._failed = True
            raise NotesRefused("The required-note bridge reserve is exhausted.")
        frame = self._finality_frame if finality else self._ordinary_frame
        pending_name = "_finality_pending" if finality else "_pending"
        self._active = True
        entered = False
        try:
            # Closed routing uses the same original endpoint. Finality is not
            # another poll, work allowance, producer, or terminal stdout grant.
            if finality:
                self._input.before_notes_finality()
            elif corrective:
                # The exact already-owned pair/original whitelist above may
                # settle after STOP, inside the frozen original filesystem E.
                # No new work, owner, retry, reserve or extra lifetime is granted.
                self._input.before_notes_settlement()
            elif recovery and not joined_exit:
                self._input.before_notes_settlement()
            elif joined_exit:
                # Same remaining recovery counter, but NORMAL STOP/deadline
                # admission: a joined phase is not a post-STOP query grant.
                self._input.before_notes_entry()
            else:
                self._input.before_notes_entry()
            setattr(self, counter, getattr(self, counter) + 1)  # never refunded
            frame.arm(operation, self._owner_key, a, b, c_key, number, count, payload, capacity)
            setattr(self, pending_name, frame)
            self._last_frame = frame
            entered = True
            c = self._ctypes
            status = self._call(c.byref(frame.request), frame.source,
                                c.byref(frame.reply), frame.destination)
            # The actual returning original frame is retained before decoder
            # allocation or any cancellation/cleanup callback.
            frame.returned = True
            self._returned_status = status
            result = self._capture_reply(frame.reply, status, operation, capacity)
            self._last_reply = result
            data = c.string_at(c.addressof(frame.destination), result.output_len) if result.output_len else b""
            self._last_payload = data
            answer = (self._failure_payload(operation, a, data, result)
                      if status in (_REFUSED, _FAILED, _UNKNOWN) else decode(data, result))
            if result.flags & (1 | 32) or status == _UNKNOWN:
                self._unknown = True
            if status in (_REFUSED, _FAILED, _UNKNOWN):
                self._failed = True
                if self._first_failure_return is None:
                    self._first_failure_return = (result, data)
            # Only a complete, validated actual return can release this frame.
            # An UNKNOWN native resource remains UNKNOWN; the separate original
            # finality cell may inspect/settle only independently known cells.
            setattr(self, pending_name, None)
            if status == _UNKNOWN or self._unknown and not finality:
                # Retain this exact original exception identity. The outer
                # core failure hook must not relabel a completely decoded,
                # positively returned UNKNOWN as a malformed caller frame.
                if self._known_unknown_error is None:
                    self._known_unknown_error = NotesUnknown("The original required-note outcome remains unknown.")
                raise self._known_unknown_error
            if status == _FAILED:
                raise NotesFailure("The original required-note primitive failed.")
            if status == _REFUSED:
                raise NotesRefused("The original required-note primitive was refused.")
            return answer
        except BaseException:
            if entered and getattr(self, pending_name) is not None:
                self._wire_lost = self._unknown = self._failed = True
                # Never reset, replace, free or infer quiescence of this cell.
                raise NotesUnknown("The original required-note ABI return is not fully known.") from None
            raise
        finally:
            self._active = False

    def _failure_payload(self, operation: int, a: int, raw: bytes, result: _ReplyData) -> Any:
        # Native never returns a partial factory/observation/read/page/scope
        # batch. Only an actually entered PRIMARY effect has a whole Effect80.
        if not raw:
            _require(result.output_len == result.token == result.count == result.total == 0)
            return None
        _require(result.status in (_FAILED, _UNKNOWN) and operation in _EFFECT_OPERATIONS
                 and result.flags & 8 != 0 and result.count == result.total == 1
                 and result.token == (0 if operation == 22 else a))
        value = _decode_effect(raw, owner=result.owner, operation=operation)
        _require(value.operation_key == a)
        self._last_effect = value
        if operation in (28, 29):
            self._security_effects[a] = value
        return value

    def _plain(self, raw: bytes, result: _ReplyData, *, token: int = 0) -> _ReplyData:
        _require(not raw and result.output_len == result.count == result.total == 0)
        if result.status in (_OK, _EOF):
            _require(result.token == token)
        return result


    def _keep(self, value: int, kind: str, *, scope: int = 0,
              logical: int = 0, object_key: int = 0) -> _Key:
        _require(type(value) is int and 0 < value < 2**64
                 and scope in (0, 1, 2, 3) and type(logical) is int
                 and type(object_key) is int)
        if kind == "pass":
            bucket, index = self._latest_pass, logical
        elif kind == "source":
            bucket, index = self._source_keys, logical
        elif kind == "current_source":
            bucket, index = self._latest_source, logical
        elif kind == "epoch":
            bucket, index = self._latest_epoch, logical
        elif kind == "presence":
            bucket, index = self._presence_keys, object_key
        elif kind == "pending":
            bucket, index = self._pending_epochs, object_key
        elif kind.startswith("data:"):
            bucket, index = self._data_keys, (scope, kind)
        else:
            bucket, index = self._keys, (kind, scope, value)
        previous = bucket.get(index)
        if previous is not None and previous.value == value:
            _require(previous.kind == kind and previous.scope == scope
                     and previous.logical == logical and previous.object_key == object_key)
            return previous
        if previous is None:
            _require(len(bucket) < (256 if bucket is self._keys else 154 if bucket is self._presence_keys else 76))
        key = _Key(self, value, kind, scope, logical, object_key)
        bucket[index] = key
        return key

    def _claim(self, operation: int, *, key: int = 0, scope: int = 0) -> None:
        marker = (operation, scope, key)
        if marker in self._claims:
            raise NotesRefused("The original required-note primitive is one-use.")
        if len(self._claims) >= 512:
            raise NotesRefused("The required-note one-use inventory is exhausted.")
        self._claims.add(marker)  # consumed even if the following entry refuses

    def _factory_call(self, operation: int, *, scope: int, a: int = 0, b: int = 0,
                      c_key: int = 0, number: int = 0, count: int = 0,
                      payload: bytes = b"") -> _FactoryData:
        def decode(raw: bytes, result: _ReplyData) -> _FactoryData:
            value = _decode_factory(raw, operation=operation,
                                    owner=None if operation == 1 else self._owner_key, scope=scope)
            _require(result.count == result.total == 1 and result.token == value.factory_key)
            return value
        return self._invoke(operation, a=a, b=b, c_key=c_key, number=number,
                            count=count, payload=payload, capacity=128, decode=decode)

    def _table(self, key_value: int, kind: int, scope: int) -> tuple[Any, ...]:
        if key_value == 0:
            return ()
        key = self._keep(key_value, "data:" + str(kind), scope=scope)
        def decode(raw: bytes, result: _ReplyData) -> tuple[Any, ...]:
            page = _decode_data_page(raw, owner=self._owner_key, scope=scope, kind=kind,
                                     key=key.value, offset=0, requested=65_472)
            _require(result.token == key.value and result.count == len(page.content)
                     and result.total == page.total and page.total == len(page.content))
            # All closed factory tables fit one page. Security descriptors are
            # not tables and are never gathered into the Python bridge.
            return _decode_table(page.content, kind=kind, scope=scope)
        return self._invoke(39, b=self._key(key, "data:" + str(kind), scope=scope),
                            number=kind, count=65_472, decode=decode)

    def _factory_tables(self, report: _FactoryData) -> _FactoryResult:
        try:
            logical = self._table(report.logical_data_key, 1, report.scope)
            mappings = self._table(report.mappings_data_key, 2, report.scope)
            moves = self._table(report.moves_data_key, 3, report.scope)
            deletes = self._table(report.deletes_data_key, 4, 3) if report.deletes_data_key else ()
            security = self._table(report.security_data_key, 5, 3) if report.security_data_key else ()
            schedule = self._table(report.schedule_data_key, 6, report.scope)
            _require(len(logical) == report.row_count
                     and len({row.logical_key for row in logical}) == len(logical)
                     and len({row.path for row in logical}) == len(logical))
            rows = {row.logical_key: row for row in logical}
            if report.known_counts & 3:
                _require(report.known_counts & 3 == 3
                         and report.files == sum(row.role in (4, 5, 6, 7, 8) for row in logical)
                         and report.parents == sum(row.role == 3 for row in logical))
            _require(report.lease_key == self._lease_key)
            roots = tuple(row for row in logical if row.role == 1)
            _require(len(roots) == 1 and all(row.parent_logical_key == 0
                                           or row.parent_logical_key in rows for row in logical))
            if report.scope == 0:
                _require(report.operation == 1 and report.row_count == 1 and not mappings
                         and not any((moves, deletes, security)))
            else:
                _require(len(mappings) == len(logical)
                         and {row.logical_key for row in mappings} == set(rows))
                root = next(row for row in mappings if row.logical_key == roots[0].logical_key)
                _require(root.source_object_key == report.root_key and root.source_state == 2)
                if report.scope == 3:
                    self._joined_exit_objects = frozenset(mapping.source_object_key for mapping in mappings
                        if rows[mapping.logical_key].role in (1, 2) and mapping.source_object_key)
                for mapping in mappings:
                    for value in (mapping.source_object_key, mapping.create_object_key):
                        if value:
                            self._keep(value, "object", scope=report.scope,
                                       logical=mapping.logical_key, object_key=value)
            _require(report.operation == 18 or not any((moves, deletes, security)))
            _require(len({row.move_key for row in moves}) == len(moves)
                     and len({row.delete_key for row in deletes}) == len(deletes)
                     and len({row.action_key for row in security}) == len(security))
            for row in moves:
                _require(row.logical_key in rows and row.from_parent_logical_key in rows
                         and row.to_parent_logical_key in rows)
                self._keep(row.move_key, "move", scope=3, logical=row.logical_key, object_key=row.object_key)
                self._move_facts[row.move_key] = row
            for row in deletes:
                _require(row.logical_key in rows and all(parent in rows for parent, _ in row.edges))
                self._keep(row.delete_key, "delete", scope=3, logical=row.logical_key, object_key=row.object_key)
            for row in security:
                _require(row.logical_key in rows and row.material_security_key == rows[row.logical_key].material_security_key)
                self._keep(row.action_key, "security", scope=3, logical=row.logical_key, object_key=row.object_key)
                self._security_facts[row.action_key] = row
            schedule = _admit_schedule(schedule, self._schedule_snapshot)
            self._schedule_snapshot = schedule
            return _FactoryResult(report, logical, mappings, moves, deletes, security, schedule)
        except NotesUnknown:
            # Cross-table DATA admission is still part of the closed factory.
            # Retain the last original page cell; do not salvage a malformed
            # graph with a new query, factory, or independent finality entry.
            self._wire_lost = self._unknown = self._failed = True
            if self._pending is None and self._last_frame is self._ordinary_frame:
                self._pending = self._ordinary_frame
            raise

    def prepare(self, root: str, identity: dict[str, str]) -> _FactoryResult:
        if self._prepare_claimed:
            raise NotesRefused("The original required-note lease preparation is one-use.")
        self._prepare_claimed = True
        admitted = registered_root(identity)
        if type(root) is not str:
            raise NotesRefused("The required-note project root is not text.")
        try:
            raw_root = root.encode("utf-8", "strict")
            original_id = bytes.fromhex(admitted["fileId"])
            volume = int(admitted["volumeSerial"], 16)
        except (ValueError, UnicodeError):
            raise NotesRefused("The required-note project registration is invalid.") from None
        if not 1 <= len(raw_root) <= 11_266 or original_id == b"\0" * 16:
            raise NotesRefused("The required-note project registration is outside its closed bounds.")
        self._check_abi()
        payload = struct.pack("<8sIIQ16sII", b"MRKNLS1\0", 48, 0, volume, original_id, len(raw_root), 0) + raw_root
        report = self._factory_call(1, scope=0, payload=payload)
        self._prepared = True
        self._lease_key, self._registered = report.lease_key, (volume, original_id)
        return self._factory_tables(report)

    def _lease_observation(self, operation: int) -> _ObservationData:
        def decode(raw: bytes, result: _ReplyData) -> _ObservationData:
            observed = _decode_lease(raw, owner=self._owner_key)
            _require(result.token == observed.observation_key and result.count == result.total == 1
                     and observed.object_key == self._lease_key
                     and (observed.volume_serial, observed.file_id) == self._registered)
            return observed
        return self._invoke(operation, capacity=332, decode=decode)

    def acquire_lease(self) -> _ObservationData:
        self._claim(2)
        return self._lease_observation(2)

    def check_lease(self) -> _ObservationData:
        return self._lease_observation(3)

    def enter_scope(self, number: int) -> _FactoryResult:
        if type(number) is not int or number != self._scope_number + 1 or number not in (1, 2, 3):
            raise NotesRefused("The required-note scope order cannot be replaced.")
        self._claim(4, scope=number)
        report = self._factory_call(4, scope=number, number=number)
        self._scope_number = number
        return self._factory_tables(report)

    def freeze_fixed(self, root: _Key) -> _FactoryResult:
        value = self._key(root, "object", scope=1)
        self._claim(5)
        return self._factory_tables(self._factory_call(5, scope=1, a=value))

    def freeze_version(self, root: _Key, config: _Key, path: str | None) -> _FactoryResult:
        a = self._key(root, "object", scope=1)
        b = self._key(config, ("source", "current_source"))
        if path is not None and type(path) is not str:
            raise NotesRefused("The original required-note version path is invalid.")
        payload = b"" if path is None else _input_path(path)
        self._claim(6)
        return self._factory_tables(self._factory_call(6, a=a, b=b, scope=1,
                                                       number=int(path is not None), payload=payload))

    def freeze_selected(self, root: _Key, config: _Key, version: _Key | None, *,
                        kind: int, selected: str, counterpart: str | None) -> _FactoryResult:
        a, b = self._key(root, "object", scope=1), self._key(config, ("source", "current_source"))
        c_key = 0 if version is None else self._key(version, ("source", "current_source"))
        if type(kind) is not int or not 1 <= kind <= 5 or type(selected) is not str:
            raise NotesRefused("The original required-note kind is outside its closed set.")
        first = _input_path(selected)
        second = b"" if counterpart is None else _input_path(counterpart)
        payload = struct.pack("<II", len(first), len(second)) + first + second
        self._claim(7)
        return self._factory_tables(self._factory_call(7, scope=1, a=a, b=b, c_key=c_key,
                                                       number=kind, count=int(counterpart is not None), payload=payload))

    def freeze_apply(self, root: _Key, selected: _Key, *, action: int,
                     byte_length: int = 0, sha256: bytes = b"") -> _FactoryResult:
        a = self._key(root, "object", scope=3)
        b = self._key(selected, ("source", "current_source", "epoch", "presence"), scope=3)
        if type(action) is not int or action not in (0, 1, 2):
            raise NotesRefused("The required-note action is outside its original plan.")
        if action == 0:
            if byte_length or sha256:
                raise NotesRefused("A preserved required note cannot bind new content.")
            payload = b""
        else:
            if (type(byte_length) is not int or not 0 <= byte_length <= 65536
                    or type(sha256) is not bytes or len(sha256) != 32):
                raise NotesRefused("The required-note body is outside its selected limit.")
            payload = struct.pack("<Q", byte_length) + sha256
        self._claim(18)
        return self._factory_tables(self._factory_call(18, scope=3, a=a, b=b, number=action, payload=payload))


    def _object(self, value: _Key) -> int:
        return self._key(value, "object", scope=self._scope_number)

    def _pass(self, value: _Pass, *, directory: bool | None = None,
              complete: bool | None = None) -> int:
        if (type(value) is not _Pass or self._passes.get(value.object.value) is not value
                or directory is not None and value.directory is not directory
                or complete is not None and value.complete is not complete):
            raise NotesRefused("The required-note pass is not this original complete stream.")
        self._object(value.object)
        return self._key(value.key, "pass", scope=self._scope_number)

    def acquire_object(self, original: _Key, proof: _NativePresence) -> None:
        a = self._object(original)
        if type(proof) is not _NativePresence or proof.object is not original or not proof.present:
            raise NotesRefused("Acquisition requires the original present edge proof.")
        b = self._key(proof.key, "presence", scope=self._scope_number)
        self._claim(8, key=a, scope=self._scope_number)
        self._invoke(8, a=a, b=b, capacity=0,
                     decode=lambda raw, result: self._plain(raw, result, token=a))

    def begin_pass(self, original: _Key, *, directory: bool) -> _Pass:
        a = self._object(original)
        if type(directory) is not bool:
            raise NotesRefused("The required-note stream kind is invalid.")
        previous = self._passes.get(a)
        if previous is not None and not previous.complete:
            raise NotesRefused("An unfinished required-note pass cannot be replaced.")
        operation = 12 if directory else 10
        def decode(raw: bytes, result: _ReplyData) -> _Pass:
            _require(result.status == _OK and not raw and result.output_len == result.count == result.total == 0
                     and result.token != 0)
            key = self._keep(result.token, "pass", scope=original.scope,
                             logical=original.logical, object_key=a)
            value = _Pass(key, original, directory)
            _require(a in self._passes or len(self._passes) < 154)
            self._passes[a] = value
            return value
        return self._invoke(operation, a=a, capacity=0, decode=decode)

    def next_read(self, stream: _Pass) -> bytes | None:
        a = self._pass(stream, directory=False, complete=False)
        def decode(raw: bytes, result: _ReplyData) -> bytes | None:
            _require(result.token == a and result.count == len(raw)
                     and result.total == stream.total + len(raw)
                     and result.total <= 1_048_576)
            if result.status == _EOF:
                _require(not raw)
                stream.complete = True
                return None
            _require(result.status == _OK and 0 < len(raw) <= 65_536)
            stream.total = result.total
            return raw
        return self._invoke(11, a=a, decode=decode)

    def next_roster(self, stream: _Pass) -> tuple[_RosterEntry, ...] | None:
        a = self._pass(stream, directory=True, complete=False)
        def decode(raw: bytes, result: _ReplyData) -> tuple[_RosterEntry, ...] | None:
            _require(result.token == a and result.total == stream.total + result.count
                     and result.total <= 128)
            if result.status == _EOF:
                _require(not raw and result.count == 0)
                stream.complete = True
                return None
            _require(result.status == _OK)
            # A genuinely returned dot-only native batch is framed <0,8>.
            # It is progress DATA, never EOF; the same finite bridge/native
            # reserves still apply and the next actual EOF must be observed.
            rows = _decode_roster(raw, expected_count=result.count)
            stream.total = result.total
            return rows
        return self._invoke(13, a=a, decode=decode)

    def presence(self, original: _Key, parent: _Pass | _NativePresence) -> _NativePresence:
        a = self._object(original)
        if type(parent) is _Pass:
            b = self._pass(parent, directory=True, complete=True)
        elif type(parent) is _NativePresence and not parent.present:
            b = self._key(parent.key, "presence", scope=original.scope)
        else:
            raise NotesRefused("An absent parent needs its original no-handle proof.")
        def decode(raw: bytes, result: _ReplyData) -> _NativePresence:
            value = _decode_presence_batch(raw, owner=self._owner_key, scope=original.scope)
            _require(result.count == result.total == 1 and result.token == value.fact_key
                     and value.object_key == a)
            if type(parent) is _Pass:
                _require(value.proof == 1 and value.parent_object_key == parent.object.value
                         and value.completed_roster_key == b)
            else:
                _require(value.proof == 2 and value.parent_object_key == parent.object.value
                         and value.original_parent_absent_key == b)
            key = self._keep(value.fact_key, "presence", scope=original.scope,
                             logical=original.logical, object_key=a)
            return _NativePresence(key, original, value)
        return self._invoke(14, a=a, b=b, capacity=427, decode=decode)

    def _observation(self, original: _Key, data: _ObservationData, *,
                     operation: int) -> _NativeObservation:
        _require(data.object_key == original.value and data.logical_key == original.logical
                 and data.scope == original.scope and data.file_id != b"\0" * 16)
        if data.tag == 2:
            kind = "epoch"
        elif data.scope == 1 and data.original_capture == data.observation_key:
            kind = "source"
        else:
            kind = "current_source"
        key = self._keep(data.observation_key, kind, scope=data.scope,
                         logical=data.logical_key, object_key=data.object_key)
        return _NativeObservation(key, original, data)

    def observe(self, original: _Key, stream: _Pass, *,
                baseline: _NativeObservation | None = None,
                accepted: _NativeObservation | _Key | None = None) -> _NativeObservation:
        a = self._object(original)
        c_key = self._pass(stream, complete=True)
        if stream.object is not original or baseline is not None and accepted is not None:
            raise NotesRefused("The completed pass is not the requested original object.")
        if baseline is not None:
            if (type(baseline) is not _NativeObservation or baseline.data.tag != 1
                    or baseline.data.scope != 1 or baseline.data.original_capture != baseline.key.value
                    or baseline.data.logical_key != original.logical):
                raise NotesRefused("A source recheck needs the original Capture baseline.")
            operation, b = 15, self._key(baseline.key, "source", scope=1)
        elif accepted is not None:
            if type(accepted) is _NativeObservation:
                if (accepted.object is not original or accepted.data.tag not in (1, 2)
                        or not accepted.data.flags & 128):
                    raise NotesRefused("A current check needs the original acknowledged anchor.")
                # Only the latest same-original native acknowledgement is an
                # anchor. The native ledger proves pending effects; this Source
                # key is never relabelled as current Epoch DATA in Python.
                b = self._key(accepted.key, ("source", "current_source", "epoch"), scope=original.scope)
            elif type(accepted) is _Key:
                if accepted.object_key != a:
                    raise NotesRefused("The pending epoch belongs to a different original.")
                b = self._key(accepted, "pending", scope=original.scope)
            else:
                raise NotesRefused("The current required-note epoch is not retained.")
            operation = 16
        else:
            operation, b, c_key = 9, c_key, 0
        def decode(raw: bytes, result: _ReplyData) -> _NativeObservation:
            values = _decode_observation_batch(raw, owner=self._owner_key, scope=original.scope,
                                               operation=operation, expected_count=1)
            value = values[0]
            _require(result.count == result.total == 1 and result.token == value.observation_key
                     and value.completed_pass_key == stream.key.value
                     and (baseline is None or value.original_capture == baseline.key.value))
            return self._observation(original, value, operation=operation)
        return self._invoke(operation, a=a, b=b, c_key=c_key, capacity=627, decode=decode)

    def bind_control(self, original: _Key, body: bytes) -> _Key:
        import hashlib
        a = self._object(original)
        if type(body) is not bytes or not 0 < len(body) <= 131_072:
            raise NotesRefused("The original required-note control is outside its closed bound.")
        self._claim(19, key=a, scope=3)
        def begin(raw: bytes, result: _ReplyData) -> _Key:
            self._plain(raw, result, token=result.token)
            _require(result.token != 0)
            return self._keep(result.token, "control", scope=3,
                              logical=original.logical, object_key=a)
        key = self._invoke(19, a=a, payload=struct.pack("<Q", len(body)) + hashlib.sha256(body).digest(),
                           capacity=0, decode=begin)
        for offset in range(0, len(body), 65_536):
            self._invoke(20, a=a, number=offset, payload=body[offset:offset + 65_536], capacity=0,
                         decode=lambda raw, result: self._plain(raw, result, token=key.value))
        self._claim(21, key=a, scope=3)
        self._invoke(21, a=a, capacity=0,
                     decode=lambda raw, result: self._plain(raw, result, token=key.value))
        return key

    def _effect(self, operation: int, a: int, raw: bytes, result: _ReplyData,
                *, expected_object: int | None = None, input_length: int = 0) -> _EffectData:
        value = _decode_effect(raw, owner=self._owner_key, operation=operation)
        _require(result.count == result.total == 1 and value.operation_key == a
                 and (expected_object is None or value.object_key == expected_object)
                 and value.flags & 3 == 3 and result.flags & 8 != 0
                 and result.flags & 16 != 0)
        if result.status == _EXPECTED_COLLISION:
            _require(operation == 26 and value.flags & 8 != 0 and not value.flags & 4)
        else:
            _require(result.status == _OK and value.flags & (4 | 8) == 0)
            # A synchronous native effect is settled success, not merely the
            # sign-bit-clear NTSTATUS_PENDING or a normalized/fabricated BOOL.
            if value.return_kind == 1:
                _require(value.return_bits == 0)
            elif value.return_kind == 2:
                _require(value.return_bits != 0)
            else:
                _require(value.return_kind == 3 and value.return_bits == 0)
            if operation == 23:
                _require(1 <= value.information <= input_length)
        self._last_effect = value
        if operation in (28, 29):
            self._security_effects[a] = value
        return value

    def create(self, original: _Key, absent: _NativePresence) -> _PendingEffect:
        a = self._object(original)
        if type(absent) is not _NativePresence or absent.object is not original or absent.present:
            raise NotesRefused("Exclusive creation needs the original absent edge proof.")
        b = self._key(absent.key, "presence", scope=3)
        self._claim(22, key=a, scope=3)
        self._last_effect = None
        def decode(raw: bytes, result: _ReplyData) -> _PendingEffect:
            effect = self._effect(22, a, raw, result, expected_object=a)
            _require(result.token != 0)
            pending = self._keep(result.token, "pending", scope=3,
                                 logical=original.logical, object_key=a)
            return _PendingEffect(pending, effect)
        return self._invoke(22, a=a, b=b, capacity=80, decode=decode)

    def write(self, original: _Key, body: bytes) -> _EffectData:
        a = self._object(original)
        if type(body) is not bytes or not 0 < len(body) <= 65_536:
            raise NotesRefused("The original required-note write chunk is outside its bound.")
        # Entry, not success, invalidates the earlier create/write acknowledgement.
        self._pending_epochs.pop(a, None)
        def decode(raw: bytes, result: _ReplyData) -> _EffectData:
            _require(result.token == a)
            return self._effect(23, a, raw, result, expected_object=a, input_length=len(body))
        return self._invoke(23, a=a, payload=body, capacity=80, decode=decode)

    def finish_write(self, original: _Key) -> _Key:
        a = self._object(original)
        self._claim(24, key=a, scope=3)
        def decode(raw: bytes, result: _ReplyData) -> _Key:
            self._plain(raw, result, token=result.token)
            _require(result.token != 0)
            return self._keep(result.token, "pending", scope=3,
                              logical=original.logical, object_key=a)
        return self._invoke(24, a=a, capacity=0, decode=decode)

    def fence(self, original: _Key) -> _EffectData:
        a = self._object(original)
        def decode(raw: bytes, result: _ReplyData) -> _EffectData:
            _require(result.token == a)
            return self._effect(25, a, raw, result, expected_object=a)
        return self._invoke(25, a=a, capacity=80, decode=decode)

    def move(self, key: _Key, destination: _Pass) -> _EffectData:
        a = self._key(key, "move", scope=3)
        b = self._pass(destination, directory=True, complete=True)
        self._claim(26, key=a, scope=3)
        def decode(raw: bytes, result: _ReplyData) -> _EffectData:
            _require(result.token == a)
            return self._effect(26, a, raw, result, expected_object=key.object_key)
        effect = self._invoke(26, a=a, b=b, capacity=80, decode=decode)
        if effect.flags & 8:
            self._collision_candidates.add(a)
        if self._recovery_mode == "corrective":
            _require(self._corrective_pair is not None and a == self._corrective_pair[1].value
                     and not effect.flags & 8)
            self._corrective_inverse_returned = True
        return effect

    def finish_move(self, key: _Key, object_pass: _Pass, old: _Pass, new: _Pass,
                    originals: tuple[_Key, ...]) -> tuple[_NativeObservation, ...]:
        a = self._key(key, "move", scope=3)
        if object_pass.object.value != key.object_key:
            raise NotesRefused("The moved object pass is not the original frozen object.")
        object_value = self._pass(object_pass, complete=True)
        b, c_key = (self._pass(old, directory=True, complete=True),
                    self._pass(new, directory=True, complete=True))
        expected = {object_pass.object.value, old.object.value, new.object.value}
        row = self._move_facts.get(a)
        if row is None or row.object_key != key.object_key:
            raise NotesRefused("The original frozen move DATA is unavailable.")
        collision = a in self._collision_candidates
        if collision and row.kind != 3:
            raise NotesUnknown("A non-probe move acquired collision status.")
        parent, name = (old.object.value, row.from_name) if collision else (new.object.value, row.to_name)
        values = self._finish_epochs(27, a=a, b=b, c_key=c_key,
                                     payload=struct.pack("<Q", object_value),
                                     originals=originals, expected=expected,
                                     primary=(key.object_key, parent, name, 0))
        if self._recovery_mode == "corrective":
            _require(self._corrective_pair is not None and a == self._corrective_pair[1].value
                     and self._corrective_inverse_returned and not collision)
            self._corrective_inverse_finished = True
        return values

    def security(self, key: _Key, *, publish: bool) -> _EffectData:
        if type(publish) is not bool:
            raise NotesRefused("The frozen security transition kind is invalid.")
        a = self._key(key, "security", scope=3)
        operation = 28 if publish else 29
        self._claim(operation, key=a, scope=3)
        def decode(raw: bytes, result: _ReplyData) -> _EffectData:
            _require(result.token == a)
            return self._effect(operation, a, raw, result, expected_object=key.object_key)
        return self._invoke(operation, a=a, capacity=80, decode=decode)

    def finish_security(self, key: _Key, *, publish: bool, object_pass: _Pass,
                        parent: _Pass, originals: tuple[_Key, ...]) -> tuple[_NativeObservation, ...]:
        a = self._key(key, "security", scope=3)
        b, c_key = (self._pass(object_pass, complete=True),
                    self._pass(parent, directory=True, complete=True))
        if object_pass.object.value != key.object_key:
            raise NotesRefused("The security pass belongs to a different original.")
        row = self._security_facts.get(a)
        if row is None or row.purpose != (1 if publish else 2):
            raise NotesRefused("The original frozen security DATA is unavailable.")
        return self._finish_epochs(30, a=a, b=b, c_key=c_key, number=1 if publish else 2,
                                   originals=originals, expected={object_pass.object.value, parent.object.value},
                                   primary=(key.object_key, parent.object.value, None, 32 if publish else 16))

    def _finish_epochs(self, operation: int, *, a: int, b: int, c_key: int,
                       originals: tuple[_Key, ...], expected: set[int],
                       primary: tuple[int, int, str | None, int], number: int = 0,
                       payload: bytes = b"") -> tuple[_NativeObservation, ...]:
        keys = {self._object(original): original for original in originals}
        if len(keys) != len(originals) or set(keys) != expected:
            raise NotesRefused("The original postcondition inventory is incomplete.")
        def decode(raw: bytes, result: _ReplyData) -> tuple[_NativeObservation, ...]:
            _require(result.token == a and result.count == result.total == len(expected))
            values = _decode_observation_batch(raw, owner=self._owner_key, scope=3,
                                               operation=operation, expected_count=len(expected))
            _require({value.object_key for value in values} == expected)
            original = next(value for value in values if value.object_key == primary[0])
            _require(original.parent_object_key == primary[1]
                     and (primary[2] is None or original.name == primary[2])
                     and (primary[3] == 0 or original.flags & (16 | 32 | 64) == primary[3]))
            # Return/data/terminal bits are already retained by _invoke. The
            # accepted postcondition uses only each original, not later paths.
            return tuple(self._observation(keys[value.object_key], value, operation=operation)
                         for value in values)
        self._claim(operation, key=a, scope=3)
        return self._invoke(operation, a=a, b=b, c_key=c_key, number=number,
                            payload=payload, capacity=1865, decode=decode)

    def delete(self, key: _Key, empty: _Pass | None) -> _EffectData:
        a = self._key(key, "delete", scope=3)
        b = 0 if empty is None else self._pass(empty, directory=True, complete=True)
        if empty is not None and (empty.total != 0 or empty.object.value != key.object_key):
            raise NotesRefused("Deleting a directory needs its actual original empty roster.")
        self._claim(31, key=a, scope=3)
        def decode(raw: bytes, result: _ReplyData) -> _EffectData:
            _require(result.token == a)
            return self._effect(31, a, raw, result, expected_object=key.object_key)
        return self._invoke(31, a=a, b=b, capacity=80, decode=decode)

    def close_deleted(self, key: _Key) -> None:
        a = self._key(key, "delete", scope=3)
        self._claim(32, key=a, scope=3)
        self._invoke(32, a=a, capacity=0,
                     decode=lambda raw, result: self._plain(raw, result, token=a))

    def finish_delete(self, key: _Key, parent: _Pass) -> _DeletionData:
        a = self._key(key, "delete", scope=3)
        b = self._pass(parent, directory=True, complete=True)
        self._claim(33, key=a, scope=3)
        def decode(raw: bytes, result: _ReplyData) -> _DeletionData:
            value = _decode_deletion(raw, owner=self._owner_key, scope=3)
            _require(result.token == a and result.count == result.total == 1
                     and value.delete_key == a and value.object_key == key.object_key)
            return value
        return self._invoke(33, a=a, b=b, capacity=72, decode=decode)

    def close_object(self, original: _Key) -> None:
        a = self._key(original, "object")
        self._claim(34, key=a, scope=original.scope)
        self._invoke(34, a=a, capacity=0,
                     decode=lambda raw, result: self._plain(raw, result, token=a))

    def scope_status(self, number: int, *, settle: bool) -> _ScopeStatus:
        if type(number) is not int or number not in (1, 2, 3) or type(settle) is not bool:
            raise NotesRefused("The original required-note scope is invalid.")
        operation = 17 if settle else 42
        if settle:
            self._claim(17, scope=number)
        def decode(raw: bytes, result: _ReplyData) -> _ScopeStatus:
            value = _decode_scope_status(raw, owner=self._owner_key, scope=number)
            _require(result.count == result.total == 1
                     and result.token == value.settlement_key
                     and bool(result.flags & 128) == value.settled
                     and (not settle or value.settled))
            return value
        return self._invoke(operation, number=number, capacity=64, decode=decode)

    def core_failure(self, reason: int) -> None:
        if type(reason) is not int or reason not in (13, 14, 18, 19):
            raise NotesRefused("The required-note first failure has no closed reason.")
        self._invoke(35, number=reason, capacity=0,
                     decode=lambda raw, result: self._plain(raw, result))
        self._failed = True

    def begin_compensation(self, forward: _Key | None = None,
                           inverse: _Key | None = None, *,
                           originals: tuple[_Key, ...] = ()) -> None:
        if (forward is None) != (inverse is None):
            raise NotesRefused("The corrective pair must retain both frozen moves.")
        if forward is None:
            continuation = (self._recovery_mode == "corrective"
                            and self._corrective_inverse_finished)
            if (originals or self._recovery_mode != "none" and not continuation
                    or self._recovery_mode == "none" and self._recovery_choice_claimed):
                raise NotesRefused("Fixed recovery cannot replace an original recovery choice.")
            self._recovery_choice_claimed = True
            self._claim(36, scope=1)
            # A corrective-to-fixed continuation retains ALL counters, the
            # first failure, the original owner and the unchanged endpoint.
            self._invoke(36, number=1, capacity=0,
                         decode=lambda raw, result: self._plain(raw, result))
            self._recovery_entered, self._recovery_mode = True, "fixed"
            return
        if self._recovery_choice_claimed or self._recovery_mode != "none" or self._terminal_bits:
            raise NotesRefused("The original corrective pair is one-use and never terminal.")
        a, b = self._key(forward, "move", scope=3), self._key(inverse, "move", scope=3)
        row, undo = self._move_facts.get(a), self._move_facts.get(b)
        if (row is None or undo is None or row.inverse_move_key != b
                or undo.forward_move_key != a or row.forward_move_key or row.kind in (3, 15, 16)
                or undo.kind in (3, 15, 16) or row.object_key != undo.object_key
                or row.logical_key != undo.logical_key
                or (row.from_parent_logical_key, row.from_name, row.to_parent_logical_key, row.to_name)
                != (undo.to_parent_logical_key, undo.to_name, undo.from_parent_logical_key, undo.from_name)):
            raise NotesRefused("The corrective pair is not the exact frozen original inverse.")
        held = {self._object(value): value for value in originals}
        parents = {value.logical: value for value in originals if value.value != row.object_key}
        if (len(held) != len(originals) or row.object_key not in held
                or held[row.object_key].logical != row.logical_key
                or set(parents) != {row.from_parent_logical_key, row.to_parent_logical_key}
                or len(parents) + 1 != len(held)):
            raise NotesRefused("The corrective pair must retain its object and exact two endpoint originals.")
        self._recovery_choice_claimed = True  # consumed before any entry can fail
        self._claim(36, key=a, scope=2)
        self._invoke(36, a=a, b=b, number=2, capacity=0,
                     decode=lambda raw, result: self._plain(raw, result))
        self._corrective_pair, self._corrective_objects = (forward, inverse), frozenset(held)
        self._corrective_restore_key = undo.restore_action_key
        self._recovery_entered, self._recovery_mode = True, "corrective"

    def begin_committed_cleanup(self, marker: _Key) -> None:
        a = self._key(marker, "move", scope=3)
        row = self._move_facts.get(a)
        if (self._recovery_choice_claimed or self._recovery_mode != "none"
                or self._terminal_bits != 1024 or row is None or row.kind != 15):
            raise NotesRefused("Committed cleanup needs the same original fully finalized decision.")
        self._recovery_choice_claimed = True
        self._claim(38)
        self._invoke(38, a=a, capacity=0,
                     decode=lambda raw, result: self._plain(raw, result))
        self._recovery_entered, self._recovery_mode = True, "committed"

    def join_compensation(self) -> None:
        if self._recovery_mode not in ("fixed", "committed") or self._recovery_joined:
            raise NotesRefused("Only the original completed fixed cleanup may attempt its join.")
        self._claim(37)
        self._invoke(37, capacity=0, decode=lambda raw, result: self._plain(raw, result))
        self._recovery_joined, self._recovery_mode = True, "joined"

    def retire(self) -> _ReplyData:
        if self._retire_claimed:
            raise NotesRefused("The original Notes retirement cannot be attempted twice.")
        self._retire_claimed = True
        result = self._invoke(40, capacity=0, decode=lambda raw, result: self._plain(raw, result))
        self._retired = True
        return result

    def status(self) -> _ReplyData:
        return self._invoke(41, capacity=0, decode=lambda raw, result: self._plain(raw, result))



@dataclass(slots=True, eq=False, repr=False)
class _OriginalObject:
    key: _Key
    row: _LogicalData
    created: bool
    state: str
    location: tuple[int, str] | None
    acknowledged: _NativeObservation | None = None
    pending: _Key | None = None
    absence: _NativePresence | None = None
    created_facts: tuple[tuple[str, int | str], ...] | None = None


class _NotesLease:
    def __init__(self, lease: Any, original_input: Any,
                 registration: dict[str, str], c: Any, dll: Any) -> None:
        self.owner, self.input = lease, original_input
        self.registration = tuple(sorted(registration.items()))
        self.bridge = _Bridge(original_input, lease.guard, c, dll)
        self._scope_slots = tuple(_NotesScope(self, number) for number in (1, 2, 3))
        self._capture: dict[int, _NativeObservation] = {}
        self._capture_objects: dict[int, _Key] = {}
        self._acquire_claimed = self._acquired = False
        self._close_claimed = self.closed = False
        self.cleanup_errors: list[BaseException] = []

    def check_lease_binding(self, lease: Any) -> None:
        from .init_workspace_custody import InitRootLease, _LeasePurpose
        from .init_transaction import TypedEditProfile
        if (type(lease) is not InitRootLease or lease is not self.owner
                or lease._notes_native is not self
                or lease.profile is not TypedEditProfile.METADATA_TEXT
                or lease._purpose is not _LeasePurpose.REQUIRED_NOTES
                or lease.guard is not self.bridge._guard
                or self.registration != lease._registered_identity):
            raise NotesUnknown("The original required-note lease binding changed.")
        self.bridge._context()

    def _run(self, operation: Any, *args: Any, **kwargs: Any) -> Any:
        from .init_transaction import InitConflict
        try:
            return operation(*args, **kwargs)
        except NotesUnknown as error:
            self.bridge._unknown = self.bridge._failed = True
            self.owner.guard._abort(error)
            raise
        except (NotesFailure, NotesRefused) as error:
            result = self.bridge._last_reply
            if result is not None and result.status in (_REFUSED, _FAILED) and result.error in (9, 10, 11):
                raise InitConflict("required-note original filesystem facts changed") from error
            raise

    def acquire(self) -> None:
        self.check_lease_binding(self.owner)
        if self._acquire_claimed or self._close_claimed:
            raise NotesRefused("The original required-note acquisition cannot be repeated.")
        self._acquire_claimed = True
        self._run(self.bridge.prepare, str(self.owner.root), dict(self.registration))
        self._run(self.bridge.acquire_lease)
        self._acquired = True

    def check(self) -> None:
        self.check_lease_binding(self.owner)
        if not self._acquired or self._close_claimed:
            raise NotesRefused("The original required-note lease is not active.")
        self._run(self.bridge.check_lease)

    def scope_for(self, scope_owner: Any, number: int) -> _NotesScope:
        from .init_workspace_custody import LockedInitScope
        if (type(scope_owner) is not LockedInitScope or scope_owner.lease is not self.owner
                or type(number) is not int or number not in (1, 2, 3)):
            raise NotesRefused("The required-note scope is outside its original lease.")
        value = self._scope_slots[number - 1]
        if value.owner is not None:
            raise NotesRefused("The required-note scope owner cannot be replaced.")
        value.owner = scope_owner
        return value

    def record_core_failure(self, error: BaseException) -> None:
        from ._desktop_edit_protocol import ProtocolError
        self.check_lease_binding(self.owner)
        if isinstance(error, NotesUnknown):
            if error is self.bridge._known_unknown_error:
                # Native/resource UNKNOWN stays absorbing, but the positively
                # returned caller cell is already known. Do not revoke the
                # separately predeclared original finality cell. Existing loss
                # flags, if any, are never cleared by this identity check.
                self.bridge._unknown = self.bridge._failed = True
                self.owner.guard._abort(error)
                return
            # A DATA/graph association failure belongs to the original return,
            # even if detected just after its scalar decoder. Do not use35 or
            # another opcode as permission to enter after malformed custody.
            self.bridge._wire_lost = self.bridge._unknown = self.bridge._failed = True
            if self.bridge._pending is None and self.bridge._last_frame is self.bridge._ordinary_frame:
                self.bridge._pending = self.bridge._ordinary_frame
            self.owner.guard._abort(error)
            return
        if not self.bridge._prepared:
            # A refused first factory has no native root acquisition. An
            # unresolved ABI frame remains retained; close() still reports it.
            return
        reason = (19 if self.input._notes_deadline_reached
                  else 18 if isinstance(error, KeyboardInterrupt) or self.owner.guard.cancelled
                  else 14 if isinstance(error, ProtocolError) else 13)
        self._run(self.bridge.core_failure, reason)

    def close(self) -> None:
        self.check_lease_binding(self.owner)
        if self._close_claimed:
            if not self.closed:
                raise NotesUnknown("The original required-note finality did not settle.")
            return
        self._close_claimed = True
        b = self.bridge
        if not b._prepared:
            if b._pending is not None or b._info_pending is not None or b._wire_lost or b._unknown:
                raise NotesUnknown("The original required-note preparation has an unresolved frame.")
            self.closed = True
            return
        # Scope owners each attempted their own once-consuming settlement
        # before this lease retirement. Native retirement independently visits
        # every remaining known original; it never recreates a failed scope.
        primary = None
        try:
            self._run(b.retire)
        except BaseException as error:
            primary = error
            self.cleanup_errors.append(error)
        result = None
        try:
            result = self._run(b.status)
        except BaseException as error:
            self.cleanup_errors.append(error)
            if primary is None:
                primary = error
        if (result is None or result.flags & (1 | 32) or result.flags & (2 | 4 | 2048) != 2 | 4 | 2048
                or any(slot.entered and not slot.closed for slot in self._scope_slots)):
            error = NotesUnknown("The required-note original resources or effects remain unresolved.")
            self.owner.guard._abort(error)
            raise error from primary
        self.closed = True
        if primary is not None:
            raise primary


class _NotesScope:
    # A non-fd sentinel deliberately cannot be passed to os.open/close.
    directory_borrow = object()

    def __init__(self, lease: _NotesLease, number: int) -> None:
        self.lease, self.number = lease, number
        self.owner = self.workspace = None
        self.entered = self.closed = self._enter_claimed = self._close_claimed = False
        self._borrows_closed = False
        self._borrow_count = 0
        self._root: _OriginalObject | None = None
        self._rows: dict[int, _LogicalData] = {}
        self._sources: dict[int, _OriginalObject] = {}
        self._created: dict[int, _OriginalObject] = {}
        self._objects: dict[int, _OriginalObject] = {}
        self._paths: dict[str, int] = {}
        self._moves: tuple[_MoveData, ...] = ()
        self._deletes: tuple[_DeleteData, ...] = ()
        self._security: tuple[_SecurityData, ...] = ()
        self._declared_edges: set[tuple[int, str]] = set()
        self._selection = None
        self._apply_frozen = False
        self._fully_finished_terminal: str | None = None
        self._last_marker: _Key | None = None
        self._recovery_started = self._recovery_joined = False
        self._recovery_join_claimed = False
        self._corrective_attempted = False

    @property
    def bridge(self) -> _Bridge:
        return self.lease.bridge

    def _call(self, operation: Any, *args: Any, **kwargs: Any) -> Any:
        return self.lease._run(operation, *args, **kwargs)

    def _check_binding(self, *, cleanup: bool = False) -> None:
        from .init_workspace_custody import LockedInitScope
        self.lease.check_lease_binding(self.lease.owner)
        if (type(self.owner) is not LockedInitScope or self.owner.notes is not self
                or self.owner.lease is not self.lease.owner
                or not self.entered or self.closed
                or not cleanup and (self._close_claimed or self._borrows_closed)):
            raise NotesRefused("The original required-note scope is not available.")
        if self.workspace is not None and (self.owner.workspace is not self.workspace
                or self.workspace._notes is not self or self.workspace._scope is not self.owner
                or self._root is None or self.workspace.fd is not self._root.key):
            raise NotesUnknown("The original required-note workspace binding changed.")

    def _workspace(self) -> Any:
        self._check_binding()
        if self.workspace is None:
            raise NotesRefused("The original required-note workspace was not bound.")
        return self.workspace

    def _install_factory(self, result: _FactoryResult) -> None:
        _require(result.report.scope == self.number)
        for row in result.logical:
            old = self._rows.get(row.logical_key)
            if old is not None:
                _require((old.role, old.parent_logical_key, old.path, old.name, old.content_limit,
                          old.selected_ancestor_index, old.material_security_key)
                         == (row.role, row.parent_logical_key, row.path, row.name, row.content_limit,
                             row.selected_ancestor_index, row.material_security_key))
            _require(row.path not in self._paths or self._paths[row.path] == row.logical_key)
            self._rows[row.logical_key] = row
            self._paths[row.path] = row.logical_key
            if row.parent_logical_key:
                self._declared_edges.add((row.parent_logical_key, row.name))
        for mapping in result.mappings:
            row = self._rows[mapping.logical_key]
            if self.number != 1:
                captured = self.lease._capture_objects.get(row.logical_key)
                _require(mapping.capture_object_key == (0 if captured is None else captured.value))
            for created, value, state in (
                    (False, mapping.source_object_key, mapping.source_state),
                    (True, mapping.create_object_key, mapping.create_state)):
                if not value:
                    continue
                key = self.bridge._keep(value, "object", scope=self.number,
                                        logical=row.logical_key, object_key=value)
                previous = self._objects.get(value)
                if previous is not None:
                    _require(previous.key is key and previous.created is created
                             and previous.row.logical_key == row.logical_key)
                    previous.row = row
                    continue
                _require(state in (1, 2, 3))  # no already-closed or unknown acquisition is adopted
                label = {1: "declared", 2: "held", 3: "absent"}[state]
                location = (row.parent_logical_key, row.name) if row.parent_logical_key else None
                original = _OriginalObject(key, row, created, label, location)
                bucket = self._created if created else self._sources
                _require(row.logical_key not in bucket)
                if self.number == 1 and not created:
                    self.lease._capture_objects[row.logical_key] = key
                self._objects[value] = original
                (self._created if created else self._sources)[row.logical_key] = original
                if row.role == 1:
                    _require(not created and state == 2 and self._root is None)
                    self._root = original
        if result.moves:
            self._moves, self._deletes, self._security = result.moves, result.deletes, result.security
            for row in result.moves:
                self._declared_edges.update(((row.from_parent_logical_key, row.from_name),
                                              (row.to_parent_logical_key, row.to_name)))
            for row in result.deletes:
                self._declared_edges.update(row.edges)
            # Only missing source parents have a public logical path and a
            # distinct private creation edge. Do not rewrite SourceNoHandle.
            for original in self._created.values():
                if original.row.role == 3:
                    candidates = [move for move in self._moves
                                  if move.kind == 9 and move.object_key == original.key.value]
                    _require(len(candidates) == 1)
                    move = candidates[0]
                    original.location = (move.from_parent_logical_key, move.from_name)
        _require(self._root is not None and self._root.key.value == result.report.root_key
                 and len(self._objects) <= 76 and len(self._rows) <= 38
                 and len(self._declared_edges) <= 154)

    def acquire(self) -> None:
        if self._enter_claimed or self._close_claimed:
            raise NotesRefused("The original required-note scope is one-use.")
        self._enter_claimed = True
        self.lease.check()
        report = self._call(self.bridge.enter_scope, self.number)
        self.entered = True
        self._install_factory(report)
        self._refresh(self._root)
        if self.number == 1:
            self._install_factory(self._call(self.bridge.freeze_fixed, self._root.key))
        self._check_reserved(initial=True)
        meta = self._paths.get(".mobile-release")
        if meta is not None:
            original = self._ensure_source(meta)
            if original.state == "held":
                _, _, rows = self._refresh(original)
                from .build_inputs import _PENDING, _TERMINAL, _TERMINAL_STAGE
                reserved = {_PENDING, _TERMINAL, _TERMINAL_STAGE}
                self._exact_names(rows, reserved)
                if any(row.name in reserved for row in rows):
                    from .init_workspace_custody import _failure
                    raise _failure("pending_state")

    def _exact_names(self, rows: tuple[_RosterEntry, ...], names: set[str]) -> None:
        from .init_transaction import InitConflict, _key
        folded = {_key(name): name for name in names}
        for row in rows:
            expected = folded.get(_key(row.name))
            if expected is not None and row.name != expected:
                raise InitConflict("required-note reserved name has a case or Unicode alias")

    def _check_reserved(self, *, initial: bool) -> tuple[_RosterEntry, ...]:
        from .init_transaction import ALL_STATE_NAMES, METADATA_STATE_NAMES, InitConflict
        _, _, rows = self._refresh(self._root)
        reserved = {".mobile-release", *ALL_STATE_NAMES}
        self._exact_names(rows, reserved)
        found = {row.name for row in rows if row.name in ALL_STATE_NAMES}
        if initial and found:
            from .init_workspace_custody import _failure
            raise _failure("pending_state")
        if len(found) > 1 or not found <= set(METADATA_STATE_NAMES):
            raise InitConflict("another original transaction state must be preserved")
        if found:
            journal = self._role(9, created=True, required=False)
            expected = None if journal is None else journal.location
            if journal is None or journal.state != "held" or expected != (self._root.row.logical_key, next(iter(found))):
                raise InitConflict("the required-note journal is not this original creation")
        return rows

    def _role(self, role: int, *, created: bool = False, required: bool = True) -> _OriginalObject | None:
        values = [value for value in (self._created if created else self._sources).values()
                  if value.row.role == role]
        if len(values) == 1:
            return values[0]
        if required or values:
            raise NotesRefused("The original required-note role is missing or ambiguous.")
        return None

    def _native_object(self, key: _Key, *, directory: bool | None = None) -> _OriginalObject:
        value = self._objects.get(self.bridge._key(key, "object", scope=self.number))
        if value is None or value.key is not key or value.state != "held":
            raise NotesRefused("The required-note borrow has no live original object.")
        if directory is not None and bool(value.row.flags & 1) is not directory:
            raise NotesRefused("The required-note borrow has the wrong object kind.")
        return value

    def _parent_original(self, logical: int) -> _OriginalObject:
        for bucket in (self._sources, self._created):
            value = bucket.get(logical)
            if value is not None and value.state == "held" and value.row.flags & 1:
                return value
        value = self._ensure_source(logical)
        if value.state != "held" or not value.row.flags & 1:
            raise NotesRefused("The required-note original parent has no live directory.")
        return value

    def _raw_pass(self, original: _OriginalObject, *, collect: bool = False
                  ) -> tuple[_Pass, bytes | None, tuple[_RosterEntry, ...]]:
        if original.state != "held":
            raise NotesRefused("The required-note original object is not acquired.")
        directory = bool(original.row.flags & 1)
        stream = self._call(self.bridge.begin_pass, original.key, directory=directory)
        body = bytearray() if collect and not directory else None
        rows: list[_RosterEntry] = []
        while not stream.complete:
            page = self._call(self.bridge.next_roster if directory else self.bridge.next_read, stream)
            if page is None:
                break
            if directory:
                rows.extend(page)
                _require(len(rows) <= 128)
            else:
                _require(stream.total <= original.row.content_limit)
                if body is not None:
                    body.extend(page)
        _require(stream.complete)
        if directory:
            _require(len(rows) == stream.total and len({row.name for row in rows}) == len(rows))
        return stream, None if body is None else bytes(body), tuple(rows)

    def _refresh(self, original: _OriginalObject | None, *, collect: bool = False
                 ) -> tuple[_NativeObservation, bytes | None, tuple[_RosterEntry, ...]]:
        if original is None:
            raise NotesRefused("The required-note original is unavailable.")
        stream, body, rows = self._raw_pass(original, collect=collect)
        if original.acknowledged is not None:
            observed = self._call(self.bridge.observe, original.key, stream, accepted=original.acknowledged)
        elif original.created:
            if original.pending is None:
                raise NotesUnknown("The original created object has no known pending epoch.")
            source = self._call(self.bridge.observe, original.key, stream)
            _require(source.data.original_capture == 0 and not source.data.flags & 128)
            observed = self._call(self.bridge.observe, original.key, stream, accepted=original.pending)
        elif self.number == 1:
            observed = self._call(self.bridge.observe, original.key, stream)
            _require(original.row.logical_key not in self.lease._capture)
            self.lease._capture[original.row.logical_key] = observed
        else:
            captured = self.lease._capture.get(original.row.logical_key)
            if captured is None:
                raise NotesUnknown("The required-note source has no original Capture observation.")
            observed = self._call(self.bridge.observe, original.key, stream, baseline=captured)
        self._accept_epochs((observed,))
        if body is not None:
            import hashlib
            _require(observed.data.size == len(body)
                     and observed.data.content_sha256 == hashlib.sha256(body).digest())
        return observed, body, rows

    def _ensure_source(self, logical: int) -> _OriginalObject:
        value = self._sources.get(logical)
        if value is None:
            raise NotesRefused("The required-note source is outside the frozen inventory.")
        if value.state in ("held", "absent"):
            return value
        if value.state != "declared":
            raise NotesUnknown("The required-note original source cannot be reacquired.")
        parent = self._ensure_source(value.row.parent_logical_key)
        if parent.state == "held":
            stream, _, _ = self._raw_pass(parent)
            # A complete current parent proof precedes the original child edge.
            observed = self._call(self.bridge.observe, parent.key, stream,
                                  accepted=parent.acknowledged) if parent.acknowledged is not None else None
            if observed is not None:
                self._accept_epochs((observed,))
            proof = self._call(self.bridge.presence, value.key, stream)
        else:
            if parent.absence is None:
                raise NotesUnknown("The absent original parent has no retained absence proof.")
            proof = self._call(self.bridge.presence, value.key, parent.absence)
        if not proof.present:
            value.state, value.location, value.absence = "absent", None, proof
            return value
        # Mark before entry so a lost acquire cannot cause an original retry.
        value.state = "acquiring"
        self._call(self.bridge.acquire_object, value.key, proof)
        value.state = "held"
        self._refresh(value)
        return value

    def root_borrow(self) -> _Key:
        self._check_binding()
        if self._root is None or self._root.state != "held":
            raise NotesUnknown("The original required-note root is not held.")
        return self._root.key

    def root_material(self) -> dict[str, Any]:
        self._check_binding()
        if self._root is None or self._root.acknowledged is None:
            raise NotesUnknown("The original required-note root has no complete material.")
        return self._root.acknowledged.material()

    def bind_workspace(self, workspace: Any) -> None:
        from .init_transaction import InitWorkspace
        if type(workspace) is not InitWorkspace or self.workspace is not None or self.owner.workspace is not workspace:
            raise NotesRefused("The required-note scope may bind only its original workspace.")
        self.workspace = workspace
        self._check_binding()

    def check(self) -> None:
        self._check_binding()
        self._refresh(self._root)
        meta = self._paths.get(".mobile-release")
        if meta is not None:
            value = self._sources.get(meta)
            if value is not None and value.state == "held":
                self._refresh(value)

    def state(self) -> str | None:
        self._workspace()
        self.lease.check()
        from .init_transaction import ALL_STATE_NAMES
        meta = self._paths.get(".mobile-release")
        if meta is not None and self._sources[meta].state == "held":
            self._refresh(self._sources[meta])
        rows = self._check_reserved(initial=False)
        found = [row.name for row in rows if row.name in ALL_STATE_NAMES]
        return found[0] if found else None

    def freeze_version(self, path: str | None) -> None:
        self._workspace()
        config = self._role(4)
        if config.acknowledged is None:
            raise NotesRefused("Version selection needs the original captured configuration.")
        self._install_factory(self._call(self.bridge.freeze_version, self._root.key,
                                         self.lease._capture[config.row.logical_key].key, path))

    def freeze_selected(self, selection: Any) -> None:
        from .required_notes import RequiredNotesSelection
        if type(selection) is not RequiredNotesSelection or self._selection is not None:
            raise NotesRefused("The required-note selection must be the original core selection.")
        self._workspace()
        kinds = {"android-build": 1, "android-default": 2, "ios-beta-review": 3,
                 "ios-app-review": 4, "testflight-what-to-test": 5}
        config, version = self._role(4), self._role(6, required=False)
        if config.acknowledged is None or version is not None and version.acknowledged is None:
            raise NotesRefused("The selected note has incomplete original dependencies.")
        self._install_factory(self._call(
            self.bridge.freeze_selected, self._root.key, self.lease._capture[config.row.logical_key].key,
            None if version is None else self.lease._capture[version.row.logical_key].key,
            kind=kinds[selection.context.kind], selected=selection.path,
            counterpart=selection.counterpart_path))
        self._selection = selection

    def freeze_apply(self, changes: Any) -> None:
        from .init_transaction import ObservedFile
        self._workspace()
        if self.number != 3 or self._apply_frozen or type(changes) is not list or len(changes) != 1:
            raise NotesRefused("Required-note Apply is one original selected change.")
        item, payload = changes[0]
        if type(item) is not ObservedFile:
            raise NotesRefused("Required-note Apply lost its original observation.")
        selected = self._role(7)
        if selected.row.path != item.path:
            raise NotesRefused("Required-note Apply cannot retarget the frozen note.")
        if selected.state == "held" and selected.acknowledged is not None:
            token = selected.acknowledged.key
        elif selected.state == "absent" and selected.absence is not None:
            token = selected.absence.key
        else:
            raise NotesUnknown("The selected required-note source was not fully observed.")
        import hashlib
        action = 0 if payload is None else 1 if item.before is None else 2
        report = self._call(self.bridge.freeze_apply, self._root.key, token, action=action,
                            byte_length=0 if payload is None else len(payload),
                            sha256=b"" if payload is None else hashlib.sha256(payload).digest())
        self._install_factory(report)
        self._apply_frozen = True
        self._selection = self.lease.owner._metadata_targets.selection

    def record_core_failure(self, error: BaseException) -> None:
        self.lease.record_core_failure(error)

    def settle_workspace_borrows(self) -> None:
        if self._borrows_closed:
            return
        self._check_binding(cleanup=True)
        if self._borrow_count:
            raise NotesUnknown("The original required-note logical borrow did not return.")
        self._borrows_closed = True

    def close(self) -> None:
        self.lease.check_lease_binding(self.lease.owner)
        if self._close_claimed:
            if not self.closed:
                raise NotesUnknown("The original required-note scope settlement is unresolved.")
            return
        self._close_claimed = True
        if self._borrow_count:
            raise NotesUnknown("The original required-note scope still has a logical borrower.")
        if self.entered:
            self._call(self.bridge.scope_status, self.number, settle=True)
        self.closed = True


    def _lookup(self, parent: _OriginalObject, name: str) -> _OriginalObject | None:
        from .init_transaction import InitConflict
        if type(name) is not str or "/" in name or (parent.row.logical_key, name) not in self._declared_edges:
            raise NotesRefused("The required-note edge is outside the frozen original graph.")
        _, _, rows = self._refresh(parent)
        self._exact_names(rows, {name})
        entries = [row for row in rows if row.name == name]
        candidates = [value for value in self._objects.values()
                      if value.state == "held" and value.location == (parent.row.logical_key, name)]
        _require(len(candidates) <= 1 and len(entries) <= 1)
        if not candidates:
            declared = [value for value in self._sources.values()
                        if value.state == "declared"
                        and (value.row.parent_logical_key, value.row.name) == (parent.row.logical_key, name)]
            _require(len(declared) <= 1)
            if declared:
                value = self._ensure_source(declared[0].row.logical_key)
                if value.state == "held":
                    return value
            if entries:
                raise InitConflict("a required-note edge contains an unrelated object")
            return None
        value = candidates[0]
        if not entries:
            raise InitConflict("an original required-note object disappeared")
        if value.acknowledged is not None and entries[0].file_id != value.acknowledged.data.file_id:
            raise InitConflict("an original required-note namespace binding changed")
        return value

    def name_present(self, parent: _Key, name: str) -> bool:
        self._workspace()
        original = self._native_object(parent, directory=True)
        _, _, rows = self._refresh(original)
        self._exact_names(rows, {name})
        return any(row.name == name for row in rows)

    def roster(self, parent: _Key) -> list[str]:
        self._workspace()
        _, _, rows = self._refresh(self._native_object(parent, directory=True))
        return [row.name for row in rows]

    def read(self, parent: _Key, name: str, limit: int) -> tuple[dict[str, Any], bytes] | None:
        workspace = self._workspace()
        if type(limit) is not int or limit < 0:
            raise NotesRefused("The required-note read bound is invalid.")
        original = self._lookup(self._native_object(parent, directory=True), name)
        workspace._last_read_facts = None
        if original is None:
            return None
        if original.row.flags & 1:
            from .init_transaction import InitConflict
            raise InitConflict("the selected required-note file became a directory")
        observed, body, _ = self._refresh(original, collect=True)
        _require(type(body) is bytes and len(body) <= min(limit, original.row.content_limit))
        workspace._last_read_facts = observed.data.source_facts()
        return observed.material(limit=limit), body

    def binding(self, parent: _Key, name: str, *, directory: bool, limit: int) -> dict[str, Any] | None:
        workspace = self._workspace()
        original = self._lookup(self._native_object(parent, directory=True), name)
        workspace._last_read_facts = None
        if original is None:
            return None
        if bool(original.row.flags & 1) is not directory:
            from .init_transaction import InitConflict
            raise InitConflict("the original required-note object kind changed")
        observed, _, _ = self._refresh(original)
        workspace._last_read_facts = observed.data.source_facts()
        return observed.material(limit=None if directory else limit)

    @contextmanager
    def parent(self, path: str, *, planning: bool = False):
        workspace = self._workspace()
        from .init_transaction import InitConflict
        raw = _input_path(path)
        del raw
        current: _OriginalObject | None = self._root
        parts = path.split("/")[:-1]
        for index in range(len(parts)):
            relative = "/".join(parts[:index + 1])
            logical = self._paths.get(relative)
            if logical is None or not self._rows[logical].flags & 1:
                raise NotesRefused("The required-note parent is outside the original inventory.")
            if current is None:
                absent = self._ensure_source(logical)
                if absent.state != "absent":
                    raise InitConflict("an originally absent required-note parent appeared")
                value = None
            else:
                value = self._lookup(current, parts[index])
                if value is not None and not value.row.flags & 1:
                    raise InitConflict("a required-note ancestor became a non-directory")
            identity = None
            facts = None
            if value is not None:
                observed, _, _ = self._refresh(value)
                identity, facts = observed.material(), observed.data.source_facts()
            if planning and relative not in workspace.parents:
                workspace.parents[relative] = identity
            if relative not in workspace.parents:
                raise NotesRefused("The required-note parent was not admitted by the original revision.")
            if workspace.parents[relative] != identity:
                raise InitConflict("the original required-note parent identity changed")
            workspace._parent_facts[relative] = facts
            current = value
        if current is None:
            # Common observe/read skips a missing parent. Complete the exact
            # source leaf's ORIGINAL absence chain before exposing that None;
            # otherwise a declared leaf has no14 receipt for Apply18.
            logical = self._paths.get(path)
            original = self._sources.get(logical)
            absent_parent = self._sources.get(self._paths.get("/".join(parts)))
            if (original is None or original.created or original.row.path != path
                    or absent_parent is None or absent_parent.state != "absent"
                    or original.row.parent_logical_key != absent_parent.row.logical_key):
                raise NotesRefused("The absent required-note edge has no original source parent.")
            if original.state not in ("declared", "absent"):
                raise InitConflict("the original required-note child differs from its absent parent")
            parent_proof = absent_parent.absence
            _require(type(parent_proof) is _NativePresence
                     and parent_proof.object is absent_parent.key and not parent_proof.present)
            parent_absence = self.bridge._key(parent_proof.key, "presence", scope=self.number)
            original = self._ensure_source(logical)
            proof = original.absence
            _require(original.state == "absent" and type(proof) is _NativePresence
                     and proof.object is original.key and not proof.present
                     and proof.data.proof == 2
                     and proof.data.parent_object_key == absent_parent.key.value
                     and proof.data.original_parent_absent_key == parent_absence)
            self.bridge._key(proof.key, "presence", scope=self.number)
        self._borrow_count += 1
        try:
            yield None if current is None else current.key
        finally:
            self._borrow_count -= 1

    @contextmanager
    def borrow_directory(self, parent: _Key, name: str):
        self._workspace()
        original = self._lookup(self._native_object(parent, directory=True), name)
        if original is None or not original.row.flags & 1:
            raise NotesRefused("The original required-note directory is absent.")
        self._refresh(original)
        self._borrow_count += 1
        try:
            yield original.key
        finally:
            self._borrow_count -= 1

    @contextmanager
    def private(self, name: str):
        self._workspace()
        from .init_transaction import METADATA_STATE_NAMES
        if name not in METADATA_STATE_NAMES:
            raise NotesRefused("The required-note private borrow cannot cross domains.")
        original = self._role(9, created=True)
        if original.state != "held" or original.location != (self._root.row.logical_key, name):
            raise NotesRefused("The required-note journal is not the original private creation.")
        self.private_check(original.key, name)
        self._borrow_count += 1
        try:
            yield original.key
        finally:
            # A verified final deletion can retire this same journal while its
            # logical borrow is still in scope. No OS HANDLE is reopened here.
            self._borrow_count -= 1

    def private_check(self, key: _Key, name: str) -> None:
        workspace = self._workspace()
        original = self._native_object(key, directory=True)
        if original is not self._role(9, created=True) or original.location != (self._root.row.logical_key, name):
            raise NotesRefused("The required-note journal changed its original location.")
        observed, _, _ = self._refresh(original)
        if (observed.material() != workspace.private_identity
                or not observed.data.flags & 16):
            from .init_transaction import InitConflict
            raise InitConflict("the original private required-note journal changed")

    def current(self, path: str, *, directory: bool) -> dict[str, Any] | None:
        with self.parent(path) as parent:
            if parent is None:
                return None
            return self.binding(parent, path.rsplit("/", 1)[-1], directory=directory, limit=1_048_576)

    def check_dependency_parent(self, path: str, facts: Any, transitions: tuple[str, ...],
                                created: dict[str, Any]) -> None:
        workspace = self._workspace()
        from .init_transaction import InitConflict
        logical = self._paths.get(path)
        if logical is None:
            raise NotesRefused("The required-note dependency parent is not original.")
        original = self._sources.get(logical)
        if original is None:
            raise NotesRefused("The required-note dependency parent has no source original.")
        if facts is not None:
            baseline = self.lease._capture.get(logical)
            if baseline is None or baseline.data.source_facts() != facts or original.state != "held":
                raise InitConflict("the required-note dependency baseline changed")
            # Native16 proves original full facts OR an exact known own effect
            # from that same original's last emitted acknowledgement. It does
            # not rewrite Capture facts when a sibling namespace changes.
            self._refresh(original)
            return
        if original.state != "absent":
            raise InitConflict("an original absent dependency parent changed")
        replacement = self._created.get(logical)
        if replacement is not None and replacement.state == "held" and replacement.location == (
                original.row.parent_logical_key, original.row.name):
            if (path not in transitions or replacement.created_facts is None
                    or created.get(path) != replacement.created_facts
                    or workspace.parents.get(path) is None):
                raise InitConflict("the dependency parent is not its original staged directory")
            observed, _, _ = self._refresh(replacement)
            if observed.material() != workspace.parents[path]:
                raise InitConflict("the original staged dependency parent changed")
        else:
            if workspace.parents.get(path) is not None or self.current(path, directory=True) is not None:
                raise InitConflict("an original absent dependency parent appeared")

    def _creation_original(self, parent: _OriginalObject, name: str, *, directory: bool) -> _OriginalObject:
        values = [value for value in self._created.values()
                  if value.location == (parent.row.logical_key, name)]
        if len(values) != 1 or values[0].state != "declared" or bool(values[0].row.flags & 1) is not directory:
            raise NotesRefused("The required-note creation is not its frozen original slot.")
        return values[0]

    def _create(self, original: _OriginalObject) -> None:
        from .init_transaction import InitConflict
        if not self._apply_frozen or original.location is None or original.state != "declared":
            raise NotesRefused("The original required-note creation is not available.")
        parent = self._parent_original(original.location[0])
        self._refresh(parent)
        stream = self.bridge._passes[parent.key.value]
        proof = self._call(self.bridge.presence, original.key, stream)
        if proof.present:
            raise InitConflict("the original exclusive required-note destination appeared")
        journal = original.row.role == 9
        if journal:
            self.workspace._creation["state"] = "IN_FLIGHT"
        original.state = "creating"
        try:
            result = self._call(self.bridge.create, original.key, proof)
        except BaseException:
            # A failed/lost create is never retried or pathname-adopted.
            result = self.bridge._last_effect
            if journal and result is not None and result.kind == 1 and result.object_key == original.key.value and result.flags & 4:
                self.workspace._creation["state"] = "NO_EFFECT"
            raise
        original.state, original.pending = "held", result.key
        if journal:
            self.workspace._creation["state"] = "CREATED"

    def mkdir(self, parent: _Key, name: str, mode: int) -> None:
        workspace = self._workspace()
        if type(mode) is not int or mode not in (0o700, 0o755):
            raise NotesRefused("The required-note directory purpose is invalid.")
        original = self._creation_original(self._native_object(parent, directory=True), name, directory=True)
        if (original.row.role == 3) != (mode == 0o755):
            raise NotesRefused("The required-note directory mode cannot choose a security policy.")
        self._create(original)
        self._call(self.bridge.fence, original.key)
        observed, _, _ = self._refresh(original)
        original.created_facts = observed.data.source_facts()
        if original.row.role == 9:
            workspace.private_identity = observed.material()
            workspace._private_facts = original.created_facts

    def write(self, parent: _Key, name: str, body: bytes) -> None:
        self._workspace()
        original = self._creation_original(self._native_object(parent, directory=True), name, directory=False)
        if type(body) is not bytes or not 0 < len(body) <= original.row.content_limit:
            raise NotesRefused("The required-note content exceeds the original selected bound.")
        if original.row.role in (10, 11, 12, 13):
            self._call(self.bridge.bind_control, original.key, body)
        elif original.row.role != 16:
            raise NotesRefused("Only original controls or the selected new note are writable.")
        self._create(original)
        original.pending = None
        offset = 0
        while offset < len(body):
            effect = self._call(self.bridge.write, original.key, body[offset:offset + 65_536])
            offset += effect.information  # positive actual partial writes, never requested count
        original.pending = self._call(self.bridge.finish_write, original.key)
        self._call(self.bridge.fence, original.key)
        observed, _, _ = self._refresh(original)
        original.created_facts = observed.data.source_facts()

    def full_fence(self, key: _Key) -> None:
        self._workspace()
        self._call(self.bridge.fence, self._native_object(key).key)

    def created_parent_facts(self, parent: _Key, name: str, expected: Any) -> tuple[tuple[str, int | str], ...]:
        self._workspace()
        original = self._lookup(self._native_object(parent, directory=True), name)
        if (original is None or not original.created or original.row.role != 3
                or original.acknowledged is None or original.created_facts is None
                or original.acknowledged.material() != expected):
            raise NotesRefused("The dependency transition has no original staged directory.")
        return original.created_facts

    def _move_key(self, row: _MoveData) -> _Key:
        return self.bridge._keep(row.move_key, "move", scope=3, logical=row.logical_key, object_key=row.object_key)

    def _security_key(self, row: _SecurityData) -> _Key:
        return self.bridge._keep(row.action_key, "security", scope=3, logical=row.logical_key, object_key=row.object_key)

    def _post_passes(self, values: tuple[_OriginalObject, ...]) -> dict[int, _Pass]:
        streams = {}
        for value in values:
            if value.key.value not in streams:
                streams[value.key.value] = self._raw_pass(value)[0]
        return streams

    def _accept_epochs(self, values: tuple[_NativeObservation, ...]) -> None:
        # Only admitted full native DATA may change a current edge. Intended
        # paths, scalar reply epochs and an entered/returned move alone cannot.
        updates = []
        for value in values:
            original = self._objects.get(value.object.value)
            _require(original is not None and original.key is value.object and original.state == "held"
                     and value.data.object_key == original.key.value
                     and value.data.logical_key == original.row.logical_key)
            location = original.location
            if value.data.tag == 2:
                if value.data.parent_object_key:
                    parent = self._objects.get(value.data.parent_object_key)
                    _require(parent is not None and parent.state == "held" and parent.row.flags & 1)
                    location = (parent.row.logical_key, value.data.name)
                    _require(location in self._declared_edges)
                else:
                    _require(original is self._root and not value.data.name)
                    location = None
            updates.append((original, value, location))
        for original, value, location in updates:
            original.acknowledged, original.location = value, location

    def _security_transition(self, action: int, *, publish: bool,
                             parent: _OriginalObject | None = None) -> None:
        candidates = [row for row in self._security if row.action_key == action]
        _require(len(candidates) == 1 and candidates[0].purpose == (1 if publish else 2))
        row = candidates[0]
        original = self._objects[row.object_key]
        if parent is None:
            if original.location is None:
                raise NotesUnknown("The original security transition has no current edge.")
            parent = self._parent_original(original.location[0])
        _require(self._objects.get(parent.key.value) is parent
                 and parent.state == original.state == "held" and parent.row.flags & 1)
        key = self._security_key(row)
        # _Bridge retains the ACTUAL PRIMARY28/29 return even if the following
        # readback/POST fails. No attempted Python call is a setter receipt.
        self._call(self.bridge.security, key, publish=publish)
        streams = self._post_passes((original, parent))
        observations = self._call(self.bridge.finish_security, key, publish=publish,
                                  object_pass=streams[original.key.value], parent=streams[parent.key.value],
                                  originals=(original.key, parent.key))
        self._accept_epochs(observations)
        _require(original.acknowledged.data.flags & (16 | 32 | 64) == (32 if publish else 16))

    def _prove_private_before_inverse(self, original: _OriginalObject,
                                      parent: _OriginalObject, name: str) -> None:
        if original.acknowledged is None:
            raise NotesRefused("The original private object has no retained full material anchor.")
        stream = self._raw_pass(original)[0]
        observed = self._call(self.bridge.observe, original.key, stream,
                              accepted=original.acknowledged)
        _require(observed.data.tag == 2 and observed.data.flags & (16 | 32 | 64) == 16
                 and observed.data.parent_object_key == parent.key.value
                 and observed.data.name == name)
        self._accept_epochs((observed,))

    def _restore_before_inverse(self, row: _MoveData, original: _OriginalObject,
                                parent: _OriginalObject) -> None:
        if not row.restore_action_key:
            return
        actions = [value for value in self._security if value.action_key == row.restore_action_key]
        _require(len(actions) == 1 and actions[0].purpose == 2
                 and actions[0].object_key == original.key.value
                 and actions[0].logical_key == original.row.logical_key)
        restore = actions[0]
        paired = [value for value in self._security if value.action_key == restore.paired_action_key]
        _require(len(paired) == 1 and paired[0].purpose == 1
                 and paired[0].paired_action_key == restore.action_key
                 and paired[0].object_key == original.key.value
                 and paired[0].logical_key == original.row.logical_key)
        effect = self.bridge._security_effects.get(paired[0].action_key)
        if effect is not None:
            _require(effect.kind == 5 and effect.object_key == original.key.value
                     and effect.operation_key == paired[0].action_key and effect.flags & 3 == 3)
        if effect is None or effect.flags & 4:
            #28 never entered (or actually proved no effect): do NOT invent29
            # success. The complete original pass16 proves PRIVATE first.
            self._prove_private_before_inverse(original, parent, row.from_name)
            return
        if effect.return_kind != 2 or effect.return_bits == 0 or effect.flags & 8:
            raise NotesRefused("The original publish setter has no known reversible result.")
        # Actual known-published28, including a failed subsequent30, requires
        # real29 -> complete readback ->30 BEFORE the inverse native move.
        self._security_transition(restore.action_key, publish=False, parent=parent)

    def _correct_original_move(self, forward: _MoveData, original: _OriginalObject,
                               source: _OriginalObject, destination: _OriginalObject, *,
                               directory_path: str | None) -> None:
        inverses = [row for row in self._moves if row.move_key == forward.inverse_move_key]
        _require(len(inverses) == 1)
        inverse = inverses[0]
        originals = tuple({value.key.value: value.key for value in (original, source, destination)}.values())
        key = self._move_key(inverse)
        # This chooses exactly ONE preowned pair, never a new transaction.
        # Its reads/effects/POST may settle after STOP only inside the original
        # frozen filesystem endpoint; unknown or lost frames never gain entry.
        self._call(self.bridge.begin_compensation, self._move_key(forward), key, originals=originals)
        self._restore_before_inverse(inverse, original, destination)
        self._refresh(source)  # actual original inverse destination roster
        effect = self._call(self.bridge.move, key, self.bridge._passes[source.key.value])
        _require(not effect.flags & 8)
        streams = self._post_passes((original, destination, source))
        observations = self._call(self.bridge.finish_move, key, streams[original.key.value],
                                  streams[destination.key.value], streams[source.key.value], originals)
        self._accept_epochs(observations)
        _require(original.location == (source.row.logical_key, forward.from_name))
        if directory_path is not None:
            _require(forward.kind == 9 and original.row.path == directory_path)
            self.workspace.parents[directory_path] = None
        # Do not synthesize37 here. The existing common lifecycle either enters
        # its one36Fixed continuation or preserves this journal on InitConflict.

    def _try_corrective(self, forward: _MoveData, original: _OriginalObject,
                        source: _OriginalObject, destination: _OriginalObject,
                        primary: BaseException, *, directory_path: str | None) -> None:
        if (not forward.inverse_move_key or forward.forward_move_key or forward.kind in (3, 15, 16)
                or self._corrective_attempted or self._recovery_started
                or self.bridge._recovery_mode != "none"):
            return
        # Latch the SAME initial error before recovery admission, not after an
        # inverse cleanup error. Unknown/malformed/lost state never enters36.
        self.workspace._notes_failure(primary)
        if (self.bridge._unknown or self.bridge._wire_lost or self.bridge._pending is not None
                or self.bridge._finality_pending is not None or self.bridge._terminal_bits):
            return
        self._corrective_attempted = True
        try:
            self._correct_original_move(forward, original, source, destination,
                                        directory_path=directory_path)
        except BaseException as cleanup_error:
            self.workspace._notes_cleanup_errors.append(cleanup_error)
            self.workspace._notes_failure(cleanup_error)
        # Caller rethrows the SAME initial exception; success of an inverse is
        # not Save, successful rollback, Joined, or permission for another pair.

    def _perform_move(self, source: _OriginalObject, source_name: str,
                      destination: _OriginalObject, destination_name: str,
                      expected: dict[str, Any] | None, *, directory: bool | None,
                      directory_path: str | None = None) -> None:
        workspace = self._workspace()
        from .init_transaction import InitConflict
        rows = [row for row in self._moves
                if (row.from_parent_logical_key, row.from_name, row.to_parent_logical_key, row.to_name)
                == (source.row.logical_key, source_name, destination.row.logical_key, destination_name)]
        if len(rows) != 1:
            raise NotesRefused("The required-note move is not its original frozen edge pair.")
        row = rows[0]
        original = self._objects.get(row.object_key)
        if (original is None or original.state != "held"
                or original.location != (source.row.logical_key, source_name)
                or directory is not None and bool(original.row.flags & 1) is not directory):
            raise NotesRefused("The required-note move lost its original object.")
        if directory_path is not None and (row.kind not in (9, 10) or original.row.path != directory_path):
            raise NotesRefused("The required-note directory handoff has no original path.")
        workspace._namespace_check()
        observed, _, _ = self._refresh(original)
        if expected is not None and observed.material() != expected:
            raise InitConflict("the original required-note move material changed")
        if row.kind in (11, 12):
            _require(row.restore_action_key == row.publish_action_key == 0)
        self._restore_before_inverse(row, original, source)
        self._refresh(destination)
        destination_stream = self.bridge._passes[destination.key.value]
        key = self._move_key(row)
        if workspace._installing:
            workspace._install_started = True
        if row.kind in (15, 16):
            state = "COMMITTED" if row.kind == 15 else "ROLLED_BACK"
            if workspace._publishing_terminal != state:
                raise NotesRefused("The terminal marker is not this original core decision.")
            workspace._terminal_ambiguous = True  # BEFORE original native effect entry
        # Only an actual fully decoded successful26 can authorize the known
        # corrective-pair branch below. Failed/lost26 is never salvaged here.
        effect = self._call(self.bridge.move, key, destination_stream)
        try:
            streams = self._post_passes((original, source, destination))
            originals = tuple({value.key.value: value.key for value in (original, source, destination)}.values())
            observations = self._call(
                self.bridge.finish_move, key, streams[original.key.value],
                streams[source.key.value], streams[destination.key.value], originals)
            self._accept_epochs(observations)
            if effect.flags & 8:
                _require(row.kind == 3)
                # Candidate26 does NOT become FileExistsError until actual27.
                raise FileExistsError("the original exclusive required-note probe was verified")
            _require(original.location == (destination.row.logical_key, destination_name))
            if row.kind in (15, 16):
                self._fully_finished_terminal = "COMMITTED" if row.kind == 15 else "ROLLED_BACK"
                self._last_marker = key
                self.retain_workspace_facts()
            if row.publish_action_key:
                self._security_transition(row.publish_action_key, publish=True, parent=destination)
            if directory_path is not None:
                workspace.parents[directory_path] = original.acknowledged.material() if row.kind == 9 else None
            workspace._namespace_check(changing=directory_path)
        except BaseException as error:
            if not effect.flags & 8:
                self._try_corrective(row, original, source, destination, error,
                                     directory_path=directory_path)
            raise

    def control_move(self, source: _Key, source_name: str, destination: _Key, destination_name: str) -> None:
        self._perform_move(self._native_object(source, directory=True), source_name,
                           self._native_object(destination, directory=True), destination_name,
                           None, directory=None)

    def move_owned(self, source: _Key, source_name: str, destination: _Key, destination_name: str,
                   expected: dict[str, Any], *, directory: bool, directory_path: str | None) -> None:
        self._perform_move(self._native_object(source, directory=True), source_name,
                           self._native_object(destination, directory=True), destination_name,
                           expected, directory=directory, directory_path=directory_path)

    def state_move_owned(self, old: str, new: str) -> None:
        workspace = self._workspace()
        from .init_transaction import METADATA_STATE_NAMES, InitConflict
        if old not in METADATA_STATE_NAMES or new not in METADATA_STATE_NAMES or self.state() != old:
            raise InitConflict("the original required-note journal state changed")
        self._perform_move(self._root, old, self._root, new, workspace.private_identity, directory=True)

    def cleanup_entry(self, parent: _Key, name: str) -> tuple[bool, dict[str, Any]]:
        self._workspace()
        original = self._lookup(self._native_object(parent, directory=True), name)
        if original is None:
            raise NotesRefused("An original required-note cleanup entry disappeared.")
        observed, _, _ = self._refresh(original)
        return bool(original.row.flags & 1), observed.material()

    def delete(self, parent: _Key, name: str, *, directory: bool) -> None:
        workspace = self._workspace()
        parent_original = self._native_object(parent, directory=True)
        original = self._lookup(parent_original, name)
        if original is None or bool(original.row.flags & 1) is not directory:
            raise NotesRefused("The required-note deletion is not the original expected kind.")
        rows = [row for row in self._deletes if row.object_key == original.key.value
                and (parent_original.row.logical_key, name) in row.edges]
        if len(rows) != 1:
            raise NotesRefused("The required-note deletion is outside the frozen cleanup graph.")
        row = rows[0]
        key = self.bridge._keep(row.delete_key, "delete", scope=3, logical=row.logical_key,
                                object_key=row.object_key)
        observed, _, _ = self._refresh(original)
        del observed
        empty = self.bridge._passes[original.key.value] if directory else None
        self._call(self.bridge.delete, key, empty)
        self._call(self.bridge.close_deleted, key)
        original.state = "closed"
        stream = self._raw_pass(parent_original)[0]
        self._call(self.bridge.finish_delete, key, stream)
        original.location = None
        if original.row.role == 9:
            # Full original33 proves actual disappearance and parent POST. This
            # fact survives a later ordinary callback or redundant core fence.
            workspace._journal_clean = True

    def retain_workspace_facts(self) -> None:
        if self.workspace is None:
            return
        workspace, bridge = self.workspace, self.bridge
        if bridge._terminal_bits & 1024:
            workspace._terminal_seen = "COMMITTED"
        elif bridge._terminal_bits & 4096:
            workspace._terminal_seen = "ROLLED_BACK"
        if self._fully_finished_terminal is not None:
            _require(workspace._terminal_seen == self._fully_finished_terminal)
            workspace._terminal_ambiguous = False
            workspace._terminal_durable = True
        if bridge._unknown or bridge._wire_lost or bridge._pending is not None or bridge._finality_pending is not None:
            if workspace._reason == "none":
                workspace._reason = "custody_unknown"
            self.lease.owner.guard._abort(NotesUnknown("the original required-note custody remains unresolved"))

    def begin_fixed_recovery(self) -> None:
        self._workspace()
        if self._recovery_started:
            raise NotesRefused("The required-note fixed recovery is one-use.")
        self._recovery_started = True
        self.retain_workspace_facts()
        if self.bridge._terminal_bits & 1024:
            if self._last_marker is None or self._fully_finished_terminal != "COMMITTED":
                raise NotesUnknown("The original COMMITTED marker has no complete cleanup proof.")
            self._call(self.bridge.begin_committed_cleanup, self._last_marker)
        else:
            self._call(self.bridge.begin_compensation)

    def finish_fixed_recovery(self) -> None:
        if not self._recovery_started or self._recovery_join_claimed:
            raise NotesRefused("The required-note fixed recovery join is one-use.")
        self._recovery_join_claimed = True
        self._call(self.bridge.join_compensation)
        self._recovery_joined = True


def _prepare_original_notes_lease(lease: Any, original_input: Any,
                                  registration: object) -> _NotesLease:
    from ._desktop_edit_control import EditInput
    from ._desktop_edit_protocol import NOTES_PROTOCOL
    from ._desktop_image_writer_windows import _original_notes_native_binding
    from .init_workspace_custody import InitRootLease, _LeasePurpose
    from .init_transaction import TypedEditProfile
    if (type(lease) is not InitRootLease or lease._purpose is not _LeasePurpose.REQUIRED_NOTES
            or lease.profile is not TypedEditProfile.METADATA_TEXT
            or type(original_input) is not EditInput or original_input.guard is not lease.guard
            or original_input.protocol != NOTES_PROTOCOL):
        raise NotesRefused("The original required-note input and lease do not match.")
    admitted = registered_root(registration)
    c, dll = _original_notes_native_binding(original_input, lease.guard)
    return _NotesLease(lease, original_input, admitted, c, dll)
