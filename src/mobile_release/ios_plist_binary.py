"""Bounded original binary-plist validation before public stdlib conversion.

This is intentionally a supported subset, not a permissive native plist reader.
Do not normalize ambiguous encodings into a different value or inspect only the
reachable root: every indexed object must satisfy the original-format contract.
"""
from __future__ import annotations

import math
import struct
from datetime import datetime, timedelta

from .errors import ValidationError
from .inspection import InspectionDeadline


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _extent(position: int, size: int, end: int) -> int:
    _require(size >= 0 and position <= end and size <= end - position,
             "iOS binary plist object content exceeds its original span")
    return position + size


def _padding(data: bytes, start: int, end: int, deadline: InspectionDeadline) -> None:
    for offset in range(start, end, 65536):
        deadline.check()
        _require(set(data[offset:min(end, offset + 65536)]) <= {0, 15},
                 "iOS binary plist has unsupported unindexed content")


def _string(data: bytes, encoding: str, deadline: InspectionDeadline) -> str:
    deadline.check()
    try:
        value = data.decode(encoding, errors="strict")
    except UnicodeError as error:
        raise ValidationError("iOS binary plist string encoding is invalid") from error
    deadline.check()
    return value


def _date(data: bytes) -> None:
    seconds = struct.unpack(">d", data)[0]
    _require(math.isfinite(seconds), "iOS binary plist date must be finite")
    epoch = datetime(2001, 1, 1)
    try:
        decoded = epoch + timedelta(seconds=seconds)
        reconstructed = struct.pack(">d", (decoded - epoch).total_seconds())
    except (OverflowError, ValueError) as error:
        raise ValidationError("iOS binary plist date exceeds the supported datetime range") from error
    # Datetime rounds to microseconds. Even two finite values can otherwise
    # collapse; bit equality also rejects the unsupported negative-zero date.
    _require(reconstructed == data, "iOS binary plist date loses precision in the supported datetime representation")


def validate_binary_dictionary(data: bytes, *, deadline: InspectionDeadline,
                               max_nodes: int, max_depth: int) -> None:
    deadline.check()
    _require(len(data) >= 40 and data[:8] == b"bplist00", "iOS binary plist header or trailer is invalid")
    _require(data[-32:-26] == b"\0" * 6, "iOS binary plist trailer version is unsupported")
    offset_width, reference_width, count, root, table = struct.unpack(">6xBBQQQ", data[-32:])
    _require(1 <= offset_width <= 8 and 1 <= reference_width <= 8,
             "iOS binary plist table widths are unsupported")
    _require(0 < count <= max_nodes, "iOS binary plist object count exceeds its bound")
    _require(root < count and 8 < table <= len(data) - 32 and
             table + count * offset_width == len(data) - 32,
             "iOS binary plist root or offset table is invalid")

    offsets = []
    for index in range(count):
        deadline.check()
        start = table + index * offset_width
        offset = int.from_bytes(data[start:start + offset_width], "big")
        _require(8 <= offset < table, "iOS binary plist object offset is outside its region")
        offsets.append(offset)
    ordered = sorted(offsets)
    _require(len(set(ordered)) == count, "iOS binary plist has aliased object offsets")
    ends = dict(zip(ordered, ordered[1:] + [table]))
    _padding(data, 8, ordered[0], deadline)

    tags: list[int] = []
    references: list[tuple[int, ...]] = []
    strings: dict[int, str] = {}
    reference_cells = 0
    for index, offset in enumerate(offsets):
        deadline.check()
        tag, position, end = data[offset], offset + 1, ends[offset]
        kind, count_hint = tag >> 4, tag & 15
        tags.append(kind)
        refs: tuple[int, ...] = ()
        if tag in {0x08, 0x09}:
            pass
        elif 0x10 <= tag <= 0x14:
            finish = _extent(position, 1 << count_hint, end)
            _require(tag != 0x14 or data[position:position + 8] == b"\0" * 8,
                     "iOS binary plist integer must be signed or zero-extended unsigned 64-bit")
            position = finish
        elif tag in {0x22, 0x23, 0x33}:
            finish = _extent(position, 4 if tag == 0x22 else 8, end)
            raw = data[position:finish]
            if tag == 0x33:
                _date(raw)
            else:
                _require(math.isfinite(struct.unpack(">f" if tag == 0x22 else ">d", raw)[0]),
                         "iOS binary plist real must be finite")
            position = finish
        elif kind in {4, 5, 6, 10, 13}:
            length = count_hint
            if count_hint == 15:
                _extent(position, 1, end)
                length_tag = data[position]
                _require(0x10 <= length_tag <= 0x13,
                         "iOS binary plist length requires a supported integer marker")
                position += 1
                finish = _extent(position, 1 << (length_tag & 15), end)
                length = int.from_bytes(data[position:finish], "big")
                position = finish
            if kind in {10, 13}:
                cells = length * (2 if kind == 13 else 1)
                reference_cells += cells
                _require(reference_cells <= max_nodes, "iOS binary plist reference count exceeds its bound")
                finish = _extent(position, cells * reference_width, end)
                values = []
                for start in range(position, finish, reference_width):
                    deadline.check()
                    reference = int.from_bytes(data[start:start + reference_width], "big")
                    _require(reference < count, "iOS binary plist container reference is invalid")
                    values.append(reference)
                refs = tuple(values)
            else:
                finish = _extent(position, length * (2 if kind == 6 else 1), end)
                if kind in {5, 6}:
                    # One decode/hashable string per index, even when a large
                    # key object is shared by many different dictionaries.
                    strings[index] = _string(data[position:finish], "ascii" if kind == 5 else "utf-16-be", deadline)
            position = finish
        else:
            raise ValidationError("iOS binary plist contains an unsupported object marker")
        _padding(data, position, end, deadline)
        references.append(refs)

    _require(tags[root] == 13, "iOS binary plist root must be a dictionary")
    for index, kind in enumerate(tags):
        deadline.check()
        if kind != 13:
            continue
        keys: set[str] = set()
        refs = references[index]
        for key in refs[:len(refs) // 2]:
            deadline.check()
            _require(key in strings and strings[key] not in keys,
                     "iOS binary plist has a duplicate or invalid dictionary key")
            keys.add(strings[key])

    # Validate every graph component, with memoized height AND expanded cost.
    # Caching only a visited flag loses depth when shared values occur deeper.
    states, heights, costs = [0] * count, [0] * count, [0] * count

    def visit(index: int, depth: int) -> tuple[int, int]:
        deadline.check()
        _require(states[index] != 1, "iOS binary plist contains a cyclic value")
        if states[index] == 2:
            _require(depth + heights[index] <= max_depth, "iOS binary plist depth exceeds its bound")
            return heights[index], costs[index]
        _require(depth <= max_depth, "iOS binary plist depth exceeds its bound")
        states[index] = 1
        height, cost = 0, 1
        for child in references[index]:
            deadline.check()
            _require(depth < max_depth, "iOS binary plist depth exceeds its bound")
            child_height, child_cost = visit(child, depth + 1)
            height = max(height, child_height + 1)
            cost = min(max_nodes + 1, cost + child_cost)
            _require(depth + height <= max_depth and cost <= max_nodes,
                     "iOS binary plist expanded graph exceeds its bounds")
        states[index], heights[index], costs[index] = 2, height, cost
        return height, cost

    for index in range(count):
        visit(index, 0)
    deadline.check()
