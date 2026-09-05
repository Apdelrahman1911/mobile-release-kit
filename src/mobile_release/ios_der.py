"""Bounded modern iOS profile/entitlement DER values, not CMS authentication.

Apple's format is versioned, not a stable public API. Unsupported encodings fail
closed. Native signature verification and profile issuer verification are separate
from decoding these values; never treat a decoded dictionary as a trust anchor.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .errors import ValidationError
from .inspection import InspectionDeadline

MAX_DER_BYTES = 4 * 1024 * 1024
MAX_DER_NODES = 100_000
MAX_DER_DEPTH = 64


def _require(condition: bool) -> None:
    if not condition:
        raise ValidationError("iOS profile/entitlement DER is malformed, unsupported or exceeds its bounds")


def decode_der_dictionary(data: bytes, *, profile: bool = False,
                          deadline: InspectionDeadline | None = None) -> dict[str, Any]:
    """Decode a profile SET, or V0 SET/V1 application[16] entitlement dictionary.

    V1 dictionaries use context[16]; SEQUENCE values are arrays. A dictionary
    entry is exactly a SEQUENCE of a unique UTF8 key and one typed value. No
    BER indefinite lengths, high tags, coercions, duplicate keys or trailing data.
    """
    deadline = deadline if deadline is not None else InspectionDeadline()
    deadline.check()
    _require(type(data) is bytes and 0 < len(data) <= MAX_DER_BYTES)
    _require(data[0] in ({0x31} if profile else {0x31, 0x70}))
    remaining = MAX_DER_NODES

    def header(offset: int, end: int) -> tuple[int, int, int]:
        nonlocal remaining
        deadline.check()
        remaining -= 1
        _require(remaining >= 0 and offset + 2 <= end)
        tag, length = data[offset:offset + 2]
        offset += 2
        _require(tag & 0x1F != 0x1F)
        if length & 0x80:
            count = length & 0x7F
            _require(0 < count <= 4 and offset + count <= end and data[offset] != 0)
            length = int.from_bytes(data[offset:offset + count], "big")
            _require(length >= 128)
            offset += count
        _require(length <= end - offset)
        return tag, offset, offset + length

    def value(offset: int, end: int, depth: int) -> tuple[Any, int]:
        _require(depth <= MAX_DER_DEPTH)
        tag, start, stop = header(offset, end)
        if tag in {0x31, 0xB0}:
            result = {}
            position = start
            while position < stop:
                entry_tag, entry_start, entry_end = header(position, stop)
                _require(entry_tag == 0x30)
                key, next_position = value(entry_start, entry_end, depth + 1)
                _require(type(key) is str and key not in result)
                item, next_position = value(next_position, entry_end, depth + 1)
                _require(next_position == entry_end)
                result[key] = item
                position = entry_end
            return result, stop
        if tag == 0x30:
            result = []
            position = start
            while position < stop:
                item, position = value(position, stop, depth + 1)
                result.append(item)
            return result, stop
        if tag == 0x70:
            version, position = value(start, stop, depth + 1)
            _require(type(version) is int and version == 1 and position < stop and data[position] == 0xB0)
            result, position = value(position, stop, depth + 1)
            _require(position == stop)
            return result, stop
        content = data[start:stop]
        if tag == 0x01:
            _require(content in {b"\x00", b"\xff"})
            return content == b"\xff", stop
        if tag == 0x02:
            _require(0 < len(content) <= 9)
            if len(content) > 1:
                _require(not (content[0] == 0 and content[1] < 0x80) and
                         not (content[0] == 0xFF and content[1] >= 0x80))
            number = int.from_bytes(content, "big", signed=True)
            _require(-(1 << 63) <= number < (1 << 64))
            return number, stop
        if tag == 0x04:
            return content, stop
        if tag == 0x0C:
            return content.decode("utf-8", errors="strict"), stop
        if tag in {0x17, 0x18}:
            size = 13 if tag == 0x17 else 15
            _require(len(content) == size and content[-1:] == b"Z" and
                     all(48 <= byte <= 57 for byte in content[:-1]))
            year_length = 2 if tag == 0x17 else 4
            year = int(content[:year_length])
            if year_length == 2:
                year += 2000 if year < 50 else 1900
            fields = [int(content[index:index + 2]) for index in range(year_length, size - 1, 2)]
            return datetime(year, *fields, tzinfo=timezone.utc), stop
        _require(False)

    try:
        result, end = value(0, len(data), 0)
        _require(end == len(data) and type(result) is dict)
        deadline.check()
        return result
    except (ValueError, OverflowError, RecursionError) as error:
        raise ValidationError("iOS profile/entitlement DER contains invalid typed values") from error
