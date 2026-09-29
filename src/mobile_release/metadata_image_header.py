"""Bounded PNG/JPEG header inspection, not an image decoder or Store approval.

There is no filesystem access here. The shared metadata validator and desktop
importer can inspect their already-owned byte streams without reopening paths.
"""
from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import BinaryIO, Callable

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
SOF_MARKERS = frozenset({0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                         0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF})
MAX_HEADER_MARKERS = 16_384


def image_dimensions(stream: BinaryIO, *, checkpoint: Callable[[], None] | None = None
                     ) -> tuple[int, int] | None:
    """Existing generic metadata assurance: only dimensions from a header.

    Preserve that narrow contract; a successful result does not establish that
    the remaining pixel stream is complete, decodable, safe or Store compliant.
    The caller bounds its owned stream. The marker loop has an additional cap.
    """
    header = stream.read(32)
    if header.startswith(PNG_SIGNATURE) and len(header) >= 24:
        return struct.unpack(">II", header[16:24])
    if not header.startswith(b"\xff\xd8"):
        return None
    stream.seek(2)
    markers = 0
    while markers < MAX_HEADER_MARKERS:
        if checkpoint is not None:
            checkpoint()
        marker_start = stream.read(1)
        if not marker_start:
            return None
        if marker_start != b"\xff":
            continue
        marker = stream.read(1)
        while marker == b"\xff":
            if checkpoint is not None:
                checkpoint()
            marker = stream.read(1)
        if not marker:
            return None
        markers += 1
        if marker in {b"\xd8", b"\xd9", b"\x01"} or 0xD0 <= marker[0] <= 0xD7:
            continue
        raw_length = stream.read(2)
        if len(raw_length) != 2:
            return None
        length = struct.unpack(">H", raw_length)[0]
        if length < 2:
            return None
        if marker[0] in SOF_MARKERS:
            payload = stream.read(length - 2)
            if len(payload) < 5:
                return None
            return struct.unpack(">HH", payload[1:5])[::-1]
        stream.seek(length - 2, 1)
    return None


@dataclass(frozen=True)
class ImageHeader:
    format: str
    width: int
    height: int


def inspect_header(raw: bytes) -> ImageHeader | None:
    """Check the complete dimension-bearing header, not compressed pixels.

    Unlike the historical dimension-only helper, PNG requires a complete legal
    IHDR with its checksum and JPEG requires the complete SOF component table.
    Trailing pixel data, image metadata and visual content remain uninspected.
    """
    if raw.startswith(PNG_SIGNATURE):
        if (len(raw) < 33 or raw[8:16] != b"\x00\x00\x00\rIHDR"
                or zlib.crc32(raw[12:29]) != int.from_bytes(raw[29:33], "big")):
            return None
        width, height, depth, color, compression, filter_method, interlace = struct.unpack(">IIBBBBB", raw[16:29])
        depths = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8}, 4: {8, 16}, 6: {8, 16}}
        if (width == 0 or height == 0 or width >= 2**31 or height >= 2**31
                or depth not in depths.get(color, ()) or compression != 0
                or filter_method != 0 or interlace not in {0, 1}):
            return None
        return ImageHeader("png", width, height)
    if not raw.startswith(b"\xff\xd8"):
        return None
    offset, markers = 2, 0
    while offset < len(raw) and markers < MAX_HEADER_MARKERS:
        if raw[offset] != 0xFF:
            return None
        while offset < len(raw) and raw[offset] == 0xFF:
            offset += 1
        if offset >= len(raw):
            return None
        marker = raw[offset]
        offset += 1
        markers += 1
        if marker in {0x00, 0xD8, 0xD9, 0xDA} or 0xD0 <= marker <= 0xD7:
            return None
        if marker == 0x01:
            continue
        if offset + 2 > len(raw):
            return None
        length = int.from_bytes(raw[offset:offset + 2], "big")
        if length < 2 or length > len(raw) - offset:
            return None
        if marker in SOF_MARKERS:
            if length < 11:
                return None
            precision = raw[offset + 2]
            height = int.from_bytes(raw[offset + 3:offset + 5], "big")
            width = int.from_bytes(raw[offset + 5:offset + 7], "big")
            count = raw[offset + 7]
            if (precision not in {8, 12, 16} or width == 0 or height == 0
                    or not 1 <= count <= 4 or length != 8 + 3 * count):
                return None
            components = [raw[offset + 8 + 3 * i] for i in range(count)]
            if len(set(components)) != count:
                return None
            return ImageHeader("jpeg", width, height)
        offset += length
    return None
