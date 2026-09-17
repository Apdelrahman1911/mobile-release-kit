"""Deterministic native icons from the desktop's existing box mark.

No external image tools or runtime hooks. --write creates only missing source
assets and refuses replacement; --check compares the three fixed tracked files.
PNG/ICO files are required even for Tauri's non-bundled native shell compilation.
"""
from __future__ import annotations

import argparse
import math
from pathlib import Path
import struct
import zlib

SIZES = (16, 32, 64, 128, 256)
BOX_PATH = "M3 7l9-4 9 4v10l-9 4-9-4Z M3 7l9 4 9-4 M12 11v10 M7.5 5l9 4"
STROKES = (
    ((3, 7), (12, 3), (21, 7), (21, 17), (12, 21), (3, 17), (3, 7)),
    ((3, 7), (12, 11), (21, 7)), ((12, 11), (12, 21)), ((7.5, 5), (16.5, 9)),
)


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))


def png(size: int) -> bytes:
    if size not in SIZES:
        raise ValueError("Only the five native icon sizes are supported")
    segments = []
    for points in STROKES:
        for start, end in zip(points, points[1:]):
            a, b = tuple(12 + n * 5 / 3 for n in start), tuple(12 + n * 5 / 3 for n in end)
            dx, dy = b[0] - a[0], b[1] - a[1]
            segments.append((a[0], a[1], dx, dy, dx * dx + dy * dy))
    scale = size / 64
    rows = bytearray()
    for py in range(size):
        rows.append(0)  # PNG's fixed no-filter scanline.
        y = (py + 0.5) / scale
        for px in range(size):
            x = (px + 0.5) / scale
            qx, qy = abs(x - 32) - 17, abs(y - 32) - 17
            edge = math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - 14
            alpha = max(0.0, min(1.0, 0.5 - edge * scale))
            distance = 64.0
            for ax, ay, dx, dy, length in segments:
                t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / length))
                distance = min(distance, math.hypot(x - ax - t * dx, y - ay - t * dy))
            white = max(0.0, min(1.0, 0.5 - (distance - 1.375) * scale))
            rows.extend(round(c + (255 - c) * white) if alpha else 0 for c in (32, 117, 103))
            rows.append(round(255 * alpha))
    return (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + _chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + _chunk(b"IEND", b""))


def assets() -> dict[str, bytes]:
    images = [(size, png(size)) for size in SIZES]
    directory = bytearray(struct.pack("<HHH", 0, 1, len(images)))
    offset = 6 + 16 * len(images)
    for size, image in images:
        directory.extend(struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(image), offset))
        offset += len(image)
    ico = bytes(directory) + b"".join(image for _, image in images)
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">\n'
           '  <rect x="1" y="1" width="62" height="62" rx="14" fill="#207567"/>\n'
           '  <g transform="translate(12 12) scale(1.6666666666666667)" fill="none" '
           'stroke="white" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round">\n'
           f'    <path d="{BOX_PATH}"/>\n  </g>\n</svg>\n').encode("ascii")
    return {"icon.svg": svg, "icon.png": images[-1][1], "icon.ico": ico}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1] / "src-tauri/icons"
    prepared = assets()
    if args.write:
        if any((root / name).exists() or (root / name).is_symlink() for name in prepared):
            parser.error("Refusing to replace existing icon source assets")
        root.mkdir(exist_ok=True)
        for name, data in prepared.items():
            with (root / name).open("xb") as stream:
                stream.write(data)
    else:
        for name, data in prepared.items():
            if (root / name).is_symlink() or (root / name).read_bytes() != data:
                parser.error("Tracked native icon assets differ from the fixed renderer")
    print("Native icon source assets written." if args.write else "Native icon source assets match.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
