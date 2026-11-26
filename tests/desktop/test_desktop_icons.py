"""Bounded, in-memory PNG/ICO structure check; no native renderer or process."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import unittest
import zlib

SPEC = importlib.util.spec_from_file_location(
    "desktop_icons_contract", Path(__file__).resolve().parents[2] / "desktop/tools/desktop_icons.py"
)
assert SPEC is not None and SPEC.loader is not None
icons = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(icons)


class NativeIconAssetsTests(unittest.TestCase):
    def test_complete_png_ico_layout_and_bounded_rgba_pixels(self):
        assets = icons.assets()
        self.assertEqual(set(assets), {"icon.png", "icon.ico", "icon.svg"})
        self.assertLess(sum(map(len, assets.values())), 128 * 1024)
        ico = assets["icon.ico"]
        self.assertEqual(struct.unpack_from("<HHH", ico), (0, 1, 5))
        expected_offset = 86
        for index, size in enumerate(icons.SIZES):
            w, h, colors, reserved, planes, bits, length, offset = struct.unpack_from("<BBBBHHII", ico, 6 + 16 * index)
            self.assertEqual((w, h, colors, reserved, planes, bits), (size % 256, size % 256, 0, 0, 1, 32))
            self.assertEqual(offset, expected_offset)
            png = ico[offset:offset + length]
            self.assertEqual(len(png), length)
            self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
            chunks = []
            cursor = 8
            while cursor < len(png):
                count = struct.unpack_from(">I", png, cursor)[0]
                kind = png[cursor + 4:cursor + 8]
                data = png[cursor + 8:cursor + 8 + count]
                self.assertEqual(struct.unpack_from(">I", png, cursor + 8 + count)[0], zlib.crc32(kind + data))
                chunks.append((kind, data))
                cursor += 12 + count
            self.assertEqual(cursor, len(png))
            self.assertEqual([kind for kind, _ in chunks], [b"IHDR", b"IDAT", b"IEND"])
            self.assertEqual(struct.unpack(">IIBBBBB", chunks[0][1]), (size, size, 8, 6, 0, 0, 0))
            self.assertEqual(chunks[-1][1], b"")
            decoder = zlib.decompressobj()
            raw = decoder.decompress(chunks[1][1], size * (1 + size * 4) + 1)
            self.assertEqual(len(raw), size * (1 + size * 4))
            self.assertTrue(decoder.eof)
            self.assertFalse(decoder.unused_data or decoder.unconsumed_tail)
            self.assertTrue(all(raw[row * (1 + size * 4)] == 0 for row in range(size)))
            self.assertEqual(raw[4], 0)  # Transparent outer corner.
            if size == 256:
                self.assertEqual(png, assets["icon.png"])
            expected_offset += length
        self.assertEqual(expected_offset, len(ico))
        self.assertIn(icons.BOX_PATH.encode("ascii"), assets["icon.svg"])


if __name__ == "__main__":
    unittest.main()
