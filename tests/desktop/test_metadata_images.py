"""Pure image-policy regressions, not native selection/write qualification.

Fixtures are synthetic public bytes. No selected project is opened and no
process, native dialog, signing material, Store or network service is used.
Execution is separately owned/admitted by the lead.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import struct
import unittest
import zlib
from unittest.mock import patch

from mobile_release import metadata_image_header as header
from mobile_release import metadata_images as images
from test_metadata_text import config, no_io


def png(width=1, height=1, pixel=1):
    def chunk(name, data):
        return struct.pack(">I", len(data)) + name + data + struct.pack(">I", zlib.crc32(name + data))
    return (header.PNG_SIGNATURE
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00" + bytes([pixel, 0, 0])))
            + chunk(b"IEND", b""))


def jpeg_header(width=3, height=2):
    # Deliberately header-only: a passing check must NEVER claim full decoding.
    return b"\xff\xd8\xff\xc0" + struct.pack(">HBHHB", 11, 8, height, width, 1) + b"\x01\x11\x00"


def native_row(raw, *, identity="a" * 32, name="01.png"):
    return {"itemId": identity, "displayName": name, "byteLength": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(), "base64": base64.b64encode(raw).decode("ascii")}


PHONE = images.ImageType("android", "phoneScreenshots", "Phone screenshots", False, 8, ())
ICON = images.ImageType("android", "icon", "App icon", True, 1, ())
APPLE = images.ImageType("ios", "APP_IPHONE_FIXTURE", "Synthetic header profile", False, 10, ((3, 2),))


def selection(kind=PHONE):
    folder = "release/store/android/en-US/images" + ("" if kind.singleton else "/" + kind.identity)
    if kind.platform == "ios":
        folder = "release/store/ios/screenshots/en-US/" + kind.identity
    return images.PublicImageSelection(kind.platform, "en-US", "release/store", kind, folder)


def selected(raw=None, *, identity="a" * 32, name="01.png"):
    return images.SelectedImage(identity, name, png() if raw is None else raw)


class HeaderPolicyTests(unittest.TestCase):
    def test_complete_header_checks_and_narrow_assurance_are_distinct(self):
        with no_io():
            self.assertEqual(header.inspect_header(png()), header.ImageHeader("png", 1, 1))
            raw = jpeg_header()
            summary, issues = images.image_summary(raw, "screen.jpg", APPLE)
            self.assertFalse(issues)
            self.assertTrue(summary["headerChecked"])
            self.assertEqual((summary["width"], summary["height"]), (3, 2))
            self.assertEqual(header.image_dimensions(io.BytesIO(raw)), (3, 2))
            view, _ = images.import_view(selection(APPLE), (selected(raw, name="screen.jpg"),),
                                          ("screen.jpg",), (), (False,), dependency_bytes=0)
            self.assertFalse(view["assurance"]["fullDecode"])
            self.assertFalse(view["assurance"]["storeAccepted"])
            self.assertFalse(view["assurance"]["storeContacted"])

    def test_truncation_checksum_extension_and_dimensions_are_material_errors(self):
        with no_io():
            for end in (0, 8, 16, 24, 29, 32):
                self.assertIsNone(header.inspect_header(png()[:end]))
            broken = bytearray(png()); broken[29] ^= 1
            self.assertIsNone(header.inspect_header(bytes(broken)))
            self.assertIsNone(header.inspect_header(jpeg_header()[:-1]))
            self.assertIn("image.extension", images.image_summary(png(), "screen.jpg")[1])
            self.assertIn("image.dimensions", images.image_summary(png(width=20_000), "screen.png")[1])
            self.assertIn("image.device", images.image_summary(png(), "screen.png", APPLE)[1])
            self.assertIn("image.format", images.image_summary(b"not a public image", "screen.png")[1])


class NativeBatchDataTests(unittest.TestCase):
    def test_exact_native_body_digest_and_padding_not_renderer_authority(self):
        with no_io():
            row = native_row(png())
            batch = images.decode_native_images([row])
            self.assertEqual(batch[0].data, png())
            self.assertNotIn(repr(png()), repr(batch[0]))
            for bad in (
                {**row, "path": "/must-not-be-opened"},
                {**row, "byteLength": True},
                {**row, "sha256": "0" * 64},
                {**row, "base64": row["base64"] + "="},
                {**row, "displayName": "../screen.png"},
            ):
                with self.assertRaises(images.MetadataImagesInputError):
                    images.decode_native_images([bad])
            with self.assertRaises(images.MetadataImagesInputError):
                images.decode_native_images([row, row])
            # A noncanonical low-bit alias decodes to the same byte. It is not
            # accepted as a second spelling of the original transfer DATA.
            with self.assertRaises(images.MetadataImagesInputError):
                images.decode_native_images([{**native_row(b"M"), "base64": "TR=="}])

    def test_batch_bound_precedes_any_base64_decode(self):
        rows = [native_row(b"ab"), native_row(b"cd", identity="b" * 32)]
        with no_io(), patch.object(images, "MAX_BATCH_BYTES", 3), \
                patch.object(images.base64, "b64decode", side_effect=AssertionError("allocation before admission")):
            with self.assertRaises(images.MetadataImagesInputError) as result:
                images.decode_native_images(rows)
            self.assertEqual(result.exception.reason, "limit")

    def test_independent_padding_quanta_do_not_reduce_the_raw_batch_allowance(self):
        rows = [native_row(b"a"), native_row(b"b", identity="b" * 32), native_row(b"c", identity="c" * 32)]
        with no_io(), patch.object(images, "MAX_BATCH_BYTES", 3):
            self.assertEqual(len(images.decode_native_images(rows)), 3)


class SelectionPreviewTests(unittest.TestCase):
    def test_saved_configuration_and_closed_type_derive_destinations(self):
        # Fixed catalog seam is DATA only. The shipped supplier equality is a
        # separate source-bound contract, not this synthetic catalog check.
        with no_io(), patch.object(images, "_types", return_value=(PHONE, ICON, APPLE)):
            actual = images.public_image_selection(json.dumps(config("public/store")), "android", "fr-FR", "phoneScreenshots")
            self.assertEqual(actual.folder, "public/store/android/fr-FR/images/phoneScreenshots")
            for platform, locale, kind in (("android", "de-DE", "phoneScreenshots"),
                                           ("ios", "fr-FR", "APP_IPHONE_FIXTURE"),
                                           ("android", "en-US", "../../secrets")):
                with self.assertRaises(images.MetadataImagesInputError):
                    images.public_image_selection(json.dumps(config()), platform, locale, kind)
            with self.assertRaises(images.MetadataImagesInputError):
                images.public_image_selection(json.dumps(config("release/credentials")), "android", "en-US", "icon")

    def test_portable_names_and_singleton_matching_format_do_not_delete_other_files(self):
        with no_io():
            batch = (selected(name="screen.png"),)
            with self.assertRaises(images.MetadataImagesInputError):
                images.target_names(selection(), batch, ("SCREEN.PNG",))
            with self.assertRaises(images.MetadataImagesInputError):
                images.target_names(selection(ICON), batch, ("icon.jpg",))
            jpeg = selected(jpeg_header(), name="new.jpg")
            self.assertEqual(images.target_names(selection(ICON), (jpeg,), ("icon.jpeg",)), ("icon.jpeg",))
            unsafe = selected(name="NUL.png")
            name = images.target_names(selection(), (unsafe,), ())[0]
            self.assertTrue(name.startswith("image-01-"))
            self.assertTrue(images.safe_name(name))
            self.assertFalse(images.safe_name("../screen.png"))

    def test_keep_existing_is_default_and_preview_distinguishes_selected_from_result(self):
        old, new = png(pixel=1), png(pixel=2)
        batch = (selected(new),)
        with no_io():
            kept, payloads = images.import_view(selection(), batch, ("01.png",), (("01.png", old),),
                                               (False,), dependency_bytes=0)
            row = kept["files"][0]
            self.assertTrue(kept["valid"])
            self.assertEqual(payloads, (None,))
            self.assertEqual(row["action"], "preserve")
            self.assertEqual(row["after"], row["before"])
            self.assertNotEqual(row["selected"], row["after"])
            replaced, payloads = images.import_view(selection(), batch, ("01.png",), (("01.png", old),),
                                                   (True,), dependency_bytes=0)
            self.assertEqual(replaced["files"][0]["action"], "replace")
            self.assertEqual(replaced["files"][0]["after"], replaced["files"][0]["selected"])
            self.assertEqual(payloads, (new,))
            self.assertNotIn("base64", json.dumps(replaced))

    def test_complete_relevant_set_controls_duplicates_count_and_real_lexical_order(self):
        raw = png()
        with no_io():
            view, _ = images.import_view(selection(), (selected(raw, name="02.png"),), ("02.png",),
                                         (("01.png", raw),), (False,), dependency_bytes=0)
            self.assertFalse(view["valid"])
            self.assertIn("image.duplicate", [row["code"] for row in view["issues"]])
            self.assertEqual(view["finalOrder"], [selection().folder + "/01.png", selection().folder + "/02.png"])
            one = images.ImageType("android", "phoneScreenshots", "Bounded fixture", False, 1, ())
            view, _ = images.import_view(selection(one), (selected(png(pixel=2), name="02.png"),), ("02.png",),
                                         (("01.png", raw),), (False,), dependency_bytes=0)
            self.assertIn("image.count", [row["code"] for row in view["issues"]])

    def test_selected_project_originals_cannot_be_overwritten_even_by_another_batch_item(self):
        old, new = png(pixel=1), png(pixel=2)
        path = selection().folder + "/01.png"
        with no_io():
            view, _ = images.import_view(selection(), (selected(new),), ("01.png",), (("01.png", old),),
                                         (True,), dependency_bytes=0, protected_sources=(path,))
            self.assertFalse(view["valid"])
            self.assertFalse(view["files"][0]["canReplace"])
            self.assertIn("image.source-target", [row["code"] for row in view["issues"]])
            # Case-folded restrictions are conservative, never more write authority.
            view, payloads = images.import_view(selection(), (selected(old),), ("01.png",), (("01.png", old),),
                                                (True,), dependency_bytes=0, protected_sources=(path.upper(),))
            self.assertTrue(view["valid"])
            self.assertEqual(view["files"][0]["action"], "preserve")
            self.assertEqual(payloads, (None,))
            # Explicit replacement may preserve identical bytes but cannot claim
            # a replacement for an absent target.
            with self.assertRaises(images.MetadataImagesInputError):
                images.import_view(selection(), (selected(),), ("01.png",), (), (True,), dependency_bytes=0)

    def test_replacement_choices_and_baseline_are_exact_data_not_paths_or_retargerters(self):
        batch = (selected(),)
        with no_io():
            self.assertEqual(images.replacement_choices([{"itemId": "a" * 32, "replaceExisting": False}], batch), (False,))
            for row in ({"itemId": "b" * 32, "replaceExisting": True},
                        {"itemId": "a" * 32, "replaceExisting": 1},
                        {"itemId": "a" * 32, "replaceExisting": True, "path": "other.png"}):
                with self.assertRaises(images.MetadataImagesInputError):
                    images.replacement_choices([row], batch)
            base = images.baseline(b"{}", b"ignore", selection(), ("01.png",), (), batch)
            self.assertEqual(images.admit_baseline(base), base)
            with self.assertRaises(images.MetadataImagesInputError):
                images.admit_baseline({**base, "root": "/other"})


if __name__ == "__main__":
    unittest.main()
