"""Inert private image-frame tests; no engine, native IO or transaction.

The initial large allowance belongs only to native-owned encoded image DATA.
These tests never qualify picker/capture, process custody or filesystem writes.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from mobile_release import _desktop_edit_protocol as edit
from mobile_release import _desktop_images_protocol as wire
from mobile_release import metadata_images as images
from test_metadata_images import PHONE, native_row, no_io, png
from test_metadata_text_protocol import SESSION, REVISION, identity


def frame(sequence, operation, params, protocol=wire.PROTOCOL):
    return json.dumps({"protocol": protocol, "session": SESSION, "seq": sequence,
                       "op": operation, "params": params}, separators=(",", ":")).encode() + b"\n"


def opening(raw=None):
    return {"root": "/inert/project", "registeredIdentity": identity(), "intent": "import",
            "platform": "android", "locale": "en-US", "assetType": "phoneScreenshots",
            "images": [native_row(png() if raw is None else raw)], "protectedSources": [],
            "protectedObjects": [{"device": "123", "inode": "456"}]}


def baseline():
    return {"config": {"byteLength": 2, "sha256": "a" * 64},
            "ignore": {"byteLength": 0, "sha256": "b" * 64}, "inventorySha256": "c" * 64}


def decode(sequence, operation, params):
    return edit.parse_request(frame(sequence, operation, params), sequence=sequence,
                              session=None if sequence == 0 else SESSION, protocol=wire.PROTOCOL)


class MetadataImagesProtocolTests(unittest.TestCase):
    def test_private_initial_image_data_decodes_once_without_encoded_retention(self):
        original = opening()
        with no_io(), patch.object(images, "_types", return_value=(PHONE,)):
            request = decode(0, "open", original)
            self.assertEqual(request.protocol, wire.PROTOCOL)
            self.assertIs(type(request.params["images"]), tuple)
            self.assertEqual(request.params["images"][0].data, png())
            self.assertNotIn("base64", repr(request.params))
            self.assertEqual(original, opening())
            # Native UTF-8 paths/names are legitimate bounded private DATA;
            # decoding the original LF frame must not corrupt/retarget them.
            unicode_params = opening()
            unicode_params["root"] = "/inert/écran-😀"
            unicode_params["images"][0]["displayName"] = "écran-😀.png"
            unicode_frame = frame(0, "open", unicode_params).decode("ascii")
            unicode_frame = unicode_frame.replace("\\u00e9", "é").replace("\\ud83d\\ude00", "😀").encode("utf-8")
            unicode_request = wire.parse_request(unicode_frame, sequence=0, session=None)
            self.assertEqual(unicode_request.params["root"], unicode_params["root"])
            self.assertEqual(unicode_request.params["images"][0].display_name, "écran-😀.png")
            for root in ("relative", "/" + "a" * 4096, "/" + "é" * 2048, "/invalid\x00", "/\ud800"):
                with self.subTest(root_kind=type(root).__name__), self.assertRaises(edit.ProtocolError):
                    decode(0, "open", {**original, "root": root})
            for extra in ("selectionToken", "projectId", "metadataRoot", "destination", "force"):
                with self.subTest(extra=extra), self.assertRaises(edit.ProtocolError):
                    decode(0, "open", {**original, extra: None})
            for protocol in (edit.PROTOCOL, edit.WORKFLOW_PROTOCOL, edit.METADATA_PROTOCOL, edit.VERSION_PROTOCOL):
                with self.subTest(protocol=protocol), self.assertRaises(edit.ProtocolError):
                    edit.parse_request(frame(0, "open", original), sequence=0, session=None, protocol=protocol)

    def test_larger_frame_is_initial_import_only_and_does_not_expand_other_domains(self):
        params = opening(b"M" * (1024 * 1024))
        raw = frame(0, "open", params)
        self.assertGreater(len(raw), edit.REQUEST_LIMIT)
        with no_io(), patch.object(images, "_types", return_value=(PHONE,)):
            self.assertEqual(len(decode(0, "open", params).params["images"][0].data), 1024 * 1024)
            with self.assertRaises(edit.ProtocolError):
                wire.parse_request(raw, sequence=1, session=SESSION)
            # A recovery frame has no image allowance even before Open.
            recovery = {"root": "/inert/project", "registeredIdentity": identity(), "intent": "recover"}
            self.assertEqual(decode(0, "open", recovery).params, recovery)
            with self.assertRaises(edit.ProtocolError):
                decode(0, "open", {**recovery, "root": "/" + "a" * wire.SMALL_REQUEST_LIMIT})
            self.assertEqual(edit.REQUEST_LIMIT, 1024 * 1024)

    def test_allocation_is_preceded_by_depth_node_and_canonical_base64_bounds(self):
        wide = b'{"wide":[' + b'0,' * 4097 + b'0]}\n'
        deep = b'{"deep":' + b'[' * 17 + b'0' + b']' * 17 + b'}\n'
        with no_io(), patch.object(wire.json, "JSONDecoder", side_effect=AssertionError("JSON allocation before structural bound")):
            for raw in (wide, deep):
                with self.assertRaises(edit.ProtocolError):
                    wire.parse_request(raw, sequence=0, session=None)
        with no_io(), patch.object(images, "_types", return_value=(PHONE,)):
            original = opening(b"M")
            for image in ({**original["images"][0], "base64": "TR=="},
                          {**original["images"][0], "byteLength": True},
                          {**original["images"][0], "sha256": "0" * 64}):
                with self.assertRaises(edit.ProtocolError):
                    decode(0, "open", {**original, "images": [image]})
            for source in (["../other.png"], ["/outside.png"], ["a.png", "A.PNG"]):
                with self.assertRaises(edit.ProtocolError):
                    decode(0, "open", {**original, "protectedSources": source})
            for objects in ([], [{"device": 123, "inode": "456"}], [{"device": "00", "inode": "456"}],
                            [{"device": "123", "inode": str(2**64)}],
                            [{"device": "123", "inode": "456", "path": "original.png"}]):
                with self.assertRaises(edit.ProtocolError):
                    decode(0, "open", {**original, "protectedObjects": objects})

    def test_prepare_apply_and_recovery_have_no_renderer_retargeting_fields(self):
        params = {"revision": REVISION, "expectedBaseline": baseline(),
                  "choices": [{"itemId": "a" * 32, "replaceExisting": False}]}
        with no_io():
            self.assertEqual(decode(1, "prepare", params).params, params)
            self.assertEqual(decode(1, "prepare", {**params, "choices": []}).params["choices"], [])
            for key in ("platform", "locale", "assetType", "action", "transactionId", "path", "draftRevision"):
                with self.assertRaises(edit.ProtocolError):
                    decode(1, "prepare", {**params, key: None})
            for choices in ([params["choices"][0]] * 2,
                            [{"itemId": "a" * 32, "replaceExisting": 1}]):
                with self.assertRaises(edit.ProtocolError):
                    decode(1, "prepare", {**params, "choices": choices})
            self.assertEqual(decode(2, "apply", {"planToken": "b" * 32}).params, {"planToken": "b" * 32})
            with self.assertRaises(edit.ProtocolError):
                decode(2, "apply", {"planToken": "b" * 32, "choices": []})
            self.assertEqual(decode(1, "discard", {}).params, {})

    def test_duplicate_keys_cross_session_nonfinite_numbers_and_trailing_frames_fail_closed(self):
        params = {"root": "/inert/project", "registeredIdentity": identity(), "intent": "recover"}
        raw = frame(0, "open", params)
        with no_io():
            for bad in (raw.replace(b'"seq":0', b'"seq":0,"seq":0'),
                        raw.replace(b'"seq":0', b'"seq":true'),
                        raw.replace(b'"seq":0', b'"seq":NaN'), raw + raw,
                        raw.replace(b'"intent":"recover"', b'"intent":"recover"\r')):
                with self.assertRaises(edit.ProtocolError):
                    wire.parse_request(bad, sequence=0, session=None)
            with self.assertRaises(edit.ProtocolError):
                wire.parse_request(raw, sequence=0, session="f" * 32)


class WindowsImageProtocolDataTests(unittest.TestCase):
    def test_full128_other_volume_import_and_recovery_are_closed_cross_platform_data(self):
        identity = {"volumeSerial": "9", "fileId": "07" * 16}
        params = {**opening(), "root": r"c:\project", "registeredIdentity": identity,
                  "protectedObjects": [{"volumeSerial": "10", "fileId": "80" * 16}]}
        with no_io(), patch.object(images, "_types", return_value=(PHONE,)):
            admitted = decode(0, "open", params)
            self.assertEqual(admitted.params["root"], params["root"])
            self.assertEqual(admitted.params["images"][0].data, png())
            self.assertEqual(admitted.params["protectedObjects"], params["protectedObjects"])
            for root in (r"C:\project", r"\\?\c:\project"):
                recovery = {"root": root, "registeredIdentity": identity, "intent": "recover"}
                self.assertEqual(decode(0, "open", recovery).params, recovery)
            for root in ("/posix", "C:\\", r"C:\project\.", "C:/project"):
                with self.assertRaises(edit.ProtocolError):
                    decode(0, "open", {"root": root, "registeredIdentity": identity, "intent": "recover"})

    def test_root_identity_and_object_family_refuse_before_any_body_decode(self):
        identity = {"volumeSerial": "9", "fileId": "07" * 16}
        params = {**opening(), "root": r"C:\project", "registeredIdentity": identity,
                  "protectedObjects": [{"volumeSerial": "10", "fileId": "80" * 16}]}
        bad = (
            {**params, "root": "/posix"},
            {**params, "registeredIdentity": {**identity, "inode": "2"}},
            {**params, "registeredIdentity": {**identity, "fileId": "A0" * 16}},
            {**params, "protectedObjects": [{"device": "1", "inode": "2"}]},
            {**opening(), "protectedObjects": params["protectedObjects"]},
            {**params, "protectedObjects": [{"volumeSerial": "010", "fileId": "80" * 16}]},
        )
        with no_io(), patch.object(images, "_types", return_value=(PHONE,)), \
                patch.object(wire, "decode_native_images", side_effect=AssertionError("body decode before identity admission")):
            for value in bad:
                with self.subTest(keys=tuple(value)), self.assertRaises(edit.ProtocolError):
                    decode(0, "open", value)


if __name__ == "__main__":
    unittest.main()
