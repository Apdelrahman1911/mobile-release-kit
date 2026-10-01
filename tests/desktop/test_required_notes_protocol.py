"""Closed required-notes wire DATA; no engine/IO/native owner is constructed."""
from __future__ import annotations

import copy
import json
import unittest

from mobile_release import _desktop_edit_protocol as wire
from mobile_release import required_notes as notes
from test_metadata_text_protocol import SESSION, REVISION, identity
from test_required_notes_edit import VERSION, configured


def frame(seq, op, params, protocol=wire.NOTES_PROTOCOL):
    return json.dumps({"protocol": protocol, "session": SESSION, "seq": seq,
                       "op": op, "params": params}, separators=(",", ":")).encode() + b"\n"


def decode(seq, op, params):
    return wire.parse_request(frame(seq, op, params), sequence=seq,
                              session=None if seq == 0 else SESSION, protocol=wire.NOTES_PROTOCOL)


def preparation(kind="android-build"):
    config, context = configured(kind)
    return {"revision": REVISION, "context": context,
            "expectedBaseline": notes.notes_baseline(json.dumps(config).encode(), VERSION if kind.startswith("android-") else None,
                                                     None, None), "text": "Reviewed instructions.\r\n"}


class RequiredNotesProtocolTests(unittest.TestCase):
    def test_fixed_notes_domain_context_and_identity_do_not_fall_back_to_public_text(self):
        params = {"root": "/inert-project", "registeredIdentity": identity(), "context": {"kind": "android-build", "locale": "en-US"}}
        self.assertEqual(decode(0, "open", params).params, params)
        for protocol in (wire.PROTOCOL, wire.METADATA_PROTOCOL, wire.VERSION_PROTOCOL, wire.WORKFLOW_PROTOCOL):
            with self.subTest(protocol=protocol), self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(0, "open", params, protocol), sequence=0, session=None, protocol=wire.NOTES_PROTOCOL)
        for key in ("path", "metadataRoot", "versionSource", "savedBuild", "force", "purpose", "notesPurpose"):
            with self.subTest(extra=key), self.assertRaises(wire.ProtocolError): decode(0, "open", {**params, key: None})
        for context in ({"kind": "ios-beta-review", "locale": "en-US"}, {"kind": "android-default"},
                        {"kind": "android-build", "locale": "en-us"}, {"kind": "private-file"}):
            with self.assertRaises(wire.ProtocolError): decode(0, "open", {**params, "context": context})
        with self.assertRaises(wire.ProtocolError): decode(0, "open", {**params, "registeredIdentity": {"inode": 0}})

    def test_prepare_retains_explicit_context_exact_baseline_and_bounded_raw_text(self):
        for kind in notes.KINDS:
            original = preparation(kind)
            self.assertEqual(decode(1, "prepare", original).params, original)
            boundary = {**original, "text": "x" * notes.editor_byte_limit(kind)}
            self.assertEqual(decode(1, "prepare", boundary).seq, 1)
            with self.assertRaises(wire.ProtocolError): decode(1, "prepare", {**boundary, "text": boundary["text"] + "x"})
            with self.assertRaises(wire.ProtocolError): decode(1, "prepare", {**original, "text": "\ud800"})
            for key in original:
                with self.assertRaises(wire.ProtocolError): decode(1, "prepare", {name: value for name, value in original.items() if name != key})
            for extra in ("path", "fields", "savedBuild", "root", "registeredIdentity"):
                with self.assertRaises(wire.ProtocolError): decode(1, "prepare", {**original, extra: None})
            invalid = copy.deepcopy(original); invalid["expectedBaseline"]["config"]["byteLength"] = True
            with self.assertRaises(wire.ProtocolError): decode(1, "prepare", invalid)
        self.assertEqual(decode(2, "apply", {"planToken": REVISION}).op, "apply")
        for seq in (1, 2): self.assertEqual(decode(seq, "discard", {}).op, "discard")
        with self.assertRaises(wire.ProtocolError): decode(1, "apply", {"planToken": REVISION})
        with self.assertRaises(wire.ProtocolError): decode(2, "apply", {"planToken": REVISION, "text": "not accepted"})

    def test_terminal_is_closed_outcome_only_and_prepared_scope_must_settle(self):
        request = decode(1, "prepare", preparation())
        terminal = {"kind": "outcome", "planToken": REVISION, "effect": "committed", "journal": "clean",
                    "resources": "settled", "reason": "none"}
        self.assertEqual(json.loads(wire.response(request, "terminal", terminal))["result"], terminal)
        for key in ("text", "view", "baseline", "selection", "sha256", "rawByteCount", "message"):
            with self.assertRaises(wire.ProtocolError): wire.response(request, "terminal", {**terminal, key: None})
        prepared = {"revision": REVISION, "planToken": SESSION, "view": {}, "scopeResources": "settled"}
        self.assertEqual(json.loads(wire.response(request, "prepared", prepared))["result"], prepared)
        with self.assertRaises(wire.ProtocolError): wire.response(request, "prepared", {**prepared, "scopeResources": "unknown"})
        with self.assertRaises(wire.ProtocolError): wire.response(request, "prepared", {**prepared, "view": {"text": "x" * wire.NOTES_PREPARED_LIMIT}})
        self.assertEqual((wire.NOTES_REQUEST_LIMIT, wire.NOTES_OPENED_LIMIT, wire.NOTES_PREPARED_LIMIT,
                          wire.NOTES_RESPONSE_LIMIT, wire.TERMINAL_LIMIT),
                         (512 * 1024, 16 * 1024, 896 * 1024, 1024 * 1024, 16 * 1024))
        self.assertEqual(wire.REQUEST_LIMIT, 1024 * 1024)
        self.assertEqual(wire.METADATA_RESPONSE_LIMIT, 2 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
