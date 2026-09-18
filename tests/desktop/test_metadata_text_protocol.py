"""Inert third-domain framing tests, authored for separately admitted execution.

Only JSON DATA and the finite protocol parser/encoder are used. No engine,
lease, native owner, descriptor, process, signal, transaction or recovery is
constructed. These tests do not qualify metadata Save or packaged execution.
"""
from __future__ import annotations

import copy
import hashlib
import json
import unittest

from mobile_release import _desktop_edit_protocol as wire


SESSION = "0123456789abcdef0123456789abcdef"
REVISION = "fedcba9876543210fedcba9876543210"
ROSTERS = {
    "android": ("title.txt", "short_description.txt", "full_description.txt"),
    "ios": ("description.txt", "keywords.txt", "privacy_url.txt", "support_url.txt", "release_notes.txt"),
}


def identity() -> dict:
    return {"device": "0", "inode": "18446744073709551615",
            "mode": 0o40755, "uid": 1000, "gid": 1001}


def frame(seq: int, op: str, params: dict, *, protocol: str = wire.METADATA_PROTOCOL) -> bytes:
    return json.dumps({"protocol": protocol, "session": SESSION, "seq": seq,
                       "op": op, "params": params}, separators=(",", ":")).encode() + b"\n"


def decode(seq: int, op: str, params: dict):
    return wire.parse_request(frame(seq, op, params), sequence=seq,
                              session=None if seq == 0 else SESSION,
                              protocol=wire.METADATA_PROTOCOL)


def opening() -> dict:
    return {"root": "/inert/project", "registeredIdentity": identity(), "platform": "android", "locale": "en-US"}


def baseline(platform: str = "android") -> dict:
    return {"config": {"byteLength": 1, "sha256": "a" * 64},
            "fields": [{"id": name, "state": "absent"} for name in ROSTERS[platform]]}


def prepare(platform: str = "android") -> dict:
    return {"revision": REVISION, "expectedBaseline": baseline(platform),
            "fields": [{"id": name, "text": "Public copy"} for name in ROSTERS[platform]]}


def opened() -> dict:
    return {"revision": REVISION, "metadataRoot": "metadata", "baseline": baseline(), "scopeResources": "settled"}


def prepared() -> dict:
    # Fixed, small DATA fixture; core policy is not reimplemented by this test.
    text = "Public copy"
    content = {"text": text, "byteLength": len(text), "sha256": hashlib.sha256(text.encode()).hexdigest()}
    validation = {"schemaVersion": 1, "platform": "android", "valid": True, "state": "format-valid",
                  "fields": [{"id": name, "valid": True, "characterCount": 11, "limit": limit, "issues": []}
                             for name, limit in zip(ROSTERS["android"], (30, 80, 4000))],
                  "assurance": {"basis": "schema-policy", "projectCodeExecuted": False, "toolsProbed": False,
                                "credentialsRead": False, "gitObserved": False, "storeContacted": False,
                                "writesPerformed": False, "releaseReadiness": "unknown"}}
    view = {"schemaVersion": 1, "platform": "android", "locale": "en-US", "metadataRoot": "metadata",
            "files": [{"id": name, "path": "metadata/android/en-US/" + name, "action": "create",
                       "before": {"state": "absent"}, "after": dict(content), "lineEndingsChanged": False}
                      for name in ROSTERS["android"]],
            "createDirectories": ["metadata", "metadata/android", "metadata/android/en-US"],
            "validation": validation}
    return {"revision": REVISION, "planToken": SESSION, "view": view, "scopeResources": "settled"}


def terminal() -> dict:
    return {"kind": "outcome", "planToken": None, "effect": "not_started", "journal": "not_created",
            "resources": "settled", "reason": "invalid_params"}


class MetadataTextProtocolTests(unittest.TestCase):
    def test_fixed_third_domain_full_identity_and_selection_are_private_open_data(self):
        original = opening()
        request = decode(0, "open", original)
        self.assertEqual(wire.METADATA_PROTOCOL, "mrk-metadata-text/1")
        self.assertEqual(request.protocol, wire.METADATA_PROTOCOL)
        self.assertEqual(request.params, original)
        self.assertEqual(wire.registered_identity(original["registeredIdentity"]),
                         {"device": 0, "inode": 2**64 - 1, "mode": 0o40755, "uid": 1000, "gid": 1001})
        self.assertEqual(original, opening())
        for key in original:
            with self.subTest(missing=key), self.assertRaises(wire.ProtocolError):
                decode(0, "open", {name: value for name, value in original.items() if name != key})
        for key in ("projectId", "metadataRoot", "path", "configPath", "fields", "revision"):
            with self.subTest(extra=key), self.assertRaises(wire.ProtocolError):
                decode(0, "open", {**original, key: None})
        for key, value in [("root", None), ("platform", "windows"), ("platform", True),
                           ("locale", ""), ("locale", "en-us"), ("locale", "e" * 13), ("locale", "éé")]:
            with self.subTest(key=key, value=value), self.assertRaises(wire.ProtocolError):
                decode(0, "open", {**original, key: value})
        for key, value in [("device", 0), ("inode", "0"), ("inode", "18446744073709551616"),
                           ("mode", 0o755), ("mode", True), ("uid", -1), ("gid", 2**32)]:
            with self.subTest(identity=key, value=value), self.assertRaises(wire.ProtocolError):
                decode(0, "open", {**original, "registeredIdentity": {**identity(), key: value}})

    def test_all_three_envelopes_are_distinct_without_fallback(self):
        openings = {wire.PROTOCOL: {"root": "/inert/project"},
                    wire.WORKFLOW_PROTOCOL: {"root": "/inert/project", "registeredIdentity": identity()},
                    wire.METADATA_PROTOCOL: opening()}
        for sent, params in openings.items():
            raw = frame(0, "open", params, protocol=sent)
            for admitted in openings:
                with self.subTest(sent=sent, admitted=admitted):
                    if sent == admitted:
                        self.assertEqual(wire.parse_request(raw, sequence=0, session=None, protocol=admitted).protocol, sent)
                    else:
                        with self.assertRaises(wire.ProtocolError):
                            wire.parse_request(raw, sequence=0, session=None, protocol=admitted)
            if sent != wire.METADATA_PROTOCOL:
                with self.assertRaises(wire.ProtocolError): decode(0, "open", params)
        for protocol in (None, "metadata_text", "mrk-metadata-text/2"):
            with self.subTest(protocol=protocol), self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(0, "open", opening()), sequence=0, session=None, protocol=protocol)

    def test_prepare_is_complete_canonical_data_without_retargeting_or_ui_counters(self):
        for platform in ROSTERS:
            original = prepare(platform)
            self.assertEqual(decode(1, "prepare", original).params, original)
            # Empty/over-Store-limit public copy is structurally representable;
            # only the core validator may decide its release-policy validity.
            for text in ("", "x" * 32768, "é" * 16384):
                value = prepare(platform)
                value["fields"][0]["text"] = text
                self.assertEqual(decode(1, "prepare", value).params, value)
            for key in original:
                with self.subTest(platform=platform, missing=key), self.assertRaises(wire.ProtocolError):
                    decode(1, "prepare", {name: value for name, value in original.items() if name != key})
        for key in ("root", "registeredIdentity", "metadataRoot", "platform", "locale", "path", "files",
                    "draft", "expectedBase", "toolingRepository", "toolingSha", "draftRevision",
                    "baselineGeneration", "planToken", "force"):
            with self.subTest(extra=key), self.assertRaises(wire.ProtocolError):
                decode(1, "prepare", {**prepare(), key: None})
        self.assertNotIn("root", decode(1, "prepare", prepare()).params)

    def test_prepare_field_baseline_digest_and_byte_bounds_are_closed(self):
        bad_fields = [None, [], prepare()["fields"][:-1], list(reversed(prepare()["fields"])),
                      [prepare()["fields"][0]] * 3]
        for key, value in [("id", "review.txt"), ("text", None), ("text", "é" * 16385),
                           ("text", "x" * 32769), ("text", "\ud800"), ("path", "arbitrary.txt")]:
            rows = prepare()["fields"]
            rows[0][key] = value
            bad_fields.append(rows)
        for value in bad_fields:
            with self.subTest(fields=type(value).__name__), self.assertRaises(wire.ProtocolError):
                decode(1, "prepare", {**prepare(), "fields": value})
        bad_baselines = [None, baseline("ios"), {**baseline(), "revision": REVISION}]
        for key, value in [("byteLength", 0), ("byteLength", 524289), ("byteLength", True),
                           ("sha256", "A" * 64), ("sha256", "a" * 63), ("path", "config.json")]:
            item = baseline()
            item["config"][key] = value
            bad_baselines.append(item)
        for row in [{"id": "title.txt", "state": "missing"},
                    {"id": "title.txt", "state": "absent", "byteLength": 0},
                    {"id": "title.txt", "state": "present", "byteLength": 32769, "sha256": "a" * 64},
                    {"id": "title.txt", "state": "present", "byteLength": False, "sha256": "a" * 64}]:
            item = baseline()
            item["fields"][0] = row
            bad_baselines.append(item)
        for value in bad_baselines:
            with self.subTest(baseline=type(value).__name__), self.assertRaises(wire.ProtocolError):
                decode(1, "prepare", {**prepare(), "expectedBaseline": value})
        for size in (0, 32768):
            value = prepare()
            value["expectedBaseline"]["fields"][0] = {
                "id": "title.txt", "state": "present", "byteLength": size, "sha256": "a" * 64}
            self.assertEqual(decode(1, "prepare", value).seq, 1)

    def test_sequence_session_duplicate_unicode_and_complete_frame_admission(self):
        self.assertEqual(decode(2, "apply", {"planToken": REVISION}).seq, 2)
        for seq in (1, 2): self.assertEqual(decode(seq, "discard", {}).op, "discard")
        for seq, op, params in [(0, "discard", {}), (1, "apply", {"planToken": REVISION}),
                                (2, "prepare", prepare()), (2, "apply", {"planToken": REVISION, "fields": []}),
                                (2, "apply", {"planToken": REVISION.upper()}), (2, "discard", {"force": True}),
                                (3, "discard", {})]:
            with self.subTest(seq=seq, op=op), self.assertRaises(wire.ProtocolError): decode(seq, op, params)
        raw = frame(1, "prepare", prepare())
        bad_frames = [raw[:-1], b" " + raw, raw + b"\n", raw + raw, raw[:-1] + b"\r\n",
                      raw.replace(b'"seq":1', b'"seq":true'), raw.replace(b'"seq":1', b'"seq":1,"seq":1'),
                      raw.replace(b'"byteLength":1', b'"byteLength":NaN'),
                      raw.replace(b'"Public copy"', b'"\\ud800"', 1), raw.replace(b'Public copy', b'\xff', 1)]
        for value in bad_frames:
            with self.subTest(prefix=value[:32]), self.assertRaises(wire.ProtocolError):
                wire.parse_request(value, sequence=1, session=SESSION, protocol=wire.METADATA_PROTOCOL)
        for sequence, session in ((0, SESSION), (1, REVISION), (2, SESSION)):
            with self.subTest(sequence=sequence, session=session), self.assertRaises(wire.ProtocolError):
                wire.parse_request(raw, sequence=sequence, session=session, protocol=wire.METADATA_PROTOCOL)
        with self.assertRaises(wire.ProtocolError):
            decode(0, "open", {**opening(), "root": "x" * wire.REQUEST_LIMIT})

    def test_response_outer_keys_settled_scope_and_outcome_only_terminal(self):
        request = decode(1, "prepare", prepare())
        for kind, value in (("opened", opened()), ("prepared", prepared()), ("terminal", terminal())):
            result = json.loads(wire.response(request, kind, value))
            self.assertEqual(set(result), {"protocol", "session", "seq", "kind", "result"})
            self.assertEqual(result, {"protocol": wire.METADATA_PROTOCOL, "session": SESSION,
                                      "seq": 1, "kind": kind, "result": value})
            for key in value:
                with self.subTest(kind=kind, missing=key), self.assertRaises(wire.ProtocolError):
                    wire.response(request, kind, {name: item for name, item in value.items() if name != key})
            for key in ("conflict", "root", "draftRevision", "baselineGeneration"):
                with self.subTest(kind=kind, extra=key), self.assertRaises(wire.ProtocolError):
                    wire.response(request, kind, {**value, key: None})
        for kind, value in (("opened", opened()), ("prepared", prepared())):
            with self.assertRaises(wire.ProtocolError):
                wire.response(request, kind, {**value, "scopeResources": "unknown"})
        with self.assertRaises(wire.ProtocolError):
            wire.response(request, "terminal", {**terminal(), "kind": "conflict"})
        self.assertNotIn("fields", opened())

    def test_complete_view_response_and_terminal_caps_refuse_without_truncation(self):
        self.assertEqual((wire.REQUEST_LIMIT, wire.METADATA_RESPONSE_LIMIT, wire.MAX_PREPARED_BYTES,
                          wire.TERMINAL_LIMIT), (1024 * 1024, 2 * 1024 * 1024, 768 * 1024, 16 * 1024))
        request = decode(1, "prepare", prepare())
        value = prepared()
        # Deliberately invalid inner DATA stresses the encoder's independent
        # complete-object cap; native DTO checks still reject such a view.
        value["view"]["files"][0]["after"]["text"] = "x" * wire.MAX_PREPARED_BYTES
        original = copy.deepcopy(value)
        with self.assertRaises(wire.ProtocolError): wire.response(request, "prepared", value)
        self.assertEqual(value, original)
        with self.assertRaises(wire.ProtocolError):
            wire.response(request, "opened", {**opened(), "metadataRoot": "x" * wire.METADATA_RESPONSE_LIMIT})
        with self.assertRaises(wire.ProtocolError):
            wire.response(request, "terminal", {**terminal(), "reason": "x" * wire.TERMINAL_LIMIT})

    def test_legacy_config_bytes_and_nonterminal_limits_remain_unchanged(self):
        request = wire.EditRequest(SESSION, 0, "open", {"root": "/inert/project"})
        result = {"revision": REVISION, "base": None, "scopeResources": "settled"}
        expected = ('{"protocol":"mrk-config-edit/1","session":"' + SESSION + '","seq":0,"kind":"opened",'
                    '"result":{"revision":"' + REVISION + '","base":null,"scopeResources":"settled"}}\n').encode()
        self.assertEqual(wire.response(request, "opened", result), expected)
        self.assertEqual(wire.RESPONSE_LIMIT, 4 * 1024 * 1024)
        self.assertEqual(wire.WORKFLOW_RESPONSE_LIMIT, 256 * 1024)
        larger = {**result, "base": {"description": "x" * wire.METADATA_RESPONSE_LIMIT}}
        self.assertGreater(len(wire.response(request, "opened", larger)), wire.METADATA_RESPONSE_LIMIT)


if __name__ == "__main__":
    unittest.main()
