"""Inert framing/ABI tests, authored for separately authorized verification.

No engine, lease, workspace, owner, descriptor, signal, thread, subprocess,
native probe, transaction, recovery or external service is constructed here.
These DATA checks do not qualify the workflow writer or its native lifetime.
"""
from __future__ import annotations

import json
import unittest

from mobile_release import _desktop_edit_protocol as wire


SESSION = "0123456789abcdef0123456789abcdef"
REVISION = "fedcba9876543210fedcba9876543210"
IDS = ("preflight", "candidate", "external-testing", "production-submit")


def identity() -> dict:
    return {"device": "0", "inode": "18446744073709551615",
            "mode": 0o40755, "uid": 1000, "gid": 1001}


def frame(seq: int, op: str, params: dict, *, protocol: str = wire.WORKFLOW_PROTOCOL) -> bytes:
    return json.dumps({"protocol": protocol, "session": SESSION, "seq": seq,
                       "op": op, "params": params}, separators=(",", ":")).encode() + b"\n"


def decode(seq: int, op: str, params: dict):
    return wire.parse_request(frame(seq, op, params), sequence=seq,
                              session=None if seq == 0 else SESSION,
                              protocol=wire.WORKFLOW_PROTOCOL)


def prepare() -> dict:
    return {"revision": REVISION, "draft": {}, "toolingRepository": "example/toolkit",
            "toolingSha": "a" * 40}


class WorkflowEditProtocolTests(unittest.TestCase):
    def test_private_identity_keeps_full_mode_u64_strings_and_gid(self):
        original = identity()
        decoded = wire.registered_identity(original)
        self.assertEqual(decoded, {"device": 0, "inode": 2**64 - 1,
                                   "mode": 0o40755, "uid": 1000, "gid": 1001})
        self.assertEqual(original, identity())
        request = decode(0, "open", {"root": "/inert/project", "registeredIdentity": original})
        self.assertEqual(request.protocol, wire.WORKFLOW_PROTOCOL)
        self.assertEqual(request.params["registeredIdentity"], original)

    def test_identity_rejects_lossy_numbers_bool_permissions_only_and_extra_fields(self):
        bad = [("device", 0), ("device", True), ("device", "00"), ("device", "+1"),
               ("device", "-1"), ("device", "1.0"), ("device", " 1"), ("device", "١"),
               ("inode", "0"), ("inode", "18446744073709551616"), ("inode", ""),
               ("mode", 0o755), ("mode", 0o100755), ("mode", True), ("mode", 1.0),
               ("uid", -1), ("uid", "1000"), ("uid", False), ("gid", 2**32), ("gid", 1.0)]
        for key, value in bad:
            with self.subTest(key=key, value=value), self.assertRaises(wire.ProtocolError):
                decode(0, "open", {"root": "/inert/project", "registeredIdentity": {**identity(), key: value}})
        for value in [None, [], {**identity(), "owner": 1000},
                      {key: value for key, value in identity().items() if key != "gid"}]:
            with self.subTest(value=value), self.assertRaises(wire.ProtocolError):
                wire.registered_identity(value)

    def test_workflow_and_configuration_envelopes_cannot_cross(self):
        workflow = frame(0, "open", {"root": "/inert/project", "registeredIdentity": identity()})
        configuration = frame(0, "open", {"root": "/inert/project"}, protocol=wire.PROTOCOL)
        self.assertEqual(wire.parse_request(configuration, sequence=0, session=None).protocol, wire.PROTOCOL)
        for raw, protocol in [(workflow, wire.PROTOCOL), (configuration, wire.WORKFLOW_PROTOCOL)]:
            with self.subTest(protocol=protocol), self.assertRaises(wire.ProtocolError):
                wire.parse_request(raw, sequence=0, session=None, protocol=protocol)
        with self.assertRaises(wire.ProtocolError):
            decode(0, "open", {"root": "/inert/project"})
        with self.assertRaises(wire.ProtocolError):
            wire.parse_request(frame(0, "open", {"root": "/inert/project", "registeredIdentity": identity()},
                                     protocol=wire.PROTOCOL), sequence=0, session=None)

    def test_prepare_is_closed_and_does_not_accept_advisory_or_file_authority(self):
        self.assertEqual(decode(1, "prepare", prepare()).op, "prepare")
        # Syntax/normalization policy is in the core proposal service, not a
        # second transport policy or a nonzero-SHA qualification assertion.
        for sha in ["0" * 40, "A" * 40]:
            self.assertEqual(decode(1, "prepare", {**prepare(), "toolingSha": sha}).params["toolingSha"], sha)
        for key in ["suppliedSnapshot", "expectedBase", "root", "registeredIdentity", "files",
                    "path", "content", "sha256", "force", "planToken", "credentials"]:
            with self.subTest(key=key), self.assertRaises(wire.ProtocolError):
                decode(1, "prepare", {**prepare(), key: None})
        for key in prepare():
            with self.subTest(missing=key), self.assertRaises(wire.ProtocolError):
                decode(1, "prepare", {name: value for name, value in prepare().items() if name != key})

    def test_draft_and_coordinates_have_separate_byte_node_and_depth_bounds(self):
        for field, value in [("draft", []), ("draft", {"text": "x" * (512 * 1024)}),
                             ("draft", {"items": [None] * 7998}),
                             ("toolingRepository", "é" * 71), ("toolingSha", "a" * 41)]:
            with self.subTest(field=field), self.assertRaises(wire.ProtocolError):
                decode(1, "prepare", {**prepare(), field: value})
        nested = {}
        for _ in range(27):
            nested = {"nested": nested}
        self.assertEqual(decode(1, "prepare", {**prepare(), "draft": nested}).seq, 1)
        with self.assertRaises(wire.ProtocolError):
            decode(1, "prepare", {**prepare(), "draft": {"nested": nested}})

    def test_finite_sequences_session_correlation_and_complete_json(self):
        self.assertEqual(decode(2, "apply", {"planToken": REVISION}).seq, 2)
        for sequence in (1, 2):
            self.assertEqual(decode(sequence, "discard", {}).op, "discard")
        for seq, op, params in [(0, "discard", {}), (1, "apply", {"planToken": REVISION}),
                                (2, "prepare", prepare()), (2, "apply", {"planToken": REVISION, "force": False}),
                                (3, "discard", {})]:
            with self.subTest(seq=seq, op=op), self.assertRaises(wire.ProtocolError):
                decode(seq, op, params)
        raw = frame(1, "prepare", prepare())
        for bad in [raw[:-1], b" " + raw, raw + b"\n", raw.replace(b'"seq":1', b'"seq":true'),
                    raw.replace(b'"seq":1', b'"seq":1,"seq":1'), raw.replace(b'"draft":{}', b'"draft":{"x":NaN}')]:
            with self.subTest(bad=bad[:32]), self.assertRaises(wire.ProtocolError):
                wire.parse_request(bad, sequence=1, session=SESSION, protocol=wire.WORKFLOW_PROTOCOL)
        with self.assertRaises(wire.ProtocolError):
            wire.parse_request(raw, sequence=1, session=REVISION, protocol=wire.WORKFLOW_PROTOCOL)

    def test_conflict_terminal_is_small_no_token_data_and_terminal_cap_is_unchanged(self):
        request = decode(1, "prepare", prepare())
        conflict = {"schemaVersion": 1, "reason": "existing_workflow_differs", "conflicts": [
            {"id": item, "observed": {"state": "present", "byteLength": 10, "sha256": "a" * 64}}
            for item in IDS]}
        result = {"kind": "conflict", "revision": REVISION, "effect": "not_started", "journal": "not_created",
                  "resources": "settled", "reason": "none", "conflict": conflict}
        raw = wire.response(request, "terminal", result)
        self.assertLess(len(raw), 4096)
        self.assertEqual(wire.TERMINAL_LIMIT, 16 * 1024)
        self.assertNotIn("planToken", json.loads(raw)["result"])
        self.assertNotIn(b'"content"', raw)
        with self.assertRaises(wire.ProtocolError):
            wire.response(request, "terminal", {**result, "padding": "x" * wire.TERMINAL_LIMIT})
        with self.assertRaises(wire.ProtocolError):
            wire.response(request, "prepared", {"padding": "x" * wire.WORKFLOW_RESPONSE_LIMIT})

    def test_legacy_configuration_encoder_bytes_and_larger_nonterminal_bound_are_unchanged(self):
        request = wire.EditRequest(SESSION, 0, "open", {"root": "/inert/project"})
        result = {"revision": REVISION, "base": None, "scopeResources": "settled"}
        expected = ('{"protocol":"mrk-config-edit/1","session":"' + SESSION + '","seq":0,"kind":"opened",'
                    '"result":{"revision":"' + REVISION + '","base":null,"scopeResources":"settled"}}\n').encode()
        self.assertEqual(wire.response(request, "opened", result), expected)
        larger = {**result, "base": {"description": "x" * wire.WORKFLOW_RESPONSE_LIMIT}}
        self.assertGreater(len(wire.response(request, "opened", larger)), wire.WORKFLOW_RESPONSE_LIMIT)
        self.assertEqual(wire.RESPONSE_LIMIT, 4 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
