"""Inert wire/refusal-key contracts; no filesystem, process or Store evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from mobile_release import _store_lane_contract as wire
from mobile_release._store_lane_files import execution_attempt_key


LANE = "ios_testflight_internal"
NONCE = bytes.fromhex("ab" * 16)
TIMING = wire.Timing("linux-monotonic-v1", wire.RUN_NS, wire.RUN_NS + wire.CLEANUP_NS)
AUTHORITY = {"attempt": 1, "callerPath": ".github/workflows/candidate.yml",
    "event": "workflow_dispatch", "headSha": "a" * 40, "ref": "refs/heads/main",
    "reusableCommit": "b" * 40, "reusablePath": ".github/workflows/candidate.yml",
    "reusableRepository": "synthetic/project", "runId": 41, "workflow": "candidate"}


def frame(*, success=False):
    identity = {"device": 1, "inode": 2, "uid": 3, "gid": 4, "mode": 0o600}
    return {"version": 1, "nonce": NONCE.hex(), "lane": LANE, "mode": "execute",
        "output": "/synthetic/raw.json", "clock": TIMING.clock,
        "run_deadline_ns": TIMING.run, "hard_deadline_ns": TIMING.hard,
        "outcome": "success" if success else "failed", "launches_closed": True,
        "adapter_settled": True, "nested_settled": True, "terminal_identity": identity,
        "receipt": {**identity, "inode": 5, "size": 3, "sha256": "a" * 64} if success else None,
        "inventory": []}


def encoded(value):
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


class StoreLaneContractTests(unittest.TestCase):
    def decode(self, content, *, code=wire.SETTLED_FAILURE, shell_home=False, timing=TIMING):
        return wire.decode_terminal(content, lane=LANE, mode="execute", output="/synthetic/raw.json",
            nonce=NONCE, timing=timing, code=code, device=1, uid=3, shell_home=shell_home,
            app_id="123456789", key_id="ABCDEF1234")

    def test_only_exact_outcome_status_pairs_admit_a_document(self):
        self.assertIsNone(self.decode(encoded(frame())).document)
        self.assertEqual(self.decode(encoded(frame(success=True)), code=0).document.size, 3)
        for status, success in ((0, False), (75, True), (7, False), (76, False), (-15, True), (True, True)):
            with self.subTest(status=status, success=success), self.assertRaises(ValueError):
                self.decode(encoded(frame(success=success)), code=status)

    def test_closed_envelope_rejects_duplicate_missing_extra_and_nonexact_fields(self):
        values = []
        for key, value in (("version", True), ("nested_settled", 1), ("nonce", "b" * 32),
                           ("run_deadline_ns", TIMING.run + 1), ("output", "/copied/raw.json"),
                           ("clock", "darwin-uptime-raw-v1"), ("unexpected", "extra")):
            values.append(encoded({**frame(), key: value}))
        missing = frame(); del missing["adapter_settled"]
        values.extend((encoded(missing), encoded(frame()).replace(b'"version":1', b'"version":1,"version":1'),
                       encoded(frame()).replace(b'"inode":2', b'"inode":true'),
                       encoded(frame()).replace(b'"gid":4', b'"gid":4,"gid":4')))
        for value in values:
            with self.subTest(content=value[:40]), self.assertRaises(ValueError):
                self.decode(value)

    def test_invalid_encoding_controls_size_depth_and_trailing_data_are_rejected(self):
        value = encoded(frame())
        deep = frame(); deep["inventory"] = [[[[[[[[[[]]]]]]]]]]
        invalid = (value[:-1], value + b"\n", value + b"{}\n", value.replace(b"failed", b"f\xffiled"),
                   value.replace(b"failed", b"f\\u0000iled"), value.replace(b"failed", b"f\\ud800iled"),
                   b" " * (wire.MAX_FRAME + 1), encoded(deep))
        for data in invalid:
            with self.subTest(size=len(data)), self.assertRaises((ValueError, UnicodeError)):
                self.decode(data)

    def test_inventory_is_finite_role_graph_with_exact_branch_and_key_identity(self):
        value = frame()
        directory = {"device": 1, "inode": 6, "uid": 3, "gid": 4, "mode": 0o700}
        key = {"role": "key", "parent": "key-dir", "name": "AuthKey_ABCDEF1234.p8", "kind": "file",
               **directory, "inode": 7, "mode": 0o600}
        owner = {"role": "key-dir", "parent": "tmp", "name": "deliver-" + "a" * 32, "kind": "directory",
                 **directory}
        value["inventory"] = [key, owner]  # Ordering is not parent/path authority.
        self.assertEqual(len(self.decode(encoded(value)).inventory), 2)
        for field, replacement in (("name", "../foreign"), ("name", "AuthKey_OTHER.p8"),
                                    ("parent", "runner"), ("device", 2), ("uid", 10), ("mode", 0o644)):
            invalid = copy.deepcopy(value); invalid["inventory"][0][field] = replacement
            with self.subTest(field=field, replacement=replacement), self.assertRaises(ValueError):
                self.decode(encoded(invalid))
        for entries in ([key], [key, owner, owner], [owner] * 33):
            with self.assertRaises(ValueError):
                self.decode(encoded({**value, "inventory": entries}))
        with self.assertRaises(ValueError):
            self.decode(encoded(value), shell_home=True)
        invalid = frame()
        invalid["inventory"] = [{"role": "upload-asset", "parent": "tmp", "kind": "file",
            "name": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.ipa", **directory, "mode": 0o600}]
        with self.assertRaises(ValueError):
            self.decode(encoded(invalid))  # No macOS-only asset branch on Linux.

    def test_absolute_timing_rejects_expired_extended_noncanonical_or_other_domain(self):
        environment = {wire.PREFIX + "CLOCK": TIMING.clock,
            wire.PREFIX + "RUN_DEADLINE_NS": str(TIMING.run),
            wire.PREFIX + "HARD_DEADLINE_NS": str(TIMING.hard)}
        with patch.object(wire, "clock_label", return_value=TIMING.clock), \
             patch.object(wire.time, "monotonic_ns", return_value=1):
            self.assertEqual(wire.Timing.from_environment(environment), TIMING)
            for key, bad in (("CLOCK", "darwin-uptime-raw-v1"), ("RUN_DEADLINE_NS", "01"),
                             ("RUN_DEADLINE_NS", "0"), ("RUN_DEADLINE_NS", str(TIMING.run + 2)),
                             ("HARD_DEADLINE_NS", str(TIMING.hard + 1))):
                with self.subTest(key=key, value=bad), self.assertRaises(ValueError):
                    wire.Timing.from_environment({**environment, wire.PREFIX + key: bad})
        with patch.object(wire, "clock_label", return_value=TIMING.clock), \
             patch.object(wire.time, "monotonic_ns", return_value=TIMING.run):
            with self.assertRaises(ValueError):
                wire.Timing.from_environment(environment)

    def test_refusal_key_uses_full_original_authority_and_unambiguous_domain_framing(self):
        digest = bytes.fromhex("cd" * 32)
        authority = json.dumps(AUTHORITY, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        lane = LANE.encode("ascii")
        expected = hashlib.sha256(b"mrk-store-attempt-v1\x00" + digest
            + len(authority).to_bytes(4, "big") + authority + bytes((len(lane),)) + lane).hexdigest()
        self.assertEqual(execution_attempt_key(digest, AUTHORITY, LANE), expected)
        for key in AUTHORITY:
            changed = {**AUTHORITY, key: (2 if type(AUTHORITY[key]) is int else AUTHORITY[key] + "x")}
            self.assertNotEqual(execution_attempt_key(digest, changed, LANE), expected)
        missing = dict(AUTHORITY); del missing["attempt"]
        for invalid in (missing, {**AUTHORITY, "extra": "x"}, {**AUTHORITY, "attempt": True}):
            with self.assertRaises(ValueError):
                execution_attempt_key(digest, invalid, LANE)


if __name__ == "__main__":
    unittest.main()
