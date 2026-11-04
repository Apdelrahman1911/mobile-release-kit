"""Actual closed codecs with shared unsigned DATA vectors; no native work.

The Rust transaction tests consume the same golden byte strings and mutations.
These tests never attest a producer, filesystem original, gate, writer or GO.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("fresh_birth_stager_codec", ROOT / "desktop/tools/stage_macos_installed.py")
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)
CORPUS = json.loads((ROOT / "tests/desktop/fixtures/fresh_birth_codec_vectors.json").read_bytes())


def selected(vector):
    return {"target": vector["target"], "releaseSet": vector["releaseSet"]}


def changed(original, mutation):
    value = copy.deepcopy(original)
    keys = mutation["path"].split("/")[1:]
    parent = value
    for key in keys[:-1]:
        parent = parent[key]
    if mutation.get("delete") is True:
        del parent[keys[-1]]
    else:
        parent[keys[-1]] = mutation["value"]
    return value


class FreshBirthCodecTests(unittest.TestCase):
    def test_shared_golden_bytes_and_legacy_reading(self):
        self.assertEqual(len(CORPUS["vectors"]), 6)
        for vector in CORPUS["vectors"]:
            with self.subTest(vector=vector["name"]):
                raw = vector["canonical"].encode()
                producer = selected(vector)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), vector["sha256"])
                intent = TOOL.maintenance_canonical_intent_data(raw, producer, current=True)
                self.assertEqual(TOOL.maintenance_intent_canonical_bytes_data(raw, producer, current=True), raw)
                self.assertEqual("freshBirth" in intent, vector["hasFreshBirth"])
                self.assertEqual(TOOL.maintenance_intent_data(raw, producer, current=False), intent)
                if vector["hasFreshBirth"]:
                    self.assertEqual(TOOL.maintenance_fresh_birth_intent_data(raw, producer), intent)
                    self.assertLessEqual(len(TOOL.canonical(intent["freshBirth"])) + 1, TOOL.FRESH_BIRTH_BYTES)
                    self.assertNotIn("sourceTree", intent["freshBirth"])
                    self.assertEqual(intent["next"], producer["releaseSet"]["current"])
                else:
                    with self.assertRaisesRegex(TOOL.Refused, "maintenance-fresh-birth-required"):
                        TOOL.maintenance_fresh_birth_intent_data(raw, producer)
        self.assertEqual(TOOL.FRESH_BIRTH_BYTES, 2 * 1024)

    def test_shared_rejections_cover_closed_identity_and_birth_fields(self):
        vector = CORPUS["vectors"][1]
        original = json.loads(vector["canonical"])
        for mutation in CORPUS["invalidMutations"]:
            with self.subTest(mutation=mutation["name"]), self.assertRaises(TOOL.Refused):
                TOOL.maintenance_intent_data(TOOL.canonical(changed(original, mutation)), selected(vector), current=True)
        for action in ("update", "same-package-noop", "restore-fixed-app", "uninstall"):
            with self.subTest(action=action), self.assertRaises(TOOL.Refused):
                TOOL.maintenance_intent_data(TOOL.canonical(dict(original, action=action)), selected(vector), current=True)
        with self.assertRaises(TOOL.Refused):
            TOOL.maintenance_intent_data(TOOL.canonical(dict(original, target="x86_64-apple-darwin")),
                                         selected(vector), current=True)

    def test_strict_entry_rejects_noncanonical_duplicate_torn_and_oversized(self):
        vector = CORPUS["vectors"][1]
        raw = vector["canonical"].encode()
        producer = selected(vector)
        sorted_raw = TOOL.canonical(json.loads(raw))
        self.assertEqual(TOOL.maintenance_intent_canonical_bytes_data(sorted_raw, producer, current=True), raw)
        for noncanonical in (sorted_raw, raw[:-1], raw + b"\n", b" " + raw):
            with self.subTest(raw=noncanonical[:30]), self.assertRaises(TOOL.Refused):
                TOOL.maintenance_fresh_birth_intent_data(noncanonical, producer)
        duplicate = raw.replace(b'"freshBirth":', b'"freshBirth":null,"freshBirth":', 1)
        for malformed in (duplicate, raw[:-2], b" " * (16 * 1024 + 1), b"[]", b"\xff"):
            with self.subTest(raw=malformed[:30]), self.assertRaises(TOOL.Refused):
                TOOL.maintenance_intent_data(malformed, producer, current=True)

    def test_recorded_predecessor_does_not_become_current_birth(self):
        vector = CORPUS["vectors"][1]
        value = json.loads(vector["canonical"])
        value["next"] = vector["releaseSet"]["acceptedPredecessors"][0]
        body = TOOL.canonical(value)
        producer = selected(vector)
        recorded = TOOL.maintenance_intent_canonical_bytes_data(body, producer, current=False)
        self.assertEqual(TOOL.maintenance_canonical_intent_data(recorded, producer, current=False), value)
        for reader in (lambda: TOOL.maintenance_intent_data(recorded, producer, current=True),
                       lambda: TOOL.maintenance_fresh_birth_intent_data(recorded, producer)):
            with self.assertRaises(TOOL.Refused):
                reader()

    def test_completed_history_binds_whole_birth_intent_and_keeps_roster(self):
        # Synthetic successful-record DATA only; these facts do not authorize
        # any filesystem effect or establish an actual native worker result.
        for vector in CORPUS["vectors"]:
            with self.subTest(vector=vector["name"]):
                body = vector["canonical"].encode()
                intent = json.loads(body)
                invocation, request = intent["invocation"], intent["requestId"]
                directory = {"device": 1, "inode": 201, "mode": 0o040755, "uid": 0, "gid": 0, "flags": 0}
                app = dict(directory, inode=202, mode=0o040555)
                generation = {"release": intent["next"], "instance": invocation, "releaseDirectory": directory,
                              "app": {"location": "canonical", "identity": app}}
                state = {"schemaVersion": 2, "kind": "mrk-macos-maintenance-state-v2", "target": intent["target"],
                         "invocation": invocation, "requestId": request, "capsuleInvocation": invocation,
                         "intendedAction": "fresh-install", "phase": "mutation-recorded", "current": generation,
                         "retained": [], "previousEvidence": [], "residue": None}
                state_body = TOOL.canonical(state)
                writer = {"returned": True, "exitCode": 0, "originalJoined": True, "resultEof": True,
                          "originalClosesKnown": True, "withinOriginalDeadline": True,
                          "payloadWriteCount": 1, "payloadWriteBytes": 1}
                capsule = {"schemaVersion": 2, "kind": "mrk-macos-maintenance-capsule-v2", "target": intent["target"],
                           "invocation": invocation, "requestId": request, "intendedAction": "fresh-install", "previous": None,
                           "next": intent["next"], "actualCurrent": intent["next"], "intentSha256": TOOL.digest(body),
                           "stateSha256": TOOL.digest(state_body), "outcome": "applied", "writer": writer}
                capsule_body = TOOL.canonical(capsule)
                result = {"invocation": invocation, "requestId": request, "action": "fresh-install",
                          "intentSha256": TOOL.digest(body), "stateSha256": TOOL.digest(state_body),
                          "capsuleSha256": TOOL.digest(capsule_body), "payloadWriteCount": 1, "payloadWriteBytes": 1}
                records = {invocation: (body, state_body, capsule_body)}
                actual_state, parsed = TOOL.maintenance_history_data(result, records, selected(vector))
                self.assertEqual(actual_state, state)
                self.assertEqual(parsed[invocation][0], intent)
                names, stages = TOOL.maintenance_roster_data(state, parsed, vector["target"])
                self.assertIn(f".maintenance-{invocation}.intent.json", names)
                self.assertEqual(stages, {f".install-{invocation}"})
                self.assertFalse(any("birth" in name for name in names))
                if vector["hasFreshBirth"]:
                    altered = copy.deepcopy(intent)
                    altered["freshBirth"]["producerDescriptorSha256"] = "e" * 64
                    altered_body = TOOL.maintenance_intent_canonical_bytes_data(TOOL.canonical(altered), selected(vector), current=True)
                    with self.assertRaisesRegex(TOOL.Refused, "maintenance-linked-records"):
                        TOOL.maintenance_history_data(result, {invocation: (altered_body, state_body, capsule_body)}, selected(vector))


if __name__ == "__main__":
    unittest.main()
