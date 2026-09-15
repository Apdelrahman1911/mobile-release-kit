"""Inert contracts for component instrumentation; not native crash evidence."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import types
import unittest
from pathlib import Path

from mobile_release import local_signing as signing
from workflow import local_signing_primitive_fixture as primitive


class ComponentContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-component-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        primitive.fixture.initialize(self.root)

    def test_original_caller_write_and_readable_buffer_close_are_actually_observed(self):
        # A fixture trampoline between the OS wrapper and origin() would drop
        # these events: the real production-module caller must remain visible.
        caller = types.ModuleType("mobile_release.credentials")
        exec("def write(call):\n    return call(17, b'fictional')\n"
             "def read(opening):\n    with opening(17, 'rb', closefd=False) as stream:\n"
             "        return stream.read(128)\n", caller.__dict__)
        trace = primitive.ComponentTrace(self.root, "contract", observe_states=False)
        trace.descriptors[17] = str(self.root / "home/algorithm.fixture")
        trace.active = True
        calls = []
        def write(fd, data):
            calls.append((fd, bytes(data)))
            return len(data)
        self.assertEqual(caller.write(trace.wrapper("write", write)), 9)
        self.assertEqual(calls, [(17, b"fictional")])
        self.assertEqual([event["operation"] for event in trace.events], ["write"])
        self.assertEqual(trace.events[0]["origin"], "mobile_release.credentials:write")
        opened = []
        stream = io.BytesIO(b"fictional readable buffer")
        def fdopen(*args, **kwargs):
            opened.append((args, kwargs))
            return stream
        self.assertEqual(caller.read(trace.fdopen(fdopen)), b"fictional readable buffer")
        self.assertEqual(opened, [((17, "rb"), {"closefd": False})])
        self.assertTrue(stream.closed)
        self.assertEqual([event["operation"] for event in trace.events],
                         ["write", "buffer.open", "buffer.read", "buffer.close"])
        self.assertTrue(all(event["succeeded"] for event in trace.events))
        self.assertEqual(trace.events[1]["details"], {"mode": "rb", "closefd": False})
        self.assertEqual(trace.descriptors[17], str(self.root / "home/algorithm.fixture"),
                         "closefd=False cannot retire the original descriptor")

        class FailedClose(io.BytesIO):
            def close(self):
                if self.closed:
                    return
                super().close()
                raise OSError("fictional close return lost")
        stream = FailedClose(b"read before the failed close")
        with self.assertRaisesRegex(OSError, "close return lost"):
            caller.read(trace.fdopen(fdopen))
        self.assertEqual(trace.events[-1]["operation"], "buffer.close")
        self.assertEqual(trace.events[-1]["error"], "OSError")
        self.assertFalse(trace.events[-1]["succeeded"])

    def test_partial_oracle_rejects_unrelated_changes_and_equal_byte_replacements(self):
        target = self.root / "home/state.pending"
        sibling = self.root / "home/sibling.fixture"
        target.write_bytes(b"")
        sibling.write_bytes(b"unrelated initial bytes")
        target.chmod(0o600)
        sibling.chmod(0o600)
        initial = primitive._identities(self.root)
        before = primitive._physical(self.root, initial)
        operand = primitive._control_bytes(primitive._NEW)
        prefix = operand[:len(operand) // 2]
        event = {"index": 1, "operation": "write", "slot": "<ROOT>/home/state.pending",
                 "origin": "mobile_release.local_signing:_write", "phase": "component", "occurrence": 1,
                 "details": {}, "succeeded": True}
        selected = {"event": event, "edge": "partial"}
        inventory = {"states": {"1": {"before": before}}}
        target.write_bytes(prefix)

        def publish():
            primitive.fixture.write_json(self.root / "cut-cut.json", {
                "nativeCommands": 0, "edge": "partial", "event": copy.deepcopy(event), "initial": initial,
                "physical": primitive._physical(self.root, initial), "generations": {},
                "atCutIdentities": primitive._identities(self.root),
                "partial": {"slot": event["slot"], "requested": len(operand), "prefixHex": prefix.hex()},
            })
        publish()
        result = primitive._assert_cut(self.root, "writer-state-first", selected, inventory)
        self.assertEqual(result["nativeCommands"], 0)
        self.assertEqual(result["edge"], "partial")
        for change in ("other-bytes", "other-mode", "same-bytes-new-inode", "wrong-prefix"):
            with self.subTest(change=change):
                if change == "other-bytes":
                    sibling.write_bytes(b"changed unrelated bytes")
                elif change == "other-mode":
                    sibling.chmod(0o640)
                elif change == "same-bytes-new-inode":
                    replacement = self.root / "replacement.fixture"
                    replacement.write_bytes(sibling.read_bytes())
                    replacement.chmod(sibling.stat().st_mode & 0o777)
                    replacement.replace(sibling)
                else:
                    target.write_bytes(b"X" + prefix[1:])
                publish()  # Even a self-consistent changed snapshot is not the oracle.
                with self.assertRaises(AssertionError):
                    primitive._assert_cut(self.root, "writer-state-first", selected, inventory)
                sibling.write_bytes(b"unrelated initial bytes")
                sibling.chmod(0o600)
                target.write_bytes(prefix)
                # Restore the test fixture's independent starting generation
                # for the next distinct mutation, not production authority.
                initial = primitive._identities(self.root)
                before = primitive._physical(self.root, initial)
                before["home/state.pending"].update(size=0, sha256=hashlib.sha256(b"").hexdigest())
                inventory = {"states": {"1": {"before": before}}}

        # A genuinely NEW stage has no initial alias. Bind its actual creation
        # identity through link/rename, then replace it with indistinguishable
        # bytes/mode/link-count after the cut. Cross-case normalized state and
        # same-case post-wait identity are separate necessary checks.
        initial = primitive._identities(self.root)
        stage, published, alias = (self.root / "home" / name for name in
                                   ("new-stage", "published", "alias"))
        stage.write_bytes(b"new generation")
        stage.chmod(0o600)
        created_by = {"operation": "open", "event": 8}
        generations = {primitive._identity_key(stage.stat()): created_by}
        alias.hardlink_to(stage)
        stage.rename(published)
        physical = primitive._physical(self.root, initial, generations)
        self.assertEqual(physical["home/published"]["createdBy"], created_by)
        self.assertEqual(physical["home/alias"]["createdBy"], created_by)
        self.assertEqual(physical["home/published"]["aliases"], ["home/alias", "home/published"])
        self.assertEqual(physical["home/published"]["initialAliases"], [])
        link_event = {**event, "index": 9, "operation": "link", "slot": "<ROOT>/home/new-stage",
                      "details": {"destination": "<ROOT>/home/alias"}}
        selected = {"event": link_event, "edge": "after"}
        inventory = {"states": {"9": {"after": physical}}}
        primitive.fixture.write_json(self.root / "cut-cut.json", {
            "nativeCommands": 0, "edge": "after", "event": link_event, "initial": initial,
            "generations": generations, "atCutIdentities": primitive._identities(self.root),
            "physical": physical, "partial": None,
        })
        primitive._assert_cut(self.root, "installer-owned", selected, inventory)
        replacement = self.root / "replacement.fixture"
        replacement.write_bytes(published.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(published)
        alias.unlink()
        alias.hardlink_to(published)
        with self.assertRaisesRegex(AssertionError, "inode changed"):
            primitive._assert_cut(self.root, "installer-owned", selected, inventory)
        with self.assertRaisesRegex(AssertionError, "unobserved algorithm creation"):
            primitive._physical(self.root, initial, generations)

    def test_component_boundaries_refuse_command_dispatch_and_do_not_alias_trace_target(self):
        trace = primitive.FailureTrace(self.root, "read-before", self.root / "home/reader.fixture",
                                       self.root / "home/reader.pending", self.root / "replacement")
        self.assertIsNone(trace.target)
        self.assertEqual(trace.target_path, self.root / "home/reader.fixture")
        # An inherited target collision must fail here, before any acquisition.
        event = trace.begin("open", "fixture", "mobile_release.local_signing:_read_regular", {})
        trace.end(event, succeeded=True)
        with trace.installed():
            with self.assertRaisesRegex(AssertionError, "native/signing command"):
                signing.SigningSession._call(None, ["not-executed"])
            with self.assertRaisesRegex(AssertionError, "native/signing command"):
                signing.SigningSession._new_scope(None)
        self.assertEqual(json.loads((self.root / "observed-native.json").read_bytes())["calls"], [])


if __name__ == "__main__":
    unittest.main()
