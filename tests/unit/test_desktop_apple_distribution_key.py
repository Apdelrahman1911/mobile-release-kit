"""Inert framing/original-retention tests; NO key generation, files or C/A/W.

Patched outcome observations below are explicitly DATA, not constructed native
finality objects. They test the custody branch while native execution remains
unqualified. Every would-run command and scratch acquisition is replaced.
"""
import base64
from contextlib import nullcontext
from pathlib import Path
import struct
from types import SimpleNamespace as Data
import unittest
from unittest.mock import patch

from mobile_release import _desktop_apple_distribution_key as subject
from mobile_release.apple_provisioning_api import ProvisioningError


CSR = b"-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n"
PRIVATE, SPKI = b"not-a-private-key", b"not-a-public-key"


def frame(*, public=False, csr=CSR, private=PRIVATE, spki=SPKI):
    parts = (csr, spki) if public else (private, csr, spki)
    return (subject.PUBLIC_MAGIC if public else subject.MAGIC) + struct.pack(">" + "I" * len(parts), *map(len, parts)) + b"".join(parts)


def child(mode=subject.PREPARE_MODE, *, raw=None):
    # No production constructor or owner admission is bypassed by a live call:
    # these unstarted objects are used only under patched DATA observations.
    value = object.__new__(subject.AppleDistributionKeyWork)
    for name in value.__slots__:
        setattr(value, name, None)
    value._mode = mode
    value._started = value._claimed = True
    value._command_active = value._complete = value._retired = False
    value._failure = None
    errors = []
    operation = Data(guard=Data(), source=Data(), runtime=Data(), remember=errors.append,
                     _close_claimed=False, _pending=None, request=Data(context={"mode": mode}))
    value._operation = operation
    value._source = operation.source
    value._runtime = operation.runtime
    operation._distribution_key = value
    value._slot = Data(_engine=Data(outputs=[bytearray(raw or b""), bytearray()], decoded=(raw, b"")))
    return value, errors


class AppleDistributionKeyChildTests(unittest.TestCase):
    def test_exact_private_frame_and_encoded_restore_bounds(self):
        private = frame()
        parts = subject._parts(private, public=False)
        self.assertEqual(tuple(map(bytes, parts)), (PRIVATE, CSR, SPKI))
        self.assertTrue(all(value.obj is private for value in parts))
        material = (base64.b64encode(PRIVATE), CSR, base64.b64encode(SPKI))
        self.assertEqual(subject._stored_frame(material), private)
        for changed in ((material[0] + b"\n", CSR, material[2]), (b"?", CSR, material[2]),
                        (material[0], b"\xff", material[2]), (material[0], CSR, b"A" * 2000),
                        list(material), material + (b"foreign",)):
            with self.subTest(changed=type(changed).__name__):
                with self.assertRaises(ProvisioningError):
                    subject._stored_frame(changed)

    def test_frame_oversize_zero_trailing_and_public_private_crossing_refused(self):
        for raw in (frame() + b"x", frame()[:-1], subject.MAGIC + struct.pack(">III", 2**32 - 1, 1, 1) + b"xxx",
                    subject.MAGIC + struct.pack(">III", 0, len(CSR), 1) + CSR + b"x", frame(public=True)):
            with self.assertRaises(ProvisioningError):
                subject._parts(raw, public=False)
        with self.assertRaises(ProvisioningError):
            subject._parts(frame(), public=True)

    def test_unknown_original_keeps_raw_and_has_no_public_result_or_disposal(self):
        value, _ = child(raw=frame())
        original = value._slot
        with patch.object(subject.AppleDistributionKeyWork, "_outcome", return_value=None):
            self.assertFalse(value._capture_returned())
            self.assertFalse(value._never_generated())
        self.assertIs(value._slot, original)
        self.assertEqual(original._engine.outputs[0], frame())
        self.assertIsNone(value._frame)
        self.assertFalse(value.private_closed())

    def test_late_stop_keeps_joined_capture_but_never_exports_preparation_csr(self):
        value, _ = child(raw=frame())
        value._failure = True  # Original STOP before ordinary result return.
        original = value._slot
        observation = Data(no_target=None, result_integrity="complete", returncode=0)
        with patch.object(subject.AppleDistributionKeyWork, "_outcome", return_value=observation):
            self.assertTrue(value._capture_returned())
            self.assertFalse(value._never_generated())
        self.assertIs(value._slot, original)
        self.assertIs(value._frame, original._engine.decoded[0])
        self.assertTrue(value._failure)
        with patch.object(subject.AppleDistributionKeyWork, "_binding", return_value=None):
            with self.assertRaises(ProvisioningError):
                value.verified_public_parts(value._operation)
        self.assertFalse(value.private_closed())  # No native permit or saved ACK was constructed.

    def test_malformed_joined_output_is_retained_and_error_is_redacted(self):
        private = b"SYNTHETIC-SECRET-DO-NOT-LOG"
        value, _ = child(raw=private)
        with patch.object(subject.AppleDistributionKeyWork, "_outcome",
                          return_value=Data(no_target=None, result_integrity="complete", returncode=0)):
            with self.assertRaises(ProvisioningError) as caught:
                value._capture_returned()
        self.assertIs(value._frame, private)
        self.assertNotIn(private.decode(), str(caught.exception))
        self.assertNotIn(private.decode(), repr(value))
        self.assertFalse(value.private_closed())

    def test_empty_failed_generator_is_not_a_never_generated_proof(self):
        value, _ = child(raw=b"")
        with patch.object(subject.AppleDistributionKeyWork, "_outcome",
                          return_value=Data(no_target=None, result_integrity="incomplete", returncode=-15)):
            self.assertFalse(value._capture_returned())
            self.assertFalse(value._never_generated())
        # A never-entered command is only local comparison DATA. The native
        # AppleKeyNeverGeneratedJoined and its actual joins remain separate.
        value._claimed = False
        value._slot = None
        self.assertTrue(value._never_generated())

    def test_restored_public_result_must_match_exact_current_borrowed_key_parts(self):
        value, _ = child("key-recover", raw=frame(public=True))
        value._private_input = frame()
        observation = Data(no_target=None, result_integrity="complete", returncode=0)
        with patch.object(subject.AppleDistributionKeyWork, "_outcome", return_value=observation):
            self.assertTrue(value._capture_returned())
            value._slot._engine.decoded = (frame(public=True, spki=b"another-public-key"), b"")
            with self.assertRaises(ProvisioningError):
                value._capture_returned()
        self.assertFalse(value.private_closed())

    def test_original_slot_binding_is_exact_and_one_use_without_io(self):
        from mobile_release._command_process import CommandOutcomeSlot, _Outer
        value, _ = child()
        value._slot = None
        engine = object.__new__(_Outer)
        slot = object.__new__(CommandOutcomeSlot)
        slot._engine = engine
        engine.slot = slot
        engine.guard = value._operation.guard
        engine.scope = engine.binding = engine.evidence = engine._store_timing = None
        engine.owns, engine.text = False, False
        value.bind_command_slot(engine, slot)
        self.assertIs(value._slot, slot)
        with self.assertRaises(ProvisioningError):
            value.bind_command_slot(engine, slot)
        value._slot = None
        engine.guard = Data()  # Equal-shaped owner is not this original.
        with self.assertRaises(ProvisioningError):
            value.bind_command_slot(engine, slot)
        self.assertIsNone(value._slot)

    def test_late_capture_failure_cannot_replace_original_command_failure(self):
        value, errors = child()
        value._started = False
        primary = RuntimeError("synthetic-original-stop")
        secondary = ProvisioningError("synthetic-capture-failure")
        scratch = Data(_path=Path("/inert-owned-scratch"))
        value._scratch = scratch
        value._runtime.private_directory = Path("/inert-parent")
        value._runtime.command = lambda *_args, **_kwargs: nullcontext()
        value._operation._base_environment = lambda: {"LANG": "C"}
        argv = ("bundle", "exec", "ruby", "/inert-bundled-helper")
        with patch.object(subject.AppleDistributionKeyWork, "_binding", return_value=None), \
             patch.object(subject.AppleDistributionKeyWork, "argv", return_value=argv), \
             patch.object(subject.AppleDistributionKeyWork, "_capture_returned", side_effect=secondary), \
             patch.object(subject, "finite_scratch", return_value=nullcontext(scratch)), \
             patch.object(subject, "run_owned", side_effect=primary) as command:
            with self.assertRaises(RuntimeError) as caught:
                value.run()
        self.assertIs(caught.exception, primary)
        self.assertIs(errors[0], primary)
        self.assertIn(secondary, errors)
        command.assert_called_once()
        self.assertTrue(value._failure)
        self.assertFalse(value._command_active)
        self.assertIsNotNone(value._slot)

    def test_generated_frame_cannot_use_verifier_or_empty_custody_retirement(self):
        value, _ = child(raw=frame())
        value._frame = frame()
        value._operation._close_claimed = True
        value._operation.guard.lifetime_ledger = Data(verdict=lambda: Data(complete=True, fatal=False))
        with patch.object(subject.AppleDistributionKeyWork, "_scratch_closed", return_value=True), \
             patch.object(subject.AppleDistributionKeyWork, "_outcome",
                          return_value=Data(no_target=None, result_integrity="complete", returncode=0)):
            with self.assertRaises(ProvisioningError):
                value.retire_non_generated(value._operation)
        self.assertFalse(value.private_closed())
        self.assertIsNotNone(value._frame)


if __name__ == "__main__":
    unittest.main()
