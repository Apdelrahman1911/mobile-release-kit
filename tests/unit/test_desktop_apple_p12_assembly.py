"""Inert original-capture/framing tests, never a native binding/join proof.

All original-outcome observations below are explicitly synthetic DATA. No
command, filesystem, certificate, key, password source or provider is invoked.
"""
from pathlib import Path
import struct
from types import SimpleNamespace as Data
import unittest
from unittest.mock import patch

from mobile_release import _desktop_apple_p12_assembly as subject
from mobile_release.apple_provisioning_api import ProvisioningError


def frame(body=b"not-a-real-p12", *, leaf=b"L" * 32, spki=b"S" * 32):
    return subject.MAGIC + struct.pack(">I", len(body)) + leaf + spki + body


def child(raw):
    value = object.__new__(subject.P12AssemblyWork)
    for name in value.__slots__:
        setattr(value, name, None)
    value._started = value._claimed = True
    value._complete = value._retired = value._command_active = False
    value._inputs = ()
    value._leaf_hash, value._spki_hash = (b"L" * 32).hex(), (b"S" * 32).hex()
    errors = []
    operation = Data(guard=Data(), source=Data(), runtime=Data(), remember=errors.append,
                     request=Data(context={"mode": subject.MODE}))
    value._operation, value._source, value._runtime = operation, operation.source, operation.runtime
    operation._p12_assembly = value
    value._slot = Data(_engine=Data(outputs=[bytearray(raw or b""), bytearray()], decoded=(raw, b"")))
    return value, errors


class P12AssemblyTests(unittest.TestCase):
    def test_private_frame_borrows_original_and_metadata_has_no_password_or_body(self):
        raw = frame()
        parts = subject._parts(raw)
        self.assertTrue(all(part.obj is raw for part in parts))
        metadata = subject.output_metadata(raw)
        self.assertEqual(set(metadata), {"frameBytes", "frameSha256", "p12Bytes", "p12Sha256", "leafSha256", "spkiSha256"})
        self.assertEqual(metadata["p12Bytes"], len(parts[0]))
        self.assertEqual(metadata["leafSha256"], (b"L" * 32).hex())
        self.assertNotIn("password", metadata)

    def test_truncation_trailing_cross_family_and_excess_length_refuse_before_copy(self):
        raw = frame()
        for bad in (raw[:0], raw[:len(subject.MAGIC)], raw[:subject.HEADER], raw[:-1], raw + b"x",
                    subject.MAGIC + struct.pack(">I", 2**32 - 1) + b"x" * 65,
                    b"MRK-APPLE-DISTRIBUTION-KEY/1\n" + raw, bytearray(raw)):
            with self.subTest(shape=type(bad).__name__):
                with self.assertRaises(ProvisioningError):
                    subject._parts(bad)

    def test_fixed_certificate_frame_is_comparison_data_not_generic_chain_input(self):
        data = subject._certificates_frame(b"leaf-data", b"intermediate-data", b"root-data")
        self.assertTrue(data.startswith(subject.CERTIFICATES_MAGIC))
        for parts in ((b"", b"int", b"root"), (b"same", b"same", b"root"),
                      (b"x" * (subject.CERTIFICATE_LIMIT + 1), b"int", b"root"),
                      (b"x" * 65536, b"y" * 65536, b"z"), (bytearray(b"leaf"), b"int", b"root")):
            with self.assertRaises(ProvisioningError):
                subject._certificates_frame(*parts)

    def test_unknown_original_never_becomes_returned_or_disposable(self):
        value, _ = child(frame())
        original = value._slot
        with patch.object(subject.P12AssemblyWork, "_outcome", return_value=None):
            self.assertFalse(value._capture_returned())
            self.assertFalse(value._never_assembled())
        self.assertIs(value._slot, original)
        self.assertIsNone(value._frame)
        self.assertFalse(value.private_closed())

    def test_late_stop_keeps_complete_original_capture_without_success_or_reassembly(self):
        raw = frame()
        value, _ = child(raw)
        value._failure = True
        with patch.object(subject.P12AssemblyWork, "_outcome", return_value=Data(no_target=None, result_integrity="complete", returncode=0)):
            self.assertTrue(value._capture_returned())
            self.assertFalse(value._never_assembled())
        self.assertIs(value._frame, raw)
        self.assertTrue(value._failure)
        self.assertFalse(value._complete)
        self.assertFalse(value.private_closed())

    def test_malformed_returned_bytes_remain_retained_with_fixed_redacted_failure(self):
        raw = b"synthetic-private-DO-NOT-RENDER"
        value, _ = child(raw)
        with patch.object(subject.P12AssemblyWork, "_outcome", return_value=Data(no_target=None, result_integrity="complete", returncode=0)):
            with self.assertRaises(ProvisioningError) as caught:
                value._capture_returned()
        self.assertIs(value._frame, raw)
        self.assertNotIn(raw.decode(), str(caught.exception))
        self.assertNotIn(raw.decode(), repr(value))
        self.assertFalse(value.private_closed())

    def test_full_original_leaf_and_spki_metadata_must_match_before_any_transfer(self):
        for raw in (frame(leaf=b"F" * 32), frame(spki=b"F" * 32)):
            value, _ = child(raw)
            with patch.object(subject.P12AssemblyWork, "_outcome", return_value=Data(no_target=None, result_integrity="complete", returncode=0)):
                with self.assertRaises(ProvisioningError):
                    value._capture_returned()
            self.assertIs(value._frame, raw)
            self.assertFalse(value.private_closed())

    def test_empty_failed_command_is_not_no_assembly_and_actual_slot_binding_is_once(self):
        value, _ = child(b"")
        with patch.object(subject.P12AssemblyWork, "_outcome", return_value=Data(no_target=None, result_integrity="incomplete", returncode=-15)):
            self.assertFalse(value._capture_returned())
            self.assertFalse(value._never_assembled())
        from mobile_release._command_process import CommandOutcomeSlot, _Outer
        value._slot = None
        engine, slot = object.__new__(_Outer), object.__new__(CommandOutcomeSlot)
        slot._engine, engine.slot = engine, slot
        engine.guard = value._operation.guard
        engine.scope = engine.binding = engine.evidence = engine._store_timing = None
        engine.owns = engine.text = False
        value.bind_command_slot(engine, slot)
        self.assertIs(value._slot, slot)
        with self.assertRaises(ProvisioningError):
            value.bind_command_slot(engine, slot)
        value._slot = None
        engine.guard = Data()
        with self.assertRaises(ProvisioningError):
            value.bind_command_slot(engine, slot)

    def test_fixed_command_has_only_original_paths_and_no_password_or_p8_environment(self):
        value, _ = child(None)
        value._runtime.tooling_root = Path('/synthetic-owned-tooling')
        value._inputs = (object(), object(), object())
        from mobile_release.build_inputs import FiniteScratch
        value._scratch = object.__new__(FiniteScratch)
        with patch.object(subject.P12AssemblyWork, '_binding', return_value=None), \
             patch.object(FiniteScratch, 'require', side_effect=(Path('/own/pending-apple-key.mrk'), Path('/own/p12-password'), Path('/own/distribution-certificate.der'))):
            argv = value.argv(value._runtime)
        self.assertEqual(argv[:4], ('bundle', 'exec', 'ruby', '/synthetic-owned-tooling/fastlane/apple_provisioning_p12_assemble.rb'))
        self.assertEqual(len(argv), 7)
        value._claimed = False
        value._operation._base_environment = lambda: {'HOME': '/synthetic-owned-home'}
        with patch.object(subject.P12AssemblyWork, '_binding', return_value=None), \
             patch.object(subject.P12AssemblyWork, 'argv', return_value=argv):
            with self.assertRaises(ProvisioningError):
                value.admit_command(value._runtime, argv, environ={'HOME': '/synthetic-owned-home', 'MOBILE_RELEASE_ASC_KEY_ID': 'not-allowed'})
        self.assertFalse(value._claimed)

    def test_known_pre_transfer_stop_disposes_only_after_same_returned_command_and_cleanup(self):
        from mobile_release._desktop_apple_p12_private import P12Output
        raw = frame(); value, _ = child(raw)
        value._frame, value._parts = raw, subject._parts(raw)
        value._scratch = None
        output = object.__new__(P12Output)
        output._child, output._raw = value, raw
        output._claimed = output._body_done = output._acknowledged = False
        output._bytes, output._ack = 0, None
        op = value._operation
        op._p12_output, op._close_claimed, op._pending, op.primary = output, True, None, KeyboardInterrupt()
        op.guard.lifetime_ledger = Data(verdict=lambda: Data(cleanup_complete=True, contained=True, profile_calls=0, fatal=False))
        with patch.object(subject.P12AssemblyWork, '_outcome', return_value=Data(no_target=None, result_integrity='complete', returncode=0)):
            value.retire(output)
        self.assertTrue(value.private_closed())
        # This only proves this worker reference cut with synthetic C/A/W
        # DATA. No native NoSaveJoined, Store outcome or cleanup is fabricated.

    def test_attempted_or_unknown_transfer_never_uses_the_known_no_save_worker_cut(self):
        from mobile_release._desktop_apple_p12_private import P12Output
        for claimed, body_done, acknowledged in ((True, False, False), (True, True, False), (False, False, False)):
            raw = frame(); value, _ = child(raw)
            value._frame, value._parts, value._scratch = raw, subject._parts(raw), None
            output = object.__new__(P12Output)
            output._child, output._raw = value, raw
            output._claimed, output._body_done, output._acknowledged = claimed, body_done, acknowledged
            output._bytes, output._ack = 1 if claimed else 0, None
            op = value._operation
            op._p12_output, op._close_claimed, op._pending = output, True, None
            op.primary = KeyboardInterrupt() if claimed else RuntimeError('unclassified failure')
            op.guard.lifetime_ledger = Data(verdict=lambda: Data(cleanup_complete=True, contained=True, profile_calls=0, fatal=False))
            with patch.object(subject.P12AssemblyWork, '_outcome', return_value=Data(no_target=None, result_integrity='complete', returncode=0)):
                with self.assertRaises(ProvisioningError): value.retire(output)
            self.assertIs(value._frame, raw)
            self.assertFalse(value.private_closed())

    def test_stop_without_original_cleanup_cannot_dispose_derived_private_material(self):
        from mobile_release._desktop_apple_p12_private import P12Output
        raw = frame(); value, _ = child(raw)
        value._frame, value._parts, value._scratch = raw, subject._parts(raw), None
        output = object.__new__(P12Output)
        output._child, output._raw, output._claimed, output._bytes, output._ack = value, raw, False, 0, None
        output._body_done = output._acknowledged = False
        op = value._operation
        op._p12_output, op._close_claimed, op._pending, op.primary = output, True, None, KeyboardInterrupt()
        for flag in ('cleanup_complete', 'contained', 'fatal'):
            verdict = dict(cleanup_complete=True, contained=True, profile_calls=0, fatal=False)
            verdict[flag] = not verdict[flag]
            op.guard.lifetime_ledger = Data(verdict=lambda: Data(**verdict))
            with self.assertRaises(ProvisioningError): value.retire(output)
            self.assertIs(value._frame, raw)
            self.assertFalse(value.private_closed())


if __name__ == '__main__':
    unittest.main()
