"""Tiny genuine DATA/owned-file regressions; never run a signer or vendor code."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import struct
import tempfile
import threading
import types
import unittest
from unittest import mock
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def signature_blob(flags=0x10000, *, cms=True):
    # Deliberately NONCRYPTOGRAPHIC CodeDirectory/CMS envelope DATA. No usable
    # certificate, signature or timestamp: native codesign remains necessary.
    directory = struct.pack('>IIII', 0xfade0c02, 44, 0x20400, flags) + bytes(28)
    wrapper = struct.pack('>II', 0xfade0b01, 9) + b'X'
    rows = [(0, directory)] + ([(0x10000, wrapper)] if cms else [])
    offset = 12 + 8 * len(rows)
    indexes, bodies = [], []
    for slot, body in rows:
        indexes.append(struct.pack('>II', slot, offset)); bodies.append(body)
        offset += len(body)
    return struct.pack('>III', 0xfade0cc0, offset, len(rows)) + b''.join(indexes + bodies)


def thin(cpu, subtype, *, signed=False, runtime=True, flags=0, cms=True):
    is32 = cpu == 7
    signature = signature_blob(0x10000 if runtime else 0, cms=cms) if signed else b''
    if is32:
        segment = struct.pack('<II16sIIIIIIII', 1, 56, b'__LINKEDIT', 0, 4096,
                              256, 64 + len(signature), 7, 1, 0, 0)
    else:
        segment = struct.pack('<II16sQQQQIIII', 0x19, 72, b'__LINKEDIT', 0, 4096,
                              256, 64 + len(signature), 7, 1, 0, 0)
    commands = [segment, struct.pack('<II16s', 0x1b, 24, b'UNCHANGED-UUID!!!'),
                struct.pack('<IIIIII', 0x32, 24, 1, 0x000a0b00, 0x000a0b00, 0)]
    if signed:
        commands.append(struct.pack('<IIII', 0x1d, 16, 320, len(signature)))
    header = struct.pack('<IiiIIII', 0xfeedface if is32 else 0xfeedfacf, cpu, subtype,
                         6 if is32 or not runtime else 2, len(commands), sum(map(len, commands)), flags)
    if not is32:
        header += bytes(4)
    body = header + b''.join(commands)
    body += bytes(256 - len(body)) + b'ACTUAL-CODE-DATA' + bytes(48)
    assert len(body) == 320
    return body + signature


def fat(*, jna=False, signed=False, runtime=True, cms=True):
    architectures = ((7, 3), (0x1000007, 3)) if jna else ((0x1000007, 3), (0x100000c, 0))
    slices = [thin(cpu, sub, signed=signed, runtime=runtime, cms=cms) for cpu, sub in architectures]
    offsets, position = [], 48
    for body in slices:
        position = (position + 4095) & ~4095
        offsets.append(position); position += len(body)
    result = bytearray(struct.pack('>II', 0xcafebabe, 2))
    for (cpu, sub), offset, body in zip(architectures, offsets, slices):
        result.extend(struct.pack('>iiIII', cpu, sub, offset, len(body), 12))
    for offset, body in zip(offsets, slices):
        result.extend(bytes(offset - len(result))); result.extend(body)
    return bytes(result)


def zip_body(rows, *, method=zipfile.ZIP_STORED, utf8=True):
    output = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(output, 'w', allowZip64=False) as archive:
        warnings.simplefilter('ignore', UserWarning)  # Deliberate duplicate fixture.
        for name, body, mode in rows:
            entry = zipfile.ZipInfo(name, (2024, 1, 2, 3, 4, 6))
            entry.compress_type = method
            entry.create_system = 3
            entry.create_version = entry.extract_version = 10 if method == 0 else 20
            entry.external_attr = mode << 16
            entry.internal_attr = 1
            entry.comment = b'unchanged-member-comment'
            archive.writestr(entry, body)
    raw = bytearray(output.getvalue())
    if utf8:
        # The real fixed originals mark even ASCII names as UTF-8. ZipFile's
        # writer does not, so set only that harmless paired header flag.
        central = struct.unpack_from('<I', raw, len(raw) - 6)[0]
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for entry in archive.infolist():
                struct.pack_into('<H', raw, entry.header_offset + 6, 2048)
                struct.pack_into('<H', raw, central + 8, 2048)
                lengths = struct.unpack_from('<HHH', raw, central + 28)
                central += 46 + sum(lengths)
    return bytes(raw)


def bundle_rows(*, signed=False):
    return [('META-INF/MANIFEST.MF', b'Manifest-Version: 1.0\r\n\r\n', 0o100644),
            ('NOTICE', b'unchanged legal text', 0o100644),
            ('pkg/Example.class', b'\xca\xfe\xba\xbe\0\0\0\x34class-not-mach-o', 0o100644),
            ('macos/aapt2', fat(signed=signed), 0o100755),
            ('com/sun/jna/darwin/libjnidispatch.jnilib', fat(jna=True, signed=signed, runtime=False), 0)]


class AndroidSupportSigningData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load('desktop/tools/macos_android_support_signing.py', 'android_support_signing_data')
        cls.helper = load('desktop/tools/macos_android_helper_package.py', 'android_support_package_data')

    def operation(self):
        m = self.module
        return types.SimpleNamespace(android_support={'started': 1, 'observed': 1, 'pending': False,
            'retiring': False, 'api': self.helper, 'complete': False}, calls=[], errors=[],
            credential_known=lambda: True, credential_failed=False, signing_mutation_pending=False,
            credential_active=None, credential_contexts=[], stager_io_pending=None)

    def context(self, op, role):
        if role.endswith('-final-verify'):
            op.credential_active = None
            op.credential_contexts = [{'purpose': purpose, 'closed': True} for purpose in
                                      ('bundletool-aapt2', 'bundletool-jna', 'agp-aapt2')]
        else:
            purpose = role.removesuffix('-verify').removesuffix('-sign')
            op.credential_active = {'purpose': purpose, 'ready': True, 'retiring': False,
                                    'roles': (purpose + '-sign', purpose + '-verify')}

    def test_repack_preserves_complete_non_native_bytes_and_logical_metadata(self):
        m = self.module
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            with self.subTest(method=method):
                original = zip_body(bundle_rows(), method=method, utf8=method == zipfile.ZIP_DEFLATED)
                replacements = {name: body for name, body, _ in bundle_rows(signed=True)
                                if name in ('macos/aapt2', 'com/sun/jna/darwin/libjnidispatch.jnilib')}
                before = m.zip_data(original)
                rebuilt = m.repack(original, replacements)
                after = m.zip_data(rebuilt)
                self.assertNotEqual(original, rebuilt)
                self.assertEqual(after['native'], replacements)
                self.assertEqual([r['metadata'] for r in before['rows']], [r['metadata'] for r in after['rows']])
                with zipfile.ZipFile(io.BytesIO(original)) as old_zip, zipfile.ZipFile(io.BytesIO(rebuilt)) as new_zip:
                    self.assertEqual([entry.flag_bits for entry in old_zip.infolist()],
                                     [entry.flag_bits for entry in new_zip.infolist()])
                for old, new in zip(before['rows'], after['rows']):
                    if old['metadata'][0] not in replacements:
                        self.assertEqual(old, new)
                self.assertEqual(after['inventorySha256'], m.sha(m.canonical(after['rows'])))
                self.assertEqual(before['decodedBytes'], sum(len(row[1]) for row in bundle_rows()))
                self.assertEqual(original, zip_body(bundle_rows(), method=method, utf8=method == zipfile.ZIP_DEFLATED))
        original = zip_body([('aapt2', fat(), 0o100755), ('NOTICE', b'AGP NOTICE', 0o100644)])
        rebuilt = m.repack(original, {'aapt2': fat(signed=True)})
        self.assertEqual(m.zip_data(rebuilt)['native'], {'aapt2': fat(signed=True)})
        for replacements in ({}, {'wrong': fat(signed=True)}, {'aapt2': b''}, {'aapt2': True},
                             {'aapt2': fat(signed=True), 'extra': b'x'}):
            with self.subTest(replacements=tuple(replacements)), self.assertRaises(m.Refused):
                m.repack(original, replacements)

    def test_zip_refuses_ambiguous_native_java_signature_and_crc_changes(self):
        m = self.module
        original = zip_body([('aapt2', fat(), 0o100755), ('NOTICE', b'legal', 0o100644)])
        bad_rows = [
            [('same', b'a', 0o100644), ('same', b'b', 0o100644)],
            [('../escape', b'x', 0o100644)], [('/absolute', b'x', 0o100644)],
            [('a\\b', b'x', 0o100644)], [('link', b'x', 0o120777)],
            [('nested.jar', b'PK\x03\x04data', 0o100644)], [('unlisted-native', fat(), 0o100755)],
            [('META-INF/OWNER.SF', b'signature', 0o100644)],
            [('META-INF/MANIFEST.MF', b'Name: a\r\nSHA-256-Digest: abc\r\n', 0o100644)]]
        for rows in bad_rows:
            with self.subTest(name=rows[0][0]), self.assertRaises((m.Refused, zipfile.BadZipFile)):
                m.zip_data(zip_body(rows))
        mutations = [b'', original + b'X']
        local = bytearray(original); local[14] ^= 1; mutations.append(bytes(local))
        central = bytearray(original); at = central.index(b'PK\x01\x02'); central[at + 16] ^= 1
        mutations.append(bytes(central))
        data = bytearray(original); data[30 + len('aapt2') + 100] ^= 1; mutations.append(bytes(data))
        for changed in mutations:
            with self.subTest(length=len(changed)), self.assertRaises((m.Refused, zipfile.BadZipFile)):
                m.zip_data(changed)
        for field, limit in (('ARCHIVE_LIMIT', len(original) - 1), ('ENTRY_LIMIT', 1),
                             ('DECODED_LIMIT', len(fat()) - 1), ('NATIVE_LIMIT', len(fat()) - 1)):
            with self.subTest(bound=field), mock.patch.object(m, field, limit), self.assertRaises(m.Refused):
                m.zip_data(original)

    def test_macho_signing_preserves_both_slices_code_sdk_and_loader(self):
        m = self.module
        for jna in (False, True):
            before, after = fat(jna=jna, runtime=not jna), fat(jna=jna, signed=True, runtime=not jna)
            m.content_unchanged(before, after)
            expected = [7, 0x1000007] if jna else [0x1000007, 0x100000c]
            self.assertEqual([row[0] for row in m.macho_slices(after)], expected)
            mutations = []
            code = bytearray(after); code[4096 + 256] ^= 1; mutations.append(code)
            flags = bytearray(after); flags[4096 + 24] ^= 1; mutations.append(flags)
            header = 28 if jna else 32
            segment = 56 if jna else 72
            loader = bytearray(after); loader[4096 + header + segment + 8] ^= 1; mutations.append(loader)
            sdk = bytearray(after); sdk[4096 + header + segment + 24 + 16] ^= 1; mutations.append(sdk)
            offset = bytearray(after); offset[4096 + header + (32 if jna else 40)] ^= 1; mutations.append(offset)
            vm = bytearray(after); vm[4096 + header + (28 if jna else 32)] ^= 1; mutations.append(vm)
            extent = bytearray(after); extent[4096 + header + (36 if jna else 48)] ^= 1; mutations.append(extent)
            shrunk = bytearray(after)
            struct.pack_into('<I', shrunk, 4096 + 20, struct.unpack_from('<I', before, 4096 + 20)[0] - 4)
            mutations.append(shrunk)
            padding = bytearray(after); padding[48] = 1; mutations.append(padding)
            subtype = bytearray(after); subtype[15] ^= 1; mutations.append(subtype)
            for index, changed in enumerate(mutations):
                with self.subTest(jna=jna, mutation=index), self.assertRaises(m.Refused):
                    m.content_unchanged(before, bytes(changed))
        with self.assertRaises(m.Refused):
            m.content_unchanged(fat(jna=True, runtime=False), fat(signed=True, runtime=False))
        with self.assertRaises(m.Refused):
            m.macho_slices(thin(7, 3, runtime=False))

    def test_signature_data_checks_all_slices_without_claiming_crypto(self):
        m = self.module
        for jna in (False, True):
            signed = fat(jna=jna, signed=True, runtime=not jna)
            rows = m.signature_data(signed, not jna)
            self.assertEqual(len(rows), 2)
            for row, (cpu, subtype, body) in zip(rows, m.macho_slices(signed)):
                self.assertEqual(row, {'cpuType': cpu, 'cpuSubtype': subtype, 'size': len(body),
                    'sha256': hashlib.sha256(body).hexdigest(), 'codeDirectoryFlags': [0 if jna else 0x10000],
                    'cmsPresent': True})
            with self.assertRaises(m.Refused):
                m.signature_data(fat(jna=jna, runtime=not jna), not jna)
            with self.assertRaises(m.Refused):
                m.signature_data(fat(jna=jna, signed=True, runtime=not jna, cms=False), not jna)
        with self.assertRaises(m.Refused):
            m.signature_data(fat(signed=True, runtime=False), True)
        with self.assertRaises(m.Refused):
            m.signature_data(fat(signed=True), 1)
        signed = fat(signed=True)
        for mutation in ('adhoc', 'overlap', 'duplicate-slot', 'missing-primary', 'range'):
            changed = bytearray(signed)
            blob = 4096 + 320
            if mutation == 'adhoc': struct.pack_into('>I', changed, blob + 28 + 12, 0x10002)
            elif mutation == 'overlap': struct.pack_into('>I', changed, blob + 24, 28)
            elif mutation == 'duplicate-slot': struct.pack_into('>I', changed, blob + 20, 0)
            elif mutation == 'missing-primary': struct.pack_into('>I', changed, blob + 12, 0x1000)
            else: struct.pack_into('>I', changed, blob + 4, 0xffffffff)
            with self.subTest(mutation=mutation), self.assertRaises(m.Refused):
                m.signature_data(bytes(changed), True)

    def test_nine_roles_preserve_first_failure_and_unknown_retirement(self):
        m = self.module
        expected = tuple(role + suffix for role in ('bundletool-aapt2', 'bundletool-jna', 'agp-aapt2')
                         for suffix in ('-sign', '-verify')) + tuple(
                         role + '-final-verify' for role in ('bundletool-aapt2', 'bundletool-jna', 'agp-aapt2'))
        self.assertEqual(m.ROLES, expected)
        op = self.operation()
        with mock.patch.object(m.time, 'monotonic_ns', return_value=2):
            for role in expected:
                op.signing_mutation_pending = role.endswith('-sign')
                self.context(op, role)
                with self.assertRaises(m.Refused): m.dispatch(op, 'unrelated')
                m.dispatch(op, role)
                op.calls.append({'role': role, 'returned': True, 'capturesSettled': True, 'returncode': 0})
                m.returned(op, role)
            op.signing_mutation_pending = False
            self.assertTrue(m.finish_ready(op))
            with self.assertRaises(m.Refused): m.dispatch(op, expected[-1])
            for code in (1, -1, True, None):
                broken = self.operation(); broken.calls = [{'role': expected[0], 'returned': True,
                    'capturesSettled': True, 'returncode': code}]
                self.context(broken, expected[1])
                with self.subTest(code=code), self.assertRaises(m.Refused): m.dispatch(broken, expected[1])
                broken.credential_active = None
                self.assertEqual(m.finish_ready(broken), type(code) is int and code == 1)
            for field in ('returned', 'capturesSettled'):
                broken = self.operation(); broken.calls = [dict(op.calls[0], **{field: False})]
                self.assertFalse(m.finish_ready(broken))
                self.context(broken, expected[1])
                with self.assertRaises(m.Refused): m.dispatch(broken, expected[1])
            for field, value in (('errors', ['original-failure']), ('credential_failed', True),
                                 ('signing_mutation_pending', True), ('stager_io_pending', 'unknown-write')):
                broken = self.operation(); setattr(broken, field, value)
                self.assertFalse(m.finish_ready(broken))
            broken = self.operation(); broken.android_support['pending'] = True
            self.assertFalse(m.finish_ready(broken))
            self.assertEqual(op.calls, [{'role': role, 'returned': True, 'capturesSettled': True,
                                        'returncode': 0} for role in expected])
            op.android_support['complete'] = True
            op.credential_calls = [dict(role=role, entered=True, returned=True, settled=True, status=0)
                for role in (self.helper.CREDENTIAL_ROLES[:17] + ('search-final', 'default-after')) * 3]
            op.credential_contexts = [dict(purpose=row[0], closed=True, retired=True,
                searchRestored=True, defaultUnchanged=True) for row in m.MEMBERS]
            self.assertTrue(m.success(op))
            for rows, key, bad in ((op.calls, 'returncode', 1), (op.credential_calls, 'status', -1),
                                   (op.credential_contexts, 'searchRestored', False)):
                original = rows[-1][key]
                rows[-1][key] = bad
                self.assertFalse(m.success(op))
                rows[-1][key] = original
            # Exercise the genuine Operation.call, not a replacement owner: the
            # only process port returns an inert CompletedProcess constructor.
            # This proves dispatch -> one original -> all captures -> returned,
            # and keeps known failure distinct from unreturned/uncaptured work.
            for outcome in ('zero', 'nonzero', 'signal', 'capture-failure', 'secret'):
                current = self.operation(); current.phase = m.PHASE
                current.calls = [dict(row) for row in op.calls[:6]]
                self.context(current, expected[6])
                current.android_support_module = m
                current.app_absence, current.removal = None, False
                current.removal_final_active = lambda: False
                current.removal_recorded_role = lambda value: value
                current.checkout = Path('/source-only')
                command = ['/usr/bin/codesign', 'INERT-DO-NOT-RUN']
                code = 1 if outcome == 'nonzero' else -15 if outcome == 'signal' else 0
                current.owner = types.SimpleNamespace(run_owned=mock.Mock(return_value=
                    self.helper.subprocess.CompletedProcess(command, code, b'fixed stdout', b'fixed stderr')))
                capture_failure = RuntimeError('INERT CAPTURE FAILURE')
                current.publish = mock.Mock(side_effect=capture_failure if outcome == 'capture-failure' else None)
                environment = {'MRK_MACOS_DEVELOPER_ID_P12_BASE64': 'INERT-NOT-A-KEY'} if outcome == 'secret' else {}
                if outcome == 'zero':
                    result = self.helper.Operation.call(current, expected[6], command, environment,
                                                        cwd=Path('/owned'), timeout=30, limit=65536)
                    self.assertEqual(result.returncode, 0)
                    self.assertTrue(current.calls[-1]['capturesSettled'])
                    self.assertEqual(current.publish.call_count, 3)
                    self.assertTrue(m.finish_ready(current))
                else:
                    with self.subTest(outcome=outcome), self.assertRaises(
                            RuntimeError if outcome == 'capture-failure' else self.helper.Refused) as failure:
                        self.helper.Operation.call(current, expected[6], command, environment,
                                                   cwd=Path('/owned'), timeout=30, limit=65536)
                    if outcome == 'capture-failure': self.assertIs(failure.exception, capture_failure)
                    if outcome == 'secret':
                        self.assertEqual(len(current.calls), 6)
                        current.owner.run_owned.assert_not_called()
                    else:
                        self.assertEqual(len(current.calls), 7)
                        self.assertEqual(current.calls[-1]['returned'], outcome != 'signal')
                        self.assertEqual(current.calls[-1]['capturesSettled'], outcome == 'nonzero')
                        self.assertEqual(m.finish_ready(current), outcome == 'nonzero')
                if outcome != 'secret':
                    current.owner.run_owned.assert_called_once_with(command, environ=environment,
                        cwd=Path('/owned'), timeout=30, capture=True, text=False, output_limit=65536)

    def test_original_endpoint_io_latch_and_fixed_signer_arguments(self):
        m = self.module
        op = self.operation()
        with mock.patch.object(m.time, 'monotonic_ns', return_value=1 + m.WORK_SECONDS * 10**9):
            with self.assertRaises(m.Refused): m.clock(op)
            m.clock(op, work=False)
        with mock.patch.object(m.time, 'monotonic_ns', return_value=1 + m.HARD_SECONDS * 10**9):
            with self.assertRaises(m.Refused): m.clock(op, work=False)
        with mock.patch.object(m.time, 'monotonic_ns', return_value=0):
            with self.assertRaises(m.Refused): m.clock(self.operation())
        sentinel = RuntimeError('SYNTHETIC FIRST FAILURE')
        op = self.operation()
        with mock.patch.object(m.time, 'monotonic_ns', return_value=2):
            with self.assertRaises(RuntimeError) as found:
                m._io(op, 'fixed-write', lambda: (_ for _ in ()).throw(sentinel))
            self.assertIs(found.exception, sentinel)
            self.assertEqual(op.stager_io_pending, 'fixed-write')
            self.assertFalse(m.finish_ready(op))
            with self.assertRaises(m.Refused): m._io(op, 'second-write', lambda: None)
        op = self.operation()
        op.signing = ('7CGZ2343AA', '5effa7d19bbe005b19c1617833cbe22186c2af96')
        op.checkout, op.work = Path('/repo'), Path('/fixed-owned-work')
        op.native_environment = lambda: {'PATH': '/usr/bin:/bin'}
        op.call = mock.Mock(return_value=types.SimpleNamespace(returncode=0))
        with mock.patch.object(m.time, 'monotonic_ns', return_value=2):
            for role in ('bundletool-aapt2', 'bundletool-jna', 'agp-aapt2'):
                runtime = role != 'bundletool-jna'
                m._call(op, role + '-sign', Path('/fixed-owned-work/native'), sign=True, requires_runtime=runtime)
                args, kwargs = op.call.call_args
                self.assertEqual(args[0], role + '-sign')
                self.assertEqual(args[1][:2], ['/usr/bin/codesign', '--force'])
                self.assertEqual(args[1][args[1].index('--sign') + 1], op.signing[1])
                self.assertIn('--timestamp', args[1]); self.assertNotIn('--arch', args[1])
                self.assertEqual('--options' in args[1], runtime)
                self.assertEqual('--entitlements' in args[1], runtime)
                self.assertEqual(kwargs['limit'], 65536)
                self.assertGreater(kwargs['timeout'], 0); self.assertLessEqual(kwargs['timeout'], 30)
                m._call(op, role + '-final-verify', Path('/fixed-owned-work/native'))
                command = op.call.call_args.args[1]
                self.assertEqual(command[:4], ['/usr/bin/codesign', '--verify', '--strict', '--all-architectures'])
                self.assertIn('--test-requirement', command)
                requirement = command[command.index('--test-requirement') + 1]
                self.assertIn(op.signing[0], requirement); self.assertIn(op.signing[1], requirement)
                self.assertIn(m.IDENTIFIERS[role], requirement)
                self.assertNotIn('--sign', command)
        # The only timer interfaces are inert ports here; no live signal is
        # installed and no public acquisition is attempted by this DATA test.
        for outcome in ('zero', 'body-error', 'expired'):
            error = RuntimeError('INERT DOWNLOAD FAILURE')
            with mock.patch.object(m.time, 'monotonic', side_effect=[100, 105, 110]), \
                 mock.patch.object(signal, 'getsignal', return_value=signal.SIG_DFL), \
                 mock.patch.object(signal, 'getitimer', return_value=(0.0, 0.0)), \
                 mock.patch.object(signal, 'signal') as install, \
                 mock.patch.object(signal, 'setitimer', return_value=(0.0, 0.0)) as timer, \
                 mock.patch.object(m, '_download_body') as body:
                if outcome == 'body-error': body.side_effect = error
                if outcome == 'expired':
                    body.side_effect = lambda _started: install.call_args_list[0].args[1](signal.SIGALRM, None)
                if outcome == 'zero': m.download()
                else:
                    with self.assertRaises(TimeoutError if outcome == 'expired' else RuntimeError) as caught:
                        m.download()
                    if outcome == 'body-error': self.assertIs(caught.exception, error)
                body.assert_called_once_with(100)
                self.assertEqual(timer.call_args_list, [mock.call(signal.ITIMER_REAL, 145), mock.call(signal.ITIMER_REAL, 0)])
                self.assertEqual(install.call_args_list[-1], mock.call(signal.SIGALRM, signal.SIG_DFL))
        with mock.patch.object(signal, 'getsignal', return_value=signal.SIG_IGN), \
             mock.patch.object(signal, 'signal') as install, mock.patch.object(signal, 'setitimer') as timer, \
             mock.patch.object(m, '_download_body') as body:
            with self.assertRaises(m.Refused): m.download()
            install.assert_not_called(); timer.assert_not_called(); body.assert_not_called()
        for cause in ('live-timer', 'not-main-thread'):
            with mock.patch.object(threading, 'current_thread', return_value=
                    object() if cause == 'not-main-thread' else threading.main_thread()), \
                 mock.patch.object(signal, 'getsignal', return_value=signal.SIG_DFL), \
                 mock.patch.object(signal, 'getitimer', return_value=(1.0, 0.0) if cause == 'live-timer' else (0.0, 0.0)), \
                 mock.patch.object(signal, 'signal') as install, mock.patch.object(signal, 'setitimer') as timer, \
                 mock.patch.object(m, '_download_body') as body:
                with self.subTest(timer=cause), self.assertRaises(m.Refused): m.download()
                install.assert_not_called(); timer.assert_not_called(); body.assert_not_called()
        for cause in ('install-error', 'arm-error', 'arm-collision', 'disarm-error'):
            error = OSError('INERT TIMER PORT FAILURE')
            timer_effect = ([error, (0.0, 0.0)] if cause == 'arm-error' else
                            [(1.0, 0.0), (0.0, 0.0)] if cause == 'arm-collision' else
                            [(0.0, 0.0), error] if cause == 'disarm-error' else None)
            with mock.patch.object(m.time, 'monotonic', side_effect=[100, 105, 110]), \
                 mock.patch.object(signal, 'getsignal', return_value=signal.SIG_DFL), \
                 mock.patch.object(signal, 'getitimer', return_value=(0.0, 0.0)), \
                 mock.patch.object(signal, 'signal', side_effect=[error, None] if cause == 'install-error' else None) as install, \
                 mock.patch.object(signal, 'setitimer', side_effect=timer_effect, return_value=(0.0, 0.0)) as timer, \
                 mock.patch.object(m, '_download_body') as body:
                with self.subTest(timer=cause), self.assertRaises(m.Refused if cause == 'arm-collision' else OSError) as caught:
                    m.download()
                if cause != 'arm-collision': self.assertIs(caught.exception, error)
                self.assertEqual(install.call_args_list[-1], mock.call(signal.SIGALRM, signal.SIG_DFL))
                self.assertEqual(timer.call_args_list[-1], mock.call(signal.ITIMER_REAL, 0))
                if cause == 'disarm-error': body.assert_called_once_with(100)
                else: body.assert_not_called()

    def test_publication_requires_settled_finality_and_keeps_delivery_files(self):
        m = self.module
        for missing in ('passed', 'complete', 'inputsRetired', 'targetRetired', 'originalClosesKnown'):
            op = self.operation()
            op.receipt = {'passed': True, 'targetRetired': True, 'originalClosesKnown': True}
            op.android_support.update(complete=True, inputsRetired=True)
            (op.receipt if missing in op.receipt else op.android_support)[missing] = False
            with self.subTest(missing=missing), mock.patch.object(m.os, 'open') as opened, self.assertRaises(m.Refused):
                m.publish_final(op)
            opened.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            op = self.operation(); op.work = Path(temporary)
            op.work_entry = {'identity': self.helper.directory_identity(op.work.lstat())}
            op.receipt = {'passed': True, 'targetRetired': True, 'originalClosesKnown': True}
            op.credential_calls, op.credential_contexts = [], []
            body = b'SYNTHETIC DERIVED DELIVERY ONLY'
            delivery = op.work / 'fixture.jar'; delivery.write_bytes(body); delivery.chmod(0o444)
            identity = self.helper.signature(delivery.lstat())
            op.android_support.update(complete=True, inputsRetired=True,
                delivery={'fixture.jar': ({'identity': identity}, m.sha(body), len(body))},
                receipt={'kind': 'INERT TEST RECEIPT', 'productReady': False, 'outerExitRequired': True})
            previous_umask = os.umask(0o077)
            try:
                with mock.patch.object(m.time, 'monotonic_ns', return_value=2):
                    m.publish_final(op)
                    with self.assertRaises(FileExistsError): m.publish_final(op)
            finally:
                os.umask(previous_umask)
            published = op.work / 'android-support-signed-receipt.json'
            raw = published.read_bytes(); value = json.loads(raw)
            self.assertEqual(raw, m.canonical(value) + b'\n')
            self.assertLessEqual(len(raw), 16384)
            self.assertEqual(stat.S_IMODE(published.stat().st_mode), 0o444)
            self.assertTrue(value['nonDeliveryScratchRetired'] and value['originalsClosed'])
            self.assertTrue(value['outerExitRequired']); self.assertFalse(value['productReady'])
            self.assertEqual(delivery.read_bytes(), body)
            self.assertEqual(self.helper.signature(delivery.lstat()), identity)
            self.assertNotIn(temporary, raw.decode())
        # Real existing file-custody methods on a six-file-size tiny fixture;
        # this is retirement DATA, not a pretend completed signer invocation.
        for mutation in ('none', 'capture-replaced', 'source-changed'):
            with tempfile.TemporaryDirectory() as temporary:
                op = self.operation(); op.work = Path(temporary)
                op.entries, op.entry_registry, op.directories = [], {}, {}
                op.app_absence, op.source_entry, op.package_sources = None, None, []
                for name in ('register', 'recheck_directory', 'directory', 'original', 'read', 'close'):
                    setattr(op, name, types.MethodType(getattr(self.helper.Operation, name), op))
                work_fd = os.open(temporary, self.helper.READ_FLAGS | os.O_DIRECTORY)
                op.work_entry = op.register(work_fd, 'inert-work', 'directory')
                op.work_entry['identity'] = self.helper.directory_identity(os.fstat(work_fd))
                try:
                    original_root = op.work / 'android-support-originals'; original_root.mkdir(mode=0o700)
                    root_entry = op.directory(op.work_entry, original_root.name, 'inert-originals')
                    def original(parent, name, body, mode):
                        path = (original_root if parent is root_entry else op.work) / name
                        path.write_bytes(body); path.chmod(mode)
                        return op.original(parent, name, 'inert-' + name, 4096, (mode,))
                    source = original(op.work_entry, 'source.py', b'SOURCE-A', 0o644)
                    original_input = original(root_entry, 'original.jar', b'ORIGINAL', 0o400)
                    capture_name = 'android-helper-bundletool-aapt2-sign.stdout'
                    capture = original(op.work_entry, capture_name, b'INERT CAPTURE', 0o600)
                    delivery_entry = original(op.work_entry, 'fixture.jar', b'DELIVERY', 0o444)
                    op.close(capture); op.close(delivery_entry)
                    op.package_sources = [(source, b'SOURCE-A')]
                    op.android_support.update(originalRoot=root_entry, inputs=[(original_input, b'ORIGINAL')],
                        sources=[], outputs={capture_name: (capture, capture['identity'])},
                        delivery={'fixture.jar': (delivery_entry, m.sha(b'DELIVERY'), 8)})
                    if mutation == 'capture-replaced':
                        (op.work / capture_name).rename(op.work / 'retained-original-capture')
                        (op.work / capture_name).write_bytes(b'REPLACEMENT')
                    elif mutation == 'source-changed':
                        (op.work / 'source.py').write_bytes(b'SOURCE-B')
                    with mock.patch.object(m.time, 'monotonic_ns', return_value=2):
                        if mutation == 'none':
                            m.retire(op)
                            self.assertTrue(op.android_support['inputsRetired'])
                            self.assertFalse(original_root.exists())
                            self.assertFalse((op.work / capture_name).exists())
                        else:
                            with self.assertRaises((m.Refused, self.helper.Refused)): m.retire(op)
                            self.assertIsNot(op.android_support.get('inputsRetired'), True)
                            self.assertTrue((op.work / capture_name).exists())
                            if mutation == 'source-changed': self.assertTrue(original_root.exists())
                    self.assertEqual((op.work / 'fixture.jar').read_bytes(), b'DELIVERY')
                    self.assertEqual(self.helper.signature((op.work / 'fixture.jar').lstat()), delivery_entry['identity'])
                finally:
                    for entry in reversed(op.entries): op.close(entry)
                    self.assertFalse(op.errors)

    def test_fixed_route_keeps_secrets_native_owner_and_outputs_closed(self):
        m = self.module
        workflow = (ROOT / '.github/workflows/desktop-macos-android-support-signing.yml').read_text()
        helper = (ROOT / 'desktop/tools/macos_android_helper_package.py').read_text()
        self.assertEqual(m.REF, 'refs/heads/verify/desktop-macos-android-support-signing')
        self.assertEqual(m.PHASE, 'android-support-shipping')
        self.assertEqual((m.WORK_SECONDS, m.HARD_SECONDS), (960, 1020))
        self.assertEqual((m.ARCHIVE_LIMIT, m.NATIVE_LIMIT, m.DECODED_LIMIT, m.ENTRY_LIMIT),
                         (48 * 1024**2, 16 * 1024**2, 112 * 1024**2, 16000))
        self.assertEqual(len(m.SPECS), 2); self.assertEqual(len(m.MEMBERS), 3)
        h = self.helper
        self.assertEqual(h.entrypoint(['helper', m.PHASE, '--target', h.ARM_TARGET]), (m.PHASE, h.ARM_TARGET))
        self.assertNotIn(m.PHASE, h.PHASES)
        for argv in (['helper', 'android-support-arbitrary'], ['helper', m.PHASE, '--other', h.ARM_TARGET],
                     ['helper', m.PHASE, '--target', 'unrelated-target']):
            with self.assertRaises(h.Refused): h.entrypoint(argv)
        source = '1' * 40
        environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS',
            'RUNNER_ARCH': 'ARM64', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REPOSITORY': 'Apdelrahman1911/mobile-release-kit',
            'GITHUB_WORKSPACE': str(h.CHECKOUT), 'GITHUB_WORKFLOW_SHA': source, 'GITHUB_SHA': source,
            'GITHUB_REF': m.REF, 'GITHUB_WORKFLOW_REF': 'Apdelrahman1911/mobile-release-kit/.github/workflows/' + m.WORKFLOW + '@' + m.REF,
            'MRK_EXPECTED_SHA': source, 'MRK_MACOS_INSTALL_SOURCE_COMMIT': source,
            'DEVELOPER_DIR': '/Library/Developer/CommandLineTools', 'MACOSX_DEPLOYMENT_TARGET': '26.0',
            'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1',
            'MRK_MACOS_WORK': str(h.WORK_PARENT / (m.PREFIX + '.Ab12Cd34'))}
        with mock.patch.object(h.sys, 'platform', 'darwin'), mock.patch.object(h.os, 'uname',
                return_value=types.SimpleNamespace(machine='arm64')), \
             mock.patch.object(h.os, 'getuid', return_value=501), mock.patch.object(h.os, 'geteuid', return_value=501), \
             mock.patch.object(h.os, 'getgid', return_value=20), mock.patch.object(h.os, 'getegid', return_value=20), \
             mock.patch.object(h, '__file__', str(h.CHECKOUT / 'desktop/tools/macos_android_helper_package.py')):
            self.assertEqual(h.admit(environment, phase=m.PHASE), Path(environment['MRK_MACOS_WORK']))
            for key, value in (('GITHUB_REF', 'refs/heads/main'), ('GITHUB_EVENT_NAME', 'workflow_dispatch'),
                    ('GITHUB_WORKFLOW_SHA', '2' * 40), ('GITHUB_WORKFLOW_REF', 'wrong'), ('RUNNER_ARCH', 'X64'),
                    ('MRK_MACOS_WORK', '/arbitrary'), ('MRK_MACOS_PACKAGE_ROLE', 'ordinary-image'),
                    ('MRK_MACOS_NOTARY_API_KEY_BASE64', 'INERT-NOT-A-KEY'),
                    ('MRK_MACOS_INSTALLER_P12_BASE64', 'INERT-NOT-A-KEY')):
                with self.subTest(admission=key), self.assertRaises(h.Refused):
                    h.admit(dict(environment, **{key: value}), phase=m.PHASE)
            for phase, target in ((None, h.ARM_TARGET), ('prepare', h.ARM_TARGET), (m.PHASE, h.INTEL_TARGET)):
                with self.assertRaises(h.Refused): h.admit(environment, phase=phase, target=target)
        for role in ('bundletool-aapt2', 'bundletool-jna', 'agp-aapt2'):
            self.assertIn(role, helper)
        for value in ('macos-developer-id', 'persist-credentials: false', 'github.sha',
                      'android-support-signed-receipt.json', 'macos_android_support_signing.py'):
            self.assertIn(value, workflow)
        for forbidden in ('workflow_dispatch:', 'notarytool', 'gh release', 'MRK_MACOS_INSTALLER_P12', 'upload-artifact@main'):
            self.assertNotIn(forbidden, workflow)
        tree = ast.parse(helper)
        operation = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Operation')
        methods = {n.name: n for n in operation.body if isinstance(n, ast.FunctionDef)}
        self.assertIn('call', methods); self.assertIn('finish', methods); self.assertIn('credential_scope', methods)
        # The new path must keep the original call owner, not shell out through
        # a signer invented inside the adapter.
        adapter = (ROOT / 'desktop/tools/macos_android_support_signing.py').read_text()
        self.assertNotIn('subprocess.', adapter)
        self.assertNotIn('os.system(', adapter)
        # The real held-SOURCE loader registers only its own module while
        # loading, rejects collisions, checks POST, and removes its registration.
        # Capacity/clock are inert observations here, not hosted resource proof.
        module_name = 'mrk_android_support_adapter'
        body = adapter.encode()
        for outcome in ('zero', 'collision', 'source-changed'):
            entry = object()
            op = types.SimpleNamespace(source_original=mock.Mock(return_value=entry),
                read=mock.Mock(side_effect=[body, body + b'\n'] if outcome == 'source-changed' else None,
                               return_value=body), checkout=ROOT, package_sources=[], support_started=1,
                phase=m.PHASE, target=h.ARM_TARGET, work_entry={'fd': -1},
                environment={'MRK_ANDROID_SUPPORT_SOURCE_TREE': '1' * 40}, receipt={})
            initial = {h.__name__: h}
            if outcome == 'collision': initial[module_name] = sentinel = object()
            with mock.patch.dict(h.sys.modules, initial), \
                 mock.patch.object(h.time, 'monotonic_ns', return_value=2), \
                 mock.patch.object(h.os, 'fstatvfs', return_value=types.SimpleNamespace(
                     f_frsize=4096, f_bavail=384 * 1024**2 // 4096)):
                if outcome == 'zero':
                    h.Operation.android_support_load(op)
                    self.assertEqual(op.package_sources, [(entry, body)])
                    self.assertIs(op.android_support['api'], h)
                    self.assertEqual(op.android_support['started'], 1)
                else:
                    with self.assertRaises(h.Refused): h.Operation.android_support_load(op)
                if outcome == 'collision': self.assertIs(h.sys.modules[module_name], sentinel)
                else: self.assertNotIn(module_name, h.sys.modules)
            op.source_original.assert_called_once_with('desktop/tools/macos_android_support_signing.py',
                                                       'source-support-adapter', 65536)


if __name__ == '__main__':
    unittest.main()
