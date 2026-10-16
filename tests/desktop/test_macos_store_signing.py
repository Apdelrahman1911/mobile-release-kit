"""Inert TAR/Mach-O DATA and existing-owner wiring; never invoke native tools."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


M = load('store_signing_test', 'desktop/tools/macos_store_signing.py')
API = load('store_signing_api_test', 'desktop/tools/macos_android_helper_package.py')
STAGER = load('store_signing_stager_test', 'desktop/tools/stage_macos_installed.py')
MATCHER = load('store_signing_matcher_test', 'desktop/tools/macos_cpython_orchestrator.py')


def native(*, signed=False, cpu=0x100000c, subtype=0, kind=2, flags=0x10000):
    # Deliberately noncryptographic signatures, never valid native evidence.
    directory = struct.pack('>IIII', 0xfade0c02, 44, 0x20400, flags) + bytes(28)
    cms = struct.pack('>II', 0xfade0b01, 9) + b'X'
    blob = struct.pack('>III', 0xfade0cc0, 28 + len(directory) + len(cms), 2)
    blob += struct.pack('>IIII', 0, 28, 0x10000, 28 + len(directory)) + directory + cms
    signature = blob if signed else b''
    segment = struct.pack('<II16sQQQQIIII', 0x19, 72, b'__LINKEDIT', 0, 4096, 256, 64 + len(signature), 7, 1, 0, 0)
    commands = [segment, struct.pack('<IIIIII', 0x32, 24, 1, 26 << 16, 26 << 16, 0)]
    if signed:
        commands.append(struct.pack('<IIII', 0x1d, 16, 320, len(signature)))
    header = struct.pack('<8I', 0xfeedfacf, cpu, subtype, kind, len(commands), sum(map(len, commands)), 0, 0)
    body = header + b''.join(commands)
    return body + bytes(256 - len(body)) + b'INERT-CODE-DATA!' + bytes(48) + signature


def tar(rows):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as archive:
        for name, data, kind in rows:
            entry = tarfile.TarInfo(name)
            entry.mode = 0o755 if name == 'runtime/bin/ruby' else 0o644
            entry.size = len(data)
            entry.type = kind
            if kind != tarfile.REGTYPE:
                entry.size = 0
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                entry.linkname = 'runtime/bin/ruby'
            archive.addfile(entry, io.BytesIO(data))
    return stream.getvalue()


def fixture(count=M.NATIVE_COUNT):
    return [('runtime/bin/ruby', native(), tarfile.REGTYPE)] + [
        (f'runtime/lib/image-{i}.bundle', native(kind=8), tarfile.REGTYPE) for i in range(1, count)] + [
        ('runtime/licenses/NOTICE', b'Keep every original notice byte\n', tarfile.REGTYPE),
        ('runtime/empty', b'', tarfile.REGTYPE)]


def profile(target=API.ARM_TARGET):
    return types.SimpleNamespace(stager=STAGER, target=target,
        arch='arm64' if target == API.ARM_TARGET else 'x86_64')


class StoreSigning(unittest.TestCase):
    def test_all_187_native_headers_and_all_data_are_examined(self):
        seen = []
        def inspect(body, name):
            M.native_policy(body, name, profile(), MATCHER)
            seen.append(name)
        rows = M.archive_scan(tar(fixture()), inspect)
        self.assertEqual(len(seen), 187)
        self.assertEqual(len(rows), 189)
        self.assertEqual(rows[-1]['bytes'], 0)
        for body in (native(cpu=0x1000007, subtype=3), b'\xca\xfe\xba\xbe' + bytes(32), native(kind=6)):
            changed = fixture(); changed[50] = (changed[50][0], body, tarfile.REGTYPE)
            with self.assertRaises((M.Refused, STAGER.Refused, MATCHER.PreparationRefused)):
                M.archive_scan(tar(changed), inspect)
        with self.assertRaises(M.Refused):
            M.archive_scan(tar(fixture(186)), inspect)
        intel = native(cpu=0x1000007, subtype=3)
        M.native_policy(intel, 'runtime/bin/ruby', profile(API.INTEL_TARGET), MATCHER)

    def test_archive_implicit_aliases_links_duplicates_and_native_disguises_refuse(self):
        for extra in (
            [('runtime/Lib/a', b'a', tarfile.REGTYPE), ('runtime/lib/b', b'b', tarfile.REGTYPE)],
            [('runtime/node', b'a', tarfile.REGTYPE), ('runtime/node/child', b'b', tarfile.REGTYPE)],
            [('runtime/node/child', b'b', tarfile.REGTYPE), ('runtime/node', b'a', tarfile.REGTYPE)],
            [('runtime/empty', b'duplicate', tarfile.REGTYPE)],
            [('runtime/link', b'', tarfile.SYMTYPE)], [('runtime/hard', b'', tarfile.LNKTYPE)],
            [('runtime/../../escape', b'x', tarfile.REGTYPE)],
            [('runtime/bad.bundle', b'not Mach-O', tarfile.REGTYPE)],
            [('runtime/other-platform', b'\x7fELF' + bytes(30), tarfile.REGTYPE)],
        ):
            with self.subTest(extra=extra[0][0]), self.assertRaises(M.Refused):
                M.archive_scan(tar(fixture() + extra), lambda *_: None)

    def test_signing_semantics_are_fixed_and_neutral_matcher_rejects_code_changes(self):
        identity = ('A' * 10, 'B' * 40, 'C' * 64)
        name = 'runtime/bin/ruby'
        sign, verify = M.sign_arguments(Path('/owned/native'), Path('/source/empty'), name,
                                       identity, lambda *_: 'fixed-team-and-leaf')
        self.assertIn('--timestamp', sign)
        self.assertEqual(sign[sign.index('--options') + 1], 'runtime')
        self.assertEqual(sign[sign.index('--entitlements') + 1], '/source/empty')
        self.assertEqual(verify, ['/usr/bin/codesign', '--verify', '--strict', '--all-architectures',
            '--test-requirement', '=fixed-team-and-leaf', '/owned/native'])
        self.assertNotEqual(M.identifier(name), M.identifier('runtime/lib/other.bundle'))
        for kind in (2, 8):
            before, after = native(kind=kind), native(kind=kind, signed=True)
            self.assertTrue(MATCHER.macho_content_valid(before, after, 'arm64', signing=True))
            self.assertEqual(API.python_code_flags(after, 'arm64', 'python-shipping', MATCHER), [0x10000])
            changed = bytearray(after); changed[270] ^= 1
            with self.assertRaises(MATCHER.PreparationRefused):
                MATCHER.macho_content_valid(before, bytes(changed), 'arm64', signing=True)
            with self.assertRaises(API.Refused):
                API.python_code_flags(native(kind=kind, signed=True, flags=0x10002), 'arm64', 'python-shipping', MATCHER)

    def test_one_aggregate_clock_and_exact_dispatch_order(self):
        state = {'started': 1_000_000_000, 'observed': 1_000_000_000, 'rows': [], 'retiring': False}
        context = {'purpose': M.PHASE, 'ready': True, 'retiring': False, 'roles': M.ROLES}
        op = types.SimpleNamespace(store_signing=state, credential_active=context, errors=[],
            stager_io_pending=None, calls=[], signing_mutation_pending=True)
        with mock.patch.object(M.time, 'monotonic_ns', return_value=2_000_000_000):
            M.dispatch(op, M.ROLES[0])
            with self.assertRaises(M.Refused): M.dispatch(op, M.ROLES[2])
            self.assertEqual(M.credential_endpoint(op), (M.HARD_SECONDS + 1) * 10**9)
        op.calls = [{'returned': True, 'capturesSettled': True, 'returncode': 0}]
        op.signing_mutation_pending = False
        with mock.patch.object(M.time, 'monotonic_ns', return_value=3_000_000_000):
            M.dispatch(op, M.ROLES[1])
        with mock.patch.object(M.time, 'monotonic_ns', return_value=(M.WORK_SECONDS + 1) * 10**9):
            with self.assertRaises(M.Refused): M.clock(op)
            M.clock(op, work=False)
        self.assertEqual(len(M.ROLES), 374)
        self.assertEqual(len(set(M.ROLES)), 374)

    def test_actual_credential_scope_uses_hard_reserve_and_only_known_native_unwind(self):
        # Reuse existing inert Security port, not a mocked credential_scope.
        # Its real private-file identities, search restoration and closes run.
        fixtures = load('store_credential_fixture_test', 'tests/desktop/test_macos_installed_staging.py')
        helper = fixtures.MacAndroidHelperPackagingData()
        api = fixtures.ANDROID_HELPER
        for failure in ('known-nonzero', 'native-unknown', 'close-unknown'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); work = root / 'work'; work.mkdir(mode=0o700)
                checkout = root / 'source'; checkout.mkdir(mode=0o700)
                environment = {'GITHUB_SHA': 'a' * 40, 'GITHUB_WORKFLOW_SHA': 'a' * 40,
                    'GITHUB_WORKFLOW_REF': 'inert-test-only', 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}
                def native_owner(argv, **_kwargs):
                    # The actual native call begins during work and returns in
                    # cleanup reserve: the old WORK credentialendpoint failed.
                    credentials.clock[0] = started + (M.WORK_SECONDS + 1) * 10**9
                    if failure == 'native-unknown':
                        raise RuntimeError('inert unknown native result')
                    if failure == 'close-unknown':
                        op.errors.append({'stage': 'close', 'role': 'inert-original', 'type': 'InjectedUnknown'})
                    return subprocess.CompletedProcess(argv, 9, b'', b'inert nonzero')
                op = api.Operation(types.SimpleNamespace(run_owned=native_owner), checkout, work,
                                   M.PHASE, environment, fixtures.TOOL)
                credentials = helper.credential_fixture(op)
                # Extend only the inert Security settings port for the new
                # batch interval; every other existing fixture command stays
                # unchanged. The real credential_scope is never replaced.
                existing_security = op.owner.run_owned
                def security(argv, **kwargs):
                    if argv[:2] == ['/usr/bin/security', 'set-keychain-settings']:
                        self.assertEqual(argv[2:], ['-l', '-u', '-t', str(M.HARD_SECONDS), credentials.keychain])
                        self.assertFalse(set(api.CREDENTIAL_VARIABLES) & set(kwargs['environ']))
                        credentials.events.append(('settings', tuple(argv)))
                        return subprocess.CompletedProcess(argv, 0, b'', b'')
                    return existing_security(argv, **kwargs)
                op.owner.run_owned = security
                op.service_profile, op.producer_profile = credentials.service, credentials.producer
                op.signing = fixtures.TOOL.service_signing_data(credentials.service)
                started = credentials.clock[0]
                with helper.credential_fixture_call(op, credentials):
                    op.open(); op.store_signing_module = M
                    with mock.patch.object(M.os, 'fstatvfs', return_value=types.SimpleNamespace(f_frsize=4096, f_bavail=524288)):
                        M.start(op, api, started)
                    op.store_signing['rows'] = []
                    try:
                        with self.assertRaises((api.Refused, RuntimeError)):
                            with op.credential_scope(M.PHASE):
                                self.assertEqual(op.credential_active['endpoint'], started + M.HARD_SECONDS * 10**9)
                                op.signing_mutation_pending = True
                                op.call(M.ROLES[0], ['/usr/bin/codesign', 'inert-never-executed'],
                                    op.native_environment(), cwd=work, timeout=30, limit=65536)
                        settings = next(argv for role, argv in credentials.events if role == 'settings')
                        self.assertEqual(settings[-2], str(M.HARD_SECONDS))
                        roles = [role for role, _ in credentials.events]
                        if failure == 'known-nonzero':
                            self.assertIn('restore', roles); self.assertIn('delete', roles)
                            self.assertEqual(credentials.search, credentials.initial)
                            self.assertFalse(Path(credentials.keychain).parent.exists())
                            self.assertTrue(op.credential_contexts[0]['retired'])
                            self.assertTrue(op.credential_contexts[0]['closed'])
                        else:
                            self.assertNotIn('restore', roles); self.assertNotIn('delete', roles)
                            self.assertTrue(Path(credentials.keychain).parent.exists())
                            self.assertTrue(op.credential_unknown)
                        self.assertTrue(op.signing_mutation_pending)
                        self.assertFalse(op.receipt['passed'])
                        self.assertFalse((work / 'store-signed-receipt.json').exists())
                    finally:
                        for entry in reversed(op.entries): op.close(entry)

    def test_real_preparer_and_original_call_ledger_with_inert_native_boundary(self):
        self.operation_case()

    def test_midway_native_failure_unknown_call_close_and_credential_cleanup_preserve(self):
        for failure in ('native-nonzero', 'native-unknown', 'close-unknown', 'credential-cleanup'):
            with self.subTest(failure=failure):
                self.operation_case(failure)

    def operation_case(self, failure=None):
        # Only native subprocess and credential acquisition are inert supplier
        # boundaries. Real descriptors, copies, TARs, ledgers and cleanup run.
        calls, scopes = [], []
        class Owner:
            @staticmethod
            def run_owned(argv, **kwargs):
                calls.append(tuple(argv))
                if len(calls) == 151 and failure == 'native-nonzero':
                    return subprocess.CompletedProcess(argv, 9, b'', b'inert failed codesign')
                if len(calls) == 151 and failure == 'native-unknown':
                    raise RuntimeError('inert native result ownership unknown')
                path = Path(argv[-1])
                if '--force' in argv:
                    original = path.read_bytes()
                    kind = struct.unpack_from('<I', original, 12)[0]
                    path.write_bytes(native(kind=kind, signed=True))
                return subprocess.CompletedProcess(argv, 0, b'', b'')
        @contextlib.contextmanager
        def credential_scope(op, purpose):
            scopes.append(purpose)
            # Keep the real census at its admitted eight-file bound through
            # all374 original calls. Closed census FDs still consume lifetime
            # ledger cells; mocking census hid the old4096-cell integration bug.
            private = op.work / op.target_name / 'inert-private-db'
            private.mkdir(mode=0o700)
            for index in range(8):
                path = private / f'database-{index}'
                path.write_bytes(b'INERT private database DATA'); path.chmod(0o600)
            root = op.directory(op.target_entry, private.name, 'inert-private-directory')
            op.credential_active = {'purpose': purpose, 'ready': True, 'retiring': False, 'roles': M.ROLES,
                                    'endpoint': time.monotonic_ns() + 1500 * 10**9,
                                    'root': root, 'directories': [root], 'entries': [], 'pending': None}
            try:
                # Conservative whole-scope auxiliary PRE/POST census allowance.
                for _ in range(40): op.credential_census(op.credential_active)
                yield
            except BaseException:
                op.credential_failed = True
                raise
            finally:
                op.credential_active = None
            if failure == 'credential-cleanup':
                op.credential_failed = op.credential_unknown = True
                raise API.Refused('inert credential cleanup unknown')
            op.credential_calls.extend({'role': role, 'returned': True, 'settled': True, 'entered': True, 'status': 0}
                for role in API.CREDENTIAL_ROLES[:17] + ('search-final', 'default-after'))
            op.credential_contexts.append({'purpose': purpose, 'retired': True, 'closed': True,
                                          'searchRestored': True, 'defaultUnchanged': True})
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            incoming = work / 'store-original'; incoming.mkdir(mode=0o700)
            body = tar(fixture())
            archive = incoming / 'store-runtime.tar.gz'; archive.write_bytes(body); archive.chmod(0o400)
            origin = {'signed': False, 'arch': 'arm64', 'archiveSha256': M.sha(body),
                'source': '0039f79baa54318d58d87606335492f7ef2a90dd', 'runId': 38844616192,
                'runAttempt': 1, 'artifactId': 12022417782}
            metadata = incoming / 'runtime-origin.json'; metadata.write_bytes(M.canonical(origin)); metadata.chmod(0o400)
            env = {'GITHUB_SHA': 'a' * 40, 'GITHUB_WORKFLOW_SHA': 'a' * 40,
                   'GITHUB_WORKFLOW_REF': 'inert-test-only', 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}
            checkout = work / 'source'
            for relative in ('desktop/packaging/macos-empty-entitlements.plist', 'desktop/tools/macos_cpython_orchestrator.py'):
                path = checkout / relative; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / relative).read_bytes()); path.chmod(0o644)
            op = API.Operation(Owner, checkout, work, M.PHASE, env, STAGER)
            op.open(); op.store_signing_module = M
            # Test files are tiny; admission's production 2GiB disk quote stays
            # intact while this DATA fixture supplies an inert capacity fact.
            with mock.patch.object(M.os, 'fstatvfs', return_value=types.SimpleNamespace(f_frsize=4096, f_bavail=524288)):
                M.start(op, API, time.monotonic_ns())
            op.signing = ('A' * 10, 'B' * 40, 'C' * 64)
            op.producer_profile = op.service_profile = b'inert public profile'
            original_close = API.Operation.close
            def close(instance, entry):
                original_close(instance, entry)
                if failure == 'close-unknown' and entry['role'] == 'store-native-075' and entry['closed']:
                    # Model a consumed sole close whose result is unknown, not
                    # a live descriptor retry or a real OS-close fault.
                    entry['closed'] = False
                    instance.errors.append({'stage': 'close', 'role': entry['role'], 'type': 'InjectedUnknown'})
            try:
                with mock.patch.object(API.Operation, 'close', close), \
                     mock.patch.object(API.Operation, 'credential_scope', credential_scope), \
                     mock.patch.object(API.Operation, 'credential_clock', side_effect=lambda context, **_: time.monotonic_ns()), \
                     mock.patch.object(API, 'signing_requirement', return_value='inert-test-only'):
                    if failure is not None:
                        with self.assertRaises((M.Refused, API.Refused, RuntimeError)):
                            M.prepare(op)
                    else:
                        M.prepare(op)
                self.assertEqual(scopes, [M.PHASE])
                if failure is not None:
                    self.assertFalse(op.store_signing['complete'])
                    self.assertFalse(M.success(op))
                    self.assertFalse((work / 'store-signed.tar.gz').exists())
                    self.assertFalse((work / 'store-signed-receipt.json').exists())
                    op.finish()
                    self.assertFalse(op.receipt['targetRetired'])
                    self.assertFalse(op.receipt['originalClosesKnown'])
                    self.assertTrue((work / op.target_name).exists())
                    self.assertEqual(archive.read_bytes(), body)
                    return
                self.assertEqual(len(calls), 374)
                self.assertEqual(tuple(c['role'] for c in op.calls), M.ROLES)
                self.assertGreaterEqual(len(op.entries), 374 * (3 + 1 + 2 * 8) + 40 * 8)
                self.assertLessEqual(len(op.entries), M.ORIGINAL_LIMIT)
                self.assertTrue(M.success(op))
                signed = (work / 'store-signed.tar.gz').read_bytes()
                final = M.archive_scan(signed, lambda value, name: M.native_policy(value, name, profile(), MATCHER))
                initial = M.archive_scan(body, lambda *_: None)
                self.assertEqual([r for r in initial if not r['native']], [r for r in final if not r['native']])
                self.assertEqual(archive.read_bytes(), body)
                self.assertEqual(len(op.store_signing['native']), 187)
                op.finish()
                self.assertTrue(op.receipt['targetRetired'])
                self.assertTrue(op.receipt['originalClosesKnown'])
                self.assertFalse(list(work.glob('android-helper-store-*')))
            finally:
                for entry in reversed(op.entries): op.close(entry)


if __name__ == '__main__': unittest.main()
