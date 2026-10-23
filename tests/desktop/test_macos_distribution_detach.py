"""Real descriptor custody with inert native responses; never mount or install."""
import contextlib
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(leaf):
    spec = importlib.util.spec_from_file_location('detach_test_' + leaf[:-3], ROOT / 'desktop/tools' / leaf)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = load('macos_android_helper_package.py')
S = load('stage_macos_installed.py')
NOW = 1_000_000_000
PRIVATE = b'PRIVATE_PATH_PID_COMMAND_SENTINEL'


def lsof_rows(device, *, pid=123, uid=501, command=b'python3', fd=b'cwd'):
    return (b'p' + str(pid).encode() + b'\0c' + command + b'\0u' + str(uid).encode() + b'\0\n'
            + b'f' + fd + b'\0tDIR\0D' + hex(device).encode() + b'\0\n')


@contextlib.contextmanager
def operation():
    """Real source methods/FDs; only mount policy is a Linux-compatible port."""
    with tempfile.TemporaryDirectory(prefix='mrk-detach-data-') as temporary:
        root = Path(temporary)
        work, volumes = root / 'work', root / 'volumes'
        work.mkdir(mode=0o700); volumes.mkdir(mode=0o700)
        env = dict(GITHUB_SHA='a'*40, GITHUB_WORKFLOW_SHA='a'*40, GITHUB_WORKFLOW_REF='inert',
                   GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', MRK_MACOS_PACKAGE_ROLE='ordinary-image')
        op = H.Operation(SimpleNamespace(), root, work, 'package-install', env, S)
        op.package_started = op.package_observed = NOW
        op.package_endpoint = NOW + 990_000_000_000
        op.stage = 'package-nonroot-v2-readback'
        op.open()
        op.transport_mount = volumes / H.transport_mount_path_data(env, op.target, op.phase).name
        op.transport_mount.mkdir(mode=0o700)
        parent = op.register(os.open(volumes, H.READ_FLAGS | os.O_DIRECTORY), 'test-volumes', 'removal-directory')
        parent['identity'] = H.directory_identity(os.fstat(parent['fd']))
        op.transport_volumes = parent
        mount = op.register(os.open(op.transport_mount, H.READ_FLAGS | os.O_DIRECTORY), 'test-mount', 'mount',
                            parent['fd'], op.transport_mount.name)
        mount['parent_entry'] = parent
        mount['identity'] = H.directory_identity(os.fstat(mount['fd']))
        op.mount_entry, op.mount_device = mount, '/dev/disk99s1'
        op.mount_entered = op.mount_known = True
        op.installer_entered = op.installer_zero = True
        op.calls.extend(dict(role=role, entered=True, returned=True, capturesSettled=True, returncode=0)
                        for role in H._PACKAGE_DIAGNOSTIC_ROLES[:-1])
        op.package_name = 'MobileReleaseKit-Request-' + '1'*32 + '.pkg'
        expected = {'Install.pkg': b'inert package', 'producer.json': b'{}\n', 'producer.sig': b'inert signature'}
        for name, body in expected.items():
            path = op.transport_mount / (op.package_name if name == 'Install.pkg' else name)
            path.write_bytes(body); path.chmod(0o444)
        def mount_post():
            assert H.directory_identity(os.fstat(mount['fd'])) == mount['identity']
            assert H.directory_identity(os.stat(mount['name'], dir_fd=parent['fd'], follow_symlinks=False)) == mount['identity']
        def parent_post(entry):
            assert entry is parent
            assert H.directory_identity(os.fstat(parent['fd'])) == parent['identity']
            assert H.directory_identity(volumes.stat()) == parent['identity']
        try:
            with (mock.patch.object(H.time, 'monotonic_ns', return_value=NOW),
                  mock.patch.object(H, 'transport_mount_path_data', return_value=op.transport_mount),
                  mock.patch.object(op, 'recheck_mount', side_effect=mount_post),
                  mock.patch.object(op, 'removal_directory_post', side_effect=parent_post)):
                op.mount_inputs(expected, op.package_name)
                yield op
        finally:
            # Every native response is an inert DATA port. Only after assertions
            # may this test consume still-held originals from an unknown port.
            for entry in reversed(op.entries):
                op.close(entry)


class DistributionDetachData(unittest.TestCase):
    def test_stderr_is_closed_bounded_data_not_exception_text(self):
        for raw, reason in ((b'', 'empty'), (b'hdiutil: detach failed - Resource busy\n', 'resource-busy'),
                            (b'hdiutil: detach failed - Permission denied\n', 'permission-denied'),
                            (b'hdiutil: detach failed - Operation not permitted\n', 'operation-not-permitted'),
                            (b'hdiutil: detach failed - No such device\n', 'no-such-device')):
            self.assertEqual(H.distribution_detach_stderr(raw), reason)
        for raw in (PRIVATE, b'prefix hdiutil: detach failed - Resource busy\n', b'x'*65537, None,
                    b'hdiutil: detach failed - Resource busy\nhdiutil: detach failed - Permission denied\n'):
            self.assertEqual(H.distribution_detach_stderr(raw), 'unclassified')

    def test_nul_fields_scope_device_and_never_publish_raw_identity(self):
        raw = (lsof_rows(9, pid=321, uid=501, fd=b'cwd')
            + lsof_rows(9, pid=543, uid=0, command=b'installd', fd=b'3')
            + lsof_rows(9, pid=765, uid=0, command=b'mdworker_shared', fd=b'txt')
            + lsof_rows(88, pid=987, command=b'foreign', fd=b'4')
            + lsof_rows(9, pid=432, command=PRIVATE + b'\np999999', fd=b'5')
            + b'p876\0cunknown\0\nfNOFD\0\n')
        value = H.distribution_busy_holders(raw, PRIVATE, 0, device=9, own_pid=321, own_uid=501)
        self.assertEqual((value['state'], value['processes'], value['references'], value['skipped']),
                         ('visible-holders', 4, 4, 2))
        self.assertTrue(value['warnings'])
        self.assertIn(dict(owner='self', command='other-name', reference='cwd', count=1), value['rows'])
        self.assertIn(dict(owner='root-visible', command='installer-name', reference='descriptor', count=1), value['rows'])
        self.assertIn(dict(owner='root-visible', command='indexer-name', reference='mapping', count=1), value['rows'])
        public = json.dumps(value)
        for forbidden in (PRIVATE.decode(), '321', '543', '765', '987', '999999', 'installd', 'mdworker_shared'):
            self.assertNotIn(forbidden, public)
        for stdout, stderr, code, expected in ((b'', b'', 1, 'no-visible-match'),
                (b'p876\0cunknown\0\nfNOFD\0\n', b'warning', 0, 'no-visible-match'),
                (lsof_rows(88), b'', 0, 'no-visible-match'), (b'', b'', 2, 'native-nonzero'),
                (lsof_rows(9)[:-1], b'', 0, 'malformed-output'),
                (b'p1\0p2\0\n', b'', 0, 'malformed-output'),
                (b'x'*16385, b'', 0, 'malformed-output')):
            with self.subTest(expected=expected):
                result = H.distribution_busy_holders(stdout, stderr, code, device=9, own_pid=321, own_uid=501)
                self.assertEqual(result['state'], expected)
                self.assertEqual(result['references'], 0)

    def test_projection_rejects_arbitrary_holder_fields(self):
        good = H.distribution_busy_holders(lsof_rows(9), b'', 0, device=9, own_pid=321, own_uid=501)
        for change in ({'owner': PRIVATE.decode()}, {'command': PRIVATE.decode()}, {'reference': 'secret-path'}, {'count': True},
                       {'pid': 12345}):
            bad = {**good, 'rows': [{**good['rows'][0], **change}]}
            value = H.distribution_detach_diagnostic_data(dict(state='visible-holders', entered=True,
                returned=True, settled=True, resourceUnknown=False, holders=bad))
            self.assertIsNone(value['holders'])
            self.assertNotIn(PRIVATE.decode(), json.dumps(value))


class DistributionDetachCustody(unittest.TestCase):
    def assert_closed(self, descriptors):
        for fd in descriptors:
            with self.assertRaises(OSError) as raised:
                os.fstat(fd)
            self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_real_readback_and_mounted_fds_close_before_original16_and_single_probe(self):
        with operation() as op:
            selected = S.BuildSelection(op.target, '0.2.0', 'macos26-detach-data')
            args = SimpleNamespace(producer_descriptor=op.transport_mount / 'producer.json',
                producer_signature=op.transport_mount / 'producer.sig', expected_source='a'*40,
                expected_inventory='b'*64, expected_manifest='c'*64, expected_package='d'*64)
            current = dict(release=selected.release, packageVersion=selected.package_version, sourceCommit=args.expected_source,
                protocolSha256=S.CURRENT_PROTOCOL, runtimeManifestSha256=args.expected_manifest,
                inventorySha256=args.expected_inventory, packageSha256=args.expected_package)
            readback_fds, events = [], []
            real_open, real_close = os.open, os.close
            def opened(*a, **kw):
                fd = real_open(*a, **kw); readback_fds.append(fd); return fd
            def readback(argument):
                # Keep the real mount ancestor/file readers and consuming
                # finally clauses. Only unrelated producer-schema DATA is inert.
                with (mock.patch.object(S, 'selected_build', return_value=selected),
                      mock.patch.object(S, 'maintenance_producer_data', return_value={'releaseSet': {'current': current}}),
                      mock.patch.object(S.os, 'open', side_effect=opened)):
                    S.maintenance_producer_inputs(argument, selected)
                self.assert_closed(readback_fds)
                return {'inert': 'readback complete'}
            with mock.patch.object(S, 'observation_command', side_effect=readback):
                self.assertEqual(op.package_stager_io('v2-readback', args), {'inert': 'readback complete'})
            self.assertIsNone(op.stager_io_pending)
            op.installation_readback = True
            op.mounted_post()
            mounted_fds = [row['fd'] for row in op.entries if row['kind'] in ('mount', 'mounted-file')]
            def closed(fd):
                real_close(fd)
                if fd in mounted_fds: events.append(('close', fd))
            def command(argv, **options):
                self.assert_closed(mounted_fds)
                self.assert_closed(readback_fds)
                self.assertEqual(options['cwd'], op.work)
                self.assertEqual(options['environ'], op.native_environment())
                if argv[0] == '/usr/bin/hdiutil':
                    events.append(('detach', None))
                    self.assertEqual(argv, ['/usr/bin/hdiutil', 'detach', '/dev/disk99s1'])
                    self.assertEqual(options['timeout'], 30)
                    return subprocess.CompletedProcess(argv, 16, b'', b'hdiutil: detach failed - Resource busy\n')
                events.append(('lsof', None))
                self.assertEqual(argv, ['/usr/sbin/lsof', '-n', '-P', '-b', '-F0pcuftD', '+f', '--', str(op.transport_mount)])
                self.assertEqual((options['timeout'], options['output_limit'], options['text'], options['capture']),
                                 (10, 16384, False, True))
                self.assertFalse(op.package_settled())  # Diagnostic original is in flight.
                return subprocess.CompletedProcess(argv, 0,
                    lsof_rows(op.mount_entry['identity'][0], pid=765, uid=0, command=b'installd', fd=b'3'), PRIVATE)
            op.owner.run_owned = mock.Mock(side_effect=command)
            with mock.patch.object(H.os, 'close', side_effect=closed):
                with self.assertRaises(H.Refused) as caught:
                    op.detach_package_mount()
            primary = caught.exception
            self.assertIs(primary, op.distribution_detach_refusal[0])
            self.assertEqual(primary.args, ('original-nonzero-distribution-detach',))
            self.assertEqual([event[0] for event in events[:len(mounted_fds)+1]], ['close']*len(mounted_fds) + ['detach'])
            self.assertEqual(op.owner.run_owned.call_count, 2)
            self.assertEqual(tuple(row['role'] for row in op.calls), H._PACKAGE_DIAGNOSTIC_ROLES)
            self.assertEqual(op.calls[-1]['returncode'], 16)
            self.assertTrue(op.calls[-1]['capturesSettled'])
            self.assertTrue(op.distribution_detach_diagnostic_known())
            self.assertFalse(op.mount_detached)
            op.observe_distribution_detach_failure(primary)
            self.assertEqual(op.owner.run_owned.call_count, 2)  # A failed slot never replays.
            op.receipt['failure'] = dict(stage=op.stage, type='Refused', reason=primary.args[0])
            op.finish()
            self.assertFalse(op.receipt['targetRetired'])
            self.assertTrue(op.receipt['originalClosesKnown'])
            sink = io.StringIO()
            with contextlib.redirect_stderr(sink):
                H.emit_failure_diagnostic(primary, phase=op.phase, target=op.target, main_stage='operation-execute', operation=op, stager=S)
            public = sink.getvalue()
            self.assertLessEqual(len(public.encode()), 4096)
            value = json.loads(public)
            self.assertEqual(value['lastRecordedNative']['role'], 'distribution-detach')
            self.assertEqual(value['distributionDetach']['stderr'], 'resource-busy')
            observation = value['distributionDetach']['holderObservation']
            self.assertEqual(observation['state'], 'visible-holders')
            self.assertEqual(observation['holders']['rows'][0]['command'], 'installer-name')
            for forbidden in (PRIVATE.decode(), str(op.work), str(op.transport_mount), '/dev/disk99s1', '765', 'installd'):
                self.assertNotIn(forbidden, public)
            self.assertFalse(observation['holderAuthentication'] or observation['systemServiceExitClaimed'])
            # Only existing hdiutil captures were published. No lsof stdout,
            # stderr, command-name/PID roster, extra role or cache file exists.
            self.assertEqual(set(path.name for path in op.work.iterdir()), {op.target_name,
                'android-helper-distribution-detach.stdout', 'android-helper-distribution-detach.stderr',
                'android-helper-distribution-detach.status'})

    def test_only_same_refusal_can_start_probe_not_late_errors_or_close_uncertainty(self):
        for fault in ('different-object', 'deadline-after-zero', 'nonzero-other', 'capture-unknown', 'close-unknown'):
            with self.subTest(fault=fault), operation() as op:
                op.installation_readback = True
                def command(argv, **options):
                    self.assertEqual(argv[0], '/usr/bin/hdiutil')
                    if fault == 'deadline-after-zero':
                        op.package_endpoint = NOW
                        return subprocess.CompletedProcess(argv, 0, b'', b'')
                    return subprocess.CompletedProcess(argv, 5 if fault == 'nonzero-other' else 16, b'', b'')
                op.owner.run_owned = mock.Mock(side_effect=command)
                real_call = op.package_call
                def changed(*a, **kw):
                    try:
                        return real_call(*a, **kw)
                    except H.Refused:
                        if fault == 'different-object': raise H.Refused('original-nonzero-distribution-detach')
                        if fault == 'capture-unknown': op.calls[-1]['capturesSettled'] = False
                        raise
                original_close = op.close
                def close(entry):
                    original_close(entry)
                    if entry['kind'] == 'mount': entry['closed'] = False
                with contextlib.ExitStack() as stack:
                    stack.enter_context(mock.patch.object(op, 'package_call', side_effect=changed))
                    if fault == 'close-unknown': stack.enter_context(mock.patch.object(op, 'close', side_effect=close))
                    with self.assertRaises(H.Refused): op.detach_package_mount()
                self.assertIsNone(op.distribution_detach_diagnostic)
                self.assertEqual(op.owner.run_owned.call_count, 0 if fault == 'close-unknown' else 1)
                if fault == 'deadline-after-zero':
                    self.assertEqual(op.calls[-1]['returncode'], 0)
                    self.assertTrue(op.calls[-1]['returned'] and op.calls[-1]['capturesSettled'])
                self.assertFalse(op.mount_detached)

    def test_unknown_diagnostic_original_retains_resources_not_just_a_state_word(self):
        for result_kind in ('exception', 'keyboard-interrupt', 'malformed-return'):
            with self.subTest(result_kind=result_kind), operation() as op:
                op.installation_readback = True
                def command(argv, **options):
                    if argv[0] == '/usr/bin/hdiutil': return subprocess.CompletedProcess(argv, 16, b'', b'')
                    if result_kind == 'exception': raise RuntimeError(PRIVATE.decode())
                    if result_kind == 'keyboard-interrupt': raise KeyboardInterrupt(PRIVATE.decode())
                    return subprocess.CompletedProcess(argv, 0, 'not bytes', b'')
                op.owner.run_owned = mock.Mock(side_effect=command)
                with self.assertRaises(H.Refused) as caught: op.detach_package_mount()
                self.assertIs(caught.exception, op.distribution_detach_refusal[0])
                self.assertFalse(op.distribution_detach_diagnostic_known() or op.package_settled())
                held = [op.work_entry, op.target_entry, op.transport_volumes]
                op.finish()
                self.assertFalse(op.receipt['targetRetired'] or op.receipt['originalClosesKnown'])
                self.assertTrue((op.work / op.target_name).is_dir())
                for entry in held:
                    self.assertIsNotNone(entry['fd'])
                    os.fstat(entry['fd'])
                public = H.failure_diagnostic(caught.exception, operation=op)['distributionDetach']['holderObservation']
                self.assertEqual(public['state'], 'native-unknown')
                self.assertTrue(public['entered'] and public['resourceUnknown'])
                self.assertFalse(public['returned'] or public['settled'])
                self.assertIn({'stage': 'distribution-detach-diagnostic', 'type': 'CompletionUnknown'}, op.errors)
                self.assertEqual(op.calls[-1]['returncode'], 16)

    def test_probe_uses_remaining_deadline_and_keeps_incomplete_visibility_nonnegative(self):
        for fault in ('no-visible', 'malformed', 'native-nonzero', 'expired', 'changed-mount', 'short-clock'):
            with self.subTest(fault=fault), operation() as op:
                op.installation_readback = True
                def command(argv, **options):
                    if argv[0] == '/usr/bin/hdiutil':
                        if fault == 'expired': op.package_endpoint = NOW + 3_000_000_000
                        elif fault == 'short-clock': op.package_endpoint = NOW + 7_000_000_000
                        elif fault == 'changed-mount': op.mount_entry['identity'] = (0,)*5
                        return subprocess.CompletedProcess(argv, 16, b'', b'')
                    if fault == 'short-clock': self.assertEqual(options['timeout'], 4)
                    return subprocess.CompletedProcess(argv, 2 if fault == 'native-nonzero' else 1,
                        b'not fields' if fault == 'malformed' else b'', b'nonroot warning')
                op.owner.run_owned = mock.Mock(side_effect=command)
                with self.assertRaises(H.Refused) as caught: op.detach_package_mount()
                self.assertIs(caught.exception, op.distribution_detach_refusal[0])
                self.assertFalse(op.mount_detached)
                self.assertTrue(op.distribution_detach_diagnostic_known())
                diagnostic = op.distribution_detach_diagnostic
                expected = {'expired': 'deadline-unavailable', 'changed-mount': 'mount-unavailable',
                            'malformed': 'malformed-output', 'native-nonzero': 'native-nonzero'}.get(fault, 'no-visible-match')
                self.assertEqual(diagnostic['state'], expected)
                self.assertEqual(op.owner.run_owned.call_count, 1 if fault in ('expired', 'changed-mount') else 2)
                if diagnostic['holders'] is not None:
                    self.assertEqual(diagnostic['holders']['references'], 0)
                    self.assertTrue(diagnostic['holders']['warnings'])


if __name__ == '__main__':
    unittest.main()
