"""Read-only notarization diagnosis: correlation, privacy and original cleanup."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from desktop.tools import macos_notary_inspect as M

ID = '11111111-1111-4111-8111-111111111111'
OLD_ID = '22222222-2222-4222-8222-222222222222'
KEY = b'synthetic-not-a-credential'
PROFILE = {'keyId': 'SYNTHETIC0', 'issuerId': OLD_ID}


def history():
    return {'history': [
        {'id': ID, 'name': M.ARCHIVE, 'createdDate': '2026-10-24T07:57:00Z', 'status': 'Invalid'},
        {'id': OLD_ID, 'name': 'unrelated-private-name', 'createdDate': '2026-10-23T07:57:00Z', 'status': 'Accepted'}]}


def log():
    return {'jobId': ID, 'archiveFilename': M.ARCHIVE, 'uploadDate': '2026-10-24T07:57:00Z',
            'status': 'Invalid', 'statusCode': 4000,
            'issues': [{'severity': 'error', 'code': None,
                        'message': 'The binary is not signed.',
                        'path': 'private/MobileReleaseKitPayload.app/store/private-file'},
                       {'severity': 'warning', 'code': 123,
                        'message': 'private-unclassified-message', 'path': 'private-path'}]}


def encoded(value):
    return json.dumps(value).encode()


class NotaryInspectTests(unittest.TestCase):
    def test_unique_correlation_and_incomplete_history(self):
        selected, state = M.select_submission(encoded(history()))
        self.assertEqual(selected, {'id': ID, 'status': 'Invalid'})
        self.assertEqual(state, 'unique-interval-correlation')
        for mutation, reason in (
            (lambda v: v['history'].pop(), 'history-coverage-unavailable'),
            (lambda v: v['history'][0].update(name='other'), 'no-match'),
            (lambda v: v['history'][0].update(status='In Progress'), 'not-terminal'),
            (lambda v: v['history'].append(dict(v['history'][0], id='33333333-3333-4333-8333-333333333333')), 'ambiguous'),
        ):
            value = history(); mutation(value)
            self.assertEqual(M.select_submission(encoded(value)), (None, reason))
        for mutation in (lambda v: v.update(nextPage='more'),
                         lambda v: v['history'][0].update(createdDate='2026-10-16T14:40:00'),
                         lambda v: v['history'].append(v['history'][0])):
            value = history(); mutation(value)
            with self.assertRaises(Exception): M.select_submission(encoded(value))

    def test_log_binding_and_finite_redaction(self):
        selected = {'id': ID, 'status': 'Invalid'}
        result = M.log_projection(encoded(log()), selected)
        self.assertEqual(result['issueCount'], 2)
        self.assertEqual(result['issues'][0]['category'], 'unsigned-binary')
        self.assertEqual(result['issues'][0]['component'], 'store-runtime')
        self.assertEqual(result['issues'][1]['category'], 'unclassified')
        exported = json.dumps(result)
        for secret in ('private', ID, M.ARCHIVE): self.assertNotIn(secret, exported)
        nested = log()
        nested['issues'] = [dict(nested['issues'][0], path=(
            'private/store/bundle/ruby/3.3.0/cache/terminal-notifier-2.0.0.gem/'
            'data.tar.gz/vendor/terminal-notifier/terminal-notifier.app/Contents/MacOS/terminal-notifier'))]
        self.assertEqual(M.log_projection(encoded(nested), selected)['issues'][0]['component'],
                         'optional-terminal-notifier-cache')
        nested['issues'][0]['path'] = 'private/store/bundle/ruby/3.3.0/cache/another.gem/native'
        self.assertEqual(M.log_projection(encoded(nested), selected)['issues'][0]['component'], 'gem-install-cache')
        for changes in ({'jobId': OLD_ID}, {'archiveFilename': 'other'}, {'status': 'Accepted'},
                        {'uploadDate': '2026-10-15T14:40:00Z'}, {'statusCode': True}):
            value = log(); value.update(changes)
            with self.assertRaises(Exception): M.log_projection(encoded(value), selected)

    def exercise(self, callback):
        # Tests run only in the disposable nonroot namespace; automatic cleanup
        # here concerns synthetic files and in-process callbacks, never children.
        self.assertNotEqual(os.getuid(), 0, 'run the focused test in its nonroot sandbox')
        with tempfile.TemporaryDirectory() as parent:
            work = Path(parent) / 'key-owner'; work.mkdir(mode=0o700)
            return callback(work)

    def good_command(self, argv, **kwargs):
        self.assertEqual(argv[:2], ['/usr/bin/xcrun', 'notarytool'])
        self.assertIn(argv[2], ('history', 'log'))
        self.assertEqual(set(kwargs['environ']), {'PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'TZ', 'DEVELOPER_DIR'})
        key_path = Path(argv[argv.index('--key') + 1])
        self.assertEqual(key_path.read_bytes(), KEY)
        self.assertEqual(key_path.stat().st_mode & 0o777, 0o400)
        self.assertLessEqual(kwargs['timeout'], 60)
        self.assertEqual(kwargs['output_limit'], 2 << 20)
        self.assertFalse(kwargs['text'])
        if argv[2] == 'log': self.assertEqual(argv[3], ID)
        return subprocess.CompletedProcess(argv, 0, encoded(history() if argv[2] == 'history' else log()), b'private-stderr')

    def test_query_and_cleanup_success_and_safe_failure(self):
        def check(work):
            calls = []
            def command(argv, **kw):
                calls.append(argv[2]); return self.good_command(argv, **kw)
            result = M.inspect(work, KEY, PROFILE, command=command)
            self.assertEqual(calls, ['history', 'log'])
            self.assertEqual(result['notary']['status'], 'Invalid')
            self.assertFalse(work.exists())
        self.exercise(check)
        def failure(work):
            def command(*a, **kw):
                raise M.ProcessError('private', dispatched=True, contained=True, cleanup_complete=True)
            with self.assertRaises(M.ProcessError): M.inspect(work, KEY, PROFILE, command=command)
            self.assertFalse(work.exists())
        self.exercise(failure)

    def test_unknown_finality_keeps_key_but_closes_original_fds(self):
        for exception in (M.ProcessError('private', dispatched=True, contained=False, cleanup_complete=False), KeyboardInterrupt()):
            def check(work):
                before = len(os.listdir('/proc/self/fd'))
                def command(*a, **kw): raise exception
                with self.assertRaises(type(exception)): M.inspect(work, KEY, PROFILE, command=command)
                self.assertEqual((work / 'key.p8').read_bytes(), KEY)
                self.assertEqual(len(os.listdir('/proc/self/fd')), before)
            self.exercise(check)

    def test_changed_key_or_failed_write_does_not_leak_descriptor_or_delete(self):
        def changed(work):
            before = len(os.listdir('/proc/self/fd'))
            def command(argv, **kw):
                path = work / 'key.p8'; path.chmod(0o600); path.write_bytes(b'changed')
                return self.good_result(argv)
            with self.assertRaises(BaseExceptionGroup): M.inspect(work, KEY, PROFILE, command=command)
            self.assertEqual((work / 'key.p8').read_bytes(), b'changed')
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        self.exercise(changed)
        def failed_write(work):
            before = len(os.listdir('/proc/self/fd'))
            with mock.patch.object(M.os, 'write', side_effect=OSError('private')):
                with self.assertRaises(OSError): M.inspect(work, KEY, PROFILE, command=self.good_command)
            self.assertTrue((work / 'key.p8').exists())
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        self.exercise(failed_write)

    @staticmethod
    def good_result(argv):
        return subprocess.CompletedProcess(argv, 0, encoded(history()), b'')

    def test_parent_stat_failure_closes_original_descriptor(self):
        def check(work):
            before = len(os.listdir('/proc/self/fd'))
            with mock.patch.object(M.os, 'fstat', side_effect=OSError('private')):
                with self.assertRaises(OSError): M.inspect(work, KEY, PROFILE, command=self.good_command)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)
            self.assertEqual(list(work.iterdir()), [])
        self.exercise(check)

    def test_uncertain_close_and_unexpected_output_veto_clean_success(self):
        def close_failure(work):
            close = os.close
            def uncertain(fd):
                # Consume once, then inject uncertainty; retry would be unsafe.
                is_key = os.path.basename(os.readlink('/proc/self/fd/' + str(fd))) == 'key.p8'
                close(fd)
                if is_key: raise OSError('private')
            with mock.patch.object(M.os, 'close', side_effect=uncertain):
                with self.assertRaises(BaseExceptionGroup): M.inspect(work, KEY, PROFILE, command=self.good_command)
            self.assertTrue((work / 'key.p8').exists())
        self.exercise(close_failure)
        def extra_file(work):
            def command(argv, **kw):
                (work / 'unrelated').write_bytes(b'preserve'); return self.good_command(argv, **kw)
            with self.assertRaises(BaseExceptionGroup): M.inspect(work, KEY, PROFILE, command=command)
            self.assertFalse((work / 'key.p8').exists())
            self.assertEqual((work / 'unrelated').read_bytes(), b'preserve')
        self.exercise(extra_file)
