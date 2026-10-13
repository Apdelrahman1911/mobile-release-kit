"""Focused DATA and real tiny-file boundaries; never invoke Apple/native tools."""
from __future__ import annotations

import ast
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class NotaryDiagnosticData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load('desktop/tools/macos_notary_diagnostic.py', 'notary_diagnostic_data')
        cls.helper = load('desktop/tools/macos_android_helper_package.py', 'notary_diagnostic_helper_data')

    def body(self, **changes):
        value = {'logFormatVersion': 1, 'jobId': self.module.SUBMISSION, 'status': self.module.STATUS,
                 'archiveFilename': self.module.ARCHIVE, 'sha256': self.module.ORIGINAL_ARCHIVE, 'issues': [], 'ticketContents': None, 'statusCode': 0 if self.module.STATUS == 'Accepted' else 4000}
        value.update(changes)
        return json.dumps(value).encode()

    def project(self, body, helper):
        # Each synthetic DATA fixture nominates its own bytes; production pins stay fixed.
        with mock.patch.object(self.module, 'ORIGINAL_LOG', self.module.sha(body)):
            return self.module.log_projection(body, helper)

    def test_exact_historical_log_and_independent_archive_gates(self):
        m = self.module
        body = self.body()
        with mock.patch.object(self.helper, 'notary_json', side_effect=AssertionError('parser entered')), \
             mock.patch.object(m, 'ticket_census', side_effect=AssertionError('census entered')):
            for raw in (body, body + b' ', b'x' * (m.LIMIT + 1), 'not bytes'):
                with self.subTest(raw_type=type(raw).__name__), self.assertRaises(m.Refused):
                    m.log_projection(raw, self.helper)
        for archive in (None, True, '0' * 64, '../private'):
            with self.subTest(archive=archive), self.assertRaises(m.Refused):
                self.project(self.body(sha256=archive), self.helper)
        value = json.loads(body); del value['sha256']
        with self.assertRaises(m.Refused):
            self.project(json.dumps(value).encode(), self.helper)
        with mock.patch.object(self.helper, 'notary_log_data', wraps=self.helper.notary_log_data) as strict:
            observed = self.project(body, self.helper)
        self.assertEqual(strict.call_args.args[2], m.ORIGINAL_ARCHIVE)
        self.assertTrue(observed['historicalBytesMatch'] and observed['archiveShaIndependentlyCompared'])
        self.assertFalse(observed['payloadNotarizationQualified'] or observed['productReady'])

    def test_log_binding_privacy_classification_and_complete_group_accounting(self):
        m = self.module
        with mock.patch.object(m, 'STATUS', 'Invalid'):
            issues = [{'severity': 'error', 'path': m.ARCHIVE + '/payload-input/MobileReleaseKit.app/Contents/MacOS/mrk-macos-entry',
                       'message': 'The executable does not have the hardened runtime enabled.', 'architecture': 'arm64', 'code': None},
                      {'severity': 'warning', 'path': '/private/DO_NOT_PUBLISH_PRIVATE_PATH',
                       'message': 'DO_NOT_PUBLISH_PRIVATE_MESSAGE', 'docUrl': 'https://private.invalid/DO_NOT_PUBLISH_URL',
                       'architecture': 'DO_NOT_PUBLISH_ARCH', 'code': 731}]
            projected = self.project(self.body(issues=issues), self.helper)
            public = json.dumps(projected)
            self.assertNotIn('DO_NOT_PUBLISH', public)
            self.assertTrue(projected['archiveShaIndependentlyCompared'])
            self.assertTrue(projected['historicalBytesMatch'])
            self.assertEqual(projected['currentObservedStatus'], 'Invalid')
            self.assertEqual(projected['errorCount'], 1)
            self.assertEqual(projected['warningCount'], 1)
            self.assertEqual({r['pathRole'] for r in projected['issueGroups']}, {'outer-entry', 'unclassified'})
            self.assertEqual({r['messageClass'] for r in projected['issueGroups']}, {'missing-hardened-runtime', 'unclassified'})
            for changes in ({'jobId': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'}, {'status': 'Accepted'},
                            {'archiveFilename': 'Other.zip'}, {'sha256': '../path'}, {'sha256': True}, {'sha256': None}):
                with self.subTest(changes=changes), self.assertRaises(Exception):
                    self.project(self.body(**changes), self.helper)
            for body in (b'{"logFormatVersion":1,"logFormatVersion":1}', b'x' * (m.LIMIT + 1)):
                with self.assertRaises(Exception):
                    self.project(body, self.helper)
            many = [{'severity': 'error', 'path': 'p/' + str(i), 'message': 'm', 'code': None} for i in range(65)]
            value = self.project(self.body(issues=many + [many[0]]), self.helper)
            self.assertEqual((value['errorCount'], value['issueGroupCount'], value['omittedGroupCount']), (66, 65, 1))
            self.assertEqual(len(value['issueGroups']), 64)
            self.assertEqual(len(value['allIssueGroupsSha256']), 64)
            self.assertEqual(projected['statusCode'], 4000)
            self.assertEqual(projected['statusSummaryClass'], 'not-supplied')
            self.assertIsNone(projected['statusSummarySha256'])
            account = self.project(self.body(issues=None, statusCode=7000,
                statusSummary='DO_NOT_PUBLISH_ACCOUNT_PRIVATE_DETAIL'), self.helper)
            self.assertEqual((account['statusCode'], account['errorCount'], account['issueGroupCount']), (7000, 0, 0))
            self.assertEqual(account['statusSummaryClass'], 'unclassified')
            self.assertEqual(len(account['statusSummarySha256']), 64)
            self.assertNotIn('DO_NOT_PUBLISH', json.dumps(account))
            summary = self.project(self.body(issues=None,
                statusSummary='Team is not yet configured for notarization.'), self.helper)
            self.assertEqual(summary['statusSummaryClass'], 'team-not-configured')
            self.assertEqual(summary['currentObservedStatus'], 'Invalid')
        # SOURCE-established component and exact public documentation topics;
        # neither can classify an unknown message or qualify a warning as harmless.
        guide = 'https://developer.apple.com/documentation/security/resolving-common-notarization-issues'
        documented = {
            guide: 'common-notarization-guidance',
            guide + '#Ensure-a-valid-code-signature': 'code-signature-guidance',
            guide + '#Use-a-valid-Developer-ID-certificate': 'developer-id-guidance',
            guide + '#Include-a-secure-timestamp': 'timestamp-guidance',
            guide + '#Avoid-the-get-task-allow-entitlement': 'get-task-allow-guidance',
            guide + '#Use-the-macOS-109-SDK-or-later': 'sdk-version-guidance',
            guide + '#Enable-the-hardened-runtime': 'hardened-runtime-guidance',
            guide + '#Handle-stapler-issues': 'stapler-guidance',
            guide + '#Ensure-properly-formatted-entitlements': 'entitlements-guidance',
            guide + '#Notarize-macOS-apps-with-external-dependencies': 'external-dependencies-guidance',
        }
        self.assertEqual(m.DOCUMENTATION_URLS, documented)
        landmark = 'runtime/python/lib/python314.zip'
        issue = {'severity': 'warning', 'path': m.ARCHIVE + '/payload-input/' + landmark,
                 'message': 'DO_NOT_PUBLISH_UNCLASSIFIED_MESSAGE', 'code': None}
        for prefix in ('', m.ARCHIVE + '/', 'payload-input/', m.ARCHIVE + '/payload-input/'):
            self.assertEqual(m.classify_path(prefix + landmark), 'runtime-python-zip-landmark')
        for path in (landmark + '/', landmark + '.other', landmark.upper(),
                     'payload-input/payload-input/' + landmark):
            self.assertEqual(m.classify_path(path), 'unclassified')
        for url, expected in documented.items():
            with self.subTest(documentation=expected):
                projected = self.project(self.body(issues=[dict(issue, docUrl=url)]), self.helper)
                group, = projected['issueGroups']
                self.assertEqual(group['documentationClass'], expected)
                self.assertEqual(group['pathRole'], 'runtime-python-zip-landmark')
                self.assertEqual(group['pathSha256'], '8d51701b2be46a0501410a98d7ed9ac68a8faa8d61382733f15d02fd83ae4b2a')
                self.assertEqual(group['messageClass'], 'unclassified')
                self.assertEqual((projected['currentObservedStatus'], projected['errorCount'], projected['warningCount']), ('Accepted', 0, 1))
                self.assertFalse(projected['payloadNotarizationQualified'] or projected['productReady'])
                public = json.dumps(projected)
                self.assertNotIn(url, public)
                self.assertNotIn(landmark, public)
                self.assertNotIn('DO_NOT_PUBLISH', public)
        known_url = guide + '#Ensure-a-valid-code-signature'
        unknown_urls = ('https://private.invalid/DO_NOT_PUBLISH_URL', guide + '#DO_NOT_PUBLISH_FRAGMENT',
                        guide + '?DO_NOT_PUBLISH_QUERY', known_url + '?DO_NOT_PUBLISH_QUERY',
                        known_url + '#extra', guide + '/', known_url.lower(),
                        known_url.replace('https:', 'http:'), known_url.replace('.com/', '.com:443/'),
                        known_url.replace('#Ensure', '#%45nsure'))
        for url in unknown_urls:
            with self.subTest(unknown_documentation=url):
                observed = self.project(self.body(issues=[dict(issue, docUrl=url)]), self.helper)
                self.assertEqual(observed['issueGroups'][0]['documentationClass'], 'unclassified')
                self.assertEqual(observed['issueGroups'][0]['messageClass'], 'unclassified')
                self.assertNotIn(url, json.dumps(observed))
                self.assertNotIn('DO_NOT_PUBLISH', json.dumps(observed))
        for row in (issue, dict(issue, docUrl=None)):
            observed = self.project(self.body(issues=[row]), self.helper)
            self.assertEqual(observed['issueGroups'][0]['documentationClass'], 'not-supplied')
        for url in (7, True, 'bad\nurl'):
            observed = self.project(self.body(issues=[dict(issue, docUrl=url)]), self.helper)
            self.assertEqual(observed['strictLogRefusal'], 'notary-log-issue-metadata')
            self.assertEqual(observed['issueGroups'], [])
        document_rows = [dict(issue, docUrl=url) for url in documented]
        document_rows.extend((issue, dict(issue, docUrl=None), dict(issue, docUrl=unknown_urls[0])))
        accounted = self.project(self.body(issues=document_rows), self.helper)
        self.assertEqual((accounted['warningCount'], accounted['issueGroupCount'], accounted['omittedGroupCount']), (13, 12, 0))
        self.assertEqual({row['documentationClass']: row['count'] for row in accounted['issueGroups']},
                         {**dict.fromkeys(documented.values(), 1), 'not-supplied': 2, 'unclassified': 1})
        self.assertEqual(accounted['allIssueGroupsSha256'], m.sha(json.dumps(accounted['issueGroups'], sort_keys=True, separators=(',', ':')).encode()))
        self.assertFalse(accounted['payloadNotarizationQualified'] or accounted['productReady'])
        self.assertNotIn('https://', json.dumps(accounted))
        self.assertNotIn('DO_NOT_PUBLISH', json.dumps(accounted))
        ticket = {'path': 'DO_NOT_PUBLISH_PRIVATE_TICKET', 'digestAlgorithm': 'SHA-256', 'cdhash': 'a' * 40, 'arch': 'arm64'}
        good = self.project(self.body(ticketContents=[ticket, dict(ticket, arch='x86_64')]), self.helper)
        self.assertTrue(good['strictLogAccepted'])
        self.assertIsNone(good['strictLogRefusal'])
        self.assertEqual((good['currentObservedStatus'], good['errorCount'], good['ticketRowCount']), ('Accepted', 0, 2))
        self.assertEqual(good['ticketCensus']['listCount'], 2)
        self.assertFalse(good['payloadNotarizationQualified'] or good['productReady'])
        with self.assertRaises(m.Refused):
            self.project(self.body(status='Invalid'), self.helper)
        missing = json.loads(self.body()); del missing['ticketContents']
        absent = self.project(json.dumps(missing).encode(), self.helper)
        self.assertEqual(absent['strictLogRefusal'], 'notary-log-binding')
        self.assertEqual((absent['ticketCensus']['kind'], absent['ticketCensus']['state']), ('missing', 'not-supplied'))
        self.assertIsNone(absent['ticketCensus']['groupCount'])
        for changed, reason in (
                ({'ticketContents': [dict(ticket, arch='arm64e')]}, 'notary-log-ticket-shape'),
                ({'ticketContents': [dict(ticket, arch=None)]}, 'notary-log-ticket-shape'),
                ({'ticketContents': [dict(ticket, arch='DO_NOT_PUBLISH_ARCH')]}, 'notary-log-ticket-shape'),
                ({'ticketContents': [{k: v for k, v in ticket.items() if k != 'arch'}]}, 'notary-log-ticket-shape'),
                ({'ticketContents': [dict(ticket, extra=True)]}, 'notary-log-ticket-shape'),
                ({'ticketContents': [dict(ticket, path='bad\ntext')]}, 'notary-log-ticket-shape'),
                ({'ticketContents': [dict(ticket, digestAlgorithm='PRIVATE_ALGORITHM')]}, 'notary-log-ticket-shape'),
                ({'ticketContents': [dict(ticket, cdhash='PRIVATE_CDHASH')]}, 'notary-log-ticket-shape'),
                ({'issues': [{'severity': 'error', 'path': 'p', 'message': 'bad\ntext'}]}, 'notary-log-issue-shape'),
                ({'issues': [{'severity': 'error', 'path': 'p', 'message': 'm', 'code': True}]}, 'notary-log-issue-code')):
            observed = self.project(self.body(**changed), self.helper)
            self.assertFalse(observed['strictLogAccepted'])
            self.assertEqual(observed['strictLogRefusal'], reason)
            self.assertIsNone(observed['errorCount'])
            self.assertIsNone(observed['warningCount'])
            self.assertIsNone(observed['issueGroupCount'])
            self.assertEqual(observed['issueProjectionState'], 'unavailable-strict-log-refused')
            self.assertEqual(observed['issueGroups'], [])
            self.assertNotIn('PRIVATE', json.dumps(observed))
            self.assertNotIn('DO_NOT_PUBLISH', json.dumps(observed))
        i386 = self.project(self.body(ticketContents=[dict(ticket, arch='i386')]), self.helper)
        row = i386['ticketCensus']['groups'][0]
        self.assertEqual(row, dict(architecture='i386', exactFourKeys=True, pathTextValid=True,
            digestAlgorithmAllowed=True, cdhash40HexValid=True, strictArchitectureAllowed=True, count=1))
        self.assertTrue(i386['strictLogAccepted'])
        self.assertFalse(i386['payloadNotarizationQualified'] or i386['productReady'])
        for tickets, kind, state in ((None, 'null', 'observed'), ({}, 'other', 'not-a-list'), ([ticket] * 2049, 'list', 'over-bound')):
            census = self.project(self.body(ticketContents=tickets), self.helper)['ticketCensus']
            self.assertEqual((census['kind'], census['state']), (kind, state))
            self.assertEqual(census['groups'], [])
        rows = []
        for mask in range(128):
            row = dict(ticket, arch=('arm64', 'x86_64', 'i386', 'arm64e', 'x86_64h', None, 'PRIVATE_ARCH', 'missing')[mask % 8])
            if row['arch'] == 'missing': del row['arch']
            if mask & 8: row['path'] = 'bad\npath'
            if mask & 16: row['digestAlgorithm'] = 'PRIVATE_ALGORITHM'
            if mask & 32: row['cdhash'] = 'PRIVATE_CDHASH'
            if mask & 64: row['extra'] = True
            rows.append(row)
        dense = self.project(self.body(ticketContents=rows), self.helper)
        self.assertFalse(dense['strictLogAccepted'])
        census = dense['ticketCensus']
        self.assertEqual(census['listCount'], 128)
        self.assertGreater(census['groupCount'], 64)
        self.assertEqual(len(census['groups']), 64)
        self.assertEqual(census['omittedGroupCount'], census['groupCount'] - 64)
        self.assertEqual(len(census['allGroupsSha256']), 64)
        self.assertLessEqual(len(json.dumps(dense, sort_keys=True, separators=(',', ':')).encode()) + 1, 65536)
        self.assertNotIn('PRIVATE', json.dumps(dense))
        with mock.patch.object(self.helper, 'notary_log_data', side_effect=self.helper.Refused('DO_NOT_PUBLISH_EXCEPTION')):
            unknown = self.project(self.body(), self.helper)
            self.assertEqual(unknown['strictLogRefusal'], 'unclassified')
            self.assertFalse(unknown['strictLogAccepted'])
        with mock.patch.object(self.helper, 'notary_log_data', side_effect=RuntimeError('DO_NOT_PUBLISH_EXCEPTION')):
            with self.assertRaises(RuntimeError): self.project(self.body(), self.helper)

    def test_exact_key_custody_retirement_replacement_and_nonrecursive_cleanup(self):
        m = self.module
        import ctypes
        native = mock.Mock(return_value=0)
        library = types.SimpleNamespace(flistxattr=native)
        with mock.patch.dict(m.os.__dict__), mock.patch.object(m.sys, 'platform', 'darwin'), \
             mock.patch.object(m, '_DARWIN_XATTRS', None), \
             mock.patch.object(ctypes, 'CDLL', return_value=library) as load_library:
            m.os.__dict__.pop('listxattr', None)  # Genuine absence, not a Linux fallback.
            for result in (0, 1, -1):
                native.return_value = result
                if result == 0:
                    m.no_xattrs(23)
                else:
                    with self.assertRaises(m.Refused):
                        m.no_xattrs(23)
            self.assertEqual(native.call_args_list, [mock.call(23, None, 0, 0)] * 3)
            load_library.assert_called_once_with('/usr/lib/libSystem.B.dylib', use_errno=True)
            self.assertEqual(native.argtypes, [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int])
            self.assertIs(native.restype, ctypes.c_ssize_t)
            native.reset_mock()
            native.return_value = 0
            with tempfile.TemporaryDirectory() as temporary:
                key = m.KeyDirectory(Path(temporary))
                key.create_key(b'SYNTHETIC DARWIN FD POST TEST')
                original_fd = key.key_fd
                key.finish(True)
                self.assertTrue(key.closed and key.retired and key.scratch_retired)
                self.assertEqual(native.call_args_list, [mock.call(original_fd, None, 0, 0)] * 2)
        with mock.patch.object(m.sys, 'platform', 'unsupported-test-host'):
            with self.assertRaises(m.Refused):
                m.no_xattrs(23)
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            key = m.KeyDirectory(parent)
            key.create_key(b'SYNTHETIC TEST KEY ONLY')
            path = key.path
            self.assertEqual(stat.S_IMODE((path / key.key_name).stat().st_mode), 0o400)
            key.finish(True)
            self.assertTrue(key.closed and key.retired and key.scratch_retired)
            self.assertFalse(path.exists())
            key = m.KeyDirectory(parent); key.create_key(b'SYNTHETIC UNKNOWN KEY')
            key.finish(False)
            self.assertTrue(key.closed)
            self.assertFalse(key.retired)
            self.assertTrue((key.path / key.key_name).exists())
            key = m.KeyDirectory(parent); key.create_key(b'SYNTHETIC REPLACEMENT TEST')
            original = key.path / key.key_name
            original.rename(key.path / 'retained-original')
            original.write_bytes(b'UNRELATED REPLACEMENT')
            with self.assertRaises(m.Refused):
                key.finish(True)
            self.assertTrue(key.closed)
            self.assertFalse(key.retired)
            self.assertEqual(original.read_bytes(), b'UNRELATED REPLACEMENT')
            self.assertTrue((key.path / 'retained-original').exists())
            key = m.KeyDirectory(parent); key.create_key(b'SYNTHETIC EXTRA STATE TEST')
            extra = key.path / 'home' / 'native-created-state'
            extra.write_bytes(b'leave task state intact')
            key.finish(True)
            self.assertTrue(key.retired)
            self.assertFalse(key.scratch_retired)
            self.assertEqual(extra.read_bytes(), b'leave task state intact')
            with mock.patch.object(m.os, 'mkdir', side_effect=OSError('inert injected setup failure')):
                with self.assertRaises(m.Refused):
                    m.KeyDirectory(parent)

    def test_one_owner_call_environment_knownness_deadline_and_first_failure(self):
        m = self.module
        profile = {'keyId': m.KEY_ID, 'issuerId': m.ISSUER}
        calls = []
        class Tool:
            path = Path('/fixed-inert-test-notarytool')
            def post(self):
                pass
            def close(self):
                pass
        for status in (0, 1, -9, True, 256, 'exception'):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                key = m.KeyDirectory(Path(temporary)); key.create_key(b'SYNTHETIC OWNER TEST')
                def invoke(argv, **kwargs):
                    calls.append((argv, kwargs))
                    self.assertEqual(argv, [str(Tool.path), 'log', m.SUBMISSION, '--key', str(key.path / key.key_name),
                                            '--key-id', m.KEY_ID, '--issuer', m.ISSUER])
                    self.assertEqual(set(kwargs['environ']), {'PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'TZ', 'DEVELOPER_DIR'})
                    self.assertNotIn(m.SECRET, kwargs['environ'])
                    self.assertEqual((kwargs['timeout'], kwargs['capture'], kwargs['text'], kwargs['output_limit']), (180, True, False, m.LIMIT))
                    key.post()
                    if status == 'exception':
                        raise OSError('DO_NOT_PUBLISH_EXCEPTION_PRIVATE_DATA')
                    return types.SimpleNamespace(returncode=status, stdout=self.body(), stderr=b'')
                with mock.patch.object(m, 'ORIGINAL_LOG', m.sha(self.body())):
                    report = m.query(types.SimpleNamespace(run_owned=invoke), self.helper, key, profile, Tool(), m.Clock(lambda: 0))
                self.assertEqual(report['diagnosticPassed'], type(status) is int and status == 0)
                known = type(status) is int and 0 <= status <= 255
                self.assertEqual(report['knownExit'], known)
                self.assertEqual(key.retired, known)
                self.assertNotIn('DO_NOT_PUBLISH', json.dumps(report))
                if status != 0:
                    self.assertIsNone(report['currentObservedStatus'])
        self.assertEqual(len(calls), 6)
        for changed in ('log', 'archive'):
            with self.subTest(binding=changed), tempfile.TemporaryDirectory() as temporary:
                key = m.KeyDirectory(Path(temporary)); key.create_key(b'SYNTHETIC BINDING REFUSAL')
                raw = self.body(sha256='0' * 64) if changed == 'archive' else self.body()
                owner = types.SimpleNamespace(run_owned=mock.Mock(return_value=
                    types.SimpleNamespace(returncode=0, stdout=raw, stderr=b'')))
                expected_log = m.sha(raw) if changed == 'archive' else '0' * 64
                with mock.patch.object(m, 'ORIGINAL_LOG', expected_log):
                    report = m.query(owner, self.helper, key, profile, Tool(), m.Clock(lambda: 0))
                self.assertEqual(owner.run_owned.call_count, 1)
                self.assertFalse(report['diagnosticPassed'])
                self.assertEqual(report['failureStage'], 'log-validation')
                self.assertIsNone(report['currentObservedStatus'])
                self.assertNotIn('issueGroups', report)
                self.assertTrue(report['knownExit'] and key.closed and key.retired and report['toolClosed'])
        with tempfile.TemporaryDirectory() as temporary:
            key = m.KeyDirectory(Path(temporary)); key.create_key(b'SYNTHETIC STRICT REFUSAL')
            ticket = {'path': 'PRIVATE_PATH', 'digestAlgorithm': 'SHA-256', 'cdhash': 'a' * 40, 'arch': 'arm64e'}
            owner = types.SimpleNamespace(run_owned=lambda *args, **kwargs:
                types.SimpleNamespace(returncode=0, stdout=self.body(ticketContents=[ticket]), stderr=b''))
            with mock.patch.object(m, 'ORIGINAL_LOG', m.sha(self.body(ticketContents=[ticket]))):
                report = m.query(owner, self.helper, key, profile, Tool(), m.Clock(lambda: 0))
            self.assertTrue(report['diagnosticPassed'])
            self.assertFalse(report['strictLogAccepted'])
            self.assertEqual(report['strictLogRefusal'], 'notary-log-ticket-shape')
            self.assertEqual(report['historicalSubmission']['status'], 'Accepted')
            self.assertTrue(key.closed and key.retired and report['toolClosed'])
            self.assertFalse(report['payloadNotarizationQualified'] or report['productReady'])
        with tempfile.TemporaryDirectory() as temporary:
            key = m.KeyDirectory(Path(temporary)); key.create_key(b'SYNTHETIC DEADLINE TEST')
            values = iter((0, 241, 242))
            owner = types.SimpleNamespace(run_owned=lambda *args, **kwargs: self.fail('deadline dispatched'))
            report = m.query(owner, self.helper, key, profile, Tool(), m.Clock(lambda: next(values)))
            self.assertFalse(report['entered'])
            self.assertEqual(report['failureStage'], 'pre-call')
            self.assertTrue(key.retired)
        with tempfile.TemporaryDirectory() as temporary:
            key = m.KeyDirectory(Path(temporary)); key.create_key(b'SYNTHETIC FIRST FAILURE')
            tool = Tool()
            tool.close = mock.Mock(side_effect=OSError('later close failure'))
            owner = types.SimpleNamespace(run_owned=mock.Mock(side_effect=OSError('first call failure')))
            report = m.query(owner, self.helper, key, profile, tool, m.Clock(lambda: 0))
            self.assertEqual(report['failureStage'], 'original-log-call')
            self.assertEqual(report['cleanupErrors'], ['tool-close'])
            self.assertFalse(key.retired)
            self.assertEqual(tool.close.call_count, 1)

    def test_source_workflow_is_fixed_read_only_and_public_output_exclusive(self):
        source = (ROOT / 'desktop/tools/macos_notary_diagnostic.py').read_text()
        m = self.module
        # Frozen SOURCE assertions, not a claim that Apple reports GitHub provenance.
        self.assertEqual((m.SOURCE, m.SOURCE_TREE, m.ORIGINAL_RECEIPT, m.SUBMISSION, m.STATUS,
                          m.ORIGINAL_ARCHIVE, m.ORIGINAL_LOG),
            ('42861e30546937d221890e7d25e6c633978347ce', '8e79035c6b6e89c8c4d417cfd25f60a3fe921dba',
             '232c3ffeb7be9c1a085417227dc440f9741ca781ce8d42b958a7782911ffc4ad',
             '479ff35b-0731-4d22-8c5a-395aa8c409b4', 'Accepted',
             'a62b6555342f70b907cc288eea5c782c11d12cc11de7b719fdf3c6f7acc88374',
             '53737a949584ba02fa34fc7d2c6fb80f7628dc79b0afb617410c02413382ba01'))
        for path, expected in m.PINS.items():
            self.assertEqual(m.sha((ROOT / path).read_bytes()), expected)
        self.assertIn("'runId': '38332288631', 'attempt': '1'", source)
        self.assertIn("'jobId': '115084521846'", source)
        syntax = ast.parse(source)
        query = next(n for n in syntax.body if isinstance(n, ast.FunctionDef) and n.name == 'query')
        calls = [n for n in ast.walk(query) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == 'run_owned']
        self.assertEqual(len(calls), 1)
        argv = next(n.value for n in ast.walk(query) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'argv' for t in n.targets))
        self.assertEqual(argv.elts[1].value, 'log')
        self.assertFalse(any(isinstance(n, ast.Constant) and n.value in ('submit', 'staple', 'sign') for n in ast.walk(query)))
        workflow = (ROOT / '.github/workflows/desktop-macos-notary-diagnostic.yml').read_text()
        self.assertIn('branches: [verify/desktop-macos-notary-diagnostic]', workflow)
        self.assertIn('environment: macos-developer-id', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('        with:\n          ref: ${{ github.sha }}\n          persist-credentials: false', workflow)
        self.assertIn('runs-on: macos-26', workflow)
        self.assertIn('Classify the exact existing Accepted payload warning', workflow)
        self.assertIn('path: ${{ runner.temp }}/mrk-notary-diagnostic-public.json', workflow)
        self.assertIn('include-hidden-files: false', workflow)
        self.assertEqual(workflow.count('${{ secrets.'), 1)
        self.assertNotIn('workflow_dispatch:', workflow)
        self.assertNotIn('download-artifact', workflow)
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            data = (b'from __future__ import annotations\nfrom dataclasses import dataclass\n'
                    b'@dataclass(frozen=True)\nclass Data:\n    value: int\n')
            (parent / 'data.py').write_bytes(data)
            m = self.module
            name = 'mrk_notary_diagnostic_inert_dataclass'
            with mock.patch.dict(m.PINS, {'data.py': m.sha(data)}), mock.patch.dict(m.sys.modules):
                self.assertNotIn(name, m.sys.modules)
                loaded = m.load_module(parent, 'data.py', name)
                self.assertIs(m.sys.modules[name], loaded)
                self.assertEqual(loaded.Data(3).value, 3)
                with self.assertRaises(m.Refused):
                    m.load_module(parent, 'data.py', name)
                self.assertIs(m.sys.modules[name], loaded)
                original_read = m.source_read
                reads = []
                def replace_after_authenticated_read(root, relative):
                    authenticated = original_read(root, relative)
                    reads.append(relative)
                    if len(reads) == 1:
                        (parent / relative).write_bytes(b'raise AssertionError("changed bytes executed")\n')
                    return authenticated
                race_name = name + '_changed'
                with mock.patch.object(m, 'source_read', side_effect=replace_after_authenticated_read):
                    with self.assertRaises(m.Refused):
                        m.load_module(parent, 'data.py', race_name)
                self.assertNotIn(race_name, m.sys.modules)
            self.assertNotIn(name, m.sys.modules)
            (parent / 'data.py').unlink()
            with self.assertRaises(self.module.Refused):
                self.module.publish(parent, {'oversized': 'x' * 65536})
            self.assertFalse((parent / self.module.PUBLIC).exists())
            self.module.publish(parent, {'diagnosticPassed': False, 'failureStage': 'fixture'})
            original = (parent / self.module.PUBLIC).read_bytes()
            with self.assertRaises(FileExistsError):
                self.module.publish(parent, {'diagnosticPassed': True})
            self.assertEqual((parent / self.module.PUBLIC).read_bytes(), original)
            self.assertEqual(list(parent.iterdir()), [parent / self.module.PUBLIC])
