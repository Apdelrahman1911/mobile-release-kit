"""Bounded DATA fixtures only; never execute a native tool or access /Applications."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('notary_admission_probe', ROOT / 'desktop/tools/macos_notary_admission_probe.py')
DATA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DATA)
PRIVATE = 'PRIVATE_PATH_OR_TOOL_MESSAGE_not_for_publication'


class NotaryAdmissionProbeData(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.body = (ROOT / 'desktop/tools/macos_android_helper_package.py').read_bytes()
        self.namespace = DATA.load_tools(self.body)
        self.xcode = Path(self.temporary.name) / 'Applications/Xcode.app/Contents/Developer'
        binary = self.xcode / 'usr/bin'
        binary.mkdir(parents=True)
        for name in ('notarytool', 'stapler'):
            path = binary / name
            path.write_bytes(b'fixture only; never executable code')
            path.chmod(0o555)
        self.namespace['NOTARY_XCODE'] = self.xcode  # Same genuine method, inert fixture root.
        self.deadline = time.monotonic_ns() + 30_000_000_000

    def test_genuine_methods_admit_fixed_fixture_and_close_both_originals(self):
        value = DATA.observe(self.namespace, self.deadline)
        self.assertTrue(value['diagnosticCompleted'])
        self.assertEqual(value['registeredToolDescriptors'], 2)
        self.assertTrue(value['toolDescriptorsClosed'])
        self.assertEqual([row['tool'] for row in value['tools']], ['notarytool', 'stapler'])
        for row in value['tools']:
            self.assertTrue(row['toolAdmissionPassed'])
            self.assertEqual(row['admission'], {'state': 'admitted', 'reason': None, 'errno': None})
            self.assertEqual(row['post']['state'], 'observed')
            self.assertTrue(all(item['predicateAccepted'] for item in row['laterCensus']['rows']))
        encoded = DATA.encode(value)
        self.assertLessEqual(len(encoded), DATA.OUTPUT_LIMIT)
        self.assertNotIn(str(self.xcode), encoded.decode())
        self.assertNotIn('fixture only', encoded.decode())

    def test_ancestry_refusal_retains_primary_and_separates_later_metadata(self):
        applications = self.xcode.parents[2]
        applications.chmod(0o775)
        value = DATA.observe(self.namespace, self.deadline)
        self.assertEqual(value['registeredToolDescriptors'], 0)
        for row in value['tools']:
            self.assertFalse(row['toolAdmissionPassed'])
            self.assertEqual(row['admission']['reason'], 'notary-selected-tool-ancestry')
            observed = [item for item in row['laterCensus']['rows'] if item['role'] == 'applications']
            self.assertEqual(len(observed), 1)
            self.assertTrue(observed[0]['groupWritable'])
            self.assertFalse(observed[0]['otherWritable'])
            self.assertFalse(observed[0]['predicateAccepted'])
            self.assertEqual(observed[0]['groupIsRootOrAdmin'], applications.stat().st_gid in (0, 80))
        applications.chmod(0o777)
        self.assertTrue(next(item for item in DATA.census(self.namespace, 'notarytool', self.deadline)
            if item['role'] == 'applications')['otherWritable'])
        with mock.patch.object(DATA, 'census', side_effect=OSError(13, PRIVATE)):
            later = DATA.observe(self.namespace, self.deadline)
        self.assertEqual(later['tools'][0]['admission'], value['tools'][0]['admission'])
        self.assertEqual(later['tools'][0]['laterCensus']['errno'], 13)
        self.assertNotIn(PRIVATE, DATA.encode(later).decode())
        applications.chmod(0o755)
        original_census = DATA.census
        def change_after_observation(namespace, name, deadline):
            rows = original_census(namespace, name, deadline)
            if name == 'notarytool':
                (self.xcode / 'usr/bin/notarytool').chmod(0o444)
            return rows
        with mock.patch.object(DATA, 'census', side_effect=change_after_observation):
            changed = DATA.observe(self.namespace, self.deadline)
        self.assertTrue(changed['tools'][0]['toolAdmissionPassed'])  # First returned observation only.
        self.assertEqual(changed['tools'][0]['admission']['state'], 'admitted')
        self.assertEqual(changed['tools'][0]['post']['reason'], 'notary-selected-tool-changed')
        self.assertTrue(changed['toolDescriptorsClosed'])

    def test_fixed_alias_is_observed_but_missing_and_escape_are_not_admitted(self):
        fixed = self.xcode.parent.parent
        resolved = fixed.with_name('Xcode_fixture.app')
        fixed.rename(resolved)
        fixed.symlink_to(resolved.name)
        value = DATA.observe(self.namespace, self.deadline)
        self.assertTrue(all(row['toolAdmissionPassed'] for row in value['tools']))
        aliases = [row for row in value['tools'][0]['laterCensus']['rows'] if row['role'] == 'xcode-alias']
        self.assertEqual(len(aliases), 1)
        self.assertTrue(aliases[0]['selectedAlias'])
        (self.xcode / 'usr/bin/notarytool').unlink()
        missing = DATA.observe(self.namespace, self.deadline)
        self.assertEqual(missing['tools'][0]['admission']['state'], 'os-error')
        outside = Path(self.temporary.name) / PRIVATE
        outside.write_bytes(b'not a tool')
        outside.chmod(0o555)
        (self.xcode / 'usr/bin/notarytool').symlink_to(outside)
        escaped = DATA.observe(self.namespace, self.deadline)
        self.assertEqual(escaped['tools'][0]['admission']['reason'], 'notary-selected-tool-path')
        self.assertEqual(escaped['tools'][0]['laterCensus']['state'], 'unavailable')
        self.assertNotIn(PRIVATE, DATA.encode(escaped).decode())

    def test_registered_descriptor_is_closed_on_error_and_unknown_close_refuses_report(self):
        original = self.namespace['FixedTools']
        entries = []
        class RegistrationFailure(original):
            def register(self, *args, **kwargs):
                entry = super().register(*args, **kwargs)
                entries.append(entry)
                raise RuntimeError(PRIVATE)
        self.namespace['FixedTools'] = RegistrationFailure
        with self.assertRaises(DATA.ProbeRefused):
            DATA.observe(self.namespace, self.deadline)
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]['closed'])
        self.assertIsNone(entries[0]['fd'])
        self.namespace['FixedTools'] = original
        calls = []
        def closed_but_unknown(fd):
            calls.append(fd)
            os.close(fd)
            raise OSError(5, PRIVATE)
        self.namespace['os'] = SimpleNamespace(open=os.open, getuid=os.getuid, readlink=os.readlink,
            fstat=os.fstat, close=closed_but_unknown)
        with self.assertRaises(DATA.ProbeRefused):
            DATA.observe(self.namespace, self.deadline)
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(set(calls)), 2)  # No retries after uncertain closes.

    def test_source_loader_and_boundaries_do_not_import_or_initialize_product(self):
        self.assertNotIn('subprocess', self.namespace)
        self.assertNotIn('__init__', self.namespace['FixedTools'].__dict__)
        self.assertEqual({key for key in self.namespace['FixedTools'].__dict__ if not key.startswith('__')}, set(DATA.METHODS))
        with self.assertRaises(DATA.ProbeRefused):
            DATA.load_tools(self.body + b'\nREAD_FLAGS = 0\n')
        path = Path(self.temporary.name) / 'source.py'
        path.write_bytes(self.body)
        self.assertEqual(DATA.source_bytes(path, self.deadline), self.body)
        path.write_bytes(b'x' * (DATA.SOURCE_LIMIT + 1))
        with self.assertRaises(DATA.ProbeRefused):
            DATA.source_bytes(path, self.deadline)
        with self.assertRaises(DATA.ProbeRefused):
            DATA.clock(0)
        with self.assertRaises(DATA.ProbeRefused):
            DATA.encode({'oversize': 'x' * DATA.OUTPUT_LIMIT})
        self.assertEqual(DATA.failure(self.namespace['Refused'](PRIVATE), self.namespace['Refused']),
            {'state': 'refused', 'reason': 'unclassified', 'errno': None})

    def test_host_context_is_exact_and_workflow_is_isolated_readonly(self):
        source = 'a' * 40
        environment = {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': DATA.REF,
            'GITHUB_REPOSITORY': 'Apdelrahman1911/mobile-release-kit', 'GITHUB_WORKSPACE': str(DATA.ROOT),
            'GITHUB_WORKFLOW_REF': DATA.WORKFLOW, 'GITHUB_SHA': source, 'GITHUB_WORKFLOW_SHA': source,
            'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'ARM64',
            'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
        host = SimpleNamespace(sysname='Darwin', machine='arm64')
        arguments = (str(DATA.ROOT / DATA.SCRIPT), host, 501, 501, 20, 20)
        self.assertEqual(DATA.context(environment, *arguments)['source'], source)
        for key in environment:
            with self.subTest(key=key), self.assertRaises(DATA.ProbeRefused):
                DATA.context({**environment, key: PRIVATE}, *arguments)
        for bad in ((str(DATA.ROOT / PRIVATE), host, 501, 501, 20, 20),
                    (arguments[0], SimpleNamespace(sysname='Darwin', machine='x86_64'), 501, 501, 20, 20),
                    (arguments[0], host, 0, 0, 20, 20)):
            with self.assertRaises(DATA.ProbeRefused):
                DATA.context(environment, *bad)
        workflow = (ROOT / '.github/workflows/desktop-macos-notary-admission.yml').read_text()
        self.assertEqual(workflow.count('      - verify/desktop-macos-notary-admission\n'), 1)
        self.assertIn("if: github.event_name == 'push' && github.ref == '" + DATA.REF + "'", workflow)
        self.assertIn('    runs-on: macos-26\n    timeout-minutes: 5\n', workflow)
        self.assertIn('permissions:\n  contents: read\n', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('          path: notary-admission-public.json\n', workflow)
        self.assertIn("if: steps.probe.outcome == 'success'", workflow)
        self.assertIn('/usr/bin/python3 -I -S -B ' + DATA.SCRIPT, workflow)
        self.assertIn('retention-days: 14', workflow)
        for forbidden in ('secrets.', 'environment:', 'workflow_dispatch:', 'id-token:', 'cargo ', 'xcrun ', 'notarytool submit'):
            self.assertNotIn(forbidden, workflow)
        installed = (ROOT / '.github/workflows/desktop-macos-installed.yml').read_text()
        self.assertNotIn('verify/desktop-macos-notary-admission', installed)


if __name__ == '__main__':
    unittest.main()
