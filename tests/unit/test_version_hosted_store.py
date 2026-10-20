"""Owned-process/TLS boundary doubles only, never a P8/provider/native test.

Actual source hashing, private environment selection and current-inventory
parsing run normally. No command, TLS connection or credential is used.
"""
import base64
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import version_hosted as h
from mobile_release import version_hosted_store as store
from mobile_release import version_ci as ci
from mobile_release import ios_store_versions as ios
from mobile_release import _github_connection_transport as tls
from test_version_hosted import SourceData
from test_version_ci import Fixture, NOW, oid


class HostedOriginalBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tooling = self.root / 'tooling'
        self.tooling.mkdir()
        self.fixture = Fixture(self.root, 2)
        self.context = SourceData(self.fixture).context
        self.clock, self.wall = 100.0, NOW + 0.75
        self.calls = []
        self.source = None
        self.env = {store._KEY: 'ABCDEFGHIJ', store._ISSUER: '00000000-0000-4000-8000-000000000001',
            store._P8: base64.b64encode(b'INERT private input, never a real key').decode(),
            'PATH': '/inert', 'GH_TOKEN': 'INERT gh token', 'HTTPS_PROXY': 'INERT proxy',
            'RUBYOPT': '-rINERT', 'SSL_CERT_FILE': '/ambient/ignored.pem'}
        self.patches = [patch.dict(h.os.environ, self.env, clear=True),
            patch.object(ci.time, 'monotonic', lambda: self.clock), patch.object(h.time, 'time', lambda: self.wall)]
        for item in self.patches:
            item.start(); self.addCleanup(item.stop)

    def source_data(self):
        source = h._Source(self.root, self.context, SimpleNamespace(check=lambda: None))
        source.binding = self.fixture.request.source
        source.identity = self.fixture.request.identity_revision
        source.app_id, source.bundle_id = '1234567890', 'com.example.inert'
        self.source = source
        return source

    def frame(self, material, source):
        context = material.context(source)
        app = {'data': {'type': 'apps', 'id': source.app_id, 'attributes': {'bundleId': source.bundle_id}}}
        empty = {'data': [], 'links': {'next': None}, 'meta': {'paging': {'total': 0, 'limit': 200}}}
        pages = []
        for step in ('app-before', *ios.COLLECTIONS, 'app-after'):
            raw = h.p.canonical(app if step.startswith('app-') else empty)
            pages.append({'step': step, 'request': ios.request(step, source.app_id),
                'response': {'status': 200, 'failure': None, 'bodyBase64': base64.b64encode(raw).decode()}})
        return h.p.canonical({'schemaVersion': 1, 'scope': ios.SCOPE, 'contextSha256': context,
            'appStoreAppId': source.app_id, 'bundleId': source.bundle_id, 'pages': pages, 'queryFinished': True}) + b'\n'

    @contextmanager
    def scratch(self, **kwargs):
        self.assertEqual(kwargs, {'layout': 'online-runner', 'cancellation': self.source.guard})
        self.calls.append('scratch-enter')
        try:
            yield SimpleNamespace(_path=self.root)
        finally:
            self.calls.append('scratch-closed')

    def test_same_original_remaining_clock_private_environment_real_summary_after_close(self):
        source = self.source_data()
        material = store.Material(self.tooling); source.material = material
        self.clock = 120.2
        raw = self.frame(material, source)
        def command(argv, **kwargs):
            self.calls.append('command-returned')
            self.assertEqual(argv, ios.fixed_argv(self.tooling))
            self.assertEqual((kwargs['timeout'], kwargs['output_limit'], kwargs['text']), (39, ios.FRAME_LIMIT, False))
            self.assertIs(kwargs['cancellation'], source.guard)
            env = kwargs['environ']
            self.assertEqual(env[store._P8], self.env[store._P8])
            self.assertEqual(env['SSL_CERT_FILE'], str(self.tooling / h.CA_PATH))
            self.assertEqual((env['BUNDLE_FROZEN'], env['BUNDLE_IGNORE_CONFIG'], env['BUNDLE_AUTO_INSTALL']), ('true', '1', 'false'))
            self.assertFalse({'GH_TOKEN', 'HTTPS_PROXY', 'RUBYOPT', 'GOOGLE_APPLICATION_CREDENTIALS'} & env.keys())
            return subprocess.CompletedProcess(argv, 0, raw, b'')
        with patch.object(store, 'finite_scratch', self.scratch), patch.object(store, 'run_owned', command):
            result = material.observe(source, material.context(source))
            with self.assertRaises(h.Refused): material.observe(source, material.context(source))
        self.assertEqual(self.calls, ['scratch-enter', 'command-returned', 'scratch-closed'])
        self.assertEqual((result.observed_at, result.max_build, result.marketing_version), (NOW, 0, None))
        self.assertNotIn(self.env[store._P8], repr(material))
        self.assertNotIn(self.env[store._P8], str(result.value()))

    def test_partial_failed_stderr_and_child_or_scratch_unknown_never_return_inventory(self):
        for condition in ('partial', 'nonzero', 'stderr', 'child-unknown', 'scratch-unknown', 'expired', 'changed-key'):
            with self.subTest(condition=condition):
                self.clock = 100.0
                source = self.source_data(); material = store.Material(self.tooling); source.material = material
                raw = self.frame(material, source)
                def command(argv, **kwargs):
                    if condition == 'child-unknown': raise OSError('INERT private failure')
                    if condition == 'expired': self.clock = 160.0
                    if condition == 'changed-key': h.os.environ[store._KEY] = 'KLMNOPQRST'
                    return subprocess.CompletedProcess(argv, 1 if condition == 'nonzero' else 0,
                        raw[:-30] if condition == 'partial' else raw, b'INERT private stderr' if condition == 'stderr' else b'')
                @contextmanager
                def scratch(**kwargs):
                    with self.scratch(**kwargs) as value:
                        yield value
                        if condition == 'scratch-unknown': raise OSError('INERT private close')
                with patch.object(store, 'finite_scratch', scratch), patch.object(store, 'run_owned', command):
                    with self.assertRaises(Exception): material.observe(source, material.context(source))
                    self.assertTrue(material.used)
                    with self.assertRaises(Exception): material.observe(source, material.context(source))
                h.os.environ[store._KEY] = self.env[store._KEY]

    def test_missing_or_replaced_private_input_no_ambient_fallback(self):
        source = self.source_data()
        for replacement in ('', 'not-base64', base64.b64encode(b'x' * (16 * 1024 + 1)).decode()):
            with patch.dict(h.os.environ, {store._P8: replacement}), self.assertRaises(h.Refused):
                store.Material(self.tooling)
        material = store.Material(self.tooling)
        with patch.dict(h.os.environ, {store._P8: base64.b64encode(b'INERT different bytes').decode()}):
            with self.assertRaises(h.Refused): material.context(source)
        self.assertEqual(self.calls, [])

    def test_real_source_hashes_fixed_ca_and_twelve_original_calls_no_unrelated_tree_read(self):
        fixture = self.fixture
        config = dict(fixture.config)
        config['ios'] = {**config['ios'], 'appStoreAppId': '1234567890'}
        config_raw = json.dumps(config, sort_keys=True).encode()
        config_oid = oid('blob', config_raw)
        ca = b'INERT fixed CA bytes, no TLS execution\n'
        ca_oid = oid('blob', ca)
        blobs = {config_oid: config_raw, fixture.before_oid: fixture.before, ca_oid: ca}
        source = h._Source(self.root, self.context, SimpleNamespace(check=lambda: None))
        def command(argv, **kwargs):
            args = argv[argv.index('-C') + 2:]
            self.calls.append(args)
            self.assertNotIn('GH_TOKEN', kwargs['environ'])
            self.assertNotIn(store._P8, kwargs['environ'])
            self.assertIn('protocol.allow=never', argv)
            self.assertEqual(kwargs['environ']['GIT_NO_LAZY_FETCH'], '1')
            if args == ['rev-parse', '--verify', 'HEAD']:
                expected = self.context.trusted_tooling_commit if kwargs['cwd'] == self.tooling else fixture.before_commit
                raw = (expected + '\n').encode()
            elif args[:2] == ['cat-file', 'commit']:
                raw = fixture.before_commit_raw
            elif args[:2] == ['cat-file', 'blob']:
                raw = blobs[args[2]]
            else:
                self.assertEqual(args[:3], ['ls-tree', '-z', '--full-tree'])
                self.assertEqual(args[-2], '--')
                path = args[-1]
                which = config_oid if path == h.version_text.CONFIG_PATH else ca_oid if path == h.CA_PATH else fixture.before_oid
                raw = f'100644 blob {which}\t{path}\0'.encode()
            return subprocess.CompletedProcess(argv, 0, raw, b'')
        with patch.object(ci, 'run_owned', command):
            source.capture()
            self.assertEqual(source.binding.configuration_sha256, hashlib.sha256(config_raw).hexdigest())
            self.assertEqual(source.checked_ca(self.tooling), hashlib.sha256(ca).hexdigest())
            self.assertEqual(source.root, self.root)
            for _ in range(3): source.check()  # before selection, PUT, final
            self.assertEqual(source.git_calls, 12)
            with self.assertRaises(ci.Refused): source.check()
        self.assertEqual(len(self.calls), 12)

    def test_source_allocation_branch_and_clock_rollback_never_start_a_command(self):
        from dataclasses import replace
        context = replace(self.context, authority={**self.context.authority, 'ref': 'refs/heads/' + h.a.LEDGER_BRANCH})
        source = h._Source(self.root, context, SimpleNamespace(check=lambda: None))
        with patch.object(ci, 'run_owned', side_effect=AssertionError('must not start')):
            with self.assertRaises(h.Refused): source.capture()
        self.wall -= .1
        with self.assertRaises(h.Refused): source.epoch()
        self.clock = 99.0
        with self.assertRaises(ci.Refused): source.remaining()

    def test_actual_raw_http_roles_keep_error_body_private_and_refuse_history_link_or_redirect(self):
        roles = tls._ResponseRole
        def parse(status, raw, role, headers=b''):
            wire = f'HTTP/1.1 {status} INERT\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\n'.encode() + headers + b'\r\n' + raw
            budget = tls._Budget(100, monotonic=lambda: 101, _profile=tls._ExchangeProfile.HOSTED_VERSION)
            response = tls._ResponseBody(io.BytesIO(wire), budget, _role=role)
            return tls._response_result(response, budget)
        self.assertEqual(parse(201, b'{"commit":{}}', roles.HOSTED_VERSION_JOURNAL_WRITE).observation['status'], 201)
        for status, role in ((404, roles.HOSTED_VERSION_JOURNAL_READ), (409, roles.HOSTED_VERSION_JOURNAL_WRITE),
                             (422, roles.HOSTED_VERSION_LEDGER_WRITE)):
            result = parse(status, b'INERT SECRET ERROR BODY', role)
            self.assertIsNone(result.observation['body'])
            self.assertEqual(result.control['reason'], 'none')
        self.assertEqual(parse(200, b'[]', roles.HOSTED_VERSION_HISTORY).observation['body'], [])
        self.assertIsNone(parse(200, b'[]', roles.HOSTED_VERSION_HISTORY,
            b'Link: <https://api.github.com/else>; rel="next"\r\n').observation['body'])
        self.assertIsNone(parse(302, b'{}', roles.HOSTED_VERSION_READ,
            b'Location: https://else.invalid/\r\n').observation['body'])
        self.assertNotEqual(parse(200, b'{}', roles.HOSTED_VERSION_READ,
            b'Retry-After: 1\r\n').control['reason'], 'none')

    def test_fixed_ca_hash_is_required_and_checked_on_original_loaded_bytes_without_network(self):
        fixed = b'INERT CA\n'
        # The live factory binds the original default clock in _Budget; no IO
        # is performed, but use its actual start rather than a foreign epoch.
        started = tls._Budget.__init__.__kwdefaults__['monotonic']()
        kwargs = dict(started=started, runtime_dir=str(self.tooling), api_version='2026-03-10',
                      _profile=tls._ExchangeProfile.HOSTED_VERSION)
        with patch.object(tls, '_fixed_ca', return_value=fixed.decode()) as read, \
             patch('ssl.SSLContext') as context:
            with self.assertRaises(ValueError): tls._make_live_exchange('INERT', **kwargs)
            self.assertFalse(read.called)
            with self.assertRaises(ValueError):
                tls._make_live_exchange('INERT', **kwargs, _hosted_ca_sha256='0' * 64)
            self.assertFalse(context.return_value.load_verify_locations.called)
            tls._make_live_exchange('INERT', **kwargs, _hosted_ca_sha256=hashlib.sha256(fixed).hexdigest())
            context.return_value.load_verify_locations.assert_called_once_with(cadata=fixed.decode())
            self.assertEqual(read.call_count, 2)
            with self.assertRaises(ValueError):
                tls._make_live_exchange('INERT', started=100.0, runtime_dir=str(self.tooling), api_version='2022-11-28',
                    _hosted_ca_sha256=hashlib.sha256(fixed).hexdigest())

    def test_cli_failure_output_is_fixed_and_never_provider_or_private_data(self):
        out, error = io.StringIO(), io.StringIO()
        with patch.object(h, 'reserve', side_effect=OSError('INERT PRIVATE KEY')), redirect_stdout(out), redirect_stderr(error):
            self.assertEqual(h.main(['reserve']), 1)
            self.assertEqual(h.main(['delete']), 1)
        self.assertEqual(out.getvalue(), '')
        self.assertNotIn('INERT PRIVATE KEY', error.getvalue())
