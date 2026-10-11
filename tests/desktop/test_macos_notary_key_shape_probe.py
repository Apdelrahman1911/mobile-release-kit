"""Synthetic DATA-only inputs; no real credential, tool, owner or authentication."""
import ast
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('notary_key_shape_probe_data', ROOT / 'desktop/tools/macos_notary_key_shape_probe.py')
DATA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DATA)
PEM = b'-----BEGIN PRIVATE KEY-----\nQUJDRA==\n-----END PRIVATE KEY-----\n'


def helper():
    return (ROOT / DATA.HELPER).read_bytes()


def encoded(body):
    return base64.b64encode(body).decode('ascii')


def environment():
    return {'GITHUB_SHA': '1' * 40, 'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'push',
        'GITHUB_REF': DATA.REF, 'GITHUB_REPOSITORY': 'Apdelrahman1911/mobile-release-kit',
        'GITHUB_WORKSPACE': str(DATA.ROOT), 'GITHUB_WORKFLOW_REF': DATA.WORKFLOW,
        'GITHUB_WORKFLOW_SHA': '1' * 40, 'RUNNER_ENVIRONMENT': 'github-hosted',
        'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64', 'GITHUB_RUN_ID': '12', 'GITHUB_RUN_ATTEMPT': '1'}


class NotaryKeyShapeProbeData(unittest.TestCase):
    def test_genuine_parser_preserves_exact_original_refusal_classes(self):
        namespace = DATA.load_parser(helper())
        for eol in (b'\n', b'\r\n', b'\r'):
            for original in (PEM.replace(b'\n', eol), PEM[:-1].replace(b'\n', eol)):
                self.assertEqual(namespace['notary_key_data']({DATA.VARIABLE: encoded(original)}), original)
                self.assertEqual(DATA.observe(namespace, encoded(original)), {'keyShapeAccepted': True,
                    'reason': None, 'newlineCompatibility': 'not-evaluated'})
        mixed = PEM.replace(b'\n', b'\r\n', 1).replace(b'QUJDRA==\n', b'QUJDRA==\r')
        self.assertEqual(namespace['notary_key_data']({DATA.VARIABLE: encoded(mixed)}), mixed)
        header, footer = b'-----BEGIN PRIVATE KEY-----\n', b'-----END PRIVATE KEY-----\n'
        space = 8192 - len(header) - len(footer)
        prefix = b'AA\n' if space % 2 else b''
        bounded = header + prefix + b'A\n' * ((space - len(prefix)) // 2) + footer
        self.assertEqual(len(bounded), 8192)
        self.assertEqual(namespace['notary_key_data']({DATA.VARIABLE: encoded(bounded)}), bounded)
        cases = [(value, 'notary-key-input') for value in (None, '', 1, 'éééé', 'AAAA\n', 'AA A', '!!!!', 'A' * 10925)]
        cases += [('AAAAA', 'notary-key-base64'), ('eB==', 'notary-key-pem-shape')]
        cases += [(encoded(value), 'notary-key-pem-shape') for value in
            (b'PRIVATE-SENTINEL', bounded.replace(header, header + b'A', 1),
             bounded.replace(b'\n', b'\r\n', 1), b'\0', b'\xff',
             b' ' + PEM, PEM + b' ', PEM + b'\n', PEM + PEM,
             PEM.replace(b'END PRIVATE KEY', b'END PUBLIC KEY'),
             PEM.replace(b'QUJDRA==', b''), PEM.replace(b'QUJDRA==', b'A' * 65),
             PEM.replace(b'QUJDRA==', b' QUJDRA=='), PEM.replace(b'QUJDRA==', b'QUJD\tRA=='))]
        for value, reason in cases:
            with self.subTest(reason=reason):
                observed = DATA.observe(namespace, value)
                self.assertIs(observed['keyShapeAccepted'], False)
                self.assertEqual(observed['reason'], reason)
                text = json.dumps(observed)
                for private in ('PRIVATE-SENTINEL', 'QUJDRA==', 'BEGIN PRIVATE KEY', 'sha256', 'bytes', 'length'):
                    self.assertNotIn(private, text)
        with self.assertRaises(DATA.ProbeRefused):
            DATA.observe({**namespace, 'notary_key_data': lambda _: (_ for _ in ()).throw(namespace['Refused']('PRIVATE-SENTINEL'))}, 'AAAA')

    def test_newline_observation_never_repairs_or_promotes_original_input(self):
        namespace = DATA.load_parser(helper())
        for body, supplemental in ((PEM.replace(b'\n', b'\r\n'), 'crlf-only'),
                (PEM[:-1], 'terminal-lf-only'), (PEM[:-1].replace(b'\n', b'\r\n'), 'crlf-only')):
            value = encoded(body)
            # Standard inputs now pass the real parser; the diagnostic does not repair them.
            with patch.object(DATA, 'newline_compatibility', side_effect=AssertionError('unexpected supplement')):
                self.assertEqual(DATA.observe(namespace, value), {'keyShapeAccepted': True, 'reason': None,
                    'newlineCompatibility': 'not-evaluated'})
            self.assertEqual(namespace['notary_key_data']({DATA.VARIABLE: value}), body)
            # Direct reducer coverage only, not an assertion that the primary refused.
            self.assertEqual(DATA.newline_compatibility(namespace, value), supplemental)
            self.assertEqual(value, encoded(body))
        self.assertEqual(DATA.observe(namespace, encoded(b'PRIVATE-SENTINEL')),
            {'keyShapeAccepted': False, 'reason': 'notary-key-pem-shape', 'newlineCompatibility': 'no-match'})
        for body in (b'A' * 8193, b'\0', b'\xff'):
            observed = DATA.observe(namespace, encoded(body))
            self.assertEqual(observed['newlineCompatibility'], 'not-evaluated')
            self.assertEqual(observed['reason'], 'notary-key-pem-shape')
            self.assertIs(observed['keyShapeAccepted'], False)
        original = namespace['notary_key_data']; calls = []
        def failing_supplement(mapping):
            calls.append(None)
            if len(calls) == 1:
                return original(mapping)
            raise RuntimeError('PRIVATE-SENTINEL')
        result = DATA.observe({**namespace, 'notary_key_data': failing_supplement}, encoded(b'PRIVATE-SENTINEL'))
        self.assertEqual(result, {'keyShapeAccepted': False, 'reason': 'notary-key-pem-shape',
                                 'newlineCompatibility': 'not-evaluated'})
        self.assertEqual(len(calls), 2)

    def test_source_loader_selects_only_the_four_genuine_definitions(self):
        body = helper()
        namespace = DATA.load_parser(body + b'\nraise RuntimeError("PRIVATE-SENTINEL")\n')
        self.assertEqual({key for key in namespace if not key.startswith('__')},
            {'base64', 're', 'NOTARY_KEY_VARIABLE', 'Refused', 'need', 'notary_key_data'})
        self.assertEqual(namespace['notary_key_data']({DATA.VARIABLE: encoded(PEM)}), PEM)
        for bad in (b'', b'X' * (DATA.SOURCE_LIMIT + 1), body + b'\nclass Refused(Exception): pass\n',
                    body.replace(b'NOTARY_KEY_VARIABLE =', b'OTHER_KEY_VARIABLE =', 1),
                    body.replace(DATA.VARIABLE.encode(), b'OTHER_PRIVATE_VARIABLE', 1)):
            with self.assertRaises(DATA.ProbeRefused):
                DATA.load_parser(bad)

    def test_source_read_bounds_identity_and_known_close_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / 'helper.py'; path.write_bytes(b'public source')
            deadline = time.monotonic_ns() + 60_000_000_000
            self.assertEqual(DATA.source_bytes(path, deadline), b'public source')
            linked = root / 'linked'; linked.symlink_to(path)
            with self.assertRaises(OSError): DATA.source_bytes(linked, deadline)
            with self.assertRaises(DATA.ProbeRefused): DATA.source_bytes(path, 0)
            path.write_bytes(b'X' * (DATA.SOURCE_LIMIT + 1))
            with self.assertRaises(DATA.ProbeRefused): DATA.source_bytes(path, deadline)
            path.write_bytes(b'public source')
            original_close = os.close; closed = []
            def uncertain_close(fd):
                original_close(fd); closed.append(fd)
                raise OSError('PRIVATE-SENTINEL')
            with patch.object(DATA.os, 'close', uncertain_close):
                with self.assertRaises(OSError): DATA.source_bytes(path, deadline)
            self.assertEqual(len(closed), 1)
            with self.assertRaises(OSError): os.fstat(closed[0])
            original_read = os.read
            def changed_read(fd, size):
                value = original_read(fd, size)
                path.chmod(0o400)
                return value
            with patch.object(DATA.os, 'read', changed_read):
                with self.assertRaises(DATA.ProbeRefused): DATA.source_bytes(path, deadline)
            path.chmod(0o600)

    def test_exact_host_context_precedes_any_environment_value_lookup(self):
        host = SimpleNamespace(sysname='Linux', machine='x86_64')
        env = environment(); args = (DATA.ROOT / DATA.SCRIPT, host, 1001, 1001, 1001, 1001)
        result = DATA.context(env, *args)
        self.assertEqual(result['source'], '1' * 40)
        for key in env:
            bad = dict(env); bad[key] = 'PRIVATE-SENTINEL'
            with self.subTest(key=key), self.assertRaises(DATA.ProbeRefused): DATA.context(bad, *args)
        for new_args in ((DATA.ROOT / 'other.py', host, 1001, 1001, 1001, 1001),
                (args[0], SimpleNamespace(sysname='Darwin', machine='arm64'), 1001, 1001, 1001, 1001),
                (args[0], host, 0, 0, 0, 0), (args[0], host, 1001, 1002, 1001, 1001),
                (args[0], host, 1001, 1001, 1001, 1002)):
            with self.assertRaises(DATA.ProbeRefused): DATA.context(env, *new_args)
        with patch.dict(os.environ, {DATA.VARIABLE: 'SYNTHETIC-PRIVATE-SENTINEL'}, clear=True), \
                patch.object(DATA, 'context', side_effect=DATA.ProbeRefused()), \
                patch.object(DATA, 'source_bytes') as source, patch.object(DATA, 'observe') as observe, \
                patch.object(DATA.sys, 'stdout', io.StringIO()) as out, patch.object(DATA.sys, 'stderr', io.StringIO()) as err:
            self.assertEqual(DATA.main(), 1)
            source.assert_not_called(); observe.assert_not_called()
            self.assertNotIn(DATA.VARIABLE, os.environ)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn('SYNTHETIC-PRIVATE-SENTINEL', err.getvalue())

    def test_main_report_is_closed_and_unexpected_failure_cannot_publish(self):
        metadata = DATA.context(environment(), DATA.ROOT / DATA.SCRIPT,
            SimpleNamespace(sysname='Linux', machine='x86_64'), 1001, 1001, 1001, 1001)
        for value, accepted in ((encoded(PEM), True), ('SYNTHETIC-PRIVATE-SENTINEL', False)):
            with patch.dict(os.environ, {DATA.VARIABLE: value}, clear=True), \
                    patch.object(DATA, 'context', return_value=metadata), patch.object(DATA, 'source_bytes', return_value=helper()), \
                    patch.object(DATA.sys, 'stdout', io.StringIO()) as out, patch.object(DATA.sys, 'stderr', io.StringIO()) as err:
                self.assertEqual(DATA.main(), 0)
                self.assertNotIn(DATA.VARIABLE, os.environ)
                report = json.loads(out.getvalue())
                self.assertEqual(set(report), {'schemaVersion', 'kind', *metadata, 'helperSourceSha256',
                    'diagnosticCompleted', 'keyShapeAccepted', 'reason', 'newlineCompatibility',
                    'authenticationAttempted', 'keyFileCreated'})
                self.assertEqual(report['keyShapeAccepted'], accepted)
                self.assertIs(report['diagnosticCompleted'], True)
                self.assertIs(report['authenticationAttempted'], False); self.assertIs(report['keyFileCreated'], False)
                self.assertLessEqual(len(out.getvalue().encode()), DATA.OUTPUT_LIMIT)
                self.assertNotIn(value, out.getvalue()); self.assertEqual(err.getvalue(), '')
        for fault in ('observe', 'close', 'output-bound', 'write'):
            with patch.dict(os.environ, {DATA.VARIABLE: encoded(PEM)}, clear=True), \
                    patch.object(DATA, 'context', return_value=metadata), \
                    patch.object(DATA, 'source_bytes', side_effect=OSError('PRIVATE-SENTINEL') if fault == 'close' else None,
                                 return_value=helper()), \
                    patch.object(DATA.sys, 'stdout', io.StringIO()) as out, patch.object(DATA.sys, 'stderr', io.StringIO()) as err:
                if fault == 'observe':
                    with patch.object(DATA, 'observe', side_effect=RuntimeError('PRIVATE-SENTINEL')): code = DATA.main()
                elif fault == 'output-bound':
                    with patch.object(DATA, 'OUTPUT_LIMIT', 1): code = DATA.main()
                elif fault == 'write':
                    with patch.object(out, 'write', side_effect=OSError('PRIVATE-SENTINEL')): code = DATA.main()
                else: code = DATA.main()
                self.assertEqual(code, 1)
                self.assertEqual(out.getvalue(), '')
                self.assertNotIn('PRIVATE-SENTINEL', err.getvalue()); self.assertNotIn(DATA.VARIABLE, os.environ)

    def test_workflow_has_only_explicit_shape_secret_and_public_report(self):
        workflow = (ROOT / '.github/workflows/desktop-macos-notary-key-shape.yml').read_text()
        self.assertIn('    branches:\n      - verify/desktop-macos-notary-key-shape\n', workflow)
        self.assertIn("if: github.event_name == 'push' && github.ref == '" + DATA.REF + "'", workflow)
        self.assertIn('    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    environment: macos-developer-id\n', workflow)
        self.assertEqual(workflow.count('${{ secrets.'), 1)
        self.assertIn('          ' + DATA.VARIABLE + ': ${{ secrets.' + DATA.VARIABLE + ' }}\n', workflow)
        self.assertIn('          set +x\n          set +a\n          export -n ' + DATA.VARIABLE + '\n', workflow)
        self.assertIn('          ' + DATA.VARIABLE + '="$' + DATA.VARIABLE + '" /usr/bin/python3 -I -S -B ' + DATA.SCRIPT + ' > notary-key-shape-public.json\n', workflow)
        self.assertIn('          unset ' + DATA.VARIABLE + '\n', workflow)
        self.assertIn("if: steps.probe.outcome == 'success'", workflow)
        self.assertEqual(workflow.count('          path: '), 1)
        self.assertIn('          path: notary-key-shape-public.json\n          if-no-files-found: error\n          retention-days: 14\n', workflow)
        self.assertIn('permissions:\n  contents: read\n', workflow)
        self.assertIn('          persist-credentials: false\n', workflow)
        self.assertNotIn('workflow_dispatch:', workflow); self.assertNotIn('secrets: inherit', workflow)
        self.assertNotIn('notarytool ', workflow); self.assertNotIn('cargo ', workflow)
        source = ast.parse((ROOT / DATA.SCRIPT).read_bytes())
        imports = {alias.name for node in source.body if isinstance(node, ast.Import) for alias in node.names}
        self.assertNotIn('subprocess', imports)


if __name__ == '__main__':
    unittest.main()
