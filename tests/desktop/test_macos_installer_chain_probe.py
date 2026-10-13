"""Inert public comparison DATA; never invokes Security, signs or starts a child."""
import ast
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


class InstallerChainProbeData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / 'desktop/tools/macos_installer_chain_probe.py'
        spec = importlib.util.spec_from_file_location('installer_chain_probe_data', path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def binding(self):
        return dict(source='a' * 40, workflowSource='a' * 40, runId='123', runAttempt='1',
                    target='aarch64-apple-darwin')

    def rows(self, codes=(1, 0)):
        return [dict(policy=p, returncode=c, stdoutSha256='a' * 64, stderrSha256='b' * 64,
                     originalJoined=True, capturesClosed=True) for p, c in zip(('pkgSign', 'basic'), codes)]

    def test_context_and_exact_public_originals_do_not_admit_other_roles(self):
        m = self.module
        env = dict(GITHUB_SHA='a' * 40, GITHUB_ACTIONS='true', GITHUB_EVENT_NAME='push', GITHUB_REF=m.REF,
            GITHUB_REPOSITORY='Apdelrahman1911/mobile-release-kit', GITHUB_WORKSPACE=str(m.ROOT),
            GITHUB_WORKFLOW_REF=m.WORKFLOW, GITHUB_WORKFLOW_SHA='a' * 40, RUNNER_ENVIRONMENT='github-hosted',
            RUNNER_OS='macOS', RUNNER_ARCH='ARM64', GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1')
        args = (m.ROOT / m.SCRIPT, SimpleNamespace(sysname='Darwin', machine='arm64'), 501, 501, 20, 20)
        self.assertEqual(m.context(env, *args), self.binding())
        for key in env:
            with self.subTest(key=key), self.assertRaises(m.Refused):
                m.context({**env, key: ''}, *args)
        for changed in ((args[0], args[1], 0, 0, 0, 0),
                        (args[0], SimpleNamespace(sysname='Darwin', machine='x86_64'), 501, 501, 20, 20)):
            with self.assertRaises(m.Refused): m.context(env, *changed)
        for role, length, sha in m.CERTIFICATES:
            body = (ROOT / 'desktop/packaging/macos-installer-certificates' / (role + '.der')).read_bytes()
            self.assertEqual((len(body), hashlib.sha256(body).hexdigest()), (length, sha))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'public.der'; path.write_bytes(b'public-only'); path.chmod(0o600)
            entry = m.Original(path, b'public-only')
            entry.post()
            path.write_bytes(b'changed-data')
            with self.assertRaises(m.Refused): entry.post()
            entry.close(); self.assertIsNone(entry.fd); entry.close()
            with self.assertRaises(m.Refused): m.Original(path, b'public-only')
            alias = Path(tmp) / 'alias'; alias.symlink_to(path)
            with self.assertRaises(OSError): m.Original(alias)

    def test_exact_commands_match_production_basic_without_changing_private_ownership(self):
        m = self.module
        paths = tuple(Path('/inert') / (name + '.der') for name in ('leaf', 'issuer', 'root'))
        for policy in ('pkgSign', 'basic'):
            self.assertEqual(m.command(policy, paths), ['/usr/bin/security', 'verify-cert', '-p', policy,
                '-N', '-L', '-c', str(paths[0]), '-c', str(paths[1]), '-r', str(paths[2])])
        for policy, value in (('codesigning', paths), ('basic', paths[::-1]), ('basic', paths[:2])):
            with self.assertRaises(m.Refused): m.command(policy, value)
        tree = ast.parse((ROOT / 'desktop/tools/macos_android_helper_package.py').read_text())
        operation = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Operation')
        scope = next(n for n in operation.body if isinstance(n, ast.FunctionDef) and n.name == 'credential_scope')
        calls = [n for n in ast.walk(scope) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr == 'credential_call' and len(n.args) > 2 and isinstance(n.args[1], ast.Constant)
                 and n.args[1].value == 'installer-chain']
        self.assertEqual(len(calls), 1)
        args = calls[0].args[2].elts
        self.assertEqual([ast.literal_eval(v) for v in args[:7]],
                         ['/usr/bin/security', 'verify-cert', '-p', 'basic', '-N', '-L', '-c'])
        self.assertEqual([ast.literal_eval(args[n]) for n in (8, 10)], ['-c', '-r'])
        self.assertEqual([ast.literal_eval(args[n].slice) for n in (7, 9, 11)], [0, 1, 2])
        self.assertEqual([(v.arg, ast.literal_eval(v.value)) for v in calls[0].keywords], [('timeout', 30)])
        seen = []
        with mock.patch.object(m, 'run', side_effect=lambda policy, *_a: seen.append(policy) or self.rows()[len(seen)-1]):
            self.assertEqual(m.compare(paths, {}, m.time.monotonic() + 10, lambda: None), self.rows())
        self.assertEqual(seen, ['pkgSign', 'basic'])
        seen.clear()
        def failed(*_args): seen.append('entered'); raise m.Refused('inert')
        with mock.patch.object(m, 'run', side_effect=failed), self.assertRaises(m.Refused):
            m.compare(paths, {}, m.time.monotonic() + 10, lambda: None)
        self.assertEqual(seen, ['entered'])

    def test_original_capture_bounds_and_unknown_preserve_the_first_failure(self):
        m = self.module
        paths = tuple(Path('/inert') / (name + '.der') for name in ('leaf', 'issuer', 'root'))
        for fault in (None, 'overflow', 'signal', 'close', 'late-launch', 'launch'):
            with self.subTest(fault=fault):
                closed, killed = [], []
                streams = [SimpleNamespace(fileno=lambda i=i: 1000+i,
                    close=lambda i=i: closed.append(i)) for i in range(2)]
                if fault == 'close':
                    def bad_close(): closed.append(0); raise OSError('inert close')
                    streams[0].close = bad_close
                data = {1000: [b'x' * (m.LIMIT + 1) if fault == 'overflow' else b'PRIVATE-SENTINEL', b''], 1001: [b'', b'']}
                class Selector:
                    def __init__(self): self.rows = {}
                    def register(self, stream, _events, index): self.rows[index] = SimpleNamespace(fileobj=stream, data=index)
                    def get_map(self): return self.rows
                    def select(self, _timeout): return [(v, 1) for v in list(self.rows.values())]
                    def unregister(self, stream): self.rows.pop(stream.fileno()-1000)
                    def close(self): closed.append('selector')
                current = [0.0]
                process = SimpleNamespace(stdout=streams[0], stderr=streams[1], poll=lambda: None if fault == 'late-launch' else 1,
                    kill=lambda: killed.append(True), wait=lambda timeout: -9 if fault == 'signal' else 1)
                def popen(*args, **kwargs):
                    self.assertEqual(args[0], m.command('pkgSign', paths))
                    self.assertEqual(kwargs['stdin'], m.subprocess.DEVNULL)
                    self.assertEqual(kwargs['env'], {'HOME': '/inert'})
                    if fault == 'launch': raise OSError('inert spawn')
                    if fault == 'late-launch': current[0] = 31.0
                    return process
                with (mock.patch.object(m.subprocess, 'Popen', side_effect=popen),
                      mock.patch.object(m.selectors, 'DefaultSelector', Selector),
                      mock.patch.object(m.os, 'set_blocking'),
                      mock.patch.object(m.os, 'read', side_effect=lambda fd, _size: data[fd].pop(0)),
                      mock.patch.object(m.time, 'monotonic', side_effect=lambda: current[0])):
                    if fault is None:
                        row = m.run('pkgSign', paths, {'HOME': '/inert'}, 90.0)
                        self.assertEqual(row['returncode'], 1)
                        self.assertEqual(row['stdoutSha256'], hashlib.sha256(b'PRIVATE-SENTINEL').hexdigest())
                        self.assertNotIn('PRIVATE-SENTINEL', json.dumps(row))
                    else:
                        with self.assertRaises(m.Refused): m.run('pkgSign', paths, {'HOME': '/inert'}, 90.0)
                if fault != 'launch': self.assertEqual(closed.count(0), 1); self.assertEqual(closed.count(1), 1)
                if fault == 'late-launch': self.assertEqual(killed, [True])
        for codes in ((1, 0), (0, 0), (1, 1), (255, 2)):
            value = json.loads(m.report(self.binding(), self.rows(codes)))
            self.assertEqual(value['comparisonMatched'], codes == (1, 0))
            for name in ('packageSigned', 'systemTrustEstablished', 'revocationChecked', 'notarizationAccepted', 'productReady'):
                self.assertIs(value[name], False)
        for key, bad in (('returncode', True), ('returncode', -1), ('returncode', 256),
                         ('capturesClosed', False), ('originalJoined', False), ('stdoutSha256', '/private/path')):
            rows = self.rows(); rows[0][key] = bad
            with self.assertRaises(m.Refused): m.report(self.binding(), rows)

    def test_exact_scratch_retirement_and_public_only_workflow(self):
        m = self.module
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); checkout = root / 'checkout'; checkout.mkdir()
                (checkout / '.git').mkdir(); (checkout / '.git/HEAD').write_text('a' * 40 + '\n')
                certroot = checkout / 'desktop/packaging/macos-installer-certificates'; certroot.mkdir(parents=True)
                certificates = []
                for role in ('leaf', 'issuer', 'root'):
                    body = ('INERT-' + role).encode(); path = certroot / (role + '.der'); path.write_bytes(body)
                    path.chmod(0o644); certificates.append((role, len(body), hashlib.sha256(body).hexdigest()))
                scratch = root / 'owned'; scratch.mkdir(mode=0o700)
                def compared(paths, environment, _endpoint, post):
                    self.assertEqual(set(environment), {'PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'TZ'})
                    self.assertEqual([p.name for p in paths], ['leaf.der', 'issuer.der', 'root.der'])
                    post()
                    if fail: (scratch / 'tmp/unexpected').write_bytes(b'INERT'); raise m.Refused('inert')
                    return self.rows()
                output = SimpleNamespace(buffer=io.BytesIO())
                # Nonroot namespaces map the host's system owner to the test
                # UID. Project only these four system-role UID values as DATA;
                # source/copy/scratch stats and every other stat field stay real.
                system_paths = {Path('/'), Path('/usr'), Path('/usr/bin'), Path('/usr/bin/true')}
                observed_systems, observed_real = set(), set()
                original_lstat = m.Path.lstat
                def system_lstat(path, *args, **kwargs):
                    value = original_lstat(path, *args, **kwargs)
                    if path not in system_paths:
                        observed_real.add(path)
                        return value
                    observed_systems.add(path)
                    return SimpleNamespace(**{name: 0 if name == 'st_uid' else getattr(value, name)
                        for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                                     'st_size', 'st_mtime_ns', 'st_ctime_ns')})
                with (mock.patch.object(m.Path, 'lstat', autospec=True, side_effect=system_lstat),
                      mock.patch.object(m, 'ROOT', checkout), mock.patch.object(m, 'context', return_value=self.binding()),
                      mock.patch.object(m.Path, 'cwd', return_value=checkout), mock.patch.object(m, 'SECURITY', '/usr/bin/true'),
                      mock.patch.object(m, 'CERTIFICATES', tuple(certificates)),
                      mock.patch.object(m.tempfile, 'mkdtemp', return_value=str(scratch)),
                      mock.patch.object(m, 'compare', side_effect=compared), mock.patch.object(m.sys, 'stdout', output)):
                    if fail:
                        with self.assertRaises(m.Refused): m.main()
                        self.assertTrue((scratch / 'tmp/unexpected').exists()); self.assertEqual(output.buffer.getvalue(), b'')
                    else:
                        m.main(); self.assertFalse(scratch.exists())
                        self.assertTrue(json.loads(output.buffer.getvalue())['ownedScratchRetired'])
                self.assertEqual(observed_systems, system_paths)
                expected_real = {checkout / '.git/HEAD', scratch, scratch / 'home', scratch / 'tmp'}
                expected_real.update(certroot / (role + '.der') for role in ('leaf', 'issuer', 'root'))
                expected_real.update(scratch / (role + '.der') for role in ('leaf', 'issuer', 'root'))
                self.assertTrue(expected_real <= observed_real)
                self.assertTrue(all((certroot / (r + '.der')).exists() for r in ('leaf', 'issuer', 'root')))
        workflow = (ROOT / '.github/workflows/desktop-macos-installer-chain.yml').read_text()
        for value in ('verify/desktop-macos-installer-chain', 'ref: ${{ github.sha }}', 'persist-credentials: false',
                      'runs-on: macos-26', 'timeout-minutes: 5', 'path: installer-chain-public.json', 'retention-days: 14'):
            self.assertIn(value, workflow)
        for value in ('secrets.', 'environment:', 'workflow_dispatch:', 'cargo ', 'productsign', 'notarytool'):
            self.assertNotIn(value, workflow)
        self.assertEqual(workflow.count('uses: actions/upload-artifact@'), 1)
