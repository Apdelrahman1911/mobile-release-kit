"""SOURCE and inert DATA contracts for fixed external XCTest work, never product proof.

Read first-party workflow/runner SOURCE; execute only AST-selected pure predicates
on tiny inert DATA, never inline cleanup, product modules or native tools.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import re
import textwrap
import unittest

ROOT = Path(__file__).absolute().parents[2]
WORKFLOW = '.github/workflows/desktop-macos-engineering-ui.yml'
OLD_BRANCH = 'verify/desktop-macos-engineering-ui'
COMPILE_BRANCH = 'verify/desktop-macos-xctest-compile'
ORIGINAL_WORKFLOW_SHA256 = 'c8b34da3a312000b53d21e019c96145d95c889d70fb8130be3e0b8b363f806e0'


def source():
    workflow = (ROOT / WORKFLOW).read_text()
    before, compile_job = workflow.split('\n  xctest-compile:\n')
    return workflow, before, compile_job


def inline_python(job, delimiter):
    return textwrap.dedent(job.split("<<'" + delimiter + "'\n", 1)[1].split('\n          ' + delimiter, 1)[0])


class MacosXCTestCompileWorkflowSourceTests(unittest.TestCase):
    def test_fixed_dispatch_preserves_original_engineering_body(self):
        workflow, before, job = source()
        self.assertEqual(workflow.count('  engineering-main:\n'), 1)
        self.assertEqual(workflow.count('  xctest-compile:\n'), 1)
        self.assertIn("    if: github.ref == 'refs/heads/" + OLD_BRANCH + "'\n", before)
        self.assertTrue(job.startswith("    if: github.ref == 'refs/heads/" + COMPILE_BRANCH + "'\n"))
        original = before.replace('branches: [' + OLD_BRANCH + ', ' + COMPILE_BRANCH + ']',
                                  'branches: [' + OLD_BRANCH + ']', 1)
        original = original.replace("    if: github.ref == 'refs/heads/" + OLD_BRANCH + "'\n", '', 1)
        self.assertEqual(hashlib.sha256(original.encode()).hexdigest(), ORIGINAL_WORKFLOW_SHA256)
        for fragment in ('"$RUNNER_ENVIRONMENT" == github-hosted', '"$RUNNER_OS" == macOS',
                         '"$RUNNER_ARCH" == ARM64', '"$(/usr/bin/uname -m)" == arm64',
                         '"$(/usr/bin/sw_vers -productVersion)" == 26.*',
                         '"$GITHUB_REPOSITORY" == Apdelrahman1911/mobile-release-kit',
                         '"$GITHUB_EVENT_NAME" == push', '"$GITHUB_REF" == refs/heads/' + COMPILE_BRANCH,
                         '"$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA"',
                         '"$GITHUB_WORKFLOW_REF" == "$GITHUB_REPOSITORY/' + WORKFLOW + '@$GITHUB_REF"',
                         'ref: ${{ github.sha }}', 'persist-credentials: false', "python-version: '3.14.7'"):
            self.assertIn(fragment, job)
        self.assertEqual(re.findall(r'uses: (\S+)', job), [
            'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
            'actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97',
            'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'])
        for forbidden in ('workflow_dispatch:', 'pull_request:', 'schedule:', 'secrets.', 'github.token',
                          'setup-node@', 'download-artifact@', 'ci_foundation.py', 'stage_macos_installed.py',
                          'supplier', 'cargo ', 'npm ', 'codesign ', 'security ', 'osascript ',
                          '--engineering-main-', '--normal-summary'):
            self.assertNotIn(forbidden, job)

    def test_one_unchanged_bounded_compile_owner(self):
        _, _, job = source()
        self.assertIn('    runs-on: macos-26\n', job)
        self.assertIn('    timeout-minutes: 32\n', job)
        limits = [int(n) for n in re.findall(r'^        timeout-minutes: ([0-9]+)$', job, re.M)]
        self.assertEqual(limits, [2, 3, 3, 1, 9, 7, 2, 2])
        self.assertEqual(sum(limits) + 3, 32)
        self.assertEqual(job.count('desktop/tools/macos_normal_ui_runner.py --normal-build'), 1)
        self.assertEqual(job.count('desktop/tools/macos_normal_ui_runner.py --normal-output-data-test'), 1)
        self.assertIn('ulimit -f 1048576', job)
        self.assertNotIn('/usr/bin/xcodebuild ', job)
        for fragment in ('ulimit -f 33554432', '/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin',
                         '"TMPDIR=$MRK_MACOS_WORK/normal-ui/tmp/"',
                         'TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=github-hosted-macos26-arm64',
                         '"TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=$GITHUB_SHA"',
                         '"TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE=$GITHUB_SHA"',
                         'mrk-macos-installed.XXXXXXXX', '/bin/mkdir -m 700', 'umask 077',
                         'original_status=$?', '[[ "$original_status" == 0 ]] || exit "$original_status"'):
            self.assertIn(fragment, job)
        self.assertEqual(job.count('"$(/usr/bin/git rev-parse HEAD)" == "$GITHUB_SHA"'), 5)
        runner = (ROOT / 'desktop/tools/macos_normal_ui_runner.py').read_text()
        tree = ast.parse(runner)
        functions = {node.name: ast.get_source_segment(runner, node) for node in tree.body if isinstance(node, ast.FunctionDef)}
        self.assertIn('timeout=240, phaseSeconds=450', functions['normal_request'])
        self.assertIn('"-jobs", "2"', functions['normal_build_arguments'])
        self.assertIn('"build-for-testing"', functions['normal_build_arguments'])
        self.assertIn('normal_source_state(phase, source) == before', functions['execute_normal_phase'])
        self.assertIn('"build.command-admission.json"', functions['execute_normal_phase'])
        self.assertIn('loader_digest == LOADER_SHA', functions['load_normal_owner'])

    def test_artifacts_are_bounded_allowlist_not_raw_output_or_qualification(self):
        _, _, job = source()
        artifact = job.split('        id: evidence\n', 1)[1].split('      - name:', 1)[0]
        self.assertIn("if: always() && steps.work.outcome == 'success'", artifact)
        paths = re.findall(r'^            \$\{\{ steps.work.outputs.root \}\}/normal-ui/(.+)$', artifact, re.M)
        self.assertEqual(paths, ['python-version.txt', 'xcode-version.txt', 'sdk-path.txt', 'sdk-version.txt',
            'sdk-build.txt', 'build.command-admission.json', 'toolchain.failure-diagnostics.json',
            'build.failure-diagnostics.json', 'build.status', 'output-data.command-admission.json',
            'output-data-test.failure-diagnostics.json', 'output-data.status'])
        self.assertIn('if-no-files-found: error', artifact)
        self.assertIn('retention-days: 14', artifact)
        for forbidden in ('stdout', 'stderr', 'DerivedData', '*.json', 'xcresult'):
            self.assertNotIn(forbidden, artifact)
        self.assertIn('Missing receipts are unavailable, never pass.', job)
        self.assertIn('External XCTest compile and fixed filesystem DATA / no product execution', job)

    def test_cleanup_requires_actual_success_and_original_private_objects(self):
        _, _, job = source()
        cleanup = job.split("      - name: Remove only the successful compile and DATA original private products\n", 1)[1]
        self.assertIn("if: success() && steps.build.outcome == 'success' && steps.data.outcome == 'success' && steps.evidence.outcome == 'success'", cleanup)
        self.assertIn('MRK_WORK_IDENTITY: ${{ steps.work.outputs.work_identity }}', cleanup)
        self.assertIn('MRK_NORMAL_IDENTITY: ${{ steps.work.outputs.normal_identity }}', cleanup)
        code = inline_python(job, 'PY_CLEAN')
        tree = ast.parse(code)  # Never executes cleanup or imports its modules.
        ast.parse(inline_python(job, 'PY_WORK'))
        for fragment in ('assert shutil.rmtree.avoids_symlink_attacks', 'os.O_DIRECTORY | os.O_NOFOLLOW',
                         "directory('normal-ui', work_fd, os.environ['MRK_NORMAL_IDENTITY'])",
                         "assert read('build.status', 4) == b'0\\n'", "read('build.command-admission.json', 32768)",
                         "originalCommandRole='normal-ui-build', originalReturncode=0",
                         "target='aarch64-apple-darwin', sourceCommit=os.environ['GITHUB_SHA'], sourcePrePostMatched=True",
                         'originalCommandReturned=True', "receiptPolicy='exclusive0600-readback-consuming-close'",
                         "assert clock['postCloseDeadlineRequired'] is True", '450 * 10**9',
                         "assert type(commands) is list and len(commands) == 7", "children = ('DerivedData', 'tmp', 'output-data-test.xcresult')",
                         "assert read('output-data.status', 4) == b'0\\n'",
                         "output_data_success_receipt(data, os.environ['GITHUB_SHA'], Path(work) / 'normal-ui', build_raw)",
                         's.st_uid == os.getuid() and s.st_gid == os.getgid()',
                         'assert identity(os.stat(name, dir_fd=normal, follow_symlinks=False)) == admitted[name]',
                         'shutil.rmtree(name, dir_fd=normal)'):
            self.assertIn(fragment, code)
        deletions = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Attribute) and node.func.attr == 'rmtree']
        self.assertEqual(len(deletions), 1)
        self.assertEqual([keyword.arg for keyword in deletions[0].keywords], ['dir_fd'])
        self.assertLess(code.index('for name in children:\n        s = os.stat'), code.index('shutil.rmtree(name, dir_fd=normal)'))
        for forbidden in ('rm -', 'kill', 'pkill', 'rmdir(', 'unlink(', 'ignore_errors', 'onerror', 'onexc',
                          '/Library/', 'ci_foundation', 'subprocess'):
            self.assertNotIn(forbidden, cleanup)


    @staticmethod
    def data_functions():
        # Only closed pure SOURCE functions/constant DATA; no owner, CLI main, filesystem or native execution.
        raw = (ROOT / 'desktop/tools/macos_normal_ui_runner.py').read_text()
        tree = ast.parse(raw)
        names = {'Refused', 'need', 'sha', 'encoded', 'pairs', 'document', 'normal_target_data',
                 'normal_build_arguments', 'xcode_test_arguments', 'normal_request', 'normal_cli_arguments',
                 'output_data_clock', 'output_data_records', 'output_data_source_argv',
                 'output_data_build_receipt', 'output_data_success_receipt', 'output_data_result',
                 'full9', 'original_body', 'output_data_read_build', 'PhaseClock', 'NormalPhase', 'original_command',
                 'execute_output_data_phase', 'execute_normal_phase', 'NativeQueryFailure', 'main'}
        constants = {'ARM_TARGET', 'INTEL_TARGET', 'PROJECT', 'TARGET', 'CLASS', 'PACKAGED_METHOD', 'RUNNER',
                     'ENGINEERING_MODES', 'NORMAL_SELECTIONS', 'TOOLCHAIN_QUERIES', 'OUTPUT_DATA_METHOD', 'OUTPUT_DATA_RESULT', 'OUTPUT_DATA_SCOPE'}
        selected = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
                    or isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in constants for target in node.targets)]
        import json, stat, subprocess
        scope = {'hashlib': hashlib, 'json': json, 're': re, 'stat': stat, 'Path': Path, 'subprocess': subprocess}
        exec(compile(ast.Module(body=selected, type_ignores=[]), '<fixed-output-data-source>', 'exec'), scope)
        return scope

    def test_fixed_data_selection_and_real_result_predicates(self):
        d = self.data_functions()
        normal = Path('/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui')
        request = d['normal_request'](['--normal-output-data-test'], str(normal / 'tmp') + '/')
        self.assertEqual((request['phase'], request['timeout'], request['phaseSeconds'], request['allowance']), ('test', 120, 345, 60))
        self.assertIs(request['outputData'], True)
        self.assertEqual(request['methods'], (d['OUTPUT_DATA_METHOD'],))
        self.assertNotIn(d['OUTPUT_DATA_RESULT'], d['NORMAL_SELECTIONS'])
        for args in (['--target', d['INTEL_TARGET'], '--normal-output-data-test'], ['--normal-output-data-test', 'extra'], ['--normal-summary', d['OUTPUT_DATA_RESULT']]):
            with self.subTest(args=args), self.assertRaises(d['Refused']):
                d['normal_request'](args, str(normal / 'tmp') + '/')
        argv = d['xcode_test_arguments'](normal / 'fixed.xctestrun', normal / d['OUTPUT_DATA_RESULT'], (d['OUTPUT_DATA_METHOD'],), 60, output_data=True)
        self.assertEqual(argv[0:2], ['/usr/bin/xcodebuild', 'test-without-building'])
        self.assertEqual([arg for arg in argv if arg.startswith('-only-testing:')], ['-only-testing:' + d['OUTPUT_DATA_METHOD']])
        for methods, kwargs in (((d['OUTPUT_DATA_METHOD'],), {}), ((d['OUTPUT_DATA_METHOD'] + 'Other',), {'output_data': True}),
                               ((d['OUTPUT_DATA_METHOD'],), {'output_data': True, 'target': d['INTEL_TARGET']})):
            with self.subTest(methods=methods, kwargs=kwargs), self.assertRaises(d['Refused']):
                d['xcode_test_arguments'](normal / 'fixed.xctestrun', normal / d['OUTPUT_DATA_RESULT'], methods, 60, **kwargs)
        selected = '-[MRKNormalAppUITests.NormalAppUITests testPositiveAndroidOutputCustodyData]'
        stdout = ("Test Case '" + selected + "' started.\nTest Case '" + selected + "' passed (0.125 seconds).\n").encode()
        summary = {'totalTestCount': 1, 'passedTests': 1, 'failedTests': 0, 'skippedTests': 0, 'expectedFailures': 0}
        case = {'name': 'testPositiveAndroidOutputCustodyData()', 'nodeType': 'Test Case', 'result': 'Passed',
                'nodeIdentifier': 'NormalAppUITests/testPositiveAndroidOutputCustodyData()'}
        tree = {'testNodes': [{'name': d['TARGET'], 'nodeType': 'Test Suite', 'children': [case]}]}
        result = d['output_data_result'](stdout, d['encoded'](summary), d['encoded'](tree))
        self.assertEqual(result['testCounts'], summary)
        self.assertIs(result['productReady'], False)
        self.assertEqual(result['testIdentifier'], d['OUTPUT_DATA_METHOD'])
        for body in (b'', stdout + stdout, stdout.replace(b'passed', b'failed'), stdout + b'MRK_MACOS_UI_ORIGINAL=1\n'):
            with self.subTest(body=body[:40]), self.assertRaises(d['Refused']):
                d['output_data_result'](body, d['encoded'](summary), d['encoded'](tree))
        for key, value in (('totalTestCount', 0), ('passedTests', 0), ('skippedTests', 1), ('failedTests', 1), ('expectedFailures', 1), ('passedTests', True)):
            with self.subTest(key=key, value=value), self.assertRaises(d['Refused']):
                d['output_data_result'](stdout, d['encoded']({**summary, key: value}), d['encoded'](tree))
        for children in ([], [case, case], [{**case, 'result': 'Skipped'}], [{**case, 'nodeIdentifier': 'Other/test()'}]):
            with self.subTest(children=children), self.assertRaises(d['Refused']):
                d['output_data_result'](stdout, d['encoded'](summary), d['encoded']({'testNodes': [{'name': d['TARGET'], 'nodeType': 'Test Suite', 'children': children}]}))
        with self.assertRaises(d['Refused']):
            d['output_data_result'](stdout, b'{"passedTests":1,"passedTests":1}', d['encoded'](tree))

    def test_fixed_data_receipt_and_cleanup_use_identical_closed_predicates(self):
        import copy
        d = self.data_functions()
        normal = Path('/Users/runner/work/_temp/mrk-macos-installed.ABCDef12/normal-ui')
        source_commit, roster = 'a' * 40, 'b' * 64
        empty = d['sha'](b'')
        def clock(seconds):
            return dict(startNs='1', deadlineNs=str(1 + seconds * 10**9), beforePublicationNs='2', postCloseDeadlineRequired=True)
        def row(role, cap, limit, argv, output=empty):
            return dict(role=role, returncode=0, timeoutSeconds=cap, roleCapSeconds=cap, outputLimitBytes=limit,
                argvSha256=d['sha'](d['encoded'](argv)), stdoutBytes=0, stdoutSha256=output, stderrBytes=0, stderrSha256=empty)
        source_row = row('normal-ui-source-roster', 15, 1048576, d['output_data_source_argv'](source_commit))
        build = dict(schemaVersion=1, scope='normal-ui-original-command-admission-only', phase='build', resultBundle=None,
            originalCommandRole='normal-ui-build', originalReturncode=0, target=d['ARM_TARGET'], sourceCommit=source_commit,
            sourceRosterSha256=roster, sourcePrePostMatched=True, originalCommandReturned=True,
            fileLimitBytes=[32 * 1024**3] * 2, receiptPolicy='exclusive0600-readback-consuming-close', phaseClock=clock(450),
            commands=[source_row, *[row('normal-toolchain-' + key, 15, 4096, list(argv)) for key, _, argv in d['TOOLCHAIN_QUERIES']],
                      row('normal-ui-build', 240, 1048576, d['normal_build_arguments'](normal / 'DerivedData')), source_row])
        d['output_data_build_receipt'](build, source_commit, normal, roster)
        raw = d['encoded'](build)
        runner = dict(schemaVersion=1, scope='actual-generated-xctrunner-admission-only',
            runnerPath=str(normal / 'DerivedData/Build/Products' / d['RUNNER']),
            xctestrunPath=str(normal / 'DerivedData/Build/Products/MRKNormalAppUI_macosx26.0-arm64.xctestrun'),
            runnerExecutable=['file', ['1', '2', str(0o100755), '501', '20', '1', '10', '3', '4'], empty],
            testExecutable=['file', ['1', '3', str(0o100755), '501', '20', '1', '10', '3', '4'], empty],
            xctestrun=['file', ['1', '4', str(0o100644), '501', '20', '1', '10', '3', '4'], empty],
            productEntryCount=5, productRosterSha256=empty, entitlementsSha256=empty, appSandboxEntitlement='absent',
            strictCodesignOriginalZero=True, reSignedOrRepaired=False, originalProductsPrePostMatched=True, originalClosesCompleted=True)
        observation = dict(testIdentifier=d['OUTPUT_DATA_METHOD'], testCounts={'totalTestCount': 1, 'passedTests': 1, 'failedTests': 0, 'skippedTests': 0, 'expectedFailures': 0},
            nativeSummarySha256=empty, nativeTestTreeSha256=empty, oneOriginalAttemptObserved=True, productReady=False)
        query = ['/usr/bin/xcrun', 'xcresulttool', 'get', 'test-results']
        tail = ['--path', str(normal / d['OUTPUT_DATA_RESULT']), '--compact']
        commands = [source_row, row('verify-generated-runner', 30, 1048576, ['/usr/bin/codesign', '--verify', '--strict', runner['runnerPath']]),
            row('generated-runner-entitlements', 30, 1048576, ['/usr/bin/codesign', '-d', '--entitlements', ':-', runner['runnerPath']]),
            row('one-admitted-ui-test', 120, 1048576, d['xcode_test_arguments'](runner['xctestrunPath'], normal / d['OUTPUT_DATA_RESULT'], (d['OUTPUT_DATA_METHOD'],), 60, output_data=True)),
            row('normal-ui-summary', 30, 262144, query + ['summary'] + tail), row('normal-ui-test-tree', 30, 262144, query + ['tests'] + tail), source_row]
        value = dict(schemaVersion=1, scope=d['OUTPUT_DATA_SCOPE'], phase='output-data', resultBundle=d['OUTPUT_DATA_RESULT'],
            originalCommandRole='one-admitted-ui-test', originalReturncode=0, target=d['ARM_TARGET'], sourceCommit=source_commit,
            sourceRosterSha256=roster, sourcePrePostMatched=True, originalCommandReturned=True, buildReceiptSha256=d['sha'](raw),
            fileLimitBytes=[1024**3] * 2, receiptPolicy='exclusive0600-readback-consuming-close', runnerAdmission=runner,
            observation=observation, commands=commands, phaseClock=clock(345))
        d['output_data_success_receipt'](value, source_commit, normal, raw)
        for key, replacement in (('sourceCommit', 'c' * 40), ('originalReturncode', True), ('buildReceiptSha256', empty),
                                 ('phaseClock', clock(346)), ('sourcePrePostMatched', False), ('fileLimitBytes', [32 * 1024**3] * 2)):
            with self.subTest(key=key), self.assertRaises(d['Refused']):
                d['output_data_success_receipt']({**value, key: replacement}, source_commit, normal, raw)
        for path, replacement in ((('commands', 3, 'roleCapSeconds'), 121), (('commands', 3, 'argvSha256'), empty),
                                  (('commands', 5, 'returncode'), 1), (('runnerAdmission', 'originalClosesCompleted'), False),
                                  (('runnerAdmission', 'xctestrunPath'), '/private/other.xctestrun'),
                                  (('observation', 'testCounts', 'skippedTests'), 1)):
            changed = copy.deepcopy(value)
            cursor = changed
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(d['Refused']):
                d['output_data_success_receipt'](changed, source_commit, normal, raw)
        for key, replacement in (('sourceCommit', 'c' * 40), ('phaseClock', clock(449)), ('originalReturncode', 1)):
            with self.subTest(build=key), self.assertRaises(d['Refused']):
                d['output_data_build_receipt']({**build, key: replacement}, source_commit, normal, roster)
        # Cleanup carries exact inert validator SOURCE, not a divergent second admission policy.
        _, _, job = source()
        cleanup = ast.parse(inline_python(job, 'PY_CLEAN'))
        runner_tree = ast.parse((ROOT / 'desktop/tools/macos_normal_ui_runner.py').read_text())
        original = {node.name: node for node in runner_tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
        copied = {node.name: node for node in cleanup.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
        for name in ('output_data_clock', 'output_data_records', 'output_data_source_argv', 'output_data_build_receipt', 'output_data_success_receipt'):
            self.assertEqual(ast.dump(copied[name], include_attributes=False), ast.dump(original[name], include_attributes=False))

        # New receipt read is nonblocking BEFORE type admission and consumes both originals once.
        from types import SimpleNamespace
        import os, stat, subprocess, io
        def file_facts(mode, size, inode):
            return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=501, st_gid=20,
                st_nlink=1, st_size=size, st_mtime_ns=3, st_ctime_ns=4)
        for nonregular, close_error in ((False, False), (True, False), (True, True), (False, True)):
            q = self.data_functions()
            opened, closed = [], []
            parent_facts = file_facts(stat.S_IFDIR | 0o700, 0, 10)
            receipt_facts = file_facts((stat.S_IFIFO if nonregular else stat.S_IFREG) | 0o600, len(raw), 11)
            def opened_receipt(name, flags, *, dir_fd):
                self.assertEqual((name, dir_fd), ('build.command-admission.json', 10))
                self.assertEqual(flags & (os.O_NONBLOCK | os.O_NOFOLLOW), os.O_NONBLOCK | os.O_NOFOLLOW)
                opened.append(11)
                return 11
            def closed_receipt(fd):
                closed.append(fd)
                if close_error and fd == 11:
                    raise OSError('inert consuming close failure')
            q.update(open_directory=lambda _: 10, os=SimpleNamespace(O_RDONLY=os.O_RDONLY, O_NONBLOCK=os.O_NONBLOCK,
                O_NOFOLLOW=os.O_NOFOLLOW, O_CLOEXEC=os.O_CLOEXEC, open=opened_receipt, close=closed_receipt,
                getuid=lambda: 501, getgid=lambda: 20, fstat=lambda fd: parent_facts if fd == 10 else receipt_facts,
                stat=lambda path, **_: parent_facts if path == normal else receipt_facts,
                pread=lambda fd, size, offset: raw[offset:offset + size]))
            phase = SimpleNamespace(clock=SimpleNamespace(check=lambda: None))
            with self.subTest(nonregular=nonregular, close_error=close_error):
                if nonregular:
                    with self.assertRaisesRegex(q['Refused'], '^ordinary-file-bound$'):
                        q['output_data_read_build'](phase, normal, source_commit, roster)
                elif close_error:
                    with self.assertRaises(OSError):
                        q['output_data_read_build'](phase, normal, source_commit, roster)
                else:
                    self.assertEqual(q['output_data_read_build'](phase, normal, source_commit, roster), d['sha'](raw))
                self.assertEqual(opened, [11])
                self.assertEqual(closed, [11, 10])

        # Actual NormalPhase/main/execute flow with inert syscall/command adapters only.
        # No product module, real key, XCTest process, or filesystem is entered.
        for fault, wanted in (('post-clock', 65), ('formatter', 65), ('stderr', 65), ('query-close', 75), ('zero-close', 1)):
            q = self.data_functions()
            now, closes, writes = [1], [], []
            result_facts = file_facts(stat.S_IFDIR | 0o700, 0, 42)
            class Owner:
                def run_owned(self, argv, **kwargs):
                    if argv == ['inert-test']:
                        code = 0 if fault in ('query-close', 'zero-close') else 65
                        if fault == 'post-clock':
                            now[0] = 346 * 10**9
                    else:
                        code = 75 if fault == 'query-close' else 0
                    return subprocess.CompletedProcess(argv, code, b'', b'')
            def close_result(fd):
                closes.append(fd)
                raise OSError('inert post-query consuming close')
            def publish_failure(*args, **kwargs):
                raise KeyboardInterrupt()
            class Stream:
                def __init__(self):
                    self.buffer = io.BytesIO()
                def write(self, text):
                    if fault == 'stderr':
                        raise SystemExit(99)
                    return len(text)
            def admission_failure(*args):
                if fault == 'formatter':
                    raise SystemExit(99)
                return {'status': 'inert-diagnostic'}
            q.update(time=SimpleNamespace(monotonic_ns=lambda: now[0]),
                sys=SimpleNamespace(argv=['runner', '--normal-output-data-test'], stdout=Stream(), stderr=Stream()),
                os=SimpleNamespace(environ={'TMPDIR': str(normal / 'tmp') + '/'}, getuid=lambda: 501, getgid=lambda: 20,
                    fstat=lambda _: result_facts, stat=lambda *args, **kwargs: result_facts, close=close_result),
                normal_context=lambda request: (Path('/inert-source'), source_commit, {}, (1024**3, 1024**3)),
                load_normal_owner=lambda root: Owner(), normal_source_state=lambda phase, source: {'inert-source': []},
                output_data_read_build=lambda *args: 'b' * 64, open_directory=lambda _: 42,
                run_admitted_test=lambda call, *args, **kwargs: (call('one-admitted-ui-test', ['inert-test'], 120), {}),
                publish_failure_diagnostics=publish_failure, normal_admission_failure=admission_failure,
                classify_normal_admission_failure=lambda _: {'status': 'inert-diagnostic'},
                exclusive_output=lambda path, body, limit: writes.append(path.name))
            with self.subTest(fault=fault):
                self.assertEqual(q['main'](), wanted)
                self.assertEqual(closes, [42] if fault in ('query-close', 'zero-close') else [])
                self.assertNotIn('output-data.command-admission.json', writes)
        # The first exact CompletedProcess survives later admitted failures; default phases do not latch.
        q = self.data_functions()
        clock = SimpleNamespace(allowance=lambda cap: cap, check=lambda: None, failed=False)
        originals = [subprocess.CompletedProcess(['one'], 65, b'', b''), subprocess.CompletedProcess(['two'], 75, b'', b'')]
        owner = SimpleNamespace(run_owned=lambda argv, **kwargs: originals[0] if argv == ['one'] else originals[1])
        phase = q['NormalPhase'](owner, {}, Path('/inert'), clock, retain_nonzero=True)
        phase.call('one-admitted-ui-test', ['one'], 120)
        phase.call('normal-ui-summary', ['two'], 30)
        self.assertIs(phase.first_nonzero, originals[0])
        ordinary = q['NormalPhase'](owner, {}, Path('/inert'), clock)
        ordinary.call('one-admitted-ui-test', ['one'], 120)
        self.assertIsNone(ordinary.first_nonzero)


if __name__ == '__main__':
    unittest.main()
