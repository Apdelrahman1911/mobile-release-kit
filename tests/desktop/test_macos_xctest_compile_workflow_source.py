"""SOURCE-only contracts for external XCTest compilation, never UI/product proof.

Read first-party workflow/runner bytes and AST only; do not execute inline code,
import product modules, invoke Xcode, or treat absent native evidence as success.
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
                          '--engineering-main-', '--normal-summary', 'test-without-building'):
            self.assertNotIn(forbidden, job)

    def test_one_unchanged_bounded_compile_owner(self):
        _, _, job = source()
        self.assertIn('    runs-on: macos-26\n', job)
        self.assertIn('    timeout-minutes: 25\n', job)
        limits = [int(n) for n in re.findall(r'^        timeout-minutes: ([0-9]+)$', job, re.M)]
        self.assertEqual(limits, [2, 3, 3, 1, 9, 2, 2])
        self.assertEqual(sum(limits) + 3, 25)
        self.assertEqual(job.count('desktop/tools/macos_normal_ui_runner.py --normal-build'), 1)
        self.assertNotIn('/usr/bin/xcodebuild ', job)
        for fragment in ('ulimit -f 33554432', '/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin',
                         '"TMPDIR=$MRK_MACOS_WORK/normal-ui/tmp/"',
                         'TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB=github-hosted-macos26-arm64',
                         '"TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE=$GITHUB_SHA"',
                         '"TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE=$GITHUB_SHA"',
                         'mrk-macos-installed.XXXXXXXX', '/bin/mkdir -m 700', 'umask 077',
                         'original_status=$?', '[[ "$original_status" == 0 ]] || exit "$original_status"'):
            self.assertIn(fragment, job)
        self.assertEqual(job.count('"$(/usr/bin/git rev-parse HEAD)" == "$GITHUB_SHA"'), 3)
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
            'build.failure-diagnostics.json', 'build.status'])
        self.assertIn('if-no-files-found: error', artifact)
        self.assertIn('retention-days: 14', artifact)
        for forbidden in ('stdout', 'stderr', 'DerivedData', '*.json', 'xcresult'):
            self.assertNotIn(forbidden, artifact)
        self.assertIn('Missing receipts are unavailable, never pass.', job)
        self.assertIn('External XCTest compile only / no product or UI execution', job)

    def test_cleanup_requires_actual_success_and_original_private_objects(self):
        _, _, job = source()
        cleanup = job.split("      - name: Remove only this successful compile's original private products\n", 1)[1]
        self.assertIn("if: success() && steps.build.outcome == 'success' && steps.evidence.outcome == 'success'", cleanup)
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
                         "assert type(commands) is list and len(commands) == 7", "children = ('DerivedData', 'tmp')",
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


if __name__ == '__main__':
    unittest.main()
