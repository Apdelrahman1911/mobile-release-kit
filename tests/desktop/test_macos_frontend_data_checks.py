"""Pure DATA/source contracts. No Node, native command or actual owner runs."""
import importlib.util
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).absolute().parents[2]
PATH = ROOT / "desktop/tools/macos_frontend_data_checks.py"
SPEC = importlib.util.spec_from_file_location("_mrk_frontend_data_checks", PATH)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

SUMMARY = b"TAP version 13\n1..151\n# tests 151\n# suites 0\n# pass 151\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 10.5\n"


class FrontendDataChecksTests(unittest.TestCase):
    def test_one_complete_summary_and_real_return_contract_are_both_required(self):
        self.assertTrue(M.counts_pass(M.tap_counts(SUMMARY)))
        result = subprocess.CompletedProcess(["fixed-node"], 0, SUMMARY, b"experimental warning")
        self.assertTrue(M.returned_result(result))
        self.assertTrue(M.returned_result(subprocess.CompletedProcess([], 1, SUMMARY, b"")))
        # A return contract establishes only return, not a successful test run.
        for value in (SimpleNamespace(returncode=0, stdout=SUMMARY, stderr=b""),
                      subprocess.CompletedProcess([], False, SUMMARY, b""),
                      subprocess.CompletedProcess([], 0, SUMMARY.decode(), b""),
                      subprocess.CompletedProcess([], 0, SUMMARY, ""),
                      subprocess.CompletedProcess([], 0, b"x" * M.OUTPUT_LIMIT, b"x")):
            with self.subTest(value_type=type(value).__name__):
                self.assertFalse(M.returned_result(value))

    def test_duplicate_missing_malformed_and_oversized_summaries_refuse(self):
        for raw in (b"", SUMMARY.decode(), SUMMARY + b"# pass 151\n",
                    SUMMARY.replace(b"# cancelled 0\n", b""),
                    SUMMARY.replace(b"# tests 151", b"# tests -1"),
                    SUMMARY.replace(b"# tests 151", b"# tests 123456789"),
                    SUMMARY + b"\xff", b"x" * (M.OUTPUT_LIMIT + 1)):
            with self.subTest(length=len(raw)):
                with self.assertRaises((ValueError, UnicodeError)):
                    M.tap_counts(raw)

    def test_failure_skip_cancellation_todo_short_or_partial_success_never_pass(self):
        for name in (b"fail", b"cancelled", b"skipped", b"todo"):
            self.assertFalse(M.counts_pass(M.tap_counts(SUMMARY.replace(b"# " + name + b" 0", b"# " + name + b" 1"))))
        self.assertFalse(M.counts_pass(M.tap_counts(SUMMARY.replace(b"151", b"150"))))
        self.assertFalse(M.counts_pass(M.tap_counts(SUMMARY.replace(b"# pass 151", b"# pass 150"))))

    def test_workflow_executes_only_the_fixed_suites_before_one_required_build(self):
        workflow = (ROOT / ".github/workflows/desktop-macos-aqua.yml").read_text()
        label = "      - name: Compile the fixed debug actual-main observer and normal embedded frontend once\n"
        step = workflow.split(label, 1)[1].split("\n      - name:", 1)[0]
        invocation = '"$MRK_PYTHON" -I -S -B tools/macos_frontend_data_checks.py'
        self.assertEqual(step.count(invocation), 1)
        self.assertLess(step.index("npm ci "), step.index(invocation))
        self.assertLess(step.index(invocation), step.index("npm run build"))
        self.assertEqual(step.count("npm run build"), 1)
        self.assertEqual(M.SUITES, ("tests/asset-session.test.mjs", "tests/ios-archive.test.mjs",
                                    "tests/catalog.test.mjs", "tests/metadata-images.test.mjs"))
        source = PATH.read_text()
        for token in ('"/usr/bin/sandbox-exec", "-p", NETWORK_POLICY, str(node)',
                      '"--permission", "--allow-fs-read=" + str(checkout)',
                      '"--test-isolation=none", "--test-concurrency=1"',
                      '"--test-reporter=tap", *SUITES',
                      'timeout=60, capture=True, text=False, output_limit=OUTPUT_LIMIT',
                      'binding = read_binding(work / "source-binding.json")',
                      'if not entered or original_returned:', 'directory.rmdir()',
                      '"nativeUiQualified": False', '"testsPassed": False'):
            self.assertIn(token, source)
        self.assertEqual(M.NETWORK_POLICY, "(version 1)(allow default)(deny network*)")
        for forbidden in ("--allow-fs-write", "--allow-child-process", "--allow-worker", "--allow-addons",
                          "rmtree", "shell=True"):
            self.assertNotIn(forbidden, source)
        for output in ("frontend-data.receipt.json", "frontend-data-tests.stdout", "frontend-data-tests.stderr"):
            self.assertIn("${{ steps.work.outputs.root }}/" + output + "\n", workflow)


if __name__ == "__main__":
    unittest.main()
