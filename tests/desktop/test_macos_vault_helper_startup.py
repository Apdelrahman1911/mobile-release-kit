"""DATA-only startup-adapter contracts; never execute a helper or process owner."""
from __future__ import annotations

import ast
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "desktop/tools/macos_vault_helper_startup.py"
spec = importlib.util.spec_from_file_location("mrk_startup_adapter_data", SOURCE)
adapter = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = adapter
spec.loader.exec_module(adapter)


class StartupAdapterData(unittest.TestCase):
    def exercise(self, codes=(64, 65, 66, 65), *, failure=None):
        calls, checks = [], []
        state = adapter.Run()

        def fake_owner(argv, **keywords):
            calls.append((argv, keywords))
            if failure is not None and len(calls) == 2:
                raise failure
            return subprocess.CompletedProcess(argv, codes[len(calls) - 1], b"", b"")

        result = adapter.run_cases(fake_owner, Path("/inert/helper"), Path("/inert/cwd"), 501,
                                   lambda: checks.append(True), state)
        return result, calls, checks, state

    def test_cases_are_fixed_explicit_environment_and_no_request_input(self):
        result, calls, checks, state = self.exercise()
        self.assertTrue(result)
        self.assertEqual(len(checks), 8)
        self.assertEqual([call[0] for call in calls], [["/inert/helper", "mrk-startup-fixture"]] + [["/inert/helper"]] * 3)
        self.assertEqual([call[1]["environ"] for call in calls], [{}, {"__CF_USER_TEXT_ENCODING": "0x1F5:0:0"},
                                                                {"MRK_STARTUP_DIAGNOSTIC": "synthetic"}, {}])
        for _, keywords in calls:
            self.assertEqual(set(keywords), {"environ", "cwd", "timeout", "capture", "text", "output_limit"})
            self.assertEqual((keywords["timeout"], keywords["capture"], keywords["text"], keywords["output_limit"]),
                             (10, True, False, 4096))
        self.assertFalse(state.inflight)
        self.assertTrue(all(row["originalCallSettled"] and row["outputEmpty"] for row in state.rows))

    def test_baseline_is_observation_not_an_assumed_cf_diagnosis(self):
        for code in (1, 64, 65, 66):
            result, _, _, state = self.exercise((64, 65, 66, code))
            self.assertTrue(result)
            self.assertEqual(state.rows[-1]["exitCode"], code)
        result, calls, _, state = self.exercise((64, 65, 66, 99))
        self.assertFalse(result)
        self.assertEqual(len(calls), 4)
        self.assertEqual(state.rows[-1]["category"], "unexpected-code")

    def test_zero_stops_without_readback_later_case_or_cleanup_authority(self):
        for stop_at in (0, 3):
            state, calls, checks = adapter.Run(), [], []

            def fake_owner(argv, **kwargs):
                index = len(calls)
                calls.append(argv)
                code = 0 if index == stop_at else (64, 65, 66, 1)[index]
                return subprocess.CompletedProcess(argv, code, b"", b"")

            with self.assertRaisesRegex(adapter.Refused, "unexpected-success"):
                adapter.run_cases(fake_owner, Path("/inert/helper"), Path("/inert/cwd"), 501,
                                  lambda: checks.append(True), state)
            self.assertEqual((len(calls), len(checks), len(state.rows)),
                             (stop_at + 1, 2 * stop_at + 1, stop_at))
            self.assertTrue(state.last_returned)
            self.assertTrue(state.inflight)  # main cannot close originals or authorize cleanup.

    def test_settled_mismatch_continues_but_never_repairs_aggregate_failure(self):
        result, calls, checks, state = self.exercise((64, 66, 66, 65))
        self.assertFalse(result)
        self.assertEqual((len(calls), len(checks)), (4, 8))
        self.assertEqual([row["matched"] for row in state.rows], [True, False, True, True])
        self.assertTrue(state.failed)

    def test_owner_exception_preserves_identity_and_stops_without_readback(self):
        error, state, calls, checks = RuntimeError("not exported"), adapter.Run(), [], []

        def fake_owner(argv, **kwargs):
            calls.append(argv)
            if len(calls) == 2:
                raise error
            return subprocess.CompletedProcess(argv, 64, b"", b"")

        with self.assertRaises(RuntimeError) as caught:
            adapter.run_cases(fake_owner, Path("/inert/helper"), Path("/inert/cwd"), 501,
                              lambda: checks.append(True), state)
        self.assertIs(caught.exception, error)
        self.assertEqual((len(calls), len(checks), len(state.rows)), (2, 3, 1))
        self.assertTrue(state.inflight)
        self.assertFalse(state.last_returned)

    def test_malformed_results_or_any_output_cannot_authorize_readback_or_next_case(self):
        for result in (object(), subprocess.CompletedProcess(["wrong"], 64, b"", b""),
                       subprocess.CompletedProcess(["/inert/helper", "mrk-startup-fixture"], True, b"", b""),
                       subprocess.CompletedProcess(["/inert/helper", "mrk-startup-fixture"], -9, b"", b""),
                       subprocess.CompletedProcess(["/inert/helper", "mrk-startup-fixture"], 64, "", b""),
                       subprocess.CompletedProcess(["/inert/helper", "mrk-startup-fixture"], 64, b"private output", b""),
                       subprocess.CompletedProcess(["/inert/helper", "mrk-startup-fixture"], 64, b"", b"x" * 4097)):
            state, calls, checks = adapter.Run(), [], []

            def fake_owner(argv, **kwargs):
                calls.append(argv)
                return result

            with self.assertRaises(adapter.Refused):
                adapter.run_cases(fake_owner, Path("/inert/helper"), Path("/inert/cwd"), 501,
                                  lambda: checks.append(True), state)
            self.assertEqual((len(calls), len(checks), len(state.rows)), (1, 1, 0))
            self.assertTrue(state.inflight)

    def test_failed_postcondition_stops_even_after_original_owner_return(self):
        calls, checks, state = [], [], adapter.Run()

        def check():
            checks.append(True)
            if len(checks) == 2:
                raise adapter.Refused("original-changed")

        def fake_owner(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 64, b"", b"")

        with self.assertRaises(adapter.Refused):
            adapter.run_cases(fake_owner, Path("/inert/helper"), Path("/inert/cwd"), 501, check, state)
        self.assertEqual((len(calls), len(checks), len(state.rows)), (1, 2, 0))
        self.assertFalse(state.inflight)
        self.assertTrue(state.last_returned)

    def test_file_custody_and_cwd_roster_are_actual_data_checks_not_fake_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "case-cwd").mkdir(mode=0o700)
            helper = root / adapter.HELPER
            helper.parent.mkdir(parents=True, mode=0o700)
            helper.write_bytes(b"inert data, not an executable")
            helper.chmod(0o500)
            originals = adapter.Originals(root, os.getuid())
            try:
                originals.open(list(adapter.signature(root.stat())[:5]))
                self.assertEqual(originals.bytes, helper.stat().st_size)
                originals.check()
                (root / "case-cwd/unexpected").write_bytes(b"fixture")
                with self.assertRaisesRegex(adapter.Refused, "cwd-roster"):
                    originals.check()
            finally:
                originals.close()
            self.assertEqual(originals.held, [])

    def test_symlink_helper_is_refused_before_any_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "case-cwd").mkdir(mode=0o700)
            helper = root / adapter.HELPER
            helper.parent.mkdir(parents=True, mode=0o700)
            helper.symlink_to("missing-fixture")
            originals = adapter.Originals(root, os.getuid())
            try:
                with self.assertRaises(OSError):
                    originals.open(list(adapter.signature(root.stat())[:5]))
            finally:
                originals.close()

    def test_workflow_and_source_keep_actual_graph_and_existing_owner_only(self):
        workflow = (ROOT / ".github/workflows/desktop-macos-vault-startup.yml").read_text()
        for action, pin in re.findall(r"uses:\s*([^@\s]+)@([0-9a-f]+)", workflow):
            self.assertEqual(len(pin), 40, action)
        self.assertIn("cargo build --manifest-path desktop/helpers/macos-vault-helper/Cargo.toml --offline --locked --release --target aarch64-apple-darwin", workflow)
        self.assertIn("runs-on: macos-26", workflow)
        self.assertIn("RUSTUP_TOOLCHAIN: '1.98.1'", workflow)
        self.assertIn("desktop/packaging/macos-empty-entitlements.plist", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("--features", workflow)
        self.assertNotIn("xcodebuild", workflow)
        self.assertNotIn("npm ", workflow)
        self.assertNotRegex(workflow, r'(?m)^\s*(?:exec\s+)?["\']?\$helper(?:["\']|\s|$)')
        source = SOURCE.read_text()
        tree = ast.parse(source)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertFalse(any(isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                             and node.func.value.id == "subprocess" for node in calls))
        self.assertIn("return module.load_owner(checkout)", source)
        self.assertIn("run_cases(owner.run_owned", source)
        helper = (ROOT / "desktop/native/macos-installed-native/src/vault_helper.rs").read_text()
        self.assertEqual(helper.count("std::env::vars_os()"), 1)
        self.assertIn("startup::refusal(std::env::args_os().take(2).count(),", helper)
        self.assertIn("||std::env::vars_os().map(|(name,_)|name)", helper)
        self.assertLess(helper.index("if let Some(code)=startup::refusal"), helper.index("let mut work=Work::new()"))


if __name__ == "__main__":
    unittest.main()
