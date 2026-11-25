"""DATA-only startup-adapter contracts; never execute a helper or process owner."""
from __future__ import annotations

import ast
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "desktop/tools/macos_vault_helper_startup.py"
spec = importlib.util.spec_from_file_location("mrk_startup_adapter_data", SOURCE)
adapter = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = adapter
spec.loader.exec_module(adapter)


class StartupAdapterData(unittest.TestCase):
    def exercise(self, codes=(64, 67, 65, 66, 67), *, failure=None):
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
        self.assertEqual(len(checks), 10)
        self.assertEqual([call[0] for call in calls], [["/inert/helper", "mrk-startup-fixture"]]
                         + [["/inert/helper", "--mrk-vault-worker-gate-v1", "3", "2"]] * 4)
        self.assertEqual([call[1]["environ"] for call in calls], [{}, {"__CF_USER_TEXT_ENCODING": "0x1F5:0:0"},
                            {"__CF_USER_TEXT_ENCODING": "0x1F5:not-an-encoding"},
                            {"MRK_STARTUP_DIAGNOSTIC": "synthetic"}, {}])
        self.assertEqual([row["case"] for row in state.rows],
                         ["bad-argc", "canonical-cf", "malformed-cf", "other-name", "empty-parent-env"])
        for _, keywords in calls:
            self.assertEqual(set(keywords), {"environ", "cwd", "timeout", "capture", "text", "output_limit"})
            self.assertEqual((keywords["timeout"], keywords["capture"], keywords["text"], keywords["output_limit"]),
                             (10, True, False, 4096))
        self.assertFalse(state.inflight)
        self.assertTrue(all(row["originalCallSettled"] and row["outputEmpty"] for row in state.rows))

    def test_canonical_and_empty_parent_cases_require_noninstalled_refusal_not_go(self):
        result, _, _, state = self.exercise()
        self.assertTrue(result)
        self.assertEqual([row["exitCode"] for row in state.rows], [64, 67, 65, 66, 67])
        self.assertEqual(state.rows[2]["category"], "cf-encoding-refused")
        for index in (1, 4):
            self.assertEqual(state.rows[index]["category"], "installed-gate-handoff-required")
            for code in (1, 64, 65, 66, 99):
                codes = [64, 67, 65, 66, 67]
                codes[index] = code
                result, calls, _, state = self.exercise(codes)
                self.assertFalse(result)
                self.assertEqual(len(calls), 5)
                self.assertFalse(state.rows[index]["matched"])
                self.assertTrue(state.failed)

    def test_zero_stops_without_readback_later_case_or_cleanup_authority(self):
        for stop_at in (0, 4):
            state, calls, checks = adapter.Run(), [], []

            def fake_owner(argv, **kwargs):
                index = len(calls)
                calls.append(argv)
                code = 0 if index == stop_at else (64, 67, 65, 66, 67)[index]
                return subprocess.CompletedProcess(argv, code, b"", b"")

            with self.assertRaisesRegex(adapter.Refused, "unexpected-success"):
                adapter.run_cases(fake_owner, Path("/inert/helper"), Path("/inert/cwd"), 501,
                                  lambda: checks.append(True), state)
            self.assertEqual((len(calls), len(checks), len(state.rows)),
                             (stop_at + 1, 2 * stop_at + 1, stop_at))
            self.assertTrue(state.last_returned)
            self.assertTrue(state.inflight)  # main cannot close originals or authorize cleanup.

    def test_settled_mismatch_continues_but_never_repairs_aggregate_failure(self):
        result, calls, checks, state = self.exercise((64, 66, 65, 66, 67))
        self.assertFalse(result)
        self.assertEqual((len(calls), len(checks)), (5, 10))
        self.assertEqual([row["matched"] for row in state.rows], [True, False, True, True, True])
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

    def test_main_requires_the_complete_five_case_roster_for_pass_or_cleanup(self):
        # DATA-only main integration: no owner, helper or filesystem is used.
        binding = {"source": "a" * 40, "tree": "b" * 40, "workflowSource": "a" * 40,
                   "runId": "1", "runAttempt": "1"}
        for row_count, failed in ((4, False), (5, False), (6, False), (5, True)):
            output, closes = [], []

            class DataOriginals:
                digest, bytes = "c" * 64, 1

                def __init__(self, *args):
                    pass

                def open(self, *args):
                    pass

                def check(self):
                    raise AssertionError("no original descriptor in this DATA test")

                def close(self):
                    closes.append(True)

            def no_owner(*args, **kwargs):
                raise AssertionError("no owner execution in this DATA test")

            def data_cases(_owner, _helper, _cwd, _uid, _check, state):
                state.rows = [{"case": "synthetic-row"} for _ in range(row_count)]
                state.failed = failed

            def data_write(fd, payload):
                self.assertEqual(fd, 1)
                output.append(payload)
                return len(payload)

            with patch.object(adapter, "admit", return_value=(Path("/inert/work"),
                              dict(binding, workDirectory=[]), {})), \
                 patch.object(adapter, "Originals", DataOriginals), \
                 patch.object(adapter, "load_owner", return_value=SimpleNamespace(run_owned=no_owner)), \
                 patch.object(adapter, "run_cases", side_effect=data_cases), \
                 patch.object(adapter.os, "write", side_effect=data_write):
                result = adapter.main()
            self.assertEqual(closes, [True])
            self.assertEqual(len(output), 1)
            report = json.loads(output[0])
            expected_pass = row_count == 5 and not failed
            self.assertEqual(result, 0 if expected_pass else 1)
            self.assertEqual(report["status"], "passed" if expected_pass else "failed")
            self.assertEqual(report["cleanupAuthorized"], row_count == 5)
            self.assertFalse(report["keychainQualified"])

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
        self.assertIn("startup::gate_handoff(std::env::args_os())", helper)
        self.assertIn("startup::refusal(4,||std::env::vars_os(),||unistd::getuid().as_raw())", helper)
        self.assertLess(helper.index("startup::gate_handoff"), helper.index("if let Some(code)=startup::refusal"))
        self.assertLess(helper.index("if let Some(code)=startup::refusal"), helper.index("std::env::current_exe()"))
        self.assertLess(helper.index("std::env::current_exe()"), helper.index("if unsafe{mrk_vault_helper_gate_admit"))
        self.assertLess(helper.index("if unsafe{mrk_vault_helper_gate_admit"), helper.index("let mut work=Work::new()"))
        self.assertIn('"installedCallerQualified": False', source)
        self.assertNotIn("pass_fds", source)

        # The ordinary workflows already select this separate helper graph on
        # both native targets. This SOURCE policy does not execute/qualify it.
        entry = (ROOT / "desktop/helpers/macos-vault-helper/src/main.rs").read_text()
        lines = entry.splitlines()
        profile = re.fullmatch(
            r'#\[cfg\(not\(all\(target_os="([^"]+)",target_pointer_width="([^"]+)",'
            r'any\(target_arch="([^"]+)",target_arch="([^"]+)"\)\)\)\)\]', lines[1])
        self.assertIsNotNone(profile)
        platform, width, arm, intel = profile.groups()
        self.assertEqual((platform, width, arm, intel), ("macos", "64", "aarch64", "x86_64"))
        for observed_os, observed_width, observed_arch, admitted in (
            ("macos", "64", "aarch64", True),
            ("macos", "64", "x86_64", True),
            ("linux", "64", "aarch64", False),
            ("windows", "64", "x86_64", False),
            ("ios", "64", "aarch64", False),
            ("macos", "32", "aarch64", False),
            ("macos", "32", "x86_64", False),
            ("macos", "64", "x86", False),
            ("macos", "64", "arm", False),
            ("macos", "64", "riscv64", False),
        ):
            with self.subTest(os=observed_os, width=observed_width, arch=observed_arch):
                self.assertEqual(observed_os == platform and observed_width == width
                                 and observed_arch in (arm, intel), admitted)
        self.assertEqual(lines[0], "//! Fixed private helper main, no user commands or renderer entry points.")
        self.assertEqual(lines[2:], [
            'compile_error!("the fixed vault helper supports only the reviewed macOS LP64 arm64/x86_64 profiles");',
            'const _:()=assert!(mrk_macos_installed_native::VAULT_HELPER_BUILD);',
            '#[no_mangle]',
            'pub extern "C" fn mrk_wrapping_vault_helper_role()->u32{3}',
            'fn main(){std::process::exit(mrk_macos_installed_native::vault_helper::main_entry());}',
        ])
        cargo = (ROOT / "desktop/helpers/macos-vault-helper/Cargo.toml").read_text()
        self.assertIn("\n[workspace]\n", cargo)
        self.assertIn('mrk-macos-installed-native = { path = "../../native/macos-installed-native", '
                      'features = ["vault-helper"] }', cargo)
        self.assertEqual(re.findall(r'features\s*=\s*\[([^\]]*)\]', cargo), ['"vault-helper"'])
        self.assertIn('[profile.release]\npanic = "unwind"', cargo)
        native = (ROOT / "desktop/native/macos-installed-native/src/lib.rs").read_text()
        self.assertIn('#![cfg(all(target_os = "macos", target_pointer_width = "64", '
                      'any(target_arch = "aarch64", target_arch = "x86_64")))]', native)
        for required in (
            'pub const VAULT_HELPER_BUILD: bool = cfg!(feature = "vault-helper");',
            'all(feature = "vault-helper", not(mrk_wrapping_vault_helper_native))',
            'all(mrk_wrapping_vault_helper_native, not(feature = "vault-helper"))',
            'all(feature = "vault-helper", any(feature = "installed-observation", mrk_wrapping_keychain_qualification))',
            'compile_error!("vault helper requires its isolated matching native Cargo role");',
        ):
            self.assertIn(required, native)
        build = (ROOT / "desktop/native/macos-installed-native/build.rs").read_text()
        for required in (
            'matches!(target.as_str(), "aarch64-apple-darwin" | "x86_64-apple-darwin")',
            'std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").as_deref(), Ok("64")',
            'let helper = std::env::var_os("CARGO_FEATURE_VAULT_HELPER").is_some();',
            'std::env::var_os("CARGO_CFG_MRK_WRAPPING_VAULT_HELPER_NATIVE").is_none()',
            'assert!(!helper || !observation && !qualification, "vault helper cannot contain observation/fixture roles");',
            '("aarch64-apple-darwin", "release: 1.98.1", "commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985")',
            '("x86_64-apple-darwin", "release: 1.98.0", "commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea")',
            'build.define("MRK_WRAPPING_VAULT_HELPER", Some("1"));',
            'build.file("src/vault_helper_auth.m");',
            'println!("cargo:rustc-cfg=mrk_wrapping_vault_helper_native");',
        ):
            self.assertIn(required, build)
        native_c = (ROOT / "desktop/native/macos-installed-native/src/native.m").read_text()
        self.assertIn('#if !defined(__APPLE__) || !defined(__LP64__) || '
                      '!defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__)', native_c)
        self.assertIn('#if defined(__arm64__) && !defined(__x86_64__)\n'
                      '#define MRK_NATIVE_MACHINE "arm64"\n'
                      '#elif defined(__x86_64__) && !defined(__arm64__)\n'
                      '#define MRK_NATIVE_MACHINE "x86_64"\n#else\n'
                      '#error "the installed native seam requires exactly one supported Mac architecture"\n#endif', native_c)
        self.assertIn('_Static_assert(sizeof(int) == 4 && sizeof(void *) == 8 && sizeof(size_t) == 8,', native_c)


if __name__ == "__main__":
    unittest.main()
