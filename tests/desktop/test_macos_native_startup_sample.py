"""Inert sample-report/process substitutes; never launch sample or an app."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("native_startup_sample", ROOT / "desktop/tools/macos_native_startup_sample.py")
SAMPLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SAMPLE)
PRIVATE = "PRIVATE STACK PATH STDERR MUST NOT BE EXPORTED"
WALK = "installed_shell_observation::installed_runtime::Book::walk"
# Generated, not executed, using existing rustc1.98.0 (88d9e12ae), default v0:
# --edition=2021 --crate-type=lib --emit=llvm-ir -C opt-level=0 -o - -
# Exact1.98.1 tagged compiler source also declares v0 default. These fixtures
# establish encodings, NOT symbols observed in the signed Mac application.
V0_CASES = (
    ("inventory-walk", "_RNvMNtCs9EckvoX1OKL_27installed_shell_observation17installed_runtimeNtB2_4Book4walk"),
    ("inventory-inspect", "_RNvMNtCs9EckvoX1OKL_27installed_shell_observation17installed_runtimeNtB2_4Book7inspect"),
    ("inventory-read", "_RNvMs_NtCs9EckvoX1OKL_27installed_shell_observation17installed_runtimeNtB4_4Book4read"),
    ("inventory-reserve", "_RNvMs_NtCs9EckvoX1OKL_27installed_shell_observation17installed_runtimeNtB4_4Book7reserve"),
    ("runtime-resolve", "_RNvMNtCs9EckvoX1OKL_27installed_shell_observation7runtimeNtB2_13RuntimeConfig25resolve_passive_installed"),
    ("supervisor-prepare", "_RNvMNtCs9EckvoX1OKL_27installed_shell_observation10supervisorNtB2_20PreparedPassiveSpawn7prepare"),
    ("supervisor-admission", "_RNvNtCs9EckvoX1OKL_27installed_shell_observation10supervisor24acquire_passive_original"),
    ("supervisor-spawn", "_RNvNtCs9EckvoX1OKL_27installed_shell_observation10supervisor22spawn_passive_original"),
    ("supervisor-wait", "_RNCNvNtCs9EckvoX1OKL_27installed_shell_observation10supervisor13wait_original0B5_"),
    ("supervisor-write", "_RNCNvNtCs9EckvoX1OKL_27installed_shell_observation10supervisor13write_request0B5_"),
    ("supervisor-read", "_RINvNtCs9EckvoX1OKL_27installed_shell_observation10supervisor12read_boundedhEB4_"),
    ("supervisor-read", "_RNCINvNtCs9EckvoX1OKL_27installed_shell_observation10supervisor12read_boundedhE0B6_"),
    ("filesystem-observe", "_RNvMNtCskC5sipNRyls_26mrk_macos_installed_native16vault_filesystemNtB2_12SnapshotBook14observe_phased"),
)


def frame(symbol, count=123):
    return f"    + ! : | {count} {symbol} (in {SAMPLE.PROCESS}) + 72 [{PRIVATE}]"


def report(*frames, path=SAMPLE.EXECUTABLE, process=None, summary=""):
    return ("Analysis of sampling\nProcess:         " + (process or SAMPLE.PROCESS + " [456]")
        + "\nPath:            " + path + "\nAnalysis Tool:   /usr/bin/sample\n\nCall graph:\n"
        + "    999 Thread_123\n" + "\n".join(frames or [frame(WALK)])
        + "\n\nTotal number in stack (recursive counted multiple, when >=5):\n" + summary
        + "\nSort by top of stack, same collapsed (when >=5):\n"
        + "\nBinary Images:\n    0x100000000 - 0x100000fff +" + SAMPLE.PROCESS
        + " (0) <UUID> /" + PRIVATE + "\n").encode()


class FakeSampler:
    def __init__(self, path, options, *, raw=None, stdout=b"", stderr=b"", code=0,
                 failure=None, cleanup_failure=False, transform=None):
        self.path, self.options = path, options
        self.raw, self.stdout, self.stderr = report() if raw is None else raw, stdout, stderr
        self.code, self.failure, self.cleanup_failure = code, failure, cleanup_failure
        self.transform, self.returncode, self.kills, self.waits = transform, None, 0, []

    def wait(self, *, timeout):
        self.waits.append(timeout)
        if len(self.waits) == 1:
            self.path.write_bytes(self.raw)
            if self.transform is not None:
                self.transform(self.path)
            for key, raw in (("stdout", self.stdout), ("stderr", self.stderr)):
                self.options[key].write(raw)
                self.options[key].flush()
            if self.failure is not None:
                raise self.failure
            self.returncode = self.code
        else:
            if self.cleanup_failure:
                raise subprocess.TimeoutExpired(PRIVATE, timeout, output=PRIVATE)
            self.returncode = -9
        return self.returncode

    def kill(self):
        self.kills += 1


class NativeStartupSampleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.temp = Path(temporary.name)
        self.work = self.temp / "existing-app-work"
        self.work.mkdir()
        (self.work / "original").write_text(PRIVATE)
        self.children = []

    def run_sample(self, *, times=(100, 102, 103, 104), **options):
        def launch(argv, **kwargs):
            self.argv, self.options = argv, kwargs
            path = Path(argv[-1])
            self.assertEqual(path.parent.parent, self.temp)
            self.assertNotEqual(path.parent, self.work)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            for key in ("stdout", "stderr"):
                self.assertEqual(stat.S_IMODE(os.fstat(kwargs[key].fileno()).st_mode), 0o600)
                self.assertEqual(os.fstat(kwargs[key].fileno()).st_nlink, 0)
            child = FakeSampler(path, kwargs, **options)
            self.children.append(child)
            return child
        with patch.object(SAMPLE, "TEMP", self.temp), patch.object(SAMPLE.subprocess, "Popen", side_effect=launch) as launch, \
                patch.object(SAMPLE.time, "monotonic", side_effect=times):
            result = SAMPLE.sample(501)
        self.assertEqual(launch.call_count, 1)
        self.assertTrue(self.options["stdout"].closed and self.options["stderr"].closed)
        self.assertEqual(list(self.work.iterdir()), [self.work / "original"])
        self.assertEqual((self.work / "original").read_text(), PRIVATE)
        for private in (PRIVATE, str(self.temp), SAMPLE.EXECUTABLE, "[456]"):
            self.assertNotIn(private, json.dumps(result))
        if result["captures"] == "removed":
            self.assertFalse(self.children[-1].path.parent.exists())
        else:
            self.assertTrue(self.children[-1].path.parent.exists())
        return result

    def test_fixed_sampler_only_no_app_launch_or_environment_inheritance(self):
        with patch.dict(os.environ, {"PATH": PRIVATE, "HOME": PRIVATE, "PYTHONPATH": PRIVATE, "TOKEN": PRIVATE}):
            result = self.run_sample(stderr=PRIVATE.encode())  # sample progress may use stderr.
        self.assertEqual(self.argv[:-1], ("/usr/bin/sample", SAMPLE.PROCESS, "10", "10", "-wait", "-mayDie", "-file"))
        self.assertEqual(self.options["cwd"], self.children[0].path.parent)
        self.assertEqual(self.options["stdin"], subprocess.DEVNULL)
        self.assertEqual(self.options["env"], {"LC_ALL": "C", "LANG": "C", "__CF_USER_TEXT_ENCODING": "0x1F5:0:0"})
        self.assertIs(self.options["preexec_fn"], SAMPLE._child_limits)
        self.assertTrue(self.options["close_fds"] and self.options["restore_signals"])
        self.assertEqual((self.children[0].waits, self.children[0].kills), ([43.0], 0))
        self.assertEqual((result["outcome"], result["elapsedSeconds"], result["exitCode"]), ("observed", 4, 0))
        self.assertEqual((result["reportShape"], result["installedHeaderMatches"]), ("known-symbols", True))
        self.assertEqual(result["knownSymbolLineCounts"]["inventory-walk"], 1)
        self.assertEqual((result["stdoutBytes"], result["stderrBytes"], result["captures"]), (0, len(PRIVATE), "removed"))

    def test_counts_are_call_tree_lines_not_sample_weights_or_exclusive_stages(self):
        raw = report(frame(WALK, 999), frame(WALK + "::h0123456789abcdef", 1),
            frame("mobile_release_desktop::installed_runtime::Book::inspect", 12),
            frame("installed_shell_observation::supervisor::read_bounded::{{closure}}", 14))
        shape, matched, counts, _, _, _ = SAMPLE.report_shape(raw)
        self.assertEqual((shape, matched), ("known-symbols", True))
        self.assertEqual((counts["inventory-walk"], counts["inventory-inspect"], counts["supervisor-read"]), (2, 1, 1))
        self.assertEqual(sum(counts.values()), 4)

    def test_fixed_legacy_rust_and_native_symbol_spellings(self):
        legacy = "_ZN" + "".join(f"{len(part)}{part}" for part in WALK.split("::")) + "17h0123456789abcdefE"
        raw = report(frame(legacy), frame("mrk_macos_installed_native::vault_filesystem::SnapshotBook::observe_phased"),
                     frame("mrk_vault_acl_step"))
        shape, _, counts, _, _, _ = SAMPLE.report_shape(raw)
        self.assertEqual(shape, "known-symbols")
        self.assertEqual((counts["inventory-walk"], counts["filesystem-observe"], counts["filesystem-acl"]), (1, 1, 1))

    def test_summaries_source_paths_images_and_unrelated_prefixes_do_not_count(self):
        raw = report(frame("???") + " " + WALK, frame(WALK + "_unrelated"), frame("different_" + WALK),
                     summary=frame(WALK))
        raw = raw.replace(("/" + PRIVATE).encode(), ("/" + WALK).encode())
        shape, matched, counts, _, _, _ = SAMPLE.report_shape(raw)
        self.assertEqual((shape, matched), ("no-known-symbols", True))
        self.assertTrue(all(value == 0 for value in counts.values()))

    def test_default_v0_generated_fixed_paths_impl_disambiguators_and_async_generics(self):
        for label, symbol in (*V0_CASES, ("inventory-walk", "_" + V0_CASES[0][1] + ".llvm.123")):
            with self.subTest(label=label, symbol=symbol):
                shape, matched, counts, weights, seen, unmatched = SAMPLE.report_shape(report(frame(symbol, 37)))
                self.assertEqual((shape, matched, seen, unmatched), ("known-symbols", True, 1, 0))
                self.assertEqual((counts[label], weights[label], sum(counts.values()), sum(weights.values())), (1, 37, 1, 37))
        # Exact outputs of existing c++filt -s rust on the generated fixtures.
        for label, symbol in (
            ("inventory-walk", "<installed_shell_observation[706169e86843f385]::installed_runtime::Book>::walk"),
            ("supervisor-read", "installed_shell_observation[706169e86843f385]::supervisor::read_bounded::<u8>::{closure#0}")):
            shape, matched, counts, weights, seen, unmatched = SAMPLE.report_shape(report(frame(symbol, 37)))
            self.assertEqual((shape, matched, seen, unmatched), ("known-symbols", True, 0, 0))
            self.assertEqual((counts[label], weights[label], sum(counts.values())), (1, 37, 1))

    def test_v0_wrong_identifiers_backrefs_embedded_paths_or_unsupported_forms_do_not_match(self):
        walk = V0_CASES[0][1]
        # The last actual compiler-generated symbol mentions the right function
        # ONLY in drop_glue's generic argument. It must not become that function.
        invalid = (walk.replace("27installed_shell_observation", "32fake_installed_shell_observation"),
            walk.replace("17installed_runtime", "23installed_runtime_extra"), walk.replace("4Book", "8BookCopy"),
            walk.replace("4walk", "10walk_extra"), walk.replace("NtB2_", "NtB3_"), walk + "extra",
            "_RINvNtCsc36rpYXAlPq_4core3ptr9drop_glueNCINvNtCs9EckvoX1OKL_27installed_shell_observation10supervisor12read_boundedhE0EBI_")
        for symbol in invalid:
            with self.subTest(symbol=symbol):
                shape, matched, counts, weights, seen, unmatched = SAMPLE.report_shape(report(frame(symbol)))
                self.assertEqual((shape, matched, seen, unmatched), ("no-known-symbols", True, 1, 1))
                self.assertEqual((sum(counts.values()), sum(weights.values())), (0, 0))
        for symbol in ("<installed_shell_observation[not-hex]::installed_runtime::Book>::walk",
                       "<installed_shell_observation[706169e86843f385]::installed_runtime::BookCopy>::walk",
                       "<installed_shell_observation[706169e86843f385]::installed_runtime::Book>::walk_extra"):
            shape, _, counts, weights, _, _ = SAMPLE.report_shape(report(frame(symbol)))
            self.assertEqual((shape, sum(counts.values()), sum(weights.values())), ("no-known-symbols", 0, 0))

    def test_weights_include_ancestor_overlap_and_recursion_not_exclusive_time_or_operations(self):
        raw = report(frame(WALK, 100), frame(V0_CASES[0][1], 25),
                     frame("installed_shell_observation::installed_runtime::Book::read", 100))
        result = self.run_sample(raw=raw)
        self.assertEqual(result["knownSymbolLineCounts"]["inventory-walk"], 2)
        self.assertEqual(result["knownSymbolInclusiveStackWeights"]["inventory-walk"], 125)
        self.assertEqual(result["knownSymbolInclusiveStackWeights"]["inventory-read"], 100)
        self.assertEqual((result["rustV0FrameLines"], result["unmatchedRustV0FrameLines"]), (1, 0))
        self.assertEqual(result["weightMeaning"], "inclusive-stack-lines-not-exclusive-cpu-time-or-operations")

    def test_matched_report_without_known_symbols_is_explicit_not_absence_proof(self):
        result = self.run_sample(raw=report(frame("???")))
        self.assertEqual((result["outcome"], result["reportShape"]), ("observed", "no-known-symbols"))
        self.assertEqual(set(result["knownSymbolLineCounts"]), set(SAMPLE.SYMBOLS))
        self.assertTrue(all(value == 0 for value in result["knownSymbolLineCounts"].values()))

    def test_wrong_or_duplicate_process_path_headers_block_all_symbol_counts(self):
        valid = report()
        for raw in (report(path=SAMPLE.EXECUTABLE + ".copy"), report(process=SAMPLE.PROCESS + "-copy [456]"),
                    report(process=SAMPLE.PROCESS + " [0]"), b"Path: " + SAMPLE.EXECUTABLE.encode() + b"\n" + valid,
                    b"Process: " + SAMPLE.PROCESS.encode() + b" [456]\n" + valid,
                    valid.replace(b"Path:", b"Elsewhere:")):
            with self.subTest(raw=raw[:40]):
                self.assertEqual(SAMPLE.report_shape(raw), ("header-mismatch", False, None, None, None, None))
        result = self.run_sample(raw=report(path=PRIVATE))
        self.assertEqual((result["outcome"], result["knownSymbolLineCounts"]), ("unavailable", None))

    def test_truncated_malformed_or_empty_graph_cannot_be_observed(self):
        valid = report()
        for raw in (b"", b"\xff\n", valid[:-1], valid.split(b"Binary Images:")[0],
                    valid.split(b"Binary Images:")[0] + b"Binary Images:\n",
                    valid.replace(b"Call graph:\n", b""), valid + b"Binary Images:\n",
                    report("Not a call-tree frame"), valid.replace(b"Path:", b"Call graph:\nPath:")):
            with self.subTest(raw=raw[:40]):
                shape, _, counts, weights, seen, unmatched = SAMPLE.report_shape(raw)
                self.assertEqual((shape, counts), ("invalid", None))
                self.assertEqual((weights, seen, unmatched), (None, None, None))

    def test_nonzero_sampler_return_is_unavailable_without_exporting_refusal_prose(self):
        result = self.run_sample(code=1, raw=b"", stdout=PRIVATE.encode(), stderr=PRIVATE.encode())
        self.assertEqual((result["outcome"], result["exitCode"], result["reportShape"]), ("unavailable", 1, "not-read"))
        self.assertIsNone(result["knownSymbolLineCounts"])

    def test_each_full_or_oversize_capture_is_refused_without_symbol_counts(self):
        for channel in ("raw", "stdout", "stderr"):
            for extra in (0, 1):
                with self.subTest(channel=channel, extra=extra):
                    result = self.run_sample(**{channel: b"x" * (SAMPLE.CAPTURE_LIMIT + extra)})
                    self.assertEqual((result["outcome"], result["reportShape"]), ("unavailable", "capture-limit"))
                    self.assertIsNone(result["knownSymbolLineCounts"])

    def test_report_permissions_missing_file_or_symlink_are_not_followed(self):
        target = self.work / "original"
        def symlink(path):
            path.unlink()
            path.symlink_to(target)
        for transform in (lambda path: path.chmod(0o644), lambda path: path.unlink(), symlink):
            with self.subTest(transform=transform):
                result = self.run_sample(transform=transform)
                self.assertEqual((result["outcome"], result["reportShape"]), ("unavailable", "invalid"))

    def test_timeout_kills_only_sampler_once_and_waits_original_cleanup_remainder(self):
        result = self.run_sample(times=(100, 102, 145.1, 145.2, 146),
            failure=subprocess.TimeoutExpired(PRIVATE, 43, output=PRIVATE))
        child = self.children[-1]
        self.assertEqual((result["outcome"], result["exitCode"], result["reportShape"]), ("timeout", -9, "not-read"))
        self.assertEqual(child.kills, 1)
        self.assertEqual(len(child.waits), 2)
        self.assertAlmostEqual(child.waits[1], 1.8)

    def test_unknown_sampler_return_retains_private_report_without_read_or_cleanup(self):
        with patch.object(SAMPLE, "_read_report") as read:
            result = self.run_sample(times=(100, 102, 145.1, 145.2, 147.1),
                failure=subprocess.TimeoutExpired(PRIVATE, 43), cleanup_failure=True)
        read.assert_not_called()
        self.assertEqual((result["outcome"], result["exitCode"], result["captures"]),
                         ("sampler-return-unknown", None, "retained-sampler-unknown"))
        self.assertIsNone(result["stdoutBytes"])
        self.assertTrue(self.children[-1].path.is_file())
        self.assertEqual((self.children[-1].kills, len(self.children[-1].waits)), (1, 2))

    def test_late_zero_return_does_not_restart_sampling_deadline(self):
        result = self.run_sample(times=(100, 102, 145, 146))
        self.assertEqual((result["outcome"], result["exitCode"], result["reportShape"]), ("timeout", 0, "not-read"))
        self.assertEqual((self.children[-1].kills, len(self.children[-1].waits)), (0, 1))

    def test_launch_error_is_not_retried_and_does_not_claim_real_sampler_return(self):
        with patch.object(SAMPLE, "TEMP", self.temp), patch.object(SAMPLE.subprocess, "Popen", side_effect=OSError(PRIVATE)) as launch, \
                patch.object(SAMPLE.time, "monotonic", side_effect=(100, 101)):
            result = SAMPLE.sample(501)
        self.assertEqual(launch.call_count, 1)
        self.assertEqual((result["outcome"], result["exitCode"], result["captures"]),
                         ("launch-error", None, "retained-sampler-unknown"))
        self.assertEqual(len(list(self.temp.glob("mrk-native-startup-sample-*/sample.txt"))), 1)
        self.assertNotIn(PRIVATE, json.dumps(result))

    def test_unknown_extra_private_file_is_not_broadly_deleted(self):
        result = self.run_sample(transform=lambda path: (path.parent / "unexpected").write_text(PRIVATE))
        self.assertEqual((result["outcome"], result["captures"]), ("observed", "cleanup-error"))
        self.assertFalse(self.children[-1].path.exists())
        self.assertTrue((self.children[-1].path.parent / "unexpected").is_file())

    @unittest.skipUnless(os.name == "posix", "child resource limits are Unix-only")
    def test_limits_and_umask_are_only_child_setup_not_parent_mutation(self):
        import resource
        with patch.object(SAMPLE.os, "umask") as mask, patch.object(resource, "setrlimit") as limit:
            SAMPLE._child_limits()
        mask.assert_called_once_with(0o077)
        self.assertEqual(limit.call_args_list, [call(resource.RLIMIT_CORE, (0, 0)),
            call(resource.RLIMIT_FSIZE, (SAMPLE.CAPTURE_LIMIT, SAMPLE.CAPTURE_LIMIT))])

    def test_entry_requires_explicit_flag_fixed_git_source_temp_and_no_core_diagnostic(self):
        environment = {"MRK_MACOS_NATIVE_STARTUP_SAMPLE": "true", "MRK_CANDIDATE_MODE": "install-retained-git-observer",
                       "MRK_CANDIDATE_SOURCE": SAMPLE.SOURCE, "RUNNER_TEMP": str(SAMPLE.TEMP)}
        overrides = ({"MRK_MACOS_NATIVE_STARTUP_SAMPLE": "false"}, {"MRK_MACOS_NATIVE_STARTUP_SAMPLE": "TRUE"},
                     {"MRK_MACOS_BUNDLED_CORE_DIAGNOSTIC": "true"}, {"MRK_CANDIDATE_MODE": "install-retained-observer"},
                     {"MRK_CANDIDATE_SOURCE": "0" * 40}, {"RUNNER_TEMP": PRIVATE})
        for override in overrides:
            with self.subTest(override=override), patch.dict(os.environ, {**environment, **override}, clear=True), \
                    patch.object(SAMPLE.sys, "argv", ["sample"]), patch.object(SAMPLE.subprocess, "Popen") as launch, \
                    patch.object(SAMPLE.importlib.util, "spec_from_file_location") as loader, redirect_stdout(io.StringIO()) as stream:
                self.assertEqual(SAMPLE.main(), 1)
            launch.assert_not_called()
            loader.assert_not_called()
            self.assertEqual(json.loads(stream.getvalue())["outcome"], "refused")
        with patch.dict(os.environ, environment, clear=True), patch.object(SAMPLE.sys, "argv", ["sample", "--pid", "456"]):
            with self.assertRaises(ValueError):
                SAMPLE.admitted_context()

    def test_existing_retained_context_user_and_exact_previous_status_are_required(self):
        context = SimpleNamespace(TARGET="aarch64-apple-darwin",
            retained_context=Mock(return_value=("helper", "1", "1", self.work)),
            _native_user=Mock(return_value=(501, 20, "runner", ("xcode-27", "27.0"))))
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda _: None))
        environment = {"MRK_MACOS_NATIVE_STARTUP_SAMPLE": "true", "MRK_CANDIDATE_MODE": "install-retained-git-observer",
                       "MRK_CANDIDATE_SOURCE": SAMPLE.SOURCE, "RUNNER_TEMP": str(SAMPLE.TEMP)}
        with patch.dict(os.environ, environment, clear=True), patch.object(SAMPLE.sys, "argv", ["sample"]), \
                patch.object(SAMPLE.importlib.util, "spec_from_file_location", return_value=spec), \
                patch.object(SAMPLE.importlib.util, "module_from_spec", return_value=context):
            for status in (b"1\n", b"0\nextra", b""):
                (self.work / "retained-observer-install.status").write_bytes(status)
                with self.assertRaises(ValueError):
                    SAMPLE.admitted_context()
            (self.work / "retained-observer-install.status").write_bytes(b"0\n")
            self.assertEqual(SAMPLE.admitted_context(), 501)
        self.assertEqual(context.retained_context.call_count, 4)
        context._native_user.assert_called_with(os.environ, retained=True)

    def test_main_exit_zero_only_for_observed_report_and_completed_private_cleanup(self):
        for outcome, captures, expected in (("observed", "removed", 0), ("unavailable", "removed", 1),
                                            ("observed", "cleanup-error", 1)):
            result = {**SAMPLE._result(), "outcome": outcome, "captures": captures}
            with patch.object(SAMPLE, "admitted_context", return_value=501), patch.object(SAMPLE, "sample", return_value=result), \
                    redirect_stdout(io.StringIO()) as stream:
                self.assertEqual(SAMPLE.main(), expected)
            self.assertEqual(json.loads(stream.getvalue()), result)


if __name__ == "__main__":
    unittest.main()
