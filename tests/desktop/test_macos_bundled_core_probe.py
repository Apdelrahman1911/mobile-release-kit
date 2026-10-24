"""Inert direct-core process substitutes only; no installed/native execution."""
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
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("bundled_core_probe", ROOT / "desktop/tools/macos_bundled_core_probe.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
PRIVATE = "PRIVATE CHILD BYTES MUST NOT LEAVE THE CAPTURE"


def envelope(*, methods=14, actions=20):
    return {"protocol": 1, "id": "direct-bundled-core", "ok": True, "result": {
        "coreVersion": "0.3.0", "apiVersion": 1, "hostPlatform": "macos", "mode": "read-only-foundation",
        "methods": [{"method": f"method-{i}", "available": True, "reason": PRIVATE} for i in range(methods)],
        "actions": [{"id": f"action-{i}", "available": False, "reason": PRIVATE} for i in range(actions)],
        "limitations": [PRIVATE]}}


def frame(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


class FakeChild:
    """Only writes inert bytes to the probe's private files, never spawns."""
    def __init__(self, options, *, raw=None, stderr=b"", code=0, failure=None, cleanup_failure=False):
        self.options, self.raw, self.stderr = options, frame(envelope()) if raw is None else raw, stderr
        self.code, self.failure, self.cleanup_failure = code, failure, cleanup_failure
        self.stdin, self.returncode = io.BytesIO(), None
        self.communications, self.kills, self.waits = [], 0, []

    def communicate(self, *, input, timeout):
        self.communications.append((input, timeout))
        # Model communicate's EOF contract; the probe never writes stdin itself.
        self.stdin.write(input)
        self.stdin.close()
        for key, raw in (("stdout", self.raw), ("stderr", self.stderr)):
            target = self.options[key]
            target.write(raw)
            target.flush()
        if self.failure is not None:
            raise self.failure
        self.returncode = self.code
        return None, None  # File capture, not PIPE content.

    def kill(self):
        self.kills += 1

    def wait(self, *, timeout):
        self.waits.append(timeout)
        if self.cleanup_failure:
            raise subprocess.TimeoutExpired(PRIVATE, timeout, output=PRIVATE.encode())
        self.returncode = -9
        return -9


class BundledCoreProbeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.children = []

    def run_probe(self, *, times=(100, 102, 103, 104), **child_options):
        def launch(argv, **options):
            self.argv, self.options = argv, options
            for key in ("stdout", "stderr"):
                self.assertEqual(stat.S_IMODE(os.fstat(options[key].fileno()).st_mode), 0o600)
            child = FakeChild(options, **child_options)
            self.children.append(child)
            return child
        with patch.object(PROBE.subprocess, "Popen", side_effect=launch) as launcher, \
                patch.object(PROBE.time, "monotonic", side_effect=times):
            result = PROBE.probe(501, self.work)
        self.assertEqual(launcher.call_count, 1)
        self.assertNotIn(PRIVATE, json.dumps(result))
        self.assertNotIn(str(self.work), json.dumps(result))
        self.assertEqual(list(self.work.iterdir()), [])
        self.assertTrue(self.options["stdout"].closed and self.options["stderr"].closed)
        return result

    def test_one_fixed_request_eof_interpreter_environment_and_private_capture(self):
        with patch.dict(os.environ, {"PATH": PRIVATE, "PYTHONPATH": PRIVATE, "HOME": PRIVATE}):
            result = self.run_probe()
        runtime = "/Library/Application Support/MobileReleaseKit/versions/macos26-arm64-desktop-03/runtime"
        self.assertEqual(self.argv, (runtime + "/python/bin/python3", "-I", "-S", "-B",
                                    runtime + "/engine_bootstrap.py", runtime + "/core.zip"))
        self.assertEqual(self.options["cwd"], Path(runtime))
        self.assertEqual(self.options["env"], {"LC_ALL": "C", "LANG": "C", "__CF_USER_TEXT_ENCODING": "0x1F5:0:0"})
        self.assertEqual(self.options["stdin"], subprocess.PIPE)
        self.assertIs(self.options["preexec_fn"], PROBE._child_limits)
        self.assertTrue(self.options["close_fds"] and self.options["restore_signals"])
        child = self.children[0]
        self.assertEqual(child.communications, [(b'{"protocol":1,"id":"direct-bundled-core","method":"capabilities","params":{}}\n', 8.0)])
        self.assertTrue(child.stdin.closed)
        self.assertEqual((child.kills, child.waits), (0, []))
        self.assertEqual(result, {"schemaVersion": 1, "scope": PROBE.SCOPE, "outcome": "passed",
            "elapsedSeconds": 4, "exitCode": 0, "responseShape": "capabilities",
            "methodCount": 14, "actionCount": 20, "stderrBytes": 0})

    def test_counts_are_observed_not_a_catalogue_qualification_roster(self):
        result = self.run_probe(raw=frame(envelope(methods=13, actions=21)))
        self.assertEqual((result["outcome"], result["methodCount"], result["actionCount"]), ("passed", 13, 21))

    def test_typed_core_refusal_never_exports_the_error_message(self):
        raw = frame({"protocol": 1, "id": "direct-bundled-core", "ok": False,
                     "error": {"code": "unavailable", "message": PRIVATE, "retryable": False}})
        result = self.run_probe(raw=raw)
        self.assertEqual((result["outcome"], result["responseShape"]), ("refused", "core-refusal"))

    def test_nonzero_exit_or_nonempty_stderr_cannot_pass(self):
        for options in ({"code": 70}, {"stderr": PRIVATE.encode()}):
            with self.subTest(options=options):
                result = self.run_probe(**options)
                self.assertEqual(result["outcome"], "refused")
                self.assertEqual(result["stderrBytes"], len(options.get("stderr", b"")))

    def test_full_and_oversize_capture_are_distinct_from_valid_response(self):
        for size in (PROBE.CAPTURE_LIMIT, PROBE.CAPTURE_LIMIT + 1):
            for channel in ("raw", "stderr"):
                with self.subTest(size=size, channel=channel):
                    result = self.run_probe(**{channel: b"x" * size})
                    self.assertEqual((result["outcome"], result["responseShape"]), ("refused", "capture-limit"))
                    self.assertIsNone(result["methodCount"])

    def test_timeout_has_one_kill_and_only_original_cleanup_remainder(self):
        error = subprocess.TimeoutExpired(PRIVATE, 8, output=PRIVATE.encode(), stderr=PRIVATE.encode())
        result = self.run_probe(times=(100, 102, 110.1, 110.2, 110.3), failure=error)
        child = self.children[-1]
        self.assertEqual((result["outcome"], result["exitCode"], result["responseShape"]), ("timeout", -9, "not-read"))
        self.assertEqual(child.kills, 1)
        self.assertEqual(len(child.waits), 1)
        self.assertAlmostEqual(child.waits[0], 1.8)
        self.assertEqual(len(child.communications), 1)

    def test_cleanup_timeout_is_unknown_without_retry_or_readback(self):
        result = self.run_probe(times=(100, 102, 110.1, 110.2, 112.1),
            failure=subprocess.TimeoutExpired(PRIVATE, 8), cleanup_failure=True)
        self.assertEqual((result["outcome"], result["exitCode"], result["stderrBytes"]), ("cleanup-unknown", None, None))
        self.assertEqual((self.children[-1].kills, len(self.children[-1].waits)), (1, 1))

    def test_late_zero_exit_does_not_restart_the_original_ten_seconds(self):
        result = self.run_probe(times=(100, 102, 110, 110.01))
        self.assertEqual((result["outcome"], result["exitCode"]), ("timeout", 0))

    def test_launch_error_is_closed_and_not_retried(self):
        with patch.object(PROBE.subprocess, "Popen", side_effect=OSError(PRIVATE)) as launch, \
                patch.object(PROBE.time, "monotonic", side_effect=(100, 101)):
            result = PROBE.probe(501, self.work)
        self.assertEqual(launch.call_count, 1)
        self.assertEqual((result["outcome"], result["exitCode"]), ("launch-error", None))
        self.assertNotIn(PRIVATE, json.dumps(result))

    @unittest.skipUnless(os.name == "posix", "child resource limits are Unix-only")
    def test_child_limits_do_not_execute_or_change_parent_limits(self):
        import resource
        with patch.object(resource, "setrlimit") as limit:
            PROBE._child_limits()
        self.assertEqual(limit.call_args_list, [unittest.mock.call(resource.RLIMIT_CORE, (0, 0)),
            unittest.mock.call(resource.RLIMIT_FSIZE, (65536, 65536))])

    def test_strict_frame_envelope_platform_and_shapes(self):
        valid = frame(envelope())
        invalid = [valid[:-1], valid + valid, valid + b"\n", b" " + valid,
                   valid.replace(b'"protocol":1', b'"protocol":true'),
                   valid.replace(b'"protocol":1', b'"protocol":1,"protocol":1'),
                   valid.replace(b'"id":"direct-bundled-core"', b'"id":"different"'),
                   valid.replace(b'"hostPlatform":"macos"', b'"hostPlatform":"linux"'),
                   valid.replace(b'"apiVersion":1', b'"apiVersion":NaN'),
                   valid.replace(b'"available":false', b'"available":true'),
                   b"\xff\n", b"[]\n", b"{" + b"[" * 1000 + b"}\n"]
        for raw in invalid:
            with self.subTest(raw=raw[:40]):
                self.assertEqual(PROBE.response_shape(raw), ("invalid", None, None))

    def test_main_refuses_without_explicit_diagnostic_context_and_never_launches(self):
        stream = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), patch.object(PROBE.sys, "argv", ["probe"]), \
                patch.object(PROBE.subprocess, "Popen") as launch, redirect_stdout(stream):
            self.assertEqual(PROBE.main(), 1)
        launch.assert_not_called()
        self.assertEqual(json.loads(stream.getvalue())["outcome"], "refused")

    def test_existing_context_and_actual_status_are_required_before_return(self):
        context = SimpleNamespace(TARGET="aarch64-apple-darwin",
            retained_context=Mock(return_value=("helper", "1", "1", self.work)),
            _native_user=Mock(return_value=(501, 20, "runner", ("xcode-27", "27.0"))))
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda _: None))
        environment = {"MRK_MACOS_BUNDLED_CORE_DIAGNOSTIC": "true",
                       "MRK_CANDIDATE_MODE": "install-retained-git-observer", "MRK_CANDIDATE_SOURCE": PROBE.SOURCE}
        with patch.dict(os.environ, environment, clear=True), patch.object(PROBE.sys, "argv", ["probe"]), \
                patch.object(PROBE.importlib.util, "spec_from_file_location", return_value=spec), \
                patch.object(PROBE.importlib.util, "module_from_spec", return_value=context):
            for status in (b"1\n", b"0\nextra", b""):
                (self.work / "retained-observer-install.status").write_bytes(status)
                with self.assertRaises(ValueError):
                    PROBE.admitted_context()
            (self.work / "retained-observer-install.status").write_bytes(b"0\n")
            self.assertEqual(PROBE.admitted_context(), (501, self.work))
        self.assertEqual(context.retained_context.call_count, 4)
        context._native_user.assert_called_with(os.environ, retained=True)


if __name__ == "__main__":
    unittest.main()
