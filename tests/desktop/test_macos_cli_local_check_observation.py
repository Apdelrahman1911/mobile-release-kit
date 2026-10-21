"""Inert CLI responses with the actual driver/thread/phase-file code.

Popen and sockets are forbidden. No mrk, Git, app, Store, native grant or worker
is run. Temporary phase/readback files are real; every service/report/return
below is explicitly DATA. The actual seven/eight native journey is UNRUN.
"""
from contextlib import contextmanager
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).absolute().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "desktop/tools" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Each module import is passive. The tests run on an exact source projection
# containing the two Root hooks, not copies of methods or source-string tests.
A = load("_cli_observer_test_aqua", "macos_aqua_qualification.py")
M = load("_cli_observer_test_current", "macos_identity_current_runtime.py")
C = A.CLI
BINDING = A.Binding("a" * 40, "123", "1")
ORIGIN = {"serviceInstance": "1" * 32, "projectId": "2" * 32, "requestId": "3" * 32}
CONFIG = {"bytes": len(A.CONFIG), "sha256": C._hash(A.CONFIG)}
REVISION = 7


def result_report():
    rows = [{"ordinal": i, "check": name, "message": name, "status": status, "projectCheckIndex": None}
            for i, (name, status) in enumerate((("android-gradle-wrapper", "MISSING"),
                                               ("version-source", "PASS"), ("workspace-private-output", "PASS")))]
    return {"schemaVersion": 1, "scope": "saved-local-android-project-checks", "usedConfig": CONFIG.copy(),
            "findings": rows, "summary": {"total": 3, "shown": 3, "omitted": 0,
                "counts": {"PASS": 2, "MISSING": 1, **dict.fromkeys(
                    ("FAIL", "BLOCKED", "INVALID", "SKIP", "MANUAL", "CONFIGURED", "NOT_APPLICABLE"), 0)}},
            "limitations": C.LIMITATIONS.copy()}


TERMINAL = {"phase": "terminal", "operationId": "4" * 32, "ownerGeneration": "5" * 32,
            "reportSha256": C._hash(C._json(result_report()))}


def native_report():
    return {"schemaVersion": 1, "scope": C.SCOPE, "origin": ORIGIN.copy(),
            **{k: TERMINAL[k] for k in ("operationId", "ownerGeneration", "reportSha256")},
            **dict.fromkeys(("consumedPermission", "sameOriginalAfterLateStop", "readRevoked", "readReallowedOnly",
                            "driverSequenceCompared", "phaseOriginalsClosed", "hostOriginalsClosed",
                            "projectFilesUnchanged"), True),
            "hostWorkersJoined": 8, "liveInterruptionTested": False, "applicationRestartTested": False}


def status():
    return {"origin": ORIGIN.copy(), "expectedObservationRevision": REVISION, "requestState": "original-available",
            "historyAvailable": True, "doNotReplay": True,
            "operation": {"operationId": TERMINAL["operationId"], "ownerGeneration": TERMINAL["ownerGeneration"],
                          "statusRevision": 9, "state": "succeeded", "settlement": "settled",
                          "outcome": "complete", "reason": "none", "result": result_report()}}


def response(number):
    if number == 0:
        kind, value = "observation", {"projectId": ORIGIN["projectId"], "registeredInCurrentHost": True,
            "observation": {"revision": REVISION, "stale": False, "discoveryPartial": False,
                            "configuration": {"state": "format-valid", **CONFIG}}}
    elif number in (1, 2, 3, 5):
        kind, value = "local-check", status()
        if number == 1:
            value.update(requestState="queued", operation=None, historyAvailable=False)
    else:
        kind = "requests"
        value = {"schemaVersion": 2, "scope": "current-host-retained-requests", "sampling": "per-request-not-atomic",
                 "doNotReplay": True, "serviceInstance": ORIGIN["serviceInstance"], "projectId": ORIGIN["projectId"],
                 "requests": [{"requestId": ORIGIN["requestId"], "expectedObservationRevision": REVISION,
                               "progress": {"family": "local-check", "requestState": "original-available"},
                               "operation": {k: v for k, v in status()["operation"].items()
                                             if k in ("operationId", "ownerGeneration", "statusRevision", "state", "settlement")},
                               "historyAvailable": True}], "additionalRequests": []}
    return {"version": 1, "requestId": f"{number + 100:032x}", "serviceInstance": ORIGIN["serviceInstance"],
            "clientId": f"{number + 200:032x}", "sessionId": f"{number + 300:032x}",
            "response": {"kind": kind, "value": value}}


class InertJourney:
    """Only fixture DATA/IO; never a process, service or cancellation owner."""
    def __init__(self, root, change=None, thrown=None):
        self.root, self.change, self.thrown = root, change, thrown
        self.calls, self.threads, self.app_calls, self.reads = [], [], 0, 0
        self.parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.fds = [self.parent]
        phases = []
        for name in C.PHASES:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                         0o600, dir_fd=self.parent)
            self.fds.append(fd)
            phases.append(fd)
        uid = os.getuid()
        self.native_send = C.PhaseFile(self.parent, C.PHASES[0], phases[0], uid, True)
        self.driver_read = C.PhaseFile(self.parent, C.PHASES[1], phases[1], uid, False)
        self.cli = SimpleNamespace(home=root / "private-home", calls=None, thread=None, joined=False,
            native=C.PhaseFile(self.parent, C.PHASES[0], phases[0], uid, False),
            driver=C.PhaseFile(self.parent, C.PHASES[1], phases[1], uid, True), current_cli=self.current)
        self.fixture = SimpleNamespace(cli=self.cli, cases=C.CASES, inflight=True, last_returned=False,
            path=root, stage="inert", close_errors=0, prepare=lambda: None,
            before_call=lambda case: C.before_call(self.fixture), recovery_runtime_paths=self.current,
            readback=lambda case: {"inertFixtureReadback": True}, close=lambda: None)

    def current(self):
        self.reads += 1  # Explicitly NOT protected installed source admission.

    def close_files(self):
        # There is never an actual child, so real fixture-thread join is the
        # only asynchronous test obligation. Unknown production custody is not
        # being reinterpreted as a safe actual native cleanup here.
        if isinstance(self.cli.thread, threading.Thread):
            if self.cli.thread.is_alive():
                self.cli.calls.close(failed=True)
                self.cli.thread.join(2)
            if self.cli.thread.is_alive():
                raise AssertionError("test thread did not join; retaining phase files")
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds = []

    def app(self, argv, kw):
        self.app_calls += 1
        if threading.current_thread() is not threading.main_thread():
            raise AssertionError("app callable must stay on main")
        if kw.get("cancellation", "absent") != "absent" or kw["timeout"] != C.APP_SECONDS:
            raise AssertionError("app caller changed its original guard/budget")
        self.native_send.append({"phase": "allowed", "projectId": ORIGIN["projectId"],
                                 "revision": REVISION, "config": CONFIG})
        sent = 0
        until = time.monotonic() + 2
        while time.monotonic() < until:
            if self.cli.calls.failed:
                break  # Return DATA cannot erase the worker's retained failure.
            rows = self.driver_read.read()
            if rows is not None and len(rows) > sent:
                if len(rows) != sent + 1:
                    raise AssertionError("test phase pacing")
                if sent == 0:
                    self.native_send.append(TERMINAL)
                elif sent == 1:
                    self.native_send.append({"phase": "revoked"})
                elif sent == 2:
                    self.native_send.append({"phase": "reallowed"})
                else:
                    break
                sent += 1
            time.sleep(0.001)
        else:
            raise AssertionError("bounded inert app did not receive the next phase")
        value = {**A.expected_result(BINDING, C.SCOPE), "installedCli": native_report()}
        return subprocess.CompletedProcess(argv, 0, A.MARKER + C._json(value) + b"\n", b"")

    def owner(self, argv, **kw):
        if argv[0] != C.CLI:
            return self.app(argv, kw)
        number = len(self.calls)
        self.calls.append((argv.copy(), kw.copy()))
        self.threads.append(threading.get_ident())
        if threading.current_thread() is threading.main_thread() or kw.get("cancellation", "absent") is not None:
            raise AssertionError("CLI used the main cancellation guard")
        if kw["environ"].get("HOME") != str(self.cli.home) or not (1 <= kw["timeout"] <= 30):
            raise AssertionError("CLI original input/budget changed")
        if self.thrown == number:
            raise RuntimeError("inert original did not return")
        if number == 4:
            err = {"version": 1, "ok": False, "error": "access_denied",
                   "message": "This host or grant does not allow the request. Actions require separate Desktop permission; serve-history allows only five cached reads."}
            r = subprocess.CompletedProcess(argv, 4, C._json(err) + b"\n", b"")
        else:
            stderr = b""
            if number == 1:
                query = f"{ORIGIN['projectId']} {ORIGIN['serviceInstance']} {ORIGIN['requestId']}"
                stderr = (f"Inspect without replay: mrk local-check-status {query} --json\n"
                          f"Request STOP: mrk local-check-cancel {query} --json\n").encode()
            r = subprocess.CompletedProcess(argv, 0, C._json(response(number)) + b"\n", stderr)
        return self.change(number, r) if self.change else r


class CliLocalCheckTests(unittest.TestCase):
    def setUp(self):
        for name in ("subprocess.Popen", "socket.socket", "socket.create_connection"):
            self.enterContext(patch(name, side_effect=AssertionError("native/process/network forbidden")))

    @contextmanager
    def journey(self, **kwargs):
        with tempfile.TemporaryDirectory(prefix="mrk-cli-inert-") as tmp:
            j = InertJourney(Path(tmp), **kwargs)
            try:
                yield j
            finally:
                j.close_files()

    def invoke(self, j):
        return C.invoke(j.fixture, j.owner, [A.EXECUTABLE, C.SCOPE], {"LANG": "C"}, j.root)

    def test_actual_driver_seven_inert_calls_one_submit_and_original_thread_join(self):
        with self.journey() as j:
            app_result = self.invoke(j)
            self.assertEqual(app_result.returncode, 0)
            self.assertEqual([args[1] for args, _ in j.calls],
                ["observe", "local-check", "local-check-status", "local-check-cancel", "observe", "local-check-status", "requests"])
            self.assertEqual(len(set(j.threads)), 1)
            self.assertNotEqual(j.threads[0], threading.get_ident())
            self.assertTrue(j.cli.joined and j.cli.calls.returned)
            self.assertFalse(j.cli.thread.is_alive())
            self.assertEqual(j.cli.calls.next, 7)
            self.assertEqual(len(j.cli.calls.results), 7)
            self.assertTrue(j.fixture.inflight)  # Only original run_cases can clear it.
            self.assertEqual(j.driver_read.read()[-1]["phase"], "done")
            self.assertEqual(j.app_calls, 1)

    def test_phase_wait_is_not_synchronous_on_start_or_main_guard_sharing(self):
        with self.journey() as j:
            original = j.app
            def app(argv, kw):
                self.assertEqual(j.calls, [])  # Worker waited for native allow, not before app launch.
                self.assertTrue(j.cli.thread.is_alive())
                return original(argv, kw)
            j.app = app
            self.invoke(j)
            self.assertTrue(all("on_start" not in kw and kw["cancellation"] is None for _, kw in j.calls))

    def test_changed_origin_terminal_or_result_does_not_continue_or_replay(self):
        for number, field in ((1, "origin"), (2, "result"), (3, "generation"), (5, "instance")):
            def change(n, r):
                if n != number:
                    return r
                v = C._decode(r.stdout)
                value = v["response"]["value"]
                if field == "origin": value["origin"]["projectId"] = "f" * 32
                if field == "result": value["operation"]["result"]["usedConfig"]["sha256"] = "f" * 64
                if field == "generation": value["operation"]["ownerGeneration"] = "e" * 32
                if field == "instance": v["serviceInstance"] = "e" * 32
                return subprocess.CompletedProcess(r.args, r.returncode, C._json(v), r.stderr)
            with self.subTest(field=field), self.journey(change=change) as j:
                with self.assertRaisesRegex(ValueError, "cli-thread-originals-not-returned"):
                    self.invoke(j)
                self.assertEqual(len(j.calls), number + 1)
                self.assertTrue(j.cli.calls.failed and j.fixture.inflight)
                self.assertTrue(j.cli.joined)
                self.assertFalse(j.cli.calls.returned)

    def test_refusal_unknown_or_fake_denial_never_counts_as_finished_invocation(self):
        for number, mode in ((1, "refused"), (4, "unknown"), (4, "success"), (4, "wrong-channel"),
                             (4, "false-ok"), (4, "wrong-error"), (4, "extra-field"),
                             (4, "boolean-version"), (4, "long-message")):
            def change(n, r):
                if n != number: return r
                if mode == "refused":
                    v = C._decode(r.stdout)
                    v["response"]["value"].update(requestState="refused-before-admission", operation=None)
                    return subprocess.CompletedProcess(r.args, 3, C._json(v), r.stderr)
                if mode in ("unknown", "success"):
                    return subprocess.CompletedProcess(r.args, 6 if mode == "unknown" else 0, r.stdout, r.stderr)
                if mode == "wrong-channel":
                    return subprocess.CompletedProcess(r.args, 4, b"", r.stdout)
                v = C._decode(r.stdout)
                if mode == "false-ok": v["ok"] = True
                if mode == "wrong-error": v["error"] = "state_unknown"
                if mode == "extra-field": v["extra"] = "unbound data"
                if mode == "boolean-version": v["version"] = True
                if mode == "long-message": v["message"] = "x" * 1025
                return subprocess.CompletedProcess(r.args, 4, C._json(v), b"")
            with self.subTest(mode=mode), self.journey(change=change) as j:
                with self.assertRaises(ValueError): self.invoke(j)
                self.assertEqual(len(j.calls), number + 1)
                self.assertTrue(j.fixture.inflight and j.cli.calls.failed)
                self.assertTrue(j.cli.joined)
                self.assertFalse(j.cli.calls.returned or j.cli.thread.is_alive())
                self.assertNotIn("denied", [r["phase"] for r in j.driver_read.read()])

    def test_denial_message_is_bounded_data_not_english_identity(self):
        def change(n, r):
            if n != 4: return r
            v = C._decode(r.stdout)
            v["message"] = "Different public denial wording."
            return subprocess.CompletedProcess(r.args, 4, C._json(v), b"")
        with self.journey(change=change) as j:
            self.invoke(j)
            self.assertEqual(len(j.calls), 7)
            self.assertTrue(j.cli.calls.returned and j.cli.joined)
            self.assertFalse(j.cli.thread.is_alive())
            self.assertEqual(j.driver_read.read()[-1]["phase"], "done")

    def test_missing_original_or_malformed_return_keeps_claim_inflight(self):
        for thrown in (True, False):
            change = None if thrown else lambda n, r: SimpleNamespace(**r.__dict__) if n == 1 else r
            with self.subTest(thrown=thrown), self.journey(thrown=1 if thrown else None, change=change) as j:
                with self.assertRaises(ValueError): self.invoke(j)
                self.assertEqual(j.cli.calls.inflight, 1)
                self.assertEqual(j.cli.calls.next, 1)
                self.assertEqual(len(j.calls), 2)
                self.assertTrue(j.cli.joined and j.fixture.inflight)
                self.assertEqual(j.driver_read.read(), [])

    def test_numbered_claim_closes_stop_launch_race_without_forgetting_preclaim(self):
        calls = C.Calls(clock=lambda: 10.0)
        self.assertEqual(calls.claim(0), 30)
        calls.close(failed=True)
        result = subprocess.CompletedProcess(["inert"], 0, b"", b"")
        calls.returned_call(0, result)
        self.assertIs(calls.results[0], result)
        self.assertIsNone(calls.inflight)
        self.assertTrue(calls.failed)
        for act in (lambda: calls.claim(1), calls.check,
                    lambda: C._phase(SimpleNamespace(read=lambda: [{"phase": "allowed"}]), calls, "allowed", 0)):
            with self.assertRaises(ValueError): act()
        self.assertEqual(calls.next, 1)

    def test_call_timeout_uses_original_case_clock_and_reserves_actual_cleanup(self):
        now = [10.0]
        calls = C.Calls(clock=lambda: now[0])
        now[0] = 110.0
        self.assertEqual(calls.claim(0), 20)
        calls.returned_call(0, object())
        self.assertEqual((calls.success_end, calls.hard_end), (130.0, 148.0))
        now[0] = 129.1
        with self.assertRaises(ValueError): calls.claim(1)
        calls = C.Calls(clock=lambda: now[0])
        calls.hard_end = now[0] + C.CLEANUP_SECONDS + C.JOIN_MARGIN + 1.9
        self.assertEqual(calls.claim(0), 1)

    def test_main_error_closes_admission_and_joins_waiting_thread_before_return(self):
        with self.journey() as j:
            def app(argv, kw): raise RuntimeError("inert app original unavailable")
            j.app = app
            with self.assertRaisesRegex(RuntimeError, "inert app"):
                self.invoke(j)
            self.assertEqual(j.calls, [])
            self.assertTrue(j.cli.calls.failed and j.cli.joined and j.fixture.inflight)
            self.assertFalse(j.cli.thread.is_alive())

    def test_unknown_join_does_not_clear_fixture_even_with_normal_app_data(self):
        class UnreturnedThread:
            def __init__(self, **kwargs): self.joins = 0
            def start(self): pass  # Explicitly inert: no background work exists.
            def join(self, timeout): self.joins += 1
            def is_alive(self): return True
        with self.journey() as j, patch.object(C.threading, "Thread", UnreturnedThread):
            j.app = lambda argv, kw: subprocess.CompletedProcess(argv, 0, b"DATA", b"")
            with self.assertRaises(ValueError): self.invoke(j)
            self.assertEqual(j.cli.thread.joins, 1)
            self.assertTrue(j.fixture.inflight and j.cli.calls.failed)
            self.assertFalse(j.cli.joined)
            # This is not a real Thread or process; avoid fake cleanup proof.
            j.cli.thread = None

    def test_actual_phase_files_refuse_replacement_prefix_rewrite_and_duplicate_json(self):
        with self.journey() as j:
            j.native_send.append({"phase": "allowed"})
            self.assertEqual(j.cli.native.read(), [{"phase": "allowed"}])
            os.pwrite(j.fds[1], b"X", 0)
            with self.assertRaises(ValueError): j.cli.native.read()
        with self.journey() as j:
            os.rename(j.root / C.PHASES[0], j.root / "retained-old-phase")
            (j.root / C.PHASES[0]).write_bytes(b"")
            with self.assertRaises(ValueError): j.cli.native.read()
        with self.journey() as j:
            os.pwrite(j.fds[1], b'{"phase":"allowed","phase":"done"}\n', 0)
            with self.assertRaisesRegex(ValueError, "cli-json-invalid"): j.cli.native.read()

    def test_same_original_append_between_stat_samples_waits_for_stable_read(self):
        with self.journey() as j:
            original_stat, entered = C.os.stat, []
            def interleaved(name, **kw):
                if name == C.PHASES[0] and not entered:
                    entered.append(True)
                    # Deterministically place a real append between this
                    # reader's held fstat and named stat. No child or writer
                    # authority is fabricated; this is a temporary DATA file.
                    os.pwrite(j.fds[1], b'{"phase":"allowed"}\n', 0)
                    os.fsync(j.fds[1])
                return original_stat(name, **kw)
            with patch.object(C.os, "stat", side_effect=interleaved):
                self.assertIsNone(j.cli.native.read())
            self.assertEqual(entered, [True])
            self.assertEqual(j.cli.native.read(), [{"phase": "allowed"}])

    def test_short_home_refuses_overlong_and_is_fixed_without_endpoint_copy(self):
        home = C.short_home(BINDING, "/Users/runner")
        self.assertEqual(len(os.fsencode(home / "Library/Application Support" / C.APPLICATION / "service-v1/s")), 101)
        self.assertTrue(home.name.startswith(".c-"))
        self.assertEqual(C.short_home(BINDING, "/Users/runner"), home)
        self.assertNotEqual(C.short_home(A.Binding("a" * 40, "123", "2"), "/Users/runner"), home)
        for path in ("/", "relative", "/Users/" + "x" * 100, "/a/b/c/d/e/f"):
            with self.subTest(path=path), self.assertRaises(ValueError): C.short_home(BINDING, path)

    def test_original_fixture_mkdir_never_adopts_collision_or_symlink(self):
        with tempfile.TemporaryDirectory(prefix="mrk-cli-parent-") as tmp:
            f = A.Fixtures(BINDING, os.getuid(), os.getgid(), C.SCOPE)
            c = C.Fixture(f)
            try:
                parent = f._open(tmp, directory=True)
                (Path(tmp) / "occupied").mkdir(mode=0o700)
                (Path(tmp) / "link").symlink_to("occupied", target_is_directory=True)
                for name in ("occupied", "link"):
                    with self.subTest(name=name), self.assertRaises((OSError, A.Refused, ValueError)):
                        c.directory(parent, name, owner=os.getuid(), mode=0o700, create=True)
                with self.assertRaises((OSError, A.Refused, ValueError)):
                    c.directory(parent, "link", owner=os.getuid(), mode=0o700)
                self.assertTrue((Path(tmp) / "occupied").is_dir())
            finally: f.close()
            self.assertEqual(f.close_errors, 0)

    def test_cli_currentness_checks_original_fd_and_retained_peer_not_equal_path(self):
        with tempfile.TemporaryDirectory(prefix="mrk-cli-source-") as tmp:
            root = Path(tmp)
            f = A.Fixtures(BINDING, os.getuid(), os.getgid(), C.SCOPE)
            try:
                (root / "mrk").write_bytes(b"INERT not executable native source")
                parent = f._open(tmp, directory=True)
                fd = f._open("mrk", parent)
                before = C._sig(os.fstat(fd))
                c = C.Fixture(f)
                c.cli_row = (parent, "mrk", fd, before, C._hash((root / "mrk").read_bytes()))
                f.recovery_runtime_originals = [(parent, "mrk", fd, before)]
                f._normal_runtime_post = lambda: None  # Protected Mac policy NOT under this test.
                c.current_cli()
                os.rename(root / "mrk", root / "held-original")
                (root / "mrk").write_bytes((root / "held-original").read_bytes())
                with self.assertRaisesRegex(ValueError, "cli-runtime-original-changed"): c.current_cli()
                with self.assertRaises(ValueError):
                    C.admit_installed(SimpleNamespace(cases=C.CASES, inflight=False, cli=C.Fixture(f)),
                        SimpleNamespace(INSTALL_ROOT=root, APP_NAME="app", INSTALLED_CLI="Contents/MacOS/mrk"), {}, {})
            finally: f.close()

    def test_closed_tool_scope_fixed_checks_and_noninvented_native_report(self):
        self.assertEqual(A.selected_cases(C.SCOPE), C.CASES)
        self.assertEqual(A.argument_scope(["--scope", C.SCOPE]), C.SCOPE)
        self.assertEqual(M.arguments(["--target", M.TARGET, "--scope", C.SCOPE]), C.SCOPE)
        self.assertEqual(M.observation_scope({"MRK_MACOS_NATIVE_SCOPE": M.TOOLS_SCOPE}, C.SCOPE), C.SCOPE)
        for scope in (M.GIT_SCOPE, M.FETCH_SCOPE, M.PUSH_SCOPE, M.SCOPE, "disabled", C.SCOPE):
            with self.subTest(scope=scope), self.assertRaises(M.Refused):
                M.observation_scope({"MRK_MACOS_NATIVE_SCOPE": scope}, C.SCOPE)
        files, dirs = A.fixture_data(C.SCOPE, False)
        self.assertEqual((files, dirs), A.local_check_fixture_data("local-saved-offline"))
        conf = json.loads(files["release/mobile-release.json"])
        self.assertEqual(conf["projectChecks"], {"preflight": [], "androidArtifact": [], "iosArtifact": []})
        self.assertIsNone(A.expected_result(BINDING, C.SCOPE)["installedCli"])
        for key, bad in (("hostWorkersJoined", 7), ("hostOriginalsClosed", False), ("consumedPermission", False),
                         ("liveInterruptionTested", True), ("applicationRestartTested", True), ("extra", "DATA")):
            with self.subTest(key=key), self.assertRaises(ValueError): C.report({**native_report(), key: bad})

    def test_actual_current_driver_one_case_waits_for_join_before_close_and_complete(self):
        with self.journey() as j:
            j.fixture.inflight, j.fixture.last_returned = False, True
            closed, emitted = [], []
            def close():
                self.assertFalse(j.fixture.inflight)
                self.assertTrue(j.cli.joined)
                self.assertFalse(j.cli.thread.is_alive())
                closed.append(True)
            j.fixture.close = close
            with patch.object(A, "Fixtures", return_value=j.fixture), \
                 patch.object(A, "load_owner", return_value=SimpleNamespace(run_owned=j.owner)), \
                 patch.object(A, "app_environment", return_value={"LANG": "C"}), \
                 patch.object(A, "emit_record", side_effect=lambda v, out: emitted.append(v)), \
                 patch.object(M, "_admit_runtime"), patch.object(M, "_current"):
                code = M._run(A, BINDING, os.getuid(), os.getgid(), "inert", j.root,
                              {"MRK_MACOS_NATIVE_SCOPE": M.TOOLS_SCOPE}, scope=C.SCOPE)
            self.assertEqual(code, 0, emitted)
            self.assertEqual(closed, [True])
            self.assertEqual(len(j.calls), 7)
            self.assertEqual(emitted[-1]["type"], "macos-installed-cli-current-complete")
            self.assertEqual(emitted[-1]["cases"], list(C.CASES))
            self.assertFalse(emitted[-1]["shippingBinaryQualified"])

    def test_actual_current_driver_does_not_close_or_emit_complete_after_unknown(self):
        with self.journey(thrown=1) as j:
            j.fixture.inflight, j.fixture.last_returned = False, True
            closed, emitted = [], []
            j.fixture.close = lambda: closed.append(True)
            with patch.object(A, "Fixtures", return_value=j.fixture), \
                 patch.object(A, "load_owner", return_value=SimpleNamespace(run_owned=j.owner)), \
                 patch.object(A, "app_environment", return_value={}), \
                 patch.object(A, "diagnostic", return_value={"inertDiagnostic": True}), \
                 patch.object(A, "emit_record", side_effect=lambda v, out: emitted.append(v)), \
                 patch.object(M, "_admit_runtime"), patch.object(M, "_current"):
                code = M._run(A, BINDING, os.getuid(), os.getgid(), "inert", j.root,
                              {"MRK_MACOS_NATIVE_SCOPE": M.TOOLS_SCOPE}, scope=C.SCOPE)
            self.assertEqual(code, 1)
            self.assertEqual(closed, [])
            self.assertEqual(emitted, [{"inertDiagnostic": True}])
            self.assertTrue(j.fixture.inflight)
            self.assertEqual(j.cli.calls.inflight, 1)


if __name__ == "__main__":
    unittest.main()
