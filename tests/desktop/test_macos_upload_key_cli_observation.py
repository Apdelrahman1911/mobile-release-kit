"""Fixed backup recipe with the EXISTING caller/thread and real phase files.

Every operation/reference/GUI/Host fact below is explicitly inert DATA. No
installed mrk, native panel, key generation, vault, service or process is run.
Popen/sockets are forbidden; this cannot qualify the shipping feature bit.
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
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("_backup_cli_existing_test", Path(__file__).with_name(
    "test_macos_cli_local_check_observation.py"))
L = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = L
spec.loader.exec_module(L)
A, C, M = L.A, L.C, L.M
B = C.BACKUP
PROJECT, INSTANCE = "2" * 32, "1" * 32
GRANTS = [f"{i:032x}" for i in (10, 11, 12)]
REQUESTS = [f"{i:032x}" for i in (20, 21, 22)]
KINDS = ["backup-encrypted", "restore-encrypted", "restore-encrypted"]
STATES = ["backup-delivered", "restored-unassigned", "cancelled"]
ORIGINALS = [6, 10, 13]
KEY = {"vaultId": "4" * 32, "generationId": "5" * 32, "recordId": "6" * 32,
       "revisionId": "7" * 32, "revisionCounter": 1}


def permission(i):
    return {"phase": B.NATIVE_PHASES[i * 2], "projectId": PROJECT,
            "serviceInstance": INSTANCE, "grantId": GRANTS[i]}


def status(i, *, terminal=False, stop=False):
    return {"schemaVersion": 1, "origin": {"projectId": PROJECT, "serviceInstance": INSTANCE,
            "requestId": REQUESTS[i]}, "grantId": GRANTS[i], "kind": KINDS[i],
            "state": STATES[i] if terminal else "stop-requested" if stop else "queued",
            "settlement": "settled" if terminal else "pending",
            "reason": "permission-revoked" if terminal and i == 2 or stop else "none",
            "assetOperationId": ORIGINALS[i] if terminal or stop else None,
            "key": KEY.copy() if terminal and i == 1 else None, "doNotReplay": True}


def marker(i):
    return {"phase": B.NATIVE_PHASES[6 if i == 2 else 2 * i + 1], "requestId": REQUESTS[i],
            "assetOperationId": ORIGINALS[i], "statusSha256": B.digest(status(i, terminal=True))}


def report():
    return {"schemaVersion": 1, "scope": B.SCOPE, "requests": REQUESTS.copy(),
            "statusSha256": [marker(i)["statusSha256"] for i in range(3)],
            "originalCount": 14, "openActions": 5, "pickerCalls": 6, "hostWorkersJoined": 10,
            **dict.fromkeys(("cancelledBeforeIo", "explicitBind", "allOriginalsSettled",
                            "sourceLockedBeforeRestore"), True),
            **dict.fromkeys(("shippingEnabled", "rendererInteractionTested", "restartTested"), False)}


class InertBackup(L.InertJourney):
    """Reuse existing test's borrowed files; change only the closed DATA recipe."""
    def __init__(self, root, *, change=None, thrown=None, settled_cancel=False, native_change=None):
        super().__init__(root, change=change, thrown=thrown)
        self.settled_cancel, self.native_change = settled_cancel, native_change
        uid, native_fd, driver_fd = os.getuid(), self.fds[1], self.fds[2]
        self.native_send = C.PhaseFile(self.parent, C.PHASES[0], native_fd, uid, True, case=B.SCOPE)
        self.driver_read = C.PhaseFile(self.parent, C.PHASES[1], driver_fd, uid, False, case=B.SCOPE)
        self.cli.native = C.PhaseFile(self.parent, C.PHASES[0], native_fd, uid, False, case=B.SCOPE)
        self.cli.driver = C.PhaseFile(self.parent, C.PHASES[1], driver_fd, uid, True, case=B.SCOPE)
        self.fixture.cases = B.CASES

    def append(self, value):
        self.native_send.append(self.native_change(copy.deepcopy(value)) if self.native_change else value)

    def app(self, argv, kw):
        self.app_calls += 1
        if threading.current_thread() is not threading.main_thread() or "cancellation" in kw or kw["timeout"] != 495:
            raise AssertionError("changed original app caller")
        self.append(permission(0))
        next_rows = [marker(0), permission(1), marker(1), permission(2),
                     {"phase": "second-entered", "requestId": REQUESTS[2], "assetOperationId": 13}, marker(2)]
        sent, until = 0, time.monotonic() + 3
        while time.monotonic() < until:
            if self.cli.calls.failed:
                break
            rows = self.driver_read.read()
            if rows is not None and len(rows) > sent:
                if len(rows) != sent + 1:
                    raise AssertionError("test DATA phase pacing")
                if sent == 6:
                    break
                self.append(next_rows[sent])
                sent += 1
            time.sleep(0.001)
        else:
            raise AssertionError("bounded inert app did not receive phase")
        value = {**A.expected_result(L.BINDING, B.SCOPE), "vaultHelper": report()}
        return subprocess.CompletedProcess(argv, 0, A.MARKER + C._json(value) + b"\n", b"")

    def owner(self, argv, **kw):
        if argv[0] != C.CLI:
            return self.app(argv, kw)
        n = len(self.calls)
        self.calls.append((argv.copy(), kw.copy()))
        self.threads.append(threading.get_ident())
        if threading.current_thread() is threading.main_thread() or kw.get("cancellation", "absent") is not None:
            raise AssertionError("CLI changed original thread cancellation")
        if kw["environ"].get("HOME") != str(self.cli.home) or not 1 <= kw["timeout"] <= 30:
            raise AssertionError("CLI changed original HOME/deadline")
        if self.thrown == n:
            raise RuntimeError("inert original did not return")
        i, code, err = min(n // 3, 2), 0, b""
        if n in (0, 3, 6):
            kind = "upload-key-access"
            value = {"schemaVersion": 1, "serviceInstance": INSTANCE, "projectId": PROJECT,
                     "grantId": GRANTS[i], "kind": KINDS[i], "requestId": None,
                     "enabled": True, "remainingMs": 250000, "consumed": False}
        else:
            kind = "upload-key-request"
            value = status(i, terminal=n in (2, 5, 9) or n == 8 and self.settled_cancel,
                           stop=n == 8 and not self.settled_cancel)
            if n in (1, 4, 7):
                err = B.receipt(permission(i), REQUESTS[i])
            code = 5 if n == 9 or n == 8 and self.settled_cancel else 0
        envelope = {"version": 1, "requestId": f"{100 + n:032x}", "clientId": f"{200 + n:032x}",
                    "sessionId": f"{300 + n:032x}", "serviceInstance": INSTANCE,
                    "response": {"kind": kind, "value": value}}
        r = subprocess.CompletedProcess(argv, code, C._json(envelope) + b"\n", err)
        return self.change(n, r) if self.change else r


class UploadBackupCliTests(unittest.TestCase):
    def setUp(self):
        for name in ("subprocess.Popen", "socket.socket", "socket.create_connection"):
            self.enterContext(patch(name, side_effect=AssertionError("process/network/native forbidden")))

    @contextmanager
    def journey(self, **kwargs):
        with tempfile.TemporaryDirectory(prefix="mrk-backup-cli-inert-") as tmp:
            j = InertBackup(Path(tmp), **kwargs)
            try:
                yield j
            finally:
                j.close_files()

    def invoke(self, j):
        return C.invoke(j.fixture, j.owner, [A.EXECUTABLE, B.SCOPE], {"LANG": "C"}, j.root)

    def test_same_caller_ten_returns_three_submits_and_real_thread_join(self):
        with self.journey() as j:
            actual = self.invoke(j)
            self.assertEqual([a[1] for a, _ in j.calls], ["upload-key-scope", "upload-key-submit", "upload-key-status"] * 2
                             + ["upload-key-scope", "upload-key-submit", "upload-key-cancel", "upload-key-status"])
            self.assertEqual([r["phase"] for r in j.driver_read.read()], list(B.DRIVER_PHASES))
            self.assertEqual(len(set(j.threads)), 1)
            self.assertNotEqual(j.threads[0], threading.get_ident())
            self.assertTrue(j.cli.joined and j.cli.calls.returned)
            self.assertFalse(j.cli.thread.is_alive())
            self.assertEqual(j.cli.calls.next, 10)
            self.assertEqual(len(j.cli.calls.results), 10)
            self.assertEqual(j.app_calls, 1)
            self.assertTrue(j.fixture.inflight)  # Only actual run_cases may release it.
            parsed = A.parse_result(actual.stdout, actual.stderr, L.BINDING, B.SCOPE)
            self.assertEqual(parsed["vaultHelper"], report())
            with self.assertRaisesRegex(ValueError, "originals-not-returned"):
                B.readback(j.fixture, report())
            j.fixture.inflight, j.fixture.last_returned = False, True
            self.assertEqual(C.readback(j.fixture, report())["cliProcessesReturned"], 10)

    def test_cancel_ack_may_be_pending_but_only_later_exact_terminal_completes(self):
        for settled in (False, True):
            with self.subTest(settled=settled), self.journey(settled_cancel=settled) as j:
                self.invoke(j)
                self.assertEqual(j.cli.calls.results[8].returncode, 5 if settled else 0)
                self.assertEqual(j.cli.calls.results[9].returncode, 5)
                self.assertEqual(j.driver_read.read()[-1]["phase"], "done")

    def test_changed_grant_reference_or_terminal_unknown_cannot_advance(self):
        for n, field in ((0, "grant"), (4, "origin"), (5, "key"), (8, "unknown"), (9, "unknown")):
            def change(number, r):
                if number != n:
                    return r
                v = C._decode(r.stdout)
                row = v["response"]["value"]
                if field == "grant": row["grantId"] = "f" * 32
                if field == "origin": row["origin"]["projectId"] = "e" * 32
                if field == "key": row["key"]["recordId"] = "d" * 32
                if field == "unknown": row.update(state="admission-unknown", settlement="unknown")
                return subprocess.CompletedProcess(r.args, r.returncode, C._json(v), r.stderr)
            with self.subTest(n=n, field=field), self.journey(change=change) as j:
                with self.assertRaisesRegex(ValueError, "cli-thread-originals-not-returned"):
                    self.invoke(j)
                self.assertEqual(len(j.calls), n + 1)
                self.assertTrue(j.cli.calls.failed and j.cli.joined and j.fixture.inflight)
                self.assertFalse(j.cli.calls.returned)

    def test_cancel_receipt_exit_or_original_cannot_be_substituted(self):
        for n, field in ((1, "receipt"), (8, "wrong-original"), (9, "exit-zero"), (9, "extra")):
            def change(number, r):
                if number != n: return r
                v = C._decode(r.stdout)
                if field == "wrong-original": v["response"]["value"]["assetOperationId"] = 10
                if field == "extra": v["response"]["value"]["privatePath"] = "forbidden"
                return subprocess.CompletedProcess(r.args, 0 if field == "exit-zero" else r.returncode,
                    C._json(v), b"wrong original\n" if field == "receipt" else r.stderr)
            with self.subTest(field=field), self.journey(change=change) as j:
                with self.assertRaises(ValueError): self.invoke(j)
                self.assertEqual(len(j.calls), n + 1)
                self.assertFalse(j.cli.calls.returned)

    def test_missing_cancel_original_keeps_claim_and_fixture_inflight(self):
        with self.journey(thrown=8) as j:
            with self.assertRaises(ValueError): self.invoke(j)
            self.assertEqual((j.cli.calls.inflight, j.cli.calls.next), (8, 8))
            self.assertTrue(j.cli.calls.failed and j.cli.joined and j.fixture.inflight)
            self.assertFalse(j.cli.calls.returned)
            self.assertEqual(j.driver_read.read()[-1]["phase"], "cancel-submitted")
            self.assertEqual(len(j.calls), 9)

    def test_second_entry_and_native_digest_are_comparison_only_required_data(self):
        for target in ("second-entered", "restore-terminal"):
            def change(v):
                if v["phase"] == target:
                    if target == "second-entered": v["assetOperationId"] = 10
                    else: v["statusSha256"] = "e" * 64
                return v
            with self.subTest(target=target), self.journey(native_change=change) as j:
                with self.assertRaises(ValueError): self.invoke(j)
                self.assertEqual(len(j.calls), 8 if target == "second-entered" else 6)
                self.assertTrue(j.fixture.inflight)
                self.assertFalse(j.cli.calls.returned)

    def test_fixed_policy_case_clock_no_new_deadline_after_each_call(self):
        now = [10.0]
        c = C.Calls(clock=lambda: now[0], case=B.SCOPE)
        self.assertEqual((c.count, c.rows, c.success_end, c.hard_end), (10, 7, 490, 508))
        now[0] = 470
        self.assertEqual(c.claim(0), 20)
        c.returned_call(0, object())
        now[0] = 489.1
        with self.assertRaises(ValueError): c.claim(1)
        self.assertEqual((c.success_end, c.hard_end), (490, 508))
        self.assertEqual(C._policy(C.SCOPE), (7, 4, 120, 135))
        self.assertFalse(C.selected((B.SCOPE, C.SCOPE)))
        with self.assertRaises(ValueError): C.Calls(case="generic-backup")

    def test_phase_file_still_bounded_and_returned_host_facts_never_inferred(self):
        with self.journey() as j:
            for i in range(7): j.native_send.append({"phase": str(i)})
            with self.assertRaises(ValueError): j.native_send.append({"phase": "extra"})
        for field, replacement in (("hostWorkersJoined", 9), ("openActions", 6), ("pickerCalls", 5),
                ("cancelledBeforeIo", False), ("allOriginalsSettled", False), ("shippingEnabled", True),
                ("restartTested", True), ("rendererInteractionTested", True)):
            v = report(); v[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError): B.report(v)
        v = report(); v["path"] = "not public"
        with self.assertRaises(ValueError): B.report(v)

    def test_short_home_and_root_selection_use_exact_closed_case(self):
        a = C.short_home(L.BINDING, "/Users/runner", case=B.SCOPE)
        self.assertNotEqual(a, C.short_home(L.BINDING, "/Users/runner"))
        self.assertLess(len(os.fsencode(a / "Library/Application Support" / C.APPLICATION / "service-v1/s")), 104)
        self.assertEqual(A.argument_scope(["--scope", B.SCOPE]), B.SCOPE)
        self.assertEqual(A.selected_cases(B.SCOPE), B.CASES)
        self.assertEqual(A.case_timeout(B.SCOPE), 495)
        with self.assertRaises(A.Refused): A.argument_scope(["--scope", A.BACKUP.SCOPE])
        self.assertEqual(M.arguments(["--target", "aarch64-apple-darwin", "--scope", B.SCOPE]),
                         B.SCOPE)


if __name__ == "__main__":
    unittest.main()
