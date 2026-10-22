"""DATA-only Git recipes through the original Calls/thread/phase-file driver.

No Git, mrk, native grant/receipt, service, provider or child process exists in
these tests. Reuse the existing fixture's retained real phase FDs and join;
only its fixed public response/phase DATA differ. Full native Git2 is UNRUN.
"""
from contextlib import contextmanager, ExitStack, redirect_stdout, redirect_stderr
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

spec = importlib.util.spec_from_file_location("git_cli_existing_inert_fixture", Path(__file__).with_name("test_macos_cli_local_check_observation.py"))
base = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = base
spec.loader.exec_module(base)
A, C, M, BINDING, ORIGIN = base.A, base.C, base.M, base.BINDING, base.ORIGIN
G = C.GIT_CLI
GRANT, HEAD = "4" * 32, "c" * 40


def allowed():
    return {"phase": "allowed", "projectId": ORIGIN["projectId"], "grantId": GRANT,
            "repositoryRevision": "a" * 64, "referenceRevision": "b" * 64, "selectionSha256": "c" * 64}


def selection(case):
    if case == G.INDEX:
        return {"summary": {"action": "stage", "repositoryRevision": "a" * 64,
                            "pathCount": 1, "selectionSha256": "c" * 64}, "paths": ["untracked.txt"]}
    return {"action": {"kind": "branch-create", "expectedRevision": "a" * 64,
                       "expectedReferenceRevision": "b" * 64, "name": "observer-local"}, "selectionSha256": "c" * 64}


def status(case, terminal=False):
    chosen = selection(case)
    return {"origin": ORIGIN.copy(), "grantId": GRANT,
            "selection": chosen["summary"] if case == G.INDEX else chosen,
            "revision": 5 if terminal else 3, "state": "finished" if terminal else "prepared",
            "prepareOperationId": "git-local-1", "applyOperationId": "git-local-2" if terminal else None,
            "review": None if terminal else {"reviewId": "git-review-1", "expectedIndex": "d" * 64,
                "reviewDigest": "e" * 64, "documentRevision": 1, "registrationGeneration": 1},
            "outcome": "succeeded" if terminal else None, "settlement": "settled" if terminal else "pending",
            "reason": None, "historyAvailable": True, "doNotReplay": True}


def phases(case):
    return [allowed(), {"phase": "prepared", "prepareOperationId": "git-local-1", "reviewId": "git-review-1",
            "reviewDigest": "e" * 64, "statusSha256": G.digest(status(case))},
            {"phase": "terminal", "applyOperationId": "git-local-2", "statusSha256": G.digest(status(case, True))},
            *([{"phase": "revoked"}, {"phase": "reallowed"}] if case == G.INDEX else [])]


def native_report(case):
    return {"mechanism": "same-original-local-git-cli-v1", "case": case, "origin": ORIGIN.copy(),
            "prepareOperationId": "git-local-1", "reviewId": "git-review-1", "applyOperationId": "git-local-2",
            "statusSha256": G.digest(status(case, True)), "readOriginalsJoined": 2, "prepareOriginalsJoined": 1,
            "applyOriginalsJoined": 1, "hostWorkersJoined": G.policy(case)[0], "normalQuitOriginal": 2,
            "allOriginalsSettled": True, "phaseOriginalsClosed": True, "projectDeltaCompared": True,
            "emptyRevokeRefused": case == G.INDEX, "lateStopOnly": case == G.INDEX, "readReallowedOnly": case == G.INDEX,
            "networkRequested": False, "bootstrapOverride": False, "productionQualified": False}


def response(case, number):
    prefix = "git-index" if case == G.INDEX else "git-repository"
    if number == 0:
        kind, value = prefix + "-scope", {"serviceInstance": ORIGIN["serviceInstance"], "projectId": ORIGIN["projectId"],
            "access": {"enabled": True, "remainingMs": 60000, "consumed": False, "projectId": ORIGIN["projectId"],
                       "grantId": GRANT, "selection": selection(case)}}
    else:
        kind, value = prefix + "-request", status(case, number >= 4)
        if number == 1:
            value.update(state="queued", prepareOperationId=None, review=None, historyAvailable=False)
        if number == 3:
            value.update(state="start-queued", review=None, historyAvailable=False)
    return {"version": 1, "requestId": f"{number + 100:032x}", "serviceInstance": ORIGIN["serviceInstance"],
            "clientId": f"{number + 200:032x}", "sessionId": f"{number + 300:032x}", "response": {"kind": kind, "value": value}}


class GitJourney(base.InertJourney):
    """Extend only the existing test fixture's DATA recipe; no native owner."""
    def __init__(self, root, case, **kwargs):
        super().__init__(root, **kwargs)
        self.case = case
        self.fixture.cases = (case,)
        # Simulate time already spent on fixed setup, not a fresh caller clock.
        self.fixture.git_cli = {"caseEnd": time.monotonic() + 110.0}
        self.native_send = C.PhaseFile(self.parent, C.PHASES[0], self.fds[1], os.getuid(), True, case=case)
        self.driver_read = C.PhaseFile(self.parent, C.PHASES[1], self.fds[2], os.getuid(), False, case=case)
        self.cli.native = C.PhaseFile(self.parent, C.PHASES[0], self.fds[1], os.getuid(), False, case=case)
        self.cli.driver = C.PhaseFile(self.parent, C.PHASES[1], self.fds[2], os.getuid(), True, case=case)

    def app(self, argv, kw):
        self.app_calls += 1
        if threading.current_thread() is not threading.main_thread() or "cancellation" in kw:
            raise AssertionError("app must retain its original main-thread guard")
        if not 120 <= kw["timeout"] <= 125 or argv != [A.EXECUTABLE, self.case]:
            raise AssertionError("pre-setup original endpoint was renewed")
        native = phases(self.case)
        self.native_send.append(native[0])
        sent, until = 0, time.monotonic() + 2
        while time.monotonic() < until:
            if self.cli.calls.failed:
                break
            rows = self.driver_read.read()
            if rows is not None and len(rows) > sent:
                if len(rows) != sent + 1:
                    raise AssertionError("inert phase pacing")
                if sent + 1 == len(native):
                    break
                self.native_send.append(native[sent + 1])
                sent += 1
            time.sleep(0.001)
        else:
            raise AssertionError("bounded inert Git phase did not return")
        value = {**A.expected_result(BINDING, self.case), "gitCli": native_report(self.case)}
        return subprocess.CompletedProcess(argv, 0, A.MARKER + C._json(value) + b"\n", b"")

    def owner(self, argv, **kw):
        if argv[0] != C.CLI:
            return self.app(argv, kw)
        number = len(self.calls)
        self.calls.append((argv.copy(), kw.copy()))
        self.threads.append(threading.get_ident())
        if threading.current_thread() is threading.main_thread() or kw.get("cancellation", "absent") is not None:
            raise AssertionError("CLI used the main guard")
        if not 1 <= kw["timeout"] <= 30 or kw["environ"].get("HOME") != str(self.cli.home):
            raise AssertionError("original CLI timeout/home changed")
        if self.thrown == number:
            raise RuntimeError("inert original did not return")
        if self.case == G.INDEX and number == 6:
            r = subprocess.CompletedProcess(argv, 4, C._json({"version": 1, "ok": False,
                "error": "access_denied", "message": "Inert original READ revoked."}) + b"\n", b"")
        else:
            r = subprocess.CompletedProcess(argv, 0, C._json(response(self.case, number)) + b"\n", b"")
        return self.change(number, r) if self.change else r


class GitCliTests(unittest.TestCase):
    def setUp(self):
        for name in ("subprocess.Popen", "socket.socket", "socket.create_connection"):
            self.enterContext(patch(name, side_effect=AssertionError("process/network forbidden")))

    @contextmanager
    def journey(self, case=G.INDEX, **kwargs):
        with tempfile.TemporaryDirectory(prefix="mrk-git-cli-data-") as tmp:
            j = GitJourney(Path(tmp), case, **kwargs)
            try:
                yield j
            finally:
                j.close_files()

    def invoke(self, j):
        return C.invoke(j.fixture, j.owner, [A.EXECUTABLE, j.case], {"LANG": "C"}, j.root)

    def test_both_actual_recipes_keep_one_prepare_start_original_thread_and_eight_or_five_calls(self):
        for case in G.CASES:
            with self.subTest(case=case), self.journey(case) as j:
                result = self.invoke(j)
                value = A.parse_result(result.stdout, result.stderr, BINDING, case)
                self.assertEqual(value["gitCli"], native_report(case))
                prefix = "git-index" if case == G.INDEX else "git-repository"
                verbs = ["scope", "prepare", "status", "start", "status"] + (["cancel", "scope", "status"] if case == G.INDEX else [])
                self.assertEqual([argv[1] for argv, _ in j.calls], [prefix + "-" + v for v in verbs])
                self.assertEqual(len(j.calls), G.policy(case)[0])
                self.assertEqual(len(set(j.threads)), 1)
                self.assertNotEqual(j.threads[0], threading.get_ident())
                self.assertTrue(j.cli.calls.returned and j.cli.joined and j.fixture.inflight)
                self.assertFalse(j.cli.thread.is_alive())
                self.assertEqual(j.driver_read.read()[-1], {"phase": "done", "origin": ORIGIN,
                    "statusSha256": native_report(case)["statusSha256"]})
                self.assertEqual(j.app_calls, 1)

    def test_original_read_prepare_apply_history_and_instance_mismatch_never_replays(self):
        for number, field in ((0, "selection"), (1, "origin"), (2, "historyAvailable"), (2, "review"),
                              (3, "prepareOperationId"), (4, "applyOperationId"), (7, "instance")):
            def change(n, r):
                if n != number:
                    return r
                v = C._decode(r.stdout); row = v["response"]["value"]
                if field == "selection": row["access"]["selection"]["paths"] = ["other.txt"]
                elif field == "origin": row["origin"]["projectId"] = "f" * 32
                elif field == "review": row["review"]["reviewDigest"] = "f" * 64
                elif field == "instance": v["serviceInstance"] = "f" * 32
                else: row[field] = False if field == "historyAvailable" else "foreign-original"
                return subprocess.CompletedProcess(r.args, r.returncode, C._json(v), r.stderr)
            with self.subTest(field=field), self.journey(change=change) as j:
                with self.assertRaises(ValueError): self.invoke(j)
                self.assertEqual(len(j.calls), number + 1)
                self.assertTrue(j.fixture.inflight and j.cli.joined and j.cli.calls.failed)
                self.assertFalse(j.cli.calls.returned)

    def test_unknown_or_fake_denial_is_not_finished_and_join_loss_keeps_original(self):
        for number, code in ((4, 6), (6, 0), (6, 6)):
            def change(n, r):
                return subprocess.CompletedProcess(r.args, code, r.stdout, r.stderr) if n == number else r
            with self.subTest(number=number, code=code), self.journey(change=change) as j:
                with self.assertRaises(ValueError): self.invoke(j)
                self.assertEqual(len(j.calls), number + 1)
                self.assertTrue(j.fixture.inflight and j.cli.calls.failed and j.cli.joined)
        for case in G.CASES:
            with self.subTest(case=case), self.journey(case, thrown=3) as j:
                with self.assertRaises(ValueError): self.invoke(j)
                self.assertEqual((j.cli.calls.inflight, j.cli.calls.next), (3, 3))
                self.assertTrue(j.fixture.inflight and j.cli.joined)
                self.assertFalse(j.cli.calls.returned)

    def test_git_phase_limits_and_original_replacement_are_not_new_authority(self):
        for case in G.CASES:
            with self.subTest(case=case), self.journey(case) as j:
                for row in phases(case): j.native_send.append(row)
                self.assertEqual(len(j.cli.native.read()), G.policy(case)[1])
                with self.assertRaises(ValueError): j.native_send.append({"phase": "again"})
            with self.journey(case) as j:
                os.pwrite(j.fds[1], C._json({"phase": "allowed", "unbounded": "x" * 513}) + b"\n", 0)
                with patch.object(C, "_decode", side_effect=AssertionError("oversized row parsed")), self.assertRaises(ValueError):
                    j.cli.native.read()
            with self.journey(case) as j:
                os.rename(j.root / C.PHASES[0], j.root / "held-old")
                (j.root / C.PHASES[0]).write_bytes(b"")
                with self.assertRaises(ValueError): j.cli.native.read()

    def test_native_report_never_invents_other_case_join_count_or_qualification(self):
        for case in G.CASES:
            expected = native_report(case)
            self.assertEqual(G.report(expected, case), expected)
            self.assertEqual(A.fixture_data(case, False), G.fixture_data(A.CONFIG, A.VERSION, A.KEEP, A.IGNORE_PREFIX, A.SOURCE))
            for key, wrong in (("hostWorkersJoined", 5 if case == G.INDEX else 8), ("readOriginalsJoined", True),
                               ("normalQuitOriginal", 3), ("productionQualified", True), ("lateStopOnly", case != G.INDEX)):
                bad = {**expected, key: wrong}
                with self.subTest(case=case, key=key), self.assertRaises(ValueError): G.report(bad, case)
            with self.assertRaises((A.Refused, ValueError)):
                A.parse_result(A.MARKER + C._json(A.expected_result(BINDING, case)) + b"\n", b"", BINDING, case)

    @contextmanager
    def tree(self, case):
        """Real private files containing inert bytes, NOT a valid Git repo."""
        with tempfile.TemporaryDirectory(prefix="mrk-git-cli-tree-") as tmp:
            root = Path(tmp)
            for name in ("app", "release", ".git", ".git/objects", ".git/objects/info", ".git/objects/pack",
                         ".git/refs", ".git/refs/heads", ".git/logs", ".git/logs/refs", ".git/logs/refs/heads"):
                (root / name).mkdir(mode=0o700)
            files, _ = G.fixture_data(A.CONFIG, A.VERSION, A.KEEP, A.IGNORE_PREFIX, A.SOURCE)
            for name, data in {**files, ".git/config": G.upstream.CONFIG, ".git/HEAD": b"ref: refs/heads/main\n",
                    ".git/refs/heads/main": (HEAD + "\n").encode(), ".git/index": b"INERT original index",
                    ".git/logs/HEAD": b"INERT original log", ".git/logs/refs/heads/main": b"INERT original log"}.items():
                (root / name).write_bytes(data); (root / name).chmod(0o600)
            f = A.Fixtures(BINDING, os.getuid(), os.getgid(), G.scope(case))
            try:
                f.projects[case] = f._open(str(root), directory=True)
                before = G.capture(f)
                yield f, root, before
            finally:
                f.close()
                self.assertFalse(f.fds)

    def mutate(self, root, case):
        # The original Branch transaction also creates/removes .git locks.
        (root / ".git/config.lock").write_bytes(b"INERT temporary owned lock")
        (root / ".git/config.lock").unlink()
        if case == G.INDEX:
            replacement = root / ".git/index.lock"
            replacement.write_bytes(b"INERT replacement index"); replacement.chmod(0o600)
            replacement.replace(root / ".git/index")
            parent = root / ".git/objects" / G.BLOB[:2]; parent.mkdir(mode=0o700)
            (parent / G.BLOB[2:]).write_bytes(zlib.compress(b"blob " + str(len(G.UNTRACKED)).encode() + b"\0" + G.UNTRACKED))
            (parent / G.BLOB[2:]).chmod(0o444)
        else:
            (root / ".git" / G.BRANCH_REF).write_bytes((HEAD + "\n").encode())
            (root / ".git/logs" / G.BRANCH_REF).write_bytes(("0" * 40 + " " + HEAD
                + " MRK Upstream Fixture <upstream-fixture@example.invalid> 1700000000 +0000\tMRK: create reviewed branch\n").encode())
            for name in (G.BRANCH_REF, "logs/" + G.BRANCH_REF): (root / ".git" / name).chmod(0o600)

    def test_real_file_reader_compares_only_stage_blob_or_absent_branch_delta(self):
        for case in G.CASES:
            with self.subTest(case=case), self.tree(case) as (f, root, before):
                self.mutate(root, case)
                after = G.capture(f)
                for path in after["git"].keys() - before["git"].keys():
                    self.assertEqual(after["git"][path][1][0], before["git"]["."][1][0], path)
                    self.assertEqual(after["git"][path][1][3:5], before["git"]["."][1][3:5], path)
                self.assertTrue(G.compare(before, after, case, HEAD))
                self.assertEqual(before["files"], after["files"])
                for path in ("HEAD", "config", "refs/heads/main", "logs/HEAD"):
                    wrong = copy.deepcopy(after)
                    row = wrong["git"][path]
                    wrong["git"][path] = (*row[:2], "f" * 64, row[3])
                    with self.subTest(path=path), self.assertRaises(ValueError): G.compare(before, wrong, case, HEAD)
                wrong = copy.deepcopy(after)
                row = wrong["git"]["."]
                identity = list(row[1]); identity[1] += 100
                wrong["git"]["."] = (row[0], tuple(identity), row[2])
                with self.assertRaises(ValueError): G.compare(before, wrong, case, HEAD)

    def test_wrong_blob_append_and_foreign_or_preexisting_branch_never_count_as_applied(self):
        for case in G.CASES:
            with self.subTest(case=case), self.tree(case) as (f, root, before):
                self.mutate(root, case); after = G.capture(f)
                path = "objects/" + G.BLOB[:2] + "/" + G.BLOB[2:] if case == G.INDEX else G.BRANCH_REF
                row = after["git"][path]
                for raw in (b"foreign", row[3] + b"extra"):
                    wrong = copy.deepcopy(after); wrong["git"][path] = (*row[:3], raw)
                    with self.assertRaises(ValueError): G.compare(before, wrong, case, HEAD)
                old = copy.deepcopy(before); old["git"][path] = row
                with self.assertRaises(ValueError): G.compare(old, after, case, HEAD)
                (root / ".git/refs/heads/foreign").write_bytes((HEAD + "\n").encode())
                with self.assertRaises(ValueError): G.capture(f)

    def test_postjoin_readback_requires_all_call_returns_and_exact_phase_originals(self):
        with self.journey() as j:
            self.invoke(j)
            f = j.fixture; report = native_report(j.case)
            f._namespace = lambda: None
            f.git_cli.update(entered=True, completed=False, before={"inert": True}, head=HEAD,
                end=time.monotonic()+600.0, version="INERT build DATA", tool=(None,None,None,"d"*64), calls=5)
            f.inflight, f.last_returned = False, True
            with patch.object(G, "tool_current"), patch.object(G, "capture", return_value={"inert": True}), patch.object(G, "compare", return_value=True) as compared:
                for obj, name, bad in ((f, "inflight", True), (f, "close_errors", 1), (j.cli, "joined", False),
                                      (j.cli.calls, "returned", False), (j.cli.calls, "inflight", 7)):
                    old = getattr(obj, name); setattr(obj, name, bad)
                    with self.subTest(name=name), self.assertRaises(ValueError): G.readback(f, report)
                    setattr(obj, name, old)
                compared.assert_not_called()
                result = G.readback(f, report)
                self.assertEqual((result["cliProcessesReturned"],result["ipcWorkersActuallyJoined"]),(8,8))
                self.assertFalse(result["nativeAuthority"] or result["privateEndpointCopied"])
                with self.assertRaises(ValueError): G.readback(f, report)

    def test_current_original_run_cases_selects_existing_cli_and_no_close_after_lost_call(self):
        for case in G.CASES:
            for lost in (False,True):
                with self.subTest(case=case, lost=lost), self.journey(case) as j, ExitStack() as stack:
                    f = j.fixture; f.inflight = False; f.last_returned = False
                    f.prepare = lambda: None
                    f.before_call = lambda c: (setattr(f,"case",c), C.before_call(f))
                    events=[]; f.close=lambda: events.append("close")
                    if lost: j.thrown=3
                    stack.enter_context(patch.object(A,"Fixtures",return_value=f))
                    stack.enter_context(patch.object(A,"load_owner",return_value=SimpleNamespace(run_owned=j.owner)))
                    stack.enter_context(patch.object(M,"_admit_runtime",side_effect=lambda *a:events.append("admit")))
                    stack.enter_context(patch.object(M,"_current",side_effect=lambda *a:events.append("current")))
                    stack.enter_context(patch.object(G,"before_invocation",side_effect=lambda *a:events.append("inert-setup")))
                    stack.enter_context(patch.object(G,"remaining",return_value=10))
                    def readback(*args):
                        self.assertFalse(f.inflight); self.assertTrue(f.last_returned and j.cli.joined)
                        events.append("readback"); return {"inert":True}
                    stack.enter_context(patch.object(C,"readback",side_effect=readback))
                    stdout, stderr=io.StringIO(),io.StringIO()
                    with redirect_stdout(stdout),redirect_stderr(stderr):
                        code=M._run(A,BINDING,os.getuid(),os.getgid(),"inert",j.root,
                            {"MRK_MACOS_NATIVE_SCOPE":M.GIT_SCOPE},scope=G.scope(case))
                    if lost:
                        self.assertEqual(code,1); self.assertTrue(f.inflight)
                        self.assertNotIn("readback",events);self.assertNotIn("close",events)
                        self.assertEqual(stdout.getvalue(),"")
                    else:
                        self.assertEqual(code,0,stderr.getvalue()); self.assertLess(events.index("readback"),events.index("close"))
                        records=[json.loads(s) for s in stdout.getvalue().splitlines()]
                        self.assertEqual(records[-1]["type"],"macos-git-cli-current-complete")
                        self.assertEqual(records[-1]["cases"],[case])
                        self.assertFalse(records[-1]["shippingBinaryQualified"])


if __name__ == "__main__":
    unittest.main()
