"""Inert DATA/routing tests, not stock Git, a Mac owner or native qualification.

Run on the composed source graph. Popen and sockets are forbidden. The original
run_cases orchestration is exercised with explicitly inert precursor, producer,
report and readback. No fake report is submitted to a native owner.
"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).absolute().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


Q = load("_fetch_qualification_test", "desktop/tools/macos_git_fetch_qualification.py")
D = load("_fetch_qualification_data_test", "src/mobile_release/_git_fetch_observation_data.py")
A = load("_fetch_qualification_aqua_test", "desktop/tools/macos_aqua_qualification.py")
M = load("_fetch_qualification_current_test", "desktop/tools/macos_identity_current_runtime.py")
S = load("_fetch_qualification_stage_test", "desktop/tools/stage_macos_installed.py")
P = load("_fetch_qualification_preparer_test", "desktop/tools/prepare_runtime.py")
BINDING = A.Binding("a" * 40, "123", "1")


def pack():
    # Deliberately opaque/non-Git object DATA. Actual setup must use stock Git.
    raw = b"PACK\0\0\0\2\0\0\0\1opaque-inert-object"
    return raw + hashlib.sha1(raw, usedforsecurity=False).digest()


def report(case):
    return dict(mechanism="same-original-git-fetch-v1", case=case,
        syntheticProviderBytes=True, connectionOriginalJoined=True, readOriginalJoined=True,
        prepareOriginalJoined=True, applyOriginalJoined=True, connectionRetired=True,
        publication=case == Q.CASES[0], helperReturnedBeforeAllCopyEof=case == Q.CASES[3],
        producerPendingBeforeStop=case == Q.CASES[3], sameTicketStop=case == Q.CASES[3],
        toolSha256="b" * 64, normalQuitOriginal=2, allOriginalsSettled=True,
        worktreePreserved=True, shippingNominationEnabled=False, tlsQualified=False,
        liveAccountQualified=False, productionQualified=False)


class Inert(unittest.TestCase):
    def setUp(self):
        for name in ("subprocess.Popen", "socket.socket", "socket.create_connection"):
            p = patch(name, side_effect=AssertionError("actual process/network forbidden"))
            p.start(); self.addCleanup(p.stop)


class DataAndClockTests(Inert):
    def test_setup_transcript_is_byte_identical_to_actual_private_supplier_schema(self):
        self.assertEqual(Q.CASES, D.CASES)
        for case in Q.CASES:
            expected = D.Transcript(case, "a" * 40, "b" * 40, pack())
            raw = Q._transcript(case, expected.base, expected.target, expected.pack)
            self.assertEqual(raw, expected.raw())
            self.assertEqual(D.decode(raw, case), expected)
        for base, target in (("0" * 40, "b" * 40), ("a" * 40, "0" * 40), ("a" * 40, "a" * 40)):
            with self.assertRaises(ValueError): Q._transcript(Q.CASES[0], base, target, pack())
        with self.assertRaises(ValueError): Q._transcript(Q.CASES[0], "a" * 40, "b" * 40, pack()[:-1] + bytes([pack()[-1] ^ 1]))

    def test_report_requires_independent_originals_and_never_promotes_qualification(self):
        for case in Q.CASES:
            value = report(case)
            self.assertIs(Q.report(value, case, Q._need), value)
            for key in ("connectionOriginalJoined", "prepareOriginalJoined", "applyOriginalJoined", "allOriginalsSettled"):
                with self.subTest(case=case, key=key), self.assertRaises(ValueError):
                    Q.report({**value, key: False}, case, Q._need)
            for key in ("shippingNominationEnabled", "tlsQualified", "liveAccountQualified", "productionQualified"):
                with self.subTest(case=case, key=key), self.assertRaises(ValueError):
                    Q.report({**value, key: True}, case, Q._need)
            with self.assertRaises(ValueError): Q.report({**value, "extra": True}, case, Q._need)
        for key in ("helperReturnedBeforeAllCopyEof", "producerPendingBeforeStop", "sameTicketStop"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                Q.report({**report(Q.CASES[3]), key: False}, Q.CASES[3], Q._need)

    def test_remaining_uses_both_original_ends_without_rounding_up_or_reset(self):
        f = SimpleNamespace(fetch_cases={Q.CASES[0]: {"end": 120.9}}, fetch_end=115.5, close_errors=0)
        with patch.object(Q.time, "monotonic", return_value=100.0):
            self.assertEqual(Q.remaining(f, Q.CASES[0]), 15)
        with patch.object(Q.time, "monotonic", return_value=115.0):
            with self.assertRaisesRegex(ValueError, "deadline"): Q.remaining(f, Q.CASES[0])
        f.close_errors = 1
        with patch.object(Q.time, "monotonic", return_value=100.0):
            with self.assertRaises(ValueError): Q.remaining(f, Q.CASES[0])
        self.assertEqual((f.fetch_end, f.fetch_cases[Q.CASES[0]]["end"]), (115.5, 120.9))

    def test_suite_clock_is_latched_before_native_user_callback_and_not_restarted(self):
        f = SimpleNamespace(cases=Q.CASES, path=None, fetch_ancestors=[], inflight=False,
                            fetch_end=None, uid=501, gid=20)
        failure = OSError("inert user lookup")
        with patch.object(Q.time, "monotonic", return_value=100.0), patch("pwd.getpwuid", side_effect=failure) as call:
            with self.assertRaises(OSError) as caught: Q.prepare_namespace(f)
            self.assertIs(caught.exception, failure)
            self.assertEqual(f.fetch_end, 700.0)
            with self.assertRaisesRegex(ValueError, "original-suite-clock"): Q.prepare_namespace(f)
            self.assertEqual(call.call_count, 1)

    def test_retired_parent_route_refuses_before_any_stat_or_equal_metadata(self):
        f = SimpleNamespace(fds=set())
        with patch.object(Q.os, "fstat") as held, patch.object(Q.os, "stat") as named:
            with self.assertRaises(ValueError): Q._parents_current(f, [(None, "/", 31, (1, 2, 3, 4, 5))])
        held.assert_not_called(); named.assert_not_called()

    def test_setup_uses_only_private_environment_and_no_protocols(self):
        f = SimpleNamespace(path=Path("/inert/fixture"))
        with patch.dict(os.environ, {"GH_TOKEN": "INERT-NOT-A-CREDENTIAL", "GIT_CONFIG_COUNT": "1", "HTTPS_PROXY": "invalid"}, clear=True):
            e = Q._environment(f, Q.CASES[0], "runner", Path("/inert/empty"))
        self.assertFalse({"GH_TOKEN", "GIT_CONFIG_COUNT", "HTTPS_PROXY"} & e.keys())
        self.assertEqual(e["GIT_ALLOW_PROTOCOL"], "none")
        self.assertEqual(e["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(e["HOME"], "/inert/fixture/state/git-fetch-pack/home")
        self.assertEqual(e["GIT_AUTHOR_NAME"], "MRK Fetch Fixture")

    def test_setup_owner_return_and_unknown_cannot_be_retried(self):
        case = Q.CASES[0]
        f = SimpleNamespace(path=Path("/inert"), fetch_cases={case: {"calls": 0}}, inflight=False, last_returned=False)
        events = []
        def actual(argv, **kw):
            self.assertTrue(f.inflight)
            self.assertEqual(kw["timeout"], 3)
            events.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 0, b"fixed", b"")
        with patch.object(Q, "tool_current", side_effect=lambda _: events.append("current")), patch.object(Q, "remaining", return_value=3):
            self.assertEqual(Q._call(f, case, actual, {}, ["--version"]), b"fixed")
            self.assertEqual(events, ["current", (Q.GIT, "-c", "gc.auto=0", "-c", "maintenance.auto=false", "--version"), "current"])
            self.assertFalse(f.inflight)
            error = KeyboardInterrupt("inert original has not returned")
            def unknown(*args, **kw): raise error
            with self.assertRaises(KeyboardInterrupt) as caught: Q._call(f, case, unknown, {}, ["--version"])
            self.assertIs(caught.exception, error); self.assertTrue(f.inflight)
            with self.assertRaisesRegex(ValueError, "call-order"): Q._call(f, case, actual, {}, ["--version"])
        self.assertEqual(f.fetch_cases[case]["calls"], 2)


class PackagingTests(Inert):
    def test_exact_observer_pair_only_defaults_remain_ordinary(self):
        self.assertFalse(S.fetch_observation_inputs())
        self.assertTrue(S.fetch_observation_inputs(M.ROLE, Q.SCOPE))
        for pair in ((M.ROLE, None), (None, Q.SCOPE), ("ordinary-image", Q.SCOPE), (M.ROLE, "tool-setup")):
            with self.subTest(pair=pair), self.assertRaises(S.Refused): S.fetch_observation_inputs(*pair)
        self.assertEqual(set(Q.BOOTSTRAPS), S.FETCH_OBSERVATION_BOOTSTRAPS)
        self.assertEqual(Q.BOOTSTRAPS, P.FETCH_OBSERVATION_BOOTSTRAPS)
        self.assertFalse(set(Q.BOOTSTRAPS) & set(P.CURRENT_BOOTSTRAPS))
        self.assertFalse(set(Q.BOOTSTRAPS) & S.CURRENT_BOOTSTRAPS)
        env = {"MRK_MACOS_NATIVE_SCOPE": Q.SCOPE, "MRK_MACOS_PACKAGE_ROLE": M.ROLE, "GITHUB_REF": M.REF}
        self.assertEqual(M.package_role(env, "package-install", M.TARGET), M.ROLE)
        self.assertEqual(M.observation_scope(env, Q.SCOPE), Q.SCOPE)
        with self.assertRaises(M.Refused): M.observation_scope(env, M.SCOPE)
        with self.assertRaises(M.Refused): M.package_role(env, "package-install", A.INTEL_TARGET)
        self.assertIsNone(M.package_role({}, "original-phase", A.INTEL_TARGET))

    def test_preparer_refuses_noncurrent_or_nonmac_before_reading_source(self):
        with patch.object(P, "_root") as source:
            for current, target in ((False, M.TARGET), (True, "x86_64-unknown-linux-gnu")):
                with self.assertRaises(P.PreparationError):
                    P._prepare(Path("/inert/source"), Path("/inert/runtime"), target, current=current, fetch_observation=True)
        source.assert_not_called()

    def runtime(self, extras=()):
        names = S.CURRENT_BOOTSTRAPS | {"core.zip", "github-ca.pem", "python/bin/python3"} | set(extras)
        files = {n: (b"INERT public runtime DATA", 0o555 if n == "python/bin/python3" else 0o444) for n in names}
        rows = [{"path": n, "sha256": S.digest(files[n][0]), "size": len(files[n][0])} for n in sorted(files)]
        manifest = {"schemaVersion": 1, "protocol": 1, "coreVersion": "INERT", "target": M.TARGET,
            "coreSha256": S.digest(files["core.zip"][0]), "protocolSha256": S.CURRENT_PROTOCOL,
            "inventorySha256": S.digest(S.canonical(rows)), "files": rows}
        files["manifest.json"] = (S.canonical(manifest), 0o444)
        return files

    def test_final_input_roster_rejects_observer_files_for_ordinary_role(self):
        for extras in (Q.BOOTSTRAPS[:1], Q.BOOTSTRAPS):
            files = self.runtime(extras)
            with patch.object(S, "tree", return_value=files), patch.object(S, "history_provider_source", return_value=(None, None)):
                with self.assertRaisesRegex(S.Refused, "nonshipping-fetch-runtime-roster"):
                    S.runtime_tree(Path("/inert"), S.digest(files["manifest.json"][0]), current=True)
                if len(extras) == 1:
                    with self.assertRaises(S.Refused):
                        S.runtime_tree(Path("/inert"), S.digest(files["manifest.json"][0]), current=True, observation_role=True)
        files = self.runtime(Q.BOOTSTRAPS)
        # Only binary shape inspection is inert here. Manifest, full roster,
        # hashes and role checks are the actual original DATA validators.
        with patch.object(S, "tree", return_value=files), patch.object(S, "history_provider_source", return_value=(None, None)), \
             patch.object(S, "current_runtime_mode", side_effect=lambda n, *a, **k: files[n][1]):
            self.assertIs(S.runtime_tree(Path("/inert"), S.digest(files["manifest.json"][0]), current=True, observation_role=True), files)


class OriginalLoopTests(Inert):
    def run_loop(self, *, unknown=None, late=False, native_scope=Q.SCOPE):
        events, errors = [], []
        f = SimpleNamespace(cases=Q.CASES, path=Path("/inert/fixture"), inflight=False, last_returned=False, case=None)
        f.prepare = lambda: events.append("prepare")
        f.recovery_runtime_paths = lambda: events.append("runtime-post")
        f.close = lambda: events.append("close")
        f.before_call = lambda case: (events.append(("before", case)), setattr(f, "case", case))
        def producer(argv, **options):
            self.assertTrue(f.inflight)
            self.assertEqual(argv, [A.EXECUTABLE, f.case])
            self.assertEqual(options["timeout"], 73)
            events.append(("producer", f.case))
            if unknown is not None: raise unknown
            return subprocess.CompletedProcess(argv, 0, b"INERT report", b"")
        def readback(_f, case, value, need):
            self.assertFalse(f.inflight); self.assertTrue(f.last_returned)
            events.append(("readback", case)); return {"inertOnly": True}
        def current(*args):
            events.append("runtime-post")
            if late and any(type(e) is tuple and e[0] == "readback" for e in events):
                raise ValueError("inert late currentness refusal")
        def diagnostic(error, owner, fixtures):
            errors.append(error); return {"inertOnly": True}
        with ExitStack() as stack:
            stack.enter_context(patch.object(A, "Fixtures", return_value=f))
            stack.enter_context(patch.object(M, "_admit_runtime", side_effect=lambda *a: events.append("admit")))
            stack.enter_context(patch.object(M, "_current", side_effect=current))
            stack.enter_context(patch.object(A, "load_owner", return_value=SimpleNamespace(run_owned=producer)))
            stack.enter_context(patch.object(A.FETCH, "before_invocation", side_effect=lambda _f, c, *a: events.append(("setup", c))))
            stack.enter_context(patch.object(A.FETCH, "remaining", return_value=73))
            stack.enter_context(patch.object(A.FETCH, "readback", side_effect=readback))
            stack.enter_context(patch.object(A, "parse_result", return_value={"gitFetch": {"inertOnly": True}}))
            stack.enter_context(patch.object(A, "diagnostic", side_effect=diagnostic))
            out, err = io.StringIO(), io.StringIO()
            stack.enter_context(redirect_stdout(out)); stack.enter_context(redirect_stderr(err))
            status = M._run(A, BINDING, 501, 20, "runner", Path("/inert/work"),
                            {"MRK_MACOS_NATIVE_SCOPE": native_scope}, scope=Q.SCOPE)
        return status, f, events, errors, [json.loads(v) for v in out.getvalue().splitlines()]

    def test_real_loop_orders_setup_original_call_readback_runtime_post_and_close(self):
        status, f, events, errors, rows = self.run_loop()
        self.assertEqual(status, 0); self.assertEqual(errors, [])
        self.assertEqual([e[1] for e in events if type(e) is tuple and e[0] == "producer"], list(Q.CASES))
        for case in Q.CASES:
            self.assertLess(events.index(("setup", case)), events.index(("before", case)))
            self.assertLess(events.index(("producer", case)), events.index(("readback", case)))
        self.assertEqual(events[-1], "close")
        self.assertEqual(rows[-1]["type"], "macos-git-fetch-current-complete")
        self.assertFalse(rows[-1]["shippingBinaryQualified"])
        self.assertFalse(f.inflight)

    def test_unknown_original_has_no_readback_close_or_later_case(self):
        error = KeyboardInterrupt("inert original wait pending")
        status, f, events, errors, rows = self.run_loop(unknown=error)
        self.assertEqual(status, 130); self.assertEqual(errors, [error]); self.assertEqual(rows, [])
        self.assertTrue(f.inflight); self.assertNotIn("close", events)
        self.assertEqual(len([e for e in events if type(e) is tuple and e[0] == "producer"]), 1)
        self.assertFalse(any(type(e) is tuple and e[0] == "readback" for e in events))

    def test_same_held_runtime_post_failure_cannot_emit_completion_or_next_case(self):
        status, f, events, errors, rows = self.run_loop(late=True)
        self.assertEqual(status, 1); self.assertEqual(len(errors), 1)
        self.assertFalse(f.inflight); self.assertEqual(events[-1], "close")
        self.assertEqual(len([e for e in events if type(e) is tuple and e[0] == "producer"]), 1)
        self.assertFalse(any(r.get("type") == "macos-git-fetch-current-complete" for r in rows))


if __name__ == "__main__":
    unittest.main()
