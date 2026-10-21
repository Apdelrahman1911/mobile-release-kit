"""Fixed setup/consumer DATA and original-call guards, not a native run.

No CLT, child, network, credential, artifact, installed app or fake receipt.
The existing Fixtures/run_owned supplied by the parent retain actual custody.
"""
import configparser
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import _git_push_observation_data as data

PATH = Path(__file__).resolve().parents[2] / "desktop/tools/macos_git_push_qualification.py"
SPEC = importlib.util.spec_from_file_location("mrk_push_qualification_data", PATH)
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)


def _module(name, filename):
    spec = importlib.util.spec_from_file_location(name, PATH.with_name(filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class PushQualificationTests(unittest.TestCase):
    def setUp(self):
        for name in ("subprocess.Popen", "socket.socket", "socket.create_connection", "os.open"):
            self.enterContext(patch(name, side_effect=AssertionError("Native effects forbidden")))

    def test_same_schema_and_three_local_oids_no_pack_copy_or_credential_input(self):
        self.assertEqual(setup.CASES, data.CASES)
        self.assertEqual(setup.SCOPE, data.SCOPE)
        self.assertEqual(setup.DATA_LIMIT, data.DATA_LIMIT)
        for case in setup.CASES:
            raw = setup._transcript(case, "a" * 40, "b" * 40, "c" * 40)
            actual = data.decode(raw, case)
            self.assertEqual(raw, actual.raw())
            self.assertNotIn(b"pack", raw.replace(case.encode(), b""))
        for other in ("a" * 40, "0" * 40, "not-an-oid"):
            with self.assertRaises(ValueError):
                setup._transcript(setup.CASES[0], "a" * 40, "b" * 40, other)

    def test_only_fresh_fixed_config_has_normal_fetch_map_and_no_forced_push_rule(self):
        for case in setup.CASES:
            c = configparser.RawConfigParser()
            c.read_string(setup._configuration(case).decode("ascii"))
            self.assertEqual(c.sections(), ["core", "user", 'remote "origin"', 'branch "main"'])
            self.assertEqual(dict(c['remote "origin"']), {
                "url": "https://github.com/" + data.coordinate(case) + ".git",
                "fetch": "+refs/heads/*:refs/remotes/origin/*"})
            self.assertEqual(dict(c['branch "main"']), {"remote": "origin", "merge": data.REFERENCE})
        with self.assertRaises(ValueError): setup._configuration("another-case")
        files, directories = setup.fixture_data(b"config", b"version", b"keep", b"ignore", b"source")
        self.assertEqual(files["untracked.txt"], setup.UNTRACKED)
        self.assertIn("untracked.txt", directories["."][1])
        self.assertNotIn("untracked.txt", setup.FILES[:-1])

    def fixture(self):
        case = setup.CASES[0]
        return SimpleNamespace(push_cases={case: {"calls": 0, "end": 140.0}}, push_end=200.0,
                               inflight=False, last_returned=True, close_errors=0, path=Path("/private/fixed"))

    def test_original_call_return_before_clock_check_no_retry_on_missing_return(self):
        f, case, seen = self.fixture(), setup.CASES[0], []
        def returned(argv, **kwargs):
            self.assertTrue(f.inflight)
            self.assertFalse(f.last_returned)
            seen.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, b"result", b"")
        with patch.object(setup, "tool_current"), patch.object(setup.time, "monotonic", return_value=100.0):
            self.assertEqual(setup._call(f, case, returned, {"fixed": "environment"}, ["--version"]), b"result")
            self.assertEqual(seen[0][1]["timeout"], 5)
            self.assertEqual(seen[0][0], [setup.GIT, "-c", "gc.auto=0", "-c", "maintenance.auto=false", "--version"])
            self.assertEqual((f.inflight, f.last_returned, f.push_cases[case]["end"], f.push_end), (False, True, 140.0, 200.0))
            error = RuntimeError("fixed fake missing return")
            with self.assertRaises(RuntimeError) as caught:
                setup._call(f, case, lambda *a, **kw: (_ for _ in ()).throw(error), {}, ["--version"])
            self.assertIs(caught.exception, error)
            self.assertTrue(f.inflight)
            self.assertFalse(f.last_returned)
            with self.assertRaises(ValueError): setup._call(f, case, returned, {}, ["--version"])
        self.assertEqual(len(seen), 1)

    def test_wrong_call_identity_and_expired_original_are_not_success_or_new_clock(self):
        f, case = self.fixture(), setup.CASES[0]
        with patch.object(setup, "tool_current"), patch.object(setup.time, "monotonic", return_value=139.5):
            with self.assertRaises(ValueError):
                setup._call(f, case, lambda *a, **kw: self.fail("must not call"), {}, ["--version"])
        self.assertEqual(f.push_cases[case]["calls"], 0)
        with patch.object(setup, "tool_current"), patch.object(setup.time, "monotonic", return_value=100.0):
            with self.assertRaises(ValueError):
                setup._call(f, case, lambda *a, **kw: subprocess.CompletedProcess(["other"], 0, b"", b""), {}, ["--version"])
        self.assertTrue(f.inflight)
        self.assertEqual(f.push_cases[case]["end"], 140.0)

    def report(self, case):
        # Deliberately inert DTO to test the parser. It is NOT an original proof.
        return dict(mechanism="same-original-git-push-v1", case=case, syntheticProviderBytes=True,
                    connectionOriginalJoined=True, readOriginalJoined=True, prepareOriginalJoined=True,
                    applyOriginalJoined=True, connectionRetired=True, remoteReturned=case == setup.CASES[0],
                    helperRefusedBeforeAllCopyEof=case == setup.CASES[2], producerPendingBeforeStop=case == setup.CASES[2],
                    sameTicketStop=case == setup.CASES[2], toolSha256="a" * 64, normalQuitOriginal=2,
                    allOriginalsSettled=True, worktreePreserved=True, shippingNominationEnabled=False,
                    tlsQualified=False, liveAccountQualified=False, productionQualified=False)

    def test_report_never_fills_missing_joins_or_claims_tls_or_native_qualification(self):
        for case in setup.CASES:
            original = self.report(case)
            self.assertIs(setup.report(original, case, setup._need), original)
            for key, value in (("applyOriginalJoined", False), ("allOriginalsSettled", None),
                               ("normalQuitOriginal", True), ("productionQualified", True),
                               ("tlsQualified", True), ("extra", False)):
                bad = {**original, key: value}
                with self.subTest(case=case, key=key), self.assertRaises(ValueError):
                    setup.report(bad, case, setup._need)
            bad = original.copy(); bad.pop("producerPendingBeforeStop")
            with self.assertRaises(ValueError): setup.report(bad, case, setup._need)

    def test_readback_requires_original_return_and_exact_before_not_adopted_new_tracking(self):
        f, case = self.fixture(), setup.CASES[0]
        before = {"tracking": (1, "old-hash"), "HEAD": (2, "unchanged"), "index": (3, "unchanged")}
        f.push_entered, f.push_completed, f._namespace = {case}, set(), lambda: None
        f.push_tool = (None, None, None, "a" * 64)
        f.push_cases[case].update(before=copy.deepcopy(before), version="git version public\n")
        with patch.object(setup, "parents_current"), patch.object(setup, "tool_current"), \
                patch.object(setup.time, "monotonic", return_value=100.0), \
                patch.object(setup, "_capture", return_value={**before, "tracking": (4, "new")}) as capture:
            with self.assertRaises(ValueError): setup.readback(f, case, self.report(case), setup._need)
            self.assertEqual(f.push_completed, set())
            capture.return_value = before
            f.last_returned = False
            with self.assertRaises(ValueError): setup.readback(f, case, self.report(case), setup._need)
            f.last_returned = True
            result = setup.readback(f, case, self.report(case), setup._need)
            self.assertTrue(result["localTrackingUnchanged"] and result["untrackedPreserved"])
            self.assertFalse(result["nativeAuthority"])
            with self.assertRaises(ValueError): setup.readback(f, case, self.report(case), setup._need)


class PushRouteTests(unittest.TestCase):
    """Actual composed callers/guards, with native effects forbidden.

    Report/owner doubles below are expressly DATA, never a real joined ticket.
    These tests run against the same Root-hook projection as native wiring.
    """
    def setUp(self):
        for name in ("subprocess.Popen", "socket.socket", "socket.create_connection"):
            self.enterContext(patch(name, side_effect=AssertionError("Native effects forbidden")))
        self.aqua = _module("_push_route_aqua", "macos_aqua_qualification.py")
        self.current = _module("_push_route_current", "macos_identity_current_runtime.py")
        # The existing stager import uses its original bounded no-follow
        # reader for public build-release.json, just like its older tests.
        self.stage = _module("_push_route_stage", "stage_macos_installed.py")
        self.prepare = _module("_push_route_prepare", "prepare_runtime.py")
        self.enterContext(patch("os.open", side_effect=AssertionError("Unexpected fixture IO")))

    def test_same_scope_and_closed_package_pair_preserve_other_families(self):
        a, m, s = self.aqua, self.current, self.stage
        self.assertEqual(a.selected_cases(setup.SCOPE), setup.CASES)
        self.assertEqual(a.selected_cases(a.FETCH.SCOPE), a.FETCH.CASES)
        self.assertEqual(a.selected_cases(None), a.CASES)
        self.assertEqual(a.argument_scope(["--scope", setup.SCOPE]), setup.SCOPE)
        self.assertEqual(m.arguments(["--target", m.TARGET, "--scope", setup.SCOPE]), setup.SCOPE)
        env = {"MRK_MACOS_NATIVE_SCOPE": setup.SCOPE, "MRK_MACOS_PACKAGE_ROLE": m.ROLE, "GITHUB_REF": m.REF}
        self.assertEqual(m.package_role(env, "prepare", m.TARGET), m.ROLE)
        self.assertEqual(m.observation_scope(env, setup.SCOPE), setup.SCOPE)
        for scope in (m.FETCH_SCOPE, m.SCOPE, m.TOOLS_SCOPE, "all"):
            with self.assertRaises(m.Refused): m.observation_scope(env, scope)
        self.assertFalse(s.push_observation_inputs())
        self.assertFalse(s.fetch_observation_inputs())
        self.assertTrue(s.push_observation_inputs(m.ROLE, setup.SCOPE))
        self.assertFalse(s.fetch_observation_inputs(m.ROLE, setup.SCOPE))
        self.assertTrue(s.fetch_observation_inputs(m.ROLE, m.FETCH_SCOPE))
        self.assertFalse(s.push_observation_inputs(m.ROLE, m.FETCH_SCOPE))
        for role, scope in ((None, setup.SCOPE), (m.ROLE, None), ("ordinary-image", setup.SCOPE), (m.ROLE, "all")):
            for selector in (s.push_observation_inputs, s.fetch_observation_inputs):
                with self.assertRaises(s.Refused): selector(role, scope)

    def test_preparer_rejects_mixed_or_foreign_flags_before_any_original_file_open(self):
        p = self.prepare
        with patch.object(p, "_root", side_effect=AssertionError("must not reach IO")) as root:
            for kwargs in ({"push_observation": 1}, {"push_observation": True, "fetch_observation": True}):
                with self.assertRaises(p.PreparationError):
                    p.prepare_current(Path("/inert-source"), Path("/inert-runtime"), "aarch64-apple-darwin", **kwargs)
            with self.assertRaises(p.PreparationError):
                p.prepare_current(Path("/inert-source"), Path("/inert-runtime"), "x86_64-unknown-linux-gnu", push_observation=True)
            root.assert_not_called()
        # Real roster gate runs before manifest parsing. A complete pair can
        # reach that next gate; this does NOT claim a valid manifest/runtime.
        s = self.stage
        sentinel = RuntimeError("next original parser, not a runtime receipt")
        with patch.object(s, "history_provider_source", return_value=(None, None)), \
                patch.object(s, "manifest_files", side_effect=sentinel) as manifest, \
                patch.object(s, "tree") as tree:
            pair = {name: (b"DATA", 0o444) for name in s.PUSH_OBSERVATION_BOOTSTRAPS}
            tree.return_value = {"manifest.json": (b"DATA", 0o444), **pair}
            with self.assertRaises(RuntimeError) as caught:
                s.runtime_tree(Path("/inert-runtime"), "0" * 64, current=True, observation_role=True)
            self.assertIs(caught.exception, sentinel)
            self.assertEqual(manifest.call_count, 1)
            for files, role in ((pair, False), ({next(iter(pair)): (b"DATA", 0o444)}, True),
                                ({**pair, **{name: (b"DATA", 0o444) for name in s.FETCH_OBSERVATION_BOOTSTRAPS}}, True)):
                tree.return_value = {"manifest.json": (b"DATA", 0o444), **files}
                with self.assertRaises(s.Refused):
                    s.runtime_tree(Path("/inert-runtime"), "0" * 64, current=True, observation_role=role)
            self.assertEqual(manifest.call_count, 1)

    def test_original_run_cases_retains_missing_app_return_and_never_enters_next_case(self):
        a, events = self.aqua, []
        binding = a.Binding("a" * 40, "123", "1")
        f = SimpleNamespace(cases=setup.CASES, path=Path("/inert-owned-push"), inflight=False,
            last_returned=True, recovery_runtime_paths=lambda: events.append("runtime"),
            before_call=lambda case: events.append(("before", case)))
        failure = RuntimeError("inert original app call did not return")
        def owner(argv, **kwargs):
            self.assertTrue(f.inflight)
            self.assertFalse(f.last_returned)
            self.assertEqual(kwargs["timeout"], 73)
            self.assertEqual(argv, [a.EXECUTABLE, setup.CASES[0]])
            events.append(("call", argv[1]))
            raise failure
        with patch.object(a.PUSH, "before_invocation", side_effect=lambda f, c, r, u: events.append(("setup", c))), \
                patch.object(a.PUSH, "remaining", return_value=73), patch.object(a.PUSH, "readback") as readback, \
                patch.object(a, "parse_result") as parse, patch.object(a, "app_environment", return_value={}):
            with self.assertRaises(RuntimeError) as caught:
                a.run_cases(binding, f, owner, 501, "runner", lambda v: self.fail("cannot emit"), setup.SCOPE)
            self.assertIs(caught.exception, failure)
            self.assertEqual(events, ["runtime", ("setup", setup.CASES[0]), ("before", setup.CASES[0]), ("call", setup.CASES[0])])
            self.assertTrue(f.inflight)
            self.assertFalse(f.last_returned)
            readback.assert_not_called(); parse.assert_not_called()

    def test_actual_result_parser_requires_returned_push_facts_not_comparison_template(self):
        a, binding = self.aqua, self.aqua.Binding("a" * 40, "123", "1")
        for case in setup.CASES:
            template = a.expected_result(binding, case)
            self.assertIsNone(template["gitPush"])
            encode = lambda value: a.MARKER + json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            with self.assertRaises(a.Refused): a.parse_result(encode(template), b"", binding, case)
            # Explicit synthetic DTO to exercise the parser only. No owner or
            # native receipt is constructed or obtained by this acceptance.
            value = {**template, "gitPush": PushQualificationTests.report(self, case)}
            self.assertEqual(a.parse_result(encode(value), b"", binding, case), value)
            value["gitPush"] = {**value["gitPush"], "applyOriginalJoined": False}
            with self.assertRaises(a.Refused): a.parse_result(encode(value), b"", binding, case)


if __name__ == "__main__":
    unittest.main()
