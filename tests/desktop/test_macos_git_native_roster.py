"""Bounded publisher/observer DATA only; no process, socket or Mac authority.

Reuses the existing inert original-loop and real bounded-file fixtures. The
installed-root owner check is explicitly substituted with this private test
UID; the actual original FD/read/hash/POST/close paths are not substituted.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_macos_git_fetch_qualification as F
import test_macos_identity_current_runtime as I


P, S, M = F.P, F.S, F.M


class GitNativeRosterTests(F.Inert):
    def test_closed_flag_and_role_truth_table_before_source_io(self):
        self.assertEqual(set(P.GIT_OBSERVATION_BOOTSTRAPS), S.GIT_OBSERVATION_BOOTSTRAPS)
        choices = (({}, set()), ({"fetch_observation": True}, S.FETCH_OBSERVATION_BOOTSTRAPS),
                   ({"push_observation": True}, S.PUSH_OBSERVATION_BOOTSTRAPS),
                   ({"git_observation": True}, S.GIT_OBSERVATION_BOOTSTRAPS))
        for options, expected in choices:
            self.assertEqual(S._git_observation_bootstraps(**options), expected)
        bad = ({"git_observation": 1}, {"git_observation": None},
               {"git_observation": True, "fetch_observation": True},
               {"git_observation": True, "push_observation": True},
               {"fetch_observation": True, "push_observation": True})
        with patch.object(P, "_root", side_effect=AssertionError("source IO forbidden")) as root, \
                patch.object(S, "tree", side_effect=AssertionError("source IO forbidden")) as tree:
            for options in bad:
                with self.subTest(options=options), self.assertRaises(P.PreparationError):
                    P.prepare_current(Path("/inert/source"), Path("/inert/runtime"), M.TARGET, **options)
                with self.assertRaises(S.Refused): S.current_source(**options)
            for current, target in ((False, M.TARGET), (True, S.INTEL_TARGET), (True, "x86_64-unknown-linux-gnu")):
                with self.assertRaises(P.PreparationError):
                    P._prepare(Path("/inert/source"), Path("/inert/runtime"), target, current=current, git_observation=True)
            root.assert_not_called(); tree.assert_not_called()
        selectors = (S.fetch_observation_inputs, S.push_observation_inputs, S.git_observation_inputs)
        for scope, expected in ((None, (False, False, False)), (M.FETCH_SCOPE, (True, False, False)),
                                (M.PUSH_SCOPE, (False, True, False)), (M.GIT_SCOPE, (False, False, True))):
            self.assertEqual(tuple(f(None if scope is None else M.ROLE, scope) for f in selectors), expected)
        for role, scope in ((None, M.GIT_SCOPE), (M.ROLE, None), ("ordinary-image", M.GIT_SCOPE),
                            (M.ROLE, "all"), (M.ROLE, M.TOOLS_SCOPE)):
            for selector in selectors:
                with self.assertRaises(S.Refused): selector(role, scope)
        env = {**I.environment(), "MRK_MACOS_NATIVE_SCOPE": M.GIT_SCOPE}
        self.assertEqual(M.current_context(env, M.TARGET)[0], I.BINDING.source)
        for scope in (M.FETCH_SCOPE, M.PUSH_SCOPE):
            self.assertEqual(M.observation_scope(env, scope), scope)
        for scope in (M.GIT_SCOPE, M.SCOPE, M.TOOLS_SCOPE, M.SERVICE_SCOPE, *M.UPLOAD_SCOPES):
            with self.assertRaises(M.Refused): M.observation_scope(env, scope)
        with self.assertRaises(M.Refused): M.arguments(["--target", M.TARGET, "--scope", M.GIT_SCOPE])
        with self.assertRaises(M.Refused): M.package_role(env, "package-install", S.INTEL_TARGET)
        with self.assertRaises(M.Refused): M.current_context({**env, "MRK_MACOS_PACKAGE_ROLE": "ordinary-image"}, M.TARGET)

    def test_actual_source_capture_and_preparation_select_complete_rosters(self):
        with tempfile.TemporaryDirectory(prefix="mrk-git-native-roster-data-") as temporary:
            root, source = Path(temporary), Path(temporary) / "source"
            package = source / "src/mobile_release"
            package.mkdir(parents=True, mode=0o700)
            (package / "__init__.py").write_bytes(b'__version__ = "0.3.0"\n')
            engine = b"# inert source, never imported or executed\n"
            (package / "_desktop_engine.py").write_bytes(engine)
            desktop = source / "desktop"
            (desktop / "tools").mkdir(parents=True, mode=0o700)
            (desktop / "cpython-source-inputs").mkdir(mode=0o700)
            (desktop / "tools/prepare_runtime.py").write_bytes(Path(P.__file__).read_bytes())
            (desktop / "cpython-source-inputs/github-ca.pem").write_bytes(b"INERT CA DATA, NOT TRUST\n")
            for name in S.CURRENT_BOOTSTRAPS | S.GIT_OBSERVATION_BOOTSTRAPS:
                (desktop / name).write_bytes(("# inert " + name + "\n").encode("ascii"))
            supplier = {"python/bin/python3": (b"INERT, NEVER EXECUTED\n", 0o555)}
            with patch.object(S, "DESKTOP", desktop), patch.object(S, "CURRENT_PROTOCOL", S.digest(engine)):
                for number, (options, expected) in enumerate((({}, set()),
                        ({"fetch_observation": True}, S.FETCH_OBSERVATION_BOOTSTRAPS),
                        ({"push_observation": True}, S.PUSH_OBSERVATION_BOOTSTRAPS),
                        ({"git_observation": True}, S.GIT_OBSERVATION_BOOTSTRAPS))):
                    captured, projection, original = S.current_source(**options)
                    self.assertEqual({"desktop/" + n for n in expected},
                        set(captured) & {"desktop/" + n for n in S.GIT_OBSERVATION_BOOTSTRAPS})
                    projected, runtime = root / ("projected" + str(number)), root / ("runtime" + str(number))
                    S.write_tree(projected, projection, current_owned=True)
                    S.write_tree(runtime, supplier, root_mode=0o700, current_owned=True)
                    result = P.prepare_current(projected, runtime, M.TARGET, **options)
                    files, _ = S.current_runtime_files(runtime, projection, supplier, **options)
                    self.assertEqual(result["qualification"], "prepared-not-native-verified")
                    self.assertEqual(set(files) & S.GIT_OBSERVATION_BOOTSTRAPS, expected)
                    self.assertEqual(S.current_source(**options), (captured, projection, original))
                peer = desktop / P.PUSH_OBSERVATION_BOOTSTRAPS[0]
                peer.write_bytes(b"# changed unused peer source\n")
                self.assertNotEqual(S.current_source(git_observation=True)[2], original)
                # Complete four-member bytes, hashes and modes are required;
                # a caller cannot quietly omit a peer from final staging.
                (runtime / P.PUSH_OBSERVATION_BOOTSTRAPS[0]).unlink()
                with self.assertRaisesRegex(S.Refused, "current-runtime-complete-roster"):
                    S.current_runtime_files(runtime, projection, supplier, git_observation=True)

    def test_final_runtime_all_four_remain_nonshipping_and_partial_mixes_refuse(self):
        extras = S.GIT_OBSERVATION_BOOTSTRAPS
        files = F.PackagingTests.runtime(self, extras)
        with patch.object(S, "tree", return_value=files), patch.object(S, "history_provider_source", return_value=(None, None)), \
                patch.object(S, "current_runtime_mode", side_effect=lambda name, *a, **k: files[name][1]):
            self.assertIs(S.runtime_tree(Path("/inert"), S.digest(files["manifest.json"][0]),
                                       current=True, observation_role=True), files)
            for options in ({"current": True}, {"current": False, "observation_role": True},
                            {"current": True, "observation_role": True, "target": S.INTEL_TARGET}):
                with self.assertRaises(S.Refused):
                    S.runtime_tree(Path("/inert"), S.digest(files["manifest.json"][0]), **options)
        for absent in extras:
            partial = F.PackagingTests.runtime(self, extras - {absent})
            with patch.object(S, "tree", return_value=partial), patch.object(S, "history_provider_source", return_value=(None, None)), \
                    patch.object(S, "manifest_files", side_effect=AssertionError("partial roster must fail first")):
                with self.assertRaises(S.Refused):
                    S.runtime_tree(Path("/inert"), S.digest(partial["manifest.json"][0]), current=True, observation_role=True)

    @contextmanager
    def held_fixture(self, scope, extras):
        fixture = I.CurrentBindingFilesTests()
        try:
            fixture.setUp()
            files = F.PackagingTests.runtime(self, extras)
            manifest = files["manifest.json"][0]
            fixture.put(fixture.root / "installed/manifest.json", manifest)
            parent, name, fd, _ = fixture.fixtures.recovery_runtime_originals[0]
            fixture.fixtures.recovery_runtime_originals[0] = (parent, name, fd, I.A.signature(os.fstat(fd)))
            for entry in extras:
                path = fixture.root / "installed" / entry
                fixture.put(path, files[entry][0]); path.chmod(0o444)
            fixture.env["MRK_MACOS_NATIVE_SCOPE"] = scope
            fixture.runtime["runtimeManifestSha256"] = I.STAGE.digest(manifest)
            fixture.bind()
            original_read = fixture.fixtures._recovery_read
            def private_public_file(parent, name, owner, limit, mode, **options):
                self.assertEqual(owner, 0)  # Production requires protected root-owned inputs.
                return original_read(parent, name, os.getuid(), limit, mode, **options)
            with patch.object(fixture.fixtures, "_recovery_read", side_effect=private_public_file) as reads:
                yield fixture, reads
        finally:
            fixture.doCleanups()

    def test_same_four_originals_held_and_unused_peer_replacement_fails_post(self):
        with self.held_fixture(I.M.GIT_SCOPE, S.GIT_OBSERVATION_BOOTSTRAPS) as (fixture, reads):
            fixture.admit()
            self.assertEqual([c.args[1] for c in reads.call_args_list], sorted(S.GIT_OBSERVATION_BOOTSTRAPS))
            held = {r["name"]: r for r in fixture.fixtures.gate_files if r["name"] in S.GIT_OBSERVATION_BOOTSTRAPS}
            self.assertEqual(set(held), S.GIT_OBSERVATION_BOOTSTRAPS)
            self.assertEqual(len({r["fd"] for r in held.values()}), 4)
            I.M._current(I.A, fixture.fixtures)
            peer = fixture.root / "installed" / P.PUSH_OBSERVATION_BOOTSTRAPS[0]
            replacement = fixture.root / "installed/replacement"
            fixture.put(replacement, peer.read_bytes()); replacement.chmod(0o444)
            replacement.replace(peer)
            with self.assertRaisesRegex(I.A.Refused, "gate-original-file-changed"):
                I.M._current(I.A, fixture.fixtures)
            self.assertTrue(peer.is_file())  # Never repair or delete the foreign replacement.
            fixture.fixtures.close()
            self.assertFalse(fixture.fixtures.fds)
        for scope, extras in ((I.M.GIT_SCOPE, S.FETCH_OBSERVATION_BOOTSTRAPS),
                              (I.M.GIT_SCOPE, S.PUSH_OBSERVATION_BOOTSTRAPS),
                              (I.M.FETCH_SCOPE, S.GIT_OBSERVATION_BOOTSTRAPS),
                              (I.M.PUSH_SCOPE, S.GIT_OBSERVATION_BOOTSTRAPS)):
            with self.subTest(scope=scope, extras=extras), self.held_fixture(scope, extras) as (fixture, reads):
                with self.assertRaisesRegex(I.A.Refused, "current-git-observation-roster"):
                    fixture.admit()
                reads.assert_not_called()

    def test_combined_image_is_not_combined_execution_and_original_failure_stays_pending(self):
        error = KeyboardInterrupt("inert original return missing")
        with patch.object(F.A.PUSH, "before_invocation", side_effect=AssertionError("no automatic peer invocation")) as peer:
            status, fixture, events, errors, rows = F.OriginalLoopTests.run_loop(
                self, native_scope=M.GIT_SCOPE, unknown=error)
        self.assertEqual(status, 130)
        self.assertEqual(errors, [error]); self.assertEqual(rows, [])
        self.assertTrue(fixture.inflight); self.assertNotIn("close", events)
        self.assertEqual([event[1] for event in events if type(event) is tuple and event[0] == "producer"], [F.Q.CASES[0]])
        peer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
