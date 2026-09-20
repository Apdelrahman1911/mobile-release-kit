"""Inert publisher CI contract tests; no compiler, process or native operation."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import os
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("publisher_ci", SOURCE / "desktop/tools/ci_ubuntu_publication.py")
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


class PublisherCI(unittest.TestCase):
    def test_fixed_route_and_compiler_profiles(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
               "RUNNER_ARCH": "X64", "GITHUB_EVENT_NAME": "push", "GITHUB_REF": S.REF,
               "MRK_UBUNTU_PUBLICATION_VERIFY": "1", "GITHUB_SHA": "a" * 40, "MRK_PUSH_EVENT_AFTER": "a" * 40,
               "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit"}
        self.assertEqual(S.route(env), "a" * 40)
        for key, value in (("GITHUB_EVENT_NAME", "workflow_dispatch"), ("GITHUB_REF", "refs/heads/main"),
                           ("RUNNER_ENVIRONMENT", "self-hosted"), ("MRK_PUSH_EVENT_AFTER", "b" * 40)):
            with self.subTest(field=key), self.assertRaises(ValueError):
                S.route({**env, key: value})
        for library in (False, True):
            argv = S.compile_argv("/tools/cargo", Path("/source"), Path("/target"), library=library)
            self.assertEqual(argv[:2], ["/tools/cargo", "test" if library else "build"])
            self.assertIn("--offline", argv)
            self.assertIn("--locked", argv)
            self.assertEqual(argv[argv.index("--features") + 1], "ubuntu-runtime-publisher")
            self.assertNotIn("development-runtime", argv)
            self.assertEqual("--no-run" in argv, library)

    def test_only_exact_fresh_compiler_artifact_is_selected(self):
        source, root = Path("/source"), Path("/target")
        for library in (False, True):
            executable = root / S.TARGET / ("debug/deps/mobile_release_desktop-0123456789abcdef" if library else "release/mrk-runtime-publish")
            row = {"reason": "compiler-artifact", "executable": str(executable), "fresh": False,
                   "features": S.FEATURES, "manifest_path": str(source / "desktop/src-tauri/Cargo.toml"),
                   "target": {"kind": ["lib" if library else "bin"], "name": "mobile_release_desktop" if library else "mrk-runtime-publish",
                              "src_path": str(source / "desktop/src-tauri/src" / ("lib.rs" if library else "bin/runtime_publish.rs"))},
                   "profile": {"test": library, "debug_assertions": library, "opt_level": "0" if library else "3"}}
            final = {"reason": "build-finished", "success": True}
            raw = S.D.canonical(row) + S.D.canonical(final)
            self.assertEqual(S.compiled_artifact(raw, source, root, library=library), executable)
            for key, value in (("fresh", True), ("features", []), ("executable", "/different/binary")):
                changed = deepcopy(row)
                changed[key] = value
                with self.subTest(library=library, field=key), self.assertRaises(ValueError):
                    S.compiled_artifact(S.D.canonical(changed) + S.D.canonical(final), source, root, library=library)
            for changed in (S.D.canonical(final), raw + S.D.canonical(final), S.D.canonical(row) * 2 + S.D.canonical(final)):
                with self.assertRaises(ValueError):
                    S.compiled_artifact(changed, source, root, library=library)

    def test_zero_partial_extra_or_failed_tests_are_not_a_pass(self):
        lines = ["running 11 tests", *(f"test {name} ... ok" for name in S.TESTS),
                 "test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.01s"]
        raw = ("\n".join(lines) + "\n").encode("ascii")
        S.test_result(raw, b"")
        for changed in (b"running 0 tests\n", raw.replace(lines[1].encode() + b"\n", b""),
                        raw.replace(b" ... ok", b" ... FAILED", 1), raw + b"test unexpected ... ok\n"):
            with self.assertRaises(ValueError):
                S.test_result(changed, b"")
        with self.assertRaises(ValueError):
            S.test_result(raw, b"unexpected diagnostic")

    def test_failed_or_expired_command_never_becomes_success(self):
        with tempfile.TemporaryDirectory(prefix="mrk-publisher-ci-data-") as name:
            root = Path(name)
            (root / "public").mkdir()
            argv = ["/inert-tool"]
            outcome = subprocess.CompletedProcess(argv, 7, b"synthetic output", b"synthetic failure")
            with patch.object(S.time, "monotonic", return_value=100), patch.object(S.D, "write", wraps=S.D.write):
                owner = unittest.mock.Mock(return_value=outcome)
                check = S.Check(root, owner)
                with self.assertRaises(ValueError):
                    check.command("failed", argv, {}, root)
                self.assertEqual(owner.call_count, 1)
                self.assertEqual((root / "public/failed.stderr").read_bytes(), b"synthetic failure")
                self.assertEqual(check.commands[0]["exitCode"], 7)
                self.assertTrue(check.failed)
                with self.assertRaises(ValueError):
                    check.command("must-not-launch", argv, {}, root)
                self.assertEqual(owner.call_count, 1)
                expired = S.Check(root, owner)
                expired.end = 99
                with self.assertRaises(ValueError):
                    expired.command("expired", argv, {}, root)
                self.assertEqual(owner.call_count, 1)

    def test_compiler_hardlink_exports_fresh_verified_data_only(self):
        with tempfile.TemporaryDirectory(prefix="mrk-publisher-copy-data-") as name:
            root = Path(name)
            source, alias, destination = root / "compiler-data", root / "compiler-alias", root / "exported-data"
            source.write_bytes(b"inert compiler DATA; never execute")
            source.chmod(0o700)
            os.link(source, alias)
            before = source.stat()
            result = S.artifact_record(source, copy_to=destination)
            self.assertEqual(result["sha256"], S.D.file_record(destination)["sha256"])
            self.assertNotEqual(before.st_ino, destination.stat().st_ino)
            self.assertEqual(source.stat().st_nlink, 2)
            self.assertEqual(destination.stat().st_nlink, 1)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o555)
            with self.assertRaises(FileExistsError):
                S.artifact_record(source, copy_to=destination)
            self.assertEqual(destination.read_bytes(), source.read_bytes())


if __name__ == "__main__":
    unittest.main()
