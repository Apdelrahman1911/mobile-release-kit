"""Real temporary Git/held-input tests; no build, credential or Store work."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from mobile_release import local_release_source as S
from mobile_release.build_inputs import invocation_custody
from mobile_release.config import default_config_data
from mobile_release.errors import MutationGuardError, ValidationError
from mobile_release.local_release_intent import prepare_owned_local_release
from mobile_release.owned_process import ProcessError, ProcessCleanupError
from test_local_release_intent import fixture


class LocalReleaseSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mrk-local-source-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "project"
        self.root.mkdir()
        self.environment = {"PATH": "/usr/bin:/bin", "HOME": self.tmp.name,
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "LANG": "C", "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0"}
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Inert Source Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.data = default_config_data({"android": {"applicationId": "com.example.reader"}})
        self.data["source"]["localStoreEnabled"] = True
        self.data["android"].update(enabled=True, identityStatus="approved", externalTrack={"kind": "closed", "name": "beta"}, uploadCertificateSha256="ab" * 32)
        self.version = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
        self.write_inputs()
        self.commit()

    def git(self, *args):
        return subprocess.run(["/usr/bin/git", *args], cwd=self.root, env=self.environment,
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def write_inputs(self):
        self.config = json.dumps(self.data).encode()
        path = self.root / "release/mobile-release.json"
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(self.config)
        selected = self.root / self.data["version"]["source"]
        selected.parent.mkdir(parents=True, exist_ok=True)
        selected.write_bytes(self.version)

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "-q", "-m", "inert source")

    @contextmanager
    def observed(self, **kwargs):
        with invocation_custody(self.root, mode="build") as invocation:
            with invocation.project(signing_lease=None):
                with S.observe_local_source(invocation, configuration_bytes=self.config,
                                            version_bytes=self.version, **kwargs) as source:
                    yield source

    def draft(self, source):
        value = fixture()
        value["source"] = {k: source.observed.as_dict()[k] for k in ("commit", "tree", "branch", "ref", "dirty")}
        value["configuration"]["sha256"] = hashlib.sha256(self.config).hexdigest()
        value["versionSource"] = {"path": self.data["version"]["source"], "sha256": hashlib.sha256(self.version).hexdigest()}
        return json.dumps(value).encode()

    def test_actual_owned_git_and_saved_prepare_ignore_github_hints_and_close_originals(self):
        real = S.run_owned
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs.copy()))
            return real(argv, **kwargs)
        with mock.patch.dict(os.environ, {"GITHUB_SHA": "f" * 40, "GITHUB_REF": "refs/heads/wrong",
                "GIT_DIR": "/untrusted", "GIT_CONFIG_COUNT": "1", "AWS_SECRET_ACCESS_KEY": "private-sentinel"}), \
                mock.patch.object(S, "run_owned", side_effect=run):
            with self.observed() as source:
                draft = prepare_owned_local_release(self.draft(source), source=source)
                self.assertEqual(draft.source.commit.encode(), self.git("rev-parse", "HEAD").strip())
                self.assertEqual((draft.source.branch, draft.source.ref, draft.source.repository), ("main", "refs/heads/main", None))
                self.assertLessEqual(source.held, S.MAX_HELD)
                from mobile_release.stores import StoreRequest, guard_ci_mutation
                with self.assertRaises(MutationGuardError):
                    guard_ci_mutation(request=StoreRequest("candidate", "android", draft.to_dict()["confirmation"], True,
                        self.root / "release/output"), config=source.config, release=draft.release,
                        git=source.observed, environ={})
            self.assertTrue(source.closed)
            self.assertTrue(all(slot.state == "CLOSED" for reader in source.readers for slot in reader.descriptors))
            with self.assertRaises(S.LocalSourceError): source.check()
        self.assertEqual(len(calls), 8)
        for argv, kwargs in calls:
            self.assertEqual(argv[0], "/usr/bin/git")
            self.assertIs(kwargs["text"], False)
            self.assertNotIn("GIT_DIR", kwargs["environ"])
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", kwargs["environ"])
            self.assertLessEqual(kwargs["timeout"], 10)
            self.assertEqual(kwargs["environ"]["GIT_LITERAL_PATHSPECS"], "1")

    def test_dirty_staged_and_untracked_changes_refuse(self):
        for change in ("tracked", "staged", "untracked"):
            with self.subTest(change=change):
                path = self.root / ("release/version.properties" if change != "untracked" else "untracked.txt")
                old = path.read_bytes() if path.exists() else None
                path.write_bytes(b"foreign")
                if change == "staged": self.git("add", "--all")
                with self.assertRaises(S.LocalSourceError):
                    with self.observed(): self.fail("dirty source admitted")
                self.git("reset", "--hard", "-q", "HEAD")
                if old is None: path.unlink()

    def test_literal_magic_looking_version_name_uses_exact_blob_not_pathspec(self):
        old = self.root / self.data["version"]["source"]
        self.data["version"]["source"] = "release/[version]*?.properties"
        old.unlink()
        self.write_inputs()
        (self.root / "release/verson-other.properties").write_bytes(b"not the selected version")
        self.commit()
        with self.observed() as source:
            self.assertEqual(prepare_owned_local_release(self.draft(source), source=source).release.build, 7)

    def test_filters_includes_and_redirect_configuration_refuse_before_status(self):
        marker = self.root / "never-executed"
        command = "touch " + str(marker)
        for key, value in (("filter.inert.clean", command), ("filter.inert.process", command),
                           ("include.path", str(marker)), ("includeIf.onbranch:main.path", str(marker)), ("core.worktree", str(self.root)),
                           ("core.fsmonitor", command), ("extensions.worktreeConfig", "true")):
            with self.subTest(key=key):
                self.git("config", key, value)
                calls = []
                real = S.run_owned
                def run(argv, **kwargs):
                    calls.append(argv)
                    return real(argv, **kwargs)
                try:
                    with mock.patch.object(S, "run_owned", side_effect=run), self.assertRaises(S.LocalSourceError):
                        with self.observed(): self.fail("unsafe config admitted")
                    self.assertEqual(len(calls), 1)
                    self.assertNotIn("status", calls[0])
                    self.assertFalse(marker.exists())
                finally:
                    self.git("config", "--unset", key)

    def test_index_flags_and_gitlink_refuse_before_status(self):
        for flag in ("--assume-unchanged", "--skip-worktree"):
            self.git("update-index", flag, "release/version.properties")
            try:
                real = S.run_owned
                calls = []
                def run(argv, **kwargs):
                    calls.append(argv)
                    return real(argv, **kwargs)
                with mock.patch.object(S, "run_owned", side_effect=run), self.assertRaises(S.LocalSourceError):
                    with self.observed(): self.fail("index flag admitted")
                self.assertFalse(any("status" in argv for argv in calls))
            finally:
                self.git("update-index", "--no-" + flag[2:], "release/version.properties")
        head = self.git("rev-parse", "HEAD").strip().decode()
        self.git("update-index", "--add", "--cacheinfo", "160000," + head + ",submodule")
        with self.assertRaises(S.LocalSourceError):
            with self.observed(): self.fail("gitlink admitted")

    def test_detached_or_wrong_branch_and_saved_head_blob_mismatch_refuse(self):
        self.git("checkout", "--detach", "-q")
        with self.assertRaises(S.LocalSourceError):
            with self.observed(): self.fail("detached admitted")
        self.git("checkout", "-q", "-b", "wrong")
        with self.assertRaises(S.LocalSourceError):
            with self.observed(): self.fail("wrong branch admitted")
        self.git("checkout", "-q", "main")
        # Disk and saved input agree, but the actual committed version does not.
        self.version += b"# uncommitted\n"
        (self.root / self.data["version"]["source"]).write_bytes(self.version)
        with self.assertRaisesRegex(S.LocalSourceError, "^Local release source could not be verified$"):
            with self.observed(): self.fail("saved bytes replaced HEAD")

    def test_symlink_gitdir_and_alternate_objects_refuse_without_git_call(self):
        path = self.root / "release/version.properties"
        original = path.read_bytes()
        path.unlink(); path.symlink_to("mobile-release.json")
        with mock.patch.object(S, "run_owned") as run, self.assertRaises(S.LocalSourceError):
            with self.observed(): self.fail("symlink admitted")
        run.assert_not_called()
        path.unlink(); path.write_bytes(original)
        alternate = self.root / ".git/objects/info/alternates"
        alternate.write_text("/outside/private-sentinel\n")
        with mock.patch.object(S, "run_owned") as run, self.assertRaises(S.LocalSourceError):
            with self.observed(): self.fail("alternate admitted")
        run.assert_not_called()
        alternate.unlink()
        actual = self.root / ".git-original"
        (self.root / ".git").rename(actual)
        (self.root / ".git").write_text("gitdir: .git-original\n")
        with mock.patch.object(S, "run_owned") as run, self.assertRaises(S.LocalSourceError):
            with self.observed(): self.fail("redirected gitdir admitted")
        run.assert_not_called()

    def test_original_change_during_git_and_after_prepare_never_publishes(self):
        real = S.run_owned
        def move_head(argv, **kwargs):
            result = real(argv, **kwargs)
            if "status" in argv:
                self.git("commit", "--allow-empty", "-q", "-m", "moved")
            return result
        with mock.patch.object(S, "run_owned", side_effect=move_head), self.assertRaises(S.LocalSourceError):
            with self.observed(): self.fail("moved HEAD admitted")
        with self.assertRaises(S.LocalSourceError):
            with self.observed() as source:
                prepared = prepare_owned_local_release(self.draft(source), source=source)
                self.assertEqual(prepared.stage, "candidate")
                (self.root / self.data["version"]["source"]).write_bytes(b"changed after preparation")
        self.assertTrue(source.closed)

    def test_one_deadline_and_original_cancellation_or_unknown_process_are_preserved(self):
        real = S.run_owned
        now = [10.0]
        def advance(argv, **kwargs):
            result = real(argv, **kwargs)
            now[0] = 1000.0
            return result
        with mock.patch.object(S, "_now", side_effect=lambda: now[0]), \
                mock.patch.object(S, "run_owned", side_effect=advance) as run, self.assertRaises(S.LocalSourceError) as caught:
            with self.observed(timeout=2): self.fail("deadline renewed")
        self.assertEqual(caught.exception.reason, "deadline")
        self.assertEqual(run.call_count, 1)
        failure = KeyboardInterrupt()
        with mock.patch.object(S, "run_owned", side_effect=failure):
            with self.assertRaises(KeyboardInterrupt) as caught:
                with self.observed(): self.fail("failed original admitted")
            self.assertIs(caught.exception, failure)
        failure = ProcessCleanupError("private-sentinel", dispatched=True, contained=False)
        # The source preserves its actual failure. The existing outer invocation
        # may then project it to its own fatal ProcessError; those lifetime facts
        # must remain fatal rather than becoming an ordinary source refusal.
        with self.assertRaises(ProcessError) as outer:
            with invocation_custody(self.root, mode="build") as invocation:
                with invocation.project(signing_lease=None):
                    with mock.patch.object(S, "run_owned", side_effect=failure):
                        with self.assertRaises(ProcessCleanupError) as inner:
                            with S.observe_local_source(invocation, configuration_bytes=self.config,
                                                        version_bytes=self.version): pass
                        self.assertIs(inner.exception, failure)
                        raise inner.exception  # The actual caller propagates its original failure.
        self.assertFalse(outer.exception.contained)
        self.assertFalse(outer.exception.cleanup_complete)

    def test_split_index_refuses_and_packed_to_loose_cannot_replace_held_ref(self):
        self.git("update-index", "--split-index")
        with self.assertRaises(S.LocalSourceError) as caught:
            with self.observed(): self.fail("split index admitted")
        self.assertEqual(caught.exception.reason, "index")
        self.git("update-index", "--no-split-index")
        self.git("pack-refs", "--all", "--prune")
        ref = self.root / ".git/refs/heads/main"
        self.assertFalse(ref.exists())
        with self.assertRaises(S.LocalSourceError):
            with self.observed() as source:
                ref.write_text(source.observed.commit + "\n")
                with mock.patch.object(S, "run_owned") as run:
                    with self.assertRaises(S.LocalSourceError): source.check()
                    run.assert_not_called()
        self.assertTrue(source.closed)

    def test_command_failure_and_output_bounds_do_not_reflect_private_output(self):
        for code, stdout, stderr in ((1, b"private-sentinel", b"private-sentinel"),
                                     (0, b"x" * 65537, b""), (0, b"", b"private-sentinel")):
            def run(argv, **kwargs):
                return subprocess.CompletedProcess(argv, code, stdout, stderr)
            with mock.patch.object(S, "run_owned", side_effect=run) as native:
                with self.assertRaises(S.LocalSourceError) as caught:
                    with self.observed(): self.fail("bad command admitted")
                self.assertEqual(native.call_count, 1)
                self.assertEqual(caught.exception.reason, "command")
                self.assertNotIn("private-sentinel", str(caught.exception))

    def test_packed_nested_branch_retains_first_missing_ancestor_absence(self):
        self.data["source"]["candidateBranch"] = "release/candidate"
        self.git("checkout", "-q", "-b", "release/candidate")
        self.write_inputs()
        self.commit()
        self.git("pack-refs", "--all", "--prune")
        parent = self.root / ".git/refs/heads/release"
        self.assertFalse(parent.exists())
        with self.observed() as source:
            prepared = prepare_owned_local_release(self.draft(source), source=source)
            self.assertEqual((prepared.source.branch, prepared.source.ref),
                             ("release/candidate", "refs/heads/release/candidate"))
        self.assertTrue(source.closed)
        self.assertFalse(parent.exists())  # Admission never repairs Git layout.
        with self.assertRaises(S.LocalSourceError):
            with self.observed() as source:
                parent.mkdir()  # Even the ancestor alone invalidates absence.
                with mock.patch.object(S, "run_owned") as run:
                    with self.assertRaises(S.LocalSourceError): source.check()
                    run.assert_not_called()
        self.assertTrue(source.closed)

        parent.rmdir()
        heads = parent.parent
        heads.rmdir()
        with self.assertRaises(S.LocalSourceError):
            with self.observed() as source:
                self.assertEqual(prepare_owned_local_release(self.draft(source), source=source).source.branch,
                                 "release/candidate")
                self.assertFalse(heads.exists())
                heads.mkdir()
                with mock.patch.object(S, "run_owned") as run:
                    with self.assertRaises(S.LocalSourceError): source.check()
                    run.assert_not_called()
        self.assertTrue(source.closed)

    def test_z_original_close_unknown_is_never_retried_or_published(self):
        original_close = os.close
        selected = [None]
        attempts = []
        def close(fd):
            if fd == selected[0]:
                selected[0] = None
                attempts.append(fd)
                original_close(fd)  # The inert fault models a lost close result.
                raise OSError("private-close-sentinel")
            return original_close(fd)
        with mock.patch.object(S.os, "close", side_effect=close), self.assertRaises(ProcessError) as caught:
            with self.observed() as source:
                selected[0] = source.files[0][1].slot.number
        self.assertTrue(caught.exception.fatal)
        self.assertEqual(len(attempts), 1)
        self.assertTrue(source.closed)
        self.assertTrue(all(slot.number is None for reader in source.readers for slot in reader.descriptors))
        self.assertEqual(sum(slot.state == "UNKNOWN" for reader in source.readers for slot in reader.descriptors), 1)

    def test_wrong_input_refuses_before_commands_and_no_saved_owner_cannot_enter(self):
        self.config += b" "
        with mock.patch.object(S, "run_owned") as run, self.assertRaises(S.LocalSourceError):
            with self.observed(): self.fail("wrong original admitted")
        run.assert_not_called()
        with self.assertRaises(S.LocalSourceError):
            with S.observe_local_source(None, configuration_bytes=self.config, version_bytes=self.version): pass
        with self.assertRaises(ValidationError): prepare_owned_local_release(b"{}", source=object())


if __name__ == "__main__":
    unittest.main()
