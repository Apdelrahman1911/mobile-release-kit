"""Small real-Git fixtures only; never the checkout, credentials, network or native suites.

Most tests substitute only the process lifecycle with a synchronous fixture
runner: these prove Git/index/ref behavior, not installed/native finality. The
one explicit owned-runner test separately exercises the existing C/A/W owner.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from mobile_release.git_service import CommitIdentity, GitError, GitRepository
from mobile_release.owned_process import ProcessError


GIT = Path("/usr/bin/git")
IDENTITY = CommitIdentity("Synthetic Builder", "builder@example.invalid")


class Owner:
    def __init__(self, callback=None):
        self.operation_id = "synthetic-git-operation"
        self.checks = []
        self.intents = []
        self.callback = callback

    def check_current(self, root, action, expected_revision):
        self.checks.append((root, action, expected_revision))

    def record_intent(self, intent):
        self.intents.append(intent)
        if self.callback:
            self.callback(intent)


@unittest.skipUnless(GIT.is_file(), "requires explicit system Git, no installation")
class GitServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-git-lane-tests-")
        self.base = Path(self.temporary.name)
        os.chmod(self.base, 0o700)
        self.root = self.base / "fixture"
        self.root.mkdir(mode=0o700)
        self.commands = []
        self.env = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": ""}
        self.git("init", "--initial-branch=main")
        self.repository = GitRepository(self.root, git_executable=GIT, _run=self.runner)

    def tearDown(self):
        # Every actual fixture child uses subprocess.run and has returned.
        # Fake unknown receipts below do not create a native child/resource.
        self.temporary.cleanup()

    def git(self, *args, cwd=None, accepted=(0,)):
        result = subprocess.run([str(GIT), "-c", "core.hooksPath=" + os.devnull,
            "-c", "commit.gpgsign=false", "-c", "user.name=" + IDENTITY.name,
            "-c", "user.email=" + IDENTITY.email, *args], cwd=cwd or self.root, env=self.env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertIn(result.returncode, accepted, "synthetic Git fixture command failed")
        return result.stdout

    def runner(self, argv, *, cwd, environ, timeout, capture, text, output_limit, cancellation, execution_scope):
        self.assertTrue(capture)
        self.assertFalse(text)
        self.assertIsNone(execution_scope)
        self.assertNotIn("GH_TOKEN", environ)
        self.assertNotIn("GITHUB_TOKEN", environ)
        self.assertNotIn("GIT_DIR", environ)
        self.assertNotIn("GIT_CONFIG_COUNT", environ)
        self.commands.append(argv)
        result = subprocess.run(argv, cwd=cwd, env=environ, timeout=timeout,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if len(result.stdout) > output_limit or len(result.stderr) > output_limit:
            raise ProcessError("Synthetic bounded capture refusal", dispatched=True)
        return result

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return target

    def baseline(self):
        self.write("a.txt", "baseline a\n")
        self.write("b.txt", "baseline b\n")
        self.git("add", "--", "a.txt", "b.txt")
        self.git("commit", "-m", "Synthetic baseline")

    def stage(self, *paths, repository=None, owner=None):
        repository = repository or self.repository
        observation = repository.observe()
        plan = repository.prepare_stage(list(paths), expected_revision=observation.revision)
        return repository.apply(plan, owner or Owner())

    def test_unborn_stage_unstage_and_commit_preserve_worktree(self):
        self.write("new.txt", "new fixture\n")
        before = self.repository.observe()
        self.assertIsNone(before.head)
        self.assertEqual(before.branch, "refs/heads/main")
        staged = self.stage("new.txt")
        self.assertEqual(staged.state, "succeeded")
        plan = self.repository.prepare_unstage(["new.txt"], expected_revision=staged.observation.revision)
        unstaged = self.repository.apply(plan, Owner())
        self.assertEqual(unstaged.state, "succeeded")
        self.assertEqual(self.git("ls-files", "-z"), b"")
        self.assertEqual((self.root / "new.txt").read_text(), "new fixture\n")
        staged = self.stage("new.txt")
        plan = self.repository.prepare_commit("First reviewed commit", IDENTITY,
                                               expected_revision=staged.observation.revision)
        result = self.repository.apply(plan, Owner())
        self.assertEqual(result.state, "succeeded")
        self.assertEqual(result.settlement, "settled")
        self.assertEqual(result.intent.candidate_commit, self.git("rev-parse", "HEAD").decode().strip())
        self.assertFalse((self.root / ".git/HEAD.lock").exists())
        self.assertFalse((self.root / ".git/index.lock").exists())
        self.assertEqual(list((self.root / ".git").glob("mrk-git-*")), [])

    def test_selected_stage_and_unstage_preserve_unrelated_index_and_worktree(self):
        self.baseline()
        self.write("b.txt", "separately staged b\n")
        self.git("add", "--", "b.txt")
        b_staged = self.git("rev-parse", ":b.txt")
        self.write("b.txt", "unstaged b draft\n")
        self.write("a.txt", "selected a\n")
        result = self.stage("a.txt")
        self.assertEqual(result.state, "succeeded")
        self.assertEqual(self.git("rev-parse", ":b.txt"), b_staged)
        self.assertEqual((self.root / "b.txt").read_text(), "unstaged b draft\n")
        plan = self.repository.prepare_unstage(["a.txt"], expected_revision=result.observation.revision)
        result = self.repository.apply(plan, Owner())
        self.assertEqual(result.state, "succeeded")
        self.assertEqual(self.git("rev-parse", ":b.txt"), b_staged)
        self.assertEqual(self.git("show", ":a.txt"), b"baseline a\n")
        self.assertEqual((self.root / "a.txt").read_text(), "selected a\n")

    def test_whole_staged_commit_includes_reviewed_unrelated_entries_not_worktree(self):
        self.baseline()
        self.write("a.txt", "staged a\n")
        self.write("b.txt", "staged b\n")
        self.git("add", "--", "a.txt", "b.txt")
        original_index = (self.root / ".git/index").read_bytes()
        self.write("a.txt", "uncommitted draft a\n")
        before = self.repository.observe()
        plan = self.repository.prepare_commit("--not-a-git-option", IDENTITY, expected_revision=before.revision)
        self.assertEqual(plan.paths, ("a.txt", "b.txt"))
        self.assertTrue(plan.as_dict()["wholeIndex"])
        owner = Owner()
        result = self.repository.apply(plan, owner)
        self.assertEqual(result.state, "succeeded")
        self.assertEqual((self.root / ".git/index").read_bytes(), original_index)
        self.assertEqual(self.git("show", "HEAD:a.txt"), b"staged a\n")
        self.assertEqual(self.git("show", "HEAD:b.txt"), b"staged b\n")
        self.assertEqual((self.root / "a.txt").read_text(), "uncommitted draft a\n")
        self.assertEqual(len(owner.intents), 1)
        self.assertGreaterEqual(len(owner.checks), 2)
        with self.assertRaises(GitError) as failure:
            self.repository.apply(plan, owner)
        self.assertEqual(failure.exception.reason, "already-used")

    def test_linked_worktree_commit_holds_its_original_head_and_index_locks(self):
        self.baseline()
        linked = self.base / "linked"
        main_head = self.git("rev-parse", "HEAD")
        self.git("worktree", "add", "-b", "linked", str(linked))
        (linked / "a.txt").write_text("linked edit\n")
        repository = GitRepository(linked, git_executable=GIT, _run=self.runner)
        result = self.stage("a.txt", repository=repository)
        self.assertEqual(result.state, "succeeded")
        plan = repository.prepare_commit("Linked reviewed commit", IDENTITY,
                                         expected_revision=result.observation.revision)
        result = repository.apply(plan, Owner())
        self.assertEqual(result.state, "succeeded")
        self.assertEqual(result.observation.branch, "refs/heads/linked")
        self.assertEqual(self.git("rev-parse", "HEAD"), main_head)
        self.assertEqual(self.git("show", "HEAD:a.txt", cwd=linked), b"linked edit\n")

    def test_stale_same_stat_bytes_and_external_head_or_index_changes_refuse(self):
        self.baseline()
        path = self.write("a.txt", "first edit\n")
        observed = self.repository.observe()
        plan = self.repository.prepare_stage(["a.txt"], expected_revision=observed.revision)
        info = path.stat()
        path.write_text("other edit\n")
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
        with self.assertRaises(GitError) as failure:
            self.repository.apply(plan, Owner())
        self.assertEqual(failure.exception.reason, "stale-observation")
        self.assertEqual(self.git("show", ":a.txt"), b"baseline a\n")
        observed = self.repository.observe()
        plan = self.repository.prepare_stage(["a.txt"], expected_revision=observed.revision)
        self.write("b.txt", "external staged b\n")
        self.git("add", "--", "b.txt")
        with self.assertRaises(GitError):
            self.repository.apply(plan, Owner())

    def test_external_index_drift_at_publication_is_never_overwritten(self):
        self.baseline()
        self.write("a.txt", "selected\n")
        index = self.root / ".git/index"
        owner = Owner(lambda _: index.write_bytes(b"synthetic foreign index"))
        result = self.stage("a.txt", owner=owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual(result.reason, "stale-observation")
        self.assertEqual(index.read_bytes(), b"synthetic foreign index")
        self.assertFalse((self.root / ".git/index.lock").exists())

    def test_existing_index_and_head_locks_are_respected_and_foreign_locks_preserved(self):
        self.baseline()
        self.write("a.txt", "selected\n")
        for name in ("index.lock", "HEAD.lock"):
            lock = self.root / ".git" / name
            lock.write_bytes(b"foreign owner")
            result = self.stage("a.txt")
            self.assertEqual(result.state, "failed")
            self.assertEqual(result.reason, "locked")
            self.assertEqual(lock.read_bytes(), b"foreign owner")
            lock.unlink()

    def test_required_hooks_signing_and_filters_never_execute(self):
        self.baseline()
        self.write("a.txt", "selected\n")
        marker = self.base / "must-not-exist"
        hook = self.root / ".git/hooks/pre-commit"
        hook.write_text("#!/bin/sh\nprintf invoked > '" + str(marker) + "'\n")
        hook.chmod(0o700)
        with self.assertRaises(GitError) as failure:
            self.stage("a.txt")
        self.assertEqual(failure.exception.reason, "required-hooks")
        self.assertFalse(marker.exists())
        hook.unlink()
        self.git("config", "filter.synthetic.clean", "sh -c 'touch " + str(marker) + "'")
        self.git("config", "filter.synthetic.required", "true")
        self.write(".gitattributes", "*.txt filter=synthetic\n")
        with self.assertRaises(GitError) as failure:
            self.repository.observe()
        self.assertEqual(failure.exception.reason, "unsupported-filter")
        self.assertFalse(marker.exists())
        self.git("config", "--remove-section", "filter.synthetic")
        (self.root / ".gitattributes").unlink()
        self.git("add", "--", "a.txt")
        self.git("config", "commit.gpgsign", "true")
        observed = self.repository.observe()
        with self.assertRaises(GitError) as failure:
            self.repository.prepare_commit("No silent signing bypass", IDENTITY, expected_revision=observed.revision)
        self.assertEqual(failure.exception.reason, "required-signing")

    def test_literal_selected_names_not_glob_traversal_directory_or_symlink(self):
        self.baseline()
        self.write(":(glob)*", "literal name\n")
        self.write("unselected.txt", "leave untracked\n")
        result = self.stage(":(glob)*")
        self.assertEqual(result.state, "succeeded")
        tracked = self.git("ls-files", "-z").split(b"\0")
        self.assertIn(b":(glob)*", tracked)
        self.assertNotIn(b"unselected.txt", tracked)
        for path in (".", "../outside", "/absolute", ".git/config", "a//b", "a\\b"):
            with self.assertRaises(GitError):
                self.repository.prepare_stage([path], expected_revision=result.observation.revision)
        self.write("nested/file.txt", "nested\n")
        (self.root / "link").symlink_to("a.txt")
        for path in ("nested", "link"):
            with self.assertRaises(GitError):
                self.stage(path)

    def test_staged_deletion_can_be_unstaged_without_recreating_working_file(self):
        self.baseline()
        (self.root / "a.txt").unlink()
        result = self.stage("a.txt")
        self.assertEqual(result.state, "succeeded")
        plan = self.repository.prepare_unstage(["a.txt"], expected_revision=result.observation.revision)
        result = self.repository.apply(plan, Owner())
        self.assertEqual(result.state, "succeeded")
        self.assertEqual(self.git("show", ":a.txt"), b"baseline a\n")
        self.assertFalse((self.root / "a.txt").exists())

    def test_diff_is_bounded_private_safe_and_has_no_external_diff(self):
        self.baseline()
        self.write("a.txt", "ordinary changed line\n")
        observed = self.repository.observe()
        diff = self.repository.diff(["a.txt"], staged=False, expected_revision=observed.revision)
        self.assertIn("+ordinary changed line", diff.text)
        diff_argv = next(argv for argv in self.commands if "diff" in argv)
        self.assertIn("--no-ext-diff", diff_argv)
        self.assertIn("--no-textconv", diff_argv)
        self.write("a.txt", "-----BEGIN PRIVATE KEY-----\nINERT_SYNTHETIC_NOT_A_KEY\n")
        observed = self.repository.observe()
        diff = self.repository.diff(["a.txt"], staged=False, expected_revision=observed.revision)
        self.assertIsNone(diff.text)
        self.assertEqual(diff.withheld, "sensitive-content")
        with self.assertRaises(GitError) as failure:
            self.stage("a.txt")
        self.assertEqual(failure.exception.reason, "sensitive-content")

    def test_remote_url_credentials_and_ambient_git_routing_never_enter_results(self):
        self.baseline()
        self.git("remote", "add", "origin", "https://INERT_NOT_A_TOKEN@example.invalid/example/fixture.git")
        with patch.dict(os.environ, {"GIT_DIR": "/nonexistent-synthetic-redirect", "GIT_CONFIG_COUNT": "1",
                        "GH_TOKEN": "INERT_NOT_A_TOKEN", "GITHUB_TOKEN": "INERT_NOT_A_TOKEN"}):
            observed = self.repository.observe().as_dict()
        self.assertEqual(observed["remotes"], ["origin"])
        self.assertNotIn("INERT_NOT_A_TOKEN", repr(observed))
        self.assertNotIn("example.invalid", repr(observed))

    def test_detached_observation_is_supported_but_new_detached_commits_refuse(self):
        self.baseline()
        self.git("checkout", "--detach", "HEAD")
        self.write("a.txt", "detached staged\n")
        self.git("add", "--", "a.txt")
        observed = self.repository.observe()
        self.assertTrue(observed.as_dict()["detached"])
        with self.assertRaises(GitError) as failure:
            self.repository.prepare_commit("Detached unsupported", IDENTITY, expected_revision=observed.revision)
        self.assertEqual(failure.exception.reason, "unsupported-repository")

    def test_gitlinks_and_nested_repositories_are_not_adopted(self):
        self.baseline()
        head = self.git("rev-parse", "HEAD").decode().strip()
        self.git("update-index", "--add", "--cacheinfo", "160000," + head + ",module")
        observed = self.repository.observe()
        with self.assertRaises(GitError):
            self.repository.prepare_commit("No gitlink adoption", IDENTITY, expected_revision=observed.revision)
        nested = self.root / "nested"
        nested.mkdir()
        self.git("init", "--initial-branch=inner", cwd=nested)
        (nested / "file.txt").write_text("nested data\n")
        with self.assertRaises(GitError):
            self.stage("nested/file.txt")

    def test_sent_ref_timeout_is_read_only_reconciliation_not_a_retry(self):
        self.baseline()
        self.write("a.txt", "staged commit\n")
        self.git("add", "--", "a.txt")
        observed = self.repository.observe()
        plan = self.repository.prepare_commit("Synthetic timed reply", IDENTITY, expected_revision=observed.revision)
        original = self.repository._run
        sends = []
        def lost_reply(argv, **kwargs):
            result = original(argv, **kwargs)
            if "update-ref" in argv:
                sends.append(1)
                raise ProcessError("Synthetic settled lost reply", dispatched=True)
            return result
        self.repository._run = lost_reply
        result = self.repository.apply(plan, Owner())
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual(result.settlement, "settled")
        self.assertEqual(self.repository.reconcile(result.intent), "candidate-observed")
        self.assertEqual(sends, [1])
        with self.assertRaises(GitError):
            self.repository.apply(plan, Owner())
        self.assertEqual(sends, [1])

    def test_unknown_process_cannot_be_upgraded_by_ref_readback(self):
        self.baseline()
        self.write("a.txt", "staged commit\n")
        self.git("add", "--", "a.txt")
        observed = self.repository.observe()
        plan = self.repository.prepare_commit("Synthetic unknown receipt", IDENTITY, expected_revision=observed.revision)
        original = self.repository._run
        def unknown(argv, **kwargs):
            result = original(argv, **kwargs)
            if "update-ref" in argv:
                raise ProcessError("Synthetic unknown lifecycle", dispatched=True, contained=False, cleanup_complete=False)
            return result
        self.repository._run = unknown
        result = self.repository.apply(plan, Owner())
        self.assertEqual((result.state, result.settlement), ("unknown", "unknown"))
        with self.assertRaises(GitError) as failure:
            self.repository.reconcile(result.intent)
        self.assertEqual(failure.exception.reason, "unknown")
        self.assertTrue((self.root / ".git/index.lock").exists())
        # The actual fixture command HAS returned; close just the fake-retained
        # fixture resources so this test does not leak a real descriptor.
        for transaction in self.repository._retained:
            transaction.close()
        for session in self.repository._retained_sessions:
            if session.frozen is not None:
                session.frozen.close()

    def test_original_owned_runner_observes_only_the_synthetic_repository(self):
        self.baseline()
        repository = GitRepository(self.root, git_executable=GIT)
        observed = repository.observe()
        self.assertEqual(observed.branch, "refs/heads/main")
        self.assertEqual(observed.head, self.git("rev-parse", "HEAD").decode().strip())
        self.assertEqual(observed.changes, ())

    def test_head_switch_at_cas_never_changes_the_newly_selected_branch(self):
        self.baseline()
        old = self.git("rev-parse", "HEAD").decode().strip()
        self.git("branch", "other")
        self.write("a.txt", "reviewed main edit\n")
        self.git("add", "--", "a.txt")
        observed = self.repository.observe()
        plan = self.repository.prepare_commit("Pinned branch only", IDENTITY, expected_revision=observed.revision)
        original = self.repository._run
        def switch_at_send(argv, **kwargs):
            if "update-ref" in argv:
                self.git("symbolic-ref", "HEAD", "refs/heads/other")
            return original(argv, **kwargs)
        self.repository._run = switch_at_send
        result = self.repository.apply(plan, Owner())
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual(result.intent.expected_ref, "refs/heads/main")
        self.assertEqual(self.git("rev-parse", "refs/heads/other").decode().strip(), old)
        self.assertEqual(self.git("rev-parse", "refs/heads/main").decode().strip(), result.intent.candidate_commit)

    def test_external_branch_cas_drift_is_preserved_without_rollback(self):
        self.baseline()
        old = self.git("rev-parse", "HEAD").decode().strip()
        tree = self.git("rev-parse", "HEAD^{tree}").decode().strip()
        external = self.git("commit-tree", tree, "-p", old, "-m", "External synthetic commit").decode().strip()
        self.write("a.txt", "reviewed main edit\n")
        self.git("add", "--", "a.txt")
        observed = self.repository.observe()
        plan = self.repository.prepare_commit("Must compare old ref", IDENTITY, expected_revision=observed.revision)
        original = self.repository._run
        def drift_at_send(argv, **kwargs):
            if "update-ref" in argv:
                self.git("update-ref", "refs/heads/main", external, old)
            return original(argv, **kwargs)
        self.repository._run = drift_at_send
        result = self.repository.apply(plan, Owner())
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual(self.git("rev-parse", "HEAD").decode().strip(), external)

    def test_replaced_head_lock_is_not_deleted(self):
        self.baseline()
        self.write("a.txt", "reviewed\n")
        self.git("add", "--", "a.txt")
        observed = self.repository.observe()
        plan = self.repository.prepare_commit("Foreign lock remains", IDENTITY, expected_revision=observed.revision)
        lock = self.root / ".git/HEAD.lock"
        def replace_lock(_):
            lock.unlink()
            lock.write_bytes(b"foreign lock")
        result = self.repository.apply(plan, Owner(replace_lock))
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual(lock.read_bytes(), b"foreign lock")

    def test_concurrent_original_filter_config_never_reaches_filter_capable_commands(self):
        self.baseline()
        marker = self.base / "late-filter-must-not-run"
        self.write("a.txt", "work edit\n")
        self.write(".gitattributes", "*.txt filter=late\n")
        original = self.repository._run
        injected = []
        def change_before_status(argv, **kwargs):
            if "status" in argv and not injected:
                injected.append(True)
                self.git("config", "filter.late.clean", "sh -c 'touch " + str(marker) + "'")
                self.git("config", "filter.late.required", "true")
            return original(argv, **kwargs)
        self.repository._run = change_before_status
        with self.assertRaises(GitError) as failure:
            self.repository.observe()
        self.assertEqual(failure.exception.reason, "stale-observation")
        self.assertFalse(marker.exists())
        self.git("config", "--remove-section", "filter.late")
        (self.root / ".gitattributes").unlink()
        self.repository._run = original
        observed = self.repository.observe()
        plan = self.repository.prepare_stage(["a.txt"], expected_revision=observed.revision)
        before = (self.root / ".git/index").read_bytes()
        def change_before_add(argv, **kwargs):
            if "add" in argv:
                self.git("config", "filter.late.clean", "sh -c 'touch " + str(marker) + "'")
                self.git("config", "filter.late.required", "true")
                self.write(".gitattributes", "*.txt filter=late\n")
            return original(argv, **kwargs)
        self.repository._run = change_before_add
        result = self.repository.apply(plan, Owner())
        self.assertEqual(result.state, "failed")
        self.assertFalse(marker.exists())
        self.assertEqual((self.root / ".git/index").read_bytes(), before)

    def test_noncanonical_or_duplicate_worktree_config_switches_fail_before_status(self):
        self.baseline()
        config = self.root / ".git/config.worktree"
        config.write_text('[filter "synthetic"]\nclean = must-never-execute\nrequired = true\n[commit]\ngpgsign = true\n')
        for value in ("1", "yes", "on", ""):
            self.git("config", "extensions.worktreeConfig", value)
            self.commands.clear()
            with self.assertRaises(GitError) as failure:
                self.repository.observe()
            self.assertEqual(failure.exception.reason, "unsupported-repository")
            self.assertFalse(any("status" in argv for argv in self.commands))
        self.git("config", "extensions.worktreeConfig", "true")
        self.git("config", "--add", "extensions.worktreeConfig", "false")
        with self.assertRaises(GitError) as failure:
            self.repository.observe()
        self.assertEqual(failure.exception.reason, "unsupported-repository")

    def test_active_git_operations_refuse_commit_and_absence_is_revision_bound(self):
        self.baseline()
        self.write("a.txt", "staged for review\n")
        self.git("add", "--", "a.txt")
        for name in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD",
                     "rebase-merge", "rebase-apply", "sequencer"):
            marker = self.root / ".git" / name
            if name in ("rebase-merge", "rebase-apply", "sequencer"):
                marker.mkdir()
            else:
                marker.write_bytes(self.git("rev-parse", "HEAD"))
            observed = self.repository.observe()
            self.assertIn("operation-in-progress", observed.restrictions)
            self.commands.clear()
            with self.assertRaises(GitError) as failure:
                self.repository.prepare_commit("Not a merge continuation", IDENTITY,
                                               expected_revision=observed.revision)
            self.assertEqual(failure.exception.reason, "operation-in-progress")
            self.assertFalse(any("commit-tree" in argv or "update-ref" in argv for argv in self.commands))
            self.assertTrue(marker.exists())
            marker.rmdir() if marker.is_dir() else marker.unlink()
        observed = self.repository.observe()
        plan = self.repository.prepare_commit("Reviewed before external merge", IDENTITY,
                                               expected_revision=observed.revision)
        marker = self.root / ".git/MERGE_HEAD"
        marker.write_bytes(self.git("rev-parse", "HEAD"))
        self.commands.clear()
        with self.assertRaises(GitError) as failure:
            self.repository.apply(plan, Owner())
        self.assertEqual(failure.exception.reason, "stale-observation")
        self.assertFalse(any("commit-tree" in argv or "update-ref" in argv for argv in self.commands))
        self.assertTrue(marker.exists())

    def test_cleanup_close_interruption_retires_original_fd_route_and_retains_owner(self):
        self.baseline()
        self.write("a.txt", "selected\n")
        observed = self.repository.observe()
        plan = self.repository.prepare_stage(["a.txt"], expected_revision=observed.revision)
        lock_identity = []
        def record(_):
            info = (self.root / ".git/index.lock").stat()
            lock_identity.append((info.st_dev, info.st_ino))
        original_close = os.close
        interrupted = []
        def close_then_interrupt(fd):
            info = os.fstat(fd)
            match = bool(lock_identity) and (info.st_dev, info.st_ino) == lock_identity[0] and not interrupted
            original_close(fd)
            if match:
                interrupted.append(fd)
                raise KeyboardInterrupt("synthetic cleanup interruption")
        with patch("mobile_release.git_service.os.close", side_effect=close_then_interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.repository.apply(plan, Owner(record))
        self.assertTrue(interrupted)
        self.assertTrue(self.repository._unknown)
        self.assertTrue(self.repository._retained)
        transaction = self.repository._retained[0]
        self.assertEqual(len(transaction.uncertain_closes), 1)
        self.assertNotIn(interrupted[0], [fd for _, fd, _ in transaction.locks])
        with self.assertRaises(GitError):
            self.repository.observe()
        # Here the injected fixture DID close the original fd before raising;
        # these explicit fixture resources have no live child. A replacement
        # descriptor must not be consumed by replaying the retired close route.
        replacement = os.open(self.base / "replacement", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            transaction.close()
            os.fstat(replacement)
        finally:
            original_close(replacement)
        for session in self.repository._retained_sessions:
            if session.frozen is not None:
                session.frozen.close()


if __name__ == "__main__":
    unittest.main()
