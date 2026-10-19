"""Fake-tool DATA tests on private, synthetic plain files only.

No Git executable, native admission, command owner, network or user repository
is exercised. The subprocess seam is forbidden for the entire test lifetime.
These tests cannot establish installed Git/C/A/W/native correctness.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import git_repository_read as read
from mobile_release import git_service as core
from mobile_release.owned_process import ProcessCleanupError

HEAD = "1" * 40
UPSTREAM = "2" * 40
PARENT = "3" * 40


class FakeGit:
    def __init__(self):
        self.calls = []
        self.config = {"core.repositoryformatversion": (b"0",), "core.bare": (b"false",),
            "remote.Origin.url": (b"https://synthetic-user:synthetic-password@example.invalid/never-contacted",),
            "remote.Origin.fetch": (b"+refs/heads/*:refs/remotes/Origin/*",),
            "branch.Main.remote": (b"Origin",), "branch.Main.merge": (b"refs/heads/Main",)}
        self.head = HEAD
        self.branch = "refs/heads/Main"
        self.upstream = UPSTREAM
        self.status = b""
        self.index = b""
        self.counts = b"2\t3\n"
        self.history = f"1234 {HEAD} {PARENT}\n1233 {PARENT}\n".encode()
        self.diff = b"diff --git a/a.txt b/a.txt\n-old\n+new\n"
        self.callback = None
        self.fail = None

    def __call__(self, argv, **kwargs):
        split = next(index for index, arg in enumerate(argv) if arg.startswith("--work-tree=")) + 1
        args = argv[split:]
        frozen = Path(next(arg.removeprefix("--git-dir=") for arg in argv if arg.startswith("--git-dir=")))
        self.calls.append((tuple(args), frozen, dict(kwargs["environ"])))
        if self.fail is not None:
            raise self.fail
        if self.callback is not None:
            self.callback(args, frozen)
        code, out = 0, b""
        if args[0] == "config":
            assert args == ["config", "--file", str(frozen / read._CONFIG_FILE), "--no-includes", "--null", "--list"]
            out = b"".join(key.encode() + b"\n" + value + b"\0" for key, values in self.config.items() for value in values)
        elif args == ["--version"]:
            out = b"git version 2.49.0 (Apple Git-154)\n"
        elif args == ["rev-parse", "--shared-index-path"]:
            out = b""
        elif args == ["symbolic-ref", "--quiet", "HEAD"]:
            if self.branch is None:
                code = 1
            else:
                assert (frozen / "HEAD").read_bytes() == (self.branch and f"ref: {self.branch}\n".encode())
                out = (self.branch + "\n").encode()
        elif args[:2] == ["symbolic-ref", "--quiet"]:
            code = 1
        elif args == ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]:
            code, out = (1, b"") if self.head is None else (0, (self.head + "\n").encode())
        elif args[:3] == ["show-ref", "--verify", "--quiet"]:
            code = 1 if self.head is None else 0
        elif args == ["ls-files", "--stage", "-z"]:
            out = self.index
        elif args[0] == "status":
            out = self.status
        elif args[0] == "for-each-ref":
            out = (self.branch + "\0refs/remotes/Origin/Main\0Origin\0refs/heads/Main\0\n").encode()
        elif args[:4] == ["rev-parse", "--verify", "--quiet", "--end-of-options"]:
            code, out = (1, b"") if self.upstream is None else (0, (self.upstream + "\n").encode())
        elif args[:3] == ["rev-list", "--left-right", "--count"]:
            out = self.counts
        elif args[:3] == ["rev-list", "--timestamp", "--parents"]:
            out = self.history
        elif args[0] == "check-attr":
            out = b"".join(path.encode() + b"\0filter\0unspecified\0" for path in args[4:])
        elif args[0] == "diff":
            out = self.diff
        else:
            raise AssertionError("unexpected inert command shape")
        return subprocess.CompletedProcess(argv, code, out, b"")


class ReadFacetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-git-read-data-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "project"
        self.root.mkdir(mode=0o700)
        for path in (".git", ".git/objects", ".git/objects/info", ".git/objects/pack", ".git/refs",
                     ".git/refs/heads", ".git/refs/remotes", ".git/refs/remotes/Origin"):
            (self.root / path).mkdir(mode=0o700)
        self.write(".git/HEAD", b"ref: refs/heads/Main\n")
        self.write(".git/config", b"[core]\nbare=false\n")
        self.write(".git/refs/heads/Main", (HEAD + "\n").encode())
        self.write(".git/refs/remotes/Origin/Main", (UPSTREAM + "\n").encode())
        self.write(".git/index", b"synthetic-data-not-a-git-index")
        self.fake = FakeGit()
        self.repository = self.repo()
        # Keep ALL scratch under this synthetic test root, never ambient home.
        original = tempfile.mkdtemp
        self.scratch = patch.object(core.tempfile, "mkdtemp", side_effect=lambda **kw: original(dir=self.base, **kw))
        self.scratch.start()
        self.addCleanup(self.scratch.stop)
        self.process = patch("subprocess.Popen", side_effect=AssertionError("no native or Git process in DATA tests"))
        self.process.start()
        self.addCleanup(self.process.stop)

    def repo(self):
        return read.GitReadRepository(self.root, git_executable=Path("/never-executed/git"),
                                      work_end=time.monotonic() + 45, _run=self.fake)

    def write(self, relative, value):
        (self.root / relative).write_bytes(value)

    def failure(self, expected, callback):
        with self.assertRaises(core.GitError) as raised:
            callback()
        self.assertEqual(raised.exception.reason, expected)

    def test_first_config_census_and_all_later_reads_use_private_frozen_git(self):
        result = self.repository.observe()
        self.assertEqual(result.observation.head, HEAD)
        self.assertEqual(result.observation.branch, "refs/heads/Main")
        self.assertEqual(result.observation.remotes, ("Origin",))
        self.assertEqual(result.tracking, read.Tracking("complete", "Origin", "refs/heads/Main", "refs/remotes/Origin/Main", UPSTREAM, 2, 3))
        self.assertEqual(self.fake.calls[0][0][0], "config")
        for args, frozen, env in self.fake.calls:
            self.assertNotEqual(frozen, self.root / ".git")
            self.assertTrue(frozen.is_relative_to(self.base))
            self.assertEqual(env["HOME"], str(frozen))
            self.assertEqual(env["XDG_CONFIG_HOME"], str(frozen))
            self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(env["GIT_CONFIG_SYSTEM"], os.devnull)
            self.assertEqual(env["GIT_ALLOW_PROTOCOL"], "")
            self.assertNotIn("SSH_AUTH_SOCK", env)
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertTrue(read._read_arguments(list(args), frozen / read._CONFIG_FILE))
            self.assertFalse(frozen.exists(), "normal read should retire its own exact scratch")
        public = json.dumps(result.as_dict())
        for forbidden in ("synthetic-user", "synthetic-password", "example.invalid", str(self.root), "--version"):
            self.assertNotIn(forbidden, public)
        self.assertEqual(result.as_dict()["basis"], "local-refs-no-fetch")

    def test_config_includes_filters_worktree_and_unknown_extensions_refuse_before_repository_commands(self):
        for name, value, expected in (("include.path", b"/never-read/private", "unsupported-repository"),
                ("includeIf.gitdir:foreign.path", b"/never-read/private", "unsupported-repository"),
                ("filter.custom.process", b"never execute", "unsupported-filter"),
                ("core.worktree", b"/foreign", "unsupported-repository"),
                ("extensions.worktreeconfig", b"true", "unsupported-repository"),
                ("extensions.worktreeconfig", b"yes", "unsupported-repository"),
                ("extensions.unknown", b"value", "unsupported-repository"),
                ("remote.Origin.promisor", b"false", "unsupported-repository")):
            with self.subTest(name=name, value=value):
                self.fake.calls.clear()
                self.fake.config[name] = (value,)
                self.failure(expected, self.repo().observe)
                self.assertEqual([call[0][0] for call in self.fake.calls], ["config"])
                del self.fake.config[name]

    def test_changed_original_configuration_never_becomes_later_executable_configuration(self):
        copied = []
        def change(args, frozen):
            if args[0] == "config":
                copied.append((frozen / read._CONFIG_FILE).read_bytes())
                self.write(".git/config", b"[include]\npath=/never-opened/foreign\n")
            elif args[0] != "--version":
                self.assertNotIn(b"never-opened", (frozen / "config").read_bytes())
        self.fake.callback = change
        self.failure("stale-observation", self.repository.observe)
        self.assertEqual(copied, [b"[core]\nbare=false\n"])
        self.assertFalse(any(call[0][0] == "status" for call in self.fake.calls))

    def test_same_symbolic_head_survives_every_private_config_refresh(self):
        observed = self.repository.observe()
        self.assertEqual(observed.observation.branch, "refs/heads/Main")
        private_heads = []
        self.fake.callback = lambda args, path: private_heads.append((path / "HEAD").read_bytes()) if args[0] == "symbolic-ref" else None
        self.repo().history(expected_revision=observed.observation.revision)
        self.assertTrue(private_heads)
        self.assertEqual(set(private_heads), {b"ref: refs/heads/Main\n"})

    def test_detached_unborn_unconfigured_and_gone_are_not_zero_counts(self):
        observed = self.repository.observe()
        self.fake.upstream = None
        gone = self.repo().observe()
        self.assertEqual(gone.tracking.state, "gone")
        self.assertIsNone(gone.tracking.ahead)
        self.assertEqual(gone.observation.revision, observed.observation.revision)
        self.fake.branch = None
        self.write(".git/HEAD", (HEAD + "\n").encode())
        self.assertEqual(self.repo().observe().tracking.state, "detached")
        self.fake.branch, self.fake.head = "refs/heads/Main", None
        self.write(".git/HEAD", b"ref: refs/heads/Main\n")
        (self.root / ".git/refs/heads/Main").unlink()
        unborn = self.repo().observe()
        self.assertEqual(unborn.tracking.state, "unborn")
        self.assertEqual(self.repo().history(expected_revision=unborn.observation.revision).commits, ())
        self.fake.head = HEAD
        self.write(".git/refs/heads/Main", (HEAD + "\n").encode())
        del self.fake.config["branch.Main.remote"]
        del self.fake.config["branch.Main.merge"]
        self.assertEqual(self.repo().observe().tracking.state, "not-configured")

    def test_shallow_and_walk_limit_do_not_invent_complete_ahead_behind(self):
        self.write(".git/shallow", (PARENT + "\n").encode())
        value = self.repository.observe()
        self.assertEqual(value.tracking.state, "shallow")
        self.assertIsNone(value.tracking.ahead)
        self.assertFalse(any(call[0][0] == "rev-list" for call in self.fake.calls))
        (self.root / ".git/shallow").unlink()
        self.fake.counts = b"10000\t1\n"
        value = self.repo().observe()
        self.assertEqual(value.tracking.state, "limit")
        self.assertIsNone(value.tracking.behind)

    def test_whole_reference_inventory_drift_refuses_even_when_head_is_unchanged(self):
        def change(args, _):
            if args[:3] == ["rev-list", "--left-right", "--count"]:
                self.write(".git/refs/remotes/Origin/Main", (PARENT + "\n").encode())
        self.fake.callback = change
        self.failure("stale-observation", self.repository.observe)

    def test_partial_common_and_symbolic_layouts_refuse_without_any_git_call(self):
        for relative in (".git/commondir", ".git/objects/info/alternates", ".git/objects/info/http-alternates", ".git/objects/pack/fixture.promisor"):
            with self.subTest(relative=relative):
                self.fake.calls.clear()
                self.write(relative, b"inert")
                self.failure("unsupported-repository", self.repo().observe)
                self.assertEqual(self.fake.calls, [])
                (self.root / relative).unlink()
        path = self.root / ".git/refs/heads/Main"
        path.unlink()
        path.symlink_to(self.root / ".git/HEAD")
        self.failure("unsupported-path", self.repo().observe)
        self.assertEqual(self.fake.calls, [])

    def test_read_only_view_keeps_hook_policy_but_never_offers_mutations(self):
        (self.root / ".git/hooks").mkdir()
        self.write(".git/hooks/pre-commit", b"not a program\n")
        (self.root / ".git/hooks/pre-commit").chmod(0o700)
        result = self.repository.observe()
        self.assertIn("required-hooks", result.observation.restrictions)
        self.fake.calls.clear()
        for name in ("prepare_stage", "prepare_unstage", "prepare_commit", "apply", "reconcile"):
            self.failure("invalid-input", lambda: getattr(self.repository, name)({"force": True}))
        self.assertEqual(self.fake.calls, [])

    def test_history_is_head_anchored_bounded_and_message_author_free(self):
        before = self.repository.observe()
        result = self.repo().history(expected_revision=before.observation.revision)
        self.assertEqual(result.commits, (read.HistoryEntry(HEAD, (PARENT,), 1234), read.HistoryEntry(PARENT, (), 1233)))
        self.assertEqual(set(result.as_dict()["commits"][0]), {"oid", "parents", "committedAt"})
        self.assertEqual(result.as_dict()["withheld"], ["message", "author", "email", "signature"])
        self.fake.history = b"sensitive arbitrary commit text\n"
        self.failure("response-invalid", lambda: self.repo().history(expected_revision=before.observation.revision))

    def test_original_diff_revision_and_sensitivity_contract_are_preserved(self):
        self.write("a.txt", b"new\n")
        self.fake.status = b" M a.txt\0"
        self.fake.index = ("100644 " + HEAD + " 0\ta.txt\0").encode()
        before = self.repository.observe()
        result = self.repo().diff(["a.txt"], staged=False, expected_revision=before.observation.revision)
        self.assertEqual(result.revision, before.observation.revision)
        self.assertEqual(result.text, self.fake.diff.decode())
        self.fake.diff = b"+github_pat_" + b"synthetic" * 8 + b"\n"
        hidden = self.repo().diff(["a.txt"], staged=False, expected_revision=before.observation.revision)
        self.assertEqual((hidden.text, hidden.withheld), (None, "sensitive-content"))

    def test_expired_original_deadline_cannot_start_or_renew_work(self):
        self.repository.work_end = time.monotonic() - 1
        self.failure("deadline", self.repository.observe)
        self.assertEqual(self.fake.calls, [])

    def test_fatal_original_command_custody_stays_unknown_and_cannot_retry(self):
        self.fake.fail = ProcessCleanupError("inert fixed failure")
        with self.assertRaises(ProcessCleanupError):
            self.repository.observe()
        self.assertTrue(self.repository._unknown)
        count = len(self.fake.calls)
        self.fake.fail = None
        self.failure("unknown", self.repository.observe)
        self.assertEqual(len(self.fake.calls), count)
        self.assertEqual(len(self.repository._retained_sessions), 1)

    def test_scan_close_lost_return_stays_on_original_and_is_never_retried(self):
        actual_scandir = os.scandir
        closed = []
        signal = KeyboardInterrupt()
        class Scan:
            def __init__(self, path):
                self.iterator = actual_scandir(path)
            def __iter__(self):
                return self.iterator
            def close(self):
                closed.append(self)
                self.iterator.close()
                raise signal  # Actual test iterator closed; its return is lost.
        with patch.object(read.os, "scandir", Scan):
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.repository.observe()
            self.assertIs(raised.exception, signal)
            self.failure("unknown", self.repository.observe)
        self.assertEqual(len(closed), 1)
        self.assertEqual(self.fake.calls, [])
        original = self.repository._retained_sessions[0].scans[0]
        self.assertTrue(original.close_claimed)
        self.assertFalse(original.closed)
        self.assertIs(original.iterator, closed[0])

    def test_returned_failed_scan_open_has_no_retained_descriptor_or_retry(self):
        with patch.object(read.os, "scandir", side_effect=FileNotFoundError()):
            with self.assertRaises(FileNotFoundError):
                self.repository.observe()
        self.assertEqual(self.fake.calls, [])
        self.assertFalse(self.repository._unknown)
        self.assertEqual(self.repository._active_sessions, [])

    def test_finite_ref_inventory_refuses_before_any_command(self):
        for index in range(read.MAX_LOOSE_REFS):
            self.write(f".git/refs/heads/fixture{index}", (HEAD + "\n").encode())
        self.failure("limit", self.repository.observe)
        self.assertEqual(self.fake.calls, [])

    def test_attribute_parent_symlink_and_deprecated_grafts_refuse_before_git(self):
        info = self.root / ".git/info"
        info.symlink_to(self.base, target_is_directory=True)
        self.failure("unsupported-repository", self.repository.observe)
        self.assertEqual(self.fake.calls, [])
        info.unlink()
        info.mkdir(mode=0o700)
        (info / "grafts").write_bytes((HEAD + " " + PARENT + "\n").encode())
        self.failure("unsupported-repository", self.repo().observe)
        self.assertEqual(self.fake.calls, [])


class ReadSyntaxTests(unittest.TestCase):
    def test_finite_commands_reject_option_injection_and_every_write_network_variant(self):
        config = Path("/inert-private/mrk-read-original-config")
        for args in (["fetch"], ["push"], ["reset", "--hard"], ["add", "--", "a"],
                     ["config", "--global", "--list"], ["status", "--short"], ["diff", "--ext-diff"],
                     ["rev-list", "--all"], ["symbolic-ref", "HEAD", "refs/heads/new"],
                     ["rev-parse", "--verify", "--quiet", "--end-of-options", "--evil^{commit}"],
                     ["--version", "--help"], ["ls-files", "--stage", "--debug"], None, [],
                     ["symbolic-ref", "--quiet", "refs/heads/\ud800"], ["--version", None]):
            with self.subTest(args=args):
                self.assertFalse(read._read_arguments(args, config))
        self.assertTrue(read._read_arguments(["config", "--file", str(config), "--no-includes", "--null", "--list"], config))
        self.assertTrue(read._read_arguments(["rev-parse", "--verify", "--quiet", "--end-of-options", "refs/remotes/Origin/Main^{commit}"], config))

    def test_config_subsection_case_is_not_lowercased_and_controls_are_not_executable(self):
        parsed = read._configuration(b"Remote.Origin.URL\nprivate\0branch.Main.Remote\nOrigin\0core.bare\nfalse\0")
        self.assertIn("remote.Origin.url", parsed)
        self.assertIn("branch.Main.remote", parsed)
        self.assertNotIn("remote.origin.url", parsed)
        for raw in (b"carriage\rreturn", b"zero\0byte", b"control\x01byte"):
            with self.subTest(raw=raw), self.assertRaises(core.GitError):
                read._quoted(raw)
