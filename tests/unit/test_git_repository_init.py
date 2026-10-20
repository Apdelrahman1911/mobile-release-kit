"""Private filesystem + explicitly inert Git outputs; no Git/native process.

The ordinary no-replace directory primitive is real. Candidate creation here is
test setup, NOT a native Preparing ACK. Owner callbacks and command replies are
comparison fixtures only, not Store, permission or C/A/W finality evidence.
"""
from contextlib import ExitStack
import errno
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import git_repository_init as init
from mobile_release import git_service as core


CONFIG = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
CONFIG_QUERY = (b"core.repositoryformatversion\n0\0core.filemode\ntrue\0"
                b"core.bare\nfalse\0core.logallrefupdates\ntrue\0")


class FakeInit:
    def __init__(self, root):
        self.root, self.calls, self.after = root, [], None
        self.query = CONFIG_QUERY
        self.config = CONFIG

    def __call__(self, argv, **options):
        work = options["cwd"]
        template = work.parent / "empty-template"
        assert work.parent.parent == self.root and work != self.root
        assert work.parent.name.startswith(init.PRIVATE_PREFIX)
        assert not (self.root / ".git").exists()
        assert options["capture"] is True and options["text"] is False
        assert 0 < options["timeout"] <= 10 and options["execution_scope"] is None
        assert not any(k in options["environ"] for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_CONFIG_COUNT"))
        assert options["environ"]["HOME"] == str(template)
        assert options["environ"]["GIT_CONFIG_NOSYSTEM"] == "1"
        assert options["environ"]["GIT_CONFIG_GLOBAL"] == os.devnull
        assert options["environ"]["GIT_ALLOW_PROTOCOL"] == ""
        args = argv[11:]
        assert argv[1:11] == ["--no-pager", "--no-replace-objects", "-c", "core.hooksPath=" + os.devnull,
                             "-c", "protocol.allow=never", "-c", "maintenance.auto=false", "-c", "gc.auto=0"]
        self.calls.append((tuple(argv), dict(options["environ"]), work))
        if len(self.calls) == 1:
            assert args == ["init", "--quiet", "--initial-branch=main", "--object-format=sha1", "--template=" + str(template)]
            assert options["output_limit"] == 1024
            for name in init.DIRECTORIES[1:]:
                (work / ".git" / name).mkdir(mode=0o700)
            (work / ".git/HEAD").write_bytes(b"ref: refs/heads/main\n")
            (work / ".git/config").write_bytes(self.config)
            out = b""
        else:
            assert len(self.calls) == 2
            assert args == ["config", "--file", str(work / ".git/config"), "--no-includes", "--null", "--list"]
            assert options["output_limit"] == init.MAX_CONFIG
            out = self.query
        if self.after is not None:
            self.after(len(self.calls), work / ".git")
        return subprocess.CompletedProcess(argv, 0, out, b"")


class Owner:
    def __init__(self, root, review):
        self.root, self.review, self.intents = root, review, []
        self.operation_id = "inert-init-original"
        self.on_intent = None

    def check_current(self, root, action, expected_revision):
        assert (root, action, expected_revision) == (self.root, init.ACTION, self.review.plan.expected_revision)

    def record_intent(self, intent):
        self.intents.append(intent)
        if self.on_intent is not None:
            self.on_intent(intent)


class InitFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-git-init-inert-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "project"
        self.root.mkdir(mode=0o700)
        (self.root / "source.txt").write_bytes(b"unsaved ordinary project content\n")
        (self.root / "untracked").mkdir(mode=0o700)
        (self.root / "untracked/keep").write_bytes(b"keep exactly\n")
        self.fake, self.descriptors = FakeInit(self.root), []
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("No real Git process in Init DATA tests")))
        self.addCleanup(self.close_descriptors)

    def close_descriptors(self):
        # Fixture-only cleanup of actual borrowed descriptors. This neither
        # clears an original unknown outcome nor proves native source closure.
        for fd, expected in reversed(self.descriptors):
            try:
                actual = init.directory(os.fstat(fd))
            except OSError:
                continue
            self.assertEqual(actual, expected)
            os.close(fd)

    def candidate(self):
        outer = self.root / (init.PRIVATE_PREFIX + "a" * 32)
        for path in (outer, outer / "worktree", outer / "worktree/.git", outer / "empty-template"):
            path.mkdir(mode=0o700)
        originals = []
        for path in (self.root, outer, outer / "worktree", outer / "worktree/.git", outer / "empty-template"):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            expected = init.directory(os.fstat(fd))
            self.descriptors.append((fd, expected))
            originals.append(init.BorrowedDirectory(path, fd, expected))
        return init.BorrowedCandidate(*originals)

    def repository(self, *, candidate=None):
        return init.GitInitRepository(self.root, git_executable=Path("/inert/never-execute-git"),
            work_end=time.monotonic() + 45, tool_digest="a" * 64, candidate=candidate, _run=self.fake)

    def prepared(self):
        repository = self.repository()
        review = repository.prepare_init()
        repository.candidate = self.candidate()
        return repository, review, Owner(self.root, review)

    @staticmethod
    def apply(repository, review, owner):
        return repository.apply_init(review, owner, expected_digest=review.digest)

    def refuses(self, call, reason=None):
        with self.assertRaises(core.GitError) as caught:
            call()
        if reason is not None:
            self.assertEqual(caught.exception.reason, reason)


class InitTests(InitFixture):
    def test_prepare_is_readonly_without_git_or_candidate(self):
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*"))
        repository = self.repository()
        with patch.object(os, "mkdir", side_effect=AssertionError("Prepare cannot mkdir")), \
                patch.object(core, "_read", side_effect=AssertionError("Prepare does not read user files")):
            review = repository.prepare_init()
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(before, sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*")))
        self.assertEqual(review.plan.as_dict(), {"action": "initialize", "expectedRevision": review.plan.expected_revision,
                                               "initialBranch": "main", "objectFormat": "sha1"})
        self.assertEqual(repository._active_sessions, [])

    def test_existing_git_file_directory_alias_and_symlink_never_adopt(self):
        for kind, name in (("directory", ".git"), ("file", ".git"), ("link", ".git"), ("directory", ".GIT")):
            with self.subTest(kind=kind, name=name):
                path = self.root / name
                if kind == "directory": path.mkdir()
                elif kind == "link": path.symlink_to("missing-external-target")
                else: path.write_bytes(b"gitdir: /not/opened\n")
                self.refuses(lambda: self.repository().prepare_init(), "git-already-present")
                self.assertTrue(path.exists() or path.is_symlink())
                path.rmdir() if kind == "directory" else path.unlink()
        self.assertEqual(self.fake.calls, [])

    def test_enclosing_repo_bare_submodule_and_previous_candidate_refuse(self):
        parent_git = self.base / ".git"
        parent_git.mkdir()
        self.refuses(lambda: self.repository().prepare_init(), "git-already-present")
        parent_git.rmdir()
        for name in (".gitmodules", "commondir", "gitdir", init.PRIVATE_PREFIX + "b" * 32):
            with self.subTest(name=name):
                path = self.root / name; path.write_bytes(b"do not alter\n")
                self.refuses(lambda: self.repository().prepare_init())
                self.assertEqual(path.read_bytes(), b"do not alter\n"); path.unlink()
        (self.root / "HEAD").write_bytes(b"refs/heads/main\n"); (self.root / "objects").mkdir()
        self.refuses(lambda: self.repository().prepare_init(), "git-init-layout")
        self.assertEqual(self.fake.calls, [])

    def test_one_private_init_preserves_files_and_moves_original_directory_only(self):
        repository, review, owner = self.prepared()
        candidate = repository.candidate
        before = (self.root / "source.txt").read_bytes(), (self.root / "untracked/keep").read_bytes()
        # Ordinary edits made after Prepare are not silently staged or reset.
        (self.root / "new-user-file").write_bytes(b"later edit\n")
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement, result.reason, result.observation), ("succeeded", "settled", None, None))
        self.assertEqual(init.directory((self.root / ".git").lstat()), candidate.git.identity)
        self.assertFalse(candidate.git.path.exists())
        self.assertEqual(init.names(candidate.worktree.path), ())
        self.assertEqual(init.names(candidate.outer.path), ("empty-template", "worktree"))
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")
        self.assertEqual((self.root / ".git/config").read_bytes(), CONFIG)
        self.assertFalse((self.root / ".git/index").exists())
        self.assertEqual(init.names(self.root / ".git/objects/pack"), ())
        self.assertEqual(init.names(self.root / ".git/refs/heads"), ())
        self.assertEqual(before, ((self.root / "source.txt").read_bytes(), (self.root / "untracked/keep").read_bytes()))
        self.assertEqual((self.root / "new-user-file").read_bytes(), b"later edit\n")
        self.assertEqual(owner.intents, [result.intent])
        self.assertTrue(repository._transaction.acknowledged and repository._transaction.returned and repository._transaction.fsynced)
        self.assertEqual(len(self.fake.calls), 2)
        self.assertEqual(repository._active_sessions, [])
        self.refuses(lambda: self.apply(repository, review, owner), "authorization")

    def test_candidate_config_and_roster_must_be_fixed_relocatable_and_bounded(self):
        for query in (CONFIG_QUERY + b"core.worktree\n/tmp/private\0", CONFIG_QUERY + b"remote.origin.url\nhttps://example.invalid/r\0",
                      CONFIG_QUERY + b"include.path\nother\0", CONFIG_QUERY + b"extensions.objectformat\nsha256\0",
                      CONFIG_QUERY + b"core.filemode\nfalse\0", CONFIG_QUERY.replace(b"core.bare\nfalse", b"core.bare\ntrue")):
            with self.subTest(query=query):
                self.refuses(lambda: init.configuration(query))
        repository, review, owner = self.prepared()
        self.fake.after = lambda n, path: (path / "foreign").write_bytes(b"not owned") if n == 1 else None
        self.refuses(lambda: self.apply(repository, review, owner), "git-init-candidate")
        self.assertEqual(owner.intents, [])
        self.assertFalse(repository._transaction.attempted)
        self.assertFalse((self.root / ".git").exists())
        self.assertEqual((repository.candidate.git.path / "foreign").read_bytes(), b"not owned")

    def test_changed_root_or_foreign_git_before_apply_never_dispatches(self):
        repository, review, owner = self.prepared()
        (self.root / ".git").mkdir()
        self.refuses(lambda: self.apply(repository, review, owner), "git-already-present")
        self.assertEqual(self.fake.calls, [])
        self.assertTrue((self.root / ".git").is_dir())

    def test_missing_candidate_ack_never_attempts_move_or_replays(self):
        repository, review, owner = self.prepared()
        def reject(_): raise core.GitError("authorization")
        owner.on_intent = reject
        self.refuses(lambda: self.apply(repository, review, owner), "authorization")
        self.assertFalse(repository._transaction.acknowledged or repository._transaction.attempted)
        self.assertFalse((self.root / ".git").exists())
        self.assertTrue(repository.candidate.git.path.is_dir())
        self.refuses(lambda: self.apply(repository, review, owner), "authorization")
        self.assertEqual(len(self.fake.calls), 2)

    def test_currentness_is_repeated_after_candidate_ack(self):
        repository, review, owner = self.prepared()
        owner.on_intent = lambda _: (self.root / ".git").mkdir()
        self.refuses(lambda: self.apply(repository, review, owner), "git-already-present")
        self.assertTrue(repository._transaction.acknowledged)
        self.assertFalse(repository._transaction.attempted)
        self.assertEqual(init.names(self.root / ".git"), ())
        self.assertTrue(repository.candidate.git.path.is_dir())

    def test_real_no_replace_refuses_last_moment_collision_without_deleting_it(self):
        repository, review, owner = self.prepared()
        actual = init._rename_function()
        def raced(*args):
            (self.root / ".git").mkdir()
            (self.root / ".git/foreign").write_bytes(b"user data\n")
            actual(*args)
        with patch.object(init, "_rename_function", return_value=raced):
            with self.assertRaises(OSError) as caught:
                self.apply(repository, review, owner)
        self.assertEqual(caught.exception.errno, errno.EEXIST)
        self.assertTrue(repository._transaction.attempted and repository._unknown)
        self.assertFalse(repository._transaction.returned)
        self.assertEqual((self.root / ".git/foreign").read_bytes(), b"user data\n")
        self.assertTrue(repository.candidate.git.path.is_dir())

    def test_lost_move_return_and_fsync_failure_preserve_distinct_original_facts(self):
        repository, review, owner = self.prepared()
        actual = init._rename_function()
        def lost(*args):
            actual(*args)
            raise KeyboardInterrupt("inert lost directory move return")
        with patch.object(init, "_rename_function", return_value=lost), self.assertRaises(KeyboardInterrupt):
            self.apply(repository, review, owner)
        self.assertTrue(repository._unknown and repository._transaction.attempted)
        self.assertFalse(repository._transaction.returned or repository._transaction.fsynced)
        self.assertEqual(init.directory((self.root / ".git").lstat()), repository.candidate.git.identity)
        self.refuses(lambda: self.apply(repository, review, owner), "authorization")

    def test_fsync_failure_never_removes_published_directory(self):
        repository, review, owner = self.prepared()
        with patch.object(os, "fsync", side_effect=OSError("inert flush failure")), self.assertRaises(OSError):
            self.apply(repository, review, owner)
        self.assertTrue(repository._transaction.attempted and repository._transaction.returned)
        self.assertFalse(repository._transaction.fsynced)
        self.assertEqual(init.directory((self.root / ".git").lstat()), repository.candidate.git.identity)
        self.assertEqual((self.root / ".git/config").read_bytes(), CONFIG)
        self.refuses(lambda: self.apply(repository, review, owner), "authorization")

    def test_expired_original_review_or_foreign_repository_never_dispatches(self):
        repository, review, owner = self.prepared()
        other = self.repository(candidate=repository.candidate)
        self.refuses(lambda: self.apply(other, review, owner), "authorization")
        repository.work_end = time.monotonic() - 1
        self.refuses(lambda: self.apply(repository, review, owner), "deadline")
        self.assertEqual(self.fake.calls, [])


if __name__ == "__main__":
    unittest.main()
