"""Fetch-core fixtures: private files, inert Git/ACK replies, no subprocess.

Pack bytes are deliberately NOT Git data. These tests exercise fixed command
selection, comparisons, file lifetime and refusal paths; they do not establish
stock-Git, socket/FD8, native SourceBook, journal or remote qualification.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import git_fetch_transaction as transaction
from mobile_release import git_repository_fetch as fetch
from mobile_release import git_repository_read as read
from mobile_release import git_service as core
from mobile_release.git_remote_transport import Target
from mobile_release.git_remote_wire import Selection
from mobile_release.owned_process import ProcessCleanupError
import test_git_repository_local as local_fixture
from test_git_repository_switch import identity_hook

HEAD, OLD, NEW, PACK, BLOB = ("1" * 40, "6" * 40, "7" * 40, "8" * 40, "9" * 40)
REF = "refs/remotes/origin/main"
GIT = Path("/never-executed/git")
LAUNCH = transaction.Launch(Path("/never executed/python"), Path("/never executed/bootstrap.py"),
                            Path("/never executed/core"), Path("/never executed/runtime"))


class FakeGit(local_fixture.FakeGit):
    def __init__(self, root):
        super().__init__(root)
        self.config.update({"core.logallrefupdates": (b"true",), "user.name": (b"Fixture Name",),
            "user.email": (b"fixture@example.invalid",), "remote.origin.url": (b"https://github.com/fixture/project.git",),
            "remote.origin.fetch": (b"+refs/heads/*:refs/remotes/origin/*",)})
        self.private, self.cas, self.after_remote, self.refuse, self.extra = [], 0, None, None, None
        self.tip, self.tree = NEW, b"100644 blob " + BLOB.encode() + b"\ta.txt\0"
        self.cas_unknown = self.cas_refused = False

    def __call__(self, argv, **kwargs):
        marker = "--work-tree=" + str(self.root)
        directory = Path(next(arg[10:] for arg in argv if arg.startswith("--git-dir=")))
        args = argv[argv.index(marker) + 1:] if marker in argv else argv[argv.index("--git-dir=" + str(directory)) + 1:]
        if marker not in argv:
            return self.private_command(argv, args, directory, kwargs)
        if args[0] == "for-each-ref" and args[-1] == "refs/remotes/":
            self.calls.append((tuple(args), directory, dict(kwargs["environ"])))
            rows = []
            base = directory / "refs/remotes"
            for path in sorted(base.rglob("*")):
                if path.is_file():
                    name = path.relative_to(directory).as_posix()
                    rows.append(name.encode() + b"\0" + path.read_bytes().rstrip(b"\n") + b"\0\0\n")
            return subprocess.CompletedProcess(argv, 0, b"".join(rows), b"")
        if args[0] == "update-ref":
            self.calls.append((tuple(args), directory, dict(kwargs["environ"])))
            assert directory == self.root / ".git"
            assert args == ["update-ref", "--no-deref", "-m", fetch.REF_MESSAGE, REF, NEW, OLD]
            assert (directory / "index.lock").is_file() and (directory / "config.lock").is_file()
            assert not (directory / "HEAD.lock").exists()
            assert (directory / ("objects/pack/pack-" + PACK + ".keep")).is_file()
            self.cas += 1
            if self.cas_refused:
                return subprocess.CompletedProcess(argv, 1, b"", b"")
            path = directory / REF
            assert path.read_bytes() == (OLD + "\n").encode()
            temporary = path.with_name(path.name + ".lock")
            temporary.write_bytes((NEW + "\n").encode())
            os.replace(temporary, path)
            log = directory / "logs" / REF
            environment = kwargs["environ"]
            identity = environment["GIT_COMMITTER_NAME"] + " <" + environment["GIT_COMMITTER_EMAIL"] + ">"
            with log.open("ab") as stream:
                stream.write((f"{OLD} {NEW} {identity} 1700000000 +0000\t{fetch.REF_MESSAGE}\n").encode())
            if self.cas_unknown:
                raise ProcessCleanupError("inert original did not settle", dispatched=True)
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        return super().__call__(argv, **kwargs)

    def private_command(self, argv, args, directory, kwargs):
        role = args[0]
        self.private.append((tuple(args), directory, dict(kwargs["environ"]), kwargs["timeout"]))
        assert directory.is_relative_to(self.root / ".git") and directory != self.root / ".git"
        assert kwargs["cwd"] == directory and kwargs["capture"] and not kwargs["text"]
        assert kwargs["timeout"] <= 45
        raw = b""
        if role == "ls-remote":
            assert args == ["ls-remote", "--exit-code", "--refs", "origin", "refs/heads/main"]
            raw = (self.tip + "\trefs/heads/main\n").encode()
            if self.after_remote:
                self.after_remote(directory)
        elif role == "fetch":
            assert args == ["fetch", "--keep", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head",
                "--no-auto-maintenance", "--no-write-commit-graph", "--jobs=1", "--refmap=", "origin",
                "refs/heads/main:" + fetch.PRIVATE_REF]
            for suffix in ("pack", "idx"):
                path = directory / ("objects/pack/pack-" + PACK + "." + suffix)
                path.write_bytes(("opaque fixture " + suffix + "\n").encode())
                path.chmod(0o444)
            (directory / fetch.PRIVATE_REF).write_bytes((self.tip + "\n").encode())
            if self.extra:
                (directory / "objects/pack" / self.extra).write_bytes(b"foreign fixture\n")
            if self.after_remote:
                self.after_remote(directory)
        elif role == "rev-parse":
            assert args == ["rev-parse", "--verify", "--end-of-options", fetch.PRIVATE_REF + "^{commit}"]
            raw = (self.tip + "\n").encode()
        elif role == "verify-pack":
            assert args == ["verify-pack", str(directory / ("objects/pack/pack-" + PACK + ".idx"))]
        elif role == "fsck":
            assert args == ["fsck", "--full", "--strict", "--no-reflogs", "--no-progress", "--no-dangling", NEW]
        elif role == "ls-tree":
            assert args == ["ls-tree", "-r", "-z", "--full-tree", NEW]
            raw = self.tree
        else:
            raise AssertionError("unexpected private fixture role")
        return subprocess.CompletedProcess(argv, 1 if self.refuse == role else 0, raw, b"")


class Owner(local_fixture.Owner):
    """Inert candidate ACK; real fsyncs only on these test-owned private files."""
    def __init__(self, root, plan, digest):
        super().__init__(root, plan)
        self.digest, self.keep, self.keep_fd, self.keep_identity = digest, None, None, None

    def record_intent(self, intent):
        assert not self.intents
        self.intents.append(intent)
        parent = self.expected[0] / ".git/objects/pack"
        before = fetch._directory(parent)
        path = parent / ("pack-" + intent.pack_oid + ".keep")
        self.keep_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        self.keep_identity = transaction._full(os.fstat(self.keep_fd))
        raw = b"mrk-git-fetch/1 " + self.digest.encode() + b"\n"
        assert os.write(self.keep_fd, raw) == len(raw)
        os.fsync(self.keep_fd)
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        self.keep_identity = transaction._full(os.fstat(self.keep_fd))
        self.keep = transaction.BorrowedKeep(intent.pack_oid, self.digest, self.keep_identity, before,
                                             fetch._directory(parent))
        if self.on_intent:
            self.on_intent(intent)
        return self.keep


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-git-fetch-data-")
        self.base = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("no process in inert Fetch tests")))
        stack.enter_context(identity_hook())
        original_mkdtemp = tempfile.mkdtemp
        def scratch(**kwargs):
            kwargs.setdefault("dir", self.base)
            assert Path(kwargs["dir"]).is_relative_to(self.base)
            return original_mkdtemp(**kwargs)
        stack.enter_context(patch.object(core.tempfile, "mkdtemp", side_effect=scratch))
        self.repositories, self.owners = [], []
        self.addCleanup(self.release_fixture_descriptors)
        self.fresh()

    def fresh(self):
        self.root = self.base / ("project-" + str(len(self.repositories)) + "-" + str(len(self.owners)))
        self.root.mkdir(mode=0o700)
        for name in (".git", ".git/objects", ".git/objects/info", ".git/objects/pack", ".git/refs", ".git/refs/heads",
                     ".git/refs/remotes", ".git/refs/remotes/origin", ".git/logs", ".git/logs/refs",
                     ".git/logs/refs/remotes", ".git/logs/refs/remotes/origin"):
            (self.root / name).mkdir(mode=0o700)
        for name, raw in {".git/HEAD": b"ref: refs/heads/main\n", ".git/config": b"[core]\nbare=false\n",
            ".git/refs/heads/main": (HEAD + "\n").encode(), ".git/index": local_fixture.OLD_INDEX,
            ".git/" + REF: (OLD + "\n").encode(), ".git/logs/" + REF: b"inert original log\n",
            "a.txt": b"unstaged fixture\n", "b.txt": b"unrelated staged fixture\n",
            "untracked.txt": b"retained untracked fixture\n"}.items():
            (self.root / name).write_bytes(raw)
        self.fake = FakeGit(self.root)
        self.target = Target("fixture/project", "fixture-user", "11", "22", Selection("refs/heads/main", NEW))

    def release_fixture_descriptors(self):
        # Test-only exact fd/identity retirement: every producer was inert.
        # Never search for another process, fd, source or output directory.
        seen = set()
        for repository in self.repositories:
            tx = repository._transaction
            if tx is None:
                continue
            routes = [*tx.locks, *tx.uncertain_closes]
            lock = tx.config_lock
            if lock.fd is not None and not lock.closed and lock.identity is not None:
                routes.append((lock.path, lock.fd, lock.identity))
            for _, fd, expected in routes:
                if fd in seen:
                    continue
                seen.add(fd)
                try:
                    actual = core._identity(os.fstat(fd))
                except OSError:
                    continue
                if actual[:2] == expected[:2]:
                    os.close(fd)
            for item in (*(tx.view.contents if tx.view else []), *tx.ref_files):
                if item.fd is not None and not item.close_claimed and item.identity is not None:
                    if transaction._full(os.fstat(item.fd))[:2] == item.identity[:2]:
                        os.close(item.fd)
                    item.fd = None
            for obj, field in ((tx, "pack_fd"), (tx, "ref_parent_fd"), (tx, "log_parent_fd"), (tx.view, "pack_dir_fd")):
                if obj is None:
                    continue
                fd = getattr(obj, field, None)
                if fd is not None:
                    identity = core._identity(os.fstat(fd))
                    path = (tx.session.git_dir / "objects/pack" if obj is tx and field == "pack_fd"
                            else tx.session.git_dir / tx.plan.target_ref.rsplit("/", 1)[0] if field == "ref_parent_fd"
                            else tx.plan._logging.path.parent if field == "log_parent_fd"
                            else tx.view.root / "objects/pack")
                    if core._identity(path.lstat())[:2] == identity[:2]:
                        os.close(fd)
                    setattr(obj, field, None)
        for owner in self.owners:
            if owner.keep_fd is not None:
                if transaction._full(os.fstat(owner.keep_fd))[:2] == owner.keep_identity[:2]:
                    os.close(owner.keep_fd)
                owner.keep_fd = None

    def prepare(self):
        observer = read.GitReadRepository(self.root, git_executable=GIT, work_end=time.monotonic() + 45, _run=self.fake)
        observed = observer.observe()
        self.assertFalse(observer._active_sessions or observer._retained or observer._unknown)
        repository = fetch.GitFetchRepository(self.root, git_executable=GIT, work_end=time.monotonic() + 45,
                                              launch=LAUNCH, _run=self.fake, _remote=self.fake)
        self.repositories.append(repository)
        review = repository.prepare_fetch("origin", self.target, expected_revision=observed.observation.revision,
                                           expected_reference_revision=observed.reference_revision)
        owner = Owner(self.root, review.plan, review.digest)
        self.owners.append(owner)
        return repository, review, owner

    def apply(self, prepared=None):
        repository, review, owner = prepared or self.prepare()
        result = repository.apply_fetch(review, owner, expected_digest=review.digest)
        return repository, review, owner, result

    def metadata(self):
        observer = read.GitReadRepository(self.root, git_executable=GIT, work_end=time.monotonic() + 45, _run=self.fake)
        observed = observer.observe()
        self.assertFalse(observer._active_sessions or observer._retained or observer._unknown)
        repository = fetch.GitFetchRepository(self.root, git_executable=GIT, work_end=time.monotonic() + 45,
                                              launch=LAUNCH, _run=self.fake, _remote=self.fake)
        self.repositories.append(repository)
        review = repository.prepare_remote("origin", replace(self.target, selected=Selection("refs/heads/main", None)),
            expected_revision=observed.observation.revision, expected_reference_revision=observed.reference_revision)
        return repository, review

    def test_metadata_uses_one_same_view_ls_remote_and_no_object_or_original_write(self):
        old = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        repository, review = self.metadata()
        self.assertEqual(review.plan.target.selected.oid, NEW)
        self.assertEqual([row[0][0] for row in self.fake.private], ["ls-remote"])
        self.assertEqual(self.fake.cas, 0)
        self.assertFalse(repository._transaction.view.root.exists())
        self.assertFalse(repository._active_sessions or repository._retained or repository._unknown)
        self.assertEqual({str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}, old)

    def test_metadata_equal_tip_still_returns_review_not_an_apply_grant(self):
        self.fake.tip = OLD
        _, review = self.metadata()
        self.assertEqual(review.plan.expected_target, review.plan.target.selected.oid)
        self.assertEqual([row[0][0] for row in self.fake.private], ["ls-remote"])
        self.assertEqual(self.fake.cas, 0)

    def test_metadata_unexpected_object_output_is_retained_never_adopted(self):
        self.fake.after_remote = lambda root: (root / "objects/pack/foreign").write_bytes(b"private fake output")
        with self.assertRaises(core.GitError):
            self.metadata()
        repository = self.repositories[-1]
        self.assertTrue(repository._unknown and repository._retained)
        self.assertTrue((repository._transaction.view.root / "objects/pack/foreign").exists())
        self.assertEqual(self.fake.cas, 0)

    def test_metadata_fatal_original_is_not_replaced_by_cleanup_error(self):
        original = ProcessCleanupError("synthetic original metadata owner", dispatched=True)
        def fail(_):
            raise original
        self.fake.after_remote = fail
        with self.assertRaises(ProcessCleanupError) as caught:
            self.metadata()
        self.assertIs(caught.exception, original)
        self.assertTrue(self.repositories[-1]._unknown and self.repositories[-1]._retained)
        self.assertEqual(self.fake.cas, 0)

    def test_metadata_known_refusal_closes_exact_empty_view_without_retry(self):
        self.fake.refuse = "ls-remote"
        with self.assertRaises(fetch.FetchError) as caught:
            self.metadata()
        self.assertEqual(caught.exception.reason, "fetch-target-changed")
        repository = self.repositories[-1]
        self.assertFalse(repository._unknown or repository._retained or repository._active_sessions)
        self.assertFalse(repository._transaction.view.root.exists())
        self.assertEqual([row[0][0] for row in self.fake.private], ["ls-remote"])

    def test_fixed_candidate_ack_links_cas_and_all_core_closes(self):
        before = {name: core._read(self.root / name, 65536)[0] for name in
                  (".git/HEAD", ".git/index", ".git/config", ".git/refs/heads/main", "a.txt", "b.txt", "untracked.txt")}
        repository, review, owner, result = self.apply()
        self.assertEqual((result.state, result.settlement, result.reason), ("succeeded", "settled", None))
        self.assertIsNone(result.observation)  # Write result cannot manufacture a read revision.
        self.assertEqual((len(owner.intents), self.fake.cas), (1, 1))
        self.assertEqual([args[0] for args, *_ in self.fake.private],
                         ["fetch", "rev-parse", "verify-pack", "fsck", "ls-tree"])
        self.assertTrue(all(core._read(self.root / name, 65536)[0] == stamp for name, stamp in before.items()))
        tx = repository._transaction
        self.assertIsNotNone(tx.publication)
        self.assertIs(tx.publication.intent, result.intent)
        self.assertFalse(tx.view.root.exists())
        self.assertEqual(tx.publication.pack[8], 1)
        self.assertEqual(tx.publication.index[8], 1)
        self.assertEqual(tx.diagnostics(), ("ref-published", ()))
        self.assertTrue((self.root / (".git/objects/pack/" + owner.keep.name)).is_file())
        self.assertEqual(transaction._full(os.fstat(owner.keep_fd)), owner.keep_identity)
        self.assertFalse(repository._active_sessions or repository._retained or repository._unknown)
        with self.assertRaises(core.GitError):
            repository.apply_fetch(review, owner, expected_digest=review.digest)
        self.assertEqual(self.fake.cas, 1)

    def test_execution_environment_is_private_and_finite_not_ambient_auth(self):
        copies = {}
        self.fake.after_remote = lambda root: copies.update(config=(root / "config").read_bytes(),
            git=(root / "exec/git").read_bytes(), helper=(root / "exec/git-remote-mrk").read_bytes())
        _, _, _, result = self.apply()
        self.assertEqual(result.state, "succeeded")
        for _, root, environment, seconds in self.fake.private:
            self.assertEqual(environment["GIT_EXEC_PATH"], str(root / "exec"))
            self.assertEqual(environment["PATH"], str(root / "exec"))
            self.assertEqual(environment["HOME"], str(root))
            self.assertEqual(environment["GIT_ALLOW_PROTOCOL"], "mrk")
            self.assertNotIn("GIT_OBJECT_DIRECTORY", environment)
            self.assertNotIn("GIT_INDEX_FILE", environment)
            self.assertFalse(set(environment) & {"GH_TOKEN", "GITHUB_TOKEN", "HTTPS_PROXY", "GIT_TRACE"})
            self.assertLessEqual(seconds, 45)
        self.assertIn(b"fsckObjects = true", copies["config"])
        self.assertIn(b"writeReverseIndex = false", copies["config"])
        self.assertIn(b"exec '/never-executed/git'", copies["git"])
        self.assertIn(b"exec '/never executed/python' -I -S -B", copies["helper"])

    def test_unsafe_remote_routes_refuse_before_remote_command(self):
        values = [
            {"remote.origin.url": (b"https://fixture@github.com/fixture/project.git",)},
            {"remote.origin.url": (b"ssh://github.com/fixture/project.git",)},
            {"remote.origin.url": (b"https://github.com/fixture/project.git", b"https://github.com/other/project.git")},
            {"remote.origin.fetch": (b"+refs/*:refs/*",)},
            {"url.https://other.invalid/.insteadof": (b"https://github.com/",)},
            {"credential.helper": (b"fixture-never-executed",)},
            {"http.proxy": (b"https://proxy.invalid",)},
        ]
        baseline = self.fake.config.copy()
        for change in values:
            with self.subTest(keys=tuple(change)):
                self.fake.config = {**baseline, **change}
                with self.assertRaises(fetch.FetchError) as raised:
                    self.prepare()
                self.assertEqual(raised.exception.reason, "fetch-remote")
                self.assertEqual(self.fake.private, [])
        self.fake.config = baseline

    def test_repository_hook_signing_and_filter_policies_are_not_bypassed(self):
        for name, value, reason in (("core.hookspath", b"/never-executed/hooks", "required-hooks"),
            ("commit.gpgsign", b"true", "required-signing"),
            ("filter.fixture.clean", b"fixture-never-executed", "unsupported-filter")):
            with self.subTest(name=name):
                self.fake.config[name] = (value,)
                with self.assertRaises(core.GitError) as raised:
                    self.prepare()
                self.assertEqual(raised.exception.reason, reason)
                self.assertEqual(self.fake.private, [])
                del self.fake.config[name]

    def test_extra_pack_outputs_are_not_adopted_or_published(self):
        for extra in ("pack-" + "a" * 40 + ".pack", "pack-" + PACK + ".rev",
                      "tmp_pack_extra", "unrelated", "pack-" + PACK + ".promisor"):
            with self.subTest(extra=extra):
                if self.repositories:
                    self.fresh()
                self.fake.extra = extra
                repository, _, owner, result = self.apply()
                self.assertEqual(result.reason, "fetch-output")
                self.assertFalse(owner.intents or self.fake.cas)
                self.assertEqual(tuple((self.root / ".git/objects/pack").iterdir()), ())
                self.assertTrue((repository._transaction.view.root / "objects/pack" / extra).exists())
                self.assertIsNone(repository._transaction.publication)
                self.assertIn(repository._transaction, repository._retained)

    def test_wrong_downloaded_ref_refuses_before_ack(self):
        self.fake.tip = "a" * 40
        _, _, owner, result = self.apply()
        self.assertEqual(result.reason, "fetch-target-changed")
        self.assertFalse(owner.intents or self.fake.cas)

    def test_gitlink_or_lfs_attribute_entries_refuse_before_ack(self):
        for tree in (b"160000 commit " + BLOB.encode() + b"\tchild\0",
                     b"100644 blob " + BLOB.encode() + b"\t.gitattributes\0",
                     b"100644 blob " + BLOB.encode() + b"\t.lfsconfig\0"):
            with self.subTest(tree=tree):
                if self.repositories:
                    self.fresh()
                self.fake.tree = tree
                _, _, owner, result = self.apply()
                self.assertEqual(result.reason, "fetch-layout")
                self.assertFalse(owner.intents or self.fake.cas)

    def test_stock_verify_and_connectivity_failure_cannot_publish(self):
        for role in ("verify-pack", "fsck"):
            with self.subTest(role=role):
                if self.repositories:
                    self.fresh()
                self.fake.refuse = role
                _, _, owner, result = self.apply()
                self.assertEqual(result.reason, "command-failed")
                self.assertFalse(owner.intents or self.fake.cas)

    def test_stop_after_candidate_ack_prevents_links_and_cas(self):
        prepared = self.prepare()
        prepared[2].on_intent = lambda _: setattr(prepared[2], "stopped", True)
        repository, _, owner, result = self.apply(prepared)
        self.assertEqual((result.state, result.reason), ("recovery-required", "authorization"))
        self.assertEqual(len(owner.intents), 1)
        self.assertEqual(self.fake.cas, 0)
        self.assertEqual({p.name for p in (self.root / ".git/objects/pack").iterdir()}, {owner.keep.name})
        self.assertIsNone(repository._transaction.publication)

    def test_foreign_ref_drift_after_ack_prevents_original_object_publication(self):
        prepared = self.prepare()
        prepared[2].on_intent = lambda _: (self.root / (".git/" + REF)).write_bytes(("b" * 40 + "\n").encode())
        repository, _, owner, result = self.apply(prepared)
        self.assertEqual(result.reason, "stale-observation")
        self.assertEqual(self.fake.cas, 0)
        self.assertEqual({p.name for p in (self.root / ".git/objects/pack").iterdir()}, {owner.keep.name})
        self.assertIsNone(repository._transaction.publication)
        self.assertEqual((self.root / (".git/" + REF)).read_bytes(), ("b" * 40 + "\n").encode())

    def test_unknown_cas_matching_readback_is_not_success_or_retry(self):
        self.fake.cas_unknown = True
        repository, review, _, result = self.apply()
        self.assertEqual((result.state, result.settlement), ("unknown", "unknown"))
        self.assertEqual((self.root / (".git/" + REF)).read_bytes(), (NEW + "\n").encode())
        self.assertIsNone(repository._transaction.publication)
        self.assertTrue(repository._unknown and repository._retained)
        self.assertTrue(repository._transaction.view.root.exists())
        with self.assertRaises(core.GitError):
            repository.apply_fetch(review, self.owners[-1], expected_digest=review.digest)
        self.assertEqual(self.fake.cas, 1)

    def test_missing_identity_or_changed_review_never_enters_remote(self):
        del self.fake.config["user.email"]
        with self.assertRaises(fetch.FetchError) as raised:
            self.prepare()
        self.assertEqual(raised.exception.reason, "fetch-identity-required")
        self.fake.config["user.email"] = (b"fixture@example.invalid",)
        repository, review, owner = self.prepare()
        with self.assertRaises(core.GitError):
            repository.apply_fetch(review, owner, expected_digest="0" * 64)
        self.assertEqual(self.fake.private, [])

    def test_casefold_collision_and_target_directory_refuse_before_remote(self):
        (self.root / ".git/refs/remotes/origin/MAIN").write_text(OLD + "\n")
        with self.assertRaises(fetch.FetchError) as raised:
            self.prepare()
        self.assertEqual(raised.exception.reason, "fetch-ref-parent")
        self.assertEqual(self.fake.private, [])
        (self.root / ".git/refs/remotes/origin/MAIN").unlink()
        (self.root / ".git" / REF).unlink()
        (self.root / ".git" / REF).mkdir(mode=0o700)
        with self.assertRaises(fetch.FetchError):
            self.prepare()
        self.assertEqual(self.fake.private, [])

    def test_keep_projection_cannot_close_unlink_or_supply_native_authority(self):
        _, _, owner, result = self.apply()
        self.assertEqual(result.state, "succeeded")
        self.assertFalse(hasattr(owner.keep, "fd") or hasattr(owner.keep, "close") or hasattr(owner.keep, "unlink"))
        with self.assertRaises(core.GitError):
            replace(owner.keep, identity=owner.keep.identity[:-1] + (2,))

    def test_closed_private_view_cannot_be_reused(self):
        repository, _, _, result = self.apply()
        self.assertEqual(result.state, "succeeded")
        tx = repository._transaction
        with self.assertRaises(core.GitError):
            tx.view.check()
        self.assertEqual(len(self.fake.private), 5)
        self.assertTrue(all((self.root / ".git/objects/pack" / row.path.name).is_file() for row in tx.view.contents))

    def test_equal_tip_review_is_held_but_apply_has_no_network_or_object_effect(self):
        self.target = replace(self.target, selected=Selection("refs/heads/main", OLD))
        repository, review, owner = self.prepare()
        self.assertEqual(review.as_dict()["expectedTarget"], review.as_dict()["candidateRefOid"])
        result = repository.apply_fetch(review, owner, expected_digest=review.digest)
        self.assertEqual((result.state, result.reason), ("failed", "fetch-up-to-date"))
        self.assertFalse(self.fake.private or self.fake.cas or owner.intents)
        self.assertIsNone(repository._transaction)
        self.assertEqual(tuple((self.root / ".git/objects/pack").iterdir()), ())
        self.assertFalse(repository._active_sessions or repository._unknown)

    def test_known_stop_after_one_durable_link_preserves_exact_positive_prefix(self):
        original = transaction.FetchTransaction.publication_ready
        def stop_after_pack(tx, **kwargs):
            if len(tx.linked) == 1:
                tx.owner.stopped = True
            return original(tx, **kwargs)
        with patch.object(transaction.FetchTransaction, "publication_ready", stop_after_pack):
            repository, _, _, result = self.apply()
        tx = repository._transaction
        self.assertEqual((result.state, result.settlement, result.reason), ("recovery-required", "settled", "authorization"))
        self.assertEqual(tx.phase, "pack-linked")
        self.assertIsNone(tx.publication.ref)
        self.assertIsNone(tx.publication.index)
        self.assertEqual(tx.publication.pack[8], 2)
        self.assertEqual((self.root / (".git/" + REF)).read_bytes(), (OLD + "\n").encode())
        self.assertIn(tx, repository._retained)
        self.assertEqual(len(tx.diagnostics()[1]), 3)
        self.assertEqual(self.fake.cas, 0)

    def test_fsync_failure_after_link_is_unknown_not_positive_publication(self):
        prepared = self.prepare()
        repository = prepared[0]
        original = os.fsync
        def fail_original_pack(fd):
            tx = repository._transaction
            if tx is not None and fd == tx.pack_fd:
                raise OSError("inert fsync failure")
            return original(fd)
        with patch.object(os, "fsync", fail_original_pack):
            _, _, _, result = self.apply(prepared)
        self.assertEqual((result.state, result.settlement), ("unknown", "unknown"))
        self.assertIsNone(repository._transaction.publication)
        self.assertEqual(repository._transaction.phase, "pack-link-entered")
        self.assertEqual(self.fake.cas, 0)

    def test_known_nonzero_cas_preserves_objects_but_never_invents_ref_return(self):
        self.fake.cas_refused = True
        repository, _, _, result = self.apply()
        tx = repository._transaction
        self.assertEqual((result.state, result.settlement), ("recovery-required", "settled"))
        self.assertIsNone(tx.publication.ref)
        self.assertIsNone(tx.publication.log)
        self.assertEqual(tx.publication.phase, "ref-send-entered")
        self.assertEqual((tx.publication.pack[8], tx.publication.index[8]), (2, 2))
        self.assertEqual(len(tx.diagnostics()[1]), 4)
        self.assertEqual((self.root / (".git/" + REF)).read_bytes(), (OLD + "\n").encode())
        self.assertIn(tx, repository._retained)
        self.assertEqual(self.fake.cas, 1)

    def test_pre_open_refusal_has_no_unknown_descriptor(self):
        item = transaction._File(self.root / ".git/absent-fixture", None)
        with self.assertRaises(FileNotFoundError):
            item.capture()
        self.assertTrue(item.closed and item.close())
        self.assertIsNone(item.fd)
        self.assertFalse(item.unknown)


if __name__ == "__main__":
    unittest.main()
