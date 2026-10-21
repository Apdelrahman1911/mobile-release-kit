"""Actual local facet with task-owned files and inert fixed Git responses.

No native mkdir/ACK is qualified here: the fixture explicitly models that
boundary to test the original core's comparisons and one-use failure paths.
Popen is forbidden by the existing BranchTests fixture.
"""
import os
from pathlib import Path
import subprocess
import time
import unittest

from mobile_release import git_repository_branches as branches
from mobile_release import git_repository_upstream as upstream
from mobile_release import git_repository_upstream_transaction as tx
from mobile_release import git_service as core
import test_git_repository_branches as base
import test_git_repository_local as old


class FakeConfig(base.FakeBranches):
    def __init__(self, root):
        super().__init__(root)
        self.added = []

    def __call__(self, argv, **kwargs):
        args = argv[argv.index("--work-tree=" + str(self.root)) + 1:]
        if args[0] != "config" or Path(args[2]).name != "upstream-config":
            return super().__call__(argv, **kwargs)
        directory = Path(next(v[10:] for v in argv if v.startswith("--git-dir=")))
        path = directory / "upstream-config"
        assert directory != self.root / ".git"
        assert args[:4] == ["config", "--file", str(path), "--no-includes"]
        assert all((self.root / ".git" / n).is_file() for n in ("config.lock", "index.lock", "HEAD.lock"))
        self.calls.append((tuple(args), directory, dict(kwargs["environ"])))
        if self.before:
            self.before(args, directory, Path(kwargs["environ"]["GIT_INDEX_FILE"]))
        raw = b""
        if args[4] == "--add":
            assert len(args) == 7
            key, value = args[5:]
            prefix, variable = key.rsplit(".", 1)
            header = "[user]\n" if prefix == "user" else '[%s "%s"]\n' % tuple(prefix.split(".", 1))
            old_prefix = self.added[-1][0].rsplit(".", 1)[0] if self.added else None
            addition = (header if old_prefix != prefix else "") + "\t" + variable + " = " + value + "\n"
            replacement = path.with_name(path.name + ".lock")
            replacement.write_bytes(path.read_bytes() + addition.encode())
            os.replace(replacement, path)
            self.added.append((key, value))
        else:
            assert args[4:] == ["--null", "--list"]
            rows = dict(self.config)
            rows.update((k, (v.encode(),)) for k, v in self.added)
            raw = b"".join(k.encode() + b"\n" + v + b"\0" for k, values in rows.items() for v in values)
        if self.after:
            self.after(args, directory, Path(kwargs["environ"]["GIT_INDEX_FILE"]))
        return subprocess.CompletedProcess(argv, 0, raw, b"")


class UpstreamTests(unittest.TestCase):
    setUp = base.BranchTests.setUp
    write = base.BranchTests.write
    release_fixture_descriptors = old.LocalFacetTests.release_fixture_descriptors

    def prepared(self, identity=None, configure=None):
        self.fake = FakeConfig(self.root)
        if configure: configure(self.fake)
        source = branches.GitBranchesRepository(self.root, git_executable=Path("/never-run/git"),
            work_end=time.monotonic() + 45, _run=self.fake)
        self.repositories.append(source)
        observation = source.observe()
        listed = source.branches(expected_revision=observation.revision)
        repo = upstream.GitUpstreamRepository(self.root, git_executable=Path("/never-run/git"),
            work_end=time.monotonic() + 45, _run=self.fake)
        self.repositories.append(repo)
        review = repo.prepare_upstream("origin", "example/project", old.BRANCH, old.HEAD, identity=identity,
            expected_revision=observation.revision, expected_reference_revision=listed.reference_revision)
        owner = old.Owner(self.root, review.plan)
        return repo, review, owner

    def modeled_ack(self, repo, intent, mutate=None, digest=None):
        """Not native proof; the callback models only reviewed exclusive mkdir."""
        t = repo._transaction
        for name in intent.missing_directories:
            (self.root / ".git" / name).mkdir(mode=0o700)
        if mutate:
            mutate(t)
        rows = tuple(upstream.Parent(n, upstream.directory(self.root / ".git" / n),
                     tuple(t.session.names(self.root / ".git" / n)))
                     for n in upstream.parent_paths("refs/remotes/origin/main"))
        t.accept_directory_ack(digest or tx.directory_digest(intent, t.plan._controls.parents, rows))

    def apply(self, repo, review, owner):
        return repo.apply_upstream(review, owner, expected_digest=review.digest)

    def test_missing_only_config_and_parent_candidate_preserves_index_dirty_files_and_refs(self):
        repo, review, owner = self.prepared()
        names = (".git/index", ".git/HEAD", ".git/refs/heads/main", "a.txt", "b.txt")
        before = [(self.root / n).read_bytes() for n in names]
        config = (self.root / ".git/config").read_bytes()
        owner.on_intent = lambda i: self.modeled_ack(repo, i)
        result = self.apply(repo, review, owner)
        self.assertEqual((result.state, result.settlement, result.reason), ("succeeded", "settled", None))
        self.assertIsNone(result.observation)
        self.assertEqual(before, [(self.root / n).read_bytes() for n in names])
        self.assertTrue((self.root / ".git/config").read_bytes().startswith(config))
        self.assertEqual(len(self.fake.added), 4)
        self.assertFalse((self.root / ".git/refs/remotes/origin/main").exists())
        self.assertTrue(repo._transaction.directory_returned)
        self.assertTrue(repo._transaction.closed)
        self.assertFalse(repo._retained or repo._unknown)

    def test_lost_directory_ack_keeps_original_pending_without_config_write_or_retry(self):
        repo, review, owner = self.prepared()
        config = (self.root / ".git/config").read_bytes()
        result = self.apply(repo, review, owner)
        self.assertNotEqual(result.state, "succeeded")
        self.assertTrue(repo._unknown)
        self.assertEqual(len(owner.intents), 1)
        self.assertEqual((self.root / ".git/config").read_bytes(), config)
        with self.assertRaises(core.GitError):
            self.apply(repo, review, owner)
        self.assertEqual(len(owner.intents), 1)

    def test_foreign_new_directory_entry_is_not_adopted_even_with_matching_digest(self):
        repo, review, owner = self.prepared()
        config = (self.root / ".git/config").read_bytes()
        owner.on_intent = lambda i: self.modeled_ack(repo, i,
            mutate=lambda t: (self.root / ".git/refs/remotes/origin/foreign").write_bytes(b"foreign"))
        result = self.apply(repo, review, owner)
        self.assertNotEqual(result.state, "succeeded")
        self.assertTrue(repo._unknown)
        self.assertEqual((self.root / ".git/config").read_bytes(), config)
        self.assertEqual((self.root / ".git/refs/remotes/origin/foreign").read_bytes(), b"foreign")

    def test_wrong_directory_digest_refuses_before_config_replacement(self):
        repo, review, owner = self.prepared()
        config = (self.root / ".git/config").read_bytes()
        owner.on_intent = lambda i: self.modeled_ack(repo, i, digest="f" * 64)
        result = self.apply(repo, review, owner)
        self.assertNotEqual(result.state, "succeeded")
        self.assertEqual((self.root / ".git/config").read_bytes(), config)

    def test_stop_after_positive_directory_ack_preserves_new_empty_parents_no_config_effect(self):
        repo, review, owner = self.prepared()
        config = (self.root / ".git/config").read_bytes()
        def cut(i):
            self.modeled_ack(repo, i)
            owner.stopped = True
        owner.on_intent = cut
        result = self.apply(repo, review, owner)
        self.assertNotEqual(result.state, "succeeded")
        self.assertEqual((self.root / ".git/config").read_bytes(), config)
        self.assertTrue((self.root / ".git/refs/remotes/origin").is_dir())

    def configure_existing(self, fake):
        changes, _, _ = upstream.configuration((self.root / ".git/config").read_bytes(), fake.config,
            "origin", "example/project", old.BRANCH, old.HEAD, None)
        self.write(".git/config", upstream.append_config((self.root / ".git/config").read_bytes(), changes))
        fake.config = upstream.configured(fake.config, changes)

    def test_identical_complete_config_only_creates_missing_parents_not_tracking_or_rewrites(self):
        repo, review, owner = self.prepared(configure=self.configure_existing)
        before = (self.root / ".git/config").stat()
        raw = (self.root / ".git/config").read_bytes()
        self.assertFalse(review.plan.public()["unchanged"])
        self.assertEqual(review.plan._controls.additions, ())
        owner.on_intent = lambda i: self.modeled_ack(repo, i)
        result = self.apply(repo, review, owner)
        self.assertEqual(result.state, "succeeded"); self.assertEqual(self.fake.added, [])
        self.assertFalse(result.intent.config_changed)
        self.assertEqual((self.root / ".git/config").read_bytes(), raw)
        self.assertEqual((self.root / ".git/config").stat().st_ino, before.st_ino)
        self.assertIsNone(repo._transaction.config_returned)
        self.assertFalse((self.root / ".git/refs/remotes/origin/main").exists())

    def test_complete_tuple_identity_and_parents_is_close_only_no_candidate_or_commands(self):
        def configure(fake):
            self.configure_existing(fake)
            for path in upstream.parent_paths("refs/remotes/origin/main"):
                if not (self.root / ".git" / path).exists(): (self.root / ".git" / path).mkdir(mode=0o700)
        repo, review, owner = self.prepared(configure=configure)
        self.assertTrue(review.plan.public()["unchanged"])
        before = len(self.fake.calls)
        with self.assertRaises(upstream.UpstreamError) as failed: self.apply(repo, review, owner)
        self.assertEqual(failed.exception.reason, "upstream-unchanged")
        self.assertEqual(len(self.fake.calls), before); self.assertEqual(owner.intents, [])
        self.assertIsNone(repo._transaction)

    def test_explicit_missing_identity_preserves_old_mode_group_and_byte_prefix(self):
        def configure(fake):
            fake.config = {k: v for k, v in fake.config.items() if not k.startswith("user.")}
            self.write(".git/config", b"[core]\nbare=false\nrepositoryformatversion=0\nlogAllRefUpdates=true\n# unchanged\n")
            os.chmod(self.root / ".git/config", 0o640)
        repo, review, owner = self.prepared(core.CommitIdentity("Explicit Name", "explicit@example.invalid"), configure)
        config = self.root / ".git/config"; before, raw = config.stat(), config.read_bytes()
        owner.on_intent = lambda i: self.modeled_ack(repo, i)
        result = self.apply(repo, review, owner)
        self.assertEqual(result.state, "succeeded"); self.assertEqual(len(self.fake.added), 6)
        after = config.stat(); self.assertEqual((after.st_uid, after.st_gid, after.st_mode), (before.st_uid, before.st_gid, before.st_mode))
        self.assertTrue(config.read_bytes().startswith(raw)); self.assertNotEqual(after.st_ino, before.st_ino)

    def test_partial_conflicting_case_alias_and_identity_are_not_missing(self):
        raw = (self.root / ".git/config").read_bytes()
        config = FakeConfig(self.root).config
        variants = [({**config, "remote.origin.url": (b"https://github.com/example/project.git",)}, raw),
            ({**config, "user.name": (b"one", b"two")}, raw),
            ({**config, "remote.Origin.url": (b"https://github.com/example/project.git",)}, raw + b'[remote "Origin"]\n')]
        for values, body in variants:
            with self.subTest(values=tuple(values)):
                with self.assertRaises(upstream.UpstreamError):
                    upstream.configuration(body, values, "origin", "example/project", old.BRANCH, old.HEAD, None)
        absent = {k: v for k, v in config.items() if not k.startswith("user.")}
        raw = b"[core]\nbare=false\nrepositoryformatversion=0\n"
        with self.assertRaises(upstream.UpstreamError):
            upstream.configuration(raw, absent, "origin", "example/project", old.BRANCH, old.HEAD, None)
        changes, identity, _ = upstream.configuration(raw, absent, "origin", "example/project", old.BRANCH, old.HEAD,
            core.CommitIdentity("Explicit Name", "explicit@example.invalid"))
        self.assertEqual(len(changes), 6)
        self.assertEqual(identity.name, "Explicit Name")


if __name__ == "__main__":
    unittest.main()
