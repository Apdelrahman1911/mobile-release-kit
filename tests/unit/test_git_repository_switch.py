"""Content-switch core tests with private files and inert Git replies only.

No subprocess/actual Git/native admission/Store/user repo. Fake responses do
not prove Git semantics, descendant custody or installed-source finality.
"""
import ast
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

from mobile_release import git_repository_branches as branches
from mobile_release import git_repository_switch as switch
from mobile_release import git_switch_transaction as tx
from mobile_release import git_service as core
import test_git_repository_branches as branch_fixture
import test_git_repository_local as local_fixture

HEAD = "1" * 40
TARGET = "6" * 40
INDEX = local_fixture.OLD_INDEX
CANDIDATE = local_fixture.CANDIDATE_INDEX


def identity_hook():
    """Use actual helper after integration; before it, project its exact body.

    This extraction is the accompanying one-file Root hook, not a substitute
    identity parser or a test that merely matches source strings.
    """
    if hasattr(branches, "_local_identity"):
        return ExitStack()
    tree = ast.parse(Path(branches.__file__).read_text())
    original = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_logging")
    body = []
    for node in original.body[2:]:
        if isinstance(node, ast.Assign) and any(isinstance(n, ast.Name) and n.id == "path" for n in node.targets):
            break
        body.append(node)
    body.append(ast.Return(value=ast.Name(id="identity", ctx=ast.Load())))
    definition = ast.FunctionDef(name="_local_identity", args=ast.arguments(posonlyargs=[], args=[ast.arg(arg="config")],
        kwonlyargs=[], kw_defaults=[], defaults=[]), body=body, decorator_list=[])
    module = ast.fix_missing_locations(ast.Module(body=[definition], type_ignores=[]))
    namespace = dict(vars(branches))
    exec(compile(module, "<exact-original-local-identity-body>", "exec"), namespace)
    return patch.object(branches, "_local_identity", namespace["_local_identity"], create=True)


class FakeSwitch(branch_fixture.FakeBranches):
    def __init__(self, root):
        super().__init__(root)
        self.before_files = {"a.txt": b"old public fixture\n", "b.txt": b"unchanged public fixture\n"}
        self.after_files = {**self.before_files, "a.txt": b"new public fixture\n"}
        self.target_oid = TARGET
        self.status = self.post_status = b"?? loose.txt\0"
        self.attrs = {}
        self.flag_prefix = b"H "
        self.checkout_count = 0
        self.refusal = None
        self.refresh_entries()

    def refresh_entries(self):
        self.original_entries = local_fixture.entries(*[(p, switch._blob(raw, HEAD)) for p, raw in self.before_files.items()])
        self.candidate_entries = local_fixture.entries(*[(p, switch._blob(raw, HEAD)) for p, raw in self.after_files.items()])

    @staticmethod
    def atomic(path, raw):
        temporary = path.with_name(path.name + ".lock")
        with open(temporary, "xb") as handle:
            handle.write(raw)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)

    def __call__(self, argv, **kwargs):
        marker = "--work-tree=" + str(self.root)
        args = argv[argv.index(marker) + 1:]
        extra = args[0] in ("ls-tree", "read-tree", "switch", "cat-file", "check-attr") or args == ["ls-files", "-v", "-z"]
        extra |= args[:2] == ["symbolic-ref", "-m"]
        if not extra:
            return super().__call__(argv, **kwargs)
        directory = Path(next(a[10:] for a in argv if a.startswith("--git-dir=")))
        index = Path(kwargs["environ"]["GIT_INDEX_FILE"])
        self.calls.append((tuple(args), directory, dict(kwargs["environ"])))
        if self.before:
            self.before(args, directory, index)
        raw, code = b"", 0
        if args[0] == "ls-tree":
            files = self.before_files if args[-1] == HEAD else self.after_files
            raw = b"".join((f"100644 blob {switch._blob(body, HEAD)} {len(body)}\t{p}\0").encode()
                           for p, body in sorted(files.items()))
        elif args == ["ls-files", "-v", "-z"]:
            raw = b"".join(self.flag_prefix + p.encode() + b"\0" for p in sorted(self.before_files))
        elif args[0] == "check-attr":
            paths = args[args.index("--") + 1:]
            raw = b"".join(p.encode() + b"\0" + a.encode() + b"\0" + self.attrs.get((p, a), b"unspecified") + b"\0"
                           for p in paths for a in switch.ATTRIBUTES)
        elif args[0] == "cat-file":
            raw = next(body for body in self.after_files.values() if switch._blob(body, HEAD) == args[-1])
        else:
            assert directory != self.root / ".git" and index != self.root / ".git/index"
            for name in ("HEAD.lock", "index.lock", "config.lock", "refs/heads/next.lock"):
                assert (self.root / ".git" / name).is_file(), name
            assert (self.root / ".git/index").read_bytes() == INDEX
            if args[0] == "read-tree":
                self.atomic(index, CANDIDATE)
            else:
                old_branch, old_oid = self.head(directory)
                target = "refs/heads/next"
                next_oid = (directory / target).read_text().strip()
                identity = kwargs["environ"]["GIT_COMMITTER_NAME"] + " <" + kwargs["environ"]["GIT_COMMITTER_EMAIL"] + ">"
                if args[0] == "switch":
                    self.checkout_count += 1
                    assert index.read_bytes() == INDEX
                    assert (directory / "info/attributes").read_bytes() == b"* -filter -text -eol -ident -working-tree-encoding\n"
                    for path, body in self.after_files.items():
                        if body != self.before_files[path]:
                            self.atomic(self.root / path, body)
                    self.atomic(index, CANDIDATE)
                    message = "checkout: moving from " + old_branch[len("refs/heads/"):] + " to next"
                else:
                    message = switch._MESSAGE
                self.atomic(directory / "HEAD", ("ref: " + target + "\n").encode())
                log = directory / "logs/HEAD"
                enabled = b"logAllRefUpdates=true\n" in (directory / "config").read_bytes() or log.exists()
                if enabled:
                    old = log.read_bytes() if log.exists() else b""
                    self.atomic(log, old + (f"{old_oid} {next_oid} {identity} 1700000000 +0000\t{message}\n").encode())
        if self.after:
            self.after(args, directory, index)
        if self.refusal == args[0]:
            code = 1
        return subprocess.CompletedProcess(argv, code, raw, b"")


class SwitchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-git-switch-data-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "project"
        for name in ("", ".git", ".git/objects", ".git/objects/info", ".git/objects/pack",
                     ".git/refs", ".git/refs/heads", ".git/logs"):
            (self.root / name).mkdir(mode=0o700)
        self.write(".git/HEAD", b"ref: refs/heads/main\n")
        self.write(".git/config", b"[core]\nbare=false\nrepositoryformatversion=0\nlogAllRefUpdates=true\n"
                                  b"[user]\nname=Fixture Name\nemail=fixture@example.invalid\n")
        self.write(".git/refs/heads/main", (HEAD + "\n").encode())
        self.write(".git/refs/heads/next", (TARGET + "\n").encode())
        self.write(".git/index", INDEX)
        self.write(".git/logs/HEAD", b"old inert fixture log preserved byte-for-byte\n")
        self.fake = FakeSwitch(self.root)
        for path, raw in self.fake.before_files.items():
            self.write(path, raw)
        self.write("loose.txt", b"untracked retained fixture\n")
        self.write("ignored.txt", b"ignored retained fixture\n")
        self.repositories = []
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("No actual process in passive switch tests")))
        stack.enter_context(identity_hook())
        original_open = os.open
        self.probe_mask = 0o022
        def passive_open(path, flags, mode=0o777, *, dir_fd=None):
            # This inert fixture models the admitted inherited mask without
            # changing process-global umask. No child is ever launched.
            fd = original_open(path, flags, mode, dir_fd=dir_fd)
            if Path(path).name == "checkout-mode" and flags & os.O_CREAT:
                os.fchmod(fd, mode & ~self.probe_mask)
            return fd
        stack.enter_context(patch.object(os, "open", passive_open))
        original = tempfile.mkdtemp
        def scratch(**kwargs):
            kwargs.setdefault("dir", self.base)
            self.assertTrue(Path(kwargs["dir"]).is_relative_to(self.base))
            return original(**kwargs)
        stack.enter_context(patch.object(core.tempfile, "mkdtemp", side_effect=scratch))
        self.addCleanup(self.close_inert_descriptors)

    def close_inert_descriptors(self):
        # Inert tests only. No real consumer exists. Do not reinterpret unknown
        # route tests as known production cleanup or use this in real fixtures.
        for repository in self.repositories:
            transaction = repository._transaction
            controls = [repository._target_lock]
            routes = []
            if transaction is not None:
                controls += [transaction.config_lock, transaction.log_lock]
                routes += [*transaction.locks, *transaction.uncertain_closes]
            for control in controls:
                if control is not None and getattr(control, "fd", None) is not None and not control.closed:
                    routes.append((control.path, control.fd, control.identity))
            for _, fd, identity in routes:
                if identity is None:
                    continue
                try:
                    current = core._identity(os.fstat(fd))
                except OSError:
                    continue
                if current[:2] == identity[:2]:
                    os.close(fd)

    def write(self, name, raw):
        path = self.root / name
        path.write_bytes(raw)
        # Model ordinary supported checkout files independently of the test
        # caller's umask. The enclosing fixture directories stay private.
        # Private-mode refusal cases explicitly narrow the file afterwards.
        path.chmod(0o644)

    def repo(self):
        repository = switch.GitSwitchRepository(self.root, git_executable=Path("/never-run/git"),
            work_end=time.monotonic() + 45, _run=self.fake)
        self.repositories.append(repository)
        return repository

    def prepared(self):
        repository = self.repo()
        observation = repository.observe()
        catalog = repository.branches(expected_revision=observation.revision)
        review = repository.prepare_switch("next", expected_revision=catalog.revision,
                                            expected_reference_revision=catalog.reference_revision)
        return repository, review, local_fixture.Owner(self.root, review.plan)

    def apply(self, repository, review, owner):
        return repository.apply_switch(review, owner, expected_digest=review.digest)

    def refusal(self, reason, callback):
        with self.assertRaises(core.GitError) as caught:
            callback()
        self.assertEqual(caught.exception.reason, reason)

    def assert_no_checkout(self):
        self.assertEqual(self.fake.checkout_count, 0)
        self.assertEqual((self.root / ".git/index").read_bytes(), INDEX)
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")

    def test_prepare_binds_exact_files_and_omits_raw_contents_and_identity(self):
        repository, review, _ = self.prepared()
        data = review.as_dict()
        self.assertEqual(data["paths"], ["a.txt"])
        self.assertEqual(data["files"][0]["targetSha256"], core._digest(self.fake.after_files["a.txt"]))
        self.assertTrue(data["contentOnly"])
        self.assertEqual(data["trackedCount"], 2)
        for private in ("Fixture Name", "fixture@example", "new public fixture", str(self.root)):
            self.assertNotIn(private, repr(data))
        self.assertFalse(repository._active_sessions or repository._unknown)
        self.assert_no_checkout()

    def test_whole_clean_switch_has_one_ack_and_exact_order_preserving_unrelated_bytes(self):
        repository, review, owner = self.prepared()
        old = {p: (self.root / p).read_bytes() for p in ("b.txt", "loose.txt", "ignored.txt", ".git/config")}
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.reason, result.settlement), ("succeeded", None, "settled"))
        self.assertEqual(result.observation.head, TARGET)
        self.assertEqual(result.observation.branch, "refs/heads/next")
        self.assertEqual((self.root / "a.txt").read_bytes(), self.fake.after_files["a.txt"])
        self.assertEqual({p: (self.root / p).read_bytes() for p in old}, old)
        self.assertEqual(owner.intents, [result.intent])
        self.assertEqual(self.fake.checkout_count, 1)
        transaction = repository._transaction
        self.assertEqual([r.name for r in transaction.publication.metadata], ["logs/HEAD", "HEAD", "index"])
        self.assertEqual(transaction.phase, "index-published")
        self.assertTrue(repository._target_lock.closed)
        self.assertFalse(repository._unknown or repository._active_sessions or repository._retained)
        self.assertEqual((self.root / ".git/index").read_bytes(), CANDIDATE)
        self.refusal("already-used", lambda: self.apply(repository, review, owner))

    def test_same_tree_is_still_real_head_log_and_index_publication(self):
        self.fake.after_files = dict(self.fake.before_files)
        self.fake.refresh_entries()
        self.write(".git/refs/heads/next", (HEAD + "\n").encode())
        repository, review, owner = self.prepared()
        self.assertEqual(review.plan.changed, ())
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "succeeded", result.reason)
        self.assertEqual((result.observation.head, result.observation.branch), (HEAD, "refs/heads/next"))
        self.assertIn((f"{HEAD} {HEAD} Fixture Name").encode(), (self.root / ".git/logs/HEAD").read_bytes())
        self.assertEqual([r.name for r in repository._transaction.metadata_returns], ["logs/HEAD", "HEAD", "index"])

    def test_dirty_index_status_and_hidden_changed_bytes_refuse(self):
        self.fake.status = b" M a.txt\0"
        self.refusal("switch-dirty", self.prepared)
        self.fake.status = b"M  a.txt\0"
        self.refusal("switch-dirty", self.prepared)
        self.fake.status = b""
        self.write("a.txt", b"unreported modified bytes\n")
        self.refusal("switch-dirty", self.prepared)
        self.assert_no_checkout()

    def test_skip_worktree_and_assume_unchanged_never_hide_checkout_destinations(self):
        for prefix in (b"S ", b"h ", b"s "):
            self.fake.flag_prefix = prefix
            self.refusal("switch-dirty", self.prepared)
        self.assert_no_checkout()

    def test_changed_path_roster_mode_and_submodule_are_unsupported(self):
        self.fake.after_files["new.txt"] = b"new entry\n"
        self.refusal("switch-layout", self.prepared)
        for row in (f"160000 commit {HEAD} -\tmodule\0", f"120000 blob {HEAD} 1\tlink\0"):
            self.refusal("switch-layout", lambda: switch._tree(row.encode()))
        for rows in (("Case", "case"), ("a", "a/file"), (".GIT/HEAD",)):
            raw = b"".join(f"100644 blob {HEAD} 1\t{p}\0".encode() for p in rows)
            self.refusal("switch-layout", lambda: switch._tree(raw))
        self.assert_no_checkout()

    def test_filters_conversion_lfs_hooks_and_signing_are_refused_not_bypassed(self):
        for attribute in switch.ATTRIBUTES:
            self.fake.attrs[("a.txt", attribute)] = b"set"
            self.refusal("switch-conversion", self.prepared)
            self.fake.attrs.clear()
        self.fake.config["filter.untrusted.process"] = (b"never-run-fixture",)
        self.refusal("unsupported-filter", self.prepared)
        del self.fake.config["filter.untrusted.process"]
        self.fake.config["commit.gpgsign"] = (b"true",)
        self.refusal("required-signing", self.prepared)
        del self.fake.config["commit.gpgsign"]
        (self.root / ".git/hooks").mkdir(mode=0o700)
        self.write(".git/hooks/post-checkout", b"never execute test text\n")
        os.chmod(self.root / ".git/hooks/post-checkout", 0o700)
        self.refusal("required-hooks", self.prepared)
        self.assert_no_checkout()

    def test_local_identity_is_required_without_ambient_or_application_default(self):
        del self.fake.config["user.name"]
        self.refusal("switch-identity-required", self.prepared)
        self.assert_no_checkout()

    def test_target_drift_and_foreign_lock_have_zero_checkout(self):
        repository, review, owner = self.prepared()
        self.write(".git/refs/heads/next", ("7" * 40 + "\n").encode())
        self.refusal("stale-observation", lambda: self.apply(repository, review, owner))
        self.write(".git/refs/heads/next", (TARGET + "\n").encode())
        repository, review, owner = self.prepared()
        self.write(".git/refs/heads/next.lock", b"foreign\n")
        with self.assertRaises(core.GitError):
            self.apply(repository, review, owner)
        self.assertEqual((self.root / ".git/refs/heads/next.lock").read_bytes(), b"foreign\n")
        self.assert_no_checkout()

    def test_stop_after_candidate_ack_never_starts_checkout_or_publishes(self):
        repository, review, owner = self.prepared()
        owner.on_intent = lambda _: setattr(owner, "stopped", True)
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual(len(owner.intents), 1)
        self.assertIsNone(repository._transaction.publication)
        self.assertTrue(repository._transaction.scratch.exists())
        self.assert_no_checkout()

    def test_changed_preserved_file_after_ack_refuses_without_overwrite(self):
        repository, review, owner = self.prepared()
        owner.on_intent = lambda _: self.write("loose.txt", b"external later bytes\n")
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual((self.root / "loose.txt").read_bytes(), b"external later bytes\n")
        self.assert_no_checkout()

    def test_known_partial_log_publication_is_retained_without_rollback_or_repeat(self):
        repository, review, owner = self.prepared()
        original = tx.SwitchTransaction.publish_metadata
        def stop_before_head(transaction, name):
            if name == "HEAD":
                raise core.GitError("authorization")
            return original(transaction, name)
        with patch.object(tx.SwitchTransaction, "publish_metadata", stop_before_head):
            result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement), ("recovery-required", "settled"))
        self.assertEqual(repository._transaction.phase, "log-published")
        self.assertEqual([r.name for r in repository._transaction.metadata_returns], ["logs/HEAD"])
        self.assertEqual((self.root / "a.txt").read_bytes(), self.fake.after_files["a.txt"])
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")
        self.assertEqual((self.root / ".git/index").read_bytes(), INDEX)
        self.assertTrue(repository._transaction.scratch.exists())
        self.refusal("already-used", lambda: self.apply(repository, review, owner))

    def test_lost_post_rename_fsync_has_no_positive_head_receipt(self):
        repository, review, owner = self.prepared()
        original = tx.SwitchTransaction._sync_directory
        def fail_head(transaction, path):
            if path == self.root / ".git":
                raise OSError("inert lost publication return")
            return original(transaction, path)
        with patch.object(tx.SwitchTransaction, "_sync_directory", fail_head):
            result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement), ("unknown", "unknown"))
        self.assertEqual([r.name for r in repository._transaction.metadata_returns], ["logs/HEAD"])
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/next\n")
        self.assertEqual((self.root / ".git/index").read_bytes(), INDEX)
        self.assertTrue(repository._unknown)

    def test_replaced_index_keeps_the_actual_old_descriptor_readable_until_its_close(self):
        repository, review, owner = self.prepared()
        fd = os.open(self.root / ".git/index", os.O_RDONLY | os.O_NOFOLLOW)
        original = os.fstat(fd)
        try:
            result = self.apply(repository, review, owner)
            self.assertEqual(result.state, "succeeded", result.reason)
            current = os.fstat(fd)
            self.assertEqual((current.st_dev, current.st_ino), (original.st_dev, original.st_ino))
            self.assertEqual(current.st_nlink, 0)
            self.assertEqual(os.read(fd, 1024), INDEX)
            self.assertNotEqual((self.root / ".git/index").stat().st_ino, original.st_ino)
        finally:
            os.close(fd)

    def test_exact_target_lock_parent_and_foreign_entries_are_not_globally_exempted(self):
        lock = tx.TargetLock(self.root, "refs/heads/next")
        lock.acquire()
        self.write(".git/refs/heads/foreign", ("8" * 40 + "\n").encode())
        try:
            self.refusal("stale-observation", lock.check)
        finally:
            # Explicit inert-test teardown; production refuses this changed
            # parent and must retain its original control for recovery.
            os.unlink(lock.path)
            os.close(lock.fd)
        self.assertEqual((self.root / ".git/refs/heads/foreign").read_bytes(), ("8" * 40 + "\n").encode())

    def test_bounds_reject_too_many_changed_files_before_checkout(self):
        for n in range(8):
            name = f"extra{n}.txt"
            self.fake.before_files[name] = b"before\n"
            self.fake.after_files[name] = b"after\n"
            self.write(name, b"before\n")
        self.fake.refresh_entries()
        self.refusal("limit", self.prepared)
        self.assert_no_checkout()

    def test_log_disabled_without_old_log_does_not_invent_one(self):
        self.fake.config["core.logallrefupdates"] = (b"false",)
        (self.root / ".git/logs/HEAD").unlink()
        repository, review, owner = self.prepared()
        self.assertFalse(review.plan._log.enabled)
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "succeeded", result.reason)
        self.assertFalse((self.root / ".git/logs/HEAD").exists())
        self.assertEqual([r.name for r in repository._transaction.metadata_returns], ["HEAD", "index"])
        self.assertEqual(result.intent.candidate_log, core._ABSENT.digest)

    def test_existing_log_with_creation_disabled_is_preserved_and_appended(self):
        self.fake.config["core.logallrefupdates"] = (b"false",)
        prefix = (self.root / ".git/logs/HEAD").read_bytes()
        repository, review, owner = self.prepared()
        self.assertTrue(review.plan._log.enabled)
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "succeeded", result.reason)
        self.assertTrue((self.root / ".git/logs/HEAD").read_bytes().startswith(prefix))
        self.assertEqual([r.name for r in repository._transaction.metadata_returns], ["logs/HEAD", "HEAD", "index"])

    def test_lfs_blob_pointer_and_obvious_secret_are_not_checked_out(self):
        for raw, reason in ((switch._LFS + b"oid sha256:" + b"0" * 64 + b"\nsize 1\n", "switch-conversion"),
                            (b"-----BEGIN PRIVATE KEY-----\nINERT FIXTURE ONLY\n", "sensitive-content")):
            self.fake.after_files["a.txt"] = raw
            self.fake.refresh_entries()
            self.refusal(reason, self.prepared)
        self.assert_no_checkout()

    def test_private_or_shared_permissions_are_not_silently_broadened(self):
        os.chmod(self.root / "a.txt", 0o600)
        self.refusal("switch-layout", self.prepared)
        os.chmod(self.root / "a.txt", 0o644)
        self.fake.config["core.sharedrepository"] = (b"group",)
        self.refusal("switch-layout", self.prepared)
        self.assert_no_checkout()

    def test_restrictive_inherited_mask_refuses_before_candidate_or_checkout(self):
        repository, review, owner = self.prepared()
        self.probe_mask = 0o077
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.reason, result.settlement),
                         ("failed", "switch-file-mode", "settled"))
        self.assertEqual(owner.intents, [])
        self.assertIsNone(repository._transaction.exec_view)
        self.assertFalse(repository._unknown or repository._retained)
        self.assert_no_checkout()

    def test_foreign_head_log_or_parent_change_after_ack_is_not_overwritten(self):
        repository, review, owner = self.prepared()
        owner.on_intent = lambda _: self.write(".git/logs/foreign", b"foreign log\n")
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual((self.root / ".git/logs/foreign").read_bytes(), b"foreign log\n")
        self.assert_no_checkout()

    def test_edited_private_candidate_is_not_published_from_a_later_reopen(self):
        repository, review, owner = self.prepared()
        owner.on_intent = lambda _: repository._transaction.index.write_bytes(b"foreign candidate\n")
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertIsNone(repository._transaction.publication)
        self.assert_no_checkout()

    def test_target_lock_last_close_ambiguity_is_one_attempt_and_preserves_error(self):
        repository, review, owner = self.prepared()
        original_close = os.close
        attempts = []
        interruption = KeyboardInterrupt("inert close ambiguity")
        def ambiguous(fd):
            lock = repository._target_lock
            if lock is not None and fd == lock.fd and lock.close_claimed and not attempts:
                attempts.append(fd)
                original_close(fd)
                raise interruption
            return original_close(fd)
        with patch.object(os, "close", ambiguous):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.apply(repository, review, owner)
        self.assertIs(caught.exception, interruption)
        self.assertTrue(repository._unknown)
        self.assertFalse(repository._target_lock.close())
        self.assertEqual(len(attempts), 1)

    def test_target_lock_post_unlink_refusal_keeps_original_fd_without_retry(self):
        actual = tx.TargetLock(self.root, "refs/heads/next")
        actual.acquire()
        original_unlink = os.unlink
        parent = actual.path.parent
        before = stat.S_IMODE(parent.lstat().st_mode)
        def changed_parent(path, *args, **kwargs):
            result = original_unlink(path, *args, **kwargs)
            if path == actual.path:
                parent.chmod(0o750)
            return result
        try:
            with patch.object(os, "unlink", changed_parent):
                with self.assertRaises(core.GitError):
                    actual.close()
            self.assertTrue(actual.unknown and actual.close_claimed)
            self.assertFalse(actual.closed)
            self.assertEqual(os.fstat(actual.fd).st_ino, actual.identity[1])
            self.assertFalse(actual.close())
        finally:
            parent.chmod(before)
            os.close(actual.fd)  # Inert-only teardown, not a production retry.

    def test_log_parent_post_publication_refusal_has_no_positive_log_receipt(self):
        repository, review, owner = self.prepared()
        original = tx.SwitchTransaction._sync_directory
        def foreign_after_return(transaction, path):
            result = original(transaction, path)
            if path == self.root / ".git/logs":
                self.write(".git/logs/foreign", b"retained later fixture entry\n")
            return result
        with patch.object(tx.SwitchTransaction, "_sync_directory", foreign_after_return):
            result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement), ("unknown", "unknown"))
        self.assertEqual(repository._transaction.metadata_returns, [])
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")
        self.assertEqual((self.root / ".git/logs/foreign").read_bytes(), b"retained later fixture entry\n")

    def test_same_inode_worktree_permissions_must_remain_exact_after_checkout(self):
        repository, review, owner = self.prepared()
        self.fake.after = lambda args, *_: os.chmod(self.root / "a.txt", 0o600) if args[0] == "switch" else None
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "unknown")
        self.assertIsNone(repository._transaction.checkout_return)
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")
        self.assertEqual((self.root / ".git/index").read_bytes(), INDEX)

    def test_borrowed_native_lock_has_no_mutation_or_close_route(self):
        actual = tx.TargetLock(self.root, "refs/heads/next")
        actual.acquire()
        try:
            borrowed = tx.BorrowedTargetLock(self.root, "refs/heads/next", actual.identity,
                                            actual.parent_before, actual.parent_locked)
            borrowed.check()
            for name in ("acquire", "close", "fd"):
                self.assertFalse(hasattr(borrowed, name))
            self.assertTrue(actual.close())
            with self.assertRaises(core.GitError):
                borrowed.check()
        finally:
            if not actual.closed:
                actual.close()
