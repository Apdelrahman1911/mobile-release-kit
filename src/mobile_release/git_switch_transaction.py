"""The fixed content-switch facet of the existing index transaction.

No generic file/command endpoint. Original Git index/config/HEAD locks never
conflict with stock Git: it operates in one private execution view. Candidates
are exact before the sole ACK. Standard locks coordinate ordinary Git, not
hostile same-UID edits; destination/parent checks remain mandatory.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat

from . import git_repository_switch as switch
from . import git_repository_local as local
from . import git_repository_read as read
from . import git_service as core


class TargetLock(local._ConfigLock):
    """Actual local-fixture/core lock. Native uses its SAME SourceBook instead.

    In production Python receives BorrowedTargetLock comparison data and never
    creates/removes the native lock. Neither form admits a native invocation.
    """
    def __init__(self, root: Path, target: str):
        core._need(core._ref(target), "invalid-input")
        self.git = root / ".git"
        self.target = target
        super().__init__(self.git / (target + ".lock"))
        self.parent_before = self.parent_locked = self.parent_closed = None

    def acquire(self):
        self.parent_before = switch._directory(self.path.parent)
        super().acquire()
        self.parent_locked = switch._directory(self.path.parent)
        core._need(self.parent_before[:3] == self.parent_locked[:3]
                   and self.parent_before[6:] == self.parent_locked[6:], "stale-observation")
        self.check()

    def check(self):
        super().check()
        if self.parent_locked is not None:
            core._need(switch._directory(self.path.parent) == self.parent_locked, "stale-observation")

    def comparison(self, inventory):
        core._need(self.parent_before is not None and self.parent_locked is not None, "authorization")
        name = self.target.rsplit("/", 1)[0]
        directories = []
        for path, stamp in inventory.directories:
            if path == name:
                # ONLY our positively created lock's immediate parent has this
                # known transition. Every other name/ref/object stays exact.
                core._need(stamp in (self.parent_before[:6], self.parent_locked[:6]), "stale-observation")
                stamp = self.parent_before[:6]
            directories.append((path, stamp))
        return read._ReferenceInventory(tuple(directories), inventory.files, inventory.forbidden, inventory.pack)

    def close(self):
        if self.closed:
            return not self.unknown
        if not self.entered:
            self.closed = True
            return True
        if (self.close_claimed or not self.returned or self.fd is None
                or self.parent_before is None or self.parent_locked is None):
            self.unknown = True
            return False
        # Do not inherit config.lock's looser cleanup: this lock stays through
        # final source closure and checks exact parent/absence after unlink.
        self.check()
        self.close_claimed = True
        self.unknown = True
        os.unlink(self.path)
        self.parent_closed = switch._directory(self.path.parent)
        core._need(self.parent_locked[:3] == self.parent_closed[:3]
                   and self.parent_locked[6:] == self.parent_closed[6:]
                   and core._read(self.path, 1, regular=False)[0].kind == "absent"
                   and switch._directory(self.path.parent) == self.parent_closed, "recovery-required")
        # This final route stays held on an unclear unlink or failed postcheck.
        # Only the positively checked removal reaches the sole close attempt.
        os.close(self.fd)  # Never retry EINTR or an ambiguous close return.
        self.closed, self.unknown = True, False
        return True


class BorrowedTargetLock:
    """Comparison-only projection of the actual native-held target lock.

    Created only by the fixed worker from its sealed native original. It owns
    no native FD and has no close/unlink/admission method. Metadata alone is
    emphatically not native authority or a transfer of the SourceBook lease.
    """
    def __init__(self, root, target, identity, parent_before, parent_locked):
        core._need(core._ref(target), "invalid-input")
        self.git, self.target = root / ".git", target
        self.path = self.git / (target + ".lock")
        self.identity = identity
        self.parent_before, self.parent_locked = parent_before, parent_locked

    def check(self):
        stamp, raw = core._read(self.path, 1)
        core._need(stamp.kind == "file" and not raw and stamp.identity == self.identity, "stale-observation")
        info = self.path.lstat()
        core._need(core._identity(info) == self.identity and info.st_uid == os.getuid() and info.st_nlink == 1
                   and stat.S_IMODE(info.st_mode) == 0o600
                   and switch._directory(self.path.parent) == self.parent_locked, "stale-observation")

    comparison = TargetLock.comparison


@dataclass(frozen=True, slots=True, repr=False)
class CheckoutReturn:
    """Positive owned checkout + exact output comparison, NOT native finality."""
    intent: switch.SwitchIntent
    files: tuple[tuple[str, core._Stamp], ...]
    parents: tuple[tuple[str, tuple[int, ...]], ...]


@dataclass(frozen=True, slots=True, repr=False)
class MetadataReturn:
    name: str
    original: core._Stamp
    successor: core._Stamp


@dataclass(frozen=True, slots=True, repr=False)
class Publication:
    intent: switch.SwitchIntent
    checkout: CheckoutReturn
    metadata: tuple[MetadataReturn, ...]


class Handoff:
    def __init__(self, repository, revision, original):
        self.repository, self.revision, self.original = repository, revision, original
        self.operation_id = core._text(original.operation_id, 128)
        self.entered = self.acknowledged = False
        self.intent = None

    def check_current(self, root, action, revision):
        core._need((root, action, revision) == (self.repository.root, "branch-switch", self.revision), "authorization")
        self.original.check_current(root, action, revision)

    def record_intent(self, intent):
        transaction = self.repository._transaction
        core._need(not self.entered and type(intent) is switch.SwitchIntent
                   and transaction is not None and transaction.intent is intent, "authorization")
        self.entered, self.intent = True, intent
        self.original.record_intent(intent)
        transaction.session.guard_current()
        self.acknowledged = True

    def publication_ready(self, *, candidate_index=None):
        core._need(self.acknowledged and self.intent is not None, "authorization")
        if candidate_index is not None:
            core._need(core._read(candidate_index, switch.MAX_INDEX)[0].digest == self.intent.candidate_index,
                       "recovery-required")


class SwitchTransaction(local._LocalTransaction):
    def __init__(self, session, original, plan, owner):
        super().__init__(session, original, plan, owner)
        self.phase = "not-entered"
        self.intent = None
        self.exec_index = None
        self.exec_index_stamp = None
        self.exec_view = None
        self.candidate_head = self.candidate_log = None
        self.checkout_return = None
        self.metadata_returns = []
        self.metadata_attempted = set()
        self.directory_closes = []
        self.command_entered = None
        self.command_returned = set()
        self.exec_unknown = False
        self.log_lock = None
        self.log_parent = plan._log.parent
        self.log_names = None

    @property
    def publication(self):
        if self.checkout_return is None:
            return None
        return Publication(self.intent, self.checkout_return, tuple(self.metadata_returns))

    def acquire(self):
        core._need(self.session.target_lock is not None, "authorization")
        self.session.target_lock.check()
        super().acquire()
        self.log_names = set(self.session.names(self.session.git_dir / "logs"))
        core._need(switch._directory(self.session.git_dir / "logs") == self.plan._log.parent, "stale-observation")
        if self.plan._log.enabled:
            path = self.session.git_dir / "logs/HEAD.lock"
            self.log_lock = local._ConfigLock(path)
            self.log_lock.acquire()
            self.log_parent = switch._directory(self.session.git_dir / "logs")
            core._need(self.log_parent[:3] == self.plan._log.parent[:3]
                       and self.log_parent[6:] == self.plan._log.parent[6:]
                       and set(self.session.names(self.session.git_dir / "logs")) == self.log_names | {"HEAD.lock"},
                       "stale-observation")
        self.phase = "locked"
        self.check_original()
        self._probe_checkout_mode()
        self.exec_view = self.session.exec_view = core._FrozenGitDirectory.__new__(core._FrozenGitDirectory)
        core._FrozenGitDirectory.__init__(self.exec_view)
        # Original read view stays immutable. This second finite view contains
        # only our execution files, never the user's executable config/hooks.
        frozen = self.session.frozen
        for path in sorted(frozen.directories, key=lambda p: len(p.parts)):
            name = path.relative_to(frozen.root)
            destination = self.exec_view.root / name
            if destination not in self.exec_view.directories:
                destination.mkdir(mode=0o700)
                self.exec_view.directories[destination] = core._identity(destination.lstat())[:2]
        for path, stamp in frozen.files.items():
            name = str(path.relative_to(frozen.root))
            if name == read._CONFIG_FILE:
                continue
            body = core._read(path, 65536)[1]
            if name == "config":
                log = self.plan._snapshot.config.get("core.logallrefupdates", (b"true",))[0]
                body += (b"[core]\nautocrlf=false\nlogAllRefUpdates=" + log
                         + b"\n[checkout]\nworkers=1\n")
            elif name == "info/attributes":
                # Original policy was explicitly checked above. This fixed
                # high-priority rule prevents a concurrent attribute/config
                # edit from running conversion before it can be refused.
                body = b"* -filter -text -eol -ident -working-tree-encoding\n"
            self.exec_view.write(name, body)
        log_parent = self.exec_view.root / "logs"
        log_parent.mkdir(mode=0o700)
        self.exec_view.directories[log_parent] = core._identity(log_parent.lstat())[:2]
        if self.plan._log.original.kind == "file":
            self.exec_view.write("logs/HEAD", self.plan._log.content)
        self.exec_index = self.scratch / "execution-index"
        self._write_scratch(self.exec_index, self.original.index_bytes)
        self.exec_index_stamp = core._read(self.exec_index, switch.MAX_INDEX)[0]
        self.check_execution()

    def _probe_checkout_mode(self):
        """No umask read/change, executable probe or original-file rewrite.

        The existing C/A/W target inherits this worker's creation mask without
        changing it. One empty non-executable file in the SAME private scratch
        catches a restrictive read/write mask before any checkout. This is not
        a proof of final executable bits: all final modes remain exact checked
        postconditions; an unexpected narrowing is retained, never success.
        """
        self.session.guard_current()
        path = self.scratch / "checkout-mode"
        core._need(path not in self.scratch_files, "already-used")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o666)
        try:
            info = os.fstat(fd)
            self.scratch_files[path] = core._identity(info)
            core._need(core._identity(path.lstat()) == self.scratch_files[path]
                       and stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                       and info.st_nlink == 1 and info.st_size == 0, "recovery-required")
            switch._require(stat.S_IMODE(info.st_mode) == 0o644, "switch-file-mode")
            os.fsync(fd)
        finally:
            self.directory_closes.append(fd)
            os.close(fd)  # Retired before one close; ambiguity is absorbing.
            self.directory_closes.pop()
        self.session.guard_current()

    def _write_scratch(self, path, content):
        core._need(path.parent == self.scratch and path.name in ("index", "execution-index", "HEAD", "HEAD-log"),
                   "authorization")
        prior = self.scratch_files.get(path)
        if prior is not None:
            core._need(core._identity(path.lstat()) == prior, "stale-observation")
        flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        flags |= os.O_CREAT | os.O_EXCL if prior is None else os.O_TRUNC
        fd = os.open(path, flags, 0o600)
        try:
            at = 0
            while at < len(content):
                count = os.write(fd, content[at:])
                core._need(count > 0, "recovery-required")
                at += count
            os.fsync(fd)
        finally:
            self.directory_closes.append(fd)
            os.close(fd)
            self.directory_closes.pop()
        self.scratch_files[path] = core._identity(path.lstat())

    def check_execution(self):
        if self.exec_view is None:
            return
        core._need(not self.exec_unknown and not self.exec_view.unknown, "unknown")
        for path, identity in self.exec_view.directories.items():
            core._need(core._identity(path.lstat())[:2] == identity and stat.S_ISDIR(path.lstat().st_mode),
                       "stale-observation")
            expected = {entry.name for entry in (*self.exec_view.directories, *self.exec_view.files)
                        if entry != path and entry.parent == path}
            core._need(set(self.session.names(path)) == expected, "stale-observation")
        for path, stamp in self.exec_view.files.items():
            core._need(core._read(path, 65536)[0] == stamp, "stale-observation")
        if self.exec_index_stamp is not None:
            core._need(core._read(self.exec_index, switch.MAX_INDEX)[0] == self.exec_index_stamp, "stale-observation")

    def _check_worktree(self, *, accept_checkout=False):
        plan = self.plan
        expected = dict(plan._footprint.files)
        after = dict(self.checkout_return.files) if self.checkout_return is not None else {}
        target = {item.path: item for item in plan.target_tree}
        hashes = dict(plan._target_hashes)
        observed = {}
        expected_parents = dict(plan._footprint.parents)
        accepted_parents = dict(self.checkout_return.parents) if self.checkout_return is not None else {}
        # Recheck every original physical ancestry BEFORE a file read, not
        # only afterwards through a parent listing. A swapped directory must
        # not redirect an unchanged tracked-file check out of this project.
        for name, old in plan._footprint.ancestors:
            actual = switch._directory(self.session.root / name)
            if accept_checkout and name in expected_parents:
                core._need(actual[:3] == old[:3] and actual[6:] == old[6:], "recovery-required")
            else:
                core._need(actual == accepted_parents.get(name, old), "stale-observation")
        for name, old in expected.items():
            actual, _ = core._read(self.session.root / name, core.MAX_FILE_BYTES)
            if accept_checkout and name in plan.changed:
                item = target[name]
                info = (self.session.root / name).lstat()
                core._need(actual.kind == "file" and actual.digest == hashes[name] and info.st_size == item.size
                           and info.st_uid == os.getuid() and info.st_nlink == 1 and not info.st_mode & 0o7022
                           and stat.S_IMODE(info.st_mode) == stat.S_IMODE(old.identity[2]), "recovery-required")
                observed[name] = actual
            else:
                core._need(actual == after.get(name, old), "stale-observation")
        parents = {}
        for name, old in expected_parents.items():
            path = self.session.root / name
            actual = switch._directory(path)
            if accept_checkout:
                core._need(actual[:3] == old[:3] and actual[6:] == old[6:], "recovery-required")
                parents[name] = actual
            else:
                core._need(actual == accepted_parents.get(name, old), "stale-observation")
            expected_names = {Path(p).name for p in (*expected, *expected_parents, *dict(plan._footprint.preserved))
                              if p != "." and (self.session.root / p).parent == path}
            if path == self.session.root:
                expected_names.add(".git")
            core._need(set(self.session.names(path)) == expected_names, "stale-observation")
        for name, before in plan._footprint.preserved:
            actual, _ = switch._stamp_preserved(self.session.root / name, core.MAX_FILE_BYTES)
            core._need(actual == before, "stale-observation")
        return tuple(sorted(observed.items())), tuple(sorted(parents.items()))

    def check_original(self):
        self.config_lock.check()
        self.session.check_original()
        self.session._check_frozen()
        self.session.target_lock.check()
        expected = {row.name: row.successor for row in self.metadata_returns}
        core._need(core._read(self.session.git_dir / "index", switch.MAX_INDEX)[0]
                   == expected.get("index", self.original.index_stamp), "stale-observation")
        for path, before in self.original.metadata.items():
            if path == self.session.git_dir / "HEAD":
                before = expected.get("HEAD", before)
            core._need(core._read(path, 65536)[0] == before, "stale-observation")
        core._need(self.session.operation_markers() == self.original.operations, "stale-observation")
        for path, fd, identity in self.locks:
            published = next((row for row in self.metadata_returns if path.name == row.name + ".lock"), None)
            current = (self.session.git_dir / published.name).lstat() if published else path.lstat()
            core._need(core._identity(current)[:2] == identity[:2] == core._identity(os.fstat(fd))[:2],
                       "stale-observation")
        log = expected.get("logs/HEAD", self.plan._log.original)
        core._need(core._read(self.session.git_dir / "logs/HEAD", 65536)[0] == log, "stale-observation")
        parent = switch._directory(self.session.git_dir / "logs")
        core._need(parent == self.log_parent, "stale-observation")
        if self.log_names is not None:
            names = self.log_names | ({"HEAD"} if "logs/HEAD" in expected else {"HEAD.lock"} if self.log_lock else set())
            core._need(set(self.session.names(self.session.git_dir / "logs")) == names, "stale-observation")
        if self.log_lock is not None and "logs/HEAD" not in expected:
            self.log_lock.check()
        self._check_worktree()
        self.session.guard_current()

    def admit_command(self, args, index, identity):
        core._need(self.command_entered is None and self.exec_view is not None, "already-used")
        head, target = self.plan._snapshot.public.head, self.plan.target
        if args == ["read-tree", "-m", head, self.plan.target_oid]:
            phase = "index-candidate"
            core._need(self.phase == "locked" and index == self.exec_index and identity is None, "authorization")
        elif args == ["ls-files", "--stage", "-z"]:
            phase = "index-verify"
            core._need(self.phase == "index-candidate" and index == self.exec_index and identity is None, "authorization")
        elif args == ["symbolic-ref", "-m", switch._MESSAGE, "HEAD", target]:
            phase = "head-candidate"
            core._need(self.phase == "index-verified" and index == self.exec_index
                       and identity is self.plan._log.identity, "authorization")
        elif args == ["switch", "--no-guess", "--no-recurse-submodules", "--no-overwrite-ignore", "--", self.plan.name]:
            phase = "checkout"
            core._need(self.phase == "candidates-ready" and index == self.exec_index
                       and identity is self.plan._log.identity, "authorization")
            self.owner.publication_ready(candidate_index=self.index)
        else:
            raise core.GitError("invalid-input")
        core._need(phase not in self.command_returned, "already-used")
        self.check_original()
        self.check_execution()
        self.command_entered = phase
        if phase == "checkout":
            self.phase = "checkout-entered"

    def command_did_return(self, args, result):
        """Called only after the actual original command/lifetime return.

        The fixed worker uses this BEFORE its source postcheck. The core-only
        caller uses the same function just after _run returns. Both supply the
        exact transaction command, never arbitrary result-shaped authority.
        """
        phase = self.command_entered
        core._need(phase is not None and phase not in self.command_returned
                   and type(result.returncode) is int and result.returncode == 0, "recovery-required")
        expected = self.session.execution_command
        core._need(expected is not None and tuple(args) == expected[0], "authorization")
        if phase == "index-candidate":
            stamp, raw = core._read(self.exec_index, switch.MAX_INDEX)
            core._need(stamp.kind == "file", "response-invalid")
            self.exec_index_stamp = stamp
            self.scratch_files[self.exec_index] = stamp.identity
            self._write_scratch(self.index, raw)
            self.phase = "index-candidate"
        elif phase == "index-verify":
            core._need(core._entries(result.stdout) == {f.path: (core._Entry(f.mode, f.oid, 0),)
                       for f in self.plan.target_tree}, "recovery-required")
            self.phase = "index-verified"
        else:
            head_path = self.exec_view.root / "HEAD"
            head, raw_head = core._read(head_path, 2048)
            core._need(head.kind == "file" and raw_head == ("ref: " + self.plan.target + "\n").encode("utf-8"),
                       "recovery-required")
            log_path = self.exec_view.root / "logs/HEAD"
            log, raw_log = core._read(log_path, 65536)
            self._check_candidate_log(log, raw_log)
            self.exec_view.files[head_path] = head
            if log.kind == "file":
                self.exec_view.files[log_path] = log
            if phase == "head-candidate":
                self.candidate_head, self.candidate_log = raw_head, raw_log
                self._write_scratch(self.scratch / "HEAD", raw_head)
                if self.plan._log.enabled:
                    self._write_scratch(self.scratch / "HEAD-log", raw_log)
                self.phase = "metadata-candidate"
            else:
                # Adopt only fixed private outputs after positive Git return.
                self.exec_index_stamp, _ = core._read(self.exec_index, switch.MAX_INDEX)
                self.scratch_files[self.exec_index] = self.exec_index_stamp.identity
                files, parents = self._check_worktree(accept_checkout=True)
                self._fsync_worktree()
                core._need(self._check_worktree(accept_checkout=True) == (files, parents), "recovery-required")
                self.checkout_return = CheckoutReturn(self.intent, files, parents)
                self.phase = "checkout-returned"
        self.command_returned.add(phase)
        self.command_entered = None
        self.check_execution()

    def _check_candidate_log(self, stamp, raw):
        policy = self.plan._log
        if not policy.enabled:
            core._need(stamp.kind == "absent" and not raw, "recovery-required")
            return
        core._need(stamp.kind == "file" and raw.startswith(policy.content), "recovery-required")
        tail = raw[len(policy.content):]
        identity = (policy.identity.name + " <" + policy.identity.email + ">").encode("utf-8")
        prefix = self.plan._snapshot.public.head.encode("ascii") + b" " + self.plan.target_oid.encode("ascii") + b" " + identity + b" "
        core._need(tail.startswith(prefix) and len(tail) <= 2048 and tail.endswith(b"\n")
                   and tail.count(b"\n") == 1, "recovery-required")
        clock, separator, message = tail[len(prefix):].partition(b"\t")
        import re
        core._need(re.fullmatch(rb"[0-9]{1,12} [+-][0-9]{4}", clock) is not None and separator == b"\t",
                   "recovery-required")
        expected = switch._MESSAGE.encode("ascii") if self.command_entered == "head-candidate" else (
            "checkout: moving from " + self.plan._snapshot.public.branch[len("refs/heads/"):] + " to " + self.plan.name).encode("utf-8")
        core._need(message == expected + b"\n", "recovery-required")

    def prepare_candidates(self):
        plan = self.plan
        self.session.execute_private(["read-tree", "-m", plan._snapshot.public.head, plan.target_oid], index=self.exec_index)
        self.session.execute_private(["ls-files", "--stage", "-z"], index=self.exec_index)
        self.session.execute_private(["symbolic-ref", "-m", switch._MESSAGE, "HEAD", plan.target],
                                     index=self.exec_index, identity=plan._log.identity)
        core._need(self.phase == "metadata-candidate", "recovery-required")
        # Reset ONLY this operation's exact private view, never user's index,
        # refs, log or worktree. Stock switch still sees the original checkout.
        self.exec_view.write("HEAD", ("ref: " + plan._snapshot.public.branch + "\n").encode("utf-8"))
        log_path = self.exec_view.root / "logs/HEAD"
        if plan._log.original.kind == "file":
            self.exec_view.write("logs/HEAD", plan._log.content)
        elif log_path in self.exec_view.files:
            core._need(core._read(log_path, 65536)[0] == self.exec_view.files[log_path], "stale-observation")
            del self.exec_view.files[log_path]
            os.unlink(log_path)
        self._write_scratch(self.exec_index, self.original.index_bytes)
        self.exec_index_stamp = core._read(self.exec_index, switch.MAX_INDEX)[0]
        self.intent = switch.SwitchIntent(plan._snapshot.public.revision, plan.reference_revision,
            plan._snapshot.public.branch, plan._snapshot.public.head, plan._snapshot.index_stamp.digest,
            plan.target, plan.target_oid, core._read(self.index, switch.MAX_INDEX)[0].digest,
            core._digest(self.session.head_bytes), core._digest(self.candidate_head), plan._log.original.digest,
            core._digest(self.candidate_log) if plan._log.enabled else core._ABSENT.digest, plan._log.enabled,
            switch._hash({"source": plan._footprint.comparison(), "target": plan._target_hashes}))
        self.phase = "candidates-ready"
        self.check_execution()
        self.check_original()

    def checkout(self):
        self.session.execute_private(["switch", "--no-guess", "--no-recurse-submodules", "--no-overwrite-ignore", "--", self.plan.name],
                                     index=self.exec_index, identity=self.plan._log.identity)
        core._need(self.checkout_return is not None, "recovery-required")
        self.check_original()

    def _sync_directory(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            self.directory_closes.append(fd)
            os.close(fd)
            self.directory_closes.pop()

    def _fsync_worktree(self):
        for name in self.plan.changed:
            path = self.session.root / name
            before = core._identity(path.lstat())
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                core._need(core._identity(os.fstat(fd)) == before, "recovery-required")
                os.fsync(fd)
                core._need(core._identity(os.fstat(fd)) == before == core._identity(path.lstat()), "recovery-required")
            finally:
                self.directory_closes.append(fd)
                os.close(fd)
                self.directory_closes.pop()
        for name, _ in self.plan._footprint.parents:
            self._sync_directory(self.session.root / name)

    def publish_metadata(self, name):
        core._need(self.checkout_return is not None and name not in self.metadata_attempted, "already-used")
        expected_order = ["logs/HEAD", "HEAD", "index"] if self.plan._log.enabled else ["HEAD", "index"]
        core._need(name == expected_order[len(self.metadata_returns)], "authorization")
        self.owner.publication_ready(candidate_index=self.index)
        self.check_original()
        if name == "logs/HEAD":
            lock, fd = self.log_lock.path, self.log_lock.fd
            content, before = self.candidate_log, self.plan._log.original
        else:
            route = next(row for row in self.locks if row[0].name == name + ".lock")
            lock, fd, _ = route
            before = self.original.index_stamp if name == "index" else next(s for n, s, _ in self.session.originals.files if n == "HEAD")
            content = core._read(self.index, switch.MAX_INDEX)[1] if name == "index" else self.candidate_head
        core._need(fd is not None and content is not None, "authorization")
        expected_digest = {"index": self.intent.candidate_index, "HEAD": self.intent.candidate_head,
                           "logs/HEAD": self.intent.candidate_log}[name]
        core._need(core._digest(content) == expected_digest, "recovery-required")
        self.metadata_attempted.add(name)  # Before the first possible effect.
        at = 0
        while at < len(content):
            size = os.write(fd, content[at:])
            core._need(size > 0, "recovery-required")
            at += size
        if before.kind == "file":
            os.fchmod(fd, stat.S_IMODE(before.identity[2]))
        os.fsync(fd)
        # Lock inode/size changes are ours; do not accidentally compare it to
        # its original empty identity as though it were immutable input.
        if name == "logs/HEAD":
            self.log_lock.identity = core._identity(os.fstat(fd))
        self.check_original()
        destination = self.session.git_dir / name
        core._need(core._read(destination, max(switch.MAX_INDEX, 65536))[0] == before, "stale-observation")
        os.replace(lock, destination)
        if name == "index":
            self.published = True  # Early fact only, NOT a positive receipt.
        self._sync_directory(destination.parent)
        successor, actual = core._read(destination, max(switch.MAX_INDEX, 65536))
        core._need(successor.kind == "file" and actual == content
                   and successor.identity == core._identity(os.fstat(fd)), "recovery-required")
        if name == "logs/HEAD":
            parent = switch._directory(destination.parent)
            core._need(parent[:3] == self.log_parent[:3] and parent[6:] == self.log_parent[6:]
                       and set(self.session.names(destination.parent)) == self.log_names | {"HEAD"}, "recovery-required")
            self.log_parent = parent
        # No positive receipt is available until the exact post-parent/name
        # checks have also returned. A renamed-but-unproven path is UNKNOWN.
        self.metadata_returns.append(MetadataReturn(name, before, successor))
        if name == "HEAD":
            self.session._resolved_head = None
            self.session.switch_successors["HEAD"] = (successor, content)
            self.session.frozen.write("HEAD", content)
            self.session.head_bytes = content
        self.phase = {"logs/HEAD": "log-published", "HEAD": "head-published", "index": "index-published"}[name]
        self.check_original()

    def close(self, *, preserve_scratch=False):
        # A possibly renamed metadata lock cannot be adopted from name alone.
        positive = {row.name for row in self.metadata_returns}
        if self.metadata_attempted - positive or self.command_entered is not None or self.directory_closes:
            self.retained = self.session.repository._unknown = True
            return False
        good = True
        if self.exec_view is not None and not preserve_scratch:
            self.check_execution()
            good = self.exec_view.close()
        # Retire positively published HEAD/log routes before the base cleanup;
        # it knows only the old index-publication case. Never unlink destination.
        for name in ("HEAD",):
            if name in positive:
                row = next(row for row in self.locks if row[0].name == name + ".lock")
                self.locks.remove(row)
                self.uncertain_closes.append(row)
                os.close(row[1])
                self.uncertain_closes.pop()
        if self.log_lock is not None:
            if "logs/HEAD" in positive:
                self.log_lock.close_claimed = True
                self.log_lock.unknown = True
                os.close(self.log_lock.fd)
                self.log_lock.closed, self.log_lock.unknown = True, False
            else:
                good = self.log_lock.close() and good
        good = super().close(preserve_scratch=preserve_scratch) and good
        self.retained |= preserve_scratch or not good
        return good
