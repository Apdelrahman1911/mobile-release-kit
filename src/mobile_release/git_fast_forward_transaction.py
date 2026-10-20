"""One fixed FF facet, not a process owner or a general file publisher.

The exact candidate index is frozen before ACK. The worktree update uses a
separate private index. Only a returned expected-old stock Git CAS can advance
the attached ref; HEAD remains symbolic and Git itself appends both reflogs.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
import stat

from . import git_repository_fast_forward as ff
from . import git_repository_local as local
from . import git_repository_read as read
from . import git_repository_switch as switch
from . import git_service as core
from . import git_switch_transaction as shared


class TrackingLock(shared.TargetLock):
    def __init__(self, root, target):
        core._need(ff.tracking_ref(target), "invalid-input")
        self.git, self.target = root / ".git", target
        local._ConfigLock.__init__(self, self.git / (target + ".lock"))
        self.parent_before = self.parent_locked = self.parent_closed = None


class BorrowedTrackingLock(shared.BorrowedTargetLock):
    def __init__(self, root, target, identity, parent_before, parent_locked):
        core._need(ff.tracking_ref(target), "invalid-input")
        self.git, self.target = root / ".git", target
        self.path = self.git / (target + ".lock")
        self.identity, self.parent_before, self.parent_locked = identity, parent_before, parent_locked


@dataclass(frozen=True, slots=True, repr=False)
class RefReturn:
    intent: ff.FastForwardIntent
    successor: local._RefSuccessor
    logs: tuple[shared.MetadataReturn, ...]
    parents: tuple


@dataclass(frozen=True, slots=True, repr=False)
class Publication:
    intent: ff.FastForwardIntent
    checkout: shared.CheckoutReturn
    index: local._IndexPublication | None
    reference: RefReturn | None


class Handoff:
    def __init__(self, repository, plan, original):
        self.repository, self.plan, self.original = repository, plan, original
        self.operation_id = core._text(original.operation_id, 128)
        self.entered = self.acknowledged = False
        self.intent = None

    def check_current(self, root, action, revision):
        core._need((root, action, revision) == (self.repository.root, ff.KIND, self.plan._snapshot.public.revision),
                   "authorization")
        self.original.check_current(root, action, revision)

    def record_intent(self, intent):
        transaction = self.repository._transaction
        core._need(not self.entered and type(intent) is ff.FastForwardIntent and transaction is not None
                   and transaction.intent is intent, "authorization")
        self.entered, self.intent = True, intent
        self.original.record_intent(intent)
        transaction.session.guard_current()
        self.acknowledged = True

    def publication_ready(self, *, candidate_index=None):
        core._need(self.acknowledged and self.intent is not None, "authorization")
        if candidate_index is not None:
            core._need(core._read(candidate_index, switch.MAX_INDEX)[0].digest == self.intent.candidate_index,
                       "recovery-required")


class FastForwardTransaction(shared.SwitchTransaction):
    def __init__(self, session, original, plan, owner):
        super().__init__(session, original, plan, owner)
        self.reference_return = None
        self.head_release_attempted = False
        self.head_released = False

    @property
    def publication(self):
        if self.checkout_return is None:
            return None
        return Publication(self.intent, self.checkout_return, self.index_publication, self.reference_return)

    def acquire(self):
        self.session.target_lock.check()
        local._LocalTransaction.acquire(self)
        self.phase = "locked"
        self.check_original()
        self._prepare_execution()

    def _logs(self):
        return (("logs/HEAD", self.plan._log), ("logs/" + self.plan._snapshot.public.branch, self.plan._branch_log))

    def _check_logs(self, *, accept=False):
        prior = {} if self.reference_return is None else {r.name: r.successor for r in self.reference_return.logs}
        parent_prior = {} if self.reference_return is None else dict(self.reference_return.parents)
        result, parents = [], []
        for name, old in self.plan._log_parents:
            actual = switch._directory(self.session.git_dir / name)
            if accept:
                core._need(actual[:3] == old[:3] and actual[6:] == old[6:], "recovery-required")
            else:
                core._need(actual == parent_prior.get(name, old), "stale-observation")
            parents.append((name, actual))
        for name, names in self.plan._log_rosters:
            expected = set(names)
            for log, policy in self._logs():
                if log.rsplit("/", 1)[0] == name and policy.enabled and (accept or self.reference_return is not None):
                    expected.add(log.rsplit("/", 1)[1])
            core._need(set(self.session.names(self.session.git_dir / name)) == expected, "stale-observation")
        for name, policy in self._logs():
            path = self.session.git_dir / name
            stamp, raw = core._read(path, 65536)
            if not accept:
                core._need(stamp == prior.get(name, policy.original), "stale-observation")
                continue
            if not policy.enabled:
                core._need(stamp == policy.original and stamp.kind == "absent", "recovery-required")
                continue
            identity = (policy.identity.name + " <" + policy.identity.email + ">").encode("utf-8")
            prefix = (self.plan._snapshot.public.head + " " + self.plan.target_oid + " ").encode("ascii") + identity + b" "
            core._need(stamp.kind == "file" and raw.startswith(policy.content), "recovery-required")
            tail = raw[len(policy.content):]
            core._need(len(tail) <= 2048 and re.fullmatch(re.escape(prefix) + rb"[0-9]{1,12} [+-][0-9]{4}\t"
                       + re.escape(ff.MESSAGE.encode("ascii")) + rb"\n", tail) is not None, "recovery-required")
            info = path.lstat()
            core._need(info.st_uid == os.getuid() and info.st_nlink == 1 and not info.st_mode & 0o7022
                       and core._identity(info) == stamp.identity, "recovery-required")
            if policy.original.kind == "file":
                core._need(stat.S_IMODE(info.st_mode) == stat.S_IMODE(policy.original.identity[2]), "recovery-required")
            result.append(shared.MetadataReturn(name, policy.original, stamp))
        return tuple(result), tuple(parents)

    def check_original(self):
        self.config_lock.check()
        self.session.check_original()
        self.session._check_frozen()
        self.session.target_lock.check()
        expected = self.original.index_stamp if self.index_publication is None else self.index_publication.successor
        core._need(core._read(self.session.git_dir / "index", switch.MAX_INDEX)[0] == expected, "stale-observation")
        core._need(all(core._read(p, 65536)[0] == s for p, s in self.original.metadata.items()), "stale-observation")
        core._need(self.session.operation_markers() == self.original.operations, "stale-observation")
        for path, fd, identity in self.locks:
            current = self.session.git_dir / "index" if path.name == "index.lock" and self.index_publication else path
            core._need(core._identity(current.lstat())[:2] == identity[:2] == core._identity(os.fstat(fd))[:2],
                       "stale-observation")
        self._check_logs()
        self._check_worktree()
        self.session.guard_current()

    def admit_command(self, args, index, identity):
        core._need(self.command_entered is None and self.exec_view is not None, "already-used")
        head, target = self.plan._snapshot.public.head, self.plan.target_oid
        if args == ["read-tree", "-m", head, target]:
            phase = "index-candidate"
            core._need(self.phase == "locked" and index == self.exec_index and identity is None, "authorization")
        elif args == ["ls-files", "--stage", "-z"]:
            phase = "index-verify"
            core._need(self.phase == "index-candidate" and index == self.exec_index and identity is None, "authorization")
        elif args == ["read-tree", "-m", "-u", head, target]:
            phase = "checkout"
            core._need(self.phase == "candidates-ready" and index == self.exec_index and identity is None, "authorization")
            self.owner.publication_ready(candidate_index=self.index)
        elif args == ["update-ref", "--no-deref", "-m", ff.MESSAGE, self.plan._snapshot.public.branch, target, head]:
            phase = "reference"
            core._need(self.phase == "index-returned" and self.head_released and index is None
                       and identity is self.plan._log.identity, "authorization")
            self.owner.publication_ready(candidate_index=self.index)
        else:
            raise core.GitError("invalid-input")
        core._need(phase not in self.command_returned, "already-used")
        self.check_original()
        self.check_execution()
        self.command_entered = phase

    def command_did_return(self, args, result):
        phase = self.command_entered
        core._need(phase is not None and phase not in self.command_returned and self.session.execution_command is not None
                   and tuple(args) == self.session.execution_command[0] and type(result.returncode) is int
                   and result.returncode == 0, "recovery-required")
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
        elif phase == "checkout":
            self.exec_index_stamp, _ = core._read(self.exec_index, switch.MAX_INDEX)
            self.scratch_files[self.exec_index] = self.exec_index_stamp.identity
            files, parents = self._check_worktree(accept_checkout=True)
            self._fsync_worktree()
            core._need(self._check_worktree(accept_checkout=True) == (files, parents), "recovery-required")
            self.checkout_return = shared.CheckoutReturn(self.intent, files, parents)
            self.phase = "worktree-returned"
        else:
            # No current/source exception is available before this actual
            # positive returned CAS. A failed postcheck keeps entered latched.
            self.session._resolved_head = None
            current = self.session.target_lock.comparison(read._inventory(self.session.git_dir,
                self.session.checkpoint, self.session.names))
            name, oid = self.plan._snapshot.public.branch, self.plan.target_oid
            selected = next((s, raw) for p, s, raw in current.files if p == name)
            core._need(selected[0].kind == "file" and selected[1] == (oid + "\n").encode("ascii"), "recovery-required")
            successor = local._RefSuccessor(name, oid, selected[0], dict(current.directories)[name.rsplit("/", 1)[0]])
            core._need(local._inventory_matches(self.session.originals, current, objects_written=False, successor=successor),
                       "recovery-required")
            logs, parents = self._check_logs(accept=True)
            for path, stamp in ((self.session.git_dir / name, selected[0]), *(
                    (self.session.git_dir / r.name, r.successor) for r in logs)):
                self._sync_file(path, stamp)
                self._sync_directory(path.parent)
            core._need(self._check_logs(accept=True) == (logs, parents)
                       and core._read(self.session.git_dir / name, 65)[0] == selected[0], "recovery-required")
            self.session.successor = successor
            self.session.frozen.write(name, selected[1])
            self.reference_return = RefReturn(self.intent, successor, logs, parents)
            self.phase = "ref-returned"
        self.command_returned.add(phase)
        self.command_entered = None
        self.check_execution()

    def _sync_file(self, path, stamp):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            core._need(core._identity(os.fstat(fd)) == stamp.identity, "recovery-required")
            os.fsync(fd)
            core._need(core._identity(os.fstat(fd)) == stamp.identity == core._identity(path.lstat()), "recovery-required")
        finally:
            self.directory_closes.append(fd)
            os.close(fd)
            self.directory_closes.pop()

    def prepare_candidates(self):
        plan = self.plan
        self.session.execute_private(["read-tree", "-m", plan._snapshot.public.head, plan.target_oid], index=self.exec_index)
        self.session.execute_private(["ls-files", "--stage", "-z"], index=self.exec_index)
        core._need(self.phase == "index-verified", "recovery-required")
        self._write_scratch(self.exec_index, self.original.index_bytes)
        self.exec_index_stamp = core._read(self.exec_index, switch.MAX_INDEX)[0]
        self.intent = ff.FastForwardIntent(plan._snapshot.public.revision, plan.reference_revision,
            plan._snapshot.public.branch, plan._snapshot.public.head, plan._snapshot.index_stamp.digest,
            plan.target_ref, plan.target_oid, core._read(self.index, switch.MAX_INDEX)[0].digest,
            core._digest(self.session.head_bytes), plan._log.original.digest, plan._branch_log.original.digest,
            plan._log.enabled, plan._branch_log.enabled,
            switch._hash({"source": plan._footprint.comparison(), "target": plan._target_hashes}))
        self.phase = "candidates-ready"
        self.check_original()
        self.check_execution()

    def checkout(self):
        self.session.execute_private(["read-tree", "-m", "-u", self.plan._snapshot.public.head, self.plan.target_oid],
                                     index=self.exec_index)
        core._need(self.checkout_return is not None, "recovery-required")
        self.check_original()

    def publish_index(self):
        core._need(self.checkout_return is not None and self.phase == "worktree-returned", "authorization")
        local._LocalTransaction.publish_index(self)
        self.phase = "index-returned"
        self.check_original()

    def publish_ref(self):
        core._need(self.index_publication is not None and not self.head_release_attempted, "authorization")
        self.check_original()
        self.head_release_attempted = True
        self.release_head_lock()
        self.head_released = True
        self.check_original()
        self.session.execute_private(["update-ref", "--no-deref", "-m", ff.MESSAGE,
            self.plan._snapshot.public.branch, self.plan.target_oid, self.plan._snapshot.public.head],
            index=None, identity=self.plan._log.identity)
        core._need(self.reference_return is not None, "recovery-required")
        self.check_original()

    def close(self, *, preserve_scratch=False):
        if (self.command_entered is not None or self.directory_closes or self.uncertain_closes
                or self.publishing_index and self.index_publication is None
                or self.head_release_attempted and not self.head_released):
            self.retained = self.session.repository._unknown = True
            return False
        good = True
        if self.exec_view is not None and not preserve_scratch:
            self.check_execution()
            good = self.exec_view.close()
        good = local._LocalTransaction.close(self, preserve_scratch=preserve_scratch) and good
        self.retained |= preserve_scratch or not good
        return good
