"""Rename-only source comparisons in the SAME original GitLocalOperation.

Every original and successor FD remains in that operation's finite close book.
No receipt-shaped input permits a pathname exception: only the actual core
transaction, matched native candidate ACK, and its exact positive prefix do.
"""
from __future__ import annotations

import hashlib
import os
import stat

from . import _desktop_git_local_protocol as wire
from . import _desktop_git_read_protocol as fields
from . import _desktop_git_rename as codec
from . import git_repository_rename as rename
from . import git_rename_transaction as tx
from . import git_service as core
from .desktop_git_read import GitReadOperation, _Original


class State:
    def __init__(self, operation):
        from .desktop_git_local import GitLocalOperation
        wire.require(type(operation) is GitLocalOperation and type(operation.request.action) is codec.Action
                     and not operation.entered and all(not row.entered for row in operation.originals))
        self.operation = operation
        self.original = operation.request.rename_sources
        self.lock = None if self.original is None else self.original.locks.comparison(
            operation.request.root, self.original.source_ref, operation.request.action.name)
        self.sources, self.successors, self.accepted = {}, {}, {}
        self.progress = None
        if self.original is not None:
            wire.require(type(self.original) is codec.Sources and operation.request.phase == "apply")
            for snapshot in (self.original.reference, self.original.branch_log, self.original.head_log):
                if snapshot is not None:
                    wire.require(all(row.path != snapshot.path for row in operation.originals))
                    operation.originals.append(_Original(snapshot.path, snapshot.identity, snapshot.sha256))
            for row in operation.originals:
                if row.sha256 is not None and row.path.is_relative_to(operation.request.root):
                    self.sources[str(row.path.relative_to(operation.request.root))] = row
        else:
            wire.require(operation.request.phase == "prepare")

    def _transaction(self):
        operation, repository = self.operation, self.operation.repository
        transaction = None if repository is None else repository._transaction
        if transaction is None or not transaction.returns:
            return None
        wire.require(type(repository) is rename.GitRenameRepository and not repository._unknown
                     and type(transaction) is tx.RenameTransaction and transaction.session.repository is repository
                     and type(operation.review) is rename.RenameReview and transaction.plan is operation.review.plan
                     and transaction.owner.original is operation and transaction.owner.acknowledged
                     and operation.source.candidate_returned and operation.source.candidate is not None
                     and transaction.intent is operation.source.candidate.intent
                     and transaction.owner.intent is transaction.intent)
        codec.matches_review(operation.request, operation.review)
        return transaction

    def receipts(self):
        transaction = self._transaction()
        if transaction is None:
            return {}
        plan, intent = transaction.plan, transaction.intent
        returned, steps = transaction.returns, rename.steps(plan)
        wire.require(len(returned) <= len(steps) and tuple(row.step for row in returned) == steps[:len(returned)])
        old_log, new_log = ".git/logs/" + plan.source, ".git/logs/" + plan.target
        originals = {"new-log": core._ABSENT, "old-log": plan._controls.file("logs/" + plan.source)[0],
                     "ref": plan._controls.file(plan.source)[0], "head-log": plan._controls.file("logs/HEAD")[0],
                     "head": plan._snapshot.metadata[transaction.session.git_dir / "HEAD"],
                     "config": plan._controls.file("config")[0]}
        names = {"new-log": (new_log, new_log), "old-log": (old_log, None), "ref": (".git/" + plan.source, ".git/" + plan.target),
                 "head-log": (".git/logs/HEAD", ".git/logs/HEAD"), "head": (".git/HEAD", ".git/HEAD"), "config": (".git/config", ".git/config")}
        digests = {"new-log": intent.candidate_log, "old-log": core._ABSENT.digest,
                   "ref": core._digest((intent.expected_head + "\n").encode("ascii")),
                   "head-log": intent.candidate_head_log, "head": core._digest(("ref: " + intent.target_ref + "\n").encode("ascii")),
                   "config": intent.candidate_config}
        result = {}
        for row in returned:
            wire.require(type(row) is tx.Returned and row.original == originals[row.step]
                         and row.successor.digest == digests[row.step]
                         and row.successor.kind == ("absent" if row.step == "old-log" else "file"))
            if row.step == "ref":
                wire.require(row.original.identity[:5] == row.successor.identity[:5] and row.parent is not None)
            result[row.step] = (*names[row.step], row.original, row.successor, row.parent)
        return result

    def _admit(self, step, receipt):
        operation = self.operation
        source_name, target_name, before, after, _ = receipt
        original = self.sources.get(source_name)
        wire.require(step not in self.accepted and
                     (before.kind == "absent" and original is None and step == "new-log" or
                      before.kind == "file" and original is not None
                      and codec.core_identity(original.identity) == before.identity and original.sha256 == before.digest))
        if target_name is None:
            wire.require(step == "old-log" and "new-log" in self.accepted and after.kind == "absent")
            wire.require(core._read(operation.request.root / source_name, rename.MAX_LOG)[0].kind == "absent")
            self.accepted[step] = receipt
            return
        operation.checkpoint()
        path = operation.request.root / target_name
        identity = fields.identity(path.lstat())
        wire.require(codec.core_identity(identity) == after.identity and stat.S_ISREG(identity[2])
                     and not identity[2] & 0o7022 and identity[3] == operation.request.uid and identity[5] == 1)
        successor = _Original(path, identity, after.digest)
        self.successors[step] = successor
        self.accepted[step] = receipt
        operation.originals.append(successor)  # Retained BEFORE the sole open.
        successor.entered = True
        try:
            successor.fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        except OSError:
            successor.closed = True
            raise core.GitError("recovery-required") from None
        except BaseException:
            successor.unknown = operation.unknown = True
            raise
        GitReadOperation._check(operation, successor, True)

    def check(self, original, hash_file):
        operation = self.operation
        name = str(original.path.relative_to(operation.request.root)) if original.path.is_relative_to(operation.request.root) else None
        matched = next(((step, row) for step, row in self.accepted.items()
                        if row[0] == name and row[2].kind == "file" and self.sources.get(name) is original), None)
        if matched is None:
            return GitReadOperation._check(operation, original, hash_file)
        step, (_, _, before, after, _) = matched
        operation.checkpoint()
        wire.require(original.fd is not None and not original.close_claimed and not original.unknown
                     and codec.core_identity(original.identity) == before.identity and original.sha256 == before.digest)
        current = fields.identity(os.fstat(original.fd))
        wire.require(all(current[i] == original.identity[i] for i in (0, 1, 2, 3, 4, 6, 7)))
        if step == "ref":
            # This one exact positive rename moves the original inode; it is
            # not an unlink/replacement or a newly accepted arbitrary ref.
            successor = self.successors[step]
            wire.require(current == successor.identity and current[5] == 1
                         and codec.core_identity(current) == after.identity)
        else:
            wire.require(current[5] == 0)
            successor = self.successors["new-log" if step == "old-log" else step]
            wire.require(current[:2] != successor.identity[:2])
        if hash_file:
            os.lseek(original.fd, 0, os.SEEK_SET)
            count, digest = 0, hashlib.sha256()
            while True:
                operation.checkpoint()
                block = os.read(original.fd, min(32768, original.identity[6] + 1 - count))
                if not block:
                    break
                count += len(block)
                wire.require(count <= original.identity[6])
                digest.update(block)
            wire.require(count == original.identity[6] and digest.hexdigest() == original.sha256
                         and fields.identity(os.fstat(original.fd)) == current)
        operation.checkpoint()

    def post(self, *, hash_files):
        operation = self.operation
        operation.checkpoint()
        receipts = self.receipts()
        for step, value in self.accepted.items():
            wire.require(receipts.get(step) == value)
        # The same core's positive ref return is the ONLY parent transition
        # accepted after native locks. Never refresh a changed parent blindly.
        if "ref" in receipts and "ref" not in self.accepted:
            transaction = self._transaction()
            self.lock.moved(next(row for row in transaction.returns if row.step == "ref"))
        if self.lock is not None:
            self.lock.check()
        for step, value in receipts.items():
            if step not in self.accepted:
                self._admit(step, value)
        for original in operation.originals:
            self.check(original, hash_files)
        if self.original is not None:
            for name, step in ((".git/" + self.original.source_ref, "ref"), (".git/logs/" + self.original.source_ref, "old-log")):
                if step in self.accepted:
                    wire.require(core._read(operation.request.root / name, rename.MAX_LOG, regular=False)[0].kind == "absent")
            new_ref = ".git/refs/heads/" + operation.request.action.name
            for name, step in ((new_ref, "ref"), (".git/logs/refs/heads/" + operation.request.action.name, "new-log")):
                if step not in self.accepted:
                    wire.require(core._read(operation.request.root / name, rename.MAX_LOG, regular=False)[0].kind == "absent")
        if self.lock is not None:
            self.lock.check()

    def capture_progress(self):
        operation = self.operation
        wire.require(not operation.closed and self.progress is None and operation.result is not None)
        receipts = self.receipts()
        step = next(reversed(receipts)) if receipts else None
        marker = "not-reported" if step is None else "rename-" + step + "-returned"
        transaction = None if operation.repository is None else operation.repository._transaction
        retained = ()
        if transaction is not None and transaction.retained:
            wire.require(operation.result.state == "recovery-required" and not operation.repository._unknown
                         and transaction in operation.repository._retained)
            retained = tuple(sorted(str(path.relative_to(operation.request.root)) for path in transaction.scratch_files))
        self.progress = codec.Progress(codec.PHASES[codec.PUBLICATIONS.index(marker)], retained)
        wire.require(self.progress.valid(marker))

    def publication(self):
        receipts = self.receipts()
        marker = "not-reported" if not receipts else "rename-" + next(reversed(receipts)) + "-returned"
        wire.require(self.progress is not None and self.progress.valid(marker))
        return marker
