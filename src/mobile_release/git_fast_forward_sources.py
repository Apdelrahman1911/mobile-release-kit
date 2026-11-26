"""Fixed fast-forward source facet of the SAME original GitLocalOperation.

There is no independent owner, close loop, process route or authority here.
The original operation acquires/closes these original and successor FD slots.
Only its actual C/A/W-returned transaction receipts allow the precise old-inode
exception. The target-ref lock is native-owned; this child only compares it.
"""
from __future__ import annotations

import hashlib
import os
import stat

from . import _desktop_git_local_protocol as wire
from . import _desktop_git_read_protocol as fields
from . import git_fast_forward_worker as codec
from . import git_repository_switch as shared
from . import git_repository_fast_forward as ff
from . import git_service as core
from . import git_fast_forward_transaction as tx
from . import git_switch_transaction as shared_tx
from .desktop_git_read import GitReadOperation, _Original


class State:
    def __init__(self, operation):
        # Fixed parent construction before any original descriptor acquisition.
        from .desktop_git_local import GitLocalOperation
        wire.require(type(operation) is GitLocalOperation and type(operation.request.action) is codec.Action
                     and not operation.entered and all(not row.entered for row in operation.originals))
        self.operation = operation
        self.original = operation.request.fast_forward_sources
        self.lock = None if self.original is None else self.original.lock.comparison(
            operation.request.root, operation.request.action.target_ref)
        self.sources, self.successors, self.accepted = {}, {}, {}
        self.progress = None
        root = operation.request.root
        if self.original is not None:
            wire.require(type(self.original) is codec.Sources and operation.request.phase == "apply")
            rows = (*self.original.files, self.original.reference,
                    *((self.original.log,) if self.original.log is not None else ()),
                    *((self.original.branch_log,) if self.original.branch_log is not None else ()))
            for snapshot in rows:
                wire.require(all(row.path != snapshot.path for row in operation.originals))
                operation.originals.append(_Original(snapshot.path, snapshot.identity, snapshot.sha256))
            for original in operation.originals:
                if original.path in (root / ".git/index", root / ".git/logs/HEAD", self.original.reference.path,
                                      root / ".git/logs" / str(self.original.reference.path.relative_to(root / ".git"))) or any(
                        original.path == row.path for row in self.original.files):
                    self.sources[str(original.path.relative_to(root))] = original
            wire.require(".git/index" in self.sources)
        else:
            wire.require(operation.request.phase == "prepare")

    def _transaction(self):
        operation = self.operation
        repository = operation.repository
        transaction = None if repository is None else repository._transaction
        if transaction is None or transaction.checkout_return is None:
            return None
        # Matching bytes or a publication-shaped object alone never reaches
        # this path. It must be the same original handoff/transaction/receipt.
        wire.require(type(repository) is ff.GitFastForwardRepository and not repository._unknown
                     and type(transaction) is tx.FastForwardTransaction and transaction.session.repository is repository
                     and type(operation.review) is ff.FastForwardReview and transaction.plan is operation.review.plan
                     and transaction.owner.original is operation and transaction.owner.acknowledged
                     and operation.source.candidate_returned and operation.source.candidate is not None
                     and transaction.intent is operation.source.candidate.intent
                     and transaction.owner.intent is transaction.intent
                     and type(transaction.checkout_return) is shared_tx.CheckoutReturn
                     and transaction.checkout_return.intent is transaction.intent)
        codec.matches_review(operation.request, operation.review)
        return transaction

    def receipts(self):
        transaction = self._transaction()
        if transaction is None:
            return {}, "not-reported"
        plan, intent = transaction.plan, transaction.intent
        files = transaction.checkout_return.files
        wire.require(tuple(path for path, _ in files) == plan.changed)
        original = dict(plan._footprint.files)
        target = {row.path: row for row in plan.target_tree}
        hashes = dict(plan._target_hashes)
        returned = {}
        for path, stamp in files:
            before = original[path]
            wire.require(type(stamp) is core._Stamp and stamp.kind == "file" and stamp.digest == hashes[path]
                         and stamp.identity[3] == target[path].size and stamp.identity[2] == before.identity[2])
            returned[path] = before, stamp
        marker = "ff-worktree-returned"
        if transaction.index_publication is not None:
            receipt = transaction.index_publication
            wire.require(receipt.intent is intent and receipt.original == plan._snapshot.index_stamp
                         and receipt.successor.digest == intent.candidate_index)
            returned[".git/index"] = receipt.original, receipt.successor
            marker = "ff-index-returned"
        if transaction.reference_return is not None:
            receipt = transaction.reference_return
            wire.require(type(receipt) is tx.RefReturn and receipt.intent is intent
                         and transaction.index_publication is not None and receipt.successor is transaction.session.successor
                         and receipt.successor.name == intent.expected_ref and receipt.successor.oid == intent.target_oid)
            before = next(s for n, s, _ in transaction.session.originals.files if n == intent.expected_ref)
            returned[".git/" + intent.expected_ref] = before, receipt.successor.stamp
            for log in receipt.logs:
                wire.require(type(log) is shared_tx.MetadataReturn and log.name in ("logs/HEAD", "logs/" + intent.expected_ref))
                returned[".git/" + log.name] = log.original, log.successor
            marker = "ff-ref-returned"
        return returned, marker

    def _admit_successor(self, name, before, after):
        operation = self.operation
        wire.require(name not in self.successors and after.kind == "file")
        original = self.sources.get(name)
        wire.require((before.kind == "absent" and original is None and name in (".git/logs/HEAD", ".git/logs/" + self.operation.review.plan._snapshot.public.branch)) or
                     (before.kind == "file" and original is not None
                      and codec.core_identity(original.identity) == before.identity and original.sha256 == before.digest))
        operation.checkpoint()
        path = operation.request.root / name
        identity = fields.identity(path.lstat())
        wire.require(codec.core_identity(identity) == after.identity and stat.S_ISREG(identity[2])
                     and not identity[2] & 0o7022 and identity[3] == operation.request.uid and identity[5] == 1)
        successor = _Original(path, identity, after.digest)
        # Retain this separate route BEFORE open; the original FD is untouched.
        self.successors[name] = successor
        self.accepted[name] = before, after
        operation.originals.append(successor)
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
        name = str(original.path.relative_to(operation.request.root)) if original.path.is_relative_to(
            operation.request.root) else None
        if self.sources.get(name) is not original or name not in self.accepted:
            GitReadOperation._check(operation, original, hash_file)
            return
        before, _ = self.accepted[name]
        successor = self.successors[name]
        operation.checkpoint()
        wire.require(original.fd is not None and not original.close_claimed and not original.unknown
                     and codec.core_identity(original.identity) == before.identity and original.sha256 == before.digest)
        current = fields.identity(os.fstat(original.fd))
        same_inode = current[:2] == successor.identity[:2]
        if same_inode:
            wire.require(name.startswith(".git/logs/") and current == successor.identity
                         and current[6] >= original.identity[6] and current[5] == 1)
        else:
            wire.require(all(current[i] == original.identity[i] for i in (0, 1, 2, 3, 4, 6, 7)) and current[5] == 0)
        if hash_file:
            os.lseek(original.fd, 0, os.SEEK_SET)
            count, digest = 0, hashlib.sha256()
            # For the actual appended log, the original bytes are the exact
            # old prefix. The separate successor route verifies the full file.
            while count < original.identity[6]:
                operation.checkpoint()
                block = os.read(original.fd, min(32768, original.identity[6] - count))
                wire.require(bool(block))
                count += len(block)
                digest.update(block)
            wire.require(digest.hexdigest() == original.sha256 and fields.identity(os.fstat(original.fd)) == current)
        operation.checkpoint()

    def post(self, *, hash_files):
        operation = self.operation
        operation.checkpoint()
        if self.lock is not None:
            self.lock.check()  # Comparison only. Native retains/retire this lock.
        receipts, _ = self.receipts()
        for name, stamps in self.accepted.items():
            wire.require(receipts.get(name) == stamps)
        for name, (before, after) in receipts.items():
            if name not in self.successors:
                self._admit_successor(name, before, after)
        for original in operation.originals:
            self.check(original, hash_files)
        if self.original is not None and self.original.log is None and ".git/logs/HEAD" not in receipts:
            wire.require(core._read(operation.request.root / ".git/logs/HEAD", shared.MAX_LOG)[0].kind == "absent")
        if self.original is not None and self.original.branch_log is None:
            name = ".git/logs/" + str(self.original.reference.path.relative_to(operation.request.root / ".git"))
            if name not in receipts:
                wire.require(core._read(operation.request.root / name, shared.MAX_LOG)[0].kind == "absent")
        if operation.request.index_absent:
            wire.require(core._read(operation.request.root / ".git/index", shared.MAX_INDEX)[0].kind == "absent")
        if self.lock is not None:
            self.lock.check()

    def capture_progress(self):
        """Before cleanup; terminal uses only bounded retained DATA, never IO."""
        operation = self.operation
        wire.require(not operation.closed and self.progress is None and operation.result is not None)
        _, marker = self.receipts()
        transaction = None if operation.repository is None else operation.repository._transaction
        retained = ()
        if transaction is not None and transaction.retained:
            wire.require(operation.result.state == "recovery-required" and not operation.repository._unknown
                         and transaction in operation.repository._retained)
            retained = tuple(sorted(str(path.relative_to(operation.request.root)) for path in transaction.scratch_files))
        progress = codec.Progress(codec.PHASES[codec.PUBLICATIONS.index(marker)], retained)
        wire.require(progress.valid(marker))
        self.progress = progress

    def publication(self):
        # No new source checks after cleanup. This is DATA projection only;
        # parent terminal still requires its original ledger/EOF/close joins.
        _, marker = self.receipts()
        wire.require(self.progress is not None and self.progress.valid(marker))
        return marker
