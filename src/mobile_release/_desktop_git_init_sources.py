"""Initialization comparisons in the SAME GitLocalOperation close book.

No process/source owner is created. Native owns the private directories; this
worker borrows and closes its original reader FDs. Only its actual returned
directory rename plus original Candidate ACK permits the one name transition.
"""
from __future__ import annotations

import hashlib
import os

from . import _desktop_git_local_protocol as wire
from . import _desktop_git_read_protocol as fields
from . import _desktop_git_init as codec
from . import git_repository_init as init
from . import git_service as core
from .desktop_git_read import GitReadOperation, _Original


class State:
    def __init__(self, operation):
        from .desktop_git_local import GitLocalOperation
        wire.require(type(operation) is GitLocalOperation and type(operation.request.action) is codec.Action
                     and not operation.entered and all(not row.entered for row in operation.originals))
        self.operation = operation
        self.borrowed = self.captured = None
        self.generated = []

    def candidate(self):
        if self.operation.request.init_sources is None:
            wire.require(self.operation.request.phase == "prepare")
            return None
        if self.borrowed is None:
            source = self.operation.request.init_sources
            paths = (self.operation.request.root, *source.paths)
            originals = []
            for path in paths:
                original = next(row for row in self.operation.originals if row.path == path)
                wire.require(original.fd is not None and original.entered and not original.close_claimed
                             and not original.unknown and len(original.identity) == 5)
                originals.append(init.BorrowedDirectory(path, original.fd, original.identity))
            self.borrowed = init.BorrowedCandidate(*originals)
        return self.borrowed

    def transaction(self):
        operation = self.operation
        repository = operation.repository
        transaction = None if repository is None else repository._transaction
        if transaction is None:
            return None
        wire.require(type(repository) is init.GitInitRepository and type(transaction) is init.InitTransaction
                     and transaction.session.repository is repository and transaction.owner is operation
                     and transaction.candidate is self.borrowed and transaction.plan is operation.review.plan)
        return transaction

    def moved(self):
        transaction = self.transaction()
        if transaction is None or not transaction.returned:
            return False
        operation = self.operation
        wire.require(transaction.attempted and transaction.acknowledged and self.captured is transaction.captured
                     and operation.source.candidate_returned and operation.source.candidate is not None
                     and operation.source.candidate.intent is transaction.intent)
        codec.matches_review(operation.request, operation.review)
        return True

    def capture(self, intent):
        operation = self.operation
        transaction = self.transaction()
        wire.require(transaction is not None and transaction.intent is intent and not transaction.attempted
                     and transaction.captured is not None and self.captured is None
                     and transaction.session.generated and transaction.session.queried and operation.pending is None)
        captured = transaction.captured
        wire.require(init.manifest(self.borrowed) == captured)
        self.captured = captured  # Retain before the first additional reader.
        entries = [(self.borrowed.git.path / name, identity, None) for name, identity in captured.directories if name]
        for name, stamp, _ in captured.files:
            path = self.borrowed.git.path / name
            identity = fields.identity(path.lstat())
            wire.require((identity[0], identity[1], identity[2], identity[6], identity[7], identity[8]) == stamp.identity)
            entries.append((path, identity, stamp.digest))
        for path, identity, digest in entries:
            row = _Original(path, identity, digest)
            self.generated.append(row)
            operation.originals.append(row)  # Same original close book BEFORE open.
            row.entered = True
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if digest is None:
                flags |= os.O_DIRECTORY
            try:
                row.fd = os.open(path, flags)
            except OSError:
                row.closed = True
                raise core.GitError("recovery-required") from None
            except BaseException:
                row.unknown = operation.unknown = True
                raise
            GitReadOperation._check(operation, row, True)
        self.post(hash_files=True)

    def check(self, original, hash_file):
        operation = self.operation
        candidate = self.borrowed
        if candidate is None or not self.moved() or not original.path.is_relative_to(candidate.git.path):
            return GitReadOperation._check(operation, original, hash_file)
        path = operation.request.root / ".git" / original.path.relative_to(candidate.git.path)
        operation.checkpoint()
        wire.require(original.fd is not None and not original.close_claimed and not original.unknown)
        identity = fields.directory_identity if original.sha256 is None else fields.identity
        wire.require(identity(os.fstat(original.fd)) == original.identity
                     and identity(os.stat(path, follow_symlinks=False)) == original.identity)
        if hash_file and original.sha256 is not None:
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
                         and identity(os.fstat(original.fd)) == original.identity
                         and identity(os.stat(path, follow_symlinks=False)) == original.identity)
        operation.checkpoint()

    def post(self, *, hash_files):
        operation = self.operation
        operation.checkpoint()
        for original in operation.originals:
            self.check(original, hash_files)
        # Admission checks each original before they are all opened. The final
        # source_post call is after their original acquisition loop returned.
        candidate = self.candidate()
        published = self.moved()
        if published:
            candidate.check(published=True)
        else:
            init.absence(operation.request.root, candidate)
        if self.captured is not None:
            wire.require(init.manifest(candidate, published=published) == self.captured)

    def publication(self):
        transaction = self.transaction()
        return "init-returned" if self.moved() and transaction.fsynced else "not-reported"
