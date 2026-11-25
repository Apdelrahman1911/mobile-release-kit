"""Set-upstream comparisons on the SAME original GitLocalOperation.

Native owns every parent/negative edge/mkdir and its actual FD retirement.
This worker compares only that exact candidate roster, and retains its own old
config FD plus returned successor. No renderer/DTO can mint a directory ACK.
"""
from __future__ import annotations

import hashlib
import os

from . import _desktop_git_local_protocol as wire
from . import _desktop_git_read_protocol as fields
from . import git_repository_upstream as upstream
from . import git_repository_upstream_transaction as tx
from . import git_repository_upstream_wire as codec
from . import git_service as core
from .desktop_git_read import GitReadOperation, _Original


class State:
    def __init__(self, operation):
        from .desktop_git_local import GitLocalOperation
        wire.require(type(operation) is GitLocalOperation and type(operation.request.action) is codec.Action
                     and type(operation.request.upstream_sources) is codec.Sources and not operation.entered
                     and all(not o.entered for o in operation.originals))
        self.operation, self.source = operation, operation.request.upstream_sources
        self.old = next(o for o in operation.originals if o.path == operation.request.root / ".git/config")
        self.successor = self.returned = self.progress = None
        for snapshot in (self.source.reference, self.source.log):
            if snapshot is not None:
                wire.require(all(o.path != snapshot.path for o in operation.originals))
                operation.originals.append(_Original(snapshot.path, snapshot.identity, snapshot.sha256))

    def transaction(self):
        op = self.operation
        t = None if op.repository is None else op.repository._transaction
        if t is not None:
            wire.require(type(op.repository) is upstream.GitUpstreamRepository and type(t) is tx.UpstreamTransaction
                         and t.session.repository is op.repository and t.owner.original is op
                         and op.review is not None and t.plan is op.review.plan)
        return t

    def acknowledge(self, digest):
        op, t = self.operation, self.transaction()
        wire.require(t is not None and op.pending is None and op.source.candidate_claimed
                     and not op.source.candidate_waiting and not op.source.candidate_returned
                     and op.source.candidate is not None and op.source.candidate.intent is t.intent
                     and op.source.upstream_ack == digest and t.owner.entered)
        t.accept_directory_ack(digest)

    def _accept_config(self, t):
        op = self.operation
        if t.config_returned is None:
            return
        wire.require(t.directory_returned and t.owner.acknowledged and op.source.candidate_returned
                     and t.intent is op.source.candidate.intent and type(t.config_returned) is tx.ConfigReturned
                     and t.config_returned.original.digest == self.old.sha256
                     and tx.core_identity(self.old.identity) == t.config_returned.original.identity
                     and t.config_returned.successor.digest == t.intent.candidate_config)
        if self.returned is not None:
            wire.require(self.returned is t.config_returned)
            return
        path = self.old.path
        identity = fields.identity(path.lstat())
        wire.require(tx.core_identity(identity) == t.config_returned.successor.identity
                     and identity[3:5] == self.old.identity[3:5] and identity[2] == self.old.identity[2]
                     and identity[5] == 1 and identity[:2] != self.old.identity[:2])
        successor = self.successor = _Original(path, identity, t.intent.candidate_config)
        self.returned = t.config_returned
        op.originals.append(successor)  # BEFORE the one acquisition attempt.
        successor.entered = True
        try:
            successor.fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        except OSError:
            successor.closed = True
            raise core.GitError("recovery-required") from None
        except BaseException:
            successor.unknown = op.unknown = True
            raise
        GitReadOperation._check(op, successor, True)

    def check(self, original, hash_file):
        op = self.operation
        if original is not self.old or self.returned is None:
            return GitReadOperation._check(op, original, hash_file)
        op.checkpoint()
        wire.require(original.fd is not None and not original.close_claimed and not original.unknown
                     and self.successor is not None)
        current = fields.identity(os.fstat(original.fd))
        wire.require(all(current[i] == original.identity[i] for i in (0, 1, 2, 3, 4, 6, 7))
                     and current[5] == 0 and current[:2] != self.successor.identity[:2])
        if hash_file:
            os.lseek(original.fd, 0, os.SEEK_SET)
            count, digest = 0, hashlib.sha256()
            while True:
                op.checkpoint()
                block = os.read(original.fd, min(32768, original.identity[6] + 1 - count))
                if not block:
                    break
                count += len(block)
                wire.require(count <= original.identity[6])
                digest.update(block)
            wire.require(count == original.identity[6] and digest.hexdigest() == original.sha256
                         and fields.identity(os.fstat(original.fd)) == current)
        op.checkpoint()

    def post(self, *, hash_files):
        op, t = self.operation, self.transaction()
        op.checkpoint()
        if t is not None:
            self._accept_config(t)
            t.check_controls()
        else:
            for p in self.source.parents:
                path = op.request.root / ".git" / p.name
                wire.require(upstream.directory(path) == p.identity)
                # Native retains/nofollow-posts these exact parents. The
                # original core will additionally retain its bounded scans.
            for name in self.source.missing:
                try:
                    (op.request.root / ".git" / name).lstat()
                except FileNotFoundError:
                    continue
                raise core.GitError("stale-observation")
        for original in op.originals:
            self.check(original, hash_files)

    def capture_progress(self):
        t = self.transaction()
        marker = codec.publication(self.operation)
        self.progress = codec.Progress(codec.PHASES[codec.PUBLICATIONS.index(marker)],
                                        tuple(codec.retained_paths(t)) if t is not None else ())
        wire.require(self.progress.valid(marker, self.operation.request.action))

    def publication(self):
        marker = codec.publication(self.operation)
        wire.require(self.progress is not None and self.progress.valid(marker, self.operation.request.action))
        return marker
