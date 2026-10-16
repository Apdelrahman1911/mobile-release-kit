"""Retained original Android build inputs, NOT local Store authority.

This optional internal seam starts before the existing signed build runs. It
retains the SAME exclusive artifact snapshot, not a renderer path/report or a
second AAB copy. Core producer finality is distinct from external native parent
and transport finality. Source/freshness, metadata, intent and consent still
need their original owners; none are inferred from a successful build.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import stat
import sys
import threading
import time

from ._desktop_android_build_files import OriginalAndroidArtifact, MAX_AAB_BYTES
from ._desktop_android_build_protocol import is_signed, validate_result, _encode, RESPONSE_LIMIT
from .build_inputs import _file
from .cancellation import CleanupScope
from .checked_files import _Reader, _Policy
from .config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES
from .errors import ValidationError

MAX_HANDOFF_FDS = 48
READ_CHUNK = 64 * 1024


class LocalCandidateError(ValidationError):
    """Finite non-reflective failure; no private path, finding text or key."""


def _need(value):
    if not value:
        raise LocalCandidateError("Original local Android build inputs are unavailable")


class LocalAndroidBuildHandoff:
    """One live read-only retention registered before the original producer.

    Neither construction nor observation authorizes preparation/Store access.
    The caller owns this scope across the existing producer's terminal and
    subsequent bounded input use. Closing it never deletes the retained AAB.
    """
    def __init__(self, run):
        from .desktop_android_build import AndroidBuildRun
        _need(type(run) is AndroidBuildRun and not run._run_claimed and not run._close_claimed
              and run.primary is None and getattr(run, "_local_handoff", None) is None
              and is_signed(run.request.context) and run.operation.signing is not None)
        run.operation.owner()
        self.run, self.guard = run, run.guard
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.reader = self.node = None
        self.failed = self.closed = self.captured = self.producer_joined = False
        self._capturing = self._reading = False
        self._read_bytes = 0
        self._completed_reads = 0
        self._result = self._config = self._version = None
        self._size = self._sha256 = None
        run._local_handoff = self  # Root receiver before any original acquisition.

    def _owner(self):
        _need(self.pid == os.getpid() and self.thread is threading.current_thread()
              and self.run._local_handoff is self)

    def _point(self):
        self._owner()
        try:
            _need(not self.closed and not self.failed)
            self.guard.check()
            _need(time.monotonic() < self.run.source.work_end)
        except BaseException:
            self.failed = True
            raise

    def _fail(self):
        self._owner()
        self.failed = True

    def _capture(self, run, artifact):
        self._point()
        _need(run is self.run and run._run_claimed and not run._close_claimed
              and run.primary is None and not self.captured and self.reader is None)
        operation = run.operation
        operation.checkpoint()
        _need(type(artifact) is OriginalAndroidArtifact and artifact is operation._artifact
              and artifact.files is operation.files and operation.files.artifact is artifact
              and operation.inputs is not None and operation.inputs.check_signer
              and operation.signing is not None and operation._signature_passed
              and operation.work_finish_attempted and not operation.close_claimed
              and operation.commands_settled() and not artifact._native and artifact._reader is None)
        validate_result(run._candidate)
        result = _encode(run._candidate)
        _need(len(result) <= RESPONSE_LIMIT and run._candidate.get("signing") == "local-upload-key")
        selected = run._candidate["artifacts"][0]
        _need((selected["size"], selected["sha256"]) == (artifact.size, artifact.sha256)
              and selected["freshness"] == "not-established"
              and run._candidate["assurances"]["sourceBinding"] == "not-established")
        saved = operation.inputs.saved
        config, version = saved.configuration.raw, saved.version_raw
        _need(type(config) is bytes and 0 < len(config) <= MAX_CONFIG_BYTES
              and type(version) is bytes and 0 < len(version) <= MAX_VERSION_BYTES)
        for body, row in ((config, run._candidate["usedConfig"]), (version, run._candidate["usedVersion"])):
            _need((len(body), hashlib.sha256(body).hexdigest()) == (row["bytes"], row["sha256"]))
        path = artifact.path  # Genuine original getter, not a supplied pathname.
        quote = len(path.parts) + 2  # Existing checked-reader Darwin alias ancestors.
        _need(path.is_absolute() and 1 < len(path.parts) and quote <= MAX_HANDOFF_FDS)
        operation.charge("local-handoff-fds", quote, MAX_HANDOFF_FDS)
        operation.charge("local-handoff-retained-bytes", len(config) + len(version) + len(result),
                         MAX_CONFIG_BYTES + MAX_VERSION_BYTES + RESPONSE_LIMIT)
        self.reader = _Reader(self.guard)
        self._capturing = True
        try:
            self.node = self.reader.acquire(path, _Policy(False, 1, MAX_AAB_BYTES), None)
            _need(len(self.reader.descriptors) <= quote
                  and _file(self.node.observed) == artifact._snapshot.identity
                  and self.node.observed.st_uid == os.geteuid() and self.node.observed.st_nlink == 1
                  and stat.S_IMODE(self.node.observed.st_mode) == 0o600)
            self._size, self._sha256 = artifact.size, artifact.sha256
            # Fixed chunks, not _Reader.read's whole-file allocation. The
            # retained byte identity is checked before/after the original hash.
            for _ in self._blocks():
                pass
            artifact.check()
            operation.check_inputs()
            operation.checkpoint()
            self._config, self._version, self._result = config, version, result
            self.captured = True
        except BaseException:
            self.failed = True
            raise
        finally:
            self._capturing = False

    def _blocks(self):
        self._point()
        _need(self.node is not None and not self._reading
              and (self._capturing or self.producer_joined))
        self._reading = True
        complete = False
        try:
            self.reader.terminal()
            digest, consumed = hashlib.sha256(), 0
            number = self.reader._number(self.node.slot)
            while consumed < self._size:
                self._point()
                amount = min(READ_CHUNK, self._size - consumed)
                _need(self._read_bytes <= 3 * self._size - amount)
                self._read_bytes += amount
                body = os.pread(number, amount, consumed)
                _need(type(body) is bytes and len(body) == amount)
                consumed += len(body)
                digest.update(body)
                self._point()
                yield body
            self._point()
            _need(not os.pread(number, 1, consumed) and digest.hexdigest() == self._sha256)
            self.reader.terminal()
            self._completed_reads += 1
            complete = True
        finally:
            self._reading = False
            if not complete:
                self.failed = True

    def _terminal(self, run, terminal):
        try:
            self._join_terminal(run, terminal)
        except BaseException:
            self.failed = True
            raise

    def _join_terminal(self, run, terminal):
        self._owner()
        _need(run is self.run)
        # Unknown/early/negative observations are absorbing for this handoff,
        # even if a later caller supplies a success-shaped result dictionary.
        if self.failed or terminal["outcome"] != "complete":
            self.failed = True
            return
        self._point()
        verdict = self.guard.lifetime_ledger.verdict()
        _need(self.captured and not self._reading and run.primary is None and run._close_claimed
              and run.operation.closed() and run.source.closed and self.guard.handler_state == "RESTORED"
              and verdict.complete and verdict.cleanup_complete and verdict.contained and not verdict.fatal
              and _encode(terminal["result"]) == self._result)
        self.reader.terminal()
        self.producer_joined = True

    def observation(self):
        """Detached bounded DATA, not a prepared intent or artifact capability."""
        self._point()
        _need(self.producer_joined and not self._reading)
        try:
            self.reader.terminal()
        except BaseException:
            self.failed = True
            raise
        return {"origin": "local-desktop", "scope": "retained-android-build-inputs",
                "producerCoreSettled": True, "outerTransportFinality": "not-established",
                "storeAuthorized": False, "candidatePrepared": False,
                "inspection": json.loads(self._result)}

    def saved_inputs(self):
        self.observation()
        return self._config, self._version

    @contextmanager
    def artifact_blocks(self):
        """At most two full retained reads after capture, under its endpoint.

        Early abandonment is a failed handoff, never successful consumption.
        No descriptor or reopenable pathname is exposed by this interface.
        """
        self.observation()
        blocks = self._blocks()
        before = self._completed_reads
        try:
            yield blocks
        except BaseException:
            self.failed = True
            raise
        finally:
            blocks.close()
            if self._completed_reads != before + 1:
                self.failed = True
        _need(not self.failed)

    def _close(self):
        self._owner()
        if self.closed:
            return
        self.closed = True
        if self._reading or not self.producer_joined:
            self.failed = True
        if self.reader is not None:
            try:
                self.reader.close()
                self.reader.assert_closed()
            except BaseException:
                self.failed = True
                raise


@contextmanager
def retain_android_build_inputs(run):
    """Internal optional handoff. Existing engine/default service never calls it."""
    handoff = LocalAndroidBuildHandoff(run)
    scope = CleanupScope(handoff.guard, handoff._close, owns_cancellation=False,
                         fork_cleanup=lambda: handoff.reader.after_fork_child() if handoff.reader else None,
                         first_primary=True)
    try:
        try:
            with scope:
                yield handoff
        finally:
            scope.__exit__(*sys.exc_info())
    except BaseException:
        handoff.failed = True
        raise
