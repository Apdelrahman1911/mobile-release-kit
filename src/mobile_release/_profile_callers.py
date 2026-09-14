"""Fixed caller-side translation of explicit profile lifetime evidence.

Only callers import this adapter. The data contract and fixed profile/native
owners do not depend on the arbitrary-command executor or its error classes.
"""
from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from sys import exc_info
from types import TracebackType

from .cancellation import CleanupScope, DefaultCancellation, cancellation_owner
from ._lifetime_evidence import LifetimeVerdict, ProfileCallEvidence, ProfileVerdict
from .owned_process import ProcessCleanupError, ProcessError, preserve_lifetime_error


def fatal_cancellation_error(
    primary: BaseException, guard: DefaultCancellation, message: str,
) -> ProcessError | None:
    """Project the actual guard only AFTER its fixed resource cleanup finished.

    First-primary cleanup deliberately retains an ordinary body exception. Its
    exception graph need not contain a later close/restoration failure, whereas
    the original guard's monotonic ledger does. This read-only projection grants
    no cleanup, retry or ownership. A raw-fork child never calls parent APIs.
    """
    if isinstance(primary, (KeyboardInterrupt, SystemExit)):
        raise primary
    if (type(primary) is GeneratorExit and type(guard) is DefaultCancellation
            and guard.pid != os.getpid()):
        # Inherited generators relinquish copied handles without consulting the
        # parent's ledger. Normal close consumes this exact exception; it grants
        # no successful lifetime verdict and cannot hide a copied-handle error.
        raise primary
    verdict = None
    if (type(guard) is DefaultCancellation and guard.pid == os.getpid()
            and guard.owner_thread is threading.current_thread()):
        try:
            candidate = guard.lifetime_ledger.verdict()
            if type(candidate) is LifetimeVerdict:
                verdict = candidate
        except BaseException:
            pass  # Diagnostic failure is not a healthy lifetime receipt.
    if verdict is None:
        observed = ProcessError(message, dispatched=True, contained=False, cleanup_complete=False)
    else:
        observed = ProcessError(
            message,
            dispatched=verdict.profile_dispatched is not False or verdict.command_dispatched is not False,
            contained=verdict.contained, cleanup_complete=verdict.cleanup_complete,
        )
    # Even a healthy ledger cannot erase direct conservative typed facts from
    # an earlier owner which was not attached to this particular guard.
    preserve_lifetime_error(observed, previous=primary)
    return observed if observed.fatal else None


def consume_profile_evidence(
    evidence: ProfileCallEvidence, *, primary: BaseException | None, message: str,
) -> ProfileVerdict:
    """Consume after callee cleanup, before ordinary finding/error conversion.

    A settled ordinary validation/deadline failure returns a nonfatal verdict;
    its caller retains its existing conversion policy. Fatal lifetime facts are
    never demoted. The actual first interruption is propagated by identity, with
    all fatality in the sidecar, not attributes/notes on a caller's exception.
    """
    first = primary
    diagnostic: BaseException | None = None
    try:
        if type(evidence) is not ProfileCallEvidence:
            raise TypeError("profile lifetime evidence is missing")
        evidence._finish(primary=primary)
    except BaseException as error:
        diagnostic = error
        if first is None:
            first = error
    try:
        if type(evidence) is not ProfileCallEvidence:
            raise TypeError("profile lifetime evidence is missing")
        verdict = evidence.verdict()
        if type(verdict) is not ProfileVerdict:
            raise TypeError("profile lifetime verdict is invalid")
        if first is None:
            first = evidence._primary
    except BaseException as error:
        if diagnostic is None:
            diagnostic = error
        if first is None:
            first = error
        # Missing/foreign/incomplete publication is not a no-dispatch receipt.
        verdict = ProfileVerdict(False, True, "UNKNOWN", "UNKNOWN", False,
                                 False, False, False, "UNKNOWN", False)
    if isinstance(first, (KeyboardInterrupt, SystemExit)):
        raise first from None
    if verdict.fatal or diagnostic is not None:
        raise ProcessError(message, dispatched=verdict.dispatched,
                           contained=verdict.contained,
                           cleanup_complete=verdict.cleanup_complete and diagnostic is None) from None
    return verdict


class _FirstPrimaryContextScope(CleanupScope):
    """Exit arbitration for fixed caller resources; no acquisition authority."""

    def __init__(self, manager: object, guard: DefaultCancellation, owns: bool) -> None:
        self._manager = manager
        self._entered = False
        self._exit_arguments = (None, None, None)
        super().__init__(guard, self._close_manager, owns_cancellation=owns, first_primary=True)

    def _close_manager(self) -> None:
        if self._entered:
            # None of these fixed resource managers may suppress the original
            # primary. The manager remains responsible for its own entry and
            # child-copy ownership; this wrapper adds no retry/fork cleanup.
            self._manager.__exit__(*self._exit_arguments)

    def _exit_owned(
        self, exception_type: type[BaseException] | None, error: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if not self.claimed:
            self._exit_arguments = (exception_type, error, traceback)
        return super()._exit_owned(exception_type, error, traceback)


@contextmanager
def first_primary_context(manager: object, *, cancellation: DefaultCancellation | None = None,
                          expose_owner: bool = False):
    """Keep the first primary through a fixed resource manager's exit.

    This is not a general resource acquisition/fork-recovery API. As with an
    ordinary ``with``, the supplied manager owns constructor/failed-entry cleanup.
    Install/enter/exit handoff and original error recording use the existing
    exact guard and fixed CleanupScope dispatch, never a new lifetime owner.
    ``expose_owner`` yields ``(resource, actual_guard)`` so nested callers can
    explicitly share the guard even when no default handlers were installed.
    """
    if type(expose_owner) is not bool:
        raise TypeError("caller owner exposure must be an exact boolean")
    guard, owns = cancellation_owner(
        cancellation, ProcessCleanupError, "caller resource cancellation cleanup is unconfirmed",
    )
    scope = _FirstPrimaryContextScope(manager, guard, owns)
    try:
        try:
            with scope:
                if owns:
                    guard.install()
                    guard.activate()
                with guard.deferred():
                    value = manager.__enter__()
                    scope._entered = True
                yield (value, guard) if expose_owner else value
        finally:
            scope.__exit__(*exc_info())
        # A borrower's cleanup can latch cancellation without restoring its
        # parent. This gate is reached only after otherwise normal completion.
        if guard.pid != os.getpid() or guard.owner_thread is not threading.current_thread():
            raise ProcessError("inherited caller resource cannot publish completion",
                               dispatched=True, contained=False, cleanup_complete=False)
        guard.check()
    except BaseException as primary:
        # The guard/ledger survive the resource manager's exit, including an
        # ExitStack which detached exception contexts. Preserve the actual first
        # interruption; only ordinary errors get the caller-layer fatal type.
        fatal = fatal_cancellation_error(
            primary, guard, "caller resource cleanup is unconfirmed; end this process before retrying",
        )
        if fatal is not None:
            raise fatal from None
        raise
