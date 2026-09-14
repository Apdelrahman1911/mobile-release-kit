"""Private bounded lifetime data shared by the actual cancellation owner.

There are no acquisitions, cleanup callbacks, process operations or receipt
constructors here.  Only the real owners bind their records before effects and
publish the read-only facts consumed below.  These facts never grant cleanup.
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass


_ROLES = frozenset(("LOAD", "DECODE", "READER", "OUTER_CMS", "INNER_CMS"))
_RESOURCE_ROLES = frozenset(("READER", "OUTER_CMS", "INNER_CMS"))
_ATTEMPTS = frozenset(("NOT_ATTEMPTED", "ATTEMPT_ARMED", "UNKNOWN"))
_DISPATCHES = frozenset(("NOT_SENT", "RUN_ATTEMPT_ARMED", "UNKNOWN"))


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("private lifetime evidence is inconsistent")


def _merge_flag(previous: bool | None, current: bool | None) -> bool | None:
    if previous is True or current is True:
        return True
    return None if previous is None or current is None else False


@dataclass(frozen=True)
class LifetimeVerdict:
    fatal: bool
    complete: bool
    profile_dispatched: bool | None
    command_dispatched: bool | None
    profile_calls: int
    commands: int
    profile_contained: bool | None
    command_contained: bool | None

    @property
    def contained(self) -> bool:
        return self.profile_contained is True and self.command_contained is True

    @property
    def cleanup_complete(self) -> bool:
        return self.complete and not self.fatal


@dataclass(frozen=True)
class ProfileVerdict:
    complete: bool
    fatal: bool
    native_attempt: str
    validator_dispatch: str
    producer_settled: bool
    native_resources_settled: bool
    local_resources_settled: bool
    handlers_settled: bool
    handler_state: str
    blocked: bool

    @property
    def dispatched(self) -> bool:
        # Legacy compatibility means possible dispatch, never proof of exec.
        return self.validator_dispatch != "NOT_SENT"

    @property
    def may_have_dispatched(self) -> bool:
        return self.dispatched

    @property
    def positive_no_native_attempt(self) -> bool:
        return self.complete and self.native_attempt == "NOT_ATTEMPTED"

    @property
    def contained(self) -> bool:
        return self.producer_settled and not self.blocked

    @property
    def cleanup_complete(self) -> bool:
        return (self.complete and self.native_resources_settled
                and self.local_resources_settled and self.handlers_settled
                and not self.fatal)


class LifetimeLedger:
    """One owner's bounded summaries and at most one active record per domain.

    Completed healthy records are folded; unresolved records remain strongly
    rooted.  A profile observation never becomes an account-command dispatch.
    No reload/reset operation exists.
    """

    def __init__(self, owner: object) -> None:
        self._owner = owner
        self._pid = os.getpid()
        self._thread = threading.current_thread()
        self._fatal = False
        self._profile: ProfileCallEvidence | None = None
        self._command: object | None = None
        self._profile_dispatched: bool | None = False
        self._command_dispatched: bool | None = False
        self._profile_contained: bool | None = True
        self._command_contained: bool | None = True
        self._profile_published = self._command_published = False
        self._profile_calls = self._commands = 0
        self._primary: BaseException | None = None
        self._secondary: list[BaseException] = []

    def _check_owner(self) -> None:
        _require(self._pid == os.getpid() and self._thread is threading.current_thread())

    @property
    def fatal(self) -> bool:
        self._check_owner()
        return self._fatal

    def _abort(self, error: BaseException | None = None) -> None:
        self._check_owner()
        self._fatal = True  # The abort latch precedes optional diagnostics.
        if error is not None:
            self._remember(error)

    def _remember(self, error: BaseException) -> None:
        """Retain the incoming first primary without inventing a fatal fact."""
        self._check_owner()
        _require(isinstance(error, BaseException))
        if self._primary is None:
            self._primary = error
        elif error is not self._primary and len(self._secondary) < 8:
            self._secondary.append(error)

    def _bind_profile(self, evidence: ProfileCallEvidence) -> None:
        self._check_owner()
        _require(not self._fatal and self._profile is None and self._command is None)
        self._profile = evidence
        self._profile_published = False

    def _finish_profile(self, evidence: ProfileCallEvidence, verdict: ProfileVerdict) -> None:
        self._check_owner()
        _require(self._profile is evidence and not self._profile_published and type(verdict) is ProfileVerdict)
        dispatch = (None if verdict.validator_dispatch == "UNKNOWN"
                    else verdict.validator_dispatch == "RUN_ATTEMPT_ARMED")
        self._profile_dispatched = _merge_flag(self._profile_dispatched, dispatch)
        self._profile_contained = verdict.contained
        self._profile_published = True
        if verdict.fatal:
            self._abort(evidence._primary)
        else:
            self._profile_calls += 1
            self._profile = None

    def _bind_command(self, outcome_slot: object) -> None:
        self._check_owner()
        _require(not self._fatal and self._command is None and self._profile is None
                 and outcome_slot is not None)
        self._command = outcome_slot
        self._command_published = False

    def _finish_command(
        self, outcome_slot: object, *, dispatched: bool | None,
        contained: bool | None, cleanup_complete: bool | None,
    ) -> None:
        self._check_owner()
        _require(self._command is outcome_slot and outcome_slot is not None and not self._command_published)
        _require(all(value is None or type(value) is bool
                     for value in (dispatched, contained, cleanup_complete)))
        self._command_dispatched = _merge_flag(self._command_dispatched, dispatched)
        self._command_contained = contained
        self._command_published = True
        if contained is not True or cleanup_complete is not True or dispatched is None:
            self._abort()
        else:
            self._commands += 1
            self._command = None

    def verdict(self) -> LifetimeVerdict:
        self._check_owner()
        complete = self._profile is None and self._command is None
        profile_pending = self._profile is not None and not self._profile_published
        command_pending = self._command is not None and not self._command_published
        return LifetimeVerdict(self._fatal or not complete, complete,
                               _merge_flag(self._profile_dispatched, None) if profile_pending else self._profile_dispatched,
                               _merge_flag(self._command_dispatched, None) if command_pending else self._command_dispatched,
                               self._profile_calls, self._commands,
                               None if profile_pending else self._profile_contained,
                               None if command_pending else self._command_contained)


@dataclass(frozen=True)
class _ScopeBinding:
    scope: object
    role: str
    guard: object
    owns_cancellation: bool
    descriptors: tuple[object, ...]
    scratch: object | None
    finality: object | None


class ProfileCallEvidence:
    """Caller-allocated sidecar; private owners bind, consumers only read.

    Supplied evidence may span read then decode under the same actual guard.
    Its caller finishes it after the whole invocation, including cleanup.
    LOAD/DECODE add local/handler obligations, not extra process slots.
    """

    def __init__(self, operation: str = "load") -> None:
        _require(type(operation) is str and operation in ("read", "authenticate", "decode", "load"))
        self._operation = operation
        self._pid = os.getpid()
        self._thread = threading.current_thread()
        self._bindings: dict[str, _ScopeBinding] = {}
        self._expected: set[str] = set()
        self._guard: object | None = None
        self._ledger: LifetimeLedger | None = None
        self._finished = False
        self._blocked = False
        self._blockers: tuple[object, ...] = ()
        self._fault: BaseException | None = None
        self._primary: BaseException | None = None
        self._native_armed = self._dispatch_armed = False
        self._published = False

    @property
    def operation(self) -> str:
        return self._operation

    def _check_owner(self) -> None:
        # No inherited locks/recorders/owner properties are touched first.
        _require(self._pid == os.getpid() and self._thread is threading.current_thread())

    def _expect(self, role: str) -> None:
        """Predeclare only the next actual child call, never unscheduled work."""
        self._check_owner()
        _require(not self._finished and type(role) is str and role in _ROLES
                 and role not in self._bindings)
        self._expected.add(role)

    def _bind_guard(self, guard: object) -> None:
        """Attach the real entry owner before a previous-UNKNOWN admission gate."""
        self._check_owner()
        _require(not self._finished and getattr(guard, "pid", None) == self._pid
                 and getattr(guard, "owner_thread", None) is self._thread)
        if self._guard is not None:
            _require(self._guard is guard)
            return
        ledger = getattr(guard, "lifetime_ledger", None)
        _require(type(ledger) is LifetimeLedger and ledger._owner is guard)
        self._guard, self._ledger = guard, ledger
        ledger._bind_profile(self)
        if self._blocked:
            ledger._abort()

    def _bind(
        self, scope: object, *, guard: object, role: str, owns_cancellation: bool,
        descriptors: tuple[object, ...] = (), scratch: object | None = None,
        finality: object | None = None,
    ) -> None:
        self._check_owner()
        _require(not self._finished and type(role) is str and role in _ROLES
                 and role not in self._bindings and scope is not None
                 and type(owns_cancellation) is bool and type(descriptors) is tuple
                 and len(descriptors) <= 4 and all(item is not None for item in descriptors))
        if role not in _RESOURCE_ROLES:
            _require(not descriptors and scratch is None and finality is None)
        if role == "READER":
            _require(scratch is None and finality is None)
        if role in ("OUTER_CMS", "INNER_CMS"):
            _require(finality is not None)
        self._bind_guard(guard)
        self._expected.add(role)
        self._bindings[role] = _ScopeBinding(scope, role, guard, owns_cancellation,
                                              descriptors, scratch, finality)

    def _block(self, blocker: object) -> None:
        self._check_owner()
        _require(not self._finished and blocker is not None)
        self._blocked = True
        if not any(item is blocker for item in self._blockers):
            # The original resource registries remain the cleanup custody. This
            # sidecar retains the exact blocking references, never an error text
            # or an invented no-dispatch result.
            _require(len(self._blockers) < 8)
            self._blockers += (blocker,)
        if self._ledger is not None:
            self._ledger._abort()

    def _record_fault(self, error: BaseException) -> None:
        if self._fault is None:
            self._fault = error
        if self._primary is None:
            self._primary = error
        if self._ledger is not None:
            try:
                self._ledger._abort(self._primary)
            except BaseException:
                # Diagnostic failure cannot replace the earlier primary or
                # make incomplete publication healthy. No resource operation.
                self._ledger._fatal = True

    def _unknown_verdict(self) -> ProfileVerdict:
        return ProfileVerdict(False, True,
                              "ATTEMPT_ARMED" if self._native_armed else "UNKNOWN",
                              "RUN_ATTEMPT_ARMED" if self._dispatch_armed else "UNKNOWN",
                              False, False, False, False, "UNKNOWN", self._blocked)

    def _snapshot(self) -> ProfileVerdict:
        missing = self._expected.difference(self._bindings)
        complete = self._finished and bool(self._bindings) and not missing and self._fault is None
        blocked = self._blocked
        ledger_fatal = self._ledger is not None and self._ledger.fatal
        native, dispatch = [], []
        producers = resources = local = handlers = bool(self._bindings)
        # Read conservative arms before independent local/handler diagnostics.
        # Missing scheduled publication cannot be inferred from absent events.
        if not self._bindings or missing.intersection(("LOAD", "DECODE", "OUTER_CMS", "INNER_CMS")):
            native.append("UNKNOWN")
            dispatch.append("UNKNOWN")
            producers = resources = False
        for binding in self._bindings.values():
            if binding.finality is None:
                continue
            attempt = getattr(binding.finality, "native_attempt", None)
            if attempt == "ATTEMPT_ARMED":
                self._native_armed = True
            sent = getattr(binding.finality, "validator_dispatch", None)
            if sent == "RUN_ATTEMPT_ARMED":
                self._dispatch_armed = True
            producer = getattr(binding.finality, "producer_settled", None)
            settled = getattr(binding.finality, "native_resources_settled", None)
            previous_unknown = getattr(binding.finality, "blocked", False)
            if previous_unknown is True:
                self._blocked = True
            valid_attempt = type(attempt) is str and attempt in _ATTEMPTS
            valid_sent = type(sent) is str and sent in _DISPATCHES
            complete = (complete and valid_attempt and valid_sent
                        and type(producer) is bool and type(settled) is bool
                        and type(previous_unknown) is bool)
            native.append(attempt if valid_attempt else "UNKNOWN")
            dispatch.append(sent if valid_sent else "UNKNOWN")
            producers = producers and producer is True
            resources = resources and settled is True
            blocked = blocked or previous_unknown is True
        state = getattr(self._guard, "handler_state", "UNKNOWN")
        for binding in self._bindings.values():
            scope_local = getattr(binding.scope, "lifetime_local_settled", None)
            scope_handler = getattr(binding.scope, "lifetime_handler_state", None)
            local = local and scope_local is True
            complete = complete and type(scope_local) is bool
            for descriptor in binding.descriptors:
                descriptor_settled = getattr(descriptor, "settled", None)
                local = local and descriptor_settled is True
                complete = complete and type(descriptor_settled) is bool
            if binding.scratch is not None:
                local = (local and getattr(binding.scratch, "state", None) == "REMOVED"
                         and getattr(binding.scratch, "retained", None) is False)
            good_handler = (scope_handler == "RESTORED" and binding.owns_cancellation
                            and state == "RESTORED") or (
                                scope_handler == "BORROWED_VALID" and not binding.owns_cancellation
                                and state in ("ACTIVE", "RESTORED"))
            handlers = handlers and good_handler
            complete = complete and scope_handler in ("RESTORED", "BORROWED_VALID", "UNKNOWN")
        # A known arm is irrevocable even if an unrelated close/restoration or
        # publication is unknown. Unknown never becomes a false legacy Boolean.
        attempt = ("ATTEMPT_ARMED" if self._native_armed else
                   "UNKNOWN" if "UNKNOWN" in native else "NOT_ATTEMPTED")
        sent = ("RUN_ATTEMPT_ARMED" if self._dispatch_armed else
                "UNKNOWN" if "UNKNOWN" in dispatch else "NOT_SENT")
        fatal = (ledger_fatal or blocked or attempt == "UNKNOWN" or sent == "UNKNOWN"
                 or (attempt == "NOT_ATTEMPTED" and sent == "RUN_ATTEMPT_ARMED")
                 or not (complete and producers and resources and local and handlers))
        return ProfileVerdict(bool(complete), bool(fatal), attempt, sent,
                              bool(producers), bool(resources), bool(local), bool(handlers),
                              state if handlers and state == "RESTORED" else
                              "BORROWED_VALID" if handlers else "UNKNOWN", bool(blocked))

    def _finish(self, *, primary: BaseException | None = None) -> None:
        self._check_owner()
        _require(primary is None or isinstance(primary, BaseException))
        if self._finished:
            return
        if self._primary is None or primary is not None:
            self._primary = primary
        self._finished = True  # No later binding can repair missing publication.
        try:
            verdict = self._snapshot()
            if self._ledger is not None:
                self._ledger._finish_profile(self, verdict)
                self._published = True
        except BaseException as error:
            self._record_fault(error)
            if primary is None:
                raise

    def verdict(self) -> ProfileVerdict:
        self._check_owner()
        try:
            verdict = self._snapshot()
            # A later parent restoration augments this sidecar too. Healthy
            # records were folded, but the shared abort latch cannot be cleared.
            if self._finished and verdict.fatal and self._ledger is not None:
                self._ledger._abort(self._primary)
            return verdict
        except BaseException as error:
            first = self._primary
            self._record_fault(error)
            if first is None and isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise  # Do not replace the first actual interruption with data.
            return self._unknown_verdict()
