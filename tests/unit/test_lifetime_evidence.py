"""Inert lifetime-contract tests: no children, real handlers, files or threads.

Synthetic owner facts below exercise aggregation only. They never manufacture a
native receipt or authorize resource cleanup. Native behavior has separate tests.
"""
from __future__ import annotations

import inspect
import signal
import threading
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import PropertyMock, patch

from mobile_release import cancellation
from mobile_release._lifetime_evidence import ProfileCallEvidence
from mobile_release._profile_callers import consume_profile_evidence, fatal_cancellation_error, first_primary_context
from mobile_release.cancellation import CleanupScope, DefaultCancellation, cancellation_owner
from mobile_release.errors import CredentialError, ValidationError
from mobile_release.owned_process import ProcessError


@contextmanager
def handler_model():
    handlers = {signal.SIGINT: signal.default_int_handler, signal.SIGTERM: signal.SIG_DFL}
    calls = []
    def setter(signum, token):
        calls.append(signum)
        previous, handlers[signum] = handlers[signum], token
        return previous
    with patch.object(cancellation.signal, "getsignal", side_effect=handlers.__getitem__), \
            patch.object(cancellation.signal, "signal", side_effect=setter):
        yield handlers, calls, setter


def guard():
    result = DefaultCancellation(CredentialError, "fixed restoration failure")
    result.install()
    result.activate()
    return result


def local_scope(*, settled=True, handler="BORROWED_VALID"):
    return SimpleNamespace(lifetime_local_settled=settled, lifetime_handler_state=handler)


def bind_reader(evidence, owner, *, settled=True):
    scope = local_scope(settled=settled)
    descriptor = SimpleNamespace(settled=settled)
    evidence._bind(scope, guard=owner, role="READER", owns_cancellation=False,
                   descriptors=(descriptor,))
    return scope, descriptor


class LifetimeEvidenceTests(unittest.TestCase):
    def test_missing_scheduled_publication_is_fatal_but_unscheduled_work_is_not_a_debt(self):
        for schedule in (False, True):
            with self.subTest(schedule=schedule), handler_model():
                owner = guard()
                evidence = ProfileCallEvidence("decode")
                evidence._bind(local_scope(), guard=owner, role="DECODE", owns_cancellation=False)
                if schedule:
                    evidence._expect("OUTER_CMS")
                evidence._finish(primary=ValidationError("ordinary early rejection"))
                verdict = evidence.verdict()
                self.assertEqual(verdict.fatal, schedule)
                self.assertEqual(verdict.complete, not schedule)
                self.assertEqual(verdict.native_attempt, "UNKNOWN" if schedule else "NOT_ATTEMPTED")
                self.assertEqual(verdict.dispatched, schedule)
                self.assertEqual(owner.lifetime_ledger.fatal, schedule)
                owner.restore()

    def test_healthy_borrowed_call_folds_and_later_parent_failure_cannot_erase_dispatch(self):
        with handler_model() as (handlers, calls, setter):
            owner = guard()
            evidence = ProfileCallEvidence("authenticate")
            finality = SimpleNamespace(native_attempt="ATTEMPT_ARMED", validator_dispatch="RUN_ATTEMPT_ARMED",
                                       producer_settled=True, native_resources_settled=True, blocked=False)
            evidence._bind(local_scope(), guard=owner, role="OUTER_CMS", owns_cancellation=False,
                           finality=finality)
            before = len(calls)
            evidence._finish(primary=ValidationError("settled issuer rejection"))
            self.assertFalse(evidence.verdict().fatal)
            self.assertEqual(evidence.verdict().handler_state, "BORROWED_VALID")
            self.assertEqual(len(calls), before)  # Borrower installed/restored nothing.
            ledger = owner.lifetime_ledger
            self.assertTrue(ledger.verdict().profile_dispatched)
            self.assertIs(ledger.verdict().command_dispatched, False)
            self.assertEqual(ledger.verdict().profile_calls, 1)
            foreign = lambda *_: None
            handlers[signal.SIGTERM] = foreign
            with self.assertRaises(CredentialError):
                owner.restore()
            self.assertIs(handlers[signal.SIGTERM], foreign)
            self.assertTrue(ledger.fatal)
            self.assertTrue(evidence.verdict().fatal)
            self.assertTrue(evidence.verdict().dispatched)
            self.assertIs(ledger.verdict().command_dispatched, False)

    def test_known_attempts_survive_missing_local_publication_and_producer_only_success(self):
        with handler_model():
            owner = guard()
            evidence = ProfileCallEvidence("authenticate")
            finality = SimpleNamespace(native_attempt="ATTEMPT_ARMED", validator_dispatch="RUN_ATTEMPT_ARMED",
                                       producer_settled=True, native_resources_settled=False, blocked=False)
            evidence._bind(SimpleNamespace(lifetime_handler_state="BORROWED_VALID"), guard=owner,
                           role="OUTER_CMS", owns_cancellation=False, finality=finality,
                           descriptors=(SimpleNamespace(settled=False),),
                           scratch=SimpleNamespace(state="UNKNOWN", retained=True))
            evidence._finish()
            verdict = evidence.verdict()
            self.assertTrue(verdict.fatal and verdict.contained)
            self.assertFalse(verdict.complete or verdict.cleanup_complete)
            self.assertEqual(verdict.native_attempt, "ATTEMPT_ARMED")
            self.assertEqual(verdict.validator_dispatch, "RUN_ATTEMPT_ARMED")
            owner.restore()

    def test_unknown_or_inconsistent_attempt_publication_cannot_fold_as_healthy(self):
        for attempted, dispatched in (("UNKNOWN", "NOT_SENT"), ("ATTEMPT_ARMED", "UNKNOWN"),
                                      ("NOT_ATTEMPTED", "RUN_ATTEMPT_ARMED")):
            with self.subTest(attempted=attempted, dispatched=dispatched), handler_model():
                owner = guard()
                evidence = ProfileCallEvidence("authenticate")
                finality = SimpleNamespace(native_attempt=attempted, validator_dispatch=dispatched,
                                           producer_settled=True, native_resources_settled=True, blocked=False)
                evidence._bind(local_scope(), guard=owner, role="OUTER_CMS", owns_cancellation=False,
                               finality=finality)
                evidence._finish()
                self.assertTrue(evidence.verdict().fatal and owner.lifetime_ledger.fatal)
                self.assertEqual(owner.lifetime_ledger.verdict().profile_calls, 0)
                owner.restore()

    def test_explicit_previous_unknown_is_strongly_bound_and_never_becomes_no_attempt_acceptance(self):
        with handler_model():
            owner = guard()
            evidence = ProfileCallEvidence("read")
            evidence._bind_guard(owner)
            blocker = object()
            evidence._block(blocker)
            self.assertIs(evidence._blockers[0], blocker)
            self.assertTrue(owner.lifetime_ledger.fatal)
            evidence._finish(primary=ValidationError("reuse rejected"))
            self.assertTrue(evidence.verdict().blocked)
            self.assertFalse(evidence.verdict().positive_no_native_attempt)
            owner.restore()
        with handler_model():
            owner = guard()
            evidence = ProfileCallEvidence("authenticate")
            finality = SimpleNamespace(native_attempt="NOT_ATTEMPTED", validator_dispatch="NOT_SENT",
                                       producer_settled=True, native_resources_settled=True, blocked=True)
            evidence._bind(local_scope(), guard=owner, role="OUTER_CMS", owns_cancellation=False,
                           finality=finality)
            evidence._finish()
            self.assertTrue(evidence.verdict().blocked and evidence.verdict().fatal)
            owner.restore()

    def test_missing_evidence_and_ordinary_fatal_use_explicit_conservative_compatibility_facts(self):
        missing = ProfileCallEvidence("read")
        with self.assertRaises(ProcessError) as raised:
            consume_profile_evidence(missing, primary=ValidationError("ordinary"), message="fixed fatal")
        self.assertTrue(raised.exception.dispatched)
        self.assertFalse(raised.exception.contained or raised.exception.cleanup_complete)
        with handler_model():
            owner = guard()
            evidence = ProfileCallEvidence("read")
            bind_reader(evidence, owner, settled=False)
            with self.assertRaises(ProcessError) as raised:
                consume_profile_evidence(evidence, primary=ValidationError("ordinary"), message="fixed fatal")
            self.assertFalse(raised.exception.dispatched or raised.exception.cleanup_complete)
            self.assertTrue(raised.exception.contained)
            owner.restore()

    def test_adapter_preserves_first_interruption_without_attributes_or_notes(self):
        for original in (KeyboardInterrupt("original"), SystemExit(37)):
            with self.subTest(kind=type(original).__name__), handler_model():
                owner = guard()
                evidence = ProfileCallEvidence("read")
                bind_reader(evidence, owner, settled=False)
                original.__notes__ = object()
                before = dict(original.__dict__)
                with self.assertRaises(type(original)) as raised:
                    consume_profile_evidence(evidence, primary=original, message="fixed fatal")
                self.assertIs(raised.exception, original)
                self.assertEqual(original.__dict__, before)
                self.assertTrue(owner.lifetime_ledger.fatal)
                self.assertIs(owner.lifetime_ledger._primary, original)
                owner.restore()

    def test_first_diagnostic_interruption_is_preserved_but_never_promoted_over_earlier_primary(self):
        for earlier in (None, ValidationError("earlier ordinary"), SystemExit(19)):
            with self.subTest(earlier=type(earlier).__name__), handler_model():
                owner = guard()
                evidence = ProfileCallEvidence("read")
                bind_reader(evidence, owner)
                diagnostic = KeyboardInterrupt("first collection interruption")
                with patch.object(evidence, "_snapshot", side_effect=diagnostic):
                    expected = type(earlier) if isinstance(earlier, SystemExit) else KeyboardInterrupt if earlier is None else ProcessError
                    with self.assertRaises(expected) as raised:
                        consume_profile_evidence(evidence, primary=earlier, message="fixed fatal")
                    if earlier is None:
                        self.assertIs(raised.exception, diagnostic)
                    elif isinstance(earlier, SystemExit):
                        self.assertIs(raised.exception, earlier)
                self.assertTrue(owner.lifetime_ledger.fatal)
                owner.restore()

    def test_command_pending_and_unknown_are_not_default_success_or_profile_dispatch(self):
        with handler_model():
            owner = guard()
            ledger = owner.lifetime_ledger
            slot = object()
            ledger._bind_command(slot)
            self.assertFalse(ledger.fatal)  # Pending is not an asynchronous abort.
            owner.check()
            self.assertTrue(ledger.verdict().fatal)
            self.assertIsNone(ledger.verdict().command_dispatched)
            with self.assertRaises(ValueError):
                ledger._finish_command(object(), dispatched=False, contained=True, cleanup_complete=True)
            ledger._finish_command(slot, dispatched=None, contained=True, cleanup_complete=True)
            self.assertTrue(ledger.fatal)
            self.assertIs(ledger.verdict().profile_dispatched, False)
            self.assertIsNone(ledger.verdict().command_dispatched)
            with self.assertRaises(ValueError):
                ledger._finish_command(slot, dispatched=False, contained=True, cleanup_complete=True)
            self.assertIs(ledger._command, slot)  # No late repair retires UNKNOWN.
            with self.assertRaises(ValueError):
                ledger._bind_command(object())
            owner.restore()

    def test_original_thread_object_not_recycled_numeric_ident_owns_evidence_and_guard(self):
        with handler_model() as (_, calls, _):
            owner = guard()
            evidence = ProfileCallEvidence("read")
            bind_reader(evidence, owner)
            depth, count = owner.depth, len(calls)
            same_ident = threading.get_ident()
            with patch.object(cancellation.threading, "current_thread", return_value=object()), \
                    patch.object(cancellation.threading, "get_ident", return_value=same_ident):
                for action in (owner.install, owner.activate, owner.check, owner.restore,
                               lambda: owner.lifetime_ledger,
                               lambda: cancellation_owner(owner, CredentialError, "fixed")):
                    with self.assertRaises(CredentialError):
                        action()
                with self.assertRaises(CredentialError):
                    with owner.deferred():
                        self.fail("foreign thread entered deferral")
                with self.assertRaises(ValueError):
                    evidence.verdict()
            self.assertEqual((owner.depth, len(calls)), (depth, count))
            evidence._finish()
            owner.restore()


class InertCancellationLifecycleTests(unittest.TestCase):
    def test_fatal_projection_rejects_foreign_guard_before_any_parent_property(self):
        from mobile_release import _profile_callers as callers

        with handler_model():
            owner = guard()
            original_pid = owner.pid
            with patch.object(callers, "os", SimpleNamespace(getpid=lambda: original_pid + 1)), \
                    patch.object(DefaultCancellation, "lifetime_ledger", new_callable=PropertyMock) as ledger:
                ledger.side_effect = AssertionError("inherited ledger property was touched")
                projected = fatal_cancellation_error(CredentialError("ordinary"), owner, "fixed")
                self.assertEqual((projected.dispatched, projected.contained, projected.cleanup_complete),
                                 (True, False, False))
                ledger.assert_not_called()
                for first in (KeyboardInterrupt("original"), SystemExit(19), GeneratorExit()):
                    with self.subTest(kind=type(first).__name__), self.assertRaises(type(first)) as caught:
                        fatal_cancellation_error(first, owner, "fixed")
                    self.assertIs(caught.exception, first)
                    ledger.assert_not_called()
                class OtherGeneratorExit(GeneratorExit):
                    pass
                for first, selected in ((OtherGeneratorExit(), owner),
                                        (GeneratorExit(), SimpleNamespace(pid=original_pid))):
                    projected = fatal_cancellation_error(first, selected, "fixed")
                    self.assertTrue(projected.fatal)
                    self.assertFalse(projected.contained)
                    ledger.assert_not_called()
            with patch.object(callers, "threading", SimpleNamespace(current_thread=lambda: object())), \
                    patch.object(DefaultCancellation, "lifetime_ledger", new_callable=PropertyMock) as ledger:
                ledger.side_effect = AssertionError("foreign-thread ledger property was touched")
                projected = fatal_cancellation_error(GeneratorExit(), owner, "fixed")
                self.assertTrue(projected.fatal)
                ledger.assert_not_called()

            # Exercise real generator.close and the actual copied-scope path,
            # but model PID observations and close failure: no fork, FD or signal.
            for close_error in (None, OSError("copied descriptor close failed")):
                with self.subTest(copy_close_failed=close_error is not None):
                    closed, primaries = [], []
                    def close_copy():
                        closed.append(True)
                        if close_error is not None:
                            raise close_error
                    scope = CleanupScope(owner, lambda: self.fail("parent cleanup was called"),
                                         owns_cancellation=False, fork_cleanup=close_copy)
                    def inherited_generator():
                        try:
                            with scope:
                                yield
                        except BaseException as primary:
                            primaries.append(primary)
                            projected = fatal_cancellation_error(primary, owner, "fixed")
                            if projected is not None:
                                raise projected from None
                            raise
                    stream = inherited_generator()
                    next(stream)
                    foreign_pid = SimpleNamespace(getpid=lambda: original_pid + 1)
                    with patch.object(callers, "os", foreign_pid), \
                            patch.object(cancellation, "os", foreign_pid), \
                            patch.object(cancellation, "_FORK_UNSAFE", False), \
                            patch.object(DefaultCancellation, "lifetime_ledger", new_callable=PropertyMock) as ledger:
                        ledger.side_effect = AssertionError("inherited close touched the parent ledger")
                        if close_error is None:
                            stream.close()
                            self.assertIs(type(primaries[0]), GeneratorExit)
                            self.assertFalse(cancellation._FORK_UNSAFE)
                        else:
                            with self.assertRaises(ProcessError) as caught:
                                stream.close()
                            self.assertIs(primaries[0], close_error)
                            self.assertTrue(caught.exception.fatal)
                            self.assertTrue(cancellation._FORK_UNSAFE)
                        ledger.assert_not_called()
                        self.assertTrue(scope.claimed and scope.fork_relinquished)
                        self.assertEqual(closed, [True])
                    self.assertIsNone(stream.gi_frame)
            owner.lifetime_ledger._abort(OSError("own-process unresolved resource"))
            projected = fatal_cancellation_error(GeneratorExit(), owner, "fixed")
            self.assertTrue(projected.fatal)
            owner.restore()

    def test_healthy_guard_cannot_demote_direct_fatal_facts_and_missing_verdict_is_unknown(self):
        with handler_model():
            owner = guard()
            first = ProcessError("earlier owner", dispatched=True, contained=False)
            projected = fatal_cancellation_error(first, owner, "fixed")
            self.assertTrue(projected.fatal)
            self.assertTrue(projected.dispatched)
            self.assertFalse(projected.contained)
            for value in (None, object(), SimpleNamespace(fatal=False, complete=True)):
                with self.subTest(verdict=type(value).__name__), \
                        patch.object(owner.lifetime_ledger, "verdict", return_value=value):
                    projected = fatal_cancellation_error(CredentialError("ordinary"), owner, "fixed")
                    self.assertEqual((projected.dispatched, projected.contained, projected.cleanup_complete),
                                     (True, False, False))
            owner.restore()

    def test_only_original_installed_tokens_are_borrowed_and_custom_handlers_are_preserved(self):
        with handler_model() as (handlers, _, _):
            owner = guard()
            depth = owner.depth
            self.assertEqual(cancellation_owner(None, CredentialError, "fixed"), (owner, False))
            self.assertEqual(cancellation_owner(owner, CredentialError, "fixed"), (owner, False))
            self.assertEqual(owner.depth, depth)
            lookalike = owner.interrupt  # Same __func__/__self__, NOT installed token.
            handlers[signal.SIGINT] = lookalike
            with self.assertRaises(CredentialError):
                cancellation_owner(owner, CredentialError, "fixed")
            with self.assertRaises(CredentialError):
                owner.restore()
            self.assertIs(handlers[signal.SIGINT], lookalike)
            self.assertIs(handlers[signal.SIGTERM], signal.SIG_DFL)

    def test_restore_return_loss_is_monotonic_and_independent_handlers_still_restore(self):
        for selected in (signal.SIGTERM, signal.SIGINT):
            for error in (KeyboardInterrupt("return lost"), SystemExit(23), OSError("private-detail")):
                with self.subTest(selected=selected, kind=type(error).__name__), handler_model() as (handlers, calls, setter):
                    owner = guard()
                    calls.clear()
                    def lost_return(signum, token):
                        previous = setter(signum, token)
                        if signum == selected:
                            raise error
                        return previous
                    with patch.object(cancellation.signal, "signal", side_effect=lost_return):
                        with self.assertRaises(type(error) if isinstance(error, (KeyboardInterrupt, SystemExit)) else CredentialError) as raised:
                            owner.restore()
                        self.assertEqual(calls, [signal.SIGTERM, signal.SIGINT])
                        self.assertEqual(handlers, owner.previous)
                        self.assertEqual(owner.handler_state, "UNKNOWN")
                        with self.assertRaises(CredentialError):
                            owner.restore()
                        self.assertEqual(calls, [signal.SIGTERM, signal.SIGINT])
                    if isinstance(error, (KeyboardInterrupt, SystemExit)):
                        self.assertIs(raised.exception, error)
                    else:
                        self.assertNotIn("private-detail", str(raised.exception))
                    self.assertTrue(owner.lifetime_ledger.fatal)

    def test_install_return_loss_cannot_be_repaired_by_observing_old_defaults(self):
        with handler_model() as (handlers, calls, setter):
            owner = DefaultCancellation(CredentialError, "fixed")
            original = KeyboardInterrupt("install return lost")
            def lost_return(signum, token):
                setter(signum, token)
                raise original
            with patch.object(cancellation.signal, "signal", side_effect=lost_return), self.assertRaises(KeyboardInterrupt) as raised:
                owner.install()
            self.assertIs(raised.exception, original)
            self.assertEqual(owner._signals[signal.SIGINT].install, "UNKNOWN")
            with self.assertRaises(CredentialError):
                owner.restore()
            self.assertIs(handlers[signal.SIGINT], signal.default_int_handler)
            self.assertEqual(owner.handler_state, "UNKNOWN")
            self.assertTrue(owner.lifetime_ledger.fatal)

    def test_custom_or_worker_owner_can_logically_install_zero_handlers(self):
        for worker in (False, True):
            with self.subTest(worker=worker), handler_model() as (handlers, calls, _):
                callbacks = {key: (lambda *_: None) for key in handlers}
                handlers.update(callbacks)
                actual_thread = object() if worker else threading.current_thread()
                with patch.object(cancellation.threading, "current_thread", return_value=actual_thread):
                    owner = guard()
                    self.assertEqual(owner.handler_state, "ACTIVE")
                    self.assertEqual(cancellation_owner(owner, CredentialError, "fixed"), (owner, False))
                    owner.restore()
                    self.assertEqual(owner.handler_state, "RESTORED")
                self.assertEqual(calls, [])
                self.assertEqual(handlers, callbacks)

    def test_protected_dispatch_preserves_incoming_primary_before_specialization_prologue(self):
        with handler_model():
            owner = guard()
            original = SystemExit(37)
            class Scope(CleanupScope):
                def _exit_owned(self, *arguments):
                    if not self.claimed:
                        owner.interrupt(signal.SIGINT, inspect.currentframe())
                    return super()._exit_owned(*arguments)
            scope = Scope(owner, lambda: None, owns_cancellation=True, first_primary=True)
            with self.assertRaises(SystemExit) as raised:
                with scope:
                    raise original
            self.assertIs(raised.exception, original)
            self.assertTrue(owner.cancelled)
            self.assertEqual(owner.handler_state, "RESTORED")
            self.assertFalse(owner.lifetime_ledger.fatal)

    def test_first_primary_scope_still_attempts_restore_after_cleanup_interruption(self):
        for original in (ValidationError("earlier"), KeyboardInterrupt("earlier"), SystemExit(9)):
            with self.subTest(kind=type(original).__name__), handler_model() as (_, calls, setter):
                owner = guard()
                calls.clear()
                def cleanup():
                    raise KeyboardInterrupt("later cleanup")
                def restore(signum, token):
                    previous = setter(signum, token)
                    if signum == signal.SIGTERM:
                        raise OSError("later restoration")
                    return previous
                scope = CleanupScope(owner, cleanup, owns_cancellation=True, first_primary=True)
                with patch.object(cancellation.signal, "signal", side_effect=restore), self.assertRaises(type(original)) as raised:
                    with scope:
                        raise original
                self.assertIs(raised.exception, original)
                self.assertEqual(calls, [signal.SIGTERM, signal.SIGINT])
                self.assertTrue(owner.lifetime_ledger.fatal)
                self.assertIs(owner.lifetime_ledger._primary, original)
                self.assertEqual(len(scope._cleanup_errors), 2)

    def test_fixed_context_preserves_first_interruption_and_surfaces_ordinary_fatal_cleanup(self):
        for original in (ValidationError("earlier"), KeyboardInterrupt("earlier"), SystemExit(9)):
            with self.subTest(kind=type(original).__name__), handler_model():
                exits = []
                class Manager:
                    def __enter__(self):
                        return self
                    def __exit__(self, *arguments):
                        exits.append(arguments)
                        raise OSError("later cleanup")
                expected = type(original) if isinstance(original, (KeyboardInterrupt, SystemExit)) else ProcessError
                with self.assertRaises(expected) as raised:
                    with first_primary_context(Manager()):
                        raise original
                if expected is not ProcessError:
                    self.assertIs(raised.exception, original)
                else:
                    self.assertTrue(raised.exception.fatal)
                    self.assertFalse(raised.exception.dispatched)
                    self.assertTrue(raised.exception.contained)
                self.assertEqual(len(exits), 1)
                self.assertIs(exits[0][1], original)

    def test_fixed_context_exposes_actual_zero_handler_owner_to_nested_resources(self):
        with handler_model() as (handlers, calls, _):
            handlers.update({signum: (lambda *_: None) for signum in handlers})
            value = object()
            class Manager:
                def __enter__(self):
                    return value
                def __exit__(self, *_arguments):
                    return False
            with first_primary_context(Manager(), expose_owner=True) as (resource, owner):
                self.assertIs(resource, value)
                self.assertEqual(owner.handler_state, "ACTIVE")
                with first_primary_context(Manager(), cancellation=owner, expose_owner=True) as (nested, borrowed):
                    self.assertIs(nested, value)
                    self.assertIs(borrowed, owner)
                self.assertEqual(owner.handler_state, "ACTIVE")
            self.assertEqual(owner.handler_state, "RESTORED")
            self.assertEqual(calls, [])
            for invalid in (None, 0, 1, "true"):
                with self.subTest(invalid=invalid), self.assertRaises(TypeError):
                    with first_primary_context(Manager(), expose_owner=invalid):
                        self.fail("invalid exposure was admitted")

    def test_fixed_context_error_projection_never_erases_direct_conservative_command_facts(self):
        with handler_model():
            original = ProcessError("earlier command", dispatched=True, contained=False)
            class Manager:
                def __enter__(self):
                    return self
                def __exit__(self, *_arguments):
                    raise OSError("independent cleanup error")
            with self.assertRaises(ProcessError) as raised:
                with first_primary_context(Manager()):
                    raise original
            self.assertTrue(raised.exception.dispatched)
            self.assertFalse(raised.exception.contained)
            self.assertFalse(raised.exception.cleanup_complete)

    def test_exposed_zero_handler_owner_retains_nested_profile_dispatch_through_outer_cleanup_failure(self):
        # Pure aggregation model, never a native receipt or cleanup authority.
        for worker in (False, True):
            with self.subTest(worker=worker), handler_model() as (handlers, calls, _):
                handlers.update({signum: (lambda *_: None) for signum in handlers})
                actual_thread = object() if worker else threading.current_thread()
                class Manager:
                    def __enter__(self):
                        return self
                    def __exit__(self, *_arguments):
                        raise OSError("outer resource close failed")
                with patch.object(cancellation.threading, "current_thread", return_value=actual_thread), \
                     self.assertRaises(ProcessError) as raised:
                    with first_primary_context(Manager(), expose_owner=True) as (_resource, owner):
                        evidence = ProfileCallEvidence("authenticate")
                        same, owns = cancellation_owner(owner, CredentialError, "fixed nested owner")
                        self.assertIs(same, owner)
                        self.assertFalse(owns)
                        finality = SimpleNamespace(native_attempt="ATTEMPT_ARMED", validator_dispatch="RUN_ATTEMPT_ARMED",
                                                   producer_settled=True, native_resources_settled=True, blocked=False)
                        evidence._bind(local_scope(), guard=same, role="OUTER_CMS", owns_cancellation=False,
                                       finality=finality)
                        consume_profile_evidence(evidence, primary=None, message="fixed profile failure")
                        self.assertFalse(owner.lifetime_ledger.fatal)
                        self.assertIs(owner.lifetime_ledger.verdict().command_dispatched, False)
                self.assertTrue(raised.exception.fatal)
                self.assertTrue(raised.exception.dispatched)
                self.assertTrue(raised.exception.contained)
                self.assertFalse(raised.exception.cleanup_complete)
                self.assertEqual(calls, [])
