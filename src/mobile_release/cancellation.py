"""Default-signal ownership for fixed, non-yielding resource cleanup.

This is not a public cancellation API or a global lifetime/concurrency lease.
Every caller must arm an unconditional outer finally around its CleanupScope:
normal with-exit dispatch can be interrupted before __exit__ has a frame.
"""
from __future__ import annotations

import os
import shutil
import signal
import stat
import tempfile
import threading
import weakref
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from types import FrameType, MethodType, TracebackType
from typing import Any

from ._lifetime_evidence import LifetimeLedger


_FORK_RESOURCES: weakref.WeakSet = weakref.WeakSet()
_FORK_UNSAFE = False


def _mark_fork_unsafe() -> None:
    global _FORK_UNSAFE
    _FORK_UNSAFE = True


@dataclass
class _SignalOwnership:
    previous: Any
    token: MethodType
    install: str = "ATTEMPT_ARMED"
    restore: str = "NOT_ATTEMPTED"
    child_restore: str = "NOT_ATTEMPTED"


def _signal_owner(handler: Any, signum: int) -> tuple[DefaultCancellation, _SignalOwnership] | None:
    """Recognize only the exact preregistered bound-method installation token."""
    if type(handler) is not MethodType:
        return None
    owner = handler.__self__
    if type(owner) is not DefaultCancellation or handler.__func__ is not DefaultCancellation.interrupt:
        return None
    record = owner._signals.get(signum)
    if record is None or record.token is not handler:
        raise ValueError("local cancellation handler has no original installation record")
    return owner, record


def _after_fork_child() -> None:
    """Relinquish child copies before restoring only inherited toolkit handlers."""
    try:
        resources = tuple(_FORK_RESOURCES)
    except BaseException:
        resources = ()
        _mark_fork_unsafe()
    for resource in resources:
        try:
            resource.after_fork_child()
        except BaseException:
            _mark_fork_unsafe()
    # No inherited guard/ledger API or lock is used here. Each setter is a
    # child-only one-attempt record, independent from the parent's restoration.
    for signum in (signal.SIGTERM, signal.SIGINT):
        record = None
        try:
            handler = signal.getsignal(signum)
            owned = _signal_owner(handler, signum)
            if owned is None or owned[0].pid == os.getpid():
                continue
            _, record = owned
            if record.child_restore != "NOT_ATTEMPTED":
                _mark_fork_unsafe()
                continue
            record.child_restore = "ATTEMPT_ARMED"
            previous = signal.signal(signum, record.previous)
            if previous is not handler:
                raise ValueError("inherited cancellation handler changed")
            record.child_restore = "RESTORED"
        except BaseException:
            if record is not None:
                record.child_restore = "UNKNOWN"
            _mark_fork_unsafe()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_child)


class DefaultCancellation:
    """Share nested deferral; leave custom handlers and worker threads alone."""

    def __init__(self, restore_error: type[Exception], restore_message: str) -> None:
        self.pid = os.getpid()
        self.owner_thread = threading.current_thread()
        self.thread = threading.get_ident()  # Diagnostic compatibility, not identity.
        self.depth = 1
        self._cancelled = False
        self._signals: dict[int, _SignalOwnership] = {}
        self._installation = "NOT_INSTALLED"
        self._restoration = "NOT_ATTEMPTED"
        self._activated = False
        # Installed only by the dedicated native edit bootstrap. Passive/CLI
        # imports neither load its module nor acquire any input descriptor.
        self._edit_source: Any = None
        self._edit_source_installed = False
        self._edit_source_removed = False
        # A separate one-request diagnostics source; never an edit protocol
        # extension or a generic cancellation callback. Only one domain binds.
        self._environment_source: Any = None
        self._environment_source_installed = False
        self._environment_source_removed = False
        # One separately typed saved-project execution domain, never diagnostics
        # or a caller cancellation callback. The bindings are mutually exclusive.
        self._preflight_source: Any = None
        self._preflight_source_installed = False
        self._preflight_source_removed = False
        self._ledger = LifetimeLedger(self)
        self._diagnostic_error: BaseException | None = None
        # Compatibility/diagnostics only: modifying this mapping grants nothing.
        self.previous: dict[int, Any] = {}
        self.restore_error = restore_error
        self.restore_message = restore_message
        _FORK_RESOURCES.add(self)

    def _check_owner(self) -> None:
        if self.pid != os.getpid() or self.owner_thread is not threading.current_thread():
            raise self.restore_error("inherited cancellation ownership cannot authorize new work")

    @property
    def cancelled(self) -> bool:
        # A reconciled creator may observe this monotonic latch, not mutate it
        # or borrow any owner-only guard API.
        return self._cancelled

    @cancelled.setter
    def cancelled(self, value: bool) -> None:
        self._check_owner()
        if type(value) is not bool or (self._cancelled and not value):
            raise self.restore_error("cancellation cannot be reset")
        self._cancelled = value

    @property
    def lifetime_ledger(self) -> LifetimeLedger:
        self._check_owner()
        return self._ledger

    @property
    def handler_state(self) -> str:
        self._check_owner()
        if (self._installation in ("INSTALLING", "UNKNOWN")
                or self._restoration in ("ATTEMPT_ARMED", "UNKNOWN")):
            return "UNKNOWN"
        if self._restoration == "RESTORED":
            return "RESTORED"
        if self._installation != "INSTALLED":
            return "NOT_INSTALLED"
        try:
            for signum, record in self._signals.items():
                owned = _signal_owner(signal.getsignal(signum), signum)
                if owned is None or owned[0] is not self or owned[1] is not record:
                    return "UNKNOWN"
        except Exception:
            return "UNKNOWN"
        return "ACTIVE"

    def _abort(self, error: BaseException) -> None:
        self._check_owner()
        try:
            try:
                if self._preflight_source is not None:
                    self._preflight_source.failure_observed()
            finally:
                self._ledger._abort(error)
        except BaseException as diagnostic:
            # The original failure precedes optional diagnostics. Retain the
            # fatal bit even if diagnostic publication itself loses its return.
            self._ledger._fatal = True
            if self._diagnostic_error is None:
                self._diagnostic_error = diagnostic

    def after_fork_child(self) -> None:
        if self.pid != os.getpid() and (
            self._installation in ("INSTALLING", "UNKNOWN")
            or self._restoration in ("ATTEMPT_ARMED", "UNKNOWN")
            or self._ledger._fatal or self._ledger._profile is not None or self._ledger._command is not None
        ):
            _mark_fork_unsafe()

    def interrupt(self, signum: int, frame: FrameType | None) -> None:
        self._check_owner()
        already_cancelled = self._cancelled
        self._cancelled = True
        if self.depth or already_cancelled:
            return
        # Only fixed executing cleanup code, never an entire setup/yield
        # generator: deferring at a late yield could enter a cancelled build.
        while frame is not None:
            if frame.f_code is CleanupScope.__exit__.__code__:
                return
            frame = frame.f_back
        raise KeyboardInterrupt

    def install(self) -> None:
        self._check_owner()
        if self._installation != "NOT_INSTALLED" or self._restoration != "NOT_ATTEMPTED":
            raise self.restore_error("cancellation installation cannot be repeated")
        self._installation = "INSTALLING"
        record = None
        try:
            if self.owner_thread is threading.main_thread():
                # Own catchable INT first; restore it last. Save the exact
                # bound method and arm its record BEFORE the setter can run.
                for signum, default in ((signal.SIGINT, signal.default_int_handler), (signal.SIGTERM, signal.SIG_DFL)):
                    previous = signal.getsignal(signum)
                    if previous is default:
                        record = _SignalOwnership(previous, self.interrupt)
                        self._signals[signum] = record
                        self.previous[signum] = previous
                        returned = signal.signal(signum, record.token)
                        if returned is not previous:
                            raise self.restore_error("cancellation handler changed during installation")
                        record.install = "INSTALLED"
                        record = None
            self._installation = "INSTALLED"  # Zero owned handlers is legitimate.
        except BaseException as error:
            if record is not None:
                record.install = "UNKNOWN"
            self._installation = "UNKNOWN"
            self._abort(error)
            raise

    def activate(self) -> None:
        self._check_owner()
        if (self._installation != "INSTALLED" or self._restoration != "NOT_ATTEMPTED"
                or self._activated or self.depth < 1):
            raise self.restore_error("cancellation activation ownership is invalid")
        self._activated = True
        self.depth -= 1
        self.check()

    def check(self) -> None:
        self._check_owner()
        self._poll_edit_stop()
        # Pending component records are normal during work. Only the monotonic
        # abort bit, not ledger.verdict().fatal, vetoes an active operation.
        if _FORK_UNSAFE or self._ledger.fatal or self.handler_state == "UNKNOWN":
            error = self.restore_error(self.restore_message)
            self._abort(error)
            raise error
        if self.cancelled:
            raise KeyboardInterrupt

    def _install_edit_source(self, source: Any) -> None:
        from ._desktop_edit_control import EditInput
        self._check_owner()
        if (type(source) is not EditInput or self.owner_thread is not threading.main_thread()
                or self._edit_source_installed or self._edit_source_removed
                or self._environment_source_installed or self._preflight_source_installed):
            raise self.restore_error("invalid edit cancellation source ownership")
        source.bind(self)
        self._edit_source_installed = True
        self._edit_source = source

    def _poll_edit_stop(self) -> None:
        """Fixed desktop sources only; cleanup may poll but not cancelled check()."""
        self._check_owner()
        if self._edit_source is not None:
            self._edit_source.poll(self)
        if self._environment_source is not None:
            self._environment_source.poll(self)
        if self._preflight_source is not None:
            self._preflight_source.poll(self)

    def _remove_edit_source(self, source: Any) -> None:
        self._check_owner()
        if self._edit_source is not source or self._edit_source_removed or not source.closed:
            raise self.restore_error("edit cancellation source did not settle")
        self._edit_source_removed = True
        self._edit_source = None

    def _install_environment_source(self, source: Any) -> None:
        from ._desktop_environment_control import EnvironmentInput
        self._check_owner()
        if (type(source) is not EnvironmentInput or self.owner_thread is not threading.main_thread()
                or self._environment_source_installed or self._environment_source_removed
                or self._edit_source_installed or self._preflight_source_installed):
            raise self.restore_error("invalid environment cancellation source ownership")
        source.bind(self)
        self._environment_source_installed = True
        self._environment_source = source

    def _remove_environment_source(self, source: Any) -> None:
        self._check_owner()
        if (self._environment_source is not source or self._environment_source_removed or not source.closed):
            raise self.restore_error("environment cancellation source did not settle")
        self._environment_source_removed = True
        self._environment_source = None

    def _install_preflight_source(self, source: Any) -> None:
        from ._desktop_preflight_control import PreflightInput
        self._check_owner()
        if (type(source) is not PreflightInput or self.owner_thread is not threading.main_thread()
                or self._preflight_source_installed or self._preflight_source_removed
                or self._edit_source_installed or self._environment_source_installed):
            raise self.restore_error("invalid offline preflight cancellation source ownership")
        source.bind(self)
        self._preflight_source_installed = True
        self._preflight_source = source

    def _remove_preflight_source(self, source: Any) -> None:
        self._check_owner()
        if self._preflight_source is not source or self._preflight_source_removed or not source.closed:
            raise self.restore_error("offline preflight cancellation source did not settle")
        self._preflight_source_removed = True
        self._preflight_source = None

    @contextmanager
    def deferred(self, *, check_on_exit: bool = True):
        self._check_owner()
        self.depth += 1
        try:
            yield
        finally:
            self._check_owner()
            self.depth -= 1
        # Do not mask an active error or end an enclosing acquisition's deferral.
        if check_on_exit and not self.depth:
            self.check()

    def restore(self) -> None:
        self._check_owner()
        if self._restoration == "RESTORED":
            return
        if self._restoration != "NOT_ATTEMPTED":
            raise self.restore_error(self.restore_message)  # No UNKNOWN retry setter.
        self._restoration = "ATTEMPT_ARMED"
        self.depth += 1
        failed = False
        first: BaseException | None = None
        for signum in (signal.SIGTERM, signal.SIGINT):
            record = self._signals.get(signum)
            if record is None:
                continue
            record.restore = "ATTEMPT_ARMED"
            try:
                current = signal.getsignal(signum)
                owned = _signal_owner(current, signum)
                if owned is None or owned[0] is not self or owned[1] is not record:
                    # Preserve any intervening callback, including one equal to
                    # the old default. Observation is not a restoration receipt.
                    raise self.restore_error(self.restore_message)
                returned = signal.signal(signum, record.previous)
                if returned is not current:
                    raise self.restore_error(self.restore_message)
                record.restore = "RESTORED"
            except BaseException as error:
                record.restore = "UNKNOWN"
                failed = True
                if first is None:
                    first = (error if isinstance(error, (KeyboardInterrupt, SystemExit))
                             else self.restore_error(self.restore_message))
                self._abort(error)
                # Always attempt the independent remaining restoration, even
                # after an actual KeyboardInterrupt/SystemExit return loss.
        if failed or self._installation in ("INSTALLING", "UNKNOWN"):
            self._restoration = "UNKNOWN"
            if first is None:
                first = self.restore_error(self.restore_message)
                self._abort(first)
            raise first from None
        self._restoration = "RESTORED"

    def _borrowable(self) -> None:
        self._check_owner()
        if self.handler_state != "ACTIVE" or self._ledger.fatal:
            raise self.restore_error("local cancellation ownership is inconsistent")
        for signum, record in self._signals.items():
            if record.install != "INSTALLED" or record.restore != "NOT_ATTEMPTED":
                raise self.restore_error("local cancellation ownership is inconsistent")
            owned = _signal_owner(signal.getsignal(signum), signum)
            if owned is None or owned[0] is not self or owned[1] is not record:
                raise self.restore_error("local cancellation ownership is inconsistent")


def cancellation_owner(
    requested: DefaultCancellation | None, error: type[Exception], message: str,
) -> tuple[DefaultCancellation, bool]:
    """Borrow the actual active same-thread owner, never a lookalike/custom handler."""
    if _FORK_UNSAFE:
        raise error("inherited resource cleanup is unresolved; end this process before retrying")
    owners = set()
    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM):
            try:
                owned = _signal_owner(signal.getsignal(signum), signum)
            except ValueError:
                raise error("local cancellation ownership is inconsistent") from None
            if owned is not None:
                owners.add(owned[0])
    if len(owners) > 1:
        raise error("local cancellation handlers have different owners")
    if requested is not None:
        if (type(requested) is not DefaultCancellation or requested.pid != os.getpid()
                or requested.owner_thread is not threading.current_thread()
                or (owners and requested not in owners)):
            raise error("local cancellation owner cannot be borrowed across processes or threads")
        owners.add(requested)
    if owners:
        owner = owners.pop()
        try:
            owner._borrowable()
        except Exception:
            raise error("local cancellation ownership is inconsistent") from None
        return owner, False
    return DefaultCancellation(error, message), True


class CleanupScope:
    """Attempt registered cleanup once; a claimed attempt is NOT proof of success.

    Construct and enter before installing handlers or acquiring resources. In an
    unconditional outer finally call __exit__(*sys.exc_info()) again: this covers
    interrupted inner with-exit dispatch, without replaying ambiguous cleanup.
    """

    def __init__(
        self, cancellation: DefaultCancellation, cleanup: Callable[[], None], *, owns_cancellation: bool,
        fork_cleanup: Callable[[], None] | None = None, first_primary: bool = False,
    ) -> None:
        self.cancellation = cancellation
        self.cleanup = cleanup
        self.owns_cancellation = owns_cancellation
        self.claimed = False
        self.pid = os.getpid()
        self.owner_thread = threading.current_thread()
        self.fork_cleanup = fork_cleanup
        self.fork_relinquished = False
        self.first_primary = first_primary
        self._first_error: BaseException | None = None
        self._cleanup_errors: list[BaseException] = []
        if fork_cleanup is not None:
            _FORK_RESOURCES.add(self)

    def after_fork_child(self) -> None:
        if self.pid != os.getpid():
            self.fork_relinquished = True
            self.claimed = True
            if self.fork_cleanup is not None:
                try:
                    # Callback slots clear before close; revisit only a new,
                    # positively published child-copy handoff, never cleanup.
                    self.fork_cleanup()
                except BaseException:
                    _mark_fork_unsafe()
                    raise

    def __enter__(self):
        return self

    def __exit__(
        self, exception_type: type[BaseException] | None, error: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if self.pid != os.getpid():
            self.after_fork_child()
            return False
        if self.owner_thread is not threading.current_thread():
            raise self.cancellation.restore_error("cleanup belongs to another thread")
        # Keep this fixed frame active before entering a specialization's first
        # instruction, including its incoming-primary recording prologue.
        return self._exit_owned(exception_type, error, traceback)

    def _record_failure(self, error: BaseException) -> None:
        if self.pid != os.getpid():
            self.after_fork_child()
            raise self.cancellation.restore_error("inherited cleanup cannot publish parent evidence")
        self.cancellation._check_owner()
        if self._first_error is None:
            self._first_error = error
        try:
            if len(self._cleanup_errors) < 8:
                self._cleanup_errors.append(error)
        except BaseException:
            pass
        self.cancellation._abort(error)

    def _exit_owned(
        self, exception_type: type[BaseException] | None, error: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if self.claimed:
            return False
        self.claimed = True
        if self.first_primary:
            self._first_error = error  # Incoming primary precedes all cleanup.
            try:
                if error is not None:
                    try:
                        if self.cancellation._preflight_source is not None:
                            # Concrete saved-preflight F, before the original
                            # cleanup call; no deadline/owner change elsewhere.
                            self.cancellation._preflight_source.failure_observed()
                        self.cancellation.lifetime_ledger._remember(error)
                    except BaseException as diagnostic:
                        self._record_failure(diagnostic)
                try:
                    with self.cancellation.deferred(check_on_exit=False):
                        self.cleanup()
                except BaseException as cleanup_error:
                    self._record_failure(cleanup_error)
            finally:
                if self.owns_cancellation:
                    try:
                        self.cancellation.restore()
                    except BaseException as restore_error:
                        self._record_failure(restore_error)
            if self._first_error is not None:
                if self._first_error is not error:
                    raise self._first_error from None
                return False
            if self.owns_cancellation:
                self.cancellation.check()
            return False
        # Legacy generic precedence intentionally remains unchanged. In
        # particular a profile specialization may rethrow its settled body
        # failure from cleanup: that is not by itself a lifetime abort fact.
        try:
            with self.cancellation.deferred(check_on_exit=False):
                self.cleanup()
        finally:
            if self.owns_cancellation:
                self.cancellation.restore()
        # Restoration itself can record cancellation. Check AFTER it, only on
        # normal completion: original/cleanup/restore errors retain precedence.
        if self.owns_cancellation and exception_type is None:
            self.cancellation.check()
        return False


def _remove_owned_scratch(state: dict[str, Any]) -> None:
    if state["pid"] != os.getpid() or state["name"] is None:
        return
    try:
        current = os.lstat(state["name"])
    except FileNotFoundError:
        return
    if (not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid()
            or stat.S_IMODE(current.st_mode) != 0o700):
        raise OSError("private workspace ownership changed")
    identity = state["identity"]
    if identity is None:
        # Acquisition failed before data could be written. Never recursively
        # remove a namespace whose original inode was not captured.
        os.rmdir(state["name"])
    elif identity != (current.st_dev, current.st_ino):
        raise OSError("private workspace identity changed")
    else:
        shutil.rmtree(state["name"])


class OwnedTemporaryDirectory:
    """Allocate only after the owner has registered this object for cleanup.

    Unlike a bare TemporaryDirectory, its finalizer cannot delete a parent's
    directory after fork, even during constructor/acquisition handoff.
    """

    def __init__(self, *, prefix: str, dir: str | os.PathLike | None = None) -> None:
        self.prefix, self.directory = prefix, dir
        self.state: dict[str, Any] = {"pid": os.getpid(), "name": None, "identity": None}
        self.finalizer = weakref.finalize(self, _remove_owned_scratch, self.state)
        _FORK_RESOURCES.add(self)

    @property
    def name(self) -> str:
        if self.state["pid"] != os.getpid() or self.state["name"] is None:
            raise OSError("private workspace has not been acquired")
        return self.state["name"]

    def acquire(self) -> None:
        if self.state["pid"] != os.getpid() or self.state["name"] is not None:
            raise OSError("private workspace acquisition ownership is invalid")
        self.state["name"] = tempfile.mkdtemp(prefix=self.prefix, dir=self.directory)
        if self.state["pid"] != os.getpid():
            raise OSError("inherited workspace cannot be acquired")
        details = os.lstat(self.name)
        self.state["identity"] = (details.st_dev, details.st_ino)

    def cleanup(self) -> None:
        self.finalizer.detach()  # An ambiguous cleanup is not a GC retry authority.
        _remove_owned_scratch(self.state)

    def after_fork_child(self) -> None:
        if self.state["pid"] != os.getpid():
            self.finalizer.detach()
