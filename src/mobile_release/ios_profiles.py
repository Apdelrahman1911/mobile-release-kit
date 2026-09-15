"""Authenticated modern provisioning content; never a substitute for app signing.

Both CMS layers need independent Apple issuer authority before the existing typed
DER/plist comparison. Historical accepted-build recovery must retain its original
authenticated validation, not call this current-policy gate again.
"""
from __future__ import annotations

import os
import stat
import sys
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from sys import exc_info
from types import TracebackType
from typing import TYPE_CHECKING, Any

from .cancellation import CleanupScope, DefaultCancellation, _FORK_RESOURCES, _mark_fork_unsafe, cancellation_owner
from .errors import ValidationError
from .inspection import InspectionDeadline
from ._lifetime_evidence import ProfileCallEvidence

if TYPE_CHECKING:
    from ._profile_process import CaptureFinality

MAX_PROFILE_BYTES = 4 * 1024 * 1024
COMPLETION_MAGIC = b"MRK-PROFILE-CMS\x01\n"
COMPLETION_MARKER = b"\x00MRK-CMS-COMPLETE\x01\n"
MAX_COMPLETION_BYTES = len(COMPLETION_MAGIC) + 4 + MAX_PROFILE_BYTES + len(COMPLETION_MARKER)
CAPTURE_SECONDS = 30
CLEANUP_SECONDS = 3
AUTHENTICATION_ERROR = (
    "Apple provisioning-profile signature or production issuer could not be authenticated; "
    "use a current Apple-issued profile and supported macOS toolkit, not a decode-only workaround"
)
_PROFILE_DESCRIPTOR_ERROR = "Apple profile descriptor cleanup could not be confirmed; end this process before retrying"
_PROFILE_SCRATCH_ERROR = "Apple profile private workspace cleanup could not be confirmed; end this process before retrying"
_PROFILE_SCOPE_ERROR = "Apple profile resource cleanup could not be confirmed; end this process before retrying"
_PROFILE_REUSE_ERROR = "Apple profile ownership remains unresolved; end this process before retrying"
_PROFILE_SCRATCH_FILES = (
    "cms.der", "verify-input.der", "native-content.bin", "native-signer.pem", "verified-content.bin",
)

# Strong roots, not finalizers. Only positively settled records are retired.
# An exception/GC/unwind cannot discard ambiguous local FD or scratch custody,
# even when the separate capture owner has proved that no producer remains.
_PROFILE_SCRATCH_LEASES: list[ScratchLease] = []
_PROFILE_RESOURCE_SCOPES: list[_ProfileCleanupScope] = []


def completion_frame(content: bytes) -> bytes:
    """Private trusted-child IPC; this framing is not Apple issuer authority."""
    if type(content) is not bytes or not 0 < len(content) <= MAX_PROFILE_BYTES:
        raise ValidationError("authenticated profile content exceeds its safety bound")
    return COMPLETION_MAGIC + len(content).to_bytes(4, "big") + content + COMPLETION_MARKER


def completed_content(frame: bytes) -> bytes:
    header = len(COMPLETION_MAGIC) + 4
    if type(frame) is bytes and header + len(COMPLETION_MARKER) < len(frame) <= MAX_COMPLETION_BYTES:
        size = int.from_bytes(frame[len(COMPLETION_MAGIC):header], "big")
        if (frame.startswith(COMPLETION_MAGIC) and 0 < size <= MAX_PROFILE_BYTES
                and len(frame) == header + size + len(COMPLETION_MARKER)
                and frame.endswith(COMPLETION_MARKER)):
            return frame[header:header + size]
    raise ValidationError(AUTHENTICATION_ERROR + "; missing or malformed private completion frame")


def _profile_cancellation(requested: DefaultCancellation | None = None) -> tuple[DefaultCancellation, bool]:
    return cancellation_owner(
        requested, ValidationError, "Apple profile cancellation handlers could not be restored; no upload is authorized",
    )


def _close_profile_descriptor(descriptor: int) -> None:
    # Ownership must be cleared BEFORE this call. An error may mean close took
    # effect; retrying this number could close a reused foreign descriptor.
    try:
        os.close(descriptor)
    except OSError:
        raise ValidationError(_PROFILE_DESCRIPTOR_ERROR) from None


class _ProfileDescriptor:
    """One profile-local raw FD attempt; its containing lease/scope roots it."""

    def __init__(self) -> None:
        self.pid = os.getpid()
        self.owner_thread = threading.current_thread()
        self.state = "UNACQUIRED"
        self.number: int | None = None
        self.retired_number: int | None = None
        self._child_close_claimed = False
        _FORK_RESOURCES.add(self)

    def after_fork_child(self) -> None:
        if self.pid == os.getpid():
            return
        # A late open return is published in the same preregistered slot. The
        # child hook can revisit it, but never replay a consumed/unknown close.
        if self.state in ("CLOSING", "UNKNOWN", "INHERITED_UNKNOWN"):
            self.state = "INHERITED_UNKNOWN"
            self._child_close_claimed = True
            _mark_fork_unsafe()
            return
        if self.state == "ACQUIRING" and self.number is None:
            _mark_fork_unsafe()
        self.state = "INHERITED"
        if type(self.number) is int and self.number >= 0 and not self._child_close_claimed:
            number, self.number = self.number, None
            self._child_close_claimed = True
            try:
                os.close(number)  # Only this positively published child copy.
            except BaseException:
                self.state = "INHERITED_UNKNOWN"
                _mark_fork_unsafe()

    def _check_origin(self) -> None:
        if self.pid != os.getpid():
            self.after_fork_child()
            raise ValidationError(_PROFILE_DESCRIPTOR_ERROR)
        if self.owner_thread is not threading.current_thread():
            raise ValidationError(_PROFILE_DESCRIPTOR_ERROR)

    @property
    def settled(self) -> bool:
        return self.pid == os.getpid() and self.state in ("UNACQUIRED", "CLOSED")

    def open(self, path: Path | str, flags: int, mode: int = 0o600, *, dir_fd: int | None = None) -> int:
        self._check_origin()
        if self.state != "UNACQUIRED":
            raise ValidationError(_PROFILE_DESCRIPTOR_ERROR)
        self.state = "ACQUIRING"
        try:
            self.number = os.open(path, flags, mode, dir_fd=dir_fd)
            self._check_origin()
            if type(self.number) is not int or self.number < 0:
                raise ValidationError(_PROFILE_DESCRIPTOR_ERROR)
            self.state = "OWNED"
            return self.number
        except BaseException:
            if self.pid != os.getpid():
                self.after_fork_child()
                raise ValidationError(_PROFILE_DESCRIPTOR_ERROR) from None
            # A published exact descriptor can still be closed once. A missing
            # result after entering open is NOT a positive no-acquisition proof.
            self.state = "OWNED" if type(self.number) is int and self.number >= 0 else "UNKNOWN"
            raise

    def close(self) -> None:
        self._check_origin()
        if self.settled:
            return
        if self.state != "OWNED" or type(self.number) is not int or self.number < 0:
            self.state = "UNKNOWN"
            raise ValidationError(_PROFILE_DESCRIPTOR_ERROR)
        self.retired_number = self.number
        self.number = None
        self.state = "CLOSING"
        try:
            _close_profile_descriptor(self.retired_number)
        except BaseException:
            self.state = "UNKNOWN"
            raise
        self.state = "CLOSED"


def _require_profile_scratch_available(evidence: ProfileCallEvidence | None = None) -> None:
    """No reset/retry path may silently abandon unresolved local ownership."""
    for record in (*_PROFILE_SCRATCH_LEASES, *_PROFILE_RESOURCE_SCOPES):
        if record.retained:
            if evidence is not None:
                evidence._block(record)
            raise ValidationError(_PROFILE_REUSE_ERROR)


class _ProfileCleanupScope(CleanupScope):
    """Profile-only first-primary arbitration, not a change to CleanupScope.

    Keep the actual base __exit__ frame and its one-attempt claim: the default
    signal guard recognizes that frame during dispatch. The unconditional outer
    finally is still required. Borrowed guards are never restored here.
    """

    def __init__(
        self, cancellation: DefaultCancellation, cleanup: Callable[[], None], *,
        owns_cancellation: bool, descriptors: tuple[_ProfileDescriptor, ...],
        scratch: ScratchLease | None = None, evidence: ProfileCallEvidence | None = None,
        evidence_role: str = "READER", finality: CaptureFinality | None = None,
    ) -> None:
        self._action = cleanup
        self._restore_owned = owns_cancellation
        self._descriptors = descriptors
        self._scratch = scratch
        self._primary_error: BaseException | None = None
        self._cleanup_errors: list[tuple[str, BaseException]] = []
        self._retained = False
        self._settled = False
        self._inherited_unknown = False
        # The profile callback collects restoration errors too, while the base
        # frame continues to protect cleanup. Do not restore the guard twice.
        super().__init__(cancellation, self._cleanup_all, owns_cancellation=False,
                         fork_cleanup=self._relinquish_profile)
        _PROFILE_RESOURCE_SCOPES.append(self)
        if evidence is not None:
            evidence._bind(self, guard=cancellation, role=evidence_role,
                           owns_cancellation=owns_cancellation, descriptors=descriptors,
                           scratch=scratch, finality=finality)

    def _relinquish_profile(self) -> None:
        if self.pid == os.getpid():
            return
        self._inherited_unknown = self._inherited_unknown or self._retained
        for descriptor in self._descriptors:
            try:
                descriptor.after_fork_child()
                self._inherited_unknown |= descriptor.state == "INHERITED_UNKNOWN"
            except BaseException:
                self._inherited_unknown = True
        if self._scratch is not None:
            try:
                self._scratch.after_fork_child()
                self._inherited_unknown |= self._scratch.retained
            except BaseException:
                self._inherited_unknown = True
        if self._inherited_unknown:
            _mark_fork_unsafe()

    @property
    def lifetime_local_settled(self) -> bool:
        return self.pid == os.getpid() and self._settled and not self.retained

    @property
    def lifetime_handler_state(self) -> str:
        if self.pid != os.getpid() or not self._settled:
            return "UNKNOWN"
        state = self.cancellation.handler_state
        if self._restore_owned:
            return "RESTORED" if state == "RESTORED" else "UNKNOWN"
        return "BORROWED_VALID" if state in ("ACTIVE", "RESTORED") else "UNKNOWN"

    @property
    def retained(self) -> bool:
        if self.pid != os.getpid():
            return self._inherited_unknown
        return (self._retained or (self.claimed and not self._settled)
                or any(item.state == "UNKNOWN" for item in self._descriptors)
                or (self._scratch is not None and self._scratch.retained))

    def _record_cleanup(self, message: str, error: BaseException, *, uncertain: bool = True) -> None:
        if self.pid != os.getpid():
            self._relinquish_profile()
            raise ValidationError(_PROFILE_SCOPE_ERROR)
        if uncertain:
            self._retained = True
        if self._primary_error is None:
            self._primary_error = (error if isinstance(error, (KeyboardInterrupt, SystemExit, ValidationError))
                                   else ValidationError(message))
        # Fixed, bounded diagnostics; never mutate the caller's exception (even
        # its __notes__ may be malformed). Diagnostic storage must not replace
        # the first primary or interrupt still-required cleanup/restoration.
        try:
            if len(self._cleanup_errors) < 8:
                self._cleanup_errors.append((message, error))
        except BaseException:
            self._retained = True

    def attempt(self, message: str, action: Callable[[], None]) -> None:
        if self.pid != os.getpid():
            self._relinquish_profile()
            raise ValidationError(_PROFILE_SCOPE_ERROR)
        try:
            action()
        except BaseException as error:
            self._record_cleanup(message, error)

    def _cleanup_all(self) -> None:
        if self.pid != os.getpid():
            self._relinquish_profile()
            raise ValidationError(_PROFILE_SCOPE_ERROR)
        try:
            self.attempt(_PROFILE_SCOPE_ERROR, self._action)
            if any(not item.settled for item in self._descriptors):
                self._record_cleanup(_PROFILE_DESCRIPTOR_ERROR, ValidationError(_PROFILE_DESCRIPTOR_ERROR))
            if self._scratch is not None and self._scratch.state != "REMOVED":
                self._record_cleanup(_PROFILE_SCRATCH_ERROR, ValidationError(_PROFILE_SCRATCH_ERROR))
        finally:
            # Restoration is required even if the action, diagnostic collection
            # or a final state check itself fails. The base one-attempt claim
            # prevents replay, and the original primary still owns precedence.
            if self._restore_owned:
                self.attempt(
                    "Apple profile cancellation handlers could not be restored; no upload is authorized",
                    self.cancellation.restore,
                )
        if self.pid != os.getpid():
            self._relinquish_profile()
            raise ValidationError(_PROFILE_SCOPE_ERROR)
        self._settled = True
        # Keep retirement inside the base protected dispatch too. An exception
        # in a later outer finally must not replace the recorded primary or
        # reopen a cleanup attempt after the handlers have been restored.
        if not self.retained and self in _PROFILE_RESOURCE_SCOPES:
            _PROFILE_RESOURCE_SCOPES.remove(self)
        if self._primary_error is not None:
            raise self._primary_error from None
        # A recorded body/cleanup error wins over a merely pending default-signal
        # flag. Check only an otherwise normal exit, AFTER handler restoration.
        if self._restore_owned:
            self.cancellation.check()

    def _exit_owned(
        self, exception_type: type[BaseException] | None, error: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if self.claimed:
            return False
        if self._primary_error is None and error is not None:
            self._primary_error = error
        try:
            return super()._exit_owned(exception_type, error, traceback)
        except BaseException as late_error:
            if self._primary_error is None:
                self._primary_error = late_error
            elif late_error is not self._primary_error:
                self._record_cleanup(_PROFILE_SCOPE_ERROR, late_error, uncertain=not self._settled)
            raise self._primary_error from None


def _directory_identity(details: os.stat_result) -> tuple[int, ...]:
    # Contents legitimately change size/timestamps/link count. They cannot
    # change the original inode, type, permissions or owner of this directory.
    return (details.st_dev, details.st_ino, stat.S_IFMT(details.st_mode),
            stat.S_IMODE(details.st_mode), details.st_uid, details.st_gid)


class ScratchLease:
    """Explicit private scratch ownership, independent of producer finality.

    Construction is resource-free and publishes a strong record before mkdtemp.
    The caller holds the default-cancellation deferral during acquire/cleanup.
    No destructor, automatic recursive removal or recovery/retry method exists.
    """

    def __init__(self, finality: CaptureFinality) -> None:
        _require_profile_scratch_available()
        self.pid = os.getpid()
        self._finality = finality
        self._state = "UNACQUIRED"
        self._created_name: str | None = None
        self._path: Path | None = None
        self._identity: tuple[int, ...] | None = None
        self._parent_identity: tuple[int, ...] | None = None
        self._source = _ProfileDescriptor()
        self._parent_descriptor = _ProfileDescriptor()
        self._directory_descriptor = _ProfileDescriptor()
        self._errors: list[BaseException] = []
        finality.bind_scratch(self)  # Custody only; NEVER advance producer state.
        _PROFILE_SCRATCH_LEASES.append(self)
        _FORK_RESOURCES.add(self)

    def after_fork_child(self) -> None:
        if self.pid == os.getpid():
            return
        unknown = self._state in ("ACQUIRING", "REMOVING", "UNKNOWN", "INHERITED_UNKNOWN")
        for descriptor in (self._source, self._parent_descriptor, self._directory_descriptor):
            try:
                descriptor.after_fork_child()
                unknown |= descriptor.state == "INHERITED_UNKNOWN"
            except BaseException:
                unknown = True
        # A parent's directory is never a child cleanup target, including a
        # mkdtemp result delivered after the hook. Preserve its private name.
        self._state = "INHERITED_UNKNOWN" if unknown else "INHERITED"
        if unknown:
            _mark_fork_unsafe()

    def _check_origin(self) -> None:
        if self.pid != os.getpid():
            self.after_fork_child()
            raise ValidationError(_PROFILE_SCRATCH_ERROR)

    @property
    def path(self) -> Path | None:
        self._check_origin()
        return self._path

    @property
    def state(self) -> str:
        if self.pid != os.getpid():
            return "INHERITED"
        return self._state

    @property
    def retained(self) -> bool:
        return (self._state in ("UNKNOWN", "INHERITED_UNKNOWN") or any(item.state in ("UNKNOWN", "INHERITED_UNKNOWN") for item in
                (self._source, self._parent_descriptor, self._directory_descriptor)))

    def acquire(self) -> Path:
        self._check_origin()
        if self._state != "UNACQUIRED":
            raise ValidationError(_PROFILE_SCRATCH_ERROR)
        self._state = "ACQUIRING"
        try:
            self._created_name = tempfile.mkdtemp(prefix="mobile-release-profile-auth-")
            self._check_origin()
            self._path = Path(self._created_name)
            if not self._path.is_absolute():
                raise ValidationError(_PROFILE_SCRATCH_ERROR)
            details = os.lstat(self._path)
            self._identity = _directory_identity(details)
            parent = os.stat(self._path.parent)
            self._parent_identity = _directory_identity(parent)
            if (not stat.S_ISDIR(details.st_mode) or stat.S_IMODE(details.st_mode) != 0o700
                    or details.st_uid != os.geteuid() or not stat.S_ISDIR(parent.st_mode)):
                raise ValidationError(_PROFILE_SCRATCH_ERROR)
            self._state = "OWNED"
            return self._path
        except BaseException as error:
            if self.pid != os.getpid():
                self.after_fork_child()
                raise ValidationError(_PROFILE_SCRATCH_ERROR) from None
            self._state = "UNKNOWN"
            self._errors.append(error)
            if isinstance(error, (KeyboardInterrupt, SystemExit, ValidationError)):
                raise
            raise ValidationError(_PROFILE_SCRATCH_ERROR) from None

    def cleanup(self) -> None:
        self._check_origin()
        if self._state == "REMOVED":
            return
        if (not self._finality.cleanup_allowed
                or self._finality.state not in ("NO_PRODUCERS", "FINALIZED")
                or not self._source.settled):
            self._state = "UNKNOWN"
            raise ValidationError(_PROFILE_SCRATCH_ERROR)
        if self._state == "UNACQUIRED":
            self._state = "REMOVED"
            _PROFILE_SCRATCH_LEASES.remove(self)
            return
        if self._state != "OWNED" or self._path is None or self._identity is None:
            self._state = "UNKNOWN"
            raise ValidationError(_PROFILE_SCRATCH_ERROR)
        self._state = "REMOVING"
        failure: BaseException | None = None
        try:
            # Parent aliases such as macOS /tmp are legitimate. Bind the actual
            # original parent, then use relative operations without re-resolving
            # mutable ancestors. The scratch leaf itself must never be followed.
            parent_fd = self._parent_descriptor.open(
                self._path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            if _directory_identity(os.fstat(parent_fd)) != self._parent_identity:
                raise ValidationError(_PROFILE_SCRATCH_ERROR)
            if _directory_identity(os.stat(self._path.name, dir_fd=parent_fd, follow_symlinks=False)) != self._identity:
                raise ValidationError(_PROFILE_SCRATCH_ERROR)
            directory_fd = self._directory_descriptor.open(
                self._path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd,
            )
            if (_directory_identity(os.fstat(directory_fd)) != self._identity
                    or _directory_identity(os.stat(self._path.name, dir_fd=parent_fd, follow_symlinks=False)) != self._identity):
                raise ValidationError(_PROFILE_SCRATCH_ERROR)
            # These are the only files produced by the fixed profile workers.
            # unlink never follows a symlink and refuses directories. Unexpected
            # entries make rmdir fail; do not add a recursive walk or repair.
            for name in _PROFILE_SCRATCH_FILES:
                self._check_origin()
                try:
                    os.unlink(name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
            if (_directory_identity(os.fstat(directory_fd)) != self._identity
                    or _directory_identity(os.stat(self._path.name, dir_fd=parent_fd, follow_symlinks=False)) != self._identity):
                raise ValidationError(_PROFILE_SCRATCH_ERROR)
            # POSIX offers no atomic inode-conditional rmdir. These checks and
            # bound descriptors require cooperative same-UID namespace ownership;
            # they do not claim safety against a hostile concurrent replacer.
            self._check_origin()
            os.rmdir(self._path.name, dir_fd=parent_fd)
        except BaseException as error:
            failure = error
            self._errors.append(error)
        finally:
            # All exact known descriptors get one close attempt even after a
            # failed operation. An ambiguous number is retired, never replayed.
            for descriptor in (self._directory_descriptor, self._parent_descriptor):
                try:
                    descriptor.close()
                except BaseException as error:
                    self._errors.append(error)
                    if failure is None:
                        failure = error
        self._check_origin()
        if failure is not None:
            self._state = "UNKNOWN"
            if isinstance(failure, (KeyboardInterrupt, SystemExit, ValidationError)):
                raise failure from None
            raise ValidationError(_PROFILE_SCRATCH_ERROR) from None
        self._state = "REMOVED"
        _PROFILE_SCRATCH_LEASES.remove(self)


def _profile_evidence(evidence: ProfileCallEvidence | None, operation: str) -> tuple[ProfileCallEvidence, bool]:
    if evidence is None:
        return ProfileCallEvidence(operation=operation), True
    if type(evidence) is not ProfileCallEvidence:
        raise ValidationError(_PROFILE_SCOPE_ERROR)
    return evidence, False


def _finish_profile_evidence(evidence: ProfileCallEvidence, owned: bool, primary: BaseException | None) -> None:
    if not owned:
        return  # The caller may still have a read→decode or load obligation.
    if evidence._pid != os.getpid():
        _mark_fork_unsafe()
        if primary is None:
            raise ValidationError(_PROFILE_SCOPE_ERROR)
        return
    evidence._finish(primary=primary)
    if primary is None and evidence.verdict().fatal:
        raise ValidationError(_PROFILE_SCOPE_ERROR)


def _profile_entry(
    requested: ProfileCallEvidence | None, operation: str, cancellation: DefaultCancellation | None,
) -> tuple[ProfileCallEvidence, bool, DefaultCancellation, bool]:
    evidence, owns_evidence = _profile_evidence(requested, operation)
    guard, owns_guard = _profile_cancellation(cancellation)
    try:
        # Admission refusal must latch the actual caller's lifetime owner too.
        # This attachment acquires no resources and installs no handlers.
        evidence._bind_guard(guard)
        _require_profile_scratch_available(evidence)
    except BaseException:
        _finish_profile_evidence(evidence, owns_evidence, exc_info()[1])
        raise
    return evidence, owns_evidence, guard, owns_guard


def read_profile_bytes(
    path: Path, *, maximum: int = MAX_PROFILE_BYTES, deadline: InspectionDeadline | None = None,
    cancellation: DefaultCancellation | None = None, _evidence: ProfileCallEvidence | None = None,
) -> bytes:
    """Take one bounded no-follow snapshot with explicit raw descriptor ownership."""
    evidence, owns_evidence, guard, owns_guard = _profile_entry(_evidence, "read", cancellation)
    deadline = deadline if deadline is not None else InspectionDeadline()
    descriptor = _ProfileDescriptor()

    def cleanup() -> None:
        scope.attempt(_PROFILE_DESCRIPTOR_ERROR, descriptor.close)

    scope = _ProfileCleanupScope(guard, cleanup, owns_cancellation=owns_guard,
                                 descriptors=(descriptor,), evidence=evidence, evidence_role="READER")
    try:
        with scope:
            if owns_guard:
                guard.install()
                guard.activate()
            deadline.check()
            guard.check()
            if type(maximum) is not int or not 0 < maximum <= MAX_PROFILE_BYTES:
                raise ValidationError("provisioning input read bound is invalid")
            # Reject ordinary invalid paths before any FD attempt. The later
            # no-follow open/fstat still establishes the actual read identity;
            # an open that was attempted but never published remains UNKNOWN.
            entry = os.lstat(path)
            if not stat.S_ISREG(entry.st_mode) or not 0 < entry.st_size <= maximum:
                raise ValidationError("provisioning input must be a nonempty bounded regular file")
            with guard.deferred():
                descriptor.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            before = os.fstat(descriptor.number)
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
                raise ValidationError("provisioning input must be a nonempty bounded regular file")
            if (entry.st_dev, entry.st_ino) != (before.st_dev, before.st_ino):
                raise ValidationError("provisioning input changed while being inspected")
            content = bytearray()
            while len(content) <= maximum:
                deadline.check()
                guard.check()
                chunk = os.read(descriptor.number, min(64 * 1024, maximum + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            after = os.fstat(descriptor.number)
            attributes = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if len(content) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in attributes):
                raise ValidationError("provisioning input changed while being inspected")
            result = bytes(content)
    except OSError:
        raise ValidationError("provisioning input could not be read safely") from None
    finally:
        try:
            scope.__exit__(*exc_info())
        finally:
            _finish_profile_evidence(evidence, owns_evidence, exc_info()[1])
    # Only an otherwise normal path reaches acceptance, after EVERY local
    # cleanup/handler obligation. A borrower's pending signal still vetoes bytes.
    deadline.check()
    guard.check()
    return result


def profile_environment(directory: Path) -> dict[str, str]:
    # Deliberately no user HOME, application PATH, runtime injection, keychain,
    # Store/OIDC capability, signing password or profile value in this boundary.
    return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(directory),
            "TMPDIR": str(directory), "LC_ALL": "C", "LANG": "C"}


def _capture_profile(
    directory: Path, deadline: InspectionDeadline, *, cancellation: DefaultCancellation | None = None,
    finality: CaptureFinality | None = None,
) -> bytes:
    """Delegate to the sole process owner; never infer/advance producer finality."""
    from ._profile_process import CaptureFinality, capture_profile

    _require_profile_scratch_available()
    finality = finality if finality is not None else CaptureFinality()
    deadline.check()
    result = capture_profile(directory, deadline, cancellation=cancellation, finality=finality)
    if finality.state != "FINALIZED":
        raise ValidationError("Apple profile worker cleanup could not be confirmed; no upload is authorized")
    deadline.check()
    # The actual owner retains the implicitly borrowed guard too. Never
    # re-resolve a replacement or omit None-borrowed cancellation at this gate.
    if finality._owner is None or finality._owner.cancellation is None:
        raise ValidationError(_PROFILE_SCOPE_ERROR)
    finality._owner.cancellation.check()
    if type(result) is not bytes or not 0 < len(result) <= MAX_PROFILE_BYTES:
        raise ValidationError(AUTHENTICATION_ERROR)
    return result


def authenticate_cms(
    content: bytes, *, deadline: InspectionDeadline, cancellation: DefaultCancellation | None = None,
    _evidence: ProfileCallEvidence | None = None, _evidence_role: str = "OUTER_CMS",
) -> bytes:
    from ._profile_process import CaptureFinality

    evidence, owns_evidence, guard, owns_guard = _profile_entry(_evidence, "authenticate", cancellation)
    finality = CaptureFinality()
    scratch = ScratchLease(finality)
    descriptor = scratch._source

    def cleanup() -> None:
        scope.attempt(_PROFILE_DESCRIPTOR_ERROR, descriptor.close)
        scope.attempt(_PROFILE_SCRATCH_ERROR, scratch.cleanup)

    # Capture borrows this exact guard through source/scratch cleanup. UNKNOWN
    # stays rooted even if the owner raises or the caller discards the exception.
    scope = _ProfileCleanupScope(
        guard, cleanup, owns_cancellation=owns_guard,
        descriptors=(descriptor, scratch._directory_descriptor, scratch._parent_descriptor), scratch=scratch,
        evidence=evidence, evidence_role=_evidence_role, finality=finality,
    )
    try:
        with scope:
            if owns_guard:
                guard.install()
                guard.activate()
            deadline.check()
            guard.check()
            if type(content) is not bytes or not 0 < len(content) <= MAX_PROFILE_BYTES:
                raise ValidationError("provisioning CMS input exceeds its supported bounds")
            if sys.platform != "darwin":
                raise ValidationError("Apple provisioning-profile authentication requires macOS")
            with guard.deferred():
                directory = scratch.acquire()
            deadline.check()
            guard.check()
            with guard.deferred():
                descriptor.open(
                    directory / "cms.der", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                )
            remaining = memoryview(content)
            while remaining:
                deadline.check()
                guard.check()
                chunk = remaining[:64 * 1024]
                count = os.write(descriptor.number, chunk)
                if not 0 < count <= len(chunk):
                    raise ValidationError("Apple profile private input could not be written completely")
                remaining = remaining[count:]
            with guard.deferred():
                descriptor.close()
            deadline.check()
            guard.check()
            result = _capture_profile(directory, deadline, cancellation=guard, finality=finality)
            deadline.check()
            guard.check()
    except OSError:
        raise ValidationError("Apple profile private input could not be prepared safely") from None
    finally:
        try:
            scope.__exit__(*exc_info())
        finally:
            _finish_profile_evidence(evidence, owns_evidence, exc_info()[1])
    # Neither normal with dispatch nor the unconditional backup finally may
    # occur after this final acceptance gate.
    deadline.check()
    guard.check()
    return result


def _no_profile_cleanup() -> None:
    """LOAD/DECODE own local/handler obligations, never an extra process slot."""


def decode_authenticated_profile(
    content: bytes, *, deadline: InspectionDeadline | None = None,
    cancellation: DefaultCancellation | None = None, _evidence: ProfileCallEvidence | None = None,
) -> dict[str, Any]:
    from .ios_der import decode_der_dictionary
    from .ios_entitlements import correlate_profile, load_plist_dictionary

    evidence, owns_evidence, guard, owns_guard = _profile_entry(_evidence, "decode", cancellation)
    deadline = deadline if deadline is not None else InspectionDeadline()
    scope = _ProfileCleanupScope(guard, _no_profile_cleanup, owns_cancellation=owns_guard,
                                 descriptors=(), evidence=evidence, evidence_role="DECODE")
    try:
        with scope:
            if owns_guard:
                guard.install()
                guard.activate()
            deadline.check()
            guard.check()
            evidence._expect("OUTER_CMS")
            outer = load_plist_dictionary(authenticate_cms(
                content, deadline=deadline, cancellation=guard, _evidence=evidence,
                _evidence_role="OUTER_CMS",
            ), deadline=deadline)
            encoded = outer.get("DER-Encoded-Profile")
            if type(encoded) is not bytes or not 0 < len(encoded) <= MAX_PROFILE_BYTES:
                raise ValidationError("modern iOS profile requires its authoritative DER-Encoded-Profile; legacy-only profiles are unsupported")
            evidence._expect("INNER_CMS")
            authoritative = decode_der_dictionary(authenticate_cms(
                encoded, deadline=deadline, cancellation=guard, _evidence=evidence,
                _evidence_role="INNER_CMS",
            ), profile=True, deadline=deadline)
            result = correlate_profile(outer, authoritative, deadline=deadline)
    finally:
        try:
            scope.__exit__(*exc_info())
        finally:
            _finish_profile_evidence(evidence, owns_evidence, exc_info()[1])
    deadline.check()
    guard.check()
    return result


def load_authenticated_profile(
    path: Path, *, deadline: InspectionDeadline | None = None,
    cancellation: DefaultCancellation | None = None, _evidence: ProfileCallEvidence | None = None,
) -> dict[str, Any]:
    evidence, owns_evidence, guard, owns_guard = _profile_entry(_evidence, "load", cancellation)
    deadline = deadline if deadline is not None else InspectionDeadline()
    scope = _ProfileCleanupScope(guard, _no_profile_cleanup, owns_cancellation=owns_guard,
                                 descriptors=(), evidence=evidence, evidence_role="LOAD")
    try:
        with scope:
            if owns_guard:
                guard.install()
                guard.activate()
            deadline.check()
            guard.check()
            evidence._expect("READER")
            content = read_profile_bytes(path, deadline=deadline, cancellation=guard, _evidence=evidence)
            evidence._expect("DECODE")
            result = decode_authenticated_profile(content, deadline=deadline, cancellation=guard, _evidence=evidence)
    finally:
        try:
            scope.__exit__(*exc_info())
        finally:
            _finish_profile_evidence(evidence, owns_evidence, exc_info()[1])
    deadline.check()
    guard.check()
    return result
