"""The one held-input lifecycle for fixed saved-command domains.

Only the exact declared entry types may bind. This is not
a command descriptor, extensible cancellation source or caller callback API.
The child-local endpoints can only tighten the original native T/W/H.
"""
from __future__ import annotations

import math
import os
import select
import stat
import threading
import time
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._desktop_android_build_protocol import AndroidBuildRequest
    from ._desktop_ios_archive_protocol import IOSArchiveRequest
    from ._desktop_preflight_protocol import PreflightRequest
    from ._desktop_project_recovery_protocol import ProjectRecoveryRequest
    from .cancellation import DefaultCancellation


class SavedCommandDomain(Enum):
    GenerateUploadKey = "generate-upload-key"
    ToolAcquisition = "tool-acquisition"
    OfflinePreflight = "offline-preflight"
    AndroidBuild = "android-build"
    ProjectRecovery = "project-recovery"
    IOSArchive = "ios-archive"
    ArtifactInspection = "artifact-inspection"
    GitHubHistory = "github-history"
    GitHubAuth = "github-auth"
    GitRead = "git-read"
    GitLocal = "git-local"
    GitRemote = "git-remote"
    VersionAllocationSource = "version-allocation-source"
    AppleProvisioning = "apple-bundle-provisioning"
    LocalStorePreflight = "local-store-preflight"
    LocalReleaseHistory = "local-release-history"
    LocalStorePrepare = "local-store-prepare"
    LocalStoreExecute = "local-store-execute"
    LocalStoreReconcile = "local-store-reconcile"


def _protocol(domain: SavedCommandDomain):
    # Fixed imports, not a module name, factory or callback supplied by a caller.
    if domain is SavedCommandDomain.GenerateUploadKey:
        from . import _desktop_upload_key_protocol
        return _desktop_upload_key_protocol
    if domain is SavedCommandDomain.ToolAcquisition:
        from . import _desktop_tool_acquisition_protocol
        return _desktop_tool_acquisition_protocol
    if domain is SavedCommandDomain.OfflinePreflight:
        from . import _desktop_preflight_protocol
        return _desktop_preflight_protocol
    if domain is SavedCommandDomain.AndroidBuild:
        from . import _desktop_android_build_protocol
        return _desktop_android_build_protocol
    if domain is SavedCommandDomain.ProjectRecovery:
        from . import _desktop_project_recovery_protocol
        return _desktop_project_recovery_protocol
    if domain is SavedCommandDomain.IOSArchive:
        from . import _desktop_ios_archive_protocol
        return _desktop_ios_archive_protocol
    if domain is SavedCommandDomain.ArtifactInspection:
        from . import _desktop_artifact_inspection_protocol
        return _desktop_artifact_inspection_protocol
    if domain is SavedCommandDomain.GitHubHistory:
        from . import _desktop_github_history_protocol
        return _desktop_github_history_protocol
    if domain is SavedCommandDomain.GitRemote:
        from . import _desktop_git_remote_protocol
        return _desktop_git_remote_protocol
    if domain is SavedCommandDomain.GitLocal:
        from . import _desktop_git_local_protocol
        return _desktop_git_local_protocol
    if domain is SavedCommandDomain.GitRead:
        from . import _desktop_git_read_protocol
        return _desktop_git_read_protocol
    if domain is SavedCommandDomain.GitHubAuth:
        from . import _desktop_github_auth_protocol
        return _desktop_github_auth_protocol
    if domain is SavedCommandDomain.VersionAllocationSource:
        from . import _desktop_version_allocation_source_protocol
        return _desktop_version_allocation_source_protocol
    if domain is SavedCommandDomain.AppleProvisioning:
        from . import _desktop_apple_provisioning_protocol
        return _desktop_apple_provisioning_protocol
    if domain is SavedCommandDomain.LocalStorePreflight:
        from . import _desktop_store_preflight_protocol
        return _desktop_store_preflight_protocol
    if domain is SavedCommandDomain.LocalStoreReconcile:
        from . import _desktop_store_reconcile_protocol
        return _desktop_store_reconcile_protocol
    if domain is SavedCommandDomain.LocalStoreExecute:
        from . import _desktop_store_execute_protocol
        return _desktop_store_execute_protocol
    if domain is SavedCommandDomain.LocalStorePrepare:
        from . import _desktop_store_prepare_protocol
        return _desktop_store_prepare_protocol
    if domain is SavedCommandDomain.LocalReleaseHistory:
        from . import _desktop_local_history_protocol
        return _desktop_local_history_protocol
    raise ValueError("Invalid saved-command domain")


def source_domain(source: object) -> SavedCommandDomain:
    """A subclass/lookalike or changed domain is not an original source."""
    from ._desktop_upload_key_control import UploadKeyInput
    if type(source) is UploadKeyInput and source.domain is SavedCommandDomain.GenerateUploadKey:
        return SavedCommandDomain.GenerateUploadKey
    from ._desktop_tool_acquisition_control import ToolAcquisitionInput
    if type(source) is ToolAcquisitionInput and source.domain is SavedCommandDomain.ToolAcquisition:
        return SavedCommandDomain.ToolAcquisition
    from ._desktop_preflight_control import PreflightInput
    if type(source) is PreflightInput and source.domain is SavedCommandDomain.OfflinePreflight:
        return SavedCommandDomain.OfflinePreflight
    from ._desktop_android_build_control import AndroidBuildInput
    if type(source) is AndroidBuildInput and source.domain is SavedCommandDomain.AndroidBuild:
        return SavedCommandDomain.AndroidBuild
    from ._desktop_project_recovery_control import ProjectRecoveryInput
    if type(source) is ProjectRecoveryInput and source.domain is SavedCommandDomain.ProjectRecovery:
        return SavedCommandDomain.ProjectRecovery
    from ._desktop_ios_archive_control import IOSArchiveInput
    if type(source) is IOSArchiveInput and source.domain is SavedCommandDomain.IOSArchive:
        return SavedCommandDomain.IOSArchive
    from ._desktop_artifact_inspection_control import ArtifactInspectionInput
    if type(source) is ArtifactInspectionInput and source.domain is SavedCommandDomain.ArtifactInspection:
        return SavedCommandDomain.ArtifactInspection
    from ._desktop_github_history_control import HistoryInput
    if type(source) is HistoryInput and source.domain is SavedCommandDomain.GitHubHistory:
        return SavedCommandDomain.GitHubHistory
    from ._desktop_git_remote_control import GitRemoteInput
    from ._desktop_git_push_control import GitPushInput
    if type(source) in (GitRemoteInput, GitPushInput) and source.domain is SavedCommandDomain.GitRemote:
        return SavedCommandDomain.GitRemote
    from ._desktop_git_local_control import GitLocalInput
    if type(source) is GitLocalInput and source.domain is SavedCommandDomain.GitLocal:
        return SavedCommandDomain.GitLocal
    from ._desktop_git_read_control import GitReadInput
    if type(source) is GitReadInput and source.domain is SavedCommandDomain.GitRead:
        return SavedCommandDomain.GitRead
    from ._desktop_github_auth_control import GhAuthInput
    if type(source) is GhAuthInput and source.domain is SavedCommandDomain.GitHubAuth:
        return SavedCommandDomain.GitHubAuth
    from ._desktop_version_allocation_source_control import BorrowedAllocationInput
    if type(source) is BorrowedAllocationInput and source.domain is SavedCommandDomain.VersionAllocationSource:
        return SavedCommandDomain.VersionAllocationSource
    from ._desktop_apple_provisioning_control import AppleProvisioningInput
    if type(source) is AppleProvisioningInput and source.domain is SavedCommandDomain.AppleProvisioning:
        return SavedCommandDomain.AppleProvisioning
    from ._desktop_store_preflight_control import StorePreflightInput
    if type(source) is StorePreflightInput and source.domain is SavedCommandDomain.LocalStorePreflight:
        return SavedCommandDomain.LocalStorePreflight
    from ._desktop_store_reconcile_control import StoreReconcileInput
    if type(source) is StoreReconcileInput and source.domain is SavedCommandDomain.LocalStoreReconcile:
        return SavedCommandDomain.LocalStoreReconcile
    from ._desktop_store_execute_control import StoreExecuteInput
    if type(source) is StoreExecuteInput and source.domain is SavedCommandDomain.LocalStoreExecute:
        return SavedCommandDomain.LocalStoreExecute
    from ._desktop_store_prepare_control import StorePrepareInput
    if type(source) is StorePrepareInput and source.domain is SavedCommandDomain.LocalStorePrepare:
        return SavedCommandDomain.LocalStorePrepare
    from ._desktop_local_history_control import LocalHistoryInput
    if type(source) is LocalHistoryInput and source.domain is SavedCommandDomain.LocalReleaseHistory:
        return SavedCommandDomain.LocalReleaseHistory
    raise ValueError("Invalid original saved-command input")


class _SavedCommandInput:
    def __init__(self, started: float, *, domain: SavedCommandDomain) -> None:
        self._domain = domain
        wire = _protocol(domain)
        wire.require(type(started) in {float, int} and math.isfinite(started) and started >= 0)
        self.pid = os.getpid()
        self.thread = threading.current_thread()
        self.work_end = started + wire.WORK_SECONDS
        self.guard: DefaultCancellation | None = None
        self.fd: int | None = None
        self.identity: tuple[int, int, int] | None = None
        self.acquired = False
        self.close_claimed = False
        self.closed = False
        self.active = False
        self.stop_reason = "none"
        self.custody_unknown = False
        self.buffer = bytearray()
        self.request_returned = False
        self.first_failure: float | None = None

    @property
    def domain(self) -> SavedCommandDomain:
        return self._domain

    def _require(self, condition: bool) -> None:
        _protocol(self.domain).require(condition)

    def _owner(self) -> None:
        source_domain(self)
        self._require(self.pid == os.getpid() and self.thread is threading.current_thread()
                      and self.thread is threading.main_thread())

    def acquire(self) -> None:
        self._owner()
        self._require(not self.acquired and self.fd is None and not self.close_claimed)
        self.fd = 0  # Claim the fixed original standard pipe before inspection.
        value = os.fstat(0)
        self._require(stat.S_ISFIFO(value.st_mode))
        self.identity = (value.st_dev, value.st_ino, value.st_mode)
        os.set_blocking(0, False)
        self.acquired = True

    def bind(self, guard: DefaultCancellation) -> None:
        from .cancellation import DefaultCancellation
        self._owner()
        self._require(type(guard) is DefaultCancellation and self.guard is None and self.acquired)
        guard._check_owner()
        self.guard = guard

    def failure_observed(self) -> None:
        self._owner()
        if self.first_failure is None:
            self.first_failure = time.monotonic()

    def remaining_timeout(self, timeout: int) -> int:
        self._owner()
        self._require(self.domain not in (SavedCommandDomain.ProjectRecovery, SavedCommandDomain.ToolAcquisition, SavedCommandDomain.GitRead, SavedCommandDomain.GitLocal, SavedCommandDomain.GitRemote))
        self._require(self.guard is not None and type(timeout) is int and timeout > 0)
        self.guard.check()
        if self.domain is SavedCommandDomain.OfflinePreflight:
            if self.budget is not None:
                self.budget.checkpoint()
        elif self.domain in (SavedCommandDomain.AndroidBuild, SavedCommandDomain.IOSArchive, SavedCommandDomain.ArtifactInspection, SavedCommandDomain.AppleProvisioning, SavedCommandDomain.LocalStorePreflight, SavedCommandDomain.LocalStorePrepare, SavedCommandDomain.LocalStoreExecute, SavedCommandDomain.LocalStoreReconcile):
            self.require_operation().checkpoint()
        else:
            self._require(False)
        remaining = int(self.work_end - time.monotonic())
        if remaining < 1:
            self.stop("timed-out")
            self.guard.check()
        return min(timeout, remaining)

    def command_limits(self, timeout: int, capture: bool, output_limit: int) -> tuple[int, int]:
        """Clamp only an original domain; no change to C/A/W command ownership."""
        self._require(self.domain not in (SavedCommandDomain.ProjectRecovery, SavedCommandDomain.ToolAcquisition, SavedCommandDomain.GitRead, SavedCommandDomain.GitLocal, SavedCommandDomain.GitRemote))
        timeout = self.remaining_timeout(timeout)
        if self.domain is SavedCommandDomain.OfflinePreflight:
            from ._desktop_preflight_budget import budget_for
            budget = budget_for(self.guard)
            if budget is None:
                raise ValueError("Offline preflight command has no original budget")
            if capture:
                output_limit = budget.capture(output_limit)
            return timeout, output_limit
        if self.domain in (SavedCommandDomain.ArtifactInspection, SavedCommandDomain.AppleProvisioning, SavedCommandDomain.LocalStorePreflight, SavedCommandDomain.LocalStorePrepare, SavedCommandDomain.LocalStoreExecute, SavedCommandDomain.LocalStoreReconcile):
            # The exact operation admits only its fixed inspector role before
            # this existing run_owned callback. No caller role/argv is authority.
            self._require(type(capture) is bool and type(output_limit) is int and output_limit > 0)
            return self.require_operation().command_limits(timeout, capture, output_limit)
        self._require(self.domain in (SavedCommandDomain.AndroidBuild, SavedCommandDomain.IOSArchive)
                      and type(capture) is bool and type(output_limit) is int and output_limit > 0)
        operation = self.require_operation()
        # Independently affirm the exact domain's closed roles. Neither domain
        # lends its role set or budget to a caller-supplied command descriptor.
        role = operation._pending
        if self.domain is SavedCommandDomain.AndroidBuild:
            maxima = {"keytool-input": 30, "gradle": 2700, "aab-sign": 120, "bundletool": 60, "jarsigner": 120, "keytool": 30}
            self._require(role in maxima and capture is (role != "gradle"))
        elif self.domain is SavedCommandDomain.IOSArchive:
            maxima = {"xcode-version": 30, "ios-sdk": 30, "prepare": 600, "archive": 3600}
            self._require(role in maxima and capture is (role in {"xcode-version", "ios-sdk"}))
        else:
            self._require(False)
        selected = operation.command_limits(timeout, capture, output_limit)
        self._require(type(selected) is tuple and len(selected) == 2
                      and type(selected[0]) is int and 0 < selected[0] <= min(timeout, maxima[role])
                      and type(selected[1]) is int and 0 < selected[1] <= output_limit
                      and (not capture or selected[1] <= 2 * 1024 * 1024))
        return selected

    def stop(self, reason: str = "cancelled") -> None:
        self._owner()
        self._require(type(reason) is str and reason in {"cancelled", "timed-out"})
        self.failure_observed()
        if self.stop_reason == "none":
            self.stop_reason = reason
        if self.guard is not None:
            self.guard.cancelled = True

    def poll(self, guard: DefaultCancellation) -> None:
        self._owner()
        self._require(guard is self.guard)
        if self.stop_reason != "none" or self.close_claimed:
            if self.stop_reason != "none":
                guard.cancelled = True
            return
        if time.monotonic() >= self.work_end:
            self.stop("timed-out")
            return
        material_phase = self.domain in (SavedCommandDomain.GenerateUploadKey, SavedCommandDomain.AndroidBuild, SavedCommandDomain.IOSArchive, SavedCommandDomain.AppleProvisioning, SavedCommandDomain.LocalStorePreflight, SavedCommandDomain.LocalReleaseHistory, SavedCommandDomain.LocalStorePrepare, SavedCommandDomain.LocalStoreExecute, SavedCommandDomain.LocalStoreReconcile) and self.material_pending
        active = self.active and not material_phase
        if active and self.buffer:
            self.stop()
            return
        try:
            self._require(self.fd is not None)
            value = os.fstat(self.fd)
            if (value.st_dev, value.st_ino, value.st_mode) != self.identity:
                self.custody_unknown = True
                message = {SavedCommandDomain.GenerateUploadKey: "Original upload-key input changed",
                           SavedCommandDomain.ToolAcquisition: "Original tool preparation input changed",
                           SavedCommandDomain.OfflinePreflight: "Original preflight input changed",
                           SavedCommandDomain.AndroidBuild: "Original Android build input changed",
                           SavedCommandDomain.ProjectRecovery: "Original project recovery input changed",
                           SavedCommandDomain.IOSArchive: "Original saved build input changed",
                           SavedCommandDomain.ArtifactInspection: "Original artifact inspection input changed",
                           SavedCommandDomain.GitHubHistory: "Original History input changed",
                           SavedCommandDomain.GitHubAuth: "Original gh-auth input changed",
                           SavedCommandDomain.GitRead: "Original Git read input changed",
                           SavedCommandDomain.GitLocal: "Original local Git input changed",
                           SavedCommandDomain.GitRemote: "Original private Git input changed",
                           SavedCommandDomain.AppleProvisioning: "Original Bundle-ID provisioning input changed",
                           SavedCommandDomain.LocalStorePreflight: "Original Store access-check input changed",
                           SavedCommandDomain.LocalStorePrepare: "Original Store preparation input changed",
                           SavedCommandDomain.LocalStoreExecute: "Original Store execution input changed",
                           SavedCommandDomain.LocalStoreReconcile: "Original Store reconciliation input changed",
                           SavedCommandDomain.LocalReleaseHistory: "Original local history input changed"}[self.domain]
                raise _protocol(self.domain).ProtocolError(message)
            if material_phase and (not self.material_receiving or self.buffer):
                # The original bounded private reader drains this buffer before
                # another read. A large body is not a large public JSON frame.
                return
            limit = 1 if active else min(64 * 1024, _protocol(self.domain).REQUEST_LIMIT + 1 - len(self.buffer))
            if material_phase and self.domain in (SavedCommandDomain.GenerateUploadKey,SavedCommandDomain.AppleProvisioning,SavedCommandDomain.LocalStorePrepare,SavedCommandDomain.LocalStoreExecute, SavedCommandDomain.LocalStoreReconcile) and self.reading:
                self._require(type(self.read_remaining) is int and 1<=self.read_remaining<=2048)
                limit=min(limit,self.read_remaining)
            if material_phase and self.domain in (SavedCommandDomain.AndroidBuild, SavedCommandDomain.IOSArchive):
                candidate=getattr(self,"candidate_input",None)
                if candidate is not None and candidate.reading:
                    from ._desktop_candidate_input_control import CandidateCreateInput
                    self._require(type(candidate) is CandidateCreateInput and candidate.source is self
                                  and type(candidate.read_remaining) is int and 1<=candidate.read_remaining<=2048)
                    limit=min(limit,candidate.read_remaining)
            self._require(limit > 0)
            try:
                chunk = os.read(self.fd, limit)
            except BlockingIOError:
                return
            if not chunk or active:
                self.stop()
                return
            self.buffer.extend(chunk)
            if len(self.buffer) > _protocol(self.domain).REQUEST_LIMIT:
                self.stop()
        except BaseException as error:
            # A read/identity failure is not successful EOF or finality. Keep
            # it on the actual guard even if closing another resource works.
            self.stop()
            guard._abort(error)

    def request(self) -> PreflightRequest | AndroidBuildRequest | ProjectRecoveryRequest | IOSArchiveRequest:
        self._owner()
        self._require(self.guard is not None and not self.active and not self.request_returned)
        while True:
            self.guard.check()
            position = self.buffer.find(b"\n")
            if position >= 0:
                raw = bytes(self.buffer[:position + 1])
                del self.buffer[:position + 1]
                if self.domain in (SavedCommandDomain.AndroidBuild, SavedCommandDomain.IOSArchive, SavedCommandDomain.AppleProvisioning, SavedCommandDomain.LocalStorePreflight):
                    request = _protocol(self.domain).parse_request(raw)
                    self._request_material(request)
                self.active = True  # Signed pending input remains inert until account/project admission.
                self.guard.check()
                if self.domain not in (SavedCommandDomain.AndroidBuild, SavedCommandDomain.IOSArchive, SavedCommandDomain.AppleProvisioning, SavedCommandDomain.LocalStorePreflight):
                    request = _protocol(self.domain).parse_request(raw)
                self.request_returned = True
                return request
            self._require(self.fd is not None)
            try:
                select.select([self.fd], [], [], 0.05)
            except (OSError, ValueError) as error:
                self.stop()
                self.guard._abort(error)

    def close(self) -> None:
        self._owner()
        if self.close_claimed:
            self._require(self.closed)
            return
        self.close_claimed = True
        number, self.fd = self.fd, None
        try:
            self._require(not self.custody_unknown)
            if number is not None:
                value = os.fstat(number)
                # A pre-acquisition error has no validated original identity;
                # do not manufacture permission to close a possibly reused FD.
                self._require(self.identity is not None
                              and (value.st_dev, value.st_ino, value.st_mode) == self.identity)
                os.close(number)  # Retired before the sole possibly consuming call.
            self.closed = True
            if self.guard is not None:
                self.guard._remove_saved_command_source(self)
        except BaseException as error:
            self.failure_observed()
            if self.guard is not None:
                self.guard._abort(error)
            raise
