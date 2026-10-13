"""One reviewed local project-recovery action over the existing core owner.

No worker takeover, Store/account recovery, process dispatch, TTY/manual bypass,
automatic retry or independent filesystem cleanup implementation exists here.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

from ._desktop_project_recovery_control import ProjectRecoveryInput
from ._desktop_project_recovery_protocol import (
    ProjectRecoveryRequest, PROFILES, ProtocolError, eligible, observation, require, result, validate_terminal,
)
from .build_inputs import (BuildInputBusy, BuildInputError, BuildInputRootChanged, _DesktopRecoveryRefused,
    _desktop_inspect_build_inputs, _desktop_recover_build_inputs)
from .cancellation import DefaultCancellation
from .owned_process import fatal_lifetime_error


class ProjectRecoveryRun:
    def __init__(self, request: ProjectRecoveryRequest, guard: DefaultCancellation,
                 source: ProjectRecoveryInput) -> None:
        require(type(request) is ProjectRecoveryRequest and type(guard) is DefaultCancellation
                and type(source) is ProjectRecoveryInput and source.guard is guard
                and guard._project_recovery_source is source and source.active and source.request_returned
                and threading.current_thread() is threading.main_thread())
        self.request, self.guard, self.source = request, guard, source
        self.primary: BaseException | None = None
        self.effect = "not-attempted"
        self._run_claimed = self._close_claimed = False
        self._candidate: dict | None = None
        self._review_stamp: str | None = None

    def remember(self, error: BaseException) -> None:
        if self.primary is None:
            self.primary = error
        self.source.failure_observed()
        self.guard.lifetime_ledger._remember(error)
        if fatal_lifetime_error(error, "Project recovery original custody did not settle") is not None:
            self.guard._abort(error)
        if self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")

    def run(self) -> None:
        require(not self._run_claimed)
        self._run_claimed = True
        self.guard.check()
        host = "linux" if sys.platform.startswith("linux") else "macos" if sys.platform == "darwin" else None
        require(PROFILES[self.request.native["profile"]][0] == host and os.getcwd() == self.request.native["cwd"])
        selected = self.request.context
        identity = self.request.native["rootIdentity"]
        expected = (int(identity["device"]), int(identity["inode"]), identity["mode"], identity["uid"], identity["gid"])
        root = Path(self.request.native["projectRoot"])
        try:
            if selected["action"] == "inspect":
                self.effect = "inspection"
                inspected = _desktop_inspect_build_inputs(root, expected_root=expected, cancellation=self.guard)
                projected = observation({"status": inspected.status, "session": inspected.session,
                    "roles": list(inspected.roles), "quiescence": inspected.quiescence})
                self._candidate = result(self.request, inspected=projected)
                self._review_stamp = inspected.review_stamp if eligible(projected) else None
            else:
                require(selected["action"] == "recover")
                self.effect = "recovery-attempted"  # Attempt, never an assertion that effects completed.
                recovered = _desktop_recover_build_inputs(root, session=selected["review"]["session"],
                    review_stamp=self.request.native["reviewStamp"], expected_root=expected, cancellation=self.guard)
                require(recovered == {"status": "recovered", "session": selected["review"]["session"]})
                self._candidate = result(self.request, recovered=recovered["session"])
            # The core functions have exited their same original project/control
            # scopes. A later cancellation still vetoes this provisional result.
            self.guard.check()
        except BaseException as error:
            self.remember(error)
            raise

    def close(self) -> None:
        if self._close_claimed:
            return
        self._close_claimed = True
        # Original core scopes alone attempt descriptor cleanup. Never reopen,
        # replay an uncertain close or rerun filesystem recovery here.
        if not self.source.resources_closed():
            error = ProtocolError("Project recovery original resources did not settle")
            self.guard._abort(error)
            raise error

    def terminal(self) -> dict:
        verdict = self.guard.lifetime_ledger.verdict()
        if verdict.commands != 0 or verdict.profile_calls != 0 or verdict.command_dispatched is True:
            self.guard._abort(ProtocolError("Unexpected project recovery lifetime domain"))
            verdict = self.guard.lifetime_ledger.verdict()
        if time.monotonic() >= self.source.work_end:
            self.source.stop("timed-out")
        elif self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")
        resources_closed = self._close_claimed and self.source.resources_closed()
        lifetime = {"complete": verdict.complete, "fatal": verdict.fatal, "contained": verdict.contained,
            "commandDispatched": verdict.command_dispatched, "commands": verdict.commands, "profileCalls": verdict.profile_calls,
            "inputClosed": self.source.closed, "handlersRestored": self.guard.handler_state == "RESTORED",
            "resourcesClosed": resources_closed, "stopObserved": self.source.stop_reason}
        settled = (verdict.cleanup_complete and verdict.contained and verdict.command_dispatched is False
                   and self.source.closed and lifetime["handlersRestored"] and resources_closed)
        candidate, stamp = None, None
        if not settled:
            outcome, reason = "unknown", "cleanup-unknown"
        elif self.source.stop_reason != "none":
            outcome = reason = self.source.stop_reason
        elif isinstance(self.primary, _DesktopRecoveryRefused):
            outcome, reason = "refused", self.primary.reason
        elif isinstance(self.primary, BuildInputRootChanged):
            outcome, reason = "refused", "project-changed"
        elif isinstance(self.primary, BuildInputBusy):
            outcome, reason = "refused", "project-busy"
        elif isinstance(self.primary, BuildInputError):
            outcome, reason = "failed" if self.effect == "recovery-attempted" else "refused", "project-conflict"
        elif self.primary is not None or self._candidate is None:
            outcome, reason = "failed", "recovery-incomplete"
        else:
            outcome, reason = "complete", "none"
            candidate, stamp = self._candidate, self._review_stamp
        value = {"schemaVersion": 1, "context": self.request.context, "outcome": outcome, "reason": reason,
                 "result": candidate, "effect": self.effect, "reviewStamp": stamp, "lifetime": lifetime}
        validate_terminal(value, self.request)
        return value
