"""One original saved-input Android offline invocation of shared core policy.

Configured project checks are trusted arbitrary project code, not sandboxed
read-only observations. This fixed service asks for no core build, credentials,
signing, artifact validation or Store work. It is not the public CLI wrapper.
"""
from __future__ import annotations

import hashlib
import os
import sys
import threading
import time
from pathlib import Path

from ._desktop_preflight_budget import OfflinePreflightBudget, PreflightBudgetError
from ._desktop_preflight_control import PreflightInput
from ._desktop_preflight_protocol import PreflightRequest, PROFILES, ProtocolError, project_result, require
from .api._snapshot import _ReadProblem
from .build_inputs import BuildInputError, invocation_custody
from .cancellation import DefaultCancellation
from .config import MAX_CONFIG_BYTES, ReleaseConfig, parse_config_text
from .errors import ConfigurationError
from .metadata import check_metadata_text
from .owned_process import fatal_lifetime_error
from .preflight import _preflight


class _Refused(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__("Saved offline preflight input was refused")


class OfflinePreflightRun:
    def __init__(self, request: PreflightRequest, guard: DefaultCancellation, source: PreflightInput) -> None:
        require(type(request) is PreflightRequest and type(guard) is DefaultCancellation
                and type(source) is PreflightInput and source.guard is guard and guard._preflight_source is source
                and source.active and source.request_returned and threading.current_thread() is threading.main_thread())
        self.request, self.guard, self.source = request, guard, source
        self.root = Path(request.native["projectRoot"])
        self.budget = OfflinePreflightBudget(self.root, guard, source)
        self.invocation_attempted = False
        self.report = None
        self.primary: BaseException | None = None

    def remember(self, error: BaseException) -> None:
        if self.primary is None:
            self.primary = error
        self.source.failure_observed()
        self.guard.lifetime_ledger._remember(error)
        if fatal_lifetime_error(error, "Offline preflight command custody did not settle") is not None:
            self.guard._abort(error)
        if self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")

    def _saved(self) -> ReleaseConfig:
        try:
            raw = self.budget.read(self.root / "release/mobile-release.json", limit=MAX_CONFIG_BYTES, binary=True)
        except _ReadProblem as error:
            raise _Refused({"snapshot.file-size": "saved-config-too-large", "snapshot.changed": "saved-config-changed",
                            "snapshot.encoding": "saved-config-invalid"}.get(error.code, "saved-config-unsafe")) from None
        except OSError:
            raise _Refused("saved-config-unsafe") from None
        if raw is None:
            raise _Refused("saved-config-missing")
        if not raw or {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} != self.request.context["savedConfig"]:
            raise _Refused("saved-config-changed")
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            raise _Refused("saved-config-invalid") from None
        if any(code == "metadata.secret-pattern" for code, _ in check_metadata_text("saved-preflight", text).issues):
            raise _Refused("saved-config-sensitive")
        try:
            data = parse_config_text(text)
        except (ConfigurationError, ValueError, TypeError, UnicodeError, RecursionError):
            raise _Refused("saved-config-invalid") from None
        if not data.get("android", {}).get("enabled", False):
            raise _Refused("platform-disabled")
        self.budget.retain(data)
        # This private parsed copy, never the renderer draft, remains the fixed
        # selection for the invocation. Other project sources are still live.
        return ReleaseConfig(path=self.root / "release/mobile-release.json", root=self.root,
                             data=data, _preflight_budget=self.budget)

    def run(self) -> None:
        self.guard.check()
        host = "linux" if sys.platform == "linux" else "macos" if sys.platform == "darwin" else None
        require(PROFILES[self.request.native["profile"]][0] == host and os.getcwd() == self.request.native["cwd"])
        self.invocation_attempted = True
        with invocation_custody(self.root, mode="build", cancellation=self.guard) as invocation:
            try:
                require(self.budget.invocation is invocation)
                with invocation.project(signing_lease=None):
                    try:
                        _, identity = invocation._offline_preflight_root(self.guard)
                        if identity != self.request.native["rootIdentity"]:
                            raise _Refused("saved-config-changed")
                        config = self._saved()
                        self.budget.checkpoint()
                        self.report = _preflight(config, mode="offline", platforms=("android",), run_builds=False,
                            artifacts=None, credentials_file=None, credentials_from_env=False, require_tools=False,
                            signing_lease=None, invocation=invocation)
                        self.budget.checkpoint()
                    except BaseException as error:
                        # F precedes potentially blocking cleanup. A later close
                        # failure must not replace this primary lifecycle fact.
                        self.remember(error)
                        raise
                    finally:
                        try:
                            # Original reader/iterator records settle before
                            # releasing the original admitted project.
                            self.budget.close()
                        except BaseException as error:
                            self.remember(error)
                            raise
            except BaseException as error:
                self.remember(error)
                raise

    def close(self) -> None:
        self.budget.close()

    def terminal(self) -> dict:
        verdict = self.guard.lifetime_ledger.verdict()
        if verdict.profile_calls != 0:
            self.guard._abort(ProtocolError("Unexpected offline preflight lifetime domain"))
            verdict = self.guard.lifetime_ledger.verdict()
        if time.monotonic() >= self.source.work_end:
            self.source.stop("timed-out")
        elif self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")
        invocation = self.budget.invocation
        invocation_closed = (not self.invocation_attempted if invocation is None
                             else invocation._offline_preflight_closed(self.guard)) and self.budget.closed
        lifetime = {"complete": verdict.complete, "fatal": verdict.fatal, "contained": verdict.contained,
            "commandDispatched": verdict.command_dispatched, "commands": verdict.commands, "profileCalls": verdict.profile_calls,
            "inputClosed": self.source.closed, "handlersRestored": self.guard.handler_state == "RESTORED",
            "invocationClosed": invocation_closed, "stopObserved": self.source.stop_reason}
        settled = (verdict.cleanup_complete and verdict.contained and verdict.command_dispatched is not None
                   and self.source.closed and lifetime["handlersRestored"] and invocation_closed)
        result = None
        if not settled:
            outcome, reason = "unknown", "cleanup-unknown"
        elif isinstance(self.primary, PreflightBudgetError):
            outcome, reason = "failed", self.primary.reason
        elif self.source.stop_reason != "none":
            outcome = reason = self.source.stop_reason
        elif isinstance(self.primary, _Refused):
            outcome, reason = "refused", self.primary.reason
        elif isinstance(self.primary, BuildInputError):
            outcome, reason = "refused", "project-admission-refused"
        elif self.primary is not None or self.report is None:
            outcome, reason = "failed", "command-incomplete"
        else:
            outcome, reason = "complete", "none"
            try:
                result = project_result(self.report, self.request.context["savedConfig"])
            except (ProtocolError, ValueError, TypeError, RecursionError):
                self.source.failure_observed()
                outcome, reason = "failed", "result-limit"
        return {"schemaVersion": 1, "context": self.request.context, "outcome": outcome,
                "reason": reason, "result": result, "lifetime": lifetime}
