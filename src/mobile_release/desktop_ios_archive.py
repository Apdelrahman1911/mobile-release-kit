"""Saved unsigned iOS archive + shared structural validation, never a CLI."""
from __future__ import annotations

import hashlib
import os
import sys
import time

from ._desktop_ios_archive_control import IOSArchiveInput
from ._desktop_ios_archive_protocol import (
    CLOSE_FIELDS, IOSArchiveRequest, LIMITATIONS, ProtocolError, SCOPE, require, validate_terminal,
)
from ._desktop_ios_archive_selection import IOSSelectionRefused
from .build_inputs import BuildInputError, invocation_custody
from .cancellation import DefaultCancellation
from .ios import run_ios_build, validate_xcarchive
from .ios_archive_operation import IOSArchiveError, IOSArchiveOperation
from .owned_process import ProcessError, fatal_lifetime_error
from .reporting import FAILING_STATUSES


class IOSArchiveRun:
    def __init__(self, request: IOSArchiveRequest, guard: DefaultCancellation, source: IOSArchiveInput) -> None:
        require(type(request) is IOSArchiveRequest and type(guard) is DefaultCancellation
                and type(source) is IOSArchiveInput and source.guard is guard
                and guard._ios_archive_source is source)
        self.request, self.guard, self.source = request, guard, source
        self.primary = None
        self._candidate = None
        self.findings = []
        self._run_claimed = self._close_claimed = False
        self.operation = IOSArchiveOperation(request, guard, source)

    def remember(self, error: BaseException) -> None:
        if self.primary is None:
            self.primary = error
        self.operation.remember(error)
        if self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")

    def run(self) -> None:
        require(not self._run_claimed)
        self._run_claimed = True
        self.guard.check()
        require(sys.platform == "darwin" and os.getcwd() == self.request.native["cwd"])
        operation = self.operation
        operation.invocation_attempted = True
        with invocation_custody(operation.root, mode="build", cancellation=self.guard) as invocation:
            try:
                require(operation.invocation is invocation)
                with invocation.project(signing_lease=None):
                    try:
                        bound = operation.bind_inputs()
                        operation.advance("inputs-bound")
                        operation.prepare()
                        run_ios_build(bound.config, signed=False, cancellation=self.guard, operation=operation)
                        operation.advance("inspecting")
                        artifact = operation.artifact()
                        self.findings = validate_xcarchive(artifact.path,
                            expected_bundle_id=bound.saved.configuration.bundle_id, release=bound.saved.release,
                            symbols_policy=bound.saved.configuration.symbols_policy,
                            cancellation=self.guard, operation=operation)
                        if any(finding.status in FAILING_STATUSES for finding in self.findings):
                            operation.fail("archive-validation-failed")
                        operation.check_inputs()
                        operation.files.check_tools()
                        artifact.check()
                        require(artifact.inventory is not None and operation.snapshot_closed())
                        operation.advance("disposing-work")
                        operation.files.finish_work()
                        operation.check_inputs()
                        operation.files.check_tools()
                        artifact.check()
                        require(operation.files.work_disposition() == "removed"
                                and operation.files.names(operation.files.namespace.fd) == {"archive.xcarchive"})
                        size = sum(entry.size for entry in artifact.inventory.values() if entry is not None)
                        self._candidate = {"schemaVersion": 1, "scope": SCOPE,
                            "usedConfig": {"bytes": len(bound.saved.configuration.raw),
                                "sha256": hashlib.sha256(bound.saved.configuration.raw).hexdigest()},
                            "usedVersion": {"source": bound.saved.configuration.source,
                                "bytes": len(bound.saved.version_raw),
                                "sha256": hashlib.sha256(bound.saved.version_raw).hexdigest(),
                                "name": bound.saved.release.name, "build": bound.saved.release.build},
                            "archive": f".mobile-release/desktop-ios-archive/{operation.operation_id}/archive.xcarchive",
                            "entries": len(artifact.inventory), "bytes": size, "limitations": list(LIMITATIONS)}
                        operation.checkpoint()
                    except BaseException as error:
                        self.remember(error)  # First failure before independent closes.
                        raise
                    finally:
                        try:
                            self.close()
                        except BaseException as error:
                            self.remember(error)
                            raise
            except BaseException as error:
                self.remember(error)
                raise

    def close(self) -> None:
        if self._close_claimed:
            return
        self._close_claimed = True
        self.operation.close()

    def _failure(self, dispatched) -> tuple[str, str]:
        error = self.primary
        if self.source.stop_reason != "none":
            return self.source.stop_reason, self.source.stop_reason
        if isinstance(error, (IOSSelectionRefused, IOSArchiveError)):
            reason = error.reason
        elif isinstance(error, BuildInputError):
            reason = "project-admission-refused"
        elif isinstance(error, ProcessError):
            reason = "command-incomplete"
        elif error is not None or self._candidate is None:
            reason = "protocol-error"
        else:
            return "complete", "none"
        return ("refused" if dispatched is False else "failed"), reason

    def terminal(self) -> dict:
        operation = self.operation
        operation.owner()
        if time.monotonic() >= self.source.work_end:
            self.source.stop("timed-out")
        elif self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")
        verdict = self.guard.lifetime_ledger.verdict()
        if verdict.profile_calls != 0 or verdict.commands > 4:
            self.guard._abort(ProtocolError("Unexpected iOS archive command domain"))
            verdict = self.guard.lifetime_ledger.verdict()
        files = operation.files
        commands_settled = operation.commands_settled()
        dispatched = operation.command_dispatch()
        lifetime = {"complete": verdict.complete and commands_settled, "fatal": verdict.fatal, "contained": verdict.contained,
            "commandDispatched": dispatched, "commands": verdict.commands,
            "profileCalls": verdict.profile_calls, "inputClosed": self.source.closed,
            "handlersRestored": self.guard.handler_state == "RESTORED", "invocationClosed": operation.closed(),
            "snapshotClosed": operation.snapshot_closed(), "filesClosed": files is None or files.closed(),
            "namespaceClosed": files is None or files.namespace is None or files.namespace.closed(),
            "stopObserved": self.source.stop_reason}
        disposition = operation.disposition()
        settled = (verdict.cleanup_complete and verdict.contained and commands_settled and dispatched is not None
                   and all(lifetime[key] for key in CLOSE_FIELDS) and "unknown" not in disposition.values())
        outcome, reason = self._failure(dispatched) if settled else ("unknown", "cleanup-unknown")
        result = None
        if outcome == "complete":
            require(self._candidate is not None and disposition["output"] == "retained-incomplete"
                    and disposition["snapshot"] == disposition["work"] == "removed")
            disposition = {**disposition, "output": "retained-local-result"}
            result = self._candidate
        checks = {"ios.archive.identity": "archive-identity", "ios.archive.dsym": "archive-dsym",
                  "ios.archive.structure": "archive-structure"}
        rows = [{"check": checks.get(finding.code, "other-core-finding"), "status": finding.status.value}
                for finding in self.findings]
        value = {"schemaVersion": 1, "context": self.request.context, "outcome": outcome, "reason": reason,
            "activity": {"stage": operation.stage, "selection": operation.selection(),
                         "commands": operation.command_outcomes(), "findings": rows},
            "disposition": disposition, "result": result, "lifetime": lifetime}
        validate_terminal(value, self.request)
        return value
