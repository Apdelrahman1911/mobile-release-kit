"""Saved local Android build/inspection using the existing core, never a CLI.

Only the original operation can supply inputs, tools and captured bytes. The
service emits bounded observation DATA after its actual cleanup. Native runtime,
process/transport and document finality still have to settle before UI success.
Explicit assigned signing uses the same core materializer and validation policy.
No Store call or release publication occurs.
"""
from __future__ import annotations

import os
import sys
import threading
import time

from ._desktop_android_build_control import AndroidBuildInput
from ._desktop_android_build_files import AndroidFileError
from ._desktop_android_build_protocol import (
    AndroidBuildRequest, PROFILES, ProtocolError, REASONS, project_activity,
    project_artifact, project_result, require, validate_terminal,
)
from ._desktop_android_build_selection import AndroidSelectionRefused
from .android import run_android_build, validate_aab
from .android_build_operation import AndroidBuildError, AndroidBuildOperation
from .android_build_tools import AndroidToolError
from .build_inputs import BuildInputError, invocation_custody
from .cancellation import DefaultCancellation
from .credentials import materialize_build_inputs, validate_signing_material
from .owned_process import ProcessError, fatal_lifetime_error
from .provenance import (
    AndroidAbiObservation, ArtifactObservation, android_abis_from_zip_metadata,
    artifact_records_from_observations,
)
from .reporting import Report


class AndroidBuildRun:
    def __init__(self, request: AndroidBuildRequest, guard: DefaultCancellation,
                 source: AndroidBuildInput) -> None:
        require(type(request) is AndroidBuildRequest and type(guard) is DefaultCancellation
                and type(source) is AndroidBuildInput and source.guard is guard
                and guard._android_build_source is source and source.active and source.request_returned
                and threading.current_thread() is threading.main_thread())
        self.request, self.guard, self.source = request, guard, source
        self.primary: BaseException | None = None
        self.report: Report | None = None
        self._candidate: dict | None = None
        self._run_claimed = self._close_claimed = False
        # This constructor roots itself in source before any child owner can
        # fail construction. The engine has a fixed original-operation fallback
        # if this service constructor does not return.
        self.operation = AndroidBuildOperation(request, guard, source)

    def remember(self, error: BaseException) -> None:
        if self.primary is None:
            self.primary = error
        self.source.failure_observed()
        self.guard.lifetime_ledger._remember(error)
        if fatal_lifetime_error(error, "Android build original custody did not settle") is not None:
            self.guard._abort(error)
        if self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")

    def _build(self, bound, invocation) -> None:
        operation, signing = self.operation, self.operation.signing
        if signing is None:
            operation.advance("building")
            run_android_build(bound.config, signed=False, cancellation=self.guard, operation=operation)
            return
        self.source.receive_material(operation)
        signing.bind_values()
        operation.advance("validating-signing")
        findings = validate_signing_material(bound.config, values=signing.values, platforms=("android",),
                                            cancellation=self.guard, android_operation=operation)
        if not signing.validation_passed:
            self.report = Report("android-build-inspect", findings=findings)
            operation.fail("signing-invalid")
        operation.advance("materializing-signing")
        with invocation.materialization(signing_lease=None) as child:
            try:
                with materialize_build_inputs(bound.config, values=signing.values, platforms=("android",),
                                              signing_lease=None, cancellation=self.guard, build_inputs=child) as materialized:
                    signing.bind_materialized(materialized)
                    operation.advance("building")
                    run_android_build(bound.config, signed=True, cancellation=self.guard,
                                      operation=operation, build_inputs=child)
                    operation.advance("restoring-signing")
            except BaseException as error:
                # Record the incoming failure before the journal can restore,
                # retain a conflict, or fail its own independent cleanup.
                self.remember(error)
                raise
        require(signing.inputs_closed())

    def run(self) -> None:
        require(not self._run_claimed)
        self._run_claimed = True
        self.guard.check()
        host = "linux" if sys.platform == "linux" else "macos" if sys.platform == "darwin" else None
        require(PROFILES[self.request.native["profile"]][0] == host
                and os.getcwd() == self.request.native["cwd"])
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
                        # Shared core owns the task invocation and capture.
                        # Its diagnostic returned Path map is deliberately unused.
                        self._build(bound, invocation)
                        operation.advance("inspecting")
                        artifact = operation.artifact()
                        findings = validate_aab(
                            artifact.path, expected_application_id=bound.saved.configuration.application_id,
                            release=bound.release, expected_fingerprint=(bound.saved.configuration.upload_certificate_sha256
                                                                        if bound.check_signer else None),
                            require_tools=True, check_signer=bound.check_signer, cancellation=self.guard, artifact=artifact,
                            tools=operation.tools,
                        )
                        self.report = Report("android-build-inspect", findings=findings)
                        operation.check_inputs()
                        operation.tools.check()
                        abi = (AndroidAbiObservation((), False) if operation.zip_metadata is None
                               else android_abis_from_zip_metadata(operation.zip_metadata,
                                                                   checkpoint=artifact.check))
                        artifact.verify_bytes()
                        records = artifact_records_from_observations((ArtifactObservation(
                            artifact.logical_name, artifact.file_name, artifact.size, artifact.sha256,
                            abi.architectures,
                        ),))
                        observed = project_artifact(records[0], unknown_abi=abi.unknown_abi)
                        used_config, used_version = operation.used_inputs()
                        operation.advance("disposing-work")
                        operation.finish_work()
                        # Final publication DATA still refers to these same
                        # retained originals, not reopened normalized filenames.
                        artifact.verify_bytes()
                        operation.check_inputs()
                        operation.tools.check()
                        try:
                            self._candidate = project_result(
                                project_activity(self.report, stage=operation.stage,
                                                 selection=operation.selection(), command=operation.command_outcome(),
                                                 signing=operation.signing_activity()),
                                observed, used_config=used_config, used_version=used_version,
                                validation=self.request.context["artifactValidation"],
                                toolchain_profile=self.request.native["toolchain"]["profile"],
                            )
                        except (ProtocolError, ValueError, TypeError, RecursionError) as error:
                            # Bounded DATA projection is not a successful build
                            # result. Preserve a hidden original lifetime failure
                            # rather than relabel it as a representation limit.
                            if fatal_lifetime_error(error, "Android result custody did not settle") is not None:
                                raise
                            raise AndroidBuildError("result-limit") from None
                        operation.checkpoint()
                    except BaseException as error:
                        # F and the original primary precede potentially blocking
                        # independent work/artifact/tool/namespace closes.
                        self.remember(error)
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

    def _failure(self, command: dict) -> tuple[str, str]:
        error = self.primary
        if isinstance(error, (AndroidSelectionRefused, AndroidBuildError, AndroidToolError, AndroidFileError)):
            reason = error.reason
        elif isinstance(error, BuildInputError):
            reason = "project-admission-refused"
        elif isinstance(error, ProcessError):
            if self.operation.command_failure_role in {"keytool-validate", "jarsigner-sign"}:
                reason = "signing-incomplete"
            else:
                reason = ("command-incomplete" if command["outcome"] != "exited" else
                          "command-failed" if command["exitCode"] != 0 else "toolchain-unavailable")
        elif isinstance(error, KeyboardInterrupt):
            reason = self.source.stop_reason if self.source.stop_reason != "none" else "protocol-error"
        elif error is not None:
            reason = "protocol-error"
        elif self.source.stop_reason != "none":
            reason = self.source.stop_reason
        elif self._candidate is None:
            reason = "command-incomplete" if command["outcome"] != "exited" else "protocol-error"
        else:
            return "complete", "none"
        require(reason in REASONS and reason not in {"none", "cleanup-unknown"})
        if reason in {"cancelled", "timed-out"}:
            return reason, reason
        if (command["outcome"] == "not-dispatched" and self.guard.lifetime_ledger.verdict().command_dispatched is False
                and reason not in {"command-incomplete", "work-retained", "signing-incomplete"}):
            return "refused", reason
        return "failed", reason

    def terminal(self) -> dict:
        operation = self.operation
        operation.owner()
        verdict = self.guard.lifetime_ledger.verdict()
        maximum_commands = (6 if operation.signing is not None else
                            4 if self.request.context["artifactValidation"]["mode"] == "upload-signature" else 2)
        if verdict.profile_calls != 0 or verdict.commands > maximum_commands:
            self.guard._abort(ProtocolError("Unexpected Android build lifetime domain"))
            verdict = self.guard.lifetime_ledger.verdict()
        if time.monotonic() >= self.source.work_end:
            self.source.stop("timed-out")
        elif self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")
        files, tools = operation.files, operation.tools
        lifetime = {
            "complete": verdict.complete, "fatal": verdict.fatal, "contained": verdict.contained,
            "commandDispatched": verdict.command_dispatched, "commands": verdict.commands,
            "profileCalls": verdict.profile_calls, "inputClosed": self.source.closed,
            "handlersRestored": self.guard.handler_state == "RESTORED",
            "invocationClosed": operation.closed(),
            "artifactsClosed": files is None or files.closed(),
            "toolsClosed": tools is None or tools.closed(),
            "namespaceClosed": files is None or files.namespace is None or files.namespace.closed(),
            "signingInputsClosed": operation.signing is None or operation.signing.inputs_closed(),
            "materialRetired": self.source.material_closed(),
            "stopObserved": self.source.stop_reason,
        }
        command, disposition = operation.command_outcome(), operation.disposition()
        try:
            activity = project_activity(self.report, stage=operation.stage,
                                        selection=operation.selection(), command=command,
                                        signing=operation.signing_activity())
        except (ProtocolError, ValueError, TypeError, RecursionError):
            self.remember(AndroidBuildError("result-limit"))
            activity = project_activity(None, stage=operation.stage,
                                        selection=operation.selection(), command=command,
                                        signing=operation.signing_activity())
        settled = (verdict.cleanup_complete and verdict.contained and verdict.command_dispatched is not None
                   and all(lifetime[key] for key in ("inputClosed", "handlersRestored", "invocationClosed",
                                                    "artifactsClosed", "toolsClosed", "namespaceClosed",
                                                    "signingInputsClosed", "materialRetired"))
                   and "unknown" not in disposition.values())
        result = None
        if not settled:
            outcome, reason = "unknown", "cleanup-unknown"
        else:
            outcome, reason = self._failure(command)
            if disposition["work"] == "retained-work":
                # Preserve an earlier primary alongside retained-work facts,
                # but never call a cancelled/refused run's leftover work clean.
                outcome = "failed"
                if reason == "none":
                    reason = "work-retained"
            if outcome == "complete":
                require(self._candidate is not None and disposition == {
                    "work": "removed", "artifacts": "retained-incomplete"})
                result = self._candidate
                disposition = {"work": "removed", "artifacts": "retained-local-result"}
        terminal = {"schemaVersion": 1, "context": self.request.context,
                    "outcome": outcome, "reason": reason, "activity": activity,
                    "disposition": disposition, "result": result, "lifetime": lifetime}
        validate_terminal(terminal, self.request)
        return terminal
