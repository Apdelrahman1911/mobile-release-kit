"""Owned iOS archive/export/validation and exact local recovery, never a CLI."""
from __future__ import annotations

import hashlib
import os
import sys
import time
from contextlib import nullcontext

from ._desktop_ios_archive_control import IOSArchiveInput
from ._desktop_ios_archive_protocol import (
    CLOSE_FIELDS, IOSArchiveRequest, LIMITATIONS, ProtocolError, SCOPE, SIGNED_LIMITATIONS, SIGNED_SCOPE,
    SIGNED_COMMAND_LIMIT, SIGNED_PROFILE_LIMIT, require, validate_terminal,
)
from ._desktop_ios_archive_selection import IOSSelectionRefused
from .build_inputs import BuildInputError, invocation_custody
from .cancellation import DefaultCancellation
from .errors import CredentialError, ValidationError
from .ios import run_ios_build, validate_xcarchive
from .ios_archive_operation import IOSArchiveError, IOSArchiveOperation
from .owned_process import ProcessError, fatal_lifetime_error
from .reporting import FAILING_STATUSES, Finding, Status


class IOSArchiveRun:
    def __init__(self, request: IOSArchiveRequest, guard: DefaultCancellation, source: IOSArchiveInput) -> None:
        require(type(request) is IOSArchiveRequest and type(guard) is DefaultCancellation
                and type(source) is IOSArchiveInput and source.guard is guard
                and guard._ios_archive_source is source)
        self.request, self.guard, self.source = request, guard, source
        self.primary = None
        self._candidate = None
        self.findings = []
        self.pairing = None
        self.recovery_report = None
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
        if self.source.recovery:
            self._recovery_run()
            return
        with invocation_custody(operation.root, mode="build", cancellation=self.guard) as invocation:
            try:
                require(operation.invocation is invocation)
                from .local_signing import local_signing_lease
                lease_context = nullcontext(None) if operation.signing is None else local_signing_lease(cancellation=self.guard)
                with lease_context as lease, invocation.project(signing_lease=lease):
                    try:
                        if operation.signing is not None:
                            self.source.receive_material(operation)
                        bound = operation.bind_inputs()
                        operation.advance("inputs-bound")
                        operation.prepare()
                        if operation.signing is None:
                            run_ios_build(bound.config, signed=False, cancellation=self.guard, operation=operation)
                            operation.advance("inspecting")
                            artifact = operation.artifact()
                            self.findings = validate_xcarchive(artifact.path,
                                expected_bundle_id=bound.saved.configuration.bundle_id, release=bound.saved.release,
                                symbols_policy=bound.saved.configuration.symbols_policy,
                                cancellation=self.guard, operation=operation)
                        else:
                            self._signed_body(bound)
                            artifact = operation.artifact()
                        if any(finding.status in FAILING_STATUSES for finding in self.findings):
                            operation.fail("archive-validation-failed")
                        operation.check_inputs()
                        operation.files.check_tools()
                        artifact.check()
                        if operation.signing is not None:
                            operation.ipa().check()
                        require(artifact.inventory is not None and operation.snapshot_closed())
                        operation.advance("disposing-work")
                        operation.files.finish_work()
                        operation.check_inputs()
                        operation.files.check_tools()
                        artifact.check()
                        if operation.signing is not None:
                            operation.ipa().check()
                        expected_names = {"archive.xcarchive"} if operation.signing is None else {"archive.xcarchive", "export"}
                        require(operation.files.work_disposition() == "removed"
                                and operation.files.names(operation.files.namespace.fd) == expected_names)
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
                        if operation.signing is not None:
                            require(self.pairing is not None and operation.ipa().inventory is not None)
                            self._candidate.update(scope=SIGNED_SCOPE, limitations=list(SIGNED_LIMITATIONS),
                                ipa=f".mobile-release/desktop-ios-archive/{operation.operation_id}/export/{operation.ipa().original.name}",
                                ipaBytes=operation.ipa().inventory.size, pairing=self.pairing)
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

    def _recovery_run(self) -> None:
        operation = self.operation
        with invocation_custody(operation.root, mode="build", cancellation=self.guard):
            try:
                operation.prepare_recovery()
                self._recovery_body()
            except BaseException as error:
                self.remember(error)
                raise
            finally:
                try:
                    self.close()
                except BaseException as error:
                    self.remember(error)
                    raise

    def _recovery_body(self) -> None:
        from ._desktop_ios_recovery_protocol import ACCOUNT_CONFIRMATION, PROJECT_CONFIRMATION, LIMITATIONS as RECOVERY_LIMITATIONS
        from .build_inputs import BuildInputManualRecoveryRequired, build_inputs_status, recover_build_inputs
        from .local_signing import SigningBusy, signing_status, recover_signing
        operation, signing = self.operation, self.operation.signing
        action = self.request.context["recovery"]["action"]
        session = self.request.context["recovery"].get("session")
        rows = {"account": None, "project": None}
        for name in (("account", "project") if action == "inspect" else (action,)):
            # The account context has fully closed before project admission;
            # no action borrows or holds the opposite lock.
            require(name != "project" or signing.account_closed())
            signing.phase = "recovering-" + name
            operation.advance(signing.phase)
            try:
                if name == "account":
                    observed = (signing_status(cancellation=self.guard) if action == "inspect" else
                        recover_signing(session, ACCOUNT_CONFIRMATION, manual=False, cancellation=self.guard))
                else:
                    observed = (build_inputs_status(operation.root, cancellation=self.guard) if action == "inspect" else
                        recover_build_inputs(operation.root, session=session, confirm=PROJECT_CONFIRMATION,
                                             manual=False, cancellation=self.guard))
            except (CredentialError, BuildInputError) as error:
                fatal = fatal_lifetime_error(error, "Original local recovery did not settle")
                if fatal is not None or self.guard.lifetime_ledger.fatal:
                    raise fatal if fatal is not None else error
                self.remember(error)
                original_session = (signing.session.token if name == "account" and signing.session is not None
                                    else None)
                observed = {"status": ("busy" if isinstance(error, SigningBusy) else
                    "manual-required" if isinstance(error, BuildInputManualRecoveryRequired) else "conflict"),
                    "session": session if action != "inspect" else original_session}
            state = observed["status"]
            token = observed.get("session", session if action != "inspect" else None)
            if state in {"idle", "recovered", "absent"}:
                following = "none"
            elif state == "busy":
                following = "wait"
            elif state == "manual-required":
                following = "manual"
            elif state == "pending":
                following = "manual" if observed.get("recovery") == "unsupported-legacy-controls" else "ordinary"
            elif state == "cleanup-only":
                following = "ordinary"
            else:
                following = "preserve"
            rows[name] = {"status": state, "session": token, "next": following}
            if state in {"busy", "conflict", "manual-required", "recovered-with-conflict"} or self.source.first_failure is not None:
                # Core status can catch a known admission refusal after its
                # original CleanupScope latched F. Never clear it or start the
                # opposite scope just because status returned benign DATA.
                self.remember(IOSArchiveError("recovery-attention"))
                if action == "inspect" and name == "account":
                    rows["project"] = {"status": "not-inspected", "session": None, "next": "preserve"}
                break
        self.recovery_report = {"schemaVersion": 1, "scope": "local-ios-recovery", **rows,
                                "limitations": list(RECOVERY_LIMITATIONS)}
        if self.primary is None:
            operation.files.check_tools()
            operation.advance("disposing-work")

    def _signed_body(self, bound) -> None:
        from .credentials import materialize_build_inputs, validate_signing_material
        from .ios import validate_ipa
        from .ios_artifacts import inspect_ios_artifact_set, snapshot_ios_artifacts
        operation, guard = self.operation, self.guard
        signing = operation.signing
        require(signing is not None and signing.lease is not None)
        signing.bind_values()
        operation.advance("checking-xcode")
        operation.check_xcode()
        operation.advance("validating-signing")
        signing.phase = "validating-signing"
        self.findings = validate_signing_material(bound.config, values=signing.values, platforms=("ios",),
            execution_source=signing.lease.execution_source(), cancellation=guard)
        if not self.findings or any(item.status not in {Status.PASS, Status.NOT_APPLICABLE} for item in self.findings):
            operation.fail("signing-validation-failed")
        operation.advance("materializing-signing")
        signing.phase = "materializing-signing"
        try:
            with operation.invocation.materialization(signing_lease=signing.lease) as child:
                with materialize_build_inputs(bound.config, values=signing.values, platforms=("ios",),
                        prepare_ios_signing=True, signing_lease=signing.lease, cancellation=guard,
                        build_inputs=child) as materialized:
                    try:
                        signing.bind_materialized(materialized)
                        signing.phase = "building"
                        run_ios_build(bound.config, signed=True, signing_session=signing.session,
                            cancellation=guard, operation=operation)
                        operation.advance("restoring-signing")
                    except BaseException as error:
                        self.remember(error)  # Before original native/account/material closes.
                        raise
                    finally:
                        signing.phase = "restoring-signing"
        except BaseException as error:
            self.remember(error)
            raise
        require(signing.inputs_closed() and signing.session is not None and signing.session.closed
                and signing.session._disposal_complete and signing.lease.active is None)
        signing.phase = "inspecting"
        operation.advance("inspecting")
        selected = bound.saved.configuration
        with snapshot_ios_artifacts({"ios-archive": operation.artifact().path, "ios-ipa": operation.ipa().path},
                cancellation=guard, desktop_operation=operation) as snapshot:
            try:
                self.pairing = inspect_ios_artifact_set(snapshot, expected_bundle_id=selected.bundle_id,
                    release=bound.saved.release, symbols_policy=selected.symbols_policy)
                self.findings.append(Finding("ios.artifacts.correspondence", Status.PASS,
                    "The retained archive and IPA match under the complete shared pairing policy.", category="ios-artifact"))
                self.findings.extend(validate_ipa(snapshot.paths["ios-ipa"], expected_bundle_id=selected.bundle_id,
                    expected_team_id=self.request.context["signing"]["teamId"],
                    expected_fingerprint=self.request.context["signing"]["distributionCertificateSha256"],
                    release=bound.saved.release, require_tools=True, deadline=snapshot.deadline, cancellation=guard))
                if any(item.status not in {Status.PASS, Status.NOT_APPLICABLE} for item in self.findings):
                    operation.fail("artifact-validation-failed")
                snapshot.assert_unchanged()
                operation.inspection_observed(snapshot)
                operation.check_inputs()
                operation.ipa().check()
                if selected.symbols_policy == "required":
                    self.findings.append(Finding("ios.symbols.upload", Status.BLOCKED,
                        "Required symbol upload was not requested; local validation never executes upload commands.",
                        category="ios-artifact"))
                    operation.fail("symbols-upload-not-requested")
                operation.advance("disposing-snapshot")
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
        if self.source.recovery:
            if error is None and self.recovery_report is not None:
                return "complete", "none"
            reason = error.reason if isinstance(error, IOSArchiveError) else "recovery-attention"
            return ("refused" if dispatched is False else "failed"), reason
        if isinstance(error, (IOSSelectionRefused, IOSArchiveError)):
            reason = error.reason
        elif isinstance(error, BuildInputError):
            reason = "project-admission-refused"
        elif isinstance(error, ProcessError):
            reason = "command-incomplete"
        elif self.operation.signing is not None and isinstance(error, CredentialError):
            reason = ("account-admission-refused" if self.operation.signing.phase == "admitting"
                      else "signing-validation-failed")
        elif self.operation.signing is not None and isinstance(error, ValidationError):
            reason = "artifact-validation-failed" if self.operation.signing.phase == "inspecting" else "signing-input-invalid"
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
        signed = self.source.signed
        from ._desktop_ios_recovery_protocol import COMMAND_LIMIT as RECOVERY_COMMAND_LIMIT
        command_limit = RECOVERY_COMMAND_LIMIT if self.source.recovery else SIGNED_COMMAND_LIMIT if signed else 4
        if (verdict.profile_calls > (SIGNED_PROFILE_LIMIT if signed else 0)
                or verdict.commands > command_limit):
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
        if self.source.account_lifecycle:
            lifetime.update(signingClosed=operation.signing.account_closed(),
                buildInputsClosed=operation.signing.inputs_closed(),
                materialRetired=self.source.material_closed())
        if self.source.recovery:
            settled = (lifetime["complete"] and not lifetime["fatal"] and lifetime["contained"]
                       and dispatched is not None and all(lifetime[key] for key in CLOSE_FIELDS)
                       and all(lifetime[key] for key in ("signingClosed", "buildInputsClosed", "materialRetired")))
            outcome, reason = self._failure(dispatched) if settled else ("unknown", "cleanup-unknown")
            value = {"schemaVersion": 1, "context": self.request.context, "outcome": outcome, "reason": reason,
                "activity": {"stage": operation.stage}, "report": self.recovery_report if settled else None, "lifetime": lifetime}
            validate_terminal(value, self.request)
            return value
        disposition = operation.disposition()
        settled = (verdict.cleanup_complete and verdict.contained and commands_settled and dispatched is not None
                   and all(lifetime[key] for key in CLOSE_FIELDS) and "unknown" not in disposition.values())
        if signed:
            settled = settled and all(lifetime[key] for key in ("signingClosed", "buildInputsClosed", "materialRetired"))
        outcome, reason = self._failure(dispatched) if settled else ("unknown", "cleanup-unknown")
        result = None
        if outcome == "complete":
            require(self._candidate is not None and disposition["output"] == "retained-incomplete"
                    and disposition["snapshot"] == disposition["work"] == "removed")
            disposition = {**disposition, "output": "retained-local-result"}
            result = self._candidate
        checks = {"ios.archive.identity": "archive-identity", "ios.archive.dsym": "archive-dsym",
                  "ios.archive.structure": "archive-structure"}
        if signed:
            checks.update({"credential-material.apple-p12": "signing-material", "credential-material.apple-profile": "profile-material",
                "credential-material.ios-firebase": "firebase-material", "ios.artifacts.correspondence": "artifact-correspondence",
                "ios.ipa.structure": "ipa-structure", "ios.ipa.profile": "ipa-profile", "ios.ipa.entitlements": "ipa-entitlements",
                "ios.ipa.signer": "ipa-signer", "ios.ipa.validation": "ipa-validation", "ios.symbols.upload": "symbols-upload"})
        rows = [{"check": checks.get(finding.code, "other-core-finding"), "status": finding.status.value}
                for finding in self.findings]
        value = {"schemaVersion": 1, "context": self.request.context, "outcome": outcome, "reason": reason,
            "activity": {"stage": operation.stage, "selection": operation.selection(),
                         "commands": operation.command_outcomes(), "findings": rows},
            "disposition": disposition, "result": result, "lifetime": lifetime}
        validate_terminal(value, self.request)
        return value
