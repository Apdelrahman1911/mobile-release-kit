"""Signed-only borrowers of the original saved iOS operation.

This module creates no process owner. Account commands retain their original
scope/journal fence, validators use the original credential-free path, and every
entered command/profile slot stays rooted through final settlement.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import os
import hashlib
import json
import sys
import time

from ._desktop_ios_archive_protocol import (
    SIGNED_COMMAND_LIMIT, SIGNED_PROFILE_LIMIT, require,
)

CAPTURE_BUDGET = 512 * 1024**2
COMMAND_METADATA_RESERVE = 1024 * 1024
# Retain the real two CMS captures, bounded parsers (100k nodes) and original
# scopes/contexts. A 2MiB allowance was smaller than one allowed4MiB capture.
# This is a conservative admission charge, not an OS RSS/secure-erasure claim.
PROFILE_RESERVE = 64 * 1024**2
ENVIRONMENT_LIMIT = 64 * 1024
_MAIN_TIMEOUTS = {"xcode-version": 30, "ios-sdk": 30, "prepare": 600, "archive": 3600, "export": 1800}
_SECURITY = {"list-keychains", "default-keychain", "create-keychain", "set-keychain-settings", "unlock-keychain",
             "import", "set-key-partition-list", "delete-keychain"}
_CLEANUP_SECURITY = {"list-keychains", "default-keychain", "delete-keychain"}


@dataclass(eq=False)
class _Command:
    role: str
    scope: object
    binding: object
    cleanup: bool
    reserved: int
    slot: object = None
    entered: bool = False
    returned: bool = False
    state: str = "RESERVED"


def original_outcome(slot, guard, scope, binding):
    """The original native finality object, never an aggregate-count inference."""
    from ._command_process import (
        CommandOutcomeSlot, NoTargetProof, OriginalCommandFinality, OriginalCommandOutcome, RouteHistory, _Outer,
    )
    if type(slot) is not CommandOutcomeSlot:
        return None
    engine = slot._engine
    if (type(engine) is not _Outer or engine.guard is not guard or engine.slot is not slot
            or engine.scope is not scope or engine.binding is not binding or engine.owns is not False
            or slot._scope is not scope or slot._nonce != engine.nonce or getattr(engine, "phase", None) != "CLOSED"
            or engine.evidence is not None or engine._store_timing is not None):
        return None
    value = slot.read()
    if (type(value) is not OriginalCommandOutcome or value._engine is not engine or value.nonce != slot._nonce
            or type(value.original_finality) is not OriginalCommandFinality
            or value.original_finality._engine is not engine or not engine.original_finality()
            or type(value.create_w) is not RouteHistory or type(value.run_tool) is not RouteHistory
            or value.create_w.retired is not True or value.run_tool.retired is not True
            or scope is not None and not value.matches(scope, binding)):
        return None
    if value.no_target is not None:
        if (type(value.no_target) is not NoTargetProof or value.no_target._engine is not engine
                or value.no_target.kind not in {"NO_W_CREATION", "CLOSED_BEFORE_RUN", "EXEC_REJECTED"}
                or value.result_integrity != "complete"):
            return None
    elif value.create_w.attempted is not True or value.run_tool.attempted is not True:
        return None
    return value


class SignedIOSOperation:
    """One exact signed facet; no independent lease, process or retry engine."""

    def __init__(self, operation) -> None:
        from .ios_archive_operation import IOSArchiveOperation
        require(type(operation) is IOSArchiveOperation and operation.source.account_lifecycle
                and operation.request.context["operation"] in {"ios-signed-export", "ios-local-recovery"})
        self.operation, self.guard = operation, operation.guard
        self.lease = self.session = self.materialization = None
        self.lease_close_claimed = self.lease_close_returned = False
        self.phase = "admitting"
        self.commands: list[_Command] = []
        self.profiles = []
        self.profile_checked = set()
        self.scratches = []
        self.pending: _Command | None = None
        self.settling_command: _Command | None = None
        self.capture_reserved = 0
        self.values = None
        self.materialized = None
        self.profile_specifier = None
        self.recovery_project = self.recovery_inspection = None
        self.inspection_close_claimed = self.inspection_close_returned = False

    def owner(self) -> None:
        self.operation.owner()
        require(self.operation.signing is self and self.operation.source.account_lifecycle)

    @property
    def recovery(self) -> bool:
        return self.operation.source.recovery

    def recovery_checkpoint(self) -> None:
        """Recovery is ordinary bounded work, even while core restores state.

        The core's cleaning flag scopes its own command purpose. It does not
        turn a user-requested recovery into post-STOP cleanup authority.
        Independent descriptor closes deliberately do not call this method.
        """
        self.owner()
        require(self.recovery and self.phase in {"admitting", "recovering-account", "recovering-project"})
        self.operation._tick()

    def bind_lease(self, lease) -> None:
        from .local_signing import SigningLease
        from . import build_inputs
        self.owner()
        invocation = self.operation.invocation
        require(type(lease) is SigningLease and lease.cancellation is self.guard and lease.supplied_home is None
                and self.lease is None and self.phase in ({"admitting", "recovering-account"} if self.recovery else {"admitting"})
                and invocation is not None
                and invocation.active and invocation.reserved and build_inputs._ENV_OWNER is invocation
                and not invocation.project_started and invocation.project_owner is None
                and invocation.signing_lease is None and lease.home_fd is None and not lease.locked)
        self.lease = lease  # Before acquisition/return: lost admission is still owned.

    def bind_session(self, session) -> None:
        from .local_signing import SigningSession
        self.owner()
        require(type(session) is SigningSession and self.session is None and session.lease is self.lease
                and session.cancellation is self.guard
                and self.phase == ("recovering-account" if self.recovery else "materializing-signing")
                and (not self.recovery or self.lease._recovery_mode is True))
        self.session = session

    def session_checkpoint(self, session) -> None:
        self.owner()
        require(session is self.session)
        if self.recovery:
            self.recovery_checkpoint()
        elif session.cleaning or self.settling_command is not None:
            if self.settling_command is not None:
                record = self.settling_command
                require(record is self.commands[-1] and record.scope is session._command_scope
                        and record.binding is session._command_binding and record.state == "CLOSED"
                        and original_outcome(record.slot, self.guard, record.scope, record.binding) is not None)
            self.operation.cleanup_checkpoint()
        else:
            self.operation._tick()

    @contextmanager
    def command_settlement(self, session):
        """Persist only the same already-final command's journal/fence result.

        A STOP between native return and durable settlement must not make an
        otherwise known command ambiguous. This is not another command phase:
        no command/profile admission is possible while this original is lent.
        Explicit recovery does not use this post-STOP cleanup borrowing.
        """
        from ._command_process import AccountExecutionScope, JournalledCommandBinding
        self.owner()
        require(not self.recovery and session is self.session and self.lease.active is session
                and not session.closed and self.settling_command is None and self.commands
                and self.commands_settled() and not self.guard.lifetime_ledger.fatal)
        record = self.commands[-1]
        require(type(record.scope) is AccountExecutionScope and type(record.binding) is JournalledCommandBinding
                and record.scope is session._command_scope and record.binding is session._command_binding
                and record.binding._session is session and record.binding._scope is record.scope
                and record.scope._source._lease is self.lease and record.scope._source._authorization is None
                and record.slot is record.scope.outcome and record.entered and record.state == "CLOSED")
        outcome = original_outcome(record.slot, self.guard, record.scope, record.binding)
        require(outcome is not None and outcome.result_integrity == "complete"
                and (outcome.no_target is not None or outcome.termination == "normal-exit"
                     and type(outcome.returncode) is int and 0 <= outcome.returncode <= 255))
        self.operation.cleanup_checkpoint()
        self.settling_command = record
        try:
            yield
        finally:
            require(self.settling_command is record)
            self.settling_command = None

    def bind_materialization(self, child) -> None:
        from .build_inputs import BuildInputs
        self.owner()
        require(type(child) is BuildInputs and child.invocation is self.operation.invocation
                and child.cancellation is self.guard and self.materialization is None
                and self.phase == "materializing-signing")
        self.materialization = child

    def bind_scratch(self, scratch) -> None:
        from .build_inputs import FiniteScratch
        self.owner()
        require(type(scratch) is FiniteScratch and scratch.cancellation is self.guard
                and scratch.layout in {"signing-validation", "build"} and not scratch.active and not scratch.claimed
                and len(self.scratches) < 2 and not any(item.layout == scratch.layout for item in self.scratches))
        if self.recovery:
            from .build_inputs import BuildInputs
            require(scratch.layout == "build" and self.phase == "recovering-project"
                    and type(scratch.journal) is BuildInputs and scratch.journal.invocation is None
                    and scratch.journal.project is self.recovery_project and not self.scratches)
        else:
            require(self.phase == ("validating-signing" if scratch.layout == "signing-validation" else "materializing-signing"))
        self.scratches.append(scratch)

    def scratch_checkpoint(self, scratch) -> None:
        self.owner()
        require(any(original is scratch for original in self.scratches))
        if self.recovery:
            self.recovery_checkpoint()
        elif scratch.claimed or (scratch.journal is self.materialization and self.materialization is not None
                                 and self.materialization.claimed):
            self.operation.cleanup_checkpoint()
        else:
            self.operation._tick()

    def bind_recovery_project(self, project) -> None:
        from . import build_inputs
        self.recovery_checkpoint()
        invocation = self.operation.invocation
        expected = self.operation.request.native["rootIdentity"]
        require(type(project) is build_inputs._Project and project.recovery is True
                and project.guard is self.guard and project.root == self.operation.root
                and project.expected_root == (int(expected["device"]), int(expected["inode"]),
                    expected["mode"], expected["uid"], expected["gid"])
                and self.phase == "recovering-project" and self.recovery_project is None and self.account_closed()
                and invocation is not None and invocation.active and invocation.reserved
                and build_inputs._ENV_OWNER is invocation and invocation.project_owner is None
                and invocation.signing_lease is None and not invocation.project_started)
        self.recovery_project = project  # Before the original _scope acquires anything.

    def bind_recovery_inspection(self, child) -> None:
        from .build_inputs import BuildInputs
        self.recovery_checkpoint()
        require(type(child) is BuildInputs and child.project is self.recovery_project
                and child.invocation is None and child.cancellation is self.guard
                and self.recovery_inspection is None and self.scratches == [child.scratch])
        self.recovery_inspection = child  # Before _load_pending or any private open.

    def inspection_closing(self, child) -> None:
        self.owner()
        require(self.recovery and child is self.recovery_inspection and not self.inspection_close_claimed)
        self.inspection_close_claimed = True

    def inspection_closed(self, child) -> None:
        self.owner()
        require(self.recovery and child is self.recovery_inspection and self.inspection_close_claimed
                and not self.inspection_close_returned)
        self.inspection_close_returned = True

    def known_descriptor(self, number: int) -> bool:
        self.owner()
        project = self.recovery_project
        if project is not None and any(slot.number == number for slot in (*project.directory.slots, project.meta)):
            return True
        for scratch in self.scratches:
            if any(slot.number == number for slot in (scratch.slot, *scratch.parent.slots, *scratch.writer_slots)):
                return True
        child = self.recovery_inspection if self.recovery else self.materialization
        return child is not None and (child.slot.number == number
            or any(slot.number == number for slot in child.control_slots)
            or any(any(slot.number == number for slot in parent.slots) for parent in child.parents.values()))

    def lease_closing(self, lease) -> None:
        self.owner()
        require(self.lease is lease and not self.lease_close_claimed)
        self.lease_close_claimed = True

    def lease_closed(self, lease) -> None:
        self.owner()
        require(self.lease is lease and self.lease_close_claimed and not self.lease_close_returned)
        self.lease_close_returned = True

    def bind_values(self) -> None:
        self.operation.checkpoint()
        require(self.values is None and self.phase == "admitting" and self.operation.inputs is not None)
        from ._desktop_ios_signing_material import PrivateIOSMaterial
        material = self.operation.source.material
        require(type(material) is PrivateIOSMaterial)
        policy = self.operation.request.context["signing"]
        config = self.operation.inputs.config
        # Rust's original NativeContext stores canonical serde_json UTF8 DATA,
        # whereas savedConfig binds the exact on-disk bytes including spacing.
        # Compare both independently; an assessment for another draft is not
        # permission to consume these selected records for the saved config.
        canonical = json.dumps(config.data, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        captured = self.operation.request.native["signingContext"]
        if len(canonical) != captured["bytes"] or hashlib.sha256(canonical).hexdigest() != captured["sha256"]:
            self.operation.fail("stale-intent")
        ios = config.section("ios")
        if (ios.get("teamId") != policy["teamId"] or
                ios.get("distributionCertificateSha256", "").replace(":", "").lower() != policy["distributionCertificateSha256"]):
            self.operation.fail("signing-policy-required")
        from .credentials import requirements
        required = requirements(config, "candidate", purpose="signing", platforms=("ios",))
        names = {item.name for item in required}
        expected = ["apple-p12", "apple-profile"]
        if config.section("services").get("iosFirebase") == "required":
            expected.append("ios-firebase")
        if "MOBILE_RELEASE_PROJECT_READ_TOKEN" in names:
            expected.append("project-read-token")
        require([row["kind"] for row in policy["assignments"]] == expected)
        self.values = material.bind(self.operation)

    def bind_materialized(self, values) -> None:
        from .credentials import materialized_profile_specifier
        self.operation.checkpoint()
        require(self.phase == "materializing-signing" and self.materialized is None
                and self.session is not None and self.lease.active is self.session
                and self.operation.invocation.child is self.materialization)
        self.profile_specifier = materialized_profile_specifier(values, invocation=self.operation.invocation)
        require(type(self.profile_specifier) is str)
        self.materialized = values

    def main_environment(self, environment: dict[str, str]) -> dict[str, str]:
        self.operation.checkpoint()
        require(self.lease is not None and self.lease.locked)
        # The admitted account home, not the operation's fake/private home.
        value = {key: item for key, item in environment.items() if key != "CFFIXED_USER_HOME"}
        value["HOME"] = str(self.lease.home)
        if self.materialized is not None and self.phase == "building":
            from .credentials import materialized_profile_specifier
            require(materialized_profile_specifier(self.materialized, invocation=self.operation.invocation) == self.profile_specifier)
            value.update(self.materialized)
        return value

    def command_environment(self, role: str, scope) -> dict[str, str]:
        """Closed, original capabilities; never scrub-and-copy ambient values."""
        files = self.operation.files
        require(files is not None and self.operation.prepared)
        if self.recovery:
            self.recovery_checkpoint()
            require(role == "account-recovery" and scope is not None and self.lease is not None)
            return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "HOME": str(self.lease.home)}
        # After _admit has checked the exact original cleaning session/scope,
        # read its unchanged private-directory bindings even after first STOP.
        # This does not renew work or permit another account command.
        with self.guard.deferred(check_on_exit=False):
            self.operation.cleanup_checkpoint()
            value = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C",
                     "HOME": str(files.work_path("home")), "TMPDIR": str(files.work_path("tmp"))}
        if role in {"prepare", "archive", "export"}:
            return self.operation.command_environment()
        if role in {"xcode-version", "ios-sdk"}:
            tool = self.operation.request.native["toolchain"]
            value.update(DEVELOPER_DIR=tool["developerDir"], SDKROOT=tool["sdk"])
        if scope is not None:
            value["HOME"] = str(self.lease.home)
            if role in {"credential-validation", "account-setup"}:
                require(self.values is not None)
                password = self.values["MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD"]
                key = ("MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD" if role == "credential-validation"
                       else "MOBILE_RELEASE_LOCAL_P12_PASSWORD")
                value[key] = password
        # Cleanup and validators never carry the P12/project-read capability.
        return value

    def check_tool_bindings(self) -> None:
        # Read-only comparison of the SAME originals remains possible after
        # ordinary STOP. No project guard/new work/cleanup authority is granted.
        with self.guard.deferred(check_on_exit=False):
            self.operation.cleanup_checkpoint()
            self.operation.files.check_tools()

    @staticmethod
    def request_reservation(arguments, environment, cwd) -> int:
        """Charge native immutable argv/environment copies BEFORE entry."""
        from .owned_process import REQUEST_LIMIT
        # All commands are absolute, so there is no expanded PATH record.
        require(os.path.isabs(arguments[0]) and len(environment) <= 64)
        argument_bytes = 0
        for value in arguments:
            require(len(value) <= REQUEST_LIMIT)
            argument_bytes += len(os.fsencode(value))
            require(argument_bytes <= REQUEST_LIMIT)
        working = str(Path.cwd() if cwd is None else cwd.absolute())
        require(len(working) <= 4096)
        environment_bytes = 0
        for name, value in environment.items():
            require(type(name) is str and type(value) is str and len(name) <= 128 and len(value) <= ENVIRONMENT_LIMIT)
            environment_bytes += len(os.fsencode(name)) + len(os.fsencode(value)) + 2
            require(environment_bytes <= ENVIRONMENT_LIMIT)
        record = 32 + 8 * len(arguments) + 14 * len(environment) + argument_bytes + len(os.fsencode(working)) + environment_bytes
        return 4 * record

    def _scope(self, scope, binding, cleanup: bool) -> None:
        from ._command_process import AccountExecutionScope, JournalledCommandBinding
        require(type(scope) is AccountExecutionScope and scope._source._lease is self.lease
                and not scope._used and scope.outcome._engine is None
                and scope._binding is binding)
        if self.recovery:
            from .local_signing import _RecoveryAttempt
            authorization = scope._source._authorization
            require(self.session is not None and type(authorization) is _RecoveryAttempt
                    and authorization is self.session._recovery_attempt
                    and authorization.lease is self.lease and authorization.session is self.session
                    and self.lease._recovery_mode is True)
            authorization.check(self.session)
        else:
            require(scope._source._authorization is None)
        self.lease.assert_owner()
        if binding is not None:
            session = self.session
            require(type(binding) is JournalledCommandBinding and binding._scope is scope
                    and binding._session is session and self.lease.active is session
                    and session._command_scope is scope and session._command_binding is binding
                    and not session.closed and session.cleaning is cleanup
                    and session.state is not None and session.state["inflight"] is not None
                    and session.state["inflight"]["kind"] == binding._fields["kind"])
        elif cleanup:
            # Original account state queries in cleanup also use unjournalled
            # original scopes; they still require the same actual cleaning owner.
            require(self.session is not None and self.lease.active is self.session
                    and self.session.cleaning and not self.session.closed)

    def _admit(self, argv, scope, binding, cleanup: bool) -> tuple[str, int]:
        require(type(cleanup) is bool and type(argv) in {tuple, list} and 0 < len(argv) <= 4096
                and all(type(item) is str and "\0" not in item for item in argv))
        role = self.operation._pending
        program = argv[0]
        if self.recovery:
            self.recovery_checkpoint()
            require(role is None and self.phase == "recovering-account"
                    and self.operation.request.context["recovery"]["action"] == "account"
                    and self.session is not None and self.session.cleaning is cleanup)
            self._scope(scope, binding, cleanup)
            require(program in {"security", "/usr/bin/security"} and len(argv) > 1
                    and argv[1] in _CLEANUP_SECURITY
                    and (binding is None or binding._fields["kind"] in {"observe", "search", "default", "delete"}))
            return "account-recovery", 30
        if cleanup:
            require(role is None and self.phase in {"materializing-signing", "building", "restoring-signing"})
            self._scope(scope, binding, True)
            require(program in {"security", "/usr/bin/security"} and len(argv) > 1 and argv[1] in _CLEANUP_SECURITY
                    and (binding is None or binding._fields["kind"] in {"observe", "search", "default", "delete"}))
            return "account-cleanup", 30
        self.operation.checkpoint()
        if role is not None:
            require(role in _MAIN_TIMEOUTS and self.operation._roles[role] == "calling")
            if role in {"xcode-version", "ios-sdk"}:
                require(scope is None and binding is None and self.phase == "admitting")
            else:
                require(self.phase == "building")
                self._scope(scope, binding, False)
                require(binding is not None and binding._fields["kind"] == "build")
            return role, _MAIN_TIMEOUTS[role]
        if scope is not None:
            self._scope(scope, binding, False)
            require(self.phase in {"validating-signing", "materializing-signing"})
            if self.phase == "validating-signing":
                require(binding is None and program in {"openssl", "/usr/bin/openssl"}
                        and len(argv) > 1 and argv[1] in {"pkcs12", "x509", "pkey"})
                return "credential-validation", 30
            require(program in {"openssl", "/usr/bin/openssl", "security", "/usr/bin/security"})
            require(len(argv) > 1 and (argv[1] == "pkcs12" if program.endswith("openssl") else argv[1] in _SECURITY))
            require(binding is None or binding._fields["kind"] in
                    {"create", "settings", "unlock", "import", "partition", "observe", "search", "default", "extract"})
            return "account-setup", 30
        require(binding is None and self.phase == "inspecting" and self.operation.snapshot_binding.consumer_active
                and program in {"codesign", "/usr/bin/codesign", "openssl", "/usr/bin/openssl"}
                and len(argv) > 1)
        require(argv[1] in {"x509", "pkey"} if program.endswith("openssl") else
                any(item in {"--verify", "--display", "-d"} for item in argv[1:]))
        return "artifact-validation", 120

    @contextmanager
    def command(self, argv, *, environ, cwd, timeout, capture, text, output_limit, cleanup, scope, binding):
        self.owner()
        require(self.pending is None and self.settling_command is None and self.commands_settled() and type(capture) is bool
                and type(text) is bool and type(timeout) is int and timeout > 0
                and type(output_limit) is int and output_limit > 0)
        if cleanup:
            self.operation.cleanup_checkpoint()
        role, maximum = self._admit(argv, scope, binding, cleanup)
        endpoint = self.operation.source.cleanup_endpoint() if cleanup and not self.recovery else self.operation.source.work_end
        # Each existing native command still gets its 10s finality allowance;
        # its work end is clamped before the original aggregate hard endpoint.
        endpoint = min(endpoint, self.operation.source.hard_endpoint() - 10)
        remaining = int(endpoint - time.monotonic())
        if remaining < 1:
            self.operation.fail("work-retained" if cleanup else "command-incomplete")
        timeout = min(timeout, maximum, remaining)
        cap = 8 * 1024**2 if role == "artifact-validation" else 2 * 1024**2
        output_limit = min(output_limit, cap)
        # Keep both native bytearrays and decoded strings intact for finality.
        # A prospective command reserves all possible capture/conversion copies.
        arguments = tuple(argv)
        if arguments[0] in {"security", "openssl", "codesign"}:
            arguments = ("/usr/bin/" + arguments[0], *arguments[1:])
        environment = self.command_environment(role, scope)
        reservation = (COMMAND_METADATA_RESERVE + self.request_reservation(arguments, environment, cwd)
                       + (12 * output_limit if capture else 0))
        from ._desktop_ios_recovery_protocol import COMMAND_LIMIT as RECOVERY_COMMAND_LIMIT
        limit = RECOVERY_COMMAND_LIMIT if self.recovery else SIGNED_COMMAND_LIMIT
        if len(self.commands) >= limit or self.capture_reserved + reservation > CAPTURE_BUDGET:
            self.operation.fail("input-limit")
        self.check_tool_bindings()
        record = _Command(role, scope, binding, cleanup, reservation)
        self.commands.append(record)
        self.capture_reserved += reservation
        self.pending = record
        if self.operation._pending is not None:
            self.operation._roles[role] = "attempted"
        primary = None
        record.entered, record.state = True, "ENTERED"
        try:
            yield arguments, environment, timeout, output_limit
            record.returned = True
        except BaseException as error:
            primary = error
            self.operation.remember(error)
            raise
        finally:
            self.owner()
            record.state = "CLOSED" if original_outcome(record.slot, self.guard, scope, binding) is not None else "UNKNOWN"
            if record.state == "CLOSED":
                engine = record.slot._engine
                # Conservative allocation charge; do not mutate original output.
                actual = COMMAND_METADATA_RESERVE + sum(sys.getsizeof(value) for value in engine.outputs)
                actual += sum(sys.getsizeof(value) for value in (engine.decoded or ()))
                if engine.frozen is not None:
                    actual += engine.frozen.manifest.record_bytes * 4
                if actual > record.reserved:
                    self.operation.remember(RuntimeError("signed retained-output accounting exceeded reservation"), fatal=True)
                else:
                    self.capture_reserved -= record.reserved - actual
                    record.reserved = actual
            self.pending = None
            try:
                self.check_tool_bindings()
            except BaseException as error:
                self.operation.remember(error)
                if primary is None:
                    raise

    def bind_command_slot(self, engine, slot) -> None:
        from ._command_process import CommandOutcomeSlot, _Outer
        self.owner()
        record = self.pending
        require(type(engine) is _Outer and type(slot) is CommandOutcomeSlot and record is not None
                and record.entered and record.state == "ENTERED" and record.slot is None
                and engine.guard is self.guard and engine.owns is False and engine._store_timing is None
                and engine.scope is record.scope and engine.binding is record.binding
                and engine.slot is slot and slot._engine is engine and slot._scope is record.scope
                and slot._nonce == engine.nonce and slot.read() is None
                and self.guard.lifetime_ledger._command is slot)
        record.slot = slot
        if self.operation._pending is not None:
            role = self.operation._pending
            require(role == record.role and self.operation._roles[role] == "attempted"
                    and self.operation._command_slots[role] is None)
            self.operation._command_slots[role] = slot

    def bind_profile(self, evidence) -> None:
        from ._lifetime_evidence import ProfileCallEvidence
        self.owner()
        require(type(evidence) is ProfileCallEvidence and evidence._guard is self.guard
                and evidence._ledger is self.guard.lifetime_ledger and not evidence._finished
                and self.pending is None and self.settling_command is None
                and self.phase in {"validating-signing", "materializing-signing", "inspecting"})
        if len(self.profiles) >= SIGNED_PROFILE_LIMIT or self.capture_reserved + PROFILE_RESERVE > CAPTURE_BUDGET:
            self.operation.fail("input-limit")
        self.profiles.append(evidence)
        self.capture_reserved += PROFILE_RESERVE
        self.operation.checkpoint()
        self.check_tool_bindings()

    def finish_profile(self, evidence) -> None:
        self.owner()
        require(evidence in self.profiles and evidence not in self.profile_checked
                and evidence._finished and evidence._published)
        self.check_tool_bindings()
        self.profile_checked.add(evidence)

    def commands_settled(self) -> bool:
        self.owner()
        return (self.pending is None and self.settling_command is None and all(not row.entered or row.state == "CLOSED"
                and original_outcome(row.slot, self.guard, row.scope, row.binding) is not None for row in self.commands)
                and all(item._finished and item._published and item in self.profile_checked
                        and item.verdict().cleanup_complete for item in self.profiles))

    def outcome(self, role: str):
        slot = self.operation._command_slots[role]
        record = next((row for row in self.commands if row.slot is slot and row.role == role), None)
        return None if record is None else original_outcome(slot, self.guard, record.scope, record.binding)

    def inputs_closed(self) -> bool:
        if self.recovery:
            project, child = self.recovery_project, self.recovery_inspection
            if project is not None and (not project.claimed or project.meta.close_state != "CLOSED"
                    or any(slot.close_state != "CLOSED" for slot in project.directory.slots)):
                return False
            if child is None:
                return not self.scratches
            # Inspection/recovery may truthfully leave original pending files.
            # Closure is only the original descriptor/iterator settlement; it
            # never asserts those retained files were disposed or recovered.
            return (self.inspection_close_claimed and self.inspection_close_returned
                    and self.scratches == [child.scratch]
                    and all(slot.close_state == "CLOSED" for slot in
                        (child.slot, child.scratch.slot, *child.scratch.writer_slots,
                         *child.scratch.parent.slots, *child.control_slots))
                    and all(all(slot.close_state == "CLOSED" for slot in parent.slots) for parent in child.parents.values()))
        def scratch_closed(scratch) -> bool:
            ended = (self.materialization is not None and self.materialization.scratch is scratch
                     and self.materialization.claimed and self.materialization._cleanup_complete) if scratch.layout == "build" else (
                         scratch.claimed and not scratch.active and scratch._cleanup_complete)
            return (ended and not scratch.created
                    and scratch.creation["state"] in {"NEW", "NO_EFFECT", "RETIRED"}
                    and all(slot.close_state == "CLOSED" for slot in
                            (scratch.slot, *scratch.writer_slots, *scratch.parent.slots)))
        if not all(scratch_closed(scratch) for scratch in self.scratches):
            return False
        child = self.materialization
        if child is None:
            return True
        scratch = child.scratch
        return (child.claimed and child._cleanup_complete and not child.created and child.creation["state"] in {"NEW", "NO_EFFECT", "RETIRED"}
                and child.slot.close_state == "CLOSED" and not scratch.created
                and scratch.slot.close_state == "CLOSED" and all(slot.close_state == "CLOSED" for slot in
                    (*scratch.writer_slots, *scratch.parent.slots, *child.control_slots))
                and all(all(slot.close_state == "CLOSED" for slot in parent.slots) for parent in child.parents.values()))

    def account_closed(self) -> bool:
        lease, session = self.lease, self.session
        return (lease is None or self.lease_close_claimed and self.lease_close_returned and not lease.locked
                and lease.home_fd is None and lease.active is None and lease._hold_slot.state in {"NEW", "CLOSED"}
                and (session is None or session.closed and session.fd is None and session.native_fd is None
                     and (self.recovery or not session._open_attempted or session._disposal_complete)))
