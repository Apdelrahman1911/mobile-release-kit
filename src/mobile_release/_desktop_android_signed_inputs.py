"""Selected Android material on the original saved-build owners.

No Apple account lease, ambient environment edit, new executor or signing policy.
The shared credential/materialization/Android functions perform the actual work.
"""
from __future__ import annotations

import hashlib
import json

from ._desktop_android_build_protocol import require


class SignedAndroidInputs:
    def __init__(self, operation) -> None:
        from .android_build_operation import AndroidBuildOperation
        require(type(operation) is AndroidBuildOperation and operation.source.signed)
        self.operation, self.guard = operation, operation.guard
        self.config_bound = self.validation_passed = False
        self.values = self.materialized = self.materialization = None
        self.validation_snapshot = None
        self.scratches = []
        self.close_claimed = False
        self.command_slot = None
        self.command_application = self.command_service = None
        self.dispatch_claimed = self.dispatch_published = False

    def owner(self) -> None:
        self.operation.owner()
        require(self.operation.signing is self and self.operation.source.signed)

    def bind_config(self) -> None:
        """Raw savedConfig was checked by bind_inputs; compare canonical DATA separately."""
        self.owner()
        operation = self.operation
        require(not self.config_bound and operation.inputs is not None)
        canonical = json.dumps(operation.inputs.config.data, sort_keys=True, ensure_ascii=False,
                               separators=(",", ":"), allow_nan=False).encode("utf-8")
        compared = operation.request.native["signingContext"]
        if len(canonical) != compared["bytes"] or hashlib.sha256(canonical).hexdigest() != compared["sha256"]:
            operation.fail("stale-intent")
        from .credentials import requirements
        names = {item.name for item in requirements(operation.inputs.config, "candidate", purpose="signing",
                                                     platforms=("android",))}
        expected = ["android-keystore"]
        if "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64" in names:
            expected.append("android-firebase")
        if "MOBILE_RELEASE_PROJECT_READ_TOKEN" in names:
            expected.append("project-read-token")
        if [row["kind"] for row in operation.request.context["signing"]["assignments"]] != expected:
            operation.fail("signing-inputs-required")
        self.config_bound = True

    def bind_values(self) -> None:
        from ._desktop_android_signing_material import PrivateAndroidMaterial
        self.operation.checkpoint()
        require(self.config_bound and self.values is None and self.operation.stage == "inputs-bound")
        original = self.operation.source.material
        require(type(original) is PrivateAndroidMaterial)
        self.values = original.bind(self.operation)

    def require_values(self, config, values) -> None:
        from ._desktop_android_signing_material import CapturedAndroidBuildValues
        self.operation.require(config, self.guard)
        require(self.config_bound and type(values) is CapturedAndroidBuildValues
                and self.values is not None and values._original is self.values._original
                and values._selected <= self.values._selected)
        values._original.check()

    def bind_scratch(self, scratch) -> None:
        from .build_inputs import FiniteScratch
        self.owner()
        require(type(scratch) is FiniteScratch and scratch.cancellation is self.guard
                and scratch.layout in {"signing-validation", "build"} and not scratch.active and not scratch.claimed
                and len(self.scratches) < 2 and not any(item.layout == scratch.layout for item in self.scratches)
                and self.operation.stage == ("validating-signing" if scratch.layout == "signing-validation"
                                             else "materializing-signing"))
        if scratch.layout == "build":
            require(self.materialization is not None and scratch.journal is self.materialization)
            self.materialization.scratch = scratch  # Root even a lost scratch-constructor return.
        else:
            require(scratch.journal is None)
        scratch._desktop_binding = self
        self.scratches.append(scratch)

    def scratch_checkpoint(self, scratch) -> None:
        self.owner()
        require(any(item is scratch for item in self.scratches))
        if scratch.claimed or scratch.journal is not None and scratch.journal is self.materialization and scratch.journal.claimed:
            self.operation.cleanup_checkpoint()
        else:
            self.operation._tick()

    def bind_materialization(self, child) -> None:
        from .build_inputs import BuildInputs
        self.owner()
        require(type(child) is BuildInputs and child.invocation is self.operation.invocation
                and child.project is child.invocation.project_owner and child.cancellation is self.guard
                and child.invocation.signing_lease is None and self.materialization is None
                and self.operation.stage == "materializing-signing" and self.validation_passed)
        self.materialization = child  # Before its scratch constructor, admission or yield.

    def bind_materialized(self, values) -> None:
        from .credentials import _MaterializedBuildEnvironment
        self.operation.checkpoint()
        child = self.materialization
        require(type(values) is _MaterializedBuildEnvironment and child is not None
                and self.materialized is None and values._inputs is child
                and values._invocation is self.operation.invocation and values._cancellation is self.guard
                and values._live and values._lease is None and values._specifier is None
                and child.invocation.child is child and child.prepared and not child.claimed)
        self.materialized = values
        self.require_materialized(child)

    def require_materialized(self, child) -> None:
        self.owner()
        values = self.materialized
        require(child is self.materialization and child is not None and values is not None
                and values._live and values._inputs is child and values._invocation is self.operation.invocation
                and values._cancellation is self.guard and values._lease is None and values._specifier is None
                and child.invocation.child is child and child.invocation.signing_lease is None
                and child.prepared and not child.claimed and self.validation_passed)
        snapshot = child.scratch.require_input("android-keystore")
        require(values.get("MOBILE_RELEASE_ANDROID_KEYSTORE_PATH") == str(child.scratch.require(snapshot)))
        expected = {"MOBILE_RELEASE_ANDROID_KEYSTORE_PATH", "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
                    "MOBILE_RELEASE_ANDROID_KEY_ALIAS", "MOBILE_RELEASE_ANDROID_KEY_PASSWORD"}
        if any(row["kind"] == "project-read-token" for row in self.operation.request.context["signing"]["assignments"]):
            expected.add("MOBILE_RELEASE_PROJECT_READ_TOKEN")
        require(set(values) == expected)
        for name in expected - {"MOBILE_RELEASE_ANDROID_KEYSTORE_PATH"}:
            require(values[name] == self.values[name])

    def validation_command(self, scratch, snapshot, values) -> tuple[str, ...]:
        from .build_inputs import InputSnapshot
        operation = self.operation
        self.require_values(operation.inputs.config, values)
        require(operation.stage == "validating-signing" and self.validation_snapshot is None
                and self.scratches == [scratch] and scratch.layout == "signing-validation"
                and type(snapshot) is InputSnapshot and scratch.require_input("android-keystore") is snapshot)
        self.validation_snapshot = snapshot
        argv = operation.tools.signing_validation_command(self, scratch, snapshot)
        operation._arm("keytool-validate")
        return argv

    def validation_finished(self, findings) -> None:
        from .reporting import FAILING_STATUSES, Finding, Status
        self.owner()
        require(type(findings) is list and findings and all(type(item) is Finding for item in findings)
                and self.operation.stage == "validating-signing" and not self.validation_passed)
        self.validation_passed = all(item.status == Status.PASS for item in findings)
        if self.validation_passed:
            require(self.operation._returned.get("keytool-validate") == 0)
        else:
            require(any(item.status in FAILING_STATUSES for item in findings))
            if self.operation.failure is None:
                self.operation.failure = "signing-invalid"
            self.operation.source.failure_observed()  # Before validation scratch cleanup.

    def signing_command(self, path, output, child) -> tuple[str, ...]:
        operation = self.operation
        operation.require(operation.inputs.config, self.guard)
        self.require_materialized(child)
        require(operation.stage == "signing" and operation.files.signing_input is not None
                and operation.files.signing_input._native and path == operation.files.signing_input.path
                and output == operation.files.signing_output())
        argv = operation.tools.signing_command(self, path, output)
        operation._arm("jarsigner-sign")
        return argv

    def bind_command_slot(self, engine, slot) -> None:
        """Retain only the original jarsigner slot; no IO/STOP/native work.

        This runs before the existing command CleanupScope is registered. All
        checks here are original-object identity/scalar predicates only.
        """
        from ._command_process import CommandOutcomeSlot, _Outer
        from ._desktop_android_build_control import AndroidBuildInput
        from ._desktop_android_build_engine import _Engine
        from .desktop_android_build import AndroidBuildRun
        self.owner()
        operation, source = self.operation, self.operation.source
        original = source._engine
        require(type(source) is AndroidBuildInput and source.signed and source.active
                and source.request_returned and not source.close_claimed
                and self.guard._saved_command_input() is source and self.guard.depth == 0
                and type(original) is _Engine and original.input is source and original.guard is self.guard
                and type(original.service) is AndroidBuildRun and original.service.operation is operation
                and original.service.source is source and original.service.guard is self.guard
                and original.service.request is operation.request and original.request is operation.request
                and self.config_bound and self.validation_passed and not self.close_claimed
                and operation.failure is None and not operation.close_claimed
                and operation.stage == "signing" and operation._pending == "jarsigner-sign"
                and operation._roles["jarsigner-sign"] == "attempted"
                and operation._command_before["jarsigner-sign"] == 2
                and operation._returned.get("keytool-validate") == operation._returned.get("gradle") == 0
                and self.command_slot is None and self.command_application is None and self.command_service is None
                and not self.dispatch_claimed and not self.dispatch_published
                and type(engine) is _Outer and type(slot) is CommandOutcomeSlot
                and engine.guard is self.guard and engine.owns is False and engine._store_timing is None
                and engine.scope is None and engine.binding is None and engine.slot is slot
                and engine._android_signing is self and slot._engine is engine and slot._scope is None
                and slot._nonce == engine.nonce and slot.read() is None
                and self.guard.lifetime_ledger._command is slot
                and engine.ctx.guard is self.guard and not engine.ctx.suppress_cancel
                and engine.phase == "NEW" and not engine.cleanup_entered)
        self.command_application, self.command_service = original, original.service
        self.command_slot = slot

    def command_dispatched(self, engine, slot) -> None:
        """Consume the exact post-RUN_TOOL event before writing its progress."""
        from ._command_process import CommandOutcomeSlot, Tag, _Outer, _Wire
        self.owner()
        operation, source = self.operation, self.operation.source
        try:
            require(type(engine) is _Outer and type(slot) is CommandOutcomeSlot
                    and self.command_slot is slot and slot._engine is engine and engine.slot is slot
                    and slot._nonce == engine.nonce and slot.read() is None and engine._android_signing is self
                    and self.command_application is not None and source._engine is self.command_application
                    and self.command_application.input is source and self.command_application.guard is self.guard
                    and self.command_application.service is self.command_service and self.command_service is not None
                    and self.command_service.source is source and self.command_service.guard is self.guard
                    and self.command_service.operation is operation
                    and self.command_service.request is self.command_application.request is operation.request
                    and engine.guard is self.guard and engine.ctx.guard is self.guard
                    and engine.owns is False and engine.scope is None and engine.binding is None
                    and engine._store_timing is None and slot._scope is None and not engine.ctx.suppress_cancel
                    and self.guard.lifetime_ledger._command is slot and self.guard._saved_command_input() is source
                    and self.guard.depth == 0 and source.active and not source.close_claimed
                    and not operation.close_claimed and operation.failure is None and not self.close_claimed
                    and self.config_bound and self.validation_passed
                    and operation.stage == "signing" and operation._pending == "jarsigner-sign"
                    and operation._roles["jarsigner-sign"] == "attempted"
                    and operation._command_before["jarsigner-sign"] == 2
                    and operation._returned.get("keytool-validate") == operation._returned.get("gradle") == 0
                    and not self.dispatch_claimed and not self.dispatch_published
                    and engine.phase == "RUNNING" and engine.ready and not engine.cleanup_entered
                    # _send pumps after the final write: its own natural
                    # PRODUCERS_SEALED may already have retired launch. The
                    # operation/slot is still live; never revive that route or
                    # accept unrelated/manual/failed retirement as this event.
                    and type(engine.sealed) is bool and engine.ctx.launch_retired is engine.sealed
                    and engine.run_route.retired is engine.sealed
                    and not engine.ctx.stopped and engine.ctx.primary is None
                    and engine.run_route.tag is Tag.RUN_TOOL and engine.run_route.attempted
                    and type(engine.wire) is _Wire
                    and engine.wire.ctx is engine.ctx and engine.wire.out is None
                    and not engine.wire.write_failed and not engine.wire.write_in_flight
                    and not engine.wire.poisoned and not engine.protocol_failed and not engine.output_failed
                    and engine.wire.sent[-1:] == [Tag.RUN_TOOL] and engine.wire.sent.count(Tag.RUN_TOOL) == 1)
            self.dispatch_claimed = True  # A partial/failed frame can never be replayed.
            source.progress("signing")
            self.dispatch_published = True
        except BaseException as error:
            # Before original command cleanup; reached work and first failure
            # survive even a lost progress-write return. The existing caller
            # still records the role failure after C/A/W finality.
            if operation.failure is None:
                operation.failure = "signing-incomplete"
            source.failure_observed()
            self.guard.lifetime_ledger._remember(error)
            raise

    def observed_exit(self) -> int | None:
        """Passive exact-slot wait DATA, never successful command-return authority.

        Used to reject a too-late cancellation observation. A normal exit already
        received by the original owner cannot become an apparently live signer
        merely because STOP prevented the Python run_owned return.
        """
        from ._command_process import CommandOutcomeSlot, OriginalCommandFinality, OriginalCommandOutcome, RouteHistory, _Outer
        self.owner()
        slot = self.command_slot
        if type(slot) is not CommandOutcomeSlot:
            return None
        engine, observed = slot._engine, slot.read()
        if (type(engine) is not _Outer or engine.slot is not slot or engine._android_signing is not self
                or engine.guard is not self.guard or engine.ctx.guard is not self.guard or engine.owns is not False
                or engine.scope is not None or engine.binding is not None or engine._store_timing is not None
                or self.command_application is None or self.operation.source._engine is not self.command_application
                or self.command_application.input is not self.operation.source or self.command_application.guard is not self.guard
                or self.command_service is None or self.command_application.service is not self.command_service
                or self.command_service.operation is not self.operation or self.command_service.source is not self.operation.source
                or self.command_service.guard is not self.guard
                or self.command_service.request is not self.operation.request
                or self.command_application.request is not self.operation.request
                or slot._scope is not None or slot._nonce != engine.nonce
                or type(observed) is not OriginalCommandOutcome or observed._engine is not engine
                or observed.nonce != slot._nonce or type(observed.original_finality) is not OriginalCommandFinality
                or observed.original_finality._engine is not engine or observed.no_target is not None
                or type(observed.create_w) is not RouteHistory or type(observed.run_tool) is not RouteHistory
                or observed.create_w.attempted is not True or observed.create_w.retired is not True
                or observed.termination != "normal-exit" or observed.run_tool.attempted is not True
                or observed.run_tool.retired is not True or engine.phase != "CLOSED"
                or type(observed.returncode) is not int or not 0 <= observed.returncode < 2 ** 31):
            return None
        return observed.returncode

    def command_environment(self, base: dict[str, str], role: str) -> dict[str, str]:
        self.owner()
        require(type(base) is dict and role in {"keytool-validate", "gradle", "jarsigner-sign"})
        if role == "gradle":
            self.require_materialized(self.materialization)
            base.update(self.materialized)
            base["MOBILE_RELEASE_REQUIRE_SIGNING"] = "true"
        else:
            require(self.values is not None)
            if role == "jarsigner-sign":
                self.require_materialized(self.materialization)
            for name in ("MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD", "MOBILE_RELEASE_ANDROID_KEY_PASSWORD"):
                base[name] = self.values[name]
            base["LC_ALL"] = "C"
        return base

    def known_descriptor(self, number: int) -> bool:
        self.owner()
        for scratch in self.scratches:
            if any(slot.number == number for slot in (scratch.slot, *scratch.parent.slots, *scratch.writer_slots)):
                return True
        child = self.materialization
        return child is not None and (child.slot.number == number
            or any(slot.number == number for slot in child.control_slots)
            or any(any(slot.number == number for slot in parent.slots) for parent in child.parents.values()))

    def dependents_settled_for(self, *, owner, cancellation) -> bool:
        self.owner()
        require(cancellation is self.guard and any(item is owner for item in self.scratches)
                and owner._desktop_binding is self)
        files = self.operation.files
        return (self.operation.commands_settled()
                and (files is None or files.signing_input is None or not files.signing_input._native))

    def inputs_closed(self) -> bool:
        self.owner()
        child = self.materialization
        for scratch in self.scratches:
            ended = (child is not None and child.scratch is scratch and child.claimed and child._cleanup_complete
                     if scratch.layout == "build" else scratch.claimed and not scratch.active and scratch._cleanup_complete)
            if (not ended or scratch.created or scratch.creation["state"] not in {"NEW", "NO_EFFECT", "RETIRED"}
                    or any(slot.close_state != "CLOSED" or slot.number is not None for slot in
                           (scratch.slot, *scratch.writer_slots, *scratch.parent.slots))):
                return False
        if child is None:
            return True
        return (child.claimed and child._cleanup_complete and not child.created
                and child.creation["state"] in {"NEW", "NO_EFFECT", "RETIRED"}
                and all(slot.close_state == "CLOSED" and slot.number is None for slot in (child.slot, *child.control_slots))
                and all(all(slot.close_state == "CLOSED" and slot.number is None for slot in parent.slots)
                        for parent in child.parents.values()))

    def activity(self) -> dict:
        self.owner()
        child = self.materialization
        state = ("not-started" if child is None else "restored" if self.inputs_closed()
                 else "unknown" if child.claimed else "active")
        return {"validationCommand": self.operation.role_outcome("keytool-validate"),
                "validationPassed": self.validation_passed,
                "signingCommand": self.operation.role_outcome("jarsigner-sign"), "materialization": state}

    def retire_values(self) -> None:
        self.owner()
        require(self.inputs_closed() and self.operation.closed()
                and (self.materialized is None or not self.materialized._live))
        if self.materialized is not None:
            dict.clear(self.materialized)
        self.values = None  # Same finality gate as the original private reader, not a secure-erasure claim.

    def close(self) -> None:
        """Fallback for constructor loss; do not retry already consuming cleanup."""
        self.owner()
        if self.close_claimed:
            require(self.inputs_closed())
            return
        self.close_claimed = True
        first = None
        child = self.materialization
        actions = [child.cleanup] if child is not None and not child.claimed else []
        actions.extend(item.cleanup for item in self.scratches
                       if item.layout == "signing-validation" and not item.claimed)
        for action in actions:
            try:
                action()
            except BaseException as error:
                self.operation.source.failure_observed()
                self.operation.cleanup_errors.append(error)
                self.guard.lifetime_ledger._remember(error)
                if first is None:
                    first = error
        if first is not None:
            raise first
        if not self.inputs_closed():
            from .build_inputs import _cleanup_failure
            raise _cleanup_failure(self.guard, ValueError("Original Android inputs did not settle")) from None
