"""The finite signing facet of one original saved Android build.

No Apple account state, second process owner, ambient credentials or renderer
material provider. The original invocation owns the one BuildInputs child.
"""
from __future__ import annotations

from ._desktop_android_build_protocol import is_signed, require
from .build_inputs import BuildInputs, FiniteScratch
from .reporting import Status


class SignedAndroidOperation:
    def __init__(self, operation) -> None:
        from .android_build_operation import AndroidBuildOperation
        require(type(operation) is AndroidBuildOperation and is_signed(operation.request.context)
                and operation.source.signed)
        self.operation, self.guard = operation, operation.guard
        self.materialization: BuildInputs | None = None
        self.scratch: FiniteScratch | None = None
        self.values = self.materialized = None
        self.materialized_retired = True
        self.input_checked = False
        self.phase = "admitting"

    def owner(self) -> None:
        self.operation.owner()
        require(self.operation.signing is self)

    def bind_values(self) -> None:
        from ._desktop_android_signing_material import PrivateAndroidMaterial
        self.owner()
        require(self.values is None and type(self.operation.source.material) is PrivateAndroidMaterial)
        self.values = self.operation.source.material.bind(self.operation)

    def bind_materialization(self, child) -> None:
        self.owner()
        require(type(child) is BuildInputs and child.invocation is self.operation.invocation
                and child.cancellation is self.guard and self.materialization is child
                and self.values is not None and self.phase == "materializing")
        require(self.scratch is child.scratch)

    def bind_scratch(self, scratch) -> None:
        self.owner()
        require(type(scratch) is FiniteScratch and scratch.layout == "build" and self.scratch is None
                and scratch.cancellation is self.guard and scratch.journal is not None
                and type(scratch.journal) is BuildInputs and self.materialization is None
                and scratch.journal.invocation is self.operation.invocation
                and scratch.journal.cancellation is self.guard)
        self.scratch = scratch  # Original before any acquisition/constructor return.
        self.materialization = scratch.journal
        # The outer BuildInputs constructor has not returned/assigned scratch
        # yet. Root the exact pair now so a lost constructor return has a close.
        self.materialization.scratch = scratch

    def scratch_checkpoint(self, scratch) -> None:
        self.owner()
        require(scratch is self.scratch and scratch.journal is not None
                and (self.materialization is None or scratch.journal is self.materialization))
        if scratch.claimed or self.guard.depth:
            self.operation.cleanup_checkpoint()
        else:
            self.operation._tick()

    def bind_materialized(self, values) -> None:
        from .credentials import _MaterializedBuildEnvironment
        self.owner()
        require(type(values) is _MaterializedBuildEnvironment and values._live
                and values._inputs is self.materialization and values._invocation is self.operation.invocation
                and values._cancellation is self.guard and values._lease is None
                and self.materialized is None and self.materialized_retired)
        self.materialized, self.materialized_retired = values, False
        self.command_inputs()

    def command_inputs(self) -> tuple[object, str, str, str]:
        self.owner()
        self.operation.checkpoint()
        child, values = self.materialization, self.materialized
        from .credentials import _MaterializedBuildEnvironment
        require(type(child) is BuildInputs and child is self.operation.invocation.child
                and child.invocation is self.operation.invocation and not child.claimed and child.prepared
                and child.scratch is self.scratch and self.operation.invocation.signing_lease is None
                and type(values) is _MaterializedBuildEnvironment and values._live
                and values._inputs is child and not self.materialized_retired)
        snapshot = child.scratch.require_input("android-keystore")
        keystore = child.scratch.require(snapshot)
        require(values.get("MOBILE_RELEASE_ANDROID_KEYSTORE_PATH") == str(keystore))
        names = ("MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD", "MOBILE_RELEASE_ANDROID_KEY_ALIAS",
                 "MOBILE_RELEASE_ANDROID_KEY_PASSWORD")
        scalars = tuple(values.get(name) for name in names)
        require(all(type(value) is str and 0 < len(value.encode("utf-8")) <= 8192 and "\0" not in value
                    for value in scalars) and not scalars[1].startswith("-"))
        require(self.values is not None and all(self.values[name] == value for name, value in zip(names, scalars)))
        return keystore, scalars[0], scalars[1], scalars[2]

    def command_environment(self) -> dict[str, str]:
        _, store_password, _, key_password = self.command_inputs()
        environment = self.operation.command_environment()  # Fixed fresh noncredential map.
        environment.update(MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD=store_password,
                           MOBILE_RELEASE_ANDROID_KEY_PASSWORD=key_password)
        return environment

    def validate_input(self) -> None:
        """Run the shared private-key/certificate policy on one protected return."""
        from .credentials import android_material_finding
        from .owned_process import run_owned
        self.owner()
        require(not self.input_checked and self.phase == "materializing")
        self.phase = "validating-signing"
        operation = self.operation
        argv = operation.keystore_command()
        try:
            result = run_owned(argv, cwd=operation.root, environ=self.command_environment(), capture=True,
                               timeout=30, output_limit=2 * 1024 * 1024, cancellation=self.guard)
            operation.returned("keytool-input", result.returncode)
        except BaseException as error:
            operation.command_error("keytool-input", error)
            raise
        if result.returncode:
            operation.fail("signing-validation-failed")
        self.command_inputs()
        finding = android_material_finding(operation.inputs.config, result.returncode, result.stdout, result.stderr)
        if finding.status is not Status.PASS:
            operation.fail("signing-validation-failed")
        self.input_checked = True

    def inputs_closed(self) -> bool:
        self.owner()
        child, scratch = self.materialization, self.scratch
        if scratch is None:
            return child is None
        if child is None:
            # A constructor never entered its scope, but original slots still
            # need their normal owner cleanup; do not invent closure here.
            return False
        return (scratch is child.scratch and child.claimed and child._cleanup_complete
                and not child.created and child.creation["state"] in {"NEW", "NO_EFFECT", "RETIRED"}
                and not scratch.created and scratch.creation["state"] in {"NEW", "NO_EFFECT", "RETIRED"}
                and all(slot.close_state == "CLOSED" for slot in
                        (child.slot, scratch.slot, *scratch.writer_slots, *scratch.parent.slots, *child.control_slots))
                and all(all(slot.close_state == "CLOSED" for slot in parent.slots) for parent in child.parents.values()))

    def known_descriptor(self, number: int) -> bool:
        """Lend only live slots of this original child to bounded enumeration."""
        self.owner()
        child, scratch = self.materialization, self.scratch
        if child is None or scratch is None or scratch is not child.scratch:
            return False
        slots = (child.slot, scratch.slot, *scratch.writer_slots, *scratch.parent.slots,
                 *child.control_slots, *(slot for parent in child.parents.values() for slot in parent.slots))
        return any(slot.number == number and slot.open_state == "OPEN" and slot.close_state == "NOT_ATTEMPTED" for slot in slots)

    def close(self) -> None:
        self.owner()
        child = self.materialization
        if child is not None and not child.claimed:
            # Only a constructor which never entered its ordinary scope may
            # need this fallback. Do not retry an attempted/failed close.
            require(self.operation.invocation.child is None)
            child.cleanup()
        require(self.inputs_closed())
        if self.materialized is not None and not self.materialized_retired:
            require(not self.materialized._live and self.materialized._inputs is self.materialization)
            self.materialized.clear()  # Reference retirement, not secure erasure.
            self.materialized_retired = True

    def closed(self) -> bool:
        return self.inputs_closed() and self.materialized_retired
