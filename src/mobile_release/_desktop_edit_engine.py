"""One original synchronous native typed-edit child, no descendants.

Only desktop/config_edit_bootstrap.py admits this entry point. It is neither a
CLI mutation method nor the passive engine. The native capability gate remains
closed; this source alone does not qualify a runtime or filesystem backend.
"""
from __future__ import annotations

import os
import select
import sys
import time
from pathlib import Path
from typing import Any

from ._desktop_edit_control import EditInput
from ._desktop_edit_protocol import (EditRequest, ProtocolError, PROTOCOL, WORKFLOW_PROTOCOL, METADATA_PROTOCOL, VERSION_PROTOCOL, IMAGES_PROTOCOL,
                                     registered_identity, response)
from .build_inputs import _attempt_all
from .cancellation import CleanupScope, DefaultCancellation
from .config_edit import (ConfigEditFailure, CoreEditOutcome, apply_config_edit,
                          capture_config_edit, discard_config_edit, prepare_config_edit)
from .errors import ValidationError
from .github_workflow_edit import (WorkflowConflict, apply_github_workflow_edit,
                                   capture_github_workflow_edit, discard_github_workflow_edit,
                                   prepare_github_workflow_edit)
from .github_workflow_recovery import (apply_github_workflow_recovery, capture_github_workflow_recovery,
                                       discard_github_workflow_recovery, prepare_github_workflow_recovery,
                                       recovery_outcome as workflow_recovery_outcome)
from .init_transaction import InitApplyOutcome, InitOperationFailure, TypedEditProfile
from .init_workspace_custody import InitRootLease
from .metadata_text_edit import (apply_metadata_text_edit, capture_metadata_text_edit,
                                 discard_metadata_text_edit, prepare_metadata_text_edit)
from .release_version_edit import (apply_release_version_edit, capture_release_version_edit,
                                   discard_release_version_edit, prepare_release_version_edit)
from .metadata_images_edit import (apply_metadata_images_edit, capture_metadata_images_edit,
                                   discard_metadata_images_edit, prepare_metadata_images_edit)

from .saved_text_recovery import (apply_saved_text_recovery, capture_saved_text_recovery,
                                  discard_saved_text_recovery, prepare_saved_text_recovery,
                                  recovery_outcome as saved_text_recovery_outcome)


def _root(value: str) -> Path:
    # Validate the exact original UTF-8 native registry string BEFORE Path can
    # normalize a double separator or dot component into different authority.
    try:
        parts = value.split("/")
        valid = (value.startswith("/") and not value.startswith("//")
                 and len(value.encode("utf-8")) <= 4096 and 1 < len(parts) <= 128
                 and all(part not in {"", ".", ".."} and len(part.encode("utf-8")) <= 255
                         and not part.endswith((" ", "."))
                         and not any(ord(c) < 32 or ord(c) == 127 or c in "\\:" for c in part)
                         for part in parts[1:]))
    except (AttributeError, UnicodeError):
        valid = False
    if not valid:
        raise ConfigEditFailure(CoreEditOutcome("not_started", "not_created", "settled", "invalid_params"))
    return Path(value)


class _Engine:
    def __init__(self, started: float, *, workflows: bool = False, domain: str | None = None) -> None:
        if type(workflows) is not bool or domain is not None and workflows:
            raise ProtocolError("Invalid fixed edit domain")
        selected = ("github_workflows" if workflows else "configuration") if domain is None else domain
        if type(selected) is not str or selected not in {"configuration", "github_workflows", "metadata_text", "release_version", "metadata_images"}:
            raise ProtocolError("Invalid fixed edit domain")
        self.domain = selected
        self.workflows = selected == "github_workflows"  # Existing private constructor compatibility.
        self.guard = DefaultCancellation(ValidationError, "configuration edit custody did not settle")
        protocol = {"configuration": PROTOCOL, "github_workflows": WORKFLOW_PROTOCOL,
                    "metadata_text": METADATA_PROTOCOL, "release_version": VERSION_PROTOCOL,
                    "metadata_images": IMAGES_PROTOCOL}[selected]
        self.input = EditInput(started, protocol=protocol)
        self.lease: InitRootLease | None = None
        self.authority: Any = None
        self.last_request: EditRequest | None = None
        self.published_token: str | None = None
        self.outcome: CoreEditOutcome | InitApplyOutcome | None = None
        self.conflict: WorkflowConflict | None = None
        self.image_intent: str | None = None
        self.workflow_intent: str | None = None
        self.saved_text_recovery = False
        self.first: BaseException | None = None
        self.frames = 0
        self.stdout_bytes = 0
        self.output_owned = False
        self.output_closed = False
        self.error_owned = False
        self.error_closed = False

    def _remember(self, error: BaseException) -> None:
        if self.first is None:
            self.first = error
        if type(error) is ConfigEditFailure:
            proposed = error.outcome
        elif type(error) is InitOperationFailure:
            proposed = CoreEditOutcome(error.outcome.effect, error.outcome.journal,
                                       error.outcome.resources, error.outcome.reason)
        else:
            proposed = CoreEditOutcome("not_started", "not_created", "settled",
                                       "cancelled" if isinstance(error, KeyboardInterrupt) else
                                       "invalid_params" if isinstance(error, ProtocolError) else "filesystem_error")
        # pending_state from a read-only recovery inspection is not a first
        # failure. Latch this actual failure without losing inspected facts.
        if self.domain == "github_workflows" and self.workflow_intent == "recover" and self.lease is not None:
            workflow_recovery_outcome(self.lease, reason=proposed.reason)
        if self.saved_text_recovery and self.lease is not None:
            saved_text_recovery_outcome(self.lease, reason=proposed.reason)
        native = self.lease.last_outcome if self.lease is not None else None
        current = self.outcome
        # A workspace fact survives a lost core-call return. This is retained
        # original-owner state, not a new path observer or inferred phase.
        if native is not None and (native.effect != "not_started" or native.journal != "not_created"
                                   or native.resources == "unknown"):
            effect, journal, resources = native.effect, native.journal, native.resources
        elif current is not None:
            effect, journal, resources = current.effect, current.journal, current.resources
        else:
            effect, journal, resources = proposed.effect, proposed.journal, proposed.resources
        if (self.saved_text_recovery or self.domain == "github_workflows" and self.workflow_intent == "recover") and native is not None:
            reason = native.reason  # Its recovery ledger, not display pending_state, owns the first actual failure.
        else:
            reason = (current.reason if current is not None and current.reason != "none" else
                      native.reason if native is not None and native.reason != "none" else proposed.reason)
        if proposed.resources == "unknown":
            resources = "unknown"
        self.outcome = CoreEditOutcome(effect, journal, resources, reason)

    def _discard_outcome(self) -> CoreEditOutcome | InitApplyOutcome:
        if self.saved_text_recovery and self.lease is not None:
            # Inspected attention is not a failed save. Keep its original ledger;
            # do not relax normal CoreEditOutcome or synthesize a primary error.
            return saved_text_recovery_outcome(self.lease)
        if self.domain == "github_workflows" and self.workflow_intent == "recover" and self.lease is not None:
            observed = workflow_recovery_outcome(self.lease)
            return CoreEditOutcome(observed.effect, observed.journal, observed.resources, observed.reason)
        return CoreEditOutcome("not_started", "not_created", "settled", "none")

    def _check_workflow_intent(self, request: EditRequest) -> None:
        if self.domain in {"metadata_text", "release_version"} and (request.params.get("intent") == "recover") != self.saved_text_recovery:
            raise ProtocolError("Saved-text edit and recovery intents cannot be exchanged")
        if self.domain == "github_workflows" and request.params.get("intent", "edit") != self.workflow_intent:
            raise ProtocolError("Workflow edit and current-inspection recovery intents cannot be exchanged")

    def cleanup(self) -> None:
        def retire() -> None:
            if self.authority is not None:
                if self.saved_text_recovery:
                    discard_saved_text_recovery(self.authority)
                elif self.domain == "github_workflows":
                    if self.workflow_intent == "recover":
                        discard_github_workflow_recovery(self.authority)
                    else:
                        discard_github_workflow_edit(self.authority)
                elif self.domain == "metadata_text":
                    discard_metadata_text_edit(self.authority)
                elif self.domain == "release_version":
                    discard_release_version_edit(self.authority)
                elif self.domain == "metadata_images":
                    if self.image_intent == "recover":
                        from .metadata_images_recovery import discard_metadata_images_recovery
                        discard_metadata_images_recovery(self.authority)
                    else:
                        discard_metadata_images_edit(self.authority)
                elif self.domain == "configuration":
                    discard_config_edit(self.authority)
                else:
                    raise ProtocolError("Invalid fixed edit domain")
        actions = [retire]
        if self.lease is not None:
            actions.append(self.lease.close)
        actions.append(self.input.close)
        _attempt_all(self.guard, actions)

    def write(self, raw: bytes, *, terminal: bool = False) -> None:
        if self.frames >= 3 or self.stdout_bytes + len(raw) > 12 * 1024 * 1024:
            raise ProtocolError("Edit output exceeded its bound")
        self.frames += 1
        self.stdout_bytes += len(raw)
        remaining = memoryview(raw)
        # Terminal output follows root/handler settlement and has only a small
        # local bounded delivery allowance. It cannot restart native cleanup.
        end = time.monotonic() + 2.0 if terminal else None
        while remaining:
            if not terminal:
                self.guard.check()
            elif end is not None and time.monotonic() >= end:
                raise ProtocolError("Edit terminal delivery did not settle")
            try:
                count = os.write(1, remaining[:64 * 1024])
                if count <= 0:
                    raise ProtocolError("Edit output made no progress")
                remaining = remaining[count:]
            except BlockingIOError:
                select.select([], [1], [], 0.1)

    def run(self) -> None:
        self.guard.install()
        self.input.acquire()
        self.guard._install_edit_source(self.input)
        # Fixed inherited standard descriptors, never renderer-controlled paths.
        self.output_owned = True
        os.set_blocking(1, False)
        self.error_owned = True
        self.guard.activate()
        request = self.input.request(0, None)
        self.last_request = request
        self.guard.check()
        root = _root(request.params["root"])
        self.saved_text_recovery = self.domain in {"metadata_text", "release_version"} and request.params.get("intent") == "recover"
        if self.domain == "github_workflows":
            self.workflow_intent = request.params.get("intent", "edit")
            # The closed lease compares all five facts to raw original fstat on
            # acquire and subsequent checks BEFORE any workflow observation.
            self.lease = InitRootLease(root, cancellation=self.guard,
                profile=TypedEditProfile.GITHUB_WORKFLOWS,
                registered_identity=registered_identity(request.params["registeredIdentity"]),
                workflow_recovery=self.workflow_intent == "recover")
        elif self.domain == "metadata_text":
            self.lease = InitRootLease(root, cancellation=self.guard,
                profile=TypedEditProfile.METADATA_TEXT,
                registered_identity=registered_identity(request.params["registeredIdentity"]),
                saved_text_recovery=self.saved_text_recovery)
        elif self.domain == "release_version":
            self.lease = InitRootLease(root, cancellation=self.guard,
                profile=TypedEditProfile.RELEASE_VERSION,
                registered_identity=registered_identity(request.params["registeredIdentity"]),
                saved_text_recovery=self.saved_text_recovery)
        elif self.domain == "metadata_images":
            self.image_intent = request.params["intent"]
            self.lease = InitRootLease(root, cancellation=self.guard,
                profile=TypedEditProfile.METADATA_IMAGES,
                registered_identity=registered_identity(request.params["registeredIdentity"]),
                image_recovery=self.image_intent == "recover")
        elif self.domain == "configuration":
            self.lease = InitRootLease(root, cancellation=self.guard)
        else:
            raise ProtocolError("Invalid fixed edit domain")
        self.lease.acquire()
        if self.saved_text_recovery:
            checkout = capture_saved_text_recovery(self.lease)
        elif self.domain == "github_workflows":
            checkout = (capture_github_workflow_recovery(self.lease) if self.workflow_intent == "recover" else
                        capture_github_workflow_edit(self.lease))
        elif self.domain == "metadata_text":
            checkout = capture_metadata_text_edit(self.lease, request.params["platform"], request.params["locale"])
        elif self.domain == "release_version":
            checkout = capture_release_version_edit(self.lease)
        elif self.domain == "metadata_images":
            if self.image_intent == "recover":
                from .metadata_images_recovery import capture_metadata_images_recovery
                checkout = capture_metadata_images_recovery(self.lease)
            else:
                images = request.params.pop("images")
                try:
                    checkout = capture_metadata_images_edit(self.lease, request.params["platform"],
                        request.params["locale"], request.params["assetType"], images,
                        request.params["protectedSources"], request.params["protectedObjects"])
                finally:
                    del images
        elif self.domain == "configuration":
            checkout = capture_config_edit(self.lease)
        else:
            raise ProtocolError("Invalid fixed edit domain")
        self.authority = checkout
        if self.saved_text_recovery:
            opened = response(request, "opened", {"revision": checkout.revision, "recovery": checkout.view,
                                                  "scopeResources": "settled"})
        elif self.domain == "github_workflows":
            details = ({"recovery": checkout.view} if self.workflow_intent == "recover" else
                       {"observed": checkout.observed})
            opened = response(request, "opened", {"revision": checkout.revision, **details, "scopeResources": "settled"})
        elif self.domain == "metadata_text":
            opened = response(request, "opened", {"revision": checkout.revision, "metadataRoot": checkout.metadata_root,
                                                  "baseline": checkout.baseline, "scopeResources": "settled"})
        elif self.domain == "release_version":
            selected = checkout.selection
            opened = response(request, "opened", {"revision": checkout.revision, "source": selected.source,
                "nameKey": selected.name_key, "buildKey": selected.build_key, "iosEnabled": selected.ios_enabled,
                "values": checkout.values, "baseline": checkout.baseline, "scopeResources": "settled"})
        elif self.domain == "metadata_images":
            opened = response(request, "opened", {"intent": checkout.intent, "revision": checkout.revision,
                "baseline": checkout.baseline, "view": checkout.view, "scopeResources": "settled"})
        elif self.domain == "configuration":
            opened = response(request, "opened", {"revision": checkout.revision, "base": checkout.base,
                                                  "scopeResources": "settled"})
        else:
            raise ProtocolError("Invalid fixed edit domain")
        self.input.idle()
        self.write(opened)
        request = self.input.request(1, request.session)
        self.last_request = request
        self.guard.check()
        if request.op == "discard":
            self.outcome = self._discard_outcome()
            return
        self._check_workflow_intent(request)
        if self.saved_text_recovery:
            plan = prepare_saved_text_recovery(self.lease, checkout, request.params["revision"])
        elif self.domain == "github_workflows":
            plan = (prepare_github_workflow_recovery(self.lease, checkout, request.params["revision"])
                    if self.workflow_intent == "recover" else
                    prepare_github_workflow_edit(self.lease, checkout, request.params["revision"],
                        request.params["draft"], request.params["toolingRepository"], request.params["toolingSha"]))
            if type(plan) is WorkflowConflict:
                # A refused review has no token and no prepared frame. Settle
                # the same original lease/input before the bounded terminal.
                self.conflict, self.outcome = plan, plan.outcome
                # Keep the original retired checkout for idempotent discard;
                # detached conflict DATA is never an authority to clean up.
                return
        elif self.domain == "metadata_text":
            plan = prepare_metadata_text_edit(self.lease, checkout, request.params["revision"],
                                             request.params["expectedBaseline"], request.params["fields"])
        elif self.domain == "release_version":
            plan = prepare_release_version_edit(self.lease, checkout, request.params["revision"],
                request.params["expectedBaseline"], request.params["intent"], request.params["values"])
        elif self.domain == "metadata_images":
            if self.image_intent == "recover":
                from .metadata_images_recovery import prepare_metadata_images_recovery
                plan = prepare_metadata_images_recovery(self.lease, checkout, request.params["revision"],
                    request.params["expectedBaseline"], request.params["choices"])
            else:
                plan = prepare_metadata_images_edit(self.lease, checkout, request.params["revision"],
                    request.params["expectedBaseline"], request.params["choices"])
        elif self.domain == "configuration":
            plan = prepare_config_edit(self.lease, checkout, request.params["revision"],
                                       request.params["expectedBase"], request.params["draft"])
        else:
            raise ProtocolError("Invalid fixed edit domain")
        self.authority = plan
        details = {"recovery" if self.saved_text_recovery or self.domain == "github_workflows" and self.workflow_intent == "recover" else "view": plan.view}
        prepared = response(request, "prepared", {"revision": plan.revision, "planToken": plan.token,
                                                   **details, "scopeResources": "settled"})
        self.input.idle()
        # Default signals are deferred only through publication of this exact
        # frame/token receipt, not the review wait or a transaction operation.
        with self.guard.deferred(check_on_exit=False):
            self.write(prepared)
            self.published_token = plan.token
        request = self.input.request(2, request.session)
        self.last_request = request
        self.guard.check()
        if request.op == "discard":
            self.outcome = self._discard_outcome()
            return
        self._check_workflow_intent(request)
        if request.params["planToken"] != plan.token:
            raise ProtocolError("The original plan token is required")
        if self.saved_text_recovery:
            self.outcome = apply_saved_text_recovery(self.lease, plan)
        elif self.domain == "github_workflows":
            self.outcome = (apply_github_workflow_recovery(self.lease, plan) if self.workflow_intent == "recover" else
                            apply_github_workflow_edit(self.lease, plan))
        elif self.domain == "metadata_text":
            self.outcome = apply_metadata_text_edit(self.lease, plan)
        elif self.domain == "release_version":
            self.outcome = apply_release_version_edit(self.lease, plan)
        elif self.domain == "metadata_images":
            if self.image_intent == "recover":
                from .metadata_images_recovery import apply_metadata_images_recovery
                self.outcome = apply_metadata_images_recovery(self.lease, plan)
            else:
                self.outcome = apply_metadata_images_edit(self.lease, plan)
        elif self.domain == "configuration":
            self.outcome = apply_config_edit(self.lease, plan)
        else:
            raise ProtocolError("Invalid fixed edit domain")

    def terminal(self) -> None:
        if self.last_request is None:
            raise ProtocolError("No accepted edit request")
        outcome = self.outcome
        if outcome is None and (self.saved_text_recovery or self.domain == "github_workflows" and self.workflow_intent == "recover"):
            outcome = self._discard_outcome()
        if outcome is None and self.domain == "metadata_images" and self.image_intent == "recover" and self.lease is not None:
            observed = self.lease.last_outcome
            outcome = CoreEditOutcome(observed.effect, observed.journal, observed.resources, observed.reason)
        outcome = outcome or CoreEditOutcome("not_started", "not_created", "settled", "none")
        if (not self.input.closed or self.lease is not None and not self.lease.closed
                or self.guard.handler_state != "RESTORED" or self.guard.lifetime_ledger.fatal):
            outcome = CoreEditOutcome(outcome.effect, outcome.journal, "unknown",
                                      outcome.reason if outcome.reason != "none" else "custody_unknown")
        self.outcome = outcome
        result = {
            "planToken": self.published_token, "effect": outcome.effect, "journal": outcome.journal,
            "resources": outcome.resources, "reason": outcome.reason,
        }
        if self.domain in {"github_workflows", "metadata_text", "release_version", "metadata_images"}:
            result["kind"] = "outcome"
            if self.domain == "github_workflows" and self.conflict is not None:
                del result["planToken"]
                result.update(kind="conflict", revision=self.conflict.revision, conflict=self.conflict.view)
        self.write(response(self.last_request, "terminal", result), terminal=True)

    def close_output(self) -> None:
        first: BaseException | None = None
        for name, number in (("error", 2), ("output", 1)):
            if getattr(self, name + "_owned") and not getattr(self, name + "_closed"):
                setattr(self, name + "_owned", False)  # Retire BEFORE sole close.
                try:
                    os.close(number)
                    setattr(self, name + "_closed", True)
                except BaseException as error:
                    if first is None:
                        first = error
        if first is not None:
            raise first


def main(*, started: float | None = None, workflows: bool = False, domain: str | None = None) -> int:
    engine = _Engine(time.monotonic() if started is None else started, workflows=workflows, domain=domain)
    scope = CleanupScope(engine.guard, engine.cleanup, owns_cancellation=True, first_primary=True)
    try:
        try:
            try:
                with scope:
                    engine.run()
            finally:
                scope.__exit__(*sys.exc_info())
        except BaseException as error:
            engine._remember(error)
        engine.terminal()
        engine.close_output()
        return 0  # A delivered typed conflict can also exit zero; not Save.
    except BaseException:
        try:
            engine.close_output()
        except BaseException:
            pass
        return 78
