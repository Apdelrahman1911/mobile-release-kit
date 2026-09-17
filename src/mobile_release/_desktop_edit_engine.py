"""One original synchronous native configuration-edit child, no descendants.

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
from ._desktop_edit_protocol import EditRequest, ProtocolError, response
from .build_inputs import _attempt_all
from .cancellation import CleanupScope, DefaultCancellation
from .config_edit import (ConfigEditFailure, CoreEditOutcome, apply_config_edit,
                          capture_config_edit, discard_config_edit, prepare_config_edit)
from .errors import ValidationError
from .init_transaction import InitOperationFailure
from .init_workspace_custody import InitRootLease


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
    def __init__(self, started: float) -> None:
        self.guard = DefaultCancellation(ValidationError, "configuration edit custody did not settle")
        self.input = EditInput(started)
        self.lease: InitRootLease | None = None
        self.authority: Any = None
        self.last_request: EditRequest | None = None
        self.published_token: str | None = None
        self.outcome: CoreEditOutcome | None = None
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
        reason = (current.reason if current is not None and current.reason != "none" else
                  native.reason if native is not None and native.reason != "none" else proposed.reason)
        if proposed.resources == "unknown":
            resources = "unknown"
        self.outcome = CoreEditOutcome(effect, journal, resources, reason)

    def cleanup(self) -> None:
        def retire() -> None:
            if self.authority is not None:
                discard_config_edit(self.authority)
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
        self.lease = InitRootLease(_root(request.params["root"]), cancellation=self.guard)
        self.lease.acquire()
        checkout = capture_config_edit(self.lease)
        self.authority = checkout
        opened = response(request, "opened", {"revision": checkout.revision, "base": checkout.base,
                                                "scopeResources": "settled"})
        self.input.idle()
        self.write(opened)
        request = self.input.request(1, request.session)
        self.last_request = request
        self.guard.check()
        if request.op == "discard":
            self.outcome = CoreEditOutcome("not_started", "not_created", "settled", "none")
            return
        plan = prepare_config_edit(self.lease, checkout, request.params["revision"],
                                   request.params["expectedBase"], request.params["draft"])
        self.authority = plan
        prepared = response(request, "prepared", {"revision": plan.revision, "planToken": plan.token,
                                                   "view": plan.view, "scopeResources": "settled"})
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
            self.outcome = CoreEditOutcome("not_started", "not_created", "settled", "none")
            return
        if request.params["planToken"] != plan.token:
            raise ProtocolError("The original plan token is required")
        self.outcome = apply_config_edit(self.lease, plan)

    def terminal(self) -> None:
        if self.last_request is None:
            raise ProtocolError("No accepted edit request")
        outcome = self.outcome or CoreEditOutcome("not_started", "not_created", "settled", "none")
        if (not self.input.closed or self.lease is not None and not self.lease.closed
                or self.guard.handler_state != "RESTORED" or self.guard.lifetime_ledger.fatal):
            outcome = CoreEditOutcome(outcome.effect, outcome.journal, "unknown",
                                      outcome.reason if outcome.reason != "none" else "custody_unknown")
        self.outcome = outcome
        self.write(response(self.last_request, "terminal", {
            "planToken": self.published_token, "effect": outcome.effect, "journal": outcome.journal,
            "resources": outcome.resources, "reason": outcome.reason,
        }), terminal=True)

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


def main(*, started: float | None = None) -> int:
    engine = _Engine(time.monotonic() if started is None else started)
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
