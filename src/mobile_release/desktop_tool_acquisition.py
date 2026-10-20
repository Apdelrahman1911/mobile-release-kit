"""The fixed admitted child adapter for reuse-first public tool acquisition.

This is not a public CLI or process launcher. Its native parent owns the
original inventory, explicit permit, pending cache intent and every actual join.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import threading
import time

from ._desktop_tool_acquisition_control import ToolAcquisitionInput
from ._desktop_tool_acquisition_protocol import (CA_LIMIT, CONTROL_LIMIT, MANIFEST_LIMIT,
    ToolAcquisitionRequest, component_partition, decode, require)
from ._tool_acquisition_spec import AcquisitionError
from ._tool_requirements_capture import Capture
from .cancellation import DefaultCancellation
from .owned_process import fatal_lifetime_error
from ._tool_acquisition_sdk import CopyBinding
from .tool_acquisition import Admission, LOOKUP_SCOPE, ToolAcquisition


class ToolAcquisitionRun:
    def __init__(self, request, guard, source):
        require(type(request) is ToolAcquisitionRequest and type(guard) is DefaultCancellation
            and type(source) is ToolAcquisitionInput and source.guard is guard and guard._saved_command_input() is source
            and source.active and source.request_returned and threading.current_thread() is threading.main_thread())
        self.request, self.guard, self.source = request, guard, source
        self.operation = self
        self.capture = None
        self.acquisition = None
        self.primary = None
        self.result = None
        self._claimed = self._captured = self._unknown = self._intent_seen = False
        self._manifest = None
        source.bind_operation(self)  # Root before either subordinate construction.
        self.capture = Capture(Path(request.native["projectRoot"]), request.native["rootIdentity"], request.context["savedConfig"], guard)
        self.acquisition = ToolAcquisition(self)

    @property
    def cancellation(self):
        return self.guard

    def checkpoint(self):
        require(self.source.require_operation() is self and self.guard._saved_command_input() is self.source
                and not self._unknown and not self.source.close_claimed)
        self.guard.check()  # Original held STOP/EOF and original child deadline.
        if self.capture is not None and self.capture.entered:
            self.capture.root.check()

    def remember(self, error):
        if self.primary is None:
            self.primary = error
        self.source.failure_observed()
        self.guard.lifetime_ledger._remember(error)
        if fatal_lifetime_error(error, "Tool preparation custody did not settle") is not None:
            self.guard._abort(error)

    def run(self):
        self.checkpoint()
        require(sys.platform == "darwin" and os.getcwd() == self.request.native["cwd"])
        hints = self.capture.run()
        if not hints["complete"]:
            raise AcquisitionError("unsupported")
        footprint = self.capture.footprint()
        self._captured = True
        if self.request.context["action"] == "inspect":
            self.result = {"kind": "tool-requirements-observation", "requirements": hints, "footprint": footprint}
            return
        native = self.request.native["cache"]
        require(footprint == native["footprint"] and hints["sourcesSha256"] == self.request.context["review"]["requirementsSha256"])
        offered = self.acquisition.run()
        self.capture.check()  # Full exact source bytes and negative footprint.
        self.checkpoint()
        self.result = offered.to_data()

    def claim(self):
        require(not self._claimed and self._captured and self.request.context["action"] == "acquire")
        self._claimed = True
        self.checkpoint()
        native = self.request.native["cache"]
        identity = native["rootIdentity"]
        missing, compatible = component_partition(native["missing"], native["compatible"])
        require(bool(missing))
        return Admission(self.request.operation_id, native["contextSha256"], self.request.native["profile"],
            native["referenceSha256"], native["projectionSha256"], native["generation"], Path(native["root"]),
            (int(identity["device"]), int(identity["inode"]), identity["uid"], identity["gid"], identity["mode"]),
            missing, compatible, True, LOOKUP_SCOPE, self.source.work_end,
            CopyBinding.parse(native.get("sdkCopy"), missing, compatible))

    def checked_manifest(self):
        require(self._claimed)
        self.checkpoint()
        if self._manifest is None:
            self._manifest = decode(self.request.native["manifestBase64"], MANIFEST_LIMIT)
        return self._manifest

    def admit_cache_origin(self, operation, intent_sha256):
        require(self._claimed)
        self.checkpoint()
        # These exact entries came from the native parent's SAME retained and
        # actually settled producer book, never cache JSON or renderer state.
        require(any(row["operationId"] == operation and row["intentSha256"] == intent_sha256
                    for row in self.request.native["cache"]["origins"]))

    def record_intent(self, intent):
        require(self._claimed and not self._intent_seen)
        self._intent_seen = True  # Consume before any possibly interrupted check.
        self.checkpoint()
        require(intent == decode(self.request.native["cache"]["intentBase64"], CONTROL_LIMIT))
        # The parent fsynced this exact pending intent BEFORE child creation.
        # No child return or this comparison is a native settlement receipt.

    def public_ca(self):
        require(self._claimed and self._intent_seen)
        self.checkpoint()
        return decode(self.request.native["caBase64"], CA_LIMIT)

    def retain_unknown(self, original):
        require(original is self.acquisition)
        self._unknown = True
        self.guard._abort(AcquisitionError("unknown"))

    def close(self):
        first = None
        if self.acquisition is not None and self.acquisition.scope is not None:
            try:
                self.acquisition.scope.__exit__(*sys.exc_info())
            except BaseException as error:
                first = error
                self.guard._abort(error)
        if self.capture is not None:
            try:
                self.capture.close()
            except BaseException as error:
                first = first or error
                self.guard._abort(error)
        if first is not None:
            raise first

    def closed(self):
        capture_closed = self.capture is None or self.capture.closed
        acquisition_closed = self.acquisition is None or (not self.acquisition.unknown
            and (self.acquisition.files is None or self.acquisition.files.settled)
            and (self.acquisition.sdk_copy is None or self.acquisition.sdk_copy.closed))
        return capture_closed and acquisition_closed and not self._unknown

    def terminal(self):
        verdict = self.guard.lifetime_ledger.verdict()
        if verdict.commands != 0 or verdict.profile_calls != 0:
            self.guard._abort(AcquisitionError("unknown"))
            verdict = self.guard.lifetime_ledger.verdict()
        if time.monotonic() >= self.source.work_end:
            self.source.stop("timed-out")
        elif self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")
        lifetime = {"complete": verdict.complete, "fatal": verdict.fatal, "contained": verdict.contained,
            "commandDispatched": verdict.command_dispatched, "commands": verdict.commands, "profileCalls": verdict.profile_calls,
            "inputClosed": self.source.closed, "handlersRestored": self.guard.handler_state == "RESTORED",
            "resourcesClosed": self.closed(), "stopObserved": self.source.stop_reason}
        settled = (verdict.cleanup_complete and verdict.contained and verdict.command_dispatched is False
            and self.source.closed and lifetime["handlersRestored"] and lifetime["resourcesClosed"])
        if not settled:
            outcome, reason = "unknown", "cleanup-unknown"
        elif self.source.stop_reason != "none":
            outcome = reason = self.source.stop_reason
        elif self.primary is not None:
            outcome, reason = "refused", self.primary.reason if isinstance(self.primary, AcquisitionError) else "input"
        elif self.result is None:
            outcome, reason = "failed", "input"
        else:
            outcome, reason = "complete", "none"
        return {"schemaVersion": 1, "context": self.request.context, "outcome": outcome, "reason": reason,
                "result": self.result if outcome == "complete" else None, "lifetime": lifetime}
