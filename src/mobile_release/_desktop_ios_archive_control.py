"""Exact third saved-command input; no caller-supplied operation or runner."""
from __future__ import annotations

from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput


class IOSArchiveInput(_SavedCommandInput):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.IOSArchive)
        self.operation = None
        self._engine = None
        self.material = None
        self.material_receiving = False
        self.material_pending = False
        self.signed = False
        self.recovery = False
        self.cleanup_end = self.work_end + 10
        self.hard_end = self.work_end + 10

    def _request_material(self, request) -> None:
        from ._desktop_ios_archive_protocol import (
            SIGNED_CLEANUP_SECONDS, SIGNED_FINALITY_SECONDS, WORK_SECONDS, is_signed, is_recovery,
        )
        self._owner()
        self.signed = is_signed(request.context)
        self.recovery = is_recovery(request.context)
        started = self.work_end - WORK_SECONDS
        if self.signed:
            # Derived from original source Start, never renewed after parsing.
            self.cleanup_end = started + SIGNED_CLEANUP_SECONDS
            self.hard_end = started + SIGNED_FINALITY_SECONDS
            self.material_pending = True
        elif self.recovery:
            from ._desktop_ios_recovery_protocol import WORK_SECONDS, CLEANUP_SECONDS, FINALITY_SECONDS
            self.work_end = started + WORK_SECONDS
            self.cleanup_end = started + CLEANUP_SECONDS
            self.hard_end = started + FINALITY_SECONDS

    @property
    def account_lifecycle(self) -> bool:
        return self.signed or self.recovery

    def receive_material(self, operation) -> None:
        """The original request does not acquire material before account admission."""
        self._owner()
        self._require(self.signed and self.material_pending and not self.material_receiving
                      and self.active and self.request_returned and operation is self.require_operation()
                      and operation.signing is not None and operation.signing.lease is not None
                      and operation.signing.lease.locked and operation.invocation is not None
                      and operation.invocation.signing_lease is operation.signing.lease
                      and operation.invocation.project_owner is not None)
        operation.checkpoint()
        from ._desktop_ios_signing_material import read_material
        self.material_receiving = True
        try:
            read_material(self, operation.request)
            self.material_pending = False
        finally:
            self.material_receiving = False
        self.guard.check()  # After the suffix, any byte/EOF is ordinary STOP.

    def cleanup_endpoint(self) -> float:
        self._owner()
        return min(self.cleanup_end, self.first_failure + (120 if self.account_lifecycle else 10)) if self.first_failure is not None else self.cleanup_end

    def hard_endpoint(self) -> float:
        self._owner()
        return min(self.hard_end, self.first_failure + (130 if self.account_lifecycle else 10)) if self.first_failure is not None else self.hard_end

    def close(self) -> None:
        super().close()
        if self.account_lifecycle:
            self.buffer.clear()
        if self.material is not None:
            self.material.retire()

    def material_closed(self) -> bool:
        self._owner()
        return (self.closed and not self.material_receiving and not self.buffer
                and (self.material is None or self.material._retired))

    def bind_operation(self, operation) -> None:
        from .ios_archive_operation import IOSArchiveOperation
        self._owner()
        self._require(type(operation) is IOSArchiveOperation and self.operation is None
                      and self.guard is not None and self.guard._saved_command_input() is self
                      and operation.source is self and operation.guard is self.guard
                      and self.active and self.request_returned and not self.close_claimed)
        self.operation = operation

    def require_operation(self):
        from .ios_archive_operation import IOSArchiveOperation
        self._owner()
        self._require(type(self.operation) is IOSArchiveOperation and self.guard is not None
                      and self.operation.source is self and self.operation.guard is self.guard)
        self.guard._check_owner()
        return self.operation

    def _bind_engine(self, engine) -> None:
        from ._desktop_ios_archive_engine import _Engine
        self._owner()
        self._require(type(engine) is _Engine and self._engine is None and engine.input is self
                      and engine.domain is SavedCommandDomain.IOSArchive)
        self._engine = engine

    def progress(self, stage: str) -> None:
        from ._desktop_ios_archive_engine import _Engine
        self._owner()
        self._require(type(self._engine) is _Engine and self._engine.input is self
                      and self._engine.guard is self.guard and not self.close_claimed)
        self._engine._progress(self, stage)
