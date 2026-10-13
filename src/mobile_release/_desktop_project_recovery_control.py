"""Exact project-recovery input; no command/tool dispatch authority."""
from __future__ import annotations

from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput


class ProjectRecoveryInput(_SavedCommandInput):
    def __init__(self, started: float) -> None:
        super().__init__(started, domain=SavedCommandDomain.ProjectRecovery)
        self.descriptors: list[object] = []

    def register_descriptor(self, descriptor: object) -> None:
        from .build_inputs import _FD
        self._owner()
        self._require(type(descriptor) is _FD and self.guard is not None
                      and self.guard._project_recovery_source is self
                      and descriptor.guard is self.guard and self.active and self.request_returned
                      and not self.close_claimed and len(self.descriptors) < 4096
                      and all(previous is not descriptor for previous in self.descriptors))
        self.descriptors.append(descriptor)  # Retain actual original before acquisition.

    def resources_closed(self) -> bool:
        from .build_inputs import _FD
        self._owner()
        self._require(self.guard is not None)
        return all(type(slot) is _FD and slot.guard is self.guard and slot.number is None
                   and slot.close_state == "CLOSED" and slot.open_state in {"NEW", "NO_EFFECT", "OPEN"}
                   for slot in self.descriptors)
