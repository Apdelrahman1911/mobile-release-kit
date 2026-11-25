"""Closed DATA for a create-only first publication, not an ordinary update.

ZERO is the server's expected-old precondition, never evidence of absence.
Only the same original Push owner may use this typed selection after its fresh
advertisement, current source checks, durable ACK and explicit consent.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import git_remote_wire as framing
from .git_service import _ref


KIND = "push-new-branch"
ZERO = "0" * 40
BASIS = "first-publication-no-upstream"


@dataclass(frozen=True, slots=True, repr=False)
class Selection:
    local_ref: str
    remote_ref: str
    old_oid: str
    new_oid: str

    def __post_init__(self):
        framing._need(type(self.local_ref) is str and self.local_ref.isascii()
                      and len(self.local_ref) <= 255 and _ref(self.local_ref)
                      and type(self.remote_ref) is str and self.remote_ref == self.local_ref
                      and type(self.old_oid) is str and self.old_oid == ZERO
                      and type(self.new_oid) is str and self.new_oid.isascii()
                      and framing._oid(self.new_oid.encode("ascii")))


def empty_row(fields, index, count):
    """The sole Git empty-repository capability row, never an actual ref.

    Called only for the explicit create-only selection. A mixed, duplicate or
    later pseudo-row is refused; ordinary Push never calls this exception.
    """
    if fields != [ZERO.encode("ascii"), b"capabilities^{}"]:
        return False
    framing._need(index == 0 and count == 1, "unsupported-protocol")
    return True
