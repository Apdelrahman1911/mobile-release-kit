"""Executable DATA policy only; never authenticates a receipt or operates Windows.

The future sole privileged publisher must own the native implementation. These
states may only be supplied by that owner after original handle observations,
not MSI properties, matching bytes, a PID, a stale journal, or timeout inference.
"""
from enum import Enum, auto

class State(Enum):
    FRESH = auto()
    PUBLISHING = auto()
    PUBLISHED = auto()
    COMPLETED = auto()
    FAILED = auto()
    UNKNOWN = auto()

class Transaction:
    def __init__(self, package_binding):
        if not isinstance(package_binding, str) or len(package_binding) != 64 or any(c not in '0123456789abcdef' for c in package_binding):
            raise ValueError('exact package binding required')
        self.binding = package_binding
        self.state = State.FRESH

    def start(self, *, target_absent, original_inputs_locked):
        if self.state != State.FRESH or not target_absent or not original_inputs_locked:
            self.state = State.UNKNOWN
            return False
        self.state = State.PUBLISHING
        return True

    def returned(self, *, original_exit, original_handles_settled):
        if self.state != State.PUBLISHING or not original_handles_settled or type(original_exit) is not int:
            self.state = State.UNKNOWN
        elif original_exit == 0:
            self.state = State.PUBLISHED
        else:
            # Includes occupied exit 2: never success, even with identical bytes.
            self.state = State.FAILED
        return self.state

    def activate(self, *, same_binding, protected_fullwalk):
        if self.state != State.PUBLISHED or same_binding != self.binding or not protected_fullwalk:
            self.state = State.UNKNOWN
            return False
        self.state = State.COMPLETED
        return True

    def maintenance(self, *, same_binding, completion_owner_authenticated, original_exit_settled, protected_fullwalk):
        # No fallback for occupied/partial runtime; a completed package-owned
        # transaction must be authenticated independently of content equality.
        return (self.state == State.COMPLETED and same_binding == self.binding
                and completion_owner_authenticated is True and original_exit_settled is True
                and protected_fullwalk is True)

    def parent_lost(self):
        self.state = State.UNKNOWN

    def may_replace_inputs(self):
        return self.state == State.COMPLETED

    def may_remove_retained_runtime(self):
        return False
