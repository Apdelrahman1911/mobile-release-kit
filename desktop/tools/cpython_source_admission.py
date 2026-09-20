"""Closed, constants-only conventional source admission root.

This file is deliberately outside the input lock's recipeFiles. The separately
reviewed final command MUST hash-pin it and every imported helper before any
import. Frozen helper sources -> input lock L -> prerequisite envelope review E
-> this literal root A -> final command is acyclic. E must not bind A or that
final command. Changing these None values requires independent source admission;
there is no caller, environment or command-line approval override.
"""

APPROVED_SOURCE_LOCK_SHA256: str | None = "11a88b367bb9cc91e5a2ffafe155b215e9860b80a0f2e711c8dcbc6891680f39"
APPROVED_SOURCE_EXECUTION_REVIEW_SHA256: str | None = "3c91eb81dac9fff49a64f97e0d8a6fb2932f4df024d0f0e4c3167c332a77cdd6"
APPROVED_SOURCE_CORE_INPUTS_SHA256: str | None = "45c9d818b267140de3bc1de5944775da21bccd019bcf45f056313a72ab6c689e"
