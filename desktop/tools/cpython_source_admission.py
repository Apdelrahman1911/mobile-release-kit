"""Closed, constants-only conventional source admission root.

This file is deliberately outside the input lock's recipeFiles. The separately
reviewed final command MUST hash-pin it and every imported helper before any
import. Frozen helper sources -> input lock L -> prerequisite envelope review E
-> this literal root A -> final command is acyclic. E must not bind A or that
final command. Changing these None values requires independent source admission;
there is no caller, environment or command-line approval override.
"""

APPROVED_SOURCE_LOCK_SHA256: str | None = None
APPROVED_SOURCE_EXECUTION_REVIEW_SHA256: str | None = None
APPROVED_SOURCE_CORE_INPUTS_SHA256: str | None = None
