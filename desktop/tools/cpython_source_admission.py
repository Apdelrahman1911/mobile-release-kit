"""Closed, constants-only conventional source admission root.

This file is deliberately outside the input lock's recipeFiles. The separately
reviewed final command MUST hash-pin it and every imported helper before any
import. Frozen helper sources -> input lock L -> prerequisite envelope review E
-> this literal root A -> final command is acyclic. E must not bind A or that
final command. Changing these None values requires independent source admission;
there is no caller, environment or command-line approval override.
"""

APPROVED_SOURCE_LOCK_SHA256: str | None = "5a10f7b24b2b081f97fd93de1f363875b570ef372e4464bc5280b632e74b60a6"
APPROVED_SOURCE_EXECUTION_REVIEW_SHA256: str | None = "a909d9e47b3b9fe96442840231e4cdf8e1f244a4cdf868066ec4e15e11b5400f"
APPROVED_SOURCE_CORE_INPUTS_SHA256: str | None = "45c9d818b267140de3bc1de5944775da21bccd019bcf45f056313a72ab6c689e"
