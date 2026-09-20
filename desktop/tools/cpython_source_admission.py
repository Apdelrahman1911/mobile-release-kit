"""Closed, constants-only conventional source admission root.

This file is deliberately outside the input lock's recipeFiles. The separately
reviewed final command MUST hash-pin it and every imported helper before any
import. Frozen helper sources -> input lock L -> prerequisite envelope review E
-> this literal root A -> final command is acyclic. E must not bind A or that
final command. Changing these None values requires independent source admission;
there is no caller, environment or command-line approval override.
"""

APPROVED_SOURCE_LOCK_SHA256: str | None = "ca192c4bc4669399b242e14dfae5a22b7121d61c412dadad23785183bd2abf97"
APPROVED_SOURCE_EXECUTION_REVIEW_SHA256: str | None = "d75e75d69bd9e6f1894b29e7202fd39800bbec24ef5850e14ba46efe4a06823b"
APPROVED_SOURCE_CORE_INPUTS_SHA256: str | None = "45c9d818b267140de3bc1de5944775da21bccd019bcf45f056313a72ab6c689e"
