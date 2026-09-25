"""Pure configuration/ignore bytes shared by CLI init and the edit adapter.

No paths, descriptors, transactions or native capability probes are consumed.
Serialization is not configuration admission; callers validate policy first.
The CLI retains its exact append behavior. The editor separately requires a
conservative proof and refuses to override uncertain negation intent.
"""
from __future__ import annotations

import json
from typing import Any

from .errors import ValidationError
from .init_transaction import IGNORE_LINES

MAX_IGNORE_BYTES = 1024 * 1024


class IgnoreRuleConflict(ValidationError):
    """The editor cannot safely infer the required private-directory rules."""


def serialize_config_data(data: dict[str, Any]) -> bytes:
    """Preserve the existing CLI's UTF-8, indent-2, final-LF serialization."""
    return (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _required_lines(lines: tuple[str, ...]) -> None:
    if (type(lines) is not tuple or len(lines) > len(IGNORE_LINES)
            or any(type(line) is not str or line not in IGNORE_LINES for line in lines)
            or len(set(lines)) != len(lines)):
        raise ValidationError("invalid fixed private-directory ignore rules")


def append_ignore_lines(before: bytes, lines: tuple[str, ...] = IGNORE_LINES) -> bytes:
    """Existing CLI byte builder, with a closed optional fixed-rule subset.

    A root-prefixed equivalent deliberately does not replace the CLI's exact
    spelling check. Only the editor filters rules by sufficient coverage first.
    """
    _required_lines(lines)
    if type(before) is not bytes:
        raise ValidationError("root .gitignore must be UTF-8")
    try:
        before.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValidationError("root .gitignore must be UTF-8") from error
    if len(before) > MAX_IGNORE_BYTES:
        raise ValidationError("root .gitignore including required ignore lines must fit within 1 MiB")
    after = before
    for line in lines:
        if line.encode() not in after.splitlines():
            if after and not after.endswith(b"\n"):
                after += b"\n"
            after += line.encode() + b"\n"
    if len(after) > MAX_IGNORE_BYTES:
        raise ValidationError("root .gitignore including required ignore lines must fit within 1 MiB")
    return after


def _ignore_facts(content: bytes, lines: tuple[str, ...]) -> tuple[frozenset[str] | None, bool]:
    _required_lines(lines)
    if type(content) is not bytes:
        return None, False
    try:
        patterns = content.decode("utf-8").split("\n")
    except UnicodeError:
        return None, False
    spelling = {variant: line for line in lines for variant in (line, "/" + line)}
    proven: set[str] = set()
    has_negation = False
    for raw in patterns:
        pattern = raw[:-1] if raw.endswith("\r") else raw
        if pattern in spelling:
            proven.add(spelling[pattern])
        elif pattern.startswith("!"):
            has_negation = True
            proven.clear()
    return frozenset(proven), has_negation


def sufficient_ignore_rules(content: bytes, lines: tuple[str, ...] = IGNORE_LINES) -> bool:
    """Conservative existing suffix proof, never a general Gitignore parser.

    The default is the ten-rule configuration/version vocabulary. Metadata
    passes its fixed original-seven tuple explicitly; it is not migrated here.
    With ``('.mobile-release/',)`` this retains build_inputs' existing proof:
    leading spaces matter, only LF/CRLF split patterns, and any later negation
    invalidates earlier positive proof. Invalid UTF-8 has no sufficient proof.
    """
    proven, _ = _ignore_facts(content, lines)
    return proven is not None and proven == frozenset(lines)


def prepare_edit_ignore(before: bytes) -> tuple[bytes, tuple[str, ...]]:
    """Derive only needed editor additions without overriding negation intent.

    Even an unrelated syntactic negation plus an uncovered required rule is a
    deliberate refusal. A complete existing sufficient suffix is untouched.
    """
    before = append_ignore_lines(before, ())  # UTF-8/byte admission, no changes.
    proven, negation = _ignore_facts(before, IGNORE_LINES)
    if proven is None:
        raise IgnoreRuleConflict("root .gitignore has no valid private-directory ignore proof")
    additions = tuple(line for line in IGNORE_LINES if line not in proven)
    if additions and negation:
        raise IgnoreRuleConflict("root .gitignore has unresolved private-directory ignore intent")
    after = append_ignore_lines(before, additions)
    if not sufficient_ignore_rules(after):
        raise IgnoreRuleConflict("root .gitignore does not establish all required private-directory rules")
    return after, additions
