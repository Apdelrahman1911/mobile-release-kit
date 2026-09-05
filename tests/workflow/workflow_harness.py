"""Small, fail-closed test interpreter for the workflow conditions we actually use.

YAML is parsed by Ruby's standard-library Psych, also used by our structural gate.
This is not a GitHub runner emulator: external actions are explicit test seams.
Unknown expressions are errors so a workflow change cannot silently broaden the
simulation. Shell contract tests execute selected *real* run blocks separately.
"""
from __future__ import annotations

import functools
import json
import re
import subprocess
from pathlib import Path
from typing import Any


@functools.lru_cache(maxsize=None)
def load_workflow(path: Path) -> dict[str, Any]:
    result = subprocess.run(
        [
            "ruby", "-rpsych", "-rjson", "-e",
            "print JSON.generate(Psych.safe_load(File.read(ARGV.fetch(0)), "
            "permitted_classes: [], permitted_symbols: [], aliases: false))",
            str(path),
        ],
        text=True, capture_output=True, check=True, timeout=30,
    )
    return json.loads(result.stdout)


def step_by_id(job: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [step for step in job["steps"] if step.get("id") == name]
    if len(matches) != 1:
        raise AssertionError(f"expected one step with id {name!r}, got {len(matches)}")
    return matches[0]


TOKEN = re.compile(
    r"\s*(?:('(?:[^']|'')*')|([A-Za-z_][A-Za-z0-9_.-]*)|(\&\&|\|\||==|!=|[!(),]))"
)


def evaluate_condition(
    expression: str | None, context: dict[str, Any], *, success: bool, cancelled: bool,
) -> bool:
    """Evaluate the restricted literal/context/status/hashFiles expression subset.

    GitHub implicitly inserts success() unless a status-check function is present.
    The caller supplies job-needs or prior-step status; missing properties are ''.
    """
    expression = expression or "success()"
    expression = expression.strip()
    if expression.startswith("${{") and expression.endswith("}}"):
        expression = expression[3:-2].strip()
    tokens: list[tuple[str, str]] = []
    position = 0
    while position < len(expression):
        match = TOKEN.match(expression, position)
        if match is None:
            raise AssertionError(f"unsupported workflow expression: {expression!r}")
        tokens.append(("string" if match[1] else "name" if match[2] else "operator", next(value for value in match.groups() if value is not None)))
        position = match.end()
    cursor = 0

    def accept(value: str) -> bool:
        nonlocal cursor
        if cursor < len(tokens) and tokens[cursor][1] == value:
            cursor += 1
            return True
        return False

    def require(value: str) -> None:
        if not accept(value):
            raise AssertionError(f"expected {value!r} in {expression!r}")

    def atom() -> Any:
        nonlocal cursor
        if accept("!"):
            return not bool(atom())
        if accept("("):
            value = logical_or()
            require(")")
            return value
        if cursor >= len(tokens):
            raise AssertionError(f"incomplete expression: {expression!r}")
        kind, token = tokens[cursor]
        cursor += 1
        if kind == "string":
            return token[1:-1].replace("''", "'")
        if kind != "name":
            raise AssertionError(f"unexpected expression token: {token!r}")
        if accept("("):
            if token in {"success", "cancelled", "always", "failure"}:
                require(")")
                return {"success": success, "cancelled": cancelled, "always": True, "failure": not success and not cancelled}[token]
            if token == "hashFiles":
                if cursor >= len(tokens) or tokens[cursor][0] != "string":
                    raise AssertionError("hashFiles requires one literal path")
                filename = atom()
                require(")")
                return "a" * 64 if filename in context.get("files", set()) else ""
            raise AssertionError(f"unsupported workflow function: {token}")
        if token in {"true", "false"}:
            return token == "true"
        value: Any = context
        for part in token.split("."):
            if not isinstance(value, dict):
                return ""
            value = value.get(part, "")
        return value

    def compare() -> Any:
        value = atom()
        if accept("=="):
            return value == atom()
        if accept("!="):
            return value != atom()
        return value

    def logical_and() -> Any:
        value = compare()
        while accept("&&"):
            other = compare()
            value = other if value else value
        return value

    def logical_or() -> Any:
        value = logical_and()
        while accept("||"):
            other = logical_and()
            value = value if value else other
        return value

    result = logical_or()
    if cursor != len(tokens):
        raise AssertionError(f"unconsumed workflow expression: {expression!r}")
    has_status = bool(re.search(r"\b(?:success|failure|cancelled|always)\s*\(", expression))
    return bool(result) and (has_status or success)


def simulate_steps(
    job: dict[str, Any], *, mode: str, fail: str | None = None,
    cancel: str | None = None, resolver_outputs: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Evaluate each actual YAML step, injecting only external success/failure.

    IDs and names can be failure-injection points. An auth seam models issuance
    of a file before an error; cleanup must still run. No continue-on-error is
    supported or allowed. Mutation is counted by the caller from the real script.
    """
    context: dict[str, Any] = {"steps": {}, "files": set()}
    executed: list[dict[str, Any]] = []
    success, cancelled = True, False
    for step in job["steps"]:
        if step.get("continue-on-error"):
            raise AssertionError("Store protocol must not continue after errors")
        identifier = step.get("id", step["name"])
        eligible = evaluate_condition(step.get("if"), context, success=success, cancelled=cancelled)
        record = {"outputs": {}, "outcome": "skipped", "conclusion": "skipped"}
        context["steps"][identifier] = record
        if not eligible:
            continue
        executed.append(step)
        if identifier == "resolve":
            record["outputs"] = {"mode": mode, **(resolver_outputs or {})}
        if "google-github-actions/auth@" in step.get("uses", ""):
            record["outputs"] = {"credentials_file_path": "/private/runner/adc.json"}
        outcome = "failure" if fail in (identifier, step["name"]) else "success"
        if cancel in (identifier, step["name"]):
            outcome, cancelled = "cancelled", True
        record.update(outcome=outcome, conclusion=outcome)
        success = success and outcome == "success"
    return executed, context
