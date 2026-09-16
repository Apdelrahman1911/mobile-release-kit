"""Bounded synchronous commands with owned descendants and parent-death cleanup.

This is private trusted-child IPC, not artifact authenticity. Shared OS services
and hostile same-UID process-group escapes are not a containment guarantee.
"""
from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from typing import TYPE_CHECKING

from .cancellation import DefaultCancellation

if TYPE_CHECKING:
    from ._command_process import AccountExecutionScope, CommandCallEvidence, JournalledCommandBinding
from .errors import CredentialError, ValidationError

REQUEST_LIMIT = 2 * 1024 * 1024
OUTPUT_LIMIT = 16 * 1024 * 1024
PRIVATE_OUTPUT_LIMIT = 2 * 1024 * 1024


class ProcessError(ValidationError, CredentialError):
    """No complete command result; dispatch/containment must not be guessed."""

    def __init__(self, message: str, *, dispatched: bool = False, contained: bool = True,
                 cleanup_complete: bool = True):
        super().__init__(message)
        self.dispatched, self.contained = dispatched, contained
        self.cleanup_complete = cleanup_complete

    @property
    def fatal(self) -> bool:
        """Group absence alone does not discharge handles or cancellation ownership."""
        return not self.contained or not self.cleanup_complete


class ProcessCleanupError(ProcessError):
    """Abort further work, even when the command group itself is already absent."""

    def __init__(self, message: str, *, dispatched: bool = False, contained: bool = True):
        super().__init__(message, dispatched=dispatched, contained=contained, cleanup_complete=False)


class ProcessOutcomeUnknown(ProcessError):
    """Settled producers do not prove which side of exec a signal reached."""


class ProcessInterrupted(KeyboardInterrupt):
    def __init__(self, *, dispatched: bool, contained: bool):
        super().__init__()
        self.dispatched, self.contained = dispatched, contained


def preserve_lifetime_error(
    error: ProcessError, *, previous: BaseException | None = None,
    dispatched: bool = False, contained: bool = True,
) -> ProcessError:
    """Later cleanup/handler errors cannot erase an earlier typed lifetime result.

    Combine only explicit observations, never error text. Python retains the
    active exception as context even when a finally/handler raises a new one.
    This also preserves cancellation dispatch across a failing cleanup.
    """
    pending, seen = [error, previous], set()
    cleanup_complete = True
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, (ProcessError, ProcessInterrupted)):
            dispatched = dispatched or current.dispatched
            contained = contained and current.contained
            if isinstance(current, ProcessError):
                cleanup_complete = cleanup_complete and current.cleanup_complete
        pending.extend((current.__context__, current.__cause__))
    error.dispatched, error.contained = dispatched, contained
    error.cleanup_complete = cleanup_complete
    return error


def fatal_lifetime_error(error: BaseException | None, message: str) -> ProcessError | None:
    """Recover typed fatal facts hidden by a later ordinary cleanup exception.

    A generic exception alone proves no process/handle uncertainty. Callers that
    catch and continue independent cleanup must also retain prior nonfatal facts
    explicitly: ExitStack.close() can detach callback exception contexts.
    """
    if error is None:
        return None
    observed = error if isinstance(error, ProcessError) else ProcessError(message)
    preserve_lifetime_error(observed, previous=error)
    return observed if observed.fatal else None


def _json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate command control")
        result[key] = value
    return result


def _parse(content: bytes) -> dict:
    result = json.loads(content, object_pairs_hook=_pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if type(result) is not dict:
        raise ValueError("invalid command control")
    return result


def _valid_request(value: dict) -> None:
    if set(value) != {"argv", "cwd", "capture", "limit"}:
        raise ValueError("invalid command request")
    args = value["argv"]
    if (type(args) is not list or not 0 < len(args) <= 4096
            or any(type(arg) is not str or "\x00" in arg or len(arg) > REQUEST_LIMIT for arg in args)
            or not args[0] or type(value["cwd"]) is not str
            or not os.path.isabs(value["cwd"]) or "\x00" in value["cwd"]
            or type(value["capture"]) is not bool or type(value["limit"]) is not int
            or not 0 < value["limit"] <= OUTPUT_LIMIT):
        raise ValueError("invalid command request")



def run_owned(
    argv: Sequence[str], *, environ: Mapping[str, str] | None = None, cwd: Path | None = None,
    timeout: int = 30, capture: bool = True, output_limit: int = PRIVATE_OUTPUT_LIMIT,
    cancellation: DefaultCancellation | None = None, on_start: Callable[[int], None] | None = None,
    cleanup: bool = False, execution_scope: AccountExecutionScope | None = None,
    journal_binding: JournalledCommandBinding | None = None,
    _evidence: CommandCallEvidence | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run through the original C/A/W owner, including unconditional cleanup.

    ``on_start`` is informational; only an original journal binding's durable
    owner callback can authorize a journalled command. Ordinary results are not
    ownership capabilities. A negative result retains exec-boundary ambiguity.
    """
    from ._command_process import run_command

    return run_command(argv, environ=environ, cwd=cwd, timeout=timeout, capture=capture,
                       output_limit=output_limit, cancellation=cancellation, on_start=on_start,
                       cleanup=cleanup, execution_scope=execution_scope, journal_binding=journal_binding,
                       _evidence=_evidence)
