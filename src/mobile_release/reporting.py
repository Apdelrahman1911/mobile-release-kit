from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, TextIO

from .errors import ValidationError


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    MISSING = "MISSING"
    BLOCKED = "BLOCKED"
    INVALID = "INVALID"
    SKIP = "SKIP"
    MANUAL = "MANUAL"
    CONFIGURED = "CONFIGURED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


FAILING_STATUSES = {Status.FAIL, Status.MISSING, Status.BLOCKED, Status.INVALID}


@dataclass(frozen=True)
class Finding:
    code: str
    status: Status
    message: str
    category: str = "general"
    remediation: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        if value["remediation"] is None:
            del value["remediation"]
        if not value["details"]:
            del value["details"]
        return value


@dataclass
class Report:
    command: str
    findings: list[Finding] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def add(
        self,
        code: str,
        status: Status,
        message: str,
        *,
        category: str = "general",
        remediation: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> Finding:
        finding = Finding(
            code=code,
            status=status,
            message=message,
            category=category,
            remediation=remediation,
            details=details or {},
        )
        self.findings.append(finding)
        return finding

    def extend(self, findings: Iterable[Finding]) -> None:
        self.findings.extend(findings)

    @property
    def ok(self) -> bool:
        return not any(item.status in FAILING_STATUSES for item in self.findings)

    def as_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.status.value] = counts.get(finding.status.value, 0) + 1
        return {
            "command": self.command,
            "ok": self.ok,
            "summary": dict(sorted(counts.items())),
            "context": self.context,
            "findings": [item.as_dict() for item in self.findings],
        }

    def render_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    def render_human(self) -> str:
        lines = [f"mobile-release {self.command}: {'PASS' if self.ok else 'FAIL'}"]
        for item in self.findings:
            lines.append(f"[{item.status.value:>14}] {item.code}: {item.message}")
            if item.remediation:
                lines.append(f"                 action: {item.remediation}")
        if not self.findings:
            lines.append("[          SKIP] no-checks: No checks were applicable.")
        return "\n".join(lines) + "\n"

    def emit(
        self,
        *,
        output_format: str = "human",
        output: Path | None = None,
        root: Path | None = None,
        stream: TextIO | None = None,
    ) -> None:
        import sys

        rendered = self.render_json() if output_format == "json" else self.render_human()
        if output:
            supplied = output.expanduser()
            boundary = root.resolve() if root is not None else Path.cwd().resolve()
            absolute = Path(
                os.path.abspath(supplied if supplied.is_absolute() else boundary / supplied)
            )
            repository_alias = next(
                (
                    ancestor
                    for ancestor in (absolute, *absolute.parents)
                    if ancestor.resolve() == boundary
                ),
                None,
            )
            if repository_alias is None or repository_alias.is_symlink():
                raise ValidationError("report output must remain inside the project root")
            relative = absolute.relative_to(repository_alias)
            current = repository_alias
            for index, part in enumerate(relative.parts):
                current = current / part
                if current.is_symlink():
                    raise ValidationError("report output must not traverse a symbolic link")
                if index < len(relative.parts) - 1 and current.exists() and not current.is_dir():
                    raise ValidationError("report output parent must be a real directory")
            destination = boundary / relative
            if destination.exists() and (
                destination.is_symlink() or not destination.is_file()
            ):
                raise ValidationError("report output must be a regular non-symlink file")
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.parent.is_symlink() or not destination.parent.is_dir():
                raise ValidationError("report output parent must be a real directory")
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{destination.name}.", dir=destination.parent
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(rendered)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temporary, 0o600)
                os.replace(temporary, destination)
            finally:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
        target = stream or sys.stdout
        target.write(rendered)


def redacted(value: str | None) -> str:
    """Return presence information without exposing even a prefix or length."""

    return "CONFIGURED" if value else "MISSING"
