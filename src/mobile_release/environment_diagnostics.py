"""Explicit non-publishing build-tool diagnostics through the ordinary owner.

Not CLI doctor, a passive API method, a project inspection, or release readiness.
Only the fixed bootstrap creates this service with its actual cancellation/input
owner. Tests may patch the library seam; no runner/resolver callback is admitted
by this interface and no injected result establishes native finality.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from ._desktop_environment_control import EnvironmentInput
from ._desktop_environment_protocol import (CALL_SECONDS, OUTPUT_LIMIT, POLICY, PROFILES, ROSTERS,
    EnvironmentRequest, ProtocolError, _json_bytes, assurance, integer, parse_version, require, row)
from .cancellation import DefaultCancellation
from .config import ReleaseConfig, parse_config_text
from .environment_diagnostics_tools import (BindingChanged, ToolBinding, ToolLookup, ToolUnavailable,
    overlaps, tool_environment)
from .errors import ConfigurationError
from .owned_process import ProcessError, fatal_lifetime_error, run_owned


class DiagnosticsRun:
    def __init__(self, request: EnvironmentRequest, guard: DefaultCancellation, source: EnvironmentInput) -> None:
        require(type(request) is EnvironmentRequest and type(guard) is DefaultCancellation
            and type(source) is EnvironmentInput and source.guard is guard)
        self.request, self.guard, self.source = request, guard, source
        self.profile = request.native["profile"]
        self.host, self.architecture = PROFILES[self.profile]
        self.lookup = ToolLookup(self.profile, request.native["projectRoot"], guard)
        self.checks = {role: row(role) for role in ROSTERS[(self.host, request.context["platform"])]}
        self.commands_attempted = 0
        self.current: str | None = None
        self.primary: BaseException | None = None
        self.roster_finished = False

    def _check(self) -> None:
        self.guard.check()
        if time.monotonic() >= self.source.work_end:
            self.source.stop("timed-out")
            self.guard.check()

    def remember(self, error: BaseException) -> None:
        if self.primary is None:
            self.primary = error
        # Preserve actual nested typed dispatch/cleanup facts. Generic text,
        # duration or exception class never distinguishes owner timeout/cap.
        self.guard.lifetime_ledger._remember(error)
        if fatal_lifetime_error(error, "Environment command custody did not settle") is not None:
            self.guard._abort(error)
        if self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")  # The actual original signal/STOP latch.
        if self.current is not None and self.checks[self.current]["state"] == "attempted":
            reason = (self.source.stop_reason if self.source.stop_reason != "none" else
                      "binding-changed" if isinstance(error, BindingChanged) else "command-incomplete")
            self.checks[self.current] = row(self.current, "attempted", reason)

    def _call(self, role: str, binding: ToolBinding, *, developer: ToolBinding | None = None) -> subprocess.CompletedProcess[bytes]:
        self._check()
        self.lookup.recheck(binding)
        self._check()
        remaining = int(self.source.work_end - time.monotonic())
        if remaining < 1:
            self.source.stop("timed-out")
            self.guard.check()
        timeout = min(CALL_SECONDS, remaining)
        require(integer(timeout, CALL_SECONDS, 1) and self.commands_attempted < 4
            and role in self.checks and self.checks[role]["state"] == "not-run")
        # Register the attempt before the only command effect. A lost call
        # return is not a completed/nonzero/absent tool observation.
        self.current = role
        self.checks[role] = row(role, "attempted", "command-incomplete")
        self.commands_attempted += 1
        argument = {"developer-selection": "-p", "git": "--version", "java": "-version",
                    "javac": "-version", "xcode": "-version"}[role]
        try:
            result = run_owned((binding.path, argument),
                environ=tool_environment(self.profile, role, None if developer is None else developer.path),
                cwd=Path(self.request.native["cwd"]), timeout=timeout, capture=True, text=False,
                output_limit=OUTPUT_LIMIT, cancellation=self.guard)
        except ProcessError:
            # Its ordinary API intentionally coalesces timeout/output/exec and
            # other incomplete cases. The original error reaches outer cleanup.
            raise
        self._check()  # STOP prohibits any new namespace probes after return.
        require(type(result) is subprocess.CompletedProcess and integer(result.returncode, 2**31 - 1, -(2**31))
            and type(result.stdout) is bytes and type(result.stderr) is bytes
            and len(result.stdout) + len(result.stderr) <= OUTPUT_LIMIT)
        self.lookup.recheck(binding)
        self._check()
        return result

    def _version(self, role: str, binding: ToolBinding, *, developer: ToolBinding | None = None) -> None:
        result = self._call(role, binding, developer=developer)
        if result.returncode != 0:
            self.checks[role] = row(role, "completed", "nonzero-exit", returncode=result.returncode)
        else:
            observed = parse_version(role, result.stdout, result.stderr)
            self.checks[role] = (row(role, "completed", "version-unrecognized", returncode=0) if observed is None else
                row(role, "completed", "observed", version=observed[0], build=observed[1], returncode=0))
        self.current = None

    def _developer(self) -> ToolBinding | None:
        role = "developer-selection"
        try:
            selector = self.lookup.mac_selector()
        except ToolUnavailable as error:
            self.checks[role] = row(role, reason=error.reason)
            return None
        result = self._call(role, selector)
        if result.returncode != 0:
            self.checks[role] = row(role, "completed", "nonzero-exit", returncode=result.returncode)
            self.current = None
            return None
        try:
            if result.stderr:
                raise ToolUnavailable()
            developer = self.lookup.mac_developer(result.stdout)
            self.lookup.recheck(developer)
        except ToolUnavailable:
            self.checks[role] = row(role, "completed", "selection-unrecognized", returncode=0)
            self.current = None
            return None
        self.checks[role] = row(role, "completed", "observed", returncode=0)
        self.current = None
        return developer

    def _unavailable(self, reason: str) -> None:
        self.checks = {role: row(role, reason=reason) for role in self.checks}
        self.roster_finished = True

    def run(self) -> None:
        self._check()
        # Supplied-draft schema validation only. These wrappers perform no
        # project path read, release-version resolution or broad discovery.
        try:
            data = parse_config_text(_json_bytes(self.request.draft).decode("utf-8"))
        except ConfigurationError:
            self._unavailable("invalid-draft")
            return
        config = ReleaseConfig(path=Path("release/mobile-release.json"), root=Path("."), data=data)
        if not config.platform_enabled(self.request.context["platform"]):
            self._unavailable("platform-disabled")
            return
        self._check()
        actual_host = "linux" if sys.platform == "linux" else "macos" if sys.platform == "darwin" else "other"
        if (os.name != "posix" or actual_host != self.host or os.uname().machine != self.architecture):
            self._unavailable("unsupported-host")
            return
        # The native gate must already have qualified this neutral directory.
        # This equality is not runtime qualification or a home/ACL inspection.
        require(os.getcwd() == self.request.native["cwd"] and not overlaps(
            self.request.native["cwd"], self.request.native["projectRoot"]))
        if self.host == "linux" and self.request.context["platform"] == "ios":
            self._unavailable("host-mismatch")
            return
        developer = self._developer() if self.host == "macos" else None
        self._check()
        if self.host == "macos" and developer is None:
            self.checks["git"] = row("git", reason="unselected-installation")
        else:
            try:
                git = self.lookup.linux_git() if self.host == "linux" else self.lookup.mac_developer_tool(developer, "git")
            except ToolUnavailable as error:
                self.checks["git"] = row("git", reason=error.reason)
            else:
                self._version("git", git)
        self._check()
        if self.request.context["platform"] == "android":
            try:
                java, javac = self.lookup.linux_jdk() if self.host == "linux" else self.lookup.mac_jdk()
            except ToolUnavailable as error:
                reason = "unselected-installation" if self.host == "macos" else error.reason
                self.checks["java"], self.checks["javac"] = row("java", reason=reason), row("javac", reason=reason)
            else:
                self._version("java", java)
                self._version("javac", javac)
        elif developer is None:
            self.checks["xcode"] = row("xcode", reason="unselected-installation")
        elif developer.path == "/Library/Developer/CommandLineTools":
            self.checks["xcode"] = row("xcode", reason="full-xcode-not-selected")
        else:
            try:
                xcode = self.lookup.mac_developer_tool(developer, "xcode")
            except ToolUnavailable as error:
                self.checks["xcode"] = row("xcode", reason=error.reason)
            else:
                self._version("xcode", xcode, developer=developer)
        self._check()
        self.roster_finished = True

    def close(self) -> None:
        self.lookup.close()

    def terminal(self) -> dict[str, Any]:
        verdict = self.guard.lifetime_ledger.verdict()
        if verdict.profile_calls != 0:
            self.guard._abort(ProtocolError("Unexpected diagnostics lifetime domain"))
            verdict = self.guard.lifetime_ledger.verdict()
        if self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")
        lifetime = {"complete": verdict.complete, "fatal": verdict.fatal, "contained": verdict.contained,
            "commandDispatched": verdict.command_dispatched, "commands": verdict.commands,
            "inputClosed": self.source.closed, "handlersRestored": self.guard.handler_state == "RESTORED",
            "toolDescriptorsClosed": self.lookup.closed, "stopObserved": self.source.stop_reason}
        settled = (verdict.cleanup_complete and verdict.contained and self.source.closed
                   and lifetime["handlersRestored"] and lifetime["toolDescriptorsClosed"])
        if self.source.stop_reason != "none":
            outcome = self.source.stop_reason
        elif not settled or self.primary is not None or not self.roster_finished:
            outcome = "partial" if any(check["state"] == "completed" for check in self.checks.values()) else "failed"
        else:
            outcome = "complete" if self.commands_attempted else "unavailable"
        return {"schemaVersion": 1, "policyVersion": POLICY, "context": dict(self.request.context),
            "hostPlatform": self.host, "outcome": outcome, "checks": list(self.checks.values()),
            "commandsAttempted": self.commands_attempted, "lifetime": lifetime, "assurance": assurance(self.commands_attempted)}
