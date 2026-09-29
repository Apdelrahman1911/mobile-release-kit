"""One original saved Android build/inspection operation, not a command API.

Selection values are DATA. The invocation, fixed input source, file owners and
tool owner remain original objects through their actual closes. This module
does not execute a program, select an ambient tool, sign, or contact a Store.
The native owner still supplies the earlier startup-inclusive final deadline.
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ._desktop_android_build_control import AndroidBuildInput
from ._desktop_android_build_protocol import AndroidBuildRequest, REASONS, is_signed, stages, require
from ._desktop_android_build_selection import (
    SavedAndroidSelection, bind_saved_android_validation, bind_saved_android_version, select_saved_android_configuration,
)
from .build_inputs import InvocationCustody
from .cancellation import DefaultCancellation
from .config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES, ReleaseConfig, ReleaseVersion
from .owned_process import ProcessError, ProcessOutcomeUnknown, fatal_lifetime_error

if TYPE_CHECKING:
    from ._desktop_android_build_files import AndroidBuildFiles, OriginalAndroidArtifact
    from .android_build_tools import AndroidValidationTools


class AndroidBuildError(Exception):
    """A fixed reason only; private paths, inputs and tool output never escape."""

    def __init__(self, reason: str) -> None:
        require(reason in REASONS and reason not in {"none", "cleanup-unknown"})
        self.reason = reason
        super().__init__("The saved Android build operation could not complete")


@dataclass(frozen=True, slots=True)
class BoundAndroidInputs:
    """Private parsed values; original file receipts remain in AndroidBuildFiles."""

    config: ReleaseConfig
    saved: SavedAndroidSelection
    task: str
    check_signer: bool

    @property
    def release(self) -> ReleaseVersion:
        return self.saved.release


class AndroidBuildOperation:
    def __init__(self, request: AndroidBuildRequest, guard: DefaultCancellation,
                 source: AndroidBuildInput) -> None:
        require(type(request) is AndroidBuildRequest and type(guard) is DefaultCancellation
                and type(source) is AndroidBuildInput and source.guard is guard
                and guard._android_build_source is source and source.active and source.request_returned
                and threading.current_thread() is threading.main_thread())
        self.request, self.guard, self.source = request, guard, source
        self.root, self.operation_id = Path(request.native["projectRoot"]), request.operation_id
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.invocation: InvocationCustody | None = None
        self.invocation_attempted = False
        self.inputs: BoundAndroidInputs | None = None
        self.files: AndroidBuildFiles | None = None
        self.tools: AndroidValidationTools | None = None
        self.counters: dict[str, int] = {}
        self.failure: str | None = None
        self.prepared = False
        self.close_claimed = False
        self.resources_closed = False
        self.work_finish_attempted = False
        self.cleanup_errors: list[BaseException] = []
        self._pending: str | None = None
        self.signing = None
        require(source.signed is is_signed(request.context))
        self._roles = ({"keytool-validate": "new", "gradle": "new", "jarsigner-sign": "new",
                        "bundletool": "new", "jarsigner": "new", "keytool": "new"}
                       if source.signed else {"gradle": "new", "bundletool": "new"})
        if not source.signed and request.context["artifactValidation"]["mode"] == "upload-signature":
            self._roles.update(jarsigner="new", keytool="new")
        self._signature_passed = False
        self._command_before: dict[str, int] = {}
        self._returned: dict[str, int] = {}
        self._dispatch: dict[str, bool | None] = {role: False for role in self._roles}
        self.command_failure_role: str | None = None
        self._artifact: OriginalAndroidArtifact | None = None
        self.zip_metadata = None
        self.stage = "accepted"
        self._ignore_policy_read = False
        # Constructors below acquire no filesystem/tool resources. Root this
        # original operation before the service constructor can lose its return.
        source.bind_operation(self)
        if source.signed:
            from ._desktop_android_signed_inputs import SignedAndroidInputs
            self.signing = SignedAndroidInputs(self)
        from ._desktop_android_build_files import AndroidBuildFiles
        self.files = AndroidBuildFiles(self)

    def owner(self) -> None:
        require(self.pid == os.getpid() and self.thread is threading.current_thread()
                and self.thread is threading.main_thread() and self.source.operation is self
                and self.source.guard is self.guard)
        self.guard._check_owner()

    def _tick(self) -> None:
        self.owner()
        require(not self.close_claimed)
        if self.failure is not None:
            raise AndroidBuildError(self.failure)
        self.guard.check()
        if time.monotonic() >= self.source.work_end:
            self.source.stop("timed-out")
            self.guard.check()

    def checkpoint(self) -> None:
        self._tick()
        require(self.invocation is not None)
        self.invocation.require(root=self.root, cancellation=self.guard, signing_lease=None)
        if self.invocation.project_owner is not None:
            _, identity = self.invocation._android_build_root(self)
            if identity != self.request.native["rootIdentity"]:
                self.fail("project-admission-refused")

    def cleanup_checkpoint(self) -> None:
        """No new invocation admission, recursive file walk, or clock renewal."""
        self.owner()
        endpoint = self.source.work_end + 10
        if self.source.first_failure is not None:
            endpoint = min(endpoint, self.source.first_failure + 10)
        if time.monotonic() >= endpoint:
            self.fail("work-retained")

    def charge(self, name: str, amount: int, limit: int) -> None:
        # File/project checks call bounded name enumeration. Charging must not
        # recursively call invocation.require -> Project.check -> names again.
        if self.close_claimed or self.guard.depth:
            self.cleanup_checkpoint()
        else:
            self._tick()
        old = self.counters.get(name, 0)
        if (type(amount) is not int or amount < 0 or type(limit) is not int or limit <= 0
                or old > limit - amount):
            self.fail("work-retained" if self.close_claimed else "input-limit")
        self.counters[name] = old + amount

    def fail(self, reason: str) -> None:
        self.owner()
        if self.failure is None:
            self.failure = reason
        self.source.failure_observed()
        raise AndroidBuildError(reason)

    def bind_invocation(self, invocation: InvocationCustody) -> None:
        self._tick()
        require(type(invocation) is InvocationCustody and self.invocation is None
                and invocation.root == self.root and invocation.mode == "build"
                and invocation.cancellation is self.guard and invocation.signing_lease is None)
        self.invocation = invocation

    def _namespace_root(self, namespace, *, ensure_meta: bool = False, cleanup: bool = False) -> int:
        self.owner()
        require(self.files is not None and self.files.namespace is namespace
                and self.invocation is not None and type(cleanup) is bool
                and not (cleanup and ensure_meta))
        fd, identity = (self.invocation._android_build_cleanup_root(self) if cleanup
                        else self.invocation._android_build_root(self))
        if identity != self.request.native["rootIdentity"]:
            self.fail("project-admission-refused")
        if ensure_meta:
            require(not self.close_claimed and self.invocation.project_owner is not None)
            self.invocation.project_owner.ensure_meta()
            fd, again = self.invocation._android_build_root(self)
            require(again == identity)
        return fd

    def bind_inputs(self) -> BoundAndroidInputs:
        self.checkpoint()
        require(self.inputs is None and self.files is not None)
        raw = self.files.read_input("release/mobile-release.json", limit=MAX_CONFIG_BYTES, optional=True)
        data, selected = select_saved_android_configuration(raw, self.request.context["savedConfig"])
        check_signer = bind_saved_android_validation(selected, self.request.context["artifactValidation"])
        require(check_signer is ("jarsigner" in self._roles))
        version = self.files.read_input(selected.source, limit=MAX_VERSION_BYTES, optional=True)
        saved = bind_saved_android_version(selected, version, self.request.context["savedVersion"])
        config = ReleaseConfig(path=self.root / "release/mobile-release.json", root=self.root, data=data)
        from .android import _bundle_task
        self.inputs = BoundAndroidInputs(config, saved, _bundle_task(selected.module, selected.variant), check_signer)
        self.check_inputs()
        if self.signing is not None:
            self.signing.bind_config()
        return self.inputs

    def _project_tool_inputs(self) -> dict[str, bytes | None]:
        require(self.inputs is not None and self.files is not None)
        module = self.inputs.saved.configuration.module.lstrip(":").replace(":", "/")
        names = {
            "wrapper_properties": "gradle/wrapper/gradle-wrapper.properties",
            "local_properties": "local.properties",
            "root_gradle_properties": "gradle.properties",
            "module_gradle_properties": f"{module}/gradle.properties" if module else "gradle.properties",
            "daemon_jvm_properties": "gradle/gradle-daemon-jvm.properties",
        }
        values: dict[str, bytes | None] = {}
        captured: dict[str, bytes | None] = {}
        remaining = 512 * 1024
        for role, name in names.items():
            if name not in captured:
                if remaining < 1:
                    self.fail("input-limit")
                raw = self.files.read_input(name, limit=remaining, optional=True)
                if raw is not None:
                    self.charge("tool-selection-bytes", len(raw), 512 * 1024)
                    remaining -= len(raw)
                captured[name] = raw
            values[role] = captured[name]
        return values

    def prepare(self) -> None:
        self.checkpoint()
        require(self.inputs is not None and not self.prepared and self.tools is None and self.files is not None)
        from .android_build_tools import AndroidValidationTools
        self.tools = AndroidValidationTools(self, self.request.native["toolchain"])
        self.tools.acquire()
        if self.inputs.check_signer:
            self.tools.require_signature_tools()
        self.tools.check_project_inputs(self._project_tool_inputs())
        self.check_inputs()
        self.files.prepare_namespace()
        self.tools.check()
        self.checkpoint()
        self.prepared = True

    def require(self, config: ReleaseConfig, cancellation: DefaultCancellation | None) -> None:
        self.checkpoint()
        require(self.inputs is not None and config is self.inputs.config and cancellation is self.guard
                and self.prepared and self.files is not None and self.tools is not None
                and self.guard._android_build_source is self.source)

    def selection(self) -> dict | None:
        self.owner()
        if self.inputs is None:
            return None
        value = self.inputs.saved.configuration
        return {"module": value.module, "variant": value.variant,
                "applicationId": value.application_id, "task": self.inputs.task}

    def used_inputs(self) -> tuple[dict, dict]:
        self.owner()
        require(self.inputs is not None)
        saved = self.inputs.saved
        config = {"bytes": len(saved.configuration.raw), "sha256": hashlib.sha256(saved.configuration.raw).hexdigest()}
        version = {"source": saved.configuration.source, "bytes": len(saved.version_raw),
                   "sha256": hashlib.sha256(saved.version_raw).hexdigest(),
                   "name": saved.release.name, "build": saved.release.build}
        return config, version

    def check_inputs(self) -> None:
        self.checkpoint()
        require(self.files is not None)
        self.files.check_inputs()
        self.checkpoint()

    def advance(self, stage: str) -> None:
        """Reached fixed stage only; the original engine encodes the frame."""
        self.checkpoint()
        allowed = stages(self.request.context)
        previous = -1 if self.stage == "accepted" else allowed.index(self.stage)
        require(stage in allowed and (allowed.index(stage) == previous + 1 if self.signing is not None
                                      else allowed.index(stage) > previous))
        if self.signing is not None:
            if stage == "signing":
                require(self.signing.command_slot is None and self.signing.command_application is None
                        and self.signing.command_service is None and not self.signing.dispatch_claimed)
            elif allowed.index(stage) > allowed.index("signing"):
                require(self.signing.dispatch_published)
        self.stage = stage  # A failed progress write cannot erase reached work.
        if self.signing is not None and stage == "signing":
            # The internal stage precedes command preparation. Its existing
            # public frame instead means the original RUN_TOOL send completed.
            return
        self.source.progress(stage)

    def _project_ignore_policy(self) -> bytes | None:
        """Original ignore-policy DATA, charged within selection-text limits."""
        self.checkpoint()
        require(self.files is not None)
        remaining = 512 * 1024 - self.counters.get("tool-selection-bytes", 0)
        # Repeated ensure_meta uses the retained original file and its recheck,
        # not a new open or a second retained-byte charge.
        limit = 512 * 1024 if self._ignore_policy_read else remaining
        if limit < 1:
            self.fail("input-limit")
        raw = self.files.read_input(".gitignore", limit=limit, optional=True)
        if not self._ignore_policy_read:
            self._ignore_policy_read = True
            if raw is not None:
                self.charge("tool-selection-bytes", len(raw), 512 * 1024)
        return raw

    def _arm(self, role: str) -> None:
        self.checkpoint()
        require(role in self._roles and self._pending is None and self._roles[role] == "new")
        facts = self.guard.lifetime_ledger.verdict()
        require(facts.cleanup_complete and facts.contained and not facts.fatal and facts.profile_calls == 0)
        previous = tuple(self._roles)[:tuple(self._roles).index(role)]
        require(facts.commands == len(previous) and all(self._roles[item] == "returned" for item in previous))
        if self.signing is not None:
            expected_stage = {"keytool-validate": "validating-signing", "gradle": "building",
                              "jarsigner-sign": "signing", "bundletool": "inspecting",
                              "jarsigner": "inspecting", "keytool": "inspecting"}[role]
            require(self.stage == expected_stage)
            if role != "keytool-validate":
                require(self._returned.get("keytool-validate") == 0 and self.signing.validation_passed)
            if role in {"gradle", "jarsigner-sign"}:
                self.signing.require_materialized(self.signing.materialization)
            if role == "jarsigner-sign":
                require(self._returned.get("gradle") == 0 and self._artifact is None
                        and self.files is not None and self.files.signing_input is not None
                        and self.files.signing_input._native)
            if role in {"bundletool", "jarsigner", "keytool"}:
                require(self._returned.get("jarsigner-sign") == 0 and self.signing.inputs_closed())
        if role in {"bundletool", "jarsigner", "keytool"}:
            require(self._returned.get("gradle") == 0 and self._artifact is not None)
        if role in {"jarsigner", "keytool"}:
            require(self.inputs is not None and self.inputs.check_signer)
        if role == "keytool":
            require(self._signature_passed)
        self._command_before[role] = facts.commands
        self._roles[role], self._pending = "armed", role

    def gradle_command(self) -> tuple[str, ...]:
        require(self.inputs is not None and self.tools is not None and self.files is not None)
        self.require(self.inputs.config, self.guard)
        self.check_inputs()
        self.tools.check()
        argv = self.tools.gradle_command(self.inputs.task, self.files.work_path)
        self._arm("gradle")
        return argv

    def bundletool_command(self, path: Path, tools) -> tuple[str, ...]:
        self.checkpoint()
        require(tools is self.tools and self.tools is not None and self._artifact is not None
                and path == self._artifact.path)
        self.tools.check()
        self._artifact.check()
        argv = self.tools.bundletool_command(path)
        self._arm("bundletool")
        return argv

    def jarsigner_command(self, path: Path, tools) -> tuple[str, ...]:
        self.checkpoint()
        require(self.inputs is not None and self.inputs.check_signer and tools is self.tools
                and self.tools is not None and self._artifact is not None and path == self._artifact.path)
        self.tools.check()
        self._artifact.check()
        argv = self.tools.jarsigner_command(path)
        self._arm("jarsigner")
        return argv

    def signature_accepted(self, path: Path, tools) -> None:
        """Called only after the common jarsigner policy accepts an actual return."""
        self.checkpoint()
        require(self.inputs is not None and self.inputs.check_signer and tools is self.tools
                and self._artifact is not None and path == self._artifact.path and self._artifact._native
                and not self._signature_passed and self._pending is None
                and self._roles.get("jarsigner") == "returned" and self._returned.get("jarsigner") in {0, 4})
        self._artifact.check()
        self._signature_passed = True

    def keytool_command(self, path: Path, tools) -> tuple[str, ...]:
        self.checkpoint()
        require(self.inputs is not None and self.inputs.check_signer and self._signature_passed
                and tools is self.tools and self.tools is not None and self._artifact is not None
                and path == self._artifact.path)
        self.tools.check()
        self._artifact.check()
        argv = self.tools.keytool_command(path)
        self._arm("keytool")
        return argv

    def command_environment(self) -> dict[str, str]:
        self.checkpoint()
        require(self.inputs is not None and self.tools is not None and self.files is not None)
        # The one fixed owner creates a fresh map; no ambient inheritance here.
        environment = self.tools.command_environment(self.files.work_path, self.inputs.release)
        if self.signing is not None and self._pending in {"keytool-validate", "gradle", "jarsigner-sign"}:
            return self.signing.command_environment(environment, self._pending)
        return environment

    def command_limits(self, timeout: int, capture: bool, output_limit: int) -> tuple[int, int]:
        self.checkpoint()
        role = self._pending
        require(role in self._roles and self._roles[role] == "armed"
                and type(capture) is bool and capture is (role != "gradle")
                and type(timeout) is int and timeout > 0 and type(output_limit) is int and output_limit > 0)
        self._roles[role] = "attempted"  # Claim once, before run_command can allocate anything.
        self._dispatch[role] = None
        ceiling = {"keytool-validate": 30, "gradle": 2700, "jarsigner-sign": 120,
                   "bundletool": 60, "jarsigner": 120, "keytool": 30}[role]
        return min(timeout, ceiling), min(output_limit, 2 * 1024 * 1024)

    def returned(self, role: str, code: int) -> None:
        # Store the actual returned command DATA before a later cancellation
        # check. Cancellation cannot invent or erase an exit already observed.
        self.owner()
        require(role in self._roles and self._pending == role and self._roles[role] == "attempted"
                and type(code) is int and -(2 ** 31) <= code < 2 ** 31)
        facts = self.guard.lifetime_ledger.verdict()
        require(facts.cleanup_complete and facts.contained and not facts.fatal
                and facts.command_dispatched is True and facts.profile_calls == 0
                and facts.commands == self._command_before[role] + 1)
        self._returned[role] = code
        self._dispatch[role] = True
        self._roles[role], self._pending = "returned", None

    def command_error(self, role: str, error: BaseException) -> None:
        self.owner()
        require(role in self._roles)
        self.source.failure_observed()
        if self.command_failure_role is None:
            self.command_failure_role = role
        if self._roles[role] != "returned":
            facts = self.guard.lifetime_ledger.verdict()
            before = self._command_before.get(role)
            if self._roles[role] == "attempted":
                # A previous preflight's aggregate dispatch says nothing about
                # this role. Only healthy original no-call/no-exec evidence can
                # distinguish not-dispatched from a lost command return.
                no_call = before is not None and facts.commands == before
                no_exec = (before is not None and facts.commands == before + 1
                           and isinstance(error, ProcessError) and not isinstance(error, ProcessOutcomeUnknown)
                           and error.dispatched is False and error.contained is True and error.cleanup_complete is True)
                self._dispatch[role] = (False if facts.cleanup_complete and facts.contained
                                        and facts.profile_calls == 0 and (no_call or no_exec) else None)
            self._roles[role] = "failed"
        if self._pending == role:
            self._pending = None
        self.guard.lifetime_ledger._remember(error)

    def role_outcome(self, role: str) -> dict:
        self.owner()
        require(role in self._roles)
        if role in self._returned:
            return {"outcome": "exited", "exitCode": self._returned[role]}
        if role == "jarsigner-sign" and self.signing is not None:
            # A genuine original wait may precede a cancelled/lost Python
            # return. Expose that observed exit, but NEVER put it in _returned:
            # observation cannot authorize capture or a successor command.
            code = self.signing.observed_exit()
            if code is not None:
                return {"outcome": "exited", "exitCode": code}
        return {"outcome": "not-dispatched" if self._dispatch[role] is False else "unknown", "exitCode": None}

    def command_outcome(self) -> dict:
        return self.role_outcome("gradle")

    def commands_settled(self) -> bool:
        self.owner()
        facts = self.guard.lifetime_ledger.verdict()
        # An independent filesystem failure does not invent a living command.
        # Actual incomplete original command records do keep this false.
        return facts.complete and facts.contained and facts.profile_calls == 0

    def signing_activity(self) -> dict | None:
        self.owner()
        return None if self.signing is None else self.signing.activity()

    def capture_ready(self, module: str, variant: str) -> None:
        self.checkpoint()
        require(self.inputs is not None and self.prepared and self._pending is None
                and self._returned.get("gradle") == 0
                and (module, variant) == (self.inputs.saved.configuration.module,
                                          self.inputs.saved.configuration.variant))
        facts = self.guard.lifetime_ledger.verdict()
        require(facts.cleanup_complete and facts.contained and not facts.fatal
                and facts.command_dispatched is True and facts.commands == (2 if self.signing is not None else 1)
                and facts.profile_calls == 0)

    def capture_after(self) -> OriginalAndroidArtifact:
        require(self.inputs is not None and self.files is not None and self._artifact is None)
        require(self.signing is None)
        selected = self.inputs.saved.configuration
        self.capture_ready(selected.module, selected.variant)
        self._artifact = self.files.capture_aab(selected.module, selected.variant)
        self.check_inputs()
        return self._artifact

    def capture_for_signing(self):
        require(self.signing is not None and self.inputs is not None and self.files is not None
                and self._artifact is None and self.stage == "capturing")
        selected = self.inputs.saved.configuration
        self.capture_ready(selected.module, selected.variant)
        captured = self.files.capture_signing_input(selected.module, selected.variant)
        self.check_inputs()
        return captured

    def capture_signed(self) -> OriginalAndroidArtifact:
        require(self.signing is not None and self.files is not None and self._artifact is None
                and self.stage == "signing" and self.signing.dispatch_published
                and self._returned.get("jarsigner-sign") == 0
                and self._pending is None and self.commands_settled())
        self._artifact = self.files.capture_signed()
        self.check_inputs()
        return self._artifact

    def artifact(self, logical_name: str = "android-aab") -> OriginalAndroidArtifact:
        self.checkpoint()
        require(logical_name == "android-aab" and self._artifact is not None)
        self._artifact.check()
        return self._artifact

    def finish_work(self) -> None:
        self.owner()
        require(self.files is not None and not self.work_finish_attempted)
        self.work_finish_attempted = True
        self.files.finish_work()

    def close(self) -> None:
        self.owner()
        if self.close_claimed:
            require(self.resources_closed)
            return
        self.close_claimed = True
        first = None
        # Independent original closures are all attempted. No failed consuming
        # deletion is retried, and no application/shared cache is selected.
        actions = []
        if self.signing is not None:
            actions.append(self.signing.close)
        if self.files is not None:
            if not self.work_finish_attempted:
                actions.append(self.finish_work)
            actions.append(self.files.close)
        if self.tools is not None:
            actions.append(self.tools.close)
        with self.guard.deferred(check_on_exit=False):
            for action in actions:
                try:
                    action()
                except BaseException as error:
                    self.source.failure_observed()
                    self.cleanup_errors.append(error)
                    self.guard.lifetime_ledger._remember(error)
                    if fatal_lifetime_error(error, "Original Android resource closure did not settle") is not None:
                        self.guard._abort(error)
                    if first is None:
                        first = error
        self.resources_closed = ((self.signing is None or self.signing.inputs_closed())
                                 and (self.files is None or self.files.closed())
                                 and (self.tools is None or self.tools.closed()))
        if first is not None:
            raise first
        require(self.resources_closed)

    def closed(self) -> bool:
        self.owner()
        invocation_closed = (not self.invocation_attempted if self.invocation is None
                             else self.invocation._android_build_closed(self))
        return (self.close_claimed and self.resources_closed and invocation_closed
                and (self.signing is None or self.signing.inputs_closed())
                and (self.files is None or self.files.closed()) and (self.tools is None or self.tools.closed()))

    def disposition(self) -> dict[str, str]:
        self.owner()
        return ({"work": "not-created", "artifacts": "not-created"} if self.files is None
                else self.files.disposition())
