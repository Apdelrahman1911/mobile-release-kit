"""One original local Android Store-access query, never mutation authority.

The native Session retains the installed runtime and selected private record.
This child borrows its original cancellation/input, existing filesystem owners,
selected material, command runner and sealed readback; no application commands.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
import time

from ._desktop_store_preflight_control import StorePreflightInput
from ._desktop_store_preflight_protocol import StorePreflightRequest, ProtocolError, project_result, require
from ._store_runtime import StoreRuntimeContext
from .build_inputs import (_Directory, _read_file, _attempt_all, FiniteScratch,
                           InvocationCustody, finite_scratch, invocation_custody)
from .cancellation import DefaultCancellation
from .config import (MAX_CONFIG_BYTES, MAX_VERSION_BYTES, ReleaseConfig, parse_config_text, parse_key_value_text,
                     release_version_from_values)
from .credentials import _selected_store_material, store_material_prerequisite_findings
from .errors import ConfigurationError
from .owned_process import fatal_lifetime_error
from .preflight import _online_query_blockers
from .reporting import Finding, Status, FAILING_STATUSES
from .stores import _fastlane_probe_commands, online_preflight_findings


class _Refused(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__("Saved Store access input was refused")


class StorePreflightRun:
    def __init__(self, request, guard, source):
        require(type(request) is StorePreflightRequest and type(guard) is DefaultCancellation
                and type(source) is StorePreflightInput and source.guard is guard
                and guard._store_preflight_source is source and source.active and source.request_returned
                and threading.current_thread() is threading.main_thread())
        self.request, self.guard, self.source = request, guard, source
        self.operation = self  # Existing engine's fixed operation/service seam.
        self.root = Path(request.native["projectRoot"])
        self._request_bytes = self._request_data()
        self.invocation = self.runtime = None
        self.scratches, self.directories, self.reads = [], [], []
        self.primary = self.report = None
        self._ran = self._close_claimed = False
        self._next_command = 0
        self._pending = self._pending_argv = None
        self._pending_capture = None
        self._command_claimed = False
        source.bind_operation(self)  # Before any fallible resource admission.

    def _request_data(self):
        return json.dumps([self.request.context, self.request.native], sort_keys=True,
                          separators=(",", ":"), allow_nan=False)

    def checkpoint(self):
        require(self.source.require_operation() is self and not self._close_claimed
                and self._request_bytes == self._request_data())
        self.guard.check()  # Original held input and original work endpoint.

    def remember(self, error):
        if self.primary is None:
            self.primary = error
        self.source.failure_observed()
        self.guard.lifetime_ledger._remember(error)
        if fatal_lifetime_error(error, "Store access ownership did not settle") is not None:
            self.guard._abort(error)
        if self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")

    def bind_invocation(self, owner):
        require(type(owner) is InvocationCustody and self.invocation is None and owner.mode == "online"
                and owner.cancellation is self.guard and owner.root == self.root)
        self.invocation = owner

    def bind_scratch(self, scratch):
        layouts = ("online-runner", "store-selection", "store-selection", "online-runner", "online-readback")
        require(type(scratch) is FiniteScratch and scratch.cancellation is self.guard
                and len(self.scratches) < len(layouts) and scratch.layout == layouts[len(self.scratches)]
                and self.invocation is not None and scratch.journal is None and scratch._lane_binding is None)
        self.scratches.append(scratch)  # Original before any acquisition.

    def _read(self, relative, maximum):
        self.checkpoint()
        path = self.root / relative
        directory = _Directory(path.parent, self.guard)
        self.directories.append(directory)
        directory.acquire()
        observed = _read_file(directory.fd, path.name, self.guard, maximum)
        if observed is None:
            raise _Refused("saved-source-changed")
        binding, raw = observed
        self.reads.append((directory, path.name, maximum, binding))
        self.checkpoint()
        return raw

    def _saved(self):
        directory = _Directory(self.root, self.guard)
        self.directories.append(directory); directory.acquire()
        current = os.fstat(directory.fd)
        identity = {"device": str(current.st_dev), "inode": str(current.st_ino),
                    "mode": current.st_mode, "uid": current.st_uid, "gid": current.st_gid}
        if identity != self.request.native["rootIdentity"]:
            raise _Refused("saved-source-changed")
        raw = self._read("release/mobile-release.json", MAX_CONFIG_BYTES)
        if {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} != self.request.context["savedConfig"]:
            raise _Refused("saved-source-changed")
        try:
            data = parse_config_text(raw.decode("utf-8"))
            canonical = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
            if {"bytes": len(canonical), "sha256": hashlib.sha256(canonical).hexdigest()} != self.request.native["credentialConfig"]:
                raise _Refused("saved-source-changed")
            config = ReleaseConfig(path=self.root / "release/mobile-release.json", root=self.root, data=data)
            spec, saved = config.section("version"), self.request.context["savedVersion"]
            if not config.platform_enabled("android") or spec["source"] != saved["source"]:
                raise _Refused("saved-source-invalid")
            raw = self._read(saved["source"], MAX_VERSION_BYTES)
            if len(raw) != saved["bytes"] or hashlib.sha256(raw).hexdigest() != saved["sha256"]:
                raise _Refused("saved-source-changed")
            version = release_version_from_values(parse_key_value_text(raw.decode("utf-8")),
                name_key=spec["nameKey"], build_key=spec["buildKey"],
                ios_enabled=config.platform_enabled("ios"), source_label="saved version")
            if version.name != saved["name"] or version.build != saved["build"]:
                raise _Refused("saved-source-changed")
        except (ConfigurationError, ValueError, TypeError, UnicodeError, KeyError, RecursionError):
            raise _Refused("saved-source-invalid") from None
        return config, version

    def _source_post(self):
        self.checkpoint()
        for directory, name, limit, original in self.reads:
            directory.check()
            value = _read_file(directory.fd, name, self.guard, limit, binding_only=True)
            if value is None or value[0] != original:
                raise _Refused("saved-source-changed")
        for directory in self.directories:
            directory.check()
        self.checkpoint()

    @staticmethod
    def validate_material_shape(raw):
        # Native already validates the RSA PKCS#8 envelope on these exact bytes.
        # Defense in depth here admits only a flat Google service-account source;
        # not gcloud/user ADC, executable credential sources or custom endpoints.
        from ._desktop_store_preflight_protocol import _pairs
        required = {"type", "project_id", "private_key_id", "private_key", "client_email", "client_id", "token_uri"}
        optional = {"auth_uri", "auth_provider_x509_cert_url", "client_x509_cert_url", "universe_domain"}
        try:
            require(type(raw) is bytes and 0 < len(raw) <= 16 * 1024)
            key = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: require(False))
            require(type(key) is dict and required <= set(key) <= required | optional
                    and all(type(value) is str and value and "\0" not in value for value in key.values())
                    and key["type"] == "service_account" and key["token_uri"] == "https://oauth2.googleapis.com/token"
                    and re.fullmatch(r"[a-z][a-z0-9-]{4,61}[a-z0-9]", key["project_id"])
                    and re.fullmatch(r"[a-zA-Z0-9._-]{1,64}@" + re.escape(key["project_id"]) + r"\.iam\.gserviceaccount\.com", key["client_email"])
                    and re.fullmatch(r"[a-fA-F0-9]{40}", key["private_key_id"])
                    and re.fullmatch(r"[0-9]{1,32}", key["client_id"])
                    and key["private_key"].startswith("-----BEGIN PRIVATE KEY-----\n")
                    and key["private_key"].rstrip().endswith("-----END PRIVATE KEY-----"))
            for name, expected in (("auth_uri", "https://accounts.google.com/o/oauth2/auth"),
                    ("auth_provider_x509_cert_url", "https://www.googleapis.com/oauth2/v1/certs"),
                    ("universe_domain", "googleapis.com")):
                require(name not in key or key[name] == expected)
            if "client_x509_cert_url" in key:
                prefix = "https://www.googleapis.com/robot/v1/metadata/x509/"
                require(key["client_x509_cert_url"] in (prefix + key["client_email"],
                                                       prefix + key["client_email"].replace("@", "%40")))
        except (ValueError, TypeError, UnicodeError, KeyError, RecursionError):
            raise _Refused("credentials-unavailable") from None

    @contextmanager
    def command(self, runtime, argv, *, capture):
        self.checkpoint()
        require(runtime is self.runtime and type(runtime) is StoreRuntimeContext and self._pending is None
                and self._next_command < 6 and type(capture) is bool)
        expected = (*_fastlane_probe_commands(runtime.tooling_root),
                    ("bundle", "exec", "ruby", str(runtime.tooling_root / "fastlane/run_lane.rb"), "android_online_preflight"))
        index = self._next_command
        require(tuple(argv) == expected[index] and capture is (index < 5))
        self._next_command += 1  # Failed/unknown calls are never replayed.
        self._pending, self._pending_argv, self._pending_capture = index, expected[index], capture
        self._command_claimed = False
        try:
            yield
        except BaseException as error:
            self.remember(error)
            raise
        finally:
            self._pending = self._pending_argv = self._pending_capture = None

    def command_arguments(self, argv, *, capture, evidence):
        from ._command_process import CommandCallEvidence
        self.checkpoint()
        require(self._pending is not None and not self._command_claimed
                and tuple(argv) == self._pending_argv and capture is self._pending_capture
                and (type(evidence) is CommandCallEvidence if self._pending == 5 else evidence is None))
        self._command_claimed = True

    def command_limits(self, timeout, capture, output_limit):
        self.checkpoint()
        require(self._pending is not None and capture is self._pending_capture and self._command_claimed)
        maximum = 60 if self._pending < 5 else 900
        return min(timeout, maximum), min(output_limit, 2 * 1024 * 1024)

    def require_query_timing(self, timeout):
        self.checkpoint()
        require(self._pending == 5 and self._command_claimed and self._pending_capture is False
                and type(timeout) is int and 1 <= timeout <= 900
                and time.monotonic() + timeout <= self.source.work_end)

    def run(self):
        self.checkpoint()
        require(not self._ran and sys.platform == "darwin" and os.getcwd() == self.request.native["cwd"])
        self._ran = True
        try:
            config, version = self._saved()
            with invocation_custody(self.root, mode="online", cancellation=self.guard) as invocation:
                with finite_scratch(layout="online-runner", cancellation=self.guard, parent=Path("/private/tmp")) as home:
                    self.runtime = StoreRuntimeContext.installed(Path(self.request.native["cwd"]),
                                                               invocation=invocation, private_home=home)
                    with finite_scratch(layout="store-selection", cancellation=self.guard, parent=home._path) as received:
                        original = self.source.receive_material(self, received)
                        values = {"GOOGLE_APPLICATION_CREDENTIALS": str(received.require(original))}
                        findings = store_material_prerequisite_findings(values=values, platforms=("android",))
                        with _selected_store_material(config, values=values, platforms=("android",),
                                                      invocation=invocation, scratch_parent=home._path) as material:
                            findings.extend(material.validate())
                            blockers = _online_query_blockers(config, ("android",), findings)
                            if blockers:
                                findings.append(Finding("store.online.gate", Status.BLOCKED,
                                                        "Configure the required saved Store inputs.", category="store-access"))
                            elif not any(row.status in FAILING_STATUSES for row in findings):
                                findings.extend(online_preflight_findings(config=config, release=version,
                                    platforms=("android",), material=material, invocation=invocation, runtime_context=self.runtime))
                            self._source_post()
                            self.report = project_result(findings)
        except BaseException as error:
            self.remember(error)
            raise
        finally:
            self.close()

    def close(self):
        if self._close_claimed:
            require(self.closed())
            return
        self._close_claimed = True
        # Reuse the actual fixed owners' single-attempt cleanup. An unconfirmed
        # close remains visible in closed(), never a retry by numeric FD.
        actions = [scratch.cleanup for scratch in reversed(self.scratches)]
        if self.invocation is not None:
            actions.append(self.invocation.cleanup)
        actions.extend(directory.close for directory in reversed(self.directories))
        try:
            _attempt_all(self.guard, actions)
        except BaseException as error:
            self.remember(error); self.guard._abort(error)
            raise

    def closed(self):
        require(self.source.operation is self)
        invocation_closed = self.invocation is None or self.invocation._store_preflight_closed(self)
        return (self._close_claimed and self._pending is None and invocation_closed
                and all(directory.slots and all(slot.number is None and slot.close_state == "CLOSED"
                        for slot in directory.slots) for directory in self.directories)
                and all(s.claimed and not s.active and s._cleanup_complete and not s.created
                        and all(slot.number is None and slot.close_state == "CLOSED"
                                for slot in (*s.writer_slots, s.slot, *s.parent.slots)) for s in self.scratches))

    def terminal(self):
        verdict = self.guard.lifetime_ledger.verdict()
        if verdict.profile_calls or verdict.commands > 6:
            self.guard._abort(ProtocolError("Unexpected Store access command lifetime"))
            verdict = self.guard.lifetime_ledger.verdict()
        if time.monotonic() >= self.source.work_end:
            self.source.stop("timed-out")
        elif self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")
        lifetime = {"complete": verdict.complete, "fatal": verdict.fatal, "contained": verdict.contained,
            "commandDispatched": verdict.command_dispatched, "commands": verdict.commands, "profileCalls": verdict.profile_calls,
            "inputClosed": self.source.material_closed(), "handlersRestored": self.guard.handler_state == "RESTORED",
            "invocationClosed": self.closed(), "stopObserved": self.source.stop_reason}
        settled = (verdict.cleanup_complete and verdict.contained and verdict.command_dispatched is not None
                   and lifetime["inputClosed"] and lifetime["handlersRestored"] and lifetime["invocationClosed"])
        result = None
        if not settled:
            outcome, reason = "unknown", "cleanup-unknown"
        elif self.source.stop_reason != "none":
            outcome = reason = self.source.stop_reason
        elif isinstance(self.primary, _Refused):
            outcome, reason = "refused", self.primary.reason
        elif self.primary is not None or self.report is None:
            outcome, reason = "failed", "command-incomplete"
        else:
            outcome, reason, result = "complete", "none", self.report
        return {"schemaVersion": 1, "context": self.request.context, "outcome": outcome,
                "reason": reason, "result": result, "lifetime": lifetime}
