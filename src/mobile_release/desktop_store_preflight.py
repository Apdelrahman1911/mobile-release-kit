"""One original local Store-access query, never mutation authority.

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
from ._desktop_store_preflight_protocol import StorePreflightRequest, ProtocolError, command_count, project_result, require
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
from . import apple_provisioning_bundle_read as bundle_read
from . import apple_provisioning_profile_read as profile_read
from . import ios_store_versions as store_versions
from . import android_store_versions as play_versions
from . import paired_store_versions as paired_versions


def _captured_query(context):
    return bundle_read.selected_read(context) or play_versions.selected_query(context) or paired_versions.selected_query(context)


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
        self._apple_material = None
        self._received = None
        self._received_material = None
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
        if paired_versions.selected_query(self.request.context):
            layouts = (*layouts[:4], "online-runner")  # Two sequential fixed readers, no readback file.
        elif _captured_query(self.request.context):
            layouts = layouts[:4]  # Private capture, never a Store-access output file.
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
            platforms = paired_versions.PLATFORMS if paired_versions.selected_query(self.request.context) else (self.request.context["platform"],)
            if not all(config.platform_enabled(p) for p in platforms) or spec["source"] != saved["source"]:
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

    @staticmethod
    def validate_apple_shape(parts):
        require(type(parts) is tuple and len(parts) == 3)
        key, key_id, issuer = parts
        if not (all(type(value) is bytes for value in parts) and 0 < len(key) <= 16 * 1024
                and re.fullmatch(rb"[A-Z0-9]{10}", key_id)
                and re.fullmatch(rb"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", issuer)):
            raise _Refused("credentials-unavailable")

    @staticmethod
    def validate_pair_shape(parts):
        require(type(parts) is tuple and len(parts) == 4)
        StorePreflightRun.validate_material_shape(parts[0])
        StorePreflightRun.validate_apple_shape(parts[1:])

    def _received_post(self):
        if self._received is not None:
            scratch, snapshot = self._received
            require(self.source._material is self._received_material)
            if paired_versions.selected_query(self.request.context):
                require(type(snapshot) is tuple and len(snapshot) == 2)
                for item in snapshot:
                    scratch.require(item)
                self.validate_pair_shape(self._received_material)
            else:
                scratch.require(snapshot)
            if self.request.context["platform"] == "ios":
                self.validate_apple_shape(self._received_material)

    def apple_material_command(self, material):
        from .credentials import SelectedStoreMaterial, APPLE_P8_CHECK
        self.checkpoint()
        pair = paired_versions.selected_query(self.request.context)
        require((self.request.context["platform"] == "ios" or pair) and type(material) is SelectedStoreMaterial
                and material._invocation is self.invocation and material._platforms == (paired_versions.PLATFORMS if pair else ("ios",))
                and len(self.scratches) >= 3 and material._scratch is self.scratches[2]
                and material._scratch.cancellation is self.guard and material._state == "validating"
                and self._apple_material in (None, material))
        self._apple_material = material
        self._received_post(); material._owner()
        return ("bundle", "exec", "ruby", "-ropenssl", "-e", APPLE_P8_CHECK,
                str(material._scratch.require(material._p8)))

    @property
    def _lane_index(self):
        return command_count(self.request.context["platform"]) - 1

    @contextmanager
    def command(self, runtime, argv, *, capture):
        self.checkpoint()
        require(runtime is self.runtime and type(runtime) is StoreRuntimeContext and self._pending is None
                and self._next_command <= self._lane_index and type(capture) is bool)
        query = _captured_query(self.request.context)
        index = self._next_command
        if paired_versions.selected_query(self.request.context):
            probes = tuple(_fastlane_probe_commands(runtime.tooling_root))
            expected = ((self.apple_material_command(self._apple_material) if index == 0 else ()),
                        *probes, store_versions.fixed_argv(runtime.tooling_root),
                        *probes, play_versions.fixed_argv(runtime.tooling_root))
        else:
            final = (play_versions.fixed_argv(runtime.tooling_root) if play_versions.selected_query(self.request.context) else
                     bundle_read.fixed_read_argv(runtime.tooling_root, self.request.context) if query else
                     ("bundle", "exec", "ruby", str(runtime.tooling_root / "fastlane/run_lane.rb"), self.request.context["platform"] + "_online_preflight"))
            expected = (*_fastlane_probe_commands(runtime.tooling_root), final)
        if self.request.context["platform"] == "ios":
            # Only the first command consumes the still-validating material.
            expected = ((self.apple_material_command(self._apple_material) if index == 0 else ()), *expected)
        require(tuple(argv) == expected[index] and capture is (index < self._lane_index or query))
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
                and (type(evidence) is CommandCallEvidence if self._pending == self._lane_index
                     and not _captured_query(self.request.context) else evidence is None))
        self._command_claimed = True

    def command_limits(self, timeout, capture, output_limit):
        self.checkpoint()
        require(self._pending is not None and capture is self._pending_capture and self._command_claimed)
        pair = paired_versions.selected_query(self.request.context)
        query = (self._pending in (6, 12) if pair else self._pending == self._lane_index) and _captured_query(self.request.context)
        maximum = 60 if self._pending < self._lane_index or query else 900
        limit = (store_versions.FRAME_LIMIT if pair and query else
                 play_versions.FRAME_LIMIT if query and play_versions.selected_query(self.request.context) else
                 store_versions.FRAME_LIMIT if query and store_versions.selected_query(self.request.context)
                 else bundle_read.FRAME_LIMIT if query else 2 * 1024 * 1024)
        return min(timeout, maximum), min(output_limit, limit)

    def require_query_timing(self, timeout):
        self.checkpoint()
        require(self._pending == self._lane_index and self._command_claimed and self._pending_capture is False
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
                        platform = self.request.context["platform"]
                        self._received = (received, original)
                        self._received_material = self.source._material
                        pair = paired_versions.selected_query(self.request.context)
                        platforms = paired_versions.PLATFORMS if pair else (platform,)
                        if pair:
                            self._received_post()
                            values = {"GOOGLE_APPLICATION_CREDENTIALS": str(received.require(original[0])),
                                      "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH": str(received.require(original[1])),
                                      "MOBILE_RELEASE_ASC_KEY_ID": self.source._material[2].decode("ascii"),
                                      "MOBILE_RELEASE_ASC_ISSUER_ID": self.source._material[3].decode("ascii")}
                        elif platform == "android":
                            values = {"GOOGLE_APPLICATION_CREDENTIALS": str(received.require(original))}
                        else:
                            self._received_post()
                            values = {"MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH": str(received.require(original)),
                                      "MOBILE_RELEASE_ASC_KEY_ID": self.source._material[1].decode("ascii"),
                                      "MOBILE_RELEASE_ASC_ISSUER_ID": self.source._material[2].decode("ascii")}
                        findings = store_material_prerequisite_findings(values=values, platforms=platforms)
                        with _selected_store_material(config, values=values, platforms=platforms,
                                                      invocation=invocation, scratch_parent=home._path) as material:
                            findings.extend(material.validate(runtime_context=self.runtime) if platform == "ios" or pair else material.validate())
                            if pair:
                                observation = paired_versions.unavailable()
                                if not paired_versions.query_prerequisites(config) or any(row.status in FAILING_STATUSES for row in findings):
                                    findings.append(Finding("store.online.gate", Status.BLOCKED,
                                        "Configure both saved app identities and bind both Store keys in this inventory context.", category="store-access"))
                                else:
                                    extra, observation = paired_versions.read_saved_versions(self, config, material)
                                    findings.extend(extra)
                                self._source_post(); self._received_post()
                                self.report = paired_versions.project_result(findings, observation)
                            elif play_versions.selected_query(self.request.context):
                                observation = play_versions.unavailable("not-checked")
                                if not play_versions.query_prerequisites(config) or any(row.status in FAILING_STATUSES for row in findings):
                                    findings.append(Finding("store.online.gate", Status.BLOCKED,
                                        "Configure the saved Android app identity and selected service-account key.", category="store-access"))
                                else:
                                    extra, observation = play_versions.read_saved_versions(self, config, material)
                                    findings.extend(extra)
                                self._source_post(); self._received_post()
                                self.report = play_versions.project_result(findings, observation)
                            elif bundle_read.selected_read(self.request.context):
                                profiles = profile_read.selected_query(self.request.context)
                                versions = store_versions.selected_query(self.request.context)
                                observation = (store_versions.unavailable("not-checked") if versions else
                                               profile_read.unavailable("not-checked") if profiles else "not-checked")
                                prerequisites = store_versions.query_prerequisites(config) if versions else bundle_read.query_prerequisites(config)
                                if not prerequisites or any(row.status in FAILING_STATUSES for row in findings):
                                    findings.append(Finding("store.online.gate", Status.BLOCKED,
                                        "Configure the saved iOS app identity and selected API key.", category="store-access"))
                                else:
                                    if versions:
                                        extra, observation = store_versions.read_saved_versions(self, config, material)
                                    elif profiles:
                                        extra, observation = profile_read.read_saved_profiles(self, config, material)
                                    else:
                                        extra, observation = bundle_read.read_saved_bundle_id(self, config, material)
                                    findings.extend(extra)
                                self._source_post(); self._received_post()
                                self.report = (store_versions.project_result(findings, observation) if versions else
                                               profile_read.project_result(findings, observation) if profiles else
                                               bundle_read.project_result(findings, observation))
                            else:
                                blockers = _online_query_blockers(config, (platform,), findings)
                                if blockers:
                                    findings.append(Finding("store.online.gate", Status.BLOCKED,
                                                            "Configure the required saved Store inputs.", category="store-access"))
                                elif not any(row.status in FAILING_STATUSES for row in findings):
                                    findings.extend(online_preflight_findings(config=config, release=version,
                                        platforms=(platform,), material=material, invocation=invocation, runtime_context=self.runtime))
                                self._source_post(); self._received_post()
                                self.report = project_result(findings, platform=platform)
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
            self._apple_material = self._received_material = None
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
        if verdict.profile_calls or verdict.commands > self._lane_index + 1:
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
