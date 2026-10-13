"""One fixed saved-command observation of selected artifact bytes.

This composes the existing invocation, C/A/W, profile and finite-snapshot
owners.  It does not launch the public CLI, build a project, acquire signing
credentials, dispatch to a Store or turn its result into provenance.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from ._desktop_artifact_inspection_control import ArtifactInspectionInput
from ._desktop_artifact_inspection_protocol import (ArtifactInspectionRequest, CHECKS, LIMITATIONS,
    SCOPE, ProtocolError, require, validate_result)
from ._desktop_artifact_inspection_selection import (ArtifactInspectionArtifact, ArtifactInspectionFiles,
    ArtifactInspectionInputs, ArtifactInspectionRefused, _identity)
from .artifact_inspection import (GIB, KIB, MIB, MAX_CALL_UNITS, MAX_NAMESPACE_ENTRIES,
    MAX_NAMESPACE_NAMES, PROFILE_DESCRIPTORS, PROFILE_CAPTURE, ArtifactInspectionLimitError,
    TreeEntryData, capture_quote_data, captured_bytes_data, control_quote_data, decode_budget_data,
    descriptor_quote_data, namespace_data, profile_quote_data, slice_budget_data, tree_identity_data)
from .build_inputs import (BuildInputError, InvocationCustody, _FD, _cleanup_failure, _fd_cleanup,
                          _Directory, _default_scratch_parent, invocation_custody)
from .cancellation import DefaultCancellation
from .config import ReleaseConfig
from .owned_process import ProcessCleanupError, ProcessError, fatal_lifetime_error, run_owned


class _ArtifactInspectionDeadline:
    def __init__(self, operation: ArtifactInspectionOperation) -> None:
        require(type(operation) is ArtifactInspectionOperation)
        self.operation = operation
        self.expires_at = operation.source.work_end

    def check(self) -> None:
        operation = operation_for(self)
        require(operation is not None)
        if operation.close_claimed or operation.guard.depth:
            operation.cleanup_checkpoint()
        else:
            operation.checkpoint()

    @contextmanager
    def descriptor(self, path: Path):
        operation = operation_for(self)
        require(operation is not None)
        self.check()
        with operation.descriptor(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK) as number:
            yield number
        self.check()


def operation_for(deadline) -> ArtifactInspectionOperation | None:
    """Exact closed origin; a similar class/name/expiry is not an admission."""
    if type(deadline) is not _ArtifactInspectionDeadline:
        return None
    operation = deadline.operation
    require(type(operation) is ArtifactInspectionOperation and operation.inspection_deadline is deadline
            and deadline.expires_at == operation.source.work_end)
    operation.owner()
    require(operation.guard._artifact_inspection_source is operation.source
            and operation.source.operation is operation and operation.source.guard is operation.guard
            and operation.source.active and operation.source.request_returned and not operation.source.close_claimed)
    return operation


class ArtifactInspectionSnapshotBinding:
    """The existing finite snapshot's third, exclusively read-only origin."""
    def __init__(self, operation: ArtifactInspectionOperation) -> None:
        self.operation = operation
        self.owner = None
        self.entered = self.active = self.returned = self.finish_claimed = self.finished = False

    def bind_owner(self, owner) -> None:
        from .ios_artifacts import _IOSSnapshotOwner
        require(type(owner) is _IOSSnapshotOwner and self.owner is None
                and owner.cancellation is self.operation.guard and owner._desktop_binding is self)
        self.operation.owner()
        self.owner = owner

    def origin(self, owner, cancellation) -> None:
        from .ios_artifacts import _IOSSnapshotOwner
        operation = self.operation
        require(type(operation) is ArtifactInspectionOperation and type(owner) is _IOSSnapshotOwner
                and owner is self.owner and owner._desktop_binding is self and owner._lane_binding is None
                and cancellation is operation.guard and operation.snapshot_binding is self)
        operation.owner()

    def producer(self, owner, cancellation) -> None:
        self.origin(owner, cancellation)
        require(not self.finish_claimed and self.entered and self.active and not self.returned
                and self.operation.inputs is not None and self.operation.original_bindings is not None)
        self.operation.checkpoint()

    @contextmanager
    def consumer(self):
        require(self.owner is not None and not self.entered and not self.finish_claimed)
        self.origin(self.owner, self.operation.guard)
        self.entered = self.active = True
        try:
            yield
        finally:
            self.active, self.returned = False, True

    def finish_consumers(self, *, cancellation, primary=None) -> None:
        self.origin(self.owner, cancellation)
        require(not self.finish_claimed)
        self.finish_claimed = True
        require(not self.active and (not self.entered or self.returned)
                and self.operation.dependents_settled() and not self.operation.files.iterators)
        owner = self.owner
        require(not owner._accounting_pending and not owner._accounting_failed
                and owner._reserved == owner._retired)
        self.finished = True

    def dependents_settled_for(self, *, owner, cancellation) -> bool:
        self.origin(owner, cancellation)
        return (self.finish_claimed and self.finished and not self.active
                and (not self.entered or self.returned) and self.operation.dependents_settled())


class ArtifactInspectionIOSTools:
    """Fixed read-only system tools, retained by the original observation.

    This is not an SDK or signing admission. The caller must already hold the
    native selection and check these originals around every actual invocation.
    """
    _NAMES = ("codesign", "security", "openssl")

    def __init__(self, operation: ArtifactInspectionOperation) -> None:
        require(type(operation) is ArtifactInspectionOperation)
        operation.owner()
        require(operation.ios_tools is None and operation.files is not None
                and operation.files.operation is operation
                and operation.guard._artifact_inspection_source is operation.source
                and not operation.close_claimed)
        self.operation = operation
        self.parent = None
        self.slots: dict[str, _FD] = {}
        self.identities: dict[str, dict] = {}
        self.attempted = self.acquired = self.close_claimed = self.close_complete = False
        # The operation retains this object before any descriptor constructor or
        # system call. Every _FD registers with that same combined budget.
        operation.ios_tools = self

    def _origin(self) -> None:
        operation = self.operation
        require(type(self) is ArtifactInspectionIOSTools
                and type(operation) is ArtifactInspectionOperation
                and operation.ios_tools is self and operation.files is not None
                and operation.files.operation is operation
                and operation.guard._artifact_inspection_source is operation.source)
        operation.owner()

    @staticmethod
    def _protected(value: os.stat_result, *, directory: bool) -> None:
        require((stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
                and value.st_uid == 0 and not value.st_mode & 0o7022
                and (directory or value.st_size > 0 and bool(value.st_mode & stat.S_IXUSR)))

    def _parent_check(self) -> None:
        require(type(self.parent) is _Directory and self.parent.path == Path("/usr/bin")
                and self.parent.guard is self.operation.guard and len(self.parent.slots) == 3)
        self.parent.check()
        for slot in self.parent.slots:
            self.operation.files.point()
            require(slot.number is not None)
            self._protected(os.fstat(slot.number), directory=True)
        self.operation.files.point()

    def acquire(self) -> None:
        self._origin()
        require(not self.attempted and not self.close_claimed)
        self.attempted = True
        try:
            self.operation.files.point()
            self.parent = _Directory(Path("/usr/bin"), self.operation.guard, edit_checkpoints=True)
            self.parent.acquire()
            self._parent_check()
            for name in self._NAMES:
                self.operation.files.point()
                slot = _FD(self.operation.guard)
                self.slots[name] = slot  # Retain before open, even on a partial return.
                named = os.stat(name, dir_fd=self.parent.fd, follow_symlinks=False)
                self._protected(named, directory=False)
                before = _identity(named)
                number = slot.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                   dir_fd=self.parent.fd)
                require(_identity(os.fstat(number)) == before)
                self.identities[name] = before
                self.operation.files.point()
            self.acquired = True
            self.check()
        except BaseException as error:
            self.operation.remember(error)
            raise

    def _check_originals(self) -> None:
        self._origin()
        self.operation.files.point()
        require(self.acquired and set(self.slots) == set(self._NAMES)
                and set(self.identities) == set(self._NAMES))
        self._parent_check()
        for name in self._NAMES:
            self.operation.files.point()
            slot = self.slots[name]
            require(type(slot) is _FD and slot.guard is self.operation.guard
                    and slot.open_state == "OPEN" and slot.close_state == "NOT_ATTEMPTED"
                    and slot.number is not None)
            require(_identity(os.fstat(slot.number)) == self.identities[name]
                    and _identity(os.stat(name, dir_fd=self.parent.fd,
                                         follow_symlinks=False)) == self.identities[name])
        self.operation.files.point()

    def check(self) -> None:
        self._origin()
        try:
            require(not self.close_claimed)
            self._check_originals()
        except BaseException as error:
            self.operation.remember(error)
            raise

    def program(self, name: str) -> str:
        require(type(name) is str and name in self._NAMES)
        self.check()
        return "/usr/bin/" + name

    def close(self) -> None:
        self._origin()
        if self.close_claimed:
            require(self.close_complete)
            return
        if not self.operation.dependents_settled():
            error = ArtifactInspectionRefused("cleanup-unknown")
            self.operation.remember(error, fatal=True)
            raise _cleanup_failure(self.operation.guard, error)
        self.close_claimed = True
        first = None
        with self.operation.guard.deferred(check_on_exit=False):
            # POST uses the same cleanup endpoint; an expired or changed binding
            # still fails, but cannot prevent independent positive FD retirement.
            if self.acquired:
                try:
                    self._check_originals()
                except BaseException as error:
                    self.operation.remember(error)
                    first = error
            originals = (*reversed(tuple(self.slots.values())),
                         *reversed(self.parent.slots if self.parent is not None else ()))
            for slot in originals:
                try:
                    slot.close()
                except BaseException as error:
                    self.operation.remember(error, fatal=True)
                    if first is None:
                        first = error
            self.close_complete = all(slot.number is None and slot.close_state == "CLOSED"
                                      for slot in originals)
        if not self.close_complete:
            error = first or ArtifactInspectionRefused("cleanup-unknown")
            self.operation.remember(error, fatal=True)
            raise _cleanup_failure(self.operation.guard, error)
        if first is not None:
            raise first


def _project_artifact_result(operation, *, aab=None, ipa=None, structure_ok: bool,
                             pair_ok: bool | None = None, symbols_ok: bool | None = None) -> dict:
    """Provisional observation DATA only; the caller still owes all final joins."""
    from .android import ArtifactAabObservation
    from .android_manifest import AndroidManifest
    from .ios import ArtifactIPAObservation

    require(type(operation) is ArtifactInspectionOperation
            and type(operation.inputs) is ArtifactInspectionInputs
            and operation.primary is None and not operation.unknown
            and type(operation._artifact_rows) is list
            and type(structure_ok) is bool
            and (pair_ok is None or type(pair_ok) is bool)
            and (symbols_ok is None or type(symbols_ok) is bool))
    inputs, context = operation.inputs, operation.request.context
    format = context["format"]
    require(format in ("aab", "ipa") and (aab is None or type(aab) is ArtifactAabObservation)
            and (ipa is None or type(ipa) is ArtifactIPAObservation)
            and (ipa is None if format == "aab" else aab is None))
    observation = aab if format == "aab" else ipa
    require((observation is not None or not structure_ok)
            and (observation is None or type(observation.structure_ok) is bool
                 and observation.structure_ok is structure_ok)
            and (structure_ok or pair_ok is symbols_ok is None))
    section = inputs.config.section("android" if format == "aab" else "ios")
    release = inputs.release
    observed = {"applicationId": None, "bundleId": None, "versionName": None,
                "versionBuild": None, "signerSha256": None, "teamId": None}
    rows = {check: {"check": check, "status": "unavailable", "reason": "prerequisite-not-run"}
            for check in CHECKS}

    def row(check, status, reason="none"):
        rows[check] = {"check": check, "status": status, "reason": reason}

    def outcome(check, value, failure, absent="prerequisite-not-run"):
        require(value is None or type(value) is bool)
        row(check, "unavailable" if value is None else "pass" if value else "fail",
            absent if value is None else "none" if value else failure)

    row("byte-identity", "pass")
    outcome("structure", structure_ok, "malformed-structure")
    if format == "aab":
        for check in ("profile-entitlements", "archive-pair", "symbols"):
            row(check, "not_applicable")
        require(pair_ok is symbols_ok is None)
        if aab is not None:
            require(all(type(value) is bool for value in (aab.manifest_failed, aab.manifest_unavailable,
                                                          aab.signature_failed, aab.signer_failed))
                    and not (aab.manifest_failed and aab.manifest_unavailable)
                    and (aab.manifest is None or type(aab.manifest) is AndroidManifest
                         and not aab.manifest_failed and not aab.manifest_unavailable)
                    and (aab.signature_ok is None or type(aab.signature_ok) is bool)
                    and (not aab.signature_failed or aab.signature_ok is False)
                    and (aab.signer_sha256 is None or aab.signature_ok is True)
                    and (not aab.signer_failed or aab.signature_ok is True and aab.signer_sha256 is None))
            if not structure_ok:
                require(aab.manifest is None and aab.signature_ok is None and aab.signer_sha256 is None
                        and not any((aab.manifest_failed, aab.manifest_unavailable,
                                     aab.signature_failed, aab.signer_failed)))
            else:
                manifest = aab.manifest
                if manifest is not None:
                    require(type(manifest.debuggable) is bool and type(manifest.test_only) is bool)
                    observed.update(applicationId=manifest.package, versionName=manifest.version_name,
                                    versionBuild=manifest.version_code)
                    outcome("manifest", not (manifest.debuggable or manifest.test_only), "malformed-structure")
                    outcome("expected-identity", manifest.package == section["applicationId"], "identity-mismatch")
                    outcome("expected-version", manifest.version_name == release.name
                            and manifest.version_code == str(release.build), "version-mismatch")
                elif aab.manifest_failed:
                    row("manifest", "fail", "malformed-structure")
                else:
                    row("manifest", "unavailable", "tools-unavailable")
                observed["signerSha256"] = aab.signer_sha256
                outcome("signature", aab.signature_ok, "signature-invalid", "tools-unavailable")
    else:
        for check, role, value, missing, mismatch in (
            ("archive-pair", "archive", pair_ok, "archive-not-selected", "pair-mismatch"),
            ("symbols", "dsyms", symbols_ok, "symbols-not-selected", "symbols-mismatch"),
        ):
            if context["selections"][role] is None:
                require(value is None)
                row(check, "unavailable", missing)
            else:
                outcome(check, value, mismatch)
        if ipa is not None and structure_ok:
            observed.update(bundleId=ipa.bundle_id, versionName=ipa.version_name, versionBuild=ipa.version_build,
                            signerSha256=ipa.signer_sha256, teamId=ipa.team_id)
            row("manifest", "pass")
            outcome("expected-identity", ipa.bundle_id == section["bundleId"], "identity-mismatch")
            outcome("expected-version", ipa.version_name == release.name and ipa.version_build == str(release.build),
                    "version-mismatch")
            require((ipa.signature_ok is not True or ipa.signer_sha256 is not None and ipa.team_id is not None)
                    and (ipa.profile_ok is not True or ipa.signature_ok is True)
                    and (ipa.current_validity_ok is None or ipa.signature_ok is ipa.profile_ok is True))
            for check, value, reason, failure in (
                ("signature", ipa.signature_ok, ipa.signature_reason, "signature-invalid"),
                ("profile-entitlements", ipa.profile_ok, ipa.profile_reason, "profile-invalid"),
                ("current-validity", ipa.current_validity_ok, ipa.current_validity_reason, "signing-time-invalid"),
            ):
                require(value is None or type(value) is bool)
                require(value is None or reason == ("none" if value else failure))
                outcome(check, value, failure, reason)

    if structure_ok:
        configured = section.get("uploadCertificateSha256" if format == "aab" else "distributionCertificateSha256")
        team = section.get("teamId") if format == "ipa" else None
        if configured is None or format == "ipa" and team is None:
            row("signer-policy", "unavailable", "saved-policy-missing")
        elif observed["signerSha256"] is None or format == "ipa" and observed["teamId"] is None:
            row("signer-policy", "unavailable", "signer-unobserved")
        else:
            require(type(configured) is str)
            matches = configured.replace(":", "").lower() == observed["signerSha256"]
            if format == "ipa":
                matches = matches and team == observed["teamId"]
            outcome("signer-policy", matches, "signer-mismatch")
    # Full closed validation also copies retained rows/identities; no original
    # result/config collection is changed or exposed as mutable output authority.
    return validate_result({"schemaVersion": 1, "scope": SCOPE, "format": format,
        "usedConfig": inputs.used_config(), "usedVersion": inputs.used_version(),
        "artifacts": operation._artifact_rows, "observed": observed,
        "checks": [rows[check] for check in CHECKS], "limitations": list(LIMITATIONS)}, context)


class ArtifactInspectionOperation:
    def __init__(self, request: ArtifactInspectionRequest, guard: DefaultCancellation,
                 source: ArtifactInspectionInput) -> None:
        require(type(request) is ArtifactInspectionRequest and type(guard) is DefaultCancellation
                and type(source) is ArtifactInspectionInput and source.guard is guard
                and guard._artifact_inspection_source is source and source.active
                and source.request_returned and threading.current_thread() is threading.main_thread())
        self.request, self.guard, self.source = request, guard, source
        self.root = Path(request.native["projectRoot"])
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.inputs: ArtifactInspectionInputs | None = None
        self.files: ArtifactInspectionFiles | None = None
        self.invocation: InvocationCustody | None = None
        self.invocation_attempted = False
        self.tools = None
        self.ios_tools = None
        self.snapshot = self.original_bindings = None
        self._artifact = None
        self.zip_metadata = None
        self.primary: BaseException | None = None
        self.close_claimed = self.close_complete = self.unknown = False
        self.counters: dict[str, int] = {}
        self.live_slots: list[_FD] = []
        self._issued_slots = 0
        self._profile_evidence = []
        self._pending_profile = None
        self._profile_capture = None
        self._scratch = []
        self._scratch_directories = {}
        self._scratch_reader_parents = []
        self._native_reservation = 0
        self._pending = None
        self._roles: dict[str, str] = {}
        self._returned: dict[str, int] = {}
        self._command_before = {}
        self._capture_limit = self._capture_before = 0
        self._captured_pending = False
        self._signature_passed = False
        self.decode_calls = self.decode_raw = self.capture_raw = self.max_capture_cap = 0
        self.profile_loads = self.call_units = self.slices = 0
        self._namespace_count = 1
        self._namespace_bytes = self._namespace_normalized = 0
        self._zip_controls: dict[str, tuple[int, int, int]] = {}
        self._disk_reserved = self._profile_disk_reserved = 0
        self._scratch_parent = None
        self._preflight_retained = 0
        self._preflight_complete = False
        self._shape_refusals: set[str] = set()
        self._artifact_rows = None
        self._ipa_layout = self._ipa_pair = None
        self._extract_prefixes: set[Path] = set()
        self.inspection_deadline = _ArtifactInspectionDeadline(self)
        self.snapshot_binding = ArtifactInspectionSnapshotBinding(self)
        source.bind_operation(self)  # Original reference before any IO or constructor handoff.
        self.files = ArtifactInspectionFiles(self)

    def owner(self) -> None:
        require(type(self) is ArtifactInspectionOperation and self.pid == os.getpid()
                and self.thread is threading.current_thread() and self.thread is threading.main_thread()
                and self.source.operation is self and self.source.guard is self.guard)

    def _tick(self) -> None:
        self.owner()
        require(not self.close_claimed and not self.unknown)
        self.guard.check()
        if time.monotonic() >= self.source.work_end:
            self.source.stop("timed-out")
            self.guard.check()

    def checkpoint(self) -> None:
        self._tick()

    def cleanup_checkpoint(self) -> None:
        self.owner()
        require(self.guard.depth > 0 or self.close_claimed)
        endpoint = self.source.work_end + 10
        if self.source.first_failure is not None:
            endpoint = min(endpoint, self.source.first_failure + 10)
        if time.monotonic() >= endpoint:
            self.remember(ArtifactInspectionRefused("cleanup-unknown"), fatal=True)
            raise ArtifactInspectionRefused("cleanup-unknown")

    def require(self, config: ReleaseConfig, guard: DefaultCancellation) -> None:
        self.checkpoint()
        require(self.inputs is not None and config is self.inputs.config and guard is self.guard
                and self.invocation is not None)
        self.invocation.require(root=self.root, cancellation=guard, signing_lease=None)

    def fail(self, reason: str) -> None:
        error = ArtifactInspectionRefused(reason)
        self.remember(error)
        raise error

    def remember(self, error: BaseException, *, fatal: bool = False) -> None:
        self.owner()
        if self.primary is None:
            self.primary = error
        self.source.failure_observed()
        self.guard.lifetime_ledger._remember(error)
        if fatal or fatal_lifetime_error(error, "Artifact inspection original did not settle") is not None:
            self.unknown = True
            self.guard._abort(error)

    def charge(self, name: str, amount: int, limit: int) -> None:
        self.owner()
        # Match the reused provider's protected-original settlement rule.
        # Work polls STOP/T900 before debit; no recursive invocation POST.
        if self.close_claimed or self.guard.depth:
            self.cleanup_checkpoint()
        else:
            self.checkpoint()
        require(type(name) is str and 0 < len(name) <= 64 and type(amount) is int and amount >= 0
                and type(limit) is int and limit > 0 and (len(self.counters) < 64 or name in self.counters))
        after = self.counters.get(name, 0) + amount
        if after > limit:
            self.fail("input-limit")
        self.counters[name] = after

    def _quote(self, **changes) -> None:
        data = {"decode_calls": self.decode_calls, "decode_raw": self.decode_raw,
                "capture_raw": self.capture_raw, "max_capture_cap": self.max_capture_cap,
                "profile_loads": self.profile_loads}
        data.update(changes)
        control_quote_data(**data)

    def before_decode(self, raw_bytes: int) -> None:
        self.inspection_deadline.check()
        calls, raw = decode_budget_data(self.decode_calls, self.decode_raw, raw_bytes)
        self._quote(decode_calls=calls, decode_raw=raw)
        self.decode_calls, self.decode_raw = calls, raw  # Before the actual parser, never refunded.

    def retain_slices(self, count: int) -> None:
        self.inspection_deadline.check()
        self.slices = slice_budget_data(self.slices, count)  # Failed parsers still occupy their reservation.

    def namespace_entry(self, parts: tuple[str, ...]) -> None:
        self.inspection_deadline.check()
        raw = "/".join(parts)
        import unicodedata
        encoded, normalized = len(raw.encode("utf-8")), len(unicodedata.normalize("NFC", raw).casefold().encode("utf-8"))
        count, names, keys = self._namespace_count + 1, self._namespace_bytes + encoded, self._namespace_normalized + normalized
        namespace_data(count, names, keys)
        self._namespace_count, self._namespace_bytes, self._namespace_normalized = count, names, keys

    def reserve_descriptors(self, additional: int) -> None:
        self.owner()
        iterators = len(self.files.iterators) if self.files is not None else 0
        # The unchanged Mac tool reader admits one scandir duplicate at a
        # time. Reserve that same future/live slot for its entire admitted
        # lifetime, before any tool descriptor acquisition can fill this pool.
        iterators += int(self.tools is not None and not self.tools._close_complete)
        profile = PROFILE_DESCRIPTORS if self._pending_profile is not None else 0
        descriptor_quote_data(self.request.native["parentDescriptorReservation"],
                              len(self.live_slots) + iterators + profile + self._native_reservation, additional)

    def register_descriptor(self, slot: _FD) -> None:
        self.owner()
        require(type(slot) is _FD and slot.guard is self.guard and slot.number is None
                and slot.open_state == "NEW" and all(item is not slot for item in self.live_slots))
        self.reserve_descriptors(1)
        self.charge("descriptor-originals", 1, 262144)
        self.live_slots.append(slot)
        self._issued_slots += 1

    def retired_descriptor(self, slot: _FD) -> None:
        self.owner()
        require(slot.close_state == "CLOSED" and slot.number is None)
        if any(item is slot for item in self.live_slots):
            self.live_slots.remove(slot)  # Retained lifetime count is never decremented.

    def bind_invocation(self, invocation: InvocationCustody) -> None:
        self.owner()
        require(type(invocation) is InvocationCustody and self.invocation is None
                and invocation.root == self.root and invocation.cancellation is self.guard)
        self.invocation = invocation

    def dependents_settled(self) -> bool:
        self.owner()
        facts = self.guard.lifetime_ledger.verdict()
        return (not self.unknown and self._pending is None and self._pending_profile is None
                and self._profile_capture is None and facts.complete and facts.contained
                and facts.cleanup_complete and not facts.fatal)

    def inspection_checkpoint(self) -> None:
        self.require(self.inputs.config, self.guard)
        require(self.snapshot is not None and self.snapshot_binding.active
                and self.snapshot._owner is self.snapshot_binding.owner)
        self.files.post()
        self.snapshot._owner.audit()

    def _content_failure(self, error: BaseException) -> None:
        """Reject wrapped original failures before any content-only projection."""
        self.checkpoint()
        require(self.primary is None and self.dependents_settled())
        current, seen = error, set()
        while current is not None:
            # Existing parsers sometimes wrap an original read error. A
            # ValidationError spelling does not make that IO failure content.
            if (id(current) in seen or len(seen) >= 16
                    or isinstance(current, (OSError, ProcessError, BuildInputError,
                                            ArtifactInspectionRefused, ProtocolError))):
                raise error
            seen.add(id(current))
            current = current.__cause__ if current.__cause__ is not None else current.__context__

    def data_refusal(self, error: BaseException) -> None:
        """Only a completed parser/policy observation may become a negative row."""
        from .errors import ValidationError
        require(isinstance(error, ValidationError) and not isinstance(error, ArtifactInspectionRefused))
        ArtifactInspectionOperation._content_failure(self, error)
        self.inspection_checkpoint()

    def profile_preflight(self) -> None:
        self.inspection_checkpoint()
        require(self._pending_profile is None and self._pending is None and self.ios_tools is not None
                and self._preflight_complete and self._disk_reserved >= 256 * MIB
                and self._profile_disk_reserved == 0)
        self.ios_tools.check()
        quote = profile_quote_data(profile_loads=self.profile_loads, call_units=self.call_units,
            decode_calls=self.decode_calls, decode_raw=self.decode_raw, capture_raw=self.capture_raw,
            max_capture_cap=self.max_capture_cap, parent_reserved=self.request.native["parentDescriptorReservation"],
            core_live=len(self.live_slots) + len(self.files.iterators))
        require(quote.private_disk_bytes <= 256 * MIB)

    def bind_profile(self, evidence) -> None:
        from ._lifetime_evidence import ProfileCallEvidence
        self.checkpoint()
        require(type(evidence) is ProfileCallEvidence and evidence.operation == "load"
                and evidence._guard is self.guard and not evidence._finished and not evidence._published
                and self._pending_profile is None and self._pending is None
                and self._preflight_complete and self._disk_reserved >= 256 * MIB
                and self._profile_disk_reserved == 0 and len(self._profile_evidence) < 128)
        quote = profile_quote_data(profile_loads=self.profile_loads, call_units=self.call_units,
            decode_calls=self.decode_calls, decode_raw=self.decode_raw, capture_raw=self.capture_raw,
            max_capture_cap=self.max_capture_cap, parent_reserved=self.request.native["parentDescriptorReservation"],
            core_live=len(self.live_slots) + len(self.files.iterators))
        require(quote.private_disk_bytes <= 256 * MIB)
        # This peak belongs to the same prequoted non-payload headroom. Only
        # the actual complete profile/scratch verdict below can release it.
        self._profile_disk_reserved = quote.private_disk_bytes
        self.profile_loads, self.call_units = quote.profile_loads, quote.call_units
        self.max_capture_cap = max(self.max_capture_cap, PROFILE_CAPTURE)
        self._profile_evidence.append(evidence)
        self._pending_profile = evidence

    def finish_profile(self, evidence) -> None:
        self.owner()
        require(evidence is self._pending_profile and evidence in self._profile_evidence
                and evidence._finished and evidence._published)
        verdict = evidence.verdict()
        if not verdict.complete or not verdict.cleanup_complete or not verdict.contained or verdict.fatal:
            self.remember(ArtifactInspectionRefused("cleanup-unknown"), fatal=True)
            return  # Same original remains retained; no next tool/cleanup admission.
        self._pending_profile = None
        self._profile_disk_reserved = 0

    def profile_capture_before(self) -> int:
        self.inspection_deadline.check()
        require(self._pending_profile is not None and self._profile_capture is None and self._pending is None)
        limit = capture_quote_data(self.capture_raw, "profile")
        self._quote(capture_raw=self.capture_raw + limit, max_capture_cap=max(self.max_capture_cap, limit))
        self._profile_capture = limit
        self.max_capture_cap = max(self.max_capture_cap, limit)
        return limit

    def profile_capture_after(self, actual: int | None) -> None:
        self.owner()
        require(self._profile_capture is not None)
        limit = self._profile_capture
        self.capture_raw = captured_bytes_data(self.capture_raw, limit if actual is None else actual, limit)
        self._profile_capture = None
        self._quote()

    def _arm(self, role: str, ceiling: int, *, output_role: str) -> None:
        self.checkpoint()
        require(self._pending is None and self._pending_profile is None and self.dependents_settled()
                and role not in self._roles and self.call_units < MAX_CALL_UNITS)
        limit = capture_quote_data(self.capture_raw, output_role)
        self._quote(capture_raw=self.capture_raw + limit, max_capture_cap=max(self.max_capture_cap, limit))
        self.reserve_descriptors(64)  # Existing C/A/W peak, not another independently full pool.
        self._native_reservation = 64
        self.call_units += 1
        self._pending, self._capture_limit = role, limit
        self._capture_before = self.capture_raw
        self._captured_pending = False
        self.max_capture_cap = max(self.max_capture_cap, limit)
        self._roles[role] = "armed"
        self._command_before[role] = (self.guard.lifetime_ledger.verdict().commands, ceiling)

    def command_limits(self, timeout: int, capture: bool, output_limit: int) -> tuple[int, int]:
        self.checkpoint()
        role = self._pending
        require(role in self._roles and self._roles[role] == "armed" and capture is True
                and type(timeout) is int and timeout > 0 and type(output_limit) is int and output_limit > 0)
        self._roles[role] = "attempted"
        return min(timeout, self._command_before[role][1]), min(output_limit, self._capture_limit)

    def captured(self, role: str, stdout: bytes, stderr: bytes) -> tuple[str, str]:
        self.owner()
        require(self._pending == role and self._roles[role] == "attempted" and not self._captured_pending
                and type(stdout) is bytes and type(stderr) is bytes)
        observed = len(stdout) + len(stderr)
        after = captured_bytes_data(self.capture_raw, observed, self._capture_limit)
        self._quote(capture_raw=after)
        self.capture_raw, self._captured_pending = after, True
        # Matches run_command's existing strict text conversion. No replacement
        # bytes, reconstruction of a byte count or exported native text.
        return stdout.decode("utf-8", "strict"), stderr.decode("utf-8", "strict")

    def captured_binary(self, role: str, stdout: bytes, stderr: bytes) -> None:
        self.owner()
        require(self._pending == role and self._roles[role] == "attempted" and not self._captured_pending
                and type(stdout) is bytes and type(stderr) is bytes)
        after = captured_bytes_data(self.capture_raw, len(stdout) + len(stderr), self._capture_limit)
        self._quote(capture_raw=after)
        self.capture_raw, self._captured_pending = after, True

    def returned(self, role: str, code: int) -> None:
        self.owner()
        require(role == self._pending and self._roles[role] == "attempted" and self._captured_pending
                and type(code) is int and -(2**31) <= code < 2**31)
        facts = self.guard.lifetime_ledger.verdict()
        require(facts.cleanup_complete and facts.complete and facts.contained and not facts.fatal
                and facts.command_dispatched is True and facts.commands == self._command_before[role][0] + 1)
        self._returned[role] = code
        self._roles[role], self._pending, self._native_reservation = "returned", None, 0

    def command_error(self, role: str, error: BaseException) -> None:
        self.owner()
        self.remember(error)
        if self._pending == role:
            if not self._captured_pending:
                self.capture_raw = captured_bytes_data(self.capture_raw, self._capture_limit, self._capture_limit)
                self._captured_pending = True
            facts = self.guard.lifetime_ledger.verdict()
            if facts.complete and facts.contained and facts.cleanup_complete and not facts.fatal:
                self._roles[role], self._pending, self._native_reservation = "failed", None, 0
            else:
                self.remember(error, fatal=True)

    def _android_command(self, role: str, path: Path, tools, ceiling: int) -> tuple[str, ...]:
        self.checkpoint()
        require(tools is self.tools and tools is not None and self._artifact is self.files.artifact
                and self._artifact is not None and self._artifact._native and path == self._artifact.path)
        if role == "keytool":
            require(self._signature_passed)
        tools.check()
        self._artifact.check()
        argv = getattr(tools, role + "_command")(path)
        self._arm(role, ceiling, output_role="aab")
        return argv

    def bundletool_command(self, path: Path, tools) -> tuple[str, ...]:
        return self._android_command("bundletool", path, tools, 60)

    def jarsigner_command(self, path: Path, tools) -> tuple[str, ...]:
        return self._android_command("jarsigner", path, tools, 120)

    def keytool_command(self, path: Path, tools) -> tuple[str, ...]:
        return self._android_command("keytool", path, tools, 30)

    def signature_accepted(self, path: Path, tools) -> None:
        self.checkpoint()
        require(tools is self.tools and self._artifact is not None and self._artifact._native
                and path == self._artifact.path and not self._signature_passed and self._pending is None
                and self._roles.get("jarsigner") == "returned" and self._returned["jarsigner"] in (0, 4))
        self._artifact.check()
        self._signature_passed = True

    def command_environment(self) -> dict[str, str]:
        self.checkpoint()
        require(self.tools is not None and self.inputs is not None)
        return self.tools.command_environment(self.files.work_path, self.inputs.release)

    def _ios_command(self, argv: list[str]) -> tuple[list[str], Path]:
        """SOURCE-fixed read-only syntax, never a renderer argv or tool path."""
        self.inspection_checkpoint()
        require(type(argv) is list and 2 <= len(argv) <= 12 and all(type(item) is str
                and 0 < len(item.encode("utf-8")) <= 4096 and "\x00" not in item for item in argv)
                and self.ios_tools is not None and self._ipa_layout is not None)
        name = argv[0].removeprefix("/usr/bin/")
        require(name in ("codesign", "openssl") and argv[0] in (name, "/usr/bin/" + name))
        self.ios_tools.check()
        if name == "openssl":
            require(len(argv) == 10 and argv[1:5] == ["x509", "-inform", "DER", "-in"]
                    and argv[6:] == ["-noout", "-fingerprint", "-sha256", "-dates"])
            path = Path(argv[5])
            require(any(path == prefix.parent / (prefix.name + "0") for prefix in self._extract_prefixes))
        else:
            path = Path(argv[-1])
            app, application = self._ipa_layout
            require(path == app or path.is_relative_to(app) and
                    path.relative_to(app).as_posix() in application.all_inventory)
            options = argv[1:-1]
            if options and options[0] == "--verify":
                require(options in (["--verify", "--all-architectures", "--deep", "--strict", "--verbose=2"],
                    ["--verify", "--all-architectures", "--strict", "--verbose=2", "--test-requirement", "=designated"]))
            else:
                require(options and options[0] == "-d")
                options = options[1:]
                if options and options[0] == "--architecture":
                    require(len(options) >= 3 and re.fullmatch(r"[0-9]{1,10},[0-9]{1,10}", options[1]) is not None)
                    options = options[2:]
                if options and options[0] == "--extract-certificates":
                    require(len(options) == 2)
                    prefix = Path(options[1])
                    record = next((record for record in self._scratch if record[2]["acquired"]
                                   and prefix.parent == Path(record[0].name)), None)
                    require(record is not None and id(record) in self._scratch_directories
                            and re.fullmatch(r"slice-(?:[0-9]|[12][0-9]|3[01])-", prefix.name) is not None
                            and prefix not in self._extract_prefixes and len(self._extract_prefixes) < 4096)
                    self._scratch_directories[id(record)].check()
                    self._extract_prefixes.add(prefix)  # Before the actual producer, never reusable.
                else:
                    require(options in (["--verbose=4"], ["--entitlements", "-", "--der"],
                                        ["--entitlements", "-", "--xml"]))
        return [self.ios_tools.program(name), *argv[1:]], path

    @contextmanager
    def _ios_native_input(self, path: Path):
        from .ios_artifacts import _input
        self.inspection_checkpoint()
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if path.is_dir():
            flags |= os.O_DIRECTORY
        with self.descriptor(path, flags):
            before = _input(path, deadline=self.inspection_deadline)
            first = None
            try:
                yield
            except BaseException as error:
                first = error
                raise
            finally:
                try:
                    require(self.dependents_settled())
                    with self.guard.deferred(check_on_exit=False):
                        require(_input(path, deadline=self.inspection_deadline) == before)
                        self.ios_tools.check()
                        self.snapshot._owner.audit()
                except BaseException as error:
                    self.remember(error, fatal=not self.dependents_settled())
                    if first is None:
                        raise

    def ios_native_call(self, argv: list[str], *, timeout: int, text: bool, cancellation):
        require(cancellation is self.guard and type(text) is bool and timeout in (30, 60))
        command, path = self._ios_command(argv)
        from .credentials import artifact_validation_environment
        environment = artifact_validation_environment(os.environ)
        work = str(self.files.work_path)
        environment.update({"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": work, "TMPDIR": work,
                            "LC_ALL": "C", "LANG": "C"})
        role = "ios-" + str(self.call_units) + "-" + Path(command[0]).name
        with self._ios_native_input(path):
            self._arm(role, timeout, output_role="ipa")
            try:
                result = run_owned(command, cwd=self.files.work_path, environ=environment,
                    capture=True, text=False, timeout=timeout, output_limit=8 * MIB, cancellation=self.guard)
                if text:
                    stdout, stderr = self.captured(role, result.stdout, result.stderr)
                else:
                    self.captured_binary(role, result.stdout, result.stderr)
                    stdout, stderr = result.stdout, result.stderr
                self.returned(role, result.returncode)
            except BaseException as error:
                self.command_error(role, error)
                raise
        self.checkpoint()
        return subprocess.CompletedProcess(result.args, result.returncode, stdout, stderr)

    def memory_preflight(self) -> None:
        from .darwin_memory import DarwinMemoryCleanupUnknown, DarwinMemoryUnavailable, sampled_free_bytes
        self.checkpoint()
        try:
            available = sampled_free_bytes(check=self._tick)
        except DarwinMemoryCleanupUnknown as error:
            self.remember(error, fatal=True)
            raise
        except DarwinMemoryUnavailable:
            self.fail("resources-unavailable")
        threshold = (4096 if self.request.context["format"] == "aab" else 1536) * MIB
        if available < threshold:
            self.fail("resources-unavailable")

    def artifact_names(self) -> tuple[str, ...]:
        self.owner()
        main = "android-aab" if self.request.context["format"] == "aab" else "ios-ipa"
        return (main, "ios-archive", "ios-dsyms")[:len(self.files.selected)]

    def artifact_paths(self) -> dict[str, Path]:
        self.checkpoint()
        require(self.files.selected and len(self.files.selected) <= 3)
        return dict(zip(self.artifact_names(), (item.path for item in self.files.selected), strict=True))

    def zip_directory(self, path: Path, raw: int, entries: int, central: int) -> None:
        """Same existing ZIP prelude, before ZipInfo's central allocation."""
        self.checkpoint()
        require(type(raw) is int and 0 <= raw <= 4 * GIB and type(entries) is int
                and type(central) is int and isinstance(path, Path))
        if entries > MAX_NAMESPACE_ENTRIES or central > 8 * MIB:
            self.fail("input-limit")
        names = self.artifact_names()
        paths = self.artifact_paths()
        name = next((name for name in names if paths[name] == path or self.snapshot is not None
                     and self.snapshot.paths[name] == path), None)
        require(name is not None)
        value = raw, entries, central
        if name in self._zip_controls:
            require(self._zip_controls[name] == value)
        else:
            require(len(self._zip_controls) < 3)
            if sum(row[2] for row in self._zip_controls.values()) + central > 8 * MIB:
                self.fail("input-limit")
            self._zip_controls[name] = value

    def preflight_originals(self) -> None:
        """Quote the real selected inputs before creating their private copy."""
        import zipfile
        from .errors import ValidationError
        from .ios_artifacts import _File, _input, _source_file, _zip_directory_bound
        self.checkpoint()
        require(not self._preflight_complete and self.original_bindings is None and self.inputs is not None)
        self.memory_preflight()
        bindings, rows, raw, expanded = {}, [], 0, 0
        for index, (name, path) in enumerate(self.artifact_paths().items()):
            original = self.files.selected[index]
            binding = _input(path, deadline=self.inspection_deadline)
            if isinstance(binding, _File):
                size, entries, digest, method = binding.size, 1, binding.sha256, "sha256-file"
                # Full source bytes are retained in bindings and rechecked
                # by the same snapshot. Intermediate saved-input POST hashes
                # only config/version, not an unbounded number of GB rereads.
            else:
                require(type(binding) is dict and len(binding) < MAX_NAMESPACE_ENTRIES)
                records = (TreeEntryData("directory", "", 0, None), *(TreeEntryData(
                    "directory" if value is None else "file", relative,
                    0 if value is None else value.size, None if value is None else value.sha256)
                    for relative, value in sorted(binding.items(), key=lambda item: item[0].encode("utf-8"))))
                digest, entries, size = tree_identity_data(records)
                method = "sha256-tree-v1"
            raw += size
            self._preflight_retained += entries
            if raw > 16 * GIB or self._preflight_retained > MAX_NAMESPACE_ENTRIES:
                self.fail("input-limit")
            bindings[name] = binding
            native = self.request.native["originals"][index]
            rows.append({"role": native["role"], "selectionId": native["selectionId"],
                "label": path.name, "kind": native["kind"], "bytes": size, "entries": entries,
                "identity": {"method": method, "sha256": digest}})
            if self.request.context["format"] == "ipa" and isinstance(binding, _File):
                try:
                    _zip_directory_bound(path, deadline=self.inspection_deadline)
                    # Prelude bounds precede this existing stdlib directory.
                    with _source_file(path, deadline=self.inspection_deadline) as stream:
                        with zipfile.ZipFile(stream) as archive:
                            total = 0
                            for item in archive.infolist():
                                self.checkpoint()
                                maximum = GIB if name == "ios-ipa" else 4 * GIB
                                if item.file_size > maximum or item.file_size < 0:
                                    self.fail("input-limit")
                                total += item.file_size
                                if total > (4 * GIB if name == "ios-ipa" else 16 * GIB):
                                    self.fail("input-limit")
                            expanded += total
                            if expanded > 16 * GIB:
                                self.fail("input-limit")
                except (ValidationError, zipfile.BadZipFile, NotImplementedError) as error:
                    self._content_failure(error)
                    # Known format refusal only: raw byte identity still has a
                    # useful result. No extraction/native role will be entered.
                    self._shape_refusals.add(name)
        # Same protected filesystem original that the existing finite snapshot
        # will use; no total-memory or another mount's free-space substitution.
        parent = _Directory(_default_scratch_parent(), self.guard, system_root_aliases=True,
                            edit_checkpoints=True)
        self._scratch_parent = parent
        parent.acquire()
        parent.check()
        available = os.fstatvfs(parent.fd)
        require(type(available.f_bavail) is int and available.f_bavail >= 0
                and type(available.f_frsize) is int and available.f_frsize > 0)
        generated = 8 * GIB if self.request.context["format"] == "ipa" else 0
        need = raw + expanded + generated + 256 * MIB
        if available.f_bavail * available.f_frsize < need:
            self.fail("resources-unavailable")
        parent.check()
        self._disk_reserved = need
        self.original_bindings, self._artifact_rows = bindings, rows
        self._preflight_complete = True

    def begin_inspection(self, artifacts, cancellation):
        self.checkpoint()
        require(cancellation is self.guard and type(artifacts) is dict and artifacts == self.artifact_paths()
                and self._preflight_complete and self.original_bindings is not None
                and self.snapshot is None and self.snapshot_binding.owner is None
                and self._scratch_parent is not None)
        self._scratch_parent.check()
        return self.inspection_deadline

    def bind_snapshot(self, snapshot) -> None:
        from .ios_artifacts import IOSArtifactSnapshot, _File
        self.checkpoint()
        require(type(snapshot) is IOSArtifactSnapshot and self.snapshot is None
                and snapshot.deadline is self.inspection_deadline and snapshot.cancellation is self.guard
                and snapshot._owner is self.snapshot_binding.owner and snapshot.bindings == self.original_bindings
                and snapshot.originals == self.artifact_paths() and self._scratch_parent is not None)
        self._scratch_parent.check()
        owner = snapshot._owner
        require(owner.parent.path == self._scratch_parent.path
                and (os.fstat(owner.parent.fd).st_dev, os.fstat(owner.parent.fd).st_ino)
                == (os.fstat(self._scratch_parent.fd).st_dev, os.fstat(self._scratch_parent.fd).st_ino))
        self.snapshot = snapshot
        name = self.artifact_names()[0]
        binding = snapshot.bindings[name]
        require(type(binding) is _File)
        artifact = ArtifactInspectionArtifact(self.files, snapshot.paths[name], binding.size, binding.sha256)
        self.files.artifact = self._artifact = artifact
        artifact.check()

    @contextmanager
    def _named_loan(self, number: int, parent: int, name: str, before):
        # The surrounding fixed owner owns the descriptor's consuming close.
        # This loan owes POST even when its parser returns a negative result.
        try:
            require(_identity(os.fstat(number)) == _identity(before)
                    and _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _identity(before))
        except BaseException as error:
            self.remember(error)
            raise
        first = None
        try:
            yield number
        except BaseException as error:
            first = error
            if isinstance(error, OSError):
                self.remember(error)
            raise
        finally:
            try:
                with self.guard.deferred(check_on_exit=False):
                    require(_identity(os.fstat(number)) == _identity(before)
                            and _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _identity(before))
            except BaseException as error:
                self.remember(error)
                if first is None:
                    raise

    @contextmanager
    def descriptor(self, path: Path | str, flags: int, *, parent: int | None = None):
        self.inspection_deadline.check()
        original = self.files.source_at(path) if isinstance(path, Path) and parent is None else None
        if original is not None:
            with original.root() as number:
                yield number
            return
        if parent is not None:
            self.files.known_number(parent)
            require(type(path) is str and path not in ("", ".", "..") and "/" not in path)
            slot = _FD(self.guard)
            with _fd_cleanup(slot):
                try:
                    before = os.stat(path, dir_fd=parent, follow_symlinks=False)
                    number = slot.open(path, flags, dir_fd=parent)
                except BaseException as error:
                    self.remember(error)
                    raise
                with self._named_loan(number, parent, path, before):
                    yield number
            return
        require(isinstance(path, Path))
        owner = self.snapshot_binding.owner
        if owner is not None and path.is_relative_to(owner._path):
            self.snapshot_binding.origin(owner, self.guard)
            if flags & os.O_DIRECTORY:
                with owner.directory(path) as number:
                    yield number
            else:
                with owner.directory(path.parent) as directory:
                    try:
                        before = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
                    except BaseException as error:
                        self.remember(error)
                        raise
                    with owner.descriptor(path.name, flags, parent=directory) as number:
                        with self._named_loan(number, directory, path.name, before):
                            yield number
            return
        scratch = next((record for record in reversed(self._scratch)
                        if record[2]["acquired"] and record[0].name is not None
                        and path.is_relative_to(Path(record[0].name))), None)
        if scratch is not None:
            with self.scratch_descriptor(path, flags, scratch) as number:
                yield number
            return
        self.fail("selection-unsafe")

    def check_private_file(self, path: Path, size: int, sha256: str, *, content: bool) -> None:
        with self.inspection_deadline.descriptor(path) as number:
            value = os.fstat(number)
            require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_size == size)
            if content:
                os.lseek(number, 0, os.SEEK_SET)
                digest, count = hashlib.sha256(), 0
                while count < size:
                    self.inspection_deadline.check()
                    block = os.read(number, min(MIB, size - count))
                    require(bool(block))
                    digest.update(block)
                    count += len(block)
                require(not os.read(number, 1) and digest.hexdigest() == sha256)

    @contextmanager
    def profile_original(self, path: Path):
        """Lend the SAME owned parent/name to the existing profile reader.

        Its _ProfileDescriptor has its own consuming close inside this loan;
        the retained source FD is POSTed only after that close has returned.
        """
        from .build_inputs import _file
        self.checkpoint()
        require(self.snapshot is not None and self._pending_profile is not None
                and isinstance(path, Path) and self._ipa_layout is not None)
        owner = self.snapshot._owner
        parts = owner._parts(path)
        require(parts in owner.entries and owner.entries[parts]["kind"] == "file")
        with owner.directory(path.parent) as parent:
            with owner.descriptor(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, parent=parent) as number:
                before = os.fstat(number)
                require(_file(before) == owner.entries[parts]["binding"] and stat.S_ISREG(before.st_mode)
                        and before.st_nlink == 1 and 0 < before.st_size <= 256 * KIB
                        and _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == _identity(before))

                def read_hash() -> str:
                    os.lseek(number, 0, os.SEEK_SET)
                    digest, size = hashlib.sha256(), 0
                    while size < before.st_size:
                        self.inspection_deadline.check()
                        block = os.read(number, min(64 * KIB, before.st_size - size))
                        require(bool(block))
                        size += len(block)
                        digest.update(block)
                    require(not os.read(number, 1))
                    return digest.hexdigest()

                digest = None
                try:
                    digest = read_hash()
                    yield parent, path.name, before, digest
                except BaseException as error:
                    # This loan contains only the actual raw reader and its
                    # consuming close, never CMS/policy interpretation.
                    self.remember(error)
                    raise
                finally:
                    try:
                        with self.guard.deferred(check_on_exit=False):
                            require(_identity(os.fstat(number)) == _identity(before)
                                    and _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == _identity(before))
                            if digest is not None:
                                require(read_hash() == digest)
                    except BaseException as error:
                        self.remember(error)
                        raise

    def has_scratch(self, record) -> bool:
        self.owner()
        return any(item is record for item in self._scratch)

    def register_scratch(self, record) -> None:
        from .cancellation import OwnedTemporaryDirectory
        self.checkpoint()
        require(type(record) is tuple and len(record) == 3 and type(record[0]) is OwnedTemporaryDirectory
                and record[1] is self.guard and type(record[2]) is dict and not record[2]["attempted"]
                and not self.has_scratch(record) and len(self._scratch) < 128)
        self._scratch.append(record)

    def scratch_parent(self, prefix: str, directory: Path | None) -> Path:
        self.checkpoint()
        require(self._preflight_complete and self._scratch_parent is not None
                and prefix in ("mobile-release-artifact-tools-", "mobile-release-ipa-observation-",
                               "mobile-release-leaf-"))
        if prefix in ("mobile-release-artifact-tools-", "mobile-release-ipa-observation-"):
            require(directory is None and not self._scratch)
            require(prefix == ("mobile-release-artifact-tools-" if self.request.context["format"] == "aab"
                               else "mobile-release-ipa-observation-"))
            self._scratch_parent.check()
            return self._scratch_parent.path
        require(directory is not None and directory == self.files.work_path)
        return directory

    def scratch_acquired(self, record) -> None:
        self.owner()
        require(self.has_scratch(record) and record[2]["acquired"]
                and id(record) not in self._scratch_directories)
        path = Path(record[0].name)
        directory = _Directory(path, self.guard, system_root_aliases=True, edit_checkpoints=True)
        self._scratch_directories[id(record)] = directory  # Before original acquisition.
        directory.acquire()
        value = os.fstat(directory.fd)
        require((value.st_dev, value.st_ino) == tuple(record[0].state["identity"])
                and stat.S_ISDIR(value.st_mode) and stat.S_IMODE(value.st_mode) == 0o700
                and value.st_uid == os.geteuid())
        directory.check()
        if record[0].prefix in ("mobile-release-artifact-tools-", "mobile-release-ipa-observation-"):
            self.files.bind_work(record)

    @contextmanager
    def scratch_descriptor(self, path: Path, flags: int, record):
        self.inspection_deadline.check()
        require(self.has_scratch(record) and record[2]["acquired"]
                and id(record) in self._scratch_directories and len(self._scratch_reader_parents) < 2)
        root = self._scratch_directories[id(record)]
        root.check()
        relative = path.relative_to(root.path)
        require(len(relative.parts) <= 64 and len(str(relative).encode("utf-8")) <= 2048)
        if path == root.path:
            require(bool(flags & os.O_DIRECTORY))
            first = None
            try:
                yield root.fd
            except BaseException as error:
                first = error
                raise
            finally:
                try:
                    with self.guard.deferred(check_on_exit=False):
                        root.check()
                except BaseException as error:
                    self.remember(error)
                    if first is None:
                        raise
            return
        parent = _Directory(path.parent, self.guard, system_root_aliases=True, edit_checkpoints=True)
        self._scratch_reader_parents.append(parent)
        first = None
        try:
            parent.acquire()
            root.check()
            slot = _FD(self.guard)
            with _fd_cleanup(slot):
                before = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
                number = slot.open(path.name, flags, dir_fd=parent.fd)
                require(_identity(os.fstat(number)) == _identity(before))
                try:
                    yield number
                finally:
                    with self.guard.deferred(check_on_exit=False):
                        require(_identity(os.fstat(number)) == _identity(before)
                                and _identity(os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)) == _identity(before))
                        parent.check()
                        root.check()
        except BaseException as error:
            first = error
            self.remember(error)
            raise
        finally:
            try:
                parent.close()
            except BaseException as error:
                self.remember(error, fatal=True)
                if first is None:
                    raise
            finally:
                if all(slot.close_state == "CLOSED" for slot in parent.slots):
                    self._scratch_reader_parents.remove(parent)

    def scratch_before_cleanup(self, record) -> None:
        from .ios_artifacts import _tree
        self.owner()
        require(self.has_scratch(record) and self.dependents_settled() and not self._scratch_reader_parents)
        directory = self._scratch_directories.get(id(record))
        if not record[2]["attempted"]:
            require(directory is None)
            return
        require(record[2]["acquired"] and directory is not None)
        directory.check()
        # The same returned native may create private work files. Bound and
        # classify the actual tree through its retained originals BEFORE the
        # existing owner removes it; never recurse through uninspected links.
        inventory = _tree(directory.path, deadline=self.inspection_deadline)
        if sum(value.size for value in inventory.values() if value is not None) > 8 * GIB:
            self.fail("input-limit")
        if self.files._work_record is record:
            self.files.close_work_handles()
        directory.close()
        require(all(slot.close_state == "CLOSED" for slot in directory.slots))

    def scratch_removed(self, record) -> None:
        self.owner()
        require(self.has_scratch(record) and record[2]["removed"] and self.dependents_settled())
        directory = self._scratch_directories.get(id(record))
        require(directory is None or all(slot.close_state == "CLOSED" for slot in directory.slots))
        self._scratch_directories.pop(id(record), None)
        self._scratch.remove(record)

    def close(self) -> None:
        self.owner()
        if self.close_claimed:
            require(self.close_complete)
            return
        if not self.dependents_settled():
            self.remember(ArtifactInspectionRefused("cleanup-unknown"), fatal=True)
            raise _cleanup_failure(self.guard, self.primary)
        self.close_claimed = True
        first = None
        with self.guard.deferred(check_on_exit=False):
            for child in (self.tools, self.ios_tools, self.files, self._scratch_parent):
                if child is not None:
                    try:
                        child.close()
                    except BaseException as error:
                        self.remember(error)
                        if first is None:
                            first = error
            # Constructor-only/no-effect slots are still original obligations.
            # Live positive slots remain with their exact owning child above.
            for slot in tuple(self.live_slots):
                if slot.open_state in ("NEW", "NO_EFFECT") and slot.number is None:
                    try:
                        slot.close()
                    except BaseException as error:
                        self.remember(error, fatal=True)
                        if first is None:
                            first = error
        project = self.invocation._original_project if self.invocation is not None else None
        project_slots = (*project.directory.slots, project.meta) if project is not None else ()
        files_closed = self.files is None or (not self.files.iterators and self.files.close_complete)
        self.close_complete = (not self.unknown and all(slot in project_slots for slot in self.live_slots)
                               and not self._scratch and self._profile_disk_reserved == 0 and files_closed)
        if not self.close_complete:
            failure = first or ArtifactInspectionRefused("cleanup-unknown")
            self.remember(failure, fatal=True)
            raise _cleanup_failure(self.guard, failure)
        if first is not None:
            raise first

    def closed(self) -> bool:
        self.owner()
        return self.close_claimed and self.close_complete and not self.unknown and not self.live_slots


class ArtifactInspectionRun:
    """One saved-command service; only this original can propose its terminal."""

    def __init__(self, request: ArtifactInspectionRequest, guard: DefaultCancellation,
                 source: ArtifactInspectionInput) -> None:
        self.operation = ArtifactInspectionOperation(request, guard, source)
        self.request, self.guard, self.source = request, guard, source
        self.root = self.operation.root
        self.result = None

    def remember(self, error: BaseException) -> None:
        self.operation.remember(error)
        if self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")

    def _close_tools(self) -> None:
        # These are the same two fixed children, not caller callbacks. Retire
        # them before releasing the private artifact or its enclosing project.
        operation = self.operation
        first = None
        with self.guard.deferred(check_on_exit=False):
            for child in (operation.tools, operation.ios_tools):
                if child is not None:
                    try:
                        child.close()
                    except BaseException as error:
                        self.remember(error)
                        if first is None:
                            first = error
        if first is not None:
            raise first

    def _aab(self) -> dict:
        from .android import inspect_artifact_aab
        from .android_build_tools import AndroidValidationTools
        from .ios import _native_scratch

        operation = self.operation
        artifact = operation.files.artifact
        require(artifact is not None)
        binding = self.request.native["tools"]["android"]
        if binding is None:
            require(operation.tools is None)
            observed = inspect_artifact_aab(artifact.path, artifact=artifact,
                                           cancellation=self.guard, tools=None)
        else:
            # Missing is an explicit native selection, not an exception from a
            # partially admitted toolchain. Do not catch/upgrade acquire errors.
            operation.tools = AndroidValidationTools(operation, binding)
            operation.tools.acquire()
            operation.tools.require_signature_tools()
            with _native_scratch(prefix="mobile-release-artifact-tools-", cancellation=self.guard) as (_, guard):
                require(guard is self.guard)
                try:
                    observed = inspect_artifact_aab(artifact.path, artifact=artifact,
                                                   cancellation=self.guard, tools=operation.tools)
                except BaseException as error:
                    self.remember(error)  # F precedes the original workspace cleanup.
                    raise
                finally:
                    self._close_tools()
        operation.inspection_checkpoint()
        return _project_artifact_result(operation, aab=observed, structure_ok=observed.structure_ok)

    def _ipa(self) -> dict:
        from .errors import ValidationError
        from .ios import inspect_artifact_ipa
        from .ios_artifacts import (inspect_artifact_archive_pair, inspect_artifact_ipa_layout,
                                    inspect_artifact_symbols)

        operation = self.operation
        if "ios-ipa" in operation._shape_refusals:
            return _project_artifact_result(operation, structure_ok=False)
        try:
            layout = inspect_artifact_ipa_layout(operation.snapshot)
        except ValidationError as error:
            if type(error) is not ValidationError:
                raise
            operation.data_refusal(error)
            return _project_artifact_result(operation, structure_ok=False)
        operation._ipa_layout = layout
        if self.request.native["tools"]["ios"] is not None:
            ArtifactInspectionIOSTools(operation).acquire()
        observed = inspect_artifact_ipa(operation, cancellation=self.guard)
        pair_ok = symbols_ok = None
        if self.request.context["selections"]["archive"] is not None:
            if "ios-archive" in operation._shape_refusals:
                pair_ok = False
            else:
                try:
                    pair = inspect_artifact_archive_pair(operation.snapshot, layout)
                except ValidationError as error:
                    if type(error) is not ValidationError:
                        raise
                    operation.data_refusal(error)
                    pair_ok = False
                else:
                    operation._ipa_pair, pair_ok = pair, True
            if pair_ok and self.request.context["selections"]["dsyms"] is not None:
                if "ios-dsyms" in operation._shape_refusals:
                    symbols_ok = False
                else:
                    try:
                        inspect_artifact_symbols(operation.snapshot, operation._ipa_pair)
                    except ValidationError as error:
                        if type(error) is not ValidationError:
                            raise
                        operation.data_refusal(error)
                        symbols_ok = False
                    else:
                        symbols_ok = True
        operation.inspection_checkpoint()
        return _project_artifact_result(operation, ipa=observed, structure_ok=True,
                                        pair_ok=pair_ok, symbols_ok=symbols_ok)

    def _inspect(self) -> None:
        from .ios_artifacts import snapshot_ios_artifacts
        operation = self.operation
        operation.inputs = operation.files.saved()
        operation.files.capture_selected()
        operation.preflight_originals()
        with snapshot_ios_artifacts(operation.artifact_paths(), cancellation=self.guard,
                                    artifact_operation=operation) as snapshot:
            try:
                require(snapshot is operation.snapshot)
                result = self._aab() if self.request.context["format"] == "aab" else self._ipa()
                # The projection remains provisional until actual source/copy
                # bytes, fixed tool originals and the enclosing owners settle.
                snapshot.assert_unchanged()
                operation.inspection_checkpoint()
                require(operation.primary is None and operation.dependents_settled())
                self.result = result
            except BaseException as error:
                self.remember(error)
                raise
            finally:
                self._close_tools()
        operation.files.post()

    def run(self) -> None:
        self.guard.check()
        require(sys.platform == "darwin" and os.getcwd() == self.request.native["cwd"]
                and os.uname().machine == {"macos-arm64": "arm64", "macos-x86_64": "x86_64"}[
                    self.request.native["profile"]])
        operation = self.operation
        operation.invocation_attempted = True
        with invocation_custody(self.root, mode="build", cancellation=self.guard) as invocation:
            try:
                require(operation.invocation is invocation)
                with invocation.project(signing_lease=None):
                    try:
                        _, identity = invocation._artifact_inspection_root(operation)
                        if identity != self.request.native["rootIdentity"]:
                            operation.fail("saved-config-changed")
                        self._inspect()
                    except BaseException as error:
                        self.remember(error)
                        raise
                    finally:
                        try:
                            # Owned sources close before their original project
                            # lock. Unknown native consumers retain both.
                            operation.close()
                        except BaseException as error:
                            self.remember(error)
                            raise
            except BaseException as error:
                self.remember(error)
                raise

    def close(self) -> None:
        self.operation.close()

    def terminal(self) -> dict:
        operation = self.operation
        facts = self.guard.lifetime_ledger.verdict()
        if time.monotonic() >= self.source.work_end:
            self.source.stop("timed-out")
        elif self.guard.cancelled and self.source.stop_reason == "none":
            self.source.stop("cancelled")
        invocation = operation.invocation
        invocation_closed = ((not operation.invocation_attempted if invocation is None else
                              invocation._artifact_inspection_closed(operation)) and operation.closed())
        lifetime = {"complete": facts.complete, "fatal": facts.fatal, "contained": facts.contained,
            "commandDispatched": facts.command_dispatched, "commands": facts.commands,
            "profileCalls": facts.profile_calls, "inputClosed": self.source.closed,
            "handlersRestored": self.guard.handler_state == "RESTORED", "invocationClosed": invocation_closed,
            "stopObserved": self.source.stop_reason}
        settled = (facts.complete and facts.cleanup_complete and facts.contained and not facts.fatal
                   and facts.command_dispatched is not None and self.source.closed
                   and lifetime["handlersRestored"] and invocation_closed)
        result = None
        if not settled:
            outcome, reason = "unknown", "cleanup-unknown"
        elif self.source.stop_reason != "none":
            outcome = reason = self.source.stop_reason
        elif isinstance(operation.primary, ArtifactInspectionRefused):
            outcome, reason = "refused", operation.primary.reason
        elif isinstance(operation.primary, ArtifactInspectionLimitError):
            outcome, reason = "refused", "input-limit"
        elif isinstance(operation.primary, BuildInputError):
            outcome, reason = "refused", "project-admission-refused"
        elif isinstance(operation.primary, ProtocolError):
            outcome, reason = "failed", "protocol-error"
        elif operation.primary is not None or self.result is None:
            outcome, reason = "failed", "command-incomplete"
        else:
            outcome, reason = "complete", "none"
            try:
                result = validate_result(self.result, self.request.context)
            except (ProtocolError, ValueError, TypeError, RecursionError):
                self.source.failure_observed()
                outcome, reason = "failed", "result-limit"
        return {"schemaVersion": 1, "context": self.request.context, "outcome": outcome,
                "reason": reason, "result": result, "lifetime": lifetime}
