"""Stage only missing pinned public tools, through an original native owner.

This is deliberately not a CLI/renderer endpoint. The fixed native bootstrap
must supply the ToolAcquisition role, current missing-only admission, admitted
runtime/CA/cache loan, durable intent and original cancellation/finality book.
There is no production fallback owner and no permission minted from JSON.

Successful extraction is an offer, not registration, native finality or build
readiness. The user still chooses the staged source in the ordinary native
picker, then uses the existing inspect/review/explicit-register flow.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from typing import Protocol

from ._tool_acquisition_spec import (AcquisitionError, Archive, CHUNK, COMPONENTS, Component,
    METADATA_RESERVE, PROFILES, RESERVE_BYTES, canonical, decode_manifest, digest, operation_id, require)
from ._tool_acquisition_files import (Files, OutputTree, directory_identity, extract_tar, extract_zip, named)
from ._tool_vendor_transport import PublicVendorTransfer
from .cancellation import CleanupScope, DefaultCancellation, cancellation_owner

CACHE_JOBS_LIMIT = 32
CONTROL_LIMIT = 16 * 1024
LOOKUP_SCOPE = "registered-selected-known"


@dataclass(frozen=True, slots=True)
class Admission:
    """Private original-owner inputs, never a deserialized renderer request.

    Context digest binds project/session, saved configuration, requirements,
    exact host/architecture/profile and all catalogue/source/service generations.
    The native book—not this value—proves currentness, the complete declared
    lookup set, explicit one-use consent and lack of unresolved known copies.
    """
    operation_id: str
    context_sha256: str
    profile: str
    reference_sha256: str
    projection_sha256: str
    cache_generation: int
    cache_root: Path
    cache_identity: tuple[int, ...]
    missing: tuple[Component, ...]
    compatible: tuple[Component, ...]
    census_complete: bool
    lookup_scope: str
    deadline: float


class NativeAcquisitionOwner(Protocol):
    """Narrow seam for the original SavedCommandOwner ToolAcquisition facet.

    Implemented only by the fixed admitted bootstrap, not a callback/URL API.
    Its parent retains real driver, child, pipe and final join ownership.
    A saved cache receipt, result frame or pathname cannot implement this role.
    """
    cancellation: DefaultCancellation | None

    def claim(self) -> Admission:
        """Consume current explicit permit; refuse any original recovery fence."""
        ...

    def checked_manifest(self) -> bytes:
        """Return the same already checked compiled reference bound at claim."""
        ...

    def checkpoint(self) -> None:
        """Recheck original context/generations, admission and absolute deadline."""
        ...

    def admit_cache_origin(self, operation: str, intent_sha256: str) -> None:
        """Require original settled producer finality for this exact old intent.

        Absent journal entry, unknown producer or interrupted intent is a fence,
        including after restart. JSON/result-shaped bytes cannot discharge it.
        """
        ...

    def record_intent(self, intent: bytes) -> None:
        """Durably bind pending intent BEFORE any new job directory or network.

        The original owner records the attempt before publication and retains
        ambiguity on interruption. No Python result can mark this native book
        settled; that requires the parent's original joins and final checks.
        """
        ...

    def public_ca(self) -> bytes:
        """Borrow immutable admitted CA bytes under this exact runtime role."""
        ...

    def retain_unknown(self, original: ToolAcquisition) -> None:
        """Retain original resources/finality fence; never reset by target absence."""
        ...


@dataclass(frozen=True, slots=True)
class StagedGroup:
    group: str
    components: tuple[Component, ...]
    all_required_components_staged: bool


@dataclass(frozen=True, slots=True)
class PreparedSources:
    operation_id: str
    context_sha256: str
    reference_sha256: str
    projection_sha256: str
    cache_job: str
    reused_archives: tuple[Component, ...]
    downloaded_archives: tuple[Component, ...]
    groups: tuple[StagedGroup, ...]

    def to_data(self) -> dict:
        # No absolute path, URL, private runtime binding or authority receipt.
        return {"schemaVersion": 1, "kind": "staged-tool-sources",
            "operationId": self.operation_id, "contextSha256": self.context_sha256,
            "referenceSha256": self.reference_sha256, "projectionSha256": self.projection_sha256,
            "cacheJob": self.cache_job, "lookupScope": LOOKUP_SCOPE,
            "reusedArchives": [part.value for part in self.reused_archives],
            "downloadedArchives": [part.value for part in self.downloaded_archives],
            "groups": [{"group": item.group, "components": [part.value for part in item.components],
                "allRequiredComponentsStaged": item.all_required_components_staged,
                "next": "choose-native-source" if item.all_required_components_staged else "complete-sdk-manually"}
                for item in self.groups],
            "assurance": {"nativeFinality": False, "registered": False, "readyToBuild": False}}


@dataclass(frozen=True, slots=True)
class _CachedArchive:
    job: str
    stamp: tuple[int, ...]
    intent_sha256: str


def _validate_admission(value: Admission) -> None:
    require(type(value) is Admission and operation_id(value.operation_id)
        and digest(value.context_sha256) and digest(value.reference_sha256) and digest(value.projection_sha256))
    require(type(value.profile) is str and value.profile in PROFILES, "unsupported")
    require(type(value.cache_generation) is int and 0 < value.cache_generation <= 2**53 - 1)
    require(isinstance(value.cache_root, Path) and value.cache_root.is_absolute() and ".." not in value.cache_root.parts)
    require(type(value.cache_identity) is tuple and len(value.cache_identity) == 5
        and all(type(part) is int and part >= 0 for part in value.cache_identity))
    require(value.census_complete is True and value.lookup_scope == LOOKUP_SCOPE, "census-incomplete")
    require(type(value.missing) is tuple and type(value.compatible) is tuple
        and all(type(part) is Component for part in value.missing + value.compatible), "census-incomplete")
    require(value.missing == tuple(part for part in COMPONENTS if part in value.missing)
        and value.compatible == tuple(part for part in COMPONENTS if part in value.compatible)
        and not set(value.missing).intersection(value.compatible)
        and set(value.missing + value.compatible) == set(COMPONENTS), "census-incomplete")
    now = time.monotonic()
    require(type(value.deadline) in (int, float) and now < value.deadline <= now + 1200, "cancelled")


def _origin(data: bytes, expected_operation: str) -> dict:
    # DATA only. Its hash must still be accepted by the ORIGINAL native book.
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "cache-conflict")
            result[key] = value
        return result
    try:
        value = json.loads(data, object_pairs_hook=pairs)
        require(type(value) is dict and set(value) == {"schemaVersion", "operationId", "contextSha256",
            "profile", "referenceSha256", "projectionSha256", "cacheGeneration", "components"}, "cache-conflict")
        require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["operationId"] == expected_operation and operation_id(value["operationId"])
            and all(digest(value[key]) for key in ("contextSha256", "referenceSha256", "projectionSha256"))
            and type(value["profile"]) is str and value["profile"] in PROFILES
            and type(value["cacheGeneration"]) is int and 0 < value["cacheGeneration"] <= 2**53 - 1
            and type(value["components"]) is list and bool(value["components"])
            and value["components"] == [part.value for part in COMPONENTS if part.value in value["components"]],
            "cache-conflict")
        require(canonical(value) == data, "cache-conflict")
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise AcquisitionError("cache-conflict") from None


class _Space:
    def __init__(self, files: Files, amount: int):
        self.files, self.remaining = files, amount + METADATA_RESERVE
        self.check()

    def check(self) -> None:
        self.files.check()
        info = os.fstatvfs(self.files.root.fd)
        require(info.f_frsize > 0 and info.f_bavail >= 0
            and info.f_frsize * info.f_bavail >= self.remaining + RESERVE_BYTES, "disk-space")

    def consume(self, amount: int) -> None:
        self.check()
        require(type(amount) is int and 0 <= amount <= self.remaining, "limit")
        self.remaining -= amount


class ToolAcquisition:
    """One attempt, original retained resources; no automatic mutation retry."""
    def __init__(self, owner: NativeAcquisitionOwner):
        self.owner = owner
        self.claimed = False
        self.intent_attempted = False
        self.intent_recorded = False
        self.unknown = False
        self.guard: DefaultCancellation | None = None
        self.files: Files | None = None
        self.transfer: PublicVendorTransfer | None = None
        self.scope: CleanupScope | None = None
        self.admission: Admission | None = None

    def _check(self) -> None:
        self.owner.checkpoint()
        require(self.admission is not None and time.monotonic() < self.admission.deadline, "cancelled")

    def run(self) -> PreparedSources:
        require(not self.claimed, "already-used")
        self.claimed = True  # Before a potentially interrupted original claim.
        try:
            admission = self.owner.claim()
            _validate_admission(admission)
            self.admission = admission
            manifest = decode_manifest(self.owner.checked_manifest())
            require((manifest.profile, manifest.reference_sha256, manifest.projection_sha256)
                == (admission.profile, admission.reference_sha256, admission.projection_sha256), "stale")
            self._check()
            # A valid complete known set with every tool compatible does not
            # even open the cache, acquire a CA loan or create a job directory.
            if not admission.missing:
                return PreparedSources(admission.operation_id, admission.context_sha256, admission.reference_sha256,
                    admission.projection_sha256, "", (), (), ())
            guard, owns = cancellation_owner(self.owner.cancellation, AcquisitionError, "unknown")
            self.guard = guard
            files = Files(admission.cache_root, guard, self._check)
            self.files = files
            scope = CleanupScope(guard, files.close, owns_cancellation=owns, first_primary=True)
            self.scope = scope
            offer = None
            try:
                try:
                    with scope:
                        if owns:
                            guard.install()
                            guard.activate()
                        files.acquire()
                        require(directory_identity(os.fstat(files.root.fd)) == admission.cache_identity, "stale")
                        archives = tuple(manifest.archive(part) for part in admission.missing)
                        cached = self._cache(archives)
                        new_bytes = sum(archive.size for archive in archives if archive.component not in cached)
                        space = _Space(files, new_bytes + sum(archive.expanded_bytes for archive in archives))
                        files.before_write = space.consume
                        self._check()
                        intent = canonical({"schemaVersion": 1, "operationId": admission.operation_id,
                            "contextSha256": admission.context_sha256, "profile": admission.profile,
                            "referenceSha256": admission.reference_sha256, "projectionSha256": admission.projection_sha256,
                            "cacheGeneration": admission.cache_generation, "components": [part.value for part in admission.missing]})
                        self.intent_attempted = True
                        self.owner.record_intent(intent)
                        self.intent_recorded = True
                        self._check()
                        job = "tool-" + admission.operation_id
                        files.mkdir(files.root.fd, job)
                        with files.directory(files.root.fd, job) as job_fd:
                            files.control(job_fd, "origin.json", json.loads(intent))
                            files.mkdir(job_fd, "sources")
                            with files.directory(job_fd, "sources") as sources_fd:
                                tree = OutputTree(files, sources_fd, archives)
                                for archive in archives:
                                    files.check()
                                    previous = cached.get(archive.component)
                                    if previous is not None:
                                        self.owner.admit_cache_origin(previous.job[5:], previous.intent_sha256)
                                        with files.directory(files.root.fd, previous.job) as old_fd:
                                            with files.reader(old_fd, archive.component.value + ".archive", archive.size) as reader:
                                                require(reader.stamp == previous.stamp and reader.size == archive.size
                                                    and reader.sha256() == archive.sha256, "archive-digest")
                                                self._extract(reader, archive, tree)
                                    else:
                                        self._download(job_fd, archive)
                                        with files.reader(job_fd, archive.component.value + ".archive", archive.size) as reader:
                                            require(reader.size == archive.size and reader.sha256() == archive.sha256, "archive-digest")
                                            self._extract(reader, archive, tree)
                                tree.verify()  # Full newly staged identity reinspection.
                            files.check()
                            offer = self._offer(job, cached)
                            files.control(job_fd, "result.json", offer.to_data())
                            files.check()
                finally:
                    scope.__exit__(*sys.exc_info())
                guard.check()
                self._check()
                require(files.settled and not (self.transfer is not None and self.transfer.unknown), "unknown")
            except BaseException:
                raise
            assert offer is not None
            return offer
        except BaseException as error:
            fatal = (self.guard is not None and self.guard.lifetime_ledger.fatal)
            self.unknown = (fatal or (self.intent_attempted and not self.intent_recorded)
                or (self.files is not None and not self.files.settled)
                or (self.transfer is not None and self.transfer.unknown))
            if self.unknown:
                # Keep this exact object even if diagnostic publication fails.
                # Root's native book retains its original pending/unknown fence.
                try:
                    self.owner.retain_unknown(self)
                except BaseException:
                    self.unknown = True
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            if self.unknown:
                raise AcquisitionError("unknown") from None
            if isinstance(error, AcquisitionError):
                raise
            raise AcquisitionError("cache-conflict") from None

    def _cache(self, archives: tuple[Archive, ...]) -> dict[Component, _CachedArchive]:
        files, admission = self.files, self.admission
        assert files is not None and admission is not None
        names = files.names(files.root.fd, CACHE_JOBS_LIMIT)
        require(len(names) < CACHE_JOBS_LIMIT, "limit")  # Leave exactly one new exclusive job slot.
        result = {}
        for job in names:
            require(job.startswith("tool-") and operation_id(job[5:]), "cache-conflict")
            require(job != "tool-" + admission.operation_id, "already-used")
            with files.directory(files.root.fd, job) as old_fd:
                require(named(old_fd, "origin.json") is not None, "recovery-required")
                with files.reader(old_fd, "origin.json", CONTROL_LIMIT) as reader:
                    raw = reader.read(reader.size)
                    require(len(raw) == reader.size, "cache-conflict")
                    origin = _origin(raw, job[5:])
                    intent_digest = hashlib.sha256(raw).hexdigest()
                self.owner.admit_cache_origin(job[5:], intent_digest)
                allowed = {"origin.json", "result.json", "sources"} | {part + ".archive" for part in origin["components"]}
                require(set(files.names(old_fd, len(allowed))) <= allowed, "cache-conflict")
                if (origin["profile"], origin["referenceSha256"], origin["projectionSha256"]) != (
                        admission.profile, admission.reference_sha256, admission.projection_sha256):
                    continue  # Settled other checked profile/reference is retained, never adopted.
                for archive in archives:
                    if archive.component in result or archive.component.value not in origin["components"]:
                        continue
                    name = archive.component.value + ".archive"
                    if named(old_fd, name) is None:
                        continue  # Only an ORIGINAL settled producer permits this partial-cache fact.
                    with files.reader(old_fd, name, archive.size) as reader:
                        require(reader.size == archive.size and reader.sha256() == archive.sha256, "archive-digest")
                        result[archive.component] = _CachedArchive(job, reader.stamp, intent_digest)
        return result

    def _download(self, job_fd: int, archive: Archive) -> None:
        files, admission = self.files, self.admission
        assert files is not None and admission is not None
        if self.transfer is None:
            self.transfer = PublicVendorTransfer(profile=admission.profile, ca_pem=self.owner.public_ca(),
                deadline=admission.deadline, checkpoint=files.check)
        with files.new_file(job_fd, archive.component.value + ".archive") as fd:
            count, hashed = 0, hashlib.sha256()

            def write(data: bytes) -> None:
                nonlocal count
                require(type(data) is bytes and 0 < len(data) <= CHUNK and count + len(data) <= archive.size, "framing")
                files.write(fd, data)
                hashed.update(data)
                count += len(data)

            self.transfer.copy(archive, write)
            require(count == archive.size and hashed.hexdigest() == archive.sha256
                and os.fstat(fd).st_size == archive.size, "archive-digest")

    @staticmethod
    def _extract(reader, archive: Archive, tree: OutputTree) -> None:
        try:
            if archive.component is Component.JDK:
                extract_tar(reader, archive, tree)
            else:
                extract_zip(reader, archive, tree)
        except (AcquisitionError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise AcquisitionError("archive-layout") from None

    def _offer(self, job: str, cached: dict[Component, _CachedArchive]) -> PreparedSources:
        admission = self.admission
        assert admission is not None
        groups = []
        for group in ("jdk", "sdk", "gradle"):
            parts = tuple(part for part in admission.missing if part.group == group)
            if parts:
                groups.append(StagedGroup(group, parts, parts == tuple(part for part in COMPONENTS if part.group == group)))
        return PreparedSources(admission.operation_id, admission.context_sha256, admission.reference_sha256,
            admission.projection_sha256, job, tuple(part for part in admission.missing if part in cached),
            tuple(part for part in admission.missing if part not in cached), tuple(groups))
