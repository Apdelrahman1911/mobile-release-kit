"""Read-only, fail-closed GitHub evidence handoff for the pinned release workflows.

This module never invokes a Store tool, a build, an upload, or an attestation
*producer*. ``gh attestation verify`` is the cryptographic boundary. A ZIP digest
and the local resolution checksum are integrity checks, not authentication.

The certificate fields checked below are the actual sigstore-go/gh JSON fields
(gh 2.88.1); in particular runInvocationURI is an OIDC-certified run/attempt,
not merely a workflow-controlled SLSA predicate assertion. Predicate layout is
the @actions/attest 3.2 provenance emitted by the pinned attest action.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .errors import MobileReleaseError, ValidationError
from .provenance import (
    WORKFLOW_PATHS,
    _authority_for_stage,
    _reject_duplicate_pairs,
    canonical_json_bytes,
    copy_immutable_file,
    load_candidate_manifest,
    load_operation_intent,
    load_release_receipt,
    load_store_receipt,
    seal,
    sha256_file,
    validate_receipt_chain,
    validate_receipt_raw_binding,
    verify_sealed,
    workflow_authority,
)

STAGES = tuple(WORKFLOW_PATHS)
PLATFORMS = ("android", "ios")
ARTIFACT_STAGES = {"candidate": "candidate", "external-testing": "external", "production-submit": "production"}
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
NUMBER = re.compile(r"[1-9][0-9]{0,19}")
MAX_JSON = 16 * 1024 * 1024
MAX_EVIDENCE = 1024 * 1024 * 1024
MAX_HANDOFF = 32 * 1024 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024 * 1024
MAX_FILES = 128
# ZIP central records have 16-bit extra/comment lengths. Bound those allocations
# before ZipFile reads the directory or constructs a ZipInfo for every record.
MAX_ZIP_NAME_BYTES = 2048
MAX_ZIP_DIRECTORY = MAX_FILES * (46 + MAX_ZIP_NAME_BYTES + 2 * 65535)
MAX_PAGES = 100
MAX_ATTEMPTS = 100
PROOF_TYPE = "workflow-provenance"
PROOF_VERSION = 1
GITHUB = "https://github.com/"
HANDOFF_FILES = {
    "android": {"app-release.aab": "android-aab", "mapping.txt": "android-mapping", "native-symbols.zip": "android-native-symbols", "validation-report.json": "validation-report"},
    "ios": {"app.ipa": "ios-ipa", "archive.zip": "ios-archive", "dsyms.zip": "ios-dsyms", "validation-report.json": "validation-report"},
}


class WorkflowError(ValidationError):
    """A fixed, safe-to-log orchestration failure (never remote response text)."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise WorkflowError(message)


def _number(value: object, label: str) -> str:
    _require(isinstance(value, str) and bool(NUMBER.fullmatch(value)), f"{label} must be a positive decimal ID")
    return value  # type: ignore[return-value]


def _integer(value: object, label: str, maximum: int = 10**20) -> int:
    _require(type(value) is int and 0 <= value <= maximum, f"{label} is not a bounded integer")
    return value  # type: ignore[return-value]


def _keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == expected, f"{label} has missing or unsupported fields")
    return value  # type: ignore[return-value]


def _date(value: object) -> datetime:
    _require(isinstance(value, str) and len(value) <= 40, "GitHub evidence timestamp is missing or malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))  # type: ignore[union-attr]
        _require(parsed.tzinfo is not None, "GitHub evidence timestamp lacks a timezone")
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise WorkflowError("GitHub evidence timestamp is malformed") from None


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_path(path: Path) -> Path:
    """Reject application-controlled symlinks, including parent components.

    macOS's root-owned /var and /tmp aliases are OS layout, not application
    symlinks. Accept only those exact aliases; resolve no other symlink.
    """
    result = path.expanduser().absolute()
    current = Path(result.anchor)
    for part in result.parts[1:]:
        current = current / part
        if current.is_symlink():
            system_alias = {"/var": "/private/var", "/tmp": "/private/tmp"}.get(str(current))
            _require(bool(system_alias) and current.lstat().st_uid == 0 and os.readlink(current) in {system_alias, system_alias.lstrip("/")}, "workflow files must not traverse symbolic links")
    return result


def _read_json(path: Path, maximum: int = MAX_JSON) -> dict[str, Any]:
    path = _safe_path(path)
    _require(path.is_file() and path.stat().st_size <= maximum, "workflow JSON is missing or exceeds its size limit")
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=_reject_duplicate_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise WorkflowError("workflow JSON is invalid") from None
    _require(isinstance(value, dict), "workflow JSON must be an object")
    return value


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path = _safe_path(path)
    _require(not path.exists(), "immutable workflow output already exists")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = canonical_json_bytes(value) + b"\n"
    descriptor, name = tempfile.mkstemp(prefix=".mrk-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.link(name, path, follow_symlinks=False)
    except OSError:
        raise WorkflowError("immutable workflow output could not be published") from None
    finally:
        os.unlink(name)


def _new_directory(path: Path) -> Path:
    path = _safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        raise WorkflowError("workflow destination already exists; preserve it and use a new empty destination") from None
    return path


def _files(root: Path, *, maximum: int = MAX_EVIDENCE) -> dict[str, Path]:
    root = _safe_path(root)
    _require(root.is_dir(), "workflow payload directory is missing")
    files: dict[str, Path] = {}
    folded: set[str] = set()
    total = 0
    for directory, children, names in os.walk(root, followlinks=False):
        for name in children + names:
            path = _safe_path(Path(directory) / name)
            relative = path.relative_to(root).as_posix()
            _require(len(relative) <= 512 and relative.casefold() not in folded, "workflow payload has duplicate or case-colliding paths")
            folded.add(relative.casefold())
            mode = path.lstat().st_mode
            _require(stat.S_ISREG(mode) or stat.S_ISDIR(mode), "workflow payload contains a non-regular file")
            if stat.S_ISREG(mode):
                size = path.stat().st_size
                total += size
                _require(size <= MAX_FILE and total <= maximum and len(files) < MAX_FILES, "workflow payload exceeds its bounded size or file count")
                files[relative] = path
    return files


def artifact_name(stage: str, platform: str, kind: str) -> str:
    _require(stage in STAGES and platform in PLATFORMS and kind in {"intent", "evidence", "handoff"}, "invalid fixed workflow artifact selector")
    _require(kind != "handoff" or stage == "candidate", "only candidates have binary handoffs")
    return f"mobile-release-{ARTIFACT_STAGES[stage]}-{kind}-{platform}"


def job_key(stage: str, platform: str) -> str:
    return f"{platform}_store" if stage == "candidate" else platform


def _job_name(name: object, key: str) -> bool:
    # GitHub prefixes reusable jobs with caller display names separated by ' / '.
    # Match complete segments, NEVER endswith(key), and reject matrix suffixes.
    return isinstance(name, str) and len(name) <= 512 and 1 <= len(name.split(" / ")) <= 4 and name.split(" / ")[-1] == key and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _().-]{0,127}", segment) for segment in name.split(" / "))


def _layout(stage: str, phase: str, prefix: str = "") -> dict[str, str]:
    _require(stage in STAGES and phase in {"intent", "final"}, "invalid evidence layout")
    if phase == "final":
        result = {
            prefix + "workflow-provenance.json": "final-provenance",
            prefix + f"{stage}-receipt.json": "final-receipt",
            prefix + "store-receipt.json": "raw-store-readback",
        }
        if stage == "candidate":
            result[prefix + "candidate-manifest.json"] = "candidate-manifest"
        result.update(_layout(stage, "intent", prefix + "operation/"))
        return result
    result = {
        prefix + f"{stage}-operation-intent.json": "operation-intent",
        prefix + "intent-provenance.json": "intent-provenance",
    }
    if stage == "candidate":
        result[prefix + "store-metadata.zip"] = "candidate-store-metadata"
    if stage != "candidate":
        result.update({path: "candidate/" + role for path, role in _layout("candidate", "final", prefix + "candidate/").items()})
    if stage == "production-submit":
        result.update({path: "external/" + role for path, role in _layout("external-testing", "final", prefix + "external/").items()})
    return result


def _inventory(root: Path, layout: Mapping[str, str], *, omitted: str | None = None) -> list[dict[str, Any]]:
    expected = set(layout) - ({omitted} if omitted else set())
    found = _files(root)
    _require(set(found) == expected, "evidence bundle contains missing or unexpected files")
    expected_directories = {str(parent) for name in expected for parent in PurePosixPath(name).parents if str(parent) != "."}
    actual_directories = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_dir()}
    _require(actual_directories == expected_directories, "evidence bundle contains unexpected directories")
    return [{"path": name, "role": layout[name], "size": found[name].stat().st_size, "sha256": sha256_file(found[name])} for name in sorted(found)]


def _inventory_shape(value: object, *, roles: bool) -> None:
    _require(isinstance(value, list) and len(value) <= MAX_FILES, "workflow inventory is not a bounded list")
    for record in value:
        _keys(record, {"path", "size", "sha256"} | ({"role"} if roles else set()), "workflow inventory entry")
        _require(isinstance(record["path"], str) and len(record["path"]) <= 512 and isinstance(record["sha256"], str) and bool(DIGEST.fullmatch(record["sha256"])), "workflow inventory path/digest is invalid")
        _integer(record["size"], "workflow inventory size", MAX_FILE)
        if roles:
            _require(isinstance(record["role"], str), "workflow inventory role is invalid")


def _copy_tree(source: Path, destination: Path) -> None:
    files = _files(source, maximum=MAX_HANDOFF)
    destination = _safe_path(destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in sorted(files):
        copy_immutable_file(files[name], destination / name)


class Transport:
    """The only external-command boundary. Output and elapsed time are bounded."""

    def run(self, arguments: Sequence[str], *, maximum: int = MAX_JSON, timeout: int = 120, output: Path | None = None) -> bytes:
        _require(arguments and arguments[0] == "gh", "workflow transport only permits the GitHub CLI")
        env = {name: os.environ[name] for name in ("PATH", "HOME", "GH_TOKEN", "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR", "SYSTEMROOT") if os.environ.get(name)}
        env.update({"GH_HOST": "github.com", "GH_PROMPT_DISABLED": "1", "GH_PAGER": "cat", "GH_NO_UPDATE_NOTIFIER": "1", "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1", "NO_COLOR": "1"})
        handle = None
        process = None
        result = bytearray()
        total = 0
        deadline = time.monotonic() + timeout
        succeeded = False
        cancelled = False
        cleaning_up = False
        previous_handlers: dict[int, Any] = {}

        def interrupt(signum: int, frame: Any) -> None:
            nonlocal cancelled
            cancelled = True
            # Do not interrupt Popen before its process handle is assigned: a
            # child in a new session would otherwise escape the finally block.
            # The pending interruption is raised immediately after spawning.
            if process is not None and not cleaning_up:
                raise KeyboardInterrupt

        # Only a CLI's default main-thread handlers are ours to translate.
        # Respect a library host's custom/ignored handlers and worker threads,
        # and restore the originals even if spawning or cleanup fails.
        if threading.current_thread() is threading.main_thread():
            for signum, default in ((signal.SIGTERM, signal.SIG_DFL), (signal.SIGINT, signal.default_int_handler)):
                previous = signal.getsignal(signum)
                if previous == default:
                    previous_handlers[signum] = previous
                    signal.signal(signum, interrupt)
        try:
            if output is not None:
                descriptor = os.open(_safe_path(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                handle = os.fdopen(descriptor, "wb")
            if cancelled:
                raise KeyboardInterrupt
            process = subprocess.Popen(list(arguments), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, start_new_session=True)
            if cancelled:
                raise KeyboardInterrupt
            assert process.stdout is not None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    _require(time.monotonic() < deadline, "GitHub verification timed out; retained evidence was not replaced")
                    for key, _ in selector.select(min(0.25, max(0.0, deadline - time.monotonic()))):
                        data = os.read(key.fd, 64 * 1024)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(data)
                        _require(total <= maximum, "GitHub response exceeded its size limit")
                        if handle:
                            handle.write(data)
                        else:
                            result.extend(data)
            _require(process.wait(timeout=max(0.01, deadline - time.monotonic())) == 0, "GitHub retrieval or attestation verification failed; no fallback is permitted")
            if handle:
                handle.flush()
                os.fsync(handle.fileno())
            succeeded = True
            return bytes(result)
        except (OSError, subprocess.SubprocessError):
            raise WorkflowError("GitHub command could not complete; verify gh availability and read permissions") from None
        finally:
            cleaning_up = True
            try:
                if process is not None:
                    if not succeeded or process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                    if process.stdout is not None:
                        process.stdout.close()
                if handle:
                    handle.close()
            finally:
                for signum, previous in previous_handlers.items():
                    signal.signal(signum, previous)
            if cancelled:
                raise KeyboardInterrupt


@dataclass(frozen=True)
class Context:
    stage: str
    platform: str
    repository: Mapping[str, str]
    authority: Mapping[str, Any]
    current_job: str
    confirmation: str = ""
    selected_platform: str = ""

    @classmethod
    def current(cls, stage: str, platform: str) -> "Context":
        _require(stage in STAGES and platform in PLATFORMS, "workflow stage/platform is invalid")
        _require(os.environ.get("GITHUB_ACTIONS") == "true", "workflow orchestration is restricted to GitHub Actions")
        _require(os.environ.get("GITHUB_SERVER_URL", "https://github.com") == "https://github.com" and os.environ.get("GITHUB_API_URL", "https://api.github.com") == "https://api.github.com", "workflow recovery currently supports github.com only")
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        _require(bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)), "workflow repository is invalid")
        authority = workflow_authority(stage)
        _require(authority["headSha"] == os.environ.get("GITHUB_SHA") and authority["ref"] == os.environ.get("GITHUB_REF"), "dispatch authority must not rewrite the actual GitHub head/ref")
        _require(authority["attempt"] <= MAX_ATTEMPTS, "workflow attempt exceeds the bounded recovery limit")
        current_job = os.environ.get("GITHUB_JOB", "")
        _require(bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,127}", current_job)), "GITHUB_JOB is required")
        return cls(stage, platform, {"fullName": repository, "id": _number(os.environ.get("GITHUB_REPOSITORY_ID"), "repository ID")}, authority, current_job, os.environ.get("MOBILE_RELEASE_CONFIRMATION", ""), os.environ.get("MOBILE_RELEASE_SELECTED_PLATFORM", ""))


class GitHub:
    def __init__(self, context: Context, transport: Transport | None = None):
        self.context = context
        self.transport = transport or Transport()
        self._attempts: dict[tuple[str, int], dict[str, Any]] = {}
        self._artifacts: dict[str, list[dict[str, Any]]] = {}
        self._trees: dict[str, str] = {}
        self._comparisons: dict[tuple[str, str], dict[str, Any]] = {}

    def json(self, endpoint: str) -> Any:
        prefix = f"repos/{self.context.repository['fullName']}/"
        compare = bool(re.fullmatch(re.escape(prefix) + r"compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}", endpoint))
        _require(endpoint.startswith(prefix) and (".." not in endpoint or compare) and "#" not in endpoint and "\\" not in endpoint, "GitHub endpoint is outside the application repository")
        data = self.transport.run(["gh", "api", "--hostname", "github.com", "--method", "GET", "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28", endpoint])
        try:
            return json.loads(data, object_pairs_hook=_reject_duplicate_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (ValueError, UnicodeError, RecursionError):
            raise WorkflowError("GitHub API returned invalid JSON") from None

    def _path(self, suffix: str) -> str:
        return f"repos/{self.context.repository['fullName']}/{suffix}"

    def pages(self, suffix: str, key: str) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        count: int | None = None
        for page in range(1, MAX_PAGES + 1):
            response = self.json(self._path(f"{suffix}?per_page=100&page={page}"))
            _require(isinstance(response, dict), "GitHub list response is invalid")
            total = _integer(response.get("total_count"), "GitHub list count", MAX_PAGES * 100)
            entries = response.get(key)
            _require(isinstance(entries, list) and len(entries) <= 100 and all(isinstance(item, dict) for item in entries), "GitHub list entries are invalid")
            _require(count is None or count == total, "GitHub list changed during pagination")
            count = total
            collected.extend(entries)
            _require(len(collected) <= total, "GitHub list count is inconsistent")
            if len(collected) == total:
                ids = [item.get("id") for item in collected]
                _require(all(type(item) is int and item > 0 for item in ids) and len(set(ids)) == len(ids), "GitHub list contains duplicate or invalid IDs")
                return collected
            _require(len(entries) == 100, "GitHub list pagination is truncated")
        raise WorkflowError("GitHub list exceeded bounded pagination")

    def attempt(self, authority: Mapping[str, Any], stage: str) -> dict[str, Any]:
        _authority_for_stage(authority, stage, "workflow producer")
        run_id, attempt = authority["runId"], authority["attempt"]
        _require(attempt <= MAX_ATTEMPTS, "workflow producer attempt exceeds the supported bound")
        key = (run_id, attempt)
        if key not in self._attempts:
            response = self.json(self._path(f"actions/runs/{run_id}/attempts/{attempt}"))
            _require(isinstance(response, dict), "workflow attempt response is invalid")
            self._attempts[key] = response
        result = self._attempts[key]
        repository = result.get("repository", {})
        head_repository = result.get("head_repository", {})
        _require(isinstance(repository, dict) and isinstance(head_repository, dict), "workflow attempt repository is missing")
        _require(repository.get("full_name") == self.context.repository["fullName"] and str(repository.get("id")) == self.context.repository["id"] and head_repository.get("full_name") == repository.get("full_name") and head_repository.get("id") == repository.get("id"), "workflow attempt belongs to another repository or fork")
        _require(type(result.get("id")) is int and result["id"] == int(run_id) and type(result.get("run_attempt")) is int and result["run_attempt"] == attempt and result.get("path") == authority["callerPath"] and result.get("head_sha") == authority["headSha"] and result.get("head_branch") == authority["ref"][len("refs/heads/"):] and result.get("event") == "workflow_dispatch" and result.get("name") == authority["workflow"], "workflow attempt identity differs from the authenticated producer")
        # Intentionally NO latest-run API lookup, overall success condition, or
        # comparison to a newer attempt. Partial success is retained authority.
        return result

    def jobs(self, authority: Mapping[str, Any], stage: str) -> list[dict[str, Any]]:
        self.attempt(authority, stage)
        return self.pages(f"actions/runs/{authority['runId']}/attempts/{authority['attempt']}/jobs", "jobs")

    def job(self, authority: Mapping[str, Any], stage: str, key: str, job_id: str | None = None, *, constructing: bool = False, allow_current: bool = False) -> dict[str, Any]:
        deadline = time.monotonic() + 60
        while True:
            matches = [job for job in self.jobs(authority, stage) if _job_name(job.get("name"), key)]
            _require(len(matches) == 1, "producer job is missing or ambiguous in its exact workflow attempt")
            job = matches[0]
            _require(type(job.get("id")) is int and job["id"] > 0 and type(job.get("run_id")) is int and job["run_id"] == int(authority["runId"]) and type(job.get("run_attempt")) is int and job["run_attempt"] == authority["attempt"] and job.get("head_sha") == authority["headSha"], "producer job run, attempt, or source is inconsistent")
            if job_id is not None:
                _require(str(job["id"]) == job_id, "producer job ID differs from its attested sidecar")
            current = authority == self.context.authority and key == self.context.current_job
            if constructing:
                _require(current and job.get("status") == "in_progress" and job.get("completed_at") is None, "sidecars must be created in the actual active protected Store job")
                _date(job.get("started_at"))
                return job
            if job.get("status") == "completed":
                _require(_date(job.get("started_at")) <= _date(job.get("completed_at")), "producer job interval is invalid")
                return job
            if allow_current and current and job.get("status") == "in_progress" and job.get("completed_at") is None:
                _date(job.get("started_at"))
                return job
            _require(job.get("status") in {"queued", "in_progress", "waiting", "pending"} and time.monotonic() < deadline, "producer job has no completed interval; retry read-only verification after it finishes")
            time.sleep(2)

    def tree(self, commit: str) -> str:
        _require(bool(SHA.fullmatch(commit)), "application source must be a full Git commit")
        if commit not in self._trees:
            result = self.json(self._path(f"git/commits/{commit}"))
            _require(isinstance(result, dict) and result.get("sha") == commit and isinstance(result.get("tree"), dict) and isinstance(result["tree"].get("sha"), str) and bool(SHA.fullmatch(result["tree"]["sha"])), "application commit/tree could not be verified")
            self._trees[commit] = result["tree"]["sha"]
        return self._trees[commit]

    def source_policy(self, stage: str, candidate: Mapping[str, str], operation: Mapping[str, str]) -> None:
        """Preserve the original exact-source/related-tree promotion guards.

        The compare endpoint is addressed with two immutable full commit IDs.
        Its identity/merge-base fields are not paginated commit-list heuristics.
        A 404 or unrelated history never proves an acceptable equal-tree rebase.
        """
        _require(stage in STAGES, "invalid release source policy stage")
        for source in (candidate, operation):
            _require(all(isinstance(source.get(key), str) and SHA.fullmatch(source[key]) for key in ("commit", "tree")), "release source identity is malformed")
            _require(self.tree(source["commit"]) == source["tree"], "release source tree differs from its immutable GitHub commit")
        if stage in {"candidate", "external-testing"}:
            _require(all(candidate[key] == operation[key] for key in ("commit", "tree")), "candidate/external operation must use the exact original candidate source")
            return
        if candidate["commit"] == operation["commit"]:
            _require(candidate["tree"] == operation["tree"], "identical commit has conflicting tree identity")
            return
        pair = candidate["commit"], operation["commit"]
        if pair not in self._comparisons:
            response = self.json(self._path(f"compare/{pair[0]}...{pair[1]}"))
            _require(isinstance(response, dict), "production source comparison is missing")
            self._comparisons[pair] = response
        comparison = self._comparisons[pair]
        base, common = comparison.get("base_commit"), comparison.get("merge_base_commit")
        _require(isinstance(base, dict) and base.get("sha") == pair[0] and isinstance(common, dict) and isinstance(common.get("sha"), str) and bool(SHA.fullmatch(common["sha"])), "production source lacks an authenticated common Git history")
        status = comparison.get("status")
        _require(status in {"ahead", "behind", "diverged"}, "production source comparison state is unsupported")
        ahead = _integer(comparison.get("ahead_by"), "source ahead count", 2**31)
        behind = _integer(comparison.get("behind_by"), "source behind count", 2**31)
        _require((status == "ahead" and ahead > 0 and behind == 0) or (status == "behind" and ahead == 0 and behind > 0) or (status == "diverged" and ahead > 0 and behind > 0), "production source comparison counters disagree")
        ancestor = status == "ahead" and common["sha"] == candidate["commit"]
        _require(ancestor or candidate["tree"] == operation["tree"], "production source must descend from the candidate or share real history and the identical complete Git tree")

    def artifact(self, run_id: str, name: str, *, redundant: bool = False) -> dict[str, Any] | None:
        _number(run_id, "artifact run")
        if run_id not in self._artifacts:
            self._artifacts[run_id] = self.pages(f"actions/runs/{run_id}/artifacts", "artifacts")
        matches = [artifact for artifact in self._artifacts[run_id] if artifact.get("name") == name]
        _require(len(matches) <= 1, "multiple immutable artifacts have the same fixed name")
        if not matches:
            return None
        value = matches[0]
        _require(type(value.get("expired")) is bool, "artifact expiry metadata is missing")
        if value["expired"] and redundant:
            return None
        _require(value["expired"] is False, "required immutable artifact expired; do not rebuild or replace its operation")
        _require(isinstance(value.get("digest"), str) and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"])), "artifact lacks a service SHA-256 digest")
        _integer(value.get("size_in_bytes"), "artifact size", MAX_HANDOFF)
        workflow = value.get("workflow_run")
        _require(isinstance(workflow, dict) and type(workflow.get("id")) is int and workflow["id"] == int(run_id) and str(workflow.get("repository_id")) == self.context.repository["id"] and str(workflow.get("head_repository_id")) == self.context.repository["id"] and isinstance(workflow.get("head_sha"), str) and bool(SHA.fullmatch(workflow["head_sha"])), "artifact belongs to another workflow or repository")
        _date(value.get("created_at"))
        return value

    def download(self, artifact: Mapping[str, Any], destination: Path, *, handoff: bool = False) -> Path:
        limit = MAX_HANDOFF if handoff else MAX_EVIDENCE
        _require(0 < artifact["size_in_bytes"] <= limit, "artifact exceeds the supported package size")
        destination = _new_directory(destination)
        with tempfile.TemporaryDirectory(prefix=".mrk-zip-", dir=destination.parent) as temporary:
            archive = Path(temporary) / "payload.zip"
            self.transport.run(["gh", "api", "--hostname", "github.com", "--method", "GET", self._path(f"actions/artifacts/{artifact['id']}/zip")], output=archive, maximum=limit, timeout=900 if handoff else 120)
            _require(archive.stat().st_size == artifact["size_in_bytes"] and "sha256:" + sha256_file(archive) == artifact["digest"], "downloaded artifact differs from its immutable service receipt")
            _extract_zip(archive, destination, limit)
        return destination

    def verify_attestation(self, path: Path, proof: Mapping[str, Any], job: Mapping[str, Any]) -> None:
        authority = proof["producer"]
        repo = self.context.repository["fullName"]
        reusable = f"{authority['reusableRepository']}/{authority['reusablePath']}"
        result = self.transport.run(["gh", "attestation", "verify", str(path), "--hostname", "github.com", "--repo", repo, "--signer-workflow", reusable, "--signer-digest", authority["reusableCommit"], "--source-digest", authority["headSha"], "--source-ref", authority["ref"], "--deny-self-hosted-runners", "--predicate-type", "https://slsa.dev/provenance/v1", "--format", "json", "--limit", "100"])
        try:
            values = json.loads(result, object_pairs_hook=_reject_duplicate_pairs)
        except (ValueError, UnicodeError, RecursionError):
            raise WorkflowError("attestation verifier returned malformed JSON") from None
        _require(isinstance(values, list) and 1 <= len(values) <= 100, "attestation verifier returned no bounded verified result")
        # More than one attestation may legitimately exist after a retry. At
        # least one complete certified identity must match; never combine fields
        # from different attestations or accept a bare predicate/checksum.
        for value in values:
            try:
                self._verified_attestation(value, path, proof, job)
                return
            except (ValidationError, KeyError, TypeError, AttributeError):
                continue
        raise WorkflowError("no verified attestation binds the exact subject, repository, reusable workflow, producer attempt, and hosted job interval")

    def _verified_attestation(self, value: Any, path: Path, proof: Mapping[str, Any], job: Mapping[str, Any]) -> None:
        result = value["verificationResult"]
        _require(result["mediaType"] == "application/vnd.dev.sigstore.verificationresult+json;version=0.1", "unsupported verifier result version")
        certificate = result["signature"]["certificate"]
        authority = proof["producer"]
        repository = GITHUB + proof["repository"]["fullName"]
        signer = GITHUB + authority["reusableRepository"] + "/" + authority["reusablePath"] + "@" + authority["reusableCommit"]
        invocation = repository + f"/actions/runs/{authority['runId']}/attempts/{authority['attempt']}"
        expected = {"issuer": "https://token.actions.githubusercontent.com", "subjectAlternativeName": signer, "buildSignerURI": signer, "buildSignerDigest": authority["reusableCommit"], "runnerEnvironment": "github-hosted", "sourceRepositoryURI": repository, "sourceRepositoryIdentifier": proof["repository"]["id"], "sourceRepositoryDigest": authority["headSha"], "sourceRepositoryRef": authority["ref"], "buildConfigURI": repository + "/" + authority["callerPath"] + "@" + authority["ref"], "buildConfigDigest": authority["headSha"], "buildTrigger": "workflow_dispatch", "runInvocationURI": invocation}
        _require(all(certificate.get(key) == value for key, value in expected.items()), "certified workflow identity differs")
        statement = result["statement"]
        _require(statement["_type"] == "https://in-toto.io/Statement/v1" and statement["predicateType"] == "https://slsa.dev/provenance/v1", "unsupported attestation statement")
        subjects = statement["subject"]
        _require(isinstance(subjects, list) and 1 <= len(subjects) <= 1024, "attestation subjects are invalid")
        matching = [subject for subject in subjects if isinstance(subject, dict) and subject.get("name") == path.name and subject.get("digest") == {"sha256": sha256_file(path)}]
        _require(len(matching) == 1, "attestation subject differs")
        definition = statement["predicate"]["buildDefinition"]
        _require(definition["buildType"] == "https://actions.github.io/buildtypes/workflow/v1", "unsupported GitHub provenance build type")
        _require(definition["externalParameters"]["workflow"] == {"ref": authority["ref"], "repository": repository, "path": authority["callerPath"]}, "predicate caller/source differs")
        internal = definition["internalParameters"]["github"]
        _require(internal["event_name"] == "workflow_dispatch" and internal["repository_id"] == proof["repository"]["id"] and internal["runner_environment"] == "github-hosted", "predicate internal identity differs")
        _require(definition["resolvedDependencies"] == [{"uri": "git+" + repository + "@" + authority["ref"], "digest": {"gitCommit": authority["headSha"]}}], "predicate dispatch dependency differs")
        details = statement["predicate"]["runDetails"]
        _require(details["builder"]["id"] == signer and details["metadata"]["invocationId"] == invocation, "predicate reusable builder or invocation differs")
        timestamps = result["verifiedTimestamps"]
        _require(isinstance(timestamps, list) and 1 <= len(timestamps) <= 16, "attestation lacks trusted timestamps")
        start = _date(job["started_at"])
        end = _date(job["completed_at"]) if job.get("completed_at") else datetime.now(timezone.utc)
        earliest = max(start, _date(proof["createdAt"]))
        _require(any(earliest <= _date(item["timestamp"]) <= end for item in timestamps), "attestation was witnessed outside its producer job or before its subject existed")


def _zip_entry_offset(header: tuple[Any, ...], extra: bytes) -> int:
    """Read only the ZIP64 fields needed to establish a single-disk offset."""
    offset, disk = header[16], header[13]
    if offset != 0xFFFFFFFF and disk != 0xFFFF:
        _require(disk == 0, "artifact ZIP must be single-disk")
        return offset
    position = 0
    zip64 = None
    while position < len(extra):
        _require(position + 4 <= len(extra), "artifact ZIP extra field is truncated")
        kind, length = struct.unpack_from("<HH", extra, position)
        position += 4
        _require(position + length <= len(extra), "artifact ZIP extra field exceeds its record")
        if kind == 1:
            _require(zip64 is None, "artifact ZIP has duplicate ZIP64 fields")
            zip64 = extra[position:position + length]
        position += length
    _require(zip64 is not None, "artifact ZIP is missing its ZIP64 offset")
    assert zip64 is not None
    position = 8 * ((header[9] == 0xFFFFFFFF) + (header[8] == 0xFFFFFFFF))
    if offset == 0xFFFFFFFF:
        _require(position + 8 <= len(zip64), "artifact ZIP64 offset is truncated")
        offset = struct.unpack_from("<Q", zip64, position)[0]
        position += 8
    if disk == 0xFFFF:
        _require(position + 4 <= len(zip64), "artifact ZIP64 disk is truncated")
        disk = struct.unpack_from("<I", zip64, position)[0]
    _require(disk == 0, "artifact ZIP must be single-disk")
    return offset


def _validate_zip_directory(archive: Path) -> int:
    """Bound the directory *before* stdlib's unbounded ZipInfo allocation.

    This is an allocation/layout gate, not a substitute for ZipFile's member
    validation, CRCs, complete inventory or authenticated evidence. GitHub
    service ZIP profile supports one disk, no prefix/trailer, and standard
    56-byte ZIP64 end records. Payload bytes (including sparse >4GiB handoffs)
    are never read here.
    """
    with archive.open("rb") as source:
        size = os.fstat(source.fileno()).st_size
        _require(size >= 22, "artifact ZIP end record is missing")
        tail_size = min(size, 22 + 65535)
        source.seek(size - tail_size)
        tail = source.read(tail_size)
        # Match the exact EOCD selection used by ZipFile. A signature embedded
        # after the real EOCD must not let the two parsers disagree.
        # Match ZipFile's ordinary no-comment fast path. The offset/size fields
        # of a valid EOCD can themselves contain its signature byte sequence.
        end_index = (
            len(tail) - 22
            if len(tail) >= 22 and tail[-22:-18] == b"PK\x05\x06" and tail[-2:] == b"\0\0"
            else tail.rfind(b"PK\x05\x06")
        )
        _require(end_index >= 0 and end_index + 22 <= len(tail), "artifact ZIP end record is truncated")
        end = struct.unpack_from("<4s4H2IH", tail, end_index)
        _require(end_index + 22 + end[7] == len(tail), "artifact ZIP has trailing or ambiguous end data")
        end_offset = size - tail_size + end_index
        _require(end[1] == end[2] == 0 and end[3] == end[4], "artifact ZIP must be single-disk with consistent counts")
        count, directory_size, directory_offset = end[4:7]
        directory_end = end_offset
        source.seek(max(0, end_offset - 20))
        locator = source.read(20)
        if len(locator) == 20 and locator[:4] == b"PK\x06\x07":
            _, disk, zip64_offset, disks = struct.unpack("<4sIQI", locator)
            _require(disk == 0 and disks == 1 and zip64_offset + 56 == end_offset - 20, "artifact ZIP64 locator has an unsupported extent or disk")
            source.seek(zip64_offset)
            prefix = source.read(12)
            _require(len(prefix) == 12 and prefix[:4] == b"PK\x06\x06", "artifact ZIP64 end record is missing")
            # This toolkit's bounded service profile deliberately excludes
            # extended records, even where ZipFile can support them. Never
            # allocate/read an extension from its untrusted 64-bit length.
            _require(struct.unpack_from("<Q", prefix, 4)[0] == 44, "artifact ZIP64 extended end records are unsupported")
            body = source.read(44)
            _require(len(body) == 44, "artifact ZIP64 end record is truncated")
            large = struct.unpack("<2H2I4Q", body)
            _require(large[2] == large[3] == 0 and large[4] == large[5], "artifact ZIP64 must be single-disk with consistent counts")
            for declared, actual, sentinel in zip((count, directory_size, directory_offset), large[5:8], (0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF)):
                _require(declared == sentinel or declared == actual, "artifact ZIP and ZIP64 directory records disagree")
            count, directory_size, directory_offset = large[5:8]
            directory_end = zip64_offset
        else:
            _require(count != 0xFFFF and directory_size != 0xFFFFFFFF and directory_offset != 0xFFFFFFFF, "artifact ZIP64 locator is missing")
        _require(0 < count <= MAX_FILES, "artifact ZIP member count is invalid")
        _require(46 * count <= directory_size <= MAX_ZIP_DIRECTORY, "artifact ZIP central directory exceeds its bounded size")
        _require(0 < directory_offset < directory_end and directory_offset + directory_size == directory_end, "artifact ZIP central directory extent is invalid")
        source.seek(0)
        _require(source.read(4) == b"PK\x03\x04", "artifact ZIP prefixes are unsupported")
        position, actual_count, first_local = directory_offset, 0, directory_offset
        while position < directory_end:
            _require(actual_count < MAX_FILES and position + 46 <= directory_end, "artifact ZIP central directory has excess or truncated entries")
            source.seek(position)
            fixed = source.read(46)
            _require(len(fixed) == 46 and fixed[:4] == b"PK\x01\x02", "artifact ZIP central directory record is invalid")
            header = struct.unpack("<4s6H3I5H2I", fixed)
            name_size, extra_size, comment_size = header[10:13]
            _require(0 < name_size <= MAX_ZIP_NAME_BYTES, "artifact ZIP filename exceeds its bounded size")
            following = position + 46 + name_size + extra_size + comment_size
            _require(following <= directory_end, "artifact ZIP central directory record exceeds its extent")
            source.seek(position + 46 + name_size)
            extra = source.read(extra_size)
            _require(len(extra) == extra_size, "artifact ZIP central directory extra field is truncated")
            local_offset = _zip_entry_offset(header, extra)
            _require(0 <= local_offset < directory_offset, "artifact ZIP local header offset is outside the payload")
            first_local = min(first_local, local_offset)
            actual_count += 1
            position = following
        _require(actual_count == count and first_local == 0, "artifact ZIP directory count or first header disagrees")
        return count


def _extract_zip(archive: Path, destination: Path, maximum: int) -> None:
    try:
        count = _validate_zip_directory(archive)
        with zipfile.ZipFile(archive) as stream:
            members = stream.infolist()
            _require(len(members) == count, "artifact ZIP member count differs from its bounded directory")
            seen: set[str] = set()
            spellings: dict[str, str] = {}
            regular: set[str] = set()
            total = 0
            deadline = time.monotonic() + (900 if maximum > MAX_EVIDENCE else 120)
            for member in members:
                name = member.filename
                clean = name[:-1] if member.is_dir() else name
                path = PurePosixPath(clean)
                _require(member.orig_filename == name and bool(clean) and len(clean) <= 512 and not path.is_absolute() and str(path) == clean and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", part) and part not in {".", ".."} for part in path.parts), "artifact ZIP contains an unsafe path")
                _require(clean.casefold() not in seen and not member.flag_bits & 1, "artifact ZIP contains duplicate/colliding or encrypted members")
                seen.add(clean.casefold())
                for index in range(1, len(path.parts) + 1):
                    prefix = "/".join(path.parts[:index])
                    previous = spellings.setdefault(prefix.casefold(), prefix)
                    _require(previous == prefix, "artifact ZIP has case-colliding directory components")
                if not member.is_dir():
                    regular.add(clean.casefold())
                mode = member.external_attr >> 16
                _require(stat.S_IFMT(mode) in {0, stat.S_IFREG, stat.S_IFDIR} and (not stat.S_ISDIR(mode) or member.is_dir()), "artifact ZIP contains a symbolic link or special file")
                _require(member.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}, "artifact ZIP compression method is unsupported")
                total += member.file_size
                _require(0 <= member.file_size <= MAX_FILE and total <= maximum, "artifact ZIP exceeds the expanded size limit")
            _require(all(not any(str(parent).casefold() in regular for parent in PurePosixPath(path).parents) for path in seen), "artifact ZIP uses a regular file as a directory")
            for member in members:
                path = _safe_path(destination / member.filename)
                if member.is_dir():
                    path.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with stream.open(member) as source, path.open("xb") as target:
                    os.chmod(path, 0o600)
                    copied = 0
                    while block := source.read(1024 * 1024):
                        _require(time.monotonic() < deadline, "artifact ZIP extraction exceeded its bounded time limit")
                        copied += len(block)
                        _require(copied <= member.file_size, "artifact ZIP member expands past its declared size")
                        target.write(block)
                    _require(copied == member.file_size, "artifact ZIP member is truncated")
    except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError, EOFError, UnicodeError, struct.error):
        raise WorkflowError("artifact ZIP could not be safely extracted") from None


class Verifier:
    def __init__(self, github: GitHub, *, allow_current: bool = False):
        self.github = github
        self.context = github.context
        self.allow_current = allow_current
        self._standalone: dict[tuple[str, str], dict[str, str] | None] = {}

    def proof(self, root: Path, stage: str, phase: str, *, artifact: Mapping[str, Any] | None = None) -> dict[str, Any]:
        name = "intent-provenance.json" if phase == "intent" else "workflow-provenance.json"
        proof = _read_json(root / name)
        _keys(proof, {"documentType", "schemaVersion", "phase", "stage", "platform", "artifactName", "repository", "producer", "jobKey", "jobId", "createdAt", "files"}, "workflow provenance")
        _require(proof["documentType"] == PROOF_TYPE and type(proof["schemaVersion"]) is int and proof["schemaVersion"] == PROOF_VERSION and proof["phase"] == phase and proof["stage"] == stage and proof["platform"] == self.context.platform and proof["repository"] == self.context.repository, "workflow provenance scope differs")
        authority = _authority_for_stage(proof["producer"], stage, "sidecar producer")
        _require(authority["reusableRepository"] == self.context.authority["reusableRepository"] and authority["reusableCommit"] == self.context.authority["reusableCommit"], "evidence was produced by different pinned release tooling")
        expected_artifact = artifact_name(stage, self.context.platform, "intent" if phase == "intent" else "evidence")
        _require(proof["artifactName"] == expected_artifact and proof["jobKey"] == job_key(stage, self.context.platform), "sidecar names a different artifact or protected job")
        _number(proof["jobId"], "producer job ID")
        job = self.github.job(authority, stage, proof["jobKey"], proof["jobId"], allow_current=self.allow_current)
        started, ended = _date(job["started_at"]), _date(job["completed_at"]) if job.get("completed_at") else datetime.now(timezone.utc)
        _require(started <= _date(proof["createdAt"]) <= ended, "sidecar timestamp is outside its producer job")
        if artifact is not None:
            _require(artifact["name"] == expected_artifact and artifact["workflow_run"]["id"] == int(authority["runId"]) and artifact["workflow_run"]["head_sha"] == authority["headSha"], "artifact service identity differs from its sidecar producer")
            _require(_date(proof["createdAt"]) <= _date(artifact["created_at"]) <= ended and started <= _date(artifact["created_at"]), "artifact was created outside its authenticated producer job interval")
        self.github.verify_attestation(root / name, proof, job)
        _inventory_shape(proof["files"], roles=True)
        expected = _layout(stage, phase)
        found = _files(root)
        _require(set(found) == set(expected), "evidence bundle has an incomplete or unexpected layout")
        inventory = [{"path": path, "role": expected[path], "size": found[path].stat().st_size, "sha256": sha256_file(found[path])} for path in sorted(found) if path != name]
        _require(proof["files"] == inventory, "signed complete evidence inventory differs from package contents")
        # Include directories in the check; an ignored extra directory is not a
        # permissible covert payload or extraction target.
        _inventory(root, expected)
        return proof

    def intent(self, root: Path, stage: str, *, artifact: Mapping[str, Any] | None = None) -> dict[str, Any]:
        proof = self.proof(root, stage, "intent", artifact=artifact)
        intent = load_operation_intent(root / f"{stage}-operation-intent.json")
        _require(intent["stage"] == stage and intent["platform"] == self.context.platform and intent["repository"] == self.context.repository and intent["authorizedBy"] == proof["producer"], "intent differs from its authenticated preparation job")
        _require(intent["tooling"]["commit"] == self.context.authority["reusableCommit"], "intent tooling differs from the selected trusted toolkit")
        for source in (intent["candidateSource"], intent["operationSource"]):
            _require(self.github.tree(source["commit"]) == source["tree"], "intent application commit/tree identity differs")
        self.github.source_policy(stage, intent["candidateSource"], intent["operationSource"])
        if stage == "candidate":
            _metadata_binding(root / "store-metadata.zip", intent)
        if stage != "candidate":
            self.final(root / "candidate", "candidate")
        if stage == "production-submit":
            self.final(root / "external", "external-testing")
            _require(_tree_digests(root / "candidate") == _tree_digests(root / "external" / "operation" / "candidate"), "production and external operation retain different candidate packages")
        self._chain(root, stage, own_intent=intent)
        if artifact is None:
            key = (stage, intent["authorizedBy"]["runId"])
            if key not in self._standalone:
                standalone = self.github.artifact(key[1], artifact_name(stage, self.context.platform, "intent"), redundant=True)
                self._standalone[key] = None
                if standalone is not None:
                    with tempfile.TemporaryDirectory(prefix="mrk-original-intent-") as temporary:
                        original = self.github.download(standalone, Path(temporary) / "operation")
                        self.intent(original, stage, artifact=standalone)
                        self._standalone[key] = _tree_digests(original)
            if self._standalone[key] is not None:
                _require(self._standalone[key] == _tree_digests(root), "standalone and embedded original intent bundles conflict")
        return intent

    def _chain(self, root: Path, stage: str, *, own_intent: Mapping[str, Any], own_final: Path | None = None) -> None:
        if stage == "candidate" and own_final is None:
            return
        candidate_root = own_final if stage == "candidate" else root / "candidate"
        assert candidate_root is not None
        arguments: dict[str, Any] = {"candidate_manifest": load_candidate_manifest(candidate_root / "candidate-manifest.json"), "candidate_receipt": load_release_receipt(candidate_root / "candidate-receipt.json"), "candidate_intent": own_intent if stage == "candidate" else load_operation_intent(candidate_root / "operation" / "candidate-operation-intent.json"), "platform": self.context.platform}
        if stage == "production-submit":
            external = root / "external"
            arguments.update(external_receipt=load_release_receipt(external / "external-testing-receipt.json"), external_intent=load_operation_intent(external / "operation" / "external-testing-operation-intent.json"), require_production_eligible_external=True)
        if own_final is not None and stage != "candidate":
            arguments["external_receipt" if stage == "external-testing" else "production_receipt"] = load_release_receipt(own_final / f"{stage}-receipt.json")
            arguments["external_intent" if stage == "external-testing" else "production_intent"] = own_intent
        validate_receipt_chain(**arguments)
        if stage != "candidate":
            candidate = arguments["candidate_manifest"]
            _require(all(own_intent[key] == candidate[key] for key in ("repository", "configuration", "version", "artifacts", "signing", "tooling")) and own_intent["candidateSource"] == candidate["source"], "operation replaced immutable candidate context")
            identity = candidate["platforms"][self.context.platform]
            expected_identity = {"id": identity["applicationId"]}
            if self.context.platform == "ios":
                expected_identity["storeAppId"] = identity["storeAppId"]
            _require(own_intent["application"] == expected_identity, "operation replaced the candidate application identity")
            predecessor = arguments["candidate_receipt"] if stage == "external-testing" else arguments["external_receipt"]
            hashes = own_intent["predecessors"]
            _require(hashes["candidateManifestSha256"] == candidate["integrity"]["sha256"] and hashes["candidateReceiptSha256"] == arguments["candidate_receipt"]["integrity"]["sha256"], "operation replaced its original candidate evidence")
            if stage == "production-submit":
                _require(hashes["externalReceiptSha256"] == predecessor["integrity"]["sha256"], "operation replaced its original external predecessor")

    def final(self, root: Path, stage: str, *, artifact: Mapping[str, Any] | None = None) -> dict[str, Any]:
        proof = self.proof(root, stage, "final", artifact=artifact)
        intent = self.intent(root / "operation", stage)
        receipt = load_release_receipt(root / f"{stage}-receipt.json")
        _require(receipt["producedBy"] == proof["producer"], "final receipt is attributed to a different producer job")
        candidate_root = root if stage == "candidate" else root / "operation" / "candidate"
        candidate = load_candidate_manifest(candidate_root / "candidate-manifest.json")
        validate_receipt_raw_binding(receipt, store_receipt=load_store_receipt(root / "store-receipt.json"), operation_intent=intent, candidate_manifest=candidate)
        self._chain(root / "operation", stage, own_intent=intent, own_final=root)
        return intent


def _tree_digests(root: Path) -> dict[str, str]:
    return {name: sha256_file(path) for name, path in _files(root).items()}


def _create_proof(root: Path, context: Context, phase: str, github: GitHub) -> None:
    key = job_key(context.stage, context.platform)
    _require(context.current_job == key, "only the fixed protected Store job may seal workflow evidence")
    job = github.job(context.authority, context.stage, key, constructing=True)
    filename = "intent-provenance.json" if phase == "intent" else "workflow-provenance.json"
    proof = {"documentType": PROOF_TYPE, "schemaVersion": PROOF_VERSION, "phase": phase, "stage": context.stage, "platform": context.platform, "artifactName": artifact_name(context.stage, context.platform, "intent" if phase == "intent" else "evidence"), "repository": dict(context.repository), "producer": dict(context.authority), "jobKey": key, "jobId": str(job["id"]), "createdAt": _now(), "files": _inventory(root, _layout(context.stage, phase), omitted=filename)}
    _write_json(root / filename, proof)


def _validate_handoff(root: Path, platform: str, intent: Mapping[str, Any] | None = None) -> None:
    files = _files(root, maximum=MAX_HANDOFF)
    allowed = HANDOFF_FILES[platform]
    required = {"app-release.aab", "validation-report.json", "SHA256SUMS"} if platform == "android" else {"app.ipa", "archive.zip", "validation-report.json", "SHA256SUMS"}
    _require(required <= set(files) <= set(allowed) | {"SHA256SUMS"}, "candidate handoff layout is incomplete or contains unknown files")
    _require(not any(path.is_dir() for path in root.iterdir()), "candidate handoff must have a flat fixed layout")
    _require(files["SHA256SUMS"].stat().st_size <= 4096, "candidate handoff checksums are oversized")
    try:
        lines = files["SHA256SUMS"].read_text(encoding="ascii").splitlines()
    except UnicodeError:
        raise WorkflowError("candidate handoff checksums are malformed") from None
    checksums: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        _require(match is not None and match[2] not in checksums, "candidate handoff checksums are malformed or duplicated")
        assert match is not None
        checksums[match[2]] = match[1]
    _require(set(checksums) == set(files) - {"SHA256SUMS"}, "candidate handoff checksum set is incomplete")
    _require(all(sha256_file(files[name]) == digest for name, digest in checksums.items()), "candidate handoff bytes differ from their checksums")
    if intent is not None:
        records = {item["logicalName"]: item for item in intent["artifacts"] if item["logicalName"] != "store-metadata"}
        _require(set(records) == {allowed[name] for name in checksums}, "candidate handoff artifact set differs from the original intent")
        for name in checksums:
            record = records[allowed[name]]
            _require(record["fileName"] == name and record["sha256"] == checksums[name] and record["size"] == files[name].stat().st_size, "candidate handoff replaced an intent-authorized artifact")


def _metadata_binding(path: Path, intent: Mapping[str, Any]) -> None:
    path = _safe_path(path)
    records = [item for item in intent["artifacts"] if item["logicalName"] == "store-metadata"]
    _require(len(records) == 1 and path.is_file(), "candidate-bound metadata archive is missing")
    record = records[0]
    _require(record["fileName"] == "store-metadata.zip" and path.stat().st_size == record["size"] and sha256_file(path) == record["sha256"] == intent["configuration"]["metadataSha256"], "retained Store metadata differs from the exact original candidate bytes")


class Resolver:
    def __init__(self, context: Context, github: GitHub | None = None):
        self.context = context
        self.github = github or GitHub(context)
        self.verifier = Verifier(self.github)

    def _artifact(self, run_id: str, kind: str, *, stage: str | None = None, redundant: bool = False) -> dict[str, Any] | None:
        return self.github.artifact(run_id, artifact_name(stage or self.context.stage, self.context.platform, kind), redundant=redundant)

    def _load_final(self, artifact: Mapping[str, Any], path: Path, stage: str) -> dict[str, Any]:
        self.github.download(artifact, path)
        return self.verifier.final(path, stage, artifact=artifact)

    def _recovery_scope(self, intent: Mapping[str, Any]) -> None:
        current, authorized = self.context.authority, intent["authorizedBy"]
        for key in ("workflow", "callerPath", "reusableRepository", "reusablePath", "reusableCommit", "event", "ref"):
            _require(current[key] == authorized[key], "recovery dispatch changed the original operation's workflow authority")

    def _recovery_context(self, intent: Mapping[str, Any], recovery_run_id: str | None) -> None:
        self._recovery_scope(intent)
        current, authorized = self.context.authority, intent["authorizedBy"]
        if authorized["runId"] == current["runId"]:
            _require(recovery_run_id is None and current["headSha"] == authorized["headSha"] and current["attempt"] >= authorized["attempt"], "same-run recovery changed its immutable dispatch")
        else:
            _require(recovery_run_id == authorized["runId"], "cross-run recovery requires the exact original authorization run")

    def _complete_context(self, root: Path, intent: Mapping[str, Any], recovery_run_id: str | None) -> None:
        """Only authenticated complete finals can refer to a recovery producer.

        A may authorize an operation that B finishes. C selecting B must reuse
        B's exact final, not require B to have issued a replacement intent. This
        is not an alias for incomplete B and does not search for other runs.
        The verifier already bound this receipt to its sidecar, service artifact
        and actual producer job/attempt; retain that identity rather than reissue.
        """
        self._recovery_scope(intent)
        current = self.context.authority
        producer = load_release_receipt(root / f"{self.context.stage}-receipt.json")["producedBy"]
        if producer["runId"] == current["runId"]:
            self._recovery_context(intent, recovery_run_id)
            _require(current["headSha"] == producer["headSha"] and current["attempt"] >= producer["attempt"], "same-run final reuse changed or predates its actual producer dispatch")
        else:
            _require(recovery_run_id == producer["runId"] and current["runId"] != intent["authorizedBy"]["runId"], "complete recovery requires the explicitly selected final producer run")

    def _confirmation(self) -> str:
        context = self.context
        selection = context.selected_platform
        _require(selection == context.platform or (selection == "both" and context.stage != "production-submit"), "resolver platform selection differs from the selected release path")
        prefix = f"{context.stage}:{selection}:"
        value = context.confirmation
        _require(isinstance(value, str) and value.startswith(prefix), "release confirmation must exactly name the stage and selected platform")
        suffix = value[len(prefix):]
        _require(bool(re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?:[1-9][0-9]{0,9}", suffix)) and len(suffix.split(":")[0]) <= 64 and int(suffix.split(":")[1]) <= 2_100_000_000, "release confirmation must contain the exact version and build without extra text")
        return f"{context.stage}:{context.platform}:{suffix}"

    def _hints(self, operation: Path, stage: str, candidate_run_id: str | None, external_run_id: str | None) -> None:
        if candidate_run_id:
            _require(stage != "candidate", "candidate creation cannot select another candidate")
            candidate = load_candidate_manifest(operation / "candidate" / "candidate-manifest.json")
            _require(candidate["producedBy"]["runId"] == candidate_run_id, "candidate selector conflicts with the original retained predecessor")
        if external_run_id:
            _require(stage == "production-submit", "only production consumes external evidence")
            external = load_release_receipt(operation / "external" / "external-testing-receipt.json")
            _require(external["producedBy"]["runId"] == external_run_id, "external selector conflicts with the original retained predecessor")

    def resolve(self, destination: Path, *, recovery_run_id: str | None = None, handoff_digest: str | None = None, candidate_run_id: str | None = None, external_run_id: str | None = None) -> dict[str, Any]:
        for value in (recovery_run_id, candidate_run_id, external_run_id):
            if value is not None:
                _number(value, "workflow run selector")
        context, github = self.context, self.github
        current_id = context.authority["runId"]
        _require(context.stage != "candidate" or candidate_run_id is None, "candidate creation cannot select another candidate")
        _require(context.stage == "production-submit" or external_run_id is None, "only production consumes external evidence")
        _require(recovery_run_id != current_id, "recovery_run_id must name a different original run; omit it for a same-run retry")
        if handoff_digest is not None:
            _require(context.stage == "candidate", "only candidate creation consumes a build handoff")
            _require(bool(DIGEST.fullmatch(handoff_digest)), "trusted build handoff digest must be plain SHA-256")
        confirmation = self._confirmation()
        github.attempt(context.authority, context.stage)
        source = {"commit": context.authority["headSha"], "tree": github.tree(context.authority["headSha"]), "ref": context.authority["ref"]}
        destination = _new_directory(destination)
        with tempfile.TemporaryDirectory(prefix=".mrk-download-", dir=destination.parent) as temporary:
            work = Path(temporary)
            current_final = self._artifact(current_id, "evidence")
            original_final = self._artifact(recovery_run_id, "evidence") if recovery_run_id else None
            if current_final or original_final:
                _require(not (current_final and original_final), "current and original runs both contain final evidence; immutable recovery must not issue a second final")
                final = current_final or original_final
                assert final is not None
                intent = self._load_final(final, work / "final", context.stage)
                self._complete_context(work / "final", intent, recovery_run_id)
                _require(confirmation == intent["confirmation"], "release confirmation differs from the authenticated original intent")
                self._hints(work / "final" / "operation", context.stage, candidate_run_id, external_run_id)
                if original_final:
                    conflicting = self._artifact(current_id, "intent", redundant=True)
                    _require(conflicting is None, "recovery run prepared a conflicting replacement intent")
                return self._finish(destination, "complete", intent["operationSource"], intent["authorizedBy"]["runId"], str(final["workflow_run"]["id"]), str(final["id"]))

            original_id = recovery_run_id or current_id
            intent_artifact = self._artifact(original_id, "intent")
            if recovery_run_id:
                _require(self._artifact(current_id, "intent", redundant=True) is None, "recovery run must not create a replacement intent")
            if intent_artifact:
                operation = github.download(intent_artifact, work / "operation")
                intent = self.verifier.intent(operation, context.stage, artifact=intent_artifact)
                self._recovery_context(intent, recovery_run_id)
                _require(confirmation == intent["confirmation"], "release confirmation differs from the authenticated original intent")
                self._hints(operation, context.stage, candidate_run_id, external_run_id)
                _copy_tree(operation, destination / "operation")
                if context.stage == "candidate":
                    handoff = self._artifact(intent["authorizedBy"]["runId"], "handoff")
                    _require(handoff is not None, "original candidate handoff is missing; do not rebuild an authorized candidate")
                    assert handoff is not None
                    _require(handoff["workflow_run"]["head_sha"] == intent["operationSource"]["commit"], "candidate handoff source differs from the authorized candidate")
                    binary_root = github.download(handoff, work / "handoff", handoff=True)
                    _validate_handoff(binary_root, context.platform, intent)
                    proof = _read_json(operation / "intent-provenance.json")
                    job = github.job(proof["producer"], context.stage, proof["jobKey"], proof["jobId"])
                    primary = "app-release.aab" if context.platform == "android" else "app.ipa"
                    github.verify_attestation(binary_root / primary, proof, job)
                    _copy_tree(binary_root, destination / "artifacts" / context.platform)
                self._expose_inputs(destination, context.stage)
                return self._finish(destination, "resume", intent["operationSource"], intent["authorizedBy"]["runId"])

            _require(recovery_run_id is None, "original authenticated operation intent is missing; recovery must not prepare or rebuild a replacement")
            if context.stage == "candidate":
                handoff = self._artifact(current_id, "handoff")
                if handoff:
                    _require(handoff_digest is not None and context.current_job == job_key(context.stage, context.platform), "handoff without authenticated intent requires re-run-failed Store job and its preserved trusted build digest; rerun-all must not rebuild")
                    _require(handoff["digest"] == "sha256:" + handoff_digest and handoff["workflow_run"]["head_sha"] == context.authority["headSha"], "handoff differs from the trusted same-run build output")
                    self._prove_no_prior_execution()
                    self._build_handoff_job(handoff)
                    binary_root = github.download(handoff, work / "handoff", handoff=True)
                    _validate_handoff(binary_root, context.platform)
                    _copy_tree(binary_root, destination / "artifacts" / context.platform)
                    return self._finish(destination, "prepare", source, current_id)
                _require(context.authority["attempt"] == 1 and handoff_digest is None, "later/partial run lacks durable evidence; absence never authorizes a rebuild")
                _require(context.current_job == f"{context.platform}_resolve", "candidate Store job must consume a verified build handoff")
                return self._finish(destination, "fresh", source, current_id)

            _require(context.authority["attempt"] == 1, "later promotion attempt lacks its durable intent; use a new protected dispatch only after confirming mutation was unreachable")
            _require(candidate_run_id is not None, "promotion preparation requires an explicit candidate evidence run")
            candidate_artifact = self._artifact(candidate_run_id, "evidence", stage="candidate")
            _require(candidate_artifact is not None, "selected candidate final evidence is missing")
            assert candidate_artifact is not None
            self._load_final(candidate_artifact, work / "candidate", "candidate")
            candidate = load_candidate_manifest(work / "candidate" / "candidate-manifest.json")
            _require(confirmation == f"{context.stage}:{context.platform}:{candidate['version']['marketing']}:{candidate['version']['build']}", "release confirmation differs from the authenticated candidate version/build")
            github.source_policy(context.stage, candidate["source"], source)
            if context.stage == "production-submit":
                _require(external_run_id is not None, "production preparation requires an explicit external evidence run")
                external_artifact = self._artifact(external_run_id, "evidence", stage="external-testing")
                _require(external_artifact is not None, "selected external final evidence is missing")
                assert external_artifact is not None
                self._load_final(external_artifact, work / "external", "external-testing")
                _require(_tree_digests(work / "candidate") == _tree_digests(work / "external" / "operation" / "candidate"), "selected external evidence belongs to a different candidate package")
                validate_receipt_chain(
                    candidate_manifest=candidate,
                    candidate_receipt=load_release_receipt(work / "candidate" / "candidate-receipt.json"),
                    candidate_intent=load_operation_intent(work / "candidate" / "operation" / "candidate-operation-intent.json"),
                    external_receipt=load_release_receipt(work / "external" / "external-testing-receipt.json"),
                    external_intent=load_operation_intent(work / "external" / "operation" / "external-testing-operation-intent.json"),
                    platform=context.platform,
                    require_production_eligible_external=True,
                )
                _copy_tree(work / "external", destination / "input" / "external")
            else:
                _require(external_run_id is None, "external promotion cannot consume another external receipt")
            _copy_tree(work / "candidate", destination / "input" / "candidate")
            return self._finish(destination, "prepare", source, current_id)

    def _prove_no_prior_execution(self) -> None:
        """A deleted intent must never look like a safe pre-mutation failure.

        A trusted build digest authenticates bytes, NOT absence of a previous
        Store call. Across every earlier attempt demand positive failed-guard
        evidence and an explicitly skipped unique execute step. No job, missing
        steps, cancellation, or absence of an artifact is such evidence.
        """
        execute_name = "Execute or reconcile the exact authorized Store operation"
        guards = {
            "Prepare immutable Store operation without mutation",
            "Bind durable intent to its actual workflow attempt and job",
            "Attest exact signed candidate before any Store mutation",
            "Attest original Store intent and producer proof",
            "Persist immutable authorization before any Store mutation",
        }
        for attempt in range(1, self.context.authority["attempt"]):
            authority = dict(self.context.authority, attempt=attempt)
            job = self.github.job(authority, "candidate", job_key("candidate", self.context.platform))
            _require(job.get("status") == "completed" and job.get("conclusion") == "failure", "missing intent follows an incomplete or possibly executed Store job; it must not be recreated")
            steps = job.get("steps")
            _require(isinstance(steps, list) and 1 <= len(steps) <= 100 and all(isinstance(step, dict) for step in steps), "prior Store job lacks a complete step graph")
            numbers = [step.get("number") for step in steps]
            _require(all(type(number) is int and number > 0 for number in numbers) and len(set(numbers)) == len(numbers), "prior Store job step identities are ambiguous")
            execute = [step for step in steps if step.get("name") == execute_name]
            _require(len(execute) == 1 and execute[0].get("status") == "completed" and execute[0].get("conclusion") == "skipped", "prior Store execution started or is not explicitly proven skipped; recover the original intent")
            _require(all(step.get("status") == "completed" and step.get("conclusion") in {"success", "failure", "skipped"} for step in steps), "prior Store job was cancelled or has unknown step outcomes")
            failed_guards = [step for step in steps if step.get("name") in guards and step["number"] < execute[0]["number"] and step.get("conclusion") == "failure"]
            _require(len(failed_guards) == 1, "missing intent lacks positive evidence of a failed pre-execution safety gate")

    def _build_handoff_job(self, artifact: Mapping[str, Any]) -> None:
        matches = []
        created = _date(artifact["created_at"])
        for attempt in range(1, self.context.authority["attempt"] + 1):
            authority = dict(self.context.authority, attempt=attempt)
            for job in self.github.jobs(authority, "candidate"):
                if _job_name(job.get("name"), f"{self.context.platform}_build") and job.get("status") == "completed" and job.get("conclusion") == "success":
                    _require(type(job.get("run_id")) is int and job["run_id"] == int(authority["runId"]) and type(job.get("run_attempt")) is int and job["run_attempt"] == attempt and job.get("head_sha") == authority["headSha"], "build handoff job identity is invalid")
                    if _date(job.get("started_at")) <= created <= _date(job.get("completed_at")):
                        matches.append(job)
        _require(len(matches) == 1, "trusted handoff cannot be tied to one successful actual build attempt")

    def _expose_inputs(self, destination: Path, stage: str) -> None:
        if stage != "candidate":
            _copy_tree(destination / "operation" / "candidate", destination / "input" / "candidate")
        if stage == "production-submit":
            _copy_tree(destination / "operation" / "external", destination / "input" / "external")

    def _finish(self, root: Path, mode: str, source: Mapping[str, str], authorization_run_id: str, evidence_run_id: str = "", artifact_id: str = "") -> dict[str, Any]:
        files = _files(root, maximum=MAX_HANDOFF)
        result = {"documentType": "workflow-resolution", "schemaVersion": 1, "stage": self.context.stage, "platform": self.context.platform, "repository": dict(self.context.repository), "dispatch": dict(self.context.authority), "jobKey": self.context.current_job, "mode": mode, "source": dict(source), "authorizationRunId": authorization_run_id, "evidenceRunId": evidence_run_id, "evidenceArtifactId": artifact_id, "files": [{"path": name, "size": path.stat().st_size, "sha256": sha256_file(path)} for name, path in sorted(files.items())]}
        _write_json(root / "resolution.json", seal(result))
        return result


def stage_resolution(resolution: Path, app_root: Path, context: Context) -> None:
    resolution = _safe_path(resolution)
    _require(resolution.is_dir() and resolution.stat().st_uid == os.getuid() and not resolution.stat().st_mode & 0o077, "resolution must be a private runner-owned directory")
    result = verify_sealed(_read_json(resolution / "resolution.json"))
    _keys(result, {"documentType", "schemaVersion", "stage", "platform", "repository", "dispatch", "jobKey", "mode", "source", "authorizationRunId", "evidenceRunId", "evidenceArtifactId", "files"}, "local workflow resolution")
    _require(result["documentType"] == "workflow-resolution" and result["schemaVersion"] == 1 and result["stage"] == context.stage and result["platform"] == context.platform and result["repository"] == context.repository and result["dispatch"] == context.authority and result["jobKey"] == context.current_job, "local resolution belongs to another workflow job")
    _require(result["mode"] in {"fresh", "prepare", "resume"}, "complete final evidence is reference-only and must not stage or execute Store work")
    files = _files(resolution, maximum=MAX_HANDOFF)
    del files["resolution.json"]
    inventory = [{"path": name, "size": path.stat().st_size, "sha256": sha256_file(path)} for name, path in sorted(files.items())]
    _inventory_shape(result["files"], roles=False)
    _require(result["files"] == inventory, "private resolution contents changed after authentication")
    expected: set[str] = set()
    if result["mode"] == "resume":
        expected.update("operation/" + path for path in _layout(context.stage, "intent"))
    if context.stage != "candidate":
        expected.update("input/candidate/" + path for path in _layout("candidate", "final"))
    if context.stage == "production-submit":
        expected.update("input/external/" + path for path in _layout("external-testing", "final"))
    if context.stage == "candidate" and result["mode"] != "fresh":
        prefix = f"artifacts/{context.platform}/"
        expected.update(name for name in files if name.startswith(prefix) and name[len(prefix):] in set(HANDOFF_FILES[context.platform]) | {"SHA256SUMS"})
        _validate_handoff(resolution / "artifacts" / context.platform, context.platform)
    _require(set(files) == expected, "local resolution layout is invalid")
    _verify_checkout(app_root, result["source"])
    output = _safe_path(app_root / ".mobile-release")
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    _require(not any(output.iterdir()), "application workflow output must be empty before staging authenticated inputs")
    for name, path in sorted(files.items()):
        copy_immutable_file(path, output / name)
    (output / "operation").mkdir(mode=0o700, exist_ok=True)


def _verify_checkout(app_root: Path, source: object) -> None:
    source = _keys(source, {"commit", "tree", "ref"}, "resolved operation source")
    _require(all(isinstance(source[field], str) and SHA.fullmatch(source[field]) for field in ("commit", "tree")), "resolved operation source object IDs are invalid")
    app_root = _safe_path(app_root)
    _require(app_root.is_dir() and (app_root / ".git").is_dir() and not (app_root / ".git").is_symlink(), "staging requires the exact application checkout, not a linked worktree or symlink")
    # No application hooks, replace objects, pager, fsmonitor, external diff,
    # optional locks, credential helpers, or inherited GIT_CONFIG/GIT_DIR. This
    # reads two object IDs only and never executes a build or application check.
    env = {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_PAGER": "cat"}
    try:
        result = subprocess.run(["git", "--no-pager", "--no-replace-objects", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull, "-C", str(app_root), "rev-parse", "--verify", "HEAD"], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False)
        tree = subprocess.run(["git", "--no-pager", "--no-replace-objects", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull, "-C", str(app_root), "rev-parse", "--verify", "HEAD^{tree}"], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        raise WorkflowError("application source identity could not be read safely") from None
    _require(result.returncode == 0 and tree.returncode == 0 and result.stdout == (source["commit"] + "\n").encode("ascii") and tree.stdout == (source["tree"] + "\n").encode("ascii"), "checked-out application HEAD/tree differs from the authenticated operation source")


def authenticate_operation_intent(intent_path: Path, *, stage: str, platform: str, github: GitHub | None = None) -> dict[str, Any]:
    """Authenticate pre-mutation authority for time-sensitive recovery decisions.

    A local seal, an environment flag, or a copied proof alone is insufficient.
    The unfinished operation must retain its original service intent artifact;
    complete-final reuse is a separate resolver path that needs no binary or
    current signing eligibility. No Store credentials are forwarded to ``gh``.
    """
    context = github.context if github else Context.current(stage, platform)
    _require(context.stage == stage and context.platform == platform and context.current_job == job_key(stage, platform), "original authorization verification requires the fixed protected Store job")
    github = github or GitHub(context)
    intent_path = _safe_path(intent_path)
    _require(intent_path.name == f"{stage}-operation-intent.json", "authenticated operation intent must use its fixed role-specific filename")
    local = load_operation_intent(intent_path)
    artifact = github.artifact(local["authorizedBy"]["runId"], artifact_name(stage, platform, "intent"))
    _require(artifact is not None, "unfinished Store operation lacks its original durable authenticated intent artifact")
    assert artifact is not None
    with tempfile.TemporaryDirectory(prefix="mrk-authenticated-operation-") as temporary:
        original = github.download(artifact, Path(temporary) / "operation")
        verified = Verifier(github, allow_current=True).intent(original, stage, artifact=artifact)
        _require(_tree_digests(original) == _tree_digests(intent_path.parent), "local intent/predecessors differ from the original authenticated artifact")
        return verified


def seal_intent(app_root: Path, context: Context, github: GitHub | None = None) -> None:
    github = github or GitHub(context)
    output = _safe_path(app_root / ".mobile-release")
    operation = output / "operation"
    intent = load_operation_intent(operation / f"{context.stage}-operation-intent.json")
    _require(intent["authorizedBy"] == context.authority and intent["repository"] == context.repository and intent["stage"] == context.stage and intent["platform"] == context.platform, "new intent is not authorized by this exact protected job")
    verifier = Verifier(github)
    if context.stage != "candidate":
        verifier.final(output / "input" / "candidate", "candidate")
        _copy_tree(output / "input" / "candidate", operation / "candidate")
    if context.stage == "production-submit":
        verifier.final(output / "input" / "external", "external-testing")
        _copy_tree(output / "input" / "external", operation / "external")
        _require(_tree_digests(operation / "candidate") == _tree_digests(operation / "external" / "operation" / "candidate"), "prepared production predecessors disagree")
    verifier._chain(operation, context.stage, own_intent=intent)
    if context.stage == "candidate":
        _validate_handoff(output / "artifacts" / context.platform, context.platform, intent)
        metadata = output / "staging" / "candidate" / context.platform / "store-metadata.zip"
        _metadata_binding(metadata, intent)
        copy_immutable_file(metadata, operation / "store-metadata.zip")
    _require(github.tree(intent["operationSource"]["commit"]) == intent["operationSource"]["tree"], "intent operation source tree differs from GitHub")
    github.source_policy(context.stage, intent["candidateSource"], intent["operationSource"])
    _create_proof(operation, context, "intent", github)


def package_final(app_root: Path, evidence_dir: Path, raw_receipt: Path, destination: Path, context: Context, github: GitHub | None = None) -> None:
    github = github or GitHub(context)
    operation = _safe_path(app_root / ".mobile-release" / "operation")
    verifier = Verifier(github, allow_current=True)
    intent = verifier.intent(operation, context.stage)
    evidence_dir = _safe_path(evidence_dir)
    receipt = load_release_receipt(evidence_dir / f"{context.stage}-receipt.json")
    _require(receipt["producedBy"] == context.authority, "final documents must retain their actual producer; do not reissue an immutable complete final")
    destination = _new_directory(destination)
    _copy_tree(operation, destination / "operation")
    copy_immutable_file(evidence_dir / f"{context.stage}-receipt.json", destination / f"{context.stage}-receipt.json")
    copy_immutable_file(_safe_path(raw_receipt), destination / "store-receipt.json")
    if context.stage == "candidate":
        copy_immutable_file(evidence_dir / "candidate-manifest.json", destination / "candidate-manifest.json")
    candidate_root = destination if context.stage == "candidate" else operation / "candidate"
    validate_receipt_raw_binding(receipt, store_receipt=load_store_receipt(destination / "store-receipt.json"), operation_intent=intent, candidate_manifest=load_candidate_manifest(candidate_root / "candidate-manifest.json"))
    verifier._chain(operation, context.stage, own_intent=intent, own_final=destination)
    _create_proof(destination, context, "final", github)


def _outputs(result: Mapping[str, Any]) -> None:
    values = {"mode": result["mode"], "source_sha": result["source"]["commit"], "source_tree": result["source"]["tree"], "source_ref": result["source"]["ref"], "authorization_run_id": result["authorizationRunId"], "evidence_run_id": result["evidenceRunId"], "evidence_artifact_id": result["evidenceArtifactId"]}
    _require(all(isinstance(value, str) and len(value) <= 512 and not any(ord(char) < 32 for char in value) for value in values.values()), "workflow output contains invalid text")
    print(json.dumps(values, sort_keys=True))
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        path = _safe_path(Path(output))
        _require(path.is_file(), "GITHUB_OUTPUT is not a regular runner file")
        with path.open("a", encoding="utf-8") as handle:
            handle.write("".join(f"{name}={value}\n" for name, value in values.items()))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    resolve = commands.add_parser("resolve", help="authenticate existing immutable evidence before deciding whether work remains")
    stage = commands.add_parser("stage", help="copy a private authenticated resolution into a clean application checkout")
    seal_parser = commands.add_parser("seal-intent", help="create the protected job's complete intent inventory; does not sign or upload")
    final = commands.add_parser("package-final", help="validate and package final evidence; does not sign, upload, or call Stores")
    for command in (resolve, seal_parser, final):
        command.add_argument("--stage", required=True, choices=STAGES)
        command.add_argument("--platform", required=True, choices=PLATFORMS)
    stage.add_argument("--stage", choices=STAGES)
    stage.add_argument("--platform", choices=PLATFORMS)
    resolve.add_argument("--destination", type=Path, required=True)
    for flag in ("recovery-run-id", "handoff-digest", "candidate-run-id", "external-run-id"):
        resolve.add_argument("--" + flag)
    stage.add_argument("--resolution", type=Path, required=True)
    for command in (stage, seal_parser, final):
        command.add_argument("--app-root", type=Path, required=True)
    final.add_argument("--evidence-dir", type=Path, required=True)
    final.add_argument("--raw-receipt", type=Path, required=True)
    final.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "stage":
            result = _read_json(args.resolution / "resolution.json")
            selected_stage = args.stage or result.get("stage")
            selected_platform = args.platform or result.get("platform")
            context = Context.current(selected_stage, selected_platform)
        else:
            context = Context.current(args.stage, args.platform)
        if args.command == "resolve":
            _outputs(Resolver(context).resolve(args.destination, recovery_run_id=args.recovery_run_id, handoff_digest=args.handoff_digest, candidate_run_id=args.candidate_run_id, external_run_id=args.external_run_id))
        elif args.command == "stage":
            stage_resolution(args.resolution, args.app_root, context)
        elif args.command == "seal-intent":
            seal_intent(args.app_root, context)
        else:
            package_final(args.app_root, args.evidence_dir, args.raw_receipt, args.destination, context)
        return 0
    except MobileReleaseError as error:
        # Only our fixed, safely reportable validation strings reach logs. Do
        # not include gh stderr, remote JSON, signed redirects, or traceback.
        message = str(error) if isinstance(error, WorkflowError) else "release evidence failed strict validation; preserve the original operation and its artifacts"
        print(f"mobile-release workflow: {message}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        print("mobile-release workflow: invalid or unavailable workflow evidence; no mutation or fallback was authorized", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("mobile-release workflow: interrupted; preserve original evidence and retry read-only resolution", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
