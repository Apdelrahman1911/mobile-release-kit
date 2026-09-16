from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from contextlib import ExitStack, nullcontext
from pathlib import Path
from typing import Mapping

from .config import ConfigurationError, ReleaseConfig, ReleaseVersion
from .credentials import (
    SelectedStoreMaterial,
    _selected_store_material,
    credential_values_from_environment,
)
from .build_inputs import (
    FiniteScratch, InvocationCustody, _app_private_directory, finite_scratch, invocation_custody,
    store_private_namespace,
)
from .cancellation import CleanupScope, DefaultCancellation
from .checked_files import read_readback_bytes
from .owned_process import ProcessError, preserve_lifetime_error, run_owned
from ._profile_callers import first_primary_context
from ._store_lane_evidence import StoreLaneCallEvidence, StoreLaneEvidenceError
from ._store_lane_files import StoreLaneAttempt, StoreLaneFiles
from .discovery import GitContext, valid_observed_source
from .errors import MutationGuardError, StoreOperationError, ValidationError
from .reporting import FAILING_STATUSES, Finding, Status
from .provenance import (
    _reject_duplicate_pairs,
    load_store_receipt,
    load_operation_intent,
    validate_operation_intent,
    validate_store_precondition,
    validate_store_receipt,
    validate_create_retry_inventory,
    canonical_sha256,
    workflow_authority,
)
from .tooling import _complete_tooling_root, resolve_tooling_root

LANES = {
    ("candidate", "android"): "android_internal_upload",
    ("candidate", "ios"): "ios_testflight_internal",
    ("external-testing", "android"): "android_external_promote",
    ("external-testing", "ios"): "ios_testflight_external",
    ("production-submit", "android"): "android_production_draft",
    ("production-submit", "ios"): "ios_app_store_submit",
}
ENVIRONMENTS = {
    "candidate": "mobile-candidate",
    "external-testing": "mobile-external-testing",
    "production-submit": "mobile-production",
}
STORE_OPERATION_ENVIRONMENT_NAMES = {
    "MOBILE_RELEASE_ANDROID_AAB_PATH",
    "MOBILE_RELEASE_ANDROID_MAPPING_PATH",
    "MOBILE_RELEASE_IOS_IPA_PATH",
    "MOBILE_RELEASE_IOS_ARCHIVE_PATH",
    "MOBILE_RELEASE_IOS_DSYMS_PATH",
}
RUNTIME_ENVIRONMENT_NAMES = {
    "BUNDLE_APP_CONFIG",
    "BUNDLE_DEPLOYMENT",
    "BUNDLE_PATH",
    "BUNDLE_WITHOUT",
    "CI",
    "DEVELOPER_DIR",
    "GEM_HOME",
    "GEM_PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "RUNNER_TEMP",
    "RUNNER_TOOL_CACHE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TMPDIR",
    "TZ",
}


def _runtime_environment(source: Mapping[str, str]) -> dict[str, str]:
    environment = {
        name: source[name] for name in RUNTIME_ENVIRONMENT_NAMES if source.get(name)
    }
    # Explicit bundle locations remain supported, but local/global Bundler
    # settings must not install, switch versions or rewrite the pinned lock.
    environment.update(
        BUNDLER_VERSION="4.0.16",
        BUNDLE_IGNORE_CONFIG="1",
        BUNDLE_AUTO_INSTALL="false",
        BUNDLE_FROZEN="true",
    )
    return environment


def _repository_path(config: ReleaseConfig, value: str | Path, label: str) -> Path:
    """Return a repository-contained path without following any committed symlink."""

    try:
        return config.project_path(os.fspath(value))
    except ConfigurationError as error:
        raise StoreOperationError(
            f"{label} must remain inside the repository without symbolic links"
        ) from error


def _private_app_directory(config: ReleaseConfig, relative: str, *,
                           cancellation: DefaultCancellation) -> Path:
    if relative != ".mobile-release/store":
        raise StoreOperationError("unsupported private Store namespace")
    # Same original checked persistent-namespace owner as Store invocations.
    # Existing unsafe state is refused, never chmodded/adopted or removed.
    _repository_path(config, relative, "tool-owned Store directory")
    with store_private_namespace(config.root, cancellation=cancellation) as owner:
        owner.check()
        return owner.path


def _play_state_journal_path(receipt_path: Path) -> Path:
    """Derive the one journal path shared by Python, Fastlane, and workflows."""

    return receipt_path.with_name(f"{receipt_path.stem}-play-state.json")


@dataclass(frozen=True)
class StoreRequest:
    stage: str
    platform: str
    confirmation: str
    execute: bool
    output_dir: Path
    store_receipt: Path | None = None
    store_precondition: Path | None = None
    prepare: bool = False
    operation_intent: Path | None = None
    recovery_run_id: str | None = None
    recovery_confirmation: str | None = None


def expected_confirmation(stage: str, platform: str, release: ReleaseVersion) -> str:
    return f"{stage}:{platform}:{release.name}:{release.build}"


def guard_ci_mutation(
    *,
    request: StoreRequest,
    config: ReleaseConfig,
    release: ReleaseVersion,
    git: GitContext,
    environ: Mapping[str, str] | None = None,
) -> None:
    env = environ if environ is not None else os.environ
    if request.stage not in ENVIRONMENTS or (request.stage, request.platform) not in LANES:
        raise MutationGuardError("unsupported CI Store operation")
    expected = expected_confirmation(request.stage, request.platform, release)
    if request.confirmation != expected:
        raise MutationGuardError(f"confirmation must exactly equal {expected!r}")
    if env.get("GITHUB_ACTIONS") != "true":
        raise MutationGuardError("Store operations are restricted to GitHub Actions")
    if env.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise MutationGuardError("Store operations require an explicit workflow_dispatch event")
    if env.get("MOBILE_RELEASE_CI_MUTATIONS_ALLOWED") != "true":
        raise MutationGuardError("MOBILE_RELEASE_CI_MUTATIONS_ALLOWED must be explicitly true")
    expected_environment = ENVIRONMENTS[request.stage]
    if env.get("MOBILE_RELEASE_ENVIRONMENT") != expected_environment:
        raise MutationGuardError(f"Store operation requires the {expected_environment} environment")
    if not git.repository or not git.repository_id or not git.commit or not git.tree or not git.ref:
        raise MutationGuardError("immutable GitHub repository/source identity is incomplete")
    if not valid_observed_source(git):
        raise MutationGuardError("Store operation requires an observed full Git commit/tree and provably clean worktree")
    if request.recovery_run_id:
        if not re.fullmatch(r"[1-9][0-9]*", request.recovery_run_id):
            raise MutationGuardError("recovery_run_id must be a positive workflow run ID")
        dispatch_sha = env.get("MOBILE_RELEASE_DISPATCH_SHA") or env.get("GITHUB_SHA")
        if not dispatch_sha or not re.fullmatch(r"[0-9A-Fa-f]{40}", dispatch_sha):
            raise MutationGuardError("recovery requires the immutable dispatch head SHA")
    elif env.get("GITHUB_SHA") != git.commit:
        raise MutationGuardError("GITHUB_SHA does not exactly match the checked-out Git commit")
    expected_branch = config.section("source").get(
        "productionBranch" if request.stage == "production-submit" else "candidateBranch", "main"
    )
    if git.ref != f"refs/heads/{expected_branch}":
        raise MutationGuardError(
            f"actual dispatch ref {git.ref!r} is not the configured {expected_branch!r} branch"
        )
    platform_config = config.section(request.platform)
    if platform_config.get("identityStatus") != "approved":
        raise MutationGuardError("Store identity must be explicitly approved in reviewed configuration")


def _store_environment(
    config: ReleaseConfig,
    release: ReleaseVersion,
    request: StoreRequest,
    receipt_path: Path,
    tooling_root: Path,
    *, material: SelectedStoreMaterial, invocation: InvocationCustody,
    lane_evidence: StoreLaneCallEvidence, source_environment: Mapping[str, str],
    authority: Mapping[str, object],
) -> dict[str, str]:
    material.require_store(config=config, platform=request.platform, invocation=invocation,
                           lane_evidence=lane_evidence)
    env = _runtime_environment(source_environment)
    env.update(material.lane_environment(platform=request.platform))
    for name in STORE_OPERATION_ENVIRONMENT_NAMES:
        if not (raw_path := source_environment.get(name)):
            continue
        artifact = _repository_path(config, raw_path, name)
        if not artifact.is_file():
            raise StoreOperationError(f"{name} must identify a regular release artifact")
        env[name] = str(artifact)
    platform_config = config.section(request.platform)
    identity_key = "applicationId" if request.platform == "android" else "bundleId"
    env.update(
        {
            "MOBILE_RELEASE_OPERATION": LANES[(request.stage, request.platform)],
            "MOBILE_RELEASE_PLATFORM": request.platform,
            "MOBILE_RELEASE_APP_IDENTITY": platform_config[identity_key],
            "MOBILE_RELEASE_MARKETING_VERSION": release.name,
            "MOBILE_RELEASE_BUILD_NUMBER": str(release.build),
            "MOBILE_RELEASE_STORE_RECEIPT_PATH": str(receipt_path),
            "MOBILE_RELEASE_CONFIG_PATH": str(config.path),
            "MOBILE_RELEASE_APP_ROOT": str(config.root),
            "BUNDLE_GEMFILE": str(tooling_root / "Gemfile"),
            "MOBILE_RELEASE_STORE_MODE": "prepare" if request.prepare else "execute",
            # Selected by the pinned installed CLI, never a caller-controlled
            # environment command. Fastlane invokes only the toolkit's isolated
            # current-upload validator through this interpreter.
            "MOBILE_RELEASE_VALIDATION_PYTHON": str(Path(sys.executable).absolute()),
            "MOBILE_RELEASE_VALIDATION_MODULE_ROOT": str(Path(__file__).resolve().parent.parent),
        }
    )
    if request.operation_intent:
        intent_path = _repository_path(config, request.operation_intent, "operation intent path")
        if not request.prepare and not intent_path.is_file():
            raise StoreOperationError("operation intent must be a regular repository file")
        env["MOBILE_RELEASE_OPERATION_INTENT_PATH"] = str(intent_path)
    if request.recovery_run_id:
        env["MOBILE_RELEASE_RECOVERY_RUN_ID"] = request.recovery_run_id
    if request.recovery_confirmation:
        env["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] = request.recovery_confirmation
    env["MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON"] = json.dumps(
        authority, sort_keys=True, separators=(",", ":")
    )
    if request.platform == "android":
        if request.stage == "candidate":
            # Public validation inputs only. Missing/stale tools must block a
            # NEW upload in the isolated helper, not historical reconciliation.
            for name in ("MOBILE_RELEASE_BUNDLETOOL_JAR", "JAVA_HOME"):
                if source_environment.get(name):
                    env[name] = source_environment[name]
        track = {
            "candidate": "internal",
            "external-testing": platform_config.get("externalTrack", {}).get("name", ""),
            "production-submit": "production",
        }[request.stage]
        env["MOBILE_RELEASE_DESTINATION_TRACK"] = track
        journal_path = _play_state_journal_path(receipt_path)
        journal_path = _repository_path(config, journal_path, "Play state journal path")
        env["MOBILE_RELEASE_PLAY_STATE_PATH"] = str(journal_path)
    else:
        journal_path = receipt_path.with_name(f"{receipt_path.stem}-apple-state.json")
        journal_path = _repository_path(config, journal_path, "Apple state journal path")
        env["MOBILE_RELEASE_APPLE_STATE_PATH"] = str(journal_path)
        env["MOBILE_RELEASE_ASC_APP_ID"] = str(platform_config.get("appStoreAppId", ""))
        env["MOBILE_RELEASE_TESTFLIGHT_EXTERNAL_GROUP"] = str(
            platform_config.get("externalTestFlightGroup", "")
        )
        review = platform_config.get("review", {})
        env["MOBILE_RELEASE_APPLE_USES_NON_EXEMPT_ENCRYPTION"] = str(
            review.get("usesNonExemptEncryption", False)
        ).lower()
        env["MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_REQUIRED"] = str(
            review.get("demoAccountRequired", False)
        ).lower()
    return env


def _require_fastlane_bundle(tooling_root: Path, *, cancellation: DefaultCancellation | None = None,
                             source_environment: Mapping[str, str] | None = None) -> None:
    gemfile = tooling_root / "Gemfile"
    source_environment = os.environ if source_environment is None else source_environment
    environment = _runtime_environment(source_environment)
    environment.update(
        {
            "BUNDLE_GEMFILE": str(gemfile),
            "FASTLANE_HIDE_CHANGELOG": "true",
            "FASTLANE_OPT_OUT_USAGE": "true",
            "FASTLANE_SKIP_DOCS": "true",
            "FASTLANE_SKIP_UPDATE_CHECK": "true",
        }
    )
    if shutil.which("ruby", path=environment.get("PATH")) is None:
        raise StoreOperationError(
            "Pinned Store tooling requires Ruby 3.3.12 and Bundler 4.0.16; "
            "dependencies are never installed automatically."
        )

    def run(argv: list[str]) -> subprocess.CompletedProcess[str] | None:
        try:
            return run_owned(
                argv,
                cwd=tooling_root,
                environ=environment,
                capture=True,
                timeout=60,
                cancellation=cancellation,
            )
        except ProcessError as error:
            if error.fatal:
                raise
            return None
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None

    ruby = run(["ruby", "-e", "print RUBY_VERSION"])
    if ruby is None or ruby.returncode or ruby.stdout.strip() != "3.3.12":
        raise StoreOperationError(
            "Pinned Store tooling requires Ruby 3.3.12. Select that exact version before running "
            "online preflight or a Store lane."
        )
    bundler = run(["bundle", "--version"])
    # Pinned Bundler 4's --version prints the bare version; its help command
    # alone adds the human-readable "Bundler version" prefix.
    if (bundler is None or bundler.returncode
            or bundler.stdout.strip() != "4.0.16"):
        raise StoreOperationError(
            "Bundler 4.0.16 is unavailable for the pinned Store tooling. Install it under Ruby 3.3.12; "
            "dependencies are never installed automatically."
        )
    completed = run(["bundle", "check"])
    if completed is None or completed.returncode:
        command = (
            f"BUNDLE_GEMFILE={shlex.quote(str(gemfile))} "
            "bundle install --jobs 4 --retry 3"
        )
        raise StoreOperationError(
            "Pinned Fastlane dependencies from Gemfile.lock are unavailable. "
            f"Run `{command}` with Ruby 3.3.12 and Bundler 4.0.16, then rerun preflight; dependencies are never "
            "installed automatically."
        )
    # The isolated helpers intentionally disable gems; the outer capture runs
    # under the locked bundle. Admit BOTH actual loaded Fiddle origins, rather
    # than treating one version string as proof of the other runtime.
    primitive = str(tooling_root / "fastlane/native_process_spawn.rb")
    marker = "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2"
    probe = (
        "require ARGV.fetch(0); "
        "MobileReleaseKit::NativeProcessSpawn.admit_runtime!; "
        f"STDOUT.write({json.dumps(marker)})"
    )
    commands = (
        [
            "ruby", "--disable=rubyopt,gems,did_you_mean,error_highlight,syntax_suggest,rjit,yjit",
            "--external-encoding=UTF-8", "--internal-encoding=UTF-8",
            "-e", probe, "--", primitive,
        ],
        ["bundle", "exec", "ruby", "-e", probe, "--", primitive],
    )
    for command in commands:
        runtime = run(command)
        if (runtime is None or runtime.returncode or runtime.stdout != marker
                or runtime.stderr):
            raise StoreOperationError(
                "Pinned Ruby 3.3.12/Fiddle 1.1.2 native-validation tooling is unavailable "
                "or its loaded origin is not the pinned distribution. Install the complete "
                "reviewed Ruby and locked bundle; dependencies are never installed automatically."
            )


def store_output_path(config: ReleaseConfig, request: StoreRequest, *,
                      source_environment: Mapping[str, str] | None = None) -> Path:
    source = os.environ if source_environment is None else source_environment
    value = (request.store_precondition or request.output_dir / "store-precondition.json"
             if request.prepare else request.store_receipt or Path(source.get(
                 "MOBILE_RELEASE_STORE_RECEIPT_PATH", request.output_dir / "raw-store-receipt.json")))
    return _repository_path(config, value, "Store output path")


def new_store_lane_evidence(config: ReleaseConfig, request: StoreRequest,
                            cancellation: DefaultCancellation) -> StoreLaneCallEvidence:
    """Allocate before entering any outer metadata/snapshot/material context."""
    return StoreLaneCallEvidence(cancellation, lane=LANES[(request.stage, request.platform)],
        output=store_output_path(config, request), nonce=secrets.token_bytes(16))


@dataclass(frozen=True, slots=True, repr=False)
class StoreLaneReadback:
    """Provisional checked bytes, NOT final Store evidence or cleanup authority."""

    _record: StoreLaneCallEvidence
    _output: Path
    _content: bytes
    _document: dict[str, object]

    def provisional(self) -> dict[str, object]:
        # Caller post-lane policy may inspect a copy before dependent cleanup;
        # no public evidence may be written until complete_store_operation.
        return copy.deepcopy(self._document)


def _decode_store_document(content: bytes) -> dict[str, object]:
    try:
        result = json.loads(content.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, RecursionError):
        raise StoreOperationError("Store lane returned an invalid bounded document") from None
    if type(result) is not dict:
        raise StoreOperationError("Store lane returned a non-object document")
    return result


def _require_original_lane(record: StoreLaneCallEvidence, cancellation: DefaultCancellation,
                           config: ReleaseConfig, request: StoreRequest) -> None:
    if type(record) is not StoreLaneCallEvidence or type(cancellation) is not DefaultCancellation:
        raise StoreLaneEvidenceError(attempted=False)
    record._origin(cancellation)
    record._require(record._lane == LANES[(request.stage, request.platform)]
                    and record._output == str(store_output_path(config, request)))


def _raise_lane_primary(record: StoreLaneCallEvidence, cancellation: DefaultCancellation,
                        primary: BaseException) -> None:
    record._remember(primary)
    if isinstance(record._primary, (KeyboardInterrupt, SystemExit)):
        raise record._primary
    facts, verdict = cancellation.lifetime_ledger.verdict(), record.verdict(cancellation=cancellation)
    if not verdict.dependents_settled or not facts.cleanup_complete:
        error = ProcessError("Store lane lifetime or dependent cleanup is unconfirmed",
            dispatched=record._attempted, contained=verdict.dependents_settled and facts.contained,
            cleanup_complete=verdict.dependents_settled and facts.cleanup_complete)
        for previous in (record._primary, *record._secondary, cancellation.lifetime_ledger._primary,
                         *cancellation.lifetime_ledger._secondary):
            preserve_lifetime_error(error, previous=previous)
        raise error from None
    if isinstance(primary, ProcessError):
        raise primary
    if isinstance(primary, (OSError, subprocess.TimeoutExpired)):
        raise StoreOperationError(f"Store lane failed or timed out: {record._lane}") from None
    raise primary


def settle_store_operation(record: StoreLaneCallEvidence, *, cancellation: DefaultCancellation,
                           primary: BaseException | None = None) -> None:
    """Retire the original fence only AFTER every attached dependent has closed.

    May settle an original ordinary failure/no-target route, but never publishes
    receipt authority. Independent original handle closes run after any error.
    """
    from .ios_artifacts import _LaneSnapshotOwner

    if type(record) is not StoreLaneCallEvidence:
        raise StoreLaneEvidenceError()
    record._origin(cancellation)
    first = None
    pending = record._pending_attempt
    try:
        record.finish(cancellation=cancellation, primary=primary)
        invocation = getattr(record, "_caller_invocation", None)
        record._require(invocation is not None or not record._attempted)
        if invocation is not None:
            record._require(type(invocation) is InvocationCustody
                            and invocation._lane_closed_for(record, cancellation))
        for role in ("metadata", "ios-snapshot", "store-selection"):
            binding = record._resources.get(role)
            if binding is None:
                continue
            owner = binding._owner
            expected = _LaneSnapshotOwner if role == "ios-snapshot" else FiniteScratch
            record._require(type(owner) is expected and owner._lane_closed_for(record, binding, cancellation))
        verdict, facts = record.verdict(cancellation=cancellation), cancellation.lifetime_ledger.verdict()
        record._require(verdict.dependents_settled and facts.cleanup_complete)
        files_binding = record._resources.get("terminal")
        if files_binding is not None:
            files = files_binding._owner
            record._require(type(files) is StoreLaneFiles and files._receipt_closed_for(record))
        if pending is not None:
            record._require(type(pending) is StoreLaneAttempt and pending.record is record)
            if pending.phase == "PENDING":
                pending.retire()
            else:
                record._require(pending.phase == "RETIRED"
                    or not record._attempted and pending.phase in ("NEW", "ABSENT"))
    except BaseException as error:
        first = error
        record._remember(error)
    finally:
        if type(pending) is StoreLaneAttempt:
            try:
                pending.close(primary=primary or first)
            except BaseException as error:
                record._remember(error)
                if first is None:
                    first = error
    if first is not None:
        _raise_lane_primary(record, cancellation, primary or first)


def close_store_operation_resources(resources: ExitStack, record: StoreLaneCallEvidence, *,
                                    cancellation: DefaultCancellation,
                                    primary: BaseException | None = None,
                                    retire_marker: bool = True) -> None:
    """Fixed encompassing cleanup, not an arbitrary resource callback contract."""
    first = None
    try:
        record.finish(cancellation=cancellation, primary=primary)
    except BaseException as error:
        first = error
        record._remember(error)
        cancellation._abort(error)
    try:
        resources.close()
    except BaseException as error:
        if first is None:
            first = error
        record._remember(error)
        cancellation._abort(error)
    if retire_marker:
        try:
            settle_store_operation(record, cancellation=cancellation, primary=primary or first)
        except BaseException as error:
            record._remember(error)
            if first is None:
                first = error
    if first is not None:
        _raise_lane_primary(record, cancellation, primary or first)


def complete_store_operation(readback: StoreLaneReadback, *, lane_evidence: StoreLaneCallEvidence,
                             cancellation: DefaultCancellation) -> dict[str, object]:
    """Final original gate; context closure and exact bytes cannot be substituted."""
    if type(readback) is not StoreLaneReadback or readback._record is not lane_evidence:
        raise StoreLaneEvidenceError()
    lane_evidence._origin(cancellation)
    files = lane_evidence._files_owner()
    lane_evidence._require(readback._output == Path(lane_evidence._output)
        and readback._content == files.checked_document()
        and readback._document == _decode_store_document(readback._content))
    settle_store_operation(lane_evidence, cancellation=cancellation)
    lane_evidence.require_receipt(lane=lane_evidence._lane, output=readback._output,
        sha256=hashlib.sha256(readback._content).digest(), cancellation=cancellation)
    return copy.deepcopy(readback._document)


def _run_store_lane(
    *, config: ReleaseConfig, release: ReleaseVersion, request: StoreRequest,
    lane_evidence: StoreLaneCallEvidence, cancellation: DefaultCancellation,
    material: SelectedStoreMaterial, invocation: InvocationCustody, resources: ExitStack,
    source_environment: Mapping[str, str], authority: Mapping[str, object],
    tooling_root: Path, operation_intent: Mapping[str, object] | None,
) -> bytes:
    """One original Store command; returns provisional checked bytes only."""
    record = lane_evidence
    _require_original_lane(record, cancellation, config, request)
    record._require(not record._sealed and not record._attempted and not record._finished and not record._failed)
    receipt_path = _repository_path(config, Path(record._output), "Store output path")
    lane = record._lane
    # Pure path/material refusal comes before reserving the lane's file owner;
    # a rejected input is not an ambiguous scratch acquisition.
    if os.path.lexists(receipt_path):
        raise StoreOperationError("Store output path already exists; authoritative state is never overwritten")
    environment = _store_environment(config, release, request, receipt_path, tooling_root,
        material=material, invocation=invocation, lane_evidence=record,
        source_environment=source_environment, authority=authority)
    # Preparation may be the first producer of staging/<stage>/<platform>.
    # Retain its original private ancestry on the encompassing resource stack
    # through the command, terminal read, file disposal and final scope checks.
    # A point-in-time mkdir (or chmod of existing state) is not that custody.
    namespace = resources.enter_context(_app_private_directory(
        receipt_path.parent, app_root=config.root, cancellation=cancellation))
    if namespace is None:
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        _repository_path(config, receipt_path, "Store output path")
    # Inputs and exact bundle have already been admitted. Preserve the selected
    # HOME for the original Altool/Java route; do not invent a shell override.
    pending = StoreLaneAttempt(record, cancellation, app_root=config.root,
        mode="prepare" if request.prepare else "execute",
        intent_sha256=None if request.prepare else bytes.fromhex(operation_intent["integrity"]["sha256"]),
        executed_by=None if request.prepare else dict(authority))
    files = StoreLaneFiles(record, cancellation, app_root=config.root,
                           mode="prepare" if request.prepare else "execute", shell_home=False)
    completed, content, primary = None, None, None
    try:
        files.acquire()
        pending.acquire()  # Exclusive original refusal fence before command sealing/creation.
        environment = files.prepare_environment(environment)
        snapshot_binding = record._resources.get("ios-snapshot")
        if snapshot_binding is not None:
            from .ios_artifacts import _LaneSnapshotOwner

            snapshot = snapshot_binding._owner
            record._require(type(snapshot) is _LaneSnapshotOwner)
            snapshot.admit(record, cancellation)
        argv = record.seal_command(runner=tooling_root / "fastlane/run_lane.rb", cwd=files.cwd,
                                   environ=environment, cancellation=cancellation)
        try:
            completed = run_owned(argv, cwd=files.cwd, environ=environment, capture=False,
                timeout=3600, cancellation=cancellation,
                _evidence=record.command_evidence(cancellation=cancellation))
        except BaseException as error:
            primary = error
            record._remember(error)
        if record._attempted:
            try:
                files.read_terminal(primary=primary)
            except BaseException as error:
                record._remember(error)
                if primary is None:
                    primary = error
        if primary is None:
            if completed is None or completed.returncode:
                primary = StoreOperationError(f"Store lane failed: {lane}")
            else:
                content = files.checked_document()
    except BaseException as error:
        record._remember(error)
        if primary is None:
            primary = error
    finally:
        try:
            record.finish(cancellation=cancellation, primary=primary)
        except BaseException as error:
            record._remember(error)
            if primary is None:
                primary = error
        try:
            files.dispose()
        except BaseException as error:
            record._remember(error)
            if primary is None:
                primary = error
        finally:
            try:
                files.close(primary=primary)
            except BaseException as error:
                record._remember(error)
                if primary is None:
                    primary = error
        # The pending owner and its original directory FDs remain rooted on
        # this record. Outer metadata/snapshot post-use and cleanup come first.
        if namespace is not None:
            try:
                namespace.check()
            except BaseException as error:
                record._remember(error)
                if primary is None:
                    primary = error
    if primary is not None:
        _raise_lane_primary(record, cancellation, primary)
    record._require(type(content) is bytes)
    return content


def _raw_readback(*, record: StoreLaneCallEvidence, cancellation: DefaultCancellation,
                  config: ReleaseConfig, release: ReleaseVersion, request: StoreRequest,
                  operation_intent: Mapping[str, object]) -> StoreLaneReadback:
    output = Path(record._output)
    if record._attempted:
        # Same live original owner only. No new caller-provided pathname read.
        content = record._files_owner().checked_document()
        raw = _decode_store_document(content)
    else:
        raw = validate_store_receipt(load_store_receipt(output), config=config, release=release,
            stage=request.stage, platform=request.platform, operation_intent=operation_intent,
            recovery_run_id=request.recovery_run_id)
        probe = StoreLaneAttempt(record, cancellation, app_root=config.root, mode="execute",
            intent_sha256=bytes.fromhex(raw["operationIntentSha256"]), executed_by=raw["executedBy"])
        probe.require_absent()  # Refusal-only lookup of ORIGINAL, not the new dispatch identity.
        raise StoreOperationError(
            "Raw Store evidence lacks its original live composite completion. Preserve the original "
            "intent/artifacts and use the existing protected readback-first recovery route; "
            "marker absence, copied bytes or a new output directory cannot authorize reuse.")
    document = validate_store_receipt(raw, config=config, release=release, stage=request.stage,
        platform=request.platform, operation_intent=operation_intent, recovery_run_id=request.recovery_run_id)
    return StoreLaneReadback(record, output, content, document)


def _store_operation(*, config: ReleaseConfig, release: ReleaseVersion, request: StoreRequest,
                     operation_intent: Mapping[str, object] | None,
                     lane_evidence: StoreLaneCallEvidence | None,
                     cancellation: DefaultCancellation | None,
                     invocation: InvocationCustody | None) -> dict[str, object] | StoreLaneReadback:
    borrowed = lane_evidence is not None
    if invocation is not None and not borrowed:
        raise StoreLaneEvidenceError(attempted=False)
    if borrowed:
        if type(lane_evidence) is not StoreLaneCallEvidence:
            raise StoreLaneEvidenceError(attempted=False)
        if cancellation is None:
            cancellation = lane_evidence._guard
        lane_evidence._origin(cancellation)
    with first_primary_context(ExitStack(), cancellation=cancellation, expose_owner=True) as (resources, guard):
        record = lane_evidence if borrowed else new_store_lane_evidence(config, request, guard)
        _require_original_lane(record, guard, config, request)
        scope = CleanupScope(guard, lambda: close_store_operation_resources(
            resources, record, cancellation=guard, primary=scope._first_error,
            retire_marker=not borrowed), owns_cancellation=False, first_primary=True)
        try:
            with scope:
                # The original encompassing environment owner is admitted
                # before tooling probes, private input selection or raw reuse.
                if invocation is None:
                    invocation = resources.enter_context(invocation_custody(
                        config.root, mode="store", cancellation=guard, lane_evidence=record))
                else:
                    record._require(type(invocation) is InvocationCustody and invocation.mode == "store"
                                    and invocation.lane_evidence is record
                                    and getattr(record, "_caller_invocation", None) is invocation)
                    invocation.require(root=config.root, cancellation=guard)
                if not request.prepare:
                    if operation_intent is None or request.operation_intent is None:
                        raise StoreOperationError("Store execution requires its authenticated original operation intent")
                    validate_operation_intent(operation_intent)
                    intent_path = _repository_path(config, request.operation_intent, "operation intent path")
                    if load_operation_intent(intent_path) != operation_intent:
                        raise StoreOperationError("operation-intent file differs from the validated authorization")
                output = Path(record._output)
                if os.path.lexists(output):
                    if request.prepare:
                        raise StoreOperationError("Store precondition output already exists; it is never renamed or adopted")
                    readback = _raw_readback(record=record, cancellation=guard, config=config, release=release,
                                             request=request, operation_intent=operation_intent)
                else:
                    source_environment = dict(os.environ)
                    authority = workflow_authority(request.stage)
                    tooling_root = resolve_tooling_root()
                    if tooling_root is None or not _complete_tooling_root(tooling_root):
                        raise StoreOperationError("Pinned shared Fastlane/Gem tooling is unavailable or incomplete")
                    _require_fastlane_bundle(tooling_root, cancellation=guard,
                                             source_environment=source_environment)
                    material = resources.enter_context(_selected_store_material(config,
                        values=credential_values_from_environment(source_environment), platforms=(request.platform,),
                        stage="production" if request.stage == "production-submit" else request.stage,
                        invocation=invocation, cancellation=guard, lane_evidence=record))
                    findings = material.validate()
                    if any(item.status in FAILING_STATUSES for item in findings):
                        raise StoreOperationError("Selected Store credential material is missing or invalid")
                    content = _run_store_lane(config=config, release=release, request=request,
                        lane_evidence=record, cancellation=guard, material=material, invocation=invocation,
                        resources=resources, source_environment=source_environment, authority=authority,
                        tooling_root=tooling_root,
                        operation_intent=operation_intent)
                    raw = _decode_store_document(content)
                    document = (validate_store_precondition(raw, stage=request.stage, platform=request.platform)
                                if request.prepare else validate_store_receipt(raw, config=config, release=release,
                                    stage=request.stage, platform=request.platform, operation_intent=operation_intent,
                                    recovery_run_id=request.recovery_run_id))
                    readback = StoreLaneReadback(record, output, content, document)
        finally:
            scope.__exit__(*sys.exc_info())
        return readback if borrowed else complete_store_operation(readback, lane_evidence=record, cancellation=guard)


def prepare_store_operation(*, config: ReleaseConfig, release: ReleaseVersion, request: StoreRequest,
                            lane_evidence: StoreLaneCallEvidence | None = None,
                            cancellation: DefaultCancellation | None = None,
                            invocation: InvocationCustody | None = None) -> dict[str, object] | StoreLaneReadback:
    if not request.prepare or request.execute:
        raise StoreOperationError("Store preparation requires prepare-only mode")
    return _store_operation(config=config, release=release, request=request, operation_intent=None,
                            lane_evidence=lane_evidence, cancellation=cancellation, invocation=invocation)


def execute_store_operation(*, config: ReleaseConfig, release: ReleaseVersion, request: StoreRequest,
                            operation_intent: Mapping[str, object] | None = None,
                            lane_evidence: StoreLaneCallEvidence | None = None,
                            cancellation: DefaultCancellation | None = None,
                            invocation: InvocationCustody | None = None) -> dict[str, object] | StoreLaneReadback:
    if not request.execute or request.prepare:
        raise StoreOperationError("Store execution requires execute-only mode")
    try:
        return _store_operation(config=config, release=release, request=request,
            operation_intent=operation_intent, lane_evidence=lane_evidence, cancellation=cancellation,
            invocation=invocation)
    except StoreOperationError as error:
        # Fatal ProcessError and original interruptions never enter this ordinary
        # recovery-diagnostic branch, nor authorize another Store launch.
        receipt_path = store_output_path(config, request)
        if request.platform == "ios" and operation_intent is not None:
            journal = receipt_path.with_name(f"{receipt_path.stem}-apple-state.json")
            if journal.is_file() and not journal.is_symlink():
                try:
                    diagnostic = load_store_receipt(journal)
                    history = diagnostic.get("history", [])
                    if isinstance(history, list):
                        for event in reversed(history[-256:]):
                            if isinstance(event, dict) and "createRetryInventory" in event:
                                inventory = validate_create_retry_inventory(event["createRetryInventory"], operation_intent=operation_intent)
                                confirmation = f"retry-ios-operation-creates:{operation_intent['integrity']['sha256']}:{canonical_sha256(inventory)}"
                                raise StoreOperationError(
                                    "Apple create outcome is ambiguous. Retain the original intent/artifacts; "
                                    "independently resolve whether prior requests were accepted, then use a NEW "
                                    "protected first-attempt recovery dispatch with --recovery-run-id "
                                    f"{operation_intent['authorizedBy']['runId']} --recovery-confirmation {confirmation}. "
                                    "Repeated absence alone is not proof of rejection."
                                ) from error
                except ValidationError:
                    pass
        raise


def online_preflight_findings(
    *,
    config: ReleaseConfig,
    release: ReleaseVersion,
    platforms: tuple[str, ...],
    material: SelectedStoreMaterial,
    invocation: InvocationCustody,
) -> list[Finding]:
    if type(material) is not SelectedStoreMaterial or type(invocation) is not InvocationCustody:
        raise StoreOperationError("Online preflight requires its original selected material and invocation")
    material.require(config=config, platforms=platforms, invocation=invocation)
    cancellation = invocation.cancellation
    explicit_readback = os.environ.get("MOBILE_RELEASE_PREFLIGHT_READBACK_PATH")
    # One caller filename cannot safely hold two platforms without overwriting.
    # Refuse before even the tooling probes; never invent filename suffixes.
    if explicit_readback and len(platforms) != 1:
        raise StoreOperationError("An explicit preflight readback path requires exactly one platform")
    explicit_path = (_repository_path(config, explicit_readback, "Store preflight readback path")
                     if explicit_readback else None)
    if explicit_path is not None and os.path.lexists(explicit_path):
        raise StoreOperationError("Refusing to overwrite an existing Store preflight readback")
    tooling_root = resolve_tooling_root()
    if tooling_root is None:
        return [Finding("store.online.tooling", Status.FAIL,
            "Shared Fastlane assets are unavailable; install the complete pinned distribution "
            "or set MOBILE_RELEASE_TOOLING_ROOT.", category="store-access")]
    runner, gemfile = tooling_root / "fastlane/run_lane.rb", tooling_root / "Gemfile"
    if not _complete_tooling_root(tooling_root):
        return [Finding("store.online.fastfile", Status.FAIL,
                        "Pinned shared Fastlane/Gem bundle is incomplete.", category="store-access")]
    try:
        _require_fastlane_bundle(tooling_root, cancellation=cancellation)
    except ProcessError:
        raise
    except StoreOperationError as error:
        return [Finding("store.online.bundle", Status.FAIL, str(error), category="store-access")]
    # An explicit filename below the same private application namespace must
    # not let ordinary recursive mkdir create that namespace0755 under0022.
    # Public repository outputs retain their separate existing path policy.
    private_root = (_private_app_directory(config, ".mobile-release/store", cancellation=cancellation)
                    if explicit_path is None or explicit_path.is_relative_to(config.root / ".mobile-release")
                    else None)
    if explicit_path is not None:
        explicit_path.parent.mkdir(parents=True, exist_ok=True)
        explicit_path = _repository_path(config, explicit_path, "Store preflight readback path")
    findings: list[Finding] = []
    for platform in platforms:
        material.require(config=config, platforms=platforms, invocation=invocation)
        # Close each platform's actual output/cwd scopes before another platform
        # can start; an unresolved writer or disposal cannot become a diagnostic
        # that allows later commands to continue.
        with finite_scratch(layout="online-runner", cancellation=cancellation) as runner_scratch:
            output_context = (finite_scratch(layout="online-readback", cancellation=cancellation,
                                              parent=private_root)
                              if explicit_path is None else nullcontext(None))
            with output_context as output:
                evidence = None
                if output is not None:
                    from ._command_process import CommandCallEvidence

                    evidence = CommandCallEvidence(cancellation)
                    report_path = output.output_path(platform, evidence=evidence)
                else:
                    assert explicit_path is not None
                    report_path = _repository_path(config, explicit_path, "Store preflight readback path")
                    if os.path.lexists(report_path):
                        raise StoreOperationError("Refusing to overwrite an existing Store preflight readback")
                runner_scratch._owner()
                runner_scratch._check()
                runner_directory = runner_scratch._path
                environment = _runtime_environment(os.environ)
                environment.update(material.lane_environment(platform=platform))
                environment.update({
                    "MOBILE_RELEASE_APP_ROOT": str(config.root),
                    "MOBILE_RELEASE_CONFIG_PATH": str(config.path),
                    "MOBILE_RELEASE_PREFLIGHT_READBACK_PATH": str(report_path),
                    "BUNDLE_GEMFILE": str(gemfile),
                })
                argv = (("bundle", "exec", "ruby", str(runner), platform + "_online_preflight")
                        if evidence is None else evidence.seal_readback(
                            runner=runner, cwd=runner_directory, environ=environment))
                try:
                    completed = run_owned(argv, cwd=runner_directory, environ=environment,
                                          capture=False, timeout=15 * 60,
                                          cancellation=cancellation, _evidence=evidence)
                except ProcessError as error:
                    if error.fatal:
                        raise
                    completed = None
                except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                    completed = None
                if completed is None or completed.returncode:
                    findings.append(Finding(f"store.online.{platform}", Status.FAIL,
                        f"Non-publishing {platform} Store preflight failed.", category="store-access"))
                    continue
                try:
                    content = (output.read_output(platform) if output is not None
                               else read_readback_bytes(report_path, cancellation=cancellation))
                    raw = json.loads(content.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
                    _validate_online_readback(raw, config=config, release=release, platform=platform)
                except (json.JSONDecodeError, UnicodeDecodeError, StoreOperationError,
                        ValidationError, OSError) as error:
                    if isinstance(error, ProcessError) and error.fatal:
                        raise
                    findings.append(Finding(f"store.online.{platform}", Status.FAIL,
                        "Non-publishing Store preflight returned missing, unsafe or inconsistent readback.",
                        category="store-access"))
                    continue
                material.require(config=config, platforms=platforms, invocation=invocation)
                findings.append(Finding(f"store.online.{platform}", Status.PASS,
                    f"Non-publishing {platform} Store access, identity, destinations, and build uniqueness are valid.",
                    category="store-access"))
    return findings


def _validate_online_readback(
    raw: object, *, config: ReleaseConfig, release: ReleaseVersion, platform: str
) -> None:
    if not isinstance(raw, dict):
        raise StoreOperationError("Store preflight readback must be a JSON object")
    required = {
        "schemaVersion",
        "platform",
        "appIdentity",
        "buildNumber",
        "buildUnused",
        "observedAt",
    }
    platform_config = config.section(platform)
    if platform == "android":
        required.add("requiredTracks")
        if platform_config.get("externalTrack", {}).get("kind") == "closed":
            required.add("closedTesterAssignmentVerified")
    else:
        required.update({"appStoreAppId", "externalGroup"})
    missing = sorted(required - set(raw))
    if missing:
        raise StoreOperationError(f"Store preflight readback is missing: {', '.join(missing)}")
    unknown = sorted(set(raw) - required)
    if unknown:
        raise StoreOperationError(
            f"Store preflight readback has unexpected fields: {', '.join(unknown)}"
        )
    identity_key = "applicationId" if platform == "android" else "bundleId"
    if (
        type(raw["schemaVersion"]) is not int
        or raw["schemaVersion"] != 1
        or raw["platform"] != platform
        or raw["appIdentity"] != config.section(platform).get(identity_key)
        or raw["buildNumber"] != release.build
        or raw["buildUnused"] is not True
    ):
        raise StoreOperationError("Store preflight identity/build uniqueness readback is inconsistent")
    if not isinstance(raw["observedAt"], str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", raw["observedAt"]
    ):
        raise StoreOperationError("Store preflight observedAt is not second-precision UTC RFC3339")
    if platform == "android":
        expected_tracks = ["internal", platform_config["externalTrack"]["name"]]
        if raw.get("requiredTracks") != expected_tracks:
            raise StoreOperationError("Play preflight tracks do not match configured lifecycle tracks")
        closed = platform_config["externalTrack"].get("kind") == "closed"
        if closed and raw.get("closedTesterAssignmentVerified") is not True:
            raise StoreOperationError(
                "Closed Play track lacks an API-verified nonempty tester-group assignment"
            )
    else:
        ios = platform_config
        if str(raw.get("appStoreAppId")) != str(ios.get("appStoreAppId")):
            raise StoreOperationError("App Store Connect app ID does not match configuration")
        if raw.get("externalGroup") != ios.get("externalTestFlightGroup"):
            raise StoreOperationError("TestFlight external group does not match configuration")
