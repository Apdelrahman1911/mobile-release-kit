from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from . import __version__
from .android import validate_aab, validate_aab_structure
from .config import ConfigurationError, default_config, load_config, write_json_exclusive
from .credentials import credential_findings
from .discovery import discover_project, git_context
from .errors import MobileReleaseError, ValidationError
from .ios import (
    SigningValidityInterval, _validated_ipa_entries, ipa_signing_evidence,
    validate_ipa_current_signing, validate_preparation_signing_time,
)
from .metadata import build_metadata_archive, metadata_findings
from .preflight import doctor, preflight
from .provenance import (
    artifact_records,
    build_candidate_manifest,
    build_operation_intent,
    build_receipt,
    copy_immutable_file,
    load_candidate_manifest,
    load_release_receipt,
    load_evidence,
    load_operation_intent,
    load_store_receipt,
    sha256_file,
    validate_receipt_chain,
    validate_evidence_context,
    validate_evidence_output_path,
    validate_immutable_copy,
    validate_operation_intent_context,
    validate_candidate_intent_binding,
    validate_candidate_raw_binding,
    validate_receipt_raw_binding,
    validate_store_receipt,
    workflow_authority,
    verify_sealed,
    write_evidence,
)
from .reporting import FAILING_STATUSES, Finding, Report, Status
from .stores import (
    StoreRequest,
    execute_store_operation,
    guard_ci_mutation,
    prepare_store_operation,
)
from .tooling import resolve_tooling_root
from .workflow import authenticate_operation_intent

DEFAULT_CONFIG = "release/mobile-release.json"
TOOLING_REPOSITORY_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/"
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?"
)


def _add_config_argument(parser: argparse.ArgumentParser, *, optional: bool = False) -> None:
    parser.add_argument("--config", default=None if optional else DEFAULT_CONFIG)


def _add_report_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument("--output", type=Path)


def _add_platform_argument(
    parser: argparse.ArgumentParser, *, allow_both: bool = True, default: str = "both"
) -> None:
    choices = ("android", "ios", "both") if allow_both else ("android", "ios")
    parser.add_argument("--platform", choices=choices, default=default)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mobile-release",
        description="Fail-early Android/iOS Store release validation and exact-build orchestration.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    init_parser = commands.add_parser("init", help="Discover a project and propose thin configuration.")
    init_parser.add_argument("--root", type=Path, default=Path.cwd())
    init_parser.add_argument("--config", default=DEFAULT_CONFIG)
    init_parser.add_argument("--apply", action="store_true")
    init_parser.add_argument("--force", action="store_true")
    init_parser.add_argument("--tooling-sha", help="Full shared-tool commit used in caller templates.")
    init_parser.add_argument(
        "--tooling-repository",
        help="GitHub OWNER/REPO containing the pinned reusable workflows.",
    )
    init_parser.add_argument("--template-dir", type=Path)

    doctor_parser = commands.add_parser("doctor", help="Run quick secretless configuration discovery.")
    _add_config_argument(doctor_parser)
    _add_platform_argument(doctor_parser)
    _add_report_arguments(doctor_parser)

    credential_parser = commands.add_parser(
        "credentials", help="List exactly which external credentials/assets are configured or missing."
    )
    _add_config_argument(credential_parser)
    _add_platform_argument(credential_parser)
    credential_parser.add_argument(
        "--stage", choices=("candidate", "external-testing", "production", "all"), default="all"
    )
    credential_parser.add_argument("--credentials-file", type=Path)
    credential_parser.add_argument("--credentials-from-env", action="store_true")
    credential_parser.add_argument("--github", action="store_true")
    _add_report_arguments(credential_parser)

    preflight_parser = commands.add_parser(
        "preflight", help="Run offline, signing, or read-only online release validation."
    )
    _add_config_argument(preflight_parser)
    _add_platform_argument(preflight_parser)
    mode = preflight_parser.add_mutually_exclusive_group()
    mode.add_argument("--offline", action="store_true")
    mode.add_argument("--signing", action="store_true")
    mode.add_argument("--online", action="store_true")
    build_group = preflight_parser.add_mutually_exclusive_group()
    build_group.add_argument("--run-builds", dest="run_builds", action="store_true")
    build_group.add_argument("--skip-builds", dest="run_builds", action="store_false")
    preflight_parser.set_defaults(run_builds=True)
    preflight_parser.add_argument("--credentials-file", type=Path)
    preflight_parser.add_argument("--credentials-from-env", action="store_true")
    preflight_parser.add_argument("--require-tools", action="store_true")
    preflight_parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="Validate an already-built normalized artifact.",
    )
    _add_report_arguments(preflight_parser)

    status_parser = commands.add_parser(
        "status", help="Verify local immutable candidate/promotion evidence without Store mutation."
    )
    _add_config_argument(status_parser)
    status_parser.add_argument("--candidate-manifest", type=Path)
    status_parser.add_argument("--receipt", action="append", type=Path, default=[])
    _add_report_arguments(status_parser)

    explain_parser = commands.add_parser("explain", help="Explain a stable release contract topic.")
    _add_config_argument(explain_parser, optional=True)
    explain_parser.add_argument(
        "topic",
        nargs="?",
        choices=("lifecycle", "credentials", "configuration", "safety"),
        default="lifecycle",
    )

    ci_parser = commands.add_parser("ci", help="Guarded exact-build Store orchestration for CI only.")
    ci_commands = ci_parser.add_subparsers(dest="ci_command", required=True)
    for name in ("candidate", "external-testing", "production-submit"):
        ci = ci_commands.add_parser(name)
        _add_config_argument(ci)
        _add_platform_argument(ci, allow_both=False, default="android")
        ci.add_argument("--output-dir", type=Path, required=True)
        ci.add_argument("--confirm", required=True)
        operation_mode = ci.add_mutually_exclusive_group()
        operation_mode.add_argument("--prepare-operation", action="store_true")
        operation_mode.add_argument("--validate-operation-intent", action="store_true")
        operation_mode.add_argument("--execute-store", action="store_true")
        ci.add_argument("--operation-intent", type=Path)
        ci.add_argument("--recovery-run-id")
        ci.add_argument("--recovery-confirmation")
        ci.add_argument("--store-receipt", type=Path)
        ci.add_argument("--artifact", action="append", default=[], metavar="NAME=PATH")
        ci.add_argument("--candidate-manifest", type=Path)
        ci.add_argument("--candidate-receipt", type=Path)
        ci.add_argument("--external-receipt", type=Path)
        ci.add_argument("--candidate-operation-intent", type=Path)
        ci.add_argument("--external-operation-intent", type=Path)
    return parser


def _platforms(value: str, enabled: Iterable[str]) -> tuple[str, ...]:
    return tuple(enabled) if value == "both" else (value,)


def _parse_artifacts(values: Iterable[str], root: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise ValidationError(f"artifact must use NAME=PATH syntax: {value}")
        name, path_value = value.split("=", 1)
        if not name or name in result or not path_value:
            raise ValidationError(f"artifact name/path is empty or duplicated: {name!r}")
        path = Path(path_value).expanduser()
        if not path.is_absolute():
            path = root / path
        result[name] = Path(os.path.abspath(path))
    return result


def _repository_path(
    config: Any,
    value: Path,
    *,
    label: str,
    must_exist: bool = False,
) -> Path:
    try:
        candidate = config.project_path(os.fspath(value))
    except ConfigurationError as error:
        raise ValidationError(
            f"{label} must remain inside the repository without symbolic links"
        ) from error
    if must_exist and not candidate.exists():
        raise ValidationError(f"{label} does not exist")
    return candidate


def _emit(report: Report, args: argparse.Namespace, config: Any) -> int:
    report.emit(output_format=args.format, output=args.output, root=config.root)
    return 0 if report.ok else 1


def _find_template_dir(root: Path, explicit: Path | None) -> Path | None:
    del root
    if explicit:
        candidate = explicit.expanduser().absolute()
        return candidate if candidate.is_dir() else None
    tooling_root = resolve_tooling_root()
    template_dir = tooling_root / "templates/workflows" if tooling_root else None
    return template_dir if template_dir and template_dir.is_dir() else None


def _lexical_project_path(root: Path, value: str | Path) -> Path:
    candidate = Path(os.path.abspath(os.fspath(root / value))).expanduser()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ValidationError("init destinations must remain inside the project") from error
    return candidate


def _validate_init_destination(
    root: Path, destination: Path, *, force: bool, label: str
) -> None:
    relative = destination.relative_to(root)
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        if current.is_symlink():
            raise ValidationError(f"refusing to write {label} through symbolic link: {current}")
        if index < len(relative.parts) - 1 and current.exists() and not current.is_dir():
            raise ValidationError(f"{label} parent is not a directory: {current}")
    if destination.exists() and not force:
        raise ValidationError(f"refusing to overwrite {label}: {destination}")
    if destination.exists() and not destination.is_file():
        raise ValidationError(f"{label} destination is not a regular file: {destination}")


def _write_text_exclusive(path: Path, value: str, *, force: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if force else os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o644)
    except FileExistsError as error:
        raise ValidationError(f"refusing to overwrite workflow caller: {path}") from error
    except OSError as error:
        if path.is_symlink():
            raise ValidationError(f"refusing to write workflow caller through symbolic link: {path}") from error
        raise
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(value)


def _metadata_skeleton(configuration: Mapping[str, Any]) -> tuple[str, ...]:
    metadata = configuration.get("metadata", {})
    root = str(metadata.get("root", "release/store")).rstrip("/")
    paths: list[str] = []
    if configuration.get("android", {}).get("enabled"):
        for locale in metadata.get("androidLocales", []):
            paths.extend(
                f"{root}/android/{locale}/{name}"
                for name in ("title.txt", "short_description.txt", "full_description.txt")
            )
    if configuration.get("ios", {}).get("enabled"):
        for locale in metadata.get("iosLocales", []):
            paths.extend(
                f"{root}/ios/{locale}/{name}"
                for name in (
                    "description.txt",
                    "keywords.txt",
                    "privacy_url.txt",
                    "support_url.txt",
                    "release_notes.txt",
                )
            )
        paths.extend(
            (
                f"{root}/review/ios-beta-notes.txt",
                f"{root}/review/ios-notes.txt",
                f"{root}/testflight/what-to-test.txt",
            )
        )
    return tuple(sorted(paths))


def _init(args: argparse.Namespace) -> int:
    root = args.root.expanduser().resolve()
    discovered = discover_project(root)
    proposed = default_config(root, discovered)
    if not any(proposed[platform].get("enabled") for platform in ("android", "ios")):
        raise ValidationError(
            "no supported Android application or iOS application project was discovered"
        )
    if not args.apply:
        print(json.dumps({"discovery": discovered, "proposedConfiguration": proposed}, indent=2))
        return 0
    config_path = _lexical_project_path(root, args.config)
    template_dir = _find_template_dir(root, args.template_dir)
    if template_dir is None:
        raise ValidationError("workflow caller templates are unavailable")
    if not args.tooling_sha or not re.fullmatch(r"[0-9A-Fa-f]{40}", args.tooling_sha):
        raise ValidationError("--tooling-sha full commit is required to install workflow callers")
    if not args.tooling_repository or not TOOLING_REPOSITORY_RE.fullmatch(
        args.tooling_repository
    ):
        raise ValidationError(
            "--tooling-repository must be a safe GitHub OWNER/REPO coordinate"
        )
    proposed["$schema"] = (
        f"https://raw.githubusercontent.com/{args.tooling_repository}/"
        f"{args.tooling_sha.lower()}/schemas/project.schema.json"
    )
    sources = sorted(template_dir.glob("*.yml"))
    if not sources:
        raise ValidationError(f"workflow caller template directory is empty: {template_dir}")

    workflow_dir = root / ".github/workflows"
    prepared: list[tuple[Path, str]] = []
    metadata_files: list[Path] = []
    gitignore = _lexical_project_path(root, ".gitignore")
    _validate_init_destination(root, gitignore, force=True, label="root .gitignore")
    gitignore_existed = gitignore.exists()
    if gitignore_existed:
        if gitignore.stat().st_size > 1024 * 1024:
            raise ValidationError("root .gitignore is unexpectedly large")
        try:
            gitignore_text = gitignore.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise ValidationError("root .gitignore must be UTF-8") from error
    else:
        gitignore_text = ""
    ignore_present = ".mobile-release/" in {
        line.strip() for line in gitignore_text.splitlines()
    }
    if not ignore_present:
        if gitignore_text and not gitignore_text.endswith("\n"):
            gitignore_text += "\n"
        gitignore_text += ".mobile-release/\n"
    destinations = {config_path}
    _validate_init_destination(root, config_path, force=args.force, label="configuration")
    for source in sources:
        if source.is_symlink() or not source.is_file():
            raise ValidationError(f"workflow caller template is not a regular file: {source}")
        rendered = source.read_text(encoding="utf-8")
        placeholders = {
            "__MOBILE_RELEASE_KIT_SHA__": args.tooling_sha.lower(),
            "__MOBILE_RELEASE_KIT_REPOSITORY__": args.tooling_repository,
        }
        missing = [name for name in placeholders if name not in rendered]
        if missing:
            raise ValidationError(
                f"workflow caller template lacks required placeholder(s): {source}"
            )
        destination = _lexical_project_path(root, workflow_dir / source.name)
        if destination in destinations:
            raise ValidationError(f"duplicate init destination: {destination}")
        destinations.add(destination)
        _validate_init_destination(
            root, destination, force=args.force, label="workflow caller"
        )
        for placeholder, replacement in placeholders.items():
            rendered = rendered.replace(placeholder, replacement)
        prepared.append((destination, rendered))
    for relative in _metadata_skeleton(proposed):
        destination = _lexical_project_path(root, relative)
        if destination in destinations:
            raise ValidationError(f"duplicate init destination: {destination}")
        destinations.add(destination)
        if destination.exists():
            if destination.is_symlink() or not destination.is_file():
                raise ValidationError(
                    f"metadata skeleton destination is not a regular file: {destination}"
                )
            continue
        _validate_init_destination(
            root, destination, force=False, label="metadata skeleton"
        )
        metadata_files.append(destination)

    write_json_exclusive(config_path, proposed, force=args.force)
    created = [str(config_path.relative_to(root))]
    workflow_dir.mkdir(parents=True, exist_ok=True)
    for destination, rendered in prepared:
        _write_text_exclusive(destination, rendered, force=args.force)
        created.append(str(destination.relative_to(root)))
    for destination in metadata_files:
        destination.parent.mkdir(parents=True, exist_ok=True)
        _write_text_exclusive(destination, "", force=False)
        created.append(str(destination.relative_to(root)))
    updated: list[str] = []
    if not ignore_present:
        _write_text_exclusive(gitignore, gitignore_text, force=gitignore_existed)
        (updated if gitignore_existed else created).append(".gitignore")
    print(
        json.dumps(
            {"created": created, "updated": updated, "requiresReview": True}, indent=2
        )
    )
    return 0


def _doctor(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    return _emit(
        doctor(config, _platforms(args.platform, config.enabled_platforms)), args, config
    )


def _credentials(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    report = Report("credentials", context={"stage": args.stage})
    report.extend(
        credential_findings(
            config,
            stage=args.stage,
            credentials_file=args.credentials_file,
            credentials_from_env=args.credentials_from_env,
            github=args.github,
            platforms=_platforms(args.platform, config.enabled_platforms),
        )
    )
    return _emit(report, args, config)


def _preflight(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    mode = "signing" if args.signing else "online" if args.online else "offline"
    artifacts = _parse_artifacts(args.artifact, config.root)
    for name, path in tuple(artifacts.items()):
        artifacts[name] = _repository_path(
            config, path, label=f"preflight artifact {name}", must_exist=True
        )
    result = preflight(
        config,
        mode=mode,
        platforms=_platforms(args.platform, config.enabled_platforms),
        run_builds=args.run_builds and mode != "online",
        artifacts=artifacts,
        credentials_file=args.credentials_file,
        credentials_from_env=args.credentials_from_env,
        require_tools=args.require_tools,
    )
    return _emit(result, args, config)


def _status(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    report = Report("status")
    candidate: dict[str, Any] | None = None
    candidate_payload: dict[str, Any] | None = None
    if args.candidate_manifest:
        try:
            candidate = load_candidate_manifest(args.candidate_manifest)
            candidate_intent = load_operation_intent(_evidence_intent_path(args.candidate_manifest, "candidate"))
            validate_candidate_intent_binding(candidate, operation_intent=candidate_intent)
            candidate_payload = verify_sealed(candidate)
            version = config.release_version()
            if candidate_payload.get("version") != {
                "marketing": version.name,
                "build": version.build,
            }:
                raise ValidationError("candidate version does not match committed configuration")
            report.add(
                "evidence.candidate", Status.PASS, "Candidate manifest integrity is valid.", category="evidence"
            )
        except MobileReleaseError as error:
            report.add("evidence.candidate", Status.FAIL, str(error), category="evidence")
            candidate = None
            candidate_payload = None
    receipts: dict[tuple[str, str], dict[str, Any]] = {}
    intents: dict[tuple[str, str], dict[str, Any]] = {}
    receipt_candidate_hashes: set[str] = set()
    for index, path in enumerate(args.receipt):
        try:
            receipt = load_release_receipt(path)
            payload = verify_sealed(receipt)
            key = (payload["platform"], payload["stage"])
            if key in receipts:
                raise ValidationError(
                    f"duplicate {payload['platform']} {payload['stage']} receipt"
                )
            if candidate and payload.get("candidateManifestSha256") != candidate["integrity"]["sha256"]:
                raise ValidationError("receipt is not bound to the supplied candidate manifest")
            intent = load_operation_intent(_evidence_intent_path(path, payload["stage"]))
            receipts[key] = receipt
            intents[key] = intent
            receipt_candidate_hashes.add(payload["candidateManifestSha256"])
            report.add(
                f"evidence.receipt.{index}", Status.PASS, f"Receipt integrity is valid: {path.name}", category="evidence"
            )
        except MobileReleaseError as error:
            report.add(f"evidence.receipt.{index}", Status.FAIL, str(error), category="evidence")
    if len(receipt_candidate_hashes) > 1:
        report.add(
            "evidence.chain.candidates",
            Status.FAIL,
            "Provided receipts refer to different candidate manifests.",
            category="evidence",
        )
    if receipts and candidate is None:
        report.add(
            "evidence.chain.candidate",
            Status.MISSING,
            "A candidate manifest is required to verify the receipt chain.",
            category="evidence",
        )
    elif receipts and candidate is not None and candidate_payload is not None:
        platforms = set(candidate_payload.get("platforms", {}))
        receipt_platforms = {platform for platform, _stage in receipts}
        if len(platforms) != 1 or receipt_platforms != platforms:
            report.add(
                "evidence.chain.platform",
                Status.FAIL,
                "Receipt platforms do not exactly match the candidate manifest.",
                category="evidence",
            )
        else:
            platform = next(iter(platforms))
            try:
                validate_receipt_chain(
                    candidate_manifest=candidate,
                    candidate_receipt=receipts.get((platform, "candidate")),
                    external_receipt=receipts.get((platform, "external-testing")),
                    production_receipt=receipts.get((platform, "production-submit")),
                    platform=platform,
                    config=config,
                    candidate_intent=candidate_intent,
                    external_intent=intents.get((platform, "external-testing")),
                    production_intent=intents.get((platform, "production-submit")),
                )
                report.add(
                    "evidence.chain",
                    Status.PASS,
                    "Candidate and receipt predecessor chain is valid.",
                    category="evidence",
                )
            except MobileReleaseError as error:
                report.add("evidence.chain", Status.FAIL, str(error), category="evidence")
    if not args.candidate_manifest and not args.receipt:
        report.add(
            "evidence.none",
            Status.MISSING,
            "Provide --candidate-manifest and/or --receipt.",
            category="evidence",
        )
    return _emit(report, args, config)


EXPLANATIONS = {
    "lifecycle": (
        "configure → doctor → offline preflight → signing preflight → online preflight → "
        "build once → validate → internal upload → exact-build external promotion → "
        "production draft/submission → human go-live"
    ),
    "configuration": (
        "The application owns release/mobile-release.json. Values discovered from Gradle/Xcode are "
        "not duplicated; security policy such as Store IDs, tracks, signer fingerprints, and review "
        "classification remains explicit and reviewed."
    ),
    "credentials": (
        "Credentials are stage- and capability-scoped. Run `mobile-release credentials` for names and "
        "status only; values are never printed or stored in release evidence."
    ),
    "safety": (
        "Only candidate builds. External and production consume exact immutable Store build IDs. "
        "Android production ends as draft and Apple submission disables automatic release."
    ),
}


def _explain(args: argparse.Namespace) -> int:
    if args.config:
        load_config(args.config)
    print(EXPLANATIONS[args.topic])
    return 0


def _require_ci_policy(config: Any, platform: str, stage: str) -> None:
    del stage
    report = doctor(config, (platform,))
    report.extend(metadata_findings(config, platforms=(platform,)))
    failures = [item for item in report.findings if item.status in FAILING_STATUSES]
    if failures:
        summary = ", ".join(item.code for item in failures[:8])
        raise ValidationError(f"CI release policy/preflight is incomplete: {summary}")


def _set_artifact_environment(artifacts: Mapping[str, Path]) -> None:
    mapping = {
        "android-aab": "MOBILE_RELEASE_ANDROID_AAB_PATH",
        "android-mapping": "MOBILE_RELEASE_ANDROID_MAPPING_PATH",
        "ios-ipa": "MOBILE_RELEASE_IOS_IPA_PATH",
    }
    for name, path in artifacts.items():
        if name in mapping:
            os.environ[mapping[name]] = str(path)


def _validate_ci_artifact_selection(
    *, stage: str, platform: str, artifacts: Mapping[str, Path]
) -> None:
    if stage != "candidate":
        if artifacts:
            raise ValidationError(
                "promotion/submission consumes immutable Store receipts and never accepts binaries"
            )
        return
    allowed = {
        "android": {
            "android-aab",
            "android-mapping",
            "android-native-symbols",
            "validation-report",
        },
        "ios": {"ios-ipa", "ios-archive", "ios-dsyms", "validation-report"},
    }[platform]
    unexpected = sorted(set(artifacts) - allowed)
    if unexpected:
        raise ValidationError(
            f"candidate contains unsupported {platform} artifact(s): {', '.join(unexpected)}"
        )
    required = {"android-aab" if platform == "android" else "ios-ipa", "validation-report"}
    missing = sorted(required - set(artifacts))
    if missing:
        raise ValidationError(
            f"candidate is missing required artifact(s): {', '.join(missing)}"
        )


def _candidate_context_matches(config: Any, candidate: Mapping[str, Any], platform: str) -> None:
    payload = verify_sealed(candidate)
    version = config.release_version()
    if payload.get("version") != {"marketing": version.name, "build": version.build}:
        raise ValidationError("candidate manifest release version no longer matches configuration")
    identity_key = "applicationId" if platform == "android" else "bundleId"
    expected_identity = config.section(platform)[identity_key]
    if payload.get("platforms", {}).get(platform, {}).get("applicationId") != expected_identity:
        raise ValidationError("candidate manifest application identity does not match configuration")
    if payload.get("configuration", {}).get("sha256") != sha256_file(config.path):
        raise ValidationError("candidate manifest configuration hash does not match checked-out source")
    with tempfile.TemporaryDirectory(prefix="mobile-release-metadata-proof-") as temporary:
        current_archive = Path(temporary) / "store-metadata.zip"
        build_metadata_archive(
            config.project_path(config.section("metadata").get("root", "release/store")),
            current_archive,
            platform=platform,
        )
        current_metadata_sha = sha256_file(current_archive)
    if payload.get("configuration", {}).get("metadataSha256") != current_metadata_sha:
        raise ValidationError(
            "current Store metadata does not match the immutable candidate metadata archive"
        )
    tooling_sha = os.environ.get("MOBILE_RELEASE_TOOLING_SHA")
    if tooling_sha and payload.get("tooling", {}).get("commit") != tooling_sha.lower():
        raise ValidationError("candidate manifest was created by a different shared-tool commit")


def _adjacent(path: Path, filename: str) -> Path:
    return path.absolute().parent / filename


def _evidence_intent_path(evidence: Path, stage: str) -> Path:
    """Accept local staging or the fixed final package, never choose a conflict."""

    filename = f"{stage}-operation-intent.json"
    adjacent = _adjacent(evidence, filename)
    packaged = _adjacent(evidence, "operation") / filename
    present = [path for path in (adjacent, packaged) if path.exists() or path.is_symlink()]
    if len(present) > 1:
        raise ValidationError("evidence has ambiguous adjacent and packaged operation intents")
    if not present:
        raise ValidationError(
            f"evidence requires {filename} beside the document or in its operation/ directory"
        )
    return present[0]


def _guard_partial_candidate_output(
    *, output_dir: Path, intent_path: Path, raw_path: Path,
    config: Any, release: Any, platform: str, recovery_run_id: str | None,
) -> None:
    """Reject incompatible partial evidence before writing anything beside it."""

    manifest_path = output_dir / "candidate-manifest.json"
    if not manifest_path.exists() or (output_dir / "candidate-receipt.json").exists():
        return
    try:
        manifest = load_candidate_manifest(manifest_path)
        intent = load_operation_intent(intent_path)
        validate_candidate_intent_binding(manifest, operation_intent=intent)
        if manifest["producedBy"] != workflow_authority("candidate"):
            raise ValidationError("partial manifest belongs to another producer")
        raw = validate_store_receipt(
            load_store_receipt(raw_path), config=config, release=release,
            stage="candidate", platform=platform, operation_intent=intent,
            recovery_run_id=recovery_run_id,
        )
        validate_candidate_raw_binding(manifest, store_receipt=raw)
    except ValidationError as error:
        raise ValidationError(
            "partial candidate evidence cannot be completed in this directory; "
            "preserve it and use a new empty --output-dir with the SAME "
            "--operation-intent and original artifacts to reconcile. "
            "Do not rebuild or change the version/build."
        ) from error


def _guard_complete_output(
    *, output_dir: Path, intent_path: Path, raw_path: Path,
    config: Any, stage: str, platform: str,
    candidate: Mapping[str, Any] | None = None,
    candidate_receipt: Mapping[str, Any] | None = None,
    external_receipt: Mapping[str, Any] | None = None,
    candidate_intent: Mapping[str, Any] | None = None,
    external_intent: Mapping[str, Any] | None = None,
) -> None:
    """Reject incompatible local finals before artifact checks or directory writes.

    This is an integrity/chain check, not GitHub authentication. The protected
    workflow resolver authenticates service artifacts; no local seal can replace
    that boundary. A surviving final must never fall back to Store execution.
    """

    receipt_path = output_dir / f"{stage}-receipt.json"
    if not receipt_path.exists() and not receipt_path.is_symlink():
        return
    try:
        receipt = load_release_receipt(receipt_path)
        intent = load_operation_intent(intent_path)
        if stage == "candidate":
            candidate = load_candidate_manifest(output_dir / "candidate-manifest.json")
            candidate_receipt = receipt
            candidate_intent = intent
        elif stage == "external-testing":
            external_receipt = receipt
            external_intent = intent
        if candidate is None:
            raise ValidationError("existing final evidence lacks its candidate manifest")
        validate_receipt_chain(
            candidate_manifest=candidate,
            candidate_receipt=candidate_receipt,
            external_receipt=external_receipt,
            production_receipt=receipt if stage == "production-submit" else None,
            candidate_intent=candidate_intent,
            external_intent=external_intent,
            production_intent=intent if stage == "production-submit" else None,
            platform=platform,
            config=config,
        )
        validate_receipt_raw_binding(
            receipt, store_receipt=load_store_receipt(raw_path),
            operation_intent=intent, candidate_manifest=candidate,
        )
    except ValidationError as error:
        raise ValidationError(
            "existing final evidence is incomplete or incompatible; preserve this "
            "directory and restore its exact original intent/raw receipt, or use "
            "a new empty --output-dir with the SAME authenticated operation intent "
            "and original artifacts. Do not rebuild or change the version/build."
        ) from error


def _ci(args: argparse.Namespace) -> int:
    modes = [args.prepare_operation, args.validate_operation_intent, args.execute_store]
    if sum(bool(value) for value in modes) != 1:
        raise ValidationError(
            "ci requires exactly one of --prepare-operation, "
            "--validate-operation-intent, or --execute-store"
        )
    # Keep temporary metadata alive through validation and final publication.
    # It must not appear beside incompatible surviving evidence as a side effect
    # of a failed invocation.
    with tempfile.TemporaryDirectory(prefix="mobile-release-intent-metadata-") as temporary:
        return _ci_operation(args, metadata_directory=Path(temporary))


def _ci_operation(args: argparse.Namespace, *, metadata_directory: Path) -> int:
    config = load_config(args.config)
    platform = args.platform
    stage = args.ci_command
    _require_ci_policy(config, platform, stage)
    release = config.release_version()
    source = git_context(config.root)
    output_dir = _repository_path(config, args.output_dir, label="output directory")
    if output_dir.exists() and not output_dir.is_dir():
        raise ValidationError("CI output path must be a directory")
    operation_intent_path = _repository_path(
        config,
        args.operation_intent or output_dir / f"{stage}-operation-intent.json",
        label="Store operation intent",
    )
    store_receipt_path = (
        _repository_path(config, args.store_receipt, label="Store receipt")
        if args.store_receipt
        else output_dir / "raw-store-receipt.json"
    )
    request = StoreRequest(
        stage=stage,
        platform=platform,
        confirmation=args.confirm,
        execute=args.execute_store,
        prepare=args.prepare_operation,
        output_dir=output_dir,
        store_receipt=store_receipt_path,
        store_precondition=output_dir / "store-precondition.json",
        operation_intent=operation_intent_path,
        recovery_run_id=args.recovery_run_id,
        recovery_confirmation=args.recovery_confirmation,
    )
    guard_ci_mutation(request=request, config=config, release=release, git=source)
    if stage == "candidate":
        _guard_partial_candidate_output(
            output_dir=output_dir, intent_path=operation_intent_path,
            raw_path=store_receipt_path, config=config, release=release,
            platform=platform, recovery_run_id=args.recovery_run_id,
        )
        _guard_complete_output(
            output_dir=output_dir, intent_path=operation_intent_path,
            raw_path=store_receipt_path, config=config, stage=stage, platform=platform,
        )
    authenticated_intent: dict[str, Any] | None = None
    if stage == "candidate":
        if operation_intent_path.exists():
            # Original signing validation is reusable only through the actual
            # original artifact/certificate/job proof, never a local seal, a
            # caller-supplied date, or an environment flag. No Store authority
            # is passed to the GitHub attestation verifier.
            authenticated_intent = authenticate_operation_intent(
                operation_intent_path, stage=stage, platform=platform,
            )
        elif not args.prepare_operation:
            raise ValidationError("an authenticated --operation-intent is required")
    candidate: dict[str, Any] | None = None
    candidate_receipt: dict[str, Any] | None = None
    external_receipt: dict[str, Any] | None = None
    candidate_intent: dict[str, Any] | None = None
    external_intent: dict[str, Any] | None = None
    candidate_path: Path | None = None
    if stage != "candidate":
        if not args.candidate_manifest:
            raise ValidationError(f"ci {stage} requires --candidate-manifest")
        candidate_path = _repository_path(
            config, args.candidate_manifest, label="candidate manifest", must_exist=True
        )
        candidate = load_candidate_manifest(candidate_path)
        if stage == "external-testing" and (
            candidate["source"]["commit"] != source.commit
            or candidate["source"]["tree"] != source.tree
        ):
            raise ValidationError(
                "external testing must check out the exact candidate source commit/tree; "
                "recovery uses the original operation source, not the new dispatch head"
            )
        candidate_intent_path = _repository_path(config, args.candidate_operation_intent or _evidence_intent_path(candidate_path, "candidate"), label="candidate operation intent", must_exist=True)
        candidate_intent = load_operation_intent(candidate_intent_path)
        _candidate_context_matches(config, candidate, platform)
        candidate_receipt_path = _repository_path(
            config,
            args.candidate_receipt or _adjacent(candidate_path, "candidate-receipt.json"),
            label="candidate receipt",
            must_exist=True,
        )
        candidate_receipt = load_release_receipt(candidate_receipt_path)
        if stage == "production-submit":
            if not args.external_receipt:
                raise ValidationError("ci production-submit requires --external-receipt")
            external_path = _repository_path(
                config, args.external_receipt, label="external receipt", must_exist=True
            )
            external_receipt = load_release_receipt(external_path)
            external_intent_path = _repository_path(config, args.external_operation_intent or _evidence_intent_path(external_path, "external-testing"), label="external operation intent", must_exist=True)
            external_intent = load_operation_intent(external_intent_path)
        validate_receipt_chain(
            candidate_manifest=candidate,
            candidate_receipt=candidate_receipt,
            external_receipt=external_receipt,
            platform=platform,
            config=config,
            require_production_eligible_external=stage == "production-submit",
            candidate_intent=candidate_intent,
            external_intent=external_intent,
        )
        _guard_complete_output(
            output_dir=output_dir, intent_path=operation_intent_path,
            raw_path=store_receipt_path, config=config, stage=stage, platform=platform,
            candidate=candidate, candidate_receipt=candidate_receipt,
            external_receipt=external_receipt, candidate_intent=candidate_intent,
            external_intent=external_intent,
        )

    artifacts = _parse_artifacts(args.artifact, config.root)
    for name, path in tuple(artifacts.items()):
        artifacts[name] = _repository_path(
            config, path, label=f"artifact {name}", must_exist=True
        )
    _validate_ci_artifact_selection(stage=stage, platform=platform, artifacts=artifacts)
    _set_artifact_environment(artifacts)

    signing_evidence: Mapping[str, Any] | None = None
    signing_validity: SigningValidityInterval | None = None
    records: list[dict[str, Any]] = []
    current_metadata = metadata_directory / "store-metadata.zip"
    build_metadata_archive(
        config.project_path(config.section("metadata").get("root", "release/store")),
        current_metadata,
        platform=platform,
    )
    metadata_hash = sha256_file(current_metadata)
    if stage == "candidate":
        primary = "android-aab" if platform == "android" else "ios-ipa"
        if authenticated_intent is not None:
            # Original authenticated native validation plus exact artifact and
            # configuration bindings supports recovery, not a new upload. The
            # Store executor gates every actual new send with current policy.
            if platform == "android":
                validate_aab_structure(artifacts[primary])
            else:
                archive, _entries = _validated_ipa_entries(artifacts[primary])
                archive.close()
            findings = []
            signing_evidence = dict(authenticated_intent["signing"][0])
        elif platform == "android":
            findings = validate_aab(
                artifacts[primary],
                expected_application_id=config.section("android")["applicationId"],
                release=release,
                expected_fingerprint=config.section("android")["uploadCertificateSha256"],
                require_tools=True,
                check_signer=True,
            )
        else:
            validated_ipa_sha256 = sha256_file(artifacts[primary])
            findings, signing_validity = validate_ipa_current_signing(
                artifacts[primary],
                expected_bundle_id=config.section("ios")["bundleId"],
                expected_team_id=config.section("ios")["teamId"],
                expected_fingerprint=config.section("ios")["distributionCertificateSha256"],
                release=release,
                require_tools=True,
            )
        failed = [item.code for item in findings if item.status in FAILING_STATUSES]
        if failed:
            raise ValidationError(
                f"final candidate artifact validation failed: {', '.join(failed)}"
            )
        if platform == "ios" and authenticated_intent is None:
            if signing_validity is None:
                raise ValidationError("candidate lacks complete current signing validity evidence")
            signing_evidence = ipa_signing_evidence(artifacts[primary])
            if sha256_file(artifacts[primary]) != validated_ipa_sha256:
                raise ValidationError("candidate IPA changed during signing validation")
        artifacts["store-metadata"] = current_metadata
        _set_artifact_environment(artifacts)
        records = artifact_records(artifacts.items())
        if platform == "ios" and authenticated_intent is None and next(item["sha256"] for item in records if item["logicalName"] == "ios-ipa") != validated_ipa_sha256:
            raise ValidationError("candidate IPA changed after signing validation")

    validate_evidence_context(source, stage=stage)

    if args.prepare_operation:
        if args.recovery_run_id:
            raise ValidationError("recovery runs cannot prepare a replacement operation intent")
        if operation_intent_path.exists():
            existing = authenticated_intent or load_operation_intent(operation_intent_path)
            validate_operation_intent_context(
                existing, config=config, release=release, git=source, stage=stage,
                platform=platform, confirmation=args.confirm, metadata_sha256=metadata_hash,
                artifacts=records, signing_evidence=signing_evidence,
                candidate_manifest=candidate, candidate_receipt=candidate_receipt,
                external_receipt=external_receipt,
            )
            print(json.dumps({"operationIntent": str(operation_intent_path), "sha256": existing["integrity"]["sha256"], "reused": True}))
            return 0
        validate_evidence_output_path(operation_intent_path)
        if store_receipt_path.exists():
            raise ValidationError(
                "existing raw Store evidence requires its original operation intent; "
                "preparation cannot replace an interrupted operation's authorization"
            )
        if stage == "candidate":
            copy_immutable_file(current_metadata, output_dir / "store-metadata.zip")
        precondition = prepare_store_operation(config=config, release=release, request=request)
        if platform == "ios" and stage == "candidate":
            assert signing_validity is not None
            validate_preparation_signing_time(
                signing_validity, precondition["snapshot"]["serverObservedAt"],
            )
        commitments = precondition.get("snapshot", {}).get("privateStateCommitments", {})
        intent = build_operation_intent(
            config=config,
            release=release,
            git=source,
            stage=stage,
            platform=platform,
            confirmation=args.confirm,
            metadata_sha256=metadata_hash,
            store_precondition=precondition,
            artifacts=records,
            signing_evidence=signing_evidence,
            candidate_manifest=candidate,
            candidate_receipt=candidate_receipt,
            external_receipt=external_receipt,
            private_state_commitments=commitments,
        )
        write_evidence(operation_intent_path, intent)
        print(
            json.dumps(
                {
                    "operationIntent": str(operation_intent_path),
                    "sha256": intent["integrity"]["sha256"],
                }
            )
        )
        return 0

    if not operation_intent_path.is_file():
        raise ValidationError("an authenticated --operation-intent is required")
    intent_document = authenticated_intent or load_operation_intent(operation_intent_path)
    intent = validate_operation_intent_context(
        intent_document,
        config=config,
        release=release,
        git=source,
        stage=stage,
        platform=platform,
        confirmation=args.confirm,
        metadata_sha256=metadata_hash,
        artifacts=records,
        signing_evidence=signing_evidence,
        candidate_manifest=candidate,
        candidate_receipt=candidate_receipt,
        external_receipt=external_receipt,
        recovery_run_id=args.recovery_run_id,
    )
    if args.validate_operation_intent:
        print(json.dumps({"operationIntent": str(operation_intent_path), "valid": True}))
        return 0

    if not (output_dir / f"{stage}-receipt.json").exists() and store_receipt_path.exists():
        # A raw-only partial output is evidence too. Validate it before creating
        # even the metadata/intent copies; an invalid observation is never a
        # reason to replace the receipt or call the Store again.
        validate_store_receipt(
            load_store_receipt(store_receipt_path), config=config, release=release,
            stage=stage, platform=platform, operation_intent=intent_document,
            recovery_run_id=args.recovery_run_id,
        )

    if stage == "candidate":
        manifest_path = output_dir / "candidate-manifest.json"
        receipt_path = output_dir / "candidate-receipt.json"
        if receipt_path.exists() and not manifest_path.exists():
            raise ValidationError("candidate receipt exists without its candidate manifest")
        manifest: dict[str, Any] | None = None
        if manifest_path.exists():
            manifest = load_candidate_manifest(manifest_path)
            validate_candidate_intent_binding(manifest, operation_intent=intent_document)
            payload = verify_sealed(manifest)
            if payload.get("operationIntentSha256") != intent_document["integrity"]["sha256"]:
                raise ValidationError("existing candidate manifest belongs to another operation intent")
            if payload.get("artifacts") != records:
                raise ValidationError("existing candidate manifest artifact set conflicts with intent")
        if receipt_path.exists():
            receipt = load_release_receipt(receipt_path)
            validate_receipt_chain(
                candidate_manifest=manifest,
                candidate_receipt=receipt,
                platform=platform,
                config=config,
                candidate_intent=intent_document,
            )
            if verify_sealed(receipt).get("operationIntentSha256") != intent_document["integrity"]["sha256"]:
                raise ValidationError("existing candidate receipt belongs to another operation intent")
            validate_receipt_raw_binding(
                receipt, store_receipt=load_store_receipt(store_receipt_path),
                operation_intent=intent_document, candidate_manifest=manifest,
            )
            print(json.dumps({"candidateManifest": str(manifest_path), "receipt": str(receipt_path), "reused": True}))
            return 0
        validate_evidence_output_path(receipt_path)
        if manifest is None:
            validate_evidence_output_path(manifest_path)
        # Publish only after validating all surviving output/context bindings.
        # Complete finals above are returned byte-for-byte without any copy.
        validate_immutable_copy(current_metadata, output_dir / "store-metadata.zip")
        validate_immutable_copy(operation_intent_path, output_dir / f"{stage}-operation-intent.json")
        copy_immutable_file(current_metadata, output_dir / "store-metadata.zip")
        copy_immutable_file(operation_intent_path, output_dir / f"{stage}-operation-intent.json")
        store = execute_store_operation(
            config=config, release=release, request=request, operation_intent=intent_document
        )
        if manifest is None:
            manifest = build_candidate_manifest(
                config=config,
                release=release,
                git=source,
                platform=platform,
                artifacts=records,
                store_receipt=store,
                metadata_sha256=metadata_hash,
                operation_intent=intent_document,
                signing_evidence=signing_evidence,
            )
            write_evidence(manifest_path, manifest)
        receipt = build_receipt(
            stage="candidate",
            platform=platform,
            candidate_manifest=manifest,
            store_receipt=store,
            operation_intent=intent_document,
        )
        write_evidence(receipt_path, receipt)
        print(json.dumps({"candidateManifest": str(manifest_path), "receipt": str(receipt_path)}))
        return 0

    assert candidate is not None and candidate_receipt is not None
    filename = (
        "external-testing-receipt.json"
        if stage == "external-testing"
        else "production-submit-receipt.json"
    )
    receipt_path = output_dir / filename
    if receipt_path.exists():
        existing = load_release_receipt(receipt_path)
        if verify_sealed(existing).get("operationIntentSha256") != intent_document["integrity"]["sha256"]:
            raise ValidationError("existing receipt belongs to another operation intent")
        validate_receipt_chain(
            candidate_manifest=candidate,
            candidate_receipt=candidate_receipt,
            external_receipt=existing if stage == "external-testing" else external_receipt,
            production_receipt=existing if stage == "production-submit" else None,
            platform=platform,
            config=config,
            candidate_intent=candidate_intent,
            external_intent=intent_document if stage == "external-testing" else external_intent,
            production_intent=intent_document if stage == "production-submit" else None,
        )
        validate_receipt_raw_binding(
            existing, store_receipt=load_store_receipt(store_receipt_path),
            operation_intent=intent_document, candidate_manifest=candidate,
        )
        print(json.dumps({"receipt": str(receipt_path), "reused": True}))
        return 0
    validate_evidence_output_path(receipt_path)
    # The exact attested authorization travels with every new final artifact.
    # Failure here still occurs before any Store mutation.
    copy_immutable_file(operation_intent_path, output_dir / f"{stage}-operation-intent.json")
    store = execute_store_operation(
        config=config, release=release, request=request, operation_intent=intent_document
    )
    predecessor = candidate_receipt if stage == "external-testing" else external_receipt
    receipt = build_receipt(
        stage=stage,
        platform=platform,
        candidate_manifest=candidate,
        store_receipt=store,
        operation_intent=intent_document,
        previous_receipt=predecessor,
    )
    write_evidence(receipt_path, receipt)
    print(json.dumps({"receipt": str(receipt_path)}))
    return 0

def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        handlers = {
            "init": _init,
            "doctor": _doctor,
            "credentials": _credentials,
            "preflight": _preflight,
            "status": _status,
            "explain": _explain,
            "ci": _ci,
        }
        return handlers[args.command](args)
    except MobileReleaseError as error:
        print(f"mobile-release: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("mobile-release: interrupted", file=sys.stderr)
        return 130
