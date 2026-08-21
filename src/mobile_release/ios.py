from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .config import ReleaseConfig, ReleaseVersion
from .credentials import artifact_validation_environment
from .discovery import discover_project, selected_ios_container, selected_ios_scheme
from .errors import ValidationError
from .reporting import Finding, Status
from .tooling import recreate_private_build_directory

MAX_ENTRY_SIZE = 1024 * 1024 * 1024
MAX_TOTAL_SIZE = 4 * 1024 * 1024 * 1024
ALLOWED_ARTIFACT_NAMES = {"ios-ipa", "ios-archive", "ios-dsyms"}
NESTED_CODE_SUFFIXES = {
    ".appex",
    ".app",
    ".dylib",
    ".framework",
    ".xpc",
}
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
MAX_NESTED_CODE_ITEMS = 512
PROFILE_UUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
MAX_GENERATED_FILES = 100_000
MAX_GENERATED_BYTES = 8 * 1024 * 1024 * 1024


def _validation_environment() -> dict[str, str]:
    return artifact_validation_environment(os.environ)


def _validated_ipa_entries(path: Path) -> tuple[zipfile.ZipFile, list[zipfile.ZipInfo]]:
    if path.is_symlink() or not path.is_file():
        raise ValidationError(f"IPA must be a regular non-symlink file: {path}")
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as error:
        raise ValidationError("IPA is not a valid ZIP archive") from error
    entries = archive.infolist()
    if len(entries) > 100_000:
        archive.close()
        raise ValidationError("IPA contains an unreasonable number of ZIP entries")
    seen: set[str] = set()
    portable_seen: set[str] = set()
    total = 0
    for entry in entries:
        raw_name = entry.filename
        portable_name = unicodedata.normalize("NFC", raw_name).casefold().rstrip("/")
        pure = PurePosixPath(raw_name)
        parts = raw_name.split("/")
        path_parts = parts[:-1] if raw_name.endswith("/") else parts
        mode = (entry.external_attr >> 16) & 0o170000
        if (
            not raw_name
            or raw_name.startswith("/")
            or "\\" in raw_name
            or pure.is_absolute()
            or any(part in {"", ".", ".."} for part in path_parts)
            or (mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)))
            or entry.flag_bits & 0x1
            or any(ord(character) < 32 or ord(character) == 127 for character in raw_name)
        ):
            archive.close()
            raise ValidationError(f"unsafe IPA entry path: {entry.filename}")
        if entry.filename in seen:
            archive.close()
            raise ValidationError(f"duplicate IPA entry: {entry.filename}")
        seen.add(entry.filename)
        if portable_name in portable_seen:
            archive.close()
            raise ValidationError(
                f"IPA has a case/Unicode-normalizing path collision: {entry.filename}"
            )
        portable_seen.add(portable_name)
        if entry.file_size > MAX_ENTRY_SIZE:
            archive.close()
            raise ValidationError(f"oversized IPA entry: {entry.filename}")
        total += entry.file_size
        if total > MAX_TOTAL_SIZE:
            archive.close()
            raise ValidationError("IPA uncompressed content exceeds safety limit")
    if archive.testzip() is not None:
        archive.close()
        raise ValidationError("IPA contains a corrupt entry")
    return archive, entries


def _profile_details(path: Path) -> dict[str, Any] | None:
    # Keep plist support lazy so Android-only/Linux use does not import the
    # platform XML parser at process start.
    import plistlib

    if sys.platform != "darwin" or not shutil.which("security"):
        return None
    result = subprocess.run(
        ["security", "cms", "-D", "-i", str(path)],
        env=_validation_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise ValidationError("security could not decode the embedded provisioning profile")
    try:
        value = plistlib.loads(result.stdout)
    except plistlib.InvalidFileException as error:
        raise ValidationError("embedded provisioning profile is not a valid plist") from error
    if not isinstance(value, dict):
        raise ValidationError("embedded provisioning profile has an invalid structure")
    return value


def _codesign_fingerprint(app_path: Path, temporary: Path) -> str | None:
    if sys.platform != "darwin" or not shutil.which("codesign") or not shutil.which("openssl"):
        return None
    verify = subprocess.run(
        ["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app_path)],
        env=_validation_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if verify.returncode:
        raise ValidationError("codesign rejected the exported application or nested code")
    return _codesign_leaf_fingerprint(app_path, temporary / "signer")


def _codesign_leaf_fingerprint(code_path: Path, prefix: Path) -> str:
    extract = subprocess.run(
        ["codesign", "-d", "--extract-certificates", str(prefix), str(code_path)],
        env=_validation_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    certificate = prefix.parent / f"{prefix.name}0"
    if extract.returncode or not certificate.is_file():
        raise ValidationError("codesign could not extract the leaf signing certificate")
    fingerprint = subprocess.run(
        [
            "openssl",
            "x509",
            "-inform",
            "DER",
            "-in",
            str(certificate),
            "-noout",
            "-fingerprint",
            "-sha256",
        ],
        env=_validation_environment(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if fingerprint.returncode:
        raise ValidationError("openssl could not inspect the leaf signing certificate")
    match = re.search(r"=([0-9A-Fa-f:]{64,95})", fingerprint.stdout)
    if not match:
        raise ValidationError("signing certificate output lacks a SHA-256 fingerprint")
    return match.group(1).replace(":", "").lower()


def _nested_codesign_identities(
    app_path: Path, temporary: Path
) -> list[tuple[Path, str, str]] | None:
    if sys.platform != "darwin" or not shutil.which("codesign") or not shutil.which("openssl"):
        return None
    def is_macho(path: Path) -> bool:
        if path.is_symlink() or not path.is_file():
            return False
        try:
            with path.open("rb") as handle:
                return handle.read(4) in MACHO_MAGICS
        except OSError as error:
            raise ValidationError(
                f"nested code could not be inspected safely: {path.name}"
            ) from error

    nested_candidates: set[Path] = set()
    for path in app_path.rglob("*"):
        if path.is_symlink():
            raise ValidationError(f"nested code must not be a symbolic link: {path.name}")
        if path.suffix.lower() in NESTED_CODE_SUFFIXES and (
            path.is_dir() or path.is_file()
        ):
            nested_candidates.add(path)
        if is_macho(path):
            nested_candidates.add(path)
        if path.name == "CodeResources" and path.parent.name == "_CodeSignature":
            signed_container = path.parent.parent
            if signed_container != app_path:
                nested_candidates.add(signed_container)
    nested = sorted(nested_candidates, key=lambda item: item.as_posix())
    if len(nested) > MAX_NESTED_CODE_ITEMS:
        raise ValidationError("IPA contains too many nested signed-code components")
    result: list[tuple[Path, str, str]] = []
    for index, code_path in enumerate(nested):
        requirement = subprocess.run(
            [
                "codesign",
                "--verify",
                "--strict",
                "--verbose=2",
                "--test-requirement",
                "=designated",
                str(code_path),
            ],
            env=_validation_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if requirement.returncode:
            raise ValidationError(
                f"nested code does not satisfy its designated requirement: {code_path.name}"
            )
        details = subprocess.run(
            ["codesign", "-d", "--verbose=4", str(code_path)],
            env=_validation_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if details.returncode:
            raise ValidationError(f"codesign could not inspect nested code: {code_path.name}")
        match = re.search(r"(?m)^TeamIdentifier=([A-Z0-9]{10})$", details.stderr + details.stdout)
        if not match:
            raise ValidationError(f"nested code lacks a TeamIdentifier: {code_path.name}")
        fingerprint = _codesign_leaf_fingerprint(
            code_path, temporary / f"nested-signer-{index}-"
        )
        if code_path.suffix.lower() in {".app", ".appex"}:
            entitlements = _codesign_entitlements(code_path)
            if entitlements is None:
                raise ValidationError(
                    f"nested application entitlements could not be inspected: {code_path.name}"
                )
            _validate_nested_bundle_security(
                code_path,
                entitlements=entitlements,
                team_id=match.group(1),
                signer_fingerprint=fingerprint,
            )
        result.append((code_path, match.group(1), fingerprint))
    return result


def _codesign_entitlements(app_path: Path) -> dict[str, Any] | None:
    if sys.platform != "darwin" or not shutil.which("codesign"):
        return None
    import plistlib

    result = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", "--xml", str(app_path)],
        env=_validation_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise ValidationError("codesign could not inspect the application's signed entitlements")
    try:
        payload = plistlib.loads(result.stdout)
    except plistlib.InvalidFileException as error:
        raise ValidationError("application signed entitlements are not a valid plist") from error
    if not isinstance(payload, dict):
        raise ValidationError("application signed entitlements have an invalid structure")
    return payload


def _profile_certificate_fingerprints(profile: dict[str, Any]) -> set[str]:
    certificates = profile.get("DeveloperCertificates")
    if not isinstance(certificates, list) or not certificates or any(
        not isinstance(certificate, bytes) or not certificate for certificate in certificates
    ):
        raise ValidationError("provisioning profile lacks valid developer certificates")
    return {hashlib.sha256(certificate).hexdigest() for certificate in certificates}


def _utc_datetime(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _validate_release_entitlement_environments(
    application: dict[str, Any], profile: dict[str, Any]
) -> None:
    expected_values = {
        "aps-environment": "production",
        "com.apple.developer.icloud-container-environment": "Production",
    }
    for key, expected in expected_values.items():
        app_present = key in application
        profile_present = key in profile
        if app_present != profile_present:
            raise ValidationError(f"signed app/profile entitlement presence differs for {key}")
        if app_present and (application[key] != expected or profile[key] != expected):
            raise ValidationError(f"signed app/profile {key} must use the production environment")


def _validate_nested_bundle_security(
    code_path: Path,
    *,
    entitlements: dict[str, Any],
    team_id: str,
    signer_fingerprint: str,
) -> None:
    """Bind a nested app/extension to its signer, profile, team, and release entitlements."""

    import plistlib

    info_path = code_path / "Info.plist"
    try:
        if (
            info_path.is_symlink()
            or not info_path.is_file()
            or info_path.stat().st_size > 2 * 1024 * 1024
        ):
            raise OSError("unsafe nested Info.plist")
        info = plistlib.loads(info_path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        raise ValidationError(
            f"nested application Info.plist is missing or invalid: {code_path.name}"
        ) from error
    bundle_id = info.get("CFBundleIdentifier") if isinstance(info, dict) else None
    application_identifier = entitlements.get("application-identifier")
    if (
        not isinstance(bundle_id, str)
        or not bundle_id
        or not isinstance(application_identifier, str)
        or application_identifier != f"{team_id}.{bundle_id}"
        or entitlements.get("com.apple.developer.team-identifier") != team_id
        or entitlements.get("get-task-allow") is True
    ):
        raise ValidationError(
            f"nested application entitlements do not match its signing team: {code_path.name}"
        )
    profile_path = code_path / "embedded.mobileprovision"
    if profile_path.is_symlink() or not profile_path.is_file():
        raise ValidationError(
            f"nested application lacks a safe embedded provisioning profile: {code_path.name}"
        )
    profile = _profile_details(profile_path)
    if profile is None:
        raise ValidationError(
            f"nested provisioning profile could not be inspected: {code_path.name}"
        )
    profile_entitlements = profile.get("Entitlements")
    teams = profile.get("TeamIdentifier")
    expiration = profile.get("ExpirationDate")
    if (
        not isinstance(profile_entitlements, dict)
        or profile_entitlements.get("application-identifier") != application_identifier
        or profile_entitlements.get("get-task-allow") is not False
        or profile_entitlements.get("beta-reports-active") is not True
        or not isinstance(teams, list)
        or team_id not in teams
        or profile.get("ProvisionedDevices")
        or profile.get("ProvisionsAllDevices")
        or not isinstance(expiration, datetime)
        or _utc_datetime(expiration) <= datetime.now(timezone.utc)
        or signer_fingerprint not in _profile_certificate_fingerprints(profile)
    ):
        raise ValidationError(
            f"nested provisioning profile does not authorize the final signer: {code_path.name}"
        )
    _validate_release_entitlement_environments(entitlements, profile_entitlements)


def _validate_generated_tree(
    root: Path,
    *,
    label: str,
    maximum_files: int = MAX_GENERATED_FILES,
    maximum_bytes: int = MAX_GENERATED_BYTES,
) -> None:
    if root.is_symlink() or not root.is_dir():
        raise ValidationError(f"{label} must be a real directory")
    count = 0
    total = 0
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in (*directories, *files):
            item = current_path / name
            if item.is_symlink():
                raise ValidationError(f"{label} must not contain symbolic links")
            count += 1
            if count > maximum_files:
                raise ValidationError(f"{label} contains too many generated entries")
            if item.is_file():
                total += item.stat().st_size
                if total > maximum_bytes:
                    raise ValidationError(f"{label} exceeds its generated-size safety bound")


def validate_ipa(
    path: Path,
    *,
    expected_bundle_id: str,
    expected_team_id: str,
    expected_fingerprint: str | None,
    release: ReleaseVersion,
    require_tools: bool = False,
) -> list[Finding]:
    import plistlib

    findings: list[Finding] = []
    try:
        archive, entries = _validated_ipa_entries(path)
    except ValidationError as error:
        return [Finding("ios.ipa.structure", Status.FAIL, str(error), category="ios-artifact")]
    try:
        plist_entries = [
            entry
            for entry in entries
            if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", entry.filename)
        ]
        if len(plist_entries) != 1:
            raise ValidationError(f"IPA must contain exactly one application; found {len(plist_entries)}")
        app_prefix = plist_entries[0].filename.removesuffix("Info.plist")
        try:
            info = plistlib.loads(archive.read(plist_entries[0]))
        except plistlib.InvalidFileException as error:
            raise ValidationError("IPA Info.plist is invalid") from error
        expectations = {
            "CFBundleIdentifier": expected_bundle_id,
            "CFBundleShortVersionString": release.name,
            "CFBundleVersion": str(release.build),
        }
        for key, expected in expectations.items():
            if str(info.get(key)) != expected:
                raise ValidationError(f"IPA {key} does not match the configured release value")
        executable = info.get("CFBundleExecutable")
        if not isinstance(executable, str) or not executable:
            raise ValidationError("IPA Info.plist lacks CFBundleExecutable")
        executable_entry = next(
            (entry for entry in entries if entry.filename == f"{app_prefix}{executable}"), None
        )
        if executable_entry is None or executable_entry.file_size == 0:
            raise ValidationError("IPA application executable is missing or empty")
        if not any(entry.filename == f"{app_prefix}_CodeSignature/CodeResources" for entry in entries):
            raise ValidationError("IPA application signature resources are missing")
        profile_entry = next(
            (entry for entry in entries if entry.filename == f"{app_prefix}embedded.mobileprovision"),
            None,
        )
        if profile_entry is None:
            raise ValidationError("IPA embedded provisioning profile is missing")
        findings.append(
            Finding(
                "ios.ipa.structure",
                Status.PASS,
                "IPA identity, version, executable, signature resources, and profile are present.",
                category="ios-artifact",
            )
        )

        with tempfile.TemporaryDirectory(prefix="mobile-release-ipa-") as temporary_string:
            temporary = Path(temporary_string)
            archive.extractall(temporary)
            app_path = temporary / app_prefix.rstrip("/")
            profile_path = app_path / "embedded.mobileprovision"
            profile = _profile_details(profile_path)
            profile_fingerprints: set[str] | None = None
            if profile is None:
                findings.append(
                    Finding(
                        "ios.ipa.profile",
                        Status.FAIL if require_tools else Status.SKIP,
                        "Provisioning-profile inspection requires macOS security tooling.",
                        category="ios-artifact",
                    )
                )
            else:
                entitlements = profile.get("Entitlements", {})
                if not isinstance(entitlements, dict):
                    raise ValidationError("profile entitlements have an invalid structure")
                app_identifier = entitlements.get("application-identifier")
                teams = profile.get("TeamIdentifier", [])
                expiration = profile.get("ExpirationDate")
                if app_identifier != f"{expected_team_id}.{expected_bundle_id}":
                    raise ValidationError("profile application-identifier does not match team and bundle")
                if expected_team_id not in teams:
                    raise ValidationError("profile TeamIdentifier does not match configuration")
                if entitlements.get("get-task-allow") is not False:
                    raise ValidationError("profile permits debugger attachment")
                if entitlements.get("beta-reports-active") is not True:
                    raise ValidationError("profile is not enabled for App Store/TestFlight distribution")
                if profile.get("ProvisionedDevices") or profile.get("ProvisionsAllDevices"):
                    raise ValidationError("profile is not an App Store distribution profile")
                if not isinstance(expiration, datetime) or _utc_datetime(expiration) <= datetime.now(
                    timezone.utc
                ):
                    raise ValidationError("profile is expired or lacks a valid expiration")
                profile_fingerprints = _profile_certificate_fingerprints(profile)
                findings.append(
                    Finding(
                        "ios.ipa.profile",
                        Status.PASS,
                        "Embedded App Store profile matches the approved app and team.",
                        category="ios-artifact",
                    )
                )

            entitlements = _codesign_entitlements(app_path)
            if entitlements is None:
                findings.append(
                    Finding(
                        "ios.ipa.entitlements",
                        Status.FAIL if require_tools else Status.SKIP,
                        "Signed-entitlement inspection requires macOS codesign.",
                        category="ios-artifact",
                    )
                )
            elif (
                entitlements.get("application-identifier")
                != f"{expected_team_id}.{expected_bundle_id}"
                or entitlements.get("com.apple.developer.team-identifier") != expected_team_id
                or entitlements.get("get-task-allow") is True
            ):
                raise ValidationError(
                    "application signed entitlements do not match the approved team/bundle release policy"
                )
            else:
                if profile is not None:
                    _validate_release_entitlement_environments(
                        entitlements, profile.get("Entitlements", {})
                    )
                findings.append(
                    Finding(
                        "ios.ipa.entitlements",
                        Status.PASS,
                        "Signed application entitlements satisfy bounded generic release checks.",
                        category="ios-artifact",
                    )
                )

            fingerprint = _codesign_fingerprint(app_path, temporary)
            if fingerprint is None:
                findings.append(
                    Finding(
                        "ios.ipa.signer",
                        Status.FAIL if require_tools else Status.SKIP,
                        "Deep code-signing inspection requires macOS codesign and openssl.",
                        category="ios-artifact",
                    )
                )
            elif expected_fingerprint and fingerprint != expected_fingerprint.replace(":", "").lower():
                raise ValidationError("IPA signer does not match the approved distribution certificate")
            elif profile_fingerprints is not None and fingerprint not in profile_fingerprints:
                raise ValidationError(
                    "IPA signer certificate is not authorized by the embedded provisioning profile"
                )
            else:
                nested_identities = _nested_codesign_identities(app_path, temporary)
                if nested_identities is None:
                    raise ValidationError(
                        "nested code identity inspection requires macOS codesign and openssl"
                    )
                for nested_path, team_id, nested_fingerprint in nested_identities:
                    if team_id != expected_team_id or nested_fingerprint != fingerprint:
                        raise ValidationError(
                            "nested code signer/team does not match the approved application: "
                            f"{nested_path.name}"
                        )
                findings.append(
                    Finding(
                        "ios.ipa.signer",
                        Status.PASS,
                        "IPA and every bounded nested-code identity match the approved signer/team.",
                        category="ios-artifact",
                    )
                )
    except ValidationError as error:
        findings.append(Finding("ios.ipa.validation", Status.FAIL, str(error), category="ios-artifact"))
    finally:
        archive.close()
    return findings


def ipa_signing_evidence(path: Path) -> dict[str, str]:
    """Extract public signing/profile identity from a previously validated IPA."""

    archive, entries = _validated_ipa_entries(path)
    try:
        profile_entries = [
            item
            for item in entries
            if re.fullmatch(r"Payload/[^/]+\.app/embedded\.mobileprovision", item.filename)
        ]
        if len(profile_entries) != 1:
            raise ValidationError("IPA must contain exactly one embedded provisioning profile")
        plist_entries = [
            item
            for item in entries
            if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", item.filename)
        ]
        if len(plist_entries) != 1:
            raise ValidationError("IPA must contain exactly one application")
        app_prefix = plist_entries[0].filename.removesuffix("Info.plist")
        with tempfile.TemporaryDirectory(prefix="mobile-release-profile-") as temporary_string:
            temporary = Path(temporary_string)
            archive.extractall(temporary)
            app_path = temporary / app_prefix.rstrip("/")
            profile_path = app_path / "embedded.mobileprovision"
            profile_path.write_bytes(archive.read(profile_entries[0]))
            profile = _profile_details(profile_path)
            signer_fingerprint = _codesign_fingerprint(app_path, temporary)
        if profile is None:
            raise ValidationError("iOS signing evidence extraction requires macOS security tooling")
        if signer_fingerprint is None:
            raise ValidationError("iOS signing evidence extraction requires codesign and openssl")
        profile_fingerprints = _profile_certificate_fingerprints(profile)
        if signer_fingerprint not in profile_fingerprints:
            raise ValidationError(
                "IPA signer certificate is not authorized by the embedded provisioning profile"
            )
        teams = profile.get("TeamIdentifier", [])
        expiration = profile.get("ExpirationDate")
        uuid = profile.get("UUID")
        entitlements = profile.get("Entitlements", {})
        if (
            len(teams) != 1
            or not isinstance(uuid, str)
            or not PROFILE_UUID_RE.fullmatch(uuid)
            or not isinstance(expiration, datetime)
            or _utc_datetime(expiration) <= datetime.now(timezone.utc)
            or not isinstance(entitlements, dict)
            or entitlements.get("get-task-allow") is not False
            or entitlements.get("beta-reports-active") is not True
            or profile.get("ProvisionedDevices")
            or profile.get("ProvisionsAllDevices")
        ):
            raise ValidationError("provisioning profile lacks stable public identity fields")
        return {
            "platform": "ios",
            "kind": "apple-distribution",
            "certificateSha256": signer_fingerprint,
            "teamId": teams[0],
            "profileUuid": uuid,
            "profileExpiresAt": _utc_datetime(expiration)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        }
    finally:
        archive.close()


def validate_xcarchive(
    archive: Path,
    *,
    expected_bundle_id: str,
    release: ReleaseVersion,
    symbols_policy: str,
    require_tools: bool = False,
) -> list[Finding]:
    """Validate effective archive identity/version before export or upload."""

    try:
        _validate_generated_tree(archive, label="xcarchive")
    except ValidationError as error:
        return [
            Finding(
                "ios.archive.structure",
                Status.FAIL,
                str(error),
                category="ios-artifact",
            )
        ]
    apps = [path for path in (archive / "Products/Applications").glob("*.app")]
    if len(apps) != 1 or apps[0].is_symlink():
        return [
            Finding(
                "ios.archive.structure",
                Status.FAIL,
                f"xcarchive must contain exactly one regular application; found {len(apps)}.",
                category="ios-artifact",
            )
        ]
    import plistlib

    info_path = apps[0] / "Info.plist"
    try:
        info = plistlib.loads(info_path.read_bytes())
    except (OSError, plistlib.InvalidFileException):
        return [
            Finding(
                "ios.archive.info",
                Status.FAIL,
                "Archived application Info.plist is missing or invalid.",
                category="ios-artifact",
            )
        ]
    expected = {
        "CFBundleIdentifier": expected_bundle_id,
        "CFBundleShortVersionString": release.name,
        "CFBundleVersion": str(release.build),
    }
    for key, value in expected.items():
        if str(info.get(key)) != value:
            return [
                Finding(
                    f"ios.archive.{key}",
                    Status.FAIL,
                    f"Archived application {key} does not match committed release configuration.",
                    category="ios-artifact",
                )
            ]
    executable_name = info.get("CFBundleExecutable")
    if (
        not isinstance(executable_name, str)
        or not executable_name
        or not (apps[0] / executable_name).is_file()
        or (apps[0] / executable_name).is_symlink()
    ):
        return [
            Finding(
                "ios.archive.executable",
                Status.FAIL,
                "Archived application executable is missing or unsafe.",
                category="ios-artifact",
            )
        ]
    findings = [
        Finding(
            "ios.archive.identity",
            Status.PASS,
            "Archived application identity and committed version match.",
            category="ios-artifact",
        )
    ]
    if symbols_policy == "disabled":
        findings.append(
            Finding(
                "ios.archive.dsym",
                Status.NOT_APPLICABLE,
                "dSYM validation is disabled by committed policy.",
                category="ios-artifact",
            )
        )
    else:
        findings.extend(validate_archive_dsyms(archive, require_tools=require_tools))
    return findings


def validate_archive_dsyms(archive: Path, *, require_tools: bool = False) -> list[Finding]:
    try:
        _validate_generated_tree(archive, label="xcarchive")
    except ValidationError as error:
        return [
            Finding(
                "ios.archive",
                Status.FAIL,
                str(error),
                category="ios-artifact",
            )
        ]
    apps = list((archive / "Products/Applications").glob("*.app"))
    dsyms = list((archive / "dSYMs").glob("*.app.dSYM"))
    if len(apps) != 1 or len(dsyms) != 1:
        return [
            Finding(
                "ios.archive.dsym",
                Status.FAIL,
                f"Expected one app and matching app dSYM; found {len(apps)} app(s), {len(dsyms)} dSYM(s).",
                category="ios-artifact",
            )
        ]
    import plistlib

    try:
        app_info = plistlib.loads((apps[0] / "Info.plist").read_bytes())
    except (OSError, plistlib.InvalidFileException):
        app_info = {}
    executable_name = app_info.get("CFBundleExecutable")
    if not isinstance(executable_name, str) or not executable_name:
        return [
            Finding(
                "ios.archive.dsym",
                Status.FAIL,
                "Archive application Info.plist lacks CFBundleExecutable.",
                category="ios-artifact",
            )
        ]
    executable = apps[0] / executable_name
    dsym_binary = dsyms[0] / "Contents/Resources/DWARF" / executable_name
    if not executable.is_file() or not dsym_binary.is_file():
        return [
            Finding(
                "ios.archive.dsym",
                Status.FAIL,
                "Archive executable or dSYM DWARF binary is missing.",
                category="ios-artifact",
            )
        ]
    if not shutil.which("dwarfdump"):
        return [
            Finding(
                "ios.archive.dsym",
                Status.FAIL if require_tools else Status.SKIP,
                "dwarfdump is unavailable for executable/dSYM UUID validation.",
                category="ios-artifact",
            )
        ]

    def uuids(path: Path) -> set[str]:
        result = subprocess.run(
            ["dwarfdump", "--uuid", str(path)],
            env=_validation_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise ValidationError(f"dwarfdump could not inspect {path.name}")
        return {value.lower() for value in re.findall(r"UUID: ([0-9A-Fa-f-]+)", result.stdout)}

    try:
        executable_uuids = uuids(executable)
        dsym_uuids = uuids(dsym_binary)
    except ValidationError as error:
        return [Finding("ios.archive.dsym", Status.FAIL, str(error), category="ios-artifact")]
    if not executable_uuids or executable_uuids != dsym_uuids:
        return [
            Finding(
                "ios.archive.dsym",
                Status.FAIL,
                "Archive executable and dSYM UUID sets do not match.",
                category="ios-artifact",
            )
        ]
    return [
        Finding(
            "ios.archive.dsym",
            Status.PASS,
            "Archive executable and dSYM UUID sets match.",
            category="ios-artifact",
        )
    ]


def _run_checked(
    argv: list[str],
    root: Path,
    timeout: int,
    *,
    environment_overrides: dict[str, str] | None = None,
) -> None:
    environment = os.environ.copy()
    environment.update(environment_overrides or {})
    try:
        result = subprocess.run(
            argv,
            cwd=root,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as error:
        raise ValidationError(f"command failed or timed out: {argv[0]}") from error
    if result.returncode:
        raise ValidationError(f"command failed with exit {result.returncode}: {argv[0]}")


def run_ios_build(config: ReleaseConfig, *, signed: bool) -> dict[str, Path]:
    if sys.platform != "darwin":
        raise ValidationError("iOS archive/export requires a macOS host")
    discovered = discover_project(config.root)
    container = selected_ios_container(config, discovered)
    scheme = selected_ios_scheme(config, discovered)
    if not container:
        raise ValidationError("Xcode project/workspace is ambiguous; configure ios.project or ios.workspace")
    if not scheme:
        raise ValidationError("shared Xcode scheme is ambiguous; configure ios.scheme")
    ios = config.section("ios")
    release = config.release_version()
    if prepare := ios.get("prepareCommand"):
        _run_checked(list(prepare), config.root, 10 * 60)
        discovered = discover_project(config.root)
        container = selected_ios_container(config, discovered)
        if not container:
            raise ValidationError("iOS preparation command did not produce the configured Xcode container")
    container_path = config.project_path(container[1])
    if not container_path.is_dir() or container_path.is_symlink():
        raise ValidationError("Configured Xcode project/workspace is missing or unsafe after preparation")

    build_root = recreate_private_build_directory(config, "ios")
    archive = build_root / "archive.xcarchive"
    container_flag = "-workspace" if container[0] == "workspace" else "-project"
    command = [
        "xcodebuild",
        container_flag,
        str(container_path),
        "-scheme",
        scheme,
        "-configuration",
        ios.get("archiveConfiguration", "Release"),
        "-destination",
        "generic/platform=iOS",
        "-archivePath",
        str(archive),
        "archive",
        f"MARKETING_VERSION={release.name}",
        f"CURRENT_PROJECT_VERSION={release.build}",
    ]
    if signed:
        profile = os.environ.get("MOBILE_RELEASE_IOS_PROFILE_SPECIFIER")
        if not profile:
            raise ValidationError("MOBILE_RELEASE_IOS_PROFILE_SPECIFIER is required for signed export")
        command.extend(
            [
                "MOBILE_RELEASE_IOS_CODE_SIGN_STYLE=Manual",
                f"MOBILE_RELEASE_IOS_DEVELOPMENT_TEAM={ios.get('teamId', '')}",
                f"MOBILE_RELEASE_IOS_PROVISIONING_PROFILE_SPECIFIER={profile}",
                "MOBILE_RELEASE_IOS_CODE_SIGN_IDENTITY=Apple Distribution",
            ]
        )
    else:
        command.extend(["CODE_SIGNING_ALLOWED=NO", "CODE_SIGNING_REQUIRED=NO"])
    build_environment = {
        "MOBILE_RELEASE_DEFER_EXTERNAL_UPLOADS": "1",
        "MOBILE_RELEASE_VERSION_NAME": release.name,
        "MOBILE_RELEASE_BUILD_NUMBER": str(release.build),
    }
    _run_checked(
        command,
        config.root,
        60 * 60,
        environment_overrides=build_environment,
    )
    archive = config.project_path(str(archive))
    _validate_generated_tree(archive, label="generated xcarchive")
    result_paths: dict[str, Path] = {"ios-archive": archive}
    dsym_source = archive / "dSYMs"
    dsym_destination = build_root / "dsyms"
    if dsym_source.is_dir():
        dsym_source = config.project_path(str(dsym_source))
        _validate_generated_tree(
            dsym_source,
            label="generated dSYMs",
            maximum_files=20_000,
            maximum_bytes=4 * 1024 * 1024 * 1024,
        )
        shutil.copytree(dsym_source, dsym_destination)
        result_paths["ios-dsyms"] = dsym_destination
    if not signed:
        return result_paths

    import plistlib

    export_options = {
        "method": "app-store-connect",
        "destination": "export",
        "signingStyle": "manual",
        "teamID": ios.get("teamId"),
        "signingCertificate": "Apple Distribution",
        "provisioningProfiles": {ios.get("bundleId"): os.environ["MOBILE_RELEASE_IOS_PROFILE_SPECIFIER"]},
        "stripSwiftSymbols": True,
        "uploadSymbols": False,
    }
    export_plist = build_root / "ExportOptions.plist"
    with export_plist.open("wb") as handle:
        plistlib.dump(export_options, handle, sort_keys=True)
    export_dir = build_root / "export"
    _run_checked(
        [
            "xcodebuild",
            "-exportArchive",
            "-archivePath",
            str(archive),
            "-exportPath",
            str(export_dir),
            "-exportOptionsPlist",
            str(export_plist),
        ],
        config.root,
        30 * 60,
        environment_overrides=build_environment,
    )
    export_dir = config.project_path(str(export_dir))
    _validate_generated_tree(export_dir, label="iOS export directory")
    ipas = list(export_dir.glob("*.ipa"))
    if len(ipas) != 1:
        raise ValidationError(f"expected one exported IPA, found {len(ipas)}")
    ipa_source = config.project_path(str(ipas[0]))
    if ipa_source.is_symlink() or not ipa_source.is_file():
        raise ValidationError("exported IPA must be a regular non-symlink file")
    ipa = build_root / "app.ipa"
    if ipa.is_symlink():
        raise ValidationError("normalized IPA destination must not be a symlink")
    shutil.copy2(ipa_source, ipa)
    result_paths["ios-ipa"] = ipa
    return result_paths
