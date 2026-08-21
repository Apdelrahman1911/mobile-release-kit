from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .config import ReleaseConfig, ReleaseVersion
from .credentials import artifact_validation_environment
from .discovery import discover_project, selected_android_module
from .errors import ValidationError
from .reporting import Finding, Status
from .tooling import canonical_external_path, recreate_private_build_directory

MAX_ENTRY_SIZE = 512 * 1024 * 1024
MAX_TOTAL_SIZE = 2 * 1024 * 1024 * 1024
MAX_ENTRY_COUNT = 100_000
ALLOWED_ARTIFACT_NAMES = {"android-aab", "android-mapping", "android-native-symbols"}
BUNDLETOOL_VERSION = "1.18.3"
BUNDLETOOL_SHA256 = "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29"


def _validation_environment() -> dict[str, str]:
    return artifact_validation_environment(os.environ)


def _validate_zip(path: Path) -> list[str]:
    if path.is_symlink() or not path.is_file():
        raise ValidationError(f"Android artifact must be a regular non-symlink file: {path}")
    try:
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) > MAX_ENTRY_COUNT:
                raise ValidationError("AAB contains an unreasonable number of ZIP entries")
            names: list[str] = []
            total = 0
            seen: set[str] = set()
            for entry in archive.infolist():
                raw_name = entry.filename
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
                ):
                    raise ValidationError(f"unsafe AAB entry path: {entry.filename}")
                if entry.filename in seen:
                    raise ValidationError(f"duplicate AAB entry: {entry.filename}")
                seen.add(entry.filename)
                if entry.file_size > MAX_ENTRY_SIZE:
                    raise ValidationError(f"oversized AAB entry: {entry.filename}")
                total += entry.file_size
                if total > MAX_TOTAL_SIZE:
                    raise ValidationError("AAB uncompressed content exceeds safety limit")
                names.append(entry.filename)
            if archive.testzip() is not None:
                raise ValidationError("AAB has a corrupt ZIP entry")
            return names
    except zipfile.BadZipFile as error:
        raise ValidationError(f"AAB is not a valid ZIP bundle: {path}") from error


def _bundletool_manifest(path: Path) -> str | None:
    jar_value = os.environ.get("MOBILE_RELEASE_BUNDLETOOL_JAR")
    if not jar_value:
        return None
    try:
        jar = canonical_external_path(Path(jar_value), label="bundletool")
    except (FileNotFoundError, OSError, ValidationError) as error:
        raise ValidationError(
            "bundletool must be a regular file without symbolic-link components"
        ) from error
    if not jar.is_file():
        raise ValidationError("bundletool must be a regular file without symbolic-link components")
    digest = hashlib.sha256()
    with jar.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != BUNDLETOOL_SHA256:
        raise ValidationError(
            f"bundletool must be the pinned {BUNDLETOOL_VERSION} JAR with its reviewed SHA-256"
        )
    try:
        result = subprocess.run(
            [
                "java",
                "-jar",
                str(jar),
                "dump",
                "manifest",
                f"--bundle={path}",
                "--module=base",
            ],
            env=_validation_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode:
        raise ValidationError("bundletool could not inspect the final AAB manifest")
    return result.stdout


def _signer_fingerprint(path: Path) -> str | None:
    environment = _validation_environment()
    try:
        result = subprocess.run(
            ["keytool", "-printcert", "-jarfile", str(path)],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode:
        raise ValidationError("keytool could not verify the final AAB signature")
    signer_blocks = re.findall(
        r"(?ms)^Signer #[0-9]+:\s*(.*?)(?=^Signer #[0-9]+:|\Z)", result.stdout
    )
    fingerprints: set[str] = set()
    if not signer_blocks:
        raise ValidationError("keytool output did not identify an unambiguous AAB signer")
    for block in signer_blocks:
        leaf = re.search(
            r"(?ms)^Certificate #1:\s*(.*?)(?=^Certificate #[0-9]+:|\Z)", block
        )
        match = re.search(
            r"(?m)^\s*SHA256:\s*([0-9A-Fa-f:]{64,95})\s*$",
            leaf.group(1) if leaf else "",
        )
        if not match:
            raise ValidationError("keytool output lacks a leaf SHA-256 signer fingerprint")
        fingerprints.add(match.group(1).replace(":", "").lower())
    if len(fingerprints) != 1:
        raise ValidationError("AAB has multiple distinct leaf signing certificates")
    return fingerprints.pop()


def _verify_jar_signature(path: Path) -> bool | None:
    """Verify every signed AAB entry; permit only the expected untrusted-root warning."""

    environment = _validation_environment()
    try:
        result = subprocess.run(
            ["jarsigner", "-verify", "-strict", str(path)],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
    except FileNotFoundError:
        return None
    except (subprocess.TimeoutExpired, OSError) as error:
        raise ValidationError("jarsigner could not complete final AAB verification") from error
    output = result.stdout + result.stderr
    forbidden_warning = re.search(
        r"(?i)(?:expired|not yet valid|disabled algorithm|algorithm (?:is )?disabled|"
        r"algorithm constraints|"
        r"treated as unsigned|unsigned entr|weak algorithm|certificate (?:is )?revoked|"
        r"invalid signature|digest error|keyusage|extendedkeyusage|netscapecerttype)",
        output,
    )
    self_signed = re.search(
        r"(?im)^This jar contains entries whose signer certificate is self-signed\.\s*$",
        output,
    )
    untrusted_self_signed_chain = re.search(
        r"(?im)^This jar contains entries whose certificate chain is invalid\. Reason: "
        r"PKIX path building failed: .*unable to find valid certification path to requested "
        r"target\s*$",
        output,
    )
    strict_diagnostics = re.findall(
        r"(?im)^(This jar contains entries whose .+|The signer certificate .+)$",
        output,
    )
    allowed_diagnostics = all(
        re.fullmatch(
            r"This jar contains entries whose signer certificate is self-signed\.",
            diagnostic,
            re.I,
        )
        or re.fullmatch(
            r"This jar contains entries whose certificate chain is invalid\. Reason: "
            r"PKIX path building failed: .*unable to find valid certification path to requested "
            r"target",
            diagnostic,
            re.I,
        )
        for diagnostic in strict_diagnostics
    )
    warning_sections = re.findall(
        r"(?ims)^Warning:\s*\n(.*?)(?=\n(?:Error|Warning):|\nRe-run|\Z)", output
    )
    allowed_warning = re.compile(
        r"This jar contains signatures that do not include a timestamp\."
        r"(?: Without a timestamp, users may not be able to validate this jar after any of the "
        r"signer certificates expire \(as early as [0-9]{4}-[0-9]{2}-[0-9]{2}\)\.)?",
        re.I,
    )
    warnings_allowed = all(
        allowed_warning.fullmatch(section.strip()) for section in warning_sections
    )
    # OpenJDK aggregates several unrelated failures into exit bit 4. Permit it
    # only when the sole exceptional condition is the expected self-signed
    # Android upload certificate; every validity/algorithm/content warning fails.
    if (
        result.returncode not in {0, 4}
        or not re.search(r"\bjar verified(?:, with signer errors)?\.\s*", output, re.I)
        or forbidden_warning
        or ("Warning:" in output and (not warning_sections or not warnings_allowed))
        or (
            result.returncode == 4
            and (
                not self_signed
                or not untrusted_self_signed_chain
                or not allowed_diagnostics
                or len(strict_diagnostics) != 2
            )
        )
    ):
        raise ValidationError("jarsigner rejected the final AAB signature or signed content")
    return True


def validate_aab(
    path: Path,
    *,
    expected_application_id: str,
    release: ReleaseVersion,
    expected_fingerprint: str | None,
    require_tools: bool = False,
    check_signer: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    try:
        names = _validate_zip(path)
        required_prefixes = ("base/manifest/", "base/dex/")
        for prefix in required_prefixes:
            if not any(name.startswith(prefix) for name in names):
                raise ValidationError(f"AAB is missing required {prefix} content")
        if not any(name == "BundleConfig.pb" for name in names):
            raise ValidationError("AAB is missing BundleConfig.pb")
        findings.append(
            Finding(
                "android.aab.structure",
                Status.PASS,
                f"Validated {len(names)} final AAB entries.",
                category="android-artifact",
            )
        )
    except ValidationError as error:
        return [Finding("android.aab.structure", Status.FAIL, str(error), category="android-artifact")]

    try:
        manifest = _bundletool_manifest(path)
    except ValidationError as error:
        findings.append(
            Finding("android.aab.manifest", Status.FAIL, str(error), category="android-artifact")
        )
        manifest = None
    if manifest is None:
        findings.append(
            Finding(
                "android.aab.manifest",
                Status.FAIL if require_tools else Status.SKIP,
                "bundletool manifest inspection is unavailable.",
                category="android-artifact",
                remediation="Set MOBILE_RELEASE_BUNDLETOOL_JAR to the pinned bundletool JAR.",
            )
        )
    else:
        expectations = {
            "package": expected_application_id,
            "versionCode": str(release.build),
            "versionName": release.name,
        }
        for attribute, expected in expectations.items():
            pattern = rf'(?:android:)?{attribute}="{re.escape(expected)}"'
            if not re.search(pattern, manifest):
                findings.append(
                    Finding(
                        f"android.aab.{attribute}",
                        Status.FAIL,
                        f"Final AAB {attribute} does not equal the configured release value.",
                        category="android-artifact",
                    )
                )
        if re.search(r'android:debuggable="true"|android:testOnly="true"', manifest):
            findings.append(
                Finding(
                    "android.aab.release-flags",
                    Status.FAIL,
                    "Final AAB is debuggable or test-only.",
                    category="android-artifact",
                )
            )
        elif not any(item.status == Status.FAIL for item in findings):
            findings.append(
                Finding(
                    "android.aab.manifest",
                    Status.PASS,
                    "Final AAB identity, version, and release flags match.",
                    category="android-artifact",
                )
            )

    if not check_signer:
        findings.append(
            Finding(
                "android.aab.signer",
                Status.SKIP,
                "AAB signer inspection is not applicable to unsigned offline preflight.",
                category="android-artifact",
            )
        )
    else:
        try:
            signature_verified = _verify_jar_signature(path)
        except ValidationError as error:
            findings.append(
                Finding("android.aab.signature", Status.FAIL, str(error), category="android-artifact")
            )
            signature_verified = False
        if signature_verified is None:
            findings.append(
                Finding(
                    "android.aab.signature",
                    Status.FAIL if require_tools else Status.SKIP,
                    "jarsigner is unavailable for final AAB signature verification.",
                    category="android-artifact",
                )
            )
        elif signature_verified:
            findings.append(
                Finding(
                    "android.aab.signature",
                    Status.PASS,
                    "jarsigner verified all final AAB signed content.",
                    category="android-artifact",
                )
            )
        if signature_verified is not True:
            return findings
        try:
            fingerprint = _signer_fingerprint(path)
        except ValidationError as error:
            findings.append(
                Finding("android.aab.signer", Status.FAIL, str(error), category="android-artifact")
            )
            fingerprint = None
        if fingerprint is None:
            findings.append(
                Finding(
                    "android.aab.signer",
                    Status.FAIL if require_tools else Status.SKIP,
                    "AAB signer fingerprint could not be inspected.",
                    category="android-artifact",
                )
            )
        elif expected_fingerprint and fingerprint != expected_fingerprint.replace(":", "").lower():
            findings.append(
                Finding(
                    "android.aab.signer",
                    Status.FAIL,
                    "Final AAB signer fingerprint does not match the approved upload certificate.",
                    category="android-artifact",
                )
            )
        else:
            findings.append(
                Finding(
                    "android.aab.signer",
                    Status.PASS,
                    "Final AAB signer fingerprint is approved.",
                    category="android-artifact",
                )
            )
    return findings


def _copy_unique(pattern: str, destination: Path, *, required: bool) -> Path | None:
    matches = [path for path in Path().glob(pattern) if path.is_file() and not path.is_symlink()]
    if len(matches) > 1:
        raise ValidationError(f"multiple release outputs match {pattern}")
    if not matches:
        if required:
            raise ValidationError(f"no release output matches {pattern}")
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(matches[0], destination)
    return destination


def run_android_build(config: ReleaseConfig, *, signed: bool) -> dict[str, Path]:
    discovered = discover_project(config.root)
    module = selected_android_module(config, discovered)
    if not module:
        raise ValidationError("Android application module is ambiguous; configure android.module")
    variant = config.section("android").get("variant", "release")
    task_variant = variant[:1].upper() + variant[1:]
    task = f"{module}:bundle{task_variant}" if module != ":" else f":bundle{task_variant}"
    wrapper = config.project_path("gradlew")
    if not wrapper.is_file():
        raise ValidationError("Gradle wrapper is missing")
    release = config.release_version()
    output = recreate_private_build_directory(config, "android")
    env = os.environ.copy()
    env["MOBILE_RELEASE_REQUIRE_SIGNING"] = "true" if signed else "false"
    # The committed release source is authoritative. Never let ambient CI
    # counters silently replace the reviewed version while Gradle evaluates.
    env["MOBILE_RELEASE_VERSION_NAME"] = release.name
    env["MOBILE_RELEASE_BUILD_NUMBER"] = str(release.build)
    try:
        result = subprocess.run(
            [str(wrapper), "--no-daemon", "--stacktrace", task],
            cwd=config.root,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=45 * 60,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        raise ValidationError("Android release build exceeded 45 minutes") from error
    if result.returncode:
        raise ValidationError(f"Android release task failed: {task}")

    module_relative = module.lstrip(":").replace(":", "/") or "."
    module_dir = config.project_path(module_relative)
    bundle_matches = sorted((module_dir / "build/outputs/bundle" / variant).glob("*.aab"))
    if len(bundle_matches) != 1:
        raise ValidationError(
            f"expected exactly one {variant} AAB, found {len(bundle_matches)} under {module_dir}"
        )
    bundle_source = config.project_path(str(bundle_matches[0]))
    if not bundle_source.is_file():
        raise ValidationError("release AAB output must be a regular file")
    aab = output / "app-release.aab"
    if aab.is_symlink():
        raise ValidationError("normalized AAB destination must not be a symlink")
    shutil.copy2(bundle_source, aab)
    result_paths = {"android-aab": aab}
    mapping = module_dir / "build/outputs/mapping" / variant / "mapping.txt"
    mapping = config.project_path(str(mapping))
    if mapping.is_file():
        destination = output / "mapping.txt"
        if mapping.is_symlink() or destination.is_symlink():
            raise ValidationError("R8 mapping source/destination must not be a symlink")
        shutil.copy2(mapping, destination)
        result_paths["android-mapping"] = destination
    native_candidates = sorted(
        path
        for path in (module_dir / "build/outputs").rglob("*.zip")
        if "native" in path.name.lower() and variant.lower() in str(path).lower()
    )
    if len(native_candidates) > 1:
        raise ValidationError("multiple native-symbol archives were produced")
    if native_candidates:
        native_source = config.project_path(str(native_candidates[0]))
        if not native_source.is_file():
            raise ValidationError("native-symbol output must be a regular file")
        destination = output / "native-symbols.zip"
        if native_source.is_symlink() or destination.is_symlink():
            raise ValidationError("native-symbol source/destination must not be a symlink")
        shutil.copy2(native_source, destination)
        result_paths["android-native-symbols"] = destination
    return result_paths
