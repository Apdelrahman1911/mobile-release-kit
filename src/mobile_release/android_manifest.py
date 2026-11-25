"""Bounded, namespace-aware policy for bundletool's base-manifest XML.

This is data inspection, not artifact custody, signing or Store authority. The
XML parser is loaded only on actual inspection: a restricted Desktop runtime
without pyexpat must refuse this operation, not fall back to text matching.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn

from .reporting import Finding, Status

if TYPE_CHECKING:
    from .cancellation import DefaultCancellation
    from .config import ReleaseVersion

ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ELEMENTS = 20_000
MAX_DEPTH = 64
MAX_ATTRIBUTES = 128
MAX_TOTAL_ATTRIBUTES = 100_000
MAX_NAMESPACES = 4096
MAX_NAME_CHARS = 512
MAX_VALUE_CHARS = 16_384
PARSE_CHUNK_BYTES = 8192

_MESSAGES = {
    "input": "The base manifest is not supported UTF-8 XML text.",
    "limit": "The base manifest exceeds the supported inspection limits.",
    "xml": "The base manifest is malformed or uses unsupported XML constructs.",
    "root": "The base manifest does not have the required manifest root.",
    "identity": "The manifest root is missing its package or Android version attributes.",
    "application": "The base manifest must contain one direct application element.",
    "flags": "Final AAB release flags could not be interpreted safely.",
    "runtime": "This runtime cannot inspect Android manifest XML.",
}


class ManifestInspectionError(ValueError):
    """Fixed public reason only; no parser text, input or private diagnostics."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(_MESSAGES[reason])


@dataclass(frozen=True)
class AndroidManifest:
    package: str
    version_code: str
    version_name: str
    debuggable: bool
    test_only: bool


def parse_android_manifest(
    text: str, *, cancellation: DefaultCancellation | None = None,
) -> AndroidManifest:
    """Inspect complete bounded XML, retaining only root identity and app flags.

    No tree, file, entity resolver or native command is created. Native Expat
    callbacks and each finite feed chunk cooperate with the original caller's
    cancellation/deadline owner. A running parser call is not forcibly preempted.
    """
    def check() -> None:
        if cancellation is not None:
            cancellation.check()

    def reject(reason: str) -> NoReturn:
        raise ManifestInspectionError(reason) from None

    check()
    if type(text) is not str:
        reject("input")
    # Bound before encoding/allocation; even the rejected UTF-8 encoding costs
    # at most four times this finite character ceiling, never the capture limit.
    if not text or len(text) > MAX_MANIFEST_BYTES:
        reject("limit")
    try:
        data = text.encode("utf-8", errors="strict")
    except UnicodeError:
        reject("input")
    if len(data) > MAX_MANIFEST_BYTES:
        reject("limit")
    # XML declaration keywords are case-sensitive exact literals. These checks
    # run before parsing; installed handlers below independently forbid DTD and
    # entity processing. Invalid spellings remain ordinary parse failures.
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        reject("xml")
    check()
    try:
        from xml.parsers import expat
    except ImportError:
        reject("runtime")

    parser = expat.ParserCreate(encoding="UTF-8", namespace_separator="}")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    depth = elements = attribute_count = namespace_count = applications = 0
    root_seen = False
    identity: tuple[str, str, str] | None = None
    flags: tuple[bool, bool] | None = None

    def forbidden(*_args: object) -> NoReturn:
        check()
        reject("xml")

    def declaration(version: str, encoding: str | None, _standalone: int) -> None:
        check()
        if version != "1.0" or (encoding is not None and encoding.lower() not in {"utf-8", "utf8"}):
            reject("xml")

    def namespace(prefix: str | None, uri: str | None) -> None:
        nonlocal namespace_count
        check()
        namespace_count += 1
        if (namespace_count > MAX_NAMESPACES or len(prefix or "") > MAX_NAME_CHARS
                or len(uri or "") > MAX_VALUE_CHARS):
            reject("limit")

    def flag(attributes: dict[str, str], name: str) -> bool:
        value = attributes.get(ANDROID_NAMESPACE + "}" + name)
        # Android's optional application flags default to false. Resource
        # references/unknown spellings are not a verified false value.
        if value is None or value in {"false", "0"}:
            return False
        if value in {"true", "1"}:
            return True
        reject("flags")

    def required_attribute(attributes: dict[str, str], name: str) -> str:
        value = attributes.get(name)
        if value is None or value == "":
            reject("identity")
        return value

    def start(name: str, attributes: dict[str, str]) -> None:
        nonlocal depth, elements, attribute_count, applications, root_seen, identity, flags
        check()
        depth += 1
        elements += 1
        attribute_count += len(attributes)
        if (depth > MAX_DEPTH or elements > MAX_ELEMENTS or len(name) > MAX_NAME_CHARS
                or len(attributes) > MAX_ATTRIBUTES or attribute_count > MAX_TOTAL_ATTRIBUTES
                or any(len(key) > MAX_NAME_CHARS or len(value) > MAX_VALUE_CHARS
                       for key, value in attributes.items())):
            reject("limit")
        if depth == 1:
            if root_seen or name != "manifest":
                reject("root")
            root_seen = True
            identity = (
                required_attribute(attributes, "package"),
                required_attribute(attributes, ANDROID_NAMESPACE + "}versionCode"),
                required_attribute(attributes, ANDROID_NAMESPACE + "}versionName"),
            )
        elif depth == 2 and name == "application":
            applications += 1
            if applications != 1:
                reject("application")
            flags = (flag(attributes, "debuggable"), flag(attributes, "testOnly"))

    def end(_name: str) -> None:
        nonlocal depth
        check()
        depth -= 1

    def characters(_text: str) -> None:
        check()

    parser.XmlDeclHandler = declaration
    parser.StartNamespaceDeclHandler = namespace
    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    parser.UnparsedEntityDeclHandler = forbidden
    parser.NotationDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = characters
    parser.CommentHandler = characters
    parser.ProcessingInstructionHandler = forbidden
    try:
        for offset in range(0, len(data), PARSE_CHUNK_BYTES):
            check()
            parser.Parse(data[offset:offset + PARSE_CHUNK_BYTES], False)
        check()
        parser.Parse(b"", True)
    except expat.ExpatError:
        reject("xml")
    check()
    if not root_seen or depth != 0 or identity is None:
        reject("root")
    if applications != 1 or flags is None:
        reject("application")
    return AndroidManifest(*identity, *flags)


def validate_android_manifest(
    text: str, *, expected_application_id: str, release: ReleaseVersion,
    cancellation: DefaultCancellation | None = None,
) -> list[Finding]:
    """Shared CLI/Desktop identity/version/flag policy, never regex searching."""
    try:
        manifest = parse_android_manifest(text, cancellation=cancellation)
    except ManifestInspectionError as error:
        return [Finding(
            "android.aab.release-flags" if error.reason == "flags" else "android.aab.manifest",
            Status.FAIL, str(error), category="android-artifact",
            remediation=("Use a qualified Mobile Release Kit runtime with its XML parser available."
                         if error.reason == "runtime" else
                         "Correct the application's manifest/build inputs and inspect a new AAB; do not promote this result."),
        )]
    findings: list[Finding] = []
    for name, actual, expected in (
        ("package", manifest.package, expected_application_id),
        ("versionCode", manifest.version_code, str(release.build)),
        ("versionName", manifest.version_name, release.name),
    ):
        if actual != expected:
            findings.append(Finding(
                f"android.aab.{name}", Status.FAIL,
                f"Final AAB {name} does not equal the configured release value.",
                category="android-artifact",
            ))
    if manifest.debuggable or manifest.test_only:
        findings.append(Finding(
            "android.aab.release-flags", Status.FAIL, "Final AAB is debuggable or test-only.",
            category="android-artifact",
        ))
    if not findings:
        findings.append(Finding(
            "android.aab.manifest", Status.PASS,
            "Final AAB identity, version, and release flags match.", category="android-artifact",
        ))
    return findings
