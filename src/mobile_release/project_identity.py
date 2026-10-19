"""Bounded, passive application-identity analysis and exact-span preparation.

These objects are DATA, not filesystem or Store authority.  The native adapter
captures the complete inventory under its registered project lease.  A literal
source match is not proof of the identity produced by arbitrary build plugins;
the usual final-artifact identity validation is still required.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Mapping

from .config import ANDROID_ID_RE, IOS_ID_RE, parse_config_text
from .errors import ConfigurationError, ValidationError
from .init_transaction import validate_paths

CONFIG_PATH = "release/mobile-release.json"
IGNORE_PATH = ".gitignore"
MAX_FILES = 64
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_TOKENS = 200_000
MAX_DEPTH = 64
MAX_DIRECTORIES = 1024

_HELP = {
    "invalid-input": "Use one supported application target and bounded UTF-8 project files.",
    "unsafe-path": "Select a regular project file outside private, generated and dependency folders.",
    "missing-control": "Include this controlling project file and analyze the saved project again.",
    "invalid-config": "Correct and save the Mobile Release Kit project settings first.",
    "identity-mismatch": "The saved app ID and source app ID disagree. Resolve that conflict explicitly first.",
    "target-mismatch": "Select the same application module or Xcode project as the saved project settings.",
    "ambiguous-target": "Select one actual Android application module or native iOS application target.",
    "unsupported-syntax": "Use an unambiguous conventional literal setting, or change this file manually.",
    "dynamic-identity": "The app ID is computed or overridden here. Change its controlling source manually.",
    "unsupported-plugin": "A convention or unrecognized plugin may control the app ID. Review it manually.",
    "imported-control": "An external or generated build control is not supported for automatic identity editing.",
    "generated-project": "Change the generator's source configuration instead of editing generated project files.",
    "variant-identity": "This flavor or release suffix needs an explicit variant adapter. Change it manually.",
    "ambiguous-identity": "The selected configurations do not have one unambiguous literal app ID.",
    "conditional-config": "Conditional build settings or includes must be resolved manually before editing.",
    "include-cycle": "Remove the xcconfig include cycle before trying this edit.",
    "shared-control": "This setting also controls another target. Split the settings before editing one app.",
    "unsupported-plist": "Use a generated Info.plist or CFBundleIdentifier = $(PRODUCT_BUNDLE_IDENTIFIER).",
    "plist-override": "This Info.plist override or preprocessing can change the bundle ID. Review it manually before editing.",
    "scheme-selection": "Select a shared Xcode scheme that archives only this app and matches the saved archive configuration. Custom or scripted schemes need manual review.",
    "scheme-required": "Save a shared Xcode scheme for this application before changing its bundle ID.",
    "existing-application": "An existing or approved app keeps its identity. A new identity is a different app.",
    "new-intent-required": "Explicitly choose Set up a new app; this is not an update of the old app.",
    "dependent-service": "This app uses a provider configuration. Prepare a matching provider configuration manually first.",
    "stale-revision": "Saved inputs changed or this review is no longer current. Analyze again.",
}


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    path: str
    line: int = 1
    column: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "path": self.path, "line": self.line,
                "column": self.column, "help": _HELP[self.code]}


class IdentityInputError(ValueError):
    """Only a closed diagnostic crosses the public boundary, never source text."""

    def __init__(self, diagnostic: Diagnostic):
        self.diagnostic = diagnostic
        super().__init__("Project identity input was refused")


def refuse(code: str, path: str = CONFIG_PATH, text: str = "", offset: int = 0) -> None:
    # All paths reach this function only after public-path admission, or are
    # fixed internal constants.  Never reflect a parser exception or a value.
    prefix = text[:offset]
    raise IdentityInputError(Diagnostic(code, path, prefix.count("\n") + 1,
                                        len(prefix.rsplit("\n", 1)[-1]) + 1))


def need(value: bool, code: str = "invalid-input", path: str = CONFIG_PATH,
         text: str = "", offset: int = 0) -> None:
    if not value:
        refuse(code, path, text, offset)


def public_path(path: object) -> bool:
    if type(path) is not str or not 0 < len(path.encode("utf-8", "replace")) <= 512:
        return False
    parts = path.split("/")
    if len(parts) > 16 or any(not re.fullmatch(r"[A-Za-z0-9_.+ @()-]+", part) for part in parts):
        return False
    folded = tuple(part.casefold() for part in parts)
    return (not any(part in {".git", ".gradle", ".idea", ".mobile-release", "build",
                             "deriveddata", "pods", "node_modules", "private", "secrets",
                             "credentials", "xcuserdata"} or part.startswith(".mobile-release-")
                    for part in folded)
            and not any(part.startswith((".private-", ".codex-private-")) for part in folded)
            and all(part not in {"", ".", ".."} for part in parts))


def source_candidate(path: str) -> bool:
    """Closed filename vocabulary, shared with the native inventory reader."""
    name = PurePosixPath(path).name
    return (path in {CONFIG_PATH, IGNORE_PATH} or name in {
        "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
        "gradle.properties", "libs.versions.toml", "project.pbxproj", "project.yml",
        "project.yaml", "Project.swift", "Tuist.swift", "Info.plist",
    } or path.endswith((".xcconfig", ".xcscheme")))


@dataclass(frozen=True, slots=True)
class IdentitySelection:
    """Caller DATA; the service supplies continuity from its saved observation.

    Default to preserving an existing app.  'unknown' does not assert Store
    nonexistence and requires an explicit new-application preparation intent.
    iOS target is a PBXNativeTarget ID or exact unambiguous target name.
    """

    platform: str
    target: str
    project: str | None = None
    continuity: str = "existing"

    def as_dict(self) -> dict[str, Any]:
        return {"platform": self.platform, "target": self.target,
                "project": self.project, "continuity": self.continuity}


def selection_input(value: object) -> IdentitySelection:
    need(type(value) is IdentitySelection)
    need(value.platform in {"android", "ios"} and value.continuity in {"existing", "unknown"})
    need(type(value.target) is str and 0 < len(value.target) <= 255
         and re.fullmatch(r"[A-Za-z0-9_. :()-]+", value.target) is not None)
    if value.platform == "android":
        need(value.project is None and re.fullmatch(r":|:[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)*", value.target) is not None)
        need(value.target == ":" or public_path(value.target[1:].replace(":", "/") + "/build.gradle.kts"))
    else:
        need(public_path(value.project) and value.project.endswith(".xcodeproj"))
    return value


@dataclass(frozen=True, slots=True)
class Token:
    value: str
    start: int
    end: int
    kind: str = "atom"
    quote: str = ""

    @property
    def literal(self) -> bool:
        return self.kind == "string" and len(self.quote) == 1 and "\\" not in self.value and "$" not in self.value


def lex(text: str, path: str, *, pbx: bool = False) -> tuple[Token, ...]:
    """Small bounded lexer; comments/quoted decoys never become declarations."""
    tokens: list[Token] = []
    pos, length = 0, len(text)
    punctuation = "{}()[]=;,:" if pbx else "{}()[]=;,:.+-*/<>!?&|"
    while pos < length:
        start, char = pos, text[pos]
        if char.isspace():
            pos += 1
            continue
        if text.startswith("//", pos):
            end = text.find("\n", pos)
            pos = length if end < 0 else end
            continue
        if text.startswith("/*", pos):
            depth, pos = 1, pos + 2
            while depth and pos < length:
                if text.startswith("/*", pos):
                    depth, pos = depth + 1, pos + 2
                    need(depth <= MAX_DEPTH, "unsupported-syntax", path, text, start)
                elif text.startswith("*/", pos):
                    depth, pos = depth - 1, pos + 2
                else:
                    pos += 1
            need(depth == 0, "unsupported-syntax", path, text, start)
            continue
        if char in "\"'":
            quote = char * (3 if not pbx and text.startswith(char * 3, pos) else 1)
            pos += len(quote)
            inner = pos
            while pos < length and not text.startswith(quote, pos):
                if text[pos] == "\\":
                    pos += 2
                else:
                    pos += 1
            need(pos < length, "unsupported-syntax", path, text, start)
            value = text[inner:pos]
            pos += len(quote)
            tokens.append(Token(value, start, pos, "string", quote))
        elif char in punctuation:
            pos += 1
            tokens.append(Token(char, start, pos, "symbol"))
        else:
            pos += 1
            while (pos < length and not text[pos].isspace() and text[pos] not in punctuation + "\"'"
                   and not text.startswith(("//", "/*"), pos)):
                pos += 1
            tokens.append(Token(text[start:pos], start, pos))
        need(len(tokens) <= MAX_TOKENS, "unsupported-syntax", path, text, start)
    return tuple(tokens)


@dataclass(frozen=True, slots=True)
class Occurrence:
    path: str
    start: int  # Byte offsets, not Unicode-codepoint offsets.
    end: int
    value: str
    line: int
    column: int
    role: str


def occurrence(path: str, text: str, token: Token, role: str) -> Occurrence:
    start = token.start + len(token.quote)
    end = token.end - len(token.quote)
    prefix = text[:start]
    return Occurrence(path, len(prefix.encode("utf-8")), len(text[:end].encode("utf-8")),
                      token.value, prefix.count("\n") + 1, len(prefix.rsplit("\n", 1)[-1]) + 1, role)


def json_string_occurrence(text: str, route: tuple[str, ...]) -> Occurrence:
    """Locate an already schema-validated JSON string by its actual object path."""
    tokens = lex(text, CONFIG_PATH, pbx=True)
    found: list[Token] = []

    def visit(index: int, path: tuple[str, ...], depth: int = 0) -> int:
        need(depth <= MAX_DEPTH and index < len(tokens), "invalid-config")
        token = tokens[index]
        if token.value == "{" and token.kind == "symbol":
            index += 1
            while tokens[index].value != "}":
                key = tokens[index]
                need(key.kind == "string" and tokens[index + 1].value == ":", "invalid-config")
                # parse_config_text has already rejected duplicate keys.
                index = visit(index + 2, (*path, json.loads('"' + key.value + '"')), depth + 1)
                if tokens[index].value != ",":
                    break
                index += 1
            need(tokens[index].value == "}", "invalid-config")
            return index + 1
        if token.value == "[" and token.kind == "symbol":
            index += 1
            while tokens[index].value != "]":
                index = visit(index, (*path, "[]"), depth + 1)
                if tokens[index].value != ",":
                    break
                index += 1
            need(tokens[index].value == "]", "invalid-config")
            return index + 1
        if path == route:
            need(token.literal, "invalid-config")
            found.append(token)
        return index + 1

    try:
        need(visit(0, ()) == len(tokens) and len(found) == 1, "invalid-config")
    except (IndexError, ValueError, RecursionError):
        refuse("invalid-config")
    return occurrence(CONFIG_PATH, text, found[0], "saved-identity")


@dataclass(frozen=True, slots=True, repr=False)
class IdentityAnalysis:
    selection: IdentitySelection
    revision: str
    identity: str | None
    configured_identity: str | None
    identity_status: str | None
    configurations: tuple[str, ...]
    diagnostics: tuple[Diagnostic, ...]
    _sources: tuple[tuple[str, bytes], ...] = field(repr=False)
    _directories: tuple[str, ...] = field(repr=False)
    _occurrences: tuple[Occurrence, ...] = field(repr=False)

    @property
    def supported(self) -> bool:
        return not self.diagnostics

    @property
    def view(self) -> dict[str, Any]:
        next_step = (self.diagnostics[0].as_dict()["help"] if self.diagnostics else
                     "Keep this ID for an existing app. Choose Set up a new app only for a different application.")
        if self.supported and self.selection.platform == "ios":
            config = parse_config_text(dict(self._sources)[CONFIG_PATH].decode("utf-8"))
            if not config["ios"].get("scheme"):
                next_step = _HELP["scheme-required"]
        return {"schemaVersion": 1, "kind": "project-identity", "revision": self.revision,
                "selection": self.selection.as_dict(), "state": "supported" if self.supported else "unsupported",
                "identity": self.identity, "configuredIdentity": self.configured_identity,
                "identityStatus": self.identity_status, "configurations": list(self.configurations),
                "locations": [{"path": item.path, "line": item.line, "column": item.column,
                               "role": item.role} for item in self._occurrences],
                "diagnostics": [item.as_dict() for item in self.diagnostics],
                "nextStep": next_step,
                "scope": "recognized-literal-source-only", "buildVerificationRequired": True}


def analyze_project_identity(sources: Mapping[str, bytes], selection: IdentitySelection, *,
                             directories: tuple[str, ...] = ()) -> IdentityAnalysis:
    selection = selection_input(selection)
    need(isinstance(sources, Mapping) and 0 < len(sources) <= MAX_FILES)
    need(all(public_path(path) and source_candidate(path) for path in sources), "unsafe-path")
    try:
        validate_paths(list(sources))
    except ValidationError:
        refuse("unsafe-path")
    need(all(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES for raw in sources.values()))
    need(sum(map(len, sources.values())) <= MAX_TOTAL_BYTES)
    need(type(directories) is tuple and len(directories) <= MAX_DIRECTORIES
         and all(public_path(path) for path in directories))
    captured = tuple(sorted(sources.items()))
    texts: dict[str, str] = {}
    configured = status = identity = None
    occurrences: tuple[Occurrence, ...] = ()
    configurations: tuple[str, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    try:
        for path, raw in captured:
            try:
                texts[path] = raw.decode("utf-8")
                need(not texts[path].startswith("\ufeff") and "\x00" not in texts[path], "unsupported-syntax", path)
            except UnicodeError:
                refuse("unsupported-syntax", path)
        need(CONFIG_PATH in texts, "missing-control")
        try:
            config = parse_config_text(texts[CONFIG_PATH])
        except ConfigurationError:
            refuse("invalid-config")
        section = config[selection.platform]
        need(section.get("enabled") is True, "invalid-config")
        key = "applicationId" if selection.platform == "android" else "bundleId"
        configured, status = section[key], section["identityStatus"]
        config_span = json_string_occurrence(texts[CONFIG_PATH], (selection.platform, key))
        if selection.platform == "android":
            from .project_identity_android import analyze_android
            identity, occurrences, configurations = analyze_android(texts, selection, section, directories)
        else:
            from .project_identity_ios import analyze_ios
            identity, occurrences, configurations = analyze_ios(texts, selection, section, directories)
        need(identity == configured, "identity-mismatch", CONFIG_PATH, texts[CONFIG_PATH],
             len(texts[CONFIG_PATH].encode("utf-8")[:config_span.start].decode("utf-8")))
        occurrences = (*occurrences, config_span)
    except IdentityInputError as error:
        diagnostics = (error.diagnostic,)
    return IdentityAnalysis(selection, uuid.uuid4().hex, identity, configured, status, configurations,
                            diagnostics, captured, tuple(sorted(set(directories))), occurrences)


@dataclass(frozen=True, slots=True, repr=False)
class IdentityPreparation:
    analysis: IdentityAnalysis = field(repr=False)
    desired_identity: str
    intent: str
    _payloads: tuple[tuple[str, bytes], ...] = field(repr=False)

    @property
    def changed(self) -> bool:
        return bool(self._payloads)

    @property
    def view(self) -> dict[str, Any]:
        changes = [] if not self.changed else [{"path": item.path, "line": item.line,
            "column": item.column, "role": item.role, "beforeId": item.value,
            "afterId": self.desired_identity} for item in self.analysis._occurrences]
        return {"schemaVersion": 1, "kind": "project-identity-preview", "revision": self.analysis.revision,
                "selection": self.analysis.selection.as_dict(), "intent": self.intent,
                "state": "change" if self.changed else "unchanged", "changes": changes,
                "warnings": (["A different identity is a different app. This cannot update your existing app. "
                              "Availability in the stores has not been checked."] if self.changed else []),
                "invalidations": (["credential-assessments-and-assignments", "prepared-release-plans",
                                   "candidate-identity-revision"] if self.changed else []),
                "retainVersionReservations": True, "buildVerificationRequired": True}


def prepare_project_identity(analysis: IdentityAnalysis, desired_identity: str, *,
                             expected_revision: str, intent: str) -> IdentityPreparation:
    need(type(analysis) is IdentityAnalysis)
    if not analysis.supported:
        raise IdentityInputError(analysis.diagnostics[0])
    need(type(expected_revision) is str and expected_revision == analysis.revision, "stale-revision")
    pattern = ANDROID_ID_RE if analysis.selection.platform == "android" else IOS_ID_RE
    need(type(desired_identity) is str and len(desired_identity) <= 255
         and pattern.fullmatch(desired_identity) is not None)
    need(type(intent) is str and intent in {"preserve", "new-application"})
    if desired_identity == analysis.identity:
        return IdentityPreparation(analysis, desired_identity, intent, ())
    config = parse_config_text(dict(analysis._sources)[CONFIG_PATH].decode("utf-8"))
    section = config[analysis.selection.platform]
    need(analysis.selection.continuity == "unknown" and analysis.identity_status == "unverified"
         and not section.get("appStoreAppId"), "existing-application")
    need(intent == "new-application", "new-intent-required")
    service = "androidFirebase" if analysis.selection.platform == "android" else "iosFirebase"
    need(config["services"][service] == "disabled", "dependent-service")
    if analysis.selection.platform == "android":
        from .project_identity_android import check_android_identity_change
        check_android_identity_change({path: raw.decode("utf-8") for path, raw in analysis._sources}, analysis.selection)
    else:
        # An explicitly chosen native target permits passive setup analysis,
        # not a guess about a missing/auto-selected release scheme. Same-ID
        # no-ops above remain safe before archive setup is complete.
        need(bool(section.get("scheme")), "scheme-required")
    originals, rewritten = dict(analysis._sources), dict(analysis._sources)
    spans: dict[str, list[Occurrence]] = {}
    for item in analysis._occurrences:
        need(item.value == analysis.identity, "ambiguous-identity", item.path)
        spans.setdefault(item.path, []).append(item)
    for path, items in spans.items():
        after, end = originals[path], len(originals[path]) + 1
        for item in sorted(set(items), key=lambda value: value.start, reverse=True):
            need(0 <= item.start < item.end <= len(after) and item.end <= end)
            need(after[item.start:item.end] == item.value.encode("ascii"))
            after = after[:item.start] + desired_identity.encode("ascii") + after[item.end:]
            end = item.start
        need(len(after) <= MAX_FILE_BYTES)
        rewritten[path] = after
    checked = analyze_project_identity(rewritten, analysis.selection, directories=analysis._directories)
    need(checked.supported and checked.identity == desired_identity, "ambiguous-identity")
    payloads = tuple((path, rewritten[path]) for path in sorted(spans) if rewritten[path] != originals[path])
    return IdentityPreparation(analysis, desired_identity, intent, payloads)
