"""Bounded, passive build-tool hints from an already owned source snapshot.

No file lookup, Gradle/Xcode execution, dependency resolution or installation is
performed here. A literal is a source observation, NOT the effective build model
or permission to download a distribution. Callers retain the source snapshot and
invalidate these hints after any source/configuration change.
"""
from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass
from typing import Mapping

from .discovery import parse_gradle_application_aliases
from .toolchain_policy import XCODE_BUILD, XCODE_VERSION

FILE_LIMIT = 512 * 1024
TOTAL_LIMIT = 2 * 1024 * 1024
TOKEN_LIMIT = 100_000
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[+-][A-Za-z0-9.]+)?\Z", re.ASCII)
_FIXED = frozenset(("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
                    "gradle.properties", "gradle/libs.versions.toml", "gradle/wrapper/gradle-wrapper.properties"))


class RequirementsInputError(ValueError):
    def __init__(self) -> None:
        super().__init__("The saved build-tool source snapshot is invalid or exceeds its bounds.")


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    line: int


def _tokens(text: str) -> list[_Token]:
    """Small literal lexer; unsupported strings/expressions remain unknown."""
    out: list[_Token] = []
    index, line = 0, 1
    while index < len(text):
        ch = text[index]
        if ch.isspace():
            line += ch == "\n"
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0 or "/*" in text[index + 2:end]:
                raise RequirementsInputError()
            line += text.count("\n", index, end + 2)
            index = end + 2
            continue
        start = index
        if ch in "\"'":
            if text.startswith(ch * 3, index):
                raise RequirementsInputError()
            index += 1
            while index < len(text) and text[index] != ch:
                if text[index] in "\\\n\r":
                    raise RequirementsInputError()
                index += 1
            if index == len(text):
                raise RequirementsInputError()
            out.append(_Token("string", text[start + 1:index], line))
            index += 1
        elif ch.isascii() and (ch.isalnum() or ch == "_"):
            while index < len(text) and text[index].isascii() and (text[index].isalnum() or text[index] in "_."):
                index += 1
            value = text[start:index]
            out.append(_Token("number" if value.isdigit() else "word", value, line))
        else:
            out.append(_Token("symbol", ch, line))
            index += 1
        if len(out) > TOKEN_LIMIT:
            raise RequirementsInputError()
    return out


def _hint(values: list[str | None], *, optional: bool = False) -> dict[str, str | None]:
    distinct = set(values)
    if None in distinct or len(distinct) > 1:
        return {"state": "unknown", "value": None}
    if distinct:
        return {"state": "literal", "value": next(iter(distinct))}
    return {"state": "unspecified" if optional else "unknown", "value": None}


def _single_value(tokens: list[_Token], at: int, *, number: bool = False) -> str | None:
    end = at + 1
    if end < len(tokens) and tokens[end].value == "=":
        end += 1
    called = end < len(tokens) and tokens[end].value == "("
    end += called
    if end >= len(tokens):
        return None
    token = tokens[end]
    if token.kind != ("number" if number else "string") or "$" in token.value:
        return None
    end += 1
    if called:
        if end >= len(tokens) or tokens[end].value != ")":
            return None
        end += 1
    if end < len(tokens) and tokens[end].line == token.line and tokens[end].value not in (";", "}"):
        return None
    return token.value


def _catalog_versions(text: str) -> dict[str, str | None]:
    if not text:
        return {}
    try:
        aliases = parse_gradle_application_aliases(text)
        parsed = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError):
        return {}
    versions = parsed.get("versions", {})
    plugins = parsed.get("plugins", {})
    if not isinstance(versions, dict) or not isinstance(plugins, dict):
        return {}
    result: dict[str, str | None] = {}
    for name, spec in plugins.items():
        accessor = re.sub(r"[-_.]+", ".", name)
        if accessor not in aliases or not isinstance(spec, dict):
            continue
        version = spec.get("version")
        if isinstance(version, dict) and set(version) == {"ref"} and isinstance(version["ref"], str):
            version = versions.get(version["ref"])
        value = version if isinstance(version, str) and _VERSION.fullmatch(version) else None
        # Gradle normalizes -, _ and . to the same accessor. Ambiguous aliases
        # are not allowed to overwrite one another in a source hint.
        result[accessor] = None if accessor in result else value
    return result


def _plugin_tail(tokens: list[_Token], end: int) -> tuple[bool, str | None]:
    """Return (applied, literal version) for one conventional declaration."""
    version = None
    if end < len(tokens) and tokens[end].value == "version":
        end += 1
        called = end < len(tokens) and tokens[end].value == "("
        end += called
        if end >= len(tokens) or tokens[end].kind != "string" or not _VERSION.fullmatch(tokens[end].value):
            return False, None
        version = tokens[end].value
        end += 1
        if called:
            if end >= len(tokens) or tokens[end].value != ")":
                return False, None
            end += 1
    applied = True
    if end < len(tokens) and tokens[end].value == "apply":
        if end + 1 >= len(tokens) or tokens[end + 1].value not in ("false", "true"):
            return False, None
        applied = tokens[end + 1].value == "true"
        end += 2
    if end < len(tokens) and tokens[end].line == tokens[end - 1].line and tokens[end].value not in (";", "}"):
        return False, None
    return applied, version


def _gradle_hints(text: str, catalog: dict[str, str | None]) -> tuple[dict[str, list[str | None]], bool]:
    values: dict[str, list[str | None]] = {name: [] for name in ("jdk", "agp", "sdkPlatform", "sdkBuildTools")}
    tokens = _tokens(text)
    scope: list[str] = []
    app_plugin = False
    for at, token in enumerate(tokens):
        word = token.value
        if token.kind == "symbol" and word == "{":
            scope.append(tokens[at - 1].value if at else "?")
            if len(scope) > 32:
                raise RequirementsInputError()
            continue
        if token.kind == "symbol" and word == "}":
            if not scope:
                raise RequirementsInputError()
            scope.pop()
            continue
        if token.kind != "word":
            continue
        if word in ("compileSdk", "compileSdkVersion", "buildToolsVersion"):
            key = "sdkBuildTools" if word == "buildToolsVersion" else "sdkPlatform"
            value = _single_value(tokens, at, number=key == "sdkPlatform") if scope == ["android"] else None
            if value is not None:
                if key == "sdkPlatform":
                    value = "android-" + value if re.fullmatch(r"[1-9][0-9]{0,2}", value) else None
                elif not _VERSION.fullmatch(value):
                    value = None
            values[key].append(value)
        elif word == "jvmToolchain":
            value = _single_value(tokens, at, number=True) if scope == ["kotlin"] else None
            values["jdk"].append(value if value and re.fullmatch(r"[1-9][0-9]{0,2}", value) else None)
        elif word == "languageVersion":
            tail = tokens[at + 1:at + 7]
            good = (scope == ["java", "toolchain"] and len(tail) >= 5
                    and [item.value for item in tail[:3]] == ["=", "JavaLanguageVersion.of", "("]
                    and tail[3].kind == "number" and tail[4].value == ")"
                    and (len(tail) == 5 or tail[5].line != tail[4].line or tail[5].value in (";", "}")))
            values["jdk"].append(tail[3].value if good and re.fullmatch(r"[1-9][0-9]{0,2}", tail[3].value) else None)
        elif scope == ["plugins"] and word == "id":
            end = at + 1
            called = end < len(tokens) and tokens[end].value == "("
            end += called
            if end >= len(tokens) or tokens[end].kind != "string" or tokens[end].value != "com.android.application":
                continue
            end += 1
            if called:
                if end >= len(tokens) or tokens[end].value != ")":
                    values["agp"].append(None)
                    continue
                end += 1
            applied, version = _plugin_tail(tokens, end)
            app_plugin = app_plugin or applied
            if version is not None or end < len(tokens) and tokens[end].value == "version":
                values["agp"].append(version)
        elif scope == ["plugins"] and word == "alias":
            tail = tokens[at + 1:at + 4]
            if len(tail) == 3 and tail[0].value == "(" and tail[2].value == ")":
                alias = tail[1].value.removeprefix("libs.plugins.")
                if tail[1].value.startswith("libs.plugins.") and alias in catalog:
                    applied, override = _plugin_tail(tokens, at + 4)
                    app_plugin = app_plugin or applied
                    values["agp"].append(catalog[alias] if override is None else None)
    if scope:
        raise RequirementsInputError()
    return values, app_plugin


def _wrapper(text: str) -> dict[str, str | None]:
    result: dict[str, str | None] = {"state": "unknown", "version": None, "distributionUrl": None, "sha256": None}
    props: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        if "=" not in line or line.endswith("\\"):
            return result
        key, value = (part.strip() for part in line.split("=", 1))
        if key in props:
            return result
        props[key] = value.replace("\\:", ":")
    url = props.get("distributionUrl", "")
    version = re.fullmatch(r"https://(?:services|downloads)\.gradle\.org/distributions/gradle-([0-9]+\.[0-9]+(?:\.[0-9]+)?)-bin\.zip", url)
    digest = props.get("distributionSha256Sum")
    if not version or digest is not None and not re.fullmatch(r"[0-9a-f]{64}", digest):
        return result
    return {"state": "literal", "version": version[1], "distributionUrl": url, "sha256": digest}


def observe_tool_requirements(sources: Mapping[str, str], *, platform: str,
                              android_build_file: str | None = None, complete: bool) -> dict[str, object]:
    """Read-only service seam. `complete` describes the caller's bounded census.

    Missing files are fingerprinted too. The native application must supply its
    saved owned snapshot, not caller-nominated paths or renderer assertions.
    """
    if (type(sources) is not dict or len(sources) > 9 or type(complete) is not bool
            or platform not in ("android", "ios")):
        raise RequirementsInputError()
    selected = android_build_file
    if platform == "android":
        if (type(selected) is not str or len(selected) > 256
                or not re.fullmatch(r"(?:[A-Za-z0-9_-]+/){0,12}build\.gradle(?:\.kts)?", selected)):
            raise RequirementsInputError()
    elif selected is not None:
        raise RequirementsInputError()
    sibling = selected.removesuffix(".kts") if selected and selected.endswith(".kts") else selected + ".kts" if selected else None
    allowed = _FIXED | ({selected, sibling} if selected else set())
    total = 0
    fingerprint = hashlib.sha256(b"mrk-tool-requirements-v1\0")
    for name in sorted(allowed):
        text = sources.get(name)
        if text is not None and type(text) is not str:
            raise RequirementsInputError()
        try:
            raw = None if text is None else text.encode("utf-8")
        except UnicodeEncodeError:
            raise RequirementsInputError() from None
        if raw is not None:
            total += len(raw)
            if len(raw) > FILE_LIMIT or total > TOTAL_LIMIT or b"\0" in raw:
                raise RequirementsInputError()
        fingerprint.update(name.encode("ascii") + b"\0")
        fingerprint.update(b"missing\0" if raw is None else str(len(raw)).encode("ascii") + b"\0" + raw)
    if any(type(name) is not str or name not in allowed for name in sources):
        raise RequirementsInputError()
    fingerprint.update((platform + "\0" + (selected or "") + "\0" + str(complete)).encode("ascii"))
    result: dict[str, object] = {"schemaVersion": 1, "basis": "unverified-static-source-hints",
        "sourcesSha256": fingerprint.hexdigest(), "complete": complete, "platform": platform,
        "projectCodeExecuted": False, "android": None, "xcode": {"version": XCODE_VERSION, "build": XCODE_BUILD}}
    if platform == "ios":
        return result
    assert selected is not None
    aggregate: dict[str, list[str | None]] = {name: [] for name in ("jdk", "agp", "sdkPlatform", "sdkBuildTools")}
    parsed, app_plugin = complete, False
    try:
        catalog = _catalog_versions(sources.get("gradle/libs.versions.toml", ""))
        paths = sorted({selected, "build.gradle", "build.gradle.kts"} & sources.keys())
        if (selected not in sources or sibling in sources or "build.gradle" in sources and "build.gradle.kts" in sources
                or "settings.gradle" in sources and "settings.gradle.kts" in sources):
            parsed = False
        for name in paths:
            hints, application = _gradle_hints(sources[name], catalog)
            if name == selected:
                app_plugin = application
            for key, values in hints.items():
                aggregate[key].extend(values)
        # Build-logic inclusions/property overrides are not silently resolved.
        for name in (*paths, "settings.gradle", "settings.gradle.kts", "gradle.properties"):
            body = sources.get(name, "")
            if re.search(r"\b(includeBuild|apply\s*(?:\(|from)|org\.gradle\.java\.home|afterEvaluate)\b", body):
                parsed = False
    except RequirementsInputError:
        parsed = False
    if not parsed or not app_plugin:
        aggregate = {key: [None] for key in aggregate}
    android: dict[str, object] = {key: _hint(values, optional=key in ("jdk", "sdkBuildTools")) for key, values in aggregate.items()}
    android["gradle"] = _wrapper(sources.get("gradle/wrapper/gradle-wrapper.properties", "") if parsed else "")
    result["android"] = android
    return result
