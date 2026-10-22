"""Literal Android applicationId adapter, not a Gradle evaluator/refactorer."""
from __future__ import annotations

import re
import tomllib
from pathlib import PurePosixPath
from typing import Any

from .config import ANDROID_ID_RE
from .discovery import parse_gradle_application_aliases
from .project_identity import (MAX_DEPTH, IdentitySelection, Occurrence, Token,
                               lex, need, occurrence, refuse)

_PLUGINS = frozenset({"com.android.application", "com.android.library",
    "org.jetbrains.kotlin.android", "org.jetbrains.kotlin.multiplatform",
    "org.jetbrains.kotlin.jvm", "org.jetbrains.kotlin.plugin.compose",
    "org.jetbrains.kotlin.plugin.serialization", "org.jetbrains.compose",
    "com.google.gms.google-services", "com.google.firebase.crashlytics"})
_PROVIDER_PLUGINS = frozenset({"com.google.gms.google-services", "com.google.firebase.crashlytics"})
_MUTATORS = frozenset({"afterEvaluate", "beforeEvaluate", "projectsEvaluated", "androidComponents",
    "applicationVariants", "setApplicationId", "setApplicationIdSuffix", "finalizeDsl",
    "beforeVariants", "onVariants", "extensions", "initWith"})


class _Scopes:
    def __init__(self, text: str, path: str):
        self.text, self.path = text, path
        self.tokens = lex(text, path)
        self.parents: list[tuple[int, ...]] = []
        self.pairs: dict[int, int] = {}
        braces: list[int] = []
        stack: list[int] = []
        for index, token in enumerate(self.tokens):
            self.parents.append(tuple(braces))
            if token.kind != "symbol":
                continue
            if token.value in {"{", "(", "["}:
                need(len(stack) < MAX_DEPTH, "unsupported-syntax", path, text, token.start)
                stack.append(index)
                if token.value == "{":
                    braces.append(index)
            elif token.value in {"}", ")", "]"}:
                need(bool(stack), "unsupported-syntax", path, text, token.start)
                opening = stack.pop()
                need(self.tokens[opening].value == {"}": "{", ")": "(", "]": "["}[token.value],
                     "unsupported-syntax", path, text, token.start)
                self.pairs[opening] = index
                if token.value == "}":
                    braces.pop()
        need(not stack, "unsupported-syntax", path, text, self.tokens[stack[-1]].start if stack else 0)

    def starts_statement(self, index: int) -> bool:
        if index == 0:
            return True
        before, token = self.tokens[index - 1], self.tokens[index]
        return (before.kind == "symbol" and before.value in {"{", "}", ";"}
                or "\n" in self.text[before.end:token.start]
                   and (before.kind != "symbol" or before.value in {")", "]", "}"}))

    def name(self, opening: int) -> str | None:
        tokens = self.tokens
        if opening and tokens[opening - 1].kind == "atom" and self.starts_statement(opening - 1):
            return tokens[opening - 1].value
        if (opening >= 4 and tokens[opening - 4].value in {"getByName", "named"}
                and self.starts_statement(opening - 4) and tokens[opening - 3].value == "("
                and tokens[opening - 2].literal and tokens[opening - 1].value == ")"):
            return tokens[opening - 2].value
        return None

    def blocks(self, name: str, parents: tuple[int, ...]) -> list[int]:
        return [index for index, token in enumerate(self.tokens)
                if token.kind == "symbol" and token.value == "{"
                and self.parents[index] == parents and self.name(index) == name]

    def literal(self, index: int) -> Token:
        """Exactly one standalone Groovy/KTS assignment/setter statement."""
        tokens, text, path = self.tokens, self.text, self.path
        original = tokens[index]
        need(self.starts_statement(index), "dynamic-identity", path, text, original.start)
        cursor = index + 1
        method = cursor < len(tokens) and tokens[cursor].value == "("
        if cursor < len(tokens) and tokens[cursor].value in {"=", "("}:
            cursor += 1
        need(cursor < len(tokens) and tokens[cursor].literal, "dynamic-identity", path, text, original.start)
        value = tokens[cursor]
        cursor += 1
        if method:
            need(cursor < len(tokens) and tokens[cursor].value == ")", "dynamic-identity", path, text, original.start)
            cursor += 1
        if cursor < len(tokens):
            tail = tokens[cursor]
            need((tail.kind == "symbol" and tail.value in {";", "}"})
                 or ("\n" in text[tokens[cursor - 1].end:tail.start]
                     and not (tail.kind == "symbol" and tail.value not in {"}"})),
                 "dynamic-identity", path, text, original.start)
        return value


def _catalog(texts: dict[str, str]) -> tuple[set[str], dict[str, str]]:
    path = "gradle/libs.versions.toml"
    source = texts.get(path, "")
    aliases = parse_gradle_application_aliases(source)
    if not source:
        return aliases, {}
    try:
        plugins = tomllib.loads(source).get("plugins", {})
        need(type(plugins) is dict, "unsupported-plugin", path)
        resolved = {}
        for name, declaration in plugins.items():
            plugin = declaration.get("id") if type(declaration) is dict else declaration
            if type(plugin) is str:
                normalized = re.sub(r"[-_.]+", ".", name)
                need(normalized not in resolved, "unsupported-plugin", path)
                resolved[normalized] = plugin
        return aliases, resolved
    except tomllib.TOMLDecodeError:
        refuse("unsupported-plugin", path)


def _application_plugin(scopes: _Scopes, aliases: set[str], catalog: dict[str, str],
                        parents: tuple[int, ...] = (), *, identity_change: bool = False) -> bool:
    tokens, path, text = scopes.tokens, scopes.path, scopes.text
    plugins = scopes.blocks("plugins", parents)
    need(len(plugins) <= 1, "unsupported-plugin", path)
    applied = False
    if plugins:
        opening = plugins[0]
        index = opening + 1
        while index < scopes.pairs[opening]:
            token = tokens[index]
            if token.kind == "symbol" and token.value == ";":
                index += 1
                continue
            need(scopes.parents[index] == (*parents, opening) and token.kind == "atom"
                 and token.value in {"id", "alias", "kotlin"}, "unsupported-plugin", path, text, token.start)
            cursor = index + 1
            parenthesized = tokens[cursor].value == "("
            cursor += int(parenthesized)
            if token.value in {"id", "kotlin"}:
                need(tokens[cursor].literal, "unsupported-plugin", path, text, token.start)
                plugin = tokens[cursor].value
                if token.value == "kotlin":
                    plugin = "org.jetbrains.kotlin." + plugin
                cursor += 1
            else:
                need(parenthesized, "unsupported-plugin", path, text, token.start)
                end = scopes.pairs[index + 1]
                accessor = "".join(item.value for item in tokens[cursor:end])
                need(accessor.startswith("libs.plugins."), "unsupported-plugin", path, text, token.start)
                alias = accessor[len("libs.plugins."):]
                plugin = "com.android.application" if alias in aliases else catalog.get(alias)
                cursor = end
            if parenthesized:
                need(tokens[cursor].value == ")", "unsupported-plugin", path, text, token.start)
                cursor += 1
            is_applied = True
            if cursor < len(tokens) and tokens[cursor].value == "version":
                cursor += 1
                # A literal plugin version is harmless; catalog versions were
                # already parsed as static DATA. Computed versions refuse.
                need(tokens[cursor].literal, "unsupported-plugin", path, text, token.start)
                cursor += 1
            if cursor < len(tokens) and tokens[cursor].value == "apply":
                cursor += 1
                need(tokens[cursor].value in {"true", "false"}, "unsupported-plugin", path, text, token.start)
                is_applied = tokens[cursor].value == "true"
                cursor += 1
            need(plugin in _PLUGINS, "unsupported-plugin", path, text, token.start)
            need(not identity_change or not is_applied or plugin not in _PROVIDER_PLUGINS,
                 "dependent-service", path, text, token.start)
            applied = applied or plugin == "com.android.application" and is_applied
            index = cursor
    for index, token in enumerate(tokens):
        if token.kind != "atom" or token.value != "apply" or scopes.parents[index] != parents:
            continue
        # Support only the old conventional apply plugin: '...' spelling.
        tail = tokens[index + 1:index + 7]
        offset = int(bool(tail) and tail[0].value == "(")
        need(scopes.starts_statement(index) and len(tail) >= offset + 3 and tail[offset].value == "plugin"
             and tail[offset + 1].value in {":", "="} and tail[offset + 2].literal,
             "imported-control", path, text, token.start)
        plugin = tail[offset + 2].value
        cursor = index + 1 + offset + 3
        if offset:
            need(cursor < len(tokens) and tokens[cursor].value == ")", "imported-control", path, text, token.start)
            cursor += 1
        need(cursor == len(tokens) or tokens[cursor].value in {";", "}"}
             or ("\n" in text[tokens[cursor - 1].end:tokens[cursor].start]
                 and (tokens[cursor].kind != "symbol" or tokens[cursor].value == "}")),
             "imported-control", path, text, token.start)
        need(plugin in _PLUGINS, "unsupported-plugin", path, text, token.start)
        need(not identity_change or plugin not in _PROVIDER_PLUGINS,
             "dependent-service", path, text, token.start)
        applied = applied or plugin == "com.android.application"
    return applied


def check_android_identity_change(texts: dict[str, str], selection: IdentitySelection) -> None:
    """Provider ownership follows applied source plugins, not an MRK toggle.

    Passive recognition and keeping the same ID remain possible. Changing the
    ID needs a separate matching provider setup, which this editor cannot read,
    create or migrate. Reuse the exact applied-plugin parser, including aliases.
    """
    folder = selection.target.lstrip(":").replace(":", "/")
    paths = [f"{folder + '/' if folder else ''}{name}" for name in ("build.gradle.kts", "build.gradle")]
    present = [path for path in paths if path in texts]
    need(len(present) == 1, "ambiguous-target", paths[0])
    path = present[0]
    aliases, catalog = _catalog(texts)
    _application_plugin(_Scopes(texts[path], path), aliases, catalog, identity_change=True)


def _controls(texts: dict[str, str], selected: str, directories: tuple[str, ...]) -> None:
    aliases, catalog = _catalog(texts)
    for path in (*texts, *directories):
        if any(part in {"buildSrc", "build-logic"} for part in PurePosixPath(path).parts):
            refuse("unsupported-plugin", path)
    parent = PurePosixPath(selected).parent
    ancestors = {str(value) for value in (parent, *parent.parents)}
    for path, text in texts.items():
        name = PurePosixPath(path).name
        if name not in {"settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts"}:
            continue
        scopes = _Scopes(text, path)
        # Root and settings plugins can control the selected module too. A
        # familiar module plugin does not license an unknown convention owner.
        _application_plugin(scopes, aliases, catalog)
        for opening in scopes.blocks("pluginManagement", ()):
            _application_plugin(scopes, aliases, catalog, (opening,))
        for index, token in enumerate(scopes.tokens):
            if token.kind != "atom":
                continue
            if token.value == "plugins" and not (index and scopes.tokens[index - 1].value == "."):
                parents = scopes.parents[index]
                allowed = not parents or (len(parents) == 1 and scopes.name(parents[0]) == "pluginManagement")
                need(allowed and index + 1 < len(scopes.tokens) and scopes.tokens[index + 1].value == "{",
                     "unsupported-plugin", path, text, token.start)
            if token.value in {"includeBuild", "includeFlat", "projectDir", "setProjectDir", "buildFileName",
                               "setBuildFileName", "allprojects", "subprojects", "resolutionStrategy",
                               "versionCatalogs", "setName"}:
                refuse("imported-control", path, text, token.start)
            if name.startswith("settings.gradle") and token.value in {"project", "findProject"}:
                refuse("imported-control", path, text, token.start)
            if token.value in _MUTATORS:
                refuse("dynamic-identity", path, text, token.start)
            if (path != selected and str(PurePosixPath(path).parent) in ancestors
                    and token.value in {"applicationId", "applicationIdSuffix"}):
                refuse("imported-control", path, text, token.start)
            if token.value == "apply":
                nearby = scopes.tokens[index + 1:index + 5]
                if any(value.value == "from" and value.kind == "atom" for value in nearby):
                    refuse("imported-control", path, text, token.start)
        if re.search(r"(?im)^[ \t]*(?://|/\*|\*)[^\r\n]*(?:generated by|do not edit)", text):
            refuse("generated-project", path)


def _settings(texts: dict[str, str], selection: IdentitySelection) -> None:
    """Only conventional root include statements establish the module path."""
    paths = [path for path in ("settings.gradle.kts", "settings.gradle") if path in texts]
    need(len(paths) <= 1, "ambiguous-target", "settings.gradle.kts")
    need(bool(paths) or selection.target == ":", "missing-control", "settings.gradle.kts")
    if not paths:
        return
    path = paths[0]
    scopes = _Scopes(texts[path], path)
    tokens, text = scopes.tokens, scopes.text
    included: set[str] = set()
    for index, token in enumerate(tokens):
        if token.kind != "atom" or token.value != "include":
            continue
        need(not scopes.parents[index] and scopes.starts_statement(index), "conditional-config", path, text, token.start)
        cursor = index + 1
        method = cursor < len(tokens) and tokens[cursor].value == "("
        cursor += int(method)
        while True:
            need(cursor < len(tokens) and tokens[cursor].literal, "imported-control", path, text, token.start)
            value = tokens[cursor]
            need(re.fullmatch(r":?[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)*", value.value) is not None
                 and all(part not in {".", ".."} for part in value.value.lstrip(":").split(":")),
                 "imported-control", path, text, value.start)
            module = ":" + value.value.lstrip(":")
            need(module not in included, "ambiguous-target", path, text, value.start)
            included.add(module)
            cursor += 1
            if cursor >= len(tokens) or tokens[cursor].value != ",":
                break
            cursor += 1
        if method:
            need(cursor < len(tokens) and tokens[cursor].value == ")", "imported-control", path, text, token.start)
            cursor += 1
        need(cursor == len(tokens) or tokens[cursor].value == ";"
             or "\n" in text[tokens[cursor - 1].end:tokens[cursor].start],
             "imported-control", path, text, token.start)
    need(selection.target == ":" or selection.target in included, "target-mismatch", path)


def analyze_android(texts: dict[str, str], selection: IdentitySelection, section: dict[str, Any],
                    directories: tuple[str, ...]) -> tuple[str, tuple[Occurrence, ...], tuple[str, ...]]:
    need(section.get("module") == selection.target, "target-mismatch")
    need(section.get("variant", "release") == "release", "variant-identity")
    folder = selection.target.lstrip(":").replace(":", "/")
    paths = [f"{folder + '/' if folder else ''}{name}" for name in ("build.gradle.kts", "build.gradle")]
    present = [path for path in paths if path in texts]
    need(len(present) == 1, "ambiguous-target", paths[0])
    path = present[0]
    _controls(texts, path, directories)
    _settings(texts, selection)
    scopes = _Scopes(texts[path], path)
    aliases, catalog = _catalog(texts)
    need(_application_plugin(scopes, aliases, catalog), "ambiguous-target", path)
    android = scopes.blocks("android", ())
    need(len(android) == 1, "dynamic-identity", path)
    defaults = scopes.blocks("defaultConfig", (android[0],))
    need(len(defaults) == 1, "dynamic-identity", path, scopes.text, scopes.tokens[android[0]].start)
    declarations: list[Token] = []
    for index, token in enumerate(scopes.tokens):
        if token.kind != "atom":
            continue
        if token.value in {"if", "when", "for", "while", "try", "return", "throw", "switch"} and (
                not scopes.parents[index] or android[0] in scopes.parents[index]):
            refuse("conditional-config", path, scopes.text, token.start)
        if token.value in {"productFlavors", "flavorDimensions"}:
            refuse("variant-identity", path, scopes.text, token.start)
        if token.value == "applicationId":
            need(scopes.parents[index] == (android[0], defaults[0]), "dynamic-identity", path, scopes.text, token.start)
            value = scopes.literal(index)
            need(len(value.value) <= 255 and ANDROID_ID_RE.fullmatch(value.value) is not None,
                 "dynamic-identity", path, scopes.text, token.start)
            declarations.append(value)
        if token.value == "applicationIdSuffix":
            parents = scopes.parents[index]
            names = tuple(scopes.name(opening) for opening in parents)
            need(names == ("android", "buildTypes", "debug"), "variant-identity", path, scopes.text, token.start)
            suffix = scopes.literal(index)
            need(re.fullmatch(r"\.[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*", suffix.value) is not None,
                 "variant-identity", path, scopes.text, token.start)
    need(len(declarations) == 1, "ambiguous-identity", path)
    found = occurrence(path, scopes.text, declarations[0], "android-application-id")
    return found.value, (found,), ("release",)
