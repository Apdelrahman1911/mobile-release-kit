"""Conventional native Xcode target/xcconfig identity adapter, without xcodebuild."""
from __future__ import annotations

import plistlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .config import IOS_ID_RE
from .project_identity import (CONFIG_PATH, MAX_DEPTH, IdentitySelection, Occurrence, Token,
                               json_string_occurrence, lex, need, occurrence, public_path, refuse)

_PLIST_OVERRIDES = frozenset({"INFOPLIST_KEY_CFBundleIdentifier", "INFOPLIST_PREPROCESS",
    "INFOPLIST_PREFIX_HEADER", "INFOPLIST_PREPROCESSOR_DEFINITIONS", "INFOPLIST_OTHER_PREPROCESSOR_FLAGS",
    "INFOPLIST_EXPAND_BUILD_SETTINGS"})
_SETTINGS = frozenset({"PRODUCT_BUNDLE_IDENTIFIER", "INFOPLIST_FILE", "GENERATE_INFOPLIST_FILE",
                       "CODE_SIGN_ENTITLEMENTS"}) | _PLIST_OVERRIDES


def _atom(value: Any, path: str, text: str = "") -> Token:
    need(type(value) is Token and value.kind in {"atom", "string"}, "unsupported-syntax", path, text)
    return value


def _value(value: Any, path: str) -> str:
    return _atom(value, path).value


def _object(value: Any, path: str) -> dict[str, Any]:
    need(type(value) is dict, "unsupported-syntax", path)
    return value


def _array(value: Any, path: str) -> list[Any]:
    need(type(value) is list, "unsupported-syntax", path)
    return value


class _Project:
    def __init__(self, path: str, text: str):
        self.path, self.text = path, text
        tokens = lex(text, path, pbx=True)
        self.tokens = tokens

        def parse(index: int, depth: int = 0) -> tuple[Any, int]:
            need(depth <= MAX_DEPTH and index < len(tokens), "unsupported-syntax", path)
            token = tokens[index]
            if token.kind == "symbol" and token.value == "{":
                result: dict[str, Any] = {}
                index += 1
                while index < len(tokens) and tokens[index].value != "}":
                    key = _atom(tokens[index], path, text)
                    need(key.value not in result and tokens[index + 1].value == "=",
                         "unsupported-syntax", path, text, key.start)
                    result[key.value], index = parse(index + 2, depth + 1)
                    need(tokens[index].value == ";", "unsupported-syntax", path, text, tokens[index].start)
                    index += 1
                need(index < len(tokens), "unsupported-syntax", path, text, token.start)
                return result, index + 1
            if token.kind == "symbol" and token.value == "(":
                values: list[Any] = []
                index += 1
                while index < len(tokens) and tokens[index].value != ")":
                    value, index = parse(index, depth + 1)
                    values.append(value)
                    if tokens[index].value != ",":
                        break
                    index += 1
                need(tokens[index].value == ")", "unsupported-syntax", path, text, token.start)
                return values, index + 1
            return _atom(token, path, text), index + 1

        try:
            document, end = parse(0)
            need(end == len(tokens), "unsupported-syntax", path)
            self.objects = _object(_object(document, path).get("objects"), path)
            need(0 < len(self.objects) <= 8192, "unsupported-syntax", path)
            self.root_id = _value(document.get("rootObject"), path)
            self.root = self.get(self.root_id, "PBXProject")
            self.main_group = _value(self.root.get("mainGroup"), path)
            self.target_ids = tuple(_value(item, path) for item in _array(self.root.get("targets"), path))
            need(len(set(self.target_ids)) == len(self.target_ids), "ambiguous-target", path)
        except (IndexError, RecursionError):
            refuse("unsupported-syntax", path)
        self.group_parents: dict[str, list[str]] = {}
        for identifier, body in self.objects.items():
            body = _object(body, path)
            kind = _value(body.get("isa"), path)
            if kind in {"PBXGroup", "PBXVariantGroup", "XCVersionGroup"}:
                for child in _array(body.get("children", []), path):
                    self.group_parents.setdefault(_value(child, path), []).append(identifier)
        self.base = str(PurePosixPath(path).parent.parent)
        if self.base == ".":
            self.base = ""

    def get(self, identifier: str, kind: str | None = None) -> dict[str, Any]:
        value = _object(self.objects.get(identifier), self.path)
        if kind is not None:
            need(_value(value.get("isa"), self.path) == kind, "unsupported-syntax", self.path)
        return value

    def configs(self, body: dict[str, Any]) -> tuple[tuple[str, dict[str, Any]], ...]:
        config_list = self.get(_value(body.get("buildConfigurationList"), self.path), "XCConfigurationList")
        items = _array(config_list.get("buildConfigurations"), self.path)
        need(0 < len(items) <= 32, "unsupported-syntax", self.path)
        result = tuple((name, self.get(name, "XCBuildConfiguration"))
                       for name in (_value(item, self.path) for item in items))
        names = [_value(config.get("name"), self.path) for _, config in result]
        for (_, config), name in zip(result, names):
            token = _atom(config.get("name"), self.path)
            need(0 < len(name) <= 80 and re.fullmatch(r"[A-Za-z0-9_. -]+", name) is not None,
                 "unsupported-syntax", self.path, self.text, token.start)
        need(len(set(names)) == len(names) and len(set(name for name, _ in result)) == len(result),
             "ambiguous-identity", self.path)
        return result

    def relative(self, base: str, raw: str, token: Token, *, root_variable: bool = False,
                 origin_path: str | None = None, origin_text: str | None = None) -> str:
        origin_path = self.path if origin_path is None else origin_path
        origin_text = self.text if origin_text is None else origin_text
        if root_variable:
            for prefix in ("$(SRCROOT)/", "${SRCROOT}/", "$(PROJECT_DIR)/", "${PROJECT_DIR}/"):
                if raw.startswith(prefix):
                    raw, base = raw[len(prefix):], self.base
                    break
        need(bool(raw) and not raw.startswith("/") and "$" not in raw and "\\" not in raw,
             "imported-control", origin_path, origin_text, token.start)
        parts = [part for part in base.split("/") if part]
        for part in raw.split("/"):
            if part == "..":
                need(bool(parts), "imported-control", origin_path, origin_text, token.start)
                parts.pop()
            elif part not in {".", ""}:
                parts.append(part)
        path = "/".join(parts)
        need(public_path(path), "imported-control", origin_path, origin_text, token.start)
        return path

    def file_path(self, identifier: str, visiting: tuple[str, ...] = ()) -> str:
        need(identifier not in visiting and len(visiting) < MAX_DEPTH, "shared-control", self.path)
        body = self.get(identifier)
        kind = _value(body.get("isa"), self.path)
        need(kind in {"PBXGroup", "PBXFileReference"}, "imported-control", self.path)
        source = _value(body.get("sourceTree"), self.path)
        token = _atom(body.get("path", Token("", 0, 0)), self.path)
        if source == "SOURCE_ROOT":
            base = self.base
        elif source == "<group>":
            parents = self.group_parents.get(identifier, [])
            if identifier == self.main_group:
                need(not parents, "shared-control", self.path)
                base = self.base
            else:
                need(len(parents) == 1, "shared-control", self.path, self.text, token.start)
                base = self.file_path(parents[0], (*visiting, identifier))
        else:
            refuse("imported-control", self.path, self.text, token.start)
        if not token.value and kind == "PBXGroup":
            return base
        return self.relative(base, token.value, token)


@dataclass(frozen=True)
class _Setting:
    token: Token
    path: str
    text: str

    def occurrence(self) -> Occurrence:
        return occurrence(self.path, self.text, self.token, "ios-bundle-id")


class _Settings:
    def __init__(self, project: _Project, texts: dict[str, str]):
        self.project, self.texts = project, texts
        self.cache: dict[str, dict[str, _Setting]] = {}

    def xcconfig(self, path: str, visiting: tuple[str, ...] = ()) -> dict[str, _Setting]:
        need(path not in visiting and len(visiting) < 16, "include-cycle", path)
        if path in self.cache:
            return dict(self.cache[path])
        need(path in self.texts, "missing-control", path)
        text = self.texts[path]
        # Retain offsets while hiding comments. Quoted // and /* are preserved.
        masked = [char if char in "\r\n" else " " for char in text]
        for token in lex(text, path, pbx=True):
            masked[token.start:token.end] = text[token.start:token.end]
        values: dict[str, _Setting] = {}
        offset = 0
        for raw_line in "".join(masked).splitlines(keepends=True):
            line = raw_line.rstrip("\r\n")
            stripped = line.strip()
            if not stripped:
                offset += len(raw_line)
                continue
            if stripped.startswith("#"):
                match = re.fullmatch(r'[ \t]*#include[ \t]+"([^"\\]+)"[ \t]*', line)
                need(match is not None, "conditional-config", path, text, offset)
                raw = match.group(1)
                token = Token(raw, offset + match.start(1), offset + match.end(1))
                # Includes are relative to their containing xcconfig, not to
                # the Xcode project. Only lexical in-project paths are allowed.
                parent = str(PurePosixPath(path).parent)
                included = self.project.relative("" if parent == "." else parent, raw, token,
                                                 origin_path=path, origin_text=text)
                additions = self.xcconfig(included, (*visiting, path))
                for key, value in additions.items():
                    need(key not in values or values[key] == value, "ambiguous-identity", path, text, offset)
                    values[key] = value
            else:
                match = re.fullmatch(r"[ \t]*([A-Za-z_][A-Za-z0-9_]*)(\[[^\r\n]*\])?[ \t]*(\+?=|\?=)[ \t]*(.*?)[ \t]*", line)
                need(match is not None, "unsupported-syntax", path, text, offset)
                key = match.group(1)
                if key in _SETTINGS:
                    need(match.group(2) is None and match.group(3) == "=", "conditional-config", path, text, offset)
                    value = match.group(4)
                    start = offset + match.start(4)
                    end = start + len(value)
                    quote = ""
                    if value.startswith('"'):
                        need(value.endswith('"') and len(value) >= 2, "unsupported-syntax", path, text, start)
                        value, quote = value[1:-1], '"'
                    item = _Setting(Token(value, start, end, "string" if quote else "atom", quote), path, text)
                    need(key not in values or values[key] == item, "ambiguous-identity", path, text, start)
                    values[key] = item
            offset += len(raw_line)
        self.cache[path] = values
        return dict(values)

    def layer(self, config: dict[str, Any]) -> dict[str, _Setting]:
        project = self.project
        values: dict[str, _Setting] = {}
        if "baseConfigurationReference" in config:
            reference = _value(config["baseConfigurationReference"], project.path)
            path = project.file_path(reference)
            need(path.endswith(".xcconfig"), "imported-control", project.path)
            values.update(self.xcconfig(path))
        settings = _object(config.get("buildSettings"), project.path)
        for key, value in settings.items():
            if any(key.startswith(name + "[") for name in _SETTINGS):
                token = _atom(value, project.path)
                refuse("conditional-config", project.path, project.text, token.start)
            if key in _SETTINGS:
                token = _atom(value, project.path)
                values[key] = _Setting(token, project.path, project.text)
        return values

    def effective(self, config: dict[str, Any]) -> dict[str, _Setting]:
        result = self.layer(self.project_config(config))
        result.update(self.layer(config))
        return result

    def project_config(self, config: dict[str, Any]) -> dict[str, Any]:
        name = _value(config.get("name"), self.project.path)
        projects = [value for _, value in self.project.configs(self.project.root)
                    if _value(value.get("name"), self.project.path) == name]
        need(len(projects) == 1, "ambiguous-identity", self.project.path)
        return projects[0]

    def identity_sources(self, config: dict[str, Any]) -> tuple[_Setting, ...]:
        """Do not hide an edited base behind another target's $(inherited)."""
        result: list[_Setting] = []
        for layer in (self.project_config(config), config):
            if "baseConfigurationReference" in layer:
                reference = _value(layer["baseConfigurationReference"], self.project.path)
                value = self.xcconfig(self.project.file_path(reference)).get("PRODUCT_BUNDLE_IDENTIFIER")
                if value is not None:
                    result.append(value)
            value = _object(layer.get("buildSettings"), self.project.path).get("PRODUCT_BUNDLE_IDENTIFIER")
            if value is not None:
                result.append(_Setting(_atom(value, self.project.path), self.project.path, self.project.text))
        return tuple(result)


def _identifier(values: dict[str, _Setting], path: str) -> _Setting:
    need("PRODUCT_BUNDLE_IDENTIFIER" in values, "missing-control", path)
    value = values["PRODUCT_BUNDLE_IDENTIFIER"]
    need(len(value.token.value) <= 255 and IOS_ID_RE.fullmatch(value.token.value) is not None,
         "dynamic-identity", value.path, value.text, value.token.start)
    return value


def _plist(project: _Project, values: dict[str, _Setting], texts: dict[str, str]) -> None:
    for key in sorted(_PLIST_OVERRIDES & values.keys()):
        value = values[key]
        harmless = (key == "INFOPLIST_PREPROCESS" and value.token.value == "NO"
                    or key == "INFOPLIST_EXPAND_BUILD_SETTINGS" and value.token.value == "YES"
                    or key in {"INFOPLIST_PREFIX_HEADER", "INFOPLIST_PREPROCESSOR_DEFINITIONS",
                               "INFOPLIST_OTHER_PREPROCESSOR_FLAGS"} and not value.token.value)
        need(harmless, "plist-override", value.path, value.text, value.token.start)
    entitlements = values.get("CODE_SIGN_ENTITLEMENTS")
    if entitlements and entitlements.token.value:
        refuse("imported-control", entitlements.path, entitlements.text, entitlements.token.start)
    info = values.get("INFOPLIST_FILE")
    if info is None:
        generated = values.get("GENERATE_INFOPLIST_FILE")
        need(generated is not None and generated.token.value == "YES", "unsupported-plist", project.path)
        return
    path = project.relative(project.base, info.token.value, info.token, root_variable=True,
                            origin_path=info.path, origin_text=info.text)
    need(path in texts, "missing-control", path)
    try:
        data = plistlib.loads(texts[path].encode("utf-8"))
        # plistlib silently replaces duplicate dictionary keys. Keep malformed
        # XML/duplicate identity declarations out of this controlling proof.
        root = ET.fromstring(texts[path])
        need(root.tag == "plist" and len(root) == 1 and root[0].tag == "dict", "unsupported-plist", path)
        keys = [node.text for node in root[0] if node.tag == "key"]
        need(len(set(keys)) == len(keys), "unsupported-plist", path)
    except (plistlib.InvalidFileException, ValueError, TypeError, RecursionError, ET.ParseError):
        refuse("unsupported-plist", path)
    need(type(data) is dict and data.get("CFBundleIdentifier") in {
        "$(PRODUCT_BUNDLE_IDENTIFIER)", "${PRODUCT_BUNDLE_IDENTIFIER}"}, "unsupported-plist", path)


def _scheme(project: _Project, target: str, section: dict[str, Any], texts: dict[str, str],
            configurations: tuple[str, ...]) -> None:
    """One conventional shared archive selection, not an Xcode evaluator."""
    name = section.get("scheme")
    if not name:
        return  # Passive setup analysis only; changed-ID Prepare requires one.

    def saved_refusal(key: str) -> None:
        text = texts[CONFIG_PATH]
        offset = (len(text.encode("utf-8")[:json_string_occurrence(text, ("ios", key)).start].decode("utf-8"))
                  if key in section else 0)
        refuse("scheme-selection", CONFIG_PATH, text, offset)

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,127}", name):
        saved_refusal("scheme")
    path = f"{PurePosixPath(project.path).parent}/xcshareddata/xcschemes/{name}.xcscheme"
    if not public_path(path):
        saved_refusal("scheme")
    need(path in texts, "missing-control", path)
    configuration = section.get("archiveConfiguration", "Release")
    if configuration not in configurations:
        saved_refusal("archiveConfiguration")
    text = texts[path]
    need("<!DOCTYPE" not in text.upper() and "<!ENTITY" not in text.upper(), "scheme-selection", path)
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError, RecursionError):
        refuse("scheme-selection", path)
    need(root.tag == "Scheme" and sum(1 for _ in root.iter()) <= 1024
         and not any(node.tag in {"ExecutionAction", "PreActions", "PostActions"} for node in root.iter()),
         "scheme-selection", path)
    build, archive = root.findall("BuildAction"), root.findall("ArchiveAction")
    need(len(build) == len(archive) == 1 and archive[0].get("buildConfiguration") == configuration,
         "scheme-selection", path)
    containers = build[0].findall("BuildActionEntries")
    need(len(containers) == 1 and 0 < len(containers[0]) <= 32, "scheme-selection", path)
    entries = list(containers[0])
    need(all(entry.tag == "BuildActionEntry" and entry.get("buildForArchiving") in {"YES", "NO"}
             for entry in entries), "scheme-selection", path)
    selected = [entry for entry in entries if entry.get("buildForArchiving") == "YES"]
    need(len(selected) == 1 and len(selected[0]) == 1 and selected[0][0].tag == "BuildableReference",
         "scheme-selection", path)
    reference = selected[0][0]
    need(reference.get("BuildableIdentifier") == "primary" and reference.get("BlueprintIdentifier") == target
         and reference.get("ReferencedContainer") == "container:" + PurePosixPath(project.path).parent.name,
         "scheme-selection", path)


def analyze_ios(texts: dict[str, str], selection: IdentitySelection, section: dict[str, Any],
                directories: tuple[str, ...]) -> tuple[str, tuple[Occurrence, ...], tuple[str, ...]]:
    path = selection.project + "/project.pbxproj"
    need(section.get("project") == selection.project and not section.get("workspace"), "target-mismatch")
    need(path in texts, "missing-control", path)
    for name in (*texts, *directories):
        parts = PurePosixPath(name).parts
        if PurePosixPath(name).name in {"project.yml", "project.yaml", "Project.swift", "Tuist.swift"} or "Tuist" in parts:
            refuse("generated-project", name)
    text = texts[path]
    if re.search(r"(?im)^[ \t]*(?://|/\*|\*)[^\r\n]*(?:generated by|do not edit)", text):
        refuse("generated-project", path)
    project = _Project(path, text)
    targets = [(identifier, project.get(identifier)) for identifier in project.target_ids]
    selected = [(identifier, body) for identifier, body in targets
                if identifier == selection.target or _value(body.get("name"), path) == selection.target]
    need(len(selected) == 1, "ambiguous-target", path)
    selected_id, target = selected[0]
    need(_value(target.get("isa"), path) == "PBXNativeTarget"
         and _value(target.get("productType"), path) == "com.apple.product-type.application", "ambiguous-target", path)
    configs = project.configs(target)
    selected_configs = {identifier for identifier, _ in configs}
    for identifier, body in targets:
        if identifier != selected_id:
            need(not selected_configs.intersection(name for name, _ in project.configs(body)), "shared-control", path)
    settings = _Settings(project, texts)
    found: list[Occurrence] = []
    names: list[str] = []
    for _, config in configs:
        effective = settings.effective(config)
        value = _identifier(effective, path)
        _plist(project, effective, texts)
        found.append(value.occurrence())
        names.append(_value(config.get("name"), path))
    need(len({value.value for value in found}) == 1, "ambiguous-identity", path)
    _scheme(project, selected_id, section, texts, tuple(names))
    locations = {(value.path, value.start, value.end) for value in found}
    # All configurations of all targets participate in the closure.  Resolved
    # PBXGroup/sourceTree aliases converge to the same path; source path names
    # alone never establish that a shared xcconfig is exclusive to one app.
    for other_path in sorted(name for name in texts if PurePosixPath(name).name == "project.pbxproj"):
        need(other_path.endswith(".xcodeproj/project.pbxproj"), "imported-control", other_path)
        other_project = project if other_path == path else _Project(other_path, texts[other_path])
        other_settings = settings if other_path == path else _Settings(other_project, texts)
        for identifier in other_project.target_ids:
            if other_path == path and identifier == selected_id:
                continue
            body = other_project.get(identifier)
            for _, config in other_project.configs(body):
                value = other_settings.effective(config).get("PRODUCT_BUNDLE_IDENTIFIER")
                if value is None:
                    continue
                site = value.occurrence()
                need((site.path, site.start, site.end) not in locations, "shared-control", site.path,
                     value.text, value.token.start)
                if IOS_ID_RE.fullmatch(value.token.value) is None:
                    inherited = (item.occurrence() for item in other_settings.identity_sources(config))
                    need(not any((item.path, item.start, item.end) in locations for item in inherited),
                         "shared-control", value.path, value.text, value.token.start)
    return found[0].value, tuple(sorted(set(found), key=lambda value: (value.path, value.start))), tuple(names)
