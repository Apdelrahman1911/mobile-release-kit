from __future__ import annotations

import os
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .config import ReleaseConfig

IGNORED_PARTS = {
    ".git",
    ".gradle",
    ".idea",
    ".mobile-release",
    "build",
    "DerivedData",
    "Pods",
    "node_modules",
}
PRIVATE_PREFIXES = {("release", "private")}


@dataclass(frozen=True)
class GitContext:
    repository: str | None
    repository_id: str | None
    commit: str | None
    tree: str | None
    ref: str | None
    branch: str | None
    dirty: bool | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "repositoryId": self.repository_id,
            "commit": self.commit,
            "tree": self.tree,
            "ref": self.ref,
            "branch": self.branch,
            "dirty": self.dirty,
        }


def _run(root: Path, argv: list[str]) -> str | None:
    try:
        result = subprocess.run(
            argv,
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def git_context(root: Path, environ: dict[str, str] | None = None) -> GitContext:
    env = environ if environ is not None else os.environ
    repository = env.get("GITHUB_REPOSITORY")
    if not repository:
        remote = _run(root, ["git", "config", "--get", "remote.origin.url"])
        if remote:
            match = re.search(r"(?:github\.com[:/])([^/]+/[^/]+?)(?:\.git)?$", remote)
            repository = match.group(1) if match else None
    # The checked-out object is authoritative. GITHUB_SHA is validated against
    # it by the mutation guard; never let an environment value invent source
    # provenance for a different local tree.
    checked_out_commit = _run(root, ["git", "rev-parse", "HEAD"])
    commit = checked_out_commit or env.get("GITHUB_SHA")
    tree = _run(
        root,
        ["git", "rev-parse", f"{commit}^{{tree}}"]
        if commit
        else ["git", "rev-parse", "HEAD^{tree}"],
    )
    branch = env.get("GITHUB_REF_NAME") or _run(root, ["git", "branch", "--show-current"])
    ref = env.get("GITHUB_REF") or (f"refs/heads/{branch}" if branch else None)
    status = _run(root, ["git", "status", "--porcelain=v1", "--untracked-files=normal"])
    dirty = None if status is None else bool(status)
    return GitContext(
        repository=repository,
        repository_id=env.get("GITHUB_REPOSITORY_ID"),
        commit=commit,
        tree=tree,
        ref=ref,
        branch=branch,
        dirty=dirty,
    )


def _candidate_files(root: Path, names: set[str], suffixes: tuple[str, ...] = ()) -> Iterable[Path]:
    for path in root.rglob("*"):
        if _ignored_path(root, path) or not path.is_file():
            continue
        if path.name in names or path.name.endswith(suffixes):
            yield path


def _ignored_path(root: Path, path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in IGNORED_PARTS for part in parts) or any(
        parts[: len(prefix)] == prefix for prefix in PRIVATE_PREFIXES
    )


def _read_small(path: Path, limit: int = 2_000_000) -> str:
    if path.stat().st_size > limit:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ""


def _gradle_application_aliases(root: Path) -> set[str]:
    """Return safe `libs.plugins.*` accessors mapped to the Android app plugin."""

    catalog = root / "gradle/libs.versions.toml"
    text = _read_small(catalog) if catalog.is_file() else ""
    if not text:
        return set()
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return set()
    plugins = parsed.get("plugins", {})
    if not isinstance(plugins, dict):
        return set()
    aliases: set[str] = set()
    for name, declaration in plugins.items():
        plugin_id = declaration.get("id") if isinstance(declaration, dict) else declaration
        if plugin_id == "com.android.application" and isinstance(name, str):
            accessor = re.sub(r"[-_.]+", ".", name)
            if re.fullmatch(r"[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*", accessor):
                aliases.add(accessor)
    return aliases


def _strip_gradle_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"(?m)//.*$", "", text)


def _applies_android_application_plugin(text: str, catalog_aliases: set[str]) -> bool:
    """Return whether this script applies (rather than only declares) the app plugin."""

    direct_patterns = (
        r"\bid\s*\(\s*[\"']com\.android\.application[\"']\s*\)",
        r"\bid\s+[\"']com\.android\.application[\"']",
        r"\bapply\s*(?:\(\s*)?plugin\s*(?:=|:)\s*[\"']com\.android\.application[\"']",
    )
    for pattern in direct_patterns:
        for match in re.finditer(pattern, text):
            line_end = text.find("\n", match.end())
            line_tail = text[match.end() : line_end if line_end >= 0 else len(text)]
            if not re.search(r"\bapply\s+false\b", line_tail):
                return True

    for match in re.finditer(
        r"\balias\s*\(\s*libs\.plugins\.([A-Za-z0-9.]+)\s*\)", text
    ):
        if match.group(1) not in catalog_aliases:
            continue
        line_end = text.find("\n", match.end())
        line_tail = text[match.end() : line_end if line_end >= 0 else len(text)]
        if not re.search(r"\bapply\s+false\b", line_tail):
            return True
    return False


def discover_android(root: Path) -> dict[str, Any] | None:
    build_files = list(_candidate_files(root, {"build.gradle", "build.gradle.kts"}))
    catalog_aliases = _gradle_application_aliases(root)
    candidates: list[dict[str, Any]] = []
    for path in build_files:
        text = _strip_gradle_comments(_read_small(path))
        if not _applies_android_application_plugin(text, catalog_aliases):
            continue
        relative_parent = path.parent.relative_to(root)
        module = ":" + ":".join(relative_parent.parts) if relative_parent.parts else ":"
        app_id_match = re.search(
            r"applicationId\s*(?:=\s*)?[\"']([A-Za-z][A-Za-z0-9_.]+)[\"']", text
        )
        namespace_match = re.search(
            r"namespace\s*(?:=\s*)?[\"']([A-Za-z][A-Za-z0-9_.]+)[\"']", text
        )
        suffix_match = re.search(r"applicationIdSuffix\s*(?:=\s*)?[\"']([^\"']+)[\"']", text)
        candidates.append(
            {
                "module": module,
                "buildFile": str(path.relative_to(root)),
                "applicationId": app_id_match.group(1) if app_id_match else None,
                "namespace": namespace_match.group(1) if namespace_match else None,
                "debugApplicationIdSuffix": suffix_match.group(1) if suffix_match else None,
            }
        )
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    return {"ambiguous": True, "candidates": candidates}


def discover_ios(root: Path) -> dict[str, Any] | None:
    workspaces = sorted(
        path
        for path in root.rglob("*.xcworkspace")
        if not _ignored_path(root, path)
        and not any(parent.suffix == ".xcodeproj" for parent in path.parents)
    )
    projects = sorted(
        path for path in root.rglob("*.xcodeproj") if not _ignored_path(root, path)
    )
    schemes = sorted(
        path
        for path in root.rglob("*.xcscheme")
        if "xcshareddata" in path.parts and not _ignored_path(root, path)
    )
    project_yml = sorted(
        path
        for path in root.rglob("project.yml")
        if not _ignored_path(root, path)
    )
    if not workspaces and not projects and not project_yml:
        return None

    texts: list[str] = []
    for path in _candidate_files(root, {"project.pbxproj", "project.yml"}, (".xcconfig",)):
        texts.append(_read_small(path))
    merged = "\n".join(texts)
    assignments: dict[str, str] = {}
    for key, value in re.findall(
        r"^[ \t]*([A-Z][A-Z0-9_]*)[ \t]*(?:=|:)[ \t]*[\"']?([^\s;\"']+)",
        merged,
        re.MULTILINE,
    ):
        if "$(" not in value:
            assignments.setdefault(key, value)
    raw_bundle_values = re.findall(
        r"(?m)^[ \t]*PRODUCT_BUNDLE_IDENTIFIER[ \t]*(?:=|:)[ \t]*"
        r"[\"']?([^\s;\"']+)",
        merged,
    )
    expanded: set[str] = set()
    for raw in raw_bundle_values:
        value = raw.rstrip(";\"'")
        variables = re.findall(r"\$\(([A-Z][A-Z0-9_]*)\)", value)
        if len(variables) == 1 and variables[0] in assignments:
            value = value.replace(f"$({variables[0]})", assignments[variables[0]])
        if "$(" not in value and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]+", value):
            expanded.add(value)
    bundle_ids = sorted(expanded)

    result: dict[str, Any] = {
        "projects": [str(path.relative_to(root)) for path in projects],
        "workspaces": [str(path.relative_to(root)) for path in workspaces],
        "schemes": sorted({path.stem for path in schemes}),
        "bundleIds": bundle_ids,
        "generatedProjectSources": [str(path.relative_to(root)) for path in project_yml],
    }
    store_ids = [value for value in bundle_ids if not value.endswith((".debug", ".dev"))]
    if len(store_ids) == 1:
        result["bundleId"] = store_ids[0]
    if len(projects) == 1:
        result["project"] = str(projects[0].relative_to(root))
    if len(workspaces) == 1:
        result["workspace"] = str(workspaces[0].relative_to(root))
    if len(result["schemes"]) == 1:
        result["scheme"] = result["schemes"][0]
    return result


def discover_version_source(root: Path) -> dict[str, str]:
    common_paths = (
        root / "release/version.properties",
        root / "config/version.xcconfig",
        root / "version.properties",
    )
    discovered_paths = sorted(
        path
        for path in _candidate_files(root, set(), (".properties", ".xcconfig"))
        if "version" in path.name.lower() and path not in common_paths
    )
    for path in (*common_paths, *discovered_paths):
        if not path.is_file() or _ignored_path(root, path):
            continue
        keys = set(
            re.findall(r"(?m)^[ \t]*([A-Z][A-Z0-9_]{0,63})[ \t]*=", _read_small(path))
        )
        pairs: list[tuple[str, str]] = []
        for name_key in sorted(
            key for key in keys if key == "MARKETING_VERSION" or key.endswith("VERSION_NAME")
        ):
            prefix = name_key[: -len("VERSION_NAME")] if name_key.endswith("VERSION_NAME") else ""
            build_candidates = (
                (f"{prefix}BUILD_NUMBER", f"{prefix}VERSION_CODE")
                if prefix
                else (
                    ("CURRENT_PROJECT_VERSION", "VERSION_CODE", "BUILD_NUMBER")
                    if name_key == "MARKETING_VERSION"
                    else ("VERSION_CODE", "BUILD_NUMBER", "CURRENT_PROJECT_VERSION")
                )
            )
            build_key = next((key for key in build_candidates if key in keys), None)
            if build_key:
                pairs.append((name_key, build_key))
        if len(pairs) == 1:
            name_key, build_key = pairs[0]
            return {
                "versionSource": str(path.relative_to(root)),
                "versionNameKey": name_key,
                "versionBuildKey": build_key,
            }
    return {}


def discover_project(root: Path) -> dict[str, Any]:
    root = root.resolve()
    result: dict[str, Any] = {"root": str(root)}
    result.update(discover_version_source(root))
    android = discover_android(root)
    ios = discover_ios(root)
    if android:
        result["android"] = android
    if ios:
        result["ios"] = ios
    result["git"] = git_context(root).as_dict()
    return result


def selected_android_module(config: ReleaseConfig, discovered: dict[str, Any]) -> str | None:
    configured = config.section("android").get("module")
    if configured:
        return configured
    android = discovered.get("android", {})
    return android.get("module") if not android.get("ambiguous") else None


def selected_android_details(
    config: ReleaseConfig, discovered: dict[str, Any]
) -> dict[str, Any]:
    """Select discovery details for the configured module, including ambiguous scans."""

    android = discovered.get("android", {})
    configured = config.section("android").get("module")
    if android.get("ambiguous"):
        if not configured:
            return {}
        return next(
            (
                candidate
                for candidate in android.get("candidates", [])
                if candidate.get("module") == configured
            ),
            {},
        )
    if configured and android.get("module") not in {None, configured}:
        return {}
    return android


def selected_ios_container(config: ReleaseConfig, discovered: dict[str, Any]) -> tuple[str, str] | None:
    ios = config.section("ios")
    if ios.get("workspace"):
        return ("workspace", ios["workspace"])
    if ios.get("project"):
        return ("project", ios["project"])
    found = discovered.get("ios", {})
    if found.get("workspace"):
        return ("workspace", found["workspace"])
    if found.get("project"):
        return ("project", found["project"])
    return None


def selected_ios_scheme(config: ReleaseConfig, discovered: dict[str, Any]) -> str | None:
    return config.section("ios").get("scheme") or discovered.get("ios", {}).get("scheme")
