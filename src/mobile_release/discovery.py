from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from .config import ReleaseConfig
from .init_transaction import ALL_STATE_NAMES, STATE_NAMES, is_state_name

# Keep the legacy passive STATE_NAMES import seam intact; the broader set is
# only for exclusions/admission and never substitutes for recovery dispatch.

IGNORED_PARTS = {
    *ALL_STATE_NAMES,
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


def run_owned(*args, **kwargs):
    """Preserve the existing injectable command seam without an eager import."""
    from .owned_process import run_owned as owned_run

    return owned_run(*args, **kwargs)


def __getattr__(name: str):
    # Compatibility for callers inspecting/patching the former imported names.
    # This fixed accessor is not API dispatch; passive parsers never use it.
    if name == "OUTPUT_LIMIT":
        from .owned_process import OUTPUT_LIMIT

        return OUTPUT_LIMIT
    if name == "ProcessError":
        from .owned_process import ProcessError

        return ProcessError
    raise AttributeError(name)


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


def _valid_git_object_id(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9A-Fa-f]{40}", value) is not None


def valid_observed_source(git: GitContext) -> bool:
    """Whether this fresh context contains complete, clean source observations.

    ``git_context`` is the observation producer; an environment hint is never
    source authority. This pure predicate performs no later checkout read and
    does not reinterpret already-authenticated historical evidence.
    """

    return _valid_git_object_id(git.commit) and _valid_git_object_id(git.tree) and git.dirty is False


def _run(root: Path, argv: list[str], *, execution_source=None, cancellation=None) -> str | None:
    # Local import keeps credentials' static project-selection dependency acyclic.
    from .credentials import scrub_credential_capabilities
    from .owned_process import OUTPUT_LIMIT as default_output_limit, ProcessError

    environment = scrub_credential_capabilities(os.environ)
    if argv and argv[0] == "git":
        # cwd alone does not bind Git to this checkout when inherited GIT_DIR,
        # worktree/index/object/config overrides can redirect its observations.
        # Keep the admitted tool PATH, not ambient Git, home or cloud settings.
        environment = {
            "PATH": environment.get("PATH", os.defpath),
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_PAGER": "cat",
        }
        argv = [
            "git", "--no-pager", "--no-replace-objects",
            "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
            "-c", "core.untrackedCache=false", "-c", "protocol.allow=never",
            *argv[1:],
        ]
    try:
        result = run_owned(
            argv,
            cwd=root,
            environ=environment,
            capture=True,
            output_limit=globals().get("OUTPUT_LIMIT", default_output_limit),
            timeout=10,
            execution_scope=None if execution_source is None else execution_source.new_scope(),
            cancellation=cancellation,
        )
    except ProcessError as error:
        if error.fatal:
            raise
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def git_context(root: Path, environ: dict[str, str] | None = None, *, execution_source=None, cancellation=None) -> GitContext:
    env = environ if environ is not None else os.environ
    repository = env.get("GITHUB_REPOSITORY")
    if not repository:
        remote = _run(root, ["git", "config", "--get", "remote.origin.url"], execution_source=execution_source, cancellation=cancellation)
        if remote:
            match = re.search(r"(?:github\.com[:/])([^/]+/[^/]+?)(?:\.git)?$", remote)
            repository = match.group(1) if match else None
    # GITHUB_SHA is a dispatch claim for the mutation guard, never a substitute
    # for observing this checkout. Derive a tree only from a valid actual HEAD.
    head = _run(root, ["git", "rev-parse", "--verify", "HEAD"], execution_source=execution_source, cancellation=cancellation)
    commit = head if _valid_git_object_id(head) else None
    tree = None
    if commit is not None:
        observed_tree = _run(
            root, ["git", "rev-parse", "--verify", f"{commit}^{{tree}}"],
            execution_source=execution_source, cancellation=cancellation,
        )
        if _valid_git_object_id(observed_tree):
            tree = observed_tree
    status = _run(root, ["git", "status", "--porcelain=v1", "--untracked-files=normal", "--ignore-submodules=none"], execution_source=execution_source, cancellation=cancellation)
    dirty = None if status is None else bool(status)
    ending_head = _run(
        root, ["git", "rev-parse", "--verify", "HEAD"],
        execution_source=execution_source, cancellation=cancellation,
    )
    if commit is None or not _valid_git_object_id(ending_head) or ending_head != commit:
        commit = tree = None
    # The bracket detects an intervening persistent checkout, not arbitrary
    # same-user ABA or an atomic filesystem snapshot. The checkout remains a
    # trusted, exclusively operated input. Ref names describe CI dispatch even
    # when recovery observes a detached original-source checkout.
    branch = env.get("GITHUB_REF_NAME") or _run(root, ["git", "branch", "--show-current"], execution_source=execution_source, cancellation=cancellation)
    ref = env.get("GITHUB_REF") or (f"refs/heads/{branch}" if branch else None)
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
    return any(part in IGNORED_PARTS or is_state_name(part) for part in parts) or any(
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
    return parse_gradle_application_aliases(text)


def parse_gradle_application_aliases(text: str) -> set[str]:
    """Parse already-admitted text; no paths, tools or project code are opened."""
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
    return parse_android_sources(
        ((path.relative_to(root).as_posix(), _read_small(path)) for path in build_files),
        catalog_aliases=catalog_aliases,
    )


def parse_android_sources(
    build_files: Iterable[tuple[str, str]], *, catalog_aliases: set[str],
) -> dict[str, Any] | None:
    """Apply the existing static Android hints policy to a finite text inventory."""
    candidates: list[dict[str, Any]] = []
    for relative, source_text in build_files:
        text = _strip_gradle_comments(source_text)
        if not _applies_android_application_plugin(text, catalog_aliases):
            continue
        relative_parent = PurePosixPath(relative).parent
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
                "buildFile": relative,
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
    return parse_ios_sources(
        projects=[str(path.relative_to(root)) for path in projects],
        workspaces=[str(path.relative_to(root)) for path in workspaces],
        scheme_names=[path.stem for path in schemes],
        generated_sources=[str(path.relative_to(root)) for path in project_yml],
        texts=texts,
    )


def parse_ios_sources(
    *, projects: list[str], workspaces: list[str], scheme_names: list[str],
    generated_sources: list[str], texts: Iterable[str],
) -> dict[str, Any] | None:
    """Parse finite static iOS hints; never evaluate Xcode or generated projects."""
    if not workspaces and not projects and not generated_sources:
        return None
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
        "projects": projects,
        "workspaces": workspaces,
        "schemes": sorted(set(scheme_names)),
        "bundleIds": bundle_ids,
        "generatedProjectSources": generated_sources,
    }
    store_ids = [value for value in bundle_ids if not value.endswith((".debug", ".dev"))]
    if len(store_ids) == 1:
        result["bundleId"] = store_ids[0]
    if len(projects) == 1:
        result["project"] = projects[0]
    if len(workspaces) == 1:
        result["workspace"] = workspaces[0]
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
    return parse_version_sources(
        (path.relative_to(root).as_posix(), _read_small(path))
        for path in (*common_paths, *discovered_paths)
        if path.is_file() and not _ignored_path(root, path)
    )


def parse_version_sources(sources: Iterable[tuple[str, str]]) -> dict[str, str]:
    """Suggest key names only, not an authoritative parsed release version."""
    for relative, text in sources:
        keys = set(
            re.findall(r"(?m)^[ \t]*([A-Z][A-Z0-9_]{0,63})[ \t]*=", text)
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
                "versionSource": relative,
                "versionNameKey": name_key,
                "versionBuildKey": build_key,
            }
    return {}


def parse_project_sources(
    sources: Mapping[str, str], directories: Iterable[str],
) -> dict[str, Any]:
    """Reuse discovery policy on a finite, caller-admitted POSIX-path inventory.

    This function performs no IO. Its caller must enforce input bounds and
    namespace admission. Its output remains unverified static suggestions.
    """
    common = ("release/version.properties", "config/version.xcconfig", "version.properties")
    version_paths = [name for name in common if name in sources]
    version_paths.extend(sorted(
        name for name in sources if name not in common
        and "version" in PurePosixPath(name).name.lower()
        and name.endswith((".properties", ".xcconfig"))
    ))
    result: dict[str, Any] = parse_version_sources((name, sources[name]) for name in version_paths)
    android = parse_android_sources(
        ((name, sources[name]) for name in sorted(sources)
         if PurePosixPath(name).name in {"build.gradle", "build.gradle.kts"}),
        catalog_aliases=parse_gradle_application_aliases(sources.get("gradle/libs.versions.toml", "")),
    )
    directory_paths = [PurePosixPath(name) for name in directories]
    ios = parse_ios_sources(
        projects=sorted(str(path) for path in directory_paths if path.suffix == ".xcodeproj"),
        workspaces=sorted(str(path) for path in directory_paths if path.suffix == ".xcworkspace"
                          and not any(parent.suffix == ".xcodeproj" for parent in path.parents)),
        scheme_names=[PurePosixPath(name).stem for name in sources if name.endswith(".xcscheme")
                      and "xcshareddata" in PurePosixPath(name).parts],
        generated_sources=sorted(name for name in sources if PurePosixPath(name).name == "project.yml"),
        texts=(sources[name] for name in sorted(sources)
               if PurePosixPath(name).name in {"project.pbxproj", "project.yml"}
               or name.endswith(".xcconfig")),
    )
    if android:
        result["android"] = android
    if ios:
        result["ios"] = ios
    return result


def discover_project(root: Path, *, include_git: bool = True, execution_source=None, cancellation=None) -> dict[str, Any]:
    root = root.resolve()
    result: dict[str, Any] = {"root": str(root)}
    result.update(discover_version_source(root))
    android = discover_android(root)
    ios = discover_ios(root)
    if android:
        result["android"] = android
    if ios:
        result["ios"] = ios
    if include_git:
        result["git"] = git_context(root, execution_source=execution_source, cancellation=cancellation).as_dict()
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
