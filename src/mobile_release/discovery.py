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


def _budget(cancellation):
    if cancellation is None or getattr(cancellation, "_preflight_source", None) is None:
        return None
    from ._desktop_preflight_budget import budget_for
    return budget_for(cancellation)


def _put_hint(target: dict, key, value, budget) -> None:
    if budget is None:
        target[key] = value
    else:
        budget.put(target, key, value)


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
        if error.fatal or _budget(cancellation) is not None:
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
    budget = _budget(cancellation)
    if budget is not None:
        budget.retain((repository, env.get("GITHUB_REPOSITORY_ID"), commit, tree, ref, branch, dirty))
    return GitContext(
        repository=repository,
        repository_id=env.get("GITHUB_REPOSITORY_ID"),
        commit=commit,
        tree=tree,
        ref=ref,
        branch=branch,
        dirty=dirty,
    )


def _candidate_files(root: Path, names: set[str], suffixes: tuple[str, ...] = (), *, cancellation=None) -> Iterable[Path]:
    budget = _budget(cancellation)
    paths = root.rglob("*") if budget is None else budget.walk(root, discovery=True)
    for path in paths:
        if cancellation is not None:
            cancellation.check()
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


def _read_small(path: Path, limit: int = 2_000_000, *, cancellation=None) -> str:
    budget = _budget(cancellation)
    if budget is not None:
        try:
            return budget.read(path, limit=limit) or ""
        except (UnicodeDecodeError, OSError):
            return ""
    if path.stat().st_size > limit:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ""


def _gradle_application_aliases(root: Path, *, cancellation=None) -> set[str]:
    """Return safe `libs.plugins.*` accessors mapped to the Android app plugin."""

    catalog = root / "gradle/libs.versions.toml"
    budget = _budget(cancellation)
    text = _read_small(catalog, cancellation=cancellation) if budget is not None or catalog.is_file() else ""
    return parse_gradle_application_aliases(text, budget=budget)


def parse_gradle_application_aliases(text: str, *, budget=None) -> set[str]:
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
        if budget is not None:
            budget.check()
        plugin_id = declaration.get("id") if isinstance(declaration, dict) else declaration
        if plugin_id == "com.android.application" and isinstance(name, str):
            accessor = re.sub(r"[-_.]+", ".", name)
            if re.fullmatch(r"[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*", accessor):
                if budget is None:
                    aliases.add(accessor)
                else:
                    budget.add(aliases, accessor)
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


def discover_android(root: Path, *, cancellation=None) -> dict[str, Any] | None:
    budget = _budget(cancellation)
    build_files = [] if budget is None else budget.list("path")
    build_files.extend(_candidate_files(root, {"build.gradle", "build.gradle.kts"}, cancellation=cancellation))
    catalog_aliases = _gradle_application_aliases(root, cancellation=cancellation)
    return parse_android_sources(
        ((path.relative_to(root).as_posix(), _read_small(path, cancellation=cancellation)) for path in build_files),
        catalog_aliases=catalog_aliases, budget=budget,
    )


def parse_android_sources(
    build_files: Iterable[tuple[str, str]], *, catalog_aliases: set[str], budget=None,
) -> dict[str, Any] | None:
    """Apply the existing static Android hints policy to a finite text inventory."""
    candidates: list[dict[str, Any]] = [] if budget is None else budget.list()
    for relative, source_text in build_files:
        if budget is not None:
            budget.check()
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
        candidate = {} if budget is None else budget.mapping()
        for key, value in (
            ("module", module),
            ("buildFile", relative),
            ("applicationId", app_id_match.group(1) if app_id_match else None),
            ("namespace", namespace_match.group(1) if namespace_match else None),
            ("debugApplicationIdSuffix", suffix_match.group(1) if suffix_match else None),
        ):
            _put_hint(candidate, key, value, budget)
        candidates.append(candidate)
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    result = {} if budget is None else budget.mapping()
    _put_hint(result, "ambiguous", True, budget)
    _put_hint(result, "candidates", candidates, budget)
    return result


def discover_ios(root: Path, *, cancellation=None) -> dict[str, Any] | None:
    budget = _budget(cancellation)
    if budget is not None:
        paths = budget.walk(root, discovery=True)
        workspaces, projects, schemes, project_yml = (budget.list("path") for _ in range(4))
        for path in paths:
            budget.check()
            if path.suffix == ".xcworkspace" and not any(parent.suffix == ".xcodeproj" for parent in path.parents):
                workspaces.append(path)
            if path.suffix == ".xcodeproj":
                projects.append(path)
            if path.suffix == ".xcscheme" and "xcshareddata" in path.parts:
                schemes.append(path)
            if path.name == "project.yml":
                project_yml.append(path)
        for group in (workspaces, projects, schemes, project_yml):
            group.sort()
        project_names, workspace_names, scheme_names, generated_names = (budget.list() for _ in range(4))
        project_names.extend(str(path.relative_to(root)) for path in projects)
        workspace_names.extend(str(path.relative_to(root)) for path in workspaces)
        scheme_names.extend(path.stem for path in schemes)
        generated_names.extend(str(path.relative_to(root)) for path in project_yml)
        return parse_ios_sources(
            projects=project_names,
            workspaces=workspace_names,
            scheme_names=scheme_names,
            generated_sources=generated_names,
            texts=(_read_small(path, cancellation=cancellation) for path in paths
                   if path.is_file() and (path.name in {"project.pbxproj", "project.yml"} or path.suffix == ".xcconfig")),
            budget=budget)
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
    generated_sources: list[str], texts: Iterable[str], budget=None,
) -> dict[str, Any] | None:
    """Parse finite static iOS hints; never evaluate Xcode or generated projects."""
    if not workspaces and not projects and not generated_sources:
        return None
    # The desktop admits one text at a time. Keep first-assignment-wins over
    # the entire inventory and defer bundle expansion until all assignments
    # are known, exactly as the legacy merged-text policy does.
    sources = ("\n".join(texts),) if budget is None else texts
    assignments: dict[str, str] = {} if budget is None else budget.mapping()
    raw_bundle_values = [] if budget is None else budget.list()
    for source in sources:
        if budget is not None:
            budget.check()
        for match in re.finditer(
            r"^[ \t]*([A-Z][A-Z0-9_]*)[ \t]*(?:=|:)[ \t]*[\"']?([^\s;\"']+)",
            source,
            re.MULTILINE,
        ):
            key, value = match.group(1, 2)
            if budget is not None:
                budget.check()
            if "$(" not in value and key not in assignments:
                _put_hint(assignments, key, value, budget)
        for match in re.finditer(
            r"(?m)^[ \t]*PRODUCT_BUNDLE_IDENTIFIER[ \t]*(?:=|:)[ \t]*"
            r"[\"']?([^\s;\"']+)",
            source,
        ):
            raw_bundle_values.append(match.group(1))
    expanded: set[str] = set()
    for raw in raw_bundle_values:
        if budget is not None:
            budget.check()
        value = raw.rstrip(";\"'")
        variables = []
        for variable in re.finditer(r"\$\(([A-Z][A-Z0-9_]*)\)", value):
            variables.append(variable.group(1))
            if len(variables) == 2:
                break  # Only an exactly-one-variable value may be expanded.
        if len(variables) == 1 and variables[0] in assignments:
            value = value.replace(f"$({variables[0]})", assignments[variables[0]])
        if "$(" not in value and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]+", value):
            if budget is None:
                expanded.add(value)
            else:
                budget.add(expanded, value)
    bundle_ids = [] if budget is None else budget.list()
    bundle_ids.extend(expanded)
    bundle_ids.sort()
    unique_schemes = set()
    for name in scheme_names:
        if budget is None:
            unique_schemes.add(name)
        else:
            budget.add(unique_schemes, name)
    schemes = [] if budget is None else budget.list()
    schemes.extend(unique_schemes)
    schemes.sort()
    result: dict[str, Any] = {} if budget is None else budget.mapping()
    for key, value in (
        ("projects", projects), ("workspaces", workspaces), ("schemes", schemes),
        ("bundleIds", bundle_ids), ("generatedProjectSources", generated_sources),
    ):
        _put_hint(result, key, value, budget)
    store_ids = [] if budget is None else budget.list()
    store_ids.extend(value for value in bundle_ids if not value.endswith((".debug", ".dev")))
    if len(store_ids) == 1:
        _put_hint(result, "bundleId", store_ids[0], budget)
    if len(projects) == 1:
        _put_hint(result, "project", projects[0], budget)
    if len(workspaces) == 1:
        _put_hint(result, "workspace", workspaces[0], budget)
    if len(result["schemes"]) == 1:
        _put_hint(result, "scheme", result["schemes"][0], budget)
    return result


def discover_version_source(root: Path, *, cancellation=None) -> dict[str, str]:
    budget = _budget(cancellation)
    common_paths = (
        root / "release/version.properties",
        root / "config/version.xcconfig",
        root / "version.properties",
    )
    discovered_paths = [] if budget is None else budget.list("path")
    discovered_paths.extend(
        path
        for path in _candidate_files(root, set(), (".properties", ".xcconfig"), cancellation=cancellation)
        if "version" in path.name.lower() and path not in common_paths
    )
    discovered_paths.sort()
    return parse_version_sources(
        ((path.relative_to(root).as_posix(), _read_small(path, cancellation=cancellation))
        for group in (common_paths, discovered_paths) for path in group
        if path.is_file() and not _ignored_path(root, path)), budget=budget
    )


def parse_version_sources(sources: Iterable[tuple[str, str]], *, budget=None) -> dict[str, str]:
    """Suggest key names only, not an authoritative parsed release version."""
    for relative, text in sources:
        keys = set()
        for match in re.finditer(r"(?m)^[ \t]*([A-Z][A-Z0-9_]{0,63})[ \t]*=", text):
            if budget is None:
                keys.add(match.group(1))
            else:
                budget.add(keys, match.group(1))
        pairs: list[tuple[str, str]] = [] if budget is None else budget.list()
        name_keys = [] if budget is None else budget.list()
        name_keys.extend(
            key for key in keys if key == "MARKETING_VERSION" or key.endswith("VERSION_NAME")
        )
        name_keys.sort()
        for name_key in name_keys:
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
            result = {} if budget is None else budget.mapping()
            _put_hint(result, "versionSource", relative, budget)
            _put_hint(result, "versionNameKey", name_key, budget)
            _put_hint(result, "versionBuildKey", build_key, budget)
            return result
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
    budget = _budget(cancellation)
    if budget is not None:
        budget.checkpoint()
        if root != budget.root:
            raise ValueError("Discovery root differs from original preflight admission")
    else:
        root = root.resolve()
    result: dict[str, Any] = {} if budget is None else budget.mapping()
    _put_hint(result, "root", str(root), budget)
    for key, value in discover_version_source(root, cancellation=cancellation).items():
        _put_hint(result, key, value, budget)
    android = discover_android(root, cancellation=cancellation)
    ios = discover_ios(root, cancellation=cancellation)
    if android:
        _put_hint(result, "android", android, budget)
    if ios:
        _put_hint(result, "ios", ios, budget)
    if include_git:
        _put_hint(result, "git", git_context(root, execution_source=execution_source, cancellation=cancellation).as_dict(), budget)
    if budget is not None:
        budget.checkpoint()
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
