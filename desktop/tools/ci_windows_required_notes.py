"""Fixed disposable Windows Required Notes SOURCE compile/selected-contract lane.

Not an installer, native qualification, shipping gate, generic runner, or a
success substitute for the original three compilers and their exact artifacts.
The existing ci_foundation dispatch/roles and Python import-denial owner are
unchanged. No old Windows phase is dispatched from this module.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import tomllib

sys.path.insert(0, str(Path(__file__).absolute().parent))
import ci_foundation as base

require = base.require
CheckFailure = base.CheckFailure
same_compile_json = base.same_compile_json
sha256_value = base.sha256_value
read = base.windows_installed_bytes
record = base.windows_installed_record
RUST, PYTHON = "1.98.0", "3.14.7"
TARGET = "x86_64-pc-windows-msvc"
SCOPE = "windows-required-notes-source-v1"
REF = "refs/heads/verify/desktop-windows-required-notes-source"
WORKFLOW = ".github/workflows/desktop-windows-notes-source.yml"
CONTRACT = "desktop/tools/windows_required_notes_source_contract.json"
OWNER = "tests/desktop/windows_required_notes_memory_owner.py"
PHASES = ("prepare", "acquire", "compile", "windows-required-notes-contracts", "retain")
ROLES = {
    "native": ("desktop/native/windows-installed-native", "mrk-windows-installed-native",
               "mrk_windows_installed_native", ("required-notes",), ("lib",), 49),
    "bridge": ("desktop/native/windows-image-writer-bridge", "mrk-windows-image-writer-bridge",
               "mrk_image_writer_native", ("required-notes",), ("cdylib",), 8),
    "app": ("desktop/src-tauri", "mobile-release-kit-desktop", "mobile_release_desktop",
            ("windows-metadata-images-loader", "windows-required-notes-loader"), ("lib",), 6),
}
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
WINDOWS_INSTALLED_APP = base.WINDOWS_INSTALLED_APP
WINDOWS_INSTALLED_CRATE = base.WINDOWS_INSTALLED_CRATE
WINDOWS_INSTALLED_APP_LOCK_LOCALS = base.WINDOWS_INSTALLED_APP_LOCK_LOCALS
WINDOWS_INSTALLED_APP_LOCALS = base.WINDOWS_INSTALLED_APP_LOCALS
WINDOWS_INSTALLED_APP_DIRECT_ROLES = {
    ("base64", "0.22.1"), ("cms", "0.2.3"), ("crypto_box", "0.9.1"),
    ("curve25519-dalek", "4.1.3"), ("der", "0.7.10"), ("getrandom", "0.3.4"),
    ("mrk-windows-installed-native", "0.1.0"), ("pkcs12", "0.1.0"), ("plist", "1.10.1"),
    ("quick-xml", "0.42.0"), ("rand_chacha", "0.3.1"), ("serde", "1.0.228"),
    ("serde_json", "1.0.145"), ("sha2", "0.10.9"), ("tokio", "1.48.0"), ("zeroize", "1.9.0"),
}
NOT_VERIFIED = (
    "compiled-notes-shipping-admission", "ordinary-native-handle-or-NTFS-qualification",
    "unmocked-bootstrap-or-child-execution", "DLL-installation-or-loading",
    "runtime-publication", "installer", "desktop-UI", "release-or-store-operation",
    "other-Windows-images", "Linux-or-Mac-Notes",
)


def write(path: Path, value: object) -> None:
    raw = base.canonical_json(value) + b"\n"
    require(len(raw) <= 4 << 20, "Notes fixed DATA output exceeds its bound")
    with path.open("xb") as output:
        require(output.write(raw) == len(raw), "Notes original DATA write was incomplete")
        output.flush()
        os.fsync(output.fileno())
    require(read(path, 4 << 20) == raw, "Notes original DATA readback changed")


def data(path: Path, limit: int = 256 << 10):
    return base.bounded_json(read(path, limit), limit, max_nodes=200000)


def binding() -> dict:
    e = os.environ
    require(sys.platform == "win32" and sys.maxsize == 2**63 - 1
            and sys.version.split()[0] == PYTHON
            and e.get("GITHUB_ACTIONS") == "true" and e.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and e.get("RUNNER_OS") == "Windows" and e.get("RUNNER_ARCH") == "X64"
            and e.get("ImageOS") == "win25-vs2026" and e.get("GITHUB_JOB") == "windows-required-notes-source"
            and e.get("GITHUB_RUN_ATTEMPT") == "1" and e.get("MRK_DESKTOP_HOSTED_CHECKS") == SCOPE
            and e.get("MRK_DESKTOP_PLATFORM") == "windows", "Notes requires its fixed disposable hosted job")
    sha, repository = e.get("GITHUB_SHA", ""), e.get("GITHUB_REPOSITORY", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None and sha != "0" * 40
            and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None
            and e.get("GITHUB_REF") == REF and e.get("GITHUB_WORKFLOW_SHA") == sha
            and e.get("GITHUB_WORKFLOW_REF") == repository + "/" + WORKFLOW + "@" + REF
            and re.fullmatch(r"[1-9][0-9]{0,19}", e.get("GITHUB_RUN_ID", "")) is not None
            and re.fullmatch(r"[0-9]{8}\.[0-9]{1,6}\.[0-9]{1,6}", e.get("ImageVersion", "")) is not None,
            "Notes workflow/commit/ref/image binding differs")
    event, dispatch, expected = (e.get(name, "") for name in
                                ("GITHUB_EVENT_NAME", "MRK_DESKTOP_DISPATCH_SCOPE", "MRK_DESKTOP_EXPECTED_SHA"))
    require(event == "push" and dispatch == "" and expected == ""
            or event == "workflow_dispatch" and dispatch == "windows-required-notes-source" and expected == sha,
            "Notes first-push or explicit-SHA dispatch binding differs")
    return {"scope": SCOPE, "sourceSha": sha, "repository": repository, "ref": REF,
            "workflowSha": sha, "workflowRef": e["GITHUB_WORKFLOW_REF"], "runId": e["GITHUB_RUN_ID"],
            "attempt": 1, "event": event, "imageOS": e["ImageOS"], "imageVersion": e["ImageVersion"]}


def source_contract(context: dict) -> dict:
    source = Path(context["source"])
    value = data(source / CONTRACT)
    require(type(value) is dict and set(value) == {"schema", "sourcePins", "rust", "python"}
            and value["schema"] == "mrk-windows-required-notes-source-contract-v1",
            "Notes source contract shape differs")
    pins = value["sourcePins"]
    require(type(pins) is list and len(pins) == 46
            and base.validate_environment_inventory(pins, maximum=8 << 20) == pins,
            "Notes exact46 source pins differ")
    require(base.fixed_file_inventory(source, tuple(row["path"] for row in pins)) == pins,
            "Notes current-preserving composition differs from reviewed source pins")
    require(type(value["rust"]) is dict and set(value["rust"]) == set(ROLES)
            and type(value["python"]) is list and len(value["python"]) == 2,
            "Notes fixed selector partitions differ")
    for role, spec in ROLES.items():
        names = value["rust"][role]
        require(type(names) is list and len(names) == spec[5] and len(set(names)) == len(names)
                and all(type(name) is str and re.fullmatch(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*){1,5}", name)
                        for name in names), "Notes Rust source selector roster differs")
    py_names = []
    for part, count, path, module in zip(value["python"], (49, 14),
            ("tests/test_required_notes_windows_contract.py", "tests/test_desktop_windows_stdio_purpose.py"),
            ("test_required_notes_windows_contract", "test_desktop_windows_stdio_purpose"), strict=True):
        require(type(part) is dict and set(part) == {"path", "module", "selectors"}
                and part["path"] == path and part["module"] == module and len(part["selectors"]) == count,
                "Notes Python source partition differs")
        for selection in part["selectors"]:
            require(type(selection) is dict and set(selection) == {"class", "test"}
                    and re.fullmatch(r"[A-Za-z_]\w{0,127}", selection["class"])
                    and re.fullmatch(r"test_[A-Za-z_]\w{0,191}", selection["test"]),
                    "Notes Python source selector differs")
            py_names.append(module + "." + selection["class"] + "." + selection["test"])
    require(len(py_names) == 63 and len(set(py_names)) == 63, "Notes Python selectors are duplicated")
    return value


def inputs(context: dict, *, retention_only: bool = False) -> None:
    root, source = Path(context["root"]), Path(context["source"])
    rows = base.validate_environment_inventory(context["sourceFiles"], maximum=64 << 20)
    for path in sorted({root, source, root / "cargo", root / "target", root / "public",
                        *((source / row["path"]).parent for row in rows)}, key=str):
        base.windows_installed_directories(path)
    observed = (base.fixed_file_inventory(source, tuple(row["path"] for row in rows)) if retention_only
                else base.windows_installed_source_files(source, root, context["git"]))
    require(observed == rows, "Notes original tracked source changed")
    require({WORKFLOW, CONTRACT, OWNER, "desktop/tools/ci_windows_required_notes.py"} <= {r["path"] for r in rows},
            "Notes fixed CI source is not tracked")
    base.no_cargo_configuration(tuple({source / spec[0] for spec in ROLES.values()}
        | {source / "desktop/native", source / "desktop", source, *source.parents,
           root, *root.parents, root / "home"}))
    require(not any((root / "cargo" / name).exists() or (root / "cargo" / name).is_symlink()
                    for name in ("config", "config.toml")), "Notes Cargo home has ambient configuration")
    require(not any(name in os.environ for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP", "CARGO_BUILD_RUSTFLAGS",
            "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS", "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER")),
            "Notes ambient compiler injection is not admitted")
    require(context["sdk"] == {"version": base.WINDOWS_SDK_VERSION,
            "headers": base.fixed_file_inventory(base.windows_sdk_root(), base.WINDOWS_SDK_HEADERS)},
            "Notes original SDK context changed")
    source_contract(context)


def context(*, create: bool, retention_only: bool = False) -> dict:
    bound = binding()
    source, temp = Path(os.environ["GITHUB_WORKSPACE"]), Path(os.environ["RUNNER_TEMP"])
    base.windows_installed_directories(source)
    base.windows_installed_directories(temp)
    root = temp / ("mrk-windows-required-notes-source-" + bound["runId"] + "-1")
    python = Path(os.environ["MRK_PYTHON"])
    base.windows_installed_tool(python, "python")
    require(python.is_absolute() and python == Path(sys.executable), "Notes selected Python differs")
    if create:
        root.mkdir(mode=0o700)
        for name in ("home", "cargo", "rustup", "tmp", "target", "appdata", "localappdata", "public"):
            (root / name).mkdir(mode=0o700)
        for role in ROLES:
            (root / "target" / role).mkdir(mode=0o700)
        (root / "gitconfig-empty").touch(mode=0o600, exist_ok=False)
        git, rustup = shutil.which("git"), shutil.which("rustup")
        require(git is not None and rustup is not None and Path(git).is_absolute() and Path(rustup).is_absolute(),
                "Notes fixed hosted compiler tools are unavailable")
        base.windows_installed_tool(Path(git), "git")
        base.windows_installed_tool(Path(rustup), "rustup")
        environment = base.clean_environment(root)
        require(base.run([git, "rev-parse", "HEAD"], check="source-head", cwd=source, env=environment,
                         timeout=15, capture=True) == bound["sourceSha"], "Notes checkout differs")
        tree = base.run([git, "rev-parse", "HEAD^{tree}"], check="source-tree", cwd=source,
                        env=environment, timeout=15, capture=True)
        require(re.fullmatch(r"[0-9a-f]{40}", tree) is not None and tree != "0" * 40, "Notes source tree differs")
        value = {**bound, "root": str(root), "source": str(source), "sourceTree": tree, "platform": "windows",
                 "python": str(python), "git": git, "rustup": rustup,
                 "pythonIdentity": record(python, 32 << 20),
                 "sourceFiles": base.windows_installed_source_files(source, root, git),
                 "sdk": {"version": base.WINDOWS_SDK_VERSION,
                         "headers": base.fixed_file_inventory(base.windows_sdk_root(), base.WINDOWS_SDK_HEADERS)},
                 "windowsVersion": list(sys.getwindowsversion()[:3])}
        inputs(value)
        admit_rust_sources(value)
        base.source_unchanged(value)
        write(root / "context.json", value)
        public = {key: value[key] for key in (*bound, "sourceTree", "sourceFiles", "pythonIdentity", "sdk", "windowsVersion")}
        public.update(rust=RUST, python=PYTHON, target=TARGET, notVerified=list(NOT_VERIFIED))
        write(root / "public-bindings.json", public)
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8", newline="\n") as output:
            text = "root=" + str(root) + "\n"
            require(output.write(text) == len(text), "Notes original root handoff is incomplete")
        return value
    require(os.environ.get("MRK_DESKTOP_CI_ROOT") == str(root), "Notes original task root differs")
    value = data(root / "context.json", 4 << 20)
    require(type(value) is dict and value.get("root") == str(root) and value.get("source") == str(source)
            and value.get("python") == str(python) and all(value.get(k) == v for k, v in bound.items())
            and value.get("platform") == "windows", "Notes original context differs")
    require(record(python, 32 << 20) == value["pythonIdentity"], "Notes original Python changed")
    inputs(value, retention_only=retention_only)
    return value


def manifest_features(source: Path) -> dict:
    value = tomllib.loads(read(source / ROLES["native"][0] / "Cargo.toml", 64 << 10).decode("utf-8"))
    features = value["features"]
    require(features.get("required-notes") == ["image-stdio", "dep:sha2"]
            and features.get("image-stdio") == ["image-writer"] and features.get("image-writer") == []
            and "default" not in features, "Notes native feature declaration differs")
    return features


def rust_tokens(raw: str) -> tuple[list[str], dict[int, int]]:
    """Bounded lexical SOURCE admission, not binary discovery or a compiler."""
    require(len(raw.encode("utf-8")) <= 2 << 20, "Notes Rust source is overbound")
    tokens, pairs, stack = [], {}, []
    i, length = 0, len(raw)
    whitespace = re.compile(r"\s+|//[^\n]*")
    raw_string = re.compile(r'(?:b|c)?r(#{0,32})"')
    quoted = re.compile(r"""(?:b|c)?"(?:\\.|[^"\\])*"|b?'(?:\\(?:u\{[0-9A-Fa-f_]+\}|x[0-9A-Fa-f]{2}|.)|[^'\\\r\n])'""", re.S)
    identifier = re.compile(r"(?:r#)?[A-Za-z_][A-Za-z_0-9]*|[0-9][A-Za-z_0-9]*")
    while i < length:
        match = whitespace.match(raw, i)
        if match:
            i += len(match[0])
            continue
        if raw.startswith("/*", i):
            depth, i = 1, i + 2
            while depth and i < length:
                if raw.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif raw.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            require(depth == 0, "Notes Rust SOURCE comment is unterminated")
            continue
        match = raw_string.match(raw, i)
        if match:
            end = raw.find('"' + match[1], i + len(match[0]))
            require(end >= 0, "Notes Rust raw string is unterminated")
            tokens.append("<literal>")
            i = end + 1 + len(match[1])
            continue
        match = quoted.match(raw, i)
        if match:
            tokens.append(match[0])
            i += len(match[0])
            continue
        match = identifier.match(raw, i)
        if match:
            tokens.append(match[0])
            i += len(match[0])
            continue
        token = raw[i]
        index = len(tokens)
        tokens.append(token)
        i += 1
        if token in "([{":
            stack.append((token, index))
        elif token in ")]}":
            require(stack and "([{".index(stack[-1][0]) == ")]}".index(token),
                    "Notes Rust SOURCE delimiter differs")
            _, opening = stack.pop()
            pairs[opening] = index
        require(len(tokens) <= 600000 and len(stack) <= 256, "Notes Rust lexical SOURCE bound exceeded")
    require(not stack and len(tokens) <= 600000, "Notes Rust SOURCE delimiter/token bound is incomplete")
    return tokens, pairs


def cfg_value(tokens: list[str], features: set[str]) -> bool:
    """Only the fixed Windows/test atoms; unsupported selected cfg fails closed."""
    at = 0

    def expression() -> bool:
        nonlocal at
        require(at < len(tokens), "Notes cfg expression is incomplete")
        name = tokens[at]
        at += 1
        if name in ("all", "any", "not"):
            require(at < len(tokens) and tokens[at] == "(", "Notes cfg operator differs")
            at += 1
            values = []
            while at < len(tokens) and tokens[at] != ")":
                values.append(expression())
                if at < len(tokens) and tokens[at] == ",":
                    at += 1
                else:
                    break
            require(at < len(tokens) and tokens[at] == ")" and (name != "not" or len(values) == 1),
                    "Notes cfg argument list differs")
            at += 1
            return all(values) if name == "all" else any(values) if name == "any" else not values[0]
        if at < len(tokens) and tokens[at] == "=":
            at += 1
            require(at < len(tokens) and tokens[at].startswith('"'), "Notes cfg scalar differs")
            value = json.loads(tokens[at])
            at += 1
            if name == "feature":
                return value in features
            known = {"target_os": "windows", "target_arch": "x86_64", "target_env": "msvc",
                     "target_family": "windows", "target_pointer_width": "64", "target_endian": "little"}
            require(name in known, "Notes selected cfg has an unreviewed scalar")
            return value == known[name]
        require(name in {"test", "windows", "unix"}, "Notes selected cfg has an unreviewed atom")
        return name != "unix"

    result = expression()
    require(at == len(tokens), "Notes cfg has trailing SOURCE tokens")
    return result


def attribute_state(attributes: list[list[str]], features: set[str]) -> tuple[bool, bool, bool, str | None]:
    active, ignored, is_test, path = True, False, False, None
    for attribute in attributes:
        require(attribute, "Notes empty selected SOURCE attribute")
        kind = attribute[0]
        if kind == "cfg":
            require(attribute[1:2] == ["("] and attribute[-1:] == [")"], "Notes cfg attribute differs")
            active = cfg_value(attribute[2:-1], features) and active
        elif kind == "cfg_attr":
            raise CheckFailure("Notes selected cfg_attr requires separate SOURCE review")
        elif kind == "ignore":
            ignored = True
        elif kind == "test":
            require(attribute == ["test"] and not is_test, "Notes test marker is duplicated")
            is_test = True
        elif kind == "path":
            require(path is None and len(attribute) == 3 and attribute[1] == "=",
                    "Notes explicit module path differs")
            path = json.loads(attribute[2])
            require(type(path) is str and re.fullmatch(r"[A-Za-z0-9_./-]{1,200}", path)
                    and not any(piece in {"", ".", ".."} for piece in path.split("/")),
                    "Notes explicit module SOURCE path is not closed")
    return active, ignored, is_test, path


def admit_rust_sources(context: dict) -> dict:
    contract = source_contract(context)
    source = Path(context["source"])
    inventory = {row["path"] for row in context["sourceFiles"]}
    result = {}
    for role, spec in ROLES.items():
        selectors = set(contract["rust"][role])
        features = ({"image-stdio", "image-writer", "required-notes"} if role == "native"
                    else {"required-notes"} if role == "bridge" else set(spec[3]))
        found = {name: [] for name in selectors}
        visits, active_files = set(), set()

        def selected_prefix(prefix: str) -> bool:
            return any(name.startswith(prefix + "::") for name in selectors)

        def scan_file(path: Path, prefix: str, active: bool) -> None:
            relative = path.relative_to(source).as_posix()
            require(relative in inventory and (relative, prefix) not in visits and len(visits) < 32,
                    "Notes selected module SOURCE is missing, recursive or duplicated")
            visits.add((relative, prefix))
            active_files.add(relative)
            body = read(path, 2 << 20).decode("utf-8")
            tokens, pairs = rust_tokens(body)
            implicit = path.parent if path.name in {"lib.rs", "main.rs", "mod.rs"} else path.parent / path.stem
            scan_block(tokens, pairs, 0, len(tokens), path, implicit, prefix, active)

        def scan_block(tokens, pairs, start, end, path, implicit, prefix, active):
            attributes, i = [], start
            while i < end:
                if tokens[i] == "#" and i + 1 < end:
                    inner = tokens[i + 1] == "!"
                    opening = i + 2 if inner else i + 1
                    require(opening in pairs and tokens[opening] == "[", "Notes SOURCE attribute is malformed")
                    closing = pairs[opening]
                    attribute = tokens[opening + 1:closing]
                    if inner:
                        enabled, ignored, is_test, alternate = attribute_state([attribute], features)
                        require(not ignored and not is_test and alternate is None, "Notes inner selected module attribute differs")
                        active = active and enabled
                    else:
                        attributes.append(attribute)
                    i = closing + 1
                    continue
                if tokens[i] == "mod" and i + 2 < end:
                    name, body_at = tokens[i + 1], i + 2
                    route = prefix + "::" + name if prefix else name
                    require(tokens[body_at] in {"{", ";"}, "Notes selected module declaration differs")
                    if selected_prefix(route):
                        enabled, ignored, is_test, alternate = attribute_state(attributes, features)
                        require(not ignored and not is_test, "Notes selected module is ignored or has a test attribute")
                        if tokens[body_at] == "{":
                            require(alternate is None, "Notes inline selected module has an external path")
                            scan_block(tokens, pairs, body_at + 1, pairs[body_at], path, implicit / name,
                                       route, active and enabled)
                        else:
                            candidates = ([path.parent / alternate] if alternate is not None
                                          else [implicit / (name + ".rs"), implicit / name / "mod.rs"])
                            candidates = [candidate for candidate in candidates
                                          if candidate.relative_to(source).as_posix() in inventory]
                            require(len(candidates) == 1, "Notes external module SOURCE is missing or ambiguous")
                            scan_file(candidates[0], route, active and enabled)
                    attributes = []
                    i = pairs[body_at] + 1 if tokens[body_at] == "{" else body_at + 1
                    continue
                if tokens[i] == "fn" and i + 1 < end:
                    name = tokens[i + 1]
                    selector = prefix + "::" + name if prefix else name
                    if selector in selectors:
                        enabled, ignored, is_test, alternate = attribute_state(attributes, features)
                        found[selector].append((active and enabled, ignored, is_test, alternate is None))
                    attributes = []
                if tokens[i] == "{":
                    i = pairs[i] + 1
                    attributes = []
                    continue
                if tokens[i] == ";":
                    attributes = []
                i += 1

        scan_file(source / spec[0] / "src/lib.rs", "", True)
        require(all(observations == [(True, False, True, True)] for observations in found.values()),
                "Notes selector is inactive, ignored, missing, not a test, or not unique in its bound module")
        result[role] = {"selected": len(selectors), "sourceFiles": sorted(active_files)}
    require(sum(row["selected"] for row in result.values()) == 63, "Notes Rust selected source total differs")
    return result


SMALL_VERSIONS = {
    "block-buffer": "0.10.4", "cfg-if": "1.0.5", "cpufeatures": "0.2.17", "crypto-common": "0.1.7",
    "digest": "0.10.7", "generic-array": "0.14.7", "sha2": "0.10.9", "typenum": "1.20.1",
    "version_check": "0.9.5", "windows-link": "0.2.1", "windows-sys": "0.61.2",
    "mrk-windows-installed-native": "0.1.0",
}
SMALL_EDGES = {
    "mrk-windows-installed-native": {"sha2", "windows-sys"},
    "sha2": {"cfg-if", "cpufeatures", "digest"}, "digest": {"block-buffer", "crypto-common"},
    "block-buffer": {"generic-array"}, "crypto-common": {"generic-array", "typenum"},
    "generic-array": {"typenum", "version_check"}, "windows-sys": {"windows-link"},
}


def small_graph(value: object, lock: object, *, source: Path, root: Path, role: str) -> dict:
    require(role in {"native", "bridge"} and type(value) is dict and value.get("version") == 1
            and type(value.get("packages")) is list and 1 <= len(value["packages"]) <= 64,
            "Notes small Windows metadata shape differs")
    require(type(lock) is dict and lock.get("version") == 4 and type(lock.get("package")) is list
            and 1 <= len(lock["package"]) <= 64, "Notes small source lock differs")
    locked = {}
    for row in lock["package"]:
        identity = (row.get("name"), row.get("version"), row.get("source"))
        require(all(type(v) is str for v in identity[:2]) and identity not in locked
                and (identity[2] is None or identity[2] == REGISTRY and sha256_value(row.get("checksum"))),
                "Notes small lock identity/checksum differs")
        locked[identity] = row
    versions = dict(SMALL_VERSIONS)
    if role == "bridge":
        versions["mrk-windows-image-writer-bridge"] = "0.1.0"
    local_names = {name for name in versions if name.startswith("mrk-")}
    packages, local, identities = {}, {}, set()
    for package in value["packages"]:
        require(type(package) is dict and type(package.get("id")) is str and 0 < len(package["id"]) <= 4096
                and package["id"] not in packages and type(package.get("features")) is dict
                and type(package.get("targets")) is list and 1 <= len(package["targets"]) <= 512,
                "Notes small package declaration differs")
        identity = (package.get("name"), package.get("version"), package.get("source"))
        require(identity in locked and identity not in identities, "Notes small package is outside its pinned source lock")
        identities.add(identity)
        manifest = Path(package["manifest_path"])
        if identity[2] is None:
            require(identity[0] in local_names and identity[0] not in local, "Notes small graph has a foreign local")
            local_role = "native" if identity[0] == ROLES["native"][1] else "bridge"
            require(manifest == source / ROLES[local_role][0] / "Cargo.toml", "Notes small local path differs")
            local[identity[0]] = package["id"]
        else:
            registry_root = root / "cargo/registry/src"
            require(manifest.is_absolute() and manifest.is_relative_to(registry_root)
                    and len(manifest.relative_to(registry_root).parts) == 3
                    and manifest.parent.name == identity[0] + "-" + identity[1] and manifest.name == "Cargo.toml",
                    "Notes registry package left its private acquisition")
        for target in package["targets"]:
            require(type(target) is dict and type(target.get("src_path")) is str
                    and Path(target["src_path"]).is_relative_to(manifest.parent),
                    "Notes small target SOURCE path differs")
        packages[package["id"]] = package
    require(set(local) == local_names, "Notes small active locals differ")
    root_id = local[ROLES[role][1]]
    require(value.get("workspace_root") == str(source / ROLES[role][0])
            and value.get("workspace_members") == [root_id] and value.get("workspace_default_members") == [root_id]
            and value.get("target_directory") == str(root / "target" / role), "Notes fixed small workspace differs")
    resolve = value.get("resolve")
    require(type(resolve) is dict and resolve.get("root") == root_id and type(resolve.get("nodes")) is list,
            "Notes small active resolution differs")
    nodes, names = {}, {}
    for node in resolve["nodes"]:
        require(type(node) is dict and node.get("id") in packages and node["id"] not in nodes
                and type(node.get("features")) is list and type(node.get("deps")) is list
                and type(node.get("dependencies")) is list, "Notes small active node differs")
        package = packages[node["id"]]
        name = package["name"]
        require(name in versions and name not in names and package["version"] == versions[name]
                and package.get("source") == (None if name in local_names else REGISTRY)
                and node["features"] == sorted(set(node["features"]))
                and set(node["features"]) <= set(package["features"]), "Notes small active identity/features differ")
        nodes[node["id"]], names[name] = node, node["id"]
    # The Windows closure, not every platform row in the lock. In particular
    # libc's inactive cpufeatures declaration does not become a Windows unit.
    require(set(names) == set(versions), "Notes Windows SHA/platform active closure differs")
    edges = {**SMALL_EDGES, "mrk-windows-image-writer-bridge": {"mrk-windows-installed-native"}}
    declarations = {}
    for name, key in names.items():
        node, package = nodes[key], packages[key]
        expected = {names[dep] for dep in edges.get(name, set())}
        require(len(node["dependencies"]) == len(expected) and set(node["dependencies"]) == expected
                and len(node["deps"]) == len(expected) and {edge.get("pkg") for edge in node["deps"]} == expected,
                "Notes fixed small dependency closure differs")
        for edge in node["deps"]:
            require(type(edge) is dict and edge.get("pkg") in expected
                    and edge.get("name") == packages[edge["pkg"]]["name"].replace("-", "_")
                    and type(edge.get("dep_kinds")) is list and len(edge["dep_kinds"]) == 1,
                    "Notes small dependency edge differs")
            kind = edge["dep_kinds"][0]
            wanted_kind = "build" if (name, packages[edge["pkg"]]["name"]) == ("generic-array", "version_check") else None
            require(type(kind) is dict and set(kind) == {"kind", "target"} and kind["kind"] == wanted_kind,
                    "Notes small dependency unit role differs")
            if kind["target"] is not None:
                tokens, _ = rust_tokens(kind["target"])
                require(tokens[:2] == ["cfg", "("] and tokens[-1:] == [")"]
                        and cfg_value(tokens[2:-1], set()), "Notes active edge has a non-Windows target")
            matched = [dep for dep in package.get("dependencies", [])
                       if dep.get("name") == packages[edge["pkg"]]["name"]
                       and (dep.get("rename") or dep["name"]).replace("-", "_") == edge["name"]
                       and dep.get("kind") == kind["kind"] and dep.get("target") == kind["target"]]
            require(len(matched) == 1 and type(matched[0].get("features")) is list
                    and type(matched[0].get("uses_default_features")) is bool,
                    "Notes small edge source declaration is ambiguous")
            declarations[key, edge["pkg"]] = matched[0]
    require(packages[local[ROLES["native"][1]]]["features"] == manifest_features(source),
            "Notes complete native declared feature map differs")
    if role == "bridge":
        require(packages[root_id]["features"] == {"default": [], "required-notes": ["mrk-windows-installed-native/required-notes"]},
                "Notes bridge feature map differs")
    return {"packages": packages, "nodes": nodes, "rootId": root_id, "localIds": local,
            "role": role, "declarations": declarations}


def small_unit_features(graph: dict) -> dict:
    """Fixed already-admitted normal/build graph only; no metadata feature union."""
    packages, nodes, declarations = graph["packages"], graph["nodes"], graph["declarations"]
    expected = {key: set() for key in nodes}
    expected[graph["rootId"]].add("required-notes")
    for (parent, child), dep in declarations.items():
        mapping = packages[child]["features"]
        require(all(type(name) is str and name in mapping for name in dep["features"]),
                "Notes requested small unit feature is undeclared")
        expected[child].update(dep["features"])
        if dep["uses_default_features"] and "default" in mapping:
            expected[child].add("default")
    for _ in range(128):
        before = sum(len(features) for features in expected.values())
        for key, features in expected.items():
            mapping = packages[key]["features"]
            require(len(mapping) <= 512, "Notes small feature map exceeds its bound")
            aliases = {edge["name"]: edge["pkg"] for edge in nodes[key]["deps"]}
            for feature in tuple(features):
                require(feature in mapping and type(mapping[feature]) is list and len(mapping[feature]) <= 128,
                        "Notes small selected feature definition differs")
                for ref in mapping[feature]:
                    require(type(ref) is str and 0 < len(ref) <= 256, "Notes small feature expression differs")
                    if ref.startswith("dep:"):
                        require(ref[4:].replace("-", "_") in aliases, "Notes selected optional edge is inactive")
                    elif "/" in ref:
                        alias, child_feature = ref.split("/", 1)
                        weak = alias.endswith("?")
                        alias = alias.removesuffix("?").replace("-", "_")
                        if weak and alias not in aliases:
                            continue
                        require(alias in aliases and child_feature in packages[aliases[alias]]["features"],
                                "Notes selected small forwarding edge differs")
                        expected[aliases[alias]].add(child_feature)
                    else:
                        require(ref in mapping, "Notes selected small local feature differs")
                        features.add(ref)
        if sum(len(features) for features in expected.values()) == before:
            break
    else:
        raise CheckFailure("Notes small feature closure exceeded its fixed bound")
    for key, features in expected.items():
        require(set(nodes[key]["features"]) == features, "Notes small metadata contains an unadmitted feature union")
    return base.windows_installed_platform_unit_features(graph, {key: sorted(value) for key, value in expected.items()})


def app_direct_roles(packages: dict, nodes: dict, app: str) -> None:
    """Current Notes-only declarations; do not widen the installed readers."""
    observed = {(packages[key]["name"], packages[key]["version"]) for key in nodes[app]["dependencies"]}
    missing, unexpected = sorted(WINDOWS_INSTALLED_APP_DIRECT_ROLES - observed), sorted(observed - WINDOWS_INSTALLED_APP_DIRECT_ROLES)
    require(not missing and not unexpected,
            "Windows app selected direct dependencies differ; missing=" + repr(missing)[:1536]
            + "; unexpected=" + repr(unexpected[:16])[:1536] + "; unexpectedCount=" + str(len(unexpected)))
    declarations = packages[app]["dependencies"]
    for name, version, defaults, features in (
            ("base64", "0.22.1", False, []),
            ("crypto_box", "0.9.1", False, ["seal", "salsa20", "rand_core"]),
            ("curve25519-dalek", "4.1.3", False, ["zeroize"]),
            ("rand_chacha", "0.3.1", False, []),
            ("zeroize", "1.9.0", False, ["alloc"]),
            ("sha2", "0.10.9", True, [])):
        kinds = (None, "build") if name == "sha2" else (None,)
        expected = [{"name": name, "source": REGISTRY, "req": "=" + version, "kind": kind, "rename": None,
                     "optional": False, "uses_default_features": defaults, "features": features,
                     "target": None, "registry": None} for kind in kinds]
        actual = [dep for dep in declarations if dep.get("name") == name]
        require(len(actual) == len(expected)
                and all(sum(same_compile_json(dep, wanted) for dep in actual) == 1 for wanted in expected),
                "Notes current direct declaration differs: " + name)
        incoming = [edge for edge in nodes[app]["deps"] if packages[edge["pkg"]]["name"] == name]
        expected_kinds = [{"kind": kind, "target": None} for kind in kinds]
        require(len(incoming) == 1 and packages[incoming[0]["pkg"]]["version"] == version
                and packages[incoming[0]["pkg"]].get("source") == REGISTRY
                and incoming[0]["name"] == name.replace("-", "_")
                and len(incoming[0]["dep_kinds"]) == len(expected_kinds)
                and all(sum(same_compile_json(kind, wanted) for kind in incoming[0]["dep_kinds"]) == 1
                        for wanted in expected_kinds), "Notes current direct edge kinds differ: " + name)


def app_unit_features(graph: dict) -> tuple[dict, dict]:
    """Fixed Notes normal/host contracts, not a resolver or metadata-union grant."""
    packages, nodes = graph["packages"], graph["nodes"]
    app_direct_roles(packages, nodes, graph["rootId"])
    expected = {key: node["features"] for key, node in nodes.items()}
    expected.update(base.windows_installed_fixed_normal_features(graph, notes_source=True))
    versions = {
        "sha2": "0.10.9", "cfg-if": "1.0.5", "cpufeatures": "0.2.17", "digest": "0.10.7",
        "block-buffer": "0.10.4", "crypto-common": "0.1.7", "generic-array": "0.14.7",
        "typenum": "1.20.1", "version_check": "0.9.5",
    }

    def package(name, version):
        found = [key for key in nodes if packages[key]["name"] == name]
        require(len(found) == 1, "Notes fixed SHA2 package is missing/ambiguous: " + name)
        key = found[0]
        require(packages[key]["version"] == version and packages[key].get("source") == REGISTRY,
                "Notes fixed SHA2 package version/source differs: " + name)
        return key

    def library(key):
        value = packages[key]
        primary = [target for target in value["targets"] if target.get("kind") in (["lib"], ["proc-macro"])]
        require(len(primary) == 1 and primary[0]["kind"] == ["lib"] and primary[0].get("crate_types") == ["lib"]
                and primary[0].get("name") == value["name"].replace("-", "_")
                and primary[0].get("src_path") == str(Path(value["manifest_path"]).parent / "src/lib.rs"),
                "Notes fixed SHA2 source library role differs: " + value["name"])

    ids = {name: package(name, version) for name, version in versions.items()}
    host = {
        "sha2": ["default", "std"], "cfg-if": [], "cpufeatures": [],
        "digest": ["alloc", "block-buffer", "core-api", "default", "std"], "block-buffer": [],
        "crypto-common": ["std"], "generic-array": ["more_lengths"], "typenum": [], "version_check": [],
    }
    normal = {**host,
        "digest": ["alloc", "block-buffer", "core-api", "default", "mac", "std", "subtle"],
        "crypto-common": ["rand_core", "std"], "generic-array": ["more_lengths", "zeroize"],
    }
    definitions = {
        "sha2": {"default": ["std"], "std": ["digest/std"]},
        "digest": {"alloc": [], "block-buffer": ["dep:block-buffer"], "core-api": ["block-buffer"],
                   "default": ["core-api"], "mac": ["subtle"], "std": ["alloc", "crypto-common/std"],
                   "subtle": ["dep:subtle"]},
        "crypto-common": {"rand_core": ["dep:rand_core"], "std": []},
        "generic-array": {"more_lengths": [], "zeroize": ["dep:zeroize"]},
    }
    for name, key in ids.items():
        library(key)
        value, mapping = packages[key], packages[key]["features"]
        require(type(mapping) is dict and len(mapping) <= 512
                and all(type(feature) is str and re.fullmatch(r"[A-Za-z0-9_+\-]{1,128}", feature) for feature in mapping)
                and all(same_compile_json(mapping.get(feature), refs) for feature, refs in definitions.get(name, {}).items())
                and ("default" in normal[name] or "default" not in mapping)
                and set(normal[name]) <= set(nodes[key]["features"]),
                "Notes fixed SHA2 feature definitions/metadata differ: " + name)
        scripts = [target for target in value["targets"] if target.get("kind") == ["custom-build"]]
        require((not scripts if name != "generic-array" else len(scripts) == 1
                 and scripts[0].get("crate_types") == ["bin"] and scripts[0].get("name") == "build-script-build"
                 and scripts[0].get("src_path") == str(Path(value["manifest_path"]).parent / "build.rs")),
                "Notes fixed SHA2 build-script source role differs: " + name)
        expected[key] = normal[name]

    # Complete active declarations in this fixed cohort. The three named
    # optional edges are target-only: host features above do not activate them.
    cpu_target = 'cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))'
    edges = {
        "sha2": (("cfg-if", "1.0.5", "^1.0", None, None, False, True, []),
                 ("digest", "0.10.7", "^0.10.7", None, None, False, True, []),
                 ("cpufeatures", "0.2.17", "^0.2", None, cpu_target, False, True, [])),
        "digest": (("block-buffer", "0.10.4", "^0.10", None, None, True, True, []),
                   ("crypto-common", "0.1.7", "^0.1.3", None, None, False, True, []),
                   ("subtle", "2.6.1", "^2.4", None, None, True, False, [])),
        "block-buffer": (("generic-array", "0.14.7", "^0.14", None, None, False, True, []),),
        "crypto-common": (("generic-array", "0.14.7", "=0.14.7", None, None, False, True, ["more_lengths"]),
                          ("rand_core", "0.6.4", "^0.6", None, None, True, True, []),
                          ("typenum", "1.20.1", "^1.14", None, None, False, True, [])),
        "generic-array": (("typenum", "1.20.1", "^1.12", None, None, False, True, []),
                          ("zeroize", "1.9.0", "^1", None, None, True, False, []),
                          ("version_check", "0.9.5", "^0.9", "build", None, False, True, [])),
    }

    def declaration(parent, child_name, child_version, requirement, kind, target, optional, defaults, features):
        child = package(child_name, child_version)
        wanted = {"name": child_name, "source": REGISTRY, "req": requirement, "kind": kind, "rename": None,
                  "optional": optional, "uses_default_features": defaults, "features": features,
                  "target": target, "registry": None}
        matches = [dep for dep in packages[parent].get("dependencies", [])
                   if dep.get("name") == child_name and dep.get("kind") == kind and dep.get("target") == target]
        incoming = [edge for edge in nodes[parent]["deps"] if edge["pkg"] == child]
        require(len(matches) == 1 and same_compile_json(matches[0], wanted)
                and len(incoming) == 1 and incoming[0]["name"] == child_name.replace("-", "_")
                and same_compile_json(incoming[0]["dep_kinds"], [{"kind": kind, "target": target}]),
                "Notes fixed SHA2 active declaration/edge differs: " + packages[parent]["name"] + "/" + child_name)
        return child

    for name, key in ids.items():
        children = {declaration(key, *spec) for spec in edges.get(name, ())}
        require(len(nodes[key]["deps"]) == len(children)
                and set(nodes[key]["dependencies"]) == children,
                "Notes fixed SHA2 active outgoing cohort differs: " + name)

    # Bind the three target-only feature causes, not just their metadata names.
    causes = {
        "digest": (("sha2", "0.10.9", "^0.10.7", False, True, []),
                   ("blake2", "0.10.6", "^0.10.3", False, True, ["mac"])),
        "crypto-common": (("aead", "0.5.2", "^0.1.4", False, True, []),
                          ("cipher", "0.4.4", "^0.1.6", False, True, []),
                          ("digest", "0.10.7", "^0.1.3", False, True, []),
                          ("universal-hash", "0.5.1", "^0.1.6", False, True, [])),
        "generic-array": (("aead", "0.5.2", "^0.14", False, False, []),
                          ("block-buffer", "0.10.4", "^0.14", False, True, []),
                          ("crypto-common", "0.1.7", "=0.14.7", False, True, ["more_lengths"]),
                          ("crypto_secretbox", "0.1.1", "^0.14.7", False, False, ["zeroize"]),
                          ("inout", "0.1.4", "^0.14", False, True, [])),
    }
    parent_definitions = {
        "aead": {"alloc": [], "rand_core": ["crypto-common/rand_core"]},
        "blake2": {}, "cipher": {"zeroize": ["dep:zeroize"]},
        "crypto_secretbox": {"salsa20": ["dep:salsa20"]}, "inout": {}, "universal-hash": {},
    }
    for child_name, parents in causes.items():
        child = ids[child_name]
        incoming = [(key, edge) for key, node in nodes.items() for edge in node["deps"] if edge["pkg"] == child]
        wanted = set()
        for name, version, requirement, optional, defaults, features in parents:
            parent = package(name, version)
            library(parent)
            declaration(parent, child_name, versions[child_name], requirement, None, None, optional, defaults, features)
            wanted.add(parent)
            if name in parent_definitions:
                mapping, definitions_for_parent = packages[parent]["features"], parent_definitions[name]
                require(nodes[parent]["features"] == sorted(definitions_for_parent)
                        and all(same_compile_json(mapping.get(feature), refs) for feature, refs in definitions_for_parent.items()),
                        "Notes target-only SHA2 parent feature cause differs: " + name)
        require(len(incoming) == len(wanted) and {key for key, _ in incoming} == wanted,
                "Notes fixed SHA2 incoming parent cohort differs: " + child_name)

    build_edges = [(packages[key]["name"], packages[key]["version"],
                          packages[edge["pkg"]]["name"], packages[edge["pkg"]]["version"], kind["target"])
                         for key, node in nodes.items() for edge in node["deps"] for kind in edge["dep_kinds"]
                         if kind["kind"] == "build"]
    require(sorted(build_edges, key=repr) == [
        ("curve25519-dalek", "4.1.3", "rustc_version", "0.4.1", None),
        ("generic-array", "0.14.7", "version_check", "0.9.5", None),
        ("mobile-release-kit-desktop", "0.1.0", "sha2", "0.10.9", None),
    ], "Notes fixed host build edge cohort differs")
    expected = base.windows_installed_platform_unit_features(graph, expected)
    return expected, {ids[name]: features for name, features in host.items()}


def compiler_unit_context(package: dict, target: dict, filenames: list, features: object,
                          normal: list, host: list | None, *, target_root: Path) -> str:
    """DATA-only role selection; never touch a compiler output during parsing."""
    context, wanted = "single", normal
    if host is not None:
        if target["kind"] == ["lib"]:
            places = {"host": target_root / "debug/deps",
                      "target": target_root / TARGET / "debug/deps"}
            matches = [name for name, directory in places.items()
                       if filenames and all(Path(path).parent == directory for path in filenames)]
            require(len(matches) == 1 and (package["name"] != "version_check" or matches[0] == "host"),
                    "Notes SHA2 library output has no exact unmixed unit context")
            context = matches[0]
            wanted = host if context == "host" else normal
        else:
            require(package["name"] == "generic-array" and target["kind"] == ["custom-build"],
                    "Notes SHA2 unit has an unreviewed target kind")
            variants = {"host": host, "target": normal}
            matches = [name for name, selected in variants.items() if same_compile_json(features, selected)]
            require(len(matches) == 1, "Notes generic-array build has no exact owner feature variant")
            context, wanted = matches[0], variants[matches[0]]
            require(filenames and all(Path(path).parent.parent == target_root / "debug/build"
                    and re.fullmatch(r"generic-array-[0-9a-f]{16}", Path(path).parent.name)
                    for path in filenames), "Notes generic-array compiler output left its host build namespace")
    require(same_compile_json(features, wanted),
            "Notes compiler unit features differ: " + package["name"] + "/" + context
            + "; expected=" + repr(wanted)[:1024] + "; observed=" + repr(features)[:1024])
    return context


def build_script_context(package: dict, out_dir: str, *, target_root: Path, split: bool) -> str:
    if not split:
        return "single"
    path = Path(out_dir)
    matches = [name for name, directory in (
        ("host", target_root / "debug/build"),
        ("target", target_root / TARGET / "debug/build"))
        if path.name == "out" and path.parent.parent == directory
        and re.fullmatch(r"generic-array-[0-9a-f]{16}", path.parent.name)]
    require(package["name"] == "generic-array" and len(matches) == 1,
            "Notes generic-array execution has no exact owner out_dir context")
    return matches[0]


def admit_script_event(scripts: set, executions: set, key: str, context: str, *, compiled: bool) -> None:
    """Only a role admitted by compiler_unit_context may create a script key."""
    require(type(compiled) is bool and context in {"single", "host", "target"},
            "Notes build-script event context differs")
    unit = (key, context)
    if compiled:
        require(unit not in scripts, "Notes build script became a duplicate unit variant")
        scripts.add(unit)
    else:
        require(unit in scripts and unit not in executions,
                "Notes build-script execution is unmatched or duplicated for its unit variant")
        executions.add(unit)


def app_graph(value: object, lock: object, *, source: Path, root: Path) -> dict:
    native_declared = manifest_features(source)
    publication = False  # No publisher role or selector exists in this driver.
    require(type(value) is dict and type(value.get("version")) is int and value["version"] == 1 and type(value.get("packages")) is list
            and 4 <= len(value["packages"]) <= 512, "Windows app package inventory differs")
    require(type(lock) is dict and type(lock.get("version")) is int and lock["version"] == 4 and type(lock.get("package")) is list
            and 4 <= len(lock["package"]) <= 2048, "Windows app source-bound lock differs")
    require(len(lock["package"]) == 527, "Notes app lock lost current package rows")
    locked = {}
    for row in lock["package"]:
        require(type(row) is dict and type(row.get("name")) is str and type(row.get("version")) is str
                and (row.get("source") is None or type(row["source"]) is str), "Windows app lock identity differs")
        key = (row["name"], row["version"], row.get("source"))
        require(key not in locked and (key[2] is None or key[2] == "registry+https://github.com/rust-lang/crates.io-index"
                and sha256_value(row.get("checksum"))), "Windows app lock source/checksum differs")
        locked[key] = row
    require({key[:2] for key in locked if key[2] is None}
            == set(WINDOWS_INSTALLED_APP_LOCK_LOCALS.items()), "Windows app declared lock locals differ")
    active_locals = {"mobile-release-kit-desktop", "mrk-windows-installed-native"}
    packages, local, identities = {}, {}, set()
    for package in value["packages"]:
        require(type(package) is dict and type(package.get("id")) is str and 0 < len(package["id"]) <= 4096
                and package["id"] not in packages and type(package.get("name")) is str
                and type(package.get("version")) is str and type(package.get("manifest_path")) is str
                and type(package.get("features")) is dict and (package.get("source") is None or type(package["source"]) is str),
                "Windows app package identity differs")
        # Cargo inventories unselected integration tests too (locked tokio has
        # 158 declarations). This finite DATA bound is not compiler permission:
        # windows_installed_app_test_path separately admits actual selected units.
        require(type(package.get("targets")) is list and 0 < len(package["targets"]) <= 512,
                "Windows app declared target inventory differs")
        key = (package["name"], package["version"], package.get("source"))
        require(key in locked and key not in identities, "Windows app package is duplicated/outside the original lock")
        identities.add(key)
        if key[2] is None:
            require(key[0] in active_locals and key[0] not in local and key[1] == "0.1.0"
                    and package["manifest_path"] == str(source / WINDOWS_INSTALLED_APP_LOCALS[key[0]]),
                    "Windows app declared local path differs")
            local[key[0]] = package["id"]
        else:
            manifest = Path(package["manifest_path"])
            registry = root / "cargo" / "registry" / "src"
            require(manifest.is_absolute() and manifest.is_relative_to(registry)
                    and len(manifest.relative_to(registry).parts) == 3
                    and manifest.parent.name == key[0] + "-" + key[1] and manifest.name == "Cargo.toml",
                    "Windows app registry manifest left the private acquisition")
        packages[package["id"]] = package
    require(set(local) == active_locals, "Windows app target must contain exactly two local packages")
    app = local["mobile-release-kit-desktop"]
    require(packages[app]["features"].get("windows-runtime-publisher") == ["mrk-windows-installed-native/runtime-publication"],
            "Windows app publisher feature must forward only the production native feature")
    require(value.get("workspace_root") == str(source / WINDOWS_INSTALLED_APP)
            and value.get("workspace_members") == [app] and value.get("workspace_default_members") == [app]
            and value.get("target_directory") == str(root / "target" / "app"), "Windows app original workspace/target differs")
    # Cargo filters package/resolve rows, not the selected app's declarations.
    # Keep the source lock's six locals separate from actual Windows packages:
    # three native normal declarations, the qualified Windows dev declaration,
    # and two inactive Linux secret-service declarations. zbus is a registry
    # dependency resolved through the source patch, not another path declaration.
    declarations = packages[app].get("dependencies")
    require(type(declarations) is list and 6 <= len(declarations) <= 256
            and all(type(dep) is dict and type(dep.get("name")) is str for dep in declarations),
            "Windows app dependency declarations differ")
    targets = {
        "mrk-linux-mount-observation": 'cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))',
        "mrk-macos-installed-native": 'cfg(all(target_os = "macos", target_arch = "aarch64"))',
        "mrk-windows-installed-native": 'cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))',
    }
    normal = {name: {"name": name, "source": None, "req": "*", "kind": None, "rename": None,
        "optional": False, "uses_default_features": True, "features": [], "target": target,
        "registry": None, "path": str((source / WINDOWS_INSTALLED_APP_LOCALS[name]).parent)}
        for name, target in targets.items()}
    secret_service = {"name": "secret-service", "source": None, "req": "=5.2.0", "kind": None,
        "rename": None, "optional": False, "uses_default_features": False, "features": ["rt-tokio-crypto-rust"],
        "target": targets["mrk-linux-mount-observation"], "registry": None,
        "path": str(source / "desktop/vendor/secret-service-5.2.0")}
    expected = [*normal.values(), {**normal["mrk-windows-installed-native"],
                                  "kind": "dev", "features": ["qualification-result"]},
        secret_service, {**secret_service, "kind": "dev", "features": ["rt-tokio-crypto-rust", "mrk-retrieval-test-support"]}]
    declared_locals = [dep for dep in declarations
                       if dep.get("source") is None or "path" in dep or dep["name"] in {*targets, "secret-service"}]
    # A map keyed only by name would collapse normal/dev or duplicate entries.
    # Compare each complete declaration exactly once, independent of order.
    require(len(declared_locals) == 6
            and all(sum(same_compile_json(actual, wanted) for actual in declared_locals) == 1 for wanted in expected),
            "Windows app exact normal and qualification-dev declarations differ")
    resolve = value.get("resolve")
    require(type(resolve) is dict and resolve.get("root") == app and type(resolve.get("nodes")) is list
            and 2 <= len(resolve["nodes"]) <= 256, "Windows app active resolution differs")
    nodes = {}
    for node in resolve["nodes"]:
        require(type(node) is dict and type(node.get("id")) is str and node["id"] in packages and node["id"] not in nodes
                and type(node.get("dependencies")) is list and type(node.get("deps")) is list
                and type(node.get("features")) is list, "Windows app active node differs")
        features = node["features"]
        require(all(type(feature) is str for feature in features) and features == sorted(set(features))
                and set(features) <= set(packages[node["id"]]["features"]), "Windows app resolved features differ")
        nodes[node["id"]] = node
    require(set(nodes) & set(local.values()) == {app, local["mrk-windows-installed-native"]}
            and nodes[app]["features"] == list(ROLES["app"][3])
            and packages[local["mrk-windows-installed-native"]]["features"] == native_declared
            and nodes[local["mrk-windows-installed-native"]]["features"]
                == ["image-stdio", "image-writer", "qualification-result", "required-notes"],
            "Windows app active locals/features differ")
    for node in nodes.values():
        edges = []
        for dep in node["deps"]:
            require(type(dep) is dict and type(dep.get("name")) is str and type(dep.get("pkg")) is str
                    and dep["pkg"] in nodes and type(dep.get("dep_kinds")) is list and 0 < len(dep["dep_kinds"]) <= 3,
                    "Windows app active dependency is missing/inactive")
            for kind in dep["dep_kinds"]:
                require(type(kind) is dict and set(kind) == {"kind", "target"}
                        and (kind["kind"] is None or type(kind["kind"]) is str and kind["kind"] in {"dev", "build"})
                        and (kind["target"] is None or type(kind["target"]) is str), "Windows app dependency kind differs")
            edges.append(dep["pkg"])
        require(all(type(item) is str for item in node["dependencies"])
                and len(set(node["dependencies"])) == len(node["dependencies"])
                and set(node["dependencies"]) == set(edges), "Windows app original edge tables differ")
    native_edges = [edge for edge in nodes[app]["deps"] if edge["pkg"] == local["mrk-windows-installed-native"]]
    expected_kinds = [{"kind": kind, "target": targets["mrk-windows-installed-native"]} for kind in (None, "dev")]
    require(len(native_edges) == 1 and native_edges[0]["name"] == "mrk_windows_installed_native"
            and len(native_edges[0]["dep_kinds"]) == 2
            and all(sum(same_compile_json(actual, wanted) for actual in native_edges[0]["dep_kinds"]) == 1
                    for wanted in expected_kinds), "Windows app qualification dependency edge differs")
    seen, pending = set(), [app]
    while pending:
        current = pending.pop()
        if current not in seen:
            seen.add(current)
            pending.extend(nodes[current]["dependencies"])
    require(seen == set(nodes), "Windows app has a disconnected active compiler node")
    app_direct_roles(packages, nodes, app)
    require({(packages[key]["name"], packages[key]["version"]) for key in nodes[local["mrk-windows-installed-native"]]["dependencies"]}
            == {("sha2", "0.10.9"), ("windows-sys", "0.61.2")}, "Windows app native dependency differs")
    return {"packages": packages, "nodes": nodes, "appId": app, "localIds": local, "publication": publication,
            "rootId": app, "role": "app"}


def metadata(context: dict, role: str) -> dict:
    require(role in ROLES, "Notes unknown fixed compiler graph")
    root, source = Path(context["root"]), Path(context["source"])
    value = data(root / (role + "-metadata.json"), 8 << 20)
    lock = tomllib.loads(read(source / ROLES[role][0] / "Cargo.lock", 8 << 20).decode("utf-8"))
    return (app_graph(value, lock, source=source, root=root) if role == "app"
            else small_graph(value, lock, source=source, root=root, role=role))


def compiler_identity(context: dict, *, select: bool) -> tuple[dict, dict]:
    root = Path(context["root"])
    environment = base.clean_environment(root)
    if select:
        cargo, rustc = base.tools(context, environment)
        value = {"cargo": {"path": cargo, **record(Path(cargo), 128 << 20)},
                 "rustc": {"path": rustc, **record(Path(rustc), 128 << 20)}}
    else:
        value = data(root / "compiler-tools.json")
        require(type(value) is dict and set(value) == {"cargo", "rustc"}, "Notes original compiler tool record differs")
        for row in value.values():
            require(type(row) is dict and set(row) == {"path", "size", "sha256"}
                    and Path(row["path"]).is_absolute() and record(Path(row["path"]), 128 << 20)
                    == {"size": row["size"], "sha256": row["sha256"]}, "Notes original compiler file changed")
        environment["RUSTC"] = value["rustc"]["path"]
        environment["PATH"] = str(Path(value["cargo"]["path"]).parent) + os.pathsep + environment["PATH"]
    return value, environment


def fixed_argv(context: dict, stage: str, role: str, compiler: dict) -> list[str]:
    require(role in ROLES and stage in {"acquire", "compile"}, "Notes unknown fixed Cargo command")
    spec, root, source = ROLES[role], Path(context["root"]), Path(context["source"])
    cargo = compiler["cargo"]["path"]
    if stage == "acquire":
        return [cargo, "metadata", "--locked", "--format-version", "1", "--no-default-features",
                "--filter-platform", TARGET, "--features", ",".join(spec[3]),
                "--manifest-path", str(source / spec[0] / "Cargo.toml")]
    return [cargo, "test", "--locked", "--offline", "--jobs", "1", "--no-default-features",
            "--target", TARGET, "--target-dir", str(root / "target" / role),
            "--manifest-path", str(source / spec[0] / "Cargo.toml"), "--features", ",".join(spec[3]),
            "--lib", "--no-run", "--message-format=json"]


def remaining(deadline: float, ceiling: int) -> int:
    value = int(deadline - time.monotonic())
    require(value > 0, "Notes original phase deadline elapsed")
    return min(ceiling, value)


def invoke(context: dict, stage: str, role: str, environment: dict, deadline: float,
           *, compiler: dict | None = None, artifact: dict | None = None) -> dict:
    """Finite SOURCE-selected commands only; never an argv supplied by workflow input."""
    root, source = Path(context["root"]), Path(context["source"])
    if stage in {"acquire", "compile"}:
        argv = fixed_argv(context, stage, role, compiler)
        stem = role + ("-metadata" if stage == "acquire" else "-compile")
        output_name = stem + (".json" if stage == "acquire" else ".jsonl")
        environment = {**environment, "CARGO_TARGET_DIR": str(root / "target" / role)}
        ceiling = 600 if stage == "acquire" else 1000
    elif stage == "rust-contracts":
        require(role in ROLES and type(artifact) is dict, "Notes fixed Rust original is missing")
        names = source_contract(context)["rust"][role]
        argv = [artifact["path"], *names, "--exact", "--test-threads=1"]
        stem, output_name, ceiling = role + "-contracts", role + "-contracts.stdout", 60
        environment = {**environment, "MRK_DESKTOP_HOSTED_CHECKS": SCOPE}
    elif stage == "python-contracts":
        require(role == "python" and compiler is None and artifact is None, "Notes Python owner role differs")
        argv = [context["python"], "-I", "-S", "-B", str(source / OWNER)]
        stem, output_name, ceiling = "python-contracts", "python-contracts.stdout", 150
        for key in ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion",
                    "GITHUB_JOB", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_REF",
                    "GITHUB_WORKFLOW_SHA", "GITHUB_WORKFLOW_REF", "GITHUB_RUN_ID", "GITHUB_EVENT_NAME",
                    "MRK_DESKTOP_DISPATCH_SCOPE", "MRK_DESKTOP_EXPECTED_SHA", "MRK_DESKTOP_PLATFORM"):
            environment[key] = os.environ.get(key, "")
        environment.update(MRK_DESKTOP_HOSTED_CHECKS=SCOPE, MRK_DESKTOP_CI_ROOT=str(root),
                           GITHUB_WORKSPACE=str(source), RUNNER_TEMP=os.environ["RUNNER_TEMP"], MRK_PYTHON=context["python"])
    else:
        raise CheckFailure("Notes command stage is not admitted")
    # These two original streams are opened exclusively, then the original
    # return/timeout/close must succeed. Failed compilers mint no success record.
    try:
        with (root / output_name).open("xb") as output, (root / (stem + ".stderr")).open("xb") as diagnostics:
            completed = subprocess.run(argv, cwd=root, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=diagnostics, check=True,
                                       timeout=remaining(deadline, ceiling))
        require(output.closed and diagnostics.closed and type(completed.returncode) is int
                and completed.returncode == 0, "Notes original process/stream close did not succeed")
    except subprocess.CalledProcessError as error:
        raise CheckFailure("Notes original " + stage + "/" + role + " exited " + str(error.returncode)) from None
    except subprocess.TimeoutExpired:
        raise CheckFailure("Notes original " + stage + "/" + role + " exceeded its deadline") from None
    except OSError:
        raise CheckFailure("Notes original " + stage + "/" + role + " process or stream operation failed") from None
    return {"originalExitCode": 0, "invocationSha256": hashlib.sha256(base.canonical_json(argv)).hexdigest(),
            "stdout": record(root / output_name, (16 << 20) if stage == "compile" else (8 << 20) if stage == "acquire" else (64 << 10)),
            "stderr": record(root / (stem + ".stderr"), 1 << 20)}


def artifact(context: dict, role: str) -> dict:
    root, source = Path(context["root"]), Path(context["source"])
    spec, graph = ROLES[role], metadata(context, role)
    packages, nodes = graph["packages"], graph["nodes"]
    expected_features, host_features = (app_unit_features(graph) if role == "app" else (small_unit_features(graph), {}))
    target_root = root / "target" / role
    messages = root / (role + "-compile.jsonl")
    raw = read(messages, 16 << 20)
    require(raw and raw.endswith(b"\n"), "Notes original compiler stream is incomplete")
    found, finished, scripts, executions, normal_native = None, False, set(), set(), 0
    for line in raw.splitlines():
        require(not finished, "Notes compiler stream continues after its original finish")
        row = base.bounded_json(line, 2 << 20)
        require(type(row) is dict and row.get("reason") in
                {"compiler-artifact", "compiler-message", "build-script-executed", "build-finished"},
                "Notes compiler message kind differs")
        reason = row["reason"]
        if reason == "build-finished":
            require(row.get("success") is True, "Notes original compiler did not succeed")
            finished = True
            continue
        key = row.get("package_id")
        require(type(key) is str and key in nodes, "Notes compiler unit is outside the selected graph")
        package = packages[key]
        if reason == "build-script-executed":
            declared = [target for target in package["targets"] if target.get("kind") == ["custom-build"]]
            require(len(declared) == 1 and type(row.get("out_dir")) is str
                    and Path(row["out_dir"]).is_absolute() and Path(row["out_dir"]).is_relative_to(target_root)
                    and Path(row["out_dir"]) != target_root
                    and not any(part in {".", ".."} for part in re.split(r"[\\/]", row["out_dir"])),
                    "Notes build-script event lacks its actual admitted compiled unit")
            unit_context = build_script_context(package, row["out_dir"], target_root=target_root,
                split=key in host_features and package["name"] == "generic-array")
            admit_script_event(scripts, executions, key, unit_context, compiled=False)
            continue
        target = row.get("target")
        allowed_root_kind = list(spec[4])
        require(type(target) is dict and sum(same_compile_json(target, declaration) for declaration in package["targets"]) == 1
                and (target.get("kind") in (["lib"], ["proc-macro"], ["custom-build"])
                     or key == graph["rootId"] and target.get("kind") == allowed_root_kind)
                and (row.get("manifest_path") is None or row["manifest_path"] == package["manifest_path"]),
                "Notes compiler target differs from its active source declaration")
        if reason == "compiler-message":
            continue
        profile = row.get("profile")
        require(row.get("manifest_path") == package["manifest_path"]
                and type(profile) is dict and type(profile.get("test")) is bool
                and type(row.get("fresh")) is bool, "Notes compiler unit features/source/profile differ")
        filenames = row.get("filenames")
        require(type(filenames) is list and len(filenames) <= 16 and all(type(name) is str
                and Path(name).is_absolute() and Path(name).is_relative_to(target_root)
                and not any(part in {".", ".."} for part in re.split(r"[\\/]", name)) for name in filenames),
                "Notes compiled unit output left the original role target")
        unit_context = compiler_unit_context(package, target, filenames, row.get("features"), expected_features[key],
                                             host_features.get(key), target_root=target_root)
        if target["kind"] == ["custom-build"]:
            require(profile["test"] is False, "Notes build script became a test unit")
            admit_script_event(scripts, executions, key, unit_context, compiled=True)
        elif key != graph["rootId"]:
            require(profile["test"] is False, "Notes dependency became an unselected test unit")
        if key == graph["localIds"]["mrk-windows-installed-native"] and role != "native":
            require(target.get("kind") == ["lib"] and target.get("crate_types") == ["lib"]
                    and target.get("name") == "mrk_windows_installed_native"
                    and target.get("src_path") == str(source / ROLES["native"][0] / "src/lib.rs")
                    and profile["test"] is False, "Notes native dependency is not its normal library unit")
            normal_native += 1
        if row.get("executable") is not None:
            require(found is None and key == graph["rootId"] and target.get("name") == spec[2]
                    and target.get("kind") == allowed_root_kind and target.get("crate_types") == allowed_root_kind
                    and target.get("src_path") == str(source / spec[0] / "src/lib.rs")
                    and profile["test"] is True and profile.get("debug_assertions") is True and row["fresh"] is False,
                    "Notes original libtest artifact role/features/freshness differ")
            candidate = Path(row["executable"])
            require(candidate.is_absolute() and candidate.parent == target_root / TARGET / "debug/deps"
                    and re.fullmatch(re.escape(spec[2]) + r"-[0-9a-f]{16}\.exe", candidate.name) is not None
                    and row["executable"] in filenames, "Notes original artifact is not the exact role libtest EXE")
            found = candidate
        elif key == graph["rootId"] and target["kind"] != ["custom-build"]:
            raise CheckFailure("Notes root compiler unit did not yield the original libtest executable")
    require(finished and found is not None and (role == "native" or normal_native == 1),
            "Notes original stream lacks its unique libtest or normal native dependency")
    # No artifact path is touched until the ENTIRE original compiler stream,
    # declarations, unit feature roles and final build-finished event are admitted.
    base.windows_installed_directories(found.parent)
    before = found.lstat()
    identity = list(base.windows_installed_state(before))
    measured = record(found, 512 << 20)
    require(list(base.windows_installed_state(found.lstat())) == identity, "Notes original artifact identity changed")
    return {"path": str(found), **measured, "identity": identity, "messages": record(messages, 16 << 20)}


def receipt(context: dict, phase: str, *, started: bool = False, **facts) -> dict:
    return {"scope": SCOPE, "phase": phase, "status": "started" if started else "passed",
            **{key: context[key] for key in ("sourceSha", "sourceTree", "runId", "attempt")},
            **facts}


def prior(context: dict, phase: str) -> dict:
    root = Path(context["root"])
    require(data(root / (phase + "-started.json")) == receipt(context, phase, started=True),
            "Notes original phase claim is missing or changed")
    value = data(root / (phase + "-checks.json"), 4 << 20)
    require(type(value) is dict and all(value.get(key) == expected for key, expected in receipt(context, phase).items()),
            "Notes original predecessor did not pass")
    return value


def acquired_gate(context: dict, compiler: dict) -> dict:
    root = Path(context["root"])
    value = prior(context, "acquire")
    require(value.get("compilerTools") == record(root / "compiler-tools.json", 256 << 10)
            and set(value.get("roles", {})) == set(ROLES), "Notes original acquisition record changed")
    for role in ROLES:
        row = value["roles"][role]
        require(type(row.get("originalExitCode")) is int and row["originalExitCode"] == 0
                and row.get("invocationSha256") == hashlib.sha256(base.canonical_json(fixed_argv(context, "acquire", role, compiler))).hexdigest()
                and row.get("stdout") == record(root / (role + "-metadata.json"), 8 << 20)
                and row.get("stderr") == record(root / (role + "-metadata.stderr"), 1 << 20),
                "Notes original acquisition command, return or streams changed")
        metadata(context, role)
    return value


def compiled_gate(context: dict) -> dict:
    compiler, _ = compiler_identity(context, select=False)
    acquired_gate(context, compiler)
    value = prior(context, "compile")
    root = Path(context["root"])
    require(set(value.get("roles", {})) == set(ROLES), "Notes compile gate lacks a role")
    originals = {}
    for role in ROLES:
        row = value["roles"][role]
        observed = artifact(context, role)
        require(type(row.get("originalExitCode")) is int and row["originalExitCode"] == 0
                and row.get("invocationSha256") == hashlib.sha256(base.canonical_json(fixed_argv(context, "compile", role, compiler))).hexdigest()
                and row.get("stdout") == record(root / (role + "-compile.jsonl"), 16 << 20)
                and row.get("stderr") == record(root / (role + "-compile.stderr"), 1 << 20)
                and row.get("artifact") == observed, "Notes original compiler/artifact gate changed")
        originals[role] = observed
    admit_rust_sources(context)
    return originals


def selected_libtest(raw: bytes, names: list[str]) -> dict:
    require(len(raw) <= 64 << 10, "Notes original selected libtest output is overbound")
    lines = [line.strip() for line in raw.decode("ascii").splitlines() if line.strip()]
    require(len(lines) == len(names) + 2 and lines[0] == "running " + str(len(names)) + " tests"
            and len(set(names)) == len(names) and set(lines[1:-1]) == {"test " + name + " ... ok" for name in names},
            "Notes original libtest selected names/statuses differ")
    matched = re.fullmatch(r"test result: ok\. " + str(len(names))
            + r" passed; 0 failed; 0 ignored; 0 measured; ([0-9]{1,5}) filtered out; finished in [0-9]+\.[0-9]+s", lines[-1])
    require(matched is not None and int(matched[1]) <= 8192, "Notes original libtest selected counts differ")
    # Preserve the original bounded filtered count as DATA. Never execute
    # --list or infer a guessed platform suite total to grant another selector.
    return {"passed": len(names), "failed": 0, "ignored": 0, "filtered": int(matched[1])}


def retain(context: dict) -> None:
    """DATA-only failure/success retention. It dispatches no compiler/test/native role."""
    root = Path(context["root"])
    files = {"public-bindings.json": 4 << 20, "acquire-checks.json": 4 << 20,
             "compile-checks.json": 4 << 20, "windows-required-notes-contracts-checks.json": 4 << 20,
             "python-contracts.stdout": 64 << 10, "python-contracts.stderr": 64 << 10}
    for role in ROLES:
        files.update({role + "-metadata.json": 8 << 20, role + "-metadata.stderr": 1 << 20,
                      role + "-compile.jsonl": 16 << 20, role + "-compile.stderr": 1 << 20,
                      role + "-contracts.stdout": 64 << 10, role + "-contracts.stderr": 64 << 10})
    retained, omitted = [], []
    for name, limit in files.items():
        path = root / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and not getattr(info, "st_file_attributes", 0) & 0x400, "Notes retained DATA is not ordinary")
        if info.st_size > limit:
            omitted.append(name)
            continue
        raw = read(path, limit)
        with (root / "public" / name).open("xb") as output:
            require(output.write(raw) == len(raw), "Notes retained DATA original write is incomplete")
        require(read(root / "public" / name, limit) == raw, "Notes retained DATA readback changed")
        retained.append({"path": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    write(root / "public/retention.json", receipt(context, "retain", files=retained, omittedOverBound=omitted,
          retentionOnlyNotCompilerOrNativeSuccess=True, notVerified=list(NOT_VERIFIED)))


def phase(name: str) -> None:
    require(name in PHASES, "Notes fixed phase is unknown")
    deadline = time.monotonic() + {"prepare": 60, "acquire": 900, "compile": 1140,
                                  "windows-required-notes-contracts": 210, "retain": 60}[name]
    current = context(create=name == "prepare", retention_only=name == "retain")
    if name == "prepare":
        remaining(deadline, 1)
        return
    if name == "retain":
        retain(current)
        return
    root = Path(current["root"])
    base.source_unchanged(current)
    admit_rust_sources(current)
    if name == "acquire":
        write(root / "acquire-started.json", receipt(current, name, started=True))
        base.run([current["rustup"], "toolchain", "install", RUST, "--profile", "minimal", "--no-self-update"],
                 check="rust-toolchain-install", cwd=root, env=base.clean_environment(root),
                 timeout=remaining(deadline, 600))
        compiler, environment = compiler_identity(current, select=True)
        write(root / "compiler-tools.json", compiler)
        results = {}
        for role in ROLES:
            results[role] = invoke(current, name, role, environment, deadline, compiler=compiler)
            graph = metadata(current, role)
            results[role]["activePackages"] = sorted(graph["nodes"])
            # Admit the exact normal/build feature units before any compiler.
            app_unit_features(graph) if role == "app" else small_unit_features(graph)
        facts = {"roles": results, "compilerTools": record(root / "compiler-tools.json", 256 << 10)}
    elif name == "compile":
        compiler, environment = compiler_identity(current, select=True)
        require(compiler == data(root / "compiler-tools.json"), "Notes selected compiler changed after acquisition")
        acquired_gate(current, compiler)
        write(root / "compile-started.json", receipt(current, name, started=True))
        results = {}
        for role in ROLES:
            base.windows_installed_directories(root / "target" / role)
            require(not any((root / "target" / role).iterdir()), "Notes compile target is not original and empty")
            results[role] = invoke(current, name, role, environment, deadline, compiler=compiler)
            results[role]["artifact"] = artifact(current, role)
        facts = {"roles": results, "compileOnlyNoLibtestExecution": True}
    else:
        # All three original compiler exit/argv/stream/unit/artifact gates finish
        # before the first selected binary or the separately owned Python fixture.
        originals = compiled_gate(current)
        write(root / (name + "-started.json"), receipt(current, name, started=True))
        _, environment = compiler_identity(current, select=False)
        selected = source_contract(current)
        results = {}
        for role in ROLES:
            require(artifact(current, role) == originals[role], "Notes original test artifact changed before launch")
            results[role] = invoke(current, "rust-contracts", role, dict(environment), deadline, artifact=originals[role])
            require(read(root / (role + "-contracts.stderr"), 64 << 10) == b"", "Notes Rust selected stderr is not empty")
            results[role]["contracts"] = selected_libtest(read(root / (role + "-contracts.stdout"), 64 << 10), selected["rust"][role])
            require(artifact(current, role) == originals[role], "Notes original test artifact changed after return")
        request = receipt(current, "python-owner", started=True, compileChecks=record(root / "compile-checks.json", 4 << 20),
                          contract=record(Path(current["source"]) / CONTRACT, 256 << 10))
        write(root / "python-owner-request.json", request)
        python = invoke(current, "python-contracts", "python", dict(environment), deadline)
        require(read(root / "python-contracts.stderr", 64 << 10) == b"", "Notes Python selected owner stderr is not empty")
        raw = read(root / "python-contracts.stdout", 64 << 10)
        prefix = b"MRK_WINDOWS_NOTES_MEMORY_CONTRACTS="
        require(raw.startswith(prefix) and raw.endswith(b"\n") and raw.count(b"\n") == 1,
                "Notes Python owner output is not its single original receipt")
        observed = base.bounded_json(raw[len(prefix):-1], 64 << 10)
        require(observed == {**request, "phase": "python-owner-return", "status": "passed", "passed": 63, "failed": 0, "ignored": 0,
                             "guard": "pinned-source-scripted-ctypes-memory-only-v1"},
                "Notes original Python owner did not pass the exact guarded selections")
        python["contracts"] = observed
        facts = {"roles": results, "python": python, "notVerified": list(NOT_VERIFIED)}
        require(compiled_gate(current) == originals, "Notes original compile evidence changed during selected contracts")
    inputs(current)
    base.source_unchanged(current)
    remaining(deadline, 1)
    write(root / (name + "-checks.json"), receipt(current, name, **facts))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=PHASES)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        phase(args.phase)
    except Exception as error:
        reason = str(error) if isinstance(error, CheckFailure) else type(error).__name__
        print("Windows Notes SOURCE phase failed: " + reason + ". No native or shipping success is implied.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
