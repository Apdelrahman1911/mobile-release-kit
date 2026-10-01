"""Source-bound Ubuntu alpha package DATA; no application/Store execution.

The hosted owner supplies private, admitted inputs and owns every command and
cleanup. This module reuses the existing runtime preparer, stager and complete
Debian readback instead of changing their publication or installed-owner rules.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tomllib

SOURCE = Path(__file__).absolute().parents[2]


def local(name):
    spec = importlib.util.spec_from_file_location(
        "_alpha_" + name, SOURCE / "desktop/tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


U = local("ci_ubuntu_publication")
D, C = U.D, U.C
P = local("prepare_runtime")
S = local("stage_ubuntu_deb")
TARGET = "x86_64-unknown-linux-gnu"
CONTROLS = Path("desktop/packaging/ubuntu-alpha")
MAP_SHA = "37d9fb826f5ed04cd691c5b8d08c2061e8f1691e279993d5ea6ef65b8f59c150"
VITE_SHA = "ed97e7caa84c313e6e80028447e62b039e9006810e6228837a7b2914c1b438ec"
NPM_LOCK_SHA = "61ed80ddda8840a13fdb54c7aac6b0d5edc3c270c0731d4044542b29fc6736cb"
MAX_BINARY = 512 << 20
ROLES = {
    "main": ("mobile-release-kit-desktop", "src/main.rs", ["custom-protocol", "desktop-shell"]),
    "publisher": ("mrk-runtime-publish", "src/bin/runtime_publish.rs", ["ubuntu-runtime-publisher"]),
}
NPM_REQUIRED = {
    "@tauri-apps/api": "2.11.1", "react": "19.3.0",
    "react-dom": "19.3.0", "scheduler": "0.28.0",
}
NPM_GENERATORS = {"vite", "rollup", "esbuild"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def records_with_modes(value):
    D.need(type(value) is list and 0 < len(value) <= 2048, "Bounded ordinary record list required")
    stripped = []
    for row in value:
        D.need(type(row) is dict and set(row) == {"path", "size", "sha256", "mode"}
               and type(row["mode"]) is int and row["mode"] in (0o644, 0o755),
               "Logical file mode or record fields differ")
        stripped.append({key: row[key] for key in ("path", "size", "sha256")})
    selected = D.records(stripped)
    D.need([row["path"] for row in value] == sorted(selected), "Record order differs")
    return selected


def current_controls(source):
    raw = D.read(source / CONTROLS / "runtime-bindings.json", 1 << 20)
    policy = D.decode(raw, 1 << 20)
    D.need(type(policy) is dict and set(policy) == {
        "schema", "qualification", "target", "bootstrapRoster", "manifestSha256",
        "protocolSha256", "coreSha256", "source", "runtime", "supplier"},
        "Alpha runtime binding fields differ")
    D.need(policy["schema"] == "mrk-desktop-ubuntu-alpha-runtime-bindings-v1"
           and policy["qualification"] == "prepared-not-native-verified"
           and policy["target"] == TARGET and policy["bootstrapRoster"] == "current",
           "Alpha runtime binding profile differs")
    for key in ("manifestSha256", "protocolSha256", "coreSha256"):
        D.sha(policy[key])
    inputs = policy["source"]
    D.need(type(inputs) is dict and set(inputs) == {
        "files", "inventorySha256", "corePrefix", "coreFileCount", "protocolPath",
        "preparerPath", "bootstrapPaths", "githubCa"},
        "Current source projection fields differ")
    source_rows = records_with_modes(inputs["files"])
    D.need(len(source_rows) == 162 and inputs["corePrefix"] == "src/mobile_release/"
           and type(inputs["coreFileCount"]) is int and inputs["coreFileCount"] == 148
           and inputs["protocolPath"] == "src/mobile_release/_desktop_engine.py"
           and inputs["preparerPath"] == "desktop/tools/prepare_runtime.py"
           and inputs["bootstrapPaths"] == ["desktop/" + name for name in P.CURRENT_BOOTSTRAPS]
           and inputs["githubCa"] == {"sourcePath": "desktop/cpython-source-inputs/github-ca.pem",
                                     "stagedPath": "desktop/github-ca.pem"}
           and all(row["mode"] == 0o644 for row in inputs["files"])
           and sha(P.canonical(inputs["files"])) == D.sha(inputs["inventorySha256"]),
           "Current core/preparer/bootstrap/CA projection differs")
    core_paths = {name for name in source_rows if name.startswith(inputs["corePrefix"])}
    D.need(len(core_paths) == inputs["coreFileCount"]
           and set(source_rows) == core_paths | set(inputs["bootstrapPaths"])
                | {inputs["preparerPath"], inputs["githubCa"]["sourcePath"]}
           and source_rows[inputs["protocolPath"]]["sha256"] == policy["protocolSha256"],
           "Current source projection membership differs")
    for name, row in source_rows.items():
        D.bound(source / name, row)
    actual_core = {path.relative_to(source).as_posix()
                   for path in P.files(source / "src/mobile_release")}
    D.need(actual_core == core_paths, "Current core has an extra or missing member")
    runtime = policy["runtime"]
    D.need(type(runtime) is dict and set(runtime) == {
        "inventoryPath", "inventorySha256", "fileCount", "manifestFileCount"}
        and runtime["inventoryPath"] == (CONTROLS / "runtime-inventory.json").as_posix()
        and type(runtime["fileCount"]) is int and runtime["fileCount"] == 613
        and type(runtime["manifestFileCount"]) is int and runtime["manifestFileCount"] == 612,
        "Current runtime inventory profile differs")
    inventory_raw = D.read(source / runtime["inventoryPath"], 1 << 20)
    D.need(sha(inventory_raw) == D.sha(runtime["inventorySha256"]), "Current runtime inventory pin differs")
    inventory = D.decode(inventory_raw, 1 << 20)
    runtime_rows = records_with_modes(inventory)
    D.need(len(runtime_rows) == 613 and runtime_rows["manifest.json"]["sha256"] == policy["manifestSha256"]
           and runtime_rows["core.zip"]["sha256"] == policy["coreSha256"]
           and all(row["mode"] == (0o755 if row["path"] == "python/bin/python3" else 0o644)
                   for row in inventory), "Current runtime logical roster differs")
    supplier = policy["supplier"]
    D.need(type(supplier) is dict and set(supplier) == {"mapPath", "mapSha256", "fileCount", "bytes"}
           and supplier == {"mapPath": (CONTROLS / "supplier-map.json").as_posix(),
                            "mapSha256": MAP_SHA, "fileCount": 598, "bytes": 27303244},
           "Canonical Python supplier binding differs")
    map_raw = D.read(source / supplier["mapPath"], 256 << 10)
    D.need(sha(map_raw) == MAP_SHA, "Canonical 598 supplier map differs")
    mapping = D.decode(map_raw, 256 << 10)
    D.need(type(mapping) is list and len(mapping) == 598 and P.canonical(mapping) == map_raw,
           "Canonical supplier map encoding differs")
    supplier_names = []
    for row in mapping:
        D.need(type(row) is dict and set(row) == {"archivePath", "destination", "size", "sha256", "mode"}
               and row["archivePath"] == "runtime/" + row["destination"]
               and row["destination"].startswith("python/")
               and type(row["mode"]) is int and row["mode"] in (0o644, 0o755),
               "Canonical supplier map row differs")
        name = D.relative(row["destination"])
        D.need(name in runtime_rows and D.same(runtime_rows[name], {
            "path": name, "size": row["size"], "sha256": row["sha256"]}),
            "Current runtime differs from its exact supplier map")
        supplier_names.append(name)
    D.need(supplier_names == sorted(set(supplier_names))
           and sum(row["size"] for row in mapping) == 27303244
           and set(runtime_rows) == set(supplier_names) | {"core.zip", "github-ca.pem", "manifest.json"}
               | set(P.CURRENT_BOOTSTRAPS), "Exact current 613 membership differs")
    return policy, runtime_rows, mapping


def copy_one(source, destination, record, mode=0o444):
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    pin = {key: record[key] for key in ("size", "sha256")}
    pin["path"] = source.name
    D.copy(source, destination, pin, mode)
    D.bound(destination, pin)


def reconstruct_runtime(source, work):
    """Exact A47/611 admission stays unchanged; current613 is a separate output."""
    policy, current, mapping = current_controls(source)
    stager, artifact, original, old_runtime, _, _, _, _ = U.package_inputs(source, work, fixtures=False)
    stager.kit_records(artifact, original)
    subset, runtime = work / "current-source", work / "current-runtime"
    subset.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)
    for row in policy["source"]["files"]:
        copy_one(source / row["path"], subset / row["path"], row)
    ca = policy["source"]["githubCa"]
    ca_row = next(row for row in policy["source"]["files"] if row["path"] == ca["sourcePath"])
    copy_one(source / ca["sourcePath"], subset / ca["stagedPath"], ca_row)
    for row in mapping:
        record = {"path": row["destination"], "size": row["size"], "sha256": row["sha256"]}
        copy_one(old_runtime / row["destination"], runtime / row["destination"], record, row["mode"])
    prepared = P.prepare_current(subset, runtime, TARGET)
    D.need(prepared == {"manifestSha256": policy["manifestSha256"],
                       "protocolSha256": policy["protocolSha256"],
                       "qualification": "prepared-not-native-verified"},
           "Same-job preparation did not reproduce the authentic current anchors")
    actual = S.runtime_records(runtime, policy["manifestSha256"], policy["protocolSha256"])
    D.need(D.same(actual, current), "Same-job current 613 runtime inventory differs")
    for name, row in actual.items():
        D.bound(runtime / name, row)
    current_controls(source)  # Original source/control postcondition.
    return policy, runtime


def compiler_artifact(raw, role, source, target):
    """One actual non-test binary role, not a path guessed after another build."""
    D.need(role in ROLES and type(raw) is bytes and 0 < len(raw) <= 8 << 20,
           "Compiler role/capture bound differs")
    binary, relative, features = ROLES[role]
    selected, finished, units = None, False, []
    for line in raw.splitlines():
        D.need(not finished, "Compiler bytes follow its terminal record")
        row = C.bounded_json(line, 2 << 20)
        D.need(type(row) is dict and row.get("reason") in {
            "compiler-artifact", "build-script-executed", "compiler-message", "build-finished"},
            "Unknown original compiler record")
        if row["reason"] == "build-finished":
            D.need(row.get("success") is True, "Original compilation failed")
            finished = True
        elif row["reason"] == "compiler-artifact":
            D.need(type(row.get("package_id")) is str and type(row.get("features")) is list
                   and type(row.get("fresh")) is bool and type(row.get("target")) is dict
                   and type(row.get("profile")) is dict, "Compiler unit fields differ")
            units.append({key: row[key] for key in ("package_id", "features", "fresh", "target", "profile")})
            D.need(len(units) <= 2048, "Compiler unit count exceeds its bound")
            if row.get("executable") is None:
                continue
            D.need(selected is None and row["target"].get("kind") == ["bin"]
                   and row["target"].get("name") == binary
                   and row["target"].get("src_path") == str(source / "desktop/src-tauri" / relative)
                   and row.get("manifest_path") == str(source / "desktop/src-tauri/Cargo.toml")
                   and row["features"] == features and row["fresh"] is False
                   and row["profile"].get("test") is False
                   and row["profile"].get("opt_level") == "0"
                   and row["profile"].get("debug_assertions") is True,
                   "Compiler output is not the selected ordinary alpha binary")
            expected = target / TARGET / "debug" / binary
            D.need(row["executable"] == str(expected) and type(row.get("filenames")) is list
                   and str(expected) in row["filenames"], "Compiler output path/roster differs")
            selected = {"role": role, "path": str(expected), "packageId": row["package_id"],
                        "features": features, "profile": row["profile"], "target": row["target"]}
    D.need(finished and selected is not None, "Compiler produced no fresh selected ordinary binary")
    return selected, units


def retain_binary(selection, destination):
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    original = U.artifact_record(Path(selection["path"]), copy_to=destination)
    retained = U.artifact_record(destination)
    D.need(original["identity"][:2] != retained["identity"][:2]
           and all(original[key] == retained[key] for key in ("size", "sha256")),
           "Retained compiler artifact aliases or differs")
    return {"selection": selection, "original": original, "retained": retained}


def verify_retained_binary(record):
    D.need(D.same(U.artifact_record(Path(record["original"]["path"])), record["original"])
           and D.same(U.artifact_record(Path(record["retained"]["path"])), record["retained"]),
           "An original or retained compiler binary changed")


def _notice_name(name):
    return any(re.match(r"(?i)^(?:licen[cs]es?|copyright|copying|notices?)(?:[._-]|$)", part)
               for part in Path(name).parts)


def _notice_output(root, component, members):
    D.need(members and len(members) <= 256 and len({name for name, _ in members}) == len(members),
           "A required component has no bounded unique original notices")
    result = []
    for index, (original_name, raw) in enumerate(sorted(members)):
        D.need(type(raw) is bytes and 0 < len(raw) <= 2 << 20, "Original notice byte bound")
        relative = component + "/notice-" + str(index).zfill(3) + ".txt"
        destination = root / D.relative(relative)
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        record = D.write(destination, raw, 0o444)
        result.append({"originalMember": original_name, "path": relative,
                       "size": record["size"], "sha256": record["sha256"]})
    return result


def _tree_notices(root):
    found, entries = [], 0
    for parent, directories, names in os.walk(root, followlinks=False):
        directories[:] = sorted(name for name in directories if name != "node_modules")
        for name in [*directories, *names]:
            path = Path(parent) / name
            mode = path.lstat().st_mode
            D.need(stat.S_ISDIR(mode) or stat.S_ISREG(mode), "Notice source tree contains a special/link entry")
            entries += 1
            D.need(entries <= 50000, "Notice source tree exceeds its bound")
        for name in sorted(names):
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            if _notice_name(relative):
                found.append((relative, D.read(path, 2 << 20)))
    return found


def collect_notices(source, work, metadata):
    """Conservative originals, with closed-config generated-JS attribution.

    No linked-object census is inferred from Cargo's package list. All selected
    registry originals are included. Npm build-only inputs are recorded too;
    the four bundled packages and Vite/Rollup/esbuild generators MUST have
    actual notices. No build tool executable is put in the package.
    """
    notices = work / "desktop-notices"
    notices.mkdir(mode=0o700)
    retained = source / "desktop/packaging/debian/native-notices"
    baseline_raw = D.read(retained / "inputs.json", 1 << 20)
    D.need(sha(baseline_raw) == U.NOTICE_INPUTS_SHA256, "Reviewed standard/local notice source differs")
    baseline = D.decode(baseline_raw, 1 << 20)
    baseline_rows = D.records(baseline["files"])
    C.conventional_files(D, retained, sorted([*baseline_rows.values(), D.file_record(retained / "inputs.json")],
                                             key=lambda row: row["path"]))
    for name, row in baseline_rows.items():
        copy_one(retained / name, notices / "retained" / name, row)
    copy_one(retained / "inputs.json", notices / "retained/inputs.json",
             D.file_record(retained / "inputs.json"))
    U.native_source_notice_inputs(source, baseline, baseline_rows)
    lock = tomllib.loads(D.read(source / "desktop/src-tauri/Cargo.lock", 256 << 10).decode("utf-8"))
    locked = {(row["name"], row["version"]): row for row in lock["package"] if "source" in row}
    packages = {}
    for graph in metadata.values():
        for row in graph["packages"]:
            key = row["name"], row["version"], row["source"]
            identity_fields = ("id", "name", "version", "source", "manifest_path", "license", "license_file")
            D.need(key not in packages or all(packages[key].get(field) == row.get(field)
                                             for field in identity_fields), "Conflicting Cargo source metadata")
            packages[key] = row
    components = []
    for index, (key, package) in enumerate(sorted(packages.items(), key=lambda item: str(item[0]))):
        name, version, origin = key
        if origin is None:
            path = Path(package["manifest_path"]).parent
            D.need(path.is_relative_to(source), "Local Cargo notice source escapes the admitted source")
            if path.relative_to(source).as_posix() in {
                "desktop/src-tauri", "desktop/native/linux-mount-observation",
                "desktop/native/macos-installed-native", "desktop/native/windows-installed-native",
            }:
                D.need(package.get("license") == "MIT", "First-party Cargo license binding differs")
                members = [("repository/LICENSE", D.read(source / "LICENSE", 2 << 20))]
            else:
                members = _tree_notices(path)
            archive_sha = None
        else:
            D.need(origin == "registry+https://github.com/rust-lang/crates.io-index"
                   and (name, version) in locked and locked[(name, version)]["source"] == origin,
                   "Cargo notice source is not the locked registry")
            archives = list((work / "cargo/registry/cache").glob("*/" + name + "-" + version + ".crate"))
            D.need(len(archives) == 1, "Missing or ambiguous original crate archive for " + name)
            raw = D.read(archives[0], 32 << 20)
            archive_sha = sha(raw)
            D.need(archive_sha == D.sha(locked[(name, version)]["checksum"]), "Original crate checksum differs")
            members = []
            prefix = name + "-" + version + "/"
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
                count = 0
                for member in archive:
                    count += 1
                    D.need(count <= 50000, "Crate member count bound")
                    if member.isdir() and member.name.rstrip("/") == prefix.rstrip("/"):
                        continue
                    D.need(member.name.startswith(prefix), "Crate member roster differs")
                    relative = member.name.removeprefix(prefix)
                    D.need(relative and ".." not in Path(relative).parts and not Path(relative).is_absolute(),
                           "Crate member name differs")
                    if _notice_name(relative) and member.isfile():
                        D.need(0 < member.size <= 2 << 20, "Original crate notice bound")
                        stream = archive.extractfile(member)
                        D.need(stream is not None, "Original crate notice is unavailable")
                        with stream:
                            body = stream.read((2 << 20) + 1)
                        D.need(len(body) == member.size, "Original crate notice size differs")
                        members.append((relative, body))
                    elif _notice_name(relative) and not member.isdir():
                        raise ValueError("Crate notice is not an ordinary original member")
        rows = _notice_output(notices, "cargo/component-" + str(index).zfill(3), members)
        components.append({"kind": "cargo-source", "name": name, "version": version,
                           "source": origin or "admitted-local-source", "archiveSha256": archive_sha,
                           "licenseMetadata": package.get("license"), "notices": rows})
    D.need(sha(D.read(source / "desktop/vite.config.mjs", 64 << 10)) == VITE_SHA
           and sha(D.read(source / "desktop/package-lock.json", 256 << 10)) == NPM_LOCK_SHA,
           "Closed frontend generator configuration/lock differs")
    npm = D.decode(D.read(source / "desktop/package-lock.json", 256 << 10), 256 << 10)
    found = {}
    npm_component = 0
    for relative, locked_package in sorted(npm["packages"].items()):
        if not relative:
            continue
        path = source / "desktop" / relative
        D.need(relative.startswith("node_modules/") and ".." not in Path(relative).parts,
               "Npm lock package path differs")
        D.need(not path.is_symlink(), "Npm package root is a link")
        if not path.exists():
            D.need(locked_package.get("optional") is True, "Required locked npm package is missing")
            continue
        D.need(path.is_dir() and not path.is_symlink(), "Npm package root is not ordinary")
        package = D.decode(D.read(path / "package.json", 512 << 10), 512 << 10)
        name, version = package["name"], package["version"]
        D.need(version == locked_package["version"], "Npm package version differs")
        if name in NPM_REQUIRED or name in NPM_GENERATORS:
            D.need(relative == "node_modules/" + name and name not in found,
                   "Bundled/generator npm role has an ambiguous source")
        if name in NPM_REQUIRED:
            D.need(version == NPM_REQUIRED[name], "Bundled npm package version differs")
        members = _tree_notices(path)
        required = name in NPM_REQUIRED or name in NPM_GENERATORS
        D.need(members or not required, "Missing bundled/generated-code original notice for " + name)
        rows = (_notice_output(notices, "npm/component-" + str(npm_component).zfill(3), members)
                if members else [])
        npm_component += 1
        found[name] = version
        components.append({"kind": "npm-source", "name": name, "version": version,
                           "integrity": locked_package.get("integrity"),
                           "licenseMetadata": package.get("license"),
                           "role": ("bundled-runtime" if name in NPM_REQUIRED else
                                    "embedded-code-generator" if name in NPM_GENERATORS else "build-input-only"),
                           "notices": rows})
    D.need(set(NPM_REQUIRED) | NPM_GENERATORS <= set(found), "Frontend runtime/generator notice closure is incomplete")
    manifest = {"schema": "mrk-ubuntu-alpha-notices-v1", "scope": "conservative-original-source-notices",
                "viteConfigSha256": VITE_SHA, "npmLockSha256": NPM_LOCK_SHA,
                "components": components}
    D.write(notices / "COMPONENTS.json", D.canonical(manifest), 0o444)
    rows = [{**D.file_record(path, 2 << 20), "path": path.relative_to(notices).as_posix()}
            for path in P.files(notices)]
    D.need(sum(row["size"] for row in rows) <= 64 << 20, "Desktop notice byte bound")
    return notices, sorted(rows, key=lambda row: row["path"])


def stage_package(source, work, destination, compiler, runtime, policy, notices, notice_rows, depends, command):
    """Exactly one real alpha package; no fixture/F1 substitution or install."""
    artifact = work / "admitted-a"
    generated = work / "generated"
    D.need(generated.lstat().st_uid == os.geteuid() and stat.S_IMODE(generated.lstat().st_mode) == 0o700,
           "Package output parent must remain private to its unprivileged owner")
    original = C.conventional_files(D, artifact, C.CONVENTIONAL_SMOKE_INPUTS["preparedArtifact"]["files"])
    kit = S.kit_records(artifact, original)
    runtime_rows = S.runtime_records(runtime, policy["manifestSha256"], policy["protocolSha256"])
    expected = D.records([{"path": ROLES[role][0], "size": compiler[role]["size"],
                          "sha256": compiler[role]["sha256"]} for role in sorted(ROLES)])
    D.need(set(expected) == set(S.BINARIES), "Both real compiler roles are required")
    compiler_pin = D.write(generated / "compiler-files.json", D.canonical(list(expected.values())))
    prepared_pin = D.write(generated / "prepared-files.json", D.canonical(list(original.values())))
    notice_pin = D.write(generated / "notice-files.json", D.canonical(notice_rows))
    stage = generated / "package-stage"
    version = "0.1.0~alpha." + policy["manifestSha256"][:12]
    values = {
        "compiled": work / "compiled", "compiler-files": generated / "compiler-files.json",
        "compiler-files-sha256": compiler_pin["sha256"], "runtime": runtime,
        "manifest-sha256": policy["manifestSha256"], "protocol-sha256": policy["protocolSha256"],
        "prepared-artifact": artifact, "prepared-files": generated / "prepared-files.json",
        "prepared-files-sha256": prepared_pin["sha256"], "desktop-notices": notices,
        "desktop-notice-files": generated / "notice-files.json", "desktop-notice-files-sha256": notice_pin["sha256"],
        "output": stage, "version": version, "depends": depends,
    }
    argv = ["/usr/bin/python3.12", "-I", "-S", "-B", str(source / "desktop/tools/stage_ubuntu_deb.py")]
    for name, value in values.items():
        argv += ["--" + name, str(value)]
    result = command("stage-real-alpha", argv, timeout=180)
    observed = D.decode(result.stdout, 16384)
    D.need(observed.get("installed") is False and observed.get("qualified") is False
           and observed.get("runtimeManifestSha256") == policy["manifestSha256"],
           "Original unprivileged stager result differs")
    D.need(stage.lstat().st_uid == os.getuid() and stat.S_IMODE(stage.lstat().st_mode) == 0o700,
           "Original package stage changed")
    os.chmod(stage, 0o755)
    package = destination / ("mobile-release-kit-desktop_" + version + "_amd64.deb")
    command("assemble-real-alpha", ["/usr/bin/dpkg-deb", "--root-owner-group", "--uniform-compression", "-Znone",
                                   "--build", str(stage), str(package)], timeout=180)
    expected_data, expected_control = U.package_rows(S, expected, runtime_rows, kit,
        D.records(notice_rows), policy["manifestSha256"], version, depends)
    readback = U.deb_readback(package, expected_data, expected_control)
    return {"package": {key: readback[key] for key in ("path", "size", "sha256")},
            "version": version, "members": {"data": expected_data, "control": expected_control},
            "qualified": False, "installed": False, "publicRelease": False}


def metadata_graph(raw, role, source, target):
    """One closed original Cargo graph per independent feature invocation."""
    if role == "main":
        return U.shell_cargo_metadata(raw, source, target)
    D.need(role == "publisher", "Unknown metadata role")
    value = C.bounded_json(raw, 8 << 20, max_nodes=200000)
    packages, resolve = value.get("packages"), value.get("resolve")
    D.need(type(packages) is list and 1 <= len(packages) <= 512 and type(resolve) is dict
           and value.get("workspace_root") == str(source / "desktop/src-tauri")
           and value.get("target_directory") == str(target), "Publisher Cargo metadata root/count differs")
    by_id = {row["id"]: row for row in packages}
    nodes = {row["id"]: row for row in resolve["nodes"]}
    D.need(len(by_id) == len(packages) and len(nodes) == len(resolve["nodes"])
           and set(nodes) <= set(by_id), "Publisher Cargo IDs duplicate or are missing")
    selected = [row for row in packages
                if row.get("manifest_path") == str(source / "desktop/src-tauri/Cargo.toml")]
    D.need(len(selected) == 1 and selected[0]["name"] == "mobile-release-kit-desktop"
           and selected[0]["version"] == "0.1.0" and resolve.get("root") == selected[0]["id"]
           and nodes[selected[0]["id"]]["features"] == ROLES[role][2], "Publisher root feature graph differs")
    U.linux_local_cargo_sources(packages, nodes, selected[0], source)
    lock = tomllib.loads(D.read(source / "desktop/src-tauri/Cargo.lock", 256 << 10).decode("utf-8"))
    locked = {(row["name"], row["version"]): row for row in lock["package"]}
    for row in packages:
        D.need((row["name"], row["version"]) in locked, "Publisher package absent from original lock")
        if row.get("source") is not None:
            D.need(row["source"] == "registry+https://github.com/rust-lang/crates.io-index"
                   and locked[row["name"], row["version"]].get("source") == row["source"],
                   "Publisher source origin differs")
    for row in nodes.values():
        D.need(type(row.get("features")) is list and all(type(name) is str for name in row["features"])
               and type(row.get("deps")) is list and all(dep.get("pkg") in nodes for dep in row["deps"]),
               "Publisher resolved Cargo edge/features differ")
    return value, by_id, nodes


def static_edges(initial, provider):
    """Resolve original ELF DATA including all requested symbol-version labels.

    The adapter owns path/byte admission. The key includes its private/system
    domain: a shipped OpenSSL library must never stand in for an OS provider
    of the GUI, nor may a system provider replace a shipped Python dependency.
    """
    objects, pending, edges = {}, list(initial.items()), []
    while pending:
        key, row = pending.pop()
        if key in objects:
            D.need(D.same(objects[key], row), "ELF provider changed or became ambiguous")
            continue
        D.need(len(objects) < 512, "Static ELF object bound")
        objects[key] = row
        elf = row["elf"]
        D.need(type(elf["needed"]) is list and len(elf["needed"]) == len(set(elf["needed"]))
               and set(elf["versionNeeds"]) <= set(elf["needed"]), "ELF required provider roster differs")
        for soname in elf["needed"]:
            provider_key, selected = provider(row, soname)
            D.need(selected["elf"]["soname"] == soname, "Provider SONAME differs")
            required = set(elf["versionNeeds"].get(soname, []))
            D.need(required <= set(selected["elf"]["versionDefinitions"]),
                   "Provider does not export every required symbol version: " + soname)
            edges.append({"from": key, "needed": soname, "to": provider_key, "versions": sorted(required)})
            pending.append((provider_key, selected))
    return {"objects": objects, "edges": sorted(edges, key=lambda row: (row["from"], row["needed"], row["to"]))}


def os_package_inputs(command):
    """One actual distro query context shared by pre/post compile admission."""
    host_files, package_files, packages = {}, {}, {}
    serial = 0

    def run(label, argv, **kwargs):
        nonlocal serial
        serial += 1
        return command(label + "-" + str(serial), argv, timeout=15, **kwargs)

    def host(path, limit=MAX_BINARY):
        selected = str(path)
        row = U.protected_host_file(Path(selected), limit)
        D.need(selected not in host_files or D.same(host_files[selected], row), "Original OS input changed")
        host_files[selected] = row
        D.need(len(host_files) <= 1024
               and sum({item["path"]: item["size"] for item in host_files.values()}.values()) <= 3 << 30,
               "Actual OS input file/byte bound")
        return row

    def package(name):
        if name in packages:
            return
        D.need(len(packages) < 256 and re.fullmatch(r"[a-z0-9][a-z0-9+.-]+(?::amd64)?", name),
               "Actual dependency package name/count differs")
        fields = "\t".join("$" + "{" + key + "}" for key in (
            "binary:Package", "db:Status-Status", "Version", "Architecture", "source:Package", "source:Version")) + "\n"
        result = run("package-query", ["/usr/bin/dpkg-query", "-W", "-f=" + fields, name], limit=64 << 10)
        values = result.stdout.decode("ascii").rstrip("\n").split("\t")
        D.need(result.stderr == b"" and result.stdout.count(b"\n") == 1 and len(values) == 6
               and values[0].split(":")[0] == name.split(":")[0] and values[1] == "installed"
               and values[3] in {"amd64", "all"} and re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", values[4])
               and all(re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", values[index]) for index in (2, 5)),
               "Actual dependency package tuple differs")
        listing = run("package-members", ["/usr/bin/dpkg-query", "-L", name], limit=1 << 20)
        package_files[name] = U.shell_package_members(listing.stdout, listing.stderr)
        packages[name] = {"binaryPackage": values[0], "version": values[2], "architecture": values[3],
                          "sourcePackage": values[4], "sourceVersion": values[5],
                          "querySha256": sha(result.stdout), "membersSha256": sha(listing.stdout)}

    def owner(row):
        def query(aliases):
            result = run("package-owner", ["/usr/bin/dpkg-query", "-S", *aliases], codes=(0, 1), limit=64 << 10)
            return result.stdout, result.stderr
        return U.shell_package_owner(row, package_files, query, package)

    return {"files": host_files, "packages": packages, "packageFiles": package_files,
            "run": run, "host": host, "owner": owner}


def support_inputs(command):
    context = os_package_inputs(command)
    run, host, owner = context["run"], context["host"], context["owner"]
    support = {}
    for name in ("Scrt1.o", "crti.o", "crtn.o", "crtbeginS.o", "crtendS.o", "libgcc.a", "libgcc_eh.a",
                 "libgcc_s.so", "libc.so", "libc_nonshared.a", "libutil.a", "librt.a", "libpthread.a", "libm.so", "libdl.a"):
        selected = run("gcc-support", ["/usr/bin/cc", "-print-file-name=" + name], limit=4096)
        D.need(selected.stderr == b"" and selected.stdout.count(b"\n") == 1, "GNU support query differs")
        path = selected.stdout.decode("ascii").rstrip("\n")
        D.need(path.startswith("/") and len(path) <= 4096, "GNU support is unresolved")
        file = host(os.path.abspath(path))
        support[name] = {"file": U.shell_file_projection(file), "package": owner(file)}
    for path in ("/usr/bin/cc", "/usr/bin/pkg-config", "/usr/bin/ld"):
        owner(host(path))
    return {"context": context, "support": support, "packages": context["packages"],
            "bindings": {"files": context["files"]}}


def support_unchanged(support):
    for path, expected in support["bindings"]["files"].items():
        D.need(D.same(U.protected_host_file(Path(path)), expected), "Original compiler support input changed")


def dependency_inputs(source, work, compiler, runtime, policy, command, *, support):
    """Actual Ubuntu 24.04 package metadata, never ldd or payload execution."""
    D.need(set(compiler) == set(ROLES), "Static dependency coverage requires both real compiler roles")
    lifecycle = U.local("ubuntu_publication_lifecycle")
    context = support["context"]
    host_files, packages, package_files = context["files"], context["packages"], context["packageFiles"]
    run, host, owner = context["run"], context["host"], context["owner"]
    host_bindings, native_records = {}, {}
    def native(path, kind="provider"):
        key = str(path)
        if key in native_records:
            return native_records[key]
        file = host(path)
        raw = D.read(Path(file["path"]), MAX_BINARY)
        D.need(sha(raw) == file["sha256"], "OS ELF bytes changed after binding")
        elf = U.elf_dependencies(raw, shell=True, shell_path=key, shell_provider=kind == "provider")
        row = {"domain": "os", "file": U.shell_file_projection(file), "elf": elf, "package": owner(file)}
        native_records[key] = row
        return row

    original_runtime = S.runtime_records(runtime, policy["manifestSha256"], policy["protocolSha256"])
    elf_names = []
    for name, expected in original_runtime.items():
        stream, before = D._open(runtime / name, expected["size"])
        with stream:
            header = stream.read(4)
            D.need(D.state(os.fstat(stream.fileno())) == D.state(before), "Runtime header read changed")
        D.bound(runtime / name, expected)
        if header == b"\x7fELF":
            elf_names.append(name)
    D.need(set(elf_names) == set(U.RUNTIME_ELF), "Every shipped runtime ELF must be explicitly covered")
    initial, private = {}, {}
    for name in sorted(U.RUNTIME_ELF):
        raw = D.read(runtime / name, MAX_BINARY)
        elf = U.elf_dependencies(raw, runtime_path=name)
        row = {"domain": "private-runtime", "file": {**original_runtime[name], "selectedPath": str(runtime / name)},
               "elf": elf, "package": "mobile-release-kit-desktop"}
        initial["private:" + name] = row
        if elf["soname"] is not None:
            private[elf["soname"]] = ("private:" + name, row)
    for role, path in compiler.items():
        raw = D.read(path, MAX_BINARY)
        elf = U.elf_dependencies(raw, shell=True)
        D.need(elf["interpreter"] == "/lib64/ld-linux-x86-64.so.2" and elf["soname"] is None,
               "Real main/publisher ELF executable kind differs")
        initial[role] = {"domain": "shipped", "file": {**D.file_record(path, MAX_BINARY), "selectedPath": str(path)},
                         "elf": elf, "package": "mobile-release-kit-desktop"}
    root_roster, root_bindings, modules = U.shell_module_inventory()
    selections = {}
    for cache in lifecycle.SHELL_MODULE_CACHES:
        binding = U.shell_host_binding(Path(cache), absent=True)
        host_bindings[cache] = binding
        if binding.get("absent"):
            selections[cache] = []
            continue
        raw = D.read(Path(binding["path"]), 1 << 20)
        D.need(len(raw) == binding["size"] and sha(raw) == binding["sha256"], "Module cache changed")
        selections[cache] = lifecycle.shell_module_cache(cache, raw)
        D.need(set(selections[cache]) <= set(modules), "Runtime module cache selects an unknown provider")
    egl = {}
    for name in ("/usr/share/glvnd/egl_vendor.d", "/etc/glvnd/egl_vendor.d"):
        path = Path(name)
        binding = U.shell_host_binding(path, directory_only=True, absent=True)
        children = [] if binding.get("absent") else sorted(child.name for child in path.iterdir())
        D.need(len(children) <= 32 and all(re.fullmatch(r"[A-Za-z0-9_.+-]+\.json", child) for child in children),
               "EGL vendor selector directory differs")
        host_bindings[name] = {"binding": binding, "children": children}
        for child in children:
            file = host(path / child, 64 << 10)
            value = D.decode(D.read(Path(file["path"]), 64 << 10), 64 << 10)
            D.need(type(value) is dict and set(value) == {"file_format_version", "ICD"}
                   and value["file_format_version"] == "1.0.0" and type(value["ICD"]) is dict
                   and set(value["ICD"]) == {"library_path"}, "EGL selector format differs")
            library = value["ICD"]["library_path"]
            D.need(type(library) is str and re.fullmatch(
                r"(?:/usr/lib/x86_64-linux-gnu/)?libEGL_[A-Za-z0-9_.+-]+\.so(?:\.[0-9]+)*", library),
                "EGL selector provider differs")
            egl[str(path / child)] = str(Path(U.SHELL_LIBRARY_ROOT) / library)
    programs = [*U.SHELL_WEBKIT_PROGRAMS, U.SHELL_LIBRARY_ROOT + "/gstreamer1.0/gstreamer-1.0/gst-plugin-scanner"]
    for path in programs:
        row = native(path, "program")
        D.need(row["elf"]["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
               and row["elf"]["soname"] is None, "Actual WebKit/runtime program ELF kind differs")
        initial["os:" + path] = row
    for path in modules:
        row = native(path, "module")
        D.need(row["elf"]["interpreter"] is None, "Runtime module has an unexpected interpreter")
        initial["os:" + path] = row
    for path in sorted(set(egl.values()) | {U.SHELL_LIBRARY_ROOT + "/libGLX_mesa.so.0",
                                         U.SHELL_LIBRARY_ROOT + "/libgbm.so.1",
                                         U.SHELL_LIBRARY_ROOT + "/ld-linux-x86-64.so.2"}):
        initial["os:" + path] = native(path)

    def provider(requester, soname):
        if requester["domain"] == "private-runtime" and soname in private:
            return private[soname]
        path = U.shell_provider_path(requester["file"]["selectedPath"], requester["elf"].get("runpath")
                                    if requester["domain"] == "os" else None, soname)
        return "os:" + path, native(path)

    graph = static_edges(initial, provider)
    libraries = {row["elf"]["soname"]: row for row in graph["objects"].values()
                 if row["domain"] == "os" and row["elf"]["soname"] is not None}
    D.need(len(libraries) == len({row["file"]["selectedPath"] for row in graph["objects"].values()
                                if row["domain"] == "os" and row["elf"]["soname"] is not None}),
           "OS provider SONAME is ambiguous")
    loader = host("/lib64/ld-linux-x86-64.so.2")
    D.need(loader["path"] == libraries["ld-linux-x86-64.so.2"]["file"]["path"],
           "Every shipped PT_INTERP must resolve to the actual OS loader")
    search = U.shell_private_search([row for row in graph["objects"].values() if row["domain"] == "os"], libraries)
    for row in search:
        binding = U.shell_host_binding(Path(row["path"]), absent=True)
        D.need((not binding.get("absent") and U.shell_file_projection(binding) == libraries[row["name"]]["file"])
               if row["selected"] else binding.get("absent") is True,
               "Requester-private loader search has an unknown alternative")
        host_bindings[row["path"]] = binding

    support_unchanged(support)

    # dpkg-shlibdeps supplies actual distro symbols/shlibs relations, not guessed
    # ABI versions. The only excluded dependency is proven shipped OpenSSL self.
    dependencies = []
    for role, paths in (("gui-publisher", [compiler["main"], compiler["publisher"]]),
                        ("private-runtime", [runtime / name for name in sorted(U.RUNTIME_ELF)])):
        query_root = work / ("shlibdeps-" + role)
        debian = query_root / "debian"
        debian.mkdir(mode=0o700, parents=True)
        D.write(debian / "control", b"Source: mobile-release-kit-desktop\nSection: devel\nPriority: optional\nMaintainer: Mobile Release Kit contributors <noreply@github.com>\nStandards-Version: 4.7.0\n\nPackage: mobile-release-kit-desktop\nArchitecture: amd64\nDescription: nonproduction Ubuntu alpha\n")
        argv = ["/usr/bin/dpkg-shlibdeps", "-O"]
        if role == "private-runtime":
            D.write(debian / "shlibs.local", b"libssl 3 mobile-release-kit-desktop\nlibcrypto 3 mobile-release-kit-desktop\n")
            argv += ["-l" + str(runtime / "python/lib"), "-xmobile-release-kit-desktop"]
        argv += ["-e" + str(path) for path in paths]
        result = command("shlibdeps-" + role, argv, cwd=query_root, timeout=90, limit=128 << 10)
        dependencies.extend(shlibdeps_relations(result.stdout, result.stderr))
    # Dynamically selected modules and WebKit children are real package needs.
    # Use the observed build-host version as a conservative minimum, never a
    # guessed earlier ABI floor. Exact build versions remain in the evidence;
    # equality would unnecessarily block superseding Ubuntu security updates.
    # This is not a claim of native testing on this or a later OS package.
    dynamic = {native_records[path]["package"] for path in {*modules, *programs, *egl.values(),
               U.SHELL_LIBRARY_ROOT + "/libGLX_mesa.so.0", U.SHELL_LIBRARY_ROOT + "/libgbm.so.1"}}
    depends = package_dependencies(packages, dynamic, dependencies)
    return {"graph": graph, "depends": depends, "packages": packages, "support": support["support"],
            "moduleRoots": root_roster, "moduleSelections": selections, "eglLibraries": egl,
            "bindings": {"files": host_files, "roots": root_bindings, "selectors": host_bindings},
            "packageFiles": {name: sorted(members) for name, members in package_files.items()}}




def shlibdeps_relations(stdout, stderr):
    # Missing-symbol/provider warnings cannot become an apparently valid
    # package just because dpkg-shlibdeps returned status zero.
    D.need(type(stdout) is bytes and 0 < len(stdout) <= 128 << 10 and stderr == b"",
           "Original dpkg-shlibdeps diagnostics are not clean")
    text = stdout.decode("ascii")
    D.need(text.startswith("shlibs:Depends=") and text.count("\n") == 1 and text.endswith("\n"),
           "dpkg dependency result differs")
    return text.removeprefix("shlibs:Depends=").rstrip("\n").split(", ")


def package_dependencies(packages, dynamic, native):
    """Keep actual distro ABI relations and conservative observed module floors."""
    D.need(type(packages) is dict and 0 < len(packages) <= 256
           and type(dynamic) is set and dynamic <= set(packages)
           and type(native) is list and 0 < len(native) <= 4096
           and all(type(item) is str and item for item in native),
           "Dependency relation inputs or actual package ownership differ")
    relations = list(native)
    relations += [packages[name]["binaryPackage"].split(":")[0] + " (>= " + packages[name]["version"] + ")"
                  for name in sorted(dynamic)]
    D.need(all(item.split(" ", 1)[0] in {row["binaryPackage"].split(":")[0] for row in packages.values()}
               for item in relations), "Dependency relation names an unbound actual package")
    depends = ", ".join(sorted(set(relations)))
    S.controls("0.1.0~alpha", depends, 1)  # Existing package grammar remains authoritative.
    return depends


def native_notices(notices, dependencies, command):
    """Retain genuine current GNU/CRT and provider package originals.

    OS DSOs are not redistributed in the .deb. Current original notices are
    included conservatively; old baseline229 OS notes are historical only.
    """
    records = []
    packages = dependencies["packages"]
    selected = sorted({row["package"] for row in dependencies["support"].values()})
    for index, name in enumerate(selected):
        package = packages[name]
        path = Path("/usr/share/doc") / package["binaryPackage"].split(":")[0] / "copyright"
        bound = U.protected_host_file(path, 2 << 20)
        raw = D.read(Path(bound["path"]), 2 << 20)
        D.need(len(raw) == bound["size"] and sha(raw) == bound["sha256"], "GNU/CRT copyright changed")
        dependencies["bindings"]["files"][str(path)] = bound
        result = command("gnu-copyright-owner-" + str(index),
                         ["/usr/bin/dpkg-query", "-S", bound["path"]], timeout=15, limit=4096)
        ownership = result.stdout.decode("ascii").rstrip("\n")
        supplier, separator, owned = ownership.rpartition(": ")
        D.need(result.stderr == b"" and result.stdout.count(b"\n") == 1 and separator
               and owned == bound["path"] and re.fullmatch(r"[a-z0-9][a-z0-9+.-]+(?::amd64)?", supplier),
               "GNU/CRT original copyright supplier is ambiguous")
        fields = "\t".join("$" + "{" + key + "}" for key in (
            "db:Status-Status", "source:Package", "source:Version")) + "\n"
        result = command("gnu-copyright-package-" + str(index),
                         ["/usr/bin/dpkg-query", "-W", "-f=" + fields, supplier], timeout=15, limit=4096)
        D.need(result.stderr == b"" and result.stdout.decode("ascii") == "installed\t"
               + package["sourcePackage"] + "\t" + package["sourceVersion"] + "\n",
               "GNU/CRT notice does not correspond to its actual linked support source")
        members = [("copyright", raw)]
        references = sorted({match.decode("ascii").rstrip(".") for match in re.findall(U.COMMON_LICENSE_PATTERN, raw)})
        D.need(all(name in U.COMMON_LICENSES for name in references), "GNU/CRT common-license reference differs")
        for reference in references:
            original = Path("/usr/share/common-licenses") / reference
            common = U.protected_host_file(original, 2 << 20)
            dependencies["bindings"]["files"][str(original)] = common
            members.append(("common-licenses/" + reference, D.read(Path(common["path"]), 2 << 20)))
        rows = _notice_output(notices, "current-gnu/component-" + str(index).zfill(3), members)
        records.append({"package": package, "originalPath": str(path), "canonicalPath": bound["path"], "notices": rows})
    D.write(notices / "CURRENT-GNU-INPUTS.json", D.canonical({
        "schema": "mrk-ubuntu-alpha-gnu-notices-v1", "scope": "actual-compiler-support-originals",
        "packages": records, "support": dependencies["support"]}), 0o444)
    rows = [{**D.file_record(path, 2 << 20), "path": path.relative_to(notices).as_posix()}
            for path in P.files(notices)]
    D.need(sum(row["size"] for row in rows) <= 64 << 20, "Complete desktop notice byte bound")
    return sorted(rows, key=lambda row: row["path"])


def dependencies_unchanged(dependencies):
    for path, expected in dependencies["bindings"]["files"].items():
        D.need(D.same(U.protected_host_file(Path(path)), expected), "Original OS supplier input changed")
    root_roster, root_bindings, _ = U.shell_module_inventory()
    D.need(D.same(root_roster, dependencies["moduleRoots"])
           and D.same(root_bindings, dependencies["bindings"]["roots"]), "Original module roots changed")
    for path, expected in dependencies["bindings"]["selectors"].items():
        if "children" in expected:
            current = U.shell_host_binding(Path(path), directory_only=True, absent=True)
            D.need(D.same(current, expected["binding"])
                   and ([] if current.get("absent") else sorted(child.name for child in Path(path).iterdir())) == expected["children"],
                   "Original EGL directory changed")
        else:
            D.need(D.same(U.shell_host_binding(Path(path), absent=True), expected),
                   "Original runtime selector/search changed")


def notice_records(notices):
    rows = [{**D.file_record(path, 2 << 20), "path": path.relative_to(notices).as_posix()}
            for path in P.files(notices)]
    D.need(sum(row["size"] for row in rows) <= 64 << 20, "Complete desktop notice byte bound")
    return sorted(rows, key=lambda row: row["path"])


def bind_notice_outputs(notices, source_sha, policy, compiler, frontend):
    outputs = {"schema": "mrk-ubuntu-alpha-notice-output-binding-v1", "sourceSha": source_sha,
               "manifestSha256": policy["manifestSha256"], "protocolSha256": policy["protocolSha256"],
               "binaries": {role: {key: row["retained"][key] for key in ("size", "sha256")}
                            for role, row in compiler.items()},
               "frontendFiles": frontend["files"], "frontendTreeSha256": frontend["treeSha256"],
               "viteConfigSha256": VITE_SHA, "npmLockSha256": NPM_LOCK_SHA}
    D.write(notices / "BUILD-OUTPUTS.json", D.canonical(outputs), 0o444)
    return notice_records(notices)
