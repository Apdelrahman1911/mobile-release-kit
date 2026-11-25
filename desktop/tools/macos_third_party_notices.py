"""Third-party licence notices for the macOS package (#29).

generate: walks the locked, resolved dependency graph of every Rust workspace
the macOS package compiles (normal dependencies only, for both macOS targets,
all features, so nothing shipped is missed) plus the npm packages bundled into
the frontend, and writes:

  desktop/macos-installed-inputs/notices/THIRD-PARTY-NOTICES.txt
  desktop/macos-installed-inputs/notices/third-party-inputs.json

Every crate's own licence/notice/copyright files are copied verbatim from its
locked source archive; npm tarballs are verified against the lockfile
integrity before their licence files are read. The embedded Python runtime and
the Android tools keep their own notices (python/licenses, android-support).

check (no network, no cargo): the recorded lockfile digests must equal the
current lockfiles and the notices file must equal its recorded digest, so a
dependency change cannot ship with stale notices.
"""
import argparse
import base64
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DESKTOP = ROOT / "desktop"
OUTPUT = DESKTOP / "macos-installed-inputs/notices"
NOTICE_NAME = "THIRD-PARTY-NOTICES.txt"
INPUTS_NAME = "third-party-inputs.json"
NOTICE_LIMIT = 16 * 1024 * 1024
WORKSPACES = ("src-tauri", "native/macos-installed-native", "helpers/macos-android-register",
              "helpers/macos-desktop-image", "helpers/macos-vault-helper", "helpers/macos-github-seal")
TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin")
NPM_PACKAGES = ("@tauri-apps/api", "react", "react-dom", "scheduler", "vite")
LICENSE_FILE = re.compile(r"(?i)^(licen[cs]e|copying|notice|unlicense|copyright|copyrights|authors|patents|third[-_]party)([-_. ].*)?$")


def digest(body):
    return hashlib.sha256(body).hexdigest()


def lockfiles():
    paths = [DESKTOP / workspace / "Cargo.lock" for workspace in WORKSPACES] + [DESKTOP / "package-lock.json"]
    return {str(path.relative_to(ROOT)): path for path in paths}


def license_files(folder):
    rows = []
    for entry in sorted(os.listdir(folder)):
        path = folder / entry
        if path.is_file() and not path.is_symlink() and LICENSE_FILE.match(entry):
            rows.append((entry, path.read_bytes()))
        elif path.is_dir() and not path.is_symlink() and entry.upper() in ("LICENSES", "LICENSE"):
            for inner in sorted(os.listdir(path)):
                if (path / inner).is_file() and not (path / inner).is_symlink():
                    rows.append((entry + "/" + inner, (path / inner).read_bytes()))
    return rows


def crates():
    found = {}
    for workspace in WORKSPACES:
        manifest = DESKTOP / workspace / "Cargo.toml"
        lock = tomllib.loads((DESKTOP / workspace / "Cargo.lock").read_text())
        checksums = {(p["name"], p["version"]): p.get("checksum") for p in lock["package"]}
        for target in TARGETS:
            raw = subprocess.run(["cargo", "metadata", "--locked", "--format-version", "1", "--all-features",
                                  "--filter-platform", target, "--manifest-path", str(manifest)],
                                 check=True, capture_output=True, timeout=600).stdout
            data = json.loads(raw)
            packages = {p["id"]: p for p in data["packages"]}
            nodes = {n["id"]: n for n in data["resolve"]["nodes"]}
            seen, queue = set(), list(data["workspace_members"])
            while queue:
                current = queue.pop()
                if current in seen:
                    continue
                seen.add(current)
                for dep in nodes[current]["deps"]:
                    if any(kind.get("kind") is None for kind in dep["dep_kinds"]):
                        queue.append(dep["pkg"])
            for pid in seen:
                package = packages[pid]
                if not (package.get("source") or "").startswith("registry+"):
                    continue
                key = (package["name"], package["version"])
                if key in found:
                    found[key]["workspaces"].add(workspace)
                    continue
                folder = Path(package["manifest_path"]).parent
                files = license_files(folder)
                if package.get("license_file"):
                    extra = folder / package["license_file"]
                    if extra.is_file() and all(name != package["license_file"] for name, _ in files):
                        files.append((package["license_file"], extra.read_bytes()))
                found[key] = {"kind": "crate", "name": key[0], "version": key[1], "checksum": checksums.get(key),
                              "license": package.get("license") or "", "repository": package.get("repository") or "",
                              "authors": package.get("authors") or [], "files": files, "workspaces": {workspace}}
    return [found[key] for key in sorted(found)]


def npm_packages(cache):
    lock = json.loads((DESKTOP / "package-lock.json").read_text())
    rows = []
    for name in NPM_PACKAGES:
        entry = lock["packages"]["node_modules/" + name]
        algorithm, expected = entry["integrity"].split("-", 1)
        if algorithm != "sha512":
            raise SystemExit(f"unexpected integrity for {name}")
        cached = cache / (name.replace("/", "__") + "-" + entry["version"] + ".tgz")
        if not cached.exists():
            with urllib.request.urlopen(entry["resolved"], timeout=120) as response:
                cached.write_bytes(response.read(64 * 1024 * 1024))
        body = cached.read_bytes()
        if base64.b64encode(hashlib.sha512(body).digest()).decode() != expected:
            raise SystemExit(f"integrity mismatch for {name}")
        files = []
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
            for member in archive.getmembers():
                parts = member.name.split("/")
                if member.isfile() and len(parts) == 2 and LICENSE_FILE.match(parts[1]):
                    files.append((parts[1], archive.extractfile(member).read()))
            manifest = json.loads(archive.extractfile("package/package.json").read())
        license_value = manifest.get("license")
        rows.append({"kind": "npm", "name": name, "version": entry["version"], "integrity": entry["integrity"],
                     "license": license_value if isinstance(license_value, str) else json.dumps(license_value),
                     "repository": json.dumps(manifest.get("repository")) if not isinstance(manifest.get("repository"), str)
                     else manifest["repository"], "authors": [], "files": sorted(files)})
    return rows


def render(components):
    out = [
        "Mobile Release Kit for macOS: third-party notices",
        "",
        "This application includes the open-source components listed below. Each",
        "component's own licence, notice and copyright files are reproduced verbatim",
        "from its locked source. Notices for the embedded Python runtime are in",
        "python/licenses inside the bundled runtime, and notices for the Android",
        "build tools are beside those tools in the application's resources.",
        "",
        f"Components: {len(components)}",
        "",
    ]
    first = {}
    for component in components:
        out.append("=" * 78)
        out.append(f"{component['name']} {component['version']} ({'Rust crate' if component['kind'] == 'crate' else 'npm package'})")
        out.append(f"License: {component['license'] or 'see files below'}")
        if component["repository"] and component["repository"] != "null":
            out.append(f"Source: {component['repository']}")
        if component["authors"]:
            out.append("Authors: " + "; ".join(component["authors"]))
        if not component["files"]:
            out.append("(The published source of this component contains no separate licence file;")
            out.append(" its licence is the SPDX expression above.)")
        for name, body in component["files"]:
            key = digest(body)
            if key in first:
                out.append(f"--- {name}: identical to {first[key]} ---")
                continue
            first[key] = f"{component['name']} {component['version']} {name}"
            out.append(f"--- {name} ---")
            out.append(body.decode("utf-8", "replace").replace("\r\n", "\n").rstrip("\n"))
        out.append("")
    # Components whose published source has no licence file: point each SPDX
    # licence they name at an identical verbatim text already reproduced above
    # (never a text typed from memory). Their listed authors are the holders.
    needed = sorted({token for c in components if not c["files"] for token in spdx_ids(c["license"])})
    if needed:
        out.append("=" * 78)
        out.append("Licence texts for the components above that publish no separate licence file")
        out.append("")
        for token in needed:
            reference = reference_text(components, token)
            users = [f"{c['name']} {c['version']}" for c in components if not c["files"] and token in spdx_ids(c["license"])]
            out.append(f"{token}: " + (f"the text reproduced above for {reference}" if reference else "see https://spdx.org/licenses/" + token + ".html"))
            out.append("  applies to: " + ", ".join(users) + " (copyright: the authors listed for each component)")
        out.append("")
    return ("\n".join(out) + "\n").encode()


def spdx_ids(expression):
    return [t for t in re.split(r"[\s()/]+|\bOR\b|\bAND\b", expression or "") if t and t not in ("OR", "AND", "WITH")]


REFERENCE_HINTS = {"MIT": ("MIT",), "Apache-2.0": ("APACHE",), "Zlib": ("ZLIB",), "BSD-3-Clause": ("LICENSE", "COPYING"),
                   "MPL-2.0": ("LICENSE", "COPYING")}


def reference_text(components, token):
    """The first reproduced file that is clearly that licence's own text."""
    for c in components:
        ids = spdx_ids(c["license"])
        for name, _body in c["files"]:
            upper = name.upper()
            hinted = any(hint in upper for hint in REFERENCE_HINTS.get(token, ()))
            if token in ("MIT", "Apache-2.0", "Zlib") and hinted and token in ids:
                return f"{c['name']} {c['version']} {name}"
            if token in ("BSD-3-Clause", "MPL-2.0") and ids == [token] and hinted:
                return f"{c['name']} {c['version']} {name}"
    return None


def generate(cache):
    cache.mkdir(parents=True, exist_ok=True)
    components = crates() + npm_packages(cache)
    notice = render(components)
    if len(notice) > NOTICE_LIMIT:
        raise SystemExit("notices too large")
    inputs = {"schemaVersion": 1, "targets": list(TARGETS), "workspaces": list(WORKSPACES),
              "lockfiles": {name: digest(path.read_bytes()) for name, path in lockfiles().items()},
              "noticeSha256": digest(notice), "noticeBytes": len(notice),
              "components": [{"kind": c["kind"], "name": c["name"], "version": c["version"],
                              **({"checksum": c["checksum"]} if c["kind"] == "crate" else {"integrity": c["integrity"]}),
                              "license": c["license"], "files": [{"name": n, "sha256": digest(b), "bytes": len(b)} for n, b in c["files"]]}
                             for c in components]}
    (OUTPUT / NOTICE_NAME).write_bytes(notice)
    (OUTPUT / INPUTS_NAME).write_text(json.dumps(inputs, indent=1, sort_keys=True) + "\n")
    return inputs


def check():
    """Return the recorded inputs when the notices still match the lockfiles."""
    inputs = json.loads((OUTPUT / INPUTS_NAME).read_text())
    current = {name: digest(path.read_bytes()) for name, path in lockfiles().items()}
    if inputs["lockfiles"] != current:
        changed = sorted(name for name in current if inputs["lockfiles"].get(name) != current[name])
        raise SystemExit("third-party notices are stale for: " + ", ".join(changed)
                         + " (run desktop/tools/macos_third_party_notices.py generate)")
    notice = (OUTPUT / NOTICE_NAME).read_bytes()
    if digest(notice) != inputs["noticeSha256"] or len(notice) != inputs["noticeBytes"]:
        raise SystemExit("third-party notices file does not match its recorded digest")
    locked = {}
    for workspace in WORKSPACES:
        for package in tomllib.loads((DESKTOP / workspace / "Cargo.lock").read_text())["package"]:
            locked[(package["name"], package["version"])] = package.get("checksum")
    npm = json.loads((DESKTOP / "package-lock.json").read_text())["packages"]
    for component in inputs["components"]:
        if component["kind"] == "crate":
            if locked.get((component["name"], component["version"]), "missing") != component["checksum"]:
                raise SystemExit(f"crate {component['name']} {component['version']} is not in the lockfiles")
        elif npm.get("node_modules/" + component["name"], {}).get("integrity") != component["integrity"]:
            raise SystemExit(f"npm package {component['name']} is not in package-lock.json")
    return inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("generate", "check"))
    parser.add_argument("--cache", type=Path, help="download cache for npm tarballs (generate)")
    args = parser.parse_args()
    if args.action == "generate":
        if args.cache is None:
            parser.error("generate needs --cache")
        inputs = generate(args.cache)
        print(f"{len(inputs['components'])} components, {inputs['noticeBytes']} bytes")
    else:
        inputs = check()
        print(f"notices current: {len(inputs['components'])} components")


if __name__ == "__main__":
    sys.exit(main())
