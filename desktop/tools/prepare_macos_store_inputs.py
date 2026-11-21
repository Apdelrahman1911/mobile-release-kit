"""Prepare public, checksum-locked Store build inputs; never execute a download.

Run with Python 3.12+ in a disposable build directory. Network acquisition is a
separate step from the offline component build. No credentials or global cache.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
SOURCES = (
    {"directory": "ruby-3.3.12", "url": "https://cache.ruby-lang.org/pub/ruby/3.3/ruby-3.3.12.tar.gz",
     "bytes": 21489887, "sha256": "b06d63beae271933033e27f0a389bc582a009e7845357d44365c39de525a051b"},
    {"directory": "yaml-0.2.5", "url": "https://pyyaml.org/download/libyaml/yaml-0.2.5.tar.gz",
     "bytes": 609454, "sha256": "c642ae9b75fee120b2d96c712538bd2cf283228d2337df2cf2988e3c02678ef4"},
)


def fetch(asset, destination):
    """Ordinary curl transport, HTTPS only; digest before any source extraction."""
    maximum = asset.get("bytes", 8 * 1024 * 1024)
    with destination.open("xb") as stream:
        subprocess.run(["curl", "--disable", "--fail", "--silent", "--show-error", "--location",
                        "--proto", "=https", "--proto-redir", "=https", "--noproxy", "*",
                        "--max-redirs", "3", "--connect-timeout", "15", "--max-time", "120",
                        "--max-filesize", str(maximum), asset["url"]],
                       stdout=stream, check=True, timeout=125)
    size = destination.stat().st_size
    with destination.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if not 0 < size <= maximum or "bytes" in asset and size != asset["bytes"] or digest != asset["sha256"]:
        raise ValueError("Public dependency size/checksum mismatch")


def unpack(archive, destination, expected_root):
    """Use Python's supported data filter; cap output and reject extra roots."""
    count = total = 0
    def selection(member, target):
        nonlocal count, total
        count += 1
        total += member.size
        if count > 100_000 or total > 512 * 1024 * 1024 or member.size < 0:
            raise ValueError("Source archive exceeds preparation bounds")
        if member.name != expected_root and not member.name.startswith(expected_root + "/"):
            raise ValueError("Unexpected source archive root")
        # data_filter prevents traversal, outside links, devices and unsafe modes.
        return tarfile.data_filter(member, target)
    destination.mkdir()
    with tarfile.open(archive, "r:gz") as source:
        source.extractall(destination, filter=selection)
    result = destination / expected_root
    if result.is_symlink() or not result.is_dir():
        raise ValueError("Missing ordinary source directory")
    return result


def unpack_ruby_headers(archive, destination):
    """Select upstream common headers only; generated arch headers stay in base.

    Matches Ruby 3.3.12 tool/rbinstall.rb's common-header selection. The caller
    authenticates the complete archive before this ordinary data-only extraction.
    """
    destination.mkdir(mode=0o700)
    prefix = SOURCES[0]["directory"] + "/include/"
    names, members, total = set(), [], 0
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            if not member.name.startswith(prefix):
                continue
            name = member.name.removeprefix(prefix)
            if member.isdir():
                continue
            parts = name.split("/")
            if (not member.isfile() or any(part in ("", ".", "..") or re.fullmatch(r"[A-Za-z0-9_.-]+", part) is None for part in parts)
                    or len(parts) > 16 or "\\" in name or len(name) > 512):
                raise ValueError("Unsupported Ruby header entry")
            if not name.endswith((".h", ".hpp")) or parts[-1] == "win32.h":
                continue
            if name.casefold() in names or member.size < 0:
                raise ValueError("Duplicate or invalid Ruby header")
            names.add(name.casefold())
            total += member.size
            if len(names) > 2048 or total > 16 * 1024 * 1024:
                raise ValueError("Ruby headers exceed assembly bounds")
            selected = copy.copy(member)
            selected.name = name
            members.append(selected)
        if not {"ruby.h", "ruby/ruby.h", "ruby/version.h"} <= names:
            raise ValueError("Required common Ruby headers missing")
        source.extractall(destination, members=members, filter=tarfile.data_filter)



def copy_tooling(source_root, destination):
    """Copy the shared core's actual tooling roster into a fresh component."""
    # This fixed first-party module imports only stdlib/config/errors. Import it
    # normally rather than maintaining a second list of required asset names.
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from mobile_release.tooling import REQUIRED_TOOLING_FILES, _complete_tooling_root
    finally:
        sys.path.pop(0)
    if not _complete_tooling_root(source_root):
        raise ValueError("Incomplete first-party tooling source")
    destination.mkdir(mode=0o700)
    for relative in REQUIRED_TOOLING_FILES:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_root / relative, target)
    if not _complete_tooling_root(destination):
        raise ValueError("Incomplete copied first-party tooling")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Absent task-owned output directory")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--tooling-only", action="store_true", help="Copy first-party tooling only; no network")
    modes.add_argument("--sources-only", action="store_true", help="Acquire native base sources/CA, no gems")
    modes.add_argument("--gems-only", action="store_true", help="Acquire locked gems only, no native sources")
    modes.add_argument("--assembly-inputs", action="store_true", help="Acquire locked gems and common Ruby headers; no base compilation")
    args = parser.parse_args()
    output = args.output.absolute()
    if args.tooling_only:
        copy_tooling(ROOT, output)
        return
    output.mkdir(mode=0o700)  # Existing/foreign output is never adopted.
    if shutil.disk_usage(output).free < 4 * 1024**3:
        raise ValueError("Need at least 4 GiB free for public sources and compilation")
    if args.assembly_inputs:
        archive = output / "ruby-headers.tar.gz"
        fetch(SOURCES[0], archive)
        unpack_ruby_headers(archive, output / "ruby-headers")
        archive.unlink()
    elif not args.gems_only:
        lock = json.loads((ROOT / "desktop/macos-cpython-source-inputs/source-lock.json").read_text())
        openssl, = [row for row in lock["archiveSelections"] if row["id"] == "openssl"]
        if openssl["version"] != "3.5.8":
            raise ValueError("Unsupported OpenSSL source version")
        sources = (*SOURCES, {**openssl, "directory": "openssl-3.5.8"})
        for asset in sources:
            archive = output / (asset["directory"] + ".tar.gz")
            fetch(asset, archive)
            staging = output / (asset["directory"] + "-extract")
            tree = unpack(archive, staging, asset["directory"])
            tree.rename(output / asset["directory"])
            staging.rmdir()
            archive.unlink()  # Exactly this authenticated downloaded archive.
        shutil.copyfile(ROOT / "desktop/cpython-source-inputs/github-ca.pem", output / "ca.pem")
    if not args.sources_only:
        spec = importlib.util.spec_from_file_location("mrk_ci_public_inputs", ROOT / ".github/scripts/ci_prepare.py")
        loader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loader)
        _manifest, _wheels, gems, _manifest_hash, _lock_hash = loader.load_assets(ROOT, "macos")
        cache = output / "gems"
        cache.mkdir()
        for asset in gems:
            fetch(asset, cache / asset["filename"])
    print("Prepared requested checksum-locked inputs; nothing executed.")



if __name__ == "__main__":
    main()
