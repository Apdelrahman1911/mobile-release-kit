#!/usr/bin/env python3
"""Mac engineering package DATA staging; never execute the payload.

Every output is fresh. No extraction API, subprocess, chmod of an existing
ancestor, replacement, deletion, network, core import or interpreter rebuild is
present. The describe commands supply proposed successor digests for independent
review BEFORE app compilation; current-source preparation uses a fresh private
projection and an explicitly selected, independently pinned supplier. Final staging
requires explicit digests, not a discovered adjacent-manifest authority.
Installer-log actions only collect bounded nonroot diagnostics from one fixed
physical log; they never give those bytes installation/readback authority.
"""
from __future__ import annotations

import argparse
from collections import namedtuple
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import struct
import sys
import tarfile
import xml.etree.ElementTree as ET
import zipfile
import zlib

DESKTOP = Path(__file__).absolute().parents[1]
BUILD_RELEASE_INPUT = DESKTOP / "macos-installed-inputs/build-release.json"
BUILD_RELEASE_LIMIT = 4096
ARM_TARGET = "aarch64-apple-darwin"
INTEL_TARGET = "x86_64-apple-darwin"
MAC_TARGETS = (ARM_TARGET, INTEL_TARGET)
BuildSelection = namedtuple("BuildSelection", "target package_version release")
ProducerSelection = namedtuple("ProducerSelection", "team leaf_sha1 leaf_sha256 rsa_bits producer_sha256 service_sha256")
PRODUCER_PROFILE = DESKTOP / "packaging/macos-install-producer-signing.profile"
SERVICE_PROFILE = DESKTOP / "packaging/macos-android-service-signing.profile"
PACKAGING_CALL_ROLES = ("producer-build", "producer-emitter", "distribution-create", "distribution-sign",
    "distribution-verify-signature", "distribution-verify-image", "observation-create", "observation-sign",
    "observation-verify-signature", "observation-verify-image", "distribution-attach", "installer-log-cursor",
    "installer", "installer-log-capture", "distribution-detach")
# Provenance label for the immutable historical supplier, not active selection.
HISTORICAL_SUPPLIER_RELEASE = "macos26-arm64-project-draft-01"
INSTALL_ROOT = Path("/Library/Application Support/MobileReleaseKit")
APP_NAME = "Mobile Release Kit.app"
ENTRY_BINARY = "Contents/MacOS/mrk-macos-entry"
ENTRY_BUNDLE_ID = "dev.mobile-release-kit.desktop.entry"
PAYLOAD_NAME = "MobileReleaseKitPayload.app"
PAYLOAD_RELATIVE = "Contents/Helpers/" + PAYLOAD_NAME
PAYLOAD_CONTENTS = PAYLOAD_RELATIVE + "/Contents/"
APP_BINARY = PAYLOAD_CONTENTS + "MacOS/mobile-release-kit-desktop"
DESKTOP_IMAGE = PAYLOAD_CONTENTS + "Frameworks/libmrk_desktop_image.dylib"
RESIDENT_IMAGE = PAYLOAD_CONTENTS + "Frameworks/libmrk_resident_image.dylib"
PACKAGE_ROLES = ("ordinary-image", "installed-shell-observation")
IMAGE_INSTALL_NAMES = {
    "desktop": str(INSTALL_ROOT / APP_NAME / DESKTOP_IMAGE),
    "resident": str(INSTALL_ROOT / APP_NAME / RESIDENT_IMAGE),
}
PAYLOAD_INFO = PAYLOAD_CONTENTS + "Info.plist"
VAULT_HELPER = PAYLOAD_CONTENTS + "Helpers/mrk-vault-keychain"
REMOVER_NAME = "mrk-macos-remove"
REMOVER = PAYLOAD_CONTENTS + "Helpers/" + REMOVER_NAME
REMOVE_PACKAGE_ID = "dev.mobile-release-kit.desktop.remove"
REMOVE_DESCRIPTOR_BYTES = 16 * 1024
REMOVER_BYTES = 64 * 1024 * 1024
ANDROID_HELPER_BUNDLE_PROGRAM = "Contents/Helpers/mrk-android-register"
ANDROID_HELPER = PAYLOAD_RELATIVE + "/" + ANDROID_HELPER_BUNDLE_PROGRAM
ANDROID_SERVICE_PLIST = PAYLOAD_CONTENTS + "Library/LaunchDaemons/dev.mobile-release-kit.desktop.android-register.plist"
ANDROID_SERVICE_LABEL = "dev.mobile-release-kit.desktop.android-register"
ANDROID_SUPPORT_PREFIX = "Contents/Resources/android-support/"
ANDROID_SUPPORT_MANIFEST = DESKTOP / "macos-installed-inputs/android-support.json"
ANDROID_SUPPORT_LAYOUT = (
    ("bundletool", "bundletool-all-1.18.3.jar",
     "https://github.com/google/bundletool/releases/download/1.18.3/bundletool-all-1.18.3.jar",
     ("LICENSE", "NOTICE", "META-INF/LICENSE", "META-INF/LICENSE.txt", "macos/NOTICE", "linux/NOTICE", "windows/NOTICE")),
    ("aapt2", "aapt2-8.9.2-12782657-osx.jar",
     "https://dl.google.com/dl/android/maven2/com/android/tools/build/aapt2/8.9.2-12782657/aapt2-8.9.2-12782657-osx.jar",
     ("NOTICE",)),
)
PACKAGE_ID = "dev.mobile-release-kit.desktop.installed"
BUNDLE_ID = "dev.mobile-release-kit.desktop"
MAINTENANCE_GATE_NAME = "maintenance-gate-v1"
MAINTENANCE_GATE_BYTES = b"MRK-MACOS-MAINTENANCE-GATE-v1\n"
REGISTRATION_GATE_NAME = "registration-reservation-v1"
REGISTRATION_GATE_BYTES = b"MRK-MACOS-REGISTRATION-RESERVATION-v1\n"
INSTALLATION_INVENTORY_NAME = "install-inventory.json"
INSTALLATION_RECORD_NAME = "installation-v1.json"
INSTALLATION_RECORD_LIMIT = 8192
FIXTURE_PREFIX = "MobileReleaseKit-InstallerFixture-"
FIXTURE_MARKER = b"MRK_MACOS_INSTALLER_FIXTURE_OCCUPANT\n"
# Exact order/expected original outcomes of the separate compile-time package.
# DATA validation does not itself witness any syscall or injected failure.
FIXTURE_CASES = {
    "occupied-app": ("destination-occupied", "not-attempted", "not-attempted", "refused-staging-retained", False, 1),
    "occupied-release": ("destination-occupied", "not-attempted", "not-attempted", "refused-staging-retained", False, 1),
    "runtime-publication-collision": ("exclusive-publication-refused-or-unknown", "occupied-refused", "not-attempted", "refused-staging-retained", True, 1),
    "staging-file-collision": ("open-refused", "not-attempted", "not-attempted", "refused-staging-retained", False, 1),
    "first-publication-second-refusal": ("exclusive-publication-refused-or-unknown", "confirmed", "occupied-refused", "partial-installation-retained", True, 20),
    "prepublication-persistence-report": ("fixture-reported-persistence-failure", "not-attempted", "not-attempted", "refused-staging-retained", False, 1),
    "postruntime-persistence-report": ("fixture-reported-persistence-failure", "confirmed", "not-attempted", "partial-installation-retained", True, 20),
    "metadata-descriptor-collision": ("open-refused", "confirmed", "not-attempted", "partial-installation-retained", True, 20),
}
PROTOCOL = "860d1cee0072730a487ac8e632206c69e3ba676cab849b144a61755c4b84e41e"
# Current product protocol is separately source-bound; never rewrite the
# historical supplier's protocol anchor to admit a newer core.
CURRENT_PROTOCOL = "083e6afae3e329c4e0d81bad00dd0c9920f77491b38ce0d23aa602996f4c4bf5"
ZIP_SIZE = 14726344
ZIP_SHA = "42a6abab90f9641ba1b8c4aa9bb4202b153d676cc6d135b8227d8690e18275be"
TAR_SIZE = 24432640
TAR_SHA = "c927caedfc5a40290da443989534e85bfdf192934f4650c3747a70c53f68d35a"
ORIGINAL_MANIFEST = "7e0b042c82ff567ccfa156974118911e2ba159dbe45020344aaf4d71a28acc44"
NOTICES = {
    "21-LLVM-header-license.txt": (15141, "8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee"),
    "22-macOS-SDK-libffi-header-notices.txt": (7329, "5ffe9bffec415b13d6de1f98cffe44bd16297bd91b64d3076cc2852b8de83c68"),
}
BOOTSTRAPS = {"engine_bootstrap.py", "config_edit_bootstrap.py", "github_connection_bootstrap.py",
              "environment_bootstrap.py", "offline_preflight_bootstrap.py", "android_build_bootstrap.py"}
# Accepted historical supplier bytes keep their original entry roster. Newly
# composed payloads include every fixed current domain without rewriting them.
CURRENT_BOOTSTRAPS = BOOTSTRAPS | {
    "project_recovery_bootstrap.py", "github_preflight_bootstrap.py",
    "ios_archive_bootstrap.py", "github_release_bootstrap.py",
}
CURRENT_CA_SOURCE = "desktop/cpython-source-inputs/github-ca.pem"
CURRENT_HELPER_SOURCE = "desktop/tools/prepare_runtime.py"
CURRENT_CORE_BYTES = 32 * 1024 * 1024
MAX_FILES = 2048
MAX_BYTES = 512 * 1024 * 1024
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
INSTALLER_RESULT_BYTES = 65536
INSTALLER_RESULT_STATE = "pending-original-export-finalization"
MAINTENANCE_STATE_NAME = "installation-v2.json"
MAINTENANCE_METADATA_BYTES = 16 * 1024 * 1024
MAINTENANCE_ACTIONS = ("fresh-install", "same-package-noop", "restore-fixed-app", "update")
PRODUCER_DESCRIPTOR_BYTES = 64 * 1024
PRODUCER_SIGNATURE_BYTES = 16 * 1024
_DARWIN_XATTRS = None
INSTALL_LOG = Path("/private/var/log/install.log")
LOG_TAIL_BYTES = 4096
LOG_INTERVAL_BYTES = 1024 * 1024
LOG_LINE_BYTES = 128 * 1024
LOG_SELECTED_BYTES = 256 * 1024
LOG_METADATA_BYTES = 256 * 1024
LOG_AUTHORITY = "project-correlated-diagnostics-not-package-pid-authentication-or-original-fd-custody"
LOG_REFUSALS = frozenset({
    "log-input-binding", "log-file-policy", "log-file-identity", "log-cursor-shape", "log-cursor-binding",
    "log-cursor-offset", "log-anchor-rewritten", "log-truncated", "log-incomplete-boundary",
    "log-interval-bound", "log-line-bound", "log-selected-bound", "log-metadata-bound",
    "log-no-project-lines", "log-read-incomplete", "log-output-readback", "original-close-unknown",
    "ancestor-close-unknown",
})


class Refused(Exception):
    pass


GENERIC_REFUSAL = "Mac package staging/observation refused; preserve original outputs, no automatic cleanup or retry."
PACKAGE_REFUSALS = {
    "android-support-manifest": "MRK_MACOS_PACKAGE_REFUSED=android-support-manifest",
    "android-support-archive": "MRK_MACOS_PACKAGE_REFUSED=android-support-archive",
    "android-support-notice": "MRK_MACOS_PACKAGE_REFUSED=android-support-notice",
    "android-support-roster": "MRK_MACOS_PACKAGE_REFUSED=android-support-roster",
    "android-support-resource": "MRK_MACOS_PACKAGE_REFUSED=android-support-resource",
    "android-service-paired-inputs": "MRK_MACOS_PACKAGE_REFUSED=android-service-paired-inputs",
    "android-service-plist": "MRK_MACOS_PACKAGE_REFUSED=android-service-plist",
    "android-helper-final-signed-digest": "MRK_MACOS_PACKAGE_REFUSED=android-helper-final-signed-digest",
    "android-service-input-pair": "MRK_MACOS_PACKAGE_REFUSED=android-service-input-pair",
    "android-helper-signature-bytes-changed": "MRK_MACOS_PACKAGE_REFUSED=android-helper-signature-bytes-changed",
    "output-mode": "MRK_MACOS_PACKAGE_REFUSED=output-mode",
    "compressed-data-bound": "MRK_MACOS_PACKAGE_REFUSED=compressed-data-bound",
    "xar-header-bound": "MRK_MACOS_PACKAGE_REFUSED=xar-header-bound",
    "xar-member-encoding": "MRK_MACOS_PACKAGE_REFUSED=xar-member-encoding",
    "scripts-only-package-no-payload": "MRK_MACOS_PACKAGE_REFUSED=scripts-only-package-no-payload",
    "unsupported-scripts-cpio-format": "MRK_MACOS_PACKAGE_REFUSED=unsupported-scripts-cpio-format",
    "cpio-trailer": "MRK_MACOS_PACKAGE_REFUSED=cpio-trailer",
    "scripts-root-required": "MRK_MACOS_PACKAGE_REFUSED=scripts-root-required",
    "scripts-root-duplicate": "MRK_MACOS_PACKAGE_REFUSED=scripts-root-duplicate",
    "scripts-root-owner-mode": "MRK_MACOS_PACKAGE_REFUSED=scripts-root-owner-mode",
    "scripts-entry-owner": "MRK_MACOS_PACKAGE_REFUSED=scripts-entry-owner",
    "scripts-directory-mode": "MRK_MACOS_PACKAGE_REFUSED=scripts-directory-mode",
    "scripts-file-type-mode": "MRK_MACOS_PACKAGE_REFUSED=scripts-file-type-mode",
    "packager-identity": "MRK_MACOS_PACKAGE_REFUSED=packager-identity",
    "packager-directory-mode-owner": "MRK_MACOS_PACKAGE_REFUSED=packager-directory-mode-owner",
    "packager-file-mode-owner": "MRK_MACOS_PACKAGE_REFUSED=packager-file-mode-owner",
    "original-package-owner": "MRK_MACOS_PACKAGE_REFUSED=original-package-owner",
    "original-package-roster": "MRK_MACOS_PACKAGE_REFUSED=original-package-roster",
    "complete-original-scripts-correspondence": "MRK_MACOS_PACKAGE_REFUSED=complete-original-scripts-correspondence",
    "scripts-package-identity": "MRK_MACOS_PACKAGE_REFUSED=scripts-package-identity",
    "final-package-roster": "MRK_MACOS_PACKAGE_REFUSED=final-package-roster",
    "package-info-bytes-changed": "MRK_MACOS_PACKAGE_REFUSED=package-info-bytes-changed",
    "complete-root-owned-scripts-correspondence": "MRK_MACOS_PACKAGE_REFUSED=complete-root-owned-scripts-correspondence",
}


def package_refusal_message(error):
    # Select only a predeclared literal. Never stringify/reflect an exception.
    if type(error) is Refused and len(error.args) == 1 and type(error.args[0]) is str:
        message = PACKAGE_REFUSALS.get(error.args[0])
        if message is not None:
            return message + "\n" + GENERIC_REFUSAL
    return GENERIC_REFUSAL


def need(ok, reason):
    if not ok:
        raise Refused(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def decode(body):
    need(len(body) <= 1024 * 1024, "json-byte-bound")
    value = json.loads(body, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Refused("json-constant")))
    todo = [(value, 0)]
    count = 0
    while todo:
        item, depth = todo.pop()
        count += 1
        need(count <= 20000 and depth <= 32, "json-shape-bound")
        if type(item) is dict:
            todo.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            todo.extend((v, depth + 1) for v in item)
        elif type(item) is float:
            need(float("-inf") < item < float("inf"), "json-constant")
    return value


def mac_target(target=ARM_TARGET):
    need(type(target) is str and target in MAC_TARGETS, "build-target")
    return target


def target_machine(target=ARM_TARGET):
    return (0x0100000C, 0) if mac_target(target) == ARM_TARGET else (0x01000007, 3)


def command_target(args):
    return mac_target(getattr(args, "target", ARM_TARGET))


def arm_only(target):
    need(mac_target(target) == ARM_TARGET, "unqualified-intel-route")


def source_lock_input(target=ARM_TARGET):
    return (FRESH_SOURCE_LOCK if mac_target(target) == ARM_TARGET else
            "desktop/macos-cpython-source-inputs/source-lock-intel.json")


def source_build_selection(target=ARM_TARGET):
    target = mac_target(target)
    # Preserve the source-bound ARM identity initialized once at module load.
    # An explicit Intel command reads only its fixed independent release input.
    version, release = ((PACKAGE_VERSION, RELEASE) if target == ARM_TARGET else
                        source_build_release(target=target))
    return BuildSelection(target, version, release)


def selected_build(selection=None):
    if selection is None:
        selection = source_build_selection()
    need(type(selection) is BuildSelection, "build-selection")
    build_release_data(canonical({"schemaVersion": 1, "packageVersion": selection.package_version,
                                  "release": selection.release}), target=selection.target)
    return selection


def build_release_data(body, *, target=ARM_TARGET):
    """The same closed fixed build DATA consumed by src-tauri/build.rs."""
    target = mac_target(target)
    prefix = "macos26-arm64-" if target == ARM_TARGET else "macos26-x86_64-"
    need(type(body) is bytes and 0 < len(body) <= BUILD_RELEASE_LIMIT, "build-release-size")
    try:
        value = decode(body)
    except (ValueError, RecursionError, OverflowError) as error:
        raise Refused("build-release-shape") from error
    need(type(value) is dict and set(value) == {"schemaVersion", "packageVersion", "release"}
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1, "build-release-shape")
    version, release = value["packageVersion"], value["release"]
    need(type(version) is str and len(version) <= 32
         and re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version) is not None
         and all(int(part) <= 0xffffffff for part in version.split('.')), "build-release-version")
    need(type(release) is str and len(release) <= 128 and release.startswith(prefix)
         and len(release) > len(prefix) and re.fullmatch(r"[a-z0-9_.-]*[a-z0-9]", release) is not None,
         "build-release-identity")
    return value


def safe_path(value):
    if type(value) is not str or not value or len(value) > 512 or not value.isascii():
        return False
    parts = value.split("/")
    if len(parts) > 16:
        return False
    for part in parts:
        if not re.fullmatch(r"[A-Za-z0-9._+-]+", part) or part in (".", "..") or part.endswith("."):
            return False
        stem = part.split(".", 1)[0].upper()
        if stem in ("CON", "PRN", "AUX", "NUL") or re.fullmatch(r"(?:COM|LPT)[1-9]", stem):
            return False
    return True


def signature(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def close_once(fd):
    # Never retry an ambiguous close or silently convert it into settlement.
    try:
        os.close(fd)
    except OSError as error:
        raise Refused("original-close-unknown") from error


@contextlib.contextmanager
def parent(path):
    path = Path(path)
    spelling = os.fspath(path)
    need(path.is_absolute() and len(os.fsencode(spelling)) <= 4096, "absolute-path-required")
    parts = spelling.split("/")[1:]
    need(parts and len(parts) <= 40 and all(p and p not in (".", "..") and len(os.fsencode(p)) <= 255 for p in parts), "path-spelling")
    originals = []
    try:
        originals.append(os.open("/", READ_FLAGS | os.O_DIRECTORY))
        for name in parts[:-1]:
            before = os.stat(name, dir_fd=originals[-1], follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode), "ancestor-type")
            opened = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=originals[-1])
            originals.append(opened)
            need(signature(os.fstat(opened)) == signature(before), "ancestor-changed")
        yield originals[-1], parts[-1]
    finally:
        unknown = False
        for fd in reversed(originals):
            try:
                close_once(fd)
            except Refused:
                unknown = True
        need(not unknown, "ancestor-close-unknown")


def no_xattrs(fd):
    # CPython's os xattr helpers are not portable to every Darwin build. This
    # fixed read-only system ABI is for the nonroot DATA stager only. The root
    # installer independently checks the actual staged originals in native C.
    global _DARWIN_XATTRS
    if sys.platform == "darwin":
        if _DARWIN_XATTRS is None:
            import ctypes
            library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            call = library.flistxattr
            call.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            call.restype = ctypes.c_ssize_t
            _DARWIN_XATTRS = call
        need(_DARWIN_XATTRS(fd, None, 0, 0) == 0, "file-extended-attributes")
    elif sys.platform == "linux":
        need(not os.listxattr(fd), "file-extended-attributes")
    else:
        raise Refused("unsupported-data-host")


def read_at(fd, name, limit, *, zero_flags=False):
    before = os.stat(name, dir_fd=fd, follow_symlinks=False)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit
         and (not zero_flags or getattr(before, "st_flags", None) == 0), "ordinary-file-bound")
    original = os.open(name, READ_FLAGS, dir_fd=fd)
    try:
        opened = os.fstat(original)
        need(signature(opened) == signature(before)
             and (not zero_flags or getattr(opened, "st_flags", None) == 0), "file-open-changed")
        no_xattrs(original)
        data = bytearray()
        while len(data) <= limit:
            block = os.read(original, min(65536, limit + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        final = os.fstat(original)
        named = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(len(data) == before.st_size and signature(final) == signature(named) == signature(before)
             and (not zero_flags or getattr(final, "st_flags", None) == getattr(named, "st_flags", None) == 0), "file-read-changed")
        return bytes(data), before
    finally:
        close_once(original)


def read(path, limit=MAX_BYTES):
    with parent(path) as (fd, name):
        return read_at(fd, name, limit)[0]


def source_build_release(*, target=ARM_TARGET):
    # Only the caller-selected closed target chooses a fixed source input;
    # no installed record, environment or package can nominate a release.
    target = mac_target(target)
    path = (BUILD_RELEASE_INPUT if target == ARM_TARGET else
            DESKTOP / "macos-installed-inputs/build-release-intel.json")
    value = build_release_data(read(path, BUILD_RELEASE_LIMIT), target=target)
    return value["packageVersion"], value["release"]


def directories(files):
    result = set()
    for path in files:
        bits = path.split("/")
        result.update("/".join(bits[:i]) for i in range(1, len(bits)))
    need(len(result) <= 2048, "directory-count")
    folded = set()
    for name in set(files) | result:
        need(safe_path(name) and name.lower() not in folded, "path-alias-or-type-collision")
        folded.add(name.lower())
    need(not (set(files) & result), "file-directory-collision")
    return result


def packager_ids():
    uid, gid = os.getuid(), os.getgid()
    need(uid != 0 and uid == os.geteuid() and gid == os.getegid(), "packager-identity")
    return uid, gid


def tree(path, *, installed=False, packager=False, max_bytes=MAX_BYTES, current_root_mode=None):
    need(not (installed and packager), "conflicting-tree-owner")
    need(type(max_bytes) is int and 0 <= max_bytes <= MAX_BYTES, "tree-byte-bound")
    need(current_root_mode is None or (not installed and not packager
         and type(current_root_mode) is int and current_root_mode in (0o555, 0o700)), "current-tree-policy")
    owner = packager_ids() if packager else None
    current_owner = packager_ids() if current_root_mode is not None else None
    found = {}
    observed_directories = set()
    count = total = 0

    def visit(fd, prefix, depth):
        nonlocal count, total
        need(depth <= 16, "tree-depth")
        before = os.fstat(fd)
        if installed:
            need(before.st_uid == 0 and before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o555, "installed-directory-mode-owner")
        if owner is not None:
            need((before.st_uid, before.st_gid) == owner and stat.S_IMODE(before.st_mode) == (0o755 if depth == 0 else 0o555),
                 "packager-directory-mode-owner")
        if current_owner is not None:
            need((before.st_uid, before.st_gid) == current_owner
                 and stat.S_IMODE(before.st_mode) == (current_root_mode if depth == 0 else 0o555),
                 "current-directory-mode-owner")
        no_xattrs(fd)
        names = sorted(os.listdir(fd))
        need(len(names) <= MAX_FILES, "directory-entry-bound")
        for name in names:
            relative = prefix + name
            count += 1
            need(count <= 4096 and safe_path(relative), "tree-path-bound")
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                observed_directories.add(relative)
                child = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=fd)
                try:
                    need(signature(os.fstat(child)) == signature(info), "tree-directory-changed")
                    visit(child, relative + "/", depth + 1)
                    need(signature(os.fstat(child)) == signature(info)
                         and signature(os.stat(name, dir_fd=fd, follow_symlinks=False)) == signature(info), "tree-directory-changed")
                finally:
                    close_once(child)
            else:
                body, info = read_at(fd, name, max_bytes - total)
                total += len(body)
                need(len(found) < MAX_FILES and relative not in found, "tree-file-bound")
                if installed:
                    need(info.st_uid == 0 and info.st_gid == 0, "installed-file-owner")
                if owner is not None:
                    need((info.st_uid, info.st_gid) == owner and stat.S_IMODE(info.st_mode) in (0o444, 0o555), "packager-file-mode-owner")
                if current_owner is not None:
                    need((info.st_uid, info.st_gid) == current_owner, "current-file-owner")
                found[relative] = (body, stat.S_IMODE(info.st_mode))
        need(signature(os.fstat(fd)) == signature(before), "tree-root-changed")

    with parent(path) as (fd, name):
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISDIR(before.st_mode), "tree-root-type")
        root = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=fd)
        try:
            need(signature(os.fstat(root)) == signature(before), "tree-root-changed")
            visit(root, "", 0)
            need(signature(os.stat(name, dir_fd=fd, follow_symlinks=False)) == signature(before), "tree-root-name-changed")
        finally:
            close_once(root)
    need(observed_directories == directories(found), "tree-unlisted-or-empty-directory")
    return found


def write_tree(output, files, *, root_mode=0o555, app_signing=False, current_owned=False):
    need(os.getuid() != 0 and os.getuid() == os.geteuid(), "builder-must-be-nonroot")
    need(type(current_owned) is bool and (not current_owned or (not app_signing and root_mode in (0o555, 0o700))),
         "current-output-policy")
    need(0 < len(files) <= MAX_FILES and sum(len(v[0]) for v in files.values()) <= MAX_BYTES, "output-bound")
    dirs = directories(files)
    with parent(output) as (outer, name):
        os.mkdir(name, 0o700, dir_fd=outer)  # Exclusive fresh task output; no cleanup on failure.
        root = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=outer)
        try:
            for directory in sorted(dirs, key=lambda p: (p.count("/"), p)):
                with parent(Path(output) / directory) as (fd, leaf):
                    os.mkdir(leaf, 0o700, dir_fd=fd)
            for path, (body, mode) in sorted(files.items()):
                # Signed resident image/helpers are copied unchanged/read-only.
                # The raw desktop image is executable code for inside-out signing.
                allowed_modes = (((0o555,) if path in (VAULT_HELPER, ANDROID_HELPER, RESIDENT_IMAGE, REMOVER)
                                  else (0o755,) if path == DESKTOP_IMAGE else (0o644, 0o755))
                                 if app_signing else (0o444, 0o555))
                need(mode in allowed_modes, "output-mode")
                with parent(Path(output) / path) as (fd, leaf):
                    opened = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=fd)
                    try:
                        view = memoryview(body)
                        while view:
                            count = os.write(opened, view)
                            need(count > 0, "output-write-zero")
                            view = view[count:]
                        os.fchmod(opened, mode)
                        os.fsync(opened)
                    finally:
                        close_once(opened)
                    actual, info = read_at(fd, leaf, len(body))
                    need(actual == body and stat.S_IMODE(info.st_mode) == mode, "output-readback")
            for directory in sorted(dirs, key=lambda p: (p.count("/"), p), reverse=True):
                with parent(Path(output) / directory) as (fd, leaf):
                    opened = os.open(leaf, READ_FLAGS | os.O_DIRECTORY, dir_fd=fd)
                    try:
                        os.fchmod(opened, 0o755 if app_signing else 0o555)
                        os.fsync(opened)
                    finally:
                        close_once(opened)
            os.fchmod(root, root_mode)
            os.fsync(root)
            os.fsync(outer)
        finally:
            close_once(root)
    actual = tree(output, current_root_mode=root_mode) if current_owned else tree(output)
    need(actual == files, "complete-output-readback")


def manifest_files(body, expected, *, current=False, target=ARM_TARGET):
    target = mac_target(target)
    need(type(current) is bool, "runtime-manifest-profile")
    need(current or target == ARM_TARGET, "unqualified-intel-route")
    protocol = CURRENT_PROTOCOL if current else PROTOCOL
    bootstraps = CURRENT_BOOTSTRAPS if current else BOOTSTRAPS
    need(sha(expected) and digest(body) == expected, "runtime-manifest-anchor")
    manifest = decode(body)
    need(type(manifest) is dict and set(manifest) == {"schemaVersion", "protocol", "coreVersion", "target", "coreSha256", "protocolSha256", "inventorySha256", "files"}
         and type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 1
         and type(manifest["protocol"]) is int and manifest["protocol"] == 1
         and manifest["target"] == target and manifest["protocolSha256"] == protocol,
         "runtime-manifest-shape")
    rows = manifest["files"]
    need(type(rows) is list and 0 < len(rows) <= MAX_FILES and digest(canonical(rows)) == manifest["inventorySha256"], "runtime-inventory-anchor")
    files = {}
    total = 0
    for row in rows:
        need(type(row) is dict and set(row) == {"path", "sha256", "size"}
             and safe_path(row["path"]) and row["path"] != "manifest.json" and row["path"] not in files
             and sha(row["sha256"]) and type(row["size"]) is int and 0 <= row["size"] <= MAX_BYTES, "runtime-inventory-entry")
        files[row["path"]] = row
        total += row["size"]
    need(list(files) == sorted(files) and total <= MAX_BYTES, "runtime-inventory-order-bound")
    need(bootstraps | {"core.zip", "github-ca.pem", "python/bin/python3"} <= set(files)
         and manifest["coreSha256"] == files["core.zip"]["sha256"], "runtime-required-members")
    directories(files)
    return manifest, files


def reused_runtime(archive_path):
    packed = read(archive_path, ZIP_SIZE)
    need(len(packed) == ZIP_SIZE and digest(packed) == ZIP_SHA, "accepted-zip-pin")
    with zipfile.ZipFile(io.BytesIO(packed)) as archive:
        rows = archive.infolist()
        need(len(rows) <= 2048 and len({row.filename for row in rows}) == len(rows), "accepted-zip-roster")
        selected = [row for row in rows if row.filename == "payload.tar"]
        need(len(selected) == 1 and selected[0].file_size == TAR_SIZE and not selected[0].flag_bits & 1, "accepted-tar-member")
        tar = archive.read(selected[0])
    need(len(tar) == TAR_SIZE and digest(tar) == TAR_SHA, "accepted-tar-pin")
    payload = {}
    with tarfile.open(fileobj=io.BytesIO(tar), mode="r:") as archive:
        total = 0
        for row in archive:
            need(row.isfile() and row.name.startswith("payload/") and row.uid == 0 and row.gid == 0
                 and 0 <= row.size <= MAX_BYTES and len(payload) < MAX_FILES, "accepted-tar-type-bound")
            name = row.name[len("payload/"):]
            need(safe_path(name) and name not in payload, "accepted-tar-path")
            total += row.size
            need(total <= MAX_BYTES, "accepted-tar-total")
            original = archive.extractfile(row)  # Memory stream only, never extract()/extractall().
            need(original is not None, "accepted-tar-stream")
            with original:
                body = original.read(row.size + 1)
            need(len(body) == row.size, "accepted-tar-size")
            payload[name] = body
    need("manifest.json" in payload, "accepted-manifest-missing")
    manifest, original_rows = manifest_files(payload["manifest.json"], ORIGINAL_MANIFEST)
    need(set(payload) == set(original_rows) | {"manifest.json"}, "accepted-tar-complete-roster")
    for name, row in original_rows.items():
        need(len(payload[name]) == row["size"] and digest(payload[name]) == row["sha256"], "accepted-tar-byte-correspondence")
    for name, (size, expected) in NOTICES.items():
        body = read(DESKTOP / "macos-installed-inputs/notices" / name, size)
        target = "python/licenses/" + name
        need(len(body) == size and digest(body) == expected and target not in payload, "notice-source-pin-or-collision")
        payload[target] = body
    successor = dict(manifest)
    successor["files"] = [{"path": name, "sha256": digest(body), "size": len(body)} for name, body in sorted(payload.items()) if name != "manifest.json"]
    successor["inventorySha256"] = digest(canonical(successor["files"]))
    payload["manifest.json"] = canonical(successor) + b"\n"
    result = {"schemaVersion": 1, "release": HISTORICAL_SUPPLIER_RELEASE, "acceptedArchiveSha256": ZIP_SHA, "acceptedTarSha256": TAR_SHA,
              "originalManifestSha256": ORIGINAL_MANIFEST, "successorManifestSha256": digest(payload["manifest.json"]),
              "protocolSha256": PROTOCOL, "unchangedOriginalFileCount": len(original_rows), "addedNotices": sorted(NOTICES),
              "qualification": "description-only-not-build-or-install-authority"}
    return payload, result


def runtime_command(args):
    arm_only(command_target(args))
    payload, result = reused_runtime(args.archive)
    if args.command == "runtime":
        need(sha(args.expected_manifest) and result["successorManifestSha256"] == args.expected_manifest, "reviewed-successor-manifest-mismatch")
        files = {name: (body, 0o555 if name == "python/bin/python3" else 0o444) for name, body in payload.items()}
        write_tree(args.output, files)
        result["qualification"] = "reused-bytes-staged-no-native-execution"
    return result


# Fresh public-source suppliers are independent of the historical archive above.
# The receipt is DATA; an external reviewed SHA256 binds actual producer evidence.
FRESH_SUPPLIER_KIND = "mrk-macos-cpython-source-supplier-v1"
FRESH_SOURCE_LOCK = "desktop/macos-cpython-source-inputs/source-lock.json"
FRESH_SOURCE_LOCK_LIMIT = 16 * 1024
FRESH_SUPPLIER_BYTES = 464 * 1024 * 1024
# tree()/write_tree() count the final manifest too, unlike its own file roster.
FRESH_SUPPLIER_FILES = MAX_FILES - len(CURRENT_BOOTSTRAPS) - 3
FRESH_EVIDENCE = {"build", "relocation", "modules", "loader", "tls", "cancellation", "notices"}


def current_supplier_origin(args):
    signed_python_options(args)
    archive, root = getattr(args, "archive", None), getattr(args, "python_root", None)
    receipt, expected = getattr(args, "supplier_receipt", None), getattr(args, "expected_supplier", None)
    need((archive is None) != (root is None), "current-supplier-selection")
    if root is None:
        need(isinstance(archive, Path) and receipt is None and expected is None, "current-historical-options")
        return "historical"
    need(isinstance(root, Path) and isinstance(receipt, Path) and sha(expected), "current-fresh-options")
    return "fresh-public-source"


def fresh_supplier_receipt(body, expected, source_lock, *, target=ARM_TARGET):
    """Validate a pinned receipt, not the native behavior its hashes reference."""
    target = mac_target(target)
    need(sha(expected) and digest(body) == expected, "fresh-receipt-anchor")
    value, lock = decode(body), decode(source_lock)
    fields = {"schemaVersion", "kind", "target", "pythonVersion", "gil", "sourceLockSha256",
              "producerSourceSha256", "recipeSha256", "toolchainSha256", "inventorySha256",
              "files", "notices", "nativeEvidence"}
    need(type(value) is dict and set(value) == fields and type(value["schemaVersion"]) is int
         and value["schemaVersion"] == 1 and value["kind"] == FRESH_SUPPLIER_KIND
         and value["target"] == target and value["pythonVersion"] == "3.14.7"
         and value["gil"] is True, "fresh-receipt-profile")
    need(all(sha(value[name]) for name in ("sourceLockSha256", "producerSourceSha256", "recipeSha256",
                                         "toolchainSha256", "inventorySha256")), "fresh-receipt-hashes")
    need(value["sourceLockSha256"] == digest(source_lock) and type(lock) is dict
         and type(lock.get("schemaVersion")) is int and lock["schemaVersion"] == 1
         and lock.get("target") == {"triple": target, "minimumMacOS": "26.0",
                                  "pythonVersion": "3.14.7", "gil": True}
         and lock["target"]["gil"] is True, "fresh-source-lock-binding")
    evidence = value["nativeEvidence"]
    need(type(evidence) is dict and set(evidence) == FRESH_EVIDENCE
         and all(sha(item) for item in evidence.values()), "fresh-native-evidence-references")
    rows = value["files"]
    need(type(rows) is list and 0 < len(rows) <= FRESH_SUPPLIER_FILES
         and digest(canonical(rows)) == value["inventorySha256"], "fresh-inventory-anchor")
    files, total = {}, 0
    for row in rows:
        need(type(row) is dict and set(row) == {"path", "size", "sha256", "mode"}
             and safe_path(row["path"]) and row["path"].startswith("python/") and row["path"] not in files
             and type(row["size"]) is int and 0 <= row["size"] <= FRESH_SUPPLIER_BYTES and sha(row["sha256"])
             and type(row["mode"]) is int
             and row["mode"] == (0o555 if row["path"] == "python/bin/python3" else 0o444), "fresh-inventory-entry")
        files[row["path"]] = row
        total += row["size"]
    need(list(files) == sorted(files) and "python/bin/python3" in files
         and total <= FRESH_SUPPLIER_BYTES, "fresh-inventory-order-bound")
    directories(files)
    notices = value["notices"]
    need(type(notices) is list and 6 <= len(notices) <= len(files)
         and all(type(name) is str and name.startswith("python/licenses/") and name in files for name in notices)
         and notices == sorted(set(notices)), "fresh-notice-roster")
    required = lock.get("requiredPublicNoticeInputs")
    need(type(required) is list and len(required) == 6, "fresh-required-notices")
    public_pairs = set()
    for row in required:
        need(type(row) is dict and type(row.get("bytes")) is int and row["bytes"] > 0
             and sha(row.get("sha256")), "fresh-required-notices")
        public_pairs.add((row["bytes"], row["sha256"]))
    actual_pairs = {(files[name]["size"], files[name]["sha256"]) for name in notices}
    need(len(public_pairs) == 6 and public_pairs <= actual_pairs, "fresh-notice-correspondence")
    return value, files


def fresh_supplier(args):
    """Read bounded fresh DATA only; never import or execute its interpreter."""
    target = command_target(args)
    owner = packager_ids()
    source_lock = read(DESKTOP.parent / source_lock_input(target), FRESH_SOURCE_LOCK_LIMIT)
    with parent(args.supplier_receipt) as (fd, leaf):
        body, info = read_at(fd, leaf, 1024 * 1024)
        need((info.st_uid, info.st_gid) == owner and stat.S_IMODE(info.st_mode) in (0o600, 0o444),
             "fresh-receipt-owner-mode")
    receipt, rows = fresh_supplier_receipt(body, args.expected_supplier, source_lock, target=target)
    supplier = tree(args.python_root, max_bytes=FRESH_SUPPLIER_BYTES, current_root_mode=0o555)
    need(set(supplier) == set(rows), "fresh-supplier-complete-roster")
    for name, (content, mode) in supplier.items():
        row = rows[name]
        need(len(content) == row["size"] and digest(content) == row["sha256"] and mode == row["mode"],
             "fresh-supplier-correspondence")
    provenance = {"supplierOrigin": "fresh-public-source", "supplierReceiptSha256": args.expected_supplier,
                  "supplierSourceLockSha256": receipt["sourceLockSha256"], "supplierProfile": FRESH_SUPPLIER_KIND,
                  "pythonVersion": receipt["pythonVersion"], "gil": receipt["gil"]}
    # Retain captured input bytes through composition; POST is a fresh same-
    # held/named read and content/mode comparison, not transferred FD custody.
    return supplier, provenance, source_lock, body


# A derived signature does not replace the original supplier's authority.
SIGNED_PYTHON_KIND = "mrk-macos-python-signed-derivation-v1"
SIGNED_PYTHON_IDENTIFIER = "dev.mobile-release-kit.desktop.python"
SIGNED_PYTHON_PATH = "python/bin/python3"
SIGNED_PYTHON_LIMIT = 32 * 1024 * 1024
SIGNED_RECEIPT_LIMIT = 16 * 1024
SIGNED_PYTHON_ROLES = ("python-sign", "python-verify", "python-modules", "python-loader", "python-tls", "python-cancellation")
SIGNED_ENTITLEMENTS_SHA256 = "0132721aff0bd52a1201ded4ea0234f622715d418d78b05917a191d8fe569e85"
SIGNED_OPTIONS = ("signed_python", "signing_receipt", "expected_signed_python", "expected_signing_receipt",
                  "expected_signing_source", "expected_signing_run", "expected_signing_attempt")
SIGNED_RUNTIME_BINDING = "macos-installed-inputs/python-signed-runtime-binding.json"
SIGNED_RUNTIME_BINDING_LIMIT = 4096


SIGNED_ORIGINAL_SUPPLIERS = {
    ARM_TARGET: {"receiptSha256": "2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d",
        "tarSha256": "ff7883185cf8226e9366b1ee9a3dcb3eb8ee761dbc1f697f952510a6bd858695",
        "sourceCommit": "158cdff422e3837f7ab5e6192af76a578faf6fab", "runId": "37467019389", "runAttempt": "1", "artifactId": "11415902210"},
    INTEL_TARGET: {"receiptSha256": "a46f6838afdb7c20c3539e8f65891312aa8df10e2de67e9b9e3ddbf449883b4b",
        "tarSha256": "739cc8b8b3c68daffba8d7b9cb7cb54ca730eef2c5842302ae8a2682bf64d5bd",
        "sourceCommit": "079ab2a2c8fef88f01bf909e7669c685f07e1375", "runId": "37476532238", "runAttempt": "1", "artifactId": "11419502465"},
}

def signed_python_options(args):
    values = tuple(getattr(args, name, None) for name in SIGNED_OPTIONS)
    if all(value is None for value in values):
        return False
    need(all(value is not None for value in values) and getattr(args, "archive", None) is None
         and isinstance(getattr(args, "python_root", None), Path)
         and isinstance(values[0], Path) and isinstance(values[1], Path)
         and sha(values[2]) and sha(values[3])
         and type(values[4]) is str and re.fullmatch(r"[0-9a-f]{40}", values[4]) and values[4] != "0" * 40
         and all(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in values[5:]),
         "signed-python-options")
    return True


def signed_python_receipt(body, signed, args, original, original_receipt, producer, service, entitlements):
    """Pinned derivation DATA only; booleans are never a native signature oracle."""
    need(type(body) is bytes and 0 < len(body) <= SIGNED_RECEIPT_LIMIT
         and digest(body) == args.expected_signing_receipt
         and type(signed) is bytes and 0 < len(signed) <= SIGNED_PYTHON_LIMIT
         and digest(signed) == args.expected_signed_python, "signed-python-anchors")
    selection = packaging_signing_data(producer, service, allow_unconfigured=False)
    need(digest(entitlements) == SIGNED_ENTITLEMENTS_SHA256, "signed-python-empty-entitlements")
    value = decode(body)
    keys = {"schemaVersion", "kind", "purpose", "target", "pythonVersion", "originalSupplier",
            "originalInventorySha256", "originalPython", "signedPython", "signer", "nativeEvidence",
            "originalsKnown", "sourcePost", "supplierPost", "nonimagePost", "targetRetired", "closesKnown",
            "outerExitRequired", "assurance"}
    need(type(value) is dict and set(value) == keys and type(value["schemaVersion"]) is int
         and value["schemaVersion"] == 1 and value["kind"] == SIGNED_PYTHON_KIND
         and value["purpose"] == "configured-shipping" and value["target"] == command_target(args)
         and value["pythonVersion"] == "3.14.7", "signed-python-receipt-kind")
    supplier = value["originalSupplier"]
    need(type(supplier) is dict and set(supplier) == {"receiptSha256", "tarSha256", "sourceCommit", "runId", "runAttempt", "artifactId"}
         and supplier == SIGNED_ORIGINAL_SUPPLIERS[command_target(args)]
         and supplier["receiptSha256"] == args.expected_supplier
         and digest(original_receipt) == args.expected_supplier and sha(supplier["tarSha256"])
         and type(supplier["sourceCommit"]) is str and re.fullmatch(r"[0-9a-f]{40}", supplier["sourceCommit"])
         and supplier["sourceCommit"] != "0" * 40
         and all(type(supplier[key]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", supplier[key])
                 for key in ("runId", "runAttempt", "artifactId")), "signed-python-original-supplier")
    original_rows = [{"path": name, "size": len(content), "sha256": digest(content), "mode": mode}
                     for name, (content, mode) in sorted(original.items())]
    need(value["originalInventorySha256"] == digest(canonical(original_rows)), "signed-python-original-inventory")
    before = original[SIGNED_PYTHON_PATH]
    for key, content, mode in (("originalPython", before[0], before[1]), ("signedPython", signed, 0o555)):
        row = value[key]
        need(type(row) is dict and set(row) == {"path", "size", "mode", "sha256"}
             and row["path"] == SIGNED_PYTHON_PATH and type(row["size"]) is int and row["size"] == len(content)
             and type(row["mode"]) is int and row["mode"] == mode and row["sha256"] == digest(content),
             "signed-python-one-file-correspondence")
    signer = value["signer"]
    signer_keys = {"sourceCommit", "workflow", "runId", "runAttempt", "identifier", "teamIdentifier",
                   "leafCertificateSha1", "producerProfileSha256", "serviceProfileSha256", "entitlementsSha256",
                   "codeDirectoryFlags", "timestampRequested"}
    workflow = ("Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-python-runtime-signing.yml"
                "@refs/heads/verify/desktop-macos-python-runtime-signing-shipping")
    need(type(signer) is dict and set(signer) == signer_keys
         and (signer["sourceCommit"], signer["runId"], signer["runAttempt"])
             == (args.expected_signing_source, args.expected_signing_run, args.expected_signing_attempt)
         and signer["workflow"] == workflow and signer["identifier"] == SIGNED_PYTHON_IDENTIFIER
         and signer["teamIdentifier"] == selection.team and signer["leafCertificateSha1"] == selection.leaf_sha1
         and signer["producerProfileSha256"] == digest(producer) and signer["serviceProfileSha256"] == digest(service)
         and signer["entitlementsSha256"] == SIGNED_ENTITLEMENTS_SHA256 and signer["timestampRequested"] is True,
         "signed-python-source-profile-binding")
    flags = signer["codeDirectoryFlags"]
    need(type(flags) is list and 1 <= len(flags) <= 6
         and all(type(flag) is int and 0 <= flag <= 0xffffffff and flag & 0x10002 == 0x10000 for flag in flags),
         "signed-python-runtime-flags")
    evidence = value["nativeEvidence"]
    need(type(evidence) is dict and set(evidence) == set(SIGNED_PYTHON_ROLES)
         and all(type(row) is dict and set(row) == {"stdoutSha256", "stderrSha256"}
                 and all(sha(item) for item in row.values()) for row in evidence.values()), "signed-python-evidence-roster")
    need(all(value[key] is True for key in ("originalsKnown", "sourcePost", "supplierPost", "nonimagePost",
                                           "targetRetired", "closesKnown", "outerExitRequired"))
         and value["assurance"] == "pinned-native-signature-and-probes-not-notarization-or-installed-authority",
         "signed-python-finality-contract")
    return value


def read_signed_python(args, original, original_receipt):
    need(signed_python_options(args), "signed-python-required")
    owner = packager_ids()
    captured, identities = [], []
    for path, limit, modes in ((args.signed_python, SIGNED_PYTHON_LIMIT, (0o555,)),
                               (args.signing_receipt, SIGNED_RECEIPT_LIMIT, (0o444, 0o600))):
        with parent(path) as (fd, leaf):
            body, info = read_at(fd, leaf, limit)
            need((info.st_uid, info.st_gid) == owner and stat.S_IMODE(info.st_mode) in modes,
                 "signed-python-owner-mode")
            captured.append(body)
            identities.append((signature(info), current_directory_identity(os.fstat(fd))))
    for name in ("macos-install-producer-signing.profile", "macos-android-service-signing.profile", "macos-empty-entitlements.plist"):
        with parent(DESKTOP / "packaging" / name) as (fd, leaf):
            body, info = read_at(fd, leaf, 1024)
            captured.append(body)
            identities.append((signature(info), current_directory_identity(os.fstat(fd))))
    value = signed_python_receipt(captured[1], captured[0], args, original, original_receipt, *captured[2:])
    return (*captured, tuple(identities)), value


def signed_runtime_binding_data(body, producer, service, *, target=ARM_TARGET):
    """Public SOURCE nomination, not certificate/key or native authority."""
    target = mac_target(target)
    need(type(body) is bytes and 0 < len(body) <= SIGNED_RUNTIME_BINDING_LIMIT,
         "signed-runtime-binding-size")
    value = decode(body.decode("utf-8", "strict"))
    need(type(value) is dict and set(value) == {"schemaVersion", "targets"}
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and type(value["targets"]) is dict and set(value["targets"]) == set(MAC_TARGETS),
         "signed-runtime-binding-shape")
    hashes = ("signedPythonSha256", "signingReceiptSha256", "sourceInputsSha256",
              "runtimeManifestSha256", "producerProfileSha256", "serviceProfileSha256")
    identifiers = ("signingRunId", "signingRunAttempt", "signingArtifactId")
    fields = {"state", "signingSourceCommit", *hashes, *identifiers}
    for row in value["targets"].values():
        need(type(row) is dict, "signed-runtime-binding-row")
        if row == {"state": "unconfigured"}:
            continue
        need(set(row) == fields and row["state"] == "configured"
             and maintenance_hex(row["signingSourceCommit"], 40)
             and all(maintenance_hex(row[key], 64) for key in hashes)
             and all(type(row[key]) is str and re.fullmatch(r"[1-9][0-9]{0,15}", row[key])
                     and int(row[key]) <= 9007199254740991 for key in identifiers),
             "signed-runtime-binding-row")
    chosen = value["targets"][target]
    need(chosen["state"] == "configured", "signed-runtime-unconfigured")
    selection = packaging_signing_data(producer, service)
    need((chosen["producerProfileSha256"], chosen["serviceProfileSha256"])
         == (selection.producer_sha256, selection.service_sha256), "signed-runtime-profile-binding")
    return dict(chosen)


def signed_runtime_source_snapshot():
    """Capture only three fixed SOURCE originals, not caller-nominated paths."""
    result = []
    for name, limit in ((SIGNED_RUNTIME_BINDING, SIGNED_RUNTIME_BINDING_LIMIT),
                        ("packaging/macos-install-producer-signing.profile", 1024),
                        ("packaging/macos-android-service-signing.profile", 512)):
        with parent(DESKTOP / name) as (fd, leaf):
            before = current_directory_identity(os.fstat(fd))
            body, info = read_at(fd, leaf, limit)
            need(current_directory_identity(os.fstat(fd)) == before, "signed-runtime-source-parent-changed")
            result.append((body, signature(info), before))
    return tuple(result)


def signed_runtime_inputs(target=ARM_TARGET):
    original = signed_runtime_source_snapshot()
    row = signed_runtime_binding_data(*(item[0] for item in original), target=target)
    need(signed_runtime_source_snapshot() == original, "signed-runtime-source-post-changed")
    return row, original


def runtime_signing_selection_command(args):
    target = command_target(args)
    row, original = signed_runtime_inputs(target)
    result = {"schemaVersion": 1, "kind": "configured-signed-runtime-selection-data", "target": target,
              "nominationSha256": digest(original[0][0]), **row, "nativeAuthority": False}
    need(len(canonical(result)) + 1 <= SIGNED_RUNTIME_BINDING_LIMIT, "signed-runtime-selection-bound")
    return result


def project_signed_python_command(args):
    """Normalize only the exact downloaded capsule pair; never execute it."""
    target = command_target(args)
    owner = packager_ids()
    binding = signed_runtime_inputs(target)
    chosen, source = binding
    fold = lambda path: tuple(part.casefold() for part in path.parts)
    paths = (args.transport_root, args.output, DESKTOP.parent)
    need(all(isinstance(path, Path) and path.is_absolute() for path in paths), "signed-transport-paths")
    for index, path in enumerate(paths):
        a = fold(path)
        for other in paths[:index]:
            b = fold(other)
            need(a[:len(b)] != b and b[:len(a)] != a, "signed-transport-overlap")
    output_parent = current_output_absent(args.output)
    names = ("python-signed-receipt.json", "python3")
    limits = {"python3": SIGNED_PYTHON_LIMIT, "python-signed-receipt.json": SIGNED_RECEIPT_LIMIT}
    expected = {"python3": chosen["signedPythonSha256"],
                "python-signed-receipt.json": chosen["signingReceiptSha256"]}
    with parent(args.transport_root) as (outer, leaf):
        outer_identity = current_directory_identity(os.fstat(outer))
        before = os.stat(leaf, dir_fd=outer, follow_symlinks=False)
        need(stat.S_ISDIR(before.st_mode) and (before.st_uid, before.st_gid) == owner
             and stat.S_IMODE(before.st_mode) in (0o700, 0o755), "signed-transport-root")
        root = os.open(leaf, READ_FLAGS | os.O_DIRECTORY, dir_fd=outer)
        try:
            def snapshot():
                need(signature(os.fstat(root)) == signature(before)
                     and signature(os.stat(leaf, dir_fd=outer, follow_symlinks=False)) == signature(before)
                     and current_directory_identity(os.fstat(outer)) == outer_identity,
                     "signed-transport-root-changed")
                no_xattrs(root)
                need(sorted(os.listdir(root)) == list(names), "signed-transport-roster")
                files, originals = {}, {}
                for name in names:
                    body, info = read_at(root, name, limits[name])
                    need((info.st_uid, info.st_gid) == owner and stat.S_IMODE(info.st_mode) in (0o400, 0o600, 0o644)
                         and len(body) > 0 and digest(body) == expected[name], "signed-transport-file")
                    files[name] = (body, 0o555 if name == "python3" else 0o444)
                    originals[name] = signature(info)
                need(signature(os.fstat(root)) == signature(before)
                     and signature(os.stat(leaf, dir_fd=outer, follow_symlinks=False)) == signature(before)
                     and sorted(os.listdir(root)) == list(names), "signed-transport-post-changed")
                return files, originals

            need(signature(os.fstat(root)) == signature(before), "signed-transport-open-changed")
            captured = snapshot()
            current_output_absent(args.output, output_parent)
            write_tree(args.output, captured[0], current_owned=True)
            need(snapshot() == captured and signed_runtime_inputs(target) == binding,
                 "signed-transport-publication-post-changed")
        finally:
            close_once(root)
    # Reopen the fixed root name after closing the held root/ancestors, too.
    with parent(args.transport_root) as (fd, name):
        need(current_directory_identity(os.fstat(fd)) == outer_identity
             and signature(os.stat(name, dir_fd=fd, follow_symlinks=False)) == signature(before),
             "signed-transport-final-name-changed")
    return {"schemaVersion": 1, "target": target, "nominationSha256": digest(source[0][0]),
            "signedPythonSha256": chosen["signedPythonSha256"],
            "signingReceiptSha256": chosen["signingReceiptSha256"], "files": 2,
            "qualification": "configured-capsule-DATA-projection-not-signature-or-installed-authority"}


def configured_current_binding(args, target):
    need(args.command == "current-runtime" and signed_python_options(args), "configured-signing-required")
    binding = signed_runtime_inputs(target)
    chosen = binding[0]
    pairs = (("expected_signed_python", "signedPythonSha256"), ("expected_signing_receipt", "signingReceiptSha256"),
             ("expected_signing_source", "signingSourceCommit"), ("expected_signing_run", "signingRunId"),
             ("expected_signing_attempt", "signingRunAttempt"), ("expected_source", "sourceInputsSha256"),
             ("expected_manifest", "runtimeManifestSha256"))
    need(all(getattr(args, option, None) == chosen[key] for option, key in pairs)
         and args.expected_supplier == SIGNED_ORIGINAL_SUPPLIERS[target]["receiptSha256"],
         "configured-signing-source-arguments")
    return binding


def current_source():
    """Capture DATA, including the committed CA's one explicit projection map."""
    source = DESKTOP.parent
    core = tree(source / "src/mobile_release", max_bytes=CURRENT_CORE_BYTES)
    need(core and all(Path(name).suffix in {".py", ".json", ".pem"} for name in core), "current-core-inputs")
    need({"__init__.py", "_desktop_engine.py"} <= set(core), "current-core-required-inputs")
    need(digest(core["_desktop_engine.py"][0]) == CURRENT_PROTOCOL, "current-protocol-source")
    captured = {"src/mobile_release/" + name: value for name, value in core.items()}
    fixed = {"desktop/" + name: 64 * 1024 for name in CURRENT_BOOTSTRAPS}
    fixed[CURRENT_CA_SOURCE] = 512 * 1024
    fixed[CURRENT_HELPER_SOURCE] = 64 * 1024
    for name, limit in sorted(fixed.items()):
        with parent(source / name) as (fd, leaf):
            body, info = read_at(fd, leaf, limit)
        captured[name] = (body, stat.S_IMODE(info.st_mode))
    need(captured[CURRENT_CA_SOURCE][0], "current-ca-empty")
    rows = [{"path": name, "size": len(body), "sha256": digest(body)}
            for name, (body, _) in sorted(captured.items())]
    projection = {}
    for name, (body, _) in captured.items():
        if name != CURRENT_HELPER_SOURCE:
            target = "desktop/github-ca.pem" if name == CURRENT_CA_SOURCE else name
            need(target not in projection, "current-source-projection-collision")
            projection[target] = (body, 0o444)
    directories(projection)
    return captured, projection, digest(canonical(rows))


def current_directory_identity(info):
    # Child creation legitimately changes a directory's nlink/times. Preserve
    # its original object/owner/mode, then take stable full snapshots at POST.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def current_output_absent(path, expected_parent=None):
    owner = packager_ids()
    with parent(path) as (fd, leaf):
        info = os.fstat(fd)
        need((info.st_uid, info.st_gid) == owner and stat.S_IMODE(info.st_mode) == 0o700,
             "current-output-parent-owner-mode")
        no_xattrs(fd)
        identity = current_directory_identity(info)
        need(expected_parent is None or identity == expected_parent, "current-output-parent-changed")
        try:
            os.stat(leaf, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return identity
        raise Refused("current-output-occupied")


def current_paths(args):
    outputs = [args.work] + ([args.output] if args.command == "current-runtime" else [])
    origin = current_supplier_origin(args)
    inputs = [DESKTOP.parent] + ([args.archive] if origin == "historical"
                                else [args.python_root, args.supplier_receipt])
    if signed_python_options(args):
        inputs.extend((args.signed_python, args.signing_receipt))
    # Components are later admitted without following links. Case folding also
    # refuses an alias on default case-insensitive Mac filesystems.
    folded = lambda path: tuple(part.casefold() for part in path.parts)
    for index, output in enumerate(outputs):
        a = folded(output)
        for other in inputs + outputs[:index]:
            b = folded(other)
            need(a[:len(b)] != b and b[:len(a)] != a, "current-path-overlap")
    return {path: current_output_absent(path) for path in outputs}


@contextlib.contextmanager
def current_work_root(path, expected_parent):
    current_output_absent(path, expected_parent)
    with parent(path) as (outer, leaf):
        need(current_directory_identity(os.fstat(outer)) == expected_parent, "current-output-parent-changed")
        os.mkdir(leaf, 0o700, dir_fd=outer)
        before = os.stat(leaf, dir_fd=outer, follow_symlinks=False)
        original = os.open(leaf, READ_FLAGS | os.O_DIRECTORY, dir_fd=outer)
        try:
            need(signature(os.fstat(original)) == signature(before)
                 and (before.st_uid, before.st_gid) == packager_ids()
                 and stat.S_IMODE(before.st_mode) == 0o700, "current-work-root-identity")
            no_xattrs(original)
            os.fsync(original)
            os.fsync(outer)
            yield
            post = os.fstat(original)
            need(current_directory_identity(post) == current_directory_identity(before)
                 and sorted(os.listdir(original)) == ["runtime", "source"], "current-work-root-changed")
            os.fsync(original)
            os.fsync(outer)
            need(signature(os.fstat(original)) == signature(post)
                 and signature(os.stat(leaf, dir_fd=outer, follow_symlinks=False)) == signature(post),
                 "current-work-root-post-changed")
        finally:
            close_once(original)


def current_preparer(captured):
    # This fixed reviewed publisher helper is code; source/core/payload files
    # remain DATA. Its import is covered by the separate COMMAND admission.
    path = DESKTOP.parent / CURRENT_HELPER_SOURCE
    expected = captured[CURRENT_HELPER_SOURCE][0]
    need(read(path, 64 * 1024) == expected, "current-helper-changed")
    try:
        spec = importlib.util.spec_from_file_location("mrk_macos_current_runtime_preparer", path)
        need(spec is not None and spec.loader is not None, "current-helper-loader")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except (ImportError, AttributeError, SyntaxError) as error:
        raise Refused("current-helper-loader") from error
    need(read(path, 64 * 1024) == expected, "current-helper-changed")
    return module


def current_core_matches(body, projection):
    expected = {name[len("src/"):]: content for name, (content, _) in projection.items()
                if name.startswith("src/mobile_release/")}
    need(len(body) <= CURRENT_CORE_BYTES + MAX_FILES * 2048, "current-core-archive-bound")
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        rows = archive.infolist()
        need([row.filename for row in rows] == sorted(expected), "current-core-complete-roster")
        for row in rows:
            content = expected[row.filename]
            need(not row.flag_bits & 1 and row.file_size == len(content)
                 and row.compress_type == zipfile.ZIP_DEFLATED
                 and row.date_time == (1980, 1, 1, 0, 0, 0)
                 and row.create_system == 3 and row.external_attr == (stat.S_IFREG | 0o644) << 16,
                 "current-core-member-shape")
            with archive.open(row) as stream:
                need(stream.read(len(content) + 1) == content, "current-core-byte-correspondence")


def current_runtime_files(runtime, projection, supplier, *, target=ARM_TARGET):
    target = mac_target(target)
    files = tree(runtime, current_root_mode=0o700)
    required = set(supplier) | CURRENT_BOOTSTRAPS | {"core.zip", "github-ca.pem", "manifest.json"}
    need(set(files) == required, "current-runtime-complete-roster")
    for name, value in supplier.items():
        need(files[name] == value, "current-supplier-changed")
    for name in required - set(supplier):
        need(files[name][1] == 0o600, "current-generated-mode")
    manifest_body = files["manifest.json"][0]
    manifest, rows = manifest_files(manifest_body, digest(manifest_body), current=True, target=target)
    need(set(rows) | {"manifest.json"} == set(files), "current-runtime-manifest-roster")
    for name, row in rows.items():
        need(row["size"] == len(files[name][0]) and row["sha256"] == digest(files[name][0]),
             "current-runtime-manifest-correspondence")
    for name in CURRENT_BOOTSTRAPS | {"github-ca.pem"}:
        need(files[name][0] == projection["desktop/" + name][0], "current-entrypoint-byte-correspondence")
    current_core_matches(files["core.zip"][0], projection)
    return files, manifest


def current_runtime_command(args):
    target = command_target(args)
    configured = getattr(args, "configured_signing", False)
    need(type(configured) is bool, "configured-signing-option")
    configured_inputs = configured_current_binding(args, target) if configured else None
    origin = current_supplier_origin(args)
    need(origin == "fresh-public-source" or target == ARM_TARGET, "unqualified-intel-route")
    selection = source_build_selection(target)
    packager_ids()
    need(args.command in ("describe-current-runtime", "current-runtime"), "current-runtime-command")
    final = args.command == "current-runtime"
    if final:
        need(sha(args.expected_source) and sha(args.expected_manifest), "current-reviewed-digests")
    parents = current_paths(args)
    captured, projection, source_digest = current_source()
    if final:
        need(source_digest == args.expected_source, "current-reviewed-source-mismatch")
    fresh_inputs = None
    if origin == "fresh-public-source":
        fresh_inputs = fresh_supplier(args)
        supplier, provenance = fresh_inputs[:2]
    else:
        historical, previous = reused_runtime(args.archive)
        supplier = {name: (body, 0o555 if name == "python/bin/python3" else 0o444)
                    for name, body in historical.items() if name.startswith("python/")}
        del historical
        provenance = {"acceptedArchiveSha256": previous["acceptedArchiveSha256"],
                      "acceptedTarSha256": previous["acceptedTarSha256"],
                      "originalManifestSha256": previous["originalManifestSha256"],
                      "supplierOnlyReuse": True, "addedNotices": previous["addedNotices"]}
    need("python/bin/python3" in supplier, "current-supplier-missing")
    supplier_rows = [{"path": name, "size": len(body), "sha256": digest(body), "mode": mode}
                     for name, (body, mode) in sorted(supplier.items())]
    signed_inputs = None
    if signed_python_options(args):
        need(fresh_inputs is not None, "signed-python-fresh-only")
        signed_inputs, _signed_receipt = read_signed_python(args, supplier, fresh_inputs[3])
        supplier = dict(supplier)
        provenance = dict(provenance)
        supplier[SIGNED_PYTHON_PATH] = (signed_inputs[0], 0o555)
        provenance.update(signedPythonSha256=args.expected_signed_python, signingReceiptSha256=args.expected_signing_receipt,
                          signingPurpose="configured-shipping-derivation-DATA-not-install-authority")
    preparer = current_preparer(captured)
    with current_work_root(args.work, parents[args.work]):
        source, runtime = args.work / "source", args.work / "runtime"
        write_tree(source, projection, current_owned=True)
        write_tree(runtime, supplier, root_mode=0o700, current_owned=True)
        old_mask = os.umask(0o077)
        try:
            prepared = preparer.prepare_current(source, runtime, target)
        finally:
            os.umask(old_mask)
        files, manifest = current_runtime_files(runtime, projection, supplier, target=target)
        manifest_digest = digest(files["manifest.json"][0])
        need(prepared == {"manifestSha256": manifest_digest, "protocolSha256": CURRENT_PROTOCOL,
                          "qualification": "prepared-not-native-verified"}, "current-preparer-result")
        need(tree(source, current_root_mode=0o555) == projection and current_source() == (captured, projection, source_digest),
             "current-source-post-changed")
        if fresh_inputs is not None:
            need(fresh_supplier(args) == fresh_inputs, "fresh-supplier-post-changed")
        if signed_inputs is not None:
            need(read_signed_python(args, fresh_inputs[0], fresh_inputs[3])[0] == signed_inputs, "signed-python-post-changed")
        if configured_inputs is not None:
            need(signed_runtime_inputs(target) == configured_inputs, "configured-signing-source-post-changed")
        core = [body for name, (body, _) in captured.items() if name.startswith("src/mobile_release/")]
        result = {"schemaVersion": 1, "release": selection.release, "target": target,
                  **provenance,
                  "successorManifestSha256": manifest_digest, "protocolSha256": CURRENT_PROTOCOL,
                  "inventorySha256": manifest["inventorySha256"], "coreSha256": manifest["coreSha256"],
                  "sourceInputsSha256": source_digest, "sourceInputCount": len(captured),
                  "supplierInventorySha256": digest(canonical(supplier_rows)), "supplierFileCount": len(supplier),
                  "currentCoreFileCount": len(core), "currentCoreBytes": sum(map(len, core)),
                  "qualification": "current-source-description-only-not-build-or-install-authority"}
        if configured_inputs is not None:
            chosen, snapshot = configured_inputs
            result.update(signedRuntimeBindingSha256=digest(snapshot[0][0]),
                          signingSourceCommit=chosen["signingSourceCommit"], signingRunId=chosen["signingRunId"],
                          signingRunAttempt=chosen["signingRunAttempt"], signingArtifactId=chosen["signingArtifactId"])
        if final:
            need(manifest_digest == args.expected_manifest, "current-reviewed-manifest-mismatch")
            current_output_absent(args.output, parents[args.output])
            normalized = {name: (body, 0o555 if name == "python/bin/python3" else 0o444)
                          for name, (body, _) in files.items()}
            write_tree(args.output, normalized, current_owned=True)
            result["qualification"] = "current-source-staged-no-native-execution"
        if signed_inputs is not None:
            need(fresh_supplier(args) == fresh_inputs
                 and read_signed_python(args, fresh_inputs[0], fresh_inputs[3])[0] == signed_inputs,
                 "signed-python-publication-post-changed")
        if configured_inputs is not None:
            need(signed_runtime_inputs(target) == configured_inputs, "configured-signing-publication-post-changed")
        return result


def macho(body, *, system_only=False, target=ARM_TARGET):
    expected_cpu, expected_subtype = target_machine(target)
    need(len(body) >= 32, "macho-header")
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from("<8I", body)
    need(magic == 0xFEEDFACF and cpu == expected_cpu and subtype == expected_subtype and kind == 2 and count <= 128
         and size <= 65536 and 32 + size <= len(body), "macho-target")
    offset = 32
    minimum = []
    for _ in range(count):
        need(offset + 8 <= 32 + size, "macho-command")
        command, length = struct.unpack_from("<II", body, offset)
        need(length >= 8 and length % 8 == 0 and offset + length <= 32 + size, "macho-command-bound")
        if system_only and command in (0x8000001C, 0x27, 0x6, 0x7, 0xD, 0xF, 0x10, 0x12, 0x13, 0x14, 0x15):
            need(False, "helper-loader-override-refused")
        if system_only and command == 0xE:
            need(length >= 16, "helper-dyld-command")
            start = struct.unpack_from("<I", body, offset + 8)[0]
            need(12 <= start < length, "helper-dyld-offset")
            raw = body[offset + start:offset + length]
            need(b"\0" in raw, "helper-dyld-terminated")
            name, padding = raw.split(b"\0", 1)
            need(name == b"/usr/lib/dyld" and not any(padding), "helper-system-dyld-only")
        if system_only and command in (0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023):
            need(length >= 24, "helper-dylib-command")
            start = struct.unpack_from("<I", body, offset + 8)[0]
            need(24 <= start < length, "helper-dylib-name-offset")
            raw = body[offset + start:offset + length]
            need(b"\0" in raw, "helper-dylib-terminated")
            name, padding = raw.split(b"\0", 1)
            need(name.startswith((b"/System/Library/", b"/usr/lib/"))
                 and all(32 < b < 127 for b in name) and all(part not in (b"", b".", b"..") for part in name.split(b"/")[1:])
                 and not any(padding), "helper-absolute-apple-system-dependency")
        if command == 0x32:
            need(length >= 24, "macho-build-version")
            platform, version = struct.unpack_from("<II", body, offset + 8)
            minimum.append((platform, version))
        offset += length
    need(offset == 32 + size and minimum == [(1, 26 << 16)], "macho-minimum-macos26")


def entry_macho(body, *, target=ARM_TARGET):
    """Closed C-entry loader policy; never execute it or infer a held lock."""
    macho(body, system_only=True, target=target)
    _magic, _cpu, _subtype, _kind, count, size, flags, _reserved = struct.unpack_from("<8I", body)
    need(flags & (0x4 | 0x80 | 0x200000) == (0x4 | 0x80 | 0x200000)
         and not flags & 0x20000, "entry-pie-no-executable-stack")
    # Exact ordinary clang/linker/code-signing command types. No rpath, dylinker
    # environment, routines, reexport/weak/lazy library, or unknown load command.
    allowed = {0x19, 0x2, 0xB, 0xE, 0xC, 0x1B, 0x32, 0x2A, 0x80000028,
               0x26, 0x29, 0x1D, 0x2E, 0x80000022, 0x80000033, 0x80000034}
    offset, libraries, dylinkers, mains = 32, [], [], 0
    for _ in range(count):
        command, length = struct.unpack_from("<II", body, offset)
        need(command in allowed, "entry-loader-command")
        if command in (0xC, 0xE):
            minimum = 24 if command == 0xC else 12
            need(length >= minimum, "entry-library-command")
            start = struct.unpack_from("<I", body, offset + 8)[0]
            need(minimum <= start < length, "entry-library-offset")
            raw = body[offset + start:offset + length]
            need(b"\0" in raw, "entry-library-termination")
            name, padding = raw.split(b"\0", 1)
            need(not any(padding), "entry-library-padding")
            (libraries if command == 0xC else dylinkers).append(name)
        elif command == 0x19:
            need(length >= 72, "entry-segment-command")
            sections = struct.unpack_from("<I", body, offset + 64)[0]
            need(sections <= 256 and length == 72 + 80 * sections, "entry-segment-sections")
            for index in range(sections):
                section = offset + 72 + 80 * index
                name = body[section:section + 16].split(b"\0", 1)[0]
                kind = struct.unpack_from("<I", body, section + 64)[0] & 0xFF
                need(kind not in (0x9, 0xA, 0x15)
                     and name not in (b"__mod_init_func", b"__mod_term_func", b"__init_offsets"),
                     "entry-native-initializer")
        elif command == 0x80000028:
            need(length == 24, "entry-main-command")
            mains += 1
        offset += length
    need(offset == 32 + size and libraries == [b"/usr/lib/libSystem.B.dylib"]
         and dylinkers == [b"/usr/lib/dyld"] and mains == 1, "entry-libsystem-only")



def package_role(value):
    """A fixed trusted-caller role, never inferred from inventory/image absence."""
    need(type(value) is str and value in PACKAGE_ROLES, "package-role")
    return value


def image_macho(body, role, *, target=ARM_TARGET):
    """Closed MH_DYLIB DATA; executable names or signatures do not change kind."""
    expected_cpu, expected_subtype = target_machine(target)
    need(role in IMAGE_INSTALL_NAMES and type(body) is bytes and len(body) >= 32, "image-role-header")
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from("<8I", body)
    need(magic == 0xFEEDFACF and cpu == expected_cpu and subtype == expected_subtype and kind == 6 and reserved == 0
         and 0 < count <= 128 and size <= 65536 and 32 + size <= len(body)
         and flags & (0x4 | 0x80) == (0x4 | 0x80) and not flags & 0x20000,
         "image-dylib-target")
    # No LC_MAIN/dyld/rpath/environment, weak/reexport/lazy/upward library,
    # routines, search path or unknown loader command. Product initialization
    # belongs only in the loaded image, never either libSystem-only facade.
    allowed = {0x19, 0x2, 0xB, 0xC, 0xD, 0x1B, 0x32, 0x2A,
               0x26, 0x29, 0x1D, 0x2E, 0x80000022, 0x80000033, 0x80000034}
    offset, identifiers, libraries, minimum = 32, [], [], []
    for _ in range(count):
        need(offset + 8 <= 32 + size, "image-command")
        command, length = struct.unpack_from("<II", body, offset)
        need(command in allowed and length >= 8 and length % 8 == 0
             and offset + length <= 32 + size, "image-loader-command")
        if command in (0xC, 0xD):
            need(length >= 24, "image-library-command")
            start = struct.unpack_from("<I", body, offset + 8)[0]
            need(24 <= start < length, "image-library-offset")
            raw = body[offset + start:offset + length]
            need(b"\0" in raw, "image-library-termination")
            name, padding = raw.split(b"\0", 1)
            need(not any(padding), "image-library-padding")
            if command == 0xD:
                identifiers.append(name)
            else:
                need(name.startswith((b"/System/Library/", b"/usr/lib/"))
                     and all(32 < byte < 127 for byte in name)
                     and all(part not in (b"", b".", b"..") for part in name.split(b"/")[1:]),
                     "image-absolute-apple-system-dependency")
                libraries.append(name)
        elif command == 0x19:
            need(length >= 72, "image-segment-command")
            sections = struct.unpack_from("<I", body, offset + 64)[0]
            need(sections <= 256 and length == 72 + 80 * sections, "image-segment-sections")
        elif command == 0x32:
            need(length >= 24, "image-build-version")
            minimum.append(struct.unpack_from("<II", body, offset + 8))
        offset += length
    need(offset == 32 + size and minimum == [(1, 26 << 16)]
         and identifiers == [IMAGE_INSTALL_NAMES[role].encode("ascii")]
         and len(libraries) == len(set(libraries))
         and libraries.count(b"/usr/lib/libSystem.B.dylib") == 1, "image-fixed-install-name-and-system-closure")


def cargo_records(messages):
    need(type(messages) is bytes and 0 < len(messages) <= 8 * 1024 * 1024
         and messages.endswith(b"\n"), "image-cargo-messages-bound")
    lines = messages.splitlines()
    need(1 < len(lines) <= 10000 and all(lines), "image-cargo-record-count")
    records, finished = [], False
    for line in lines:
        need(not finished, "image-cargo-after-finish")
        item = decode(line)
        need(type(item) is dict and item.get("reason") in
             ("compiler-artifact", "compiler-message", "build-script-executed", "build-finished"),
             "image-cargo-record-kind")
        if item["reason"] == "build-finished":
            need(set(item) == {"reason", "success"} and item["success"] is True, "image-cargo-not-successful")
            finished = True
        elif item["reason"] == "compiler-artifact":
            need(type(item.get("target")) is dict and type(item.get("filenames")) is list
                 and all(type(value) is str for value in item["filenames"]), "image-cargo-target-shape")
            records.append(item)
    need(finished, "image-cargo-terminal-success")
    return records


def cargo_profile(row, *, test):
    profile = row.get("profile")
    need(type(profile) is dict and profile.get("test") is test
         and profile.get("debug_assertions") is test
         and profile.get("opt_level") == ("0" if test else "3"), "image-cargo-profile")
    need(type(row.get("fresh")) is bool, "image-cargo-fresh-field")


def cargo_features(row, expected):
    features = row.get("features")
    need(type(features) is list and all(type(value) is str for value in features)
         and sorted(features) == sorted(expected), "image-cargo-exact-features")


def cargo_library(records, directory, package, name, features, *, test):
    selected = [row for row in records if row["target"].get("name") == name]
    need(len(selected) == 1, "image-cargo-one-library")
    row = selected[0]
    need(row.get("package_id") == "path+" + directory.as_uri() + "#" + package + ("@0.1.1" if package == "mobile-release-kit-desktop" else "@0.1.0")
         and row.get("manifest_path") == str(directory / "Cargo.toml")
         and row["target"].get("kind") == ["lib"] and row["target"].get("crate_types") == ["lib"]
         and row["target"].get("src_path") == str(directory / "src/lib.rs")
         and row["target"].get("edition") == "2021"
         and "executable" in row and row["executable"] is None, "image-cargo-source-library")
    cargo_profile(row, test=test)
    cargo_features(row, features)


def image_cargo_artifact(messages, binary, target_dir, body, role, *, target=ARM_TARGET):
    target = mac_target(target)
    need(role in ("desktop", "resident"), "image-cargo-role")
    name = "mrk_desktop_image" if role == "desktop" else "mrk_resident_image"
    package = "mrk-desktop-image" if role == "desktop" else "mrk-android-register"
    root = DESKTOP / "helpers" / ("macos-desktop-image" if role == "desktop" else "macos-android-register")
    target_dir, binary = Path(target_dir), Path(binary)
    need(target_dir.is_absolute() and binary.is_absolute()
         and all(part not in (".", "..") for part in target_dir.parts + binary.parts), "image-cargo-absolute-path")
    expected = target_dir / target / "release" / ("lib" + name + ".dylib")
    need(binary == expected and type(body) is bytes and 32 <= len(body) <= MAX_BYTES, "image-cargo-release-output")
    records = cargo_records(messages)
    selected = [row for row in records if row["target"].get("name") == name
                or str(expected) in row.get("filenames", []) or row.get("executable") == str(expected)]
    need(len(selected) == 1, "image-cargo-unique-cdylib")
    row = selected[0]
    cargo_target = row["target"]
    need(row.get("package_id") == "path+" + root.as_uri() + "#" + package + "@0.1.0"
         and row.get("manifest_path") == str(root / "Cargo.toml")
         and cargo_target.get("name") == name and cargo_target.get("kind") == ["cdylib"]
         and cargo_target.get("crate_types") == ["cdylib"] and cargo_target.get("src_path") == str(root / "src/lib.rs")
         and cargo_target.get("edition") == "2021" and "executable" in row and row["executable"] is None
         and row.get("filenames") == [str(expected)], "image-cargo-cdylib-source")
    cargo_profile(row, test=False)
    cargo_features(row, [])
    app_features = (["custom-protocol", "desktop-shell", "macos-installed-desktop-image"] if role == "desktop"
                    else ["macos-android-registration-helper", "macos-installed-resident-image"])
    native_features = (["default", "desktop-image"] if role == "desktop"
                       else ["android-registration-helper", "default", "resident-image"])
    cargo_library(records, DESKTOP / "src-tauri", "mobile-release-kit-desktop",
                  "mobile_release_desktop", app_features, test=False)
    cargo_library(records, DESKTOP / "native/macos-installed-native", "mrk-macos-installed-native",
                  "mrk_macos_installed_native", native_features, test=False)
    need(not any(item["target"].get("kind") in (["bin"], ["test"], ["example"], ["bench"])
                 or item is not row and item["target"].get("kind") == ["cdylib"]
                 for item in records), "image-cargo-no-executable-role")
    image_macho(body, role, target=target)
    return {"schemaVersion": 1, "entrypoint": "src/lib.rs", "targetKind": "cdylib", "imageRole": role,
            "package": package, "crate": name, "target": target, "profileTest": False,
            "features": [], "appFeatures": app_features, "nativeFeatures": native_features,
            "cargoMessagesSha256": digest(messages), "binarySha256": digest(body), "binarySize": len(body),
            "instrumented": False, "qualification": "actual-cdylib-data-not-launched"}


def observer_cargo_artifact(messages, binary, target_dir, body, *, target=ARM_TARGET):
    target = mac_target(target)
    root, name = DESKTOP / "src-tauri", "installed-shell-observation"
    binary, target_dir = Path(binary), Path(target_dir)
    need(binary.is_absolute() and target_dir.is_absolute()
         and all(part not in (".", "..") for part in binary.parts + target_dir.parts)
         and binary.parent == target_dir / target / "debug/deps"
         and re.fullmatch(r"installed_shell_observation-[0-9a-f]+", binary.name) is not None,
         "observer-cargo-fixed-output")
    records = cargo_records(messages)
    selected = [row for row in records if row["target"].get("name") == name or row.get("executable") == str(binary)]
    need(len(selected) == 1, "observer-cargo-one-test")
    row = selected[0]
    cargo_target = row["target"]
    features = ["custom-protocol", "desktop-shell", "macos-installed-observation"]
    need(row.get("package_id") == "path+" + root.as_uri() + "#mobile-release-kit-desktop@0.1.1"
         and row.get("manifest_path") == str(root / "Cargo.toml")
         and cargo_target.get("name") == name and cargo_target.get("kind") == ["test"]
         and cargo_target.get("crate_types") == ["bin"]
         and cargo_target.get("src_path") == str(root / "tests/installed_shell_observation.rs")
         and cargo_target.get("edition") == "2021" and row.get("executable") == str(binary)
         and row.get("filenames") == [str(binary)], "observer-cargo-source-test")
    cargo_profile(row, test=True)
    cargo_features(row, features)
    # A --test build compiles the ordinary dependency library, not a libtest
    # library. Its code is dev/opt0 but profile.test is false.
    app = [item for item in records if item["target"].get("name") == "mobile_release_desktop"]
    native = [item for item in records if item["target"].get("name") == "mrk_macos_installed_native"]
    for selected_library, directory, package, expected_features in (
        (app, root, "mobile-release-kit-desktop", features),
        (native, DESKTOP / "native/macos-installed-native", "mrk-macos-installed-native", ["default", "installed-observation"]),
    ):
        need(len(selected_library) == 1, "observer-cargo-one-library")
        item = selected_library[0]
        need(item.get("package_id") == "path+" + directory.as_uri() + "#" + package + ("@0.1.1" if package == "mobile-release-kit-desktop" else "@0.1.0")
             and item.get("manifest_path") == str(directory / "Cargo.toml")
             and item["target"].get("src_path") == str(directory / "src/lib.rs")
             and item["target"].get("kind") == ["lib"] and item["target"].get("crate_types") == ["lib"]
             and item["target"].get("edition") == "2021"
             and "executable" in item and item["executable"] is None
             and type(item.get("profile")) is dict and item["profile"].get("test") is False
             and item.get("profile", {}).get("debug_assertions") is True
             and item.get("profile", {}).get("opt_level") == "0"
             and type(item.get("fresh")) is bool, "observer-cargo-source-library")
        cargo_features(item, expected_features)
    need(not any(item["target"].get("kind") in (["cdylib"], ["bin"], ["example"], ["bench"])
                 or item is not row and item["target"].get("kind") == ["test"]
                 for item in records), "observer-cargo-no-image-or-bin")
    macho(body, target=target)
    return {"schemaVersion": 1, "entrypoint": "tests/installed_shell_observation.rs", "targetKind": "test",
            "target": target, "profileTest": True, "features": features,
            "cargoMessagesSha256": digest(messages), "binarySha256": digest(body), "binarySize": len(body),
            "instrumented": True, "qualification": "observer-executable-data-not-image-or-launched"}


def remover_cargo_artifact(messages, binary, target_dir, body, *, target=ARM_TARGET):
    """Actual fixed remover graph DATA; not signing, execution or install authority."""
    target = mac_target(target)
    root = DESKTOP / "src-tauri"
    binary, target_dir = Path(binary), Path(target_dir)
    need(binary.is_absolute() and target_dir.is_absolute()
         and all(part not in (".", "..") for part in binary.parts + target_dir.parts)
         and binary == target_dir / target / "release" / REMOVER_NAME
         and type(body) is bytes and 32 <= len(body) <= REMOVER_BYTES, "remover-cargo-fixed-output")
    records = cargo_records(messages)
    selected = [row for row in records if row["target"].get("name") == REMOVER_NAME
                or str(binary) in row.get("filenames", []) or row.get("executable") == str(binary)]
    need(len(selected) == 1, "remover-cargo-one-binary")
    row = selected[0]
    role = row["target"]
    need(row.get("package_id") == "path+" + root.as_uri() + "#mobile-release-kit-desktop@0.1.1"
         and row.get("manifest_path") == str(root / "Cargo.toml") and role.get("name") == REMOVER_NAME
         and role.get("kind") == ["bin"] and role.get("crate_types") == ["bin"]
         and role.get("src_path") == str(root / "src/bin/macos_install.rs") and role.get("edition") == "2021"
         and row.get("executable") == str(binary) and row.get("filenames") == [str(binary)], "remover-cargo-source")
    cargo_profile(row, test=False)
    cargo_features(row, ["macos-installed-remover"])
    cargo_library(records, root, "mobile-release-kit-desktop", "mobile_release_desktop", ["macos-installed-remover"], test=False)
    cargo_library(records, DESKTOP / "native/macos-installed-native", "mrk-macos-installed-native",
                  "mrk_macos_installed_native", ["default"], test=False)
    need(not any(item is not row and item["target"].get("kind") in
                 (["bin"], ["test"], ["example"], ["bench"], ["cdylib"]) for item in records), "remover-cargo-no-mixed-role")
    macho(body, target=target)
    return {"schemaVersion": 1, "entrypoint": "src/bin/macos_install.rs", "targetKind": "bin",
            "binaryRole": REMOVER_NAME, "target": target, "features": ["macos-installed-remover"],
            "cargoMessagesSha256": digest(messages), "binarySha256": digest(body), "binarySize": len(body),
            "qualification": "actual-remover-data-not-signed-or-launched"}


def removal_package_receipt_data(body, *, selection, binding, package, descriptor, signed, expected_descriptor,
                                 final_package_sha, release_body, profiles):
    """Closed prior Remove emission correspondence. Caller retains original0 separately."""
    selection = selected_build(selection)
    source = packaging_signing_data(*profiles)
    need(source is not None and type(final_package_sha) is str and maintenance_hex(final_package_sha, 64),
         "remove-owner-source")
    value = maintenance_json(body, 16384)
    maintenance_map(value, ("schemaVersion", "phase", "target", "source", "packageRole", "workflowSource", "workflow", "runId", "runAttempt",
        "toolchain", "helperIdentifier", "originalCalls", "credentialOriginals", "credentialContexts", "targetRetired", "originalClosesKnown",
        "passed", "outerFinalityRequired", "androidServiceAuthenticated", "androidRegisteredCopyQualified", "androidBuildQualified",
        "developerIdOrNotarizationQualified", "productReady", "finalPackageReceiptSha256", "removalDistribution", "directStagerIOPending",
        "cleanupErrors", "imageSourceCommit", "imageReleaseId", "imageReleaseSourceSha256"), "remove-owner-fields")
    workflow = "Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-installed.yml@refs/heads/verify/desktop-macos-preview"
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["phase"] == "package-remove"
         and value["target"] == selection.target and value["source"] == value["workflowSource"] == binding["source"]
         and maintenance_hex(value["source"], 40) and value["workflow"] == workflow
         and value["runId"] == binding["runId"] and value["runAttempt"] == binding["runAttempt"]
         and all(type(value[key]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value[key]) for key in ("runId", "runAttempt"))
         and value["packageRole"] == "ordinary-image" and value["imageSourceCommit"] == value["source"]
         and value["imageReleaseId"] == selection.release and value["imageReleaseSourceSha256"] == digest(release_body)
         and value["toolchain"] == ("1.98.0" if selection.target == INTEL_TARGET else "1.98.1")
         and value["helperIdentifier"] == "dev.mobile-release-kit.desktop.android-register", "remove-owner-current-source")
    need(all(value[key] is True for key in ("targetRetired", "originalClosesKnown", "passed", "outerFinalityRequired"))
         and all(value[key] is False for key in ("androidServiceAuthenticated", "androidRegisteredCopyQualified", "androidBuildQualified",
                                                "developerIdOrNotarizationQualified", "productReady"))
         and value["directStagerIOPending"] is None and value["cleanupErrors"] == []
         and value["finalPackageReceiptSha256"] == final_package_sha, "remove-owner-finality")
    roles = ("producer-build", "producer-emitter", "distribution-create", "distribution-sign", "distribution-verify-signature", "distribution-verify-image")
    calls = value["originalCalls"]
    need(type(calls) is list and len(calls) == len(roles), "remove-owner-call-count")
    for row, role in zip(calls, roles):
        maintenance_map(row, ("role", "entered", "returned", "capturesSettled", "returncode", "stdoutSha256", "stderrSha256"), "remove-owner-call-fields")
        need(row["role"] == role and all(row[k] is True for k in ("entered", "returned", "capturesSettled"))
             and type(row["returncode"]) is int and row["returncode"] == 0
             and all(maintenance_hex(row[k], 64) for k in ("stdoutSha256", "stderrSha256")), "remove-owner-call-finality")
    credential_roles = ("search-before", "default-before", "create", "search-created", "settings", "unlock", "import", "partitions", "identity",
        "certificates", "search-admit", "restrict", "search-restricted", "search-after-callback", "restore", "search-restored", "delete", "search-final", "default-after")
    credentials = value["credentialOriginals"]
    ordered = ("producer-adhoc", "producer-adhoc-verify", "producer-cdhash") + credential_roles * 2
    need(type(credentials) is list and len(credentials) == len(ordered), "remove-owner-credential-count")
    for row, role in zip(credentials, ordered):
        maintenance_map(row, ("role", "entered", "returned", "settled", "status"), "remove-owner-credential-fields")
        need(row["role"] == role and all(row[k] is True for k in ("entered", "returned", "settled"))
             and type(row["status"]) is int and row["status"] == 0, "remove-owner-credential-finality")
    contexts = value["credentialContexts"]
    need(type(contexts) is list and len(contexts) == 2, "remove-owner-context-count")
    for row, purpose in zip(contexts, ("producer", "distribution-image")):
        maintenance_map(row, ("purpose", "searchRestored", "defaultUnchanged", "retired", "closed"), "remove-owner-context-fields")
        need(row["purpose"] == purpose and all(row[k] is True for k in ("searchRestored", "defaultUnchanged", "retired", "closed")),
             "remove-owner-context-finality")
    distribution = maintenance_map(value["removalDistribution"], ("schemaVersion", "kind", "target", "packageVersion", "release", "packageSha256", "packageBytes",
        "descriptorSha256", "signatureSha256", "producerSummary", "userImage", "installedProducerSha256", "inventorySha256", "removerExecutableSha256",
        "sourceProducerProfileSha256", "sourceServiceProfileSha256", "finalPackageReceiptSha256", "groupEndpointMet", "originalOuterReturnRequired",
        "installerEntered", "applicationLaunched", "removalExecuted", "productReady"), "remove-distribution-fields")
    emitted_removal_data(canonical(distribution["producerSummary"]) + b"\n", b"", 0, package, descriptor, signed, expected_descriptor)
    planned = maintenance_json(expected_descriptor, REMOVE_DESCRIPTOR_BYTES)
    need(type(distribution["schemaVersion"]) is int and distribution["schemaVersion"] == 1
         and distribution["kind"] == "mrk-remove-package-emitted-image-v1"
         and (distribution["target"], distribution["release"], distribution["packageVersion"]) == (selection.target, selection.release, selection.package_version)
         and type(distribution["packageBytes"]) is int and distribution["packageBytes"] == len(package)
         and (distribution["packageSha256"], distribution["descriptorSha256"], distribution["signatureSha256"]) == (digest(package), digest(descriptor), digest(signed))
         and all(distribution[k] is True for k in ("groupEndpointMet", "originalOuterReturnRequired"))
         and all(distribution[k] is False for k in ("installerEntered", "applicationLaunched", "removalExecuted", "productReady"))
         and distribution["finalPackageReceiptSha256"] == final_package_sha
         and distribution["sourceProducerProfileSha256"] == source.producer_sha256 and distribution["sourceServiceProfileSha256"] == source.service_sha256
         and distribution["installedProducerSha256"] == planned["installedProducerSha256"]
         and distribution["inventorySha256"] == planned["installedInventorySha256"]
         and distribution["removerExecutableSha256"] == planned["removerExecutableSha256"], "remove-distribution-current-binding")
    image = maintenance_map(distribution["userImage"], ("file", "bytes", "sha256"), "remove-image-fields")
    need(image["file"] == "MobileReleaseKit-Remove.dmg" and type(image["bytes"]) is int and 0 < image["bytes"] <= MAX_BYTES
         and maintenance_hex(image["sha256"], 64), "remove-image-bound")
    return distribution


def final_image_receipt_data(body, *, selection, binding, request, package, descriptor, signed,
                             original_image, package_owner, final_package, release_body, profiles, remove=False):
    """Correspondence with original0/status inputs, not new native authority.

    The fixed phase consumed the actual S3 parser/signing chain and final P.
    Preserve its raw receipt hash here; never hash a reserialized substitute.
    Existing preview checks still bind Installer/readback/current producer DATA.
    """
    need(type(remove) is bool, "final-image-receipt-purpose")
    selection = selected_build(selection)
    release = build_release_data(release_body, target=selection.target)
    need((release["packageVersion"], release["release"]) == (selection.package_version, selection.release)
         and type(profiles) is tuple and len(profiles) == 3
         and all(type(item) is bytes and 0 < len(item) <= 1024 for item in profiles), "final-image-source-inputs")
    source = packaging_signing_data(profiles[0], profiles[1])
    need(source is not None, "final-image-source-signing")
    value = maintenance_json(body, 16384)
    maintenance_map(value, ("schemaVersion", "phase", "target", "source", "packageRole", "workflowSource", "workflow", "runId", "runAttempt",
        "toolchain", "helperIdentifier", "originalCalls", "credentialOriginals", "credentialContexts", "targetRetired",
        "originalClosesKnown", "passed", "outerFinalityRequired", "androidServiceAuthenticated", "androidRegisteredCopyQualified",
        "androidBuildQualified", "developerIdOrNotarizationQualified", "distributionQualified", "productReady", "notaryAuthentication",
        "notarySubmission", "finalImage", "finalImageMount", "finalPackageReceiptSha256", "directStagerIOPending", "cleanupErrors",
        "imageSourceCommit", "imageReleaseId", "imageReleaseSourceSha256"), "final-image-receipt-fields")
    workflow = "Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-installed.yml@refs/heads/verify/desktop-macos-preview"
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["phase"] == ("finalize-remove-image" if remove else "finalize-image")
         and value["target"] == selection.target and value["source"] == value["workflowSource"] == binding["source"]
         and maintenance_hex(value["source"], 40) and value["workflow"] == workflow
         and value["runId"] == binding["runId"] and value["runAttempt"] == binding["runAttempt"]
         and all(type(value[key]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value[key]) for key in ("runId", "runAttempt"))
         and value["packageRole"] == "ordinary-image" and value["imageSourceCommit"] == value["source"]
         and value["imageReleaseId"] == selection.release and value["imageReleaseSourceSha256"] == digest(release_body)
         and value["toolchain"] is None and value["helperIdentifier"] is None, "final-image-receipt-source")
    need(all(value[key] is True for key in ("targetRetired", "originalClosesKnown", "passed", "outerFinalityRequired"))
         and all(value[key] is False for key in ("androidServiceAuthenticated", "androidRegisteredCopyQualified", "androidBuildQualified",
                                                "developerIdOrNotarizationQualified", "distributionQualified", "productReady"))
         and value["credentialOriginals"] == [] and value["credentialContexts"] == [] and value["cleanupErrors"] == []
         and value["directStagerIOPending"] is None, "final-image-receipt-finality")
    auth = maintenance_map(value["notaryAuthentication"], ("created", "closed", "retired"), "final-image-key-finality")
    need(all(item is True for item in auth.values()), "final-image-key-finality")
    mount = maintenance_map(value["finalImageMount"], ("attachEntered", "originalKnown", "detached", "retained", "installerEntered",
                                                     "systemServiceExitClaimed"), "final-image-mount-fields")
    need(all(mount[key] is True for key in ("attachEntered", "originalKnown", "detached"))
         and all(mount[key] is False for key in ("retained", "installerEntered", "systemServiceExitClaimed")), "final-image-mount-finality")
    roles = ("resolve-notarytool", "resolve-stapler", "signature-before", "submit", "log", "staple", "validate", "signature-after",
             "verify", "attach", "detach")
    calls = value["originalCalls"]
    need(type(calls) is list and len(calls) == len(roles), "final-image-original-count")
    for row, role in zip(calls, roles):
        maintenance_map(row, ("role", "entered", "returned", "capturesSettled", "returncode", "stdoutSha256", "stderrSha256"),
                        "final-image-original-fields")
        need(row["role"] == "final-image-" + role and all(row[key] is True for key in ("entered", "returned", "capturesSettled"))
             and type(row["returncode"]) is int and row["returncode"] == 0
             and maintenance_hex(row["stdoutSha256"], 64) and maintenance_hex(row["stderrSha256"], 64), "final-image-original-result")
    final = maintenance_map(value["finalImage"], ("schemaVersion", "kind", "target", "release", "packageVersion",
        *( () if remove else ("requestId",) ), "packageRemoveReceiptSha256" if remove else "packageInstallReceiptSha256", "finalPackageReceiptSha256", "packageBytes", "packageSha256", "descriptorBytes", "descriptorSha256",
        "signatureBytes", "signatureSha256", "producerProfileSha256", "serviceProfileSha256", "originalImageBytes", "originalImageSha256",
        "submittedSha256", "imageBytes", "imageSha256", "imageMode", "notaryProfileSha256", "submissionId", "status", "sha256Compared",
        "errorCount", "warningCount", "ticketRowCount", "logSha256", "strictSignatureBeforeAndAfter", "actualStaplerValidation",
        "actualImageVerification", "finalMountReadOnly", "finalMountOriginalsMatch", "originalMountDetached", "assurance"), "final-image-fields")
    need(type(final["schemaVersion"]) is int and final["schemaVersion"] == 1 and final["kind"] == ("mrk-final-removal-image" if remove else "mrk-final-user-image")
         and (final["target"], final["release"], final["packageVersion"]) == (selection.target, selection.release, selection.package_version)
         and (request is None if remove else maintenance_hex(request, 32) and final["requestId"] == request), "final-image-current-binding")
    for label, contents, maximum in (("package", package, MAX_BYTES), ("descriptor", descriptor, PRODUCER_DESCRIPTOR_BYTES),
                                    ("signature", signed, PRODUCER_SIGNATURE_BYTES)):
        need(type(contents) is bytes and 0 < len(contents) <= maximum
             and type(final[label + "Bytes"]) is int and final[label + "Bytes"] == len(contents)
             and final[label + "Sha256"] == digest(contents), "final-image-current-bytes")
    old = maintenance_map(original_image, ("file", "bytes", "sha256"), "final-image-original-shape")
    need(old["file"] == ("MobileReleaseKit-Remove.dmg" if remove else "MobileReleaseKit.dmg") and type(old["bytes"]) is int and 0 < old["bytes"] <= MAX_BYTES
         and maintenance_hex(old["sha256"], 64) and type(final["originalImageBytes"]) is int
         and final["originalImageBytes"] == old["bytes"] and final["originalImageSha256"] == final["submittedSha256"] == old["sha256"]
         and type(final["imageBytes"]) is int and 0 < final["imageBytes"] <= MAX_BYTES
         and abs(final["imageBytes"] - old["bytes"]) <= 1024 * 1024
         and type(final["imageMode"]) is int and final["imageMode"] == 0o444
         and maintenance_hex(final["imageSha256"], 64), "final-image-carrier-binding")
    need(type(package_owner) is bytes and 0 < len(package_owner) <= 16384
         and type(final_package) is bytes and 0 < len(final_package) <= 16384
         and final["packageRemoveReceiptSha256" if remove else "packageInstallReceiptSha256"] == digest(package_owner)
         and final["finalPackageReceiptSha256"] == value["finalPackageReceiptSha256"] == digest(final_package)
         and final["producerProfileSha256"] == source.producer_sha256 and final["serviceProfileSha256"] == source.service_sha256
         and final["notaryProfileSha256"] == digest(profiles[2]), "final-image-raw-predecessors")
    preceding = maintenance_json(package_owner, 16384)
    need(preceding.get("finalPackageReceiptSha256") == value["finalPackageReceiptSha256"], "final-image-package-predecessor")
    need(final["status"] == "Accepted" and type(final["submissionId"]) is str
         and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", final["submissionId"])
         and final["submissionId"] != "00000000-0000-0000-0000-000000000000"
         and type(final["sha256Compared"]) is bool and type(final["errorCount"]) is int and final["errorCount"] == 0
         and all(type(final[key]) is int and 0 <= final[key] <= 2048 for key in ("warningCount", "ticketRowCount"))
         and maintenance_hex(final["logSha256"], 64)
         and value["notarySubmission"] == {"id": final["submissionId"], "status": "Accepted"}, "final-image-notary-observation")
    need(all(final[key] is True for key in ("strictSignatureBeforeAndAfter", "actualStaplerValidation", "actualImageVerification",
                                          "finalMountReadOnly", "finalMountOriginalsMatch", "originalMountDetached"))
         and final["assurance"] == "final-carrier-observation-not-downloaded-install-or-gatekeeper-authority", "final-image-scoped-observation")
    return final


def preview_command(args):
    """Copy only an audited, normally built and read-back package to fresh output."""
    selection = source_build_selection(command_target(args))
    need(type(args.expected_source) is str and re.fullmatch(r"[0-9a-f]{40}", args.expected_source),
         "preview-source")
    work = Path(args.work)
    need(work.is_absolute(), "preview-work-absolute")
    binding = decode(read(work / "source-binding.json", 65536))
    source = decode(read(work / "source-inventory.json", 1024 * 1024))
    need(type(binding) is dict and type(source) is dict
         and source.get("source") == binding.get("source") == args.expected_source
         and binding.get("workflowSource") == args.expected_source
         and source.get("tree") == binding.get("tree") and type(source.get("tree")) is str
         and re.fullmatch(r"[0-9a-f]{40}", source["tree"])
         and binding.get("scope") == "normal-macos-early-preview" and binding.get("instrumented") is False
         and binding.get("packageRole") == "ordinary-image",
         "preview-source-binding")
    need(all(type(binding.get(k)) is str and re.fullmatch(r"[1-9][0-9]{0,19}", binding[k])
             for k in ("runId", "runAttempt")), "preview-run-binding")
    need(read(work / "normal-build.status", 4) == b"0\n"
         and read(work / "installer-output.status", 4) == b"0\n"
         and read(work / "package-install.status", 4) == b"0\n", "preview-original-statuses")
    original = work / "cargo-target" / selection.target / "release/libmrk_desktop_image.dylib"
    normal = image_cargo_artifact(read(work / "normal-build.jsonl", 8 * 1024 * 1024),
                                 original, work / "cargo-target", read(original), "desktop", target=selection.target)
    facade = read(work / "mobile-release-kit-desktop", 1024 * 1024)
    entry_macho(facade, target=selection.target)
    app = decode(read(work / "app-result.json", 16384))
    need(type(app) is dict and app.get("packageRole") == "ordinary-image"
         and app.get("desktopImageCargoArtifact") == normal and "observerCargoArtifact" not in app
         and "normalCargoArtifact" not in app
         and app.get("desktopImageSha256BeforeSigning") == normal["binarySha256"]
         and app.get("appBinarySha256BeforeSigning") == digest(facade)
         and sha(app.get("residentImageSha256")) and sha(app.get("androidHelperSha256"))
         and sha(app.get("entryBinarySha256BeforeSigning"))
         and app.get("entryBundleIdentifier") == ENTRY_BUNDLE_ID
         and app.get("payloadBundleIdentifier") == BUNDLE_ID, "preview-normal-app-binding")
    observed = decode(read(work / "installation-observation.json", INSTALLER_RESULT_BYTES))
    owner_body = read(work / "android-helper-package-install.json", 16384)
    owner = decode(owner_body)
    need(type(owner) is dict and owner.get("phase") == "package-install" and owner.get("target") == selection.target
         and owner.get("source") == args.expected_source and owner.get("passed") is True
         and owner.get("targetRetired") is True and owner.get("originalClosesKnown") is True
         and owner.get("outerFinalityRequired") is True and not owner.get("cleanupErrors"), "preview-original-package-owner")
    calls = owner.get("originalCalls")
    need(type(calls) is list and all(type(row) is dict for row in calls)
         and tuple(row.get("role") for row in calls) == PACKAGING_CALL_ROLES
         and all(row.get("returned") is True and type(row.get("returncode")) is int
                 and row["returncode"] in ((0, 1) if row["role"] in ("installer-log-cursor", "installer-log-capture") else (0,))
                 for row in calls), "preview-original-package-calls")
    distribution = owner.get("distribution")
    need(type(distribution) is dict and distribution.get("schemaVersion") == 1
         and distribution.get("kind") == "mrk-ordinary-package-observed-v2"
         and distribution.get("target") == selection.target and distribution.get("packageVersion") == selection.package_version
         and distribution.get("release") == selection.release and distribution.get("originalInstallerReturnedZero") is True
         and distribution.get("sameRequestV2Readback") is True and distribution.get("originalMountDetached") is True
         and distribution.get("groupEndpointMet") is True and distribution.get("originalOuterReturnRequired") is True,
         "preview-original-distribution")
    request_id = distribution.get("requestId")
    need(maintenance_hex(request_id, 32) and read(work / "package-request-id.txt", 33) == (request_id + "\n").encode("ascii"),
         "preview-original-request")
    need(type(observed) is dict and observed.get("schemaVersion") == 2
         and observed.get("sourceCommit") == args.expected_source and observed.get("release") == selection.release
         and observed.get("requestId") == request_id and observed.get("originalInstallerReturnedZero") is True
         and observed.get("originalWriterJoined") is True and observed.get("historicalOuterExit") == "unverified"
         and observed.get("applicationLaunched") is False and observed.get("guiSaveQualified") is False
         and observed.get("runtimeManifestSha256") == binding.get("runtimeManifestSha256")
         and observed.get("completedPackageSha256") == distribution.get("packageSha256"), "preview-installation-readback")
    result = maintenance_result_data(canonical(observed.get("originalInstallerResult")) + b"\n", request_id)
    need(result["invocation"] == observed.get("invocation"), "preview-current-invocation")
    metadata = observed.get("installationMetadata")
    need(type(metadata) is list and 0 < len(metadata) <= 9 and all(type(row) is dict for row in metadata)
         and metadata[0].get("release") == selection.release
         and metadata[0].get("verifiedCurrentFiles") == observed.get("nonrootReadbackFileCount")
         and all(row.get("historicalOuterExit") == "unverified" for row in metadata), "preview-v2-metadata-readback")
    need(observed.get("maintenanceGate") == {
        "state": "protected-permanent-gate-data-correspondence", "bytes": len(MAINTENANCE_GATE_BYTES),
        "exclusionObserved": False, "workerFinalityEstablished": False}, "preview-maintenance-gate-readback")
    need(observed.get("registrationReservation") == {
        "state": "protected-permanent-reservation-data-correspondence", "bytes": len(REGISTRATION_GATE_BYTES),
        "exclusionObserved": False, "workerFinalityEstablished": False}, "preview-registration-reservation-readback")
    expected = observation_inventory(argparse.Namespace(input=work / "input",
        expected_inventory=observed["inventorySha256"], expected_manifest=observed["runtimeManifestSha256"], target=selection.target), selection=selection)
    need(observed.get("nonrootReadbackFileCount") == len(expected)
         and all("app/" + path in expected for path in (ENTRY_BINARY, APP_BINARY, ANDROID_HELPER,
                     ANDROID_SERVICE_PLIST, DESKTOP_IMAGE, RESIDENT_IMAGE))
         and expected["app/" + RESIDENT_IMAGE]["sha256"] == app["residentImageSha256"]
         and expected["app/" + ANDROID_HELPER]["sha256"] == app["androidHelperSha256"], "preview-readback-roster")
    audit = decode(read(work / "package-audit.json", 16384))
    package = read(work / "package-final/MobileReleaseKit.pkg")
    need(type(audit) is dict and audit.get("packageSha256") == digest(package)
         and type(audit.get("packageSize")) is int and audit["packageSize"] == len(package)
         and audit.get("packageIdentifier") == "dev.mobile-release-kit.desktop.installed"
         and audit.get("qualification") == "scripts-only-package-audited-not-installed-or-GUI-qualified",
         "preview-original-audited-package")
    descriptor = read(work / "producer-root/producer.json", PRODUCER_DESCRIPTOR_BYTES)
    signed = read(work / "producer-root/producer.sig", PRODUCER_SIGNATURE_BYTES)
    need(read(work / "producer-root/Install.pkg") == package, "preview-emitted-package-bytes")
    emitted = emitted_package_data(canonical(distribution.get("producerSummary")) + b"\n", b"", 0,
        package, descriptor, signed, target=selection.target)
    producer = maintenance_producer_data(descriptor, target=selection.target)
    current = producer["releaseSet"]["current"]
    need(current["sourceCommit"] == args.expected_source and current["release"] == selection.release
         and current["packageVersion"] == selection.package_version and current["protocolSha256"] == CURRENT_PROTOCOL
         and current["inventorySha256"] == observed["inventorySha256"]
         and current["runtimeManifestSha256"] == observed["runtimeManifestSha256"]
         and (distribution.get("packageSha256"), distribution.get("descriptorSha256"), distribution.get("signatureSha256"))
             == (digest(package), digest(descriptor), digest(signed)), "preview-emitted-current-correspondence")
    image = read(work / "distribution/MobileReleaseKit.dmg")
    need(distribution.get("userImage") == {"file": "MobileReleaseKit.dmg", "bytes": len(image), "sha256": digest(image)},
         "preview-original-distribution-image")
    original_image = dict(distribution["userImage"])
    del image  # Never retain a second whole DMG buffer or rewrite the recorded original.
    need(read(work / "image-finalization.status", 4) == b"0\n"
         and read(work / "package-finalization.status", 4) == b"0\n", "preview-finalization-original-statuses")
    receipt_body = read(work / "android-helper-finalize-image.json", 16384)
    final_package_body = read(work / "android-helper-finalize-package.json", 16384)
    release_path = (BUILD_RELEASE_INPUT if selection.target == ARM_TARGET else
                    DESKTOP / "macos-installed-inputs/build-release-intel.json")
    final = final_image_receipt_data(receipt_body, selection=selection, binding=binding, request=request_id,
        package=package, descriptor=descriptor, signed=signed, original_image=original_image,
        package_owner=owner_body, final_package=final_package_body, release_body=read(release_path, BUILD_RELEASE_LIMIT),
        profiles=(read(PRODUCER_PROFILE, 1024), read(SERVICE_PROFILE, 1024), read(DESKTOP / "packaging/macos-notary-service.json", 1024)))
    image = read(work / "distribution-final/MobileReleaseKit.dmg")
    need(len(image) == final["imageBytes"] and digest(image) == final["imageSha256"], "preview-finalized-image-bytes")
    summary = {"schemaVersion": 2, "scope": "normal-macos-early-preview", "sourceCommit": args.expected_source,
        "sourceTree": source["tree"], "workflow": ".github/workflows/desktop-macos-installed.yml",
        "runId": binding["runId"], "runAttempt": binding["runAttempt"], "platform": "macOS26-arm64" if selection.target == ARM_TARGET else "macOS26-x86_64",
        "packageSha256": digest(package), "packageSize": len(package), "runtimeManifestSha256": observed["runtimeManifestSha256"],
        "distributionSha256": digest(image), "distributionBytes": len(image), "descriptorSha256": emitted["descriptorSha256"],
        "signatureSha256": emitted["signatureSha256"], "requestId": request_id, "originalInstallerReturnedZero": True,
        "originalPackageGroupReturnedZero": True, "originalObservationMountDetached": True,
        "originalImageFinalizationReturnedZero": True, "originalFinalImageMountDetached": True,
        "finalImageReceiptSha256": digest(receipt_body), "originalDistributionSha256": original_image["sha256"],
        "finalImageScopedNotarizationObserved": True,
        "installerInventorySha256": observed["inventorySha256"],
        "packageRole": "ordinary-image", "normalBinaryBeforeSigningSha256": app["appBinarySha256BeforeSigning"],
        "desktopImageBeforeSigningSha256": normal["binarySha256"],
        "signedDesktopImageSha256": expected["app/" + DESKTOP_IMAGE]["sha256"],
        "signedResidentImageSha256": expected["app/" + RESIDENT_IMAGE]["sha256"],
        "signedAppBinarySha256": expected["app/" + APP_BINARY]["sha256"], "instrumented": False,
        "signedEntryBinarySha256": expected["app/" + ENTRY_BINARY]["sha256"],
        "entryBundleIdentifier": ENTRY_BUNDLE_ID, "payloadBundleIdentifier": BUNDLE_ID,
        "ordinaryEntryRoute": "unexecuted", "directPayloadPreMain": "unqualified",
        "fullM2Qualified": False, "maintenanceQualified": False,
        "normalBuild": "passed", "packageAudit": "passed", "installationReadback": "passed",
        "automaticWindowOpen": "unexecuted", "normalQuit": "unexecuted", "manualUIAcceptance": "pending",
        "unexecutedReason": "original-normal-app-quit-custody-not-established",
        "fullUIQualified": False, "distributionQualified": False, "productReady": False}
    guide = read(DESKTOP / "packaging/macos-preview.md", 32768)
    write_tree(args.output, {"MobileReleaseKit.dmg": (image, 0o444), "README.md": (guide, 0o444),
                            "PREVIEW.json": (canonical(summary) + b"\n", 0o444)})
    return {"schemaVersion": 2, "sourceCommit": args.expected_source, "packageSha256": digest(package),
            "distributionSha256": digest(image), "fileCount": 3, "qualification": "normal-early-preview-not-launched-or-product-qualified"}

def remove_preview_command(args):
    """Stage only the separately completed Remove carrier; never execute removal."""
    selection = source_build_selection(command_target(args))
    need(maintenance_hex(args.expected_source, 40) and Path(args.work).is_absolute(), "remove-preview-source")
    work = Path(args.work)
    binding = maintenance_json(read(work / "source-binding.json", 65536), 65536)
    source_inventory = maintenance_json(read(work / "source-inventory.json", 1024 * 1024), 1024 * 1024)
    need(type(binding) is dict and type(source_inventory) is dict
         and binding.get("source") == source_inventory.get("source") == args.expected_source
         and binding.get("workflowSource") == args.expected_source
         and source_inventory.get("tree") == binding.get("tree") and maintenance_hex(source_inventory.get("tree"), 40)
         and binding.get("scope") == "normal-macos-early-preview" and binding.get("instrumented") is False
         and binding.get("packageRole") == "ordinary-image", "remove-preview-source-binding")
    need(all(type(binding.get(k)) is str and re.fullmatch(r"[1-9][0-9]{0,19}", binding[k])
             for k in ("runId", "runAttempt")), "remove-preview-run-binding")
    for name in ("remove-package-finalization.status", "package-remove.status", "remove-image-finalization.status"):
        need(read(work / name, 4) == b"0\n", "remove-preview-original-statuses")
    package = read(work / "remove-package-final/Remove.pkg", MAX_BYTES)
    need(read(work / "remove-producer-root/Remove.pkg", MAX_BYTES) == package, "remove-preview-package-copy")
    descriptor = read(work / "remove-producer-root/remove-producer.json", REMOVE_DESCRIPTOR_BYTES)
    signed = read(work / "remove-producer-root/remove-producer.sig", PRODUCER_SIGNATURE_BYTES)
    input_root = work / "remove-emitter-input"
    installed = read(input_root / "producer.json", PRODUCER_DESCRIPTOR_BYTES)
    inventory = read(input_root / "install-inventory.json", 1024 * 1024)
    with parent(input_root / REMOVER_NAME) as (fd, name):
        program, info = read_at(fd, name, REMOVER_BYTES)
        need(stat.S_IMODE(info.st_mode) == 0o555, "remove-preview-program-mode")
    producer_profile, service_profile = read(PRODUCER_PROFILE, 1024), read(SERVICE_PROFILE, 1024)
    signing = packaging_signing_data(producer_profile, service_profile)
    expected = packaging_removal_descriptor_data(installed, inventory, program, package, signing, selection,
        source_commit=args.expected_source, manifest=binding.get("runtimeManifestSha256"))
    need(read(input_root / "remove-descriptor-input.json", REMOVE_DESCRIPTOR_BYTES) == expected == descriptor,
         "remove-preview-exact-descriptor")
    release_path = BUILD_RELEASE_INPUT if selection.target == ARM_TARGET else DESKTOP / "macos-installed-inputs/build-release-intel.json"
    release_body = read(release_path, BUILD_RELEASE_LIMIT)
    owner_body = read(work / "android-helper-package-remove.json", 16384)
    final_package_body = read(work / "android-helper-finalize-remove-package.json", 16384)
    distribution = removal_package_receipt_data(owner_body, selection=selection, binding=binding,
        package=package, descriptor=descriptor, signed=signed, expected_descriptor=expected,
        final_package_sha=digest(final_package_body), release_body=release_body, profiles=(producer_profile, service_profile))
    original_image = read(work / "remove-distribution/MobileReleaseKit-Remove.dmg", MAX_BYTES)
    need(distribution["userImage"] == {"file": "MobileReleaseKit-Remove.dmg", "bytes": len(original_image), "sha256": digest(original_image)},
         "remove-preview-original-image")
    del original_image
    receipt_body = read(work / "android-helper-finalize-remove-image.json", 16384)
    final = final_image_receipt_data(receipt_body, selection=selection, binding=binding, request=None,
        package=package, descriptor=descriptor, signed=signed, original_image=distribution["userImage"], package_owner=owner_body,
        final_package=final_package_body, release_body=release_body,
        profiles=(producer_profile, service_profile, read(DESKTOP / "packaging/macos-notary-service.json", 1024)), remove=True)
    image = read(work / "remove-distribution-final/MobileReleaseKit-Remove.dmg", MAX_BYTES)
    need(len(image) == final["imageBytes"] and digest(image) == final["imageSha256"], "remove-preview-final-image")
    summary = {"schemaVersion": 1, "kind": "mrk-removal-carrier-preview-v1", "sourceCommit": args.expected_source,
        "sourceTree": source_inventory["tree"], "target": selection.target, "release": selection.release, "packageVersion": selection.package_version,
        "runId": binding["runId"], "runAttempt": binding["runAttempt"], "packageSha256": digest(package), "packageBytes": len(package),
        "descriptorSha256": digest(descriptor), "signatureSha256": digest(signed), "installedProducerSha256": digest(installed),
        "inventorySha256": digest(inventory), "removerExecutableSha256": digest(program), "distributionSha256": digest(image), "distributionBytes": len(image),
        "finalPackageReceiptSha256": digest(final_package_body), "packageRemoveReceiptSha256": digest(owner_body),
        "finalImageReceiptSha256": digest(receipt_body), "originalPackageFinalizationReturnedZero": True, "originalPackageRemoveReturnedZero": True,
        "originalImageFinalizationReturnedZero": True, "originalFinalImageMountDetached": True,
        "status": "packaged-and-image-verified", "removalExecuted": False, "installedAppLaunchedByRemovalRoute": False,
        "initialRemovalQualified": False, "interruptedRemovalQualified": False, "distributionQualified": False, "productReady": False}
    guide = read(DESKTOP / "packaging/macos-removal.md", 32768)
    write_tree(args.output, {"MobileReleaseKit-Remove.dmg": (image, 0o444), "REMOVE.md": (guide, 0o444),
                            "REMOVAL.json": (canonical(summary) + b"\n", 0o444)})
    return {"schemaVersion": 1, "sourceCommit": args.expected_source, "distributionSha256": digest(image), "fileCount": 3,
            "qualification": "separate-removal-carrier-not-removal-or-recovery-qualified"}


def android_support_manifest():
    # Reviewed source DATA, not a user recipe, runtime network grant or sidecar.
    body = read(ANDROID_SUPPORT_MANIFEST, 16384)
    value = decode(body)
    need(type(value) is dict and set(value) == {"schemaVersion", "platform", "archives"}
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["platform"] == "macos" and type(value["archives"]) is list
         and len(value["archives"]) == len(ANDROID_SUPPORT_LAYOUT), "android-support-manifest")
    destinations = set()
    total = notices_total = 0
    for row, (identity, filename, url, members) in zip(value["archives"], ANDROID_SUPPORT_LAYOUT):
        need(type(row) is dict and set(row) == {"id", "fileName", "resourcePath", "url", "size", "sha256", "notices"}
             and row["id"] == identity and row["fileName"] == filename and row["url"] == url
             and row["resourcePath"] == ANDROID_SUPPORT_PREFIX + filename
             and type(row["size"]) is int and 0 < row["size"] <= 64 * 1024 * 1024 and sha(row["sha256"])
             and type(row["notices"]) is list and len(row["notices"]) == len(members), "android-support-manifest")
        total += row["size"]
        destinations.add(row["resourcePath"])
        for notice, member in zip(row["notices"], members):
            expected = ANDROID_SUPPORT_PREFIX + "notices/" + identity + "/" + member
            need(type(notice) is dict and set(notice) == {"member", "resourcePath", "size", "sha256"}
                 and notice["member"] == member and notice["resourcePath"] == expected
                 and type(notice["size"]) is int and 0 < notice["size"] <= 1024 * 1024
                 and sha(notice["sha256"]) and expected not in destinations, "android-support-manifest")
            notices_total += notice["size"]
            destinations.add(expected)
    need(total <= 64 * 1024 * 1024 and notices_total <= 1024 * 1024, "android-support-manifest")
    directories(destinations)  # Same path, case-fold and file/directory policy.
    return digest(body), value["archives"]


def android_support_files(args):
    manifest_sha, rows = android_support_manifest()
    files = {}
    for row, path in zip(rows, (args.bundletool_archive, args.aapt2_archive)):
        body = read(path, row["size"])
        # Authenticate the complete original before parsing even its directory.
        need(len(body) == row["size"] and digest(body) == row["sha256"], "android-support-archive")
        files[row["resourcePath"]] = (body, 0o644)
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            entries = archive.infolist()
            need(0 < len(entries) <= 32768, "android-support-archive")
            for notice in row["notices"]:
                selected = [entry for entry in entries if entry.filename == notice["member"]]
                need(len(selected) == 1, "android-support-notice")
                entry = selected[0]
                need(not entry.is_dir() and not entry.flag_bits & 1 and entry.file_size == notice["size"]
                     and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "android-support-notice")
                with archive.open(entry) as stream:
                    text = stream.read(notice["size"] + 1)
                need(len(text) == notice["size"] and digest(text) == notice["sha256"]
                     and b"\0" not in text, "android-support-notice")
                text.decode("utf-8", "strict")
                files[notice["resourcePath"]] = (text, 0o644)
    return manifest_sha, files


def android_support_input(app):
    manifest_sha, rows = android_support_manifest()
    expected = {PAYLOAD_RELATIVE + "/" + row["resourcePath"]: row for row in rows}
    expected.update({PAYLOAD_RELATIVE + "/" + notice["resourcePath"]: notice for row in rows for notice in row["notices"]})
    need({name for name in app if name.startswith(PAYLOAD_RELATIVE + "/" + ANDROID_SUPPORT_PREFIX)} == set(expected), "android-support-roster")
    for name, row in expected.items():
        body, mode = app[name]
        need(mode in (0o444, 0o644) and len(body) == row["size"] and digest(body) == row["sha256"],
             "android-support-resource")
    return manifest_sha


def android_support_command(args):
    manifest_sha, files = android_support_files(args)
    return {"schemaVersion": 1, "androidSupportManifestSha256": manifest_sha,
            "fileCount": len(files), "payloadBytes": sum(len(body) for body, _ in files.values()),
            "qualification": "original-archive-and-notice-data-only-no-vendor-execution"}


def source_app_info(*, selection=None):
    selection = selected_build(selection)
    info = read(DESKTOP / "macos-installed-inputs/Info.plist", 16384)
    parsed = plistlib.loads(info)
    need(parsed["CFBundleExecutable"] == "mobile-release-kit-desktop" and parsed["LSMinimumSystemVersion"] == "26.0"
         and parsed["CFBundleIdentifier"] == BUNDLE_ID
         and parsed["CFBundleShortVersionString"] == parsed["CFBundleVersion"] == selection.package_version, "app-info-binding")
    return info


def source_entry_info(*, selection=None):
    selection = selected_build(selection)
    info = read(DESKTOP / "macos-installed-inputs/EntryInfo.plist", 16384)
    parsed = plistlib.loads(info)
    payload = plistlib.loads(source_app_info(selection=selection))
    expected = dict(payload, CFBundleExecutable="mrk-macos-entry", CFBundleIdentifier=ENTRY_BUNDLE_ID)
    need(parsed == expected, "entry-info-binding")
    return info


def android_service_plist():
    body = read(DESKTOP / "macos-installed-inputs" / Path(ANDROID_SERVICE_PLIST).name, 4096)
    try:
        value = plistlib.loads(body)
    except Exception:
        raise Refused("android-service-plist") from None
    need(value == {"Label": ANDROID_SERVICE_LABEL, "BundleProgram": ANDROID_HELPER_BUNDLE_PROGRAM,
                   "MachServices": {ANDROID_SERVICE_LABEL: True}}
         and value["MachServices"][ANDROID_SERVICE_LABEL] is True, "android-service-plist")
    return body


def android_service_files(args, *, target=ARM_TARGET):
    target = mac_target(target)
    helper, expected = getattr(args, "android_helper", None), getattr(args, "expected_android_helper", None)
    image, expected_image = getattr(args, "resident_image", None), getattr(args, "expected_resident_image", None)
    need((helper is None) == (expected is None) == (image is None) == (expected_image is None),
         "android-service-paired-inputs")
    if helper is None:
        return {}
    need(sha(expected) and sha(expected_image), "android-helper-final-signed-digest")
    body, image_body = read(helper, 32 * 1024 * 1024), read(image, 32 * 1024 * 1024)
    need(digest(body) == expected and digest(image_body) == expected_image, "android-helper-final-signed-digest")
    entry_macho(body, target=target)
    image_macho(image_body, "resident", target=target)
    # No native signing, service registration, approval or launch occurs here.
    return {ANDROID_HELPER: (body, 0o555), RESIDENT_IMAGE: (image_body, 0o555),
            ANDROID_SERVICE_PLIST: (android_service_plist(), 0o644)}


def android_service_input(app, expected, expected_image=None, *, target=ARM_TARGET):
    target = mac_target(target)
    helper = ANDROID_HELPER in app
    need(helper == (ANDROID_SERVICE_PLIST in app) == (RESIDENT_IMAGE in app)
         == (expected is not None) == (expected_image is not None), "android-service-input-pair")
    if not helper:
        return
    body, mode = app[ANDROID_HELPER]
    image_body, image_mode = app[RESIDENT_IMAGE]
    need(sha(expected) and digest(body) == expected and sha(expected_image)
         and digest(image_body) == expected_image, "android-helper-signature-bytes-changed")
    entry_macho(body, target=target)
    image_macho(image_body, "resident", target=target)
    need(mode == image_mode == 0o555 and app[ANDROID_SERVICE_PLIST][0] == android_service_plist()
         and app[ANDROID_SERVICE_PLIST][1] in (0o444, 0o644), "android-service-plist")


def app_command(args):
    target = command_target(args)
    role = package_role(getattr(args, "package_role", None))
    # Both explicit roles must pass their own selected-target artifact parser.
    selection = source_build_selection(target)
    desktop_inputs = [getattr(args, key, None) for key in
                      ("desktop_image", "expected_desktop_image", "desktop_image_cargo_messages", "desktop_image_cargo_target_dir")]
    observer_inputs = [getattr(args, key, None) for key in ("observer_cargo_messages", "observer_cargo_target_dir")]
    need((all(value is not None for value in desktop_inputs) and all(value is None for value in observer_inputs))
         if role == "ordinary-image" else
         (all(value is None for value in desktop_inputs) and all(value is not None for value in observer_inputs)),
         "package-role-artifact-inputs")
    need(getattr(args, "android_helper", None) is not None and getattr(args, "resident_image", None) is not None,
         "package-role-resident-required")
    body = read(args.binary)
    need(sha(getattr(args, "expected_app_binary", None)) and digest(body) == args.expected_app_binary,
         "app-original-compiler-digest")
    desktop_body = None
    if role == "ordinary-image":
        entry_macho(body, target=target)
        desktop_body = read(args.desktop_image)
        need(sha(args.expected_desktop_image) and digest(desktop_body) == args.expected_desktop_image,
             "desktop-image-original-compiler-digest")
        compiled = image_cargo_artifact(read(args.desktop_image_cargo_messages, 8 * 1024 * 1024),
                                       args.desktop_image, args.desktop_image_cargo_target_dir, desktop_body, "desktop", target=target)
    else:
        compiled = observer_cargo_artifact(read(args.observer_cargo_messages, 8 * 1024 * 1024),
                                          args.binary, args.observer_cargo_target_dir, body, target=target)
    need(all(getattr(args, key, None) is not None for key in
             ("remover", "expected_remover", "remover_cargo_messages", "remover_cargo_target_dir")), "package-role-remover-required")
    remover = read(args.remover, REMOVER_BYTES)
    need(sha(args.expected_remover) and digest(remover) == args.expected_remover, "remover-final-signed-digest")
    abrupt = getattr(args, "removal_abrupt_fixture", False)
    need(type(abrupt) is bool and (not abrupt or role == "ordinary-image" and target == ARM_TARGET),
         "app-removal-fixture-role")
    if abrupt:
        remover_compiled = removal_fixture_cargo_artifact(read(args.remover_cargo_messages, 4 * 1024 * 1024),
            args.remover, args.remover_cargo_target_dir, remover, role="abrupt", target=target)
    else:
        remover_compiled = remover_cargo_artifact(read(args.remover_cargo_messages, 8 * 1024 * 1024),
                                                args.remover, args.remover_cargo_target_dir, remover, target=target)
    helper = read(args.vault_helper, 32 * 1024 * 1024)
    need(sha(args.expected_vault_helper) and digest(helper) == args.expected_vault_helper,
         "helper-final-signed-digest")
    macho(helper, system_only=True, target=target)
    entry = read(args.entry_binary, 1024 * 1024)
    need(sha(args.expected_entry) and digest(entry) == args.expected_entry, "entry-original-compiler-digest")
    entry_macho(entry, target=target)
    icon = read(DESKTOP / "src-tauri/icons/icon.png", 1024 * 1024)
    files = {ENTRY_BINARY: (entry, 0o755), APP_BINARY: (body, 0o755), VAULT_HELPER: (helper, 0o555), REMOVER: (remover, 0o555),
             "Contents/Info.plist": (source_entry_info(selection=selection), 0o644), PAYLOAD_INFO: (source_app_info(selection=selection), 0o644),
             "Contents/PkgInfo": (b"APPL????", 0o644), PAYLOAD_CONTENTS + "PkgInfo": (b"APPL????", 0o644),
             "Contents/Resources/icon.png": (icon, 0o644), PAYLOAD_CONTENTS + "Resources/icon.png": (icon, 0o644)}
    if desktop_body is not None:
        files[DESKTOP_IMAGE] = (desktop_body, 0o755)
    support_sha, support = android_support_files(args)
    files.update({PAYLOAD_RELATIVE + "/" + name: value for name, value in support.items()})
    android_service = android_service_files(args, target=target)
    need(bool(android_service), "package-role-resident-required")
    files.update(android_service)
    # Each image/helper is separately signed/verified before payload then outer
    # bundle signing. No deep repair or image/executable fallback is permitted.
    write_tree(args.output, files, root_mode=0o755, app_signing=True)
    result = {"schemaVersion": 1, "packageRole": role,
              "appBinarySha256BeforeSigning": digest(body), "vaultHelperSha256": digest(helper),
              "removerSha256": digest(remover), "removerCargoArtifact": remover_compiled,
              "entryBinarySha256BeforeSigning": digest(entry), "entryBundleIdentifier": ENTRY_BUNDLE_ID,
              "payloadBundleIdentifier": BUNDLE_ID, "androidSupportManifestSha256": support_sha,
              "androidHelperSha256": digest(android_service[ANDROID_HELPER][0]),
              "residentImageSha256": digest(android_service[RESIDENT_IMAGE][0]),
              "androidServicePlistSha256": digest(android_service[ANDROID_SERVICE_PLIST][0]),
              "qualification": "app-copied-not-signed-or-launched"}
    if role == "ordinary-image":
        result["desktopImageCargoArtifact"] = compiled
        result["desktopImageSha256BeforeSigning"] = digest(desktop_body)
    else:
        result["observerCargoArtifact"] = compiled
    return result


def runtime_tree(root, expected, *, current=False, target=ARM_TARGET):
    target = mac_target(target)
    need(type(current) is bool, "runtime-manifest-profile")
    need(current or target == ARM_TARGET, "unqualified-intel-route")
    files = tree(root)
    need("manifest.json" in files, "runtime-manifest-missing")
    _, rows = manifest_files(files["manifest.json"][0], expected, current=current, target=target)
    need(set(files) == set(rows) | {"manifest.json"}, "runtime-complete-roster")
    for name, (body, mode) in files.items():
        need(mode == (0o555 if name == "python/bin/python3" else 0o444), "runtime-mode")
        if name != "manifest.json":
            need(len(body) == rows[name]["size"] and digest(body) == rows[name]["sha256"], "runtime-byte-correspondence")
    return files


def ticket_input_names(app, expectations):
    """Match only explicit ticket DATA; this does not establish notarization.

    The existing tree reader supplies regular, single-link, original-bound
    leaves. Native Accepted/stapler verification belongs to the later owner;
    neither these bytes nor their hashes grant that authority.
    """
    if expectations is None:
        return set()
    paths = ("Contents/CodeResources", PAYLOAD_CONTENTS + "CodeResources")
    need(type(expectations) is list and len(expectations) == 2, "ticket-input-expectations")
    for row, path in zip(expectations, paths):
        need(type(row) is dict and set(row) == {"path", "bytes", "sha256"}
             and row["path"] == path and type(row["bytes"]) is int
             and 1 <= row["bytes"] <= 1024 * 1024 and sha(row["sha256"]), "ticket-input-expectations")
        need(path in app, "ticket-input-correspondence")
        body, mode = app[path]
        need(type(body) is bytes and type(mode) is int and mode & 0o7133 == 0
             and len(body) == row["bytes"] and digest(body) == row["sha256"], "ticket-input-correspondence")
    return set(paths)


def input_command(args, *, ticket_expectations=None):
    target = command_target(args)
    role = package_role(getattr(args, "package_role", None))
    need(target == ARM_TARGET or args.current_runtime is True, "unqualified-intel-route")
    selection = source_build_selection(target)
    expected_desktop = getattr(args, "expected_desktop_image", None)
    expected_resident = getattr(args, "expected_resident_image", None)
    need((expected_desktop is not None) == (role == "ordinary-image")
         and sha(expected_resident) and sha(getattr(args, "expected_android_helper", None)),
         "package-role-signed-inputs")
    runtime = runtime_tree(args.runtime, args.expected_manifest, current=args.current_runtime, target=target)
    app = tree(args.app)
    _support_sha, support_rows = android_support_manifest()
    support = {PAYLOAD_RELATIVE + "/" + row["resourcePath"] for row in support_rows}
    support.update(PAYLOAD_RELATIVE + "/" + notice["resourcePath"] for row in support_rows for notice in row["notices"])
    expected_names = {ENTRY_BINARY, APP_BINARY, VAULT_HELPER, ANDROID_HELPER, ANDROID_SERVICE_PLIST, RESIDENT_IMAGE, REMOVER,
                      "Contents/Info.plist", PAYLOAD_INFO, "Contents/PkgInfo", PAYLOAD_CONTENTS + "PkgInfo",
                      "Contents/Resources/icon.png", PAYLOAD_CONTENTS + "Resources/icon.png",
                      "Contents/_CodeSignature/CodeResources", PAYLOAD_CONTENTS + "_CodeSignature/CodeResources"} | support
    if role == "ordinary-image":
        expected_names.add(DESKTOP_IMAGE)
    expected_names.update(ticket_input_names(app, ticket_expectations))
    need(set(app) == expected_names and app["Contents/Info.plist"][0] == source_entry_info(selection=selection)
         and app[PAYLOAD_INFO][0] == source_app_info(selection=selection), "signed-app-roster")
    need(sha(args.expected_entry) and digest(app[ENTRY_BINARY][0]) == args.expected_entry
         and sha(args.expected_app_binary) and digest(app[APP_BINARY][0]) == args.expected_app_binary,
         "final-entry-payload-signature-bytes-changed")
    entry_macho(app[ENTRY_BINARY][0], target=target)
    if role == "ordinary-image":
        entry_macho(app[APP_BINARY][0], target=target)
        image_macho(app[DESKTOP_IMAGE][0], "desktop", target=target)
        need(sha(expected_desktop) and digest(app[DESKTOP_IMAGE][0]) == expected_desktop,
             "desktop-image-signature-bytes-changed")
    else:
        macho(app[APP_BINARY][0], target=target)
    macho(app[VAULT_HELPER][0], system_only=True, target=target)
    need(sha(args.expected_vault_helper) and digest(app[VAULT_HELPER][0]) == args.expected_vault_helper,
         "nested-helper-signature-bytes-changed")
    need(sha(getattr(args, "expected_remover", None)) and digest(app[REMOVER][0]) == args.expected_remover
         and app[REMOVER][1] == 0o555, "remover-signature-bytes-or-mode-changed")
    macho(app[REMOVER][0], target=target)
    android_service_input(app, args.expected_android_helper, expected_resident, target=target)
    support_sha = android_support_input(app)
    files = {}
    for prefix, source in (("runtime/", runtime), ("app/", app)):
        for name, (body, mode) in source.items():
            need(prefix != "app/" or name.startswith("Contents/"), "app-contents-scope")
            code = ("app/" + ENTRY_BINARY, "app/" + APP_BINARY, "app/" + VAULT_HELPER, "app/" + ANDROID_HELPER,
                    "app/" + DESKTOP_IMAGE, "app/" + RESIDENT_IMAGE, "app/" + REMOVER, "runtime/python/bin/python3")
            expected_mode = 0o555 if prefix + name in code else 0o444
            # Normalize only the fresh copy, never the signed original.
            need(mode & 0o7022 == 0 and bool(mode & 0o111) == (expected_mode == 0o555), "input-executable-scope")
            files[prefix + name] = (body, expected_mode)
    rows = [{"path": path, "sha256": digest(body), "size": len(body), "executable": mode == 0o555} for path, (body, mode) in sorted(files.items())]
    need(len(rows) <= MAX_FILES - 4, "installer-inventory-bound")
    inventory = canonical({"schemaVersion": 1, "release": selection.release, "runtimeManifestSha256": args.expected_manifest, "files": rows}) + b"\n"
    decode(inventory)
    need(sum(len(data) for data, _mode in files.values()) + len(inventory) + INSTALLATION_RECORD_LIMIT
         + len(MAINTENANCE_GATE_BYTES) + len(REGISTRATION_GATE_BYTES) <= MAX_BYTES, "installer-complete-byte-bound")
    files["install-inventory.json"] = (inventory, 0o444)
    write_tree(args.output, files)
    result = {"schemaVersion": 1, "packageRole": role, "inventorySha256": digest(inventory),
              "runtimeManifestSha256": args.expected_manifest, "androidSupportManifestSha256": support_sha,
              "residentImageSha256": expected_resident, "removerSha256": args.expected_remover, "fileCount": len(rows),
              "qualification": "fresh-install-input-not-installed"}
    if role == "ordinary-image":
        result["desktopImageSha256"] = expected_desktop
    return result


def scripts_command(args):
    selection = source_build_selection(command_target(args))
    need(type(args.expected_source) is str and re.fullmatch(r"[0-9a-f]{40}", args.expected_source), "installer-source-binding")
    source = tree(args.input)
    need("install-inventory.json" in source and digest(source["install-inventory.json"][0]) == args.expected_inventory, "installer-input-anchor")
    installer = read(args.installer)
    macho(installer, target=selection.target)
    scripts = {"input/" + path: value for path, value in source.items()}
    scripts["mrk-macos-install"] = (installer, 0o555)
    scripts["postinstall"] = (read(DESKTOP / "macos-installed-inputs/postinstall", 8192), 0o555)
    write_tree(args.output, scripts, root_mode=0o755)
    return {"schemaVersion": 1, "installerSha256": digest(installer), "inventorySha256": args.expected_inventory,
            "sourceCommit": args.expected_source, "packageIdentifier": PACKAGE_ID + ("-fixture" if args.fixture else ""),
            "qualification": "scripts-only-input-must-pass-package-archive-audit"}


def inflate(body, limit, *, gzip=False):
    stream = zlib.decompressobj(31 if gzip else 15)
    output = stream.decompress(body, limit + 1)
    need(len(output) <= limit and not stream.unconsumed_tail and stream.eof and not stream.unused_data, "compressed-data-bound")
    return output


def xar_members(body):
    need(len(body) >= 28, "xar-header")
    magic, header, version, compressed, expanded, checksum = struct.unpack_from(">IHHQQI", body)
    need(magic == 0x78617221 and header == 28 and version == 1 and compressed <= 1024 * 1024
         and expanded <= 2 * 1024 * 1024 and header + compressed <= len(body), "xar-header-bound")
    toc_bytes = inflate(body[header:header + compressed], expanded)
    need(len(toc_bytes) == expanded, "xar-toc-size")
    toc = ET.fromstring(toc_bytes)
    need(toc.tag == "xar" and len(toc.findall("toc")) == 1, "xar-toc")
    result = {}
    for member in toc.findall("toc/file"):
        name = member.findtext("name")
        need(name in ("Bom", "PackageInfo", "Scripts") and name not in result and member.findtext("type") == "file"
             and not member.findall("file"), "scripts-only-package-no-payload")
        length, offset, size = (member.findtext("data/" + key) for key in ("length", "offset", "size"))
        need(all(v is not None and re.fullmatch(r"[0-9]{1,10}", v) for v in (length, offset, size)), "xar-member-bound")
        length, offset, size = int(length), int(offset), int(size)
        start = header + compressed + offset
        need(length <= MAX_BYTES and size <= MAX_BYTES and start + length <= len(body), "xar-member-bound")
        packed = body[start:start + length]
        encoding = member.find("data/encoding")
        need(encoding is not None and encoding.get("style") in ("application/octet-stream", "application/x-gzip"), "xar-member-encoding")
        unpacked = packed if encoding.get("style") == "application/octet-stream" else inflate(packed, size, gzip=packed[:2] == b"\x1f\x8b")
        need(len(unpacked) == size, "xar-member-size")
        result[name] = unpacked
    need({"PackageInfo", "Scripts"} <= set(result), "scripts-package-required")
    return result


def _cpio_members(body, owner):
    # The only nonzero owner caller is original-package PREPARATION below.
    # Public cpio_members and final package acceptance are always fixed0:0.
    need(len(body) <= MAX_BYTES, "scripts-archive-bound")
    entries = {}
    root_seen = False
    offset = 0
    for _ in range(4098):
        start = offset
        magic = body[start:start + 6]
        if magic == b"070707":
            widths = [6, 6, 6, 6, 6, 6, 6, 11, 6, 11]
            cursor = start + 6
            values = []
            for width in widths:
                raw = body[cursor:cursor + width]
                need(len(raw) == width and re.fullmatch(b"[0-7]+", raw) is not None, "odc-header")
                values.append(int(raw, 8))
                cursor += width
            dev, ino, mode, uid, gid, links, rdev, mtime, namesize, size = values
            name_start = cursor
            align = 1
        elif magic == b"070701":
            need(start + 110 <= len(body), "newc-header")
            raw = body[start + 6:start + 110]
            need(re.fullmatch(b"[0-9a-fA-F]+", raw) is not None, "newc-header")
            values = [int(raw[i:i + 8], 16) for i in range(0, len(raw), 8)]
            ino, mode, uid, gid, links, mtime, size, devmaj, devmin, rdevmaj, rdevmin, namesize, check = values
            name_start = start + 110
            align = 4
        else:
            raise Refused("unsupported-scripts-cpio-format")
        need(1 <= namesize <= 1025 and size <= MAX_BYTES and name_start + namesize <= len(body), "cpio-entry-bound")
        name_bytes = body[name_start:name_start + namesize]
        need(name_bytes[-1:] == b"\0" and b"\0" not in name_bytes[:-1], "cpio-name")
        name = name_bytes[:-1].decode("ascii")
        data_start = (name_start + namesize + align - 1) // align * align
        offset = (data_start + size + align - 1) // align * align
        need(offset <= len(body), "cpio-data-bound")
        if name == "TRAILER!!!":
            need(size == 0 and not any(body[offset:]), "cpio-trailer")
            need(root_seen, "scripts-root-required")
            return entries
        if name in (".", "./"):
            need(not root_seen, "scripts-root-duplicate")
            need(stat.S_ISDIR(mode) and (uid, gid) == owner and stat.S_IMODE(mode) == 0o755 and size == 0, "scripts-root-owner-mode")
            root_seen = True
            continue
        if name.startswith("./"):
            name = name[2:]
        need(safe_path(name) and name not in entries and (uid, gid) == owner, "scripts-entry-owner")
        if stat.S_ISDIR(mode):
            need(size == 0 and stat.S_IMODE(mode) == 0o555, "scripts-directory-mode")
            entries[name] = (None, 0o555)
        else:
            need(stat.S_ISREG(mode) and links == 1 and stat.S_IMODE(mode) in (0o444, 0o555), "scripts-file-type-mode")
            entries[name] = (body[data_start:data_start + size], stat.S_IMODE(mode))
    raise Refused("scripts-entry-count")


def cpio_members(body):
    return _cpio_members(body, (0, 0))


def package_info(body, *, fixture=False, selection=None, remove=False):
    selection = selected_build(selection)
    need(type(fixture) is bool and type(remove) is bool and not (fixture and remove), "fixed-package-kind")
    identifier = REMOVE_PACKAGE_ID if remove else PACKAGE_ID + ("-fixture" if fixture else "")
    info = ET.fromstring(body)
    need(info.tag == "pkg-info" and info.get("identifier") == identifier
         and info.get("version") == selection.package_version and info.get("install-location") == "/" and info.get("auth") == "root", "scripts-package-identity")
    payload = info.find("payload")
    need(payload is None or payload.get("numberOfFiles") == "0", "installer-must-have-no-payload")
    hooks = info.find("scripts")
    need(hooks is not None and [child.tag for child in hooks] == ["postinstall"], "no-other-package-hooks")
    post = info.findall("scripts/postinstall")
    need(len(post) == 1 and post[0].get("file") in ("./postinstall", "postinstall"), "fixed-postinstall")
    return identifier


def original_package(scripts_path, package_path, *, fixture=False, selection=None, remove=False, expected_remover=None,
                     removal_fixture_role=None, removal_fixture_correlation=None, removal_fixture_binding=None):
    selection = selected_build(selection)
    owner = packager_ids()
    scripts = tree(scripts_path, packager=True)
    if remove:
        need(sha(expected_remover), "remove-program-anchor")
        expected_script = (read(DESKTOP / "macos-installed-inputs/remove-postinstall", 8192)
            if removal_fixture_role is None else removal_fixture_script_data(removal_fixture_role,
                correlation=removal_fixture_correlation, target=removal_fixture_binding, selection=selection))
        need(removal_fixture_role is not None or removal_fixture_correlation is removal_fixture_binding is None,
             "remove-script-purpose")
        need(set(scripts) == {"postinstall", REMOVER_NAME}
             and scripts["postinstall"] == (expected_script, 0o555), "remove-fixed-scripts-only")
        program, mode = scripts[REMOVER_NAME]
        need(mode == 0o555 and 0 < len(program) <= REMOVER_BYTES and digest(program) == expected_remover,
             "remove-program-correspondence")
        macho(program, target=selection.target)
    else:
        need(expected_remover is removal_fixture_role is removal_fixture_correlation is removal_fixture_binding is None,
             "remove-program-purpose")
    with parent(package_path) as (fd, name):
        package, info = read_at(fd, name, MAX_BYTES)
        need((info.st_uid, info.st_gid) == owner, "original-package-owner")
    members = xar_members(package)
    need(set(members) == {"PackageInfo", "Scripts"}, "original-package-roster")
    identifier = package_info(members["PackageInfo"], fixture=fixture, selection=selection, remove=remove)
    archive = members["Scripts"]
    if archive[:2] == b"\x1f\x8b":
        archive = inflate(archive, MAX_BYTES, gzip=True)
    actual = _cpio_members(archive, owner)
    expected = {**scripts, **{name: (None, 0o555) for name in directories(scripts)}}
    need(actual == expected, "complete-original-scripts-correspondence")
    return scripts, package, members, identifier, owner


def prepare_package_command(args):
    selection = source_build_selection(command_target(args))
    removal = ({"expected_remover": getattr(args, "expected_remover", None), **removal_fixture_script_arguments(args)}
               if getattr(args, "remove", False) else {})
    scripts, package, members, identifier, owner = original_package(args.scripts, args.package, fixture=args.fixture, selection=selection, remove=getattr(args, "remove", False), **removal)
    # This is not archive extraction: only validated, unchanged PackageInfo
    # DATA is copied to a fixed literal name in an exclusively-created root.
    write_tree(args.output, {"PackageInfo": (members["PackageInfo"], 0o444)}, root_mode=0o700)
    return {"schemaVersion": 1, "originalPackageSha256": digest(package), "originalPackageSize": len(package),
            "packageInfoSha256": digest(members["PackageInfo"]), "packageIdentifier": identifier,
            "scriptFileCount": len(scripts), "packagerUid": owner[0], "packagerGid": owner[1],
            "qualification": "caller-owned-original-prepared-not-root-audited-or-installed"}


def package_format_input_command(args):
    files = {"input/readonly.txt": (b"MRK_MACOS_PACKAGE_FORMAT_DATA\n", 0o444),
             "postinstall": (b"#!/bin/sh\n# Inert archive-format input; never execute.\nexit 97\n", 0o555)}
    write_tree(args.output, files, root_mode=0o755)
    return {"schemaVersion": 1, "scriptFileCount": len(files), "qualification": "tiny-inert-package-format-input-never-execute"}


def audit_command(args):
    selection = source_build_selection(command_target(args))
    removal = ({"expected_remover": getattr(args, "expected_remover", None), **removal_fixture_script_arguments(args)}
               if getattr(args, "remove", False) else {})
    scripts, original, original_members, identifier, _owner = original_package(args.scripts, args.original_package, fixture=args.fixture, selection=selection, remove=getattr(args, "remove", False), **removal)
    package = read(args.package)
    members = xar_members(package)
    need(set(members) == {"PackageInfo", "Scripts"}, "final-package-roster")
    need(members["PackageInfo"] == original_members["PackageInfo"], "package-info-bytes-changed")
    package_info(members["PackageInfo"], fixture=args.fixture, selection=selection, remove=getattr(args, "remove", False))
    archive = members["Scripts"]
    if archive[:2] == b"\x1f\x8b":
        archive = inflate(archive, MAX_BYTES, gzip=True)
    actual = cpio_members(archive)
    expected = {**scripts, **{name: (None, 0o555) for name in directories(scripts)}}
    need(actual == expected, "complete-root-owned-scripts-correspondence")
    return {"schemaVersion": 1, "packageSha256": digest(package), "packageSize": len(package),
            "originalPackageSha256": digest(original), "packageInfoSha256": digest(members["PackageInfo"]),
            "packageIdentifier": identifier, "scriptFileCount": len(scripts), "finalDestinationPayloadEntries": 0,
            "qualification": "scripts-only-package-audited-not-installed-or-GUI-qualified"}


# Fixed Install-only product envelope. The existing flat component/Remove
# parsers above remain unchanged. These are the same closed productbuild
# forms observed by macos_e2_native_fixture.context_xar/context_product; this
# reader adds only the one SOURCE-selected presentation resource, not an
# extraction API, alternate payload, package choice or general XML policy.
INSTALL_COMPONENT = "MobileReleaseKit.pkg"
INSTALL_PRESENTATION = ("Distribution.xml", "InstallerReadMe.html")
INSTALL_PRESENTATION_LIMIT = 8192


def install_product_sources(selection):
    selection = selected_build(selection)
    definition, readme = (read(DESKTOP / "macos-installed-inputs" / name, INSTALL_PRESENTATION_LIMIT)
                          for name in INSTALL_PRESENTATION)
    token = b"__MRK_PACKAGE_VERSION__"
    need(definition.count(token) == 1, "install-product-source-version")
    definition = definition.replace(token, selection.package_version.encode("ascii"))
    need(0 < len(definition) <= INSTALL_PRESENTATION_LIMIT and 0 < len(readme) <= INSTALL_PRESENTATION_LIMIT,
         "install-product-source-bound")
    return definition, readme


def install_product_xml(body):
    need(type(body) is bytes and 0 < len(body) <= INSTALL_PRESENTATION_LIMIT, "install-product-xml")
    try:
        text = body.decode("utf-8", "strict")
    except UnicodeError as error:
        raise Refused("install-product-xml") from error
    # Parse only the text whose grammar was checked. Byte-parser encoding
    # autodetection must not hide a zero-interleaved DTD/entity declaration.
    need("\0" not in text and "<!DOCTYPE" not in text.upper()
         and "<!ENTITY" not in text.upper(), "install-product-xml")
    value = ET.fromstring(text)
    need(sum(1 for _ in value.iter()) <= 64, "install-product-xml")
    return value


def install_product_distribution(body, expected):
    def tree(element):
        return (element.tag, tuple(sorted(element.attrib.items())), (element.text or "").strip(),
                tuple((tree(child), (child.tail or "").strip()) for child in element))
    actual = install_product_xml(body)
    references = actual.findall("pkg-ref")
    # Exact macOS26 context-product observations only, not a general duplicate
    # reference merge or authorization to add an action. The metadata reference
    # has no payload/bundle and is the final child of the original definition.
    if len(references) == 2:
        metadata = references[1]
        need(list(actual)[-1] is metadata and metadata.attrib == {"id": PACKAGE_ID}
             and not (metadata.text or "").strip() and not (metadata.tail or "").strip()
             and len(metadata) == 1, "install-product-distribution")
        bundle = metadata[0]
        need(bundle.tag == "bundle-version" and not bundle.attrib and not list(bundle)
             and not (bundle.text or "").strip() and not (bundle.tail or "").strip(),
             "install-product-distribution")
        actual.remove(metadata)
    for reference in actual.findall("pkg-ref"):
        for name, value in (("installKBytes", "0"), ("updateKBytes", "0"), ("onConclusion", "None")):
            if name in reference.attrib:
                need(reference.attrib.pop(name) == value, "install-product-distribution")
        if (reference.text or "").strip() == "#" + INSTALL_COMPONENT:
            reference.text = INSTALL_COMPONENT
    need(tree(actual) == tree(install_product_xml(expected)), "install-product-distribution")


def install_product_members(body):
    """Closed outer Install XAR using the existing context's member syntax.

    Native signature/timestamp/staple verification and final whole-P binding
    remain mandatory in the existing owner. Signature/ticket bytes are not
    filesystem members and are not treated as authority by this DATA audit.
    """
    need(type(body) is bytes and 28 <= len(body) <= MAX_BYTES, "install-product-xar-bound")
    magic, header, version, compressed, expanded, checksum = struct.unpack_from(">IHHQQI", body)
    algorithms = {1: ("sha1", 20), 3: ("sha256", 32), 4: ("sha512", 64)}
    need((magic, header, version) == (0x78617221, 28, 1) and 0 < compressed <= 1024 * 1024
         and 0 < expanded <= 2 * 1024 * 1024 and header + compressed <= len(body)
         and checksum in algorithms, "install-product-xar-header")
    packed_toc = body[header:header + compressed]
    toc_body = inflate(packed_toc, expanded)
    need(len(toc_body) == expanded, "install-product-xar-toc")
    try:
        toc_text = toc_body.decode("utf-8", "strict")
    except UnicodeError as error:
        raise Refused("install-product-xar-toc") from error
    need("\0" not in toc_text and "<!DOCTYPE" not in toc_text.upper()
         and "<!ENTITY" not in toc_text.upper(), "install-product-xar-toc")
    root = ET.fromstring(toc_text)
    need(root.tag == "xar" and not root.attrib and [child.tag for child in root] == ["toc"],
         "install-product-xar-toc")
    toc = root[0]
    need(not toc.attrib and all(child.tag in ("creation-time", "checksum", "file", "signature", "x-signature") for child in toc)
         and len(toc.findall("checksum")) == 1 and len(toc.findall("creation-time")) <= 1
         and len(toc.findall("signature")) <= 1 and len(toc.findall("x-signature")) <= 1,
         "install-product-xar-toc")
    for element in toc.findall("creation-time"):
        need(not element.attrib and not list(element), "install-product-xar-toc")
    for tag in ("signature", "x-signature"):
        for element in toc.findall(tag):
            # Existing native productsign/pkgutil own this opaque signature
            # metadata. It may not hide another filesystem member/tree.
            need(not any(child.tag == "file" for child in element.iter()), "install-product-xar-toc")
    algorithm, checksum_size = algorithms[checksum]
    check = toc.find("checksum")
    need(check.attrib == {"style": algorithm} and [child.tag for child in check] == ["offset", "size"]
         and check.findtext("offset") == "0" and check.findtext("size") == str(checksum_size)
         and all(not child.attrib and not list(child) for child in check), "install-product-xar-checksum")
    heap = header + compressed
    need(body[heap:heap + checksum_size] == hashlib.new(algorithm, packed_toc).digest(),
         "install-product-xar-checksum")
    allowed = {"Distribution", "Resources", "Resources/InstallerReadMe.html", INSTALL_COMPONENT,
               INSTALL_COMPONENT + "/PackageInfo", INSTALL_COMPONENT + "/Scripts"}
    queue = [(element, "") for element in toc.findall("file")]
    members, directories, identifiers, intervals, expanded_bytes = {}, set(), set(), [], 0
    while queue:
        need(len(queue) + len(identifiers) <= 6, "install-product-xar-count")
        element, parent = queue.pop(0)
        file_id = element.get("id")
        need(set(element.attrib) == {"id"} and type(file_id) is str
             and re.fullmatch(r"[1-9][0-9]{0,3}", file_id) and file_id not in identifiers,
             "install-product-xar-id")
        identifiers.add(file_id)
        metadata = {"name", "type", "data", "file", "mode", "uid", "gid", "user", "group",
                    "atime", "ctime", "mtime", "inode", "deviceno", "FinderCreateTime"}
        need(all(child.tag in metadata for child in element), "install-product-xar-metadata")
        names, types = element.findall("name"), element.findall("type")
        repeated = (len(names) == 2 and len(types) == 1 and types[0].text == "file"
                    and len(element.findall("data")) == 1 and not element.findall("file")
                    and all(not node.attrib and not list(node) and not (node.tail or "").strip() for node in names)
                    and type(names[0].text) is str and names[0].text == names[1].text
                    and parent + names[0].text in allowed)
        need(len(types) == 1 and (len(names) == 1 or repeated)
             and all(len(element.findall(tag)) <= 1 for tag in metadata - ({"file", "name"} if repeated else {"file"})),
             "install-product-xar-duplicate")
        for child in element:
            if child.tag == "FinderCreateTime":
                need(not child.attrib and not (child.text or "").strip() and not (child.tail or "").strip()
                     and len(child) == 2 and {item.tag for item in child} == {"time", "nanoseconds"}
                     and all(not item.attrib and not list(item) and not (item.tail or "").strip() for item in child)
                     and type(child.findtext("time")) is str
                     and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}", child.findtext("time"))
                     and type(child.findtext("nanoseconds")) is str
                     and re.fullmatch(r"0|[1-9][0-9]{0,8}", child.findtext("nanoseconds")),
                     "install-product-xar-metadata")
            elif child.tag not in ("file", "data"):
                need(not child.attrib and not list(child), "install-product-xar-metadata")
            if child.tag in ("inode", "deviceno"):
                need(type(child.text) is str and re.fullmatch(r"0|-?[1-9][0-9]{0,19}", child.text),
                     "install-product-xar-metadata")
        name, kind = element.findtext("name"), element.findtext("type")
        need(type(name) is str and name and "/" not in name and "\\" not in name and name not in (".", ".."),
             "install-product-xar-name")
        name = parent + name
        need(name in allowed and name not in members and name not in directories, "install-product-xar-roster")
        if kind == "directory":
            need(not parent and name in ("Resources", INSTALL_COMPONENT) and element.find("data") is None
                 and len(element.findall("file")) == (1 if name == "Resources" else 2), "install-product-xar-directory")
            directories.add(name)
            queue.extend((child, name + "/") for child in element.findall("file"))
            continue
        need(kind == "file" and not element.findall("file") and len(element.findall("data")) == 1,
             "install-product-xar-file")
        data = element.find("data")
        required, optional = {"length", "offset", "size", "encoding"}, {"archived-checksum", "extracted-checksum"}
        need(not data.attrib and required <= {child.tag for child in data} <= required | optional
             and len({child.tag for child in data}) == len(data), "install-product-xar-data")
        texts = [data.findtext(key) for key in ("length", "offset", "size")]
        need(all(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,9}", value) for value in texts)
             and all(not data.find(key).attrib and not list(data.find(key)) for key in ("length", "offset", "size")),
             "install-product-xar-range")
        length, offset, size = map(int, texts)
        limit = INSTALL_PRESENTATION_LIMIT if name in ("Distribution", "Resources/InstallerReadMe.html") else MAX_BYTES
        need(0 < length <= MAX_BYTES and 0 < size <= limit and expanded_bytes + size <= MAX_BYTES
             and offset >= checksum_size and heap + offset + length <= len(body)
             and all(offset + length <= low or offset >= high for low, high in intervals), "install-product-xar-range")
        encoding = data.find("encoding")
        need(encoding.attrib in ({"style": "application/octet-stream"}, {"style": "application/x-gzip"})
             and not list(encoding) and not (encoding.text or "").strip(), "install-product-xar-encoding")
        packed = body[heap + offset:heap + offset + length]
        decoded = packed if encoding.get("style") == "application/octet-stream" else inflate(packed, size, gzip=packed[:2] == b"\x1f\x8b")
        need(len(decoded) == size, "install-product-xar-size")
        for tag, content in (("archived-checksum", packed), ("extracted-checksum", decoded)):
            item = data.find(tag)
            if item is not None:
                need(set(item.attrib) == {"style"} and item.get("style") in ("sha1", "sha256", "sha512")
                     and not list(item) and item.text == hashlib.new(item.get("style"), content).hexdigest(),
                     "install-product-xar-member-checksum")
        members[name] = decoded
        expanded_bytes += size
        intervals.append((offset, offset + length))
    presentation = {"Distribution", "Resources/InstallerReadMe.html"}
    need(set(members) == presentation | {INSTALL_COMPONENT}
         or set(members) == presentation | {INSTALL_COMPONENT + "/PackageInfo", INSTALL_COMPONENT + "/Scripts"},
         "install-product-xar-roster")
    need(directories == ({"Resources"} if INSTALL_COMPONENT in members else {"Resources", INSTALL_COMPONENT}),
         "install-product-xar-directory")
    return members


def prepare_install_product_command(args):
    definition, readme = install_product_sources(source_build_selection(command_target(args)))
    write_tree(args.output, {"Distribution": (definition, 0o444),
                            "resources/InstallerReadMe.html": (readme, 0o444)}, root_mode=0o700)
    return {"schemaVersion": 1, "distributionSha256": digest(definition), "readMeSha256": digest(readme),
            "qualification": "fixed-install-presentation-prepared-not-built-or-GUI-qualified"}


def audit_install_product_command(args):
    need(getattr(args, "fixture", False) is False and getattr(args, "remove", False) is False,
         "fixed-install-product-purpose")
    selection = source_build_selection(command_target(args))
    scripts, original, original_members, identifier, _owner = original_package(
        args.scripts, args.original_package, selection=selection)
    definition, readme = install_product_sources(selection)
    package = read(args.package)
    members = install_product_members(package)
    install_product_distribution(members["Distribution"], definition)
    need(members["Resources/InstallerReadMe.html"] == readme, "install-product-readme")
    if INSTALL_COMPONENT in members:
        component = xar_members(members[INSTALL_COMPONENT])
    else:
        component = {name: members[INSTALL_COMPONENT + "/" + name] for name in ("PackageInfo", "Scripts")}
    need(set(component) == {"PackageInfo", "Scripts"}
         and component["PackageInfo"] == original_members["PackageInfo"], "install-product-component")
    package_info(component["PackageInfo"], selection=selection)
    archive = component["Scripts"]
    if archive[:2] == b"\x1f\x8b":
        archive = inflate(archive, MAX_BYTES, gzip=True)
    actual = cpio_members(archive)
    expected = {**scripts, **{name: (None, 0o555) for name in directories(scripts)}}
    need(actual == expected, "complete-root-owned-scripts-correspondence")
    return {"schemaVersion": 1, "packageSha256": digest(package), "packageSize": len(package),
            "originalPackageSha256": digest(original), "packageInfoSha256": digest(component["PackageInfo"]),
            "packageIdentifier": identifier, "scriptFileCount": len(scripts), "finalDestinationPayloadEntries": 0,
            "productDistributionSha256": digest(members["Distribution"]), "productReadMeSha256": digest(readme),
            "qualification": "fixed-install-product-and-scripts-audited-not-installed-or-GUI-qualified"}


def remove_scripts_command(args):
    selection = source_build_selection(command_target(args))
    fixture_arguments = removal_fixture_script_arguments(args)
    if fixture_arguments:
        need(fixture_arguments["removal_fixture_role"] == "abrupt", "remove-script-fixture-role")
        return removal_fixture_scripts_command(argparse.Namespace(target=selection.target, role="abrupt",
            correlation=None, target_binding=None, remover=args.remover, expected_remover=args.expected_remover,
            output=args.output))
    need(sha(args.expected_remover), "remove-program-anchor")
    body = read(DESKTOP / "macos-installed-inputs/remove-postinstall", 8192)
    with parent(args.remover) as (fd, name):
        program, info = read_at(fd, name, REMOVER_BYTES)
        need(stat.S_IMODE(info.st_mode) == 0o555 and digest(program) == args.expected_remover,
             "remove-program-correspondence")
        macho(program, target=selection.target)
    write_tree(args.output, {"postinstall": (body, 0o555), REMOVER_NAME: (program, 0o555)}, root_mode=0o755)
    return {"schemaVersion": 1, "packageIdentifier": REMOVE_PACKAGE_ID, "packageVersion": selection.package_version,
            "postinstallSha256": digest(body), "removerSha256": digest(program), "scriptFileCount": 2,
            "destinationPayloadEntries": 0, "qualification": "remove-scripts-staged-not-executed"}


# Two NONSHIPPING real-root cases. DATA below never authorizes a native effect,
# accepts a cleanup result on its own, or changes any ordinary Remove template.
REMOVAL_FIXTURE_CASES = ("ordinary", "abrupt")
REMOVAL_FIXTURE_PHASES = {
    "ordinary": ("before", "after-cancel", "terminal"),
    "abrupt": ("before", "after-cut", "terminal"),
}
REMOVAL_FIXTURE_FEATURES = {
    "abrupt": "macos-installed-removal-abrupt-fixture",
    "observer": "macos-installed-removal-observer",
}
REMOVAL_FIXTURE_COMMON = ("sourceCommit", "target", "release", "inventorySha256", "packageSha256",
                          "removeDescriptorSha256", "removeSignatureSha256")
REMOVAL_FIXTURE_SCRIPT_PREFIX = b'''#!/bin/sh
# NONSHIPPING: one fixed original supervisor; no test payload or root override.
set -eu
umask 077
[ "$#" -eq 3 ] || exit 78
[ "$3" = "/" ] || exit 78
case "$1" in /*) ;; *) exit 78 ;; esac
case "$0" in
    ./postinstall) scripts=. ;;
    /*/postinstall) scripts=${0%/*} ;;
    *) exit 78 ;;
esac
cd -P "$scripts" 2>/dev/null || exit 78
'''
REMOVAL_FIXTURE_ABRUPT_SCRIPT = (REMOVAL_FIXTURE_SCRIPT_PREFIX
    + b'exec ./mrk-macos-remove --fixture-supervise "$1"\n')


def removal_fixture_case_data(case):
    need(type(case) is str and case in REMOVAL_FIXTURE_CASES, "removal-fixture-fixed-case")
    return REMOVAL_FIXTURE_PHASES[case]


def removal_fixture_mount_path(correlation, role):
    need(maintenance_hex(correlation, 32) and type(role) is str
         and role in ("install", "target", "observers"), "removal-fixture-fixed-mount")
    return Path("/Volumes") / ("MRK-Removal-" + correlation + "-" + role)


def removal_fixture_binding_data(value, *, selection=None):
    selection = selected_build(selection)
    need(selection.target == ARM_TARGET and type(value) is dict and set(value) == set(REMOVAL_FIXTURE_COMMON)
         and maintenance_hex(value["sourceCommit"], 40) and value["target"] == ARM_TARGET
         and value["release"] == selection.release
         and all(maintenance_hex(value[key], 64) for key in REMOVAL_FIXTURE_COMMON[3:]),
         "removal-fixture-binding")
    return value


def removal_fixture_script_data(role, *, correlation=None, target=None, selection=None):
    """Closed SOURCE form only. Never accept arbitrary expected script bytes."""
    if role == "abrupt":
        need(correlation is None and target is None, "removal-fixture-abrupt-script-purpose")
        return REMOVAL_FIXTURE_ABRUPT_SCRIPT
    need(type(role) is str and role in ("observer-before", "observer-after-cancel", "observer-after-cut", "observer-terminal"),
         "removal-fixture-script-role")
    target = removal_fixture_binding_data(target, selection=selection)
    package = removal_fixture_mount_path(correlation, "target") / "Remove.pkg"
    # All interpolated characters are from fixed ASCII components or nonzero
    # lowercase hex, not a shell-quoting function or caller-selected location.
    body = (REMOVAL_FIXTURE_SCRIPT_PREFIX.replace(b"one fixed original supervisor", b"one fixed readonly observer")
        + ("exec ./mrk-macos-remove --fixture-observe-" + role[len("observer-"):]
           + ' "$1" ' + " ".join("'" + item + "'" for item in (str(package), target["packageSha256"],
               target["removeDescriptorSha256"], target["removeSignatureSha256"])) + "\n").encode("ascii"))
    need(len(body) <= 1024, "removal-fixture-script-bound")
    return body


def removal_fixture_cargo_artifact(messages, binary, target_dir, body, *, role, target=ARM_TARGET):
    """Actual compiled fixed feature graph; no signing/execution authority."""
    need(target == ARM_TARGET and role in REMOVAL_FIXTURE_FEATURES, "removal-fixture-cargo-role")
    root, binary, target_dir = DESKTOP / "src-tauri", Path(binary), Path(target_dir)
    need(binary.is_absolute() and target_dir.is_absolute()
         and all(part not in (".", "..") for part in binary.parts + target_dir.parts)
         and binary == target_dir / target / "release" / REMOVER_NAME
         and type(body) is bytes and 32 <= len(body) <= REMOVER_BYTES, "removal-fixture-cargo-output")
    records = cargo_records(messages)
    matches = [row for row in records if row["target"].get("name") == REMOVER_NAME
               or str(binary) in row.get("filenames", []) or row.get("executable") == str(binary)]
    need(len(matches) == 1, "removal-fixture-cargo-one-binary")
    row, features = matches[0], sorted(["macos-installed-remover", REMOVAL_FIXTURE_FEATURES[role]])
    kind = row["target"]
    need(row.get("package_id") == "path+" + root.as_uri() + "#mobile-release-kit-desktop@0.1.1"
         and row.get("manifest_path") == str(root / "Cargo.toml") and kind.get("name") == REMOVER_NAME
         and kind.get("kind") == ["bin"] and kind.get("crate_types") == ["bin"]
         and kind.get("src_path") == str(root / "src/bin/macos_install.rs") and kind.get("edition") == "2021"
         and row.get("executable") == str(binary) and row.get("filenames") == [str(binary)], "removal-fixture-cargo-source")
    cargo_profile(row, test=False)
    cargo_features(row, features)
    cargo_library(records, root, "mobile-release-kit-desktop", "mobile_release_desktop", features, test=False)
    cargo_library(records, DESKTOP / "native/macos-installed-native", "mrk-macos-installed-native",
                  "mrk_macos_installed_native", ["default"], test=False)
    need(not any(item is not row and item["target"].get("kind") in
                 (["bin"], ["test"], ["example"], ["bench"], ["cdylib"]) for item in records), "removal-fixture-no-mixed-graph")
    macho(body, target=target)
    return {"schemaVersion": 1, "role": role, "target": target, "features": features,
            "binarySha256": digest(body), "cargoMessagesSha256": digest(messages),
            "qualification": "source-bound-nonshipping-program-not-signed-or-executed"}


def removal_fixture_scripts_command(args):
    selection = source_build_selection(command_target(args))
    need(selection.target == ARM_TARGET and sha(args.expected_remover), "removal-fixture-program-anchor")
    body = removal_fixture_script_data(args.role, correlation=args.correlation, target=args.target_binding, selection=selection)
    with parent(args.remover) as (fd, name):
        program, info = read_at(fd, name, REMOVER_BYTES, zero_flags=True)
        need(stat.S_IMODE(info.st_mode) == 0o555 and digest(program) == args.expected_remover,
             "removal-fixture-program-correspondence")
        macho(program, target=ARM_TARGET)
    write_tree(args.output, {"postinstall": (body, 0o555), REMOVER_NAME: (program, 0o555)}, root_mode=0o755)
    return {"schemaVersion": 1, "role": args.role, "packageIdentifier": REMOVE_PACKAGE_ID,
            "packageVersion": selection.package_version, "postinstallSha256": digest(body),
            "removerSha256": digest(program), "scriptFileCount": 2, "destinationPayloadEntries": 0,
            "qualification": "nonshipping-fixed-scripts-staged-not-executed"}


def removal_fixture_export_name(kind, descriptor, *, role=None):
    need(maintenance_hex(descriptor, 64), "removal-fixture-export-binding")
    if kind == "observer":
        need(role is None, "removal-fixture-export-role")
        name, limit = "removal-observer-v1-" + descriptor + ".json", 65536
    elif kind == "effects":
        need(role is None, "removal-fixture-export-role")
        name, limit = "removal-fixture-effects-v1-" + descriptor + ".json", 4096
    else:
        need(kind == "supervisor" and role in ("live", "resume"), "removal-fixture-export-role")
        name, limit = "removal-fixture-supervisor-v1-" + role + "-" + descriptor + ".json", 4096
    return INSTALL_ROOT.parent / name, limit


def removal_fixture_export_data(body, kind, expected, *, role=None, selection=None):
    expected = removal_fixture_binding_data(expected, selection=selection)
    _path, limit = removal_fixture_export_name(kind, expected["removeDescriptorSha256"], role=role)
    need(type(body) is bytes and 0 < len(body) <= limit and body.endswith(b"\n"), "removal-fixture-export-bound")
    value = maintenance_json(body, limit)
    common = set(REMOVAL_FIXTURE_COMMON) | {"schemaVersion", "kind", "transportState"}
    if kind == "effects":
        fields = common | {"requestId", "rootNonce", "genesisSnapshotSha256", "previousTipSha256", "prefix",
                           "returnedUnlinks", "appRootUnlinkOrdinal"}
        need(set(value) == fields and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
             and value["kind"] == "removal-fixture-effects-v1"
             and value["transportState"] == "pending-original-child-exit"
             and all(value[key] == expected[key] for key in REMOVAL_FIXTURE_COMMON)
             and all(maintenance_hex(value[key], 32) for key in ("requestId", "rootNonce"))
             and all(maintenance_hex(value[key], 64) for key in ("genesisSnapshotSha256", "previousTipSha256"))
             and type(value["prefix"]) is int and value["prefix"] == 4
             and type(value["returnedUnlinks"]) is int and 0 < value["returnedUnlinks"] <= 4096
             and type(value["appRootUnlinkOrdinal"]) is int
             and value["appRootUnlinkOrdinal"] == value["returnedUnlinks"], "removal-fixture-effects-fields")
    else:
        need(kind == "supervisor", "removal-fixture-export-purpose")
        fields = common | {"role", "actualChildReturncode", "originalChildWaitObserved", "effectsSha256"}
        need(set(value) == fields and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
             and value["kind"] == "removal-fixture-supervisor-v1" and value["role"] == role
             and value["transportState"] == "pending-original-installer-exit"
             and all(value[key] == expected[key] for key in REMOVAL_FIXTURE_COMMON)
             and type(value["actualChildReturncode"]) is int
             and value["actualChildReturncode"] == (86 if role == "live" else 0)
             and value["originalChildWaitObserved"] is True
             and (value["effectsSha256"] is None if role == "live" else maintenance_hex(value["effectsSha256"], 64)),
             "removal-fixture-supervisor-fields")
    return value


def removal_fixture_observer_data(body, expected, own, phase, *, selection=None):
    expected = removal_fixture_binding_data(expected, selection=selection)
    need(phase in ("before", "after-cancel", "after-cut", "terminal") and type(own) is dict
         and set(own) == {"packageSha256", "descriptorSha256", "signatureSha256"}
         and all(maintenance_hex(v, 64) for v in own.values()), "removal-observer-expected")
    need(type(body) is bytes and 0 < len(body) <= 65536 and body.endswith(b"\n"), "removal-observer-bound")
    value = maintenance_json(body, 65536)
    fields = {"schemaVersion", "kind", "phase", "ownPackageSha256", "ownDescriptorSha256", "ownSignatureSha256",
              "binding", "rootIdentity", "installationStateSha256", "installedProducerSha256", "installedSignatureSha256",
              "payloadCommitmentSha256", "expectedFiles", "expectedDirectories", "presentFiles", "presentDirectories",
              "appPresent", "firstEligibleAbsent", "allPayloadAbsent", "lockMode", "archives", "transportState"}
    need(set(value) == fields and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["kind"] == "removal-observer-v1" and value["phase"] == phase and value["binding"] == expected
         and type(value["binding"]) is dict and set(value["binding"]) == set(REMOVAL_FIXTURE_COMMON)
         and (value["ownPackageSha256"], value["ownDescriptorSha256"], value["ownSignatureSha256"])
             == (own["packageSha256"], own["descriptorSha256"], own["signatureSha256"])
         and value["transportState"] == "pending-original-installer-exit"
         and value["lockMode"] == ("shared-readonly" if phase == "after-cancel" else "exclusive")
         and all(maintenance_hex(value[key], 64) for key in ("installationStateSha256", "installedProducerSha256",
                  "installedSignatureSha256", "payloadCommitmentSha256")), "removal-observer-binding")
    identity = value["rootIdentity"]
    need(type(identity) is list and len(identity) == 9
         and all(type(n) is str and re.fullmatch(r"0|-?[1-9][0-9]{0,19}", n) for n in identity), "removal-observer-root")
    actual = tuple(map(int, identity))
    need(-(1 << 31) <= actual[0] < 1 << 31 and 0 < actual[1] < 1 << 64
         and actual[2] == stat.S_IFDIR | 0o755 and 0 < actual[3] < 1 << 64
         and actual[4] == actual[5] == 0 and 0 <= actual[6] < 1 << 63
         and all(-(1 << 63) <= n < 1 << 63 for n in actual[7:]), "removal-observer-root")
    for kind in ("Files", "Directories"):
        need(type(value["expected" + kind]) is int and 0 < value["expected" + kind] <= MAX_FILES
             and type(value["present" + kind]) is int and 0 <= value["present" + kind] <= value["expected" + kind],
             "removal-observer-payload-count")
    need(all(type(value[key]) is bool for key in ("appPresent", "firstEligibleAbsent", "allPayloadAbsent"))
         and value["allPayloadAbsent"] == (value["presentFiles"] == value["presentDirectories"] == 0)
         and (not value["allPayloadAbsent"] or not value["appPresent"]), "removal-observer-payload-state")
    archives = value["archives"]
    need(type(archives) is list and len(archives) <= 64, "removal-observer-archive-bound")
    names, requests = [], set()
    keys = {"invocation", "snapshotSha256", "tipSha256", "prefix", "requestId", "rootNonce", "previousTipSha256",
            "genesisSnapshotSha256", "immutableControlsSha256"}
    for row in archives:
        need(type(row) is dict and set(row) == keys and maintenance_hex(row["invocation"], 32)
             and row["invocation"] == row["rootNonce"] and maintenance_hex(row["requestId"], 32)
             and row["requestId"] not in requests
             and type(row["prefix"]) is int and 1 <= row["prefix"] <= 4
             and all(maintenance_hex(row[key], 64) for key in ("tipSha256", "genesisSnapshotSha256", "immutableControlsSha256"))
             and (row["snapshotSha256"] is None or maintenance_hex(row["snapshotSha256"], 64))
             and (row["previousTipSha256"] is None or maintenance_hex(row["previousTipSha256"], 64))
             and ((row["snapshotSha256"] == row["genesisSnapshotSha256"] and row["previousTipSha256"] is None)
                  if row["snapshotSha256"] is not None else row["previousTipSha256"] is not None),
             "removal-observer-archive-row")
        names.append(row["invocation"])
        requests.add(row["requestId"])
    need(names == sorted(set(names)), "removal-observer-archive-order")
    return value


def removal_fixture_observation_pair(before, after, *, phase):
    """Compare already validated independent observations; DATA, never a lock."""
    need(phase in ("after-cancel", "after-cut", "terminal") and before["phase"] == "before" and after["phase"] == phase,
         "removal-observer-comparison-phase")
    need(not before["archives"] and before["appPresent"] and not before["firstEligibleAbsent"]
         and not before["allPayloadAbsent"]
         and (before["presentFiles"], before["presentDirectories"])
             == (before["expectedFiles"], before["expectedDirectories"]), "removal-observer-fresh-baseline")
    need(before["binding"] == after["binding"] and before["expectedFiles"] == after["expectedFiles"]
         and before["expectedDirectories"] == after["expectedDirectories"]
         and all(before[key] == after[key] for key in ("installationStateSha256", "installedProducerSha256", "installedSignatureSha256",
                                                        "payloadCommitmentSha256"))
         and all(before["rootIdentity"][index] == after["rootIdentity"][index] for index in (0, 1, 2, 4, 5)),
         "removal-observer-original-baseline")
    if phase == "after-cancel":
        need(after["archives"] == before["archives"] and after["rootIdentity"] == before["rootIdentity"]
             and after["payloadCommitmentSha256"] == before["payloadCommitmentSha256"]
             and (after["presentFiles"], after["presentDirectories"]) == (before["presentFiles"], before["presentDirectories"])
             and after["appPresent"] and not after["firstEligibleAbsent"] and not after["allPayloadAbsent"],
             "removal-cancel-unchanged")
    elif phase == "after-cut":
        need(len(after["archives"]) == 1 and after["archives"][0]["prefix"] == 3
             and after["archives"][0]["snapshotSha256"] is not None
             and after["firstEligibleAbsent"] and after["appPresent"] and not after["allPayloadAbsent"]
             and after["presentFiles"] + after["presentDirectories"]
                 == before["expectedFiles"] + before["expectedDirectories"] - 1,
             "removal-cut-one-real-effect")
    else:
        need(after["allPayloadAbsent"] and not after["appPresent"] and after["firstEligibleAbsent"],
             "removal-terminal-payload-absence")


def removal_fixture_terminal_data(case, before, middle, terminal, *, supervisor=None, effects=None, effects_sha=None):
    removal_fixture_case_data(case)
    removal_fixture_observation_pair(before, middle, phase="after-cancel" if case == "ordinary" else "after-cut")
    removal_fixture_observation_pair(before, terminal, phase="terminal")
    rows = terminal["archives"]
    if case == "ordinary":
        need(supervisor is None and effects is None and effects_sha is None and len(rows) == 1
             and rows[0]["prefix"] == 4 and rows[0]["snapshotSha256"] is not None,
             "removal-ordinary-terminal")
    else:
        need(type(supervisor) is dict and supervisor["role"] == "resume" and supervisor["actualChildReturncode"] == 0
             and supervisor["originalChildWaitObserved"] is True and type(effects) is dict
             and maintenance_hex(effects_sha, 64) and supervisor["effectsSha256"] == effects_sha
             and len(rows) == 2, "removal-resume-original-results")
        old = middle["archives"][0]
        actual_old = [row for row in rows if row["invocation"] == old["invocation"]]
        fresh = [row for row in rows if row["invocation"] != old["invocation"]]
        need(actual_old == [old] and len(fresh) == 1, "removal-resume-immutable-previous")
        new = fresh[0]
        need(new["prefix"] == 4 and new["snapshotSha256"] is None and new["requestId"] != old["requestId"]
             and new["rootNonce"] != old["rootNonce"] and new["previousTipSha256"] == old["tipSha256"]
             and new["genesisSnapshotSha256"] == old["genesisSnapshotSha256"]
             and effects["requestId"] == new["requestId"] and effects["rootNonce"] == new["rootNonce"]
             and effects["previousTipSha256"] == old["tipSha256"]
             and effects["genesisSnapshotSha256"] == old["genesisSnapshotSha256"]
             and effects["returnedUnlinks"] == before["expectedFiles"] + before["expectedDirectories"] - 1
             and effects["appRootUnlinkOrdinal"] == effects["returnedUnlinks"], "removal-resume-raw-tip-genesis-effects")
    return {"schemaVersion": 1, "case": case, "targetBinding": before["binding"],
            "archives": len(rows), "allPayloadAbsent": True,
            "abruptProcessCutObserved": case == "abrupt", "samePackageLinkedResumeObserved": case == "abrupt",
            "appRootLastReturnedEffectObserved": case == "abrupt", "powerLossQualified": False,
            "ordinaryOriginalFinalityRequired": True, "qualification": "pending-original-owner-finality"}


def removal_fixture_marker_data(body, correlation, case, name, *, complete=False):
    removal_fixture_case_data(case)
    need(maintenance_hex(correlation, 32) and name in (("launched", "cancel-observed") if case == "ordinary" else ("launched",))
         and type(body) is bytes and len(body) <= 128 and type(complete) is bool, "removal-ui-marker-shape")
    expected = ("mrk-removal-ui-v1\n" + correlation + "\n" + case + "\n" + name + "\n").encode("ascii")
    need(body == expected if complete else expected.startswith(body), "removal-ui-marker-bytes")
    return body == expected  # A scheduling hint only; not the writer's future close.


def removal_fixture_original_data(case, role, returncode, *, entered, returned, captures_settled):
    removal_fixture_case_data(case)
    expected = {"ordinary": {"live-cancel": 1, "live-continue": 0}, "abrupt": {"live-cut": 1, "resume": 0}}[case]
    need(role in expected and type(returncode) is int and returncode == expected[role]
         and entered is True and returned is True and captures_settled is True, "removal-fixture-original-outcome")
    return returncode


def observation_inventory(args, *, selection=None):
    selection = selected_build(selection) if selection is not None else source_build_selection(command_target(args))
    body = read(Path(args.input) / INSTALLATION_INVENTORY_NAME, 1024 * 1024)
    return observation_inventory_bytes(body, args.expected_inventory, args.expected_manifest, selection=selection)


def observation_inventory_bytes(body, expected_inventory, expected_manifest, *, selection=None):
    selection = selected_build(selection)
    need(type(body) is bytes and 0 < len(body) <= 1024 * 1024, "observation-inventory-bytes")
    need(sha(expected_inventory) and sha(expected_manifest) and digest(body) == expected_inventory, "observation-inventory-anchor")
    inventory = decode(body)
    need(type(inventory) is dict and set(inventory) == {"schemaVersion", "release", "runtimeManifestSha256", "files"}
         and type(inventory["schemaVersion"]) is int and inventory["schemaVersion"] == 1
         and inventory["release"] == selection.release and inventory["runtimeManifestSha256"] == expected_manifest
         and type(inventory["files"]) is list and 0 < len(inventory["files"]) <= MAX_FILES - 4, "observation-inventory-shape")
    rows = {}
    for row in inventory["files"]:
        need(type(row) is dict and set(row) == {"path", "sha256", "size", "executable"}
             and safe_path(row["path"]) and row["path"].startswith(("app/Contents/", "runtime/")) and row["path"] not in rows
             and sha(row["sha256"]) and type(row["size"]) is int and 0 <= row["size"] <= MAX_BYTES
             and type(row["executable"]) is bool
             and row["executable"] == (row["path"] in ("app/" + ENTRY_BINARY, "app/" + APP_BINARY, "app/" + VAULT_HELPER, "app/" + ANDROID_HELPER,
                                                     "app/" + DESKTOP_IMAGE, "app/" + RESIDENT_IMAGE, "app/" + REMOVER, "runtime/python/bin/python3")), "observation-inventory-row")
        rows[row["path"]] = row
    need(("app/" + ANDROID_HELPER in rows) == ("app/" + ANDROID_SERVICE_PLIST in rows)
         == ("app/" + RESIDENT_IMAGE in rows)
         and ("app/" + DESKTOP_IMAGE not in rows or "app/" + RESIDENT_IMAGE in rows), "android-service-input-pair")
    need(list(rows) == sorted(rows) and sum(row["size"] for row in rows.values()) <= MAX_BYTES
         and {"app/" + ENTRY_BINARY, "app/" + APP_BINARY, "app/" + VAULT_HELPER, "app/Contents/Info.plist", "app/" + PAYLOAD_INFO,
              "runtime/python/bin/python3", "runtime/manifest.json"} <= set(rows)
         and rows["runtime/manifest.json"]["sha256"] == expected_manifest, "observation-inventory-required")
    directories(rows)
    return rows


def installer_log_binding(args):
    need(type(args.fixture) is bool and type(args.expected_source) is str
         and re.fullmatch(r"[0-9a-f]{40}", args.expected_source)
         and sha(args.expected_inventory) and sha(args.expected_manifest)
         and type(args.run_id) is str and re.fullmatch(r"[1-9][0-9]{0,23}", args.run_id)
         and type(args.run_attempt) is str and re.fullmatch(r"[1-9][0-9]{0,5}", args.run_attempt), "log-input-binding")
    package = os.fspath(args.package)
    request_id = getattr(args, "request_id", None)
    need(not args.fixture or request_id is None, "log-input-binding")
    basename = "MobileReleaseKit-InstallerFixture.pkg" if args.fixture else distribution_request_name(request_id)
    dirname = "package-fixture-final" if args.fixture else "package-mount"
    need(type(package) is str and package.startswith("/") and len(os.fsencode(package)) <= 4096
         and all(ord(c) >= 32 and ord(c) != 127 for c in package)
         and all(part and part not in (".", "..") for part in package.split("/")[1:])
         and package.split("/")[-2:] == [dirname, basename], "log-input-binding")
    return {"packageKind": "fixture" if args.fixture else "ordinary", "packageIdentifier": PACKAGE_ID + ("-fixture" if args.fixture else ""),
            "packagePath": package, "sourceCommit": args.expected_source, "inventorySha256": args.expected_inventory,
            "runtimeManifestSha256": args.expected_manifest, "runId": args.run_id, "runAttempt": args.run_attempt,
            **({} if args.fixture else {"requestId": request_id})}


def installer_log_identity(info):
    identity = {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
                "uid": info.st_uid, "gid": info.st_gid, "links": info.st_nlink}
    validate_log_identity(identity)
    return identity


def validate_log_identity(identity):
    need(type(identity) is dict and set(identity) == {"device", "inode", "mode", "uid", "gid", "links"}
         and all(type(value) is int and value >= 0 for value in identity.values())
         and identity["inode"] > 0 and stat.S_ISREG(identity["mode"]) and identity["uid"] == 0
         and identity["links"] == 1 and identity["mode"] & 0o022 == 0, "log-file-policy")


@contextlib.contextmanager
def installer_log_file():
    # A fresh nonroot read of the one fixed physical path, not an original FD
    # held across Installer and not permission to inspect rotated/other logs.
    with parent(INSTALL_LOG) as (outer, name):
        named = installer_log_identity(os.stat(name, dir_fd=outer, follow_symlinks=False))
        original = os.open(name, READ_FLAGS, dir_fd=outer)
        try:
            info = os.fstat(original)
            need(installer_log_identity(info) == named, "log-file-identity")
            yield original, outer, name, info
        finally:
            close_once(original)


def positioned_log_read(fd, offset, size):
    need(type(offset) is int and offset >= 0 and type(size) is int and 0 <= size <= LOG_INTERVAL_BYTES, "log-interval-bound")
    body = bytearray()
    while len(body) < size:
        block = os.pread(fd, min(65536, size - len(body)), offset + len(body))
        need(bool(block), "log-read-incomplete")
        body.extend(block)
    return bytes(body)


def log_growth(fd, outer, name, identity, end):
    current = os.fstat(fd)
    named = os.stat(name, dir_fd=outer, follow_symlinks=False)
    need(installer_log_identity(current) == installer_log_identity(named) == identity, "log-file-identity")
    need(current.st_size >= end and named.st_size >= current.st_size, "log-truncated")
    return named.st_size - end


def make_log_cursor(binding, identity, offset, tail, growth):
    need(type(offset) is int and 0 <= offset < 2 ** 63
         and type(tail) is bytes and len(tail) == min(offset, LOG_TAIL_BYTES), "log-cursor-offset")
    need(not offset or tail.endswith(b"\n"), "log-incomplete-boundary")
    cursor = {"schemaVersion": 1, "kind": "installer-log-cursor", "state": "observed", "binding": binding,
              "logPath": str(INSTALL_LOG), "identity": identity, "offsetBytes": offset,
              "precedingTailBytes": len(tail), "precedingTailSha256": digest(tail),
              "growthBeyondSnapshotBytes": growth, "authority": LOG_AUTHORITY}
    validate_log_cursor(cursor, binding)
    return cursor


def validate_log_cursor(cursor, binding):
    need(type(cursor) is dict and set(cursor) == {"schemaVersion", "kind", "state", "binding", "logPath", "identity",
         "offsetBytes", "precedingTailBytes", "precedingTailSha256", "growthBeyondSnapshotBytes", "authority"}
         and type(cursor["schemaVersion"]) is int and cursor["schemaVersion"] == 1
         and cursor["kind"] == "installer-log-cursor" and cursor["state"] == "observed"
         and cursor["logPath"] == str(INSTALL_LOG) and cursor["authority"] == LOG_AUTHORITY, "log-cursor-shape")
    need(cursor["binding"] == binding, "log-cursor-binding")
    validate_log_identity(cursor["identity"])
    offset = cursor["offsetBytes"]
    need(type(offset) is int and 0 <= offset < 2 ** 63 and type(cursor["precedingTailBytes"]) is int
         and cursor["precedingTailBytes"] == min(offset, LOG_TAIL_BYTES) and sha(cursor["precedingTailSha256"])
         and (offset != 0 or cursor["precedingTailSha256"] == digest(b""))
         and type(cursor["growthBeyondSnapshotBytes"]) is int and 0 <= cursor["growthBeyondSnapshotBytes"] < 2 ** 63, "log-cursor-offset")
    return cursor


def validate_log_window(cursor, identity, end, anchor, body):
    need(identity == cursor["identity"], "log-file-identity")
    need(type(end) is int and end >= cursor["offsetBytes"], "log-truncated")
    size = end - cursor["offsetBytes"]
    need(0 <= size <= LOG_INTERVAL_BYTES, "log-interval-bound")
    need(type(anchor) is bytes and len(anchor) == cursor["precedingTailBytes"]
         and digest(anchor) == cursor["precedingTailSha256"], "log-anchor-rewritten")
    need(type(body) is bytes and len(body) == size, "log-read-incomplete")
    need((not anchor or anchor.endswith(b"\n")) and (not body or body.endswith(b"\n")), "log-incomplete-boundary")


def select_installer_log(body, binding):
    # Byte-preserving diagnostic selection only. No PID attribution, JSON result
    # decoding, convenient-record choice, or acceptance/finality implication.
    need(type(body) is bytes and len(body) <= LOG_INTERVAL_BYTES, "log-interval-bound")
    need(not body or body.endswith(b"\n"), "log-incomplete-boundary")
    def token(value, path=False):
        chars = rb"A-Za-z0-9._+~%/-" if path else rb"A-Za-z0-9._+-"
        return re.compile(rb"(?<![" + chars + rb"])" + re.escape(value) + rb"(?![" + chars + rb"])")
    patterns = {
        "package-identifier": token(binding["packageIdentifier"].encode()),
        "package-path": token(binding["packagePath"].encode(), path=True),
        "native-executable": token(b"mrk-macos-install"),
        "fixture-result": re.compile(rb"(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_FIXTURE_RESULT="),
        "ordinary-result": re.compile(rb"(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_RESULT="),
        "postinstall-phase": re.compile(rb"(?<![A-Za-z0-9_])MRK_MACOS_POSTINSTALL_PHASE=(?:entry|target-ok|relative-entry|absolute-entry|cwd-ok|pre-exec)(?![A-Za-z0-9_-])"),
        "postinstall-refusal": re.compile(rb"(?<![A-Za-z0-9_])MRK_MACOS_POSTINSTALL_REFUSED=(?:target|entry|cwd)(?![A-Za-z0-9_-])"),
        "acl-diagnostic": re.compile(
            rb"(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_ACL_DIAGNOSTIC=role="
            rb"(?:input-directory|input-inventory|system-root|system-library|system-support|other-protected-object);phase="
            rb"(?:filesec-allocation|fstatx-snapshot|snapshot-owner|snapshot-group|snapshot-mode|acl-presence|acl-conversion|"
            rb"acl-object|acl-validation|acl-first-entry|acl-entry-present|acl-free|ffi-output)"
            rb";result=-?[0-9]{1,10};call=-?[0-9]{1,10};errno=-?[0-9]{1,10};freeCall=-?[0-9]{1,10};freeErrno=-?[0-9]{1,10}(?=\r?\n$)"),
    }
    counts = {key: 0 for key in patterns}
    selected = bytearray()
    rows = []
    offset = 0
    total = 0
    for line in body.splitlines(keepends=True):
        need(line.endswith(b"\n") and len(line) <= LOG_LINE_BYTES, "log-line-bound")
        matches = {key: sum(1 for _ in pattern.finditer(line)) for key, pattern in patterns.items()}
        anchors = [key for key, count in matches.items() if count]
        for key, count in matches.items():
            counts[key] += count
        if anchors:
            need(len(selected) + len(line) <= LOG_SELECTED_BYTES, "log-selected-bound")
            rows.append({"relativeOffsetBytes": offset, "retainedOffsetBytes": len(selected), "bytes": len(line),
                         "sha256": digest(line), "anchors": anchors})
            selected.extend(line)
        offset += len(line)
        total += 1
    need(bool(selected), "log-no-project-lines")
    wanted = "fixture-result" if binding["packageKind"] == "fixture" else "ordinary-result"
    other = "ordinary-result" if wanted == "fixture-result" else "fixture-result"
    state = "mixed" if counts[other] else "duplicate" if counts[wanted] > 1 else "unbound" if counts[wanted] == 1 else "missing"
    return bytes(selected), {"linesObserved": total, "linesUnselected": total - len(rows), "selectedLines": rows,
                             "markerCounts": counts, "resultMarkerState": state}


def write_log_selection(path, body):
    need(type(body) is bytes and 0 < len(body) <= LOG_SELECTED_BYTES, "log-selected-bound")
    with parent(path) as (outer, name):
        original = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=outer)
        try:
            offset = 0
            while offset < len(body):
                written = os.write(original, body[offset:])
                need(written > 0, "log-output-readback")
                offset += written
            os.fsync(original)
            info = os.fstat(original)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(body)
                 and positioned_log_read(original, 0, len(body)) == body
                 and signature(os.fstat(original)) == signature(info)
                 and signature(os.stat(name, dir_fd=outer, follow_symlinks=False)) == signature(info), "log-output-readback")
        finally:
            close_once(original)


def installer_log_diagnostic(args):
    binding = None
    phase = "input"
    planned_selection = None
    try:
        binding = installer_log_binding(args)
        if args.command == "installer-log-cursor":
            with installer_log_file() as (fd, outer, name, info):
                identity = installer_log_identity(info)
                tail_size = min(info.st_size, LOG_TAIL_BYTES)
                tail = positioned_log_read(fd, info.st_size - tail_size, tail_size)
                need(positioned_log_read(fd, info.st_size - tail_size, tail_size) == tail, "log-anchor-rewritten")
                growth = log_growth(fd, outer, name, identity, info.st_size)
                result = make_log_cursor(binding, identity, info.st_size, tail, growth)
            need(len(canonical(result)) <= 16383, "log-metadata-bound")
            return result, 0
        with parent(args.cursor) as (outer, name):
            cursor_bytes, info = read_at(outer, name, 16384)
            need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600, "log-cursor-shape")
        cursor = validate_log_cursor(decode(cursor_bytes), binding)
        phase = "capture"
        with installer_log_file() as (fd, outer, name, info):
            identity = installer_log_identity(info)
            need(identity == cursor["identity"], "log-file-identity")
            start, end = cursor["offsetBytes"], info.st_size
            need(end >= start, "log-truncated")
            need(end - start <= LOG_INTERVAL_BYTES, "log-interval-bound")
            anchor = positioned_log_read(fd, start - cursor["precedingTailBytes"], cursor["precedingTailBytes"])
            body = positioned_log_read(fd, start, end - start)
            validate_log_window(cursor, identity, end, anchor, body)
            need(positioned_log_read(fd, start - len(anchor), len(anchor)) == anchor, "log-anchor-rewritten")
            growth = log_growth(fd, outer, name, identity, end)
        selected, selection = select_installer_log(body, binding)
        result = {"schemaVersion": 1, "kind": "installer-log-capture", "state": "observed-project-correlated",
                  "binding": binding, "logPath": str(INSTALL_LOG), "identity": identity, "cursorSha256": digest(cursor_bytes),
                  "startOffsetBytes": start, "endOffsetBytes": end, "growthBeyondSnapshotBytes": growth,
                  "intervalBytes": len(body), "intervalSha256": digest(body), **selection,
                  "selectedData": {"file": Path(args.selected_output).name, "bytes": len(selected), "sha256": digest(selected)},
                  "authority": LOG_AUTHORITY, "scriptOutputFinality": "unestablished"}
        need(len(canonical(result)) < LOG_METADATA_BYTES, "log-metadata-bound")
        phase = "output"
        planned_selection = result["selectedData"]
        write_log_selection(args.selected_output, selected)
        return result, 0
    except (Refused, OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError) as error:
        reason = "log-output-unavailable" if phase == "output" else "log-input-or-capture-unavailable"
        if type(error) is Refused and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in LOG_REFUSALS:
            reason = error.args[0]
        return {"schemaVersion": 1, "kind": args.command, "state": "unknown", "reason": reason,
                "binding": binding, "authority": LOG_AUTHORITY, "scriptOutputFinality": "unestablished",
                "plannedSelectedData": planned_selection,
                "selectedOutputState": "write-or-close-unknown-preserve-original" if phase == "output" else "not-created"}, 1


def installer_record(log, *, fixture=False):
    marker = b"MRK_MACOS_INSTALL_FIXTURE_RESULT=" if fixture else b"MRK_MACOS_INSTALL_RESULT="
    other = b"MRK_MACOS_INSTALL_RESULT=" if fixture else b"MRK_MACOS_INSTALL_FIXTURE_RESULT="
    need(other not in log, "separate-installer-outcomes-required")
    records = [decode(line.split(marker, 1)[1]) for line in log.splitlines() if marker in line]
    need(len(records) == 1 and type(records[0]) is dict, "original-installer-result-missing-or-duplicate")
    return records[0]


def maintenance_hex(value, width):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(width) + r"}", value) is not None and value != "0" * width


def maintenance_map(value, keys, reason):
    need(type(value) is dict and set(value) == set(keys), reason)
    return value


def maintenance_json(body, limit):
    need(type(body) is bytes and 0 < len(body) <= limit, "maintenance-record-byte-bound")
    try:
        value = decode(body.decode("utf-8"))
    except (ValueError, RecursionError, OverflowError) as error:
        raise Refused("maintenance-record-encoding-or-shape") from error
    need(type(value) is dict, "maintenance-record-map")
    return value


def maintenance_release_data(value, target):
    maintenance_map(value, ("profile", "packageIdentifier", "bundleIdentifier", "packageVersion", "release", "sourceCommit",
                           "protocolSha256", "runtimeManifestSha256", "inventorySha256", "signingPolicySha256", "packageSha256"),
                    "maintenance-release-shape")
    need(all(type(value[key]) is str and value[key].isascii() for key in ("packageVersion", "release")),
         "maintenance-release-binding")
    build_release_data(canonical({"schemaVersion": 1, "packageVersion": value["packageVersion"], "release": value["release"]}), target=target)
    profile = "fixed-macos26-arm64-maintenance-v2" if target == ARM_TARGET else "fixed-macos26-x86_64-maintenance-v2"
    need(value["profile"] == profile and value["packageIdentifier"] == PACKAGE_ID and value["bundleIdentifier"] == BUNDLE_ID
         and value["packageVersion"] != "0.1.0"
         and value["release"] not in ("macos26-arm64-project-draft-01", "macos26-arm64-entry-m2a-01")
         and maintenance_hex(value["sourceCommit"], 40)
         and all(maintenance_hex(value[key], 64) for key in ("protocolSha256", "runtimeManifestSha256", "inventorySha256",
                                                            "signingPolicySha256", "packageSha256")), "maintenance-release-binding")
    return value


def maintenance_producer_data(body, *, target):
    """Closed DATA correspondence only: no signature or Developer-ID authority."""
    target = mac_target(target)
    document = maintenance_json(body, PRODUCER_DESCRIPTOR_BYTES)
    maintenance_map(document, ("schemaVersion", "kind", "domain", "target", "releaseSet", "signingPolicies"), "maintenance-producer-shape")
    need(type(document["schemaVersion"]) is int and document["schemaVersion"] == 2
         and document["kind"] == "mrk-macos-install-producer-v2" and document["domain"] == "MobileReleaseKit-package-producer-v2"
         and document["target"] == target, "maintenance-producer-binding")
    releases = maintenance_map(document["releaseSet"], ("schemaVersion", "current", "acceptedPredecessors"), "maintenance-release-set-shape")
    need(type(releases["schemaVersion"]) is int and releases["schemaVersion"] == 2
         and type(releases["acceptedPredecessors"]) is list and len(releases["acceptedPredecessors"]) <= 8,
         "maintenance-release-set-bound")
    current = maintenance_release_data(releases["current"], target)
    seen = {key: {current[key]} for key in ("release", "packageVersion", "packageSha256")}
    for old in releases["acceptedPredecessors"]:
        maintenance_release_data(old, target)
        need(tuple(map(int, old["packageVersion"].split('.'))) < tuple(map(int, current["packageVersion"].split('.'))),
             "maintenance-predecessor-order")
        for key, values in seen.items():
            need(old[key] not in values, "maintenance-reused-release-identity")
            values.add(old[key])
    need(len(canonical(releases)) <= 16 * 1024, "maintenance-release-set-bound")
    policies = document["signingPolicies"]
    need(type(policies) is list and 0 < len(policies) <= 9, "maintenance-signing-policies-bound")
    ordered_keys = ("schemaVersion", "kind", "teamIdentifier", "leafCertificateSha1", "leafCertificateSha256", "hardenedRuntime", "entitlements")
    hashes, previous = set(), ""
    for row in policies:
        maintenance_map(row, ("sha256", "policy"), "maintenance-policy-row")
        policy = maintenance_map(row["policy"], ordered_keys, "maintenance-policy-shape")
        need(type(policy["schemaVersion"]) is int and policy["schemaVersion"] == 1
             and policy["kind"] == "mrk-macos-developer-id-code-policy-v1"
             and type(policy["teamIdentifier"]) is str and re.fullmatch(r"[A-Z0-9]{10}", policy["teamIdentifier"])
             and maintenance_hex(policy["leafCertificateSha1"], 40) and maintenance_hex(policy["leafCertificateSha256"], 64)
             and policy["hardenedRuntime"] is True and policy["entitlements"] == "empty", "maintenance-policy-binding")
        # Rust PolicyWire declaration order, not sorted JSON or normalized signed
        # descriptor bytes. This digest only checks the declared policy's DATA.
        policy_bytes = json.dumps({key: policy[key] for key in ordered_keys}, ensure_ascii=True,
                                  separators=(",", ":"), allow_nan=False).encode("ascii")
        need(maintenance_hex(row["sha256"], 64) and row["sha256"] > previous and digest(policy_bytes) == row["sha256"],
             "maintenance-policy-digest-or-order")
        previous = row["sha256"]
        hashes.add(previous)
    need(hashes == {row["signingPolicySha256"] for row in (current, *releases["acceptedPredecessors"])},
         "maintenance-policy-membership")
    return document


def service_signing_data(body):
    """Fixed SOURCE identity DATA; never a key search or code-signing verdict."""
    need(type(body) is bytes and 0 < len(body) <= 512 and body.endswith(b"\n")
         and all(byte == 10 or 0x21 <= byte <= 0x7e for byte in body), "source-service-profile")
    rows = body[:-1].decode("ascii").split("\n")
    need(len(rows) == 5 and rows[:3] == ["schema=1", "app-identifier=" + BUNDLE_ID,
         "helper-identifier=" + ANDROID_SERVICE_LABEL]
         and rows[3].startswith("team-identifier=")
         and rows[4].startswith("developer-id-certificate-sha1="), "source-service-profile")
    team, leaf = rows[3][len("team-identifier="):], rows[4][len("developer-id-certificate-sha1="):]
    if team == leaf == "unconfigured":
        return None
    need(re.fullmatch(r"[A-Z0-9]{10}", team) and maintenance_hex(leaf, 40), "source-service-profile")
    return team, leaf


def packaging_signing_data(producer, service, *, allow_unconfigured=False):
    """Match the existing nine-row build selection; native DER/trust is separate."""
    need(type(allow_unconfigured) is bool and type(producer) is bytes
         and 0 < len(producer) <= 1024 and producer.endswith(b"\n")
         and all(byte == 10 or 0x21 <= byte <= 0x7e for byte in producer), "source-producer-profile")
    identity = service_signing_data(service)
    if producer == b"schema=1\nstate=unconfigured\n":
        need(allow_unconfigured and identity is None, "source-producer-unconfigured")
        return None
    rows = producer[:-1].decode("ascii").split("\n")
    keys = ("schema", "state", "team-identifier", "rsa-bits", "leaf-certificate-sha1",
            "leaf-certificate-sha256", "issuer-certificate-sha256", "root-certificate-sha256",
            "public-key-pkcs1-sha256")
    need(len(rows) == len(keys) and all(row.startswith(key + "=") for row, key in zip(rows, keys)),
         "source-producer-profile")
    values = tuple(row[len(key) + 1:] for row, key in zip(rows, keys))
    need(values[:2] == ("1", "configured") and re.fullmatch(r"[A-Z0-9]{10}", values[2])
         and values[3] in ("2048", "3072", "4096") and maintenance_hex(values[4], 40)
         and all(maintenance_hex(value, 64) for value in values[5:])
         and len(set(values[5:8])) == 3 and identity == (values[2], values[4]), "source-producer-correspondence")
    return ProducerSelection(values[2], values[4], values[5], int(values[3]), digest(producer), digest(service))


def packaging_selection_command(args):
    selection = source_build_selection(command_target(args))
    source = packaging_signing_data(read(PRODUCER_PROFILE, 1024), read(SERVICE_PROFILE, 512))
    need(selection.package_version != "0.1.0"
         and selection.release not in ("macos26-arm64-project-draft-01", "macos26-arm64-entry-m2a-01"),
         "source-production-release-required")
    return {"schemaVersion": 1, "kind": "source-packaging-selection-data", "target": selection.target,
            "packageVersion": selection.package_version, "release": selection.release,
            "teamIdentifier": source.team, "leafCertificateSha1": source.leaf_sha1,
            "leafCertificateSha256": source.leaf_sha256, "producerProfileSha256": source.producer_sha256,
            "serviceProfileSha256": source.service_sha256, "nativeAuthority": False}


def packaging_descriptor_data(history_body, source, selection, *, source_commit, manifest, inventory, package):
    """Assemble exact existing schema2 from SOURCE history, not installed discovery."""
    selection = selected_build(selection)
    need(type(source) is ProducerSelection and maintenance_hex(source_commit, 40)
         and all(maintenance_hex(value, 64) for value in (manifest, inventory, package)), "packaging-descriptor-input")
    history = maintenance_json(history_body, PRODUCER_DESCRIPTOR_BYTES)
    maintenance_map(history, ("schemaVersion", "targets"), "producer-history-shape")
    need(type(history["schemaVersion"]) is int and history["schemaVersion"] == 1, "producer-history-shape")
    targets = maintenance_map(history["targets"], MAC_TARGETS, "producer-history-targets")
    for target, row in targets.items():
        maintenance_map(row, ("acceptedPredecessors", "signingPolicies"), "producer-history-row")
        need(type(row["acceptedPredecessors"]) is list and len(row["acceptedPredecessors"]) <= 8
             and type(row["signingPolicies"]) is list and len(row["signingPolicies"]) <= 8, "producer-history-bound")
        for old in row["acceptedPredecessors"]:
            maintenance_release_data(old, target)
    chosen = targets[selection.target]
    # This insertion order is the accepted Rust PolicyWire order, not the
    # descriptor's sorted canonical encoding and not service-profile text.
    policy = {"schemaVersion": 1, "kind": "mrk-macos-developer-id-code-policy-v1", "teamIdentifier": source.team,
              "leafCertificateSha1": source.leaf_sha1, "leafCertificateSha256": source.leaf_sha256,
              "hardenedRuntime": True, "entitlements": "empty"}
    policy_bytes = json.dumps(policy, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    policy_sha = digest(policy_bytes)
    policies = list(chosen["signingPolicies"])
    matches = [row for row in policies if type(row) is dict and row.get("sha256") == policy_sha]
    need(len(matches) <= 1 and (not matches or matches[0] == {"sha256": policy_sha, "policy": policy}),
         "producer-history-current-policy")
    if not matches:
        policies.append({"sha256": policy_sha, "policy": policy})
    need(all(type(row) is dict and type(row.get("sha256")) is str for row in policies), "producer-history-policy")
    policies.sort(key=lambda row: row["sha256"])
    current = {"profile": "fixed-macos26-arm64-maintenance-v2" if selection.target == ARM_TARGET else "fixed-macos26-x86_64-maintenance-v2",
               "packageIdentifier": PACKAGE_ID, "bundleIdentifier": BUNDLE_ID, "packageVersion": selection.package_version,
               "release": selection.release, "sourceCommit": source_commit, "protocolSha256": CURRENT_PROTOCOL,
               "runtimeManifestSha256": manifest, "inventorySha256": inventory, "signingPolicySha256": policy_sha,
               "packageSha256": package}
    document = {"schemaVersion": 2, "kind": "mrk-macos-install-producer-v2", "domain": "MobileReleaseKit-package-producer-v2",
                "target": selection.target, "releaseSet": {"schemaVersion": 2, "current": current,
                    "acceptedPredecessors": chosen["acceptedPredecessors"]}, "signingPolicies": policies}
    body = canonical(document) + b"\n"
    maintenance_producer_data(body, target=selection.target)  # The existing full validator, not a parallel parser.
    return body


def packaging_removal_descriptor_data(installed, inventory, program, package, source, selection, *, source_commit, manifest):
    """New remove domain from exact current Install DATA; no live/removal authority."""
    selection = selected_build(selection)
    need(type(source) is ProducerSelection and maintenance_hex(source_commit, 40) and maintenance_hex(manifest, 64)
         and type(program) is bytes and 0 < len(program) <= REMOVER_BYTES
         and type(package) is bytes and 0 < len(package) <= MAX_BYTES and package[:4] == b"xar!", "remove-descriptor-input")
    install = maintenance_producer_data(installed, target=selection.target)
    current = install["releaseSet"]["current"]
    need((current["sourceCommit"], current["release"], current["packageVersion"], current["protocolSha256"], current["runtimeManifestSha256"])
         == (source_commit, selection.release, selection.package_version, CURRENT_PROTOCOL, manifest), "remove-current-install-source")
    policies = [row["policy"] for row in install["signingPolicies"] if row["sha256"] == current["signingPolicySha256"]]
    need(len(policies) == 1 and (policies[0]["teamIdentifier"], policies[0]["leafCertificateSha1"], policies[0]["leafCertificateSha256"])
         == (source.team, source.leaf_sha1, source.leaf_sha256), "remove-current-install-signer")
    rows = observation_inventory_bytes(inventory, current["inventorySha256"], manifest, selection=selection)
    name = "app/" + REMOVER
    need(name in rows and rows[name]["executable"] is True
         and (rows[name]["size"], rows[name]["sha256"]) == (len(program), digest(program)), "remove-current-program-inventory")
    macho(program, target=selection.target)
    document = {"schemaVersion": 1, "kind": "mrk-macos-remove-producer-v1", "domain": "MobileReleaseKit-remove-producer-v1",
                "target": selection.target, "sourceCommit": source_commit, "release": selection.release,
                "protocolSha256": CURRENT_PROTOCOL, "installedProducerSha256": digest(installed),
                "installedInventorySha256": digest(inventory), "signingPolicySha256": current["signingPolicySha256"],
                "packageIdentifier": REMOVE_PACKAGE_ID, "packageVersion": selection.package_version,
                "packageSha256": digest(package), "removerExecutableSha256": digest(program)}
    body = canonical(document) + b"\n"
    need(len(body) <= REMOVE_DESCRIPTOR_BYTES, "remove-descriptor-bound")
    return body


def packaging_observer_descriptor_data(installed, inventory, installed_program, own_program, package,
                                      source, selection, *, source_commit, manifest):
    """NONSHIPPING O: preserve genuine target lineage, bind different own code.

    The existing ordinary constructor performs every installed tuple/inventory
    comparison against the actual sixth input. This DATA never replaces the
    emitter's genuine installed signature or actual own-program verifier.
    """
    selection = selected_build(selection)
    need(selection.target == ARM_TARGET and type(own_program) is bytes
         and 0 < len(own_program) <= REMOVER_BYTES and digest(own_program) != digest(installed_program),
         "observer-distinct-program")
    body = packaging_removal_descriptor_data(installed, inventory, installed_program, package, source, selection,
                                            source_commit=source_commit, manifest=manifest)
    macho(own_program, target=selection.target)
    value = maintenance_json(body, REMOVE_DESCRIPTOR_BYTES)
    value["removerExecutableSha256"] = digest(own_program)
    result = canonical(value) + b"\n"
    need(len(result) <= REMOVE_DESCRIPTOR_BYTES, "observer-descriptor-bound")
    return result


def removal_observer_copy_quote_data(sizes):
    """Before reads/write_tree, charge both live bodies and their output copies.

    Values must come from the SAME retained original fstats. The caller checks
    actual byte lengths and originals again after every read; this is not RSS
    or an authority inferred from caller-supplied lengths.
    """
    names = ("package", "observer", "installedProgram", "inventory", "installed", "signature")
    limits = (MAX_BYTES, REMOVER_BYTES, REMOVER_BYTES, 1024 * 1024,
              PRODUCER_DESCRIPTOR_BYTES, PRODUCER_SIGNATURE_BYTES)
    need(type(sizes) is dict and set(sizes) == set(names)
         and all(type(sizes[n]) is int and 0 < sizes[n] <= cap for n, cap in zip(names, limits)),
         "observer-copy-quote-inputs")
    quote = 2 * (sum(sizes.values()) + REMOVE_DESCRIPTOR_BYTES) + 16 * 1024 * 1024
    need(quote <= MAX_BYTES, "observer-copy-quote-bound")
    return quote


def removal_fixture_script_arguments(args):
    role = getattr(args, "removal_fixture_role", None)
    correlation = getattr(args, "removal_fixture_correlation", None)
    target = getattr(args, "removal_fixture_binding", None)
    if role is None:
        need(correlation is None and target is None, "removal-fixture-script-purpose")
        return {}
    # SOURCE roles only. The actual owner must separately admit the B/O graph,
    # completed P and raw sidecars; this selection is never a signature proof.
    removal_fixture_script_data(role, correlation=correlation, target=target,
                                selection=source_build_selection(command_target(args)))
    return {"removal_fixture_role": role, "removal_fixture_correlation": correlation,
            "removal_fixture_binding": target}


def remove_input_command(args):
    selection = source_build_selection(command_target(args))
    source = packaging_signing_data(read(PRODUCER_PROFILE, 1024), read(SERVICE_PROFILE, 512))
    installed = read(args.installed_producer, PRODUCER_DESCRIPTOR_BYTES)
    signature = read(args.installed_signature, PRODUCER_SIGNATURE_BYTES)
    need(len(signature) == source.rsa_bits // 8, "remove-installed-signature-size")
    inventory = read(args.inventory, 1024 * 1024)
    with parent(args.remover) as (fd, name):
        program, info = read_at(fd, name, REMOVER_BYTES)
        need(stat.S_IMODE(info.st_mode) == 0o555, "remove-program-signed-mode")
    package = read(args.package, MAX_BYTES)
    body = packaging_removal_descriptor_data(installed, inventory, program, package, source, selection,
                                            source_commit=args.expected_source, manifest=args.expected_manifest)
    files = {"remove-descriptor-input.json": (body, 0o444), "producer.json": (installed, 0o444),
             "producer.sig": (signature, 0o444), "install-inventory.json": (inventory, 0o444), REMOVER_NAME: (program, 0o555)}
    write_tree(args.output, files, root_mode=0o700, current_owned=True)
    return {"schemaVersion": 1, "kind": "remove-emitter-input-data", "target": selection.target,
            "descriptorSha256": digest(body), "installedProducerSha256": digest(installed),
            "inventorySha256": digest(inventory), "removerSha256": digest(program), "packageSha256": digest(package),
            "inputFiles": 5, "qualification": "remove-input-data-not-signature-or-removal-authority"}


def emitted_package_data(stdout, stderr, returncode, package, descriptor, signed, *, target):
    """Original child status AND retained exact output bytes; no receipt authority."""
    need(type(returncode) is int and returncode == 0 and type(stdout) is bytes and 0 < len(stdout) <= 512
         and stdout.endswith(b"\n") and stderr == b"", "producer-emitter-original")
    result = maintenance_json(stdout, 512)
    maintenance_map(result, ("schemaVersion", "kind", "packageSha256", "descriptorSha256", "signatureSha256",
                             "descriptorBytes", "signatureBytes"), "producer-emitter-summary")
    need(type(result["schemaVersion"]) is int and result["schemaVersion"] == 1
         and result["kind"] == "mrk-package-producer-emitted"
         and type(package) is bytes and 0 < len(package) <= MAX_BYTES
         and type(descriptor) is bytes and 0 < len(descriptor) <= PRODUCER_DESCRIPTOR_BYTES
         and type(signed) is bytes and 0 < len(signed) <= PRODUCER_SIGNATURE_BYTES
         and type(result["descriptorBytes"]) is int and result["descriptorBytes"] == len(descriptor)
         and type(result["signatureBytes"]) is int and result["signatureBytes"] == len(signed)
         and (result["packageSha256"], result["descriptorSha256"], result["signatureSha256"])
             == (digest(package), digest(descriptor), digest(signed)), "producer-emitter-summary")
    producer = maintenance_producer_data(descriptor, target=target)
    need(producer["releaseSet"]["current"]["packageSha256"] == digest(package), "producer-emitter-package-binding")
    return result


def emitted_removal_data(stdout, stderr, returncode, package, descriptor, signed, expected_descriptor):
    """Actual closed Remove emitter result, never native-signature authority by itself."""
    need(type(returncode) is int and returncode == 0 and type(stdout) is bytes and 0 < len(stdout) <= 512
         and stdout.endswith(b"\n") and type(stderr) is bytes and not stderr, "remove-emitter-original")
    result = maintenance_json(stdout, 512)
    maintenance_map(result, ("schemaVersion", "kind", "packageSha256", "descriptorSha256", "signatureSha256",
                             "descriptorBytes", "signatureBytes"), "remove-emitter-summary")
    need(type(result["schemaVersion"]) is int and result["schemaVersion"] == 1
         and result["kind"] == "mrk-remove-producer-emitted"
         and type(package) is bytes and 0 < len(package) <= MAX_BYTES
         and type(descriptor) is bytes and 0 < len(descriptor) <= REMOVE_DESCRIPTOR_BYTES
         and type(expected_descriptor) is bytes and descriptor == expected_descriptor
         and type(signed) is bytes and 0 < len(signed) <= PRODUCER_SIGNATURE_BYTES
         and type(result["descriptorBytes"]) is int and result["descriptorBytes"] == len(descriptor)
         and type(result["signatureBytes"]) is int and result["signatureBytes"] == len(signed)
         and (result["packageSha256"], result["descriptorSha256"], result["signatureSha256"])
             == (digest(package), digest(descriptor), digest(signed)), "remove-emitter-summary")
    return result


def removal_distribution_layout_data(names, expected, actual):
    """The separate fixed three-file Remove carrier; no arbitrary filename selector."""
    roster = {"Remove.pkg", "remove-producer.json", "remove-producer.sig"}
    need(type(names) in (list, tuple, set) and len(names) == 3 and set(names) == roster
         and type(expected) is dict and set(expected) == roster and type(actual) is dict and set(actual) == roster,
         "remove-distribution-three-file-roster")
    for name, original in expected.items():
        need(type(original) is bytes and actual[name] == (original, 0o444), "remove-distribution-original-byte-mode")


def distribution_request_name(request_id):
    need(maintenance_hex(request_id, 32), "distribution-request-id")
    return "MobileReleaseKit-Request-" + request_id + ".pkg"


def distribution_layout_data(names, package_name, expected, actual):
    """Closed file bytes/modes DATA; mount and command ownership remain separate."""
    need(package_name == "Install.pkg" or type(package_name) is str
         and re.fullmatch(r"MobileReleaseKit-Request-[0-9a-f]{32}\.pkg", package_name)
         and maintenance_hex(package_name[len("MobileReleaseKit-Request-"):-4], 32), "distribution-package-name")
    roster = {package_name, "producer.json", "producer.sig"}
    need(type(names) in (list, tuple, set) and len(names) == 3 and set(names) == roster
         and type(expected) is dict and set(expected) == {"Install.pkg", "producer.json", "producer.sig"}
         and type(actual) is dict and set(actual) == roster, "distribution-three-file-roster")
    for name, original in expected.items():
        renamed = package_name if name == "Install.pkg" else name
        need(type(original) is bytes and actual[renamed] == (original, 0o444), "distribution-original-byte-mode")


def distribution_mount_data(stdout, stderr, returncode, mountpoint):
    """Bounded structured hdiutil output; never eval or an inferred trust grant."""
    need(type(returncode) is int and returncode == 0 and type(stdout) is bytes and 0 < len(stdout) <= 65536
         and type(stderr) is bytes and len(stderr) <= 65536 and b"\x00" not in stdout
         and b"<!ENTITY" not in stdout.upper(), "distribution-attach-original")
    try:
        value = plistlib.loads(stdout)
    except (ValueError, TypeError, OverflowError, RecursionError, ET.ParseError) as error:
        raise Refused("distribution-attach-plist") from error
    need(type(value) is dict and set(value) == {"system-entities"} and type(value["system-entities"]) is list
         and 0 < len(value["system-entities"]) <= 8, "distribution-attach-plist")
    found = []
    for row in value["system-entities"]:
        need(type(row) is dict and set(row) <= {"content-hint", "dev-entry", "potentially-mountable", "mount-point", "unmapped-content-hint"}
             and type(row.get("dev-entry")) is str and re.fullmatch(r"/dev/disk[0-9]{1,5}(?:s[0-9]{1,3})?", row["dev-entry"]),
             "distribution-attach-entity")
        if "mount-point" in row:
            need(row["mount-point"] == str(mountpoint) and row.get("potentially-mountable") is True,
                 "distribution-attach-mount")
            found.append(row["dev-entry"])
    need(len(found) == 1, "distribution-attach-single-mount")
    return found[0]

def maintenance_producer_inputs(args, selection):
    """Retain the caller's exact emitted bytes, not installed-file expectations."""
    selection = selected_build(selection)
    descriptor, signature_path = Path(args.producer_descriptor), Path(args.producer_signature)
    need(descriptor.is_absolute() and signature_path.is_absolute() and descriptor.name == "producer.json"
         and signature_path.name == "producer.sig" and descriptor.parent == signature_path.parent,
         "maintenance-original-producer-paths")
    with parent(descriptor) as (fd, name):
        before = signature(os.fstat(fd))
        raw, info = read_at(fd, name, PRODUCER_DESCRIPTOR_BYTES)
        signed, signed_info = read_at(fd, signature_path.name, PRODUCER_SIGNATURE_BYTES)
        need(info.st_mode == signed_info.st_mode == stat.S_IFREG | 0o444 and 0 < len(signed) <= PRODUCER_SIGNATURE_BYTES
             and signature(os.fstat(fd)) == before, "maintenance-original-producer-changed")
    producer = maintenance_producer_data(raw, target=selection.target)
    current = producer["releaseSet"]["current"]
    need(maintenance_hex(args.expected_source, 40) and maintenance_hex(args.expected_inventory, 64)
         and maintenance_hex(args.expected_manifest, 64) and maintenance_hex(args.expected_package, 64)
         and current["release"] == selection.release and current["packageVersion"] == selection.package_version
         and current["sourceCommit"] == args.expected_source and current["protocolSha256"] == CURRENT_PROTOCOL
         and current["runtimeManifestSha256"] == args.expected_manifest and current["inventorySha256"] == args.expected_inventory
         and current["packageSha256"] == args.expected_package, "maintenance-original-producer-current-binding")
    return producer, raw, signed


def maintenance_result_data(body, request_id):
    need(maintenance_hex(request_id, 32), "maintenance-request-id")
    need(type(body) is bytes and body.endswith(b"\n"), "installer-export-byte-bound")
    value = maintenance_json(body, INSTALLER_RESULT_BYTES)
    maintenance_map(value, ("schemaVersion", "kind", "invocation", "requestId", "resultName", "resultFinality", "action",
                           "writerState", "writerExit", "intentSha256", "stateSha256", "capsuleSha256", "payloadWriteCount",
                           "payloadWriteBytes", "originalWriterJoined", "parentFinality", "retainedGate", "historicalOuterExit", "registrationReservation"),
                    "maintenance-export-shape")
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 2
         and value["kind"] == "maintenance-parent-pending-finalization"
         and maintenance_hex(value["invocation"], 32) and value["invocation"] != request_id and value["requestId"] == request_id
         and value["resultName"] == "MobileReleaseKit-InstallerResult-v2-" + request_id + ".json"
         and value["resultFinality"] == "pending-own-write-readback-close-and-outer-return"
         and value["parentFinality"] == "pending-original-closes-and-outer-return"
         and value["retainedGate"] == "parent-command-reference-until-kernel-exit" and value["historicalOuterExit"] == "unverified"
         and value["originalWriterJoined"] is True and type(value["writerExit"]) is int and value["writerExit"] == 0
         and all(maintenance_hex(value[key], 64) for key in ("intentSha256", "stateSha256", "capsuleSha256")), "maintenance-export-binding")
    states = {"fresh-install": "installed", "update": "installed", "same-package-noop": "same-package", "restore-fixed-app": "restored-app"}
    need(type(value["action"]) is str and value["action"] in states and value["writerState"] == states[value["action"]],
         "maintenance-export-action")
    maintenance_write_data(value["payloadWriteCount"], value["payloadWriteBytes"], value["action"])
    registration_reservation_result(value["registrationReservation"], entered=True)
    need(value["registrationReservation"]["creation"] != "created" or value["action"] in ("fresh-install", "update"),
         "registration-reservation-not-predecessor-creation")
    return value


def maintenance_write_data(count, byte_count, action):
    need(type(count) is int and type(byte_count) is int and 0 <= count <= byte_count <= MAX_BYTES
         and (count == 0) == (byte_count == 0) and (count == 0) == (action == "same-package-noop"),
         "maintenance-write-accounting")


def maintenance_record_header(value, kind, producer):
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 2 and value["kind"] == kind
         and value["target"] == producer["target"] and maintenance_hex(value["invocation"], 32)
         and maintenance_hex(value["requestId"], 32), "maintenance-record-header")


def maintenance_pair_data(action, previous, next_release, producer, *, current):
    releases = producer["releaseSet"]
    allowed = [releases["current"], *releases["acceptedPredecessors"]]
    need(type(action) is str and action in MAINTENANCE_ACTIONS and type(next_release) is dict and next_release in allowed
         and (not current or next_release == releases["current"])
         and (previous is None or type(previous) is dict and previous in allowed), "maintenance-record-release-membership")
    if action == "fresh-install":
        need(previous is None, "maintenance-record-action-pair")
    elif action in ("same-package-noop", "restore-fixed-app"):
        need(previous == next_release, "maintenance-record-action-pair")
    else:
        need(previous is not None and tuple(map(int, previous["packageVersion"].split('.')))
             < tuple(map(int, next_release["packageVersion"].split('.'))), "maintenance-record-action-pair")


def maintenance_identity_data(value, mode):
    maintenance_map(value, ("device", "inode", "mode", "uid", "gid", "flags"), "maintenance-directory-identity")
    need(all(type(item) is int for item in value.values()) and 0 < value["device"] < (1 << 63)
         and 0 < value["inode"] < (1 << 64) and value["mode"] == stat.S_IFDIR | mode
         and value["uid"] == value["gid"] == value["flags"] == 0, "maintenance-directory-identity")
    return value


def maintenance_generation_data(value, producer, *, retained):
    maintenance_map(value, ("release", "instance", "releaseDirectory", "app"), "maintenance-generation-shape")
    allowed = [producer["releaseSet"]["current"], *producer["releaseSet"]["acceptedPredecessors"]]
    need(type(value["release"]) is dict and value["release"] in allowed and maintenance_hex(value["instance"], 32),
         "maintenance-generation-binding")
    maintenance_identity_data(value["releaseDirectory"], 0o755)
    app = maintenance_map(value["app"], ("location", "invocation", "identity") if retained else ("location", "identity"),
                          "maintenance-generation-app")
    need(app["location"] == ("retained" if retained else "canonical")
         and (not retained or maintenance_hex(app["invocation"], 32)), "maintenance-generation-app")
    maintenance_identity_data(app["identity"], 0o555)
    return value


def maintenance_state_data(body, producer):
    value = maintenance_json(body, 16 * 1024)
    maintenance_map(value, ("schemaVersion", "kind", "target", "invocation", "requestId", "capsuleInvocation", "intendedAction",
                           "phase", "current", "retained", "previousEvidence", "residue"), "maintenance-state-shape")
    maintenance_record_header(value, "mrk-macos-maintenance-state-v2", producer)
    need(value["capsuleInvocation"] == value["invocation"] and type(value["intendedAction"]) is str
         and value["intendedAction"] in MAINTENANCE_ACTIONS and value["phase"] == "mutation-recorded" and value["residue"] is None
         and type(value["retained"]) is list and len(value["retained"]) <= 8
         and type(value["previousEvidence"]) is list and len(value["previousEvidence"]) < 64,
         "maintenance-state-success-bound")
    maintenance_generation_data(value["current"], producer, retained=False)
    generations, identities, retained_names = [], set(), set()
    for index, generation in enumerate((value["current"], *value["retained"])):
        if index:
            maintenance_generation_data(generation, producer, retained=True)
            name = generation["app"]["invocation"]
            need(name not in retained_names, "maintenance-reused-generation")
            retained_names.add(name)
        need(not any(old["release"] == generation["release"] or old["instance"] == generation["instance"] for old in generations),
             "maintenance-reused-generation")
        for identity in (generation["releaseDirectory"], generation["app"]["identity"]):
            key = (identity["device"], identity["inode"])
            need(key not in identities, "maintenance-reused-generation")
            identities.add(key)
        generations.append(generation)
    previous, links = "", set()
    for row in value["previousEvidence"]:
        maintenance_map(row, ("invocation", "intentSha256", "stateSha256", "capsuleSha256"), "maintenance-evidence-link")
        need(maintenance_hex(row["invocation"], 32) and row["invocation"] != value["invocation"] and row["invocation"] > previous
             and all(maintenance_hex(row[key], 64) for key in ("intentSha256", "stateSha256", "capsuleSha256")), "maintenance-evidence-link")
        previous = row["invocation"]
        links.add(previous)
    need(retained_names <= links | {value["invocation"]}, "maintenance-retained-app-link")
    return value


def maintenance_intent_data(body, producer, *, current):
    value = maintenance_json(body, 16 * 1024)
    maintenance_map(value, ("schemaVersion", "kind", "target", "invocation", "requestId", "action", "previous", "next", "previousState"),
                    "maintenance-intent-shape")
    maintenance_record_header(value, "mrk-macos-maintenance-intent-v2", producer)
    maintenance_pair_data(value["action"], value["previous"], value["next"], producer, current=current)
    previous = value["previousState"]
    if previous is None:
        need(value["action"] == "fresh-install", "maintenance-intent-previous-state")
    else:
        maintenance_map(previous, ("invocation", "sha256"), "maintenance-intent-previous-state")
        need(maintenance_hex(previous["invocation"], 32) and maintenance_hex(previous["sha256"], 64)
             and previous["invocation"] != value["invocation"] and value["previous"] is not None,
             "maintenance-intent-previous-state")
    return value


def maintenance_capsule_data(body, producer, *, current):
    value = maintenance_json(body, 64 * 1024)
    maintenance_map(value, ("schemaVersion", "kind", "target", "invocation", "requestId", "intendedAction", "previous", "next",
                           "actualCurrent", "intentSha256", "stateSha256", "outcome", "writer"), "maintenance-capsule-shape")
    maintenance_record_header(value, "mrk-macos-maintenance-capsule-v2", producer)
    action = value["intendedAction"]
    maintenance_pair_data(action, value["previous"], value["next"], producer, current=current)
    expected_outcome = {"fresh-install": "applied", "update": "applied", "same-package-noop": "same-package", "restore-fixed-app": "restored-app"}
    need(value["outcome"] == expected_outcome[action] and value["actualCurrent"] == value["next"]
         and maintenance_hex(value["intentSha256"], 64) and maintenance_hex(value["stateSha256"], 64), "maintenance-capsule-success")
    writer = maintenance_map(value["writer"], ("returned", "exitCode", "originalJoined", "resultEof", "originalClosesKnown",
                                              "withinOriginalDeadline", "payloadWriteCount", "payloadWriteBytes"), "maintenance-writer-shape")
    need(all(writer[key] is True for key in ("returned", "originalJoined", "resultEof", "originalClosesKnown", "withinOriginalDeadline"))
         and type(writer["exitCode"]) is int and writer["exitCode"] == 0, "maintenance-writer-not-settled")
    maintenance_write_data(writer["payloadWriteCount"], writer["payloadWriteBytes"], action)
    return value


def maintenance_history_data(result, records, producer):
    """Successful linked DATA, not old outer exits or native/signature evidence."""
    need(type(records) is dict and 0 < len(records) <= 64 and result["invocation"] in records, "maintenance-history-bound")
    parsed, hashes, requests = {}, {}, set()
    for invocation, bodies in records.items():
        need(maintenance_hex(invocation, 32) and type(bodies) is tuple and len(bodies) == 3, "maintenance-history-row")
        current = invocation == result["invocation"]
        intent = maintenance_intent_data(bodies[0], producer, current=current)
        state = maintenance_state_data(bodies[1], producer)
        capsule = maintenance_capsule_data(bodies[2], producer, current=current)
        need(intent["invocation"] == state["invocation"] == capsule["invocation"] == invocation
             and intent["requestId"] == state["requestId"] == capsule["requestId"] and intent["requestId"] not in requests
             and intent["action"] == state["intendedAction"] == capsule["intendedAction"]
             and intent["previous"] == capsule["previous"] and intent["next"] == capsule["next"] == state["current"]["release"]
             and capsule["intentSha256"] == digest(bodies[0]) and capsule["stateSha256"] == digest(bodies[1]),
             "maintenance-linked-records")
        requests.add(intent["requestId"])
        parsed[invocation] = (intent, state, capsule)
        hashes[invocation] = {"invocation": invocation, "intentSha256": digest(bodies[0]),
                              "stateSha256": digest(bodies[1]), "capsuleSha256": digest(bodies[2])}
    intent, state, capsule = parsed[result["invocation"]]
    need(result["requestId"] == intent["requestId"] and result["action"] == intent["action"]
         and all(result[key] == hashes[result["invocation"]][key] for key in ("intentSha256", "stateSha256", "capsuleSha256"))
         and all(result[key] == capsule["writer"][key] for key in ("payloadWriteCount", "payloadWriteBytes")), "maintenance-export-record-link")
    need(state["previousEvidence"] == [hashes[key] for key in sorted(hashes) if key != result["invocation"]], "maintenance-complete-history")
    for invocation, (current_intent, current_state, _capsule) in parsed.items():
        link = current_intent["previousState"]
        action = current_intent["action"]
        if link is None:
            need(action == "fresh-install" and not current_state["previousEvidence"] and not current_state["retained"],
                 "maintenance-fresh-history")
            continue
        need(link["invocation"] in parsed and link["sha256"] == hashes[link["invocation"]]["stateSha256"], "maintenance-previous-state-link")
        previous_state = parsed[link["invocation"]][1]
        need(current_intent["previous"] == previous_state["current"]["release"], "maintenance-previous-release")
        evidence = [*previous_state["previousEvidence"], hashes[link["invocation"]]]
        need(current_state["previousEvidence"] == sorted(evidence, key=lambda row: row["invocation"]), "maintenance-history-derivation")
        now, old = current_state["current"], previous_state["current"]
        if action == "same-package-noop":
            need(now == old and current_state["retained"] == previous_state["retained"], "maintenance-noop-objects")
        elif action == "restore-fixed-app":
            need(all(now[key] == old[key] for key in ("release", "instance", "releaseDirectory"))
                 and current_state["retained"] == previous_state["retained"], "maintenance-restore-objects")
        else:
            retained = {**old, "app": {"location": "retained", "invocation": invocation, "identity": old["app"]["identity"]}}
            need(action == "update" and len(current_state["retained"]) == len(previous_state["retained"]) + 1
                 and all(row in current_state["retained"] for row in previous_state["retained"]) and retained in current_state["retained"],
                 "maintenance-update-objects")
    visited, cursor = set(), result["invocation"]
    while cursor is not None:
        need(cursor not in visited and cursor in parsed, "maintenance-history-cycle")
        visited.add(cursor)
        previous = parsed[cursor][0]["previousState"]
        cursor = None if previous is None else previous["invocation"]
    need(visited == set(parsed), "maintenance-disconnected-history")
    return state, parsed


def installer_result_path(source, inventory, manifest, *, fixture=False, request_id=None):
    need(type(fixture) is bool and type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source)
         and sha(inventory) and sha(manifest), "installer-export-binding")
    if fixture:
        need(request_id is None, "separate-installer-outcomes-required")
        name = "MobileReleaseKit-InstallerResult-v1-fixture-" + source + "-" + inventory + "-" + manifest + ".json"
    else:
        need(maintenance_hex(request_id, 32), "maintenance-request-id")
        name = "MobileReleaseKit-InstallerResult-v2-" + request_id + ".json"
    need(name.isascii() and len(name) <= 255, "installer-export-name")
    return INSTALL_ROOT.parent / name


def installer_parent_identity(info):
    # Exclude unrelated child timestamps/link counts; preserve original object,
    # protection and named/FD correspondence throughout this one read interval.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


@contextlib.contextmanager
def installer_channel_parent(path, *, private=None):
    """Only the fixed export parent or original task's private status parent."""
    path = Path(path)
    need(path.is_absolute() and len(os.fsencode(path)) <= 4096 and path.parent == (INSTALL_ROOT.parent if private is None else private),
         "installer-channel-path")
    parts = os.fspath(path).split("/")[1:]
    need(1 < len(parts) <= 40 and all(p and p not in (".", "..") and len(os.fsencode(p)) <= 255 for p in parts), "installer-channel-spelling")
    uid, _gid = packager_ids()
    originals = []
    try:
        for index, name in enumerate(("/", *parts[:-1])):
            outer = originals[-1][0] if originals else None
            before = os.stat(name, dir_fd=outer, follow_symlinks=False)
            task_parent = private is not None and index == len(parts) - 1
            need(stat.S_ISDIR(before.st_mode) and not before.st_mode & 0o7022
                 and before.st_uid in ((0, uid) if private is not None else (0,))
                 and (not task_parent or before.st_uid == uid and stat.S_IMODE(before.st_mode) == 0o700),
                 "installer-channel-parent-protection")
            original = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=outer)
            originals.append((original, outer, name, installer_parent_identity(before)))
            need(installer_parent_identity(os.fstat(original)) == originals[-1][3]
                 and installer_parent_identity(os.stat(name, dir_fd=outer, follow_symlinks=False)) == originals[-1][3],
                 "installer-channel-parent-changed")
        yield originals[-1][0], parts[-1]
        for original, outer, name, identity in originals:
            need(installer_parent_identity(os.fstat(original)) == identity
                 and installer_parent_identity(os.stat(name, dir_fd=outer, follow_symlinks=False)) == identity,
                 "installer-channel-parent-changed")
    finally:
        active = sys.exc_info()[0] is not None
        unknown = False
        for original, _outer, _name, _identity in reversed(originals):
            try:
                close_once(original)
            except Refused:
                unknown = True
        if unknown and not active:
            raise Refused("installer-channel-parent-close-unknown")


def installer_result_absent_command(args):
    need(not args.fixture or getattr(args, "request_id", None) is None, "separate-installer-outcomes-required")
    request_id = None if args.fixture else getattr(args, "request_id", None)
    path = installer_result_path(args.expected_source, args.expected_inventory, args.expected_manifest, fixture=args.fixture, request_id=request_id)
    with installer_channel_parent(path) as (fd, name):
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except OSError as error:
            need(error.errno == errno.ENOENT, "installer-export-absence-unknown")
        else:
            raise Refused("installer-export-name-occupied")
    return {"schemaVersion": 1 if args.fixture else 2, "kind": "fixture" if args.fixture else "ordinary", "state": "expected-result-name-absent",
            "sourceCommit": args.expected_source, "inventorySha256": args.expected_inventory, "runtimeManifestSha256": args.expected_manifest,
            **({} if args.fixture else {"requestId": request_id, "name": path.name})}


def installer_success_status(args, *, fixture=False):
    work = Path(args.input).parent
    expected = work / ("installer-fixture-output.status" if fixture else "installer-output.status")
    need(Path(args.input) == work / "input" and Path(args.installer_status) == expected, "installer-status-original-path")
    uid, _gid = packager_ids()
    with installer_channel_parent(expected, private=work) as (fd, name):
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == uid and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size == 2, "installer-status-private-original")
        body, actual = read_at(fd, name, 2)
        need(signature(actual) == signature(before) and body == b"0\n", "installer-status-not-original-zero")


def installer_result_document(body, source, inventory, manifest, *, fixture=False, request_id=None):
    installer_result_path(source, inventory, manifest, fixture=fixture, request_id=request_id)  # Expected anchors, not document authority.
    if not fixture:
        return maintenance_result_data(body, request_id)
    need(type(body) is bytes and 0 < len(body) <= INSTALLER_RESULT_BYTES and body.endswith(b"\n"), "installer-export-byte-bound")
    document = decode(body.decode("utf-8"))  # Do not admit json.loads bytes auto-detected UTF-16/32.
    need(type(document) is dict and set(document) == {"schemaVersion", "kind", "sourceCommit", "inventorySha256",
         "runtimeManifestSha256", "transportState", "result"} and type(document["schemaVersion"]) is int and document["schemaVersion"] == 1
         and document["kind"] == ("fixture" if fixture else "ordinary") and document["sourceCommit"] == source
         and document["inventorySha256"] == inventory and document["runtimeManifestSha256"] == manifest
         and document["transportState"] == INSTALLER_RESULT_STATE and type(document["result"]) is dict, "installer-export-closed-binding")
    return document["result"]


def installer_result_readback(args, *, fixture=False):
    # Saved same-run Installer0 is an independent gate, not a durable journal or
    # something the pending export/diagnostic channel can certify about itself.
    installer_success_status(args, fixture=fixture)
    request_id = None if fixture else getattr(args, "request_id", None)
    path = installer_result_path(args.expected_source, args.expected_inventory, args.expected_manifest, fixture=fixture, request_id=request_id)
    with installer_channel_parent(path) as (fd, name):
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o444 and 0 < before.st_size <= INSTALLER_RESULT_BYTES, "installer-export-file-policy")
        body, actual = read_at(fd, name, INSTALLER_RESULT_BYTES)
        need(signature(actual) == signature(before), "installer-export-file-changed")
        result = installer_result_document(body, args.expected_source, args.expected_inventory, args.expected_manifest,
                                           fixture=fixture, request_id=request_id)
    # Both the leaf and all parent originals have actually closed before DATA
    # can be returned. No private staging, log, alternate leaf or sudo reader.
    return result, {"bytes": len(body), "sha256": digest(body), "identity": list(signature(actual)),
                    "finalityBasis": "original-successful-Installer-return-and-checked-readback"}


def bound_original_result(result, expected, source, inventory, manifest, *, selection=None):
    selection = selected_build(selection)
    need(type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source) and sha(inventory) and sha(manifest), "original-result-input-binding")
    reason, runtime, app, state, verified, _exit = expected
    need(type(result) is dict and set(result) == {"schemaVersion", "state", "reason", "release", "runtimePublication", "appPublication",
         "staging", "payloadVerified", "payloadWritersSettled", "originalsSettled", "deadlineMetAfterFinalCloses", "createdAncestors",
         "cleanup", "sourceCommit", "inventorySha256", "runtimeManifestSha256", "installationMetadata", "maintenanceGate", "registrationReservation"}, "original-result-closed-shape")
    need(type(result["schemaVersion"]) is int and result["schemaVersion"] == 1 and result["release"] == selection.release
         and result["sourceCommit"] == source and result["inventorySha256"] == inventory and result["runtimeManifestSha256"] == manifest
         and result["state"] == state and result["reason"] == reason and result["runtimePublication"] == runtime and result["appPublication"] == app
         and result["payloadVerified"] is verified and result["payloadWritersSettled"] is True and result["originalsSettled"] is True
         and result["deadlineMetAfterFinalCloses"] is True and result["cleanup"] == "original-closes-only-no-deletion", "original-installer-not-settled-bound-timely")
    installation_metadata_result(result["installationMetadata"], expected)
    stage = result["staging"]
    need(stage is None or type(stage) is str and re.fullmatch(r"\.install-[0-9a-f]{32}", stage), "original-staging-name")
    maintenance_gate_result(result["maintenanceGate"], entered=stage is not None)
    registration_reservation_result(result["registrationReservation"], entered=stage is not None)
    need(type(result["createdAncestors"]) is list and len(result["createdAncestors"]) <= 4, "original-created-ancestors")
    for row in result["createdAncestors"]:
        need(type(row) is dict and set(row) == {"name", "state", "parentOriginal", "object"} and type(row["name"]) is str
             and (row["name"] in ("MobileReleaseKit", "versions", selection.release) or row["name"] == stage)
             and row["state"] in ("created", "existing-not-modified") and type(row["parentOriginal"]) is int
             and 0 <= row["parentOriginal"] < 24576 and type(row["object"]) is dict and set(row["object"]) == {"device", "inode"}
             and all(type(value) is int for value in row["object"].values()) and row["object"]["inode"] > 0, "original-created-ancestor")


def byte_correspondence(actual, expected):
    need(set(actual) == set(expected), "installed-complete-roster")
    for name, (body, mode) in actual.items():
        row = expected[name]
        need(len(body) == row["size"] and digest(body) == row["sha256"] and mode == (0o555 if row["executable"] else 0o444), "installed-byte-mode-correspondence")


def installation_directory_data(info):
    """Stable DATA only; caller separately retains/checks full named originals."""
    need(stat.S_ISDIR(info.st_mode) and info.st_mode == stat.S_IFDIR | 0o755
         and info.st_uid == info.st_gid == 0 and getattr(info, "st_flags", None) == 0
         and type(info.st_dev) is int and 0 < info.st_dev <= (1 << 63) - 1
         and type(info.st_ino) is int and 0 < info.st_ino <= (1 << 64) - 1, "installation-directory-policy")
    return {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
            "uid": info.st_uid, "gid": info.st_gid, "flags": info.st_flags}


def installation_record_data(body, inventory_body, source, manifest, root, release, instance, *, fixture=False, selection=None,
                             expected_protocol=CURRENT_PROTOCOL):
    """Closed DATA comparison, never permission or native/old finality evidence."""
    selection = selected_build(selection)
    need(type(body) is bytes and 0 < len(body) <= INSTALLATION_RECORD_LIMIT
         and type(inventory_body) is bytes and 0 < len(inventory_body) <= 1024 * 1024
         and type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source)
         and sha(manifest) and sha(expected_protocol) and type(fixture) is bool
         and (not fixture or expected_protocol == CURRENT_PROTOCOL)
         and type(instance) is str and re.fullmatch(r"[0-9a-f]{32}", instance) and instance != "0" * 32,
         "installation-record-input")
    for identity in (root, release):
        need(type(identity) is dict and set(identity) == {"device", "inode", "mode", "uid", "gid", "flags"}
             and all(type(value) is int for value in identity.values())
             and 0 < identity["device"] <= (1 << 63) - 1 and 0 < identity["inode"] <= (1 << 64) - 1
             and identity["mode"] == stat.S_IFDIR | 0o755 and identity["uid"] == identity["gid"] == identity["flags"] == 0,
             "installation-record-expected-directory")
    try:
        record = decode(body.decode("utf-8"))
    except UnicodeError as error:
        raise Refused("installation-record-encoding") from error
    need(type(record) is dict and set(record) == {"schemaVersion", "basis", "phase", "kind", "instance",
         "packageIdentifier", "packageVersion", "bundleIdentifier", "release", "sourceCommit", "protocolSha256",
         "runtimeManifestSha256", "inventory", "policy", "installRoot", "releaseDirectory"}
         and type(record["schemaVersion"]) is int and record["schemaVersion"] == 1
         and record["basis"] == "protected-recorded-installation-inventory" and record["phase"] == "inventory-recorded"
         and record["kind"] == ("fixture" if fixture else "ordinary") and record["instance"] == instance
         and record["packageIdentifier"] == PACKAGE_ID + ("-fixture" if fixture else "") and record["packageVersion"] == selection.package_version
         and record["bundleIdentifier"] == BUNDLE_ID and record["release"] == selection.release and record["sourceCommit"] == source
         and record["protocolSha256"] == expected_protocol and record["runtimeManifestSha256"] == manifest
         and record["policy"] == "fixed-root-wheel-readonly-v1", "installation-record-binding")
    for key, expected in (("installRoot", root), ("releaseDirectory", release)):
        need(type(record[key]) is dict and set(record[key]) == set(expected)
             and all(type(value) is int for value in record[key].values()) and record[key] == expected,
             "installation-record-directory")
    inventory = record["inventory"]
    need(type(inventory) is dict and set(inventory) == {"name", "bytes", "sha256"}
         and inventory["name"] == INSTALLATION_INVENTORY_NAME and type(inventory["bytes"]) is int
         and inventory["bytes"] == len(inventory_body) and inventory["sha256"] == digest(inventory_body),
         "installation-record-inventory")
    rows = observation_inventory_bytes(inventory_body, inventory["sha256"], manifest, selection=selection)
    need(sum(row["size"] for row in rows.values()) + len(inventory_body) + INSTALLATION_RECORD_LIMIT
         + len(MAINTENANCE_GATE_BYTES) + len(REGISTRATION_GATE_BYTES) <= MAX_BYTES, "installation-record-total-bound")
    return record


def installation_metadata_result(value, expected):
    reason, runtime, app, state, _verified, _exit = expected
    need(type(value) is dict and set(value) == {"state", "attemptedFiles", "openedFiles", "plannedBytes", "writtenBytes", "writersSettled"}
         and value["state"] in ("not-attempted", "incomplete", "recorded") and value["writersSettled"] is True
         and all(type(value[key]) is int for key in ("attemptedFiles", "openedFiles", "plannedBytes", "writtenBytes"))
         and 0 <= value["openedFiles"] <= value["attemptedFiles"] <= 2
         and 0 <= value["writtenBytes"] <= value["plannedBytes"] <= 1024 * 1024 + INSTALLATION_RECORD_LIMIT,
         "installation-metadata-result")
    expected_state = ("recorded" if state == "installed" or (runtime == "confirmed" and app == "occupied-refused") else
                      "incomplete" if reason == "open-refused" and runtime == "confirmed" else "not-attempted")
    need(value["state"] == expected_state, "installation-metadata-phase")
    if expected_state == "not-attempted":
        need(all(value[key] == 0 for key in ("attemptedFiles", "openedFiles", "plannedBytes", "writtenBytes")), "installation-metadata-unentered")
    elif expected_state == "recorded":
        need(value["attemptedFiles"] == value["openedFiles"] == 2 and 0 < value["writtenBytes"] == value["plannedBytes"],
             "installation-metadata-not-recorded")
    else:
        need(value["attemptedFiles"] == 2 and value["openedFiles"] == 1 and 0 < value["writtenBytes"] < value["plannedBytes"],
              "installation-metadata-partial-accounting")


def maintenance_gate_result(value, *, entered):
    need(type(value) is dict and set(value) == {"schemaVersion", "entered", "creation", "fixedBytes", "writtenBytes",
         "sealed", "filePersisted", "parentPersisted", "writer", "verified", "exclusiveAttempted", "exclusiveAcquired", "participant", "cleanup"}
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and type(value["fixedBytes"]) is int and value["fixedBytes"] == len(MAINTENANCE_GATE_BYTES)
         and type(value["writtenBytes"]) is int
         and all(type(value[key]) is bool for key in ("entered", "sealed", "filePersisted", "parentPersisted", "verified", "exclusiveAttempted", "exclusiveAcquired"))
         and value["entered"] is entered and value["cleanup"] == "original-closes-only-permanent-gate-retained",
         "maintenance-gate-result")
    if not entered:
        need(value["creation"] == value["writer"] == value["participant"] == "not-attempted"
             and value["writtenBytes"] == 0 and not any(value[k] for k in ("sealed", "filePersisted", "parentPersisted", "verified", "exclusiveAttempted", "exclusiveAcquired")),
             "maintenance-gate-unentered")
        return
    need(value["verified"] and value["exclusiveAttempted"] and value["exclusiveAcquired"]
         and value["participant"] == "closed", "maintenance-gate-original-not-settled")
    if value["creation"] == "created":
        need(value["writtenBytes"] == len(MAINTENANCE_GATE_BYTES) and value["sealed"]
             and value["filePersisted"] and value["parentPersisted"] and value["writer"] == "closed", "maintenance-gate-creation-incomplete")
    else:
        need(value["creation"] == "existing-not-modified" and value["writtenBytes"] == 0
             and value["writer"] == "not-attempted" and not value["sealed"] and not value["filePersisted"]
             and not value["parentPersisted"], "maintenance-gate-reuse-not-observed")


def maintenance_gate_readback(root_fd):
    body, _info = installation_metadata_leaf(root_fd, MAINTENANCE_GATE_NAME, len(MAINTENANCE_GATE_BYTES))
    need(body == MAINTENANCE_GATE_BYTES, "maintenance-gate-content")
    return {"state": "protected-permanent-gate-data-correspondence", "bytes": len(body),
            "exclusionObserved": False, "workerFinalityEstablished": False}


def registration_reservation_result(value, *, entered):
    """Parent original facts only; fixed readback cannot establish these facts."""
    flags = ("entered", "sealed", "filePersisted", "parentPersisted", "verified", "exclusiveAttempted",
             "exclusiveAcquired", "closedUnderMaintenance", "verifiedAfterGo")
    need(type(entered) is bool and type(value) is dict and set(value) == {
         "schemaVersion", "entered", "creation", "fixedBytes", "writtenBytes", "sealed", "filePersisted", "parentPersisted",
         "writer", "verified", "exclusiveAttempted", "exclusiveAcquired", "participant", "closedUnderMaintenance", "verifiedAfterGo", "cleanup"}
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and type(value["fixedBytes"]) is int and value["fixedBytes"] == len(REGISTRATION_GATE_BYTES)
         and type(value["writtenBytes"]) is int and all(type(value[key]) is bool for key in flags)
         and value["entered"] is entered and value["cleanup"] == "original-closes-only-permanent-reservation-retained",
         "registration-reservation-result")
    if not entered:
        need(value["creation"] == value["writer"] == value["participant"] == "not-attempted"
             and value["writtenBytes"] == 0 and not any(value[key] for key in flags), "registration-reservation-unentered")
        return
    need(value["verified"] and value["participant"] == "closed" and value["closedUnderMaintenance"]
         and not value["verifiedAfterGo"], "registration-reservation-parent-not-settled")
    if value["creation"] == "created":
        # Creation was authorized by actual M_EX, not a fictitious R_EX call.
        need(value["writtenBytes"] == len(REGISTRATION_GATE_BYTES) and value["sealed"] and value["filePersisted"]
             and value["parentPersisted"] and value["writer"] == "closed"
             and not value["exclusiveAttempted"] and not value["exclusiveAcquired"], "registration-reservation-creation-incomplete")
    else:
        need(value["creation"] == "existing-not-modified" and value["writtenBytes"] == 0
             and value["writer"] == "not-attempted" and not value["sealed"] and not value["filePersisted"]
             and not value["parentPersisted"] and value["exclusiveAttempted"] and value["exclusiveAcquired"],
             "registration-reservation-reuse-not-observed")


def registration_reservation_readback(root_fd):
    body, _info = installation_metadata_leaf(root_fd, REGISTRATION_GATE_NAME, len(REGISTRATION_GATE_BYTES))
    need(body == REGISTRATION_GATE_BYTES, "registration-reservation-content")
    return {"state": "protected-permanent-reservation-data-correspondence", "bytes": len(body),
            "exclusionObserved": False, "workerFinalityEstablished": False}


@contextlib.contextmanager
def installation_metadata_directory(root, names, *, selection=None):
    """Fixed caller-selected ordinary/fixture installation, read-only originals."""
    selection = selected_build(selection)
    originals = []
    with parent(root) as (outer, name):
        try:
            for entry in (name, "versions", selection.release):
                before = os.stat(entry, dir_fd=outer, follow_symlinks=False)
                data = installation_directory_data(before)
                opened = os.open(entry, READ_FLAGS | os.O_DIRECTORY, dir_fd=outer)
                originals.append((opened, outer, entry, signature(before), data))
                need(signature(os.fstat(opened)) == signature(before)
                     and installation_directory_data(os.fstat(opened)) == data, "installation-directory-changed")
                no_xattrs(opened)
                outer = opened
            need(set(os.listdir(outer)) == names, "installation-release-roster")
            yield originals[0][4], originals[-1][4], outer
            need(set(os.listdir(outer)) == names, "installation-release-roster")
            for opened, outer, entry, before, data in originals:
                current = os.fstat(opened)
                named = os.stat(entry, dir_fd=outer, follow_symlinks=False)
                need(signature(current) == signature(named) == before
                     and installation_directory_data(current) == installation_directory_data(named) == data,
                     "installation-directory-changed")
        finally:
            active = sys.exc_info()[0] is not None
            unknown = False
            for opened, _outer, _entry, _before, _data in reversed(originals):
                try:
                    close_once(opened)
                except Refused:
                    unknown = True
            if unknown and not active:
                raise Refused("installation-metadata-close-unknown")


def installation_metadata_leaf(fd, name, limit):
    body, info = read_at(fd, name, limit, zero_flags=True)
    need(info.st_uid == info.st_gid == 0 and info.st_mode == stat.S_IFREG | 0o444 and info.st_nlink == 1
         and getattr(info, "st_flags", None) == 0, "installation-metadata-file-policy")
    # read_at consumed its original, without retry, before returning these DATA.
    return body, info


def installation_metadata_readback(args, root, original, *, fixture=False, occupant=None, selection=None):
    selection = selected_build(selection) if selection is not None else source_build_selection(command_target(args))
    source_inventory = read(Path(args.input) / INSTALLATION_INVENTORY_NAME, 1024 * 1024)
    need(digest(source_inventory) == args.expected_inventory, "installation-inventory-source")
    metadata = original["installationMetadata"]
    need(metadata["state"] == ("incomplete" if occupant is not None else "recorded"), "installation-readback-phase")
    names = {"runtime", INSTALLATION_INVENTORY_NAME, INSTALLATION_RECORD_NAME}
    with installation_metadata_directory(root, names, selection=selection) as (root_data, release_data, fd):
        inventory, _info = installation_metadata_leaf(fd, INSTALLATION_INVENTORY_NAME, 1024 * 1024)
        need(inventory == source_inventory, "installation-inventory-exact-bytes")
        descriptor, info = installation_metadata_leaf(fd, INSTALLATION_RECORD_NAME, INSTALLATION_RECORD_LIMIT)
        if occupant is None:
            stage = original["staging"]
            need(type(stage) is str and re.fullmatch(r"\.install-[0-9a-f]{32}", stage), "installation-record-instance")
            record = installation_record_data(descriptor, inventory, args.expected_source, args.expected_manifest,
                                              root_data, release_data, stage[9:], fixture=fixture, selection=selection)
            need(metadata["writtenBytes"] == metadata["plannedBytes"] == len(inventory) + len(descriptor),
                 "installation-metadata-exact-accounting")
            result = {"state": "recorded-current-data-correspondence", "instance": record["instance"],
                      "inventoryBytes": len(inventory), "descriptorBytes": len(descriptor), "originalFinality": "separate-Installer-status"}
        else:
            identity = {"device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
                        "links": info.st_nlink, "size": info.st_size, "mtimeSeconds": info.st_mtime_ns // 1000000000,
                        "mtimeNanoseconds": info.st_mtime_ns % 1000000000, "ctimeSeconds": info.st_ctime_ns // 1000000000,
                        "ctimeNanoseconds": info.st_ctime_ns % 1000000000}
            need(descriptor == FIXTURE_MARKER and identity == occupant["before"] == occupant["after"]
                 and metadata["writtenBytes"] == len(inventory) and metadata["openedFiles"] == 1,
                 "installation-metadata-occupant-not-preserved")
            result = {"state": "partial-inventory-and-occupant-preserved", "inventoryBytes": len(inventory),
                      "descriptorBytes": len(descriptor), "originalFinality": "separate-Installer-status"}
    return result  # All original leaf/parent closes returned above.


def maintenance_control_names(target, release):
    # The same DATA name grammar as installed_control_names_data; neither a name
    # nor reading a root-owned file authenticates a descriptor or former process.
    need(type(release) is str and release.isascii(), "maintenance-release-binding")
    build_release_data(canonical({"schemaVersion": 1, "packageVersion": "0.0.0", "release": release}), target=target)
    return (".producer-" + release + ".json", ".producer-" + release + ".sig")


def maintenance_directory_identity(info, mode):
    need(mode in (0o755, 0o555, 0o700), "maintenance-directory-policy")
    return maintenance_identity_data({"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
                                      "uid": info.st_uid, "gid": info.st_gid, "flags": getattr(info, "st_flags", None)}, mode)


@contextlib.contextmanager
def maintenance_directory(parent_fd, name, mode):
    """One existing read-only directory original, with consuming close on failure."""
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    identity = maintenance_directory_identity(before, mode)
    need(before.st_dev == os.fstat(parent_fd).st_dev, "maintenance-directory-volume")
    original = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=parent_fd)
    try:
        need(signature(os.fstat(original)) == signature(before), "maintenance-directory-changed")
        no_xattrs(original)
        yield original, identity
        current = os.fstat(original)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        need(signature(current) == signature(named) == signature(before)
             and maintenance_directory_identity(current, mode) == maintenance_directory_identity(named, mode) == identity,
             "maintenance-directory-changed")
    finally:
        close_once(original)


def maintenance_metadata_leaf(fd, name, limit, budget):
    # Bound before read/allocation. This is the existing 16MiB metadata envelope,
    # including held raw bytes, parse capacity and per-original record overhead.
    remaining = (MAINTENANCE_METADATA_BYTES - budget[0] - 4096) // 8
    need(remaining >= 0, "maintenance-metadata-budget")
    body, _info = installation_metadata_leaf(fd, name, min(limit, remaining))
    budget[0] += len(body) * 8 + 4096
    need(budget[0] <= MAINTENANCE_METADATA_BYTES, "maintenance-metadata-budget")
    return body


def maintenance_roster_data(state, records, target):
    names = {APP_NAME, "versions", MAINTENANCE_GATE_NAME, REGISTRATION_GATE_NAME, MAINTENANCE_STATE_NAME}
    stages = set()
    for invocation, (intent, _old_state, _capsule) in records.items():
        names.update((".maintenance-" + invocation + ".intent.json", ".maintenance-" + invocation + ".capsule.json"))
        if invocation != state["invocation"]:
            names.add(".maintenance-" + invocation + ".state.json")
        if intent["action"] != "same-package-noop":
            stages.add(".install-" + invocation)
    names.update(stages)
    for generation in (state["current"], *state["retained"]):
        names.update(maintenance_control_names(target, generation["release"]["release"]))
        if generation["app"]["location"] == "retained":
            names.add(".retained-app-" + generation["app"]["invocation"])
    need(len(names) <= 512, "maintenance-root-roster-bound")
    return names, stages


def maintenance_generation_readback(root_fd, versions_fd, root_identity, generation, producer, budget,
                                    *, current, source_inventory, source_descriptor, source_signature):
    release = generation["release"]
    selection = BuildSelection(producer["target"], release["packageVersion"], release["release"])
    descriptor_name, signature_name = maintenance_control_names(selection.target, selection.release)
    descriptor = maintenance_metadata_leaf(root_fd, descriptor_name, PRODUCER_DESCRIPTOR_BYTES, budget)
    signed = maintenance_metadata_leaf(root_fd, signature_name, PRODUCER_SIGNATURE_BYTES, budget)
    need(0 < len(signed) <= PRODUCER_SIGNATURE_BYTES, "maintenance-retained-signature-bound")
    if current:
        need(descriptor == source_descriptor and signed == source_signature, "maintenance-installed-producer-exact-bytes")
    else:
        recorded = maintenance_producer_data(descriptor, target=selection.target)
        need(recorded["releaseSet"]["current"] == release, "maintenance-retained-producer-binding")
    # Historical pair parsing is correspondence, NOT a current-signature or old
    # outer-Installer attestation. Only the current payload receives the full walk.
    app_name = APP_NAME if current else ".retained-app-" + generation["app"]["invocation"]
    with maintenance_directory(root_fd, app_name, 0o555) as (_app_fd, app_identity):
        need(app_identity == generation["app"]["identity"], "maintenance-app-object")
        with maintenance_directory(versions_fd, selection.release, 0o755) as (release_fd, release_identity):
            need(release_identity == generation["releaseDirectory"], "maintenance-runtime-object")
            names = {"runtime", INSTALLATION_INVENTORY_NAME, INSTALLATION_RECORD_NAME}
            need(set(os.listdir(release_fd)) == names, "installation-release-roster")
            inventory = maintenance_metadata_leaf(release_fd, INSTALLATION_INVENTORY_NAME, 1024 * 1024, budget)
            record = maintenance_metadata_leaf(release_fd, INSTALLATION_RECORD_NAME, INSTALLATION_RECORD_LIMIT, budget)
            need(digest(inventory) == release["inventorySha256"] and (not current or inventory == source_inventory),
                 "installation-inventory-exact-bytes")
            installation_record_data(record, inventory, release["sourceCommit"], release["runtimeManifestSha256"], root_identity,
                                     release_identity, generation["instance"], selection=selection, expected_protocol=release["protocolSha256"])
            rows = observation_inventory_bytes(inventory, release["inventorySha256"], release["runtimeManifestSha256"], selection=selection)
            verified_files = 0
            if current:
                app = tree(INSTALL_ROOT / APP_NAME, installed=True)
                runtime = tree(INSTALL_ROOT / "versions" / selection.release / "runtime", installed=True)
                actual = {"app/" + name: value for name, value in app.items()}
                actual.update({"runtime/" + name: value for name, value in runtime.items()})
                byte_correspondence(actual, rows)
                verified_files = len(actual)
            else:
                # The retained runtime is at its original fixed path and is only
                # a protected directory observation here, not a payload rehash.
                with maintenance_directory(release_fd, "runtime", 0o555):
                    pass
            need(set(os.listdir(release_fd)) == names, "installation-release-roster")
    declared_bytes = sum(row["size"] for row in rows.values()) + len(inventory) + len(record) + len(descriptor) + len(signed)
    return {"release": selection.release, "instance": generation["instance"], "inventoryBytes": len(inventory),
            "descriptorBytes": len(record), "producerDescriptorBytes": len(descriptor), "producerSignatureBytes": len(signed),
            "verifiedCurrentFiles": verified_files, "declaredPayloadFiles": len(rows), "declaredBytes": declared_bytes,
            "historicalOuterExit": "unverified"}


def observation_command(args):
    selection = source_build_selection(command_target(args))
    # The same-run original Installer0 is first. No export/file can certify its
    # own future close, kernel-retained gate lifetime or original outer return.
    result, exported = installer_result_readback(args)
    producer, descriptor, signed = maintenance_producer_inputs(args, selection)
    source_inventory = read(Path(args.input) / INSTALLATION_INVENTORY_NAME, 1024 * 1024)
    observation_inventory_bytes(source_inventory, args.expected_inventory, args.expected_manifest, selection=selection)
    budget = [(len(source_inventory) + len(descriptor) + len(signed) + len(MAINTENANCE_GATE_BYTES) + len(REGISTRATION_GATE_BYTES)) * 8 + 3 * 4096]
    need(budget[0] <= MAINTENANCE_METADATA_BYTES, "maintenance-metadata-budget")
    with installer_channel_parent(INSTALL_ROOT) as (outer, name):
        with maintenance_directory(outer, name, 0o755) as (root_fd, root_identity):
            current_body = maintenance_metadata_leaf(root_fd, MAINTENANCE_STATE_NAME, 16 * 1024, budget)
            current = maintenance_state_data(current_body, producer)
            need(current["invocation"] == result["invocation"] and current["requestId"] == args.request_id,
                 "maintenance-not-requested-current-state")
            records = {}
            for invocation in (current["invocation"], *(row["invocation"] for row in current["previousEvidence"])):
                intent = maintenance_metadata_leaf(root_fd, ".maintenance-" + invocation + ".intent.json", 16 * 1024, budget)
                state = current_body if invocation == current["invocation"] else maintenance_metadata_leaf(
                    root_fd, ".maintenance-" + invocation + ".state.json", 16 * 1024, budget)
                capsule = maintenance_metadata_leaf(root_fd, ".maintenance-" + invocation + ".capsule.json", 64 * 1024, budget)
                records[invocation] = (intent, state, capsule)
            current, parsed = maintenance_history_data(result, records, producer)
            names, stages = maintenance_roster_data(current, parsed, selection.target)
            need(set(os.listdir(root_fd)) == names, "maintenance-root-roster")
            stage_originals = []
            for stage in sorted(stages):
                # Root-private retained stages are stat-only from this nonroot
                # reader. Do not claim to have opened or checked their contents.
                info = os.stat(stage, dir_fd=root_fd, follow_symlinks=False)
                identity = maintenance_directory_identity(info, 0o700)
                need(identity["device"] == root_identity["device"], "maintenance-directory-volume")
                stage_originals.append((stage, signature(info)))
            gate = maintenance_gate_readback(root_fd)
            reservation = registration_reservation_readback(root_fd)
            generation_results = []
            with maintenance_directory(root_fd, "versions", 0o755) as (versions_fd, _versions_identity):
                versions = {generation["release"]["release"] for generation in (current["current"], *current["retained"])}
                need(set(os.listdir(versions_fd)) == versions, "maintenance-versions-roster")
                for index, generation in enumerate((current["current"], *current["retained"])):
                    generation_results.append(maintenance_generation_readback(root_fd, versions_fd, root_identity, generation, producer, budget,
                        current=index == 0, source_inventory=source_inventory, source_descriptor=descriptor, source_signature=signed))
                    need(sum(row["declaredPayloadFiles"] for row in generation_results) + 2 <= MAX_FILES
                         and sum(row["declaredBytes"] for row in generation_results) + len(MAINTENANCE_GATE_BYTES)
                         + len(REGISTRATION_GATE_BYTES) <= MAX_BYTES, "maintenance-declared-generation-bound")
                need(set(os.listdir(versions_fd)) == versions, "maintenance-versions-roster")
            # Pin the same requested current state throughout current-byte and
            # retained-metadata readback. A newer operation never substitutes.
            need(maintenance_metadata_leaf(root_fd, MAINTENANCE_STATE_NAME, 16 * 1024, budget) == current_body,
                 "maintenance-current-state-changed")
            for stage, original in stage_originals:
                final = os.stat(stage, dir_fd=root_fd, follow_symlinks=False)
                maintenance_directory_identity(final, 0o700)
                need(signature(final) == original, "maintenance-root-roster-changed")
            need(set(os.listdir(root_fd)) == names, "maintenance-root-roster-changed")
    # No result is returned until every acquired original above has closed.
    return {"schemaVersion": 2, "sourceCommit": args.expected_source, "inventorySha256": args.expected_inventory,
            "runtimeManifestSha256": args.expected_manifest, "completedPackageSha256": args.expected_package, "release": selection.release,
            "requestId": args.request_id, "invocation": current["invocation"], "originalInstallerReturnedZero": True,
            "originalWriterJoined": True, "nonrootReadbackFileCount": generation_results[0]["verifiedCurrentFiles"],
            "originalInstallerResult": result, "installerResultExport": exported, "installationMetadata": generation_results,
            "maintenanceGate": gate, "registrationReservation": reservation, "producerSignatureAuthority": "native-parent-and-application-checks-separate",
            "historicalOuterExit": "unverified", "applicationLaunched": False, "guiSaveQualified": False,
            "aquaGate": "required-separate-actual-session", "qualification": "engineering-install-observed-not-runtime-or-GUI-acceptance"}


def visible_occupant(case, *, selection=None):
    selection = selected_build(selection)
    if case in ("occupied-app", "first-publication-second-refusal"):
        return APP_NAME + "/occupied.txt"
    if case in ("occupied-release", "runtime-publication-collision"):
        return "versions/" + selection.release + "/runtime/occupied.txt"
    if case == "metadata-descriptor-collision":
        return "versions/" + selection.release + "/" + INSTALLATION_RECORD_NAME
    return None


def fixture_record(log, source, inventory, manifest, *, selection=None):
    # Legacy marker parser is diagnostic/test-only, never readback authority.
    return bound_fixture_result(installer_record(log, fixture=True), source, inventory, manifest, selection=selection)


def bound_fixture_result(result, source, inventory, manifest, *, selection=None):
    selection = selected_build(selection)
    need(type(source) is str and re.fullmatch(r"[0-9a-f]{40}", source) and sha(inventory) and sha(manifest), "fixture-input-binding")
    need(type(result) is dict and set(result) == {"schemaVersion", "sourceCommit", "inventorySha256", "runtimeManifestSha256", "fixtureBase", "setupError",
         "setupOriginalsSettled", "setupDeadlineMet", "inertCloseDeadlinePolicyTable", "fixedCasesComplete", "passed", "cases",
         "genuineConcurrentRaceObserved", "nativeCloseFailureInjected", "applicationLaunched", "guiSaveQualified", "qualification"}, "fixture-closed-shape")
    need(type(result["schemaVersion"]) is int and result["schemaVersion"] == 1 and result["sourceCommit"] == source
         and result["inventorySha256"] == inventory and result["runtimeManifestSha256"] == manifest and result["setupError"] is None
         and all(result[key] is True for key in ("setupOriginalsSettled", "setupDeadlineMet", "inertCloseDeadlinePolicyTable", "fixedCasesComplete", "passed"))
         and all(result[key] is False for key in ("genuineConcurrentRaceObserved", "nativeCloseFailureInjected", "applicationLaunched", "guiSaveQualified"))
         and result["qualification"] == "native-installer-collisions-and-injected-policy-only", "fixture-not-complete-or-bound")
    # Never accept a report-supplied arbitrary pathname: fixed protected ancestry,
    # this explicit source prefix, one nonce component, then eight fixed names.
    need(type(result["fixtureBase"]) is str and re.fullmatch(re.escape(FIXTURE_PREFIX + source[:12] + "-") + r"[0-9a-f]{32}", result["fixtureBase"]), "fixture-base-binding")
    need(type(result["cases"]) is list and len(result["cases"]) == len(FIXTURE_CASES), "fixture-exact-eight-cases")
    for row, (name, expected) in zip(result["cases"], FIXTURE_CASES.items()):
        need(type(row) is dict and set(row) == {"case", "passed", "proofError", "originalResult", "originalExit", "occupant",
             "absenceObservedBeforeCollision", "stagingOpenErrno", "persistence"} and row["case"] == name
             and row["passed"] is True and row["proofError"] is None and type(row["originalExit"]) is int and row["originalExit"] == expected[-1], "fixture-case-shape-or-outcome")
        bound_original_result(row["originalResult"], expected, source, inventory, manifest, selection=selection)
        need((row["originalResult"]["staging"] is None) == (name in ("occupied-app", "occupied-release")), "fixture-staging-phase")
        collision = name in ("runtime-publication-collision", "staging-file-collision", "first-publication-second-refusal", "metadata-descriptor-collision")
        need(row["absenceObservedBeforeCollision"] is collision, "fixture-absence-observation")
        error = row["stagingOpenErrno"]
        need((type(error) is int and error == 17) if name in ("staging-file-collision", "metadata-descriptor-collision") else error is None, "fixture-actual-o-excl-eexist")  # Darwin EEXIST.
        point = {"prepublication-persistence-report": "payload-file-before-any-publication",
                 "postruntime-persistence-report": "stage-directory-after-runtime-rename"}.get(name)
        persistence = row["persistence"]
        if point is not None:
            need(type(persistence) is dict and set(persistence) == {"point", "actualNativeSucceeded", "actualNativeErrno", "injectedReportedFailure"}
                 and persistence["point"] == point and persistence["actualNativeSucceeded"] is True and persistence["actualNativeErrno"] is None
                 and persistence["injectedReportedFailure"] is True and row["occupant"] is None, "fixture-reported-not-actual-native-failure")
        else:
            need(persistence is None, "unexpected-fixture-persistence-report")
            witness = row["occupant"]
            need(type(witness) is dict and set(witness) == {"visibleRelativePath", "sha256", "before", "after", "verifiedByOriginalInstaller"}
                 and witness["visibleRelativePath"] == visible_occupant(name, selection=selection) and witness["sha256"] == digest(FIXTURE_MARKER)
                 and witness["verifiedByOriginalInstaller"] is True and witness["before"] == witness["after"], "fixture-occupant-witness")
            identity = witness["before"]
            need(type(identity) is dict and set(identity) == {"device", "inode", "mode", "uid", "gid", "links", "size",
                 "mtimeSeconds", "mtimeNanoseconds", "ctimeSeconds", "ctimeNanoseconds"} and all(type(value) is int for value in identity.values())
                 and type(witness["after"]) is dict and all(type(value) is int for value in witness["after"].values())
                 and identity["inode"] > 0 and identity["mode"] == 0o444 and identity["uid"] == identity["gid"] == 0 and identity["links"] == 1
                 and identity["size"] == len(FIXTURE_MARKER) and 0 <= identity["mtimeNanoseconds"] < 1000000000
                 and 0 <= identity["ctimeNanoseconds"] < 1000000000, "fixture-occupant-identity")
    return result


@contextlib.contextmanager
def fixture_directory(path, names):
    with parent(path) as (outer, name):
        before = os.stat(name, dir_fd=outer, follow_symlinks=False)
        need(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o755, "fixture-ancestor-protection")
        original = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=outer)
        try:
            need(signature(os.fstat(original)) == signature(before), "fixture-directory-changed")
            no_xattrs(original)
            need(set(os.listdir(original)) == names, "fixture-directory-roster")
            yield original
            need(signature(os.fstat(original)) == signature(before)
                 and signature(os.stat(name, dir_fd=outer, follow_symlinks=False)) == signature(before), "fixture-directory-changed")
        finally:
            close_once(original)


def observe_occupant(path, witness):
    with parent(path) as (fd, name):
        before = os.fstat(fd)
        need(before.st_uid == before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o555 and set(os.listdir(fd)) == {"occupied.txt"}, "fixture-occupant-directory")
        no_xattrs(fd)
        body, info = read_at(fd, name, len(FIXTURE_MARKER))
        identity = {"device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
                    "links": info.st_nlink, "size": info.st_size, "mtimeSeconds": info.st_mtime_ns // 1000000000,
                    "mtimeNanoseconds": info.st_mtime_ns % 1000000000, "ctimeSeconds": info.st_ctime_ns // 1000000000, "ctimeNanoseconds": info.st_ctime_ns % 1000000000}
        need(body == FIXTURE_MARKER and identity == witness["before"] == witness["after"] and signature(os.fstat(fd)) == signature(before), "fixture-occupant-not-preserved")


def fixture_observation_command(args):
    selection = source_build_selection(command_target(args))
    expected = observation_inventory(args, selection=selection)
    result, exported = installer_result_readback(args, fixture=True)
    bound_fixture_result(result, args.expected_source, args.expected_inventory, args.expected_manifest, selection=selection)
    base = INSTALL_ROOT.parent / result["fixtureBase"]  # Closed source/nonce component validated above.
    published = {name: row for name, row in expected.items() if name.startswith("runtime/")}
    observations = []
    with fixture_directory(base, set(FIXTURE_CASES)):
        for row in result["cases"]:
            name = row["case"]
            root = base / name
            stage = row["originalResult"]["staging"]
            app_occupant = name in ("occupied-app", "first-publication-second-refusal")
            has_versions = name != "occupied-app"
            has_release = name in ("occupied-release", "runtime-publication-collision", "first-publication-second-refusal", "postruntime-persistence-report", "metadata-descriptor-collision")
            runtime_published = row["originalResult"]["runtimePublication"] == "confirmed"
            names = ({stage} if stage is not None else set()) | ({APP_NAME} if app_occupant else set()) | ({"versions"} if has_versions else set())
            if row["originalResult"]["maintenanceGate"]["entered"]:
                names.add(MAINTENANCE_GATE_NAME)
            if row["originalResult"]["registrationReservation"]["entered"]:
                names.add(REGISTRATION_GATE_NAME)
            runtime_files = 0
            metadata_observation = None
            with fixture_directory(root, names) as fd:
                gate = maintenance_gate_readback(fd) if MAINTENANCE_GATE_NAME in names else None
                reservation = registration_reservation_readback(fd) if REGISTRATION_GATE_NAME in names else None
                if stage is not None:
                    # Metadata only. Never open/chmod the root-owned0700 staging.
                    info = os.stat(stage, dir_fd=fd, follow_symlinks=False)
                    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700, "fixture-protected-staging")
                if app_occupant:
                    observe_occupant(root / APP_NAME / "occupied.txt", row["occupant"])
                if has_versions:
                    with fixture_directory(root / "versions", {selection.release} if has_release else set()):
                        if has_release:
                            metadata_reached = row["originalResult"]["installationMetadata"]["state"] != "not-attempted"
                            members = {"runtime"} | ({INSTALLATION_INVENTORY_NAME, INSTALLATION_RECORD_NAME} if metadata_reached else set())
                            with fixture_directory(root / "versions" / selection.release, members):
                                runtime_path = root / "versions" / selection.release / "runtime"
                                if runtime_published:
                                    files = tree(runtime_path, installed=True)
                                    byte_correspondence({"runtime/" + key: value for key, value in files.items()}, published)
                                    runtime_files = len(files)
                                else:
                                    observe_occupant(runtime_path / "occupied.txt", row["occupant"])
                                if metadata_reached:
                                    metadata_observation = installation_metadata_readback(args, root, row["originalResult"], fixture=True,
                                        occupant=row["occupant"] if name == "metadata-descriptor-collision" else None, selection=selection)
            observations.append({"case": name, "accessibleOccupantChecked": visible_occupant(name, selection=selection) is not None,
                                 "runtimeReadbackFileCount": runtime_files, "protectedStagingOpened": False, "installationMetadata": metadata_observation,
                                 "maintenanceGate": gate, "registrationReservation": reservation})
    return {"schemaVersion": 1, "sourceCommit": args.expected_source, "inventorySha256": args.expected_inventory,
            "runtimeManifestSha256": args.expected_manifest, "originalFixtureResult": result, "installerResultExport": exported, "nonrootReadback": observations,
            "applicationLaunched": False, "guiSaveQualified": False, "genuineConcurrentRaceObserved": False,
            "nativeCloseFailureInjected": False, "qualification": "fixed-native-collisions-and-reported-policy-only-not-Aqua-Save-or-power-loss"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("describe-runtime", "runtime"):
        command = commands.add_parser(name)
        command.add_argument("--archive", required=True, type=Path)
        if name == "runtime":
            command.add_argument("--expected-manifest", required=True)
            command.add_argument("--output", required=True, type=Path)
    for name in ("describe-current-runtime", "current-runtime"):
        command = commands.add_parser(name)
        supplier = command.add_mutually_exclusive_group(required=True)
        supplier.add_argument("--archive", type=Path, help="Historical SOURCE-compatible route, never a fresh supplier fallback")
        supplier.add_argument("--python-root", type=Path, help="Fresh read-only supplier root containing only python/")
        command.add_argument("--supplier-receipt", type=Path, help="Fresh supplier receipt, outside its python-only root")
        command.add_argument("--expected-supplier", help="Independently reviewed SHA256 of the fresh supplier receipt")
        command.add_argument("--signed-python", type=Path, help="Explicit configured-signing capsule executable; never fallback")
        command.add_argument("--signing-receipt", type=Path)
        for option in ("signed-python", "signing-receipt", "signing-source", "signing-run", "signing-attempt"):
            command.add_argument("--expected-" + option)
        command.add_argument("--work", required=True, type=Path)
        if name == "current-runtime":
            command.add_argument("--configured-signing", action="store_true",
                                 help="Require the fixed SOURCE capsule/S/M nomination, never a CLI replacement")
            command.add_argument("--expected-source", required=True)
            command.add_argument("--expected-manifest", required=True)
            command.add_argument("--output", required=True, type=Path)
    commands.add_parser("packaging-selection", help="Fixed SOURCE signing/release DATA; refuses unconfigured ordinary distribution")
    commands.add_parser("runtime-signing-selection", help="Fixed SOURCE signed-runtime nomination; refuses unconfigured target")
    capsule = commands.add_parser("project-signed-python", help="Project only the two SOURCE-pinned capsule files as DATA")
    capsule.add_argument("--transport-root", required=True, type=Path)
    capsule.add_argument("--output", required=True, type=Path)
    app = commands.add_parser("app")
    app.add_argument("--package-role", required=True, choices=PACKAGE_ROLES)
    app.add_argument("--binary", required=True, type=Path)
    app.add_argument("--expected-app-binary", required=True)
    app.add_argument("--desktop-image", type=Path)
    app.add_argument("--expected-desktop-image")
    app.add_argument("--desktop-image-cargo-messages", type=Path)
    app.add_argument("--desktop-image-cargo-target-dir", type=Path)
    app.add_argument("--observer-cargo-messages", type=Path)
    app.add_argument("--observer-cargo-target-dir", type=Path)
    app.add_argument("--resident-image", required=True, type=Path)
    app.add_argument("--expected-resident-image", required=True)
    app.add_argument("--entry-binary", required=True, type=Path)
    app.add_argument("--expected-entry", required=True)
    app.add_argument("--vault-helper", required=True, type=Path)
    app.add_argument("--expected-vault-helper", required=True)
    app.add_argument("--android-helper", required=True, type=Path,
                     help="Already-signed fixed resident facade; requires the resident image and exact signed digests")
    app.add_argument("--expected-android-helper", required=True)
    app.add_argument("--remover", required=True, type=Path)
    app.add_argument("--expected-remover", required=True)
    app.add_argument("--remover-cargo-messages", required=True, type=Path)
    app.add_argument("--remover-cargo-target-dir", required=True, type=Path)
    app.add_argument("--removal-abrupt-fixture", action="store_true",
                     help="NONSHIPPING exact same-engine abrupt graph; never ordinary product qualification")
    app.add_argument("--output", required=True, type=Path)
    app.add_argument("--bundletool-archive", required=True, type=Path)
    app.add_argument("--aapt2-archive", required=True, type=Path)
    support = commands.add_parser("android-support", help="Verify only the two fixed original support archives and notices; never execute them")
    support.add_argument("--bundletool-archive", required=True, type=Path)
    support.add_argument("--aapt2-archive", required=True, type=Path)
    preview = commands.add_parser("preview")
    preview.add_argument("--work", required=True, type=Path)
    preview.add_argument("--expected-source", required=True)
    preview.add_argument("--output", required=True, type=Path)
    remove_preview = commands.add_parser("remove-preview")
    remove_preview.add_argument("--work", required=True, type=Path)
    remove_preview.add_argument("--expected-source", required=True)
    remove_preview.add_argument("--output", required=True, type=Path)
    inputs = commands.add_parser("input")
    inputs.add_argument("--package-role", required=True, choices=PACKAGE_ROLES)
    inputs.add_argument("--app", required=True, type=Path)
    inputs.add_argument("--expected-desktop-image")
    inputs.add_argument("--expected-resident-image", required=True)
    inputs.add_argument("--expected-entry", required=True)
    inputs.add_argument("--expected-app-binary", required=True)
    inputs.add_argument("--expected-vault-helper", required=True)
    inputs.add_argument("--expected-android-helper", required=True,
                        help="Final signed resident facade digest; the complete helper/image/plist group is required")
    inputs.add_argument("--runtime", required=True, type=Path)
    inputs.add_argument("--expected-manifest", required=True)
    inputs.add_argument("--current-runtime", action="store_true",
                        help="Select the fixed current protocol and bootstrap roster; default retains the historical profile")
    inputs.add_argument("--expected-remover", required=True)
    inputs.add_argument("--output", required=True, type=Path)
    scripts = commands.add_parser("scripts")
    scripts.add_argument("--input", required=True, type=Path)
    scripts.add_argument("--installer", required=True, type=Path)
    scripts.add_argument("--expected-inventory", required=True)
    scripts.add_argument("--expected-source", required=True)
    scripts.add_argument("--fixture", action="store_true")
    scripts.add_argument("--output", required=True, type=Path)
    probe = commands.add_parser("package-format-input")
    probe.add_argument("--output", required=True, type=Path)
    for name in ("prepare-package", "audit-package"):
        package = commands.add_parser(name)
        package.add_argument("--scripts", required=True, type=Path)
        package.add_argument("--package", required=True, type=Path)
        package.add_argument("--fixture", action="store_true")
        if name == "prepare-package":
            package.add_argument("--output", required=True, type=Path)
        else:
            package.add_argument("--original-package", required=True, type=Path)
    remove_scripts = commands.add_parser("remove-scripts")
    remove_scripts.add_argument("--output", required=True, type=Path)
    remove_scripts.add_argument("--remover", required=True, type=Path)
    remove_scripts.add_argument("--expected-remover", required=True)
    remove_scripts.add_argument("--removal-abrupt-fixture", action="store_true")
    for name in ("prepare-remove-package", "audit-remove-package"):
        package = commands.add_parser(name)
        package.set_defaults(fixture=False, remove=True)
        package.add_argument("--removal-abrupt-fixture", action="store_true")
        package.add_argument("--expected-remover", required=True)
        package.add_argument("--scripts", required=True, type=Path)
        package.add_argument("--package", required=True, type=Path)
        if name == "prepare-remove-package":
            package.add_argument("--output", required=True, type=Path)
        else:
            package.add_argument("--original-package", required=True, type=Path)
    remove_input = commands.add_parser("remove-input")
    for name in ("installed-producer", "installed-signature", "inventory", "remover", "package", "output"):
        remove_input.add_argument("--" + name, required=True, type=Path)
    remove_input.add_argument("--expected-source", required=True)
    remove_input.add_argument("--expected-manifest", required=True)
    for name in ("observe-installation", "observe-installer-fixture"):
        observation = commands.add_parser(name)
        observation.add_argument("--input", required=True, type=Path)
        observation.add_argument("--expected-inventory", required=True)
        observation.add_argument("--expected-manifest", required=True)
        observation.add_argument("--expected-source", required=True)
        observation.add_argument("--installer-status", required=True, type=Path)
        if name == "observe-installation":
            observation.add_argument("--request-id", required=True)
            observation.add_argument("--expected-package", required=True)
            observation.add_argument("--producer-descriptor", required=True, type=Path)
            observation.add_argument("--producer-signature", required=True, type=Path)
    absent = commands.add_parser("check-installer-result-absent")
    absent.add_argument("--fixture", action="store_true")
    absent.add_argument("--expected-source", required=True)
    absent.add_argument("--expected-inventory", required=True)
    absent.add_argument("--expected-manifest", required=True)
    absent.add_argument("--request-id", help="Required ordinary correlation ID; never inferred from the installation or an export")
    for name in ("installer-log-cursor", "installer-log-capture"):
        diagnostic = commands.add_parser(name)
        diagnostic.add_argument("--fixture", action="store_true")
        diagnostic.add_argument("--package", required=True, type=Path)
        diagnostic.add_argument("--request-id", help="Ordinary fixed mounted package correlation only; absent for fixtures")
        diagnostic.add_argument("--expected-source", required=True)
        diagnostic.add_argument("--expected-inventory", required=True)
        diagnostic.add_argument("--expected-manifest", required=True)
        diagnostic.add_argument("--run-id", required=True)
        diagnostic.add_argument("--run-attempt", required=True)
        if name == "installer-log-capture":
            diagnostic.add_argument("--cursor", required=True, type=Path)
            diagnostic.add_argument("--selected-output", required=True, type=Path)
    for command in commands.choices.values():
        command.add_argument("--target", choices=MAC_TARGETS, default=ARM_TARGET,
                             help="Exact Mac build target; unqualified legacy routes remain ARM-only")
    args = parser.parse_args(argv)
    if getattr(args, "removal_abrupt_fixture", False) and args.command != "app":
        need(args.command in ("remove-scripts", "prepare-remove-package", "audit-remove-package"),
             "removal-fixture-cli-purpose")
        args.removal_fixture_role = "abrupt"
        args.removal_fixture_correlation = args.removal_fixture_binding = None
    need(args.command == "describe-runtime" or os.getuid() != 0 and os.getuid() == os.geteuid(), "only-installer-is-privileged")
    if args.command in ("installer-log-cursor", "installer-log-capture"):
        result, status = installer_log_diagnostic(args)
        print(canonical(result).decode("utf-8"))
        return status
    action = {"packaging-selection": packaging_selection_command, "runtime-signing-selection": runtime_signing_selection_command,
              "project-signed-python": project_signed_python_command, "describe-runtime": runtime_command, "runtime": runtime_command,
              "describe-current-runtime": current_runtime_command, "current-runtime": current_runtime_command, "app": app_command, "preview": preview_command, "remove-preview": remove_preview_command,
              "input": input_command, "android-support": android_support_command, "scripts": scripts_command, "package-format-input": package_format_input_command,
              "prepare-package": prepare_package_command, "audit-package": audit_command,
              "remove-scripts": remove_scripts_command, "remove-input": remove_input_command,
              "prepare-remove-package": prepare_package_command, "audit-remove-package": audit_command,
              "check-installer-result-absent": installer_result_absent_command,
              "observe-installation": observation_command, "observe-installer-fixture": fixture_observation_command}[args.command]
    try:
        result = action(args)
    except Refused as error:
        if args.command in ("app", "android-support", "input", "package-format-input", "prepare-package", "audit-package"):
            print(package_refusal_message(error), file=sys.stderr)
            raise SystemExit(1)
        raise
    print(canonical(result).decode("utf-8"))


if __name__ == "__main__":
    try:
        PACKAGE_VERSION, RELEASE = source_build_release()
        raise SystemExit(main())
    except (Refused, OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError, zipfile.BadZipFile, tarfile.TarError, ET.ParseError):
        print(GENERIC_REFUSAL, file=sys.stderr)
        raise SystemExit(1)
else:
    # Contract consumers use the same fixed source selection. No payload is
    # imported or executed; only this bounded source DATA is read once.
    PACKAGE_VERSION, RELEASE = source_build_release()
