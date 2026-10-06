#!/usr/bin/env python3
"""Fixed engineering Android-helper packaging, never service registration.

Fixed helper prepare/verify and ordinary package-install entries reuse the same
original process owner. Import is DATA-only; the hosted main alone loads that
owner. SOURCE selects the signing identity. The unconfigured helper engineering
path is separate; ordinary V2 distribution requires genuine configured inputs.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import time

CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
WORK_PARENT = Path("/Users/runner/work/_temp")
HELPER = "mrk-android-register"
ENTRY = "mrk-macos-entry"
DESKTOP_FACADE = "mobile-release-kit-desktop"
RESIDENT_IMAGE = "libmrk_resident_image.dylib"
IMAGE_TARGET = "mrk_resident_image"
PREPARE_ROLES = ("build", "resident-image-sign", "resident-image-verify-signed", "entry-build",
                 "desktop-facade-build", "resident-facade-build", "sign", "verify-signed")
IDENTIFIER = "dev.mobile-release-kit.desktop.android-register"
WORKSPACE = "desktop/helpers/macos-android-register"
PROFILE = "desktop/packaging/macos-android-service-signing.profile"
UNCONFIGURED_PROFILE = (
    b"schema=1\napp-identifier=dev.mobile-release-kit.desktop\n"
    b"helper-identifier=dev.mobile-release-kit.desktop.android-register\n"
    b"team-identifier=unconfigured\ndeveloper-id-certificate-sha1=unconfigured\n"
)
PACKAGE_SCOPES = (
    "project-fields", "ios-current-synthetic", "android-inputs",
    "project-fields-android-inputs", "vault-helper-shipping",
    "installation-inspection", "vault-helper-shipping-installation-inspection",
    "project-recovery-pending", "ios-recovery-pending", "doctor-preflight2", "local-edits3",
)
PHASES = ("prepare", "verify-before", "verify-after", "package-install")
PRODUCER_PROFILE = "desktop/packaging/macos-install-producer-signing.profile"
ARM_TARGET = "aarch64-apple-darwin"
INTEL_TARGET = "x86_64-apple-darwin"
MAX_HELPER = 32 * 1024 * 1024
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


PYTHON_PHASES = ("python-engineering", "python-shipping")
PYTHON_IDENTIFIER = "dev.mobile-release-kit.desktop.python"
PYTHON_ROLES = ("python-sign", "python-verify", "python-modules", "python-loader", "python-tls", "python-cancellation")
PYTHON_SUPPLIERS = {
    ARM_TARGET: {"receiptSha256": "2f9cf013c0598b08e89fd9b26d1d74d8ab08be2c22c152ae27cb3219139cd81d",
        "tarSha256": "ff7883185cf8226e9366b1ee9a3dcb3eb8ee761dbc1f697f952510a6bd858695",
        "sourceCommit": "158cdff422e3837f7ab5e6192af76a578faf6fab", "runId": "37467019389", "runAttempt": "1", "artifactId": "11415902210"},
    INTEL_TARGET: {"receiptSha256": "a46f6838afdb7c20c3539e8f65891312aa8df10e2de67e9b9e3ddbf449883b4b",
        "tarSha256": "739cc8b8b3c68daffba8d7b9cb7cb54ca730eef2c5842302ae8a2682bf64d5bd",
        "sourceCommit": "079ab2a2c8fef88f01bf909e7669c685f07e1375", "runId": "37476532238", "runAttempt": "1", "artifactId": "11419502465"},
}


SIGNING_PHASES = ("sign-vault-helper", "sign-desktop-image", "sign-desktop-payload", "sign-root-app", "sign-root-installer")
CREDENTIAL_VARIABLES = ("MRK_MACOS_DEVELOPER_ID_P12_BASE64", "MRK_MACOS_DEVELOPER_ID_P12_PASSWORD")
CREDENTIAL_ROLES = ("search-before", "default-before", "create", "search-created", "settings", "unlock", "import",
                    "partitions", "identity", "certificates", "search-admit", "restrict", "search-restricted",
                    "search-after-callback", "restore", "search-restored", "delete", "default-after", "search-final",
                    "producer-adhoc", "producer-adhoc-verify", "producer-cdhash")


def credential_values(environment):
    """Bounded secrets only; neither inputs nor their hashes are public evidence."""
    encoded, password = (environment.get(key) for key in CREDENTIAL_VARIABLES)
    need(type(encoded) is str and 4 <= len(encoded) <= 43692 and encoded.isascii()
         and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded) is not None
         and type(password) is str and 1 <= len(password) <= 1024
         and all(0x20 <= ord(value) <= 0x7e for value in password), "credential-input-bound")
    try:
        body = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise Refused("credential-base64") from None
    need(0 < len(body) <= 32768 and base64.b64encode(body).decode("ascii") == encoded, "credential-base64")
    return body, password


def credential_paths(body, *, single=False):
    """Decode only security's quoted user-domain path list, without escapes."""
    need(type(body) is bytes and len(body) <= 16384 and (not body or body.endswith(b"\n")), "credential-search-format")
    paths = []
    for line in body.splitlines(keepends=True):
        match = re.fullmatch(rb'[ \t]*"(/[\x20-\x21\x23-\x5b\x5d-\x7e]{1,4094})"\n', line)
        need(match is not None, "credential-search-format")
        path = match[1].decode("ascii")
        need(all(part not in ("", ".", "..") for part in path[1:].split("/")), "credential-search-format")
        paths.append(path)
    need(len(paths) <= 16 and len(paths) == len(set(paths)) and (not single or len(paths) == 1), "credential-search-format")
    return tuple(paths)


def credential_identity(identity_body, certificate_body, identity, certificates):
    """Exact public SOURCE identity and cert bytes; no general PKCS12 parser."""
    signing_requirement(identity, PYTHON_IDENTIFIER)
    need(type(identity_body) is bytes and type(certificate_body) is bytes
         and len(identity_body) <= 16384 and len(certificate_body) <= 16384
         and type(certificates) is tuple and len(certificates) == 3 and all(type(value) is bytes for value in certificates),
         "credential-identity-bound")
    try:
        text = identity_body.decode("utf-8")
    except UnicodeError:
        raise Refused("credential-identity-format") from None
    rows, summaries = [], []
    for line in text.splitlines():
        match = re.fullmatch(r'[ \t]*1\) ([0-9A-Fa-f]{40}) "([^"\x00-\x1f\x7f]{1,512})"', line)
        if match is not None:
            rows.append(match[1].lower())
        elif re.fullmatch(r"[ \t]*1 valid identities found", line):
            summaries.append(True)
        else:
            need(not line.strip(), "credential-identity-format")
    need(rows == [identity[1]] and summaries == [True], "credential-source-identity")
    pattern = rb"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n"
    values, end = [], 0
    for match in re.finditer(pattern, certificate_body):
        need(match.start() == end and len(values) < 3, "credential-certificate-format")
        encoded = match[1].replace(b"\n", b"")
        try:
            value = base64.b64decode(encoded, validate=True)
        except ValueError:
            raise Refused("credential-certificate-format") from None
        need(0 < len(value) <= 16384 and base64.b64encode(value) == encoded, "credential-certificate-format")
        values.append(value); end = match.end()
    need(end == len(certificate_body) and values and len(values) == len(set(values))
         and certificates[0] in values and all(value in certificates for value in values), "credential-source-certificates")


def credential_cdhash(body):
    need(type(body) is bytes and len(body) <= 16384, "producer-cdhash-bound")
    try:
        text = body.decode("utf-8")
    except UnicodeError:
        raise Refused("producer-cdhash-format") from None
    hashes = [line for line in text.splitlines() if line.startswith("CDHash=")]
    signatures = [line for line in text.splitlines() if line.startswith("Signature=")]
    need(len(hashes) == 1 and re.fullmatch(r"CDHash=[0-9a-f]{40}", hashes[0]) is not None
         and signatures == ["Signature=adhoc"], "producer-cdhash-format")
    return hashes[0][7:]


def python_sign_command(path, entitlements, phase, identity):
    need(phase in PYTHON_PHASES and isinstance(path, Path) and isinstance(entitlements, Path), "python-sign-purpose")
    if phase == "python-engineering":
        signer, timestamp = "-", "--timestamp=none"
    else:
        signing_requirement(identity, PYTHON_IDENTIFIER)
        signer, timestamp = identity[1], "--timestamp"
    return ["/usr/bin/codesign", "--force", "--sign", signer, "--identifier", PYTHON_IDENTIFIER,
            "--options", "runtime", "--entitlements", str(entitlements), timestamp, str(path)]


def python_code_flags(body, machine, phase, matcher):
    """Observe bounded signed headers; codesign, not this reader, verifies crypto."""
    need(phase in PYTHON_PHASES and type(body) is bytes and 0 < len(body) <= MAX_HELPER, "python-signed-image-bound")
    records = matcher.macho_records(body, machine)
    commands = [row for row in records if row["command"] == 0x1D]
    need(len(commands) == 1 and commands[0]["size"] == 16, "python-signature-command")
    offset, size = struct.unpack_from("<II", body, commands[0]["offset"] + 8)
    need(offset >= 32 + struct.unpack_from("<I", body, 20)[0] and 12 <= size <= 1024 * 1024
         and offset + size == len(body), "python-signature-range")
    blob = body[offset:]
    magic, length, count = struct.unpack_from(">III", blob)
    need(magic == 0xFADE0CC0 and 1 <= count <= 32 and 12 + count * 8 <= length <= size,
         "python-signature-superblob")
    # LC_CODE_SIGNATURE allocation may exceed the declared SuperBlob. Parse
    # only that extent; preserve the complete signed body for native verification.
    blob = blob[:length]
    intervals, slots, flags = [], set(), {}
    for index in range(count):
        slot, start = struct.unpack_from(">II", blob, 12 + index * 8)
        need(slot not in slots and 12 + count * 8 <= start <= length - 8, "python-signature-index")
        slots.add(slot)
        kind, extent = struct.unpack_from(">II", blob, start)
        end = start + extent
        need(extent >= 8 and end <= length and all(end <= left or start >= right for left, right in intervals),
             "python-signature-components")
        intervals.append((start, end))
        if slot == 0 or 0x1000 <= slot < 0x1005:
            need(kind == 0xFADE0C02 and extent >= 44, "python-code-directory")
            version, value = struct.unpack_from(">II", blob, start + 8)
            need(0x20001 <= version <= 0x2F000 and value & 0x10002 == (0x10002 if phase == "python-engineering" else 0x10000),
                 "python-runtime-signature-flags")
            flags[slot] = value
    need(0 in flags and 1 <= len(flags) <= 6 and len(set(flags.values())) == 1, "python-code-directory-agreement")
    return [flags[key] for key in sorted(flags)]


def python_signature_diagnostic(original, body, machine, matcher):
    """Failure-only original-byte DATA, never signature or native authority."""
    need(type(original) is bytes and type(body) is bytes
         and 0 < len(original) <= MAX_HELPER and 0 < len(body) <= MAX_HELPER
         and type(machine) is str and machine in ("arm64", "x86_64"), "python-signature-diagnostic-bound")
    records = matcher.macho_records(body, machine)
    commands = [row for row in records if row["command"] == 0x1D]
    need(len(commands) == 1 and commands[0]["size"] == 16, "python-signature-diagnostic-command")
    offset, size = struct.unpack_from("<II", body, commands[0]["offset"] + 8)
    need(offset >= 32 + struct.unpack_from("<I", body, 20)[0] and 12 <= size <= 1024 * 1024
         and offset + size == len(body), "python-signature-diagnostic-range")
    magic, length, count = struct.unpack_from(">III", body, offset)
    tail, tail_zero = None, None
    if 12 <= length <= size:
        start, end = offset + length, offset + size
        remaining = body[start:end]
        nonzero, first, last = 0, None, None
        for position, value in enumerate(remaining):
            if value:
                nonzero += 1
                if first is None:
                    first = position
                last = position
        # Positions are relative to this tail, not raw bytes or process paths.
        tail_zero = nonzero == 0
        tail = {"bytes": len(remaining), "nonzeroBytes": nonzero, "firstNonzeroOffset": first,
                "lastNonzeroOffset": last, "sha256": digest(remaining),
                "matchesOriginalInput": original[start:end] == remaining if end <= len(original) else None}
    result = {"schemaVersion": 1, "available": True, "authority": "original-byte-data-only",
        "input": {"bytes": len(original), "sha256": digest(original)},
        "output": {"bytes": len(body), "sha256": digest(body)},
        "signature": {"offset": offset, "allocatedBytes": size, "magic": magic, "declaredBytes": length, "count": count},
        "predicates": {"magicKnown": magic == 0xFADE0CC0, "countAtLeastOne": count >= 1,
            "countAtMost32": count <= 32, "indexFitsDeclared": 12 + count * 8 <= length,
            "declaredFitsAllocation": length <= size, "allocationTailZero": tail_zero},
        "tail": tail}
    # Every value is constructed from exact bytes, uint32 unpacking, len(),
    # comparison booleans, or explicit nulls; no decoded/arbitrary fields.
    need(len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii")) <= 1536,
         "python-signature-diagnostic-output-bound")
    return result


class Refused(ValueError):
    pass


def need(value, label):
    if not value:
        raise Refused(label)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_identity(info):
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
         and info.st_gid == os.getgid() and not info.st_mode & 0o022, "directory-owner-mode")
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def build_profile(target):
    """Declared compile target only; never supplier/service/native qualification."""
    need(type(target) is str and target in (ARM_TARGET, INTEL_TARGET), "closed-build-target")
    if target == ARM_TARGET:
        return "arm64", "ARM64", "desktop/macos-installed-inputs/build-release.json"
    return "x86_64", "X64", "desktop/macos-installed-inputs/build-release-intel.json"


def entrypoint(argv):
    need(type(argv) is list and len(argv) in (2, 4) and all(type(value) is str for value in argv)
         and argv[1] in PHASES + PYTHON_PHASES + SIGNING_PHASES and (len(argv) == 2 or argv[2] == "--target"), "closed-entrypoint")
    target = ARM_TARGET if len(argv) == 2 else argv[3]
    build_profile(target)
    return argv[1], target


def artifact(messages, checkout, target, *, build_target=ARM_TARGET):
    """One real resident cdylib graph; no executable can stand in for the image."""
    build_profile(build_target)
    need(type(messages) is bytes and 0 < len(messages) <= 4 * 1024 * 1024
         and messages.endswith(b"\n"), "compiler-bound")
    def pairs(items):
        output = {}
        for key, value in items:
            need(key not in output, "compiler-duplicate-key")
            output[key] = value
        return output
    try:
        rows = [json.loads(line, object_pairs_hook=pairs) for line in messages.splitlines()]
    except (ValueError, TypeError, RecursionError) as error:
        raise Refused("compiler-json") from error
    need(1 < len(rows) <= 8192 and all(type(row) is dict for row in rows), "compiler-rows")
    records, finished = [], False
    for row in rows:
        need(not finished and row.get("reason") in
             ("compiler-artifact", "compiler-message", "build-script-executed", "build-finished"), "compiler-terminal-order")
        if row["reason"] == "build-finished":
            need(set(row) == {"reason", "success"} and row["success"] is True, "compiler-finish")
            finished = True
        elif row["reason"] == "compiler-artifact":
            need(type(row.get("target")) is dict and type(row.get("filenames")) is list
                 and all(type(value) is str for value in row["filenames"]), "compiler-artifact-shape")
            records.append(row)
    need(finished and not any(row["target"].get("kind") in (["bin"], ["test"], ["example"], ["bench"])
                             for row in records), "resident-image-only-graph")
    source = checkout / WORKSPACE
    binary = target / build_target / "release" / RESIDENT_IMAGE
    selected = [row for row in records if row["target"].get("name") == IMAGE_TARGET
                or str(binary) in row["filenames"] or row.get("executable") == str(binary)]
    need(len(selected) == 1, "one-resident-image")
    row = selected[0]
    need(not any(item is not row and item["target"].get("kind") == ["cdylib"] for item in records),
         "resident-image-only-graph")
    need(row.get("package_id") == "path+" + source.as_uri() + "#" + HELPER + "@0.1.0"
         and row.get("manifest_path") == str(source / "Cargo.toml")
         and row.get("features") == [] and "executable" in row and row["executable"] is None
         and row["filenames"] == [str(binary)], "helper-package-artifact")
    target_row = row["target"]
    need(target_row.get("name") == IMAGE_TARGET and target_row.get("kind") == ["cdylib"]
         and target_row.get("crate_types") == ["cdylib"]
         and target_row.get("src_path") == str(source / "src/lib.rs")
         and target_row.get("edition") == "2021", "helper-release-graph")
    selected_rows = [row]
    for directory, package, name, features in (
        ("desktop/src-tauri", "mobile-release-kit-desktop", "mobile_release_desktop",
         ["macos-android-registration-helper", "macos-installed-resident-image"]),
        ("desktop/native/macos-installed-native", "mrk-macos-installed-native", "mrk_macos_installed_native",
         ["android-registration-helper", "default", "resident-image"]),
    ):
        libraries = [item for item in records if item["target"].get("name") == name]
        need(len(libraries) == 1, "helper-one-library")
        library = libraries[0]
        need(library.get("package_id") == "path+" + (checkout / directory).as_uri() + "#" + package + ("@0.1.1" if package == "mobile-release-kit-desktop" else "@0.1.0")
             and library.get("manifest_path") == str(checkout / directory / "Cargo.toml")
             and library.get("features") == features
             and library["target"].get("src_path") == str(checkout / directory / "src/lib.rs")
             and library["target"].get("kind") == ["lib"] and library["target"].get("crate_types") == ["lib"]
             and library["target"].get("edition") == "2021"
             and "executable" in library and library["executable"] is None, "helper-separate-library-features")
        selected_rows.append(library)
    for selected in selected_rows:
        profile = selected.get("profile")
        need(type(profile) is dict and profile.get("test") is False and profile.get("debug_assertions") is False
             and profile.get("opt_level") == "3" and type(selected.get("fresh")) is bool, "helper-release-profile")
    return binary


def direct_rust_tools(target=ARM_TARGET):
    """Closed SOURCE path selection only; actual workflow admission is separate."""
    build_profile(target)
    directory = "/Users/runner/.rustup/toolchains/stable-" + target + "/bin"
    return directory + "/cargo", directory + "/rustc"


def build_environment(environment, work, release, *, target=ARM_TARGET):
    # release is the SAME owner's parsed, held source build-release projection;
    # direct tools cannot fall back to a rustup shim or inherited selector.
    need(type(release) is str and 0 < len(release) < 64 and release.isascii()
         and re.fullmatch(r"[a-z0-9_.-]*[a-z0-9]", release) is not None, "image-source-release")
    cargo, rustc = direct_rust_tools(target)
    need(environment.get("HOME") == "/Users/runner"
         and environment.get("CARGO_HOME", "/Users/runner/.cargo") == "/Users/runner/.cargo"
         and environment.get("RUSTUP_HOME", "/Users/runner/.rustup") == "/Users/runner/.rustup"
         and environment.get("RUSTC", rustc) == rustc
         and environment.get("RUSTUP_TOOLCHAIN", "1.98.1") == "1.98.1"
         and environment.get("RUSTUP_AUTO_INSTALL", "0") == "0", "direct-rust-source-route")
    selected = {key: environment[key] for key in ("DEVELOPER_DIR", "MACOSX_DEPLOYMENT_TARGET")}
    selected.update(PATH=cargo.rsplit("/", 1)[0] + ":/usr/bin:/bin:/usr/sbin:/sbin", HOME="/Users/runner",
                    CARGO_HOME="/Users/runner/.cargo", RUSTUP_HOME="/Users/runner/.rustup", RUSTC=rustc,
                    LANG="C", LC_ALL="C", TZ="UTC", RUSTUP_TOOLCHAIN="1.98.1", RUSTUP_AUTO_INSTALL="0",
                    CARGO_INCREMENTAL="0", CARGO_TARGET_DIR=str(work / "android-helper-target"),
                    TMPDIR=str(work / "android-helper-target/tmp"),
                    MRK_MACOS_INSTALL_SOURCE_COMMIT=environment["GITHUB_SHA"], MRK_IMAGE_RELEASE_ID=release)
    return selected


def original_failure(error, owner, checkout, timeout, limit):
    """Bounded original exception DATA; never output, completion or custody proof."""
    need(type(timeout) is int and 0 < timeout < 2 ** 31
         and type(limit) is int and 0 < limit < 2 ** 31, "diagnostic-request-bound")
    error_type = next((name for name in ("ProcessError", "ProcessCleanupError", "ProcessOutcomeUnknown")
                       if type(error) is getattr(owner, name, None)), "other")
    classification = "unclassified"
    if error_type != "other":
        # Bypass subclass properties; never render an arbitrary exception.
        arguments = BaseException.args.__get__(error)
        if type(arguments) is tuple and len(arguments) == 1 and type(arguments[0]) is str and len(arguments[0]) <= 128:
            classification = {
                "owned command output exceeds its bound": "output-bound",
                "owned command exceeded its original deadline": "deadline",
                "owned command protocol or original ownership is incomplete": "protocol-or-original-ownership",
                "owned command original parent ended": "original-parent-ended",
                "owned command cleanup could not be confirmed": "cleanup-unconfirmed",
                "owned command failed, timed out, or produced incomplete output": "failed-timeout-or-incomplete-output",
                "owned command executable could not be started": "exec-rejected",
                "owned command was stopped before execution": "stopped-before-execution",
                "owned command produced incomplete output": "incomplete-output",
            }.get(arguments[0], "unclassified")
    # load_owner admitted these exact SOURCE files before the original call.
    # No basename/normalization aliases, filesystem reads or frame locals here.
    sources = {str(checkout / "src/mobile_release" / name): "src/mobile_release/" + name
               for name in ("owned_process.py", "_command_process.py", "_native_process.py", "cancellation.py")}
    frames, visited, foreign = [], 0, 0
    trace = BaseException.__traceback__.__get__(error)
    while trace is not None and visited < 32:
        visited += 1
        code = trace.tb_frame.f_code
        filename, function, line = code.co_filename, code.co_name, trace.tb_lineno
        source = sources.get(filename) if type(filename) is str and len(filename) <= 4096 else None
        if source is None:
            foreign += 1
        elif (type(function) is str and len(function) <= 64
              and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*|<(?:module|lambda|listcomp|setcomp|dictcomp|genexpr)>", function)
              and type(line) is int and 0 < line <= 1000000):
            if len(frames) == 8:
                frames.pop(0)
            frames.append({"source": source, "function": function, "line": line})
        trace = trace.tb_next
    result = {"schemaVersion": 1, "available": True, "ownerErrorType": error_type,
              "classification": classification, "timeoutSeconds": timeout,
              "outputLimitBytes": limit, "captureMode": "bytes", "frames": frames,
              "visitedFrames": visited, "omittedFrames": visited - len(frames),
              "foreignFrames": foreign, "tracebackTruncated": trace is not None}
    need(len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii")) <= 2048,
         "original-failure-diagnostic-bound")
    return result


def package_timeout_data(now, endpoint, requested):
    """Leave the existing owner's three-second settlement inside this group."""
    need(type(now) is int and type(endpoint) is int and 0 <= now < endpoint
         and type(requested) is int and 0 < requested <= 480, "package-group-clock")
    remaining = (endpoint - now - 3_000_000_000) // 1_000_000_000
    need(remaining >= 1, "package-group-settlement-reserve")
    return min(requested, remaining)


def signing_requirement(identity, identifier):
    need(type(identity) is tuple and len(identity) == 2
         and re.fullmatch(r"[A-Z0-9]{10}", identity[0])
         and re.fullmatch(r"[0-9a-f]{40}", identity[1]) and identity[1] != "0" * 40
         and identifier in (IDENTIFIER, IDENTIFIER + ".image", "dev.mobile-release-kit.desktop.distribution",
                            "dev.mobile-release-kit.desktop.observation", PYTHON_IDENTIFIER), "fixed-signing-requirement")
    return ('identifier "' + identifier + '" and anchor apple generic'
            ' and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
            ' and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
            ' and certificate leaf[subject.OU] = "' + identity[0] + '"'
            ' and certificate leaf = H"' + identity[1] + '"')


def producer_artifact(messages, checkout, target_root, target):
    """One explicit nonshipping example graph; no packaged code is rebuilt."""
    build_profile(target)
    need(type(messages) is bytes and 0 < len(messages) <= 4 * 1024 * 1024
         and messages.endswith(b"\n"), "producer-compiler-bound")
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "producer-compiler-duplicate-key")
            value[key] = item
        return value
    try:
        rows = [json.loads(line, object_pairs_hook=pairs) for line in messages.splitlines()]
    except (ValueError, TypeError, RecursionError) as error:
        raise Refused("producer-compiler-json") from error
    need(1 < len(rows) <= 8192 and all(type(row) is dict for row in rows), "producer-compiler-rows")
    finished, artifacts = False, []
    for row in rows:
        need(not finished and row.get("reason") in ("compiler-artifact", "compiler-message", "build-script-executed", "build-finished"),
             "producer-compiler-terminal-order")
        if row["reason"] == "build-finished":
            need(row == {"reason": "build-finished", "success": True} and row["success"] is True, "producer-compiler-finish")
            finished = True
        elif row["reason"] == "compiler-artifact":
            need(type(row.get("target")) is dict and type(row.get("filenames")) is list
                 and all(type(name) is str for name in row["filenames"]), "producer-compiler-artifact")
            artifacts.append(row)
    binary = target_root / target / "release/examples/macos_package_producer"
    specs = (("desktop/src-tauri", "mobile-release-kit-desktop", "macos_package_producer", "examples/macos_package_producer.rs",
              ["example"], ["bin"], ["macos-package-producer"], str(binary)),
             ("desktop/src-tauri", "mobile-release-kit-desktop", "mobile_release_desktop", "src/lib.rs",
              ["lib"], ["lib"], ["macos-package-producer"], None),
             ("desktop/native/macos-installed-native", "mrk-macos-installed-native", "mrk_macos_installed_native", "src/lib.rs",
              ["lib"], ["lib"], ["default", "package-producer-signing"], None))
    chosen = []
    for directory, package, name, source, kinds, crates, features, executable in specs:
        matches = [row for row in artifacts if row["target"].get("name") == name]
        need(len(matches) == 1, "producer-one-target")
        row, root = matches[0], checkout / directory
        profile = row.get("profile")
        need(row.get("package_id") == "path+" + root.as_uri() + "#" + package + ("@0.1.1" if package == "mobile-release-kit-desktop" else "@0.1.0")
             and row.get("manifest_path") == str(root / "Cargo.toml") and row.get("features") == features
             and row["target"].get("src_path") == str(root / source)
             and row["target"].get("kind") == kinds and row["target"].get("crate_types") == crates
             and row["target"].get("edition") == "2021" and "executable" in row and row["executable"] == executable
             and type(row.get("fresh")) is bool and type(profile) is dict and profile.get("test") is False
             and profile.get("debug_assertions") is False and profile.get("opt_level") == "3", "producer-exact-feature-graph")
        if executable is not None:
            need(row["filenames"] == [executable], "producer-executable-path")
        chosen.append(row)
    need(finished and all(row in chosen or row["target"].get("kind") not in
         (["bin"], ["test"], ["example"], ["bench"], ["cdylib"]) for row in artifacts), "producer-only-executable")
    return binary



class Operation:
    """Custody for this one fixed packaging operation and its finite outputs."""

    def __init__(self, owner, checkout, work, phase, environment, stager, *, target=ARM_TARGET):
        need(phase in PHASES + PYTHON_PHASES + SIGNING_PHASES, "closed-phase")
        self.arch, self.runner_arch, self.release_input = build_profile(target)
        self.target = target
        self.owner, self.checkout, self.work = owner, checkout, work
        self.phase, self.environment, self.stager = phase, environment, stager
        self.entries, self.calls, self.errors = [], [], []
        self.credential_calls, self.credential_contexts = [], []
        self.credential_active = None
        self.credential_unknown = self.credential_failed = self.signing_mutation_pending = False
        self.fixed_sign_complete = False
        self.directories = {}
        self.work_entry = self.target_entry = None
        self.profile_entry = self.source_entry = None
        self.target_name = "android-helper-target" if phase == "prepare" else "android-helper-" + phase
        self.stage, self.sha256 = "owned-directory-admission", None
        self.signing = self.service_profile = self.producer_profile = None
        self.package_started = self.package_observed = self.package_endpoint = None
        self.package_outputs, self.package_sources, self.package_roots = [], [], []
        self.stager_io_pending = None
        self.python_started = self.python_observed = None
        self.python_directories, self.python_files, self.python_input_originals = {}, {}, []
        self.python_mutation_pending = self.python_retiring = False
        self.python_signed = self.python_modules = None
        self.producer_profile_entry = self.distribution_entry = None
        self.mount_entry = self.mount_placeholder = self.mount_device = None
        self.mount_entered = self.mount_known = self.mount_detached = False
        self.installer_entered = self.installer_zero = self.installation_readback = False
        self.entry_sha256 = self.desktop_facade_sha256 = self.resident_image_sha256 = None
        self.image_release = self.image_source = self.release_entry = None
        self.receipt = {"schemaVersion": 1, "phase": phase, "target": target, "source": environment["GITHUB_SHA"],
                        "packageRole": environment.get("MRK_MACOS_PACKAGE_ROLE"),
                        "workflowSource": environment["GITHUB_WORKFLOW_SHA"],
                        "workflow": environment["GITHUB_WORKFLOW_REF"], "runId": environment["GITHUB_RUN_ID"],
                        "runAttempt": environment["GITHUB_RUN_ATTEMPT"], "toolchain": "1.98.1",
                        "helperIdentifier": IDENTIFIER, "originalCalls": self.calls,
                        "credentialOriginals": self.credential_calls, "credentialContexts": self.credential_contexts,
                        "targetRetired": False, "originalClosesKnown": False, "passed": False,
                        "outerFinalityRequired": True, "androidServiceAuthenticated": False,
                        "androidRegisteredCopyQualified": False, "androidBuildQualified": False,
                        "developerIdOrNotarizationQualified": False, "productReady": False}

    def register(self, fd, role, kind, parent=None, name=None):
        entry = {"fd": fd, "role": role, "kind": kind, "parent": parent, "name": name, "closed": False}
        self.entries.append(entry)  # Before any fallible identity/content observation.
        return entry

    def close(self, entry):
        if entry["fd"] is None:
            return
        fd, entry["fd"] = entry["fd"], None
        try:
            os.close(fd)  # Never retry an uncertain descriptor close.
            entry["closed"] = True
        except BaseException as error:
            self.errors.append({"stage": "close", "role": entry["role"], "type": type(error).__name__})

    def recheck_directory(self, entry):
        need(any(owned is entry for owned in self.entries) and entry["kind"] == "directory"
             and type(entry["fd"]) is int and not entry["closed"], "directory-original-unavailable")
        parent = entry.get("parent_entry")
        if parent is not None:
            self.recheck_directory(parent)
            need(entry["parent"] == parent["fd"], "directory-parent-changed")
            named = os.stat(entry["name"], dir_fd=parent["fd"], follow_symlinks=False)
        elif entry is self.work_entry:
            named = self.work.lstat()
        elif entry is self.source_entry:
            named = self.checkout.lstat()
        else:
            raise Refused("directory-original-unbound")
        need(directory_identity(os.fstat(entry["fd"])) == directory_identity(named)
             == entry["identity"], "directory-original-changed")

    def directory(self, parent, name, role):
        need(type(name) is str and name not in ("", ".", "..") and "/" not in name,
             "directory-component")
        self.recheck_directory(parent)
        # entries retains each parent object for this operation's lifetime, so
        # its identity cannot be recycled like a consumed numeric descriptor.
        key = (id(parent), name)
        if key in self.directories:
            entry = self.directories[key]
            self.recheck_directory(entry)
            return entry  # Same original only; never reopen a closed/replaced hit.
        fd = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=parent["fd"])
        entry = self.register(fd, role, "directory", parent["fd"], name)
        entry["parent_entry"] = parent
        entry["identity"] = directory_identity(os.fstat(fd))
        self.recheck_directory(entry)
        self.directories[key] = entry
        return entry

    def descend(self, parent, names):
        for name in names:
            parent = self.directory(parent, name, "directory-" + name)
        return parent

    def original(self, parent, name, role, limit, modes, *, alias=False):
        self.recheck_directory(parent)
        fd = os.open(name, READ_FLAGS, dir_fd=parent["fd"])
        entry = self.register(fd, role, "file", parent["fd"], name)
        entry["parent_entry"] = parent
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_gid == os.getgid()
             and before.st_nlink in ((1, 2) if alias else (1,))
             and stat.S_IMODE(before.st_mode) in modes and 0 < before.st_size <= limit, "file-original-shape")
        entry["identity"] = signature(before)
        return entry

    def source_original(self, relative, role, limit):
        if self.source_entry is None:
            fd = os.open(self.checkout, READ_FLAGS | os.O_DIRECTORY)
            self.source_entry = self.register(fd, "source-root", "directory")
            self.source_entry["identity"] = directory_identity(os.fstat(fd))
            need(directory_identity(self.checkout.lstat()) == self.source_entry["identity"], "source-original-changed")
        parts = Path(relative).parts
        parent = self.descend(self.source_entry, parts[:-1])
        return self.original(parent, parts[-1], role, limit, (0o444, 0o644))

    def read(self, entry):
        self.recheck_directory(entry["parent_entry"])
        need(signature(os.fstat(entry["fd"])) == entry["identity"]
             and signature(os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False)) == entry["identity"], "file-original-changed")
        size = entry["identity"][6]
        value = os.pread(entry["fd"], size + 1, 0)
        need(len(value) == size and signature(os.fstat(entry["fd"])) == entry["identity"]
             and signature(os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False)) == entry["identity"], "file-original-read-changed")
        self.recheck_directory(entry["parent_entry"])
        return value

    def publish(self, name, data, *, mode=0o600):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     mode, dir_fd=self.work_entry["fd"])
        entry = self.register(fd, "output-" + name, "file")
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            need(written > 0, "output-short-write")
            offset += written
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
             and info.st_gid == os.getgid(), "exclusive-output-original")
        os.fchmod(fd, mode)
        os.fsync(fd)
        need(os.pread(fd, len(data) + 1, 0) == data, "output-readback")
        self.close(entry)
        need(entry["closed"], "output-close-unknown")

    def call(self, role, argv, environment, *, cwd, timeout, limit):
        need(self.credential_known() and not self.credential_failed, "credential-dispatch-unknown")
        if self.credential_active is not None:
            context = self.credential_active
            need(context["ready"] and not context["retiring"] and role in context["roles"], "credential-callback-purpose")
            now = self.credential_clock(context)
            need(now + (timeout + 3) * 1_000_000_000 < context["endpoint"] - 30_000_000_000, "credential-callback-deadline")
            self.credential_census(context)
            environment = dict(environment, HOME="/Users/runner")
        need(not any(name in environment for name in CREDENTIAL_VARIABLES), "credential-child-environment")
        if self.phase in PYTHON_PHASES:
            need(not self.python_retiring and not self.errors and self.stager_io_pending is None
                 and len(self.calls) < len(PYTHON_ROLES) and role == PYTHON_ROLES[len(self.calls)]
                 and self.python_mutation_pending == (role == "python-sign")
                 and all(row.get("returned") is True and row.get("capturesSettled") is True for row in self.calls),
                 "python-original-dispatch-boundary")
            self.python_clock()
        record = {"role": role, "entered": True, "returned": False, "capturesSettled": False}
        self.calls.append(record)
        try:
            # This is the SAME owner invocation, after package clock/reserve
            # admission. An unknown dispatch remains conservatively entered.
            if self.phase == "package-install":
                if role == "distribution-attach":
                    self.mount_entered = True
                elif role == "installer":
                    self.installer_entered = True
            result = self.owner.run_owned(argv, environ=environment, cwd=cwd, timeout=timeout,
                                          capture=True, text=False, output_limit=limit)
        except BaseException as error:
            for field in ("dispatched", "contained", "cleanup_complete"):
                value = getattr(error, field, None)
                record[field] = value if type(value) is bool else None
            try:
                record["originalFailure"] = original_failure(error, self.owner, self.checkout, timeout, limit)
            except BaseException:
                # Diagnostic failure must never replace the original exception.
                try:
                    record["originalFailure"] = {"schemaVersion": 1, "available": False}
                except BaseException:
                    pass
            raise
        need(type(result) is subprocess.CompletedProcess and type(result.returncode) is int
             and type(result.args) in (list, tuple) and tuple(result.args) == tuple(argv)
             and type(result.stdout) is bytes and type(result.stderr) is bytes
             and len(result.stdout) + len(result.stderr) <= limit, "original-return-contract")
        if self.phase == "package-install" and role == "installer":
            # Save the actual original status before any diagnostics/readback.
            self.publish("installer-output.status", (str(result.returncode) + "\n").encode("ascii"))
        record.update(returned=True, returncode=result.returncode,
                      stdoutSha256=digest(result.stdout), stderrSha256=digest(result.stderr))
        prefix = "android-helper-" + role
        self.publish(prefix + (".jsonl" if role == "build" else ".stdout"), result.stdout)
        self.publish(prefix + ".stderr", result.stderr)
        self.publish(prefix + ".status", (str(result.returncode) + "\n").encode("ascii"))
        if self.phase == "package-install" and role == "installer":
            self.publish("installer-output.txt", result.stdout + result.stderr)
        record["capturesSettled"] = True  # All original output/readback/closes returned.
        diagnostic = self.phase == "package-install" and role in ("installer-log-cursor", "installer-log-capture")
        need(result.returncode == 0 or diagnostic and result.returncode == 1, "original-nonzero-" + role)
        if self.credential_active is not None:
            self.credential_clock(self.credential_active)
            self.credential_census(self.credential_active)
        return result

    def credential_known(self):
        return (not self.credential_unknown and all(row["returned"] and row["settled"] for row in self.credential_calls))

    def credential_clock(self, context, *, cleanup=False):
        now = time.monotonic_ns()
        need(type(now) is int and context["observed"] <= now < context["endpoint"] - (0 if cleanup else 30_000_000_000),
             "credential-original-deadline")
        context["observed"] = now
        if self.phase in PYTHON_PHASES:
            self.python_clock(work=not cleanup)
        elif self.package_endpoint is not None:
            self.package_clock()
        return now

    def credential_new_clock(self):
        now = time.monotonic_ns()
        need(type(now) is int, "credential-original-clock")
        endpoint = now + 240_000_000_000
        if self.phase in PYTHON_PHASES:
            _observed, outer = self.python_clock()
            endpoint = min(endpoint, outer)
        elif self.package_endpoint is not None:
            self.package_clock()
            endpoint = min(endpoint, self.package_endpoint)
        return {"observed": now, "endpoint": endpoint, "ready": False, "retiring": False, "pending": None,
                "directories": [], "root": None, "created": False, "p12": None, "entries": [], "roles": ()}

    def credential_io(self, context, label, function, *args, **kwargs):
        need(self.credential_known() and context["pending"] is None, "credential-original-unknown")
        self.credential_clock(context, cleanup=context["retiring"])
        context["pending"] = label
        try:
            value = function(*args, **kwargs)
            self.credential_clock(context, cleanup=context["retiring"])
        except BaseException:
            self.credential_unknown = True
            raise
        context["pending"] = None
        return value

    def credential_open(self, context, name, flags, mode=0o600, *, parent=None, directory=False):
        entry = self.register(None, "credential-directory" if directory else "credential-file", "credential-original")
        context["entries"].append(entry)  # Before the original acquisition/result assignment.
        entry["name"], entry["parent_entry"] = name, parent
        entry["fd"] = self.credential_io(context, "open", os.open, name, flags, mode,
                                          **({} if parent is None else {"dir_fd": parent["fd"]}))
        return entry

    def credential_directories_post(self, context):
        for entry in context["directories"]:
            parent = entry["parent_entry"]
            named = os.stat(entry["name"], follow_symlinks=False,
                            **({} if parent is None else {"dir_fd": parent["fd"]}))
            held = os.fstat(entry["fd"])
            value = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
            need(stat.S_ISDIR(held.st_mode) and value(held) == value(named) == entry["identity"],
                 "credential-directory-original")

    def credential_census(self, context):
        """Opaque DBs may be0644: held0700 root, not tool-mode guesses, confines them.

        No special/execute/nonowner-write bits or private DB content reads. The
        one decoded credential file retains its separate exact0600 contract.
        """
        if context["root"] is None:
            return
        def inspect():
            self.credential_directories_post(context)
            root = context["root"]
            names = os.listdir(root["fd"])
            need(len(names) <= 8 and len(names) == len(set(names)) and all(type(name) is str
                 and re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", name) and name not in (".", "..") for name in names),
                 "credential-private-census")
            total = 0
            for name in sorted(names):
                entry = self.register(None, "credential-census-file", "credential-original")
                context["entries"].append(entry)
                entry["fd"] = os.open(name, READ_FLAGS, dir_fd=root["fd"])
                try:
                    info = os.fstat(entry["fd"])
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                         and info.st_gid == os.getgid() and not info.st_mode & 0o7133
                         and (name != "identity.p12" or stat.S_IMODE(info.st_mode) == 0o600)
                         and 0 <= info.st_size <= 16 * 1024 * 1024, "credential-private-file")
                    total += info.st_size
                    need(total <= 16 * 1024 * 1024 and signature(os.fstat(entry["fd"])) == signature(info)
                         == signature(os.stat(name, dir_fd=root["fd"], follow_symlinks=False)), "credential-private-file-post")
                finally:
                    self.close(entry)
                need(entry["closed"], "credential-census-close-unknown")
            self.credential_directories_post(context)
        self.credential_io(context, "census", inspect)

    def credential_call(self, context, role, argv, *, timeout=10):
        """The SAME process owner, but no public raw argv/captures/exception text."""
        need(context is self.credential_active and role in CREDENTIAL_ROLES
             and self.credential_known() and context["pending"] is None
             and len(self.credential_calls) < 64 and timeout in (10, 30), "credential-fixed-original")
        now = self.credential_clock(context, cleanup=context["retiring"])
        endpoint = context["endpoint"] - (0 if context["retiring"] else 30_000_000_000)
        need(now + (timeout + 3) * 1_000_000_000 < endpoint, "credential-dispatch-reserve")
        self.credential_census(context)
        record = {"role": role, "entered": True, "returned": False, "settled": False, "status": None}
        self.credential_calls.append(record)
        environment = self.native_environment()
        environment["HOME"] = "/Users/runner"
        try:
            result = self.owner.run_owned(argv, environ=environment, cwd=self.work, timeout=timeout,
                                          capture=True, text=False, output_limit=16384)
            need(type(result) is subprocess.CompletedProcess and type(result.returncode) is int and -65536 <= result.returncode <= 65535
                 and type(result.args) in (tuple, list) and tuple(result.args) == tuple(argv)
                 and type(result.stdout) is bytes and type(result.stderr) is bytes
                 and len(result.stdout) + len(result.stderr) <= 16384, "credential-original-return")
            record.update(returned=True, settled=True, status=result.returncode)
            self.credential_clock(context, cleanup=context["retiring"])
            self.credential_census(context)
        except BaseException:
            self.credential_unknown = True
            raise
        if result.returncode != 0:
            # A normally returned mutator may still have partially changed the
            # database/searchlist. Do not guess its state or delete its names.
            if role in ("create", "settings", "unlock", "import", "partitions", "restrict", "restore", "delete", "producer-adhoc"):
                self.credential_unknown = True
            raise Refused("credential-original-nonzero")
        return result

    def credential_search(self, context, role, *, default=False, expected=None):
        result = self.credential_call(context, role, ["/usr/bin/security",
            "default-keychain" if default else "list-keychains", "-d", "user"])
        try:
            need(not result.stderr, "credential-search-stderr")
            observed = credential_paths(result.stdout, single=default)
            need(expected is None or observed == expected, "credential-search-value-changed")
            return observed
        except BaseException:
            self.credential_unknown = True  # Cannot restore/adopt an unknown list.
            raise

    def credential_sources(self):
        source = self.stager.packaging_signing_data(self.producer_profile, self.service_profile)
        need(self.signing == (source.team, source.leaf_sha1), "credential-profile-identity")
        fields = dict(line.split("=", 1) for line in self.producer_profile.decode("ascii").splitlines())
        certificates = []
        for name, field in (("leaf", "leaf-certificate-sha256"), ("issuer", "issuer-certificate-sha256"), ("root", "root-certificate-sha256")):
            entry = self.source_original("desktop/packaging/macos-install-producer-certificates/" + name + ".der",
                                         "credential-source-" + name, 16384)
            body = self.read(entry)
            need(digest(body) == fields[field], "credential-source-certificate")
            certificates.append(body)
            self.package_sources.append((entry, body))
        need(hashlib.sha1(certificates[0]).hexdigest() == self.signing[1], "credential-source-leaf")
        return tuple(certificates)

    def credential_private_root(self, context, body):
        parts = WORK_PARENT.parts
        need(WORK_PARENT.is_absolute() and self.work.parent == WORK_PARENT,
             "credential-private-parent")
        parent = None
        for part in parts:
            entry = self.credential_open(context, part, READ_FLAGS | os.O_DIRECTORY, parent=parent, directory=True)
            info = os.fstat(entry["fd"])
            need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
                 and (not info.st_mode & 0o022 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                 "credential-ancestor-mode")
            entry["identity"] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
            context["directories"].append(entry)
            self.credential_io(context, "ancestor-post", self.credential_directories_post, context)
            parent = entry
        capacity = self.credential_io(context, "capacity", os.fstatvfs, parent["fd"])
        need(capacity.f_frsize > 0 and capacity.f_bavail * capacity.f_frsize >= 16 * 1024 * 1024 + 32768,
             "credential-private-storage-reserve")
        name = "mrk-macos-signing-private." + os.urandom(16).hex()
        context["path"] = WORK_PARENT / name
        context["parent"] = parent
        self.credential_io(context, "private-mkdir", os.mkdir, name, 0o700, dir_fd=parent["fd"])
        context["created"] = True
        root = self.credential_open(context, name, READ_FLAGS | os.O_DIRECTORY, parent=parent, directory=True)
        info = os.fstat(root["fd"])
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
             and info.st_uid == os.getuid() and info.st_gid == os.getgid(), "credential-root-mode")
        root["identity"] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        context["root"] = root
        context["directories"].append(root)
        self.credential_census(context)
        need(not os.listdir(root["fd"]), "credential-root-exclusive")
        entry = self.credential_open(context, "identity.p12", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     parent=root)
        context["p12"] = entry
        context["body"] = body
        def write():
            offset = 0
            while offset < len(body):
                count = os.write(entry["fd"], body[offset:])
                need(type(count) is int and count > 0, "credential-short-write")
                offset += count
            os.fchmod(entry["fd"], 0o600)
            os.fsync(entry["fd"])
            entry["identity"] = signature(os.fstat(entry["fd"]))
            self.credential_p12_post(context)
        self.credential_io(context, "p12-write-readback", write)

    def credential_p12_post(self, context):
        entry, root, body = context["p12"], context["root"], context["body"]
        self.credential_directories_post(context)
        info = os.fstat(entry["fd"])
        need(signature(info) == entry["identity"] == signature(os.stat("identity.p12", dir_fd=root["fd"], follow_symlinks=False))
             and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
             and info.st_uid == os.getuid() and info.st_gid == os.getgid() and info.st_size == len(body), "credential-p12-original")
        need(os.pread(entry["fd"], len(body) + 1, 0) == body and os.pread(entry["fd"], 1, len(body)) == b""
             and signature(os.fstat(entry["fd"])) == entry["identity"], "credential-p12-readback")
        self.credential_directories_post(context)

    def credential_p12_retire(self, context):
        entry = context["p12"]
        if entry is None:
            return
        self.credential_io(context, "p12-post", self.credential_p12_post, context)
        self.close(entry)
        need(entry["closed"] and not self.errors, "credential-p12-close-unknown")
        def remove():
            self.credential_directories_post(context)
            need(signature(os.stat("identity.p12", dir_fd=context["root"]["fd"], follow_symlinks=False)) == entry["identity"],
                 "credential-p12-after-close")
            os.unlink("identity.p12", dir_fd=context["root"]["fd"])
        self.credential_io(context, "p12-remove", remove)
        context["p12"] = None
        context.pop("body", None)

    @contextlib.contextmanager
    def credential_scope(self, purpose, *, producer=None):
        pairs = {"python": PYTHON_ROLES[:2], "resident-image": ("resident-image-sign", "resident-image-verify-signed"),
                 "helper": ("sign", "verify-signed"), "producer": ("producer-emitter",),
                 **{phase: (phase, phase + "-verify") for phase in SIGNING_PHASES}}
        need((purpose == "python" and self.phase in PYTHON_PHASES or purpose in ("resident-image", "helper") and self.phase == "prepare"
              or purpose == "producer" and self.phase == "package-install" or purpose in SIGNING_PHASES and self.phase == purpose)
             and self.credential_active is None and not self.credential_failed and self.credential_known(), "credential-fixed-purpose")
        if self.phase == "python-engineering" or self.phase == "prepare" and self.signing is None:
            yield  # No secret read, directory, keychain or auxiliary call.
            return
        need(self.environment.get("HOME") == "/Users/runner", "credential-user-domain")
        certificates = self.credential_sources()
        context = self.credential_new_clock()
        context["roles"] = pairs[purpose]
        fact = {"purpose": purpose, "searchRestored": False, "defaultUnchanged": False, "retired": False, "closed": False}
        primary, original_list, original_default, expected_list = None, None, None, None
        keychain, password, secret = None, None, None
        keychain_created = False
        try:
            self.credential_active = context  # Inside the whole acquisition/use/unwind guard.
            self.credential_contexts.append(fact)
            body, secret = credential_values(self.environment)
            password = os.urandom(32).hex()
            self.credential_private_root(context, body)
            keychain = str(context["path"] / "identity.keychain-db")
            original_list = self.credential_search(context, "search-before")
            original_default = self.credential_search(context, "default-before", default=True)
            expected_list = original_list
            self.credential_call(context, "create", ["/usr/bin/security", "create-keychain", "-p", password, keychain])
            keychain_created = True
            observed = self.credential_search(context, "search-created")
            if not (observed.count(keychain) <= 1 and tuple(value for value in observed if value != keychain) == original_list):
                self.credential_unknown = True
                raise Refused("credential-created-searchlist")
            expected_list = observed
            self.credential_call(context, "settings", ["/usr/bin/security", "set-keychain-settings", "-l", "-u", "-t", "240", keychain])
            self.credential_call(context, "unlock", ["/usr/bin/security", "unlock-keychain", "-p", password, keychain])
            if purpose == "producer":
                need(type(producer) is tuple and len(producer) == 3 and re.fullmatch(r"[0-9a-f]{40}", producer[2]),
                     "credential-producer-admission")
                copied, copied_body, code_hash = producer
                need(self.read(copied) == copied_body, "credential-producer-original")
                trusted = str(self.work / "macos-package-producer")
                partitions = "apple-tool:,cdhash:" + code_hash
            else:
                need(producer is None, "credential-code-purpose")
                trusted, partitions = "/usr/bin/codesign", "apple-tool:,apple:"
            self.credential_io(context, "p12-import-pre", self.credential_p12_post, context)
            self.credential_call(context, "import", ["/usr/bin/security", "import", str(context["path"] / "identity.p12"),
                "-k", keychain, "-f", "pkcs12", "-P", secret, "-T", trusted, "-T", "/usr/bin/security"])
            if purpose == "producer":
                need(self.read(copied) == copied_body, "credential-producer-import-post")
            self.credential_p12_retire(context)  # No encoded key file exists during the callback.
            secret = None
            self.credential_call(context, "partitions", ["/usr/bin/security", "set-key-partition-list", "-S", partitions,
                                                       "-s", "-k", password, keychain])
            identities = self.credential_call(context, "identity", ["/usr/bin/security", "find-identity", "-v", "-p", "codesigning", keychain])
            certs = self.credential_call(context, "certificates", ["/usr/bin/security", "find-certificate", "-a", "-p", keychain])
            need(not identities.stderr and not certs.stderr, "credential-private-query-stderr")
            credential_identity(identities.stdout, certs.stdout, self.signing, certificates)
            self.credential_search(context, "search-admit", expected=expected_list)
            self.credential_call(context, "restrict", ["/usr/bin/security", "list-keychains", "-d", "user", "-s", keychain])
            expected_list = (keychain,)
            self.credential_search(context, "search-restricted", expected=expected_list)
            for entry, data in self.package_sources:
                need(self.read(entry) == data, "credential-source-post")
            maximum = 126 if purpose == "producer" else 66
            need(self.credential_clock(context) + maximum * 1_000_000_000 < context["endpoint"] - 30_000_000_000,
                 "credential-callback-reserve")
            before = len(self.calls)
            context["ready"] = True
            yield
            context["ready"] = False
            need(tuple(row["role"] for row in self.calls[before:]) == context["roles"], "credential-callback-roster")
            if purpose == "producer":
                need(self.read(copied) == copied_body, "credential-producer-callback-post")
            for entry, data in self.package_sources:
                need(self.read(entry) == data, "credential-source-post")
            self.credential_clock(context)
        except BaseException as error:
            primary = error
        finally:
            context["ready"] = False
            context["retiring"] = True
            try:
                need(self.credential_known() and context["pending"] is None and not self.errors
                     and self.stager_io_pending is None and not self.python_mutation_pending and not self.signing_mutation_pending
                     and all(row["returned"] and row.get("capturesSettled") is True for row in self.calls),
                     "credential-unwind-original-unknown")
                self.credential_clock(context, cleanup=True)
                if keychain_created:
                    self.credential_census(context)
                    self.credential_search(context, "search-after-callback", expected=expected_list)
                    self.credential_call(context, "restore", ["/usr/bin/security", "list-keychains", "-d", "user", "-s", *original_list])
                    self.credential_search(context, "search-restored", expected=original_list)
                    fact["searchRestored"] = True
                    self.credential_p12_retire(context)
                    self.credential_call(context, "delete", ["/usr/bin/security", "delete-keychain", keychain])
                elif original_list is not None:
                    self.credential_search(context, "search-final", expected=original_list)
                    fact["searchRestored"] = True
                    if original_default is not None:
                        self.credential_search(context, "default-after", default=True, expected=original_default)
                        fact["defaultUnchanged"] = True
                if context["root"] is not None:
                    self.credential_p12_retire(context)
                    self.credential_census(context)
                    need(not os.listdir(context["root"]["fd"]), "credential-private-root-not-empty")
                    self.credential_io(context, "private-rmdir", os.rmdir, context["path"].name,
                                       dir_fd=context["parent"]["fd"])
                    context["directories"].remove(context["root"])
                    context["root"] = None
                    self.credential_io(context, "private-parent-post", self.credential_directories_post, context)
                    try:
                        os.stat(context["path"].name, dir_fd=context["parent"]["fd"], follow_symlinks=False)
                    except FileNotFoundError:
                        fact["retired"] = True
                    else:
                        raise Refused("credential-private-root-remains")
            except BaseException as error:
                self.credential_unknown = True
                self.errors.append({"stage": "credential-unwind", "type": type(error).__name__})
                if primary is None:
                    primary = error
            finally:
                secret = password = None
                context.pop("body", None)
                for entry in reversed(context["entries"]):
                    self.close(entry)  # Known held FDs only, even if a process is unknown.
                fact["closed"] = all(entry["closed"] for entry in context["entries"])
                if not fact["closed"] or context["pending"] is not None:
                    self.credential_unknown = True
                    if primary is None:
                        primary = Refused("credential-close-unknown")
                try:
                    if not self.credential_unknown and original_list is not None:
                        self.credential_search(context, "search-final", expected=original_list)
                        if original_default is not None:
                            self.credential_search(context, "default-after", default=True, expected=original_default)
                            fact["defaultUnchanged"] = True
                    self.credential_clock(context, cleanup=True)
                except BaseException as error:
                    self.credential_unknown = True
                    self.errors.append({"stage": "credential-final-post", "type": type(error).__name__})
                    if primary is None:
                        primary = error
                # Every exit, including BaseException/constructor gaps, latches
                # pending/unknown state before any later command/retirement.
                if context["created"] and not fact["retired"]:
                    self.credential_unknown = True
                self.credential_active = None
        if primary is not None:
            self.credential_failed = True
            raise primary
        need(fact["retired"] and fact["closed"] and fact["searchRestored"] and fact["defaultUnchanged"]
             and self.credential_known(), "credential-finality-incomplete")

    def signing_matcher(self):
        entry = self.source_original("desktop/tools/macos_cpython_orchestrator.py", "signing-content-source", 256 * 1024)
        body = self.read(entry)
        # Existing DATA parser, admitted from the exact held SOURCE before/after
        # loading; not a new native process, signing owner or executable input.
        self.stager_io_pending = "signing-content-source-load"
        matcher = load_data(self.checkout, "macos_cpython_orchestrator.py", "_mrk_credential_signing_content")
        need(self.read(entry) == body, "signing-content-source-post")
        self.stager_io_pending = None
        self.package_sources.append((entry, body))
        return matcher

    def fixed_sign(self):
        """Five fixed existing workflow roles, never a user-selected path/argv."""
        need(self.phase in SIGNING_PHASES and self.signing is not None, "fixed-signing-purpose")
        base = "app/Mobile Release Kit.app"
        payload = base + "/Contents/Helpers/MobileReleaseKitPayload.app"
        selected = {
            "sign-vault-helper": "vault-helper-target/" + self.target + "/release/mrk-vault-keychain",
            "sign-desktop-image": payload + "/Contents/Frameworks/libmrk_desktop_image.dylib",
            "sign-desktop-payload": payload,
            "sign-root-app": base,
            "sign-root-installer": "cargo-target/" + self.target + "/release/mrk-macos-install",
        }[self.phase]
        if self.phase == "sign-desktop-image":
            need(self.environment.get("MRK_MACOS_PACKAGE_ROLE") == "ordinary-image", "fixed-desktop-image-role")
        if self.phase == "sign-root-installer":
            need(self.environment.get("CARGO_TARGET_DIR") == str(self.work / "cargo-target"), "fixed-installer-target")
        path = self.work / selected
        bundled = self.phase in ("sign-desktop-payload", "sign-root-app")
        root = self.descend(self.work_entry, tuple(selected.split("/"))) if bundled else None
        binary_name = ("mobile-release-kit-desktop" if self.phase == "sign-desktop-payload" else ENTRY)
        binary = selected + "/Contents/MacOS/" + binary_name if bundled else selected
        parent = self.descend(self.work_entry, tuple(binary.split("/")[:-1]))
        old = self.original(parent, binary.split("/")[-1], "fixed-sign-input", 64 * 1024 * 1024, (0o555, 0o700, 0o755), alias=not bundled)
        original = self.read(old)
        if self.phase == "sign-desktop-image":
            self.stager.image_macho(original, "desktop", target=self.target)
        else:
            self.stager.macho(original, system_only=True, target=self.target)
        matcher = self.signing_matcher()
        entitlements = self.source_original("desktop/packaging/macos-empty-entitlements.plist", "fixed-sign-empty-entitlements", 1024)
        empty = self.read(entitlements)
        need(digest(empty) == self.stager.SIGNED_ENTITLEMENTS_SHA256, "fixed-sign-empty-profile")
        self.package_sources.append((entitlements, empty))
        arguments = ["--options", "runtime", "--entitlements",
            str(self.checkout / "desktop/packaging/macos-empty-entitlements.plist")]
        with self.credential_scope(self.phase):
            self.stage = self.phase
            self.signing_mutation_pending = True
            self.call(self.phase, ["/usr/bin/codesign", "--force", "--sign", self.signing[1], *arguments, "--timestamp", str(path)],
                      self.native_environment(), cwd=self.work, timeout=30, limit=65536)
            if root is not None:
                self.recheck_directory(root)
            self.recheck_directory(parent)
            signed = self.original(parent, binary.split("/")[-1], "fixed-sign-output", 64 * 1024 * 1024,
                                   (0o555, 0o700, 0o755), alias=not bundled)
            body = self.read(signed)
            matcher.macho_content_valid(original, body, self.arch, signing=True)
            self.close(old)
            need(old["closed"] and not self.errors, "fixed-sign-input-close-unknown")
            self.signing_mutation_pending = False
            verified = self.call(self.phase + "-verify", ["/usr/bin/codesign", "--verify", "--strict", str(path)],
                                 self.native_environment(), cwd=self.work, timeout=30, limit=65536)
            need(not verified.stdout and not verified.stderr and self.read(signed) == body, "fixed-sign-original-verification")
            if root is not None:
                self.recheck_directory(root)
        self.sha256 = digest(body)
        self.fixed_sign_complete = True
        self.receipt.update(fixedSigningRole=self.phase, signedBytesSha256=self.sha256,
                            signingAuthority="unchanged-source-identity-native-verification-still-required")

    def producer_signing_copy(self, executable, executable_body):
        """Give only the final compiler-derived copy an exact ad-hoc CDHash ACL."""
        self.publish("macos-package-producer", executable_body, mode=0o755)
        need(self.read(executable) == executable_body, "producer-compiler-copy-post")
        old = self.original(self.work_entry, "macos-package-producer", "producer-unsigned-copy", 64 * 1024 * 1024, (0o755,))
        need(self.read(old) == executable_body, "producer-copy-original")
        matcher = self.signing_matcher()
        context = self.credential_new_clock()
        need(self.credential_active is None and self.credential_known() and not self.credential_failed, "producer-seal-finality")
        primary = None
        try:
            self.credential_active = context
            self.stage = "producer-private-copy-sealing"
            self.signing_mutation_pending = True
            self.credential_call(context, "producer-adhoc", ["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
                                 str(self.work / "macos-package-producer")], timeout=30)
            copied = self.original(self.work_entry, "macos-package-producer", "producer-sealed-copy", 64 * 1024 * 1024, (0o755,))
            body = self.read(copied)
            matcher.macho_content_valid(executable_body, body, self.arch, signing=True)
            self.close(old)
            need(old["closed"] and not self.errors, "producer-copy-close-unknown")
            self.signing_mutation_pending = False
            verified = self.credential_call(context, "producer-adhoc-verify", ["/usr/bin/codesign", "--verify", "--strict",
                str(self.work / "macos-package-producer")], timeout=30)
            need(not verified.stdout and not verified.stderr, "producer-seal-verification")
            display = self.credential_call(context, "producer-cdhash", ["/usr/bin/codesign", "--display", "--verbose=4",
                str(self.work / "macos-package-producer")], timeout=30)
            need(not display.stdout and self.read(copied) == body and self.read(executable) == executable_body,
                 "producer-seal-post")
            code_hash = credential_cdhash(display.stderr)
            self.signing_mutation_pending = True
            os.fchmod(copied["fd"], 0o555)
            copied["identity"] = signature(os.fstat(copied["fd"]))
            need(stat.S_IMODE(copied["identity"][2]) == 0o555 and self.read(copied) == body, "producer-final-seal-original")
            self.signing_mutation_pending = False
            self.credential_clock(context)
        except BaseException as error:
            primary = error
            self.credential_failed = True
            if self.signing_mutation_pending or not self.credential_known():
                self.credential_unknown = True
        finally:
            self.credential_active = None
        if primary is not None:
            raise primary
        self.package_outputs.append((copied, digest(body)))
        self.package_post()
        return copied, body, code_hash

    def native_environment(self):
        return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(self.work),
                "TMPDIR": str(self.work / self.target_name / "tmp"), "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}

    def open(self):
        fd = os.open(self.work, READ_FLAGS | os.O_DIRECTORY)
        self.work_entry = self.register(fd, "work", "directory")
        self.work_entry["identity"] = directory_identity(os.fstat(fd))
        need(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700
             and directory_identity(self.work.lstat()) == self.work_entry["identity"], "work-original")
        need(shutil.rmtree.avoids_symlink_attacks, "descriptor-relative-cleanup-required")
        os.mkdir(self.target_name, 0o700, dir_fd=fd)  # Exclusive, never an old target.
        self.target_entry = self.directory(self.work_entry, self.target_name, "target")
        os.mkdir("tmp", 0o700, dir_fd=self.target_entry["fd"])

    def python_clock(self, *, work=True):
        now = time.monotonic_ns()
        need(type(now) is int and self.python_started is not None and self.python_observed <= now,
             "python-monotonic-clock")
        self.python_observed = now
        limit = self.python_started + (300 if work else 360) * 1_000_000_000
        need(now < limit, "python-group-deadline")
        return now, limit

    def python_known(self):
        return (not self.errors and self.credential_known()
                and not self.signing_mutation_pending and self.stager_io_pending is None and not self.python_mutation_pending
                and all(row.get("returned") is True and row.get("capturesSettled") is True for row in self.calls))

    def python_io(self, label, function, *args, **kwargs):
        self.python_clock()
        need(self.python_known() and not self.credential_failed and not self.python_retiring, "python-originals-unknown")
        self.stage = label
        self.stager_io_pending = label
        # A raised external DATA operation has no transferable close proof.
        value = function(*args, **kwargs)
        self.python_clock()
        self.stager_io_pending = None
        return value

    def python_call(self, role, argv, *, maximum=30, limit=65536):
        need(self.python_known() and not self.credential_failed and not self.python_retiring, "python-originals-unknown")
        self.python_post()
        now, endpoint = self.python_clock()
        self.stage = role
        result = self.call(role, argv, self.native_environment(), cwd=self.work,
                           timeout=package_timeout_data(now, endpoint, maximum), limit=limit)
        self.python_clock()
        need(self.python_known(), "python-originals-unknown")
        return result

    def python_directory(self, name):
        self.python_clock()
        need(self.python_known() and not self.python_retiring and type(name) is str
             and self.stager.safe_path(name), "python-owned-relative-directory")
        if name in self.python_directories:
            entry = self.python_directories[name]
            self.recheck_directory(entry)
            return entry
        parts = name.split("/")
        parent = self.target_entry if len(parts) == 1 else self.python_directory("/".join(parts[:-1]))
        self.recheck_directory(parent)
        self.stager_io_pending = "python-directory-create"
        os.mkdir(parts[-1], 0o700, dir_fd=parent["fd"])
        entry = self.directory(parent, parts[-1], "python-directory-" + name)
        self.python_directories[name] = entry
        self.python_clock()
        self.stager_io_pending = None
        return entry

    def python_write(self, name, body, mode):
        self.python_clock()
        need(self.python_known() and not self.python_retiring and self.stager.safe_path(name)
             and name not in self.python_files and type(body) is bytes and len(body) <= MAX_HELPER
             and mode in (0o444, 0o555, 0o755), "python-exclusive-output")
        parts = name.split("/")
        parent = self.target_entry if len(parts) == 1 else self.python_directory("/".join(parts[:-1]))
        self.recheck_directory(parent)
        self.stager_io_pending = "python-file-create"
        fd = os.open(parts[-1], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent["fd"])
        entry = self.register(fd, "python-file-" + name, "file", parent["fd"], parts[-1])
        entry["parent_entry"] = parent
        offset = 0
        while offset < len(body):
            written = os.write(fd, body[offset:])
            need(type(written) is int and written > 0, "python-short-write")
            offset += written
        os.fchmod(fd, mode)
        os.fsync(fd)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
             and info.st_gid == os.getgid() and info.st_size == len(body) and stat.S_IMODE(info.st_mode) == mode,
             "python-created-original")
        entry["identity"] = signature(info)
        need(self.read(entry) == body, "python-created-readback")
        self.python_files[name] = (entry, body)
        self.python_clock()
        self.stager_io_pending = None
        return entry

    def python_post(self):
        self.python_clock(work=not self.python_retiring)
        need(self.python_known(), "python-originals-unknown")
        self.recheck_directory(self.target_entry)
        for name, entry in self.python_directories.items():
            self.recheck_directory(entry)
            expected = {path[len(name) + 1:].split("/")[0] for path in (*self.python_directories, *self.python_files)
                        if path.startswith(name + "/")}
            need(set(os.listdir(entry["fd"])) == expected, "python-directory-members-changed")
        need(set(os.listdir(self.target_entry["fd"]))
             == {path.split("/")[0] for path in (*self.python_directories, *self.python_files)},
             "python-target-members-changed")
        for entry, body in self.python_files.values():
            need(self.read(entry) == body, "python-owned-file-post")
        for entry, body in self.python_input_originals:
            need(self.read(entry) == body, "python-input-original-post")
        self.python_clock(work=not self.python_retiring)

    def python_directory_mode(self, entry, mode):
        self.python_clock(work=not self.python_retiring)
        need(self.python_known() and mode in (0o555, 0o700), "python-directory-mode-purpose")
        self.recheck_directory(entry)
        before = entry["identity"]
        self.stager_io_pending = "python-directory-mode"
        os.fchmod(entry["fd"], mode)
        after = directory_identity(os.fstat(entry["fd"]))
        expected = before[:2] + (stat.S_IFDIR | mode,) + before[3:]
        need(after == expected and directory_identity(os.stat(entry["name"], dir_fd=entry["parent"],
             follow_symlinks=False)) == expected, "python-directory-mode-original")
        entry["identity"] = after
        self.recheck_directory(entry)
        self.python_clock(work=not self.python_retiring)
        self.stager_io_pending = None

    def python_seal(self):
        # Seal only our newly created probe tree, never an input/ancestor.
        for name in sorted(self.python_directories, key=lambda value: (-value.count("/"), value)):
            if name == "signed-payload" or name.startswith("signed-payload/"):
                self.python_directory_mode(self.python_directories[name], 0o555)
        self.python_post()

    def python_prepare(self, modules=None):
        self.python_clock()
        self.python_directories["tmp"] = self.directory(self.target_entry, "tmp", "python-tmp")
        self.python_input_originals.extend(((self.profile_entry, self.service_profile),
                                           (self.producer_profile_entry, self.producer_profile)))
        self.python_pins = dict(PYTHON_SUPPLIERS[self.target])
        data = self.directory(self.work_entry, "python-supplier-transport", "python-original-transport")
        need(set(os.listdir(data["fd"])) == {"supplier.tar", "supplier-receipt.json"}, "python-transport-two-originals")
        receipt_entry = self.original(data, "supplier-receipt.json", "python-original-receipt", 1024 * 1024,
                                      (0o400, 0o444, 0o600, 0o644))
        archive_entry = self.original(data, "supplier.tar", "python-original-tar", 64 * 1024 * 1024,
                                      (0o400, 0o444, 0o600, 0o644))
        receipt, archive = self.read(receipt_entry), self.read(archive_entry)
        self.python_input_originals.extend(((receipt_entry, receipt), (archive_entry, archive)))
        need(digest(receipt) == self.python_pins["receiptSha256"] and digest(archive) == self.python_pins["tarSha256"],
             "python-original-six-pins")
        lock = self.source_original(self.stager.source_lock_input(self.target), "python-original-source-lock", 16384)
        lock_body = self.read(lock)
        self.python_input_originals.append((lock, lock_body))
        provenance, rows = self.stager.fresh_supplier_receipt(receipt, self.python_pins["receiptSha256"], lock_body, target=self.target)
        source_names = ("macos_python_supplier_transport.py", "macos_cpython_orchestrator.py", "macos_cpython_source_build.py",
                        "macos_cpython_source_probe.py", "stage_macos_installed.py", "macos_android_helper_package.py")
        for name in source_names:
            entry = self.source_original("desktop/tools/" + name, "python-source-" + name, 1024 * 1024)
            self.python_input_originals.append((entry, self.read(entry)))
        if modules is None:
            def load_modules():
                loaded = tuple(load_data(self.checkout, name, "_mrk_python_signing_" + str(index))
                               for index, name in enumerate(source_names[:4]))
                for entry, body in self.python_input_originals:
                    need(self.read(entry) == body, "python-import-source-post")
                return loaded
            modules = self.python_io("python-source-import", load_modules)
        transport, matcher, builder, probe = modules
        self.python_modules = modules
        original = transport.project_archive(archive, rows, self.stager)
        need(set(original) == set(rows), "python-original-complete-inventory")
        python = original[self.stager.SIGNED_PYTHON_PATH][0]
        need(0 < len(python) <= MAX_HELPER, "python-executable-bound")
        self.python_original = original
        self.python_original_receipt = receipt
        self.python_inventory = provenance["inventorySha256"]
        capacity = os.fstatvfs(self.target_entry["fd"])
        need(capacity.f_frsize > 0 and capacity.f_bavail * capacity.f_frsize
             >= sum(len(body) for body, _mode in original.values()) + 2 * MAX_HELPER,
             "python-copy-storage-reserve")
        def source_snapshot():
            need(builder.DATA.known, "python-source-data-finality")
            result = builder.source_snapshot(self.checkout, self.target)
            need(builder.DATA.known, "python-source-data-finality")
            return result
        self.python_source_snapshot = self.python_io("python-source-snapshot", source_snapshot)
        entitlements = self.source_original("desktop/packaging/macos-empty-entitlements.plist", "python-empty-entitlements", 1024)
        empty = self.read(entitlements)
        self.python_input_originals.append((entitlements, empty))
        need(digest(empty) == self.stager.SIGNED_ENTITLEMENTS_SHA256, "python-empty-entitlement-source")
        self.python_empty = empty
        path = self.work / self.target_name / "signing-slot/python3"
        old = self.python_write("signing-slot/python3", python, 0o755)
        self.python_post()
        with self.credential_scope("python"):
            now, endpoint = self.python_clock()
            self.stage = "python-sign"
            self.python_mutation_pending = True
            self.call("python-sign", python_sign_command(path, self.checkout / "desktop/packaging/macos-empty-entitlements.plist",
                      self.phase, self.signing), self.native_environment(), cwd=self.work,
                      timeout=package_timeout_data(now, endpoint, 30), limit=65536)
            self.python_clock()
            slot = self.python_directories["signing-slot"]
            self.recheck_directory(slot)
            need(set(os.listdir(slot["fd"])) == {"python3"}, "python-sign-slot-members")
            output = self.original(slot, "python3", "python-signed-original", MAX_HELPER, (0o755,))
            signed = self.read(output)
            matcher.macho_content_valid(python, signed, self.arch, signing=True)
            try:
                self.python_flags = python_code_flags(signed, self.arch, self.phase, matcher)
            except Refused as error:
                if type(error) is Refused and error.args == ("python-signature-superblob",):
                    try:
                        self.receipt["pythonSignatureDiagnostic"] = {
                            "schemaVersion": 1, "available": False, "authority": "original-byte-data-only"}
                        self.receipt["pythonSignatureDiagnostic"] = python_signature_diagnostic(python, signed, self.arch, matcher)
                    except BaseException:
                        pass  # Optional observation must not replace the identical primary refusal.
                raise
            self.close(old)
            need(old["closed"] and not self.errors, "python-input-slot-close-unknown")
            self.python_files["signing-slot/python3"] = (output, signed)
            self.python_mutation_pending = False
            requirement = [] if self.phase == "python-engineering" else ["--test-requirement", signing_requirement(self.signing, PYTHON_IDENTIFIER)]
            verified = self.python_call("python-verify", ["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", *requirement, str(path)])
            need(not verified.stdout and not verified.stderr and self.read(output) == signed, "python-strict-signature-original")
        derived = dict(original)
        derived[self.stager.SIGNED_PYTHON_PATH] = (signed, 0o555)
        for name, (body, mode) in sorted(derived.items()):
            self.python_write("signed-payload/" + name, body, mode)
        self.python_directory("probe-scratch")
        self.python_seal()
        inventory = [{"path": name, "size": len(body), "sha256": digest(body), "mode": mode}
                     for name, (body, mode) in sorted(derived.items())]
        builtins = sorted(set(builder.BOOTSTRAP + builder.INTRINSIC + builder.OPTIONAL))
        need(len(builtins) == 61, "python-exact-builtin-roster")
        context = {"schemaVersion": 1, "target": self.target, "payload": str(self.work / self.target_name / "signed-payload"),
                   "checkout": str(self.checkout), "scratch": str(self.work / self.target_name / "probe-scratch"),
                   "sourceCommit": self.environment["GITHUB_SHA"], "builtins": builtins, "files": inventory,
                   "sourceFiles": {name: row["sha256"] for name, row in self.python_source_snapshot.items()}}
        context_body = self.stager.canonical(context)
        need(len(context_body) <= 512 * 1024, "python-probe-context-bound")
        self.python_write("python-probe-context.json", context_body, 0o444)
        context_path = self.work / self.target_name / "python-probe-context.json"
        executable = self.work / self.target_name / "signed-payload" / self.stager.SIGNED_PYTHON_PATH
        for role in ("modules", "loader", "tls", "cancellation"):
            result = self.python_call("python-" + role, [str(executable), "-I", "-S", "-B",
                str(self.checkout / "desktop/tools/macos_cpython_source_probe.py"), role, self.target, str(context_path)],
                maximum=60, limit=512 * 1024)
            builder.probe_result(result.stdout, role, self.target, probe)
            self.python_post()
        need(self.python_io("python-source-post", source_snapshot)
             == self.python_source_snapshot, "python-source-post-changed")
        self.python_post()
        self.python_signed = signed
        self.sha256 = digest(signed)
        self.receipt.update(pythonOriginalInventorySha256=self.python_inventory, pythonSignedSha256=self.sha256,
                            pythonCodeDirectoryFlags=self.python_flags, pythonPurpose=self.phase,
                            pythonNativeProbesPassed=True, signedRuntimeManifestComputed=False,
                            developerIdOrNotarizationQualified=False, productReady=False)

    def python_retirement(self):
        if (self.phase not in PYTHON_PHASES or self.python_started is None or self.target_entry is None
                or not self.python_known()):
            return
        self.python_retiring = True  # No command can be dispatched after this point.
        try:
            self.stage = "python-known-target-retirement"
            self.python_clock(work=False)
            self.python_post()
            for name in sorted(self.python_directories, key=lambda value: (value.count("/"), value)):
                self.python_directory_mode(self.python_directories[name], 0o700)
        except BaseException as error:
            self.errors.append({"stage": "python-target-retained", "type": type(error).__name__})

    def python_capsule(self):
        need(self.phase == "python-shipping" and self.receipt["passed"] is True
             and self.python_signed is not None and self.signing is not None, "python-shipping-capsule-required")
        def row(body):
            return {"path": self.stager.SIGNED_PYTHON_PATH, "size": len(body), "mode": 0o555, "sha256": digest(body)}
        signer = {"sourceCommit": self.environment["GITHUB_SHA"], "workflow": self.environment["GITHUB_WORKFLOW_REF"],
                  "runId": self.environment["GITHUB_RUN_ID"], "runAttempt": self.environment["GITHUB_RUN_ATTEMPT"],
                  "identifier": PYTHON_IDENTIFIER, "teamIdentifier": self.signing[0], "leafCertificateSha1": self.signing[1],
                  "producerProfileSha256": digest(self.producer_profile), "serviceProfileSha256": digest(self.service_profile),
                  "entitlementsSha256": digest(self.python_empty), "codeDirectoryFlags": self.python_flags, "timestampRequested": True}
        return {"schemaVersion": 1, "kind": self.stager.SIGNED_PYTHON_KIND, "purpose": "configured-shipping",
                "target": self.target, "pythonVersion": "3.14.7", "originalSupplier": self.python_pins,
                "originalInventorySha256": self.python_inventory,
                "originalPython": row(self.python_original[self.stager.SIGNED_PYTHON_PATH][0]), "signedPython": row(self.python_signed),
                "signer": signer, "nativeEvidence": {record["role"]: {key: record[key] for key in ("stdoutSha256", "stderrSha256")}
                                                        for record in self.calls},
                "originalsKnown": True, "sourcePost": True, "supplierPost": True, "nonimagePost": True,
                "targetRetired": True, "closesKnown": True, "outerExitRequired": True,
                "assurance": "pinned-native-signature-and-probes-not-notarization-or-installed-authority"}
    def python_publish_final(self, name, body, mode):
        # No new process owner. Reopen only the previously held work ORIGINAL;
        # capsule files remain inadmissible until all closes and outer exit zero.
        need(self.phase in PYTHON_PHASES and type(body) is bytes and self.work_entry is not None,
             "python-publication-purpose")
        facts_name = "android-helper-" + self.phase + ".json"
        need((name == facts_name and mode == 0o600 and len(body) <= 16384)
             or (self.phase == "python-shipping" and self.receipt["passed"] is True and self.python_known()
                 and self.receipt["targetRetired"] and self.receipt["originalClosesKnown"]
                 and ((name == "python3" and mode == 0o555 and body == self.python_signed)
                      or (name == "python-signed-receipt.json" and mode == 0o444 and len(body) <= 16384))),
             "python-publication-closed-output")
        self.python_clock(work=False)
        original = self.work_entry["identity"]
        directory_entry = file_entry = None
        primary = None
        try:
            directory = os.open(self.work, READ_FLAGS | os.O_DIRECTORY)
            directory_entry = self.register(directory, "python-publication-directory", "publication-directory")
            need(directory_identity(os.fstat(directory)) == directory_identity(self.work.lstat()) == original,
                 "python-publication-work-changed")
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
            file_entry = self.register(fd, "python-publication-" + name, "file")
            offset = 0
            while offset < len(body):
                count = os.write(fd, body[offset:])
                need(type(count) is int and count > 0, "python-publication-short-write")
                offset += count
                self.python_clock(work=False)
            os.fchmod(fd, mode)
            os.fsync(fd)
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                 and info.st_gid == os.getgid() and info.st_size == len(body) and stat.S_IMODE(info.st_mode) == mode,
                 "python-publication-original")
            need(os.pread(fd, len(body) + 1, 0) == body
                 and signature(os.fstat(fd)) == signature(info)
                 == signature(os.stat(name, dir_fd=directory, follow_symlinks=False)), "python-publication-readback")
            os.fsync(directory)
            need(directory_identity(os.fstat(directory)) == directory_identity(self.work.lstat()) == original,
                 "python-publication-work-post")
            self.python_clock(work=False)
        except BaseException as error:
            primary = error
        finally:
            for entry in (file_entry, directory_entry):
                if entry is not None:
                    self.close(entry)
                    if not entry["closed"] and primary is None:
                        primary = Refused("python-publication-close-unknown")
            self.receipt["originalClosesKnown"] = (self.credential_known() and self.credential_active is None and not self.signing_mutation_pending
                                               and self.stager_io_pending is None and not self.python_mutation_pending
                                                   and all(entry["closed"] for entry in self.entries))
            try:
                need(directory_identity(self.work.lstat()) == original, "python-publication-work-after-close")
                self.python_clock(work=False)
            except BaseException as error:
                self.errors.append({"stage": "python-publication-post", "type": type(error).__name__})
                if primary is None:
                    primary = error
        if primary is not None:
            self.receipt["passed"] = False
            self.receipt.setdefault("failure", {"stage": "python-final-publication", "type": type(primary).__name__,
                                               "reason": "original-publication-refused"})
            raise primary

    def image_binding(self):
        self.stage = "source-image-binding"
        self.release_entry = self.source_original(self.release_input, "source-image-release", self.stager.BUILD_RELEASE_LIMIT)
        body = self.read(self.release_entry)
        value = self.stager.build_release_data(body, target=self.target)
        source, release = self.environment["GITHUB_SHA"], value["release"]
        need(re.fullmatch(r"[0-9a-f]{40}", source) is not None and source != "0" * 40
             and source == self.environment["MRK_MACOS_INSTALL_SOURCE_COMMIT"]
             and type(release) is str and 0 < len(release) < 64 and release.isascii(), "source-image-binding")
        self.image_source, self.image_release = source, release
        self.receipt.update(imageSourceCommit=source, imageReleaseId=release, imageReleaseSourceSha256=digest(body))
        return body

    def prepare(self):
        self.stage = "separate-resident-image-compiler"
        result = self.call("build", [direct_rust_tools(self.target)[0], "build", "--manifest-path", str(self.checkout / WORKSPACE / "Cargo.toml"),
                           "--locked", "--release", "--jobs", "1", "--target", self.target,
                           "--lib", "--message-format=json-render-diagnostics"],
                           build_environment(self.environment, self.work, self.image_release, target=self.target),
                           cwd=self.checkout / WORKSPACE, timeout=480, limit=4 * 1024 * 1024)
        artifact(result.stdout, self.checkout, self.work / self.target_name, build_target=self.target)
        self.stage = "compiler-original-copy"
        release = self.descend(self.target_entry, (self.target, "release"))
        original = self.original(release, RESIDENT_IMAGE, "compiler-artifact", MAX_HELPER, (0o700, 0o755), alias=True)
        if original["identity"][3] == 2:
            deps = self.directory(release, "deps", "compiler-deps")
            names = os.listdir(deps["fd"])
            need(len(names) <= 8192, "compiler-alias-directory-bound")
            # Cargo cdylib outputs have the fixed un-hashed name in deps; never
            # accept a guessed executable alias or sign either linked original.
            aliases = [name for name in names if name == RESIDENT_IMAGE]
            need(len(aliases) == 1, "one-compiler-alias")
            alias = self.original(deps, aliases[0], "compiler-alias", MAX_HELPER, (0o700, 0o755), alias=True)
            need(alias["identity"] == original["identity"], "compiler-alias-original")
        body = self.read(original)
        self.stager.image_macho(body, "resident", target=self.target)
        self.receipt["residentImageCargoArtifact"] = {
            "targetKind": "cdylib", "crate": IMAGE_TARGET, "package": HELPER, "target": self.target,
            "entrypoint": "src/lib.rs", "profileTest": False, "features": [],
            "cargoMessagesSha256": digest(result.stdout), "binarySha256BeforeSigning": digest(body),
            "binaryBytesBeforeSigning": len(body), "instrumented": False}
        self.publish(RESIDENT_IMAGE, body, mode=0o755)
        need(self.read(original) == body, "compiler-original-copy-changed")
        for entry in self.entries:
            if entry["role"] in ("compiler-artifact", "compiler-alias"):
                self.close(entry)
                need(entry["closed"], "compiler-artifact-close-unknown")
        with self.credential_scope("resident-image"):
            self.stage = "resident-image-source-selected-signing"
            self.call("resident-image-sign", ["/usr/bin/codesign", "--force", "--sign", "-" if self.signing is None else self.signing[1],
                      "--identifier", IDENTIFIER + ".image", "--options", "runtime",
                      "--entitlements", str(self.checkout / "desktop/packaging/macos-empty-entitlements.plist"),
                      "--timestamp=none" if self.signing is None else "--timestamp", str(self.work / RESIDENT_IMAGE)],
                      self.native_environment(), cwd=self.work, timeout=30, limit=65536)
            signed = self.original(self.work_entry, RESIDENT_IMAGE, "signed-resident-image", MAX_HELPER, (0o755,))
            body = self.read(signed)
            self.stager.image_macho(body, "resident", target=self.target)
            self.strict_verify(signed, body, "resident-image-verify-signed", self.work / RESIDENT_IMAGE)
        self.resident_image_sha256 = digest(body)
        self.receipt.update(residentImageSha256=self.resident_image_sha256, residentImageBytes=len(body),
                            residentImageOriginal=signed["identity"],
                            residentImageSigning=("ad-hoc" if self.signing is None else "source-selected-leaf") + "-fixed-identifier-runtime-empty-entitlements-strictly-verified")
        self.prepare_entry()
        self.prepare_facade("desktop")
        self.prepare_facade("resident")

    def prepare_facade(self, role):
        need(role in ("desktop", "resident"), "fixed-facade-role")
        name = DESKTOP_FACADE if role == "desktop" else HELPER
        self.stage = role + "-facade-compiler"
        paths = ("desktop/native/macos-installed-entry/" + role + "_facade.c",
                 "desktop/native/macos-installed-entry/gate.c", "desktop/native/macos-installed-entry/gate.h",
                 "desktop/native/macos-installed-entry/fixed_paths.h", "desktop/native/macos-installed-entry/image_abi.h",
                 "desktop/native/macos-installed-native/src/native.m", "desktop/src-tauri/src/macos_install_fixed_paths.rs")
        originals = [(path, self.source_original(path, role + "-facade-source-" + Path(path).name,
                     256 * 1024 if path == paths[5] else 128 * 1024)) for path in paths]
        bodies = [self.read(entry) for _path, entry in originals]
        destination = self.work / self.target_name / name
        self.call(role + "-facade-build", ["/usr/bin/xcrun", "--sdk", "macosx", "clang", "-x", "c", "-std=c11",
                  "-Wall", "-Wextra", "-Werror", "-O2", "-arch", self.arch, "-mmacosx-version-min=26.0",
                  "-DMRK_ENTRY_METADATA_ONLY=1", '-DMRK_IMAGE_SOURCE_COMMIT="' + self.image_source + '"',
                  '-DMRK_IMAGE_RELEASE_ID="' + self.image_release + '"',
                  str(self.checkout / paths[0]), str(self.checkout / paths[1]), str(self.checkout / paths[5]),
                  "-o", str(destination)],
                  dict(self.native_environment(), DEVELOPER_DIR=self.environment["DEVELOPER_DIR"]),
                  cwd=self.checkout, timeout=30, limit=65536)
        need(all(self.read(entry) == body for (_path, entry), body in zip(originals, bodies)), "facade-source-changed")
        original = self.original(self.target_entry, name, role + "-facade-compiler-artifact", 1024 * 1024, (0o700, 0o755))
        body = self.read(original)
        self.stager.entry_macho(body, target=self.target)
        self.publish(name, body, mode=0o755)
        need(self.read(original) == body, "facade-compiler-original-changed")
        self.receipt[role + "FacadeSources"] = [
            {"path": path, "bytes": len(source), "sha256": digest(source)}
            for (path, _entry), source in zip(originals, bodies)]
        self.receipt[role + "FacadeSha256BeforeSigning"] = digest(body)
        self.receipt[role + "FacadeBytesBeforeSigning"] = len(body)
        self.receipt[role + "FacadeOriginalBeforeSigning"] = original["identity"]
        self.close(original)
        need(original["closed"], "facade-compiler-artifact-close-unknown")
        if role == "desktop":
            self.desktop_facade_sha256 = digest(body)
            return
        with self.credential_scope("helper"):
            self.stage = "helper-source-selected-signing"
            self.call("sign", ["/usr/bin/codesign", "--force", "--sign", "-" if self.signing is None else self.signing[1], "--identifier", IDENTIFIER,
                               "--options", "runtime", "--entitlements", str(self.checkout / "desktop/packaging/macos-empty-entitlements.plist"),
                               "--timestamp=none" if self.signing is None else "--timestamp", str(self.work / HELPER)],
                      self.native_environment(), cwd=self.work, timeout=30, limit=65536)
            signed = self.original(self.work_entry, HELPER, "signed-helper", MAX_HELPER, (0o755,))
            body = self.read(signed)
            self.stager.entry_macho(body, target=self.target)
            self.strict_verify(signed, body, "verify-signed", self.work / HELPER)
        self.sha256 = digest(body)
        self.receipt.update(helperSha256=self.sha256, helperBytes=len(body), helperOriginal=signed["identity"],
                            signing=("ad-hoc-fixed-identifier-runtime-empty-entitlements-strictly-verified" if self.signing is None else
                                      "source-selected-developer-id-fixed-requirement-runtime-empty-entitlements"))


    def prepare_entry(self):
        """One fixed C/libSystem-only compile through this same original owner."""
        self.stage = "fixed-installed-entry-compiler"
        paths = ("desktop/native/macos-installed-entry/entry.c", "desktop/native/macos-installed-entry/gate.c",
                 "desktop/native/macos-installed-entry/gate.h", "desktop/native/macos-installed-entry/fixed_paths.h",
                 "desktop/native/macos-installed-native/src/native.m", "desktop/src-tauri/src/macos_install_fixed_paths.rs")
        originals = [(name, self.source_original(name, "entry-source-" + Path(name).name,
                     256 * 1024 if name == paths[4] else 128 * 1024)) for name in paths]
        bodies = [self.read(entry) for _name, entry in originals]
        destination = self.work / self.target_name / ENTRY
        self.call("entry-build", ["/usr/bin/xcrun", "--sdk", "macosx", "clang", "-x", "c", "-std=c11",
                  "-Wall", "-Wextra", "-Werror", "-O2", "-arch", self.arch, "-mmacosx-version-min=26.0",
                  "-DMRK_ENTRY_METADATA_ONLY=1", str(self.checkout / paths[0]), str(self.checkout / paths[1]),
                  str(self.checkout / paths[4]), "-o", str(destination)],
                  dict(self.native_environment(), DEVELOPER_DIR=self.environment["DEVELOPER_DIR"]),
                  cwd=self.checkout, timeout=30, limit=65536)
        need(all(self.read(entry) == body for (_name, entry), body in zip(originals, bodies)), "entry-source-changed")
        original = self.original(self.target_entry, ENTRY, "entry-compiler-artifact", 1024 * 1024, (0o700, 0o755))
        body = self.read(original)
        self.stager.entry_macho(body, target=self.target)
        self.publish(ENTRY, body, mode=0o755)
        need(self.read(original) == body, "entry-compiler-original-changed")
        self.entry_sha256 = digest(body)
        self.receipt.update(entryBinarySha256BeforeSigning=self.entry_sha256, entryBytes=len(body),
                            entryOriginal=original["identity"], entryLoaderPolicy="libSystem-only-no-native-initializers",
                            entrySources=[{"path": name, "bytes": len(body), "sha256": digest(body)}
                                          for (name, _entry), body in zip(originals, bodies)],
                            entryExecutionObserved=False, maintenanceQualified=False)

    def strict_verify(self, original, body, role, path):
        self.stage = role
        requirement = [] if self.signing is None else ["--all-architectures", "--test-requirement",
            signing_requirement(self.signing, IDENTIFIER + ".image" if path.name == RESIDENT_IMAGE else IDENTIFIER)]
        result = self.call(role, ["/usr/bin/codesign", "--verify", "--strict", *requirement, str(path)],
                           self.native_environment(), cwd=self.work, timeout=30, limit=65536)
        need(not result.stdout and not result.stderr and self.read(original) == body, "strict-original-verification")

    def verify_staged(self, expected, expected_image):
        need(type(expected) is str and re.fullmatch(r"[0-9a-f]{64}", expected), "expected-helper-digest")
        need(type(expected_image) is str and re.fullmatch(r"[0-9a-f]{64}", expected_image), "expected-resident-image-digest")
        self.stage = "staged-helper-original"
        contents = self.descend(self.work_entry, ("app", "Mobile Release Kit.app", "Contents", "Helpers", "MobileReleaseKitPayload.app", "Contents"))
        helpers = self.directory(contents, "Helpers", "staged-helpers")
        original = self.original(helpers, HELPER, "staged-helper", MAX_HELPER, (0o555,))
        body = self.read(original)
        need(digest(body) == expected, "staged-helper-signature-bytes-changed")
        self.stager.entry_macho(body, target=self.target)
        frameworks = self.directory(contents, "Frameworks", "staged-frameworks")
        image = self.original(frameworks, RESIDENT_IMAGE, "staged-resident-image", MAX_HELPER, (0o555,))
        image_body = self.read(image)
        need(digest(image_body) == expected_image, "staged-resident-image-signature-bytes-changed")
        self.stager.image_macho(image_body, "resident", target=self.target)
        daemons = self.descend(contents, ("Library", "LaunchDaemons"))
        plist = self.original(daemons, IDENTIFIER + ".plist", "staged-service-plist", 4096, (0o444, 0o644))
        source_plist = self.source_original("desktop/macos-installed-inputs/" + IDENTIFIER + ".plist", "source-service-plist", 4096)
        expected_plist = self.read(source_plist)
        parsed = self.stager.plistlib.loads(expected_plist)
        need(parsed == {"Label": IDENTIFIER, "BundleProgram": "Contents/Helpers/" + HELPER,
                        "MachServices": {IDENTIFIER: True}} and parsed["MachServices"][IDENTIFIER] is True,
             "source-service-plist")
        need(self.read(plist) == expected_plist, "staged-service-plist")
        self.strict_verify(original, body, self.phase, self.work / "app/Mobile Release Kit.app" / self.stager.ANDROID_HELPER)
        self.strict_verify(image, image_body, self.phase + "-resident-image",
                           self.work / "app/Mobile Release Kit.app" / self.stager.RESIDENT_IMAGE)
        need(self.read(original) == body and self.read(image) == image_body
             and self.read(plist) == self.read(source_plist) == expected_plist, "staged-service-group-changed")
        self.sha256, self.resident_image_sha256 = expected, expected_image
        self.receipt.update(helperSha256=expected, helperBytes=len(body), helperOriginal=original["identity"],
                            residentImageSha256=expected_image, residentImageBytes=len(image_body),
                            residentImageOriginal=image["identity"])

    def package_clock(self):
        now = time.monotonic_ns()
        need(type(now) is int and type(self.package_endpoint) is int
             and self.package_started <= self.package_observed <= now < self.package_endpoint, "package-group-deadline")
        self.package_observed = now
        return now

    def package_settled(self):
        return (self.stager_io_pending is None and not self.errors and self.credential_known()
                and not self.credential_failed and not self.signing_mutation_pending
                and all(call["returned"] and call.get("capturesSettled") is True for call in self.calls)
                and all(entry["closed"] for entry in self.entries if entry["role"].startswith("output-")))

    def package_stager_io(self, operation, args):
        # Only the three existing direct stager I/O boundaries. A thrown parse
        # refusal can mask that stager's local finally/close uncertainty; only a
        # normal return proves completion. Never infer it from an error token.
        need(operation in ("final-audit", "result-absence", "v2-readback"), "closed-stager-io")
        need(self.package_settled(), "package-io-finality-unknown")
        self.package_clock()
        self.stager_io_pending = operation
        try:
            if operation == "final-audit":
                result = self.stager.audit_command(args)
            elif operation == "result-absence":
                result = self.stager.installer_result_absent_command(args)
            else:
                result = self.stager.observation_command(args)
        except BaseException:
            self.errors.append({"stage": "package-stager-io", "operation": operation, "type": "CompletionUnknown"})
            raise  # Preserve the identical primary error; the pending latch stays.
        self.stager_io_pending = None
        self.package_clock()
        return result

    def package_call(self, role, argv, *, environment=None, timeout=30, limit=65536, cwd=None):
        need(self.package_settled(), "package-io-finality-unknown")
        timeout = package_timeout_data(self.package_clock(), self.package_endpoint, timeout)
        result = self.call(role, argv, self.native_environment() if environment is None else environment,
                           cwd=self.work if cwd is None else cwd, timeout=timeout, limit=limit)
        self.package_clock()  # Original return AND the existing capture/status closes.
        return result

    def package_directory(self, name):
        self.package_clock()
        self.recheck_directory(self.work_entry)
        os.mkdir(name, 0o700, dir_fd=self.work_entry["fd"])
        entry = self.directory(self.work_entry, name, "package-" + name)
        need(not os.listdir(entry["fd"]), "package-exclusive-empty-directory")
        return entry

    def package_file(self, parent, name, body):
        self.package_clock()
        need(type(body) is bytes and 0 < len(body) <= self.stager.MAX_BYTES, "package-output-bound")
        self.recheck_directory(parent)
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent["fd"])
        entry = self.register(fd, "package-output-" + name, "file", parent["fd"], name)
        entry["parent_entry"] = parent
        offset = 0
        while offset < len(body):
            self.package_clock()
            written = os.write(fd, body[offset:offset + 1024 * 1024])
            need(written > 0, "package-output-short-write")
            offset += written
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
             and info.st_gid == os.getgid() and info.st_size == len(body), "package-output-original")
        os.fchmod(fd, 0o444)
        os.fsync(fd)
        entry["identity"] = signature(os.fstat(fd))
        need(self.read(entry) == body, "package-output-readback")
        self.package_outputs.append((entry, digest(body)))
        self.package_clock()
        return entry

    def package_post(self):
        self.package_clock()
        for root, names in self.package_roots:
            self.recheck_directory(root)
            need(set(os.listdir(root["fd"])) == names, "package-source-layout-roster")
        for entry, expected in self.package_outputs:
            need(digest(self.read(entry)) == expected, "package-original-post")
            self.package_clock()
        for entry, body in self.package_sources:
            need(self.read(entry) == body, "package-source-post")
        self.package_clock()

    def package_image(self, root, label):
        path = self.work / "distribution" / ("MobileReleaseKit.dmg" if label == "distribution" else "MobileReleaseKit-Observation.dmg")
        identifier = "dev.mobile-release-kit.desktop." + label
        self.package_call(label + "-create", ["/usr/bin/hdiutil", "create", "-srcfolder", str(self.work / root["name"]),
            "-fs", "HFS+", "-format", "UDZO", "-volname", "MobileReleaseKit", str(path)], timeout=180)
        self.package_post()
        # Only this fresh task-owned image is signed. SOURCE selects the exact
        # identity; missing credentials never fall back to an ad-hoc identity.
        self.package_call(label + "-sign", ["/usr/bin/codesign", "--sign", self.signing[1], "--timestamp",
            "--identifier", identifier, str(path)], timeout=60)
        image = self.original(self.distribution_entry, path.name, label + "-signed-image", self.stager.MAX_BYTES, (0o600, 0o644, 0o444))
        body = self.read(image)
        before = image["identity"]
        os.fchmod(image["fd"], 0o444)  # Authorized metadata change on our newly-created original only.
        os.fsync(image["fd"])
        after = signature(os.fstat(image["fd"]))
        need(after[:2] == before[:2] and after[3:8] == before[3:8]
             and after[2] == stat.S_IFREG | 0o444, "package-image-mode-transition")
        image["identity"] = after  # fchmod may legitimately change ctime; bytes/other identity stay exact.
        need(self.read(image) == body, "package-image-mode-bytes")
        self.package_outputs.append((image, digest(body)))
        self.package_call(label + "-verify-signature", ["/usr/bin/codesign", "--verify", "--strict",
            "--test-requirement", signing_requirement(self.signing, identifier), str(path)])
        self.package_call(label + "-verify-image", ["/usr/bin/hdiutil", "verify", str(path)], timeout=120)
        self.package_post()
        return {"file": path.name, "sha256": digest(body), "bytes": len(body)}, path

    def recheck_mount(self):
        entry = self.mount_entry
        self.package_clock()
        self.recheck_directory(self.work_entry)
        need(entry is not None and entry["fd"] is not None and not entry["closed"]
             and self.mount_known and not self.mount_detached, "package-original-mount-unavailable")
        named, held = os.stat("package-mount", dir_fd=self.work_entry["fd"], follow_symlinks=False), os.fstat(entry["fd"])
        def identity(info):
            need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022,
                 "package-readonly-mount-shape")
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        flags = os.fstatvfs(entry["fd"]).f_flag
        need(type(flags) is int and flags & os.ST_RDONLY
             and identity(named) == identity(held) == entry["identity"]
             and held.st_dev != self.work_entry["identity"][0], "package-readonly-mount-original")

    def mount_inputs(self, expected, package_name):
        self.recheck_mount()
        actual = {}
        for name in (package_name, "producer.json", "producer.sig"):
            limit = self.stager.MAX_BYTES if name == package_name else (
                self.stager.PRODUCER_DESCRIPTOR_BYTES if name == "producer.json" else self.stager.PRODUCER_SIGNATURE_BYTES)
            fd = os.open(name, READ_FLAGS, dir_fd=self.mount_entry["fd"])
            entry = self.register(fd, "mounted-" + name, "mounted-file", self.mount_entry["fd"], name)
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o444
                 and info.st_nlink == 1 and info.st_uid in (0, os.getuid()) and 0 < info.st_size <= limit,
                 "package-mounted-file-shape")
            entry["identity"] = signature(info)
            body = os.pread(fd, info.st_size + 1, 0)
            need(len(body) == info.st_size and signature(os.fstat(fd)) == entry["identity"]
                 == signature(os.stat(name, dir_fd=self.mount_entry["fd"], follow_symlinks=False)), "package-mounted-file-original")
            entry["sha256"] = digest(body)
            actual[name] = (body, 0o444)
        self.stager.distribution_layout_data(os.listdir(self.mount_entry["fd"]), package_name, expected, actual)
        self.recheck_mount()

    def mounted_post(self):
        self.recheck_mount()
        for entry in self.entries:
            if entry["kind"] == "mounted-file":
                need(entry["fd"] is not None and signature(os.fstat(entry["fd"])) == entry["identity"]
                     == signature(os.stat(entry["name"], dir_fd=self.mount_entry["fd"], follow_symlinks=False)), "package-mounted-post")
                body = os.pread(entry["fd"], entry["identity"][6] + 1, 0)
                need(len(body) == entry["identity"][6] and digest(body) == entry["sha256"]
                     and signature(os.fstat(entry["fd"])) == entry["identity"]
                     == signature(os.stat(entry["name"], dir_fd=self.mount_entry["fd"], follow_symlinks=False)), "package-mounted-post-bytes")
        need(set(os.listdir(self.mount_entry["fd"])) == {self.package_name, "producer.json", "producer.sig"}, "package-mounted-post-roster")
        self.recheck_mount()

    def detach_package_mount(self):
        need(self.mount_known and not self.mount_detached
             and (not self.installer_entered or self.installer_zero and self.installation_readback), "package-mount-retention-required")
        need(self.package_settled(), "package-mount-finality-unknown")
        self.recheck_mount()
        for entry in self.entries:
            if entry["kind"] in ("mounted-file", "mount"):
                self.close(entry)
                need(entry["closed"], "package-mount-close-unknown")
        # The original reported device is used once, without force/fallback or
        # adopting unrelated OS services. Closing our FDs precedes detach.
        self.package_call("distribution-detach", ["/usr/bin/hdiutil", "detach", self.mount_device], timeout=30)
        self.recheck_directory(self.mount_placeholder)
        need(not os.listdir(self.mount_placeholder["fd"]), "package-detached-mountpoint-not-empty")
        os.rmdir("package-mount", dir_fd=self.work_entry["fd"])
        self.mount_detached = True
        self.package_clock()

    def package_install(self):
        self.stage = "package-final-audit"
        self.package_started = self.package_observed = time.monotonic_ns()
        self.package_endpoint = self.package_started + 990_000_000_000
        self.package_clock()
        inventory_hash, manifest_hash = (self.environment.get(name) for name in
            ("MRK_MACOS_INSTALL_INVENTORY_SHA256", "MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"))
        need(self.stager.maintenance_hex(inventory_hash, 64) and self.stager.maintenance_hex(manifest_hash, 64), "package-compiled-bindings")
        selection = self.stager.BuildSelection(self.target, self.stager.build_release_data(self.read(self.release_entry), target=self.target)["packageVersion"], self.image_release)
        source = self.stager.packaging_signing_data(self.producer_profile, self.service_profile)
        need(self.signing == (source.team, source.leaf_sha1), "package-source-signing-selection")
        original = self.original(self.directory(self.work_entry, "package-final", "package-final"), "MobileReleaseKit.pkg",
                                 "final-package-original", self.stager.MAX_BYTES, (0o600, 0o644, 0o444))
        body = self.read(original)
        audit = self.package_stager_io("final-audit", argparse.Namespace(target=self.target, fixture=False,
            scripts=self.work / "scripts", package=self.work / "package-final/MobileReleaseKit.pkg",
            original_package=self.work / "MobileReleaseKit-original.pkg"))
        need(audit["packageSha256"] == digest(body) and audit["packageSize"] == len(body)
             and self.read(original) == body, "package-final-audit-original")
        self.package_outputs.append((original, digest(body)))
        self.publish("package-audit.json", self.stager.canonical(audit) + b"\n")
        self.package_clock()
        history_entry = self.source_original("desktop/macos-installed-inputs/producer-history.json", "source-producer-history", self.stager.PRODUCER_DESCRIPTOR_BYTES)
        history = self.read(history_entry)
        self.package_sources.append((history_entry, history))
        for name in ("leaf.der", "issuer.der", "root.der"):
            entry = self.source_original("desktop/packaging/macos-install-producer-certificates/" + name, "source-producer-" + name, 16384)
            self.package_sources.append((entry, self.read(entry)))
        source_inventory = self.original(self.directory(self.work_entry, "input", "package-input"), self.stager.INSTALLATION_INVENTORY_NAME,
            "package-source-inventory", 1024 * 1024, (0o444,))
        inventory = self.read(source_inventory)
        self.stager.observation_inventory_bytes(inventory, inventory_hash, manifest_hash, selection=selection)
        self.package_outputs.append((source_inventory, digest(inventory)))
        descriptor = self.stager.packaging_descriptor_data(history, source, selection, source_commit=self.image_source,
            manifest=manifest_hash, inventory=inventory_hash, package=digest(body))
        root = self.package_directory("producer-root")
        self.package_file(root, "Install.pkg", body)
        self.package_file(self.work_entry, "producer-descriptor-input.json", descriptor)
        self.package_post()
        self.stage = "package-explicit-producer-compiler"
        environment = build_environment(self.environment, self.work, self.image_release, target=self.target)
        environment.update(CARGO_TARGET_DIR=str(self.work / self.target_name), TMPDIR=str(self.work / self.target_name / "tmp"),
            MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=manifest_hash, MRK_MACOS_INSTALL_INVENTORY_SHA256=inventory_hash)
        compiled = self.package_call("producer-build", [direct_rust_tools(self.target)[0], "build", "--manifest-path", str(self.checkout / "desktop/src-tauri/Cargo.toml"),
            "--locked", "--offline", "--release", "--jobs", "1", "--target", self.target, "--no-default-features",
            "--features", "macos-package-producer", "--example", "macos_package_producer", "--message-format=json-render-diagnostics"],
            environment=environment, cwd=self.checkout / "desktop/src-tauri", timeout=480, limit=4 * 1024 * 1024)
        binary = producer_artifact(compiled.stdout, self.checkout, self.work / self.target_name, self.target)
        binary_dir = self.descend(self.target_entry, (self.target, "release", "examples"))
        executable = self.original(binary_dir, binary.name, "producer-compiled-example", 64 * 1024 * 1024, (0o700, 0o755), alias=True)
        executable_body = self.read(executable)
        self.stager.macho(executable_body, system_only=True, target=self.target)
        # Cargo may retain an alias. Execute only a fresh single-link copy, not
        # either compiler-owned name; keep the original through copy POST.
        producer = self.producer_signing_copy(executable, executable_body)
        with self.credential_scope("producer", producer=producer):
            self.stage = "package-producer-emission"
            need(package_timeout_data(self.package_clock(), self.package_endpoint, 123) == 123, "producer-original-clock-reserve")
            emitted = self.package_call("producer-emitter", [str(self.work / "macos-package-producer"), "--package-root", str(self.work / "producer-root"),
                "--descriptor-input", str(self.work / "producer-descriptor-input.json")], timeout=123, limit=4096)
            signed_entry = self.original(root, "producer.sig", "producer-original-signature", self.stager.PRODUCER_SIGNATURE_BYTES, (0o444,))
            descriptor_entry = self.original(root, "producer.json", "producer-original-descriptor", self.stager.PRODUCER_DESCRIPTOR_BYTES, (0o444,))
            signed, actual_descriptor = self.read(signed_entry), self.read(descriptor_entry)
            need(actual_descriptor == descriptor, "producer-exact-descriptor-emission")
            summary = self.stager.emitted_package_data(emitted.stdout, emitted.stderr, emitted.returncode, body, actual_descriptor, signed, target=self.target)
            self.package_outputs.extend(((signed_entry, digest(signed)), (descriptor_entry, digest(descriptor))))
        expected = {"Install.pkg": body, "producer.json": descriptor, "producer.sig": signed}
        self.stager.distribution_layout_data(os.listdir(root["fd"]), "Install.pkg", expected,
            {name: (value, 0o444) for name, value in expected.items()})
        self.package_roots.append((root, set(expected)))
        request_id = os.urandom(16).hex()  # One new independent correlation ID, no fallback/retry.
        self.package_name = self.stager.distribution_request_name(request_id)
        self.publish("package-request-id.txt", (request_id + "\n").encode("ascii"))
        observed_root = self.package_directory("producer-observation-root")
        for name, value in expected.items():
            self.package_file(observed_root, self.package_name if name == "Install.pkg" else name, value)
        self.package_roots.append((observed_root, {self.package_name, "producer.json", "producer.sig"}))
        self.distribution_entry = self.package_directory("distribution")
        self.package_post()
        user_image, _user_path = self.package_image(root, "distribution")
        observation_image, observation_path = self.package_image(observed_root, "observation")
        self.mount_placeholder = self.package_directory("package-mount")
        self.stage = "package-readonly-attach"
        attached = self.package_call("distribution-attach", ["/usr/bin/hdiutil", "attach", str(observation_path), "-readonly", "-nobrowse",
            "-noautoopen", "-mountpoint", str(self.work / "package-mount"), "-plist"], timeout=60)
        self.mount_device = self.stager.distribution_mount_data(attached.stdout, attached.stderr, attached.returncode, self.work / "package-mount")
        fd = os.open("package-mount", READ_FLAGS | os.O_DIRECTORY, dir_fd=self.work_entry["fd"])
        self.mount_entry = self.register(fd, "package-readonly-mount", "mount", self.work_entry["fd"], "package-mount")
        info = os.fstat(fd)
        self.mount_entry["identity"] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        self.mount_known = True
        self.mount_inputs(expected, self.package_name)
        args = argparse.Namespace(target=self.target, fixture=False, input=self.work / "input", expected_source=self.image_source,
            expected_inventory=inventory_hash, expected_manifest=manifest_hash, request_id=request_id, expected_package=digest(body),
            producer_descriptor=self.work / "package-mount/producer.json", producer_signature=self.work / "package-mount/producer.sig",
            installer_status=self.work / "installer-output.status", package=self.work / "package-mount" / self.package_name,
            run_id=self.environment["GITHUB_RUN_ID"], run_attempt=self.environment["GITHUB_RUN_ATTEMPT"])
        self.package_stager_io("result-absence", args)
        self.package_diagnostic(args, capture=False)
        self.package_post()
        self.mounted_post()
        self.stage = "standard-original-installer"
        # Require the unchanged inner120s plus this owner's existing3s reserve;
        # neither starts a renewed package-group deadline.
        need(package_timeout_data(self.package_clock(), self.package_endpoint, 123) == 123, "installer-original-clock-reserve")
        try:
            result = self.package_call("installer", ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer", "-pkg", str(args.package),
                "-target", "/", "-dumplog", "-verboseR"], timeout=123, limit=256 * 1024)
            self.installer_zero = result.returncode == 0
        except BaseException:
            # Diagnostics never replace original status or a failing call, and
            # cannot run across an unknown original process boundary.
            if self.calls and self.calls[-1]["role"] == "installer" and self.package_settled():
                try:
                    self.package_diagnostic(args, capture=True)
                except BaseException as diagnostic:
                    self.errors.append({"stage": "installer-diagnostic", "type": type(diagnostic).__name__})
            raise
        self.package_diagnostic(args, capture=True)
        self.package_post()
        self.mounted_post()
        self.stage = "package-nonroot-v2-readback"
        observed = self.package_stager_io("v2-readback", args)
        self.package_clock()
        self.publish("installation-observation.json", self.stager.canonical(observed) + b"\n")
        self.installation_readback = True
        self.package_clock()
        self.package_post()
        self.mounted_post()
        self.detach_package_mount()
        self.package_post()
        self.receipt["distribution"] = {"schemaVersion": 1, "kind": "mrk-ordinary-package-observed-v2", "target": self.target,
            "packageVersion": selection.package_version, "release": selection.release, "requestId": request_id,
            "packageSha256": digest(body), "packageBytes": len(body), "descriptorSha256": digest(descriptor), "signatureSha256": digest(signed),
            "producerSummary": summary, "userImage": user_image, "observationImage": observation_image,
            "sourceProducerProfileSha256": source.producer_sha256, "sourceServiceProfileSha256": source.service_sha256,
            "originalInstallerReturnedZero": self.installer_zero, "sameRequestV2Readback": self.installation_readback,
            "originalMountDetached": self.mount_detached, "mountIdentity": list(self.mount_entry["identity"]),
            "groupEndpointMet": True, "originalOuterReturnRequired": True,
            "developerIdPurposeAuthority": "native-parent-and-application-checks-separate",
            "notarizationQualified": False, "gatekeeperQualified": False, "systemServiceExitClaimed": False, "productReady": False}
        self.sha256 = user_image["sha256"]
        self.package_clock()

    def package_diagnostic(self, args, *, capture):
        need(self.package_settled(), "package-io-finality-unknown")
        self.package_clock()
        command = "installer-log-capture" if capture else "installer-log-cursor"
        argv = [sys.executable, "-I", "-S", "-B", str(self.checkout / "desktop/tools/stage_macos_installed.py"), command,
            "--target", self.target, "--package", str(args.package), "--request-id", args.request_id,
            "--expected-source", args.expected_source, "--expected-inventory", args.expected_inventory,
            "--expected-manifest", args.expected_manifest, "--run-id", args.run_id, "--run-attempt", args.run_attempt]
        if capture:
            argv.extend(("--cursor", str(self.work / "installer-log-cursor.json"), "--selected-output", str(self.work / "installer-log-selected.txt")))
        # This is the existing nonroot log action, run by the SAME original
        # process owner. Its joined0/1 result cannot substitute for Installer0;
        # a child's uncertain file close cannot be disguised as our own close.
        result = self.package_call(command, argv, timeout=30, limit=self.stager.LOG_METADATA_BYTES)
        need(result.returncode in (0, 1), "installer-diagnostic-original-status")
        document = self.stager.decode(result.stdout)
        need(type(document) is dict and document.get("authority") == self.stager.LOG_AUTHORITY,
             "installer-diagnostic-original-output")
        self.publish(command + ".json", result.stdout)
        self.publish(command + ".status", (str(result.returncode) + "\n").encode("ascii"))
        self.package_clock()

    def finish(self):
        if self.phase in PYTHON_PHASES:
            self.python_retirement()
        # Close every artifact/output/descendant first. Raised or malformed
        # original calls and any unknown close prevent target deletion.
        for entry in self.entries:
            if entry is not self.work_entry and entry is not self.target_entry:
                self.close(entry)
        ordinary_closes = all(entry["closed"] for entry in self.entries
                              if entry is not self.work_entry and entry is not self.target_entry)
        mount_safe = not self.mount_entered or self.mount_detached
        if (self.target_entry and mount_safe and self.credential_known() and self.credential_active is None
                and not self.signing_mutation_pending and self.stager_io_pending is None and not self.python_mutation_pending
                and ordinary_closes and not self.errors
                and all(call["returned"] and call.get("capturesSettled") is True for call in self.calls)):
            try:
                work_fd, target_fd = self.work_entry["fd"], self.target_entry["fd"]
                need(directory_identity(os.fstat(work_fd)) == directory_identity(self.work.lstat()) == self.work_entry["identity"]
                     and directory_identity(os.fstat(target_fd)) == self.target_entry["identity"]
                     and directory_identity(os.stat(self.target_name, dir_fd=work_fd, follow_symlinks=False)) == self.target_entry["identity"],
                     "cleanup-original-directory-changed")
                if self.phase == "package-install" and self.package_endpoint is not None:
                    self.package_clock()
                if self.phase in PYTHON_PHASES:
                    need(self.python_retiring, "python-retirement-not-admitted")
                    self.python_clock(work=False)
                shutil.rmtree(self.target_name, dir_fd=work_fd)
                if self.phase in PYTHON_PHASES:
                    self.python_clock(work=False)
                if self.phase == "package-install" and self.package_endpoint is not None:
                    self.package_clock()
                try:
                    os.stat(self.target_name, dir_fd=work_fd, follow_symlinks=False)
                except FileNotFoundError:
                    self.receipt["targetRetired"] = True
                else:
                    raise Refused("cleanup-target-remains")
            except BaseException as error:
                self.errors.append({"stage": "target-retirement", "type": type(error).__name__})
        for entry in (self.target_entry, self.work_entry):
            if entry:
                self.close(entry)
        if self.phase == "package-install":
            self.receipt["packageMount"] = {"attachEntered": self.mount_entered, "originalKnown": self.mount_known,
                "detached": self.mount_detached, "retained": self.mount_entered and not self.mount_detached,
                "installerEntered": self.installer_entered, "installerOriginalZero": self.installer_zero,
                "sameRequestV2Readback": self.installation_readback, "systemServiceExitClaimed": False}
        self.receipt["directStagerIOPending"] = self.stager_io_pending
        if self.phase in PYTHON_PHASES and self.python_started is not None:
            try:
                self.python_clock(work=False)
            except BaseException as error:
                self.errors.append({"stage": "python-post-close-deadline", "type": type(error).__name__})
        self.receipt["originalClosesKnown"] = (self.credential_known() and self.credential_active is None and not self.signing_mutation_pending
                                               and self.stager_io_pending is None and not self.python_mutation_pending
                                               and all(entry["closed"] for entry in self.entries))
        self.receipt["cleanupErrors"] = self.errors

    def execute(self, expected=None):
        try:
            if self.phase in PYTHON_PHASES:
                self.python_started = self.python_observed = time.monotonic_ns()
                self.python_clock()
                self.receipt.update(toolchain=None, helperIdentifier=None, pythonIdentifier=PYTHON_IDENTIFIER)
            self.open()
            self.profile_entry = self.source_original(PROFILE, "source-signing-profile", 1024)
            self.service_profile = self.read(self.profile_entry)
            self.signing = self.stager.service_signing_data(self.service_profile)
            self.producer_profile_entry = self.source_original(PRODUCER_PROFILE, "source-producer-profile", 1024)
            self.producer_profile = self.read(self.producer_profile_entry)
            selection = self.stager.packaging_signing_data(self.producer_profile, self.service_profile,
                allow_unconfigured=self.phase not in ("package-install", "python-shipping") + SIGNING_PHASES)
            need((selection is None) == (self.signing is None), "source-signing-profile-pair")
            self.package_sources.extend(((self.profile_entry, self.service_profile), (self.producer_profile_entry, self.producer_profile)))
            if self.phase in PYTHON_PHASES:
                self.python_prepare()
            else:
                need(self.environment.get("MRK_MACOS_PACKAGE_ROLE") in self.stager.PACKAGE_ROLES, "source-package-role")
                release_body = self.image_binding()
                self.package_sources.append((self.release_entry, release_body))
                if self.phase == "prepare":
                    self.prepare()
                elif self.phase == "package-install":
                    self.package_install()
                elif self.phase in SIGNING_PHASES:
                    self.fixed_sign()
                else:
                    self.verify_staged(expected, self.environment.get("MRK_MACOS_RESIDENT_IMAGE_SHA256"))
            need(self.read(self.profile_entry) == self.service_profile
                 and self.read(self.producer_profile_entry) == self.producer_profile, "source-signing-profile-changed")
            if self.phase not in PYTHON_PHASES:
                need(self.read(self.release_entry) == release_body, "source-image-release-changed")
        except BaseException as error:
            self.receipt["failure"] = {"stage": self.stage, "type": type(error).__name__,
                                       "reason": str(error) if type(error) is Refused else "original-operation-refused"}
            if isinstance(error, OSError):
                number = OSError.errno.__get__(error)
                if type(number) is int and 0 < number < 65536:
                    self.receipt["failure"]["errno"] = number
        finally:
            if (self.phase == "package-install" and self.mount_known and not self.mount_detached
                    and not self.installer_entered and self.package_settled()):
                try:
                    self.detach_package_mount()  # Pure pre-Installer refusal only, original attach/close/clock known.
                except BaseException as error:
                    self.errors.append({"stage": "package-mount-retained", "type": type(error).__name__})
            self.finish()
        roles = (PYTHON_ROLES if self.phase in PYTHON_PHASES else
                 self.stager.PACKAGING_CALL_ROLES if self.phase == "package-install" else
                 PREPARE_ROLES if self.phase == "prepare" else
                 (self.phase, self.phase + "-verify") if self.phase in SIGNING_PHASES else (self.phase, self.phase + "-resident-image"))
        self.receipt["passed"] = ("failure" not in self.receipt and not self.errors and self.credential_known()
                                  and not self.credential_failed and self.credential_active is None
                                  and all(row["status"] == 0 for row in self.credential_calls)
                                  and all(all(row[key] is True for key in ("retired", "closed", "searchRestored", "defaultUnchanged"))
                                          for row in self.credential_contexts)
                                  and self.receipt["targetRetired"] and self.receipt["originalClosesKnown"]
                                  and tuple(call["role"] for call in self.calls) == roles
                                  and all(call["returned"] and call.get("capturesSettled") is True
                                       and (call["returncode"] == 0 or self.phase == "package-install"
                                       and call["role"] in ("installer-log-cursor", "installer-log-capture") and call["returncode"] == 1) for call in self.calls)
                                  and self.sha256 is not None
                                  and ((self.phase in PYTHON_PHASES and self.python_signed is not None and self.python_known())
                                       or (self.phase not in PYTHON_PHASES
                                            and (self.phase == "package-install" or self.resident_image_sha256 is not None
                                                 or self.phase in SIGNING_PHASES and self.fixed_sign_complete)
                                           and self.image_source is not None and self.image_release is not None
                                           and (self.phase != "prepare" or self.entry_sha256 is not None
                                                and self.desktop_facade_sha256 is not None))))
        # This receipt remains provisional until its own write/readback/close
        # and the original Python caller's zero exit. No output digest on error.
        if self.phase == "package-install" and self.receipt["passed"]:
            self.package_clock()
            need(self.installer_zero and self.installation_readback and self.mount_detached, "package-finality-incomplete")
        if self.phase in PYTHON_PHASES and self.receipt["passed"]:
            self.python_clock(work=False)
            if self.phase == "python-shipping":
                self.python_publish_final("python3", self.python_signed, 0o555)
                capsule = (json.dumps(self.python_capsule(), sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
                self.python_publish_final("python-signed-receipt.json", capsule, 0o444)
        self.publish_receipt()
        if self.phase in PYTHON_PHASES and self.receipt["passed"]:
            self.python_clock(work=False)
        if self.phase == "package-install" and self.receipt["passed"]:
            self.package_clock()  # Receipt write/readback/closes are inside the SAME original group.
        need(self.receipt["passed"], "helper-package-incomplete")
        return self.sha256

    def publish_receipt(self):
        need(self.work_entry is not None and self.work_entry.get("identity") is not None, "receipt-work-unavailable")
        body = (json.dumps(self.receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        need(len(body) <= 16384, "receipt-bound")
        if self.phase in PYTHON_PHASES:
            self.python_publish_final("android-helper-" + self.phase + ".json", body, 0o600)
            return
        directory = os.open(self.work, READ_FLAGS | os.O_DIRECTORY)
        try:
            need(directory_identity(os.fstat(directory)) == directory_identity(self.work.lstat()) == self.work_entry["identity"], "receipt-work-changed")
            fd = os.open("android-helper-" + self.phase + ".json", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
            try:
                need(os.write(fd, body) == len(body), "receipt-short-write")
                os.fsync(fd)
                need(os.pread(fd, len(body) + 1, 0) == body, "receipt-readback")
            finally:
                os.close(fd)
        finally:
            os.close(directory)


def load_data(checkout, filename, name):
    spec = importlib.util.spec_from_file_location(name, checkout / "desktop/tools" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def admit(environment, *, target=ARM_TARGET, phase=None):
    machine, runner_arch, _release_input = build_profile(target)
    need(sys.platform == "darwin" and sys.maxsize == 2 ** 63 - 1, "hosted-native-platform")
    host = os.uname()  # One original observation; an artifact cannot select a host.
    need(host.machine == machine and os.getuid() != 0
         and os.getuid() == os.geteuid() and os.getgid() == os.getegid(), "hosted-native-platform")
    need(Path(__file__).absolute() == CHECKOUT / "desktop/tools/macos_android_helper_package.py", "fixed-source-driver")
    ref = environment.get("GITHUB_REF")
    python_phase = phase in PYTHON_PHASES
    if python_phase:
        need(ref == "refs/heads/verify/desktop-macos-python-runtime-signing-" + phase[len("python-"):],
             "closed-python-purpose-ref")
    workflow = ("desktop-macos-python-runtime-signing.yml" if python_phase else
                "desktop-macos-aqua.yml" if ref == "refs/heads/verify/desktop-macos-aqua" else
                "desktop-macos-installed.yml" if ref in ("refs/heads/verify/desktop-macos-installed", "refs/heads/verify/desktop-macos-preview") else None)
    need(workflow is not None, "closed-workflow-route")
    sha = environment.get("GITHUB_SHA", "")
    required = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": runner_arch,
                "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit",
                "GITHUB_WORKSPACE": str(CHECKOUT), "GITHUB_WORKFLOW_SHA": sha,
                "GITHUB_WORKFLOW_REF": "Apdelrahman1911/mobile-release-kit/.github/workflows/" + workflow + "@" + ref,
                "MRK_EXPECTED_SHA": sha, "MRK_MACOS_INSTALL_SOURCE_COMMIT": sha,
                "MRK_MACOS_PACKAGE_ROLE": "installed-shell-observation" if workflow == "desktop-macos-aqua.yml" else "ordinary-image",
                "RUSTUP_TOOLCHAIN": "1.98.1", "DEVELOPER_DIR": "/Library/Developer/CommandLineTools", "MACOSX_DEPLOYMENT_TARGET": "26.0"}
    if python_phase:
        del required["MRK_MACOS_PACKAGE_ROLE"]
        del required["RUSTUP_TOOLCHAIN"]
        need(environment.get("MRK_MACOS_PACKAGE_ROLE") is None, "python-no-install-package-role")
    need(re.fullmatch(r"[0-9a-f]{40}", sha) and sha != "0" * 40
         and all(environment.get(k) == v for k, v in required.items()), "hosted-source-bindings")
    need(all(re.fullmatch(r"[1-9][0-9]{0,19}", environment.get(key, "")) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "run-identity")
    if workflow == "desktop-macos-aqua.yml":
        need(environment.get("MRK_MACOS_AQUA_SCOPE") in PACKAGE_SCOPES, "full-package-scope-only")
    work = Path(environment.get("MRK_MACOS_WORK", ""))
    prefix = "mrk-macos-python-signing" if python_phase else "mrk-macos-aqua" if workflow == "desktop-macos-aqua.yml" else "mrk-macos-installed"
    need(work.parent == WORK_PARENT and re.fullmatch(re.escape(prefix) + r"\.[A-Za-z0-9]{8}", work.name), "owned-work-route")
    return work


def main():
    try:
        phase, target = entrypoint(sys.argv)
        work = admit(os.environ, target=target, phase=phase)
        stager = load_data(CHECKOUT, "stage_macos_installed.py", "_mrk_android_helper_stager")
        need(stager.read(CHECKOUT / ".git/HEAD", 64) == (os.environ["GITHUB_SHA"] + "\n").encode("ascii"), "exact-detached-checkout")
        stager.packaging_signing_data(stager.read(CHECKOUT / PRODUCER_PROFILE, 1024), stager.read(CHECKOUT / PROFILE, 1024),
                                     allow_unconfigured=phase not in ("package-install", "python-shipping") + SIGNING_PHASES)
        qualification = load_data(CHECKOUT, "macos_aqua_qualification.py", "_mrk_android_helper_owner_loader")
        owner = qualification.load_owner(CHECKOUT)
        operation = Operation(owner, CHECKOUT, work, phase, os.environ, stager, target=target)
        result = operation.execute(os.environ.get("MRK_MACOS_ANDROID_HELPER_SHA256"))
        if phase == "prepare":
            print("sha256=" + result, flush=True)
            print("entry-sha256=" + operation.entry_sha256, flush=True)
            print("resident-image-sha256=" + operation.resident_image_sha256, flush=True)
            print("desktop-facade-sha256=" + operation.desktop_facade_sha256, flush=True)
            print("image-release-id=" + operation.image_release, flush=True)
        return 0
    except BaseException:
        # Native/owner messages can contain local paths. Exact bounded command
        # outputs and typed failures are retained in the private work evidence.
        print("Fixed Android helper packaging refused; see its bounded work receipt.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
