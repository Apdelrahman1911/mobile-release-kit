#!/usr/bin/env python3
"""Fixed engineering Android-helper packaging, never service registration.

The only entries are prepare/verify-before/verify-after. Every new compiler or
codesign call uses the existing original process owner. Import is DATA-only;
the hosted main alone loads that owner. No signer, command or path is supplied
by a caller. The deliberately unconfigured publisher profile is mandatory.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
WORK_PARENT = Path("/Users/runner/work/_temp")
HELPER = "mrk-android-register"
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
    "project-recovery-pending",
)
PHASES = ("prepare", "verify-before", "verify-after")
MAX_HELPER = 32 * 1024 * 1024
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


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


def artifact(messages, checkout, target):
    """The actual separate release graph, not a plausible executable filename."""
    need(type(messages) is bytes and 0 < len(messages) <= 4 * 1024 * 1024, "compiler-bound")
    rows = [json.loads(line) for line in messages.splitlines()]
    need(len(rows) <= 8192 and all(type(row) is dict for row in rows), "compiler-rows")
    need([r.get("success") for r in rows if r.get("reason") == "build-finished"] == [True], "compiler-finish")
    executables = [r for r in rows if r.get("reason") == "compiler-artifact" and r.get("executable") is not None]
    need(len(executables) == 1, "one-helper-executable")
    row = executables[0]
    source = checkout / WORKSPACE
    binary = target / "aarch64-apple-darwin/release" / HELPER
    need(row.get("package_id") == "path+" + source.as_uri() + "#" + HELPER + "@0.1.0"
         and row.get("manifest_path") == str(source / "Cargo.toml")
         and row.get("features") == [] and row.get("executable") == str(binary)
         and row.get("filenames") == [str(binary)], "helper-package-artifact")
    target_row, profile = row.get("target", {}), row.get("profile", {})
    need(target_row.get("name") == HELPER and target_row.get("kind") == ["bin"]
         and target_row.get("crate_types") == ["bin"]
         and target_row.get("src_path") == str(source / "src/main.rs")
         and target_row.get("edition") == "2021"
         and profile.get("test") is False and profile.get("debug_assertions") is False
         and profile.get("opt_level") == "3", "helper-release-graph")
    for directory, package, name, features in (
        ("desktop/src-tauri", "mobile-release-kit-desktop", "mobile_release_desktop", ["macos-android-registration-helper"]),
        ("desktop/native/macos-installed-native", "mrk-macos-installed-native", "mrk_macos_installed_native", ["android-registration-helper", "default"]),
    ):
        selected = [r for r in rows if r.get("reason") == "compiler-artifact"
                    and r.get("target", {}).get("name") == name
                    and r.get("target", {}).get("kind") == ["lib"]]
        need(len(selected) == 1, "helper-one-library")
        library = selected[0]
        need(library.get("package_id") == "path+" + (checkout / directory).as_uri() + "#" + package + "@0.1.0"
             and library.get("manifest_path") == str(checkout / directory / "Cargo.toml")
             and library.get("features") == features
             and library["target"].get("src_path") == str(checkout / directory / "src/lib.rs")
             and library.get("profile", {}).get("test") is False, "helper-separate-library-features")
    return binary


def build_environment(environment, work):
    # No inherited Rust flags/wrappers, service selectors, credential variables,
    # private signing configuration or arbitrary compiler/profile switches.
    selected = {key: environment[key] for key in ("PATH", "HOME", "DEVELOPER_DIR", "MACOSX_DEPLOYMENT_TARGET")}
    for key in ("CARGO_HOME", "RUSTUP_HOME"):
        if key in environment:
            selected[key] = environment[key]
    selected.update(LANG="C", LC_ALL="C", TZ="UTC", RUSTUP_TOOLCHAIN="1.98.1",
                    CARGO_INCREMENTAL="0", CARGO_TARGET_DIR=str(work / "android-helper-target"),
                    TMPDIR=str(work / "android-helper-target/tmp"),
                    MRK_MACOS_INSTALL_SOURCE_COMMIT=environment["GITHUB_SHA"])
    return selected


class Operation:
    """Custody for this one fixed packaging operation and its finite outputs."""

    def __init__(self, owner, checkout, work, phase, environment, stager):
        need(phase in PHASES, "closed-phase")
        self.owner, self.checkout, self.work = owner, checkout, work
        self.phase, self.environment, self.stager = phase, environment, stager
        self.entries, self.calls, self.errors = [], [], []
        self.work_entry = self.target_entry = None
        self.profile_entry = self.source_entry = None
        self.target_name = "android-helper-target" if phase == "prepare" else "android-helper-" + phase
        self.stage, self.sha256 = "owned-directory-admission", None
        self.receipt = {"schemaVersion": 1, "phase": phase, "source": environment["GITHUB_SHA"],
                        "workflowSource": environment["GITHUB_WORKFLOW_SHA"],
                        "workflow": environment["GITHUB_WORKFLOW_REF"], "runId": environment["GITHUB_RUN_ID"],
                        "runAttempt": environment["GITHUB_RUN_ATTEMPT"], "toolchain": "1.98.1",
                        "helperIdentifier": IDENTIFIER, "originalCalls": self.calls,
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

    def directory(self, parent, name, role):
        fd = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=parent["fd"])
        entry = self.register(fd, role, "directory", parent["fd"], name)
        entry["identity"] = directory_identity(os.fstat(fd))
        need(directory_identity(os.stat(name, dir_fd=parent["fd"], follow_symlinks=False)) == entry["identity"], "directory-original-changed")
        return entry

    def descend(self, parent, names):
        for name in names:
            parent = self.directory(parent, name, "directory-" + name)
        return parent

    def original(self, parent, name, role, limit, modes, *, alias=False):
        fd = os.open(name, READ_FLAGS, dir_fd=parent["fd"])
        entry = self.register(fd, role, "file", parent["fd"], name)
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
        need(signature(os.fstat(entry["fd"])) == entry["identity"]
             and signature(os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False)) == entry["identity"], "file-original-changed")
        size = entry["identity"][6]
        value = os.pread(entry["fd"], size + 1, 0)
        need(len(value) == size and signature(os.fstat(entry["fd"])) == entry["identity"]
             and signature(os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False)) == entry["identity"], "file-original-read-changed")
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
        record = {"role": role, "entered": True, "returned": False}
        self.calls.append(record)
        try:
            result = self.owner.run_owned(argv, environ=environment, cwd=cwd, timeout=timeout,
                                          capture=True, text=False, output_limit=limit)
        except BaseException as error:
            for field in ("dispatched", "contained", "cleanup_complete"):
                value = getattr(error, field, None)
                record[field] = value if type(value) is bool else None
            raise
        need(type(result) is subprocess.CompletedProcess and type(result.returncode) is int
             and type(result.args) in (list, tuple) and tuple(result.args) == tuple(argv)
             and type(result.stdout) is bytes and type(result.stderr) is bytes
             and len(result.stdout) + len(result.stderr) <= limit, "original-return-contract")
        record.update(returned=True, returncode=result.returncode,
                      stdoutSha256=digest(result.stdout), stderrSha256=digest(result.stderr))
        prefix = "android-helper-" + role
        self.publish(prefix + (".jsonl" if role == "build" else ".stdout"), result.stdout)
        self.publish(prefix + ".stderr", result.stderr)
        self.publish(prefix + ".status", (str(result.returncode) + "\n").encode("ascii"))
        need(result.returncode == 0, "original-nonzero-" + role)
        return result

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

    def prepare(self):
        self.stage = "separate-helper-compiler"
        result = self.call("build", ["cargo", "build", "--manifest-path", str(self.checkout / WORKSPACE / "Cargo.toml"),
                           "--locked", "--release", "--jobs", "1", "--target", "aarch64-apple-darwin",
                           "--bin", HELPER, "--message-format=json"],
                           build_environment(self.environment, self.work), cwd=self.checkout / WORKSPACE,
                           timeout=480, limit=4 * 1024 * 1024)
        artifact(result.stdout, self.checkout, self.work / self.target_name)
        self.stage = "compiler-original-copy"
        release = self.descend(self.target_entry, ("aarch64-apple-darwin", "release"))
        original = self.original(release, HELPER, "compiler-artifact", MAX_HELPER, (0o700, 0o755), alias=True)
        if original["identity"][3] == 2:
            deps = self.directory(release, "deps", "compiler-deps")
            names = os.listdir(deps["fd"])
            need(len(names) <= 8192, "compiler-alias-directory-bound")
            aliases = [name for name in names if re.fullmatch(r"mrk_android_register-[0-9a-f]{16}", name)]
            need(len(aliases) == 1, "one-compiler-alias")
            alias = self.original(deps, aliases[0], "compiler-alias", MAX_HELPER, (0o700, 0o755), alias=True)
            need(alias["identity"] == original["identity"], "compiler-alias-original")
        body = self.read(original)
        self.stager.macho(body, system_only=True)
        self.publish(HELPER, body, mode=0o755)  # nlink1 copy; never sign Cargo's alias.
        need(self.read(original) == body, "compiler-original-copy-changed")
        for entry in self.entries:
            if entry["role"] in ("compiler-artifact", "compiler-alias"):
                self.close(entry)
                need(entry["closed"], "compiler-artifact-close-unknown")
        self.stage = "helper-ad-hoc-signing"
        self.call("sign", ["/usr/bin/codesign", "--force", "--sign", "-", "--identifier", IDENTIFIER,
                           "--options", "runtime", "--entitlements", str(self.checkout / "desktop/packaging/macos-empty-entitlements.plist"),
                           "--timestamp=none", str(self.work / HELPER)],
                  self.native_environment(), cwd=self.work, timeout=30, limit=65536)
        # codesign may replace the inode. Only its actual completed return
        # allows this new post-sign original to be acquired and retained.
        self.stage = "signed-helper-original"
        signed = self.original(self.work_entry, HELPER, "signed-helper", MAX_HELPER, (0o755,))
        body = self.read(signed)
        self.stager.macho(body, system_only=True)
        self.strict_verify(signed, body, "verify-signed", self.work / HELPER)
        self.sha256 = digest(body)
        self.receipt.update(helperSha256=self.sha256, helperBytes=len(body), helperOriginal=signed["identity"],
                            signing="ad-hoc-fixed-identifier-runtime-empty-entitlements-strictly-verified")

    def strict_verify(self, original, body, role, path):
        self.stage = role
        result = self.call(role, ["/usr/bin/codesign", "--verify", "--strict", str(path)],
                           self.native_environment(), cwd=self.work, timeout=30, limit=65536)
        need(not result.stdout and not result.stderr and self.read(original) == body, "strict-original-verification")

    def verify_staged(self, expected):
        need(type(expected) is str and re.fullmatch(r"[0-9a-f]{64}", expected), "expected-helper-digest")
        self.stage = "staged-helper-original"
        contents = self.descend(self.work_entry, ("app", "Mobile Release Kit.app", "Contents"))
        helpers = self.directory(contents, "Helpers", "staged-helpers")
        original = self.original(helpers, HELPER, "staged-helper", MAX_HELPER, (0o555,))
        body = self.read(original)
        need(digest(body) == expected, "staged-helper-signature-bytes-changed")
        self.stager.macho(body, system_only=True)
        daemons = self.descend(contents, ("Library", "LaunchDaemons"))
        plist = self.original(daemons, IDENTIFIER + ".plist", "staged-service-plist", 4096, (0o444, 0o644))
        source_plist = self.source_original("desktop/macos-installed-inputs/" + IDENTIFIER + ".plist", "source-service-plist", 4096)
        expected_plist = self.read(source_plist)
        parsed = self.stager.plistlib.loads(expected_plist)
        need(parsed == {"Label": IDENTIFIER, "BundleProgram": "Contents/Helpers/" + HELPER,
                        "MachServices": {IDENTIFIER: True}} and parsed["MachServices"][IDENTIFIER] is True,
             "source-service-plist")
        need(self.read(plist) == expected_plist, "staged-service-plist")
        self.strict_verify(original, body, self.phase, self.work / "app/Mobile Release Kit.app/Contents/Helpers" / HELPER)
        need(self.read(plist) == self.read(source_plist) == expected_plist, "staged-service-plist-changed")
        self.sha256 = expected
        self.receipt.update(helperSha256=expected, helperBytes=len(body), helperOriginal=original["identity"])

    def finish(self):
        # Close every artifact/output/descendant first. Raised or malformed
        # original calls and any unknown close prevent target deletion.
        for entry in self.entries:
            if entry is not self.work_entry and entry is not self.target_entry:
                self.close(entry)
        ordinary_closes = all(entry["closed"] for entry in self.entries
                              if entry is not self.work_entry and entry is not self.target_entry)
        if self.target_entry and all(call["returned"] for call in self.calls) and ordinary_closes and not self.errors:
            try:
                work_fd, target_fd = self.work_entry["fd"], self.target_entry["fd"]
                need(directory_identity(os.fstat(work_fd)) == directory_identity(self.work.lstat()) == self.work_entry["identity"]
                     and directory_identity(os.fstat(target_fd)) == self.target_entry["identity"]
                     and directory_identity(os.stat(self.target_name, dir_fd=work_fd, follow_symlinks=False)) == self.target_entry["identity"],
                     "cleanup-original-directory-changed")
                shutil.rmtree(self.target_name, dir_fd=work_fd)
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
        self.receipt["originalClosesKnown"] = all(entry["closed"] for entry in self.entries)
        self.receipt["cleanupErrors"] = self.errors

    def execute(self, expected=None):
        try:
            self.open()
            self.profile_entry = self.source_original(PROFILE, "source-signing-profile", 1024)
            need(self.read(self.profile_entry) == UNCONFIGURED_PROFILE, "engineering-profile-only")
            if self.phase == "prepare":
                self.prepare()
            else:
                self.verify_staged(expected)
            need(self.read(self.profile_entry) == UNCONFIGURED_PROFILE, "engineering-profile-changed")
        except BaseException as error:
            self.receipt["failure"] = {"stage": self.stage, "type": type(error).__name__,
                                       "reason": str(error) if type(error) is Refused else "original-operation-refused"}
        finally:
            self.finish()
        self.receipt["passed"] = ("failure" not in self.receipt and not self.errors
                                  and self.receipt["targetRetired"] and self.receipt["originalClosesKnown"]
                                  and len(self.calls) == (3 if self.phase == "prepare" else 1)
                                  and all(call["returned"] and call["returncode"] == 0 for call in self.calls)
                                  and self.sha256 is not None)
        # This receipt remains provisional until its own write/readback/close
        # and the original Python caller's zero exit. No output digest on error.
        self.publish_receipt()
        need(self.receipt["passed"], "helper-package-incomplete")
        return self.sha256

    def publish_receipt(self):
        need(self.work_entry is not None and self.work_entry.get("identity") is not None, "receipt-work-unavailable")
        body = (json.dumps(self.receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        need(len(body) <= 16384, "receipt-bound")
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


def admit(environment):
    need(sys.platform == "darwin" and os.uname().machine == "arm64" and os.getuid() != 0
         and os.getuid() == os.geteuid() and os.getgid() == os.getegid(), "hosted-native-platform")
    need(Path(__file__).absolute() == CHECKOUT / "desktop/tools/macos_android_helper_package.py", "fixed-source-driver")
    ref = environment.get("GITHUB_REF")
    workflow = ("desktop-macos-aqua.yml" if ref == "refs/heads/verify/desktop-macos-aqua" else
                "desktop-macos-installed.yml" if ref in ("refs/heads/verify/desktop-macos-installed", "refs/heads/verify/desktop-macos-preview") else None)
    need(workflow is not None, "closed-workflow-route")
    sha = environment.get("GITHUB_SHA", "")
    required = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
                "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit",
                "GITHUB_WORKSPACE": str(CHECKOUT), "GITHUB_WORKFLOW_SHA": sha,
                "GITHUB_WORKFLOW_REF": "Apdelrahman1911/mobile-release-kit/.github/workflows/" + workflow + "@" + ref,
                "MRK_EXPECTED_SHA": sha, "MRK_MACOS_INSTALL_SOURCE_COMMIT": sha,
                "RUSTUP_TOOLCHAIN": "1.98.1", "DEVELOPER_DIR": "/Library/Developer/CommandLineTools", "MACOSX_DEPLOYMENT_TARGET": "26.0"}
    need(re.fullmatch(r"[0-9a-f]{40}", sha) and all(environment.get(k) == v for k, v in required.items()), "hosted-source-bindings")
    need(all(re.fullmatch(r"[1-9][0-9]{0,19}", environment.get(key, "")) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "run-identity")
    if workflow == "desktop-macos-aqua.yml":
        need(environment.get("MRK_MACOS_AQUA_SCOPE") in PACKAGE_SCOPES, "full-package-scope-only")
    work = Path(environment.get("MRK_MACOS_WORK", ""))
    prefix = "mrk-macos-aqua" if workflow == "desktop-macos-aqua.yml" else "mrk-macos-installed"
    need(work.parent == WORK_PARENT and re.fullmatch(re.escape(prefix) + r"\.[A-Za-z0-9]{8}", work.name), "owned-work-route")
    return work


def main():
    try:
        need(len(sys.argv) == 2 and sys.argv[1] in PHASES, "closed-entrypoint")
        work = admit(os.environ)
        stager = load_data(CHECKOUT, "stage_macos_installed.py", "_mrk_android_helper_stager")
        need(stager.read(CHECKOUT / ".git/HEAD", 64) == (os.environ["GITHUB_SHA"] + "\n").encode("ascii"), "exact-detached-checkout")
        need(stager.read(CHECKOUT / PROFILE, 1024) == UNCONFIGURED_PROFILE, "engineering-profile-only")
        qualification = load_data(CHECKOUT, "macos_aqua_qualification.py", "_mrk_android_helper_owner_loader")
        owner = qualification.load_owner(CHECKOUT)
        operation = Operation(owner, CHECKOUT, work, sys.argv[1], os.environ, stager)
        result = operation.execute(os.environ.get("MRK_MACOS_ANDROID_HELPER_SHA256"))
        if sys.argv[1] == "prepare":
            print("sha256=" + result, flush=True)
        return 0
    except BaseException:
        # Native/owner messages can contain local paths. Exact bounded command
        # outputs and typed failures are retained in the private work evidence.
        print("Fixed Android helper packaging refused; see its bounded work receipt.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
