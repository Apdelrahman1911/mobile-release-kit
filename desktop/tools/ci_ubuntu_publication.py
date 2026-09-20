"""One fixed hosted publisher compiler/helper check; never an installation.

Reuses the current core's original command owner. No application, payload,
administrator operation, Store API or production qualification is invoked.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

SOURCE = Path(__file__).absolute().parents[2]


def local(name):
    spec = importlib.util.spec_from_file_location("_publisher_" + name, SOURCE / "desktop/tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


D = local("conventional_runtime_data")
C = local("ci_foundation")
REF = "refs/heads/verify/desktop-ubuntu-publication"
WORKFLOW = ".github/workflows/desktop-ubuntu-publication.yml"
FEATURES = ["ubuntu-runtime-publisher"]
TARGET = "x86_64-unknown-linux-gnu"
PREFIX = "runtime_publication::tests::"
TESTS = tuple(sorted(PREFIX + name for name in (
    "release_inputs_are_fixed_and_lowercase", "root_status_requires_all_initial_root_ids",
    "complete_membership_requires_exact_manifest_roster",
    "helper_fresh_copy_has_independent_inode_and_bytes", "helper_source_size_digest_and_readback_refuse",
    "helper_noreplace_preserves_existing_names", "helper_lost_close_receipt_blocks_publication",
    "helper_stage_sync_failure_prevents_rename", "helper_parent_sync_failure_preserves_published_name",
    "helper_extra_destination_member_is_rejected", "helper_source_directory_drift_is_rejected",
)))
LOG_LIMIT = 16 << 20
LOG_TOTAL = 64 << 20
MAX_BINARY = 512 << 20


def route(env):
    D.need(env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
           and env.get("RUNNER_OS") == "Linux" and env.get("RUNNER_ARCH") == "X64"
           and env.get("GITHUB_EVENT_NAME") == "push" and env.get("GITHUB_REF") == REF
           and env.get("MRK_UBUNTU_PUBLICATION_VERIFY") == "1", "Wrong fixed publisher verification route")
    sha = env.get("GITHUB_SHA", "")
    D.need(re.fullmatch(r"[0-9a-f]{40}", sha) is not None and sha != "0" * 40
           and env.get("MRK_PUSH_EVENT_AFTER") == sha, "Publisher event source differs")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        D.need(re.fullmatch(r"[1-9][0-9]{0,19}", env.get(key, "")) is not None, "Invalid original run identity")
    D.need(env.get("GITHUB_REPOSITORY") == "Apdelrahman1911/mobile-release-kit", "Different repository")
    return sha


def compile_argv(cargo, source, target, *, library):
    return [cargo, "test" if library else "build", "--locked", "--offline", "--jobs", "1",
            "--no-default-features", "--features", FEATURES[0], "--target", TARGET,
            "--manifest-path", str(source / "desktop/src-tauri/Cargo.toml"),
            "--target-dir", str(target), *( ["--lib", "--no-run"] if library else ["--release", "--bin", "mrk-runtime-publish"] ),
            "--message-format=json"]


def compiled_artifact(raw, source, target_root, *, library):
    """Select only an original fresh Cargo result for this fixed profile."""
    D.need(type(raw) is bytes and 0 < len(raw) <= LOG_LIMIT, "Compiler message bound")
    executable, finished = None, False
    for line in raw.splitlines():
        D.need(not finished, "Compiler data follows its final result")
        row = C.bounded_json(line, 1 << 20)
        D.need(type(row) is dict and type(row.get("reason")) is str, "Invalid original compiler message")
        if row["reason"] == "compiler-artifact" and row.get("executable") is not None:
            kind, name, filename = (("lib", "mobile_release_desktop", "lib.rs") if library
                                    else ("bin", "mrk-runtime-publish", "bin/runtime_publish.rs"))
            target, profile = row.get("target"), row.get("profile")
            D.need(executable is None and type(target) is dict and target.get("kind") == [kind]
                   and target.get("name") == name and target.get("src_path") == str(source / "desktop/src-tauri/src" / filename)
                   and row.get("manifest_path") == str(source / "desktop/src-tauri/Cargo.toml")
                   and row.get("features") == FEATURES and row.get("fresh") is False
                   and type(profile) is dict and profile.get("test") is library
                   and profile.get("debug_assertions") is library
                   and profile.get("opt_level") == ("0" if library else "3"), "Different publisher compiler profile")
            value = row["executable"]
            if library:
                executable = C.github_executable_path(value, target_root=target_root)
            else:
                D.need(value == str(target_root / TARGET / "release/mrk-runtime-publish"), "Publisher binary path differs")
                executable = Path(value)
        elif row["reason"] == "build-finished":
            D.need(row.get("success") is True, "Original publisher compiler failed")
            finished = True
    D.need(finished and executable is not None, "Compiler did not yield exactly one fresh artifact")
    return executable


def test_result(stdout, stderr):
    D.need(type(stdout) is bytes and type(stderr) is bytes and len(stdout) <= 2 << 20
           and stderr == b"", "Publisher test capture differs")
    lines = [line for line in stdout.decode("ascii").splitlines() if line]
    D.need(len(lines) == len(TESTS) + 2 and lines[0] == f"running {len(TESTS)} tests"
           and lines[1:-1] == [f"test {name} ... ok" for name in TESTS]
           and re.fullmatch(r"test result: ok\. 11 passed; 0 failed; 0 ignored; 0 measured; "
                            r"[0-9]+ filtered out; finished in [0-9]+\.[0-9]+s", lines[-1]) is not None,
           "Exact publisher test roster did not pass once")


def directory_identity(path):
    D.directory(path)
    value = path.lstat()
    D.need(value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700, "Private task directory changed")
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def artifact_record(path, *, copy_to=None):
    """Cargo may hardlink its own outputs. This is NOT runtime-file admission.

    Keep the original identity/count stable while reading; an exported copy is
    a fresh single-link file whose bytes are independently read back.
    """
    D.directory(path.parent)
    before = path.lstat()
    D.need(stat.S_ISREG(before.st_mode) and before.st_nlink >= 1 and before.st_uid == os.geteuid()
           and before.st_mode & 0o7022 == 0 and before.st_mode & stat.S_IXUSR
           and 0 < before.st_size <= MAX_BINARY, "Unexpected compiler output identity")
    identity = (*D.state(before), before.st_uid, before.st_gid)
    original = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        stream = os.fdopen(original, "rb")
    except BaseException:
        os.close(original)
        raise
    writer = None
    try:
        with stream as source:
            opened = os.fstat(source.fileno())
            D.need((*D.state(opened), opened.st_uid, opened.st_gid) == identity, "Compiler output changed before read")
            if copy_to is not None:
                writer = copy_to.open("xb")
            digest, size = hashlib.sha256(), 0
            for block in iter(lambda: source.read(64 << 10), b""):
                size += len(block)
                D.need(size <= before.st_size, "Compiler output grew")
                digest.update(block)
                if writer is not None:
                    D.need(writer.write(block) == len(block), "Short compiler output copy")
            D.need(size == before.st_size and D.state(os.fstat(source.fileno())) == D.state(before), "Compiler output changed")
            if writer is not None:
                writer.flush()
                os.fchmod(writer.fileno(), 0o555)
                os.fsync(writer.fileno())
    finally:
        if writer is not None:
            writer.close()
    after = path.lstat()
    D.need((*D.state(after), after.st_uid, after.st_gid) == identity, "Compiler output identity changed after close")
    result = {"path": str(path), "size": size, "sha256": digest.hexdigest(), "identity": list(identity)}
    if copy_to is not None:
        D.bound(copy_to, {"path": copy_to.name, "size": size, "sha256": result["sha256"]})
    return result


class Check:
    def __init__(self, root, owner):
        self.root, self.owner = root, owner
        self.end = time.monotonic() + 720
        self.retained = 0
        self.phase = "admission"
        self.commands = []
        self.failed = False

    def command(self, label, argv, env, cwd, *, timeout=600, codes=(0,), limit=LOG_LIMIT):
        D.need(not self.failed, "Prior command failed; no further launch")
        self.phase = label
        self.failed = True
        remaining = min(timeout, int(self.end - time.monotonic()))
        D.need(remaining >= 1, "Common publisher-check endpoint expired")
        print("Publisher check: " + label, flush=True)
        result = self.owner(argv, environ=env, cwd=cwd, timeout=remaining, capture=True, text=False, output_limit=limit)
        D.need(type(result) is subprocess.CompletedProcess and result.args == argv
               and type(result.returncode) is int and type(result.stdout) is bytes and type(result.stderr) is bytes,
               "Original command result incomplete")
        size = len(result.stdout) + len(result.stderr)
        D.need(size <= limit and self.retained + size <= LOG_TOTAL, "Original command capture bound")
        self.retained += size
        for suffix, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            D.write(self.root / "public" / (label + "." + suffix), raw)
        self.commands.append({"phase": label, "argv": argv, "exitCode": result.returncode,
                              "timeoutSeconds": remaining, "ordinaryOwnerReturned": True})
        D.need(result.returncode in codes and time.monotonic() < self.end, "Original command failed or finished late: " + label)
        self.failed = False
        return result


def verify():
    started = time.monotonic()
    D.need(len(sys.argv) == 1, "Publisher check takes no arguments")
    sha = route(os.environ)
    C.conventional_host(D)
    D.need(os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0, "Nonroot publisher checks required")
    source, temporary = Path(os.environ["GITHUB_WORKSPACE"]), Path(os.environ["RUNNER_TEMP"])
    for path in (source, temporary):
        D.directory(path)
        D.need(path.resolve(strict=True) == path, "Noncanonical hosted directory")
    D.need(source == SOURCE, "Publisher checkout source differs")
    C.no_cargo_configuration((source / "desktop/src-tauri", source / "desktop", source, *source.parents,
                              temporary, *temporary.parents))
    os.umask(0o077)
    root = temporary / ("mrk-desktop-ubuntu-publisher-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"])
    root.mkdir(mode=0o700)
    for name in ("work", "public", "cases"):
        (root / name).mkdir(mode=0o700)
    work = root / "work"
    for name in ("home", "tmp", "cargo", "rustup", "target"):
        (work / name).mkdir(mode=0o700)
    D.write(work / "gitconfig-empty", b"")
    original_root, original_work = directory_identity(root), directory_identity(work)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write("root=" + str(root) + "\n")

    # Source is the exact credential-free checkout; no installed package/project
    # Python import, command-evidence adapter or account execution scope is used.
    sys.path.insert(0, str(source / "src"))
    from mobile_release.owned_process import run_owned
    check = Check(root, run_owned)
    check.end = started + 720
    environment = C.clean_environment(work)
    git, rustup = shutil.which("git"), shutil.which("rustup")
    D.need(all(value is not None and Path(value).is_absolute() for value in (git, rustup)), "Hosted compiler/source tools missing")

    def source_check(label):
        C.conventional_host(D)
        D.need(directory_identity(root) == original_root and directory_identity(work) == original_work, "Task root changed")
        C.no_cargo_configuration((work, root, *root.parents, source / "desktop/src-tauri", source / "desktop", source, *source.parents,
                                  work / "cargo", work / "home"))
        D.need(all(not (work / "cargo" / name).exists() and not (work / "cargo" / name).is_symlink()
                   for name in ("config", "config.toml")), "Unexpected private Cargo configuration")
        D.need(check.command(label + "-head", [git, "rev-parse", "HEAD"], environment, source, timeout=15).stdout.strip() == sha.encode(),
               "Publisher source commit changed")
        status = check.command(label + "-status", [git, "status", "--porcelain=v1", "--untracked-files=all", "--ignored"],
                               environment, source, timeout=15)
        D.need(status.stdout == b"", "Publisher source has modified, untracked or ignored additions")

    try:
        source_check("before")
        tree = check.command("source-tree", [git, "rev-parse", "HEAD^{tree}"], environment, source, timeout=15).stdout.strip().decode("ascii")
        D.need(re.fullmatch(r"[0-9a-f]{40}", tree) is not None, "Invalid source tree")
        kernel = os.uname()
        metadata = {"sourceSha": sha, "sourceTree": tree, "workflow": D.file_record(source / WORKFLOW, 64 << 10),
                    "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
                    "imageOS": os.environ["ImageOS"], "imageVersion": os.environ["ImageVersion"],
                    "kernel": {key: getattr(kernel, key) for key in ("sysname", "machine", "release", "version")},
                    "nativeQualification": False, "features": FEATURES, "rust": C.RUST}
        D.write(root / "public/source.json", D.canonical(metadata))
        # Current-job package metadata, not invented historical H evidence.
        D.need(re.fullmatch(r"[0-9][0-9A-Za-z.+-]{0,127}", kernel.release) is not None, "Kernel package query name differs")
        try:
            with Path("/proc/version_signature").open("rb") as signature:
                raw = signature.read(4097)
        except (FileNotFoundError, PermissionError) as error:
            D.write(root / "public/version-signature-unavailable.json", D.canonical({"reason": type(error).__name__}))
        else:
            D.need(0 < len(raw) <= 4096, "Version signature metadata bound")
            D.write(root / "public/version-signature.txt", raw)
        check.command("kernel-packages", ["/usr/bin/dpkg-query", "-W",
            "-f=${binary:Package}\t${db:Status-Status}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n",
            "linux-image-" + kernel.release, "linux-image-unsigned-" + kernel.release, "linux-modules-" + kernel.release],
            environment, work, timeout=15, codes=(0, 1), limit=64 << 10)

        check.command("rust-acquire", [rustup, "toolchain", "install", C.RUST, "--profile", "minimal", "--no-self-update"], environment, work)
        cargo = check.command("cargo-selection", [rustup, "which", "--toolchain", C.RUST, "cargo"], environment, work, timeout=15).stdout.strip().decode("utf-8")
        rustc = check.command("rustc-selection", [rustup, "which", "--toolchain", C.RUST, "rustc"], environment, work, timeout=15).stdout.strip().decode("utf-8")
        D.need(all(Path(value).is_absolute() and Path(value).is_file() for value in (cargo, rustc)), "Selected compiler missing")
        version = check.command("rust-version", [rustc, "-vV"], environment, work, timeout=15).stdout.decode("ascii")
        D.need(f"release: {C.RUST}\n" in version and f"host: {TARGET}\n" in version, "Selected compiler identity differs")
        environment.update(RUSTC=rustc, PATH=str(Path(cargo).parent) + os.pathsep + environment["PATH"])
        check.command("locked-inputs", [cargo, "metadata", "--locked", "--format-version", "1", "--no-default-features",
            "--features", FEATURES[0], "--filter-platform", TARGET, "--manifest-path", str(source / "desktop/src-tauri/Cargo.toml")], environment, work)
        source_check("acquired")
        environment.update(GITHUB_SHA=sha, MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=C.CONVENTIONAL_SMOKE_INPUTS["manifestSha256"],
                           MRK_BUNDLED_PROTOCOL_SHA256=C.CONVENTIONAL_SMOKE_INPUTS["protocolSha256"])
        binary_raw = check.command("publisher-compile", compile_argv(cargo, source, work / "target", library=False), environment, work).stdout
        binary_path = compiled_artifact(binary_raw, source, work / "target", library=False)
        binary = artifact_record(binary_path, copy_to=root / "public/mrk-runtime-publish")
        library_raw = check.command("helper-compile", compile_argv(cargo, source, work / "target", library=True), environment, work).stdout
        library_path = compiled_artifact(library_raw, source, work / "target", library=True)
        library = artifact_record(library_path)
        source_check("compiled")
        D.need(D.same(artifact_record(binary_path), binary) and D.same(artifact_record(library_path), library), "Original compiler output changed")
        test_env = {"LANG": "C", "LC_ALL": "C", "TMPDIR": str(root / "cases"), "MRK_RUNTIME_PUBLICATION_HELPER_TESTS": "1",
                    "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
        result = check.command("publisher-helpers", [str(library_path), PREFIX, "--include-ignored", "--test-threads=1"],
                               test_env, root / "cases", timeout=120, limit=2 << 20)
        test_result(result.stdout, result.stderr)
        D.need(D.same(artifact_record(binary_path), binary) and D.same(artifact_record(library_path), library), "Compiler output changed after tests")
        source_check("after")
        D.write(root / "public/compiler.json", D.canonical({"binary": binary, "library": library,
            "manifestSha256": environment["MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"], "protocolSha256": environment["MRK_BUNDLED_PROTOCOL_SHA256"]}))
        # All command owners returned; remove only these original disposable
        # compiler/dependency outputs. Tiny native fixtures remain evidence.
        D.need(directory_identity(root) == original_root and directory_identity(work) == original_work, "Cleanup root changed")
        check.phase = "compiler-output-cleanup"
        shutil.rmtree(work)
        D.need(not work.exists() and not work.is_symlink(), "Compiler output cleanup incomplete")
        D.write(root / "public/result.json", D.canonical({"sourceSha": sha, "tests": list(TESTS), "passed": 11,
            "commands": check.commands, "compilerOutputsRemoved": True, "helperFixturesRetained": True,
            "qualified": False, "scope": "publisher-compiler-and-helper-contracts-only"}))
        print("Publisher compilation and 11 helper contracts passed; no installed/product qualification.", flush=True)
    except BaseException:
        # Never turn a failure into a pass or infer disposal from process exit.
        D.write(root / "public/failure.json", D.canonical({"phase": check.phase, "commands": check.commands,
                                                         "qualified": False, "partialOutputsMayRemain": True}))
        raise


if __name__ == "__main__":
    try:
        verify()
    except Exception as error:
        print("Publisher check refused: " + type(error).__name__ + ". Preserve original evidence; no qualification.", file=sys.stderr)
        raise SystemExit(1)
