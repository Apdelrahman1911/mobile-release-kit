"""One disposable Ubuntu alpha build/package job, never an installer or release.

The root owner runs only on the exact reviewed GitHub-hosted verification ref.
Three finite, task-owned systemd services acquire inputs, compile offline, and
stage a real package. A successful manager command is not child-domain finality.
No application, runtime Python, Store API, release workflow or installer runs.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import grp
import re
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import time

WORKFLOW = ".github/workflows/desktop-ubuntu-alpha-package.yml"
REF = "refs/heads/verify/desktop-ubuntu-alpha-package"
REPOSITORY = "Apdelrahman1911/mobile-release-kit"
TARGET = "x86_64-unknown-linux-gnu"
RUST = "1.98.0"
NODE = "v24.20.0"
RUST_COMMIT = "88d9e12ae178fab0fb5cc050a94da85685d449ea"
# Explicitly reviewed pre-release source candidate, NOT protected main or GA.
ALPHA_TOOLING_SHA = "2e4480b8fb3358427dfa7f29df2d8ec89ae6e524"
MAX_CAPTURE = 16 << 20
MAX_SECONDS = 2700
ROLES = ("acquire", "build", "package")
GENERATED = ("desktop/node_modules", "desktop/dist", "desktop/src-tauri/gen", "desktop/src-tauri/permissions")
TASK_PARENT = Path("/var/lib")
TASK_PATTERN = r"/var/lib/mrk-alpha-[1-9][0-9]{0,17}-[1-9][0-9]{0,3}-[0-9a-f]{24}"
STARTUP_PHASES = frozenset((
    "host-identity", "workflow-identity", "workflow-coordinates", "ubuntu-release",
    "cgroup-v2", "protected-task-parent", "task-nonce", "create-task-directory",
    "create-task-subdirectories", "resource-pressure", "initialize-manager",
))
PARENT_REFUSALS = frozenset((
    "protected-parent-not-directory", "protected-parent-owner", "protected-parent-mode",
))
CGROUP_OPERATIONS = frozenset((
    "parent-open", "parent-bind", "directory-open", "directory-bind",
    "events-open", "events-bind", "directory-stat", "events-stat",
    "events-seek", "events-read", "retired-parent-bind", "retired-name-absence",
))


class Refused(ValueError):
    pass


class ParentRefused(Refused):
    def __init__(self, reason):
        if reason not in PARENT_REFUSALS:
            raise ValueError("Unknown protected-parent invariant")
        self.reason = reason
        super().__init__(reason)


def startup_diagnostic(phase, error, *, task_directory_may_exist=False):
    """Closed failure DATA, never exception text, paths or a cleanup claim.

    Call only before the first manager/worker command has been attempted.
    Partial directory creation is possible, including an exclusive-name
    collision; this record neither adopts nor removes anything at that name.
    """
    if isinstance(error, ParentRefused) and error.reason in PARENT_REFUSALS:
        reason = error.reason
    elif isinstance(error, Refused):
        reason = "predicate-refused"
    elif isinstance(error, PermissionError):
        reason = "permission-denied"
    elif isinstance(error, FileExistsError):
        reason = "already-exists"
    elif isinstance(error, FileNotFoundError):
        reason = "not-found"
    elif isinstance(error, InterruptedError):
        reason = "interrupted"
    elif isinstance(error, OSError):
        reason = "os-error"
    else:
        reason = "unexpected"
    return {
        "schema": "mrk-ubuntu-alpha-startup-failure-v1",
        "phase": phase if type(phase) is str and phase in STARTUP_PHASES else "startup-internal",
        "reason": reason, "taskWorkerStartAttempted": False,
        "taskDirectoryMayExist": task_directory_may_exist is not False,
    }


def write_startup_diagnostic(phase, error, *, task_directory_may_exist=False):
    # Logging must not replace the original startup failure if stderr itself
    # is unavailable. The caller still raises that original exception.
    try:
        sys.stderr.write(canonical(startup_diagnostic(
            phase, error, task_directory_may_exist=task_directory_may_exist)).decode("ascii") + "\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


def task_path(value):
    return type(value) is str and re.fullmatch(TASK_PATTERN, value) is not None


def need(condition, message):
    if not condition:
        raise Refused(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def ordinary(path, *, limit=512 << 20, owner=None, executable=None, hardlinks=False):
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and (before.st_nlink >= 1 if hardlinks else before.st_nlink == 1) and 0 <= before.st_size <= limit
         and not before.st_mode & 0o7022 and (owner is None or before.st_uid == owner)
         and (executable is None or bool(before.st_mode & 0o111) == executable),
         "Unexpected ordinary task file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        need(identity(os.fstat(descriptor)) == identity(before), "Task file changed before read")
        digest, count = hashlib.sha256(), 0
        while block := os.read(descriptor, 65536):
            count += len(block)
            need(count <= before.st_size, "Task file grew")
            digest.update(block)
        need(count == before.st_size and identity(os.fstat(descriptor)) == identity(before)
             == identity(path.lstat()), "Task file changed during read")
    finally:
        os.close(descriptor)
    return {"path": str(path), "size": count, "sha256": digest.hexdigest(), "identity": list(identity(before))}


def read(path, limit=1 << 20, owner=None):
    before = ordinary(path, limit=limit, owner=owner)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        need(list(identity(os.fstat(descriptor))) == before["identity"], "Task data changed before open")
        pieces, size = [], 0
        while block := os.read(descriptor, 65536):
            size += len(block)
            need(size <= before["size"], "Task data read grew")
            pieces.append(block)
        body = b"".join(pieces)
        need(len(body) == before["size"] and hashlib.sha256(body).hexdigest() == before["sha256"]
             and list(identity(os.fstat(descriptor))) == before["identity"]
             == list(identity(Path(path).lstat())), "Task data read differs")
        return body
    finally:
        os.close(descriptor)


def data(path, limit=1 << 20, owner=None):
    def pairs(values):
        result = {}
        for key, value in values:
            need(key not in result, "Duplicate control field")
            result[key] = value
        return result
    return json.loads(read(path, limit, owner), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused("Nonfinite control value")))


def write_new(path, body, mode=0o444):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view, count = memoryview(body), 0
        while count < len(view):
            written = os.write(descriptor, view[count:])
            need(written > 0, "Short exclusive task write")
            count += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    result = ordinary(path)
    need(result["size"] == len(body) and result["sha256"] == hashlib.sha256(body).hexdigest(),
         "Task output readback differs")
    return result


def copy_file(source, destination, *, expected=None, mode=0o444, owner=None):
    record = ordinary(source, owner=owner)
    if expected is not None:
        need(all(record[key] == expected[key] for key in ("size", "sha256")), "Copied task input differs")
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    output = None
    try:
        need(list(identity(os.fstat(descriptor))) == record["identity"], "Copy source changed before open")
        output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        digest, count = hashlib.sha256(), 0
        while block := os.read(descriptor, 65536):
            count += len(block)
            need(count <= record["size"], "Copy source grew")
            digest.update(block)
            view, at = memoryview(block), 0
            while at < len(view):
                written = os.write(output, view[at:])
                need(written > 0, "Short task copy")
                at += written
        need(count == record["size"] and digest.hexdigest() == record["sha256"]
             and list(identity(os.fstat(descriptor))) == record["identity"]
             == list(identity(Path(source).lstat())), "Copy source changed")
        os.fchmod(output, mode)
        os.fsync(output)
    finally:
        if output is not None:
            os.close(output)
        os.close(descriptor)
    copied = ordinary(destination)
    need(copied["identity"][:2] != record["identity"][:2]
         and all(copied[key] == record[key] for key in ("size", "sha256")), "Task copy aliases or differs")
    return copied


def emit(event, **values):
    body = canonical({"event": event, **values}) + b"\n"
    need(len(body) <= 8 << 20, "Worker event bound")
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def load_data(source):
    spec = importlib.util.spec_from_file_location("_mrk_alpha_data", source / "desktop/tools/linux_alpha_package_data.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def plain_environment(home, temporary):
    return {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(temporary),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "NODE_DISABLE_COMPILE_CACHE": "1",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": "0"}



def public_compiler_diagnostics(rows):
    """Only error codes and repository-relative spans; never source snippets."""
    output = []
    if type(rows) is not list:
        return output
    for row in rows[:32]:
        if type(row) is not dict or not re.fullmatch(r"E[0-9]{4}", str(row.get("code", ""))):
            continue
        spans = []
        for span in row.get("spans", [])[:8] if type(row.get("spans")) is list else []:
            if type(span) is not dict:
                continue
            name = span.get("path")
            if (type(name) is str and len(name) <= 256
                    and re.fullmatch(r"(?:desktop|src)/[A-Za-z0-9_./+-]+", name)
                    and all(part not in ("", ".", "..") for part in name.split("/"))
                    and all(type(span.get(key)) is int and 1 <= span[key] <= 1_000_000
                            for key in ("lineStart", "lineEnd"))
                    and span["lineStart"] <= span["lineEnd"]):
                spans.append({key: span[key] for key in ("path", "lineStart", "lineEnd")})
        output.append({"code": row["code"], "spans": spans})
    return output


def compiler_diagnostics(raw, source):
    if source is None:
        return []
    rows = []
    for line in raw.splitlines()[:2048]:
        if len(line) > 2 << 20:
            continue
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if type(event) is not dict or event.get("reason") != "compiler-message":
            continue
        message = event.get("message")
        if type(message) is not dict or type(message.get("code")) is not dict:
            continue
        code = message["code"].get("code")
        if type(code) is not str or not re.fullmatch(r"E[0-9]{4}", code):
            continue
        spans = []
        for span in message.get("spans", [])[:8] if type(message.get("spans")) is list else []:
            if type(span) is not dict or type(span.get("file_name")) is not str:
                continue
            path = Path(span["file_name"])
            if path.is_absolute():
                if not path.is_relative_to(source):
                    continue
                name = path.relative_to(source).as_posix()
            else:
                name = (Path("desktop/src-tauri") / path).as_posix()
            spans.append({"path": name, "lineStart": span.get("line_start"), "lineEnd": span.get("line_end")})
        rows.append({"code": code, "spans": spans})
        if len(rows) >= 32:
            break
    return public_compiler_diagnostics(rows)


class Commands:
    """Bounded direct children; unit owner handles the entire domain on failure."""

    def __init__(self, deadline_ns, environment, cwd, logs, *, source=None):
        self.deadline_ns, self.environment, self.cwd, self.logs = deadline_ns, environment, cwd, logs
        self.count, self.records, self.source = 0, [], source

    def __call__(self, label, argv, *, cwd=None, timeout=300, limit=8 << 20, codes=(0,)):
        need(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", label) and type(argv) is list and argv
             and all(type(value) is str and "\0" not in value for value in argv), "Command role/arguments differ")
        self.count += 1
        need(self.count <= 1536 and 0 < limit <= MAX_CAPTURE, "Command count/capture bound")
        end = min(self.deadline_ns, time.monotonic_ns() + int(timeout * 1_000_000_000))
        need(time.monotonic_ns() < end, "Original aggregate command deadline expired")
        process = subprocess.Popen(argv, cwd=cwd or self.cwd, env=self.environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   close_fds=True)
        selector, buffers = selectors.DefaultSelector(), {1: bytearray(), 2: bytearray()}
        failure, status = None, None
        try:
            for key, stream in ((1, process.stdout), (2, process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, key)
            while selector.get_map() or process.poll() is None:
                need(time.monotonic_ns() < end, "Original command/EOF deadline expired: " + label)
                for selected, _ in selector.select(0.1):
                    block = os.read(selected.fileobj.fileno(), 65536)
                    if block:
                        buffers[selected.data].extend(block)
                        need(sum(map(len, buffers.values())) <= limit, "Original command output bound: " + label)
                    else:
                        selector.unregister(selected.fileobj)
                status = process.poll()
            status = process.wait(timeout=1)
            need(status in codes, "Original command failed: " + label + " (" + str(status) + ")")
        except BaseException as error:
            failure = error
        finally:
            # Kill/reap only this still-owned Popen child. Descendant finality is
            # deliberately left to the original systemd unit, never a PID scan.
            if process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    failure = failure or Refused("Original command child did not join")
            selector.close()
            process.stdout.close()
            process.stderr.close()
        if failure is None and time.monotonic_ns() >= end:
            failure = Refused("Original command completed after its deadline: " + label)
        raw = {}
        for key, suffix in ((1, "stdout"), (2, "stderr")):
            path = self.logs / (str(self.count).zfill(4) + "-" + label + "." + suffix)
            raw[suffix] = bytes(buffers[key])
            write_new(path, raw[suffix], 0o400)
        record = {"label": label, "argv": argv, "exit": process.returncode,
                  "stdoutSha256": hashlib.sha256(raw["stdout"]).hexdigest(),
                  "stderrSha256": hashlib.sha256(raw["stderr"]).hexdigest(),
                  "stdoutBytes": len(raw["stdout"]), "stderrBytes": len(raw["stderr"]),
                  "compilerDiagnostics": compiler_diagnostics(raw["stdout"], self.source) if label.startswith("compile-") else []}
        self.records.append(record)
        if failure is not None:
            emit("command-failed", command=record)
            raise failure
        return subprocess.CompletedProcess(argv, status, raw["stdout"], raw["stderr"])


def worker_environment(task, role, configuration):
    work = task / role
    environment = plain_environment(work / "home", work / "tmp")
    source = task / "source"
    node = task / "tools/node/bin/node"
    environment["PATH"] = str(node.parent) + ":/usr/bin:/bin"
    environment.update(
        CARGO_HOME=str(work / "cargo"), RUSTUP_HOME=str(work / "rustup"),
        CARGO_TARGET_DIR=str(task / "build/target"), RUSTUP_TOOLCHAIN=RUST,
        CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0",
        CARGO_PROFILE_DEV_DEBUG_ASSERTIONS="true", CARGO_BUILD_JOBS="1",
        CARGO_CACHE_AUTO_CLEAN_FREQUENCY="never",
        NPM_CONFIG_CACHE=str(work / "npm-cache"),
        NPM_CONFIG_USERCONFIG=str(task / "control/npmrc-user"),
        NPM_CONFIG_GLOBALCONFIG=str(task / "control/npmrc-global"),
        NPM_CONFIG_REGISTRY="https://registry.npmjs.org/",
        GITHUB_SHA=configuration["sourceSha"])
    if role != "acquire":
        environment["CARGO_NET_OFFLINE"] = "true"
    return environment


def worker_go(task, role, configuration):
    need(os.getuid() == os.geteuid() == configuration["accounts"][role]["uid"] != 0
         and os.getgid() == os.getegid() == configuration["accounts"][role]["gid"]
         and os.getgroups() in ([], [os.getgid()]), "Worker account role differs")
    path = task / "control" / (role + ".go")
    while not path.exists():
        need(time.monotonic_ns() < configuration["deadlineNs"], "Original pre-GO deadline expired")
        time.sleep(0.02)
    value = data(path, 4096, 0)
    with open("/proc/self/cgroup", "rb") as stream:
        cgroup = stream.read(4097)
    need(len(cgroup) <= 4096 and value == {
        "role": role, "nonce": configuration["nonce"], "pid": os.getpid(),
        "uid": os.getuid(), "controlGroup": "/system.slice/" + configuration["units"][role],
        "invocationId": value.get("invocationId")}
        and re.fullmatch(r"[0-9a-f]{32}", value["invocationId"])
        and cgroup == ("0::" + value["controlGroup"] + "\n").encode("ascii"),
        "GO is not routed to this original worker/unit/account")


def acquire_worker(task, configuration, command, D):
    source, work = task / "source", task / "acquire"
    rustup = str(task / "tools/rustup")
    command("rust-acquire", [rustup, "toolchain", "install", RUST, "--profile", "minimal", "--no-self-update"], timeout=600)
    selected = {}
    for name in ("cargo", "rustc"):
        result = command(name + "-selection", [rustup, "which", "--toolchain", RUST, name], timeout=15, limit=4096)
        expected = work / ("rustup/toolchains/" + RUST + "-" + TARGET + "/bin/" + name)
        need(result.stderr == b"" and result.stdout == (str(expected) + "\n").encode(),
             "Private compiler selection differs")
        selected[name] = str(expected)
    version = command("rust-version", [selected["rustc"], "-vV"], timeout=15, limit=4096)
    need(version.stderr == b"" and ("release: " + RUST + "\n").encode() in version.stdout
         and ("host: " + TARGET + "\n").encode() in version.stdout
         and ("commit-hash: " + RUST_COMMIT + "\n").encode() in version.stdout, "Actual Rust compiler tuple differs")
    command.environment["RUSTC"] = selected["rustc"]
    command.environment["PATH"] = str(Path(selected["cargo"]).parent) + ":" + command.environment["PATH"]
    command("cargo-locked-fetch", [selected["cargo"], "fetch", "--locked", "--target", TARGET,
                                  "--manifest-path", str(source / "desktop/src-tauri/Cargo.toml")], timeout=600)
    node = str(task / "tools/node/bin/node")
    observed = command("node-version", [node, "--version"], timeout=15, limit=4096)
    need(observed.stdout == (NODE + "\n").encode() and observed.stderr == b"", "Actual Node version differs")
    command("npm-locked-no-scripts", [node, "--max-old-space-size=768",
        str(task / "tools/node/lib/node_modules/npm/bin/npm-cli.js"), "ci", "--ignore-scripts",
        "--no-audit", "--no-fund", "--userconfig", str(task / "control/npmrc-user"),
        "--globalconfig", str(task / "control/npmrc-global"), "--cache", str(work / "npm-cache"),
        "--registry", "https://registry.npmjs.org/"], cwd=source / "desktop", timeout=300)
    npm_tree = D.U.shell_generated_tree(source / "desktop/node_modules", links=True)
    emit("acquired", selected=selected, npmTreeSha256=npm_tree["treeSha256"], commands=command.records)


def build_worker(task, configuration, command, D):
    source, work = task / "source", task / "build"
    compiler_root = work / ("rustup/toolchains/" + RUST + "-" + TARGET + "/bin")
    cargo, rustc = str(compiler_root / "cargo"), str(compiler_root / "rustc")
    command.environment.update(RUSTC=rustc, PATH=str(compiler_root) + ":" + command.environment["PATH"])
    policy, runtime = D.reconstruct_runtime(source, work)
    command.environment.update(MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=policy["manifestSha256"],
                               MRK_BUNDLED_PROTOCOL_SHA256=policy["protocolSha256"])
    tooling = configuration["githubTooling"]
    for name, value in tooling.items():
        command.environment[name] = value
    metadata, identities, nodes = {}, {}, {}
    for role in ("main", "publisher"):
        raw = command("metadata-" + role, [cargo, "metadata", "--offline", "--locked", "--format-version", "1",
            "--no-default-features", "--features", ",".join(D.ROLES[role][2]), "--filter-platform", TARGET,
            "--manifest-path", str(source / "desktop/src-tauri/Cargo.toml")], timeout=90).stdout
        metadata[role], identities[role], nodes[role] = D.metadata_graph(raw, role, source, work / "target")
        if role == "main":
            compiler_inputs, _ = D.U.shell_compiler_inputs(source, work, cargo, rustc, raw)
    notices, notice_rows = D.collect_notices(source, work, metadata)
    support = D.support_inputs(command)
    notice_rows = D.native_notices(notices, support, command)
    D.support_unchanged(support)
    emit("inputs-admitted", noticeFiles=notice_rows)
    node = str(task / "tools/node/bin/node")
    # One meaningful no-emit check plus one frontend build, not a test rerun.
    command("typescript-no-emit", [node, "--max-old-space-size=768", "node_modules/typescript/bin/tsc",
                                 "--noEmit", "-p", "tsconfig.json"], cwd=source / "desktop", timeout=90)
    command("vite-assets", [node, "--max-old-space-size=768", "node_modules/vite/bin/vite.js", "build",
        "--config", str(source / "desktop/vite.config.mjs"), "--configLoader", "native",
        "--outDir", str(source / "desktop/dist")], cwd=source / "desktop", timeout=120)
    frontend = D.U.shell_generated_tree(source / "desktop/dist")
    need(1 <= len(frontend["files"]) <= 64 and not frontend["links"]
         and any(row["path"] == "index.html" for row in frontend["files"]), "Actual embedded asset roster differs")
    retained = {}
    for role in ("main", "publisher"):
        raw = command("compile-" + role, [cargo, "build", "--locked", "--offline", "--jobs", "1",
            "--no-default-features", "--features", ",".join(D.ROLES[role][2]), "--target", TARGET,
            "--manifest-path", str(source / "desktop/src-tauri/Cargo.toml"), "--target-dir", str(work / "target"),
            "--profile", "dev", "--bin", D.ROLES[role][0], "--message-format=json"], timeout=1800).stdout
        selection, units = D.compiler_artifact(raw, role, source, work / "target")
        D.U.shell_compiler_units(units, identities[role], nodes[role])
        need(selection["packageId"] == metadata[role]["resolve"]["root"], "Compiler role is not the actual package root")
        retained[role] = D.retain_binary(selection, work / "compiled" / D.ROLES[role][0])
        # Root-only systemd stdout retains this BEFORE the later invocation.
        emit("binary-retained", role=role, record=retained[role])
        for previous in retained.values():
            D.verify_retained_binary(previous)
    dependencies = D.dependency_inputs(source, work,
        {role: Path(retained[role]["retained"]["path"]) for role in retained}, runtime, policy, command, support=support)
    notice_rows = D.bind_notice_outputs(notices, configuration["sourceSha"], policy, retained, frontend)
    D.dependencies_unchanged(dependencies)
    for record in retained.values():
        D.verify_retained_binary(record)
    runtime_rows = D.S.runtime_records(runtime, policy["manifestSha256"], policy["protocolSha256"])
    D.current_controls(source)
    result = {
        "policy": policy, "runtimeFiles": list(runtime_rows.values()), "noticeFiles": notice_rows,
        "compiler": retained, "compilerInputs": compiler_inputs, "frontend": frontend,
        "dependencies": dependencies, "commands": command.records,
    }
    # The root later binds these originals after cgroup finality before transfer.
    emit("built", result=result)


def package_worker(task, configuration, command, D):
    work, source = task / "package", task / "source"
    original = data(task / "control/package-inputs.json", 8 << 20, 0)
    result = D.stage_package(source, work, work / "export", original["compiler"], work / "runtime",
                             original["policy"], work / "desktop-notices", original["noticeFiles"],
                             original["depends"], command)
    emit("packaged", result=result, commands=command.records)


def worker(task, role):
    configuration = data(task / "control/configuration.json", 1 << 20, 0)
    worker_go(task, role, configuration)
    D = load_data(task / "source")
    work = task / role
    command = Commands(configuration["deadlineNs"], worker_environment(task, role, configuration), work, work / "logs", source=task / "source")
    {"acquire": acquire_worker, "build": build_worker, "package": package_worker}[role](
        task, configuration, command, D)


def manager_command(argv, *, environment, cwd, timeout=15, codes=(0,), limit=1 << 20, receipts=None):
    """Finite original OS control client; worker cgroups do not own this child."""
    need(0 < timeout <= 30 and 0 < limit <= 2 << 20, "Original manager command bounds differ")
    end = time.monotonic_ns() + int(timeout * 1_000_000_000)
    process, selector, failure = None, None, None
    launch_attempted = False
    streams, eof, buffers = {}, set(), {1: bytearray(), 2: bytearray()}
    counts, hashes = {1: 0, 2: 0}, {1: hashlib.sha256(), 2: hashlib.sha256()}
    joined, in_time, overflow, errors, status = False, False, False, [], None

    def consume(deadline, *, cleanup=False):
        nonlocal overflow
        while selector.get_map() or process.poll() is None:
            need(time.monotonic_ns() < deadline, "Original manager command/EOF deadline expired")
            for selected, _ in selector.select(0.05):
                block = os.read(selected.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(selected.fileobj)
                    eof.add(selected.data)
                    continue
                counts[selected.data] += len(block)
                hashes[selected.data].update(block)
                room = max(0, limit - sum(map(len, buffers.values())))
                buffers[selected.data].extend(block[:room])
                overflow = sum(counts.values()) > limit
                if not cleanup:
                    need(not overflow, "Original manager command output bound exceeded")

    try:
        launch_attempted = True
        process = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        streams = {1: process.stdout, 2: process.stderr}
        selector = selectors.DefaultSelector()
        for key, stream in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, key)
        consume(end)
        status = process.wait(timeout=max(0.001, (end - time.monotonic_ns()) / 1_000_000_000))
        joined = True
        in_time = time.monotonic_ns() < end
        need(in_time, "Original manager command completed after its deadline")
        need(status in codes, "Original manager command failed")
    except BaseException as error:
        failure = error
    finally:
        # Bounded consuming cleanup cannot be interrupted halfway through a
        # stream close. Restore the caller's mask afterward; do not suppress a
        # requested cancellation or renew the original success deadline.
        old_mask = None
        try:
            old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGHUP, signal.SIGINT})
        except BaseException as error:
            errors.append(("signal-mask", type(error).__name__))
            failure = failure or error
        try:
            cleanup_end = time.monotonic_ns() + 5_000_000_000
            if process is not None:
                try:
                    if process.poll() is None:
                        process.kill()  # Only this original, still-owned Popen.
                except BaseException as error:
                    errors.append(("original-kill", type(error).__name__))
                    failure = failure or error
                if selector is not None and eof != {1, 2}:
                    try:
                        consume(cleanup_end, cleanup=True)
                    except BaseException as error:
                        errors.append(("original-eof", type(error).__name__))
                        failure = failure or error
                try:
                    status = process.wait(timeout=max(0.001, (cleanup_end - time.monotonic_ns()) / 1_000_000_000))
                    joined = True
                except BaseException as error:
                    errors.append(("original-join", type(error).__name__))
                    failure = failure or error
            if selector is not None:
                try:
                    selector.close()
                except BaseException as error:
                    errors.append(("selector-close", type(error).__name__))
                    failure = failure or error
            for key, stream in streams.items():
                try:
                    stream.close()  # Exactly one consuming close per stream.
                except BaseException as error:
                    errors.append(("stream-close-" + str(key), type(error).__name__))
                    failure = failure or error
            # A constructor may be interrupted after spawning but before it
            # returns ownership. No returned handle is not proof of no child.
            final = (not launch_attempted) if process is None else joined and eof == {1, 2} and not errors
            receipt = {
                "program": Path(argv[0]).name, "pid": process.pid if process is not None else None,
                "launchAttempted": launch_attempted, "originalHandleReturned": process is not None,
                "exit": status, "joined": joined, "eof": sorted(eof),
                "withinDeadline": in_time, "outputOverflow": overflow, "final": bool(final),
                "stdoutBytes": counts[1], "stderrBytes": counts[2],
                "stdoutSha256": hashes[1].hexdigest(), "stderrSha256": hashes[2].hexdigest(),
                "closeErrors": errors,
            }
            if receipts is not None:
                receipts.append(receipt)
            if not final:
                failure = failure or Refused("Original manager client finality is unknown")
        finally:
            if old_mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
    if failure is not None:
        raise failure
    need(joined and eof == {1, 2} and in_time and not overflow and not errors,
         "Original manager command acceptance is incomplete")
    return subprocess.CompletedProcess(argv, status, bytes(buffers[1]), bytes(buffers[2]))


UNIT_PROPERTIES = (
    "Id", "LoadState", "ActiveState", "SubState", "InvocationID", "MainPID", "ExecMainPID",
    "ControlGroup", "Result", "ExecMainCode", "ExecMainStatus", "ExecMainStartTimestampMonotonic",
    "ExecMainExitTimestampMonotonic", "Restart", "KillMode", "RemainAfterExit", "RuntimeMaxUSec",
)


def unit_values(raw, *, allow_absent=False):
    result = {}
    for line in raw.decode("utf-8").splitlines():
        key, separator, value = line.partition("=")
        need(separator and key in UNIT_PROPERTIES and key not in result, "Unit property result differs")
        result[key] = value
    if allow_absent and result.get("LoadState") == "not-found":
        need({"Id", "LoadState", "ActiveState", "SubState"} <= set(result)
             and result["ActiveState"] == "inactive" and result["SubState"] == "dead"
             and result.get("MainPID", "0") == result.get("ExecMainPID", "0") == "0"
             and result.get("InvocationID", "") == result.get("ControlGroup", "") == "",
             "Absent task unit has an active invocation")
    else:
        need(set(result) == set(UNIT_PROPERTIES), "Unit property result is incomplete")
    return result


class UnitOwner:
    def __init__(self, task, configuration):
        self.task, self.configuration = task, configuration
        self.environment = plain_environment(task / "owner/home", task / "owner/tmp")
        self.live, self.results, self.pending, self.errors = {}, [], set(), []
        self.clients, self.phase, self.role = [], "initialization", None
        self.cgroup_operation, self.cgroup_read_errno, self.cgroup_failure = None, None, None

    def control(self, argv, **kwargs):
        return manager_command(argv, environment=self.environment, cwd=self.task / "owner", receipts=self.clients, **kwargs)

    def show(self, name, *, allow_absent=False):
        result = self.control(["/usr/bin/systemctl", "show", "--no-pager",
            "--property=" + ",".join(UNIT_PROPERTIES), name], codes=(0, 1) if allow_absent else (0,))
        values = unit_values(result.stdout, allow_absent=allow_absent)
        absent = allow_absent and values["LoadState"] == "not-found"
        need(result.stderr == b"" or absent and result.stderr == ("Unit " + name + " could not be found.\n").encode(),
             "Unexpected unit query diagnostic")
        need(result.returncode == 0 or absent, "Existing task unit query failed")
        return values

    def match_original(self, name, initial):
        current = self.show(name)
        need(current["Id"] == name and current["InvocationID"] == initial["InvocationID"]
             and current["ExecMainPID"] == initial["ExecMainPID"]
             and current["ExecMainStartTimestampMonotonic"] == initial["ExecMainStartTimestampMonotonic"]
             and current["ControlGroup"] in (initial["ControlGroup"], ""),
             "Original unit invocation changed")
        return current

    def remember_cgroup_failure(self, error):
        # Keep only the first actual failing observation, not exception text,
        # paths, or a later cleanup error that could mask the original fault.
        if self.cgroup_failure is None:
            number = error.errno if isinstance(error, OSError) else None
            self.cgroup_failure = {
                "operation": self.cgroup_operation,
                "errno": number if type(number) is int and 1 <= number <= 4095 else None,
                "eventsReadErrno": self.cgroup_read_errno,
            }

    def bind_cgroup(self, name, current):
        """Retain the original parent/name and both original cgroup objects."""
        need(current["ControlGroup"] == "/system.slice/" + name, "Original cgroup path differs")
        parent_path = Path("/sys/fs/cgroup/system.slice")
        acquired = {}
        self.cgroup_read_errno = None
        try:
            self.cgroup_operation = "parent-open"
            acquired["cgroupParentFd"] = os.open(parent_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.cgroup_operation = "parent-bind"
            parent = os.fstat(acquired["cgroupParentFd"])
            need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == parent.st_gid == 0
                 and identity(parent)[:5] == identity(parent_path.lstat())[:5],
                 "Original cgroup parent changed")
            self.cgroup_operation = "directory-open"
            acquired["cgroupFd"] = os.open(name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=acquired["cgroupParentFd"])
            self.cgroup_operation = "directory-bind"
            original = os.fstat(acquired["cgroupFd"])
            need(stat.S_ISDIR(original.st_mode) and original.st_uid == original.st_gid == 0
                 and identity(original) == identity(os.stat(name,
                     dir_fd=acquired["cgroupParentFd"], follow_symlinks=False)),
                 "Original unit cgroup changed")
            self.cgroup_operation = "events-open"
            acquired["eventsFd"] = os.open("cgroup.events",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=acquired["cgroupFd"])
            self.cgroup_operation = "events-bind"
            events = os.fstat(acquired["eventsFd"])
            need(stat.S_ISREG(events.st_mode) and events.st_uid == events.st_gid == 0
                 and events.st_dev == original.st_dev
                 and identity(events) == identity(os.stat("cgroup.events",
                     dir_fd=acquired["cgroupFd"], follow_symlinks=False)),
                 "Original cgroup.events changed")
            return {"name": name, "initial": current, **acquired,
                    "cgroupIdentity": (original.st_dev, original.st_ino),
                    "eventsIdentity": identity(events)[:5],
                    "cgroupParentIdentity": identity(parent)[:5],
                    "cgroupParentPath": parent_path}
        except BaseException as error:
            self.remember_cgroup_failure(error)
            # Every actually acquired descriptor is consumed, even if an
            # earlier admission check or another consuming close failed.
            for key in ("eventsFd", "cgroupFd", "cgroupParentFd"):
                descriptor = acquired.pop(key, None)
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError as close_error:
                        self.errors.append(close_error.errno)
            raise

    def retired_name_absent(self, owner):
        # This latch proves only that the original invocation was matched and
        # its no-resubmit stop attempt began. It is NOT a launched/successful
        # stop receipt. Earlier submission/deadline/client failures stay sticky.
        need(owner.get("stopAttempted") is True, "Retirement was not a stop-settlement observation")
        for index in range(3):
            self.cgroup_operation = "retired-parent-bind"
            parent = os.fstat(owner["cgroupParentFd"])
            need(identity(parent)[:5] == owner["cgroupParentIdentity"]
                 == identity(owner["cgroupParentPath"].lstat())[:5],
                 "Original retirement parent changed")
            if index == 2:
                break
            self.cgroup_operation = "retired-name-absence"
            try:
                os.stat(owner["name"], dir_fd=owner["cgroupParentFd"], follow_symlinks=False)
            except FileNotFoundError as error:
                if error.errno != errno.ENOENT:
                    raise
            else:
                # Never reopen, adopt or signal a replacement at this name.
                raise Refused("Original retired cgroup name is still present")

    def populated(self, owner):
        self.cgroup_read_errno = None
        try:
            self.cgroup_operation = "directory-stat"
            value = os.fstat(owner["cgroupFd"])
            need((value.st_dev, value.st_ino) == owner["cgroupIdentity"], "Original cgroup descriptor changed")
            if value.st_nlink == 0:
                return False, "retired"
            self.cgroup_operation = "events-stat"
            need(identity(os.fstat(owner["eventsFd"]))[:5] == owner["eventsIdentity"],
                 "Original cgroup.events descriptor changed")
            try:
                self.cgroup_operation = "events-seek"
                os.lseek(owner["eventsFd"], 0, os.SEEK_SET)
                self.cgroup_operation = "events-read"
                raw = os.read(owner["eventsFd"], 4097)
            except OSError as error:
                operation = self.cgroup_operation  # Preserve the actual failing syscall.
                if error.errno != errno.ENODEV or owner.get("stopAttempted") is not True:
                    raise
                # kernfs can reject either seek or read after deactivating the
                # original events object, while its directory retains a stale
                # nonzero link count. Neither errno nor a successful systemctl
                # alone proves retirement: keep the exact original-parent/name
                # absence witness. A failed seek never counts as an actual read.
                if operation == "events-read":
                    self.cgroup_read_errno = errno.ENODEV
                self.retired_name_absent(owner)
                owner["retirementOperation"] = operation
                owner["retirementErrno"] = errno.ENODEV
                if operation == "events-read":
                    owner["retirementReadErrno"] = errno.ENODEV
                return False, "retired"
            need(len(raw) <= 4096, "Original cgroup.events bound")
            rows = dict(line.split(" ", 1) for line in raw.decode("ascii").splitlines())
            need(rows.get("populated") in ("0", "1"), "Original cgroup population is unknown")
            return rows["populated"] == "1", "empty" if rows["populated"] == "0" else "populated"
        except BaseException as error:
            self.remember_cgroup_failure(error)
            raise

    def stop_original(self, role, *, main=None):
        owner = self.live[role]
        if not owner.get("stopAttempted", False):
            before = self.match_original(owner["name"], owner["initial"])
            # Preserve the genuine pre-stop outcome BEFORE submitting a stop.
            if main is not None:
                need(all(before[key] == main[key] for key in ("Result", "ExecMainCode", "ExecMainStatus",
                      "ExecMainExitTimestampMonotonic")), "Original worker outcome changed before stop")
            owner["mainBeforeStop"] = before
            owner["stopDeadlineNs"] = min(self.configuration["deadlineNs"] + 20_000_000_000,
                                          time.monotonic_ns() + 20_000_000_000)
            owner["stopAttempted"] = True
            remaining = (owner["stopDeadlineNs"] - time.monotonic_ns()) / 1_000_000_000
            need(remaining > 0, "Original stop deadline expired before submission")
            self.control(["/usr/bin/systemctl", "stop", owner["name"]], timeout=min(20, remaining))
        # On a failed/interrupted submission, cleanup revisits ONLY the held
        # original cgroup. Never submit another stop or adopt a collected unit.
        while True:
            populated, state = self.populated(owner)
            if not populated:
                break
            need(time.monotonic_ns() < owner["stopDeadlineNs"], "Original cgroup did not become empty/retired")
            time.sleep(0.05)
        errors = []
        for key in ("eventsFd", "cgroupFd", "cgroupParentFd"):
            try:
                os.close(owner.pop(key))
            except OSError as error:
                errors.append(error.errno)
        del self.live[role]
        self.errors.extend(errors)
        record = {"role": role, "initial": owner["initial"], "mainBeforeStop": owner["mainBeforeStop"],
                  "stopAttempted": True, "stopDeadlineNs": owner["stopDeadlineNs"],
                  "originalCgroupFinality": state, "closed": not errors,
                  "retirementReadErrno": owner.get("retirementReadErrno")}
        self.results.append(record)
        need(not errors, "Original cgroup descriptor close failed")
        return record

    def run(self, role):
        self.phase, self.role = "worker-" + role, role
        name = self.configuration["units"][role]
        initial = self.show(name, allow_absent=True)
        need(initial["Id"] == name and initial["LoadState"] == "not-found", "Task unit already exists")
        remaining = (self.configuration["deadlineNs"] - time.monotonic_ns()) // 1_000_000_000
        need(remaining >= 30, "Original aggregate unit deadline expired")
        account = self.configuration["accounts"][role]
        source, work = self.task / "source", self.task / role
        properties = {
            "Type": "exec", "RemainAfterExit": "yes", "Restart": "no", "CollectMode": "inactive",
            "KillMode": "control-group", "SendSIGKILL": "yes", "RuntimeMaxSec": str(remaining),
            "TimeoutStartSec": "20", "TimeoutStopSec": "10", "User": account["name"], "Group": account["name"],
            "SupplementaryGroups": "", "WorkingDirectory": str(work), "UMask": "0077",
            "NoNewPrivileges": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "",
            "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes", "PrivateDevices": "yes",
            "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes",
            "ProtectControlGroups": "yes", "ProtectClock": "yes", "RestrictSUIDSGID": "yes",
            "InaccessiblePaths": "-/run/user -/run/dbus -/run/docker.sock -/var/run/docker.sock",
            "RestrictRealtime": "yes", "LockPersonality": "yes", "SystemCallArchitectures": "native",
            "PrivateNetwork": "no" if role == "acquire" else "yes",
            "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6" if role == "acquire" else "AF_UNIX",
            "MemoryMax": "5G", "MemorySwapMax": "0", "TasksMax": "256", "LimitNOFILE": "1024",
            "LimitFSIZE": str(1 << 30), "StandardInput": "null",
            "StandardOutput": "append:" + str(self.task / "private" / (role + ".stdout")),
            "StandardError": "append:" + str(self.task / "private" / (role + ".stderr")),
        }
        writable = [str(work)]
        if role == "acquire":
            writable.append(str(source / "desktop/node_modules"))
        elif role == "build":
            properties["ReadOnlyPaths"] = str(work / "admitted-a")
            writable += [str(source / relative) for relative in GENERATED if relative != "desktop/node_modules"]
            properties["BindReadOnlyPaths"] = " ".join((
                str(self.task / "acquire/rustup") + ":" + str(work / "rustup"),
                str(self.task / "acquire/cargo/registry") + ":" + str(work / "cargo/registry")))
        else:
            writable = [str(work / relative) for relative in ("generated", "export", "logs", "home", "tmp")]
        properties["ReadWritePaths"] = " ".join(writable)
        argv = ["/usr/bin/systemd-run", "--quiet", "--unit=" + name]
        for key, value in properties.items():
            argv += ["--property=" + key + "=" + value]
        environment = plain_environment(work / "home", work / "tmp")
        argv += ["/usr/bin/env", "-i", *(key + "=" + value for key, value in environment.items()),
                 "/usr/bin/python3.12", "-I", "-S", "-B", str(source / "desktop/tools/linux_alpha_package.py"),
                 "worker", "--task", str(self.task), "--role", role]
        self.pending.add(name)
        self.control(argv, timeout=30)
        current = self.show(name)
        need(current["Id"] == name and current["LoadState"] == "loaded"
             and current["ActiveState"] == "active" and current["SubState"] == "running"
             and re.fullmatch(r"[0-9a-f]{32}", current["InvocationID"])
             and current["MainPID"] == current["ExecMainPID"] and current["MainPID"].isdigit()
             and int(current["MainPID"]) > 1 and current["ControlGroup"] == "/system.slice/" + name
             and current["Restart"] == "no" and current["KillMode"] == "control-group"
             and current["RemainAfterExit"] == "yes", "Original started worker unit differs")
        owner = self.bind_cgroup(name, current)
        self.live[role] = owner
        self.pending.remove(name)
        need(self.populated(owner)[0], "Original GO worker is absent from its cgroup")
        self.match_original(name, current)
        write_new(self.task / "control" / (role + ".go"), canonical({
            "role": role, "nonce": self.configuration["nonce"], "pid": int(current["MainPID"]),
            "uid": account["uid"], "controlGroup": current["ControlGroup"], "invocationId": current["InvocationID"]}))
        while True:
            need(time.monotonic_ns() < self.configuration["deadlineNs"], "Original aggregate owner deadline expired")
            pressure(self.task, running=True)
            observed = self.match_original(name, current)
            need(time.monotonic_ns() < self.configuration["deadlineNs"], "Original unit completed after its deadline")
            for suffix in ("stdout", "stderr"):
                need((self.task / "private" / (role + "." + suffix)).lstat().st_size <= MAX_CAPTURE,
                     "Original worker capture bound exceeded")
            if observed["MainPID"] == "0":
                need(observed["SubState"] in ("exited", "failed", "dead"), "Original worker terminal state differs")
                break
            time.sleep(0.5)
        final = self.stop_original(role, main=observed)
        need(observed["Result"] == "success" and observed["ExecMainCode"] == "1"
             and observed["ExecMainStatus"] == "0", "Original worker did not succeed: " + role)
        need(read(self.task / "private" / (role + ".stderr"), MAX_CAPTURE, 0) == b"",
             "Original worker emitted unexpected stderr")
        raw = read(self.task / "private" / (role + ".stdout"), MAX_CAPTURE, 0)
        events = [json.loads(line) for line in raw.splitlines()]
        need(events and all(type(row) is dict and type(row.get("event")) is str for row in events),
             "Original worker event stream differs")
        return events, final


def pressure(task, *, running=False):
    disk = os.statvfs(task)
    available = disk.f_bavail * disk.f_frsize
    need(available >= (2 if running else 8) << 30, "Insufficient disposable-runner free disk")
    if not running:
        with open("/proc/meminfo", "rb") as stream:
            body = stream.read(65537)
        need(len(body) <= 65536, "Host memory-data bound")
        found = re.search(rb"^MemAvailable:\s+([0-9]+) kB$", body, re.M)
        need(found and int(found[1]) * 1024 >= 4 << 30, "Insufficient disposable-runner available memory")


def make_directory(path, mode=0o700, uid=0, gid=0):
    path.mkdir(mode=0o700)
    os.chown(path, uid, gid)
    os.chmod(path, mode)
    item = path.lstat()
    need(stat.S_ISDIR(item.st_mode) and (item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode)) == (uid, gid, mode),
         "Exclusive task directory changed")
    return list(identity(item)[:5])


def protected_parent(path):
    for selected in [*reversed(path.parents), path]:
        value = selected.lstat()
        if not stat.S_ISDIR(value.st_mode):
            raise ParentRefused("protected-parent-not-directory")
        if value.st_uid != 0 or value.st_gid != 0:
            raise ParentRefused("protected-parent-owner")
        if value.st_mode & 0o7022:
            raise ParentRefused("protected-parent-mode")

HOSTED_DATA_BASES = {
    "documentation": "/usr/share/doc",
    "common-license": "/usr/share/common-licenses",
    "egl": "/usr/share/glvnd/egl_vendor.d",
    "applications": "/usr/share/applications",
}


def hosted_data_path(value, domain, *, directory=False, common_names=()):
    """Only the closed distro DATA surface, never executable/tool/cache paths."""
    if type(value) is not str or domain not in HOSTED_DATA_BASES:
        return False
    base = HOSTED_DATA_BASES[domain]
    if directory:
        return value == base and domain in {"egl", "applications"}
    relative = value.removeprefix(base + "/") if value.startswith(base + "/") else ""
    if domain == "documentation":
        return re.fullmatch(r"[a-z0-9][a-z0-9+.-]+/copyright", relative) is not None
    if domain == "common-license":
        return relative in common_names
    return domain == "egl" and re.fullmatch(r"[A-Za-z0-9_.+-]+\.json", relative) is not None


def hosted_data_mode_transition(before, after, mode):
    """The one permitted original-inode transition is canonical mode/ctime."""
    stable = (0, 1, 3, 4, 5, 6, 7)
    return (type(before) is tuple and type(after) is tuple and len(before) == len(after) == 9
            and before[3] == before[4] == after[3] == after[4] == 0
            and (stat.S_ISDIR(before[2]) and mode == 0o755 or stat.S_ISREG(before[2]) and mode == 0o644)
            and all(before[index] == after[index] for index in stable)
            and after[2] == stat.S_IFMT(before[2]) | mode and after[8] >= before[8])


class HostedDistroData:
    """Held originals for one fresh hosted VM's finite distro DATA mode setup.

    This is not a general repair API. The caller has already admitted the exact
    disposable workflow and must not have started any project worker. No bytes,
    owners, symlink targets, membership or executable paths may be changed.
    """
    def __init__(self, common_names):
        self.common_names = frozenset(common_names)
        self.entries, self.total, self.mode_attempts = {}, 0, 0

    def _body(self, row):
        os.lseek(row["fd"], 0, os.SEEK_SET)
        chunks, count = [], 0
        while block := os.read(row["fd"], 65536):
            count += len(block)
            need(count <= row["identity"][6] <= 2 << 20, "Hosted DATA read bound")
            chunks.append(block)
        need(count == row["identity"][6], "Hosted DATA original read length differs")
        return b"".join(chunks)

    def _named(self, row):
        return identity(os.stat(row["name"], dir_fd=row["parent"], follow_symlinks=False)
                        if row["parent"] is not None else Path("/").lstat())

    def _post_one(self, row):
        need(identity(os.fstat(row["fd"])) == row["identity"] == self._named(row),
             "Hosted DATA original identity changed")
        if "children" in row:
            need(sorted(os.listdir(row["fd"])) == row["children"], "Hosted DATA directory roster changed")
        if "target" in row:
            need(os.readlink(row["name"], dir_fd=row["parent"]) == row["target"],
                 "Hosted DATA original alias changed")
        if "body" in row:
            need(self._body(row) == row["body"], "Hosted DATA original bytes changed")
        need(identity(os.fstat(row["fd"])) == row["identity"] == self._named(row),
             "Hosted DATA changed during postcheck")

    def _node(self, path, parent, name):
        if path in self.entries:
            row = self.entries[path]
            self._post_one(row)
            return row
        need(len(self.entries) < 128, "Hosted DATA original count bound")
        before = (os.stat(name, dir_fd=parent, follow_symlinks=False)
                  if parent is not None else Path("/").lstat())
        need(before.st_uid == before.st_gid == 0 and not before.st_mode & 0o7000,
             "Hosted DATA must already be root-owned ordinary distro input")
        kind = ("directory" if stat.S_ISDIR(before.st_mode) else
                "file" if stat.S_ISREG(before.st_mode) else
                "link" if stat.S_ISLNK(before.st_mode) else None)
        need(kind is not None and (kind == "directory" or before.st_nlink == 1),
             "Hosted DATA special or multiply-linked entry")
        need((path == "/usr/share" or path.startswith("/usr/share/")) or kind == "directory" and not before.st_mode & 0o7022,
             "Hosted DATA cannot repair other ancestry")
        flags = os.O_CLOEXEC | os.O_NOFOLLOW
        flags |= os.O_PATH if kind == "link" else os.O_RDONLY | os.O_NONBLOCK
        if kind == "directory":
            flags |= os.O_DIRECTORY
        descriptor = os.open(name if parent is not None else "/", flags, dir_fd=parent)
        row = {"path": path, "parent": parent, "name": name, "fd": descriptor,
               "identity": identity(before), "original": identity(before), "kind": kind}
        self.entries[path] = row  # Every successful open is in the consuming-close book.
        need(identity(os.fstat(descriptor)) == row["identity"] == self._named(row),
             "Hosted DATA original changed before open")
        if kind == "directory":
            row["children"] = sorted(os.listdir(descriptor))
            need(len(row["children"]) <= 16384
                 and all(type(item) is str and 0 < len(item) <= 255 for item in row["children"]),
                 "Hosted DATA directory roster bound")
        elif kind == "link":
            row["target"] = os.readlink(name, dir_fd=parent)
            need(0 < len(row["target"]) <= 4096 and "\0" not in row["target"],
                 "Hosted DATA alias bound")
        else:
            need(0 <= before.st_size <= 2 << 20, "Hosted DATA file bound")
            self.total += before.st_size
            need(self.total <= 16 << 20, "Hosted DATA aggregate byte bound")
            row["body"] = self._body(row)
        self._post_one(row)
        return row

    def bind(self, selected, domain, *, directory=False):
        selected = str(selected)
        need(hosted_data_path(selected, domain, directory=directory, common_names=self.common_names),
             "Hosted DATA selection is outside the closed surface")
        original, redirects = selected, 0
        while True:
            parts, parent, current = Path(selected).parts[1:], self._node("/", None, "/"), ""
            redirected = False
            for index, name in enumerate(parts):
                current += "/" + name
                row = self._node(current, parent["fd"], name)
                if row["kind"] == "link":
                    redirects += 1
                    need(redirects <= 16, "Hosted DATA alias count bound")
                    target_parts = row["target"].split("/")
                    base_parts = list(parts[:index])  # All are already-held real ancestors.
                    if row["target"].startswith("/"):
                        base_parts, target_parts = [], target_parts[1:]
                    else:
                        while target_parts and target_parts[0] == "..":
                            need(bool(base_parts), "Hosted DATA alias traverses above held root")
                            base_parts.pop()
                            target_parts.pop(0)
                    # Never collapse a/..: a may itself be an unobserved alias.
                    # Only leading .. through held real ancestors is admissible.
                    need(bool(target_parts) and all(part not in {"", ".", ".."} for part in target_parts),
                         "Hosted DATA alias target is not canonical")
                    selected = "/" + "/".join(base_parts + target_parts + list(parts[index + 1:]))
                    need(hosted_data_path(selected, domain, directory=directory, common_names=self.common_names),
                         "Hosted DATA alias escapes its closed distro surface")
                    redirected = True
                    break
                need(row["kind"] == ("directory" if index < len(parts) - 1 or directory else "file"),
                     "Hosted DATA selected kind differs")
                parent = row
            if not redirected:
                return row | {"selectedPath": original}

    def post(self):
        for row in self.entries.values():
            self._post_one(row)

    def normalize(self):
        self.post()  # No mutation until every selected original has been admitted.
        for row in self.entries.values():
            if not (row["path"] == "/usr/share" or row["path"].startswith("/usr/share/")) or row["kind"] == "link":
                continue
            mode = 0o755 if row["kind"] == "directory" else 0o644
            if stat.S_IMODE(row["identity"][2]) == mode:
                continue
            self._post_one(row)
            self.mode_attempts += 1  # A failing fchmod may already have taken effect.
            os.fchmod(row["fd"], mode)
            after = identity(os.fstat(row["fd"]))
            need(hosted_data_mode_transition(row["identity"], after, mode),
                 "Hosted DATA mode operation changed another original property")
            row["identity"] = after
            self._post_one(row)
        self.post()

    def receipt(self):
        rows = []
        for row in self.entries.values():
            value = {"path": row["path"], "kind": row["kind"],
                     "beforeMode": oct(stat.S_IMODE(row["original"][2])),
                     "afterMode": oct(stat.S_IMODE(row["identity"][2]))}
            if "body" in row:
                value.update(size=len(row["body"]), sha256=hashlib.sha256(row["body"]).hexdigest())
            if "children" in row:
                value.update(childrenSha256=hashlib.sha256(canonical(row["children"])).hexdigest(),
                             childCount=len(row["children"]))
            if "target" in row:
                value["target"] = row["target"]
            rows.append(value)
        return sorted(rows, key=lambda row: row["path"])

    def finish(self):
        errors = []
        try:
            self.post()
        except BaseException:
            errors.append("hosted-data-post")
        for row in reversed(list(self.entries.values())):
            descriptor, row["fd"] = row["fd"], None
            if descriptor is None:
                continue
            try:
                os.close(descriptor)
            except BaseException:
                errors.append("hosted-data-close")
        return errors


def prepare_hosted_distro_data(manager, D):
    """Normalize only trusted fresh-image DATA before original OS bindings.

    runner-images makes /usr/share recursively writable. Canonical DATA modes
    are prepared on this disposable job VM, not on developer/shared machines.
    This is neither content authentication after untrusted execution nor a
    relaxation of protected_host_file/shell_host_binding or their postchecks.
    """
    need(os.getuid() == os.geteuid() == 0 and sys.platform == "linux"
         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
         and os.environ.get("RUNNER_OS") == "Linux" and os.environ.get("RUNNER_ARCH") == "X64"
         and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
         and not manager.live and not manager.pending and not manager.results,
         "Hosted distro DATA setup requires the original pre-worker disposable VM")
    scope, failure, output = HostedDistroData(D.U.COMMON_LICENSES), None, None
    packages = {}

    def command(_label, argv, **options):
        return manager.control(argv, **options)

    def package_owner(path):
        result = manager.control(["/usr/bin/dpkg-query", "-S", path], timeout=15, limit=4096)
        name, separator, member = result.stdout.decode("ascii").rstrip("\n").rpartition(": ")
        need(result.stderr == b"" and result.stdout.count(b"\n") == 1 and separator
             and member == path and re.fullmatch(r"[a-z0-9][a-z0-9+.-]+(?::amd64)?", name),
             "Hosted distro DATA member ownership is ambiguous")
        if name not in packages:
            fields = "\t".join("$" + "{" + key + "}" for key in (
                "binary:Package", "db:Status-Status", "Version", "Architecture", "source:Package", "source:Version")) + "\n"
            result = manager.control(["/usr/bin/dpkg-query", "-W", "-f=" + fields, name], timeout=15, limit=4096)
            values = result.stdout.decode("ascii").rstrip("\n").split("\t")
            need(result.stderr == b"" and result.stdout.count(b"\n") == 1 and len(values) == 6
                 and values[0].split(":")[0] == name.split(":")[0] and values[1] == "installed"
                 and values[3] in {"amd64", "all"} and re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", values[4])
                 and all(re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", values[index]) for index in (2, 5)),
                 "Hosted distro DATA supplier tuple differs")
            packages[name] = {"binaryPackage": values[0], "version": values[2], "architecture": values[3],
                              "sourcePackage": values[4], "sourceVersion": values[5]}
        return packages[name]

    try:
        support = D.support_inputs(command)
        references, copyrights = set(), []
        for name in sorted({row["package"] for row in support["support"].values()}):
            package = support["packages"][name]
            need(package["sourcePackage"] in {"glibc", "gcc-13", "gcc-14"},
                 "Hosted compiler support source is outside the reviewed Ubuntu profile")
            path = "/usr/share/doc/" + package["binaryPackage"].split(":")[0] + "/copyright"
            selected = scope.bind(path, "documentation")
            supplier = package_owner(selected["path"])
            need(all(supplier[key] == package[key] for key in ("sourcePackage", "sourceVersion")),
                 "Hosted copyright is not from its actual linked support source")
            found = {item.decode("ascii").rstrip(".")
                     for item in re.findall(D.U.COMMON_LICENSE_PATTERN, selected["body"])}
            need(found <= set(D.U.COMMON_LICENSES), "Hosted copyright common-license reference differs")
            references |= found
            copyrights.append({"selectedPath": path, "canonicalPath": selected["path"],
                               "supportPackage": package, "supplier": supplier, "commonReferences": sorted(found)})
        for name in sorted(references):
            selected = scope.bind("/usr/share/common-licenses/" + name, "common-license")
            supplier = package_owner(selected["path"])
            need(supplier["binaryPackage"].split(":")[0] == supplier["sourcePackage"] == "base-files",
                 "Hosted common license is not original distro DATA")
        egl = scope.bind("/usr/share/glvnd/egl_vendor.d", "egl", directory=True)
        need(0 < len(egl["children"]) <= 32, "Hosted EGL selector roster bound")
        for name in egl["children"]:
            selected = scope.bind(egl["path"] + "/" + name, "egl")
            supplier = package_owner(selected["path"])
            need(supplier["binaryPackage"].split(":")[0] == "libegl-mesa0"
                 and supplier["sourcePackage"] == "mesa", "Hosted EGL selector is not reviewed Mesa DATA")
            value = D.D.decode(selected["body"], 64 << 10)
            need(type(value) is dict and set(value) == {"file_format_version", "ICD"}
                 and value["file_format_version"] == "1.0.0" and type(value["ICD"]) is dict
                 and set(value["ICD"]) == {"library_path"} and value["ICD"]["library_path"] == "libEGL_mesa.so.0",
                 "Hosted EGL selector does not name the actual reviewed Mesa provider")
        scope.bind("/usr/share/applications", "applications", directory=True)
        scope.normalize()
        D.support_unchanged(support)
        output = {"schema": "mrk-ubuntu-alpha-hosted-data-preparation-v1",
                  "scope": "fresh-disposable-hosted-vm-before-project-workers",
                  "sourceSha": os.environ["GITHUB_SHA"], "modeChanges": scope.mode_attempts,
                  "files": scope.receipt(), "copyrights": copyrights,
                  "packages": packages, "bytesUnchanged": True, "ownershipUnchanged": True,
                  "membershipUnchanged": True, "originalsClosed": False}
    except BaseException as error:
        failure = error
    finally:
        errors = scope.finish()
        manager.errors.extend(errors)
        if errors and failure is None:
            failure = Refused("Hosted distro DATA finality is incomplete")
    if failure is not None:
        # No rollback/retry: the disposable job stops; unchanged guards remain.
        try:
            sys.stderr.write(canonical({"schema": "mrk-ubuntu-alpha-hosted-data-preparation-failure-v1",
                "modeChangeAttempted": scope.mode_attempts > 0, "postOrCloseErrors": len(errors),
                "projectWorkerStartAttempted": False}).decode("ascii") + "\n")
        except (OSError, ValueError):
            pass
        raise failure
    output["originalsClosed"] = True
    return output


def snapshot_source(original, destination, configuration, manager):
    git = ["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
           "-c", "core.hooksPath=/dev/null", "-c", "safe.directory=" + str(original), "-C", str(original)]
    head = manager.control(git + ["rev-parse", "--verify", "HEAD"], limit=4096).stdout.decode().strip()
    need(head == configuration["sourceSha"], "Checkout HEAD differs from the reviewed source")
    tree = manager.control(git + ["rev-parse", "--verify", head + "^{tree}"], limit=4096).stdout.decode().strip()
    need(re.fullmatch(r"[0-9a-f]{40}", tree), "Source tree identity differs")
    listing = manager.control(git + ["ls-tree", "-r", "-z", "--full-tree", head], limit=2 << 20).stdout
    values = listing.split(b"\0")
    need(values[-1] == b"" and 1 <= len(values) - 1 <= 4096, "Tracked source inventory bound")
    records, folded, total = [], set(), 0
    make_directory(destination, 0o755)
    for item in values[:-1]:
        prefix, separator, encoded_path = item.partition(b"\t")
        pieces = prefix.decode("ascii").split(" ")
        name = encoded_path.decode("utf-8")
        path = Path(name)
        need(separator and len(pieces) == 3 and pieces[0] in ("100644", "100755") and pieces[1] == "blob"
             and re.fullmatch(r"[0-9a-f]{40}", pieces[2]) and not path.is_absolute()
             and all(part not in ("", ".", "..", ".git") for part in path.parts)
             and name.casefold() not in folded and len(path.parts) <= 32,
             "Tracked source member differs")
        folded.add(name.casefold())
        raw = read(original / name, 32 << 20)
        need(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == pieces[2],
             "Checkout source bytes differ from the exact reviewed commit")
        total += len(raw)
        need(total <= 256 << 20, "Tracked source byte bound")
        target = destination / name
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        pin = write_new(target, raw, 0o555 if pieces[0] == "100755" else 0o444)
        records.append({"path": name, "size": pin["size"], "sha256": pin["sha256"], "gitMode": pieces[0], "gitBlob": pieces[2]})
    need(not any((destination / relative).exists() for relative in GENERATED), "Generated source outputs already exist")
    for root, directories, _ in os.walk(destination, topdown=False, followlinks=False):
        for name in directories:
            os.chmod(Path(root) / name, 0o555)
    os.chmod(destination, 0o555)
    return {"sourceSha": head, "sourceTree": tree, "files": sorted(records, key=lambda row: row["path"])}


def copy_node_tool(original, destination):
    """Copy the fixed setup-node installation, not the runner home or config."""
    selected = original.resolve(strict=True)
    need(selected.name == "node" and selected.parent.name == "bin" and str(selected).startswith("/opt/hostedtoolcache/node/"),
         "Node is not the setup-node toolchain")
    source = selected.parent.parent
    make_directory(destination, 0o755)
    entries, total = 0, 0
    for root, directories, names in os.walk(source, followlinks=False):
        relative = Path(root).relative_to(source)
        target_root = destination / relative
        if relative != Path("."):
            target_root.mkdir(mode=0o755)
        for name in sorted(directories):
            path = Path(root) / name
            need(stat.S_ISDIR(path.lstat().st_mode), "Node toolchain directory alias is not admitted")
        for name in sorted(names):
            path = Path(root) / name
            actual = path.resolve(strict=True)
            need(actual.is_relative_to(source), "Node toolchain file alias escapes its original installation")
            before = ordinary(actual)
            entries += 1
            total += before["size"]
            need(entries <= 16384 and total <= 512 << 20, "Fixed Node input inventory bound")
            copy_file(actual, target_root / name, expected=before,
                      mode=0o555 if before["identity"][2] & 0o111 else 0o444)
    for root, directories, _ in os.walk(destination, topdown=False):
        for name in directories:
            os.chmod(Path(root) / name, 0o555)
    os.chmod(destination, 0o555)


def seal_acquired(path):
    """After original-unit finality, only root retains mutable compiler inputs."""
    count, total = 0, 0
    for root, directories, names in os.walk(path, topdown=False, followlinks=False):
        for name in [*names, *directories]:
            selected = Path(root) / name
            item = selected.lstat()
            count += 1
            need(count <= 131072 and item.st_dev == path.lstat().st_dev, "Acquired input count/mount bound")
            if stat.S_ISLNK(item.st_mode):
                need(selected.resolve(strict=True).is_relative_to(path), "Acquired alias escapes its exact input tree")
                os.chown(selected, 0, 0, follow_symlinks=False)
            elif stat.S_ISREG(item.st_mode):
                need(item.st_nlink == 1 and not item.st_mode & 0o7000, "Acquired input is nonordinary")
                total += item.st_size
                need(total <= 4 << 30, "Acquired input byte bound")
                os.chown(selected, 0, 0)
                os.chmod(selected, 0o555 if item.st_mode & 0o111 else 0o444)
            else:
                need(stat.S_ISDIR(item.st_mode), "Acquired input special entry")
                os.chown(selected, 0, 0)
                os.chmod(selected, 0o555)
    os.chown(path, 0, 0)
    os.chmod(path, 0o555)
    return {"entries": count, "bytes": total}


def create_account(manager, name):
    try:
        pwd.getpwnam(name)
    except KeyError:
        pass
    else:
        raise Refused("Task account already exists")
    try:
        grp.getgrnam(name)
    except KeyError:
        pass
    else:
        raise Refused("Task group already exists")
    manager.control(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home",
                     "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", name])
    account, group = pwd.getpwnam(name), grp.getgrnam(name)
    need(account.pw_uid != 0 and account.pw_gid == group.gr_gid and not group.gr_mem,
         "Fresh task account/group differs")
    return {"name": name, "uid": account.pw_uid, "gid": account.pw_gid}


def ordinary_members(source, destination, rows, *, owner=None):
    make_directory(destination, 0o755)
    expected = {row["path"]: row for row in rows}
    need(len(expected) == len(rows) and len(rows) <= 8192, "Transferred output roster differs")
    actual = set()
    for root, directories, names in os.walk(source, followlinks=False):
        for name in directories:
            need(stat.S_ISDIR((Path(root) / name).lstat().st_mode), "Transfer directory is nonordinary")
        for name in names:
            actual.add((Path(root) / name).relative_to(source).as_posix())
    need(actual == set(expected), "Transfer source has an extra or missing member")
    for name, row in sorted(expected.items()):
        target = destination / name
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        copy_file(source / name, target, expected=row, mode=0o444, owner=owner)
    for root, directories, _ in os.walk(destination, topdown=False):
        for name in directories:
            os.chmod(Path(root) / name, 0o555)
    os.chmod(destination, 0o555)


def transfer_build(task, configuration, event_rows, D):
    need([row["event"] for row in event_rows] == ["inputs-admitted", "binary-retained", "binary-retained", "built"]
         and [row["role"] for row in event_rows[1:3]] == ["main", "publisher"],
         "Original compiler event order differs")
    result = event_rows[3]["result"]
    pre_notices = D.D.records(event_rows[0]["noticeFiles"])
    final_notices = D.D.records(result["noticeFiles"])
    need(set(final_notices) == set(pre_notices) | {"BUILD-OUTPUTS.json"}
         and all(final_notices[name] == row for name, row in pre_notices.items()),
         "Precompile notice originals changed or disappeared after compilation")
    policy, current_runtime, _ = D.current_controls(task / "source")
    need(result["policy"] == policy and D.D.same(D.D.records(result["runtimeFiles"]), current_runtime),
         "Original build current-runtime binding differs")
    compiler = {}
    for index, role in enumerate(("main", "publisher")):
        expected = result["compiler"][role]
        need(event_rows[index + 1]["record"] == expected, "Original immediate compiler receipt changed later")
        for key, path in (("original", task / "build/target" / TARGET / "debug" / D.ROLES[role][0]),
                          ("retained", task / "build/compiled" / D.ROLES[role][0])):
            observed = ordinary(path, owner=configuration["accounts"]["build"]["uid"], executable=True, hardlinks=key == "original")
            item = path.lstat()
            need(expected[key]["path"] == str(path) and list((*D.D.state(item), item.st_uid, item.st_gid)) == expected[key]["identity"]
                 and all(observed[field] == expected[key][field] for field in ("size", "sha256")),
                 "Original compiler output changed after worker finality")
        compiler[role] = {field: expected["retained"][field] for field in ("size", "sha256")}
    compiled_rows = [{"path": D.ROLES[role][0], **compiler[role]} for role in ("main", "publisher")]
    ordinary_members(task / "build/compiled", task / "package/compiled", compiled_rows,
                     owner=configuration["accounts"]["build"]["uid"])
    ordinary_members(task / "build/current-runtime", task / "package/runtime", result["runtimeFiles"],
                     owner=configuration["accounts"]["build"]["uid"])
    ordinary_members(task / "build/desktop-notices", task / "package/desktop-notices", result["noticeFiles"],
                     owner=configuration["accounts"]["build"]["uid"])
    a_rows = D.C.CONVENTIONAL_SMOKE_INPUTS["preparedArtifact"]["files"]
    ordinary_members(task / "build/admitted-a", task / "package/admitted-a", a_rows, owner=0)
    D.dependencies_unchanged(result["dependencies"])
    write_new(task / "control/package-inputs.json", canonical({
        "compiler": compiler, "policy": policy, "noticeFiles": result["noticeFiles"],
        "depends": result["dependencies"]["depends"]}))
    return result


def preserve_logs(source, destination, uid):
    """Copy only finite flat original command captures after domain finality."""
    initial = source.lstat()
    need(stat.S_ISDIR(initial.st_mode) and initial.st_uid == uid
         and not initial.st_mode & 0o7022, "Original command log directory differs")
    entries = sorted(source.iterdir(), key=lambda path: path.name)
    need(len(entries) <= 3072 and all(re.fullmatch(
        r"[0-9]{4}-[a-z0-9][a-z0-9-]{0,79}\.(stdout|stderr)", path.name) for path in entries),
        "Original command log roster differs")
    make_directory(destination, 0o700)
    total = 0
    for path in entries:
        pin = ordinary(path, limit=MAX_CAPTURE, owner=uid)
        total += pin["size"]
        need(total <= 128 << 20, "Original command logs exceed retained byte bound")
        copy_file(path, destination / path.name, expected=pin, owner=uid, mode=0o400)
    need(identity(source.lstat()) == identity(initial)
         and sorted(path.name for path in source.iterdir()) == [path.name for path in entries],
         "Original command log directory changed after finality")


def remove_owned_tree(path, task, *, all_final):
    need(all_final and path.parent == task and path.name in {"source", "tools", "acquire", "build", "package"},
         "Only final task-owned disposable roots may be removed")
    value = path.lstat()
    need(stat.S_ISDIR(value.st_mode) and value.st_dev == task.lstat().st_dev
         and shutil.rmtree.avoids_symlink_attacks, "Disposable root/mount/cleanup support differs")
    for root, directories, _ in os.walk(path, followlinks=False):
        for name in directories:
            child = Path(root) / name
            item = child.lstat()
            need(stat.S_ISLNK(item.st_mode) or stat.S_ISDIR(item.st_mode)
                 and item.st_dev == value.st_dev, "Disposable tree contains another mount")
    shutil.rmtree(path)
    need(not path.exists() and not path.is_symlink(), "Disposable root remains after removal")



def public_cgroup_diagnostic(value):
    """Only a closed operation tag and actual numeric OS observations."""
    if (type(value) is not dict or set(value) != {"operation", "errno", "eventsReadErrno"}
            or type(value["operation"]) is not str or value["operation"] not in CGROUP_OPERATIONS
            or not (value["errno"] is None or type(value["errno"]) is int and 1 <= value["errno"] <= 4095)
            or not (value["eventsReadErrno"] is None
                    or type(value["eventsReadErrno"]) is int and value["eventsReadErrno"] == errno.ENODEV)):
        return None
    return {key: value[key] for key in ("operation", "errno", "eventsReadErrno")}


def failure_summary(task, manager, failure, phase, role, finality):
    """Small public diagnostic projection; original captures stay private."""
    value = {"schema": "mrk-ubuntu-alpha-failure-v1", "phase": phase, "role": role,
             "errorClass": type(failure).__name__, "originalFinality": finality}
    cgroup_observation = public_cgroup_diagnostic(manager.cgroup_failure)
    if cgroup_observation is not None:
        value["cgroupObservation"] = cgroup_observation
    if manager.clients:
        value["lastManagerClient"] = {key: manager.clients[-1][key] for key in (
            "program", "exit", "joined", "eof", "withinDeadline", "outputOverflow", "final",
            "stdoutBytes", "stderrBytes", "stdoutSha256", "stderrSha256")}
    if manager.results:
        last = next((row for row in reversed(manager.results) if row["role"] == role), manager.results[-1])
        value["unit"] = {"role": last["role"], "finality": last["originalCgroupFinality"],
                         "closed": last["closed"]}
        retirement_errno = last.get("retirementReadErrno")
        if type(retirement_errno) is int and retirement_errno == errno.ENODEV:
            value["unit"]["retirementReadErrno"] = retirement_errno
        original = last.get("mainBeforeStop")
        if original is not None:
            value["unit"]["result"] = original["Result"]
            value["unit"]["exitCode"] = original["ExecMainCode"]
            value["unit"]["exitStatus"] = original["ExecMainStatus"]
    if finality and role in ROLES:
        try:
            raw = read(task / "private" / (role + ".stdout"), MAX_CAPTURE, 0)
            for line in raw.splitlines():
                if len(line) > 8 << 20:
                    continue
                event = json.loads(line)
                if type(event) is not dict or event.get("event") != "command-failed":
                    continue
                item = event.get("command")
                if (type(item) is not dict or type(item.get("label")) is not str
                        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", item["label"])
                        or not (item.get("exit") is None or type(item["exit"]) is int and -255 <= item["exit"] <= 255)
                        or not all(type(item.get(key)) is int and 0 <= item[key] <= MAX_CAPTURE
                                   for key in ("stdoutBytes", "stderrBytes"))
                        or not all(type(item.get(key)) is str and re.fullmatch(r"[0-9a-f]{64}", item[key])
                                   for key in ("stdoutSha256", "stderrSha256"))):
                    continue
                value["command"] = {key: item[key] for key in (
                    "label", "exit", "stdoutBytes", "stderrBytes", "stdoutSha256", "stderrSha256")}
                value["command"]["compilerDiagnostics"] = public_compiler_diagnostics(item.get("compilerDiagnostics"))
                break
        except (OSError, ValueError, UnicodeError):
            value["workerDiagnostic"] = "unavailable"
    return value


def prepare_route(args):
    phase, task_directory_may_exist = "host-identity", False
    try:
        need(os.getuid() == os.geteuid() == 0 and sys.platform == "linux", "Hosted Linux owner required")
        phase = "workflow-identity"
        need(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ.get("RUNNER_OS") == "Linux"
             and os.environ.get("RUNNER_ARCH") == "X64" and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
             and os.environ.get("GITHUB_REF") == REF and os.environ.get("GITHUB_EVENT_NAME") in ("push", "workflow_dispatch")
             and os.environ.get("GITHUB_SHA") == args.source_sha
             and os.environ.get("GITHUB_WORKFLOW_SHA") == args.source_sha
             and os.environ.get("GITHUB_WORKFLOW_REF") == REPOSITORY + "/" + WORKFLOW + "@" + REF,
             "Only the exact reviewed nonrelease GitHub-hosted dispatch is allowed")
        phase = "workflow-coordinates"
        need(re.fullmatch(r"[0-9a-f]{40}", args.source_sha) and re.fullmatch(r"[1-9][0-9]{0,17}", args.run_id)
             and re.fullmatch(r"[1-9][0-9]{0,3}", args.attempt), "Original workflow coordinates differ")
        phase = "ubuntu-release"
        release = Path("/etc/os-release").read_text()
        need(re.search(r'^ID=ubuntu$', release, re.M) and re.search(r'^VERSION_ID="24\.04"$', release, re.M),
             "This alpha producer supports only Ubuntu 24.04")
        phase = "cgroup-v2"
        need(Path("/sys/fs/cgroup/cgroup.controllers").is_file(), "Unified cgroup v2 is required")
        phase = "protected-task-parent"
        protected_parent(TASK_PARENT)
        phase = "task-nonce"
        nonce = os.urandom(12).hex()
        task = TASK_PARENT / ("mrk-alpha-" + args.run_id + "-" + args.attempt + "-" + nonce)
        phase = "create-task-directory"
        task_directory_may_exist = True
        make_directory(task, 0o755)
        phase = "create-task-subdirectories"
        for name in ("owner", "private", "control", "public"):
            make_directory(task / name, 0o755 if name in ("public", "control") else 0o700)
        for name in ("home", "tmp"):
            make_directory(task / "owner" / name)
        phase = "resource-pressure"
        pressure(task)
        phase = "initialize-manager"
        configuration = {
            "schema": "mrk-ubuntu-alpha-owner-v1", "sourceSha": args.source_sha,
            "runId": args.run_id, "attempt": args.attempt, "nonce": nonce,
            "deadlineNs": time.monotonic_ns() + MAX_SECONDS * 1_000_000_000,
            "units": {role: "mrk-alpha-" + nonce + "-" + role + ".service" for role in ROLES},
            "accounts": {}, "githubTooling": {
                "MRK_GITHUB_PREFLIGHT_TOOLING_SHA": ALPHA_TOOLING_SHA,
                "MRK_GITHUB_RELEASE_TOOLING_SHA": ALPHA_TOOLING_SHA},
        }
        manager = UnitOwner(task, configuration)
        return task, configuration, manager
    except BaseException as error:
        write_startup_diagnostic(phase, error, task_directory_may_exist=task_directory_may_exist)
        raise


def route(args):
    task, configuration, manager = prepare_route(args)
    nonce = configuration["nonce"]
    accounts, source_record, build, package, failure = [], None, None, None, None
    try:
        manager.phase = "create-build-account"
        builder = create_account(manager, "mrkab" + nonce[:12])
        accounts.append(builder)
        manager.phase = "create-package-account"
        packager = create_account(manager, "mrkap" + nonce[:12])
        accounts.append(packager)
        configuration["accounts"] = {"acquire": builder, "build": builder, "package": packager}
        manager.phase = "snapshot-source"
        source_record = snapshot_source(args.source, task / "source", configuration, manager)
        manager.phase = "current-runtime-controls"
        D = load_data(task / "source")
        D.current_controls(task / "source")
        manager.phase = "prepare-hosted-distro-data"
        hosted_data = prepare_hosted_distro_data(manager, D)
        write_new(task / "public/hosted-data-preparation.json", canonical(hosted_data))
        for relative in GENERATED:
            parent = task / "source" / relative
            make_directory(parent, 0o700, builder["uid"], builder["gid"])
        manager.phase = "admit-build-tools"
        make_directory(task / "tools", 0o755)
        copy_node_tool(args.node, task / "tools/node")
        copy_file(args.rustup.resolve(strict=True), task / "tools/rustup", mode=0o555)
        os.chmod(task / "tools", 0o555)
        for role in ROLES:
            account = configuration["accounts"][role]
            make_directory(task / role, 0o755 if role == "package" else 0o700,
                           0 if role == "package" else account["uid"], 0 if role == "package" else account["gid"])
            for name in ("home", "tmp", "logs"):
                make_directory(task / role / name, 0o700, account["uid"], account["gid"])
            for suffix in ("stdout", "stderr"):
                write_new(task / "private" / (role + "." + suffix), b"", 0o600)
        for name in ("cargo", "rustup", "npm-cache"):
            make_directory(task / "acquire" / name, 0o700, builder["uid"], builder["gid"])
        make_directory(task / "build/cargo", 0o700, builder["uid"], builder["gid"])
        for name in ("cargo/registry", "rustup"):
            make_directory(task / "build" / name, 0o555)
        for name in ("target",):
            make_directory(task / "build" / name, 0o700, builder["uid"], builder["gid"])
        for name in ("generated", "export"):
            make_directory(task / "package" / name, 0o700, packager["uid"], packager["gid"])
        for name in ("npmrc-user", "npmrc-global"):
            write_new(task / "control" / name, b"")
        ordinary_members(args.supplier, task / "build/admitted-a",
                         D.C.CONVENTIONAL_SMOKE_INPUTS["preparedArtifact"]["files"])
        write_new(task / "control/configuration.json", canonical(configuration))
        acquired, _ = manager.run("acquire")
        need(len(acquired) == 1 and acquired[0]["event"] == "acquired", "Original acquisition event differs")
        for path in (task / "acquire/rustup", task / "acquire/cargo/registry", task / "source/desktop/node_modules"):
            seal_acquired(path)
        built, _ = manager.run("build")
        manager.phase = "transfer-built-inputs"
        build = transfer_build(task, configuration, built, D)
        packaged, _ = manager.run("package")
        need(len(packaged) == 1 and packaged[0]["event"] == "packaged", "Original package event differs")
        package = packaged[0]["result"]
        need(package["installed"] is False and package["qualified"] is False and package["publicRelease"] is False,
             "Package staging cannot claim installation, native acceptance, or a release")
        manager.phase = "export-package"
        original = Path(package["package"]["path"])
        need(original.parent == task / "package/export" and original.suffix == ".deb", "Package export role differs")
        final_file = copy_file(original, task / "public" / original.name, expected=package["package"],
                               mode=0o444, owner=packager["uid"])
        package["package"] = {field: final_file[field] for field in ("size", "sha256")}
        package["package"]["name"] = original.name
    except BaseException as error:
        failure = error
    finally:
        failure_phase, failure_role = manager.phase, manager.role
        failed_before_cleanup = failure is not None
        for role in list(manager.live):
            try:
                manager.stop_original(role)
            except BaseException as error:
                failure = failure or error
        for role, original in manager.live.items():
            # An uncertain domain remains uncertain: consume only our retained
            # descriptors, never stop a replacement or call this cleanup success.
            descriptor_errors = []
            for key in ("eventsFd", "cgroupFd", "cgroupParentFd"):
                descriptor = original.pop(key, None)
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError as error:
                        descriptor_errors.append(error.errno)
            manager.errors.extend(descriptor_errors)
            manager.results.append({"role": role, "initial": original["initial"],
                "mainBeforeStop": original.get("mainBeforeStop"),
                "originalCgroupFinality": "unknown", "closed": not descriptor_errors,
                "retirementReadErrno": original.get("retirementReadErrno")})
        finality = not manager.live and not manager.pending and not manager.errors and all(row["final"] for row in manager.clients)
        # Retain original small logs/captures, not the compiler/cache gigabytes.
        if finality:
            logs_preserved, outputs_removed = True, True
            for role in ROLES:
                logs = task / role / "logs"
                if logs.exists():
                    destination = task / "private" / (role + "-commands")
                    try:
                        preserve_logs(logs, destination, configuration["accounts"][role]["uid"])
                    except BaseException as error:
                        logs_preserved = False
                        failure = failure or error
            for name in ("source", "tools", "acquire", "build", "package") if logs_preserved else ():
                path = task / name
                if path.exists():
                    try:
                        remove_owned_tree(path, task, all_final=True)
                    except BaseException as error:
                        outputs_removed = False
                        failure = failure or error
            for account in reversed(accounts) if logs_preserved and outputs_removed else ():
                if not all(row["final"] for row in manager.clients):
                    break
                try:
                    actual = pwd.getpwnam(account["name"])
                    need((actual.pw_uid, actual.pw_gid) == (account["uid"], account["gid"]),
                         "Task account changed before removal")
                    manager.control(["/usr/sbin/userdel", account["name"]])
                    try:
                        pwd.getpwnam(account["name"])
                    except KeyError:
                        pass
                    else:
                        raise Refused("Task account remains")
                    try:
                        group = grp.getgrnam(account["name"])
                    except KeyError:
                        pass
                    else:
                        need(group.gr_gid == account["gid"] and not group.gr_mem, "Task group changed")
                        manager.control(["/usr/sbin/groupdel", account["name"]])
                except BaseException as error:
                    failure = failure or error
                    if not all(row["final"] for row in manager.clients):
                        break
        else:
            failure = failure or Refused("Unknown original domain finality; retain all task inputs/outputs")
        finality = finality and all(row["final"] for row in manager.clients)
        write_new(task / "private/finality.json", canonical({
            "units": manager.results, "managerClients": manager.clients, "unknownUnits": sorted(manager.pending | {row["name"] for row in manager.live.values()}),
            "allFinal": finality, "failed": failure is not None,
            "errorClass": type(failure).__name__ if failure is not None else None}))
    if failure is not None:
        # Exact phase/status/hash projection only; never publish private paths,
        # compiler snippets, arbitrary exception text or raw command captures.
        diagnostic = failure_summary(task, manager, failure,
            failure_phase if failed_before_cleanup else "cleanup", failure_role, finality)
        public = canonical(diagnostic)
        need(len(public) <= 16384, "Sanitized diagnostic bound")
        sys.stderr.buffer.write(public + b"\n")
        raise failure
    need(package is not None and build is not None and source_record is not None and len(manager.results) == 3,
         "All three original roles and a real package are required")
    summary = {
        "schema": "mrk-ubuntu-alpha-package-v1", "scope": "pre-release-dev-profile-ordinary-gui-real-publisher",
        "sourceSha": args.source_sha, "sourceTree": source_record["sourceTree"],
        "workflow": WORKFLOW, "runId": args.run_id, "attempt": args.attempt,
        "platform": "ubuntu-24.04-x86_64", "package": package["package"], "packageMembers": package["members"],
        "runtime": {key: build["policy"][key] for key in ("manifestSha256", "protocolSha256", "coreSha256")},
        "runtimeFiles": len(build["runtimeFiles"]), "bootstrapFiles": len(D.P.CURRENT_BOOTSTRAPS),
        "compiler": {role: {"features": record["selection"]["features"], "profile": record["selection"]["profile"],
                            "size": record["retained"]["size"], "sha256": record["retained"]["sha256"]}
                     for role, record in build["compiler"].items()},
        "frontend": {key: build["frontend"][key] for key in ("files", "treeSha256")},
        "githubTooling": {"sourceSha": ALPHA_TOOLING_SHA, "qualification": "pre-release-alpha-source-not-protected-main",
                         "compilerEnvironment": configuration["githubTooling"],
                         "protectedToolingDelivered": False, "productionReady": False},
        "depends": build["dependencies"]["depends"],
        "osPackages": build["dependencies"]["packages"], "staticElfObjects": len(build["dependencies"]["graph"]["objects"]),
        "noticeFiles": len(build["noticeFiles"]), "nativeVerified": False, "installed": False, "publicRelease": False,
        "originalUnitsSucceededAndFinal": True, "disposableBuildOutputsRemoved": True,
        "capabilities": {
            "androidBuild": {"available": False, "reason": "no-admitted-user-machine-toolchain"},
            "iosBuild": {"available": False, "reason": "requires-supported-macos-environment"},
        },
        "limitations": [
            "Unsigned pre-release alpha; not production-ready or a protected distribution release.",
            "Real GUI, private engine and publisher compiled and packaged; no GUI or installer/native run in this job.",
            "Android build requires a separate genuine user-machine tool binding; this alpha supplies no CI-machine substitute.",
            "GitHub tool workflows use an explicitly reviewed alpha source candidate, not protected main.",
            "GitHub publisher/OAuth setup and live Store/release actions are not qualified by this artifact.",
            "macOS, Windows, signing, installed-kernel compatibility and complete lifecycle acceptance remain separate.",
        ],
    }
    write_new(task / "public/package-summary.json", canonical(summary) + b"\n")
    write_new(task / "public/source-files.json", canonical(source_record) + b"\n")
    write_new(task / "public/ALPHA-README.txt", (
        "Mobile Release Kit — Ubuntu 24.04 x86_64 pre-release alpha\n\n"
        "This is the real ordinary GUI and publisher with a bundled private Python/core runtime.\n"
        "End users do not install Python, Rust, npm, or development dependencies.\n"
        "The .deb's Depends field names ordinary OS runtime packages; use Ubuntu's package installer.\n"
        "No application or installer was executed by this package-production job. Native acceptance is separate.\n"
        "Android build is unavailable: this alpha has no admitted user-machine Android toolchain binding.\n"
        "Installing an SDK alone does not enable that action. iOS builds require a supported macOS environment.\n"
        "Read package-summary.json for exact source/runtime/compiler bindings and all limitations.\n"
        "Do not use this unsigned development alpha for public releases or production Store changes.\n"
    ).encode())
    sys.stdout.buffer.write(canonical({"publicDirectory": str(task / "public"), "package": package["package"]}) + b"\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    selected = subcommands.add_parser("owner")
    selected.add_argument("--source", required=True, type=Path)
    selected.add_argument("--source-sha", required=True)
    selected.add_argument("--run-id", required=True)
    selected.add_argument("--attempt", required=True)
    selected.add_argument("--supplier", required=True, type=Path)
    selected.add_argument("--node", required=True, type=Path)
    selected.add_argument("--rustup", required=True, type=Path)
    selected = subcommands.add_parser("worker")
    selected.add_argument("--task", required=True, type=Path)
    selected.add_argument("--role", required=True, choices=ROLES)
    args = parser.parse_args()
    import signal
    def interrupted(_signal, _frame):
        raise InterruptedError("Original owner/worker interrupted")
    for name in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(name, interrupted)
    try:
        if args.command == "worker":
            need(task_path(str(args.task)),
                 "Worker task path differs")
            worker(args.task, args.role)
        else:
            route(args)
    except BaseException as error:
        if args.command == "worker":
            emit("worker-error", errorClass=type(error).__name__)
        else:
            sys.stderr.write("Alpha owner refused: " + type(error).__name__ + "\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
