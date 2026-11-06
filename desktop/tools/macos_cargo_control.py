"""Fixed hosted Cargo comparison DATA and a draining sink; no process controller.

The shell invokes Cargo. GitHub owns the step deadline. This file never starts,
signals, cancels or waits for Cargo, and emits no shipping/libtest qualification.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time

PRODUCT = "f3260553ba539c674a119cab9ac334d6af4c6a3e"
TREE = "b1be19c9f78d534b8473d1f577aa1269c277730b"
BRANCH = "refs/heads/codex/macos-cargo-control"
WORKFLOW = ".github/workflows/desktop-macos-cargo-control.yml"
CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
RUST_BIN = Path("/Users/runner/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin")
TARGET = "aarch64-apple-darwin"
LIMIT = 4 * 1024 * 1024
META_LIMIT = 65536
ROLES = ("npm-ci", "frontend-build", "resident-image-build", "shipping-image-build")


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def save(path, value):
    body = canonical(value)
    need(len(body) <= META_LIMIT, "control-metadata-bound")
    with path.open("xb", buffering=0) as output:
        need(output.write(body) == len(body), "control-metadata-short-write")
        os.fsync(output.fileno())


def data(path):
    body = path.read_bytes()
    need(0 < len(body) <= META_LIMIT, "control-metadata-bound")
    return json.loads(body)


def git(*args):
    # Existing source inventory's ordinary read-only Git primitive.
    result = subprocess.run(["/usr/bin/git", "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null", *args], cwd=CHECKOUT,
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    need(len(result.stdout) <= 2 * 1024 * 1024 and len(result.stderr) <= 65536, "control-git-bound")
    return result.stdout


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def file_hash(path, maximum):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "control-file-type-bound")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        need(identity(before) == identity(os.fstat(stream.fileno())), "control-file-open")
        while block := stream.read(65536):
            h.update(block)
        need(identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat()), "control-file-post")
    return {"bytes": before.st_size, "sha256": h.hexdigest()}


def inventory():
    # Same tracked-blob/size/mode rule as the reviewed source recipe. Untracked
    # generated frontend files are not substituted for any tracked product input.
    rows = git("ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0")
    need(rows[-1] == b"" and len(rows) <= 4096, "control-source-count")
    files = []
    for row in rows[:-1]:
        header, raw_name = row.split(b"\t", 1)
        mode, kind, blob = header.split(b" ")
        name = raw_name.decode("utf-8", "strict")
        need(kind == b"blob" and mode in (b"100644", b"100755")
             and not name.startswith("/") and all(p not in ("", ".", "..") for p in name.split("/")), "control-source-path")
        path = CHECKOUT / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_size <= 32 * 1024 * 1024, "control-source-file")
            digest = hashlib.sha256()
            blob_digest = hashlib.sha1(b"blob " + str(before.st_size).encode() + b"\0")
            size = 0
            while block := os.read(fd, 65536):
                size += len(block)
                need(size <= before.st_size, "control-source-growth")
                digest.update(block)
                blob_digest.update(block)
            need(size == before.st_size and identity(before) == identity(os.fstat(fd))
                 == identity(path.lstat()) and blob_digest.hexdigest() == blob.decode()
                 and bool(before.st_mode & 0o111) == (mode == b"100755"), "control-source-post")
        finally:
            os.close(fd)
        files.append({"path": name, "gitMode": mode.decode(), "blob": blob.decode(),
                      "size": size, "sha256": digest.hexdigest()})
    raw = canonical({"source": PRODUCT, "tree": TREE, "files": files})
    need(len(raw) <= 2 * 1024 * 1024, "control-source-inventory-bound")
    return {"files": len(files), "bytes": sum(row["size"] for row in files),
            "inventorySha256": hashlib.sha256(raw).hexdigest()}


def context(work):
    need(sys.platform == "darwin" and os.uname().machine == "arm64" and os.getuid() != 0
         and os.getuid() == os.geteuid() and sys.version_info[:3] == (3, 14, 7)
         and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode, "control-host")
    expected = {"GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit", "GITHUB_EVENT_NAME": "push",
                "GITHUB_REF": BRANCH, "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
                "RUNNER_ARCH": "ARM64", "GITHUB_WORKSPACE": str(CHECKOUT)}
    need(all(os.environ.get(k) == v for k, v in expected.items()), "control-route")
    need(re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", ""))
         and os.environ.get("GITHUB_WORKFLOW_SHA") == os.environ["GITHUB_SHA"]
         and os.environ.get("GITHUB_WORKFLOW_REF") == "Apdelrahman1911/mobile-release-kit/" + WORKFLOW + "@" + BRANCH,
         "control-workflow-source")
    need(re.fullmatch(r"/Users/runner/work/_temp/mrk-macos-cargo-control\.[A-Za-z0-9_]+", str(work))
         and work.is_dir() and not work.is_symlink() and stat.S_IMODE(work.stat().st_mode) == 0o700, "control-work")
    return {"controlSource": os.environ["GITHUB_SHA"], "productSource": PRODUCT, "productTree": TREE,
            "runId": os.environ["GITHUB_RUN_ID"], "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"]}


def commands(node, npm, work):
    cargo = str(RUST_BIN / "cargo")
    return {
        "npm-ci": [str(node), str(npm), "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", str(work / "npm-cache")],
        "frontend-build": [str(node), str(npm), "run", "build"],
        "resident-image-build": [cargo, "build", "--locked", "--jobs", "1", "--target", TARGET,
            "--message-format=json-render-diagnostics", "--release", "--manifest-path", "../helpers/macos-android-register/Cargo.toml",
            "--config", "profile.release.package.mobile-release-kit-desktop.opt-level=1",
            "--config", "profile.release.package.mrk-android-catalogue-schema.opt-level=1", "--lib"],
        "shipping-image-build": [cargo, "build", "--locked", "--release", "--jobs", "1", "--manifest-path",
            "../helpers/macos-desktop-image/Cargo.toml", "--lib", "--target", TARGET, "--message-format=json-render-diagnostics"],
    }


def environment(node, work, release, npm=False):
    base = dict(PATH=str(RUST_BIN) + ":" + str(node.parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
        HOME="/Users/runner", CARGO_HOME="/Users/runner/.cargo", RUSTUP_HOME="/Users/runner/.rustup",
        RUSTC=str(RUST_BIN / "rustc"), RUSTUP_TOOLCHAIN="1.98.1", RUSTUP_AUTO_INSTALL="0", CARGO_INCREMENTAL="0",
        CARGO_TARGET_DIR=str(work / "cargo-target"), TMPDIR=str(work / "compile-tmp"), LANG="C", LC_ALL="C", TZ="UTC",
        CI="true", DEVELOPER_DIR="/Library/Developer/CommandLineTools", MACOSX_DEPLOYMENT_TARGET="26.0",
        MRK_MACOS_INSTALL_SOURCE_COMMIT=PRODUCT, MRK_IMAGE_RELEASE_ID=release)
    if npm:
        base.update(HOME=str(work / "compile-home"), npm_config_userconfig=str(work / "compile-user.npmrc"),
            npm_config_globalconfig=str(work / "compile-global.npmrc"), npm_config_registry="https://registry.npmjs.org/",
            npm_config_cache=str(work / "npm-cache"), npm_config_update_notifier="false")
    return base


def consume(stream, output, limit=LIMIT):
    """Bounded prefix recorder only. Overflow and write errors still drain input."""
    total = kept = 0
    complete_hash, prefix_hash = hashlib.sha256(), hashlib.sha256()
    error = None
    eof = False
    # read1 performs one underlying pipe read, retaining short live bursts
    # immediately instead of waiting to fill a 64KiB buffered read.
    read = getattr(stream, "read1", stream.read)
    while True:
        try:
            block = read(65536)
        except Exception:
            error = error or "input-read-failed"
            break
        if type(block) is not bytes:
            error = error or "input-read-type"
            break
        if not block:
            eof = True
            break
        total += len(block)
        complete_hash.update(block)
        piece = block[:max(0, limit - kept)] if error is None else b""
        if piece:
            try:
                count = output.write(piece)
                if type(count) is not int or not 0 <= count <= len(piece):
                    error = "output-write-count"
                else:
                    prefix_hash.update(piece[:count])
                    kept += count
                    if count != len(piece):
                        error = "output-short-write"
            except Exception:
                error = "output-write-failed"
    return dict(totalBytes=total, retainedBytes=kept, truncated=total > kept, eof=eof,
        captureError=error, complete=eof and error is None and total == kept,
        retainedSha256=prefix_hash.hexdigest(), completeStreamSha256=complete_hash.hexdigest() if eof else None)


def optional_data(path):
    """Interrupted sidecars are observations of unknown state, never fatal to collection."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(8193)
        if len(raw) > 8192:
            return {"value": None, "state": "oversized"}
        value = json.loads(raw)
        # Enforce an explicit DATA depth bound across Python versions; parser
        # recursion limits do not consistently reject deeply nested JSON.
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            need(depth <= 32, "control-sidecar-depth")
            if type(item) is dict:
                pending.extend((child, depth + 1) for child in item.values())
            elif type(item) is list:
                pending.extend((child, depth + 1) for child in item)
        # Includes exponent overflow (1e999) and JSON NaN/Infinity extensions.
        canonical(value)
        if type(value) is not dict:
            return {"value": None, "state": "wrong-shape"}
        return {"value": value, "state": "read", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    except FileNotFoundError:
        return {"value": None, "state": "missing"}
    except (OSError, ValueError, UnicodeError, RecursionError):
        return {"value": None, "state": "partial-or-unreadable"}


def collect_data(work, bound):
    rows, selected, last_started = [], None, None
    for name in ROLES:
        observations = {kind: optional_data(work / (name + suffix)) for kind, suffix in
            (("start", "-started.json"), ("original", "-original.json"), ("sink", "-sink.json"), ("pipeline", "-pipeline.json"))}
        rows.append({"role": name, "observations": observations})
        if observations["start"]["state"] != "missing":
            last_started = name
        if (work / (name + ".log")).is_file():
            selected = name
    log_path = work / "evidence/merged.log"
    snapshot_error = None
    if selected is not None:
        try:
            with (work / (selected + ".log")).open("rb") as inp, log_path.open("wb", buffering=0) as out:
                remaining = LIMIT
                while remaining:
                    block = inp.read(min(65536, remaining))
                    if not block:
                        break
                    if out.write(block) != len(block):
                        raise OSError("snapshot short write")
                    remaining -= len(block)
                os.fsync(out.fileno())
        except OSError:
            snapshot_error = "partial-or-unreadable"
    try:
        selected_log = file_hash(log_path, LIMIT)
    except (OSError, ValueError):
        selected_log = None
        snapshot_error = "partial-or-unreadable"
    def completed(row):
        fields = row["observations"]
        if not all(fields[k]["state"] == "read" for k in ("start", "original", "sink", "pipeline")):
            return False
        original, sink, pipeline = (fields[k]["value"] for k in ("original", "sink", "pipeline"))
        return (type(original.get("originalReturn")) is int and original["originalReturn"] == 0
            and pipeline.get("components") == [0, 0] and all(type(n) is int for n in pipeline["components"])
            and sink.get("complete") is True and sink.get("eof") is True and sink.get("captureError") is None)
    inputs = {name: optional_data(work / filename) for name, filename in
              (("control", "control-binding.json"), ("tools", "tool-binding.json"), ("product", "product-before.json"))}
    report = dict(bound, kind="mrk-direct-cargo-diagnostic-control-v1", diagnosticOnly=True,
        inputs=inputs, selectedLogRole=selected, lastStartedRole=last_started, selectedLog=selected_log,
        logAttribution="merged direct-command group; includes status-writer errors if any",
        snapshotError=snapshot_error, commands=rows, metadataReduced=False,
        temporaryLogLimitBytesPerRole=LIMIT, temporaryLogAggregateLimitBytes=4 * LIMIT,
        retainedLogAggregateLimitBytes=LIMIT, retainedMetadataLimitBytes=META_LIMIT,
        allDirectCommandsReturnedZeroWithCompleteCaptures=all(completed(row) for row in rows),
        originalResultMissingMeansUnknown=True, partialTimeoutLogNeverQualifies=True,
        outputSnapshotIsOriginalClosureProof=False, fullUnsignedSequenceQualified=False,
        artifactAdmitted=False, testsExecuted=False, signed=False, installed=False)
    if len(canonical(report)) > META_LIMIT:
        # Preserve bounded observations of damaged oversized sidecars; no failed
        # metadata reduction is allowed to erase the available log snapshot.
        for row in rows:
            for observation in row["observations"].values():
                observation["value"] = None
        for observation in inputs.values():
            observation["value"] = None
        report.update(metadataReduced=True, allDirectCommandsReturnedZeroWithCompleteCaptures=False)
    return report


def main():
    action, work_text, *args = sys.argv[1:]
    work = Path(work_text)
    bound = context(work)
    if action == "bootstrap":
        need(git("rev-parse", "HEAD").decode().strip() == bound["controlSource"], "control-checkout")
        expected = {}
        for name in ("macos_cargo_control.py", "macos_cargo_control.sh"):
            original = CHECKOUT / "desktop/tools" / name
            expected[name] = file_hash(original, 65536)
            need(file_hash(work / name, 65536) == expected[name], "control-copy")
        save(work / "control-binding.json", dict(bound, controls=expected,
            workflow=file_hash(CHECKOUT / WORKFLOW, 65536), diagnosticOnly=True))
        (work / "evidence").mkdir(mode=0o700)
        (work / "evidence/merged.log").touch(mode=0o600)
        return
    binding = data(work / "control-binding.json")
    need(all(binding[k] == v for k, v in bound.items()), "control-binding")
    for name, expected in binding["controls"].items():
        need(file_hash(work / name, 65536) == expected, "control-script-changed")
    if action == "prepare":
        need(git("rev-parse", "HEAD").decode().strip() == PRODUCT
             and git("rev-parse", "HEAD^{tree}").decode().strip() == TREE
             and not git("status", "--porcelain=v1", "--untracked-files=all"), "control-product-checkout")
        for path in (CHECKOUT / "desktop/node_modules", CHECKOUT / "desktop/dist"):
            need(not path.exists() and not path.is_symlink(), "control-fresh-frontend")
        for parent in (CHECKOUT / "desktop", *(CHECKOUT / "desktop").parents):
            need(not (parent / ".npmrc").exists() and not (parent / ".npmrc").is_symlink(), "control-npm-config")
        for name in ("npm-cache", "compile-home", "compile-tmp", "cargo-target"):
            (work / name).mkdir(mode=0o700)
        for name in ("compile-user.npmrc", "compile-global.npmrc"):
            (work / name).touch(mode=0o600, exist_ok=False)
        save(work / "product-before.json", inventory())
        return
    if action == "bind-tools":
        node, npm = Path(shutil.which("node")).resolve(strict=True), Path(shutil.which("npm")).resolve(strict=True)
        need(npm == node.parent.parent / "lib/node_modules/npm/bin/npm-cli.js", "control-npm-distribution")
        release = json.loads((CHECKOUT / "desktop/macos-installed-inputs/build-release.json").read_bytes())["release"]
        need(re.fullmatch(r"[a-z0-9_.-]{1,63}", release), "control-release")
        version = subprocess.run([str(node), "--version"], check=True, capture_output=True, timeout=15,
            env=environment(node, work, release), cwd=CHECKOUT / "desktop")
        need(version.stdout == b"v24.20.0\n" and version.stderr == b"", "control-node-version")
        npm_version = subprocess.run([str(node), str(npm), "--version"], check=True, capture_output=True, timeout=15,
            env=environment(node, work, release, npm=True), cwd=CHECKOUT / "desktop")
        need(len(npm_version.stdout) <= 4096 and not npm_version.stderr
             and re.fullmatch(rb"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\n", npm_version.stdout), "control-npm-version")
        tools = {str(p): file_hash(p, 128 * 1024 * 1024) for p in (node, npm, RUST_BIN / "cargo", RUST_BIN / "rustc")}
        save(work / "tool-binding.json", {"tools": tools, "node": str(node), "npm": str(npm), "release": release,
            "nodeVersion": version.stdout.decode().strip(), "npmVersion": npm_version.stdout.decode().strip()})
        return
    role = args[0] if args else None
    if action in ("begin", "returned", "record", "end"):
        need(role in ROLES, "control-role")
    if action == "record":
        # No subprocess, timeout, signal or application-owner call on this path.
        error = None
        output = None
        try:
            output = (work / (role + ".log")).open("r+b", buffering=0)
        except Exception:
            error = "output-open-failed"
        class Discard:
            def write(self, block):
                raise OSError("output unavailable")
        result = consume(sys.stdin.buffer, output if output is not None else Discard())
        if output is not None:
            try:
                os.fsync(output.fileno())
                output.close()
            except Exception:
                error = "output-close-or-sync-failed"
        if error:
            result.update(captureError=error, complete=False)
        save(work / (role + "-sink.json"), result)
        raise SystemExit(0 if result["captureError"] is None and result["eof"] else 1)
    if action == "returned":
        status = int(args[1])
        need(0 <= status <= 255, "control-original-status")
        save(work / (role + "-original.json"), {"role": role, "originalReturn": status,
            "returnedMonotonicNs": time.monotonic_ns(), "elapsedShellSeconds": int(args[2]),
            "elapsedPrecision": "whole Bash SECONDS; excludes later recorder drain",
            "origin": "shell-direct-command-question-mark"})
        return
    if action == "end":
        components = [int(n) for n in args[1:]]
        need(len(components) == 2 and all(0 <= n <= 255 for n in components), "control-pipeline-status")
        original = data(work / (role + "-original.json")) if (work / (role + "-original.json")).exists() else None
        sink = data(work / (role + "-sink.json")) if (work / (role + "-sink.json")).exists() else None
        save(work / (role + "-pipeline.json"), {"components": components, "original": original, "sink": sink})
        good = original is not None and original["originalReturn"] == 0 and components == [0, 0]
        good = good and sink is not None and sink["eof"] is True and sink["captureError"] is None
        raise SystemExit(0 if good else 1)
    if action == "begin":
        for previous in ROLES[:ROLES.index(role)]:
            result = data(work / (previous + "-pipeline.json"))
            need(result["components"] == [0, 0] and result["original"]["originalReturn"] == 0
                 and result["sink"]["eof"] is True and result["sink"]["captureError"] is None, "control-prerequisite")
        need(inventory() == data(work / "product-before.json"), "control-product-changed")
        selected = data(work / "tool-binding.json")
        for name, expected in selected["tools"].items():
            need(file_hash(Path(name), 128 * 1024 * 1024) == expected, "control-tool-changed")
        node, npm = Path(selected["node"]), Path(selected["npm"])
        argv = commands(node, npm, work)[role]
        env = environment(node, work, selected["release"], role in ROLES[:2])
        cwd = CHECKOUT / ("desktop" if role in ROLES[:2] else "desktop/src-tauri")
        save(work / (role + "-started.json"), dict(bound, role=role, argv=argv, environment=env,
            cwd=str(cwd), startedMonotonicNs=time.monotonic_ns(), supervision="github-step-only",
            outputMode="merged-direct-command-group", logLimitBytes=LIMIT))
        (work / (role + ".log")).touch(mode=0o600, exist_ok=False)
        text = "command=(" + " ".join(shlex.quote(v) for v in argv) + ")\n"
        text += "command_environment=(" + " ".join(shlex.quote(k + "=" + v) for k, v in env.items()) + ")\n"
        text += "command_cwd=" + shlex.quote(str(cwd)) + "\n"
        with (work / (role + "-command.sh")).open("x") as out:
            out.write(text)
        return
    if action == "collect":
        save(work / "evidence/control.json", collect_data(work, bound))
        return
    raise ValueError("control-action")


if __name__ == "__main__":
    main()
