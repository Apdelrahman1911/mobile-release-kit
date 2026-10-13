set -euo pipefail
umask 077
ulimit -n 1024
cd /Users/runner/work/mobile-release-kit/mobile-release-kit
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=/Users/runner LANG=C LC_ALL=C TZ=UTC \
  GITHUB_ACTIONS="$GITHUB_ACTIONS" RUNNER_ENVIRONMENT="$RUNNER_ENVIRONMENT" RUNNER_OS="$RUNNER_OS" RUNNER_ARCH="$RUNNER_ARCH" \
  GITHUB_REPOSITORY="$GITHUB_REPOSITORY" GITHUB_EVENT_NAME="$GITHUB_EVENT_NAME" GITHUB_REF="$GITHUB_REF" \
  GITHUB_SHA="$GITHUB_SHA" GITHUB_WORKFLOW_SHA="$GITHUB_WORKFLOW_SHA" GITHUB_WORKFLOW_REF="$GITHUB_WORKFLOW_REF" \
  GITHUB_WORKSPACE="$GITHUB_WORKSPACE" RUNNER_TEMP="$RUNNER_TEMP" GITHUB_JOB="$GITHUB_JOB" \
  GITHUB_RUN_ID="$GITHUB_RUN_ID" GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" GITHUB_OUTPUT="$GITHUB_OUTPUT" \
  "$MRK_PYTHON" -I -S -B - <<'PY_PREPARE'
import hashlib, importlib.util, json, os, platform, re, secrets, shutil, stat, sys, threading, tomllib
from pathlib import Path

CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
WORK_PARENT = Path("/Users/runner/work/_temp")
HOME = Path("/Users/runner")
TARGET = "aarch64-apple-darwin"
TOOLCHAIN = "1.98.1"
SOURCE = os.environ["GITHUB_SHA"]
WORKFLOW = "Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-maintenance-fixture.yml@refs/heads/verify/desktop-macos-maintenance-fixture"
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
phase = "route"
book = None
scratch = None
scratch_identity = None
entered_calls = []
failure = False
source_ordinal = 0

PREPARATION_COMMANDS = (
    "git-tree", "git-roster", "rustc-version", "cargo-version", "fetch-0", "fetch-1", "fetch-2",
)
PREPARATION_PHASES = (
    "route", "source-inventory", "git-tree", "git-roster", "source-roster-decode",
    "source-roster-entry", "source-file-inventory", "source-required-roster",
    "cargo-home-admission", "cargo-configuration", "locked-manifests",
    "repository-toolchain", "rust-tool-admission",
    "rustc-version", "cargo-version", "fetch-0", "fetch-1", "fetch-2", "source-recheck",
    "input-publication",
)
PREPARATION_REFUSALS = (
    "ambient-cargo-configuration", "ambient-cargo-directory", "bootstrap-close-unknown",
    "bootstrap-directory", "bootstrap-directory-changed", "bootstrap-import-changed",
    "bootstrap-loader", "bootstrap-short-read", "bootstrap-source", "bootstrap-source-changed",
    "bootstrap-source-grew", "effective-cargo-clock-binding", "effective-rust-clock-binding", "effective-tool-version",
    "local-source-checksum", "locked-package-shape", "locked-public-source",
    "locked-registry-shape", "preparation-bootstrap-binding", "preparation-detached-source",
    "preparation-original-command-failed", "preparation-platform-account", "preparation-route",
    "preparation-scratch-original", "preparation-scratch-remains", "prepared-input-bound",
    "prepared-rust-tool", "private-work", "repository-toolchain-default", "source-bootstrap-roster",
    "source-file-close-unknown", "source-file-correspondence", "source-roster-bound",
    "source-roster-bytes-mode", "source-roster-entry", "step-output-changed", "step-output-original",
    "step-output-route", "step-output-value", "step-output-write", "tree-shape",
    # Fixed imported fixture filesystem/result predicates, not arbitrary exception text.
    "directory-spelling", "directory-owner-mode", "original-handle-bound", "original-unbound",
    "original-changed", "file-original-policy", "original-short-read", "original-grew",
    "original-owner-return", "output-bound", "output-short-write", "output-readback",
    "output-close-unknown", "required-source-roster", "source-shape", "run-shape",
    "source-run-binding", "source-inventory-binding", "source-inventory-row",
    "effective-rust-binding", "effective-rust-tool", "effective-rust-clock-version", "effective-cargo-clock-version",
)

def preparation_failure_data(error, stage, ordinal, calls):
    """Closed diagnostic DATA only; no output or lifetime authority."""
    reason, category, number = "unknown", "other", None
    if isinstance(error, UnicodeError):
        category = "unicode-error"
    elif isinstance(error, ValueError):
        category = "value-error"
    elif isinstance(error, OSError):
        category = "os-error"
        value = OSError.errno.__get__(error)
        if type(value) is int and 1 <= value <= 255:
            number = value
    elif type(error) is KeyError:
        category = "key-error"
    elif type(error) is TypeError:
        category = "type-error"
    elif type(error) is KeyboardInterrupt:
        category = "interrupted"
    elif type(error) is SystemExit:
        category = "exit"
    if isinstance(error, ValueError):
        args = BaseException.args.__get__(error)
        if type(args) is tuple and len(args) == 1 and type(args[0]) is str and args[0] in PREPARATION_REFUSALS:
            reason = args[0]
    safe_stage = stage if type(stage) is str and stage in PREPARATION_PHASES else "unknown"
    safe_ordinal = (ordinal if safe_stage in ("source-roster-entry", "source-file-inventory", "source-recheck")
                    and type(ordinal) is int and 1 <= ordinal <= 4096 else None)
    safe_calls = None
    if type(calls) is list and len(calls) <= len(PREPARATION_COMMANDS):
        checked = []
        for index, row in enumerate(calls):
            if (type(row) is not dict or set(row) != {"role", "returned"}
                    or type(row["role"]) is not str or row["role"] != PREPARATION_COMMANDS[index]
                    or type(row["returned"]) is not bool):
                break
            checked.append({"role": row["role"], "returned": row["returned"]})
        else:
            safe_calls = checked
    return {"schemaVersion": 1, "diagnosticOnly": True, "phase": safe_stage,
            "reason": reason, "exceptionKind": category, "errno": number,
            "sourceOrdinal": safe_ordinal, "originalCalls": safe_calls}

def need(value, label):
    if not value:
        raise ValueError(label)

def sig(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def bootstrap(relative, name):
    # Actions' exact-SHA checkout is the bootstrap SOURCE trust.
    # Both modules are DATA-only on import. This is not a remote Git
    # object authentication claim or a user-supplied import path.
    path = CHECKOUT / relative
    fds, directories, leaf = [], [], None
    closed = True
    try:
        parent = None
        current = Path("/")
        for piece in path.parent.parts:
            current = Path("/") if piece == "/" else current / piece
            fd = os.open(str(current) if parent is None else piece, FLAGS | os.O_DIRECTORY,
                         dir_fd=parent)
            fds.append(fd)
            before = sig(os.fstat(fd))
            need(stat.S_ISDIR(before[2]) and before[3] in (0, os.getuid())
                 and not before[2] & 0o022, "bootstrap-directory")
            directories.append((fd, parent, str(current) if parent is None else piece, before[:5]))
            parent = fd
        fd = os.open(path.name, FLAGS, dir_fd=parent)
        fds.append(fd)
        before = sig(os.fstat(fd))
        need(stat.S_ISREG(before[2]) and before[3] == os.getuid() and before[5] == 1
             and stat.S_IMODE(before[2]) in (0o444, 0o644) and 0 < before[6] <= 1048576,
             "bootstrap-source")
        leaf = (fd, parent, path.name, before)
        content, offset = bytearray(), 0
        while offset < before[6]:
            part = os.pread(fd, min(65536, before[6] - offset), offset)
            need(part, "bootstrap-short-read")
            content.extend(part)
            offset += len(part)
        need(os.pread(fd, 1, offset) == b"", "bootstrap-source-grew")
        need(sig(os.fstat(fd)) == before
             and sig(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == before,
             "bootstrap-source-changed")
        spec = importlib.util.spec_from_file_location(name, path)
        need(spec is not None and spec.loader is not None and name not in sys.modules, "bootstrap-loader")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        need(sig(os.fstat(fd)) == before
             and sig(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == before,
             "bootstrap-import-changed")
        for held, at, child, expected in directories:
            need(sig(os.fstat(held))[:5] == expected
                 and sig(os.stat(child, dir_fd=at, follow_symlinks=False))[:5] == expected,
                 "bootstrap-directory-changed")
        return module, hashlib.sha256(content).hexdigest()
    finally:
        for fd in reversed(fds):
            try:
                os.close(fd)  # Consuming close; never retry a numeric fd.
            except OSError:
                closed = False
        need(closed, "bootstrap-close-unknown")

def output(name, value):
    need(name in ("root",) and re.fullmatch(r"/Users/runner/work/_temp/mrk-macos-maintenance-fixture\.[A-Za-z0-9]{8}", value),
         "step-output-value")
    path = Path(os.environ["GITHUB_OUTPUT"])
    need(path.parent == WORK_PARENT / "_runner_file_commands"
         and re.fullmatch(r"set_output_[A-Za-z0-9-]+", path.name), "step-output-route")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1, "step-output-original")
        body = (name + "=" + value + "\n").encode("ascii")
        need(os.write(fd, body) == len(body), "step-output-write")
        os.fsync(fd)
        need(sig(os.fstat(fd)) == sig(os.stat(path, follow_symlinks=False)), "step-output-changed")
    finally:
        os.close(fd)

try:
    need(sys.version_info >= (3, 11) and sys.flags.isolated and sys.flags.no_site
         and sys.dont_write_bytecode and sys.platform == "darwin"
         and platform.machine() == "arm64" and platform.mac_ver()[0].split(".")[0] == "26"
         and os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid()
         and threading.current_thread() is threading.main_thread()
         and Path.cwd() == CHECKOUT, "preparation-platform-account")
    required = {
        "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64", "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit",
        "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/verify/desktop-macos-maintenance-fixture",
        "GITHUB_WORKFLOW_REF": WORKFLOW, "GITHUB_WORKFLOW_SHA": SOURCE,
        "GITHUB_WORKSPACE": str(CHECKOUT), "RUNNER_TEMP": str(WORK_PARENT),
        "GITHUB_JOB": "e2_fixture", "HOME": str(HOME),
    }
    need(re.fullmatch(r"[0-9a-f]{40}", SOURCE) and SOURCE != "0" * 40
         and all(os.environ.get(key) == value for key, value in required.items())
         and all(re.fullmatch(r"[1-9][0-9]{0,19}", os.environ.get(key, ""))
                 for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "preparation-route")

    fixture, fixture_hash = bootstrap("desktop/tools/macos_e2_native_fixture.py", "_mrk_e2_prepare_fixture")
    qualification, qualification_hash = bootstrap("desktop/tools/macos_aqua_qualification.py", "_mrk_e2_prepare_owner_loader")
    book = fixture.Originals()
    need(book.file(CHECKOUT / ".git/HEAD", 64, modes=(0o600, 0o644))[1] == (SOURCE + "\n").encode("ascii"),
         "preparation-detached-source")
    # Hold the actual bootstrap and pinned command-owner closure.
    for relative, expected in (
        ("desktop/tools/macos_e2_native_fixture.py", fixture_hash),
        ("desktop/tools/macos_aqua_qualification.py", qualification_hash),
        *(("src/mobile_release/" + name, pin) for name, pin in qualification.OWNER_PINS.items()),
    ):
        entry, content = book.file(CHECKOUT / relative, 1048576, modes=(0o444, 0o644))
        need(hashlib.sha256(content).hexdigest() == expected, "preparation-bootstrap-binding")
    owner = qualification.load_owner(CHECKOUT)
    book.check()

    parent = book.directory(WORK_PARENT)
    work = WORK_PARENT / ("mrk-macos-maintenance-fixture." + secrets.token_hex(4))
    os.mkdir(work.name, 0o700, dir_fd=parent["fd"])  # Exclusive; a collision refuses.
    work_entry = book.directory(work)
    work_info = os.fstat(work_entry["fd"])
    need(work_info.st_uid == os.getuid() and stat.S_IMODE(work_info.st_mode) == 0o700, "private-work")
    output("root", str(work))
    scratch = work / "preparation"
    os.mkdir(scratch.name, 0o700, dir_fd=work_entry["fd"])
    scratch_entry = book.directory(scratch)
    scratch_identity = sig(os.fstat(scratch_entry["fd"]))[:5]
    for name in ("home", "tmp"):
        os.mkdir(name, 0o700, dir_fd=scratch_entry["fd"])
        book.directory(scratch / name)

    clean = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(scratch / "home"),
        "TMPDIR": str(scratch / "tmp"), "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
    }
    git_env = dict(clean, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
                   GIT_CONFIG_SYSTEM="/dev/null", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    git_prefix = ["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                  "-c", "credential.helper=", "-c", "core.autocrlf=false"]

    def call(role, argv, environment, timeout, limit=65536, cwd=CHECKOUT):
        global phase
        phase = role
        book.check()
        record = {"role": role, "returned": False}
        entered_calls.append(record)
        result = owner.run_owned(argv, environ=environment, cwd=cwd, timeout=timeout,
                                 capture=True, text=False, output_limit=limit)
        fixture.completed(result, argv, limit)
        record["returned"] = True
        # Bounded raw diagnostics remain PRIVATE, never an artifact glob.
        book.publish(work / ("prepare-" + role + ".stdout"), result.stdout)
        book.publish(work / ("prepare-" + role + ".stderr"), result.stderr)
        book.check()
        need(result.returncode == 0, "preparation-original-command-failed")
        return result.stdout

    phase = "source-inventory"
    tree_output = call("git-tree", git_prefix + ["rev-parse", "--verify", SOURCE + "^{tree}"], git_env, 15, 4096)
    need(re.fullmatch(rb"[0-9a-f]{40}\n", tree_output), "tree-shape")
    tree = tree_output.decode("ascii").strip()
    roster = call("git-roster", git_prefix + ["ls-tree", "-r", "-z", "--full-tree", SOURCE], git_env, 15, 2097152)
    phase = "source-roster-decode"
    raw_rows = roster.split(b"\0")
    need(raw_rows[-1] == b"" and 1 < len(raw_rows) <= 4097, "source-roster-bound")
    rows = []
    names = set()

    def source_file(relative, expected=None):
        # Inventory consumes each leaf and its traversal immediately;
        # it does not hold the entire checkout under nofile1024.
        reader = fixture.Originals()
        try:
            entry, content = reader.file(CHECKOUT / relative, 32 * 1024 * 1024)
            info = entry["identity"]
            blob = hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()
            row = {"path": relative, "gitMode": "100755" if stat.S_IMODE(info[2]) in (0o555, 0o755) else "100644",
                   "blob": blob, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            need(stat.S_IMODE(info[2]) in (0o444, 0o644, 0o555, 0o755)
                 and (expected is None or row == expected), "source-file-correspondence")
            reader.check()
            return row, content
        finally:
            need(reader.finish(), "source-file-close-unknown")

    for source_ordinal, raw in enumerate(raw_rows[:-1], 1):
        phase = "source-roster-entry"
        header, encoded = raw.split(b"\t", 1)
        mode, kind, blob = header.split(b" ")
        name = encoded.decode("utf-8", "strict")
        need(kind == b"blob" and mode in (b"100644", b"100755") and len(name) <= 512
             and name not in names and not name.startswith("/") and "\\" not in name and "\0" not in name
             and all(piece not in ("", ".", "..") for piece in name.split("/")), "source-roster-entry")
        names.add(name)
        phase = "source-file-inventory"
        row, _content = source_file(name)
        need(row["gitMode"].encode("ascii") == mode and row["blob"].encode("ascii") == blob, "source-roster-bytes-mode")
        rows.append(row)
    source_ordinal = 0
    phase = "source-required-roster"
    by_name = {row["path"]: row for row in rows}
    fixture.source_names(by_name)  # Includes this committed workflow.
    need(by_name["desktop/tools/macos_e2_native_fixture.py"]["sha256"] == fixture_hash
         and by_name["desktop/tools/macos_aqua_qualification.py"]["sha256"] == qualification_hash,
         "source-bootstrap-roster")

    manifests = ("desktop/native/macos-installed-native", "desktop/helpers/macos-android-register", "desktop/src-tauri")
    cargo_home, rustup_home = HOME / ".cargo", HOME / ".rustup"
    phase = "cargo-home-admission"
    book.directory(cargo_home)
    book.directory(rustup_home)
    configuration_parents = {cargo_home}
    for manifest in manifests:
        directory = CHECKOUT / manifest
        configuration_parents.update(parent / ".cargo" for parent in (directory, *directory.parents))

    def no_configuration():
        for directory in sorted(configuration_parents):
            try:
                info = os.stat(directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            need(stat.S_ISDIR(info.st_mode), "ambient-cargo-directory")
            original = book.directory(directory)  # No parent-link traversal.
            for name in ("config", "config.toml", "credentials", "credentials.toml"):
                try:
                    os.stat(name, dir_fd=original["fd"], follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError("ambient-cargo-configuration")

    phase = "cargo-configuration"
    no_configuration()
    phase = "locked-manifests"
    for directory in manifests:
        lock_name = directory + "/Cargo.lock"
        _row, content = source_file(lock_name, by_name[lock_name])
        lock = tomllib.loads(content.decode("utf-8", "strict"))
        need(lock.get("version") == 4 and type(lock.get("package")) is list
             and 0 < len(lock["package"]) <= 2048, "locked-registry-shape")
        for package in lock["package"]:
            need(type(package) is dict, "locked-package-shape")
            if "source" in package:
                need(package["source"] == "registry+https://github.com/rust-lang/crates.io-index"
                     and type(package.get("checksum")) is str
                     and re.fullmatch(r"[0-9a-f]{64}", package["checksum"]), "locked-public-source")
            else:
                need("checksum" not in package, "local-source-checksum")
    phase = "repository-toolchain"
    _row, toolchain_bytes = source_file("desktop/rust-toolchain.toml", by_name["desktop/rust-toolchain.toml"])
    need(tomllib.loads(toolchain_bytes.decode("utf-8"))["toolchain"]["channel"] == "1.98.0",
         "repository-toolchain-default")

    # Admit the image's fixed direct tools by their actual version outputs.
    # Only rustup distribution/install network is removed; the two locked fetches remain.
    tool_environment = dict(clean, CARGO_HOME=str(cargo_home), RUSTUP_HOME=str(rustup_home),
                            RUSTUP_TOOLCHAIN=TOOLCHAIN, RUSTUP_AUTO_INSTALL="0")
    phase = "rust-tool-admission"
    bin_directory = rustup_home / "toolchains" / "stable-aarch64-apple-darwin" / "bin"
    book.directory(bin_directory)
    tool_environment["PATH"] = str(bin_directory) + ":/usr/bin:/bin:/usr/sbin:/sbin"
    tool_environment["RUSTC"] = str(bin_directory / "rustc")
    tools = {}
    for tool in ("rustc", "cargo"):
        phase = "rust-tool-admission"
        executable = bin_directory / tool
        info = os.stat(executable, follow_symlinks=False)
        need(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid())
             and not info.st_mode & 0o022 and info.st_mode & 0o111, "prepared-rust-tool")
        raw = call(tool + "-version", [str(executable), "--version", "--verbose"],
                   tool_environment, 15, 4096, cwd=CHECKOUT / "desktop/src-tauri")
        text = raw.decode("utf-8", "strict").strip()
        need(text.startswith(tool + " "), "effective-tool-version")
        if tool == "rustc":
            need("release: 1.98.1" in text.splitlines()
                 and "commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985" in text.splitlines(),
                 "effective-rust-clock-binding")
        else:
            need("release: 1.98.1" in text.splitlines(), "effective-cargo-clock-binding")
        tools[tool] = {"command": [tool, "--version", "--verbose"], "output": text}
    # Acquisition only: no build scripts, credential helpers, alternate
    # registries, token/proxy/SSL overrides or inherited Cargo settings.
    fetch_environment = dict(tool_environment, CARGO_NET_OFFLINE="false",
                             CARGO_REGISTRIES_CRATES_IO_PROTOCOL="sparse", CARGO_NET_RETRY="1",
                             CARGO_HTTP_TIMEOUT="30", CARGO_HTTP_SSL_VERIFY="true",
                             CARGO_NET_GIT_FETCH_WITH_CLI="false")
    for index, directory in enumerate(manifests):
        phase = "cargo-configuration"
        no_configuration()
        call("fetch-" + str(index), [str(bin_directory / "cargo"), "fetch", "--manifest-path",
                                   str(CHECKOUT / directory / "Cargo.toml"), "--locked", "--target", TARGET],
             fetch_environment, 240, 262144)
    phase = "cargo-configuration"
    no_configuration()
    phase = "source-recheck"
    for source_ordinal, row in enumerate(rows, 1):
        source_file(row["path"], row)
    source_ordinal = 0
    book.check()

    common = {"schemaVersion": 1, "source": SOURCE, "workflowSource": SOURCE,
              "runId": os.environ["GITHUB_RUN_ID"], "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"]}
    binding = dict(common, tree=tree, workDirectory=[work_info.st_dev, work_info.st_ino, work_info.st_uid],
                   fixtureAdministrativeDomain={
                       "schemaVersion": 1, "allocation": "fresh-github-hosted-single-job",
                       "writer": "macos_e2_native_fixture.py",
                       "root": "/Library/Application Support/MobileReleaseKit-E2NativeFixture",
                       "receipt": "dev.mobile-release-kit.fixture.e2.pkg.v1", "priorFixtureUse": False,
                   })
    inventory = {"source": SOURCE, "tree": tree, "files": rows}
    rust = dict(common, cwd="desktop/src-tauri", autoInstall=False,
                selectedMacToolchain=TOOLCHAIN, repositoryDefault="1.98.0", tools=tools)
    fixture.binding_data(os.environ, binding, inventory, rust, sig(work_info))
    phase = "input-publication"
    for name, value, limit in (("source-binding.json", binding, 65536),
                               ("source-inventory.json", inventory, 2097152),
                               ("effective-rust-toolchain.json", rust, 16384)):
        body = fixture.canonical(value)
        need(len(body) <= limit, "prepared-input-bound")
        book.publish(work / name, body, 0o600)
    book.check()
except BaseException as error:
    failure = True
    # No arbitrary exception text, pathname, capture, environment or traceback.
    # Returned flags describe only the existing validated call return, not finality.
    try:
        diagnostic = preparation_failure_data(error, phase, source_ordinal, entered_calls)
        print("E2 preparation refused in " + diagnostic["phase"] + "; native fixture was not entered.", file=sys.stderr)
        print("E2 preparation diagnostic " + json.dumps(diagnostic, sort_keys=True, separators=(",", ":")), file=sys.stderr)
    except BaseException:
        # Diagnostic failure cannot replace the original failure or skip cleanup.
        pass
finally:
    closes_known = book is None or book.finish()
    if not closes_known:
        failure = True
    all_returned = all(record["returned"] for record in entered_calls)
    if scratch is not None and scratch_identity is not None and closes_known and all_returned:
        cleanup = fixture.Originals()
        try:
            parent = cleanup.directory(scratch.parent)
            need(sig(os.stat(scratch.name, dir_fd=parent["fd"], follow_symlinks=False))[:5] == scratch_identity
                 and shutil.rmtree.avoids_symlink_attacks, "preparation-scratch-original")
            shutil.rmtree(scratch.name, dir_fd=parent["fd"])
            try:
                os.stat(scratch.name, dir_fd=parent["fd"], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("preparation-scratch-remains")
        except BaseException:
            failure = True
            print("E2 preparation scratch retirement was not established.", file=sys.stderr)
        finally:
            if not cleanup.finish():
                failure = True
    elif scratch is not None:
        print("E2 preparation retains task scratch because original finality is unknown.", file=sys.stderr)
if failure:
    raise SystemExit(1)
print("Locked fixture inputs prepared; source/input originals closed. No native qualification is claimed.")
PY_PREPARE
