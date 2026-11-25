#!/usr/bin/env python3
"""Optional stack observation beside the UNCHANGED first retained Git case.

No app launch, PID handoff/control, runtime pre-read or direct-core prewarming.
sample(1) documents name selection, -wait, -mayDie and -file. It periodically
suspends/resumes the target: this is PERTURBED observation, not native timing or
qualification. Name/header correspondence is not original-child custody.
See https://keith.github.io/xcode-man-pages/sample.1.html . Import is inert.
"""
from pathlib import Path
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time


SOURCE = "216a2d3a559dd562164e852ea78b7235916e7c3a"
TEMP = Path("/Users/runner/work/_temp")
PROCESS = "mobile-release-kit-desktop"
EXECUTABLE = ("/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/"
              "MobileReleaseKitPayload.app/Contents/MacOS/mobile-release-kit-desktop")
SCOPE = "perturbed-native-startup-sample-not-app-qualification"
WORK_SECONDS, CLEANUP_SECONDS = 45.0, 2.0
CAPTURE_LIMIT = 4 * 1024 * 1024  # Per sampler file, not a native/protocol limit.
# Fixed source labels only; no arbitrary symbol, path, PID or stack is emitted.
SYMBOLS = {
    **{f"inventory-{name}": f"installed_runtime::Book::{name}" for name in (
        "inspect", "walk", "read", "reserve", "filesystem", "check_name", "prepare", "settle", "close")},
    "runtime-resolve": "runtime::RuntimeConfig::resolve_passive_installed",
    "supervisor-admission": "supervisor::acquire_passive_original",
    "supervisor-prepare": "supervisor::PreparedPassiveSpawn::prepare",
    "supervisor-spawn": "supervisor::spawn_passive_original",
    "supervisor-write": "supervisor::write_request",
    "supervisor-read": "supervisor::read_bounded",
    "supervisor-wait": "supervisor::wait_original",
    "supervisor-settle": "supervisor::settle_installed",
    "supervisor-ready": "supervisor::ready_after_custody",
    "filesystem-observe": "mrk_macos_installed_native::vault_filesystem::SnapshotBook::observe_phased",
    "filesystem-acl": "mrk_vault_acl_step",
}


def _need(value):
    if not value:
        raise ValueError("native-sample-refused")


def _symbol_names(symbol):
    return ([f"{crate}::{symbol}" for crate in ("installed_shell_observation", "mobile_release_desktop")]
            if symbol.startswith(("installed_runtime::", "runtime::", "supervisor::")) else [symbol])


def _symbol_pattern(symbol):
    names = _symbol_names(symbol)
    # Also accept the exact v0 display forms observed with c++filt -s rust:
    # crate[hex]::module::fn and <crate[hex]::module::Type>::method.
    demangled = []
    for name in names:
        parts = [re.escape(part) for part in name.split("::")]
        if len(parts) > 1:
            parts[0] += r"(?:\[[0-9a-f]{1,16}\])?"
            parent = "::".join(parts[:-1])
            if len(parts) == 4:
                parent = "(?:<" + parent + ">|" + parent + ")"
            demangled.append(parent + "::" + parts[-1])
        else:
            demangled.append(parts[0])
    demangled = "|".join(demangled)
    legacy = "|".join(re.escape("".join(f"{len(part)}{part}" for part in name.split("::"))) for name in names)
    return re.compile(r"(?<![A-Za-z0-9_:])(?:(?:" + demangled + r")(?=::|[^A-Za-z0-9_]|$)|__?ZN(?:"
                      + legacy + r")(?=[0-9E]))")


PATTERNS = {label: _symbol_pattern(symbol) for label, symbol in SYMBOLS.items()}
DISAMBIGUATOR = r"(?:s[A-Za-z0-9]{0,16}_)?"
BACKREF = r"[A-Za-z0-9]{0,8}_"
V0_FRAME = re.compile(r"__?R([A-Za-z0-9_]+)(?:\.llvm\.[0-9]+)?\Z")


def _v0_pattern(symbol):
    """Only fixed complete paths: free functions or inherent methods, optionally
    instantiated and/or inside one closure. NOT a general Rust-v0 demangler.
    Rust1.98 defaults to v0; legacy-only matching loses undemangled Rust frames.
    """
    names = [[f"{len(part)}{part}" for part in name.split("::")] for name in _symbol_names(symbol)]
    if len(names[0]) not in (3, 4):
        return None
    module = r"(?P<module>NtC" + DISAMBIGUATOR + "(?:" + "|".join("".join(name[:2]) for name in names) + "))"
    path = (module + names[0][2] if len(names[0]) == 3 else
            "M" + DISAMBIGUATOR + module + r"NtB(?P<parent>" + BACKREF + ")" + "".join(names[0][2:]))
    return re.compile(r"(?P<closure>NC)?(?P<generic>I?)Nv" + path + r"(?P<tail>[A-Za-z0-9_]*)\Z")


V0_PATTERNS = {label: _v0_pattern(symbol) for label, symbol in SYMBOLS.items()}


def _backref(value):
    number = 0
    for char in value[:-1]:
        number = number * 62 + "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".index(char)
    return number + 1 if value != "_" else 0


def _v0_matches(pattern, body):
    match = pattern.fullmatch(body) if pattern is not None and body is not None else None
    if match is None:
        return False
    if "parent" in match.groupdict() and _backref(match["parent"]) != match.start("module"):
        return False  # Book/type must refer to THIS fully encoded crate/module.
    if not match["generic"] and not match["closure"]:
        return not match["tail"]
    # Generic arguments remain opaque, never searched for known names. Accept
    # only the observed same-crate suffix; other backrefs/trait paths stay unknown.
    suffix = (r"[A-Za-z0-9_]+E" if match["generic"] else "")
    suffix += (DISAMBIGUATOR + "0" if match["closure"] else "")
    tail = re.fullmatch(suffix + r"B(" + BACKREF + ")", match["tail"])
    return tail is not None and _backref(tail[1]) == match.start("module") + 2


FRAME = re.compile(r"^[ \t+|:!]*([1-9][0-9]{0,9})[ \t]+(.+?)[ \t]+\(in ")


def report_shape(raw):
    """Count matching CALL-TREE LINES and their inclusive integer line weights.

    Weights can overlap between ancestors/recursion; they are NOT exclusive CPU
    time, duration, percentages or a count of operations. Zero is not absence.

    Only the graph is searched, not repeated summaries, source paths or binary
    images. A returned0 sampler, sub-limit capture, trailing newline and image
    footer are required by the caller/parser; no arbitrary-truncation proof.
    """
    matched = None
    try:
        _need(type(raw) is bytes and 0 < len(raw) < CAPTURE_LIMIT and raw.endswith(b"\n"))
        lines = raw.decode("utf-8").splitlines()
        paths = [line for line in lines if line.startswith("Path:")]
        processes = [line for line in lines if line.startswith("Process:")]
        matched = (len(paths) == len(processes) == 1
                   and re.fullmatch(r"Path:[ \t]+" + re.escape(EXECUTABLE), paths[0]) is not None
                   and re.fullmatch(r"Process:[ \t]+" + PROCESS + r" \[[1-9][0-9]{0,9}\]", processes[0]) is not None)
        if not matched:
            return "header-mismatch", False, None, None, None, None
        _need(lines.count("Call graph:") == lines.count("Binary Images:") == 1)
        start, footer = lines.index("Call graph:"), lines.index("Binary Images:")
        _need(lines.index(paths[0]) < start and lines.index(processes[0]) < start < footer)
        _need(any(re.match(r"[ \t]*0x[0-9a-fA-F]+[ \t]+-[ \t]+0x[0-9a-fA-F]+[ \t]+", line)
                  for line in lines[footer + 1:]))
        end = next((index for index in range(start + 1, footer) if lines[index].startswith((
            "Total number in stack ", "Sort by top of stack,"))), footer)
        frames = [(int(match[1]), match[2]) for line in lines[start + 1:end] if (match := FRAME.match(line))]
        _need(frames)
        counts, weights = dict.fromkeys(SYMBOLS, 0), dict.fromkeys(SYMBOLS, 0)
        v0_lines = unmatched_v0 = 0
        for weight, frame in frames:
            v0 = V0_FRAME.fullmatch(frame)
            body = v0[1] if v0 else None
            known = False
            for label, pattern in PATTERNS.items():
                if pattern.search(frame) is not None or _v0_matches(V0_PATTERNS[label], body):
                    counts[label] += 1
                    weights[label] += weight
                    known = True
            if v0:  # Format-looking lines, not a claim to validate all v0 syntax.
                v0_lines += 1
                unmatched_v0 += not known
        return "known-symbols" if any(counts.values()) else "no-known-symbols", True, counts, weights, v0_lines, unmatched_v0
    except (ValueError, TypeError, UnicodeError):
        return "invalid", matched, None, None, None, None


def _child_limits():
    import resource
    os.umask(0o077)  # Child-only; a replaced -file remains private too.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (CAPTURE_LIMIT, CAPTURE_LIMIT))


def _result():
    return {"schemaVersion": 1, "scope": SCOPE, "outcome": "refused",
            "elapsedSeconds": None, "exitCode": None, "reportShape": "not-read",
            "installedHeaderMatches": None, "knownSymbolLineCounts": None,
            "knownSymbolInclusiveStackWeights": None,
            "weightMeaning": "inclusive-stack-lines-not-exclusive-cpu-time-or-operations",
            "rustV0FrameLines": None, "unmatchedRustV0FrameLines": None,
            "stdoutBytes": None, "stderrBytes": None, "captures": "not-created"}


def _read_report(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as original:
        info = os.fstat(original.fileno())
        _need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
              and info.st_uid == os.getuid() and info.st_nlink == 1)
        if info.st_size >= CAPTURE_LIMIT:
            return "capture-limit", None, None, None, None, None
        return report_shape(original.read(CAPTURE_LIMIT))


def sample(uid):
    """One sampler child only; never discover, signal or wait for the app PID.

    The45s endpoint includes -wait and synchronous Popen creation and is never
    renewed. stdlib cannot interrupt creation itself. Named captures remain
    private if sampler return is unknown. stdout/stderr use0600 UNLINKED FDs;
    closing parent FDs does not remove an unknown child's open captures.
    """
    _need(type(uid) is int and uid > 0)
    result, directory, child, attempted = _result(), None, None, False
    started = time.monotonic()
    end = started + WORK_SECONDS
    try:
        directory = Path(tempfile.mkdtemp(prefix="mrk-native-startup-sample-", dir=TEMP))
        result["captures"] = "private-created"
        path = directory / "sample.txt"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        os.close(fd)
        with tempfile.TemporaryFile(dir=directory) as out, tempfile.TemporaryFile(dir=directory) as err:
            try:
                attempted = True
                child = subprocess.Popen(("/usr/bin/sample", PROCESS, "10", "10", "-wait", "-mayDie", "-file", str(path)),
                    stdin=subprocess.DEVNULL, stdout=out, stderr=err, cwd=directory,
                    env={"LC_ALL": "C", "LANG": "C", "__CF_USER_TEXT_ENCODING": f"0x{uid:X}:0:0"},
                    close_fds=True, restore_signals=True, preexec_fn=_child_limits)
                child.wait(timeout=max(0.0, end - time.monotonic()))
                result["outcome"] = "returned" if time.monotonic() < end else "timeout"
            except subprocess.TimeoutExpired:
                result["outcome"] = "timeout"
            except BaseException:
                result["outcome"] = "launch-error" if child is None else "process-error"
            finally:
                if child is not None:
                    if child.returncode is None:
                        cleanup_end = min(time.monotonic(), end) + CLEANUP_SECONDS
                        try:
                            child.kill()  # Exact sampler only, once. Never an app PID/name/group.
                        except OSError:
                            pass
                        try:
                            child.wait(timeout=max(0.0, cleanup_end - time.monotonic()))
                        except (subprocess.TimeoutExpired, OSError):
                            result["outcome"] = "sampler-return-unknown"
                    result["exitCode"] = child.returncode
            if child is not None and child.returncode is not None:
                result.update(stdoutBytes=os.fstat(out.fileno()).st_size, stderrBytes=os.fstat(err.fileno()).st_size)
                if max(result["stdoutBytes"], result["stderrBytes"]) >= CAPTURE_LIMIT:
                    result["reportShape"] = "capture-limit"
                elif result["outcome"] == "returned" and child.returncode == 0:
                    try:
                        shape, matched, counts, weights, v0_lines, unmatched_v0 = _read_report(path)
                        result.update(reportShape=shape, installedHeaderMatches=matched,
                                      knownSymbolLineCounts=counts, knownSymbolInclusiveStackWeights=weights,
                                      rustV0FrameLines=v0_lines, unmatchedRustV0FrameLines=unmatched_v0)
                    except (OSError, ValueError):
                        result["reportShape"] = "invalid"
                if result["outcome"] == "returned":
                    result["outcome"] = ("observed" if child.returncode == 0 and result["reportShape"] in (
                        "known-symbols", "no-known-symbols") else "unavailable")
    except BaseException:
        result["outcome"] = "capture-error"
    finally:
        if directory is not None:
            if not attempted or (child is not None and child.returncode is not None):
                try:
                    (directory / "sample.txt").unlink(missing_ok=True)
                    directory.rmdir()  # Only our known file/dir; never broad deletion.
                    result["captures"] = "removed"
                except OSError:
                    result["captures"] = "cleanup-error"
            else:
                result["captures"] = "retained-sampler-unknown"
        result["elapsedSeconds"] = round(time.monotonic() - started, 6)
    return result


def admitted_context():
    """Reuse pure retained route/user checks; no installed-tree/cache reads."""
    _need(not sys.argv[1:] and os.environ.get("MRK_MACOS_NATIVE_STARTUP_SAMPLE") == "true"
          and os.environ.get("MRK_MACOS_BUNDLED_CORE_DIAGNOSTIC", "false") == "false"
          and os.environ.get("MRK_CANDIDATE_MODE") == "install-retained-git-observer"
          and os.environ.get("MRK_CANDIDATE_SOURCE") == SOURCE and os.environ.get("RUNNER_TEMP") == str(TEMP))
    path = Path(__file__).absolute().with_name("macos_identity_current_runtime.py")
    spec = importlib.util.spec_from_file_location("_mrk_startup_sample_context", path)
    _need(spec is not None and spec.loader is not None)
    context = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(context)
    _, _, _, work = context.retained_context(os.environ, context.TARGET)
    uid, _, _, _ = context._native_user(os.environ, retained=True)
    # Previous workflow return0 + fresh install/readback/eject remain required.
    # This existing status is read only; create NOTHING in work/fixture rosters.
    fd = os.open(work / "retained-observer-install.status", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        _need(stat.S_ISREG(os.fstat(fd).st_mode) and os.read(fd, 3) == b"0\n")
    finally:
        os.close(fd)
    return uid


def main():
    result = _result()
    try:
        result = sample(admitted_context())
    except BaseException:
        pass  # No exceptions, command lines, private reports or paths on output.
    print(json.dumps(result, separators=(",", ":"), allow_nan=False))
    return 0 if result["outcome"] == "observed" and result["captures"] == "removed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
