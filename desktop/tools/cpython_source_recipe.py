"""One closed serial source recipe using the existing ordinary C/A/W owner.

No supervisor, shell wrapper, capture shim, package installer or retry. A later
review must select the input and actual finite execution domain before build().
Even complete original mandatory work is only evidence, not supply acceptance.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import time

_SPEC = importlib.util.spec_from_file_location("_mrk_source_recipe_inputs", Path(__file__).with_name("cpython_static_inputs.py"))
I = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(I)

WORK_SECONDS = 40 * 60
# Existing per-call cleanup is 3s, not replaced here. The admitted outer owner
# must reserve another finite 10s for cleanup/final reconciliation, not renew work.
OUTER_RESERVE_SECONDS = 10
PHASE_OUTPUT_LIMIT = 16 << 20
TOTAL_OUTPUT_LIMIT = 256 << 20
NS = 1_000_000_000


def fixed_phases() -> tuple[dict, ...]:
    """Literal table only; callers cannot provide argv, phases or environment."""
    make = I.SOURCE_TOOLS["make"]
    dependency_env = {**I.SOURCE_ENV, "CFLAGS": I.FIXED_ENV["CFLAGS"] + " -fPIC"}
    python_env = dict(I.SOURCE_PYTHON_ENV)
    specifications = (
        ("zlib-configure", "zlib", (I.SOURCE_TOOLS["sh"], "./configure", *I.ZLIB_CONFIGURE), dependency_env),
        ("zlib-build", "zlib", (make, "-j1"), dependency_env),
        ("zlib-install", "zlib", (make, "-j1", "install"), dependency_env),
        ("libffi-configure", "libffi", (I.SOURCE_TOOLS["sh"], "/work/inputs/sources/libffi/configure", *I.FFI_CONFIGURE), dependency_env),
        ("libffi-build", "libffi", (make, "-j1"), dependency_env),
        ("libffi-install", "libffi", (make, "-j1", "install"), dependency_env),
        ("openssl-configure", "openssl", (I.SOURCE_TOOLS["perl"], "./Configure", *I.SOURCE_OPENSSL_CONFIGURE), dependency_env),
        ("openssl-build", "openssl", (make, "-j1", I.SOURCE_OPENSSL_LDFLAGS, "build_libs"), dependency_env),
        ("openssl-install", "openssl", (make, "-j1", I.SOURCE_OPENSSL_LDFLAGS, "install_dev"), dependency_env),
        ("openssl-layout", "openssl", (), I.SOURCE_ENV),
        ("python-configure", "cpython", (I.SOURCE_TOOLS["sh"], "/work/inputs/sources/cpython/configure", *I.SOURCE_PYTHON_CONFIGURE), python_env),
        ("builtin-archives", "cpython", (make, "-j1", *I.SOURCE_PYTHON_MAKE, *I.SOURCE_ARCHIVE_TARGETS), python_env),
        ("python-build", "cpython", (make, "-j1", *I.SOURCE_PYTHON_MAKE,
                                      "python", "platform", "checksharedmods", "build-details.json"), python_env),
        ("python-project", "cpython", (), I.SOURCE_ENV))
    return tuple({"name": name, "cwd": "/work/build/" + directory, "argv": list(argv), "environment": dict(env)}
                 for name, directory, argv, env in specifications)


def remaining_seconds(deadline_ns: int, now_ns: int) -> int:
    remaining = (deadline_ns - now_ns) // NS
    I.need(1 <= remaining <= WORK_SECONDS, "Common source work deadline exhausted")
    return remaining  # Positive floor, never max(1, remaining) or a renewed timeout.


def _owner_modules(lock: dict):
    root = I.CORE_ROOT / "src"
    originals = {row["path"] for row in lock["coreSourceFiles"] if row["path"].startswith(str(root) + "/")}

    def checked_modules():
        for name, module in tuple(sys.modules.items()):
            if name == "mobile_release" or name.startswith("mobile_release."):
                I.need(getattr(module, "__file__", None) in originals, "Foreign existing owner module origin")

    checked_modules()
    previous = list(sys.path)
    try:
        sys.path.insert(0, str(root))
        from mobile_release import cancellation, owned_process
    finally:
        sys.path[:] = previous
    checked_modules()
    return owned_process, cancellation


def _relative_record(record: dict) -> dict:
    return {**record, "path": Path(record["path"]).relative_to(I.RECEIPTS).as_posix()}


def _persist_phase(lock: dict, phase: dict, outcome, start_ns: int, deadline_ns: int,
                   data_files: list[dict], retained_bytes: int) -> tuple[dict, int]:
    native = bool(phase["argv"])
    if native:
        I.need(outcome.args == phase["argv"] and type(outcome.returncode) is int
               and type(outcome.stdout) is bytes and type(outcome.stderr) is bytes,
               "Original phase result/streams incomplete")
        stdout, stderr, code = outcome.stdout, outcome.stderr, outcome.returncode
    else:
        stdout, stderr, code = b"", b"", None
    size = len(stdout) + len(stderr)
    I.need(size <= PHASE_OUTPUT_LIMIT and retained_bytes + size <= TOTAL_OUTPUT_LIMIT,
           "Original source capture/log ceiling exceeded")
    out = I.source_write(I.RECEIPTS / (phase["name"] + ".stdout"), stdout)
    err = I.source_write(I.RECEIPTS / (phase["name"] + ".stderr"), stderr)
    # A required make recipe must not disguise an observed error as success.
    ignored = any(marker in stdout or marker in stderr for marker in
                  (b"(ignored)", b"*** Error compiling", b"Can't list "))
    in_time = time.monotonic_ns() < deadline_ns
    if native and code == 0 and in_time and not ignored:
        data_files.extend(I.source_capture_configuration(phase["name"]))
    finished_ns = time.monotonic_ns()
    complete = (not native or code == 0) and not ignored and finished_ns < deadline_ns
    record = {"schema": I.SOURCE_PHASE_SCHEMA, "profile": I.SOURCE_PROFILE,
        "inputLockSha256": lock["_digest"], "phase": phase["name"], "kind": "native" if native else "data",
        "argv": phase["argv"], "cwd": phase["cwd"], "environmentSha256": I.digest(I.canonical(phase["environment"])),
        "startMonotonicNs": start_ns, "endMonotonicNs": finished_ns, "deadlineMonotonicNs": deadline_ns,
        "originalExitCode": code, "state": "complete" if complete else "failed-or-late",
        "observedIgnoredError": ignored, "stdout": _relative_record(out), "stderr": _relative_record(err),
        "dataFiles": [_relative_record(row) for row in data_files]}
    saved = I.source_write(I.RECEIPTS / (phase["name"] + ".json"), I.canonical(record))
    I.need(complete, "Original source phase failed/was late; preserve partials without retry")
    return _relative_record(saved), retained_bytes + size


def _run_phases(lock: dict, owner, guard, deadline_ns: int) -> list[dict]:
    """Private seam for inert fixtures; production uses only the original owner."""
    records, retained = [], 0
    for phase in fixed_phases():
        guard.check()
        timeout = remaining_seconds(deadline_ns, time.monotonic_ns())
        start = time.monotonic_ns()
        data_files, outcome = [], None
        if phase["argv"]:
            # Original ordinary C/A/W route. No execution scope, journal or on_start authority.
            outcome = owner.run_owned(phase["argv"], environ=phase["environment"], cwd=Path(phase["cwd"]),
                timeout=timeout, capture=True, text=False, output_limit=PHASE_OUTPUT_LIMIT,
                cancellation=guard, cleanup=False, execution_scope=None, journal_binding=None, on_start=None)
        elif phase["name"] == "openssl-layout":
            data_files.append(I.source_openssl_layout())
        elif phase["name"] == "python-project":
            data_files.append(I.source_project(lock))
        else:
            raise I.InputError("Different fixed DATA phase")
        # Owner exceptions leave no passing phase record. Do not recover a wait,
        # retry a close, guess streams or replace an unknown native outcome.
        record, retained = _persist_phase(lock, phase, outcome, start, deadline_ns, data_files, retained)
        guard.check()
        remaining_seconds(deadline_ns, time.monotonic_ns())
        records.append(record)
    return records


def build(lock_path: Path) -> dict:
    I.require_source_build()
    started = time.monotonic_ns()
    deadline = started + WORK_SECONDS * NS
    lock = I.load_source_lock(lock_path)
    remaining_seconds(deadline, time.monotonic_ns())
    owner, cancellation = _owner_modules(lock)
    guard, owns = cancellation.cancellation_owner(None, I.InputError, "Conventional source cancellation finality failed")
    scope = cancellation.CleanupScope(guard, lambda: None, owns_cancellation=owns, first_primary=True)
    try:
        with scope:
            if owns:
                guard.install()
                guard.activate()
            guard.check()
            I.source_workspace(lock)
            I.source_write(I.RECEIPTS / "input-lock.json", I.canonical({k: v for k, v in lock.items() if not k.startswith("_")}))
            I.source_write(I.RECEIPTS / "execution-review.json", I.source_bound(lock["_executionReview"], I.MAX_JSON))
            I.source_write(I.RECEIPTS / "rootfs.json", I.source_bound(lock["rootfs"], I.MAX_JSON))
            I.source_write(I.RECEIPTS / "source-patchlevel.h", I.source_read(I.SOURCE_ROOT / "cpython/Include/patchlevel.h", 1 << 20))
            records = _run_phases(lock, owner, guard, deadline)
            guard.check()
    finally:
        # Required unconditional dispatch of the existing one-attempt scope,
        # not a new cleanup mechanism or an ambiguous cleanup retry.
        scope.__exit__(*sys.exc_info())
    remaining_seconds(deadline, time.monotonic_ns())
    projection_raw = I.source_read(I.RECEIPTS / "source-projection.json", I.MAX_JSON)
    projection = I.decode(projection_raw)
    result = {"schema": "mrk-cpython-source-result-1", "profile": I.SOURCE_PROFILE,
        "inputLockSha256": lock["_digest"], "rootfsSha256": lock["rootfs"]["sha256"],
        "executionReviewSha256": lock["_executionReview"]["sha256"],
        "state": "mandatory-work-complete", "nativeQualification": "not-established",
        "startMonotonicNs": started, "deadlineMonotonicNs": deadline, "endMonotonicNs": time.monotonic_ns(),
        "phases": records, "projectionSha256": I.digest(projection_raw)}
    result_record = I.source_write(I.RECEIPTS / "source-result.json", I.canonical(result))
    output = {"schema": I.SOURCE_OUTPUT_SCHEMA, "profile": I.SOURCE_PROFILE, "target": I.TARGET["triple"],
        "inputLockSha256": lock["_digest"], "hostInputsSha256": lock["hostInputs"]["sha256"],
        "rootfsSha256": lock["rootfs"]["sha256"], "result": _relative_record(result_record),
        "stage": {k: v for k, v in projection.items() if k != "profile"}}
    saved = I.source_write(I.RECEIPTS / "source-output.json", I.canonical(output))
    remaining_seconds(deadline, time.monotonic_ns())
    return {"operation": "source-build-evidence-written", "output": saved,
            "qualification": "not-supply-install-or-native-acceptance"}


def main() -> None:
    I.require_source_build()
    I.need(len(sys.argv) == 2, "Expected fixed LOCK path; no command/profile/timeout/approval override")
    result = build(Path(sys.argv[1]))
    raw = I.canonical(result)
    I.need(sys.stdout.buffer.write(raw) == len(raw), "Short source result output")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
