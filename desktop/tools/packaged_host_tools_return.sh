set +x
set -euo pipefail
set +o posix
umask 077
unset CDPATH ENV BASH_ENV POSIXLY_CORRECT
export PATH=/usr/bin:/bin
fail() { printf 'MRK-H1 ERROR RETURN_BOOTSTRAP\n'; exit 70; }
[[ ${GITHUB_EVENT_NAME-} == push && ${GITHUB_REF-} == refs/heads/verify/desktop-packaged-host-tools ]] || fail
[[ ${GITHUB_REPOSITORY-} == Apdelrahman1911/mobile-release-kit && ${RUNNER_ENVIRONMENT-} == github-hosted ]] || fail
[[ ${GITHUB_RUN_ID-} =~ ^[1-9][0-9]{0,19}$ && ${GITHUB_RUN_ATTEMPT-} == 1 ]] || fail
[[ ${GITHUB_SHA-} =~ ^[0-9a-f]{40}$ && ${GITHUB_SHA-} != 0000000000000000000000000000000000000000 ]] || fail
[[ ${GITHUB_WORKSPACE-} == /home/runner/work/mobile-release-kit/mobile-release-kit && ${RUNNER_TEMP-} == /home/runner/work/_temp ]] || fail
[[ ${GITHUB_EVENT_PATH-} == /home/runner/work/_temp/_github_workflow/event.json ]] || fail
[[ ${ImageOS-} =~ ^[A-Za-z0-9_.-]{1,32}$ && ${ImageVersion-} =~ ^[0-9]{8}\.[0-9]{1,6}\.[0-9]{1,6}$ ]] || fail
uuid='[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
[[ ${GITHUB_ENV-} =~ ^/home/runner/work/_temp/_runner_file_commands/set_env_${uuid}$ ]] || fail
[[ ${GITHUB_OUTPUT-} =~ ^/home/runner/work/_temp/_runner_file_commands/set_output_${uuid}$ ]] || fail
[[ ${GITHUB_PATH-} =~ ^/home/runner/work/_temp/_runner_file_commands/add_path_${uuid}$ ]] || fail
[[ ${GITHUB_STEP_SUMMARY-} =~ ^/home/runner/work/_temp/_runner_file_commands/step_summary_${uuid}$ ]] || fail
[[ $UID == "$EUID" && $EUID -gt 0 && -d /tmp && ! -L /tmp ]] || fail
S="/tmp/mrk-packaged-host-tools-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
readonly S
[[ -d $S && ! -L $S ]] || fail
{ ulimit -v 524288 && ulimit -t 60 && ulimit -n 128 && ulimit -f 8192 && ulimit -c 0; } 2>/dev/null || fail
export HOME="$S/home" TMPDIR="$S/tmp" TMP="$S/tmp" TEMP="$S/tmp"
cd -- "$S/neutral" 2>/dev/null || fail
set +e
{
  /usr/bin/env -i \
    PATH=/usr/bin:/bin \
    HOME="$S/home" \
    TMPDIR="$S/tmp" \
    TMP="$S/tmp" \
    TEMP="$S/tmp" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    ImageOS="$ImageOS" \
    ImageVersion="$ImageVersion" \
    GITHUB_WORKSPACE=/home/runner/work/mobile-release-kit/mobile-release-kit \
    RUNNER_TEMP=/home/runner/work/_temp \
    GITHUB_ENV="$GITHUB_ENV" \
    GITHUB_OUTPUT="$GITHUB_OUTPUT" \
    GITHUB_PATH="$GITHUB_PATH" \
    GITHUB_STEP_SUMMARY="$GITHUB_STEP_SUMMARY" \
    GITHUB_EVENT_PATH=/home/runner/work/_temp/_github_workflow/event.json \
    GITHUB_SHA="$GITHUB_SHA" \
    GITHUB_REPOSITORY=Apdelrahman1911/mobile-release-kit \
    GITHUB_RUN_ID="$GITHUB_RUN_ID" \
    GITHUB_RUN_ATTEMPT=1 \
    GITHUB_EVENT_NAME=push \
    RUNNER_ENVIRONMENT=github-hosted \
    GITHUB_REF=refs/heads/verify/desktop-packaged-host-tools \
    /usr/bin/timeout --signal=TERM --kill-after=5s 20s \
    /usr/bin/python3.12 -I -S -B - <<'MRK_H1_RETURN'
"""Original DATA return, after observer wait."""
import base64
import hashlib
import json
import os
import re
import resource
import stat
import sys

COLLECTOR_SHA256 = "e1f3e8726b7b4bd6f8f3eb23e6a760e20fc28890a8a00bcab326d606f84144ff"
POLICY_SHA256 = "f9df2617dee80f6fa6b523334ac2fa9de741272a06ba73f4a85bc18543344d15"
COMMON = ("scope", "state", "nativeQualification", "profile", "schema")
SHAPES = {
    "host-facts.json": COMMON + ("policySha256", "run", "uid", "gid", "kernel"),
    "host-candidate-files.json": COMMON + ("sourceDatasetSha256", "policySha256", "objectColumns", "statColumns", "objects", "roles", "providerDeclarations", "self"),
    "ci-shape.json": COMMON + ("return", "originalObserver"),
    "fit-gaps.json": COMMON + ("storageBoundary", "observedGaps"),
}
ENVIRONMENT = ['PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL', 'TZ', 'ImageOS', 'ImageVersion', 'GITHUB_WORKSPACE', 'RUNNER_TEMP', 'GITHUB_ENV', 'GITHUB_OUTPUT', 'GITHUB_PATH', 'GITHUB_STEP_SUMMARY', 'GITHUB_EVENT_PATH', 'GITHUB_SHA', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_EVENT_NAME', 'RUNNER_ENVIRONMENT', 'GITHUB_REF']
PUBLIC_RUN = ['ImageOS', 'ImageVersion', 'GITHUB_SHA', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_EVENT_NAME', 'RUNNER_ENVIRONMENT', 'GITHUB_REF']
NAMES = ("host-facts.json", "host-candidate-files.json", "ci-shape.json", "fit-gaps.json")
D = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
F = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
ROOT = None


def need(value):
    if not value:
        raise ValueError()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def decode(raw):
    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict and canonical(value) == raw)
    return value


def validate_values(values):
    need(set(values) == set(SHAPES))
    for name, value in values.items():
        need(type(value) is dict and set(value) == set(SHAPES[name]))
        need(value["schema"] == "mrk-h1-" + name.removesuffix(".json") + "-1")
        need(value["state"] == "UNSEALED" and value["scope"] == "candidate-only"
             and value["nativeQualification"] == "not-established" and value["profile"] == "mrk-packaged-host-tool-inputs-1")
    need(values["host-facts.json"]["policySha256"] == POLICY_SHA256 and values["ci-shape.json"]["return"] is None)
    need(values["fit-gaps.json"]["storageBoundary"] == "bounded-observer-scratch-not-build-admission")
    files = values["host-candidate-files.json"]
    need(files["sourceDatasetSha256"] == '6cf2895fb722f183434a7cb49c487b0494dc70715feef085886452e02801f20d' and files["policySha256"] == POLICY_SHA256)
    need(len(files["objects"]) == 3460 and len(files["roles"]) == 13 and len(files["providerDeclarations"]) == 42)


def ident(s):
    return dict(zip(("device", "inode", "mode", "uid", "gid", "links", "bytes", "blocks", "mtimeNs", "ctimeNs"),
                    (s.st_dev, s.st_ino, stat.S_IMODE(s.st_mode), s.st_uid, s.st_gid, s.st_nlink,
                     s.st_size, s.st_blocks, s.st_mtime_ns, s.st_ctime_ns)))


def owned(actual, expected):
    return all(actual[k] == expected[k] for k in ("device", "inode", "mode", "uid", "gid"))


def directory(path):
    fd = os.open("/", D)
    try:
        for part in path.split("/")[1:]:
            nxt = os.open(part, D, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def entries(fd, cap):
    before, names = ident(os.fstat(fd)), []
    with os.scandir(fd) as items:
        for item in items:
            need(len(names) < cap)
            names.append(item.name)
    need(ident(os.fstat(fd)) == before)
    return set(names)


def read(name, cap, expected=None):
    before = os.stat(name, dir_fd=ROOT, follow_symlinks=False)
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600)
    need(before.st_nlink == 1 and before.st_size <= cap)
    fd = os.open(name, F, dir_fd=ROOT)
    try:
        need(ident(os.fstat(fd)) == ident(before))
        raw = bytearray()
        while len(raw) < before.st_size:
            chunk = os.read(fd, min(65536, before.st_size - len(raw)))
            need(chunk)
            raw.extend(chunk)
        # Original capture EOF, after wait=0.
        need(os.read(fd, 1) == b"")
        need(ident(before) == ident(os.fstat(fd)) == ident(os.stat(name, dir_fd=ROOT, follow_symlinks=False)))
        row = {"stat": ident(before), "sha256": hashlib.sha256(raw).hexdigest()}
        if expected is not None:
            need(row == expected)
        return bytes(raw), row
    finally:
        os.close(fd)


def main():
    global ROOT
    os.umask(0o077)
    for key, value in ((resource.RLIMIT_AS, 512 * 2**20), (resource.RLIMIT_CPU, 60), (resource.RLIMIT_NOFILE, 128),
                       (resource.RLIMIT_FSIZE, 8 * 2**20), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(key, (value, value))
    e = dict(os.environ)
    need(set(e) == set(ENVIRONMENT) and os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid())
    need(e["GITHUB_REPOSITORY"] == "Apdelrahman1911/mobile-release-kit" and e["GITHUB_EVENT_NAME"] == "push")
    need(e["GITHUB_REF"] == "refs/heads/verify/desktop-packaged-host-tools" and e["RUNNER_ENVIRONMENT"] == "github-hosted")
    need(re.fullmatch(r"[1-9][0-9]{0,19}", e["GITHUB_RUN_ID"]) and e["GITHUB_RUN_ATTEMPT"] == "1")
    need(re.fullmatch(r"(?!0{40}$)[0-9a-f]{40}", e["GITHUB_SHA"]))
    scratch = "/tmp/mrk-packaged-host-tools-" + e["GITHUB_RUN_ID"] + "-1"
    need(os.getcwd() == scratch + "/neutral" and e["HOME"] == scratch + "/home")
    need(all(e[k] == scratch + "/tmp" for k in ("TMPDIR", "TMP", "TEMP")))
    ROOT = directory(scratch)
    root_stat = os.fstat(ROOT)
    need(root_stat.st_uid == os.getuid() and stat.S_IMODE(root_stat.st_mode) == 0o700)
    index_raw, index_row = read("index.json", 2**20)
    index = decode(index_raw)
    need(set(index) == {"schema", "root", "directories", "files"} and index["schema"] == "mrk-h1-index-1")
    need(owned(ident(root_stat), index["root"]) and set(index["files"]) == set(NAMES))
    need(set(index["directories"]) == {scratch, scratch + "/home", scratch + "/tmp", scratch + "/neutral"})
    for path, expected in index["directories"].items():
        fd = directory(path)
        try:
            s = ident(os.fstat(fd))
            need(s["uid"] == os.getuid() and s["mode"] == 0o700 and owned(s, expected))
            if path != scratch:
                need(entries(fd, 1) == set())
        finally:
            os.close(fd)
    expected_names = set(NAMES) | {"index.json", "wait.json", "stdout.bin", "stderr.bin", "home", "tmp", "neutral"}
    need(entries(ROOT, 16) == expected_names)
    originals, values = {"index.json": index_row}, {}
    for name in NAMES:
        raw, row = read(name, 2 * 2**20, index["files"][name])
        value = decode(raw)
        values[name], originals[name] = value, row
    validate_values(values)
    facts, ci = values["host-facts.json"], values["ci-shape.json"]
    need(facts["run"] == {k: e[k] for k in PUBLIC_RUN} and facts["uid"] == os.getuid() and facts["gid"] == os.getgid())
    observer = ci["originalObserver"]
    need(observer["validatedPushNonDeletion"] is True and observer["pythonArgv"] == ["-"])
    need(observer["scratchDirectories"] == index["directories"] and set(observer["captures"]) == {"stdout.bin", "stderr.bin"})
    wait_raw, wait_row = read("wait.json", 4096)
    wait = decode(wait_raw)
    need(set(wait) == {"schema", "status", "startUnix", "endUnix"} and wait["schema"] == "mrk-h1-shell-wait-1")
    need(type(wait["status"]) is int and wait["status"] == 0)
    need(all(type(wait[k]) is str and re.fullmatch(r"[0-9]{10,12}\.[0-9]{6}", wait[k]) for k in ("startUnix", "endUnix")))
    need(int(wait["endUnix"].replace(".", "")) >= int(wait["startUnix"].replace(".", "")))
    originals["wait.json"] = wait_row
    captures = {}
    for name in ("stdout.bin", "stderr.bin"):
        raw, row = read(name, 0)
        need(row["stat"] == observer["captures"][name])
        originals[name] = row
        captures[name] = {"stat": row["stat"], "bytes": 0, "sha256": row["sha256"], "eofAfterWait": True}
    ci["return"] = {"collectorSha256": COLLECTOR_SHA256, "policySha256": POLICY_SHA256,
        "sourceCiShapeSha256": originals["ci-shape.json"]["sha256"], "observerWait": wait, "captures": captures,
        "finalizerArgv": ["/usr/bin/env", "-i"] + [k + "=" + e[k] for k in ENVIRONMENT] +
            ["/usr/bin/timeout", "--signal=TERM", "--kill-after=5s", "20s", "/usr/bin/python3.12", "-I", "-S", "-B", "-"],
        "finalizerWait": "pending-original-shell-wait", "cleanup": "pending-after-finalizer-wait",
        "jobCompletionAndDisposal": "requires-independent-original-service-evidence"}
    encoded = {name: canonical(values[name]) for name in NAMES}
    need(sum(map(len, encoded.values())) <= 2 * 2**20)
    frames, summary = [], []
    for number, name in enumerate(NAMES, 1):
        raw = encoded[name]
        digest, parts = hashlib.sha256(raw).hexdigest(), (len(raw) + 3071) // 3072
        frames.append(f"MRK-H1 BEGIN {number} {name} {len(raw)} {digest}\n".encode())
        for part, offset in enumerate(range(0, len(raw), 3072), 1):
            frames.append(f"MRK-H1 DATA {number} {part:06d} ".encode() + base64.b64encode(raw[offset:offset + 3072]) + b"\n")
        frames.append(f"MRK-H1 END {number} {parts} {len(raw)} {digest}\n".encode())
        summary.append([number, name, len(raw), parts, digest])
    frames.append(f"MRK-H1 COMPLETE 4 {sum(map(len, encoded.values()))} {hashlib.sha256(canonical(summary)).hexdigest()}\n".encode())
    need(sum(map(len, frames)) <= 4 * 2**20)
    ledger = canonical({"schema": "mrk-h1-return-ledger-1", "root": index["root"],
                        "directories": index["directories"], "files": originals})
    need(len(ledger) <= 65536 and entries(ROOT, 16) == expected_names)
    fd = os.open("return-ledger.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=ROOT)
    try:
        view = memoryview(ledger)
        while view:
            count = os.write(fd, view)
            need(count > 0)
            view = view[count:]
        os.fsync(fd)
        need(ident(os.fstat(fd)) == ident(os.stat("return-ledger.json", dir_fd=ROOT, follow_symlinks=False)))
    finally:
        os.close(fd)
    os.fsync(ROOT)
    again = directory(scratch)
    try:
        need(owned(ident(os.fstat(again)), index["root"]))
    finally:
        os.close(again)
    for frame in frames:
        view = memoryview(frame)
        while view:
            count = os.write(1, view)
            need(count > 0)
            view = view[count:]


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        os.write(1, b"MRK-H1 ERROR RETURN\n")
        sys.exit(70)
    finally:
        if ROOT is not None:
            os.close(ROOT)
MRK_H1_RETURN
} 2>/dev/null
rc=$?
set -e
printf 'MRK-H1 FINALIZER-WAIT %s\n' "$rc"
if [[ $rc -ne 0 ]]; then
  printf 'MRK-H1 ERROR RETURN_RETAINED\n'
  exit "$rc"
fi
cd / 2>/dev/null || fail
set +e
{
  /usr/bin/env -i \
    PATH=/usr/bin:/bin \
    HOME="$S/home" \
    TMPDIR="$S/tmp" \
    TMP="$S/tmp" \
    TEMP="$S/tmp" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    ImageOS="$ImageOS" \
    ImageVersion="$ImageVersion" \
    GITHUB_WORKSPACE=/home/runner/work/mobile-release-kit/mobile-release-kit \
    RUNNER_TEMP=/home/runner/work/_temp \
    GITHUB_ENV="$GITHUB_ENV" \
    GITHUB_OUTPUT="$GITHUB_OUTPUT" \
    GITHUB_PATH="$GITHUB_PATH" \
    GITHUB_STEP_SUMMARY="$GITHUB_STEP_SUMMARY" \
    GITHUB_EVENT_PATH=/home/runner/work/_temp/_github_workflow/event.json \
    GITHUB_SHA="$GITHUB_SHA" \
    GITHUB_REPOSITORY=Apdelrahman1911/mobile-release-kit \
    GITHUB_RUN_ID="$GITHUB_RUN_ID" \
    GITHUB_RUN_ATTEMPT=1 \
    GITHUB_EVENT_NAME=push \
    RUNNER_ENVIRONMENT=github-hosted \
    GITHUB_REF=refs/heads/verify/desktop-packaged-host-tools \
    /usr/bin/timeout --signal=TERM --kill-after=5s 10s \
    /usr/bin/python3.12 -I -S -B - <<'MRK_H1_CLEANUP'
"""Remove identified originals after both waits."""
import json
import os
import re
import resource
import stat
import sys

D = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILES = {"host-facts.json", "host-candidate-files.json", "ci-shape.json", "fit-gaps.json", "index.json", "wait.json", "stdout.bin", "stderr.bin"}


def need(value):
    if not value:
        raise ValueError()


def ident(s):
    return dict(zip(("device", "inode", "mode", "uid", "gid", "links", "bytes", "blocks", "mtimeNs", "ctimeNs"),
                    (s.st_dev, s.st_ino, stat.S_IMODE(s.st_mode), s.st_uid, s.st_gid, s.st_nlink,
                     s.st_size, s.st_blocks, s.st_mtime_ns, s.st_ctime_ns)))


def owned(actual, expected):
    return all(actual[k] == expected[k] for k in ("device", "inode", "mode", "uid", "gid"))


def directory(path):
    fd = os.open("/", D)
    try:
        for part in path.split("/")[1:]:
            nxt = os.open(part, D, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def entries(fd, cap):
    before, names = ident(os.fstat(fd)), []
    with os.scandir(fd) as items:
        for item in items:
            need(len(names) < cap)
            names.append(item.name)
    need(ident(os.fstat(fd)) == before)
    return set(names)


def main():
    for key, value in ((resource.RLIMIT_AS, 512 * 2**20), (resource.RLIMIT_CPU, 60), (resource.RLIMIT_NOFILE, 128),
                       (resource.RLIMIT_FSIZE, 8 * 2**20), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(key, (value, value))
    e = os.environ
    need(os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() and os.getcwd() == "/")
    need(e["GITHUB_REPOSITORY"] == "Apdelrahman1911/mobile-release-kit" and e["GITHUB_EVENT_NAME"] == "push")
    need(e["GITHUB_REF"] == "refs/heads/verify/desktop-packaged-host-tools" and e["RUNNER_ENVIRONMENT"] == "github-hosted")
    need(re.fullmatch(r"[1-9][0-9]{0,19}", e["GITHUB_RUN_ID"]) and e["GITHUB_RUN_ATTEMPT"] == "1")
    need(re.fullmatch(r"(?!0{40}$)[0-9a-f]{40}", e["GITHUB_SHA"]))
    scratch = "/tmp/mrk-packaged-host-tools-" + e["GITHUB_RUN_ID"] + "-1"
    parent = directory("/tmp")
    root = os.open(scratch.rsplit("/", 1)[1], D, dir_fd=parent)
    try:
        before = os.stat("return-ledger.json", dir_fd=root, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1)
        need(stat.S_IMODE(before.st_mode) == 0o600 and before.st_size <= 65536)
        fd = os.open("return-ledger.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=root)
        try:
            need(ident(os.fstat(fd)) == ident(before))
            raw = bytearray()
            while len(raw) < before.st_size:
                chunk = os.read(fd, before.st_size - len(raw))
                need(chunk)
                raw.extend(chunk)
            need(os.read(fd, 1) == b"")
            need(ident(before) == ident(os.fstat(fd)) == ident(os.stat("return-ledger.json", dir_fd=root, follow_symlinks=False)))
        finally:
            os.close(fd)
        ledger = json.loads(raw)
        need(set(ledger) == {"schema", "root", "directories", "files"} and ledger["schema"] == "mrk-h1-return-ledger-1")
        need(set(ledger["files"]) == FILES and owned(ident(os.fstat(root)), ledger["root"]))
        need(ledger["root"]["uid"] == os.getuid() and ledger["root"]["mode"] == 0o700)
        need(set(ledger["directories"]) == {scratch, scratch + "/home", scratch + "/tmp", scratch + "/neutral"})
        need(entries(root, 16) == FILES | {"return-ledger.json", "home", "tmp", "neutral"})
        for name, expected in ledger["files"].items():
            s = os.stat(name, dir_fd=root, follow_symlinks=False)
            need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600)
            need(ident(s) == expected["stat"])
        for name in ("home", "tmp", "neutral"):
            fd = os.open(name, D, dir_fd=root)
            try:
                s = ident(os.fstat(fd))
                need(s["uid"] == os.getuid() and s["mode"] == 0o700 and owned(s, ledger["directories"][scratch + "/" + name]))
                need(entries(fd, 1) == set())
            finally:
                os.close(fd)
        need(owned(ident(os.stat(scratch.rsplit("/", 1)[1], dir_fd=parent, follow_symlinks=False)), ledger["root"]))
        # Preflight all originals; later failure reports partial cleanup.
        for name in sorted(FILES):
            need(ident(os.stat(name, dir_fd=root, follow_symlinks=False)) == ledger["files"][name]["stat"])
            os.unlink(name, dir_fd=root)
        need(ident(os.stat("return-ledger.json", dir_fd=root, follow_symlinks=False)) == ident(before))
        os.unlink("return-ledger.json", dir_fd=root)
        for name in ("home", "tmp", "neutral"):
            need(owned(ident(os.stat(name, dir_fd=root, follow_symlinks=False)), ledger["directories"][scratch + "/" + name]))
            os.rmdir(name, dir_fd=root)
        need(entries(root, 1) == set())
        need(owned(ident(os.stat(scratch.rsplit("/", 1)[1], dir_fd=parent, follow_symlinks=False)), ledger["root"]))
        os.rmdir(scratch.rsplit("/", 1)[1], dir_fd=parent)
    finally:
        os.close(root)
        os.close(parent)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        sys.exit(70)
MRK_H1_CLEANUP
} 2>/dev/null
rc=$?
set -e
printf 'MRK-H1 CLEANUP-WAIT %s\n' "$rc"
if [[ $rc -ne 0 ]]; then
  printf 'MRK-H1 ERROR CLEANUP_PARTIAL_OR_RETAINED\n'
  exit "$rc"
fi
