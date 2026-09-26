"""Inert policy for one fixed disposable-runner glibc upgrade, never apt execution.

Package membership/relations come from authenticated Ubuntu snapshot
20260922T000000Z noble-security selected metadata SHA256
4e74c0ea961356f5b8f7f198a1c895269c810c3045de5257c3bca3abcc36bcb0.
These tuple checks do not qualify the installed library bodies or native runtime.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


OLD, NEW = "2.39-0ubuntu8.8", "2.39-0ubuntu8.9"
PACKAGES = {name: "amd64" for name in (
    "libc-bin", "libc-dev-bin", "libc-devtools", "libc6", "libc6-dbg", "libc6-dev",
    "libc6-dev-i386", "libc6-dev-x32", "libc6-i386", "libc6-x32")}
PACKAGES.update({"glibc-doc": "all", "locales": "all"})
REQUIRED = {"libc-bin", "libc-dev-bin", "libc6", "libc6-dev"}
FIELDS = ("package", "architecture", "version", "sourcePackage", "sourceVersion", "status")
MAX_DATA = 2 << 20
ROUTES = {("refs/heads/verify/desktop-ubuntu-publication", "publisher-helpers", None),
          ("refs/heads/verify/desktop-shell-host-metadata", "compile", "host-metadata-only"),
          ("refs/heads/verify/desktop-installed-shell", "compile", "compile"),
          ("refs/heads/verify/desktop-installed-github-readonly", "compile", "compile"),
          ("refs/heads/verify/desktop-installed-github-normal-boundaries", "compile", "compile")}


class Refused(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Refused(reason)


def snapshot(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_DATA and raw.endswith(b"\n"), "snapshot-bound")
    rows = {}
    for line in raw.decode("ascii").splitlines():
        values = line.split("\t")
        need(len(values) == len(FIELDS) and all(len(value) <= 256 for value in values), "snapshot-fields")
        row = dict(zip(FIELDS, values))
        need(re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,127}", row["package"]) is not None
             and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", row["architecture"]) is not None,
             "snapshot-package-identity")
        key = row["package"] + ":" + row["architecture"]
        need(key not in rows and len(rows) < 8192, "snapshot-duplicate-or-count")
        rows[key] = row
    return rows


def selected(rows):
    chosen = {}
    for key, row in rows.items():
        package = row["package"]
        if row["sourcePackage"] == "glibc" or package in PACKAGES:
            need(package in PACKAGES and row["architecture"] == PACKAGES[package]
                 and row["sourcePackage"] == "glibc" and row["version"] in {OLD, NEW}
                 and row["sourceVersion"] == row["version"] and row["status"] == "install ok installed",
                 "unknown-held-partial-or-nonforward-glibc")
            chosen[key] = row
    need(REQUIRED <= {row["package"] for row in chosen.values()}, "missing-required-glibc")
    # These non-glibc direct dependencies must already be installed. The actual
    # apt simulation remains authoritative for versions/alternatives/transitives;
    # any proposed install/repair outside the selected glibc set is refused.
    for package in ("libgcc-s1", "linux-libc-dev", "libcrypt-dev", "rpcsvc-proto"):
        need(any(row["package"] == package and row["architecture"] in {"amd64", "all"}
                 and row["status"] in {"install ok installed", "hold ok installed"}
                 for row in rows.values()), "missing-existing-glibc-dependency")
    return chosen


def arguments(rows):
    return [key + "=" + NEW for key in sorted(selected(rows))]


def simulation(raw, before):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_DATA and raw.endswith(b"\n"), "simulation-bound")
    chosen = selected(before)
    changed = {key for key, row in chosen.items() if row["version"] == OLD}
    observed, configured, summaries = set(), set(), []
    names = {row["package"]: key for key, row in chosen.items()}
    for line in raw.decode("ascii").splitlines():
        summary = re.fullmatch(r"([0-9]+) upgraded, ([0-9]+) newly installed, ([0-9]+) to remove and ([0-9]+) not upgraded\.", line)
        if summary:
            summaries.append(tuple(int(value) for value in summary.groups()))
        if line.startswith(("Inst ", "Conf ")):
            action = re.fullmatch(r"(Inst|Conf) ([a-z0-9+.-]+)(?::(amd64|all))?(?: \[([^]\s]+)\])? \(([^\s()]+) ([^\r\n]*?) \[(amd64|all)\]\)(?: \[([a-z0-9+. :\-]*)\])?", line)
            need(action is not None, "simulation-action-format")
            kind, package, explicit_arch, old, new, origin, arch, pending = action.groups()
            key = names.get(package)
            need(key in changed and arch == chosen[key]["architecture"] and explicit_arch in {None, arch}
                 and new == NEW and (old == OLD if kind == "Inst" else old is None)
                 and origin, "simulation-unplanned-package-or-version")
            need(pending is None or all(name in chosen for name in pending.split()), "simulation-unplanned-pending-dependency")
            values = observed if kind == "Inst" else configured
            need(key not in values, "simulation-repeated-action")
            values.add(key)
        elif line.startswith(("Remv ", "Purg ")):
            raise Refused("simulation-removal")
    need(len(summaries) == 1 and summaries[0][:3] == (len(changed), 0, 0)
         and observed == configured == changed, "simulation-incomplete-or-extra-transaction")
    return sorted(changed)


def after(before, actual):
    chosen = selected(before)
    need(set(actual) == set(before), "package-roster-changed")
    for key, row in before.items():
        expected = {**row, "version": NEW, "sourceVersion": NEW} if key in chosen else row
        need(actual[key] == expected, "installed-package-postcondition-differs")
    need(all(row["version"] == NEW for row in selected(actual).values()), "glibc-target-not-established")


def context(env):
    repository = "Apdelrahman1911/mobile-release-kit"
    ref = env.get("GITHUB_REF", "")
    sha = env.get("GITHUB_SHA", "")
    need(env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
         and env.get("RUNNER_OS") == "Linux" and env.get("RUNNER_ARCH") == "X64"
         and env.get("GITHUB_EVENT_NAME") == "push" and env.get("GITHUB_REPOSITORY") == repository
         and (ref, env.get("GITHUB_JOB"), env.get("MRK_INSTALLED_SHELL_CASE")) in ROUTES,
         "fixed-hosted-setup-route")
    need(re.fullmatch(r"[0-9a-f]{40}", sha) is not None and sha != "0" * 40
         and sha == env.get("MRK_PUSH_EVENT_AFTER") == env.get("GITHUB_WORKFLOW_SHA")
         and env.get("GITHUB_WORKFLOW_REF") == repository + "/.github/workflows/desktop-ubuntu-publication.yml@" + ref
         and all(re.fullmatch(r"[1-9][0-9]{0,19}", env.get(key, "")) is not None
                 for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
         and (ref != "refs/heads/verify/desktop-shell-host-metadata" or env.get("GITHUB_RUN_ATTEMPT") == "1"),
         "original-setup-source-run")
    return {key: env[key] for key in ("GITHUB_SHA", "GITHUB_WORKFLOW_SHA", "GITHUB_WORKFLOW_REF",
            "GITHUB_REF", "GITHUB_JOB", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}


def read(root, name):
    for directory in (root, *root.parents):
        need(stat.S_ISDIR(directory.lstat().st_mode), "setup-directory-type")
    parent = root.lstat()
    need(parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) == 0o700, "setup-directory-owner")
    path = root / name
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
         and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= MAX_DATA, "setup-input-metadata")
    def identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        need(identity(os.fstat(fd)) == identity(before), "setup-input-open")
        raw = bytearray()
        while len(raw) < before.st_size:
            block = os.read(fd, min(65536, before.st_size - len(raw)))
            need(block, "setup-input-short")
            raw.extend(block)
        need(identity(os.fstat(fd)) == identity(before) == identity(path.lstat()), "setup-input-changed")
    finally:
        os.close(fd)
    final_parent = root.lstat()
    need((parent.st_dev, parent.st_ino, parent.st_mode, parent.st_uid, parent.st_gid)
         == (final_parent.st_dev, final_parent.st_ino, final_parent.st_mode, final_parent.st_uid, final_parent.st_gid),
         "setup-directory-changed")
    return bytes(raw)


def main():
    try:
        run = context(os.environ)
        need(len(sys.argv) == 2 and sys.argv[1] in {"plan", "simulation", "after"}, "fixed-policy-phase")
        need(sys.platform == "linux" and os.uname().machine == "x86_64"
             and sys.flags.isolated == sys.flags.no_site == sys.flags.dont_write_bytecode == 1
             and os.getresuid()[0] != 0 and os.getresgid()[0] != 0
             and len(set(os.getresuid())) == len(set(os.getresgid())) == 1,
             "isolated-nonroot-data-policy")
        temp = Path(os.environ["RUNNER_TEMP"])
        need(temp.is_absolute() and ".." not in temp.parts and temp.resolve(strict=True) == temp, "setup-parent")
        root = temp / ("mrk-desktop-glibc89-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"])
        original = read(root, "before.tsv")
        before = snapshot(original)
        phase = sys.argv[1]
        if phase == "plan":
            print("\n".join(arguments(before)), flush=True)
        else:
            raw = read(root, "simulation.txt" if phase == "simulation" else "after.tsv")
            if phase == "simulation":
                changes = simulation(raw, before)
            else:
                after(before, snapshot(raw))
                changes = sorted(key for key, row in selected(before).items() if row["version"] == OLD)
            print("MRK-GLIBC-TUPLE-DATA " + json.dumps({"schema": "mrk-hosted-glibc-tuple-data-1",
                "phase": phase, "run": run, "beforeSha256": hashlib.sha256(original).hexdigest(),
                "observedSha256": hashlib.sha256(raw).hexdigest(), "target": NEW, "changes": changes,
                "packages": sorted(selected(before)), "runtimeAdmission": False, "nativeQualification": False},
                sort_keys=True, separators=(",", ":")), flush=True)
    except Refused as error:
        print("MRK-GLIBC-POLICY-REFUSED " + str(error), file=sys.stderr, flush=True)
        raise SystemExit(70)
    except BaseException:
        print("MRK-GLIBC-POLICY-REFUSED io-or-internal", file=sys.stderr, flush=True)
        raise SystemExit(70)


if __name__ == "__main__":
    main()
