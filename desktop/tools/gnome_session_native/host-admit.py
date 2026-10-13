"""Finite Ubuntu24 host reservation for the foreground GNOME SESSION fixture.

Loaded only by the source-authenticated hosted controller.  The pure parsers are
inert contract subjects; importing this file performs no host reads or commands.
There is no account adoption, retry, deletion, provider repair, or NSS-negative
absence inference.  Private snapshots must never be uploaded.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

UID = GID = 61000
NAME = "mrk-gnome-fixture"
MIB = 1 << 20
ROWS = 32768
CAPS = 0x2001C5
GROUPADD = ("/usr/sbin/groupadd", "--system", "--gid", "61000", NAME)
USERADD = ("/usr/sbin/useradd", "--system", "--uid", "61000", "--gid", "61000",
           "--no-user-group", "--no-create-home", "--no-log-init", "--home-dir",
           "/nonexistent", "--shell", "/usr/sbin/nologin", "--comment",
           "MRK GNOME fixture", NAME)
BUS = ("/usr/bin/busctl", "--system", "--no-pager", "--auto-start=no",
       "--timeout=5s", "--json=short", "call")
DBUS = ("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus")
MANAGER = "org.freedesktop.systemd1"
ACCOUNT_FILES = ("passwd", "group", "shadow", "gshadow")
EMPTY_DIRS = ("/etc/userdb", "/run/userdb", "/run/host/userdb", "/usr/lib/userdb",
              "/etc/shadow-maint/useradd-pre.d", "/etc/shadow-maint/useradd-post.d",
              "/run/nscd", "/var/cache/nscd", "/run/sssd", "/var/lib/sss", "/etc/sssd")
ABSENT = ("/usr/sbin/nscd", "/usr/sbin/sss_cache", "/etc/nscd.conf",
          "/nonexistent", "/var/mail/" + NAME, "/var/spool/mail/" + NAME)
FORBIDDEN_PACKAGES = {"nscd", "unscd", "sssd", "systemd-homed", "systemd-userdbd", "systemd-container"}
FORBIDDEN_UNITS = {"systemd-homed.service", "systemd-homed-activate.service",
                   "systemd-userdbd.service", "systemd-userdbd.socket",
                   "systemd-machined.service", "nscd.service", "sssd.service"}
ALIASES = {"/bin": "usr/bin", "/sbin": "usr/sbin", "/lib": "usr/lib",
           "/lib64": "usr/lib64", "/var/run": "/run", "/var/spool/mail": "../mail"}
STAGES = ("before-creation", "after-creation", "before-owner", "after-settlement")


class Refused(Exception):
    """Finite refusal codes only; never include account or process DATA."""


def need(value, code):
    if not value:
        raise Refused(code)


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def number(value, *, positive=False):
    need(type(value) is str and re.fullmatch(r"[0-9]{1,10}", value) is not None,
         "unsigned-number-shape")
    result = int(value)
    need(int(positive) <= result < (1 << 32) - 1, "unsigned-number-range")
    return result


def user_name(value):
    need(type(value) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,254}\$?", value),
         "account-name-shape")
    return value


def parse_status(raw):
    need(type(raw) is bytes and 0 < len(raw) < 16384 and raw.endswith(b"\n"),
         "process-status-bound-frame")
    result = {}
    for line in raw.decode("ascii", "strict").splitlines():
        key, colon, value = line.partition(":")
        need(colon and key not in result, "process-status-duplicate-or-shape")
        result[key] = value.split()
    need(all(key in result for key in ("Uid", "Gid", "Groups"))
         and len(result["Uid"]) == len(result["Gid"]) == 4, "process-identity-width")
    for key in ("Uid", "Gid", "Groups"):
        values = [number(value) for value in result[key]]
        if key == "Groups":
            need(len(values) == len(set(values)), "process-groups-duplicate")
        result[key] = values
    return result


def parse_nss(raw):
    rules = {}
    for line in raw.decode("ascii", "strict").splitlines():
        line = line.partition("#")[0].strip()
        if not line:
            continue
        key, colon, value = line.partition(":")
        key = key.strip()
        need(bool(colon), "nss-rule-shape")
        if key in ("passwd", "group"):
            need(key not in rules, "nss-rule-duplicate")
            rules[key] = value.split()
    need(rules.get("passwd") == ["files", "systemd"]
         and rules.get("group") in (["files", "systemd"], ["files", "[SUCCESS=merge]", "systemd"]),
         "unsupported-nss-provider-rule")
    return rules


def parse_login_defs(raw):
    defaults = {"UID_MIN": 1000, "UID_MAX": 60000, "GID_MIN": 1000, "GID_MAX": 60000,
                "SYS_UID_MIN": 100, "SYS_UID_MAX": 999, "SYS_GID_MIN": 100, "SYS_GID_MAX": 999}
    observed = {}
    for line in raw.decode("ascii", "strict").splitlines():
        words = line.partition("#")[0].split()
        if not words:
            continue
        if words[0] in defaults:
            need(len(words) == 2 and words[0] not in observed, "automatic-range-duplicate-shape")
            observed[words[0]] = number(words[1], positive=True)
    effective = {**defaults, **observed}
    for prefix in ("UID", "GID", "SYS_UID", "SYS_GID"):
        low, high = effective[prefix + "_MIN"], effective[prefix + "_MAX"]
        need(0 < low <= high <= (999 if prefix.startswith("SYS_") else 60000)
             and not low <= UID <= high, "automatic-allocation-conflict")
        if prefix.startswith("SYS_"):
            need((low, high) == (100, 999), "unsupported-system-allocation-range")
    return effective


def parse_subids(raw):
    need(type(raw) is bytes and len(raw) <= MIB and (not raw or raw.endswith(b"\n")),
         "subordinate-bound-frame")
    seen = set()
    for line in raw.decode("ascii", "strict").splitlines():
        if not line:
            continue
        row = line.split(":")
        need(len(row) == 3 and tuple(row) not in seen, "subordinate-duplicate-shape")
        seen.add(tuple(row))
        need(len(seen) <= ROWS, "subordinate-record-bound")
        grantee, start, count = row
        if grantee.isascii() and grantee.isdecimal():
            need(number(grantee) != UID, "subordinate-numeric-grantee-conflict")
        else:
            need(user_name(grantee) != NAME, "subordinate-grantee-conflict")
        start, count = number(start), number(count, positive=True)
        end = start + count - 1
        need(end < (1 << 32) - 1, "subordinate-overflow")
        need(not start <= UID <= end, "subordinate-range-conflict")
    return len(seen)


def parse_accounts(raw, kind, created):
    need(kind in ACCOUNT_FILES and len(raw) <= MIB and raw.endswith(b"\n"), "account-bound-frame")
    width = {"passwd": 7, "group": 4, "shadow": 9, "gshadow": 4}[kind]
    records = {}
    for line in raw.decode("utf-8", "strict").splitlines():
        if not line:
            continue
        row = line.split(":")
        need(len(row) == width and "\x00" not in line, "account-record-shape")
        name = user_name(row[0])
        need(name not in records and len(records) < ROWS, "account-duplicate-bound")
        records[name] = row
        if kind in ("passwd", "group"):
            value = number(row[2])
            need(value != UID or (created and name == NAME), "local-numeric-conflict")
        if kind == "passwd":
            need(number(row[3]) != GID or (created and name == NAME), "local-primary-group-conflict")
        if kind in ("group", "gshadow"):
            for members in (row[3:], row[2:3] if kind == "gshadow" else []):
                for entry in members:
                    names = entry.split(",") if entry else []
                    need(len(names) == len(set(names)) and NAME not in names, "local-membership-conflict")
                    for item in names:
                        user_name(item)
    need((NAME in records) is created, "local-reservation-state")
    if created:
        row = records[NAME]
        if kind == "passwd":
            need(row == [NAME, "x", "61000", "61000", "MRK GNOME fixture", "/nonexistent", "/usr/sbin/nologin"],
                 "created-user-record")
        elif kind == "group":
            need(row == [NAME, "x", "61000", ""], "created-group-record")
        elif kind == "gshadow":
            need(row == [NAME, "!", "", ""], "created-group-shadow-record")
        else:
            need(row[1] == "!" and row[2].isascii() and row[2].isdecimal()
                 and 0 < int(row[2]) < (1 << 31) and row[3:] == [""] * 6,
                 "created-locked-system-shadow-record")
    return records


def unrelated_bytes(raw):
    prefix = (NAME + ":").encode("ascii")
    return b"".join(line for line in raw.splitlines(keepends=True) if not line.startswith(prefix))


def decode_bus(raw, signature):
    need(type(raw) is bytes and 0 < len(raw) < MIB and raw.endswith(b"\n"), "backend-bound-frame")
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "backend-duplicate-json-field")
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Refused("backend-nonfinite-json")))
    need(type(value) is dict and set(value) == {"type", "data"} and value["type"] == signature
         and type(value["data"]) is list and len(value["data"]) == 1, "backend-reply-signature")
    return value["data"][0]


def parse_dynamic_users(raw):
    rows = decode_bus(raw, "a(us)")
    need(type(rows) is list and len(rows) <= ROWS, "backend-record-bound")
    seen = set()
    for row in rows:
        need(type(row) is list and len(row) == 2 and type(row[0]) is int
             and 0 <= row[0] < (1 << 32) - 1, "backend-record-shape")
        user_name(row[1])
        need(tuple(row) not in seen, "backend-record-duplicate")
        seen.add(tuple(row))
        # No automatic-range filter: static/explicit IDs and group objects count.
        need(row[0] != UID and row[1] != NAME, "backend-reservation-conflict")
    return len(rows)


class HostAdmission:
    def __init__(self, command, supplier_facts):
        # command is the private controller's authenticated run_owned adapter,
        # not a user-supplied program, timeout, environment, or backend route.
        self.command = command
        need(supplier_facts.get("shadowCacheHelpers") == {
            "nscd": "/usr/sbin/nscd", "sssCache": "/usr/sbin/sss_cache"}, "shadow-helper-source-unestablished")
        need(supplier_facts.get("systemdVersion") == "255.4-1ubuntu8.17"
             and supplier_facts.get("shadowVersion") == "1:4.13+dfsg1-4ubuntu3.2",
             "unsupported-account-provider-supplier")

    @staticmethod
    def ancestors(path):
        for parent in reversed(path.parents):
            s = parent.lstat()
            if str(parent) in ALIASES and stat.S_ISLNK(s.st_mode):
                need(s.st_uid == 0 and os.readlink(parent) == ALIASES[str(parent)], "host-alias-differs")
            else:
                need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                     "host-path-ancestor")

    def read(self, name, limit=MIB, *, optional=False):
        path = Path(name)
        self.ancestors(path)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except FileNotFoundError:
            if optional:
                return None
            raise Refused("required-host-file-absent")
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == 0
                 and not before.st_mode & 0o022 and 0 <= before.st_size <= limit, "host-file-state-bound")
            chunks, count = [], 0
            while block := os.read(fd, min(65536, before.st_size - count + 1)):
                chunks.append(block)
                count += len(block)
                need(count <= before.st_size, "host-file-grew")
            need(count == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
                 "host-file-changed")
            raw = b"".join(chunks)
            return {"identity": identity(before), "sha256": hashlib.sha256(raw).hexdigest(), "raw": raw}
        finally:
            os.close(fd)

    @staticmethod
    def kernel(path, limit=16383):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            raw = os.read(fd, limit + 1)
            need(len(raw) <= limit and not os.read(fd, 1), "kernel-property-bound")
            return raw
        finally:
            os.close(fd)

    def empty_or_absent(self, name):
        path = Path(name)
        # An absent ancestor is real absence only after its nearest existing
        # parent has been authenticated; symlink/dangling aliases are not absent.
        current = path
        while True:
            try:
                s = current.lstat()
                break
            except FileNotFoundError:
                need(current != current.parent, "host-root-absent")
                current = current.parent
        self.ancestors(current)
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
             "provider-directory-shape")
        if current != path:
            return {"absent": True}
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            need(os.listdir(fd) == [] and identity(os.fstat(fd)) == identity(s) == identity(path.lstat()),
                 "provider-or-hook-directory-occupied")
        finally:
            os.close(fd)
        return {"empty": True, "identity": identity(s)}

    def absent(self, name):
        path = Path(name)
        current = path.parent
        while not current.exists():
            need(not current.is_symlink(), "absent-path-dangling-ancestor")
            current = current.parent
        self.ancestors(current / ".host-check")
        need(not path.exists() and not path.is_symlink(), "forbidden-host-path-occupied")
        return {"absent": True}

    def socket(self, name):
        path = Path(name)
        self.ancestors(path)
        s = path.lstat()
        need(stat.S_ISSOCK(s.st_mode) and s.st_uid == 0 and s.st_gid == 0, "provider-socket-owner-kind")
        return identity(s)

    def root_identity(self):
        need(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0) and os.getgroups() == [],
             "root-original-identity")
        fields = parse_status(self.kernel("/proc/self/status"))
        need(fields["Uid"] == fields["Gid"] == [0] * 4 and fields["Groups"] == [], "root-full-identity")
        for key in ("CapPrm", "CapEff", "CapBnd"):
            values = fields.get(key, [])
            need(len(values) == 1 and re.fullmatch(r"[0-9a-f]{16}", values[0])
                 and int(values[0], 16) & CAPS == CAPS, "root-required-capabilities")
        for name in ("uid_map", "gid_map"):
            need(self.kernel("/proc/self/" + name).split() == [b"0", b"0", b"4294967295"],
                 "root-initial-identity-mapping")
        need(self.kernel("/proc/self/setgroups") == b"allow\n", "root-setgroups-policy")

    def census(self, deadline):
        count = vanished = 0
        seen = set()
        with os.scandir("/proc") as processes:
            for process in processes:
                if not re.fullmatch(r"[1-9][0-9]{0,9}", process.name):
                    continue
                need(time.monotonic() < deadline, "host-phase-deadline")
                paths = [(Path(process.path) / "status", process.name)]
                try:
                    with os.scandir(Path(process.path) / "task") as threads:
                        for thread in threads:
                            need(re.fullmatch(r"[1-9][0-9]{0,9}", thread.name), "host-thread-name")
                            if thread.name != process.name:
                                paths.append((Path(thread.path) / "status", thread.name))
                            need(len(paths) + count <= ROWS, "host-census-bound")
                except FileNotFoundError:
                    need(not Path(process.path).exists(), "host-task-directory-missing")
                    vanished += 1
                    continue
                for path, tid in paths:
                    key = (process.name, tid)
                    need(key not in seen and count < ROWS, "host-census-duplicate-bound")
                    seen.add(key)
                    count += 1
                    try:
                        fields = parse_status(self.kernel(path))
                    except FileNotFoundError:
                        need(not path.parent.exists(), "host-status-missing-with-live-task")
                        vanished += 1
                        continue
                    need(all(UID not in fields[key] for key in ("Uid", "Gid", "Groups")),
                         "active-host-credential-conflict")
        need(count > 0, "host-census-empty")
        return {"records": count, "vanished": vanished, "threadCredentialsIncluded": True}

    def profile(self):
        result = {}
        for name in EMPTY_DIRS:
            result[name] = self.empty_or_absent(name)
        for name in ABSENT:
            result[name] = self.absent(name)
        for name, target in ALIASES.items():
            s = Path(name).lstat()
            need(stat.S_ISLNK(s.st_mode) and s.st_uid == 0 and os.readlink(name) == target,
                 "supported-host-alias")
            result[name] = {"link": target, "identity": identity(s)}
        root = Path("/run/systemd/userdb")
        self.ancestors(root)
        s = root.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022
             and sorted(os.listdir(root)) == ["io.systemd.DynamicUser"], "sole-dynamicuser-provider")
        result["dynamicSocket"] = self.socket(str(root / "io.systemd.DynamicUser"))
        result["systemBusSocket"] = self.socket("/run/dbus/system_bus_socket")
        for name in ("/etc/nsswitch.conf", "/etc/login.defs", "/etc/default/useradd", "/var/lib/dpkg/status"):
            value = self.read(name, 32 * MIB if name.endswith("/status") else MIB)
            result[name] = {k: value[k] for k in ("identity", "sha256")}
            if name.endswith("nsswitch.conf"):
                result["nss"] = parse_nss(value["raw"])
            elif name.endswith("login.defs"):
                result["automaticRanges"] = parse_login_defs(value["raw"])
            elif name.endswith("/status"):
                packages = set()
                for paragraph in value["raw"].decode("utf-8", "strict").split("\n\n"):
                    selected = [line[9:] for line in paragraph.splitlines() if line.startswith("Package: ")]
                    if not selected:
                        continue
                    need(len(selected) == 1 and selected[0] not in packages, "package-census-shape")
                    packages.add(selected[0])
                    need(selected[0] not in FORBIDDEN_PACKAGES and not selected[0].startswith("sssd-"),
                         "unsupported-provider-package")
                need(0 < len(packages) <= ROWS, "package-census-bound")
        for base in ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system"):
            p = Path(base)
            if not p.exists():
                result[base] = self.absent(base)
                continue
            self.ancestors(p / ".unit-check")
            names = os.listdir(p)
            need(len(names) <= 4096 and not FORBIDDEN_UNITS.intersection(names), "foreign-provider-activation")
            for name in names:
                if name.endswith((".wants", ".requires")):
                    child = p / name
                    need(child.is_dir() and not child.is_symlink(), "activation-directory-kind")
                    self.ancestors(child / ".unit-check")
                    items = os.listdir(child)
                    need(len(items) <= 4096 and not FORBIDDEN_UNITS.intersection(items), "foreign-provider-activation")
        for base in ("/usr/share/dbus-1/system-services", "/etc/dbus-1/system-services"):
            for name in ("org.freedesktop.home1.service", "org.freedesktop.machine1.service",
                         "org.freedesktop.userdb1.service"):
                self.absent(base + "/" + name)
        return result

    def backend(self, stage, deadline):
        pid1 = parse_status(self.kernel("/proc/1/status"))
        need(pid1["Uid"] == pid1["Gid"] == [0] * 4, "system-manager-root-identity")
        for name in ("uid_map", "gid_map"):
            need(self.kernel("/proc/1/" + name).split() == [b"0", b"0", b"4294967295"],
                 "system-manager-initial-mapping")
        need(os.readlink("/proc/1/exe") == "/usr/lib/systemd/systemd", "system-manager-executable")
        executable = self.read("/usr/lib/systemd/systemd", 32 * MIB)
        need(os.stat("/proc/1/exe").st_ino == executable["identity"][1]
             and os.stat("/proc/1/exe").st_dev == executable["identity"][0], "system-manager-original-executable")
        def call(role, destination, method, *arguments):
            result = self.command(stage + "-" + role, list(BUS + destination + (method,) + arguments),
                                  maximum=8, deadline=deadline, output_limit=MIB)
            need(result.returncode == 0 and result.stderr == b"", "backend-original-failed")
            return result.stdout
        owner = decode_bus(call("manager-owner", DBUS, "GetNameOwner", "s", MANAGER), "s")
        need(type(owner) is str and re.fullmatch(r":[0-9]+\.[0-9]+", owner), "system-manager-unique-owner")
        pid = decode_bus(call("manager-pid", DBUS, "GetConnectionUnixProcessID", "s", owner), "u")
        uid = decode_bus(call("manager-uid", DBUS, "GetConnectionUnixUser", "s", owner), "u")
        need(type(pid) is int and pid == 1 and type(uid) is int and uid == 0, "system-manager-peer-identity")
        raw = call("manager-roster", (MANAGER, "/org/freedesktop/systemd1", MANAGER + ".Manager"), "GetDynamicUsers")
        count = parse_dynamic_users(raw)
        need(decode_bus(call("manager-owner-post", DBUS, "GetNameOwner", "s", MANAGER), "s") == owner,
             "system-manager-owner-changed")
        return {"records": count, "managerPid": 1, "managerUid": 0,
                "managerExecutableSha256": executable["sha256"], "managerExecutableIdentity": executable["identity"],
                "rosterSha256": hashlib.sha256(raw).hexdigest(), "healthyAuthoritativeBackend": True,
                "nssTransportQualified": False}

    def capture(self, stage, deadline, *, created, baseline=None):
        need(stage in STAGES and type(created) is bool, "fixed-host-stage")
        need(time.monotonic() < deadline, "host-phase-deadline")
        self.root_identity()
        snapshot = {"stage": stage, "profile": self.profile(), "accounts": {}, "sideEffects": {}}
        for name in ACCOUNT_FILES:
            value = self.read("/etc/" + name)
            parse_accounts(value["raw"], name, created)
            snapshot["accounts"][name] = value
        for name in ("/etc/subuid", "/etc/subgid", "/var/log/lastlog", "/var/log/faillog"):
            value = self.read(name, 64 * MIB if name.startswith("/var/log/") else MIB, optional=True)
            if value is not None:
                if name in ("/etc/subuid", "/etc/subgid"):
                    parse_subids(value["raw"])
                value = {k: value[k] for k in ("identity", "sha256")}
            snapshot["sideEffects"][name] = value
        snapshot["backend"] = self.backend(stage, deadline)
        snapshot["census"] = self.census(deadline)
        if baseline is not None:
            need(snapshot["profile"] == baseline["profile"], "host-provider-configuration-changed")
            need(snapshot["sideEffects"] == baseline["sideEffects"], "home-mail-subids-login-effects")
            for name in ACCOUNT_FILES:
                before, after = baseline["accounts"][name], snapshot["accounts"][name]
                need(unrelated_bytes(after["raw"]) == unrelated_bytes(before["raw"]), "unrelated-account-records-changed")
                need(after["identity"][2:6] == before["identity"][2:6], "account-database-permission-changed")
                if baseline["stage"] != "before-creation":
                    need(after == before, "reserved-account-original-changed")
        need(time.monotonic() < deadline, "host-phase-deadline")
        return snapshot

    def provision(self, deadline):
        # The controller first persists the original before-creation snapshot.
        # Each command result is persisted by its sole original owner adapter.
        for role, argv in (("groupadd", GROUPADD), ("useradd", USERADD)):
            result = self.command(role, list(argv), maximum=20, deadline=deadline, output_limit=65536)
            need(result.returncode == 0 and result.stdout == b"", "account-original-command-failed")
            expected_warning = b"useradd warning: mrk-gnome-fixture's uid 61000 is greater than SYS_UID_MAX 999\n"
            need(result.stderr in ((b"", expected_warning) if role == "useradd" else (b"",)),
                 "account-unexpected-diagnostic")


def public_projection(snapshots, *, account_created):
    need(type(account_created) is bool, "reservation-result-shape")
    stages = [row["stage"] for row in snapshots]
    need(stages == list(STAGES)[:len(stages)], "reservation-phase-order")
    return {"uid": UID, "gid": GID, "hostAccountCreated": account_created,
            "reservation": "positive-static-files-and-systemd",
            "disposition": "retained-until-disposable-vm-retirement",
            "phases": stages, "nssTransportQualified": False,
            "completeHostThreadCensus": len(stages) == 4,
            "scope": "fresh-bounded-snapshots-not-arbitrary-future-privileged-host-exclusion"}
