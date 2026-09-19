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
