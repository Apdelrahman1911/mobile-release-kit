"""Fixed hosted Android DATA setup; never a tool installer or process owner.

Normal import only defines DATA/functions. Only the guarded prepare entry mutates
the three named configuration objects. The existing root service's authenticated
StopPost calls settle after its original native workers have ended. A workflow
step outcome, copied JSON or a generic root invocation cannot settle this lease.
If a later workflow step fails before that service exists, the private originals
and replacements remain until disposable-VM teardown; restoration is unproved.
"""
from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time


ORIGIN = "hosted-provider-sdk-data-snapshot-v1"
ROOT = Path("/opt/mobile-release-kit/qualification-inputs/android-saved3-v1")
SDK_ROOT = ROOT / "sdk"
MANIFEST = ROOT / "manifest.json"
IMAGE = "/imagegeneration/imagedata.json"
SOURCE_SDK = "/usr/local/lib/android/sdk"
SOURCE_INPUTS = {
    "licenses/android-sdk-license": (4096, "receipt", None),
    "platforms/android-35/package.xml": (32 << 10, "metadata", "platforms;android-35"),
    "platforms/android-35/source.properties": (16 << 10, "properties", "platforms;android-35"),
    "build-tools/35.0.0/package.xml": (32 << 10, "metadata", "build-tools;35.0.0"),
    "build-tools/35.0.0/source.properties": (16 << 10, "properties", "build-tools;35.0.0"),
}
CONFIGURATION = {
    "/etc/host.conf": b"multi on\n",
    "/etc/hosts": b"127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n",
    "/etc/resolv.conf": b"nameserver 127.0.0.53\noptions timeout:5 attempts:2 edns0 trust-ad\nsearch .\n",
}
DIRECTORIES = {
    str(ROOT): ["manifest.json", "sdk"],
    str(SDK_ROOT): ["build-tools", "licenses", "platforms"],
    str(SDK_ROOT / "licenses"): ["android-sdk-license"],
    str(SDK_ROOT / "platforms"): ["android-35"],
    str(SDK_ROOT / "platforms/android-35"): ["package.xml", "source.properties"],
    str(SDK_ROOT / "build-tools"): ["35.0.0"],
    str(SDK_ROOT / "build-tools/35.0.0"): ["package.xml", "source.properties"],
}
# Exact resource-free parser dependencies, not runtime/profile admission.
PARSER_SOURCE_PINS = {'android_material_preparation.py': {'size': 182020, 'sha256': '2e4c5fcad38417a76a39a2ee752d868ef77dd77ef6d4ac0baacb8c843b282041'}, 'conventional_runtime_data.py': {'size': 19198, 'sha256': 'b22b83554231bef19178fbb8723acfed71e4476df14048bd9b4c763b937743d5'}, 'android_material_data/policy.json': {'size': 61607, 'sha256': '51f6a65c6f683c129bba862f9c0cc74035834f1731a409d37493da54134ba210'}}
FIELDS = ("sourceCommit", "runId", "runAttempt", "job")
LIMIT = 256 << 10
CHUNK = 64 << 10


class Refused(RuntimeError):
    """Only fixed invariant labels escape this private DATA boundary."""


def need(ok, label):
    if not ok:
        raise Refused(label)


def point(end):
    need(type(end) in (int, float) and math.isfinite(end) and time.monotonic() < end,
         "hosted-data-endpoint")


def identity(item):
    return [item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns]


def pin(raw):
    return {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def _keys(value, names, label):
    need(type(value) is dict and set(value) == set(names), label)
    return value


def _source_pin(value, limit):
    _keys(value, {"size", "sha256"}, "hosted-data-source-pin-fields")
    need(type(value["size"]) is int and 0 < value["size"] <= limit
         and type(value["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]),
         "hosted-data-source-pin")


def selected(value):
    host = value.get("hostPolicy") if type(value) is dict else None
    generated = host.get("generated") if type(host) is dict else None
    rule = generated.get("sdkLicense") if type(generated) is dict else None
    return type(rule) is dict and rule.get("classification") == ORIGIN


def rule(api, value):
    """Independent exact source pins are required before opening any source."""
    need(selected(value) and "_retained" not in value, "hosted-data-policy-not-admitted")
    candidate = value["hostPolicy"]["generated"]["sdkLicense"]
    provision = _keys(candidate.get("provisioning"),
        {"schemaVersion", "root", "manifestPath", "image", "sourceInputs", "configuration"},
        "hosted-data-provisioning-fields")
    inputs = _keys(provision["sourceInputs"], {SOURCE_SDK + "/" + name for name in SOURCE_INPUTS},
                   "hosted-data-exact-five-source-inputs")
    for name, (limit, _, _) in SOURCE_INPUTS.items():
        _source_pin(inputs[SOURCE_SDK + "/" + name], limit)
    packages = [{"id": name, "metadataPath": str(SDK_ROOT / name.replace(";", "/") / "package.xml"),
                 "propertiesPath": str(SDK_ROOT / name.replace(";", "/") / "source.properties")}
                for name in api.SDK_PACKAGE_PATHS]
    expected = {
        "path": str(SDK_ROOT / "licenses/android-sdk-license"), "classification": ORIGIN,
        "imagePath": IMAGE, "sourceRecipe": api.SDK_SOURCE_RECIPE,
        "licenseDefinition": {"id": "android-sdk-license", "normalizedSha1": api.LICENSE_HASH,
                              "normalizedSha256": api.LICENSE_NORMALIZED_SHA256},
        "packages": packages,
        "provisioning": {"schemaVersion": 1, "root": str(ROOT), "manifestPath": str(MANIFEST),
            "image": api.SDK_IMAGE, "sourceInputs": inputs,
            "configuration": {name: pin(raw) for name, raw in CONFIGURATION.items()}},
    }
    need(canonical(candidate) == canonical(expected), "hosted-data-complete-source-rule")
    host_inputs = api._input_rules(value)
    required = {IMAGE, str(MANIFEST), *(str(SDK_ROOT / name) for name in SOURCE_INPUTS), *CONFIGURATION}
    need(required <= set(host_inputs["files"])
         and set(inputs).isdisjoint(host_inputs["files"])
         and all(host_inputs["directories"].get(name) == children for name, children in DIRECTORIES.items()),
         "hosted-data-protected-consumer-roster")
    return deepcopy(candidate)


def input_limit(name):
    if name == str(MANIFEST):
        return LIMIT
    for relative, (limit, _, _) in SOURCE_INPUTS.items():
        if name == str(SDK_ROOT / relative):
            return limit
    return None


def _close_all(fds, first):
    """Remove custody before each sole close; never retry a possibly reused FD."""
    failures = []
    while fds:
        fd = fds.pop()
        try:
            os.close(fd)
        except BaseException as error:
            failures.append(type(error).__name__)
    if failures and first is None:
        first = Refused("hosted-data-original-close")
    if first is not None:
        if failures:
            first.hosted_data_close_errors = [*getattr(first, "hosted_data_close_errors", []), *failures]
        raise first


def read_original(path, limit, end, *, protected, device=None, expected=None):
    """Held/no-follow DATA read with complete PRE/POST and sole consuming close.

    Low-trust input permissions are classified, never converted to protection.
    Only independently pinned bytes may subsequently be published by prepare.
    """
    path = Path(path)
    need(path.is_absolute() and str(path) == os.path.normpath(str(path)) and 0 <= limit <= LIMIT,
         "hosted-data-fixed-original-path")
    fds, ancestors, row, raw, first = [], [], None, None, None
    try:
        parent = None
        for name in (Path("/"), *list(reversed(path.parents))[1:]):
            point(end)
            before = os.lstat(name)
            need(stat.S_ISDIR(before.st_mode), "hosted-data-original-directory")
            if protected:
                need(before.st_uid == before.st_gid == 0 and not before.st_mode & 0o7022,
                     "hosted-data-protected-directory")
            need(device is None or before.st_dev == device, "hosted-data-original-device")
            fd = os.open(str(name) if parent is None else name.name,
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         **({} if parent is None else {"dir_fd": parent}))
            fds.append(fd)
            attributes = sorted(os.listxattr(fd))
            need(not os.get_inheritable(fd) and identity(os.fstat(fd)) == identity(before)
                 and identity(os.lstat(name)) == identity(before)
                 and len(attributes) <= 32 and all(len(item) <= 256 for item in attributes)
                 and (not protected or not attributes), "hosted-data-directory-custody")
            ancestors.append((name, fd, identity(before), attributes))
            parent = fd
        point(end)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        fds.append(fd)
        before = os.fstat(fd)
        original = identity(before)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o7000
             and 0 <= before.st_size <= limit and (device is None or before.st_dev == device)
             and identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == original
             and not os.get_inheritable(fd), "hosted-data-original-file")
        attributes = sorted(os.listxattr(fd))
        need(len(attributes) <= 32 and all(len(item) <= 256 for item in attributes)
             and (not protected or before.st_uid == before.st_gid == 0
                  and not before.st_mode & 0o7022 and not attributes), "hosted-data-file-protection")
        pieces, count = [], 0
        while count <= before.st_size:
            point(end)
            block = os.read(fd, min(CHUNK, before.st_size + 1 - count))
            if not block:
                break
            pieces.append(block)
            count += len(block)
        raw = b"".join(pieces)
        need(len(raw) == before.st_size and identity(os.fstat(fd)) == original
             == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
             == identity(os.lstat(path)) and sorted(os.listxattr(fd)) == attributes,
             "hosted-data-original-drift")
        for name, held, before_dir, attrs in ancestors:
            need(identity(os.fstat(held)) == before_dir == identity(os.lstat(name))
                 and sorted(os.listxattr(held)) == attrs, "hosted-data-ancestry-drift")
        need(expected is None or pin(raw) == expected, "hosted-data-independent-byte-pin")
        row = {"path": str(path), **pin(raw), "identity": original, "xattrs": attributes,
               "ancestry": {str(name): {"identity": state, "xattrs": attrs}
                            for name, _, state, attrs in ancestors},
               "classification": "protected-original" if protected else "low-trust-data-original"}
    except BaseException as error:
        first = error
    _close_all(fds, first)
    point(end)
    need(row is not None and identity(os.lstat(path)) == row["identity"]
         and all(identity(os.lstat(name)) == state for name, _, state, _ in ancestors),
         "hosted-data-named-post-close")
    return raw, row


def _kernel(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    first, raw = None, b""
    try:
        while len(raw) <= limit:
            block = os.read(fd, min(CHUNK, limit + 1 - len(raw)))
            if not block:
                break
            raw += block
        need(len(raw) <= limit, "hosted-data-kernel-extent")
    except BaseException as error:
        first = error
    _close_all([fd], first)
    return raw


def filesystem(end, *, initial=True):
    """Unchanged root-device/ext4-XFS contract; not an overlay/VPS repair."""
    point(end)
    need(sys.platform == "linux" and os.uname().machine == "x86_64", "hosted-data-platform")
    raw = _kernel("/proc/" + str(os.getpid()) + "/mountinfo", LIMIT)
    rows = []
    for line in raw.decode("ascii").splitlines():
        fields = line.split()
        need("-" in fields and len(fields) >= 10, "hosted-data-mount-shape")
        split = fields.index("-")
        need(split >= 6 and len(fields) >= split + 4, "hosted-data-mount-fields")
        rows.append((fields[2], fields[3], fields[4], fields[split + 1]))
    roots = [row for row in rows if row[2] == "/"]
    current = os.lstat("/")
    need(len(roots) == 1 and roots[0][1] == "/" and roots[0][3] in ("ext4", "xfs")
         and roots[0][0] == str(os.major(current.st_dev)) + ":" + str(os.minor(current.st_dev))
         and current.st_uid == current.st_gid == 0 and not current.st_mode & 0o7022,
         "hosted-data-root-filesystem")
    targets = [str(ROOT), "/var/lib", *CONFIGURATION, IMAGE,
               *(SOURCE_SDK + "/" + name for name in SOURCE_INPUTS)]
    need(all(not any(mount != "/" and (path == mount or path.startswith(mount + "/"))
                     for _, _, mount, _ in rows) for path in targets), "hosted-data-separate-input-mount")
    if initial:
        for role in ("mnt", "user", "pid"):
            need(os.stat("/proc/self/ns/" + role).st_ino == os.stat("/proc/1/ns/" + role).st_ino,
                 "hosted-data-initial-namespace")
    point(end)
    return {"device": current.st_dev, "mountInfo": raw}


def _engine(end, context, device, custody):
    # Capture reviewed parser SOURCE as DATA, then import only fresh protected
    # copies. The mutable checkout is never an import donor for root parsing.
    base = Path(__file__).absolute().parent
    need(set(PARSER_SOURCE_PINS) == {"android_material_preparation.py", "conventional_runtime_data.py",
                                    "android_material_data/policy.json"}, "hosted-data-parser-source-roster")
    originals = {name: read_original(base / name, expected["size"], end, protected=False, expected=expected)[0]
                 for name, expected in PARSER_SOURCE_PINS.items()}
    target = Path("/var/lib/mrk-android-hosted-parser-" + context["runId"] + "-" + context["runAttempt"])
    _mkdir(target, end, device, custody["directories"])
    _mkdir(target / "android_material_data", end, device, custody["directories"])
    for name, raw in originals.items():
        custody["files"].append(_fresh(target / name, raw, 0o444, end, device))
    for row in custody["files"]:
        _same(row, end, device)
    spec = importlib.util.spec_from_file_location("_fixed_hosted_android_material_data",
                                                target / "android_material_preparation.py")
    engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(engine)
    for row in custody["files"]:
        _same(row, end, device)
    return engine


def _retire_parser_sources(custody, end, device):
    # These pure parser imports launch no worker. Retire only proven temporary
    # source copies after the guarded entry's final actual parser consumer.
    errors = []
    for row in reversed(custody["files"]):
        try:
            _unlink_owned(row, end, device)
        except BaseException as error:
            errors.append(type(error).__name__)
    for row in reversed(custody["directories"]):
        try:
            path = Path(row["path"])
            need(_directory(path, end, device) == row["identity"] and os.listdir(path) == [],
                 "hosted-data-parser-directory-conflict")
            with _parent(path.parent, end, device) as parent:
                need(identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))[:5] == row["identity"],
                     "hosted-data-parser-directory-retirement")
                os.rmdir(path.name, dir_fd=parent)
            _absent(path)
        except BaseException as error:
            errors.append(type(error).__name__)
    return errors


def _environment(api, mode):
    need(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), "hosted-data-root-owner")
    env = os.environ
    ref = "refs/heads/verify/desktop-shell-host-metadata" if mode == "observe-sdk" else "refs/heads/verify/desktop-installed-shell"
    need(env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
         and env.get("RUNNER_OS") == "Linux" and env.get("RUNNER_ARCH") == "X64"
         and env.get("GITHUB_EVENT_NAME") == "push" and env.get("GITHUB_REF") == ref
         and env.get("GITHUB_REPOSITORY") == "Apdelrahman1911/mobile-release-kit"
         and env.get("GITHUB_WORKFLOW_REF") == "Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-ubuntu-publication.yml@" + ref
         and env.get("GITHUB_JOB") == "compile", "hosted-data-original-workflow")
    sha = env.get("GITHUB_SHA", "")
    need(re.fullmatch(r"[0-9a-f]{40}", sha) is not None
         and sha == env.get("GITHUB_WORKFLOW_SHA") == env.get("MRK_PUSH_EVENT_AFTER")
         and all(re.fullmatch(r"[1-9][0-9]{0,19}", env.get(name, "")) is not None
                 for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "hosted-data-original-attempt")
    if mode == "prepare":
        need(env.get("MRK_INSTALLED_SHELL_CASE") == "compile"
             and env.get("MRK_INSTALLED_SHELL_SCOPE") == "android-saved-signing3-v1"
             and env.get("MRK_INSTALLED_SHELL_TRANSPORT") == "android-same-job-local-v1",
             "hosted-data-selected-consumer")
    else:
        need(env.get("MRK_INSTALLED_SHELL_CASE") == "host-metadata-only"
             and env.get("GITHUB_RUN_ATTEMPT") == "1", "hosted-data-observation-only")
    need(env.get("ImageOS") == "ubuntu24" and (api is None
         or env.get("ImageVersion") == api.SDK_IMAGE["image_version"]), "hosted-data-original-image")
    return {"sourceCommit": sha, "runId": env["GITHUB_RUN_ID"],
            "runAttempt": env["GITHUB_RUN_ATTEMPT"], "job": env["GITHUB_JOB"]}


def _parse(api, kind, package, raw):
    if kind == "receipt":
        return api._sdk_receipt_ids(raw)
    return (api._sdk_local_package if kind == "metadata" else api._sdk_source_properties)(package, raw)


def _sdk_originals(api, end, device, reviewed=None):
    image_raw, image = read_original(IMAGE, 64 << 10, end, protected=True, device=device)
    image["correspondence"] = api._sdk_image_identity(image_raw)
    rows, bodies = {}, {}
    for name, (limit, kind, package) in SOURCE_INPUTS.items():
        path = SOURCE_SDK + "/" + name
        raw, row = read_original(path, limit, end, protected=False, device=device,
                                 expected=None if reviewed is None else reviewed[path])
        rows[name] = {**row, "correspondence": _parse(api, kind, package, raw)}
        bodies[name] = raw
    return image, rows, bodies


def _directory(path, end, device):
    point(end)
    path = Path(path)
    for name in (*reversed(path.parents), path):
        item = os.lstat(name)
        need(stat.S_ISDIR(item.st_mode) and item.st_uid == item.st_gid == 0
             and not item.st_mode & 0o7022 and item.st_dev == device
             and not os.listxattr(name, follow_symlinks=False), "hosted-data-owned-directory")
    return identity(path.lstat())[:5]


@contextmanager
def _parent(path, end, device):
    """Hold exact protected ancestry for the following single namespace effect."""
    fds, rows, first = [], [], None
    try:
        parent = None
        for name in (*reversed(path.parents), path):
            point(end)
            before = name.lstat()
            need(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0
                 and not before.st_mode & 0o7022 and before.st_dev == device,
                 "hosted-data-effect-directory")
            fd = os.open(str(name) if parent is None else name.name,
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         **({} if parent is None else {"dir_fd": parent}))
            fds.append(fd)
            need(identity(os.fstat(fd)) == identity(before) == identity(name.lstat())
                 and not os.listxattr(fd) and not os.get_inheritable(fd), "hosted-data-effect-custody")
            rows.append((name, fd, identity(before)[:5]))
            parent = fd
        yield parent
        for name, fd, before in rows:
            point(end)
            need(identity(os.fstat(fd))[:5] == before == identity(name.lstat())[:5]
                 and not os.listxattr(fd), "hosted-data-effect-ancestry-drift")
    except BaseException as error:
        first = error
    _close_all(fds, first)


def _unlink_owned(row, end, device):
    _same(row, end, device)
    path = Path(row["path"])
    with _parent(path.parent, end, device) as parent:
        need(identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == row["identity"],
             "hosted-data-owned-retirement-drift")
        os.unlink(path.name, dir_fd=parent)
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refused("hosted-data-owned-retirement-incomplete")


def _seal_directory(row, mode, end, device):
    path = Path(row["path"])
    with _parent(path.parent, end, device) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        first = None
        try:
            need(identity(os.fstat(fd))[:5] == row["identity"]
                 and identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))[:5] == row["identity"]
                 and not os.listxattr(fd), "hosted-data-created-directory-drift")
            os.fchmod(fd, mode)
            current = identity(os.fstat(fd))[:5]
            need(identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))[:5] == current,
                 "hosted-data-directory-seal-drift")
        except BaseException as error:
            first = error
        _close_all([fd], first)
    row["identity"] = _directory(path, end, device)
    need(row["identity"] == current, "hosted-data-directory-seal-close")


def _fresh(path, raw, mode, end, device):
    need(type(raw) is bytes and len(raw) <= LIMIT and mode in (0o400, 0o444), "hosted-data-output-bound")
    parent = _directory(path.parent, end, device)
    fd = None
    # Creation is descriptor-relative under held no-follow ancestry. Ownership
    # moves immediately to this function, including a later parent-close error.
    try:
        with _parent(path.parent, end, device) as parent_fd:
            fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent_fd)
    except BaseException as error:
        _close_all([] if fd is None else [fd], error)
    first, row = None, None
    try:
        original = os.fstat(fd)
        need(stat.S_ISREG(original.st_mode) and original.st_nlink == 1
             and original.st_uid == original.st_gid == 0 and original.st_dev == device
             and not os.listxattr(fd), "hosted-data-fresh-output")
        offset = 0
        while offset < len(raw):
            point(end)
            count = os.write(fd, raw[offset:offset + CHUNK])
            need(count > 0, "hosted-data-output-short-write")
            offset += count
        os.fsync(fd)
        os.fchmod(fd, mode)
        state = identity(os.fstat(fd))
        os.lseek(fd, 0, os.SEEK_SET)
        body = b""
        while len(body) <= len(raw):
            point(end)
            chunk = os.read(fd, min(CHUNK, len(raw) + 1 - len(body)))
            if not chunk:
                break
            body += chunk
        need(body == raw and identity(os.fstat(fd)) == state == identity(path.lstat())
             and _directory(path.parent, end, device) == parent, "hosted-data-output-readback")
        row = {"path": str(path), **pin(raw), "identity": state}
    except BaseException as error:
        first = error
    _close_all([fd], first)
    point(end)
    need(row is not None and identity(path.lstat()) == row["identity"]
         and _directory(path.parent, end, device) == parent, "hosted-data-output-close")
    return row


def _mkdir(path, end, device, owned):
    _directory(path.parent, end, device)
    with _parent(path.parent, end, device) as parent:
        os.mkdir(path.name, 0o700, dir_fd=parent)
    state = _directory(path, end, device)
    owned.append({"path": str(path), "identity": state})
    return state


def _absent(path):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    raise Refused("hosted-data-namespace-collision")


def _same(row, end, device):
    point(end)
    path = Path(row["path"])
    _directory(path.parent, end, device)
    need(identity(path.lstat()) == row["identity"], "hosted-data-owned-object-drift")
    if "linkTarget" in row:
        need(os.readlink(path) == row["linkTarget"], "hosted-data-owned-link-drift")
    else:
        read_original(path, row["size"], end, protected=True, device=device,
                      expected={key: row[key] for key in ("size", "sha256")})
        need(identity(path.lstat()) == row["identity"], "hosted-data-owned-body-drift")


def _moved(row, destination, end, device):
    current = identity(destination.lstat())
    need(current[:8] == row["identity"][:8], "hosted-data-known-rename-identity")
    result = {**row, "path": str(destination), "identity": current}
    _same(result, end, device)
    return result


def _rename_noreplace(source_parent, source_name, target_parent, target_name, end):
    """One documented Linux no-replace transfer; never a replacing fallback."""
    import ctypes
    import errno
    try:
        library = ctypes.CDLL(None, use_errno=True)
        transfer = library.renameat2
    except (AttributeError, OSError):
        raise Refused("hosted-data-no-replace-unavailable") from None
    transfer.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    transfer.restype = ctypes.c_int
    ctypes.set_errno(0)
    point(end)
    result = transfer(source_parent, os.fsencode(source_name), target_parent, os.fsencode(target_name), 1)
    error = ctypes.get_errno()
    if result != 0:
        if error == errno.EEXIST:
            raise Refused("hosted-data-namespace-collision")
        if error in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
            raise Refused("hosted-data-no-replace-unavailable")
        raise Refused("hosted-data-no-replace-failed")


def _rename(row, destination, end, device):
    _same(row, end, device)
    source = Path(row["path"])
    with _parent(source.parent, end, device) as source_parent:
        with _parent(destination.parent, end, device) as target_parent:
            need(identity(os.stat(source.name, dir_fd=source_parent, follow_symlinks=False)) == row["identity"],
                 "hosted-data-original-before-transfer")
            try:
                os.stat(destination.name, dir_fd=target_parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refused("hosted-data-namespace-collision")
            _rename_noreplace(source_parent, source.name, target_parent, destination.name, end)
    return _moved(row, destination, end, device)


def _configuration_originals(api, end, device):
    rows = []
    for name in CONFIGURATION:
        path = Path(name)
        _directory(path.parent, end, device)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode):
            need(name == "/etc/resolv.conf" and current.st_uid == current.st_gid == 0
                 and current.st_nlink == 1 and current.st_dev == device
                 and not os.listxattr(path, follow_symlinks=False), "hosted-data-resolver-link")
            target = os.readlink(path)
            need(target in ("/run/systemd/resolve/stub-resolv.conf", "../run/systemd/resolve/stub-resolv.conf")
                 and identity(path.lstat()) == identity(current), "hosted-data-fixed-resolver-link")
            row = {"path": name, "identity": identity(current), "linkTarget": target}
            raw, source = read_original("/run/systemd/resolve/stub-resolv.conf", 128 << 10,
                                        end, protected=False)
        else:
            raw, source = read_original(path, 128 << 10, end, protected=True, device=device)
            row = {key: source[key] for key in ("path", "size", "sha256", "identity")}
        if name == "/etc/resolv.conf":
            configuration = api._network_configuration_data(name, raw, end)
            need(configuration["nameservers"] == ["127.0.0.53"],
                 "hosted-data-existing-loopback-resolver-required")
            row["resolverSource"] = source
        rows.append(row)
    return rows


def _restore(rows, end, device):
    """Only exact owned replacement and retained original pairs may be moved."""
    results, errors = [], []
    for row in reversed(rows):
        name = row["original"]["path"]
        result = {"path": name, "restored": False, "temporaryRemoved": False}
        results.append(result)
        try:
            original, replacement = row.get("backup"), row.get("installed")
            if original is None:
                # Remove only a proven unused temporary; an uncertain transfer
                # cannot prove the live original and therefore retains both.
                _same(row["original"], end, device)
                _unlink_owned(row["temporary"], end, device)
                result.update(restored=True, temporaryRemoved=True, state="original-unchanged-owned-temporary-removed")
                continue
            _same(original, end, device)
            destination = Path(name)
            if replacement is not None:
                _same(replacement, end, device)
                row["temporary"] = _rename(replacement, Path(row["temporary"]["path"]), end, device)
            else:
                _absent(destination)
            restored = _rename(original, destination, end, device)
            row["restored"] = restored
            result["restored"] = True
            temporary = row["temporary"]
            _unlink_owned(temporary, end, device)
            result.update(temporaryRemoved=True, state="original-restored-owned-replacement-removed")
        except BaseException as error:
            result["state"] = "retained-conflict-or-unknown"
            errors.append({"path": name, "errorType": type(error).__name__})
    return {"configuration": results, "errors": errors,
            "allOriginalsRestored": len(results) == len(CONFIGURATION) and all(row["restored"] for row in results)}


def _setup_failure(first, changes, context, cleanup_end, device):
    """No consumer has started: settle known pairs once within the original end."""
    retire_end = min(cleanup_end, time.monotonic() + 5)
    try:
        result = _restore(changes, retire_end, device)
    except BaseException as error:
        first.hosted_setup_cleanup_error = type(error).__name__
        return
    first.hosted_setup_cleanup = result
    journal = Path("/var/lib/mrk-android-hosted-data-" + context["runId"] + "-" + context["runAttempt"])
    try:
        _fresh(journal / "setup-failure.json", canonical({"firstError": type(first).__name__, **result}),
               0o400, retire_end, device)
    except BaseException as error:
        first.hosted_setup_cleanup_record_error = type(error).__name__


def prepare(api, value, context, end, host, *, cleanup_end=None):
    selected_rule = rule(api, value)  # Null/unknown pins refuse before creation.
    cleanup_end = end if cleanup_end is None else cleanup_end
    need(type(cleanup_end) in (int, float) and math.isfinite(cleanup_end)
         and end <= cleanup_end <= end + 10, "hosted-data-action-cleanup-bound")
    device = host["device"]
    image, sources, bodies = _sdk_originals(api, end, device, selected_rule["provisioning"]["sourceInputs"])
    originals = _configuration_originals(api, end, device)
    journal = Path("/var/lib/mrk-android-hosted-data-" + context["runId"] + "-" + context["runAttempt"])
    for path in (ROOT, journal):
        _absent(path)
    need(_kernel("/proc/" + str(os.getpid()) + "/mountinfo", LIMIT) == host["mountInfo"],
         "hosted-data-mount-drift")
    owned, changes, first = [], [], None
    prepared = None
    try:
        _mkdir(journal, end, device, owned)
        _mkdir(journal / "originals", end, device, owned)
        # No source object is chowned/chmodded. Missing task prefix components
        # are newly created; preexisting protected parents retain their modes.
        for path in (ROOT.parent.parent, ROOT.parent):
            try:
                _directory(path, end, device)
            except FileNotFoundError:
                _mkdir(path, end, device, owned)
        _mkdir(ROOT, end, device, owned)
        for path in sorted((Path(name) for name in DIRECTORIES if name != str(ROOT)),
                           key=lambda item: (len(item.parts), str(item))):
            _mkdir(path, end, device, owned)
        snapshots = {name: _fresh(SDK_ROOT / name, bodies[name], 0o444, end, device) for name in SOURCE_INPUTS}
        for original in originals:
            name = Path(original["path"]).name
            temporary = Path("/etc/.mrk-android-" + context["runId"] + "-" + context["runAttempt"] + "-" + name)
            row = {"original": original, "backup": None, "installed": None,
                   "temporary": _fresh(temporary, CONFIGURATION[original["path"]], 0o444, end, device)}
            changes.append(row)
        intent = {"schemaVersion": 1, "origin": ORIGIN, "context": context, "policySha256": api.POLICY_SHA256,
                  "image": image, "sourceOriginals": sources, "ownedDirectories": owned,
                  "sdk": snapshots, "configuration": changes, "producerExecutionProven": False, "newConsent": False}
        _fresh(journal / "intent.json", canonical(intent), 0o400, end, device)
        for row in changes:
            destination = journal / "originals" / Path(row["original"]["path"]).name
            row["backup"] = _rename(row["original"], destination, end, device)
            row["installed"] = _rename(row["temporary"], Path(row["original"]["path"]), end, device)
        for item in reversed(owned):
            path = Path(item["path"])
            if path == ROOT or path.is_relative_to(ROOT) or path in (ROOT.parent.parent, ROOT.parent):
                _seal_directory(item, 0o755 if path == ROOT.parent.parent else 0o555, end, device)
        manifest = {"schemaVersion": 1, "origin": ORIGIN, "context": context, "policySha256": api.POLICY_SHA256,
                    "image": image["correspondence"],
                    "imageOriginal": {key: image[key] for key in ("path", "size", "sha256", "identity")},
                    "sourceRecipe": api.SDK_SOURCE_RECIPE,
                    "sourceInputs": selected_rule["provisioning"]["sourceInputs"], "snapshots": snapshots,
                    "configuration": {row["original"]["path"]: row["installed"] for row in changes},
                    "journal": str(journal), "producerExecutionProven": False, "newConsent": False,
                    "state": "owned-through-original-consumers"}
        manifest_pin = _fresh(MANIFEST, canonical(manifest), 0o444, end, device)
        for name, children in DIRECTORIES.items():
            need(sorted(os.listdir(name)) == children, "hosted-data-complete-output-roster")
        prepared = {**intent, "configuration": changes, "ownedDirectories": owned, "manifest": manifest_pin,
                    "state": "owned-through-original-consumers"}
        _fresh(journal / "prepared.json", canonical(prepared), 0o400, end, device)
        need(_kernel("/proc/" + str(os.getpid()) + "/mountinfo", LIMIT) == host["mountInfo"],
             "hosted-data-mount-drift")
        point(end)
    except BaseException as error:
        first = error
    if first is not None:
        # This guarded DATA setup launches no worker; in-process failure has no
        # consumer to join. Unknown transfers remain retained, never inferred.
        _setup_failure(first, changes, context, cleanup_end, device)
        raise first
    return prepared


def _manifest(api, value, host, end):
    selected_rule = rule(api, value)
    binding = host["bindings"]["files"][str(MANIFEST)]
    with api._stock_host_original(binding, str(MANIFEST), LIMIT, end) as (raw, original):
        manifest = api.D.decode(raw, LIMIT)
    _keys(manifest, {"schemaVersion", "origin", "context", "policySha256", "image", "imageOriginal", "sourceRecipe", "sourceInputs",
        "snapshots", "configuration", "journal", "producerExecutionProven", "newConsent", "state"},
        "hosted-data-manifest-fields")
    context = _keys(manifest["context"], FIELDS, "hosted-data-context-fields")
    need(type(context["sourceCommit"]) is str and re.fullmatch(r"[0-9a-f]{40}", context["sourceCommit"])
         and all(type(context[name]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", context[name])
                 for name in ("runId", "runAttempt")) and context["job"] == "compile",
         "hosted-data-manifest-context")
    need(manifest["schemaVersion"] == 1 and manifest["origin"] == ORIGIN
         and manifest["policySha256"] == api.POLICY_SHA256 and manifest["image"] == api.SDK_IMAGE
         and manifest["sourceRecipe"] == api.SDK_SOURCE_RECIPE
         and manifest["sourceInputs"] == selected_rule["provisioning"]["sourceInputs"]
         and manifest["producerExecutionProven"] is False and manifest["newConsent"] is False
         and manifest["state"] == "owned-through-original-consumers"
         and manifest["journal"] == "/var/lib/mrk-android-hosted-data-" + context["runId"] + "-" + context["runAttempt"],
         "hosted-data-manifest-correspondence")
    image_row = _keys(manifest["imageOriginal"], {"path", "size", "sha256", "identity"},
                      "hosted-data-image-original-fields")
    image_binding = host["bindings"]["files"][IMAGE]
    image_state = image_row["identity"]
    need(type(image_state) is list and len(image_state) == 9
         and all(type(number) is int for number in image_state)
         and image_row["path"] == IMAGE and image_state[3:6] == [0, 0, 1]
         and image_binding["identity"] == [image_state[index] for index in (0, 1, 2, 5, 6, 7, 8)]
         and all(image_binding[key] == image_row[key] for key in ("path", "size", "sha256")),
         "hosted-data-original-image-binding")
    _keys(manifest["snapshots"], SOURCE_INPUTS, "hosted-data-manifest-five-snapshots")
    _keys(manifest["configuration"], CONFIGURATION, "hosted-data-manifest-three-configurations")
    for name, row in manifest["configuration"].items():
        _keys(row, {"path", "size", "sha256", "identity"}, "hosted-data-configuration-original-fields")
        actual = api._protected_binding(host["bindings"]["files"][name], name)
        need(row["path"] == name and {key: row[key] for key in ("size", "sha256")} == pin(CONFIGURATION[name])
             and all(actual[key] == row[key] for key in ("path", "size", "sha256"))
             and _binding_identity(host["bindings"]["files"][name], row["identity"]),
             "hosted-data-configuration-original")
    return manifest, original


def _binding_identity(binding, full):
    # conventional_runtime_data.state is dev/ino/mode/nlink/size/mtime_ns/ctime_ns.
    need(type(full) is list and len(full) == 9 and all(type(item) is int for item in full)
         and full[2:6] == [stat.S_IFREG | 0o444, 0, 0, 1]
         and full[0] >= 0 and full[1] > 0 and 0 <= full[6] <= LIMIT,
         "hosted-data-full-nine-identity")
    return binding["identity"] == [full[index] for index in (0, 1, 2, 5, 6, 7, 8)]


def receipt_state(api, value, host, end):
    manifest, manifest_original = _manifest(api, value, host, end)
    proof = {"classification": ORIGIN, "sourceRecipe": deepcopy(api.SDK_SOURCE_RECIPE),
             "currentUse": "selected-provider-data-snapshot-no-install-v1",
             "producerExecutionProven": False, "newConsent": False, "packages": {},
             "provisioning": {"manifest": manifest_original, "context": manifest["context"],
                              "sourceInputs": manifest["sourceInputs"], "configuration": manifest["configuration"]}}
    files = host["bindings"]["files"]
    with api._stock_host_original(files[IMAGE], IMAGE, 64 << 10, end) as (raw, original):
        summary = api._sdk_image_identity(raw)
    proof["image"] = {**original, "correspondence": summary}
    for name, (limit, kind, package) in SOURCE_INPUTS.items():
        selected_path = str(SDK_ROOT / name)
        row = manifest["snapshots"][name]
        _keys(row, {"path", "size", "sha256", "identity"}, "hosted-data-snapshot-fields")
        need(row["path"] == selected_path and _binding_identity(files[selected_path], row["identity"])
             and {key: row[key] for key in ("size", "sha256")} == manifest["sourceInputs"][SOURCE_SDK + "/" + name],
             "hosted-data-snapshot-original")
        with api._stock_host_original(files[selected_path], selected_path, limit, end) as (raw, original):
            need(pin(raw) == manifest["sourceInputs"][SOURCE_SDK + "/" + name],
                 "hosted-data-consumed-source-pin")
            summary = _parse(api, kind, package, raw)
        result = {**original, "correspondence": summary}
        if kind == "receipt":
            proof["receipt"] = result
        else:
            proof["packages"].setdefault(package, {})[kind] = result
    point(end)
    return proof


def context_correspondence(value, host, context):
    if selected(value):
        proof = host["graph"].get("androidGenerated", {}).get("sdkLicense", {})
        need(proof.get("classification") == ORIGIN and type(proof.get("provisioning")) is dict
             and proof["provisioning"].get("context") == {name: context[name] for name in FIELDS},
             "hosted-data-original-compiler-context")


def settle(value, domain, end, api):
    """Called only after existing root-owner authenticated manager StopPost.

    No standalone settle command exists. Independently repeat the actual process
    binding here; the caller's existing domain admission additionally proves
    MainPID=0, ControlPID=self, original invocation, limits and stop-post phase.
    """
    point(end)
    need(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0) and os.getppid() == 1,
         "hosted-data-original-manager-child")
    unit = "mrk-ubuntu-native-" + value["runId"] + "-" + value["attempt"] + ".service"
    need(domain["unit"]["Id"] == unit and domain["unit"]["ControlGroup"] == "/system.slice/" + unit
         and domain["sourceSha"] == value["sourceSha"]
         and domain["invocationId"] == os.environ.get("INVOCATION_ID")
         and _kernel("/proc/" + str(os.getpid()) + "/cgroup", 4096) == ("0::/system.slice/" + unit + "\n").encode(),
         "hosted-data-original-stop-domain")
    device = filesystem(end)["device"]
    journal = Path("/var/lib/mrk-android-hosted-data-" + value["runId"] + "-" + value["attempt"])
    raw, original = read_original(journal / "prepared.json", LIMIT, end, protected=True, device=device)
    prepared = json.loads(raw)
    need(prepared["origin"] == ORIGIN and prepared["state"] == "owned-through-original-consumers"
         and prepared["context"] == {"sourceCommit": value["sourceSha"], "runId": value["runId"],
                                    "runAttempt": value["attempt"], "job": "compile"}
         and prepared["policySha256"] == api.POLICY_SHA256
         and prepared["producerExecutionProven"] is False and prepared["newConsent"] is False,
         "hosted-data-original-setup-journal")
    _same(prepared["manifest"], end, device)
    rows = prepared["configuration"]
    need(type(rows) is list and len(rows) == len(CONFIGURATION)
         and [row["original"]["path"] for row in rows] == list(CONFIGURATION),
         "hosted-data-original-config-roster")
    _fresh(journal / "settlement-intent.json", canonical({"sourceSha": value["sourceSha"],
        "invocationId": domain["invocationId"], "prepared": original, "state": "after-original-manager-teardown"}),
        0o400, end, device)
    result = _restore(rows, end, device)
    _fresh(journal / "settlement.json", canonical(result), 0o400, end, device)
    need(result["allOriginalsRestored"] and not result["errors"], "hosted-data-restoration-retained-conflict")
    return {"origin": ORIGIN, "configurationOriginalsRestored": 3, "temporaryReplacementsRemoved": 3,
            "sourceSnapshotsRetainedForEvidence": True, "nativeQualified": False,
            "boundary": "original-manager-stop-post-after-native-workers"}


def main():
    need(sys.argv[1:] in (["prepare"], ["observe-sdk"]), "hosted-data-fixed-entry")
    mode, started = sys.argv[1], time.monotonic()
    end, action_end = started + 45, started + 55  # Within the workflow's fixed 60s outer bound.
    context = _environment(None, mode)
    host = filesystem(end)
    os.umask(0o077)
    custody, first, result, prepared = {"files": [], "directories": []}, None, None, None
    try:
        api = _engine(end, context, host["device"], custody)
        need(_environment(api, mode) == context, "hosted-data-workflow-context-drift")
        if mode == "observe-sdk":
            image, sources, _ = _sdk_originals(api, end, host["device"])
            result = {"schemaVersion": 1, "scope": "android-hosted-sdk-pin-proposal-only-v1", "context": context,
                      "image": image["correspondence"], "sourceRecipe": api.SDK_SOURCE_RECIPE,
                      "inputs": {row["path"]: {key: row[key] for key in ("size", "sha256")} for row in sources.values()},
                      "classification": "low-trust-originals-not-runtime-admission",
                      "sourceChanged": False, "profileAdmitted": False, "nativeQualified": False,
                      "producerExecutionProven": False, "newConsent": False}
        else:
            prepared = prepare(api, api.policy(), context, end, host, cleanup_end=action_end)
            result = {"scope": ORIGIN, "state": "owned-through-original-consumers", "sdkInputs": 5,
                      "configurationReplacements": 3, "nativeQualified": False,
                      "producerExecutionProven": False, "newConsent": False}
        point(end)  # Work/consumers never borrow the separate retirement interval.
    except BaseException as error:
        first = error
    cleanup = []
    try:
        cleanup = _retire_parser_sources(custody, min(action_end, time.monotonic() + 5), host["device"])
        need(not cleanup, "hosted-data-parser-source-retirement")
    except BaseException as error:
        if first is None:
            first = error
        else:
            first.hosted_parser_retirement_error = type(error).__name__
    if first is None:
        try:
            point(action_end)
            print(canonical(result).decode("ascii"), end="", flush=True)
        except BaseException as error:
            first = error
    if first is not None:
        first.hosted_parser_cleanup_errors = cleanup
        # A returned prepared journal is the sole in-process restoration token.
        # A failed prepare already attempted its own cleanup: never repeat it.
        # The compiler/native consumer starts only after this entry exits zero.
        if prepared is not None:
            _setup_failure(first, prepared["configuration"], context, action_end, host["device"])
        raise first


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        # Do not print private hosts, resolver data, identities or exception text.
        print("Fixed hosted Android DATA step refused; originals retained, no native admission.", file=sys.stderr)
        raise SystemExit(70)
