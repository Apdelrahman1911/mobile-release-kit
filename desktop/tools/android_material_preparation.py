"""One fixed, private same-VM Android material preparation.

This is DATA plumbing for the existing Ubuntu compiler/publication owner. Import,
``validate`` and ``read_record`` do not launch commands. ``prepare`` uses only the
caller's existing private_command owner, original deadline and failure latch.
No SDK manager, Java, Gradle, licence acceptance or package maintainer script is
run here. A missing reviewed host policy refuses before acquisition or creation.
"""
from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager, ExitStack
import gzip
import hashlib
import importlib.util
import io
import math
import os
from pathlib import Path
import posixpath
import re
import stat
import tarfile
import time
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
import zipfile


def _data_module():
    spec = importlib.util.spec_from_file_location("_publisher_android_material_data",
        Path(__file__).with_name("conventional_runtime_data.py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


D = _data_module()
SCOPE = "android-same-vm-private-material-v1"
POLICY_SHA256 = "b785a69a9856d4ab333fed6383921601a85f1d340778e799982d59fea9a2627f"
DATA = Path(__file__).with_name("android_material_data")
DOCS = {"manifest": ("android-toolchain.json", 4 << 20),
        "osContract": ("os-contract.json", 1 << 20), "sources": ("source-rows.json", 4 << 20)}
PRIVATE_DOCS = {"context": 64 << 10, "host": 32 << 20, "provenance": 8 << 20}
AUXILIARY = {"replay.curl": 512 << 10, "body-142.redirect": 4096, "body-143.redirect": 4096}
FONT_OUTPUTS = {"font-cache.stdout": 512 << 10, "font-list.stdout": 32 << 10}
AUXILIARY.update(FONT_OUTPUTS)
PROVIDER_OUTPUTS = {"provider-diagnostics.stdout": 64 << 10, "provider-cache.stdout": 512 << 10}
AUXILIARY.update(PROVIDER_OUTPUTS)
PROVIDER_CLASSIFICATION = "android-fixed-loader-structure-v1"
_PROVIDER_ELF_DATA = None
_PROVIDER_LOADER_DATA = None
FONT_CLASSIFICATION = "same-vm-font-consumer-correspondence-v1"
STOCK_CLASSIFICATION = "stock-ca-consumer-correspondence-v1"
STOCK_POLICY_SHA256 = "633273a983d53a4a493b96d949f35f2a82bcd9752f0239bb7e8f62e8d4c70f5c"
STOCK_PEM = "/etc/ssl/certs/ca-certificates.crt"
STOCK_JKS = "/etc/ssl/certs/java/cacerts"
STOCK_CUSTOM = "/usr/local/share/ca-certificates"
FONT_DIRECTORIES = ("/usr/local/share/fonts", "/usr/share/fonts", "/usr/share/fonts/truetype",
                    "/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/truetype/lato",
                    "/usr/share/fonts/truetype/liberation", "/usr/share/fonts/truetype/noto")
FONT_ROOTS = ("/etc/fonts", "/usr/share/fontconfig", "/usr/share/fonts", "/usr/local/share/fonts")
GENERATED = ("jdk/lib/security/cacerts", "sdk/build-tools/35.0.0/package.xml",
             "sdk/licenses/android-sdk-license", "sdk/platforms/android-35/package.xml")
CHUNK, FILE_LIMIT, TOTAL_LIMIT = 64 << 10, 512 << 20, 1 << 30
CONTEXT_FIELDS = {"sourceCommit", "sourceTree", "runId", "runAttempt", "job", "preparation"}
LICENSE_HASH = "24333f8a63b6825ea9c5514f83c2829b004d1fee"
LICENSE_NORMALIZED_SHA256 = "aaf80cd0aee7e569ffa8a4be1b61189c0fefccf23068e38dfafe336289b8c723"
SDK_NAMESPACE = "http://schemas.android.com/sdk/android/repo/repository2/03"
COMMON_NAMESPACE = "http://schemas.android.com/repository/android/common/02"
GENERIC_NAMESPACE = "http://schemas.android.com/repository/android/generic/02"
# Reused fixed fsys-tarfile adapter from gnome_session_hosted.acquire_archive.
# The original ordinary owner owns exec and descendants; this is not an owner.
DECODER_SCRIPT = 'set -euC; umask 077; ulimit -c 0; ulimit -f "$1"; output=$2; shift 2; exec "$@" > "$output"'
HTTP_RECEIPT = r"%{urlnum}\t%{exitcode}\t%{response_code}\t%{size_download}\t%{num_redirects}\t%{ssl_verify_result}\n"
HTTP_SUFFIX = r"\nMRK_HTTP=%{response_code}\t%{exitcode}\t%{size_download}\t%{num_redirects}\t%{ssl_verify_result}\n"


def _keys(value, fields, label):
    D.need(type(value) is dict and set(value) == set(fields), label)
    return value


def _point(deadline):
    D.need(type(deadline) in (int, float) and math.isfinite(deadline)
           and time.monotonic() < deadline, "Android original preparation endpoint expired")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _identity(item):
    return [item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns]


def _directory_identity(path):
    item = path.lstat()
    D.need(stat.S_ISDIR(item.st_mode), "Android original directory differs")
    return [item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid]


def _absolute(value):
    D.need(type(value) is str and 1 < len(value) <= 4096 and value.startswith("/")
           and re.fullmatch(r"/[A-Za-z0-9_./+@=,\-]+", value) is not None
           and str(Path(value)) == value and all(x not in ("", ".", "..") for x in value[1:].split("/")),
           "Android fixed absolute DATA path differs")
    return Path(value)


def _tool_path(value):
    D.relative(value)
    parts = value.split("/")
    D.need(1 < len(parts) <= 16 and parts[0] in {"jdk", "gradle", "sdk", "bundletool"}
           and all(len(x) <= 255 and not x.endswith(".") for x in parts), "Android material path differs")
    return value


def policy():
    raw = D.read(DATA / "policy.json", 64 << 10)
    D.need(_sha(raw) == POLICY_SHA256, "Android preparation policy source differs")
    value = D.decode(raw, 64 << 10)
    D.need(value["schemaVersion"] == 1 and value["supplierCount"] == 401
           and value["supplierBytes"] == 678706726, "Android fixed policy extent differs")
    return value


def _control(value, name):
    pin = value["documents"][name]
    raw = D.read(DATA / name, pin["size"])
    D.need(len(raw) == pin["size"] and _sha(raw) == pin["sha256"], "Android fixed control differs")
    if name.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as decoder:
            raw = decoder.read(pin["decodedSize"] + 1)
            D.need(len(raw) == pin["decodedSize"] and not decoder.read(1), "Android control expansion bound")
    D.need(len(raw) == pin["decodedSize"] and _sha(raw) == pin["decodedSha256"], "Android control body differs")
    return D.decode(raw, pin["decodedSize"])


def _context(context):
    _keys(context, CONTEXT_FIELDS, "Android original context shape differs")
    D.need(all(type(context[k]) is str and re.fullmatch(r"[0-9a-f]{40}", context[k]) for k in ("sourceCommit", "sourceTree"))
           and all(type(context[k]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", context[k]) for k in ("runId", "runAttempt"))
           and type(context["job"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", context["job"]),
           "Android original source/run/job differs")
    pin = _keys(context["preparation"], {"path", "size", "sha256"}, "Android preparation reference differs")
    path = _absolute(pin["path"])
    D.need(path.name == "preparation.json" and type(pin["size"]) is int and 0 < pin["size"] <= 16384,
           "Android original preparation path/bound differs")
    D.bound(path, pin)
    original = D.decode(D.read(path, pin["size"]), 16384)
    _keys(original, {"sourceSha", "runId", "attempt", "source", "root", "deadline", "runnerUid", "runnerGid",
                    "rootIdentity", "workIdentity", "shellCase", "job"}, "Android compiler preparation row differs")
    D.need((original["sourceSha"], original["runId"], original["attempt"], original["job"], original["shellCase"])
           == (context["sourceCommit"], context["runId"], context["runAttempt"], context["job"], "compile")
           and type(original["runnerUid"]) is int and type(original["runnerGid"]) is int
           and original["runnerUid"] > 0 and original["runnerGid"] > 0 and path.parent == _absolute(original["root"])
           and _directory_identity(path.parent) == original["rootIdentity"], "Android compiler namespace/role changed")
    # Compiler work may legitimately be removed after its consumer settles.
    # Never use an absent work directory as permission to renew the preparation.
    if (path.parent / "work").exists():
        D.need(_directory_identity(path.parent / "work") == original["workIdentity"], "Android original compiler work changed")
    D.need(type(original["deadline"]) is str and re.fullmatch(r"[0-9]+\.[0-9]+", original["deadline"]),
           "Android original compiler endpoint differs")
    return original


def _private(path, owner, *, directory=False, mode=0o400):
    item = path.lstat()
    D.need((item.st_uid, item.st_gid) == owner and stat.S_IMODE(item.st_mode) == mode
           and (stat.S_ISDIR(item.st_mode) if directory else stat.S_ISREG(item.st_mode) and item.st_nlink == 1)
           and not os.listxattr(path, follow_symlinks=False), "Android private original ownership/mode/attributes differ")
    return _identity(item)


def _protected_ancestry(binding):
    path = _absolute(binding["path"])
    D.need(type(binding["ancestry"]) is dict and {str(p) for p in path.parents} <= set(binding["ancestry"]),
           "Android protected host canonical ancestry is incomplete")
    for name, original in binding["ancestry"].items():
        p = _absolute(name) if name != "/" else Path("/")
        D.need(type(original) is list and len(original) == 5 and all(type(v) is int for v in original)
               and _directory_identity(p) == original and original[3:] == [0, 0] and not original[2] & 0o7022
               and not os.listxattr(p, follow_symlinks=False), "Android protected host ancestor changed")
    for name, original, target in binding["links"]:
        item = _absolute(name).lstat()
        D.need(stat.S_ISLNK(item.st_mode) and item.st_uid == item.st_gid == 0 and item.st_nlink == 1
               and list(D.state(item)) == original and os.readlink(name) == target,
               "Android protected host alias changed")


def _protected_binding(binding, expected_path):
    """Recheck an existing compiler protected_host_file record, without commands."""
    _keys(binding, {"path", "size", "sha256", "selectedPath", "identity", "links", "ancestry"},
          "Android protected host binding shape differs")
    D.need(binding["selectedPath"] == expected_path and type(binding["size"]) is int
           and 0 <= binding["size"] <= FILE_LIMIT, "Android host selection differs")
    path = _absolute(binding["path"])
    _protected_ancestry(binding)
    item = path.lstat()
    D.need(item.st_uid == item.st_gid == 0 and not item.st_mode & 0o7022 and item.st_nlink == 1
           and stat.S_ISREG(item.st_mode) and not os.listxattr(path, follow_symlinks=False)
           and list(D.state(item)) == binding["identity"] and Path(expected_path).resolve(strict=True) == path,
           "Android protected host original changed")
    expected = {"path": path.name, "size": binding["size"], "sha256": binding["sha256"]}
    D.bound(path, expected)
    D.need(list(D.state(path.lstat())) == binding["identity"], "Android host original changed after hash")
    _protected_ancestry(binding)
    return {"path": str(path), "size": expected["size"], "sha256": expected["sha256"], "mode": stat.S_IMODE(item.st_mode)}


def _empty_directory(path, deadline):
    """Observe at most one entry; never collect or export an unexpected name."""
    _point(deadline)
    with os.scandir(path) as entries:
        D.need(next(entries, None) is None, "Android expected-empty input contains an entry")
    _point(deadline)


def _protected_namespace(binding, expected_path, *, children=None, deadline=None):
    """Recheck the ordinary shell directory/absence companion, not a new census."""
    fields = {"path", "selectedPath", "links", "ancestry"}
    _keys(binding, fields | ({"directory"} if children is not None else {"absent", "absentAt"}),
          "Android protected host namespace shape differs")
    D.need(binding["selectedPath"] == expected_path, "Android host namespace selection differs")
    path = _absolute(binding["path"])
    if children is None:
        missing = _absolute(binding["absentAt"])
        D.need(binding["absent"] is True and missing in (path, *path.parents)
               and Path(expected_path).resolve(strict=False) == path,
               "Android host absence boundary differs")
        # For an absent nested path, only ancestors up to its first absent
        # component exist. Do not require or invent identities below it.
        parent_binding = {**binding, "path": str(missing)}
        _protected_ancestry(parent_binding)
        D.need(not missing.exists() and not missing.is_symlink(), "Android protected host absence changed")
        _protected_ancestry(parent_binding)
        return
    D.need(type(children) is list and children == sorted(set(children)) and len(children) <= 512
           and all(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.+@\-]{1,255}", name)
                   and name not in (".", "..") for name in children), "Android fixed directory membership differs")
    _protected_ancestry(binding)
    original = _directory_identity(path)
    D.need(binding["directory"] == original and original[3:] == [0, 0] and not original[2] & 0o7022
           and Path(expected_path).resolve(strict=True) == path and not os.listxattr(path, follow_symlinks=False),
           "Android protected host directory changed")
    if children:
        D.need(sorted(entry.name for entry in path.iterdir()) == children,
               "Android fixed directory membership changed")
    else:
        _empty_directory(path, deadline)
    D.need(_directory_identity(path) == original, "Android fixed directory original changed")
    _protected_ancestry(binding)


def _input_rules(value):
    rules = value["hostPolicy"]
    D.need(type(rules) is dict, "Android target supplier/configuration/licence policy is not yet admitted")
    inputs = _keys(rules["inputs"], {"files", "directories", "absences"}, "Android fixed host input roster differs")
    D.need(type(inputs["files"]) is list and 0 < len(inputs["files"]) <= 512
           and inputs["files"] == sorted(set(inputs["files"])) and type(inputs["directories"]) is dict
           and len(inputs["directories"]) <= 128 and type(inputs["absences"]) is list
           and len(inputs["absences"]) <= 512 and inputs["absences"] == sorted(set(inputs["absences"])),
           "Android finite host input extent/order differs")
    all_paths = [*inputs["files"], *inputs["directories"], *inputs["absences"]]
    D.need(len(all_paths) == len(set(all_paths)), "Android fixed host input roles collide")
    for name in all_paths:
        _absolute(name)
    return inputs


def android_host_inputs(native, bindings, *, bind_path, deadline):
    """Bind only the source-policy delta through the existing protected reader.

    No command, package discovery, native execution, or mutation of the original
    shell inventory occurs. Existing files retain their original identity;
    fonts/configuration not present in the shell executable map get their own
    original before any material preparation. Full shell DATA correspondence is
    still checked independently by the unchanged original shell owner.
    """
    _point(deadline)
    inputs = _input_rules(policy())
    D.need(type(native) is dict and type(bindings) is dict and type(bindings.get("files")) is dict
           and "androidDirectories" not in bindings and "androidAbsences" not in bindings,
           "Android original shell host input shape differs")
    host = {"graph": deepcopy(native), "bindings": deepcopy(bindings)}
    files = host["bindings"]["files"]
    for name in inputs["files"]:
        _point(deadline)
        if name not in files:
            files[name] = bind_path(Path(name), limit=FILE_LIMIT)
        _protected_binding(files[name], name)
    for key, names, options in (("androidDirectories", inputs["directories"], {"directory_only": True}),
                                ("androidAbsences", inputs["absences"], {"absent": True})):
        selected = {}
        for name in names:
            _point(deadline)
            selected[name] = bind_path(Path(name), **options)
            _protected_namespace(selected[name], name,
                                 children=inputs["directories"][name] if key == "androidDirectories" else None,
                                 deadline=deadline)
        host["bindings"][key] = selected
    _provider_host_inputs(policy(), host, bind_path, deadline)
    _point(deadline)
    return host


@contextmanager
def _stock_original_bytes(path, original, limit, deadline, recheck):
    """One original read/close interval; the caller supplies a fixed role check.

    No process, alternate reader, inherited handle, or successor owner exists.
    A failed body keeps its primary exception; a failed close is never retried.
    """
    _point(deadline)
    recheck()
    stream, before = D._open(path, limit)
    primary = None
    try:
        D.need(_identity(before) == original == _identity(os.fstat(stream.fileno())),
               "Android stock input changed before original read")
        raw = bytearray()
        while True:
            _point(deadline)
            block = stream.read(min(CHUNK, limit + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
            D.need(len(raw) <= limit, "Android stock original read bound")
        D.need(len(raw) == original[6] and _identity(os.fstat(stream.fileno())) == original,
               "Android stock original extent/identity changed during read")
        recheck()
        yield bytes(raw)
        _point(deadline)
        D.need(_identity(os.fstat(stream.fileno())) == original,
               "Android stock original changed during consumer")
        recheck()
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            stream.close()
        except BaseException:
            if primary is None:
                raise
            primary.add_note("Android stock original close also failed; no retry or successor.")
    _point(deadline)
    recheck()  # Successful original close and final named check precede return.


@contextmanager
def _stock_host_original(binding, selected, limit, deadline):
    _point(deadline)
    D.need(type(binding.get("size")) is int and 0 < binding["size"] <= limit,
           "Android stock input extent differs")
    row = _protected_binding(binding, selected)
    path = Path(row["path"])
    original = _identity(path.lstat())
    def recheck():
        _point(deadline)
        _protected_ancestry(binding)
        item = path.lstat()
        D.need(_identity(item) == original and list(D.state(item)) == binding["identity"]
               and item.st_uid == item.st_gid == 0 and item.st_nlink == 1
               and stat.S_ISREG(item.st_mode) and not item.st_mode & 0o7022
               and not os.listxattr(path, follow_symlinks=False)
               and Path(selected).resolve(strict=True) == path,
               "Android stock original name/owner/alias changed")
        _protected_ancestry(binding)
    with _stock_original_bytes(path, original, limit, deadline, recheck) as raw:
        D.need(len(raw) == row["size"] and _sha(raw) == row["sha256"],
               "Android stock parser bytes differ from the bound original")
        yield raw, {"binding": deepcopy(binding), "file": row, "identity": original}


@contextmanager
def _stock_private_original(path, owner, limit, deadline, *, mode=0o400, expected=None):
    _point(deadline)
    original = _private(path, owner, mode=mode)
    parent = _private(path.parent, owner, directory=True, mode=0o700)[:5]
    def recheck():
        _point(deadline)
        D.need(_private(path, owner, mode=mode) == original
               and _private(path.parent, owner, directory=True, mode=0o700)[:5] == parent,
               "Android stock private original/parent changed")
    with _stock_original_bytes(path, original, limit, deadline, recheck) as raw:
        pin = {"path": path.name, "size": len(raw), "sha256": _sha(raw), "identity": original}
        D.need(expected is None or D.same(pin, expected), "Android stock retained original differs")
        yield raw, pin


def _stock_policy():
    spec = importlib.util.spec_from_file_location("_android_stock_trust", Path(__file__).with_name("stock_trust_correspondence.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    D.need(module.POLICY_SHA256 == STOCK_POLICY_SHA256, "Android stock policy selector differs")
    return module.Policy(D.read(Path(__file__).with_name("ubuntu_stock_ca_policy.json"), 64 << 10))


def _stock_custom(host, deadline):
    binding = host["bindings"]["androidDirectories"][STOCK_CUSTOM]
    _protected_namespace(binding, STOCK_CUSTOM, children=[], deadline=deadline)
    original = _identity(Path(binding["path"]).lstat())
    _empty_directory(Path(binding["path"]), deadline)
    D.need(_identity(Path(binding["path"]).lstat()) == original, "Android custom CA directory changed")
    return {"binding": deepcopy(binding), "identity": original, "status": "empty",
            "customBodiesRead": False, "customNamesExported": False}


def _stock_trust_state(value, host, deadline):
    rule = value["hostPolicy"]["generated"]["javaTrustStore"]
    D.need(rule == {"path": STOCK_JKS, "classification": STOCK_CLASSIFICATION,
        "policySha256": STOCK_POLICY_SHA256, "pemPath": STOCK_PEM, "customCaDirectory": STOCK_CUSTOM},
        "Android stock consumer source rule differs")
    inputs = _input_rules(value)
    D.need({STOCK_PEM, STOCK_JKS} <= set(inputs["files"])
           and inputs["directories"].get(STOCK_CUSTOM) == [], "Android stock input roster is incomplete")
    policy = _stock_policy()
    proof = {"classification": STOCK_CLASSIFICATION, "policySha256": STOCK_POLICY_SHA256,
             "producerExecutionProven": False, "customCa": _stock_custom(host, deadline)}
    for kind, name, limit in (("pem", STOCK_PEM, 4 << 20), ("jks", STOCK_JKS, 1 << 20)):
        with _stock_host_original(host["bindings"]["files"][name], name, limit, deadline) as (raw, original):
            summary = getattr(policy, kind)(raw, lambda: _point(deadline))
        proof[kind] = {**original, "correspondence": summary}
    D.need(_stock_custom(host, deadline) == proof["customCa"], "Android stock custom input changed")
    _point(deadline)
    return proof


def _stock_jks_bytes(host, stock, deadline):
    """Return only bytes parsed from the bound original, after positive close."""
    with _stock_host_original(host["bindings"]["files"][STOCK_JKS], STOCK_JKS, 1 << 20, deadline) as (raw, original):
        summary = _stock_policy().jks(raw, lambda: _point(deadline))
        D.need(D.same({**original, "correspondence": summary}, stock["jks"]),
               "Android staged JKS differs from its checked original")
    return raw


def _stock_staged_jks(root, owner, row, identity, jks, deadline):
    """Compare the retained private staging original, not a publication copy."""
    # _member_output and _tree keep every non-executable private leaf0400;
    # row["mode"] describes only its later public manifest projection.
    with _stock_private_original(root / "tools" / GENERATED[0], owner, 1 << 20, deadline, mode=0o400,
        expected={"path": "cacerts", "size": row["size"], "sha256": row["sha256"],
                  "identity": identity}) as (staged, _):
        D.need(staged == jks, "Android staged JKS bytes differ from the checked original")


def _host_state(value, host, deadline):
    """A source-reviewed supplier/configuration policy, not an ambient census.

    ``runtimeData.suppliers`` is the existing portable shell DATA projection;
    ``caches`` is its explicitly separate original same-VM observation. Dynamic
    Android rows must be named in the policy and in that original observation.
    The caller independently recreates shell_data_snapshot before this check.
    """
    rules = value["hostPolicy"]
    D.need(type(rules) is dict, "Android target supplier/configuration/licence policy is not yet admitted")
    _keys(rules, {"id", "files", "aliases", "generated", "preparationFiles", "suppliersSha256",
                  "inputs"},
          "Android source host policy differs")
    _keys(host, {"bindings", "graph"}, "Android original host graph shape differs")
    runtime = host["graph"]["runtimeData"]
    D.need(_sha(D.canonical(runtime["suppliers"])) == D.sha(rules["suppliersSha256"]),
           "Android target portable supplier provenance differs")
    provider_state = _provider_state(value, host, deadline)
    bindings, files, used = host["bindings"]["files"], [], set()
    preparation_paths = {"/usr/bin/curl", "/usr/bin/bash", "/usr/bin/dpkg-deb", "/usr/bin/python3.12", "/usr/bin/fc-cat", "/usr/bin/fc-list"}
    D.need(type(rules["preparationFiles"]) is list and len(rules["preparationFiles"]) == len(preparation_paths)
           and {r["path"] for r in rules["preparationFiles"]} == preparation_paths,
           "Android fixed preparation tools/TLS source roster differs")
    for row in rules["preparationFiles"]:
        _point(deadline)
        _keys(row, {"path", "size", "sha256", "mode"}, "Android preparation source fields differ")
        D.need(row["path"] in bindings and _protected_binding(bindings[row["path"]], row["path"]) == row,
               "Android original preparation tool/TLS bytes differ")
    D.need(type(rules["files"]) is list and 0 < len(rules["files"]) <= 256
           and type(rules["aliases"]) is list and len(rules["aliases"]) <= 128,
           "Android complete OS closure exceeds its original bound")
    font_state = _font_state(value, host, deadline)
    for rule in rules["files"]:
        _point(deadline)
        _keys(rule, {"path", "origin"}, "Android OS origin row differs")
        name, origin = rule["path"], rule["origin"]
        D.need(name in bindings and name not in used, "Android OS file missing/duplicated")
        row = _protected_binding(bindings[name], name)
        D.need(row["path"] == name, "Android OS file must use its explicit canonical spelling")
        if origin.get("kind") == "supplier":
            _keys(origin, {"kind", "size", "sha256", "mode"}, "Android supplier origin fields differ")
            D.need(row == {"path": name, **{k: origin[k] for k in ("size", "sha256", "mode")}},
                   "Android portable supplier bytes/mode differ")
        else:
            _keys(origin, {"kind", "cacheRoot", "rule"}, "Android generated OS origin fields differ")
            if origin["rule"] == "font-cache":
                # Static byte/original correspondence only. The mandatory
                # paired consumers below and validate/read_record supply the
                # independent, explicitly nongeneration consumer evidence.
                D.need(origin["kind"] == "same-vm" and origin["cacheRoot"] == "/var/cache/fontconfig"
                       and name in {*font_state["roster"], "/var/cache/fontconfig/CACHEDIR.TAG"},
                       "Android font cache is outside its complete current-VM correspondence")
            elif origin["rule"] == "loader-cache":
                # The original is checked now; paired command consumption and
                # full candidate correspondence are mandatory on readback.
                D.need(origin["kind"] == "same-vm" and origin["cacheRoot"] == "/etc"
                       and name == "/etc/ld.so.cache" and name in provider_state["bindings"],
                       "Android loader cache is outside its original consumer interval")
            else:
                # No caller-populated androidValidatedFiles map can substitute
                # for the still-required loader/network rule implementation.
                raise D.Refused("Android generated loader/network rule is not yet implemented")
        used.add(name)
        files.append(row)
    D.need([r["path"] for r in files] == sorted(used), "Android OS contract order differs")
    D.need(set(provider_state["osFiles"]) <= used,
           "Android OS contract omits a required fixed provider/helper")
    aliases = deepcopy(rules["aliases"])
    for alias in aliases:
        _keys(alias, {"path", "target", "canonical"}, "Android OS alias fields differ")
        p = _absolute(alias["path"])
        item = p.lstat()
        D.need(stat.S_ISLNK(item.st_mode) and item.st_uid == item.st_gid == 0
               and os.readlink(p) == alias["target"] and p.resolve(strict=True) == _absolute(alias["canonical"]),
               "Android fixed OS alias differs")
    _keys(rules["generated"], {"javaTrustStore", "sdkLicense"}, "Android generated origins differ")
    stock = _stock_trust_state(value, host, deadline)
    generated = {"javaTrustStore": stock["jks"]["file"]}
    for role, rule in rules["generated"].items():
        if role == "javaTrustStore":
            continue  # Exact consumer contents, never an updater execution claim.
        _keys(rule, {"path", "producerSha256", "inputsSha256", "binding"}, "Android generated producer policy differs")
        D.need(rule["path"] in bindings and type(rule["binding"]) is dict,
               "Android fixed generated input is absent")
        # These producer/input projections must be generated by the admitted
        # current-host preparation. Merely copying an ambient digest cannot pass.
        proof = host["graph"]["androidGenerated"][role]
        D.need(proof["producerSha256"] == D.sha(rule["producerSha256"])
               and proof["inputsSha256"] == D.sha(rule["inputsSha256"])
               and proof["policy"] == rule["binding"] and proof["newConsent"] is False,
               "Android generated input producer/origin differs")
        generated[role] = _protected_binding(bindings[rule["path"]], rule["path"])
        D.need(rule["path"] == "/usr/local/lib/android/sdk/licenses/android-sdk-license"
               and proof["preExistingHostedImageReceipt"] is True,
               "Android SDK receipt is not the fixed existing hosted-image input")
    return {"schemaVersion": 1, "id": rules["id"], "closure": "python-jdk-sdk-gradle-shell-loader-v1",
            "files": files, "aliases": aliases}, generated


def _provider_readers():
    """Reuse the existing pure parsers, never their command entry points.

    The protected root caller supplies its already loaded lifecycle DATA
    functions. Its source roster separately pins/copies the original ELF
    parser and ci_foundation dependency; no self-hash or second owner is made.
    """
    global _PROVIDER_ELF_DATA, _PROVIDER_LOADER_DATA
    def module(name):
        spec = importlib.util.spec_from_file_location("_android_provider_" + name,
            Path(__file__).with_name(name + ".py"))
        result = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(result)
        return result
    if _PROVIDER_ELF_DATA is None:
        _PROVIDER_ELF_DATA = module("ci_ubuntu_publication").elf_dependencies
    if _PROVIDER_LOADER_DATA is None:
        lifecycle = module("ubuntu_publication_lifecycle")
        _PROVIDER_LOADER_DATA = {name: getattr(lifecycle, name) for name in (
            "loader_diagnostics", "loader_cache", "shell_loader_candidates", "loader_selected",
            "DEFAULT_LIBRARY_DIRS", "HWCAPS")}
    return _PROVIDER_ELF_DATA, _PROVIDER_LOADER_DATA


def _provider_control(value):
    control = _keys(_control(value, "providers.json"), {"schemaVersion", "classification", "toolObjects", "nestedObjects",
        "osLibraries", "programs", "packages", "loader", "ldconfig", "launches", "postJliModules", "jvm", "java",
        "expectedGlobalAbsences", "sourceCommitments", "nativeSelectorObligations", "nativeSelectionProven", "symbolBindingProven"},
        "Android fixed provider control differs")
    D.need(control["schemaVersion"] == 1 and control["classification"] == PROVIDER_CLASSIFICATION
           and len(control["toolObjects"]) == 87 and len(control["nestedObjects"]) == 6
           and len(control["osLibraries"]) == 40 and len(control["programs"]) == 8
           and control["expectedGlobalAbsences"] == ["libtinfo.so.5"]
           and control["java"] == "jdk/bin/java" and control["jvm"] == "jdk/lib/server/libjvm.so"
           and control["nativeSelectionProven"] is False and control["symbolBindingProven"] is False,
           "Android provider source extent/phase/classification differs")
    return control


def _provider_boundary(binding, selected):
    if binding.get("absent") is True:
        _protected_namespace(binding, selected)
    elif "directory" in binding:
        _keys(binding, {"path", "selectedPath", "links", "ancestry", "directory"},
              "Android loader directory original differs")
        _protected_ancestry(binding)
        path = _absolute(binding["path"])
        original = _directory_identity(path)
        D.need(binding["selectedPath"] == selected and original == binding["directory"]
               and original[3:] == [0, 0] and not original[2] & 0o7022
               and Path(selected).resolve(strict=True) == path and not os.listxattr(path, follow_symlinks=False),
               "Android protected loader directory changed")
        _protected_ancestry(binding)
    else:
        _protected_binding(binding, selected)


def _provider_host_inputs(value, host, bind_path, deadline):
    """Finite original delta using the compiler's existing protected reader."""
    control = _provider_control(value)
    _, readers = _provider_readers()
    files = host["bindings"]["files"]
    selected = [row["file"]["selectedPath"] for row in (*control["osLibraries"].values(), *control["programs"].values())]
    selected += [control["loader"]["selectedPath"], control["ldconfig"]["selectedPath"], "/etc/ld.so.cache"]
    for name in sorted(set(selected)):
        _point(deadline)
        if name not in files:
            files[name] = bind_path(Path(name), limit=FILE_LIMIT)
        _protected_binding(files[name], name)
    D.need("androidLoader" not in host["bindings"], "Android original loader delta already exists")
    bindings = {}
    for directory in readers["DEFAULT_LIBRARY_DIRS"]:
        bindings[directory] = bind_path(Path(directory), directory_only=True)
        for tier in readers["HWCAPS"]:
            name = directory + "/glibc-hwcaps/" + tier
            bindings[name] = bind_path(Path(name), directory_only=True, absent=True)
    tiers = {name: row.get("absent") is not True for name, row in bindings.items() if "/glibc-hwcaps/" in name}
    names = sorted(set(control["osLibraries"]) | set(control["expectedGlobalAbsences"]))
    # The cache cannot introduce another unbound location. A new cache path
    # outside this finite roster refuses after the original capture is parsed.
    for _, name in readers["shell_loader_candidates"](names, [], tiers):
        _point(deadline)
        bindings[name] = files[name] if name in files else bind_path(Path(name), absent=True, limit=FILE_LIMIT)
    bindings["/etc/ld.so.preload"] = bind_path(Path("/etc/ld.so.preload"), absent=True)
    D.need(len(bindings) <= 1024, "Android complete loader alternative bound")
    for name, binding in bindings.items():
        _provider_boundary(binding, name)
    host["bindings"]["androidLoader"] = bindings


def _provider_state(value, host, deadline):
    control = _provider_control(value)
    files, bindings, required = host["bindings"]["files"], {}, set()
    for row in (*control["osLibraries"].values(), *control["programs"].values()):
        _point(deadline)
        file = row["file"]
        name = file["selectedPath"]
        D.need(name in files and _protected_binding(files[name], name)
               == {key: file[key] for key in ("path", "size", "sha256", "mode")},
               "Android provider/helper differs from its exact source supplier")
        bindings[name] = files[name]
        # Font consumer executables belong to preparation, not runtime PATH.
        if name not in ("/usr/bin/fc-cat", "/usr/bin/fc-list"):
            required.add(file["path"])
    for file in (control["loader"], control["ldconfig"]):
        name = file["selectedPath"]
        D.need(name in files and _protected_binding(files[name], name)
               == {key: file[key] for key in ("path", "size", "sha256", "mode")},
               "Android original loader/static cache reader differs")
        bindings[name] = files[name]
    inputs = _input_rules(value)
    D.need("/etc/ld.so.conf" in inputs["files"] and "/etc/ld.so.conf.d" in inputs["directories"]
           and all("/etc/ld.so.conf.d/" + leaf in inputs["files"] for leaf in inputs["directories"]["/etc/ld.so.conf.d"]),
           "Android original loader configuration roster is incomplete")
    configuration = host["bindings"]["androidDirectories"]["/etc/ld.so.conf.d"]
    _protected_namespace(configuration, "/etc/ld.so.conf.d", children=inputs["directories"]["/etc/ld.so.conf.d"], deadline=deadline)
    bindings["/etc/ld.so.conf.d"] = configuration
    for name in ["/etc/ld.so.cache", *[name for name in inputs["files"] if name.startswith("/etc/ld.so.conf")]]:
        _point(deadline)
        D.need(name in files, "Android original loader input is absent")
        _protected_binding(files[name], name)
        bindings[name] = files[name]
        required.add(files[name]["path"])
    alternatives = host["bindings"]["androidLoader"]
    D.need(type(alternatives) is dict and 0 < len(alternatives) <= 1024
           and alternatives.get("/etc/ld.so.preload", {}).get("absent") is True,
           "Android loader alternatives/preload absence are missing")
    for name, binding in alternatives.items():
        _point(deadline)
        _provider_boundary(binding, name)
    return {"policySha256": value["documents"]["providers.json"]["decodedSha256"],
            "bindings": bindings, "alternatives": alternatives, "osFiles": sorted(required)}


def _provider_graph(control, tool_files):
    """Finite per-launch GNU loader structure. No executable or symbol proof.

    RPATH follows the loader ancestor chain only without this requester's
    RUNPATH; RUNPATH is direct-only. Completed load state is copied, never
    leaked between roots, optional modules, or a rejected ncurses5 attempt.
    Paths without a leading slash are inside the concrete protected tool tree.
    A nested member may have no search tags: its temporary spelling is NOT a
    fabricated filesystem provider or a source of additional search paths.
    """
    _, readers = _provider_readers()
    tools, libraries = control["toolObjects"], control["osLibraries"]
    objects = {name: row["elf"] for name, row in tools.items()}
    objects.update({row["file"]["path"]: row["elf"] for row in libraries.values()})
    objects.update({name: row["elf"] for name, row in control["programs"].items()})
    nested = {}
    for row in control["nestedObjects"]:
        name = row["jar"]["path"] + "!" + row["member"]
        D.need(name not in objects and row["elf"]["rpath"] is None and row["elf"]["runpath"] is None,
               "Android nested native member has an unknown origin/search rule")
        objects[name] = row["elf"]
        nested[name] = row
    D.need(len(objects) <= 256 and set(tools) <= set(tool_files), "Android finite provider object roster differs")
    known_paths = set(tool_files) | {row["file"]["path"] for row in libraries.values()}
    edges, contexts, covered = [], [], set()

    def paths(requester, tag):
        if tag is None:
            return []
        D.need(type(tag) is str and 0 < len(tag) <= 4096 and "!" not in requester,
               "Android unknown native search origin")
        result = []
        for component in tag.split(":"):
            D.need(component == "$ORIGIN" or component.startswith("$ORIGIN/")
                   or component.startswith("/") and "$" not in component,
                   "Android relative/empty/unknown loader search token")
            path = posixpath.normpath(component.replace("$ORIGIN", posixpath.dirname(requester)))
            D.need("$" not in path and path not in ("", ".", "..") and not path.startswith("../")
                   and (path.startswith("/") if requester.startswith("/") else not path.startswith("/")),
                   "Android loader search escapes the admitted tool tree")
            result.append(path)
        return result

    def rpaths(requester):
        elf = objects[requester]
        return paths(requester, elf.get("rpath")) if elf.get("runpath") is None else []

    def walk(root, phase, entry, initial=None, inherited=(), expected_missing=None):
        D.need(entry in objects and len(contexts) < 256, "Android unknown/too many native load contexts")
        loaded = dict(initial or {})
        pending, visited, missing = [(entry, tuple(inherited))], set(), None
        context = {"root": root, "phase": phase, "entry": entry}
        start = len(edges)
        while pending and missing is None:
            requester, ancestors = pending.pop(0)
            key = (requester, ancestors)
            if key in visited:
                continue
            D.need(len(visited) < 256 and len(ancestors) <= 128, "Android loader context traversal bound")
            visited.add(key)
            covered.add(requester)
            elf = objects[requester]
            own = rpaths(requester)
            search = paths(requester, elf.get("runpath")) if elf.get("runpath") is not None else list(dict.fromkeys([*own, *ancestors]))
            children = tuple(dict.fromkeys([*own, *ancestors]))
            soname = elf["soname"]
            if soname is not None and "/" not in soname:
                D.need(soname not in loaded or loaded[soname] == requester,
                       "Android context has conflicting loaded SONAME providers")
                loaded[soname] = requester
            for name in elf["needed"]:
                D.need(type(name) is str and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_+.-]{0,191}", name)
                       and ".so" in name and len(edges) < 16384, "Android native dependency/edge bound")
                candidates = [directory + "/" + suffix + name for directory in search
                              for suffix in (*("glibc-hwcaps/" + tier + "/" for tier in readers["HWCAPS"]), "")]
                selected, via = loaded.get(name), "loaded"
                if selected is None:
                    present = [path for path in candidates if path in known_paths]
                    D.need(all(path in objects for path in present), "Android unparsed native search candidate")
                    D.need(len(set(present)) <= 1, "Android ambiguous private native providers")
                    if present:
                        selected, via = present[0], "private"
                    elif name in libraries:
                        selected, via = libraries[name]["file"]["path"], "global"
                    else:
                        D.need(name == expected_missing and name in control["expectedGlobalAbsences"],
                               "Android native dependency has no admitted provider")
                        via, missing = "expected-global-miss", name
                row = {**context, "requester": requester, "name": name, "inheritedRpath": list(ancestors),
                       "candidates": candidates if via != "loaded" else [], "via": via, "selected": selected}
                edges.append(row)
                if selected is None:
                    break
                D.need(selected in objects and set(elf["versionNeeds"].get(name, []))
                       <= set(objects[selected]["versionDefinitions"]), "Android required GNU version nodes are absent")
                if name not in loaded:
                    loaded[name] = selected
                    pending.append((selected, children))
        D.need(missing == expected_missing, "Android native fallback did not have its exact first-variant miss")
        contexts.append({**context, "edgeStart": start, "edgeCount": len(edges) - start, "expectedMissing": missing})
        return loaded

    java_base, java_inherited = None, ()
    for entry in control["launches"]:
        loaded = walk(entry, "startup", entry)
        if entry.startswith("jdk/bin/"):
            # The accepted GNU JLI path loads this exact server original with
            # RTLD_GLOBAL only AFTER the launcher dependency closure succeeds.
            jli = loaded.get("libjli.so")
            D.need(jli == "jdk/lib/libjli.so", "Android GNU launcher did not bind the fixed original JLI")
            inherited = tuple(dict.fromkeys([*rpaths(jli), *rpaths(entry)]))
            loaded = walk(entry, "post-jli-global", control["jvm"], loaded, inherited)
        if entry == control["java"]:
            java_base = loaded
            java_inherited = tuple(dict.fromkeys([*rpaths(control["jvm"]), *inherited]))
    D.need(java_base is not None and java_base.get("libjvm.so") == control["jvm"],
           "Android post-JLI global JVM phase is absent")
    for entry in control["postJliModules"]:
        walk(control["java"], "jdk-module", entry, java_base, java_inherited)
    # Each optional class-loader request starts with the actual successful JVM
    # baseline, not libraries accidentally loaded by another optional module.
    ordered = sorted(nested, key=lambda name: ("ncurses6" in name, name))
    for entry in ordered:
        walk(control["java"], "jni-ncurses6-fallback" if "ncurses6" in entry else "jni-module", entry,
             java_base, java_inherited, "libtinfo.so.5" if "ncurses5" in entry else None)
    for entry in sorted(control["programs"]):
        walk(entry, "os-helper", entry)
    D.need(set(objects) <= covered, "Android fixed native roster has an unvisited object")
    return {"classification": PROVIDER_CLASSIFICATION, "contexts": contexts, "edges": edges,
            "globalNames": sorted(libraries), "expectedGlobalAbsences": control["expectedGlobalAbsences"],
            "nativeSelectionProven": False, "symbolBindingProven": False}


def _provider_loader_proof(control, state, diagnostics, cache):
    _, readers = _provider_readers()
    profile = readers["loader_diagnostics"](diagnostics)
    names = sorted(set(control["osLibraries"]) | set(control["expectedGlobalAbsences"]))
    rows = readers["loader_cache"](cache, control["packages"]["libc-bin"]["version"], shell_names=names)
    bindings = state["alternatives"]
    tiers, expected = {}, {"/etc/ld.so.preload"}
    for directory in readers["DEFAULT_LIBRARY_DIRS"]:
        D.need(directory in bindings and "directory" in bindings[directory],
               "Android loader default directory original is missing")
        expected.add(directory)
        for tier in readers["HWCAPS"]:
            path = directory + "/glibc-hwcaps/" + tier
            D.need(path in bindings, "Android loader hwcaps directory original is missing")
            tiers[path] = bindings[path].get("absent") is not True
            D.need(not tiers[path] or "directory" in bindings[path], "Android loader hwcaps input is not a directory")
            expected.add(path)
    candidates = readers["shell_loader_candidates"](names, rows, tiers)
    found = set()
    for name, path in candidates:
        D.need(path in bindings, "Android cache names an unbound provider alternative")
        expected.add(path)
        binding = bindings[path]
        if name in control["expectedGlobalAbsences"]:
            D.need(binding.get("absent") is True, "Android global JNI ABI5 absence was replaced by another provider")
        else:
            provider = state["bindings"][control["osLibraries"][name]["file"]["selectedPath"]]
            readers["loader_selected"](binding, provider)
            if binding.get("absent") is not True:
                found.add(name)
    D.need(set(bindings) == expected and found == set(control["osLibraries"]),
           "Android complete loader alternatives omit or add an original")
    return {"diagnostics": profile, "cacheRows": [row for row in rows if row["soname"] in names],
            "candidates": [list(row) for row in candidates], "hwcapsTiers": tiers}


def _provider_material_graph(value, root, owner, inventory, deadline):
    """Check bound actual ELF/JAR DATA before recomputing the finite structure."""
    control = _provider_control(value)
    parse, _ = _provider_readers()
    originals = {row["path"]: row["identity"] for row in inventory["files"]}
    materials = {}
    def body(row):
        _point(deadline)
        name = _tool_path(row["path"])
        path = root / "tools" / name
        D.need(name in originals and _private(path, owner, mode=0o500 if row["mode"] & 0o111 else 0o400) == originals[name],
               "Android native material lost its original staging writer")
        raw = D.read(path, row["size"])
        D.need(len(raw) == row["size"] and _sha(raw) == row["sha256"]
               and _private(path, owner, mode=0o500 if row["mode"] & 0o111 else 0o400) == originals[name],
               "Android native material changed during bounded inspection")
        materials[name] = {"size": row["size"], "sha256": row["sha256"], "identity": originals[name]}
        _point(deadline)
        return raw
    for name, row in control["toolObjects"].items():
        D.need(row["file"]["path"] == name and parse(body(row["file"]), android_data=True) == row["elf"],
               "Android actual tool ELF differs from its pinned source DATA")
    for row in control["nestedObjects"]:
        with zipfile.ZipFile(io.BytesIO(body(row["jar"])), "r") as archive:
            infos = archive.infolist()
            D.need(0 < len(infos) <= 8192 and len({item.filename for item in infos}) == len(infos),
                   "Android fixed JNI archive has duplicate/excess members")
            matches = [item for item in infos if item.filename == row["member"]]
            D.need(len(matches) == 1, "Android selected JNI member is absent")
            item = matches[0]
            D.need(item.orig_filename == item.filename and not item.is_dir() and not item.flag_bits & 1
                   and not stat.S_ISLNK(item.external_attr >> 16) and item.file_size == row["size"]
                   and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                   "Android fixed JNI member metadata differs")
            raw = bytearray()
            with archive.open(item, "r") as stream:
                while block := stream.read(CHUNK):
                    _point(deadline)
                    D.need(len(raw) + len(block) <= row["size"] <= FILE_LIMIT, "Android JNI expansion bound")
                    raw.extend(block)
            D.need(len(raw) == row["size"] and _sha(raw) == row["sha256"]
                   and parse(bytes(raw), android_data=True) == row["elf"], "Android actual JNI source member differs")
    graph = _provider_graph(control, originals)
    graph["materialOriginalsSha256"] = _sha(D.canonical(materials))
    _point(deadline)
    return graph


def _provider_commands():
    return (("provider-diagnostics.stdout", "android-provider-diagnostics", ["/lib64/ld-linux-x86-64.so.2", "--list-diagnostics"]),
            ("provider-cache.stdout", "android-provider-cache", ["/usr/sbin/ldconfig.real", "-p"]))


def _provider_output_readback(root, owner, compiler_root, name, label, argv, proof, deadline):
    """Original fixed command settlement, before a succeeding DATA consumer."""
    _point(deadline)
    pin = _keys(proof["outputs"][name], {"path", "size", "sha256", "identity"}, "Android provider output reference differs")
    D.need(pin["path"] == name and type(pin["size"]) is int and 0 < pin["size"] <= PROVIDER_OUTPUTS[name]
           and _private(root / "private" / name, owner) == pin["identity"], "Android original provider output changed")
    raw = D.read(root / "private" / name, PROVIDER_OUTPUTS[name])
    D.need(len(raw) == pin["size"] and _sha(raw) == pin["sha256"]
           and _private(root / "private" / name, owner) == pin["identity"], "Android original provider output differs")
    original = _font_owner_records(compiler_root, label, owner, expected=proof["ownerRecords"][name])
    selected = {row["path"]: row for row in original["files"]}
    D.need(selected[label + ".stdout"]["size"] == pin["size"] and selected[label + ".stdout"]["sha256"] == pin["sha256"]
           and selected[label + ".stderr"]["size"] == 0, "Android original provider owner stdout/stderr differs")
    capture = compiler_root / "private-material"
    request = D.decode(D.read(capture / (label + ".request.json"), 64 << 10), 64 << 10)
    result = D.decode(D.read(capture / (label + ".result.json"), 128 << 10), 128 << 10)
    _keys(request, {"phase", "argv", "timeoutSeconds"}, "Android provider original request differs")
    D.need(request["phase"] == label and request["argv"] == argv and type(request["timeoutSeconds"]) is int
           and 1 <= request["timeoutSeconds"] <= 15, "Android provider request/endpoint differs")
    expected = {**request, "exitCode": 0, "ordinaryOwnerReturned": True,
        "captures": {suffix: {key: selected[label + "." + suffix][key] for key in ("size", "sha256")}
                     for suffix in ("stdout", "stderr")}}
    D.need(D.same(result, expected), "Android provider original owner did not settle successfully")
    _font_owner_records(compiler_root, label, owner, expected=original)
    _point(deadline)
    return raw


def _provider_capture_readback(value, host, root, owner, directories, compiler_root, proof, deadline):
    state = _provider_state(value, host, deadline)
    D.need(proof["classification"] == PROVIDER_CLASSIFICATION
           and proof["hostInputsSha256"] == _sha(D.canonical(state))
           and set(proof["outputs"]) == set(PROVIDER_OUTPUTS) and set(proof["ownerRecords"]) == set(PROVIDER_OUTPUTS),
           "Android provider proof lost its source/original inputs")
    outputs = {}
    for name, label, argv in _provider_commands():
        outputs[name] = _provider_output_readback(root, owner, compiler_root, name, label, argv, proof, deadline)
    loader = _provider_loader_proof(_provider_control(value), state,
        outputs["provider-diagnostics.stdout"], outputs["provider-cache.stdout"])
    D.need(D.same(proof["loader"], loader), "Android original loader consumer structure changed")
    _font_private_empty(root, owner, directories)
    D.need(_provider_state(value, host, deadline) == state, "Android provider originals changed during consumer readback")
    _point(deadline)
    return proof


def _provider_consumers(check, value, host, root, owner, directories):
    D.need(not check.failed, "Android prior preparation failure is latched")
    try:
        state = _provider_state(value, host, check.end)
        _font_private_empty(root, owner, directories)
        environment = {"PATH": "/usr/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
                       "HOME": str(root / "home"), "TMPDIR": str(root / "tmp")}
        proof = {"classification": PROVIDER_CLASSIFICATION, "hostInputsSha256": _sha(D.canonical(state)),
                 "outputs": {}, "ownerRecords": {}, "loader": {}}
        outputs = {}
        for name, label, argv in _provider_commands():
            _point(check.end)
            result = check.private_command(label, argv, environment, root, timeout=15, limit=PROVIDER_OUTPUTS[name])
            D.need(not check.failed and result.returncode == 0 and result.args == argv and result.stderr == b""
                   and type(result.stdout) is bytes and 0 < len(result.stdout) <= PROVIDER_OUTPUTS[name],
                   "Android provider consumer result/stderr differs")
            _point(check.end)
            _font_private_empty(root, owner, directories)
            D.need(_provider_state(value, host, check.end) == state, "Android loader originals changed during consumption")
            proof["outputs"][name] = _font_output(root, name, result.stdout, owner, directories, check.end)
            proof["ownerRecords"][name] = _font_owner_records(check.root, label, owner)
            D.need(proof["ownerRecords"][name]["directory"] == list(check.private_roots["material"]),
                   "Android provider capture directory differs from its original command owner")
            outputs[name] = _provider_output_readback(root, owner, check.root, name, label, argv, proof, check.end)
            if name == "provider-diagnostics.stdout":
                # Refuse a malformed first consumer before starting the second.
                _, readers = _provider_readers()
                readers["loader_diagnostics"](outputs[name])
        proof["loader"] = _provider_loader_proof(_provider_control(value), state,
            outputs["provider-diagnostics.stdout"], outputs["provider-cache.stdout"])
        return _provider_capture_readback(value, host, root, owner, directories, check.root, proof, check.end)
    except BaseException:
        check.failed = True
        raise


def _provider_readback(value, host, root, owner, directories, compiler_root, inventory, proof, deadline):
    _keys(proof, {"classification", "hostInputsSha256", "outputs", "ownerRecords", "loader", "graph"},
          "Android provider proof fields differ")
    _provider_capture_readback(value, host, root, owner, directories, compiler_root, proof, deadline)
    D.need(D.same(proof["graph"], _provider_material_graph(value, root, owner, inventory, deadline)),
           "Android original provider material/context graph changed")
    _point(deadline)
    return proof


def _font_cache_report(raw, roster):
    """Fixed fc-cat framing/membership, NOT generation or full-path proof.

    Upstream2.15.0 returns0 after some load errors and its fccat format strips
    full paths. The caller also requires empty stderr and the independent full
    configured path set from fc-list. No output path here is opened or followed.
    """
    D.need(type(raw) is bytes and 0 < len(raw) <= 512 << 10 and raw.endswith(b"\n")
           and type(roster) is dict and 0 < len(roster) <= 16, "Android font-cache output/roster bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise D.Refused("Android font-cache output is not UTF-8") from exc
    D.need(all(ord(c) >= 32 and not 127 <= ord(c) < 160 or c == "\n" for c in text),
           "Android font-cache output contains a control character")
    blocks, seen, faces = text[:-1].split("\n\n"), set(), 0
    D.need(len(blocks) == len(roster), "Android font-cache report is incomplete/duplicated")
    for block in blocks:
        lines = block.split("\n")
        D.need(4 <= len(lines) <= 1024 and all(0 < len(line.encode("utf-8")) <= 64 << 10 for line in lines)
               and lines[0].startswith("Directory: ") and lines[1].startswith("Cache: ") and lines[2] == "--------",
               "Android font-cache block framing differs")
        directory, cache = lines[0][11:], lines[1][7:]
        D.need(cache in roster and cache not in seen
               and re.fullmatch(r"/var/cache/fontconfig/[0-9a-f]{32}-le64\.cache-9", cache),
               "Android font-cache source is outside its exact roster")
        rule = _keys(roster[cache], {"directory", "subdirectories", "fonts"}, "Android font-cache rule fields differ")
        D.need(directory == rule["directory"] and str(_absolute(directory)) == directory
               and type(rule["subdirectories"]) is list and type(rule["fonts"]) is list
               and len(rule["subdirectories"]) <= 32 and len(rule["fonts"]) <= 512,
               "Android font-cache directory/extent differs")
        members = {}
        for kind, paths in (("directory", rule["subdirectories"]), ("font", rule["fonts"])):
            D.need(paths == sorted(set(paths)), "Android font-cache member roster collision/order differs")
            for path in paths:
                p = _absolute(path)
                D.need(str(p.parent) == directory and p.name not in members
                       and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+\-]*", p.name)
                       and (kind == "directory" or p.name.endswith(".ttf")),
                       "Android font-cache member is not a fixed direct child")
                members[p.name] = kind
        if not members:
            D.need(lines[3:] == ["<empty>"], "Android empty font-cache directory has unexpected members")
        else:
            found = set()
            for line in lines[3:]:
                match = re.fullmatch(r'"([A-Za-z0-9][A-Za-z0-9_.+\-]*)" (0) "((?:[^"\\\x00-\x1f]|\\["\\])*)"', line)
                D.need(match is not None and match[1] in members and match[1] not in found,
                       "Android font-cache face/member/framing differs")
                D.need((match[3] == ".dir") == (members[match[1]] == "directory") and bool(match[3]),
                       "Android font-cache member kind differs")
                found.add(match[1])
                faces += members[match[1]] == "font"
            D.need(found == set(members), "Android font-cache direct member inventory is incomplete")
        seen.add(cache)
    D.need(seen == set(roster), "Android complete font-cache inventory differs")
    return {"cacheFiles": len(seen), "fontFaces": faces}


def _font_list_report(raw, paths):
    """Exact configured font paths; not a substitute for per-cache parsing."""
    D.need(type(raw) is bytes and 0 < len(raw) <= 32 << 10 and raw.endswith(b"\n")
           and type(paths) is list and 0 < len(paths) <= 512 and paths == sorted(set(paths)),
           "Android configured font output/roster bound")
    try:
        selected = raw[:-1].decode("utf-8").split("\n")
    except UnicodeError as exc:
        raise D.Refused("Android configured font output is not UTF-8") from exc
    D.need(len(selected) == len(paths) and len(set(selected)) == len(selected)
           and set(selected) == set(paths), "Android configured font paths are missing/ambiguous/outside the admitted set")
    return {"fontFiles": len(selected)}


def _font_config_io(raw):
    """Only the pinned fontconfig I/O selectors, not a second font matcher."""
    D.need(type(raw) is bytes and 0 < len(raw) <= 64 << 10 and b"<!ENTITY" not in raw,
           "Android font configuration bound/entity differs")
    # ElementTree never loads a DTD. Still accept only the ordinary declarative
    # fontconfig identifier, not a caller-selected external/internal subset.
    clean = re.sub(rb'<!DOCTYPE fontconfig SYSTEM "(?:urn:fontconfig:fonts.dtd|fonts.dtd)">', b"", raw)
    D.need(b"<!DOCTYPE" not in clean, "Android font configuration DTD differs")
    root = ET.fromstring(clean)
    D.need(root.tag == "fontconfig" and not root.attrib, "Android font configuration root differs")
    result, direct = [], {id(node) for node in root}
    nodes = list(root.iter())
    D.need(len(nodes) <= 8192, "Android font configuration element bound")
    for node in nodes:
        D.need(type(node.tag) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", node.tag)
               and node.tag not in {"reset-dirs", "remap-dir"}, "Android font configuration namespace/remapping differs")
        if node.tag not in {"dir", "cachedir", "include"}:
            continue
        allowed = {"prefix", "ignore_missing", "deprecated"} if node.tag == "include" else {"prefix"}
        D.need(id(node) in direct and not len(node) and set(node.attrib) <= allowed
               and node.attrib.get("prefix", "") in {"", "xdg"}
               and all(node.attrib.get(key, "no") in {"yes", "no"} for key in ("ignore_missing", "deprecated"))
               and type(node.text) is str, "Android font configuration selector attributes differ")
        path = node.text.strip()
        D.need(0 < len(path) <= 512 and re.fullmatch(r"[A-Za-z0-9_./~+\-]+", path)
               and ".." not in path.split("/"), "Android font configuration selector differs")
        result.append({"kind": node.tag, "prefix": node.attrib.get("prefix", ""), "path": path,
                       "optional": node.attrib.get("ignore_missing", "no") == "yes"})
    return result


def _font_configuration(host, inputs, fonts, deadline):
    wanted = fonts["configurationFiles"]
    D.need(type(wanted) is list and 0 < len(wanted) <= 64 and wanted == sorted(set(wanted))
           and wanted[0] != "" and "/etc/fonts/fonts.conf" in wanted,
           "Android fixed font configuration file roster differs")
    pending, selected, system_dirs, cache_dirs = ["/etc/fonts/fonts.conf"], {}, set(), set()
    private_locations = {("dir", "xdg", "fonts"), ("dir", "", "~/.fonts"),
        ("cachedir", "xdg", "fontconfig"), ("cachedir", "", "~/.fontconfig"),
        ("include", "xdg", "fontconfig/conf.d"), ("include", "xdg", "fontconfig/fonts.conf"),
        ("include", "", "~/.fonts.conf.d"), ("include", "", "~/.fonts.conf")}
    while pending:
        _point(deadline)
        name = pending.pop()
        D.need(name in wanted and name not in selected and name in inputs["files"],
               "Android font configuration cycle/unadmitted include")
        binding = host["bindings"]["files"][name]
        pin = _protected_binding(binding, name)
        raw = D.read(Path(pin["path"]), 64 << 10)
        D.need(len(raw) == pin["size"] and _sha(raw) == pin["sha256"], "Android original font configuration changed")
        selectors = _font_config_io(raw)
        selected[name] = selectors
        for row in selectors:
            role = (row["kind"], row["prefix"], row["path"])
            if role in private_locations:
                D.need(row["kind"] != "include" or row["optional"], "Android private font include must be optional")
                continue  # Fresh private HOME/XDG paths are checked separately.
            D.need(row["prefix"] == "" and not row["path"].startswith("~"),
                   "Android font selector escapes the closed private/system paths")
            path = row["path"]
            if not path.startswith("/"):
                D.need(row["kind"] == "include" and path in {"conf.d", "local.conf"},
                       "Android relative font configuration include differs")
                path = "/etc/fonts/" + path
            _absolute(path)
            if row["kind"] == "dir":
                D.need(path in {"/usr/share/fonts", "/usr/local/share/fonts"},
                       "Android font directory is outside the complete roster")
                system_dirs.add(path)
            elif row["kind"] == "cachedir":
                D.need(path == "/var/cache/fontconfig", "Android font cache directory differs")
                cache_dirs.add(path)
            elif path == "/etc/fonts/conf.d":
                D.need(path in inputs["directories"], "Android font include directory is not bound")
                pending.extend(path + "/" + leaf for leaf in inputs["directories"][path]
                               if re.fullmatch(r"[0-9][A-Za-z0-9_.+\-]*\.conf", leaf))
            else:
                D.need(path == "/etc/fonts/local.conf" and row["optional"] and path in inputs["absences"],
                       "Android local font include is not a protected absence")
    D.need(set(selected) == set(wanted) and system_dirs == {"/usr/share/fonts", "/usr/local/share/fonts"}
           and cache_dirs == {"/var/cache/fontconfig"}, "Android font configuration closure is incomplete")
    return selected


def _font_state(value, host, deadline):
    """Finite source roster joined to this VM's originals; no ambient admission."""
    inputs = _input_rules(value)
    fonts = _keys(_control(value, "fonts.json"), {"schemaVersion", "classification", "supplierRoots", "configurationFiles", "fontFiles",
                  "files", "directories", "absences", "consumers", "providers"},
                  "Android fixed font policy shape differs")
    D.need(fonts["schemaVersion"] == 1 and fonts["classification"] == FONT_CLASSIFICATION
           and type(fonts["supplierRoots"]) is dict and set(fonts["supplierRoots"]) == set(FONT_ROOTS)
           and all(host["graph"]["runtimeData"]["suppliers"]["roots"][name] == expected
                   for name, expected in fonts["supplierRoots"].items()),
           "Android font supplier roots differ from the reviewed source")
    D.need(type(fonts["directories"]) is dict and len(fonts["directories"]) == 13
           and all(inputs["directories"].get(name) == children for name, children in fonts["directories"].items())
           and fonts["absences"] == ["/etc/fonts/local.conf"] and set(fonts["absences"]) <= set(inputs["absences"]),
           "Android font namespace differs from the reviewed source")
    paths = fonts["fontFiles"]
    D.need(type(paths) is list and len(paths) == 53 and paths == sorted(set(paths))
           and set(paths) <= set(inputs["files"]), "Android complete fixed font file roster differs")
    directories = host["bindings"]["androidDirectories"]
    absences = host["bindings"]["androidAbsences"]
    D.need(set(directories) == set(inputs["directories"]) and set(absences) == set(inputs["absences"]),
           "Android original host directory/absence roster differs")
    for name, children in inputs["directories"].items():
        _point(deadline)
        _protected_namespace(directories[name], name, children=children, deadline=deadline)
    for name, binding in absences.items():
        _point(deadline)
        _protected_namespace(binding, name)
    roster, file_state = {}, {}
    for name in FONT_DIRECTORIES:
        D.need(name in inputs["directories"], "Android font directory is not bound")
        subdirectories = sorted(child for child in FONT_DIRECTORIES if str(Path(child).parent) == name)
        files = [path for path in paths if str(Path(path).parent) == name]
        D.need(inputs["directories"][name] == sorted(Path(path).name for path in [*subdirectories, *files]),
               "Android font directory contains an unaccounted member")
        cache = "/var/cache/fontconfig/" + hashlib.md5(name.encode("ascii")).hexdigest() + "-le64.cache-9"
        D.need(cache in inputs["files"], "Android original font cache is not bound")
        roster[cache] = {"directory": name, "subdirectories": subdirectories, "fonts": files}
    D.need(set(paths) == {path for row in roster.values() for path in row["fonts"]},
           "Android font supplier path is outside the admitted directories")
    tag = "/var/cache/fontconfig/CACHEDIR.TAG"
    D.need(tag in inputs["files"] and inputs["directories"].get("/var/cache/fontconfig")
           == sorted(Path(name).name for name in [*roster, tag]), "Android font cache directory is not complete")
    expected_files = dict(fonts["files"])
    D.need(set(expected_files) == set(paths) | set(fonts["configurationFiles"])
           and set(fonts["consumers"]) == {"/usr/bin/fc-cat", "/usr/bin/fc-list"}
           and type(fonts["providers"]) is dict and 0 < len(fonts["providers"]) <= 32,
           "Android font consumer/file/provider source roster differs")
    for name, provider in fonts["providers"].items():
        D.need(host["graph"]["sharedObjects"].get(name) == provider,
               "Android font provider differs from the admitted original shell graph")
    for row in [*fonts["consumers"].values(), *fonts["providers"].values()]:
        file = row["file"]
        expected_files[file["selectedPath"]] = {k: file[k] for k in ("path", "size", "sha256", "mode")}
        D.need(all(name in fonts["providers"] for name in row["elf"]["needed"])
               and all(set(required) <= set(fonts["providers"][name]["elf"]["versionDefinitions"])
                       for name, required in row["elf"]["versionNeeds"].items()),
               "Android font consumer provider/version edge is incomplete")
    D.need(set(expected_files) <= set(inputs["files"]), "Android font supplier/tool/provider input is not bound")
    for name in sorted({*expected_files, *roster, tag}):
        _point(deadline)
        file_state[name] = _protected_binding(host["bindings"]["files"][name], name)
        if name in expected_files:
            D.need(file_state[name] == expected_files[name], "Android current font/configuration/tool/provider supplier bytes differ")
        else:
            D.need(file_state[name]["path"] == name, "Android canonical font cache input is an alias")
    D.need(sum(file_state[name]["size"] for name in paths) == 37255936,
           "Android fixed font supplier byte extent differs")
    marker = D.read(Path(tag), 4096)
    D.need(len(marker) == file_state[tag]["size"] and _sha(marker) == file_state[tag]["sha256"]
           and marker.startswith(b"Signature: 8a477f597d28d172789f06886806bc55\n")
           and all(not line or line.startswith(b"#") for line in marker.splitlines()[1:]),
           "Android font cache directory marker differs")
    configuration = _font_configuration(host, inputs, fonts, deadline)
    cache_rows = [{"path": ".", "kind": "directory", "present": True, "canonical": "/var/cache/fontconfig",
                   "mode": stat.S_IMODE(directories["/var/cache/fontconfig"]["directory"][2]), "children": []}]
    for name in sorted([*roster, tag]):
        row = file_state[name]
        cache_rows.append({"path": Path(name).name, "kind": "file", "present": True,
                           "canonical": name, **{k: row[k] for k in ("size", "sha256", "mode")}, "links": []})
    summary = {"kind": "directory", "present": True, "entryCount": len(cache_rows), "fileCount": len(roster) + 1,
               "byteCount": sum(row.get("size", 0) for row in cache_rows), "sha256": _sha(D.canonical(cache_rows))}
    D.need(summary == host["graph"]["runtimeData"]["caches"]["roots"]["/var/cache/fontconfig"],
           "Android font caches changed from the original shell DATA snapshot")
    return {"roster": roster, "paths": paths, "configuration": configuration,
            "files": {name: host["bindings"]["files"][name] for name in file_state},
            "directories": directories, "absences": absences}


def _font_commands(state):
    return (("font-cache.stdout", "android-font-cache", ["/usr/bin/fc-cat", "--verbose", *sorted(state["roster"])]),
            ("font-list.stdout", "android-font-list", ["/usr/bin/fc-list", "--format=%{file}\\n"]))


def _font_private_empty(root, owner, directories):
    D.need(_private(root, owner, directory=True, mode=0o700)[:5] == directories["."],
           "Android font preparation root changed")
    for name in ("home", "tmp"):
        path = root / name
        D.need(_private(path, owner, directory=True, mode=0o700)[:5] == directories[name]
               and not list(path.iterdir()), "Android font consumer created private configuration/cache output")


def _font_output(root, name, raw, owner, directories, deadline):
    """Fresh private copy bound to its original writer, including close errors."""
    outputs = {**FONT_OUTPUTS, **PROVIDER_OUTPUTS, "replay.curl": AUXILIARY["replay.curl"]}
    D.need(name in outputs and type(raw) is bytes and 0 < len(raw) <= outputs[name],
           "Android private consumer output bound/name differs")
    parent = _staging_parent(root, "private/" + name, directories, owner)
    fd = None
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        count = 0
        while count < len(raw):
            _point(deadline)
            written = os.write(fd, raw[count:count + CHUNK])
            D.need(written > 0, "Android private font output short write")
            count += written
        os.fchmod(fd, 0o400)
        os.fsync(fd)
        original = _identity(os.fstat(fd))
        D.need(original == _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
               and original == _private(root / "private" / name, owner),
               "Android private font writer/name changed")
    finally:
        try:
            if fd is not None:
                os.close(fd)
        finally:
            os.close(parent)
    checked_parent = _staging_parent(root, "private/" + name, directories, owner)
    os.close(checked_parent)
    pin = {"path": name, "size": len(raw), "sha256": _sha(raw)}
    D.bound(root / "private" / name, pin)
    D.need(_private(root / "private" / name, owner) == original, "Android private font output changed after close")
    return {**pin, "identity": original}


def _font_owner_records(compiler_root, label, owner, *, expected=None):
    """Existing private_command originals, not a new execution receipt API."""
    root = compiler_root / "private-material"
    identity = _private(root, owner, directory=True, mode=0o700)[:5]
    records = []
    for suffix, bound in (("request.json", 64 << 10), ("result.json", 128 << 10),
                          ("stdout", 512 << 10), ("stderr", 512 << 10)):
        path = root / (label + "." + suffix)
        original = _private(path, owner, mode=0o600)
        pin = D.file_record(path, bound)
        D.need(_private(path, owner, mode=0o600) == original, "Android original font owner capture changed")
        records.append({**pin, "identity": original})
    D.need(_private(root, owner, directory=True, mode=0o700)[:5] == identity,
           "Android original private command directory changed")
    record = {"directory": identity, "files": records}
    D.need(expected is None or D.same(record, expected), "Android original font owner records differ")
    return record


def _font_readback(value, host, root, owner, directories, compiler_root, proof, deadline):
    _keys(proof, {"classification", "generationProvenance", "hostInputsSha256", "outputs", "ownerRecords", "counts"},
          "Android font consumer proof fields differ")
    state = _font_state(value, host, deadline)
    D.need(proof["classification"] == FONT_CLASSIFICATION and proof["generationProvenance"] is False
           and proof["hostInputsSha256"] == _sha(D.canonical(state))
           and type(proof["outputs"]) is dict and set(proof["outputs"]) == set(FONT_OUTPUTS)
           and type(proof["ownerRecords"]) is dict and set(proof["ownerRecords"]) == set(FONT_OUTPUTS),
           "Android font proof classification/original inputs differ")
    counts = {}
    for name, label, argv in _font_commands(state):
        _point(deadline)
        pin = _keys(proof["outputs"][name], {"path", "size", "sha256", "identity"}, "Android font output reference differs")
        D.need(pin["path"] == name and type(pin["size"]) is int and 0 < pin["size"] <= FONT_OUTPUTS[name]
               and _private(root / "private" / name, owner) == pin["identity"], "Android font output original differs")
        D.bound(root / "private" / name, {k: pin[k] for k in ("path", "size", "sha256")})
        raw = D.read(root / "private" / name, FONT_OUTPUTS[name])
        D.need(len(raw) == pin["size"] and _sha(raw) == pin["sha256"]
               and _private(root / "private" / name, owner) == pin["identity"],
               "Android font output changed during parser readback")
        original = _font_owner_records(compiler_root, label, owner, expected=proof["ownerRecords"][name])
        selected = {row["path"]: row for row in original["files"]}
        D.need(selected[label + ".stdout"]["size"] == pin["size"]
               and selected[label + ".stdout"]["sha256"] == pin["sha256"]
               and selected[label + ".stderr"]["size"] == 0, "Android original font stdout/stderr differs")
        capture = compiler_root / "private-material"
        request = D.decode(D.read(capture / (label + ".request.json"), 64 << 10), 64 << 10)
        result = D.decode(D.read(capture / (label + ".result.json"), 128 << 10), 128 << 10)
        _keys(request, {"phase", "argv", "timeoutSeconds"}, "Android font owner request differs")
        D.need(request["phase"] == label and request["argv"] == argv and type(request["timeoutSeconds"]) is int
               and 1 <= request["timeoutSeconds"] <= 15, "Android font owner original argv/deadline differs")
        expected_result = {**request, "exitCode": 0, "ordinaryOwnerReturned": True,
            "captures": {suffix: {key: selected[label + "." + suffix][key] for key in ("size", "sha256")}
                         for suffix in ("stdout", "stderr")}}
        D.need(D.same(result, expected_result), "Android font owner did not close successfully on its original request")
        _font_owner_records(compiler_root, label, owner, expected=original)
        counts.update(_font_cache_report(raw, state["roster"]) if name == "font-cache.stdout"
                      else _font_list_report(raw, state["paths"]))
    D.need(D.same(proof["counts"], counts) and counts == {"cacheFiles": 7, "fontFaces": 53, "fontFiles": 53},
           "Android font consumer complete correspondence differs")
    _font_private_empty(root, owner, directories)
    D.need(_font_state(value, host, deadline) == state, "Android font inputs changed during parser readback")
    _point(deadline)
    return proof


def _font_consumers(check, value, host, root, owner, directories):
    """Two fixed documented consumers under the caller's original owner/end."""
    D.need(not check.failed, "Android prior preparation failure is latched")
    try:
        state = _font_state(value, host, check.end)
        original_host = _host_state(value, host, check.end)
        _font_private_empty(root, owner, directories)
        environment = {"PATH": "/usr/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
                       "HOME": str(root / "home"), "TMPDIR": str(root / "tmp"), "XDG_RUNTIME_DIR": str(root / "tmp"),
                       **{"XDG_" + role.upper() + "_HOME": str(root / "home" / ("xdg-" + role))
                          for role in ("config", "cache", "data", "state")}}
        proof = {"classification": FONT_CLASSIFICATION, "generationProvenance": False,
                 "hostInputsSha256": _sha(D.canonical(state)), "outputs": {}, "ownerRecords": {}, "counts": {}}
        for name, label, argv in _font_commands(state):
            _point(check.end)
            result = check.private_command(label, argv, environment, root, timeout=15, limit=FONT_OUTPUTS[name])
            D.need(not check.failed and result.returncode == 0 and result.args == argv and result.stderr == b""
                   and type(result.stdout) is bytes and 0 < len(result.stdout) <= FONT_OUTPUTS[name],
                   "Android font consumer result/stderr differs")
            _point(check.end)
            _font_private_empty(root, owner, directories)
            D.need(_font_state(value, host, check.end) == state
                   and _host_state(value, host, check.end) == original_host,
                   "Android original font consumer/provider/configuration inputs changed")
            proof["outputs"][name] = _font_output(root, name, result.stdout, owner, directories, check.end)
            proof["ownerRecords"][name] = _font_owner_records(check.root, label, owner)
            D.need(proof["ownerRecords"][name]["directory"] == list(check.private_roots["material"]),
                   "Android font capture directory differs from its original command owner")
            proof["counts"].update(_font_cache_report(result.stdout, state["roster"]) if name == "font-cache.stdout"
                                  else _font_list_report(result.stdout, state["paths"]))
        return _font_readback(value, host, root, owner, directories, check.root, proof, check.end)
    except BaseException:
        check.failed = True
        raise


def sdk_license_value(value):
    """Exact repository31.9.2 TrimStringAdapter rule; not a hash search."""
    D.need(type(value) is str and len(value.encode("utf-8")) <= 32 << 10, "Android SDK licence text bound")
    value = re.sub(r"(?<=\s)[ \t]*", "", value, flags=re.ASCII)
    value = re.sub(r"(?<!\n)\n(?!\n)", " ", value)
    value = re.sub(r" +", " ", value)
    return value.strip("".join(chr(n) for n in range(33)))


def existing_license(raw, text):
    normalized = sdk_license_value(text).encode("utf-8")
    D.need(len(normalized) == 16960 and _sha(normalized) == LICENSE_NORMALIZED_SHA256
           and hashlib.sha1(normalized).hexdigest() == LICENSE_HASH, "Android pinned SDK licence definition differs")
    D.need(type(raw) is bytes and 0 < len(raw) <= 4096 and re.fullmatch(rb"\n?(?:[0-9a-f]{40}\n)*[0-9a-f]{40}\n?", raw),
           "Android existing SDK licence receipt shape differs")
    lines = raw.decode("ascii").strip("\n").split("\n")
    D.need(len(lines) == len(set(lines)) and LICENSE_HASH in lines,
           "Android existing hosted receipt does not contain the selected SDK licence")
    return raw  # Preserve the existing bytes. Never synthesize an acceptance marker.


def sdk_packages(xml, source_properties):
    D.need(len(xml) == 420815 and _sha(xml) == "a4e2d5ea8b44470352fb48124fe3df2a1b0dfd323bbe9e570491301bf44f118d"
           and b"<!DOCTYPE" not in xml and b"<!ENTITY" not in xml, "Android pinned official SDK XML differs")
    root = ET.fromstring(xml)
    D.need(root.tag == "{" + SDK_NAMESPACE + "}sdk-repository", "Android SDK XML root differs")
    licenses = [r for r in root if r.tag == "license" and r.get("id") == "android-sdk-license"]
    D.need(len(licenses) == 1 and licenses[0].text is not None, "Android selected SDK licence is missing/ambiguous")
    result = {}
    for name, wanted in (("platforms;android-35", {"Pkg.Revision": "2", "AndroidVersion.ApiLevel": "35",
            "AndroidVersion.ExtensionLevel": "13", "AndroidVersion.IsBaseSdk": "true", "Layoutlib.Api": "15"}),
            ("build-tools;35.0.0", {"Pkg.Revision": "35.0.0"})):
        props = {}
        raw = source_properties[name]
        D.need(type(raw) is bytes and len(raw) <= 16384, "Android source.properties bound")
        for line in raw.decode("ascii").splitlines():
            if not line or line.startswith("#"):
                continue
            key, sep, val = line.partition("=")
            D.need(sep == "=" and key not in props, "Android source.properties field differs")
            props[key] = val
        D.need(all(props.get(k) == v for k, v in wanted.items()), "Android official package/source.properties disagree")
        packages = [r for r in root if r.tag == "remotePackage" and r.get("path") == name]
        D.need(len(packages) == 1, "Android fixed SDK package missing/ambiguous")
        package = packages[0]
        D.need(package.find("uses-license").get("ref") == "android-sdk-license", "Android package licence changed")
        revision = package.find("revision")
        D.need([r.text for r in revision] == (["2"] if name.startswith("platforms;") else ["35", "0", "0"]),
               "Android selected SDK revision changed")
        document = ET.Element("{" + COMMON_NAMESPACE + "}repository",
                              {"xmlns:sdk": SDK_NAMESPACE, "xmlns:generic": GENERIC_NAMESPACE})
        document.append(deepcopy(licenses[0]))
        local = ET.SubElement(document, "localPackage", {"path": name, "obsolete": "false"})
        for child in package:
            if child.tag in {"type-details", "revision", "display-name", "uses-license", "dependencies"}:
                local.append(deepcopy(child))
        content = ET.tostring(document, encoding="utf-8", xml_declaration=True) + b"\n"
        D.need(len(content) <= 32 << 10, "Android deterministic SDK package XML bound")
        result["sdk/" + name.replace(";", "/") + "/package.xml"] = content
    return result, licenses[0].text


def _curl(root, url, size):
    return ["/usr/bin/curl", "-q", "--silent", "--no-show-error", "--fail", "--globoff", "--disallow-username-in-url",
            "--proto", "=https", "--proto-redir", "=https", "--no-location", "--max-redirs", "0", "--retry", "0",
            "--proxy", "", "--noproxy", "*", "--no-netrc", "--no-netrc-optional", "--no-insecure", "--tlsv1.2",
            "--no-compressed", "--no-remove-on-error", "--connect-timeout", "10", "--max-time", "180",
            "--cacert", "/etc/ssl/certs/ca-certificates.crt", "--capath", str(root / "empty-capath"),
            "--max-filesize", str(size), "--request", "GET", "--header", "Accept-Encoding: identity",
            "--write-out", HTTP_SUFFIX, "--url", url]


def _stock_environment(root):
    # The exact object is forwarded by Check to its existing owner. These are
    # caller fields, not an invented independent kernel environment observation.
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
            "HOME": str(root / "home"), "TMPDIR": str(root / "tmp")}


def _stock_capath(root, owner, directories, deadline):
    D.need(_private(root, owner, directory=True, mode=0o700)[:5] == directories["."],
           "Android stock private root changed")
    path = root / "empty-capath"
    original = _private(path, owner, directory=True, mode=0o700)
    D.need(original[:5] == directories["empty-capath"], "Android original empty capath changed")
    _empty_directory(path, deadline)
    D.need(_private(path, owner, directory=True, mode=0o700) == original,
           "Android empty capath changed during observation")
    return original


def _stock_partition(suppliers):
    direct, assets = [], []
    for row in suppliers:
        parsed = urlsplit(row["url"])
        D.need(parsed.scheme == "https" and not parsed.username and not parsed.password and not parsed.fragment
               and not parsed.query and parsed.port is None and "\\" not in row["url"], "Android fixed source URL differs")
        (assets if row["githubAsset"] else direct).append(row)
    D.need(direct and [row["id"] for row in assets] == ["body-142", "body-143"]
           and all(urlsplit(row["url"]).netloc == "github.com" for row in assets),
           "Android fixed five-consumer supplier roles differ")
    return direct, assets


def _stock_replay_config(root, direct):
    # Every transfer keeps its own explicit bounds. One original curl owns the
    # bounded four-way batch; no Python thread pool or background workers.
    common = ["fail", "silent", "no-show-error", "globoff", "disallow-username-in-url", 'proto = "=https"',
        'proto-redir = "=https"', "no-location", 'max-redirs = "0"', 'retry = "0"', 'proxy = ""', 'noproxy = "*"',
        "no-netrc", "no-netrc-optional", "no-insecure", "tlsv1.2", "no-compressed", "no-remove-on-error",
        'connect-timeout = "10"', 'max-time = "180"', 'cacert = "/etc/ssl/certs/ca-certificates.crt"',
        'capath = "' + str(root / "empty-capath") + '"', 'header = "Accept-Encoding: identity"']
    blocks = []
    for index, row in enumerate(direct):
        blocks.append(("next\n" if index else "") + "\n".join(common)
            + '\nmax-filesize = "' + str(row["size"]) + '"\nurl = "' + row["url"]
            + '"\noutput = "' + str(root / "bodies" / row["id"]) + '"\nwrite-out = "' + HTTP_RECEIPT + '"\n')
    config = "\n".join(blocks).encode("ascii")
    D.need(len(config) <= 512 << 10, "Android exact replay configuration bound")
    return config


def _stock_replay_argv(root):
    return ["/usr/bin/curl", "-q", "--parallel", "--parallel-immediate", "--parallel-max", "4",
            "--config", str(root / "private/replay.curl")]


def _stock_replay_receipt(stdout, stderr, direct):
    D.need(stderr == b"" and stdout.endswith(b"\n"), "Android fixed replay receipt missing")
    seen = set()
    for line in stdout.decode("ascii").splitlines():
        parts = line.split("\t")
        D.need(len(parts) == 6 and parts[0].isdigit(), "Android replay receipt shape differs")
        index = int(parts[0])
        D.need(0 <= index < len(direct) and index not in seen
               and parts == [str(index), "0", "200", str(direct[index]["size"]), "0", "0"],
               "Android replay HTTP/TLS/original result differs")
        seen.add(index)
    D.need(len(seen) == len(direct), "Android replay receipt inventory incomplete")


def _stock_redirect_receipt(stdout, stderr):
    header, separator, status = stdout.rpartition(b"\nMRK_HTTP=")
    D.need(stderr == b"" and separator and re.fullmatch(rb"302\t0\t[0-9]{1,4}\t0\t0\n", status)
           and header.endswith(b"\r\n\r\n") and header.count(b"\r\n\r\n") == 1,
           "Android fixed asset initial HTTP/TLS response differs")
    size = int(status.split(b"\t")[2])
    lines = header[:-4].split(b"\r\n")
    D.need(len(lines) <= 128 and re.fullmatch(rb"HTTP/(?:1\.[01]|2|3) 302(?: [\x20-\x7e]*)?", lines[0]),
           "Android fixed asset header status differs")
    headers = {}
    for line in lines[1:]:
        D.need(len(line) <= 8192 and b":" in line, "Android fixed asset header bound")
        key, val = line.split(b":", 1)
        D.need(re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key), "Android fixed asset header name differs")
        key = key.lower()
        if key in (b"location", b"content-length", b"content-encoding"):
            D.need(key not in headers, "Android fixed asset header collision")
            headers[key] = val.strip(b" \t")
    D.need(headers.get(b"content-encoding", b"identity").lower() == b"identity", "Android fixed asset encoding differs")
    if b"content-length" in headers:
        D.need(re.fullmatch(rb"[0-9]{1,4}", headers[b"content-length"])
               and int(headers[b"content-length"]) == size, "Android fixed asset header extent differs")
    location = headers.get(b"location", b"").decode("ascii")
    D.need(0 < len(location) <= 8192 and "\\" not in location and all(33 <= ord(c) <= 126 for c in location),
           "Android fixed asset location differs")
    parsed = urlsplit(location)
    D.need(parsed.scheme == "https" and parsed.netloc == "release-assets.githubusercontent.com"
           and re.fullmatch(r"/github-production-release-asset/[0-9]{1,20}/[0-9a-fA-F-]{36}", parsed.path)
           and parsed.query and not parsed.fragment, "Android fixed asset redirected outside its one supplier")
    return location, size


def _stock_body_receipt(stdout, stderr, size):
    D.need(stderr == b"" and stdout == ("\nMRK_HTTP=200\t0\t" + str(size) + "\t0\t0\n").encode(),
           "Android fixed asset body response differs")


def _stock_owner_records(compiler_root, label, owner, argv, timeout, limit, deadline, *, expected=None):
    """Read the existing owner's actual private records, not a replacement owner."""
    capture = compiler_root / "private-material"
    identity = _private(capture, owner, directory=True, mode=0o700)[:5]
    bodies, files = {}, []
    for suffix, bound in (("request.json", 64 << 10), ("result.json", 128 << 10), ("stdout", limit), ("stderr", limit)):
        with _stock_private_original(capture / (label + "." + suffix), owner, bound, deadline, mode=0o600) as (raw, pin):
            bodies[suffix] = raw
            files.append(pin)
    request = _keys(D.decode(bodies["request.json"], 64 << 10), {"phase", "argv", "timeoutSeconds"},
                    "Android stock original request differs")
    record = {"directory": identity, "files": files, "request": request}
    D.need(_private(capture, owner, directory=True, mode=0o700)[:5] == identity
           and (expected is None or D.same(record, expected)), "Android stock original owner records changed")
    D.need(request["phase"] == label and D.same(request["argv"], argv) and type(request["timeoutSeconds"]) is int
           and 1 <= request["timeoutSeconds"] <= timeout and len(bodies["stdout"]) + len(bodies["stderr"]) <= limit,
           "Android stock original command/bounds differ")
    result = D.decode(bodies["result.json"], 128 << 10)
    wanted = {**request, "exitCode": 0, "ordinaryOwnerReturned": True,
              "captures": {suffix: {"size": len(bodies[suffix]), "sha256": _sha(bodies[suffix])}
                           for suffix in ("stdout", "stderr")}}
    D.need(D.same(result, wanted), "Android stock owner did not close on its original successful request")
    _point(deadline)
    return record, bodies["stdout"], bodies["stderr"]


def _stock_consumer(check, root, owner, directories, host, stock, label, argv, timeout, limit, receipt, *, capath, replay=None):
    D.need(not check.failed, "Android prior preparation failure is latched")
    environment = _stock_environment(root)
    expected_environment = dict(environment)
    D.need(_stock_capath(root, owner, directories, check.end) == capath,
           "Android original empty capath changed before the next consumer")
    with ExitStack() as originals:
        raw, pem = originals.enter_context(_stock_host_original(host["bindings"]["files"][STOCK_PEM],
                                                               STOCK_PEM, 4 << 20, check.end))
        D.need(D.same(pem, {k: stock["pem"][k] for k in ("binding", "file", "identity")}),
               "Android curl original PEM differs from its checked stock input")
        replay_pin = None
        if replay is not None:
            body, replay_pin = originals.enter_context(_stock_private_original(root / "private/replay.curl",
                owner, AUXILIARY["replay.curl"], check.end, expected=replay[1]))
            D.need(body == replay[0], "Android curl original replay configuration differs")
        _point(check.end)
        result = check.private_command(label, argv, environment, root, timeout=timeout, limit=limit)
        D.need(D.same(environment, expected_environment), "Android curl fixed environment was changed")
        records, stdout, stderr = _stock_owner_records(check.root, label, owner, argv, timeout, limit, check.end)
        D.need(check.original_commands and D.same(check.original_commands[-1],
                    {**records["request"], "exitCode": 0, "ordinaryOwnerReturned": True})
               and D.same(check.private_metadata["material"][-2:],
                    [{key: pin[key] for key in ("path", "size", "sha256")} for pin in records["files"][:2]])
               and list(check.private_roots["material"]) == records["directory"],
               "Android stock records differ from the original Check return/writer pins")
        D.need(result.args == argv and type(result.returncode) is int and result.returncode == 0
               and result.stdout == stdout and result.stderr == stderr,
               "Android stock captured owner result differs from its actual return")
        parsed = receipt(stdout, stderr)
        D.need(_stock_capath(root, owner, directories, check.end) == capath,
               "Android curl empty capath original changed")
    # Both the original PEM and config must positively close before a successor.
    proof = {"label": label, "environment": expected_environment, "cwd": str(root), "pem": pem,
             "emptyCapath": capath, "replay": replay_pin, "ownerRecords": records}
    D.need(len(D.canonical(proof)) <= 64 << 10, "Android stock consumer private proof bound")
    _point(check.end)
    return parsed, proof


def _download(check, root, suppliers, owner, *, directories, host, stock):
    D.need(not check.failed, "Android prior preparation failure is latched")
    try:
        return _download_owned(check, root, suppliers, owner, directories=directories, host=host, stock=stock)
    except BaseException:
        check.failed = True
        raise


def _download_owned(check, root, suppliers, owner, *, directories, host, stock):
    _point(check.end)
    direct, assets = _stock_partition(suppliers)
    initial, consumers = {}, []
    capath = _stock_capath(root, owner, directories, check.end)
    for row in suppliers:
        path = root / "bodies" / row["id"]
        D.write(path, b"", 0o600)
        initial[row["id"]] = _private(path, owner, mode=0o600)[:6]
    config = _stock_replay_config(root, direct)
    config_pin = _font_output(root, "replay.curl", config, owner, directories, check.end)
    _, proof = _stock_consumer(check, root, owner, directories, host, stock, "android-fixed-material-replay",
        _stock_replay_argv(root), 600, 128 << 10, lambda out, err: _stock_replay_receipt(out, err, direct),
        capath=capath, replay=(config, config_pin))
    consumers.append(proof)
    for row in assets:
        _point(check.end)
        prefix = row["id"]
        redirect_body = root / "private" / (prefix + ".redirect")
        D.write(redirect_body, b"", 0o600)
        redirect_identity = _private(redirect_body, owner, mode=0o600)[:6]
        (location, size), proof = _stock_consumer(check, root, owner, directories, host, stock,
            "android-asset-location-" + prefix,
            _curl(root, row["url"], 4096) + ["--output", str(redirect_body), "--dump-header", "-"],
            195, 32 << 10, _stock_redirect_receipt, capath=capath)
        D.need(_private(redirect_body, owner, mode=0o600)[:6] == redirect_identity
               and redirect_body.lstat().st_size == size, "Android fixed asset response destination changed")
        os.chmod(redirect_body, 0o400, follow_symlinks=False)
        consumers.append(proof)
        _, proof = _stock_consumer(check, root, owner, directories, host, stock,
            "android-asset-body-" + prefix,
            _curl(root, location, row["size"]) + ["--output", str(root / "bodies" / prefix)],
            195, 32 << 10, lambda out, err: _stock_body_receipt(out, err, row["size"]), capath=capath)
        consumers.append(proof)
    observations = []
    for row in suppliers:
        _point(check.end)
        path = root / "bodies" / row["id"]
        D.need(_private(path, owner, mode=0o600)[:6] == initial[row["id"]], "Android replay destination was replaced")
        D.bound(path, {"path": row["id"], "size": row["size"], "sha256": row["sha256"]})
        stream, before = D._open(path, row["size"])
        digest = hashlib.sha1()
        with stream:
            while block := stream.read(CHUNK):
                _point(check.end)
                digest.update(block)
            D.need(D.state(os.fstat(stream.fileno())) == D.state(before) == D.state(path.lstat()),
                   "Android published-checksum input changed")
        D.need((row["publishedSha256"] is None or row["sha256"] == row["publishedSha256"])
               and (row["publishedSha1"] is None or digest.hexdigest() == row["publishedSha1"])
               and (row["sha1"] is None or digest.hexdigest() == row["sha1"]), "Android published checksum differs")
        os.chmod(path, 0o400)
        observations.append({"id": row["id"], "size": row["size"], "sha256": row["sha256"],
                             "identity": _private(path, owner)})
    D.need(_stock_capath(root, owner, directories, check.end) == capath, "Android TLS fallback directory changed")
    D.need(len(consumers) == 5 and len(D.canonical(consumers)) <= 5 * (64 << 10),
           "Android complete private curl consumer proof bound")
    return observations, consumers


def _stock_readback(value, host, root, owner, directories, compiler_root, suppliers, stock, consumers, deadline):
    """Command-free current originals and exact five consumed owner records."""
    D.need(D.same(_stock_trust_state(value, host, deadline), stock), "Android stock original trust proof differs")
    D.need(type(consumers) is list and len(consumers) == 5
           and len(D.canonical(consumers)) <= 5 * (64 << 10), "Android original curl proof roster/bound differs")
    direct, assets = _stock_partition(suppliers)
    capath = _stock_capath(root, owner, directories, deadline)
    pem = {key: stock["pem"][key] for key in ("binding", "file", "identity")}
    with _stock_private_original(root / "private/replay.curl", owner, AUXILIARY["replay.curl"], deadline) as (raw, replay):
        D.need(raw == _stock_replay_config(root, direct), "Android original curl replay body differs")
        def read(index, label, argv, timeout, limit, receipt):
            row = _keys(consumers[index], {"label", "environment", "cwd", "pem", "emptyCapath", "replay", "ownerRecords"},
                        "Android original curl proof shape differs")
            D.need(row["label"] == label and row["cwd"] == str(root)
                   and D.same(row["environment"], _stock_environment(root)) and D.same(row["pem"], pem)
                   and D.same(row["emptyCapath"], capath) and D.same(row["replay"], replay if index == 0 else None),
                   "Android original curl environment/cwd/TLS/config binding differs")
            _, out, err = _stock_owner_records(compiler_root, label, owner, argv, timeout, limit, deadline,
                                              expected=row["ownerRecords"])
            return receipt(out, err)
        read(0, "android-fixed-material-replay", _stock_replay_argv(root), 600, 128 << 10,
             lambda out, err: _stock_replay_receipt(out, err, direct))
        for offset, row in enumerate(assets):
            prefix = row["id"]
            redirect = root / "private" / (prefix + ".redirect")
            location, size = read(1 + 2 * offset, "android-asset-location-" + prefix,
                _curl(root, row["url"], 4096) + ["--output", str(redirect), "--dump-header", "-"],
                195, 32 << 10, _stock_redirect_receipt)
            with _stock_private_original(redirect, owner, 4096, deadline) as (body, _):
                D.need(len(body) == size, "Android original curl redirect output extent differs")
            read(2 + 2 * offset, "android-asset-body-" + prefix,
                _curl(root, location, row["size"]) + ["--output", str(root / "bodies" / prefix)],
                195, 32 << 10, lambda out, err: _stock_body_receipt(out, err, row["size"]))
    D.need(_stock_capath(root, owner, directories, deadline) == capath
           and D.same(_stock_trust_state(value, host, deadline), stock),
           "Android original trust inputs changed during curl readback")
    _point(deadline)
    return consumers


def _parents(paths):
    result = {str(p) for name in paths for p in Path(name).parents if str(p) != "."}
    D.need(len(set(paths) | result | {"android-toolchain.json"}) <= 32768
           and len({p.lower() for p in set(paths) | result}) == len(set(paths) | result)
           and not set(paths) & result, "Android fixed material case/ancestor/count collision")
    return sorted(result, key=lambda p: (p.count("/"), p))


def _staging_parent(root, name, directories, owner):
    """Open only the recorded, freshly created parent; never a replacement."""
    D.relative(name)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(root, flags)
    relative = "."
    try:
        for part in [None, *name.split("/")[:-1]]:
            if part is not None:
                child = os.open(part, flags, dir_fd=fd)
                previous, fd = fd, child
                os.close(previous)
                relative = part if relative == "." else relative + "/" + part
            D.need(relative in directories and _identity(os.fstat(fd))[:5] == directories[relative]
                   and _private(root / relative, owner, directory=True, mode=0o700)[:5] == directories[relative]
                   and not os.listxattr(fd), "Android fresh staging directory was replaced")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _staging_mkdir(root, name, directories, owner):
    parent = _staging_parent(root, name, directories, owner)
    try:
        leaf = name.split("/")[-1]
        os.mkdir(leaf, mode=0o700, dir_fd=parent)
        fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            original = _identity(os.fstat(fd))[:5]
            D.need(name not in directories and original == _private(root / name, owner, directory=True, mode=0o700)[:5]
                   and not os.listxattr(fd), "Android fresh staging directory creation differs")
            # Child creation changes directory link counts/times. Its original
            # dev/inode/mode/owner do not change and are retained from creation.
            directories[name] = original
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _member_output(stream, root, rows, expected, deadline, *, directories, originals, owner):
    writers, count, digest = [], 0, hashlib.sha256()
    try:
        for row in rows:
            D.need(row["sourceMode"] == expected["mode"], "Android selected member mode projection differs")
            name = "tools/" + _tool_path(row["path"])
            D.need(row["path"] not in originals, "Android staged leaf already has an original writer")
            parent = _staging_parent(root, name, directories, owner)
            try:
                fd = os.open(name.split("/")[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
            except BaseException:
                os.close(parent)
                raise
            try:
                output = os.fdopen(fd, "wb")
            except BaseException:
                try:
                    os.close(fd)
                finally:
                    os.close(parent)
                raise
            writer = {"output": output, "parent": parent, "name": name, "row": row}
            writers.append(writer)
            mode = 0o500 if row["mode"] & 0o111 else 0o400
            os.fchmod(output.fileno(), mode)
            writer["created"] = _identity(os.fstat(output.fileno()))[:6]
            D.need(writer["created"][2:] == [stat.S_IFREG | mode, *owner, 1]
                   and not os.listxattr(output.fileno()), "Android original material writer differs")
        while block := stream.read(CHUNK):
            _point(deadline)
            count += len(block)
            D.need(count <= expected["size"], "Android decoded member grew")
            digest.update(block)
            for writer in writers:
                D.need(writer["output"].write(block) == len(block), "Android material short write")
        D.need(count == expected["size"] and digest.hexdigest() == expected["sha256"], "Android decoded member differs")
        for writer in writers:
            output = writer["output"]
            output.flush()
            os.fsync(output.fileno())
            writer["final"] = _identity(os.fstat(output.fileno()))
            D.need(writer["final"][:6] == writer["created"] and writer["final"][6] == count
                   and _identity(os.stat(writer["name"].split("/")[-1], dir_fd=writer["parent"], follow_symlinks=False)) == writer["final"]
                   and not os.listxattr(output.fileno()), "Android original material writer/name changed")
    finally:
        errors = []
        for writer in writers:
            try:
                writer["output"].close()
            except OSError:
                errors.append(True)
            try:
                os.close(writer["parent"])
            except OSError:
                errors.append(True)
        D.need(not errors, "Android original material close failed")
    for writer in writers:
        row, name = writer["row"], writer["name"]
        D.need(row["size"] == count and row["sha256"] == digest.hexdigest(), "Android material route differs")
        parent = _staging_parent(root, name, directories, owner)
        try:
            D.need(_identity(os.stat(name.split("/")[-1], dir_fd=parent, follow_symlinks=False)) == writer["final"],
                   "Android original material changed after writer close")
            D.bound(root / name, {k: row[k] for k in ("path", "size", "sha256")})
            D.need(_private(root / name, owner, mode=stat.S_IMODE(writer["final"][2])) == writer["final"],
                   "Android original material changed after readback")
            originals[row["path"]] = writer["final"]
        finally:
            os.close(parent)


def _archive(check, root, index, routes, owner, directories, originals):
    path = root / "bodies" / index["id"]
    source_identity = _private(path, owner)
    members = {r["path"]: r for r in index["members"]}
    D.need(len(members) == len(index["members"]), "Android archive control has duplicate members")
    seen, decoded = set(), None
    if index["format"] == "dpkg-fsys-tar":
        decoded = root / "decoded" / (index["id"] + ".tar")
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
                       "HOME": str(root / "home"), "TMPDIR": str(root / "tmp")}
        result = check.private_command("android-decode-" + index["id"], ["/usr/bin/bash", "--noprofile", "--norc",
            "-c", DECODER_SCRIPT, "mrk-fixed-android-decoder", str(math.ceil(index["decodedBytes"] / 1024)),
            str(decoded), "/usr/bin/dpkg-deb", "--fsys-tarfile", str(path)],
            environment, root, timeout=120, limit=64 << 10)
        D.need(result.stdout == result.stderr == b"", "Android original DATA decoder failed")
        _private(decoded, owner, mode=0o600)
        os.chmod(decoded, 0o400, follow_symlinks=False)
        original_decoded = _private(decoded, owner)
        D.bound(decoded, {"path": decoded.name, "size": index["decodedBytes"], "sha256": index["decodedSha256"]})
        source, original = D._open(decoded, index["decodedBytes"])
        count = 0
        with source, tarfile.open(fileobj=source, mode="r:") as archive:
            for item in archive:
                _point(check.end)
                count += 1
                D.need(count <= index["logicalMembers"] and not item.sparse and item.offset_data + item.size <= index["decodedBytes"]
                       and set(item.pax_headers) <= {"path", "linkpath", "mtime", "atime", "ctime"}, "Android tar extent/headers differ")
                if item.name in (".", "./"):
                    D.need(count == 1 and item.isdir() and item.size == 0 and item.mode == 0o755
                           and item.uid == item.gid == 0, "Android tar root differs")
                    continue
                name = item.name.removeprefix("./").rstrip("/")
                D.need(name in members and name not in seen, "Android tar member outside accepted inventory")
                expected = members[name]
                kind = ("regular" if item.isreg() else "directory" if item.isdir() else "symlink" if item.issym()
                        else "hardlink" if item.islnk() else "special")
                D.need((kind, item.size, item.mode, item.uid, item.gid) ==
                       (expected["type"], expected["size"], expected["mode"], expected["uid"], expected["gid"])
                       and (item.linkname or None) == expected["target"], "Android tar member metadata differs")
                if kind == "regular":
                    with archive.extractfile(item) as body:
                        _member_output(body, root, routes.get(name, []), expected, check.end,
                                       directories=directories, originals=originals, owner=owner)
                else:
                    D.need(name not in routes, "Android material route cannot materialize an archive alias")
                seen.add(name)
            D.need(count == index["logicalMembers"] and D.state(os.fstat(source.fileno())) == D.state(original),
                   "Android tar inventory/input changed")
        D.need(_private(decoded, owner) == original_decoded, "Android decoded original changed after staging")
    else:
        D.need(index["format"] == "zip", "Android archive format differs")
        source, original = D._open(path, FILE_LIMIT)
        with source, zipfile.ZipFile(source, "r") as archive:
            infos = archive.infolist()
            D.need(len(infos) == index["logicalMembers"] <= 20000, "Android ZIP member count differs")
            for info in infos:
                _point(check.end)
                name = info.filename.rstrip("/")
                D.need(info.orig_filename == info.filename and "\x00" not in name and "\\" not in name
                       and name in members and name not in seen and not info.flag_bits & 1,
                       "Android ZIP member outside accepted inventory")
                expected = members[name]
                mode = (info.external_attr >> 16) & 0xffff
                kind = "directory" if info.is_dir() else "symlink" if stat.S_ISLNK(mode) else "regular"
                observed = {"path": name, "type": kind, "size": info.file_size, "mode": mode & 0o7777,
                    "externalAttr": info.external_attr, "creatorSystem": info.create_system, "compression": info.compress_type,
                    "flags": info.flag_bits, "compressedBytes": info.compress_size, "crc32": info.CRC, "headerOffset": info.header_offset}
                D.need(all(observed[k] == expected[k] for k in observed)
                       and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "Android ZIP member metadata differs")
                if kind == "regular":
                    with archive.open(info, "r") as body:
                        _member_output(body, root, routes.get(name, []), expected, check.end,
                                       directories=directories, originals=originals, owner=owner)
                elif kind == "symlink":
                    with archive.open(info, "r") as body:
                        raw = body.read(4097)
                    D.need(len(raw) <= 4096 and _sha(raw) == expected["sha256"] and raw.decode("ascii") == expected["target"]
                           and name not in routes, "Android ZIP alias differs")
                else:
                    D.need(name not in routes and info.file_size == 0, "Android ZIP directory route differs")
                seen.add(name)
            D.need(D.state(os.fstat(source.fileno())) == D.state(original), "Android ZIP original changed")
    D.need(seen == set(members) and _private(path, owner) == source_identity, "Android complete archive input/inventory differs")
    if decoded is not None:
        # Only this task's fully consumed, original closed decoded copy.
        decoded.unlink()


def _tree(root, files, owner, deadline, *, directories, originals):
    expected = {row["path"]: row for row in files}
    expected_directories = set(_parents(expected))
    D.need(len(expected) == len(files) <= 16384 and set(originals) == set(expected)
           and {name for name in directories if name == "tools" or name.startswith("tools/")}
               == {"tools"} | {"tools/" + name for name in expected_directories},
           "Android material file/creation inventory differs")
    pending, seen, records, original_directories = [(root / "tools", "")], set(), [], []
    while pending:
        directory, relative = pending.pop()
        _point(deadline)
        before = _private(directory, owner, directory=True, mode=0o700)[:5]
        D.need(before == directories["tools" + ("/" + relative if relative else "")],
               "Android original created staging directory changed")
        original_directories.append({"path": relative or ".", "identity": before})
        children = sorted(directory.iterdir())
        for path in children:
            name = (relative + "/" if relative else "") + path.name
            D.need(name not in seen and len(seen) < 32768, "Android material namespace collision/entry bound")
            seen.add(name)
            if name in expected_directories:
                _private(path, owner, directory=True, mode=0o700)
                pending.append((path, name))
            else:
                D.need(name in expected, "Android material namespace contains an unaccounted file")
                row = expected[name]
                identity = _private(path, owner, mode=0o500 if row["mode"] & 0o111 else 0o400)
                D.need(identity == originals[name], "Android original created material leaf changed")
                D.bound(path, {k: row[k] for k in ("path", "size", "sha256")})
                D.need(_identity(path.lstat()) == identity, "Android staged original changed after hash")
                records.append({"path": name, "identity": identity})
        D.need(_private(directory, owner, directory=True, mode=0o700)[:5] == before,
               "Android staged directory changed during inventory")
    D.need(seen == set(expected) | expected_directories, "Android staged complete inventory differs")
    return {"files": sorted(records, key=lambda row: row["path"]),
            "directories": sorted(original_directories, key=lambda row: row["path"])}


def _auxiliary(root, owner, deadline):
    records = []
    for name, limit in sorted(AUXILIARY.items()):
        _point(deadline)
        path = root / "private" / name
        original = _private(path, owner)
        record = D.file_record(path, limit)
        D.need(_private(path, owner) == original, "Android original auxiliary DATA changed")
        records.append({**record, "identity": original})
    return records


def _closed_namespace(root, owner, deadline):
    """The finite preparation namespace after every consumer has settled."""
    directories = {"private", "bodies", "decoded", "home", "tmp", "empty-capath", "tools"}
    private = {key + ".json": limit for key, limit in PRIVATE_DOCS.items()}
    private.update({**AUXILIARY, "prepared.json": 64 << 10})
    expected = {root: directories | {name for name, _ in DOCS.values()}, root / "private": set(private)}
    expected.update({root / name: set() for name in directories - {"private", "tools"}})
    originals = {}
    for path, names in expected.items():
        _point(deadline)
        original = _private(path, owner, directory=True, mode=0o700)[:5]
        originals[str(path.relative_to(root))] = original
        D.need({child.name for child in path.iterdir()} == names,
               "Android preparation contains an unaccounted auxiliary output")
        D.need(_private(path, owner, directory=True, mode=0o700)[:5] == original,
               "Android original auxiliary directory changed")
    for name, limit in private.items():
        original = _private(root / "private" / name, owner)
        D.need(original[6] <= limit, "Android private output extent differs")
    return originals


def _space(parent, files, indexes):
    import resource  # Linux-only preparation; DATA imports stay platform-neutral.
    # No credit for future deletion: originals + native copy + root publication,
    # all transfers + the largest decoder + existing compiler/native scratch.
    tools = sum(row["size"] for row in files) + (4 << 20)
    required = 678706726 + 3 * tools + max(row["decodedBytes"] for row in indexes) + (8 << 30) + (64 << 20)
    space = os.statvfs(parent)
    D.need(space.f_bavail * space.f_frsize >= required and space.f_favail >= 65536,
           "Android overlapping material/compiler/native disk reservation unavailable")
    memory = Path("/proc/meminfo").read_text(encoding="ascii")
    available = re.search(r"^MemAvailable:\s+([0-9]+) kB$", memory, re.M)
    D.need(available is not None and int(available[1]) * 1024 >= 1536 << 20,
           "Android material preparation RAM headroom unavailable")
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    D.need(soft == resource.RLIM_INFINITY or soft >= 65536,
           "Android original descriptor admission floor unavailable")
    return {"materialAndScratchReservation": required, "availableBytes": space.f_bavail * space.f_frsize,
            "availableInodes": space.f_favail, "compilerNativeScratchReservation": 8 << 30, "deletionCredit": 0}


def _prospective_files(value, files, generated):
    """Complete generated union from original sizes, before creation/acquisition."""
    extra = {name: {"path": name, "mode": 0o444, **pin} for name, pin in value["generatedPackages"].items()}
    for role, name, bound in (("javaTrustStore", GENERATED[0], 1 << 20), ("sdkLicense", GENERATED[2], 4096)):
        pin = generated[role]
        D.need(type(pin["size"]) is int and 0 < pin["size"] <= bound,
               "Android original generated input extent differs")
        extra[name] = {"path": name, "mode": 0o444, "size": pin["size"], "sha256": pin["sha256"]}
    D.need(set(extra) == set(GENERATED) and not {row["path"] for row in files} & set(extra),
           "Android complete prospective generated roster differs")
    return [*files, *[extra[name] for name in GENERATED]]


def _archive_routes(files, suppliers, indexes):
    """One original archive owner also writes the fixed nested aapt2 leaf."""
    by_path = {row["path"]: row for row in files}
    bodies = {row["id"]: row for row in suppliers}
    archives = {row["id"]: row for row in indexes}
    members = {index["id"]: {row["path"]: row for row in index["members"]} for index in indexes}
    D.need(len(by_path) == len(files) and len(bodies) == len(suppliers) and len(archives) == len(indexes)
           and all(len(members[index["id"]]) == len(index["members"]) for index in indexes),
           "Android source route inventory contains duplicate originals")
    routes = {}
    for row in files:
        source = row["source"]
        D.need(source["id"] in bodies, "Android source body is outside its original inventory")
        if source["kind"] == "body":
            D.need(all(row[key] == bodies[source["id"]][key] for key in ("size", "sha256")),
                   "Android opaque material source body differs")
            continue
        D.need(source["kind"] in ("archive", "nested-archive") and source["id"] in archives,
               "Android source route differs")
        if source["kind"] == "nested-archive":
            _keys(source, {"kind", "id", "jar", "member"}, "Android nested source route fields differ")
            jar = by_path.get(source["jar"], {})
            D.need(row["path"] == "gradle/native/aapt2/aapt2" and source["id"] == "body-010"
                   and source["jar"] == "gradle/repository/com/android/tools/build/aapt2/8.9.2-12782657/aapt2-8.9.2-12782657-linux.jar"
                   and source["member"] == "aapt2" and row["mode"] == 0o555 and row["sourceMode"] == 0o755
                   and jar.get("source") == {"kind": "body", "id": source["id"]}
                   and all(jar.get(key) == bodies[source["id"]][key] for key in ("size", "sha256"))
                   and archives[source["id"]]["format"] == "zip",
                   "Android fixed aapt2 nested JAR/body correspondence differs")
        member = members[source["id"]].get(source["member"])
        D.need(member is not None and member["type"] == "regular"
               and all(row[key] == member[key] for key in ("size", "sha256"))
               and row["sourceMode"] == member["mode"], "Android original member route differs")
        routes.setdefault(source["id"], {}).setdefault(source["member"], []).append(row)
    return routes


def _documents(value, context, files, os_contract):
    files = [{k: row[k] for k in ("path", "size", "sha256", "mode")} for row in files]
    files.sort(key=lambda row: row["path"])
    paths = [_tool_path(row["path"]) for row in files]
    parents = _parents(paths)
    D.need(0 < len(files) <= 16384 and len(set(paths)) == len(files)
           and 0 < len(os_contract["files"]) <= 256 and len(os_contract["aliases"]) <= 128,
           "Android complete tool+OS count bound")
    os_directories = {str(parent) for row in os_contract["files"] for parent in _absolute(row["path"]).parents}
    # Fixed publication root has five original ancestors including itself.
    # One manifest, all tool/OS objects and directories, one serial iterator;
    # the shared / and /opt ancestors need no second descriptor.
    shared = {"/", "/opt", "/opt/mobile-release-kit", "/opt/mobile-release-kit/android"}
    D.need(5 + 1 + len(parents) + len(files) + len(os_contract["files"])
           + len(os_directories - shared) + 1 <= 32768, "Android complete descriptor roster bound")
    total = sum(row["size"] for row in files) + sum(row["size"] for row in os_contract["files"])
    D.need(0 < total <= TOTAL_LIMIT and all(type(row["size"]) is int and 0 <= row["size"] <= FILE_LIMIT
                                           for row in [*files, *os_contract["files"]]),
           "Android complete tool+OS byte bound")
    contract = D.canonical(os_contract)
    instance = "ci-" + context["runId"] + "-" + context["runAttempt"] + "-" + context["sourceCommit"][:12]
    manifest = {"schemaVersion": 1, "profile": value["profile"], "target": value["target"], "instance": instance,
        "launchContract": "gradle-posix-private-jvm-v1", "versions": value["versions"],
        "gradleDistribution": value["gradleDistribution"], "bundletool": value["bundletool"], "roles": value["roles"],
        "files": files, "osProfile": {"id": os_contract["id"], "inventorySha256": _sha(contract),
            "shell": "/usr/bin/dash", "executableDirectory": "/usr/bin", "helpers": value["helpers"], "files": os_contract["files"]}}
    sources = {"schemaVersion": 1, "files": [{"path": row["path"], "source": row["path"]} for row in files]}
    raw = {"manifest": D.canonical(manifest), "osContract": contract, "sources": D.canonical(sources)}
    D.need(all(0 < len(raw[key]) <= limit for key, (_, limit) in DOCS.items()), "Android publication document bound")
    publication = {"documents": {key: {"size": len(body), "sha256": _sha(body)} for key, body in raw.items()},
        "totals": {"toolFiles": len(files), "toolDirectories": len(parents),
                   "toolBytes": sum(row["size"] for row in files), "osFiles": len(os_contract["files"]),
                   "osAliases": len(os_contract["aliases"]), "osBytes": sum(row["size"] for row in os_contract["files"])}}
    materials = {"instance": instance, "manifestSha256": _sha(raw["manifest"]), "osContractSha256": _sha(contract),
                 "distributionSha256": value["gradleDistribution"]["sha256"]}
    return raw, materials, publication


def prepare(check, source: Path, material_root: Path, *, context: dict, host: dict):
    """Fresh exact-source preparation; call only after the lead admits execution.

    A pure copy/parse/readback failure latches the same original owner just as a
    command failure does. No failed partial preparation can launch a successor.
    """
    D.need(not check.failed, "Android prior preparation failure is latched")
    try:
        return _prepare(check, source, material_root, context=context, host=host)
    except BaseException:
        check.failed = True
        raise


def _prepare(check, source: Path, material_root: Path, *, context: dict, host: dict):
    _point(check.end)
    value, original = policy(), _context(context)
    owner = (original["runnerUid"], original["runnerGid"])
    D.need((os.getuid(), os.getgid()) == owner and source == _absolute(original["source"])
           and material_root == _absolute(str(material_root)) and material_root.parent == Path(original["root"]).parent
           and material_root.name == "mrk-android-material-" + context["runId"] + "-" + context["runAttempt"],
           "Android material root/source/preparer differs")
    D.need(check.end == float(original["deadline"]), "Android original compiler endpoint differs")
    os_contract, generated = _host_state(value, host, check.end)  # Refuse BEFORE any creation/download.
    stock = _stock_trust_state(value, host, check.end)
    D.need(check.root == _absolute(original["root"]), "Android font commands require the original compiler owner")
    suppliers = _control(value, "suppliers.json")["files"]
    layout = _control(value, "layout.json.gz")
    indexes = _control(value, "archives.json.gz")["archives"]
    files = layout["files"]
    D.need(len(suppliers) == 401 and sum(row["size"] for row in suppliers) == value["supplierBytes"]
           and [row["path"] for row in layout["generated"]] == list(GENERATED), "Android fixed roster differs")
    archive_routes = _archive_routes(files, suppliers, indexes)
    prospective = _prospective_files(value, files, generated)
    planned = _documents(value, context, prospective, os_contract)
    capacity = _space(material_root.parent, prospective, indexes)
    material_root.mkdir(mode=0o700)
    root = material_root
    root_identity = _private(root, owner, directory=True, mode=0o700)[:5]
    directories, originals = {".": root_identity}, {}
    for name in ("private", "bodies", "decoded", "home", "tmp", "empty-capath", "tools"):
        _staging_mkdir(root, name, directories, owner)
    namespace = {name: directories[name]
                 for name in (".", "private", "bodies", "decoded", "home", "tmp", "empty-capath")}
    private = {"context": context, "host": host}
    references = {}
    for key, body in private.items():
        raw = D.canonical(body)
        D.need(len(raw) <= PRIVATE_DOCS[key], "Android original private input bound")
        references[key] = D.write(root / "private" / (key + ".json"), raw, 0o400)
    font_consumers = _font_consumers(check, value, host, root, owner, directories)
    provider_consumers = _provider_consumers(check, value, host, root, owner, directories)
    observations, curl_consumers = _download(check, root, suppliers, owner,
        directories=directories, host=host, stock=stock)
    auxiliary = _auxiliary(root, owner, check.end)
    paths = [_tool_path(row["path"]) for row in files] + list(GENERATED)
    for name in _parents(paths):
        _staging_mkdir(root, "tools/" + name, directories, owner)
    for row in files:
        if row["source"]["kind"] == "body":
            source_path = root / "bodies" / row["source"]["id"]
            stream, before = D._open(source_path, row["size"])
            with stream:
                _member_output(stream, root, [{**row, "sourceMode": 0o400}], {**row, "mode": 0o400}, check.end,
                               directories=directories, originals=originals, owner=owner)
                D.need(D.state(os.fstat(stream.fileno())) == D.state(before) == D.state(source_path.lstat()),
                       "Android original opaque material source changed")
    for index in indexes:
        _archive(check, root, index, archive_routes.get(index["id"], {}), owner, directories, originals)
    xml = D.read(root / "bodies/sdk-repository", 420815)
    packages, licence = sdk_packages(xml, {name: D.read(root / "tools/sdk" / name.replace(";", "/") / "source.properties", 16384)
                                          for name in ("platforms;android-35", "build-tools;35.0.0")})
    D.need({name: {"size": len(body), "sha256": _sha(body)} for name, body in packages.items()} == value["generatedPackages"],
           "Android deterministic package metadata source commitment differs")
    receipt = generated["sdkLicense"]
    packages[GENERATED[0]] = _stock_jks_bytes(host, stock, check.end)
    packages[GENERATED[2]] = existing_license(D.read(Path(receipt["path"]), 4096), licence)
    for name, raw in sorted(packages.items()):
        row = {"path": name, "size": len(raw), "sha256": _sha(raw), "mode": 0o444}
        _member_output(io.BytesIO(raw), root, [{**row, "sourceMode": 0o444}], row, check.end,
                       directories=directories, originals=originals, owner=owner)
        files.append(row)
    raw, materials, publication = _documents(value, context, files, os_contract)
    D.need((raw, materials, publication) == planned, "Android complete prospective/staged union differs")
    for key, body in raw.items():
        D.write(root / DOCS[key][0], body, 0o400)
    inventory = _tree(root, files, owner, check.end, directories=directories, originals=originals)
    provider_consumers["graph"] = _provider_material_graph(value, root, owner, inventory, check.end)
    D.need(_host_state(value, host, check.end) == (os_contract, generated), "Android host inputs changed during preparation")
    _stock_readback(value, host, root, owner, directories, check.root, suppliers, stock, curl_consumers, check.end)
    provenance = {"policySha256": POLICY_SHA256, "contextSha256": _sha(D.canonical(context)),
        "hostSha256": _sha(D.canonical(host)), "rootIdentity": root_identity, "suppliers": observations,
        "generated": generated, "fontConsumers": font_consumers, "providerConsumers": provider_consumers,
        "stockTrust": stock, "curlConsumers": curl_consumers,
        "tools": inventory, "auxiliary": auxiliary, "namespace": namespace,
        "capacity": capacity, "newConsent": False,
        "compilerOrNativeExecuted": False, "qualification": False}
    body = D.canonical(provenance)
    D.need(len(body) <= PRIVATE_DOCS["provenance"], "Android private provenance bound")
    references["provenance"] = D.write(root / "private/provenance.json", body, 0o400)
    record = {"schemaVersion": 1, "scope": SCOPE, "materials": materials, "publication": publication,
              "materialRoot": str(root), "provenance": {"policySha256": POLICY_SHA256, "documents": references}}
    D.need(len(D.canonical(record)) <= 64 << 10, "Android compact preparation record bound")
    # Remove only fully consumed original bodies after all their owners returned
    # and their staged counterparts/host inputs were checked. No failure-path
    # deletion credit or deletion of an unknown-finality producer's output.
    for row in observations:
        path = root / "bodies" / row["id"]
        D.need(_private(path, owner) == row["identity"], "Android consumed supplier changed before cleanup")
        path.unlink()
    D.write(root / "private/prepared.json", D.canonical(record), 0o400)
    D.need(_closed_namespace(root, owner, check.end) == namespace, "Android original private namespace changed")
    _point(check.end)
    return record


def validate(record, *, context: dict, host: dict, deadline: float):
    """Command-free original/custody check; the caller supplies its existing end."""
    _point(deadline)
    _keys(record, {"schemaVersion", "scope", "materials", "publication", "materialRoot", "provenance"},
          "Android compact preparation record differs")
    D.need(record["schemaVersion"] == 1 and record["scope"] == SCOPE, "Android preparation scope differs")
    value, original = policy(), _context(context)
    root, owner = _absolute(record["materialRoot"]), (original["runnerUid"], original["runnerGid"])
    D.need(root.parent == Path(original["root"]).parent
           and root.name == "mrk-android-material-" + context["runId"] + "-" + context["runAttempt"],
           "Android original same-job material namespace differs")
    _keys(record["provenance"], {"policySha256", "documents"}, "Android compact provenance differs")
    D.need(record["provenance"]["policySha256"] == POLICY_SHA256, "Android preparation policy commitment differs")
    references = _keys(record["provenance"]["documents"], PRIVATE_DOCS, "Android private document roster differs")
    private = {}
    for key, pin in references.items():
        _keys(pin, {"path", "size", "sha256"}, "Android private original reference differs")
        D.need(pin["path"] == key + ".json" and type(pin["size"]) is int and 0 < pin["size"] <= PRIVATE_DOCS[key],
               "Android private original path/extent differs")
        path = root / "private" / pin["path"]
        _private(path, owner)
        D.bound(path, pin)
        private[key] = D.decode(D.read(path, pin["size"]), PRIVATE_DOCS[key])
    D.need(D.same(private["context"], context) and D.same(private["host"], host), "Android original source/attempt/host input changed")
    provenance = private["provenance"]
    _keys(provenance, {"policySha256", "contextSha256", "hostSha256", "rootIdentity", "suppliers", "generated", "fontConsumers", "providerConsumers", "stockTrust", "curlConsumers", "tools", "auxiliary", "namespace",
                      "capacity", "newConsent", "compilerOrNativeExecuted", "qualification"}, "Android original provenance shape differs")
    D.need(provenance["rootIdentity"] == _private(root, owner, directory=True, mode=0o700)[:5]
           and provenance["policySha256"] == POLICY_SHA256 and provenance["contextSha256"] == _sha(D.canonical(context))
           and provenance["hostSha256"] == _sha(D.canonical(host)) and provenance["newConsent"] is False
           and provenance["compilerOrNativeExecuted"] is False and provenance["qualification"] is False,
           "Android original material provenance changed")
    os_contract, generated = _host_state(value, host, deadline)
    D.need(provenance["generated"] == generated, "Android original generated material changed")
    _font_readback(value, host, root, owner, provenance["namespace"], _absolute(original["root"]),
                   provenance["fontConsumers"], deadline)
    suppliers = _control(value, "suppliers.json")["files"]
    _stock_readback(value, host, root, owner, provenance["namespace"], _absolute(original["root"]),
                    suppliers, provenance["stockTrust"], provenance["curlConsumers"], deadline)
    D.need(type(provenance["suppliers"]) is list and len(provenance["suppliers"]) == len(suppliers),
           "Android original supplier observation roster differs")
    for expected, observation in zip(suppliers, provenance["suppliers"]):
        _keys(observation, {"id", "size", "sha256", "identity"}, "Android original supplier observation differs")
        D.need(all(observation[k] == expected[k] for k in ("id", "size", "sha256"))
               and type(observation["identity"]) is list and len(observation["identity"]) == 9
               and observation["identity"][2:7] == [stat.S_IFREG | 0o400, *owner, 1, expected["size"]],
               "Android original supplier extent/owner commitment differs")
    files = _control(value, "layout.json.gz")["files"]
    manifest_raw = D.read(root / DOCS["manifest"][0], DOCS["manifest"][1])
    manifest = D.decode(manifest_raw, DOCS["manifest"][1])
    actual = {r["path"]: r for r in manifest["files"]}
    for row in files:
        D.need(actual.get(row["path"]) == {k: row[k] for k in ("path", "size", "sha256", "mode")},
               "Android unchanged supplier layout differs")
    D.need(set(actual) == {r["path"] for r in files} | set(GENERATED), "Android complete generated/unchanged roster differs")
    D.need(len(actual) == len(manifest["files"]) and all(actual[name]["mode"] == 0o444 for name in GENERATED),
           "Android generated material mode/uniqueness differs")
    for name, pin in value["generatedPackages"].items():
        D.need(actual[name] == {"path": name, "mode": 0o444, **pin}, "Android generated XML differs from pinned deterministic derivation")
    files.extend(actual[name] for name in GENERATED)
    raw, materials, publication = _documents(value, context, files, os_contract)
    D.need(D.same(record["materials"], materials) and D.same(record["publication"], publication),
           "Android preparation selectors/publication changed")
    for key, body in raw.items():
        path = root / DOCS[key][0]
        _private(path, owner)
        D.need(D.read(path, DOCS[key][1]) == body, "Android original publication document changed")
    tools = _keys(provenance["tools"], {"directories", "files"}, "Android original tool custody roster differs")
    D.need(type(tools["directories"]) is list and type(tools["files"]) is list
           and len(tools["directories"]) <= 32768 and len(tools["files"]) <= 16384,
           "Android original tool custody roster bound")
    directories, originals = {}, {}
    for kind, rows in tools.items():
        for row in rows:
            _keys(row, {"path", "identity"}, "Android original tool identity row differs")
            target = directories if kind == "directories" else originals
            name = "tools" + ("/" + row["path"] if row["path"] != "." else "") if kind == "directories" else row["path"]
            D.need(type(row["identity"]) is list and len(row["identity"]) == (5 if kind == "directories" else 9)
                   and all(type(v) is int for v in row["identity"]) and name not in target,
                   "Android original tool identity shape/collision differs")
            target[name] = row["identity"]
    D.need(_tree(root, files, owner, deadline, directories=directories, originals=originals) == tools,
           "Android prepared complete original tool tree changed")
    _provider_readback(value, host, root, owner, provenance["namespace"], _absolute(original["root"]),
                       tools, provenance["providerConsumers"], deadline)
    D.need(_auxiliary(root, owner, deadline) == provenance["auxiliary"], "Android original auxiliary inventory changed")
    D.need(_closed_namespace(root, owner, deadline) == provenance["namespace"], "Android original private namespace changed")
    jks = _stock_jks_bytes(host, provenance["stockTrust"], deadline)
    _stock_staged_jks(root, owner, actual[GENERATED[0]], originals[GENERATED[0]], jks, deadline)
    D.need(D.read(root / "tools" / GENERATED[2], 4096) == D.read(Path(generated["sdkLicense"]["path"]), 4096),
           "Android generated receipt input differs")
    _point(deadline)
    return record


def read_record(path: Path, expected: dict, *, context: dict, host: dict, deadline: float):
    _keys(expected, {"size", "sha256"}, "Android preparation record pin differs")
    D.need(type(expected["size"]) is int and 0 < expected["size"] <= 64 << 10, "Android preparation record bound")
    D.bound(path, {"path": path.name, **expected})
    record = D.decode(D.read(path, expected["size"]), 64 << 10)
    D.need(path == _absolute(record["materialRoot"]) / "private/prepared.json", "Android original record path differs")
    return validate(record, context=context, host=host, deadline=deadline)


def public_summary(record):
    """Separate safe projection, never a replacement for private original proof."""
    materials = _keys(record["materials"], {"instance", "manifestSha256", "osContractSha256", "distributionSha256"},
                      "Android public material projection fields differ")
    D.need(type(materials["instance"]) is str and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", materials["instance"]),
           "Android public material instance differs")
    for name in ("manifestSha256", "osContractSha256", "distributionSha256"):
        D.sha(materials[name])
    publication = _keys(record["publication"], {"documents", "totals"}, "Android public publication fields differ")
    _keys(publication["documents"], DOCS, "Android public document references differ")
    for name, pin in publication["documents"].items():
        _keys(pin, {"size", "sha256"}, "Android public document reference fields differ")
        D.sha(pin["sha256"])
        D.need(type(pin["size"]) is int and 0 < pin["size"] <= DOCS[name][1], "Android public document extent differs")
    totals = _keys(publication["totals"], {"toolFiles", "toolDirectories", "toolBytes", "osFiles", "osAliases", "osBytes"},
                   "Android public count fields differ")
    D.need(all(type(v) is int and 0 <= v <= TOTAL_LIMIT for v in totals.values()), "Android public count type/bound differs")
    return {"schemaVersion": 1, "scope": SCOPE, "policySha256": POLICY_SHA256,
            "materials": dict(materials), "publication": deepcopy(publication),
            "qualification": False, "newConsent": False}
