"""Fixed conventional-interpreter smoke probe for independently admitted inputs.

This is not a launcher, installer, TLS client or runtime-custody constructor.
The reviewed outer command must first call inspect_prepared() in its
trusted host interpreter, bind this source, and retain the original candidate
wait and bounded output closes. Calling this file under Python is ALREADY an
execution: its own checks cannot retroactively authorize that launch.

The two source pins select the independently accepted prepared manifest/protocol,
not merely a source-build result. Missing pins still refuse before input access.
No fallback, candidate discovery or production gate is supplied by this probe.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

PROFILE = "cpython-3.14.7-linux-x86_64-source-v1"
SCOPE = "conventional-interpreter-behavior-smoke-v1"
APPROVED_PREPARED_MANIFEST_SHA256: str | None = '8ef2fefe057a1773acb8d5d514adc08c28baebc98d4178f448ad2b74be204d66'
APPROVED_PROTOCOL_SHA256: str | None = '083e6afae3e329c4e0d81bad00dd0c9920f77491b38ce0d23aa602996f4c4bf5'
TARGET = "x86_64-unknown-linux-gnu"
CA = (240216, "9cc2a774b5198dcff14d9be1e66091f538975d867ce029a96bce15a55dfd730f")
SELECTED = {
    "python/bin/python3": 64 << 20,
    "core.zip": 32 << 20,
    "engine_bootstrap.py": 64 << 10,
    "github-ca.pem": 512 << 10,
    "python/lib/libssl.so.3": 64 << 20,
    "python/lib/libcrypto.so.3": 64 << 20,
}
EXPECTED_BUILTINS = tuple(sorted((
    "atexit faulthandler posix _signal _tracemalloc _suggestions _datetime "
    "_codecs _collections errno _io itertools _sre _sysconfig _thread time _types _typing "
    "_weakref _abc _functools _locale _opcode _operator _stat _symtable pwd "
    "marshal _imp _ast _tokenize builtins sys gc _contextvars _warnings _string "
    "_bisect _blake2 _ctypes _heapq _hmac _json _md5 _posixsubprocess _random _sha1 "
    "_sha2 _sha3 _struct binascii fcntl math select unicodedata zlib _socket _ssl pyexpat resource"
).split()))
NOT_VERIFIED = ["installed-runtime-custody", "immutable-publication", "tls-handshake",
                "dns-or-github-authentication", "native-close-faults", "gui", "production-enablement"]
SAFE_REFUSALS = frozenset((
    "ambient-core-already-imported candidate-builtin-origin candidate-ca-bytes candidate-ca-parse "
    "candidate-default-trust-present candidate-eof-option-clear candidate-eof-option-missing "
    "candidate-eof-option-set candidate-exact-sixty-builtins candidate-expat-version "
    "candidate-malformed-xml-accepted candidate-openssl-version candidate-relocated-search "
    "candidate-resource-api candidate-stdlib-origin candidate-version-flags-platform "
    "candidate-xml-refusal candidate-xml-value checkout-bootstrap-differs-from-prepared "
    "core-import-not-prepared-zip duplicate-manifest-key fixed-ca-pin fixed-probe-arguments "
    "foreign-or-deleted-private-dso manifest-number noncanonical-prepared-path prepared-body-pin "
    "prepared-file-fields prepared-file-name prepared-file-open-changed prepared-file-read-changed "
    "prepared-file-shape prepared-file-value prepared-inputs-changed-after-probe "
    "prepared-inventory-order prepared-inventory-pin prepared-manifest-fields prepared-manifest-pin "
    "prepared-manifest-profile prepared-output-not-admitted prepared-runtime-root prepared-selected-files "
    "private-executable-mapping-missing private-mapped-backing-changed private-mapped-body-pin "
    "private-mapping-alias private-mapping-identity private-maps-bound probe-output-bound probe-output-short"
).split())


class SmokeRefused(ValueError):
    pass


def _diagnostic(error: BaseException) -> str:
    # Only this source's literal refusal roster or fixed categories leave stderr.
    # Never stringify an exception, path, argv, import diagnostic or traceback.
    if type(error) is SmokeRefused:
        args = error.args
        code = (args[0] if len(args) == 1 and type(args[0]) is str and len(args[0]) <= 64
                and args[0] in SAFE_REFUSALS else "unrecognized-refusal")
    elif isinstance(error, KeyboardInterrupt):
        code = "interrupted"
    elif isinstance(error, ImportError):
        code = "import-failed"
    elif isinstance(error, OSError):
        code = "io-failed"
    elif isinstance(error, (ValueError, TypeError, KeyError, AttributeError, OverflowError)):
        code = "data-or-api-failed"
    else:
        code = "unexpected-exception"
    return f"Conventional runtime smoke refused or failed [{SCOPE}]: {code}; preserve original evidence.\n"


def _openssl_version(value: object) -> bool:
    # CPython 3.14.7 _ssl.c:6753-6759 exposes a legacy five-field tuple, not
    # semantic major/minor/patch; the public string comes from OpenSSL_version.
    return (type(value) is str and 0 < len(value) <= 128 and value.startswith("OpenSSL 3.5.8 ")
            and all(" " <= character <= "~" for character in value))


def _need(value: bool, code: str) -> None:
    if not value:
        raise SmokeRefused(code)


def _sha(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _anchors() -> tuple[str, str]:
    _need(_sha(APPROVED_PREPARED_MANIFEST_SHA256) and _sha(APPROVED_PROTOCOL_SHA256),
          "prepared-output-not-admitted")
    return APPROVED_PREPARED_MANIFEST_SHA256, APPROVED_PROTOCOL_SHA256


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        _need(key not in result, "duplicate-manifest-key")
        result[key] = value
    return result


def _state(value) -> tuple[int, ...]:
    # Same bounded ordinary-file correspondence as prepare_runtime.read_checked;
    # not a retained descriptor, immutable namespace or original-close receipt.
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _read(path: Path, limit: int, mapped_identity: tuple[int, int, int] | None = None) -> bytes:
    _need(path.is_absolute() and path.resolve(strict=True) == path, "noncanonical-prepared-path")
    before = path.lstat()
    _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
          and 0 < before.st_size <= limit, "prepared-file-shape")
    if mapped_identity is not None:
        _need(mapped_identity == (os.major(before.st_dev), os.minor(before.st_dev), before.st_ino),
              "private-mapped-backing-changed")
    with path.open("rb") as original:
        _need(_state(os.fstat(original.fileno())) == _state(before), "prepared-file-open-changed")
        raw = original.read(before.st_size + 1)
        after = os.fstat(original.fileno())
    _need(len(raw) == before.st_size and _state(after) == _state(before)
          and _state(path.lstat()) == _state(before), "prepared-file-read-changed")
    return raw


def _selected_records(raw: bytes, manifest_sha: str, protocol_sha: str) -> list[dict]:
    _need(_sha(manifest_sha) and _sha(protocol_sha) and _digest(raw) == manifest_sha,
          "prepared-manifest-pin")
    document = json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(SmokeRefused("manifest-number")))
    _need(type(document) is dict and set(document) == {"schemaVersion", "protocol", "coreVersion", "target",
          "coreSha256", "protocolSha256", "inventorySha256", "files"}, "prepared-manifest-fields")
    _need(type(document["schemaVersion"]) is int and document["schemaVersion"] == 1
          and type(document["protocol"]) is int and document["protocol"] == 1
          and document["coreVersion"] == "0.3.0" and document["target"] == TARGET
          and document["protocolSha256"] == protocol_sha, "prepared-manifest-profile")
    rows = document["files"]
    _need(type(rows) is list and 0 < len(rows) <= 2048
          and _digest(_canonical(rows)) == document["inventorySha256"], "prepared-inventory-pin")
    names, total = [], 0
    for row in rows:
        _need(type(row) is dict and set(row) == {"path", "size", "sha256"}, "prepared-file-fields")
        name = row["path"]
        _need(type(name) is str and 0 < len(name) <= 512 and name != "manifest.json"
              and 0 < len(name.split("/")) <= 16
              and all(re.fullmatch(r"[A-Za-z0-9._+-]+", part) and part not in {".", ".."}
                      and not part.endswith(".") for part in name.split("/")), "prepared-file-name")
        _need(type(row["size"]) is int and 0 <= row["size"] <= 512 << 20 and _sha(row["sha256"]),
              "prepared-file-value")
        total += row["size"]
        names.append(name)
    _need(names == sorted(names) and len(set(name.lower() for name in names)) == len(names)
          and total <= 1 << 30, "prepared-inventory-order")
    chosen = {row["path"]: row for row in rows if row["path"] in SELECTED}
    _need(set(chosen) == set(SELECTED) and chosen["core.zip"]["sha256"] == document["coreSha256"],
          "prepared-selected-files")
    _need((chosen["github-ca.pem"]["size"], chosen["github-ca.pem"]["sha256"]) == CA,
          "fixed-ca-pin")
    return [chosen[name] for name in sorted(chosen)]


def _inspect_prepared(root: Path, manifest_sha: str, protocol_sha: str, source_bootstrap: Path) -> dict:
    _need(root.is_absolute() and root.name == "runtime" and root.resolve(strict=True) == root
          and root.is_dir(), "prepared-runtime-root")
    raw = _read(root / "manifest.json", 1 << 20)
    rows = _selected_records(raw, manifest_sha, protocol_sha)
    for row in rows:
        body = _read(root / row["path"], SELECTED[row["path"]])
        _need(len(body) == row["size"] and _digest(body) == row["sha256"], "prepared-body-pin")
    bootstrap = next(row for row in rows if row["path"] == "engine_bootstrap.py")
    original = _read(source_bootstrap, SELECTED["engine_bootstrap.py"])
    _need(len(original) == bootstrap["size"] and _digest(original) == bootstrap["sha256"],
          "checkout-bootstrap-differs-from-prepared")
    return {"manifestSha256": manifest_sha, "protocolSha256": protocol_sha, "files": rows}


def inspect_prepared(root: Path) -> dict:
    """Host-side prelaunch DATA check, also repeated by the candidate probe.

    Returned paths/hashes never grant execution or original-resource authority.
    The future outer command must bind this source and the original process.
    """
    manifest_sha, protocol_sha = _anchors()  # Before any caller path access.
    bootstrap = Path(__file__).resolve(strict=True).parent.parent / "engine_bootstrap.py"
    return _inspect_prepared(root, manifest_sha, protocol_sha, bootstrap)


def _mapped_private_rows(raw: bytes, paths: dict[str, str]) -> dict[str, tuple[int, int, int]]:
    """Only two named DSOs, not a new loader/stdlib/component census.

    Reuse github_tls_runtime's bounded original maps/backing identity grammar;
    multiple executable VMAs of the same file are not multiple libraries.
    """
    _need(type(raw) is bytes and 0 < len(raw) <= 1 << 20, "private-maps-bound")
    found, executable = {}, set()
    for line in raw.decode("utf-8", errors="strict").splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6 or not fields[5].startswith("/"):
            continue
        name = fields[5].removesuffix(" (deleted)").rsplit("/", 1)[-1]
        if not name.startswith(("libssl.so", "libcrypto.so")):
            continue
        _need(name in paths and fields[5] == paths[name], "foreign-or-deleted-private-dso")
        _need(re.fullmatch(r"[0-9a-f]+:[0-9a-f]+", fields[3]) is not None
              and re.fullmatch(r"[1-9][0-9]{0,19}", fields[4]) is not None, "private-mapping-identity")
        identity = (*[int(part, 16) for part in fields[3].split(":")], int(fields[4]))
        _need(name not in found or found[name] == identity, "private-mapping-alias")
        found[name] = identity
        if "x" in fields[1]:
            executable.add(name)
    _need(set(found) == set(paths) and executable == set(paths), "private-executable-mapping-missing")
    return found


def _observe(root: Path, bindings: dict) -> dict:
    # Explicit behavior probes occur here, after the fixed prepared-body check;
    # ordinary host-side DATA imports above are not candidate launch admission.
    import importlib
    _need(sys.version_info[:3] == (3, 14, 7) and sys.platform == "linux"
          and os.uname().machine == "x86_64" and os.geteuid() != 0
          and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
          and sys.flags.optimize == 0, "candidate-version-flags-platform")
    prefix, library = root / "python", root / "python/lib/python3.14"
    _need(Path(sys.executable) == root / "python/bin/python3" and Path(sys.base_prefix) == prefix
          and Path(sys.prefix) == prefix and str(library) in sys.path
          and all(path in {str(library), str(library / "lib-dynload"), str(prefix / "lib/python314.zip")}
                  for path in sys.path), "candidate-relocated-search")
    _need(tuple(sorted(sys.builtin_module_names)) == EXPECTED_BUILTINS, "candidate-exact-sixty-builtins")
    for name in EXPECTED_BUILTINS:
        module = importlib.import_module(name)
        _need(module.__spec__ is not None and module.__spec__.origin == "built-in"
              and not hasattr(module, "__file__"), "candidate-builtin-origin")
    import pyexpat
    import resource
    import socket
    import ssl
    import sysconfig
    _need(sysconfig.get_path("stdlib") == str(library)
          and Path(ssl.__file__) == library / "ssl.py"
          and Path(socket.__file__) == library / "socket.py", "candidate-stdlib-origin")
    _need(pyexpat.EXPAT_VERSION == "expat_2.8.2", "candidate-expat-version")
    nofile = resource.getrlimit(resource.RLIMIT_NOFILE)  # Read only; never setrlimit/toolchain admission.
    _need(len(nofile) == 2 and all(type(value) is int for value in nofile)
          and (nofile[0] == resource.RLIM_INFINITY or nofile[0] > 0)
          and (nofile[1] == resource.RLIM_INFINITY or 0 < nofile[0] <= nofile[1]), "candidate-resource-api")
    core = str(root / "core.zip")
    _need(not any(name == "mobile_release" or name.startswith("mobile_release.") for name in sys.modules),
          "ambient-core-already-imported")
    previous = list(sys.path)
    try:
        sys.path.insert(0, core)
        from mobile_release import android_manifest as xml
        from mobile_release import _github_connection_transport as transport
        _need(all(getattr(module, "__file__", "").startswith(core + "/mobile_release/")
                  for name, module in sys.modules.items()
                  if name == "mobile_release" or name.startswith("mobile_release.")), "core-import-not-prepared-zip")
        # Existing ManifestPolicyTests' valid namespace/identity fixture and an
        # actual malformed parser call, not a mock or a pre-parser DTD refusal.
        valid = ('<manifest xmlns:a="http://schemas.android.com/apk/res/android" '
                 'package="org.fixture.app" a:versionCode="42" a:versionName="1.2.3"><application /></manifest>')
        _need(xml.parse_android_manifest(valid) == xml.AndroidManifest("org.fixture.app", "42", "1.2.3", False, False),
              "candidate-xml-value")
        try:
            xml.parse_android_manifest(valid[:-1])
        except xml.ManifestInspectionError as error:
            _need(error.reason == "xml", "candidate-xml-refusal")
        else:
            raise SmokeRefused("candidate-malformed-xml-accepted")
        _need(_openssl_version(ssl.OPENSSL_VERSION), "candidate-openssl-version")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        mask = int(getattr(ssl, "OP_IGNORE_UNEXPECTED_EOF", 0))
        _need(0 < mask < 2**64, "candidate-eof-option-missing")
        context.options |= mask
        _need(int(context.options) & mask == mask, "candidate-eof-option-set")
        context.options &= ~mask
        _need(int(context.options) & mask == 0, "candidate-eof-option-clear")
        # Exact initialization APIs from _make_live_reader, without calling its
        # live factory or ever creating a socket, request, token or peer.
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.keylog_filename = None
        context.set_alpn_protocols(["http/1.1"])
        _need(context.cert_store_stats()["x509"] == 0, "candidate-default-trust-present")
        ca = transport._fixed_ca(str(root), transport._Budget(time.monotonic()))
        _need((len(ca.encode("ascii")), _digest(ca.encode("ascii"))) == CA, "candidate-ca-bytes")
        context.load_verify_locations(cadata=ca)
        certificates = context.cert_store_stats()["x509_ca"]
        _need(type(certificates) is int and certificates > 0, "candidate-ca-parse")
        with Path("/proc/self/maps").open("rb") as original:
            mapped = original.read((1 << 20) + 1)
        paths = {name: str(prefix / "lib" / name) for name in ("libssl.so.3", "libcrypto.so.3")}
        identities = _mapped_private_rows(mapped, paths)
        rows = {row["path"]: row for row in bindings["files"]}
        for name, identity in identities.items():
            path = Path(paths[name])
            row = rows["python/lib/" + name]
            body = _read(path, SELECTED[row["path"]], identity)
            _need(len(body) == row["size"] and _digest(body) == row["sha256"], "private-mapped-body-pin")
        return {"pythonVersion": [3, 14, 7], "builtinNames": list(EXPECTED_BUILTINS),
                "expatVersion": pyexpat.EXPAT_VERSION, "xmlValid": True, "xmlMalformedRefused": True,
                "nofile": list(nofile), "opensslVersion": ssl.OPENSSL_VERSION,
                "ignoreUnexpectedEof": mask, "caCertificates": certificates,
                "privateMappedLibraries": sorted(paths), "coreImportsFromPreparedZip": True}
    finally:
        sys.path[:] = previous


def main() -> int:
    _anchors()  # Even argument/path inspection cannot bypass absent preparation admission.
    _need(len(sys.argv) == 2, "fixed-probe-arguments")
    root = Path(sys.argv[1])
    before = inspect_prepared(root)
    observed = _observe(root, before)
    _need(inspect_prepared(root) == before, "prepared-inputs-changed-after-probe")
    raw = _canonical({"schemaVersion": 1, "profile": PROFILE, "scope": SCOPE, "status": "passed",
                      "bindings": before, "observed": observed, "notVerified": NOT_VERIFIED,
                      "outerOriginalWaitRequired": True}) + b"\n"
    _need(len(raw) <= 32 << 10, "probe-output-bound")
    _need(sys.stdout.buffer.write(raw) == len(raw), "probe-output-short")
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except (Exception, KeyboardInterrupt) as error:
        sys.stderr.write(_diagnostic(error))
        code = 78
    raise SystemExit(code)
