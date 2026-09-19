"""Fixed H1 installed-input DATA observation; never tool/build admission.

The workflow embeds this exact source. Its separately pinned, bounded JSON DATA
is passed through one literal environment value, removed before context capture.
Importing this module does not observe a host, create outputs or launch anything.
"""
import base64
import errno
import hashlib
import json
import os
import re
import resource
import stat
import sys
import zlib

POLICY_SHA256 = 'f9df2617dee80f6fa6b523334ac2fa9de741272a06ba73f4a85bc18543344d15'
POLICY_BYTES = 197755
POLICY_ENCODED_BYTES = 27665
DATASET_SHA256 = '6cf2895fb722f183434a7cb49c487b0494dc70715feef085886452e02801f20d'
PROFILE = "mrk-packaged-host-tool-inputs-1"
ROLE_NAMES = ("ar", "as", "cc", "cc1", "cc1plus", "collect2", "cxx", "host_python", "ld", "make", "perl", "ranlib", "sh")
STAT_KEYS = ("device", "inode", "mode", "uid", "gid", "links", "bytes", "blocks", "mtimeNs", "ctimeNs")
D = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
F = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
BODY = META = SUPPORT = 0
CACHE, ORIGINALS, GAPS = {}, {}, {}
P = None
PHASE = "BOOTSTRAP_CONTEXT"
ENVIRONMENT = ('PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL', 'TZ', 'ImageOS', 'ImageVersion', 'GITHUB_WORKSPACE', 'RUNNER_TEMP', 'GITHUB_ENV', 'GITHUB_OUTPUT', 'GITHUB_PATH', 'GITHUB_STEP_SUMMARY', 'GITHUB_EVENT_PATH', 'GITHUB_SHA', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_EVENT_NAME', 'RUNNER_ENVIRONMENT', 'GITHUB_REF')
PATTERNS = {'GITHUB_ENV': '/home/runner/work/_temp/_runner_file_commands/set_env_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'GITHUB_OUTPUT': '/home/runner/work/_temp/_runner_file_commands/set_output_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'GITHUB_PATH': '/home/runner/work/_temp/_runner_file_commands/add_path_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'GITHUB_RUN_ID': '[1-9][0-9]{0,19}', 'GITHUB_SHA': '(?!0{40}$)[0-9a-f]{40}', 'GITHUB_STEP_SUMMARY': '/home/runner/work/_temp/_runner_file_commands/step_summary_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'ImageOS': '[A-Za-z0-9_.-]{1,32}', 'ImageVersion': '[0-9]{8}\\.[0-9]{1,6}\\.[0-9]{1,6}'}
FIXED_ENVIRONMENT = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_EVENT_PATH': '/home/runner/work/_temp/_github_workflow/event.json', 'GITHUB_REF': 'refs/heads/verify/desktop-packaged-host-tools', 'GITHUB_REPOSITORY': 'Apdelrahman1911/mobile-release-kit', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_WORKSPACE': '/home/runner/work/mobile-release-kit/mobile-release-kit', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PATH': '/usr/bin:/bin', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_TEMP': '/home/runner/work/_temp', 'TZ': 'UTC'}
PUBLIC_RUN = ('ImageOS', 'ImageVersion', 'GITHUB_SHA', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_EVENT_NAME', 'RUNNER_ENVIRONMENT', 'GITHUB_REF')
GAP_CODES = frozenset(("OBJECT_UNAVAILABLE", "OBJECT_NONORDINARY", "OBJECT_MODE", "ALIAS_DIFFERENT", "ABSENCE_NOT_ESTABLISHED",
    "PROVIDER_UNAVAILABLE", "PROVIDER_INVALID", "PROVIDER_MISSING", "PROVIDER_DUPLICATE", "PROVIDER_DIFFERENT",
    "ROLE_BODY_DIFFERENT", "ROLE_DECLARATION_MISSING", "ROLE_DECLARATION_DUPLICATE", "SELF_EXE_DIFFERENT",
    "MAP_UNKNOWN", "MAP_DELETED", "MAP_CHANGED", "MAP_INVALID", "MAP_SELF_MISSING", "PYTHON_STARTUP_NOT_QUALIFIED",
    "PERL_NAMESPACE_NOT_QUALIFIED", "COMPILER_RUNTIME_NOT_QUALIFIED"))


class Refused(Exception):
    """Closed failure, never populated from input or exception messages."""


class CleanupUnknown(Refused):
    pass


def need(value):
    if not value:
        raise Refused()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def load_policy(encoded):
    """Only the frozen DATA body, never a configurable path policy."""
    need(type(encoded) is str and len(encoded) == POLICY_ENCODED_BYTES and len(encoded) <= 48 * 1024)
    try:
        packed = base64.b85decode(encoded.encode("ascii"))
        decoder = zlib.decompressobj()
        raw = decoder.decompress(packed, 512 * 1024 + 1)
        need(len(raw) == POLICY_BYTES <= 512 * 1024 and decoder.eof
             and not decoder.unconsumed_tail and not decoder.unused_data)
        need(hashlib.sha256(raw).hexdigest() == POLICY_SHA256)
        value = json.loads(raw, object_pairs_hook=unique)
        need(canonical(value) == raw)
        validate_policy(value)
        return value
    except (ValueError, TypeError, UnicodeError, zlib.error):
        raise Refused() from None


def validate_policy(value):
    need(type(value) is dict and set(value) == {"schemaVersion", "profile", "paths", "roles", "providers", "aliases",
        "metadataIndices", "cacheIndices", "absenceIndices", "directoryIndices", "mapFileIndices", "sourceDatasetSha256"})
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["profile"] == PROFILE
         and value["sourceDatasetSha256"] == DATASET_SHA256)
    paths = value["paths"]
    need(type(paths) is list and len(paths) == 3460 and paths == sorted(set(paths)))
    need(all(type(p) is str and len(p) <= 512 and re.fullmatch(r"/[A-Za-z0-9_./+@=:-]+", p)
             and os.path.normpath(p) == p for p in paths))
    need(type(value["roles"]) is dict and tuple(sorted(value["roles"])) == ROLE_NAMES)
    for role in value["roles"].values():
        need(type(role) is dict and set(role) == {"path", "index", "package", "bytes", "mode", "sha256"})
        need(type(role["index"]) is int and 0 <= role["index"] < len(paths) and paths[role["index"]] == role["path"])
        need(type(role["bytes"]) is int and 0 < role["bytes"] <= 512 * 2**20 and role["mode"] == 0o755)
        need(type(role["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", role["sha256"]) is not None)
    need(type(value["providers"]) is list and len(value["providers"]) == 42)
    names = []
    for provider in value["providers"]:
        need(type(provider) is dict and set(provider) == {"path", "index", "package", "architecture", "version"})
        need(type(provider["index"]) is int and 0 <= provider["index"] < len(paths)
             and paths[provider["index"]] == provider["path"] and provider["path"].startswith("/var/lib/dpkg/info/"))
        names.append(provider["package"])
    need(names == sorted(set(names)) and all(role["package"] in names for role in value["roles"].values()))
    for key, count in (("metadataIndices", 43), ("cacheIndices", 568), ("absenceIndices", 63), ("mapFileIndices", 156)):
        rows = value[key]
        need(type(rows) is list and len(rows) == count and rows == sorted(set(rows))
             and all(type(i) is int and 0 <= i < len(paths) for i in rows))
    need(type(value["directoryIndices"]) is list and value["directoryIndices"] == sorted(set(value["directoryIndices"])))
    need(all(type(i) is int and 0 <= i < len(paths) for i in value["directoryIndices"]))
    need(type(value["aliases"]) is dict and all(p in paths and target in paths for p, target in value["aliases"].items()))
    # The digest binds the complete roster, not only these structural guards.
    need(hashlib.sha256(canonical(value)).hexdigest() == POLICY_SHA256)


def gap(code, count=1):
    need(code in GAP_CODES and type(count) is int and 0 < count <= 8192)
    GAPS[code] = GAPS.get(code, 0) + count
    need(len(GAPS) <= 192 and GAPS[code] <= 16384)


def close_all(descriptors):
    """Attempt each retained original once; close failure cannot become absence."""
    failed = False
    for descriptor in descriptors:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException:
                failed = True
    if failed:
        raise CleanupUnknown() from None


def ident(s):
    return dict(zip(STAT_KEYS, (s.st_dev, s.st_ino, stat.S_IMODE(s.st_mode), s.st_uid, s.st_gid,
        s.st_nlink, s.st_size, s.st_blocks, s.st_mtime_ns, s.st_ctime_ns)))


def link_body(descriptor, name):
    """Reserve before each readlink, including original-self rechecks."""
    global META, BODY
    need(META + 4096 <= 8 * 2**20 and BODY + 4096 <= 3 * 2**30)
    link = os.readlink(name, dir_fd=descriptor)
    length = len(os.fsencode(link))
    need(length <= 512)
    META += length
    BODY += length
    return link


def parent(path):
    need(type(path) is str and path.startswith("/") and os.path.normpath(path) == path and len(path) <= 512)
    if path.startswith("/proc/self/"):
        need(path in ("/proc/self/maps", "/proc/self/exe"))
        proc = directory("/proc")
        descriptor = None
        try:
            link = link_body(proc, "self")
            need(link == str(os.getpid()))
            descriptor = os.open("self", D & ~os.O_NOFOLLOW, dir_fd=proc)
        finally:
            try:
                close_all([proc])
            except BaseException:
                close_all([descriptor])
                raise
        return descriptor, path.rsplit("/", 1)[1]
    descriptor = os.open("/", D)
    try:
        parts = path.split("/")[1:]
        for part in parts[:-1]:
            child = os.open(part, D, dir_fd=descriptor)
            previous, descriptor = descriptor, child
            close_all([previous])
        return descriptor, parts[-1]
    except BaseException:
        close_all([descriptor])
        raise


def at(path):
    descriptor, name = parent(path)
    try:
        return os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    finally:
        close_all([descriptor])


def directory(path):
    descriptor, name = parent(path)
    child = None
    try:
        child = os.open(name, D, dir_fd=descriptor)
    finally:
        try:
            close_all([descriptor])
        except BaseException:
            close_all([child])
            raise
    return child


def body(path, cap, metadata=False, support=False):
    """H0 bounded original-parent read; only close handling is tightened."""
    global BODY, META, SUPPORT
    if path in CACHE:
        row, raw = CACHE[path]
        need(ident(at(path)) == row["stat"] and row["stat"]["bytes"] <= cap)
        return row, raw
    parent_fd, name = parent(path)
    descriptor = None
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= cap)
        descriptor = os.open(name, F, dir_fd=parent_fd)
        need(ident(os.fstat(descriptor)) == ident(before))
        digest, raw, total = hashlib.sha256(), bytearray(), 0
        pseudo = path == "/proc/self/maps"
        while pseudo or total < before.st_size:
            room = min(cap - total, 3 * 2**30 - BODY, 8 * 2**20 - META if metadata else cap,
                       2 * 2**30 - SUPPORT if support else cap)
            need(room > 0)
            chunk = os.read(descriptor, min(65536, room, cap if pseudo else before.st_size - total))
            if not chunk:
                break
            total += len(chunk)
            BODY += len(chunk)
            META += len(chunk) if metadata else 0
            SUPPORT += len(chunk) if support else 0
            need(total <= cap and BODY <= 3 * 2**30 and META <= 8 * 2**20 and SUPPORT <= 2 * 2**30)
            digest.update(chunk)
            if metadata:
                raw.extend(chunk)
        need(total == before.st_size or pseudo)
        need(ident(before) == ident(os.fstat(descriptor)) == ident(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)))
        need(ident(before) == ident(at(path)))
        row = {"path": path, "kind": "regular", "stat": ident(before), "sha256": digest.hexdigest(), "aliasTarget": None}
        CACHE[path] = (row, bytes(raw))
        return CACHE[path]
    finally:
        close_all([descriptor, parent_fd])


def measure(path, metadata=False):
    try:
        before = at(path)
        if stat.S_ISREG(before.st_mode):
            cap = 4 * 2**20 if path == "/var/lib/dpkg/status" else 256 * 1024 if metadata else 512 * 2**20
            row = body(path, cap, metadata=metadata, support=not metadata)[0]
            ORIGINALS[path] = ident(before)
            return row
        target = None
        if stat.S_ISLNK(before.st_mode):
            need(before.st_size <= 512)
            descriptor, name = parent(path)
            try:
                link = link_body(descriptor, name)
            finally:
                close_all([descriptor])
            dest = os.path.normpath(os.path.join(os.path.dirname(path), link))
            if P["aliases"].get(path) == dest:
                target = dest
        need(ident(before) == ident(at(path)))
        ORIGINALS[path] = ident(before)
        kind = "alias" if stat.S_ISLNK(before.st_mode) else "directory" if stat.S_ISDIR(before.st_mode) else "nonordinary"
        return {"path": path, "kind": kind, "stat": ident(before), "sha256": None, "aliasTarget": target}
    except OSError as error:
        need(error.errno in (errno.ENOENT, errno.EACCES, errno.EPERM, errno.ENOTDIR, errno.ELOOP))
        ORIGINALS[path] = error.errno
        return {"path": path, "kind": "unavailable", "stat": None, "sha256": None, "aliasTarget": None}


def recheck_originals():
    for path, expected in ORIGINALS.items():
        try:
            current = ident(at(path))
        except OSError as error:
            current = error.errno
        need(current == expected)


def provider_status(raw, providers):
    """Selected declarations, never installed-byte authentication or lookup."""
    result = {p["package"]: [] for p in providers}
    if raw is None:
        return {name: {"state": "unavailable"} for name in result}
    if type(raw) is not bytes or len(raw) > 4 * 2**20 or b"\r" in raw:
        return {name: {"state": "invalid"} for name in result}
    try:
        text = raw.decode("utf-8")
        for stanza in text.split("\n\n"):
            fields, invalid, previous = {}, False, None
            for line in stanza.splitlines():
                if line.startswith((" ", "\t")):
                    invalid |= previous is None or previous in ("package", "status", "version", "architecture")
                    continue
                if ":" not in line:
                    invalid = True
                    continue
                name, value = line.split(":", 1)
                name = name.lower()
                invalid |= re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) is None or name in fields
                fields[name], previous = value.lstrip(" \t"), name
            name = fields.get("package")
            if name in result:
                valid = not invalid and fields.get("status") == "install ok installed" and all(
                    re.fullmatch(r"[A-Za-z0-9_.+:~=-]{1,96}", fields.get(key, "")) for key in ("version", "architecture"))
                result[name].append({key: fields[key] for key in ("version", "architecture")} if valid else None)
    except UnicodeError:
        return {name: {"state": "invalid"} for name in result}
    compared = {}
    for provider in providers:
        name = provider["package"]
        rows = result[name]
        if not rows:
            compared[name] = {"state": "missing"}
        elif len(rows) != 1:
            compared[name] = {"state": "duplicate"}
        elif rows[0] is None:
            compared[name] = {"state": "invalid"}
        else:
            compared[name] = {"state": "matches-declaration" if rows[0] == {key: provider[key] for key in ("version", "architecture")} else "different", **rows[0]}
    return compared


def declared_members(raw, allowed, aliases):
    """Provider names can select only existing indices, never authorize reads."""
    if type(raw) is not bytes or len(raw) > 256 * 1024:
        return None
    try:
        result, seen = set(), set()
        for name in raw.decode("utf-8").splitlines():
            for old, target in aliases.items():
                if name.startswith(old + "/"):
                    name = target + name[len(old):]
                    break
            if name in allowed:
                need(name not in seen)
                seen.add(name)
                result.add(allowed[name])
        return result
    except (UnicodeError, Refused):
        return None


def role_observation(expected, row, declarations):
    matches = row["kind"] == "regular" and row["sha256"] == expected["sha256"] and all(
        row["stat"][key] == value for key, value in (("bytes", expected["bytes"]), ("mode", expected["mode"]), ("uid", 0), ("gid", 0), ("links", 1)))
    owners = sorted(name for name, indices in declarations.items() if indices is not None and expected["index"] in indices)
    return {"index": expected["index"], "body": "matches-retained-member" if matches else "different-or-unavailable",
            "declaredProviders": owners, "expectedProviderDeclared": expected["package"] in owners,
            "scope": "fixed-provider-declarations-not-global-ownership"}


_MAP = re.compile(r"([0-9a-f]{1,16})-([0-9a-f]{1,16}) ([r-][w-][x-][ps]) ([0-9a-f]{1,16}) ([0-9a-f]{1,8}):([0-9a-f]{1,8}) ([0-9]{1,20})(?: +(.+))?\Z")
_KERNEL = frozenset(("[heap]", "[stack]", "[vvar]", "[vvar_vclock]", "[vdso]", "[vsyscall]"))


def normalized_maps(raw, rows, allowed_indices, aliases, self_index):
    """No filesystem operations, raw path export, process search or authority."""
    result = {"mappedIndices": [], "anonymousMappings": 0, "kernelMappings": 0, "gaps": {}}
    def note(code):
        result["gaps"][code] = result["gaps"].get(code, 0) + 1
    if type(raw) is not bytes or not raw or len(raw) > 256 * 1024 or not raw.endswith(b"\n"):
        note("MAP_INVALID")
        return result
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        note("MAP_INVALID")
        return result
    if len(lines) > 2048:
        note("MAP_INVALID")
        return result
    by_path = {rows[i]["path"]: (i, rows[i]) for i in allowed_indices}
    mapped, last = set(), 0
    for line in lines:
        match = _MAP.fullmatch(line) if len(line) <= 8192 else None
        if match is None:
            note("MAP_INVALID")
            continue
        start, end, inode = int(match[1], 16), int(match[2], 16), int(match[7])
        if not last <= start < end or inode >= 2**64:
            note("MAP_INVALID")
            continue
        last = end
        path = match[8]
        if path is None and inode == 0:
            result["anonymousMappings"] += 1
            continue
        if path in _KERNEL and inode == 0:
            result["kernelMappings"] += 1
            continue
        if path is None:
            note("MAP_UNKNOWN")
            continue
        if path.endswith(" (deleted)"):
            note("MAP_DELETED")
            continue
        for old, target in aliases.items():
            if path.startswith(old + "/"):
                path = target + path[len(old):]
                break
        if path not in by_path:
            note("MAP_UNKNOWN")
            continue
        index, row = by_path[path]
        identity = row["stat"]
        if row["kind"] != "regular" or identity is None or identity["inode"] != inode or (
            os.major(identity["device"]), os.minor(identity["device"])) != (int(match[5], 16), int(match[6], 16)):
            note("MAP_CHANGED")
            continue
        mapped.add(index)
    result["mappedIndices"] = sorted(mapped)
    if self_index not in mapped:
        note("MAP_SELF_MISSING")
    return result


def self_observation(rows, aliases):
    descriptor, name = parent("/proc/self/exe")
    try:
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=True)
        target = link_body(descriptor, name)
        _, raw = body("/proc/self/maps", 256 * 1024, metadata=True)
        need(ident(before) == ident(os.stat(name, dir_fd=descriptor, follow_symlinks=True)))
        need(target == link_body(descriptor, name))
    finally:
        close_all([descriptor])
    index = P["roles"]["host_python"]["index"]
    row = rows[index]
    bound = row["kind"] == "regular" and target == P["paths"][index] and row["stat"] == ident(before)
    if not bound:
        gap("SELF_EXE_DIFFERENT")
    result = normalized_maps(raw, rows, P["mapFileIndices"], aliases, index)
    for code, count in result["gaps"].items():
        gap(code, count)
    return {"scope": "original-observer-self-only", "executableIndex": index if bound else None, **result}


def candidates():
    metadata = set(P["metadataIndices"])
    rows = [measure(path, index in metadata) for index, path in enumerate(P["paths"])]
    allowed = {path: i for i, path in enumerate(P["paths"])}
    aliases = {row["path"]: row["aliasTarget"] for row in rows if row["kind"] == "alias" and row["aliasTarget"]
               and row["path"] in ("/bin", "/lib", "/lib64", "/sbin")}
    for i, row in enumerate(rows):
        if row["kind"] == "unavailable" and i not in P["cacheIndices"] and i not in P["absenceIndices"] and i not in P["directoryIndices"]:
            gap("OBJECT_UNAVAILABLE")
        if row["kind"] == "nonordinary":
            gap("OBJECT_NONORDINARY")
        if row["kind"] == "alias" and row["aliasTarget"] is None:
            gap("ALIAS_DIFFERENT")
        if row["kind"] == "regular" and (row["stat"]["uid"] != 0 or row["stat"]["links"] != 1 or row["stat"]["mode"] & 0o7022):
            gap("OBJECT_MODE")
        if i in P["absenceIndices"] and row["kind"] != "unavailable":
            gap("ABSENCE_NOT_ESTABLISHED")
    declarations = {}
    for provider in P["providers"]:
        cached = CACHE.get(provider["path"])
        declarations[provider["package"]] = declared_members(cached[1] if cached else None, allowed, aliases)
        if declarations[provider["package"]] is None:
            gap("PROVIDER_UNAVAILABLE")
    cached = CACHE.get("/var/lib/dpkg/status")
    statuses = provider_status(cached[1] if cached else None, P["providers"])
    for value in statuses.values():
        if value["state"] != "matches-declaration":
            gap("PROVIDER_" + value["state"].upper())
    roles = {name: role_observation(expected, rows[expected["index"]], declarations) for name, expected in P["roles"].items()}
    for value in roles.values():
        if value["body"] != "matches-retained-member":
            gap("ROLE_BODY_DIFFERENT")
        if not value["expectedProviderDeclared"]:
            gap("ROLE_DECLARATION_MISSING")
        if len(value["declaredProviders"]) > 1:
            gap("ROLE_DECLARATION_DUPLICATE")
    original_self = self_observation(rows, aliases)
    recheck_originals()
    # Compact exact identity arrays leave the unchanged 2-MiB return bound room
    # for the complete frozen roster; indices refer only to its pinned path table.
    compact = [[row["kind"], [row["stat"][key] for key in STAT_KEYS] if row["stat"] else None,
                row["sha256"], allowed[row["aliasTarget"]] if row["aliasTarget"] else None] for row in rows]
    return {"schema": "mrk-h1-host-candidate-files-1", "scope": "candidate-only", "state": "UNSEALED", "nativeQualification": "not-established",
            "profile": PROFILE, "sourceDatasetSha256": DATASET_SHA256, "policySha256": POLICY_SHA256,
            "objectColumns": ["kind", "stat", "sha256", "aliasTargetIndex"], "statColumns": list(STAT_KEYS),
            "objects": compact, "roles": roles, "providerDeclarations": statuses, "self": original_self}


def context():
    global PHASE
    e = dict(os.environ)
    need(set(e) == set(ENVIRONMENT))
    need(all(re.fullmatch(pattern, e[key]) is not None for key, pattern in PATTERNS.items()))
    need(all(e[key] == value for key, value in FIXED_ENVIRONMENT.items()))
    scratch = "/tmp/mrk-packaged-host-tools-" + e["GITHUB_RUN_ID"] + "-1"
    need(all(e[key] == scratch + "/tmp" for key in ("TMPDIR", "TMP", "TEMP")))
    need(e["HOME"] == scratch + "/home" and os.getcwd() == scratch + "/neutral")
    need(os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid())
    need(sys.version_info[:2] == (3, 12) and sys.platform == "linux" and sys.flags.isolated == 1
         and sys.flags.no_site == 1 and sys.flags.dont_write_bytecode == 1 and sys.flags.optimize == 0)
    PHASE = "EVENT"
    _, raw = body(e["GITHUB_EVENT_PATH"], 2**20, metadata=True)
    event = json.loads(raw, object_pairs_hook=unique)
    need(type(event) is dict and event.get("deleted") is False and event.get("ref") == e["GITHUB_REF"]
         and event.get("after") == e["GITHUB_SHA"] and type(event.get("repository")) is dict
         and event["repository"].get("full_name") == e["GITHUB_REPOSITORY"])
    return e, scratch


def bounded_outputs(values):
    encoded = {name: canonical(value) for name, value in values.items()}
    need(sum(map(len, encoded.values())) <= 2 * 2**20)
    return encoded


def main():
    global P, PHASE
    os.umask(0o077)
    for key, value in ((resource.RLIMIT_AS, 512 * 2**20), (resource.RLIMIT_CPU, 60), (resource.RLIMIT_NOFILE, 128),
                       (resource.RLIMIT_FSIZE, 8 * 2**20), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(key, (value, value))
    encoded_policy = os.environ.pop("MRK_H1_POLICY_B85", None)
    P = load_policy(encoded_policy)
    e, scratch = context()
    PHASE = "OWNED_SCRATCH"
    owned_dirs = {p: ident(at(p)) for p in (scratch, scratch + "/home", scratch + "/tmp", scratch + "/neutral")}
    for path, identity in owned_dirs.items():
        need(identity["uid"] == os.getuid() and identity["mode"] == 0o700 and stat.S_ISDIR(at(path).st_mode))
        descriptor = directory(path)
        try:
            names = []
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    need(len(names) < 5)
                    names.append(entry.name)
            need(set(names) == ({"home", "tmp", "neutral", "stdout.bin", "stderr.bin"} if path == scratch else set()))
        finally:
            close_all([descriptor])
    captures = {}
    for descriptor, name in ((1, "stdout.bin"), (2, "stderr.bin")):
        value = os.fstat(descriptor)
        need(stat.S_ISREG(value.st_mode) and ident(value) == ident(at(scratch + "/" + name)))
        need(value.st_uid == os.getuid() and stat.S_IMODE(value.st_mode) == 0o600 and value.st_nlink == 1 and value.st_size == 0)
        captures[name] = ident(value)
    stdin = os.fstat(0)
    need(stat.S_ISFIFO(stdin.st_mode) or (stat.S_ISREG(stdin.st_mode) and stdin.st_size <= 65536))
    need(sys.argv == ["-"])
    reservation = 26 * 2**20 + 512 * 1024
    need(reservation < 32 * 2**20 and os.statvfs(scratch).f_frsize <= 4096)
    def charge(value):
        return max(4096, value.st_blocks * 512, ((value.st_size + 4095) // 4096) * 4096)
    need(sum(charge(at(path)) for path in owned_dirs) + charge(os.fstat(1)) + charge(os.fstat(2))
         + (charge(stdin) if stat.S_ISREG(stdin.st_mode) else 0) <= 256 * 1024)
    PHASE = "CANDIDATES"
    files = candidates()
    for code in ("PYTHON_STARTUP_NOT_QUALIFIED", "PERL_NAMESPACE_NOT_QUALIFIED", "COMPILER_RUNTIME_NOT_QUALIFIED"):
        gap(code)
    kernel = os.uname()
    need(all(re.fullmatch(r"[A-Za-z0-9_.+~-]{1,128}", item) for item in (kernel.sysname, kernel.release, kernel.machine)))
    common = {"scope": "candidate-only", "state": "UNSEALED", "nativeQualification": "not-established", "profile": PROFILE}
    facts = {**common, "schema": "mrk-h1-host-facts-1", "policySha256": POLICY_SHA256,
             "run": {k: e[k] for k in PUBLIC_RUN}, "uid": os.getuid(), "gid": os.getgid(),
             "kernel": {"system": kernel.sysname, "release": kernel.release, "machine": kernel.machine}}
    shape = {**common, "schema": "mrk-h1-ci-shape-1", "return": None, "originalObserver": {
        "argv": ["/usr/bin/env", "-i"] + [key + "=" + e[key] for key in ENVIRONMENT] +
            ["MRK_H1_POLICY_B85=" + encoded_policy, "/usr/bin/timeout", "--signal=TERM", "--kill-after=5s", "180s", "/usr/bin/python3.12", "-I", "-S", "-B", "-"],
        "validatedPushNonDeletion": True, "pythonArgv": sys.argv, "environment": e,
        "policyEnvironment": {"key": "MRK_H1_POLICY_B85", "decodedSha256": POLICY_SHA256, "decodedBytes": POLICY_BYTES, "encodedBytes": POLICY_ENCODED_BYTES},
        "stdinKind": "pipe" if stat.S_ISFIFO(stdin.st_mode) else "regular-heredoc", "captures": captures,
        "scratchDirectories": owned_dirs, "reservedBytes": reservation, "hostBodyReadBytes": BODY, "selectedMetadataBytes": META, "supportBodyReadBytes": SUPPORT,
        "limits": {name: list(resource.getrlimit(key)) for name, key in (("addressSpaceBytes", resource.RLIMIT_AS), ("cpuSeconds", resource.RLIMIT_CPU),
            ("fileDescriptors", resource.RLIMIT_NOFILE), ("fileSizeBytes", resource.RLIMIT_FSIZE), ("coreBytes", resource.RLIMIT_CORE))}}}
    gaps = {**common, "schema": "mrk-h1-fit-gaps-1", "storageBoundary": "bounded-observer-scratch-not-build-admission",
            "observedGaps": [{"predicate": code, "count": count} for code, count in sorted(GAPS.items())]}
    PHASE = "ENCODE"
    encoded = bounded_outputs(dict(zip(("host-facts.json", "host-candidate-files.json", "ci-shape.json", "fit-gaps.json"), (facts, files, shape, gaps))))
    PHASE = "WRITE"
    root = directory(scratch)
    index = {"schema": "mrk-h1-index-1", "root": owned_dirs[scratch], "directories": owned_dirs, "files": {}}
    try:
        for name, raw in encoded.items():
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root)
            try:
                view = memoryview(raw)
                while view:
                    count = os.write(descriptor, view)
                    need(count > 0)
                    view = view[count:]
                os.fsync(descriptor)
                need(ident(os.fstat(descriptor)) == ident(os.stat(name, dir_fd=root, follow_symlinks=False)))
                index["files"][name] = {"stat": ident(os.fstat(descriptor)), "sha256": hashlib.sha256(raw).hexdigest()}
            finally:
                close_all([descriptor])
        raw = canonical(index)
        need(len(raw) <= 2**20)
        descriptor = os.open("index.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root)
        try:
            need(os.write(descriptor, raw) == len(raw))
            os.fsync(descriptor)
        finally:
            close_all([descriptor])
        os.fsync(root)
    finally:
        close_all([root])


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        # Never print an exception, target, map, path, body or raw environment.
        os.write(2, b"MRK_H1_REFUSED\n")
        phases = ("BOOTSTRAP_CONTEXT", "EVENT", "OWNED_SCRATCH", "CANDIDATES", "ENCODE", "WRITE")
        offset = 0 if isinstance(error, Refused) else 1 if isinstance(error, OSError) else 2
        sys.exit(79 if isinstance(error, CleanupUnknown) else 80 + phases.index(PHASE) * 3 + offset)
