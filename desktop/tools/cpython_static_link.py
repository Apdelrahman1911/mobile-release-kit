"""Thin original GNU ld.bfd recorder for the fixed publisher source build.

One real linker invocation; no retry, replacement link, general command runner,
acquisition or timeout owner. Failed native probes and capture failures are
separate. This records publisher evidence, not a linked SBOM or qualification.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

_SPEC = importlib.util.spec_from_file_location("_mrk_static_inputs", Path(__file__).with_name("cpython_static_inputs.py"))
assert _SPEC is not None and _SPEC.loader is not None
I = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(I)
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_LINKS = 4096
MAX_DIAGNOSTIC = 64 * 1024 * 1024
_SAFE_PATH = re.compile(r"[A-Za-z0-9_./+@=,-]+\Z")
_MAP_MEMBER = re.compile(r"([A-Za-z0-9_./+@=,-]+\.a)\(([A-Za-z0-9_./+-]+)\)")
_TRACE_MEMBER = re.compile(r"\(([A-Za-z0-9_./+@=,-]+\.a)\)([A-Za-z0-9_./+-]+)\Z")
_QUERIES = {("--version",), ("-v",), ("-V",), ("--help",)}


def original_result(returncode: int) -> dict:
    I.need(type(returncode) is int and -127 <= returncode <= 255, "Unexpected native return status")
    return {"kind": "exit", "code": returncode} if returncode >= 0 else {"kind": "signal", "signal": -returncode}


def artifact(raw: bytes | None, *, failed: bool, query: bool = False) -> dict:
    if raw is not None:
        return {"available": True, "size": len(raw), "sha256": I.digest(raw)}
    I.need(failed or query, "Required successful-link artifact absent")
    return {"available": False, "reason": "not-a-link" if query else "original-link-failed"}


def output_observation(raw: bytes | None, before: bytes | None, status: int, *, query: bool = False) -> str:
    if query:
        return "not-a-link"
    if status == 0:
        return "successful-original-link-output"
    if raw is not None and raw == before:
        return "unchanged-preexisting-after-failure"
    return "observed-after-failed-link-not-an-accepted-output"


def resolved(name: str, cwd: Path) -> Path:
    I.need(_SAFE_PATH.fullmatch(name) is not None, "Unsupported linker input path syntax")
    path = Path(name)
    return I.absolute(os.path.realpath(path if path.is_absolute() else cwd / path))


def dep_inputs(raw: bytes) -> tuple[str, list[str]]:
    """Closed GNU make subset: ASCII paths without spaces/colon, LF continuations."""
    text = raw.decode("ascii").replace("\\\n", " ")
    I.need("\\" not in text and "\r" not in text, "Unsupported linker depfile escaping")
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    I.need(bool(lines) and lines[0].count(":") == 1, "Incomplete linker depfile")
    output, inputs = lines[0].split(":", 1)
    names = inputs.split()
    I.need(_SAFE_PATH.fullmatch(output) is not None and names and
           all(_SAFE_PATH.fullmatch(name) for name in names), "Unsupported linker dependency path")
    # GNU ld's optional empty phony rules name only those same dependencies.
    I.need(all(line.endswith(":") and line[:-1] in names for line in lines[1:]),
           "Unsupported linker dependency rule")
    return output, names


def member_references(mapping: bytes, trace: bytes) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    map_text, trace_text = mapping.decode("ascii"), trace.decode("ascii")
    selected = set(_MAP_MEMBER.findall(map_text))
    unparsed = _MAP_MEMBER.sub("", map_text)
    I.need(".a(" not in unparsed and ".a)" not in unparsed, "Unsupported map member notation")
    traced = set()
    for line in trace_text.splitlines():
        line = line.strip()
        match = _TRACE_MEMBER.fullmatch(line) or _MAP_MEMBER.fullmatch(line)
        if match:
            traced.add((match[1], match[2]))
        else:
            I.need(".a(" not in line and ".a)" not in line, "Unsupported trace member notation")
    return selected, traced


def reconcile(mapping: bytes, dependency: bytes, trace: bytes, output: Path, cwd: Path) -> tuple[set[Path], set[tuple[Path, str]]]:
    I.need(bool(mapping.strip()), "Empty successful-link map")
    dep_output, names = dep_inputs(dependency)
    I.need(resolved(dep_output, cwd) == output, "Depfile output disagrees with original argv")
    paths = {resolved(name, cwd) for name in names}
    selected_raw, traced_raw = member_references(mapping, trace)
    selected = {(resolved(name, cwd), member) for name, member in selected_raw}
    traced = {(resolved(name, cwd), member) for name, member in traced_raw}
    I.need(selected == traced and {name for name, _ in selected} <= paths,
           "Archive map/trace/dependency evidence disagrees")
    plain_trace = {resolved(line.strip(), cwd) for line in trace.decode("ascii").splitlines()
                   if _SAFE_PATH.fullmatch(line.strip())}
    I.need(plain_trace <= paths, "Trace names an input absent from the dependency file")
    return paths, selected


def archive_members(raw: bytes) -> dict[str, list[dict]]:
    """GNU ar data only; ordinals count all headers (including symbol/name tables)."""
    I.need(raw.startswith(b"!<arch>\n"), "Unsupported or thin archive")
    offset, ordinal, names = 8, 0, None
    result = {}
    while offset < len(raw):
        header = raw[offset:offset + 60]
        I.need(len(header) == 60 and header[58:] == b"`\n", "Invalid ar member header")
        size_field = header[48:58].strip()
        I.need(size_field.isdigit(), "Invalid ar member size")
        size = int(size_field)
        I.need(size <= I.MAX_FILE and offset + 60 + size <= len(raw), "Truncated ar member")
        label = header[:16].decode("ascii").rstrip()
        content = raw[offset + 60:offset + 60 + size]
        if label == "//":
            I.need(names is None, "Duplicate ar long-name table")
            names = content
        elif label not in {"/", "/SYM64/"}:
            if label.startswith("/") and label[1:].isdigit():
                start = int(label[1:])
                I.need(names is not None and 0 <= start < len(names)
                       and (start == 0 or names[start - 2:start] == b"/\n"), "Unresolved ar long name")
                end = names.find(b"/\n", start)
                I.need(end >= start, "Unterminated ar long name")
                name = names[start:end].decode("ascii")
            else:
                I.need(not label.startswith("#1/"), "BSD ar names are outside this fixed profile")
                name = label.removesuffix("/")
            I.need(re.fullmatch(r"[A-Za-z0-9_./+-]+", name) is not None, "Unsupported ar member name")
            result.setdefault(name, []).append({"name": name, "ordinal": ordinal,
                "headerOffset": offset, "size": size, "sha256": I.digest(content), "content": content})
        ordinal += 1
        offset += 60 + size
        if size % 2:
            I.need(offset < len(raw) and raw[offset:offset + 1] == b"\n", "Invalid ar padding")
            offset += 1
    I.need(offset == len(raw), "Trailing archive bytes")
    return result


def selected_members(raw: bytes, requested: set[str]) -> list[dict]:
    inventory = archive_members(raw)
    result = []
    for name in sorted(requested):
        choices = inventory.get(name, [])
        I.need(len(choices) == 1, "Missing or ambiguous selected archive member")
        result.append(choices[0])
    return result


def store_blob(root: Path, raw: bytes) -> dict:
    name = I.digest(raw)
    path = root / "objects" / name
    if path.exists():
        I.need(I.read_file(path, single_link=True) == raw and stat.S_IMODE(path.lstat().st_mode) == 0o600,
               "Retained evidence object changed")
    else:
        I.write_new(path, raw)
    return {"object": "objects/" + name, "size": len(raw), "sha256": name}


def response_tokens(raw: bytes) -> list[str]:
    """GNU documented quote/escape subset, not shell/shlex semantics.

    Quotes group text; backslash escapes the next character in or out of quotes.
    Unclosed quotes, a final backslash, non-ASCII and NUL are refused. There are
    no shell expansions or comments. Native ld still receives the original @arg.
    """
    I.need(len(raw) <= MAX_ARGUMENT_BYTES, "Response-file bound exceeded")
    text = raw.decode("ascii")
    I.need("\0" not in text, "NUL in linker response file")
    tokens, token = [], []
    quote, escaped, started = None, False, False
    for char in text:
        if escaped:
            token.append(char)
            escaped = False
        elif char == "\\":
            escaped, started = True, True
        elif quote is not None:
            if char == quote:
                quote = None
            else:
                token.append(char)
        elif char in {"'", '"'}:
            quote, started = char, True
        elif char in " \t\n\r\v\f":
            if started:
                tokens.append("".join(token))
                token, started = [], False
        else:
            token.append(char)
            started = True
    I.need(quote is None and not escaped, "Unclosed response-file quote/escape")
    if started:
        tokens.append("".join(token))
    return tokens


def expand_arguments(args: list[str], cwd: Path, root: Path, responses: list[dict], depth: int = 0) -> list[str]:
    I.need(depth <= 4 and len(responses) <= 128, "Nested response-file bound exceeded")
    expanded = []
    for arg in args:
        if arg.startswith("@"):
            path = resolved(arg[1:], cwd)
            raw = I.read_file(path, MAX_ARGUMENT_BYTES, single_link=True)
            I.need(len(responses) < 128 and sum(r["size"] for r in responses) + len(raw) <= MAX_ARGUMENT_BYTES,
                   "Total response-file bound exceeded")
            responses.append({"path": str(path), **store_blob(root, raw)})
            expanded.extend(expand_arguments(response_tokens(raw), cwd, root, responses, depth + 1))
        else:
            I.need(arg and all(32 <= ord(c) < 127 for c in arg), "Unsupported linker argument")
            expanded.append(arg)
        I.need(sum(len(a) + 1 for a in expanded) <= MAX_ARGUMENT_BYTES, "Expanded linker argv bound exceeded")
    return expanded


def output_path(args: list[str], cwd: Path) -> Path:
    outputs, operand = [], False
    for arg in args:
        option = arg.lstrip("-").partition("=")[0] if arg.startswith("-") else None
        I.need(not (option in {"M", "print-map", "cref", "t", "tt", "trace", "Map", "dependency-file"}
                    or arg.startswith("-Map")), "Recorder output flags may not be replaced")
        if operand:
            outputs.append(arg)
            operand = False
        elif arg in {"-o", "--output"}:
            operand = True
        elif arg.startswith("--output="):
            outputs.append(arg.partition("=")[2])
        else:
            # GCC in this fixed profile uses separate '-o PATH'. Do not guess
            # whether an unknown '-o...' spelling is an output or another option.
            I.need(not arg.startswith("-o"), "Unsupported concatenated -o/option spelling")
    I.need(not operand and len(outputs) <= 1, "Missing or ambiguous original output operand")
    return resolved(outputs[0] if outputs else "a.out", cwd)


def plugin_paths(args: list[str], cwd: Path) -> dict[Path, str]:
    """Retain linker plugin code and absolute plugin option paths, not as members."""
    result = {}
    operand = None
    for arg in args:
        value, role = None, None
        if operand is not None:
            value, role, operand = arg, operand, None
        elif arg in {"-plugin", "--plugin"}:
            operand = "linker-plugin"
        elif arg in {"-plugin-opt", "--plugin-opt"}:
            operand = "plugin-option-path-not-execution-proof"
        elif arg.startswith(("-plugin=", "--plugin=")):
            value, role = arg.partition("=")[2], "linker-plugin"
        elif arg.startswith(("-plugin-opt=", "--plugin-opt=")):
            value, role = arg.partition("=")[2], "plugin-option-path-not-execution-proof"
        if value is not None and (role == "linker-plugin" or value.startswith("/")):
            result[resolved(value, cwd)] = role
    I.need(operand is None, "Missing plugin option operand")
    return result


def origin(path: Path, raw: bytes, lock: dict, *, argument_only: bool = False) -> dict:
    known = lock["_origins"].get(str(path))
    if known is not None:
        I.need((len(raw), I.digest(raw)) == (known["size"], known["sha256"]), "Resolved sysroot input changed")
        return {"kind": "package", "id": known["package"], "path": str(path)}
    for component in ("cpython", "libffi", "zlib"):
        if path.is_relative_to(I.WORK / "build" / component) or path.is_relative_to(I.SOURCE_ROOT / component):
            return {"kind": "source-build", "id": component, "inputLockSha256": lock["_digest"]}
    deps = {I.WORK / "deps/lib/libz.a": "zlib", I.WORK / "deps/lib/libffi.a": "libffi"}
    if path in deps:
        return {"kind": "source-build", "id": deps[path], "inputLockSha256": lock["_digest"]}
    if path.is_relative_to(I.WORK / "tmp"):
        return {"kind": "driver-temporary", "compiler": lock["_tools"]["cc"], "inputLockSha256": lock["_digest"]}
    I.need(argument_only, "Resolved input lacks a sealed package/source origin")
    return {"kind": "unattributed-argument-only", "notEvidenceOfReadOrIncorporation": True}


def capture_failure(root: Path, link_id: str, result: dict | None) -> None:
    path = root / "CAPTURE-FAILED.json"
    if not path.exists():
        I.write_new(path, I.canonical({"schemaVersion": 1, "linkId": link_id,
                                      "originalResult": result, "reason": "original-link-capture-failed"}))


def _maybe_read(path: Path, limit: int) -> bytes | None:
    try:
        return I.read_file(path, limit)
    except FileNotFoundError:
        return None


def record(args: list[str], lock: dict) -> int:
    root, cwd = I.RECEIPTS, Path.cwd()
    I.ordinary_directory(root)
    I.need(cwd.is_relative_to(I.WORK / "build"), "Linker called outside the fixed build tree")
    I.need(not any(p.name == "CAPTURE-FAILED.json" for p in root.iterdir()),
           "Prior capture failed; no later linker invocation")
    objects = root / "objects"
    objects.mkdir(mode=0o700, exist_ok=True)
    I.ordinary_directory(objects)
    numbers = [int(p.name[5:]) for p in root.iterdir() if re.fullmatch(r"link-[0-9]{6}", p.name)]
    I.need(sorted(numbers) == list(range(len(numbers))), "Missing original link receipt directory")
    number = len(numbers)
    I.need(number < MAX_LINKS, "Link receipt count bound exceeded")
    link_id = f"link-{number:06d}"
    directory = root / link_id
    directory.mkdir(mode=0o700)  # A collision fails, never retries/replaces.
    result = None
    try:
        original = b"".join(os.fsencode(a) + b"\0" for a in args)
        I.need(len(original) <= MAX_ARGUMENT_BYTES, "Original linker argv bound exceeded")
        I.write_new(directory / "original.argv", original)
        responses = []
        expanded = expand_arguments(args, cwd, root, responses)
        expanded_raw = b"".join(a.encode("ascii") + b"\0" for a in expanded)
        I.write_new(directory / "expanded.argv", expanded_raw)
        query = tuple(expanded) in _QUERIES
        output = None if query else output_path(expanded, cwd)
        plugins = {} if query else plugin_paths(expanded, cwd)
        before = None if output is None else _maybe_read(output, I.MAX_FILE)
        before_record = {"available": False, "reason": "absent-before-link"} if before is None else {
            "available": True, "retained": store_blob(root, before)}
        # Keep original response operands for native ld; expansion is analysis,
        # never an attempt to replace native parsing with a different command.
        effective = list(args) if query else [*args, "-Map=" + str(directory / "map"), "--cref",
            "-t", "-t", "--dependency-file=" + str(directory / "deps")]
        effective_raw = b"".join(os.fsencode(a) + b"\0" for a in effective)
        I.write_new(directory / "effective.argv", effective_raw)
        environment = I.canonical(dict(sorted(os.environ.items())))
        I.need(len(environment) <= MAX_ARGUMENT_BYTES, "Link environment bound exceeded")
        I.write_new(directory / "environment.json", environment)
        linker_record = next(t["file"] for t in lock["tools"] if t["role"] == "ld")
        I.verify_file(linker_record)
        with (directory / "stdout").open("xb") as stdout, (directory / "stderr").open("xb") as stderr:
            os.fchmod(stdout.fileno(), 0o600)
            os.fchmod(stderr.fileno(), 0o600)
            # The only native invocation in this module; inert tests never call record().
            status = subprocess.run([linker_record["path"], *effective], cwd=cwd,
                                    env=dict(os.environ), stdout=stdout, stderr=stderr, check=False).returncode
        result = original_result(status)
        I.write_new(directory / "original-result.json", I.canonical({"linkId": link_id, "result": result}))
        for response in responses:
            I.need(I.digest(I.read_file(Path(response["path"]), MAX_ARGUMENT_BYTES, single_link=True)) == response["sha256"],
                   "Response file changed during native link")
        out = I.read_file(directory / "stdout", MAX_DIAGNOSTIC)
        err = I.read_file(directory / "stderr", MAX_DIAGNOSTIC)
        mapping = None if query else _maybe_read(directory / "map", MAX_DIAGNOSTIC)
        dependency = None if query else _maybe_read(directory / "deps", MAX_DIAGNOSTIC)
        binary = None if output is None else _maybe_read(output, I.MAX_FILE)
        records = {"map": artifact(mapping, failed=status != 0, query=query),
                   "deps": artifact(dependency, failed=status != 0, query=query),
                   "output": artifact(binary, failed=status != 0, query=query)}
        records["output"]["observation"] = output_observation(binary, before, status, query=query)
        paths, selected, complete = set(), set(), not query
        if not query:
            try:
                I.need(mapping is not None and dependency is not None, "Original failed link left partial evidence")
                paths, selected = reconcile(mapping, dependency, out, output, cwd)
            except (I.InputError, UnicodeError):
                if status == 0:
                    raise
                complete = False  # C2: unavailable/partial failed-link artifacts are not fabricated.
                # Still retain independently parseable partial dependencies and
                # selected members. Failure to retain those bytes remains fatal.
                if dependency is not None:
                    try:
                        _, names = dep_inputs(dependency)
                        paths = {resolved(name, cwd) for name in names}
                    except (I.InputError, UnicodeError):
                        pass
                if mapping is not None:
                    try:
                        members, _ = member_references(mapping, b"")
                        selected = {(resolved(name, cwd), member) for name, member in members}
                        paths.update(name for name, _ in selected)
                    except (I.InputError, UnicodeError):
                        pass
        # A positional-looking argument is merely a candidate, not proof ld read
        # or incorporated it. Plugin code is retained separately even if GNU ld
        # omits it from its depfile. The complete original argv remains available.
        candidates = {resolved(arg, cwd) for arg in expanded
                      if not arg.startswith("-") and _SAFE_PATH.fullmatch(arg)}
        candidates = {path for path in candidates if path != output and path.is_file()}
        inputs, process_files = [], []
        for path in sorted(paths | candidates | set(plugins)):
            raw = _maybe_read(path, I.MAX_FILE)
            if raw is None and path in plugins and status != 0 and path not in paths:
                process_files.append({"path": str(path), "role": plugins[path],
                                      "available": False, "reason": "original-link-failed"})
                continue
            I.need(raw is not None, "An observed input could not be retained")
            if path in plugins:
                process_files.append({"path": str(path), "role": plugins[path], "available": True,
                    "origin": origin(path, raw, lock), "retained": store_blob(root, raw),
                    "notAnIncorporatedArchiveMember": True})
                I.need(path not in {name for name, _ in selected}, "Plugin/member role collision")
                if path not in paths:
                    continue
            I.need(not raw.startswith(b"!<thin>\n"), "Thin archive is outside this fixed profile")
            selected_names = {member for name, member in selected if name == path}
            members = selected_members(raw, selected_names) if selected_names else []
            retained_members = [{k: v for k, v in member.items() if k != "content"} |
                                {"retained": store_blob(root, member["content"])} for member in members]
            role = ("archive" if raw.startswith(b"!<arch>\n") else "elf-input" if raw.startswith(b"\x7fELF")
                    else "linker-script-or-argument-data")
            inputs.append({"path": str(path), "role": role, "observedRead": path in paths,
                "origin": origin(path, raw, lock, argument_only=path not in paths),
                "retained": store_blob(root, raw), "selectedMembers": retained_members})
        for key, raw in (("map", mapping), ("deps", dependency), ("output", binary)):
            if raw is not None:
                records[key]["retained"] = store_blob(root, raw)
        receipt = {"schemaVersion": 1, "inputLockSha256": lock["_digest"], "linkId": link_id,
            "phase": os.environ["MRK_PHASE"], "kind": "query" if query else "linked" if status == 0 else "link-failed",
            "originalResult": result, "originalArgvSha256": I.digest(original),
            "effectiveArgvSha256": I.digest(effective_raw), "expandedArgvSha256": I.digest(expanded_raw),
            "cwd": str(cwd), "environmentSha256": I.digest(environment), "responseFiles": responses,
            "linkerSha256": linker_record["sha256"], "stdout": store_blob(root, out), "stderr": store_blob(root, err),
            "analysisComplete": complete, "artifacts": records, "inputs": inputs, "processFiles": process_files,
            "outputPath": str(output) if output else None, "beforeLinkOutput": before_record}
        I.write_new(directory / "receipt.json", I.canonical(receipt))
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
        sys.stderr.buffer.write(err)
        sys.stderr.buffer.flush()
        # Preserve nonzero exits. Signals remain distinct in originalResult;
        # the shell-facing wrapper status is the conventional 128 + signal.
        return status if status >= 0 else 128 - status
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        capture_failure(root, link_id, result)
        raise I.InputError("Link capture failed; original evidence and workspace retained") from None


def main() -> None:
    try:
        lock = I.load_lock(I.absolute(os.environ["MRK_LOCK"]), I.sha(os.environ["MRK_LOCK_SHA256"]),
                           verify_inputs=False)
        I.need(os.environ.get("MRK_PHASE") in I.PHASES, "Linker called outside the fixed recipe phases")
        I.need(os.environ.get("PYTHONSTRICTEXTENSIONBUILD") == "1", "Strict extension build flag changed")
        code = record(sys.argv[1:], lock)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        try:
            capture_failure(I.RECEIPTS, "unregistered", None)  # Never overwrites an earlier original result.
        except (OSError, ValueError):
            pass
        print("Publisher linker capture refused; retain the original workspace", file=sys.stderr)
        code = 125
    raise SystemExit(code)


if __name__ == "__main__":
    main()
