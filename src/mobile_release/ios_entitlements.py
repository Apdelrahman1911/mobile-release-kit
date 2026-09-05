"""Complete, typed iOS signed-claim comparison with bounded profile grants.

No application code, credentials or Store mutations belong here. Comparing
claims is distinct from authenticating the profile's Apple issuer and signature.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .errors import ValidationError
from .inspection import InspectionDeadline

MAX_PLIST_BYTES = 4 * 1024 * 1024
MAX_VALUE_NODES = 100_000
MAX_VALUE_DEPTH = 64
MAX_IDENTIFIER_BYTES = 4096
MAX_XML_TAG_BYTES = 8192
XML_WHITESPACE = " \t\r\n"
XML_TEXT_TOKEN = re.compile(r"[<&]")
XML_REFERENCES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}
PREFIX_ARRAY_KEYS = frozenset({
    "keychain-access-groups", "com.apple.developer.icloud-container-identifiers",
    "com.apple.developer.ubiquity-container-identifiers",
    "com.apple.developer.icloud-container-development-container-identifiers",
})
EXACT_IDENTIFIER_ARRAY_KEYS = frozenset({
    "com.apple.security.application-groups", "com.apple.developer.in-app-payments",
})
DOMAIN_KEY = "com.apple.developer.associated-domains"
SERVICES_KEY = "com.apple.developer.icloud-services"
KVSTORE_KEY = "com.apple.developer.ubiquity-kvstore-identifier"


def _require(condition: bool, message: str) -> None:
    if not condition:
        # Never include profile/entitlement values or native command output.
        raise ValidationError(message)


def typed_value(value: Any, *, deadline: InspectionDeadline | None = None) -> Any:
    """Canonical hashable value without Python's bool/int equality ambiguity."""
    deadline = deadline if deadline is not None else InspectionDeadline()
    remaining, active = MAX_VALUE_NODES, set()

    def convert(item: Any, depth: int) -> Any:
        nonlocal remaining
        deadline.check()
        remaining -= 1
        _require(depth <= MAX_VALUE_DEPTH and remaining >= 0, "iOS plist complexity exceeds its bound")
        if isinstance(item, dict) or type(item) is list:
            identity = id(item)
            _require(identity not in active, "iOS plist contains a cyclic value")
            active.add(identity)
            try:
                if isinstance(item, dict):
                    _require(all(type(key) is str for key in item), "iOS plist dictionary key is invalid")
                    return ("dict", tuple((key, convert(val, depth + 1)) for key, val in sorted(item.items())))
                return ("list", tuple(convert(val, depth + 1) for val in item))
            finally:
                active.remove(identity)
        _require(type(item) in {str, bytes, int, bool, float, datetime}, "iOS plist contains an unsupported value type")
        _require(type(item) is not float or math.isfinite(item), "iOS plist contains a nonfinite value")
        if type(item) is float:
            # Python equality collapses signed zero; native real values do not.
            return ("float", item.hex())
        if type(item) is datetime:
            item = item.replace(tzinfo=timezone.utc) if item.tzinfo is None else item.astimezone(timezone.utc)
        return (type(item).__name__, item)

    try:
        return convert(value, 0)
    except (ValueError, OverflowError, RecursionError) as error:
        raise ValidationError("iOS plist contains invalid typed values") from error


@dataclass
class _XMLFrame:
    tag: str
    values: list[Any] = field(default_factory=list)
    content_start: int = 0


def _literal_xml_opening(data: bytes, offset: int, tag: str, encoding: str) -> int:
    # Expat can silently remove an undeclared entity from an attribute under
    # an external DTD, without a SkippedEntityHandler callback. The only
    # supported attribute is a literal root version; check the ORIGINAL bytes.
    terminator = ">".encode(encoding)
    end = data.find(terminator, offset, offset + MAX_XML_TAG_BYTES)
    label = "root tag" if tag == "plist" else "opening tag"
    _require(end >= 0 and (end - offset) % len(terminator) == 0,
             f"iOS XML plist {label} is unsupported or exceeds its bound")
    end += len(terminator)
    opening = data[offset:end].decode(encoding, errors="strict")
    grammar = (r'''<plist(?:[ \t\r\n]+version[ \t\r\n]*=[ \t\r\n]*(?:"1\.0"|'1\.0'))?[ \t\r\n]*/?>'''
               if tag == "plist" else rf"<{tag}[ \t\r\n]*/?>")
    _require(re.fullmatch(grammar, opening) is not None,
             "iOS XML plist requires literal supported opening tags and root version")
    _require(tag != "data" or not opening.endswith("/>"),
             "iOS XML plist data requires an explicit closing tag, including empty data")
    return end


def _xml_text(text: str, *, deadline: InspectionDeadline) -> str:
    """Decode supported text once, preserving Apple's literal CR/CRLF semantics."""
    parts, position = [], 0
    while position < len(text):
        deadline.check()
        marker = XML_TEXT_TOKEN.search(text, position)
        if marker is None:
            parts.append(text[position:])
            break
        start = marker.start()
        parts.append(text[position:start])
        if text.startswith("<![CDATA[", start):
            end = text.find("]]>", start + 9)
            _require(end >= 0, "iOS XML plist has incomplete text markup")
            parts.append(text[start + 9:end])
            position = end + 3
            continue
        _require(text[start] == "&", "iOS XML plist has unsupported text markup")
        end = text.find(";", start + 1)
        _require(end >= 0, "iOS XML plist has an incomplete text reference")
        reference = text[start + 1:end]
        if reference in XML_REFERENCES:
            value = XML_REFERENCES[reference]
        else:
            hexadecimal = reference.startswith("#x")
            digits = reference[2:] if hexadecimal else reference[1:]
            _require(reference.startswith("#") and re.fullmatch(r"[0-9a-fA-F]+" if hexadecimal else r"[0-9]+", digits) is not None,
                     "iOS XML plist has an unsupported text reference")
            _require(len(digits) <= 8, "iOS XML plist numeric reference spelling exceeds its bound")
            # Leading zeros do not need a huge Python integer conversion.
            digits = digits.lstrip("0") or "0"
            _require(len(digits) <= (6 if hexadecimal else 7), "iOS XML plist reference is out of range")
            codepoint = int(digits, 16 if hexadecimal else 10)
            _require(codepoint in {9, 10, 13} or 0x20 <= codepoint <= 0xD7FF or
                     0xE000 <= codepoint <= 0xFFFD or 0x10000 <= codepoint <= 0x10FFFF,
                     "iOS XML plist reference is not an XML character")
            value = chr(codepoint)
        parts.append(value)
        position = end + 1
    deadline.check()
    return "".join(parts)


def _load_xml_dictionary(data: bytes, *, dictionary_type: type[dict], deadline: InspectionDeadline) -> dict[str, Any]:
    """Decode one complete supported plist; never ignore unrecognized structure."""
    import base64
    from xml.parsers import expat

    values = {"dict", "array", "string", "integer", "real", "true", "false", "data", "date"}
    containers = {"plist", "dict", "array"}
    encoding = "utf-16-le" if data.startswith(b"\xff\xfe") else "utf-16-be" if data.startswith(b"\xfe\xff") else "utf-8"
    frames: list[_XMLFrame] = []
    nodes, root = 0, None
    parser = expat.ParserCreate()
    # Unbuffered callbacks expose the original reference offset in container
    # trivia. Primitive values come from original spans, NEVER normalized text.
    parser.buffer_text = False
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)

    def start(tag: str, attributes: dict[str, str]) -> None:
        nonlocal nodes
        deadline.check()
        nodes += 1
        _require(nodes <= MAX_VALUE_NODES and len(frames) <= MAX_VALUE_DEPTH + 1,
                 "iOS XML plist complexity exceeds its bound")
        if not frames:
            _require(root is None and tag == "plist" and attributes in ({}, {"version": "1.0"}),
                     "iOS XML plist must contain one supported dictionary root")
        else:
            parent = frames[-1]
            _require(not attributes, "iOS XML plist value attributes are unsupported")
            if parent.tag == "plist":
                allowed = not parent.values and tag == "dict"
            elif parent.tag == "dict":
                allowed = tag == "key" if len(parent.values) % 2 == 0 else tag in values
            elif parent.tag == "array":
                allowed = tag in values
            else:
                allowed = False
            _require(allowed, "iOS XML plist has an unsupported or misplaced element")
        content_start = _literal_xml_opening(data, parser.CurrentByteIndex, tag, encoding)
        frame = _XMLFrame(tag)
        frame.content_start = content_start
        frames.append(frame)

    def characters(text: str) -> None:
        deadline.check()
        if not frames or frames[-1].tag in containers:
            _require(all(char in XML_WHITESPACE for char in text) and
                     not data.startswith("&".encode(encoding), parser.CurrentByteIndex),
                     "iOS XML plist container text must be literal whitespace")
        elif frames[-1].tag in {"true", "false"}:
            _require(not text, "iOS XML plist Boolean must not contain text")

    def comment(_text: str) -> None:
        deadline.check()
        _require(not frames or frames[-1].tag in containers,
                 "iOS XML plist comments are unsupported inside primitives or keys")

    def cdata() -> None:
        deadline.check()
        _require(bool(frames) and frames[-1].tag in {"string", "key", "real"},
                 "iOS XML plist CDATA is unsupported in this element")

    def end(tag: str) -> None:
        nonlocal root
        deadline.check()
        frame = frames.pop()
        text = ""
        if tag not in containers:
            _require(frame.content_start <= parser.CurrentByteIndex, "iOS XML plist content span is invalid")
            text = data[frame.content_start:parser.CurrentByteIndex].decode(encoding, errors="strict")
            if tag in {"string", "key", "real"}:
                text = _xml_text(text, deadline=deadline)
            else:
                _require("<" not in text and "&" not in text,
                         "iOS XML plist primitive requires literal content without references or markup")
        if tag == "plist":
            _require(len(frame.values) == 1, "iOS XML plist must contain one dictionary root")
            result = frame.values[0]
        elif tag == "dict":
            _require(len(frame.values) % 2 == 0, "iOS XML plist dictionary has a key without a value")
            result = dictionary_type()
            for index in range(0, len(frame.values), 2):
                deadline.check()
                result[frame.values[index]] = frame.values[index + 1]
        elif tag == "array":
            result = frame.values
        elif tag in {"key", "string"}:
            result = text
        elif tag in {"true", "false"}:
            _require(not text, "iOS XML plist Boolean must have an empty literal body")
            result = tag == "true"
        elif tag == "integer":
            hexadecimal = re.fullmatch(r"[+-]?0[xX][0-9a-fA-F]+", text) is not None
            _require(len(text) <= 128 and (hexadecimal or re.fullmatch(r"[+-]?[0-9]+", text) is not None),
                     "iOS XML plist integer syntax is invalid")
            result = int(text, 16 if hexadecimal else 10)
            _require(-(1 << 63) <= result < (1 << 64), "iOS XML plist integer exceeds its range")
        elif tag == "real":
            _require(len(text) <= 128 and re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", text) is not None,
                     "iOS XML plist real syntax is invalid")
            result = float(text)
            _require(math.isfinite(result), "iOS XML plist real must be finite")
        elif tag == "date":
            match = re.fullmatch(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z", text)
            _require(match is not None, "iOS XML plist date must be an exact UTC datetime")
            result = datetime(*(int(item) for item in match.groups()), tzinfo=timezone.utc)
        elif tag == "data":
            encoded = "".join(char for char in text if char not in XML_WHITESPACE).encode("ascii")
            result = base64.b64decode(encoded, validate=True)
            _require(base64.b64encode(result) == encoded, "iOS XML plist data must use canonical padded base64")
        else:
            raise ValidationError("iOS XML plist has an unsupported value")
        if frames:
            frames[-1].values.append(result)
        else:
            root = result

    def doctype(name: str, system: str | None, public: str | None, internal: bool) -> None:
        deadline.check()
        # Current dsymutil still emits the Apple Computer public identifier.
        _require(name == "plist" and not internal and
                 public in {"-//Apple//DTD PLIST 1.0//EN", "-//Apple Computer//DTD PLIST 1.0//EN"} and
                 system in {"http://www.apple.com/DTDs/PropertyList-1.0.dtd", "https://www.apple.com/DTDs/PropertyList-1.0.dtd"},
                 "iOS XML plist declaration is unsupported")

    def reject_feature(*_args: Any) -> None:
        raise ValidationError("iOS XML plist declarations, skipped entities and external references are unsupported")

    def declaration(version: str, declared: str | None, _standalone: int) -> None:
        deadline.check()
        _require(version == "1.0", "iOS XML version is unsupported")
        if declared is not None:
            allowed = {encoding.replace("16-", "16"), "utf-16"} if encoding.startswith("utf-16") else {"utf-8"}
            _require(declared.lower() in allowed, "iOS XML plist encoding requires consistent UTF-8 or BOM-bearing UTF-16")

    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.CharacterDataHandler, parser.StartDoctypeDeclHandler = characters, doctype
    parser.CommentHandler, parser.StartCdataSectionHandler = comment, cdata
    parser.XmlDeclHandler = declaration
    parser.EntityDeclHandler = parser.UnparsedEntityDeclHandler = reject_feature
    parser.ExternalEntityRefHandler = parser.SkippedEntityHandler = reject_feature
    parser.NotationDeclHandler = parser.ProcessingInstructionHandler = reject_feature
    parser.Parse(data, True)
    deadline.check()
    _require(isinstance(root, dict) and not frames, "iOS XML plist root must be a complete dictionary")
    return root


def load_plist_dictionary(data: bytes, *, deadline: InspectionDeadline | None = None) -> dict[str, Any]:
    # Lazy imports preserve Android-only operation without an XML parser import.
    import plistlib
    from xml.parsers.expat import ExpatError

    from .ios_plist_binary import validate_binary_dictionary

    class UniqueDictionary(dict):
        def __setitem__(self, key: Any, item: Any) -> None:
            _require(type(key) is str and key not in self, "iOS plist has a duplicate or invalid dictionary key")
            super().__setitem__(key, item)

    deadline = deadline if deadline is not None else InspectionDeadline()
    deadline.check()
    _require(type(data) is bytes and 0 < len(data) <= MAX_PLIST_BYTES, "iOS plist size exceeds its bound or is empty")
    try:
        if data.startswith(b"bplist00"):
            validate_binary_dictionary(data, deadline=deadline, max_nodes=MAX_VALUE_NODES, max_depth=MAX_VALUE_DEPTH)
        result = (plistlib.loads(data, dict_type=UniqueDictionary) if data.startswith(b"bplist00") else
                  _load_xml_dictionary(data, dictionary_type=UniqueDictionary, deadline=deadline))
        _require(isinstance(result, dict), "iOS plist root must be a dictionary")
        typed_value(result, deadline=deadline)
        return result
    except (ValueError, TypeError, LookupError, AttributeError, OverflowError, RecursionError, plistlib.InvalidFileException, ExpatError) as error:
        raise ValidationError("iOS plist is malformed or exceeds its bounds") from error


def correlate_profile(outer: dict[str, Any], authoritative: dict[str, Any], *,
                      deadline: InspectionDeadline | None = None) -> dict[str, Any]:
    """Bind used outer fields/certificate bytes to the modern DER profile content.

    Neither CMS decoding nor this equality check authenticates an Apple issuer.
    """
    deadline = deadline if deadline is not None else InspectionDeadline()
    left = dict(typed_value(outer, deadline=deadline)[1])
    right = dict(typed_value(authoritative, deadline=deadline)[1])
    required = {"Entitlements", "TeamIdentifier", "UUID", "CreationDate", "ExpirationDate"}
    optional = {"ProvisionedDevices", "ProvisionsAllDevices"}
    _require(required <= left.keys() and required <= right.keys(), "modern provisioning profile lacks required authoritative fields")
    _require(all(left.get(key) == right.get(key) for key in required | optional),
             "provisioning profile outer and authoritative DER security fields differ")
    certificates, digests = outer.get("DeveloperCertificates"), authoritative.get("DeveloperCertificates")
    _require(type(certificates) is list and bool(certificates) and
             all(type(item) is bytes and bool(item) for item in certificates) and
             type(digests) is list and bool(digests) and
             all(type(item) is bytes and len(item) == 32 for item in digests),
             "modern provisioning profile developer certificate binding is invalid")
    _require(sorted(hashlib.sha256(item).digest() for item in certificates) == sorted(digests),
             "provisioning profile certificates differ from authoritative DER digests")
    result = dict(authoritative)
    result["DeveloperCertificates"] = certificates
    return result


def _string(value: Any) -> bool:
    return type(value) is str and 0 < len(value.encode("utf-8")) <= MAX_IDENTIFIER_BYTES and not any(
        ord(char) < 32 or ord(char) == 127 for char in value
    )


def _identifier(value: Any) -> bool:
    return _string(value) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", value) is not None


def _prefix_authorization(claims: list[str], grants: list[str], *, deadline: InspectionDeadline) -> bool:
    # An explicit trie bounds wildcard work by the total string length. Do not
    # perform a claims-by-grants scan or interpret shell glob syntax.
    exact, prefixes = set(), {}
    for grant in grants:
        deadline.check()
        if "*" not in grant:
            if not _identifier(grant):
                return False
            exact.add(grant)
        else:
            if not (grant.endswith(".*") and grant.count("*") == 1 and _identifier(grant[:-2])):
                return False
            cursor = prefixes
            for char in grant[:-1]:
                cursor = cursor.setdefault(char, {})
            cursor[None] = True
    for claim in claims:
        deadline.check()
        if not _identifier(claim):
            return False
        if claim in exact:
            continue
        cursor, matched = prefixes, False
        for index, char in enumerate(claim):
            if char not in cursor:
                break
            cursor = cursor[char]
            if None in cursor and index + 1 < len(claim):
                matched = True
                break
        if not matched:
            return False
    return True


def validate_profile_entitlements(application: dict[str, Any], grants: dict[str, Any], *,
                                  deadline: InspectionDeadline | None = None) -> None:
    """Require every signed claim to fit the profile's typed allowlist.

    Unknown compound values are exact, not speculative recursive permission
    subsets. Only documented keys get wildcard/scalar-to-array interpretation.
    """
    deadline = deadline if deadline is not None else InspectionDeadline()
    _require(isinstance(application, dict) and isinstance(grants, dict), "signed entitlements and profile grants must be dictionaries")
    claims_typed = dict(typed_value(application, deadline=deadline)[1])
    grants_typed = dict(typed_value(grants, deadline=deadline)[1])
    for key, claim in application.items():
        deadline.check()
        # Names are not echoed either: a malicious dictionary key can contain
        # credential-looking text or log controls. The next action is stable.
        failure = "signed entitlement is not authorized by the embedded profile; check capability/profile grants"
        _require(key in grants, failure)
        grant = grants[key]
        if key == "get-task-allow":
            _require(claim is False and grant is False, "signed app/profile permits debugger attachment or has an invalid debugger flag")
        elif key in {"application-identifier", "com.apple.developer.team-identifier"}:
            _require(_identifier(claim) and _identifier(grant) and claim == grant, failure)
        elif key in {"aps-environment", "com.apple.developer.icloud-container-environment"}:
            expected = "production" if key == "aps-environment" else "Production"
            allowed = type(grant) is str and grant == expected
            if key != "aps-environment" and type(grant) is list:
                allowed = bool(grant) and all(_string(item) for item in grant) and expected in grant
            _require(type(claim) is str and claim == expected and allowed,
                     "signed app/profile entitlement must use the production environment")
        elif key == KVSTORE_KEY:
            _require(_string(claim) and _string(grant) and
                     _prefix_authorization([claim], [grant], deadline=deadline), failure)
        elif key in PREFIX_ARRAY_KEYS | EXACT_IDENTIFIER_ARRAY_KEYS | {DOMAIN_KEY, SERVICES_KEY}:
            _require(type(claim) is list and bool(claim) and all(_string(item) for item in claim), failure)
            if key in {DOMAIN_KEY, SERVICES_KEY}:
                _require(all(item != "*" for item in claim), failure)
                if key == SERVICES_KEY:
                    _require(set(claim) <= {"CloudKit", "CloudDocuments"}, failure)
                if grant == "*":
                    continue
            _require(type(grant) is list and all(_string(item) for item in grant), failure)
            if key in PREFIX_ARRAY_KEYS:
                _require(_prefix_authorization(claim, grant, deadline=deadline), failure)
            else:
                if key in EXACT_IDENTIFIER_ARRAY_KEYS:
                    _require(all(_identifier(item) for item in claim + grant), failure)
                _require((key in {DOMAIN_KEY, SERVICES_KEY} and "*" in grant) or set(claim) <= set(grant), failure)
        elif type(claim) is list:
            _require(type(grant) is list, failure)
            _require(set(claims_typed[key][1]) <= set(grants_typed[key][1]), failure)
        else:
            _require(claims_typed[key] == grants_typed[key], failure)
