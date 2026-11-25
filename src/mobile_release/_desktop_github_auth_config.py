"""Closed schema-one recognizer, NOT a general YAML parser or config writer.

Stock gh 2.88.1 migrates before even --version. Its go-gh v2.13.0 loader
reads config.yml as the root map and adds hosts.yml only beneath ``hosts``;
Get(["version"]) returns the scalar node's Value. Accept only the ordinary
single-document options/aliases subset below, with one unambiguous root 1.
Legacy, complex or unknown configuration needs manual attention, never a gh
probe/migration here. Input is actual held private bytes; nothing is logged.
Keep this finite grammar identical to github_auth_config.rs.
"""
from __future__ import annotations

ROOT_KEYS = (b"version", b"git_protocol", b"editor", b"prompt", b"prefer_editor_prompt", b"pager",
             b"aliases", b"http_unix_socket", b"browser", b"color_labels", b"accessible_colors",
             b"accessible_prompter", b"spinner")
MAX_BYTES, MAX_LINES, MAX_ALIASES = 65536, 256, 64


def _scalar(raw: bytes) -> bytes | None:
    raw = raw.strip(b" ")
    if not raw or raw.startswith(b"#"):
        return b""
    if raw[0] in (34, 39):
        quote = raw[:1]
        end = raw.find(quote, 1)
        if end < 0:
            return None
        tail = raw[end + 1:]
        if tail and (not tail.startswith(b" ") or not tail.strip(b" ").startswith(b"#")):
            return None
        # No escapes/embedded quotes: the upstream scalar Value is these exact
        # bytes, not an independently interpreted Unicode/YAML expression.
        value = raw[1:end]
        return None if b"\\" in value or b"'" in value or b'"' in value else value
    value = raw.split(b" #", 1)[0].rstrip(b" ")
    if not value or any(not (48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122 or c in b" _./=+-") for c in value):
        return None
    # YAML indicators cannot start a plain scalar in this supported subset.
    return None if value[:1] in (b"-", b"+") else value


def schema_one(raw: bytes | bytearray) -> bool:
    if type(raw) not in (bytes, bytearray) or not 0 < len(raw) <= MAX_BYTES:
        return False
    if any(c not in (10, 13) and not 32 <= c <= 126 for c in raw):
        return False
    rows = raw.split(b"\n")
    if len(rows) > MAX_LINES:
        return False
    roots, aliases = set(), set()
    in_aliases, alias_indent, found = False, None, False
    for row in rows:
        row = bytes(row.removesuffix(b"\r"))
        if b"\r" in row:
            return False
        text = row.lstrip(b" ")
        if not text or text.startswith(b"#"):
            continue
        indent = len(row) - len(text)
        key, separator, rest = text.partition(b":")
        if not separator or rest and not rest.startswith(b" "):
            return False
        if indent == 0:
            if key not in ROOT_KEYS or key in roots:
                return False
            roots.add(key)
            in_aliases, alias_indent = key == b"aliases", None
        else:
            if not in_aliases or indent not in (2, 4) or alias_indent not in (None, indent):
                return False
            alias_indent = indent
            if not 0 < len(key) <= 64 or any(not (48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122 or c in b"_-") for c in key):
                return False
            if key in aliases or len(aliases) >= MAX_ALIASES:
                return False
            aliases.add(key)
        value = _scalar(rest)
        if value is None:
            return False
        if indent == 0 and key == b"aliases":
            # Only a real empty/null entry may introduce the nested map.
            if rest.strip(b" ") and not rest.strip(b" ").startswith(b"#"):
                return False
        if indent == 0 and key == b"version":
            if value != b"1":
                return False
            found = True
    return found
