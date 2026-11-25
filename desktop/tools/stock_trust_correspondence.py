"""Command-free correspondence for one authenticated public Ubuntu CA set.

Not a general keystore reader, certificate verifier, native admission, or proof
of historical producer execution. Callers own protected original acquisition,
final rebind/close and deadlines. Import performs no I/O.
"""
import base64
import binascii
import hashlib
import hmac
import json
import struct


POLICY_FILE = "ubuntu_stock_ca_policy.json"
POLICY_SHA256 = "633273a983d53a4a493b96d949f35f2a82bcd9752f0239bb7e8f62e8d4c70f5c"
POLICY_LIMIT = 64 << 10
COUNT = 121
DER_LIMIT = 16 << 10
PEM_LIMIT = 4 << 20
JKS_LIMIT = 8 << 20
CONFIG_LIMIT = 256 << 10


class Refused(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


class Cursor:
    """Bounded byte DATA; no original handles or native operations."""

    def __init__(self, raw):
        self.raw, self.offset = raw, 0

    def take(self, count):
        need(0 <= count <= len(self.raw) - self.offset, "stock-jks-framing")
        start = self.offset
        self.offset += count
        return self.raw[start:self.offset]

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def text(self):
        count = struct.unpack(">H", self.take(2))[0]
        need(0 < count <= 128, "stock-jks-encoding")
        try:
            value = self.take(count).decode("utf-8", errors="strict")
        except UnicodeError:
            raise Refused("stock-jks-encoding") from None
        # Canonical UTF-8 equals Java modified-UTF-8 on this fixed alphabet.
        # In particular NUL/overlong NUL, surrogates and astral forms are absent.
        need(all(32 <= ord(c) < 127 or c in "őúíá" for c in value), "stock-jks-encoding")
        return value


class Policy:
    def __init__(self, raw):
        need(type(raw) is bytes and 0 < len(raw) <= POLICY_LIMIT
             and hashlib.sha256(raw).hexdigest() == POLICY_SHA256, "stock-policy")
        value = json.loads(raw.decode("utf-8"))
        need(value["schema"] == "mrk-ubuntu-stock-ca-policy-v1"
             and value["certificateCount"] == COUNT and len(value["certificates"]) == COUNT,
             "stock-policy")
        self.names, self.aliases, self.anchors = {}, {}, {}
        for row in value["certificates"]:
            name, alias, digest, size = row["name"], row["jksAlias"], row["derSha256"], row["derBytes"]
            need(name not in self.names and alias not in self.aliases and digest not in self.anchors
                 and type(size) is int and 0 < size <= DER_LIMIT, "stock-policy")
            self.names[name] = digest
            self.aliases[alias] = digest
            self.anchors[digest] = size

    def summary(self, component):
        need(component in {"pem", "jks", "config", "complete"}, "stock-correspondence")
        return {"policySha256": POLICY_SHA256, "certificateCount": COUNT,
                "component": component, "contentCorrespondence": True,
                "producerExecutionProven": False}

    def certificate(self, der, seen, expected=None):
        need(type(der) is bytes and 0 < len(der) <= DER_LIMIT, "stock-der")
        digest = hashlib.sha256(der).hexdigest()
        need(self.anchors.get(digest) == len(der) and digest not in seen
             and (expected is None or expected == digest), "stock-der")
        seen.add(digest)

    def pem(self, raw, point):
        point()
        need(type(raw) is bytes and 0 < len(raw) <= PEM_LIMIT, "stock-pem-bound")
        lines = raw.split(b"\n")
        need(len(lines) <= 32768, "stock-pem-bound")
        active, parts, encoded_size, seen = False, [], 0, set()
        for line in lines:
            point()
            if line == b"-----BEGIN CERTIFICATE-----":
                need(not active and len(seen) < COUNT, "stock-pem-framing")
                active, parts, encoded_size = True, [], 0
            elif line == b"-----END CERTIFICATE-----":
                need(active and parts, "stock-pem-framing")
                encoded = b"".join(parts)
                try:
                    der = base64.b64decode(encoded, validate=True)
                except (ValueError, binascii.Error):
                    raise Refused("stock-pem-framing") from None
                # Compare a re-encoding of unchanged DER, never reserialize X.509.
                need(base64.b64encode(der) == encoded, "stock-pem-framing")
                self.certificate(der, seen)
                active = False
            elif active:
                need(0 < len(line) <= 80, "stock-pem-framing")
                encoded_size += len(line)
                need(encoded_size <= 4 * ((DER_LIMIT + 2) // 3), "stock-pem-bound")
                parts.append(line)
            else:
                need(line == b"", "stock-pem-framing")
        need(not active and seen == self.anchors.keys(), "stock-complete-set")
        point()
        return self.summary("pem")

    def jks(self, raw, point):
        point()
        need(type(raw) is bytes and 32 <= len(raw) <= JKS_LIMIT, "stock-jks-framing")
        cursor = Cursor(raw[:-20])
        need(cursor.u32() == 0xFEEDFEED and cursor.u32() == 2 and cursor.u32() == COUNT,
             "stock-jks-framing")
        seen, aliases = set(), set()
        for _ in range(COUNT):
            point()
            need(cursor.u32() == 2, "stock-jks-framing")  # Trusted certificates only; never keys.
            alias = cursor.text()
            need(alias in self.aliases and alias not in aliases, "stock-jks-alias")
            aliases.add(alias)
            cursor.take(8)  # Timestamp is opaque metadata, never trust authority.
            need(cursor.text() == "X.509", "stock-jks-framing")
            size = cursor.u32()
            need(0 < size <= DER_LIMIT, "stock-jks-framing")
            self.certificate(cursor.take(size), seen, self.aliases[alias])
        need(cursor.offset == len(cursor.raw) and aliases == self.aliases.keys()
             and seen == self.anchors.keys(), "stock-complete-set")
        point()
        # Standard public system-store password, not a private signing credential.
        # This checksum proves consistency only. The pinned DER set is authority.
        digest = hashlib.sha1("changeit".encode("utf-16be") + b"Mighty Aphrodite" + cursor.raw).digest()
        need(hmac.compare_digest(digest, raw[-20:]), "stock-jks-integrity")
        point()
        return self.summary("jks")

    def config(self, raw, point):
        point()
        need(type(raw) is bytes and 0 < len(raw) <= CONFIG_LIMIT, "stock-config")
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeError:
            raise Refused("stock-config") from None
        lines, seen = text.split("\n"), set()
        need(len(lines) <= 8192, "stock-config")
        for line in lines:
            point()
            need(len(line.encode("utf-8")) <= 2048
                 and all(c.isprintable() or c == "\t" for c in line), "stock-config")
            if not line or line.lstrip(" \t").startswith("#"):
                continue
            need(line in self.names and line not in seen, "stock-config")
            seen.add(line)
        need(seen == self.names.keys(), "stock-complete-set")
        point()
        return self.summary("config")

    def complete(self, components, custom):
        need(type(components) is dict and set(components) == {"pem", "jks", "config"}
             and all(components[kind] == self.summary(kind) for kind in components),
             "stock-correspondence")
        need(custom == {"status": "empty", "customBodiesRead": False, "customNamesExported": False},
             "stock-custom-inputs")
        return self.summary("complete")
