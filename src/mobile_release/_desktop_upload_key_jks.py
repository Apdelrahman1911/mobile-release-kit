"""Narrow generated JKSv2 container checks, not an imported-keystore parser.

No private key is decrypted or generated here. JKS's specified SHA-1 integrity
format is used for interoperability, not as a new cryptographic construction.
The actual original keytool producer and native joins remain mandatory.
"""
from __future__ import annotations

import hashlib
import hmac
import struct

from ._desktop_upload_key_protocol import ALIAS, CERTIFICATE_LIMIT, JKS_LIMIT, PASSWORD_LENGTH, require

_HEADER = struct.pack(">III", 0xFEEDFEED, 2, 0)
_WHITENER = b"Mighty Aphrodite"


def _digest(password, content):
    require(type(password) in (bytes, bytearray, memoryview) and len(password) == PASSWORD_LENGTH
            and all(c in b"0123456789abcdef" for c in password))
    encoded = bytearray(2 * PASSWORD_LENGTH)
    try:
        for i, value in enumerate(password):
            encoded[2 * i + 1] = value  # JKS password UTF-16BE; supported ASCII only.
        state = hashlib.sha1()
        state.update(encoded)
        state.update(_WHITENER)
        state.update(content)
        return state.digest()
    finally:
        encoded[:] = b"\0" * len(encoded)


def empty_jks(password) -> bytearray:
    return bytearray(_HEADER + _digest(password, _HEADER))


def check_empty(raw, password) -> None:
    require(type(raw) in (bytes, bytearray, memoryview) and len(raw) == 32 and raw[:12] == _HEADER)
    require(hmac.compare_digest(raw[12:], _digest(password, raw[:12])))


def generated_certificate(raw, password, exported):
    """Borrow the one certificate slice; malformed/extra/truncated entries refuse.

    Successful container comparison proves neither private-key usability nor
    X.509 trust/Play acceptance. Those require the original producer/evidence
    and later explicit assessment, never this parser alone.
    """
    require(type(raw) in (bytes, bytearray, memoryview) and 32 < len(raw) <= JKS_LIMIT
            and type(exported) in (bytes, bytearray, memoryview) and 0 < len(exported) <= CERTIFICATE_LIMIT)
    data = memoryview(raw)
    require(hmac.compare_digest(data[-20:], _digest(password, data[:-20])))
    at, end = 0, len(data) - 20

    def take(size):
        nonlocal at
        require(type(size) is int and 0 <= size <= end - at)
        result = data[at:at + size]
        at += size
        return result

    def integer():
        return struct.unpack(">I", take(4))[0]

    def fixed_utf(expected):
        size = struct.unpack(">H", take(2))[0]
        require(size == len(expected) and take(size) == expected)

    require(integer() == 0xFEEDFEED and integer() == 2 and integer() == 1)
    require(integer() == 1)  # Exactly one private-key entry, never a trusted-cert entry.
    fixed_utf(ALIAS.encode("ascii"))
    require(struct.unpack(">q", take(8))[0] > 0)
    encrypted_length = integer()
    require(32 <= encrypted_length <= JKS_LIMIT - 64)
    encrypted = take(encrypted_length)
    require(encrypted[0] == 0x30)  # EncryptedPrivateKeyInfo; no private decryption here.
    require(integer() == 1)  # A newly generated self-signed key has one leaf, not imported chains.
    fixed_utf(b"X.509")
    size = integer()
    require(0 < size <= CERTIFICATE_LIMIT)
    certificate = take(size)
    require(at == end and certificate[0] == 0x30 and hmac.compare_digest(certificate, exported))
    return certificate
