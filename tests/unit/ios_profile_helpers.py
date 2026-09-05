"""Independent bounded CMS fixtures. No private identity or key is retained."""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path

from mobile_release.ios_profiles import profile_environment

from .ios_entitlement_helpers import tlv


def public_certificates() -> dict[str, bytes]:
    path = Path(__file__).parents[1] / "fixtures/apple-profile-authority/certificates.json"
    values = json.loads(path.read_text())
    result = {}
    for name, record in values.items():
        raw = base64.b64decode(record["derBase64"], validate=True)
        assert len(raw) == record["bytes"] and hashlib.sha256(raw).hexdigest() == record["sha256"]
        result[name] = raw
    return result


def pem(raw: bytes) -> bytes:
    body = base64.b64encode(raw)
    return b"-----BEGIN CERTIFICATE-----\n" + b"\n".join(body[index:index + 64] for index in range(0, len(body), 64)) + b"\n-----END CERTIFICATE-----\n"


def framed_cms(payload=b"fictional payload", *, certificates=(b"\x30\x01\x00",),
               signer_count=1, version=b"\x01", content_type=b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01",
               detached=False, digest_count=1, digest_oid=b"\x60\x86\x48\x01\x65\x03\x04\x02\x01",
               signer_digest=None) -> bytes:
    """Structural SignedData, NOT a valid signature or X.509 certificate."""
    econtent = tlv(6, content_type) + (b"" if detached else tlv(0xa0, tlv(4, payload)))
    signer = (tlv(2, b"\x01") + tlv(48, b"") + tlv(48, tlv(6, digest_oid if signer_digest is None else signer_digest))
              + tlv(48, b"") + tlv(4, b"not-a-signature"))
    fields = (tlv(2, version) + tlv(49, tlv(48, tlv(6, digest_oid)) * digest_count)
              + tlv(48, econtent) + tlv(0xa0, b"".join(certificates))
              + tlv(49, tlv(48, signer) * signer_count))
    return tlv(48, tlv(6, b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02") + tlv(0xa0, tlv(48, fields)))


def native_command(directory: Path, *arguments: str) -> None:
    subprocess.run(["/usr/bin/openssl", *arguments], check=True, timeout=20,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   env=profile_environment(directory))


def synthetic_identity(directory: Path) -> None:
    # Deliberately production-looking name proves names alone are NOT authority.
    native_command(directory, "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
                   "-days", "1", "-subj", "/CN=Apple iPhone OS Provisioning Profile Signing",
                   "-keyout", str(directory / "fictional.key"), "-out", str(directory / "fictional.pem"))


def signed_cms(directory: Path, content: bytes, name: str) -> bytes:
    source, output = directory / (name + ".input"), directory / (name + ".cms")
    source.write_bytes(content)
    native_command(directory, "cms", "-sign", "-binary", "-nodetach", "-md", "sha256",
                   "-in", str(source), "-signer", str(directory / "fictional.pem"),
                   "-inkey", str(directory / "fictional.key"), "-outform", "DER", "-out", str(output))
    return output.read_bytes()
