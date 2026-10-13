"""Deterministic macOS SDK local-package SOURCE projection, not installation.

Only exact source-reviewed official DATA is accepted. This module opens no path,
starts no process, reads no environment, contacts no service, or acknowledges any
licence. Callers own input/output custody. Generated package.xml is explicitly
not a vendor ZIP member and never records licence acceptance.
"""
from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET

REPOSITORY_BYTES = 419185
REPOSITORY_SHA256 = "c9e2f9e8b118dcc9c5584904ea27cbcefb217a5807029cedadfaa0b2f842fa8d"
SDK_NAMESPACE = "http://schemas.android.com/sdk/android/repo/repository2/03"
COMMON_NAMESPACE = "http://schemas.android.com/repository/android/common/02"
GENERIC_NAMESPACE = "http://schemas.android.com/repository/android/generic/02"
XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"
LICENSE_SHA256 = "aaf80cd0aee7e569ffa8a4be1b61189c0fefccf23068e38dfafe336289b8c723"
LICENSE_SHA1 = "24333f8a63b6825ea9c5514f83c2829b004d1fee"
PACKAGE_LIMIT = 32 * 1024
PROPERTY_PINS = {
    "platforms;android-35": (257, "2c3764446f335ad2cc44383a0360fe247620b7c774ec100d5087771ac8ed3b28"),
    "build-tools;35.0.0": (63, "084847d70abc41284feee7ea717e7c92eab0d1be05f048c27445a359cfe109d8"),
}


class Refused(ValueError):
    """The fixed official input/source projection does not match."""


def _need(value):
    if not value:
        raise Refused("fixed SDK metadata source differs")


def _pin(raw, size, sha):
    _need(type(raw) is bytes and len(raw) == size and hashlib.sha256(raw).hexdigest() == sha)


def _license_value(value):
    # Same Repository31.9.2 TrimStringAdapter semantics as the established
    # android_material_preparation.sdk_license_value; no permissive hash search.
    import re
    _need(type(value) is str and len(value.encode("utf-8")) <= PACKAGE_LIMIT)
    value = re.sub(r"(?<=\s)[ \t]*", "", value, flags=re.ASCII)
    value = re.sub(r"(?<!\n)\n(?!\n)", " ", value)
    value = re.sub(r" +", " ", value)
    return value.strip("".join(chr(n) for n in range(33)))


def _escape(text, attribute=False):
    value = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return value.replace('"', "&quot;") if attribute else value


def _emit(node):
    # Closed serializer; unlike ET.tostring it never depends on process-global
    # namespace registrations. This exact official definition needs no generic
    # XML copier, external schemas, local SDK-manager invocation or network.
    tags = {"license", "type-details", "revision", "major", "minor", "micro",
            "display-name", "uses-license", "api-level", "extension-level",
            "base-extension", "layoutlib"}
    _need(node.tag in tags and len(node.attrib) <= 2)
    attributes = []
    for key, value in sorted(node.attrib.items()):
        if key == "{" + XSI_NAMESPACE + "}type":
            key = "xsi:type"
        _need(key in {"id", "type", "ref", "api", "xsi:type"})
        attributes.append(" " + key + '="' + _escape(value, True) + '"')
    body = _escape(node.text or "")
    for child in node:
        body += _emit(child) + _escape(child.tail or "")
    return "<" + node.tag + "".join(attributes) + ">" + body + "</" + node.tag + ">"


def compile_sdk_metadata(repository_xml, source_properties):
    """Return exactly two generated package.xml byte strings, in fixed order.

    The return value is SOURCE/DATA. It confers no original identity, supplier
    authority, native qualification, ownership, licence consent or success.
    """
    _pin(repository_xml, REPOSITORY_BYTES, REPOSITORY_SHA256)
    _need(type(source_properties) is dict and set(source_properties) == set(PROPERTY_PINS))
    for path, (size, sha) in PROPERTY_PINS.items():
        _pin(source_properties[path], size, sha)
    _need(b"<!DOCTYPE" not in repository_xml and b"<!ENTITY" not in repository_xml)
    root = ET.fromstring(repository_xml)
    _need(root.tag == "{" + SDK_NAMESPACE + "}sdk-repository")
    licences = [node for node in root if node.tag == "license" and node.get("id") == "android-sdk-license"]
    _need(len(licences) == 1 and licences[0].text is not None)
    licence = licences[0]
    normalized = _license_value(licence.text).encode("utf-8")
    _need(len(normalized) == 16960 and hashlib.sha256(normalized).hexdigest() == LICENSE_SHA256
          and hashlib.sha1(normalized).hexdigest() == LICENSE_SHA1)
    header = ('<?xml version="1.0" encoding="UTF-8"?>\n'
              '<common:repository xmlns:common="' + COMMON_NAMESPACE + '" xmlns:sdk="' + SDK_NAMESPACE
              + '" xmlns:generic="' + GENERIC_NAMESPACE + '" xmlns:xsi="' + XSI_NAMESPACE + '">\n')
    result = {}
    for path in PROPERTY_PINS:
        packages = [node for node in root if node.tag == "remotePackage" and node.get("path") == path]
        _need(len(packages) == 1)
        package = packages[0]
        fields = {node.tag: node for node in package if node.tag in
                  {"type-details", "revision", "display-name", "uses-license", "dependencies"}}
        _need(set(fields) == {"type-details", "revision", "display-name", "uses-license"})
        _need(sum(node.tag in fields for node in package) == len(fields))
        _need(fields["uses-license"].attrib == {"ref": "android-sdk-license"})
        platform = path == "platforms;android-35"
        _need([node.text for node in fields["revision"]] == (["2"] if platform else ["35", "0", "0"]))
        _need(fields["type-details"].get("{" + XSI_NAMESPACE + "}type")
              == ("sdk:platformDetailsType" if platform else "generic:genericDetailsType"))
        content = header + _emit(licence) + '\n<localPackage path="' + path + '" obsolete="false">\n'
        for key in ("type-details", "revision", "display-name", "uses-license"):
            content += _emit(fields[key]) + "\n"
        content += "</localPackage>\n</common:repository>\n"
        raw = content.encode("utf-8")
        _need(0 < len(raw) <= PACKAGE_LIMIT)
        result["sdk/" + path.replace(";", "/") + "/package.xml"] = raw
    return result
