"""Freeze and reverify the exact signed macOS distribution media."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import tempfile


TARGET = "aarch64-apple-darwin"
MANIFEST = "RELEASE-MANIFEST.json"
CHECKSUMS = "SHA256SUMS"
PROFILE = Path("desktop/packaging/macos-installer-signing.json")
CERT = Path("desktop/packaging/macos-install-producer-certificates/leaf.der")
IMAGE_LIMIT = 512 * 1024**2
IMAGE_PREFIX = "MobileReleaseKit"
DESCRIPTOR_LIMIT = 64 * 1024


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size,
            value.st_uid, value.st_gid, value.st_mtime_ns, value.st_ctime_ns)


def record(path, limit=IMAGE_LIMIT):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit,
             "release-file-bound")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    need(identity(before) == identity(after) == identity(path.lstat()), "release-original-changed")
    return {"bytes": before.st_size, "sha256": digest}


def json_data(path, limit=DESCRIPTOR_LIMIT):
    before = record(path, limit)
    body = path.read_bytes()
    need(hashlib.sha256(body).hexdigest() == before["sha256"], "release-json-changed")

    def pairs(items):
        result = dict(items)
        need(len(items) == len(result), "release-json-duplicate")
        return result

    return json.loads(body, object_pairs_hook=pairs)


def run(*args, timeout=90, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=timeout, **kwargs).stdout


def dump(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")


def image_names(version):
    need(re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}", version) and len(version) <= 32,
         "release-version")
    return tuple(f"{IMAGE_PREFIX}-{version}-macos-arm64-{role}.dmg" for role in ("Install", "Remove"))


@contextlib.contextmanager
def mount_readonly(image, work):
    mount = work / "volume"
    mount.mkdir()
    attached = run("/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen",
                   "-mountpoint", str(mount), "-plist", str(image))
    try:
        entities = plistlib.loads(attached)["system-entities"]
        need(sum(row.get("mount-point") == str(mount) for row in entities) == 1,
             "release-mounted-volume")
        yield mount
    finally:
        run("/usr/bin/hdiutil", "detach", str(mount))


def validate_package(package, profile):
    proof = run("/usr/sbin/pkgutil", "--check-signature", str(package))
    leaf = re.search(rb"1\. Developer ID Installer:[^\n]+\n\s*Expires:[^\n]+\n"
                     rb"\s*SHA256 Fingerprint:\s*((?:[0-9A-Fa-f]{2}[\s:]*){32})", proof)
    need(b"trusted by the Apple notary service" in proof and leaf is not None
         and bytes.fromhex(re.sub(rb"[^0-9A-Fa-f]", b"", leaf[1]).decode()).hex() == profile["leafSha256"],
         "release-installer-certificate")
    run("/usr/bin/xcrun", "stapler", "validate", str(package))
    run("/usr/sbin/spctl", "--assess", "--type", "install", str(package))


def inspect_image(image, role):
    before = record(image)
    installer = json_data(PROFILE)
    team = installer["teamId"]
    identity = record(CERT, 16384)["sha256"]
    leaf_sha1 = hashlib.sha1(CERT.read_bytes()).hexdigest()
    identifier = "dev.mobile-release-kit.desktop." + (
        "distribution" if role == "Install" else "remove-distribution")
    requirement = (f'=identifier "{identifier}" and anchor apple generic '
                   f'and certificate leaf[subject.OU] = "{team}" and certificate leaf = H"{leaf_sha1}"')
    run("/usr/bin/codesign", "--verify", "--strict", "--test-requirement", requirement, str(image))
    run("/usr/bin/xcrun", "stapler", "validate", str(image))
    run("/usr/sbin/spctl", "--assess", "--type", "open", "--context", "context:primary-signature", str(image))
    stem, domain = (("producer", b"MobileReleaseKit-package-producer-v2") if role == "Install"
                    else ("remove-producer", b"MobileReleaseKit-remove-producer-v1"))
    with tempfile.TemporaryDirectory(prefix="mrk-release-media-") as temporary:
        work = Path(temporary).resolve()
        with mount_readonly(image, work) as volume:
            package = volume / f"{role}.pkg"
            validate_package(package, installer)
            package_record = record(package)
            descriptor = volume / f"{stem}.json"
            descriptor_hash = record(descriptor, DESCRIPTOR_LIMIT)["sha256"]
            signature = volume / f"{stem}.sig"
            signature_hash = record(signature, 16384)["sha256"]
            key = work / "producer-key.pem"
            key.write_bytes(run("/usr/bin/openssl", "x509", "-inform", "der", "-in", str(CERT),
                                "-pubkey", "-noout"))
            payload = domain + b"\0" + descriptor.read_bytes()
            run("/usr/bin/openssl", "dgst", "-sha256", "-verify", str(key),
                "-signature", str(signature), input=payload)
            value = json_data(descriptor)
            need(hashlib.sha256(payload[len(domain) + 1:]).hexdigest() == descriptor_hash,
                 "release-descriptor-changed")
            if role == "Remove":
                app = volume / "Uninstall Mobile Release Kit.app"
                run("/usr/bin/codesign", "--verify", "--strict", "--deep", str(app))
                run("/usr/sbin/spctl", "--assess", "--type", "execute", str(app))
    need(before == record(image), "release-image-changed")
    return before, dict(package_record, descriptorSha256=descriptor_hash, signatureSha256=signature_hash,
                        developerIdApplicationLeafSha256=identity), value


def package_identities(install, remove, *, source, release, version):
    _, installed_package, installed_descriptor = install
    _, removed_package, removal_descriptor = remove
    current = installed_descriptor["releaseSet"]["current"]
    for row, package in ((current, installed_package), (removal_descriptor, removed_package)):
        need((row["sourceCommit"], row["release"], row["packageVersion"]) == (source, release, version)
             and row["packageSha256"] == package["sha256"], "release-package-source")
    need(installed_descriptor["target"] == removal_descriptor["target"] == TARGET
         and removal_descriptor["installedProducerSha256"] == installed_package["descriptorSha256"]
         and removal_descriptor["installedInventorySha256"] == current["inventorySha256"]
         and removal_descriptor["signingPolicySha256"] == current["signingPolicySha256"],
         "release-matching-pair")


def checksum_bytes(media, names):
    return "".join(f"{record(media / name)['sha256']}  {name}\n" for name in names).encode("ascii")


def verify_frozen(media, source, tree, build_run, carrier_run):
    value = json_data(media / MANIFEST)
    need(set(value) == {"schemaVersion", "version", "release", "target", "sourceCommit", "sourceTree",
                        "buildRun", "buildAttempt", "carrierRun", "carrierAttempt", "images", "packages"}
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["target"] == TARGET and value["sourceCommit"] == source and value["sourceTree"] == tree
         and value["buildRun"] == build_run and value["carrierRun"] == carrier_run,
         "release-manifest-source")
    need(all(type(value[key]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value[key])
             for key in ("buildRun", "buildAttempt", "carrierRun", "carrierAttempt")),
         "release-run-identity")
    names = image_names(value["version"])
    need({path.name for path in media.iterdir()} == {*names, MANIFEST, CHECKSUMS}, "release-asset-roster")
    need(value["images"] == {name: record(media / name) for name in names}, "release-image-digests")
    need((media / CHECKSUMS).read_bytes() == checksum_bytes(media, (*names, MANIFEST)), "release-checksums")
    return value


def freeze(work, media):
    source = os.environ["GITHUB_SHA"]
    tree = run("/usr/bin/git", "rev-parse", "HEAD^{tree}").decode().strip()
    need(run("/usr/bin/git", "rev-parse", "HEAD").decode().strip() == source, "release-detached-source")
    prepared = json_data(work / "prepared-input/PREPARED.json")
    local = json_data(work / "LOCAL-CARRIER.json")
    origin = prepared["origin"]
    consumer = local["consumer"]
    need(origin["source"] == consumer["source"] == source and origin["tree"] == consumer["tree"] == tree
         and origin["target"] == consumer["target"] == TARGET
         and origin["runId"] == os.environ["PRODUCER_RUN"]
         and consumer["runId"] == os.environ["GITHUB_RUN_ID"]
         and consumer["runAttempt"] == os.environ["GITHUB_RUN_ATTEMPT"],
         "release-carrier-source")
    release = json_data(Path("desktop/macos-installed-inputs/build-release.json"))
    version = release["packageVersion"]
    need((version, release["release"]) == (prepared["packageVersion"], prepared["release"]),
         "release-source-version")
    media.mkdir(mode=0o700)
    names = image_names(version)
    originals = (work / "distribution-final/MobileReleaseKit.dmg",
                 work / "remove-distribution-final/MobileReleaseKit-Remove.dmg")
    for original, name in zip(originals, names):
        before = record(original)
        shutil.copyfile(original, media / name, follow_symlinks=False)
        need(record(media / name) == before == record(original), "release-image-original")
    install, remove = (inspect_image(media / name, role) for name, role in zip(names, ("Install", "Remove")))
    package_identities(install, remove, source=source, release=release["release"], version=version)
    need(install[1]["sha256"] == local["packageSha256"], "release-install-owner-binding")
    value = dict(schemaVersion=1, target=TARGET, sourceCommit=source, sourceTree=tree,
                 version=version, release=release["release"], buildRun=origin["runId"],
                 buildAttempt=origin["runAttempt"], carrierRun=consumer["runId"],
                 carrierAttempt=consumer["runAttempt"], images=dict(zip(names, (install[0], remove[0]))),
                 packages={"Install.pkg": install[1], "Remove.pkg": remove[1]})
    (media / MANIFEST).write_bytes(dump(value))
    (media / CHECKSUMS).write_bytes(checksum_bytes(media, (*names, MANIFEST)))
    verify_frozen(media, source, tree, origin["runId"], consumer["runId"])


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("freeze")
    make.add_argument("work", type=Path)
    make.add_argument("media", type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("media", type=Path)
    verify.add_argument("--source", required=True)
    verify.add_argument("--tree", required=True)
    verify.add_argument("--build-run", required=True)
    verify.add_argument("--carrier-run", required=True)
    args = parser.parse_args()
    if args.command == "freeze":
        freeze(args.work, args.media)
    else:
        verify_frozen(args.media, args.source, args.tree, args.build_run, args.carrier_run)


if __name__ == "__main__":
    main()
