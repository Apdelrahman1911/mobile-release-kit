"""Prepare one byte-bound distribution wrapper on a disposable Mac."""
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

REPOSITORY = "Apdelrahman1911/mobile-release-kit"
SOURCE = "6bde41073ab878ab83f1e70ac46bfac7d0b7c185"
TREE = "410f788d127278fa8041417c4dba039596714141"
RELEASE = "macos26-arm64-desktop-16"
ARTIFACT = 14903178669
ARCHIVE = "abdce8855e548449b808a6b18ae6c655a2832ae9f8ce9196e76c6565229e9ed8"
TEAM = "7CGZ2343AA"
IDENTITY = "5EFFA7D19BBE005B19C1617833CBE22186C2AF96"
CERTIFICATE = "e5ba1d05f136fbef3ca5816f0efb1e946cb2cfb81819b745d9f914e7e9256d72"
IDENTIFIER = "dev.mobile-release-kit.desktop.install-distribution"
MEMBERS = {
    "Install.pkg": "8f4dcf34a87c2d0966c51b2786b951eec1c22a17c516e30ba54ac664bc227dbe",
    "producer.json": "6cbc9876124eea225e3295e0dd21bc63a5fbf0423a26a21567f3b7bc82f188ef",
    "producer.sig": "36d661cf8010effd2d0a68279a6ff31d2b80372126145ae5f08dca96f21f337a",
}
IMAGE = "MobileReleaseKit-Install.dmg"
SECRETS = ("MRK_MACOS_DEVELOPER_ID_P12_BASE64", "MRK_MACOS_DEVELOPER_ID_P12_PASSWORD",
           "MRK_MACOS_NOTARY_API_KEY_BASE64")


def need(value, label):
    if not value:
        raise RuntimeError(label)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def run(label, args, *, timeout=120, output=None, cwd=None, combined=False, public_failure=False):
    try:
        result = subprocess.run(args, stdout=output if output is not None else subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, cwd=cwd)
    except subprocess.TimeoutExpired:
        raise RuntimeError(label + " timed out") from None
    if result.returncode != 0:
        detail = (result.stderr or b"").decode(errors="replace")[-500:] if public_failure else ""
        raise RuntimeError(f"{label} failed ({result.returncode}) {detail}")
    return (result.stdout or b"") + (result.stderr if combined else b"")


def accept_package(path):
    proof = run("package signature", ["/usr/sbin/pkgutil", "--check-signature", str(path)])
    need(b"Developer ID Installer" in proof and b"trusted by the Apple notary service" in proof,
         "package signer or notarization mismatch")
    proof = run("package Gatekeeper", ["/usr/sbin/spctl", "-a", "-vv", "-t", "install", str(path)], combined=True)
    need(b"Notarized Developer ID" in proof, "package Gatekeeper origin mismatch")
    run("package staple", ["/usr/bin/xcrun", "stapler", "validate", str(path)])


def prepare(root):
    source = root / "release-asset.zip"
    artifact = f"repos/{REPOSITORY}/actions/artifacts/{ARTIFACT}"
    details = json.loads(run("artifact metadata", ["gh", "api", artifact]))
    need(details["workflow_run"]["id"] == 45358905902 and not details["expired"]
         and details["digest"] == "sha256:" + ARCHIVE and details["size_in_bytes"] == 260216887,
         "unexpected input artifact")
    with source.open("xb") as stream:
        run("artifact download", ["gh", "api", artifact + "/zip"], output=stream, timeout=540)
    need(source.stat().st_size == details["size_in_bytes"] and digest(source) == ARCHIVE,
         "input artifact bytes mismatch")
    directory = root / "image-files"
    directory.mkdir()
    with zipfile.ZipFile(source) as archive:
        need(len(archive.namelist()) == 7 and len(set(archive.namelist())) == 7, "unexpected archive roster")
        manifest = json.loads(archive.read("MANIFEST.json"))
        need((manifest["sourceCommit"], manifest["sourceTree"], manifest["release"], manifest["target"])
             == (SOURCE, TREE, RELEASE, "aarch64-apple-darwin"), "input source mismatch")
        for name, expected in MEMBERS.items():
            info = archive.getinfo(name)
            need(0 < info.file_size < 200 * 1024**2 and not stat.S_ISLNK(info.external_attr >> 16)
                 and manifest["sha256"][name] == expected, "input member metadata mismatch")
            with archive.open(info) as original, (directory / name).open("xb") as target:
                shutil.copyfileobj(original, target, 1024 * 1024)
            need(digest(directory / name) == expected, "input member hash mismatch")
    source.unlink()
    accept_package(directory / "Install.pkg")
    run("hide producer sidecars", ["/usr/bin/chflags", "hidden", str(directory / "producer.json"),
                                    str(directory / "producer.sig")])
    run("create read-only HFS+ image", ["/usr/bin/hdiutil", "create", "-srcfolder", str(directory),
        "-fs", "HFS+", "-format", "UDZO", "-volname", "Mobile Release Kit Install", str(root / IMAGE)],
        timeout=300)


def sign(root, p12, password, p8):
    image = root / IMAGE
    need(all(digest(root / "image-files" / name) == sha for name, sha in MEMBERS.items()), "staged members changed")
    with tempfile.TemporaryDirectory(prefix="signing-", dir=root) as scratch:
        private = Path(scratch)
        keychain = str(private / "distribution.keychain-db")
        secret = secrets.token_hex(32)
        cert_file = private / "application.p12"
        cert_file.write_bytes(base64.b64decode(p12, validate=True))
        base = ["/usr/bin/security", "list-keychains", "-d", "user"]
        search_list = run("read keychain search list", base)
        default = ["/usr/bin/security", "default-keychain", "-d", "user"]
        original_default = run("read default keychain", default)
        run("create ephemeral keychain", ["/usr/bin/security", "create-keychain", "-p", secret, keychain])
        try:
            run("limit the ephemeral unlock interval", ["/usr/bin/security", "set-keychain-settings",
                                                        "-l", "-u", "-t", "240", keychain])
            run("unlock ephemeral keychain", ["/usr/bin/security", "unlock-keychain", "-p", secret, keychain])
            run("import Developer ID identity", ["/usr/bin/security", "import", str(cert_file), "-k", keychain,
                "-f", "pkcs12", "-P", password, "-T", "/usr/bin/codesign", "-T", "/usr/bin/security"])
            cert_file.unlink()
            run("allow codesign in ephemeral keychain", ["/usr/bin/security", "set-key-partition-list",
                "-S", "apple-tool:,apple:", "-s", "-k", secret, keychain])
            identities = run("find ephemeral identity", ["/usr/bin/security", "find-identity", "-v", "-p",
                                                         "codesigning", keychain])
            need(len(re.findall(rb"(?m)^\s*\d+\) " + IDENTITY.encode() + rb' "Developer ID Application:', identities)) == 1,
                 "pinned Developer ID identity unavailable")
            run("select only the ephemeral keychain", [*base, "-s", keychain])
            image.chmod(0o600)
            run("sign outer image", ["/usr/bin/codesign", "--sign", IDENTITY,
                                     "--timestamp", "--identifier", IDENTIFIER, str(image)], public_failure=True)
        finally:
            try:
                run("restore original keychain search list", [*base, "-s", *shlex.split(search_list.decode())])
            finally:
                run("retire ephemeral keychain", ["/usr/bin/security", "delete-keychain", keychain])
        need(run("verify original keychain search list", base) == search_list
             and run("verify original default keychain", default) == original_default,
             "ephemeral keychain search cleanup mismatch")
        profile = json.loads(Path("desktop/packaging/macos-notary-service.json").read_bytes())
        need(profile["mode"] == "app-store-connect-team-key" and profile["teamId"] == TEAM
             and re.fullmatch(r"[A-Z0-9]{10}", profile["keyId"])
             and re.fullmatch(r"[a-f0-9-]{36}", profile["issuerId"]), "notary profile mismatch")
        key = private / "notary.p8"
        key.write_bytes(base64.b64decode(p8, validate=True))
        key.chmod(0o400)
        submission = json.loads(run("notary submission", ["/usr/bin/xcrun", "notarytool", "submit", str(image),
            "--key", str(key), "--key-id", profile["keyId"], "--issuer", profile["issuerId"],
            "--wait", "--timeout", "18m", "--output-format", "json"], timeout=1200))
        need(submission["status"] == "Accepted" and re.fullmatch(r"[a-f0-9-]{36}", submission["id"]),
             "Apple did not accept this wrapper")
    run("staple outer image", ["/usr/bin/xcrun", "stapler", "staple", str(image)])
    (root / "submission.json").write_text(json.dumps({"status": submission["status"], "id": submission["id"]}) + "\n")


def validate_and_encrypt(root):
    image = root / IMAGE
    run("verify strict image signature", ["/usr/bin/codesign", "--verify", "--strict", str(image)])
    detail = run("image signing policy", ["/usr/bin/codesign", "-dv", "--verbose=4", str(image)], combined=True)
    need(all(value in detail for value in [
        f"Identifier={IDENTIFIER}\n".encode(), f"TeamIdentifier={TEAM}\n".encode(), b"Timestamp=",
        b"Authority=Developer ID Application:",
    ]), "image signing identity mismatch")
    with tempfile.TemporaryDirectory(dir=root) as directory:
        run("extract public image certificate", ["/usr/bin/codesign", "-d", "--extract-certificates", str(image)],
            cwd=directory)
        need(digest(Path(directory) / "codesign0") == CERTIFICATE, "image leaf certificate mismatch")
    run("image staple", ["/usr/bin/xcrun", "stapler", "validate", str(image)])
    run("mark quarantined download", ["/usr/bin/xattr", "-w", "com.apple.quarantine",
         "0081;6a000000;Safari;", str(image)])
    assessment = run("quarantined image Gatekeeper", ["/usr/sbin/spctl", "-a", "-vv", "-t", "open",
                     "--context", "context:primary-signature", str(image)], combined=True)
    need(b"Notarized Developer ID" in assessment, "quarantined image Gatekeeper origin mismatch")
    data = plistlib.loads(run("attach quarantined image", ["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse",
                                                         "-noautoopen", "-plist", str(image)], timeout=180))
    mounts = [Path(row["mount-point"]) for row in data["system-entities"] if row.get("mount-point")]
    need(len(mounts) == 1, "unexpected image mount")
    mount = mounts[0]
    try:
        need(os.statvfs(mount).f_flag & os.ST_RDONLY, "image mount is writable")
        need({item.name for item in mount.iterdir() if not item.name.startswith(".")} == set(MEMBERS)
             and all(digest(mount / name) == sha for name, sha in MEMBERS.items())
             and all((mount / name).lstat().st_flags & stat.UF_HIDDEN for name in ("producer.json", "producer.sig")),
             "image roster or media bytes mismatch")
        package = mount / "Install.pkg"
        accept_package(package)
        app_root = Path("/Library/Application Support/MobileReleaseKit")
        need(not app_root.exists(), "runner already contains the app")
        run("fresh Installer from verified image", ["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-verbose",
                                                    "-pkg", str(package), "-target", "/"], timeout=600)
        state = json.loads((app_root / "installation-v2.json").read_bytes())["current"]["release"]
        need((state["sourceCommit"], state["packageSha256"], state["packageVersion"], state["release"])
             == (SOURCE, MEMBERS["Install.pkg"], "0.2.10", RELEASE), "installed identity mismatch")
        run("installed bundle strict signature", ["/usr/bin/codesign", "--verify", "--deep", "--strict",
                                                  str(app_root / "Mobile Release Kit.app")])
        print("Verified quarantined Gatekeeper, mounted original bytes and fresh Installer", flush=True)
    finally:
        # Installer can briefly retain a reference after its client exits.
        for delay in (0, 1, 2, 4, 8, 16):
            time.sleep(delay)
            result = subprocess.run(["/usr/bin/hdiutil", "detach", str(mount)],
                                    capture_output=True, timeout=35)
            if result.returncode == 0:
                did_detach = True
                break
            need(result.returncode == 16, "unexpected image detach failure")
        else:
            did_detach = False
            print("Installer still holds the read-only mount. Hosted runner teardown will retire it.",
                  flush=True)
    recipient = base64.b64decode(os.environ["MRK_PRIVATE_RECIPIENT"], validate=True)
    need(0 < len(recipient) <= 4096 and recipient.startswith(b"-----BEGIN CERTIFICATE-----\n"),
         "invalid transport recipient")
    cert = root / "recipient.pem"
    cert.write_bytes(recipient)
    out = root / "private-export"
    out.mkdir()
    envelope = out / (IMAGE + ".cms")
    run("encrypt private export", ["/usr/bin/openssl", "cms", "-encrypt", "-binary", "-aes256",
        "-outform", "DER", "-in", str(image), "-out", str(envelope), str(cert)], timeout=300)
    receipt = {"version": "0.2.10", "release": RELEASE, "sourceCommit": SOURCE, "sourceTree": TREE,
               "inputArtifact": ARTIFACT, "inputArtifactSha256": ARCHIVE, "members": MEMBERS,
               "image": IMAGE, "imageSha256": digest(image), "imageBytes": image.stat().st_size,
               "signedByTeam": TEAM, "signerLeafSha256": CERTIFICATE,
               "notary": json.loads((root / "submission.json").read_bytes()),
               "quarantinedGatekeeper": True, "stapleVerified": True, "installedExactCandidate": True,
               "detachedAfterInstall": did_detach,
               "encryptedExportSha256": digest(envelope), "workflowRun": os.environ["GITHUB_RUN_ID"],
               "workflowSource": os.environ["GITHUB_SHA"]}
    (out / "distribution-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("Verified signed wrapper, original members, quarantined Gatekeeper and fresh Installer", flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    need(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
         and os.environ.get("GITHUB_REF") == "refs/heads/verify/desktop-macos-update-check"
         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and sys.platform == "darwin"
         and os.uname().machine == "arm64" and os.getuid() != 0, "unexpected signing host")
    work = Path(sys.argv[2]).resolve(strict=True)
    need(work.parent == Path(os.environ["RUNNER_TEMP"]).resolve() and work.is_dir(), "unexpected work location")
    phase = sys.argv[1]
    if phase == "sign":
        signing = tuple(os.environ.pop(name) for name in SECRETS)
        sign(work, *signing)
    else:
        need(not any(name in os.environ for name in SECRETS), "unexpected signing credentials")
        {"prepare": prepare, "export": validate_and_encrypt}[phase](work)
