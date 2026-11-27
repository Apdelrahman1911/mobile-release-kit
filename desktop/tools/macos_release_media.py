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
import tomllib


TARGET = "aarch64-apple-darwin"
REPOSITORY = "Apdelrahman1911/mobile-release-kit"
SIGNER_WORKFLOW = REPOSITORY + "/.github/workflows/desktop-macos-installed.yml"
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
    expected = checksum_bytes(media, (*names, MANIFEST))
    need(record(media / CHECKSUMS, DESCRIPTOR_LIMIT)["sha256"] == hashlib.sha256(expected).hexdigest(), "release-checksums")
    need(set(value["packages"]) == {"Install.pkg", "Remove.pkg"}, "release-package-roster")
    for package in value["packages"].values():
        need(set(package) == {"bytes", "sha256", "descriptorSha256", "signatureSha256",
                              "developerIdApplicationLeafSha256"}
             and type(package["bytes"]) is int and 0 < package["bytes"] <= IMAGE_LIMIT
             and all(re.fullmatch(r"[0-9a-f]{64}", digest) for key, digest in package.items() if key != "bytes"),
             "release-package-record")
    return value


def verify_qualification(media, manifest, proof_path, run_id, attempt, carrier_attempt):
    proof = json_data(proof_path)
    frozen = {key: manifest[key] for key in ("sourceCommit", "sourceTree", "buildRun", "carrierRun", "carrierAttempt")}
    frozen.update(manifestSha256=record(media / MANIFEST, DESCRIPTOR_LIMIT)["sha256"],
                  installSha256=manifest["packages"]["Install.pkg"]["sha256"],
                  removeSha256=manifest["packages"]["Remove.pkg"]["sha256"])
    modes = {"archived-upgrade", "core-recovery", "delete-data", "fresh", "performance-long",
             "post-reinstall-prepare", "recovery-xctest", "uninstaller", "update-credentials", "workspace-xctest"}
    need(set(proof) == {"qualificationRun", "qualificationAttempt", "frozenRelease", "modes"}
         and proof["qualificationRun"] == run_id and proof["qualificationAttempt"] == attempt
         and proof["frozenRelease"] == frozen and frozen["carrierAttempt"] == carrier_attempt,
         "release-qualification-identity")
    observed = proof["modes"]
    need(isinstance(observed, list) and all(isinstance(mode, str) for mode in observed)
         and len(observed) == len(modes) and set(observed) == modes, "release-qualification-modes")


def release_selection(value):
    """Select the qualified predecessor and actual same-source Actions outputs."""
    repository = REPOSITORY
    source, tree = value["sourceCommit"], value["sourceTree"]
    workflow = ".github/workflows/desktop-macos-installed.yml"

    def api(path):
        return json.loads(run("gh", "api", f"repos/{repository}/{path}", timeout=45))

    def artifact(run_id, attempt, name):
        original = api(f"actions/runs/{run_id}/attempts/{attempt}")
        need(original["id"] == int(run_id) and original["run_attempt"] == int(attempt)
             and original["head_sha"] == source and original["head_commit"]["tree_id"] == tree
             and original["head_branch"] == "main" and original["event"] == "workflow_dispatch"
             and original["path"] == workflow and original["repository"]["full_name"] == repository
             and original["status"] == "completed" and original["conclusion"] == "success",
             "release-selection-run")
        page = api(f"actions/runs/{run_id}/artifacts?per_page=100")
        need(len(page["artifacts"]) == page["total_count"] <= 100, "release-selection-page")
        matches = [item for item in page["artifacts"] if item["name"] == name and item["expired"] is False]
        need(len(matches) == 1 and matches[0]["workflow_run"]["head_sha"] == source
             and matches[0]["workflow_run"]["id"] == int(run_id), "release-selection-artifact")
        return str(matches[0]["id"])

    build, attempt = value["buildRun"], value["buildAttempt"]
    carrier, carrier_attempt = value["carrierRun"], value["carrierAttempt"]
    prepared = artifact(build, attempt, f"mobile-release-kit-macos26-{TARGET}-prepared-{source}-{build}-{attempt}")
    transport = artifact(carrier, carrier_attempt, f"candidate-local-carrier-{source}-{attempt}-{source}-{carrier}-{carrier_attempt}")
    remove = artifact(carrier, carrier_attempt, f"candidate-local-remove-{source}-{source}-{carrier}-{carrier_attempt}")
    remove_name = image_names(value["version"])[1]
    return dict(schemaVersion=1,
        next=dict(runId=build, artifactId=prepared, carrierArtifactId=transport,
                  packageSha256=value["packages"]["Install.pkg"]["sha256"],
                  packageVersion=value["version"], release=value["release"]),
        removal=dict(runId=carrier, artifactId=remove, imageSha256=value["images"][remove_name]["sha256"]),
        previous=dict(runId="45599087818", artifactId="15020241911", carrierArtifactId="15021626521",
                      packageSha256="0b0b77dc8168194622d230af72e75d112458ff3831130fb069d4a06d0a2cbab2",
                      packageVersion="0.2.12", release="macos26-arm64-desktop-18"),
        previousRemoval=dict(runId="45612131054", artifactId="15021938507",
                             imageSha256="c04b2eb96e431f44ced32bfdc276b6b813d1155b45928ebcc7f1bc9c2ddaae6e"))


def draft_assets(draft, manifest, expected):
    """Check the REST metadata before requesting any private draft download."""
    tag = f"desktop-v{manifest['version']}"
    need(draft["draft"] is True and draft["prerelease"] is True and draft["published_at"] is None
         and draft["tag_name"] == tag and draft["target_commitish"] == manifest["sourceCommit"],
         "release-private-draft-binding")
    rows = draft["assets"]
    need(type(rows) is list and len(rows) == len(expected)
         and {row["name"] for row in rows} == set(expected), "release-draft-asset-roster")
    for asset in rows:
        record = expected[asset["name"]]
        need(type(asset["id"]) is int and asset["id"] > 0 and asset["state"] == "uploaded"
             and asset["size"] == record["bytes"] and asset["digest"] == "sha256:" + record["sha256"],
             "release-draft-asset-digest")
    need(len({asset["id"] for asset in rows}) == len(rows), "release-draft-asset-identities")
    return rows


def verify_draft_tag(tag, source):
    ref = "refs/tags/" + tag
    reply = subprocess.run(["/usr/bin/git", "ls-remote", "--exit-code", "--tags",
                            f"https://github.com/{REPOSITORY}.git", ref, ref + "^{}"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
    if reply.returncode == 2 and not reply.stdout:
        return "uncreated"
    need(reply.returncode == 0, "release-tag-lookup")
    refs = {}
    for row in reply.stdout.decode("ascii").splitlines():
        digest, name = row.split("\t")
        need(name in (ref, ref + "^{}") and name not in refs and re.fullmatch(r"[0-9a-f]{40}", digest),
             "release-tag-result")
        refs[name] = digest
    need(ref in refs and refs.get(ref + "^{}", refs[ref]) == source, "release-tag-source")
    return "exact-source"


def verify_draft(media, manifest, release_id):
    need(re.fullmatch(r"[1-9][0-9]{0,19}", release_id), "release-draft-id")
    endpoint = f"repos/{REPOSITORY}/releases/{release_id}"
    draft = json.loads(run("gh", "api", endpoint))
    need(draft["id"] == int(release_id), "release-draft-id")
    expected = {name: record(media / name) for name in (*image_names(manifest["version"]), MANIFEST, CHECKSUMS)}
    assets = draft_assets(draft, manifest, expected)
    tag_state = verify_draft_tag(draft["tag_name"], manifest["sourceCommit"])
    with tempfile.TemporaryDirectory(prefix="mrk-release-draft-check-") as path:
        downloaded = Path(path)
        for asset in assets:
            name = asset["name"]
            file = downloaded / name
            with file.open("xb") as stream:
                subprocess.run(["gh", "api", f"repos/{REPOSITORY}/releases/assets/{asset['id']}",
                                "-H", "Accept: application/octet-stream"],
                               stdout=stream, stderr=subprocess.PIPE, timeout=600, check=True)
            need(record(file) == expected[name], "release-draft-downloaded-bytes")
            run("gh", "attestation", "verify", str(file), "--repo", REPOSITORY, "--source-ref", "refs/heads/main",
                "--source-digest", manifest["sourceCommit"], "--deny-self-hosted-runners",
                "--signer-workflow", SIGNER_WORKFLOW, timeout=180)
        need(verify_frozen(downloaded, manifest["sourceCommit"], manifest["sourceTree"],
                           manifest["buildRun"], manifest["carrierRun"]) == manifest,
             "release-draft-downloaded-manifest")
    after = json.loads(run("gh", "api", endpoint))
    need(after["id"] == draft["id"] and after["body"] == draft["body"]
         and draft_assets(after, manifest, expected) == assets
         and verify_draft_tag(draft["tag_name"], manifest["sourceCommit"]) == tag_state,
         "release-draft-changed-during-download")
    print(dump({"releaseId": release_id, "tag": draft["tag_name"], "sourceCommit": manifest["sourceCommit"],
                "tagState": tag_state, "sourceTree": manifest["sourceTree"], "assets": expected}).decode("ascii"), end="")


def preflight():
    tracked = run("/usr/bin/git", "ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0")
    need(tracked[-1] == b"" and 1 <= len(tracked) - 1 <= 4128, "release-preflight-source-inventory")
    inputs = Path("desktop/macos-installed-inputs")
    build = json_data(inputs / "build-release.json")
    version = build["packageVersion"]
    image_names(version)
    versions = [json_data(Path(path))["version"] for path in (
        "desktop/src-tauri/tauri.conf.json", "desktop/package.json", "desktop/package-lock.json")]
    versions.append(tomllib.loads(Path("desktop/src-tauri/Cargo.toml").read_text())["package"]["version"])
    for plist in (inputs / "Info.plist", inputs / "EntryInfo.plist",
                  Path("desktop/native/macos-applications-launcher/Info.plist")):
        values = plistlib.loads(plist.read_bytes())
        versions.extend(values[key] for key in ("CFBundleVersion", "CFBundleShortVersionString"))
        need(values["LSMinimumSystemVersion"] == "26.0", "release-preflight-minimum-os")
    need(all(item == version for item in versions), "release-preflight-version-projection")
    notices = json_data(inputs / "notices/third-party-inputs.json", 1024 * 1024)
    for path, digest in notices["lockfiles"].items():
        need(record(Path(path), 4 * 1024 * 1024)["sha256"] == digest, "release-preflight-notice-lockfile")
    for certificate in (CERT, Path("desktop/packaging/macos-installer-certificates/leaf.der")):
        run("/usr/bin/openssl", "x509", "-inform", "DER", "-in", str(certificate), "-noout", "-checkend", "86400")

    tools = json_data(inputs / "github-tool-signing.json")["tools"]
    python = json_data(inputs / "python-signed-runtime-binding.json")["targets"][TARGET]
    store = json_data(inputs / "store-signed-retained-transport.json")["targets"][TARGET]["transport"]
    support = Path(".github/actions/macos-retained-android-support/action.yml").read_text()
    supplier = Path(".github/workflows/desktop-macos-update-parts.yml").read_text()
    support_id, = re.findall(r"artifact-ids: '([1-9][0-9]+)'", support)
    supplier_id = re.search(r"supplier_artifact: '([1-9][0-9]+)'", supplier)[1]
    artifacts = [tools[key][TARGET]["signed"]["artifactId"] for key in ("history-provider", "github-seal")]
    artifacts.extend((python["signingArtifactId"], store["artifactId"], support_id, supplier_id,
                      "15020241911", "15021626521", "15021938507"))
    for artifact in artifacts:
        need(re.fullmatch(r"[1-9][0-9]{0,19}", artifact), "release-preflight-artifact-input")
        value = json.loads(run("gh", "api", "repos/Apdelrahman1911/mobile-release-kit/actions/artifacts/" + artifact))
        need(value["id"] == int(artifact) and value["expired"] is False
             and re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"]), "release-preflight-artifact")
        print(f"Available immutable input {artifact} through {value['expires_at']}")


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
    commands.add_parser("preflight")
    make = commands.add_parser("freeze")
    make.add_argument("work", type=Path)
    make.add_argument("media", type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("media", type=Path)
    verify.add_argument("--source", required=True)
    verify.add_argument("--tree", required=True)
    verify.add_argument("--build-run", required=True)
    verify.add_argument("--carrier-run", required=True)
    verify.add_argument("--selection", type=Path)
    verify.add_argument("--draft-id")
    verify.add_argument("--qualification", nargs=4, metavar=("PROOF", "RUN", "ATTEMPT", "CARRIER_ATTEMPT"))
    args = parser.parse_args()
    if args.command == "preflight":
        preflight()
    elif args.command == "freeze":
        freeze(args.work, args.media)
    else:
        value = verify_frozen(args.media, args.source, args.tree, args.build_run, args.carrier_run)
        if args.qualification is not None:
            proof, run_id, attempt, carrier_attempt = args.qualification
            verify_qualification(args.media, value, Path(proof), run_id, attempt, carrier_attempt)
        if args.selection is not None:
            with args.selection.open("xb") as stream:
                stream.write(dump(release_selection(value)))
        if args.draft_id is not None:
            verify_draft(args.media, value, args.draft_id)


if __name__ == "__main__":
    main()
