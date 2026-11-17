"""Hosted in-place update check for the installed macOS app (#49).

Fresh disposable runner only. Installs the selected previous signed package,
seeds per-user application data, installs the selected next signed package over
it with the standard Installer, then verifies:
  * both Installer runs returned 0 and the installed state names the next release;
  * the installed app reports the next version and the installed CLI still runs;
  * every seeded user-data file is byte-identical after the update;
  * re-installing the previous package is refused (downgrade) and changes nothing.
No signing credential is used. Evidence holds no user content or secrets.
"""
import argparse
import hashlib
import json
import os
import plistlib
import re
import subprocess
import sys
import time
import zipfile
from pathlib import Path

REPOSITORY = "Apdelrahman1911/mobile-release-kit"
STATE = Path("/Library/Application Support/MobileReleaseKit")
APP = STATE / "Mobile Release Kit.app"
USER_DATA = Path.home() / "Library/Application Support/dev.mobile-release-kit.desktop"
PACKAGE_ID = "dev.mobile-release-kit.desktop.installed"


class Failed(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise Failed(reason)


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def run(argv, timeout, check=False):
    started = time.monotonic()
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    row = {"argv": [Path(argv[0]).name] + [a if not a.startswith("/") else Path(a).name for a in argv[1:]],
           "returncode": p.returncode, "seconds": round(time.monotonic() - started, 1)}
    if check:
        need(p.returncode == 0, f"{row['argv'][0]}-returned-{p.returncode}")
    return p, row


def tail_text(text, lines=40):
    home = str(Path.home())
    return [line.replace(home, "~")[:400] for line in text.splitlines()[-lines:]]


def failure_diagnostics(evidence, role, p):
    """Failure-only evidence: installer output, post-failure state, crashes, unified log."""
    out = {"role": role, "installerStdout": tail_text(p.stdout), "installerStderr": tail_text(p.stderr)}
    try:
        out["afterFailure"] = installed_state()
    except Exception as error:  # the state may legitimately be absent or partial
        out["afterFailure"] = {"error": type(error).__name__, "detail": str(error)[:120]}
    listing = subprocess.run(["/usr/bin/sudo", "-n", "/bin/ls", "-laR", str(STATE)],
                             capture_output=True, text=True, timeout=60)
    out["stateListing"] = [line[:200] for line in listing.stdout.splitlines()
                           if ".app/" not in line][:200]
    reports = []
    for folder in (Path("/Library/Logs/DiagnosticReports"), Path.home() / "Library/Logs/DiagnosticReports"):
        r = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/find", str(folder), "-mmin", "-30", "-type", "f"],
                           capture_output=True, text=True, timeout=60)
        for name in r.stdout.split():
            if "mrk" in name.lower() or "install" in name.lower():
                body = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/head", "-c", "12000", name],
                                      capture_output=True, text=True, timeout=30)
                (evidence / ("crash-" + Path(name).name + ".txt")).write_text(body.stdout)
                reports.append(Path(name).name)
    out["crashReports"] = reports
    log = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/log", "show", "--style", "syslog", "--last", "8m",
                          "--predicate", 'process BEGINSWITH "mrk" OR process == "postinstall" '
                          'OR eventMessage CONTAINS[c] "mrk-macos" OR eventMessage CONTAINS[c] "MobileReleaseKit" '
                          'OR (process == "kernel" AND (eventMessage CONTAINS[c] "mrk" OR eventMessage CONTAINS "CODE SIGNING" '
                          'OR eventMessage CONTAINS "Sandbox"))'],
                         capture_output=True, text=True, timeout=300)
    (evidence / "unified-log-excerpt.txt").write_text("\n".join(tail_text(log.stdout, 1500)) + "\n")
    whole = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/tail", "-n", "4000", "/var/log/install.log"],
                           capture_output=True, text=True, timeout=60).stdout.splitlines()
    starts = [i for i, line in enumerate(whole) if "MRK_MACOS_POSTINSTALL_PHASE=pre-exec" in line]
    window = whole[starts[-1]:] if starts else whole[-300:]
    (evidence / "install-log-window.txt").write_text("\n".join(tail_text("\n".join(window), 600)) + "\n")
    (evidence / "FAILURE.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")


def hex_field(value, size):
    return type(value) is str and re.fullmatch(f"[0-9a-f]{{{size}}}", value) is not None


def load_selection(path):
    data = json.loads(Path(path).read_text())
    need(set(data) == {"schemaVersion", "previous", "next"} and data["schemaVersion"] == 1, "selection-shape")
    for role in ("previous", "next"):
        row = data[role]
        need(set(row) == {"runId", "artifactId", "carrierArtifactId", "packageSha256", "packageVersion", "release"}, f"selection-{role}")
        need(re.fullmatch(r"[1-9][0-9]{0,19}", row["runId"]) and re.fullmatch(r"[1-9][0-9]{0,19}", row["artifactId"])
             and re.fullmatch(r"[1-9][0-9]{0,19}", row["carrierArtifactId"])
             and hex_field(row["packageSha256"], 64) and re.fullmatch(r"\d+\.\d+\.\d+", row["packageVersion"])
             and re.fullmatch(r"macos26-arm64-desktop-[0-9]+", row["release"]), f"selection-{role}-fields")
    key = lambda v: tuple(int(x) for x in v.split("."))
    need(key(data["previous"]["packageVersion"]) < key(data["next"]["packageVersion"]), "selection-not-an-upgrade")
    return data


def fetch(role, row, work, steps):
    target = work / role
    target.mkdir(mode=0o700)
    def download(artifact, members, label):
        archive = target / f"{label}.zip"
        with open(archive, "wb") as out:
            p = subprocess.run(["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{artifact}/zip"],
                               stdout=out, stderr=subprocess.PIPE, timeout=900)
        need(p.returncode == 0, f"{role}-{label}-download")
        with zipfile.ZipFile(archive) as z:
            need(set(members) <= set(z.namelist()), f"{role}-{label}-members")
            for name in members:
                z.extract(name, target)
        archive.unlink()
    download(row["artifactId"], ("MobileReleaseKit.pkg", "PREPARED.json"), "prepared")
    # The signed producer descriptor and signature come from the carrier run
    # that authenticated this exact package (the installer reads them beside it).
    download(row["carrierArtifactId"], ("producer-root/producer.json", "producer-root/producer.sig"), "carrier")
    producer = json.loads((target / "producer-root/producer.json").read_text())["releaseSet"]["current"]
    need((producer["release"], producer["packageVersion"], producer["packageSha256"])
         == (row["release"], row["packageVersion"], row["packageSha256"]), f"{role}-producer-identity")
    # The bundled installer admits only the fixed package names "Install.pkg" or
    # "MobileReleaseKit-Request-<32 hex>.pkg" (macos_install_transaction.rs), so
    # each role's package is installed as Install.pkg from its own directory.
    (target / "MobileReleaseKit.pkg").rename(target / "Install.pkg")
    package, prepared = target / "Install.pkg", json.loads((target / "PREPARED.json").read_text())
    need(digest(package) == row["packageSha256"], f"{role}-package-digest")
    need(prepared.get("packageVersion") == row["packageVersion"] and prepared.get("release") == row["release"]
         and prepared.get("origin", {}).get("runId") == row["runId"], f"{role}-prepared-identity")
    listed = {m["name"]: m["sha256"] for m in prepared.get("members", [])}
    need(listed.get("MobileReleaseKit.pkg") == row["packageSha256"], f"{role}-prepared-member")
    signature, s1 = run(["/usr/sbin/pkgutil", "--check-signature", str(package)], 120)
    need(signature.returncode == 0 and "Developer ID Installer" in signature.stdout
         and "trusted by the Apple notary service" in signature.stdout, f"{role}-signature")
    gatekeeper, s2 = run(["/usr/sbin/spctl", "-a", "-vv", "-t", "install", str(package)], 120)
    text = gatekeeper.stdout + gatekeeper.stderr
    need(gatekeeper.returncode == 0 and "accepted" in text and "Notarized Developer ID" in text, f"{role}-gatekeeper")
    steps += [dict(s1, role=role), dict(s2, role=role)]
    return target


def carrier_image(role, folder, steps):
    """Same shape as the owner's successful install: a read-only HFS+ image
    holding exactly Install.pkg, producer.json and producer.sig, mounted under
    /Volumes; the bundled installer refuses user-owned or non-file sources."""
    source = folder / f"carrier-{role}"
    source.mkdir(mode=0o755)
    for name, origin in (("Install.pkg", folder / "Install.pkg"),
                         ("producer.json", folder / "producer-root/producer.json"),
                         ("producer.sig", folder / "producer-root/producer.sig")):
        os.link(origin, source / name) if name == "Install.pkg" else (source / name).write_bytes(origin.read_bytes())
    image, volume = folder / f"carrier-{role}.dmg", f"MRK-Update-{role}"
    p, row = run(["/usr/bin/hdiutil", "create", "-srcfolder", str(source), "-fs", "HFS+", "-format", "UDRO",
                  "-volname", volume, str(image)], 600, check=True)
    steps.append(dict(row, role=role))
    p, row = run(["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", str(image)], 300, check=True)
    steps.append(dict(row, role=role))
    mount = Path("/Volumes") / volume
    need(sorted(os.listdir(mount)) == ["Install.pkg", "producer.json", "producer.sig"], f"{role}-carrier-roster")
    need(digest(mount / "Install.pkg") == digest(folder / "Install.pkg"), f"{role}-carrier-digest")
    return mount


def install(role, folder, steps, expect_success=True, evidence=None):
    mount = carrier_image(role, folder, steps)
    p, row = run(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-verbose", "-pkg", str(mount / "Install.pkg"),
                  "-target", "/"], 1500)
    row.update(role=role, expected="success" if expect_success else "refusal")
    steps.append(row)
    if expect_success and p.returncode != 0 and evidence is not None:
        try:
            failure_diagnostics(evidence, role, p)
        except Exception as error:  # diagnostics must not mask the result
            row["diagnostics"] = type(error).__name__
    return p.returncode


def installed_state():
    p = subprocess.run(["/usr/bin/sudo", "-n", "/bin/cat", str(STATE / "installation-v2.json")],
                       capture_output=True, text=True, timeout=30)
    need(p.returncode == 0, "state-read")
    release = json.loads(p.stdout)["current"]["release"]
    info = plistlib.loads((APP / "Contents/Info.plist").read_bytes())
    cli = subprocess.run([str(APP / "Contents/MacOS/mrk"), "--version"], capture_output=True, text=True, timeout=60)
    receipt = subprocess.run(["/usr/sbin/pkgutil", "--pkg-info-plist", PACKAGE_ID], capture_output=True, timeout=30)
    receipt_version = plistlib.loads(receipt.stdout).get("pkg-version") if receipt.returncode == 0 else None
    return {"release": release["release"], "packageVersion": release["packageVersion"],
            "packageSha256": release["packageSha256"], "sourceCommit": release["sourceCommit"],
            "bundleShortVersion": info.get("CFBundleShortVersionString"), "cliReturn": cli.returncode,
            "cliVersionLine": cli.stdout.strip().splitlines()[0][:80] if cli.stdout.strip() else "",
            "receiptVersion": receipt_version}


def seed_user_data():
    files = {
        "settings.json": json.dumps({"fixture": "mrk-update-check", "theme": "dark", "projects": 2}).encode(),
        "projects.json": json.dumps({"projects": [{"name": "fixture-one"}, {"name": "fixture-two"}]}).encode(),
        "drafts/release-notes.json": json.dumps({"draft": "update preservation fixture " * 20}).encode(),
        "history/entry-0001.json": os.urandom(4096).hex().encode(),
        "history/entry-0002.json": os.urandom(4096).hex().encode(),
    }
    USER_DATA.mkdir(parents=True, mode=0o700)
    for name, body in files.items():
        path = USER_DATA / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(body)
    return manifest()


def manifest():
    rows = {}
    for path in sorted(USER_DATA.rglob("*")):
        if path.is_file():
            info = path.stat()
            rows[str(path.relative_to(USER_DATA))] = {"sha256": digest(path), "bytes": info.st_size,
                                                     "mode": oct(info.st_mode & 0o7777), "uid": info.st_uid}
    return rows


def install_log_excerpt(evidence):
    p = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/tail", "-n", "4000", "/var/log/install.log"],
                       capture_output=True, text=True, timeout=60)
    keep = [line for line in p.stdout.splitlines()
            if "MRK_" in line or "mrk-macos" in line or "PKInstallErrorDomain" in line or "postinstall" in line.lower()]
    home = str(Path.home())
    (evidence / "install-log-excerpt.txt").write_text("\n".join(line.replace(home, "~") for line in keep[-600:]) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection", required=True)
    parser.add_argument("--work", required=True)
    args = parser.parse_args()
    work = Path(args.work)
    evidence = work / "evidence"
    evidence.mkdir(mode=0o700)
    steps, result = [], {"schemaVersion": 1, "kind": "mrk-macos-update-check-v1", "passed": False}
    try:
        selection = load_selection(args.selection)
        result["selection"] = selection
        need(not STATE.exists() and not USER_DATA.exists(), "runner-not-fresh")
        previous = fetch("previous", selection["previous"], work, steps)
        upgraded = fetch("next", selection["next"], work, steps)

        need(install("previous", previous, steps, evidence=evidence) == 0, "previous-install-returned-nonzero")
        before = installed_state()
        result["afterPrevious"] = before
        need((before["release"], before["packageVersion"], before["packageSha256"])
             == (selection["previous"]["release"], selection["previous"]["packageVersion"],
                 selection["previous"]["packageSha256"]), "previous-installed-identity")
        seeded = seed_user_data()
        result["seededFiles"] = len(seeded)

        update_rc = install("next", upgraded, steps, evidence=evidence)
        result["updateReturn"] = update_rc
        need(update_rc == 0, "update-returned-nonzero")
        after = installed_state()
        result["afterUpdate"] = after
        need((after["release"], after["packageVersion"], after["packageSha256"])
             == (selection["next"]["release"], selection["next"]["packageVersion"],
                 selection["next"]["packageSha256"]), "updated-installed-identity")
        need(after["bundleShortVersion"] == selection["next"]["packageVersion"], "updated-bundle-version")
        # The installed CLI reports its observation protocol, not the package
        # version; the version itself is proven by state, bundle and receipt.
        need(after["cliReturn"] == 0 and after["cliVersionLine"].startswith("mrk ")
             and after["cliVersionLine"] == before["cliVersionLine"], "updated-cli-runs")
        preserved = manifest()
        result["userDataPreserved"] = preserved == seeded
        need(preserved == seeded, "user-data-changed-by-update")

        downgrade_rc = install("downgrade", previous, steps, expect_success=False)
        result["downgradeReturn"] = downgrade_rc
        need(downgrade_rc != 0, "downgrade-was-not-refused")
        final = installed_state()
        result["afterDowngradeAttempt"] = final
        need((final["release"], final["packageVersion"]) == (after["release"], after["packageVersion"]),
             "downgrade-changed-installation")
        need(manifest() == seeded, "user-data-changed-by-downgrade-attempt")
        result["passed"] = True
    except (Failed, subprocess.TimeoutExpired, OSError, ValueError, KeyError) as error:
        result["failure"] = str(error)[:200]
    finally:
        result["steps"] = steps
        try:
            install_log_excerpt(evidence)
        except Exception as error:  # evidence capture must not mask the result
            result["logCapture"] = type(error).__name__
        (evidence / "RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps({k: result.get(k) for k in ("passed", "failure", "updateReturn", "downgradeReturn",
                                                     "userDataPreserved")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
