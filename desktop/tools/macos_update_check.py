"""Hosted install, update and first-launch check for the installed macOS app.

Fresh disposable runner only. Three modes, each on its own fresh runner:

update (#49): installs the selected previous signed package, seeds per-user
application data, installs the selected next signed package over it with the
standard Installer, then verifies:
  * both Installer runs returned 0 and the installed state names the next release;
  * the installed app reports the next version and the installed CLI still runs;
  * every seeded user-data file is byte-identical after the update;
  * re-installing the previous package is refused (downgrade) and changes nothing;
  * the updated app launches and shows a window (#45/#46 smoke).

fresh: installs only the next package on a clean runner, launches it for the
first time (window shown, process alive, no crash report), then reinstalls the
same package (same-package no-op returns 0 and changes neither the installation
nor the app data the first launch created), and reopens the app.

remove: installs the next package, seeds user data, opens the app, runs the
matching notarized Remove.pkg from its read-only image and confirms the app's
own removal sheet; then requires Installer 0, no app, launcher or process left
and every seeded user-data file unchanged; then reinstalls the same package and
launches it again.
No signing credential is used. Evidence holds no user content or secrets.
"""
import argparse
import hashlib
import json
import os
import plistlib
import re
import signal
import stat
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
PAYLOAD_PROCESS = "mobile-release-kit-desktop"
# CoreGraphics window list through the JXA bridge: no Apple Events, no TCC prompt.
WINDOWS_JXA = """ObjC.import('CoreGraphics');
function run(argv) {
  const pid = parseInt(argv[0], 10);
  const list = ObjC.castRefToObject($.CGWindowListCopyWindowInfo(1 | 16, 0));
  let count = 0;
  for (let i = 0; i < list.count; i++) {
    const w = list.objectAtIndex(i);
    const owner = w.objectForKey('kCGWindowOwnerPID'), layer = w.objectForKey('kCGWindowLayer');
    if (owner && layer && owner.intValue === pid && layer.intValue === 0) count++;
  }
  return String(count);
}
"""


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
    need(set(data) in ({"schemaVersion", "previous", "next"}, {"schemaVersion", "previous", "next", "removal"})
         and data["schemaVersion"] == 1, "selection-shape")
    if "removal" in data:
        # The matching Remove carrier produced by the carrier run for "next".
        row = data["removal"]
        need(set(row) == {"runId", "artifactId", "imageSha256"}
             and re.fullmatch(r"[1-9][0-9]{0,19}", row["runId"]) and re.fullmatch(r"[1-9][0-9]{0,19}", row["artifactId"])
             and hex_field(row["imageSha256"], 64), "selection-removal-fields")
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


def payload_pids():
    p = subprocess.run(["/usr/bin/pgrep", "-x", PAYLOAD_PROCESS], capture_output=True, text=True, timeout=30)
    return sorted(int(v) for v in p.stdout.split()) if p.returncode == 0 else []


def window_count(pid, work):
    script = work / "windows.js"
    if not script.exists():
        script.write_text(WINDOWS_JXA)
    p = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(script), str(pid)],
                       capture_output=True, text=True, timeout=30)
    return int(p.stdout.strip()) if p.returncode == 0 and p.stdout.strip().isdigit() else None


def recent_crashes(minutes=10):
    names = []
    for folder in (Path("/Library/Logs/DiagnosticReports"), Path.home() / "Library/Logs/DiagnosticReports"):
        r = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/find", str(folder), "-mmin", f"-{minutes}", "-type", "f"],
                           capture_output=True, text=True, timeout=60)
        names += [Path(n).name for n in r.stdout.split()
                  if PAYLOAD_PROCESS in n or "mrk-macos" in n or "Mobile Release Kit" in n]
    return sorted(names)


def stop_app(pids):
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 20
    while payload_pids() and time.monotonic() < deadline:
        time.sleep(1)
    for pid in payload_pids():
        os.kill(pid, signal.SIGKILL)
    time.sleep(2)
    need(not payload_pids(), "app-did-not-stop")


UI_JXA = """function run(argv) {
  const se = Application('System Events');
  const matches = se.processes.whose({unixId: Number(argv[0])});
  if (matches.length !== 1) return JSON.stringify({error: 'no-process'});
  const wins = matches[0].windows();
  if (wins.length < 1) return JSON.stringify({error: 'no-window'});
  const all = wins[0].entireContents();
  const label = (e) => { for (const k of ['name', 'title', 'description']) { try { const v = e[k](); if (typeof v === 'string' && v) return v; } catch (x) {} } return ''; };
  const role = (e) => { try { return e.role(); } catch (x) { return ''; } };
  if (argv[1] === 'click') {
    const preferred = ['AXLink', 'AXButton', 'AXRadioButton', 'AXTab', 'AXMenuItem'];
    for (const pass of [true, false]) {
      for (const e of all) {
        if (label(e) !== argv[2] || preferred.includes(role(e)) !== pass) continue;
        try { e.click(); return JSON.stringify({clicked: argv[2], role: role(e)}); } catch (x) {}
      }
    }
    return JSON.stringify({error: 'not-found'});
  }
  const texts = [];
  for (const e of all) {
    if (role(e) !== 'AXStaticText') continue;
    try { const v = e.value(); if (typeof v === 'string' && v.trim()) texts.push(v.trim()); } catch (x) {}
    if (texts.length >= 600) break;
  }
  return JSON.stringify({texts: texts});
}
"""
RUNTIME_AVAILABLE_TEXT, RUNTIME_UNAVAILABLE_TEXT = "Bundled runtime", "Runtime unavailable"
WORKSPACE_ERROR_MARKERS = ("Maximum update depth", "Minified React error", "Something went wrong")
CLI_STATUS_GUIDANCE = "CLI / AI access"


def ui_query(pid, work, *args, timeout=90):
    """Read-only accessibility query of the app's first window (texts), or
    one click on a named navigation element. Never types or grants anything."""
    script = work / "ui.js"
    if not script.exists():
        script.write_text(UI_JXA)
    try:
        p = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(script), str(pid), *args],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    try:
        value = json.loads(p.stdout.strip())
        return value if type(value) is dict else {"error": "shape"}
    except ValueError:
        return {"error": f"osascript-{p.returncode}"}


def first_launch_observe(pid, work, evidence, label):
    """#45/#46/#50 evidence from the live first launch: workspace texts, the
    Build tools runtime card, and the installed CLI's read-access refusal."""
    overview = ui_query(pid, work, "texts")
    navigate = ui_query(pid, work, "click", "Build tools")
    time.sleep(6)
    tools = ui_query(pid, work, "texts")
    texts = (overview.get("texts") or []) + (tools.get("texts") or [])
    shot = evidence / f"screen-{label}-build-tools.png"
    subprocess.run(["/usr/sbin/screencapture", "-x", str(shot)], capture_output=True, timeout=60)
    card = tools.get("texts") or []
    runtime = ("unavailable" if RUNTIME_UNAVAILABLE_TEXT in card else
               "bundled" if RUNTIME_AVAILABLE_TEXT in card else "not-observed")
    try:
        cli = subprocess.run([str(APP / "Contents/MacOS/mrk"), "status", "--json"], capture_output=True, text=True, timeout=60)
        status = {"returncode": cli.returncode, "guidance": CLI_STATUS_GUIDANCE in (cli.stdout + cli.stderr)}
    except subprocess.TimeoutExpired:
        status = {"returncode": None, "guidance": False}
    return {"overviewTexts": len(overview.get("texts") or []), "overviewError": overview.get("error"),
            "navigate": navigate, "buildToolsTexts": len(card), "buildToolsError": tools.get("error"),
            "runtimeCard": runtime, "workspaceErrorMarkers": sorted({m for m in WORKSPACE_ERROR_MARKERS
                                                                     for t in texts if m in t}),
            "cliStatus": status, "screenshot": shot.name if shot.exists() else None}


def launch_smoke(label, work, evidence, steps, observe=None):
    """Open the installed app as the logged-in runner user and require a live
    payload process with an on-screen window and no crash report."""
    need(not payload_pids(), f"{label}-app-already-running")
    before = set(recent_crashes())
    started = time.monotonic()
    p, row = run(["/usr/bin/open", str(APP)], 60)
    steps.append(dict(row, role=label))
    need(p.returncode == 0, f"{label}-open-returned-{p.returncode}")
    pids, windows = [], None
    while time.monotonic() - started < 90:
        pids = payload_pids()
        if pids:
            windows = window_count(pids[0], work)
            if windows:
                break
        time.sleep(2)
    first_window = round(time.monotonic() - started, 1) if windows else None
    time.sleep(15)  # still alive and showing a window after the first paint
    alive = payload_pids()
    settled = window_count(alive[0], work) if alive else None
    shot = evidence / f"screen-{label}.png"
    subprocess.run(["/usr/sbin/screencapture", "-x", str(shot)], capture_output=True, timeout=60)
    ui = observe(alive[0], work, evidence, label) if observe and alive and settled else None
    crashes = sorted(set(recent_crashes()) - before)
    observed = {"label": label, "processSeen": bool(pids), "secondsToFirstWindow": first_window,
                "aliveAfterSettle": bool(alive), "windowsAfterSettle": settled, "newCrashReports": crashes,
                "screenshot": shot.name if shot.exists() else None}
    if ui is not None:
        observed["ui"] = ui
    if alive:
        stop_app(alive)
    need(pids, f"{label}-app-process-not-started")
    need(not crashes, f"{label}-app-crashed")
    need(alive and settled, f"{label}-app-window-missing")
    return observed


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
    parser.add_argument("--mode", choices=("update", "fresh", "remove"), default="update")
    args = parser.parse_args()
    work = Path(args.work)
    evidence = work / "evidence"
    evidence.mkdir(mode=0o700)
    steps, result = [], {"schemaVersion": 1, "kind": "mrk-macos-update-check-v1", "mode": args.mode, "passed": False}
    try:
        selection = load_selection(args.selection)
        result["selection"] = selection
        need(not STATE.exists() and not USER_DATA.exists(), "runner-not-fresh")
        if args.mode in ("fresh", "remove"):
            (fresh_check if args.mode == "fresh" else remove_check)(selection, work, evidence, steps, result)
            result["passed"] = True
            return 0
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
        # Last: launching writes the app's own data beside the seeded files.
        result["launchAfterUpdate"] = launch_smoke("after-update", work, evidence, steps)
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
        print(json.dumps({k: result.get(k) for k in ("mode", "passed", "failure", "updateReturn", "downgradeReturn",
                                                     "userDataPreserved", "samePackageReturn", "removeReturn",
                                                     "reinstallReturn")}))
    return 0 if result["passed"] else 1


def fresh_check(selection, work, evidence, steps, result):
    row = selection["next"]
    folder = fetch("next", row, work, steps)
    need(install("next", folder, steps, evidence=evidence) == 0, "fresh-install-returned-nonzero")
    state = installed_state()
    result["afterFreshInstall"] = state
    need((state["release"], state["packageVersion"], state["packageSha256"])
         == (row["release"], row["packageVersion"], row["packageSha256"]), "fresh-installed-identity")
    # Install.pkg is a scripts-only package (PackageInfo + Scripts, no Payload),
    # so macOS records no pkgutil receipt; the protected state is the record.
    need(state["bundleShortVersion"] == row["packageVersion"], "fresh-bundle-version")
    need(state["receiptVersion"] is None, "fresh-unexpected-package-receipt")
    need(state["cliReturn"] == 0 and state["cliVersionLine"].startswith("mrk "), "fresh-cli-runs")
    result["firstLaunch"] = launch_smoke("first-launch", work, evidence, steps, observe=first_launch_observe)
    ui = result["firstLaunch"].get("ui") or {}
    # A missing accessibility read is recorded as not-observed, never a pass;
    # only a definite unavailable card, error marker or wrong CLI refusal fails.
    need(ui.get("runtimeCard") != "unavailable", "fresh-first-launch-runtime-unavailable")
    need(not ui.get("workspaceErrorMarkers"), "fresh-first-launch-workspace-error")
    need(ui.get("cliStatus", {}).get("returncode") == 3 and ui.get("cliStatus", {}).get("guidance"),
         "fresh-cli-status-guidance")
    data = manifest() if USER_DATA.exists() else {}
    result["appDataFilesAfterFirstLaunch"] = len(data)
    # Same package again: the no-op route keeps the installation and app data.
    same_rc = install("same", folder, steps, evidence=evidence)
    result["samePackageReturn"] = same_rc
    need(same_rc == 0, "same-package-returned-nonzero")
    again = installed_state()
    result["afterSamePackage"] = again
    need(again == state, "same-package-changed-installation")
    need((manifest() if USER_DATA.exists() else {}) == data, "same-package-changed-app-data")
    result["reopen"] = launch_smoke("reopen", work, evidence, steps)


SHEET_JXA = """function run(argv) {
  const se = Application('System Events');
  const matches = se.processes.whose({unixId: Number(argv[0])});
  if (matches.length !== 1) return 'no-process';
  const proc = matches[0];
  for (const w of proc.windows()) {
    const sheets = w.sheets();
    if (sheets.length !== 1) continue;
    const sheet = sheets[0];
    const names = sheet.buttons().map(b => b.name());
    const texts = sheet.staticTexts().map(t => t.value());
    if (names.length !== 2 || names.indexOf('Cancel') < 0 || names.indexOf('Continue and Quit') < 0) return 'unexpected:' + names.join('|');
    if (!texts.some(t => t === 'Quit and prepare to remove Mobile Release Kit?')) return 'unexpected-text';
    if (argv[1] === 'click') { sheet.buttons.byName('Continue and Quit').click(); return 'clicked'; }
    return 'present';
  }
  return 'absent';
}
"""
LAUNCHER = Path("/Applications/Mobile Release Kit.app")
REMOVAL_SIDECARS = ("Remove.pkg", "remove-producer.json", "remove-producer.sig")
UNINSTALLER = "Uninstall Mobile Release Kit.app"
UNINSTALLER_ID = "dev.mobile-release-kit.desktop.uninstaller"
APP_IDS = ("dev.mobile-release-kit.desktop", "dev.mobile-release-kit.desktop.entry", "dev.mobile-release-kit.desktop.launcher")
KEYCHAIN_SERVICES = ("dev.mobile-release-kit.desktop/vault/wrapping-key/v1",
                     "dev.mobile-release-kit.desktop/local-release/key/v1",
                     "dev.mobile-release-kit.desktop/local-release/checkpoint/v1")
DECOY_SERVICE = "dev.mobile-release-kit.desktop.decoy/keep/v1"
KEEP_LABEL = "Uninstall App (Keep My Data)"
DELETE_LABEL = "Uninstall App & Delete All Data"
DIALOG_JXA = """function run(argv) {
  const se = Application('System Events');
  const matches = se.processes.whose({bundleIdentifier: argv[0]});
  if (matches.length < 1) return JSON.stringify({state: 'no-process'});
  const wins = matches[0].windows();
  if (wins.length < 1) return JSON.stringify({state: 'no-window'});
  const w = wins[0];
  const buttons = w.buttons().map(b => b.name());
  const texts = w.staticTexts().map(t => { try { return t.value(); } catch (x) { return ''; } });
  if (argv[1] === 'click') {
    if (buttons.indexOf(argv[2]) < 0) return JSON.stringify({state: 'missing-button', buttons: buttons});
    w.buttons.byName(argv[2]).click();
    return JSON.stringify({state: 'clicked', buttons: buttons, texts: texts});
  }
  return JSON.stringify({state: 'dialog', buttons: buttons, texts: texts});
}
"""


def removal_image(row, work, steps):
    """Download the notarized Remove carrier and mount it read-only, as the
    owner would open it; the package runs only from the mounted image."""
    target = work / "removal"
    target.mkdir(mode=0o700)
    archive = target / "remove.zip"
    with open(archive, "wb") as out:
        p = subprocess.run(["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{row['artifactId']}/zip"],
                           stdout=out, stderr=subprocess.PIPE, timeout=900)
    need(p.returncode == 0, "removal-download")
    with zipfile.ZipFile(archive) as z:
        need(z.namelist() == ["MobileReleaseKit-Remove.dmg"], "removal-artifact-members")
        z.extract("MobileReleaseKit-Remove.dmg", target)
    archive.unlink()
    image = target / "MobileReleaseKit-Remove.dmg"
    need(digest(image) == row["imageSha256"], "removal-image-digest")
    p, r1 = run(["/usr/sbin/spctl", "-a", "-vv", "-t", "open", "--context", "context:primary-signature", str(image)], 120)
    steps.append(dict(r1, role="removal-image-gatekeeper"))
    need(p.returncode == 0 and "Notarized Developer ID" in (p.stdout + p.stderr), "removal-image-gatekeeper")
    p, r2 = run(["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", "-plist", str(image)], 300, check=True)
    steps.append(dict(r2, role="removal-image-attach"))
    mounts = [e["mount-point"] for e in plistlib.loads(p.stdout.encode())["system-entities"] if e.get("mount-point")]
    need(len(mounts) == 1, "removal-image-mount")
    mount = Path(mounts[0])
    package = mount / "Remove.pkg"
    need(package.is_file(), "removal-image-roster")
    # #83/#51: the image shows only the uninstaller; the package and its two
    # signed sidecars are present but hidden (UF_HIDDEN), never absent.
    names = sorted(n for n in os.listdir(mount) if not n.startswith("."))
    hidden = sorted(n for n in names if os.lstat(mount / n).st_flags & stat.UF_HIDDEN)
    need(names == sorted([*REMOVAL_SIDECARS, UNINSTALLER]), "removal-image-roster")
    need(hidden == sorted(REMOVAL_SIDECARS), "removal-image-hidden-sidecars")
    app = mount / UNINSTALLER
    p, r4 = run(["/usr/bin/codesign", "--verify", "--strict", "--deep", "-vv", str(app)], 120)
    steps.append(dict(r4, role="uninstaller-codesign"))
    need(p.returncode == 0, "uninstaller-codesign")
    p, r5 = run(["/usr/bin/codesign", "-d", "-r-", str(app)], 60)
    need(p.returncode == 0 and f'identifier "{UNINSTALLER_ID}"' in (p.stdout + p.stderr), "uninstaller-identifier")
    p, r6 = run(["/usr/sbin/spctl", "-a", "-vv", "-t", "exec", str(app)], 120)
    steps.append(dict(r6, role="uninstaller-gatekeeper"))
    need(p.returncode == 0 and "Notarized Developer ID" in (p.stdout + p.stderr), "uninstaller-gatekeeper")
    p, r3 = run(["/usr/sbin/pkgutil", "--check-signature", str(package)], 120)
    steps.append(dict(r3, role="removal-package-signature"))
    need(p.returncode == 0 and "Developer ID Installer" in p.stdout and "trusted by the Apple notary service" in p.stdout,
         "removal-package-signature")
    return mount, sorted(os.listdir(mount))


def stall_diagnostics(evidence, label):
    """Diagnostics only, captured while a live removal is still pending at the
    deadline: process table, stacks of the app and the remover, the request
    directory and the unified log of those processes, plus a screenshot.
    Never changes the verdict; every capture is bounded and best effort."""
    def capture(name, argv, timeout=90, keep=4000):
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            text = "\n".join(tail_text(p.stdout + p.stderr, keep))
        except Exception as error:  # diagnostics must not raise
            text = f"capture failed: {type(error).__name__}"
        (evidence / f"{label}-stall-{name}.txt").write_text(text + "\n")
    capture("ps", ["/bin/ps", "-axo", "pid,ppid,user,etime,stat,command"])
    remover = subprocess.run(["/usr/bin/pgrep", "-f", "Helpers/mrk-macos-remove"], capture_output=True, text=True, timeout=30)
    for role, pids in (("app", payload_pids()), ("remover", sorted(int(v) for v in remover.stdout.split()))):
        for pid in pids[:2]:
            capture(f"sample-{role}-{pid}", ["/usr/bin/sudo", "-n", "/usr/bin/sample", str(pid), "3"], 120, 1500)
    capture("requests", ["/usr/bin/sudo", "-n", "/bin/ls", "-laeOR", "/Library/Application Support/MobileReleaseKit-RemovalRequests"])
    capture("log", ["/usr/bin/log", "show", "--last", "6m", "--style", "compact", "--predicate",
                    f'(process == "{PAYLOAD_PROCESS}" OR process == "mrk-macos-remove" OR process == "mrk-macos-entry"'
                    ' OR process == "installd" OR process == "package_script_service")'
                    ' AND NOT (subsystem BEGINSWITH "com.apple.WebKit")'], 180)
    subprocess.run(["/usr/sbin/screencapture", "-x", str(evidence / f"screen-{label}-stall.png")], capture_output=True, timeout=60)


def live_remove(mount, work, evidence, steps, label):
    """Open the installed app, run the mounted Remove.pkg with the standard
    Installer and confirm only the app's own exact sheet; require Installer 0
    and no app, launcher or process left. Returns the observations."""
    out = {}
    # The live route asks the running app to confirm; open it first.
    p, r = run(["/usr/bin/open", str(APP)], 60)
    steps.append(dict(r, role=f"{label}-launch"))
    need(p.returncode == 0, f"{label}-launch-returned-nonzero")
    started = time.monotonic()
    pids = []
    while time.monotonic() - started < 90 and not (pids and window_count(pids[0], work)):
        time.sleep(2)
        pids = payload_pids()
    need(pids, f"{label}-app-not-running")
    time.sleep(10)
    script = work / "sheet.js"
    script.write_text(SHEET_JXA)
    log = open(evidence / f"{label}-installer.log", "w")
    installer = subprocess.Popen(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-verbose", "-pkg",
                                  str(mount / "Remove.pkg"), "-target", "/"], stdout=log, stderr=subprocess.STDOUT, text=True)
    sheet, clicked_at = [], None
    try:
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline and installer.poll() is None:
            live = payload_pids()
            if live and clicked_at is None:
                q = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(script), str(live[0]), "probe"],
                                   capture_output=True, text=True, timeout=30)
                state_text = (q.stdout.strip() or ("error:" + q.stderr.strip()[-160:]))
                if not sheet or sheet[-1] != state_text:
                    sheet.append(state_text)
                if state_text == "present":
                    subprocess.run(["/usr/sbin/screencapture", "-x", str(evidence / f"screen-{label}-sheet.png")],
                                   capture_output=True, timeout=60)
                    q = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(script), str(live[0]), "click"],
                                       capture_output=True, text=True, timeout=30)
                    sheet.append(q.stdout.strip() or ("error:" + q.stderr.strip()[-160:]))
                    if q.stdout.strip() == "clicked":
                        clicked_at = time.monotonic()
            time.sleep(2)
        if installer.poll() is None:
            stall_diagnostics(evidence, label)
            installer.kill()
            out["timedOut"] = True
        installer.wait(timeout=60)
    finally:
        log.close()
        out["sheet"] = sheet[-12:]
        # Keep the probe history even when this check fails below.
        (evidence / f"{label}-sheet-probes.json").write_text(json.dumps(sheet[-40:]) + "\n")
        # The app's fixed-code removal trace (no paths/ids), pass or fail.
        try:
            t = subprocess.run(["/usr/bin/log", "show", "--last", "8m", "--style", "compact", "--predicate",
                                'eventMessage BEGINSWITH "MRK_REMOVAL_TRACE"'], capture_output=True, text=True, timeout=180)
            trace = [line[:300] for line in t.stdout.splitlines() if "MRK_REMOVAL_TRACE" in line][-60:]
        except Exception as error:  # diagnostics must not raise
            trace = [f"capture failed: {type(error).__name__}"]
        out["appTrace"] = trace
        (evidence / f"{label}-app-trace.txt").write_text("\n".join(trace) + "\n")
    out["returncode"] = installer.returncode
    steps.append({"argv": ["installer", "-pkg", "Remove.pkg"], "returncode": installer.returncode, "role": label})
    need(clicked_at is not None, "removal-sheet-not-confirmed")
    need(installer.returncode == 0, "remove-returned-nonzero")
    time.sleep(5)
    remaining = {"app": APP.exists(), "launcher": LAUNCHER.exists(), "process": bool(payload_pids())}
    out["remaining"] = remaining
    need(not any(remaining.values()), "removal-left-app-objects")
    return out


def remove_check(selection, work, evidence, steps, result):
    """Fresh install, launch, live removal through the matching Remove.pkg
    (confirming the app's own sheet), then reinstall and launch again."""
    need("removal" in selection, "selection-has-no-removal-carrier")
    row = selection["next"]
    folder = fetch("next", row, work, steps)
    mount, roster = removal_image(selection["removal"], work, steps)
    result["removalImageRoster"] = roster
    need(install("next", folder, steps, evidence=evidence) == 0, "remove-baseline-install-returned-nonzero")
    state = installed_state()
    result["afterInstall"] = state
    need((state["release"], state["packageVersion"], state["packageSha256"])
         == (row["release"], row["packageVersion"], row["packageSha256"]), "remove-baseline-identity")
    seeded = seed_user_data()
    result["seededFiles"] = len(seeded)
    out = live_remove(mount, work, evidence, steps, "remove")
    result.update(removalSheet=out["sheet"], removeReturn=out["returncode"], afterRemoval=out["remaining"])
    if out.get("timedOut"):
        result["removeTimedOut"] = True
    kept = manifest()
    result["userDataPreservedByRemoval"] = all(kept.get(k) == v for k, v in seeded.items())
    need(result["userDataPreservedByRemoval"], "user-data-changed-by-removal")
    # Reinstall after confirmed removal with the matching installer.
    rc = install("reinstall", folder, steps, evidence=evidence)
    result["reinstallReturn"] = rc
    need(rc == 0, "reinstall-returned-nonzero")
    again = installed_state()
    result["afterReinstall"] = again
    need((again["release"], again["packageVersion"], again["packageSha256"])
         == (row["release"], row["packageVersion"], row["packageSha256"]), "reinstall-identity")
    need(all(manifest().get(k) == v for k, v in seeded.items()), "user-data-changed-by-reinstall")
    result["launchAfterReinstall"] = launch_smoke("after-reinstall", work, evidence, steps)
    try:
        uninstaller_check(mount, work, evidence, steps, result)
    finally:
        subprocess.run(["/usr/bin/hdiutil", "detach", "-force", str(mount)], capture_output=True, timeout=120)


def home_path(relative):
    return Path.home() / relative


DECOY_FILES = ("Library/Application Support/dev.mobile-release-kit.desktop.decoy/keep.txt",
               "Library/Caches/dev.mobile-release-kit.desktop-other/keep.txt",
               "Projects/MRKDecoyProject/README.md",
               "Projects/MRKDecoyProject/.mobile-release-kit/state.json",
               ".config/gh/mrk-decoy.txt",
               "MRKOutside/keep.txt",
               "MRKOutsideData/keep.txt")
# Exact per-user app locations the "delete all data" choice must remove.
DELETE_TARGETS = ("Library/Caches/dev.mobile-release-kit.desktop/fixture.bin",
                  "Library/WebKit/dev.mobile-release-kit.desktop/fixture.bin",
                  "Library/HTTPStorages/dev.mobile-release-kit.desktop.binarycookies",
                  "Library/Saved Application State/dev.mobile-release-kit.desktop.savedState/fixture.bin",
                  "Library/Logs/dev.mobile-release-kit.desktop/fixture.log",
                  "Library/Application Support/dev.mobile-release-kit.desktop.entry/fixture.json")
LINKED_TARGET = "Library/Caches/dev.mobile-release-kit.desktop.launcher"


def plant_decoys():
    for relative in DECOY_FILES:
        path = home_path(relative)
        need(not path.exists(), "decoy-preexists")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(os.urandom(512))
    return decoy_state()


def decoy_state():
    return {relative: digest(home_path(relative)) if home_path(relative).is_file() else None for relative in DECOY_FILES}


def keychain_has(service):
    return subprocess.run(["/usr/bin/security", "find-generic-password", "-s", service],
                          capture_output=True, timeout=30).returncode == 0


def installer_running():
    return subprocess.run(["/usr/bin/pgrep", "-x", "Installer"], capture_output=True, timeout=30).returncode == 0


def uninstaller_run(mount, work, evidence, label, answers, timeout=240):
    """Open the mounted uninstaller as the owner would and answer its dialogs
    in order. An answer is a button name, or None to quit Installer once the
    uninstaller has opened it (Installer is quit before any step runs, so
    nothing is removed by it). Returns every dialog seen."""
    script = work / "dialog.js"
    script.write_text(DIALOG_JXA)

    def ask(*args):
        q = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(script), UNINSTALLER_ID, *args],
                           capture_output=True, text=True, timeout=30)
        try:
            return json.loads(q.stdout)
        except ValueError:
            return {"state": "error", "detail": q.stderr.strip()[-160:]}

    need(not installer_running(), f"{label}-installer-already-running")
    p, _ = run(["/usr/bin/open", "-n", str(mount / UNINSTALLER)], 60)
    need(p.returncode == 0, f"{label}-open-returned-{p.returncode}")
    seen, deadline = [], time.monotonic() + timeout
    for step, answer in enumerate(answers):
        if answer is None:
            while time.monotonic() < deadline and not installer_running():
                time.sleep(1)
            need(installer_running(), f"{label}-installer-not-opened")
            time.sleep(5)
            subprocess.run(["/usr/sbin/screencapture", "-x", str(evidence / f"screen-{label}-installer.png")],
                           capture_output=True, timeout=60)
            subprocess.run(["/usr/bin/osascript", "-e", 'tell application id "com.apple.installer" to quit'],
                           capture_output=True, timeout=30)
            quit_by = time.monotonic() + 15
            while installer_running() and time.monotonic() < quit_by:
                time.sleep(1)
            if installer_running():
                subprocess.run(["/usr/bin/pkill", "-x", "Installer"], capture_output=True, timeout=30)
            seen.append({"installer": "quit"})
            continue
        # An answer may name a second button that must be on the same dialog,
        # so a shared "Cancel" is never clicked on the wrong one.
        answer, also = answer if isinstance(answer, tuple) else (answer, answer)
        state, wanted = {}, lambda st: st.get("state") == "dialog" and {answer, also} <= set(st.get("buttons", []))
        while time.monotonic() < deadline:
            state = ask("probe")
            if wanted(state):
                break
            time.sleep(1)
        need(wanted(state), f"{label}-dialog-{step}-missing")
        subprocess.run(["/usr/sbin/screencapture", "-x", str(evidence / f"screen-{label}-{step}.png")],
                       capture_output=True, timeout=60)
        home = str(Path.home())
        seen.append({"buttons": state["buttons"], "texts": [t.replace(home, "~") for t in state.get("texts", [])],
                     "answer": answer})
        clicked = ask("click", answer)
        need(clicked.get("state") == "clicked", f"{label}-dialog-{step}-click")
        closed_by = time.monotonic() + 15
        while time.monotonic() < closed_by:
            after = ask("probe")
            if (after.get("buttons"), after.get("texts")) != (state.get("buttons"), state.get("texts")):
                break
            time.sleep(0.5)
    while time.monotonic() < deadline and ask("probe").get("state") != "no-process":
        time.sleep(1)
    need(ask("probe").get("state") == "no-process", f"{label}-uninstaller-did-not-exit")
    need(not installer_running(), f"{label}-installer-left-running")
    return seen


def dialog_says(seen, fragment):
    return any(fragment in text for row in seen for text in row.get("texts", []))


def uninstaller_check(mount, work, evidence, steps, result):
    """#83: the Remove image's signed uninstaller. While the app is installed:
    cancelling either choice, or quitting Installer, removes and deletes
    nothing, and the data script refuses. After a second confirmed removal,
    "Delete All Data" removes only the app's own exact per-user locations and
    keychain items; links, look-alike siblings, projects and other files stay."""
    out = result["uninstaller"] = {}
    script = mount / UNINSTALLER / "Contents/Resources/delete-data.sh"
    need(script.is_file(), "uninstaller-data-script-missing")
    decoys = plant_decoys()
    before = manifest()
    need(before, "uninstaller-no-user-data")

    def unchanged(tag):
        need(APP.exists(), f"{tag}-app-removed")
        need(manifest() == before, f"{tag}-user-data-changed")
        need(decoy_state() == decoys, f"{tag}-decoy-changed")

    seen = uninstaller_run(mount, work, evidence, "uninstall-cancel-delete",
                           [DELETE_LABEL, ("Cancel", "Delete All Data")])
    out["cancelAtDeleteConfirmation"] = seen
    need(sorted(seen[0]["buttons"]) == sorted(["Cancel", DELETE_LABEL, KEEP_LABEL]), "uninstaller-choice-buttons")
    unchanged("uninstall-cancel-delete")
    out["cancelBeforeInstallerKeep"] = uninstaller_run(mount, work, evidence, "uninstall-cancel-keep",
                                                       [KEEP_LABEL, ("Cancel", "Continue")])
    unchanged("uninstall-cancel-keep")
    # Failure recovery: Installer quit without removing; nothing may be deleted.
    seen = uninstaller_run(mount, work, evidence, "uninstall-installer-quit",
                           [DELETE_LABEL, "Delete All Data", "Continue", None, "OK"])
    out["installerQuitWhileInstalled"] = seen
    need(dialog_says(seen, "still installed, so none of your data was deleted"), "uninstall-installer-quit-message")
    unchanged("uninstall-installer-quit")
    p, r = run(["/bin/sh", str(script)], 60)
    steps.append(dict(r, role="delete-data-while-installed"))
    out["dataScriptWhileInstalled"] = p.returncode
    need(p.returncode == 65, "delete-data-not-refused-while-installed")
    unchanged("delete-data-while-installed")

    second = live_remove(mount, work, evidence, steps, "remove-again")
    out["secondRemoval"] = second
    need(manifest() == before, "user-data-changed-by-second-removal")

    # Exact app locations, a link at one of them, a link inside the app data,
    # and keychain items: the app's exact services plus a look-alike decoy.
    for relative in DELETE_TARGETS:
        path = home_path(relative)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(os.urandom(256))
    link = home_path(LINKED_TARGET)
    need(not link.exists() and not link.is_symlink(), "linked-target-preexists")
    link.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    link.symlink_to(home_path("MRKOutside"))
    (USER_DATA / "link-out").symlink_to(home_path("MRKOutsideData"))
    subprocess.run(["/usr/bin/defaults", "write", APP_IDS[0], "mrkFixture", "-bool", "YES"], check=True, timeout=30)
    out["appKeychainItemsBefore"] = {svc: keychain_has(svc) for svc in KEYCHAIN_SERVICES}
    for svc in (*KEYCHAIN_SERVICES, DECOY_SERVICE):
        subprocess.run(["/usr/bin/security", "add-generic-password", "-A", "-a", "mrk-fixture", "-s", svc,
                        "-w", os.urandom(16).hex()], check=True, capture_output=True, timeout=30)
    seen = uninstaller_run(mount, work, evidence, "uninstall-delete",
                           [DELETE_LABEL, "Delete All Data", "Continue", None, "OK"])
    out["deleteAllData"] = seen
    gone = {relative: not home_path(relative).exists() for relative in DELETE_TARGETS}
    gone["Library/Application Support/dev.mobile-release-kit.desktop"] = not USER_DATA.exists() and not USER_DATA.is_symlink()
    gone["Library/Preferences/dev.mobile-release-kit.desktop.plist"] = not home_path(
        "Library/Preferences/dev.mobile-release-kit.desktop.plist").exists()
    out["deleted"] = gone
    out["keychainAfter"] = {svc: keychain_has(svc) for svc in (*KEYCHAIN_SERVICES, DECOY_SERVICE)}
    out["linkKept"] = link.is_symlink()
    out["decoysUnchanged"] = decoy_state() == decoys
    subprocess.run(["/usr/bin/security", "delete-generic-password", "-s", DECOY_SERVICE], capture_output=True, timeout=30)
    need(all(gone.values()), "delete-all-data-left-app-data")
    need(not any(out["keychainAfter"][svc] for svc in KEYCHAIN_SERVICES), "delete-all-data-left-keychain-item")
    need(out["keychainAfter"][DECOY_SERVICE], "delete-all-data-removed-decoy-keychain-item")
    need(out["linkKept"] and out["decoysUnchanged"], "delete-all-data-touched-other-files")
    need(dialog_says(seen, "was removed, but some data was kept") and dialog_says(seen, "kept (link, not followed)"),
         "delete-all-data-did-not-report-kept-link")
    need(not APP.exists() and not LAUNCHER.exists(), "delete-all-data-app-present")


if __name__ == "__main__":
    sys.exit(main())
