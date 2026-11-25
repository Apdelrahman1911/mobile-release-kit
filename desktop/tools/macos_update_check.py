"""Hosted install, update and first-launch check for the installed macOS app.

Each check runs on its own fresh disposable runner.

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
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from collections import deque
from contextlib import contextmanager
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


def selected_release_roles(data):
    return [role for role in ("initial", "intermediate", "bridge", "previous", "next") if role in data]


def load_selection(path):
    data = json.loads(Path(path).read_text())
    required = {"schemaVersion", "previous", "next"}
    need(type(data) is dict and required <= set(data) <= required | {"initial", "intermediate", "bridge", "removal", "previousRemoval", "recoveryInstall", "recoveryRemoval"}
         and ("intermediate" not in data or "initial" in data)
         and ("bridge" not in data or {"intermediate", "previousRemoval"} <= set(data))
         and (("recoveryInstall" in data) == ("recoveryRemoval" in data))
         and data["schemaVersion"] == 1, "selection-shape")
    for key in ("removal", "previousRemoval", "recoveryRemoval"):
        if key not in data:
            continue
        row = data[key]
        need(set(row) == {"runId", "artifactId", "imageSha256"}
             and re.fullmatch(r"[1-9][0-9]{0,19}", row["runId"]) and re.fullmatch(r"[1-9][0-9]{0,19}", row["artifactId"])
             and hex_field(row["imageSha256"], 64), "selection-removal-fields")
    roles = selected_release_roles(data)
    if "recoveryInstall" in data:
        roles.insert(roles.index("next"), "recoveryInstall")
    for role in roles:
        row = data[role]
        need(set(row) == {"runId", "artifactId", "carrierArtifactId", "packageSha256", "packageVersion", "release"}, f"selection-{role}")
        need(re.fullmatch(r"[1-9][0-9]{0,19}", row["runId"]) and re.fullmatch(r"[1-9][0-9]{0,19}", row["artifactId"])
             and re.fullmatch(r"[1-9][0-9]{0,19}", row["carrierArtifactId"])
             and hex_field(row["packageSha256"], 64) and re.fullmatch(r"\d+\.\d+\.\d+", row["packageVersion"])
             and re.fullmatch(r"macos26-arm64-desktop-[0-9]+", row["release"]), f"selection-{role}-fields")
    key = lambda v: tuple(int(x) for x in v.split("."))
    need(all(key(data[old]["packageVersion"]) < key(data[new]["packageVersion"])
             for old, new in zip(roles, roles[1:])), "selection-not-an-upgrade")
    return data


def fetch(role, row, work, steps):
    target = work / role
    target.mkdir(mode=0o700)
    def download(artifact, members, label):
        archive = target / f"{label}.zip"
        deadline = time.monotonic() + 900
        downloaded = False
        for attempt in range(1, 4):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                with archive.open("wb") as out:
                    p = subprocess.run(["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{artifact}/zip"],
                                       stdout=out, stderr=subprocess.PIPE, timeout=remaining)
            except subprocess.TimeoutExpired:
                break
            steps.append({"role": f"{role}-{label}-download", "attempt": attempt,
                          "returncode": p.returncode, "artifactId": str(artifact)})
            if p.returncode == 0:
                downloaded = True
                break
            if attempt < 3:
                time.sleep(min(2 ** attempt, max(0, deadline - time.monotonic())))
        need(downloaded, f"{role}-{label}-download")
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
    frozen = os.environ.get("MRK_FROZEN_RELEASE_MEDIA")
    if frozen:
        media = Path(frozen)
        manifest = json.loads((media / "RELEASE-MANIFEST.json").read_bytes())
        if digest(folder / "Install.pkg") == manifest["packages"]["Install.pkg"]["sha256"]:
            name = f"MobileReleaseKit-{manifest['version']}-macos-arm64-Install.dmg"
            image = media / name
            need(digest(image) == manifest["images"][name]["sha256"], "frozen-install-image-digest")
            p, row = run(["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen",
                          "-plist", str(image)], 300, check=True)
            steps.append(dict(row, role=role))
            mounts = [e["mount-point"] for e in plistlib.loads(p.stdout.encode())["system-entities"] if e.get("mount-point")]
            need(len(mounts) == 1 and Path(mounts[0]).parent == Path("/Volumes"), "frozen-install-mount")
            mount = Path(mounts[0])
            expected = {"Install.pkg": folder / "Install.pkg", **{
                name: folder / "producer-root" / name for name in ("producer.json", "producer.sig")}}
            try:
                need(all(digest(mount / name) == digest(path) for name, path in expected.items()),
                     "frozen-install-carrier-pair")
            except BaseException:
                run(["/usr/bin/hdiutil", "detach", str(mount)], 45, check=True)
                raise
            return mount
    source = folder / f"carrier-{role}"
    source.mkdir(mode=0o755)
    for name, origin in (("Install.pkg", folder / "Install.pkg"),
                         ("producer.json", folder / "producer-root/producer.json"),
                         ("producer.sig", folder / "producer-root/producer.sig")):
        os.link(origin, source / name) if name == "Install.pkg" else (source / name).write_bytes(origin.read_bytes())
    image, volume = folder / f"carrier-{role}.dmg", f"MRK-Update-{role}"
    p, row = run(["/usr/bin/hdiutil", "create", "-srcfolder", str(source), "-fs", "HFS+", "-format", "UDRO",
                  "-volname", volume, str(image)], 600)
    steps.append(dict(row, role=role))
    if p.returncode != 0:
        steps[-1]["stderr"] = tail_text(p.stderr, 8)
        raise Failed(f"{role}-carrier-create")
    p, row = run(["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", str(image)], 300)
    steps.append(dict(row, role=role))
    if p.returncode != 0:
        steps[-1]["stderr"] = tail_text(p.stderr, 8)
        raise Failed(f"{role}-carrier-attach")
    mount = Path("/Volumes") / volume
    need(sorted(os.listdir(mount)) == ["Install.pkg", "producer.json", "producer.sig"], f"{role}-carrier-roster")
    need(digest(mount / "Install.pkg") == digest(folder / "Install.pkg"), f"{role}-carrier-digest")
    return mount


def install(role, folder, steps, expect_success=True, evidence=None):
    mount = carrier_image(role, folder, steps)
    try:
        p, row = run(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-verbose", "-pkg", str(mount / "Install.pkg"),
                      "-target", "/"], 1500)
        row.update(role=role, expected="success" if expect_success else "refusal")
        steps.append(row)
        if expect_success and p.returncode != 0 and evidence is not None:
            try:
                failure_diagnostics(evidence, role, p)
            except Exception as error:  # diagnostics must not mask the result
                row["diagnostics"] = type(error).__name__
    finally:
        try:
            detached, row = run(["/usr/bin/hdiutil", "detach", str(mount)], 45)
            steps.append(dict(row, role=role))
            if detached.returncode != 0:
                steps[-1]["stderr"] = tail_text(detached.stderr, 8)
        except (OSError, subprocess.TimeoutExpired) as error:
            steps.append({"role": role, "mediaDetach": type(error).__name__})
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


def recent_crash_paths(minutes=10):
    paths = {}
    for folder in (Path("/Library/Logs/DiagnosticReports"), Path.home() / "Library/Logs/DiagnosticReports"):
        r = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/find", str(folder), "-mmin", f"-{minutes}", "-type", "f", "-print0"],
                           capture_output=True, text=True, timeout=60)
        for entry in r.stdout.split("\0"):
            path = Path(entry)
            if PAYLOAD_PROCESS in path.name or "mrk-macos" in path.name or "Mobile Release Kit" in path.name:
                paths[path.name] = path
    return paths


def recent_crashes(minutes=10):
    return sorted(recent_crash_paths(minutes))


def crash_report_facts(path, observed_pids):
    """Return closed process, exception and termination facts from a hosted .ips report."""
    try:
        if path.suffix != ".ips":
            return {"read": False}
        limit = 4 * 1024 * 1024
        with path.open("rb") as source:
            body = source.read(limit + 1)
        if len(body) > limit:
            return {"read": False}
        _, report = body.split(b"\n", 1)
        facts = json.loads(report)
        name = facts.get("procName")
        role = {PAYLOAD_PROCESS: "payload", "mrk-macos-entry": "entry", "mrk-macos-launcher": "launcher",
                "mrk-macos-remove": "remover", "mrk-macos-install": "installer"}.get(name, "other-product")
        exception = facts.get("exception", {}).get("type")
        termination = facts.get("termination", {}).get("namespace")
        return {"read": True, "role": role, "pidSeenThisLaunch": facts.get("pid") in observed_pids,
                "exception": exception if re.fullmatch(r"EXC_[A-Z_]{1,32}", str(exception)) else None,
                "termination": termination if re.fullmatch(r"[A-Z0-9_]{1,24}", str(termination)) else None}
    except (OSError, ValueError, AttributeError, TypeError):
        return {"read": False}


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
    const preferred = ['AXLink', 'AXButton', 'AXCheckBox', 'AXRadioButton', 'AXTab', 'AXMenuItem'];
    for (const pass of [true, false]) {
      for (const e of all) {
        if (label(e) !== argv[2] || preferred.includes(role(e)) !== pass || (argv[3] && role(e) !== argv[3])) continue;
        try { if (e.enabled() === false) continue; } catch (x) {}
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
RUNTIME_DETAILS_LABEL = "Advanced · app connection details"
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
    details = None
    runtime_labels = {RUNTIME_AVAILABLE_TEXT, RUNTIME_UNAVAILABLE_TEXT}
    if navigate.get("clicked") == "Build tools" and not tools.get("error") and not runtime_labels.intersection(texts):
        # The healthy card starts collapsed. An unhealthy card stays open.
        # Opening this disclosure leaves the original connection untouched.
        details = ui_query(pid, work, "click", RUNTIME_DETAILS_LABEL)
        if details.get("clicked") == RUNTIME_DETAILS_LABEL:
            tools = ui_query(pid, work, "texts")
            texts += tools.get("texts") or []
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
            "navigate": navigate, "runtimeDetails": details, "buildToolsTexts": len(card), "buildToolsError": tools.get("error"),
            "runtimeCard": runtime, "workspaceErrorMarkers": sorted({m for m in WORKSPACE_ERROR_MARKERS
                                                                     for t in texts if m in t}),
            "cliStatus": status, "screenshot": shot.name if shot.exists() else None}


COLD_MARKER = re.compile(rb"^MRK(?:DBG_DESKTOP_BOOTSTRAP|_DESKTOP_CAPABILITIES|_RUNTIME_INSPECTION_FAILED)=[a-zA-Z0-9_-]{1,140}$")


def time_bootstrap(trace, started, stop, observations):
    with trace.open("rb") as stream:
        for _ in range(1200):
            for raw in stream.readlines(64 * 1024):
                if COLD_MARKER.fullmatch(raw.rstrip(b"\n")) and len(observations) < 128:
                    observations.append({"second": round(time.monotonic() - started, 3),
                                         "event": raw.decode("ascii").strip()})
            if stop.wait(0.05):
                break


def capture_cold_runtime(evidence, label, started, observations, stop):
    end = time.monotonic() + 40
    while time.monotonic() < end and not stop.wait(0.03):
        if any(item["event"] == "MRKDBG_DESKTOP_BOOTSTRAP=app-info-enter" for item in observations):
            pids = payload_pids()
            if len(pids) == 1:
                break
    else:
        return
    sampled_at = time.monotonic() - started
    load = []
    try:
        if os.environ.get("MRK_COLD_RUNTIME_SAMPLE") == "contention" and label == "first-launch":
            code = ("import hashlib,time\nend=time.monotonic()+13\n"
                    "block=bytes(32*1024*1024)\n"
                    "while time.monotonic()<end: hashlib.sha256(block).digest()\n")
            for _ in range(max(1, min((os.cpu_count() or 2) - 1, 3))):
                load.append(subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", code],
                                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL))
        with tempfile.TemporaryFile(mode="w+t", dir=evidence.parent, errors="replace") as trace:
            p = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/sample", str(pids[0]), "13", "5"],
                               stdout=trace, stderr=subprocess.DEVNULL, timeout=24)
            trace.seek(0)
            sample = trace.read(8 * 1024 * 1024).splitlines()
    finally:
        for child in load:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
    markers = ("installed_runtime", "supervisor", "vault_acl", "directory_block", "fstat",
               "sha256", "posix_spawn", "bootstrap", "wait_for_response", "capabilities", "SecStaticCode")
    kept = [f"sample began {sampled_at:.3f}s after open; return={p.returncode}; workload processes={len(load)}"]
    in_graph = False
    per_marker = dict.fromkeys(markers, 0)
    for row in sample:
        if row.startswith("Call graph:"):
            in_graph = True
        if row.startswith("Total number in stack"):
            break
        if not in_graph or len(row) > 1400:
            continue
        for marker in markers:
            if marker in row and per_marker[marker] < 55:
                kept.append(row.strip())
                per_marker[marker] += 1
                break
    (evidence / f"{label}-bootstrap-sample.txt").write_text("\n".join(kept) + "\n")


class BootstrapJournal:
    def __init__(self, sink, started):
        self.sink = sink
        self.started = started
        self.lock = threading.Lock()
        self.app_info = threading.Event()

    def record(self, event, origin="runner", **facts):
        with self.lock:
            record = {"elapsedSeconds": round(time.monotonic() - self.started, 3),
                      "observedAtUnixNs": time.time_ns(), "origin": origin, "event": event, **facts}
            self.sink.write(json.dumps(record, separators=(",", ":")) + "\n")
            self.sink.flush()
            os.fsync(self.sink.fileno())
            if event == "MRKDBG_DESKTOP_BOOTSTRAP=app-info-enter":
                self.app_info.set()

    def read_markers(self, trace, stop):
        budget = 1024 * 1024
        pending = b""
        markers = 0
        try:
            with trace.open("rb", buffering=0) as raw:
                while budget:
                    data = raw.read(min(budget, 8192))
                    if not data:
                        if stop.wait(0.05) and not (data := raw.read(min(budget, 8192))):
                            return
                        if not data:
                            continue
                    budget -= len(data)
                    lines = (pending + data).split(b"\n")
                    pending = lines.pop()
                    for line in lines:
                        if COLD_MARKER.fullmatch(line):
                            self.record(line.decode("ascii"), origin="app-stderr")
                            markers += 1
                            if markers == 128:
                                self.record("marker-count-limit")
                                return
                self.record("stderr-byte-limit")
        except OSError as error:
            self.record("marker-reader-error", error=type(error).__name__)


def capture_durable_contention(journal, ready, finished):
    # Demand real scheduled CPU work before the first LaunchServices request.
    if finished.is_set():
        return
    load = []
    benchmark = ("import hashlib,time\nblock=bytes(32*1024*1024)\n"
                 "until=time.monotonic()+28\n"
                 "while time.monotonic()<until: hashlib.sha256(block).digest()\n")
    try:
        for _ in range(max(1, min(os.cpu_count() or 2, 4))):
            load.append(subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", benchmark],
                                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL))
        journal.record("pressure-started", workers=len(load))
        process_list = ",".join(str(worker.pid) for worker in load)
        for _ in range(12):
            if finished.wait(0.25):
                break
            sample, _ = run(["/bin/ps", "-o", "time=", "-p", process_list], 3)
            times = sample.stdout.splitlines()
            active = sum(any(digit in "123456789" for digit in elapsed) for elapsed in times)
            if sample.returncode == 0 and active == len(load):
                journal.record("pressure-cpu-observed", activeWorkers=active)
                ready.set()
                break
        for child in load:
            child.wait(timeout=31)
        journal.record("pressure-finished", workerExits=[child.returncode for child in load])
    except (OSError, subprocess.TimeoutExpired) as error:
        journal.record("pressure-error", error=type(error).__name__)
    finally:
        for child in load:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)


@contextmanager
def durable_bootstrap(work, evidence, label):
    trace = work / f"{label}-bootstrap-stderr.private"
    trace.touch(mode=0o600, exist_ok=False)
    stop = threading.Event()
    with (evidence / f"{label}-bootstrap-journal.jsonl").open("x", encoding="utf-8") as sink:
        journal = BootstrapJournal(sink, time.monotonic())
        journal.record("capture-start")
        reader = threading.Thread(target=journal.read_markers, args=(trace, stop), daemon=True)
        reader.start()
        pressure = None
        ready = threading.Event()
        if os.environ.get("MRK_COLD_RUNTIME_SAMPLE", "").startswith("contention"):
            pressure = threading.Thread(target=capture_durable_contention, args=(journal, ready, stop), daemon=True)
            pressure.start()
        try:
            if pressure is not None:
                need(ready.wait(7), "cold-contention-not-ready-before-open")
            yield trace, journal
        except subprocess.TimeoutExpired as error:
            journal.record("launch-observation-timeout", limitSeconds=error.timeout)
            raise
        except Exception as error:
            journal.record("launch-observation-error", error=type(error).__name__)
            raise
        finally:
            stop.set()
            reader.join(timeout=3)
            if pressure is not None:
                pressure.join(timeout=37)
            journal.record("capture-finished", readerDrained=not reader.is_alive(),
                           pressureDrained=pressure is None or not pressure.is_alive())


def launch_smoke(label, work, evidence, steps, observe=None, steady_idle_seconds=0, steady_interval=1):
    if os.environ.get("MRK_COLD_RUNTIME_DURABLE") == "true" and label == "first-launch":
        with durable_bootstrap(work, evidence, label) as capture:
            return observe_launch(label, work, evidence, steps, observe, steady_idle_seconds, steady_interval, capture)
    return observe_launch(label, work, evidence, steps, observe, steady_idle_seconds, steady_interval)


def observe_launch(label, work, evidence, steps, observe, steady_idle_seconds, steady_interval, durable=None):
    """Open the installed app as the logged-in runner user and require a live
    payload process with an on-screen window and no crash report."""
    need(not payload_pids(), f"{label}-app-already-running")
    before = set(recent_crashes())
    started = time.monotonic()
    argv = ["/usr/bin/open"]
    if durable:
        capture_path, journal = durable
        argv += ["--stderr", str(capture_path)]
    cold = durable is None and os.environ.get("MRK_COLD_RUNTIME_DIAGNOSTIC") == "true" and label in ("first-launch", "warm-after-timeout")
    trace = work / f"{label}-bootstrap-stderr.txt"
    sample = None
    timing_stop = threading.Event()
    observations = []
    if cold:
        trace.touch(mode=0o600, exist_ok=False)
        argv += ["--stderr", str(trace)]
        timing = threading.Thread(target=time_bootstrap, args=(trace, started, timing_stop, observations), daemon=True)
        timing.start()
        if os.environ.get("MRK_COLD_RUNTIME_SAMPLE") in ("profile", "contention"):
            sample = threading.Thread(target=capture_cold_runtime,
                                      args=(evidence, label, started, observations, timing_stop), daemon=True)
            sample.start()
    if durable:
        journal.record("open-request")
    p, row = run([*argv, str(APP)], 60)
    if durable:
        journal.record("open-returned", returnCode=p.returncode)
    steps.append(dict(row, role=label))
    need(p.returncode == 0, f"{label}-open-returned-{p.returncode}")
    pids, windows, samples = [], None, []
    observed_pids = set()
    while time.monotonic() - started < 90:
        pids = payload_pids()
        observed_pids.update(pids)
        if pids:
            samples.append(resource_sample(pids[0], started, "startup"))
            windows = window_count(pids[0], work)
            if windows:
                break
        time.sleep(2)
    first_window = round(time.monotonic() - started, 1) if windows else None
    if durable:
        journal.record("first-window-observed" if windows else "first-window-unobserved")
    for _ in range(15):  # still alive and showing a window after the first paint
        time.sleep(1)
        live = payload_pids()
        observed_pids.update(live)
        if live:
            samples.append(resource_sample(live[0], started, "idle"))
    steady_samples = []
    if steady_idle_seconds and pids and windows:
        # Preserve the short sample for comparison with earlier runs. Measure
        # a separate later interval on the same process without UI activity.
        steady_started = time.monotonic()
        for _ in range(steady_idle_seconds // steady_interval):
            time.sleep(steady_interval)
            if pids[0] not in payload_pids():
                break
            steady_samples.append(resource_sample(pids[0], steady_started, "idle"))
    alive = payload_pids()
    observed_pids.update(alive)
    settled = window_count(alive[0], work) if alive else None
    shot = evidence / f"screen-{label}.png"
    subprocess.run(["/usr/sbin/screencapture", "-x", str(shot)], capture_output=True, timeout=60)
    ui = observe(alive[0], work, evidence, label) if observe and alive and settled else None
    if durable:
        journal.record("build-tools-observed", runtimeCard=(ui or {}).get("runtimeCard", "not-observed"))
    reports = recent_crash_paths()
    new_reports = sorted(set(reports) - before)
    # A resource diagnostic from the completed Installer is a separate
    # observation from an app crash that occurred during this launch.
    installer_diagnostics = [name for name in new_reports
                             if name.startswith("mrk-macos-install_") and name.endswith(".diag")]
    crashes = [name for name in new_reports if name not in installer_diagnostics]
    observed = {"label": label, "processSeen": bool(pids), "secondsToFirstWindow": first_window,
                "resources": resource_summary(samples),
                "aliveAfterSettle": bool(alive), "windowsAfterSettle": settled, "newCrashReports": crashes,
                "screenshot": shot.name if shot.exists() else None}
    if installer_diagnostics:
        observed["installerDiagnosticReports"] = installer_diagnostics
    if crashes:
        observed["crashReportFacts"] = [crash_report_facts(reports[name], observed_pids) for name in crashes[:10]]
    if ui is not None:
        observed["ui"] = ui
    if steady_idle_seconds:
        observed["steadyIdleResources"] = steady_resource_summary(steady_samples, steady_idle_seconds, steady_interval)
        if steady_interval > 1:
            (evidence / f"{label}-resources.json").write_text(json.dumps(steady_samples) + "\n")
    (evidence / f"{label}-launch.json").write_text(json.dumps(observed, indent=2) + "\n")
    if alive:
        stop_app(alive)
    if cold:
        timing_stop.set()
    if sample is not None:
        sample.join(timeout=25)
    if cold:
        timing.join(timeout=2)
        (evidence / f"{label}-bootstrap-status.json").write_text(json.dumps(observations, indent=2) + "\n")
    need(pids, f"{label}-app-process-not-started")
    need(not crashes, f"{label}-app-crashed")
    need(alive and settled, f"{label}-app-window-missing")
    return observed


def resource_sample(pid, started, phase):
    """RSS (KiB) and CPU (%) of the app process and all its descendants (#66)."""
    p = subprocess.run(["/bin/ps", "-A", "-o", "pid=,ppid=,rss=,%cpu="], capture_output=True, text=True, timeout=30)
    rows = {}
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) == 4:
            try:
                rows[int(parts[0])] = (int(parts[1]), int(parts[2]), float(parts[3]))
            except ValueError:
                continue
    tree, grew = {pid}, True
    while grew:
        grew = False
        for child, (parent, _rss, _cpu) in rows.items():
            if parent in tree and child not in tree:
                tree.add(child)
                grew = True
    present = [rows[q] for q in tree if q in rows]
    return {"t": round(time.monotonic() - started, 1), "phase": phase, "processes": len(present),
            "rssKiB": sum(r[1] for r in present), "cpuPercent": round(sum(r[2] for r in present), 1),
            "appRssKiB": rows[pid][1] if pid in rows else None}


def resource_summary(samples):
    idle = [s for s in samples if s["phase"] == "idle"]
    return {"samples": len(samples), "peakRssKiB": max((s["rssKiB"] for s in samples), default=None),
            "idleRssKiB": idle[-1]["rssKiB"] if idle else None,
            "idleAppRssKiB": idle[-1]["appRssKiB"] if idle else None,
            "idleMeanCpuPercent": round(sum(s["cpuPercent"] for s in idle) / len(idle), 1) if idle else None,
            "peakProcesses": max((s["processes"] for s in samples), default=None),
            "method": "ps rss/%cpu of the app process tree; startup every 2 s until the first window, then 15 x 1 s idle"}


def steady_resource_summary(samples, seconds, interval):
    summary = resource_summary(samples)
    summary.update(plannedSamples=seconds // interval,
                   sampleWindowSeconds=samples[-1]["t"] if samples else None,
                   method=f"ps rss/%cpu of the same app process tree every {interval} s after the initial idle sample")
    if len(samples) >= 2:
        size = max(1, len(samples) // 12)
        summary["firstWindowMeanRssKiB"] = round(sum(s["rssKiB"] for s in samples[:size]) / size)
        summary["lastWindowMeanRssKiB"] = round(sum(s["rssKiB"] for s in samples[-size:]) / size)
        summary["firstWindowMeanCpuPercent"] = round(sum(s["cpuPercent"] for s in samples[:size]) / size, 1)
        summary["lastWindowMeanCpuPercent"] = round(sum(s["cpuPercent"] for s in samples[-size:]) / size, 1)
        summary["actualSampleSpanSeconds"] = round(samples[-1]["t"] - samples[0]["t"], 1)
        summary["rssWindowSamples"] = size
    return summary


def json_files_intact():
    """Every JSON file in the app data parses: no partial write survived (#65)."""
    broken = []
    for path in sorted(USER_DATA.rglob("*.json")) if USER_DATA.exists() else []:
        if path.is_file() and not path.is_symlink():
            try:
                json.loads(path.read_bytes())
            except ValueError:
                broken.append(str(path.relative_to(USER_DATA)))
    return broken


def kill_and_relaunch(label, work, evidence, steps, when):
    """#65: SIGKILL the app (as a crash would: the app only, no cleanup) during
    startup or at idle, then require an intact data folder and a normal relaunch."""
    need(not payload_pids(), f"{label}-app-already-running")
    before = manifest() if USER_DATA.exists() else {}
    p, row = run(["/usr/bin/open", str(APP)], 60)
    steps.append(dict(row, role=label + "-open"))
    need(p.returncode == 0, f"{label}-open-returned-{p.returncode}")
    started, pids = time.monotonic(), []
    while time.monotonic() - started < 90 and not pids:
        time.sleep(0.25)
        pids = payload_pids()
    need(pids, f"{label}-app-process-not-started")
    if when == "startup":
        time.sleep(1.0)
    else:
        while time.monotonic() - started < 90 and not window_count(pids[0], work):
            time.sleep(1)
        time.sleep(5)
        before = manifest() if USER_DATA.exists() else {}
    killed_at = round(time.monotonic() - started, 1)
    for pid in payload_pids():
        os.kill(pid, signal.SIGKILL)
    deadline = time.monotonic() + 20
    while payload_pids() and time.monotonic() < deadline:
        time.sleep(0.5)
    need(not payload_pids(), f"{label}-app-survived-sigkill")
    time.sleep(2)
    after = manifest() if USER_DATA.exists() else {}
    broken = json_files_intact()
    observed = {"killedAfterSeconds": killed_at, "when": when, "brokenJsonFiles": broken,
                "dataUnchangedByIdleKill": after == before if when == "idle" else None}
    need(not broken, f"{label}-partial-app-data")
    if when == "idle":
        need(after == before, f"{label}-idle-kill-changed-app-data")
    observed["relaunch"] = launch_smoke(label + "-relaunch", work, evidence, steps)
    need(not json_files_intact(), f"{label}-relaunch-partial-app-data")
    return observed


def installed_signature_check(steps):
    """#30: the installed app's own signature and Gatekeeper assessment."""
    out = {}
    p, r = run(["/usr/bin/codesign", "--verify", "--strict", "--deep", "-vv", str(APP)], 300)
    steps.append(dict(r, role="installed-codesign"))
    out["codesignStrictDeep"] = p.returncode
    p, r = run(["/usr/sbin/spctl", "-a", "-vv", "-t", "exec", str(APP)], 120)
    steps.append(dict(r, role="installed-gatekeeper"))
    text = p.stdout + p.stderr
    out["gatekeeper"] = {"returncode": p.returncode, "notarizedDeveloperId": "Notarized Developer ID" in text,
                         "lines": tail_text(text, 6)}
    p, r = run(["/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", str(APP)], 60)
    out["entitlementsBytes"] = len(p.stdout)
    p, r = run(["/usr/bin/codesign", "-dv", str(APP)], 60)
    flags = re.search(r"flags=0x[0-9a-f]+\(([^)]*)\)", p.stderr)
    out["codeFlags"] = flags.group(1) if flags else None
    return out


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
    parser.add_argument("--mode", choices=("update", "fresh", "remove", "uninstaller", "delete-data",
                                           "repeat", "repeat-after-dialogs", "removal-archive", "prepare-quit", "performance",
                                           "update-credentials", "release-asset", "workspace-cli",
                                           "workspace-xctest", "prepare-xctest", "performance-long", "core-recovery",
                                           "recovery-xctest", "retained-transition", "retained-prepare",
                                           "macl-journal-recovery", "post-reinstall-prepare", "archived-upgrade"), default="update")
    args = parser.parse_args()
    work = Path(args.work)
    evidence = work / "evidence"
    evidence.mkdir(mode=0o700)
    steps, result = [], {"schemaVersion": 1, "kind": "mrk-macos-update-check-v1", "mode": args.mode, "passed": False}
    try:
        selection = load_selection(args.selection)
        if os.environ.get("MRK_FROZEN_RELEASE_MEDIA"):
            need(os.environ.get("GITHUB_REF") == "refs/heads/main"
                 and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "frozen-release-check-route")
            manifest_path = Path(os.environ["MRK_FROZEN_RELEASE_MEDIA"]) / "RELEASE-MANIFEST.json"
            frozen = json.loads(manifest_path.read_bytes())
            result["frozenRelease"] = {key: frozen[key] for key in
                                       ("sourceCommit", "sourceTree", "buildRun", "carrierRun", "carrierAttempt")}
            result["frozenRelease"].update(manifestSha256=digest(manifest_path),
                                           installSha256=frozen["packages"]["Install.pkg"]["sha256"],
                                           removeSha256=frozen["packages"]["Remove.pkg"]["sha256"])
            if args.mode == "archived-upgrade":
                selection.update(recoveryInstall=selection["previous"], recoveryRemoval=selection["previousRemoval"])
        result["selection"] = selection
        if os.environ.get("MRK_RELEASE_QUALIFICATION") == "true":
            chosen = selection["next"]
            need((chosen["packageVersion"], chosen["release"], chosen["packageSha256"]) == (
                "0.2.10", "macos26-arm64-desktop-16",
                "8f4dcf34a87c2d0966c51b2786b951eec1c22a17c516e30ba54ac664bc227dbe",
            ), "release-qualification-selection")
            result["hostOs"] = run(["/usr/bin/sw_vers", "-productVersion"], 20)[0].stdout.strip()
            result["hostArchitecture"] = run(["/usr/bin/uname", "-m"], 20)[0].stdout.strip()
        if os.environ.get("MRK_SIGNED_INTERMITTENTS") == "true":
            chosen = selection["next"]
            need((chosen["packageVersion"], chosen["release"], chosen["runId"])
                 == ("0.2.11", "macos26-arm64-desktop-17", "45556678054"), "signed-intermittent-selection")
            result["hostOs"] = run(["/usr/bin/sw_vers", "-productVersion"], 20)[0].stdout.strip()
            result["hostArchitecture"] = run(["/usr/bin/uname", "-m"], 20)[0].stdout.strip()
        if os.environ.get("MRK_APFS_ARCHIVE_ACCEPTANCE") == "true":
            chosen = selection["next"]
            need((chosen["packageVersion"], chosen["release"], chosen["runId"])
                 == ("0.2.12", "macos26-arm64-desktop-18", "45599087818"), "apfs-archive-selection")
            result["hostOs"] = run(["/usr/bin/sw_vers", "-productVersion"], 20)[0].stdout.strip()
            result["hostArchitecture"] = run(["/usr/bin/uname", "-m"], 20)[0].stdout.strip()
        need(not STATE.exists() and not USER_DATA.exists(), "runner-not-fresh")
        if args.mode not in ("update", "update-credentials"):
            {"fresh": fresh_check, "remove": remove_check, "uninstaller": uninstaller_installed_check,
             "delete-data": remove_check, "repeat": remove_check, "repeat-after-dialogs": remove_check,
             "removal-archive": remove_check, "post-reinstall-prepare": remove_check,
             "retained-transition": retained_transition_check, "retained-prepare": retained_transition_check,
             "macl-journal-recovery": macl_journal_recovery_check, "archived-upgrade": archived_upgrade_check,
             "prepare-quit": prepare_quit_check, "performance": fresh_check, "release-asset": release_asset_check,
             "workspace-cli": workspace_cli_check, "workspace-xctest": workspace_xctest,
             "prepare-xctest": workspace_xctest, "performance-long": performance_long_check,
             "core-recovery": core_recovery_check, "recovery-xctest": workspace_xctest}[args.mode](
                selection, work, evidence, steps, result)
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
        credential = seed_update_credential() if args.mode == "update-credentials" else None

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
        if credential is not None:
            result["credentialPreserved"] = update_credential_matches(credential)
            need(result["credentialPreserved"], "app-keychain-fixture-changed-by-update")

        downgrade_rc = install("downgrade", previous, steps, expect_success=False)
        result["downgradeReturn"] = downgrade_rc
        need(downgrade_rc != 0, "downgrade-was-not-refused")
        final = installed_state()
        result["afterDowngradeAttempt"] = final
        need((final["release"], final["packageVersion"]) == (after["release"], after["packageVersion"]),
             "downgrade-changed-installation")
        need(manifest() == seeded, "user-data-changed-by-downgrade-attempt")
        if credential is not None:
            result["credentialPreservedAfterDowngrade"] = update_credential_matches(credential)
            need(result["credentialPreservedAfterDowngrade"], "app-keychain-fixture-changed-by-downgrade-attempt")
        # Last: launching writes the app's own data beside the seeded files.
        result["launchAfterUpdate"] = launch_smoke("after-update", work, evidence, steps)
        result["passed"] = True
    except (Failed, subprocess.TimeoutExpired, OSError, ValueError, KeyError) as error:
        result["failure"] = str(error)[:200]
    finally:
        result["steps"] = steps
        if args.mode in ("remove", "delete-data", "repeat", "repeat-after-dialogs", "removal-archive", "retained-transition"):
            removed = next((step for step in steps if step.get("role") == "remove"), {})
            result.setdefault("removeReturn", removed.get("returncode"))
            if removed.get("watchdogTimedOut"):
                result["removeTimedOut"] = True
            if "seconds" in removed:
                result["removeSeconds"] = removed["seconds"]
        if args.mode in ("remove", "repeat", "repeat-after-dialogs"):
            recorded = [step["returncode"] for step in steps if step.get("role") == "remove-again"
                        and step.get("argv") == ["installer", "-pkg", "Remove.pkg"]]
            if recorded:
                result["secondRemoveReturn"] = recorded[-1]
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
    durable = os.environ.get("MRK_COLD_RUNTIME_DURABLE") == "true"
    if durable:
        origin = json.loads((folder / "PREPARED.json").read_text())["origin"]
        expected = {
            "macos26-arm64-desktop-14": ("ce9380df50c0a6bc6a51f6e23eba1e0ac7ccf89a",
                                       "dcce7b95cf7465e51adc7df7fd141d0fe6d99b87"),
            "macos26-arm64-desktop-15": ("e5f56c3d925c76df61bf43e24a0086815405ed25",
                                       "e8db6d235daecfd3648852dfd143c4717e72dcae"),
            "macos26-arm64-desktop-16": ("6bde41073ab878ab83f1e70ac46bfac7d0b7c185",
                                       "410f788d127278fa8041417c4dba039596714141"),
            "macos26-arm64-desktop-18": ("3aa536dfbb23f846377112a2e217f84dd44d83f5", "8cde7dfc96a0788ed70ed74f25b41d3a3f4a0aeb"),
            "macos26-arm64-desktop-17": ("c7f5b2a2a6a41a3b930ff0d937198cd25abcb48d",
                                       "526b16a692a2df7a8ed29028d84c76f60050cb3e"),
        }.get(row["release"])
        need((origin["source"], origin["tree"]) == expected, "cold-diagnostic-exact-source")
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
    if durable:
        need(state["sourceCommit"] == origin["source"], "cold-diagnostic-installed-source")
        result["durableBootstrap"] = True
    performance = result["mode"] == "performance"
    result["firstLaunch"] = launch_smoke("first-launch", work, evidence, steps, observe=first_launch_observe,
                                         steady_idle_seconds=300 if performance else 0)
    ui = result["firstLaunch"].get("ui") or {}
    # A missing accessibility read is recorded as not-observed, never a pass;
    # only a definite unavailable card, error marker or wrong CLI refusal fails.
    if not durable and ui.get("runtimeCard") == "unavailable" and os.environ.get("MRK_COLD_RUNTIME_DIAGNOSTIC") == "true":
        result["warmAfterFirstLaunchRefusal"] = launch_smoke(
            "warm-after-timeout", work, evidence, steps, observe=first_launch_observe)
    need(ui.get("runtimeCard") != "unavailable", "fresh-first-launch-runtime-unavailable")
    need(not ui.get("workspaceErrorMarkers"), "fresh-first-launch-workspace-error")
    need(ui.get("cliStatus", {}).get("returncode") == 3 and ui.get("cliStatus", {}).get("guidance"),
         "fresh-cli-status-guidance")
    if performance:
        need(ui.get("runtimeCard") == "bundled", "resource-first-launch-runtime-unproven")
        need(result["firstLaunch"]["steadyIdleResources"]["samples"] == 300, "resource-sample-incomplete")
        return
    if durable or os.environ.get("MRK_COLD_RUNTIME_DIAGNOSTIC") == "true":
        need(ui.get("runtimeCard") == "bundled", "cold-first-launch-runtime-unobserved")
        if durable:
            journal = (evidence / "first-launch-bootstrap-journal.jsonl").read_text().splitlines()
            records = [json.loads(line) for line in journal]
            need(any(row["event"] == "MRK_DESKTOP_CAPABILITIES=available" for row in records)
                 and records[-1].get("readerDrained") is True, "cold-bootstrap-evidence-incomplete")
            stages = {entry["event"]: entry for entry in records}
            if os.environ.get("MRK_SIGNED_INTERMITTENTS") == "true":
                ordered = ("open-request", "MRKDBG_DESKTOP_BOOTSTRAP=app-info-enter",
                           "MRKDBG_DESKTOP_BOOTSTRAP=capabilities-inspection-enter",
                           "MRKDBG_DESKTOP_BOOTSTRAP=capabilities-inspection-joined",
                           "MRKDBG_DESKTOP_BOOTSTRAP=capabilities-child-acquired",
                           "MRK_DESKTOP_CAPABILITIES=available")
                need(all(stage in stages for stage in ordered), "cold-bootstrap-stage-missing")
                need(sum(row["event"] == "MRKDBG_DESKTOP_BOOTSTRAP=app-info-enter" for row in records) == 1,
                     "cold-bootstrap-request-count")
                times = [stages[stage]["elapsedSeconds"] for stage in ordered]
                need(times == sorted(times), "cold-bootstrap-stage-order")
                result["firstLaunchBootstrapSeconds"] = dict(zip(ordered, times))
            if os.environ.get("MRK_COLD_RUNTIME_SAMPLE", "").startswith("contention"):
                active = stages.get("pressure-cpu-observed", {})
                completed = stages.get("pressure-finished", {})
                available = stages["MRK_DESKTOP_CAPABILITIES=available"]["elapsedSeconds"]
                opened = stages["open-request"]["elapsedSeconds"]
                need(active.get("elapsedSeconds", float("inf")) <= opened < available
                     <= completed.get("elapsedSeconds", float("-inf"))
                     and active.get("activeWorkers") == stages["pressure-started"]["workers"]
                     and completed.get("workerExits") and all(code == 0 for code in completed["workerExits"])
                     and records[-1]["pressureDrained"], "cold-contention-evidence-incomplete")
        if os.environ.get("MRK_CHECK_FULL_FRESH_AFTER_TRACE") != "true":
            result["diagnosticOnly"] = True
            return
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
    result["reopen"] = launch_smoke("reopen", work, evidence, steps, steady_idle_seconds=60)
    # Additional coverage after every earlier fact is recorded: interruption
    # (#65), then the installed app's signature and Gatekeeper result (#30).
    result["interruption"] = {"startup": kill_and_relaunch("kill-startup", work, evidence, steps, "startup"),
                              "idle": kill_and_relaunch("kill-idle", work, evidence, steps, "idle")}
    security = result["installedSignature"] = installed_signature_check(steps)
    need(security["codesignStrictDeep"] == 0, "installed-app-codesign")
    need(security["gatekeeper"]["returncode"] == 0 and security["gatekeeper"]["notarizedDeveloperId"],
         "installed-app-gatekeeper")
    need("runtime" in (security["codeFlags"] or ""), "installed-app-not-hardened-runtime")
    if os.environ.get("MRK_CHECK_REFRESHED_RUNTIME") == "true":
        need(ui.get("runtimeCard") == "bundled", "installed-refresh-first-launch-runtime-unobserved")
        check_installed_runtime_refresh(row, folder, work, result)


def check_installed_runtime_refresh(row, folder, work, result):
    prepared = json.loads((folder / "PREPARED.json").read_bytes())
    runtime = STATE / "versions" / row["release"] / "runtime"
    manifest_path = runtime / "manifest.json"
    manifest_sha256 = digest(manifest_path)
    need(manifest_sha256 == prepared["runtimeManifestSha256"], "installed-refresh-runtime-manifest")
    members = {item["path"]: item for item in json.loads(manifest_path.read_bytes())["files"]}
    python, ruby, github_ca, store_ca = (runtime / name for name in
        ("python/bin/python3", "store/bin/ruby", "github-ca.pem", "store/ca.pem"))
    ca_sha256 = "8a2bfdbfac68ecdda694c8dd46f5d29d4386fa0402f844b59a17b7d073ebbd81"
    for path in (python, ruby, github_ca, store_ca):
        relative = path.relative_to(runtime).as_posix()
        need(path.is_file() and not path.is_symlink() and path.stat().st_size == members[relative]["size"]
             and digest(path) == members[relative]["sha256"], "installed-refresh-runtime-member")
    need(digest(github_ca) == digest(store_ca) == ca_sha256, "installed-refresh-trust-anchors")
    for binary in (python, ruby):
        signature, _ = run(["/usr/bin/codesign", "--verify", "--strict", str(binary)], 60)
        need(signature.returncode == 0, "installed-refresh-runtime-signature")

    probe_home = work / "runtime-refresh-probe"
    probe_home.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(probe_home), "TMPDIR": str(probe_home),
           "LC_ALL": "C.UTF-8", "TZ": "UTC"}
    python_probe = ("import platform,ssl,sys; context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); "
                    "context.load_verify_locations(cafile=sys.argv[1]); "
                    "print(platform.python_version(), platform.machine(), ssl.OPENSSL_VERSION.split()[1], "
                    "len(context.get_ca_certs()))")
    python_result = subprocess.run([str(python), "-I", "-S", "-B", "-c", python_probe, str(github_ca)],
                                   env=env, capture_output=True, text=True, timeout=45)
    ruby_probe = 'puts [RUBY_VERSION, RbConfig::CONFIG.fetch("host_cpu"), OpenSSL::OPENSSL_LIBRARY_VERSION.split[1]].join(" ")'
    ruby_result = subprocess.run([str(ruby), "--disable=gems", "-rrbconfig", "-ropenssl", "-e", ruby_probe],
                                 env=env, capture_output=True, text=True, timeout=45)
    need(python_result.returncode == 0 and python_result.stdout.strip() == "3.14.10 arm64 3.5.9 117",
         "installed-refresh-python-version-or-trust")
    need(ruby_result.returncode == 0 and ruby_result.stdout.strip() == "3.3.14 arm64 3.5.9",
         "installed-refresh-ruby-version")
    receipt = (Path(__file__).resolve().parents[1] /
               "macos-installed-inputs/notices/THIRD-PARTY-NOTICES.txt")
    notices = APP / "Contents/Resources/THIRD-PARTY-NOTICES.txt"
    notice_sha256 = digest(notices)
    need(notice_sha256 == digest(receipt), "installed-refresh-notice-content")
    result["installedRuntime"] = {
        "manifestSha256": manifest_sha256, "caSha256": ca_sha256, "trustAnchors": 117,
        "python": "3.14.10", "ruby": "3.3.14", "openssl": "3.5.9", "architecture": "arm64",
        "runtimeSignaturesVerified": True, "noticesSha256": notice_sha256,
    }


def performance_long_check(selection, work, evidence, steps, result):
    row = selection["next"]
    folder = fetch("next", row, work, steps)
    need(install("next", folder, steps, evidence=evidence) == 0, "performance-install")
    installed = result["afterInstall"] = installed_state()
    need(installed["packageSha256"] == row["packageSha256"], "performance-package-identity")
    result["hostOs"] = run(["/usr/bin/sw_vers", "-productVersion"], 20)[0].stdout.strip()
    result["firstLaunch"] = launch_smoke("one-hour-idle", work, evidence, steps,
                                         steady_idle_seconds=3600, steady_interval=5)
    resources = result["firstLaunch"]["steadyIdleResources"]
    need(resources["samples"] == resources["plannedSamples"] == 720
         and resources["sampleWindowSeconds"] >= 3600, "performance-one-hour-sample-incomplete")
    samples = json.loads((evidence / "one-hour-idle-resources.json").read_text())
    need(len(samples) == 720 and all(s["appRssKiB"] and s["processes"] >= 1 for s in samples),
         "performance-original-process-census-incomplete")


CORE_RECOVERY_TEST = """import json, pathlib, sys, unittest
root = pathlib.Path(sys.argv[1])
sys.path[:0] = [str(root / member) for member in ('src', '', 'tests', 'tests/desktop')]
import mobile_release
if not mobile_release.__file__.startswith(str(root / 'src') + '/'):
    raise RuntimeError('packaged core import did not resolve to the admitted archive')
modules = ['tests.desktop.test_saved_text_recovery', 'tests.desktop.test_configuration_crash_recovery',
           'tests.desktop.test_project_crash_recovery']
suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
result = unittest.TextTestRunner(verbosity=0).run(suite)
print(json.dumps({'tests': result.testsRun, 'errors': len(result.errors), 'failures': len(result.failures),
                  'skipped': len(result.skipped)}), flush=True)
raise SystemExit(0 if result.wasSuccessful() else 1)
"""


def prepare_signed_core_fixture(runtime, work, repository, manifest_sha256):
    manifest_path = runtime / "manifest.json"
    need(digest(manifest_path) == manifest_sha256, "core-recovery-runtime-manifest")
    manifest = json.loads(manifest_path.read_bytes())
    members = {row["path"]: row for row in manifest["files"]}
    for relative in ("core.zip", "python/bin/python3"):
        path = runtime / relative
        need(path.is_file() and not path.is_symlink() and path.stat().st_size == members[relative]["size"]
             and digest(path) == members[relative]["sha256"], "core-recovery-runtime-member")
    core_sha256 = members["core.zip"]["sha256"]
    need(core_sha256 == manifest["coreSha256"], "core-recovery-core-binding")
    fixture = work.resolve() / "signed-core-recovery"
    fixture.mkdir(mode=0o700)
    shutil.copytree(repository / "tests", fixture / "tests", ignore=shutil.ignore_patterns("__pycache__"))
    # The existing restart-child tests add ./src to sys.path. It is the exact
    # packaged archive in this disposable fixture, with no checkout fallback.
    shutil.copyfile(runtime / "core.zip", fixture / "src")
    need(digest(fixture / "src") == core_sha256, "core-recovery-test-archive")
    return fixture, runtime / "python/bin/python3", core_sha256


def run_signed_core_recovery(runtime, work, repository, manifest_sha256, result):
    fixture, python, core_sha256 = prepare_signed_core_fixture(runtime, work, repository, manifest_sha256)
    temporary = fixture / "tmp"
    temporary.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(fixture), "TMPDIR": str(temporary),
           "LC_ALL": "C", "LANG": "C", "TZ": "UTC"}
    tested = subprocess.run([str(python), "-I", "-S", "-B", "-c", CORE_RECOVERY_TEST, str(fixture)],
                            cwd=fixture, env=env, capture_output=True, text=True, timeout=600)
    result["coreRecoveryReturn"] = tested.returncode
    result["coreRecoveryArchiveSha256"] = core_sha256
    summary = re.search(r'(?m)^\{"tests": ([0-9]{1,3}), "errors": ([0-9]{1,3}), '
                       r'"failures": ([0-9]{1,3}), "skipped": ([0-9]{1,3})\}$', tested.stdout)
    if summary:
        result["coreRecoveryCounts"] = dict(zip(("tests", "errors", "failures", "skipped"), map(int, summary.groups())))
    result["coreRecoveryFailureSites"] = re.findall(r"(?m)^(?:FAIL|ERROR): (test_[a-z0-9_]{1,105})\b",
                                                   tested.stderr)[-20:]
    counts = result.get("coreRecoveryCounts", {})
    need(tested.returncode == 0 and counts.get("tests") == 12
         and counts.get("errors") == counts.get("failures") == counts.get("skipped") == 0,
         "core-recovery-original-suite")
    need(digest(fixture / "src") == core_sha256 and digest(runtime / "manifest.json") == manifest_sha256,
         "core-recovery-source-changed")


def core_recovery_check(selection, work, evidence, steps, result):
    row = selection["next"]
    folder = fetch("next", row, work, steps)
    need(install("next", folder, steps, evidence=evidence) == 0, "core-recovery-install")
    state = result["afterInstall"] = installed_state()
    prepared = json.loads((folder / "PREPARED.json").read_text())
    need(state["packageSha256"] == row["packageSha256"] and state["sourceCommit"] == prepared["origin"]["source"],
         "core-recovery-package-identity")
    runtime = STATE / "versions" / row["release"] / "runtime"
    run_signed_core_recovery(runtime, work, Path(__file__).resolve().parents[2], prepared["runtimeManifestSha256"], result)


def recovery_project_manifest(project):
    rows = {}
    for path in project.rglob("*"):
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), "recovery-ui-project-roster")
        rows[path.relative_to(project).as_posix()] = (digest(path) if stat.S_ISREG(info.st_mode) else None,
                                                      info.st_ino, stat.S_IMODE(info.st_mode))
    return rows


def seed_signed_gui_recovery(row, folder, work, env, result):
    runtime = STATE / "versions" / row["release"] / "runtime"
    prepared = json.loads((folder / "PREPARED.json").read_text())
    fixture, python, core_sha256 = prepare_signed_core_fixture(runtime, work, Path(__file__).resolve().parents[2],
                                                              prepared["runtimeManifestSha256"])
    parent = Path(tempfile.mkdtemp(prefix="mrk-normal-project-", dir="/private/tmp"))
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        original = os.fstat(fd)
        need(os.path.samestat(original, parent.lstat()) and original.st_uid == os.getuid()
             and stat.S_IMODE(original.st_mode) == 0o700 and not os.listdir(fd), "recovery-ui-fresh-parent")
        if original.st_gid != os.getgid():
            os.fchown(fd, -1, os.getgid())
        need(os.fstat(fd).st_gid == os.getgid() and os.path.samestat(original, parent.lstat()),
             "recovery-ui-parent-primary-group")
    finally:
        os.close(fd)
    result["recoveryFixturePrimaryGroup"] = True
    project = parent / "project"
    seed = """import pathlib, sys
root, project = map(pathlib.Path, sys.argv[1:])
sys.path[:0] = [str(root / 'src'), str(root)]
from tests.desktop.test_saved_text_recovery import _init_project
_init_project(project, 'version')
"""
    environment = {key: env[key] for key in ("PATH", "LANG", "LC_ALL", "TZ", "TMPDIR")}
    environment["HOME"] = str(fixture)
    initial = subprocess.run([str(python), "-I", "-S", "-B", "-c", seed, str(fixture), str(project)],
                             cwd=fixture, env=environment, capture_output=True, timeout=30)
    need(initial.returncode == 0 and not initial.stderr, "recovery-ui-synthetic-project")
    baseline = recovery_project_manifest(project)
    control = "public/version.properties"
    worker = fixture / "tests/desktop/test_saved_text_recovery.py"
    killed = subprocess.run([str(python), "-I", "-S", "-B", str(worker), "--restart-child", str(project),
                             "release_version", "crash-replacement"], cwd=project, env=environment,
                            capture_output=True, timeout=20)
    need(killed.returncode == -signal.SIGKILL and not killed.stderr, "recovery-ui-original-writer-kill")
    need(len(killed.stdout) <= 65536 and [json.loads(line)["kind"] for line in killed.stdout.splitlines()]
         == ["opened", "prepared"], "recovery-ui-original-writer-frames")
    journal = project / ".mobile-release-version"
    old = journal / "old-0"
    need(digest(old) == baseline[control][0] and old.stat().st_ino == baseline[control][1]
         and digest(project / control) != baseline[control][0], "recovery-ui-retained-replacement-journal")
    env["TEST_RUNNER_MRK_RELEASE_RECOVERY_PROJECT"] = str(project)
    result.update(recoveryWriterReturn=killed.returncode, recoveryCoreSha256=core_sha256,
                  recoveryOriginalFiles=sum(row[0] is not None for row in baseline.values()))
    return project, baseline


SHEET_JXA = """function run(argv) {
  const quit = argv[2] === 'quit';
  const title = quit ? 'Quit and discard unsaved drafts?' : 'Quit and prepare to remove Mobile Release Kit?';
  const confirm = quit ? 'Quit' : 'Continue and Quit';
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
    if (names.length !== 2 || names.indexOf('Cancel') < 0 || names.indexOf(confirm) < 0) return 'unexpected:' + names.join('|');
    if (!texts.some(t => t === title)) return 'unexpected-text';
    if (argv[1] === 'click') { sheet.buttons.byName(confirm).click(); return 'clicked'; }
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
    matches[0].frontmost = true;
    delay(0.5);
    if (!matches[0].frontmost()) return JSON.stringify({state: 'uninstaller-not-frontmost'});
    w.buttons.byName(argv[2]).click();
    return JSON.stringify({state: 'clicked', buttons: buttons, texts: texts});
  }
  return JSON.stringify({state: 'dialog', buttons: buttons, texts: texts});
}
"""


GATEKEEPER_UNINSTALLER_JXA = r"""function run() {
  const app = 'Uninstall Mobile Release Kit';
  const emit = (state, checks) => JSON.stringify({state, checks});
  const agent = Application('System Events').processes.whose({name: 'CoreServicesUIAgent'});
  if (agent.length !== 1) return emit('no-agent', null);
  for (const w of agent[0].windows()) {
    for (const panel of [w].concat(w.sheets())) {
      const descendants = panel.entireContents().slice(0, 64);
      const lines = [panel.name()];
      for (const element of descendants) {
        if (element.role() !== 'AXStaticText') continue;
        const value = element.value();
        if (typeof value === 'string') lines.push(value);
      }
      const text = lines.join(' ').replace(/\s+/g, ' ');
      if (!text.includes(app)) continue;
      const buttons = panel.buttons();
      const names = buttons.map(b => b.name());
      const open = buttons.filter((_, index) => names[index] === 'Open');
      const actions = names.filter(name => name && !['Help', '?'].includes(name)).sort().join('|');
      const checks = {
        actionSet: ['Cancel|Open', 'Cancel|Open|Show Disk Image'].includes(actions),
        download: /downloaded from the internet/i.test(text),
        confirmation: /are you sure you want to open/i.test(text),
        hardBlock: /malware|unidentified developer|could not verify|cannot be opened|is damaged/i.test(text),
        uniqueOpen: open.length === 1,
      };
      if (!checks.actionSet || !checks.download || !checks.confirmation || checks.hardBlock || !checks.uniqueOpen)
        return emit('unexpected-dialog', checks);
      open[0].click();
      return emit('standard-open-confirmed', checks);
    }
  }
  return emit('no-matching-dialog', null);
}
"""


def open_quarantined_removal_image(image, steps):
    """Use the same Launch Services handoff as a Finder double-click."""
    deadline = time.monotonic() + 300
    opened, step = run(["/usr/bin/open", str(image)], 60)
    steps.append(dict(step, role="removal-image-launch-services"))
    need(opened.returncode == 0, "removal-image-open")
    original = image.resolve()
    while time.monotonic() < deadline:
        info = subprocess.run(["/usr/bin/hdiutil", "info", "-plist"], capture_output=True, timeout=20)
        need(info.returncode == 0, "removal-image-info")
        entries = plistlib.loads(info.stdout)["images"]
        matched = [entry for entry in entries if entry.get("image-path")
                   and Path(entry["image-path"]).resolve() == original]
        need(len(matched) <= 1, "removal-image-multiple-attachments")
        if matched:
            need(matched[0].get("writeable") is False, "removal-image-writable")
            mounts = [e["mount-point"] for e in matched[0]["system-entities"] if e.get("mount-point")]
            if mounts:
                need(len(mounts) == 1, "removal-image-mount")
                return Path(mounts[0])
        time.sleep(1)
    raise Failed("removal-image-open-no-mount")


def removal_image(row, work, steps):
    """Mount the authenticated carrier read-only and verify its exact roster."""
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
    quarantined = os.environ.get("MRK_CHECK_QUARANTINED_REMOVE_MEDIA") == "true"
    if quarantined:
        require_quarantine(image)
    p, r1 = run(["/usr/sbin/spctl", "-a", "-vv", "-t", "open", "--context", "context:primary-signature", str(image)], 120)
    steps.append(dict(r1, role="removal-image-gatekeeper"))
    need(p.returncode == 0 and "Notarized Developer ID" in (p.stdout + p.stderr), "removal-image-gatekeeper")
    if quarantined:
        mount = open_quarantined_removal_image(image, steps)
    else:
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


def removal_file_summary(trace):
    """Summarize installer-owned path activity without retaining raw paths."""
    sections = (
        ("/MobileReleaseKit-RemovalRequests/", "request"),
        ("/install-inventory.json", "inventory"),
        ("/installation-v1.json", "installation-record"),
        ("/installation-v2.json", "transaction-state"),
        ("/.install-", "transaction-stage"),
        ("/runtime/", "runtime"),
        ("/MobileReleaseKitPayload.app/", "payload"),
        ("/Mobile Release Kit.app/", "app"),
    )
    previous = None
    summary = deque(maxlen=80)
    for line in trace:
        if str(STATE) not in line:
            continue
        for marker, section in sections:
            if marker in line:
                break
        else:
            section = "installed-root"
        if section != previous:
            summary.append(section)
            previous = section
    return " -> ".join(summary)


def removal_requests(directory):
    return {path for path in directory.glob("r-*") if re.fullmatch(r"r-[0-9a-f]{32}", path.name)}


def sample_removal_start(pid, evidence, label, stop, existing_requests):
    """Capture short-lived app work while Installer publishes the request."""
    requests = STATE.with_name("MobileReleaseKit-RemovalRequests")
    deadline = time.monotonic() + 60
    try:
        while not stop.is_set() and time.monotonic() < deadline:
            if any((path / "request.json").is_file() for path in removal_requests(requests) - existing_requests):
                break
            stop.wait(0.025)
        else:
            return
        with tempfile.TemporaryFile(mode="w+t", dir=evidence.parent, errors="replace") as trace:
            files = subprocess.Popen(["/usr/bin/sudo", "-n", "/usr/bin/fs_usage", "-w", "-f", "filesys",
                                      "-t", "8", str(pid)], stdout=trace, stderr=subprocess.DEVNULL)
            try:
                sample = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/sample", str(pid), "9", "2"],
                                        capture_output=True, text=True, timeout=75)
                graph = sample.stdout.partition("Call graph:\n")[2].partition("\nTotal number in stack")[0]
                # Keep function names and counts, with the path-bearing header
                # and binary-image list omitted.
                lines = [line.strip() for line in graph.splitlines()
                         if "(in libmrk_desktop_image.dylib)" in line
                         and any(name in line for name in ("removal", "installation_observation_macos", "install_producer"))]
                prompt = [line.strip() for line in graph.splitlines()
                          if any(name in line for name in ("removal_prompt", "mrk_removal_confirmation", "beginSheet", "endSheet"))]
                report = [f"sample returncode={sample.returncode} frames={len(lines)} promptFrames={len(prompt)}",
                          *prompt[:80], *lines[:160]]
            except (OSError, subprocess.SubprocessError) as error:
                report = [f"sample failed: {type(error).__name__}"]
            finally:
                try:
                    files.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    files.kill()
                    files.wait()
            trace.seek(0)
            report.append(f"filesystem returncode={files.returncode} sections={removal_file_summary(trace)}")
    except (OSError, subprocess.SubprocessError) as error:
        report = [f"capture failed: {type(error).__name__}"]
    (evidence / f"{label}-app-start-sample.txt").write_text("\n".join(report) + "\n")


REMOVAL_METADATA_FIELDS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_flags",
                           "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")


def removal_metadata_changes(paths, previous):
    snapshot, changes = {}, {}
    for role, path in paths.items():
        try:
            info = path.lstat()
            identity = tuple(getattr(info, name) for name in REMOVAL_METADATA_FIELDS)
        except OSError as error:
            identity = (error.errno,)
        snapshot[role] = identity
        if role not in previous or identity == previous[role]:
            continue
        before = previous[role]
        changes[role] = (
            [name for name, old, new in zip(REMOVAL_METADATA_FIELDS, before, identity) if old != new]
            if len(before) == len(identity) == len(REMOVAL_METADATA_FIELDS)
            else ["availability"]
        )
    return snapshot, changes


def sample_removal_metadata(release, requests, existing_requests, evidence, label, stop):
    """Observe fixed source roles without exporting paths, metadata values, or contents."""
    contents = APP / "Contents"
    payload = contents / "Helpers/MobileReleaseKitPayload.app/Contents"
    generation = STATE / "versions" / release
    paths = {
        "system-root": Path("/"), "system-library": Path("/Library"), "system-support": STATE.parent,
        "system-applications": Path("/Applications"), "system-volumes": Path("/Volumes"),
        "system-private": Path("/private"), "system-tmp": Path("/private/tmp"),
        "installed-launcher": LAUNCHER,
        "installed-root": STATE, "versions": generation.parent, "generation": generation,
        "record": generation / "installation-v1.json", "inventory": generation / "install-inventory.json",
        "runtime": generation / "runtime", "producer": STATE / f".producer-{release}.json",
        "signature": STATE / f".producer-{release}.sig", "app": APP, "app-contents": contents,
        "app-macos": contents / "MacOS", "entry": contents / "MacOS/mrk-macos-entry",
        "app-helpers": contents / "Helpers", "payload": payload.parent, "payload-contents": payload,
        "payload-macos": payload / "MacOS", "payload-entry": payload / f"MacOS/{PAYLOAD_PROCESS}",
        "payload-helpers": payload / "Helpers", "remover": payload / "Helpers/mrk-macos-remove",
        "request-root": requests,
    }
    snapshot, events = {}, deque(maxlen=160)
    deadline = time.monotonic() + (150 if label == "macl-interrupted"
        or os.environ.get("MRK_LIVE_REMOVAL_DIAGNOSTIC") == "true" else 30)
    try:
        while not stop.is_set() and time.monotonic() < deadline:
            if "request" not in paths:
                new = removal_requests(requests) - existing_requests
                if len(new) == 1:
                    request = next(iter(new))
                    paths.update(request=request, **{"request-json": request / "request.json", "socket": request / "s"})
                    events.append({"utcMs": time.time_ns() // 1_000_000, "newRequest": True})
            snapshot, changes = removal_metadata_changes(paths, snapshot)
            if changes:
                events.append({"utcMs": time.time_ns() // 1_000_000, "changes": changes})
            stop.wait(0.025)
    finally:
        (evidence / f"{label}-source-metadata.json").write_text(json.dumps(list(events), indent=2) + "\n")



def fixed_app_trace(evidence, label):
    # The original native traces contain closed stage and status atoms only.
    try:
        run = subprocess.run(["/usr/bin/log", "show", "--last", "8m", "--style", "compact", "--predicate",
                              'eventMessage BEGINSWITH "MRK_REMOVAL_TRACE"'],
                             capture_output=True, text=True, timeout=180)
        trace = [line[:300] for line in run.stdout.splitlines() if "MRK_REMOVAL_TRACE" in line][-60:]
    except (OSError, subprocess.TimeoutExpired) as error:
        trace = [f"capture failed: {type(error).__name__}"]
    (evidence / f"{label}-app-trace.txt").write_text("\n".join(trace) + "\n")
    return trace

def removal_script_diagnostics(evidence, label):
    installer_log, _ = run(["/usr/bin/sudo", "-n", "/usr/bin/tail", "-n", "3000", "/var/log/install.log"], 30)
    unified, _ = run(["/usr/bin/log", "show", "--last", "5m", "--style", "compact",
                      "--predicate", 'eventMessage CONTAINS "MRK_MACOS_REMOVAL_"'], 40)
    lines = [line for line in (installer_log.stdout + "\n" + unified.stdout).splitlines()
             if "MRK_MACOS_REMOVAL_" in line]
    captured = "\n".join(tail_text("\n".join(lines), 24)) + "\n"
    (evidence / f"{label}-script-diagnostics.txt").write_text(captured)
    return captured


def sample_native_removal(evidence, label, stop):
    deadline = time.monotonic() + 150
    while not stop.is_set() and time.monotonic() < deadline:
        lookup = subprocess.run(["/usr/bin/pgrep", "-x", "mrk-macos-remove"], capture_output=True,
                                text=True, timeout=10)
        pids = lookup.stdout.split()
        if len(pids) == 1 and pids[0].isdigit():
            break
        stop.wait(0.15)
    else:
        return
    trace = evidence / f"{label}-native-filesys.txt"
    with tempfile.TemporaryFile(mode="w+t", dir=evidence.parent, errors="replace") as all_events:
        child = subprocess.Popen(["/usr/bin/sudo", "-n", "/usr/bin/fs_usage", "-w", "-f", "filesys",
                                  "-t", "135", pids[0]], stdout=all_events, stderr=subprocess.DEVNULL)
        try:
            while child.poll() is None and not stop.wait(0.15):
                if time.monotonic() >= deadline:
                    break
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        all_events.seek(0)
        fields = deque(maxlen=3000)
        tail = deque(maxlen=80)
        for row in all_events:
            if len(row) > 16384 or "mrk-macos-remove" not in row:
                continue
            tail.append(row)
            tokens = row.split(maxsplit=3)
            if len(tokens) >= 2 and tokens[1] not in ("pread", "pwrite", "read", "write", "PAGE_IN"):
                fields.append(row)
        trace.write_text("".join(fields) + "\nLast filesystem calls, including data I/O\n" + "".join(tail))

def hosted_shared_parent_change(evidence, label, stop):
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        return
    deadline = time.monotonic() + 150
    while not stop.is_set() and time.monotonic() < deadline:
        if not LAUNCHER.exists() and APP.exists():
            break
        stop.wait(0.025)
    else:
        return
    marker = STATE.parent / (".mrk-hosted-removal-proof-" + secrets.token_hex(16))
    p, _ = run(["/usr/bin/sudo", "-n", "/bin/mkdir", "-m", "0700", str(marker)], 15, check=True)
    try:
        (evidence / f"{label}-shared-parent-fixture.json").write_text(json.dumps({
            "createdAfterLauncherRetirement": True, "clockUtcMs": time.time_ns() // 1_000_000,
            "returncode": p.returncode,
        }) + "\n")
        stop.wait(max(0, deadline - time.monotonic()))
    finally:
        run(["/usr/bin/sudo", "-n", "/bin/rmdir", str(marker)], 15, check=True)

def live_remove(mount, work, evidence, steps, label, observe_release=None, *, refuse_at=None, background=False):
    """Open the installed app, run the mounted Remove.pkg with the standard
    Installer and confirm its exact removal sheet and ensuing ordinary Quit
    sheet. Require Installer 0 and no app, launcher or process left."""
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
    if background:
        focus = work / "background-app.js"
        focus.write_text("""function run(argv) {
  const se = Application('System Events');
  const app = se.processes.whose({unixId: Number(argv[0])});
  const finder = se.processes.whose({bundleIdentifier: 'com.apple.finder'});
  if (app.length !== 1 || finder.length !== 1) return 'missing-process';
  finder[0].frontmost = true;
  delay(1);
  return finder[0].frontmost() && !app[0].frontmost() ? 'background' : 'focus-unconfirmed';
}
""")
        p, step = run(["/usr/bin/osascript", "-l", "JavaScript", str(focus), str(pids[0])], 15)
        steps.append(dict(step, role=f"{label}-app-background"))
        need(p.returncode == 0 and p.stdout.strip() == "background", "remove-app-not-background")
    requests = STATE.with_name("MobileReleaseKit-RemovalRequests")
    existing_requests = removal_requests(requests)
    log = open(evidence / f"{label}-installer.log", "w")
    installer = subprocess.Popen(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-verbose", "-pkg",
                                  str(mount / "Remove.pkg"), "-target", "/"], stdout=log, stderr=subprocess.STDOUT, text=True)
    sample_stop = threading.Event()
    sample_thread = threading.Thread(target=sample_removal_start,
                                     args=(pids[0], evidence, label, sample_stop, existing_requests), daemon=True)
    sample_thread.start()
    change_thread = None
    if os.environ.get("MRK_LIVE_SHARED_PARENT_FIXTURE") == "true" and label == "remove":
        change_thread = threading.Thread(target=hosted_shared_parent_change, daemon=True,
                                         args=(evidence, label, sample_stop))
        change_thread.start()
    native_thread = None
    if os.environ.get("MRK_LIVE_REMOVAL_DIAGNOSTIC") == "true":
        native_thread = threading.Thread(target=sample_native_removal, daemon=True,
                                         args=(evidence, label, sample_stop))
        native_thread.start()
    metadata_thread = None
    if observe_release is not None:
        metadata_thread = threading.Thread(target=sample_removal_metadata, daemon=True,
                                           args=(observe_release, requests, existing_requests, evidence, label, sample_stop))
        metadata_thread.start()
    sheet, quit_sheet = [], []
    clicked, quit_clicked = False, False
    try:
        started = time.monotonic()
        deadline = started + 240
        while time.monotonic() < deadline and installer.poll() is None:
            live = payload_pids()
            if pids[0] in live and not quit_clicked:
                phase = "quit" if clicked else "removal"
                history = quit_sheet if clicked else sheet
                cmd = ["/usr/bin/osascript", "-l", "JavaScript", str(script), str(pids[0])]
                q = subprocess.run([*cmd, "probe", phase], capture_output=True, text=True, timeout=30)
                state_text = (q.stdout.strip() or ("error:" + q.stderr.strip()[-160:]))
                if not history or history[-1] != state_text:
                    history.append(state_text)
                if state_text == "present":
                    suffix = "quit-sheet" if clicked else "sheet"
                    subprocess.run(["/usr/sbin/screencapture", "-x", str(evidence / f"screen-{label}-{suffix}.png")],
                                   capture_output=True, timeout=60)
                    q = subprocess.run([*cmd, "click", phase],
                                       capture_output=True, text=True, timeout=30)
                    history.append(q.stdout.strip() or ("error:" + q.stderr.strip()[-160:]))
                    if q.stdout.strip() == "clicked":
                        if clicked:
                            quit_clicked = True
                        else:
                            clicked = True
            time.sleep(2)
        if installer.poll() is None:
            stall_diagnostics(evidence, label)
            installer.kill()
            out["timedOut"] = True
        installer.wait(timeout=60)
        out["seconds"] = round(time.monotonic() - started, 1)
    finally:
        sample_stop.set()
        sample_thread.join(timeout=87)
        if metadata_thread is not None:
            metadata_thread.join(timeout=1)
        log.close()
        out["sheet"] = sheet[-12:]
        out["quitSheet"] = quit_sheet[-12:]
        # Keep the probe history even when this check fails below.
        (evidence / f"{label}-sheet-probes.json").write_text(json.dumps(sheet[-40:]) + "\n")
        (evidence / f"{label}-quit-sheet-probes.json").write_text(json.dumps(quit_sheet[-40:]) + "\n")
        out["appTrace"] = fixed_app_trace(evidence, label)
    if change_thread is not None:
        change_thread.join(timeout=15)
        need((evidence / f"{label}-shared-parent-fixture.json").is_file(), "shared-parent-change-not-observed")
    if native_thread is not None:
        native_thread.join(timeout=9)
    out["returncode"] = installer.returncode
    steps.append({"argv": ["installer", "-pkg", "Remove.pkg"], "returncode": installer.returncode,
                  "role": label, "seconds": out["seconds"], "watchdogTimedOut": bool(out.get("timedOut"))})
    if clicked and installer.returncode != 0:
        removal_refusal_evidence(pids[0], work, evidence, label)
    need(clicked, "removal-sheet-not-confirmed")
    need(not out.get("timedOut"), "removal-watchdog-timed-out")
    if refuse_at is not None:
        logged = removal_script_diagnostics(evidence, label)
        out["expectedRefusalObserved"] = refuse_at in logged
        need(installer.returncode != 0, "expected-removal-refusal-not-observed")
    else:
        need(installer.returncode == 0, "remove-returned-nonzero")
    need(quit_clicked, "removal-quit-sheet-not-confirmed")
    time.sleep(5)
    remaining = {"app": APP.exists(), "launcher": LAUNCHER.exists(), "process": bool(payload_pids())}
    out["remaining"] = remaining
    if refuse_at is None:
        need(not any(remaining.values()), "removal-left-app-objects")
    return out


def removal_refusal_evidence(pid, work, evidence, label):
    """Observe the original failure on the disposable runner after Installer exits."""
    service_label = "dev.mobile-release-kit.desktop.android-register"
    try:
        with (evidence / f"{label}-maintenance-service.log").open("w") as output:
            for argv in (
                ["/bin/launchctl", "print", f"system/{service_label}"],
                ["/bin/launchctl", "print", f"gui/{os.getuid()}/{service_label}"],
                ["/usr/bin/sudo", "-n", "/usr/bin/log", "show", "--last", "3m", "--info",
                 "--style", "compact", "--predicate",
                 '(process == "smd" OR process == "backgroundtaskmanagementd" OR process == "launchd"'
                 ' OR subsystem CONTAINS[c] "servicemanagement") AND'
                 ' (eventMessage CONTAINS[c] "mobile-release-kit" OR eventMessage CONTAINS[c] "MobileReleaseKit")'],
            ):
                probe = subprocess.run(argv, capture_output=True, text=True, timeout=35)
                output.write(f"{argv[-1]} returned {probe.returncode}\n")
                output.write((probe.stdout + probe.stderr)[-24000:] + "\n")
        if pid in payload_pids():
            for control in ("Build tools", "About this installation", "Refresh preparation status"):
                ui_query(pid, work, "click", control, timeout=10)
            time.sleep(1)
            words = ui_query(pid, work, "texts", timeout=10).get("texts") or []
            relevant = [line for line in words if any(term in line.lower() for term in
                        ("prepare", "preparation", "native helper", "cleanup", "original request"))]
            (evidence / f"{label}-maintenance-ui.json").write_text(json.dumps(relevant[:30]) + "\n")
            subprocess.run(["/usr/sbin/screencapture", "-x", str(evidence / f"screen-{label}-maintenance.png")],
                           capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        (evidence / f"{label}-maintenance-probe-error.txt").write_text(type(error).__name__ + "\n")


def removal_archive_identities():
    before = STATE.lstat()
    need(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0,
         "removal-archive-parent")
    entries = {}
    for path in STATE.iterdir():
        if not path.name.startswith(".remove-"):
            continue
        info = path.lstat()
        need(re.fullmatch(r"\.remove-[0-9a-f]{32}", path.name) and path.name[8:] != "0" * 32
             and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
             and info.st_uid == info.st_gid == info.st_flags == 0 and info.st_dev == before.st_dev
             and info.st_ino != 0, "removal-archive-protection")
        entries[path.name] = (info.st_dev, info.st_ino)
    after = STATE.lstat()
    need(os.path.samestat(before, after) and before.st_mtime_ns == after.st_mtime_ns
         and before.st_ctime_ns == after.st_ctime_ns, "removal-archive-parent-changed")
    return entries


def remove_check(selection, work, evidence, steps, result, *, folder=None, seeded=None, credential=None):
    """Fresh install, launch, live removal through the matching Remove.pkg
    (confirming the app's own sheet), then check deletion or reinstall."""
    need("removal" in selection, "selection-has-no-removal-carrier")
    row = selection["next"]
    mode = result["mode"]
    repeat = mode in ("repeat", "repeat-after-dialogs")
    post_reinstall_prepare = mode == "post-reinstall-prepare"
    check_archives = repeat or post_reinstall_prepare or mode in ("removal-archive", "retained-transition")
    need((folder is None) == (seeded is None), "remove-baseline-selection")
    if folder is None:
        folder = fetch("next", row, work, steps)
    mount, roster = removal_image(selection["removal"], work, steps)
    result["removalImageRoster"] = roster
    if seeded is None:
        need(install("next", folder, steps, evidence=evidence) == 0, "remove-baseline-install-returned-nonzero")
    state = installed_state()
    result["afterInstall"] = state
    need((state["release"], state["packageVersion"], state["packageSha256"])
         == (row["release"], row["packageVersion"], row["packageSha256"]), "remove-baseline-identity")
    if seeded is None:
        seeded = seed_user_data()
    result["seededFiles"] = len(seeded)
    if post_reinstall_prepare:
        credential = seed_update_credential()
    background = os.environ.get("MRK_CHECK_REMOVE_INACTIVE") == "true"
    if background:
        install_macl_fixture((APP,))
        credential = seed_update_credential()
    diagnosing = os.environ.get("MRK_LIVE_REMOVAL_DIAGNOSTIC") == "true"
    try:
        out = live_remove(mount, work, evidence, steps, "remove",
                          observe_release=row["release"] if repeat or diagnosing else None, background=background)
    finally:
        if diagnosing:
            archive_shapes = {}
            for name in removal_archive_identities():
                p, _ = run(["/usr/bin/sudo", "-n", "/bin/ls", "-A", str(STATE / name)], 15)
                archive_shapes[name] = p.stdout.splitlines() if p.returncode == 0 else None
            (evidence / "remove-journal-cut.json").write_text(json.dumps({
                "app": APP.exists(), "launcher": LAUNCHER.exists(), "process": bool(payload_pids()),
                "archives": archive_shapes,
            }, indent=2) + "\n")
    result.update(removalSheet=out["sheet"], removalQuitSheet=out["quitSheet"],
                  removeReturn=out["returncode"], afterRemoval=out["remaining"])
    if out.get("timedOut"):
        result["removeTimedOut"] = True
    kept = manifest()
    result["userDataPreservedByRemoval"] = all(kept.get(k) == v for k, v in seeded.items())
    need(result["userDataPreservedByRemoval"], "user-data-changed-by-removal")
    try:
        if mode == "retained-transition" or background or post_reinstall_prepare:
            kept_credential = credential is not None and update_credential_matches(credential)
            result["credentialPreservedAfterRemoval"] = kept_credential
            need(kept_credential, "retained-credential-changed-by-removal")
        if mode == "delete-data":
            confirmed_data_deletion(mount, work, evidence, result, plant_decoys())
            return
        archives = removal_archive_identities() if check_archives else {}
        if check_archives:
            result["removalArchiveCount"] = len(archives)
            need(len(archives) == 1, "first-removal-archive-roster")
        # Reinstall after confirmed removal with the matching installer.
        rc = install("reinstall", folder, steps, evidence=evidence)
        result["reinstallReturn"] = rc
        need(rc == 0, "reinstall-returned-nonzero")
        again = installed_state()
        result["afterReinstall"] = again
        need((again["release"], again["packageVersion"], again["packageSha256"])
             == (row["release"], row["packageVersion"], row["packageSha256"]), "reinstall-identity")
        need(all(manifest().get(k) == v for k, v in seeded.items()), "user-data-changed-by-reinstall")
        if check_archives:
            after = removal_archive_identities()
            result["removalArchiveIdentityPreserved"] = after == archives
            need(after == archives, "reinstall-removal-archive-changed")
        if mode == "removal-archive":
            return
        observer = first_launch_observe if mode == "retained-transition" or background or post_reinstall_prepare else None
        result["launchAfterReinstall"] = launch_smoke("after-reinstall", work, evidence, steps, observe=observer)
        if observer is not None:
            require_runtime(result["launchAfterReinstall"], "reinstall-bundled-runtime")
            if background or post_reinstall_prepare:
                need(update_credential_matches(credential), "removal-reinstalled-credential")
            if post_reinstall_prepare:
                need(android_helper_status() == 113, "reinstall-prepare-helper-not-absent")
                try:
                    run_workspace_xctest("prepare-xctest", row, folder, again, work, evidence, steps, result)
                finally:
                    result["prepareAppTrace"] = trace = fixed_app_trace(evidence, "post-reinstall-prepare")
                need(any("app maintenance-worker=settled route=prepare branch=ObservedAbsent" in line
                         for line in trace), "reinstall-prepare-native-settlement")
                need(android_helper_status() == 113, "reinstall-prepare-helper-changed")
                need(removal_archive_identities() == archives, "reinstall-prepare-archive-changed")
                need(all(manifest().get(k) == v for k, v in seeded.items())
                     and update_credential_matches(credential), "reinstall-prepare-data-changed")
            return
        if repeat:
            if mode == "repeat-after-dialogs":
                _, before_repeat = uninstaller_while_installed(mount, work, evidence, steps, result)
            else:
                before_repeat = manifest()
            result["secondRemoval"] = live_remove(mount, work, evidence, steps, "remove-again", observe_release=row["release"])
            need(manifest() == before_repeat, "user-data-changed-by-second-removal")
            final = removal_archive_identities()
            result["finalRemovalArchiveCount"] = len(final)
            need(len(final) == 2 and all(final.get(name) == identity for name, identity in archives.items()),
                 "second-removal-archive-roster")
            return
        uninstaller_check(mount, work, evidence, steps, result)
    finally:
        subprocess.run(["/usr/bin/hdiutil", "detach", "-force", str(mount)], capture_output=True, timeout=120)


def home_path(relative):
    return Path.home() / relative


def update_credential_query():
    return subprocess.run(["/usr/bin/security", "find-generic-password", "-s", KEYCHAIN_SERVICES[0],
                           "-a", "mrk-upgrade-fixture", "-w"], capture_output=True, timeout=30)


def update_credential_matches(expected):
    observed = update_credential_query()
    return observed.returncode == 0 and observed.stdout.strip() == expected


def seed_update_credential():
    """An exact app service with a separate fixture account on the hosted user."""
    need(update_credential_query().returncode == 44, "upgrade-keychain-fixture-preexists-or-unavailable")
    value = os.urandom(24).hex()
    created = subprocess.run(["/usr/bin/security", "add-generic-password", "-s", KEYCHAIN_SERVICES[0],
                              "-a", "mrk-upgrade-fixture", "-w", value, "-T", "/usr/bin/security"],
                             capture_output=True, timeout=30)
    need(created.returncode == 0 and update_credential_matches(value.encode()), "upgrade-keychain-fixture-unreadable")
    return value.encode()


def click_when_ready(pid, work, title, role=None):
    args = ("click", title) if role is None else ("click", title, role)
    deadline = time.monotonic() + 30
    while True:
        result = ui_query(pid, work, *args, timeout=10)
        if result.get("clicked") == title or pid not in payload_pids() or time.monotonic() >= deadline:
            return result
        time.sleep(1)


def start_app_window(work, steps, label):
    process, step = run(["/usr/bin/open", str(APP)], 60)
    steps.append(dict(step, role=label + "-launch"))
    need(process.returncode == 0, label + "-open")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        live = payload_pids()
        if len(live) == 1 and window_count(live[0], work):
            return live[0]
        time.sleep(2)
    raise Failed(label + "-window")


def prepare_quit_check(selection, work, evidence, steps, result):
    row = selection["next"]
    folder = fetch("next", row, work, steps)
    need(install("next", folder, steps, evidence=evidence) == 0, "prepare-quit-install")
    state = result["afterInstall"] = installed_state()
    need(state["packageSha256"] == row["packageSha256"], "prepare-quit-install-identity")
    exercise_prepare_quit(work, evidence, steps, result)


def exercise_prepare_quit(work, evidence, steps, result):
    before_crashes = set(recent_crashes())
    pid = start_app_window(work, steps, "prepare-quit")
    result["prepareQuitNavigation"] = actions = []
    try:
        for title in ("Build tools", "About this installation"):
            action = click_when_ready(pid, work, title)
            actions.append(action)
            need(action.get("clicked") == title, "prepare-quit-navigation")
        ui_query(pid, work, "click", "Refresh preparation status", timeout=20)
        consent = "I want to stop the installed Android helper and prepare this application to quit."
        for title, role in ((consent, "AXCheckBox"), ("Prepare and quit", "AXButton")):
            action = click_when_ready(pid, work, title, role)
            actions.append(action)
            need(action.get("clicked") == title, "prepare-quit-control")
        script = work / "sheet.js"
        script.write_text(SHEET_JXA)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline and pid in payload_pids():
            cmd = ["/usr/bin/osascript", "-l", "JavaScript", str(script), str(pid)]
            probe = subprocess.run([*cmd, "probe", "quit"], capture_output=True, text=True, timeout=30)
            if probe.stdout.strip() == "present":
                clicked = subprocess.run([*cmd, "click", "quit"], capture_output=True, text=True, timeout=30)
                result["ordinaryQuitSheet"] = clicked.stdout.strip()
            time.sleep(2)
        need(not payload_pids(), "prepare-quit-app-still-running")
        result["newCrashReports"] = sorted(set(recent_crashes()) - before_crashes)
        need(not result["newCrashReports"], "prepare-quit-crash")
        census, _ = run(["/bin/ps", "-A", "-o", "command="], 30)
        need(census.returncode == 0, "prepare-quit-process-census")
        result["remainingInstalledProcesses"] = sum(line.lstrip().startswith(str(APP) + "/")
                                                    for line in census.stdout.splitlines())
        need(result["remainingInstalledProcesses"] == 0, "prepare-quit-left-installed-processes")
    finally:
        subprocess.run(["/usr/sbin/screencapture", "-x", str(evidence / "screen-prepare-quit.png")],
                       capture_output=True, timeout=60)
    result["reopen"] = launch_smoke("prepare-quit-reopen", work, evidence, steps)


def require_runtime(observation, failure):
    ui = observation.get("ui") or {}
    need(ui.get("runtimeCard") == "bundled" and not ui.get("workspaceErrorMarkers"), failure)


def install_macl_fixture(paths):
    # This is used only on fresh hosted verification installations. Preserve
    # the signed resources while reproducing the OS metadata on the app roots.
    for path in paths:
        p, _ = run(["/usr/bin/sudo", "-n", "/usr/bin/xattr", "-wx", "com.apple.macl", "07" * 72, str(path)], 15)
        need(p.returncode == 0, "macl-fixture-tag")
        p, _ = run(["/usr/bin/sudo", "-n", "/usr/bin/xattr", str(path)], 15)
        need(p.returncode == 0 and p.stdout.splitlines() == ["com.apple.macl"], "macl-fixture-attributes")
        p, _ = run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(path)], 60)
        need(p.returncode == 0, "macl-fixture-signature")


def detach_macl_fixture(volume, role, steps, result):
    # On disposable hosted runners, the diagnostic must preserve any earlier
    # Installer failure. An attached read-only fixture does not change the
    # later upgrade or archive roster, which use independent paths.
    try:
        completed, step = run(["/usr/bin/hdiutil", "detach", str(volume)], 45)
        steps.append(dict(step, role="macl-detach-" + role, stderr=tail_text(completed.stderr, 3)))
        result[f"detach{role.title()}Return"] = completed.returncode
    except (subprocess.TimeoutExpired, OSError) as error:
        result[f"detach{role.title()}Error"] = type(error).__name__


def macl_journal_recovery_check(selection, work, evidence, steps, result):
    """Exercise the exact signed 0.2.3-to-0.2.8 interrupted removal transition."""
    recovery = selection.get("recoveryInstall", selection["next"])
    recovery_removal = selection.get("recoveryRemoval", selection.get("removal"))
    need("previousRemoval" in selection and recovery_removal is not None
         and selection["previous"]["release"] == "macos26-arm64-desktop-09"
         and recovery["release"] == "macos26-arm64-desktop-14", "macl-recovery-selection")
    replay_only = os.environ.get("MRK_RECOVERY_UPGRADE_DIAGNOSTIC") == "true"
    result["oldAppletAssertionsReused"] = replay_only
    need(not STATE.exists(), "macl-recovery-existing-installation")
    if "recoveryInstall" in selection:
        need("removal" in selection, "macl-recovery-candidate-removal-selection")
        row = selection["next"]
        upgrade_folder = fetch("recoveryUpgrade", row, work, steps)
        producer = upgrade_folder / "producer-root/producer.json"
        source = json.loads(producer.read_bytes())["releaseSet"]["current"]["sourceCommit"]
        check_media = work / "upgrade-remove-proof"
        check_media.mkdir(mode=0o700)
        mount, _ = removal_image(selection["removal"], check_media, steps)
        try:
            removal = json.loads((mount / "remove-producer.json").read_bytes())
            remove_sha = digest(mount / "Remove.pkg")
            need(removal["installedProducerSha256"] == digest(producer)
                 and removal["sourceCommit"] == source and removal["release"] == row["release"]
                 and removal["packageVersion"] == row["packageVersion"]
                 and removal["packageSha256"] == remove_sha, "macl-recovery-candidate-pair")
            result["verifiedUpgradePair"] = {
                "sourceCommit": source, "packageVersion": row["packageVersion"], "release": row["release"],
                "installSha256": row["packageSha256"], "removeSha256": remove_sha,
            }
        finally:
            detach_macl_fixture(mount, "upgrade-media", steps, result)
    next_folder = fetch("recovery", recovery, work, steps)
    for role in selected_release_roles(selection):
        if role == "next":
            break
        expected = selection[role]
        folder = fetch(role, expected, work, steps)
        need(install(role, folder, steps, evidence=evidence) == 0, "macl-recovery-install-" + role)
        actual = installed_state()
        need(all(actual[key] == expected[key] for key in ("release", "packageVersion", "packageSha256")),
             "macl-recovery-identity-" + role)
    seeded, credential = seed_user_data(), seed_update_credential()
    original = APP.lstat()
    state = json.loads((STATE / "installation-v2.json").read_bytes())
    retained = [STATE / (".retained-app-" + row["app"]["invocation"]) for row in state["retained"]]
    need(len(retained) >= 1 and all(path.is_dir() for path in retained), "macl-recovery-retained-originals")
    retained_originals = {path: path.lstat() for path in retained}
    install_macl_fixture((APP, *retained))

    old_work = work / "previous-removal"
    old_work.mkdir(mode=0o700)
    old_mount, _ = removal_image(selection["previousRemoval"], old_work, steps)
    try:
        need(digest(old_mount / "Remove.pkg") == "3b5d40ff516c429df98147d57dbf9be36f5ea07bf71564e54dc440266fc469d6",
             "macl-recovery-previous-removal-digest")
        reason = hashlib.sha256(b"removal-payload-node-attributes").hexdigest()
        legacy = live_remove(old_mount, work, evidence, steps, "macl-interrupted",
                             observe_release=selection["previous"]["release"], refuse_at=reason)
        result["interruptedReturn"] = legacy["returncode"]
        result["interruptedExpectedDiagnostic"] = legacy["expectedRefusalObserved"]
    finally:
        archive_shapes = {}
        for name in removal_archive_identities():
            p, _ = run(["/usr/bin/sudo", "-n", "/bin/ls", "-A", str(STATE / name)], 15)
            archive_shapes[name] = p.stdout.splitlines() if p.returncode == 0 else None
        (evidence / "macl-interrupted-journal-cut.json").write_text(json.dumps({
            "app": APP.exists(), "launcher": LAUNCHER.exists(), "process": bool(payload_pids()),
            "archives": archive_shapes,
        }, indent=2) + "\n")
        detach_macl_fixture(old_mount, "interrupted", steps, result)
    # Qualify the signed historical fixture by its original app inode and
    # durable failure record. The outer diagnostic can name a later refusal.
    result["interruptedDataPreserved"] = (
        all(manifest().get(key) == value for key, value in seeded.items())
        and update_credential_matches(credential)
    )
    need(result["interruptedDataPreserved"], "macl-recovery-interrupted-data")
    need(not any(legacy["remaining"].values()), "macl-recovery-interruption-before-app-withdrawal")
    archives = removal_archive_identities()
    need(len(archives) == 1, "macl-recovery-original-journal")
    archived = STATE / next(iter(archives))
    p, _ = run(["/usr/bin/sudo", "-n", "/usr/bin/stat", "-f", "%i", str(archived / "app")], 15)
    need(p.returncode == 0 and p.stdout.strip() == str(original.st_ino)
         and all(path.is_dir() and os.path.samestat(before, path.lstat())
                 for path, before in retained_originals.items()),
         "macl-recovery-withdrawn-originals")
    p, _ = run(["/usr/bin/sudo", "-n", "/bin/cat", str(archived / "first-failure.json")], 15)
    need(p.returncode == 0 and 0 < len(p.stdout) <= 4096, "macl-recovery-failure-record")
    first_failure = json.loads(p.stdout)
    need(first_failure["firstFailure"] == {"phase": "payload-roster-removal", "kind": "post-mismatch"},
         "macl-recovery-failure-phase")
    result["interruptedFailure"] = first_failure["firstFailure"]
    first_digest = hashlib.sha256(p.stdout.encode()).hexdigest()
    result["historicalFixtureQualified"] = True
    result["seededFileCount"] = len(seeded)

    # A later attempt on the physical Mac reached linked journal creation
    # but stopped with a protected empty journal and the original intact.
    empty = STATE / (".remove-" + secrets.token_hex(16))
    run(["/usr/bin/sudo", "-n", "/bin/mkdir", "-m", "0700", str(empty)], 15, check=True)
    prior_archives = archives
    archives = removal_archive_identities()
    need(set(archives) - set(prior_archives) == {empty.name}
         and all(archives.get(name) == identity for name, identity in prior_archives.items()),
         "macl-preadmission-identity")
    empty_before = empty.lstat()
    check_empty = ["/usr/bin/sudo", "-n", "/bin/ls", "-A", str(empty)]
    p, _ = run(check_empty, 15, check=True)
    need(not p.stdout.strip(), "macl-preadmission-not-empty")
    result["priorEmptyJournal"] = True

    # Mount the previously verified legacy image again to match the
    # physical layout. Both images stay mounted for the 0.2.8 applet checks.
    legacy_image = old_work / "removal/MobileReleaseKit-Remove.dmg"
    need(digest(legacy_image) == selection["previousRemoval"]["imageSha256"], "macl-legacy-image-changed")
    p, step = run(["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen",
                   "-plist", str(legacy_image)], 300, check=True)
    steps.append(dict(step, role="macl-legacy-image-reattach"))
    legacy_mounts = [e["mount-point"] for e in plistlib.loads(p.stdout.encode())["system-entities"] if e.get("mount-point")]
    need(len(legacy_mounts) == 1, "macl-legacy-image-mount")
    legacy_mount = Path(legacy_mounts[0])
    try:
        repair_mount, _ = removal_image(recovery_removal, work, steps)
        try:
            need(repair_mount != legacy_mount and str(repair_mount).startswith(str(legacy_mount) + " "),
                 "macl-duplicate-volume-label")
            result["duplicateSignedRemovalImages"] = True
            if not replay_only:
                keep_incomplete = uninstaller_diagnostic_run(repair_mount, work, evidence, "macl-duplicate-keep-incomplete",
                                                             [KEEP_LABEL, "Continue", None, "OK"])
                selected = json.loads((evidence / "macl-duplicate-keep-incomplete-package-selection.json").read_bytes())
                need(len(selected) == 1 and selected[0].endswith(str(repair_mount / "Remove.pkg")),
                     "macl-duplicate-image-wrong-package")
                need(dialog_says(keep_incomplete, "removal could not be confirmed. Your data was kept.")
                     and all(manifest().get(key) == value for key, value in seeded.items())
                     and update_credential_matches(credential), "macl-duplicate-incomplete-keep-data")
                result["uninstallerDuplicateImageKeptOriginals"] = True
                # The prior process withdrew the app and launcher, but its removal
                # never finished. Signing and both data confirmations cannot turn that
                # missing pathname into permission to clean up this hosted user's data.
                refusal = uninstaller_run(repair_mount, work, evidence, "macl-incomplete-delete",
                                          [DELETE_LABEL, "Delete All Data", "Continue", None, "OK"])
                result["uninstallerIncompleteRemovalRefused"] = dialog_says(
                    refusal, "removal could not be confirmed. Your data was kept.")
                need(result["uninstallerIncompleteRemovalRefused"], "macl-incomplete-deletion-reported-success")
                need(all(manifest().get(key) == value for key, value in seeded.items())
                     and update_credential_matches(credential), "macl-incomplete-deletion-touched-fake-data")
            output = work / "macl-recovery-installer.raw"
            started = time.monotonic()
            try:
                with output.open("w") as stream:
                    p = subprocess.run(
                        ["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-verbose", "-pkg",
                         str(repair_mount / "Remove.pkg"), "-target", "/"],
                        stdout=stream, stderr=subprocess.STDOUT, timeout=240,
                    )
            except subprocess.TimeoutExpired:
                p = None
            finally:
                result["resumeSeconds"] = round(time.monotonic() - started, 1)
                with output.open("r", errors="replace") as stream:
                    lines = deque(stream, maxlen=80)
                (evidence / "macl-recovery-installer.log").write_text(
                    "\n".join(tail_text("".join(lines), 80)) + "\n")
            if p is None:
                result["resumeTimedOut"] = True
                removal_script_diagnostics(evidence, "macl-recovery-timeout")
                raise Failed("macl-signed-recovery-timeout")
            steps.append({"argv": ["installer", "-verbose", "-pkg", "Remove.pkg", "-target", ""],
                          "role": "macl-signed-resume", "returncode": p.returncode,
                          "seconds": result["resumeSeconds"]})
            result["resumeReturn"] = p.returncode
            if p.returncode != 0:
                removal_script_diagnostics(evidence, "macl-recovery")
            need(p.returncode == 0, "macl-signed-recovery-returned-nonzero")
            if not replay_only:
                keep = uninstaller_run(repair_mount, work, evidence, "macl-completed-keep",
                                       [KEEP_LABEL, "Continue", None, "OK"])
                result["uninstallerCompletedKeepConfirmed"] = dialog_says(keep, "was removed. Your data was kept.")
                need(result["uninstallerCompletedKeepConfirmed"], "macl-complete-report-not-recognized")
        finally:
            detach_macl_fixture(repair_mount, "recovery", steps, result)
    finally:
        detach_macl_fixture(legacy_mount, "legacy", steps, result)

    result["payloadAbsent"] = (not APP.exists() and not LAUNCHER.exists()
                               and not payload_pids() and not any(path.exists() for path in retained))
    need(result["payloadAbsent"], "macl-recovery-payload-present")
    after = removal_archive_identities()
    added = set(after) - set(archives)
    need(len(added) == 1 and all(after.get(key) == value for key, value in archives.items()),
         "macl-recovery-linked-journal")
    p, _ = run(check_empty, 15, check=True)
    empty_after = empty.lstat()
    result["priorEmptyJournalPreserved"] = (not p.stdout.strip()
        and os.path.samestat(empty_before, empty_after)
        and empty_before.st_mtime_ns == empty_after.st_mtime_ns
        and empty_before.st_ctime_ns == empty_after.st_ctime_ns)
    need(result["priorEmptyJournalPreserved"], "macl-preadmission-changed")
    p, _ = run(["/usr/bin/sudo", "-n", "/bin/cat",
                str(STATE / next(iter(added)) / "payload-absent-observed.json")], 15)
    need(p.returncode == 0 and 0 < len(p.stdout) <= 4096, "macl-recovery-terminal-record")
    terminal = json.loads(p.stdout)
    need(terminal["prefix"] == "payload-absent-observed"
         and terminal["previousAttempt"]["recordSha256"] == first_digest, "macl-recovery-record-link")
    result["priorFailureLinked"] = True
    need(all(manifest().get(key) == value for key, value in seeded.items())
         and update_credential_matches(credential), "macl-recovery-resumed-data")

    result["reinstallReturn"] = install("macl-reinstall", next_folder, steps, evidence=evidence)
    need(result["reinstallReturn"] == 0, "macl-recovery-reinstall-returned-nonzero")
    actual = installed_state()
    need(all(actual[key] == recovery[key] for key in ("release", "packageVersion", "packageSha256")),
         "macl-recovery-reinstalled-identity")
    result["launchAfterReinstall"] = launch_smoke("macl-reinstalled", work, evidence, steps, observe=first_launch_observe)
    require_runtime(result["launchAfterReinstall"], "macl-recovery-reinstalled-runtime")
    result["dataPreserved"] = (all(manifest().get(key) == value for key, value in seeded.items())
                               and update_credential_matches(credential))
    need(result["dataPreserved"], "macl-recovery-reinstalled-data")
    p, _ = run(check_empty, 15, check=True)
    empty_reinstalled = empty.lstat()
    result["priorEmptyJournalPreservedAfterReinstall"] = (not p.stdout.strip()
        and os.path.samestat(empty_before, empty_reinstalled)
        and empty_before.st_mtime_ns == empty_reinstalled.st_mtime_ns
        and empty_before.st_ctime_ns == empty_reinstalled.st_ctime_ns)
    need(result["priorEmptyJournalPreservedAfterReinstall"], "macl-reinstall-preadmission-changed")
    if "recoveryInstall" in selection:
        row = selection["next"]
        archives_before = removal_archive_identities()
        need(len(archives_before) == 3, "macl-recovery-upgrade-archive-baseline")
        previous_app = APP.lstat()
        result["recoveryUpgradeReturn"] = install("recoveryUpgrade", upgrade_folder, steps, evidence=evidence)
        need(result["recoveryUpgradeReturn"] == 0, "macl-recovery-upgrade-installer")
        actual = result["afterRecoveryUpgrade"] = installed_state()
        need(all(actual[key] == row[key] for key in ("release", "packageVersion", "packageSha256")),
             "macl-recovery-upgrade-identity")
        need(actual["sourceCommit"] == result["verifiedUpgradePair"]["sourceCommit"],
             "macl-recovery-upgrade-source")
        installed = json.loads((STATE / "installation-v2.json").read_bytes())
        previous_rows = [item for item in installed["retained"]
                         if item["release"]["packageSha256"] == recovery["packageSha256"]]
        need(len(previous_rows) == 1 and hex_field(previous_rows[0]["app"]["invocation"], 32),
             "macl-recovery-upgrade-predecessor")
        kept = STATE / (".retained-app-" + previous_rows[0]["app"]["invocation"])
        result["recoveryUpgradePredecessorPreserved"] = os.path.samestat(previous_app, kept.lstat())
        need(result["recoveryUpgradePredecessorPreserved"], "macl-recovery-upgrade-predecessor-original")
        result["recoveryUpgradeRuntime"] = launch_smoke("macl-after-upgrade", work, evidence, steps, observe=first_launch_observe)
        require_runtime(result["recoveryUpgradeRuntime"], "macl-recovery-upgrade-runtime")
        need(android_helper_status() == 113, "macl-recovery-upgrade-helper-not-absent")
        run_workspace_xctest("prepare-xctest", row, upgrade_folder, actual, work, evidence, steps, result)
        need(any("app maintenance-worker=settled route=prepare branch=ObservedAbsent" in line
                 for line in result["prepareAppTrace"]), "macl-recovery-upgrade-native-settlement")
        need(android_helper_status() == 113, "macl-recovery-upgrade-helper-changed")
        result["recoveryUpgradeArchivesPreserved"] = removal_archive_identities() == archives_before
        result["recoveryUpgradeDataPreserved"] = (all(manifest().get(k) == v for k, v in seeded.items())
                                                  and update_credential_matches(credential))
        need(result["recoveryUpgradeArchivesPreserved"], "macl-recovery-upgrade-archive-changed")
        need(result["recoveryUpgradeDataPreserved"], "macl-recovery-upgrade-data-changed")


def archived_upgrade_check(selection, work, evidence, steps, result):
    """Exercise the signed writer on three preserved journals using one real removal."""
    need({"recoveryInstall", "recoveryRemoval"} <= set(selection), "archived-upgrade-selection")
    previous, current = selection["recoveryInstall"], selection["next"]
    old_folder = fetch("archived-previous", previous, work, steps)
    new_folder = fetch("archived-next", current, work, steps)
    need(install("archived-previous", old_folder, steps, evidence=evidence) == 0, "archived-upgrade-initial")
    need(installed_state()["packageSha256"] == previous["packageSha256"], "archived-upgrade-initial-identity")
    seeded, credential = seed_user_data(), seed_update_credential()
    # Empty pre-admission records are inert. The original signed remover
    # independently reads this roster and creates the genuine completion.
    for _ in range(2):
        path = STATE / (".remove-" + secrets.token_hex(16))
        run(["/usr/bin/sudo", "-n", "/bin/mkdir", "-m", "0700", str(path)], 15, check=True)
    empty = removal_archive_identities()
    need(len(empty) == 2, "archived-upgrade-empty-roster")
    mount, _ = removal_image(selection["recoveryRemoval"], work, steps)
    try:
        removed = live_remove(mount, work, evidence, steps, "archived-prior-remove",
                              observe_release=previous["release"], background=True)
        result["removeReturn"] = removed["returncode"]
        need(removed["returncode"] == 0, "archived-upgrade-prior-removal")
    finally:
        detach_macl_fixture(mount, "fixture", steps, result)
    journals = removal_archive_identities()
    need(len(journals) == 3 and all(journals.get(name) == identity for name, identity in empty.items()),
         "archived-upgrade-three-original-journals")
    result["journalsBeforeReinstall"] = len(journals)
    result["dataPreservedAfterRemoval"] = (all(manifest().get(k) == v for k, v in seeded.items())
                                           and update_credential_matches(credential))
    need(result["dataPreservedAfterRemoval"], "archived-upgrade-data-after-removal")
    result["reinstallReturn"] = install("archived-reinstall", old_folder, steps, evidence=evidence)
    need(result["reinstallReturn"] == 0, "archived-upgrade-reinstall")
    need(installed_state()["packageSha256"] == previous["packageSha256"], "archived-upgrade-reinstall-identity")
    need(removal_archive_identities() == journals, "archived-upgrade-reinstall-journals")
    previous_original = APP.lstat()
    result["recoveryUpgradeReturn"] = install("archived-next", new_folder, steps, evidence=evidence)
    need(result["recoveryUpgradeReturn"] == 0, "archived-upgrade-installer")
    installed = result["afterRecoveryUpgrade"] = installed_state()
    need(installed["packageSha256"] == current["packageSha256"], "archived-upgrade-identity")
    state = json.loads((STATE / "installation-v2.json").read_bytes())
    predecessors = [row for row in state["retained"] if row["release"]["packageSha256"] == previous["packageSha256"]]
    need(len(predecessors) == 1 and hex_field(predecessors[0]["app"]["invocation"], 32),
         "archived-upgrade-retained-predecessor")
    old_app = STATE / (".retained-app-" + predecessors[0]["app"]["invocation"])
    need(os.path.samestat(previous_original, old_app.lstat()), "archived-upgrade-retained-predecessor-original")
    result["journalIdentitiesPreserved"] = removal_archive_identities() == journals
    result["dataPreservedAfterUpgrade"] = (all(manifest().get(k) == v for k, v in seeded.items())
                                          and update_credential_matches(credential))
    need(result["journalIdentitiesPreserved"] and result["dataPreservedAfterUpgrade"],
         "archived-upgrade-preservation")
    result["recoveryUpgradeRuntime"] = launch_smoke("archived-current", work, evidence, steps, observe=first_launch_observe)
    require_runtime(result["recoveryUpgradeRuntime"], "archived-upgrade-runtime")
    need(android_helper_status() == 113, "archived-upgrade-helper-not-absent")
    run_workspace_xctest("prepare-xctest", current, new_folder, installed, work, evidence, steps, result)
    need(any("app maintenance-worker=settled route=prepare branch=ObservedAbsent" in line
             for line in result["prepareAppTrace"]), "archived-upgrade-native-settlement")
    need(android_helper_status() == 113 and removal_archive_identities() == journals,
         "archived-upgrade-quit-journal-preservation")

    if os.environ.get("MRK_APFS_ARCHIVE_ACCEPTANCE") == "true" or os.environ.get("MRK_FROZEN_RELEASE_MEDIA"):
        remove_after_archived_upgrade(selection, work, evidence, steps, result, new_folder,
                                      journals, seeded, credential)


def remove_after_archived_upgrade(selection, work, evidence, steps, result, folder,
                                  prior_journals, seeded, credential):
    """Verify the fixed signed remover and reinstaller on an upgraded archive roster."""
    assert all(name.startswith(".remove-") and hex_field(name[8:], 32) for name in prior_journals)
    row = selection["next"]
    remove_work = work / "archived-current-removal"
    remove_work.mkdir(mode=0o700)
    mount, _ = removal_image(selection["removal"], remove_work, steps)
    try:
        package = json.loads((mount / "remove-producer.json").read_bytes())
        current = json.loads((folder / "producer-root/producer.json").read_bytes())["releaseSet"]["current"]
        need(package["sourceCommit"] == current["sourceCommit"]
             and package["installedProducerSha256"] == digest(folder / "producer-root/producer.json")
             and package["packageSha256"] == digest(mount / "Remove.pkg"), "archived-current-remove-pair")
        result["matchedRemovePackageSha256"] = package["packageSha256"]
        state = STATE / "installation-v2.json"
        state_sha = digest(state)
        removed = live_remove(mount, work, evidence, steps, "archived-current-remove", observe_release=row["release"])
        result["candidateRemoveReturn"] = removed["returncode"]
        need(removed["returncode"] == 0, "archived-current-remove")
        need(not APP.exists() and not LAUNCHER.exists() and not payload_pids(), "archived-current-payload-still-present")
        need(digest(state)==state_sha, "archived-current-installation-state-changed")
        receipt = STATE.parent / ("MobileReleaseKit-RemovalComplete-v1-" + state_sha)
        expected = f"Mobile Release Kit removal complete v1\n{state_sha}\n".encode()
        metadata = receipt.lstat()
        need(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == metadata.st_gid == 0
             and metadata.st_nlink == 1 and metadata.st_mode & 0o022 == 0
             and metadata.st_size == len(expected) and receipt.read_bytes() == expected,
             "archived-current-native-receipt")
        result["candidateNativeCompletionReceiptVerified"] = True
        after = removal_archive_identities()
        added = set(after) - set(prior_journals)
        need(len(added) == 1 and all(after.get(name) == identity for name, identity in prior_journals.items()),
             "archived-current-original-journal-changed")
        name, = added
        need(name.startswith(".remove-") and hex_field(name[8:], 32), "archived-current-journal-name")
        terminal, _ = run(["/usr/bin/sudo", "-n", "/bin/cat",
                           str(STATE / name / "payload-absent-observed.json")], 15, check=True)
        need(0 < len(terminal.stdout) <= 4096, "archived-current-terminal-size")
        raw = json.loads(terminal.stdout)
        need(raw["prefix"] == "payload-absent-observed", "archived-current-terminal-record")
        result["candidateRemovalTerminalSha256"] = hashlib.sha256(terminal.stdout.encode()).hexdigest()
        result["priorJournalsPreservedAfterCandidateRemoval"] = True
        result["candidateRemovalDataPreserved"] = (all(manifest().get(key) == value for key, value in seeded.items())
                                                      and update_credential_matches(credential))
        need(result["candidateRemovalDataPreserved"], "archived-current-keep-data-changed")
        result["candidateReinstallReturn"] = install("archived-current-reinstall", folder, steps, evidence=evidence)
        need(result["candidateReinstallReturn"] == 0, "archived-current-reinstall")
        installed = result["candidateReinstalled"] = installed_state()
        need(installed["packageSha256"] == row["packageSha256"], "archived-current-reinstall-identity")
        need(removal_archive_identities() == after, "archived-current-reinstall-journal-changed")
        result["allJournalsPreservedAfterCandidateReinstall"] = len(after)
        result["candidateReinstallRuntime"] = launch_smoke("archived-current-reinstalled", work, evidence, steps,
                                                           observe=first_launch_observe)
        require_runtime(result["candidateReinstallRuntime"], "archived-current-reinstall-runtime")
        result["candidateReinstallDataPreserved"] = (all(manifest().get(key) == value for key, value in seeded.items())
                                                      and update_credential_matches(credential))
        need(result["candidateReinstallDataPreserved"], "archived-current-reinstall-data-changed")
    finally:
        detach_macl_fixture(mount, "archived-current-removal", steps, result)


def retained_transition_check(selection, work, evidence, steps, result):
    """Replay the owner's signed upgrade history before testing preparation or removal."""
    preparing = result["mode"] == "retained-prepare"
    need("initial" in selection and (preparing or "removal" in selection), "retained-transition-selection")
    roles = selected_release_roles(selection)
    folders = {}
    for role in roles:
        package = selection[role]
        folders[role] = fetch(role, package, work, steps)
    for role in roles:
        need(install(role, folders[role], steps, evidence=evidence) == 0, f"retained-{role}-install")
        observed = installed_state()
        result[f"retainedInstall-{role}"] = observed
        need(all(observed[key] == selection[role][key] for key in ("release", "packageVersion", "packageSha256")),
             f"retained-{role}-identity")
        if role == "initial":
            launch_smoke("retained-initial-launch", work, evidence, steps)
            seeded = seed_user_data()
            credential = seed_update_credential()
        else:
            current = manifest()
            need(all(current.get(key) == value for key, value in seeded.items())
                 and update_credential_matches(credential), f"retained-{role}-data")
            if role != "next":
                launch_smoke(f"retained-{role}-launch", work, evidence, steps)

    state = json.loads((STATE / "installation-v2.json").read_text())
    expected = [selection[role]["packageSha256"] for role in roles[:-1]]
    need([row["release"]["packageSha256"] for row in state["retained"]] == expected,
         "retained-original-generations")
    result["retainedBundles"] = []
    for row in state["retained"]:
        original = row["app"]
        invocation = original["invocation"]
        need(original["location"] == "retained" and hex_field(invocation, 32), "retained-original-path")
        path = STATE / (".retained-app-" + invocation)
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
             and info.st_ino == original["identity"]["inode"], "retained-original-inode")
        attributes = subprocess.run(["/usr/bin/xattr", str(path)], capture_output=True, timeout=10, check=True)
        result["retainedBundles"].append({"release": row["release"]["release"],
            "hasMacl": b"com.apple.macl" in attributes.stdout.splitlines()})
    result["firstLaunch"] = launch_smoke("retained-first-launch", work, evidence, steps, observe=first_launch_observe)
    require_runtime(result["firstLaunch"], "retained-first-launch-runtime")
    if preparing:
        result["helperStatusBeforePrepare"] = android_helper_status()
        run_workspace_xctest("prepare-xctest", selection["next"], folders["next"],
                             result["retainedInstall-next"], work, evidence, steps, result)
        current = manifest()
        result["userDataPreservedByPrepare"] = all(current.get(key) == value for key, value in seeded.items())
        need(result["userDataPreservedByPrepare"], "retained-prepare-data")
    else:
        remove_check(selection, work, evidence, steps, result, folder=folders["next"], seeded=seeded,
                     credential=credential)
    result["credentialPreserved"] = update_credential_matches(credential)
    need(result["credentialPreserved"], "retained-credential-changed")


PROJECT_PICKER_JXA = """function run(argv) {
  ObjC.import('Foundation');
  const se = Application('System Events');
  const matches = se.processes.whose({unixId: Number(argv[0])});
  if (matches.length !== 1 || matches[0].windows().length !== 1) return 'no-project-window';
  const app = matches[0], panels = app.windows[0].sheets();
  if (panels.length !== 1) return 'no-project-sheet';
  const panel = panels[0], buttons = panel.buttons();
  if (!buttons.some(b => b.name() === 'Cancel') || !buttons.some(b => b.name() === 'Open')
      || panel.sheets().length) return 'unexpected-project-sheet';
  const titled = panel.name() === 'Choose a mobile project folder' ||
    panel.staticTexts().some(t => t.value() === 'Choose a mobile project folder');
  if (!titled) return 'unexpected-project-title';
  app.frontmost = true;
  se.keystroke('g', {using: ['command down', 'shift down']});
  for (let i = 0; i < 15 && !panel.sheets().length; ++i) $.NSThread.sleepForTimeInterval(0.2);
  if (panel.sheets().length !== 1) return 'missing-project-navigation';
  se.keystroke(argv[1]);
  se.keyCode(36);
  for (let i = 0; i < 15 && panel.sheets().length; ++i) $.NSThread.sleepForTimeInterval(0.2);
  if (panel.sheets().length) return 'project-navigation-still-open';
  const open = panel.buttons().filter(b => b.name() === 'Open' && b.enabled());
  if (open.length !== 1) return 'no-original-open-button';
  open[0].click();
  return 'selected';
}
"""


def workspace_cli_check(selection, work, evidence, steps, result):
    row = selection["next"]
    folder = fetch("next", row, work, steps)
    need(install("next", folder, steps, evidence=evidence) == 0, "workspace-install")
    result["afterInstall"] = installed_state()
    need(result["afterInstall"]["packageSha256"] == row["packageSha256"], "workspace-install-identity")
    fixture = work / "workspace"
    shutil.copytree(Path(__file__).resolve().parents[2] / "tests/fixtures/macos_android_journey", fixture)
    originals = {p.relative_to(fixture): digest(p) for p in fixture.rglob("*") if p.is_file()}
    before_crashes = set(recent_crashes())
    pid = start_app_window(work, steps, "workspace")
    try:
        overview = first_launch_observe(pid, work, evidence, "workspace-first-launch")
        result["firstConnection"] = overview
        need(overview["runtimeCard"] == "bundled" and not overview["workspaceErrorMarkers"], "workspace-first-connection")
        need(overview["cliStatus"]["returncode"] == 3 and overview["cliStatus"]["guidance"], "workspace-default-denial")
        nav = click_when_ready(pid, work, "Overview", "AXButton")
        result["overviewNavigation"] = nav
        need(nav.get("clicked") == "Overview", "workspace-overview-navigation")
        opened = click_when_ready(pid, work, "Choose project folder", "AXButton")
        need(opened.get("clicked") == "Choose project folder", "workspace-open-project-picker")
        script = work / "project-picker.js"
        script.write_text(PROJECT_PICKER_JXA)
        picked = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(script), str(pid), str(fixture.resolve())],
                                capture_output=True, text=True, timeout=30)
        result["picker"] = picked.stdout.strip()
        need(picked.returncode == 0 and result["picker"] == "selected", "workspace-native-picker")
        details = "Project details & saved observations"
        need(click_when_ready(pid, work, details).get("clicked") == details, "workspace-project-details")
        deadline = time.monotonic() + 60
        while True:
            texts = ui_query(pid, work, "texts", timeout=10).get("texts") or []
            need(not any(marker in text for marker in WORKSPACE_ERROR_MARKERS for text in texts), "workspace-view-error")
            if "org.mrk.fixture" in texts:
                break
            need(time.monotonic() < deadline, "workspace-fixture-not-observed")
            time.sleep(2)
        result["fixtureWorkspaceObserved"] = True
        for title in ("Open all project settings", "Advanced · CLI / AI access", "Check access",
                      "Allow selected project for 1 hour"):
            action = click_when_ready(pid, work, title)
            result.setdefault("accessNavigation", []).append(action)
            need(action.get("clicked") == title, "workspace-cli-access-control")
        cli = APP / "Contents/MacOS/mrk"
        statuses = result["statusReturns"] = []
        for expected in (0, 4):
            deadline = time.monotonic() + 25
            while True:
                status = subprocess.run([str(cli), "status", "--json"], capture_output=True, text=True, timeout=20)
                if status.returncode == expected:
                    break
                need(time.monotonic() < deadline, "workspace-cli-status")
                time.sleep(1)
            statuses.append(status.returncode)
            payload = json.loads(status.stdout + status.stderr)
            need(type(payload) is dict, "workspace-cli-json")
            if expected == 0:
                need(payload.get("error") is None, "workspace-cli-grant-refused")
                revoked = click_when_ready(pid, work, "Turn off access", "AXButton")
                need(revoked.get("clicked") == "Turn off access", "workspace-cli-revoke-control")
            else:
                need(payload.get("error") == "access_denied", "workspace-cli-explicit-revoked-denial")
        deadline = time.monotonic() + 15
        while True:
            texts = ui_query(pid, work, "texts", timeout=10).get("texts") or []
            if "Off at last check" in texts:
                result["offUiObservedAfterDenial"] = True
                break
            need(time.monotonic() < deadline, "workspace-cli-off-ui-after-denial")
            time.sleep(1)
        result["fixtureUnchanged"] = {p.relative_to(fixture): digest(p) for p in fixture.rglob("*") if p.is_file()} == originals
        need(result["fixtureUnchanged"], "workspace-cli-modified-fixture")
        need(set(recent_crashes()) == before_crashes, "workspace-crash")
    finally:
        stop_app(payload_pids())


def workspace_resource_observations(stop, samples):
    started = time.monotonic()
    while not stop.wait(1):
        try:
            pids = payload_pids()
            if len(pids) == 1:
                sample = resource_sample(pids[0], started, "workspace")
                if sample["appRssKiB"] is not None:
                    samples.append(dict(sample, epochMillis=time.time_ns() // 1_000_000))
        except (OSError, subprocess.TimeoutExpired):
            return


def workspace_resource_summary(transcript, samples):
    stages = ("project-open", "cli-allow", "cli-revoke")
    events = re.findall(r"(?m)^MRK_NORMAL_PROJECT_STAGE=([a-z-]+);result=(started|passed);epochMillis=([0-9]{13})$",
                        transcript)
    result = {}
    for stage in stages:
        times = {event: int(epoch) for name, event, epoch in events if name == stage}
        if set(times) == {"started", "passed"} and times["started"] <= times["passed"]:
            window = [sample for sample in samples
                      if times["started"] <= sample["epochMillis"] <= times["passed"]]
            result[stage] = {"seconds": (times["passed"] - times["started"]) / 1000, "samples": len(window),
                             "peakRssKiB": max((s["rssKiB"] for s in window), default=None),
                             "meanCpuPercent": round(sum(s["cpuPercent"] for s in window) / len(window), 1)
                             if window else None}
    return result


def workspace_xctest(selection, work, evidence, steps, result):
    row = selection["next"]
    folder = fetch("next", row, work, steps)
    need(install("next", folder, steps, evidence=evidence) == 0, "workspace-xctest-install")
    result["afterInstall"] = installed_state()
    run_workspace_xctest(result["mode"], row, folder, result["afterInstall"], work, evidence, steps, result)


def android_helper_status():
    return subprocess.run(["/bin/launchctl", "print", "system/dev.mobile-release-kit.desktop.android-register"],
                          capture_output=True, timeout=10).returncode


def run_workspace_xctest(mode, row, folder, installed, work, evidence, steps, result):
    """Run the original production UI check on the caller's verified installed package."""
    origin = json.loads((folder / "PREPARED.json").read_text())["origin"]
    source, harness = installed["sourceCommit"], os.environ["GITHUB_SHA"]
    same_frozen_source = bool(os.environ.get("MRK_FROZEN_RELEASE_MEDIA")) and os.environ.get("GITHUB_REF") == "refs/heads/main"
    need(source == origin["source"] and (source != harness or same_frozen_source) and hex_field(harness, 40)
         and installed["packageSha256"] == row["packageSha256"], "workspace-xctest-source-binding")
    temporary = work / "xctest-tmp"
    temporary.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "USER": "runner",
           "LOGNAME": "runner", "TMPDIR": str(temporary) + "/", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
           "TZ": "UTC", "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer",
           "TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB": "github-hosted-macos26-arm64",
           "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE": source, "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE": harness,
           "TEST_RUNNER_MRK_NORMAL_UI_CURRENT_ORDINARY": "current-candidate-ordinary-only-v1"}
    if same_frozen_source:
        env["TEST_RUNNER_MRK_NORMAL_UI_SAME_FROZEN_SOURCE"] = "true"
    project = Path(__file__).resolve().parents[2] / "desktop/native/macos-normal-ui/MRKNormalAppUI.xcodeproj"
    derived = work / "DerivedData"
    base = ["/usr/bin/xcodebuild", "-project", str(project), "-scheme", "MRKNormalAppUI",
            "-configuration", "Debug", "-destination", "platform=macOS,arch=arm64",
            "-destination-timeout", "15", "-derivedDataPath", str(derived), "-jobs", "2",
            "-disableAutomaticPackageResolution", "COMPILER_INDEX_STORE_ENABLE=NO"]
    with (work / "workspace-xctest-build.private.log").open("wb") as log:
        built = subprocess.run([*base, "build-for-testing"], env=env, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    result["xctestBuildReturn"] = built.returncode
    need(built.returncode == 0, "workspace-xctest-build")
    manifests = list((derived / "Build/Products").glob("MRKNormalAppUI_*.xctestrun"))
    need(len(manifests) == 1 and manifests[0].is_file() and not manifests[0].is_symlink(),
         "workspace-xctest-single-original-manifest")
    prepare = mode == "prepare-xctest"
    recovery = mode == "recovery-xctest"
    method = {"prepare-xctest": "testCurrentPrepareToQuit", "workspace-xctest": "testCurrentGuidedWorkspaceAndCli",
              "recovery-xctest": "testCurrentSavedVersionRecovery"}[mode]
    if recovery:
        project_path, baseline = seed_signed_gui_recovery(row, folder, work, env, result)
    bundle = work / "project-test.xcresult"
    before_crashes = set(recent_crashes())
    resource_samples, stop_sampling = [], threading.Event()
    sampler = None
    if not (prepare or recovery):
        sampler = threading.Thread(target=workspace_resource_observations, args=(stop_sampling, resource_samples),
                                   daemon=True)
        sampler.start()
    try:
        tested = subprocess.run(["/usr/bin/xcodebuild", "test-without-building", "-xctestrun", str(manifests[0]),
                                 "-destination", "platform=macOS,arch=arm64", "-destination-timeout", "15",
                                 "-resultBundlePath", str(bundle), "-disableAutomaticPackageResolution",
                                 "-only-testing:MRKNormalAppUITests/NormalAppUITests/" + method,
                                 "-parallel-testing-enabled", "NO", "-test-timeouts-enabled", "YES",
                                 "-default-test-execution-time-allowance", "300",
                                 "-maximum-test-execution-time-allowance", "300"],
                                env=env, capture_output=True, text=True, timeout=600)
    finally:
        stop_sampling.set()
        if sampler is not None:
            sampler.join(timeout=65)

    result["xctestReturn"] = tested.returncode
    transcript = tested.stdout + "\n" + tested.stderr
    if sampler is not None:
        result["workspaceResources"] = {
            "method": "ps RSS/%cpu of the signed app process tree, sampled every second during actual XCTest stages",
            "stages": workspace_resource_summary(transcript, resource_samples),
        }
        (evidence / "workspace-resources.json").write_text(json.dumps(resource_samples) + "\n")
    result["cliAccessFacts"] = re.findall(
        r"(?m)^MRK_RELEASE_CLI_ACCESS_STATE=([a-z-]{2,24})$", transcript)
    result["snapshotState"] = re.findall(
        r"(?m)^MRK_NORMAL_SNAPSHOT_STATE=v2;sample=post-wait;waiter=(completed|timed-out|other);"
        r"error=([0-5]);partial=([0-5]);unread=([0-5]);loading=([0-5]);empty=([0-5]);"
        r"unsupported=([0-5]);invalid=([0-5]);missing=([0-5]);runtime=([0-5]);protocol=([0-5]);"
        r"engineDisabled=([0-5]);engineUnavailable=([0-5]);firstKnownReason=([a-z0-9-]{1,40});nonAtomic=1$",
        transcript)[-4:]
    result["cliRevokeCuts"] = re.findall(r"(?m)^MRK_RELEASE_CLI_REVOKE_CUT=(click-returned|off-visible)$", transcript)
    result["xctestStages"] = re.findall(r"(?m)^MRK_NORMAL_PROJECT_STAGE=([a-z0-9-]{1,70});result=(started|passed|failed)",
                                          transcript)[-60:]
    for field, pattern in (
        ("xctestRequireLine", r"MRK_NORMAL_PROJECT_REQUIRE_FAILURE=v1;method=" + method + r";line=([0-9]{1,5});check="),
        ("xctestClockRefusalLine", r"MRK_NORMAL_PROJECT_CLOCK_FAILURE=v1;line=([0-9]{1,5})"),
        ("xctestLaunchStage", r"MRK_NORMAL_PROJECT_LAUNCH_STAGE=(account|identity|proxies|gate-open|gate-free|request|gate-held|owner|window|renderer|dashboard)\b"),
        ("xctestWait", r"MRK_NORMAL_WAIT=v1;line=([0-9]{1,5});waiter=(completed|timed-out|other);matches=([0-5]);failures=([0-5])"),
        ("installedCLIStatuses", r"MRK_RELEASE_CLI_STATUS=expected=([034]);exit=(-?[0-9]{1,3})"),
        ("postRefusalCliStatus", r"MRK_RELEASE_CLI_POST_REFUSAL_STATUS=exit=(-?[0-9]{1,3});json=([01])"),
        ("prepareAdmissionObservations", r"MRK_RELEASE_PREPARE_ADMISSION=(native-unavailable|busy|unknown-cleanup|closing|confirmation-invalid|reply-unconfirmed)\b"),
        ("prepareStatusObservations", r"MRK_RELEASE_PREPARE_STATUS=(rejected-request|refused|unknown|prepared|started|native-refused|cleanup-unknown|deadline)\b"),
    ):
        result[field] = re.findall(pattern, transcript)[-12:]
    if prepare:
        result["prepareAppTrace"] = fixed_app_trace(evidence, "prepare")
        result["prepareQuitObserved"] = "MRK_RELEASE_PREPARE_TO_QUIT=confirmed-original-quit-and-gate-release" in transcript
        observed = result["prepareQuitObserved"]
    elif recovery:
        result["recoveryLaunchRefusal"] = re.findall(
            r"(?m)^MRK_RELEASE_RECOVERY_LAUNCH_REFUSAL=reason=(deadline|clock|launch-work-closed|payload-identity|callback|owner|other|untyped);budget=(elapsed|under-five|available|unavailable)$",
            transcript)
        result["recoveryFacts"] = re.findall(
            r"(?m)^MRK_RELEASE_RECOVERY_FACT=(before|refused|review);panel=(true|false);review=([0-3])$", transcript)
        result["recoveryMatches"] = re.findall(
            r"(?m)^MRK_RELEASE_RECOVERY_MATCH=(before|refused|review);state=([a-z-]{2,24})$", transcript)
        result["recoveryControls"] = re.findall(
            r"(?m)^MRK_RELEASE_RECOVERY_CONTROL=(before|refused|review);inspect=(true|false);close=(true|false)$",
            transcript)
        result["recoveryTestRunnerEvents"] = [event for event, fragment in (
            ("objective-c-exception", "NSInvalidArgumentException"),
            ("unsupported-predicate", "Unsupported predicate"),
            ("execution-timeout", "exceeded execution time allowance"),
            ("runner-exited", "Test runner exited"),
            ("test-crashed", "TEST CRASHED"),
        ) if fragment.lower() in transcript.lower()]
        result["guiRecoveryObserved"] = "MRK_RELEASE_GUI_RECOVERY=confirmed-original-rollback-and-quit" in transcript
        result["recoveryProjectMatchesOriginals"] = recovery_project_manifest(project_path) == baseline
        observed = result["guiRecoveryObserved"] and result["recoveryProjectMatchesOriginals"]
    else:
        result["workspaceFixtureObserved"] = "MRK_RELEASE_WORKSPACE=selected-saved-identity-files-unchanged" in transcript
        result["cliGrantAndRevokeObserved"] = "MRK_RELEASE_CLI_ACCESS=denied-allowed-revoked" in transcript
        observed = result["workspaceFixtureObserved"] and result["cliGrantAndRevokeObserved"]
    result["xctestCasePassed"] = bool(re.search(r"(?m)^Test Case .*" + method + r"\]' passed ", transcript))
    result["newCrashReports"] = sorted(set(recent_crashes()) - before_crashes)
    need(tested.returncode == 0 and observed and result["xctestCasePassed"] and not result["newCrashReports"],
         "xctest-original-result")
    if mode == "workspace-xctest" and os.environ.get("MRK_CHECK_DURABLE_CLI_STATE") == "true":
        binding = USER_DATA / "service-v1.reservation"
        info = binding.lstat()
        header = b"MRK service root v2\n"
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
             and info.st_uid == os.getuid() and info.st_nlink == 1
             and info.st_size == len(header) + 16, "workspace-cli-volume-binding-protection")
        with binding.open("rb") as original:
            need(os.path.samestat(info, os.fstat(original.fileno()))
                 and original.read(len(header)) == header, "workspace-cli-volume-binding-format")
        service = USER_DATA / "service-v1"
        for name in ("s", "agent.connection"):
            need(not (service / name).exists() and not (service / name).is_symlink(),
                 "workspace-cli-original-endpoint-left-after-quit")
        result["durableCliStateAndCleanEndpointShutdown"] = True
    if prepare:
        census, _ = run(["/bin/ps", "-A", "-o", "command="], 30)
        need(census.returncode == 0, "prepare-quit-process-census")
        result["remainingInstalledProcesses"] = sum(line.lstrip().startswith(str(APP) + "/")
                                                    for line in census.stdout.splitlines())
        need(result["remainingInstalledProcesses"] == 0, "prepare-quit-left-installed-processes")
        if result["mode"] == "retained-prepare":
            result["helperStatusAfterPrepare"] = android_helper_status()
            need(result["helperStatusAfterPrepare"] == 113, "retained-prepare-quit-helper-still-registered")
        result["reopen"] = launch_smoke("prepare-quit-reopen", work, evidence, steps)


def require_quarantine(path):
    quarantine = f"0081;{int(time.time()):x};GitHubActions;"
    written, _ = run(["/usr/bin/xattr", "-w", "com.apple.quarantine", quarantine, str(path)], 30)
    read, _ = run(["/usr/bin/xattr", "-p", "com.apple.quarantine", str(path)], 30)
    need(written.returncode == read.returncode == 0 and read.stdout.strip() == quarantine, "asset-quarantine")


def package_acceptance(package):
    require_quarantine(package)
    signature, _ = run(["/usr/sbin/pkgutil", "--check-signature", str(package)], 120)
    need(signature.returncode == 0 and "Developer ID Installer" in signature.stdout
         and "trusted by the Apple notary service" in signature.stdout, "asset-signature")
    gate, _ = run(["/usr/sbin/spctl", "-a", "-vv", "-t", "install", str(package)], 120)
    need(gate.returncode == 0 and "Notarized Developer ID" in gate.stdout + gate.stderr, "asset-gatekeeper")
    staple = subprocess.run(["/usr/bin/xcrun", "stapler", "validate", "-v", str(package)],
                            capture_output=True, text=True, timeout=120)
    tickets = set(re.findall(r'recordName = "(2/[0-9]+/[0-9a-f]{40,64})";', staple.stdout + staple.stderr))
    need(staple.returncode == 0 and len(tickets) == 1, "asset-stapled-ticket")
    return {"sha256": digest(package), "notarizationTicket": tickets.pop(), "quarantineVerified": True}


def release_asset_check(selection, work, evidence, steps, result):
    row = selection["next"]
    folder = fetch("next", row, work, steps)
    prepared = json.loads((folder / "PREPARED.json").read_text())
    origin = prepared["origin"]
    producer = json.loads((folder / "producer-root/producer.json").read_text())["releaseSet"]["current"]
    need(origin["target"] == "aarch64-apple-darwin" and origin["source"] == producer["sourceCommit"]
         and hex_field(origin["source"], 40) and hex_field(origin["tree"], 40), "asset-source-binding")
    install_mount = carrier_image("release-asset", folder, steps)
    detached, _ = run(["/usr/bin/hdiutil", "detach", str(install_mount)], 120)
    need(detached.returncode == 0, "asset-install-image-detach")
    mount, _ = removal_image(selection["removal"], work, steps)
    output = work / "release-assets"
    output.mkdir(mode=0o700)
    try:
        assets = {"Install.pkg": folder / "Install.pkg", "Remove.pkg": mount / "Remove.pkg"}
        verified = {}
        for name, path in assets.items():
            copied = output / name
            shutil.copyfile(path, copied)
            verified[name] = package_acceptance(copied)
            need(verified[name]["sha256"] == digest(path), "asset-copy-digest")
        for name in ("producer.json", "producer.sig"):
            shutil.copyfile(folder / "producer-root" / name, output / name)
        image = output / "MobileReleaseKit-Remove.dmg"
        shutil.copyfile(work / "removal/MobileReleaseKit-Remove.dmg", image)
        need(digest(image) == selection["removal"]["imageSha256"], "asset-removal-image-digest")
        shutil.copyfile(folder / "carrier-release-asset.dmg", output / "MobileReleaseKit-Install.dmg")
        result["asset"] = {"schemaVersion": 1, "version": row["packageVersion"], "release": row["release"],
                           "sourceCommit": origin["source"], "sourceTree": origin["tree"], "target": origin["target"],
                           "buildRun": row["runId"], "removalRun": selection["removal"]["runId"],
                           "packages": verified, "sha256": {p.name: digest(p) for p in sorted(output.iterdir())}}
        (output / "MANIFEST.json").write_text(json.dumps(result["asset"], indent=2) + "\n")
    finally:
        subprocess.run(["/usr/bin/hdiutil", "detach", "-force", str(mount)], capture_output=True, timeout=120)


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


def open_quarantined_uninstaller(mount, work, evidence, label):
    """Observe the ordinary first-launch prompt while Launch Services waits."""
    script = work / "uninstaller-gatekeeper.js"
    script.write_text(GATEKEEPER_UNINSTALLER_JXA)
    observations = set()
    prompt_checks = None
    deadline = time.monotonic() + 60
    with subprocess.Popen(["/usr/bin/open", "-n", str(mount / UNINSTALLER)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as launch:
        try:
            while launch.poll() is None and time.monotonic() < deadline:
                if "standard-open-confirmed" not in observations:
                    try:
                        reply = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(script)],
                                               capture_output=True, text=True,
                                               timeout=min(10, max(0.1, deadline - time.monotonic())))
                        probe = json.loads(reply.stdout)
                        state = probe["state"]
                        if probe["checks"] is not None:
                            prompt_checks = probe["checks"]
                    except (subprocess.TimeoutExpired, json.JSONDecodeError):
                        state = "probe-error"
                    observations.add(state if state in ("no-agent", "no-matching-dialog", "unexpected-dialog",
                                                          "standard-open-confirmed") else "probe-error")
                    if state == "unexpected-dialog":
                        break
                time.sleep(min(1, max(0, deadline - time.monotonic())))
            returncode = launch.poll()
        finally:
            if launch.poll() is None:
                try:
                    subprocess.run(["/usr/sbin/screencapture", "-x", str(evidence / f"screen-{label}-open.png")],
                                   capture_output=True, timeout=15)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                finally:
                    launch.kill()
            processes, _ = run(["/bin/ps", "-axo", "comm="], 15)
            uninstaller = [name.strip() for name in processes.stdout.splitlines()
                           if name.strip().endswith("/" + UNINSTALLER + "/Contents/MacOS/applet")]
            (evidence / f"{label}-open.json").write_text(json.dumps({
                "observations": sorted(observations),
                "promptChecks": prompt_checks,
                "appTranslocated": any("/AppTranslocation/" in name for name in uninstaller),
                "atMount": str(mount / UNINSTALLER / "Contents/MacOS/applet") in uninstaller,
            }) + "\n")
    need(returncode == 0, f"{label}-quarantined-open-{returncode}")


def uninstaller_diagnostic_run(mount, work, evidence, label, answers, timeout=240):
    # Observe actual process lifetimes without collecting command arguments,
    # which could include credentials from independent hosted fixtures.
    done = threading.Event()
    records = []
    started = time.monotonic()
    def sample():
        previous = None
        while not done.is_set():
            p = subprocess.run(["/bin/ps", "-A", "-o", "pid=,ppid=,stat=,comm="],
                               capture_output=True, text=True, timeout=5)
            rows = [line.strip() for line in p.stdout.splitlines()
                    if re.search(r"(?:/MacOS/(?:Installer|applet)|/usr/bin/(?:open|security)|/bin/sh)$", line)]
            if rows != previous:
                records.append({"elapsed": round(time.monotonic() - started, 3), "processes": rows})
                previous = rows
            done.wait(.5)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    try:
        return uninstaller_run(mount, work, evidence, label, answers, timeout=timeout)
    finally:
        done.set()
        sampler.join(timeout=7)
        (evidence / f"{label}-process-timeline.json").write_text(json.dumps(records, indent=2) + "\n")


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
    if os.environ.get("MRK_CHECK_QUARANTINED_REMOVE_MEDIA") == "true":
        open_quarantined_uninstaller(mount, work, evidence, label)
    else:
        p, _ = run(["/usr/bin/open", "-n", str(mount / UNINSTALLER)], 60)
        need(p.returncode == 0, f"{label}-open-returned-{p.returncode}")
    seen, deadline = [], time.monotonic() + timeout
    for step, answer in enumerate(answers):
        if answer is None:
            while time.monotonic() < deadline and not installer_running():
                time.sleep(1)
            need(installer_running(), f"{label}-installer-not-opened")
            window_deadline = min(time.monotonic() + 30, deadline)
            probes = []
            count = None
            while time.monotonic() < window_deadline:
                p = subprocess.run(["/usr/bin/pgrep", "-x", "Installer"], capture_output=True, text=True, timeout=5)
                pids = [int(pid) for pid in p.stdout.split() if pid.isdigit()]
                count = window_count(pids[0], work) if len(pids) == 1 else None
                probes.append({"pids": pids, "visibleWindows": count})
                if count:
                    break
                time.sleep(.5)
            (evidence / f"{label}-installer-window-probes.json").write_text(json.dumps(probes))
            subprocess.run(["/usr/sbin/screencapture", "-x", str(evidence / f"screen-{label}-installer.png")],
                           capture_output=True, timeout=60)
            need(count, f"{label}-installer-visible-window-missing")
            if label == "macl-duplicate-keep-incomplete":
                listed = subprocess.check_output(["/bin/ps", "-axo", "command="], text=True, timeout=10)
                opened = [line.strip() for line in listed.splitlines()
                          if line.strip().startswith("/usr/bin/open -W -a Installer ")
                          and line.strip().endswith("/Remove.pkg")]
                (evidence / f"{label}-package-selection.json").write_text(json.dumps(opened, indent=2))
                need(opened == ["/usr/bin/open -W -a Installer " + str(mount / "Remove.pkg")],
                     f"{label}-installer-package-on-wrong-mount")
            quit_script = work / "installer-normal-quit.js"
            quit_script.write_text("""function run() {
  const se = Application('System Events');
  const apps = se.processes.whose({bundleIdentifier: 'com.apple.installer'});
  if (apps.length !== 1) return 'installer-not-unique';
  apps[0].frontmost = true;
  delay(0.6);
  if (!apps[0].frontmost()) return 'installer-not-frontmost';
  se.keystroke('q', {using: ['command down']});
  return 'quit-key';
}
""")
            quit_started = time.monotonic()
            closed = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(quit_script)],
                                    capture_output=True, text=True, timeout=30)
            need(closed.returncode == 0 and closed.stdout.strip() == "quit-key", f"{label}-installer-quit-key")
            quit_by = time.monotonic() + 20
            while installer_running() and time.monotonic() < quit_by:
                time.sleep(.5)
            need(not installer_running(), f"{label}-installer-normal-quit-did-not-exit")
            seen.append({"installer": "quit", "path": "foreground-cmd-q",
                         "elapsed": round(time.monotonic() - quit_started, 3)})
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


def uninstaller_installed_check(selection, work, evidence, steps, result):
    """#83 without a live removal: install the next package, seed data, then
    run every uninstaller path that must remove and delete nothing while the
    app is installed (both cancels, Installer quit, data script refusal).
    The confirmed Delete All Data path needs a completed live removal and
    stays in remove mode."""
    need("removal" in selection, "selection-has-no-removal-carrier")
    row = selection["next"]
    folder = fetch("next", row, work, steps)
    mount, roster = removal_image(selection["removal"], work, steps)
    result["removalImageRoster"] = roster
    try:
        need(install("next", folder, steps, evidence=evidence) == 0, "uninstaller-baseline-install-returned-nonzero")
        state = installed_state()
        result["afterInstall"] = state
        need((state["release"], state["packageVersion"], state["packageSha256"])
             == (row["release"], row["packageVersion"], row["packageSha256"]), "uninstaller-baseline-identity")
        result["seededFiles"] = len(seed_user_data())
        uninstaller_while_installed(mount, work, evidence, steps, result)
    finally:
        subprocess.run(["/usr/bin/hdiutil", "detach", "-force", str(mount)], capture_output=True, timeout=120)


def uninstaller_while_installed(mount, work, evidence, steps, result):
    """While the app is installed: cancelling either choice, or quitting
    Installer, removes and deletes nothing, and the data script refuses.
    Returns (decoys, before) for the confirmed path that follows."""
    out = result.setdefault("uninstaller", {})
    script = mount / UNINSTALLER / "Contents/Resources/removal-data-v1.sh"
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
    p, _ = run(["/bin/sh", str(script)], 60)
    need(p.returncode == 64, "uninstaller-empty-operation-admitted")
    p, r = run(["/bin/sh", str(script), "--delete-data"], 60)
    steps.append(dict(r, role="delete-data-while-installed"))
    out["dataScriptWhileInstalled"] = p.returncode
    need(p.returncode == 65, "delete-data-not-refused-while-installed")
    unchanged("delete-data-while-installed")
    return decoys, before


def uninstaller_check(mount, work, evidence, steps, result):
    """#83: the Remove image's signed uninstaller. The installed-app paths
    (uninstaller_while_installed), then after a second confirmed removal,
    "Delete All Data" removes only the app's own exact per-user locations and
    keychain items; links, look-alike siblings, projects and other files stay."""
    decoys, before = uninstaller_while_installed(mount, work, evidence, steps, result)
    out = result["uninstaller"]
    second = live_remove(mount, work, evidence, steps, "remove-again")
    out["secondRemoval"] = second
    need(manifest() == before, "user-data-changed-by-second-removal")
    confirmed_data_deletion(mount, work, evidence, result, decoys)


def confirmed_data_deletion(mount, work, evidence, result, decoys):
    """Exercise the signed Delete All Data UI after native removal succeeds."""
    need(not APP.exists() and not LAUNCHER.exists(), "delete-all-data-app-present-before")
    out = result.setdefault("uninstaller", {})
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
    out["appKeychainItemsSeeded"] = {svc: keychain_has(svc) for svc in (*KEYCHAIN_SERVICES, DECOY_SERVICE)}
    need(all(out["appKeychainItemsSeeded"].values()), "delete-all-data-keychain-fixture")
    seen = uninstaller_diagnostic_run(mount, work, evidence, "uninstall-delete",
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
