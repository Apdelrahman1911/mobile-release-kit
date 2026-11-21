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


def launch_smoke(label, work, evidence, steps, observe=None, steady_idle_seconds=0, steady_interval=1):
    """Open the installed app as the logged-in runner user and require a live
    payload process with an on-screen window and no crash report."""
    need(not payload_pids(), f"{label}-app-already-running")
    before = set(recent_crashes())
    started = time.monotonic()
    p, row = run(["/usr/bin/open", str(APP)], 60)
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
    reports = recent_crash_paths()
    crashes = sorted(set(reports) - before)
    observed = {"label": label, "processSeen": bool(pids), "secondsToFirstWindow": first_window,
                "resources": resource_summary(samples),
                "aliveAfterSettle": bool(alive), "windowsAfterSettle": settled, "newCrashReports": crashes,
                "screenshot": shot.name if shot.exists() else None}
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
                                           "repeat", "repeat-after-dialogs", "prepare-quit", "performance",
                                           "update-credentials", "release-asset", "workspace-cli",
                                           "workspace-xctest", "prepare-xctest", "performance-long"), default="update")
    args = parser.parse_args()
    work = Path(args.work)
    evidence = work / "evidence"
    evidence.mkdir(mode=0o700)
    steps, result = [], {"schemaVersion": 1, "kind": "mrk-macos-update-check-v1", "mode": args.mode, "passed": False}
    try:
        selection = load_selection(args.selection)
        result["selection"] = selection
        need(not STATE.exists() and not USER_DATA.exists(), "runner-not-fresh")
        if args.mode not in ("update", "update-credentials"):
            {"fresh": fresh_check, "remove": remove_check, "uninstaller": uninstaller_installed_check,
             "delete-data": remove_check, "repeat": remove_check, "repeat-after-dialogs": remove_check,
             "prepare-quit": prepare_quit_check, "performance": fresh_check, "release-asset": release_asset_check,
             "workspace-cli": workspace_cli_check, "workspace-xctest": workspace_xctest,
             "prepare-xctest": workspace_xctest, "performance-long": performance_long_check}[args.mode](
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
        if args.mode in ("remove", "delete-data", "repeat", "repeat-after-dialogs") and "removeReturn" not in result:
            result["removeReturn"] = next((step["returncode"] for step in steps if step.get("role") == "remove"), None)
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
    performance = result["mode"] == "performance"
    result["firstLaunch"] = launch_smoke("first-launch", work, evidence, steps, observe=first_launch_observe,
                                         steady_idle_seconds=300 if performance else 0)
    ui = result["firstLaunch"].get("ui") or {}
    # A missing accessibility read is recorded as not-observed, never a pass;
    # only a definite unavailable card, error marker or wrong CLI refusal fails.
    need(ui.get("runtimeCard") != "unavailable", "fresh-first-launch-runtime-unavailable")
    need(not ui.get("workspaceErrorMarkers"), "fresh-first-launch-workspace-error")
    need(ui.get("cliStatus", {}).get("returncode") == 3 and ui.get("cliStatus", {}).get("guidance"),
         "fresh-cli-status-guidance")
    if performance:
        need(ui.get("runtimeCard") == "bundled", "resource-first-launch-runtime-unproven")
        need(result["firstLaunch"]["steadyIdleResources"]["samples"] == 300, "resource-sample-incomplete")
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
    deadline = time.monotonic() + 30
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


def live_remove(mount, work, evidence, steps, label, observe_release=None):
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
    requests = STATE.with_name("MobileReleaseKit-RemovalRequests")
    existing_requests = removal_requests(requests)
    log = open(evidence / f"{label}-installer.log", "w")
    installer = subprocess.Popen(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-verbose", "-pkg",
                                  str(mount / "Remove.pkg"), "-target", "/"], stdout=log, stderr=subprocess.STDOUT, text=True)
    sample_stop = threading.Event()
    sample_thread = threading.Thread(target=sample_removal_start,
                                     args=(pids[0], evidence, label, sample_stop, existing_requests), daemon=True)
    sample_thread.start()
    metadata_thread = None
    if observe_release is not None:
        metadata_thread = threading.Thread(target=sample_removal_metadata, daemon=True,
                                           args=(observe_release, requests, existing_requests, evidence, label, sample_stop))
        metadata_thread.start()
    sheet, quit_sheet = [], []
    clicked, quit_clicked = False, False
    try:
        deadline = time.monotonic() + 240
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
                    q = subprocess.run([*cmd, "click", phase], capture_output=True, text=True, timeout=30)
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
    if clicked and installer.returncode != 0:
        removal_refusal_evidence(pids[0], work, evidence, label)
    need(clicked, "removal-sheet-not-confirmed")
    need(installer.returncode == 0, "remove-returned-nonzero")
    need(quit_clicked, "removal-quit-sheet-not-confirmed")
    time.sleep(5)
    remaining = {"app": APP.exists(), "launcher": LAUNCHER.exists(), "process": bool(payload_pids())}
    out["remaining"] = remaining
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


def remove_check(selection, work, evidence, steps, result):
    """Fresh install, launch, live removal through the matching Remove.pkg
    (confirming the app's own sheet), then check deletion or reinstall."""
    need("removal" in selection, "selection-has-no-removal-carrier")
    row = selection["next"]
    mode = result["mode"]
    repeat = mode in ("repeat", "repeat-after-dialogs")
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
    out = live_remove(mount, work, evidence, steps, "remove", observe_release=row["release"] if repeat else None)
    result.update(removalSheet=out["sheet"], removalQuitSheet=out["quitSheet"],
                  removeReturn=out["returncode"], afterRemoval=out["remaining"])
    if out.get("timedOut"):
        result["removeTimedOut"] = True
    kept = manifest()
    result["userDataPreservedByRemoval"] = all(kept.get(k) == v for k, v in seeded.items())
    need(result["userDataPreservedByRemoval"], "user-data-changed-by-removal")
    try:
        if mode == "delete-data":
            confirmed_data_deletion(mount, work, evidence, result, plant_decoys())
            return
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
        if repeat:
            if mode == "repeat-after-dialogs":
                _, before_repeat = uninstaller_while_installed(mount, work, evidence, steps, result)
            else:
                before_repeat = manifest()
            result["secondRemoval"] = live_remove(mount, work, evidence, steps, "remove-again", observe_release=row["release"])
            need(manifest() == before_repeat, "user-data-changed-by-second-removal")
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
        click_when_ready(pid, work, "Dashboard")
        opened = click_when_ready(pid, work, "Open project folder", "AXButton")
        need(opened.get("clicked") == "Open project folder", "workspace-open-project-picker")
        script = work / "project-picker.js"
        script.write_text(PROJECT_PICKER_JXA)
        picked = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(script), str(pid), str(fixture.resolve())],
                                capture_output=True, text=True, timeout=30)
        result["picker"] = picked.stdout.strip()
        need(picked.returncode == 0 and result["picker"] == "selected", "workspace-native-picker")
        deadline = time.monotonic() + 60
        while True:
            texts = ui_query(pid, work, "texts", timeout=10).get("texts") or []
            need(not any(marker in text for marker in WORKSPACE_ERROR_MARKERS for text in texts), "workspace-view-error")
            if str(fixture.resolve()) in texts or "org.mrk.fixture" in texts:
                break
            need(time.monotonic() < deadline, "workspace-fixture-not-observed")
            time.sleep(2)
        result["fixtureWorkspaceObserved"] = True
        for title in ("Project settings", "Advanced · CLI / AI access", "Check access",
                      "Allow selected project for 1 hour"):
            action = click_when_ready(pid, work, title)
            result.setdefault("accessNavigation", []).append(action)
            need(action.get("clicked") == title, "workspace-cli-access-control")
        cli = APP / "Contents/MacOS/mrk"
        statuses = result["statusReturns"] = []
        for expected in (0, 3):
            deadline = time.monotonic() + 25
            while True:
                status = subprocess.run([str(cli), "status", "--json"], capture_output=True, text=True, timeout=20)
                if status.returncode == expected:
                    break
                need(time.monotonic() < deadline, "workspace-cli-status")
                time.sleep(1)
            statuses.append(status.returncode)
            if expected == 0:
                need(isinstance(json.loads(status.stdout), dict), "workspace-cli-json")
                revoked = click_when_ready(pid, work, "Turn off access", "AXButton")
                need(revoked.get("clicked") == "Turn off access", "workspace-cli-revoke-control")
            else:
                need(CLI_STATUS_GUIDANCE in status.stdout + status.stderr, "workspace-cli-revoke-guidance")
        result["fixtureUnchanged"] = {p.relative_to(fixture): digest(p) for p in fixture.rglob("*") if p.is_file()} == originals
        need(result["fixtureUnchanged"], "workspace-cli-modified-fixture")
        need(set(recent_crashes()) == before_crashes, "workspace-crash")
    finally:
        subprocess.run(["/usr/sbin/screencapture", "-x", str(evidence / "screen-workspace-cli.png")],
                       capture_output=True, timeout=60)
        stop_app(payload_pids())


def workspace_xctest(selection, work, evidence, steps, result):
    row = selection["next"]
    folder = fetch("next", row, work, steps)
    need(install("next", folder, steps, evidence=evidence) == 0, "workspace-xctest-install")
    result["afterInstall"] = installed_state()
    origin = json.loads((folder / "PREPARED.json").read_text())["origin"]
    source, harness = result["afterInstall"]["sourceCommit"], os.environ["GITHUB_SHA"]
    need(source == origin["source"] and source != harness and hex_field(harness, 40)
         and result["afterInstall"]["packageSha256"] == row["packageSha256"], "workspace-xctest-source-binding")
    temporary = work / "xctest-tmp"
    temporary.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "USER": "runner",
           "LOGNAME": "runner", "TMPDIR": str(temporary) + "/", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
           "TZ": "UTC", "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer",
           "TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB": "github-hosted-macos26-arm64",
           "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE": source, "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE": harness,
           "TEST_RUNNER_MRK_NORMAL_UI_CURRENT_ORDINARY": "current-candidate-ordinary-only-v1"}
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
    prepare = result["mode"] == "prepare-xctest"
    method = "testCurrentPrepareToQuit" if prepare else "testCurrentGuidedWorkspaceAndCli"
    bundle = work / "project-test.xcresult"
    before_crashes = set(recent_crashes())
    tested = subprocess.run(["/usr/bin/xcodebuild", "test-without-building", "-xctestrun", str(manifests[0]),
                             "-destination", "platform=macOS,arch=arm64", "-destination-timeout", "15",
                             "-resultBundlePath", str(bundle), "-disableAutomaticPackageResolution",
                             "-only-testing:MRKNormalAppUITests/NormalAppUITests/" + method,
                             "-parallel-testing-enabled", "NO", "-test-timeouts-enabled", "YES",
                             "-default-test-execution-time-allowance", "300",
                             "-maximum-test-execution-time-allowance", "300"],
                            env=env, capture_output=True, text=True, timeout=600)
    result["xctestReturn"] = tested.returncode
    transcript = tested.stdout + "\n" + tested.stderr
    result["xctestStages"] = re.findall(r"(?m)^MRK_NORMAL_PROJECT_STAGE=([a-z0-9-]{1,70});result=(started|passed|failed)",
                                          transcript)[-60:]
    for field, pattern in (
        ("xctestRequireLine", r"MRK_NORMAL_PROJECT_REQUIRE_FAILURE=v1;method=" + method + r";line=([0-9]{1,5});check="),
        ("xctestClockRefusalLine", r"MRK_NORMAL_PROJECT_CLOCK_FAILURE=v1;line=([0-9]{1,5})"),
        ("xctestLaunchStage", r"MRK_NORMAL_PROJECT_LAUNCH_STAGE=(account|identity|proxies|gate-open|gate-free|request|gate-held|owner|window|renderer|dashboard)\b"),
        ("xctestWait", r"MRK_NORMAL_WAIT=v1;line=([0-9]{1,5});waiter=(completed|timed-out|other);matches=([0-5]);failures=([0-5])"),
        ("installedCLIStatuses", r"MRK_RELEASE_CLI_STATUS=expected=([034]);exit=(-?[0-9]{1,3})"),
    ):
        result[field] = re.findall(pattern, transcript)[-12:]
    if prepare:
        result["prepareQuitObserved"] = "MRK_RELEASE_PREPARE_TO_QUIT=confirmed-original-quit-and-gate-release" in transcript
        observed = result["prepareQuitObserved"]
    else:
        result["workspaceFixtureObserved"] = "MRK_RELEASE_WORKSPACE=selected-saved-identity-files-unchanged" in transcript
        result["cliGrantAndRevokeObserved"] = "MRK_RELEASE_CLI_ACCESS=denied-allowed-revoked" in transcript
        observed = result["workspaceFixtureObserved"] and result["cliGrantAndRevokeObserved"]
    result["xctestCasePassed"] = bool(re.search(r"(?m)^Test Case .*" + method + r"\]' passed ", transcript))
    result["newCrashReports"] = sorted(set(recent_crashes()) - before_crashes)
    need(tested.returncode == 0 and observed and result["xctestCasePassed"] and not result["newCrashReports"],
         "xctest-original-result")
    if prepare:
        census, _ = run(["/bin/ps", "-A", "-o", "command="], 30)
        need(census.returncode == 0, "prepare-quit-process-census")
        result["remainingInstalledProcesses"] = sum(line.lstrip().startswith(str(APP) + "/")
                                                    for line in census.stdout.splitlines())
        need(result["remainingInstalledProcesses"] == 0, "prepare-quit-left-installed-processes")
        result["reopen"] = launch_smoke("prepare-quit-reopen", work, evidence, steps)


def package_acceptance(package):
    quarantine = f"0081;{int(time.time()):x};GitHubActions;"
    written, _ = run(["/usr/bin/xattr", "-w", "com.apple.quarantine", quarantine, str(package)], 30)
    read, _ = run(["/usr/bin/xattr", "-p", "com.apple.quarantine", str(package)], 30)
    need(written.returncode == read.returncode == 0 and read.stdout.strip() == quarantine, "asset-quarantine")
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
