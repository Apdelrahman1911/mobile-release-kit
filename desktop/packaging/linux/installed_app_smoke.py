"""Disposable hosted-VM observation of the ACTUAL installed Desktop app (DEB).

Installs the exact built DEB, launches /usr/bin/mobile-release-kit-desktop as
the ordinary runner account under Xvfb + a private D-Bus session, records the
window, a screenshot and bounded logs, requests a normal close with
WM_DELETE_WINDOW, reopens, closes again, then removes the package.
Observation only: never edits the DEB, never qualifies shipping.
"""
import argparse, hashlib, json, os, subprocess, sys, time
from pathlib import Path

APP = '/usr/bin/mobile-release-kit-desktop'
result = {'schema': 1, 'steps': [], 'shippingQualified': False, 'firstFailure': None}


def step(name, **data):
    result['steps'].append({'name': name, 'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), **data})


def sh(argv, timeout=600, **kw):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, **kw)
    return p.returncode, p.stdout[-20000:], p.stderr[-20000:]


def as_user(user, argv):
    return ['runuser', '-u', user, '--', *argv]


def windows_for(display, pid):
    from Xlib import display as xd, X
    d = xd.Display(display); root = d.screen().root
    pid_atom = d.intern_atom('_NET_WM_PID'); found = []
    def walk(w):
        try:
            prop = w.get_full_property(pid_atom, X.AnyPropertyType)
            if prop and prop.value and int(prop.value[0]) == pid:
                attrs = w.get_attributes()
                if attrs.map_state == X.IsViewable:
                    found.append((w.id, w.get_wm_name() or ''))
            for c in w.query_tree().children: walk(c)
        except Exception:
            pass
    walk(root); d.close(); return found


def close_window(display, wid):
    from Xlib import display as xd, X
    from Xlib.protocol import event
    d = xd.Display(display); w = d.create_resource_object('window', wid)
    proto = d.intern_atom('WM_PROTOCOLS'); delete = d.intern_atom('WM_DELETE_WINDOW')
    ev = event.ClientMessage(window=w, client_type=proto, data=(32, [delete, X.CurrentTime, 0, 0, 0]))
    w.send_event(ev, event_mask=X.NoEventMask); d.flush(); d.close()


def session(label, user, home, display, evidence):
    log = open(evidence / f'{label}-app.log', 'wb')
    env = {'PATH': '/usr/bin:/bin', 'HOME': home, 'DISPLAY': display, 'LANG': 'C.UTF-8',
           'XDG_RUNTIME_DIR': f'/tmp/mrk-xdg-{user}', 'WEBKIT_DISABLE_COMPOSITING_MODE': '1'}
    os.makedirs(env['XDG_RUNTIME_DIR'], mode=0o700, exist_ok=True); sh(['chown', user, env['XDG_RUNTIME_DIR']])
    argv = ['runuser', '-u', user, '--', 'env', '-i', *[f'{k}={v}' for k, v in env.items()], 'dbus-run-session', '--', APP]
    p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.time() + 60; wins = []
    while time.time() < deadline and p.poll() is None:
        time.sleep(1)
        rc, out, _ = sh(['pgrep', '-u', user, '-f', '-x', APP])
        for pid in [int(x) for x in out.split()]:
            wins = windows_for(display, pid)
            if wins: break
        if wins: break
    if p.poll() is not None:
        step(f'{label}-launch', exited=True, exitCode=p.returncode); raise RuntimeError(f'{label}: app exited before showing a window')
    if not wins:
        sh(['import', '-display', display, '-window', 'root', str(evidence / f'{label}-no-window.png')])
        raise RuntimeError(f'{label}: no window within 60 s')
    time.sleep(25)
    if p.poll() is not None:
        step(f'{label}-after-start', exitCode=p.returncode); raise RuntimeError(f'{label}: app exited during startup')
    sh(['import', '-display', display, '-window', 'root', str(evidence / f'{label}-running.png')])
    step(f'{label}-running', windows=[{'id': w, 'title': t} for w, t in wins])
    close_window(display, wins[0][0])
    try:
        p.wait(timeout=30); exited = True
    except subprocess.TimeoutExpired:
        exited = False
        sh(['import', '-display', display, '-window', 'root', str(evidence / f'{label}-close-pending.png')])
    rc, out, _ = sh(['pgrep', '-u', user, '-f', '-x', APP])
    step(f'{label}-close', exitedWithin30s=exited, exitCode=p.returncode if exited else None, remainingAppProcesses=len(out.split()))
    if not exited:
        os.killpg(p.pid, 9); raise RuntimeError(f'{label}: did not exit within 30 s after WM_DELETE_WINDOW')
    log.close()


def main():
    a = argparse.ArgumentParser(); a.add_argument('--download', type=Path, required=True); a.add_argument('--evidence', type=Path, required=True)
    a = a.parse_args(); assert os.geteuid() == 0 and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    user = os.environ['SUDO_USER']; home = f'/home/{user}'; ev = a.evidence; ev.mkdir(mode=0o755)
    try:
        debs = list(a.download.rglob('mobile-release-kit-desktop_0.1.4-1_amd64.deb')); assert len(debs) == 1, 'exactly one DEB'
        deb = debs[0]; step('inputs', debSha256=hashlib.sha256(deb.read_bytes()).hexdigest(), bytes=deb.stat().st_size)
        step('host', kernel=os.uname().release, machine=os.uname().machine, osRelease=Path('/etc/os-release').read_text()[:600])
        env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
        sh(['apt-get', 'update'], env=env)
        env['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
        rc, out, err = sh(['apt-get', 'install', '-y', '--no-install-recommends', str(deb.resolve()), 'xvfb', 'python3-xlib', 'imagemagick', 'dbus'], timeout=900, env=env)
        (ev / 'install.log').write_text(out + '\n' + err); step('install', exitCode=rc)
        if rc: raise RuntimeError(f'apt-get install of the DEB returned {rc}')
        step('installed', appSha256=hashlib.sha256(Path(APP).read_bytes()).hexdigest())
        display = ':99'; xvfb = subprocess.Popen(['runuser', '-u', user, '--', 'Xvfb', display, '-screen', '0', '1440x900x24', '-nolisten', 'tcp'])
        time.sleep(3)
        try:
            session('first-launch', user, home, display, ev)
            session('reopen', user, home, display, ev)
        finally:
            xvfb.terminate()
        rc, out, err = sh(['apt-get', 'remove', '-y', 'mobile-release-kit-desktop'], env=env)
        (ev / 'remove.log').write_text(out + '\n' + err); step('remove', exitCode=rc, appRemains=Path(APP).exists())
    except Exception as e:
        result['firstFailure'] = f'{type(e).__name__}: {e}'
    (ev / 'result.json').write_text(json.dumps(result, indent=2) + '\n'); sh(['chmod', '-R', 'a+rX', str(ev)])
    sys.exit(1 if result['firstFailure'] else 0)


if __name__ == '__main__':
    main()
