"""Uploaded only for a test run; requires Linux, Python 3 and systemd."""
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

BASE = Path('/run/firewall-port-tester')


def run_path(run_id):
    if not re.fullmatch(r'[a-f0-9]{32}', run_id):
        raise ValueError('Invalid run ID')
    if BASE.exists() and (BASE.is_symlink() or BASE.stat().st_uid != 0
                          or stat.S_IMODE(BASE.stat().st_mode) != 0o700):
        raise ValueError('Unsafe remote base directory')
    path = BASE / run_id
    if path.is_symlink():
        raise ValueError('Unsafe run directory')
    return path


def unit_name(run_id):
    run_path(run_id)
    return 'firewall-port-tester-' + run_id + '.service'


def systemctl(*args):
    return subprocess.run(['systemctl', *args], capture_output=True, text=True, timeout=20)


def atomic_json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value))
    temporary.replace(path)


def serve(ports, token, state_path, stop, lifetime, bind_host='0.0.0.0'):
    """Bind once and never rebind: a healthy run proves listener continuity."""
    sockets = []
    selector = selectors.DefaultSelector()
    ready_at = None
    try:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(sock)
            sock.bind((bind_host, port))
            sock.listen(128)
            sock.setblocking(False)
            selector.register(sock, selectors.EVENT_READ)
        ready_at = time.time()
        deadline = time.monotonic() + lifetime
        while not stop[0] and time.monotonic() < deadline:
            atomic_json(state_path, {'status': 'ready', 'pid': os.getpid(),
                        'token': token, 'ports': ports, 'ready_at': ready_at,
                        'heartbeat': time.time()})
            for key, _ in selector.select(timeout=0.5):
                try:
                    conn, _ = key.fileobj.accept()
                except BlockingIOError:
                    continue
                with conn:
                    conn.settimeout(0.2)
                    try:
                        conn.sendall((token + '\n').encode('ascii'))
                    except (OSError, TimeoutError):
                        pass
        atomic_json(state_path, {'status': 'stopped', 'token': token,
                                'ready_at': ready_at, 'heartbeat': time.time()})
    except BaseException as exc:
        atomic_json(state_path, {'status': 'error', 'token': token, 'error': str(exc),
                                'heartbeat': time.time()})
        raise
    finally:
        selector.close()
        for sock in sockets:
            sock.close()


def worker(run_id):
    path = run_path(run_id)
    config = json.loads((path / 'config.json').read_text())
    stop = [False]
    signal.signal(signal.SIGTERM, lambda *_: stop.__setitem__(0, True))
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__(0, True))
    serve(config['ports'], config['token'], path / 'state.json', stop, config['ttl_seconds'])


def control(request):
    if os.geteuid() != 0:
        raise ValueError('Passwordless sudo is required')
    run_id = request['run_id']
    path = run_path(run_id)
    unit = unit_name(run_id)
    action = request['action']
    if action == 'start':
        ports = request['ports']
        if not ports or len(ports) > 256 or len(set(ports)) != len(ports):
            raise ValueError('Invalid port list')
        if any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
            raise ValueError('Invalid port')
        ttl = request['ttl_seconds']
        if type(ttl) is not int or not 120 <= ttl <= 7200:
            raise ValueError('Invalid lifetime')
        if request['token'] != 'FPT-' + run_id:
            raise ValueError('Invalid listener token')
        if not shutil.which('systemd-run') or not shutil.which('systemctl'):
            raise ValueError('systemd-run and systemctl are required')
        BASE.mkdir(mode=0o700, exist_ok=True)
        run_path(run_id)
        path.mkdir(mode=0o700)
        try:
            (path / 'agent.py').write_text(request['source'])
            (path / 'config.json').write_text(json.dumps(request))
            python = os.path.realpath(sys.executable)
            command = ['systemd-run', '--quiet', '--collect', '--unit=' + unit,
                       '--property=RuntimeMaxSec=' + str(ttl), '--property=TimeoutStopSec=5',
                       '--property=Restart=no', '--property=KillMode=control-group',
                       '--property=UMask=0077', '--property=NoNewPrivileges=yes',
                       '--property=StandardOutput=null', '--property=StandardError=null',
                       '--property=ExecStopPost=' + python + ' ' + str(path / 'agent.py') + ' purge ' + run_id,
                       python, str(path / 'agent.py'), 'worker', run_id]
            subprocess.run(command, capture_output=True, text=True, check=True, timeout=20)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if (path / 'state.json').exists():
                    state = json.loads((path / 'state.json').read_text())
                    if state['status'] == 'ready':
                        return {'ok': True, 'state': state, 'remote_time': time.time()}
                    if state['status'] == 'error':
                        raise RuntimeError(state['error'])
                if not path.exists():
                    raise RuntimeError('Listener startup failed; a port may already be occupied')
                time.sleep(0.1)
            raise RuntimeError('Timed out waiting for listeners')
        except BaseException:
            systemctl('stop', unit)
            if path.exists():
                shutil.rmtree(path)
            raise
    if action == 'inspect':
        state = json.loads((path / 'state.json').read_text())
        active = systemctl('is-active', unit)
        pid = systemctl('show', unit, '--property=MainPID', '--value')
        healthy = (active.stdout.strip() == 'active' and state['status'] == 'ready'
                   and pid.stdout.strip() == str(state['pid'])
                   and 0 <= time.time() - state['heartbeat'] < 5
                   and state['token'] == 'FPT-' + run_id)
        return {'ok': healthy, 'state': state, 'remote_time': time.time()}
    if action == 'stop':
        # Only stop this unique test service. ExecStopPost removes its private files.
        systemctl('stop', unit)
        active = systemctl('is-active', unit)
        state = active.stdout.strip()
        if state in ('active', 'activating', 'deactivating', 'reloading'):
            raise RuntimeError('Test service is still active')
        if active.returncode not in (3, 4) or state not in ('inactive', 'failed', 'unknown'):
            raise RuntimeError('Cannot confirm test service stopped')
        if path.exists():
            shutil.rmtree(path)
        if path.exists():
            raise RuntimeError('Test files were not removed')
        return {'ok': True, 'cleaned': True}
    raise ValueError('Unknown action')


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'worker':
        worker(sys.argv[2])
    elif len(sys.argv) > 1 and sys.argv[1] == 'purge':
        path = run_path(sys.argv[2])
        if path.exists():
            shutil.rmtree(path)
    else:
        try:
            result = control(json.load(sys.stdin))
            print(json.dumps(result))
        except Exception as exc:
            print(json.dumps({'ok': False, 'error': str(exc)}))
            sys.exit(1)


if __name__ == '__main__':
    main()
