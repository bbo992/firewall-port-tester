"""Per-run listeners and existing-listener monitoring for Linux/systemd VMs."""
import concurrent.futures
import ipaddress
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


def tcp_listeners(proc_root=Path('/proc/net'), with_backlog=True):
    """Read LISTEN socket identities without reading application data or commands."""
    result = {}
    for filename, family in (('tcp', socket.AF_INET), ('tcp6', socket.AF_INET6)):
        path = proc_root / filename
        if filename == 'tcp6' and not path.exists():
            continue
        for line in path.read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3] != '0A':
                continue
            address_hex, port_hex = fields[1].split(':')
            raw = bytes.fromhex(address_hex)
            # Linux stores each 32-bit address word in host byte order.
            if sys.byteorder == 'little':
                raw = b''.join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
            address = socket.inet_ntop(family, raw)
            port = int(port_hex, 16)
            result.setdefault(port, []).append({'family': 4 if family == socket.AF_INET else 6,
                'address': address, 'port': port, 'inode': fields[9]})
    if with_backlog and result:
        queues = subprocess.run(['ss', '-H', '-ltn', '-e', '-O'], capture_output=True, text=True, timeout=3)
        if queues.returncode:
            raise ValueError('Cannot inspect TCP listener queues')
        by_inode = {}
        for line in queues.stdout.splitlines():
            fields = line.split()
            inode = re.search(r'(?:^|\s)ino:(\d+)(?:\s|$)', line)
            if inode and len(fields) >= 3 and fields[0] == 'LISTEN':
                by_inode[inode.group(1)] = (int(fields[1]), int(fields[2]))
        for entries in result.values():
            for item in entries:
                if item['inode'] in by_inode:
                    item['recv_queue'], item['backlog'] = by_inode[item['inode']]
    return result


def listener_issue(entries):
    if not entries:
        return 'TCP listener is missing'
    for item in entries:
        if item.get('backlog', 0) <= 0 or 'recv_queue' not in item:
            return 'TCP listener queue capacity cannot be verified'
        if item['recv_queue'] >= item['backlog']:
            return 'TCP listener backlog is full; connection readiness is unverified'
    return ''


def identities(entries):
    return sorted((entry['family'], entry['address'], entry['port'], str(entry['inode']))
                  for entry in entries)


def can_accept_ipv4(entries, destination):
    target = ipaddress.IPv4Address(destination)
    for entry in entries:
        address = ipaddress.ip_address(entry['address'])
        if entry['family'] == 4 and (address.is_unspecified or (address == target and not address.is_loopback)):
            return True
        if entry['family'] == 6 and (address.is_unspecified or (address.ipv4_mapped == target and not target.is_loopback)):
            return True
    return False


def local_connect(address, port):
    try:
        with socket.create_connection((address, port), timeout=0.5):
            return True
    except OSError:
        return False


def ensure_direct_host_network():
    checked = False
    nft = shutil.which('nft')
    if nft:
        response = subprocess.run([nft, '-j', 'list', 'ruleset'], capture_output=True,
                                  text=True, timeout=10)
        if response.returncode:
            raise ValueError('Cannot inspect nftables rules; endpoint ownership is unverified')
        rules = json.loads(response.stdout)
        def has_translation(value):
            if isinstance(value, dict):
                return any(key in ('dnat', 'redirect', 'tproxy') or has_translation(child)
                           for key, child in value.items())
            return isinstance(value, list) and any(has_translation(child) for child in value)
        if has_translation(rules):
            raise ValueError('NAT/redirect forwarding detected; automatic host-listener verification is unsupported')
        checked = True
    for name in ('iptables-save', 'iptables-legacy-save'):
        binary = shutil.which(name)
        if not binary:
            continue
        response = subprocess.run([binary], capture_output=True, text=True, timeout=10)
        if response.returncode:
            raise ValueError('Cannot inspect IPv4 NAT rules; endpoint ownership is unverified')
        if re.search(r'\b(?:DNAT|REDIRECT|TPROXY)\b', response.stdout):
            raise ValueError('NAT/redirect forwarding detected; automatic host-listener verification is unsupported')
        checked = True
    if not checked:
        raise ValueError('nft or iptables-save is required to check host port forwarding')


def preflight(ports, destination, management_port):
    destination = str(ipaddress.IPv4Address(destination))
    ensure_direct_host_network()
    if not shutil.which('ss'):
        raise ValueError('ss is required to check existing listener queues')
    snapshot = tcp_listeners()
    plan = {}
    candidates = []
    for port in ports:
        entries = snapshot.get(port, [])
        item = {'mode': 'unsupported', 'reason': '', 'listeners': entries,
                'target_address': destination}
        if entries:
            if not can_accept_ipv4(entries, destination):
                item['reason'] = 'Listener is not bound to the SSH destination IPv4 interface'
            elif any(not str(entry['inode']).isdigit() or int(entry['inode']) == 0 for entry in entries):
                item['reason'] = 'Listener identity cannot be verified'
            elif listener_issue(entries):
                item['reason'] = listener_issue(entries)
            else:
                candidates.append(port)
        elif port == management_port:
            item['reason'] = 'Management port has no verified listener; never create one here'
        else:
            try:
                # Bind without listen, then release: no test listener is started yet.
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
                    check.bind(('0.0.0.0', port))
                item.update(mode='temporary', reason='TCP port is available')
            except OSError:
                item['reason'] = 'Port is reserved or occupied without a usable TCP listener'
        plan[str(port)] = item
    def check_existing(port):
        return port, local_connect(destination, port)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        for port, ready in executor.map(check_existing, candidates):
            if ready:
                plan[str(port)].update(mode='existing', reason='Existing IPv4 TCP listener detected')
            else:
                plan[str(port)]['reason'] = 'Existing listener does not accept local IPv4 TCP connections'
    return plan


def serve(ports, token, state_path, stop, lifetime, bind_host='0.0.0.0', plan=None, inspector=None):
    """Bind only empty ports; monitor existing socket identities once per second."""
    if plan is None:
        plan = {str(port): {'mode': 'temporary'} for port in ports}
    if set(plan) != {str(port) for port in ports}:
        raise ValueError('Port plan does not match requested ports')
    temporary = [port for port in ports if plan[str(port)]['mode'] == 'temporary']
    existing = [port for port in ports if plan[str(port)]['mode'] == 'existing']
    inspector = inspector or tcp_listeners
    sockets = []
    selector = selectors.DefaultSelector()
    ready_at = None
    status = {str(port): {'mode': plan[str(port)]['mode'],
              'healthy': plan[str(port)]['mode'] in ('temporary', 'existing'),
              'reason': plan[str(port)].get('reason', '')} for port in ports}
    def mark_bad(port, reason):
        item = status[str(port)]
        if item['healthy']:
            item.update(healthy=False, reason=reason, first_issue_at=time.time())
    last_sample = None
    def sample():
        nonlocal last_sample
        now = time.monotonic()
        if last_sample is not None and now - last_sample > 3:
            for port in existing:
                mark_bad(port, 'Existing-listener monitoring gap exceeded 3 seconds')
        try:
            current = inspector() if existing else {}
            for port in existing:
                if identities(current.get(port, [])) != identities(plan[str(port)]['listeners']):
                    mark_bad(port, 'Existing listener stopped, restarted or changed its binding')
                elif listener_issue(current.get(port, [])):
                    mark_bad(port, listener_issue(current[port]))
        except Exception:
            for port in existing:
                mark_bad(port, 'Cannot read existing-listener health')
        last_sample = now
    try:
        for port in temporary:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(sock)
            sock.bind((bind_host, port))
            sock.listen(128)
            sock.setblocking(False)
            selector.register(sock, selectors.EVENT_READ)
        sample()
        ready_at = time.time()
        deadline = time.monotonic() + lifetime
        next_sample = 0
        while not stop[0] and time.monotonic() < deadline:
            if time.monotonic() >= next_sample:
                sample()
                next_sample = time.monotonic() + 1
            atomic_json(state_path, {'status': 'ready', 'pid': os.getpid(),
                        'token': token, 'ports': ports, 'ready_at': ready_at,
                        'heartbeat': time.time(), 'port_status': status})
            # A monitor-only run has no selector descriptors on some platforms.
            events = selector.select(timeout=0.5) if temporary else []
            if not temporary:
                time.sleep(0.5)
            for key, _ in events:
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
                                'ready_at': ready_at, 'heartbeat': time.time(), 'port_status': status})
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
    serve(config['ports'], config['token'], path / 'state.json', stop,
          config['ttl_seconds'], plan=config['plan'])


def validate_ports(ports):
    if (not isinstance(ports, list) or not 1 <= len(ports) <= 256
            or any(type(p) is not int or not 1 <= p <= 65535 for p in ports)
            or len(set(ports)) != len(ports)):
        raise ValueError('Invalid port list')


def control(request):
    if os.geteuid() != 0:
        raise ValueError('Passwordless sudo is required')
    run_id = request['run_id']
    path = run_path(run_id)
    unit = unit_name(run_id)
    action = request['action']
    if action == 'preflight':
        validate_ports(request['ports'])
        if not shutil.which('systemd-run') or not shutil.which('systemctl'):
            raise ValueError('systemd-run and systemctl are required')
        return {'ok': True, 'plan': preflight(request['ports'], request['destination_ip'],
                                             request['management_port'])}
    if action == 'start':
        ports = request['ports']
        validate_ports(ports)
        ttl = request['ttl_seconds']
        if type(ttl) is not int or not 120 <= ttl <= 7200:
            raise ValueError('Invalid lifetime')
        if request['token'] != 'FPT-' + run_id:
            raise ValueError('Invalid listener token')
        plan = request.get('plan')
        if not isinstance(plan, dict) or set(plan) != {str(p) for p in ports}:
            raise ValueError('Preflight plan is required for every port')
        if any(item.get('mode') not in ('temporary', 'existing', 'unsupported') for item in plan.values()):
            raise ValueError('Invalid port mode')
        management = str(request.get('management_port', 22))
        if plan.get(management, {}).get('mode') == 'temporary':
            raise ValueError('Never create a temporary listener on the management port')
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
                    raise RuntimeError('Listener startup failed; a port may have changed after preflight')
                time.sleep(0.1)
            raise RuntimeError('Timed out waiting for listeners')
        except BaseException:
            systemctl('stop', unit)
            if path.exists():
                shutil.rmtree(path)
            raise
    if action == 'inspect':
        state = json.loads((path / 'state.json').read_text())
        config = json.loads((path / 'config.json').read_text())
        active = systemctl('is-active', unit)
        pid = systemctl('show', unit, '--property=MainPID', '--value')
        healthy = (active.stdout.strip() == 'active' and state['status'] == 'ready'
                   and pid.stdout.strip() == str(state['pid'])
                   and 0 <= time.time() - state['heartbeat'] < 2
                   and state['token'] == 'FPT-' + run_id)
        if healthy:
            current = tcp_listeners()
            def check_existing(item):
                port, details = item
                return port, local_connect(details['target_address'], int(port))
            existing = [(p, details) for p, details in config['plan'].items() if details['mode'] == 'existing']
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                for port, ready in executor.map(check_existing, existing):
                    item = state['port_status'][port]
                    if (not ready or identities(current.get(int(port), []))
                            != identities(config['plan'][port]['listeners'])
                            or listener_issue(current.get(int(port), []))):
                        item.update(healthy=False, reason='Existing listener identity or local TCP readiness failed at final check')
        return {'ok': healthy, 'state': state, 'remote_time': time.time()}
    if action == 'stop':
        # Stop only the monitor/test unit; existing applications are never its children.
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
            request = json.load(sys.stdin)
            if request.get('action') == 'preflight':
                # OpenSSH supplies this before sudo resets its environment.
                parts = sys.argv[1].split() if len(sys.argv) > 1 else []
                if len(parts) != 4:
                    raise ValueError('SSH destination IPv4 cannot be determined')
                request['destination_ip'] = str(ipaddress.IPv4Address(parts[2]))
            result = control(request)
            print(json.dumps(result))
        except Exception as exc:
            print(json.dumps({'ok': False, 'error': str(exc)}))
            sys.exit(1)


if __name__ == '__main__':
    main()
