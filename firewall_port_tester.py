#!/usr/bin/env python3
"""Explicit-target TCP access verification from company and external networks."""
import argparse
import concurrent.futures
import csv
import datetime
import ipaddress
import json
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent
POLICIES = ('world_ports', 'company_ports', 'blocked_ports')
DEFAULTS = {'ttl_seconds': 3600, 'connect_timeout_seconds': 3, 'attempts': 2,
            'public_ip_url': 'https://api.ipify.org'}


def fail(message):
    raise ValueError(message)


def keys(obj, allowed, label):
    if not isinstance(obj, dict):
        fail(label + ' must be an object')
    unknown = set(obj) - set(allowed)
    if unknown:
        fail(label + ': unknown fields: ' + ', '.join(sorted(unknown)))


def integer(value, lower, upper, label):
    if type(value) is not int or not lower <= value <= upper:
        fail(f'{label} must be an integer between {lower} and {upper}')
    return value


def ssh_config(value, folder):
    keys(value, ('user', 'key_file', 'port'), 'ssh')
    if not isinstance(value.get('user'), str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', value['user']):
        fail('ssh.user must be a Linux account name')
    key = value.get('key_file')
    if not isinstance(key, str) or not key.strip() or '\x00' in key or '\n' in key:
        fail('ssh.key_file is required')
    path = Path(key).expanduser()
    if not path.is_absolute():
        path = folder / path
    return {'user': value['user'], 'key_file': str(path.resolve()),
            'port': integer(value.get('port', 22), 1, 65535, 'ssh.port')}


def validate(raw, folder):
    keys(raw, ('schema_version', 'company_cidrs', 'ssh', 'settings', 'machines'), 'config')
    if type(raw.get('schema_version')) is not int or raw['schema_version'] != 1:
        fail('schema_version must be 1')
    cidrs = raw.get('company_cidrs')
    if not isinstance(cidrs, list) or not cidrs:
        fail('company_cidrs must contain the company public IPv4 CIDRs')
    networks = []
    for cidr in cidrs:
        if not isinstance(cidr, str):
            fail('company_cidrs entries must be IPv4 CIDR strings')
        network = ipaddress.IPv4Network(cidr, strict=True)
        if network.prefixlen == 0:
            fail('company_cidrs cannot include 0.0.0.0/0')
        networks.append(str(network))
    default_ssh = ssh_config(raw.get('ssh'), folder)
    settings = raw.get('settings', {})
    keys(settings, DEFAULTS, 'settings')
    settings = {**DEFAULTS, **settings}
    integer(settings['ttl_seconds'], 120, 7200, 'ttl_seconds')
    integer(settings['connect_timeout_seconds'], 1, 15, 'connect_timeout_seconds')
    integer(settings['attempts'], 1, 5, 'attempts')
    url = settings['public_ip_url']
    if not isinstance(url, str) or not url.startswith('https://'):
        fail('public_ip_url must use HTTPS')
    machines = raw.get('machines')
    if not isinstance(machines, list) or not 1 <= len(machines) <= 64:
        fail('machines must contain 1 to 64 targets')
    output = []
    names, hosts = set(), set()
    for m in machines:
        keys(m, ('name', 'host', 'ssh', *POLICIES), 'machine')
        name = m.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name):
            fail('machine.name must contain 1 to 64 letters, digits, dots, underscores or hyphens')
        if not isinstance(m.get('host'), str):
            fail('machine.host must be an IPv4 string')
        host = str(ipaddress.IPv4Address(m['host']))
        if name in names or host in hosts:
            fail('Duplicate machine name or host')
        names.add(name)
        hosts.add(host)
        if 'ssh' in m:
            keys(m['ssh'], ('user', 'key_file', 'port'), 'machine.ssh')
        target_ssh = default_ssh if 'ssh' not in m else ssh_config({**raw['ssh'], **m['ssh']}, folder)
        target = {'name': name, 'host': host, 'ssh': target_ssh}
        seen = set()
        for policy in POLICIES:
            ports = m.get(policy, [])
            if not isinstance(ports, list):
                fail(policy + ' must be an array')
            for port in ports:
                integer(port, 1, 65535, policy)
                if port in seen:
                    fail(name + ': duplicate port or conflicting policy')
                if port == target_ssh['port']:
                    fail(name + ': the SSH management port cannot be a temporary test port')
                seen.add(port)
            target[policy] = ports
        if not 1 <= len(seen) <= 256:
            fail(name + ': specify 1 to 256 explicit test ports')
        output.append(target)
    return {'schema_version': 1, 'company_cidrs': networks, 'settings': settings, 'machines': output}


def load_config(path):
    path = Path(path).resolve()
    return validate(json.loads(path.read_text()), path.parent)


def all_ports(machine):
    return sorted(p for policy in POLICIES for p in machine[policy])


def expected(phase, policy):
    return policy == 'world_ports' or (phase == 'company' and policy == 'company_ports')


def is_company(source, cidrs):
    address = ipaddress.IPv4Address(source)
    return any(address in ipaddress.IPv4Network(cidr) for cidr in cidrs)


def public_ip(url):
    # Query directly so a configured HTTP proxy cannot masquerade as the probe source.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=10) as response:
        return str(ipaddress.IPv4Address(response.read(128).decode().strip()))


def check_source(config, phase):
    source = public_ip(config['settings']['public_ip_url'])
    company = is_company(source, config['company_cidrs'])
    if company != (phase == 'company'):
        fail(f'{source}: incorrect source for {phase}; check network and VPN, then retry')
    print(f'{phase}: public source IP {source}', flush=True)
    return source


def remote(machine, run_id, action, settings=None):
    ssh = machine['ssh']
    source = (ROOT / 'remote_agent.py').read_text()
    request = {'action': action, 'run_id': run_id}
    if action == 'start':
        request.update(ports=all_ports(machine), token='FPT-' + run_id,
                       ttl_seconds=settings['ttl_seconds'], source=source)
    command = ['ssh', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
               '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=10',
               '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
               '-i', ssh['key_file'], '-p', str(ssh['port']),
               ssh['user'] + '@' + machine['host'],
               shlex.join(['sudo', '-n', 'python3', '-c', source])]
    result = subprocess.run(command, input=json.dumps(request), text=True,
                            capture_output=True, timeout=55)
    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        # Do not copy arbitrary remote output or paths to public logs.
        fail(machine['name'] + ': SSH/remote command failed; verify SSH, Python 3 and sudo -n')
    if result.returncode or not data.get('ok'):
        fail(machine['name'] + ': ' + str(data.get('error', 'Remote listener is not healthy')))
    return data


def preflight_keys(config):
    for machine in config['machines']:
        path = Path(machine['ssh']['key_file'])
        if not path.is_file():
            fail(machine['name'] + ': SSH key file does not exist')
        if path.stat().st_mode & 0o077:
            fail(machine['name'] + ': SSH key permissions must restrict group/other access (chmod 600)')


def probe(host, port, token, timeout):
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((host, port), timeout=timeout) as connection:
            data = b''
            try:
                while len(data) < 128 and b'\n' not in data:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    connection.settimeout(remaining)
                    block = connection.recv(128 - len(data))
                    if not block:
                        break
                    data += block
            except (OSError, TimeoutError):
                pass
            return {'connected': True, 'marker_ok': data.strip() == token.encode(), 'detail': 'connected'}
    except (ConnectionRefusedError, TimeoutError, socket.timeout) as exc:
        return {'connected': False, 'marker_ok': False, 'detail': type(exc).__name__}
    except OSError as exc:
        # Routing, permissions and local resource errors are not proof of blocking.
        return {'connected': None, 'marker_ok': False, 'detail': type(exc).__name__}


def test_phase(config, phase, run_id, source):
    jobs = []
    settings = config['settings']
    for machine in config['machines']:
        for policy in POLICIES:
            for port in machine[policy]:
                jobs.append((machine, policy, port))
    def task(job):
        machine, policy, port = job
        started_at = time.time()
        attempts = [probe(machine['host'], port, 'FPT-' + run_id,
                          settings['connect_timeout_seconds']) for _ in range(settings['attempts'])]
        return {'machine': machine['name'], 'host': machine['host'], 'phase': phase,
                'source_ip': source, 'port': port, 'policy': policy,
                'expected': 'ALLOW' if expected(phase, policy) else 'BLOCK',
                'started_at': started_at, 'finished_at': time.time(),
                'attempts': attempts, 'result': 'PENDING'}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        for row in executor.map(task, jobs):
            print(f"  {row['machine']}:{row['port']} expected {row['expected']} (pending health verification)", flush=True)
            yield row


def verdict(row, healthy, cleaned):
    if not healthy or not cleaned:
        return 'ERROR'
    attempts = row['attempts']
    if row['expected'] == 'BLOCK':
        if any(item['connected'] is True for item in attempts):
            return 'FAIL'
        return 'PASS' if all(item['connected'] is False for item in attempts) else 'ERROR'
    if any(item['connected'] is None for item in attempts):
        return 'ERROR'
    if any(item['connected'] and not item['marker_ok'] for item in attempts):
        return 'ERROR'
    return 'PASS' if all(item['connected'] and item['marker_ok'] for item in attempts) else 'FAIL'


def save_report(folder, report):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    columns = ['machine', 'host', 'phase', 'source_ip', 'port', 'policy', 'expected', 'result']
    with (folder / 'report.csv').open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(report['tests'])


def cleanup_manifest(folder):
    manifest = json.loads((folder / 'run.local.json').read_text())
    run_id = manifest['run_id']
    if not re.fullmatch(r'[a-f0-9]{32}', run_id):
        fail('Invalid run ID in manifest')
    failures = []
    for machine in manifest['machines']:
        try:
            remote(machine, run_id, 'stop')
            print(machine['name'] + ': cleaned')
        except Exception:
            failures.append(machine['name'])
    if failures:
        fail('Cleanup not confirmed for: ' + ', '.join(failures))
    return 0


def run(config, folder):
    preflight_keys(config)
    if folder.exists():
        fail('Output directory already exists; choose a new one')
    folder.mkdir(parents=True, mode=0o700)
    run_id = uuid.uuid4().hex
    report = {'run_id': run_id, 'status': 'ERROR', 'tests': [], 'hosts': {}, 'errors': []}
    started = []
    manifest = {'run_id': run_id, 'machines': started}
    healthy, cleaned = {}, {}
    def save_manifest():
        path = folder / 'run.local.json'
        path.write_text(json.dumps(manifest, indent=2))
        path.chmod(0o600)
    try:
        check_source(config, 'company')
        save_manifest()
        for machine in config['machines']:
            # Track before SSH: the remote service may start even if its SSH reply is lost.
            started.append(machine)
            save_manifest()
            ready = remote(machine, run_id, 'start', config['settings'])
            report['hosts'][machine['name']] = {'initial': ready}
            print(machine['name'] + ': temporary listeners ready', flush=True)
        company_source = check_source(config, 'company')
        report['tests'].extend(test_phase(config, 'company', run_id, company_source))
        if check_source(config, 'company') != company_source:
            fail('Public source changed during company probes; rerun this test')
        save_report(folder, report)
        input('\n公司測試完成。請切換至外網（確認 VPN 也已切換），完成後按 Enter：')
        external_source = check_source(config, 'external')
        report['tests'].extend(test_phase(config, 'external', run_id, external_source))
        if check_source(config, 'external') != external_source:
            fail('Public source changed during external probes; rerun this test')
        save_report(folder, report)
        input('\n外網測試完成。請切回公司網路，完成後按 Enter，以驗證監聽並清理：')
        check_source(config, 'company')
        for machine in started:
            name = machine['name']
            try:
                final = remote(machine, run_id, 'inspect')
                initial = report['hosts'][name]['initial']['state']
                state = final['state']
                healthy[name] = (state['pid'] == initial['pid'] and state['token'] == initial['token']
                                 and state['ready_at'] == initial['ready_at']
                                 and state['ports'] == all_ports(machine))
                report['hosts'][name]['final'] = final
                if not healthy[name]:
                    report['errors'].append(name + ': listener continuity not verified')
            except Exception as exc:
                report['errors'].append(name + ': listener health verification failed')
    except (Exception, KeyboardInterrupt) as exc:
        report['errors'].append(str(exc) if not isinstance(exc, KeyboardInterrupt) else 'Interrupted by user')
    finally:
        if started:
            # Cleanup must not depend on the third-party public-IP service.
            def stop_one(machine):
                try:
                    remote(machine, run_id, 'stop')
                    return machine['name'], True
                except Exception:
                    return machine['name'], False
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                    for name, confirmed in executor.map(stop_one, started):
                        cleaned[name] = confirmed
                        if not confirmed:
                            report['errors'].append(name + ': cleanup not confirmed; remote expiry remains active')
            except KeyboardInterrupt:
                report['errors'].append('Cleanup interrupted; remote expiry remains active')
        for row in report['tests']:
            row['result'] = verdict(row, healthy.get(row['machine'], False), cleaned.get(row['machine'], False))
        for machine in started:
            name = machine['name']
            report['hosts'].setdefault(name, {}).update(healthy=healthy.get(name, False), cleaned=cleaned.get(name, False))
        if report['errors'] or not report['tests'] or any(r['result'] == 'ERROR' for r in report['tests']):
            report['status'] = 'ERROR'
        elif any(r['result'] == 'FAIL' for r in report['tests']):
            report['status'] = 'FAIL'
        else:
            report['status'] = 'PASS'
        save_report(folder, report)
        print('\nResult: ' + report['status'])
        for result in ('PASS', 'FAIL', 'ERROR'):
            print(f"  {result}: {sum(row['result'] == result for row in report['tests'])}")
        for error in report['errors']:
            print('  ' + error)
        print('Local reports: ' + str(folder))
        if any(not cleaned.get(m['name']) for m in started):
            print('Return to company network, then run: ./test-ports.sh cleanup --run-dir ' + shlex.quote(str(folder)))
    return {'PASS': 0, 'FAIL': 1, 'ERROR': 2}[report['status']]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('validate', 'run'):
        item = commands.add_parser(command)
        item.add_argument('--config', required=True)
        if command == 'run':
            item.add_argument('--output', help='New local report directory')
    item = commands.add_parser('cleanup')
    item.add_argument('--run-dir', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'cleanup':
            return cleanup_manifest(Path(args.run_dir).resolve())
        config = load_config(args.config)
        if args.command == 'validate':
            print('Valid configuration; no SSH, network requests or remote changes performed.')
            print(f"Targets: {len(config['machines'])}; explicit ports: {sum(len(all_ports(m)) for m in config['machines'])}")
            return 0
        output = Path(args.output) if args.output else Path('reports') / (datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
        return run(config, output.resolve())
    except Exception as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
