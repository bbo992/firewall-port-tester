import contextlib
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import firewall_port_tester as tool
import remote_agent as agent


def entry(port, address='0.0.0.0', inode='100', family=4):
    return {'family': family, 'address': address, 'port': port, 'inode': inode, 'recv_queue': 0, 'backlog': 128}


class AutoDetectionTests(unittest.TestCase):
    def classify(self, ports, snapshot, ready=True, management=22):
        fake_socket = Mock()
        fake_socket.__enter__ = Mock(return_value=fake_socket)
        fake_socket.__exit__ = Mock(return_value=False)
        with patch.object(agent, 'ensure_direct_host_network'), \
             patch.object(agent.shutil, 'which', return_value='/usr/bin/ss'), \
             patch.object(agent, 'tcp_listeners', return_value=snapshot), \
             patch.object(agent, 'local_connect', return_value=ready), \
             patch.object(agent.socket, 'socket', return_value=fake_socket):
            plan = agent.preflight(ports, '198.51.100.20', management)
        return plan, fake_socket

    def test_mixed_ports_auto_select_existing_and_temporary(self):
        plan, sock = self.classify([3306, 18080], {3306: [entry(3306)]})
        self.assertEqual(plan['3306']['mode'], 'existing')
        self.assertEqual(plan['18080']['mode'], 'temporary')
        sock.bind.assert_called_once_with(('0.0.0.0', 18080))
        self.assertEqual(plan['3306']['listeners'][0]['inode'], '100')

    def test_loopback_or_other_interface_never_becomes_temporary(self):
        for address in ('127.0.0.1', '203.0.113.40'):
            plan, sock = self.classify([3306], {3306: [entry(3306, address)]})
            self.assertEqual(plan['3306']['mode'], 'unsupported')
            sock.bind.assert_not_called()

    def test_ipv6_dual_stack_requires_ipv4_readiness(self):
        for ready, expected in ((True, 'existing'), (False, 'unsupported')):
            plan, sock = self.classify([443], {443: [entry(443, '::', family=6)]}, ready)
            self.assertEqual(plan['443']['mode'], expected)
            sock.bind.assert_not_called()
        plan, _ = self.classify([443], {443: [entry(443, '::1', family=6)]})
        self.assertEqual(plan['443']['mode'], 'unsupported')

    def test_saturated_or_unverifiable_listener_queue_is_not_a_block_pass(self):
        for details in ({'backlog': 128, 'recv_queue': 128}, {'backlog': 0}):
            listener = entry(3306)
            listener.update(details)
            plan, sock = self.classify([3306], {3306: [listener]})
            self.assertEqual(plan['3306']['mode'], 'unsupported')
            sock.bind.assert_not_called()

    def test_existing_service_must_accept_local_tcp(self):
        plan, sock = self.classify([3306], {3306: [entry(3306)]}, ready=False)
        self.assertEqual(plan['3306']['mode'], 'unsupported')
        sock.bind.assert_not_called()

    def test_unverifiable_inode_and_missing_ssh_listener_are_errors(self):
        plan, sock = self.classify([22, 3306], {3306: [entry(3306, inode='0')]})
        self.assertEqual(plan['22']['mode'], 'unsupported')
        self.assertEqual(plan['3306']['mode'], 'unsupported')
        sock.bind.assert_not_called()

    def test_reserved_non_listening_port_is_not_taken_over(self):
        with patch.object(agent, 'ensure_direct_host_network'), \
             patch.object(agent.shutil, 'which', return_value='/usr/bin/ss'), \
             patch.object(agent, 'tcp_listeners', return_value={}), \
             patch.object(agent.socket, 'socket') as make_socket:
            make_socket.return_value.__enter__.return_value.bind.side_effect = OSError('occupied')
            plan = agent.preflight([18080], '198.51.100.20', 22)
        self.assertEqual(plan['18080']['mode'], 'unsupported')

    def test_proc_parser_ipv4_ipv6_and_ignore_established_connections(self):
        def line(address, family, state, inode):
            raw = socket.inet_pton(family, address)
            if sys.byteorder == 'little':
                raw = b''.join(raw[i:i+4][::-1] for i in range(0, len(raw), 4))
            return f'0: {raw.hex().upper()}:0CEA 00000000:0000 {state} 00000000:00000000 00:0 0 0 0 {inode}\n'
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / 'tcp').write_text('header\n' + line('198.51.100.20', socket.AF_INET, '0A', 123)
                                       + line('127.0.0.1', socket.AF_INET, '01', 999))
            (folder / 'tcp6').write_text('header\n' + line('::ffff:198.51.100.20', socket.AF_INET6, '0A', 456))
            result = agent.tcp_listeners(folder, with_backlog=False)
        self.assertEqual(len(result[3306]), 2)
        self.assertEqual(result[3306][0]['address'], '198.51.100.20')
        self.assertTrue(agent.can_accept_ipv4(result[3306], '198.51.100.20'))

    def test_ss_queue_data_is_matched_by_socket_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / 'tcp').write_text('header\n0: 00000000:0CEA 00000000:0000 0A 0:0 00:0 0 0 0 123\n')
            ss_output = 'LISTEN 2 128 0.0.0.0:3306 0.0.0.0:* uid:0 ino:123 sk:1\n'
            with patch.object(agent.subprocess, 'run', return_value=Mock(returncode=0, stdout=ss_output)):
                result = agent.tcp_listeners(folder)
            self.assertEqual(result[3306][0]['recv_queue'], 2)
            self.assertEqual(result[3306][0]['backlog'], 128)
            self.assertEqual(agent.listener_issue(result[3306]), '')

    def test_forwarded_container_ports_are_not_claimed_as_free(self):
        for rules in ({'nftables': [{'rule': {'expr': [{'dnat': {'addr': '192.0.2.20'}}]}}]},
                      {'nftables': [{'rule': {'expr': [{'redirect': {'port': 8443}}]}}]}):
            with patch.object(agent.shutil, 'which', side_effect=lambda name: '/usr/sbin/nft' if name == 'nft' else None), \
                 patch.object(agent.subprocess, 'run', return_value=Mock(returncode=0, stdout=json.dumps(rules))):
                with self.assertRaisesRegex(ValueError, 'forwarding'):
                    agent.ensure_direct_host_network()

    def test_nat_rules_unavailable_is_error_not_assumed_safe(self):
        with patch.object(agent.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(ValueError, 'required'):
                agent.ensure_direct_host_network()
        with patch.object(agent.shutil, 'which', return_value='/usr/sbin/nft'), \
             patch.object(agent.subprocess, 'run', return_value=Mock(returncode=1, stdout='')):
            with self.assertRaisesRegex(ValueError, 'Cannot inspect'):
                agent.ensure_direct_host_network()

    def test_ssh_destination_survives_sudo_environment_reset(self):
        request = {'action': 'preflight', 'run_id': 'a' * 32, 'ports': [443]}
        with patch.object(agent.sys, 'argv', ['-c', '192.0.2.10 40000 198.51.100.20 22']), \
             patch.object(agent.sys, 'stdin', io.StringIO(json.dumps(request))), \
             patch.object(agent, 'control', return_value={'ok': True}) as control, \
             contextlib.redirect_stdout(io.StringIO()):
            agent.main()
        self.assertEqual(control.call_args.args[0]['destination_ip'], '198.51.100.20')


class ExistingProbeTests(unittest.TestCase):
    def test_existing_tcp_probe_sends_and_reads_no_application_data(self):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        with patch.object(tool.socket, 'create_connection', return_value=connection):
            result = tool.probe('192.0.2.20', 3306, 'not-used', 3, mode='existing')
        self.assertTrue(result['connected'])
        connection.recv.assert_not_called()
        connection.sendall.assert_not_called()
        connection.send.assert_not_called()
        self.assertEqual(tool.verdict({'mode': 'existing', 'expected': 'ALLOW', 'attempts': [result]}, True, True), 'PASS')

    def test_unsupported_and_changed_services_never_pass(self):
        row = {'mode': 'existing', 'expected': 'BLOCK', 'attempts': [{'connected': False}]}
        self.assertEqual(tool.verdict(row, False, True), 'ERROR')
        row['mode'] = 'unsupported'
        self.assertEqual(tool.verdict(row, True, True), 'ERROR')

    def test_phase_uses_per_port_modes_and_skips_unsupported_ports(self):
        machine = {'name': 'example', 'host': '192.0.2.20', 'world_ports': [443],
                   'company_ports': [3306], 'blocked_ports': [18080]}
        config = {'machines': [machine], 'settings': {'attempts': 1, 'connect_timeout_seconds': 3}}
        plan = {'example': {'443': {'mode': 'temporary'}, '3306': {'mode': 'existing'},
                           '18080': {'mode': 'unsupported', 'reason': 'loopback only'}}}
        with patch.object(tool, 'probe', return_value={'connected': True, 'marker_ok': True}) as probe:
            rows = list(tool.test_phase(config, 'company', 'a' * 32, '192.0.2.10', plans=plan))
        self.assertEqual(probe.call_count, 2)
        self.assertEqual({c.kwargs['mode'] for c in probe.call_args_list}, {'existing', 'temporary'})
        self.assertIsNone(next(r for r in rows if r['port'] == 18080)['attempts'][0]['connected'])


class ExistingMonitorTests(unittest.TestCase):
    def test_monitor_keeps_restart_failure_after_listener_recovers(self):
        original = entry(3306)
        snapshots = [{3306: [original]}, {3306: [entry(3306, inode='200')]}, {3306: [original]}]
        count = [0]
        def inspector():
            index = min(count[0], len(snapshots) - 1)
            count[0] += 1
            return snapshots[index]
        plan = {'3306': {'mode': 'existing', 'listeners': [original]}}
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / 'state.json'
            with patch.object(agent.socket, 'socket', side_effect=AssertionError('must not bind existing port')):
                agent.serve([3306], 'test', state, [False], 1.1, plan=plan, inspector=inspector)
            result = json.loads(state.read_text())
        self.assertFalse(result['port_status']['3306']['healthy'])
        self.assertIn('changed', result['port_status']['3306']['reason'])

    def test_final_check_rejects_stale_monitor_before_it_can_hide_a_gap(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            state = {'status': 'ready', 'pid': 123, 'token': 'FPT-' + 'a' * 32,
                     'heartbeat': 97, 'port_status': {}}
            (path / 'state.json').write_text(json.dumps(state))
            (path / 'config.json').write_text(json.dumps({'plan': {}}))
            replies = [Mock(stdout='active', returncode=0), Mock(stdout='123', returncode=0)]
            with patch.object(agent, 'run_path', return_value=path), \
                 patch.object(agent, 'unit_name', return_value='test.service'), \
                 patch.object(agent.os, 'geteuid', return_value=0), \
                 patch.object(agent.time, 'time', return_value=100), \
                 patch.object(agent, 'systemctl', side_effect=replies), \
                 patch.object(agent, 'tcp_listeners', side_effect=AssertionError('must reject stale evidence first')):
                result = agent.control({'action': 'inspect', 'run_id': 'a' * 32})
            self.assertFalse(result['ok'])

    def test_monitoring_gap_invalidates_existing_listener_evidence(self):
        baseline = entry(3306)
        plan = {'3306': {'mode': 'existing', 'listeners': [baseline]}}
        clock, count, stop = [0.0], [0], [False]
        def inspect():
            count[0] += 1
            if count[0] == 2:
                clock[0] = 4.0
            if count[0] == 3:
                stop[0] = True
            return {3306: [baseline]}
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / 'state.json'
            with patch.object(agent.time, 'monotonic', side_effect=lambda: clock[0]), \
                 patch.object(agent.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
                agent.serve([3306], 'test', state, stop, 20, plan=plan, inspector=inspect)
            result = json.loads(state.read_text())['port_status']['3306']
        self.assertFalse(result['healthy'])
        self.assertIn('gap', result['reason'])

    def test_existing_server_survives_test_monitor_stop_and_no_payload_is_sent(self):
        with tempfile.TemporaryDirectory() as temp, socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen(8)
            server.settimeout(0.2)
            port = server.getsockname()[1]
            app_stop = threading.Event()
            received = []
            def application():
                while not app_stop.is_set():
                    try:
                        conn, _ = server.accept()
                    except socket.timeout:
                        continue
                    with conn:
                        conn.settimeout(1)
                        received.append(conn.recv(64))
            application_thread = threading.Thread(target=application)
            application_thread.start()
            baseline = entry(port)
            plan = {str(port): {'mode': 'existing', 'listeners': [baseline]}}
            state = Path(temp) / 'state.json'
            try:
                self.assertTrue(tool.probe('127.0.0.1', port, 'unused', 1, mode='existing')['connected'])
                agent.serve([port], 'test', state, [False], 0.2, plan=plan,
                            inspector=lambda: {port: [baseline]})
                self.assertTrue(tool.probe('127.0.0.1', port, 'unused', 1, mode='existing')['connected'])
                time.sleep(0.1)
                self.assertTrue(json.loads(state.read_text())['port_status'][str(port)]['healthy'])
                self.assertTrue(received)
                self.assertTrue(all(data == b'' for data in received))
            finally:
                app_stop.set()
                application_thread.join(timeout=2)
            self.assertFalse(application_thread.is_alive())


class MixedWorkflowTests(unittest.TestCase):
    def exercise(self, problem=None):
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / 'placeholder.pem'
            key.write_text('fake test key path only')
            key.chmod(0o600)
            raw = json.loads((ROOT / 'examples/targets.example.json').read_text())
            raw['ssh']['key_file'] = str(key)
            config = tool.validate(raw, ROOT)
            current_phase = ['company']
            def source(config, phase):
                current_phase[0] = phase
                return '192.0.2.10' if phase == 'company' else '203.0.113.90'
            def modes(machine):
                result = {}
                for port in tool.all_ports(machine):
                    mode = 'existing' if port in (443, 3306) else 'temporary'
                    if problem == 'unsupported' and port == 18080:
                        mode = 'unsupported'
                    result[str(port)] = {'mode': mode, 'reason': 'loopback only' if mode == 'unsupported' else 'detected'}
                return result
            def remote(machine, run_id, action, settings=None, plan=None):
                ports = modes(machine)
                if action == 'preflight':
                    return {'ok': True, 'plan': ports}
                state = {'pid': 100, 'token': 'FPT-' + run_id, 'ready_at': 1,
                         'ports': tool.all_ports(machine), 'port_status': {}}
                for port, item in ports.items():
                    good = item['mode'] != 'unsupported'
                    if action == 'inspect' and problem == 'restarted' and port == '3306':
                        good = False
                    state['port_status'][port] = {'mode': item['mode'], 'healthy': good,
                                                 'reason': 'changed' if not good else 'verified'}
                return {'ok': True, 'state': state}
            def probe(host, port, token, timeout, mode='temporary'):
                machine = next(m for m in config['machines'] if m['host'] == host)
                policy = next(p for p in tool.POLICIES if port in machine[p])
                allowed = tool.expected(current_phase[0], policy)
                return {'connected': allowed, 'marker_ok': allowed if mode == 'temporary' else None}
            folder = Path(temp) / 'reports'
            with patch.object(tool, 'remote', side_effect=remote), \
                 patch.object(tool, 'check_source', side_effect=source), \
                 patch.object(tool, 'probe', side_effect=probe), \
                 patch('builtins.input', return_value=''), contextlib.redirect_stdout(io.StringIO()):
                code = tool.run(config, folder)
            report = json.loads((folder / 'report.json').read_text())
            self.assertIn('mode,expected,listener_healthy,health_reason,cleanup_confirmed,result', (folder / 'report.csv').read_text().splitlines()[0])
            return code, report

    def test_mixed_existing_and_temporary_ports_both_phases_pass(self):
        code, report = self.exercise()
        self.assertEqual(code, 0)
        self.assertEqual({r['mode'] for r in report['tests']}, {'existing', 'temporary'})
        self.assertTrue(all(r['result'] == 'PASS' for r in report['tests']))
        self.assertEqual(report['report_version'], 2)

    def test_changed_service_invalidates_only_its_port(self):
        code, report = self.exercise('restarted')
        self.assertEqual(code, 2)
        for row in report['tests']:
            self.assertEqual(row['result'], 'ERROR' if row['port'] == 3306 else 'PASS')

    def test_unsupported_port_does_not_become_a_false_block_pass(self):
        code, report = self.exercise('unsupported')
        self.assertEqual(code, 2)
        for row in report['tests']:
            self.assertEqual(row['result'], 'ERROR' if row['port'] == 18080 else 'PASS')


if __name__ == '__main__':
    unittest.main()
