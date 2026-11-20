import copy
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import firewall_port_tester as tool
import remote_agent as agent


def raw_config():
    return json.loads((ROOT / 'examples/targets.example.json').read_text())


class ConfigTests(unittest.TestCase):
    def test_example_validates_without_network_or_ssh(self):
        with patch.object(tool, 'public_ip', side_effect=AssertionError), patch.object(tool, 'remote', side_effect=AssertionError):
            self.assertEqual(tool.main(['validate', '--config', str(ROOT / 'examples/targets.example.json')]), 0)

    def test_refuse_conflicting_policy_and_ssh_port(self):
        for port in (443, 22):
            raw = raw_config()
            raw['machines'][0]['blocked_ports'] = [port]
            with self.assertRaises(ValueError):
                tool.validate(raw, ROOT)

    def test_reject_invalid_inputs(self):
        changes = [lambda r: r.update(company_cidrs=['0.0.0.0/0']),
                   lambda r: r.update(company_cidrs=['192.0.2.11/24']),
                   lambda r: r['ssh'].update(user='ubuntu;rm'),
                   lambda r: r['machines'][0].update(host='example.com'),
                   lambda r: r['machines'][0].update(host=123),
                   lambda r: r['machines'][0].update(ssh=[]),
                   lambda r: r['machines'][0].update(world_ports=[True]),
                   lambda r: r['machines'][0].update(unknown=1),
                   lambda r: r['settings'].update(public_ip_url='http://example.invalid'),
                   lambda r: r['machines'].append(copy.deepcopy(r['machines'][0]))]
        for change in changes:
            raw = raw_config()
            change(raw)
            with self.assertRaises((ValueError, TypeError)):
                tool.validate(raw, ROOT)

    def test_per_machine_ssh_and_relative_path(self):
        raw = raw_config()
        raw['machines'][0]['ssh'] = {'user': 'operator', 'key_file': 'keys/test.pem', 'port': 2222}
        config = tool.validate(raw, ROOT)
        self.assertEqual(config['machines'][0]['ssh']['key_file'], str(ROOT / 'keys/test.pem'))
        self.assertEqual(config['machines'][0]['ssh']['port'], 2222)

    def test_source_modes_and_vpn_still_in_company(self):
        config = tool.validate(raw_config(), ROOT)
        with patch.object(tool, 'public_ip', return_value='192.0.2.10'):
            self.assertEqual(tool.check_source(config, 'company'), '192.0.2.10')
            with self.assertRaises(ValueError):
                tool.check_source(config, 'external')
        with patch.object(tool, 'public_ip', return_value='203.0.113.99'):
            self.assertEqual(tool.check_source(config, 'external'), '203.0.113.99')


class VerdictTests(unittest.TestCase):
    def test_policy_matrix(self):
        self.assertEqual([tool.expected('company', p) for p in tool.POLICIES], [True, True, False])
        self.assertEqual([tool.expected('external', p) for p in tool.POLICIES], [True, False, False])

    def test_no_false_pass_when_listener_or_cleanup_unknown(self):
        row = {'expected': 'BLOCK', 'attempts': [{'connected': False, 'marker_ok': False}]}
        self.assertEqual(tool.verdict(row, False, True), 'ERROR')
        self.assertEqual(tool.verdict(row, True, False), 'ERROR')
        self.assertEqual(tool.verdict(row, True, True), 'PASS')

    def test_connected_blocked_port_fails(self):
        row = {'expected': 'BLOCK', 'attempts': [{'connected': True, 'marker_ok': False}]}
        self.assertEqual(tool.verdict(row, True, True), 'FAIL')

    def test_wrong_marker_and_route_error_are_not_passes(self):
        for attempt in ({'connected': True, 'marker_ok': False}, {'connected': None, 'marker_ok': False}):
            self.assertEqual(tool.verdict({'expected': 'ALLOW', 'attempts': [attempt]}, True, True), 'ERROR')
        self.assertEqual(tool.verdict({'expected': 'BLOCK', 'attempts': [{'connected': None}]}, True, True), 'ERROR')

    def test_probe_uses_one_deadline_for_connect_and_partial_reads(self):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        connection.recv.side_effect = [b'F', b'P']
        with patch.object(tool.socket, 'create_connection', return_value=connection), \
             patch.object(tool.time, 'monotonic', side_effect=[10.0, 12.0, 12.9, 13.1]):
            result = tool.probe('192.0.2.20', 443, 'FPT-test', 3)
        self.assertTrue(result['connected'])
        self.assertFalse(result['marker_ok'])
        self.assertEqual(connection.recv.call_count, 2)
        self.assertEqual(len(connection.settimeout.call_args_list), 2)
        self.assertAlmostEqual(connection.settimeout.call_args_list[0].args[0], 1.0)
        self.assertAlmostEqual(connection.settimeout.call_args_list[1].args[0], 0.1)

    def test_intermittent_allow_fails(self):
        row = {'expected': 'ALLOW', 'attempts': [{'connected': True, 'marker_ok': True}, {'connected': False, 'marker_ok': False}]}
        self.assertEqual(tool.verdict(row, True, True), 'FAIL')


class ListenerTests(unittest.TestCase):
    def test_listener_marker_expiry_and_port_release(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / 'state.json'
            with socket.socket() as reserve:
                reserve.bind(('127.0.0.1', 0))
                port = reserve.getsockname()[1]
            errors = []
            def worker():
                try:
                    agent.serve([port], 'local-test', state, [False], 1.3, bind_host='127.0.0.1')
                except BaseException as exc:
                    errors.append(exc)
            thread = threading.Thread(target=worker)
            thread.start()
            try:
                deadline = time.monotonic() + 1
                while not state.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(state.exists())
                result = tool.probe('127.0.0.1', port, 'local-test', 1)
                self.assertTrue(result['connected'])
                self.assertTrue(result['marker_ok'])
            finally:
                thread.join(timeout=4)
            self.assertFalse(thread.is_alive())
            self.assertFalse(errors)
            self.assertEqual(json.loads(state.read_text())['status'], 'stopped')
            self.assertFalse(tool.probe('127.0.0.1', port, 'local-test', 1)['connected'])

    def test_occupied_port_is_setup_error_and_existing_listener_survives(self):
        with tempfile.TemporaryDirectory() as temp, socket.socket() as existing:
            existing.bind(('127.0.0.1', 0))
            existing.listen()
            port = existing.getsockname()[1]
            state = Path(temp) / 'state.json'
            with self.assertRaises(OSError):
                agent.serve([port], 'test', state, [False], 1, bind_host='127.0.0.1')
            self.assertEqual(json.loads(state.read_text())['status'], 'error')
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                pass

    def test_invalid_run_ids_rejected(self):
        for value in ('../../etc', 'abc; rm', 'x' * 32, ''):
            with self.assertRaises(ValueError):
                agent.run_path(value)

    def test_transient_service_has_independent_expiry_and_scoped_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / ('a' * 32)
            request = {'action': 'start', 'run_id': 'a' * 32, 'ports': [18080],
                       'ttl_seconds': 120, 'token': 'FPT-' + 'a' * 32, 'source': '# test stub'}
            def fake_run(command, **kwargs):
                self.assertIn('--property=RuntimeMaxSec=120', command)
                self.assertIn('--property=Restart=no', command)
                self.assertTrue(any(p.startswith('--property=ExecStopPost=') and p.endswith(' purge ' + 'a' * 32) for p in command))
                (path / 'state.json').write_text(json.dumps({'status': 'ready'}))
                return Mock(returncode=0)
            with patch.object(agent, 'BASE', Path(temp)), patch.object(agent, 'run_path', return_value=path), \
                 patch.object(agent, 'unit_name', return_value='test.service'), \
                 patch.object(agent.os, 'geteuid', return_value=0), \
                 patch.object(agent.shutil, 'which', return_value='/usr/bin/tool'), \
                 patch.object(agent.subprocess, 'run', side_effect=fake_run):
                self.assertTrue(agent.control(request)['ok'])

    def test_cleanup_does_not_remove_directory_of_active_service(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            with patch.object(agent, 'run_path', return_value=path), patch.object(agent, 'unit_name', return_value='test.service'), \
                 patch.object(agent.os, 'geteuid', return_value=0), \
                 patch.object(agent, 'systemctl', return_value=Mock(stdout='active')):
                with self.assertRaises(RuntimeError):
                    agent.control({'action': 'stop', 'run_id': 'a' * 32})
                self.assertTrue(path.exists())


    def test_cleanup_systemctl_error_is_not_success(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            with patch.object(agent, 'run_path', return_value=path), patch.object(agent, 'unit_name', return_value='test.service'), \
                 patch.object(agent.os, 'geteuid', return_value=0), \
                 patch.object(agent, 'systemctl', return_value=Mock(stdout='', returncode=1)):
                with self.assertRaisesRegex(RuntimeError, 'Cannot confirm'):
                    agent.control({'action': 'stop', 'run_id': 'a' * 32})
                self.assertTrue(path.exists())

    def test_cleanup_is_repeatable_after_expiry(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'already-expired'
            with patch.object(agent, 'run_path', return_value=path), patch.object(agent, 'unit_name', return_value='test.service'), \
                 patch.object(agent.os, 'geteuid', return_value=0), \
                 patch.object(agent, 'systemctl', return_value=Mock(stdout='inactive', returncode=3)):
                for _ in range(2):
                    self.assertTrue(agent.control({'action': 'stop', 'run_id': 'a' * 32})['cleaned'])


class WorkflowTests(unittest.TestCase):
    def exercise(self, fault=None):
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / 'fake-key.pem'
            key.write_text('placeholder, never transmitted')
            key.chmod(0o600)
            raw = raw_config()
            raw['ssh']['key_file'] = str(key)
            config = tool.validate(raw, ROOT)
            events = []
            def remote(machine, run_id, action, settings=None):
                events.append((machine['name'], action))
                if fault == 'startup' and action == 'start':
                    raise ValueError('setup failed')
                if fault == 'health' and action == 'inspect':
                    raise ValueError('listener expired')
                if fault == 'cleanup' and action == 'stop':
                    raise ValueError('cleanup failed')
                return {'ok': True, 'state': {'pid': 123, 'token': 'FPT-' + run_id,
                       'ready_at': 10, 'ports': tool.all_ports(machine)}}
            def phase(config, name, run_id, source):
                for machine in config['machines']:
                    for policy in tool.POLICIES:
                        for port in machine[policy]:
                            allow = tool.expected(name, policy)
                            connected = not allow if fault == 'policy' else allow
                            yield {'machine': machine['name'], 'host': machine['host'], 'phase': name,
                                   'source_ip': source, 'port': port, 'policy': policy,
                                   'expected': 'ALLOW' if allow else 'BLOCK',
                                   'attempts': [{'connected': connected, 'marker_ok': connected}], 'result': 'PENDING'}
            source_checks = ['192.0.2.10', OSError('public IP endpoint unavailable')] if fault == 'source' else None
            with patch.object(tool, 'remote', side_effect=remote), patch.object(tool, 'check_source', return_value='192.0.2.10', side_effect=source_checks), \
                 patch.object(tool, 'test_phase', side_effect=phase), patch('builtins.input', return_value=''):
                folder = Path(temp) / 'report'
                code = tool.run(config, folder)
                report = json.loads((folder / 'report.json').read_text())
                self.assertTrue((folder / 'report.csv').exists())
                self.assertEqual((folder / 'run.local.json').stat().st_mode & 0o777, 0o600)
            return code, report, events

    def test_two_modes_pass_then_cleanup(self):
        code, report, events = self.exercise()
        self.assertEqual(code, 0)
        self.assertEqual({r['phase'] for r in report['tests']}, {'company', 'external'})
        self.assertTrue(all(r['result'] == 'PASS' for r in report['tests']))
        self.assertEqual(sum(action == 'stop' for _, action in events), 2)

    def test_cleanup_still_runs_when_public_ip_lookup_fails(self):
        code, report, events = self.exercise('source')
        self.assertEqual(code, 2)
        self.assertEqual(report['tests'], [])
        self.assertEqual(sum(action == 'stop' for _, action in events), 2)
        self.assertTrue(all(host['cleaned'] for host in report['hosts'].values()))
        self.assertIn('public IP endpoint unavailable', report['errors'])

    def test_health_failure_invalidates_negative_results(self):
        code, report, _ = self.exercise('health')
        self.assertEqual(code, 2)
        self.assertTrue(all(r['result'] == 'ERROR' for r in report['tests']))

    def test_cleanup_failure_invalidates_result(self):
        code, report, _ = self.exercise('cleanup')
        self.assertEqual(code, 2)
        self.assertTrue(all(r['result'] == 'ERROR' for r in report['tests']))

    def test_start_failure_still_cleans_possibly_started_service(self):
        code, report, events = self.exercise('startup')
        self.assertEqual(code, 2)
        self.assertIn(('example-proxy-01', 'stop'), events)
        self.assertEqual(report['tests'], [])

    def test_policy_mismatch_is_fail(self):
        code, report, _ = self.exercise('policy')
        self.assertEqual(code, 1)
        self.assertTrue(all(r['result'] == 'FAIL' for r in report['tests']))

    def test_wrong_external_source_aborts_and_cleans(self):
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / 'test.pem'
            key.write_text('local placeholder')
            key.chmod(0o600)
            raw = raw_config()
            raw['ssh']['key_file'] = str(key)
            config = tool.validate(raw, ROOT)
            events = []
            def remote(machine, run_id, action, settings=None):
                events.append(action)
                return {'ok': True, 'state': {}}
            def phase(*args):
                return iter([])
            sources = ['192.0.2.10', '192.0.2.10', '192.0.2.10',
                       ValueError('still using company egress'), '192.0.2.10']
            with patch.object(tool, 'remote', side_effect=remote), \
                 patch.object(tool, 'check_source', side_effect=sources), \
                 patch.object(tool, 'test_phase', side_effect=phase) as probes, \
                 patch('builtins.input', return_value=''):
                self.assertEqual(tool.run(config, Path(temp) / 'reports'), 2)
                self.assertEqual(probes.call_count, 1)
                self.assertEqual(events.count('stop'), 2)

    def test_ssh_call_uses_only_key_path_and_safe_host_key_policy(self):
        config = tool.validate(raw_config(), ROOT)
        completed = Mock(returncode=0, stdout='{"ok":true}')
        with patch.object(tool.subprocess, 'run', return_value=completed) as invoke:
            tool.remote(config['machines'][0], 'a' * 32, 'stop')
            args, kwargs = invoke.call_args
            self.assertIn('StrictHostKeyChecking=accept-new', args[0])
            self.assertIn('BatchMode=yes', args[0])
            self.assertNotIn('key_file', kwargs['input'])
            self.assertEqual(json.loads(kwargs['input'])['action'], 'stop')


if __name__ == '__main__':
    unittest.main()
