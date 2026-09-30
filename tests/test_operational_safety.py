"""Verify failure handling before destructive operations and HTTP cleanup."""
import base64
import copy
import json
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

import app as panel
from managers.awg_manager import AWGManager
from managers.ssh_manager import SSHManager


class OperationalSafetyTests(unittest.TestCase):
    def test_mutation_does_not_trust_a_previous_status_snapshot(self):
        import time
        ssh = Mock(_awg_batch={'_ts': time.time(), 'containers': {
            'amnezia-awg2': {'config': '[Interface]\n', 'clients': '[]'},
        }})
        ssh.run_sudo_command.return_value = ('', 'transport lost', -1)
        manager = AWGManager(ssh)
        with self.assertRaisesRegex(RuntimeError, 'Cannot read clients table'):
            manager.rename_client('awg2', 'native-peer', 'renamed')
        self.assertIsNone(ssh._awg_batch)
        ssh.upload_file.assert_not_called()

    def test_incomplete_batch_config_falls_back_to_direct_read(self):
        import time
        ssh = Mock(_awg_batch={'_ts': time.time(), 'containers': {
            'amnezia-awg2': {'config': '', 'clients': '[]'},
        }})
        ssh.run_sudo_command.return_value = ('[Interface]\nListenPort = 443\n', '', 0)
        manager = AWGManager(ssh)
        manager._resolve_config_path = Mock(return_value='/opt/amnezia/awg/awg0.conf')
        self.assertIn('ListenPort = 443', manager._get_server_config('awg2'))
        ssh.run_sudo_command.assert_called_once()

    def test_failed_docker_snapshot_never_caches_absent_containers(self):
        ssh = SSHManager('example.invalid', 22, 'root')
        with patch.object(ssh, 'run_sudo_command', return_value=('', 'transport lost', -1)):
            with self.assertRaisesRegex(RuntimeError, 'Cannot read Docker'):
                AWGManager(ssh).get_server_status('awg2')
        self.assertIsNone(getattr(ssh, '_docker_ps_cache', None))
        with patch.object(ssh, 'run_sudo_command', return_value=('amnezia-awg2\trunning\n', '', 0)):
            self.assertEqual(ssh.docker_container_state('amnezia-awg2'), (True, True))

    def test_incomplete_snapshot_is_an_error(self):
        ssh = SSHManager('example.invalid', 22, 'root')
        with patch.object(ssh, 'run_sudo_command', return_value=('amnezia-awg2', '', 0)):
            with self.assertRaisesRegex(RuntimeError, 'Incomplete'):
                ssh.docker_ps_snapshot()

    def test_failed_backup_aborts_reinstall_before_removal(self):
        ssh = Mock(_awg_batch=None)
        manager = AWGManager(ssh)
        with patch.object(manager, 'check_docker_installed', return_value=True), patch.object(
            manager, 'prepare_host', return_value=None
        ), patch.object(manager, 'setup_kernel_module', return_value='ok'), patch.object(
            manager, '_host_awg_module_version', return_value=''
        ), patch.object(manager, 'check_protocol_installed', return_value=True), patch.object(
            manager, '_backup_container_state', return_value=False
        ), patch.object(manager, 'remove_container') as remove:
            with self.assertRaisesRegex(RuntimeError, 'backup failed'):
                manager.install_protocol('awg2')
            remove.assert_not_called()
            ssh.upload_file_sudo.assert_not_called()

    def test_failed_container_removal_is_reported(self):
        ssh = Mock(_awg_batch=None)
        ssh.run_sudo_command.side_effect = [('', '', 0), ('', 'busy', 1)]
        with self.assertRaisesRegex(RuntimeError, 'Failed to remove'):
            AWGManager(ssh).remove_container('awg2')
        self.assertEqual(ssh.run_sudo_command.call_count, 2)

    def test_failed_prefetch_drops_old_batch(self):
        ssh = Mock(_awg_batch={'_ts': 0, 'containers': {'amnezia-awg2': {'clients': '[]'}}})
        ssh.docker_container_state.return_value = (True, True)
        ssh.run_sudo_command.return_value = ('partial', 'broken channel', -1)
        with self.assertRaisesRegex(RuntimeError, 'Cannot prefetch'):
            AWGManager(ssh).prefetch_awg_state(['awg2'])
        self.assertIsNone(ssh._awg_batch)


class UninstallHttpClientTests(unittest.TestCase):
    def setUp(self):
        self.state = {
            'users': [{'id': 'admin', 'role': 'admin', 'enabled': True}],
            'servers': [{'host': 'example.invalid', 'protocols': {'awg2': {}, 'awg2__2': {}}}],
            'user_connections': [
                {'id': 'remove', 'user_id': 'admin', 'server_id': 0, 'protocol': 'awg2', 'client_id': 'a'},
                {'id': 'keep-instance', 'user_id': 'admin', 'server_id': 0, 'protocol': 'awg2__2', 'client_id': 'b'},
                {'id': 'keep-server', 'user_id': 'admin', 'server_id': 1, 'protocol': 'awg2', 'client_id': 'c'},
            ],
        }
        middleware = next(m for m in panel.app.user_middleware
                          if m.cls.__name__ == 'SessionMiddleware')
        cookie = TimestampSigner(str(middleware.kwargs['secret_key'])).sign(
            base64.b64encode(json.dumps({'user_id': 'admin'}).encode())).decode()
        self.client = TestClient(panel.app)
        self.addCleanup(self.client.close)
        self.client.cookies.set('session', cookie)

    def test_uninstall_purges_only_matching_instance_and_server(self):
        with patch.object(panel, 'load_data', return_value=self.state), patch.object(
            panel, 'save_data'
        ) as save, patch.object(panel, 'get_ssh', return_value=Mock()), patch.object(
            panel, 'get_protocol_manager', return_value=Mock()
        ):
            response = self.client.post('/api/servers/0/uninstall', json={'protocol': 'awg2'})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual([c['id'] for c in self.state['user_connections']], ['keep-instance', 'keep-server'])
            self.assertIn('awg2__2', self.state['servers'][0]['protocols'])
            save.assert_called_once()

    def test_failed_uninstall_preserves_all_bindings(self):
        before = copy.deepcopy(self.state)
        manager = Mock()
        manager.remove_container.side_effect = RuntimeError('removal failed')
        with patch.object(panel, 'load_data', return_value=self.state), patch.object(
            panel, 'save_data'
        ) as save, patch.object(panel, 'get_ssh', return_value=Mock()), patch.object(
            panel, 'get_protocol_manager', return_value=manager
        ):
            response = self.client.post('/api/servers/0/uninstall', json={'protocol': 'awg2'})
            self.assertEqual(response.status_code, 500)
            self.assertEqual(self.state, before)
            save.assert_not_called()
