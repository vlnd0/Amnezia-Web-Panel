import copy
import json
import os
import re
import threading
from base64 import b64encode, b64decode
from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient

import app as panel
from awg_recovery import AwgRecoveryError, AwgRecoveryStore, ROOT, public_key, state_summary
from managers.awg_manager import AWGManager
from test_awg_config_cache import FakeSSH


def key(value):
    return b64encode(bytes([value]) * 32).decode()


def recovery_state(protocol='awg3'):
    private = key(1)
    active, disabled = public_key(key(2)), public_key(key(3))
    config = (f'[Interface]\nPrivateKey = {private}\nAddress = 10.8.1.1/24, fd42:8:1::1/64\n'
              f'ListenPort = 3478\nJc = 2\nJmin = 17\nJmax = 50\nS1 = 26\nS2 = 45\nS3 = 20\nS4 = 33\n'
              f'H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nHeaderProtectionKey = {key(5)}\nMTU = 1280\n'
              f'\n[Peer]\nPublicKey = {active}\nPresharedKey = {key(4)}\n'
              'AllowedIPs = 10.8.1.2/32, fd42:8:1::2/128\n')
    table = [{'clientId': public_key(key(i)), 'userData': {
        'clientName': f'client-{i}', 'clientPrivateKey': key(i),
        'clientIp': f'10.8.1.{i}', 'clientIpv6': f'fd42:8:1::{i}',
        'psk': key(4), 'enabled': i == 2,
    }} for i in (2, 3)]
    return {
        'version': 1, 'protocol': protocol, 'config_path': ROOT + 'awg0.conf',
        'listen_port': 3478, 'server_public_key': public_key(private),
        'port_bindings': {'3478/udp': [{'HostIp': '', 'HostPort': '3478'},
                                      {'HostIp': '', 'HostPort': '443'}]},
        'files': {ROOT + 'awg0.conf': config, ROOT + 'clientsTable': json.dumps(table),
                  ROOT + 'wireguard_server_private_key.key': private + '\n',
                  ROOT + 'wireguard_server_public_key.key': public_key(private) + '\n',
                  ROOT + 'wireguard_psk.key': key(4) + '\n',
                  '/opt/amnezia/start.sh': '#!/bin/bash\n# preserved startup\ntail -f /dev/null\n'},
    }


class RecoverySSH(FakeSSH):
    def __init__(self, state, exists=True):
        super().__init__(state['files'] if exists else {})
        self.bindings = state['port_bindings']
        self.exists = exists
        self._exec_lock = threading.RLock()

    def docker_container_state(self, container):
        return self.exists, self.exists

    def _make_private_temp_dir(self):
        return '/tmp/recovery-test'

    def upload_file_sudo(self, content, remote_path):
        self.uploads[remote_path] = content

    def run_sudo_command(self, command, timeout=60):
        if 'base64 "$p"' in command:
            from awg_recovery import ALLOWED_FILES
            return '\n'.join(p + ':' + b64encode(v.encode()).decode()
                             for p, v in self.files.items() if p in ALLOWED_FILES), '', 0
        if 'json .HostConfig.PortBindings' in command:
            return json.dumps(self.bindings), '', 0
        if command.startswith('bash /tmp/recovery-test/restore.sh'):
            script = self.uploads['/tmp/recovery-test/restore.sh']
            for encoded, path in re.findall(r"printf '%s' '([^']*)' \| base64 -d > \"\$work/([^\"]+)\"", script):
                self.files['/opt/amnezia/' + path] = b64decode(encoded).decode()
            return '', '', 0
        if command.startswith('docker run -d'):
            self.exists = True
            self.commands.append(command)
            return 'new-container', '', 0
        if command.endswith(' public-key'):
            from awg_recovery import config_values
            private = config_values(self.files[ROOT + 'awg0.conf'])['PrivateKey'][0]
            return public_key(private), '', 0
        if command.endswith(' peers'):
            from awg_recovery import config_values
            return '\n'.join(config_values(self.files[ROOT + 'awg0.conf'], 'Peer')['PublicKey']), '', 0
        if command.startswith('cat /tmp/docker-build-') and '.log.code' in command:
            return '0\n', '', 0
        return super().run_sudo_command(command, timeout)


def store_at(tmp_path):
    return AwgRecoveryStore(str(tmp_path / 'awg-recovery' / 'state.sqlite3'))


def test_state_survives_panel_restart_and_server_reorder(tmp_path):
    store = store_at(tmp_path)
    state = recovery_state('awg3__2')
    summary = store.save('permanent-node-uid', state)
    reopened = AwgRecoveryStore(store.path)
    assert reopened.load('permanent-node-uid', 'awg3__2')['files'] == state['files']
    assert reopened.load('another-node', 'awg3__2') is None
    assert summary['available'] and summary['clients_count'] == 2
    assert key(1) not in json.dumps(summary)
    assert os.stat(store.path).st_mode & 0o777 == 0o600
    assert os.stat(os.path.dirname(store.path)).st_mode & 0o777 == 0o700


@pytest.mark.parametrize('damage', ['wrong_key', 'missing_psk', 'path_traversal', 'missing_table', 'invalid_port'])
def test_incomplete_capture_never_replaces_good_identity(tmp_path, damage):
    store = store_at(tmp_path)
    original = recovery_state()
    store.save('node', original)
    broken = copy.deepcopy(original)
    if damage == 'wrong_key':
        broken['server_public_key'] = public_key(key(9))
    elif damage == 'missing_psk':
        del broken['files'][ROOT + 'wireguard_psk.key']
    elif damage == 'path_traversal':
        broken['files']['/opt/amnezia/../../etc/shadow'] = 'forbidden'
    elif damage == 'missing_table':
        del broken['files'][ROOT + 'clientsTable']
    else:
        broken['port_bindings'] = {'3478/udp': [{'HostPort': '443; echo injected'}]}
    with pytest.raises(AwgRecoveryError):
        store.save('node', broken)
    assert store.load('node', 'awg3')['files'] == original['files']


def test_pending_failed_change_cannot_resurrect_stale_peers(tmp_path):
    store = store_at(tmp_path)
    state = recovery_state()
    store.save('node', state)
    ssh = RecoverySSH(state)
    ssh._awg_recovery_binding = (store, 'node')
    manager = AWGManager(ssh)
    with patch.object(manager, '_get_clients_table', side_effect=RuntimeError('node lost')):
        with pytest.raises(RuntimeError, match='node lost'):
            manager.toggle_client('awg3', public_key(key(2)), False)
    with pytest.raises(AwgRecoveryError, match='unsynchronized'):
        store.load('node', 'awg3')
    assert state_summary(store.load('node', 'awg3', allow_pending=True))['sync_pending']
    manager.capture_recovery_state('awg3')
    assert store.load('node', 'awg3') is not None


def test_native_reinstall_cannot_overwrite_original_server_identity(tmp_path):
    state = recovery_state()
    store = store_at(tmp_path)
    store.save('node', state)
    changed = copy.deepcopy(state)
    changed['files'][ROOT + 'awg0.conf'] = changed['files'][ROOT + 'awg0.conf'].replace(key(1), key(8))
    changed['files'][ROOT + 'wireguard_server_private_key.key'] = key(8) + '\n'
    changed['files'][ROOT + 'wireguard_server_public_key.key'] = public_key(key(8)) + '\n'
    changed['server_public_key'] = public_key(key(8))
    with pytest.raises(AwgRecoveryError, match='identity changed'):
        store.save('node', changed)
    assert store.load('node', 'awg3')['files'] == state['files']


def test_client_mutations_are_committed_before_reply(tmp_path):
    state = recovery_state()
    store = store_at(tmp_path)
    ssh = RecoverySSH(state)
    ssh._awg_recovery_binding = (store, 'node')
    manager = AWGManager(ssh)
    manager.capture_recovery_state('awg3')
    active = public_key(key(2))
    manager.toggle_client('awg3', active, False)
    saved = store.load('node', 'awg3')
    assert active not in saved['files'][ROOT + 'awg0.conf']
    assert not json.loads(saved['files'][ROOT + 'clientsTable'])[0]['userData']['enabled']
    manager.remove_client('awg3', active)
    assert active not in store.load('node', 'awg3')['files'][ROOT + 'clientsTable']
    result = manager.add_client('awg3', 'new-client', 'example.invalid', '443')
    saved = store.load('node', 'awg3')
    assert result['client_id'] in saved['files'][ROOT + 'clientsTable']
    assert result['client_id'] in saved['files'][ROOT + 'awg0.conf']


@pytest.mark.parametrize('protocol', ['awg', 'awg2', 'awg3', 'awg_legacy', 'awg3__2'])
def test_lost_node_restore_keeps_client_config_and_disabled_peer(tmp_path, protocol):
    state = recovery_state(protocol)
    old = AWGManager(RecoverySSH(state))
    before = old.get_client_config(protocol, public_key(key(2)), 'example.invalid', '443')
    store = store_at(tmp_path)
    store.save('node', state)
    # Entire node filesystem is gone; only panel-owned state survives.
    ssh = RecoverySSH(state, exists=False)
    ssh._awg_recovery_binding = (store, 'node')
    manager = AWGManager(ssh)
    manager.check_docker_installed = Mock(return_value=True)
    manager.prepare_host = Mock(return_value=None)
    manager.setup_kernel_module = Mock(return_value='skipped')
    manager._host_awg_module_version = Mock(return_value='')
    manager._detect_server_ipv6 = Mock(return_value=False)
    manager._wait_container_running = Mock()
    manager._verify_interface_up = Mock()
    manager.setup_firewall = Mock()
    manager.setup_host_tuning = Mock()
    manager._configure_container = Mock(side_effect=AssertionError('must never generate new keys'))
    with patch('managers.awg_manager.time.sleep'):
        manager.restore_recovery_state(store.load('node', protocol))
    manager._configure_container.assert_not_called()
    assert ssh.files == state['files']
    after = manager.get_client_config(protocol, public_key(key(2)), 'example.invalid', '443')
    assert after == before
    assert public_key(key(3)) not in ssh.files[ROOT + 'awg0.conf']
    assert json.loads(ssh.files[ROOT + 'clientsTable'])[1]['userData']['enabled'] is False
    run = next(c for c in ssh.commands if c.startswith('docker run -d'))
    assert '-p 443:3478/udp' in run and '-p 3478:3478/udp' in run
    assert 'net.ipv6.conf.all.disable_ipv6=0' in run


def test_restore_refuses_live_container_and_wrong_instance():
    state = recovery_state()
    manager = AWGManager(RecoverySSH(state))
    with pytest.raises(AwgRecoveryError, match='already exists'):
        manager.restore_recovery_state(state)
    with pytest.raises(AwgRecoveryError, match='another protocol'):
        manager.install_protocol('awg2', recovery_state=state)


def test_recovery_invalidates_container_cache_and_never_removes_new_container():
    state = recovery_state()
    ssh = RecoverySSH(state)
    ssh._docker_ps_cache = {'stale': True}
    manager = AWGManager(ssh)
    with pytest.raises(AwgRecoveryError, match='already exists'):
        manager.restore_recovery_state(state)
    assert ssh._docker_ps_cache is None
    manager.check_docker_installed = Mock(return_value=True)
    manager.prepare_host = Mock(return_value=None)
    manager.setup_kernel_module = Mock(return_value='skipped')
    manager._host_awg_module_version = Mock(return_value='')
    manager._backup_container_state = Mock()
    manager.remove_container = Mock()
    with pytest.raises(AwgRecoveryError, match='appeared during recovery'):
        manager.install_protocol('awg3', recovery_state=state, require_missing=True)
    manager._backup_container_state.assert_not_called()
    manager.remove_container.assert_not_called()


def test_status_is_admin_only_and_does_not_expose_keys(tmp_path):
    store = store_at(tmp_path)
    state = recovery_state()
    store.save('node', state)
    data = {'servers': [{'uid': 'node', 'protocols': {'awg3': {'installed': True}}}]}
    with patch.object(panel, 'load_data', return_value=data), patch.object(
        panel, 'awg_recovery_store', return_value=store
    ), patch.object(panel, '_check_admin', return_value=False), patch.object(panel, 'get_ssh') as get_ssh:
        client = TestClient(panel.app)
        for action in ('status', 'capture', 'restore'):
            assert client.post(f'/api/servers/0/recovery/{action}', json={'protocol': 'awg3'}).status_code == 403
        get_ssh.assert_not_called()
        with patch.object(panel, '_check_admin', return_value={'role': 'admin'}):
            response = client.post('/api/servers/0/recovery/status', json={'protocol': 'awg3'})
            assert response.status_code == 200 and response.json()['available']
            assert key(1) not in response.text and key(2) not in response.text and key(4) not in response.text
            assert client.post('/api/servers/0/recovery/restore', json={'protocol': 'awg2'}).status_code == 409
            get_ssh.assert_not_called()


def test_store_follows_persistent_data_symlink(tmp_path):
    volume = tmp_path / 'volume'
    volume.mkdir()
    data = volume / 'data.json'
    data.write_text('{}')
    link = tmp_path / 'data.json'
    link.symlink_to(data)
    with patch.object(panel, 'DATA_FILE', str(link)):
        assert panel.awg_recovery_store().path == str(volume / 'awg-recovery' / 'state.sqlite3')


def test_restore_api_follows_uid_after_reorder_and_keeps_advertised_port(tmp_path):
    store = store_at(tmp_path)
    state = recovery_state()
    state['port_bindings'] = {'3478/udp': [{'HostIp': '', 'HostPort': '443'}]}
    store.save('target', state)
    initial = {'servers': [{'uid': 'other'}, {'uid': 'target', 'host': 'example.invalid'}]}
    fresh = {'servers': [{'uid': 'target', 'name': 'renamed', 'protocols': {}}, {'uid': 'other'}]}
    manager = Mock()
    manager.restore_recovery_state.return_value = {'status': 'success', 'awg_params': {'port': '3478'}}
    with patch.object(panel, 'load_data', side_effect=[initial, fresh]), patch.object(
        panel, 'save_data'
    ) as save, patch.object(panel, 'awg_recovery_store', return_value=store), patch.object(
        panel, '_check_admin', return_value={'role': 'admin'}
    ), patch.object(panel, 'get_ssh', return_value=Mock()), patch.object(panel, 'AWGManager', return_value=manager):
        response = TestClient(panel.app).post('/api/servers/1/recovery/restore', json={'protocol': 'awg3'})
        assert response.status_code == 200
        assert key(1) not in response.text
        restored = save.call_args.args[0]['servers'][0]
        assert restored['name'] == 'renamed'
        assert restored['protocols']['awg3']['advertised_port'] == 443
        assert save.call_args.args[0]['servers'][1] == {'uid': 'other'}


def test_unavailable_node_does_not_erase_panel_owned_state(tmp_path):
    store = store_at(tmp_path)
    store.save('node', recovery_state())
    data = {'servers': [{'uid': 'node', 'protocols': {'awg3': {'installed': True}}}]}
    with patch.object(panel, 'load_data', return_value=data), patch.object(
        panel, 'awg_recovery_store', return_value=store
    ), patch.object(panel, 'get_ssh', side_effect=OSError('node lost')):
        panel.synchronize_awg_recovery()
    assert store.load('node', 'awg3')['server_public_key'] == public_key(key(1))
