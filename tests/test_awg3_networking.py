import ipaddress
import json
from unittest.mock import Mock

import pytest

from managers.awg_manager import AWGManager, generate_awg_params
from test_awg_config_cache import FakeSSH


CONFIG_PATH = '/opt/amnezia/awg/awg0.conf'
TABLE_PATH = '/opt/amnezia/awg/clientsTable'
HEAD = '[Interface]\nPrivateKey = TEST\nAddress = 10.8.1.1/16, fd42:8:1::1/64\n'


def manager(config=HEAD, clients=None):
    ssh = FakeSSH({CONFIG_PATH: config, TABLE_PATH: json.dumps(clients or [])})
    return AWGManager(ssh)


def test_first_dual_stack_client_cannot_take_the_server_ipv6():
    mgr = manager()
    ip = mgr._get_next_ip('awg3')
    assert ip == '10.8.0.2'
    assert mgr._get_client_ipv6('awg3', ip) == 'fd42:8:1::2'


def test_ipv6_mapping_is_unique_across_ipv4_octet_boundaries():
    mgr = manager()
    base = int(ipaddress.IPv4Address('10.8.0.0'))
    addresses = [mgr._get_client_ipv6('awg3', str(ipaddress.IPv4Address(base + i)))
                 for i in range(1, 1025)]
    assert len(set(addresses)) == len(addresses)
    assert addresses[255] == 'fd42:8:1::100'
    assert addresses[257] == 'fd42:8:1::102'


@pytest.mark.parametrize('disabled', [False, True])
def test_native_and_disabled_peers_reserve_their_old_ipv6(disabled):
    peer = '\n[Peer]\nPublicKey = OLD\nAllowedIPs = 10.8.1.2/32, fd42:8:1::2/128\n'
    clients = [{'clientId': 'OLD', 'userData': {
        'clientIp': '10.8.1.2', 'clientIpv6': 'fd42:8:1::2', 'enabled': False,
    }}] if disabled else []
    mgr = manager(HEAD if disabled else HEAD + peer, clients)
    assert mgr._get_next_ip('awg3') == '10.8.0.3'


def test_stored_and_native_assignments_survive_reconstruction():
    peer = '\n[Peer]\nPublicKey = OLD\nAllowedIPs = 10.8.1.2/32, fd42:8:1::2/128\n'
    mgr = manager(HEAD + peer)
    assert mgr._get_existing_client_ipv6('awg3', 'OLD', {}, '10.8.1.2') == 'fd42:8:1::2'
    assert mgr._get_existing_client_ipv6(
        'awg3', 'DISABLED', {'allowedIps': '10.8.1.2/32, fd42:8:1::2/128'}, '10.8.1.2'
    ) == 'fd42:8:1::2'
    assert mgr._get_existing_client_ipv6('awg3', 'OLD', {}, '10.8.1.3') == 'fd42:8:1::2'


@pytest.mark.parametrize('proto', ['awg2', 'awg3'])
def test_config_export_preserves_the_existing_peer_address_and_key(proto):
    peer = '\n[Peer]\nPublicKey = OLD\nAllowedIPs = 10.8.1.2/32, fd42:8:1::2/128\n'
    mgr = manager(HEAD + peer, [{'clientId': 'OLD', 'userData': {
        'clientIp': '10.8.1.2', 'clientPrivateKey': 'EXISTING_KEY', 'psk': 'PSK',
    }}])
    mgr._get_server_public_key = Mock(return_value='SERVER_KEY')
    config = mgr.get_client_config(proto, 'OLD', 'example.invalid', '3478')
    assert 'Address = 10.8.1.2/32, fd42:8:1::2/128' in config
    assert 'PrivateKey = EXISTING_KEY' in config
    assert not mgr.ssh.uploads


def test_issuing_a_peer_after_an_octet_boundary_persists_its_unique_ipv6():
    peers = ''.join(f'\n[Peer]\nPublicKey = OLD{i}\nAllowedIPs = 10.8.0.{i}/32\n'
                    for i in range(1, 256))
    mgr = manager(HEAD + peers)
    mgr._get_server_public_key = Mock(return_value='SERVER_KEY')
    mgr._get_server_psk = Mock(return_value='PSK')
    mgr._ensure_subnet_nat = Mock()
    mgr._sync_config = Mock()
    result = mgr.add_client('awg3', 'new', 'example.invalid', '3478')
    assert result['client_ip'] == '10.8.1.0'
    assert 'Address = 10.8.1.0/32, fd42:8:1::100/128' in result['config']
    assert 'MTU = 1280' in result['config']
    assert 'AllowedIPs = 10.8.1.0/32, fd42:8:1::100/128' in mgr.ssh.files[CONFIG_PATH]
    saved = json.loads(mgr.ssh.files[TABLE_PATH])[-1]
    assert saved['userData']['clientIpv6'] == 'fd42:8:1::100'


@pytest.mark.parametrize('proto', ['awg', 'awg2', 'awg_legacy'])
def test_ipv4_only_legacy_allocation_and_mtu_stay_unchanged(proto):
    mgr = manager('[Interface]\nAddress = 10.8.1.1/16\n')
    assert mgr._get_next_ip(proto) == '10.8.0.1'
    assert mgr._get_client_ipv6(proto, '10.8.0.1') == ''
    assert mgr._get_mtu(proto) == ('1280' if proto == 'awg2' else '1376')


def test_awg3_exports_ignore_old_server_and_client_mtu_overrides():
    mgr = manager()
    assert mgr._get_mtu('awg3') == '1280'
    assert mgr._get_mtu('awg3__2') == '1280'
    assert mgr._get_mtu('awg3', {'mtu': '1300'}) == '1280'
    mgr = manager(HEAD + '# MTU = 1320\n')
    assert mgr._get_mtu('awg3') == '1280'


def test_new_awg3_server_persists_safe_interface_and_client_mtu():
    mgr = manager()
    mgr._configure_container('awg3', '3478', generate_awg_params(awg3=True), ipv6=True)
    command = mgr.ssh.commands[-1]
    assert '\nMTU = 1280\n' in command
    assert '\n# MTU = 1280\n' in command
    mgr._configure_container('awg2', '3478', generate_awg_params(), ipv6=True)
    assert '\nMTU = ' not in mgr.ssh.commands[-1]
    assert '\n# MTU = 1280\n' in mgr.ssh.commands[-1]


@pytest.mark.parametrize('proto', ['awg2', 'awg2__2', 'awg3', 'awg3__2'])
def test_existing_and_custom_exports_get_safe_mtu_without_rotating_keys(proto):
    custom = '[Interface]\nPrivateKey = EXISTING_KEY\nMTU=1376\n\n[Peer]\nPublicKey=SERVER_KEY\n'
    clients = [{'clientId': 'OLD', 'userData': {
        'clientIp': '10.8.0.2', 'clientPrivateKey': 'EXISTING_KEY',
        'psk': 'PSK', 'mtu': '1376',
    }}]
    mgr = manager(HEAD + '# MTU = 1376\n', clients)
    mgr._get_server_public_key = Mock(return_value='SERVER_KEY')
    assert mgr._get_mtu(proto, clients[0]['userData']) == '1280'
    # Instance slots share the export policy; avoid FakeSSH path assumptions.
    mgr._get_clients_table = Mock(return_value=clients)
    config = mgr.get_client_config(proto, 'OLD', 'example.invalid', '3478')
    assert 'MTU = 1280' in config
    assert 'PrivateKey = EXISTING_KEY' in config
    assert 'PresharedKey = PSK' in config
    clients[0]['userData']['customConfig'] = custom
    exported = mgr.get_client_config(proto, 'OLD', 'example.invalid', '3478')
    assert exported == custom.replace('MTU=1376\n', '').replace(
        '[Interface]\n', '[Interface]\nMTU = 1280\n')
    assert clients[0]['userData']['customConfig'] == custom
    assert not mgr.ssh.uploads


def test_mtu_settings_apply_live_without_restarting_or_changing_peers():
    peer = '\n[Peer]\nPublicKey = OLD\nAllowedIPs = 10.8.0.2/32, fd42:8:1::2/128\n'
    mgr = manager(HEAD + '# MTU = 1376\nMTU = 1420\n' + peer)
    mgr.exit_link_info = Mock(return_value=None)
    settings = mgr.update_awg_settings('awg3', mtu='1280', dns='1.1.1.1', dns6='::1')
    saved = mgr.ssh.files[CONFIG_PATH]
    assert saved.count('MTU = ') == 1
    assert '\nMTU = 1280\n' in saved
    assert peer.strip() in saved
    assert settings['mtu'] == '1280'
    assert any('ip link set dev awg0 mtu 1280' in cmd for cmd in mgr.ssh.commands)
    assert not any('docker restart' in cmd or 'syncconf' in cmd for cmd in mgr.ssh.commands)


@pytest.mark.parametrize('mtu', ['1279', '65536', '1280; reboot'])
def test_invalid_awg3_mtu_aborts_before_writes(mtu):
    mgr = manager()
    with pytest.raises(ValueError, match='MTU must be'):
        mgr.update_awg_settings('awg3', mtu=mtu)
    assert not mgr.ssh.uploads
