"""Review regression: retry must reconcile persisted and running peer state."""

import json
from unittest.mock import Mock

import pytest

from managers.awg_manager import AWGManager
from test_awg_config_cache import CLIENTS_TABLE, CONFIG_PATH, FakeSSH


@pytest.mark.parametrize("protocol", ["awg2", "awg3"])
def test_retry_enable_syncs_peer_after_first_sync_failed(protocol):
    peer_id = "retry-peer"
    ssh = FakeSSH({
        CONFIG_PATH: "[Interface]\nAddress = 10.8.1.1/16\nListenPort = 443\n",
        CLIENTS_TABLE: json.dumps([{
            "clientId": peer_id,
            "userData": {
                "clientIp": "10.8.0.2", "psk": "psk", "enabled": False,
            },
        }]),
    })
    manager = AWGManager(ssh)
    manager._ensure_subnet_nat = Mock()
    manager._get_client_ipv6 = Mock(return_value=None)
    manager._apply_bw_limits = Mock()
    manager._sync_config = Mock(side_effect=[RuntimeError("sync failed"), None])

    with pytest.raises(RuntimeError, match="sync failed"):
        manager.toggle_client(protocol, peer_id, True)
    assert peer_id in ssh.files[CONFIG_PATH]
    assert json.loads(ssh.files[CLIENTS_TABLE])[0]["userData"]["enabled"] is False

    manager.toggle_client(protocol, peer_id, True)
    assert manager._sync_config.call_count == 2
    assert json.loads(ssh.files[CLIENTS_TABLE])[0]["userData"]["enabled"] is True
