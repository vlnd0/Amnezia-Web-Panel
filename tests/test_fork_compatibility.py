"""Compatibility contracts for the production AWG2 fleet and its bot."""

import asyncio
import base64
import copy
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

import app as panel
from managers.awg_manager import AWGManager
from managers.serialization import serialized_manager
from managers.ssh_manager import SSHManager
from managers.telemt_manager import TelemtManager
from test_awg_config_cache import FakeSSH


class LegacyPoolTests(unittest.TestCase):
    def manager(self):
        manager = AWGManager(Mock())
        manager._get_server_config = Mock(
            return_value="[Interface]\nAddress = 10.8.1.1/16\n"
        )
        manager._get_used_ips = Mock(return_value=["10.8.1.1"])
        manager._get_reserved_ips = Mock(return_value=set())
        return manager

    def test_pool_crosses_octet_boundary(self):
        manager = self.manager()
        manager._get_used_ips.return_value += [f"10.8.0.{i}" for i in range(1, 255)]
        self.assertEqual(manager._get_next_ip("awg2"), "10.8.0.255")

    def test_disabled_peer_address_stays_reserved(self):
        manager = self.manager()
        manager._get_reserved_ips.return_value = {"10.8.0.1"}
        self.assertEqual(manager._get_next_ip("awg2"), "10.8.0.2")

    def test_advertised_port_precedes_listen_port(self):
        self.assertEqual(
            panel._client_port({"port": "443", "advertised_port": 3478}), "3478"
        )

    def test_start_script_retains_redirects_and_awg3_guard(self):
        manager = self.manager()
        script = manager._build_start_script(
            "awg3", manager._get_subnet("awg3"), 443, [3478]
        )
        self.assertIn("--dport 3478 -j REDIRECT --to-ports 443", script)
        self.assertIn("WG_FORCE_USERSPACE", script)
        self.assertIn("x_killswitch_on", script)

    def test_peer_sync_failure_is_not_reported_as_success(self):
        manager = self.manager()
        manager._purge_invalid_peers = Mock(return_value=[])
        manager._resolve_config_path = Mock(return_value="/opt/amnezia/awg/awg0.conf")
        manager.ssh.run_sudo_command.return_value = ("", "rejected peer", 1)
        with self.assertRaisesRegex(RuntimeError, "Failed to sync"):
            manager._sync_config("awg2")


class ClientsTableTests(unittest.TestCase):
    def test_old_table_format_keeps_disabled_peer_reservations_and_keys(self):
        ssh = Mock()
        row = {'clientIp': '10.8.0.1', 'enabled': False, 'clientPrivateKey': 'test-key'}
        ssh.run_sudo_command.return_value = (json.dumps({'peer': row}), '', 0)
        manager = AWGManager(ssh)
        self.assertEqual(manager._get_reserved_ips('awg2'), {'10.8.0.1'})
        self.assertEqual(manager._get_clients_table('awg2')[0]['userData'], row)

    def test_failed_read_aborts_add_before_any_write(self):
        for response in [("", "transport died", -1), ("{bad json", "", 0), ("", "", 0)]:
            with self.subTest(response=response):
                ssh = Mock()
                ssh.run_sudo_command.return_value = response
                manager = AWGManager(ssh)
                manager._resolve_config_path = Mock(
                    return_value="/opt/amnezia/awg/awg0.conf"
                )
                with self.assertRaises(RuntimeError):
                    manager.add_client("awg2", "new", "example.invalid", "443")
                ssh.upload_file.assert_not_called()
                self.assertFalse(
                    any(
                        "syncconf" in str(c)
                        for c in ssh.run_sudo_command.call_args_list
                    )
                )

    def test_only_confirmed_missing_file_is_empty(self):
        ssh = Mock()
        ssh.run_sudo_command.return_value = ("", "", 42)
        self.assertEqual(AWGManager(ssh)._get_clients_table("awg2"), [])

    def test_save_failure_is_reported(self):
        ssh = Mock()
        ssh.run_sudo_command.return_value = ("", "copy failed", 1)
        with self.assertRaisesRegex(RuntimeError, "Cannot save"):
            AWGManager(ssh)._save_clients_table("awg2", [])


class SSHAtomicityTests(unittest.TestCase):
    def test_connect_keeps_active_shared_transport(self):
        ssh = SSHManager("example.invalid", 22, "root")
        client = Mock()
        client.get_transport.return_value.is_active.return_value = True
        ssh.client = client
        with patch.object(ssh, "_connect_once") as connect:
            self.assertTrue(ssh.connect())
        connect.assert_not_called()
        client.close.assert_not_called()

    def test_full_read_modify_write_is_serialized_across_managers(self):
        ssh = SSHManager("example.invalid", 22, "root")
        entered, release, second_entered = (threading.Event() for _ in range(3))
        rows = []

        @serialized_manager
        class Manager:
            def __init__(self):
                self.ssh = ssh

            def add(self, value):
                snapshot = list(rows)
                if value == "first":
                    entered.set()
                    if not release.wait(2):
                        raise AssertionError("test operation was not released")
                else:
                    second_entered.set()
                rows[:] = snapshot + [value]

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(Manager().add, "first")
            self.assertTrue(entered.wait(2))
            second = pool.submit(Manager().add, "second")
            try:
                self.assertFalse(second_entered.wait(0.05))
            finally:
                release.set()
            first.result(timeout=2)
            second.result(timeout=2)
        self.assertEqual(rows, ["first", "second"])


class TelemtRegressionTests(unittest.TestCase):
    def test_add_and_edit_persist_config_and_fallback_is_tls(self):
        config = '[general.modes]\nclassic = false\nsecure = false\ntls = true\n[general]\ntls_domain = "example.com"\n[access.users]\n'
        ssh = Mock()
        manager = TelemtManager(ssh)
        manager._get_server_config = Mock(return_value=config)
        manager._api_request = Mock(return_value=None)
        manager.get_client_config = Mock(return_value="Not found")
        result = manager.add_client(
            "telemt", "alice", "example.invalid", "443", secret="ab" * 16
        )
        self.assertIn(
            "secret=ee" + "ab" * 16 + "example.com".encode().hex(), result["config"]
        )
        self.assertIn("alice = ", ssh.upload_file_sudo.call_args.args[0])
        manager.edit_client("telemt", "alice", {"telemt_quota": 1024})
        self.assertIn("alice = 1024", ssh.upload_file_sudo.call_args.args[0])


class BotContractTests(unittest.TestCase):
    def test_existing_bearer_and_bot_signed_session_are_compatible(self):
        state = {
            "servers": [],
            "users": [
                {
                    "id": "admin-id",
                    "username": "admin",
                    "role": "admin",
                    "enabled": True,
                }
            ],
            "user_connections": [],
            "api_tokens": [
                {
                    "id": "t",
                    "user_id": "admin-id",
                    "token_hash": panel._hash_api_token("synthetic-test-token"),
                }
            ],
        }
        middleware = next(
            m
            for m in panel.app.user_middleware
            if m.cls.__name__ == "SessionMiddleware"
        )
        secret = middleware.kwargs["secret_key"]
        session = base64.b64encode(json.dumps({"user_id": "admin-id"}).encode())
        cookie = TimestampSigner(str(secret)).sign(session).decode()
        with tempfile.TemporaryDirectory() as directory, patch.object(
            panel, "DATA_FILE", directory + "/data.json"
        ):
            panel.save_data(state)
            client = TestClient(panel.app)
            self.assertEqual(
                client.get(
                    "/api/users",
                    headers={"Authorization": "Bearer synthetic-test-token"},
                ).status_code,
                200,
            )
            self.assertEqual(
                client.get(
                    "/api/users", headers={"Authorization": "Bearer wrong"}
                ).status_code,
                403,
            )
            client.cookies.set("session", cookie)
            response = client.post(
                "/api/users/add",
                json={
                    "username": "prosto_test",
                    "password": "synthetic-test-password",
                    "role": "user",
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(
                any(u["username"] == "prosto_test" for u in panel.load_data()["users"])
            )

    def test_awg3_install_is_rejected_before_ssh_on_existing_node(self):
        state = {"servers": [{"protocols": {"awg2": {"installed": True}}}]}
        with patch.object(panel, "_check_admin", return_value=True), patch.object(
            panel, "load_data", return_value=state
        ), patch.object(panel, "get_ssh") as ssh:
            response = TestClient(panel.app).post(
                "/api/servers/0/install", json={"protocol": "awg3"}
            )
        self.assertEqual(response.status_code, 409)
        ssh.assert_not_called()

    def test_user_connection_add_returns_client_id_and_advertised_port(self):
        state = {
            "servers": [
                {
                    "host": "example.invalid",
                    "protocols": {"awg2": {"port": "443", "advertised_port": 3478}},
                }
            ],
            "users": [{"id": "u"}],
            "user_connections": [],
        }
        manager = Mock()
        config = "[Interface]\nPrivateKey = test\nAddress = 10.8.0.1/32\n[Peer]\nPublicKey = test\nEndpoint = example.invalid:3478\n"
        manager.add_client.return_value = {"client_id": "peer", "config": config}
        with patch.object(panel, "_check_admin", return_value=True), patch.object(
            panel, "load_data", side_effect=lambda: copy.deepcopy(state)
        ), patch.object(panel, "save_data") as save, patch.object(
            panel, "get_ssh", return_value=Mock()
        ), patch.object(
            panel, "get_protocol_manager", return_value=manager
        ):
            response = TestClient(panel.app).post(
                "/api/users/u/connections/add",
                json={"server_id": 0, "protocol": "awg2", "name": "test"},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["client_id"], "peer")
        self.assertEqual(response.json()["config"], config)
        self.assertEqual(manager.add_client.call_args.args[-1], "3478")
        self.assertEqual(
            save.call_args.args[0]["user_connections"][0]["protocol"], "awg2"
        )

    def test_server_ids_cannot_shift_by_default(self):
        with patch.object(panel, "_check_admin", return_value=True), patch.dict(
            "os.environ", {"PRESERVE_SERVER_IDS": "on"}
        ), patch.object(panel, "save_data") as save, patch.object(
            panel, "get_ssh"
        ) as ssh:
            client = TestClient(panel.app)
            self.assertEqual(
                client.post("/api/servers/reorder", json={"order": [1, 0]}).status_code,
                409,
            )
            self.assertEqual(client.post("/api/servers/0/delete").status_code, 409)
        save.assert_not_called()
        ssh.assert_not_called()

    def test_startup_does_not_start_new_node_monitor_by_default(self):
        state = {"servers": [], "users": [{"id": "u", "username": "u"}], "settings": {}}

        def close_task(coroutine):
            coroutine.close()

        with patch.dict("os.environ", {"AWG_CONN_MONITOR": "off"}), patch.object(
            panel, "load_data", return_value=state
        ), patch.object(panel, "save_data"), patch.object(
            panel, "_start_conn_monitor"
        ) as monitor, patch.object(
            panel.asyncio, "create_task", side_effect=close_task
        ), patch.object(
            panel, "get_ssh"
        ) as ssh:
            asyncio.run(panel.startup())
        monitor.assert_not_called()
        ssh.assert_not_called()


class PeerLifecycleTests(unittest.TestCase):
    def test_awg2_and_awg3_preserve_keys_ports_and_idempotent_enable(self):
        for proto in ("awg2", "awg3"):
            with self.subTest(protocol=proto):
                conf_path = "/opt/amnezia/awg/awg0.conf"
                table_path = "/opt/amnezia/awg/clientsTable"
                conf = "[Interface]\nAddress = 10.8.1.1/16\nListenPort = 443\nPrivateKey = server-private\nH1 = 1\n"
                if proto == "awg3":
                    conf += (
                        "HeaderProtectionKey = "
                        + "ab" * 32
                        + "\nRandomTrailers = true\n"
                    )
                ssh = FakeSSH(
                    {
                        conf_path: conf,
                        table_path: "[]",
                        "/opt/amnezia/start.sh": "#!/bin/bash\n# 10.8.0.0/16\ntail -f /dev/null\n",
                    }
                )
                ssh._exec_lock = threading.RLock()
                manager = AWGManager(ssh)
                manager._get_server_public_key = Mock(return_value="server-public")
                manager._get_server_psk = Mock(return_value="psk")
                manager._apply_bw_limits = Mock()
                result = manager.add_client(proto, "test", "example.invalid", "3478")
                cid = result["client_id"]
                self.assertIn("Endpoint = example.invalid:3478", result["config"])
                self.assertEqual(
                    "HeaderProtectionKey" in result["config"], proto == "awg3"
                )
                self.assertEqual(len(json.loads(ssh.files[table_path])), 1)
                manager.toggle_client(proto, cid, False)
                self.assertNotIn(cid, ssh.files[conf_path])
                manager.toggle_client(proto, cid, True)
                manager.toggle_client(proto, cid, True)
                self.assertEqual(ssh.files[conf_path].count(f"PublicKey = {cid}"), 1)
                restored = manager.get_client_config(
                    proto, cid, "example.invalid", "3478"
                )
                self.assertEqual(restored, result["config"])
                self.assertFalse(
                    any(
                        "docker restart" in cmd or "docker rm" in cmd
                        for cmd in ssh.commands
                    )
                )
                manager.remove_client(proto, cid)
                self.assertNotIn(cid, ssh.files[conf_path])
                self.assertEqual(json.loads(ssh.files[table_path]), [])
