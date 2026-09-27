"""Per-IP diagnostics use the existing RU UDP/443 capture, with no DNS changes."""

import asyncio
import json
import socket
import subprocess
import sys
import threading
from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest

from managers import server_health as health
from tests.test_server_health import target_ssh


def _servers():
    return [
        {
            "name": name,
            "host": name + ".test",
            "protocols": {"awg2": {"installed": True}},
        }
        for name in ("ru-01", "ru-02", "ch-01", "unrelated")
    ]


def test_probe_sends_to_literal_ip_and_capture_matches_that_destination(monkeypatch):
    monkeypatch.setattr(health.secrets, "token_hex", lambda _: "fixed")
    target = target_ssh([{"ready": True}, {"received": ["PVH_fixed"]}])
    sender = NS(
        run_command=Mock(
            return_value=('{"sent": true, "destination_ip": "192.0.2.2"}', "", 0)
        )
    )

    result = health.probe_udp(
        {"host": "current.example", "username": "root"},
        target,
        {"ru-01": (sender, threading.Lock())},
        target_ip="192.0.2.2",
    )

    capture = target.client.exec_command.call_args.args[0]
    send = sender.run_command.call_args.args[0]
    assert "--destination-ip=192.0.2.2" in capture
    assert "443" in capture
    assert "192.0.2.2" in send
    assert "current.example" not in send
    assert result["ru-01"] == {"status": "received", "destination_ip": "192.0.2.2"}


def test_collector_connects_only_target_and_ru_probes_and_checks_each_spare(
    monkeypatch,
):
    servers = _servers()
    clients = {}

    def connect(server, factory):
        client = NS(disconnect=Mock())
        clients[server["name"]] = client
        return client, {"status": "ok"}

    monkeypatch.setattr(health, "_connect", connect)
    probe = Mock(
        side_effect=lambda target, ssh, sources, target_ip: {
            name: {"status": "received", "destination_ip": target_ip}
            for name in health.PROBE_NAMES
        }
    )
    monkeypatch.setattr(health, "probe_udp", probe)

    result = health.collect_ip_health(
        servers, None, 2, ["192.0.2.1", "192.0.2.2", "192.0.2.2"]
    )

    assert set(clients) == {"ru-01", "ru-02", "ch-01"}
    assert list(result["addresses"]) == ["192.0.2.1", "192.0.2.2"]
    assert result["server_id"] == 2 and result["udp_port"] == 443
    assert result["probe_sources"] == ["ru-01", "ru-02"]
    assert probe.call_count == 2
    for call in probe.call_args_list:
        assert call.args[0] is servers[2]
        assert call.args[1] is clients["ch-01"]
    assert servers[2]["host"] == "ch-01.test"
    assert all(client.disconnect.call_count == 1 for client in clients.values())


def test_ru_target_skips_its_own_source(monkeypatch):
    monkeypatch.setattr(health, "_connect", lambda s, f: (NS(disconnect=Mock()), {}))

    def probe(target, ssh, sources, target_ip):
        assert set(sources) == {"ru-02"}
        return {
            "ru-01": {"status": "unknown"},
            "ru-02": {"status": "received", "destination_ip": target_ip},
        }

    monkeypatch.setattr(health, "probe_udp", probe)

    result = health.collect_ip_health(_servers(), None, 0, ["192.0.2.1"])

    assert result["probe_sources"] == ["ru-02"]
    assert set(result["addresses"]["192.0.2.1"]) == {"ru-02"}


def test_missing_or_ambiguous_source_is_unknown(monkeypatch):
    servers = _servers()
    servers[1]["name"] = "another ru-01"
    monkeypatch.setattr(health, "_connect", lambda s, f: (NS(disconnect=Mock()), {}))

    result = health.collect_ip_health(servers, None, 2, ["192.0.2.1"])

    assert all(
        item["status"] == "unknown"
        for item in result["addresses"]["192.0.2.1"].values()
    )


def test_budget_exhaustion_reports_unknown_and_closes_ssh(monkeypatch):
    clients = []

    def connect(server, factory):
        client = NS(disconnect=Mock())
        clients.append(client)
        return client, {}

    monkeypatch.setattr(health, "_connect", connect)
    monkeypatch.setattr(health, "TOTAL_BUDGET_SECONDS", 0)
    probe = Mock()
    monkeypatch.setattr(health, "probe_udp", probe)

    result = health.collect_ip_health(_servers(), None, 2, ["192.0.2.1"])

    probe.assert_not_called()
    assert all(
        item["reason"] == "budget_exceeded"
        for item in result["addresses"]["192.0.2.1"].values()
    )
    assert all(client.disconnect.call_count == 1 for client in clients)


def test_ip_api_authorizes_and_rechecks_instead_of_reusing_node_cache(monkeypatch):
    from fastapi.testclient import TestClient
    import app as panel

    monkeypatch.setattr(panel, "load_data", lambda: {"servers": _servers()})
    monkeypatch.setattr(panel, "_check_admin", lambda request: None)
    collect = Mock(return_value={"server_id": 2, "udp_port": 443, "addresses": {}})
    monkeypatch.setattr(health, "collect_ip_health", collect)
    client = TestClient(panel.app)
    route = "/api/health/servers/2/ips"
    body = {"addresses": ["192.0.2.1", "192.0.2.1"]}

    assert client.post(route, json=body).status_code == 403
    collect.assert_not_called()
    monkeypatch.setattr(panel, "_check_admin", lambda request: True)
    assert client.post(route, json=body).status_code == 200
    assert client.post(route, json=body).status_code == 200
    assert collect.call_count == 2
    assert collect.call_args.args[2:] == (2, ["192.0.2.1"])
    assert collect.call_args.args[1] is panel.get_diagnostic_ssh


@pytest.mark.parametrize(
    "addresses",
    [[], ["example.test"], ["::1"], ["192.0.2.1; command"], ["192.0.2.1"] * 9],
)
def test_api_rejects_non_literal_ipv4_and_unbounded_work(monkeypatch, addresses):
    from fastapi.testclient import TestClient
    import app as panel

    monkeypatch.setattr(panel, "_check_admin", lambda request: True)
    collect = Mock()
    monkeypatch.setattr(health, "collect_ip_health", collect)
    response = TestClient(panel.app).post(
        "/api/health/servers/2/ips", json={"addresses": addresses}
    )

    assert response.status_code == 422
    collect.assert_not_called()


@pytest.mark.parametrize("server_id", [-1, 9])
def test_api_rejects_unknown_target(monkeypatch, server_id):
    from fastapi.testclient import TestClient
    import app as panel

    monkeypatch.setattr(panel, "_check_admin", lambda request: True)
    monkeypatch.setattr(panel, "load_data", lambda: {"servers": _servers()})
    collect = Mock()
    monkeypatch.setattr(health, "collect_ip_health", collect)

    response = TestClient(panel.app).post(
        f"/api/health/servers/{server_id}/ips", json={"addresses": ["192.0.2.1"]}
    )

    assert response.status_code == 404
    collect.assert_not_called()


def test_cancelled_ip_request_keeps_shared_lock_until_capture_finishes(monkeypatch):
    import app as panel

    started, release = threading.Event(), threading.Event()

    def collect(*args):
        started.set()
        assert release.wait(3)
        return {"addresses": {}}

    monkeypatch.setattr(panel, "_check_admin", lambda request: True)
    monkeypatch.setattr(panel, "load_data", lambda: {"servers": _servers()})
    monkeypatch.setattr(health, "collect_ip_health", collect)

    async def scenario():
        monkeypatch.setattr(panel, "_HEALTH_LOCK", asyncio.Lock())
        body = panel.IpHealthRequest(addresses=["192.0.2.1"])
        task = asyncio.create_task(panel.api_server_ip_health(NS(), 2, body))
        assert await asyncio.to_thread(started.wait, 2)
        task.cancel()
        await asyncio.sleep(0)
        assert panel._HEALTH_LOCK.locked()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not panel._HEALTH_LOCK.locked()

    asyncio.run(scenario())


def test_real_receiver_filters_destination_ip_without_binding_awg_port():
    wrong, right = "PVH_wrong_destination", "PVH_right_destination"
    process = subprocess.Popen(
        [
            sys.executable,
            "-u",
            "-c",
            health.RECEIVER,
            "443",
            ".3",
            wrong,
            right,
            "--destination-ip=127.0.0.2",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert json.loads(process.stdout.readline()) == {"ready": True}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(wrong.encode(), ("127.0.0.1", 443))
            sender.sendto(right.encode(), ("127.0.0.2", 443))
        output, errors = process.communicate(timeout=3)
        assert process.returncode == 0, errors
        assert json.loads(output)["received"] == [right]
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
