import asyncio
import io
import json
import socket
import subprocess
import sys
import threading
from types import SimpleNamespace as NS
from unittest.mock import Mock

from managers import server_health as health


def test_normal_ssh_connections_keep_existing_timeout_defaults(monkeypatch):
    import paramiko

    from managers.ssh_manager import SSHManager

    client = Mock()
    monkeypatch.setattr(paramiko, "SSHClient", lambda: client)
    manager = SSHManager("example.test", 22, "root")
    manager.connect()
    kwargs = client.connect.call_args.kwargs
    assert kwargs["timeout"] == 15
    assert "auth_timeout" not in kwargs
    assert "banner_timeout" not in kwargs

    manager.connect(timeout=5)
    kwargs = client.connect.call_args.kwargs
    assert kwargs["timeout"] == kwargs["auth_timeout"] == kwargs["banner_timeout"] == 5


def test_cancelled_http_request_keeps_lock_until_ssh_worker_finishes(monkeypatch):
    import app as panel

    started, release = threading.Event(), threading.Event()

    def collect(*args):
        started.set()
        assert release.wait(3)
        return {"servers": []}

    monkeypatch.setattr(panel, "_HEALTH_CACHE", None)
    monkeypatch.setattr(panel, "_check_admin", lambda request: {"role": "admin"})
    monkeypatch.setattr(panel, "load_data", lambda: {"servers": []})
    monkeypatch.setattr(health, "collect_health", collect)

    async def scenario():
        monkeypatch.setattr(panel, "_HEALTH_LOCK", asyncio.Lock())
        task = asyncio.create_task(panel.api_server_health(NS()))
        assert await asyncio.to_thread(started.wait, 2)
        task.cancel()
        await asyncio.sleep(0)
        assert panel._HEALTH_LOCK.locked()
        release.set()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert not panel._HEALTH_LOCK.locked()

    asyncio.run(scenario())


def test_health_api_authorization_and_cached_read(monkeypatch):
    from fastapi.testclient import TestClient

    import app as panel

    monkeypatch.setattr(panel, "_HEALTH_CACHE", None)
    monkeypatch.setattr(panel, "_HEALTH_CACHE_AT", 0.0)
    monkeypatch.setattr(panel, "_check_admin", lambda request: None)
    collect = Mock(
        return_value={"servers": [], "checked_at": "2026-09-19T00:00:00+00:00"}
    )
    monkeypatch.setattr(health, "collect_health", collect)
    monkeypatch.setattr(panel, "load_data", lambda: {"servers": []})
    client = TestClient(panel.app)
    assert client.get("/api/health/servers").status_code == 403
    collect.assert_not_called()
    monkeypatch.setattr(panel, "_check_admin", lambda request: {"role": "admin"})
    assert client.get("/api/health/servers").status_code == 200
    assert client.get("/api/health/servers").status_code == 200
    collect.assert_called_once()


def target_ssh(lines):
    stream = io.StringIO("\n".join(json.dumps(line) for line in lines))
    stream.channel = NS(settimeout=Mock(), recv_exit_status=lambda: 0, close=Mock())
    return NS(
        client=NS(
            exec_command=Mock(return_value=(NS(close=Mock()), stream, io.StringIO()))
        )
    )


def test_missing_probes_are_unknown():
    result = health.probe_udp({"host": "test", "username": "root"}, None, {})
    assert all(item["status"] == "unknown" for item in result.values())
    assert all(item["reason"] == "probe_unavailable" for item in result.values())


def test_receiver_ready_precedes_sending_and_only_matching_token_passes(monkeypatch):
    monkeypatch.setattr(health.secrets, "token_hex", lambda _: "fixed")
    target = target_ssh([{"ready": True}, {"received": ["PVH_fixed"]}])
    sender = NS(
        run_command=Mock(
            return_value=('{"sent": true, "destination_ip": "192.0.2.1"}', "", 0)
        )
    )
    result = health.probe_udp(
        {"host": "test", "username": "root"},
        target,
        {"ru-01": (sender, threading.Lock())},
    )
    assert result["ru-01"]["status"] == "received"
    assert result["ru-01"]["destination_ip"] == "192.0.2.1"
    assert result["ru-02"]["status"] == "unknown"
    assert sender.run_command.call_count == 1


def test_missing_packet_after_successful_sender_is_not_received():
    target = target_ssh([{"ready": True}, {"received": []}])
    sender = NS(
        run_command=Mock(
            return_value=('{"sent": true, "destination_ip": "192.0.2.1"}', "", 0)
        )
    )
    result = health.probe_udp(
        {"host": "test", "username": "root"},
        target,
        {"ru-01": (sender, threading.Lock())},
    )
    assert result["ru-01"]["status"] == "not_received"


def test_sender_failure_is_unknown_not_a_blocked_port():
    target = target_ssh([{"ready": True}, {"received": []}])
    sender = NS(run_command=Mock(return_value=("", "error", 1)))
    result = health.probe_udp(
        {"host": "test", "username": "root"},
        target,
        {"ru-01": (sender, threading.Lock())},
    )
    assert result["ru-01"] == {"status": "unknown", "reason": "send_failed"}


def test_capture_failure_does_not_send_or_claim_network_failure():
    target = target_ssh([{"ready": False}])
    sender = NS(run_command=Mock())
    result = health.probe_udp(
        {"host": "test", "username": "super"},
        target,
        {"ru-01": (sender, threading.Lock())},
    )
    assert result["ru-01"]["reason"] == "capture_unavailable"
    sender.run_command.assert_not_called()
    assert target.client.exec_command.call_args.args[0].startswith("sudo -n -- ")


def test_probe_names_are_explicit_and_not_substring_matches():
    assert health.probe_name({"name": "🇷🇺 pv-ru-01"}) == "ru-01"
    assert health.probe_name({"name": "ru-010"}) is None
    assert health.probe_name({"name": "somewhere", "host": "ru-01.example"}) is None


def test_ssh_failure_closes_connection_and_hides_error_details():
    ssh = NS(connect=Mock(side_effect=RuntimeError("secret text")), disconnect=Mock())
    result, status = health._connect({}, lambda _: ssh)
    assert result is None and status["status"] == "failed"
    assert "secret" not in json.dumps(status)
    ssh.disconnect.assert_called_once()


def test_collector_checks_sources_but_sends_only_to_other_awg_nodes(monkeypatch):
    clients = []

    def connect(server, factory):
        client = NS(disconnect=Mock())
        clients.append(client)
        return client, {"status": "ok", "ms": 1}

    monkeypatch.setattr(health, "_connect", connect)
    probe = Mock(return_value={"ru-01": {"status": "received"}})
    monkeypatch.setattr(health, "probe_udp", probe)
    servers = [
        {"name": n, "host": "test", "protocols": {"awg2": {"installed": True}}}
        for n in ("ru-01", "ru-02", "ch-01")
    ]
    result = health.collect_health(servers, None)
    assert len(result["servers"]) == 3
    assert result["probe_sources"] == [
        {"name": n, "available": True} for n in health.PROBE_NAMES
    ]
    probe.assert_called_once()
    assert probe.call_args.args[0]["name"] == "ch-01"
    assert all(c.disconnect.call_count == 1 for c in clients)


def test_real_packet_receiver_matches_only_probe_payload():
    # Run in Docker/Linux with its default CAP_NET_RAW; no external networking.
    token = "PVH_local_test"
    process = subprocess.Popen(
        [sys.executable, "-u", "-c", health.RECEIVER, "443", "2", token],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert json.loads(process.stdout.readline()) == {"ready": True}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"unrelated-payload", ("127.0.0.1", 443))
            sender.sendto(token.encode(), ("127.0.0.1", 443))
        output, errors = process.communicate(timeout=4)
        assert process.returncode == 0, errors
        assert json.loads(output)["received"] == [token]
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def test_diagnostic_filter_does_not_intercept_application_datagrams():
    # A normal UDP application must continue receiving all its traffic while
    # the diagnostic socket listens. This exercises the real Linux filter.
    token = "PVH_app_coexistence"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as application:
        application.bind(("127.0.0.1", 443))
        application.settimeout(2)
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", health.RECEIVER, "443", "2", token],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert json.loads(process.stdout.readline()) == {"ready": True}
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                for index in range(100):
                    payload = f"ordinary-application-data-{index}".encode()
                    sender.sendto(payload, ("127.0.0.1", 443))
                    assert application.recv(512) == payload
                sender.sendto(token.encode(), ("127.0.0.1", 443))
                assert application.recv(512) == token.encode()
            output, errors = process.communicate(timeout=4)
            assert process.returncode == 0, errors
            assert json.loads(output)["received"] == [token]
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
