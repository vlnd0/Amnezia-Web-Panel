"""Real Paramiko waits must terminate even without a remote exit-status/exec ACK."""

import asyncio
import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace as NS
from unittest.mock import Mock

import paramiko
import pytest

from managers import server_health as health
from managers.ssh_manager import SSHManager


@pytest.fixture
def stalled_channel():
    channel = paramiko.Channel(1)
    channel.active = True
    channel.transport = Mock()
    yield channel
    channel.close()


def stalled_ssh(channel):
    manager = SSHManager("example.test", 22, "root")
    manager.connect = Mock()
    stream = NS(channel=channel, read=lambda: b"")
    manager.client = NS(
        exec_command=Mock(return_value=(NS(close=Mock()), stream, stream)),
        close=channel.close,
    )
    return manager


def bounded_result(channel, fn, *args):
    # A failing regression must not hang pytest's executor shutdown.
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(fn, *args)
        try:
            return future.result(timeout=2)
        finally:
            channel.close()


def test_ssh_exit_status_timeout_closes_transport(monkeypatch, stalled_channel):
    monkeypatch.setattr(health, "SSH_TIMEOUT", 0.05)
    ssh = stalled_ssh(stalled_channel)
    client, status = bounded_result(stalled_channel, health._connect, {}, lambda _: ssh)
    assert client is None
    assert status["status"] == "failed"
    assert stalled_channel.closed
    assert ssh.client is None


def test_sender_exit_status_timeout_is_unknown(monkeypatch, stalled_channel):
    monkeypatch.setattr(health, "SSH_TIMEOUT", 0.05)
    sender = stalled_ssh(stalled_channel)
    stream = io.StringIO('{"ready": true}\n{"received": []}\n')
    stream.channel = NS(settimeout=Mock(), recv_exit_status=lambda: 0, close=Mock())
    target = NS(client=NS(exec_command=Mock(return_value=(Mock(), stream, Mock()))))
    result = bounded_result(
        stalled_channel,
        health.probe_udp,
        {"host": "example.test", "username": "root"},
        target,
        {"ru-01": (sender, threading.Lock())},
    )
    assert result["ru-01"]["reason"] == "send_failed"
    assert stalled_channel.closed


@pytest.mark.parametrize("wait_for_ack", [False, True])
def test_receiver_ack_and_exit_status_are_bounded(
    monkeypatch, stalled_channel, wait_for_ack
):
    monkeypatch.setattr(health, "SSH_TIMEOUT", 0.05)
    monkeypatch.setattr(health, "CAPTURE_SECONDS", 0.05)
    target = stalled_ssh(stalled_channel)
    stream = io.StringIO('{"ready": true}\n{"received": []}\n')
    stream.channel = stalled_channel

    def execute(*args, **kwargs):
        if wait_for_ack:
            # The actual Paramiko exec-ack wait also ignores settimeout.
            stalled_channel._wait_for_event()
        return Mock(), stream, Mock()

    target.client.exec_command = execute
    sender = NS(run_command=Mock(return_value=(json.dumps({"sent": True}), "", 0)))
    result = bounded_result(
        stalled_channel,
        health.probe_udp,
        {"host": "example.test", "username": "root"},
        target,
        {"ru-01": (sender, threading.Lock())},
    )
    assert result["ru-01"]["reason"] == "capture_unavailable"
    assert stalled_channel.closed


def test_health_lock_is_reusable_after_stalled_ssh(monkeypatch, stalled_channel):
    import app as panel

    monkeypatch.setattr(health, "SSH_TIMEOUT", 0.05)
    monkeypatch.setattr(panel, "_HEALTH_CACHE", None)
    monkeypatch.setattr(panel, "_check_admin", lambda _: True)
    monkeypatch.setattr(panel, "load_data", lambda: {"servers": [{"name": "test"}]})
    monkeypatch.setattr(panel, "get_ssh", lambda _: stalled_ssh(stalled_channel))

    async def scenario():
        monkeypatch.setattr(panel, "_HEALTH_LOCK", asyncio.Lock())
        # Backup release only to bound a regression's thread cleanup.
        release = threading.Timer(2, stalled_channel.close)
        release.start()
        try:
            result = await asyncio.wait_for(panel.api_server_health(NS()), timeout=1)
            assert result["servers"][0]["ssh"]["status"] == "failed"
            assert not panel._HEALTH_LOCK.locked()
            assert await panel.api_server_health(NS()) == result
        finally:
            release.cancel()
            stalled_channel.close()

    asyncio.run(scenario())
