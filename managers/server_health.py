"""Read-only SSH and one-way UDP reachability checks from RU probe nodes.

No peers, firewall rules or listeners are created. An authenticated SSH command
checks the host; a short packet socket matches only our random UDP payloads.
Receipt proves delivery to the destination host, NOT an AWG handshake or tunnel.
"""

import json
import re
import secrets
import shlex
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

PROBE_NAMES = ("ru-01", "ru-02")
UDP_PORT = 443
SSH_TIMEOUT = 5
CAPTURE_SECONDS = 6
MAX_NODES = 24
TOTAL_BUDGET_SECONDS = 120

# A SOCK_DGRAM packet socket strips the link header. A socket-local BPF filter
# rejects unrelated traffic in the kernel before the Python diagnostic sees it.
# This is not a firewall filter and cannot alter the application's traffic.
RECEIVER = r"""
import ctypes, json, socket, struct, sys, time
port, seconds = int(sys.argv[1]), float(sys.argv[2])
tokens = set(sys.argv[3:])
s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]
class Program(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]
# IPv4: UDP, unfragmented, requested destination port and payload prefix PVH_.
# Offsets start at the IP header for SOCK_DGRAM; X is the variable IP header size.
code = (Filter * 11)(
    Filter(0x30, 0, 0, 9),          # ldb protocol
    Filter(0x15, 0, 8, 17),         # reject unless UDP
    Filter(0x28, 0, 0, 6),          # ldh fragmentation flags/offset
    Filter(0x45, 6, 0, 0x3fff),     # reject fragments
    Filter(0xb1, 0, 0, 0),          # X = 4 * IPv4 IHL
    Filter(0x48, 0, 0, 2),          # ldh [X + 2]: UDP destination port
    Filter(0x15, 0, 3, port),       # reject other ports
    Filter(0x40, 0, 0, 8),          # ld [X + 8]: first four payload bytes
    Filter(0x15, 0, 1, 0x5056485f), # reject non-probe payloads
    Filter(0x06, 0, 0, 128),        # accept only a bounded prefix
    Filter(0x06, 0, 0, 0),          # reject for this diagnostic socket only
)
program = Program(len(code), code)
s.setsockopt(socket.SOL_SOCKET, 26, bytes(program))  # Linux SO_ATTACH_FILTER
s.settimeout(.25)
print(json.dumps({"ready": True}), flush=True)
seen = set()
end = time.monotonic() + seconds
while time.monotonic() < end and seen != tokens:
    try:
        p, meta = s.recvfrom(128)
    except socket.timeout:
        continue
    if meta[2] == socket.PACKET_OUTGOING or len(p) < 28 or p[0] >> 4 != 4 or p[9] != 17:
        continue
    ihl = (p[0] & 15) * 4
    if ihl < 20 or len(p) < ihl + 8 or struct.unpack("!H", p[ihl+2:ihl+4])[0] != port:
        continue
    # Reject fragmented traffic rather than matching an incomplete datagram.
    if struct.unpack("!H", p[6:8])[0] & 0x3fff:
        continue
    size = struct.unpack("!H", p[ihl+4:ihl+6])[0]
    token = p[ihl+8:ihl+size].decode("ascii", errors="ignore")
    if token in tokens:
        seen.add(token)
s.close()
print(json.dumps({"received": sorted(seen)}), flush=True)
"""

SENDER = r"""
import json, socket, sys, time
host, port, token = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode("ascii")
address = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(2)
    for _ in range(3):
        s.sendto(token, address)
        time.sleep(.1)
print(json.dumps({"sent": True, "destination_ip": address[0]}), flush=True)
"""


def probe_name(server):
    """Match explicit RU node names, never assume mutable panel list indices."""
    name = str(server.get("name", "")).lower()
    for slug in PROBE_NAMES:
        if re.search(r"(?<![a-z0-9])" + re.escape(slug) + r"(?![a-z0-9])", name):
            return slug
    return None


def is_awg_server(server):
    return any(
        info.get("installed")
        for name, info in server.get("protocols", {}).items()
        if name in ("awg", "awg2", "awg_legacy") and isinstance(info, dict)
    )


def _python(script, *args):
    return (
        "python3 -u -c "
        + shlex.quote(script)
        + " "
        + " ".join(shlex.quote(str(arg)) for arg in args)
    )


def _connect(server, ssh_factory):
    started = time.monotonic()
    ssh = None
    try:
        ssh = ssh_factory(server)
        ssh.connect(timeout=SSH_TIMEOUT)
        out, _, code = ssh.run_command("printf HEALTH_SSH_OK", timeout=SSH_TIMEOUT)
        if code != 0 or out.strip() != "HEALTH_SSH_OK":
            raise RuntimeError("command_failed")
        return ssh, {
            "status": "ok",
            "ms": round((time.monotonic() - started) * 1000),
            "peer_ip": ssh.client.get_transport().getpeername()[0],
        }
    except Exception:
        # SSH exception strings may contain hostnames, paths or key details.
        if ssh is not None:
            try:
                ssh.disconnect()
            except Exception:
                pass
        return None, {"status": "failed", "reason": "ssh_auth_or_command_failed"}


def probe_udp(target, target_ssh, sources):
    """sources: name -> (connected SSHManager or None, per-transport lock).

    The receiver's READY marker is read before senders start. A missing probe or
    failed sender/capture is UNKNOWN, never a claim that the route is blocked.
    """
    results = {
        name: {"status": "unknown", "reason": "probe_unavailable"}
        for name in PROBE_NAMES
    }
    active = {name: item for name, item in sources.items() if item[0] is not None}
    if not active:
        return results
    if target_ssh is None:
        return {
            name: {"status": "unknown", "reason": "target_ssh_unavailable"}
            for name in PROBE_NAMES
        }
    tokens = {name: "PVH_" + secrets.token_hex(16) for name in active}
    command = _python(RECEIVER, UDP_PORT, CAPTURE_SECONDS, *tokens.values())
    if target.get("username") != "root":
        command = "sudo -n -- " + command
    stdout = None
    try:
        stdin, stdout, stderr = target_ssh.client.exec_command(
            command, timeout=SSH_TIMEOUT
        )
        stdin.close()
        stdout.channel.settimeout(CAPTURE_SECONDS + SSH_TIMEOUT)
        if json.loads(stdout.readline()).get("ready") is not True:
            raise RuntimeError("capture_not_ready")

        def send(name):
            ssh, lock = active[name]
            try:
                with lock:
                    out, _, code = ssh.run_command(
                        _python(SENDER, target["host"], UDP_PORT, tokens[name]),
                        timeout=SSH_TIMEOUT,
                    )
                result = json.loads(out) if code == 0 else {}
                return name, result if result.get("sent") is True else {}
            except Exception:
                return name, {}

        with ThreadPoolExecutor(max_workers=2) as pool:
            sent = dict(pool.map(send, active))
        payload = json.loads(stdout.readline())
        if stdout.channel.recv_exit_status() != 0:
            raise RuntimeError("capture_failed")
        received = payload.get("received")
        if not isinstance(received, list):
            raise RuntimeError("capture_invalid")
        for name in active:
            if tokens[name] in received:
                results[name] = {"status": "received"}
            elif not sent[name]:
                results[name] = {"status": "unknown", "reason": "send_failed"}
            else:
                results[name] = {"status": "not_received"}
            if sent[name].get("destination_ip"):
                results[name]["destination_ip"] = sent[name]["destination_ip"]
    except Exception:
        for name in active:
            results[name] = {"status": "unknown", "reason": "capture_unavailable"}
    finally:
        if stdout is not None:
            stdout.channel.close()
    return results


def collect_health(servers, ssh_factory):
    """Bounded work, no config writes; SSH clients always close on completion."""
    started = time.monotonic()
    inventory = list(servers[:MAX_NODES])
    connections = {}
    rows = []
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            checks = list(pool.map(lambda s: _connect(s, ssh_factory), inventory))
        for index, (server, (ssh, status)) in enumerate(zip(inventory, checks)):
            connections[index] = ssh
            rows.append(
                {
                    "server_id": index,
                    "name": server.get("name") or server.get("host"),
                    "ssh": status,
                    "awg": is_awg_server(server),
                }
            )
        sources = {}
        for name in PROBE_NAMES:
            matches = [i for i, s in enumerate(inventory) if probe_name(s) == name]
            # Ambiguous names must not silently choose a different probe.
            sources[name] = (
                connections.get(matches[0]) if len(matches) == 1 else None,
                threading.Lock(),
            )

        def check_target(index):
            return index, probe_udp(inventory[index], connections[index], sources)

        targets = [
            i for i, s in enumerate(inventory) if is_awg_server(s) and not probe_name(s)
        ]
        # One target at a time ensures sender contention cannot consume the
        # capture window and turn a queued check into a false network failure.
        for index in targets:
            if (
                time.monotonic() - started
                > TOTAL_BUDGET_SECONDS - CAPTURE_SECONDS - SSH_TIMEOUT
            ):
                rows[index]["udp"] = {
                    name: {"status": "unknown", "reason": "budget_exceeded"}
                    for name in PROBE_NAMES
                }
            else:
                _, rows[index]["udp"] = check_target(index)
        return {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((time.monotonic() - started) * 1000),
            "udp_port": UDP_PORT,
            "probe_sources": [
                {"name": name, "available": sources[name][0] is not None}
                for name in PROBE_NAMES
            ],
            "servers": rows,
            "truncated": len(servers) > MAX_NODES,
            "method": "authenticated_ssh_and_one_way_udp_capture",
        }
    finally:
        for ssh in connections.values():
            if ssh is not None:
                try:
                    ssh.disconnect()
                except Exception:
                    pass
