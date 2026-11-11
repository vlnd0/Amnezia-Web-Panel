"""Read-only SSH and one-way UDP reachability checks from two RU vantage points.

No peers, firewall rules or listeners are created. An authenticated SSH command
checks the host; a short packet socket matches only our random UDP payloads, or
empty datagrams from the check-host.net nodes we asked to send them.
Receipt proves delivery to the destination host, NOT an AWG handshake or tunnel.
"""

import ipaddress
import json
import os
import re
import secrets
import shlex
import socket
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone

# ru-01 is an inventory node. check-host.net is a third party, so it is opt-in
# (HEALTH_CHECK_HOST=1).
PROBE_NAMES = ("ru-01", "check-host")
# Domestic nodes are never UDP targets, whether or not they still send probes.
RU_NODES = ("ru-01", "ru-02")
CHECK_HOST_NODES = ("ru1.node.check-host.net", "ru2.node.check-host.net")
UDP_PORT = 443
SSH_TIMEOUT = 5
CAPTURE_SECONDS = 6
MAX_NODES = 24
MAX_IPS = 8
TOTAL_BUDGET_SECONDS = 120

# A SOCK_DGRAM packet socket strips the link header. A socket-local BPF filter
# rejects unrelated traffic in the kernel before the Python diagnostic sees it.
# This is not a firewall filter and cannot alter the application's traffic.
RECEIVER = r"""
import ctypes, json, socket, struct, sys, time
port, seconds = int(sys.argv[1]), float(sys.argv[2])
sources = {arg.split('=', 1)[1] for arg in sys.argv[3:] if arg.startswith('--source-ip=')}
tokens = {arg for arg in sys.argv[3:] if not arg.startswith('--')}
tokens |= {'src:' + ip for ip in sources}
destination_ip = next((arg.split('=', 1)[1] for arg in sys.argv[3:]
                       if arg.startswith('--destination-ip=')), None)
s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]
class Program(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]
# IPv4: UDP, unfragmented, requested destination port, then either a listed
# source address or the payload prefix PVH_. Sources are tested first: their
# datagrams are empty, and an out-of-range payload load rejects the packet.
# Offsets start at the IP header for SOCK_DGRAM; X is the variable IP header size.
A, R = "accept", "reject"
rows = [
    (0x30, 0, 0, 9),           # ldb protocol
    (0x15, 0, R, 17),          # reject unless UDP
    (0x28, 0, 0, 6),           # ldh fragmentation flags/offset
    (0x45, R, 0, 0x3fff),      # reject fragments
    (0xb1, 0, 0, 0),           # X = 4 * IPv4 IHL
    (0x48, 0, 0, 2),           # ldh [X + 2]: UDP destination port
    (0x15, 0, R, port),        # reject other ports
    (0x20, 0, 0, 12),          # ld [12]: source address
] + [
    (0x15, A, 0, struct.unpack("!I", socket.inet_aton(ip))[0]) for ip in sorted(sources)
] + [
    (0x40, 0, 0, 8),           # ld [X + 8]: first four payload bytes
    (0x15, 0, R, 0x5056485f),  # reject non-probe payloads
    (0x06, 0, 0, 128),         # accept only a bounded prefix
    (0x06, 0, 0, 0),           # reject for this diagnostic socket only
]
jump = lambda i, to: {A: len(rows) - 2, R: len(rows) - 1}[to] - i - 1 if to else 0
code = (Filter * len(rows))(*(
    Filter(op, jump(i, jt), jump(i, jf), k) for i, (op, jt, jf, k) in enumerate(rows)
))
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
    if destination_ip is not None and socket.inet_ntoa(p[16:20]) != destination_ip:
        continue
    size = struct.unpack("!H", p[ihl+4:ihl+6])[0]
    token = p[ihl+8:ihl+size].decode("ascii", errors="ignore")
    for token in (token, 'src:' + socket.inet_ntoa(p[12:16])):
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
    for slug in RU_NODES:
        if re.search(r"(?<![a-z0-9])" + re.escape(slug) + r"(?![a-z0-9])", name):
            return slug
    return None


def is_awg_server(server):
    return any(
        info.get("installed")
        for name, info in server.get("protocols", {}).items()
        if name.split("__", 1)[0] in ("awg", "awg2", "awg3", "awg_legacy")
        and isinstance(info, dict)
    )


def _check_host(path):
    request = urllib.request.Request(
        "https://check-host.net/" + path,
        # The API answers 403 to urllib's default agent.
        headers={"Accept": "application/json", "User-Agent": "curl/8"},
    )
    with urllib.request.urlopen(request, timeout=SSH_TIMEOUT) as response:
        return json.load(response)


_CHECK_HOST_IPS = (0.0, None)


def check_host_ips():
    """Addresses of the Moscow check-host nodes, or None when off/unreachable.

    Their datagrams are empty, so the capture can only match them by source.
    """
    global _CHECK_HOST_IPS
    if os.environ.get("HEALTH_CHECK_HOST") != "1":
        return None
    at, ips = _CHECK_HOST_IPS
    if ips is None or time.monotonic() - at > 3600:
        try:
            nodes = _check_host("nodes/hosts")["nodes"]
            ips = tuple(
                str(ipaddress.IPv4Address(nodes[name]["ip"]))
                for name in CHECK_HOST_NODES
            )
        except Exception:
            ips = None
        _CHECK_HOST_IPS = (time.monotonic(), ips)
    return ips


def _send_check_host(ips, destination):
    """Ask both nodes for one UDP datagram; refuse a reply naming other senders."""
    global _CHECK_HOST_IPS
    reply = _check_host(
        f"check-udp?host={destination}:{UDP_PORT}"
        + "".join(f"&node={name}" for name in CHECK_HOST_NODES)
    )
    if reply.get("ok") != 1:
        return {}
    if {node[3] for node in reply.get("nodes", {}).values()} != set(ips):
        _CHECK_HOST_IPS = (0.0, None)  # the nodes moved: re-read them next time
        return {}
    return {"sent": True, "destination_ip": destination}


def _python(script, *args):
    return (
        "python3 -u -c "
        + shlex.quote(script)
        + " "
        + " ".join(shlex.quote(str(arg)) for arg in args)
    )


@contextmanager
def _ssh_deadline(ssh, seconds):
    """Close this diagnostic transport to interrupt Paramiko's unbounded waits.

    Channel.settimeout only bounds I/O, not exec acknowledgement or exit-status
    waits. Closing the owning client wakes both, including channels not yet
    returned by exec_command. These clients are never shared with provisioning.
    """
    expired = threading.Event()

    def close():
        expired.set()
        client = getattr(ssh, "client", None)
        if client is not None:
            client.close()

    timer = threading.Timer(seconds, close)
    timer.daemon = True
    timer.start()
    try:
        yield
    finally:
        timer.cancel()
        timer.join()
    if expired.is_set():
        raise TimeoutError("diagnostic_ssh_deadline")


def _connect(server, ssh_factory):
    started = time.monotonic()
    ssh = None
    try:
        ssh = ssh_factory(server)
        with _ssh_deadline(ssh, SSH_TIMEOUT):
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


def probe_udp(target, target_ssh, sources, *, target_ip=None):
    """sources: name -> (handle or None, lock). The handle is a connected
    SSHManager, or for check-host the addresses its nodes send from.

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
    expected = {name: [token] for name, token in tokens.items()}
    filters = [f"--destination-ip={target_ip}"] if target_ip else []
    if "check-host" in active:
        ips = active["check-host"][0]
        expected["check-host"] = ["src:" + ip for ip in ips]
        filters += [f"--source-ip={ip}" for ip in ips]
        del tokens["check-host"]
    command = _python(RECEIVER, UDP_PORT, CAPTURE_SECONDS, *tokens.values(), *filters)
    if target.get("username") != "root":
        command = "sudo -n -- " + command
    stdout = None
    try:
        with _ssh_deadline(target_ssh, CAPTURE_SECONDS + 2 * SSH_TIMEOUT):
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
                    host = target_ip or target["host"]
                    if name == "check-host":
                        # Resolved here so the reply can name the probed address.
                        return name, _send_check_host(ssh, socket.gethostbyname(host))
                    with lock, _ssh_deadline(ssh, SSH_TIMEOUT):
                        out, _, code = ssh.run_command(
                            _python(SENDER, host, UDP_PORT, tokens[name]),
                            timeout=SSH_TIMEOUT,
                        )
                    result = json.loads(out) if code == 0 else {}
                    return name, result if result.get("sent") is True else {}
                except Exception:
                    return name, {}

            with ThreadPoolExecutor(max_workers=len(active)) as pool:
                sent = dict(pool.map(send, active))
            payload = json.loads(stdout.readline())
            if stdout.channel.recv_exit_status() != 0:
                raise RuntimeError("capture_failed")
            received = payload.get("received")
            if not isinstance(received, list):
                raise RuntimeError("capture_invalid")
        for name in active:
            if all(token in received for token in expected[name]):
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


def collect_ip_health(servers, ssh_factory, server_id, addresses):
    """Reuse the RU probes and target capture for literal pool IPv4 addresses.

    SSH always connects to the configured node, not to each spare IP. Only
    this node and unambiguous RU sources are connected; self probes are skipped.
    """
    if not 0 <= server_id < len(servers) or not is_awg_server(servers[server_id]):
        raise ValueError("invalid_awg_server")
    if not 1 <= len(addresses) <= MAX_IPS:
        raise ValueError("invalid_address_count")
    addresses = list(dict.fromkeys(str(ipaddress.IPv4Address(ip)) for ip in addresses))
    started = time.monotonic()
    target = servers[server_id]
    names = [name for name in PROBE_NAMES if probe_name(target) != name]
    source_indices = {}
    if "ru-01" in names:
        matches = [i for i, s in enumerate(servers) if probe_name(s) == "ru-01"]
        if len(matches) == 1:
            source_indices["ru-01"] = matches[0]
    indices = list(dict.fromkeys([server_id, *source_indices.values()]))
    connections = {}
    try:
        with ThreadPoolExecutor(max_workers=3) as pool:
            checks = list(
                pool.map(lambda i: _connect(servers[i], ssh_factory), indices)
            )
        connections = {index: result[0] for index, result in zip(indices, checks)}
        sources = {
            name: (connections.get(source_indices.get(name)), threading.Lock())
            for name in names
        }
        sources["check-host"] = (check_host_ips(), threading.Lock())
        results = {}
        for ip in addresses:
            if (
                time.monotonic() - started
                > TOTAL_BUDGET_SECONDS - CAPTURE_SECONDS - 2 * SSH_TIMEOUT
            ):
                result = {
                    name: {"status": "unknown", "reason": "budget_exceeded"}
                    for name in names
                }
            else:
                result = probe_udp(
                    target, connections[server_id], sources, target_ip=ip
                )
            results[ip] = {name: result[name] for name in names}
        return {
            "server_id": server_id,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "udp_port": UDP_PORT,
            "addresses": results,
            "probe_sources": names,
            "method": "authenticated_ssh_and_one_way_udp_capture",
        }
    finally:
        for ssh in connections.values():
            if ssh is not None:
                try:
                    ssh.disconnect()
                except Exception:
                    pass


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
        matches = [i for i, s in enumerate(inventory) if probe_name(s) == "ru-01"]
        # Ambiguous names must not silently choose a different probe.
        sources = {
            "ru-01": (
                connections.get(matches[0]) if len(matches) == 1 else None,
                threading.Lock(),
            )
        }
        sources["check-host"] = (check_host_ips(), threading.Lock())

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
                > TOTAL_BUDGET_SECONDS - CAPTURE_SECONDS - 2 * SSH_TIMEOUT
            ):
                rows[index]["udp"] = {
                    name: {"status": "unknown", "reason": "budget_exceeded"}
                    for name in PROBE_NAMES
                }
            else:
                _, rows[index]["udp"] = check_target(index)

        def available(name):
            # A source that could not send to any target is itself down (a
            # check-host limit or outage), not a problem of every node.
            sends = [rows[i].get("udp", {}).get(name, {}) for i in targets]
            return sources[name][0] is not None and not (
                sends and all(item.get("reason") == "send_failed" for item in sends)
            )

        return {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((time.monotonic() - started) * 1000),
            "udp_port": UDP_PORT,
            "probe_sources": [
                {"name": name, "available": available(name)} for name in PROBE_NAMES
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
