# Server health API

`GET /api/health/servers` requires the existing admin/support session or Bearer
token. It returns SSH authentication/command results for the panel inventory
and UDP/443 delivery from explicitly named `ru-01` and `ru-02` to the other
servers with an installed AWG protocol in the catalogue.

SSH credentials are consumed inside the panel and never included in the
response. No peer creation, daemon restart, firewall or DNS edits are performed.
Linux/Python 3 are required remotely. Capture runs as root or through
noninteractive `sudo -n`. Its socket-local kernel BPF filter admits only UDP
packets for the probe port with the diagnostic marker prefix; Python then checks
the full random payload. Normal application traffic is not copied into Python.
This socket filter does not change firewall rules or application delivery. It does not write
pcap files or return unrelated traffic. All SSH clients/channels are closed.

Response fields:

- `checked_at`, `duration_ms`, `udp_port`, `probe_sources`, `servers`, `truncated`.
- Each server: panel `server_id`, `name`, `ssh`, `awg`; tested targets also `udp`.
- SSH status: `ok` with elapsed `ms` and actual `peer_ip`, or `failed` with a stable reason code.
- Per-source UDP status: `received`, `not_received`, or `unknown` with a reason
  (`probe_unavailable`, `target_ssh_unavailable`, `capture_unavailable`,
  `send_failed`, `budget_exceeded`).
  Successful senders also include `destination_ip`, resolved on the source node.
  This makes a source-side DNS mismatch visible instead of mislabelling it as
  a blocked port.

One result is shared for 30 seconds and concurrent callers coalesce behind a
lock. SSH uses four workers with connection/banner/authentication deadlines.
At most 24 servers are checked; incomplete inventory is explicitly flagged.
SSH deadlines are explicit for diagnostics; normal provisioning keeps the
pre-existing SSH timeout defaults.
The total UDP work budget is 120 seconds including the initial SSH phase.
Targets are checked sequentially to prevent source-channel contention from
consuming another target's capture window. Each capture lasts at most 6 seconds.

The endpoint deliberately does not claim that a delivered packet proves an
AWG tunnel: ingress capture precedes some firewall processing and does not
authenticate an AWG handshake or check the VPN return path. A silent UDP
service cannot be diagnosed just by a successful send:
[WireGuard protocol](https://www.wireguard.com/protocol/).

Deploy this panel endpoint before enabling the bot's new health screen. The bot
uses its existing AWG panel URL and API token; no SSH secret needs to be copied
to the bot. An older panel returns 404, handled as an unavailable diagnostic.

Tests run only in Docker. `tests/test_server_health.py` includes an actual local
Linux packet-socket/UDP test (default Docker CAP_NET_RAW), along with fake-SSH
checks for failed senders, unavailable capture, authorization and caching.
