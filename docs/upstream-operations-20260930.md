# AWG operational maintenance

Ports detached Docker builds, peer-state backup before reinstall, batched
container/config status reads, native-peer counts and stale connection cleanup
from upstream v1.7.0 and subsequent fixes through 2026-09-30.

Reinstall stops before removing an existing AWG container when peer-state
backup fails. Backups stay under a private /opt/amnezia/backups directory.
They do not automatically restore peers into a newly installed protocol.
Container removal failures preserve panel connections.

Failed Docker status reads raise instead of caching an empty inventory.
Truncated prefetched client tables fall back to a direct read. Only the
confirmed missing-file exit code permits an empty client table; transport
errors abort mutations. Peer/config writes invalidate the prefetched state.

Existing /16 allocation, disabled-peer reservations, IPv6 allocation,
AWG3 MTU 1280, advertised ports, bot client_id, stable server IDs and
isolated diagnostic SSH transports remain intact. Deployment changes only
the panel; it does not reinstall or restart node containers. Keep the
existing DATA_FILE and volume. Connection-flood polling remains opt-in.
