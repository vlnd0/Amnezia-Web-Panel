# Upstream 1.6.7 and AWG 3.1 rollout

This fork integrates upstream `02c1182284d0f5a7b9d5f034a15c77a9fb966c00`
(v1.6.7), retaining the existing bot's AWG2 contract. Deploying this PR does
not require reinstalling protocols or regenerating existing client keys.

## Compatibility retained

- `/16` allocation, disabled-peer IP reservations, legacy NAT/on-link repair,
  invalid-peer cleanup, and advertised ports with legacy-port redirects.
- `POST /api/users/{id}/connections/add` returns `client_id`, `config` and
  `vpn_link`. Existing Bearer tokens and session authentication remain valid
  when the same data file and `SECRET_KEY` are used.
- Full AWG/WireGuard/Telemt manager operations are serialized per SSH session;
  different nodes remain concurrent. Repeated connect calls keep an active
  pooled transport. Failed metadata reads abort instead of overwriting clients.
- Retrying enable after a failed `syncconf` reapplies the persisted peer before
  reporting success. This prevents renewal from leaving a paid peer disabled.
- Server-health diagnostics use separate SSH transports with bounded connect
  and command lifetimes. Their timeouts cannot close a provisioning transport;
  diagnostics also recognize AWG3 instances.
- Numeric server IDs remain list indices. Reordering/deleting servers is
  blocked by default (`PRESERVE_SERVER_IDS=on`); add new nodes at the end.
  Do not disable this protection while the bot uses numeric IDs.
- New connection-flood polling is opt-in (`AWG_CONN_MONITOR=off` by default).
  Existing traffic/expiry and Remnawave synchronization settings still apply.
- Installing AWG3 on a node already registered with legacy AWG/exit services
  is rejected. Install it on a fresh host; its DKMS/firewall/Docker tuning can
  change host-wide state and must not be run on an existing production node.

## Staging and deployment

1. Back up the panel state file and record its actual mounted path, existing
   image digest and `SECRET_KEY` outside Git. Preserve the server list order,
   user IDs, token hashes and `user_connections`. Also back up each node's
   `clientsTable` and AWG config through the existing operational process.
2. Build this fork, not `prvtpro/amnezia-panel:latest`. The bundled Compose
   builds `amnezia-panel:fork-local`. Its `DATA_FILE=/app/data/data.json` must
   point at the existing data, not an empty new volume. Existing deployments
   using `/app/data.json` or a symlink must keep their actual mount/volume.
3. Test a separate panel with synthetic state and no production SSH keys,
   tokens, Telegram bot or Remnawave credentials. Startup creates background
   jobs; a second panel must never manage production nodes during validation.
4. Run the compatibility/API tests and use one fresh test node to install
   `awg3`. Verify actual client import, handshake, traffic, enable/disable and
   persistence after container restart with a client that supports AWG 3.1.
5. Switch the panel in a controlled maintenance window. Existing VPN tunnels
   are served by node containers independently of the panel; bot provisioning
   needs the panel API available. Drain in-flight mutations before switching;
   run only one panel writer. Do not restart existing node containers.
6. Check bot issuance/reissue/renewal/revocation on an AWG2 test peer and verify
   existing server IDs, keys, endpoints and peer counts. Introduce AWG3 nodes
   to the bot only after its separate protocol-aware PR and migration ship.

Rollback uses the previous panel image and saved panel state while the old
AWG2 nodes continue running. Do not allow AWG3 issuance until the new panel
and bot have been validated together; the old panel cannot manage AWG3 peers.

No deployment, production migration or real-node installation is performed
by this PR. Unit/API tests use fake transports; an actual AWG3 handshake is a
separate rollout gate.

## Verification

Use Docker for all Python checks:

```sh
docker build -f Dockerfile.test -t amnezia-panel-tests .
docker run --rm --network none amnezia-panel-tests
```

The default test image uses production's Python 3.14. CI also tests Python 3.11
with `--build-arg PYTHON_VERSION=3.11`. It runs undefined-name checks and pytest, including
upstream's unittest suites and the fork's existing on-link regressions. Browser
E2E needs a running disposable panel and Playwright browser dependencies; it is
separate from these offline tests.
