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

## AWG3 MTU and dual-stack address allocation

New AWG3 installations default to MTU 1280 for both client exports and the
server interface. Changing AWG3 MTU in the settings persists it in the server
config and applies it without restarting the container. Existing imported
client profiles need a new export to pick up the client MTU. AWG2 and legacy
MTU defaults and settings retain their previous behavior.

New dual-stack peers derive IPv6 from the entire IPv4 host offset. The allocator
reserves the server IPv6, native peers, and disabled peers, so the first client
cannot take the gateway address and crossing an IPv4 octet boundary cannot
reuse IPv6. Existing stored/native assignments stay intact during config
export and re-enabling. An already issued gateway collision requires moving
the server gateway to an unused address in the same IPv6 prefix; deploying
the panel alone does not change existing node addresses or keys.

On some VPS networks the external IPv6 gateway answers multicast neighbor
solicitations but ignores unicast reachability probes. A single successful
HTTPS request can therefore hide recurring several-second IPv6 outages.
Capture the host uplink as well as the AWG interface and repeat DNS/HTTPS
checks over several neighbor reachability cycles. For the affected node,
inspect the successful neighbor advertisements before choosing a workaround.
A static gateway neighbor entry or shorter probe timers may still fail if
the provider needs Neighbor Discovery from the guest's global IPv6 address.
Keep any host-specific repair separate from fleet-wide panel startup actions
and verify it over repeated DNS/HTTPS requests before persisting it.

`scripts/refresh_ipv6_gateway.sh` and
`config/prosto-ipv6-ndp-refresh.service` provide an opt-in workaround that
sends a multicast neighbor solicitation from the host's global IPv6 address
every three seconds. They discover the current address and gateway dynamically
and do not pin the provider MAC, change routes, or restart networking. Install
`ndisc6`, copy the script to `/usr/local/sbin/prosto-ipv6-ndp-refresh` with mode
755, and install the unit under `/etc/systemd/system`. Set `NDP_INTERFACE` to
the affected uplink before enabling it. Test the script with `--once`, then
run `systemctl daemon-reload` and
`systemctl enable --now prosto-ipv6-ndp-refresh.service`. Revert by disabling
the unit. This workaround is not installed automatically by the panel.

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
