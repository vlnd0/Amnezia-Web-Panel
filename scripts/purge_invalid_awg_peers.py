#!/usr/bin/env python3
"""One-shot maintenance: remove invalid-AllowedIPs AWG peers across all panel
nodes and resync the live interface.

Why: the old IP allocator could write peers with an invalid AllowedIPs (e.g.
``10.8.1.257/32``). A single such peer makes ``wg syncconf`` reject the WHOLE
config, so every client added afterwards lands in the config file but never
loads into the live wg interface — the user gets a connect timeout. This tool
drops those poisoned peers and resyncs, reviving the stuck clients.

Run on the panel host (needs data.json + SSH creds):

    python3 scripts/purge_invalid_awg_peers.py            # dry-run, report only
    python3 scripts/purge_invalid_awg_peers.py --apply    # actually fix

If the panel runs in Docker:

    docker exec <panel-container> python3 scripts/purge_invalid_awg_peers.py --apply
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import load_data, get_ssh  # reuse the panel's server list + SSH creds
from managers.awg_manager import AWGManager

AWG_PROTOS = ('awg2', 'awg', 'awg_legacy')


def main():
    apply = '--apply' in sys.argv
    mode = 'APPLY' if apply else 'DRY-RUN (pass --apply to fix)'
    print(f"== Purge invalid AWG peers — {mode} ==\n")

    data = load_data()
    total_invalid = 0
    total_revived = 0

    for server in data.get('servers', []):
        host = server.get('host', '?')
        protos = [p for p in AWG_PROTOS if p in server.get('protocols', {})]
        if not protos:
            continue
        try:
            ssh = get_ssh(server)
            ssh.connect()
        except Exception as e:
            print(f"[{host}] SSH FAILED: {e}")
            continue

        mgr = AWGManager(ssh)
        for proto in protos:
            try:
                invalid = mgr._find_invalid_peers(mgr._get_server_config(proto))
            except Exception as e:
                print(f"[{host}/{proto}] ERROR reading config: {e}")
                continue

            if not invalid:
                print(f"[{host}/{proto}] clean")
                continue

            total_invalid += len(invalid)
            ips = [a for _, a in invalid]
            print(f"[{host}/{proto}] {len(invalid)} invalid peer(s): {ips}")

            if apply:
                try:
                    res = mgr.cleanup_invalid_peers(proto)
                    revived = res['peers_live_after'] - res['peers_live_before']
                    total_revived += max(revived, 0)
                    print(f"    -> purged {len(res['dropped'])}; "
                          f"live peers {res['peers_live_before']} -> {res['peers_live_after']} "
                          f"(+{revived})")
                except Exception as e:
                    print(f"    -> FIX FAILED: {e}")

        ssh.disconnect()

    print(f"\n== Done. invalid peers found: {total_invalid}"
          + (f", clients revived: {total_revived}" if apply else "") + " ==")
    if not apply and total_invalid:
        print("Re-run with --apply to fix.")


if __name__ == '__main__':
    main()
