#!/usr/bin/env python3
"""One-shot maintenance: widen the AWG tunnel interface's on-link subnet to the
client pool across all panel nodes.

Why: the client pool was widened from /24 to /16 (so a node can host tens of
thousands of clients), and both the IP allocator and the NAT masquerade follow
the wider /16. But on nodes first installed with a /24 ``Address`` the tunnel
interface (awg0) is still brought up on a /24 on-link subnet. Peers added live
via ``wg syncconf`` (which writes no kernel route) whose IP falls outside that
/24 then have no return route to awg0: the client connects and *uploads* fine
(egress NAT is /16) but *receives nothing* — "connects, no internet". This tool
rewrites the server ``Address`` to the pool prefix and applies it live (no
session drop), so every current and future peer is reachable and the fix
survives container restarts.

Idempotent: nodes already on the pool prefix (fresh /16 installs) are a no-op.

Run on the panel host (needs data.json + SSH creds):

    python3 scripts/heal_awg_onlink.py            # dry-run, report only
    python3 scripts/heal_awg_onlink.py --apply    # actually fix

If the panel runs in Docker:

    docker exec <panel-container> python3 scripts/heal_awg_onlink.py --apply
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
    print(f"== Heal AWG tunnel on-link subnet — {mode} ==\n")

    data = load_data()
    total_widen = 0
    total_done = 0

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
                res = mgr.heal_tunnel_onlink(proto, apply=apply)
            except Exception as e:
                print(f"[{host}/{proto}] ERROR: {e}")
                continue

            status = res.get('status')
            if status == 'noop':
                print(f"[{host}/{proto}] ok — on-link /{res['from']} already covers pool")
            elif status == 'unknown':
                print(f"[{host}/{proto}] SKIP — could not read tunnel Address")
            elif status == 'widen':  # dry-run: needs fixing
                total_widen += 1
                print(f"[{host}/{proto}] NEEDS FIX — {res['ip']}/{res['from']} "
                      f"-> /{res['to']}")
            elif status == 'widened':  # applied
                total_widen += 1
                total_done += 1
                print(f"[{host}/{proto}] FIXED — {res['ip']}/{res['from']} "
                      f"-> /{res['to']} (live + persisted)")

        ssh.disconnect()

    print(f"\n== Done. nodes needing widen: {total_widen}"
          + (f", fixed: {total_done}" if apply else "") + " ==")
    if not apply and total_widen:
        print("Re-run with --apply to fix.")


if __name__ == '__main__':
    main()
