#!/bin/sh
# Opt-in workaround for providers whose NDP proxy requires a global source.
set -u
interface=${NDP_INTERFACE:-net0}
interval=${NDP_INTERVAL_SECONDS:-3}

refresh() {
    source_ip=$(ip -6 -o address show dev "$interface" scope global |
        awk '!/ tentative | dadfailed | deprecated / {sub(/\/.*/, "", $4); print $4; exit}')
    gateway=$(ip -6 route show default dev "$interface" |
        awk '$1 == "default" && $2 == "via" {print $3; exit}')
    [ -n "$source_ip" ] && [ -n "$gateway" ] || return 1
    ndisc6 -q -r 1 -w 1000 -s "$source_ip" "$gateway" "$interface" >/dev/null 2>&1
}

if [ "${1:-}" = '--once' ]; then
    refresh
    exit $?
fi

failed=0
while :; do
    if refresh; then
        if [ "$failed" -eq 1 ]; then
            logger -t prosto-ipv6-ndp 'IPv6 gateway neighbor discovery recovered'
        fi
        failed=0
    else
        if [ "$failed" -eq 0 ]; then
            logger -t prosto-ipv6-ndp 'IPv6 gateway neighbor discovery failed; retrying'
        fi
        failed=1
    fi
    sleep "$interval"
done
