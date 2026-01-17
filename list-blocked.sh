#!/bin/bash
# list blocked IPs

set -e

echo "=== Blocked IPv4 Addresses ==="

# IPv4 blocked IPs
sudo bpftool map dump name rate_limit_v4 -j 2>/dev/null | \
    jq -r '.[] | select(.formatted.value.blocked != 0) | 
           .formatted.key' 2>/dev/null | \
    while read -r key; do
        printf "%d.%d.%d.%d\n" \
            $(( (key >> 24) & 0xFF )) \
            $(( (key >> 16) & 0xFF )) \
            $(( (key >> 8) & 0xFF )) \
            $(( key & 0xFF ))
    done

echo -e "\n=== Blocked IPv6 Prefixes ==="

# IPv6 blocked prefixes
sudo bpftool map dump name rate_limit_v6 -j 2>/dev/null | \
    jq -r '.[] | select(.formatted.value.blocked != 0) | 
           .formatted.key' 2>/dev/null | \
    while read -r key; do
        printf "%04x:%04x:%04x:%04x::/64\n" \
            $(( (key >> 48) & 0xFFFF )) \
            $(( (key >> 32) & 0xFFFF )) \
            $(( (key >> 16) & 0xFFFF )) \
            $(( key & 0xFFFF ))
    done
