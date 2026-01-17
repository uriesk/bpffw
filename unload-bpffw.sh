#!/bin/sh
INTERFACE="$1"
if [ -z "${INTERFACE}" ]; then
  echo "No interface given"
  exit 1
fi

ip link set dev "${INTERFACE}" xdp off 2>/dev/null || true
echo "BPF firewall unloaded on ${INTERFACE}"
