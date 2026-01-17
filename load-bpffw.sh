#!/bin/sh
INTERFACE="$1"
if [ -z "${INTERFACE}" ]; then
  echo "No interface given"
  exit 1
fi
BPF_SOURCE="/opt/bpffw/bpffw.c"
BPF_OBJECT="/opt/bpffw/bpffw.o"

clang -O2 -g -target bpf -c "${BPF_SOURCE}" -o "${BPF_OBJECT}"

if [ $? -ne 0 ]; then
  echo "Could not compile BPF firewall"
  exit 2
fi

# increase ring buffers if neccessary
if [ `ethtool -g "${INTERFACE}" | grep "RX:" | tail -n 1 | sed -e 's/.*\s//g'` -ne 4096 ]; then
  echo "Increase ring buffer of ${INTERFACE}"
  ethtool -G "${INTERFACE}" rx 4096 tx 2084 2>/dev/null || true
fi

# load bpf
echo "Reset XDP BPF of ${INTERFACE}"
ip link set dev "${INTERFACE}" xdp off 2>/dev/null || true
echo "Load XDP BPF firewall into ${INTERFACE}"
ip link set dev "${INTERFACE}" xdp obj "${BPF_OBJECT}"
echo "BPF firewall loaded on ${INTERFACE}"
