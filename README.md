# Simple BPF firewall

Simple bpf program for filtering ports and rate limiting against SYN flood and
volumetric UDP flood attacks.

- rate limits incomming SYN packets per IPv4 or /64 IPv6 subnet
- rate limit incomming UDP packets per IPv4 or /64 IPv6 subnet
- only allow TCP SYN on specific ports
- only allow incomming UDP on specific ports (note that this includes responses)

All values are hardcoded and therefor this programm is just an inspiration, you
can not use it as is and need to adjust it for your needs.

This does not replace **iptables** or **nftables**, since it does not track
connections.

## Installation

Again: This is a filter with hardcoded ports and package-per-seconds limits. It
does need adjustment in *bpffw.c* for your needs, otherwise it kicks you out of
SSH or worse.

1. *Install needed packages on Ubuntu*

```bash
# required for compilation
sudo apt install clang llvm libbpf-dev linux-headers-generic ethtool
# optional for diagnosis
sudo apt install linux-tools-common iftop
# make sure /usr/include/asm points to something usable
ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
```

2. copy or clone repository into `/opt/bpffw`

```bash
cd /opt
git clone [wherever this repo is]
```

3. copy service file into systemd folder

```bash
cp /opt/bpffw/bpffw@.service /etc/systemd/system/
```

4. *Enable service for device eth0*

```bash
sudo systemctl enable bpffw@eth0.service
```

## basic commands for BPF

♣ *Compile BPF filter*

```bash
clang -O2 -g -target bpf -c bpffw.c -o bpffw.o
```

♣ *Load filter onto device eth0*

```bash
sudo ip link set dev eth0 xdp obj bpffw.o
```

♣ *Reload filter*

```bash
sudo ip --force link set dev eth0 xdp obj bpffw.o
```

♣ *Remove filter from device again*

```bash
sudo ip link set dev eth0 xdp off
```

♣ *Check perf messages (only prints a line "ratelimit triggered" whenever an ip gets limited)*

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

♣ *List loaded BPF programms*

```bash
bpftool prog list
```

♣ *Dump all blocked IPs of rate limiting map to json*

```bash
bpftool map dump name rate_limit_v4 -j | jq -r '.[] | select(.formatted.value.blocked != 0)'
bpftool map dump name rate_limit_v6 -j | jq -r '.[] | select(.formatted.value.blocked != 0)'
```

♣ *List all currently blocked IPs*

```bash
./list-blocked.sh
```
