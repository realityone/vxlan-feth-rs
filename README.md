# vxlan-feth-rs

Userspace VXLAN tunnel for macOS using [feth](https://github.com/realityone/feth-rs) interfaces.

Bridges a macOS feth pair with remote VXLAN peers (typically Linux) over UDP, enabling L2 connectivity across hosts.

```
macOS (this tool)                        Linux
┌──────────────┐                   ┌──────────────┐
│  10.0.0.2/24 │                   │  10.0.0.1/24 │
│    feth100   │                   │   vxlan100   │
│      ↕       │                   │      ↕       │
│    feth101   │                   │    eth0      │
│  (raw I/O)   │                   │ 192.168.50.212│
│      ↕       │                   └──────────────┘
│  UDP :4789   │◄──── VXLAN VNI 100 ────►
│ 192.168.50.x │
└──────────────┘
```

## Build

```sh
cargo build --release
```

## Usage

Run as root (required for feth interface creation):

```sh
sudo ./target/release/vxlan-feth server up vxlan-feth.yaml
```

## Configuration

See [vxlan-feth.yaml](vxlan-feth.yaml) for a full example.

```yaml
server:
  listen: "0.0.0.0:4789"
  vni: 100

interface:
  io_unit: 101
  ip_unit: 100
  address: "10.0.0.2/24"
  mtu: 1450

fdb:
  # Flood entry for broadcast/unknown unicast/multicast
  - mac: "00:00:00:00:00:00"
    dst: "192.168.50.212:4789"
  # Static unicast entry
  - mac: "46:69:54:77:86:17"
    dst: "192.168.50.212:4789"
```

## Linux peer setup

On the remote Linux host (`192.168.50.212`), create a matching VXLAN interface:

```sh
# Create VXLAN interface with the same VNI
ip link add vxlan100 type vxlan \
  id 100 \
  dstport 4789 \
  local 192.168.50.212 \
  nolearning

# Add the macOS host as a remote peer (replace with actual macOS IP)
bridge fdb append 00:00:00:00:00:00 dev vxlan100 dst 192.168.50.100

# Assign inner IP and bring up
ip addr add 10.0.0.1/24 dev vxlan100
ip link set vxlan100 mtu 1450
ip link set vxlan100 up
```

Verify connectivity:

```sh
# From Linux
ping 10.0.0.2

# From macOS
ping 10.0.0.1
```
