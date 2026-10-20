# getdevices

A small C++ utility that scans the local IPv4 subnet for live devices and reports
each device's **IP address**, **MAC address**, and **hostname**.

It works by sending raw ARP requests on the local Ethernet interface and
collecting the ARP replies, then resolving each responding IP to a hostname via
reverse DNS. This is the same technique used by tools like `arp-scan`, and it
only works on the local link (the same broadcast domain) — it cannot scan
across routers.

## How it works

1. **Find a usable interface** — picks the first active, non-loopback IPv4
   Ethernet interface (with a valid netmask and hardware MAC address).
2. **Enumerate the subnet** — computes the network and broadcast addresses
   from the interface IP and netmask.
3. **ARP sweep** — sends ARP requests to every host address in the subnet in
   small batches, draining replies between batches so bursts stay small and
   responses aren't lost.
4. **Collect replies** — records the sender IP and MAC of each ARP reply,
   de-duplicating repeated responses.
5. **Resolve hostnames** — runs reverse DNS lookups concurrently across several
   threads, so slow lookups don't serialize the whole run.
6. **Report** — prints a sorted table of IP address and hostname, plus a total
   count of responding devices.

The machine running the scan is always included in the results.

## Requirements

- Linux (uses `AF_PACKET` raw sockets and `linux/if_packet.h`)
- A C++17 compiler (e.g. `g++`)
- `make`
- For `install` / `uninstall`: root privileges
- For `install`: the `setcap` tool, provided by `libcap` on most distributions

### Debian / Raspbian

```sh
sudo apt-get install build-essential libcap2-bin
```

### Fedora

```sh
sudo dnf install gcc-c++ make libcap
```

Alternatively, install the full development toolchain group:

```sh
sudo dnf groupinstall "Development Tools"
```

### Arch Linux

```sh
sudo pacman -S base-devel libcap
```

## Building

```sh
make
```

This produces the `getdevices` binary in the current directory.

Build options can be overridden on the command line, for example:

```sh
make CXX=clang++ CXXFLAGS="-O2 -std=c++20 -pthread"
```

## Installing

```sh
sudo make install
```

This installs the binary to `/usr/local/bin/getdevices` and grants it the
`cap_net_raw` capability:

```sh
setcap cap_net_raw+ep /usr/local/bin/getdevices
```

The capability lets the program open raw packet sockets **without** needing to
be run as `root`, so after installing you can run it as an ordinary user:

```sh
getdevices
```

To install to a different prefix:

```sh
sudo make install PREFIX=/usr
```

You can verify the capability was applied with:

```sh
getcap /usr/local/bin/getdevices
# -> /usr/local/bin/getdevices cap_net_raw=ep
```

## Running

```sh
getdevices
```

Example output:

```
Using interface: eth0 (192.168.1.42), MAC aa:bb:cc:dd:ee:ff
Scanning 192.168.1.0 through 192.168.1.255 on eth0 (254 addresses)...
192.168.1.1     aa:bb:cc:00:11:22
192.168.1.42    aa:bb:cc:dd:ee:ff
192.168.1.17    aa:bb:cc:33:44:55

Resolving hostnames...

Final results:
IP address      Hostname
192.168.1.1     router.lan
192.168.1.17    printer.lan
192.168.1.42    myhost.lan

Found 3 responding devices.
```

### If you haven't run `make install`

You can run the binary directly from the build directory, but it needs
`CAP_NET_RAW`, so run it with `sudo`:

```sh
sudo ./getdevices
```

## Uninstalling

```sh
sudo make uninstall
```

This removes `/usr/local/bin/getdevices`. The capability lives in the file's
extended attributes, so removing the file removes it as well.

## Cleaning build artifacts

```sh
make clean
```

Removes the `getdevices` binary and any `.o` files from the build directory.

## Limitations

- **Local link only** — ARP is not routed, so only hosts on the same subnet as
  the scanning interface will respond.
- **IPv4 only** — IPv6 neighbors are not scanned.
- **Subnet size cap** — subnets larger than 65534 host addresses are rejected
  to avoid pathological run times.
- **Hostname resolution depends on DNS/mDNS** — devices without PTR records
  show as `-`. Reverse lookups may be slow on networks with no local DNS; the
  program resolves them concurrently but does not time them out individually
  beyond the system resolver's own timeouts.
- **Filesystems without xattr support** — if `setcap` fails on the target
  filesystem, the installed binary will still require `sudo` to run.

