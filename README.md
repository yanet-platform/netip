# netip

A Rust library for working with IP networks and MAC addresses.

Key feature: support for **non-contiguous subnet masks**, e.g. `192.168.0.0/255.255.0.255`.

Zero runtime dependencies. Rust edition 2024.

## Types

| Type            | Description                                                       |
| --------------- | -----------                                                       |
| `Ipv4Network`   | IPv4 network: (address, mask) pair, supports non-contiguous masks |
| `Ipv6Network`   | IPv6 network: (address, mask) pair, supports non-contiguous masks |
| `IpNetwork`     | Enum over `Ipv4Network` / `Ipv6Network`                           |
| `Contiguous<T>` | Newtype wrapper that enforces contiguous masks at parse time      |
| `MacAddr`       | MAC address (EUI-48), stored as the lower 48 bits of a `u64`      |

## Build and test

```sh
cargo build
cargo clippy
cargo test
cargo bench
```
