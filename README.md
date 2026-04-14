# netip

[![crates.io](https://img.shields.io/crates/v/netip.svg)](https://crates.io/crates/netip)
[![docs.rs](https://docs.rs/netip/badge.svg)](https://docs.rs/netip)
[![License](https://img.shields.io/crates/l/netip.svg)](LICENSE)

**Zero-dependency** Rust library for IPv4/IPv6 networks and MAC addresses — with first-class support for **non-contiguous subnet masks**.

## Why netip?

Most networking libraries assume subnet masks are contiguous (a run of 1-bits followed by 0-bits, like `255.255.255.0`). Real-world network hardware — routers, firewalls, packet classifiers — often uses **non-contiguous masks** like `255.0.255.0` or even `170.85.170.85` to match on arbitrary bit patterns.

`netip` treats every network as a `(address, mask)` pair where the mask can be *any* bit pattern. All operations — containment, intersection, difference, iteration — work correctly with non-contiguous masks.

If your masks happen to be contiguous, the `Contiguous<T>` wrapper gives you a compile-time guarantee and CIDR prefix access.

### Key features

- **Non-contiguous mask support** — the only open-source Rust library that handles arbitrary subnet masks
- **Full set algebra** — `contains`, `intersection`, `difference`, `merge`, `is_adjacent` on networks as sets of addresses
- **Correct iteration** — iterate over addresses in a non-contiguous network in host-index order
- **Zero dependencies** — only `core`, nothing else
- **Performance-first** — `const fn` where possible, `#[inline]` on hot paths, minimal instruction count
- **Type-safe** — `Contiguous<T>` enforces contiguous masks at parse time; mismatched IPv4/IPv6 operations are compile errors

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
netip = "0.2"
```

### Parsing and basic operations

```rust
use netip::{Ipv4Network, IpNetwork};

// Standard CIDR notation.
let net: Ipv4Network = Ipv4Network::parse("10.0.0.0/8").unwrap();
assert_eq!(net.prefix(), Some(8));

// Dotted-mask notation — including non-contiguous masks.
let net = Ipv4Network::parse("192.168.0.0/255.0.255.0").unwrap();
assert!(!net.is_contiguous());

// IpNetwork parses both IPv4 and IPv6.
let net: IpNetwork = IpNetwork::parse("2001:db8::/32").unwrap();
```

### Set operations on networks

Networks are sets of addresses. `netip` gives you the algebra:

```rust
use netip::Ipv4Network;

let a = Ipv4Network::parse("10.0.0.0/255.0.0.0").unwrap();
let b = Ipv4Network::parse("10.1.0.0/255.255.0.0").unwrap();

// Containment: is every address in b also in a?
assert!(a.contains(&b));

// Intersection: the set of addresses in both networks.
let ab = a.intersection(&b).unwrap();
assert_eq!(ab, b);

// Difference: addresses in a but not in b — returns an iterator of networks.
for net in a.difference(&b) {
    println!("{net}"); // each chunk of the remaining address space
}
```

### Non-contiguous masks in action

This is where `netip` shines. Non-contiguous masks let you express bit-pattern matching that CIDR cannot:

```rust
use netip::Ipv4Network;

// Match all addresses where the first and third octets are 10 and 0.
// Second and fourth octets can be anything.
let pattern = Ipv4Network::parse("10.0.0.0/255.0.255.0").unwrap();
let specific = Ipv4Network::parse("10.42.0.99/255.255.255.255").unwrap();
assert!(pattern.contains(&specific)); // 10.42.0.99 matches 10.*.0.*

// Intersection of two non-contiguous networks — always a single network.
let a = Ipv4Network::parse("10.0.0.0/255.0.255.0").unwrap();
let b = Ipv4Network::parse("10.0.5.0/255.255.0.255").unwrap();
let ab = a.intersection(&b).unwrap();
assert_eq!(ab.to_string(), "10.0.5.0/255.255.255.255");

// Iterate over all addresses in a non-contiguous network.
let small = Ipv4Network::parse("192.168.0.0/255.255.255.252").unwrap();
let addrs: Vec<_> = small.addrs().collect();
assert_eq!(addrs.len(), 4);
```

### Contiguous wrapper

When you need the CIDR guarantee, `Contiguous<T>` enforces it at parse time:

```rust
use netip::Contiguous;
use netip::Ipv4Network;

let net: Contiguous<Ipv4Network> = Contiguous::parse("10.0.0.0/8").unwrap();
assert_eq!(net.prefix(), 8); // guaranteed to succeed — no Option

// Non-contiguous mask is rejected at parse time.
assert!(Contiguous::<Ipv4Network>::parse("10.0.0.0/255.0.255.0").is_err());

// Contiguous<T> derefs to T — all network methods are available.
assert!(net.contains(&Ipv4Network::parse("10.1.2.3/32").unwrap()));
```

### MAC addresses

```rust
use netip::MacAddr;

let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
```

## Types

| Type | Description |
|------|-------------|
| `Ipv4Network` | IPv4 network — `(address, mask)` pair, arbitrary masks |
| `Ipv6Network` | IPv6 network — `(address, mask)` pair, arbitrary masks |
| `IpNetwork` | Enum over `Ipv4Network` / `Ipv6Network` |
| `Contiguous<T>` | Newtype that enforces contiguous masks at parse time |
| `MacAddr` | MAC address (EUI-48), stored as lower 48 bits of `u64` |

## Roadmap

`netip` is on the path to a stable 1.0. Current version: **0.2.0**.

- **v0.3** — API cleanup: `#[must_use]`, `#[deny(missing_docs)]`
- **v0.4** — Complete set algebra: `complement`, `Contiguous<T>` merge/adjacent
- **v0.5** — Testing hardening: fuzz targets, exhaustive non-contiguous edge cases
- **v0.6+** — Documentation polish, API review, CHANGELOG
- **v1.0** — Stable release

## License

Apache-2.0
