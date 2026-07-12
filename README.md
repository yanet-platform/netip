# netip

[![crates.io](https://img.shields.io/crates/v/netip.svg)](https://crates.io/crates/netip)
[![docs.rs](https://docs.rs/netip/badge.svg)](https://docs.rs/netip)
[![License](https://img.shields.io/crates/l/netip.svg)](LICENSE)

**Zero-dependency** Rust library for IPv4/IPv6 networks and MAC addresses — with first-class support for **non-contiguous subnet masks**.

## Why netip?

Most networking libraries assume subnet masks are contiguous (a run of 1-bits followed by 0-bits, like `255.255.255.0`). Real-world network hardware — routers, firewalls, packet classifiers — often uses **non-contiguous masks** like `255.0.255.0` or even `170.85.170.85` to match on arbitrary bit patterns.

`netip` treats every network as a `(address, mask)` pair where the mask can be *any* bit pattern. All operations — containment, intersection, difference, merge, aggregation, iteration — work correctly with non-contiguous masks.

If your masks happen to be contiguous, the `Contiguous<T>` wrapper gives you a compile-time guarantee and CIDR prefix access. For IPv6 masks made of two prefix runs (one per 64-bit half — the common shape of site×subnet classifiers), there is `BiContiguous<Ipv6Network>`.

### Key features

- **Non-contiguous mask support** — the only open-source Rust library that handles arbitrary subnet masks
- **Full set algebra** — `contains`, `intersection`, `difference`, `merge`, `is_adjacent` on networks as sets of addresses
- **Slice operations** — in-place aggregation (`ipv4_aggregate`, `ipv6_aggregate` and typed variants), binary split, range-to-CIDR decomposition — all allocation-free
- **Fast parsing** — hand-rolled ASCII parsers, 1.8–3.2× faster than parsing through the standard library; `parse_ascii` accepts byte buffers, `parse_next_ascii` extracts the leading network from rule text and returns the remainder
- **Correct iteration** — iterate over addresses in a non-contiguous network in host-index order, from either end, with O(1) stepping
- **Zero dependencies** — only `core`, nothing else
- **`no_std`** — works on bare metal, no allocator required; CI builds the library for `thumbv7em-none-eabihf`
- **No unsafe** — `#![forbid(unsafe_code)]`
- **Performance-first** — `const fn` where possible, allocation-free runtime, minimal instruction count, criterion-benchmarked
- **Type-safe** — `Contiguous<T>` and `BiContiguous<T>` enforce mask shape at parse time; mismatched IPv4/IPv6 operations are compile errors

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
netip = "0.3"
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

// Parse straight from byte buffers — no UTF-8 validation pass.
let net = Ipv4Network::parse_ascii(b"10.0.0.0/8").unwrap();

// Extract the leading network from rule text; get the remainder back.
let (net, rest) = Ipv4Network::parse_next_ascii(b"10.0.0.0/8 allow").unwrap();
assert_eq!(rest, b" allow");
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

### Aggregation

Collapse a slice of networks in place — duplicates and contained networks are dropped, mergeable neighbors are merged:

```rust
use netip::{Ipv4Network, ipv4_aggregate};

let mut nets = [
    Ipv4Network::parse("10.0.0.0/24").unwrap(),
    Ipv4Network::parse("10.0.1.0/24").unwrap(),
    Ipv4Network::parse("10.0.0.128/25").unwrap(),
];
let nets = ipv4_aggregate(&mut nets);
assert_eq!(nets.len(), 1); // 10.0.0.0/23 covers all three
```

For contiguous inputs, `ipv4_aggregate_contiguous`/`ipv6_aggregate_contiguous` on `&mut [Contiguous<T>]` produce the provably minimal CIDR cover in a single O(N log N) pass.

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
let a = Ipv4Network::parse("10.0.0.0/255.0.255.0").unwrap(); // 10.*.0.*
let b = Ipv4Network::parse("10.5.0.0/255.255.0.255").unwrap(); // 10.5.*.0
let ab = a.intersection(&b).unwrap();
assert_eq!(ab.to_string(), "10.5.0.0/32"); // the single common address

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

let net = Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap();
assert_eq!(net.prefix(), 8); // guaranteed to succeed — no Option

// Non-contiguous mask is rejected at parse time.
assert!(Contiguous::<Ipv4Network>::parse("10.0.0.0/255.0.255.0").is_err());

// Typed operations stay in the wrapper.
let host = Contiguous::<Ipv4Network>::parse("10.1.2.3/32").unwrap();
assert!(net.contains(&host));

// Contiguous<T> derefs to T — the general network methods are available too.
assert!(net.intersects(&Ipv4Network::parse("10.1.2.3/32").unwrap()));
```

### BiContiguous wrapper

An IPv6 mask made of two prefix runs — one per 64-bit half — describes a product of a network prefix and a subnet prefix. `BiContiguous<Ipv6Network>` validates that shape at parse time and specializes the hot paths (address iteration, intersection, aggregation):

```rust
use netip::{BiContiguous, Ipv6Network};

let net: BiContiguous<Ipv6Network> =
    BiContiguous::parse("2001:db8::/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
assert_eq!(net.hi_prefix(), 40); // prefix of the high 64-bit half
assert_eq!(net.lo_prefix(), 32); // prefix of the low 64-bit half
```

### MAC addresses

```rust
use netip::MacAddr;

let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");

// Or straight from bytes.
let mac = MacAddr::parse_ascii(b"aa-bb-cc-dd-ee-ff").unwrap();
```

## Types

| Type | Description |
|------|-------------|
| `Ipv4Network` | IPv4 network — `(address, mask)` pair, arbitrary masks |
| `Ipv6Network` | IPv6 network — `(address, mask)` pair, arbitrary masks |
| `IpNetwork` | Enum over `Ipv4Network` / `Ipv6Network` |
| `Contiguous<T>` | Newtype that enforces contiguous masks at parse time |
| `BiContiguous<Ipv6Network>` | Newtype for two-run IPv6 masks — one contiguous prefix per 64-bit half |
| `MacAddr` | MAC address (EUI-48), stored as lower 48 bits of `u64` |

## Roadmap

`netip` is on the path to a stable 1.0. Current version: **0.3.5**.

- ~~**v0.3** — API cleanup, set-algebra completion, `Contiguous`/`BiContiguous` wrappers, slice aggregation, fast ASCII parsers, performance campaigns~~ ✓
- **v0.4** — Testing hardening: fuzz targets, exhaustive non-contiguous edge cases
- **v0.5+** — Documentation polish, API review, CHANGELOG
- **v1.0** — Stable release

## License

Apache-2.0
