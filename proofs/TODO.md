# Not proved yet

Claims made by the network code and the parsers in `src/` that the proofs do
not cover yet. Formatting is out of scope. Remove an entry once its proof lands.

## Parsers (`src/parser.rs`)

The reference is `core`'s own parsing as of Rust 1.99: `Ipv4Addr::parse_ascii`,
`Ipv6Addr::parse_ascii` and `u8::from_str`.

- [ ] Addresses: `ipv4_parse_ascii` and `ipv6_parse_ascii` accept exactly the
  inputs `core` accepts, with the same value, as the module documentation claims
  ("replicates `core::net`'s address grammar exactly"). In particular the `core`
  fallback of `parse_ipv*_addr` never accepts an input the hand-written parser
  rejected. `parse_cidr_suffix` accepts exactly what `u8::from_str` accepts.
- [ ] Prefixes: when `ipv4_parse_at` or `ipv6_parse_at` stops before a byte that
  cannot continue an address, `core` parses the consumed prefix to the same
  address. The fused fast paths rely on it.
- [ ] Networks: `parse_ipv4_network_ascii`, `parse_ipv6_network_ascii` and
  `parse_ip_network_ascii` equal the split-first reference, errors included: the
  address up to the first `/`, then a CIDR suffix as `u8::from_str` reads it, or
  else a mask address, with the documented family dispatch.
- [ ] Tokens: `parse_ipv4_network_next_ascii`, `parse_ipv6_network_next_ascii`
  and `parse_ip_network_next_ascii` parse the maximal leading token of their
  alphabet as a whole and return the rest after it, errors included.
