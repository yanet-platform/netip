# Not proved yet

Claims made by the network code and the parsers in `src/` that the proofs do
not cover yet. Formatting is out of scope. Remove an entry once its proof lands.

## Parsers (`src/parser.rs`)

The reference is `core`'s own parsing as of Rust 1.99: `Ipv4Addr::parse_ascii`,
`Ipv6Addr::parse_ascii` and `u8::from_str`.

- [ ] Tokens: `parse_ipv4_network_next_ascii`, `parse_ipv6_network_next_ascii`
  and `parse_ip_network_next_ascii` parse the maximal leading token of their
  alphabet as a whole and return the rest after it, errors included.
