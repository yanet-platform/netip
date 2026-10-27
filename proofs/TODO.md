# Not proved yet

Claims made by the network code in `src/` that the proofs do not cover yet.
Parsers and formatting are out of scope. Remove an entry once its proof lands.

## Set algebra (`src/net.rs`)

- [ ] `IpNetwork`: every method agrees with the per-family one and handles
  mixed families as documented. `to_ipv6_mapped` and `to_canonical` are proved.

## Slice algorithms

- [ ] `ipv6_aggregate_bicontiguous`: the union is preserved, every output is
  bi-contiguous, and no output contains another, is a lowest-mask-bit sibling of
  another, or is a high-half buddy of another with an equal low-half set. This
  includes the level-sweep invariants and the containment probe.
