# Not proved yet

Claims made by the network code in `src/` that the proofs do not cover yet.
Parsers and formatting are out of scope. Remove an entry once its proof lands.

## Set algebra (`src/net.rs`)

- [ ] `IpNetwork`: every method agrees with the per-family one and handles
  mixed families as documented. `to_ipv6_mapped` and `to_canonical` are proved.

## Iterators (`src/net.rs`, `src/net/contiguous.rs`, `src/net/bicontiguous.rs`)

- [ ] `BiContiguousIpv6Addrs`: `base | (i & lo_mask) | ((i >> split_shift) << 64)`
  is the `i`-th member in host-index order, strictly increasing, and the same
  sequence as the general iterator, plus the sentinel and `size_hint`.

## Slice algorithms

- [ ] `ipv6_aggregate_bicontiguous`: the union is preserved, every output is
  bi-contiguous, and no output contains another, is a lowest-mask-bit sibling of
  another, or is a high-half buddy of another with an equal low-half set. This
  includes the level-sweep invariants and the containment probe.
- [ ] `ipv4_binary_split`, `ipv6_binary_split`: the linear and quadratic
  candidate searches return the same network (the kill-word identity and the
  counter-based sliding OR), and the candidate contains a whole window, so the
  block holds at least half of the slice. Gathering the block is proved.
