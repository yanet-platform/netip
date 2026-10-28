# Not proved yet

Claims made by the network code in `src/` that the proofs do not cover yet.
Parsers and formatting are out of scope. Remove an entry once its proof lands.

## Set algebra (`src/net.rs`)

- [ ] `IpNetwork`: every method agrees with the per-family one and handles
  mixed families as documented. `to_ipv6_mapped` and `to_canonical` are proved.

## Iterators (`src/net.rs`, `src/net/contiguous.rs`, `src/net/bicontiguous.rs`)

- [ ] `Ipv4NetworkAddrs`, `Ipv6NetworkAddrs`: every member is yielded exactly
  once, in host-index order (index bits deposited into the host positions).
  `next` and `next_back` interleave and meet, the exhaustion sentinel states are
  final, and `len`, `size_hint` and `count` equal `2^(host bits)`. The single
  steps are proved.
- [ ] `ContiguousIpv4NetworkAddrs`, `ContiguousIpv6NetworkAddrs`: sentinels,
  remaining counts, and the same sequence as the general iterator. The closed
  forms are proved.
- [ ] `BiContiguousIpv6Addrs`: `base | (i & lo_mask) | ((i >> split_shift) << 64)`
  is the `i`-th member in host-index order, strictly increasing, and the same
  sequence as the general iterator, plus the sentinel and `size_hint`.
## Slice algorithms

- [ ] `ipv6_aggregate_bicontiguous`: the union is preserved, every output is
  bi-contiguous, and no output contains another, is a lowest-mask-bit sibling of
  another, or is a high-half buddy of another with an equal low-half set. This
  includes the level-sweep invariants and the containment probe.
- [ ] `ipv4_binary_split`, `ipv6_binary_split`: the linear and quadratic
  implementations return identical results (including the kill-word identity
  and the counter-based sliding OR). For sorted, non-overlapping input the
  returned network contains every network in `range`, `range` holds at least
  half of the slice, and it cannot be extended at either end. The doc's
  "shortest common network" needs a precise statement first.
- [ ] `ipv4_binary_split`: `range` does not always hold every network that the
  returned supernet contains, which the doc examples assert for their inputs.
  The supernet of a window can be non-contiguous even for CIDR input, and the
  networks it contains are then not consecutive in sorted order. Smallest case
  found: `10.0.0.4/32, 10.0.0.6/31, 10.0.0.12/31, 10.0.0.20/31, 10.0.0.25/32,
  10.0.0.28/30, 10.0.0.56/30` gives `10.0.0.4/255.255.255.228` with `range`
  `0..4`, while `10.0.0.28/30` (index 5) lies inside it. Decide whether this is
  the intended contract or a bug.

## Width-generic mathematics

- [ ] `|S(a, m)| = 2^(n - popcount m)`.
- [ ] `S(a, m)` is an interval iff `m` is contiguous, for symbolic `n` (proved
  for 32 and 128 bits).
- [ ] Host-index order: depositing the index bits into the host positions is a
  monotone bijection from `BitVec (n - popcount m)` onto `S(a, m)`.
