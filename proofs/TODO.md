# Not proved yet

Claims made by the network code in `src/` that the proofs do not cover yet.
Parsers and formatting are out of scope. Remove an entry once its proof lands.

## Set algebra (`src/net.rs`)

- [ ] `merge`: completeness, `None` only when the union is not a single network
  (the doc's "`Some(N)` iff their union is exactly representable"). Soundness is
  proved.
- [ ] `supernet_for`: the result contains every input and is contained in every
  network that contains them all.
- [ ] `is_adjacent`, `is_adjacent_by_lowest_mask_bit`: adjacent pairs are
  exactly the equal-mask pairs whose union is one network one bit wider.
- [ ] `to_contiguous`: the result clears the mask bits after the first zero and
  contains the input.
- [ ] `to_ipv6_mapped`, `to_ipv4_mapped`, `is_ipv4_mapped_ipv6`,
  `IpNetwork::to_canonical`: the mapping is a bijection on address sets and the
  conversions round-trip.
- [ ] `IpNetwork`: every method agrees with the per-family one and handles
  mixed families as documented.
- [ ] `Ord for Ipv6Network`: lexicographic `(addr, mask)`.

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
- [ ] `Ipv4NetworkDiff`, `Ipv6NetworkDiff`: the statement over a whole run, where
  any interleaving of `next` and `next_back` yields the item of every bit of `d`
  exactly once (with `len` and `last`), the subset branch of `new`, and
  minimality: no family of fewer networks has the union `S(A) \ S(B)`. The
  decomposition, the per-step invariant, the `predicted` ladder and the disjoint
  shortcut are proved.
- [ ] `Ipv4RangeNetworks`, `Ipv6RangeNetworks`: the blocks are CIDR and pairwise
  disjoint, their union is `[first, last]`, and their number is the minimum and
  at most `2n - 2`. The ascending/descending phase split equals the greedy
  cover, plus `size_hint` and fusedness. The per-step block arithmetic is proved.

## Slice algorithms

- [ ] `ipv4_aggregate`, `ipv6_aggregate` (`ip_aggregate`): the union is
  preserved, no output network contains or `merge`s with another, and the loops
  terminate.
- [ ] `ipv4_aggregate_contiguous`, `ipv6_aggregate_contiguous`: the union is
  preserved, the output is the unique minimum CIDR cover, and the top-only
  cascade is complete.
- [ ] `ipv6_aggregate_bicontiguous`: the union is preserved, every output is
  bi-contiguous, and no output contains another, is a lowest-mask-bit sibling of
  another, or is a high-half buddy of another with an equal low-half set. This
  includes the level-sweep invariants and the containment probe.
- [ ] `ipv4_binary_split`, `ipv6_binary_split`: the linear and quadratic
  implementations return identical results (including the kill-word identity).
  For sorted, non-overlapping input the returned network covers at least half
  of the slice and `range` is exactly the inputs it contains. The doc's
  "shortest common network" needs a precise statement first.

## Width-generic mathematics

- [ ] `|S(a, m)| = 2^(n - popcount m)`.
- [ ] `S(a, m)` is an interval iff `m` is contiguous, for symbolic `n` (proved
  for 32 and 128 bits).
- [ ] Host-index order: depositing the index bits into the host positions is a
  monotone bijection from `BitVec (n - popcount m)` onto `S(a, m)`.
