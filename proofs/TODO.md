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
- [ ] `to_contiguous`: clears the mask bits after the first zero; the result
  contains the input.
- [ ] `Ipv6Network::is_bicontiguous`, `to_ipv6_mapped`, `to_ipv4_mapped`,
  `is_ipv4_mapped_ipv6`, `IpNetwork::to_canonical`: the mapping is a bijection
  on address sets and the conversions round-trip.
- [ ] `IpNetwork`: every method agrees with the per-family one and handles
  mixed families as documented.
- [ ] `Ord for Ipv6Network`: lexicographic `(addr, mask)`.

## Iterators (`src/net.rs`, `src/net/contiguous.rs`, `src/net/bicontiguous.rs`)

- [ ] `Ipv4NetworkAddrs`, `Ipv6NetworkAddrs`: yield every member exactly once,
  in host-index order (index bits deposited into the host positions); `next`
  and `next_back` interleave and meet; exhaustion sentinel states; `len`,
  `size_hint`, `count` equal `2^(host bits)`. The single steps are proved.
- [ ] `ContiguousIpv4NetworkAddrs`, `ContiguousIpv6NetworkAddrs`: the closed
  forms (`base | index`, and `base + index` agreeing with it), sentinels,
  remaining counts, the same sequence as the general iterator.
- [ ] `BiContiguousIpv6Addrs`: `base | (i & lo_mask) | ((i >> split_shift) << 64)`
  is the `i`-th member in host-index order, strictly increasing, the same
  sequence as the general iterator; sentinel and `size_hint`.
- [ ] `Ipv4NetworkDiff`, `Ipv6NetworkDiff`: the statement over a whole run (any
  interleaving of `next`/`next_back` yields the item of every bit of `d` exactly
  once; `len`, `last`), the subset branch of `new`, and minimality: no family of
  fewer networks has the union `S(A) \ S(B)`. The decomposition, the per-step
  invariant, the `predicted` ladder and the disjoint shortcut are proved.
- [ ] `Ipv4RangeNetworks`, `Ipv6RangeNetworks`: the blocks are CIDR, pairwise
  disjoint, their union is `[first, last]`, their number is the minimum and at
  most `2n - 2`; the ascending/descending phase split equals the greedy cover;
  `size_hint`, fusedness. The per-step block arithmetic is proved.

## Slice algorithms

- [ ] `ipv4_aggregate`, `ipv6_aggregate` (`ip_aggregate`): the union is
  preserved, no output network contains or `merge`s with another, the loops
  terminate.
- [ ] `ipv4_aggregate_contiguous`, `ipv6_aggregate_contiguous`: the union is
  preserved and the output is the unique minimum CIDR cover; the top-only
  cascade is complete.
- [ ] `ipv6_aggregate_bicontiguous`: the union is preserved, every output is
  bi-contiguous, and no output contains another, is a lowest-mask-bit sibling of
  another, or is a high-half buddy of another with an equal low-half set; the
  level-sweep invariants and the containment probe.
- [ ] `ipv4_binary_split`, `ipv6_binary_split`: the linear and quadratic
  implementations return identical results (incl. the kill-word identity); for
  sorted, non-overlapping input the returned network covers at least half of
  the slice and `range` is exactly the inputs it contains. The doc's "shortest
  common network" needs a precise statement first.

## Wrappers

- [ ] `Contiguous::contains`: the integer compare `m1 <= m2` replaces the mask
  subset test for contiguous masks.
- [ ] `Contiguous<T>::prefix`, `BiContiguous::{hi_prefix, lo_prefix}`, the
  conversions `From<Contiguous<Ipv6Network>>` and `TryFrom<Ipv6Network>`.
- [ ] `BiContiguous::intersection`: the bi-contiguous class is closed under
  intersection.

## Width-generic mathematics

- [ ] `|S(a, m)| = 2^(n - popcount m)`.
- [ ] `S(a, m)` is an interval iff `m` is contiguous, for symbolic `n` (proved
  for 32 and 128 bits).
- [ ] Host-index order: depositing the index bits into the host positions is a
  monotone bijection from `BitVec (n - popcount m)` onto `S(a, m)`.
