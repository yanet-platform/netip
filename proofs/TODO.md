# Not proved yet

Claims made by the network code in `src/` that the proofs do not cover yet.
Parsers and formatting are out of scope. Remove an entry once its proof lands.

## Slice algorithms

- [ ] `ipv6_aggregate_bicontiguous`: the union is preserved, every output is
  bi-contiguous, and no output contains another, is a lowest-mask-bit sibling of
  another, or is a high-half buddy of another with an equal low-half set. The
  level sweep is proved (`BiSweep`); the containment probe and the rounds that
  repeat both until the probe drops nothing are not.
