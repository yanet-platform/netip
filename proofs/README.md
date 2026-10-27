# netip proofs

Machine-checked proofs, in Lean 4, of the network algorithms and the parsers in
`src/`. Formatting is out of scope. [`TODO.md`](TODO.md) lists the claims that
are not proved yet.

## Layout

- `Netip/` — the address-set model for an arbitrary width `n`:
  `S(a, m) = {X | X ∧ m = a}`, normalization, contiguous masks, and the
  theorems that hold at every width.
- `Netip/Impl/` — Lean transcriptions of the Rust functions on `(addr, mask)`
  bit patterns, with their correctness theorems at the widths the crate uses:
  `BitVec 32` for `u32`, `BitVec 128` for `u128`. Namespaces `Ipv4` and `Ipv6`
  mirror the Rust types.

Transcriptions are written by hand and follow the Rust code branch for branch,
so changing an algorithm in `src/` needs the matching change here.

## Building

Install [elan](https://github.com/leanprover/elan), then run in this directory:

    lake build

Only the Lean core library is used, no Mathlib. Each module checks in seconds
and under about 1 GB of memory. `lake build` checks independent modules in
parallel. To bound memory, build one module at a time, for example
`lake build Netip.Impl.Difference`.

If elan cannot download the toolchain (seen on IPv6-only networks), fetch
`lean-<version>-linux.tar.zst` from the Lean releases on GitHub, unpack it, and
register it with `elan toolchain link leanprover/lean4:<version> <dir>`.

## Trust

Theorems proved by hand depend only on Lean's standard axioms (`propext`,
`Classical.choice`, `Quot.sound`). Theorems proved by `bv_decide`, which
bit-blasts the goal to SAT, also depend on an auxiliary axiom stating that the
compiled LRAT checker accepted the solver's certificate, and `#print axioms`
lists it as `..._native.bv_decide.ax_...`. CI rejects `sorry`, `native_decide` and
declared axioms.
