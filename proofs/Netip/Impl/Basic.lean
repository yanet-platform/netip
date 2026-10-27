import Std.Tactic.BVDecide

/-!
# The bit vocabulary of the Rust code

Modules under `Netip.Impl` state facts about the Rust implementation at the
widths it actually uses, `BitVec 32` for `u32` (IPv4) and `BitVec 128` for
`u128` (IPv6), and discharge them with `bv_decide`: the goal is bit-blasted to
SAT and the solver's LRAT certificate is checked, so a theorem covers every
input of the width.

Dictionary: `wrapping_add` / `wrapping_sub` / `wrapping_neg` are the modular
`+` / `-` / `-x` of `BitVec`; `<` and `≤` on `BitVec` are unsigned;
`leading_zeros` is `BitVec.clz`; `count_ones` is `BitVec.cpop`;
`as u64` on a `u128` is `setWidth 64`.

Trust: besides the usual axioms, every `bv_decide` proof depends on an
auxiliary axiom asserting that the compiled LRAT checker accepted the
certificate (`#print axioms` lists it as `..._native.bv_decide.ax_...`).
-/

namespace Netip.Impl

variable {w : Nat}

/-- `x & x.wrapping_neg()`: the lowest set bit of `x`, `0` for `x = 0`. -/
def lowestBit (x : BitVec w) : BitVec w := x &&& -x

/-- `is_contiguous`: `mask | mask.wrapping_sub(1) == MAX`. -/
def IsContiguous (m : BitVec w) : Prop := m ||| (m - 1) = BitVec.allOnes w

/-- `ipv4_mask_from_cidr` / `ipv6_mask_from_cidr`: `!(MAX >> cidr)`. Shifting by the
full width yields `0`, as Rust's `checked_shr(..).unwrap_or(0)` does. -/
def maskFromCidr (w : Nat) (cidr : BitVec w) : BitVec w := ~~~(BitVec.allOnes w >>> cidr)

/-- `0x8000_0000 >> x.leading_zeros()`: the highest set bit of `x`, `0` for `x = 0`. -/
def highestBit32 (x : BitVec 32) : BitVec 32 := 0x80000000#32 >>> x.clz

/-- The highest set bit of a `u128`, `0` for `x = 0`. -/
def highestBit128 (x : BitVec 128) : BitVec 128 := (1#128 <<< 127) >>> x.clz

end Netip.Impl
