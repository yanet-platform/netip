import Netip.Impl.Basic

/-!
# Range-to-CIDR iterators: the block arithmetic

`Ipv4RangeNetworks::next` / `Ipv6RangeNetworks::next`. Proved here are the two
bit tricks each step relies on, not yet the claims about the whole
decomposition (minimum cardinality, at most `2n - 2` blocks, the phase split).

* Ascending phase: `block = x & -x` is a single bit set in `x` with nothing of `x`
  below it, and `mask = x | -x` is "every bit from `block` up" — the netmask of
  a `block`-sized CIDR block.
* Descending phase: `block_max + 1` is the largest power of two not exceeding the
  remaining `size`. IPv4 computes it in `u64` so that `size = 2^32` needs no
  branch. IPv6 splits `size` into 64-bit words and maps `size = 0` (the full
  range, wrapped) to `u128::MAX`.
-/

namespace Netip.Impl

namespace Ipv4

theorem ascending_block (x : BitVec 32) (hx : x ≠ 0) :
    let block := x &&& -x
    let mask := x ||| -x
    (block &&& (block - 1) = 0 ∧ block ≠ 0 ∧ x &&& block = block ∧ x &&& (block - 1) = 0) ∧
    mask = ~~~(block - 1) := by
  intro block mask
  bv_decide

/-- `((u64::MAX >> 1) >> size.leading_zeros()) as u32`: for `1 ≤ size ≤ 2^32`,
`block_max` is an all-ones suffix, `block_max + 1 ≤ size < 2 * (block_max + 1)`,
and the cast to `u32` loses nothing. -/
theorem descending_block (size : BitVec 64) (h0 : size ≠ 0) (h1 : size ≤ 0x100000000#64) :
    let bm := (BitVec.allOnes 64 >>> 1) >>> size.clz
    bm &&& (bm + 1) = 0 ∧ bm < size ∧ size ≤ (bm <<< 1) ||| 1 ∧ bm ≤ 0xFFFFFFFF#64 := by
  intro bm
  bv_decide

end Ipv4

namespace Ipv6

theorem ascending_block (x : BitVec 128) (hx : x ≠ 0) :
    let block := x &&& -x
    let mask := x ||| -x
    (block &&& (block - 1) = 0 ∧ block ≠ 0 ∧ x &&& block = block ∧ x &&& (block - 1) = 0) ∧
    mask = ~~~(block - 1) := by
  intro block mask
  bv_decide

/-- `block_max` of `Ipv6RangeNetworks::next`, on 64-bit words. -/
def blockMax (size : BitVec 128) : BitVec 128 :=
  if (size >>> 64).setWidth 64 ≠ 0 then
    (((BitVec.allOnes 64 >>> 1) >>> ((size >>> 64).setWidth 64).clz).setWidth 128 <<< 64) |||
      (BitVec.allOnes 64).setWidth 128
  else if size.setWidth 64 = 0 then BitVec.allOnes 128
  else ((BitVec.allOnes 64 >>> 1) >>> (size.setWidth 64).clz).setWidth 128

theorem descending_block (size : BitVec 128) :
    (size = 0 → blockMax size = BitVec.allOnes 128) ∧
    (size ≠ 0 → blockMax size &&& (blockMax size + 1) = 0 ∧ blockMax size < size ∧
      size ≤ (blockMax size <<< 1) ||| 1) := by
  unfold blockMax
  bv_decide

end Ipv6

end Netip.Impl
