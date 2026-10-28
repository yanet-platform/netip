import Netip.Impl.Basic

/-!
# `is_contiguous`, CIDR masks and `prefix()`

`ipv4_mask_from_cidr`, `ipv6_mask_from_cidr`,
`Ipv4Network::{is_contiguous, prefix}`, their IPv6 counterparts and
`BiContiguous::<Ipv6Network>::is_contiguous`.
-/

namespace Netip.Impl

namespace Ipv4

/-- `is_contiguous` computes `m | (m - 1) == MAX`; equivalently, the host mask `!m`
is a trailing run of ones, `!m & (!m + 1) == 0`. -/
theorem isContiguous_iff_hostmask (m : BitVec 32) : IsContiguous m ↔ ~~~m &&& (~~~m + 1) = 0 := by
  unfold IsContiguous
  bv_decide

/-- A mask passes `is_contiguous` iff it is the CIDR mask of its own `leading_ones`. -/
theorem isContiguous_iff_eq_maskFromCidr (m : BitVec 32) :
    IsContiguous m ↔ m = maskFromCidr 32 (~~~m).clz := by
  unfold IsContiguous maskFromCidr
  bv_decide

/-- Every mask `ipv4_mask_from_cidr` accepts (`cidr ≤ 32`) passes `is_contiguous`. -/
theorem isContiguous_maskFromCidr (cidr : BitVec 32) (h : cidr ≤ 32) :
    IsContiguous (maskFromCidr 32 cidr) := by
  unfold IsContiguous maskFromCidr
  bv_decide

/-- The comment in `prefix()`: for a contiguous mask `leading_ones` equals the popcount. -/
theorem leadingOnes_eq_popcount (m : BitVec 32) (h : IsContiguous m) : (~~~m).clz = m.cpop := by
  unfold IsContiguous at h
  bv_decide

end Ipv4

namespace Ipv6

theorem isContiguous_iff_hostmask (m : BitVec 128) : IsContiguous m ↔ ~~~m &&& (~~~m + 1) = 0 := by
  unfold IsContiguous
  bv_decide

theorem isContiguous_iff_eq_maskFromCidr (m : BitVec 128) :
    IsContiguous m ↔ m = maskFromCidr 128 (~~~m).clz := by
  unfold IsContiguous maskFromCidr
  bv_decide

theorem isContiguous_maskFromCidr (cidr : BitVec 128) (h : cidr ≤ 128) :
    IsContiguous (maskFromCidr 128 cidr) := by
  unfold IsContiguous maskFromCidr
  bv_decide

theorem leadingOnes_eq_popcount (m : BitVec 128) (h : IsContiguous m) : (~~~m).clz = m.cpop := by
  unfold IsContiguous at h
  bv_decide

/-- `BiContiguous::is_contiguous`: for a mask made of one prefix per 64-bit half,
`lo == 0 || hi == u64::MAX` agrees with the general 128-bit test. -/
theorem biContiguous_isContiguous (p q : BitVec 64) (hp : p ≤ 64) (hq : q ≤ 64) :
    IsContiguous (maskFromCidr 64 p ++ maskFromCidr 64 q) ↔
      (maskFromCidr 64 q = 0 ∨ maskFromCidr 64 p = BitVec.allOnes 64) := by
  unfold IsContiguous maskFromCidr
  bv_decide

end Ipv6

end Netip.Impl
