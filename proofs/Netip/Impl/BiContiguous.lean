import Netip.Impl.Basic

/-!
# Bi-contiguous masks

`Ipv6Network::is_bicontiguous` and the `BiContiguous<Ipv6Network>` wrapper. A
bi-contiguous mask carries one leading run of ones in each 64-bit half.
-/

namespace Netip.Impl.Ipv6

/-- The high 64-bit half, `(mask >> 64) as u64`. -/
def hi (m : BitVec 128) : BitVec 64 := (m >>> 64).setWidth 64

/-- The low 64-bit half, `mask as u64`. -/
def lo (m : BitVec 128) : BitVec 64 := m.setWidth 64

/-- `is_bicontiguous`: `(mask & !(mask >> 1)) & CLEAR == 0`, where `CLEAR` clears
bits 127 and 63, the only places a run of ones may start from the top. -/
def IsBiContiguous (m : BitVec 128) : Prop :=
  (m &&& ~~~(m >>> 1)) &&& ~~~((1#128 <<< 127) ||| (1#128 <<< 63)) = 0

/-- The check is exactly "each half is contiguous". -/
theorem isBiContiguous_iff (m : BitVec 128) :
    IsBiContiguous m ↔ IsContiguous (hi m) ∧ IsContiguous (lo m) := by
  unfold IsBiContiguous IsContiguous hi lo
  bv_decide

/-- A bi-contiguous mask is the concatenation of the CIDR masks of `hi_prefix` and
`lo_prefix` (each the `leading_ones` of its half). -/
theorem eq_of_isBiContiguous (m : BitVec 128) (h : IsBiContiguous m) :
    m = maskFromCidr 64 (~~~(hi m)).clz ++ maskFromCidr 64 (~~~(lo m)).clz := by
  unfold IsBiContiguous at h
  unfold maskFromCidr hi lo
  bv_decide

/-- `From<Contiguous<Ipv6Network>>`: every contiguous mask is bi-contiguous. -/
theorem isBiContiguous_of_isContiguous (m : BitVec 128) (h : IsContiguous m) :
    IsBiContiguous m := by
  unfold IsBiContiguous
  unfold IsContiguous at h
  bv_decide

/-- `BiContiguous::intersection`: the class is closed under the mask `m1 | m2` of an
intersection, so the result needs no re-validation. -/
theorem isBiContiguous_or (m1 m2 : BitVec 128) (h1 : IsBiContiguous m1)
    (h2 : IsBiContiguous m2) : IsBiContiguous (m1 ||| m2) := by
  unfold IsBiContiguous at *
  bv_decide

/-- `BiContiguous::is_contiguous`: for a bi-contiguous mask the per-half check
`lo == 0 || hi == u64::MAX` agrees with the general 128-bit test. -/
theorem isContiguous_iff_of_isBiContiguous (m : BitVec 128) (h : IsBiContiguous m) :
    IsContiguous m ↔ (lo m = 0 ∨ hi m = BitVec.allOnes 64) := by
  unfold IsBiContiguous at h
  unfold IsContiguous hi lo
  bv_decide

end Netip.Impl.Ipv6
