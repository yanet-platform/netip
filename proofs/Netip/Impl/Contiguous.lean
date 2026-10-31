import Netip.Impl.Basic

/-!
# The `Contiguous<T>` wrapper

Specializations that rely on the wrapper's contiguous mask: `contains` with an
integer comparison, the address iterators that step a plain index, and
`intersection`, whose result stays contiguous.
-/

namespace Netip.Impl

namespace Ipv4

/-- `Contiguous::contains`: for contiguous masks the subset test `m2 & m1 == m1`
is the integer comparison `m1 <= m2`. -/
theorem contains_mask_iff_le (m1 m2 : BitVec 32) (h1 : IsContiguous m1) (h2 : IsContiguous m2) :
    m2 &&& m1 = m1 ↔ m1 ≤ m2 := by
  unfold IsContiguous at *
  bv_decide

/-- `Contiguous::intersection`: the class is closed under the mask `m1 | m2` of an
intersection, so the result needs no re-validation. -/
theorem isContiguous_or (m1 m2 : BitVec 32) (h1 : IsContiguous m1) (h2 : IsContiguous m2) :
    IsContiguous (m1 ||| m2) := by
  unfold IsContiguous at *
  bv_decide

/-- `Contiguous::<Ipv4Network>::addrs`: `back = u32::MAX.checked_shr(32 - host_bits)`
is the host mask, so the indices run over `0 ..= !mask`. -/
theorem addrs_back (mask : BitVec 32) (h : IsContiguous mask) :
    BitVec.allOnes 32 >>> (32#32 - (~~~mask).cpop) = ~~~mask := by
  unfold IsContiguous at h
  bv_decide

/-- For an index in `0 ..= !mask`, `base | index` is a member, and it equals
`base + index`, so numeric order and index order agree. -/
theorem or_index (base mask index : BitVec 32) (h : IsContiguous mask)
    (hb : base &&& mask = base) (hi : index ≤ ~~~mask) :
    (base ||| index) &&& mask = base ∧ base ||| index = base + index := by
  unfold IsContiguous at h
  bv_decide

/-- Every member is `base | index` for its index `X & !mask`. -/
theorem eq_or_index (base mask X : BitVec 32) (hX : X &&& mask = base) :
    X = base ||| (X &&& ~~~mask) ∧ X &&& ~~~mask ≤ ~~~mask := by
  bv_decide

end Ipv4

namespace Ipv6

theorem contains_mask_iff_le (m1 m2 : BitVec 128) (h1 : IsContiguous m1) (h2 : IsContiguous m2) :
    m2 &&& m1 = m1 ↔ m1 ≤ m2 := by
  unfold IsContiguous at *
  bv_decide

theorem isContiguous_or (m1 m2 : BitVec 128) (h1 : IsContiguous m1) (h2 : IsContiguous m2) :
    IsContiguous (m1 ||| m2) := by
  unfold IsContiguous at *
  bv_decide

theorem addrs_back (mask : BitVec 128) (h : IsContiguous mask) :
    BitVec.allOnes 128 >>> (128#128 - (~~~mask).cpop) = ~~~mask := by
  unfold IsContiguous at h
  bv_decide

/-- The comment in `Contiguous::<Ipv6Network>::addrs`: `addr | index` and
`addr + index` agree for every index in `0 ..= back`, which is what lets the
iterator step the packed address `current` from `addr` to `last = addr | back`. -/
theorem or_index (base mask index : BitVec 128) (h : IsContiguous mask)
    (hb : base &&& mask = base) (hi : index ≤ ~~~mask) :
    (base ||| index) &&& mask = base ∧ base ||| index = base + index := by
  unfold IsContiguous at h
  bv_decide

theorem eq_or_index (base mask X : BitVec 128) (hX : X &&& mask = base) :
    X = base ||| (X &&& ~~~mask) ∧ X &&& ~~~mask ≤ ~~~mask := by
  bv_decide

end Ipv6

end Netip.Impl
