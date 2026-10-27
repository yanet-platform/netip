import Netip.Impl.Basic

/-!
# `Ord for Ipv4Network`

The comparison packs `addr` into the high and `mask` into the low 32 bits of a
`u64` key. The comment claims this preserves the lexicographic `(addr, mask)`
order exactly. (`Ord for Ipv6Network` compares the two fields directly.)
-/

namespace Netip.Impl.Ipv4

theorem ord_key (a1 m1 a2 m2 : BitVec 32) :
    ((a1.setWidth 64 <<< 32) ||| m1.setWidth 64) < ((a2.setWidth 64 <<< 32) ||| m2.setWidth 64) ↔
      (a1 < a2 ∨ (a1 = a2 ∧ m1 < m2)) := by
  bv_decide

theorem ord_key_eq (a1 m1 a2 m2 : BitVec 32) :
    ((a1.setWidth 64 <<< 32) ||| m1.setWidth 64) = ((a2.setWidth 64 <<< 32) ||| m2.setWidth 64) ↔
      (a1 = a2 ∧ m1 = m2) := by
  bv_decide

end Netip.Impl.Ipv4
