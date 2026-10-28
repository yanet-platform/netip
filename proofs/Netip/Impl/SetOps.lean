import Netip.Impl.Basic

/-!
# `contains`, `intersection`, `last_addr`

`Ipv4Network::{contains, intersection, last_addr}` and the IPv6 versions, on the
`(addr, mask)` bit patterns. Inputs are normalized, as every constructor
guarantees.
-/

namespace Netip.Impl

namespace Ipv4

/-- `intersection`: `X` is in both networks iff the emptiness test
`a1 & m2 == a2 & m1` passes and `X` is in the returned `(a1 | a2, m1 | m2)`. -/
theorem intersection_iff (a1 m1 a2 m2 X : BitVec 32) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2) :
    (X &&& m1 = a1 ∧ X &&& m2 = a2) ↔
      (a1 &&& m2 = a2 &&& m1 ∧ X &&& (m1 ||| m2) = a1 ||| a2) := by
  bv_decide

/-- The `NOTE: address is already normalized` in `intersection`. -/
theorem intersection_normalized (a1 m1 a2 m2 : BitVec 32) (h1 : a1 &&& m1 = a1)
    (h2 : a2 &&& m2 = a2) : (a1 ||| a2) &&& (m1 ||| m2) = a1 ||| a2 := by
  bv_decide

/-- `contains` is exactly set inclusion `S(a2, m2) ⊆ S(a1, m1)`. -/
theorem contains_iff (a1 m1 a2 m2 : BitVec 32) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2) :
    (a2 &&& m1 = a1 ∧ m2 &&& m1 = m1) ↔ ∀ X : BitVec 32, X &&& m2 = a2 → X &&& m1 = a1 := by
  constructor
  · intro hc X hX
    bv_decide
  · intro h
    -- Completeness needs two witnesses only: the first and the last address of `S(a2, m2)`.
    have first := h a2 h2
    have last := h (a2 ||| ~~~m2) (by bv_decide)
    bv_decide

/-- `last_addr`: `addr | !mask` is a member, and no member is larger. -/
theorem lastAddr_max (a m X : BitVec 32) (h : a &&& m = a) (hX : X &&& m = a) :
    (a ||| ~~~m) &&& m = a ∧ X ≤ a ||| ~~~m := by
  bv_decide

end Ipv4

namespace Ipv6

theorem intersection_iff (a1 m1 a2 m2 X : BitVec 128) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2) :
    (X &&& m1 = a1 ∧ X &&& m2 = a2) ↔
      (a1 &&& m2 = a2 &&& m1 ∧ X &&& (m1 ||| m2) = a1 ||| a2) := by
  bv_decide

theorem intersection_normalized (a1 m1 a2 m2 : BitVec 128) (h1 : a1 &&& m1 = a1)
    (h2 : a2 &&& m2 = a2) : (a1 ||| a2) &&& (m1 ||| m2) = a1 ||| a2 := by
  bv_decide

theorem contains_iff (a1 m1 a2 m2 : BitVec 128) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2) :
    (a2 &&& m1 = a1 ∧ m2 &&& m1 = m1) ↔ ∀ X : BitVec 128, X &&& m2 = a2 → X &&& m1 = a1 := by
  constructor
  · intro hc X hX
    bv_decide
  · intro h
    have first := h a2 h2
    have last := h (a2 ||| ~~~m2) (by bv_decide)
    bv_decide

theorem lastAddr_max (a m X : BitVec 128) (h : a &&& m = a) (hX : X &&& m = a) :
    (a ||| ~~~m) &&& m = a ∧ X ≤ a ||| ~~~m := by
  bv_decide

end Ipv6

end Netip.Impl
