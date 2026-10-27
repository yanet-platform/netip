import Netip.Impl.Basic

/-!
# `merge` and `merge_by_lowest_mask_bit`

`Ipv4Network::{merge, merge_by_lowest_mask_bit}` and the IPv6 versions (the same
code at both widths), transcribed branch for branch.

Proved, for every input of the width:
* every `Some` that `merge` returns is normalized and is exactly the union of the
  two inputs;
* `merge_by_lowest_mask_bit` returns `Some` only where `merge` returns the same
  value, its result is normalized (the `NOTE` on `a1 & a2`), and it keeps
  contiguous inputs contiguous, which `ipv*_aggregate_contiguous` relies on.

Still open: the other half of `merge`'s documentation, "`Some(N)` iff the union
is exactly representable as a single network". It needs a counting argument
(two faces of different dimension, or two intersecting faces neither of which
contains the other, never have a union of power-of-two size) and is not a
bit-blasting goal.
-/

namespace Netip.Impl

variable {w : Nat}

/-- `merge` on `(addr, mask)` bit patterns. -/
def merge (a1 m1 a2 m2 : BitVec w) : Option (BitVec w × BitVec w) :=
  if m1 = m2 then
    if (a1 ^^^ a2) &&& ((a1 ^^^ a2) - 1) = 0 then
      some (a1 &&& (m1 ^^^ (a1 ^^^ a2)), m1 ^^^ (a1 ^^^ a2))
    else none
  else if m1 &&& m2 = m2 then
    if a1 &&& m2 = a2 then some (a2, m2) else none
  else if m1 &&& m2 = m1 then
    if a2 &&& m1 = a1 then some (a1, m1) else none
  else none

/-- `merge_by_lowest_mask_bit` on `(addr, mask)` bit patterns; the sibling test is
`ipv*_adjacent_by_lowest_mask_bit`, the containment tests are `contains`. -/
def mergeByLowestMaskBit (a1 m1 a2 m2 : BitVec w) : Option (BitVec w × BitVec w) :=
  if m1 = m2 then
    if a1 = a2 then some (a1, m1)
    else if m1 ≠ 0 ∧ a1 ^^^ a2 = m1 &&& -m1 then some (a1 &&& a2, m1 &&& (m1 - 1))
    else none
  else if a2 &&& m1 = a1 ∧ m2 &&& m1 = m1 then some (a1, m1)
  else if a1 &&& m2 = a2 ∧ m1 &&& m2 = m2 then some (a2, m2)
  else none

namespace Ipv4

theorem merge_sound {a1 m1 a2 m2 a m : BitVec 32} (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (h : merge a1 m1 a2 m2 = some (a, m)) (X : BitVec 32) :
    a &&& m = a ∧ (X &&& m = a ↔ X &&& m1 = a1 ∨ X &&& m2 = a2) := by
  unfold merge at h
  by_cases hm : m1 = m2
  · rw [ite_eq_left hm] at h
    by_cases hd : (a1 ^^^ a2) &&& ((a1 ^^^ a2) - 1) = 0
    · rw [ite_eq_left hd] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨ha, hm'⟩ := h
      bv_decide
    · rw [ite_eq_right hd] at h
      simp at h
  · rw [ite_eq_right hm] at h
    by_cases hc2 : m1 &&& m2 = m2
    · rw [ite_eq_left hc2] at h
      by_cases ha2 : a1 &&& m2 = a2
      · rw [ite_eq_left ha2] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨ha, hm'⟩ := h
        bv_decide
      · rw [ite_eq_right ha2] at h
        simp at h
    · rw [ite_eq_right hc2] at h
      by_cases hc1 : m1 &&& m2 = m1
      · rw [ite_eq_left hc1] at h
        by_cases ha1 : a2 &&& m1 = a1
        · rw [ite_eq_left ha1] at h
          simp only [Option.some.injEq, Prod.mk.injEq] at h
          obtain ⟨ha, hm'⟩ := h
          bv_decide
        · rw [ite_eq_right ha1] at h
          simp at h
      · rw [ite_eq_right hc1] at h
        simp at h

theorem mergeByLowestMaskBit_eq_merge {a1 m1 a2 m2 a m : BitVec 32} (h1 : a1 &&& m1 = a1)
    (h2 : a2 &&& m2 = a2) (h : mergeByLowestMaskBit a1 m1 a2 m2 = some (a, m)) :
    merge a1 m1 a2 m2 = some (a, m) := by
  unfold mergeByLowestMaskBit at h
  unfold merge
  by_cases hm : m1 = m2
  · rw [ite_eq_left hm] at h
    rw [ite_eq_left hm]
    by_cases he : a1 = a2
    · rw [ite_eq_left he] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨ha, hm'⟩ := h
      have hd : (a1 ^^^ a2) &&& ((a1 ^^^ a2) - 1) = 0 := by bv_decide
      rw [ite_eq_left hd]
      simp only [Option.some.injEq, Prod.mk.injEq]
      constructor <;> bv_decide
    · rw [ite_eq_right he] at h
      by_cases hs : m1 ≠ 0 ∧ a1 ^^^ a2 = m1 &&& -m1
      · rw [ite_eq_left hs] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨ha, hm'⟩ := h
        have hd : (a1 ^^^ a2) &&& ((a1 ^^^ a2) - 1) = 0 := by bv_decide
        rw [ite_eq_left hd]
        simp only [Option.some.injEq, Prod.mk.injEq]
        constructor <;> bv_decide
      · rw [ite_eq_right hs] at h
        simp at h
  · rw [ite_eq_right hm] at h
    rw [ite_eq_right hm]
    by_cases hc : a2 &&& m1 = a1 ∧ m2 &&& m1 = m1
    · rw [ite_eq_left hc] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨ha, hm'⟩ := h
      have hnot : ¬ (m1 &&& m2 = m2) := by bv_decide
      have hyes : m1 &&& m2 = m1 := by bv_decide
      have hadr : a2 &&& m1 = a1 := hc.1
      rw [ite_eq_right hnot, ite_eq_left hyes, ite_eq_left hadr, ha, hm']
    · rw [ite_eq_right hc] at h
      by_cases hc' : a1 &&& m2 = a2 ∧ m1 &&& m2 = m2
      · rw [ite_eq_left hc'] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨ha, hm'⟩ := h
        have hyes : m1 &&& m2 = m2 := hc'.2
        have hadr : a1 &&& m2 = a2 := hc'.1
        rw [ite_eq_left hyes, ite_eq_left hadr, ha, hm']
      · rw [ite_eq_right hc'] at h
        simp at h

theorem mergeByLowestMaskBit_normalized {a1 m1 a2 m2 a m : BitVec 32} (h1 : a1 &&& m1 = a1)
    (h2 : a2 &&& m2 = a2) (h : mergeByLowestMaskBit a1 m1 a2 m2 = some (a, m)) : a &&& m = a :=
  (merge_sound h1 h2 (mergeByLowestMaskBit_eq_merge h1 h2 h) 0).1

theorem mergeByLowestMaskBit_contiguous {a1 m1 a2 m2 a m : BitVec 32}
    (c1 : IsContiguous m1) (c2 : IsContiguous m2)
    (h : mergeByLowestMaskBit a1 m1 a2 m2 = some (a, m)) : IsContiguous m := by
  unfold IsContiguous at *
  unfold mergeByLowestMaskBit at h
  by_cases hm : m1 = m2
  · rw [ite_eq_left hm] at h
    by_cases he : a1 = a2
    · rw [ite_eq_left he] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      rw [← h.2]
      exact c1
    · rw [ite_eq_right he] at h
      by_cases hs : m1 ≠ 0 ∧ a1 ^^^ a2 = m1 &&& -m1
      · rw [ite_eq_left hs] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨_, hm'⟩ := h
        bv_decide
      · rw [ite_eq_right hs] at h
        simp at h
  · rw [ite_eq_right hm] at h
    by_cases hc : a2 &&& m1 = a1 ∧ m2 &&& m1 = m1
    · rw [ite_eq_left hc] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      rw [← h.2]
      exact c1
    · rw [ite_eq_right hc] at h
      by_cases hc' : a1 &&& m2 = a2 ∧ m1 &&& m2 = m2
      · rw [ite_eq_left hc'] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        rw [← h.2]
        exact c2
      · rw [ite_eq_right hc'] at h
        simp at h

end Ipv4

namespace Ipv6

theorem merge_sound {a1 m1 a2 m2 a m : BitVec 128} (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (h : merge a1 m1 a2 m2 = some (a, m)) (X : BitVec 128) :
    a &&& m = a ∧ (X &&& m = a ↔ X &&& m1 = a1 ∨ X &&& m2 = a2) := by
  unfold merge at h
  by_cases hm : m1 = m2
  · rw [ite_eq_left hm] at h
    by_cases hd : (a1 ^^^ a2) &&& ((a1 ^^^ a2) - 1) = 0
    · rw [ite_eq_left hd] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨ha, hm'⟩ := h
      bv_decide
    · rw [ite_eq_right hd] at h
      simp at h
  · rw [ite_eq_right hm] at h
    by_cases hc2 : m1 &&& m2 = m2
    · rw [ite_eq_left hc2] at h
      by_cases ha2 : a1 &&& m2 = a2
      · rw [ite_eq_left ha2] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨ha, hm'⟩ := h
        bv_decide
      · rw [ite_eq_right ha2] at h
        simp at h
    · rw [ite_eq_right hc2] at h
      by_cases hc1 : m1 &&& m2 = m1
      · rw [ite_eq_left hc1] at h
        by_cases ha1 : a2 &&& m1 = a1
        · rw [ite_eq_left ha1] at h
          simp only [Option.some.injEq, Prod.mk.injEq] at h
          obtain ⟨ha, hm'⟩ := h
          bv_decide
        · rw [ite_eq_right ha1] at h
          simp at h
      · rw [ite_eq_right hc1] at h
        simp at h

theorem mergeByLowestMaskBit_eq_merge {a1 m1 a2 m2 a m : BitVec 128} (h1 : a1 &&& m1 = a1)
    (h2 : a2 &&& m2 = a2) (h : mergeByLowestMaskBit a1 m1 a2 m2 = some (a, m)) :
    merge a1 m1 a2 m2 = some (a, m) := by
  unfold mergeByLowestMaskBit at h
  unfold merge
  by_cases hm : m1 = m2
  · rw [ite_eq_left hm] at h
    rw [ite_eq_left hm]
    by_cases he : a1 = a2
    · rw [ite_eq_left he] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨ha, hm'⟩ := h
      have hd : (a1 ^^^ a2) &&& ((a1 ^^^ a2) - 1) = 0 := by bv_decide
      rw [ite_eq_left hd]
      simp only [Option.some.injEq, Prod.mk.injEq]
      constructor <;> bv_decide
    · rw [ite_eq_right he] at h
      by_cases hs : m1 ≠ 0 ∧ a1 ^^^ a2 = m1 &&& -m1
      · rw [ite_eq_left hs] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨ha, hm'⟩ := h
        have hd : (a1 ^^^ a2) &&& ((a1 ^^^ a2) - 1) = 0 := by bv_decide
        rw [ite_eq_left hd]
        simp only [Option.some.injEq, Prod.mk.injEq]
        constructor <;> bv_decide
      · rw [ite_eq_right hs] at h
        simp at h
  · rw [ite_eq_right hm] at h
    rw [ite_eq_right hm]
    by_cases hc : a2 &&& m1 = a1 ∧ m2 &&& m1 = m1
    · rw [ite_eq_left hc] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨ha, hm'⟩ := h
      have hnot : ¬ (m1 &&& m2 = m2) := by bv_decide
      have hyes : m1 &&& m2 = m1 := by bv_decide
      have hadr : a2 &&& m1 = a1 := hc.1
      rw [ite_eq_right hnot, ite_eq_left hyes, ite_eq_left hadr, ha, hm']
    · rw [ite_eq_right hc] at h
      by_cases hc' : a1 &&& m2 = a2 ∧ m1 &&& m2 = m2
      · rw [ite_eq_left hc'] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨ha, hm'⟩ := h
        have hyes : m1 &&& m2 = m2 := hc'.2
        have hadr : a1 &&& m2 = a2 := hc'.1
        rw [ite_eq_left hyes, ite_eq_left hadr, ha, hm']
      · rw [ite_eq_right hc'] at h
        simp at h

theorem mergeByLowestMaskBit_normalized {a1 m1 a2 m2 a m : BitVec 128} (h1 : a1 &&& m1 = a1)
    (h2 : a2 &&& m2 = a2) (h : mergeByLowestMaskBit a1 m1 a2 m2 = some (a, m)) : a &&& m = a :=
  (merge_sound h1 h2 (mergeByLowestMaskBit_eq_merge h1 h2 h) 0).1

theorem mergeByLowestMaskBit_contiguous {a1 m1 a2 m2 a m : BitVec 128}
    (c1 : IsContiguous m1) (c2 : IsContiguous m2)
    (h : mergeByLowestMaskBit a1 m1 a2 m2 = some (a, m)) : IsContiguous m := by
  unfold IsContiguous at *
  unfold mergeByLowestMaskBit at h
  by_cases hm : m1 = m2
  · rw [ite_eq_left hm] at h
    by_cases he : a1 = a2
    · rw [ite_eq_left he] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      rw [← h.2]
      exact c1
    · rw [ite_eq_right he] at h
      by_cases hs : m1 ≠ 0 ∧ a1 ^^^ a2 = m1 &&& -m1
      · rw [ite_eq_left hs] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨_, hm'⟩ := h
        bv_decide
      · rw [ite_eq_right hs] at h
        simp at h
  · rw [ite_eq_right hm] at h
    by_cases hc : a2 &&& m1 = a1 ∧ m2 &&& m1 = m1
    · rw [ite_eq_left hc] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      rw [← h.2]
      exact c1
    · rw [ite_eq_right hc] at h
      by_cases hc' : a1 &&& m2 = a2 ∧ m1 &&& m2 = m2
      · rw [ite_eq_left hc'] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        rw [← h.2]
        exact c2
      · rw [ite_eq_right hc'] at h
        simp at h

end Ipv6

end Netip.Impl
