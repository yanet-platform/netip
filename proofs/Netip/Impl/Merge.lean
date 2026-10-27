import Netip.Impl.BiContiguous

/-!
# `merge` and `merge_by_lowest_mask_bit`

`Ipv4Network::{merge, merge_by_lowest_mask_bit}` and the IPv6 versions (the same
code at both widths), transcribed branch for branch.

Proved, for every input of the width:
* Every `Some` that `merge` returns is normalized and is exactly the union of the
  two inputs.
* `merge_by_lowest_mask_bit` returns `Some` only where `merge` returns the same
  value, and its result is normalized (the `NOTE` on `a1 & a2`).
* Its result mask is an input mask or one with the lowest set bit cleared, which
  never adds a run of ones: contiguous inputs stay contiguous
  (`ipv*_aggregate_contiguous` relies on it) and bi-contiguous inputs stay
  bi-contiguous (`ipv6_aggregate_bicontiguous` relies on it), while a
  non-contiguous pair can land in the contiguous class.

The other half of `merge`'s documentation, `None` only when the union is not a
single network, is in `MergeComplete`.
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

/-- `merge_by_lowest_mask_bit` on `(addr, mask)` bit patterns. The sibling test is
`ipv*_adjacent_by_lowest_mask_bit`, the containment tests are `contains`. -/
def mergeByLowestMaskBit (a1 m1 a2 m2 : BitVec w) : Option (BitVec w × BitVec w) :=
  if m1 = m2 then
    if a1 = a2 then some (a1, m1)
    else if m1 ≠ 0 ∧ a1 ^^^ a2 = m1 &&& -m1 then some (a1 &&& a2, m1 &&& (m1 - 1))
    else none
  else if a2 &&& m1 = a1 ∧ m2 &&& m1 = m1 then some (a1, m1)
  else if a1 &&& m2 = a2 ∧ m1 &&& m2 = m2 then some (a2, m2)
  else none

/-- The mask `merge_by_lowest_mask_bit` returns is one of the input masks, or the
shared mask with its lowest set bit cleared. -/
theorem mergeByLowestMaskBit_mask {a1 m1 a2 m2 a m : BitVec w}
    (h : mergeByLowestMaskBit a1 m1 a2 m2 = some (a, m)) :
    m = m1 ∨ m = m2 ∨ (m1 = m2 ∧ m = m1 &&& (m1 - 1)) := by
  unfold mergeByLowestMaskBit at h
  split at h
  · rename_i hm
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      exact Or.inl h.2.symm
    · split at h
      · simp only [Option.some.injEq, Prod.mk.injEq] at h
        exact Or.inr (Or.inr ⟨hm, h.2.symm⟩)
      · simp at h
  · split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      exact Or.inl h.2.symm
    · split at h
      · simp only [Option.some.injEq, Prod.mk.injEq] at h
        exact Or.inr (Or.inl h.2.symm)
      · simp at h

/-- The lowest bit of every run of ones in `m`. Their number is the number of runs. -/
def runStarts (m : BitVec w) : BitVec w := m &&& ~~~(m <<< 1)

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

theorem clearLowest_runs_le (m : BitVec 32) :
    (runStarts (m &&& (m - 1))).cpop ≤ (runStarts m).cpop := by
  unfold runStarts
  bv_decide

/-- The example in the documentation: two non-contiguous networks whose
lowest-mask-bit merge is the contiguous `10.0.0.0/30`. -/
theorem mergeByLowestMaskBit_tightens :
    ¬ IsContiguous 0xFFFFFFFD#32 ∧
    mergeByLowestMaskBit 0x0A000000#32 0xFFFFFFFD#32 0x0A000001#32 0xFFFFFFFD#32 =
      some (0x0A000000#32, 0xFFFFFFFC#32) ∧
    IsContiguous 0xFFFFFFFC#32 := by
  unfold IsContiguous
  decide

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

theorem clearLowest_runs_le (m : BitVec 128) :
    (runStarts (m &&& (m - 1))).cpop ≤ (runStarts m).cpop := by
  unfold runStarts
  bv_decide

theorem mergeByLowestMaskBit_biContiguous {a1 m1 a2 m2 a m : BitVec 128}
    (c1 : IsBiContiguous m1) (c2 : IsBiContiguous m2)
    (h : mergeByLowestMaskBit a1 m1 a2 m2 = some (a, m)) : IsBiContiguous m := by
  rcases mergeByLowestMaskBit_mask h with rfl | rfl | ⟨_, rfl⟩
  · exact c1
  · exact c2
  · unfold IsBiContiguous at *
    bv_decide

end Ipv6

end Netip.Impl
