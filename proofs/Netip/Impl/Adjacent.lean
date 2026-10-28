import Netip.Impl.Merge

/-!
# `is_adjacent` and `is_adjacent_by_lowest_mask_bit`

`ipv*_adjacent_bit` and `ipv*_adjacent_by_lowest_mask_bit`, transcribed.

Proved, for every input of the width: adjacent networks share the mask, are
disjoint, and differ in exactly one masked bit `d`, and `merge` combines them
into their union under the mask with `d` dropped. Identical networks are not
adjacent, a `/0` is adjacent to nothing, and the lowest-mask-bit variant only
accepts pairs that `is_adjacent` accepts.
-/

namespace Netip.Impl

variable {w : Nat}

/-- `ipv*_adjacent_bit`: the single differing bit of two same-mask networks. The
Rust `d != 0 && d & (d - 1) == 0` never computes `0 - 1`. -/
def adjacentBit (a1 m1 a2 m2 : BitVec w) : Option (BitVec w) :=
  if m1 ≠ m2 then none
  else if a1 ^^^ a2 ≠ 0 ∧ (a1 ^^^ a2) &&& ((a1 ^^^ a2) - 1) = 0 then some (a1 ^^^ a2)
  else none

/-- `ipv*_adjacent_by_lowest_mask_bit`. -/
def AdjacentByLowestMaskBit (a1 m1 a2 m2 : BitVec w) : Prop :=
  m1 = m2 ∧ m1 ≠ 0 ∧ a1 ^^^ a2 = m1 &&& -m1

theorem adjacentBit_eq_some {a1 m1 a2 m2 d : BitVec w} (h : adjacentBit a1 m1 a2 m2 = some d) :
    m1 = m2 ∧ d = a1 ^^^ a2 ∧ d ≠ 0 ∧ d &&& (d - 1) = 0 := by
  unfold adjacentBit at h
  split at h
  · simp at h
  · rename_i hm
    split at h
    · rename_i hd
      simp only [Option.some.injEq] at h
      subst h
      exact ⟨Classical.byContradiction hm, rfl, hd.1, hd.2⟩
    · simp at h

theorem adjacentBit_self (a m : BitVec w) : adjacentBit a m a m = none := by
  unfold adjacentBit
  simp

namespace Ipv4

/-- Adjacent networks differ in one masked bit, are disjoint, and `merge` makes
their union under the mask with that bit dropped. -/
theorem adjacent_merge {a1 m1 a2 m2 d : BitVec 32} (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (h : adjacentBit a1 m1 a2 m2 = some d) :
    d &&& m1 = d ∧ (∀ X : BitVec 32, ¬ (X &&& m1 = a1 ∧ X &&& m2 = a2)) ∧
      merge a1 m1 a2 m2 = some (a1 &&& (m1 ^^^ d), m1 ^^^ d) := by
  obtain ⟨hm, rfl, hd0, hd⟩ := adjacentBit_eq_some h
  subst hm
  refine ⟨by bv_decide, fun X => by bv_decide, ?_⟩
  unfold merge
  rw [ite_eq_left rfl, ite_eq_left hd]

/-- A `/0` network is adjacent to nothing. -/
theorem adjacentBit_zero_mask (a1 a2 : BitVec 32) (h1 : a1 &&& 0 = a1) (h2 : a2 &&& 0 = a2) :
    adjacentBit a1 0 a2 0 = none := by
  have : a1 ^^^ a2 = 0 := by bv_decide
  unfold adjacentBit
  simp [this]

/-- Every lowest-mask-bit sibling pair is adjacent. -/
theorem adjacentBit_of_byLowestMaskBit {a1 m1 a2 m2 : BitVec 32}
    (h : AdjacentByLowestMaskBit a1 m1 a2 m2) : adjacentBit a1 m1 a2 m2 = some (a1 ^^^ a2) := by
  unfold AdjacentByLowestMaskBit at h
  obtain ⟨hm, h0, hx⟩ := h
  have hd : a1 ^^^ a2 ≠ 0 ∧ (a1 ^^^ a2) &&& ((a1 ^^^ a2) - 1) = 0 := by bv_decide
  unfold adjacentBit
  rw [ite_eq_right (not_not_intro hm), ite_eq_left hd]

end Ipv4

namespace Ipv6

theorem adjacent_merge {a1 m1 a2 m2 d : BitVec 128} (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (h : adjacentBit a1 m1 a2 m2 = some d) :
    d &&& m1 = d ∧ (∀ X : BitVec 128, ¬ (X &&& m1 = a1 ∧ X &&& m2 = a2)) ∧
      merge a1 m1 a2 m2 = some (a1 &&& (m1 ^^^ d), m1 ^^^ d) := by
  obtain ⟨hm, rfl, hd0, hd⟩ := adjacentBit_eq_some h
  subst hm
  refine ⟨by bv_decide, fun X => by bv_decide, ?_⟩
  unfold merge
  rw [ite_eq_left rfl, ite_eq_left hd]

theorem adjacentBit_zero_mask (a1 a2 : BitVec 128) (h1 : a1 &&& 0 = a1) (h2 : a2 &&& 0 = a2) :
    adjacentBit a1 0 a2 0 = none := by
  have : a1 ^^^ a2 = 0 := by bv_decide
  unfold adjacentBit
  simp [this]

theorem adjacentBit_of_byLowestMaskBit {a1 m1 a2 m2 : BitVec 128}
    (h : AdjacentByLowestMaskBit a1 m1 a2 m2) : adjacentBit a1 m1 a2 m2 = some (a1 ^^^ a2) := by
  unfold AdjacentByLowestMaskBit at h
  obtain ⟨hm, h0, hx⟩ := h
  have hd : a1 ^^^ a2 ≠ 0 ∧ (a1 ^^^ a2) &&& ((a1 ^^^ a2) - 1) = 0 := by bv_decide
  unfold adjacentBit
  rw [ite_eq_right (not_not_intro hm), ite_eq_left hd]

end Ipv6

end Netip.Impl
