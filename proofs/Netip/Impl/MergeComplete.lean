import Netip.Impl.Merge
import Netip.Impl.SetOps

/-!
# `merge` is complete

`merge` returns `None` only when the union of the two networks is not a single
network. With `merge_sound` this is the documented "`Some(N)` iff their union is
exactly representable as a single network" (`merge_isSome_iff`).

When `merge` gives up, `noneWitness` is an address that lies in every network
containing both inputs but in neither input. A network equal to the union would
contain both inputs, hence the witness, so it cannot equal the union.
-/

namespace Netip.Impl

variable {w : Nat}

/-- The cases in which `merge` returns `None`. -/
def MergeNone (a1 m1 a2 m2 : BitVec w) : Prop :=
  (m1 = m2 ∧ (a1 ^^^ a2) &&& ((a1 ^^^ a2) - 1) ≠ 0) ∨
  (m1 ≠ m2 ∧ m1 &&& m2 = m2 ∧ a1 &&& m2 ≠ a2) ∨
  (m1 ≠ m2 ∧ m1 &&& m2 ≠ m2 ∧ m1 &&& m2 = m1 ∧ a2 &&& m1 ≠ a1) ∨
  (m1 ≠ m2 ∧ m1 &&& m2 ≠ m2 ∧ m1 &&& m2 ≠ m1)

theorem mergeNone_of_merge_eq_none {a1 m1 a2 m2 : BitVec w} (h : merge a1 m1 a2 m2 = none) :
    MergeNone a1 m1 a2 m2 := by
  unfold merge at h
  unfold MergeNone
  by_cases hm : m1 = m2
  · rw [ite_eq_left hm] at h
    by_cases hd : (a1 ^^^ a2) &&& ((a1 ^^^ a2) - 1) = 0
    · rw [ite_eq_left hd] at h
      simp at h
    · exact Or.inl ⟨hm, hd⟩
  · rw [ite_eq_right hm] at h
    by_cases h2 : m1 &&& m2 = m2
    · rw [ite_eq_left h2] at h
      by_cases ha : a1 &&& m2 = a2
      · rw [ite_eq_left ha] at h
        simp at h
      · exact Or.inr (Or.inl ⟨hm, h2, ha⟩)
    · rw [ite_eq_right h2] at h
      by_cases h1 : m1 &&& m2 = m1
      · rw [ite_eq_left h1] at h
        by_cases ha : a2 &&& m1 = a1
        · rw [ite_eq_left ha] at h
          simp at h
        · exact Or.inr (Or.inr (Or.inl ⟨hm, h2, h1, ha⟩))
      · exact Or.inr (Or.inr (Or.inr ⟨hm, h2, h1⟩))

/-- An address in every common supernet of the two networks, in neither of them,
when `merge` returns `None`:
* equal masks: flip one of the differing address bits;
* nested masks: flip a bit that only the finer network fixes;
* incomparable masks: flip a bit that only the first network fixes and one that
  only the second fixes. -/
def noneWitness (a1 m1 a2 m2 : BitVec w) : BitVec w :=
  if m1 = m2 then a1 ^^^ lowestBit (a1 ^^^ a2)
  else if m1 &&& m2 = m2 then a1 ^^^ lowestBit (m1 &&& ~~~m2)
  else if m1 &&& m2 = m1 then a2 ^^^ lowestBit (m2 &&& ~~~m1)
  else ((a1 &&& m1) ||| (a2 &&& m2 &&& ~~~m1)) ^^^ lowestBit (m1 &&& ~~~m2) ^^^
    lowestBit (m2 &&& ~~~m1)

namespace Ipv4

theorem noneWitness_spec (a1 m1 a2 m2 c mc : BitVec 32) (h1 : a1 &&& m1 = a1)
    (h2 : a2 &&& m2 = a2) (hn : MergeNone a1 m1 a2 m2)
    (hc1 : a1 &&& mc = c ∧ m1 &&& mc = mc) (hc2 : a2 &&& mc = c ∧ m2 &&& mc = mc) :
    noneWitness a1 m1 a2 m2 &&& mc = c ∧
    noneWitness a1 m1 a2 m2 &&& m1 ≠ a1 ∧ noneWitness a1 m1 a2 m2 &&& m2 ≠ a2 := by
  unfold MergeNone at hn
  unfold noneWitness lowestBit
  bv_decide

/-- `None` means the union is not a single network. -/
theorem merge_complete (a1 m1 a2 m2 : BitVec 32) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (hnone : merge a1 m1 a2 m2 = none) :
    ¬ ∃ c mc : BitVec 32, ∀ X, X &&& mc = c ↔ (X &&& m1 = a1 ∨ X &&& m2 = a2) := by
  rintro ⟨c, mc, hN⟩
  have ha1 : a1 &&& mc = c := (hN a1).2 (Or.inl h1)
  have hcn : c &&& mc = c := by bv_decide
  have hc1 := (contains_iff c mc a1 m1 hcn h1).2 fun X hX => (hN X).2 (Or.inl hX)
  have hc2 := (contains_iff c mc a2 m2 hcn h2).2 fun X hX => (hN X).2 (Or.inr hX)
  obtain ⟨hw, hw1, hw2⟩ :=
    noneWitness_spec a1 m1 a2 m2 c mc h1 h2 (mergeNone_of_merge_eq_none hnone) hc1 hc2
  rcases (hN _).1 hw with h | h
  · exact hw1 h
  · exact hw2 h

/-- `merge` returns `Some` iff the union of the two networks is a single network. -/
theorem merge_isSome_iff (a1 m1 a2 m2 : BitVec 32) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2) :
    (merge a1 m1 a2 m2).isSome ↔
      ∃ c mc : BitVec 32, ∀ X, X &&& mc = c ↔ (X &&& m1 = a1 ∨ X &&& m2 = a2) := by
  constructor
  · intro hs
    obtain ⟨⟨c, mc⟩, hcm⟩ := Option.isSome_iff_exists.mp hs
    exact ⟨c, mc, fun X => (merge_sound h1 h2 hcm X).2⟩
  · intro hex
    cases hm : merge a1 m1 a2 m2 with
    | none => exact absurd hex (merge_complete a1 m1 a2 m2 h1 h2 hm)
    | some r => rfl

end Ipv4

namespace Ipv6

theorem noneWitness_spec (a1 m1 a2 m2 c mc : BitVec 128) (h1 : a1 &&& m1 = a1)
    (h2 : a2 &&& m2 = a2) (hn : MergeNone a1 m1 a2 m2)
    (hc1 : a1 &&& mc = c ∧ m1 &&& mc = mc) (hc2 : a2 &&& mc = c ∧ m2 &&& mc = mc) :
    noneWitness a1 m1 a2 m2 &&& mc = c ∧
    noneWitness a1 m1 a2 m2 &&& m1 ≠ a1 ∧ noneWitness a1 m1 a2 m2 &&& m2 ≠ a2 := by
  unfold MergeNone at hn
  unfold noneWitness lowestBit
  bv_decide

theorem merge_complete (a1 m1 a2 m2 : BitVec 128) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (hnone : merge a1 m1 a2 m2 = none) :
    ¬ ∃ c mc : BitVec 128, ∀ X, X &&& mc = c ↔ (X &&& m1 = a1 ∨ X &&& m2 = a2) := by
  rintro ⟨c, mc, hN⟩
  have ha1 : a1 &&& mc = c := (hN a1).2 (Or.inl h1)
  have hcn : c &&& mc = c := by bv_decide
  have hc1 := (contains_iff c mc a1 m1 hcn h1).2 fun X hX => (hN X).2 (Or.inl hX)
  have hc2 := (contains_iff c mc a2 m2 hcn h2).2 fun X hX => (hN X).2 (Or.inr hX)
  obtain ⟨hw, hw1, hw2⟩ :=
    noneWitness_spec a1 m1 a2 m2 c mc h1 h2 (mergeNone_of_merge_eq_none hnone) hc1 hc2
  rcases (hN _).1 hw with h | h
  · exact hw1 h
  · exact hw2 h

theorem merge_isSome_iff (a1 m1 a2 m2 : BitVec 128) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2) :
    (merge a1 m1 a2 m2).isSome ↔
      ∃ c mc : BitVec 128, ∀ X, X &&& mc = c ↔ (X &&& m1 = a1 ∨ X &&& m2 = a2) := by
  constructor
  · intro hs
    obtain ⟨⟨c, mc⟩, hcm⟩ := Option.isSome_iff_exists.mp hs
    exact ⟨c, mc, fun X => (merge_sound h1 h2 hcm X).2⟩
  · intro hex
    cases hm : merge a1 m1 a2 m2 with
    | none => exact absurd hex (merge_complete a1 m1 a2 m2 h1 h2 hm)
    | some r => rfl

end Ipv6

end Netip.Impl
