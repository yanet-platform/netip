import Netip.Contiguous

/-!
# Contiguous networks are nested or disjoint

Two networks whose masks are comparable under `⊆` are nested or disjoint, for
arbitrary masks (`nested_or_disjoint_of_subset`). Contiguous masks are always
comparable, so contiguous networks form a laminar family
(`Contiguous.nested_or_disjoint`). The alternatives are not exclusive: for equal
networks both inclusions hold.
-/

namespace Netip

variable {n : Nat}

/-- For masks with `m₁ ⊆ m₂`, the network `(a₂, m₂)` is inside `(a₁, m₁)` or
disjoint from it. -/
theorem nested_or_disjoint_of_subset {a1 m1 a2 m2 : BitVec n} (hm : m1 &&& m2 = m1) :
    (∀ X, S a2 m2 X → S a1 m1 X) ∨ (∀ X, ¬ (S a1 m1 X ∧ S a2 m2 X)) := by
  by_cases h : a2 &&& m1 = a1
  · left
    intro X hX
    unfold S at *
    rw [← h, ← hX, BitVec.and_assoc, BitVec.and_comm m2 m1, hm]
  · right
    rintro X ⟨hX1, hX2⟩
    apply h
    unfold S at hX1 hX2
    rw [← hX2, BitVec.and_assoc, BitVec.and_comm m2 m1, hm, hX1]

/-- Two contiguous networks are nested or disjoint. -/
theorem Contiguous.nested_or_disjoint {a1 m1 a2 m2 : BitVec n}
    (h1 : Contiguous m1) (h2 : Contiguous m2) :
    (∀ X, S a1 m1 X → S a2 m2 X) ∨ (∀ X, S a2 m2 X → S a1 m1 X) ∨
      (∀ X, ¬ (S a1 m1 X ∧ S a2 m2 X)) := by
  rcases Contiguous.total h1 h2 with hm | hm
  · rcases nested_or_disjoint_of_subset (a1 := a1) (a2 := a2) hm with h | h
    · exact Or.inr (Or.inl h)
    · exact Or.inr (Or.inr h)
  · rcases nested_or_disjoint_of_subset (a1 := a2) (a2 := a1) hm with h | h
    · exact Or.inl h
    · exact Or.inr (Or.inr fun X hx => h X ⟨hx.2, hx.1⟩)

end Netip
