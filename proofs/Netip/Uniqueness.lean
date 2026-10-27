import Netip.Network

/-!
# Uniqueness of the normalized representation

Bitwise identities at a symbolic width are proved in two steps: the per-bit
fact is a statement about `Bool` that `decide` checks by truth table, and
`BitVec.eq_of_getLsbD_eq` lifts it to `BitVec n`.
-/

namespace Netip

variable {n : Nat}

private theorem repr_unique_bit : ∀ a1 m1 a2 m2 : Bool,
    (a1 && m1) = a1 → (a2 && m2) = a2 → (a1 && m2) = a2 → (a2 && m1) = a1 →
    ((a1 || !m1) && m2) = a2 → ((a2 || !m2) && m1) = a1 → a1 = a2 ∧ m1 = m2 := by
  decide

/-- Two normalized pairs with the same address set are equal.

Four members suffice as witnesses: `a₁`, `a₂` and the two last addresses
`aᵢ ∨ ¬mᵢ`. -/
theorem repr_unique {a1 m1 a2 m2 : BitVec n} (h1 : Normalized a1 m1) (h2 : Normalized a2 m2)
    (hS : ∀ X, S a1 m1 X ↔ S a2 m2 X) : a1 = a2 ∧ m1 = m2 := by
  have e1 : a1 &&& m2 = a2 := (hS a1).1 h1
  have e2 : a2 &&& m1 = a1 := (hS a2).2 h2
  have e3 : (a1 ||| ~~~m1) &&& m2 = a2 := (hS _).1 (S_last h1)
  have e4 : (a2 ||| ~~~m2) &&& m1 = a1 := (hS _).2 (S_last h2)
  have per_bit : ∀ i < n, a1.getLsbD i = a2.getLsbD i ∧ m1.getLsbD i = m2.getLsbD i := by
    intro i hi
    have t1 := getLsbD_congr h1 i
    have t2 := getLsbD_congr h2 i
    have t3 := getLsbD_congr e1 i
    have t4 := getLsbD_congr e2 i
    have t5 := getLsbD_congr e3 i
    have t6 := getLsbD_congr e4 i
    simp only [BitVec.getLsbD_and, BitVec.getLsbD_or, BitVec.getLsbD_not, hi, decide_true,
      Bool.true_and] at t1 t2 t3 t4 t5 t6
    exact repr_unique_bit _ _ _ _ t1 t2 t3 t4 t5 t6
  exact ⟨BitVec.eq_of_getLsbD_eq fun i hi => (per_bit i hi).1,
    BitVec.eq_of_getLsbD_eq fun i hi => (per_bit i hi).2⟩

end Netip
