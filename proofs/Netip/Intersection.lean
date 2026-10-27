import Netip.Network

/-!
# Intersection of two networks

`A ∩ B` is the network `(a₁ ∨ a₂, m₁ ∨ m₂)`, or empty. The emptiness test is the
one `Ipv4Network::intersection` uses, `a₁ ∧ m₂ = a₂ ∧ m₁`.
-/

namespace Netip

variable {n : Nat}

private theorem S_inter_bit : ∀ a1 m1 a2 m2 x : Bool, (a1 && m1) = a1 → (a2 && m2) = a2 →
    (((x && m1) = a1 ∧ (x && m2) = a2) ↔
      ((a1 && m2) = (a2 && m1) ∧ (x && (m1 || m2)) = (a1 || a2))) := by
  decide

/-- `X` lies in both networks iff the two agree on their common fixed bits and `X`
lies in `(a₁ ∨ a₂, m₁ ∨ m₂)`. -/
theorem S_inter_iff {a1 m1 a2 m2 : BitVec n} (h1 : Normalized a1 m1) (h2 : Normalized a2 m2)
    (X : BitVec n) :
    (S a1 m1 X ∧ S a2 m2 X) ↔ (a1 &&& m2 = a2 &&& m1 ∧ S (a1 ||| a2) (m1 ||| m2) X) := by
  unfold S
  have key : ∀ i < n,
      ((X.getLsbD i && m1.getLsbD i) = a1.getLsbD i ∧ (X.getLsbD i && m2.getLsbD i) = a2.getLsbD i) ↔
      ((a1.getLsbD i && m2.getLsbD i) = (a2.getLsbD i && m1.getLsbD i) ∧
        (X.getLsbD i && (m1.getLsbD i || m2.getLsbD i)) = (a1.getLsbD i || a2.getLsbD i)) := by
    intro i hi
    have t1 := getLsbD_congr h1 i
    have t2 := getLsbD_congr h2 i
    simp only [BitVec.getLsbD_and] at t1 t2
    exact S_inter_bit _ _ _ _ _ t1 t2
  constructor
  · rintro ⟨hx1, hx2⟩
    have k : ∀ i < n, _ := fun i hi =>
      (key i hi).1 ⟨by simpa using getLsbD_congr hx1 i, by simpa using getLsbD_congr hx2 i⟩
    exact ⟨BitVec.eq_of_getLsbD_eq fun i hi => by simpa using (k i hi).1,
      BitVec.eq_of_getLsbD_eq fun i hi => by simpa using (k i hi).2⟩
  · rintro ⟨ht, hx⟩
    have k : ∀ i < n, _ := fun i hi =>
      (key i hi).2 ⟨by simpa using getLsbD_congr ht i, by simpa using getLsbD_congr hx i⟩
    exact ⟨BitVec.eq_of_getLsbD_eq fun i hi => by simpa using (k i hi).1,
      BitVec.eq_of_getLsbD_eq fun i hi => by simpa using (k i hi).2⟩

end Netip
