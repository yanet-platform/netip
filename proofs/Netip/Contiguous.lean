import Netip.Network

/-!
# Contiguous masks

A mask is contiguous when its one bits form a leading run `1^k 0^(n-k)`, where
`k` is the prefix length of CIDR notation.
-/

namespace Netip

variable {n : Nat}

/-- `m` is contiguous iff its set bits are exactly the `k` most significant ones. -/
def Contiguous (m : BitVec n) : Prop := ∃ k ≤ n, ∀ i < n, m.getMsbD i = decide (i < k)

/-- The `/0` mask is contiguous. -/
theorem Contiguous.zero : Contiguous (0 : BitVec n) :=
  ⟨0, Nat.zero_le _, fun i _ => by simp⟩

/-- Contiguous masks are totally ordered by bitwise inclusion: of two prefixes,
the shorter one is a subset of the longer one. -/
theorem Contiguous.total {m1 m2 : BitVec n} (h1 : Contiguous m1) (h2 : Contiguous m2) :
    m1 &&& m2 = m1 ∨ m2 &&& m1 = m2 := by
  obtain ⟨k1, _, e1⟩ := h1
  obtain ⟨k2, _, e2⟩ := h2
  rcases Nat.le_total k1 k2 with h | h
  · left
    apply BitVec.eq_of_getMsbD_eq
    intro i hi
    rw [BitVec.getMsbD_and, e1 i hi, e2 i hi]
    by_cases h' : i < k1
    · have : i < k2 := by omega
      simp [h', this]
    · simp [h']
  · right
    apply BitVec.eq_of_getMsbD_eq
    intro i hi
    rw [BitVec.getMsbD_and, e1 i hi, e2 i hi]
    by_cases h' : i < k2
    · have : i < k1 := by omega
      simp [h', this]
    · simp [h']

end Netip
