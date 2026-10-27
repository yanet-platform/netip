/-!
# Networks as `(address, mask)` pairs

An address is a bit string of length `n`, modelled as `BitVec n`. The pair
`(a, m)` denotes the address set `S(a, m) = {X | X ∧ m = a}`: the one bits of
the mask are *fixed* positions, its zero bits are *free*. Every constructor of
the Rust types (`Ipv4Network::new`, `from_bits`, ...) establishes the
normalization invariant `a ∧ m = a`.

`BitVec.getLsbD i` reads bit `i` counting from the least significant end,
`BitVec.getMsbD i` counting from the most significant one.
-/

namespace Netip

variable {n : Nat}

/-- `S(a, m)`: the address set of the pair `(a, m)`, as a predicate on addresses. -/
def S (a m X : BitVec n) : Prop := X &&& m = a

/-- The normalization invariant `a ∧ m = a`: every free bit of the address is zero. -/
abbrev Normalized (a m : BitVec n) : Prop := a &&& m = a

/-- Reads an equation between bitwise expressions at bit `i`. -/
theorem getLsbD_congr {x y : BitVec n} (h : x = y) (i : Nat) : x.getLsbD i = y.getLsbD i := by
  rw [h]

/-- The address `a ∨ ¬m`, with every free bit set, belongs to `S(a, m)`. This is
the value of `last_addr`. -/
theorem S_last {a m : BitVec n} (h : Normalized a m) : S a m (a ||| ~~~m) := by
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  have t := getLsbD_congr h i
  simp only [BitVec.getLsbD_and, BitVec.getLsbD_or, BitVec.getLsbD_not, hi, decide_true,
    Bool.true_and] at t ⊢
  revert t
  cases a.getLsbD i <;> cases m.getLsbD i <;> decide

end Netip
