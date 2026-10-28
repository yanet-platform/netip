import Netip.Contiguous

/-!
# Host-index order and the size of `S(a, m)`

The free positions of `m`, its zero bits, are the *host* positions. Listed from
the least significant end, the `j`-th host position of the member with host index
`i` carries bit `j` of `i`, and the fixed positions carry the bits of `a`:
the member is `a ∨ pdep(i, ¬m)`. This is the order the address iterators yield.

`pdep` and its inverse `pext` are defined on natural numbers, one low bit at a
time. Proved for every width `n`:
* bit `b` of `pdep(i, h)` is bit `rank(b)` of `i` when `b` is a one bit of `h`,
  where `rank(b)` counts the one bits of `h` below `b`, and zero otherwise
  (`testBit_pdepNat`);
* with `k = n - popcount(m)` host positions, `i ↦ a ∨ pdep(i, ¬m)` is a strictly
  increasing bijection from `BitVec k` onto `S(a, m)` (`hostIndex_bijection`);
* hence `|S(a, m)| = 2^(n - popcount m)`: of all `2^n` addresses exactly that many
  are members (`card_S`), and listing the members by host index lists them in
  ascending order without repetition (`members_spec`).
-/

namespace Netip

/-! ## `pdep` and `pext` on natural numbers -/

/-- The number of one bits. -/
def popNat (h : Nat) : Nat := if h = 0 then 0 else h % 2 + popNat (h / 2)
decreasing_by omega

/-- `pdep(i, h)`: deposits the bits of `i`, least significant first, into the one
bits of `h`, least significant first. -/
def pdepNat (h i : Nat) : Nat :=
  if h = 0 then 0
  else if h % 2 = 1 then i % 2 + 2 * pdepNat (h / 2) (i / 2)
  else 2 * pdepNat (h / 2) i
decreasing_by all_goals omega

/-- `pext(x, h)`: gathers the bits of `x` at the one bits of `h` into the low bits. -/
def pextNat (h x : Nat) : Nat :=
  if h = 0 then 0
  else if h % 2 = 1 then x % 2 + 2 * pextNat (h / 2) (x / 2)
  else pextNat (h / 2) (x / 2)
decreasing_by all_goals omega

theorem popNat_zero : popNat 0 = 0 := by
  rw [popNat, ite_eq_left rfl]

theorem popNat_eq (h : Nat) : popNat h = h % 2 + popNat (h / 2) := by
  by_cases h0 : h = 0
  · subst h0
    rw [popNat_zero]
  · rw [popNat, ite_eq_right h0]

theorem pdepNat_zero_left (i : Nat) : pdepNat 0 i = 0 := by
  simp [pdepNat]

theorem pdepNat_odd {h : Nat} (hh : h % 2 = 1) (i : Nat) :
    pdepNat h i = i % 2 + 2 * pdepNat (h / 2) (i / 2) := by
  rw [pdepNat, ite_eq_right (show ¬h = 0 by omega), ite_eq_left hh]

theorem pdepNat_even {h : Nat} (h0 : h ≠ 0) (hh : h % 2 = 0) (i : Nat) :
    pdepNat h i = 2 * pdepNat (h / 2) i := by
  rw [pdepNat, ite_eq_right h0, ite_eq_right (show ¬h % 2 = 1 by omega)]

theorem pextNat_odd {h : Nat} (hh : h % 2 = 1) (x : Nat) :
    pextNat h x = x % 2 + 2 * pextNat (h / 2) (x / 2) := by
  rw [pextNat, ite_eq_right (show ¬h = 0 by omega), ite_eq_left hh]

theorem pextNat_even {h : Nat} (h0 : h ≠ 0) (hh : h % 2 = 0) (x : Nat) :
    pextNat h x = pextNat (h / 2) (x / 2) := by
  rw [pextNat, ite_eq_right h0, ite_eq_right (show ¬h % 2 = 1 by omega)]

theorem two_pow_one_add (p : Nat) : 2 ^ (1 + p) = 2 * 2 ^ p := by
  rw [Nat.add_comm, Nat.pow_succ, Nat.mul_comm]

/-- `pdep` is strictly increasing on the indices that fit the one bits of `h`. -/
theorem pdepNat_lt_pdepNat (h : Nat) :
    ∀ i j, i < j → j < 2 ^ popNat h → pdepNat h i < pdepNat h j := by
  induction h using Nat.strongRecOn with
  | ind h ih =>
    intro i j hij hj
    by_cases h0 : h = 0
    · subst h0
      rw [popNat_zero, Nat.pow_zero] at hj
      omega
    · have hlt : h / 2 < h := by omega
      rw [popNat_eq] at hj
      by_cases hodd : h % 2 = 1
      · rw [pdepNat_odd hodd, pdepNat_odd hodd]
        rw [hodd, two_pow_one_add] at hj
        have hj2 : j / 2 < 2 ^ popNat (h / 2) := by omega
        by_cases hq : i / 2 < j / 2
        · have := ih (h / 2) hlt (i / 2) (j / 2) hq hj2
          omega
        · have hq' : i / 2 = j / 2 := by omega
          rw [hq']
          omega
      · have hev : h % 2 = 0 := by omega
        rw [pdepNat_even h0 hev, pdepNat_even h0 hev]
        rw [hev, Nat.zero_add] at hj
        have := ih (h / 2) hlt i j hij hj
        omega

/-- Bit `b` of `pdep(i, h)`: bit `rank(b)` of `i` at a one bit of `h`, where `rank(b)`
is the number of one bits of `h` below `b`. -/
theorem testBit_pdepNat (h : Nat) :
    ∀ i b, (pdepNat h i).testBit b = (h.testBit b && i.testBit (popNat (h % 2 ^ b))) := by
  induction h using Nat.strongRecOn with
  | ind h ih =>
    intro i b
    by_cases h0 : h = 0
    · subst h0
      simp [pdepNat_zero_left]
    · have hlt : h / 2 < h := by omega
      cases b with
      | zero =>
        have hp0 : popNat (h % 2 ^ 0) = 0 := by rw [Nat.pow_zero, Nat.mod_one, popNat_zero]
        rw [hp0]
        simp only [Nat.testBit_zero]
        by_cases hodd : h % 2 = 1
        · rw [pdepNat_odd hodd]
          have : (i % 2 + 2 * pdepNat (h / 2) (i / 2)) % 2 = i % 2 := by omega
          simp [this, hodd]
        · rw [pdepNat_even h0 (by omega)]
          have : 2 * pdepNat (h / 2) i % 2 = 0 := by omega
          simp [this, hodd]
      | succ b =>
        have hmod : h % 2 ^ (b + 1) / 2 = h / 2 % 2 ^ b := by
          rw [Nat.pow_succ, Nat.mul_comm, Nat.mod_mul_right_div_self]
        have hpop : popNat (h % 2 ^ (b + 1)) = h % 2 + popNat (h / 2 % 2 ^ b) := by
          rw [popNat_eq, ← hmod]
          congr 1
          rw [Nat.pow_succ, Nat.mod_mul_left_mod]
        rw [Nat.testBit_add_one, Nat.testBit_add_one h, hpop]
        by_cases hodd : h % 2 = 1
        · rw [pdepNat_odd hodd]
          have : (i % 2 + 2 * pdepNat (h / 2) (i / 2)) / 2 = pdepNat (h / 2) (i / 2) := by omega
          rw [this, ih (h / 2) hlt, hodd, Nat.add_comm 1, Nat.testBit_add_one]
        · have hev : h % 2 = 0 := by omega
          rw [pdepNat_even h0 hev]
          have : 2 * pdepNat (h / 2) i / 2 = pdepNat (h / 2) i := by omega
          rw [this, ih (h / 2) hlt, hev, Nat.zero_add]

/-- `pdep` only sets one bits of `h`. -/
theorem testBit_of_testBit_pdepNat {h i b : Nat} (hb : (pdepNat h i).testBit b = true) :
    h.testBit b = true := by
  rw [testBit_pdepNat] at hb
  exact (Bool.and_eq_true _ _ ▸ hb).1

theorem pextNat_lt (h : Nat) : ∀ x, pextNat h x < 2 ^ popNat h := by
  induction h using Nat.strongRecOn with
  | ind h ih =>
    intro x
    by_cases h0 : h = 0
    · subst h0
      rw [popNat_zero, pextNat, ite_eq_left rfl]
      exact Nat.one_pos
    · have hlt : h / 2 < h := by omega
      rw [popNat_eq]
      by_cases hodd : h % 2 = 1
      · rw [pextNat_odd hodd, hodd, two_pow_one_add]
        have := ih (h / 2) hlt (x / 2)
        omega
      · have hev : h % 2 = 0 := by omega
        rw [pextNat_even h0 hev, hev, Nat.zero_add]
        exact ih (h / 2) hlt (x / 2)

/-- `pdep` undoes `pext` on the values whose one bits lie in `h`. -/
theorem pdepNat_pextNat (h : Nat) :
    ∀ x, (∀ b, x.testBit b = true → h.testBit b = true) → pdepNat h (pextNat h x) = x := by
  induction h using Nat.strongRecOn with
  | ind h ih =>
    intro x hx
    by_cases h0 : h = 0
    · subst h0
      rw [pdepNat_zero_left]
      apply Eq.symm
      apply Nat.eq_of_testBit_eq
      intro b
      cases hb : x.testBit b
      · simp
      · simpa using hx b hb
    · have hlt : h / 2 < h := by omega
      have hx2 : ∀ b, (x / 2).testBit b = true → (h / 2).testBit b = true := by
        intro b hb
        rw [← Nat.testBit_add_one] at hb ⊢
        exact hx (b + 1) hb
      by_cases hodd : h % 2 = 1
      · rw [pextNat_odd hodd, pdepNat_odd hodd]
        have e1 : (x % 2 + 2 * pextNat (h / 2) (x / 2)) % 2 = x % 2 := by omega
        have e2 : (x % 2 + 2 * pextNat (h / 2) (x / 2)) / 2 = pextNat (h / 2) (x / 2) := by omega
        rw [e1, e2, ih (h / 2) hlt (x / 2) hx2]
        omega
      · have hev : h % 2 = 0 := by omega
        rw [pextNat_even h0 hev, pdepNat_even h0 hev, ih (h / 2) hlt (x / 2) hx2]
        have hx0 : x % 2 = 0 := by
          have hb := hx 0
          simp only [Nat.testBit_zero, decide_eq_true_eq, hev] at hb
          omega
        omega

/-- The all-ones index fills every one bit of `h`. -/
theorem pdepNat_allOnes (h : Nat) : pdepNat h (2 ^ popNat h - 1) = h := by
  induction h using Nat.strongRecOn with
  | ind h ih =>
    by_cases h0 : h = 0
    · subst h0
      simp [pdepNat_zero_left]
    · have hlt : h / 2 < h := by omega
      have hp := @Nat.one_le_two_pow (popNat (h / 2))
      rw [popNat_eq]
      by_cases hodd : h % 2 = 1
      · rw [pdepNat_odd hodd, hodd, two_pow_one_add]
        have e2 : (2 * 2 ^ popNat (h / 2) - 1) / 2 = 2 ^ popNat (h / 2) - 1 := by omega
        rw [e2, ih (h / 2) hlt]
        omega
      · have hev : h % 2 = 0 := by omega
        rw [pdepNat_even h0 hev, hev, Nat.zero_add, ih (h / 2) hlt]
        omega

theorem pdepNat_zero (h : Nat) : pdepNat h 0 = 0 := by
  induction h using Nat.strongRecOn with
  | ind h ih =>
    by_cases h0 : h = 0
    · subst h0
      exact pdepNat_zero_left 0
    · by_cases hodd : h % 2 = 1
      · rw [pdepNat_odd hodd, ih (h / 2) (by omega)]
      · rw [pdepNat_even h0 (by omega), ih (h / 2) (by omega)]

/-! ## Popcount -/

theorem popNat_two_pow_add (w : Nat) : ∀ y, y < 2 ^ w → popNat (2 ^ w + y) = 1 + popNat y := by
  induction w with
  | zero =>
    intro y hy
    have : y = 0 := by omega
    subst this
    rw [Nat.pow_zero, Nat.add_zero, popNat_eq 1, popNat_zero]
  | succ w ih =>
    intro y hy
    have h2 : 2 ^ (w + 1) = 2 * 2 ^ w := by rw [Nat.pow_succ, Nat.mul_comm]
    have e1 : (2 ^ (w + 1) + y) % 2 = y % 2 := by omega
    have e2 : (2 ^ (w + 1) + y) / 2 = 2 ^ w + y / 2 := by omega
    rw [popNat_eq (2 ^ (w + 1) + y), e1, e2, ih (y / 2) (by omega), popNat_eq y]
    omega

/-- `popNat` agrees with `BitVec.cpop`, the `count_ones` of the Rust code. -/
theorem popNat_toNat : ∀ {w : Nat} (x : BitVec w), popNat x.toNat = x.cpop.toNat
  | 0, x => by
    rw [BitVec.toNat_of_zero_length rfl x, BitVec.toNat_of_zero_length rfl x.cpop, popNat_zero]
  | w + 1, x => by
    rw [← BitVec.cons_msb_setWidth x, BitVec.toNat_cons', BitVec.toNat_cpop_cons,
      ← popNat_toNat (x.setWidth w)]
    cases x.msb with
    | false => simp
    | true =>
      simp only [Bool.toNat_true, Nat.shiftLeft_eq, Nat.one_mul]
      exact popNat_two_pow_add w _ (BitVec.isLt _)

theorem cpop_not_add_cpop : ∀ {w : Nat} (x : BitVec w), (~~~x).cpop.toNat + x.cpop.toNat = w
  | 0, x => by
    rw [BitVec.toNat_of_zero_length rfl, BitVec.toNat_of_zero_length rfl]
  | w + 1, x => by
    rw [← BitVec.cons_msb_setWidth x, BitVec.not_cons, BitVec.toNat_cpop_cons,
      BitVec.toNat_cpop_cons]
    have := cpop_not_add_cpop (x.setWidth w)
    cases x.msb <;> simp <;> omega

/-! ## Members by host index -/

variable {n : Nat}

/-- The number of host positions, `n - popcount(m)`. -/
abbrev hostBits (m : BitVec n) : Nat := n - m.cpop.toNat

/-- `pdep(i, ¬m)` as an address. -/
def deposit (m : BitVec n) (i : Nat) : BitVec n := BitVec.ofNat n (pdepNat (~~~m).toNat i)

/-- The member of `S(a, m)` with host index `i`, `a ∨ pdep(i, ¬m)`. -/
def hostAddr (a m : BitVec n) (i : Nat) : BitVec n := a ||| deposit m i

/-- `(!m).count_ones()` is the number of host positions. -/
theorem cpop_not_eq_hostBits (m : BitVec n) : (~~~m).cpop.toNat = hostBits m := by
  have := cpop_not_add_cpop m
  unfold hostBits
  omega

theorem hostBits_le (m : BitVec n) : hostBits m ≤ n := Nat.sub_le _ _

theorem popNat_not (m : BitVec n) : popNat (~~~m).toNat = hostBits m := by
  have := cpop_not_add_cpop m
  rw [popNat_toNat]
  unfold hostBits
  omega

theorem pdepNat_lt_two_pow (m : BitVec n) (i : Nat) : pdepNat (~~~m).toNat i < 2 ^ n := by
  apply Nat.lt_pow_two_of_testBit
  intro b hb
  cases h : (pdepNat (~~~m).toNat i).testBit b with
  | false => rfl
  | true =>
    have := testBit_of_testBit_pdepNat h
    rw [BitVec.testBit_toNat, BitVec.getLsbD_of_ge _ _ hb] at this
    exact absurd this (by simp)

theorem toNat_deposit (m : BitVec n) (i : Nat) : (deposit m i).toNat = pdepNat (~~~m).toNat i := by
  rw [deposit, BitVec.toNat_ofNat, Nat.mod_eq_of_lt (pdepNat_lt_two_pow m i)]

/-- The deposited bits are host positions. -/
theorem getLsbD_deposit {m : BitVec n} {i b : Nat} (h : (deposit m i).getLsbD b = true) :
    m.getLsbD b = false := by
  rw [← BitVec.testBit_toNat, toNat_deposit] at h
  have := testBit_of_testBit_pdepNat h
  rw [BitVec.testBit_toNat, BitVec.getLsbD_not] at this
  simp only [Bool.and_eq_true, decide_eq_true_eq, Bool.not_eq_eq_eq_not, Bool.not_true] at this
  exact this.2

theorem hostAddr_mem {a m : BitVec n} (hn : Normalized a m) (i : Nat) : S a m (hostAddr a m i) := by
  unfold S hostAddr
  apply BitVec.eq_of_getLsbD_eq
  intro b _
  have t := getLsbD_congr hn b
  have hd : (deposit m i).getLsbD b = true → m.getLsbD b = false := getLsbD_deposit
  simp only [BitVec.getLsbD_and, BitVec.getLsbD_or] at t ⊢
  revert t hd
  cases a.getLsbD b <;> cases m.getLsbD b <;> cases (deposit m i).getLsbD b <;> simp

theorem toNat_le_of_and_eq {x y : BitVec n} (h : x &&& y = x) : x.toNat ≤ y.toNat := by
  rw [← h, BitVec.toNat_and]
  exact Nat.and_le_right

/-- The fixed and the host bits do not overlap, so the member is `a + pdep(i, ¬m)`. -/
theorem toNat_hostAddr {a m : BitVec n} (hn : Normalized a m) (i : Nat) :
    (hostAddr a m i).toNat = a.toNat + pdepNat (~~~m).toNat i := by
  have hdisj : a &&& deposit m i = 0#n := by
    apply BitVec.eq_of_getLsbD_eq
    intro b _
    have t := getLsbD_congr hn b
    have hd : (deposit m i).getLsbD b = true → m.getLsbD b = false := getLsbD_deposit
    simp only [BitVec.getLsbD_and, BitVec.getLsbD_zero] at t ⊢
    revert t hd
    cases a.getLsbD b <;> cases m.getLsbD b <;> cases (deposit m i).getLsbD b <;> simp
  have hsub : deposit m i &&& ~~~m = deposit m i := by
    apply BitVec.eq_of_getLsbD_eq
    intro b hb
    have hd : (deposit m i).getLsbD b = true → m.getLsbD b = false := getLsbD_deposit
    simp only [BitVec.getLsbD_and, BitVec.getLsbD_not, hb, decide_true, Bool.true_and]
    revert hd
    cases m.getLsbD b <;> cases (deposit m i).getLsbD b <;> simp
  have h1 := toNat_le_of_and_eq hn
  have h2 := toNat_le_of_and_eq hsub
  have h3 : (~~~m).toNat = 2 ^ n - 1 - m.toNat := BitVec.toNat_not
  have h4 := m.isLt
  unfold hostAddr
  rw [← BitVec.add_eq_or_of_and_eq_zero a (deposit m i) hdisj, BitVec.toNat_add,
    Nat.mod_eq_of_lt (by omega), toNat_deposit]

/-- The member is the sum `a + pdep(i, ¬m)`. -/
theorem hostAddr_eq_add {a m : BitVec n} (hn : Normalized a m) (i : Nat) :
    hostAddr a m i = a + deposit m i := by
  apply BitVec.eq_of_toNat_eq
  rw [toNat_hostAddr hn, BitVec.toNat_add, toNat_deposit, Nat.mod_eq_of_lt]
  rw [← toNat_hostAddr hn]
  exact BitVec.isLt _

/-- Host-index order is numeric order. -/
theorem hostAddr_lt_hostAddr {a m : BitVec n} (hn : Normalized a m) {i j : Nat} (hij : i < j)
    (hj : j < 2 ^ hostBits m) : hostAddr a m i < hostAddr a m j := by
  rw [BitVec.lt_def, toNat_hostAddr hn, toNat_hostAddr hn]
  have := pdepNat_lt_pdepNat (~~~m).toNat i j hij (by rw [popNat_not]; exact hj)
  omega

/-- Every member has a host index. -/
theorem exists_hostAddr {a m X : BitVec n} (hX : S a m X) :
    ∃ i < 2 ^ hostBits m, hostAddr a m i = X := by
  refine ⟨pextNat (~~~m).toNat (X &&& ~~~m).toNat, ?_, ?_⟩
  · rw [← popNat_not]
    exact pextNat_lt _ _
  · have hsub : ∀ b, (X &&& ~~~m).toNat.testBit b = true → (~~~m).toNat.testBit b = true := by
      intro b hb
      rw [BitVec.testBit_toNat, BitVec.getLsbD_and] at hb
      rw [BitVec.testBit_toNat]
      exact (Bool.and_eq_true _ _ ▸ hb).2
    unfold hostAddr deposit
    rw [pdepNat_pextNat _ _ hsub, BitVec.ofNat_toNat, BitVec.setWidth_eq]
    unfold S at hX
    rw [← hX]
    apply BitVec.eq_of_getLsbD_eq
    intro b hb
    simp only [BitVec.getLsbD_or, BitVec.getLsbD_and, BitVec.getLsbD_not, hb, decide_true,
      Bool.true_and]
    cases X.getLsbD b <;> cases m.getLsbD b <;> rfl

theorem hostAddr_zero (a m : BitVec n) : hostAddr a m 0 = a := by
  unfold hostAddr deposit
  rw [pdepNat_zero]
  simp

/-- The last host index gives `a ∨ ¬m`, the value of `last_addr`. -/
theorem hostAddr_last (a m : BitVec n) : hostAddr a m (2 ^ hostBits m - 1) = a ||| ~~~m := by
  unfold hostAddr deposit
  rw [← popNat_not, pdepNat_allOnes, BitVec.ofNat_toNat, BitVec.setWidth_eq]

/-- `hostAddr` on indices of exactly `n - popcount(m)` bits. -/
def hostAddrBV (a m : BitVec n) (i : BitVec (hostBits m)) : BitVec n := hostAddr a m i.toNat

/-- Depositing the index bits into the host positions is a strictly increasing
bijection from `BitVec (n - popcount m)` onto `S(a, m)`. -/
theorem hostIndex_bijection {a m : BitVec n} (hn : Normalized a m) :
    (∀ i, S a m (hostAddrBV a m i)) ∧
    (∀ i j, i < j → hostAddrBV a m i < hostAddrBV a m j) ∧
    (∀ X, S a m X → ∃ i, hostAddrBV a m i = X) := by
  refine ⟨fun i => hostAddr_mem hn _,
    fun i j hij => hostAddr_lt_hostAddr hn (BitVec.lt_def.mp hij) j.isLt, fun X hX => ?_⟩
  obtain ⟨i, hi, rfl⟩ := exists_hostAddr hX
  refine ⟨BitVec.ofNat _ i, ?_⟩
  unfold hostAddrBV
  rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt hi]

/-! ## The size of `S(a, m)` -/

/-- The members of `S(a, m)` in host-index order. -/
def members (a m : BitVec n) : List (BitVec n) := (List.range (2 ^ hostBits m)).map (hostAddr a m)

/-- Listing the members by host index lists every member once, in ascending order. -/
theorem members_spec {a m : BitVec n} (hn : Normalized a m) :
    (members a m).Pairwise (· < ·) ∧ (members a m).Nodup ∧
    (∀ X, X ∈ members a m ↔ S a m X) ∧ (members a m).length = 2 ^ hostBits m := by
  have hpw : (members a m).Pairwise (· < ·) := by
    unfold members
    rw [List.pairwise_map]
    exact List.pairwise_lt_range.imp_of_mem fun _ hj hij =>
      hostAddr_lt_hostAddr hn hij (List.mem_range.mp hj)
  refine ⟨hpw, hpw.imp BitVec.ne_of_lt, fun X => ?_, by simp [members]⟩
  unfold members
  rw [List.mem_map]
  constructor
  · rintro ⟨i, -, rfl⟩
    exact hostAddr_mem hn i
  · intro hX
    obtain ⟨i, hi, rfl⟩ := exists_hostAddr hX
    exact ⟨i, List.mem_range.mpr hi, rfl⟩

/-- Every address of width `n`, in ascending order. -/
def allAddrs (n : Nat) : List (BitVec n) := (List.range (2 ^ n)).map (BitVec.ofNat n)

theorem allAddrs_spec (n : Nat) : (allAddrs n).Nodup ∧ ∀ X : BitVec n, X ∈ allAddrs n := by
  refine ⟨?_, fun X => ?_⟩
  · unfold allAddrs
    rw [List.nodup_iff_pairwise_ne, List.pairwise_map]
    refine List.pairwise_lt_range.imp_of_mem fun {i j} hi hj hij heq => ?_
    have := congrArg BitVec.toNat heq
    rw [BitVec.toNat_ofNat, BitVec.toNat_ofNat, Nat.mod_eq_of_lt (List.mem_range.mp hi),
      Nat.mod_eq_of_lt (List.mem_range.mp hj)] at this
    omega
  · unfold allAddrs
    rw [List.mem_map]
    exact ⟨X.toNat, List.mem_range.mpr X.isLt, by simp⟩

/-- `|S(a, m)| = 2^(n - popcount m)`: that many of the `2^n` addresses are members. -/
theorem card_S {a m : BitVec n} (hn : Normalized a m) :
    (allAddrs n).countP (fun X => X &&& m == a) = 2 ^ (n - m.cpop.toNat) := by
  obtain ⟨-, hnd, hmem, hlen⟩ := members_spec hn
  have hperm : ((allAddrs n).filter (fun X => X &&& m == a)).Perm (members a m) := by
    rw [List.perm_ext_iff_of_nodup ((allAddrs_spec n).1.filter _) hnd]
    intro X
    rw [List.mem_filter, hmem X]
    simp [(allAddrs_spec n).2 X, S]
  rw [List.countP_eq_length_filter, hperm.length_eq, hlen]

end Netip
