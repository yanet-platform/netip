import Netip.Contiguous
import Std.Tactic.BVDecide

/-!
# Contiguous ⟺ interval

`S(a, m)` is an interval of the integer order iff `m` is contiguous, at every
width `n` (`interval_iff_contiguous`).

Two addresses that agree above bit `b` and differ at `b` compare as their bit `b`
(`lt_of_getLsbD`). A contiguous mask fixes every position above a fixed one
(`contiguous_iff_upward`). So if an address between two members is not a member,
take the highest fixed position where it differs from `a`: above it all three
agree, and at it the address lies above the upper member or below the lower one.

For the "only if" half, a non-contiguous mask has a free bit `j` above a fixed
bit `i`, and `hole a i j` is a non-member strictly between the members `a` and
`a ∨ 2^j`. Flipping bit `i` of `a` works when that bit of `a` is clear. When it
is set, the flip lands below `a`, the smallest member, so the bit is cleared in
`a ∨ 2^j` instead.

At the widths the library uses, `Contiguous` is exactly the Rust check
`m | (m - 1) == MAX` (`contiguous_iff_32`, `contiguous_iff_128`), which gives the
theorem in the form of `is_contiguous` (`interval_iff_contiguous_32`,
`interval_iff_contiguous_128`).
-/

namespace Netip

variable {n : Nat}

theorem exists_least {P : Nat → Prop} : ∀ i, P i → ∃ j, P j ∧ ∀ l < j, ¬ P l := by
  intro i
  induction i using Nat.strongRecOn with
  | ind i ih =>
    intro hi
    by_cases h : ∃ l < i, P l
    · obtain ⟨l, hl, hPl⟩ := h
      exact ih l hl hPl
    · exact ⟨i, hi, fun l hl hPl => h ⟨l, hl, hPl⟩⟩

/-- Two addresses that agree above bit `b` compare as their bit `b`. -/
theorem lt_of_getLsbD : ∀ {n : Nat} {x y : BitVec n} {b : Nat}, b < n →
    x.getLsbD b = false → y.getLsbD b = true →
    (∀ p, b < p → p < n → x.getLsbD p = y.getLsbD p) → x < y
  | 0, _, _, _, hb, _, _, _ => absurd hb (Nat.not_lt_zero _)
  | n + 1, x, y, b, hb, hx, hy, hagree => by
    rw [← BitVec.cons_msb_setWidth x, ← BitVec.cons_msb_setWidth y, BitVec.lt_def,
      BitVec.toNat_cons', BitVec.toNat_cons']
    by_cases hbn : b = n
    · subst hbn
      have hxm : x.msb = false := by rw [BitVec.msb_eq_getLsbD_last]; simpa using hx
      have hym : y.msb = true := by rw [BitVec.msb_eq_getLsbD_last]; simpa using hy
      rw [hxm, hym]
      have := (x.setWidth b).isLt
      simp only [Bool.toNat_false, Bool.toNat_true, Nat.shiftLeft_eq, Nat.one_mul]
      omega
    · have hbn' : b < n := by omega
      have hmsb : x.msb = y.msb := by
        rw [BitVec.msb_eq_getLsbD_last, BitVec.msb_eq_getLsbD_last]
        simpa using hagree n (by omega) (by omega)
      have ih := lt_of_getLsbD (x := x.setWidth n) (y := y.setWidth n) hbn'
        (by simpa [BitVec.getLsbD_setWidth, hbn'] using hx)
        (by simpa [BitVec.getLsbD_setWidth, hbn'] using hy)
        (fun p hp hpn => by
          simp only [BitVec.getLsbD_setWidth, hpn, decide_true, Bool.true_and]
          exact hagree p hp (by omega))
      rw [BitVec.lt_def] at ih
      rw [hmsb]
      omega

/-- A mask is contiguous iff every position above a fixed one is fixed. -/
theorem contiguous_iff_upward {m : BitVec n} :
    Contiguous m ↔ ∀ i j, i < j → j < n → m.getLsbD i = true → m.getLsbD j = true := by
  constructor
  · rintro ⟨k, -, hk⟩ i j hij hjn hi
    rw [BitVec.getLsbD_eq_getMsbD] at hi ⊢
    rw [hk (n - 1 - i) (by omega)] at hi
    rw [hk (n - 1 - j) (by omega)]
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hi ⊢
    omega
  · intro hup
    by_cases hz : ∃ i, m.getLsbD i = true
    · obtain ⟨i, hi⟩ := hz
      obtain ⟨i0, hi0, hmin⟩ := exists_least (P := fun i => m.getLsbD i = true) i hi
      have hi0n : i0 < n := by
        apply Classical.byContradiction
        intro h
        rw [BitVec.getLsbD_of_ge m i0 (by omega)] at hi0
        exact absurd hi0 (by simp)
      refine ⟨n - i0, by omega, fun p hp => ?_⟩
      rw [BitVec.getMsbD_eq_getLsbD]
      simp only [hp, decide_true, Bool.true_and]
      by_cases hpk : p < n - i0
      · rw [decide_eq_true hpk]
        by_cases he : n - 1 - p = i0
        · rw [he]
          exact hi0
        · exact hup i0 (n - 1 - p) (by omega) (by omega) hi0
      · rw [decide_eq_false hpk]
        cases h : m.getLsbD (n - 1 - p)
        · rfl
        · exact absurd h (hmin (n - 1 - p) (by omega))
    · refine ⟨0, Nat.zero_le _, fun p _ => ?_⟩
      rw [BitVec.getMsbD_eq_getLsbD]
      cases h : m.getLsbD (n - 1 - p)
      · simp
      · exact absurd ⟨_, h⟩ hz

/-- A non-member between `a` and `a ∨ 2^j`, for a free bit `j` above a fixed bit `i`. -/
def hole (a : BitVec n) (i j : Nat) : BitVec n :=
  if a.getLsbD i then (a ||| BitVec.twoPow n j) &&& ~~~(BitVec.twoPow n i)
  else a ||| BitVec.twoPow n i

theorem hole_between {a m : BitVec n} (hn : Normalized a m) {i j : Nat} (hij : i < j)
    (hjn : j < n) (hi : m.getLsbD i = true) (hj : m.getLsbD j = false) :
    S a m (a ||| BitVec.twoPow n j) ∧ ¬ S a m (hole a i j) ∧ a < hole a i j ∧
      hole a i j < a ||| BitVec.twoPow n j := by
  have hin : i < n := by omega
  have ha : ∀ p, a.getLsbD p = (a.getLsbD p && m.getLsbD p) := fun p => by
    have := getLsbD_congr hn p
    rw [BitVec.getLsbD_and] at this
    exact this.symm
  have haj : a.getLsbD j = false := by rw [ha j, hj, Bool.and_false]
  have hmem : S a m (a ||| BitVec.twoPow n j) := by
    apply BitVec.eq_of_getLsbD_eq
    intro p hp
    simp only [BitVec.getLsbD_and, BitVec.getLsbD_or, BitVec.getLsbD_twoPow, hjn, decide_true,
      Bool.true_and]
    by_cases hpj : j = p
    · subst hpj
      rw [hj, haj]
      simp
    · simp only [hpj, decide_false, Bool.or_false]
      exact (ha p).symm
  refine ⟨hmem, ?_, ?_⟩
  · intro hs
    have t := getLsbD_congr hs i
    unfold hole at t
    simp only [BitVec.getLsbD_and] at t
    cases hai : a.getLsbD i
    · simp only [hai, Bool.false_eq_true, ↓reduceIte, BitVec.getLsbD_or, BitVec.getLsbD_twoPow,
        hin, decide_true, Bool.true_and, Bool.or_true, hi] at t
      exact absurd t (by simp)
    · simp only [hai, ↓reduceIte, BitVec.getLsbD_and, BitVec.getLsbD_not, BitVec.getLsbD_twoPow,
        hin, decide_true, Bool.true_and, Bool.not_true, Bool.and_false, Bool.false_and] at t
      exact absurd t (by simp)
  · have hji : j ≠ i := Nat.ne_of_gt hij
    have hij' : i ≠ j := Nat.ne_of_lt hij
    unfold hole
    cases hai : a.getLsbD i
    · simp only [Bool.false_eq_true, ↓reduceIte]
      constructor
      · apply lt_of_getLsbD hin hai
        · simp [hin]
        · intro p hp _
          have h : i ≠ p := by omega
          simp [h]
      · apply lt_of_getLsbD hjn
        · simp [haj, hij']
        · simp [hjn]
        · intro p hp _
          have h1 : i ≠ p := by omega
          have h2 : j ≠ p := by omega
          simp [h1, h2]
    · simp only [↓reduceIte]
      constructor
      · apply lt_of_getLsbD hjn haj
        · simp [hjn, hji]
        · intro p hp hpn
          have h1 : p ≠ i := by omega
          have h2 : p ≠ j := by omega
          simp [h1, h2, hpn]
      · apply lt_of_getLsbD hin
        · simp
        · simp [hai]
        · intro p hp hpn
          have h : p ≠ i := by omega
          simp [h, hpn]

/-- `S(a, m)` is closed under betweenness iff `m` is contiguous. -/
theorem interval_iff_contiguous {a m : BitVec n} (hn : Normalized a m) :
    (∀ x y z, S a m x → S a m z → x ≤ y → y ≤ z → S a m y) ↔ Contiguous m := by
  rw [contiguous_iff_upward]
  constructor
  · intro hI i j hij hjn hi
    apply Classical.byContradiction
    intro hj
    have hj' : m.getLsbD j = false := by simpa using hj
    obtain ⟨hmem, hnot, hlo, hhi⟩ := hole_between hn hij hjn hi hj'
    exact hnot (hI _ _ _ hn hmem (BitVec.le_of_lt hlo) (BitVec.le_of_lt hhi))
  · intro hup x y z hx hz hxy hyz
    apply Classical.byContradiction
    intro hy
    have ha : ∀ p, a.getLsbD p = (a.getLsbD p && m.getLsbD p) := fun p => by
      have := getLsbD_congr hn p
      rw [BitVec.getLsbD_and] at this
      exact this.symm
    -- the positions where `y` breaks membership are fixed positions where it differs from `a`
    have hex : ∃ d, d < n ∧ m.getLsbD (n - 1 - d) = true ∧
        y.getLsbD (n - 1 - d) ≠ a.getLsbD (n - 1 - d) := by
      apply Classical.byContradiction
      intro hno
      apply hy
      apply BitVec.eq_of_getLsbD_eq
      intro p hp
      rw [BitVec.getLsbD_and, ha p]
      cases hmp : m.getLsbD p
      · simp
      · have : y.getLsbD p = a.getLsbD p := by
          apply Classical.byContradiction
          intro hne
          exact hno ⟨n - 1 - p, by omega, by rw [show n - 1 - (n - 1 - p) = p by omega]; exact hmp,
            by rw [show n - 1 - (n - 1 - p) = p by omega]; exact hne⟩
        rw [this]
    obtain ⟨d0, hd0⟩ := hex
    obtain ⟨d, ⟨hdn, hmb, hyb⟩, hmin⟩ := exists_least (P := fun d => d < n ∧
      m.getLsbD (n - 1 - d) = true ∧ y.getLsbD (n - 1 - d) ≠ a.getLsbD (n - 1 - d)) d0 hd0
    -- `b` is the highest fixed position where `y` differs from `a`
    have hb : n - 1 - d < n := by omega
    have habove : ∀ p, n - 1 - d < p → p < n →
        x.getLsbD p = y.getLsbD p ∧ y.getLsbD p = z.getLsbD p := by
      intro p hp hpn
      have hmp : m.getLsbD p = true := hup _ _ hp hpn hmb
      have hyp : y.getLsbD p = a.getLsbD p := by
        apply Classical.byContradiction
        intro hne
        exact hmin (n - 1 - p) (by omega)
          ⟨by omega, by rw [show n - 1 - (n - 1 - p) = p by omega]; exact hmp,
            by rw [show n - 1 - (n - 1 - p) = p by omega]; exact hne⟩
      have hxp := getLsbD_congr hx p
      have hzp := getLsbD_congr hz p
      simp only [BitVec.getLsbD_and, hmp, Bool.and_true] at hxp hzp
      exact ⟨hxp.trans hyp.symm, hyp.trans hzp.symm⟩
    have hxb := getLsbD_congr hx (n - 1 - d)
    have hzb := getLsbD_congr hz (n - 1 - d)
    simp only [BitVec.getLsbD_and, hmb, Bool.and_true] at hxb hzb
    cases hyv : y.getLsbD (n - 1 - d)
    · -- `y` is below `x`
      have hxv : x.getLsbD (n - 1 - d) = true := by
        rw [hxb]
        cases hav : a.getLsbD (n - 1 - d)
        · exact absurd (hyv.trans hav.symm) hyb
        · rfl
      have := lt_of_getLsbD hb hyv hxv fun p hp hpn => (habove p hp hpn).1.symm
      exact absurd hxy (BitVec.not_le.mpr this)
    · -- `y` is above `z`
      have hzv : z.getLsbD (n - 1 - d) = false := by
        rw [hzb]
        cases hav : a.getLsbD (n - 1 - d)
        · rfl
        · exact absurd (hyv.trans hav.symm) hyb
      have := lt_of_getLsbD hb hzv hyv fun p hp hpn => (habove p hp hpn).2.symm
      exact absurd hyz (BitVec.not_le.mpr this)

/-! ## The Rust check -/

theorem upward_of_step {m : BitVec n}
    (h : ∀ p, p + 1 < n → m.getLsbD p = true → m.getLsbD (p + 1) = true) :
    ∀ i j, i < j → j < n → m.getLsbD i = true → m.getLsbD j = true := by
  intro i j
  induction j with
  | zero => intro hij; omega
  | succ j ih =>
    intro hij hjn hi
    by_cases he : i = j
    · subst he
      exact h i hjn hi
    · exact h j hjn (ih (by omega) (by omega) hi)

/-- `Contiguous` as a bit identity: no fixed bit sits right below a free one. -/
theorem contiguous_iff_shl {m : BitVec n} : Contiguous m ↔ (m <<< 1) &&& ~~~m = 0#n := by
  rw [contiguous_iff_upward]
  constructor
  · intro hup
    apply BitVec.eq_of_getLsbD_eq
    intro p hp
    simp only [BitVec.getLsbD_and, BitVec.getLsbD_shiftLeft, BitVec.getLsbD_not, hp, decide_true,
      Bool.true_and, BitVec.getLsbD_zero]
    by_cases hp0 : p < 1
    · simp [hp0]
    · cases hm : m.getLsbD (p - 1)
      · simp
      · rw [hup (p - 1) p (by omega) hp hm]
        simp
  · intro h
    apply upward_of_step
    intro p hp hm
    have t := getLsbD_congr h (p + 1)
    simp only [BitVec.getLsbD_and, BitVec.getLsbD_shiftLeft, BitVec.getLsbD_not, hp, decide_true,
      Bool.true_and, BitVec.getLsbD_zero, Nat.add_sub_cancel, hm] at t
    simpa using t

theorem contiguous_iff_32 (m : BitVec 32) : Contiguous m ↔ m ||| (m - 1) = BitVec.allOnes 32 := by
  rw [contiguous_iff_shl]
  bv_decide

theorem contiguous_iff_128 (m : BitVec 128) :
    Contiguous m ↔ m ||| (m - 1) = BitVec.allOnes 128 := by
  rw [contiguous_iff_shl]
  bv_decide

/-- `S(a, m)` is closed under betweenness iff `m` passes `is_contiguous`. -/
theorem interval_iff_contiguous_32 (a m : BitVec 32) (hn : Normalized a m) :
    (∀ x y z, S a m x → S a m z → x ≤ y → y ≤ z → S a m y) ↔
      m ||| (m - 1) = BitVec.allOnes 32 :=
  (interval_iff_contiguous hn).trans (contiguous_iff_32 m)

theorem interval_iff_contiguous_128 (a m : BitVec 128) (hn : Normalized a m) :
    (∀ x y z, S a m x → S a m z → x ≤ y → y ≤ z → S a m y) ↔
      m ||| (m - 1) = BitVec.allOnes 128 :=
  (interval_iff_contiguous hn).trans (contiguous_iff_128 m)

end Netip
