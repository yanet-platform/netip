import Netip.Impl.Difference

/-!
# `difference` over a whole run, and minimality

`Difference` proves each step of `Ipv4NetworkDiff` / `Ipv6NetworkDiff`. Here the
steps are chained over an arbitrary schedule of `next()` and `next_back()` calls
(`diffRun`), and the result is compared with every other way of writing the
difference:

* `difference_run`: a schedule of at least `popcount(d)` calls emits exactly
  `popcount(d)` networks, one per bit of `d`, which are pairwise disjoint and
  whose union is `S(A) \ S(B)`. Calls after that emit nothing.
* `difference_minimal`: every list of networks whose union is `S(A) \ S(B)` has
  at least `popcount(d)` members, so the iterator's output is a minimum cover.

The minimality argument: for each bit `b` of `d`, the address `ia ⊕ b` lies in
`S(A) \ S(B)`, and no network inside `S(A) \ S(B)` holds two of them, since a
network holding `ia ⊕ b` and `ia ⊕ c` also holds `ia`, which is in `S(B)`.
-/

namespace Netip.Impl

variable {w : Nat}

/-- The OR of a list of masks. -/
def orAll (l : List (BitVec w)) : BitVec w := l.foldr (· ||| ·) 0

/-! ## Counting set bits -/

/-- The one-hot masks of the set bits of `x` below position `n`. -/
def setBits (x : BitVec w) : Nat → List (BitVec w)
  | 0 => []
  | n + 1 => (if x.getLsbD n then [BitVec.twoPow w n] else []) ++ setBits x n

theorem length_setBits (x : BitVec w) (n : Nat) : (setBits x n).length = x.cpopNatRec n 0 := by
  induction n with
  | zero => rfl
  | succ n ih =>
    rw [setBits, List.length_append, ih, BitVec.cpopNatRec_succ, Nat.zero_add,
      BitVec.cpopNatRec_eq (acc := (x.getLsbD n).toNat)]
    cases x.getLsbD n <;> simp <;> omega

/-- `count_ones` counts `setBits`. -/
theorem length_setBits_eq_cpop (x : BitVec w) : (setBits x w).length = x.cpop.toNat := by
  rw [length_setBits, BitVec.toNat_cpop]

theorem mem_setBits {x b : BitVec w} {n : Nat} (h : b ∈ setBits x n) :
    ∃ i < n, x.getLsbD i = true ∧ b = BitVec.twoPow w i := by
  induction n with
  | zero => simp [setBits] at h
  | succ n ih =>
    simp only [setBits, List.mem_append] at h
    rcases h with h | h
    · split at h
      · rename_i hx
        simp only [List.mem_singleton] at h
        exact ⟨n, by omega, hx, h⟩
      · simp at h
    · obtain ⟨i, hi, hx, rfl⟩ := ih h
      exact ⟨i, by omega, hx, rfl⟩

theorem twoPow_ne_twoPow {i j : Nat} (hi : i < w) (hij : i ≠ j) :
    BitVec.twoPow w i ≠ BitVec.twoPow w j := by
  intro h
  have := congrArg (BitVec.getLsbD · i) h
  simp [hi, hij] at this

theorem nodup_setBits (x : BitVec w) (n : Nat) (hn : n ≤ w) : (setBits x n).Nodup := by
  induction n with
  | zero => simp [setBits]
  | succ n ih =>
    simp only [setBits]
    split
    · rw [List.singleton_append, List.nodup_cons]
      refine ⟨fun hmem => ?_, ih (by omega)⟩
      obtain ⟨i, hi, _, heq⟩ := mem_setBits hmem
      exact twoPow_ne_twoPow (by omega) (by omega : n ≠ i) heq
    · simpa using ih (by omega)

theorem twoPow_and_of_getLsbD {x : BitVec w} {i : Nat} (hi : i < w) (hx : x.getLsbD i = true) :
    BitVec.twoPow w i &&& x = BitVec.twoPow w i := by
  apply BitVec.eq_of_getLsbD_eq
  intro j hj
  simp only [BitVec.getLsbD_and, BitVec.getLsbD_twoPow]
  by_cases h : i = j
  · subst h
    simp [hi, hx]
  · simp [h]

theorem twoPow_ne_zero' {i : Nat} (hi : i < w) : BitVec.twoPow w i ≠ 0 := by
  intro h
  have := congrArg (BitVec.getLsbD · i) h
  simp [hi] at this

theorem twoPow_and_twoPow {i j : Nat} (hij : i ≠ j) :
    BitVec.twoPow w i &&& BitVec.twoPow w j = 0 := by
  apply BitVec.eq_of_getLsbD_eq
  intro k hk
  simp only [BitVec.getLsbD_and, BitVec.getLsbD_twoPow]
  by_cases h1 : i = k <;> by_cases h2 : j = k <;> simp_all

/-- An injection from a duplicate-free list into a list bounds the lengths. -/
theorem length_le_of_inj {α β : Type} [DecidableEq β] (P : α → β → Prop) :
    ∀ (L : List α) (C : List β), L.Nodup → (∀ b ∈ L, ∃ N ∈ C, P b N) →
      (∀ b ∈ L, ∀ c ∈ L, ∀ N ∈ C, P b N → P c N → b = c) → L.length ≤ C.length := by
  intro L
  induction L with
  | nil => intro C _ _ _; exact Nat.zero_le _
  | cons b L ih =>
    intro C hnd hcov huniq
    obtain ⟨N, hN, hbN⟩ := hcov b List.mem_cons_self
    have hnd' := List.nodup_cons.mp hnd
    have hrest : L.length ≤ (C.erase N).length := by
      apply ih (C.erase N) hnd'.2
      · intro c hc
        obtain ⟨N', hN', hcN'⟩ := hcov c (List.mem_cons_of_mem _ hc)
        refine ⟨N', ?_, hcN'⟩
        have hne : N' ≠ N := by
          rintro rfl
          have := huniq b List.mem_cons_self c (List.mem_cons_of_mem _ hc) N' hN hbN hcN'
          subst this
          exact hnd'.1 hc
        exact (List.mem_erase_of_ne hne).mpr hN'
      · intro c hc d hd N' hN' h1 h2
        exact huniq c (List.mem_cons_of_mem _ hc) d (List.mem_cons_of_mem _ hd) N'
          (List.mem_of_mem_erase hN') h1 h2
    rw [List.length_erase_of_mem hN] at hrest
    have : 0 < C.length := List.length_pos_of_mem hN
    simp only [List.length_cons]
    omega

namespace Ipv4

/-! ## Minimality -/

theorem diff_point_mem (a1 m1 a2 m2 b : BitVec 32) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (hi : a1 &&& m2 = a2 &&& m1) (hb0 : b ≠ 0) (hbd : b &&& diffBits m1 m2 = b) :
    ((a1 ||| a2) ^^^ b) &&& m1 = a1 ∧ ((a1 ||| a2) ^^^ b) &&& m2 ≠ a2 := by
  unfold diffBits at hbd
  bv_decide

theorem diff_points_separate (a1 m1 a2 m2 b c cN mN : BitVec 32) (h1 : a1 &&& m1 = a1)
    (h2 : a2 &&& m2 = a2) (hi : a1 &&& m2 = a2 &&& m1) (hbc : b &&& c = 0)
    (hb : ((a1 ||| a2) ^^^ b) &&& mN = cN) (hc : ((a1 ||| a2) ^^^ c) &&& mN = cN) :
    (a1 ||| a2) &&& mN = cN ∧ (a1 ||| a2) &&& m2 = a2 := by
  bv_decide

/-- Every list of networks whose union is `S(A) \ S(B)` has at least `popcount(d)`
members. -/
theorem difference_minimal (a1 m1 a2 m2 : BitVec 32) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (hi : a1 &&& m2 = a2 &&& m1) (C : List (BitVec 32 × BitVec 32))
    (hC : ∀ X, (∃ N ∈ C, X &&& N.2 = N.1) ↔ (X &&& m1 = a1 ∧ X &&& m2 ≠ a2)) :
    (diffBits m1 m2).cpop.toNat ≤ C.length := by
  rw [← length_setBits_eq_cpop]
  apply length_le_of_inj (fun b (N : BitVec 32 × BitVec 32) => ((a1 ||| a2) ^^^ b) &&& N.2 = N.1)
  · exact nodup_setBits _ _ (Nat.le_refl _)
  · intro b hb
    obtain ⟨i, hi', hx, rfl⟩ := mem_setBits hb
    exact (hC _).2 (diff_point_mem a1 m1 a2 m2 _ h1 h2 hi (twoPow_ne_zero' hi')
      (twoPow_and_of_getLsbD hi' hx))
  · intro b hb c hc N hN hbN hcN
    obtain ⟨i, hi', -, rfl⟩ := mem_setBits hb
    obtain ⟨j, -, -, rfl⟩ := mem_setBits hc
    by_cases hij : i = j
    · rw [hij]
    · exfalso
      obtain ⟨hia, hib⟩ := diff_points_separate a1 m1 a2 m2 _ _ N.1 N.2 h1 h2 hi
        (twoPow_and_twoPow hij) hbN hcN
      exact ((hC _).1 ⟨N, hN, hia⟩).2 hib

/-! ## A whole run -/

/-- One call on the state `(mask, remaining)`: `true` is `next()`, `false` is
`next_back()`. Emits the peeled bit and the mask of the network it yields. -/
def diffStep (front : Bool) (s : BitVec 32 × BitVec 32) :
    Option (BitVec 32 × BitVec 32) × (BitVec 32 × BitVec 32) :=
  if s.2 = 0 then (none, s)
  else if front then
    (some (highestBit32 s.2, s.1 ||| highestBit32 s.2),
      (s.1 ||| highestBit32 s.2, s.2 ^^^ highestBit32 s.2))
  else (some (lowestBit s.2, s.1 ||| s.2), (s.1, s.2 ^^^ lowestBit s.2))

/-- Runs a schedule of calls, collecting what they emit. -/
def diffRun : List Bool → BitVec 32 × BitVec 32 →
    List (BitVec 32 × BitVec 32) × (BitVec 32 × BitVec 32)
  | [], s => ([], s)
  | f :: fs, s =>
    ((diffStep f s).1.toList ++ (diffRun fs (diffStep f s).2).1, (diffRun fs (diffStep f s).2).2)

theorem diffStep_none (f : Bool) (s : BitVec 32 × BitVec 32) (h : (diffStep f s).1 = none) :
    s.2 = 0 ∧ (diffStep f s).2 = s := by
  unfold diffStep at *
  by_cases hr : s.2 = 0
  · simp [hr]
  · simp only [hr, ↓reduceIte] at h
    cases f <;> simp at h

theorem diffStep_some (m1 d : BitVec 32) (f : Bool) (s : BitVec 32 × BitVec 32)
    (h : Inv m1 d s.1 s.2) (b M : BitVec 32) (hs : (diffStep f s).1 = some (b, M)) :
    M = itemMask m1 d b ∧ b &&& (b - 1) = 0 ∧ b ≠ 0 ∧ b &&& s.2 = b ∧
      (diffStep f s).2.2 = s.2 ^^^ b ∧ Inv m1 d (diffStep f s).2.1 (diffStep f s).2.2 := by
  obtain ⟨mask, r⟩ := s
  by_cases hr : r = 0
  · simp [diffStep, hr] at hs
  · cases f
    · simp only [diffStep, hr, ↓reduceIte, Bool.false_eq_true, Option.some.injEq,
        Prod.mk.injEq] at hs ⊢
      obtain ⟨rfl, rfl⟩ := hs
      have := nextBack_emits m1 d mask r h hr
      refine ⟨this.1, ?_, ?_, ?_, rfl, this.2⟩ <;> unfold lowestBit <;> bv_decide
    · simp only [diffStep, hr, ↓reduceIte, Option.some.injEq, Prod.mk.injEq] at hs ⊢
      obtain ⟨rfl, rfl⟩ := hs
      have := next_emits m1 d mask r h hr
      refine ⟨this.1, ?_, ?_, ?_, rfl, this.2⟩ <;> unfold highestBit32 <;> bv_decide

theorem cpop_xor_bit (r b : BitVec 32) (hb : b &&& (b - 1) = 0) (hb0 : b ≠ 0) (hbr : b &&& r = b) :
    (r ^^^ b).cpop.toNat + 1 = r.cpop.toNat := by
  have h : (r ^^^ b).cpop + 1 = r.cpop := by bv_decide
  have hle := BitVec.toNat_cpop_le (r ^^^ b)
  rw [← h, BitVec.toNat_add]
  simp
  omega

theorem eq_zero_of_cpop (r : BitVec 32) (h : r.cpop.toNat = 0) : r = 0 := by
  have hc : r.cpop = 0#32 := BitVec.eq_of_toNat_eq (by simpa using h)
  bv_decide

/-- What a run from state `s` produced. -/
def RunSpec (m1 d : BitVec 32) (s : BitVec 32 × BitVec 32)
    (res : List (BitVec 32 × BitVec 32) × (BitVec 32 × BitVec 32)) (calls : Nat) : Prop :=
  Inv m1 d res.2.1 res.2.2 ∧
  (∀ e ∈ res.1, e.2 = itemMask m1 d e.1 ∧ e.1 &&& (e.1 - 1) = 0 ∧ e.1 ≠ 0 ∧ e.1 &&& s.2 = e.1) ∧
  (res.1.map Prod.fst).Pairwise (fun b c => b &&& c = 0) ∧
  orAll (res.1.map Prod.fst) ||| res.2.2 = s.2 ∧
  orAll (res.1.map Prod.fst) &&& res.2.2 = 0 ∧
  res.1.length + res.2.2.cpop.toNat = s.2.cpop.toNat ∧
  (s.2.cpop.toNat ≤ calls → res.2.2 = 0)

/-- A run emits distinct one-hot bits of `remaining`, each with its item mask,
removes them from `remaining`, and empties it given enough calls. -/
theorem diffRun_spec (m1 d : BitVec 32) (fs : List Bool) :
    ∀ s : BitVec 32 × BitVec 32, Inv m1 d s.1 s.2 → RunSpec m1 d s (diffRun fs s) fs.length := by
  induction fs with
  | nil =>
    intro s h
    simp only [RunSpec, diffRun, List.map_nil, List.Pairwise.nil, orAll, List.foldr_nil,
      List.length_nil, List.not_mem_nil, false_implies, implies_true, true_and, Nat.zero_add]
    refine ⟨h, by bv_decide, by bv_decide, fun hle => eq_zero_of_cpop _ (by omega)⟩
  | cons f fs ih =>
    intro s h
    simp only [diffRun, List.length_cons]
    cases hds : (diffStep f s).1 with
    | none =>
      obtain ⟨hs0, hseq⟩ := diffStep_none f s hds
      have hinv0 : Inv m1 d (diffStep f s).2.1 (diffStep f s).2.2 := by
        rw [hseq]
        exact h
      have hih := ih (diffStep f s).2 hinv0
      simp only [Option.toList_none, List.nil_append, Prod.eta]
      rw [hseq] at hih ⊢
      obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := hih
      refine ⟨h1, h2, h3, h4, h5, h6, fun _ => ?_⟩
      have : s.2.cpop.toNat = 0 := by rw [hs0]; simp
      exact h7 (by omega)
    | some e =>
      obtain ⟨b, M⟩ := e
      obtain ⟨hM, hb1, hb0, hbs, hr', hinv⟩ := diffStep_some m1 d f s h b M hds
      obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := ih (diffStep f s).2 hinv
      rw [hr'] at h2 h4 h6 h7
      simp only [Option.toList_some, List.singleton_append]
      generalize diffRun fs (diffStep f s).2 = R at h1 h2 h3 h4 h5 h6 h7 ⊢
      generalize hL : R.1.map Prod.fst = L at h3 h4 h5
      have hsubL : ∀ c ∈ L, c &&& (s.2 ^^^ b) = c := by
        intro c hc
        rw [← hL] at hc
        obtain ⟨e, he, rfl⟩ := List.mem_map.mp hc
        exact (h2 e he).2.2.2
      refine ⟨h1, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · intro e he
        rcases List.mem_cons.mp he with rfl | he
        · exact ⟨hM, hb1, hb0, hbs⟩
        · obtain ⟨he1, he2, he3, he4⟩ := h2 e he
          exact ⟨he1, he2, he3, by bv_decide⟩
      · simp only [List.map_cons, hL, List.pairwise_cons]
        refine ⟨fun c hc => ?_, h3⟩
        have := hsubL c hc
        bv_decide
      · simp only [List.map_cons, hL, orAll, List.foldr_cons] at h4 ⊢
        bv_decide
      · simp only [List.map_cons, hL, orAll, List.foldr_cons] at h4 h5 ⊢
        bv_decide
      · have := cpop_xor_bit s.2 b hb1 hb0 hbs
        simp only [List.length_cons]
        omega
      · intro hle
        have := cpop_xor_bit s.2 b hb1 hb0 hbs
        exact h7 (by omega)

theorem mem_of_one_hot_sub_orAll (L : List (BitVec 32)) (b : BitVec 32) (hb : b &&& (b - 1) = 0)
    (hb0 : b ≠ 0) (hL : ∀ x ∈ L, x &&& (x - 1) = 0 ∧ x ≠ 0) (hsub : b &&& orAll L = b) : b ∈ L := by
  induction L with
  | nil =>
    simp only [orAll, List.foldr_nil] at hsub
    exact absurd (by bv_decide) hb0
  | cons x L ih =>
    simp only [orAll, List.foldr_cons] at hsub
    obtain ⟨hx, hx0⟩ := hL x List.mem_cons_self
    have : b = x ∨ b &&& orAll L = b := by
      simp only [orAll]
      bv_decide
    rcases this with rfl | h
    · exact List.mem_cons_self
    · exact List.mem_cons_of_mem _ (ih (fun y hy => hL y (List.mem_cons_of_mem _ hy)) h)

/-- Any schedule of at least `popcount(d)` calls on `Ipv4NetworkDiff`, from the
general case of `new()`, emits exactly `popcount(d)` pairwise disjoint networks
whose union is `S(A) \ S(B)`. By `difference_minimal` no cover is smaller. -/
theorem difference_run (a1 m1 a2 m2 : BitVec 32) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (hi : a1 &&& m2 = a2 &&& m1) (fs : List Bool) (hfs : (diffBits m1 m2).cpop.toNat ≤ fs.length) :
    (diffRun fs (m1, diffBits m1 m2)).1.length = (diffBits m1 m2).cpop.toNat ∧
    (∀ e ∈ (diffRun fs (m1, diffBits m1 m2)).1, e.2 = itemMask m1 (diffBits m1 m2) e.1) ∧
    (∀ X, (X &&& m1 = a1 ∧ X &&& m2 ≠ a2) ↔
      ∃ e ∈ (diffRun fs (m1, diffBits m1 m2)).1, X &&& e.2 = ((a1 ||| a2) ^^^ e.1) &&& e.2) ∧
    (diffRun fs (m1, diffBits m1 m2)).1.Pairwise (fun e f =>
      ∀ X, ¬ (X &&& e.2 = ((a1 ||| a2) ^^^ e.1) &&& e.2 ∧ X &&& f.2 = ((a1 ||| a2) ^^^ f.1) &&& f.2)) := by
  obtain ⟨-, hitems, hpw, hor, -, hlen, hdone⟩ :=
    diffRun_spec m1 (diffBits m1 m2) fs (m1, diffBits m1 m2) (inv_init m1 _)
  simp only at hitems hor hlen hdone
  have hz := hdone hfs
  rw [hz] at hor hlen
  generalize diffRun fs (m1, diffBits m1 m2) = R at *
  refine ⟨by simpa using hlen, fun e he => (hitems e he).1, fun X => ⟨?_, ?_⟩, ?_⟩
  · intro ⟨hA, hB⟩
    obtain ⟨c0, c1, c2⟩ := item_cover a1 m1 a2 m2 X h1 h2 hi hA hB
    have hone : highestBit32 ((X ^^^ (a1 ||| a2)) &&& diffBits m1 m2) &&&
        (highestBit32 ((X ^^^ (a1 ||| a2)) &&& diffBits m1 m2) - 1) = 0 := by
      unfold highestBit32
      bv_decide
    have hmem := mem_of_one_hot_sub_orAll (R.1.map Prod.fst) _ hone c0
      (fun x hx => by
        obtain ⟨e, he, rfl⟩ := List.mem_map.mp hx
        exact ⟨(hitems e he).2.1, (hitems e he).2.2.1⟩)
      (by rw [show orAll (R.1.map Prod.fst) = diffBits m1 m2 by simpa using hor]; exact c1)
    obtain ⟨e, he, hfst⟩ := List.mem_map.mp hmem
    refine ⟨e, he, ?_⟩
    rw [(hitems e he).1, hfst]
    exact c2
  · rintro ⟨e, he, hX⟩
    obtain ⟨hM, hb1, hb0, hbd⟩ := hitems e he
    rw [hM] at hX
    exact item_sub a1 m1 a2 m2 X e.1 h1 h2 hi hb1 hb0 hbd hX
  · have := List.pairwise_map.mp hpw
    refine this.imp_of_mem fun {e f} he hf hef X ⟨hXe, hXf⟩ => ?_
    obtain ⟨hMe, he1, he0, hed⟩ := hitems e he
    obtain ⟨hMf, hf1, hf0, hfd⟩ := hitems f hf
    rw [hMe] at hXe
    rw [hMf] at hXf
    exact item_disjoint a1 m1 a2 m2 X e.1 f.1 he1 he0 hed hf1 hf0 hfd (by bv_decide) hXe hXf

end Ipv4

namespace Ipv6

/-! ## Minimality -/

theorem diff_point_mem (a1 m1 a2 m2 b : BitVec 128) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (hi : a1 &&& m2 = a2 &&& m1) (hb0 : b ≠ 0) (hbd : b &&& diffBits m1 m2 = b) :
    ((a1 ||| a2) ^^^ b) &&& m1 = a1 ∧ ((a1 ||| a2) ^^^ b) &&& m2 ≠ a2 := by
  unfold diffBits at hbd
  bv_decide

theorem diff_points_separate (a1 m1 a2 m2 b c cN mN : BitVec 128) (h1 : a1 &&& m1 = a1)
    (h2 : a2 &&& m2 = a2) (hi : a1 &&& m2 = a2 &&& m1) (hbc : b &&& c = 0)
    (hb : ((a1 ||| a2) ^^^ b) &&& mN = cN) (hc : ((a1 ||| a2) ^^^ c) &&& mN = cN) :
    (a1 ||| a2) &&& mN = cN ∧ (a1 ||| a2) &&& m2 = a2 := by
  bv_decide

/-- Every list of networks whose union is `S(A) \ S(B)` has at least `popcount(d)`
members. -/
theorem difference_minimal (a1 m1 a2 m2 : BitVec 128) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (hi : a1 &&& m2 = a2 &&& m1) (C : List (BitVec 128 × BitVec 128))
    (hC : ∀ X, (∃ N ∈ C, X &&& N.2 = N.1) ↔ (X &&& m1 = a1 ∧ X &&& m2 ≠ a2)) :
    (diffBits m1 m2).cpop.toNat ≤ C.length := by
  rw [← length_setBits_eq_cpop]
  apply length_le_of_inj (fun b (N : BitVec 128 × BitVec 128) => ((a1 ||| a2) ^^^ b) &&& N.2 = N.1)
  · exact nodup_setBits _ _ (Nat.le_refl _)
  · intro b hb
    obtain ⟨i, hi', hx, rfl⟩ := mem_setBits hb
    exact (hC _).2 (diff_point_mem a1 m1 a2 m2 _ h1 h2 hi (twoPow_ne_zero' hi')
      (twoPow_and_of_getLsbD hi' hx))
  · intro b hb c hc N hN hbN hcN
    obtain ⟨i, hi', -, rfl⟩ := mem_setBits hb
    obtain ⟨j, -, -, rfl⟩ := mem_setBits hc
    by_cases hij : i = j
    · rw [hij]
    · exfalso
      obtain ⟨hia, hib⟩ := diff_points_separate a1 m1 a2 m2 _ _ N.1 N.2 h1 h2 hi
        (twoPow_and_twoPow hij) hbN hcN
      exact ((hC _).1 ⟨N, hN, hia⟩).2 hib

/-! ## A whole run -/

/-- One call on the state `(mask, remaining)`: `true` is `next()`, `false` is
`next_back()`. Emits the peeled bit and the mask of the network it yields. -/
def diffStep (front : Bool) (s : BitVec 128 × BitVec 128) :
    Option (BitVec 128 × BitVec 128) × (BitVec 128 × BitVec 128) :=
  if s.2 = 0 then (none, s)
  else if front then
    (some (highestBit128 s.2, s.1 ||| highestBit128 s.2),
      (s.1 ||| highestBit128 s.2, s.2 ^^^ highestBit128 s.2))
  else (some (lowestBit s.2, s.1 ||| s.2), (s.1, s.2 ^^^ lowestBit s.2))

/-- Runs a schedule of calls, collecting what they emit. -/
def diffRun : List Bool → BitVec 128 × BitVec 128 →
    List (BitVec 128 × BitVec 128) × (BitVec 128 × BitVec 128)
  | [], s => ([], s)
  | f :: fs, s =>
    ((diffStep f s).1.toList ++ (diffRun fs (diffStep f s).2).1, (diffRun fs (diffStep f s).2).2)

theorem diffStep_none (f : Bool) (s : BitVec 128 × BitVec 128) (h : (diffStep f s).1 = none) :
    s.2 = 0 ∧ (diffStep f s).2 = s := by
  unfold diffStep at *
  by_cases hr : s.2 = 0
  · simp [hr]
  · simp only [hr, ↓reduceIte] at h
    cases f <;> simp at h

theorem diffStep_some (m1 d : BitVec 128) (f : Bool) (s : BitVec 128 × BitVec 128)
    (h : Inv m1 d s.1 s.2) (b M : BitVec 128) (hs : (diffStep f s).1 = some (b, M)) :
    M = itemMask m1 d b ∧ b &&& (b - 1) = 0 ∧ b ≠ 0 ∧ b &&& s.2 = b ∧
      (diffStep f s).2.2 = s.2 ^^^ b ∧ Inv m1 d (diffStep f s).2.1 (diffStep f s).2.2 := by
  obtain ⟨mask, r⟩ := s
  by_cases hr : r = 0
  · simp [diffStep, hr] at hs
  · cases f
    · simp only [diffStep, hr, ↓reduceIte, Bool.false_eq_true, Option.some.injEq,
        Prod.mk.injEq] at hs ⊢
      obtain ⟨rfl, rfl⟩ := hs
      have := nextBack_emits m1 d mask r h hr
      refine ⟨this.1, ?_, ?_, ?_, rfl, this.2⟩ <;> unfold lowestBit <;> bv_decide
    · simp only [diffStep, hr, ↓reduceIte, Option.some.injEq, Prod.mk.injEq] at hs ⊢
      obtain ⟨rfl, rfl⟩ := hs
      have := next_emits m1 d mask r h hr
      refine ⟨this.1, ?_, ?_, ?_, rfl, this.2⟩ <;> unfold highestBit128 <;> bv_decide

theorem cpop_xor_bit (r b : BitVec 128) (hb : b &&& (b - 1) = 0) (hb0 : b ≠ 0) (hbr : b &&& r = b) :
    (r ^^^ b).cpop.toNat + 1 = r.cpop.toNat := by
  have h : (r ^^^ b).cpop + 1 = r.cpop := by bv_decide
  have hle := BitVec.toNat_cpop_le (r ^^^ b)
  rw [← h, BitVec.toNat_add]
  simp
  omega

theorem eq_zero_of_cpop (r : BitVec 128) (h : r.cpop.toNat = 0) : r = 0 := by
  have hc : r.cpop = 0#128 := BitVec.eq_of_toNat_eq (by simpa using h)
  bv_decide

/-- What a run from state `s` produced. -/
def RunSpec (m1 d : BitVec 128) (s : BitVec 128 × BitVec 128)
    (res : List (BitVec 128 × BitVec 128) × (BitVec 128 × BitVec 128)) (calls : Nat) : Prop :=
  Inv m1 d res.2.1 res.2.2 ∧
  (∀ e ∈ res.1, e.2 = itemMask m1 d e.1 ∧ e.1 &&& (e.1 - 1) = 0 ∧ e.1 ≠ 0 ∧ e.1 &&& s.2 = e.1) ∧
  (res.1.map Prod.fst).Pairwise (fun b c => b &&& c = 0) ∧
  orAll (res.1.map Prod.fst) ||| res.2.2 = s.2 ∧
  orAll (res.1.map Prod.fst) &&& res.2.2 = 0 ∧
  res.1.length + res.2.2.cpop.toNat = s.2.cpop.toNat ∧
  (s.2.cpop.toNat ≤ calls → res.2.2 = 0)

/-- A run emits distinct one-hot bits of `remaining`, each with its item mask,
removes them from `remaining`, and empties it given enough calls. -/
theorem diffRun_spec (m1 d : BitVec 128) (fs : List Bool) :
    ∀ s : BitVec 128 × BitVec 128, Inv m1 d s.1 s.2 → RunSpec m1 d s (diffRun fs s) fs.length := by
  induction fs with
  | nil =>
    intro s h
    simp only [RunSpec, diffRun, List.map_nil, List.Pairwise.nil, orAll, List.foldr_nil,
      List.length_nil, List.not_mem_nil, false_implies, implies_true, true_and, Nat.zero_add]
    refine ⟨h, by bv_decide, by bv_decide, fun hle => eq_zero_of_cpop _ (by omega)⟩
  | cons f fs ih =>
    intro s h
    simp only [diffRun, List.length_cons]
    cases hds : (diffStep f s).1 with
    | none =>
      obtain ⟨hs0, hseq⟩ := diffStep_none f s hds
      have hinv0 : Inv m1 d (diffStep f s).2.1 (diffStep f s).2.2 := by
        rw [hseq]
        exact h
      have hih := ih (diffStep f s).2 hinv0
      simp only [Option.toList_none, List.nil_append, Prod.eta]
      rw [hseq] at hih ⊢
      obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := hih
      refine ⟨h1, h2, h3, h4, h5, h6, fun _ => ?_⟩
      have : s.2.cpop.toNat = 0 := by rw [hs0]; simp
      exact h7 (by omega)
    | some e =>
      obtain ⟨b, M⟩ := e
      obtain ⟨hM, hb1, hb0, hbs, hr', hinv⟩ := diffStep_some m1 d f s h b M hds
      obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := ih (diffStep f s).2 hinv
      rw [hr'] at h2 h4 h6 h7
      simp only [Option.toList_some, List.singleton_append]
      generalize diffRun fs (diffStep f s).2 = R at h1 h2 h3 h4 h5 h6 h7 ⊢
      generalize hL : R.1.map Prod.fst = L at h3 h4 h5
      have hsubL : ∀ c ∈ L, c &&& (s.2 ^^^ b) = c := by
        intro c hc
        rw [← hL] at hc
        obtain ⟨e, he, rfl⟩ := List.mem_map.mp hc
        exact (h2 e he).2.2.2
      refine ⟨h1, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · intro e he
        rcases List.mem_cons.mp he with rfl | he
        · exact ⟨hM, hb1, hb0, hbs⟩
        · obtain ⟨he1, he2, he3, he4⟩ := h2 e he
          exact ⟨he1, he2, he3, by bv_decide⟩
      · simp only [List.map_cons, hL, List.pairwise_cons]
        refine ⟨fun c hc => ?_, h3⟩
        have := hsubL c hc
        bv_decide
      · simp only [List.map_cons, hL, orAll, List.foldr_cons] at h4 ⊢
        bv_decide
      · simp only [List.map_cons, hL, orAll, List.foldr_cons] at h4 h5 ⊢
        bv_decide
      · have := cpop_xor_bit s.2 b hb1 hb0 hbs
        simp only [List.length_cons]
        omega
      · intro hle
        have := cpop_xor_bit s.2 b hb1 hb0 hbs
        exact h7 (by omega)

theorem mem_of_one_hot_sub_orAll (L : List (BitVec 128)) (b : BitVec 128) (hb : b &&& (b - 1) = 0)
    (hb0 : b ≠ 0) (hL : ∀ x ∈ L, x &&& (x - 1) = 0 ∧ x ≠ 0) (hsub : b &&& orAll L = b) : b ∈ L := by
  induction L with
  | nil =>
    simp only [orAll, List.foldr_nil] at hsub
    exact absurd (by bv_decide) hb0
  | cons x L ih =>
    simp only [orAll, List.foldr_cons] at hsub
    obtain ⟨hx, hx0⟩ := hL x List.mem_cons_self
    have : b = x ∨ b &&& orAll L = b := by
      simp only [orAll]
      bv_decide
    rcases this with rfl | h
    · exact List.mem_cons_self
    · exact List.mem_cons_of_mem _ (ih (fun y hy => hL y (List.mem_cons_of_mem _ hy)) h)

/-- Any schedule of at least `popcount(d)` calls on `Ipv6NetworkDiff`, from the
general case of `new()`, emits exactly `popcount(d)` pairwise disjoint networks
whose union is `S(A) \ S(B)`. By `difference_minimal` no cover is smaller. -/
theorem difference_run (a1 m1 a2 m2 : BitVec 128) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (hi : a1 &&& m2 = a2 &&& m1) (fs : List Bool) (hfs : (diffBits m1 m2).cpop.toNat ≤ fs.length) :
    (diffRun fs (m1, diffBits m1 m2)).1.length = (diffBits m1 m2).cpop.toNat ∧
    (∀ e ∈ (diffRun fs (m1, diffBits m1 m2)).1, e.2 = itemMask m1 (diffBits m1 m2) e.1) ∧
    (∀ X, (X &&& m1 = a1 ∧ X &&& m2 ≠ a2) ↔
      ∃ e ∈ (diffRun fs (m1, diffBits m1 m2)).1, X &&& e.2 = ((a1 ||| a2) ^^^ e.1) &&& e.2) ∧
    (diffRun fs (m1, diffBits m1 m2)).1.Pairwise (fun e f =>
      ∀ X, ¬ (X &&& e.2 = ((a1 ||| a2) ^^^ e.1) &&& e.2 ∧ X &&& f.2 = ((a1 ||| a2) ^^^ f.1) &&& f.2)) := by
  obtain ⟨-, hitems, hpw, hor, -, hlen, hdone⟩ :=
    diffRun_spec m1 (diffBits m1 m2) fs (m1, diffBits m1 m2) (inv_init m1 _)
  simp only at hitems hor hlen hdone
  have hz := hdone hfs
  rw [hz] at hor hlen
  generalize diffRun fs (m1, diffBits m1 m2) = R at *
  refine ⟨by simpa using hlen, fun e he => (hitems e he).1, fun X => ⟨?_, ?_⟩, ?_⟩
  · intro ⟨hA, hB⟩
    obtain ⟨c0, c1, c2⟩ := item_cover a1 m1 a2 m2 X h1 h2 hi hA hB
    have hone : highestBit128 ((X ^^^ (a1 ||| a2)) &&& diffBits m1 m2) &&&
        (highestBit128 ((X ^^^ (a1 ||| a2)) &&& diffBits m1 m2) - 1) = 0 := by
      unfold highestBit128
      bv_decide
    have hmem := mem_of_one_hot_sub_orAll (R.1.map Prod.fst) _ hone c0
      (fun x hx => by
        obtain ⟨e, he, rfl⟩ := List.mem_map.mp hx
        exact ⟨(hitems e he).2.1, (hitems e he).2.2.1⟩)
      (by rw [show orAll (R.1.map Prod.fst) = diffBits m1 m2 by simpa using hor]; exact c1)
    obtain ⟨e, he, hfst⟩ := List.mem_map.mp hmem
    refine ⟨e, he, ?_⟩
    rw [(hitems e he).1, hfst]
    exact c2
  · rintro ⟨e, he, hX⟩
    obtain ⟨hM, hb1, hb0, hbd⟩ := hitems e he
    rw [hM] at hX
    exact item_sub a1 m1 a2 m2 X e.1 h1 h2 hi hb1 hb0 hbd hX
  · have := List.pairwise_map.mp hpw
    refine this.imp_of_mem fun {e f} he hf hef X ⟨hXe, hXf⟩ => ?_
    obtain ⟨hMe, he1, he0, hed⟩ := hitems e he
    obtain ⟨hMf, hf1, hf0, hfd⟩ := hitems f hf
    rw [hMe] at hXe
    rw [hMf] at hXf
    exact item_disjoint a1 m1 a2 m2 X e.1 f.1 he1 he0 hed hf1 hf0 hfd (by bv_decide) hXe hXf

end Ipv6

end Netip.Impl
