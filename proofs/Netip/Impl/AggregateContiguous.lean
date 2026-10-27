import Netip.Impl.CidrCover

/-!
# `ipv4_aggregate_contiguous` / `ipv6_aggregate_contiguous`

The aggregation pass, transcribed: after sorting, every input is pushed onto a
stack, merging with the top through `merge_by_lowest_mask_bit` for as long as
that succeeds (`push`, `aggregate`).

Proved, for any input of CIDR blocks sorted by address (the sort by
`(addr, mask)` gives that): the output is made of CIDR blocks, they are pairwise
disjoint, no two are buddies, and their union is the union of the input
(`aggregate_spec`). By `CidrCover` the output is then a minimum CIDR cover of
that union, and every minimum cover is made of its blocks
(`aggregate_minimal`, `aggregate_unique`) — the documented "unique smallest set
of contiguous blocks".

The stack invariant: listed from the top, every deeper block ends before every
higher one starts, no pair is a buddy pair, and the next input starts no lower
than the top. That is why merging against the top alone is complete.
-/

namespace Netip.Impl

variable {w : Nat}

/-- `merge_by_lowest_mask_bit(top, current)` on blocks. -/
def mergeLow (t c : Block w) : Option (Block w) := mergeByLowestMaskBit t.1 t.2 c.1 c.2

/-- Pushes `cur`, merging it with the top of the stack while that succeeds. The
stack is listed top first. -/
def push (cur : Block w) : List (Block w) → List (Block w)
  | [] => [cur]
  | t :: rest =>
    match mergeLow t cur with
    | some m => push m rest
    | none => cur :: t :: rest

/-- The aggregation pass over the sorted input: the stack, bottom first. -/
def aggregate (sorted : List (Block w)) : List (Block w) :=
  (sorted.foldl (fun st b => push b st) []).reverse

/-- The last address of a block. -/
def lastAddr (B : Block w) : BitVec w := B.1 ||| ~~~B.2

theorem pairwise_forall_ne {α : Type} {R : α → α → Prop} (hsymm : ∀ a b, R a b → R b a)
    {l : List α} (h : l.Pairwise R) : ∀ a ∈ l, ∀ b ∈ l, a ≠ b → R a b := by
  induction l with
  | nil => simp
  | cons x l ih =>
    rw [List.pairwise_cons] at h
    obtain ⟨hx, hl⟩ := h
    intro a ha b hb hab
    rcases List.mem_cons.mp ha with hax | ha' <;> rcases List.mem_cons.mp hb with hbx | hb'
    · exact absurd (hax.trans hbx.symm) hab
    · subst hax
      exact hx b hb'
    · subst hbx
      exact hsymm _ _ (hx a ha')
    · exact ih hl a ha' b hb' hab

namespace Ipv4

theorem addr_le_of_last_lt {r t : Block 32} (h : lastAddr r < t.1) : r.1 ≤ t.1 := by
  obtain ⟨r1, r2⟩ := r
  simp only [lastAddr] at *
  bv_decide

theorem buddies_symm {B C : Block 32} (h : Buddies B C) : Buddies C B := by
  simp only [Buddies, AdjacentByLowestMaskBit] at *
  bv_decide

theorem not_buddies_self (B : Block 32) : ¬ Buddies B B := by
  simp only [Buddies, AdjacentByLowestMaskBit]
  bv_decide

/-- A successful merge with a later block keeps the top's address. -/
theorem mergeLow_addr {t c m : Block 32} (ht : IsCidr t) (hc : IsCidr c) (hle : t.1 ≤ c.1)
    (h : mergeLow t c = some m) : m.1 = t.1 := by
  obtain ⟨t1, t2⟩ := t
  obtain ⟨c1, c2⟩ := c
  obtain ⟨m1, m2⟩ := m
  simp only [IsCidr, IsContiguous] at ht hc
  simp only at hle ⊢
  unfold mergeLow mergeByLowestMaskBit at h
  simp only at h
  by_cases hm : t2 = c2
  · rw [ite_eq_left hm] at h
    by_cases he : t1 = c1
    · rw [ite_eq_left he] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      exact h.1.symm
    · rw [ite_eq_right he] at h
      by_cases hs : t2 ≠ 0 ∧ t1 ^^^ c1 = t2 &&& -t2
      · rw [ite_eq_left hs] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨h1, -⟩ := h
        subst h1
        bv_decide
      · rw [ite_eq_right hs] at h
        simp at h
  · rw [ite_eq_right hm] at h
    by_cases hc1 : c1 &&& t2 = t1 ∧ c2 &&& t2 = t2
    · rw [ite_eq_left hc1] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      exact h.1.symm
    · rw [ite_eq_right hc1] at h
      by_cases hc2 : t1 &&& c2 = c1 ∧ t2 &&& c2 = c2
      · rw [ite_eq_left hc2] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨h1, -⟩ := h
        subst h1
        bv_decide
      · rw [ite_eq_right hc2] at h
        simp at h

/-- A failed merge with a later block: the later block starts after the top ends,
and the two are not buddies. -/
theorem mergeLow_none {t c : Block 32} (ht : IsCidr t) (hc : IsCidr c) (hle : t.1 ≤ c.1)
    (h : mergeLow t c = none) : lastAddr t < c.1 ∧ ¬ Buddies t c := by
  obtain ⟨t1, t2⟩ := t
  obtain ⟨c1, c2⟩ := c
  simp only [IsCidr, IsContiguous] at ht hc
  simp only at hle
  unfold mergeLow mergeByLowestMaskBit at h
  simp only at h
  simp only [lastAddr, Buddies, AdjacentByLowestMaskBit]
  by_cases hm : t2 = c2
  · rw [ite_eq_left hm] at h
    by_cases he : t1 = c1
    · rw [ite_eq_left he] at h
      simp at h
    · rw [ite_eq_right he] at h
      by_cases hs : t2 ≠ 0 ∧ t1 ^^^ c1 = t2 &&& -t2
      · rw [ite_eq_left hs] at h
        simp at h
      · constructor <;> bv_decide
  · rw [ite_eq_right hm] at h
    by_cases hc1 : c1 &&& t2 = t1 ∧ c2 &&& t2 = t2
    · rw [ite_eq_left hc1] at h
      simp at h
    · rw [ite_eq_right hc1] at h
      by_cases hc2 : t1 &&& c2 = c1 ∧ t2 &&& c2 = c2
      · rw [ite_eq_left hc2] at h
        simp at h
      · constructor <;> bv_decide

theorem mergeLow_mem {t c m : Block 32} (ht : IsCidr t) (hc : IsCidr c) (h : mergeLow t c = some m)
    (X : BitVec 32) : IsCidr m ∧ (Mem X m ↔ Mem X t ∨ Mem X c) := by
  have h' : mergeByLowestMaskBit t.1 t.2 c.1 c.2 = some (m.1, m.2) := h
  obtain ⟨hn, hu⟩ := merge_sound ht.2 hc.2 (mergeByLowestMaskBit_eq_merge ht.2 hc.2 h') X
  exact ⟨⟨mergeByLowestMaskBit_contiguous ht.1 hc.1 h', hn⟩, hu⟩

/-- Blocks separated by a third one are not buddies, and the far one ends before
the near one starts. -/
theorem far_apart {c t b : Block 32} (hc : IsCidr c) (ht : IsCidr t) (hb : IsCidr b)
    (h1 : lastAddr c < t.1) (h2 : lastAddr t < b.1) : lastAddr c < b.1 ∧ ¬ Buddies c b := by
  obtain ⟨c1, c2⟩ := c
  obtain ⟨t1, t2⟩ := t
  obtain ⟨b1, b2⟩ := b
  simp only [IsCidr, IsContiguous, lastAddr, Buddies, AdjacentByLowestMaskBit] at *
  constructor <;> bv_decide

theorem not_meets_of_lt {c b : Block 32} (hc : IsCidr c) (hb : IsCidr b) (h : lastAddr c < b.1) :
    ¬ Meets b c := by
  obtain ⟨c1, c2⟩ := c
  obtain ⟨b1, b2⟩ := b
  simp only [IsCidr, IsContiguous, lastAddr, Meets] at *
  bv_decide

/-- The stack invariant, top first: CIDR blocks, every deeper block ends before
every higher one starts, and no pair is a buddy pair. -/
def StackInv (st : List (Block 32)) : Prop :=
  (∀ b ∈ st, IsCidr b) ∧ st.Pairwise fun hi lo => lastAddr lo < hi.1 ∧ ¬ Buddies lo hi

theorem push_spec (cur : Block 32) (hcur : IsCidr cur) :
    ∀ st : List (Block 32), StackInv st → (∀ t ∈ st.head?, t.1 ≤ cur.1) →
      StackInv (push cur st) ∧ (∀ t ∈ (push cur st).head?, t.1 ≤ cur.1) ∧
      ∀ X, (∃ B ∈ push cur st, Mem X B) ↔ (∃ B ∈ st, Mem X B) ∨ Mem X cur := by
  intro st
  induction st generalizing cur with
  | nil =>
    intro _ _
    show StackInv [cur] ∧ (∀ t ∈ [cur].head?, t.1 ≤ cur.1) ∧
      ∀ X, (∃ B ∈ [cur], Mem X B) ↔ (∃ B ∈ ([] : List (Block 32)), Mem X B) ∨ Mem X cur
    refine ⟨⟨fun b hb => ?_, List.pairwise_singleton _ _⟩, fun t ht => ?_, fun X => ?_⟩
    · rw [List.mem_singleton] at hb
      subst hb
      exact hcur
    · simp only [List.head?_cons, Option.mem_def, Option.some.injEq] at ht
      subst ht
      exact BitVec.le_refl _
    · simp
  | cons t rest ih =>
    intro hinv hhead
    obtain ⟨hall, hpw⟩ := hinv
    rw [List.pairwise_cons] at hpw
    have ht := hall t List.mem_cons_self
    have hle : t.1 ≤ cur.1 := hhead t rfl
    cases hm : mergeLow t cur with
    | some m =>
      have hpush : push cur (t :: rest) = push m rest := by simp [push, hm]
      rw [hpush]
      obtain ⟨hmc, -⟩ := mergeLow_mem ht hcur hm 0
      have hma := mergeLow_addr ht hcur hle hm
      have hrest : StackInv rest := ⟨fun b hb => hall b (List.mem_cons_of_mem _ hb), hpw.2⟩
      have hhead' : ∀ r ∈ rest.head?, r.1 ≤ m.1 := by
        intro r hr
        rw [hma]
        exact addr_le_of_last_lt (hpw.1 r (List.mem_of_mem_head? hr)).1
      obtain ⟨hinv', hhead'', hunion⟩ := ih m hmc hrest hhead'
      refine ⟨hinv', fun r hr => ?_, fun X => ?_⟩
      · have := hhead'' r hr
        rw [hma] at this
        exact BitVec.le_trans this hle
      · rw [hunion X, (mergeLow_mem ht hcur hm X).2]
        constructor
        · rintro (⟨B, hB, hX⟩ | hX | hX)
          · exact Or.inl ⟨B, List.mem_cons_of_mem _ hB, hX⟩
          · exact Or.inl ⟨t, List.mem_cons_self, hX⟩
          · exact Or.inr hX
        · rintro (⟨B, hB, hX⟩ | hX)
          · rcases List.mem_cons.mp hB with rfl | hB
            · exact Or.inr (Or.inl hX)
            · exact Or.inl ⟨B, hB, hX⟩
          · exact Or.inr (Or.inr hX)
    | none =>
      have hpush : push cur (t :: rest) = cur :: t :: rest := by simp [push, hm]
      rw [hpush]
      obtain ⟨hsep, hnb⟩ := mergeLow_none ht hcur hle hm
      refine ⟨⟨fun b hb => ?_, ?_⟩, by simp, fun X => ?_⟩
      · rcases List.mem_cons.mp hb with rfl | hb
        · exact hcur
        · exact hall b hb
      · rw [List.pairwise_cons]
        refine ⟨fun lo hlo => ?_, List.pairwise_cons.mpr hpw⟩
        rcases List.mem_cons.mp hlo with rfl | hlo
        · exact ⟨hsep, hnb⟩
        · exact far_apart (hall lo (List.mem_cons_of_mem _ hlo)) ht hcur (hpw.1 lo hlo).1 hsep
      · constructor
        · rintro ⟨B, hB, hX⟩
          rcases List.mem_cons.mp hB with rfl | hB
          · exact Or.inr hX
          · exact Or.inl ⟨B, hB, hX⟩
        · rintro (⟨B, hB, hX⟩ | hX)
          · exact ⟨B, List.mem_cons_of_mem _ hB, hX⟩
          · exact ⟨cur, List.mem_cons_self, hX⟩

/-- The pass over a prefix of the sorted input: the stack keeps its invariant,
covers the inputs seen so far, and its top starts no later than the last of them. -/
theorem foldl_push_spec (L : List (Block 32)) (hL : ∀ B ∈ L, IsCidr B)
    (hsorted : L.Pairwise fun x y => x.1 ≤ y.1) :
    ∀ st : List (Block 32), StackInv st → (∀ t ∈ st.head?, ∀ x ∈ L, t.1 ≤ x.1) →
      StackInv (L.foldl (fun st b => push b st) st) ∧
      ∀ X, (∃ B ∈ L.foldl (fun st b => push b st) st, Mem X B) ↔
        (∃ B ∈ st, Mem X B) ∨ ∃ B ∈ L, Mem X B := by
  induction L with
  | nil => intro st h _; simp [h]
  | cons x L ih =>
    intro st hst hhead
    rw [List.pairwise_cons] at hsorted
    obtain ⟨hinv, hhead', hunion⟩ :=
      push_spec x (hL x List.mem_cons_self) st hst fun t ht => hhead t ht x List.mem_cons_self
    obtain ⟨hinv'', hunion''⟩ := ih (fun B hB => hL B (List.mem_cons_of_mem _ hB)) hsorted.2
      (push x st) hinv fun t ht y hy => BitVec.le_trans (hhead' t ht) (hsorted.1 y hy)
    refine ⟨hinv'', fun X => ?_⟩
    rw [List.foldl_cons, hunion'' X, hunion X]
    constructor
    · rintro ((h | h) | ⟨B, hB, hX⟩)
      · exact Or.inl h
      · exact Or.inr ⟨x, List.mem_cons_self, h⟩
      · exact Or.inr ⟨B, List.mem_cons_of_mem _ hB, hX⟩
    · rintro (h | ⟨B, hB, hX⟩)
      · exact Or.inl (Or.inl h)
      · rcases List.mem_cons.mp hB with rfl | hB
        · exact Or.inl (Or.inr hX)
        · exact Or.inr ⟨B, hB, hX⟩

/-- The output: CIDR blocks, pairwise disjoint, no buddy pair, same union as the
input. -/
theorem aggregate_spec (L : List (Block 32)) (hL : ∀ B ∈ L, IsCidr B)
    (hsorted : L.Pairwise fun x y => x.1 ≤ y.1) :
    (∀ B ∈ aggregate L, IsCidr B) ∧ PairwiseDisjoint (aggregate L) ∧
    (∀ B ∈ aggregate L, ∀ C ∈ aggregate L, ¬ Buddies B C) ∧
    ∀ X, (∃ B ∈ aggregate L, Mem X B) ↔ ∃ B ∈ L, Mem X B := by
  obtain ⟨⟨hall, hpw⟩, hunion⟩ :=
    foldl_push_spec L hL hsorted [] ⟨by simp, List.Pairwise.nil⟩ (by simp)
  unfold aggregate
  generalize L.foldl (fun st b => push b st) [] = st at *
  refine ⟨fun B hB => hall B (List.mem_reverse.mp hB), ?_, ?_, fun X => ?_⟩
  · unfold PairwiseDisjoint
    rw [List.pairwise_reverse]
    exact hpw.imp_of_mem fun {hi lo} hhi hlo h hm =>
      not_meets_of_lt (hall lo hlo) (hall hi hhi) h.1 hm.symm
  · intro B hB C hC hbc
    rw [List.mem_reverse] at hB hC
    by_cases heq : B = C
    · subst heq
      exact not_buddies_self B hbc
    · exact pairwise_forall_ne (R := fun hi lo => ¬ Buddies lo hi)
        (fun a b h hb => h (buddies_symm hb)) (hpw.imp fun h => h.2) B hB C hC heq (buddies_symm hbc)
  · simp only [List.mem_reverse]
    rw [hunion X]
    simp

/-- The output is a minimum CIDR cover of the union of the input. -/
theorem aggregate_minimal (L : List (Block 32)) (hL : ∀ B ∈ L, IsCidr B)
    (hsorted : L.Pairwise fun x y => x.1 ≤ y.1) (C : List (Block 32)) (hC : ∀ B ∈ C, IsCidr B)
    (hcov : ∀ X, (∃ B ∈ C, Mem X B) ↔ ∃ B ∈ L, Mem X B) :
    (aggregate L).length ≤ C.length := by
  obtain ⟨hcidr, hdis, hnb, hunion⟩ := aggregate_spec L hL hsorted
  exact cover_minimal (aggregate L) C (fun X => ∃ B ∈ L, Mem X B) hdis
    (maximal_of_no_buddies _ _ hcidr hdis hunion hnb) hC hcov

/-- Every CIDR cover of the union that is no longer than the output is made of its
blocks: the minimum cover is unique. -/
theorem aggregate_unique (L : List (Block 32)) (hL : ∀ B ∈ L, IsCidr B)
    (hsorted : L.Pairwise fun x y => x.1 ≤ y.1) (C : List (Block 32)) (hC : ∀ B ∈ C, IsCidr B)
    (hcov : ∀ X, (∃ B ∈ C, Mem X B) ↔ ∃ B ∈ L, Mem X B) (hlen : C.length ≤ (aggregate L).length) :
    ∀ c ∈ C, c ∈ aggregate L := by
  obtain ⟨hcidr, hdis, hnb, hunion⟩ := aggregate_spec L hL hsorted
  exact cover_unique (aggregate L) C _ hdis (maximal_of_no_buddies _ _ hcidr hdis hunion hnb)
    hunion hC hcov hlen

end Ipv4

namespace Ipv6

theorem addr_le_of_last_lt {r t : Block 128} (h : lastAddr r < t.1) : r.1 ≤ t.1 := by
  obtain ⟨r1, r2⟩ := r
  simp only [lastAddr] at *
  bv_decide

theorem buddies_symm {B C : Block 128} (h : Buddies B C) : Buddies C B := by
  simp only [Buddies, AdjacentByLowestMaskBit] at *
  bv_decide

theorem not_buddies_self (B : Block 128) : ¬ Buddies B B := by
  simp only [Buddies, AdjacentByLowestMaskBit]
  bv_decide

/-- A successful merge with a later block keeps the top's address. -/
theorem mergeLow_addr {t c m : Block 128} (ht : IsCidr t) (hc : IsCidr c) (hle : t.1 ≤ c.1)
    (h : mergeLow t c = some m) : m.1 = t.1 := by
  obtain ⟨t1, t2⟩ := t
  obtain ⟨c1, c2⟩ := c
  obtain ⟨m1, m2⟩ := m
  simp only [IsCidr, IsContiguous] at ht hc
  simp only at hle ⊢
  unfold mergeLow mergeByLowestMaskBit at h
  simp only at h
  by_cases hm : t2 = c2
  · rw [ite_eq_left hm] at h
    by_cases he : t1 = c1
    · rw [ite_eq_left he] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      exact h.1.symm
    · rw [ite_eq_right he] at h
      by_cases hs : t2 ≠ 0 ∧ t1 ^^^ c1 = t2 &&& -t2
      · rw [ite_eq_left hs] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨h1, -⟩ := h
        subst h1
        bv_decide
      · rw [ite_eq_right hs] at h
        simp at h
  · rw [ite_eq_right hm] at h
    by_cases hc1 : c1 &&& t2 = t1 ∧ c2 &&& t2 = t2
    · rw [ite_eq_left hc1] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      exact h.1.symm
    · rw [ite_eq_right hc1] at h
      by_cases hc2 : t1 &&& c2 = c1 ∧ t2 &&& c2 = c2
      · rw [ite_eq_left hc2] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨h1, -⟩ := h
        subst h1
        bv_decide
      · rw [ite_eq_right hc2] at h
        simp at h

/-- A failed merge with a later block: the later block starts after the top ends,
and the two are not buddies. -/
theorem mergeLow_none {t c : Block 128} (ht : IsCidr t) (hc : IsCidr c) (hle : t.1 ≤ c.1)
    (h : mergeLow t c = none) : lastAddr t < c.1 ∧ ¬ Buddies t c := by
  obtain ⟨t1, t2⟩ := t
  obtain ⟨c1, c2⟩ := c
  simp only [IsCidr, IsContiguous] at ht hc
  simp only at hle
  unfold mergeLow mergeByLowestMaskBit at h
  simp only at h
  simp only [lastAddr, Buddies, AdjacentByLowestMaskBit]
  by_cases hm : t2 = c2
  · rw [ite_eq_left hm] at h
    by_cases he : t1 = c1
    · rw [ite_eq_left he] at h
      simp at h
    · rw [ite_eq_right he] at h
      by_cases hs : t2 ≠ 0 ∧ t1 ^^^ c1 = t2 &&& -t2
      · rw [ite_eq_left hs] at h
        simp at h
      · constructor <;> bv_decide
  · rw [ite_eq_right hm] at h
    by_cases hc1 : c1 &&& t2 = t1 ∧ c2 &&& t2 = t2
    · rw [ite_eq_left hc1] at h
      simp at h
    · rw [ite_eq_right hc1] at h
      by_cases hc2 : t1 &&& c2 = c1 ∧ t2 &&& c2 = c2
      · rw [ite_eq_left hc2] at h
        simp at h
      · constructor <;> bv_decide

theorem mergeLow_mem {t c m : Block 128} (ht : IsCidr t) (hc : IsCidr c) (h : mergeLow t c = some m)
    (X : BitVec 128) : IsCidr m ∧ (Mem X m ↔ Mem X t ∨ Mem X c) := by
  have h' : mergeByLowestMaskBit t.1 t.2 c.1 c.2 = some (m.1, m.2) := h
  obtain ⟨hn, hu⟩ := merge_sound ht.2 hc.2 (mergeByLowestMaskBit_eq_merge ht.2 hc.2 h') X
  exact ⟨⟨mergeByLowestMaskBit_contiguous ht.1 hc.1 h', hn⟩, hu⟩

/-- Blocks separated by a third one are not buddies, and the far one ends before
the near one starts. -/
theorem far_apart {c t b : Block 128} (hc : IsCidr c) (ht : IsCidr t) (hb : IsCidr b)
    (h1 : lastAddr c < t.1) (h2 : lastAddr t < b.1) : lastAddr c < b.1 ∧ ¬ Buddies c b := by
  obtain ⟨c1, c2⟩ := c
  obtain ⟨t1, t2⟩ := t
  obtain ⟨b1, b2⟩ := b
  simp only [IsCidr, IsContiguous, lastAddr, Buddies, AdjacentByLowestMaskBit] at *
  constructor <;> bv_decide

theorem not_meets_of_lt {c b : Block 128} (hc : IsCidr c) (hb : IsCidr b) (h : lastAddr c < b.1) :
    ¬ Meets b c := by
  obtain ⟨c1, c2⟩ := c
  obtain ⟨b1, b2⟩ := b
  simp only [IsCidr, IsContiguous, lastAddr, Meets] at *
  bv_decide

/-- The stack invariant, top first: CIDR blocks, every deeper block ends before
every higher one starts, and no pair is a buddy pair. -/
def StackInv (st : List (Block 128)) : Prop :=
  (∀ b ∈ st, IsCidr b) ∧ st.Pairwise fun hi lo => lastAddr lo < hi.1 ∧ ¬ Buddies lo hi

theorem push_spec (cur : Block 128) (hcur : IsCidr cur) :
    ∀ st : List (Block 128), StackInv st → (∀ t ∈ st.head?, t.1 ≤ cur.1) →
      StackInv (push cur st) ∧ (∀ t ∈ (push cur st).head?, t.1 ≤ cur.1) ∧
      ∀ X, (∃ B ∈ push cur st, Mem X B) ↔ (∃ B ∈ st, Mem X B) ∨ Mem X cur := by
  intro st
  induction st generalizing cur with
  | nil =>
    intro _ _
    show StackInv [cur] ∧ (∀ t ∈ [cur].head?, t.1 ≤ cur.1) ∧
      ∀ X, (∃ B ∈ [cur], Mem X B) ↔ (∃ B ∈ ([] : List (Block 128)), Mem X B) ∨ Mem X cur
    refine ⟨⟨fun b hb => ?_, List.pairwise_singleton _ _⟩, fun t ht => ?_, fun X => ?_⟩
    · rw [List.mem_singleton] at hb
      subst hb
      exact hcur
    · simp only [List.head?_cons, Option.mem_def, Option.some.injEq] at ht
      subst ht
      exact BitVec.le_refl _
    · simp
  | cons t rest ih =>
    intro hinv hhead
    obtain ⟨hall, hpw⟩ := hinv
    rw [List.pairwise_cons] at hpw
    have ht := hall t List.mem_cons_self
    have hle : t.1 ≤ cur.1 := hhead t rfl
    cases hm : mergeLow t cur with
    | some m =>
      have hpush : push cur (t :: rest) = push m rest := by simp [push, hm]
      rw [hpush]
      obtain ⟨hmc, -⟩ := mergeLow_mem ht hcur hm 0
      have hma := mergeLow_addr ht hcur hle hm
      have hrest : StackInv rest := ⟨fun b hb => hall b (List.mem_cons_of_mem _ hb), hpw.2⟩
      have hhead' : ∀ r ∈ rest.head?, r.1 ≤ m.1 := by
        intro r hr
        rw [hma]
        exact addr_le_of_last_lt (hpw.1 r (List.mem_of_mem_head? hr)).1
      obtain ⟨hinv', hhead'', hunion⟩ := ih m hmc hrest hhead'
      refine ⟨hinv', fun r hr => ?_, fun X => ?_⟩
      · have := hhead'' r hr
        rw [hma] at this
        exact BitVec.le_trans this hle
      · rw [hunion X, (mergeLow_mem ht hcur hm X).2]
        constructor
        · rintro (⟨B, hB, hX⟩ | hX | hX)
          · exact Or.inl ⟨B, List.mem_cons_of_mem _ hB, hX⟩
          · exact Or.inl ⟨t, List.mem_cons_self, hX⟩
          · exact Or.inr hX
        · rintro (⟨B, hB, hX⟩ | hX)
          · rcases List.mem_cons.mp hB with rfl | hB
            · exact Or.inr (Or.inl hX)
            · exact Or.inl ⟨B, hB, hX⟩
          · exact Or.inr (Or.inr hX)
    | none =>
      have hpush : push cur (t :: rest) = cur :: t :: rest := by simp [push, hm]
      rw [hpush]
      obtain ⟨hsep, hnb⟩ := mergeLow_none ht hcur hle hm
      refine ⟨⟨fun b hb => ?_, ?_⟩, by simp, fun X => ?_⟩
      · rcases List.mem_cons.mp hb with rfl | hb
        · exact hcur
        · exact hall b hb
      · rw [List.pairwise_cons]
        refine ⟨fun lo hlo => ?_, List.pairwise_cons.mpr hpw⟩
        rcases List.mem_cons.mp hlo with rfl | hlo
        · exact ⟨hsep, hnb⟩
        · exact far_apart (hall lo (List.mem_cons_of_mem _ hlo)) ht hcur (hpw.1 lo hlo).1 hsep
      · constructor
        · rintro ⟨B, hB, hX⟩
          rcases List.mem_cons.mp hB with rfl | hB
          · exact Or.inr hX
          · exact Or.inl ⟨B, hB, hX⟩
        · rintro (⟨B, hB, hX⟩ | hX)
          · exact ⟨B, List.mem_cons_of_mem _ hB, hX⟩
          · exact ⟨cur, List.mem_cons_self, hX⟩

/-- The pass over a prefix of the sorted input: the stack keeps its invariant,
covers the inputs seen so far, and its top starts no later than the last of them. -/
theorem foldl_push_spec (L : List (Block 128)) (hL : ∀ B ∈ L, IsCidr B)
    (hsorted : L.Pairwise fun x y => x.1 ≤ y.1) :
    ∀ st : List (Block 128), StackInv st → (∀ t ∈ st.head?, ∀ x ∈ L, t.1 ≤ x.1) →
      StackInv (L.foldl (fun st b => push b st) st) ∧
      ∀ X, (∃ B ∈ L.foldl (fun st b => push b st) st, Mem X B) ↔
        (∃ B ∈ st, Mem X B) ∨ ∃ B ∈ L, Mem X B := by
  induction L with
  | nil => intro st h _; simp [h]
  | cons x L ih =>
    intro st hst hhead
    rw [List.pairwise_cons] at hsorted
    obtain ⟨hinv, hhead', hunion⟩ :=
      push_spec x (hL x List.mem_cons_self) st hst fun t ht => hhead t ht x List.mem_cons_self
    obtain ⟨hinv'', hunion''⟩ := ih (fun B hB => hL B (List.mem_cons_of_mem _ hB)) hsorted.2
      (push x st) hinv fun t ht y hy => BitVec.le_trans (hhead' t ht) (hsorted.1 y hy)
    refine ⟨hinv'', fun X => ?_⟩
    rw [List.foldl_cons, hunion'' X, hunion X]
    constructor
    · rintro ((h | h) | ⟨B, hB, hX⟩)
      · exact Or.inl h
      · exact Or.inr ⟨x, List.mem_cons_self, h⟩
      · exact Or.inr ⟨B, List.mem_cons_of_mem _ hB, hX⟩
    · rintro (h | ⟨B, hB, hX⟩)
      · exact Or.inl (Or.inl h)
      · rcases List.mem_cons.mp hB with rfl | hB
        · exact Or.inl (Or.inr hX)
        · exact Or.inr ⟨B, hB, hX⟩

/-- The output: CIDR blocks, pairwise disjoint, no buddy pair, same union as the
input. -/
theorem aggregate_spec (L : List (Block 128)) (hL : ∀ B ∈ L, IsCidr B)
    (hsorted : L.Pairwise fun x y => x.1 ≤ y.1) :
    (∀ B ∈ aggregate L, IsCidr B) ∧ PairwiseDisjoint (aggregate L) ∧
    (∀ B ∈ aggregate L, ∀ C ∈ aggregate L, ¬ Buddies B C) ∧
    ∀ X, (∃ B ∈ aggregate L, Mem X B) ↔ ∃ B ∈ L, Mem X B := by
  obtain ⟨⟨hall, hpw⟩, hunion⟩ :=
    foldl_push_spec L hL hsorted [] ⟨by simp, List.Pairwise.nil⟩ (by simp)
  unfold aggregate
  generalize L.foldl (fun st b => push b st) [] = st at *
  refine ⟨fun B hB => hall B (List.mem_reverse.mp hB), ?_, ?_, fun X => ?_⟩
  · unfold PairwiseDisjoint
    rw [List.pairwise_reverse]
    exact hpw.imp_of_mem fun {hi lo} hhi hlo h hm =>
      not_meets_of_lt (hall lo hlo) (hall hi hhi) h.1 hm.symm
  · intro B hB C hC hbc
    rw [List.mem_reverse] at hB hC
    by_cases heq : B = C
    · subst heq
      exact not_buddies_self B hbc
    · exact pairwise_forall_ne (R := fun hi lo => ¬ Buddies lo hi)
        (fun a b h hb => h (buddies_symm hb)) (hpw.imp fun h => h.2) B hB C hC heq (buddies_symm hbc)
  · simp only [List.mem_reverse]
    rw [hunion X]
    simp

/-- The output is a minimum CIDR cover of the union of the input. -/
theorem aggregate_minimal (L : List (Block 128)) (hL : ∀ B ∈ L, IsCidr B)
    (hsorted : L.Pairwise fun x y => x.1 ≤ y.1) (C : List (Block 128)) (hC : ∀ B ∈ C, IsCidr B)
    (hcov : ∀ X, (∃ B ∈ C, Mem X B) ↔ ∃ B ∈ L, Mem X B) :
    (aggregate L).length ≤ C.length := by
  obtain ⟨hcidr, hdis, hnb, hunion⟩ := aggregate_spec L hL hsorted
  exact cover_minimal (aggregate L) C (fun X => ∃ B ∈ L, Mem X B) hdis
    (maximal_of_no_buddies _ _ hcidr hdis hunion hnb) hC hcov

/-- Every CIDR cover of the union that is no longer than the output is made of its
blocks: the minimum cover is unique. -/
theorem aggregate_unique (L : List (Block 128)) (hL : ∀ B ∈ L, IsCidr B)
    (hsorted : L.Pairwise fun x y => x.1 ≤ y.1) (C : List (Block 128)) (hC : ∀ B ∈ C, IsCidr B)
    (hcov : ∀ X, (∃ B ∈ C, Mem X B) ↔ ∃ B ∈ L, Mem X B) (hlen : C.length ≤ (aggregate L).length) :
    ∀ c ∈ C, c ∈ aggregate L := by
  obtain ⟨hcidr, hdis, hnb, hunion⟩ := aggregate_spec L hL hsorted
  exact cover_unique (aggregate L) C _ hdis (maximal_of_no_buddies _ _ hcidr hdis hunion hnb)
    hunion hC hcov hlen

end Ipv6

end Netip.Impl
