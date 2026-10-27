import Netip.Impl.MergeComplete
import Netip.Impl.CidrCover

/-!
# `ipv4_aggregate` / `ipv6_aggregate`

`ip_aggregate`, transcribed: a stack of networks, and for every input `r`
* the top-most entry `nets[k]` that `merge`s with `r` absorbs it (`topMerge`);
* if that changed the entry, it is merged again with the first other entry that
  merges with it, which is removed, until none does (`rescan`). The stack is kept
  as a zipper `(pre, nets[k], post)`, so removing an entry before `k` shrinks
  `pre` exactly as the Rust code decrements `k`;
* if no entry merges, `r` is pushed.

Proved, for any input of normalized networks in any order: the union of the
output equals the union of the input, and no two output networks `merge` in
either order (`aggregateGeneral_spec`). In particular no output network contains
another and there are no duplicates (`aggregateGeneral_no_containment`), which is what
the documentation promises. The output is not claimed to be minimal, and is not:
covering by subcubes is the minimum-DNF problem.

Termination: every round of `rescan` removes an entry, so a fuel of the stack
length suffices.
-/

namespace Netip.Impl

variable {w : Nat}

/-- `merge(self, other)` on blocks. -/
def mergeB (x b : Block w) : Option (Block w) := merge x.1 x.2 b.1 b.2

/-- The first index whose element `f` maps to `some`. -/
def firstBy {α : Type} (f : α → Option α) : List α → Option (Nat × α)
  | [] => none
  | b :: l =>
    match f b with
    | some m => some (0, m)
    | none =>
      match firstBy f l with
      | some (i, m) => some (i + 1, m)
      | none => none

/-- Rescans: merges `x` with the first entry of `pre`, then of `post`, that merges
with it, removes that entry, and repeats. -/
def rescan : Nat → List (Block w) → Block w → List (Block w) →
    List (Block w) × Block w × List (Block w)
  | 0, pre, x, post => (pre, x, post)
  | f + 1, pre, x, post =>
    match firstBy (mergeB x) pre with
    | some (i, m) => rescan f (pre.eraseIdx i) m post
    | none =>
      match firstBy (mergeB x) post with
      | some (i, m) => rescan f pre m (post.eraseIdx i)
      | none => (pre, x, post)

/-- The top-most entry of the stack (listed bottom first) that merges with `r`:
its index and the merged network. -/
def topMerge (st : List (Block w)) (r : Block w) : Option (Nat × Block w) :=
  match firstBy (fun e => mergeB e r) st.reverse with
  | some (i, m) => some (st.length - 1 - i, m)
  | none => none

/-- One iteration of the outer loop. -/
def aggStep (st : List (Block w)) (r : Block w) : List (Block w) :=
  match topMerge st r with
  | none => st ++ [r]
  | some (k, m) =>
    if st[k]? = some m then st
    else
      match rescan st.length (st.take k) m (st.drop (k + 1)) with
      | (pre, x, post) => pre ++ x :: post

/-- `ip_aggregate` on the sorted input. -/
def aggregateGeneral (L : List (Block w)) : List (Block w) := L.foldl aggStep []

/-! ## List facts -/

theorem firstBy_none {α : Type} {f : α → Option α} :
    ∀ {l : List α}, firstBy f l = none → ∀ b ∈ l, f b = none := by
  intro l
  induction l with
  | nil => simp
  | cons b l ih =>
    intro h c hc
    simp only [firstBy] at h
    split at h
    · simp at h
    · rename_i hb
      split at h
      · simp at h
      · rename_i hl
        rcases List.mem_cons.mp hc with rfl | hc
        · exact hb
        · exact ih hl c hc

theorem firstBy_some {α : Type} {f : α → Option α} :
    ∀ {l : List α} {i : Nat} {m : α}, firstBy f l = some (i, m) →
      ∃ h : i < l.length, f l[i] = some m := by
  intro l
  induction l with
  | nil => simp [firstBy]
  | cons b l ih =>
    intro i m h
    simp only [firstBy] at h
    split at h
    · rename_i m' hb
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨by simp, hb⟩
    · split at h
      · rename_i i' m' hl
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨hi, hf⟩ := ih hl
        exact ⟨by simp; omega, hf⟩
      · simp at h

theorem mem_iff_mem_eraseIdx {α : Type} (l : List α) (i : Nat) (h : i < l.length) (b : α) :
    b ∈ l ↔ b ∈ l.eraseIdx i ∨ b = l[i] := by
  constructor
  · intro hb
    obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem hb
    by_cases hji : j = i
    · subst hji
      exact Or.inr rfl
    · exact Or.inl (List.mem_eraseIdx_iff_getElem.mpr ⟨j, hj, hji, rfl⟩)
  · rintro (hb | rfl)
    · exact List.mem_of_mem_eraseIdx hb
    · exact List.getElem_mem h

theorem eraseIdx_take_drop {α : Type} (l : List α) (k : Nat) :
    l.take k ++ l.drop (k + 1) = l.eraseIdx k := by
  rw [List.eraseIdx_eq_take_drop_succ]

namespace Ipv4

theorem mergeB_none_symm {a b : Block 32} (ha : a.1 &&& a.2 = a.1) (hb : b.1 &&& b.2 = b.1)
    (h : mergeB a b = none) : mergeB b a = none := by
  have hna : ¬ (merge a.1 a.2 b.1 b.2).isSome := by simp [mergeB] at h; simp [h]
  rw [merge_isSome_iff _ _ _ _ ha hb] at hna
  cases hm : merge b.1 b.2 a.1 a.2 with
  | none => exact hm
  | some r =>
    exfalso
    apply hna
    obtain ⟨c, mc, hcm⟩ := (merge_isSome_iff _ _ _ _ hb ha).mp (by simp [hm])
    exact ⟨c, mc, fun X => (hcm X).trans or_comm⟩

theorem mergeB_mem {x b m : Block 32} (hx : x.1 &&& x.2 = x.1) (hb : b.1 &&& b.2 = b.1)
    (h : mergeB x b = some m) (X : BitVec 32) :
    m.1 &&& m.2 = m.1 ∧ (Mem X m ↔ Mem X x ∨ Mem X b) := by
  have h' : merge x.1 x.2 b.1 b.2 = some (m.1, m.2) := h
  exact merge_sound hx hb h' X

/-- What a rescan keeps: the union, normalization, sublists, and — given enough
fuel — an `x` that merges with nothing left. -/
theorem rescan_spec : ∀ (fuel : Nat) (pre : List (Block 32)) (x : Block 32) (post : List (Block 32)),
    (∀ b ∈ pre, b.1 &&& b.2 = b.1) → (∀ b ∈ post, b.1 &&& b.2 = b.1) → x.1 &&& x.2 = x.1 →
    pre.length + post.length < fuel →
    List.Sublist (rescan fuel pre x post).1 pre ∧ List.Sublist (rescan fuel pre x post).2.2 post ∧
    (rescan fuel pre x post).2.1.1 &&& (rescan fuel pre x post).2.1.2 = (rescan fuel pre x post).2.1.1 ∧
    (∀ b ∈ (rescan fuel pre x post).1, mergeB (rescan fuel pre x post).2.1 b = none) ∧
    (∀ b ∈ (rescan fuel pre x post).2.2, mergeB (rescan fuel pre x post).2.1 b = none) ∧
    ∀ X, (∃ b ∈ (rescan fuel pre x post).1, Mem X b) ∨ Mem X (rescan fuel pre x post).2.1 ∨
        (∃ b ∈ (rescan fuel pre x post).2.2, Mem X b) ↔
      (∃ b ∈ pre, Mem X b) ∨ Mem X x ∨ (∃ b ∈ post, Mem X b) := by
  intro fuel
  induction fuel with
  | zero => intro _ _ _ _ _ _ h; omega
  | succ f ih =>
    intro pre x post hpre hpost hx hlen
    simp only [rescan]
    split
    · rename_i i m hfm
      obtain ⟨hi, hmi⟩ := firstBy_some hfm
      have hpi := hpre _ (List.getElem_mem hi)
      obtain ⟨hmn, -⟩ := mergeB_mem hx hpi hmi 0
      have hlen' : (pre.eraseIdx i).length + post.length < f := by
        rw [List.length_eraseIdx_of_lt hi]
        omega
      obtain ⟨h1, h2, h3, h4, h5, h6⟩ := ih (pre.eraseIdx i) m post
        (fun b hb => hpre b (List.mem_of_mem_eraseIdx hb)) hpost hmn hlen'
      refine ⟨h1.trans (List.eraseIdx_sublist _ _), h2, h3, h4, h5, fun X => ?_⟩
      rw [h6 X]
      have hm := (mergeB_mem hx hpi hmi X).2
      constructor
      · rintro (⟨b, hb, hX⟩ | hX | hX)
        · exact Or.inl ⟨b, List.mem_of_mem_eraseIdx hb, hX⟩
        · rcases hm.1 hX with hX | hX
          · exact Or.inr (Or.inl hX)
          · exact Or.inl ⟨_, List.getElem_mem hi, hX⟩
        · exact Or.inr (Or.inr hX)
      · rintro (⟨b, hb, hX⟩ | hX | hX)
        · rcases (mem_iff_mem_eraseIdx pre i hi b).1 hb with hb | rfl
          · exact Or.inl ⟨b, hb, hX⟩
          · exact Or.inr (Or.inl (hm.2 (Or.inr hX)))
        · exact Or.inr (Or.inl (hm.2 (Or.inl hX)))
        · exact Or.inr (Or.inr hX)
    · rename_i hnone
      split
      · rename_i i m hfm
        obtain ⟨hi, hmi⟩ := firstBy_some hfm
        have hpi := hpost _ (List.getElem_mem hi)
        obtain ⟨hmn, -⟩ := mergeB_mem hx hpi hmi 0
        have hlen' : pre.length + (post.eraseIdx i).length < f := by
          rw [List.length_eraseIdx_of_lt hi]
          omega
        obtain ⟨h1, h2, h3, h4, h5, h6⟩ := ih pre m (post.eraseIdx i) hpre
          (fun b hb => hpost b (List.mem_of_mem_eraseIdx hb)) hmn hlen'
        refine ⟨h1, h2.trans (List.eraseIdx_sublist _ _), h3, h4, h5, fun X => ?_⟩
        rw [h6 X]
        have hm := (mergeB_mem hx hpi hmi X).2
        constructor
        · rintro (hX | hX | ⟨b, hb, hX⟩)
          · exact Or.inl hX
          · rcases hm.1 hX with hX | hX
            · exact Or.inr (Or.inl hX)
            · exact Or.inr (Or.inr ⟨_, List.getElem_mem hi, hX⟩)
          · exact Or.inr (Or.inr ⟨b, List.mem_of_mem_eraseIdx hb, hX⟩)
        · rintro (hX | hX | ⟨b, hb, hX⟩)
          · exact Or.inl hX
          · exact Or.inr (Or.inl (hm.2 (Or.inl hX)))
          · rcases (mem_iff_mem_eraseIdx post i hi b).1 hb with hb | rfl
            · exact Or.inr (Or.inr ⟨b, hb, hX⟩)
            · exact Or.inr (Or.inl (hm.2 (Or.inr hX)))
      · rename_i hnone'
        exact ⟨List.Sublist.refl _, List.Sublist.refl _, hx, firstBy_none hnone, firstBy_none hnone',
          fun X => Iff.rfl⟩

theorem topMerge_none {st : List (Block 32)} {r : Block 32} (h : topMerge st r = none) :
    ∀ e ∈ st, mergeB e r = none := by
  unfold topMerge at h
  split at h
  · simp at h
  · rename_i hn
    intro e he
    exact firstBy_none hn e (List.mem_reverse.mpr he)

theorem topMerge_some {st : List (Block 32)} {r : Block 32} {k : Nat} {m : Block 32}
    (h : topMerge st r = some (k, m)) : ∃ hk : k < st.length, mergeB st[k] r = some m := by
  unfold topMerge at h
  split at h
  · rename_i i m' hfm
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    obtain ⟨hi, hf⟩ := firstBy_some hfm
    rw [List.length_reverse] at hi
    refine ⟨by omega, ?_⟩
    rw [List.getElem_reverse] at hf
    exact hf
  · simp at h

/-- The stack invariant: normalized entries, no two of which merge. -/
def AggInv (st : List (Block 32)) : Prop :=
  (∀ b ∈ st, b.1 &&& b.2 = b.1) ∧ st.Pairwise fun a b => mergeB a b = none

theorem mem_take_drop {st : List (Block 32)} {k : Nat} (hk : k < st.length) (b : Block 32) :
    b ∈ st ↔ b ∈ st.take k ∨ b = st[k] ∨ b ∈ st.drop (k + 1) := by
  rw [mem_iff_mem_eraseIdx st k hk b, ← eraseIdx_take_drop, List.mem_append]
  constructor
  · rintro ((h | h) | h)
    · exact Or.inl h
    · exact Or.inr (Or.inr h)
    · exact Or.inr (Or.inl h)
  · rintro (h | h | h)
    · exact Or.inl (Or.inl h)
    · exact Or.inr h
    · exact Or.inl (Or.inr h)

theorem aggStep_spec (st : List (Block 32)) (r : Block 32) (hst : AggInv st)
    (hr : r.1 &&& r.2 = r.1) :
    AggInv (aggStep st r) ∧ ∀ X, (∃ b ∈ aggStep st r, Mem X b) ↔ (∃ b ∈ st, Mem X b) ∨ Mem X r := by
  obtain ⟨hnorm, hpw⟩ := hst
  unfold aggStep
  split
  · rename_i hnone
    have hall := topMerge_none hnone
    refine ⟨⟨fun b hb => ?_, ?_⟩, fun X => ?_⟩
    · rcases List.mem_append.mp hb with hb | hb
      · exact hnorm b hb
      · rw [List.mem_singleton] at hb
        exact hb ▸ hr
    · rw [List.pairwise_append]
      refine ⟨hpw, List.pairwise_singleton _ _, fun a ha b hb => ?_⟩
      rw [List.mem_singleton] at hb
      exact hb ▸ hall a ha
    · simp only [List.mem_append, List.mem_singleton]
      constructor
      · rintro ⟨b, hb | rfl, hX⟩
        · exact Or.inl ⟨b, hb, hX⟩
        · exact Or.inr hX
      · rintro (⟨b, hb, hX⟩ | hX)
        · exact ⟨b, Or.inl hb, hX⟩
        · exact ⟨r, Or.inr rfl, hX⟩
  · rename_i k m hsome
    obtain ⟨hk, hmk⟩ := topMerge_some hsome
    have hstk := hnorm _ (List.getElem_mem hk)
    have hmerge := mergeB_mem hstk hr hmk
    split
    · rename_i heq
      have hkm : st[k] = m := by
        rw [List.getElem?_eq_getElem hk] at heq
        exact Option.some.inj heq
      refine ⟨⟨hnorm, hpw⟩, fun X => ⟨fun h => Or.inl h, ?_⟩⟩
      rintro (h | hX)
      · exact h
      · refine ⟨st[k], List.getElem_mem hk, ?_⟩
        have := ((hmerge X).2.2 (Or.inr hX))
        rw [← hkm] at this
        exact this
    · have hlen : (st.take k).length + (st.drop (k + 1)).length < st.length := by
        simp only [List.length_take, List.length_drop]
        omega
      have hpre : ∀ b ∈ st.take k, b.1 &&& b.2 = b.1 := fun b hb => hnorm b (List.mem_of_mem_take hb)
      have hpost : ∀ b ∈ st.drop (k + 1), b.1 &&& b.2 = b.1 :=
        fun b hb => hnorm b (List.mem_of_mem_drop hb)
      obtain ⟨h1, h2, h3, h4, h5, h6⟩ :=
        rescan_spec st.length (st.take k) m (st.drop (k + 1)) hpre hpost (hmerge 0).1 hlen
      generalize rescan st.length (st.take k) m (st.drop (k + 1)) = R at h1 h2 h3 h4 h5 h6
      obtain ⟨pre, x, post⟩ := R
      simp only at h1 h2 h3 h4 h5 h6 ⊢
      have hpwe : (st.take k ++ st.drop (k + 1)).Pairwise fun a b => mergeB a b = none := by
        rw [eraseIdx_take_drop]
        exact hpw.sublist (List.eraseIdx_sublist _ _)
      rw [List.pairwise_append] at hpwe
      obtain ⟨hpwt, hpwd, hcross⟩ := hpwe
      refine ⟨⟨fun b hb => ?_, ?_⟩, fun X => ?_⟩
      · rcases List.mem_append.mp hb with hb | hb
        · exact hpre b (h1.subset hb)
        · rcases List.mem_cons.mp hb with rfl | hb
          · exact h3
          · exact hpost b (h2.subset hb)
      · rw [List.pairwise_append, List.pairwise_cons]
        refine ⟨hpwt.sublist h1, ⟨h5, hpwd.sublist h2⟩, fun a ha b hb => ?_⟩
        rcases List.mem_cons.mp hb with rfl | hb
        · exact mergeB_none_symm h3 (hpre a (h1.subset ha)) (h4 a ha)
        · exact hcross a (h1.subset ha) b (h2.subset hb)
      · have h6X := h6 X
        simp only [List.mem_append, List.mem_cons] at h6X ⊢
        have hmX := (hmerge X).2
        constructor
        · rintro ⟨b, hb | rfl | hb, hX⟩
          · rcases h6X.1 (Or.inl ⟨b, hb, hX⟩) with ⟨c, hc, hXc⟩ | hXm | ⟨c, hc, hXc⟩
            · exact Or.inl ⟨c, List.mem_of_mem_take hc, hXc⟩
            · rcases hmX.1 hXm with hXk | hXr
              · exact Or.inl ⟨_, List.getElem_mem hk, hXk⟩
              · exact Or.inr hXr
            · exact Or.inl ⟨c, List.mem_of_mem_drop hc, hXc⟩
          · rcases h6X.1 (Or.inr (Or.inl hX)) with ⟨c, hc, hXc⟩ | hXm | ⟨c, hc, hXc⟩
            · exact Or.inl ⟨c, List.mem_of_mem_take hc, hXc⟩
            · rcases hmX.1 hXm with hXk | hXr
              · exact Or.inl ⟨_, List.getElem_mem hk, hXk⟩
              · exact Or.inr hXr
            · exact Or.inl ⟨c, List.mem_of_mem_drop hc, hXc⟩
          · rcases h6X.1 (Or.inr (Or.inr ⟨b, hb, hX⟩)) with ⟨c, hc, hXc⟩ | hXm | ⟨c, hc, hXc⟩
            · exact Or.inl ⟨c, List.mem_of_mem_take hc, hXc⟩
            · rcases hmX.1 hXm with hXk | hXr
              · exact Or.inl ⟨_, List.getElem_mem hk, hXk⟩
              · exact Or.inr hXr
            · exact Or.inl ⟨c, List.mem_of_mem_drop hc, hXc⟩
        · intro hX
          have : (∃ b ∈ st.take k, Mem X b) ∨ Mem X m ∨ (∃ b ∈ st.drop (k + 1), Mem X b) := by
            rcases hX with ⟨b, hb, hXb⟩ | hXr
            · rcases (mem_take_drop hk b).1 hb with hb | rfl | hb
              · exact Or.inl ⟨b, hb, hXb⟩
              · exact Or.inr (Or.inl (hmX.2 (Or.inl hXb)))
              · exact Or.inr (Or.inr ⟨b, hb, hXb⟩)
            · exact Or.inr (Or.inl (hmX.2 (Or.inr hXr)))
          rcases h6X.2 this with ⟨b, hb, hXb⟩ | hXx | ⟨b, hb, hXb⟩
          · exact ⟨b, Or.inl hb, hXb⟩
          · exact ⟨x, Or.inr (Or.inl rfl), hXx⟩
          · exact ⟨b, Or.inr (Or.inr hb), hXb⟩

/-- `ipv4_aggregate`: the union is preserved and no two output networks merge. -/
theorem aggregateGeneral_spec (L : List (Block 32)) (hL : ∀ b ∈ L, b.1 &&& b.2 = b.1) :
    (∀ b ∈ aggregateGeneral L, b.1 &&& b.2 = b.1) ∧
    (∀ X, (∃ b ∈ aggregateGeneral L, Mem X b) ↔ ∃ b ∈ L, Mem X b) ∧
    (aggregateGeneral L).Pairwise fun a b => mergeB a b = none ∧ mergeB b a = none := by
  have key : ∀ (L : List (Block 32)) (st : List (Block 32)), (∀ b ∈ L, b.1 &&& b.2 = b.1) →
      AggInv st → AggInv (L.foldl aggStep st) ∧
        ∀ X, (∃ b ∈ L.foldl aggStep st, Mem X b) ↔ (∃ b ∈ st, Mem X b) ∨ ∃ b ∈ L, Mem X b := by
    intro L
    induction L with
    | nil => intro st _ h; simp [h]
    | cons r L ih =>
      intro st hL hst
      obtain ⟨hinv, hunion⟩ := aggStep_spec st r hst (hL r List.mem_cons_self)
      obtain ⟨hinv', hunion'⟩ := ih (aggStep st r) (fun b hb => hL b (List.mem_cons_of_mem _ hb)) hinv
      refine ⟨hinv', fun X => ?_⟩
      rw [List.foldl_cons, hunion' X, hunion X]
      constructor
      · rintro ((h | h) | ⟨b, hb, hX⟩)
        · exact Or.inl h
        · exact Or.inr ⟨r, List.mem_cons_self, h⟩
        · exact Or.inr ⟨b, List.mem_cons_of_mem _ hb, hX⟩
      · rintro (h | ⟨b, hb, hX⟩)
        · exact Or.inl (Or.inl h)
        · rcases List.mem_cons.mp hb with rfl | hb
          · exact Or.inl (Or.inr hX)
          · exact Or.inr ⟨b, hb, hX⟩
  obtain ⟨⟨hnorm, hpw⟩, hunion⟩ := key L [] hL ⟨by simp, List.Pairwise.nil⟩
  unfold aggregateGeneral
  refine ⟨hnorm, fun X => by simpa using hunion X, ?_⟩
  exact hpw.imp_of_mem fun {a b} ha hb h => ⟨h, mergeB_none_symm (hnorm a ha) (hnorm b hb) h⟩

/-- No output network contains another. -/
theorem aggregateGeneral_no_containment (L : List (Block 32)) (hL : ∀ b ∈ L, b.1 &&& b.2 = b.1) :
    (aggregateGeneral L).Pairwise fun a b => ¬ Contains a b ∧ ¬ Contains b a := by
  obtain ⟨hnorm, -, hpw⟩ := aggregateGeneral_spec L hL
  refine hpw.imp_of_mem fun {a b} ha hb h => ⟨fun hc => ?_, fun hc => ?_⟩
  · have hs : (merge a.1 a.2 b.1 b.2).isSome := by
      rw [merge_isSome_iff _ _ _ _ (hnorm a ha) (hnorm b hb)]
      refine ⟨a.1, a.2, fun X => ⟨Or.inl, ?_⟩⟩
      rintro (hX | hX)
      · exact hX
      · exact (contains_iff a.1 a.2 b.1 b.2 (hnorm a ha) (hnorm b hb)).1 hc X hX
    simp [mergeB] at h
    simp [h] at hs
  · have hs : (merge b.1 b.2 a.1 a.2).isSome := by
      rw [merge_isSome_iff _ _ _ _ (hnorm b hb) (hnorm a ha)]
      refine ⟨b.1, b.2, fun X => ⟨Or.inl, ?_⟩⟩
      rintro (hX | hX)
      · exact hX
      · exact (contains_iff b.1 b.2 a.1 a.2 (hnorm b hb) (hnorm a ha)).1 hc X hX
    have h2 := h.2
    simp [mergeB] at h2
    simp [h2] at hs

end Ipv4

namespace Ipv6

theorem mergeB_none_symm {a b : Block 128} (ha : a.1 &&& a.2 = a.1) (hb : b.1 &&& b.2 = b.1)
    (h : mergeB a b = none) : mergeB b a = none := by
  have hna : ¬ (merge a.1 a.2 b.1 b.2).isSome := by simp [mergeB] at h; simp [h]
  rw [merge_isSome_iff _ _ _ _ ha hb] at hna
  cases hm : merge b.1 b.2 a.1 a.2 with
  | none => exact hm
  | some r =>
    exfalso
    apply hna
    obtain ⟨c, mc, hcm⟩ := (merge_isSome_iff _ _ _ _ hb ha).mp (by simp [hm])
    exact ⟨c, mc, fun X => (hcm X).trans or_comm⟩

theorem mergeB_mem {x b m : Block 128} (hx : x.1 &&& x.2 = x.1) (hb : b.1 &&& b.2 = b.1)
    (h : mergeB x b = some m) (X : BitVec 128) :
    m.1 &&& m.2 = m.1 ∧ (Mem X m ↔ Mem X x ∨ Mem X b) := by
  have h' : merge x.1 x.2 b.1 b.2 = some (m.1, m.2) := h
  exact merge_sound hx hb h' X

/-- What a rescan keeps: the union, normalization, sublists, and — given enough
fuel — an `x` that merges with nothing left. -/
theorem rescan_spec : ∀ (fuel : Nat) (pre : List (Block 128)) (x : Block 128) (post : List (Block 128)),
    (∀ b ∈ pre, b.1 &&& b.2 = b.1) → (∀ b ∈ post, b.1 &&& b.2 = b.1) → x.1 &&& x.2 = x.1 →
    pre.length + post.length < fuel →
    List.Sublist (rescan fuel pre x post).1 pre ∧ List.Sublist (rescan fuel pre x post).2.2 post ∧
    (rescan fuel pre x post).2.1.1 &&& (rescan fuel pre x post).2.1.2 = (rescan fuel pre x post).2.1.1 ∧
    (∀ b ∈ (rescan fuel pre x post).1, mergeB (rescan fuel pre x post).2.1 b = none) ∧
    (∀ b ∈ (rescan fuel pre x post).2.2, mergeB (rescan fuel pre x post).2.1 b = none) ∧
    ∀ X, (∃ b ∈ (rescan fuel pre x post).1, Mem X b) ∨ Mem X (rescan fuel pre x post).2.1 ∨
        (∃ b ∈ (rescan fuel pre x post).2.2, Mem X b) ↔
      (∃ b ∈ pre, Mem X b) ∨ Mem X x ∨ (∃ b ∈ post, Mem X b) := by
  intro fuel
  induction fuel with
  | zero => intro _ _ _ _ _ _ h; omega
  | succ f ih =>
    intro pre x post hpre hpost hx hlen
    simp only [rescan]
    split
    · rename_i i m hfm
      obtain ⟨hi, hmi⟩ := firstBy_some hfm
      have hpi := hpre _ (List.getElem_mem hi)
      obtain ⟨hmn, -⟩ := mergeB_mem hx hpi hmi 0
      have hlen' : (pre.eraseIdx i).length + post.length < f := by
        rw [List.length_eraseIdx_of_lt hi]
        omega
      obtain ⟨h1, h2, h3, h4, h5, h6⟩ := ih (pre.eraseIdx i) m post
        (fun b hb => hpre b (List.mem_of_mem_eraseIdx hb)) hpost hmn hlen'
      refine ⟨h1.trans (List.eraseIdx_sublist _ _), h2, h3, h4, h5, fun X => ?_⟩
      rw [h6 X]
      have hm := (mergeB_mem hx hpi hmi X).2
      constructor
      · rintro (⟨b, hb, hX⟩ | hX | hX)
        · exact Or.inl ⟨b, List.mem_of_mem_eraseIdx hb, hX⟩
        · rcases hm.1 hX with hX | hX
          · exact Or.inr (Or.inl hX)
          · exact Or.inl ⟨_, List.getElem_mem hi, hX⟩
        · exact Or.inr (Or.inr hX)
      · rintro (⟨b, hb, hX⟩ | hX | hX)
        · rcases (mem_iff_mem_eraseIdx pre i hi b).1 hb with hb | rfl
          · exact Or.inl ⟨b, hb, hX⟩
          · exact Or.inr (Or.inl (hm.2 (Or.inr hX)))
        · exact Or.inr (Or.inl (hm.2 (Or.inl hX)))
        · exact Or.inr (Or.inr hX)
    · rename_i hnone
      split
      · rename_i i m hfm
        obtain ⟨hi, hmi⟩ := firstBy_some hfm
        have hpi := hpost _ (List.getElem_mem hi)
        obtain ⟨hmn, -⟩ := mergeB_mem hx hpi hmi 0
        have hlen' : pre.length + (post.eraseIdx i).length < f := by
          rw [List.length_eraseIdx_of_lt hi]
          omega
        obtain ⟨h1, h2, h3, h4, h5, h6⟩ := ih pre m (post.eraseIdx i) hpre
          (fun b hb => hpost b (List.mem_of_mem_eraseIdx hb)) hmn hlen'
        refine ⟨h1, h2.trans (List.eraseIdx_sublist _ _), h3, h4, h5, fun X => ?_⟩
        rw [h6 X]
        have hm := (mergeB_mem hx hpi hmi X).2
        constructor
        · rintro (hX | hX | ⟨b, hb, hX⟩)
          · exact Or.inl hX
          · rcases hm.1 hX with hX | hX
            · exact Or.inr (Or.inl hX)
            · exact Or.inr (Or.inr ⟨_, List.getElem_mem hi, hX⟩)
          · exact Or.inr (Or.inr ⟨b, List.mem_of_mem_eraseIdx hb, hX⟩)
        · rintro (hX | hX | ⟨b, hb, hX⟩)
          · exact Or.inl hX
          · exact Or.inr (Or.inl (hm.2 (Or.inl hX)))
          · rcases (mem_iff_mem_eraseIdx post i hi b).1 hb with hb | rfl
            · exact Or.inr (Or.inr ⟨b, hb, hX⟩)
            · exact Or.inr (Or.inl (hm.2 (Or.inr hX)))
      · rename_i hnone'
        exact ⟨List.Sublist.refl _, List.Sublist.refl _, hx, firstBy_none hnone, firstBy_none hnone',
          fun X => Iff.rfl⟩

theorem topMerge_none {st : List (Block 128)} {r : Block 128} (h : topMerge st r = none) :
    ∀ e ∈ st, mergeB e r = none := by
  unfold topMerge at h
  split at h
  · simp at h
  · rename_i hn
    intro e he
    exact firstBy_none hn e (List.mem_reverse.mpr he)

theorem topMerge_some {st : List (Block 128)} {r : Block 128} {k : Nat} {m : Block 128}
    (h : topMerge st r = some (k, m)) : ∃ hk : k < st.length, mergeB st[k] r = some m := by
  unfold topMerge at h
  split at h
  · rename_i i m' hfm
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    obtain ⟨hi, hf⟩ := firstBy_some hfm
    rw [List.length_reverse] at hi
    refine ⟨by omega, ?_⟩
    rw [List.getElem_reverse] at hf
    exact hf
  · simp at h

/-- The stack invariant: normalized entries, no two of which merge. -/
def AggInv (st : List (Block 128)) : Prop :=
  (∀ b ∈ st, b.1 &&& b.2 = b.1) ∧ st.Pairwise fun a b => mergeB a b = none

theorem mem_take_drop {st : List (Block 128)} {k : Nat} (hk : k < st.length) (b : Block 128) :
    b ∈ st ↔ b ∈ st.take k ∨ b = st[k] ∨ b ∈ st.drop (k + 1) := by
  rw [mem_iff_mem_eraseIdx st k hk b, ← eraseIdx_take_drop, List.mem_append]
  constructor
  · rintro ((h | h) | h)
    · exact Or.inl h
    · exact Or.inr (Or.inr h)
    · exact Or.inr (Or.inl h)
  · rintro (h | h | h)
    · exact Or.inl (Or.inl h)
    · exact Or.inr h
    · exact Or.inl (Or.inr h)

theorem aggStep_spec (st : List (Block 128)) (r : Block 128) (hst : AggInv st)
    (hr : r.1 &&& r.2 = r.1) :
    AggInv (aggStep st r) ∧ ∀ X, (∃ b ∈ aggStep st r, Mem X b) ↔ (∃ b ∈ st, Mem X b) ∨ Mem X r := by
  obtain ⟨hnorm, hpw⟩ := hst
  unfold aggStep
  split
  · rename_i hnone
    have hall := topMerge_none hnone
    refine ⟨⟨fun b hb => ?_, ?_⟩, fun X => ?_⟩
    · rcases List.mem_append.mp hb with hb | hb
      · exact hnorm b hb
      · rw [List.mem_singleton] at hb
        exact hb ▸ hr
    · rw [List.pairwise_append]
      refine ⟨hpw, List.pairwise_singleton _ _, fun a ha b hb => ?_⟩
      rw [List.mem_singleton] at hb
      exact hb ▸ hall a ha
    · simp only [List.mem_append, List.mem_singleton]
      constructor
      · rintro ⟨b, hb | rfl, hX⟩
        · exact Or.inl ⟨b, hb, hX⟩
        · exact Or.inr hX
      · rintro (⟨b, hb, hX⟩ | hX)
        · exact ⟨b, Or.inl hb, hX⟩
        · exact ⟨r, Or.inr rfl, hX⟩
  · rename_i k m hsome
    obtain ⟨hk, hmk⟩ := topMerge_some hsome
    have hstk := hnorm _ (List.getElem_mem hk)
    have hmerge := mergeB_mem hstk hr hmk
    split
    · rename_i heq
      have hkm : st[k] = m := by
        rw [List.getElem?_eq_getElem hk] at heq
        exact Option.some.inj heq
      refine ⟨⟨hnorm, hpw⟩, fun X => ⟨fun h => Or.inl h, ?_⟩⟩
      rintro (h | hX)
      · exact h
      · refine ⟨st[k], List.getElem_mem hk, ?_⟩
        have := ((hmerge X).2.2 (Or.inr hX))
        rw [← hkm] at this
        exact this
    · have hlen : (st.take k).length + (st.drop (k + 1)).length < st.length := by
        simp only [List.length_take, List.length_drop]
        omega
      have hpre : ∀ b ∈ st.take k, b.1 &&& b.2 = b.1 := fun b hb => hnorm b (List.mem_of_mem_take hb)
      have hpost : ∀ b ∈ st.drop (k + 1), b.1 &&& b.2 = b.1 :=
        fun b hb => hnorm b (List.mem_of_mem_drop hb)
      obtain ⟨h1, h2, h3, h4, h5, h6⟩ :=
        rescan_spec st.length (st.take k) m (st.drop (k + 1)) hpre hpost (hmerge 0).1 hlen
      generalize rescan st.length (st.take k) m (st.drop (k + 1)) = R at h1 h2 h3 h4 h5 h6
      obtain ⟨pre, x, post⟩ := R
      simp only at h1 h2 h3 h4 h5 h6 ⊢
      have hpwe : (st.take k ++ st.drop (k + 1)).Pairwise fun a b => mergeB a b = none := by
        rw [eraseIdx_take_drop]
        exact hpw.sublist (List.eraseIdx_sublist _ _)
      rw [List.pairwise_append] at hpwe
      obtain ⟨hpwt, hpwd, hcross⟩ := hpwe
      refine ⟨⟨fun b hb => ?_, ?_⟩, fun X => ?_⟩
      · rcases List.mem_append.mp hb with hb | hb
        · exact hpre b (h1.subset hb)
        · rcases List.mem_cons.mp hb with rfl | hb
          · exact h3
          · exact hpost b (h2.subset hb)
      · rw [List.pairwise_append, List.pairwise_cons]
        refine ⟨hpwt.sublist h1, ⟨h5, hpwd.sublist h2⟩, fun a ha b hb => ?_⟩
        rcases List.mem_cons.mp hb with rfl | hb
        · exact mergeB_none_symm h3 (hpre a (h1.subset ha)) (h4 a ha)
        · exact hcross a (h1.subset ha) b (h2.subset hb)
      · have h6X := h6 X
        simp only [List.mem_append, List.mem_cons] at h6X ⊢
        have hmX := (hmerge X).2
        constructor
        · rintro ⟨b, hb | rfl | hb, hX⟩
          · rcases h6X.1 (Or.inl ⟨b, hb, hX⟩) with ⟨c, hc, hXc⟩ | hXm | ⟨c, hc, hXc⟩
            · exact Or.inl ⟨c, List.mem_of_mem_take hc, hXc⟩
            · rcases hmX.1 hXm with hXk | hXr
              · exact Or.inl ⟨_, List.getElem_mem hk, hXk⟩
              · exact Or.inr hXr
            · exact Or.inl ⟨c, List.mem_of_mem_drop hc, hXc⟩
          · rcases h6X.1 (Or.inr (Or.inl hX)) with ⟨c, hc, hXc⟩ | hXm | ⟨c, hc, hXc⟩
            · exact Or.inl ⟨c, List.mem_of_mem_take hc, hXc⟩
            · rcases hmX.1 hXm with hXk | hXr
              · exact Or.inl ⟨_, List.getElem_mem hk, hXk⟩
              · exact Or.inr hXr
            · exact Or.inl ⟨c, List.mem_of_mem_drop hc, hXc⟩
          · rcases h6X.1 (Or.inr (Or.inr ⟨b, hb, hX⟩)) with ⟨c, hc, hXc⟩ | hXm | ⟨c, hc, hXc⟩
            · exact Or.inl ⟨c, List.mem_of_mem_take hc, hXc⟩
            · rcases hmX.1 hXm with hXk | hXr
              · exact Or.inl ⟨_, List.getElem_mem hk, hXk⟩
              · exact Or.inr hXr
            · exact Or.inl ⟨c, List.mem_of_mem_drop hc, hXc⟩
        · intro hX
          have : (∃ b ∈ st.take k, Mem X b) ∨ Mem X m ∨ (∃ b ∈ st.drop (k + 1), Mem X b) := by
            rcases hX with ⟨b, hb, hXb⟩ | hXr
            · rcases (mem_take_drop hk b).1 hb with hb | rfl | hb
              · exact Or.inl ⟨b, hb, hXb⟩
              · exact Or.inr (Or.inl (hmX.2 (Or.inl hXb)))
              · exact Or.inr (Or.inr ⟨b, hb, hXb⟩)
            · exact Or.inr (Or.inl (hmX.2 (Or.inr hXr)))
          rcases h6X.2 this with ⟨b, hb, hXb⟩ | hXx | ⟨b, hb, hXb⟩
          · exact ⟨b, Or.inl hb, hXb⟩
          · exact ⟨x, Or.inr (Or.inl rfl), hXx⟩
          · exact ⟨b, Or.inr (Or.inr hb), hXb⟩

/-- `ipv6_aggregate`: the union is preserved and no two output networks merge. -/
theorem aggregateGeneral_spec (L : List (Block 128)) (hL : ∀ b ∈ L, b.1 &&& b.2 = b.1) :
    (∀ b ∈ aggregateGeneral L, b.1 &&& b.2 = b.1) ∧
    (∀ X, (∃ b ∈ aggregateGeneral L, Mem X b) ↔ ∃ b ∈ L, Mem X b) ∧
    (aggregateGeneral L).Pairwise fun a b => mergeB a b = none ∧ mergeB b a = none := by
  have key : ∀ (L : List (Block 128)) (st : List (Block 128)), (∀ b ∈ L, b.1 &&& b.2 = b.1) →
      AggInv st → AggInv (L.foldl aggStep st) ∧
        ∀ X, (∃ b ∈ L.foldl aggStep st, Mem X b) ↔ (∃ b ∈ st, Mem X b) ∨ ∃ b ∈ L, Mem X b := by
    intro L
    induction L with
    | nil => intro st _ h; simp [h]
    | cons r L ih =>
      intro st hL hst
      obtain ⟨hinv, hunion⟩ := aggStep_spec st r hst (hL r List.mem_cons_self)
      obtain ⟨hinv', hunion'⟩ := ih (aggStep st r) (fun b hb => hL b (List.mem_cons_of_mem _ hb)) hinv
      refine ⟨hinv', fun X => ?_⟩
      rw [List.foldl_cons, hunion' X, hunion X]
      constructor
      · rintro ((h | h) | ⟨b, hb, hX⟩)
        · exact Or.inl h
        · exact Or.inr ⟨r, List.mem_cons_self, h⟩
        · exact Or.inr ⟨b, List.mem_cons_of_mem _ hb, hX⟩
      · rintro (h | ⟨b, hb, hX⟩)
        · exact Or.inl (Or.inl h)
        · rcases List.mem_cons.mp hb with rfl | hb
          · exact Or.inl (Or.inr hX)
          · exact Or.inr ⟨b, hb, hX⟩
  obtain ⟨⟨hnorm, hpw⟩, hunion⟩ := key L [] hL ⟨by simp, List.Pairwise.nil⟩
  unfold aggregateGeneral
  refine ⟨hnorm, fun X => by simpa using hunion X, ?_⟩
  exact hpw.imp_of_mem fun {a b} ha hb h => ⟨h, mergeB_none_symm (hnorm a ha) (hnorm b hb) h⟩

/-- No output network contains another. -/
theorem aggregateGeneral_no_containment (L : List (Block 128)) (hL : ∀ b ∈ L, b.1 &&& b.2 = b.1) :
    (aggregateGeneral L).Pairwise fun a b => ¬ Contains a b ∧ ¬ Contains b a := by
  obtain ⟨hnorm, -, hpw⟩ := aggregateGeneral_spec L hL
  refine hpw.imp_of_mem fun {a b} ha hb h => ⟨fun hc => ?_, fun hc => ?_⟩
  · have hs : (merge a.1 a.2 b.1 b.2).isSome := by
      rw [merge_isSome_iff _ _ _ _ (hnorm a ha) (hnorm b hb)]
      refine ⟨a.1, a.2, fun X => ⟨Or.inl, ?_⟩⟩
      rintro (hX | hX)
      · exact hX
      · exact (contains_iff a.1 a.2 b.1 b.2 (hnorm a ha) (hnorm b hb)).1 hc X hX
    simp [mergeB] at h
    simp [h] at hs
  · have hs : (merge b.1 b.2 a.1 a.2).isSome := by
      rw [merge_isSome_iff _ _ _ _ (hnorm b hb) (hnorm a ha)]
      refine ⟨b.1, b.2, fun X => ⟨Or.inl, ?_⟩⟩
      rintro (hX | hX)
      · exact hX
      · exact (contains_iff b.1 b.2 a.1 a.2 (hnorm b hb) (hnorm a ha)).1 hc X hX
    have h2 := h.2
    simp [mergeB] at h2
    simp [h2] at hs

end Ipv6

end Netip.Impl
