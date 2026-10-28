import Netip.Impl.AggregateContiguous
import Netip.Impl.BiContiguous

/-!
# `ipv6_aggregate_bicontiguous`: the groups of the level sweep

A bi-contiguous network is a rectangle: a CIDR block of high halves times a CIDR
block of low halves. The level sweep of `ipv6_aggregate_bicontiguous` works on
*groups*, the networks that share the high half and its prefix, and aggregates
each group's low halves with the stack of `ipv6_aggregate_contiguous`.

Moving the low half to the top, `rot x = (addr << 64, mask << 64)`, turns the
networks of a group into 128-bit CIDR blocks, and `merge_by_lowest_mask_bit`
commutes with it inside a group (`mergeLow_rot`): the high halves agree, so only
the low halves decide. The stack pass over a group is therefore the stack pass of
`AggregateContiguous` over the rotated blocks (`aggregate_rot`), and its results
carry over (`groupAggregate_spec`): the group's union is kept, every result stays
in the group and in the class, and the results' low halves are pairwise disjoint,
ascending and free of buddy pairs.
-/

namespace Netip.Impl.Ipv6

/-- A network as `(addr, mask)`. -/
abbrev Net := BitVec 128 × BitVec 128

/-- A normalized bi-contiguous network, what `BiContiguous<Ipv6Network>` holds. -/
def IsBiNet (x : Net) : Prop := IsBiContiguous x.2 ∧ x.1 &&& x.2 = x.1

/-- `bicontiguous_hi_addr`: the high half of the address. -/
def hiA (x : Net) : BitVec 64 := hi x.1

/-- `bicontiguous_lo_addr`: the low half of the address. -/
def loA (x : Net) : BitVec 64 := lo x.1

/-- The high half of the mask. -/
def hiM (x : Net) : BitVec 64 := hi x.2

/-- The low half of the mask. -/
def loM (x : Net) : BitVec 64 := lo x.2

/-- Two networks of one group: the same high half of address and mask. -/
def SameHi (x y : Net) : Prop := hiA x = hiA y ∧ hiM x = hiM y

/-- The low half moved to the top. -/
def rot (x : Net) : Block 128 := (x.1 <<< 64, x.2 <<< 64)

/-! ## Bit facts -/

theorem shl64_eq_iff {x y : BitVec 128} (h : hi x = hi y) : x <<< 64 = y <<< 64 ↔ x = y := by
  unfold hi at h
  bv_decide

theorem shl64_sibling_iff {x1 y1 x2 : BitVec 128} (h : hi x1 = hi y1) :
    (x2 <<< 64 ≠ 0 ∧ x1 <<< 64 ^^^ y1 <<< 64 = x2 <<< 64 &&& -(x2 <<< 64)) ↔
      (x2 ≠ 0 ∧ x1 ^^^ y1 = x2 &&& -x2) := by
  unfold hi at h
  bv_decide

theorem shl64_contains_iff {x1 x2 y1 y2 : BitVec 128} (hn : x1 &&& x2 = x1) (ha : hi x1 = hi y1)
    (hm : hi x2 = hi y2) :
    (y1 <<< 64 &&& x2 <<< 64 = x1 <<< 64 ∧ y2 <<< 64 &&& x2 <<< 64 = x2 <<< 64) ↔
      (y1 &&& x2 = x1 ∧ y2 &&& x2 = x2) := by
  unfold hi at ha hm
  bv_decide

theorem shl64_and (x y : BitVec 128) : x <<< 64 &&& y <<< 64 = (x &&& y) <<< 64 := by
  bv_decide

theorem shl64_clear (x : BitVec 128) : x <<< 64 &&& (x <<< 64 - 1) = (x &&& (x - 1)) <<< 64 := by
  bv_decide

theorem rot_isCidr {x : Net} (h : IsBiNet x) : IsCidr (rot x) := by
  obtain ⟨x1, x2⟩ := x
  simp only [IsBiNet, IsBiContiguous] at h
  simp only [rot, IsCidr, IsContiguous]
  obtain ⟨h1, h2⟩ := h
  constructor <;> bv_decide

/-- Inside a group, `merge_by_lowest_mask_bit` only looks at the low halves. -/
theorem mergeLow_rot {x y : Net} (hx : x.1 &&& x.2 = x.1) (hy : y.1 &&& y.2 = y.1)
    (hs : SameHi x y) : mergeLow (rot x) (rot y) = (mergeLow x y).map rot := by
  obtain ⟨x1, x2⟩ := x
  obtain ⟨y1, y2⟩ := y
  obtain ⟨ha, hm⟩ := hs
  simp only [hiA, hiM] at ha hm hx hy
  simp only [mergeLow, mergeByLowestMaskBit, rot]
  simp only [shl64_eq_iff hm, shl64_eq_iff ha, shl64_sibling_iff ha, shl64_contains_iff hx ha hm,
    shl64_contains_iff hy ha.symm hm.symm]
  by_cases hmm : x2 = y2
  · simp only [hmm, ↓reduceIte]
    by_cases haa : x1 = y1
    · simp only [haa, ↓reduceIte, Option.map_some]
      rfl
    · simp only [haa, ↓reduceIte]
      by_cases hsib : y2 ≠ 0 ∧ x1 ^^^ y1 = y2 &&& -y2
      · simp only [hsib, ne_eq, not_false_eq_true, and_self, ↓reduceIte, Option.map_some, rot,
          shl64_and]
        exact congrArg some (Prod.ext rfl (shl64_clear y2))
      · simp only [hsib, ↓reduceIte, Option.map_none]
  · simp only [hmm, ↓reduceIte]
    by_cases hc1 : y1 &&& x2 = x1 ∧ y2 &&& x2 = x2
    · simp only [hc1, and_self, ↓reduceIte, Option.map_some]
      rfl
    · simp only [hc1, ↓reduceIte]
      by_cases hc2 : x1 &&& y2 = y1 ∧ x2 &&& y2 = y2
      · simp only [hc2, and_self, ↓reduceIte, Option.map_some]
        rfl
      · simp only [hc2, ↓reduceIte, Option.map_none]

/-! ## Translating facts about rotated blocks -/

theorem mem_iff_rot {x r : Net} {X : BitVec 128} (hs : SameHi x r) :
    Mem X x ↔ hi X &&& hi r.2 = hi r.1 ∧ Mem (X <<< 64) (rot x) := by
  obtain ⟨x1, x2⟩ := x
  obtain ⟨r1, r2⟩ := r
  obtain ⟨ha, hm⟩ := hs
  simp only [hiA, hiM, hi] at ha hm
  simp only [Mem, rot, hi]
  bv_decide

theorem meets_iff_rot {x y : Net} (hx : x.1 &&& x.2 = x.1) (hy : y.1 &&& y.2 = y.1)
    (hs : SameHi x y) : Meets x y ↔ Meets (rot x) (rot y) := by
  obtain ⟨x1, x2⟩ := x
  obtain ⟨y1, y2⟩ := y
  obtain ⟨ha, hm⟩ := hs
  simp only [hiA, hiM, hi] at ha hm hx hy
  simp only [Meets, rot]
  bv_decide

theorem buddies_iff_rot {x y : Net} (hs : SameHi x y) : Buddies x y ↔ Buddies (rot x) (rot y) := by
  obtain ⟨x1, x2⟩ := x
  obtain ⟨y1, y2⟩ := y
  obtain ⟨ha, hm⟩ := hs
  simp only [hiA, hiM, hi] at ha hm
  simp only [Buddies, AdjacentByLowestMaskBit, rot]
  bv_decide

theorem loA_lt_of_rot {x y : Net} (h : lastAddr (rot x) < (rot y).1) : loA x < loA y := by
  obtain ⟨x1, x2⟩ := x
  obtain ⟨y1, y2⟩ := y
  simp only [lastAddr, rot] at h
  simp only [loA, lo]
  bv_decide

theorem rot_le_iff {x y : Net} : (rot x).1 ≤ (rot y).1 ↔ loA x ≤ loA y := by
  obtain ⟨x1, x2⟩ := x
  obtain ⟨y1, y2⟩ := y
  simp only [rot, loA, lo]
  bv_decide

/-! ## The stack pass over a group -/

/-- A network of the group of `r`. -/
def InGroup (r x : Net) : Prop := IsBiNet x ∧ SameHi x r

theorem sameHi_trans {x y z : Net} (h1 : SameHi x y) (h2 : SameHi y z) : SameHi x z :=
  ⟨h1.1.trans h2.1, h1.2.trans h2.2⟩

theorem sameHi_symm {x y : Net} (h : SameHi x y) : SameHi y x := ⟨h.1.symm, h.2.symm⟩

/-- A merge inside a group stays in the group. -/
theorem mergeLow_sameHi {t c m : Net} (hs : SameHi t c) (h : mergeLow t c = some m) :
    SameHi t m := by
  obtain ⟨t1, t2⟩ := t
  obtain ⟨c1, c2⟩ := c
  obtain ⟨m1, m2⟩ := m
  obtain ⟨ha, hm⟩ := hs
  simp only [SameHi, hiA, hiM, hi] at ha hm ⊢
  unfold mergeLow mergeByLowestMaskBit at h
  simp only at h
  by_cases hmm : t2 = c2
  · rw [ite_eq_left hmm] at h
    by_cases he : t1 = c1
    · rw [ite_eq_left he] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨rfl, rfl⟩
    · rw [ite_eq_right he] at h
      by_cases hsib : t2 ≠ 0 ∧ t1 ^^^ c1 = t2 &&& -t2
      · rw [ite_eq_left hsib] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨-, hx⟩ := hsib
        constructor <;> bv_decide
      · rw [ite_eq_right hsib] at h
        simp at h
  · rw [ite_eq_right hmm] at h
    by_cases hc1 : c1 &&& t2 = t1 ∧ c2 &&& t2 = t2
    · rw [ite_eq_left hc1] at h
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨rfl, rfl⟩
    · rw [ite_eq_right hc1] at h
      by_cases hc2 : t1 &&& c2 = c1 ∧ t2 &&& c2 = c2
      · rw [ite_eq_left hc2] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        exact ⟨ha, hm⟩
      · rw [ite_eq_right hc2] at h
        simp at h

theorem mergeLow_inGroup {r t c m : Net} (ht : InGroup r t) (hc : InGroup r c)
    (h : mergeLow t c = some m) : InGroup r m := by
  have h' : mergeByLowestMaskBit t.1 t.2 c.1 c.2 = some (m.1, m.2) := h
  refine ⟨⟨mergeByLowestMaskBit_biContiguous ht.1.1 hc.1.1 h',
    mergeByLowestMaskBit_normalized ht.1.2 hc.1.2 h'⟩, ?_⟩
  exact sameHi_trans (sameHi_symm (mergeLow_sameHi (sameHi_trans ht.2 (sameHi_symm hc.2)) h)) ht.2

theorem push_inGroup {r : Net} :
    ∀ (st : List Net) (c : Net), InGroup r c → (∀ t ∈ st, InGroup r t) →
      ∀ x ∈ push c st, InGroup r x := by
  intro st
  induction st with
  | nil =>
    intro c hc _ x hx
    simp only [push, List.mem_singleton] at hx
    exact hx ▸ hc
  | cons t rest ih =>
    intro c hc hst x hx
    have ht := hst t List.mem_cons_self
    simp only [push] at hx
    split at hx
    · rename_i m hm
      exact ih m (mergeLow_inGroup ht hc hm) (fun y hy => hst y (List.mem_cons_of_mem _ hy)) x hx
    · rcases List.mem_cons.mp hx with rfl | hx
      · exact hc
      · exact hst x hx

theorem push_rot {r : Net} :
    ∀ (st : List Net) (c : Net), InGroup r c → (∀ t ∈ st, InGroup r t) →
      push (rot c) (st.map rot) = (push c st).map rot := by
  intro st
  induction st with
  | nil => intro c _ _; rfl
  | cons t rest ih =>
    intro c hc hst
    have ht := hst t List.mem_cons_self
    have hrot : mergeLow (rot t) (rot c) = (mergeLow t c).map rot :=
      mergeLow_rot ht.1.2 hc.1.2 (sameHi_trans ht.2 (sameHi_symm hc.2))
    simp only [List.map_cons, push, hrot]
    cases hm : mergeLow t c with
    | none => rfl
    | some m =>
      exact ih m (mergeLow_inGroup ht hc hm) fun y hy => hst y (List.mem_cons_of_mem _ hy)

theorem foldl_push_rot {r : Net} :
    ∀ (L st : List Net), (∀ x ∈ L, InGroup r x) → (∀ t ∈ st, InGroup r t) →
      (L.map rot).foldl (fun st b => push b st) (st.map rot) =
          (L.foldl (fun st b => push b st) st).map rot ∧
        ∀ x ∈ L.foldl (fun st b => push b st) st, InGroup r x := by
  intro L
  induction L with
  | nil => intro st _ hst; exact ⟨rfl, hst⟩
  | cons c L ih =>
    intro st hL hst
    have hc := hL c List.mem_cons_self
    simp only [List.map_cons, List.foldl_cons]
    rw [push_rot st c hc hst]
    exact ih (push c st) (fun x hx => hL x (List.mem_cons_of_mem _ hx)) (push_inGroup st c hc hst)

/-- The stack pass over a group is the stack pass over its rotated blocks. -/
theorem aggregate_rot {r : Net} {L : List Net} (hL : ∀ x ∈ L, InGroup r x) :
    aggregate (L.map rot) = (aggregate L).map rot ∧ ∀ x ∈ aggregate L, InGroup r x := by
  obtain ⟨h1, h2⟩ := foldl_push_rot L [] hL (by simp)
  refine ⟨?_, fun x hx => h2 x (List.mem_reverse.mp hx)⟩
  unfold aggregate
  rw [List.map_nil] at h1
  rw [h1, List.map_reverse]

/-- The stack pass over a group sorted by low address: the results stay in the group,
their low halves are ascending, pairwise disjoint and free of buddy pairs, and the
union is kept. -/
theorem groupAggregate_spec {r : Net} (L : List Net) (hL : ∀ x ∈ L, InGroup r x)
    (hsorted : L.Pairwise fun x y => loA x ≤ loA y) :
    (∀ x ∈ aggregate L, InGroup r x) ∧
      (aggregate L).Pairwise (fun x y => loA x < loA y ∧ ¬ Meets x y ∧ ¬ Buddies x y) ∧
      ∀ X, (∃ x ∈ aggregate L, Mem X x) ↔ ∃ x ∈ L, Mem X x := by
  obtain ⟨hagg, hin⟩ := aggregate_rot hL
  have hcidr : ∀ B ∈ L.map rot, IsCidr B := by
    intro B hB
    obtain ⟨x, hx, rfl⟩ := List.mem_map.mp hB
    exact rot_isCidr (hL x hx).1
  have hsorted' : (L.map rot).Pairwise fun x y => x.1 ≤ y.1 := by
    rw [List.pairwise_map]
    exact hsorted.imp fun h => rot_le_iff.mpr h
  obtain ⟨⟨hall, hpw⟩, hunion⟩ :=
    foldl_push_spec (L.map rot) hcidr hsorted' [] ⟨by simp, List.Pairwise.nil⟩ (by simp)
  have hst : (aggregate (L.map rot)).Pairwise
      (fun lo hi => lastAddr lo < hi.1 ∧ ¬ Buddies lo hi) := by
    unfold aggregate
    rw [List.pairwise_reverse]
    exact hpw
  rw [hagg, List.pairwise_map] at hst
  refine ⟨hin, ?_, fun X => ?_⟩
  · refine hst.imp_of_mem fun {x y} hx hy h => ⟨loA_lt_of_rot h.1, ?_, ?_⟩
    · have hxg := hin x hx
      have hyg := hin y hy
      have hs : SameHi x y := sameHi_trans hxg.2 (sameHi_symm hyg.2)
      rw [meets_iff_rot hxg.1.2 hyg.1.2 hs]
      exact fun hm => not_meets_of_lt (rot_isCidr hxg.1) (rot_isCidr hyg.1) h.1 hm.symm
    · have hxg := hin x hx
      have hyg := hin y hy
      rw [buddies_iff_rot (sameHi_trans hxg.2 (sameHi_symm hyg.2))]
      exact h.2
  · have hu := hunion (X <<< 64)
    have hagg' : ∀ B, B ∈ aggregate (L.map rot) ↔
        B ∈ (L.map rot).foldl (fun st b => push b st) [] := by
      intro B
      unfold aggregate
      exact List.mem_reverse
    constructor
    · rintro ⟨x, hx, hX⟩
      have hxg := hin x hx
      rw [mem_iff_rot hxg.2] at hX
      have hmem : ∃ B ∈ (L.map rot).foldl (fun st b => push b st) [], Mem (X <<< 64) B :=
        ⟨rot x, (hagg' _).mp (by rw [hagg]; exact List.mem_map_of_mem hx), hX.2⟩
      rcases hu.mp hmem with ⟨B, hB, -⟩ | ⟨B, hB, hYB⟩
      · simp at hB
      · obtain ⟨y, hy, rfl⟩ := List.mem_map.mp hB
        exact ⟨y, hy, (mem_iff_rot (hL y hy).2).mpr ⟨hX.1, hYB⟩⟩
    · rintro ⟨y, hy, hX⟩
      have hyg := hL y hy
      rw [mem_iff_rot hyg.2] at hX
      obtain ⟨B, hB, hYB⟩ := hu.mpr (Or.inr ⟨rot y, List.mem_map_of_mem hy, hX.2⟩)
      have hB' : B ∈ (aggregate L).map rot := by
        rw [← hagg]
        exact (hagg' B).mpr hB
      obtain ⟨x, hx, rfl⟩ := List.mem_map.mp hB'
      exact ⟨x, hx, (mem_iff_rot (hin x hx).2).mpr ⟨hX.1, hYB⟩⟩

end Netip.Impl.Ipv6
