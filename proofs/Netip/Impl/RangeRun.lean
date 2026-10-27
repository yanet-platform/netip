import Netip.Impl.AggregateContiguous
import Netip.Impl.Range

/-!
# Range-to-CIDR iterators over a whole run

`Ipv4RangeNetworks` is transcribed as a state machine (`rangeInit`, `rangeNext`)
and run to completion (`rangeRun`).

Proved, for every `first ≤ last`: the run emits at most `2 · 32 - 2 = 62` CIDR
blocks, pairwise disjoint, with no buddy pair among them, whose union is exactly
`[first, last]` (`range_spec`). By `CidrCover` they are the minimum CIDR cover of
the range, and every minimum cover is made of them (`range_minimal`,
`range_unique`). For `first > last` the run is empty.

Each emitted block is greedy: when it is the lower half of its parent, the
parent ends past `last`. Consecutive blocks therefore never form a buddy pair,
and blocks further apart cannot. A potential, `popcount(ascending)` plus the
`popcount` of the remaining descending size, drops by one per call.
-/

namespace Netip.Impl.Ipv4

/-- The fields of `Ipv4RangeNetworks`. -/
structure RangeState where
  first : BitVec 32
  last : BitVec 32
  ascending : BitVec 32
  done : Bool

/-- `ipv4_range_to_networks`. -/
def rangeInit (first last : BitVec 32) : RangeState :=
  if last < first then ⟨first, last, 0, true⟩
  else if (first ^^^ last) &&& ((first ^^^ last) + 1) = 0 ∧ first &&& (first ^^^ last) = 0 then
    ⟨first, last, 0, false⟩
  else ⟨first, last, (last &&& -(1#32 <<< (31#32 - (first ^^^ last).clz))) - first, false⟩

/-- The remaining `size` of the descending phase, in `u64`. -/
def descSize (first last : BitVec 32) : BitVec 64 := last.setWidth 64 - first.setWidth 64 + 1

/-- `block_max` of the descending phase. -/
def descBlockMax (first last : BitVec 32) : BitVec 32 :=
  ((BitVec.allOnes 64 >>> 1) >>> (descSize first last).clz).setWidth 32

/-- `Ipv4RangeNetworks::next`. -/
def rangeNext (s : RangeState) : Option (Block 32) × RangeState :=
  if s.done then (none, s)
  else if s.ascending ≠ 0 then
    (some (s.first, s.ascending ||| -s.ascending),
      ⟨s.first + (s.ascending &&& -s.ascending), s.last,
        s.ascending ^^^ (s.ascending &&& -s.ascending), false⟩)
  else
    (some (s.first, ~~~(descBlockMax s.first s.last)),
      ⟨s.first + descBlockMax s.first s.last + 1, s.last, 0,
        s.first + descBlockMax s.first s.last = s.last⟩)

/-- Calls `next` up to `n` times, collecting the blocks. -/
def rangeRun : Nat → RangeState → List (Block 32)
  | 0, _ => []
  | n + 1, s =>
    match rangeNext s with
    | (some b, s') => b :: rangeRun n s'
    | (none, _) => []

/-- The highest set bit of a `u64`. -/
def highestBit64 (x : BitVec 64) : BitVec 64 := (1#64 <<< 63) >>> x.clz

/-- A greedy block: if it is the lower half of its parent, the parent ends past `l`. -/
def Greedy (b : Block 32) (l : BitVec 32) : Prop :=
  b.2 = 0 ∨ ¬ ((parent b).1 = b.1 ∧ lastAddr (parent b) ≤ l)

/-- Ascending phase with boundary `x + a`. -/
def AscInv (x l a : BitVec 32) : Prop :=
  a ≠ 0 ∧ x ≤ x + a ∧ x + a ≤ l ∧
  (x + a) &&& (highestBit32 a - 1) = 0 ∧
  ((x + a) &&& ((highestBit32 a <<< 1) - 1) = 0 ∨
    (a &&& (a - 1) = 0 ∧ descSize (x + a) l < (highestBit32 a).setWidth 64)) ∧
  (x + a).setWidth 64 &&& (highestBit64 (descSize (x + a) l) - 1) = 0

/-- Descending phase: `x` is aligned to the largest block that fits. -/
def DescInv (x l : BitVec 32) : Prop :=
  x ≤ l ∧ x.setWidth 64 &&& (highestBit64 (descSize x l) - 1) = 0

def StateInv (s : RangeState) : Prop :=
  s.done = false → (s.ascending ≠ 0 ∧ AscInv s.first s.last s.ascending) ∨
    (s.ascending = 0 ∧ DescInv s.first s.last)

/-- The number of calls still to emit a block. -/
def potential (s : RangeState) : Nat :=
  if s.done then 0
  else if s.ascending ≠ 0 then
    s.ascending.cpop.toNat + (descSize (s.first + s.ascending) s.last).cpop.toNat
  else (descSize s.first s.last).cpop.toNat

theorem addr_le_lastAddr (B : Block 32) : B.1 ≤ lastAddr B := by
  obtain ⟨b1, b2⟩ := B
  simp only [lastAddr]
  bv_decide

theorem mem_iff_interval {b : Block 32} (hb : IsCidr b) (X : BitVec 32) :
    Mem X b ↔ b.1 ≤ X ∧ X ≤ lastAddr b := by
  obtain ⟨b1, b2⟩ := b
  simp only [IsCidr, IsContiguous, Mem, lastAddr] at *
  bv_decide

theorem asc_step (x l a : BitVec 32) (h : AscInv x l a) :
    IsCidr (x, a ||| -a) ∧ lastAddr (x, a ||| -a) < l ∧ lastAddr (x, a ||| -a) + 1 = x + (a &&& -a) ∧
    x ≤ lastAddr (x, a ||| -a) ∧ Greedy (x, a ||| -a) l ∧
    (x + (a &&& -a)) + (a ^^^ (a &&& -a)) = x + a ∧
    (a ^^^ (a &&& -a) ≠ 0 → AscInv (x + (a &&& -a)) l (a ^^^ (a &&& -a))) ∧
    (a ^^^ (a &&& -a) = 0 → DescInv (x + (a &&& -a)) l) ∧
    (a ^^^ (a &&& -a)).cpop + 1 = a.cpop := by
  simp only [AscInv, DescInv, IsCidr, IsContiguous, lastAddr, Greedy, parent, descSize,
    highestBit32, highestBit64] at *
  bv_decide

theorem desc_step (x l : BitVec 32) (h : DescInv x l) :
    IsCidr (x, ~~~(descBlockMax x l)) ∧ lastAddr (x, ~~~(descBlockMax x l)) = x + descBlockMax x l ∧
    x ≤ x + descBlockMax x l ∧ x + descBlockMax x l ≤ l ∧ Greedy (x, ~~~(descBlockMax x l)) l ∧
    (x + descBlockMax x l ≠ l →
      DescInv (x + descBlockMax x l + 1) l ∧
      (descSize (x + descBlockMax x l + 1) l).cpop + 1 = (descSize x l).cpop) ∧
    (x + descBlockMax x l = l → (descSize x l).cpop = 1) := by
  simp only [DescInv, IsCidr, IsContiguous, lastAddr, Greedy, parent, descSize, descBlockMax,
    highestBit64] at *
  bv_decide

theorem cpop_sum_le {a : BitVec 32} {z : BitVec 64} (h : a.cpop.setWidth 64 + z.cpop ≤ 62#64) :
    a.cpop.toNat + z.cpop.toNat ≤ 62 := by
  have h1 := BitVec.toNat_cpop_le a
  have h2 := BitVec.toNat_cpop_le z
  rw [BitVec.le_def, BitVec.toNat_add, BitVec.toNat_setWidth] at h
  simp at h
  omega

theorem cpop_le_62 {z : BitVec 64} (h : z.cpop ≤ 62#64) : z.cpop.toNat ≤ 62 := by
  rw [BitVec.le_def] at h
  simpa using h

theorem init_spec (x l : BitVec 32) (h : x ≤ l) :
    (rangeInit x l).first = x ∧ (rangeInit x l).last = l ∧ (rangeInit x l).done = false ∧
    StateInv (rangeInit x l) ∧ potential (rangeInit x l) ≤ 62 := by
  have hnlt : ¬ l < x := by bv_decide
  unfold rangeInit
  rw [ite_eq_right hnlt]
  by_cases hs : (x ^^^ l) &&& ((x ^^^ l) + 1) = 0 ∧ x &&& (x ^^^ l) = 0
  · rw [ite_eq_left hs]
    refine ⟨rfl, rfl, rfl, fun _ => Or.inr ⟨rfl, ?_⟩, ?_⟩
    · simp only [DescInv, descSize, highestBit64]
      bv_decide
    · simp only [potential, Bool.false_eq_true, ↓reduceIte, ne_eq, not_true_eq_false]
      apply cpop_le_62
      simp only [descSize]
      bv_decide
  · rw [ite_eq_right hs]
    have ha : (l &&& -(1#32 <<< (31#32 - (x ^^^ l).clz))) - x ≠ 0 := by bv_decide
    refine ⟨rfl, rfl, rfl, fun _ => Or.inl ⟨ha, ?_⟩, ?_⟩
    · simp only [AscInv, descSize, highestBit32, highestBit64]
      bv_decide
    · simp only [potential, Bool.false_eq_true, ↓reduceIte]
      rw [ite_eq_left ha]
      apply cpop_sum_le
      simp only [descSize]
      bv_decide

theorem not_buddies_of_greedy {b c : Block 32} {l : BitVec 32} (hb : IsCidr b) (hc : IsCidr c)
    (hg : Greedy b l) (hbl : lastAddr b < l) (hadj : c.1 = lastAddr b + 1) (hcl : lastAddr c ≤ l) :
    ¬ Buddies b c := by
  obtain ⟨b1, b2⟩ := b
  obtain ⟨c1, c2⟩ := c
  simp only [IsCidr, IsContiguous, Greedy, parent, lastAddr, Buddies, AdjacentByLowestMaskBit] at *
  bv_decide

theorem cpop_toNat_of_add64 {x y : BitVec 64} (h : x.cpop + 1 = y.cpop) :
    x.cpop.toNat + 1 = y.cpop.toNat := by
  have hle := BitVec.toNat_cpop_le x
  rw [← h, BitVec.toNat_add]
  simp
  omega

theorem cpop_pos32 {x : BitVec 32} (h : x ≠ 0) : 1 ≤ x.cpop.toNat := by
  have h0 : x.cpop ≠ 0 := by bv_decide
  have : x.cpop.toNat ≠ 0 := fun h' => h0 (BitVec.eq_of_toNat_eq (by simpa using h'))
  omega

theorem cpop_pos64 {x : BitVec 64} (h : x ≠ 0) : 1 ≤ x.cpop.toNat := by
  have h0 : x.cpop ≠ 0 := by bv_decide
  have : x.cpop.toNat ≠ 0 := fun h' => h0 (BitVec.eq_of_toNat_eq (by simpa using h'))
  omega

theorem cpop_eq_one {x : BitVec 64} (h : x.cpop = 1) : x.cpop.toNat = 1 := by
  rw [h]
  rfl

theorem potential_pos {s : RangeState} (hs : StateInv s) (hd : s.done = false) :
    1 ≤ potential s := by
  rcases hs hd with ⟨ha, -⟩ | ⟨ha, hdesc⟩
  · simp only [potential, hd, Bool.false_eq_true, ↓reduceIte]
    rw [ite_eq_left ha]
    have := cpop_pos32 ha
    omega
  · simp only [potential, hd, Bool.false_eq_true, ↓reduceIte, ha, ne_eq, not_true_eq_false]
    apply cpop_pos64
    simp only [DescInv, descSize] at hdesc ⊢
    bv_decide

theorem rangeRun_done (n : Nat) (s : RangeState) (hd : s.done = true) : rangeRun n s = [] := by
  cases n <;> simp [rangeRun, rangeNext, hd]

theorem rangeNext_asc (x l a : BitVec 32) (ha : a ≠ 0) :
    rangeNext ⟨x, l, a, false⟩ =
      (some (x, a ||| -a), ⟨x + (a &&& -a), l, a ^^^ (a &&& -a), false⟩) := by
  unfold rangeNext
  simp only [Bool.false_eq_true, ↓reduceIte]
  rw [ite_eq_left ha]

theorem rangeNext_desc (x l : BitVec 32) :
    rangeNext ⟨x, l, 0, false⟩ =
      (some (x, ~~~(descBlockMax x l)),
        ⟨x + descBlockMax x l + 1, l, 0, decide (x + descBlockMax x l = l)⟩) := by
  unfold rangeNext
  simp only [Bool.false_eq_true, ↓reduceIte]
  rw [ite_eq_right (not_not_intro rfl)]

theorem rangeRun_asc (n : Nat) (x l a : BitVec 32) (ha : a ≠ 0) :
    rangeRun (n + 1) ⟨x, l, a, false⟩ =
      (x, a ||| -a) :: rangeRun n ⟨x + (a &&& -a), l, a ^^^ (a &&& -a), false⟩ := by
  rw [rangeRun, rangeNext_asc x l a ha]

theorem rangeRun_desc (n : Nat) (x l : BitVec 32) :
    rangeRun (n + 1) ⟨x, l, 0, false⟩ =
      (x, ~~~(descBlockMax x l)) ::
        rangeRun n ⟨x + descBlockMax x l + 1, l, 0, decide (x + descBlockMax x l = l)⟩ := by
  rw [rangeRun, rangeNext_desc x l]

/-- Prepending a greedy block to a run that starts right after it. -/
theorem cons_spec (b : Block 32) (x l : BitVec 32) (rest : List (Block 32)) (y : BitVec 32)
    (hb : IsCidr b) (hbx : b.1 = x) (hg : Greedy b l) (hbl : lastAddr b < l)
    (hy : lastAddr b + 1 = y) (hxb : x ≤ lastAddr b)
    (hall : ∀ c ∈ rest, IsCidr c ∧ Greedy c l)
    (hpw : rest.Pairwise fun b c => lastAddr b < c.1 ∧ ¬ Buddies b c)
    (hunion : ∀ X, (∃ c ∈ rest, Mem X c) ↔ y ≤ X ∧ X ≤ l)
    (hhead : ∀ c ∈ rest.head?, c.1 = y) :
    (∀ c ∈ b :: rest, IsCidr c ∧ Greedy c l) ∧
    (b :: rest).Pairwise (fun b c => lastAddr b < c.1 ∧ ¬ Buddies b c) ∧
    (∀ X, (∃ c ∈ b :: rest, Mem X c) ↔ x ≤ X ∧ X ≤ l) := by
  have hrestge : ∀ c ∈ rest, y ≤ c.1 ∧ lastAddr c ≤ l := by
    intro c hc
    have h1 := (hunion c.1).1 ⟨c, hc, mem_addr (hall c hc).1⟩
    have h2 := (hunion (lastAddr c)).1 ⟨c, hc, ((mem_iff_interval (hall c hc).1 _).2
      ⟨addr_le_lastAddr c, BitVec.le_refl _⟩)⟩
    exact ⟨h1.1, h2.2⟩
  refine ⟨fun c hc => ?_, List.pairwise_cons.mpr ⟨fun c hc => ?_, hpw⟩, fun X => ?_⟩
  · rcases List.mem_cons.mp hc with rfl | hc
    · exact ⟨hb, hg⟩
    · exact hall c hc
  · obtain ⟨hyc, hcl⟩ := hrestge c hc
    have hlt : lastAddr b < c.1 := by
      subst hy
      obtain ⟨b1, b2⟩ := b
      simp only [lastAddr] at *
      bv_decide
    refine ⟨hlt, ?_⟩
    cases rest with
    | nil => simp at hc
    | cons h t =>
      rcases List.mem_cons.mp hc with rfl | hc'
      · have hcy : c.1 = y := hhead c rfl
        exact not_buddies_of_greedy hb (hall c List.mem_cons_self).1 hg hbl (hcy.trans hy.symm) hcl
      · have hhy : h.1 = y := hhead h rfl
        have hbh : lastAddr b < h.1 := by
          subst hy
          rw [hhy]
          obtain ⟨b1, b2⟩ := b
          simp only [lastAddr] at *
          bv_decide
        exact (far_apart hb (hall h List.mem_cons_self).1 (hall c (List.mem_cons_of_mem _ hc')).1 hbh
          ((List.pairwise_cons.mp hpw).1 c hc').1).2
  · have hmb := mem_iff_interval hb X
    constructor
    · rintro ⟨c, hc, hX⟩
      rcases List.mem_cons.mp hc with rfl | hc
      · have := hmb.1 hX
        subst hbx
        obtain ⟨b1, b2⟩ := c
        simp only [lastAddr] at *
        constructor <;> bv_decide
      · have := (hunion X).1 ⟨c, hc, hX⟩
        subst hy hbx
        obtain ⟨b1, b2⟩ := b
        simp only [lastAddr] at *
        constructor <;> bv_decide
    · rintro ⟨h1, h2⟩
      by_cases hX : X ≤ lastAddr b
      · exact ⟨b, List.mem_cons_self, hmb.2 ⟨hbx ▸ h1, hX⟩⟩
      · obtain ⟨c, hc, hXc⟩ := (hunion X).2 ⟨by subst hy; bv_decide, h2⟩
        exact ⟨c, List.mem_cons_of_mem _ hc, hXc⟩

theorem rangeRun_spec (n : Nat) : ∀ s : RangeState, StateInv s → s.done = false →
    potential s ≤ n →
    (rangeRun n s).length = potential s ∧
    (∀ b ∈ rangeRun n s, IsCidr b ∧ Greedy b s.last) ∧
    (rangeRun n s).Pairwise (fun b c => lastAddr b < c.1 ∧ ¬ Buddies b c) ∧
    (∀ X, (∃ b ∈ rangeRun n s, Mem X b) ↔ s.first ≤ X ∧ X ≤ s.last) ∧
    (∀ b ∈ (rangeRun n s).head?, b.1 = s.first) := by
  induction n with
  | zero =>
    intro s hs hd hp
    have := potential_pos hs hd
    omega
  | succ n ih =>
    intro s hs hd hp
    obtain ⟨x, l, a, done⟩ := s
    simp only at hd
    subst hd
    rcases hs rfl with ⟨ha, hasc⟩ | ⟨ha, hdesc⟩
    · simp only at ha hasc
      obtain ⟨hcidr, hlt, hnext, hle, hg, hB, hasc', hdesc', hcp⟩ := asc_step x l a hasc
      rw [rangeRun_asc n x l a ha]
      have hcpn := cpop_toNat_of_add hcp
      have hs' : StateInv ⟨x + (a &&& -a), l, a ^^^ (a &&& -a), false⟩ := by
        intro _
        by_cases ha' : a ^^^ (a &&& -a) = 0
        · exact Or.inr ⟨ha', hdesc' ha'⟩
        · exact Or.inl ⟨ha', hasc' ha'⟩
      have hp' : potential ⟨x + (a &&& -a), l, a ^^^ (a &&& -a), false⟩ + 1 =
          potential ⟨x, l, a, false⟩ := by
        simp only [potential, Bool.false_eq_true, ↓reduceIte]
        rw [ite_eq_left ha]
        by_cases ha' : a ^^^ (a &&& -a) = 0
        · rw [ite_eq_right (not_not_intro ha')]
          have hx : x + (a &&& -a) = x + a := by
            rw [← hB, ha']
            simp
          rw [hx]
          rw [ha'] at hcpn
          simp at hcpn
          omega
        · rw [ite_eq_left ha', hB]
          omega
      obtain ⟨hlen, hall, hpw, hunion, hhead⟩ := ih _ hs' rfl (by omega)
      simp only at hall hunion hhead
      obtain ⟨hall', hpw', hunion'⟩ := cons_spec (x, a ||| -a) x l _ (x + (a &&& -a)) hcidr rfl hg
        hlt hnext hle hall hpw hunion hhead
      refine ⟨by simp only [List.length_cons]; omega, hall', hpw', hunion', by simp⟩
    · simp only at ha hdesc
      subst ha
      obtain ⟨hcidr, hlast, hxle, hle, hg, hmore, hone⟩ := desc_step x l hdesc
      rw [rangeRun_desc n x l]
      by_cases hend : x + descBlockMax x l = l
      · rw [rangeRun_done n _ (by simp [hend])]
        have hp1 : potential ⟨x, l, 0, false⟩ = 1 := by
          simp only [potential, Bool.false_eq_true, ↓reduceIte, ne_eq, not_true_eq_false]
          exact cpop_eq_one (hone hend)
        refine ⟨hp1.symm, fun b hb => ?_, List.pairwise_singleton _ _, fun X => ?_, by simp⟩
        · simp only [List.mem_singleton] at hb
          subst hb
          exact ⟨hcidr, hg⟩
        · simp only [List.mem_singleton, exists_eq_left]
          rw [mem_iff_interval hcidr, hlast, hend]
      · obtain ⟨hdesc', hcp⟩ := hmore hend
        have hcpn := cpop_toNat_of_add64 hcp
        have hs' : StateInv ⟨x + descBlockMax x l + 1, l, 0, decide (x + descBlockMax x l = l)⟩ := by
          intro _
          exact Or.inr ⟨rfl, hdesc'⟩
        have hd' : decide (x + descBlockMax x l = l) = false := by simp [hend]
        have hp' : potential ⟨x + descBlockMax x l + 1, l, 0, decide (x + descBlockMax x l = l)⟩ + 1 =
            potential ⟨x, l, 0, false⟩ := by
          simp only [potential, hd', Bool.false_eq_true, ↓reduceIte, ne_eq, not_true_eq_false]
          exact hcpn
        obtain ⟨hlen, hall, hpw, hunion, hhead⟩ := ih _ hs' hd' (by omega)
        simp only at hall hunion hhead
        have hlt : lastAddr (x, ~~~(descBlockMax x l)) < l := by
          rw [hlast]
          bv_decide
        have hxl : x ≤ lastAddr (x, ~~~(descBlockMax x l)) := by
          rw [hlast]
          exact hxle
        obtain ⟨hall', hpw', hunion'⟩ := cons_spec (x, ~~~(descBlockMax x l)) x l _
          (x + descBlockMax x l + 1) hcidr rfl hg hlt (by rw [hlast]) hxl hall hpw hunion hhead
        refine ⟨by simp only [List.length_cons]; omega, hall', hpw', hunion', by simp⟩

/-- `ipv4_range_to_networks(first, last)` with `first ≤ last` emits at most 62 CIDR
blocks, pairwise disjoint, without buddy pairs, whose union is `[first, last]`. -/
theorem range_spec (f l : BitVec 32) (h : f ≤ l) :
    (rangeRun 64 (rangeInit f l)).length ≤ 62 ∧
    (∀ b ∈ rangeRun 64 (rangeInit f l), IsCidr b) ∧
    PairwiseDisjoint (rangeRun 64 (rangeInit f l)) ∧
    (∀ b ∈ rangeRun 64 (rangeInit f l), ∀ c ∈ rangeRun 64 (rangeInit f l), ¬ Buddies b c) ∧
    ∀ X, (∃ b ∈ rangeRun 64 (rangeInit f l), Mem X b) ↔ f ≤ X ∧ X ≤ l := by
  obtain ⟨hf, hl, hd, hs, hp⟩ := init_spec f l h
  obtain ⟨hlen, hall, hpw, hunion, -⟩ := rangeRun_spec 64 _ hs hd (by omega)
  rw [hf, hl] at hunion
  refine ⟨by omega, fun b hb => (hall b hb).1, ?_, ?_, hunion⟩
  · unfold PairwiseDisjoint
    exact hpw.imp_of_mem fun {b c} hb hc hbc hm =>
      not_meets_of_lt (hall b hb).1 (hall c hc).1 hbc.1 hm.symm
  · intro b hb c hc hbc
    by_cases heq : b = c
    · subst heq
      exact not_buddies_self b hbc
    · exact pairwise_forall_ne (R := fun b c => ¬ Buddies b c)
        (fun a b h hb => h (buddies_symm hb)) (hpw.imp fun h => h.2) b hb c hc heq hbc

/-- The range is empty when `first > last`. -/
theorem range_empty (f l : BitVec 32) (h : l < f) : rangeRun 64 (rangeInit f l) = [] := by
  apply rangeRun_done
  simp [rangeInit, h]

/-- No CIDR cover of `[first, last]` is shorter than the iterator's output. -/
theorem range_minimal (f l : BitVec 32) (h : f ≤ l) (C : List (Block 32)) (hC : ∀ B ∈ C, IsCidr B)
    (hcov : ∀ X, (∃ B ∈ C, Mem X B) ↔ f ≤ X ∧ X ≤ l) :
    (rangeRun 64 (rangeInit f l)).length ≤ C.length := by
  obtain ⟨-, hcidr, hdis, hnb, hunion⟩ := range_spec f l h
  exact cover_minimal _ C (fun X => f ≤ X ∧ X ≤ l) hdis
    (maximal_of_no_buddies _ _ hcidr hdis hunion hnb) hC hcov

/-- Every CIDR cover of `[first, last]` that is no longer than the output is made of
its blocks. -/
theorem range_unique (f l : BitVec 32) (h : f ≤ l) (C : List (Block 32)) (hC : ∀ B ∈ C, IsCidr B)
    (hcov : ∀ X, (∃ B ∈ C, Mem X B) ↔ f ≤ X ∧ X ≤ l)
    (hlen : C.length ≤ (rangeRun 64 (rangeInit f l)).length) :
    ∀ c ∈ C, c ∈ rangeRun 64 (rangeInit f l) := by
  obtain ⟨-, hcidr, hdis, hnb, hunion⟩ := range_spec f l h
  exact cover_unique _ C _ hdis (maximal_of_no_buddies _ _ hcidr hdis hunion hnb) hunion hC hcov hlen

end Netip.Impl.Ipv4

namespace Netip.Impl.Ipv6

/-- The fields of `Ipv6RangeNetworks`. -/
structure RangeState where
  first : BitVec 128
  last : BitVec 128
  ascending : BitVec 128
  done : Bool

/-- `ipv6_range_to_networks`. -/
def rangeInit (first last : BitVec 128) : RangeState :=
  if last < first then ⟨first, last, 0, true⟩
  else if (first ^^^ last) &&& ((first ^^^ last) + 1) = 0 ∧ first &&& (first ^^^ last) = 0 then
    ⟨first, last, 0, false⟩
  else ⟨first, last, (last &&& -(1#128 <<< (127#128 - (first ^^^ last).clz))) - first, false⟩

/-- The remaining `size` of the descending phase, in 129 bits so that the full range is `2^128`. -/
def descSize (first last : BitVec 128) : BitVec 129 := last.setWidth 129 - first.setWidth 129 + 1

/-- `block_max` of the descending phase, computed from the wrapping `u128` size on
64-bit words as `Range.blockMax` transcribes it. -/
def descBlockMax (first last : BitVec 128) : BitVec 128 := blockMax (last - first + 1)

/-- `Ipv6RangeNetworks::next`. -/
def rangeNext (s : RangeState) : Option (Block 128) × RangeState :=
  if s.done then (none, s)
  else if s.ascending ≠ 0 then
    (some (s.first, s.ascending ||| -s.ascending),
      ⟨s.first + (s.ascending &&& -s.ascending), s.last,
        s.ascending ^^^ (s.ascending &&& -s.ascending), false⟩)
  else
    (some (s.first, ~~~(descBlockMax s.first s.last)),
      ⟨s.first + descBlockMax s.first s.last + 1, s.last, 0,
        s.first + descBlockMax s.first s.last = s.last⟩)

/-- Calls `next` up to `n` times, collecting the blocks. -/
def rangeRun : Nat → RangeState → List (Block 128)
  | 0, _ => []
  | n + 1, s =>
    match rangeNext s with
    | (some b, s') => b :: rangeRun n s'
    | (none, _) => []

/-- The highest set bit of a 129-bit value. -/
def highestBit129 (x : BitVec 129) : BitVec 129 := (1#129 <<< 128) >>> x.clz

/-- A greedy block: if it is the lower half of its parent, the parent ends past `l`. -/
def Greedy (b : Block 128) (l : BitVec 128) : Prop :=
  b.2 = 0 ∨ ¬ ((parent b).1 = b.1 ∧ lastAddr (parent b) ≤ l)

/-- Ascending phase with boundary `x + a`. -/
def AscInv (x l a : BitVec 128) : Prop :=
  a ≠ 0 ∧ x ≤ x + a ∧ x + a ≤ l ∧
  (x + a) &&& (highestBit128 a - 1) = 0 ∧
  ((x + a) &&& ((highestBit128 a <<< 1) - 1) = 0 ∨
    (a &&& (a - 1) = 0 ∧ descSize (x + a) l < (highestBit128 a).setWidth 129)) ∧
  (x + a).setWidth 129 &&& (highestBit129 (descSize (x + a) l) - 1) = 0

/-- Descending phase: `x` is aligned to the largest block that fits. -/
def DescInv (x l : BitVec 128) : Prop :=
  x ≤ l ∧ x.setWidth 129 &&& (highestBit129 (descSize x l) - 1) = 0

def StateInv (s : RangeState) : Prop :=
  s.done = false → (s.ascending ≠ 0 ∧ AscInv s.first s.last s.ascending) ∨
    (s.ascending = 0 ∧ DescInv s.first s.last)

/-- The number of calls still to emit a block. -/
def potential (s : RangeState) : Nat :=
  if s.done then 0
  else if s.ascending ≠ 0 then
    s.ascending.cpop.toNat + (descSize (s.first + s.ascending) s.last).cpop.toNat
  else (descSize s.first s.last).cpop.toNat

theorem addr_le_lastAddr (B : Block 128) : B.1 ≤ lastAddr B := by
  obtain ⟨b1, b2⟩ := B
  simp only [lastAddr]
  bv_decide

theorem mem_iff_interval {b : Block 128} (hb : IsCidr b) (X : BitVec 128) :
    Mem X b ↔ b.1 ≤ X ∧ X ≤ lastAddr b := by
  obtain ⟨b1, b2⟩ := b
  simp only [IsCidr, IsContiguous, Mem, lastAddr] at *
  bv_decide

set_option maxHeartbeats 4000000 in
theorem asc_step (x l a : BitVec 128) (h : AscInv x l a) :
    IsCidr (x, a ||| -a) ∧ lastAddr (x, a ||| -a) < l ∧ lastAddr (x, a ||| -a) + 1 = x + (a &&& -a) ∧
    x ≤ lastAddr (x, a ||| -a) ∧ Greedy (x, a ||| -a) l ∧
    (x + (a &&& -a)) + (a ^^^ (a &&& -a)) = x + a ∧
    (a ^^^ (a &&& -a) ≠ 0 → AscInv (x + (a &&& -a)) l (a ^^^ (a &&& -a))) ∧
    (a ^^^ (a &&& -a) = 0 → DescInv (x + (a &&& -a)) l) ∧
    (a ^^^ (a &&& -a)).cpop + 1 = a.cpop := by
  simp only [AscInv, DescInv, IsCidr, IsContiguous, lastAddr, Greedy, parent, descSize,
    highestBit128, highestBit129] at *
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> bv_decide (timeout := 300)

set_option maxHeartbeats 4000000 in
theorem desc_step (x l : BitVec 128) (h : DescInv x l) :
    IsCidr (x, ~~~(descBlockMax x l)) ∧ lastAddr (x, ~~~(descBlockMax x l)) = x + descBlockMax x l ∧
    x ≤ x + descBlockMax x l ∧ x + descBlockMax x l ≤ l ∧ Greedy (x, ~~~(descBlockMax x l)) l ∧
    (x + descBlockMax x l ≠ l →
      DescInv (x + descBlockMax x l + 1) l ∧
      (descSize (x + descBlockMax x l + 1) l).cpop + 1 = (descSize x l).cpop) ∧
    (x + descBlockMax x l = l → (descSize x l).cpop = 1) := by
  simp only [DescInv, IsCidr, IsContiguous, lastAddr, Greedy, parent, descSize, descBlockMax,
    blockMax, highestBit129] at *
  refine ⟨?_, ?_, ?_, ?_, ?_, fun hne => ⟨?_, ?_⟩, ?_⟩ <;> bv_decide (timeout := 300)

theorem cpop_sum_le {a : BitVec 128} {z : BitVec 129} (h : a.cpop.setWidth 129 + z.cpop ≤ 254#129) :
    a.cpop.toNat + z.cpop.toNat ≤ 254 := by
  have h1 := BitVec.toNat_cpop_le a
  have h2 := BitVec.toNat_cpop_le z
  rw [BitVec.le_def, BitVec.toNat_add, BitVec.toNat_setWidth] at h
  simp at h
  omega

theorem cpop_le_254 {z : BitVec 129} (h : z.cpop ≤ 254#129) : z.cpop.toNat ≤ 254 := by
  rw [BitVec.le_def] at h
  simpa using h

theorem init_spec (x l : BitVec 128) (h : x ≤ l) :
    (rangeInit x l).first = x ∧ (rangeInit x l).last = l ∧ (rangeInit x l).done = false ∧
    StateInv (rangeInit x l) ∧ potential (rangeInit x l) ≤ 254 := by
  have hnlt : ¬ l < x := by bv_decide
  unfold rangeInit
  rw [ite_eq_right hnlt]
  by_cases hs : (x ^^^ l) &&& ((x ^^^ l) + 1) = 0 ∧ x &&& (x ^^^ l) = 0
  · rw [ite_eq_left hs]
    refine ⟨rfl, rfl, rfl, fun _ => Or.inr ⟨rfl, ?_⟩, ?_⟩
    · simp only [DescInv, descSize, highestBit129]
      bv_decide
    · simp only [potential, Bool.false_eq_true, ↓reduceIte, ne_eq, not_true_eq_false]
      apply cpop_le_254
      simp only [descSize]
      bv_decide
  · rw [ite_eq_right hs]
    have ha : (l &&& -(1#128 <<< (127#128 - (x ^^^ l).clz))) - x ≠ 0 := by bv_decide
    refine ⟨rfl, rfl, rfl, fun _ => Or.inl ⟨ha, ?_⟩, ?_⟩
    · simp only [AscInv, descSize, highestBit128, highestBit129]
      bv_decide
    · simp only [potential, Bool.false_eq_true, ↓reduceIte]
      rw [ite_eq_left ha]
      apply cpop_sum_le
      simp only [descSize]
      bv_decide

theorem not_buddies_of_greedy {b c : Block 128} {l : BitVec 128} (hb : IsCidr b) (hc : IsCidr c)
    (hg : Greedy b l) (hbl : lastAddr b < l) (hadj : c.1 = lastAddr b + 1) (hcl : lastAddr c ≤ l) :
    ¬ Buddies b c := by
  obtain ⟨b1, b2⟩ := b
  obtain ⟨c1, c2⟩ := c
  simp only [IsCidr, IsContiguous, Greedy, parent, lastAddr, Buddies, AdjacentByLowestMaskBit] at *
  bv_decide

theorem cpop_toNat_of_add129 {x y : BitVec 129} (h : x.cpop + 1 = y.cpop) :
    x.cpop.toNat + 1 = y.cpop.toNat := by
  have hle := BitVec.toNat_cpop_le x
  rw [← h, BitVec.toNat_add]
  simp
  omega

theorem cpop_pos128 {x : BitVec 128} (h : x ≠ 0) : 1 ≤ x.cpop.toNat := by
  have h0 : x.cpop ≠ 0 := by bv_decide
  have : x.cpop.toNat ≠ 0 := fun h' => h0 (BitVec.eq_of_toNat_eq (by simpa using h'))
  omega

theorem cpop_pos129 {x : BitVec 129} (h : x ≠ 0) : 1 ≤ x.cpop.toNat := by
  have h0 : x.cpop ≠ 0 := by bv_decide
  have : x.cpop.toNat ≠ 0 := fun h' => h0 (BitVec.eq_of_toNat_eq (by simpa using h'))
  omega

theorem cpop_eq_one {x : BitVec 129} (h : x.cpop = 1) : x.cpop.toNat = 1 := by
  rw [h]
  rfl

theorem potential_pos {s : RangeState} (hs : StateInv s) (hd : s.done = false) :
    1 ≤ potential s := by
  rcases hs hd with ⟨ha, -⟩ | ⟨ha, hdesc⟩
  · simp only [potential, hd, Bool.false_eq_true, ↓reduceIte]
    rw [ite_eq_left ha]
    have := cpop_pos128 ha
    omega
  · simp only [potential, hd, Bool.false_eq_true, ↓reduceIte, ha, ne_eq, not_true_eq_false]
    apply cpop_pos129
    simp only [DescInv, descSize] at hdesc ⊢
    bv_decide

theorem rangeRun_done (n : Nat) (s : RangeState) (hd : s.done = true) : rangeRun n s = [] := by
  cases n <;> simp [rangeRun, rangeNext, hd]

theorem rangeNext_asc (x l a : BitVec 128) (ha : a ≠ 0) :
    rangeNext ⟨x, l, a, false⟩ =
      (some (x, a ||| -a), ⟨x + (a &&& -a), l, a ^^^ (a &&& -a), false⟩) := by
  unfold rangeNext
  simp only [Bool.false_eq_true, ↓reduceIte]
  rw [ite_eq_left ha]

theorem rangeNext_desc (x l : BitVec 128) :
    rangeNext ⟨x, l, 0, false⟩ =
      (some (x, ~~~(descBlockMax x l)),
        ⟨x + descBlockMax x l + 1, l, 0, decide (x + descBlockMax x l = l)⟩) := by
  unfold rangeNext
  simp only [Bool.false_eq_true, ↓reduceIte]
  rw [ite_eq_right (not_not_intro rfl)]

theorem rangeRun_asc (n : Nat) (x l a : BitVec 128) (ha : a ≠ 0) :
    rangeRun (n + 1) ⟨x, l, a, false⟩ =
      (x, a ||| -a) :: rangeRun n ⟨x + (a &&& -a), l, a ^^^ (a &&& -a), false⟩ := by
  rw [rangeRun, rangeNext_asc x l a ha]

theorem rangeRun_desc (n : Nat) (x l : BitVec 128) :
    rangeRun (n + 1) ⟨x, l, 0, false⟩ =
      (x, ~~~(descBlockMax x l)) ::
        rangeRun n ⟨x + descBlockMax x l + 1, l, 0, decide (x + descBlockMax x l = l)⟩ := by
  rw [rangeRun, rangeNext_desc x l]

/-- Prepending a greedy block to a run that starts right after it. -/
theorem cons_spec (b : Block 128) (x l : BitVec 128) (rest : List (Block 128)) (y : BitVec 128)
    (hb : IsCidr b) (hbx : b.1 = x) (hg : Greedy b l) (hbl : lastAddr b < l)
    (hy : lastAddr b + 1 = y) (hxb : x ≤ lastAddr b)
    (hall : ∀ c ∈ rest, IsCidr c ∧ Greedy c l)
    (hpw : rest.Pairwise fun b c => lastAddr b < c.1 ∧ ¬ Buddies b c)
    (hunion : ∀ X, (∃ c ∈ rest, Mem X c) ↔ y ≤ X ∧ X ≤ l)
    (hhead : ∀ c ∈ rest.head?, c.1 = y) :
    (∀ c ∈ b :: rest, IsCidr c ∧ Greedy c l) ∧
    (b :: rest).Pairwise (fun b c => lastAddr b < c.1 ∧ ¬ Buddies b c) ∧
    (∀ X, (∃ c ∈ b :: rest, Mem X c) ↔ x ≤ X ∧ X ≤ l) := by
  have hrestge : ∀ c ∈ rest, y ≤ c.1 ∧ lastAddr c ≤ l := by
    intro c hc
    have h1 := (hunion c.1).1 ⟨c, hc, mem_addr (hall c hc).1⟩
    have h2 := (hunion (lastAddr c)).1 ⟨c, hc, ((mem_iff_interval (hall c hc).1 _).2
      ⟨addr_le_lastAddr c, BitVec.le_refl _⟩)⟩
    exact ⟨h1.1, h2.2⟩
  refine ⟨fun c hc => ?_, List.pairwise_cons.mpr ⟨fun c hc => ?_, hpw⟩, fun X => ?_⟩
  · rcases List.mem_cons.mp hc with rfl | hc
    · exact ⟨hb, hg⟩
    · exact hall c hc
  · obtain ⟨hyc, hcl⟩ := hrestge c hc
    have hlt : lastAddr b < c.1 := by
      subst hy
      obtain ⟨b1, b2⟩ := b
      simp only [lastAddr] at *
      bv_decide
    refine ⟨hlt, ?_⟩
    cases rest with
    | nil => simp at hc
    | cons h t =>
      rcases List.mem_cons.mp hc with rfl | hc'
      · have hcy : c.1 = y := hhead c rfl
        exact not_buddies_of_greedy hb (hall c List.mem_cons_self).1 hg hbl (hcy.trans hy.symm) hcl
      · have hhy : h.1 = y := hhead h rfl
        have hbh : lastAddr b < h.1 := by
          subst hy
          rw [hhy]
          obtain ⟨b1, b2⟩ := b
          simp only [lastAddr] at *
          bv_decide
        exact (far_apart hb (hall h List.mem_cons_self).1 (hall c (List.mem_cons_of_mem _ hc')).1 hbh
          ((List.pairwise_cons.mp hpw).1 c hc').1).2
  · have hmb := mem_iff_interval hb X
    constructor
    · rintro ⟨c, hc, hX⟩
      rcases List.mem_cons.mp hc with rfl | hc
      · have := hmb.1 hX
        subst hbx
        obtain ⟨b1, b2⟩ := c
        simp only [lastAddr] at *
        constructor <;> bv_decide
      · have := (hunion X).1 ⟨c, hc, hX⟩
        subst hy hbx
        obtain ⟨b1, b2⟩ := b
        simp only [lastAddr] at *
        constructor <;> bv_decide
    · rintro ⟨h1, h2⟩
      by_cases hX : X ≤ lastAddr b
      · exact ⟨b, List.mem_cons_self, hmb.2 ⟨hbx ▸ h1, hX⟩⟩
      · obtain ⟨c, hc, hXc⟩ := (hunion X).2 ⟨by subst hy; bv_decide, h2⟩
        exact ⟨c, List.mem_cons_of_mem _ hc, hXc⟩

theorem rangeRun_spec (n : Nat) : ∀ s : RangeState, StateInv s → s.done = false →
    potential s ≤ n →
    (rangeRun n s).length = potential s ∧
    (∀ b ∈ rangeRun n s, IsCidr b ∧ Greedy b s.last) ∧
    (rangeRun n s).Pairwise (fun b c => lastAddr b < c.1 ∧ ¬ Buddies b c) ∧
    (∀ X, (∃ b ∈ rangeRun n s, Mem X b) ↔ s.first ≤ X ∧ X ≤ s.last) ∧
    (∀ b ∈ (rangeRun n s).head?, b.1 = s.first) := by
  induction n with
  | zero =>
    intro s hs hd hp
    have := potential_pos hs hd
    omega
  | succ n ih =>
    intro s hs hd hp
    obtain ⟨x, l, a, done⟩ := s
    simp only at hd
    subst hd
    rcases hs rfl with ⟨ha, hasc⟩ | ⟨ha, hdesc⟩
    · simp only at ha hasc
      obtain ⟨hcidr, hlt, hnext, hle, hg, hB, hasc', hdesc', hcp⟩ := asc_step x l a hasc
      rw [rangeRun_asc n x l a ha]
      have hcpn := cpop_toNat_of_add hcp
      have hs' : StateInv ⟨x + (a &&& -a), l, a ^^^ (a &&& -a), false⟩ := by
        intro _
        by_cases ha' : a ^^^ (a &&& -a) = 0
        · exact Or.inr ⟨ha', hdesc' ha'⟩
        · exact Or.inl ⟨ha', hasc' ha'⟩
      have hp' : potential ⟨x + (a &&& -a), l, a ^^^ (a &&& -a), false⟩ + 1 =
          potential ⟨x, l, a, false⟩ := by
        simp only [potential, Bool.false_eq_true, ↓reduceIte]
        rw [ite_eq_left ha]
        by_cases ha' : a ^^^ (a &&& -a) = 0
        · rw [ite_eq_right (not_not_intro ha')]
          have hx : x + (a &&& -a) = x + a := by
            rw [← hB, ha']
            simp
          rw [hx]
          rw [ha'] at hcpn
          simp at hcpn
          omega
        · rw [ite_eq_left ha', hB]
          omega
      obtain ⟨hlen, hall, hpw, hunion, hhead⟩ := ih _ hs' rfl (by omega)
      simp only at hall hunion hhead
      obtain ⟨hall', hpw', hunion'⟩ := cons_spec (x, a ||| -a) x l _ (x + (a &&& -a)) hcidr rfl hg
        hlt hnext hle hall hpw hunion hhead
      refine ⟨by simp only [List.length_cons]; omega, hall', hpw', hunion', by simp⟩
    · simp only at ha hdesc
      subst ha
      obtain ⟨hcidr, hlast, hxle, hle, hg, hmore, hone⟩ := desc_step x l hdesc
      rw [rangeRun_desc n x l]
      by_cases hend : x + descBlockMax x l = l
      · rw [rangeRun_done n _ (by simp [hend])]
        have hp1 : potential ⟨x, l, 0, false⟩ = 1 := by
          simp only [potential, Bool.false_eq_true, ↓reduceIte, ne_eq, not_true_eq_false]
          exact cpop_eq_one (hone hend)
        refine ⟨hp1.symm, fun b hb => ?_, List.pairwise_singleton _ _, fun X => ?_, by simp⟩
        · simp only [List.mem_singleton] at hb
          subst hb
          exact ⟨hcidr, hg⟩
        · simp only [List.mem_singleton, exists_eq_left]
          rw [mem_iff_interval hcidr, hlast, hend]
      · obtain ⟨hdesc', hcp⟩ := hmore hend
        have hcpn := cpop_toNat_of_add129 hcp
        have hs' : StateInv ⟨x + descBlockMax x l + 1, l, 0, decide (x + descBlockMax x l = l)⟩ := by
          intro _
          exact Or.inr ⟨rfl, hdesc'⟩
        have hd' : decide (x + descBlockMax x l = l) = false := by simp [hend]
        have hp' : potential ⟨x + descBlockMax x l + 1, l, 0, decide (x + descBlockMax x l = l)⟩ + 1 =
            potential ⟨x, l, 0, false⟩ := by
          simp only [potential, hd', Bool.false_eq_true, ↓reduceIte, ne_eq, not_true_eq_false]
          exact hcpn
        obtain ⟨hlen, hall, hpw, hunion, hhead⟩ := ih _ hs' hd' (by omega)
        simp only at hall hunion hhead
        have hlt : lastAddr (x, ~~~(descBlockMax x l)) < l := by
          rw [hlast]
          bv_decide
        have hxl : x ≤ lastAddr (x, ~~~(descBlockMax x l)) := by
          rw [hlast]
          exact hxle
        obtain ⟨hall', hpw', hunion'⟩ := cons_spec (x, ~~~(descBlockMax x l)) x l _
          (x + descBlockMax x l + 1) hcidr rfl hg hlt (by rw [hlast]) hxl hall hpw hunion hhead
        refine ⟨by simp only [List.length_cons]; omega, hall', hpw', hunion', by simp⟩

/-- `ipv6_range_to_networks(first, last)` with `first ≤ last` emits at most 254 CIDR
blocks, pairwise disjoint, without buddy pairs, whose union is `[first, last]`. -/
theorem range_spec (f l : BitVec 128) (h : f ≤ l) :
    (rangeRun 256 (rangeInit f l)).length ≤ 254 ∧
    (∀ b ∈ rangeRun 256 (rangeInit f l), IsCidr b) ∧
    PairwiseDisjoint (rangeRun 256 (rangeInit f l)) ∧
    (∀ b ∈ rangeRun 256 (rangeInit f l), ∀ c ∈ rangeRun 256 (rangeInit f l), ¬ Buddies b c) ∧
    ∀ X, (∃ b ∈ rangeRun 256 (rangeInit f l), Mem X b) ↔ f ≤ X ∧ X ≤ l := by
  obtain ⟨hf, hl, hd, hs, hp⟩ := init_spec f l h
  obtain ⟨hlen, hall, hpw, hunion, -⟩ := rangeRun_spec 256 _ hs hd (by omega)
  rw [hf, hl] at hunion
  refine ⟨by omega, fun b hb => (hall b hb).1, ?_, ?_, hunion⟩
  · unfold PairwiseDisjoint
    exact hpw.imp_of_mem fun {b c} hb hc hbc hm =>
      not_meets_of_lt (hall b hb).1 (hall c hc).1 hbc.1 hm.symm
  · intro b hb c hc hbc
    by_cases heq : b = c
    · subst heq
      exact not_buddies_self b hbc
    · exact pairwise_forall_ne (R := fun b c => ¬ Buddies b c)
        (fun a b h hb => h (buddies_symm hb)) (hpw.imp fun h => h.2) b hb c hc heq hbc

/-- The range is empty when `first > last`. -/
theorem range_empty (f l : BitVec 128) (h : l < f) : rangeRun 256 (rangeInit f l) = [] := by
  apply rangeRun_done
  simp [rangeInit, h]

/-- No CIDR cover of `[first, last]` is shorter than the iterator's output. -/
theorem range_minimal (f l : BitVec 128) (h : f ≤ l) (C : List (Block 128)) (hC : ∀ B ∈ C, IsCidr B)
    (hcov : ∀ X, (∃ B ∈ C, Mem X B) ↔ f ≤ X ∧ X ≤ l) :
    (rangeRun 256 (rangeInit f l)).length ≤ C.length := by
  obtain ⟨-, hcidr, hdis, hnb, hunion⟩ := range_spec f l h
  exact cover_minimal _ C (fun X => f ≤ X ∧ X ≤ l) hdis
    (maximal_of_no_buddies _ _ hcidr hdis hunion hnb) hC hcov

/-- Every CIDR cover of `[first, last]` that is no longer than the output is made of
its blocks. -/
theorem range_unique (f l : BitVec 128) (h : f ≤ l) (C : List (Block 128)) (hC : ∀ B ∈ C, IsCidr B)
    (hcov : ∀ X, (∃ B ∈ C, Mem X B) ↔ f ≤ X ∧ X ≤ l)
    (hlen : C.length ≤ (rangeRun 256 (rangeInit f l)).length) :
    ∀ c ∈ C, c ∈ rangeRun 256 (rangeInit f l) := by
  obtain ⟨-, hcidr, hdis, hnb, hunion⟩ := range_spec f l h
  exact cover_unique _ C _ hdis (maximal_of_no_buddies _ _ hcidr hdis hunion hnb) hunion hC hcov hlen

end Netip.Impl.Ipv6
