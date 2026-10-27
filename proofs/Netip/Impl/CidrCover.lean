import Netip.Impl.Adjacent
import Netip.Impl.Supernet
import Netip.Impl.SetOps
import Netip.Impl.DifferenceRun

/-!
# Minimum CIDR covers

A list of pairwise disjoint CIDR blocks with no buddy pair among them (two
blocks that would merge into their common parent) consists of maximal CIDR
blocks of its union (`maximal_of_no_buddies`). A list of maximal blocks is a
minimum CIDR cover of the union (`cover_minimal`), and every minimum cover is
made of its blocks (`cover_unique`).

`ipv*_aggregate_contiguous` and `ipv*_range_to_networks` produce such lists,
which is what their claims of a minimum, unique cover rest on.

The key step, `has_buddies_of_fine`: a CIDR block covered by blocks that all lie
strictly inside it contains a buddy pair among them. It is an induction on the
number of host bits, splitting the block into its two halves.
-/

namespace Netip.Impl

variable {w : Nat}

/-- An `(addr, mask)` pair. -/
abbrev Block (w : Nat) := BitVec w × BitVec w

/-- `X` is an address of the block. -/
def Mem (X : BitVec w) (B : Block w) : Prop := X &&& B.2 = B.1

/-- A normalized network with a contiguous mask. -/
def IsCidr (B : Block w) : Prop := IsContiguous B.2 ∧ B.1 &&& B.2 = B.1

/-- The intersection test of `intersects`. -/
def Meets (B C : Block w) : Prop := B.1 &&& C.2 = C.1 &&& B.2

/-- Equal non-zero masks, addresses differing exactly in the mask's lowest set bit. -/
def Buddies (B C : Block w) : Prop := AdjacentByLowestMaskBit B.1 B.2 C.1 C.2

/-- The blocks of the list are pairwise disjoint. -/
def PairwiseDisjoint (P : List (Block w)) : Prop := P.Pairwise fun B C => ¬ Meets B C

/-- The union of the blocks is `U`. -/
def Covers (C : List (Block w)) (U : BitVec w → Prop) : Prop := ∀ X, (∃ B ∈ C, Mem X B) ↔ U X

/-- `B` lies in `U`, and no strictly larger CIDR block does. -/
def Maximal (U : BitVec w → Prop) (B : Block w) : Prop :=
  IsCidr B ∧ (∀ X, Mem X B → U X) ∧
    ∀ B', IsCidr B' → Contains B' B → (∀ X, Mem X B' → U X) → B' = B

theorem eq_of_meets {P : List (Block w)} (h : PairwiseDisjoint P) :
    ∀ B ∈ P, ∀ C ∈ P, Meets B C → B = C := by
  induction P with
  | nil => simp
  | cons D P ih =>
    intro B hB C hC hm
    unfold PairwiseDisjoint at h
    rw [List.pairwise_cons] at h
    obtain ⟨hD, hP⟩ := h
    rcases List.mem_cons.mp hB with hBD | hB' <;> rcases List.mem_cons.mp hC with hCD | hC'
    · rw [hBD, hCD]
    · subst hBD
      exact absurd hm (hD C hC')
    · subst hCD
      exact absurd hm.symm (hD B hB')
    · exact ih hP B hB' C hC' hm

theorem nodup_of_pairwiseDisjoint {P : List (Block w)} (h : PairwiseDisjoint P) : P.Nodup := by
  unfold PairwiseDisjoint at h
  exact h.imp fun {B C} hm heq => hm (by subst heq; rfl)

namespace Ipv4

theorem mem_addr {B : Block 32} (h : IsCidr B) : Mem B.1 B := h.2

theorem meets_of_mem {X : BitVec 32} {B C : Block 32} (hB : Mem X B) (hC : Mem X C) : Meets B C := by
  simp only [Mem, Meets] at *
  bv_decide

theorem mem_of_contains {X : BitVec 32} {B C : Block 32} (h : Contains B C) (hX : Mem X C) :
    Mem X B := by
  simp only [Mem, Contains] at *
  bv_decide

theorem laminar {B C : Block 32} (hB : IsCidr B) (hC : IsCidr C) (hm : Meets B C) :
    Contains B C ∨ Contains C B := by
  simp only [IsCidr, IsContiguous, Meets, Contains] at *
  bv_decide

theorem contains_of_subset {B C : Block 32} (hB : IsCidr B) (hC : IsCidr C)
    (h : ∀ X, Mem X C → Mem X B) : Contains B C :=
  (contains_iff B.1 B.2 C.1 C.2 hB.2 hC.2).2 h

theorem eq_of_contains {B C : Block 32} (hB : IsCidr B) (hC : IsCidr C) (h1 : Contains B C)
    (h2 : Contains C B) : B = C := by
  obtain ⟨b1, b2⟩ := B
  obtain ⟨c1, c2⟩ := C
  simp only [IsCidr, Contains, Prod.mk.injEq] at *
  constructor <;> bv_decide

/-! ## Halves of a block -/

/-- The highest host bit of a contiguous mask with at least one host bit. -/
def topHost (m : BitVec 32) : BitVec 32 := (~~~m >>> 1) + 1

def loHalf (Y : Block 32) : Block 32 := (Y.1, Y.2 ||| topHost Y.2)

def hiHalf (Y : Block 32) : Block 32 := (Y.1 ||| topHost Y.2, Y.2 ||| topHost Y.2)

theorem halves_spec {Y : Block 32} (hY : IsCidr Y) (hn : Y.2 ≠ BitVec.allOnes 32) :
    IsCidr (loHalf Y) ∧ IsCidr (hiHalf Y) ∧ Contains Y (loHalf Y) ∧ Contains Y (hiHalf Y) ∧
    Buddies (loHalf Y) (hiHalf Y) ∧ ¬ Meets (loHalf Y) (hiHalf Y) ∧
    (~~~(loHalf Y).2).cpop + 1 = (~~~Y.2).cpop := by
  obtain ⟨y1, y2⟩ := Y
  simp only [IsCidr, IsContiguous, Contains, Buddies, AdjacentByLowestMaskBit, Meets, loHalf,
    hiHalf, topHost] at *
  bv_decide

theorem mem_halves {Y : Block 32} {X : BitVec 32} (hY : IsCidr Y) (hX : Mem X Y) :
    Mem X (loHalf Y) ∨ Mem X (hiHalf Y) := by
  obtain ⟨y1, y2⟩ := Y
  simp only [IsCidr, IsContiguous, Mem, loHalf, hiHalf, topHost] at *
  bv_decide

theorem contains_half {Y B : Block 32} (hY : IsCidr Y) (hB : IsCidr B) (h : Contains Y B)
    (hne : B ≠ Y) : Contains (loHalf Y) B ∨ Contains (hiHalf Y) B := by
  obtain ⟨y1, y2⟩ := Y
  obtain ⟨b1, b2⟩ := B
  simp only [ne_eq, Prod.mk.injEq] at hne
  simp only [IsCidr, IsContiguous, Contains, loHalf, hiHalf, topHost] at *
  bv_decide

theorem eq_of_contains_host {Y B : Block 32} (hY : IsCidr Y) (hB : IsCidr B)
    (hn : Y.2 = BitVec.allOnes 32) (h : Contains Y B) : B = Y := by
  obtain ⟨y1, y2⟩ := Y
  obtain ⟨b1, b2⟩ := B
  simp only [IsCidr, IsContiguous, Contains, Prod.mk.injEq] at *
  constructor <;> bv_decide

theorem allOnes_of_cpop {m : BitVec 32} (h : (~~~m).cpop.toNat = 0) : m = BitVec.allOnes 32 := by
  have hc : (~~~m).cpop = 0#32 := BitVec.eq_of_toNat_eq (by simpa using h)
  bv_decide

theorem cpop_toNat_of_add {x y : BitVec 32} (h : x.cpop + 1 = y.cpop) :
    x.cpop.toNat + 1 = y.cpop.toNat := by
  have hle := BitVec.toNat_cpop_le x
  rw [← h, BitVec.toNat_add]
  simp
  omega

theorem meets_of_contains_right {B Y Z : Block 32} (hB : IsCidr B) (hZ : IsCidr Z)
    (hm : Meets B Z) (h : Contains Y Z) : Meets B Y := by
  simp only [IsCidr, IsContiguous, Meets, Contains] at *
  bv_decide

theorem meets_of_contains_left {B Z Z' : Block 32} (hB : IsCidr B) (hZ : IsCidr Z)
    (h : Contains Z' B) (hm : Meets B Z) : Meets Z' Z := by
  simp only [IsCidr, IsContiguous, Meets, Contains] at *
  bv_decide

theorem meets_of_contains {C B : Block 32} (hB : IsCidr B) (h : Contains C B) : Meets C B := by
  simp only [IsCidr, IsContiguous, Meets, Contains] at *
  bv_decide

theorem contains_refl {B : Block 32} (hB : IsCidr B) : Contains B B := by
  simp only [IsCidr, Contains] at *
  exact ⟨hB.2, BitVec.and_self⟩

/-- A CIDR block that `P` covers with blocks lying strictly inside it contains a
buddy pair of `P`. -/
theorem has_buddies_of_fine (P : List (Block 32)) (hP : ∀ B ∈ P, IsCidr B) :
    ∀ n, ∀ Y : Block 32, IsCidr Y → (~~~Y.2).cpop.toNat = n →
      (∀ X, Mem X Y → ∃ B ∈ P, Mem X B) →
      (∀ B ∈ P, Meets B Y → Contains Y B ∧ B ≠ Y) →
      ∃ B ∈ P, ∃ C ∈ P, Buddies B C := by
  intro n
  induction n with
  | zero =>
    intro Y hY hn hcov hfine
    obtain ⟨B, hB, hmem⟩ := hcov Y.1 (mem_addr hY)
    obtain ⟨hc, hne⟩ := hfine B hB (meets_of_mem hmem (mem_addr hY))
    exact absurd (eq_of_contains_host hY (hP B hB) (allOnes_of_cpop hn) hc) hne
  | succ n ih =>
    intro Y hY hn hcov hfine
    have hne : Y.2 ≠ BitVec.allOnes 32 := by
      intro h
      rw [h] at hn
      simp at hn
    obtain ⟨hl, hh, hcl, hch, hbud, hdj, hcnt⟩ := halves_spec hY hne
    have hlcnt : (~~~(loHalf Y).2).cpop.toNat = n := by
      have := cpop_toNat_of_add hcnt
      omega
    have hhcnt : (~~~(hiHalf Y).2).cpop.toNat = n := hlcnt
    have inL : ∀ B ∈ P, Meets B (loHalf Y) → Contains (loHalf Y) B := by
      intro B hB hm
      obtain ⟨hc, hne'⟩ := hfine B hB (meets_of_contains_right (hP B hB) hl hm hcl)
      rcases contains_half hY (hP B hB) hc hne' with h | h
      · exact h
      · exact absurd (meets_of_contains_left (hP B hB) hl h hm).symm hdj
    have inH : ∀ B ∈ P, Meets B (hiHalf Y) → Contains (hiHalf Y) B := by
      intro B hB hm
      obtain ⟨hc, hne'⟩ := hfine B hB (meets_of_contains_right (hP B hB) hh hm hch)
      rcases contains_half hY (hP B hB) hc hne' with h | h
      · exact absurd (meets_of_contains_left (hP B hB) hh h hm) hdj
      · exact h
    by_cases hLP : loHalf Y ∈ P
    · by_cases hHP : hiHalf Y ∈ P
      · exact ⟨_, hLP, _, hHP, hbud⟩
      · exact ih (hiHalf Y) hh hhcnt (fun X hX => hcov X (mem_of_contains hch hX))
          fun B hB hm => ⟨inH B hB hm, fun heq => hHP (heq ▸ hB)⟩
    · exact ih (loHalf Y) hl hlcnt (fun X hX => hcov X (mem_of_contains hcl hX))
        fun B hB hm => ⟨inL B hB hm, fun heq => hLP (heq ▸ hB)⟩

/-! ## Parent and buddy -/

/-- The block one bit wider, `merge_by_lowest_mask_bit`'s result for a sibling pair. -/
def parent (B : Block 32) : Block 32 := (B.1 &&& (B.2 &&& (B.2 - 1)), B.2 &&& (B.2 - 1))

/-- The other half of the parent. -/
def buddy (B : Block 32) : Block 32 := (B.1 ^^^ lowestBit B.2, B.2)

theorem buddy_spec {B : Block 32} (hB : IsCidr B) (h0 : B.2 ≠ 0) :
    IsCidr (buddy B) ∧ Buddies B (buddy B) ∧ ¬ Meets B (buddy B) := by
  obtain ⟨b1, b2⟩ := B
  simp only [IsCidr, IsContiguous, Buddies, AdjacentByLowestMaskBit, Meets, buddy, lowestBit] at *
  bv_decide

/-- A CIDR block strictly containing `B` contains its buddy. -/
theorem contains_buddy {B C : Block 32} (hB : IsCidr B) (hC : IsCidr C) (h0 : B.2 ≠ 0)
    (h : Contains C B) (hne : C ≠ B) : Contains C (buddy B) := by
  obtain ⟨b1, b2⟩ := B
  obtain ⟨c1, c2⟩ := C
  simp only [ne_eq, Prod.mk.injEq] at hne
  simp only [IsCidr, IsContiguous, Contains, buddy, lowestBit] at *
  bv_decide

/-- A CIDR block strictly containing the buddy of `B` contains `B`. -/
theorem contains_of_contains_buddy {B C : Block 32} (hB : IsCidr B) (hC : IsCidr C)
    (h0 : B.2 ≠ 0) (h : Contains C (buddy B)) (hne : C ≠ buddy B) : Contains C B := by
  obtain ⟨b1, b2⟩ := B
  obtain ⟨c1, c2⟩ := C
  simp only [ne_eq, Prod.mk.injEq, buddy] at hne
  simp only [IsCidr, IsContiguous, Contains, buddy, lowestBit] at *
  bv_decide

theorem eq_of_contains_zero {B C : Block 32} (hB : IsCidr B) (hC : IsCidr C) (h0 : B.2 = 0)
    (h : Contains C B) : C = B := by
  obtain ⟨b1, b2⟩ := B
  obtain ⟨c1, c2⟩ := C
  simp only [IsCidr, IsContiguous, Contains, Prod.mk.injEq] at *
  constructor <;> bv_decide

/-! ## Maximal blocks and minimum covers -/

/-- In a disjoint cover of `U` without buddy pairs, every block is maximal in `U`. -/
theorem maximal_of_no_buddies (P : List (Block 32)) (U : BitVec 32 → Prop)
    (hP : ∀ B ∈ P, IsCidr B) (hdis : PairwiseDisjoint P) (hcov : Covers P U)
    (hnb : ∀ B ∈ P, ∀ C ∈ P, ¬ Buddies B C) : ∀ B ∈ P, Maximal U B := by
  intro B hB
  refine ⟨hP B hB, fun X hX => (hcov X).1 ⟨B, hB, hX⟩, fun B' hB' hcont hsub => ?_⟩
  apply Classical.byContradiction
  intro hne
  have h0 : B.2 ≠ 0 := fun h0 => hne (eq_of_contains_zero (hP B hB) hB' h0 hcont)
  obtain ⟨hbc, hbb, hbm⟩ := buddy_spec (hP B hB) h0
  have hpar := contains_buddy (hP B hB) hB' h0 hcont hne
  obtain ⟨C, hC, D, hD, hCD⟩ := has_buddies_of_fine P hP _ (buddy B) hbc rfl
    (fun X hX => (hcov X).2 (hsub X (mem_of_contains hpar hX)))
    (fun C hC hm => by
      have hCne : C ≠ buddy B := fun heq => hnb B hB C hC (heq ▸ hbb)
      rcases laminar (hP C hC) hbc hm with h | h
      · have hCB := contains_of_contains_buddy (hP B hB) (hP C hC) h0 h hCne
        have heq := eq_of_meets hdis C hC B hB (meets_of_contains (hP B hB) hCB)
        subst heq
        exact absurd (meets_of_contains hbc h) hbm
      · exact ⟨h, hCne⟩)
  exact hnb C hC D hD hCD

/-- A CIDR block of a cover that meets a maximal block lies inside it. -/
theorem contains_of_maximal {U : BitVec 32 → Prop} {o c : Block 32} (ho : Maximal U o)
    (hc : IsCidr c) (hcU : ∀ X, Mem X c → U X) (hm : Meets o c) : Contains o c := by
  obtain ⟨hoc, -, hom⟩ := ho
  rcases laminar hoc hc hm with h | h
  · exact h
  · have := hom c hc h hcU
    subst this
    exact contains_refl hoc

/-- A list of pairwise disjoint maximal blocks of `U` is no longer than any CIDR
cover of `U`. -/
theorem cover_minimal (O C : List (Block 32)) (U : BitVec 32 → Prop) (hdis : PairwiseDisjoint O)
    (hmax : ∀ B ∈ O, Maximal U B) (hC : ∀ B ∈ C, IsCidr B) (hcov : Covers C U) :
    O.length ≤ C.length := by
  apply length_le_of_inj (fun (o c : Block 32) => Contains o c ∧ Mem c.1 c) O C
    (nodup_of_pairwiseDisjoint hdis)
  · intro o ho
    have hoc := (hmax o ho).1
    obtain ⟨c, hc, hmem⟩ := (hcov o.1).2 ((hmax o ho).2.1 o.1 (mem_addr hoc))
    exact ⟨c, hc, contains_of_maximal (hmax o ho) (hC c hc) (fun X hX => (hcov X).1 ⟨c, hc, hX⟩)
      (meets_of_mem (mem_addr hoc) hmem), mem_addr (hC c hc)⟩
  · intro o ho o' ho' c _ ⟨h1, hm1⟩ ⟨h2, hm2⟩
    exact eq_of_meets hdis o ho o' ho' (meets_of_mem (mem_of_contains h1 hm1) (mem_of_contains h2 hm2))

theorem outside_point {o c : Block 32} (ho : IsCidr o) (hc : IsCidr c) (h : Contains o c)
    (hne : c ≠ o) : Mem (c.1 ^^^ lowestBit (c.2 &&& ~~~o.2)) o ∧
      ¬ Mem (c.1 ^^^ lowestBit (c.2 &&& ~~~o.2)) c := by
  obtain ⟨o1, o2⟩ := o
  obtain ⟨c1, c2⟩ := c
  simp only [ne_eq, Prod.mk.injEq] at hne
  simp only [IsCidr, IsContiguous, Contains, Mem, lowestBit] at *
  constructor <;> bv_decide

/-- Every CIDR cover of `U` no longer than a disjoint cover `O` by maximal blocks
is made of blocks of `O`. -/
theorem cover_unique (O C : List (Block 32)) (U : BitVec 32 → Prop) (hdis : PairwiseDisjoint O)
    (hmax : ∀ B ∈ O, Maximal U B) (hcovO : Covers O U) (hC : ∀ B ∈ C, IsCidr B)
    (hcov : Covers C U) (hlen : C.length ≤ O.length) : ∀ c ∈ C, c ∈ O := by
  intro c hc
  have hcU : ∀ c ∈ C, ∀ X, Mem X c → U X := fun c hc X hX => (hcov X).1 ⟨c, hc, hX⟩
  obtain ⟨o, ho, hmem⟩ := (hcovO c.1).2 (hcU c hc c.1 (mem_addr (hC c hc)))
  have hco := contains_of_maximal (hmax o ho) (hC c hc) (hcU c hc)
    (meets_of_mem hmem (mem_addr (hC c hc)))
  by_cases heq : c = o
  · exact heq ▸ ho
  · exfalso
    obtain ⟨hXo, hXc⟩ := outside_point (hmax o ho).1 (hC c hc) hco heq
    have hle : O.length ≤ (C.erase c).length := by
      apply length_le_of_inj (fun (o c' : Block 32) => Contains o c' ∧ Mem c'.1 c') O (C.erase c)
        (nodup_of_pairwiseDisjoint hdis)
      · intro o' ho'
        by_cases ho'o : o' = o
        · subst ho'o
          obtain ⟨c', hc', hmc'⟩ := (hcov _).2 ((hmax o' ho').2.1 _ hXo)
          have hc'ne : c' ≠ c := fun h => hXc (h ▸ hmc')
          exact ⟨c', (List.mem_erase_of_ne hc'ne).mpr hc',
            contains_of_maximal (hmax o' ho') (hC c' hc') (hcU c' hc') (meets_of_mem hXo hmc'),
            mem_addr (hC c' hc')⟩
        · have ho'c := (hmax o' ho').1
          obtain ⟨c', hc', hmc'⟩ := (hcov o'.1).2 ((hmax o' ho').2.1 o'.1 (mem_addr ho'c))
          have hcont := contains_of_maximal (hmax o' ho') (hC c' hc') (hcU c' hc')
            (meets_of_mem (mem_addr ho'c) hmc')
          have hc'ne : c' ≠ c := by
            rintro rfl
            exact ho'o (eq_of_meets hdis o' ho' o ho (meets_of_mem
              (mem_of_contains hcont (mem_addr (hC c' hc'))) (mem_of_contains hco (mem_addr (hC c' hc')))))
          exact ⟨c', (List.mem_erase_of_ne hc'ne).mpr hc', hcont, mem_addr (hC c' hc')⟩
      · intro o1 ho1 o2 ho2 c' _ ⟨h1, hm1⟩ ⟨h2, hm2⟩
        exact eq_of_meets hdis o1 ho1 o2 ho2
          (meets_of_mem (mem_of_contains h1 hm1) (mem_of_contains h2 hm2))
    rw [List.length_erase_of_mem hc] at hle
    have := List.length_pos_of_mem hc
    omega

end Ipv4

namespace Ipv6

theorem mem_addr {B : Block 128} (h : IsCidr B) : Mem B.1 B := h.2

theorem meets_of_mem {X : BitVec 128} {B C : Block 128} (hB : Mem X B) (hC : Mem X C) : Meets B C := by
  simp only [Mem, Meets] at *
  bv_decide

theorem mem_of_contains {X : BitVec 128} {B C : Block 128} (h : Contains B C) (hX : Mem X C) :
    Mem X B := by
  simp only [Mem, Contains] at *
  bv_decide

theorem laminar {B C : Block 128} (hB : IsCidr B) (hC : IsCidr C) (hm : Meets B C) :
    Contains B C ∨ Contains C B := by
  simp only [IsCidr, IsContiguous, Meets, Contains] at *
  bv_decide

theorem contains_of_subset {B C : Block 128} (hB : IsCidr B) (hC : IsCidr C)
    (h : ∀ X, Mem X C → Mem X B) : Contains B C :=
  (contains_iff B.1 B.2 C.1 C.2 hB.2 hC.2).2 h

theorem eq_of_contains {B C : Block 128} (hB : IsCidr B) (hC : IsCidr C) (h1 : Contains B C)
    (h2 : Contains C B) : B = C := by
  obtain ⟨b1, b2⟩ := B
  obtain ⟨c1, c2⟩ := C
  simp only [IsCidr, Contains, Prod.mk.injEq] at *
  constructor <;> bv_decide

/-! ## Halves of a block -/

/-- The highest host bit of a contiguous mask with at least one host bit. -/
def topHost (m : BitVec 128) : BitVec 128 := (~~~m >>> 1) + 1

def loHalf (Y : Block 128) : Block 128 := (Y.1, Y.2 ||| topHost Y.2)

def hiHalf (Y : Block 128) : Block 128 := (Y.1 ||| topHost Y.2, Y.2 ||| topHost Y.2)

theorem halves_spec {Y : Block 128} (hY : IsCidr Y) (hn : Y.2 ≠ BitVec.allOnes 128) :
    IsCidr (loHalf Y) ∧ IsCidr (hiHalf Y) ∧ Contains Y (loHalf Y) ∧ Contains Y (hiHalf Y) ∧
    Buddies (loHalf Y) (hiHalf Y) ∧ ¬ Meets (loHalf Y) (hiHalf Y) ∧
    (~~~(loHalf Y).2).cpop + 1 = (~~~Y.2).cpop := by
  obtain ⟨y1, y2⟩ := Y
  simp only [IsCidr, IsContiguous, Contains, Buddies, AdjacentByLowestMaskBit, Meets, loHalf,
    hiHalf, topHost] at *
  bv_decide

theorem mem_halves {Y : Block 128} {X : BitVec 128} (hY : IsCidr Y) (hX : Mem X Y) :
    Mem X (loHalf Y) ∨ Mem X (hiHalf Y) := by
  obtain ⟨y1, y2⟩ := Y
  simp only [IsCidr, IsContiguous, Mem, loHalf, hiHalf, topHost] at *
  bv_decide

theorem contains_half {Y B : Block 128} (hY : IsCidr Y) (hB : IsCidr B) (h : Contains Y B)
    (hne : B ≠ Y) : Contains (loHalf Y) B ∨ Contains (hiHalf Y) B := by
  obtain ⟨y1, y2⟩ := Y
  obtain ⟨b1, b2⟩ := B
  simp only [ne_eq, Prod.mk.injEq] at hne
  simp only [IsCidr, IsContiguous, Contains, loHalf, hiHalf, topHost] at *
  bv_decide

theorem eq_of_contains_host {Y B : Block 128} (hY : IsCidr Y) (hB : IsCidr B)
    (hn : Y.2 = BitVec.allOnes 128) (h : Contains Y B) : B = Y := by
  obtain ⟨y1, y2⟩ := Y
  obtain ⟨b1, b2⟩ := B
  simp only [IsCidr, IsContiguous, Contains, Prod.mk.injEq] at *
  constructor <;> bv_decide

theorem allOnes_of_cpop {m : BitVec 128} (h : (~~~m).cpop.toNat = 0) : m = BitVec.allOnes 128 := by
  have hc : (~~~m).cpop = 0#128 := BitVec.eq_of_toNat_eq (by simpa using h)
  bv_decide

theorem cpop_toNat_of_add {x y : BitVec 128} (h : x.cpop + 1 = y.cpop) :
    x.cpop.toNat + 1 = y.cpop.toNat := by
  have hle := BitVec.toNat_cpop_le x
  rw [← h, BitVec.toNat_add]
  simp
  omega

theorem meets_of_contains_right {B Y Z : Block 128} (hB : IsCidr B) (hZ : IsCidr Z)
    (hm : Meets B Z) (h : Contains Y Z) : Meets B Y := by
  simp only [IsCidr, IsContiguous, Meets, Contains] at *
  bv_decide

theorem meets_of_contains_left {B Z Z' : Block 128} (hB : IsCidr B) (hZ : IsCidr Z)
    (h : Contains Z' B) (hm : Meets B Z) : Meets Z' Z := by
  simp only [IsCidr, IsContiguous, Meets, Contains] at *
  bv_decide

theorem meets_of_contains {C B : Block 128} (hB : IsCidr B) (h : Contains C B) : Meets C B := by
  simp only [IsCidr, IsContiguous, Meets, Contains] at *
  bv_decide

theorem contains_refl {B : Block 128} (hB : IsCidr B) : Contains B B := by
  simp only [IsCidr, Contains] at *
  exact ⟨hB.2, BitVec.and_self⟩

/-- A CIDR block that `P` covers with blocks lying strictly inside it contains a
buddy pair of `P`. -/
theorem has_buddies_of_fine (P : List (Block 128)) (hP : ∀ B ∈ P, IsCidr B) :
    ∀ n, ∀ Y : Block 128, IsCidr Y → (~~~Y.2).cpop.toNat = n →
      (∀ X, Mem X Y → ∃ B ∈ P, Mem X B) →
      (∀ B ∈ P, Meets B Y → Contains Y B ∧ B ≠ Y) →
      ∃ B ∈ P, ∃ C ∈ P, Buddies B C := by
  intro n
  induction n with
  | zero =>
    intro Y hY hn hcov hfine
    obtain ⟨B, hB, hmem⟩ := hcov Y.1 (mem_addr hY)
    obtain ⟨hc, hne⟩ := hfine B hB (meets_of_mem hmem (mem_addr hY))
    exact absurd (eq_of_contains_host hY (hP B hB) (allOnes_of_cpop hn) hc) hne
  | succ n ih =>
    intro Y hY hn hcov hfine
    have hne : Y.2 ≠ BitVec.allOnes 128 := by
      intro h
      rw [h] at hn
      simp at hn
    obtain ⟨hl, hh, hcl, hch, hbud, hdj, hcnt⟩ := halves_spec hY hne
    have hlcnt : (~~~(loHalf Y).2).cpop.toNat = n := by
      have := cpop_toNat_of_add hcnt
      omega
    have hhcnt : (~~~(hiHalf Y).2).cpop.toNat = n := hlcnt
    have inL : ∀ B ∈ P, Meets B (loHalf Y) → Contains (loHalf Y) B := by
      intro B hB hm
      obtain ⟨hc, hne'⟩ := hfine B hB (meets_of_contains_right (hP B hB) hl hm hcl)
      rcases contains_half hY (hP B hB) hc hne' with h | h
      · exact h
      · exact absurd (meets_of_contains_left (hP B hB) hl h hm).symm hdj
    have inH : ∀ B ∈ P, Meets B (hiHalf Y) → Contains (hiHalf Y) B := by
      intro B hB hm
      obtain ⟨hc, hne'⟩ := hfine B hB (meets_of_contains_right (hP B hB) hh hm hch)
      rcases contains_half hY (hP B hB) hc hne' with h | h
      · exact absurd (meets_of_contains_left (hP B hB) hh h hm) hdj
      · exact h
    by_cases hLP : loHalf Y ∈ P
    · by_cases hHP : hiHalf Y ∈ P
      · exact ⟨_, hLP, _, hHP, hbud⟩
      · exact ih (hiHalf Y) hh hhcnt (fun X hX => hcov X (mem_of_contains hch hX))
          fun B hB hm => ⟨inH B hB hm, fun heq => hHP (heq ▸ hB)⟩
    · exact ih (loHalf Y) hl hlcnt (fun X hX => hcov X (mem_of_contains hcl hX))
        fun B hB hm => ⟨inL B hB hm, fun heq => hLP (heq ▸ hB)⟩

/-! ## Parent and buddy -/

/-- The block one bit wider, `merge_by_lowest_mask_bit`'s result for a sibling pair. -/
def parent (B : Block 128) : Block 128 := (B.1 &&& (B.2 &&& (B.2 - 1)), B.2 &&& (B.2 - 1))

/-- The other half of the parent. -/
def buddy (B : Block 128) : Block 128 := (B.1 ^^^ lowestBit B.2, B.2)

theorem buddy_spec {B : Block 128} (hB : IsCidr B) (h0 : B.2 ≠ 0) :
    IsCidr (buddy B) ∧ Buddies B (buddy B) ∧ ¬ Meets B (buddy B) := by
  obtain ⟨b1, b2⟩ := B
  simp only [IsCidr, IsContiguous, Buddies, AdjacentByLowestMaskBit, Meets, buddy, lowestBit] at *
  bv_decide

/-- A CIDR block strictly containing `B` contains its buddy. -/
theorem contains_buddy {B C : Block 128} (hB : IsCidr B) (hC : IsCidr C) (h0 : B.2 ≠ 0)
    (h : Contains C B) (hne : C ≠ B) : Contains C (buddy B) := by
  obtain ⟨b1, b2⟩ := B
  obtain ⟨c1, c2⟩ := C
  simp only [ne_eq, Prod.mk.injEq] at hne
  simp only [IsCidr, IsContiguous, Contains, buddy, lowestBit] at *
  bv_decide

/-- A CIDR block strictly containing the buddy of `B` contains `B`. -/
theorem contains_of_contains_buddy {B C : Block 128} (hB : IsCidr B) (hC : IsCidr C)
    (h0 : B.2 ≠ 0) (h : Contains C (buddy B)) (hne : C ≠ buddy B) : Contains C B := by
  obtain ⟨b1, b2⟩ := B
  obtain ⟨c1, c2⟩ := C
  simp only [ne_eq, Prod.mk.injEq, buddy] at hne
  simp only [IsCidr, IsContiguous, Contains, buddy, lowestBit] at *
  bv_decide

theorem eq_of_contains_zero {B C : Block 128} (hB : IsCidr B) (hC : IsCidr C) (h0 : B.2 = 0)
    (h : Contains C B) : C = B := by
  obtain ⟨b1, b2⟩ := B
  obtain ⟨c1, c2⟩ := C
  simp only [IsCidr, IsContiguous, Contains, Prod.mk.injEq] at *
  constructor <;> bv_decide

/-! ## Maximal blocks and minimum covers -/

/-- In a disjoint cover of `U` without buddy pairs, every block is maximal in `U`. -/
theorem maximal_of_no_buddies (P : List (Block 128)) (U : BitVec 128 → Prop)
    (hP : ∀ B ∈ P, IsCidr B) (hdis : PairwiseDisjoint P) (hcov : Covers P U)
    (hnb : ∀ B ∈ P, ∀ C ∈ P, ¬ Buddies B C) : ∀ B ∈ P, Maximal U B := by
  intro B hB
  refine ⟨hP B hB, fun X hX => (hcov X).1 ⟨B, hB, hX⟩, fun B' hB' hcont hsub => ?_⟩
  apply Classical.byContradiction
  intro hne
  have h0 : B.2 ≠ 0 := fun h0 => hne (eq_of_contains_zero (hP B hB) hB' h0 hcont)
  obtain ⟨hbc, hbb, hbm⟩ := buddy_spec (hP B hB) h0
  have hpar := contains_buddy (hP B hB) hB' h0 hcont hne
  obtain ⟨C, hC, D, hD, hCD⟩ := has_buddies_of_fine P hP _ (buddy B) hbc rfl
    (fun X hX => (hcov X).2 (hsub X (mem_of_contains hpar hX)))
    (fun C hC hm => by
      have hCne : C ≠ buddy B := fun heq => hnb B hB C hC (heq ▸ hbb)
      rcases laminar (hP C hC) hbc hm with h | h
      · have hCB := contains_of_contains_buddy (hP B hB) (hP C hC) h0 h hCne
        have heq := eq_of_meets hdis C hC B hB (meets_of_contains (hP B hB) hCB)
        subst heq
        exact absurd (meets_of_contains hbc h) hbm
      · exact ⟨h, hCne⟩)
  exact hnb C hC D hD hCD

/-- A CIDR block of a cover that meets a maximal block lies inside it. -/
theorem contains_of_maximal {U : BitVec 128 → Prop} {o c : Block 128} (ho : Maximal U o)
    (hc : IsCidr c) (hcU : ∀ X, Mem X c → U X) (hm : Meets o c) : Contains o c := by
  obtain ⟨hoc, -, hom⟩ := ho
  rcases laminar hoc hc hm with h | h
  · exact h
  · have := hom c hc h hcU
    subst this
    exact contains_refl hoc

/-- A list of pairwise disjoint maximal blocks of `U` is no longer than any CIDR
cover of `U`. -/
theorem cover_minimal (O C : List (Block 128)) (U : BitVec 128 → Prop) (hdis : PairwiseDisjoint O)
    (hmax : ∀ B ∈ O, Maximal U B) (hC : ∀ B ∈ C, IsCidr B) (hcov : Covers C U) :
    O.length ≤ C.length := by
  apply length_le_of_inj (fun (o c : Block 128) => Contains o c ∧ Mem c.1 c) O C
    (nodup_of_pairwiseDisjoint hdis)
  · intro o ho
    have hoc := (hmax o ho).1
    obtain ⟨c, hc, hmem⟩ := (hcov o.1).2 ((hmax o ho).2.1 o.1 (mem_addr hoc))
    exact ⟨c, hc, contains_of_maximal (hmax o ho) (hC c hc) (fun X hX => (hcov X).1 ⟨c, hc, hX⟩)
      (meets_of_mem (mem_addr hoc) hmem), mem_addr (hC c hc)⟩
  · intro o ho o' ho' c _ ⟨h1, hm1⟩ ⟨h2, hm2⟩
    exact eq_of_meets hdis o ho o' ho' (meets_of_mem (mem_of_contains h1 hm1) (mem_of_contains h2 hm2))

theorem outside_point {o c : Block 128} (ho : IsCidr o) (hc : IsCidr c) (h : Contains o c)
    (hne : c ≠ o) : Mem (c.1 ^^^ lowestBit (c.2 &&& ~~~o.2)) o ∧
      ¬ Mem (c.1 ^^^ lowestBit (c.2 &&& ~~~o.2)) c := by
  obtain ⟨o1, o2⟩ := o
  obtain ⟨c1, c2⟩ := c
  simp only [ne_eq, Prod.mk.injEq] at hne
  simp only [IsCidr, IsContiguous, Contains, Mem, lowestBit] at *
  constructor <;> bv_decide

/-- Every CIDR cover of `U` no longer than a disjoint cover `O` by maximal blocks
is made of blocks of `O`. -/
theorem cover_unique (O C : List (Block 128)) (U : BitVec 128 → Prop) (hdis : PairwiseDisjoint O)
    (hmax : ∀ B ∈ O, Maximal U B) (hcovO : Covers O U) (hC : ∀ B ∈ C, IsCidr B)
    (hcov : Covers C U) (hlen : C.length ≤ O.length) : ∀ c ∈ C, c ∈ O := by
  intro c hc
  have hcU : ∀ c ∈ C, ∀ X, Mem X c → U X := fun c hc X hX => (hcov X).1 ⟨c, hc, hX⟩
  obtain ⟨o, ho, hmem⟩ := (hcovO c.1).2 (hcU c hc c.1 (mem_addr (hC c hc)))
  have hco := contains_of_maximal (hmax o ho) (hC c hc) (hcU c hc)
    (meets_of_mem hmem (mem_addr (hC c hc)))
  by_cases heq : c = o
  · exact heq ▸ ho
  · exfalso
    obtain ⟨hXo, hXc⟩ := outside_point (hmax o ho).1 (hC c hc) hco heq
    have hle : O.length ≤ (C.erase c).length := by
      apply length_le_of_inj (fun (o c' : Block 128) => Contains o c' ∧ Mem c'.1 c') O (C.erase c)
        (nodup_of_pairwiseDisjoint hdis)
      · intro o' ho'
        by_cases ho'o : o' = o
        · subst ho'o
          obtain ⟨c', hc', hmc'⟩ := (hcov _).2 ((hmax o' ho').2.1 _ hXo)
          have hc'ne : c' ≠ c := fun h => hXc (h ▸ hmc')
          exact ⟨c', (List.mem_erase_of_ne hc'ne).mpr hc',
            contains_of_maximal (hmax o' ho') (hC c' hc') (hcU c' hc') (meets_of_mem hXo hmc'),
            mem_addr (hC c' hc')⟩
        · have ho'c := (hmax o' ho').1
          obtain ⟨c', hc', hmc'⟩ := (hcov o'.1).2 ((hmax o' ho').2.1 o'.1 (mem_addr ho'c))
          have hcont := contains_of_maximal (hmax o' ho') (hC c' hc') (hcU c' hc')
            (meets_of_mem (mem_addr ho'c) hmc')
          have hc'ne : c' ≠ c := by
            rintro rfl
            exact ho'o (eq_of_meets hdis o' ho' o ho (meets_of_mem
              (mem_of_contains hcont (mem_addr (hC c' hc'))) (mem_of_contains hco (mem_addr (hC c' hc')))))
          exact ⟨c', (List.mem_erase_of_ne hc'ne).mpr hc', hcont, mem_addr (hC c' hc')⟩
      · intro o1 ho1 o2 ho2 c' _ ⟨h1, hm1⟩ ⟨h2, hm2⟩
        exact eq_of_meets hdis o1 ho1 o2 ho2
          (meets_of_mem (mem_of_contains h1 hm1) (mem_of_contains h2 hm2))
    rw [List.length_erase_of_mem hc] at hle
    have := List.length_pos_of_mem hc
    omega

end Ipv6

end Netip.Impl
