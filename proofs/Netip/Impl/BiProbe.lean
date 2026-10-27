import Netip.Impl.BiSweep
import Netip.Impl.BinarySplitSearch

/-!
# `ipv6_aggregate_bicontiguous`: the containment probe and the rounds

`bicontiguous_find_containment` sorts the swept networks by `(mask, address)` and
drops every network that another network contains (`bicontiguous_containment_probe`,
transcribed as `probe`). It walks the networks in chunks of at most 64 with one
mask, and for each chunk probes every present ancestor shape, a smaller high-half
prefix and a low-half prefix no larger, in ascending order: the networks already
kept with that mask form one run of the sorted kept prefix, found with
`partition_point` from a cursor that only moves forward, and each chunk network is
looked up there by its address under the ancestor mask. On sorted slices,
`partition_point` is the length of the prefix that satisfies the predicate and
`binary_search_by_key` finds a key iff it is present, which is how they are
transcribed. `bicontiguous_aggregate` repeats the level sweep and the probe until
the probe drops nothing (`rounds`). Every repeated round starts from fewer networks,
so the fuel `L.length + 1` of `aggregateBi` never runs out.

Sorting is `sort_unstable_by_key`, and `mergeSort` stands for it: the key
`(mask, address)` orders networks totally, and only equal networks share it.

Proved, for a level sweep's output (`findContainment_spec`): the probe keeps exactly
the networks that no other network contains, each once. A container always has a
smaller high-half prefix, as one of the same prefix would share the group and meet
the network, so probing the smaller high-half prefixes finds every container, and
probing only the networks kept so far suffices, as every container is inside a kept
one. For any input of normalized bi-contiguous networks (`aggregateBi_spec`): the
output has the same union, holds normalized bi-contiguous networks in canonical
groups, no network contains another, no two are lowest-mask-bit siblings, and no
level carries two buddy groups with the same low halves.
-/

namespace Netip.Impl.Ipv6

/-- `bicontiguous_sort_key`: the pair `(mask, address)`, whose lexicographic order is
the numeric order of this number. -/
def sortKey (x : Net) : Nat := x.2.toNat * 2 ^ 128 + x.1.toNat

/-- Comparing sort keys. -/
def sortLe (x y : Net) : Bool := decide (sortKey x ≤ sortKey y)

/-- `bicontiguous_shape_mask(hi_prefix, lo_prefix)`. -/
def shapeMask (hp lp : Nat) : BitVec 128 :=
  ((halfMask hp).setWidth 128 <<< 64) ||| (halfMask lp).setWidth 128

/-- The present shapes: the bit rows of `lo_prefixes_by_hi_prefix`, by high-half prefix,
and `hi_prefixes_present`. -/
abbrev Table := (Nat → BitVec 128) × BitVec 128

/-- One network of the shape table: `lo_prefixes_by_hi_prefix[hi_prefix] |= 1 << lo_prefix`
and `hi_prefixes_present |= 1 << hi_prefix`. -/
def tableStep (t : Table) (x : Net) : Table :=
  (fun h => if h = hiP x then t.1 h ||| (1#128 <<< loP x) else t.1 h, t.2 ||| (1#128 <<< hiP x))

/-- The shape table of every network. -/
def shapeTable (S : List Net) : Table := S.foldl tableStep (fun _ => 0, 0)

/-- The set bits of `x` from the lowest, as
`while x != 0 { b = x.trailing_zeros(); x &= x - 1 }` visits them. -/
def bitsAsc : Nat → BitVec 128 → List Nat
  | 0, _ => []
  | f + 1, x => if x = 0 then [] else x.ctz.toNat :: bitsAsc f (x &&& (x - 1))

/-- The probe of one chunk: the cursor into the kept networks, and the dropped flags. -/
structure Probe where
  cursor : Nat
  dropped : BitVec 64

/-- `from + kept[from..].partition_point(|net| sort_key(net) < (bound, 0))`. -/
def below (kept : List Net) (start : Nat) (bound : BitVec 128) : Nat :=
  start + ((kept.drop start).takeWhile (fun y => sortKey y < bound.toNat * 2 ^ 128)).length

/-- One chunk network against the run of ancestor networks with mask `am`: unless it is
dropped already, it is dropped if its address under `am` is the address of one of them. -/
def dropStep (run : List Net) (am : BitVec 128) (d : BitVec 64) (aj : BitVec 128 × Nat) :
    BitVec 64 :=
  if d &&& (1#64 <<< aj.2) ≠ 0 then d
  else if run.any (fun y => y.1 = aj.1 &&& am) then d ||| (1#64 <<< aj.2)
  else d

/-- Probing one ancestor shape with mask `am`: find the run of kept networks with that
mask, and drop every chunk network whose address under `am` is the address of one. -/
def probeShape (kept : List Net) (addrs : List (BitVec 128)) (st : Probe) (am : BitVec 128) :
    Probe :=
  let runStart := below kept st.cursor am
  let runEnd := below kept runStart (am + 1#128)
  if runStart = runEnd then ⟨runEnd, st.dropped⟩
  else
    ⟨runEnd, addrs.zipIdx.foldl (dropStep ((kept.drop runStart).take (runEnd - runStart)) am)
      st.dropped⟩

/-- `all_dropped` of a chunk of `n` networks. -/
def allDropped (n : Nat) : BitVec 64 := if n = 64 then BitVec.allOnes 64 else (1#64 <<< n) - 1#64

/-- `eligible_lo_prefixes`: the low-half prefixes present with high-half prefix `ahp`, up to
and including `lp`. -/
def eligLo (tbl : Table) (ahp lp : Nat) : BitVec 128 :=
  if lp = 64 then tbl.1 ahp else tbl.1 ahp &&& ((1#128 <<< (lp + 1)) - 1#128)

/-- Probing the ancestor shape `s`, unless every chunk network is dropped already. -/
def shapeStep (kept : List Net) (addrs : List (BitVec 128)) (all : BitVec 64) (st : Probe)
    (s : Nat × Nat) : Probe :=
  if st.dropped = all then st else probeShape kept addrs st (shapeMask s.1 s.2)

/-- The dropped flags of one chunk of shape `(hp, lp)`: every present ancestor shape,
in ascending order, until all are dropped. -/
def probeChunk (tbl : Table) (kept chunk : List Net) (hp lp : Nat) : BitVec 64 :=
  ((bitsAsc 128 (tbl.2 &&& ((1#128 <<< hp) - 1#128))).foldl (fun st ahp =>
    if st.dropped = allDropped chunk.length then st
    else (bitsAsc 128 (eligLo tbl ahp lp)).foldl (fun st alp =>
      shapeStep kept (chunk.map (·.1)) (allDropped chunk.length) st (ahp, alp)) st)
    ⟨0, 0⟩).dropped

/-- The chunk loop of `bicontiguous_containment_probe`: a chunk is the next run of at
most 64 networks with one mask, and its networks whose flag stays clear are appended
to the kept prefix. -/
def probeLoop (tbl : Table) : Nat → List Net → List Net → List Net
  | 0, kept, _ => kept
  | _ + 1, kept, [] => kept
  | f + 1, kept, x :: xs =>
    let chunk := ((x :: xs).takeWhile (fun y => y.2 = x.2)).take 64
    let d := probeChunk tbl kept chunk (hiP x) (loP x)
    probeLoop tbl f (kept ++ (chunk.zipIdx.filter fun aj => d &&& (1#64 <<< aj.2) = 0).map (·.1))
      ((x :: xs).drop chunk.length)

/-- `bicontiguous_containment_probe`. -/
def probe (S : List Net) : List Net := probeLoop (shapeTable S) S.length [] S

/-- `bicontiguous_find_containment`. -/
def findContainment (S : List Net) : List Net :=
  if S.length ≤ 1 then S else probe (S.mergeSort sortLe)

/-- `bicontiguous_aggregate`: the level sweep and the containment probe, repeated until
the probe drops nothing. Every repeated round starts from fewer networks. -/
def rounds : Nat → List Net → List Net
  | 0, L => L
  | f + 1, L =>
    if (findContainment (sweep L)).length = (sweep L).length then findContainment (sweep L)
    else rounds f (findContainment (sweep L))

/-- `ipv6_aggregate_bicontiguous`. -/
def aggregateBi (L : List Net) : List Net := rounds (L.length + 1) L

/-! ## Bits -/

theorem getLsbD_one_shl {w k : Nat} (hk : k < w) (b : Nat) :
    (1#w <<< k).getLsbD b = decide (b = k) := by
  simp only [BitVec.getLsbD_shiftLeft, BitVec.getLsbD_one]
  by_cases h : b = k
  · subst h; simp [hk]; omega
  · by_cases h2 : b < k
    · simp [h, h2]
    · simp [h, h2]; omega

theorem toNat_lowMask {w k : Nat} (hk : k < w) : ((1#w <<< k) - 1#w).toNat = 2 ^ k - 1 := by
  have h1 : (1#w <<< k).toNat = 2 ^ k := by
    rw [BitVec.toNat_shiftLeft, BitVec.toNat_ofNat]
    have : 2 ^ k < 2 ^ w := Nat.pow_lt_pow_right (by omega) hk
    have h2 : 1 % 2 ^ w = 1 := Nat.mod_eq_of_lt (Nat.one_lt_two_pow (by omega))
    rw [h2, Nat.shiftLeft_eq, Nat.one_mul, Nat.mod_eq_of_lt this]
  have hp : 0 < 2 ^ k := Nat.two_pow_pos k
  rw [BitVec.toNat_sub, h1, BitVec.toNat_ofNat]
  have h2 : 1 % 2 ^ w = 1 := Nat.mod_eq_of_lt (Nat.one_lt_two_pow (by omega))
  rw [h2]
  have : 2 ^ k < 2 ^ w := Nat.pow_lt_pow_right (by omega) hk
  have : 2 ^ w - 1 + 2 ^ k = 2 ^ w + (2 ^ k - 1) := by omega
  rw [this, Nat.add_mod_left, Nat.mod_eq_of_lt (by omega)]

theorem getLsbD_lowMask {w k : Nat} (hk : k < w) (b : Nat) :
    ((1#w <<< k) - 1#w).getLsbD b = decide (b < k) := by
  rw [BitVec.getLsbD, toNat_lowMask hk, Nat.testBit_two_pow_sub_one]

theorem and_bit_eq_zero {d : BitVec 64} {j : Nat} (hj : j < 64) :
    d &&& (1#64 <<< j) = 0 ↔ d.getLsbD j = false := by
  constructor
  · intro h
    have := congrArg (·.getLsbD j) h
    simpa [BitVec.getLsbD_and, getLsbD_one_shl hj] using this
  · intro h
    apply BitVec.eq_of_getLsbD_eq
    intro i hi
    rw [BitVec.getLsbD_and, getLsbD_one_shl hj]
    by_cases hij : i = j
    · subst hij; simp [h]
    · simp [hij]

theorem bitsAsc_spec : ∀ (f : Nat) (x : BitVec 128), (∀ b < 128 - f, x.getLsbD b = false) →
    (∀ b, b ∈ bitsAsc f x ↔ x.getLsbD b = true) ∧ (bitsAsc f x).Pairwise (· < ·)
  | 0, x, h => by
    refine ⟨fun b => ?_, List.Pairwise.nil⟩
    simp only [bitsAsc, List.not_mem_nil, false_iff, Bool.not_eq_true]
    by_cases hb : b < 128
    · exact h b (by omega)
    · exact BitVec.getLsbD_of_ge x b (by omega)
  | f + 1, x, h => by
    rw [bitsAsc]
    by_cases hx : x = 0
    · subst hx
      simp
    · rw [ite_eq_right hx]
      have hset := killFacts128.getLsbD_ctz x hx
      have hclr := killFacts128.clear x hx
      have hbelow : ∀ b < x.ctz.toNat, x.getLsbD b = false := fun b hb =>
        BitVec.getLsbD_false_of_lt_ctz hb
      have hc' : 128 - (f + 1) ≤ x.ctz.toNat := by
        apply Classical.byContradiction
        intro hlt
        have := h x.ctz.toNat (by omega)
        rw [hset] at this
        exact absurd this (by simp)
      obtain ⟨ih1, ih2⟩ := bitsAsc_spec f (x &&& (x - 1)) (fun b hb => by
        rw [hclr]
        by_cases hbc : b = x.ctz.toNat
        · simp [hbc]
        · have : b < x.ctz.toNat := by omega
          simp [hbelow b this])
      refine ⟨fun b => ?_, ?_⟩
      · rw [List.mem_cons, ih1, hclr]
        by_cases hbc : b = x.ctz.toNat
        · subst hbc
          simp [hset]
        · simp [hbc]
      · rw [List.pairwise_cons]
        refine ⟨fun b hb => ?_, ih2⟩
        rw [ih1, hclr] at hb
        simp only [Bool.and_eq_true, decide_eq_true_eq] at hb
        apply Classical.byContradiction
        intro hlt
        have := hbelow b (by omega)
        rw [hb.1] at this
        exact absurd this (by simp)

theorem mem_bitsAsc (x : BitVec 128) (b : Nat) : b ∈ bitsAsc 128 x ↔ x.getLsbD b = true :=
  (bitsAsc_spec 128 x (fun b hb => by omega)).1 b

theorem bitsAsc_sorted (x : BitVec 128) : (bitsAsc 128 x).Pairwise (· < ·) :=
  (bitsAsc_spec 128 x (fun b hb => by omega)).2

/-! ## The shape table -/

theorem loP_le (x : Net) : loP x ≤ 64 := clz_not_le _

theorem shapeTable_foldl : ∀ (l : List Net) (t : Table),
    (∀ b, (l.foldl tableStep t).2.getLsbD b = (t.2.getLsbD b || l.any (fun z => hiP z = b))) ∧
    (∀ h b, ((l.foldl tableStep t).1 h).getLsbD b =
        ((t.1 h).getLsbD b || l.any (fun z => hiP z = h ∧ loP z = b)))
  | [], t => by simp
  | x :: l, t => by
    obtain ⟨ih1, ih2⟩ := shapeTable_foldl l (tableStep t x)
    have hx1 : hiP x < 128 := by have := hiP_le x; omega
    have hx2 : loP x < 128 := by have := loP_le x; omega
    refine ⟨fun b => ?_, fun h b => ?_⟩
    · rw [List.foldl_cons, ih1, tableStep, BitVec.getLsbD_or, getLsbD_one_shl hx1, List.any_cons]
      by_cases hb : b = hiP x
      · subst hb; simp
      · have : ¬ hiP x = b := fun e => hb e.symm
        simp [hb, this]
    · rw [List.foldl_cons, ih2, tableStep, List.any_cons]
      by_cases hh : h = hiP x
      · subst hh
        simp only [↓reduceIte, BitVec.getLsbD_or, getLsbD_one_shl hx2]
        by_cases hb : b = loP x
        · subst hb; simp
        · have : ¬ loP x = b := fun e => hb e.symm
          simp [hb, this]
      · have : ¬ hiP x = h := fun e => hh e.symm
        simp [hh, this]

theorem shapeTable_hi (S : List Net) (b : Nat) :
    (shapeTable S).2.getLsbD b = true ↔ ∃ z ∈ S, hiP z = b := by
  rw [shapeTable, (shapeTable_foldl S _).1 b]
  simp

theorem shapeTable_lo (S : List Net) (h b : Nat) :
    ((shapeTable S).1 h).getLsbD b = true ↔ ∃ z ∈ S, hiP z = h ∧ loP z = b := by
  rw [shapeTable, (shapeTable_foldl S _).2 h b]
  simp

/-! ## Sort keys and shape masks -/

theorem sortKey_lt_of_mask {x y : Net} (h : x.2.toNat < y.2.toNat) : sortKey x < sortKey y := by
  have := x.1.isLt
  have : (x.2.toNat + 1) * 2 ^ 128 ≤ y.2.toNat * 2 ^ 128 := Nat.mul_le_mul_right _ h
  unfold sortKey
  omega

theorem mask_le_of_sortKey {x y : Net} (h : sortKey x ≤ sortKey y) : x.2.toNat ≤ y.2.toNat := by
  apply Classical.byContradiction
  intro hn
  have := sortKey_lt_of_mask (x := y) (y := x) (by omega)
  omega

theorem sortKey_lt_bound (y : Net) (B : Nat) : sortKey y < B * 2 ^ 128 ↔ y.2.toNat < B := by
  have := y.1.isLt
  unfold sortKey
  constructor
  · intro h
    apply Classical.byContradiction
    intro hn
    have : B * 2 ^ 128 ≤ y.2.toNat * 2 ^ 128 := Nat.mul_le_mul_right _ (by omega)
    omega
  · intro h
    have : (y.2.toNat + 1) * 2 ^ 128 ≤ B * 2 ^ 128 := Nat.mul_le_mul_right _ h
    omega

theorem sortKey_inj {x y : Net} (h : sortKey x = sortKey y) : x = y := by
  have h1 := mask_le_of_sortKey (Nat.le_of_eq h)
  have h2 := mask_le_of_sortKey (Nat.le_of_eq h.symm)
  have hm : x.2.toNat = y.2.toNat := by omega
  unfold sortKey at h
  rw [hm] at h
  have ha : x.1.toNat = y.1.toNat := by omega
  exact Prod.ext (BitVec.eq_of_toNat_eq ha) (BitVec.eq_of_toNat_eq hm)

theorem hi_shapeMask (h l : Nat) : hi (shapeMask h l) = halfMask h := by
  unfold shapeMask hi
  generalize halfMask h = A
  generalize halfMask l = B
  bv_decide

theorem lo_shapeMask (h l : Nat) : lo (shapeMask h l) = halfMask l := by
  unfold shapeMask lo
  generalize halfMask h = A
  generalize halfMask l = B
  bv_decide

theorem mask_eq_shapeMask {x : Net} (hx : IsBiNet x) : x.2 = shapeMask (hiP x) (loP x) := by
  unfold shapeMask
  rw [← hiM_eq hx, ← loM_eq hx]
  unfold hiM loM hi lo
  bv_decide

theorem hiP_of_mask {y : Net} {h l : Nat} (hy : y.2 = shapeMask h l) (hh : h ≤ 64) :
    hiP y = h := by
  unfold hiP hiM
  rw [hy, hi_shapeMask, clz_halfMask h hh]

theorem loP_of_mask {y : Net} {h l : Nat} (hy : y.2 = shapeMask h l) (hl : l ≤ 64) :
    loP y = l := by
  unfold loP loM
  rw [hy, lo_shapeMask, clz_halfMask l hl]

theorem halfMask_lt {k1 k2 : Nat} (h : k1 < k2) (h2 : k2 ≤ 64) :
    (halfMask k1).toNat < (halfMask k2).toNat := by
  rw [halfMask_eq k1 (by omega), halfMask_eq k2 h2, ← BitVec.lt_def]
  have e1 : BitVec.ofNat 64 k1 < BitVec.ofNat 64 k2 := by
    rw [BitVec.lt_def, toNat_ofNat_64 (by omega), toNat_ofNat_64 h2]
    exact h
  have e2 : BitVec.ofNat 64 k2 ≤ 64#64 := by
    rw [BitVec.le_def, toNat_ofNat_64 h2]
    simp only [show (64#64).toNat = 64 from rfl]
    exact h2
  generalize BitVec.ofNat 64 k1 = K1 at *
  generalize BitVec.ofNat 64 k2 = K2 at *
  bv_decide

theorem halfMask_sub {k1 k2 : Nat} (h : k1 ≤ k2) : halfMask k2 &&& halfMask k1 = halfMask k1 := by
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  simp only [halfMask, BitVec.getLsbD_and, BitVec.getLsbD_not, BitVec.getLsbD_ushiftRight,
    BitVec.getLsbD_allOnes, hi]
  by_cases h1 : k1 + i < 64 <;> by_cases h2 : k2 + i < 64 <;> simp [h1, h2] <;> omega

theorem shapeMask_lt_hi {h1 h2 : Nat} (l1 l2 : Nat)
    (h : (halfMask h1).toNat < (halfMask h2).toNat) :
    (shapeMask h1 l1).toNat < (shapeMask h2 l2).toNat := by
  unfold shapeMask
  rw [← BitVec.lt_def] at h ⊢
  generalize halfMask h1 = A1 at *
  generalize halfMask h2 = A2 at *
  generalize halfMask l1 = B1 at *
  generalize halfMask l2 = B2 at *
  bv_decide

theorem shapeMask_lt_lo (h : Nat) {l1 l2 : Nat} (hl : (halfMask l1).toNat < (halfMask l2).toNat) :
    (shapeMask h l1).toNat < (shapeMask h l2).toNat := by
  unfold shapeMask
  rw [← BitVec.lt_def] at hl ⊢
  generalize halfMask h = A at *
  generalize halfMask l1 = B1 at *
  generalize halfMask l2 = B2 at *
  bv_decide

theorem shapeMask_sub {h1 h2 l1 l2 : Nat} (hh : h1 ≤ h2) (hl : l1 ≤ l2) :
    shapeMask h2 l2 &&& shapeMask h1 l1 = shapeMask h1 l1 := by
  have e1 := halfMask_sub hh
  have e2 := halfMask_sub hl
  unfold shapeMask
  generalize halfMask h1 = A1 at *
  generalize halfMask h2 = A2 at *
  generalize halfMask l1 = B1 at *
  generalize halfMask l2 = B2 at *
  bv_decide

theorem toNat_shapeMask_succ {h l : Nat} (hh : h < 64) :
    (shapeMask h l + 1#128).toNat = (shapeMask h l).toNat + 1 := by
  have h1 := halfMask_lt hh (Nat.le_refl 64)
  have h64 : halfMask 64 = BitVec.allOnes 64 := by
    rw [halfMask_eq 64 (Nat.le_refl 64)]
    bv_decide
  rw [h64, ← BitVec.lt_def] at h1
  have hlt : shapeMask h l < BitVec.allOnes 128 := by
    unfold shapeMask
    generalize halfMask h = A at *
    generalize halfMask l = B at *
    bv_decide
  rw [BitVec.lt_def, BitVec.toNat_allOnes] at hlt
  rw [BitVec.toNat_add, show (1#128).toNat = 1 from rfl, Nat.mod_eq_of_lt (by omega)]

theorem contains_trans {x y z : Net} (h1 : Contains z y) (h2 : Contains y x) : Contains z x := by
  obtain ⟨a1, a2⟩ := h1
  obtain ⟨b1, b2⟩ := h2
  constructor
  · calc x.1 &&& z.2 = x.1 &&& (y.2 &&& z.2) := by rw [a2]
      _ = (x.1 &&& y.2) &&& z.2 := by rw [BitVec.and_assoc]
      _ = z.1 := by rw [b1, a1]
  · calc x.2 &&& z.2 = x.2 &&& (y.2 &&& z.2) := by rw [a2]
      _ = (x.2 &&& y.2) &&& z.2 := by rw [BitVec.and_assoc]
      _ = z.2 := by rw [b2, a2]

/-! ## Runs of the sorted kept prefix -/

theorem below_eq {kept : List Net} {c : Nat} {B : BitVec 128} (hc : c ≤ kept.length)
    (hlt : ∀ y ∈ kept.take c, y.2.toNat < B.toNat) :
    below kept c B = (kept.takeWhile (fun y => sortKey y < B.toNat * 2 ^ 128)).length := by
  unfold below
  conv => rhs; rw [← List.take_append_drop c kept]
  rw [List.takeWhile_append_of_pos (fun a ha => by
    simpa only [decide_eq_true_eq, sortKey_lt_bound] using hlt a ha)]
  rw [List.length_append, List.length_take, Nat.min_eq_left hc]

theorem sorted_downward {kept : List Net} (hk : kept.Pairwise fun a b => sortKey a < sortKey b)
    (c : Nat) :
    kept.Pairwise fun x y => decide (sortKey y < c) = true → decide (sortKey x < c) = true :=
  hk.imp fun h hy => by simp only [decide_eq_true_eq] at hy ⊢; omega

/-- The run of kept networks with mask `am`, as `probeShape` finds it from a cursor below it. -/
theorem run_spec {kept : List Net} (hk : kept.Pairwise fun a b => sortKey a < sortKey b)
    {am : BitVec 128} (hsucc : (am + 1#128).toNat = am.toNat + 1) {c : Nat} (hc : c ≤ kept.length)
    (hlt : ∀ y ∈ kept.take c, y.2.toNat < am.toNat) :
    let rs := below kept c am
    let re := below kept rs (am + 1#128)
    re ≤ kept.length ∧ (∀ y ∈ kept.take re, y.2.toNat ≤ am.toNat) ∧
      (∀ y, y ∈ (kept.drop rs).take (re - rs) ↔ y ∈ kept ∧ y.2 = am) ∧
      (rs = re → ∀ y ∈ kept, y.2 ≠ am) := by
  intro rs re
  have hrs : rs = (kept.takeWhile (fun y => sortKey y < am.toNat * 2 ^ 128)).length :=
    below_eq hc hlt
  generalize hP : (fun y : Net => decide (sortKey y < am.toNat * 2 ^ 128)) = P at hrs
  have hpre : kept.takeWhile P = kept.take rs := by
    rw [hrs]
    exact List.prefix_iff_eq_take.mp (List.takeWhile_prefix _)
  have hdrop : kept.drop rs = kept.dropWhile P := by
    have h := List.takeWhile_append_dropWhile (p := P) (l := kept)
    rw [hrs]
    calc kept.drop (kept.takeWhile P).length
        = (kept.takeWhile P ++ kept.dropWhile P).drop (kept.takeWhile P).length := by rw [h]
      _ = kept.dropWhile P := List.drop_left
  have hrsle : rs ≤ kept.length := by
    rw [hrs]
    exact (List.takeWhile_prefix _).length_le
  have hdw : kept.dropWhile P = kept.filter (fun x => !P x) := by
    rw [← hP]
    exact dropWhile_eq_filter (sorted_downward hk _)
  generalize hT : (kept.drop rs).takeWhile
    (fun y => decide (sortKey y < (am + 1#128).toNat * 2 ^ 128)) = T
  have hre : re = rs + T.length := by
    show below kept rs (am + 1#128) = rs + T.length
    unfold below
    rw [hT]
  have hTpre' : (kept.drop rs).take T.length = T := by
    rw [← hT]
    exact (List.prefix_iff_eq_take.mp (List.takeWhile_prefix _)).symm
  have hTpre : (kept.drop rs).take (re - rs) = T := by
    rw [hre, Nat.add_sub_cancel_left, hTpre']
  have hTfil :
      T = (kept.drop rs).filter (fun y => decide (sortKey y < (am + 1#128).toNat * 2 ^ 128)) := by
    rw [← hT]
    exact takeWhile_eq_filter (sorted_downward (hk.sublist (List.drop_sublist _ _)) _)
  have hmemT : ∀ y, y ∈ T ↔ y ∈ kept ∧ y.2 = am := by
    intro y
    rw [hTfil, List.mem_filter, hdrop, hdw, List.mem_filter, ← hP]
    simp only [Bool.not_eq_eq_eq_not, Bool.not_true, decide_eq_false_iff_not, decide_eq_true_eq,
      sortKey_lt_bound, hsucc]
    constructor
    · rintro ⟨⟨hy, h1⟩, h2⟩
      exact ⟨hy, BitVec.eq_of_toNat_eq (by omega)⟩
    · rintro ⟨hy, rfl⟩
      exact ⟨⟨hy, by omega⟩, by omega⟩
  have hTlen : T.length ≤ (kept.drop rs).length := by
    rw [← hT]
    exact (List.takeWhile_prefix _).length_le
  refine ⟨?_, ?_, ?_, ?_⟩
  · rw [hre]
    rw [List.length_drop] at hTlen
    omega
  · intro y hy
    rw [hre, List.take_add, hTpre', ← hpre] at hy
    rcases List.mem_append.mp hy with hy | hy
    · have := mem_takeWhile_pred hy
      rw [← hP] at this
      simp only [decide_eq_true_eq, sortKey_lt_bound] at this
      omega
    · rw [(hmemT y).mp hy |>.2]
      exact Nat.le_refl _
  · intro y
    rw [hTpre]
    exact hmemT y
  · intro he y hy hya
    have hnil : T = [] := List.length_eq_zero_iff.mp (by omega)
    have := (hmemT y).mpr ⟨hy, hya⟩
    rw [hnil] at this
    exact absurd this List.not_mem_nil

theorem dropStep_bit (run : List Net) (am : BitVec 128) (d : BitVec 64) (aj : BitVec 128 × Nat)
    (hj : aj.2 < 64) (i : Nat) :
    (dropStep run am d aj).getLsbD i = true ↔
      d.getLsbD i = true ∨ (aj.2 = i ∧ run.any (fun y => y.1 = aj.1 &&& am) = true) := by
  unfold dropStep
  by_cases h1 : d &&& (1#64 <<< aj.2) = 0
  · have hn : ¬ (d &&& (1#64 <<< aj.2) ≠ 0) := fun h => h h1
    rw [ite_eq_right hn]
    by_cases h2 : run.any (fun y => y.1 = aj.1 &&& am) = true
    · rw [ite_eq_left h2, BitVec.getLsbD_or, getLsbD_one_shl hj]
      by_cases hi : aj.2 = i
      · subst hi
        simp [h2]
      · have : ¬ i = aj.2 := fun e => hi e.symm
        simp [this, hi]
    · rw [ite_eq_right h2]
      simp [h2]
  · rw [ite_eq_left h1]
    have hb : d.getLsbD aj.2 = true := by
      cases hb : d.getLsbD aj.2
      · exact absurd ((and_bit_eq_zero hj).mpr hb) h1
      · rfl
    constructor
    · exact Or.inl
    · rintro (h | ⟨rfl, -⟩)
      · exact h
      · exact hb

theorem dropFold_spec (run : List Net) (am : BitVec 128) :
    ∀ (l : List (BitVec 128 × Nat)) (d : BitVec 64), (∀ aj ∈ l, aj.2 < 64) → ∀ i,
      ((l.foldl (dropStep run am) d).getLsbD i = true ↔
        d.getLsbD i = true ∨
          ∃ aj ∈ l, aj.2 = i ∧ run.any (fun y => y.1 = aj.1 &&& am) = true)
  | [], d, _, i => by simp
  | aj :: l, d, hl, i => by
    rw [List.foldl_cons,
      dropFold_spec run am l _ (fun b hb => hl b (List.mem_cons_of_mem _ hb)) i,
      dropStep_bit run am d aj (hl aj List.mem_cons_self) i]
    constructor
    · rintro ((h | h) | ⟨b, hb, h⟩)
      · exact Or.inl h
      · exact Or.inr ⟨aj, List.mem_cons_self, h⟩
      · exact Or.inr ⟨b, List.mem_cons_of_mem _ hb, h⟩
    · rintro (h | ⟨b, hb, h⟩)
      · exact Or.inl (Or.inl h)
      · rcases List.mem_cons.mp hb with rfl | hb
        · exact Or.inl (Or.inr h)
        · exact Or.inr ⟨b, hb, h⟩

/-- Probing one ancestor shape: the cursor moves past the run of mask `am`, and the chunk
networks whose address under `am` is a kept network's address are dropped. -/
theorem probeShape_spec {kept : List Net} (hk : kept.Pairwise fun a b => sortKey a < sortKey b)
    {addrs : List (BitVec 128)} (hlen : addrs.length ≤ 64) {st : Probe} {am : BitVec 128}
    (hsucc : (am + 1#128).toNat = am.toNat + 1) (hc : st.cursor ≤ kept.length)
    (hlt : ∀ y ∈ kept.take st.cursor, y.2.toNat < am.toNat) :
    (probeShape kept addrs st am).cursor ≤ kept.length ∧
      (∀ y ∈ kept.take (probeShape kept addrs st am).cursor, y.2.toNat ≤ am.toNat) ∧
      ∀ i, ((probeShape kept addrs st am).dropped.getLsbD i = true ↔
        st.dropped.getLsbD i = true ∨
          ∃ a, addrs[i]? = some a ∧ ∃ y ∈ kept, y.2 = am ∧ y.1 = a &&& am) := by
  obtain ⟨r1, r2, r3, r4⟩ := run_spec hk hsucc hc hlt
  unfold probeShape
  simp only
  split
  · rename_i he
    refine ⟨r1, r2, fun i => ⟨Or.inl, ?_⟩⟩
    rintro (h | ⟨a, -, y, hy, hya, -⟩)
    · exact h
    · exact absurd hya (r4 he y hy)
  · refine ⟨r1, r2, fun i => ?_⟩
    rw [dropFold_spec _ am _ _ (fun aj haj => ?_) i]
    · apply or_congr Iff.rfl
      constructor
      · rintro ⟨aj, haj, rfl, hany⟩
        rw [List.mem_zipIdx_iff_getElem?] at haj
        rw [List.any_eq_true] at hany
        obtain ⟨y, hy, hya⟩ := hany
        rw [r3] at hy
        exact ⟨aj.1, haj, y, hy.1, hy.2, by simpa [hy.2] using hya⟩
      · rintro ⟨a, ha, y, hy, hya, hyb⟩
        refine ⟨(a, i), List.mem_zipIdx_iff_getElem?.mpr ha, rfl, ?_⟩
        rw [List.any_eq_true]
        exact ⟨y, (r3 y).mpr ⟨hy, hya⟩, by simpa using hyb⟩
    · have h1 := List.mem_zipIdx_iff_getElem?.mp haj
      have h2 := (List.getElem?_eq_some_iff.mp h1).1
      omega

/-! ## One chunk -/

theorem getLsbD_allDropped {n : Nat} (hn : n ≤ 64) (j : Nat) :
    (allDropped n).getLsbD j = decide (j < n) := by
  unfold allDropped
  split
  · rename_i h
    subst h
    simp only [BitVec.getLsbD_allOnes]
  · rw [getLsbD_lowMask (by omega)]

theorem inner_fold_done {kept : List Net} {addrs : List (BitVec 128)} {all : BitVec 64}
    (ahp : Nat) :
    ∀ (l : List Nat) (st : Probe), st.dropped = all →
      l.foldl (fun st alp => shapeStep kept addrs all st (ahp, alp)) st = st
  | [], _, _ => rfl
  | a :: l, st, h => by
    rw [List.foldl_cons]
    have : shapeStep kept addrs all st (ahp, a) = st := by
      unfold shapeStep
      rw [ite_eq_left h]
    rw [this]
    exact inner_fold_done ahp l st h

/-- The shapes `probeChunk` visits, in order. -/
def chunkShapes (tbl : Table) (hp lp : Nat) : List (Nat × Nat) :=
  (bitsAsc 128 (tbl.2 &&& ((1#128 <<< hp) - 1#128))).flatMap
    (fun ahp => (bitsAsc 128 (eligLo tbl ahp lp)).map (ahp, ·))

/-- The nested loops of `probeChunk` are one loop over the visited shapes: once every
network is dropped, the rest of a row changes nothing. -/
theorem probeChunk_eq (tbl : Table) (kept chunk : List Net) (hp lp : Nat) :
    probeChunk tbl kept chunk hp lp =
      ((chunkShapes tbl hp lp).foldl (shapeStep kept (chunk.map (·.1)) (allDropped chunk.length))
        ⟨0, 0⟩).dropped := by
  unfold probeChunk chunkShapes
  rw [List.foldl_flatMap]
  congr 2
  funext st ahp
  rw [List.foldl_map]
  split
  · rename_i h
    exact (inner_fold_done ahp _ st h).symm
  · rfl

theorem mem_chunkShapes (S : List Net) {hp lp : Nat} (hhp : hp ≤ 64) (hlp : lp ≤ 64)
    (s : Nat × Nat) :
    s ∈ chunkShapes (shapeTable S) hp lp ↔
      s.1 < hp ∧ s.2 ≤ lp ∧ ∃ z ∈ S, hiP z = s.1 ∧ loP z = s.2 := by
  obtain ⟨h, l⟩ := s
  simp only [chunkShapes, List.mem_flatMap, List.mem_map, mem_bitsAsc, BitVec.getLsbD_and,
    getLsbD_lowMask (show hp < 128 by omega), Bool.and_eq_true, decide_eq_true_eq, shapeTable_hi,
    Prod.mk.injEq]
  constructor
  · rintro ⟨a, ⟨-, ha⟩, b, hb, rfl, rfl⟩
    unfold eligLo at hb
    split at hb
    · rename_i hl
      obtain ⟨z, hz, hz1, hz2⟩ := (shapeTable_lo S a b).mp hb
      exact ⟨ha, by have := loP_le z; omega, z, hz, hz1, hz2⟩
    · rw [BitVec.getLsbD_and, getLsbD_lowMask (show lp + 1 < 128 by omega), Bool.and_eq_true,
        decide_eq_true_eq] at hb
      obtain ⟨z, hz, hz1, hz2⟩ := (shapeTable_lo S a b).mp hb.1
      exact ⟨ha, by omega, z, hz, hz1, hz2⟩
  · rintro ⟨ha, hb, z, hz, hz1, hz2⟩
    refine ⟨h, ⟨⟨z, hz, hz1⟩, ha⟩, l, ?_, rfl, rfl⟩
    have hlo : ((shapeTable S).1 h).getLsbD l = true :=
      (shapeTable_lo S h l).mpr ⟨z, hz, hz1, hz2⟩
    unfold eligLo
    split
    · exact hlo
    · rw [BitVec.getLsbD_and, getLsbD_lowMask (show lp + 1 < 128 by omega), hlo]
      simp only [Bool.true_and, decide_eq_true_eq]
      omega

theorem chunkShapes_sorted (tbl : Table) (hp lp : Nat) :
    (chunkShapes tbl hp lp).Pairwise fun s t => s.1 < t.1 ∨ (s.1 = t.1 ∧ s.2 < t.2) := by
  unfold chunkShapes
  rw [List.pairwise_flatMap]
  refine ⟨fun a _ => ?_, ?_⟩
  · rw [List.pairwise_map]
    exact (bitsAsc_sorted _).imp fun h => Or.inr ⟨rfl, h⟩
  · refine (bitsAsc_sorted _).imp fun {a b} h => ?_
    intro x hx y hy
    obtain ⟨_, _, rfl⟩ := List.mem_map.mp hx
    obtain ⟨_, _, rfl⟩ := List.mem_map.mp hy
    exact Or.inl h

/-- Visiting shapes in ascending order visits their masks in ascending order. -/
theorem shapeMask_lt_of_lex {s t : Nat × Nat} (ht : t.1 ≤ 64) (ht2 : t.2 ≤ 64)
    (h : s.1 < t.1 ∨ (s.1 = t.1 ∧ s.2 < t.2)) :
    (shapeMask s.1 s.2).toNat < (shapeMask t.1 t.2).toNat := by
  rcases h with h | ⟨h1, h2⟩
  · exact shapeMask_lt_hi _ _ (halfMask_lt h ht)
  · rw [h1]
    exact shapeMask_lt_lo _ (halfMask_lt h2 ht2)

/-- What probing the shapes `V` established, with the shapes `R` still to come: the
cursor is below every network of a coming mask, every dropped network has an ancestor
of a visited shape, and unless all are dropped, every network with an ancestor of a
visited shape is dropped. -/
structure ChunkInv (kept : List Net) (addrs : List (BitVec 128)) (all : BitVec 64)
    (V R : List (Nat × Nat)) (st : Probe) : Prop where
  cursor_le : st.cursor ≤ kept.length
  cursor_lt : ∀ y ∈ kept.take st.cursor, ∀ s ∈ R, y.2.toNat < (shapeMask s.1 s.2).toNat
  sound : ∀ i, st.dropped.getLsbD i = true → ∃ a, addrs[i]? = some a ∧
    ∃ s ∈ V, ∃ y ∈ kept, y.2 = shapeMask s.1 s.2 ∧ y.1 = a &&& y.2
  complete : st.dropped = all ∨ ∀ s ∈ V, ∀ i a, addrs[i]? = some a →
    (∃ y ∈ kept, y.2 = shapeMask s.1 s.2 ∧ y.1 = a &&& y.2) → st.dropped.getLsbD i = true

theorem chunkInv_step {kept : List Net} (hk : kept.Pairwise fun a b => sortKey a < sortKey b)
    {addrs : List (BitVec 128)} (hlen : addrs.length ≤ 64) {all : BitVec 64}
    {V R : List (Nat × Nat)} {s : Nat × Nat} {st : Probe} (hs : s.1 < 64)
    (hR : ∀ t ∈ R, (shapeMask s.1 s.2).toNat < (shapeMask t.1 t.2).toNat)
    (h : ChunkInv kept addrs all V (s :: R) st) :
    ChunkInv kept addrs all (V ++ [s]) R (shapeStep kept addrs all st s) := by
  unfold shapeStep
  split
  · rename_i hall
    exact ⟨h.cursor_le, fun y hy t ht => h.cursor_lt y hy t (List.mem_cons_of_mem _ ht),
      fun i hi => by
        obtain ⟨a, ha, s', hs', hy⟩ := h.sound i hi
        exact ⟨a, ha, s', List.mem_append_left _ hs', hy⟩,
      Or.inl hall⟩
  · rename_i hall
    obtain ⟨p1, p2, p3⟩ := probeShape_spec hk hlen (toNat_shapeMask_succ (l := s.2) hs)
      h.cursor_le (fun y hy => h.cursor_lt y hy s List.mem_cons_self)
    refine ⟨p1, fun y hy t ht => Nat.lt_of_le_of_lt (p2 y hy) (hR t ht), fun i hi => ?_, ?_⟩
    · rcases (p3 i).mp hi with hi | ⟨a, ha, y, hy, hya, hyb⟩
      · obtain ⟨a, ha, s', hs', hy⟩ := h.sound i hi
        exact ⟨a, ha, s', List.mem_append_left _ hs', hy⟩
      · exact ⟨a, ha, s, List.mem_append_right _ List.mem_cons_self, y, hy, hya,
          by rw [hya]; exact hyb⟩
    · rcases h.complete with hc | hc
      · exact absurd hc hall
      · refine Or.inr fun s' hs' i a ha hy => (p3 i).mpr ?_
        rcases List.mem_append.mp hs' with hs' | hs'
        · exact Or.inl (hc s' hs' i a ha hy)
        · rw [List.mem_singleton] at hs'
          subst hs'
          obtain ⟨y, hy, hya, hyb⟩ := hy
          exact Or.inr ⟨a, ha, y, hy, hya, by rw [hyb, hya]⟩

theorem chunkInv_fold {kept : List Net} (hk : kept.Pairwise fun a b => sortKey a < sortKey b)
    {addrs : List (BitVec 128)} (hlen : addrs.length ≤ 64) {all : BitVec 64} :
    ∀ (R V : List (Nat × Nat)) (st : Probe), (∀ s ∈ R, s.1 < 64) →
      R.Pairwise (fun s t => (shapeMask s.1 s.2).toNat < (shapeMask t.1 t.2).toNat) →
      ChunkInv kept addrs all V R st →
      ChunkInv kept addrs all (V ++ R) [] (R.foldl (shapeStep kept addrs all) st)
  | [], V, st, _, _, h => by simpa using h
  | s :: R, V, st, hR, hs, h => by
    rw [List.foldl_cons, show V ++ s :: R = (V ++ [s]) ++ R by simp]
    rw [List.pairwise_cons] at hs
    exact chunkInv_fold hk hlen R (V ++ [s]) _ (fun t ht => hR t (List.mem_cons_of_mem _ ht))
      hs.2 (chunkInv_step hk hlen (hR s List.mem_cons_self) hs.1 h)

theorem prefix_le_of_sub {k1 k2 : Nat} (hk1 : k1 ≤ 64)
    (h : halfMask k2 &&& halfMask k1 = halfMask k1) : k1 ≤ k2 := by
  apply Classical.byContradiction
  intro hn
  have hlt := halfMask_lt (show k2 < k1 by omega) hk1
  have hle : (halfMask k1).toNat ≤ (halfMask k2).toNat := by
    rw [← h, BitVec.toNat_and]
    exact Nat.and_le_left
  omega

/-- A mask inside another has both prefixes no larger. -/
theorem prefixes_le {x y : Net} (hx : IsBiNet x) (hy : IsBiNet y) (h : x.2 &&& y.2 = y.2) :
    hiP y ≤ hiP x ∧ loP y ≤ loP x := by
  have hh : hiM x &&& hiM y = hiM y := by
    unfold hiM hi
    generalize x.2 = a at h ⊢
    generalize y.2 = b at h ⊢
    bv_decide
  have hl : loM x &&& loM y = loM y := by
    unfold loM lo
    generalize x.2 = a at h ⊢
    generalize y.2 = b at h ⊢
    bv_decide
  rw [hiM_eq hx, hiM_eq hy] at hh
  rw [loM_eq hx, loM_eq hy] at hl
  exact ⟨prefix_le_of_sub (hiP_le y) hh, prefix_le_of_sub (loP_le y) hl⟩

/-- One chunk of networks of shape `(hp, lp)`: a network is dropped iff a kept network
other than it contains it, given that every container has a smaller high-half prefix. -/
theorem probeChunk_spec {S kept chunk : List Net}
    (hk : kept.Pairwise fun a b => sortKey a < sortKey b) (hkS : ∀ y ∈ kept, y ∈ S)
    (hbi : ∀ z ∈ S, IsBiNet z) (hlen : chunk.length ≤ 64) {hp lp : Nat}
    (hchunk : ∀ x ∈ chunk, IsBiNet x ∧ hiP x = hp ∧ loP x = lp)
    (hstrict : ∀ y ∈ kept, ∀ x ∈ chunk, y ≠ x → Contains y x → hiP y < hiP x)
    (i : Nat) (hi : i < chunk.length) :
    (probeChunk (shapeTable S) kept chunk hp lp).getLsbD i = true ↔
      ∃ y ∈ kept, y ≠ chunk[i] ∧ Contains y chunk[i] := by
  have hx := hchunk chunk[i] (List.getElem_mem hi)
  have hhp : hp ≤ 64 := by rw [← hx.2.1]; exact hiP_le _
  have hlp : lp ≤ 64 := by rw [← hx.2.2]; exact loP_le _
  have hmem := mem_chunkShapes S hhp hlp
  have hlt64 : ∀ s ∈ chunkShapes (shapeTable S) hp lp, s.1 < 64 := fun s hs => by
    have := (hmem s).mp hs
    omega
  have hsorted : (chunkShapes (shapeTable S) hp lp).Pairwise
      (fun s t => (shapeMask s.1 s.2).toNat < (shapeMask t.1 t.2).toNat) :=
    (chunkShapes_sorted (shapeTable S) hp lp).imp_of_mem fun {s t} _ ht h => by
      have := (hmem t).mp ht
      exact shapeMask_lt_of_lex (by omega) (by omega) h
  have hinit : ChunkInv kept (chunk.map (·.1)) (allDropped chunk.length) []
      (chunkShapes (shapeTable S) hp lp) ⟨0, 0⟩ :=
    ⟨Nat.zero_le _, fun y hy => by simp at hy, fun i hi => by simp at hi,
      Or.inr fun s hs => by simp at hs⟩
  have hfin := chunkInv_fold hk (by simpa using hlen) _ [] _ hlt64 hsorted hinit
  rw [List.nil_append] at hfin
  have haddr : (chunk.map (·.1))[i]? = some chunk[i].1 := by simp [hi]
  rw [probeChunk_eq]
  constructor
  · intro hb
    obtain ⟨a, ha, s, hs, y, hy, hys, hya⟩ := hfin.sound i hb
    rw [haddr, Option.some.injEq] at ha
    subst ha
    obtain ⟨hs1, hs2, -⟩ := (hmem s).mp hs
    refine ⟨y, hy, fun e => ?_, ⟨hya.symm, ?_⟩⟩
    · have := hiP_of_mask hys (by omega)
      rw [e, hx.2.1] at this
      omega
    · rw [hys, mask_eq_shapeMask hx.1, hx.2.1, hx.2.2]
      exact shapeMask_sub (by omega) hs2
  · rintro ⟨y, hy, hne, hc⟩
    have hyb := hbi y (hkS y hy)
    have h1 := hstrict y hy chunk[i] (List.getElem_mem hi) hne hc
    have h2 := (prefixes_le hx.1 hyb hc.2).2
    rcases hfin.complete with hall | hall
    · rw [hall, getLsbD_allDropped hlen]
      simpa using hi
    · apply hall (hiP y, loP y) ((hmem _).mpr ⟨by rw [← hx.2.1]; exact h1,
        by rw [← hx.2.2]; exact h2, y, hkS y hy, rfl, rfl⟩) i chunk[i].1 haddr
      exact ⟨y, hy, mask_eq_shapeMask hyb, hc.1.symm⟩

/-! ## The chunk loop -/

/-- A network that another network of `S` contains. -/
def Dominated (S : List Net) (x : Net) : Prop := ∃ y ∈ S, y ≠ x ∧ Contains y x

instance (S : List Net) (x : Net) : Decidable (Dominated S x) :=
  inferInstanceAs (Decidable (∃ y ∈ S, y ≠ x ∧ Contains y x))

/-- The networks the probe keeps. -/
def keep (S : List Net) (x : Net) : Bool := !decide (Dominated S x)

theorem containsNet_refl {x : Net} (hx : x.1 &&& x.2 = x.1) : Contains x x :=
  ⟨hx, BitVec.and_self⟩

/-- A container other than the network itself has a smaller mask. -/
theorem mask_lt_of_contains {x y : Net} (hx : x.1 &&& x.2 = x.1) (h : Contains y x)
    (hne : y ≠ x) : y.2.toNat < x.2.toNat := by
  have hle : y.2.toNat ≤ x.2.toNat := by
    rw [← h.2, BitVec.toNat_and]
    exact Nat.and_le_left
  have hm : y.2 ≠ x.2 := by
    intro e
    apply hne
    have : y.1 = x.1 := by rw [← h.1, e, hx]
    exact Prod.ext this e
  have : y.2.toNat ≠ x.2.toNat := fun e => hm (BitVec.eq_of_toNat_eq e)
  omega

/-- Every network of `S` is contained in a network of `S` that nothing else contains. -/
theorem exists_undominated {S : List Net} (hn : ∀ z ∈ S, z.1 &&& z.2 = z.1) :
    ∀ (n : Nat) (y : Net), y.2.toNat < n → y ∈ S →
      ∃ z ∈ S, ¬ Dominated S z ∧ Contains z y
  | 0, _, h, _ => absurd h (Nat.not_lt_zero _)
  | n + 1, y, hyn, hy => by
    by_cases hd : Dominated S y
    · obtain ⟨w, hw, hne, hc⟩ := hd
      have hlt := mask_lt_of_contains (hn y hy) hc hne
      obtain ⟨z, hz, hzd, hzc⟩ := exists_undominated hn n w (by omega) hw
      exact ⟨z, hz, hzd, contains_trans hzc hc⟩
    · exact ⟨y, hy, hd, containsNet_refl (hn y hy)⟩

theorem zipIdx_filter_map {α : Type} (P : Nat → Bool) (q : α → Bool) :
    ∀ (l : List α) (n : Nat), (∀ j (hj : j < l.length), P (n + j) = q l[j]) →
      ((l.zipIdx n).filter (fun aj => P aj.2)).map (·.1) = l.filter q
  | [], _, _ => rfl
  | a :: l, n, h => by
    rw [List.zipIdx_cons, List.filter_cons, List.filter_cons]
    have h0 : P n = q a := by
      have := h 0 (by simp)
      rwa [Nat.add_zero, List.getElem_cons_zero] at this
    have ih := zipIdx_filter_map P q l (n + 1) fun j hj => by
      have := h (j + 1) (by simp; omega)
      rwa [List.getElem_cons_succ, show n + (j + 1) = n + 1 + j by omega] at this
    rw [h0]
    split
    · rw [List.map_cons, ih]
    · exact ih

theorem mask_ge_of_sorted {x : Net} {xs : List Net}
    (hs : (x :: xs).Pairwise fun a b => sortKey a < sortKey b) :
    ∀ z ∈ x :: xs, x.2.toNat ≤ z.2.toNat := by
  intro z hz
  rcases List.mem_cons.mp hz with rfl | hz
  · exact Nat.le_refl _
  · exact mask_le_of_sortKey (Nat.le_of_lt ((List.pairwise_cons.mp hs).1 z hz))

/-- The chunk loop keeps exactly the networks that no other network contains. -/
theorem probeLoop_spec {S : List Net} (hS : S.Pairwise fun a b => sortKey a < sortKey b)
    (hbi : ∀ z ∈ S, IsBiNet z)
    (hstrict : ∀ y ∈ S, ∀ x ∈ S, y ≠ x → Contains y x → hiP y < hiP x) :
    ∀ (f : Nat) (done rest : List Net), S = done ++ rest → rest.length ≤ f →
      probeLoop (shapeTable S) f (done.filter (keep S)) rest = S.filter (keep S)
  | 0, done, rest, hS', hf => by
    have : rest = [] := List.length_eq_zero_iff.mp (by omega)
    subst this
    rw [List.append_nil] at hS'
    subst hS'
    rfl
  | f + 1, done, [], hS', _ => by
    rw [List.append_nil] at hS'
    subst hS'
    rfl
  | f + 1, done, x :: xs, hS', hf => by
    rw [probeLoop]
    generalize hC : ((x :: xs).takeWhile (fun y => y.2 = x.2)).take 64 = chunk
    have hpre : chunk <+: x :: xs := by
      rw [← hC]
      exact (List.take_prefix _ _).trans (List.takeWhile_prefix _)
    have hsplit : x :: xs = chunk ++ (x :: xs).drop chunk.length := by
      conv => lhs; rw [← List.take_append_drop chunk.length (x :: xs)]
      rw [← List.prefix_iff_eq_take.mp hpre]
    have hlen : chunk.length ≤ 64 := by
      rw [← hC]
      exact List.length_take_le _ _
    have hpos : 1 ≤ chunk.length := by
      rw [← hC, List.takeWhile_cons_of_pos (by simp)]
      simp
    have hmask : ∀ c ∈ chunk, c.2 = x.2 := by
      intro c hc
      rw [← hC] at hc
      simpa using mem_takeWhile_pred (List.mem_of_mem_take hc)
    have hSsplit : S = (done ++ chunk) ++ (x :: xs).drop chunk.length := by
      rw [List.append_assoc, ← hsplit]
      exact hS'
    have hdone : ∀ y ∈ done, y ∈ S := fun y hy => by rw [hS']; exact List.mem_append_left _ hy
    have hchunkS : ∀ c ∈ chunk, c ∈ S := fun c hc => by
      rw [hS', hsplit]
      exact List.mem_append_right _ (List.mem_append_left _ hc)
    have hsorted_rest : (x :: xs).Pairwise fun a b => sortKey a < sortKey b := by
      rw [hS'] at hS
      exact (List.pairwise_append.mp hS).2.1
    have hsorted_done : done.Pairwise fun a b => sortKey a < sortKey b := by
      rw [hS'] at hS
      exact (List.pairwise_append.mp hS).1
    have hkept_sorted : (done.filter (keep S)).Pairwise fun a b => sortKey a < sortKey b :=
      hsorted_done.filter _
    have hkS : ∀ y ∈ done.filter (keep S), y ∈ S := fun y hy =>
      hdone y (List.mem_filter.mp hy).1
    have hchunk : ∀ c ∈ chunk, IsBiNet c ∧ hiP c = hiP x ∧ loP c = loP x := by
      intro c hc
      have e := hmask c hc
      refine ⟨hbi c (hchunkS c hc), ?_, ?_⟩
      · unfold hiP hiM
        rw [e]
      · unfold loP loM
        rw [e]
    -- a chunk network is contained in another network iff in a kept one
    have hdom : ∀ c ∈ chunk,
        (Dominated S c ↔ ∃ y ∈ done.filter (keep S), y ≠ c ∧ Contains y c) := by
      intro c hc
      have hcn := (hbi c (hchunkS c hc)).2
      constructor
      · rintro ⟨y, hy, hne, hcy⟩
        have hlt := mask_lt_of_contains hcn hcy hne
        have hyd : y ∈ done := by
          rw [hS'] at hy
          rcases List.mem_append.mp hy with hy | hy
          · exact hy
          · have := mask_ge_of_sorted hsorted_rest y hy
            rw [← hmask c hc] at this
            omega
        obtain ⟨z, hz, hzd, hzc⟩ := exists_undominated (fun z hz => (hbi z hz).2) _ y
          (Nat.lt_succ_self _) (hdone y hyd)
        have hzy : z = y ∨ z.2.toNat < y.2.toNat := by
          by_cases e : z = y
          · exact Or.inl e
          · exact Or.inr (mask_lt_of_contains (hbi y (hdone y hyd)).2 hzc e)
        have hzdone : z ∈ done := by
          rcases hzy with rfl | hzy
          · exact hyd
          · rw [hS'] at hz hS
            rcases List.mem_append.mp hz with hz | hz
            · exact hz
            · have := (List.pairwise_append.mp hS).2.2 y hyd z hz
              have := sortKey_lt_of_mask hzy
              omega
        refine ⟨z, List.mem_filter.mpr ⟨hzdone, by simp [keep, hzd]⟩, fun e => ?_,
          contains_trans hzc hcy⟩
        rw [e] at hzy
        rcases hzy with rfl | hzy
        · exact hne rfl
        · omega
      · rintro ⟨y, hy, hne, hcy⟩
        exact ⟨y, hkS y hy, hne, hcy⟩
    have hfilter : (chunk.zipIdx.filter fun aj =>
        decide (probeChunk (shapeTable S) (done.filter (keep S)) chunk (hiP x) (loP x) &&&
          (1#64 <<< aj.2) = 0)).map (·.1) = chunk.filter (keep S) := by
      have hb := probeChunk_spec hkept_sorted hkS hbi hlen hchunk
        (fun y hy c hc => hstrict y (hkS y hy) c (hchunkS c hc))
      generalize probeChunk (shapeTable S) (done.filter (keep S)) chunk (hiP x) (loP x) = D
        at hb ⊢
      refine zipIdx_filter_map (fun j => decide (D &&& (1#64 <<< j) = 0)) (keep S) chunk 0
        fun j hj => ?_
      simp only [Nat.zero_add]
      have hbj := hb j hj
      rw [← hdom chunk[j] (List.getElem_mem hj)] at hbj
      have hj64 : j < 64 := by omega
      unfold keep
      by_cases hd : Dominated S chunk[j]
      · have := hbj.mpr hd
        simp only [hd, decide_true, Bool.not_true, decide_eq_false_iff_not]
        rw [and_bit_eq_zero hj64, this]
        simp
      · have : D.getLsbD j = false := by
          cases h : D.getLsbD j
          · rfl
          · exact absurd (hbj.mp h) hd
        simp only [hd, decide_false, Bool.not_false, decide_eq_true_eq]
        exact (and_bit_eq_zero hj64).mpr this
    rw [hfilter, ← List.filter_append]
    apply probeLoop_spec hS hbi hstrict f _ _ hSsplit
    have : ((x :: xs).drop chunk.length).length = (x :: xs).length - chunk.length :=
      List.length_drop
    simp only [List.length_cons] at this hf
    omega

theorem probe_spec {S : List Net} (hS : S.Pairwise fun a b => sortKey a < sortKey b)
    (hbi : ∀ z ∈ S, IsBiNet z)
    (hstrict : ∀ y ∈ S, ∀ x ∈ S, y ≠ x → Contains y x → hiP y < hiP x) :
    probe S = S.filter (keep S) := by
  have := probeLoop_spec hS hbi hstrict S.length [] S (List.nil_append S).symm (Nat.le_refl _)
  rwa [List.filter_nil] at this

/-! ## `bicontiguous_find_containment` -/

theorem sortLe_trans (x y z : Net) (h1 : sortLe x y = true) (h2 : sortLe y z = true) :
    sortLe x z = true := by
  simp only [sortLe, decide_eq_true_eq] at *
  omega

theorem sortLe_total (x y : Net) : (sortLe x y || sortLe y x) = true := by
  simp only [sortLe, Bool.or_eq_true, decide_eq_true_eq]
  omega

theorem pairwise_forall {α : Type} {R : α → α → Prop} (hR : ∀ {a b}, R a b → R b a) :
    ∀ {l : List α}, l.Pairwise R → ∀ a ∈ l, ∀ b ∈ l, a ≠ b → R a b
  | [], _ => by simp
  | x :: l, h => by
    rw [List.pairwise_cons] at h
    intro a ha b hb hab
    rcases List.mem_cons.mp ha with ha' | ha'
    · rcases List.mem_cons.mp hb with hb' | hb'
      · exact absurd (ha'.trans hb'.symm) hab
      · rw [ha']
        exact h.1 b hb'
    · rcases List.mem_cons.mp hb with hb' | hb'
      · rw [hb']
        exact hR (h.1 a ha')
      · exact pairwise_forall hR h.2 a ha' b hb' hab

/-- Canonical groups, for any two distinct networks. -/
theorem canon_pair {S : List Net} (h : GroupsCanon S) :
    ∀ x ∈ S, ∀ y ∈ S, x ≠ y → SameHi x y → ¬ Meets x y ∧ ¬ Buddies x y :=
  pairwise_forall (fun {_ _} hab hs => ⟨fun hm => (hab (sameHi_symm hs)).1 hm.symm,
    fun hb => (hab (sameHi_symm hs)).2 (buddies_symm hb)⟩) h

theorem nodup_of_canon {S : List Net} (h : GroupsCanon S) : S.Nodup :=
  h.imp fun {a b} hab e => by
    subst e
    exact (hab ⟨rfl, rfl⟩).1 rfl

/-- On canonical groups, a container has a smaller high-half prefix: one of the same
prefix shares the group and meets the network it contains. -/
theorem hiP_lt_of_contains {S : List Net} (hbi : ∀ z ∈ S, IsBiNet z) (hcanon : GroupsCanon S) :
    ∀ y ∈ S, ∀ x ∈ S, y ≠ x → Contains y x → hiP y < hiP x := by
  intro y hy x hx hne hc
  have hle := (prefixes_le (hbi x hx) (hbi y hy) hc.2).1
  apply Nat.lt_of_le_of_ne hle
  intro heq
  have hm : hiM y = hiM x := hiM_eq_of_level (hbi y hy) (hbi x hx) heq
  have hn := hi_normalized (hbi x hx)
  have ha : hiA y = hiA x := by
    have h1 := hc.1
    unfold hiA hiM hi at *
    generalize x.1 = x1 at *
    generalize x.2 = x2 at *
    generalize y.1 = y1 at *
    generalize y.2 = y2 at *
    bv_decide
  have hmeets : Meets y x := by
    have h1 := hc.1
    have h2 := hc.2
    unfold Meets
    generalize x.1 = x1 at *
    generalize x.2 = x2 at *
    generalize y.1 = y1 at *
    generalize y.2 = y2 at *
    bv_decide
  exact (canon_pair hcanon y hy x hx hne ⟨ha, hm⟩).1 hmeets

/-- `bicontiguous_find_containment` on a level sweep's output: it keeps exactly the
networks no other network contains, each once. -/
theorem findContainment_spec {S : List Net} (hbi : ∀ x ∈ S, IsBiNet x)
    (hcanon : GroupsCanon S) :
    (∀ x, x ∈ findContainment S ↔ x ∈ S ∧ ¬ Dominated S x) ∧
      (findContainment S).Nodup ∧ (findContainment S).length ≤ S.length ∧
      ((findContainment S).length = S.length → (findContainment S).Perm S) := by
  have hnd := nodup_of_canon hcanon
  unfold findContainment
  split
  · rename_i hlen
    refine ⟨fun x => ⟨fun hx => ⟨hx, ?_⟩, fun h => h.1⟩, hnd, Nat.le_refl _,
      fun _ => List.Perm.refl _⟩
    rintro ⟨y, hy, hne, -⟩
    rcases S with _ | ⟨a, _ | ⟨b, S'⟩⟩
    · simp at hx
    · simp only [List.mem_singleton] at hx hy
      exact hne (hy.trans hx.symm)
    · simp at hlen
  · have hperm := List.mergeSort_perm S sortLe
    have hle := List.pairwise_mergeSort sortLe_trans sortLe_total S
    generalize S.mergeSort sortLe = S' at hperm hle ⊢
    have hnd' : S'.Nodup := hperm.nodup_iff.mpr hnd
    have hbi' : ∀ z ∈ S', IsBiNet z := fun z hz => hbi z (hperm.subset hz)
    have hsorted : S'.Pairwise fun a b => sortKey a < sortKey b :=
      (hle.and hnd').imp fun ⟨h1, h2⟩ => by
        simp only [sortLe, decide_eq_true_eq] at h1
        exact Nat.lt_of_le_of_ne h1 fun e => h2 (sortKey_inj e)
    have hstrict : ∀ y ∈ S', ∀ x ∈ S', y ≠ x → Contains y x → hiP y < hiP x :=
      fun y hy x hx => hiP_lt_of_contains hbi hcanon y (hperm.subset hy) x (hperm.subset hx)
    rw [probe_spec hsorted hbi' hstrict]
    have hdom : ∀ x, Dominated S' x ↔ Dominated S x := fun x =>
      ⟨fun ⟨y, hy, h⟩ => ⟨y, hperm.subset hy, h⟩,
        fun ⟨y, hy, h⟩ => ⟨y, hperm.symm.subset hy, h⟩⟩
    refine ⟨fun x => ?_, hnd'.filter _, ?_, fun h => ?_⟩
    · rw [List.mem_filter, hperm.mem_iff]
      simp only [keep, Bool.not_eq_eq_eq_not, Bool.not_true, decide_eq_false_iff_not, hdom]
    · rw [← hperm.length_eq]
      exact List.filter_sublist.length_le
    · rw [← hperm.length_eq] at h
      rw [List.filter_sublist.eq_of_length h]
      exact hperm

/-- `bicontiguous_find_containment` keeps the union: every dropped network is inside a
kept one. -/
theorem findContainment_union {S : List Net} (hbi : ∀ x ∈ S, IsBiNet x)
    (hcanon : GroupsCanon S) (X : BitVec 128) :
    (∃ z ∈ findContainment S, Mem X z) ↔ ∃ x ∈ S, Mem X x := by
  have hmem := (findContainment_spec hbi hcanon).1
  constructor
  · rintro ⟨z, hz, hX⟩
    exact ⟨z, ((hmem z).mp hz).1, hX⟩
  · rintro ⟨x, hx, hX⟩
    obtain ⟨z, hz, hzd, hzc⟩ :=
      exists_undominated (fun z hz => (hbi z hz).2) _ x (Nat.lt_succ_self _) hx
    exact ⟨z, (hmem z).mpr ⟨hz, hzd⟩, mem_of_contains hzc hX⟩

/-! ## The rounds -/

theorem canon_perm {S S' : List Net} (h : S.Perm S') (hc : GroupsCanon S) : GroupsCanon S' :=
  (List.Perm.pairwise_iff (fun {_ _} hab hs => ⟨fun hm => (hab (sameHi_symm hs)).1 hm.symm,
    fun hb => (hab (sameHi_symm hs)).2 (buddies_symm hb)⟩) h).mp hc

/-- The rounds, while the fuel lasts longer than the networks: the union is kept, and the
result is a level sweep's output that no containment drop changes. -/
theorem rounds_spec : ∀ (f : Nat) (L : List Net), L.length < f → (∀ x ∈ L, IsBiNet x) →
    (∀ x ∈ rounds f L, IsBiNet x) ∧
      (∀ X, (∃ z ∈ rounds f L, Mem X z) ↔ ∃ x ∈ L, Mem X x) ∧
      GroupsCanon (rounds f L) ∧ (∀ q H, ¬ MergeableAt (rounds f L) q H) ∧
      (rounds f L).Nodup ∧ ∀ x ∈ rounds f L, ¬ Dominated (rounds f L) x
  | 0, _, h, _ => absurd h (Nat.not_lt_zero _)
  | f + 1, L, hlen, hL => by
    obtain ⟨s1, s2, s3, s4, s5⟩ := sweep_spec L hL
    obtain ⟨k1, k2, k3, k4⟩ := findContainment_spec s1 s3
    have ku := findContainment_union s1 s3
    rw [rounds]
    split
    · rename_i heq
      have hp := k4 heq
      refine ⟨fun x hx => s1 x ((k1 x).mp hx).1, fun X => (ku X).trans (s2 X),
        canon_perm hp.symm s3,
        fun q H hM => s4 q H (mergeableAt_of_perm (fun H => group_perm hp q H) hM), k2,
        fun x hx hd => ?_⟩
      obtain ⟨y, hy, hne, hc⟩ := hd
      exact ((k1 x).mp hx).2 ⟨y, ((k1 y).mp hy).1, hne, hc⟩
    · rename_i hne
      have hlt : (findContainment (sweep L)).length < f := by omega
      obtain ⟨r1, r2, r3, r4, r5, r6⟩ :=
        rounds_spec f _ hlt fun x hx => s1 x ((k1 x).mp hx).1
      exact ⟨r1, fun X => (r2 X).trans ((ku X).trans (s2 X)), r3, r4, r5, r6⟩

/-! ## No lowest-mask-bit siblings -/

theorem halfMask_and_neg {q : Nat} (h1 : 1 ≤ q) (hq : q ≤ 64) :
    halfMask q &&& -halfMask q = buddyBit q := by
  rw [halfMask_eq q hq, buddyBit_eq q hq, ofNat_sub_64 hq]
  have e1 : 1#64 ≤ BitVec.ofNat 64 q := by
    rw [BitVec.le_def, toNat_ofNat_64 hq]
    simpa using h1
  have e2 : BitVec.ofNat 64 q ≤ 64#64 := by
    rw [BitVec.le_def, toNat_ofNat_64 hq]
    simpa using hq
  generalize BitVec.ofNat 64 q = Q at *
  bv_decide

/-- Lowest-mask-bit siblings share their group, or their low halves are whole and they
are high-half buddies. -/
theorem buddies_cases {x y : Net} (hx : IsBiNet x) (hy : IsBiNet y) (h : Buddies x y) :
    SameHi x y ∨
      (1 ≤ hiP x ∧ hiP y = hiP x ∧ loM x = 0 ∧ loM y = 0 ∧ loA x = 0 ∧ loA y = 0 ∧
        loP y = loP x ∧ hiA x ^^^ hiA y = buddyBit (hiP x)) := by
  obtain ⟨hm, h0, hxor⟩ := h
  have hpy : hiP y = hiP x := by
    unfold hiP hiM
    rw [hm]
  have hly : loP y = loP x := by
    unfold loP loM
    rw [hm]
  by_cases hlo : loM x = 0
  · right
    have hxn := hx.2
    have hyn := hy.2
    have hhi : hiM x ≠ 0 := by
      unfold loM hiM lo hi at *
      generalize x.2 = x2 at *
      bv_decide
    have hq1 : 1 ≤ hiP x := by
      apply Classical.byContradiction
      intro hq
      apply hhi
      rw [hiM_eq hx, show hiP x = 0 by omega, halfMask_eq 0 (by omega)]
      bv_decide
    have hxl : loA x = 0 := by
      unfold loA loM lo at *
      generalize x.1 = x1 at *
      generalize x.2 = x2 at *
      bv_decide
    have hyl : loA y = 0 := by
      unfold loA loM lo at *
      rw [← hm] at hyn
      generalize x.2 = x2 at *
      generalize y.1 = y1 at *
      bv_decide
    have hlo' : loM y = 0 := by
      unfold loM at *
      rw [← hm]
      exact hlo
    have hbit : hiA x ^^^ hiA y = hiM x &&& -hiM x := by
      unfold hiA hiM loM hi lo at *
      generalize x.1 = x1 at *
      generalize x.2 = x2 at *
      generalize y.1 = y1 at *
      bv_decide
    rw [hiM_eq hx, halfMask_and_neg hq1 (hiP_le x)] at hbit
    exact ⟨hq1, hpy, hlo, hlo', hxl, hyl, hly, hbit⟩
  · left
    refine ⟨?_, by unfold hiM; rw [hm]⟩
    unfold hiA loM hi lo at *
    generalize x.1 = x1 at *
    generalize x.2 = x2 at *
    generalize y.1 = y1 at *
    bv_decide

theorem meets_of_loM_zero {a z : Net} (ha : IsBiNet a) (hz : IsBiNet z) (hs : SameHi a z)
    (h0 : loM a = 0) : Meets a z := by
  have h1 := ha.2
  have h2 := hz.2
  obtain ⟨hA, hM⟩ := hs
  unfold Meets
  unfold hiA hiM loM hi lo at *
  generalize a.1 = a1 at *
  generalize a.2 = a2 at *
  generalize z.1 = z1 at *
  generalize z.2 = z2 at *
  bv_decide

theorem eq_singleton_of_nodup {α : Type} {a : α} :
    ∀ {l : List α}, l.Nodup → a ∈ l → (∀ z ∈ l, z = a) → l = [a]
  | [], _, ha, _ => absurd ha List.not_mem_nil
  | [b], _, _, h => by rw [h b List.mem_cons_self]
  | b :: c :: l, hnd, _, h => by
    have hb := h b List.mem_cons_self
    have hc := h c (List.mem_cons_of_mem _ List.mem_cons_self)
    rw [hb, hc] at hnd
    exact absurd List.mem_cons_self (List.nodup_cons.mp hnd).1

/-- A network with a whole low half is alone in its group. -/
theorem group_whole {S : List Net} (hbi : ∀ z ∈ S, IsBiNet z) (hcanon : GroupsCanon S)
    (hnd : S.Nodup) {a : Net} (ha : a ∈ S) (h0 : loM a = 0) :
    group S (hiP a) (hiA a) = [a] := by
  have hag : a ∈ group S (hiP a) (hiA a) := List.mem_filter.mpr ⟨ha, by simp⟩
  apply eq_singleton_of_nodup (hnd.filter _) hag
  intro z hz
  have hzS := (List.mem_filter.mp hz).1
  have hs : SameHi a z := group_sameHi hbi a hag z hz
  apply Classical.byContradiction
  intro hne
  exact (canon_pair hcanon a ha z hzS (Ne.symm hne) hs).1
    (meets_of_loM_zero (hbi a ha) (hbi z hzS) hs h0)

theorem xor_single {a b c : BitVec 64} (hc : c &&& (c - 1) = 0) (h : a ^^^ b = c) :
    (a &&& c = 0 ∧ b = a ||| c) ∨ (b &&& c = 0 ∧ a = b ||| c) := by
  bv_decide

theorem buddyBit_single {q : Nat} (hq : q ≤ 64) : buddyBit q &&& (buddyBit q - 1) = 0 := by
  rw [buddyBit_eq q hq]
  generalize BitVec.ofNat 64 (64 - q) = K
  bv_decide

/-- Two high-half buddies with whole low halves make their groups mergeable. -/
theorem mergeable_of_whole {S : List Net} (hbi : ∀ z ∈ S, IsBiNet z) (hcanon : GroupsCanon S)
    (hnd : S.Nodup) {a b : Net} (ha : a ∈ S) (hb : b ∈ S) (hq1 : 1 ≤ hiP a)
    (hpb : hiP b = hiP a) (ha0 : loM a = 0) (hb0 : loM b = 0) (hal : loA a = 0) (hbl : loA b = 0)
    (hlp : loP b = loP a)
    (hclr : hiA a &&& buddyBit (hiP a) = 0) (hset : hiA b = hiA a ||| buddyBit (hiP a)) :
    MergeableAt S (hiP a) (hiA a) := by
  have ga := group_whole hbi hcanon hnd ha ha0
  have gb := group_whole hbi hcanon hnd hb hb0
  rw [hpb, hset] at gb
  refine ⟨hq1, hiP_le a, hclr, ?_, ?_, ?_⟩
  · rw [ga]
    exact List.cons_ne_nil _ _
  · rw [gb]
    exact List.cons_ne_nil _ _
  · rw [ga, gb]
    simp [loShape, hal, hbl, hlp]

/-! ## `ipv6_aggregate_bicontiguous` -/

/-- `ipv6_aggregate_bicontiguous`: the output holds normalized bi-contiguous networks with
the input's union, no network contains another, no two are lowest-mask-bit siblings, the
groups are canonical, and no two high-half buddy groups carry the same low halves. -/
theorem aggregateBi_spec (L : List Net) (hL : ∀ x ∈ L, IsBiNet x) :
    (∀ x ∈ aggregateBi L, IsBiNet x) ∧
      (∀ X, (∃ z ∈ aggregateBi L, Mem X z) ↔ ∃ x ∈ L, Mem X x) ∧
      (aggregateBi L).Pairwise
        (fun x y => ¬ Contains x y ∧ ¬ Contains y x ∧ ¬ Buddies x y) ∧
      GroupsCanon (aggregateBi L) ∧ (∀ q H, ¬ MergeableAt (aggregateBi L) q H) := by
  obtain ⟨r1, r2, r3, r4, r5, r6⟩ := rounds_spec (L.length + 1) L (Nat.lt_succ_self _) hL
  unfold aggregateBi
  generalize rounds (L.length + 1) L = O at *
  refine ⟨r1, r2, r5.imp_of_mem fun {x y} hx hy hne => ⟨fun hc => r6 y hy ⟨x, hx, hne, hc⟩,
    fun hc => r6 x hx ⟨y, hy, Ne.symm hne, hc⟩, fun hb => ?_⟩, r3, r4⟩
  rcases buddies_cases (r1 x hx) (r1 y hy) hb with
    hs | ⟨hq1, hpy, hx0, hy0, hxl, hyl, hly, hxor⟩
  · exact (canon_pair r3 x hx y hy hne hs).2 hb
  · rcases xor_single (buddyBit_single (hiP_le x)) hxor with ⟨hc, hs⟩ | ⟨hc, hs⟩
    · exact r4 _ _ (mergeable_of_whole r1 r3 r5 hx hy hq1 hpy hx0 hy0 hxl hyl hly hc hs)
    · rw [← hpy] at hc hs hq1
      exact r4 _ _
        (mergeable_of_whole r1 r3 r5 hy hx hq1 hpy.symm hy0 hx0 hyl hxl hly.symm hc hs)

end Netip.Impl.Ipv6
