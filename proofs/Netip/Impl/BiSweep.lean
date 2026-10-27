import Netip.Impl.BiGroup

/-!
# `ipv6_aggregate_bicontiguous`: the level sweep

`bicontiguous_sweep`, transcribed. The slice is sorted by the level key
`(hi mask, hi address, lo address, lo mask)`, then the levels, the blocks of one
high-half prefix `p`, are processed from `p = 64` down to `0`:

* Phase A (`loAggregate`): every run of one high address, a group, goes through
  the stack of `ipv6_aggregate_contiguous` (`aggregate`);
* Phase B (`hiBuddyMerge`, for `p ≥ 1`): a group whose high address has the buddy
  bit `1 << (64 - p)` clear, followed by its buddy group with element-wise equal
  low halves, is re-parented to prefix `p - 1`, and the buddy group is dropped;
* the block is replaced by its survivors, and if any was re-parented, the native
  block of `p - 1` and the survivors are sorted again (`sweepLevel`).

Sorting is `sort_unstable_by_key`; `mergeSort` stands for it, as the key orders
networks totally and only equal networks share a key, so every sorting
algorithm returns the same list.

Proved (`sweep_spec`), for any input of normalized bi-contiguous networks: the
output has the same union, only normalized bi-contiguous networks, no two
networks of a group whose low halves meet or are buddies, and no level `p ≥ 1`
with two buddy groups carrying the same low halves (`MergeableAt`). After level
`p` is processed, the networks at levels `p` and above never change again, which
is the invariant `SweepInv` carries down the levels.
-/

namespace Netip.Impl.Ipv6

/-- `hi_prefix()`: the leading ones of the high mask half. -/
def hiP (x : Net) : Nat := (~~~(hiM x)).clz.toNat

/-- `lo_prefix()`: the leading ones of the low mask half. -/
def loP (x : Net) : Nat := (~~~(loM x)).clz.toNat

/-- `bicontiguous_level_sort_key`: the tuple `(hi mask, hi address, lo address,
lo mask)`, whose lexicographic order is the numeric order of this number. -/
def levelKey (x : Net) : Nat :=
  (hiM x).toNat * 2 ^ 192 + (hiA x).toNat * 2 ^ 128 + (loA x).toNat * 2 ^ 64 + (loM x).toNat

/-- Comparing level keys. -/
def levelLe (x y : Net) : Bool := decide (levelKey x ≤ levelKey y)

/-- The maximal runs of consecutive networks with the same high address. -/
def hiRuns : List Net → List (List Net)
  | [] => []
  | x :: xs =>
    (x :: xs.takeWhile (fun y => hiA y = hiA x)) :: hiRuns (xs.dropWhile (fun y => hiA y = hiA x))
termination_by l => l.length
decreasing_by
  have := (List.dropWhile_sublist (l := xs) (fun y => decide (hiA y = hiA x))).length_le
  simp only [List.length_cons]
  omega

/-- `bicontiguous_lo_aggregate`: the stack pass over every run of the block. -/
def loAggregate (blk : List Net) : List Net := (hiRuns blk).flatMap aggregate

/-- `bicontiguous_half_prefix_mask(k)`: `!(u64::MAX.checked_shr(k).unwrap_or(0))`. A shift by
`64` or more gives `0` in `BitVec` as in `unwrap_or(0)`. -/
def halfMask (k : Nat) : BitVec 64 := ~~~(BitVec.allOnes 64 >>> k)

/-- `1u64 << (64 - p)`: the buddy bit of high-half prefix `p ≥ 1`. -/
def buddyBit (p : Nat) : BitVec 64 := 1#64 <<< (64 - p)

/-- Re-parenting to high-half prefix `p - 1`:
`from_bits(addr, (mask & u64::MAX as u128) | (new_hi_mask << 64))`. -/
def reparent (p : Nat) (x : Net) : Net :=
  let m := (x.2 &&& (BitVec.allOnes 64).setWidth 128) ||| ((halfMask (p - 1)).setWidth 128 <<< 64)
  (x.1 &&& m, m)

/-- `bicontiguous_lo_lists_equal`: equal lengths, and equal low address and low-half
prefix at every position. -/
def loListsEq (A B : List Net) : Bool :=
  A.length == B.length && (A.zip B).all fun ab => loA ab.1 == loA ab.2 && loP ab.1 == loP ab.2

/-- `bicontiguous_hi_buddy_merge` at level `p`. -/
def hiBuddyMerge (p : Nat) : List Net → List Net
  | [] => []
  | x :: xs =>
    match _h : xs.dropWhile (fun y => hiA y = hiA x) with
    | [] => x :: xs.takeWhile (fun y => hiA y = hiA x)
    | y :: ys =>
      if hiA x &&& buddyBit p = 0 ∧ hiA y = hiA x ||| buddyBit p then
        if loListsEq (x :: xs.takeWhile (fun y => hiA y = hiA x))
            (y :: ys.takeWhile (fun z => hiA z = hiA y)) then
          (x :: xs.takeWhile (fun y => hiA y = hiA x)).map (reparent p) ++
            hiBuddyMerge p (ys.dropWhile (fun z => hiA z = hiA y))
        else (x :: xs.takeWhile (fun y => hiA y = hiA x)) ++ hiBuddyMerge p (y :: ys)
      else (x :: xs.takeWhile (fun y => hiA y = hiA x)) ++ hiBuddyMerge p (y :: ys)
termination_by l => l.length
decreasing_by
  all_goals
    have h1 := (List.dropWhile_sublist (l := xs) (fun y => decide (hiA y = hiA x))).length_le
    rw [_h] at h1
    simp only [List.length_cons] at h1 ⊢
  · have := (List.dropWhile_sublist (l := ys) (fun z => decide (hiA z = hiA y))).length_le
    omega
  · omega
  · omega

/-- One level of `bicontiguous_sweep`: the block of high-half prefix `p` is replaced
by its survivors, and when networks were re-parented, the native block of `p - 1`
and the survivors are sorted again. -/
def sweepLevel (p : Nat) (L : List Net) : List Net :=
  let pre := L.takeWhile (fun x => hiP x < p)
  let rest := L.dropWhile (fun x => hiP x < p)
  let blk := rest.takeWhile (fun x => hiP x ≤ p)
  let post := rest.dropWhile (fun x => hiP x ≤ p)
  let afterLo := loAggregate blk
  let surv := if p = 0 then afterLo else hiBuddyMerge p afterLo
  if surv.length < afterLo.length ∧ p ≠ 0 then
    pre.takeWhile (fun x => hiP x < p - 1) ++
      (pre.dropWhile (fun x => hiP x < p - 1) ++ surv).mergeSort levelLe ++ post
  else pre ++ surv ++ post

/-- The levels from `p` down to `0`. -/
def sweepFrom : Nat → List Net → List Net
  | 0, L => sweepLevel 0 L
  | p + 1, L => sweepFrom p (sweepLevel (p + 1) L)

/-- `bicontiguous_sweep`. -/
def sweep (L : List Net) : List Net :=
  if L.length ≤ 1 then L else sweepFrom 64 (L.mergeSort levelLe)

/-- The group of high-half prefix `q` and high address `H`. -/
def group (S : List Net) (q : Nat) (H : BitVec 64) : List Net :=
  S.filter fun x => hiP x = q ∧ hiA x = H

/-- The low-half shape `(lo address, lo prefix)`. -/
def loShape (x : Net) : BitVec 64 × Nat := (loA x, loP x)

/-- Two buddy groups at level `q` with the same low halves, which their parent at
level `q - 1` would cover exactly. -/
def MergeableAt (S : List Net) (q : Nat) (H : BitVec 64) : Prop :=
  1 ≤ q ∧ q ≤ 64 ∧ H &&& buddyBit q = 0 ∧ group S q H ≠ [] ∧ group S q (H ||| buddyBit q) ≠ [] ∧
    ((group S q H).map loShape).Perm ((group S q (H ||| buddyBit q)).map loShape)

/-! ## Prefixes and the level key -/

theorem contiguous64_eq_halfMask {m : BitVec 64} (h : IsContiguous m) :
    m = halfMask (~~~m).clz.toNat := by
  unfold IsContiguous at h
  unfold halfMask
  rw [← BitVec.ushiftRight_eq']
  bv_decide

theorem clz_not_le (m : BitVec 64) : (~~~m).clz.toNat ≤ 64 := by
  have h : (~~~m).clz ≤ 64#64 := by bv_decide
  rw [BitVec.le_def] at h
  simpa using h

theorem contiguous64_lt_iff {m1 m2 : BitVec 64} (h1 : IsContiguous m1) (h2 : IsContiguous m2) :
    m1.toNat < m2.toNat ↔ (~~~m1).clz.toNat < (~~~m2).clz.toNat := by
  rw [← BitVec.lt_def, ← BitVec.lt_def]
  unfold IsContiguous at h1 h2
  bv_decide

theorem hiM_contiguous {x : Net} (h : IsBiNet x) : IsContiguous (hiM x) :=
  ((isBiContiguous_iff x.2).mp h.1).1

theorem loM_contiguous {x : Net} (h : IsBiNet x) : IsContiguous (loM x) :=
  ((isBiContiguous_iff x.2).mp h.1).2

theorem hiM_eq {x : Net} (h : IsBiNet x) : hiM x = halfMask (hiP x) :=
  contiguous64_eq_halfMask (hiM_contiguous h)

theorem hiP_le (x : Net) : hiP x ≤ 64 := clz_not_le _

theorem hiM_lt_iff {x y : Net} (hx : IsBiNet x) (hy : IsBiNet y) :
    (hiM x).toNat < (hiM y).toNat ↔ hiP x < hiP y :=
  contiguous64_lt_iff (hiM_contiguous hx) (hiM_contiguous hy)

theorem sameHi_iff {x y : Net} (hx : IsBiNet x) (hy : IsBiNet y) :
    SameHi x y ↔ hiA x = hiA y ∧ hiP x = hiP y := by
  constructor
  · rintro ⟨ha, hm⟩
    exact ⟨ha, by unfold hiP; rw [hm]⟩
  · rintro ⟨ha, hp⟩
    exact ⟨ha, by rw [hiM_eq hx, hiM_eq hy, hp]⟩

theorem levelKey_lt_of_hiP {x y : Net} (hx : IsBiNet x) (hy : IsBiNet y) (h : hiP x < hiP y) :
    levelKey x < levelKey y := by
  have := (hiM_lt_iff hx hy).mpr h
  have := (hiA x).isLt
  have := (loA x).isLt
  have := (loM x).isLt
  unfold levelKey
  omega

theorem hiP_le_of_levelLe {x y : Net} (hx : IsBiNet x) (hy : IsBiNet y) (h : levelLe x y = true) :
    hiP x ≤ hiP y := by
  apply Classical.byContradiction
  intro hlt
  have := levelKey_lt_of_hiP hy hx (by omega)
  simp only [levelLe, decide_eq_true_eq] at h
  omega

theorem levelKey_lt_of_hiA {x y : Net} (hm : hiM x = hiM y) (h : (hiA x).toNat < (hiA y).toNat) :
    levelKey x < levelKey y := by
  have := (loA x).isLt
  have := (loM x).isLt
  unfold levelKey
  rw [hm]
  omega

theorem hiA_le_of_levelLe {x y : Net} (hm : hiM x = hiM y) (h : levelLe x y = true) :
    (hiA x).toNat ≤ (hiA y).toNat := by
  apply Classical.byContradiction
  intro hlt
  have := levelKey_lt_of_hiA hm.symm (by omega)
  simp only [levelLe, decide_eq_true_eq] at h
  omega

theorem levelKey_lt_of_loA {x y : Net} (hs : SameHi x y) (h : (loA x).toNat < (loA y).toNat) :
    levelKey x < levelKey y := by
  have := (loM x).isLt
  unfold levelKey
  rw [hs.1, hs.2]
  omega

theorem loA_le_of_levelLe {x y : Net} (hs : SameHi x y) (h : levelLe x y = true) :
    (loA x).toNat ≤ (loA y).toNat := by
  apply Classical.byContradiction
  intro hlt
  have := levelKey_lt_of_loA (sameHi_symm hs) (by omega)
  simp only [levelLe, decide_eq_true_eq] at h
  omega

/-- The level key orders networks totally, and only equal networks share a key. -/
theorem levelKey_inj {x y : Net} (h : levelKey x = levelKey y) : x = y := by
  have h1 := (hiA x).isLt
  have h2 := (loA x).isLt
  have h3 := (loM x).isLt
  have h4 := (hiA y).isLt
  have h5 := (loA y).isLt
  have h6 := (loM y).isLt
  have h7 := (hiM x).isLt
  have h8 := (hiM y).isLt
  unfold levelKey at h
  have ehm : (hiM x).toNat = (hiM y).toNat := by omega
  have eha : (hiA x).toNat = (hiA y).toNat := by omega
  have ela : (loA x).toNat = (loA y).toNat := by omega
  have elm : (loM x).toNat = (loM y).toNat := by omega
  obtain ⟨x1, x2⟩ := x
  obtain ⟨y1, y2⟩ := y
  simp only [hiM, hiA, loA, loM, hi, lo] at ehm eha ela elm
  have a1 := BitVec.eq_of_toNat_eq ehm
  have a2 := BitVec.eq_of_toNat_eq eha
  have a3 := BitVec.eq_of_toNat_eq ela
  have a4 := BitVec.eq_of_toNat_eq elm
  simp only [Prod.mk.injEq]
  constructor <;> bv_decide

theorem levelLe_trans (x y z : Net) (h1 : levelLe x y = true) (h2 : levelLe y z = true) :
    levelLe x z = true := by
  simp only [levelLe, decide_eq_true_eq] at *
  omega

theorem levelLe_total (x y : Net) : (levelLe x y || levelLe y x) = true := by
  simp only [levelLe, Bool.or_eq_true, decide_eq_true_eq]
  omega

theorem sorted_mergeSort (l : List Net) : (l.mergeSort levelLe).Pairwise (fun x y => levelLe x y = true) :=
  List.pairwise_mergeSort levelLe_trans levelLe_total l

/-! ## Taking and dropping on sorted lists -/

theorem takeWhile_eq_filter {α : Type} {P : α → Bool} :
    ∀ {l : List α}, l.Pairwise (fun x y => P y = true → P x = true) → l.takeWhile P = l.filter P
  | [], _ => rfl
  | x :: xs, h => by
    rw [List.pairwise_cons] at h
    cases hx : P x
    · rw [List.takeWhile_cons_of_neg (by simp [hx]), List.filter_cons_of_neg (by simp [hx])]
      symm
      rw [List.filter_eq_nil_iff]
      intro y hy hPy
      have := h.1 y hy hPy
      simp [hx] at this
    · rw [List.takeWhile_cons_of_pos hx, List.filter_cons_of_pos hx, takeWhile_eq_filter h.2]

theorem dropWhile_eq_filter {α : Type} {P : α → Bool} :
    ∀ {l : List α}, l.Pairwise (fun x y => P y = true → P x = true) →
      l.dropWhile P = l.filter (fun x => !P x)
  | [], _ => rfl
  | x :: xs, h => by
    rw [List.pairwise_cons] at h
    cases hx : P x
    · rw [List.dropWhile_cons_of_neg (by simp [hx]), List.filter_cons_of_pos (by simp [hx])]
      congr 1
      symm
      rw [List.filter_eq_self]
      intro y hy
      have : P y = false := by
        cases hy' : P y
        · rfl
        · have := h.1 y hy hy'
          simp [hx] at this
      simp [this]
    · rw [List.dropWhile_cons_of_pos hx, List.filter_cons_of_neg (by simp [hx]), dropWhile_eq_filter h.2]

/-- In a list sorted by prefix, the levels below, at and above `p` are consecutive. -/
theorem level_split {L : List Net} (p : Nat) (hs : L.Pairwise fun x y => hiP x ≤ hiP y) :
    L.takeWhile (fun x => hiP x < p) = L.filter (fun x => hiP x < p) ∧
      (L.dropWhile (fun x => hiP x < p)).takeWhile (fun x => hiP x ≤ p) =
        L.filter (fun x => hiP x = p) ∧
      (L.dropWhile (fun x => hiP x < p)).dropWhile (fun x => hiP x ≤ p) =
        L.filter (fun x => p < hiP x) := by
  have h1 : L.Pairwise fun x y => decide (hiP y < p) = true → decide (hiP x < p) = true :=
    hs.imp fun h hy => by simp at hy ⊢; omega
  rw [dropWhile_eq_filter h1]
  have hs' : (L.filter fun x => !decide (hiP x < p)).Pairwise
      fun x y => decide (hiP y ≤ p) = true → decide (hiP x ≤ p) = true :=
    (hs.filter _).imp fun h hy => by simp at hy ⊢; omega
  refine ⟨takeWhile_eq_filter h1, ?_, ?_⟩
  · rw [takeWhile_eq_filter hs', List.filter_filter]
    apply List.filter_congr
    intro x _
    apply Bool.eq_iff_iff.mpr
    simp only [Bool.and_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true, decide_eq_false_iff_not,
      decide_eq_true_eq, Nat.not_lt]
    omega
  · rw [dropWhile_eq_filter hs', List.filter_filter]
    apply List.filter_congr
    intro x _
    apply Bool.eq_iff_iff.mpr
    simp only [Bool.and_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true, decide_eq_false_iff_not,
      decide_eq_true_eq, Nat.not_le, Nat.not_lt]
    omega

/-! ## Phase A: the stack pass over every group -/

theorem push_length {w : Nat} (c : Block w) : ∀ st : List (Block w), (push c st).length ≤ st.length + 1
  | [] => by simp [push]
  | t :: rest => by
    simp only [push]
    split
    · rename_i m _
      have := push_length m rest
      simp only [List.length_cons]
      omega
    · simp

theorem aggregate_length {w : Nat} (L : List (Block w)) : (aggregate L).length ≤ L.length := by
  have : ∀ (L st : List (Block w)), (L.foldl (fun st b => push b st) st).length ≤ st.length + L.length := by
    intro L
    induction L with
    | nil => intro st; simp
    | cons c L ih =>
      intro st
      have h1 := ih (push c st)
      have h2 := push_length c st
      simp only [List.foldl_cons, List.length_cons]
      omega
  unfold aggregate
  rw [List.length_reverse]
  simpa using this L []

theorem mem_takeWhile_pred {α : Type} {P : α → Bool} {l : List α} {y : α} (hy : y ∈ l.takeWhile P) :
    P y = true :=
  List.all_eq_true.mp List.all_takeWhile y hy

/-- In a list sorted by high address, the networks sharing the first one's high address
come first. -/
theorem sameHiA_first {x : Net} {xs : List Net}
    (hs : (x :: xs).Pairwise fun a b => (hiA a).toNat ≤ (hiA b).toNat) :
    xs.Pairwise fun a b => decide (hiA b = hiA x) = true → decide (hiA a = hiA x) = true := by
  rw [List.pairwise_cons] at hs
  refine (hs.2.imp_of_mem fun {a b} ha _ hab hb => ?_)
  simp only [decide_eq_true_eq] at hb ⊢
  have h1 := hs.1 a ha
  have h2 : (hiA a).toNat ≤ (hiA x).toNat := by rw [← hb]; exact hab
  exact BitVec.eq_of_toNat_eq (by omega)

theorem hiRuns_cons (x : Net) (xs : List Net) :
    hiRuns (x :: xs) = (x :: xs.takeWhile (fun y => hiA y = hiA x)) ::
      hiRuns (xs.dropWhile (fun y => hiA y = hiA x)) := by
  rw [hiRuns]

theorem hiRuns_flatten : ∀ (l : List Net), (hiRuns l).flatten = l
  | [] => by simp [hiRuns]
  | x :: xs => by
    rw [hiRuns_cons, List.flatten_cons, hiRuns_flatten, List.cons_append,
      List.takeWhile_append_dropWhile]
termination_by l => l.length
decreasing_by
  have := (List.dropWhile_sublist (l := xs) (fun y => decide (hiA y = hiA x))).length_le
  simp only [List.length_cons]
  omega

/-- Every run is nonempty and has one high address. -/
theorem hiRuns_run : ∀ (l : List Net), ∀ r ∈ hiRuns l, ∃ x xs, r = x :: xs ∧ ∀ y ∈ r, hiA y = hiA x
  | [] => by simp [hiRuns]
  | x :: xs => by
    intro r hr
    rw [hiRuns_cons, List.mem_cons] at hr
    rcases hr with rfl | hr
    · refine ⟨x, _, rfl, fun y hy => ?_⟩
      rcases List.mem_cons.mp hy with rfl | hy
      · rfl
      · simpa using mem_takeWhile_pred hy
    · exact hiRuns_run _ r hr
termination_by l => l.length
decreasing_by
  have := (List.dropWhile_sublist (l := xs) (fun y => decide (hiA y = hiA x))).length_le
  simp only [List.length_cons]
  omega

/-- In a list sorted by high address, the runs have strictly increasing high addresses. -/
theorem hiRuns_sorted : ∀ (l : List Net), l.Pairwise (fun a b => (hiA a).toNat ≤ (hiA b).toNat) →
    (hiRuns l).Pairwise fun r s => ∀ a ∈ r, ∀ b ∈ s, (hiA a).toNat < (hiA b).toNat
  | [] => by simp [hiRuns]
  | x :: xs => by
    intro hs
    rw [hiRuns_cons, List.pairwise_cons]
    have hfirst := sameHiA_first hs
    rw [List.pairwise_cons] at hs
    have hdrop : ∀ b ∈ xs.dropWhile (fun y => hiA y = hiA x), (hiA x).toNat < (hiA b).toNat := by
      intro b hb
      rw [dropWhile_eq_filter hfirst, List.mem_filter] at hb
      have h1 := hs.1 b hb.1
      have h2 : hiA b ≠ hiA x := by simpa using hb.2
      have : (hiA b).toNat ≠ (hiA x).toNat := fun h => h2 (BitVec.eq_of_toNat_eq h)
      omega
    refine ⟨fun s hsr a ha b hb => ?_, hiRuns_sorted _ (hs.2.sublist (List.dropWhile_sublist _))⟩
    have hb' : b ∈ xs.dropWhile (fun y => hiA y = hiA x) := by
      rw [← hiRuns_flatten (xs.dropWhile _)]
      exact List.mem_flatten.mpr ⟨s, hsr, hb⟩
    have hax : hiA a = hiA x := by
      rcases List.mem_cons.mp ha with rfl | ha
      · rfl
      · simpa using mem_takeWhile_pred ha
    rw [hax]
    exact hdrop b hb'
termination_by l => l.length
decreasing_by
  have := (List.dropWhile_sublist (l := xs) (fun y => decide (hiA y = hiA x))).length_le
  simp only [List.length_cons]
  omega

/-- Canonical groups: no two networks of one group whose low halves meet or are buddies. -/
def GroupsCanon (S : List Net) : Prop :=
  S.Pairwise fun x y => SameHi x y → ¬ Meets x y ∧ ¬ Buddies x y

theorem hiP_eq_of_sameHi {x y : Net} (h : SameHi x y) : hiP x = hiP y := by
  unfold hiP
  rw [h.2]

theorem hiM_eq_of_level {x y : Net} (hx : IsBiNet x) (hy : IsBiNet y) (h : hiP x = hiP y) :
    hiM x = hiM y := by
  rw [hiM_eq hx, hiM_eq hy, h]

theorem runs_aggregate_spec {p : Nat} : ∀ (R : List (List Net)),
    (∀ r ∈ R, ∃ x xs, r = x :: xs ∧ (∀ y ∈ r, InGroup x y ∧ hiP y = p) ∧
      r.Pairwise (fun a b => loA a ≤ loA b)) →
    R.Pairwise (fun r s => ∀ a ∈ r, ∀ b ∈ s, (hiA a).toNat < (hiA b).toNat) →
    (∀ z ∈ R.flatMap aggregate, IsBiNet z ∧ hiP z = p ∧ ∃ x ∈ R.flatten, SameHi z x) ∧
      (∀ X, (∃ z ∈ R.flatMap aggregate, Mem X z) ↔ ∃ x ∈ R.flatten, Mem X x) ∧
      GroupsCanon (R.flatMap aggregate) ∧
      (R.flatMap aggregate).Pairwise (fun x y => levelKey x < levelKey y) ∧
      (R.flatMap aggregate).length ≤ R.flatten.length := by
  intro R
  induction R with
  | nil => intro _ _; simp [GroupsCanon]
  | cons r R ih =>
    intro hR hpw
    rw [List.pairwise_cons] at hpw
    obtain ⟨x, xs, rfl, hgrp, hsort⟩ := hR _ List.mem_cons_self
    obtain ⟨g1, g2, g3⟩ := groupAggregate_spec (x :: xs) (fun y hy => (hgrp y hy).1) hsort
    obtain ⟨i1, i2, i3, i4, i5⟩ := ih (fun r hr => hR r (List.mem_cons_of_mem _ hr)) hpw.2
    have hxp : hiP x = p := (hgrp x List.mem_cons_self).2
    have hxbi : IsBiNet x := (hgrp x List.mem_cons_self).1.1
    -- every network after this group has a larger high address
    have hlater : ∀ b ∈ R.flatMap aggregate, (hiA x).toNat < (hiA b).toNat := by
      intro b hb
      obtain ⟨-, -, y, hy, hby⟩ := i1 b hb
      obtain ⟨s, hs, hys⟩ := List.mem_flatten.mp hy
      rw [hby.1]
      exact hpw.1 s hs x List.mem_cons_self y hys
    simp only [List.flatMap_cons, List.flatten_cons]
    refine ⟨fun z hz => ?_, fun X => ?_, ?_, ?_, ?_⟩
    · rcases List.mem_append.mp hz with hz | hz
      · have hzg := g1 z hz
        exact ⟨hzg.1, by rw [hiP_eq_of_sameHi hzg.2, hxp], x, List.mem_append_left _ List.mem_cons_self,
          hzg.2⟩
      · obtain ⟨h1, h2, y, hy, h3⟩ := i1 z hz
        exact ⟨h1, h2, y, List.mem_append_right _ hy, h3⟩
    · simp only [List.mem_append]
      constructor
      · rintro ⟨z, hz | hz, hX⟩
        · obtain ⟨y, hy, hXy⟩ := (g3 X).mp ⟨z, hz, hX⟩
          exact ⟨y, Or.inl hy, hXy⟩
        · obtain ⟨y, hy, hXy⟩ := (i2 X).mp ⟨z, hz, hX⟩
          exact ⟨y, Or.inr hy, hXy⟩
      · rintro ⟨y, hy | hy, hX⟩
        · obtain ⟨z, hz, hXz⟩ := (g3 X).mpr ⟨y, hy, hX⟩
          exact ⟨z, Or.inl hz, hXz⟩
        · obtain ⟨z, hz, hXz⟩ := (i2 X).mpr ⟨y, hy, hX⟩
          exact ⟨z, Or.inr hz, hXz⟩
    · unfold GroupsCanon
      rw [List.pairwise_append]
      refine ⟨g2.imp fun h _ => ⟨h.2.1, h.2.2⟩, i3, fun a ha b hb hab => ?_⟩
      have := hlater b hb
      rw [← (g1 a ha).2.1, hab.1] at this
      omega
    · rw [List.pairwise_append]
      refine ⟨g2.imp_of_mem fun {a b} ha hb h => ?_, i4, fun a ha b hb => ?_⟩
      · exact levelKey_lt_of_loA (sameHi_trans (g1 a ha).2 (sameHi_symm (g1 b hb).2)) h.1
      · have hag := g1 a ha
        obtain ⟨hbbi, hbp, -⟩ := i1 b hb
        apply levelKey_lt_of_hiA
        · exact hiM_eq_of_level hag.1 hbbi (by rw [hiP_eq_of_sameHi hag.2, hxp, hbp])
        · rw [hag.2.1]
          exact hlater b hb
    · have := aggregate_length (x :: xs)
      simp only [List.length_append]
      omega

/-- Phase A over a sorted block of level `p`: the union is kept, the results are
normalized bi-contiguous networks of the block's groups, the groups become
canonical, and the block stays sorted. -/
theorem loAggregate_spec {blk : List Net} {p : Nat} (hbi : ∀ x ∈ blk, IsBiNet x)
    (hlev : ∀ x ∈ blk, hiP x = p) (hs : blk.Pairwise fun x y => levelLe x y = true) :
    (∀ z ∈ loAggregate blk, IsBiNet z ∧ hiP z = p ∧ ∃ x ∈ blk, SameHi z x) ∧
      (∀ X, (∃ z ∈ loAggregate blk, Mem X z) ↔ ∃ x ∈ blk, Mem X x) ∧
      GroupsCanon (loAggregate blk) ∧
      (loAggregate blk).Pairwise (fun x y => levelKey x < levelKey y) ∧
      (loAggregate blk).length ≤ blk.length := by
  have hflat := hiRuns_flatten blk
  have hsortA : blk.Pairwise fun a b => (hiA a).toNat ≤ (hiA b).toNat :=
    hs.imp_of_mem fun {a b} ha hb h =>
      hiA_le_of_levelLe (hiM_eq_of_level (hbi a ha) (hbi b hb) (by rw [hlev a ha, hlev b hb])) h
  have hrun : ∀ r ∈ hiRuns blk, ∃ x xs, r = x :: xs ∧ (∀ y ∈ r, InGroup x y ∧ hiP y = p) ∧
      r.Pairwise (fun a b => loA a ≤ loA b) := by
    intro r hr
    have hsub : r.Sublist blk := by
      rw [← hflat]
      exact List.sublist_flatten_of_mem hr
    obtain ⟨x, xs, rfl, hsame⟩ := hiRuns_run blk _ hr
    have hxin : x ∈ blk := hsub.subset List.mem_cons_self
    have hgrp : ∀ y ∈ x :: xs, InGroup x y ∧ hiP y = p := by
      intro y hy
      have hyin := hsub.subset hy
      exact ⟨⟨hbi y hyin, (sameHi_iff (hbi y hyin) (hbi x hxin)).mpr
        ⟨hsame y hy, by rw [hlev y hyin, hlev x hxin]⟩⟩, hlev y hyin⟩
    refine ⟨x, xs, rfl, hgrp, (hs.sublist hsub).imp_of_mem fun {a b} ha hb h => ?_⟩
    rw [BitVec.le_def]
    exact loA_le_of_levelLe (sameHi_trans (hgrp a ha).1.2 (sameHi_symm (hgrp b hb).1.2)) h
  have := runs_aggregate_spec (p := p) (hiRuns blk) hrun (hiRuns_sorted blk hsortA)
  rw [hflat] at this
  exact this

/-! ## Phase B: merging buddy groups -/

/-- The network with the buddy bit set in the high half of the address. -/
def buddyNet (p : Nat) (x : Net) : Net := (x.1 ||| ((buddyBit p).setWidth 128 <<< 64), x.2)

theorem halfMask_eq (k : Nat) (hk : k ≤ 64) :
    halfMask k = ~~~(BitVec.allOnes 64 >>> BitVec.ofNat 64 k) := by
  unfold halfMask
  rw [BitVec.ushiftRight_eq', BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega)]

theorem buddyBit_eq (p : Nat) (hp : p ≤ 64) : buddyBit p = 1#64 <<< BitVec.ofNat 64 (64 - p) := by
  unfold buddyBit
  rw [BitVec.shiftLeft_eq', BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega)]

/-- The bit facts of re-parenting, with the prefix as a bit vector. -/
theorem reparent_spec_bv (x1 x2 X : BitVec 128) (P : BitVec 64) (h1 : 1#64 ≤ P) (h64 : P ≤ 64#64)
    (hbi : IsBiContiguous x2) (hn : x1 &&& x2 = x1) (hm : hi x2 = ~~~(BitVec.allOnes 64 >>> P))
    (hb : hi x1 &&& (1#64 <<< (64#64 - P)) = 0) :
    let m := (x2 &&& (BitVec.allOnes 64).setWidth 128) |||
      ((~~~(BitVec.allOnes 64 >>> (P - 1#64))).setWidth 128 <<< 64)
    IsBiContiguous m ∧ (x1 &&& m) &&& m = x1 &&& m ∧ hi m = ~~~(BitVec.allOnes 64 >>> (P - 1#64)) ∧
      hi (x1 &&& m) = hi x1 ∧ lo (x1 &&& m) = lo x1 ∧ lo m = lo x2 ∧
      (X &&& m = x1 &&& m ↔
        (X &&& x2 = x1 ∨ X &&& x2 = x1 ||| ((1#64 <<< (64#64 - P)).setWidth 128 <<< 64))) := by
  intro m
  unfold IsBiContiguous at hbi ⊢
  unfold hi lo at *
  bv_decide

theorem toNat_ofNat_64 {k : Nat} (hk : k ≤ 64) : (BitVec.ofNat 64 k).toNat = k := by
  rw [BitVec.toNat_ofNat]
  exact Nat.mod_eq_of_lt (by omega)

theorem ofNat_sub_64 {p : Nat} (hp : p ≤ 64) :
    BitVec.ofNat 64 (64 - p) = 64#64 - BitVec.ofNat 64 p := by
  apply BitVec.eq_of_toNat_eq
  rw [BitVec.toNat_ofNat, BitVec.toNat_sub, BitVec.toNat_ofNat, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt (show 64 - p < 2 ^ 64 by omega), Nat.mod_eq_of_lt (show p < 2 ^ 64 by omega)]
  simp only [show (64 : Nat) % 2 ^ 64 = 64 from rfl]
  omega

theorem ofNat_pred_64 {p : Nat} (hp1 : 1 ≤ p) (hp : p ≤ 64) :
    BitVec.ofNat 64 (p - 1) = BitVec.ofNat 64 p - 1#64 := by
  apply BitVec.eq_of_toNat_eq
  have h1 : (BitVec.ofNat 64 (p - 1)).toNat = p - 1 := by
    rw [BitVec.toNat_ofNat]
    exact Nat.mod_eq_of_lt (by omega)
  have h2 : (BitVec.ofNat 64 p).toNat = p := by
    rw [BitVec.toNat_ofNat]
    exact Nat.mod_eq_of_lt (by omega)
  rw [h1, BitVec.toNat_sub, h2, show (1#64).toNat = 1 from rfl]
  omega

theorem clz_halfMask (k : Nat) (hk : k ≤ 64) : (~~~(halfMask k)).clz.toNat = k := by
  rw [halfMask_eq k hk]
  have h : (~~~~~~(BitVec.allOnes 64 >>> BitVec.ofNat 64 k)).clz = BitVec.ofNat 64 k := by
    have hle : BitVec.ofNat 64 k ≤ 64#64 := by
      rw [BitVec.le_def, BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega)]
      simp only [show (64#64).toNat = 64 from rfl]
      omega
    bv_decide
  rw [h, BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega)]

/-- Re-parenting a network whose buddy bit is clear: it moves to level `p - 1` with the
same addresses and low mask, and covers exactly itself and its high-half buddy. -/
theorem reparent_spec {p : Nat} (hp1 : 1 ≤ p) (hp : p ≤ 64) {x : Net} (hx : IsBiNet x)
    (hxp : hiP x = p) (hb : hiA x &&& buddyBit p = 0) :
    IsBiNet (reparent p x) ∧ hiP (reparent p x) = p - 1 ∧ hiA (reparent p x) = hiA x ∧
      loA (reparent p x) = loA x ∧ loM (reparent p x) = loM x ∧
      ∀ X, Mem X (reparent p x) ↔ Mem X x ∨ Mem X (buddyNet p x) := by
  obtain ⟨x1, x2⟩ := x
  have hm : hi x2 = ~~~(BitVec.allOnes 64 >>> BitVec.ofNat 64 p) := by
    have := hiM_eq hx
    rw [hxp, halfMask_eq p hp] at this
    exact this
  have hP1 : 1#64 ≤ BitVec.ofNat 64 p := by
    rw [BitVec.le_def, toNat_ofNat_64 (show 1 ≤ 64 by omega), toNat_ofNat_64 hp]
    omega
  have hP64 : BitVec.ofNat 64 p ≤ 64#64 := by
    rw [BitVec.le_def, toNat_ofNat_64 hp, toNat_ofNat_64 (show 64 ≤ 64 by omega)]
    omega
  rw [buddyBit_eq p hp, ofNat_sub_64 hp] at hb
  have key := reparent_spec_bv x1 x2 0 (BitVec.ofNat 64 p) hP1 hP64 hx.1 hx.2 hm hb
  have hrep : reparent p (x1, x2) = (x1 &&& ((x2 &&& (BitVec.allOnes 64).setWidth 128) |||
      ((~~~(BitVec.allOnes 64 >>> (BitVec.ofNat 64 p - 1#64))).setWidth 128 <<< 64)),
      (x2 &&& (BitVec.allOnes 64).setWidth 128) |||
      ((~~~(BitVec.allOnes 64 >>> (BitVec.ofNat 64 p - 1#64))).setWidth 128 <<< 64)) := by
    simp only [reparent]
    rw [halfMask_eq (p - 1) (by omega), ofNat_pred_64 hp1 hp]
  obtain ⟨k1, k2, k3, k4, k5, k6, -⟩ := key
  refine ⟨?_, ?_, ?_, ?_, ?_, fun X => ?_⟩
  · rw [hrep]
    exact ⟨k1, k2⟩
  · unfold hiP hiM
    rw [hrep, k3, ← ofNat_pred_64 hp1 hp, ← halfMask_eq (p - 1) (by omega), clz_halfMask (p - 1) (by omega)]
  · unfold hiA
    rw [hrep]
    exact k4
  · unfold loA
    rw [hrep]
    exact k5
  · unfold loM
    rw [hrep]
    exact k6
  · have := (reparent_spec_bv x1 x2 X (BitVec.ofNat 64 p) hP1 hP64 hx.1 hx.2 hm hb).2.2.2.2.2.2
    rw [hrep]
    simp only [Mem, buddyNet]
    rw [buddyBit_eq p hp, ofNat_sub_64 hp]
    exact this

theorem hiBuddyMerge_eq_last {p : Nat} {x : Net} {xs : List Net}
    (h : xs.dropWhile (fun y => hiA y = hiA x) = []) :
    hiBuddyMerge p (x :: xs) = x :: xs.takeWhile (fun y => hiA y = hiA x) := by
  rw [hiBuddyMerge]
  split
  · rfl
  · rename_i y ys h'
    rw [h] at h'
    simp at h'

theorem hiBuddyMerge_eq_step {p : Nat} {x y : Net} {xs ys : List Net}
    (h : xs.dropWhile (fun y => hiA y = hiA x) = y :: ys) :
    hiBuddyMerge p (x :: xs) =
      if hiA x &&& buddyBit p = 0 ∧ hiA y = hiA x ||| buddyBit p then
        if loListsEq (x :: xs.takeWhile (fun y => hiA y = hiA x))
            (y :: ys.takeWhile (fun z => hiA z = hiA y)) then
          (x :: xs.takeWhile (fun y => hiA y = hiA x)).map (reparent p) ++
            hiBuddyMerge p (ys.dropWhile (fun z => hiA z = hiA y))
        else (x :: xs.takeWhile (fun y => hiA y = hiA x)) ++ hiBuddyMerge p (y :: ys)
      else (x :: xs.takeWhile (fun y => hiA y = hiA x)) ++ hiBuddyMerge p (y :: ys) := by
  rw [hiBuddyMerge]
  split
  · rename_i h'
    rw [h] at h'
    simp at h'
  · rename_i y' ys' h'
    rw [h] at h'
    simp only [List.cons.injEq] at h'
    obtain ⟨rfl, rfl⟩ := h'
    rfl

/-- What Phase B gets from Phase A at level `p`: normalized bi-contiguous networks of
level `p` in canonical groups, sorted strictly. -/
def BlockInv (p : Nat) (l : List Net) : Prop :=
  (∀ x ∈ l, IsBiNet x ∧ hiP x = p) ∧ GroupsCanon l ∧
    l.Pairwise (fun x y => levelKey x < levelKey y)

theorem BlockInv.sublist {p : Nat} {l l' : List Net} (h : BlockInv p l) (hs : l'.Sublist l) :
    BlockInv p l' :=
  ⟨fun x hx => h.1 x (hs.subset hx), h.2.1.sublist hs, h.2.2.sublist hs⟩

theorem BlockInv.hiA_sorted {p : Nat} {l : List Net} (h : BlockInv p l) :
    l.Pairwise (fun a b => (hiA a).toNat ≤ (hiA b).toNat) :=
  h.2.2.imp_of_mem fun {a b} ha hb hab =>
    hiA_le_of_levelLe (hiM_eq_of_level (h.1 a ha).1 (h.1 b hb).1 (by rw [(h.1 a ha).2, (h.1 b hb).2]))
      (by simp only [levelLe, decide_eq_true_eq]; omega)

/-- The first group of a block, and the rest above it. -/
theorem block_head {p : Nat} {x : Net} {xs : List Net} (h : BlockInv p (x :: xs)) :
    xs.takeWhile (fun y => hiA y = hiA x) = xs.filter (fun y => hiA y = hiA x) ∧
      (∀ z ∈ xs.dropWhile (fun y => hiA y = hiA x), (hiA x).toNat < (hiA z).toNat) := by
  have hs := h.hiA_sorted
  have hfirst := sameHiA_first hs
  rw [List.pairwise_cons] at hs
  refine ⟨takeWhile_eq_filter hfirst, fun z hz => ?_⟩
  rw [dropWhile_eq_filter hfirst, List.mem_filter] at hz
  have h1 := hs.1 z hz.1
  have h2 : hiA z ≠ hiA x := by simpa using hz.2
  have : (hiA z).toNat ≠ (hiA x).toNat := fun h => h2 (BitVec.eq_of_toNat_eq h)
  omega

theorem group_append (A B : List Net) (q : Nat) (H : BitVec 64) :
    group (A ++ B) q H = group A q H ++ group B q H := List.filter_append _ _

theorem group_eq_nil {S : List Net} {q : Nat} {H : BitVec 64} (h : ∀ z ∈ S, hiP z = q → hiA z ≠ H) :
    group S q H = [] := by
  unfold group
  rw [List.filter_eq_nil_iff]
  intro z hz hzq
  simp only [decide_eq_true_eq] at hzq
  exact h z hz hzq.1 hzq.2

theorem group_eq_self {S : List Net} {q : Nat} {H : BitVec 64} (h : ∀ z ∈ S, hiP z = q ∧ hiA z = H) :
    group S q H = S := by
  unfold group
  rw [List.filter_eq_self]
  intro z hz
  simpa using h z hz

theorem loListsEq_iff : ∀ (A B : List Net), loListsEq A B = true ↔ A.map loShape = B.map loShape
  | [], [] => by simp [loListsEq]
  | [], b :: B => by simp [loListsEq]
  | a :: A, [] => by simp [loListsEq]
  | a :: A, b :: B => by
    have ih := loListsEq_iff A B
    simp only [loListsEq, List.length_cons, List.zip_cons_cons, List.all_cons, Bool.and_eq_true,
      beq_iff_eq, List.map_cons, List.cons.injEq, loShape, Prod.mk.injEq] at ih ⊢
    constructor
    · rintro ⟨hl, ⟨h1, h2⟩, h3⟩
      exact ⟨⟨h1, h2⟩, ih.mp ⟨by omega, h3⟩⟩
    · rintro ⟨⟨h1, h2⟩, h3⟩
      obtain ⟨hl, h4⟩ := ih.mpr h3
      exact ⟨by omega, ⟨h1, h2⟩, h4⟩

theorem meets_of_loA_eq {x y : Net} (hx : x.1 &&& x.2 = x.1) (hy : y.1 &&& y.2 = y.1)
    (hs : SameHi x y) (h : loA x = loA y) : Meets x y := by
  obtain ⟨x1, x2⟩ := x
  obtain ⟨y1, y2⟩ := y
  obtain ⟨ha, hm⟩ := hs
  simp only [hiA, hiM, loA, hi, lo] at ha hm h hx hy
  simp only [Meets]
  bv_decide

/-- A canonical group sorted by level key has strictly increasing low addresses. -/
theorem group_shapes_sorted {G : List Net} (hbi : ∀ a ∈ G, IsBiNet a) (hcanon : GroupsCanon G)
    (hs : G.Pairwise fun x y => levelKey x < levelKey y) (hsame : ∀ a ∈ G, ∀ b ∈ G, SameHi a b) :
    (G.map loShape).Pairwise (fun s t => s.1.toNat < t.1.toNat) := by
  rw [List.pairwise_map]
  have hboth := hs.and hcanon
  refine hboth.imp_of_mem fun {a b} ha hb h => ?_
  have hab := hsame a ha b hb
  have hle := loA_le_of_levelLe hab (by simp only [levelLe, decide_eq_true_eq]; omega)
  have hne : loA a ≠ loA b := fun he => (h.2 hab).1 (meets_of_loA_eq (hbi a ha).2 (hbi b hb).2 hab he)
  have : (loA a).toNat ≠ (loA b).toNat := fun he => hne (BitVec.eq_of_toNat_eq he)
  show (loA a).toNat < (loA b).toNat
  omega

theorem eq_of_perm_shapes {G1 G2 : List Net}
    (h1 : (G1.map loShape).Pairwise (fun s t => s.1.toNat < t.1.toNat))
    (h2 : (G2.map loShape).Pairwise (fun s t => s.1.toNat < t.1.toNat))
    (hp : (G1.map loShape).Perm (G2.map loShape)) : G1.map loShape = G2.map loShape :=
  hp.eq_of_pairwise (fun _ _ _ _ hab hba => absurd (Nat.lt_trans hab hba) (Nat.lt_irrefl _)) h1 h2

theorem net_eq_of_halves {x y : Net} (h1 : hiA x = hiA y) (h2 : loA x = loA y) (h3 : hiM x = hiM y)
    (h4 : loM x = loM y) : x = y := by
  obtain ⟨x1, x2⟩ := x
  obtain ⟨y1, y2⟩ := y
  simp only [hiA, loA, hiM, loM, hi, lo] at h1 h2 h3 h4
  simp only [Prod.mk.injEq]
  constructor <;> bv_decide

theorem buddyNet_halves {p : Nat} (x : Net) (hb : hiA x &&& buddyBit p = 0) :
    hiA (buddyNet p x) = hiA x ||| buddyBit p ∧ loA (buddyNet p x) = loA x ∧
      hiM (buddyNet p x) = hiM x ∧ loM (buddyNet p x) = loM x := by
  obtain ⟨x1, x2⟩ := x
  refine ⟨?_, ?_, rfl, rfl⟩
  · simp only [buddyNet, hiA, hi] at hb ⊢
    generalize buddyBit p = b at hb ⊢
    bv_decide
  · simp only [buddyNet, loA, lo]
    generalize buddyBit p = b
    bv_decide

theorem loM_eq {x : Net} (h : IsBiNet x) : loM x = halfMask (loP x) :=
  contiguous64_eq_halfMask (loM_contiguous h)

/-- A buddy group with the same low halves is the group shifted by the buddy bit. -/
theorem buddy_group_eq {p : Nat} {H : BitVec 64} (hH : H &&& buddyBit p = 0) :
    ∀ (A B : List Net), (∀ a ∈ A, IsBiNet a ∧ hiP a = p ∧ hiA a = H) →
      (∀ b ∈ B, IsBiNet b ∧ hiP b = p ∧ hiA b = H ||| buddyBit p) →
      A.map loShape = B.map loShape → B = A.map (buddyNet p)
  | [], [], _, _, _ => rfl
  | [], b :: B, _, _, h => by simp at h
  | a :: A, [], _, _, h => by simp at h
  | a :: A, b :: B, hA, hB, h => by
    simp only [List.map_cons, List.cons.injEq, loShape, Prod.mk.injEq] at h
    obtain ⟨⟨hl1, hl2⟩, hrest⟩ := h
    have ha := hA a List.mem_cons_self
    have hb := hB b List.mem_cons_self
    rw [List.map_cons, buddy_group_eq hH A B (fun a h => hA a (List.mem_cons_of_mem _ h))
      (fun b h => hB b (List.mem_cons_of_mem _ h)) hrest]
    congr 1
    obtain ⟨e1, e2, e3, e4⟩ := buddyNet_halves (p := p) a (by rw [ha.2.2]; exact hH)
    apply net_eq_of_halves
    · rw [e1, hb.2.2, ha.2.2]
    · rw [e2, hl1]
    · rw [e3, hiM_eq_of_level hb.1 ha.1 (by rw [hb.2.1, ha.2.1])]
    · rw [e4, loM_eq hb.1, loM_eq ha.1, hl2]

/-- Re-parenting a group covers the group and its buddy group. -/
theorem reparent_union {p : Nat} (hp1 : 1 ≤ p) (hp : p ≤ 64) (A : List Net)
    (hA : ∀ a ∈ A, IsBiNet a ∧ hiP a = p ∧ hiA a &&& buddyBit p = 0) (X : BitVec 128) :
    (∃ z ∈ A.map (reparent p), Mem X z) ↔
      (∃ a ∈ A, Mem X a) ∨ ∃ b ∈ A.map (buddyNet p), Mem X b := by
  constructor
  · rintro ⟨z, hz, hX⟩
    obtain ⟨a, ha, rfl⟩ := List.mem_map.mp hz
    have := (reparent_spec hp1 hp (hA a ha).1 (hA a ha).2.1 (hA a ha).2.2).2.2.2.2.2 X
    rcases this.mp hX with h | h
    · exact Or.inl ⟨a, ha, h⟩
    · exact Or.inr ⟨buddyNet p a, List.mem_map_of_mem ha, h⟩
  · rintro (⟨a, ha, hX⟩ | ⟨b, hb, hX⟩)
    · have := (reparent_spec hp1 hp (hA a ha).1 (hA a ha).2.1 (hA a ha).2.2).2.2.2.2.2 X
      exact ⟨reparent p a, List.mem_map_of_mem ha, this.mpr (Or.inl hX)⟩
    · obtain ⟨a, ha, rfl⟩ := List.mem_map.mp hb
      have := (reparent_spec hp1 hp (hA a ha).1 (hA a ha).2.1 (hA a ha).2.2).2.2.2.2.2 X
      exact ⟨reparent p a, List.mem_map_of_mem ha, this.mpr (Or.inr hX)⟩

theorem hi_normalized {x : Net} (h : IsBiNet x) : hiA x &&& hiM x = hiA x := by
  obtain ⟨x1, x2⟩ := x
  have := h.2
  simp only [hiA, hiM, hi] at this ⊢
  bv_decide

/-- At level `p`, the high address after `a` with the buddy bit set is the next one. -/
theorem next_hiA {p : Nat} (hp1 : 1 ≤ p) (hp : p ≤ 64) {x y : Net} (hx : IsBiNet x)
    (hy : IsBiNet y) (hxp : hiP x = p) (hyp : hiP y = p) (hb : hiA x &&& buddyBit p = 0)
    (hxy : (hiA x).toNat < (hiA y).toNat) (hyz : (hiA y).toNat ≤ (hiA x ||| buddyBit p).toNat) :
    hiA y = hiA x ||| buddyBit p := by
  have nx := hi_normalized hx
  have ny := hi_normalized hy
  rw [hiM_eq hx, hxp, halfMask_eq p hp] at nx
  rw [hiM_eq hy, hyp, halfMask_eq p hp] at ny
  rw [buddyBit_eq p hp, ofNat_sub_64 hp] at hb hyz ⊢
  have hP1 : 1#64 ≤ BitVec.ofNat 64 p := by
    rw [BitVec.le_def, toNat_ofNat_64 (show 1 ≤ 64 by omega), toNat_ofNat_64 hp]
    omega
  have hP64 : BitVec.ofNat 64 p ≤ 64#64 := by
    rw [BitVec.le_def, toNat_ofNat_64 hp, toNat_ofNat_64 (show 64 ≤ 64 by omega)]
    omega
  rw [← BitVec.lt_def] at hxy
  rw [← BitVec.le_def] at hyz
  generalize hiA x = a at *
  generalize hiA y = b at *
  generalize BitVec.ofNat 64 p = P at *
  bv_decide

theorem buddyBit_ne_zero {p : Nat} (hp1 : 1 ≤ p) (hp : p ≤ 64) : buddyBit p ≠ 0 := by
  rw [buddyBit_eq p hp, ofNat_sub_64 hp]
  have hP1 : 1#64 ≤ BitVec.ofNat 64 p := by
    rw [BitVec.le_def, toNat_ofNat_64 (show 1 ≤ 64 by omega), toNat_ofNat_64 hp]
    omega
  have hP64 : BitVec.ofNat 64 p ≤ 64#64 := by
    rw [BitVec.le_def, toNat_ofNat_64 hp, toNat_ofNat_64 (show 64 ≤ 64 by omega)]
    omega
  generalize BitVec.ofNat 64 p = P at *
  bv_decide

/-- What Phase B guarantees for its output `o` on the block `l`. -/
def BuddySpec (p : Nat) (l o : List Net) : Prop :=
  (∀ z ∈ o, z ∈ l ∨ ∃ x ∈ l, z = reparent p x ∧ hiA x &&& buddyBit p = 0) ∧
    (∀ X, (∃ z ∈ o, Mem X z) ↔ ∃ x ∈ l, Mem X x) ∧
    (∀ H, group o p H = [] ∨ group o p H = group l p H) ∧
    (∀ H, ¬ MergeableAt o p H) ∧
    (o = l ∨ o.length < l.length)

theorem or_buddyBit_ne {p : Nat} (hp1 : 1 ≤ p) (hp : p ≤ 64) {H : BitVec 64}
    (hH : H &&& buddyBit p = 0) : H ||| buddyBit p ≠ H := by
  have := buddyBit_ne_zero hp1 hp
  generalize buddyBit p = b at *
  intro h
  apply this
  bv_decide

theorem lt_or_buddyBit {p : Nat} (hp1 : 1 ≤ p) (hp : p ≤ 64) {H : BitVec 64}
    (hH : H &&& buddyBit p = 0) : H.toNat < (H ||| buddyBit p).toNat := by
  have := buddyBit_ne_zero hp1 hp
  rw [← BitVec.lt_def]
  generalize buddyBit p = b at *
  bv_decide

/-- The output networks above the first group have the high addresses of the rest. -/
theorem buddySpec_hiA {p : Nat} (hp1 : 1 ≤ p) (hp : p ≤ 64) {l o : List Net} (hl : BlockInv p l)
    (h : BuddySpec p l o) : ∀ z ∈ o, ∃ w ∈ l, hiA z = hiA w ∧ (hiP z = p → z ∈ l) := by
  intro z hz
  rcases h.1 z hz with hz | ⟨w, hw, rfl, hb⟩
  · exact ⟨z, hz, rfl, fun _ => hz⟩
  · have := reparent_spec hp1 hp (hl.1 w hw).1 (hl.1 w hw).2 hb
    refine ⟨w, hw, this.2.2.1, fun h' => ?_⟩
    rw [this.2.1] at h'
    omega

/-- Keeping the first group and merging the rest. -/
theorem buddySpec_keep {p : Nat} (hp1 : 1 ≤ p) (hp : p ≤ 64) {x : Net} {xs : List Net}
    (hl : BlockInv p (x :: xs)) (o' : List Net)
    (hrest : BuddySpec p (xs.dropWhile (fun y => hiA y = hiA x)) o')
    (hfirst : ∀ H, H = hiA x → ¬ MergeableAt ((x :: xs.takeWhile (fun y => hiA y = hiA x)) ++ o') p H) :
    BuddySpec p (x :: xs) ((x :: xs.takeWhile (fun y => hiA y = hiA x)) ++ o') := by
  have hsplit : x :: xs = (x :: xs.takeWhile (fun y => hiA y = hiA x)) ++
      xs.dropWhile (fun y => hiA y = hiA x) := by
    rw [List.cons_append, List.takeWhile_append_dropWhile]
  generalize hA : x :: xs.takeWhile (fun y => hiA y = hiA x) = A at *
  generalize hR : xs.dropWhile (fun y => hiA y = hiA x) = R at *
  have hAx : ∀ z ∈ A, hiA z = hiA x := by
    intro z hz
    rw [← hA] at hz
    rcases List.mem_cons.mp hz with rfl | hz
    · rfl
    · simpa using mem_takeWhile_pred hz
  have hRx : ∀ z ∈ R, (hiA x).toNat < (hiA z).toNat := by
    rw [← hR]
    exact (block_head hl).2
  have hlR : BlockInv p R := hl.sublist (by rw [hsplit]; exact List.sublist_append_right _ _)
  have hlA : ∀ z ∈ A, IsBiNet z ∧ hiP z = p := fun z hz =>
    hl.1 z (by rw [hsplit]; exact List.mem_append_left _ hz)
  have ho'x : ∀ z ∈ o', (hiA x).toNat < (hiA z).toNat ∧ (hiP z = p → z ∈ R) := by
    intro z hz
    obtain ⟨w, hw, he, hk⟩ := buddySpec_hiA hp1 hp hlR hrest z hz
    exact ⟨by rw [he]; exact hRx w hw, hk⟩
  have hgA : ∀ H, group A p H = if H = hiA x then A else [] := by
    intro H
    split
    · rename_i hH
      exact group_eq_self fun z hz => ⟨(hlA z hz).2, by rw [hAx z hz, hH]⟩
    · rename_i hH
      exact group_eq_nil fun z hz _ he => hH (by rw [← he, hAx z hz])
  have hgo'x : group o' p (hiA x) = [] :=
    group_eq_nil fun z hz _ he => by have := (ho'x z hz).1; rw [he] at this; omega
  have hgRx : group R p (hiA x) = [] :=
    group_eq_nil fun z hz _ he => by have := hRx z hz; rw [he] at this; omega
  obtain ⟨r1, r2, r3, r4, r5⟩ := hrest
  refine ⟨fun z hz => ?_, fun X => ?_, fun H => ?_, fun H hM => ?_, ?_⟩
  · rcases List.mem_append.mp hz with hz | hz
    · exact Or.inl (by rw [hsplit]; exact List.mem_append_left _ hz)
    · rcases r1 z hz with hz' | ⟨w, hw, he, hb⟩
      · exact Or.inl (by rw [hsplit]; exact List.mem_append_right _ hz')
      · exact Or.inr ⟨w, by rw [hsplit]; exact List.mem_append_right _ hw, he, hb⟩
  · rw [hsplit]
    simp only [List.mem_append]
    constructor
    · rintro ⟨z, hz | hz, hXz⟩
      · exact ⟨z, Or.inl hz, hXz⟩
      · obtain ⟨w, hw, hXw⟩ := (r2 X).mp ⟨z, hz, hXz⟩
        exact ⟨w, Or.inr hw, hXw⟩
    · rintro ⟨w, hw | hw, hXw⟩
      · exact ⟨w, Or.inl hw, hXw⟩
      · obtain ⟨z, hz, hXz⟩ := (r2 X).mpr ⟨w, hw, hXw⟩
        exact ⟨z, Or.inr hz, hXz⟩
  · rw [hsplit, group_append, group_append, hgA H]
    by_cases hH : H = hiA x
    · subst hH
      rw [ite_eq_left rfl, hgo'x, hgRx]
      exact Or.inr rfl
    · rw [ite_eq_right hH, List.nil_append, List.nil_append]
      exact r3 H
  · by_cases hH : H = hiA x
    · exact hfirst H hH hM
    · obtain ⟨_, _, hHb, hne1, hne2, hperm⟩ := hM
      rw [group_append, hgA H, ite_eq_right hH, List.nil_append] at hne1 hperm
      by_cases hHx : H ||| buddyBit p = hiA x
      · -- the group below `x`'s would have to come after it
        apply hne1
        apply group_eq_nil
        intro z hz _ he
        have h1 := (ho'x z hz).1
        have h2 := lt_or_buddyBit hp1 hp hHb
        rw [he] at h1
        rw [hHx] at h2
        omega
      · rw [group_append, hgA (H ||| buddyBit p), ite_eq_right hHx, List.nil_append] at hne2 hperm
        exact r4 H ⟨by omega, by omega, hHb, hne1, hne2, hperm⟩
  · rcases r5 with h | h
    · exact Or.inl (by rw [hsplit, h])
    · exact Or.inr (by rw [hsplit, List.length_append, List.length_append]; omega)

/-- Phase B over a block of level `p ≥ 1`: merges every buddy pair of groups with equal
low halves, keeps the union, and leaves no such pair at level `p`. -/
theorem hiBuddyMerge_spec {p : Nat} (hp1 : 1 ≤ p) (hp : p ≤ 64) (l : List Net) :
    BlockInv p l → BuddySpec p l (hiBuddyMerge p l) := by
  induction l using hiBuddyMerge.induct (p := p) with
  | case1 =>
    intro _
    rw [hiBuddyMerge]
    refine ⟨by simp, fun X => Iff.rfl, fun H => Or.inr rfl, fun H hM => ?_, Or.inl rfl⟩
    exact hM.2.2.2.1 (by simp [group])
  | case2 x xs hdrop =>
    intro hl
    rw [hiBuddyMerge_eq_last hdrop]
    have hxs : xs.takeWhile (fun y => hiA y = hiA x) = xs := by
      have := List.takeWhile_append_dropWhile (p := fun y => decide (hiA y = hiA x)) (l := xs)
      rw [hdrop, List.append_nil] at this
      exact this
    rw [hxs]
    refine ⟨fun z hz => Or.inl hz, fun X => Iff.rfl, fun H => Or.inr rfl, fun H hM => ?_, Or.inl rfl⟩
    obtain ⟨_, _, hHb, hne1, hne2, -⟩ := hM
    have hall : ∀ z ∈ x :: xs, hiA z = hiA x := by
      intro z hz
      rcases List.mem_cons.mp hz with rfl | hz
      · rfl
      · rw [← hxs] at hz
        simpa using mem_takeWhile_pred hz
    have h1 : H = hiA x := by
      obtain ⟨z, hz⟩ := List.exists_mem_of_ne_nil _ hne1
      simp only [group, List.mem_filter, decide_eq_true_eq] at hz
      rw [← hz.2.2, hall z hz.1]
    have h2 : H ||| buddyBit p = hiA x := by
      obtain ⟨z, hz⟩ := List.exists_mem_of_ne_nil _ hne2
      simp only [group, List.mem_filter, decide_eq_true_eq] at hz
      rw [← hz.2.2, hall z hz.1]
    exact or_buddyBit_ne hp1 hp hHb (h2.trans h1.symm)
  | case3 x xs y ys hdrop hcond heq ih =>
    intro hl
    rw [hiBuddyMerge_eq_step hdrop, ite_eq_left hcond, ite_eq_left heq]
    have hsplit : x :: xs = (x :: xs.takeWhile (fun y => hiA y = hiA x)) ++
        ((y :: ys.takeWhile (fun z => hiA z = hiA y)) ++ ys.dropWhile (fun z => hiA z = hiA y)) := by
      rw [List.cons_append, List.cons_append, List.takeWhile_append_dropWhile, ← hdrop,
        List.takeWhile_append_dropWhile]
    generalize hA : x :: xs.takeWhile (fun y => hiA y = hiA x) = A at *
    generalize hB : y :: ys.takeWhile (fun z => hiA z = hiA y) = B at *
    generalize hR : ys.dropWhile (fun z => hiA z = hiA y) = R at *
    have hAx : ∀ z ∈ A, hiA z = hiA x := by
      intro z hz
      rw [← hA] at hz
      rcases List.mem_cons.mp hz with rfl | hz
      · rfl
      · simpa using mem_takeWhile_pred hz
    have hBy : ∀ z ∈ B, hiA z = hiA y := by
      intro z hz
      rw [← hB] at hz
      rcases List.mem_cons.mp hz with rfl | hz
      · rfl
      · simpa using mem_takeWhile_pred hz
    have hl' : BlockInv p (y :: ys) := hl.sublist (by
      rw [← hdrop]
      exact (List.dropWhile_sublist _).cons _)
    have hRy : ∀ z ∈ R, (hiA y).toNat < (hiA z).toNat := by
      rw [← hR]
      exact (block_head hl').2
    have hRx : ∀ z ∈ R, (hiA x).toNat < (hiA z).toNat := by
      intro z hz
      have h1 := hRy z hz
      have h2 := lt_or_buddyBit hp1 hp hcond.1
      rw [← hcond.2] at h2
      omega
    have hlR : BlockInv p R := hl.sublist (by
      rw [hsplit]
      exact (List.sublist_append_right _ _).trans (List.sublist_append_right _ _))
    have hlA : ∀ z ∈ A, IsBiNet z ∧ hiP z = p := fun z hz =>
      hl.1 z (by rw [hsplit]; exact List.mem_append_left _ hz)
    have hlB : ∀ z ∈ B, IsBiNet z ∧ hiP z = p := fun z hz =>
      hl.1 z (by rw [hsplit]; exact List.mem_append_right _ (List.mem_append_left _ hz))
    have hArep : ∀ a ∈ A, IsBiNet a ∧ hiP a = p ∧ hiA a &&& buddyBit p = 0 := fun a ha =>
      ⟨(hlA a ha).1, (hlA a ha).2, by rw [hAx a ha]; exact hcond.1⟩
    have hBeq : B = A.map (buddyNet p) :=
      buddy_group_eq hcond.1 A B (fun a ha => ⟨(hlA a ha).1, (hlA a ha).2, hAx a ha⟩)
        (fun b hb => ⟨(hlB b hb).1, (hlB b hb).2, by rw [hBy b hb, hcond.2]⟩)
        ((loListsEq_iff A B).mp heq)
    obtain ⟨r1, r2, r3, r4, r5⟩ := ih hlR
    have hgrep : ∀ H, group (A.map (reparent p)) p H = [] := by
      intro H
      apply group_eq_nil
      intro z hz hzp
      obtain ⟨a, ha, rfl⟩ := List.mem_map.mp hz
      rw [(reparent_spec hp1 hp (hArep a ha).1 (hArep a ha).2.1 (hArep a ha).2.2).2.1] at hzp
      omega
    refine ⟨fun z hz => ?_, fun X => ?_, fun H => ?_, fun H hM => ?_, ?_⟩
    · rcases List.mem_append.mp hz with hz | hz
      · obtain ⟨a, ha, rfl⟩ := List.mem_map.mp hz
        exact Or.inr ⟨a, by rw [hsplit]; exact List.mem_append_left _ ha, rfl, (hArep a ha).2.2⟩
      · rcases r1 z hz with hz' | ⟨w, hw, he, hb⟩
        · exact Or.inl (by
            rw [hsplit]
            exact List.mem_append_right _ (List.mem_append_right _ hz'))
        · exact Or.inr ⟨w, by
            rw [hsplit]
            exact List.mem_append_right _ (List.mem_append_right _ hw), he, hb⟩
    · rw [hsplit]
      simp only [List.mem_append]
      have hu := reparent_union hp1 hp A hArep X
      rw [← hBeq] at hu
      constructor
      · rintro ⟨z, hz | hz, hXz⟩
        · rcases hu.mp ⟨z, hz, hXz⟩ with ⟨a, ha, h⟩ | ⟨b, hb, h⟩
          · exact ⟨a, Or.inl ha, h⟩
          · exact ⟨b, Or.inr (Or.inl hb), h⟩
        · obtain ⟨w, hw, hXw⟩ := (r2 X).mp ⟨z, hz, hXz⟩
          exact ⟨w, Or.inr (Or.inr hw), hXw⟩
      · rintro ⟨w, hw | hw | hw, hXw⟩
        · obtain ⟨z, hz, hXz⟩ := hu.mpr (Or.inl ⟨w, hw, hXw⟩)
          exact ⟨z, Or.inl hz, hXz⟩
        · obtain ⟨z, hz, hXz⟩ := hu.mpr (Or.inr ⟨w, hw, hXw⟩)
          exact ⟨z, Or.inl hz, hXz⟩
        · obtain ⟨z, hz, hXz⟩ := (r2 X).mpr ⟨w, hw, hXw⟩
          exact ⟨z, Or.inr hz, hXz⟩
    · rw [group_append, hgrep, List.nil_append]
      rcases r3 H with h | h
      · exact Or.inl h
      · by_cases hne : group R p H = []
        · exact Or.inl (h.trans hne)
        · right
          obtain ⟨z, hz⟩ := List.exists_mem_of_ne_nil _ hne
          simp only [group, List.mem_filter, decide_eq_true_eq] at hz
          have hzx := hRx z hz.1
          have hzy := hRy z hz.1
          rw [h, hsplit, group_append, group_append]
          rw [group_eq_nil (S := A) fun a ha _ he => by
                rw [← hz.2.2, hAx a ha] at he; rw [he] at hzx; omega,
            group_eq_nil (S := B) fun b hb _ he => by
                rw [← hz.2.2, hBy b hb] at he; rw [he] at hzy; omega,
            List.nil_append, List.nil_append]
    · obtain ⟨h1, h2, hHb, hne1, hne2, hperm⟩ := hM
      simp only [group_append, hgrep, List.nil_append] at hne1 hne2 hperm
      exact r4 H ⟨h1, h2, hHb, hne1, hne2, hperm⟩
    · right
      have hBl : 0 < B.length := by rw [← hB]; simp
      have hRl : (hiBuddyMerge p R).length ≤ R.length := by
        rcases r5 with h | h
        · rw [h]
          exact Nat.le_refl _
        · omega
      rw [hsplit]
      simp only [List.length_append, List.length_map]
      omega
  | case4 x xs y ys hdrop hcond hneq ih =>
    intro hl
    rw [hiBuddyMerge_eq_step hdrop, ite_eq_left hcond, ite_eq_right hneq]
    have hl' : BlockInv p (y :: ys) := hl.sublist (by
      rw [← hdrop]
      exact (List.dropWhile_sublist _).cons _)
    have hrest : BuddySpec p (xs.dropWhile (fun y => hiA y = hiA x)) (hiBuddyMerge p (y :: ys)) := by
      rw [hdrop]
      exact ih hl'
    refine buddySpec_keep hp1 hp hl _ hrest fun H hH hM => ?_
    subst hH
    obtain ⟨-, -, hHb, hne1, hne2, hperm⟩ := hM
    have hsplit : y :: ys = (y :: ys.takeWhile (fun z => hiA z = hiA y)) ++
        ys.dropWhile (fun z => hiA z = hiA y) := by
      rw [List.cons_append, List.takeWhile_append_dropWhile]
    have hxs : x :: xs = (x :: xs.takeWhile (fun y => hiA y = hiA x)) ++ (y :: ys) := by
      rw [List.cons_append, ← hdrop, List.takeWhile_append_dropWhile]
    generalize hA : x :: xs.takeWhile (fun y => hiA y = hiA x) = A at *
    generalize hB : y :: ys.takeWhile (fun z => hiA z = hiA y) = B at *
    generalize hR : ys.dropWhile (fun z => hiA z = hiA y) = R at *
    have hAx : ∀ z ∈ A, hiA z = hiA x := by
      intro z hz
      rw [← hA] at hz
      rcases List.mem_cons.mp hz with rfl | hz
      · rfl
      · simpa using mem_takeWhile_pred hz
    have hBy : ∀ z ∈ B, hiA z = hiA y := by
      intro z hz
      rw [← hB] at hz
      rcases List.mem_cons.mp hz with rfl | hz
      · rfl
      · simpa using mem_takeWhile_pred hz
    have hyrest : ∀ z ∈ y :: ys, (hiA x).toNat < (hiA z).toNat := by
      rw [← hdrop]
      exact (block_head hl).2
    have hRy : ∀ z ∈ R, (hiA y).toNat < (hiA z).toNat := by
      rw [← hR]
      exact (block_head hl').2
    have hxy : hiA x ≠ hiA y := by
      intro he
      have := hyrest y List.mem_cons_self
      rw [he] at this
      omega
    -- the output's group at `x` is `A`, the one at its buddy `y` is `B`
    have hgo'x : group (hiBuddyMerge p (y :: ys)) p (hiA x) = [] := by
      apply group_eq_nil
      intro z hz _ he
      obtain ⟨w, hw, hzw, -⟩ := buddySpec_hiA hp1 hp hl' (ih hl') z hz
      have := hyrest w hw
      rw [← hzw, he] at this
      omega
    have hgA : group A p (hiA x) = A :=
      group_eq_self fun z hz => ⟨(hl.1 z (by rw [hxs]; exact List.mem_append_left _ hz)).2, hAx z hz⟩
    have hgAy : group A p (hiA y) = [] :=
      group_eq_nil fun z hz _ he => hxy (by rw [← he, hAx z hz])
    rw [group_append, hgA, hgo'x, List.append_nil] at hperm
    rw [← hcond.2, group_append, hgAy, List.nil_append] at hne2 hperm
    have hB' : group (hiBuddyMerge p (y :: ys)) p (hiA y) = B := by
      rcases (ih hl').2.2.1 (hiA y) with h | h
      · exact absurd h hne2
      · rw [h, hsplit, group_append, group_eq_self (S := B) fun z hz =>
          ⟨(hl'.1 z (by rw [hsplit]; exact List.mem_append_left _ hz)).2, hBy z hz⟩,
          group_eq_nil (S := R) fun z hz _ he => by have := hRy z hz; rw [he] at this; omega,
          List.append_nil]
    rw [hB'] at hperm
    have hlA : BlockInv p A := hl.sublist (by rw [hxs]; exact List.sublist_append_left _ _)
    have hlB : BlockInv p B := hl'.sublist (by rw [hsplit]; exact List.sublist_append_left _ _)
    have hsA := group_shapes_sorted (fun a ha => (hlA.1 a ha).1) hlA.2.1 hlA.2.2 fun a ha b hb =>
      (sameHi_iff (hlA.1 a ha).1 (hlA.1 b hb).1).mpr ⟨by rw [hAx a ha, hAx b hb],
        by rw [(hlA.1 a ha).2, (hlA.1 b hb).2]⟩
    have hsB := group_shapes_sorted (fun a ha => (hlB.1 a ha).1) hlB.2.1 hlB.2.2 fun a ha b hb =>
      (sameHi_iff (hlB.1 a ha).1 (hlB.1 b hb).1).mpr ⟨by rw [hBy a ha, hBy b hb],
        by rw [(hlB.1 a ha).2, (hlB.1 b hb).2]⟩
    exact hneq ((loListsEq_iff A B).mpr (eq_of_perm_shapes hsA hsB hperm))
  | case5 x xs y ys hdrop hcond ih =>
    intro hl
    rw [hiBuddyMerge_eq_step hdrop, ite_eq_right hcond]
    have hl' : BlockInv p (y :: ys) := hl.sublist (by
      rw [← hdrop]
      exact (List.dropWhile_sublist _).cons _)
    have hrest : BuddySpec p (xs.dropWhile (fun y => hiA y = hiA x)) (hiBuddyMerge p (y :: ys)) := by
      rw [hdrop]
      exact ih hl'
    refine buddySpec_keep hp1 hp hl _ hrest fun H hH hM => ?_
    subst hH
    obtain ⟨-, -, hHb, -, hne2, -⟩ := hM
    obtain ⟨z, hz⟩ := List.exists_mem_of_ne_nil _ hne2
    simp only [group, List.mem_filter, decide_eq_true_eq] at hz
    obtain ⟨hz, hzp, hzH⟩ := hz
    have hyrest : ∀ w ∈ y :: ys, (hiA x).toNat < (hiA w).toNat := by
      rw [← hdrop]
      exact (block_head hl).2
    rcases List.mem_append.mp hz with hz | hz
    · -- the first group has `x`'s high address, not its buddy's
      rcases List.mem_cons.mp hz with rfl | hz
      · exact or_buddyBit_ne hp1 hp hHb hzH.symm
      · exact or_buddyBit_ne hp1 hp hHb (by rw [← hzH]; simpa using mem_takeWhile_pred hz)
    · obtain ⟨w, hw, hzw, hk⟩ := buddySpec_hiA hp1 hp hl' (ih hl') z hz
      have hzin := hk hzp
      have hyz : (hiA y).toNat ≤ (hiA z).toNat := by
        rcases List.mem_cons.mp hzin with rfl | hzin
        · exact Nat.le_refl _
        · exact (List.pairwise_cons.mp hl'.hiA_sorted).1 z hzin
      have hxl : BlockInv p (x :: xs) := hl
      have hy := hl'.1 y List.mem_cons_self
      have hx := hl.1 x List.mem_cons_self
      apply hcond
      refine ⟨hHb, next_hiA hp1 hp hx.1 hy.1 hx.2 hy.2 hHb (hyrest y List.mem_cons_self) ?_⟩
      rw [← hzH]
      exact hyz

/-! ## One level, and the sweep -/

/-- Pairs of one class are related iff every class is pairwise related. -/
theorem pairwise_of_classes {α β : Type} [DecidableEq β] (f : α → β) {R : α → α → Prop} :
    ∀ {S : List α}, (∀ b, (S.filter fun x => f x = b).Pairwise R) →
      S.Pairwise (fun x y => f x = f y → R x y)
  | [], _ => List.Pairwise.nil
  | s :: S, h => by
    rw [List.pairwise_cons]
    constructor
    · intro y hy hfy
      have := h (f s)
      rw [List.filter_cons_of_pos (by simp)] at this
      exact (List.pairwise_cons.mp this).1 y (List.mem_filter.mpr ⟨hy, by simp [hfy]⟩)
    · apply pairwise_of_classes f
      intro b
      have := h b
      by_cases hb : f s = b
      · rw [List.filter_cons_of_pos (by simp [hb])] at this
        exact (List.pairwise_cons.mp this).2
      · rw [List.filter_cons_of_neg (by simp [hb])] at this
        exact this

theorem group_perm {S S' : List Net} (h : S.Perm S') (q : Nat) (H : BitVec 64) :
    (group S q H).Perm (group S' q H) := h.filter _

theorem mergeableAt_of_perm {S S' : List Net} {q : Nat} {H : BitVec 64}
    (h : ∀ H, (group S q H).Perm (group S' q H)) (hM : MergeableAt S q H) : MergeableAt S' q H := by
  obtain ⟨h1, h2, hb, hne1, hne2, hp⟩ := hM
  refine ⟨h1, h2, hb, fun he => hne1 ?_, fun he => hne2 ?_, ?_⟩
  · exact List.Perm.eq_nil ((h H).trans (by rw [he]))
  · exact List.Perm.eq_nil ((h _).trans (by rw [he]))
  · exact ((h H).map loShape).symm.trans (hp.trans ((h _).map loShape))

theorem union_of_perm {S S' : List Net} (h : S.Perm S') (X : BitVec 128) :
    (∃ z ∈ S, Mem X z) ↔ ∃ z ∈ S', Mem X z :=
  ⟨fun ⟨z, hz, hX⟩ => ⟨z, h.subset hz, hX⟩, fun ⟨z, hz, hX⟩ => ⟨z, h.symm.subset hz, hX⟩⟩

/-- The invariant of the sweep once the levels `k` and above are processed: sorted,
bi-contiguous, the groups of those levels canonical, and no mergeable buddy groups
among them. -/
def SweepInv (k : Nat) (L : List Net) : Prop :=
  L.Pairwise (fun x y => levelLe x y = true) ∧ (∀ x ∈ L, IsBiNet x) ∧
    L.Pairwise (fun x y => k ≤ hiP x → SameHi x y → ¬ Meets x y ∧ ¬ Buddies x y) ∧
    (∀ q H, k ≤ q → ¬ MergeableAt L q H)

theorem buddies_symm' {x y : Net} (h : Buddies x y) : Buddies y x := buddies_symm h

theorem canon_symm (k : Nat) {x y : Net}
    (h : k ≤ hiP x → SameHi x y → ¬ Meets x y ∧ ¬ Buddies x y) :
    k ≤ hiP y → SameHi y x → ¬ Meets y x ∧ ¬ Buddies y x := by
  intro hk hs
  obtain ⟨h1, h2⟩ := h (by rw [hiP_eq_of_sameHi (sameHi_symm hs)]; exact hk) (sameHi_symm hs)
  exact ⟨fun hm => h1 hm.symm, fun hb => h2 (buddies_symm hb)⟩

theorem group_filter_eq (S : List Net) (q : Nat) (H : BitVec 64) :
    S.filter (fun x => (hiP x, hiA x) = (q, H)) = group S q H := by
  unfold group
  apply List.filter_congr
  intro x _
  simp

theorem pairwise_guard_false {l : List Net} {G : Net → Prop} {C : Net → Net → Prop}
    (h : ∀ x ∈ l, ¬ G x) : l.Pairwise fun x y => G x → C x y := by
  induction l with
  | nil => exact List.Pairwise.nil
  | cons a l ih =>
    rw [List.pairwise_cons]
    exact ⟨fun y _ hg => absurd hg (h a List.mem_cons_self),
      ih fun x hx => h x (List.mem_cons_of_mem _ hx)⟩

theorem mergeableAt_congr {S S' : List Net} {q : Nat} (h : ∀ H, group S q H = group S' q H)
    (H : BitVec 64) : MergeableAt S q H ↔ MergeableAt S' q H := by
  unfold MergeableAt
  rw [h H, h (H ||| buddyBit q)]

theorem group_sameHi {S : List Net} {q : Nat} {H : BitVec 64} (hbi : ∀ x ∈ S, IsBiNet x) :
    ∀ x ∈ group S q H, ∀ y ∈ group S q H, SameHi x y := by
  intro x hx y hy
  simp only [group, List.mem_filter, decide_eq_true_eq] at hx hy
  exact (sameHi_iff (hbi x hx.1) (hbi y hy.1)).mpr ⟨by rw [hx.2.2, hy.2.2], by rw [hx.2.1, hy.2.1]⟩

/-- Canonical groups give pairwise canonical groups. -/
theorem group_canon {S : List Net} {q : Nat} {H : BitVec 64} (hbi : ∀ x ∈ S, IsBiNet x)
    (h : S.Pairwise fun x y => SameHi x y → ¬ Meets x y ∧ ¬ Buddies x y) :
    (group S q H).Pairwise fun x y => ¬ Meets x y ∧ ¬ Buddies x y :=
  (h.filter _).imp_of_mem fun hx hy hxy => hxy (group_sameHi hbi _ hx _ hy)


/-- What the survivors of one level satisfy, for either branch of Phase B. -/
def SurvSpec (p : Nat) (afterLo surv : List Net) : Prop :=
  (∀ z ∈ surv, IsBiNet z ∧ (hiP z = p ∨ (1 ≤ p ∧ hiP z = p - 1))) ∧
    (∀ X, (∃ z ∈ surv, Mem X z) ↔ ∃ x ∈ afterLo, Mem X x) ∧
    (∀ H, group surv p H = [] ∨ group surv p H = group afterLo p H) ∧
    (∀ H, ¬ MergeableAt surv p H) ∧
    (surv = afterLo ∨ surv.length < afterLo.length)

theorem survSpec {p : Nat} (hp : p ≤ 64) {afterLo : List Net} (hBI : BlockInv p afterLo) :
    SurvSpec p afterLo (if p = 0 then afterLo else hiBuddyMerge p afterLo) := by
  by_cases hp0 : p = 0
  · subst hp0
    rw [ite_eq_left rfl]
    exact ⟨fun z hz => ⟨(hBI.1 z hz).1, Or.inl (hBI.1 z hz).2⟩, fun X => Iff.rfl,
      fun H => Or.inr rfl, fun H hM => absurd hM.1 (by omega), Or.inl rfl⟩
  · rw [ite_eq_right hp0]
    have hp1 : 1 ≤ p := by omega
    obtain ⟨b1, b2, b3, b4, b5⟩ := hiBuddyMerge_spec hp1 hp afterLo hBI
    refine ⟨fun z hz => ?_, b2, b3, b4, b5⟩
    rcases b1 z hz with hz' | ⟨x, hx, rfl, hb⟩
    · exact ⟨(hBI.1 z hz').1, Or.inl (hBI.1 z hz').2⟩
    · have := reparent_spec hp1 hp (hBI.1 x hx).1 (hBI.1 x hx).2 hb
      exact ⟨this.1, Or.inr ⟨hp1, this.2.1⟩⟩

theorem sweepLevel_eq (p : Nat) {L : List Net} (hsP : L.Pairwise fun x y => hiP x ≤ hiP y) :
    sweepLevel p L =
      let P := L.filter (fun x => hiP x < p)
      let afterLo := loAggregate (L.filter (fun x => hiP x = p))
      let surv := if p = 0 then afterLo else hiBuddyMerge p afterLo
      if surv.length < afterLo.length ∧ p ≠ 0 then
        P.takeWhile (fun x => hiP x < p - 1) ++
          (P.dropWhile (fun x => hiP x < p - 1) ++ surv).mergeSort levelLe ++
          L.filter (fun x => p < hiP x)
      else P ++ surv ++ L.filter (fun x => p < hiP x) := by
  obtain ⟨e1, e2, e3⟩ := level_split p hsP
  simp only [sweepLevel]
  rw [e1, e2, e3]

/-- One level: processing level `p` keeps the union, and afterwards the levels `p` and
above are canonical and free of mergeable buddy groups. -/
theorem sweepLevel_spec {p : Nat} (hp : p ≤ 64) {L : List Net} (hinv : SweepInv (p + 1) L) :
    SweepInv p (sweepLevel p L) ∧ (∀ X, (∃ z ∈ sweepLevel p L, Mem X z) ↔ ∃ x ∈ L, Mem X x) ∧
      (sweepLevel p L).length ≤ L.length := by
  obtain ⟨hs, hbi, hcan, hmer⟩ := hinv
  have hsP : L.Pairwise fun x y => hiP x ≤ hiP y :=
    hs.imp_of_mem fun ha hb h => hiP_le_of_levelLe (hbi _ ha) (hbi _ hb) h
  have hLsplit : L = L.filter (fun x => hiP x < p) ++ L.filter (fun x => hiP x = p) ++
      L.filter (fun x => p < hiP x) := by
    obtain ⟨e1, e2, e3⟩ := level_split p hsP
    have h1 := List.takeWhile_append_dropWhile (p := fun x => decide (hiP x < p)) (l := L)
    have h2 := List.takeWhile_append_dropWhile (p := fun x => decide (hiP x ≤ p))
      (l := L.dropWhile fun x => decide (hiP x < p))
    rw [e2, e3] at h2
    rw [← h2, e1] at h1
    rw [List.append_assoc]
    exact h1.symm
  rw [sweepLevel_eq p hsP]
  simp only
  generalize hPd : L.filter (fun x => hiP x < p) = P at *
  generalize hBd : L.filter (fun x => hiP x = p) = Bk at *
  generalize hQd : L.filter (fun x => p < hiP x) = Q at *
  have hPlev : ∀ x ∈ P, hiP x < p := fun x hx => by
    rw [← hPd] at hx
    simpa using (List.mem_filter.mp hx).2
  have hBlev : ∀ x ∈ Bk, hiP x = p := fun x hx => by
    rw [← hBd] at hx
    simpa using (List.mem_filter.mp hx).2
  have hQlev : ∀ x ∈ Q, p < hiP x := fun x hx => by
    rw [← hQd] at hx
    simpa using (List.mem_filter.mp hx).2
  have hPsub : P.Sublist L := by
    rw [hLsplit, List.append_assoc]
    exact List.sublist_append_left _ _
  have hBsub : Bk.Sublist L := by
    rw [hLsplit, List.append_assoc]
    exact (List.sublist_append_left _ _).trans (List.sublist_append_right _ _)
  have hQsub : Q.Sublist L := by
    rw [hLsplit]
    exact List.sublist_append_right _ _
  obtain ⟨la1, la2, la3, la4, la5⟩ := loAggregate_spec (fun x hx => hbi x (hBsub.subset hx)) hBlev
    (hs.sublist hBsub)
  generalize hAd : loAggregate Bk = afterLo at *
  have hBI : BlockInv p afterLo := ⟨fun z hz => ⟨(la1 z hz).1, (la1 z hz).2.1⟩, la3, la4⟩
  obtain ⟨s1, s2, s3, s4, s5⟩ := survSpec hp hBI
  have hS0 : p = 0 → (if p = 0 then afterLo else hiBuddyMerge p afterLo) = afterLo :=
    fun h => by rw [ite_eq_left h]
  generalize hSd : (if p = 0 then afterLo else hiBuddyMerge p afterLo) = surv at *
  have hSlev : ∀ z ∈ surv, hiP z ≤ p := fun z hz => by
    rcases (s1 z hz).2 with h | h
    · omega
    · omega
  -- every list that permutes `P ++ surv ++ Q` and is sorted satisfies the invariant
  suffices key : ∀ N : List Net, N.Perm (P ++ surv ++ Q) →
      N.Pairwise (fun x y => levelLe x y = true) →
      SweepInv p N ∧ (∀ X, (∃ z ∈ N, Mem X z) ↔ ∃ x ∈ L, Mem X x) ∧ N.length ≤ L.length by
    have hPs : P.Pairwise (fun x y => levelLe x y = true) := hs.sublist hPsub
    have hQs : Q.Pairwise (fun x y => levelLe x y = true) := hs.sublist hQsub
    have hlt : ∀ {x y : Net}, IsBiNet x → IsBiNet y → hiP x < hiP y → levelLe x y = true :=
      fun hx hy h => by
        simp only [levelLe, decide_eq_true_eq]
        exact Nat.le_of_lt (levelKey_lt_of_hiP hx hy h)
    have hPbi : ∀ x ∈ P, IsBiNet x := fun x hx => hbi x (hPsub.subset hx)
    have hQbi : ∀ x ∈ Q, IsBiNet x := fun x hx => hbi x (hQsub.subset hx)
    by_cases hr : surv.length < afterLo.length ∧ p ≠ 0
    · rw [ite_eq_left hr]
      apply key
      · have hsort := List.mergeSort_perm
          ((P.dropWhile (fun x => hiP x < p - 1)) ++ surv) levelLe
        have hP := List.takeWhile_append_dropWhile (p := fun x => decide (hiP x < p - 1)) (l := P)
        have h1 : List.Perm (P.takeWhile (fun x => hiP x < p - 1) ++
              ((P.dropWhile (fun x => hiP x < p - 1)) ++ surv).mergeSort levelLe ++ Q)
            (P.takeWhile (fun x => hiP x < p - 1) ++
              ((P.dropWhile (fun x => hiP x < p - 1)) ++ surv) ++ Q) :=
          (hsort.append_left _).append_right _
        rw [← List.append_assoc (P.takeWhile _), hP] at h1
        exact h1
      · have hPsP : P.Pairwise fun x y => hiP x ≤ hiP y := hsP.sublist hPsub
        have hmid : ∀ x ∈ P.dropWhile (fun x => hiP x < p - 1), p - 1 ≤ hiP x := by
          intro x hx
          have hfirst : P.Pairwise fun a b => decide (hiP b < p - 1) = true →
              decide (hiP a < p - 1) = true :=
            hPsP.imp fun h hb => by simp only [decide_eq_true_eq] at hb ⊢; omega
          rw [dropWhile_eq_filter hfirst, List.mem_filter] at hx
          simpa using hx.2
        have hsortm : ∀ x ∈ ((P.dropWhile (fun x => hiP x < p - 1)) ++ surv).mergeSort levelLe,
            IsBiNet x ∧ p - 1 ≤ hiP x ∧ hiP x ≤ p := by
          intro x hx
          rw [List.mem_mergeSort, List.mem_append] at hx
          rcases hx with hx | hx
          · have hxP := (List.dropWhile_sublist _).subset hx
            exact ⟨hPbi x hxP, hmid x hx, by have := hPlev x hxP; omega⟩
          · rcases (s1 x hx).2 with h | h
            · exact ⟨(s1 x hx).1, by omega, by omega⟩
            · exact ⟨(s1 x hx).1, by omega, by omega⟩
        rw [List.pairwise_append, List.pairwise_append]
        refine ⟨⟨hPs.sublist (List.takeWhile_sublist _), sorted_mergeSort _, fun a ha b hb => ?_⟩,
          hQs, fun a ha b hb => ?_⟩
        · have haP := (List.takeWhile_sublist _).subset ha
          have hal : hiP a < p - 1 := by simpa using mem_takeWhile_pred ha
          exact hlt (hPbi a haP) (hsortm b hb).1 (by have := (hsortm b hb).2.1; omega)
        · rcases List.mem_append.mp ha with ha | ha
          · have haP := (List.takeWhile_sublist _).subset ha
            exact hlt (hPbi a haP) (hQbi b hb) (by have := hPlev a haP; have := hQlev b hb; omega)
          · exact hlt (hsortm a ha).1 (hQbi b hb) (by have := (hsortm a ha).2.2; have := hQlev b hb; omega)
    · rw [ite_eq_right hr]
      have hSA : surv = afterLo := by
        by_cases hp0 : p = 0
        · exact hS0 hp0
        · rcases s5 with h | h
          · exact h
          · exact absurd ⟨h, hp0⟩ hr
      apply key _ (List.Perm.refl _)
      rw [List.pairwise_append, List.pairwise_append]
      refine ⟨⟨hPs, by rw [hSA]; exact la4.imp fun h => by simp only [levelLe, decide_eq_true_eq]; omega,
        fun a ha b hb => ?_⟩, hQs, fun a ha b hb => ?_⟩
      · rw [hSA] at hb
        exact hlt (hPbi a ha) (la1 b hb).1 (by have := hPlev a ha; rw [(la1 b hb).2.1]; exact this)
      · rcases List.mem_append.mp ha with ha | ha
        · exact hlt (hPbi a ha) (hQbi b hb) (by have := hPlev a ha; have := hQlev b hb; omega)
        · rw [hSA] at ha
          exact hlt (la1 a ha).1 (hQbi b hb) (by rw [(la1 a ha).2.1]; exact hQlev b hb)
  intro N hN hNs
  have hPbi : ∀ x ∈ P, IsBiNet x := fun x hx => hbi x (hPsub.subset hx)
  have hQbi : ∀ x ∈ Q, IsBiNet x := fun x hx => hbi x (hQsub.subset hx)
  have hTbi : ∀ x ∈ P ++ surv ++ Q, IsBiNet x := by
    intro x hx
    simp only [List.mem_append] at hx
    rcases hx with (hx | hx) | hx
    · exact hPbi x hx
    · exact (s1 x hx).1
    · exact hQbi x hx
  have hgP : ∀ q H, p ≤ q → group P q H = [] := fun q H hq =>
    group_eq_nil fun z hz hzq _ => by have := hPlev z hz; omega
  have hgQ : ∀ q H, q ≤ p → group Q q H = [] := fun q H hq =>
    group_eq_nil fun z hz hzq _ => by have := hQlev z hz; omega
  have hgS : ∀ q H, p < q → group surv q H = [] := fun q H hq =>
    group_eq_nil fun z hz hzq _ => by have := hSlev z hz; omega
  have hgL : ∀ q H, p < q → group L q H = group Q q H := fun q H hq => by
    rw [hLsplit, group_append, group_append, hgP q H (by omega),
      group_eq_nil (S := Bk) fun z hz hzq _ => by have := hBlev z hz; omega,
      List.nil_append, List.nil_append]
  refine ⟨⟨hNs, fun z hz => hTbi z (hN.subset hz), ?_, ?_⟩, fun X => ?_, ?_⟩
  · apply (hN.pairwise_iff fun h => canon_symm p h).mpr
    have hcls := pairwise_of_classes (fun x : Net => (hiP x, hiA x))
      (R := fun x y => p ≤ hiP x → ¬ Meets x y ∧ ¬ Buddies x y) (S := P ++ surv ++ Q)
      (fun b => by
        obtain ⟨q, H⟩ := b
        rw [group_filter_eq, group_append, group_append]
        by_cases hq : q < p
        · apply pairwise_guard_false
          intro x hx hpx
          simp only [group, List.mem_append, List.mem_filter, decide_eq_true_eq] at hx
          rcases hx with (hx | hx) | hx <;> omega
        · by_cases hqp : q = p
          · subst hqp
            rw [hgP q H (Nat.le_refl _), hgQ q H (Nat.le_refl _), List.nil_append, List.append_nil]
            rcases s3 H with h | h
            · rw [h]
              exact List.Pairwise.nil
            · rw [h]
              refine (group_canon (S := afterLo) (q := q) (H := H) (fun x hx => (la1 x hx).1)
                la3).imp ?_
              intro x y h _
              exact h
          · rw [hgP q H (by omega), hgS q H (by omega), List.nil_append, List.nil_append,
              ← hgL q H (by omega)]
            exact ((hcan.filter _).imp_of_mem fun {x y} hx hy h _ =>
              h (by
                simp only [group, List.mem_filter, decide_eq_true_eq] at hx
                omega)
                (group_sameHi hbi _ hx _ hy)))
    exact hcls.imp_of_mem fun {x y} hx hy h hpx hsame =>
      h (by
        obtain ⟨ha, hp'⟩ := (sameHi_iff (hTbi x hx) (hTbi y hy)).mp hsame
        rw [ha, hp']) hpx
  · intro q H hq hM
    have hM' : MergeableAt (P ++ surv ++ Q) q H := mergeableAt_of_perm (fun H => group_perm hN q H) hM
    by_cases hqp : q = p
    · subst hqp
      have hg : ∀ H, group (P ++ surv ++ Q) q H = group surv q H := fun H => by
        rw [group_append, group_append, hgP q H (Nat.le_refl _), hgQ q H (Nat.le_refl _),
          List.nil_append, List.append_nil]
      exact s4 H ((mergeableAt_congr hg H).mp hM')
    · have hg : ∀ H, group (P ++ surv ++ Q) q H = group L q H := fun H => by
        rw [group_append, group_append, hgP q H (by omega), hgS q H (by omega), List.nil_append,
          List.nil_append, hgL q H (by omega)]
      exact hmer q H (by omega) ((mergeableAt_congr hg H).mp hM')
  · rw [union_of_perm hN X]
    rw [hLsplit]
    simp only [List.mem_append]
    constructor
    · rintro ⟨z, (hz | hz) | hz, hX⟩
      · exact ⟨z, Or.inl (Or.inl hz), hX⟩
      · obtain ⟨y, hy, hXy⟩ := (s2 X).mp ⟨z, hz, hX⟩
        obtain ⟨w, hw, hXw⟩ := (la2 X).mp ⟨y, hy, hXy⟩
        exact ⟨w, Or.inl (Or.inr hw), hXw⟩
      · exact ⟨z, Or.inr hz, hX⟩
    · rintro ⟨w, (hw | hw) | hw, hX⟩
      · exact ⟨w, Or.inl (Or.inl hw), hX⟩
      · obtain ⟨y, hy, hXy⟩ := (la2 X).mpr ⟨w, hw, hX⟩
        obtain ⟨z, hz, hXz⟩ := (s2 X).mpr ⟨y, hy, hXy⟩
        exact ⟨z, Or.inl (Or.inr hz), hXz⟩
      · exact ⟨w, Or.inr hw, hX⟩
  · rw [hN.length_eq, hLsplit]
    simp only [List.length_append]
    have : surv.length ≤ afterLo.length := by
      rcases s5 with h | h
      · rw [h]
        exact Nat.le_refl _
      · omega
    omega

theorem sweepFrom_spec : ∀ (p : Nat), p ≤ 64 → ∀ (L : List Net), SweepInv (p + 1) L →
    SweepInv 0 (sweepFrom p L) ∧ (∀ X, (∃ z ∈ sweepFrom p L, Mem X z) ↔ ∃ x ∈ L, Mem X x) ∧
      (sweepFrom p L).length ≤ L.length
  | 0, _, L, h => by
    rw [sweepFrom]
    exact sweepLevel_spec (by omega) h
  | p + 1, hp, L, h => by
    rw [sweepFrom]
    obtain ⟨i1, i2, i3⟩ := sweepLevel_spec hp h
    obtain ⟨j1, j2, j3⟩ := sweepFrom_spec p (by omega) _ i1
    exact ⟨j1, fun X => (j2 X).trans (i2 X), by omega⟩

/-- `bicontiguous_sweep`: the union is kept, the output holds normalized bi-contiguous
networks in canonical groups, no level carries two buddy groups with the same low
halves, and nothing is added. -/
theorem sweep_spec (L : List Net) (hL : ∀ x ∈ L, IsBiNet x) :
    (∀ x ∈ sweep L, IsBiNet x) ∧ (∀ X, (∃ z ∈ sweep L, Mem X z) ↔ ∃ x ∈ L, Mem X x) ∧
      GroupsCanon (sweep L) ∧ (∀ q H, ¬ MergeableAt (sweep L) q H) ∧
      (sweep L).length ≤ L.length := by
  unfold sweep
  split
  · rename_i hlen
    refine ⟨hL, fun X => Iff.rfl, ?_, fun q H hM => ?_, Nat.le_refl _⟩
    · rcases L with _ | ⟨x, _ | ⟨y, L'⟩⟩
      · exact List.Pairwise.nil
      · exact List.pairwise_singleton _ _
      · simp at hlen
    · obtain ⟨h1, h2, hHb, hne1, hne2, -⟩ := hM
      obtain ⟨a, ha⟩ := List.exists_mem_of_ne_nil _ hne1
      obtain ⟨b, hb⟩ := List.exists_mem_of_ne_nil _ hne2
      simp only [group, List.mem_filter, decide_eq_true_eq] at ha hb
      have hab : a = b := by
        rcases L with _ | ⟨x, _ | ⟨y, L'⟩⟩
        · simp at ha
        · simp only [List.mem_singleton] at ha hb
          rw [ha.1, hb.1]
        · simp at hlen
      apply or_buddyBit_ne h1 h2 hHb
      rw [← hb.2.2, ← hab, ha.2.2]
  · have hinit : SweepInv 65 (L.mergeSort levelLe) :=
      ⟨sorted_mergeSort L, fun x hx => hL x (List.mem_mergeSort.mp hx),
        pairwise_guard_false fun x _ h => by have := hiP_le x; omega,
        fun q H hq hM => by have := hM.2.1; omega⟩
    obtain ⟨⟨-, h2, h3, h4⟩, h5, h6⟩ := sweepFrom_spec 64 (Nat.le_refl _) _ hinit
    refine ⟨h2, fun X => (h5 X).trans (union_of_perm (List.mergeSort_perm L levelLe) X),
      h3.imp fun h => h (Nat.zero_le _), fun q H => h4 q H (Nat.zero_le _), ?_⟩
    rw [(List.mergeSort_perm L levelLe).length_eq] at h6
    exact h6

end Netip.Impl.Ipv6
