import Netip.HostIndex
import Netip.Impl.Addrs
import Netip.Impl.Contiguous
import Netip.Impl.IsContiguous

/-!
# Address iterators over a whole run

`Addrs` proves the single steps of `Ipv4NetworkAddrs` / `Ipv6NetworkAddrs` at the
widths the crate uses, and `HostIndex` that host-index order is numeric order.
Here the iterators are transcribed as state machines and run over an arbitrary
schedule of `next()` and `next_back()` calls, `true` for `next()`.

`expected` is the sequence every iterator below produces: a `next()` call returns
item `f` and a `next_back()` call item `K - 1 - b`, where `f` and `b` count the
earlier calls of each kind, until `R` items have been returned, and `None` from
then on. The front walks up, the back walks down, and they meet: with `R = K`
every item is returned exactly once (`expected_perm`), and any `c` calls return
`min c (R - f - b)` items (`expected_length`).

* `Ipv4NetworkAddrs`, `Ipv6NetworkAddrs` (`addrsNext`, `addrsNextBack`): the items
  are the members in host-index order, `K = 2^(host bits)`, and `R = K` except
  `2^128 - 1` for the IPv6 `/0` (`Ipv4.addrs_run`, `Ipv6.addrs_run`). `collect()`
  and `rev().collect()` list the members in ascending and descending order, every
  interleaving returns each member once, `remaining` is the exact count left
  (`addrs_remaining`), and a drain ends in the sentinel state its last call fixes
  (`addrs_drain_state`). The run is proved once for every width from the step
  facts of `Addrs` (`StepFacts`), which hold at 32 and 128 bits.
* `ContiguousIpv4NetworkAddrs`, `ContiguousIpv6NetworkAddrs` (`cursorNext`,
  `cursorNextBack`): a pair of cursors over indices or packed addresses. For a
  contiguous mask the member with host index `i` is `a + i = a | i`
  (`deposit_eq_ofNat`), so they return, call for call, what the general
  iterators return (`Ipv4.caddrs_run`, `Ipv6.caddrs_run_eq`). `remaining()` and
  `size_hint` count exactly, and after `K` calls the cursors have crossed, the
  sentinel in which every call returns `None` (`caddrs_remaining`).
-/

namespace Netip.Impl

open Netip (hostAddr hostBits Normalized)

variable {w : Nat}

/-! ## The expected sequence -/

/-- What each call of a schedule returns after `f` calls of `next()` and `b` of
`next_back()`: item `f` from the front, item `K - 1 - b` from the back, until `R`
items have been returned. -/
def expected (g : Nat → BitVec w) (K R : Nat) : Nat → Nat → List Bool → List (Option (BitVec w))
  | _, _, [] => []
  | f, b, true :: fs => (if f + b < R then some (g f) else none) :: expected g K R (f + 1) b fs
  | f, b, false :: fs =>
    (if f + b < R then some (g (K - 1 - b)) else none) :: expected g K R f (b + 1) fs

theorem expected_none {g : Nat → BitVec w} {K R : Nat} :
    ∀ (fs : List Bool) (f b : Nat), R ≤ f + b → expected g K R f b fs = fs.map fun _ => none := by
  intro fs
  induction fs with
  | nil => intro f b _; rfl
  | cons x fs ih =>
    intro f b h
    cases x
    · simp only [expected, List.map_cons]
      rw [ite_eq_right (by omega), ih f (b + 1) (by omega)]
    · simp only [expected, List.map_cons]
      rw [ite_eq_right (by omega), ih (f + 1) b (by omega)]

/-- Any schedule of `c` calls returns `min c (R - f - b)` items. -/
theorem expected_length {g : Nat → BitVec w} {K R : Nat} :
    ∀ (fs : List Bool) (f b : Nat),
      ((expected g K R f b fs).filterMap id).length = min fs.length (R - (f + b)) := by
  intro fs
  induction fs with
  | nil => intro f b; simp [expected]
  | cons x fs ih =>
    intro f b
    cases x
    · simp only [expected, List.filterMap_cons, List.length_cons]
      by_cases h : f + b < R
      · rw [ite_eq_left h]
        simp only [id_eq, List.length_cons]
        rw [ih f (b + 1)]
        omega
      · rw [ite_eq_right h]
        simp only [id_eq]
        rw [ih f (b + 1)]
        omega
    · simp only [expected, List.filterMap_cons, List.length_cons]
      by_cases h : f + b < R
      · rw [ite_eq_left h]
        simp only [id_eq, List.length_cons]
        rw [ih (f + 1) b]
        omega
      · rw [ite_eq_right h]
        simp only [id_eq]
        rw [ih (f + 1) b]
        omega

/-- With `R = K` and enough calls, the items returned are the indices `f ..< K - b`,
each once. -/
theorem expected_perm {g : Nat → BitVec w} {K : Nat} :
    ∀ (fs : List Bool) (f b : Nat), f + b ≤ K → K - (f + b) ≤ fs.length →
      ((expected g K K f b fs).filterMap id).Perm ((List.range' f (K - (f + b))).map g) := by
  intro fs
  induction fs with
  | nil =>
    intro f b _ hlen
    simp only [List.length_nil, Nat.le_zero] at hlen
    simp [expected, hlen]
  | cons x fs ih =>
    intro f b hle hlen
    simp only [List.length_cons] at hlen
    by_cases hlt : f + b < K
    · obtain ⟨n, hn⟩ : ∃ n, K - (f + b) = n + 1 := ⟨K - (f + b) - 1, by omega⟩
      rw [hn]
      cases x
      · simp only [expected, ite_eq_left hlt, List.filterMap_cons, id_eq]
        have := ih f (b + 1) (by omega) (by omega)
        rw [show K - (f + (b + 1)) = n by omega] at this
        rw [List.range'_concat, List.map_append, List.map_singleton,
          show f + 1 * n = K - 1 - b by omega]
        exact (this.cons _).trans (List.perm_append_comm (l₁ := [g (K - 1 - b)]))
      · simp only [expected, ite_eq_left hlt, List.filterMap_cons, id_eq]
        have := ih (f + 1) b (by omega) (by omega)
        rw [show K - (f + 1 + b) = n by omega] at this
        rw [List.range'_succ, List.map_cons]
        exact this.cons _
    · have h0 : K - (f + b) = 0 := by omega
      rw [h0, expected_none _ _ _ (by omega)]
      simp

/-- Items `g i` and `g' i` agree below `K`, so the sequences agree. -/
theorem expected_congr {g g' : Nat → BitVec w} {K R : Nat} (hR : R ≤ K)
    (hg : ∀ i < K, g i = g' i) :
    ∀ (fs : List Bool) (f b : Nat), expected g K R f b fs = expected g' K R f b fs := by
  intro fs
  induction fs with
  | nil => intro f b; rfl
  | cons x fs ih =>
    intro f b
    cases x
    · simp only [expected, ih]
      by_cases h : f + b < R
      · rw [ite_eq_left h, ite_eq_left h, hg _ (by omega)]
      · rw [ite_eq_right h, ite_eq_right h]
    · simp only [expected, ih]
      by_cases h : f + b < R
      · rw [ite_eq_left h, ite_eq_left h, hg _ (by omega)]
      · rw [ite_eq_right h, ite_eq_right h]

/-- Counts that are not reached by the schedule do not matter. -/
theorem expected_count {g : Nat → BitVec w} {K R R' : Nat} :
    ∀ (fs : List Bool) (f b : Nat), f + b + fs.length ≤ R → f + b + fs.length ≤ R' →
      expected g K R f b fs = expected g K R' f b fs := by
  intro fs
  induction fs with
  | nil => intro f b _ _; rfl
  | cons x fs ih =>
    intro f b h h'
    simp only [List.length_cons] at h h'
    cases x
    · simp only [expected]
      rw [ite_eq_left (by omega), ite_eq_left (by omega), ih f (b + 1) (by omega) (by omega)]
    · simp only [expected]
      rw [ite_eq_left (by omega), ite_eq_left (by omega), ih (f + 1) b (by omega) (by omega)]

/-! ## The general iterators -/

/-- The fields of `Ipv4NetworkAddrs` / `Ipv6NetworkAddrs`. The Rust `remaining` is
a `u64` (IPv4) or `u128` (IPv6) that is only decremented from a positive value,
so it is a natural number here. -/
structure Addrs (w : Nat) where
  base : BitVec w
  mask : BitVec w
  front : BitVec w
  back : BitVec w
  remaining : Nat

/-- The general step of `next`: with the mask bits preset to one, the carry ripples
across them. -/
def stepUp (base mask bits : BitVec w) : BitVec w := (((bits ||| mask) + 1) &&& ~~~mask) ||| base

/-- The general step of `next_back`: with the mask bits cleared, the borrow ripples
across them. -/
def stepDown (base mask bits : BitVec w) : BitVec w :=
  (((bits &&& ~~~mask) - 1) &&& ~~~mask) ||| base

/-- `next`: the step, then on exhaustion the front cursor is parked on `base`. -/
def addrsNext (s : Addrs w) : Option (BitVec w) × Addrs w :=
  if s.remaining = 0 then (none, s)
  else
    let front :=
      if ~~~s.mask &&& (~~~s.mask + 1) = 0 then s.front + 1 else stepUp s.base s.mask s.front
    (some s.front,
      { s with front := if s.remaining - 1 = 0 then s.base else front, remaining := s.remaining - 1 })

/-- `next_back`: the step, then on exhaustion both cursors are parked on `base`. -/
def addrsNextBack (s : Addrs w) : Option (BitVec w) × Addrs w :=
  if s.remaining = 0 then (none, s)
  else
    let back :=
      if ~~~s.mask &&& (~~~s.mask + 1) = 0 then s.back - 1 else stepDown s.base s.mask s.back
    (some s.back,
      { s with
        front := if s.remaining - 1 = 0 then s.base else s.front
        back := if s.remaining - 1 = 0 then s.base else back
        remaining := s.remaining - 1 })

/-- Runs a schedule of calls, collecting what each returns, and the final state. -/
def addrsRun : List Bool → Addrs w → List (Option (BitVec w)) × Addrs w
  | [], s => ([], s)
  | f :: fs, s =>
    let r := if f then addrsNext s else addrsNextBack s
    (r.1 :: (addrsRun fs r.2).1, (addrsRun fs r.2).2)

/-- The single steps of `Addrs`, proved there by `bv_decide` at 32 and 128 bits. -/
structure StepFacts (w : Nat) : Prop where
  up : ∀ base mask bits y : BitVec w, base &&& mask = base → bits &&& mask = base →
    bits ≠ base ||| ~~~mask →
    stepUp base mask bits &&& mask = base ∧ bits < stepUp base mask bits ∧
      (y &&& mask = base → bits < y → stepUp base mask bits ≤ y)
  down : ∀ base mask bits y : BitVec w, base &&& mask = base → bits &&& mask = base →
    bits ≠ base →
    stepDown base mask bits &&& mask = base ∧ stepDown base mask bits < bits ∧
      (y &&& mask = base → y < bits → y ≤ stepDown base mask bits)
  upFast : ∀ base mask bits : BitVec w, base &&& mask = base → bits &&& mask = base →
    ~~~mask &&& (~~~mask + 1) = 0 → bits ≠ base ||| ~~~mask → bits + 1 = stepUp base mask bits
  downFast : ∀ base mask bits : BitVec w, base &&& mask = base → bits &&& mask = base →
    ~~~mask &&& (~~~mask + 1) = 0 → bits ≠ base → bits - 1 = stepDown base mask bits

theorem stepFacts32 : StepFacts 32 :=
  ⟨Ipv4.next_step, Ipv4.nextBack_step, Ipv4.next_fastPath, Ipv4.nextBack_fastPath⟩

theorem stepFacts128 : StepFacts 128 :=
  ⟨Ipv6.next_step, Ipv6.nextBack_step, Ipv6.next_fastPath, Ipv6.nextBack_fastPath⟩

/-! ## Steps between members -/

variable {a m : BitVec w}

theorem hostAddr_le_hostAddr (hn : Normalized a m) {i j : Nat} (hij : i ≤ j)
    (hj : j < 2 ^ hostBits m) : hostAddr a m i ≤ hostAddr a m j := by
  rcases Nat.lt_or_eq_of_le hij with h | rfl
  · exact BitVec.le_of_lt (Netip.hostAddr_lt_hostAddr hn h hj)
  · exact BitVec.le_refl _

theorem hostAddr_ne_last (hn : Normalized a m) {i : Nat} (hi : i + 1 < 2 ^ hostBits m) :
    hostAddr a m i ≠ a ||| ~~~m := by
  rw [← Netip.hostAddr_last]
  exact BitVec.ne_of_lt (Netip.hostAddr_lt_hostAddr hn (by omega) (by omega))

theorem hostAddr_ne_first (hn : Normalized a m) {i : Nat} (hi0 : 0 < i) (hi : i < 2 ^ hostBits m) :
    hostAddr a m i ≠ a := by
  intro h
  have := Netip.hostAddr_lt_hostAddr hn hi0 hi
  rw [Netip.hostAddr_zero, h] at this
  exact absurd this (BitVec.lt_irrefl _)

/-- The general step of `next` moves from host index `i` to `i + 1`. -/
theorem stepUp_hostAddr (hf : StepFacts w) (hn : Normalized a m) {i : Nat}
    (hi : i + 1 < 2 ^ hostBits m) : stepUp a m (hostAddr a m i) = hostAddr a m (i + 1) := by
  obtain ⟨hr, hlt, hmin⟩ := hf.up a m (hostAddr a m i) (hostAddr a m (i + 1)) hn
    (Netip.hostAddr_mem hn i) (hostAddr_ne_last hn hi)
  obtain ⟨j, hj, hjeq⟩ := Netip.exists_hostAddr hr
  have h1 : i < j := by
    apply Classical.byContradiction
    intro h
    have := hostAddr_le_hostAddr hn (show j ≤ i by omega) (by omega)
    rw [hjeq] at this
    exact absurd hlt (BitVec.not_lt.mpr this)
  have h2 : j ≤ i + 1 := by
    apply Classical.byContradiction
    intro h
    have hgt := Netip.hostAddr_lt_hostAddr hn (show i + 1 < j by omega) hj
    rw [hjeq] at hgt
    have hle := hmin (Netip.hostAddr_mem hn (i + 1))
      (Netip.hostAddr_lt_hostAddr hn (Nat.lt_succ_self i) hi)
    exact absurd hle (BitVec.not_le.mpr hgt)
  rw [← hjeq, show j = i + 1 by omega]

/-- The general step of `next_back` moves from host index `i` to `i - 1`. -/
theorem stepDown_hostAddr (hf : StepFacts w) (hn : Normalized a m) {i : Nat} (hi0 : 0 < i)
    (hi : i < 2 ^ hostBits m) : stepDown a m (hostAddr a m i) = hostAddr a m (i - 1) := by
  obtain ⟨hr, hlt, hmax⟩ := hf.down a m (hostAddr a m i) (hostAddr a m (i - 1)) hn
    (Netip.hostAddr_mem hn i) (hostAddr_ne_first hn hi0 hi)
  obtain ⟨j, hj, hjeq⟩ := Netip.exists_hostAddr hr
  have h1 : j < i := by
    apply Classical.byContradiction
    intro h
    have := hostAddr_le_hostAddr hn (show i ≤ j by omega) hj
    rw [hjeq] at this
    exact absurd hlt (BitVec.not_lt.mpr this)
  have h2 : i - 1 ≤ j := by
    apply Classical.byContradiction
    intro h
    have hlt' := Netip.hostAddr_lt_hostAddr hn (show j < i - 1 by omega) (by omega)
    rw [hjeq] at hlt'
    have hle := hmax (Netip.hostAddr_mem hn (i - 1))
      (Netip.hostAddr_lt_hostAddr hn (show i - 1 < i by omega) hi)
    exact absurd hle (BitVec.not_le.mpr hlt')
  rw [← hjeq, show j = i - 1 by omega]

/-- `next` moves the front cursor from host index `i` to `i + 1`, on either path. -/
theorem front_step (hf : StepFacts w) (hn : Normalized a m) {i : Nat} (hi : i + 1 < 2 ^ hostBits m) :
    (if ~~~m &&& (~~~m + 1) = 0 then hostAddr a m i + 1 else stepUp a m (hostAddr a m i)) =
      hostAddr a m (i + 1) := by
  split
  · rw [hf.upFast a m _ hn (Netip.hostAddr_mem hn i) ‹_› (hostAddr_ne_last hn hi)]
    exact stepUp_hostAddr hf hn hi
  · exact stepUp_hostAddr hf hn hi

/-- `next_back` moves the back cursor from host index `i` to `i - 1`, on either path. -/
theorem back_step (hf : StepFacts w) (hn : Normalized a m) {i : Nat} (hi0 : 0 < i)
    (hi : i < 2 ^ hostBits m) :
    (if ~~~m &&& (~~~m + 1) = 0 then hostAddr a m i - 1 else stepDown a m (hostAddr a m i)) =
      hostAddr a m (i - 1) := by
  split
  · rw [hf.downFast a m _ hn (Netip.hostAddr_mem hn i) ‹_› (hostAddr_ne_first hn hi0 hi)]
    exact stepDown_hostAddr hf hn hi0 hi
  · exact stepDown_hostAddr hf hn hi0 hi

/-! ## A whole run -/

/-- The state after `f` calls of `next()` and `b` of `next_back()`, from a count `R`. -/
def AddrsInv (a m : BitVec w) (R : Nat) (s : Addrs w) (f b : Nat) : Prop :=
  s.base = a ∧ s.mask = m ∧ s.remaining = R - (f + b) ∧
    (f + b < R → s.front = hostAddr a m f ∧ s.back = hostAddr a m (2 ^ hostBits m - 1 - b))

theorem addrsNext_spec (hf : StepFacts w) (hn : Normalized a m) {R : Nat} (hR : R ≤ 2 ^ hostBits m)
    {s : Addrs w} {f b : Nat} (h : AddrsInv a m R s f b) :
    (addrsNext s).1 = (if f + b < R then some (hostAddr a m f) else none) ∧
      AddrsInv a m R (addrsNext s).2 (f + 1) b := by
  obtain ⟨sb, sm, sf, sk, sr⟩ := s
  obtain ⟨hb, hm, hr, hc⟩ := h
  simp only at hb hm hr hc
  subst sb sm
  by_cases hlt : f + b < R
  · obtain ⟨hfr, hbk⟩ := hc hlt
    subst sf sk
    have hr0 : sr ≠ 0 := by omega
    simp only [addrsNext, ite_eq_right hr0, ite_eq_left hlt, true_and]
    refine ⟨rfl, rfl, by dsimp only; omega, fun hlt' => ?_⟩
    have hr1 : ¬ (sr - 1 = 0) := by omega
    simp only [ite_eq_right hr1, and_true]
    exact front_step hf hn (i := f) (by omega)
  · have hr0 : sr = 0 := by omega
    simp only [addrsNext, ite_eq_left hr0, ite_eq_right hlt, true_and]
    exact ⟨rfl, rfl, by dsimp only; omega, fun h' => absurd h' (by omega)⟩

theorem addrsNextBack_spec (hf : StepFacts w) (hn : Normalized a m) {R : Nat}
    (hR : R ≤ 2 ^ hostBits m) {s : Addrs w} {f b : Nat} (h : AddrsInv a m R s f b) :
    (addrsNextBack s).1 =
        (if f + b < R then some (hostAddr a m (2 ^ hostBits m - 1 - b)) else none) ∧
      AddrsInv a m R (addrsNextBack s).2 f (b + 1) := by
  obtain ⟨sb, sm, sf, sk, sr⟩ := s
  obtain ⟨hb, hm, hr, hc⟩ := h
  simp only at hb hm hr hc
  subst sb sm
  by_cases hlt : f + b < R
  · obtain ⟨hfr, hbk⟩ := hc hlt
    subst sf sk
    have hr0 : sr ≠ 0 := by omega
    simp only [addrsNextBack, ite_eq_right hr0, ite_eq_left hlt, true_and]
    refine ⟨rfl, rfl, by dsimp only; omega, fun hlt' => ?_⟩
    have hr1 : ¬ (sr - 1 = 0) := by omega
    simp only [ite_eq_right hr1, true_and]
    rw [back_step hf hn (i := 2 ^ hostBits m - 1 - b) (by omega) (by omega), Nat.sub_sub]
  · have hr0 : sr = 0 := by omega
    simp only [addrsNextBack, ite_eq_left hr0, ite_eq_right hlt, true_and]
    exact ⟨rfl, rfl, by dsimp only; omega, fun h' => absurd h' (by omega)⟩

/-- Every call of every schedule returns what `expected` says, and the state keeps
its invariant. -/
theorem addrsRun_spec (hf : StepFacts w) (hn : Normalized a m) {R : Nat}
    (hR : R ≤ 2 ^ hostBits m) :
    ∀ (fs : List Bool) (s : Addrs w) (f b : Nat), AddrsInv a m R s f b →
      (addrsRun fs s).1 = expected (hostAddr a m) (2 ^ hostBits m) R f b fs ∧
        AddrsInv a m R (addrsRun fs s).2 (f + fs.count true) (b + fs.count false) := by
  intro fs
  induction fs with
  | nil => intro s f b h; exact ⟨rfl, h⟩
  | cons x fs ih =>
    intro s f b h
    cases x
    · obtain ⟨h1, h2⟩ := addrsNextBack_spec hf hn hR h
      obtain ⟨h3, h4⟩ := ih _ f (b + 1) h2
      have hc1 : (false :: fs).count true = fs.count true := by simp
      have hc2 : (false :: fs).count false = fs.count false + 1 := by simp
      refine ⟨?_, ?_⟩
      · simp only [addrsRun, Bool.false_eq_true, ↓reduceIte, expected, h1, h3]
      · simp only [addrsRun, Bool.false_eq_true, ↓reduceIte, hc1, hc2]
        rw [show b + (fs.count false + 1) = b + 1 + fs.count false by omega]
        exact h4
    · obtain ⟨h1, h2⟩ := addrsNext_spec hf hn hR h
      obtain ⟨h3, h4⟩ := ih _ (f + 1) b h2
      have hc1 : (true :: fs).count true = fs.count true + 1 := by simp
      have hc2 : (true :: fs).count false = fs.count false := by simp
      refine ⟨?_, ?_⟩
      · simp only [addrsRun, ↓reduceIte, expected, h1, h3]
      · simp only [addrsRun, ↓reduceIte, hc1, hc2]
        rw [show f + (fs.count true + 1) = f + 1 + fs.count true by omega]
        exact h4

theorem count_true_add_count_false : ∀ l : List Bool, l.count true + l.count false = l.length
  | [] => rfl
  | x :: l => by
    have := count_true_add_count_false l
    cases x <;> simp <;> omega

/-- Forward iteration returns the items in order. -/
theorem expected_front {g : Nat → BitVec w} {K R : Nat} :
    ∀ (n f : Nat), expected g K R f 0 (List.replicate n true) =
      (List.range' f n).map fun i => if i < R then some (g i) else none := by
  intro n
  induction n with
  | zero => intro f; rfl
  | succ n ih =>
    intro f
    rw [List.replicate_succ, List.range'_succ, List.map_cons, expected, ih (f + 1), Nat.add_zero]

/-- Backward iteration returns the items in reverse order. -/
theorem expected_back {g : Nat → BitVec w} {K R : Nat} :
    ∀ (n b : Nat), expected g K R 0 b (List.replicate n false) =
      (List.range' b n).map fun j => if j < R then some (g (K - 1 - j)) else none := by
  intro n
  induction n with
  | zero => intro b; rfl
  | succ n ih =>
    intro b
    rw [List.replicate_succ, List.range'_succ, List.map_cons, expected, ih (b + 1), Nat.zero_add]

theorem addrsRun_append : ∀ (xs ys : List Bool) (s : Addrs w),
    addrsRun (xs ++ ys) s =
      ((addrsRun xs s).1 ++ (addrsRun ys (addrsRun xs s).2).1, (addrsRun ys (addrsRun xs s).2).2)
  | [], _, _ => rfl
  | x :: xs, ys, s => by
    simp only [List.cons_append, addrsRun, addrsRun_append xs ys, List.cons_append]

/-- An exhausted iterator returns `None` and stays as it is. -/
theorem addrsRun_exhausted {s : Addrs w} (h : s.remaining = 0) :
    ∀ fs : List Bool, addrsRun fs s = (fs.map fun _ => none, s) := by
  intro fs
  induction fs with
  | nil => rfl
  | cons x fs ih =>
    have h1 : addrsNext s = (none, s) := by simp [addrsNext, h]
    have h2 : addrsNextBack s = (none, s) := by simp [addrsNextBack, h]
    cases x <;> simp [addrsRun, h1, h2, ih]

/-- `remaining` is the number of addresses still to come: any schedule of `c`
calls returns `min c remaining` of them. -/
theorem addrs_remaining (hf : StepFacts w) (hn : Normalized a m) {R : Nat}
    (hR : R ≤ 2 ^ hostBits m) {s : Addrs w} {f b : Nat} (h : AddrsInv a m R s f b)
    (fs : List Bool) : ((addrsRun fs s).1.filterMap id).length = min fs.length s.remaining := by
  rw [(addrsRun_spec hf hn hR fs s f b h).1, expected_length, h.2.2.1]

/-- The state after the call that returns the last address. If it is `next_back()`,
both cursors are parked on `base`; if it is `next()`, only the front cursor is, and
the back cursor keeps the member it reached. Later calls change nothing. -/
theorem addrs_drain_state (hf : StepFacts w) (hn : Normalized a m) {R : Nat}
    (hR : R ≤ 2 ^ hostBits m) {s : Addrs w} (hs : AddrsInv a m R s 0 0) (pre : List Bool)
    (last : Bool) (post : List Bool) (hlen : pre.length + 1 = R) :
    (addrsRun (pre ++ last :: post) s).2 =
      if last then ⟨a, m, a, hostAddr a m (2 ^ hostBits m - 1 - pre.count false), 0⟩
      else ⟨a, m, a, a, 0⟩ := by
  have hcount := count_true_add_count_false pre
  obtain ⟨-, hinv⟩ := addrsRun_spec hf hn hR pre s 0 0 hs
  rw [Nat.zero_add, Nat.zero_add] at hinv
  rw [addrsRun_append]
  generalize (addrsRun pre s).2 = s1 at hinv ⊢
  obtain ⟨sb, sm, sf, sk, sr⟩ := s1
  obtain ⟨hb, hm, hr, hc⟩ := hinv
  simp only at hb hm hr hc
  obtain ⟨hfr, hbk⟩ := hc (by omega)
  subst sb sm sf sk
  have hr1 : sr = 1 := by omega
  subst hr1
  cases last
  · simp only [addrsRun, Bool.false_eq_true, ↓reduceIte, addrsNextBack]
    rw [(addrsRun_exhausted (by rfl) post)]
    rfl
  · simp only [addrsRun, ↓reduceIte, addrsNext]
    rw [(addrsRun_exhausted (by rfl) post)]
    rfl

/-! ## `size_hint` -/

/-- `size_hint` for a count of `r` items with a `usize` of `ub` bits:
`usize::try_from(r)`, saturating to `(usize::MAX, None)` when it does not fit.
`count()` is its first component, and `len()` (64-bit targets only) the count. -/
def sizeHint (ub r : Nat) : Nat × Option Nat := if r < 2 ^ ub then (r, some r) else (2 ^ ub - 1, none)

/-! ## `Ipv4NetworkAddrs` -/

namespace Ipv4

/-- `Ipv4Network::addrs`: `remaining = 1u64 << host_bits`. -/
def addrsInit (addr mask : BitVec 32) : Addrs 32 :=
  ⟨addr, mask, addr, addr ||| ~~~mask, (1#64 <<< (~~~mask).cpop.toNat).toNat⟩

theorem addrsInit_remaining (addr mask : BitVec 32) :
    (addrsInit addr mask).remaining = 2 ^ hostBits mask := by
  have hk : hostBits mask ≤ 32 := Netip.hostBits_le mask
  simp only [addrsInit, BitVec.toNat_shiftLeft, Netip.cpop_not_eq_hostBits]
  rw [show (1#64).toNat = 1 from rfl, Nat.shiftLeft_eq, Nat.one_mul,
    Nat.mod_eq_of_lt (Nat.pow_lt_pow_right (by decide) (by omega))]

theorem addrsInit_inv (addr mask : BitVec 32) :
    AddrsInv addr mask (2 ^ hostBits mask) (addrsInit addr mask) 0 0 :=
  ⟨rfl, rfl, by rw [addrsInit_remaining]; simp, fun _ =>
    ⟨(Netip.hostAddr_zero addr mask).symm, by rw [Nat.sub_zero, Netip.hostAddr_last]; rfl⟩⟩

/-- On every schedule, `next()` returns the members in host-index order from the
first and `next_back()` from the last, until all `2^(host bits)` are returned. -/
theorem addrs_run {addr mask : BitVec 32} (hn : addr &&& mask = addr) (fs : List Bool) :
    (addrsRun fs (addrsInit addr mask)).1 =
      expected (hostAddr addr mask) (2 ^ hostBits mask) (2 ^ hostBits mask) 0 0 fs :=
  (addrsRun_spec stepFacts32 hn (Nat.le_refl _) fs _ 0 0 (addrsInit_inv addr mask)).1

/-- `collect()` lists the members in host-index order, which is ascending. -/
theorem addrs_collect {addr mask : BitVec 32} (hn : addr &&& mask = addr) :
    (addrsRun (List.replicate (2 ^ hostBits mask) true) (addrsInit addr mask)).1 =
      (Netip.members addr mask).map some := by
  rw [addrs_run hn, expected_front, Netip.members, List.range_eq_range', List.map_map]
  apply List.map_congr_left
  intro i hi
  rw [List.mem_range'_1] at hi
  have : i < 2 ^ hostBits mask := by omega
  simp [this]

/-- `rev().collect()` lists them in reverse. -/
theorem addrs_collect_rev {addr mask : BitVec 32} (hn : addr &&& mask = addr) :
    (addrsRun (List.replicate (2 ^ hostBits mask) false) (addrsInit addr mask)).1 =
      (Netip.members addr mask).reverse.map some := by
  rw [addrs_run hn, expected_back, Netip.members, ← List.map_reverse, List.range_eq_range',
    List.reverse_range', ← List.range_eq_range', List.map_map, List.map_map]
  apply List.map_congr_left
  intro j hj
  rw [List.mem_range] at hj
  simp [hj]

/-- However the calls interleave, once `2^(host bits)` of them are made every member
has been returned exactly once. -/
theorem addrs_exactly_once {addr mask : BitVec 32} (hn : addr &&& mask = addr) (fs : List Bool)
    (hlen : 2 ^ hostBits mask ≤ fs.length) :
    ((addrsRun fs (addrsInit addr mask)).1.filterMap id).Perm (Netip.members addr mask) := by
  rw [addrs_run hn, Netip.members, List.range_eq_range']
  exact expected_perm fs 0 0 (Nat.zero_le _) (by omega)

/-- `size_hint()`, `count()` and `len()` are exact on 64-bit targets in every state,
and start at `2^(host bits)`. -/
theorem addrs_sizeHint {addr mask : BitVec 32} (hn : addr &&& mask = addr) (fs : List Bool) :
    sizeHint 64 (addrsRun fs (addrsInit addr mask)).2.remaining =
      ((addrsRun fs (addrsInit addr mask)).2.remaining,
        some (addrsRun fs (addrsInit addr mask)).2.remaining) ∧
    (addrsInit addr mask).remaining = 2 ^ hostBits mask := by
  have hk : hostBits mask ≤ 32 := Netip.hostBits_le mask
  obtain ⟨-, hinv⟩ := addrsRun_spec stepFacts32 hn (Nat.le_refl _) fs _ 0 0 (addrsInit_inv addr mask)
  have hle : (addrsRun fs (addrsInit addr mask)).2.remaining ≤ 2 ^ 32 := by
    rw [hinv.2.2.1]
    have := Nat.pow_le_pow_right (show 0 < 2 by decide) hk
    omega
  have hlt : (addrsRun fs (addrsInit addr mask)).2.remaining < 2 ^ 64 := by
    have : 2 ^ 32 < 2 ^ 64 := by decide
    omega
  exact ⟨by rw [sizeHint, ite_eq_left hlt], addrsInit_remaining addr mask⟩

end Ipv4

/-! ## `Ipv6NetworkAddrs` -/

namespace Ipv6

/-- `Ipv6Network::addrs`: `remaining = 1u128.checked_shl(host_bits).unwrap_or(u128::MAX)`. -/
def addrsInit (addr mask : BitVec 128) : Addrs 128 :=
  ⟨addr, mask, addr, addr ||| ~~~mask,
    if (~~~mask).cpop.toNat < 128 then (1#128 <<< (~~~mask).cpop.toNat).toNat
    else (BitVec.allOnes 128).toNat⟩

/-- The initial count: `2^(host bits)`, saturated to `2^128 - 1` for the `/0`. -/
def addrsCount (mask : BitVec 128) : Nat :=
  if hostBits mask < 128 then 2 ^ hostBits mask else 2 ^ 128 - 1

theorem addrsInit_remaining (addr mask : BitVec 128) :
    (addrsInit addr mask).remaining = addrsCount mask := by
  simp only [addrsInit, addrsCount, Netip.cpop_not_eq_hostBits]
  split
  · rename_i hk
    rw [BitVec.toNat_shiftLeft, show (1#128).toNat = 1 from rfl, Nat.shiftLeft_eq, Nat.one_mul,
      Nat.mod_eq_of_lt (Nat.pow_lt_pow_right (by decide) hk)]
  · rw [BitVec.toNat_allOnes]

theorem addrsCount_le (mask : BitVec 128) : addrsCount mask ≤ 2 ^ hostBits mask := by
  unfold addrsCount
  split
  · exact Nat.le_refl _
  · rename_i hk
    have : hostBits mask = 128 := by have := Netip.hostBits_le mask; omega
    rw [this]
    omega

theorem addrsInit_inv (addr mask : BitVec 128) :
    AddrsInv addr mask (addrsCount mask) (addrsInit addr mask) 0 0 :=
  ⟨rfl, rfl, by rw [addrsInit_remaining]; simp, fun _ =>
    ⟨(Netip.hostAddr_zero addr mask).symm, by rw [Nat.sub_zero, Netip.hostAddr_last]; rfl⟩⟩

/-- On every schedule, `next()` returns the members in host-index order from the
first and `next_back()` from the last, until `2^(host bits)` are returned, or
`2^128 - 1` for the `/0`. -/
theorem addrs_run {addr mask : BitVec 128} (hn : addr &&& mask = addr) (fs : List Bool) :
    (addrsRun fs (addrsInit addr mask)).1 =
      expected (hostAddr addr mask) (2 ^ hostBits mask) (addrsCount mask) 0 0 fs :=
  (addrsRun_spec stepFacts128 hn (addrsCount_le mask) fs _ 0 0 (addrsInit_inv addr mask)).1

/-- Every schedule of fewer than `2^128` calls, the `/0` included, returns what an
exact count would. -/
theorem addrs_run_exact {addr mask : BitVec 128} (hn : addr &&& mask = addr) (fs : List Bool)
    (hlen : fs.length ≤ 2 ^ 128 - 1) :
    (addrsRun fs (addrsInit addr mask)).1 =
      expected (hostAddr addr mask) (2 ^ hostBits mask) (2 ^ hostBits mask) 0 0 fs := by
  rw [addrs_run hn]
  unfold addrsCount
  split
  · rfl
  · rename_i hk
    have h128 : hostBits mask = 128 := by have := Netip.hostBits_le mask; omega
    rw [h128]
    apply expected_count <;> omega

/-- `collect()` lists the members in host-index order, which is ascending. -/
theorem addrs_collect {addr mask : BitVec 128} (hn : addr &&& mask = addr)
    (hk : hostBits mask < 128) :
    (addrsRun (List.replicate (2 ^ hostBits mask) true) (addrsInit addr mask)).1 =
      (Netip.members addr mask).map some := by
  rw [addrs_run hn, expected_front, Netip.members, List.range_eq_range', List.map_map]
  apply List.map_congr_left
  intro i hi
  rw [List.mem_range'_1] at hi
  have : i < addrsCount mask := by simp only [addrsCount, hk, ↓reduceIte]; omega
  simp [this]

/-- `rev().collect()` lists them in reverse. -/
theorem addrs_collect_rev {addr mask : BitVec 128} (hn : addr &&& mask = addr)
    (hk : hostBits mask < 128) :
    (addrsRun (List.replicate (2 ^ hostBits mask) false) (addrsInit addr mask)).1 =
      (Netip.members addr mask).reverse.map some := by
  rw [addrs_run hn, expected_back, Netip.members, ← List.map_reverse, List.range_eq_range',
    List.reverse_range', ← List.range_eq_range', List.map_map, List.map_map]
  apply List.map_congr_left
  intro j hj
  rw [List.mem_range] at hj
  have : j < addrsCount mask := by simp only [addrsCount, hk, ↓reduceIte]; omega
  simp [this]

/-- However the calls interleave, once `2^(host bits)` of them are made every member
has been returned exactly once. The `/0` stops one address short. -/
theorem addrs_exactly_once {addr mask : BitVec 128} (hn : addr &&& mask = addr)
    (hk : hostBits mask < 128) (fs : List Bool) (hlen : 2 ^ hostBits mask ≤ fs.length) :
    ((addrsRun fs (addrsInit addr mask)).1.filterMap id).Perm (Netip.members addr mask) := by
  rw [addrs_run hn, Netip.members, List.range_eq_range', show addrsCount mask = 2 ^ hostBits mask by
    simp [addrsCount, hk]]
  exact expected_perm fs 0 0 (Nat.zero_le _) (by omega)

end Ipv6

/-! ## The cursor iterators -/

theorem toNat_one_w (hw : 0 < w) : (1 : BitVec w).toNat = 1 := BitVec.toNat_one hw

theorem toNat_zero_w : (0 : BitVec w).toNat = 0 := rfl

theorem zero_lt_one_w (hw : 0 < w) : (0 : BitVec w) < 1 := by
  rw [BitVec.lt_def, toNat_one_w hw]
  exact Nat.one_pos

/-- `x + 1` wraps to `0` exactly at the largest value. -/
theorem toNat_add_one (hw : 0 < w) (x : BitVec w) :
    (x + 1).toNat = if x.toNat = 2 ^ w - 1 then 0 else x.toNat + 1 := by
  rw [BitVec.toNat_add, toNat_one_w hw]
  have := x.isLt
  split
  · rw [show x.toNat + 1 = 2 ^ w by omega, Nat.mod_self]
  · exact Nat.mod_eq_of_lt (by omega)

theorem toNat_sub_one (hw : 0 < w) (x : BitVec w) (hx : x.toNat ≠ 0) : (x - 1).toNat = x.toNat - 1 := by
  rw [BitVec.toNat_sub, toNat_one_w hw]
  have := x.isLt
  rw [show 2 ^ w - 1 + x.toNat = (x.toNat - 1) + 2 ^ w by omega, Nat.add_mod_right,
    Nat.mod_eq_of_lt (by omega)]

/-- The cursor pair of `ContiguousIpv4NetworkAddrs` (`front`, `back`: host
indices), `ContiguousIpv6NetworkAddrs` (`current`, `last`: addresses) and
`BiContiguousIpv6Addrs` (`front`, `back`: host indices). `hi < lo` is exhausted. -/
structure Cursor (w : Nat) where
  lo : BitVec w
  hi : BitVec w

/-- `next`: returns `lo` and steps it, entering the sentinel `(1, 0)` when it wraps. -/
def cursorNext (c : Cursor w) : Option (BitVec w) × Cursor w :=
  if c.hi < c.lo then (none, c)
  else if c.lo + 1 = 0 then (some c.lo, ⟨1, 0⟩)
  else (some c.lo, ⟨c.lo + 1, c.hi⟩)

/-- `next_back`: returns `hi` and steps it, entering the sentinel `(1, 0)` when the
cursors meet. -/
def cursorNextBack (c : Cursor w) : Option (BitVec w) × Cursor w :=
  if c.hi < c.lo then (none, c)
  else if c.lo = c.hi then (some c.hi, ⟨1, 0⟩)
  else (some c.hi, ⟨c.lo, c.hi - 1⟩)

/-- Runs a schedule of calls, collecting what each returns, and the final state. -/
def cursorRun : List Bool → Cursor w → List (Option (BitVec w)) × Cursor w
  | [], c => ([], c)
  | f :: fs, c =>
    let r := if f then cursorNext c else cursorNextBack c
    (r.1 :: (cursorRun fs r.2).1, (cursorRun fs r.2).2)

/-- The number of values left, `remaining()` of `ContiguousIpv4NetworkAddrs`. -/
def cursorCount (c : Cursor w) : Nat := if c.hi < c.lo then 0 else (c.hi - c.lo).toNat + 1

/-- After `f` calls of `next()` and `b` of `next_back()` on the `N` values from `L`:
the values `L + f ..= L + N - 1 - b` are left, or the cursors have crossed. -/
def CursorInv (L N : Nat) (c : Cursor w) (f b : Nat) : Prop :=
  (f + b < N → c.lo.toNat = L + f ∧ c.hi.toNat = L + N - 1 - b) ∧ (N ≤ f + b → c.hi < c.lo)

theorem cursorNext_spec (hw : 0 < w) {L N : Nat} (hLN : L + N ≤ 2 ^ w) {c : Cursor w} {f b : Nat}
    (h : CursorInv L N c f b) :
    (cursorNext c).1 = (if f + b < N then some (BitVec.ofNat w (L + f)) else none) ∧
      CursorInv L N (cursorNext c).2 (f + 1) b := by
  obtain ⟨hin, hout⟩ := h
  by_cases hlt : f + b < N
  · obtain ⟨hlo, hhi⟩ := hin hlt
    have hnot : ¬ c.hi < c.lo := by rw [BitVec.lt_def]; omega
    have hval : c.lo = BitVec.ofNat w (L + f) := by
      apply BitVec.eq_of_toNat_eq
      rw [hlo, BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega)]
    have hstep := toNat_add_one hw c.lo
    rw [cursorNext, ite_eq_right hnot, ite_eq_left hlt]
    by_cases hwrap : c.lo + 1 = 0
    · rw [ite_eq_left hwrap]
      have hmax : c.lo.toNat = 2 ^ w - 1 := by
        rw [hwrap] at hstep
        split at hstep
        · assumption
        · exact absurd hstep (by rw [toNat_zero_w]; omega)
      refine ⟨by rw [hval], fun h' => absurd h' (by omega), fun _ => zero_lt_one_w hw⟩
    · rw [ite_eq_right hwrap]
      have hsucc : (c.lo + 1).toNat = c.lo.toNat + 1 := by
        rw [hstep]
        split
        · exact absurd (BitVec.eq_of_toNat_eq (by rw [hstep, ite_eq_left ‹_›]; rfl)) hwrap
        · rfl
      refine ⟨by rw [hval], fun h' => ⟨by simp only; rw [hsucc, hlo]; omega, hhi⟩, fun h' => ?_⟩
      simp only
      rw [BitVec.lt_def, hsucc]
      omega
  · rw [cursorNext, ite_eq_left (hout (by omega)), ite_eq_right hlt]
    exact ⟨rfl, fun h' => absurd h' (by omega), fun _ => hout (by omega)⟩

theorem cursorNextBack_spec (hw : 0 < w) {L N : Nat} (hLN : L + N ≤ 2 ^ w) {c : Cursor w}
    {f b : Nat} (h : CursorInv L N c f b) :
    (cursorNextBack c).1 = (if f + b < N then some (BitVec.ofNat w (L + (N - 1 - b))) else none) ∧
      CursorInv L N (cursorNextBack c).2 f (b + 1) := by
  obtain ⟨hin, hout⟩ := h
  by_cases hlt : f + b < N
  · obtain ⟨hlo, hhi⟩ := hin hlt
    have hnot : ¬ c.hi < c.lo := by rw [BitVec.lt_def]; omega
    have hval : c.hi = BitVec.ofNat w (L + (N - 1 - b)) := by
      apply BitVec.eq_of_toNat_eq
      rw [hhi, BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega)]
      omega
    rw [cursorNextBack, ite_eq_right hnot, ite_eq_left hlt]
    by_cases hmeet : c.lo = c.hi
    · rw [ite_eq_left hmeet]
      have : c.lo.toNat = c.hi.toNat := by rw [hmeet]
      refine ⟨by rw [hval], fun h' => absurd h' (by omega), fun _ => zero_lt_one_w hw⟩
    · rw [ite_eq_right hmeet]
      have hne : c.lo.toNat ≠ c.hi.toNat := fun h' => hmeet (BitVec.eq_of_toNat_eq h')
      have hpred := toNat_sub_one hw c.hi (by omega)
      refine ⟨by rw [hval], fun h' => ⟨hlo, by simp only; rw [hpred, hhi]; omega⟩,
        fun h' => absurd h' (by omega)⟩
  · rw [cursorNextBack, ite_eq_left (hout (by omega)), ite_eq_right hlt]
    exact ⟨rfl, fun h' => absurd h' (by omega), fun _ => hout (by omega)⟩

/-- Every call of every schedule returns the value `L + f` from the front or
`L + N - 1 - b` from the back, until the `N` values are used up. -/
theorem cursorRun_spec (hw : 0 < w) {L N : Nat} (hLN : L + N ≤ 2 ^ w) :
    ∀ (fs : List Bool) (c : Cursor w) (f b : Nat), CursorInv L N c f b →
      (cursorRun fs c).1 = expected (fun i => BitVec.ofNat w (L + i)) N N f b fs ∧
        CursorInv L N (cursorRun fs c).2 (f + fs.count true) (b + fs.count false) := by
  intro fs
  induction fs with
  | nil => intro c f b h; exact ⟨rfl, h⟩
  | cons x fs ih =>
    intro c f b h
    cases x
    · obtain ⟨h1, h2⟩ := cursorNextBack_spec hw hLN h
      obtain ⟨h3, h4⟩ := ih _ f (b + 1) h2
      have hc1 : (false :: fs).count true = fs.count true := by simp
      have hc2 : (false :: fs).count false = fs.count false + 1 := by simp
      refine ⟨?_, ?_⟩
      · simp only [cursorRun, Bool.false_eq_true, ↓reduceIte, expected, h1, h3]
      · simp only [cursorRun, Bool.false_eq_true, ↓reduceIte, hc1, hc2]
        rw [show b + (fs.count false + 1) = b + 1 + fs.count false by omega]
        exact h4
    · obtain ⟨h1, h2⟩ := cursorNext_spec hw hLN h
      obtain ⟨h3, h4⟩ := ih _ (f + 1) b h2
      have hc1 : (true :: fs).count true = fs.count true + 1 := by simp
      have hc2 : (true :: fs).count false = fs.count false := by simp
      refine ⟨?_, ?_⟩
      · simp only [cursorRun, ↓reduceIte, expected, h1, h3]
      · simp only [cursorRun, ↓reduceIte, hc1, hc2]
        rw [show f + (fs.count true + 1) = f + 1 + fs.count true by omega]
        exact h4

/-- Once the cursors cross, every call returns `None` and changes nothing. -/
theorem cursorRun_exhausted {c : Cursor w} (h : c.hi < c.lo) :
    ∀ fs : List Bool, cursorRun fs c = (fs.map fun _ => none, c) := by
  intro fs
  induction fs with
  | nil => rfl
  | cons x fs ih =>
    have h1 : cursorNext c = (none, c) := by simp [cursorNext, h]
    have h2 : cursorNextBack c = (none, c) := by simp [cursorNextBack, h]
    cases x <;> simp [cursorRun, h1, h2, ih]

/-- `remaining()` counts the values left. -/
theorem cursorCount_eq {L N : Nat} {c : Cursor w} {f b : Nat} (h : CursorInv L N c f b) :
    cursorCount c = N - (f + b) := by
  unfold cursorCount
  by_cases hlt : f + b < N
  · obtain ⟨hlo, hhi⟩ := h.1 hlt
    have hnot : ¬ c.hi < c.lo := by rw [BitVec.lt_def]; omega
    have hle : c.lo ≤ c.hi := by rw [BitVec.le_def]; omega
    rw [ite_eq_right hnot, BitVec.toNat_sub_of_le hle, hlo, hhi]
    omega
  · rw [ite_eq_left (h.2 (by omega))]
    omega

/-! ## Contiguous masks: host-index order is index order -/

/-- With a trailing host mask (`!m & (!m + 1) == 0`, the fast path of the general
iterators), the member with host index `i` is `a + i`. -/
theorem hostAddr_eq_add_ofNat (hf : StepFacts w) (hn : Normalized a m)
    (hfast : ~~~m &&& (~~~m + 1) = 0) :
    ∀ i, i < 2 ^ hostBits m → hostAddr a m i = a + BitVec.ofNat w i := by
  intro i
  induction i with
  | zero =>
    intro _
    rw [Netip.hostAddr_zero]
    exact (BitVec.add_zero a).symm
  | succ i ih =>
    intro hi
    rw [← stepUp_hostAddr hf hn hi,
      ← hf.upFast a m _ hn (Netip.hostAddr_mem hn i) hfast (hostAddr_ne_last hn hi),
      ih (by omega), BitVec.ofNat_add, BitVec.add_assoc]
    rfl

/-- ... so `pdep` is the identity there, and the member is also `a | i`. -/
theorem deposit_eq_ofNat (hf : StepFacts w) (hn : Normalized a m) (hfast : ~~~m &&& (~~~m + 1) = 0)
    {i : Nat} (hi : i < 2 ^ hostBits m) :
    Netip.deposit m i = BitVec.ofNat w i ∧ hostAddr a m i = a ||| BitVec.ofNat w i := by
  have h := hostAddr_eq_add_ofNat hf hn hfast i hi
  rw [Netip.hostAddr_eq_add hn] at h
  have hd : Netip.deposit m i = BitVec.ofNat w i := (BitVec.add_right_inj a).mp h
  exact ⟨hd, by rw [Netip.hostAddr, hd]⟩

/-- `!m` is the largest index. -/
theorem not_eq_ofNat (hf : StepFacts w) (hfast : ~~~m &&& (~~~m + 1) = 0) :
    ~~~m = BitVec.ofNat w (2 ^ hostBits m - 1) := by
  have hn0 : Normalized (0 : BitVec w) m := by simp [Normalized]
  have := (deposit_eq_ofNat hf hn0 hfast (i := 2 ^ hostBits m - 1)
    (by have := @Nat.one_le_two_pow (hostBits m); omega)).2
  rw [Netip.hostAddr_last] at this
  simpa using this

theorem toNat_not_eq (hf : StepFacts w) (hfast : ~~~m &&& (~~~m + 1) = 0) :
    (~~~m).toNat = 2 ^ hostBits m - 1 := by
  rw [not_eq_ofNat hf hfast, BitVec.toNat_ofNat, Nat.mod_eq_of_lt]
  have := Nat.pow_le_pow_right (show 0 < 2 by decide) (Netip.hostBits_le m)
  have := Nat.two_pow_pos (hostBits m)
  omega

/-- Mapping the values of a run through the iterator's output. -/
theorem expected_map (out : BitVec w → BitVec w) {g : Nat → BitVec w} {K R : Nat} :
    ∀ (fs : List Bool) (f b : Nat),
      (expected g K R f b fs).map (Option.map out) = expected (fun i => out (g i)) K R f b fs := by
  intro fs
  induction fs with
  | nil => intro f b; rfl
  | cons x fs ih =>
    intro f b
    cases x
    · simp only [expected, List.map_cons, ih]
      split <;> rfl
    · simp only [expected, List.map_cons, ih]
      split <;> rfl

/-! ## `ContiguousIpv4NetworkAddrs` -/

namespace Ipv4

/-- `Contiguous::<Ipv4Network>::addrs`: the host indices `0 ..= back`, for
`back = u32::MAX.checked_shr(32 - host_bits).unwrap_or(0)`. A shift by the full
width gives `0` in `BitVec` as in `unwrap_or(0)`. The iterator returns `base | index`. -/
def caddrsInit (mask : BitVec 32) : Cursor 32 :=
  ⟨0, BitVec.allOnes 32 >>> (32#32 - (~~~mask).cpop)⟩

theorem caddrsInit_inv {mask : BitVec 32} (hc : IsContiguous mask) :
    CursorInv 0 (2 ^ hostBits mask) (caddrsInit mask) 0 0 := by
  have hfast := (isContiguous_iff_hostmask mask).mp hc
  refine ⟨fun _ => ⟨rfl, ?_⟩, fun h => ?_⟩
  · simp only [caddrsInit]
    rw [addrs_back mask hc, toNat_not_eq stepFacts32 hfast]
    omega
  · have := @Nat.one_le_two_pow (hostBits mask)
    omega

/-- On every schedule, `ContiguousIpv4NetworkAddrs` returns, call for call, what the
general `Ipv4NetworkAddrs` returns. -/
theorem caddrs_run {addr mask : BitVec 32} (hn : addr &&& mask = addr) (hc : IsContiguous mask)
    (fs : List Bool) :
    (cursorRun fs (caddrsInit mask)).1.map (Option.map (addr ||| ·)) =
      (addrsRun fs (addrsInit addr mask)).1 := by
  have hfast := (isContiguous_iff_hostmask mask).mp hc
  have hK : 0 + 2 ^ hostBits mask ≤ 2 ^ 32 := by
    have := Nat.pow_le_pow_right (show 0 < 2 by decide) (Netip.hostBits_le mask)
    omega
  rw [(cursorRun_spec (by decide) hK fs _ 0 0 (caddrsInit_inv hc)).1, expected_map, addrs_run hn]
  apply expected_congr (Nat.le_refl _)
  intro i hi
  rw [Nat.zero_add, (deposit_eq_ofNat stepFacts32 hn hfast hi).2]

/-- `remaining()` is the number of addresses left, and once `2^(host bits)` calls are
made the cursors have crossed, the sentinel state in which every call returns `None`. -/
theorem caddrs_remaining {mask : BitVec 32} (hc : IsContiguous mask) (fs : List Bool) :
    cursorCount (cursorRun fs (caddrsInit mask)).2 = 2 ^ hostBits mask - fs.length ∧
      (2 ^ hostBits mask ≤ fs.length →
        (cursorRun fs (caddrsInit mask)).2.hi < (cursorRun fs (caddrsInit mask)).2.lo) := by
  have hK : 0 + 2 ^ hostBits mask ≤ 2 ^ 32 := by
    have := Nat.pow_le_pow_right (show 0 < 2 by decide) (Netip.hostBits_le mask)
    omega
  obtain ⟨-, hinv⟩ := cursorRun_spec (by decide) hK fs _ 0 0 (caddrsInit_inv hc)
  have hcount := count_true_add_count_false fs
  refine ⟨by rw [cursorCount_eq hinv]; omega, fun h => hinv.2 (by omega)⟩

end Ipv4

/-! ## `ContiguousIpv6NetworkAddrs` -/

/-- `size_hint` of `ContiguousIpv6NetworkAddrs` and `BiContiguousIpv6Addrs`: the
wrapped count `hi - lo + 1` is `0` only when all `2^128` values are left. -/
def cursorSizeHint128 (ub : Nat) (c : Cursor 128) : Nat × Option Nat :=
  if c.hi < c.lo then (0, some 0)
  else if c.hi - c.lo + 1 = 0 then (2 ^ ub - 1, none)
  else sizeHint ub (c.hi - c.lo + 1).toNat

/-- It is the `size_hint` of the exact count. -/
theorem cursorSizeHint128_eq {ub : Nat} (hub : ub ≤ 128) (c : Cursor 128) :
    cursorSizeHint128 ub c = sizeHint ub (cursorCount c) := by
  have hpow : 2 ^ ub ≤ 2 ^ 128 := Nat.pow_le_pow_right (by decide) hub
  unfold cursorSizeHint128 cursorCount
  by_cases hlt : c.hi < c.lo
  · rw [ite_eq_left hlt, ite_eq_left hlt, sizeHint, ite_eq_left (Nat.two_pow_pos ub)]
  · rw [ite_eq_right hlt, ite_eq_right hlt]
    have hstep := toNat_add_one (by decide) (c.hi - c.lo)
    by_cases hwrap : c.hi - c.lo + 1 = 0
    · rw [ite_eq_left hwrap]
      have hmax : (c.hi - c.lo).toNat = 2 ^ 128 - 1 := by
        rw [hwrap] at hstep
        split at hstep
        · assumption
        · exact absurd hstep (by rw [toNat_zero_w]; omega)
      rw [sizeHint, ite_eq_right (by omega)]
    · rw [ite_eq_right hwrap, hstep]
      split
      · rename_i hmax
        exact absurd (BitVec.eq_of_toNat_eq (by rw [hstep, ite_eq_left hmax]; rfl)) hwrap
      · rfl

namespace Ipv6

/-- `Contiguous::<Ipv6Network>::addrs`: the packed addresses `addr ..= addr | back`. -/
def caddrsInit (addr mask : BitVec 128) : Cursor 128 :=
  ⟨addr, addr ||| (BitVec.allOnes 128 >>> (128#128 - (~~~mask).cpop))⟩

theorem caddrsInit_inv {addr mask : BitVec 128} (hn : addr &&& mask = addr)
    (hc : IsContiguous mask) :
    addr.toNat + 2 ^ hostBits mask ≤ 2 ^ 128 ∧
      CursorInv addr.toNat (2 ^ hostBits mask) (caddrsInit addr mask) 0 0 := by
  have hfast := (isContiguous_iff_hostmask mask).mp hc
  have hp : Netip.pdepNat (~~~mask).toNat (2 ^ hostBits mask - 1) = (~~~mask).toNat := by
    rw [← Netip.popNat_not]
    exact Netip.pdepNat_allOnes _
  have hlast : (addr ||| ~~~mask).toNat = addr.toNat + (2 ^ hostBits mask - 1) := by
    rw [← Netip.hostAddr_last, Netip.toNat_hostAddr hn, hp, toNat_not_eq stepFacts128 hfast]
  have hlt := (addr ||| ~~~mask).isLt
  have := @Nat.one_le_two_pow (hostBits mask)
  refine ⟨by omega, fun _ => ⟨by simp [caddrsInit], ?_⟩, fun h => by omega⟩
  simp only [caddrsInit]
  rw [addrs_back mask hc, hlast]
  omega

/-- On every schedule, `ContiguousIpv6NetworkAddrs` returns the members in host-index
order from both ends, call for call, as the general `Ipv6NetworkAddrs` does except
for the one address the `/0` saturation loses. -/
theorem caddrs_run {addr mask : BitVec 128} (hn : addr &&& mask = addr) (hc : IsContiguous mask)
    (fs : List Bool) :
    (cursorRun fs (caddrsInit addr mask)).1 =
      expected (hostAddr addr mask) (2 ^ hostBits mask) (2 ^ hostBits mask) 0 0 fs := by
  have hfast := (isContiguous_iff_hostmask mask).mp hc
  obtain ⟨hK, hinv⟩ := caddrsInit_inv hn hc
  rw [(cursorRun_spec (by decide) hK fs _ 0 0 hinv).1]
  apply expected_congr (Nat.le_refl _)
  intro i hi
  rw [hostAddr_eq_add_ofNat stepFacts128 hn hfast i hi, BitVec.ofNat_add, BitVec.ofNat_toNat,
    BitVec.setWidth_eq]

/-- The same sequence as `Ipv6NetworkAddrs`, for every mask but the `/0`, and for
every schedule of fewer than `2^128` calls. -/
theorem caddrs_run_eq {addr mask : BitVec 128} (hn : addr &&& mask = addr) (hc : IsContiguous mask)
    (fs : List Bool) (h : hostBits mask < 128 ∨ fs.length ≤ 2 ^ 128 - 1) :
    (cursorRun fs (caddrsInit addr mask)).1 = (addrsRun fs (addrsInit addr mask)).1 := by
  rw [caddrs_run hn hc]
  rcases h with hk | hlen
  · rw [addrs_run hn, show addrsCount mask = 2 ^ hostBits mask by simp [addrsCount, hk]]
  · rw [addrs_run_exact hn fs hlen]

/-- The count left is exact, `size_hint` saturates only above `usize::MAX`, and once
`2^(host bits)` calls are made the cursors have crossed. -/
theorem caddrs_remaining {addr mask : BitVec 128} (hn : addr &&& mask = addr)
    (hc : IsContiguous mask) (fs : List Bool) (ub : Nat) (hub : ub ≤ 128) :
    cursorCount (cursorRun fs (caddrsInit addr mask)).2 = 2 ^ hostBits mask - fs.length ∧
      cursorSizeHint128 ub (cursorRun fs (caddrsInit addr mask)).2 =
        sizeHint ub (2 ^ hostBits mask - fs.length) ∧
      (2 ^ hostBits mask ≤ fs.length →
        (cursorRun fs (caddrsInit addr mask)).2.hi < (cursorRun fs (caddrsInit addr mask)).2.lo) := by
  obtain ⟨hK, hinv0⟩ := caddrsInit_inv hn hc
  obtain ⟨-, hinv⟩ := cursorRun_spec (by decide) hK fs _ 0 0 hinv0
  have hcount := count_true_add_count_false fs
  have hc' : cursorCount (cursorRun fs (caddrsInit addr mask)).2 = 2 ^ hostBits mask - fs.length := by
    rw [cursorCount_eq hinv]
    omega
  exact ⟨hc', by rw [cursorSizeHint128_eq hub, hc'], fun h => hinv.2 (by omega)⟩

end Ipv6

end Netip.Impl
