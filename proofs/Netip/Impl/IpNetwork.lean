import Netip.Impl.Conversions
import Netip.Impl.MergeComplete
import Netip.Impl.Adjacent
import Netip.Impl.IsContiguous

/-!
# `IpNetwork`

Every method of `IpNetwork` dispatches to the `Ipv4Network` or `Ipv6Network` one
when both operands have the same family. For mixed families `contains`,
`intersects`, `is_adjacent` and `is_adjacent_by_lowest_mask_bit` return `false`,
`is_disjoint` returns `true`, and `intersection`, `merge` and
`merge_by_lowest_mask_bit` return `None`. The transcriptions below are those
dispatches.

An `IpAddr` belongs to one family, and the members of a network are the addresses
of its own family that match its fixed bits (`IpNet.Mem`). So networks of
different families are disjoint, neither contains the other, and no network is
their union: the documented mixed-family results are the set-theoretic ones.

Proved, for normalized networks of either family and every combination of
families: `contains` is set inclusion (`contains_iff`), `intersects` is having a
common member and `is_disjoint` its absence (`intersects_iff`, `isDisjoint_iff`),
`intersection` is exactly the common members and `None` only when there are none
(`intersection_some`, `intersection_none_iff`), `merge` returns the union whenever
it returns `Some` and `None` only when no network is the union (`merge_some`,
`merge_none`), `merge_by_lowest_mask_bit` returns `Some` only where `merge` returns
the same network (`mergeByLowestMaskBit_some`), adjacent networks are disjoint and
merge (`isAdjacent_spec`), the lowest-mask-bit variant implies `is_adjacent`
(`isAdjacent_of_byLowestMaskBit`), `last_addr` is the largest member
(`lastAddr_spec`), `prefix` is `Some` exactly for contiguous masks and then the
popcount (`prefix_spec`), and `to_contiguous` is the smallest CIDR network
containing the network (`toContiguous_spec`).
-/

namespace Netip.Impl

/-- `IpAddr`: an address of one family. -/
inductive IpAddr where
  | v4 (x : BitVec 32)
  | v6 (x : BitVec 128)

/-- Two addresses of the same family, in numeric order. -/
def IpAddr.Le : IpAddr → IpAddr → Prop
  | .v4 x, .v4 y => x ≤ y
  | .v6 x, .v6 y => x ≤ y
  | _, _ => False

instance {w : Nat} (m : BitVec w) : Decidable (IsContiguous m) := by
  unfold IsContiguous
  infer_instance

instance {w : Nat} (a1 m1 a2 m2 : BitVec w) : Decidable (AdjacentByLowestMaskBit a1 m1 a2 m2) := by
  unfold AdjacentByLowestMaskBit
  infer_instance

namespace IpNet

/-- The members: the addresses of the network's family that match its fixed bits. -/
def Mem : IpAddr → IpNet → Prop
  | .v4 x, .v4 a m => x &&& m = a
  | .v6 x, .v6 a m => x &&& m = a
  | _, _ => False

/-- `IpNetwork::addr`. -/
def addr : IpNet → IpAddr
  | .v4 a _ => .v4 a
  | .v6 a _ => .v6 a

/-- `IpNetwork::mask`. -/
def mask : IpNet → IpAddr
  | .v4 _ m => .v4 m
  | .v6 _ m => .v6 m

/-- `IpNetwork::contains`: `(a2 & m1 == a1) && (m2 & m1 == m1)`. -/
def contains : IpNet → IpNet → Bool
  | .v4 a1 m1, .v4 a2 m2 => a2 &&& m1 == a1 && m2 &&& m1 == m1
  | .v6 a1 m1, .v6 a2 m2 => a2 &&& m1 == a1 && m2 &&& m1 == m1
  | _, _ => false

/-- `IpNetwork::intersection`: `(a1 | a2, m1 | m2)` unless `a1 & m2 != a2 & m1`. -/
def intersection : IpNet → IpNet → Option IpNet
  | .v4 a1 m1, .v4 a2 m2 =>
    if a1 &&& m2 = a2 &&& m1 then some (.v4 (a1 ||| a2) (m1 ||| m2)) else none
  | .v6 a1 m1, .v6 a2 m2 =>
    if a1 &&& m2 = a2 &&& m1 then some (.v6 (a1 ||| a2) (m1 ||| m2)) else none
  | _, _ => none

/-- `IpNetwork::intersects`: `intersection(..).is_some()` of the family. -/
def intersects : IpNet → IpNet → Bool
  | .v4 a1 m1, .v4 a2 m2 => (intersection (.v4 a1 m1) (.v4 a2 m2)).isSome
  | .v6 a1 m1, .v6 a2 m2 => (intersection (.v6 a1 m1) (.v6 a2 m2)).isSome
  | _, _ => false

/-- `IpNetwork::is_disjoint`. -/
def isDisjoint (n1 n2 : IpNet) : Bool := !intersects n1 n2

/-- `IpNetwork::merge`. -/
def merge : IpNet → IpNet → Option IpNet
  | .v4 a1 m1, .v4 a2 m2 => (Netip.Impl.merge a1 m1 a2 m2).map fun r => .v4 r.1 r.2
  | .v6 a1 m1, .v6 a2 m2 => (Netip.Impl.merge a1 m1 a2 m2).map fun r => .v6 r.1 r.2
  | _, _ => none

/-- `IpNetwork::merge_by_lowest_mask_bit`. -/
def mergeByLowestMaskBit : IpNet → IpNet → Option IpNet
  | .v4 a1 m1, .v4 a2 m2 => (Netip.Impl.mergeByLowestMaskBit a1 m1 a2 m2).map fun r => .v4 r.1 r.2
  | .v6 a1 m1, .v6 a2 m2 => (Netip.Impl.mergeByLowestMaskBit a1 m1 a2 m2).map fun r => .v6 r.1 r.2
  | _, _ => none

/-- `IpNetwork::is_adjacent`: `ipv*_adjacent_bit(..).is_some()`. -/
def isAdjacent : IpNet → IpNet → Bool
  | .v4 a1 m1, .v4 a2 m2 => (adjacentBit a1 m1 a2 m2).isSome
  | .v6 a1 m1, .v6 a2 m2 => (adjacentBit a1 m1 a2 m2).isSome
  | _, _ => false

/-- `IpNetwork::is_adjacent_by_lowest_mask_bit`. -/
def isAdjacentByLowestMaskBit : IpNet → IpNet → Bool
  | .v4 a1 m1, .v4 a2 m2 => decide (AdjacentByLowestMaskBit a1 m1 a2 m2)
  | .v6 a1 m1, .v6 a2 m2 => decide (AdjacentByLowestMaskBit a1 m1 a2 m2)
  | _, _ => false

/-- `IpNetwork::is_contiguous`: `mask | mask.wrapping_sub(1) == MAX`. -/
def isContiguous : IpNet → Bool
  | .v4 _ m => decide (IsContiguous m)
  | .v6 _ m => decide (IsContiguous m)

/-- `IpNetwork::prefix`: `leading_ones` of a contiguous mask. -/
def prefixLen : IpNet → Option Nat
  | .v4 _ m => if IsContiguous m then some (~~~m).clz.toNat else none
  | .v6 _ m => if IsContiguous m then some (~~~m).clz.toNat else none

/-- `IpNetwork::last_addr`: `addr | !mask`. -/
def lastAddr : IpNet → IpAddr
  | .v4 a m => .v4 (a ||| ~~~m)
  | .v6 a m => .v6 (a ||| ~~~m)

/-- `IpNetwork::to_contiguous`. -/
def toContiguous : IpNet → IpNet
  | .v4 a m => .v4 (Netip.Impl.toContiguous a m).1 (Netip.Impl.toContiguous a m).2
  | .v6 a m => .v6 (Netip.Impl.toContiguous a m).1 (Netip.Impl.toContiguous a m).2

/-- A CIDR network. -/
def IsCidrNet : IpNet → Prop
  | .v4 a m => IsContiguous m ∧ a &&& m = a
  | .v6 a m => IsContiguous m ∧ a &&& m = a

theorem mem_addr {n : IpNet} (h : n.Normalized) : Mem n.addr n := by
  cases n with
  | v4 a m => exact h
  | v6 a m => exact h

/-- `contains` is set inclusion, `false` across families. -/
theorem contains_iff {n1 n2 : IpNet} (h1 : n1.Normalized) (h2 : n2.Normalized) :
    contains n1 n2 = true ↔ ∀ X, Mem X n2 → Mem X n1 := by
  cases n1 with
  | v4 a1 m1 =>
    cases n2 with
    | v4 a2 m2 =>
      have := Ipv4.contains_iff a1 m1 a2 m2 h1 h2
      simp only [contains, Bool.and_eq_true, beq_iff_eq]
      rw [this]
      constructor
      · intro h X hX
        cases X with
        | v4 x => exact h x hX
        | v6 x => exact hX.elim
      · intro h x hx
        exact h (.v4 x) hx
    | v6 a2 m2 =>
      simp only [contains, Bool.false_eq_true, false_iff]
      intro h
      exact h (.v6 a2) h2
  | v6 a1 m1 =>
    cases n2 with
    | v4 a2 m2 =>
      simp only [contains, Bool.false_eq_true, false_iff]
      intro h
      exact h (.v4 a2) h2
    | v6 a2 m2 =>
      have := Ipv6.contains_iff a1 m1 a2 m2 h1 h2
      simp only [contains, Bool.and_eq_true, beq_iff_eq]
      rw [this]
      constructor
      · intro h X hX
        cases X with
        | v4 x => exact hX.elim
        | v6 x => exact h x hX
      · intro h x hx
        exact h (.v6 x) hx

/-- `intersection` holds exactly the common members. -/
theorem intersection_some {n1 n2 n : IpNet} (h1 : n1.Normalized) (h2 : n2.Normalized)
    (h : intersection n1 n2 = some n) :
    n.Normalized ∧ ∀ X, Mem X n ↔ Mem X n1 ∧ Mem X n2 := by
  cases n1 with
  | v4 a1 m1 =>
    cases n2 with
    | v4 a2 m2 =>
      simp only [intersection] at h
      split at h
      · rename_i hc
        simp only [Option.some.injEq] at h
        subst h
        refine ⟨Ipv4.intersection_normalized a1 m1 a2 m2 h1 h2, fun X => ?_⟩
        cases X with
        | v4 x =>
          show x &&& (m1 ||| m2) = a1 ||| a2 ↔ x &&& m1 = a1 ∧ x &&& m2 = a2
          rw [Ipv4.intersection_iff a1 m1 a2 m2 x h1 h2]
          exact ⟨fun h => ⟨hc, h⟩, fun h => h.2⟩
        | v6 x => exact ⟨False.elim, fun h => h.1.elim⟩
      · simp at h
    | v6 a2 m2 => simp [intersection] at h
  | v6 a1 m1 =>
    cases n2 with
    | v4 a2 m2 => simp [intersection] at h
    | v6 a2 m2 =>
      simp only [intersection] at h
      split at h
      · rename_i hc
        simp only [Option.some.injEq] at h
        subst h
        refine ⟨Ipv6.intersection_normalized a1 m1 a2 m2 h1 h2, fun X => ?_⟩
        cases X with
        | v4 x => exact ⟨False.elim, fun h => h.1.elim⟩
        | v6 x =>
          show x &&& (m1 ||| m2) = a1 ||| a2 ↔ x &&& m1 = a1 ∧ x &&& m2 = a2
          rw [Ipv6.intersection_iff a1 m1 a2 m2 x h1 h2]
          exact ⟨fun h => ⟨hc, h⟩, fun h => h.2⟩
      · simp at h

/-- `intersection` is `None` exactly when there is no common member, in particular
across families. -/
theorem intersection_none_iff {n1 n2 : IpNet} (h1 : n1.Normalized) (h2 : n2.Normalized) :
    intersection n1 n2 = none ↔ ∀ X, ¬ (Mem X n1 ∧ Mem X n2) := by
  cases n1 with
  | v4 a1 m1 =>
    cases n2 with
    | v4 a2 m2 =>
      simp only [intersection]
      split
      · rename_i hc
        simp only [reduceCtorEq, false_iff, Classical.not_forall, Classical.not_not]
        refine ⟨.v4 (a1 ||| a2), ?_⟩
        exact (Ipv4.intersection_iff a1 m1 a2 m2 _ h1 h2).2
          ⟨hc, Ipv4.intersection_normalized a1 m1 a2 m2 h1 h2⟩
      · rename_i hc
        simp only [true_iff]
        intro X hX
        cases X with
        | v4 x => exact hc ((Ipv4.intersection_iff a1 m1 a2 m2 x h1 h2).1 hX).1
        | v6 x => exact hX.1.elim
    | v6 a2 m2 =>
      simp only [intersection, true_iff]
      intro X hX
      cases X with
      | v4 x => exact hX.2.elim
      | v6 x => exact hX.1.elim
  | v6 a1 m1 =>
    cases n2 with
    | v4 a2 m2 =>
      simp only [intersection, true_iff]
      intro X hX
      cases X with
      | v4 x => exact hX.1.elim
      | v6 x => exact hX.2.elim
    | v6 a2 m2 =>
      simp only [intersection]
      split
      · rename_i hc
        simp only [reduceCtorEq, false_iff, Classical.not_forall, Classical.not_not]
        refine ⟨.v6 (a1 ||| a2), ?_⟩
        exact (Ipv6.intersection_iff a1 m1 a2 m2 _ h1 h2).2
          ⟨hc, Ipv6.intersection_normalized a1 m1 a2 m2 h1 h2⟩
      · rename_i hc
        simp only [true_iff]
        intro X hX
        cases X with
        | v4 x => exact hX.1.elim
        | v6 x => exact hc ((Ipv6.intersection_iff a1 m1 a2 m2 x h1 h2).1 hX).1

theorem intersects_eq (n1 n2 : IpNet) : intersects n1 n2 = (intersection n1 n2).isSome := by
  cases n1 <;> cases n2 <;> rfl

/-- `intersects` is having a common member, `false` across families. -/
theorem intersects_iff {n1 n2 : IpNet} (h1 : n1.Normalized) (h2 : n2.Normalized) :
    intersects n1 n2 = true ↔ ∃ X, Mem X n1 ∧ Mem X n2 := by
  rw [intersects_eq, Option.isSome_iff_ne_none, Ne, intersection_none_iff h1 h2]
  simp only [Classical.not_forall, Classical.not_not]

/-- `is_disjoint` is having no common member, `true` across families. -/
theorem isDisjoint_iff {n1 n2 : IpNet} (h1 : n1.Normalized) (h2 : n2.Normalized) :
    isDisjoint n1 n2 = true ↔ ∀ X, ¬ (Mem X n1 ∧ Mem X n2) := by
  rw [isDisjoint, Bool.not_eq_true', ← Bool.not_eq_true, intersects_iff h1 h2]
  simp only [not_exists]

/-- A `Some` from `merge` is normalized and is the union. -/
theorem merge_some {n1 n2 n : IpNet} (h1 : n1.Normalized) (h2 : n2.Normalized)
    (h : merge n1 n2 = some n) : n.Normalized ∧ ∀ X, Mem X n ↔ Mem X n1 ∨ Mem X n2 := by
  cases n1 with
  | v4 a1 m1 =>
    cases n2 with
    | v4 a2 m2 =>
      simp only [merge, Option.map_eq_some_iff] at h
      obtain ⟨⟨a, m⟩, hm, rfl⟩ := h
      refine ⟨(Ipv4.merge_sound h1 h2 hm 0).1, fun X => ?_⟩
      cases X with
      | v4 x => exact (Ipv4.merge_sound h1 h2 hm x).2
      | v6 x => exact ⟨False.elim, fun h => h.elim False.elim False.elim⟩
    | v6 a2 m2 => simp [merge] at h
  | v6 a1 m1 =>
    cases n2 with
    | v4 a2 m2 => simp [merge] at h
    | v6 a2 m2 =>
      simp only [merge, Option.map_eq_some_iff] at h
      obtain ⟨⟨a, m⟩, hm, rfl⟩ := h
      refine ⟨(Ipv6.merge_sound h1 h2 hm 0).1, fun X => ?_⟩
      cases X with
      | v4 x => exact ⟨False.elim, fun h => h.elim False.elim False.elim⟩
      | v6 x => exact (Ipv6.merge_sound h1 h2 hm x).2

/-- `None` from `merge` means no network is the union, in particular across families. -/
theorem merge_none {n1 n2 : IpNet} (h1 : n1.Normalized) (h2 : n2.Normalized)
    (h : merge n1 n2 = none) : ∀ n : IpNet, ¬ ∀ X, Mem X n ↔ Mem X n1 ∨ Mem X n2 := by
  intro n hn
  cases n1 with
  | v4 a1 m1 =>
    cases n2 with
    | v4 a2 m2 =>
      simp only [merge, Option.map_eq_none_iff] at h
      cases n with
      | v4 c mc =>
        exact Ipv4.merge_complete a1 m1 a2 m2 h1 h2 h ⟨c, mc, fun x => hn (.v4 x)⟩
      | v6 c mc => exact (hn (.v4 a1)).2 (Or.inl h1)
    | v6 a2 m2 =>
      cases n with
      | v4 c mc => exact (hn (.v6 a2)).2 (Or.inr h2)
      | v6 c mc => exact (hn (.v4 a1)).2 (Or.inl h1)
  | v6 a1 m1 =>
    cases n2 with
    | v4 a2 m2 =>
      cases n with
      | v4 c mc => exact (hn (.v6 a1)).2 (Or.inl h1)
      | v6 c mc => exact (hn (.v4 a2)).2 (Or.inr h2)
    | v6 a2 m2 =>
      simp only [merge, Option.map_eq_none_iff] at h
      cases n with
      | v4 c mc => exact (hn (.v6 a1)).2 (Or.inl h1)
      | v6 c mc =>
        exact Ipv6.merge_complete a1 m1 a2 m2 h1 h2 h ⟨c, mc, fun x => hn (.v6 x)⟩

/-- `merge_by_lowest_mask_bit` returns `Some` only where `merge` returns the same
network. -/
theorem mergeByLowestMaskBit_some {n1 n2 n : IpNet} (h1 : n1.Normalized) (h2 : n2.Normalized)
    (h : mergeByLowestMaskBit n1 n2 = some n) : merge n1 n2 = some n := by
  cases n1 with
  | v4 a1 m1 =>
    cases n2 with
    | v4 a2 m2 =>
      simp only [mergeByLowestMaskBit, Option.map_eq_some_iff] at h
      obtain ⟨⟨a, m⟩, hm, rfl⟩ := h
      simp [merge, Ipv4.mergeByLowestMaskBit_eq_merge h1 h2 hm]
    | v6 a2 m2 => simp [mergeByLowestMaskBit] at h
  | v6 a1 m1 =>
    cases n2 with
    | v4 a2 m2 => simp [mergeByLowestMaskBit] at h
    | v6 a2 m2 =>
      simp only [mergeByLowestMaskBit, Option.map_eq_some_iff] at h
      obtain ⟨⟨a, m⟩, hm, rfl⟩ := h
      simp [merge, Ipv6.mergeByLowestMaskBit_eq_merge h1 h2 hm]

/-- Adjacent networks are disjoint and merge, and only networks of one family are
adjacent. -/
theorem isAdjacent_spec {n1 n2 : IpNet} (h1 : n1.Normalized) (h2 : n2.Normalized)
    (h : isAdjacent n1 n2 = true) :
    (∀ X, ¬ (Mem X n1 ∧ Mem X n2)) ∧ ∃ n, merge n1 n2 = some n := by
  cases n1 with
  | v4 a1 m1 =>
    cases n2 with
    | v4 a2 m2 =>
      simp only [isAdjacent, Option.isSome_iff_exists] at h
      obtain ⟨d, hd⟩ := h
      obtain ⟨-, hdis, hm⟩ := Ipv4.adjacent_merge h1 h2 hd
      refine ⟨fun X hX => ?_, .v4 (a1 &&& (m1 ^^^ d)) (m1 ^^^ d), by simp [merge, hm]⟩
      cases X with
      | v4 x => exact hdis x hX
      | v6 x => exact hX.1.elim
    | v6 a2 m2 => simp [isAdjacent] at h
  | v6 a1 m1 =>
    cases n2 with
    | v4 a2 m2 => simp [isAdjacent] at h
    | v6 a2 m2 =>
      simp only [isAdjacent, Option.isSome_iff_exists] at h
      obtain ⟨d, hd⟩ := h
      obtain ⟨-, hdis, hm⟩ := Ipv6.adjacent_merge h1 h2 hd
      refine ⟨fun X hX => ?_, .v6 (a1 &&& (m1 ^^^ d)) (m1 ^^^ d), by simp [merge, hm]⟩
      cases X with
      | v4 x => exact hX.1.elim
      | v6 x => exact hdis x hX

/-- Every lowest-mask-bit sibling pair is adjacent. -/
theorem isAdjacent_of_byLowestMaskBit {n1 n2 : IpNet} (h : isAdjacentByLowestMaskBit n1 n2 = true) :
    isAdjacent n1 n2 = true := by
  cases n1 with
  | v4 a1 m1 =>
    cases n2 with
    | v4 a2 m2 =>
      simp only [isAdjacentByLowestMaskBit, decide_eq_true_eq] at h
      simp [isAdjacent, Ipv4.adjacentBit_of_byLowestMaskBit h]
    | v6 a2 m2 => simp [isAdjacentByLowestMaskBit] at h
  | v6 a1 m1 =>
    cases n2 with
    | v4 a2 m2 => simp [isAdjacentByLowestMaskBit] at h
    | v6 a2 m2 =>
      simp only [isAdjacentByLowestMaskBit, decide_eq_true_eq] at h
      simp [isAdjacent, Ipv6.adjacentBit_of_byLowestMaskBit h]

/-- `last_addr` is a member, and no member of the network is larger. -/
theorem lastAddr_spec {n : IpNet} (h : n.Normalized) :
    Mem n.lastAddr n ∧ ∀ X, Mem X n → X.Le n.lastAddr := by
  cases n with
  | v4 a m =>
    refine ⟨(Ipv4.lastAddr_max a m a h h).1, fun X hX => ?_⟩
    cases X with
    | v4 x => exact (Ipv4.lastAddr_max a m x h hX).2
    | v6 x => exact hX.elim
  | v6 a m =>
    refine ⟨(Ipv6.lastAddr_max a m a h h).1, fun X hX => ?_⟩
    cases X with
    | v4 x => exact hX.elim
    | v6 x => exact (Ipv6.lastAddr_max a m x h hX).2

/-- `prefix` is `Some` exactly for contiguous masks, and then the popcount. -/
theorem prefix_spec (n : IpNet) :
    (prefixLen n).isSome = isContiguous n ∧
      ∀ k, prefixLen n = some k → match n with
        | .v4 _ m => k = m.cpop.toNat
        | .v6 _ m => k = m.cpop.toNat := by
  cases n with
  | v4 a m =>
    refine ⟨by simp only [prefixLen, isContiguous]; split <;> simp_all, fun k hk => ?_⟩
    simp only [prefixLen] at hk
    split at hk
    · rename_i hc
      simp only [Option.some.injEq] at hk
      rw [← hk, Ipv4.leadingOnes_eq_popcount m hc]
    · simp at hk
  | v6 a m =>
    refine ⟨by simp only [prefixLen, isContiguous]; split <;> simp_all, fun k hk => ?_⟩
    simp only [prefixLen] at hk
    split at hk
    · rename_i hc
      simp only [Option.some.injEq] at hk
      rw [← hk, Ipv6.leadingOnes_eq_popcount m hc]
    · simp at hk

/-- `to_contiguous` is a CIDR network containing the network, inside every CIDR
network that contains it. -/
theorem toContiguous_spec {n : IpNet} (h : n.Normalized) :
    IsCidrNet n.toContiguous ∧ contains n.toContiguous n = true ∧
      ∀ c, IsCidrNet c → contains c n = true → contains c n.toContiguous = true := by
  cases n with
  | v4 a m =>
    obtain ⟨hcon, -, -⟩ := Ipv4.toContiguous_mask m 0 (by decide)
    obtain ⟨hcont, -⟩ := Ipv4.toContiguous_minimal a m 0 0 h (by decide)
    have hnorm : (Netip.Impl.toContiguous a m).1 &&& (Netip.Impl.toContiguous a m).2 =
        (Netip.Impl.toContiguous a m).1 := by
      simp only [Netip.Impl.toContiguous]
      rw [BitVec.and_assoc, BitVec.and_self]
    refine ⟨⟨by simpa [Netip.Impl.toContiguous] using hcon, hnorm⟩, ?_, fun c hc hcn => ?_⟩
    · simp only [toContiguous, contains, Bool.and_eq_true, beq_iff_eq]
      exact hcont
    · cases c with
      | v4 c mc =>
        obtain ⟨hcc, hcnorm⟩ := hc
        have hk : mc = maskFromCidr 32 (~~~mc).clz := (Ipv4.isContiguous_iff_eq_maskFromCidr mc).mp hcc
        simp only [toContiguous, contains, Bool.and_eq_true, beq_iff_eq] at hcn ⊢
        have := (Ipv4.toContiguous_minimal a m c (~~~mc).clz h (Ipv4.leadingOnes_le mc)).2
        rw [← hk] at this
        exact this hcn
      | v6 c mc => simp [contains] at hcn
  | v6 a m =>
    obtain ⟨hcon, -, -⟩ := Ipv6.toContiguous_mask m 0 (by decide)
    obtain ⟨hcont, -⟩ := Ipv6.toContiguous_minimal a m 0 0 h (by decide)
    have hnorm : (Netip.Impl.toContiguous a m).1 &&& (Netip.Impl.toContiguous a m).2 =
        (Netip.Impl.toContiguous a m).1 := by
      simp only [Netip.Impl.toContiguous]
      rw [BitVec.and_assoc, BitVec.and_self]
    refine ⟨⟨by simpa [Netip.Impl.toContiguous] using hcon, hnorm⟩, ?_, fun c hc hcn => ?_⟩
    · simp only [toContiguous, contains, Bool.and_eq_true, beq_iff_eq]
      exact hcont
    · cases c with
      | v4 c mc => simp [contains] at hcn
      | v6 c mc =>
        obtain ⟨hcc, hcnorm⟩ := hc
        have hk : mc = maskFromCidr 128 (~~~mc).clz :=
          (Ipv6.isContiguous_iff_eq_maskFromCidr mc).mp hcc
        simp only [toContiguous, contains, Bool.and_eq_true, beq_iff_eq] at hcn ⊢
        have := (Ipv6.toContiguous_minimal a m c (~~~mc).clz h (Ipv6.leadingOnes_le mc)).2
        rw [← hk] at this
        exact this hcn

end IpNet

end Netip.Impl
