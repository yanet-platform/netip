import Netip.Impl.Basic

/-!
# `supernet_for`

`Ipv4Network::supernet_for` / `Ipv6Network::supernet_for` fold the mask
`mask &= m & !(addr ^ a)` over the given networks, keeping `addr` from `self`,
and normalize at the end.

Proved, for any list of normalized networks: the result contains `self` and
every given network, and it is contained in every network that contains them
all, so it is the smallest common supernet. Containment is `contains`, which
`SetOps` shows to be set inclusion.

The IPv4 fold runs on native-endian words. On a little-endian target that is
the byte-swapped value, and AND, XOR and NOT commute with the byte swap
(`bswap_and`, `bswap_xor`, `bswap_not`), so folding the swapped words and
swapping back gives the big-endian result (`supernetMask_bswap`).
-/

namespace Netip.Impl

variable {w : Nat}

/-- `x ⊆ y` on bit sets. -/
def Sub (x y : BitVec w) : Prop := x &&& y = x

/-- The factor one network contributes: its mask, minus the bits where its
address disagrees with `addr`. -/
def supernetFactor (addr : BitVec w) (net : BitVec w × BitVec w) : BitVec w :=
  net.2 &&& ~~~(addr ^^^ net.1)

/-- The fold of `supernet_for`, starting from `self`'s mask. -/
def supernetMask (addr mask : BitVec w) (nets : List (BitVec w × BitVec w)) : BitVec w :=
  nets.foldl (fun acc net => acc &&& supernetFactor addr net) mask

/-- `contains`: `(a2 & m1 == a1) && (m2 & m1 == m1)`. -/
def Contains (n1 n2 : BitVec w × BitVec w) : Prop :=
  n2.1 &&& n1.2 = n1.1 ∧ n2.2 &&& n1.2 = n1.2

theorem sub_and_left (x y : BitVec w) : Sub (x &&& y) x := by
  unfold Sub
  rw [BitVec.and_assoc, BitVec.and_comm y x, ← BitVec.and_assoc, BitVec.and_self]

theorem sub_and_right (x y : BitVec w) : Sub (x &&& y) y := by
  unfold Sub
  rw [BitVec.and_assoc, BitVec.and_self]

theorem sub_trans {x y z : BitVec w} (h1 : Sub x y) (h2 : Sub y z) : Sub x z := by
  unfold Sub at *
  rw [← h1, BitVec.and_assoc, h2]

theorem sub_and {x y z : BitVec w} (h1 : Sub x y) (h2 : Sub x z) : Sub x (y &&& z) := by
  unfold Sub at *
  rw [← BitVec.and_assoc, h1, h2]

/-- The fold only removes bits. -/
theorem supernetMask_sub_init (addr : BitVec w) (nets : List (BitVec w × BitVec w)) :
    ∀ mask, Sub (supernetMask addr mask nets) mask := by
  induction nets with
  | nil => intro mask; simp [supernetMask, Sub]
  | cons net nets ih =>
    intro mask
    exact sub_trans (ih (mask &&& supernetFactor addr net)) (sub_and_left _ _)

/-- The result is inside every factor. -/
theorem supernetMask_sub_factor (addr : BitVec w) (nets : List (BitVec w × BitVec w)) :
    ∀ mask, ∀ net ∈ nets, Sub (supernetMask addr mask nets) (supernetFactor addr net) := by
  induction nets with
  | nil => intro mask net h; simp at h
  | cons n nets ih =>
    intro mask net h
    rcases List.mem_cons.mp h with rfl | h
    · exact sub_trans (supernetMask_sub_init addr nets _) (sub_and_right _ _)
    · exact ih _ net h

/-- Anything inside the initial mask and every factor stays inside the result. -/
theorem sub_supernetMask (addr : BitVec w) (nets : List (BitVec w × BitVec w)) :
    ∀ mask z, Sub z mask → (∀ net ∈ nets, Sub z (supernetFactor addr net)) →
      Sub z (supernetMask addr mask nets) := by
  induction nets with
  | nil => intro mask z h _; simpa [supernetMask] using h
  | cons n nets ih =>
    intro mask z h hall
    exact ih _ z (sub_and h (hall n List.mem_cons_self)) fun net hn => hall net (List.mem_cons_of_mem _ hn)

namespace Ipv4

/-- The bit-level step behind "the result contains `self`". -/
theorem contains_self (a m M : BitVec 32) (h : Sub M m) : Contains (a &&& M, M) (a, m) := by
  simp only [Contains, Sub] at *
  bv_decide

/-- The bit-level step behind "the result contains each network". -/
theorem contains_net (a M a' m' : BitVec 32) (h : Sub M (supernetFactor a (a', m'))) :
    Contains (a &&& M, M) (a', m') := by
  simp only [Contains, Sub, supernetFactor] at *
  bv_decide

/-- A network containing `self` and a given network is inside that network's factor. -/
theorem sub_factor_of_contains (a m a' m' c mc : BitVec 32) (hs : Contains (c, mc) (a, m))
    (hn : Contains (c, mc) (a', m')) : Sub mc (supernetFactor a (a', m')) := by
  simp only [Contains, Sub, supernetFactor] at *
  bv_decide

theorem contains_of_sub (a m c mc M : BitVec 32) (hs : Contains (c, mc) (a, m)) (h : Sub mc M) :
    Contains (c, mc) (a &&& M, M) := by
  simp only [Contains, Sub] at *
  bv_decide

/-- `supernet_for` returns a common supernet of `self` and `nets`. -/
theorem supernet_contains (a m : BitVec 32) (nets : List (BitVec 32 × BitVec 32)) :
    Contains (a &&& supernetMask a m nets, supernetMask a m nets) (a, m) ∧
    ∀ net ∈ nets, Contains (a &&& supernetMask a m nets, supernetMask a m nets) net := by
  refine ⟨contains_self _ _ _ (supernetMask_sub_init a nets m), fun net hn => ?_⟩
  exact contains_net _ _ _ _ (supernetMask_sub_factor a nets m net hn)

/-- ... and the smallest one: every network containing `self` and `nets` contains it. -/
theorem supernet_minimal (a m c mc : BitVec 32) (nets : List (BitVec 32 × BitVec 32))
    (hs : Contains (c, mc) (a, m)) (hn : ∀ net ∈ nets, Contains (c, mc) net) :
    Contains (c, mc) (a &&& supernetMask a m nets, supernetMask a m nets) := by
  apply contains_of_sub a m c mc _ hs
  apply sub_supernetMask a nets m mc
  · unfold Contains at hs
    unfold Sub
    rw [BitVec.and_comm]
    exact hs.2
  · intro net h
    exact sub_factor_of_contains a m net.1 net.2 c mc hs (hn net h)

/-- Byte swap of a `u32`: the native-endian reading of big-endian octets on a
little-endian target. -/
def bswap (x : BitVec 32) : BitVec 32 :=
  (x.extractLsb' 0 8 ++ x.extractLsb' 8 8) ++ (x.extractLsb' 16 8 ++ x.extractLsb' 24 8)

theorem bswap_bswap (x : BitVec 32) : bswap (bswap x) = x := by
  unfold bswap
  bv_decide

theorem bswap_and (x y : BitVec 32) : bswap (x &&& y) = bswap x &&& bswap y := by
  unfold bswap
  bv_decide

theorem bswap_xor (x y : BitVec 32) : bswap (x ^^^ y) = bswap x ^^^ bswap y := by
  unfold bswap
  bv_decide

theorem bswap_not (x : BitVec 32) : bswap (~~~x) = ~~~(bswap x) := by
  unfold bswap
  bv_decide

/-- Folding the byte-swapped words and swapping back gives the big-endian fold. -/
theorem supernetMask_bswap (a : BitVec 32) (nets : List (BitVec 32 × BitVec 32)) :
    ∀ m, bswap (supernetMask (bswap a) (bswap m) (nets.map fun n => (bswap n.1, bswap n.2))) =
      supernetMask a m nets := by
  induction nets with
  | nil => intro m; simp [supernetMask, bswap_bswap]
  | cons n nets ih =>
    intro m
    simp only [supernetMask, List.map_cons, List.foldl_cons] at ih ⊢
    rw [← ih (m &&& supernetFactor a n)]
    congr 2
    unfold supernetFactor
    rw [bswap_and, bswap_and, bswap_not, bswap_xor]

end Ipv4

namespace Ipv6

theorem contains_self (a m M : BitVec 128) (h : Sub M m) : Contains (a &&& M, M) (a, m) := by
  simp only [Contains, Sub] at *
  bv_decide

theorem contains_net (a M a' m' : BitVec 128) (h : Sub M (supernetFactor a (a', m'))) :
    Contains (a &&& M, M) (a', m') := by
  simp only [Contains, Sub, supernetFactor] at *
  bv_decide

theorem sub_factor_of_contains (a m a' m' c mc : BitVec 128) (hs : Contains (c, mc) (a, m))
    (hn : Contains (c, mc) (a', m')) : Sub mc (supernetFactor a (a', m')) := by
  simp only [Contains, Sub, supernetFactor] at *
  bv_decide

theorem contains_of_sub (a m c mc M : BitVec 128) (hs : Contains (c, mc) (a, m)) (h : Sub mc M) :
    Contains (c, mc) (a &&& M, M) := by
  simp only [Contains, Sub] at *
  bv_decide

theorem supernet_contains (a m : BitVec 128) (nets : List (BitVec 128 × BitVec 128)) :
    Contains (a &&& supernetMask a m nets, supernetMask a m nets) (a, m) ∧
    ∀ net ∈ nets, Contains (a &&& supernetMask a m nets, supernetMask a m nets) net := by
  refine ⟨contains_self _ _ _ (supernetMask_sub_init a nets m), fun net hn => ?_⟩
  exact contains_net _ _ _ _ (supernetMask_sub_factor a nets m net hn)

theorem supernet_minimal (a m c mc : BitVec 128) (nets : List (BitVec 128 × BitVec 128))
    (hs : Contains (c, mc) (a, m)) (hn : ∀ net ∈ nets, Contains (c, mc) net) :
    Contains (c, mc) (a &&& supernetMask a m nets, supernetMask a m nets) := by
  apply contains_of_sub a m c mc _ hs
  apply sub_supernetMask a nets m mc
  · unfold Contains at hs
    unfold Sub
    rw [BitVec.and_comm]
    exact hs.2
  · intro net h
    exact sub_factor_of_contains a m net.1 net.2 c mc hs (hn net h)

end Ipv6

end Netip.Impl
