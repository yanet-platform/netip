import Netip.Impl.Basic

/-!
# `difference`: the peeling decomposition and its iterator

`Ipv4NetworkDiff` / `Ipv6NetworkDiff` yield `S(A) \ S(B)` as one network per bit
of `d = (m₁ ∨ m₂) ∧ ¬m₁`, the bits fixed by `B` but free in `A`. With
`ia = a₁ ∨ a₂`, the address of `A ∩ B`, the network for a bit `b` of `d` is
`((ia ⊕ b) ∧ M(b), M(b))` with `M(b) = m₁ ∨ (d ∧ ¬(b - 1))`: it agrees with
`A ∩ B` on the bits of `d` above `b`, disagrees at `b`, and is free below.

Proved for every input of the width, `A` and `B` intersecting:
* Each item lies in `S(A) \ S(B)` (`item_sub`), the items cover it
  (`item_cover`), and they are pairwise disjoint (`item_disjoint`).
* `Inv` describes the iterator state after any mix of `next()` and
  `next_back()`: under it `next()` (highest pending bit) and `next_back()`
  (lowest pending bit) both emit exactly the item of their bit, and both keep
  `Inv` (`inv_init`, `next_emits`, `nextBack_emits`). Each call removes one
  pending bit, so any interleaving emits the item of every bit of `d` once.
* The two-rung `predicted` ladder of `next()` returns the highest pending bit,
  and both ends keep its invariant (`ladder_*`). The IPv6 ladder runs on 64-bit
  halves and is transcribed as such.
* The disjoint shortcut of `new()` emits the source network itself
  (`disjoint_shortcut`).

Whole runs and minimality are in `DifferenceRun`.
-/

namespace Netip.Impl

variable {w : Nat}

/-- `d`: bits fixed in `B = (_, m₂)` but free in `A = (_, m₁)`. -/
def diffBits (m1 m2 : BitVec w) : BitVec w := (m1 ||| m2) &&& ~~~m1

/-- `M(b)`: the mask of the item for difference bit `b`. -/
def itemMask (m1 d b : BitVec w) : BitVec w := m1 ||| (d &&& ~~~(b - 1))

/-- The address of the item for difference bit `b`. -/
def itemAddr (ia m1 d b : BitVec w) : BitVec w := (ia ^^^ b) &&& itemMask m1 d b

/-- The invariant behind `predicted`: zero, or a single bit with every pending bit
at or below it. -/
def LadderInv (p r : BitVec w) : Prop :=
  p = 0 ∨ (p &&& (p - 1) = 0 ∧ r &&& ~~~(p ||| (p - 1)) = 0)

namespace Ipv4

theorem item_sub (a1 m1 a2 m2 X b : BitVec 32) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (hi : a1 &&& m2 = a2 &&& m1) (hb : b &&& (b - 1) = 0) (hb0 : b ≠ 0)
    (hbd : b &&& diffBits m1 m2 = b)
    (hX : X &&& itemMask m1 (diffBits m1 m2) b = itemAddr (a1 ||| a2) m1 (diffBits m1 m2) b) :
    X &&& m1 = a1 ∧ X &&& m2 ≠ a2 := by
  unfold itemAddr itemMask diffBits at *
  bv_decide

/-- Every address of `S(A) \ S(B)` is in the item of the highest bit of `d` where
it differs from `A ∩ B`. -/
theorem item_cover (a1 m1 a2 m2 X : BitVec 32) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (hi : a1 &&& m2 = a2 &&& m1) (hA : X &&& m1 = a1) (hB : X &&& m2 ≠ a2) :
    highestBit32 ((X ^^^ (a1 ||| a2)) &&& diffBits m1 m2) ≠ 0 ∧
    highestBit32 ((X ^^^ (a1 ||| a2)) &&& diffBits m1 m2) &&& diffBits m1 m2 =
      highestBit32 ((X ^^^ (a1 ||| a2)) &&& diffBits m1 m2) ∧
    X &&& itemMask m1 (diffBits m1 m2) (highestBit32 ((X ^^^ (a1 ||| a2)) &&& diffBits m1 m2)) =
      itemAddr (a1 ||| a2) m1 (diffBits m1 m2)
        (highestBit32 ((X ^^^ (a1 ||| a2)) &&& diffBits m1 m2)) := by
  unfold itemAddr itemMask diffBits highestBit32
  bv_decide

theorem item_disjoint (a1 m1 a2 m2 X b c : BitVec 32)
    (hb : b &&& (b - 1) = 0) (hb0 : b ≠ 0) (hbd : b &&& diffBits m1 m2 = b)
    (hc : c &&& (c - 1) = 0) (hc0 : c ≠ 0) (hcd : c &&& diffBits m1 m2 = c) (hbc : b ≠ c)
    (hXb : X &&& itemMask m1 (diffBits m1 m2) b = itemAddr (a1 ||| a2) m1 (diffBits m1 m2) b)
    (hXc : X &&& itemMask m1 (diffBits m1 m2) c = itemAddr (a1 ||| a2) m1 (diffBits m1 m2) c) :
    False := by
  unfold itemAddr itemMask diffBits at *
  bv_decide

/-- The state `(mask, remaining)`: pending bits are bits of `d` and form a gap-free
run of them, and `mask` holds `m₁` plus exactly the bits of `d` above every
pending bit. -/
def Inv (m1 d mask r : BitVec 32) : Prop :=
  r &&& ~~~d = 0 ∧
  (r ≠ 0 →
    mask = m1 ||| (d &&& ~~~((highestBit32 r <<< 1) - 1)) ∧
    (d &&& ~~~(lowestBit r - 1) &&& ((highestBit32 r <<< 1) - 1)) &&& ~~~r = 0)

/-- `new()`: the general case starts from `mask = m₁`, `remaining = d`. -/
theorem inv_init (m1 d : BitVec 32) : Inv m1 d m1 d := by
  unfold Inv highestBit32 lowestBit
  bv_decide

/-- `next()`: `mask |= b` for the highest pending `b` emits the item of `b`. -/
theorem next_emits (m1 d mask r : BitVec 32) (h : Inv m1 d mask r) (hr : r ≠ 0) :
    mask ||| highestBit32 r = itemMask m1 d (highestBit32 r) ∧
    Inv m1 d (mask ||| highestBit32 r) (r ^^^ highestBit32 r) := by
  unfold Inv at *
  unfold itemMask highestBit32 lowestBit at *
  bv_decide

/-- `next_back()`: `mask | remaining` for the lowest pending `b` emits the item of
`b`, and `mask` itself is left alone. -/
theorem nextBack_emits (m1 d mask r : BitVec 32) (h : Inv m1 d mask r) (hr : r ≠ 0) :
    mask ||| r = itemMask m1 d (lowestBit r) ∧ Inv m1 d mask (r ^^^ lowestBit r) := by
  unfold Inv at *
  unfold itemMask highestBit32 lowestBit at *
  bv_decide

/-- `next()`'s choice of the peel bit from `predicted` and `remaining`. -/
def ladder (p r : BitVec 32) : BitVec 32 :=
  if p &&& r ≠ 0 then p else if (p >>> 1) &&& r ≠ 0 then p >>> 1 else highestBit32 r

theorem ladder_eq_highestBit (p r : BitVec 32) (h : LadderInv p r) :
    ladder p r = highestBit32 r := by
  unfold LadderInv at h
  unfold ladder highestBit32
  bv_decide

theorem ladder_init (r : BitVec 32) : LadderInv 0 r := Or.inl rfl

/-- After `next()` peels `b`, `predicted = b >> 1`. -/
theorem ladder_next (p r : BitVec 32) (h : LadderInv p r) :
    LadderInv (highestBit32 r >>> 1) (r ^^^ highestBit32 r) := by
  unfold LadderInv at *
  unfold highestBit32
  bv_decide

/-- `next_back()` leaves `predicted` alone and removes a pending bit. -/
theorem ladder_nextBack (p r : BitVec 32) (h : LadderInv p r) :
    LadderInv p (r ^^^ lowestBit r) := by
  unfold LadderInv at *
  unfold lowestBit
  bv_decide

/-- Disjoint `A`, `B`: borrowing the lowest mask bit `b` into the state
`(addr ^ b, mask ^ b, remaining = b)` makes either end emit `(addr, mask)`. -/
theorem disjoint_shortcut (addr mask : BitVec 32) (hn : addr &&& mask = addr) (hm : mask ≠ 0) :
    ((mask ^^^ lowestBit mask) ||| lowestBit mask = mask ∧
      ((addr ^^^ lowestBit mask) ^^^ lowestBit mask) &&&
        ((mask ^^^ lowestBit mask) ||| lowestBit mask) = addr) ∧
    highestBit32 (lowestBit mask) = lowestBit mask := by
  unfold lowestBit highestBit32
  bv_decide

end Ipv4

namespace Ipv6

theorem item_sub (a1 m1 a2 m2 X b : BitVec 128) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (hi : a1 &&& m2 = a2 &&& m1) (hb : b &&& (b - 1) = 0) (hb0 : b ≠ 0)
    (hbd : b &&& diffBits m1 m2 = b)
    (hX : X &&& itemMask m1 (diffBits m1 m2) b = itemAddr (a1 ||| a2) m1 (diffBits m1 m2) b) :
    X &&& m1 = a1 ∧ X &&& m2 ≠ a2 := by
  unfold itemAddr itemMask diffBits at *
  bv_decide

theorem item_cover (a1 m1 a2 m2 X : BitVec 128) (h1 : a1 &&& m1 = a1) (h2 : a2 &&& m2 = a2)
    (hi : a1 &&& m2 = a2 &&& m1) (hA : X &&& m1 = a1) (hB : X &&& m2 ≠ a2) :
    highestBit128 ((X ^^^ (a1 ||| a2)) &&& diffBits m1 m2) ≠ 0 ∧
    highestBit128 ((X ^^^ (a1 ||| a2)) &&& diffBits m1 m2) &&& diffBits m1 m2 =
      highestBit128 ((X ^^^ (a1 ||| a2)) &&& diffBits m1 m2) ∧
    X &&& itemMask m1 (diffBits m1 m2) (highestBit128 ((X ^^^ (a1 ||| a2)) &&& diffBits m1 m2)) =
      itemAddr (a1 ||| a2) m1 (diffBits m1 m2)
        (highestBit128 ((X ^^^ (a1 ||| a2)) &&& diffBits m1 m2)) := by
  unfold itemAddr itemMask diffBits highestBit128
  bv_decide

theorem item_disjoint (a1 m1 a2 m2 X b c : BitVec 128)
    (hb : b &&& (b - 1) = 0) (hb0 : b ≠ 0) (hbd : b &&& diffBits m1 m2 = b)
    (hc : c &&& (c - 1) = 0) (hc0 : c ≠ 0) (hcd : c &&& diffBits m1 m2 = c) (hbc : b ≠ c)
    (hXb : X &&& itemMask m1 (diffBits m1 m2) b = itemAddr (a1 ||| a2) m1 (diffBits m1 m2) b)
    (hXc : X &&& itemMask m1 (diffBits m1 m2) c = itemAddr (a1 ||| a2) m1 (diffBits m1 m2) c) :
    False := by
  unfold itemAddr itemMask diffBits at *
  bv_decide

def Inv (m1 d mask r : BitVec 128) : Prop :=
  r &&& ~~~d = 0 ∧
  (r ≠ 0 →
    mask = m1 ||| (d &&& ~~~((highestBit128 r <<< 1) - 1)) ∧
    (d &&& ~~~(lowestBit r - 1) &&& ((highestBit128 r <<< 1) - 1)) &&& ~~~r = 0)

theorem inv_init (m1 d : BitVec 128) : Inv m1 d m1 d := by
  unfold Inv highestBit128 lowestBit
  bv_decide

theorem next_emits (m1 d mask r : BitVec 128) (h : Inv m1 d mask r) (hr : r ≠ 0) :
    mask ||| highestBit128 r = itemMask m1 d (highestBit128 r) ∧
    Inv m1 d (mask ||| highestBit128 r) (r ^^^ highestBit128 r) := by
  unfold Inv at *
  unfold itemMask highestBit128 lowestBit at *
  bv_decide

theorem nextBack_emits (m1 d mask r : BitVec 128) (h : Inv m1 d mask r) (hr : r ≠ 0) :
    mask ||| r = itemMask m1 d (lowestBit r) ∧ Inv m1 d mask (r ^^^ lowestBit r) := by
  unfold Inv at *
  unfold itemMask highestBit128 lowestBit at *
  bv_decide

/-- `Ipv6NetworkDiff::next`'s peel bit and the `predicted` it stores, computed on
64-bit halves exactly as the Rust code does, `none` once nothing is pending. -/
def ladder (p r : BitVec 128) : Option (BitVec 128 × BitVec 128) :=
  if (r >>> 64).setWidth 64 ≠ 0 then
    if (p >>> 64).setWidth 64 &&& (r >>> 64).setWidth 64 ≠ 0 then
      some (((p >>> 64).setWidth 64).setWidth 128 <<< 64,
        ((p >>> 64).setWidth 64).setWidth 128 <<< 63)
    else if ((p >>> 64).setWidth 64 >>> 1) &&& (r >>> 64).setWidth 64 ≠ 0 then
      some ((((p >>> 64).setWidth 64) >>> 1).setWidth 128 <<< 64,
        (((p >>> 64).setWidth 64) >>> 1).setWidth 128 <<< 63)
    else
      some ((0x8000000000000000#64 >>> ((r >>> 64).setWidth 64).clz).setWidth 128 <<< 64,
        (0x8000000000000000#64 >>> ((r >>> 64).setWidth 64).clz).setWidth 128 <<< 63)
  else if p.setWidth 64 &&& r.setWidth 64 ≠ 0 then
    some ((p.setWidth 64).setWidth 128, (p.setWidth 64 >>> 1).setWidth 128)
  else if (p.setWidth 64 >>> 1) &&& r.setWidth 64 ≠ 0 then
    some ((p.setWidth 64 >>> 1).setWidth 128, (p.setWidth 64 >>> 2).setWidth 128)
  else if r.setWidth 64 = 0 then none
  else
    some ((0x8000000000000000#64 >>> (r.setWidth 64).clz).setWidth 128,
      ((0x8000000000000000#64 >>> (r.setWidth 64).clz) >>> 1).setWidth 128)

/-- The split ladder returns the highest pending bit of the whole `u128` and stores
`predicted = b >> 1`, even when `predicted` crosses from the high half into the
low one. -/
theorem ladder_eq_highestBit (p r : BitVec 128) (h : LadderInv p r) (hr : r ≠ 0) :
    ladder p r = some (highestBit128 r, highestBit128 r >>> 1) := by
  unfold LadderInv at h
  unfold ladder highestBit128
  split
  · split
    · simp only [Option.some.injEq, Prod.mk.injEq]
      constructor <;> bv_decide
    · split
      · simp only [Option.some.injEq, Prod.mk.injEq]
        constructor <;> bv_decide
      · simp only [Option.some.injEq, Prod.mk.injEq]
        constructor <;> bv_decide
  · split
    · simp only [Option.some.injEq, Prod.mk.injEq]
      constructor <;> bv_decide
    · split
      · simp only [Option.some.injEq, Prod.mk.injEq]
        constructor <;> bv_decide
      · split
        · exfalso
          bv_decide
        · simp only [Option.some.injEq, Prod.mk.injEq]
          constructor <;> bv_decide

theorem ladder_exhausted (p : BitVec 128) : ladder p 0 = none := by
  unfold ladder
  simp

theorem ladder_init (r : BitVec 128) : LadderInv 0 r := Or.inl rfl

theorem ladder_next (p r : BitVec 128) (h : LadderInv p r) :
    LadderInv (highestBit128 r >>> 1) (r ^^^ highestBit128 r) := by
  unfold LadderInv at *
  unfold highestBit128
  bv_decide

theorem ladder_nextBack (p r : BitVec 128) (h : LadderInv p r) :
    LadderInv p (r ^^^ lowestBit r) := by
  unfold LadderInv at *
  unfold lowestBit
  bv_decide

theorem disjoint_shortcut (addr mask : BitVec 128) (hn : addr &&& mask = addr) (hm : mask ≠ 0) :
    ((mask ^^^ lowestBit mask) ||| lowestBit mask = mask ∧
      ((addr ^^^ lowestBit mask) ^^^ lowestBit mask) &&&
        ((mask ^^^ lowestBit mask) ||| lowestBit mask) = addr) ∧
    highestBit128 (lowestBit mask) = lowestBit mask := by
  unfold lowestBit highestBit128
  bv_decide

end Ipv6

end Netip.Impl
