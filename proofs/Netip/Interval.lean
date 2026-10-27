import Netip.Network
import Std.Tactic.BVDecide

/-!
# Contiguous ⟺ interval

`S(a, m)` is an interval of the integer order iff `m` is contiguous. For the
"only if" half, a non-contiguous mask has a free bit `ep` above a fixed bit `eq`,
and `hole a ep eq` is a non-member strictly between the members `a` and `a ∨ ep`.

The witness needs two cases. Flipping bit `eq` of `a` works when that bit of `a`
is clear. When it is set, the flip lands below `a`, the smallest member, so the
bit is cleared in `a ∨ ep` instead.

Proved for the widths the library uses, a proof for symbolic `n` is still to be
written. Bits are one-hot masks here, so "`eq` sits below `ep`" is `eq < ep`.
-/

namespace Netip

/-- A non-member between the members `a` and `a ∨ ep`, for a free bit `ep` above a
fixed bit `eq`. -/
def hole {w : Nat} (a ep eq : BitVec w) : BitVec w :=
  if a &&& eq = 0 then a ||| eq else (a ||| ep) &&& ~~~eq

theorem hole_between_32 (a m ep eq : BitVec 32) (hn : Normalized a m)
    (hep : ep &&& (ep - 1) = 0) (heq : eq &&& (eq - 1) = 0) (hlt : eq < ep)
    (hfree : m &&& ep = 0) (hfixed : m &&& eq ≠ 0) :
    S a m (a ||| ep) ∧ ¬ S a m (hole a ep eq) ∧ a < hole a ep eq ∧ hole a ep eq < a ||| ep := by
  unfold Normalized at hn
  unfold S hole
  bv_decide

theorem hole_between_128 (a m ep eq : BitVec 128) (hn : Normalized a m)
    (hep : ep &&& (ep - 1) = 0) (heq : eq &&& (eq - 1) = 0) (hlt : eq < ep)
    (hfree : m &&& ep = 0) (hfixed : m &&& eq ≠ 0) :
    S a m (a ||| ep) ∧ ¬ S a m (hole a ep eq) ∧ a < hole a ep eq ∧ hole a ep eq < a ||| ep := by
  unfold Normalized at hn
  unfold S hole
  bv_decide

/-- `S(a, m)` is closed under betweenness iff `m` passes `is_contiguous`.

For a non-contiguous `m`, the fixed bit is the lowest set bit of `m` and the free
bit is the lowest clear bit above it. -/
theorem interval_iff_contiguous_32 (a m : BitVec 32) (hn : Normalized a m) :
    (∀ x y z, S a m x → S a m z → x ≤ y → y ≤ z → S a m y) ↔
      m ||| (m - 1) = BitVec.allOnes 32 := by
  constructor
  · intro h
    apply Classical.byContradiction
    intro hc
    have hn' : a &&& m = a := hn
    have hh := hole_between_32 a m (~~~(m ||| (m - 1)) &&& -(~~~(m ||| (m - 1)))) (m &&& -m) hn
      (by bv_decide) (by bv_decide) (by bv_decide) (by bv_decide) (by bv_decide)
    exact hh.2.1 (h _ _ _ hn hh.1 (BitVec.le_of_lt hh.2.2.1) (BitVec.le_of_lt hh.2.2.2))
  · intro hc x y z hx hz hxy hyz
    unfold Normalized at hn
    unfold S at *
    bv_decide

theorem interval_iff_contiguous_128 (a m : BitVec 128) (hn : Normalized a m) :
    (∀ x y z, S a m x → S a m z → x ≤ y → y ≤ z → S a m y) ↔
      m ||| (m - 1) = BitVec.allOnes 128 := by
  constructor
  · intro h
    apply Classical.byContradiction
    intro hc
    have hn' : a &&& m = a := hn
    have hh := hole_between_128 a m (~~~(m ||| (m - 1)) &&& -(~~~(m ||| (m - 1)))) (m &&& -m) hn
      (by bv_decide) (by bv_decide) (by bv_decide) (by bv_decide) (by bv_decide)
    exact hh.2.1 (h _ _ _ hn hh.1 (BitVec.le_of_lt hh.2.2.1) (BitVec.le_of_lt hh.2.2.2))
  · intro hc x y z hx hz hxy hyz
    unfold Normalized at hn
    unfold S at *
    bv_decide

end Netip
