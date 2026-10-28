import Netip.Impl.Basic

/-!
# Address iterators: the O(1) steps

`Ipv4NetworkAddrs::{next, next_back}` and `Ipv6NetworkAddrs::{next, next_back}`
move between members with
* `next`: `((bits | mask).wrapping_add(1) & !mask) | base`,
* `next_back`: `((bits & !mask).wrapping_sub(1) & !mask) | base`,
and with a plain `±1` when the host mask is a trailing run.

Proved: from a member that is not the last (first) one, the general step lands on
the numerically next (previous) member, and the `±1` fast path agrees with it.
Starting from `base`, the iterator therefore lists the members in ascending
numeric order. That this is also the documented host-index order (index bits
deposited into the host positions) follows from `pdep` being monotone, which is
not formalized here.
-/

namespace Netip.Impl

namespace Ipv4

theorem next_step (base mask bits y : BitVec 32) (hb : base &&& mask = base)
    (hbits : bits &&& mask = base) (hlast : bits ≠ base ||| ~~~mask) :
    ((((bits ||| mask) + 1) &&& ~~~mask) ||| base) &&& mask = base ∧
    bits < (((bits ||| mask) + 1) &&& ~~~mask) ||| base ∧
    (y &&& mask = base → bits < y → (((bits ||| mask) + 1) &&& ~~~mask) ||| base ≤ y) := by
  bv_decide

theorem nextBack_step (base mask bits y : BitVec 32) (hb : base &&& mask = base)
    (hbits : bits &&& mask = base) (hfirst : bits ≠ base) :
    ((((bits &&& ~~~mask) - 1) &&& ~~~mask) ||| base) &&& mask = base ∧
    (((bits &&& ~~~mask) - 1) &&& ~~~mask) ||| base < bits ∧
    (y &&& mask = base → y < bits → y ≤ (((bits &&& ~~~mask) - 1) &&& ~~~mask) ||| base) := by
  bv_decide

/-- The contiguous fast path of `next`: `bits + 1` is the general step. -/
theorem next_fastPath (base mask bits : BitVec 32) (hb : base &&& mask = base)
    (hbits : bits &&& mask = base) (hc : ~~~mask &&& (~~~mask + 1) = 0)
    (hlast : bits ≠ base ||| ~~~mask) :
    bits + 1 = (((bits ||| mask) + 1) &&& ~~~mask) ||| base := by
  bv_decide

/-- The contiguous fast path of `next_back`: `bits - 1` is the general step. -/
theorem nextBack_fastPath (base mask bits : BitVec 32) (hb : base &&& mask = base)
    (hbits : bits &&& mask = base) (hc : ~~~mask &&& (~~~mask + 1) = 0) (hfirst : bits ≠ base) :
    bits - 1 = (((bits &&& ~~~mask) - 1) &&& ~~~mask) ||| base := by
  bv_decide

end Ipv4

namespace Ipv6

theorem next_step (base mask bits y : BitVec 128) (hb : base &&& mask = base)
    (hbits : bits &&& mask = base) (hlast : bits ≠ base ||| ~~~mask) :
    ((((bits ||| mask) + 1) &&& ~~~mask) ||| base) &&& mask = base ∧
    bits < (((bits ||| mask) + 1) &&& ~~~mask) ||| base ∧
    (y &&& mask = base → bits < y → (((bits ||| mask) + 1) &&& ~~~mask) ||| base ≤ y) := by
  bv_decide

theorem nextBack_step (base mask bits y : BitVec 128) (hb : base &&& mask = base)
    (hbits : bits &&& mask = base) (hfirst : bits ≠ base) :
    ((((bits &&& ~~~mask) - 1) &&& ~~~mask) ||| base) &&& mask = base ∧
    (((bits &&& ~~~mask) - 1) &&& ~~~mask) ||| base < bits ∧
    (y &&& mask = base → y < bits → y ≤ (((bits &&& ~~~mask) - 1) &&& ~~~mask) ||| base) := by
  bv_decide

theorem next_fastPath (base mask bits : BitVec 128) (hb : base &&& mask = base)
    (hbits : bits &&& mask = base) (hc : ~~~mask &&& (~~~mask + 1) = 0)
    (hlast : bits ≠ base ||| ~~~mask) :
    bits + 1 = (((bits ||| mask) + 1) &&& ~~~mask) ||| base := by
  bv_decide

theorem nextBack_fastPath (base mask bits : BitVec 128) (hb : base &&& mask = base)
    (hbits : bits &&& mask = base) (hc : ~~~mask &&& (~~~mask + 1) = 0) (hfirst : bits ≠ base) :
    bits - 1 = (((bits &&& ~~~mask) - 1) &&& ~~~mask) ||| base := by
  bv_decide

end Ipv6

end Netip.Impl
