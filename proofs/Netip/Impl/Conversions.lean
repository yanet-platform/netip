import Netip.Impl.Supernet

/-!
# Conversions: `to_contiguous`, IPv4-mapped networks, `to_canonical`

* `to_contiguous` keeps the leading run of the mask. The result is the smallest
  CIDR network containing the input.
* `Ipv4Network::to_ipv6_mapped` embeds a network into `::ffff:0:0/96`, and its
  address set is the image of the IPv4 one. `Ipv6Network::to_ipv4_mapped`
  inverts it exactly on the networks `is_ipv4_mapped_ipv6` accepts.
* `IpNetwork::to_canonical` never changes the dual-stack view
  `IpNetwork::to_ipv6_mapped`.
-/

namespace Netip.Impl

variable {w : Nat}

/-- `to_contiguous`: `Self::new(addr, mask_from_cidr(mask.leading_ones()))`. -/
def toContiguous (a m : BitVec w) : BitVec w × BitVec w :=
  (a &&& maskFromCidr w (~~~m).clz, maskFromCidr w (~~~m).clz)

namespace Ipv4

/-- The `NOTE` in `to_contiguous`: `leading_ones` is at most 32, which
`ipv4_mask_from_cidr` always accepts. -/
theorem leadingOnes_le (m : BitVec 32) : (~~~m).clz ≤ 32 := by
  bv_decide

/-- The result mask is contiguous, inside the input mask, and the largest
contiguous mask inside it. -/
theorem toContiguous_mask (m k : BitVec 32) (hk : k ≤ 32) :
    IsContiguous (toContiguous 0 m).2 ∧ Sub (toContiguous 0 m).2 m ∧
    (Sub (maskFromCidr 32 k) m → Sub (maskFromCidr 32 k) (toContiguous 0 m).2) := by
  simp only [toContiguous, IsContiguous, Sub, maskFromCidr]
  bv_decide

/-- The result contains the input, and every CIDR network containing the input
contains the result. -/
theorem toContiguous_minimal (a m c k : BitVec 32) (h : a &&& m = a) (hk : k ≤ 32) :
    Contains (toContiguous a m) (a, m) ∧
    (Contains (c, maskFromCidr 32 k) (a, m) → Contains (c, maskFromCidr 32 k) (toContiguous a m)) := by
  simp only [toContiguous, Contains, maskFromCidr]
  bv_decide

/-- `Ipv4Network::to_ipv6_mapped`: address `::ffff:a`, mask `ffff:...:ffff:m`. -/
def toIpv6Mapped (a m : BitVec 32) : BitVec 128 × BitVec 128 :=
  ((0xffff#128 <<< 32) ||| a.setWidth 128, (BitVec.allOnes 128 <<< 32) ||| m.setWidth 128)

/-- The mapped network is normalized, and its members are exactly `::ffff:X` for
the members `X` of the IPv4 network. -/
theorem toIpv6Mapped_mem (a m : BitVec 32) (X : BitVec 128) (h : a &&& m = a) :
    (toIpv6Mapped a m).1 &&& (toIpv6Mapped a m).2 = (toIpv6Mapped a m).1 ∧
    (X &&& (toIpv6Mapped a m).2 = (toIpv6Mapped a m).1 ↔
      X >>> 32 = 0xffff#128 ∧ X.setWidth 32 &&& m = a) := by
  simp only [toIpv6Mapped]
  bv_decide

end Ipv4

namespace Ipv6

theorem leadingOnes_le (m : BitVec 128) : (~~~m).clz ≤ 128 := by
  bv_decide

theorem toContiguous_mask (m k : BitVec 128) (hk : k ≤ 128) :
    IsContiguous (toContiguous 0 m).2 ∧ Sub (toContiguous 0 m).2 m ∧
    (Sub (maskFromCidr 128 k) m → Sub (maskFromCidr 128 k) (toContiguous 0 m).2) := by
  simp only [toContiguous, IsContiguous, Sub, maskFromCidr]
  bv_decide

theorem toContiguous_minimal (a m c k : BitVec 128) (h : a &&& m = a) (hk : k ≤ 128) :
    Contains (toContiguous a m) (a, m) ∧
    (Contains (c, maskFromCidr 128 k) (a, m) → Contains (c, maskFromCidr 128 k) (toContiguous a m)) := by
  simp only [toContiguous, Contains, maskFromCidr]
  bv_decide

/-- `is_ipv4_mapped_ipv6`: the address lies in `::ffff:0:0/96` and the mask fixes
all 96 bits of that prefix. -/
def IsIpv4Mapped (a m : BitVec 128) : Prop :=
  a &&& 0xffffffffffffffffffffffff00000000#128 = 0x00000000000000000000ffff00000000#128 ∧
  m &&& 0xffffffffffffffffffffffff00000000#128 = 0xffffffffffffffffffffffff00000000#128

instance (a m : BitVec 128) : Decidable (IsIpv4Mapped a m) := by
  unfold IsIpv4Mapped
  infer_instance

/-- `to_ipv4_mapped`: the low 32 bits of address and mask, when mapped. -/
def toIpv4Mapped (a m : BitVec 128) : Option (BitVec 32 × BitVec 32) :=
  if IsIpv4Mapped a m then
    some ((a &&& 0xffffffff#128).setWidth 32, (m &&& 0xffffffff#128).setWidth 32)
  else none

/-- The IPv4 network `to_ipv4_mapped` returns is normalized (the `NOTE`), and
mapping it back gives the original network. -/
theorem toIpv4Mapped_spec (a6 m6 : BitVec 128) (a m : BitVec 32) (h : a6 &&& m6 = a6)
    (hs : toIpv4Mapped a6 m6 = some (a, m)) :
    a &&& m = a ∧ Ipv4.toIpv6Mapped a m = (a6, m6) := by
  unfold toIpv4Mapped at hs
  split at hs
  · rename_i hmap
    unfold IsIpv4Mapped at hmap
    simp only [Option.some.injEq, Prod.mk.injEq] at hs
    obtain ⟨rfl, rfl⟩ := hs
    simp only [Ipv4.toIpv6Mapped, Prod.mk.injEq]
    refine ⟨by bv_decide, by bv_decide, by bv_decide⟩
  · simp at hs

/-- `to_ipv4_mapped (to_ipv6_mapped n) = Some n`. -/
theorem toIpv4Mapped_toIpv6Mapped (a m : BitVec 32) :
    toIpv4Mapped (Ipv4.toIpv6Mapped a m).1 (Ipv4.toIpv6Mapped a m).2 = some (a, m) := by
  have hmap : IsIpv4Mapped (Ipv4.toIpv6Mapped a m).1 (Ipv4.toIpv6Mapped a m).2 := by
    simp only [IsIpv4Mapped, Ipv4.toIpv6Mapped]
    bv_decide
  unfold toIpv4Mapped
  rw [ite_eq_left hmap]
  simp only [Ipv4.toIpv6Mapped, Option.some.injEq, Prod.mk.injEq]
  constructor <;> bv_decide

/-- An address outside `::ffff:0:0/96` gives `None`. -/
theorem toIpv4Mapped_none (a m : BitVec 128) (h : a >>> 32 ≠ 0xffff#128) :
    toIpv4Mapped a m = none := by
  have : ¬ IsIpv4Mapped a m := by
    unfold IsIpv4Mapped
    bv_decide
  unfold toIpv4Mapped
  rw [ite_eq_right this]

end Ipv6

/-- `IpNetwork`, on bit patterns. -/
inductive IpNet where
  | v4 (a m : BitVec 32)
  | v6 (a m : BitVec 128)

namespace IpNet

/-- Every network of the enum is normalized. -/
def Normalized : IpNet → Prop
  | v4 a m => a &&& m = a
  | v6 a m => a &&& m = a

/-- `IpNetwork::to_ipv6_mapped`: IPv4 is embedded, IPv6 is the identity. -/
def toIpv6Mapped : IpNet → BitVec 128 × BitVec 128
  | v4 a m => Ipv4.toIpv6Mapped a m
  | v6 a m => (a, m)

/-- `IpNetwork::to_canonical`: an IPv4-mapped IPv6 network becomes IPv4. -/
def toCanonical : IpNet → IpNet
  | v4 a m => v4 a m
  | v6 a m =>
    match Ipv6.toIpv4Mapped a m with
    | some (a', m') => v4 a' m'
    | none => v6 a m

/-- Canonicalization keeps the network normalized and leaves its dual-stack view
unchanged. -/
theorem toCanonical_spec (n : IpNet) (h : n.Normalized) :
    n.toCanonical.Normalized ∧ n.toCanonical.toIpv6Mapped = n.toIpv6Mapped := by
  cases n with
  | v4 a m => exact ⟨h, rfl⟩
  | v6 a m =>
    simp only [Normalized] at h
    simp only [toCanonical]
    split
    · rename_i a' m' hs
      have := Ipv6.toIpv4Mapped_spec a m a' m' h hs
      exact ⟨this.1, this.2⟩
    · exact ⟨h, rfl⟩

end IpNet

end Netip.Impl
