import Netip.Impl.AddrsRun
import Netip.Impl.BiContiguous

/-!
# `BiContiguousIpv6Addrs`

`BiContiguous::<Ipv6Network>::addrs` steps a host index through `0 ..= back` with
the cursor pair of `AddrsRun` and maps it to an address by the closed form
`base | (i & lo_mask) | ((i >> split_shift) << 64)`, where
`split_shift = 64 - lo_prefix` and `lo_mask = (1 << split_shift) - 1`.

Proved for every bi-contiguous mask: from index `i` to `i + 1` the closed form moves
exactly as the general step of `next` does (`indexToAddr_step`, by `bv_decide`),
and index `0` gives `base`. So the closed form of index `i` is the member with host
index `i` (`indexToAddr_eq`) and is strictly increasing in `i`
(`indexToAddr_lt_indexToAddr`). The iterator returns, call for call, what
`Ipv6NetworkAddrs` returns, except for the one address the general `/0` count
loses (`baddrs_run_eq`). Its count and `size_hint` are exact, and after
`2^(host bits)` calls the cursors have crossed, the sentinel in which every call
returns `None` (`baddrs_remaining`).
-/

namespace Netip.Impl

open Netip (hostAddr hostBits)

/-- The cursor bound of the index iterators: `MAX.checked_shr(w - k).unwrap_or(0)`
is `2^k - 1`. A shift by the full width gives `0` in `BitVec`, as in `unwrap_or(0)`. -/
theorem toNat_allOnes_ushiftRight {w k : Nat} (hk : k ≤ w) :
    (BitVec.allOnes w >>> (w - k)).toNat = 2 ^ k - 1 := by
  rw [BitVec.toNat_ushiftRight, BitVec.toNat_allOnes, Nat.shiftRight_eq_div_pow]
  have hp : 2 ^ k * 2 ^ (w - k) = 2 ^ w := by rw [← Nat.pow_add, Nat.add_sub_cancel' hk]
  have h1 := Nat.two_pow_pos k
  have h2 := Nat.two_pow_pos (w - k)
  have h3 := Nat.two_pow_pos w
  apply Nat.div_eq_of_lt_le
  · rw [Nat.sub_mul, hp, Nat.one_mul]
    omega
  · rw [Nat.sub_add_cancel h1, hp]
    omega

namespace Ipv6

/-- `split_shift = 64 - (mask as u64).leading_ones()`: the host bits of the low half. -/
def splitShift (mask : BitVec 128) : BitVec 128 := (64#64 - (~~~(lo mask)).clz).setWidth 128

/-- `lo_mask = (1u128 << split_shift) - 1`. -/
def loMask (mask : BitVec 128) : BitVec 128 := (1#128 <<< splitShift mask) - 1

/-- `index_to_addr`. -/
def indexToAddr (base mask i : BitVec 128) : BitVec 128 :=
  base ||| (i &&& loMask mask) ||| ((i >>> splitShift mask) <<< 64)

/-- `back = u128::MAX.checked_shr(128 - host_bits).unwrap_or(0)`. -/
def indexBack (mask : BitVec 128) : BitVec 128 := BitVec.allOnes 128 >>> (128#128 - (~~~mask).cpop)

theorem toNat_indexBack (mask : BitVec 128) : (indexBack mask).toNat = 2 ^ hostBits mask - 1 := by
  have hk := Netip.hostBits_le mask
  have hc := Netip.cpop_not_eq_hostBits mask
  have hsub : (128#128 - (~~~mask).cpop).toNat = 128 - hostBits mask := by
    rw [BitVec.toNat_sub_of_le (by rw [BitVec.le_def]; simp; omega)]
    simp
    omega
  rw [indexBack, BitVec.ushiftRight_eq', hsub]
  exact toNat_allOnes_ushiftRight hk

theorem indexToAddr_zero (base mask : BitVec 128) : indexToAddr base mask 0 = base := by
  unfold indexToAddr
  bv_decide

/-- From index `i` to `i + 1` the closed form takes the general step of `next`. -/
theorem indexToAddr_step (base mask i : BitVec 128) (hb : IsBiContiguous mask)
    (hn : base &&& mask = base) (hi : i < indexBack mask) :
    indexToAddr base mask (i + 1) = stepUp base mask (indexToAddr base mask i) := by
  unfold IsBiContiguous at hb
  unfold indexBack at hi
  unfold indexToAddr loMask splitShift lo stepUp
  bv_decide

/-- The closed form of index `i` is the member with host index `i`. -/
theorem indexToAddr_eq {base mask : BitVec 128} (hb : IsBiContiguous mask)
    (hn : base &&& mask = base) :
    ∀ j, j < 2 ^ hostBits mask → indexToAddr base mask (BitVec.ofNat 128 j) = hostAddr base mask j := by
  have hK := Nat.pow_le_pow_right (show 0 < 2 by decide) (Netip.hostBits_le mask)
  intro j
  induction j with
  | zero =>
    intro _
    rw [Netip.hostAddr_zero]
    exact indexToAddr_zero base mask
  | succ j ih =>
    intro hj
    have hlt : BitVec.ofNat 128 j < indexBack mask := by
      rw [BitVec.lt_def, toNat_indexBack, BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega)]
      omega
    rw [BitVec.ofNat_add, show BitVec.ofNat 128 1 = 1 from rfl, indexToAddr_step base mask _ hb hn hlt,
      ih (by omega), stepUp_hostAddr stepFacts128 hn hj]

/-- The closed form is strictly increasing in the index. -/
theorem indexToAddr_lt_indexToAddr {base mask : BitVec 128} (hb : IsBiContiguous mask)
    (hn : base &&& mask = base) {i j : Nat} (hij : i < j) (hj : j < 2 ^ hostBits mask) :
    indexToAddr base mask (BitVec.ofNat 128 i) < indexToAddr base mask (BitVec.ofNat 128 j) := by
  rw [indexToAddr_eq hb hn i (by omega), indexToAddr_eq hb hn j hj]
  exact Netip.hostAddr_lt_hostAddr hn hij hj

/-- `BiContiguous::<Ipv6Network>::addrs`: the indices `0 ..= back`. -/
def baddrsInit (mask : BitVec 128) : Cursor 128 := ⟨0, indexBack mask⟩

theorem baddrsInit_inv (mask : BitVec 128) :
    CursorInv 0 (2 ^ hostBits mask) (baddrsInit mask) 0 0 := by
  have := @Nat.one_le_two_pow (hostBits mask)
  refine ⟨fun _ => ⟨rfl, ?_⟩, fun h => by omega⟩
  simp only [baddrsInit]
  rw [toNat_indexBack]
  omega

theorem baddrs_bound (mask : BitVec 128) : 0 + 2 ^ hostBits mask ≤ 2 ^ 128 := by
  have := Nat.pow_le_pow_right (show 0 < 2 by decide) (Netip.hostBits_le mask)
  omega

/-- On every schedule the iterator returns the members in host-index order from both
ends. -/
theorem baddrs_run {addr mask : BitVec 128} (hn : addr &&& mask = addr) (hb : IsBiContiguous mask)
    (fs : List Bool) :
    (cursorRun fs (baddrsInit mask)).1.map (Option.map (indexToAddr addr mask)) =
      expected (hostAddr addr mask) (2 ^ hostBits mask) (2 ^ hostBits mask) 0 0 fs := by
  rw [(cursorRun_spec (by decide) (baddrs_bound mask) fs _ 0 0 (baddrsInit_inv mask)).1, expected_map]
  apply expected_congr (Nat.le_refl _)
  intro i hi
  rw [Nat.zero_add, indexToAddr_eq hb hn i hi]

/-- The same sequence as `Ipv6NetworkAddrs`, for every mask but the `/0`, and for
every schedule of fewer than `2^128` calls. -/
theorem baddrs_run_eq {addr mask : BitVec 128} (hn : addr &&& mask = addr) (hb : IsBiContiguous mask)
    (fs : List Bool) (h : hostBits mask < 128 ∨ fs.length ≤ 2 ^ 128 - 1) :
    (cursorRun fs (baddrsInit mask)).1.map (Option.map (indexToAddr addr mask)) =
      (addrsRun fs (addrsInit addr mask)).1 := by
  rw [baddrs_run hn hb]
  rcases h with hk | hlen
  · rw [addrs_run hn, show addrsCount mask = 2 ^ hostBits mask by simp [addrsCount, hk]]
  · rw [addrs_run_exact hn fs hlen]

/-- The count left is exact, `size_hint` saturates only above `usize::MAX`, and once
`2^(host bits)` calls are made the cursors have crossed. -/
theorem baddrs_remaining (mask : BitVec 128) (fs : List Bool) (ub : Nat) (hub : ub ≤ 128) :
    cursorCount (cursorRun fs (baddrsInit mask)).2 = 2 ^ hostBits mask - fs.length ∧
      cursorSizeHint128 ub (cursorRun fs (baddrsInit mask)).2 =
        sizeHint ub (2 ^ hostBits mask - fs.length) ∧
      (2 ^ hostBits mask ≤ fs.length →
        (cursorRun fs (baddrsInit mask)).2.hi < (cursorRun fs (baddrsInit mask)).2.lo) := by
  obtain ⟨-, hinv⟩ := cursorRun_spec (by decide) (baddrs_bound mask) fs _ 0 0 (baddrsInit_inv mask)
  have hcount := count_true_add_count_false fs
  have hc : cursorCount (cursorRun fs (baddrsInit mask)).2 = 2 ^ hostBits mask - fs.length := by
    rw [cursorCount_eq hinv]
    omega
  exact ⟨hc, by rw [cursorSizeHint128_eq hub, hc], fun h => hinv.2 (by omega)⟩

end Ipv6

end Netip.Impl
