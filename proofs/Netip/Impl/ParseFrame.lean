import Netip.Impl.ParseAddr

/-!
# `core`'s readers on a prefix

The fast paths of the network parsers read an address as a prefix of their input and
stop before a `/` or the end of a token, where the split-first reference parses the
bytes before the `/` on their own. Both agree because `core`'s readers decide on the
bytes they read and the byte after: on `x ++ y`, where `y` starts with a byte that
cannot continue the address, every reader returns what it returns on `x`, with `y`
appended to the rest (`readIpv4Addr_append`, `readIpv6Addr_append`). Failures included:
a reader that fails on `x ++ y` fails on `x`, and the other way round.

So where `ipv4_parse_at` or `ipv6_parse_at` stops before such a byte, `core`, and the
hand-written whole-input parser with it, parse the consumed bytes alone to the same
address (`parseIpv4_take`, `ipv4ParseAscii_take` and their IPv6 counterparts).
-/

namespace Netip.Impl.Parse

/-- `y` is empty or starts with a byte that is no `radix` digit. -/
def NoDigitHead (radix : Nat) (y : Bytes) : Prop := ∀ b, y.head? = some b → toDigit radix b = none

/-- `y` is empty or starts with a byte that is no digit and no `.`: it cannot continue
an IPv4 address. -/
def StopsV4 (y : Bytes) : Prop := ∀ b, y.head? = some b → toDigit 10 b = none ∧ b ≠ 46

/-- `y` is empty or starts with a byte that is no hex digit, `:` or `.`: it cannot
continue an IPv6 address. -/
def StopsV6 (y : Bytes) : Prop := ∀ b, y.head? = some b → toDigit 16 b = none ∧ b ≠ 58 ∧ b ≠ 46

theorem StopsV6.v4 {y : Bytes} (h : StopsV6 y) : StopsV4 y := by
  intro b hb
  obtain ⟨h16, -, hdot⟩ := h b hb
  refine ⟨?_, hdot⟩
  cases h10 : toDigit 10 b with
  | none => rfl
  | some d => rw [toDigit_16_of_10 h10] at h16; simp at h16

theorem StopsV4.noDigit {y : Bytes} (h : StopsV4 y) : NoDigitHead 10 y := fun b hb => (h b hb).1

theorem StopsV6.noHex {y : Bytes} (h : StopsV6 y) : NoDigitHead 16 y := fun b hb => (h b hb).1

/-- A slice stops an IPv6 address after `n` bytes when `StopV6` holds there. -/
theorem stopsV6_drop {s : Bytes} {n : Nat} (h : StopV6 s n) : StopsV6 (s.drop n) := by
  intro b hb
  apply h b
  simpa using hb

/-- The digit run of `x ++ y`, when `y` cannot continue it. -/
theorem digitRun_append {radix : Nat} (x : Bytes) {y : Bytes} (hy : NoDigitHead radix y) :
    digitRun radix (x ++ y) = ((digitRun radix x).1, (digitRun radix x).2 ++ y) := by
  induction x with
  | nil =>
    cases y with
    | nil => simp [digitRun]
    | cons b y => simp [digitRun, hy b rfl]
  | cons b x ih =>
    cases hb : toDigit radix b with
    | none => simp [digitRun, hb]
    | some d => simp [digitRun, hb, ih]

namespace Core

theorem readRadixMaxDigits_append {radix maxDigits : Nat} {allowZeroPrefix : Bool} {bound : Nat}
    (hmax : 1 ≤ maxDigits) (x : Bytes) {y : Bytes} (hy : NoDigitHead radix y) :
    readRadixMaxDigits radix maxDigits allowZeroPrefix bound (x ++ y) =
      (readRadixMaxDigits radix maxDigits allowZeroPrefix bound x).map (fun p => (p.1, p.2 ++ y)) := by
  rw [readRadixMaxDigits_eq _ _ _ _ hmax, readRadixMaxDigits_eq _ _ _ _ hmax, digitRun_append x hy]
  simp only
  generalize (digitRun radix x).1 = ds
  match ds with
  | [] => rfl
  | first :: rest =>
    simp only
    split
    · rfl
    · split
      · rfl
      · split <;> rfl

theorem readGivenChar_append (c : UInt8) {x : Bytes} (hx : x ≠ []) (y : Bytes) :
    readGivenChar c (x ++ y) = (readGivenChar c x).map (· ++ y) := by
  match x, hx with
  | b :: x, _ =>
    simp only [List.cons_append, readGivenChar]
    split <;> rfl

theorem readOctet_append (x : Bytes) {y : Bytes} (hy : NoDigitHead 10 y) :
    readOctet (x ++ y) = (readOctet x).map (fun p => (p.1, p.2 ++ y)) :=
  readRadixMaxDigits_append (by decide) x hy

theorem readGroup_append (x : Bytes) {y : Bytes} (hy : NoDigitHead 16 y) :
    readGroup (x ++ y) = (readGroup x).map (fun p => (p.1, p.2 ++ y)) :=
  readRadixMaxDigits_append (by decide) x hy

/-- `.` then an octet. -/
theorem sepOctet_append (x : Bytes) {y : Bytes} (hy : StopsV4 y) :
    (readGivenChar 46 (x ++ y)).bind readOctet =
      ((readGivenChar 46 x).bind readOctet).map (fun p => (p.1, p.2 ++ y)) := by
  cases x with
  | nil =>
    cases y with
    | nil => rfl
    | cons b y =>
      have := (hy b rfl).2
      simp [readGivenChar, this]
  | cons b x =>
    rw [readGivenChar_append 46 (by simp) y]
    cases readGivenChar 46 (b :: x) with
    | none => rfl
    | some u =>
      simp only [Option.map_some, Option.bind_some]
      exact readOctet_append u hy.noDigit

/-- `read_ipv4_addr` on `x ++ y` reads what it reads on `x`, when `y` cannot continue
an IPv4 address. -/
theorem readIpv4Addr_append (x : Bytes) {y : Bytes} (hy : StopsV4 y) :
    readIpv4Addr (x ++ y) = (readIpv4Addr x).map (fun p => (p.1, p.2 ++ y)) := by
  unfold readIpv4Addr
  rw [readOctet_append x hy.noDigit]
  cases readOctet x with
  | none => rfl
  | some p =>
    obtain ⟨a, r1⟩ := p
    simp only [Option.map_some]
    rw [sepOctet_append r1 hy]
    cases (readGivenChar 46 r1).bind readOctet with
    | none => rfl
    | some p =>
      obtain ⟨b, r2⟩ := p
      simp only [Option.map_some]
      rw [sepOctet_append r2 hy]
      cases (readGivenChar 46 r2).bind readOctet with
      | none => rfl
      | some p =>
        obtain ⟨c, r3⟩ := p
        simp only [Option.map_some]
        rw [sepOctet_append r3 hy]
        cases (readGivenChar 46 r3).bind readOctet with
        | none => rfl
        | some p => rfl

/-- Nothing that cannot continue an IPv6 address starts an IPv4 address or a group. -/
theorem readIpv4Addr_stops {y : Bytes} (hy : StopsV6 y) : readIpv4Addr y = none := by
  have := readIpv4Addr_append [] hy.v4
  simp only [List.nil_append] at this
  rw [this]
  simp [readIpv4Addr, readOctet, readRadixMaxDigits]

theorem readGroup_stops {y : Bytes} (hy : StopsV6 y) : readGroup y = none := by
  have := readGroup_append [] hy.noHex
  simp only [List.nil_append] at this
  rw [this]
  simp [readGroup, readRadixMaxDigits]

theorem readGivenChar_colon_stops {y : Bytes} (hy : StopsV6 y) : readGivenChar 58 y = none := by
  cases y with
  | nil => rfl
  | cons b y =>
    have := (hy b rfl).2.1
    simp [readGivenChar, this]

theorem readSeparator_append (index : Nat) (x : Bytes) {y : Bytes} (hy : StopsV6 y) :
    readSeparator 58 index (x ++ y) = (readSeparator 58 index x).map (· ++ y) := by
  unfold readSeparator
  split
  · cases x with
    | nil => rw [List.nil_append, readGivenChar_colon_stops hy]; rfl
    | cons b x => exact readGivenChar_append 58 (by simp) y
  · rfl

/-- `read_groups` on `x ++ y` reads what it reads on `x`, when `y` cannot continue an
IPv6 address. -/
theorem readGroupsLoop_append (limit : Nat) {y : Bytes} (hy : StopsV6 y) :
    ∀ fuel index acc x, readGroupsLoop limit fuel index acc (x ++ y) =
      ((readGroupsLoop limit fuel index acc x).1, (readGroupsLoop limit fuel index acc x).2.1,
        (readGroupsLoop limit fuel index acc x).2.2 ++ y) := by
  intro fuel
  induction fuel with
  | zero => intro index acc x; rfl
  | succ fuel ih =>
    intro index acc x
    simp only [readGroupsLoop]
    rw [readSeparator_append index x hy]
    cases hsep : readSeparator 58 index x with
    | none => simp
    | some u =>
      simp only [Option.map_some, Option.bind_some]
      rw [readIpv4Addr_append u hy.v4, readGroup_append u hy.noHex]
      by_cases hc : index + 1 < limit
      · simp only [hc, ↓reduceIte]
        cases readIpv4Addr u with
        | some p => rfl
        | none =>
          simp only [Option.map_none]
          cases readGroup u with
          | none => simp
          | some p => exact ih (index + 1) _ p.2
      · simp only [hc, ↓reduceIte]
        cases readGroup u with
        | none => simp
        | some p => exact ih (index + 1) _ p.2

theorem readGroups_append (limit : Nat) (x : Bytes) {y : Bytes} (hy : StopsV6 y) :
    readGroups limit (x ++ y) =
      ((readGroups limit x).1, (readGroups limit x).2.1, (readGroups limit x).2.2 ++ y) :=
  readGroupsLoop_append limit hy limit 0 [] x

/-- `::` read off `r ++ y` is read off `r`. -/
theorem colons_append (r : Bytes) {y : Bytes} (hy : StopsV6 y) :
    (readGivenChar 58 (r ++ y)).bind (readGivenChar 58) =
      ((readGivenChar 58 r).bind (readGivenChar 58)).map (· ++ y) := by
  have hc := readGivenChar_colon_stops hy
  match r with
  | [] => rw [List.nil_append, hc]; rfl
  | [c] =>
    rw [List.cons_append, List.nil_append]
    by_cases h58 : c = 58
    · subst h58
      have e1 : readGivenChar 58 (58 :: y) = some y := by simp [readGivenChar]
      have e2 : readGivenChar 58 [58] = some [] := by simp [readGivenChar]
      rw [e1, e2, Option.bind_some, Option.bind_some, hc]
      rfl
    · have e1 : readGivenChar 58 (c :: y) = none := by simp [readGivenChar, h58]
      have e2 : readGivenChar 58 [c] = none := by simp [readGivenChar, h58]
      rw [e1, e2]
      rfl
  | c1 :: c2 :: r =>
    rw [readGivenChar_append 58 (by simp) y]
    cases readGivenChar 58 (c1 :: c2 :: r) with
    | none => rfl
    | some u =>
      simp only [Option.map_some, Option.bind_some]
      match u with
      | [] => rw [List.nil_append, hc]; rfl
      | b :: u => exact readGivenChar_append 58 (by simp) y

/-- `read_ipv6_addr` on `x ++ y` reads what it reads on `x`, when `y` cannot continue
an IPv6 address. -/
theorem readIpv6Addr_append (x : Bytes) {y : Bytes} (hy : StopsV6 y) :
    readIpv6Addr (x ++ y) = (readIpv6Addr x).map (fun p => (p.1, p.2 ++ y)) := by
  unfold readIpv6Addr
  rw [readGroups_append 8 x hy]
  generalize readGroups 8 x = H
  obtain ⟨head, hipv4, r⟩ := H
  simp only
  split
  · rfl
  · split
    · rfl
    · rw [colons_append r hy]
      cases (readGivenChar 58 r).bind (readGivenChar 58) with
      | none => rfl
      | some u =>
        simp only [Option.map_some]
        rw [readGroups_append _ u hy]

end Core

/-- Where `core` reads an IPv4 address from `s` and stops after `n` bytes, before a
byte that cannot continue it, it parses those `n` bytes alone to the same address. -/
theorem parseIpv4_take {s : Bytes} {a : BitVec 32} {n : Nat} (h : Core.readIpv4Addr s = some (a, s.drop n))
    (hy : StopsV4 (s.drop n)) (hn : n ≤ 15) : Core.parseIpv4 (s.take n) = some a := by
  have e := Core.readIpv4Addr_append (s.take n) hy
  rw [List.take_append_drop, h] at e
  cases hp : Core.readIpv4Addr (s.take n) with
  | none => simp [hp] at e
  | some p =>
    obtain ⟨a', r⟩ := p
    simp [hp] at e
    obtain ⟨rfl, hr⟩ := e
    have : r = [] := by simpa using hr
    subst this
    have hlen : (s.take n).length ≤ 15 := by simp only [List.length_take]; omega
    simp only [Core.parseIpv4, hp, show ¬((s.take n).length > 15) by omega, ↓reduceIte]

theorem parseIpv6_take {s : Bytes} {a : BitVec 128} {n : Nat} (h : Core.readIpv6Addr s = some (a, s.drop n))
    (hy : StopsV6 (s.drop n)) : Core.parseIpv6 (s.take n) = some a := by
  have e := Core.readIpv6Addr_append (s.take n) hy
  rw [List.take_append_drop, h] at e
  cases hp : Core.readIpv6Addr (s.take n) with
  | none => simp [hp] at e
  | some p =>
    obtain ⟨a', r⟩ := p
    simp [hp] at e
    obtain ⟨rfl, hr⟩ := e
    have : r = [] := by simpa using hr
    subst this
    simp [Core.parseIpv6, hp]

/-- Where `ipv4_parse_at` stops before a byte that cannot continue the address,
`ipv4_parse_ascii` reads the same address from the consumed bytes alone. -/
theorem ipv4ParseAscii_take {s : Bytes} {a : BitVec 32} {n : Nat} (h : ipv4ParseAt s = some (a, n))
    (hy : StopsV4 (s.drop n)) : ipv4ParseAscii (s.take n) = some a := by
  have hstop : StopAt 10 s n := fun b hb => (hy b (by simpa using hb)).1
  rw [ipv4ParseAscii_eq]
  exact parseIpv4_take (ipv4ParseAt_sound h hstop) hy (ipv4ParseAt_le15 h)

theorem ipv6ParseAscii_take {s : Bytes} {a : BitVec 128} {n : Nat} (h : ipv6ParseAt s = some (a, n))
    (hy : StopsV6 (s.drop n)) : ipv6ParseAscii (s.take n) = some a := by
  have hstop : StopV6 s n := fun b hb => hy b (by simpa using hb)
  rw [ipv6ParseAscii_eq]
  exact parseIpv6_take (ipv6ParseAt_sound h hstop) hy

end Netip.Impl.Parse
