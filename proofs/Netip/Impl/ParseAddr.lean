import Netip.Impl.ParseCore

/-!
# The address parsers of `src/parser.rs`

The hand-written readers, transcribed: `ascii_digit_value`, `hex_digit_value`,
`read_ipv4_octet`, `ipv4_parse_at`, `read_ipv6_group`, `maybe_embedded_ipv4`,
`read_ipv6_groups`, `assemble_ipv6_groups`, `ipv6_parse_at`, `ipv4_parse_ascii`,
`ipv6_parse_ascii` and `parse_cidr_suffix`. Their `u16` arithmetic never wraps, at
most `255 * 10 + 9` or `0xffff`, so it is transcribed on `Nat`.

Proved, for every byte slice, against `core` as `ParseCore` transcribes it:

* `ipv4ParseAscii_eq`, `ipv6ParseAscii_eq`: `ipv4_parse_ascii` and `ipv6_parse_ascii`
  are `Ipv4Addr::parse_ascii` and `Ipv6Addr::parse_ascii`. They accept the same inputs,
  with the same address, so the `core` fallback of `parse_ipv*_addr` never accepts an
  input the hand-written parser rejected. No IPv6 address is longer than 45 bytes
  (`ipv6ParseAt_le45`), which makes the fast reject of longer inputs exact.
* `parseCidrSuffix_eq`: `parse_cidr_suffix` is `u8::from_str`, `+` included.
* Prefixes: where `ipv4_parse_at` stops before a byte that is no digit, `core` reads
  the same address up to there (`ipv4ParseAt_sound`), and where `core` reads an
  address, `ipv4_parse_at` reads it too (`ipv4ParseAt_complete`). For `ipv6_parse_at`
  the stop is a byte that is no hex digit, `:` or `.` (`ipv6ParseAt_sound`,
  `ipv6ParseAt_complete`). Every caller checks such a stop.

The readers differ from `core`'s in where they stop. `read_ipv4_octet` reads at most
3 digits and leaves a fourth unread, where `core` fails on it, and `read_ipv6_group`
does the same with a fifth hex digit. So the IPv6 group runs either agree group for
group, or both stop where no address can end (`readIpv6GroupsLoop_rel`): ours before a
hex digit, `core` before a `.`, a hex digit, or a `:` and a hex digit.
-/

namespace Netip.Impl.Parse

/-- `ascii_digit_value`. -/
def asciiDigitValue (b : UInt8) : Option Nat :=
  if b - 48 ≤ 9 then some (b - 48).toNat else none

/-- `hex_digit_value`. -/
def hexDigitValue (b : UInt8) : Option Nat :=
  if b - 48 ≤ 9 then some (b - 48).toNat
  else
    let lower := b ||| 0x20
    if lower - 97 ≤ 5 then some (lower - 97 + 10).toNat else none

set_option maxRecDepth 8192 in
theorem asciiDigitValue_eq (b : UInt8) : asciiDigitValue b = toDigit 10 b :=
  forall_uint8 (P := fun b => asciiDigitValue b = toDigit 10 b) (by decide) b

set_option maxRecDepth 8192 in
theorem hexDigitValue_eq (b : UInt8) : hexDigitValue b = toDigit 16 b :=
  forall_uint8 (P := fun b => hexDigitValue b = toDigit 16 b) (by decide) b

/-- `read_ipv4_octet(bytes, start)`: at most 3 digits read by fixed index, a byte past
the end reading as the sentinel `.`. A leading zero followed by a digit and a 3-digit
value over 255 are rejected. -/
def readIpv4Octet (bytes : Bytes) (start : Nat) : Option (Nat × Nat) :=
  match bytes[start]? with
  | none => none
  | some b0 =>
    match asciiDigitValue b0 with
    | none => none
    | some digit0 =>
      match asciiDigitValue (bytes[start + 1]?.getD 46) with
      | none => some (digit0, start + 1)
      | some digit1 =>
        if digit0 = 0 then none
        else
          let value := digit0 * 10 + digit1
          match asciiDigitValue (bytes[start + 2]?.getD 46) with
          | none => some (value, start + 2)
          | some digit2 =>
            let value := value * 10 + digit2
            if value ≤ 255 then some (value, start + 3) else none

/-- `ipv4_parse_at`: four octets separated by `.`, as a prefix of `bytes`. Returns the
address and the number of bytes read. -/
def ipv4ParseAt (bytes : Bytes) : Option (BitVec 32 × Nat) :=
  match readIpv4Octet bytes 0 with
  | none => none
  | some (a, pos) =>
    if bytes[pos]? ≠ some 46 then none
    else
      match readIpv4Octet bytes (pos + 1) with
      | none => none
      | some (b, pos) =>
        if bytes[pos]? ≠ some 46 then none
        else
          match readIpv4Octet bytes (pos + 1) with
          | none => none
          | some (c, pos) =>
            if bytes[pos]? ≠ some 46 then none
            else
              match readIpv4Octet bytes (pos + 1) with
              | none => none
              | some (d, pos) => some (ipv4OfOctets a b c d, pos)

/-- `ipv4_parse_ascii`: over 15 bytes is rejected up front, and the prefix parse must
read the whole input. -/
def ipv4ParseAscii (bytes : Bytes) : Option (BitVec 32) :=
  if bytes.length > 15 then none
  else
    match ipv4ParseAt bytes with
    | some (addr, consumed) => if consumed = bytes.length then some addr else none
    | none => none

/-! ## The IPv4 octet -/

/-- A position read by a reader of the suffix from `start` on. -/
theorem getElem?_drop' (l : Bytes) (start i : Nat) : (l.drop start)[i]? = l[start + i]? := by
  simp [List.getElem?_drop]

/-- `read_ipv4_octet` at `start` reads the suffix from `start`. -/
theorem readIpv4Octet_drop (bytes : Bytes) (start : Nat) :
    readIpv4Octet bytes start = (readIpv4Octet (bytes.drop start) 0).map (fun p => (p.1, start + p.2)) := by
  unfold readIpv4Octet
  simp only [getElem?_drop', Nat.add_zero, Nat.zero_add]
  cases bytes[start]? with
  | none => rfl
  | some b0 =>
    simp only
    cases asciiDigitValue b0 with
    | none => rfl
    | some d0 =>
      simp only
      cases asciiDigitValue (bytes[start + 1]?.getD 46) with
      | none => rfl
      | some d1 =>
        simp only
        split
        · rfl
        · cases asciiDigitValue (bytes[start + 2]?.getD 46) with
          | none => simp
          | some d2 =>
            simp only
            split <;> simp

/-- `read_ipv4_octet` by the digit run: it reads up to 3 of the run's digits. -/
theorem readIpv4Octet_eq (t : Bytes) : readIpv4Octet t 0 =
    match (digitRun 10 t).1 with
    | [] => none
    | [d0] => some (d0, 1)
    | d0 :: d1 :: rest =>
      if d0 = 0 then none
      else
        match rest with
        | [] => some (d0 * 10 + d1, 2)
        | d2 :: _ =>
          if (d0 * 10 + d1) * 10 + d2 ≤ 255 then some ((d0 * 10 + d1) * 10 + d2, 3) else none := by
  match t with
  | [] => simp [readIpv4Octet, digitRun]
  | b0 :: s =>
    cases h0 : toDigit 10 b0 with
    | none => simp [readIpv4Octet, digitRun, asciiDigitValue_eq, h0]
    | some d0 =>
      match s with
      | [] => simp [readIpv4Octet, digitRun, asciiDigitValue_eq, h0, toDigit_10_dot]
      | b1 :: s1 =>
        cases h1 : toDigit 10 b1 with
        | none => simp [readIpv4Octet, digitRun, asciiDigitValue_eq, h0, h1]
        | some d1 =>
          match s1 with
          | [] => simp [readIpv4Octet, digitRun, asciiDigitValue_eq, h0, h1, toDigit_10_dot]
          | b2 :: s2 =>
            cases h2 : toDigit 10 b2 with
            | none => simp [readIpv4Octet, digitRun, asciiDigitValue_eq, h0, h1, h2]
            | some d2 => simp [readIpv4Octet, digitRun, asciiDigitValue_eq, h0, h1, h2]

/-- No byte at `k`, or one that is not a `radix` digit: a run read up to `k` is
maximal there. -/
def StopAt (radix : Nat) (t : Bytes) (k : Nat) : Prop := ∀ b, t[k]? = some b → toDigit radix b = none

/-- A stop at `k` bounds the digit run by `k`. -/
theorem digitRun_length_le_of_stop {radix : Nat} {t : Bytes} {k : Nat} (h : StopAt radix t k) :
    (digitRun radix t).1.length ≤ k := by
  apply Nat.le_of_not_lt
  intro hk
  obtain ⟨b, hb, hd⟩ := digitRun_getElem radix t k hk
  simp [h b hb] at hd

/-- The end of the digit run is a stop. -/
theorem stopAt_digitRun (radix : Nat) (t : Bytes) : StopAt radix t (digitRun radix t).1.length := by
  intro b hb
  have : (t.drop (digitRun radix t).1.length)[0]? = some b := by simpa using hb
  rw [digitRun_drop] at this
  cases hr : (digitRun radix t).2 with
  | nil => simp [hr] at this
  | cons c r =>
    simp [hr] at this
    subst this
    exact digitRun_rest radix t _ _ hr

/-- Values of decimal and hex digit runs stay below their radix. -/
theorem digitRun_lt (radix : Nat) (t : Bytes) : ∀ d ∈ (digitRun radix t).1, d < radix := by
  induction t with
  | nil => simp [digitRun]
  | cons b s ih =>
    cases hb : toDigit radix b with
    | none => simp [digitRun, hb]
    | some d =>
      simp only [digitRun, hb, List.mem_cons]
      rintro e (rfl | he)
      · exact toDigit_lt hb
      · exact ih e he

/-- A successful `read_ipv4_octet` stopping before a non-digit reads the whole run,
which is what `core` reads. -/
theorem readIpv4Octet_sound {t : Bytes} {v k : Nat} (h : readIpv4Octet t 0 = some (v, k))
    (hstop : StopAt 10 t k) : Core.readOctet t = some (v, t.drop k) := by
  have hle := digitRun_length_le_of_stop hstop
  have hlt := digitRun_lt 10 t
  rw [readIpv4Octet_eq] at h
  rw [Core.readOctet, Core.readRadixMaxDigits_eq _ _ _ _ (by decide), ← digitRun_drop 10 t]
  generalize (digitRun 10 t).1 = ds at h hle hlt ⊢
  match ds, h, hle, hlt with
  | [], h, _, _ => simp at h
  | [d0], h, hle, hlt =>
    simp at h
    obtain ⟨rfl, rfl⟩ := h
    have := hlt d0 (by simp)
    simp [digitsValue]
    omega
  | [d0, d1], h, hle, hlt =>
    simp at h
    obtain ⟨hz, rfl, rfl⟩ := h
    have := hlt d0 (by simp)
    have := hlt d1 (by simp)
    simp [digitsValue, hz]
    omega
  | [d0, d1, d2], h, hle, hlt =>
    simp at h
    obtain ⟨hz, hv, rfl, rfl⟩ := h
    simp [digitsValue, hz]
    omega
  | d0 :: d1 :: d2 :: d3 :: rest, h, hle, _ =>
    simp at h
    obtain ⟨_, _, _, rfl⟩ := h
    simp at hle

/-- When `core` reads an octet, `read_ipv4_octet` reads the same one and stops where
`core` does. -/
theorem readIpv4Octet_complete {t : Bytes} {v : Nat} {r : Bytes} (h : Core.readOctet t = some (v, r)) :
    ∃ k, readIpv4Octet t 0 = some (v, k) ∧ r = t.drop k ∧ StopAt 10 t k := by
  refine ⟨(digitRun 10 t).1.length, ?_, ?_, stopAt_digitRun 10 t⟩
  · have hlt := digitRun_lt 10 t
    rw [readIpv4Octet_eq]
    rw [Core.readOctet, Core.readRadixMaxDigits_eq _ _ _ _ (by decide)] at h
    generalize (digitRun 10 t).1 = ds at h hlt ⊢
    match ds, h, hlt with
    | [], h, _ => simp at h
    | [d0], h, _ =>
      simp [digitsValue] at h
      by_cases hc : d0 < 256
      · simp [hc] at h; simp [h.1]
      · simp [hc] at h
    | [d0, d1], h, hlt =>
      simp [digitsValue] at h
      obtain ⟨hz, h⟩ := h
      by_cases hc : d0 * 10 + d1 < 256
      · simp [hc] at h; simp [hz, h.1]
      · simp [hc] at h
    | [d0, d1, d2], h, _ =>
      simp [digitsValue] at h
      obtain ⟨hz, h⟩ := h
      by_cases hc : (d0 * 10 + d1) * 10 + d2 < 256
      · simp [hc] at h; simp [hz, h.1]; omega
      · simp [hc] at h
    | _ :: _ :: _ :: _ :: _, h, _ => simp at h
  · rw [Core.readOctet, Core.readRadixMaxDigits_eq _ _ _ _ (by decide)] at h
    rw [digitRun_drop]
    split at h
    · simp at h
    · split at h
      · simp at h
      · split at h
        · simp at h
        · split at h
          · simp at h; exact h.2.symm
          · simp at h

/-- A successful `read_ipv4_octet` reads 1 to 3 decimal digits, inside the slice, to
a value below 256. -/
theorem readIpv4Octet_some {bytes : Bytes} {start v k : Nat} (h : readIpv4Octet bytes start = some (v, k)) :
    start < k ∧ k ≤ start + 3 ∧ k ≤ bytes.length ∧ v < 256 ∧
      ∀ i, start ≤ i → i < k → ∃ b, bytes[i]? = some b ∧ (toDigit 10 b).isSome := by
  rw [readIpv4Octet_drop] at h
  cases h0 : readIpv4Octet (bytes.drop start) 0 with
  | none => simp [h0] at h
  | some p =>
    obtain ⟨v', k'⟩ := p
    simp [h0] at h
    obtain ⟨rfl, rfl⟩ := h
    have hlen := digitRun_length_le 10 (bytes.drop start)
    have hget := digitRun_getElem 10 (bytes.drop start)
    have hlt := digitRun_lt 10 (bytes.drop start)
    rw [readIpv4Octet_eq] at h0
    -- `k'` digits are read, all of the run.
    have key : 1 ≤ k' ∧ k' ≤ 3 ∧ k' ≤ (digitRun 10 (bytes.drop start)).1.length ∧ v' < 256 := by
      generalize (digitRun 10 (bytes.drop start)).1 = ds at h0 hlt
      match ds, h0, hlt with
      | [], h0, _ => simp at h0
      | [d0], h0, hlt =>
        simp at h0
        have := hlt d0 (by simp)
        simp; omega
      | [d0, d1], h0, hlt =>
        simp at h0
        have := hlt d0 (by simp)
        have := hlt d1 (by simp)
        simp; omega
      | d0 :: d1 :: d2 :: _, h0, _ =>
        simp at h0
        simp; omega
    obtain ⟨h1, h3, hrun, hv⟩ := key
    simp only [List.length_drop] at hlen
    refine ⟨by omega, by omega, by omega, hv, ?_⟩
    intro i hi hik
    obtain ⟨b, hb, hd⟩ := hget (i - start) (by omega)
    refine ⟨b, ?_, by simp [hd]⟩
    rw [getElem?_drop'] at hb
    rwa [show start + (i - start) = i by omega] at hb

theorem stopAt_drop {radix : Nat} {bytes : Bytes} {start k : Nat} (hk : start ≤ k) :
    StopAt radix (bytes.drop start) (k - start) ↔ StopAt radix bytes k := by
  have e : (bytes.drop start)[k - start]? = bytes[k]? := by
    rw [getElem?_drop', show start + (k - start) = k by omega]
  unfold StopAt
  rw [e]

theorem readIpv4Octet_sound_at {bytes : Bytes} {start v k : Nat}
    (h : readIpv4Octet bytes start = some (v, k)) (hstop : StopAt 10 bytes k) :
    Core.readOctet (bytes.drop start) = some (v, bytes.drop k) := by
  have hk := (readIpv4Octet_some h).1
  have h' := h
  rw [readIpv4Octet_drop] at h'
  cases h0 : readIpv4Octet (bytes.drop start) 0 with
  | none => simp [h0] at h'
  | some p =>
    obtain ⟨v', k'⟩ := p
    simp [h0] at h'
    obtain ⟨rfl, rfl⟩ := h'
    have hs : StopAt 10 (bytes.drop start) k' := by
      have := (stopAt_drop (radix := 10) (bytes := bytes) (start := start) (k := start + k')
        (by omega)).2 hstop
      simpa using this
    rw [readIpv4Octet_sound h0 hs]
    simp [List.drop_drop]

theorem readIpv4Octet_complete_at {bytes : Bytes} {start v : Nat} {r : Bytes}
    (h : Core.readOctet (bytes.drop start) = some (v, r)) :
    ∃ k, readIpv4Octet bytes start = some (v, k) ∧ r = bytes.drop k ∧ StopAt 10 bytes k := by
  obtain ⟨k, hk, hr, hstop⟩ := readIpv4Octet_complete h
  have hk' : readIpv4Octet bytes start = some (v, start + k) := by
    rw [readIpv4Octet_drop, hk]; rfl
  refine ⟨start + k, hk', ?_, ?_⟩
  · rw [hr, List.drop_drop]
  · have hpos := (readIpv4Octet_some hk').1
    have := (stopAt_drop (radix := 10) (bytes := bytes) (start := start) (k := start + k) (by omega)).1
    simp only [Nat.add_sub_cancel_left] at this
    exact this hstop

/-- A `.` is not a decimal digit, so a read stopping before one is complete. -/
theorem stopAt_of_dot {bytes : Bytes} {p : Nat} (h : bytes[p]? = some 46) : StopAt 10 bytes p := by
  intro b hb
  rw [h] at hb
  cases hb
  decide

theorem readGivenChar_drop {bytes : Bytes} {p : Nat} {c : UInt8} (h : bytes[p]? = some c) :
    Core.readGivenChar c (bytes.drop p) = some (bytes.drop (p + 1)) := by
  obtain ⟨hp, hv⟩ := List.getElem?_eq_some_iff.mp h
  rw [List.drop_eq_getElem_cons hp]
  simp [Core.readGivenChar, hv]

theorem readGivenChar_drop_some {bytes : Bytes} {p : Nat} {c : UInt8} {r : Bytes}
    (h : Core.readGivenChar c (bytes.drop p) = some r) : bytes[p]? = some c ∧ r = bytes.drop (p + 1) := by
  cases hd : bytes.drop p with
  | nil => simp [hd, Core.readGivenChar] at h
  | cons b t =>
    simp only [hd, Core.readGivenChar] at h
    split at h
    · simp at h
      rename_i hb
      have h0 : (bytes.drop p)[0]? = some b := by simp [hd]
      rw [getElem?_drop', Nat.add_zero] at h0
      refine ⟨by rw [h0, hb], ?_⟩
      rw [← h, ← List.drop_drop, hd]
      simp
    · simp at h

/-- When `ipv4_parse_at` stops before a non-digit, `core` reads the same address and
stops there too. -/
theorem ipv4ParseAt_sound {s : Bytes} {a : BitVec 32} {n : Nat} (h : ipv4ParseAt s = some (a, n))
    (hstop : StopAt 10 s n) : Core.readIpv4Addr s = some (a, s.drop n) := by
  unfold ipv4ParseAt at h
  split at h
  · simp at h
  · rename_i a1 p1 h1
    split at h
    · simp at h
    · rename_i hd1
      simp only [ne_eq, Decidable.not_not] at hd1
      split at h
      · simp at h
      · rename_i b1 p2 h2
        split at h
        · simp at h
        · rename_i hd2
          simp only [ne_eq, Decidable.not_not] at hd2
          split at h
          · simp at h
          · rename_i c1 p3 h3
            split at h
            · simp at h
            · rename_i hd3
              simp only [ne_eq, Decidable.not_not] at hd3
              split at h
              · simp at h
              · rename_i d1 p4 h4
                simp at h
                obtain ⟨rfl, rfl⟩ := h
                have o1 := readIpv4Octet_sound_at h1 (stopAt_of_dot hd1)
                have o2 := readIpv4Octet_sound_at h2 (stopAt_of_dot hd2)
                have o3 := readIpv4Octet_sound_at h3 (stopAt_of_dot hd3)
                have o4 := readIpv4Octet_sound_at h4 hstop
                simp only [List.drop_zero] at o1
                simp [Core.readIpv4Addr, o1, readGivenChar_drop hd1, o2, readGivenChar_drop hd2, o3,
                  readGivenChar_drop hd3, o4]

/-- When `core` reads an address, `ipv4_parse_at` reads the same one and stops where
`core` does, before a non-digit. -/
theorem ipv4ParseAt_complete {s : Bytes} {a : BitVec 32} {r : Bytes}
    (h : Core.readIpv4Addr s = some (a, r)) :
    ∃ n, ipv4ParseAt s = some (a, n) ∧ r = s.drop n ∧ StopAt 10 s n := by
  unfold Core.readIpv4Addr at h
  split at h
  · simp at h
  · rename_i a1 r1 h1
    obtain ⟨p1, hp1, rfl, -⟩ := readIpv4Octet_complete_at (bytes := s) (start := 0) (by simpa using h1)
    split at h
    · simp at h
    · rename_i b1 r2 h2
      cases hg1 : Core.readGivenChar 46 (s.drop p1) with
      | none => simp [hg1] at h2
      | some r1' =>
        simp only [hg1, Option.bind_some] at h2
        obtain ⟨hd1, rfl⟩ := readGivenChar_drop_some hg1
        obtain ⟨p2, hp2, rfl, -⟩ := readIpv4Octet_complete_at h2
        split at h
        · simp at h
        · rename_i c1 r3 h3
          cases hg2 : Core.readGivenChar 46 (s.drop p2) with
          | none => simp [hg2] at h3
          | some r2' =>
            simp only [hg2, Option.bind_some] at h3
            obtain ⟨hd2, rfl⟩ := readGivenChar_drop_some hg2
            obtain ⟨p3, hp3, rfl, -⟩ := readIpv4Octet_complete_at h3
            split at h
            · simp at h
            · rename_i d1 r4 h4
              cases hg3 : Core.readGivenChar 46 (s.drop p3) with
              | none => simp [hg3] at h4
              | some r3' =>
                simp only [hg3, Option.bind_some] at h4
                obtain ⟨hd3, rfl⟩ := readGivenChar_drop_some hg3
                obtain ⟨p4, hp4, rfl, hstop⟩ := readIpv4Octet_complete_at h4
                simp at h
                obtain ⟨rfl, rfl⟩ := h
                refine ⟨p4, ?_, rfl, hstop⟩
                simp [ipv4ParseAt, hp1, hd1, hp2, hd2, hp3, hd3, hp4]

/-- A successful `ipv4_parse_at` reads digits and dots, inside the slice. -/
theorem ipv4ParseAt_some {s : Bytes} {a : BitVec 32} {n : Nat} (h : ipv4ParseAt s = some (a, n)) :
    0 < n ∧ n ≤ s.length ∧ ∀ i, i < n → ∃ b, s[i]? = some b ∧ ((toDigit 10 b).isSome ∨ b = 46) := by
  unfold ipv4ParseAt at h
  split at h
  · simp at h
  · rename_i a1 p1 h1
    have o1 := readIpv4Octet_some h1
    split at h
    · simp at h
    · rename_i hd1
      simp only [ne_eq, Decidable.not_not] at hd1
      split at h
      · simp at h
      · rename_i b1 p2 h2
        have o2 := readIpv4Octet_some h2
        split at h
        · simp at h
        · rename_i hd2
          simp only [ne_eq, Decidable.not_not] at hd2
          split at h
          · simp at h
          · rename_i c1 p3 h3
            have o3 := readIpv4Octet_some h3
            split at h
            · simp at h
            · rename_i hd3
              simp only [ne_eq, Decidable.not_not] at hd3
              split at h
              · simp at h
              · rename_i d1 p4 h4
                have o4 := readIpv4Octet_some h4
                simp at h
                obtain ⟨-, rfl⟩ := h
                refine ⟨by omega, o4.2.2.1, ?_⟩
                intro i hi
                by_cases e1 : i < p1
                · obtain ⟨b, hb, hd⟩ := o1.2.2.2.2 i (by omega) e1; exact ⟨b, hb, Or.inl hd⟩
                by_cases e1' : i = p1
                · subst e1'; exact ⟨46, hd1, Or.inr rfl⟩
                by_cases e2 : i < p2
                · obtain ⟨b, hb, hd⟩ := o2.2.2.2.2 i (by omega) e2; exact ⟨b, hb, Or.inl hd⟩
                by_cases e2' : i = p2
                · subst e2'; exact ⟨46, hd2, Or.inr rfl⟩
                by_cases e3 : i < p3
                · obtain ⟨b, hb, hd⟩ := o3.2.2.2.2 i (by omega) e3; exact ⟨b, hb, Or.inl hd⟩
                by_cases e3' : i = p3
                · subst e3'; exact ⟨46, hd3, Or.inr rfl⟩
                obtain ⟨b, hb, hd⟩ := o4.2.2.2.2 i (by omega) hi
                exact ⟨b, hb, Or.inl hd⟩

/-- A slice ends at its length. -/
theorem stopAt_length (radix : Nat) (s : Bytes) : StopAt radix s s.length := by
  intro b hb
  simp at hb

/-- `ipv4_parse_ascii` is `Ipv4Addr::parse_ascii`: the hand-written parser accepts
exactly the inputs `core` accepts, with the same address. -/
theorem ipv4ParseAscii_eq (s : Bytes) : ipv4ParseAscii s = Core.parseIpv4 s := by
  unfold ipv4ParseAscii Core.parseIpv4
  by_cases hl : s.length > 15
  · simp [hl]
  · simp only [hl, ↓reduceIte]
    cases h : ipv4ParseAt s with
    | none =>
      cases hc : Core.readIpv4Addr s with
      | none => rfl
      | some p =>
        obtain ⟨a, r⟩ := p
        obtain ⟨n, hn, -, -⟩ := ipv4ParseAt_complete hc
        simp [h] at hn
    | some p =>
      obtain ⟨a, n⟩ := p
      simp only
      by_cases hn : n = s.length
      · subst hn
        rw [ipv4ParseAt_sound h (stopAt_length 10 s)]
        simp
      · simp only [hn, ↓reduceIte]
        cases hc : Core.readIpv4Addr s with
        | none => rfl
        | some p =>
          obtain ⟨a', r⟩ := p
          obtain ⟨n', hn', hr, -⟩ := ipv4ParseAt_complete hc
          rw [h] at hn'
          simp at hn'
          obtain ⟨rfl, rfl⟩ := hn'
          have hle := (ipv4ParseAt_some h).2.1
          cases r with
          | nil =>
            have := congrArg List.length hr
            simp at this
            omega
          | cons _ _ => rfl

/-! ## IPv6 -/

/-- `read_ipv6_group`: up to 4 hex digits read by fixed index, a byte past the end
reading as the sentinel `:`. -/
def readIpv6Group (bytes : Bytes) : Option (Nat × Nat) :=
  match bytes.head? with
  | none => none
  | some b0 =>
    match hexDigitValue b0 with
    | none => none
    | some value0 =>
      match hexDigitValue (bytes[1]?.getD 58) with
      | none => some (value0, 1)
      | some value1 =>
        let value := value0 * 16 + value1
        match hexDigitValue (bytes[2]?.getD 58) with
        | none => some (value, 2)
        | some value2 =>
          let value := value * 16 + value2
          match hexDigitValue (bytes[3]?.getD 58) with
          | none => some (value, 3)
          | some value3 => some (value * 16 + value3, 4)

/-- `maybe_embedded_ipv4`: a `.` among the first 4 bytes. -/
def maybeEmbeddedIpv4 : Bytes → Bool
  | b0 :: b1 :: b2 :: b3 :: _ => b0 == 46 || b1 == 46 || b2 == 46 || b3 == 46
  | [b0, b1, b2] => b0 == 46 || b1 == 46 || b2 == 46
  | [b0, b1] => b0 == 46 || b1 == 46
  | [b0] => b0 == 46
  | [] => false

/-- What `read_ipv6_groups` returns: the half accumulators (groups 0-3 and 4-7), the
number of groups, whether the run ended in an embedded IPv4 address, and the rest. -/
structure Groups where
  high : BitVec 64
  low : BitVec 64
  count : Nat
  ipv4 : Bool
  rest : Bytes

/-- The separator step of `read_ipv6_groups`: past the first group a `:` must come
next, and is consumed. -/
def separate (index : Nat) (s : Bytes) : Option Bytes :=
  if index > 0 then
    match s with
    | 58 :: tail => some tail
    | _ => none
  else some s

/-- `read_ipv6_groups(bytes, limit)` from group `index` on, with the accumulators so
far. `fuel` counts the iterations left, `limit - index`. -/
def readIpv6GroupsLoop (limit : Nat) : (fuel index : Nat) → BitVec 64 → BitVec 64 → Bytes → Groups
  | 0, _, high, low, rest => ⟨high, low, limit, false, rest⟩
  | fuel + 1, index, high, low, beforeSeparator =>
    match separate index beforeSeparator with
    | none => ⟨high, low, index, false, beforeSeparator⟩
    | some rest =>
      match (if index + 1 < limit ∧ maybeEmbeddedIpv4 rest = true then ipv4ParseAt rest else none) with
      | some (addr, consumed) =>
        if index ≤ 2 then ⟨(high <<< 32) ||| addr.setWidth 64, low, index + 2, true, rest.drop consumed⟩
        else if index = 3 then
          ⟨(high <<< 16) ||| (addr >>> 16).setWidth 64, addr.setWidth 64 &&& 0xFFFF#64, index + 2, true,
            rest.drop consumed⟩
        else ⟨high, (low <<< 32) ||| addr.setWidth 64, index + 2, true, rest.drop consumed⟩
      | none =>
        match readIpv6Group rest with
        | some (value, consumed) =>
          if index < 4 then
            readIpv6GroupsLoop limit fuel (index + 1) ((high <<< 16) ||| BitVec.ofNat 64 value) low
              (rest.drop consumed)
          else
            readIpv6GroupsLoop limit fuel (index + 1) high ((low <<< 16) ||| BitVec.ofNat 64 value)
              (rest.drop consumed)
        | none => ⟨high, low, index, false, beforeSeparator⟩

/-- `read_ipv6_groups(bytes, limit)`. -/
def readIpv6Groups (bytes : Bytes) (limit : Nat) : Groups :=
  readIpv6GroupsLoop limit limit 0 0 0 bytes

/-- `assemble_ipv6_groups`: a run of `count` groups, top-aligned. -/
def assembleIpv6Groups (high low : BitVec 64) (count : Nat) : BitVec 128 :=
  if count = 0 then 0
  else if count ≤ 4 then high.setWidth 128 <<< (128 - 16 * count)
  else (high.setWidth 128 <<< 64) ||| (low.setWidth 128 <<< (64 - 16 * (count - 4)))

/-- `ipv6_parse_at`: a head run of groups and, unless it fills all 8, `::` and a tail
run bottom-aligned by one shift. Returns the address and the number of bytes read. -/
def ipv6ParseAt (bytes : Bytes) : Option (BitVec 128 × Nat) :=
  let head := readIpv6Groups bytes 8
  if head.count = 8 then some (assembleIpv6Groups head.high head.low 8, bytes.length - head.rest.length)
  else if head.ipv4 then none
  else
    match head.rest with
    | 58 :: 58 :: rest =>
      let tail := readIpv6Groups rest (7 - head.count)
      let headBits := assembleIpv6Groups head.high head.low head.count
      let tailShifted :=
        if tail.count = 0 then 0
        else assembleIpv6Groups tail.high tail.low tail.count >>> (128 - 16 * tail.count)
      some (headBits ||| tailShifted, bytes.length - tail.rest.length)
    | _ => none

/-- `ipv6_parse_ascii`: over 45 bytes is rejected up front, and the prefix parse must
read the whole input. -/
def ipv6ParseAscii (bytes : Bytes) : Option (BitVec 128) :=
  if bytes.length > 45 then none
  else
    match ipv6ParseAt bytes with
    | some (addr, consumed) => if consumed = bytes.length then some addr else none
    | none => none

/-! ### The IPv6 group -/

/-- `read_ipv6_group` by the hex digit run: it reads up to 4 of the run's digits. -/
theorem readIpv6Group_eq (t : Bytes) : readIpv6Group t =
    match (digitRun 16 t).1 with
    | [] => none
    | [v0] => some (v0, 1)
    | [v0, v1] => some (v0 * 16 + v1, 2)
    | [v0, v1, v2] => some ((v0 * 16 + v1) * 16 + v2, 3)
    | v0 :: v1 :: v2 :: v3 :: _ => some (((v0 * 16 + v1) * 16 + v2) * 16 + v3, 4) := by
  match t with
  | [] => simp [readIpv6Group, digitRun]
  | b0 :: s =>
    cases h0 : toDigit 16 b0 with
    | none => simp [readIpv6Group, digitRun, hexDigitValue_eq, h0]
    | some d0 =>
      match s with
      | [] => simp [readIpv6Group, digitRun, hexDigitValue_eq, h0, toDigit_colon]
      | b1 :: s1 =>
        cases h1 : toDigit 16 b1 with
        | none => simp [readIpv6Group, digitRun, hexDigitValue_eq, h0, h1]
        | some d1 =>
          match s1 with
          | [] => simp [readIpv6Group, digitRun, hexDigitValue_eq, h0, h1, toDigit_colon]
          | b2 :: s2 =>
            cases h2 : toDigit 16 b2 with
            | none => simp [readIpv6Group, digitRun, hexDigitValue_eq, h0, h1, h2]
            | some d2 =>
              match s2 with
              | [] => simp [readIpv6Group, digitRun, hexDigitValue_eq, h0, h1, h2, toDigit_colon]
              | b3 :: s3 =>
                cases h3 : toDigit 16 b3 with
                | none => simp [readIpv6Group, digitRun, hexDigitValue_eq, h0, h1, h2, h3]
                | some d3 => simp [readIpv6Group, digitRun, hexDigitValue_eq, h0, h1, h2, h3]

/-- Byte `i` of `t` is a hex digit. -/
def HexAt (t : Bytes) (i : Nat) : Prop := ∃ b, t[i]? = some b ∧ (toDigit 16 b).isSome

/-- A run of `k` hex digits in a row has at least `k` digits. -/
theorem digitRun_length_ge {radix : Nat} {t : Bytes} {k : Nat}
    (h : ∀ i, i < k → ∃ b, t[i]? = some b ∧ (toDigit radix b).isSome) : k ≤ (digitRun radix t).1.length := by
  induction t generalizing k with
  | nil =>
    cases k with
    | zero => simp
    | succ k => obtain ⟨b, hb, -⟩ := h 0 (by omega); simp at hb
  | cons b s ih =>
    cases k with
    | zero => simp
    | succ k =>
      obtain ⟨c, hc, hd⟩ := h 0 (by omega)
      simp at hc
      subst hc
      cases hb : toDigit radix b with
      | none => simp [hb] at hd
      | some d =>
        have hrun : (digitRun radix (b :: s)).1 = d :: (digitRun radix s).1 := by simp [digitRun, hb]
        rw [hrun, List.length_cons]
        have := ih (k := k) (fun i hi => by simpa using h (i + 1) (by omega))
        omega

/-- `read_ipv6_group` against `core`'s group reader: both fail on no hex digit, both
read the same group from a run of 1 to 4 digits, and on a longer run only ours reads
one, stopping before a fifth digit. -/
theorem readIpv6Group_rel (t : Bytes) :
    (readIpv6Group t = none ∧ Core.readGroup t = none) ∨
    (∃ v k, readIpv6Group t = some (v, k) ∧ Core.readGroup t = some (v, t.drop k) ∧ v < 65536) ∨
    (∃ v, readIpv6Group t = some (v, 4) ∧ Core.readGroup t = none ∧ HexAt t 4) := by
  have hlt := digitRun_lt 16 t
  have hget := digitRun_getElem 16 t
  rw [readIpv6Group_eq, Core.readGroup, Core.readRadixMaxDigits_eq _ _ _ _ (by decide), ← digitRun_drop 16 t]
  generalize (digitRun 16 t).1 = ds at hlt hget ⊢
  match ds, hlt, hget with
  | [], _, _ => simp
  | [v0], hlt, _ =>
    have := hlt v0 (by simp)
    right; left
    exact ⟨v0, 1, by simp, by simp [digitsValue]; omega, by omega⟩
  | [v0, v1], hlt, _ =>
    have := hlt v0 (by simp)
    have := hlt v1 (by simp)
    right; left
    exact ⟨v0 * 16 + v1, 2, by simp, by simp [digitsValue]; omega, by omega⟩
  | [v0, v1, v2], hlt, _ =>
    have := hlt v0 (by simp)
    have := hlt v1 (by simp)
    have := hlt v2 (by simp)
    right; left
    exact ⟨(v0 * 16 + v1) * 16 + v2, 3, by simp, by simp [digitsValue]; omega, by omega⟩
  | [v0, v1, v2, v3], hlt, _ =>
    have := hlt v0 (by simp)
    have := hlt v1 (by simp)
    have := hlt v2 (by simp)
    have := hlt v3 (by simp)
    right; left
    exact ⟨((v0 * 16 + v1) * 16 + v2) * 16 + v3, 4, by simp, by simp [digitsValue]; omega, by omega⟩
  | v0 :: v1 :: v2 :: v3 :: v4 :: rest, _, hget =>
    right; right
    obtain ⟨b, hb, hd⟩ := hget 4 (by simp)
    exact ⟨((v0 * 16 + v1) * 16 + v2) * 16 + v3, by simp, by simp, b, hb, by simp [hd]⟩

/-! ### The half accumulators -/

/-- A half accumulator holding `gs`: each group shifted in by 16 bits. -/
def pack (gs : List (BitVec 16)) : BitVec 64 := gs.foldl (fun acc g => (acc <<< 16) ||| g.setWidth 64) 0

theorem pack_nil : pack [] = 0 := rfl

theorem pack_append_single (gs : List (BitVec 16)) (g : BitVec 16) :
    pack (gs ++ [g]) = (pack gs <<< 16) ||| g.setWidth 64 := by
  simp [pack, List.foldl_append]

theorem pack_append_ipv4 (gs : List (BitVec 16)) (a : BitVec 32) :
    pack (gs ++ ipv4Groups a) = (pack gs <<< 32) ||| a.setWidth 64 := by
  simp only [pack, List.foldl_append, ipv4Groups, List.foldl_cons, List.foldl_nil]
  generalize List.foldl _ 0 gs = x
  bv_decide

/-- A group read as `u16` and widened to `u64` is the group `core` stores. -/
theorem ofNat_group {v : Nat} (h : v < 65536) : BitVec.ofNat 64 v = (BitVec.ofNat 16 v).setWidth 64 := by
  apply BitVec.eq_of_toNat_eq
  simp [BitVec.toNat_ofNat]
  omega

theorem separate_eq (index : Nat) (s : Bytes) : separate index s = Core.readSeparator 58 index s := by
  unfold separate Core.readSeparator
  split
  · match s with
    | [] => rfl
    | b :: t =>
      simp only [Core.readGivenChar]
      by_cases hb : b = 58
      · subst hb; rfl
      · simp only [hb, ↓reduceIte]
        split
        · rename_i h; simp at h; exact absurd h.1 hb
        · rfl
  · rfl

theorem maybeEmbeddedIpv4_iff (t : Bytes) :
    maybeEmbeddedIpv4 t = true ↔ ∃ i, i < 4 ∧ t[i]? = some 46 := by
  match t with
  | [] => simp [maybeEmbeddedIpv4]
  | [b0] =>
    simp only [maybeEmbeddedIpv4, beq_iff_eq]
    constructor
    · intro h; exact ⟨0, by omega, by simp [h]⟩
    · rintro ⟨i, hi, h⟩
      match i, h with
      | 0, h => simpa using h
  | [b0, b1] =>
    simp only [maybeEmbeddedIpv4, Bool.or_eq_true, beq_iff_eq]
    constructor
    · rintro (h | h)
      · exact ⟨0, by omega, by simp [h]⟩
      · exact ⟨1, by omega, by simp [h]⟩
    · rintro ⟨i, hi, h⟩
      match i, h with
      | 0, h => left; simpa using h
      | 1, h => right; simpa using h
  | [b0, b1, b2] =>
    simp only [maybeEmbeddedIpv4, Bool.or_eq_true, beq_iff_eq]
    constructor
    · rintro ((h | h) | h)
      · exact ⟨0, by omega, by simp [h]⟩
      · exact ⟨1, by omega, by simp [h]⟩
      · exact ⟨2, by omega, by simp [h]⟩
    · rintro ⟨i, hi, h⟩
      match i, h with
      | 0, h => left; left; simpa using h
      | 1, h => left; right; simpa using h
      | 2, h => right; simpa using h
  | b0 :: b1 :: b2 :: b3 :: rest =>
    simp only [maybeEmbeddedIpv4, Bool.or_eq_true, beq_iff_eq]
    constructor
    · rintro (((h | h) | h) | h)
      · exact ⟨0, by omega, by simp [h]⟩
      · exact ⟨1, by omega, by simp [h]⟩
      · exact ⟨2, by omega, by simp [h]⟩
      · exact ⟨3, by omega, by simp [h]⟩
    · rintro ⟨i, hi, h⟩
      match i, h with
      | 0, h => left; left; left; simpa using h
      | 1, h => left; left; right; simpa using h
      | 2, h => left; right; simpa using h
      | 3, h => right; simpa using h

/-- An IPv4 address starts with an octet of 1 to 3 digits and a `.`: within the 4
bytes `maybe_embedded_ipv4` looks at, and a hex group to `core`. -/
theorem ipv4ParseAt_first_octet {t : Bytes} {a : BitVec 32} {n : Nat} (h : ipv4ParseAt t = some (a, n)) :
    ∃ p, 0 < p ∧ p ≤ 3 ∧ t[p]? = some 46 ∧
      ∀ i, i < p → ∃ b, t[i]? = some b ∧ (toDigit 10 b).isSome := by
  unfold ipv4ParseAt at h
  split at h
  · simp at h
  · rename_i a1 p1 h1
    split at h
    · simp at h
    · rename_i hd1
      simp only [ne_eq, Decidable.not_not] at hd1
      obtain ⟨hp, hp3, -, -, hdig⟩ := readIpv4Octet_some h1
      exact ⟨p1, hp, by omega, hd1, fun i hi => hdig i (by omega) hi⟩

theorem maybeEmbeddedIpv4_of_ipv4ParseAt {t : Bytes} {a : BitVec 32} {n : Nat}
    (h : ipv4ParseAt t = some (a, n)) : maybeEmbeddedIpv4 t = true := by
  obtain ⟨p, -, hp3, hd, -⟩ := ipv4ParseAt_first_octet h
  exact (maybeEmbeddedIpv4_iff t).2 ⟨p, by omega, hd⟩

/-- Where `ipv4_parse_at` reads an address, `core`'s group reader reads the first octet
as a hex group and stops before its `.`. -/
theorem readGroup_of_ipv4ParseAt {t : Bytes} {a : BitVec 32} {n : Nat} (h : ipv4ParseAt t = some (a, n)) :
    ∃ g k, Core.readGroup t = some (g, t.drop k) ∧ t[k]? = some 46 := by
  obtain ⟨p, hp, hp3, hd, hdig⟩ := ipv4ParseAt_first_octet h
  have hhex : ∀ i, i < p → ∃ b, t[i]? = some b ∧ (toDigit 16 b).isSome := by
    intro i hi
    obtain ⟨b, hb, hb10⟩ := hdig i hi
    obtain ⟨d, hd⟩ := Option.isSome_iff_exists.mp hb10
    exact ⟨b, hb, by simp [toDigit_16_of_10 hd]⟩
  have hge := digitRun_length_ge hhex
  have hstop : StopAt 16 t p := by
    intro b hb
    rw [hd] at hb
    cases hb
    exact toDigit_dot
  have hle := digitRun_length_le_of_stop hstop
  have hlen : (digitRun 16 t).1.length = p := by omega
  have hlt := digitRun_lt 16 t
  rw [Core.readGroup, Core.readRadixMaxDigits_eq _ _ _ _ (by decide)]
  rw [← digitRun_drop 16 t, hlen]
  generalize (digitRun 16 t).1 = ds at hlen hlt ⊢
  match ds, hlen, hlt with
  | [], hlen, _ => simp at hlen; omega
  | [d0], hlen, hlt =>
    have := hlt d0 (by simp)
    simp at hlen; subst hlen
    exact ⟨d0, 1, by simp [digitsValue]; omega, hd⟩
  | [d0, d1], hlen, hlt =>
    have := hlt d0 (by simp)
    have := hlt d1 (by simp)
    simp at hlen; subst hlen
    exact ⟨d0 * 16 + d1, 2, by simp [digitsValue, show d0 * 16 + d1 < 65536 by omega], hd⟩
  | [d0, d1, d2], hlen, hlt =>
    have := hlt d0 (by simp)
    have := hlt d1 (by simp)
    have := hlt d2 (by simp)
    simp at hlen; subst hlen
    exact ⟨(d0 * 16 + d1) * 16 + d2, 3,
      by simp [digitsValue, show (d0 * 16 + d1) * 16 + d2 < 65536 by omega], hd⟩
  | _ :: _ :: _ :: _ :: _, hlen, _ => simp at hlen; omega

/-- `core`'s group loop past its first group stops at once before a byte that is not
`:`. -/
theorem Core.readGroupsLoop_stop (limit : Nat) {index : Nat} (hi : 0 < index) (acc : List (BitVec 16))
    {s : Bytes} (hs : Core.readGivenChar 58 s = none) :
    ∀ fuel, Core.readGroupsLoop limit fuel index acc s = (acc, false, s) := by
  intro fuel
  cases fuel with
  | zero => rfl
  | succ fuel =>
    have hsep : Core.readSeparator 58 index s = none := by simp [Core.readSeparator, hi, hs]
    simp [Core.readGroupsLoop, hsep]

/-- Ours stops there too, keeping the rest. -/
theorem readIpv6GroupsLoop_stop (limit : Nat) {index : Nat} (high low : BitVec 64)
    {s : Bytes} (hs : separate index s = none) :
    ∀ fuel, (readIpv6GroupsLoop limit fuel index high low s).rest = s := by
  intro fuel
  cases fuel with
  | zero => rfl
  | succ fuel => simp [readIpv6GroupsLoop, hs]

/-! ### The group runs -/

/-- The two group runs agree: the same groups, accumulated into the halves, the same
flag and the same rest. -/
def RunAgree (o : Groups) (c : List (BitVec 16) × Bool × Bytes) : Prop :=
  o.count = c.1.length ∧ o.ipv4 = c.2.1 ∧ o.rest = c.2.2 ∧
    o.high = pack (c.1.take 4) ∧ o.low = pack (c.1.drop 4)

/-- The runs part where neither can end an address: ours stopped before a hex digit,
`core` before a `.`, a hex digit, or a `:` and a hex digit. -/
def RunDiverge (o : Groups) (c : List (BitVec 16) × Bool × Bytes) : Prop :=
  HexAt o.rest 0 ∧ (c.2.2[0]? = some 46 ∨ HexAt c.2.2 0 ∨ (c.2.2[0]? = some 58 ∧ HexAt c.2.2 1))

/-- The halves after one more group. -/
theorem pack_step_low {acc : List (BitVec 16)} (h : acc.length < 4) (g : BitVec 16) :
    (pack (acc.take 4) <<< 16) ||| g.setWidth 64 = pack ((acc ++ [g]).take 4) ∧
      pack (acc.drop 4) = pack ((acc ++ [g]).drop 4) := by
  rw [List.take_of_length_le (by omega), List.take_of_length_le (by simp; omega),
    List.drop_eq_nil_of_le (by omega), List.drop_eq_nil_of_le (by simp; omega), pack_append_single]
  exact ⟨rfl, rfl⟩

theorem pack_step_high {acc : List (BitVec 16)} (h : 4 ≤ acc.length) (g : BitVec 16) :
    pack (acc.take 4) = pack ((acc ++ [g]).take 4) ∧
      (pack (acc.drop 4) <<< 16) ||| g.setWidth 64 = pack ((acc ++ [g]).drop 4) := by
  rw [List.take_append_of_le_length h, List.drop_append_of_le_length h, pack_append_single]
  exact ⟨rfl, rfl⟩

/-- The halves after an embedded IPv4 address, at each of the slots it can start in. -/
theorem pack_ipv4_low {acc : List (BitVec 16)} (h : acc.length ≤ 2) (a : BitVec 32) :
    (pack (acc.take 4) <<< 32) ||| a.setWidth 64 = pack ((acc ++ ipv4Groups a).take 4) ∧
      pack (acc.drop 4) = pack ((acc ++ ipv4Groups a).drop 4) := by
  have hl : (acc ++ ipv4Groups a).length ≤ 4 := by simp [ipv4Groups]; omega
  rw [List.take_of_length_le (by omega), List.take_of_length_le hl,
    List.drop_eq_nil_of_le (by omega), List.drop_eq_nil_of_le hl, pack_append_ipv4]
  exact ⟨rfl, rfl⟩

theorem pack_ipv4_mid {acc : List (BitVec 16)} (h : acc.length = 3) (a : BitVec 32) :
    (pack (acc.take 4) <<< 16) ||| (a >>> 16).setWidth 64 = pack ((acc ++ ipv4Groups a).take 4) ∧
      a.setWidth 64 &&& 0xFFFF#64 = pack ((acc ++ ipv4Groups a).drop 4) := by
  have ht : (acc ++ ipv4Groups a).take 4 = acc ++ [a.extractLsb' 16 16] := by
    rw [List.take_append, List.take_of_length_le (by omega)]
    simp [ipv4Groups, h]
  have hd : (acc ++ ipv4Groups a).drop 4 = [a.extractLsb' 0 16] := by
    rw [List.drop_append, List.drop_eq_nil_of_le (by omega)]
    simp [ipv4Groups, h]
  rw [ht, hd, List.take_of_length_le (by omega), pack_append_single]
  simp only [pack, List.foldl_cons, List.foldl_nil]
  constructor <;> bv_decide

theorem pack_ipv4_high {acc : List (BitVec 16)} (h : 4 ≤ acc.length) (a : BitVec 32) :
    pack (acc.take 4) = pack ((acc ++ ipv4Groups a).take 4) ∧
      (pack (acc.drop 4) <<< 32) ||| a.setWidth 64 = pack ((acc ++ ipv4Groups a).drop 4) := by
  rw [List.take_append_of_le_length h, List.drop_append_of_le_length h, pack_append_ipv4]
  exact ⟨rfl, rfl⟩

/-- A failed `ipv4_parse_at` attempt leaves `core` failing too, and a successful one
that `core` rejects stops before a digit. -/
theorem ipv4ParseAt_diverge {t : Bytes} {a : BitVec 32} {n : Nat} (h : ipv4ParseAt t = some (a, n))
    (hc : Core.readIpv4Addr t = none) : HexAt (t.drop n) 0 := by
  by_cases hstop : StopAt 10 t n
  · rw [ipv4ParseAt_sound h hstop] at hc
    simp at hc
  · cases hn' : t[n]? with
    | none => exact absurd (fun b hb => by simp [hn'] at hb) hstop
    | some b =>
      cases hd : toDigit 10 b with
      | none => exact absurd (fun c hc => by rw [hn'] at hc; cases hc; exact hd) hstop
      | some d => exact ⟨b, by simpa using hn', by simp [toDigit_16_of_10 hd]⟩

/-- The group runs agree, or both part where no address can end. -/
theorem readIpv6GroupsLoop_rel (limit : Nat) :
    ∀ fuel index (acc : List (BitVec 16)) (s : Bytes), index + fuel = limit → acc.length = index →
      RunAgree (readIpv6GroupsLoop limit fuel index (pack (acc.take 4)) (pack (acc.drop 4)) s)
          (Core.readGroupsLoop limit fuel index acc s) ∨
        RunDiverge (readIpv6GroupsLoop limit fuel index (pack (acc.take 4)) (pack (acc.drop 4)) s)
          (Core.readGroupsLoop limit fuel index acc s) := by
  intro fuel
  induction fuel with
  | zero =>
    intro index acc s hlim hacc
    left
    simp [readIpv6GroupsLoop, Core.readGroupsLoop, RunAgree]
    omega
  | succ fuel ih =>
    intro index acc s hlim hacc
    -- No separator where one is due: both stop before it.
    cases hsep : separate index s with
    | none =>
      have hc : Core.readSeparator 58 index s = none := by rw [← separate_eq]; exact hsep
      left
      simp [readIpv6GroupsLoop, Core.readGroupsLoop, hsep, hc, RunAgree, hacc]
    | some t =>
      have hc : Core.readSeparator 58 index s = some t := by rw [← separate_eq]; exact hsep
      -- The group step, once neither run read an embedded IPv4 address.
      have group_step :
          RunAgree
              (match readIpv6Group t with
                | some (value, consumed) =>
                  if index < 4 then
                    readIpv6GroupsLoop limit fuel (index + 1)
                      ((pack (acc.take 4) <<< 16) ||| BitVec.ofNat 64 value) (pack (acc.drop 4)) (t.drop consumed)
                  else
                    readIpv6GroupsLoop limit fuel (index + 1) (pack (acc.take 4))
                      ((pack (acc.drop 4) <<< 16) ||| BitVec.ofNat 64 value) (t.drop consumed)
                | none => ⟨pack (acc.take 4), pack (acc.drop 4), index, false, s⟩)
              (match Core.readGroup t with
                | some (g, rest) => Core.readGroupsLoop limit fuel (index + 1) (acc ++ [BitVec.ofNat 16 g]) rest
                | none => (acc, false, s)) ∨
            RunDiverge
              (match readIpv6Group t with
                | some (value, consumed) =>
                  if index < 4 then
                    readIpv6GroupsLoop limit fuel (index + 1)
                      ((pack (acc.take 4) <<< 16) ||| BitVec.ofNat 64 value) (pack (acc.drop 4)) (t.drop consumed)
                  else
                    readIpv6GroupsLoop limit fuel (index + 1) (pack (acc.take 4))
                      ((pack (acc.drop 4) <<< 16) ||| BitVec.ofNat 64 value) (t.drop consumed)
                | none => ⟨pack (acc.take 4), pack (acc.drop 4), index, false, s⟩)
              (match Core.readGroup t with
                | some (g, rest) => Core.readGroupsLoop limit fuel (index + 1) (acc ++ [BitVec.ofNat 16 g]) rest
                | none => (acc, false, s)) := by
        rcases readIpv6Group_rel t with ⟨ho, hc'⟩ | ⟨v, k, ho, hc', hv⟩ | ⟨v, ho, hc', hhex⟩
        · left
          simp [ho, hc', RunAgree, hacc]
        · simp only [ho, hc']
          have hg := ofNat_group hv
          split
          · obtain ⟨e1, e2⟩ := pack_step_low (acc := acc) (by omega) (BitVec.ofNat 16 v)
            rw [hg, e1, e2]
            exact ih (index + 1) (acc ++ [BitVec.ofNat 16 v]) (t.drop k) (by omega) (by simp [hacc])
          · obtain ⟨e1, e2⟩ := pack_step_high (acc := acc) (by omega) (BitVec.ofNat 16 v)
            rw [hg, e1, e2]
            exact ih (index + 1) (acc ++ [BitVec.ofNat 16 v]) (t.drop k) (by omega) (by simp [hacc])
        · -- A run of 5 or more hex digits: ours reads 4 and stops before the fifth.
          right
          simp only [ho, hc']
          have hrest : HexAt (t.drop 4) 0 := by
            obtain ⟨b, hb, hd⟩ := hhex
            exact ⟨b, by simpa using hb, hd⟩
          have hsep' : separate (index + 1) (t.drop 4) = none := by
            obtain ⟨b, hb, hd⟩ := hrest
            unfold separate
            simp only [show index + 1 > 0 by omega, ↓reduceIte]
            cases ht : t.drop 4 with
            | nil => rfl
            | cons c r =>
              rw [ht] at hb
              simp at hb
              subst hb
              split
              · rename_i h58
                simp at h58
                rw [h58.1] at hd
                simp [toDigit_colon] at hd
              · rfl
          refine ⟨?_, ?_⟩
          · split
            · rw [readIpv6GroupsLoop_stop limit _ _ hsep']; exact hrest
            · rw [readIpv6GroupsLoop_stop limit _ _ hsep']; exact hrest
          · -- `core` stops before the group's separator, or at the group itself.
            have ht0 : HexAt t 0 := by
              rw [readIpv6Group_eq] at ho
              obtain ⟨b, hb, hd⟩ := digitRun_getElem 16 t 0 (by
                cases hds : (digitRun 16 t).1 with
                | nil => simp [hds] at ho
                | cons _ _ => simp)
              exact ⟨b, hb, by simp [hd]⟩
            unfold Core.readSeparator at hc
            split at hc
            · right; right
              match s, hc with
              | b :: s', hc =>
                simp only [Core.readGivenChar] at hc
                split at hc
                · rename_i hb
                  simp at hc
                  subst hc
                  subst hb
                  obtain ⟨c, hc', hd⟩ := ht0
                  exact ⟨by simp, c, by simpa using hc', hd⟩
                · simp at hc
            · right; left
              simp at hc
              subst hc
              exact ht0
      -- The embedded IPv4 attempt.
      by_cases hv4 : index + 1 < limit
      · cases hcore : Core.readIpv4Addr t with
        | some p =>
          -- `core` reads an address, and so does ours, to the same rest.
          obtain ⟨a, r⟩ := p
          obtain ⟨n, hn, hr, -⟩ := ipv4ParseAt_complete hcore
          have hme := maybeEmbeddedIpv4_of_ipv4ParseAt hn
          left
          simp only [readIpv6GroupsLoop, hsep, hv4, hme, and_self, ↓reduceIte, hn,
            Core.readGroupsLoop, hc, Option.bind_some, hcore]
          split
          · obtain ⟨e1, e2⟩ := pack_ipv4_low (acc := acc) (by omega) a
            refine ⟨by simp [ipv4Groups, hacc], rfl, hr.symm, e1, e2⟩
          · split
            · obtain ⟨e1, e2⟩ := pack_ipv4_mid (acc := acc) (by omega) a
              refine ⟨by simp [ipv4Groups, hacc], rfl, hr.symm, e1, e2⟩
            · obtain ⟨e1, e2⟩ := pack_ipv4_high (acc := acc) (by omega) a
              refine ⟨by simp [ipv4Groups, hacc], rfl, hr.symm, e1, e2⟩
        | none =>
          cases hours : (if maybeEmbeddedIpv4 t = true then ipv4ParseAt t else none) with
          | some p =>
            -- Ours reads an address `core` rejects: ours stops before a digit, `core`
            -- reads the first octet as a group and stops before its `.`.
            obtain ⟨a, n⟩ := p
            have hn : ipv4ParseAt t = some (a, n) := by
              split at hours
              · exact hours
              · simp at hours
            have hme : maybeEmbeddedIpv4 t = true := maybeEmbeddedIpv4_of_ipv4ParseAt hn
            right
            obtain ⟨g, k, hg, hdot⟩ := readGroup_of_ipv4ParseAt hn
            have hcstop : Core.readGivenChar 58 (t.drop k) = none := by
              have : (t.drop k)[0]? = some 46 := by simpa using hdot
              cases ht : t.drop k with
              | nil => simp [ht] at this
              | cons c r => simp [ht] at this; subst this; simp [Core.readGivenChar]
            have hfuel : 0 < fuel := by omega
            simp only [readIpv6GroupsLoop, hsep, hv4, hme, and_self, ↓reduceIte, hn,
              Core.readGroupsLoop, hc, Option.bind_some, hcore, hg]
            rw [Core.readGroupsLoop_stop limit (by omega) _ hcstop]
            refine ⟨?_, Or.inl (by simpa using hdot)⟩
            split
            · exact ipv4ParseAt_diverge hn hcore
            · split <;> exact ipv4ParseAt_diverge hn hcore
          | none =>
            simp only [readIpv6GroupsLoop, hsep, hv4, true_and, hours, Core.readGroupsLoop, hc,
              Option.bind_some, ↓reduceIte, hcore]
            exact group_step
      · simp only [readIpv6GroupsLoop, hsep, hv4, false_and, ↓reduceIte, Core.readGroupsLoop, hc,
          Option.bind_some]
        exact group_step

/-! ### Assembling the address -/

theorem ofGroups_foldl (ys : List (BitVec 16)) : ∀ a : BitVec 128,
    ys.foldl (fun (acc : BitVec 128) (g : BitVec 16) => (acc <<< 16) ||| g.setWidth 128) a =
      (a <<< (16 * ys.length)) ||| ofGroups ys := by
  induction ys with
  | nil => intro a; simp [ofGroups]
  | cons y ys ih =>
    intro a
    simp only [List.foldl_cons, List.length_cons, ofGroups]
    rw [ih, ih]
    simp only [BitVec.shiftLeft_or_distrib, ← BitVec.shiftLeft_add, BitVec.or_assoc]
    have h0 : (0 : BitVec 128) <<< (16 + 16 * ys.length) = 0 := by simp
    rw [h0, show 16 + 16 * ys.length = 16 * (ys.length + 1) by omega]
    simp

/-- Groups in a row: the earlier ones shifted up past the later ones. -/
theorem ofGroups_append (xs ys : List (BitVec 16)) :
    ofGroups (xs ++ ys) = (ofGroups xs <<< (16 * ys.length)) ||| ofGroups ys := by
  rw [ofGroups, List.foldl_append]
  exact ofGroups_foldl ys _

theorem ofGroups_replicate_zero (n : Nat) : ofGroups (List.replicate n 0) = 0 := by
  induction n with
  | zero => rfl
  | succ n ih =>
    rw [List.replicate_succ', ofGroups_append, ih]
    simp [ofGroups]

/-- `assemble_ipv6_groups` of the halves holding `gs` is `gs` top-aligned. -/
theorem assemble_pack (gs : List (BitVec 16)) (h : gs.length ≤ 8) :
    assembleIpv6Groups (pack (gs.take 4)) (pack (gs.drop 4)) gs.length = ofGroups gs <<< (16 * (8 - gs.length)) := by
  match gs, h with
  | [], _ => simp [assembleIpv6Groups, ofGroups]
  | [g0], _ => simp [assembleIpv6Groups, pack, ofGroups] <;> bv_decide
  | [g0, g1], _ => simp [assembleIpv6Groups, pack, ofGroups] <;> bv_decide
  | [g0, g1, g2], _ => simp [assembleIpv6Groups, pack, ofGroups] <;> bv_decide
  | [g0, g1, g2, g3], _ => simp [assembleIpv6Groups, pack, ofGroups] <;> bv_decide
  | [g0, g1, g2, g3, g4], _ => simp [assembleIpv6Groups, pack, ofGroups] <;> bv_decide
  | [g0, g1, g2, g3, g4, g5], _ => simp [assembleIpv6Groups, pack, ofGroups] <;> bv_decide
  | [g0, g1, g2, g3, g4, g5, g6], _ => simp [assembleIpv6Groups, pack, ofGroups] <;> bv_decide
  | [g0, g1, g2, g3, g4, g5, g6, g7], _ => simp [assembleIpv6Groups, pack, ofGroups] <;> bv_decide

/-- Shifting a top-aligned tail of 1 to 7 groups down to the bottom restores it. -/
theorem tail_shift (ts : List (BitVec 16)) (h0 : 0 < ts.length) (h : ts.length ≤ 7) :
    (ofGroups ts <<< (16 * (8 - ts.length))) >>> (128 - 16 * ts.length) = ofGroups ts := by
  match ts, h0, h with
  | [g0], _, _ => simp [ofGroups] <;> bv_decide
  | [g0, g1], _, _ => simp [ofGroups] <;> bv_decide
  | [g0, g1, g2], _, _ => simp [ofGroups] <;> bv_decide
  | [g0, g1, g2, g3], _, _ => simp [ofGroups] <;> bv_decide
  | [g0, g1, g2, g3, g4], _, _ => simp [ofGroups] <;> bv_decide
  | [g0, g1, g2, g3, g4, g5], _, _ => simp [ofGroups] <;> bv_decide
  | [g0, g1, g2, g3, g4, g5, g6], _, _ => simp [ofGroups] <;> bv_decide

/-! ### Bounds -/

theorem readIpv6Group_some {t : Bytes} {v k : Nat} (h : readIpv6Group t = some (v, k)) :
    1 ≤ k ∧ k ≤ 4 ∧ k ≤ t.length := by
  have hlen := digitRun_length_le 16 t
  rw [readIpv6Group_eq] at h
  generalize (digitRun 16 t).1 = ds at h hlen
  match ds, h with
  | [], h => simp at h
  | [_], h => simp at h; simp at hlen; omega
  | [_, _], h => simp at h; simp at hlen; omega
  | [_, _, _], h => simp at h; simp at hlen; omega
  | _ :: _ :: _ :: _ :: _, h => simp at h; simp at hlen; omega

/-- An IPv4 address is at most 15 bytes. -/
theorem ipv4ParseAt_le15 {t : Bytes} {a : BitVec 32} {n : Nat} (h : ipv4ParseAt t = some (a, n)) : n ≤ 15 := by
  unfold ipv4ParseAt at h
  split at h
  · simp at h
  · rename_i a1 p1 h1
    have o1 := readIpv4Octet_some h1
    split at h
    · simp at h
    · split at h
      · simp at h
      · rename_i b1 p2 h2
        have o2 := readIpv4Octet_some h2
        split at h
        · simp at h
        · split at h
          · simp at h
          · rename_i c1 p3 h3
            have o3 := readIpv4Octet_some h3
            split at h
            · simp at h
            · split at h
              · simp at h
              · rename_i d1 p4 h4
                have o4 := readIpv4Octet_some h4
                simp at h
                omega

/-- A group run reads a suffix of its input: past the first group at most 5 bytes per
group, one less for the first group of the address, and 6 more for an embedded IPv4
address standing for two groups. -/
theorem readIpv6GroupsLoop_bounds (limit : Nat) :
    ∀ fuel index high low (s : Bytes), index + fuel = limit →
      index ≤ (readIpv6GroupsLoop limit fuel index high low s).count ∧
      (readIpv6GroupsLoop limit fuel index high low s).count ≤ limit ∧
      ∃ k, k ≤ s.length ∧ (readIpv6GroupsLoop limit fuel index high low s).rest = s.drop k ∧
        k + (if index = 0 ∧ index < (readIpv6GroupsLoop limit fuel index high low s).count then 1 else 0) ≤
          5 * ((readIpv6GroupsLoop limit fuel index high low s).count - index) +
            (if (readIpv6GroupsLoop limit fuel index high low s).ipv4 then 6 else 0) := by
  intro fuel
  induction fuel with
  | zero =>
    intro index high low s hlim
    simp only [readIpv6GroupsLoop]
    have : index = limit := by omega
    subst this
    refine ⟨Nat.le_refl _, Nat.le_refl _, 0, by omega, by simp, ?_⟩
    simp
  | succ fuel ih =>
    intro index high low s hlim
    -- The group step, after the separator left `s.drop j`.
    have step : ∀ j, j ≤ 1 → (index = 0 → j = 0) → j ≤ s.length →
        index ≤ (match readIpv6Group (s.drop j) with
          | some (value, consumed) =>
            if index < 4 then
              readIpv6GroupsLoop limit fuel (index + 1) ((high <<< 16) ||| BitVec.ofNat 64 value) low
                ((s.drop j).drop consumed)
            else
              readIpv6GroupsLoop limit fuel (index + 1) high ((low <<< 16) ||| BitVec.ofNat 64 value)
                ((s.drop j).drop consumed)
          | none => ⟨high, low, index, false, s⟩).count ∧
        (match readIpv6Group (s.drop j) with
          | some (value, consumed) =>
            if index < 4 then
              readIpv6GroupsLoop limit fuel (index + 1) ((high <<< 16) ||| BitVec.ofNat 64 value) low
                ((s.drop j).drop consumed)
            else
              readIpv6GroupsLoop limit fuel (index + 1) high ((low <<< 16) ||| BitVec.ofNat 64 value)
                ((s.drop j).drop consumed)
          | none => ⟨high, low, index, false, s⟩).count ≤ limit ∧
        ∃ k, k ≤ s.length ∧ (match readIpv6Group (s.drop j) with
          | some (value, consumed) =>
            if index < 4 then
              readIpv6GroupsLoop limit fuel (index + 1) ((high <<< 16) ||| BitVec.ofNat 64 value) low
                ((s.drop j).drop consumed)
            else
              readIpv6GroupsLoop limit fuel (index + 1) high ((low <<< 16) ||| BitVec.ofNat 64 value)
                ((s.drop j).drop consumed)
          | none => ⟨high, low, index, false, s⟩).rest = s.drop k ∧
          k + (if index = 0 ∧ index < (match readIpv6Group (s.drop j) with
            | some (value, consumed) =>
              if index < 4 then
                readIpv6GroupsLoop limit fuel (index + 1) ((high <<< 16) ||| BitVec.ofNat 64 value) low
                  ((s.drop j).drop consumed)
              else
                readIpv6GroupsLoop limit fuel (index + 1) high ((low <<< 16) ||| BitVec.ofNat 64 value)
                  ((s.drop j).drop consumed)
            | none => ⟨high, low, index, false, s⟩).count then 1 else 0) ≤
            5 * ((match readIpv6Group (s.drop j) with
              | some (value, consumed) =>
                if index < 4 then
                  readIpv6GroupsLoop limit fuel (index + 1) ((high <<< 16) ||| BitVec.ofNat 64 value) low
                    ((s.drop j).drop consumed)
                else
                  readIpv6GroupsLoop limit fuel (index + 1) high ((low <<< 16) ||| BitVec.ofNat 64 value)
                    ((s.drop j).drop consumed)
              | none => ⟨high, low, index, false, s⟩).count - index) +
              (if (match readIpv6Group (s.drop j) with
                | some (value, consumed) =>
                  if index < 4 then
                    readIpv6GroupsLoop limit fuel (index + 1) ((high <<< 16) ||| BitVec.ofNat 64 value) low
                      ((s.drop j).drop consumed)
                  else
                    readIpv6GroupsLoop limit fuel (index + 1) high ((low <<< 16) ||| BitVec.ofNat 64 value)
                      ((s.drop j).drop consumed)
                | none => ⟨high, low, index, false, s⟩).ipv4 then 6 else 0) := by
      intro j hj1 hj0 hjs
      cases hg : readIpv6Group (s.drop j) with
      | none =>
        simp only
        refine ⟨Nat.le_refl _, by omega, 0, by omega, by simp, ?_⟩
        simp
      | some p =>
        obtain ⟨v, c⟩ := p
        have hc := readIpv6Group_some hg
        simp only [List.length_drop] at hc
        simp only
        have key : ∀ high' low',
            index ≤ (readIpv6GroupsLoop limit fuel (index + 1) high' low' ((s.drop j).drop c)).count ∧
            (readIpv6GroupsLoop limit fuel (index + 1) high' low' ((s.drop j).drop c)).count ≤ limit ∧
            ∃ k, k ≤ s.length ∧
              (readIpv6GroupsLoop limit fuel (index + 1) high' low' ((s.drop j).drop c)).rest = s.drop k ∧
              k + (if index = 0 ∧ index < (readIpv6GroupsLoop limit fuel (index + 1) high' low'
                ((s.drop j).drop c)).count then 1 else 0) ≤
                5 * ((readIpv6GroupsLoop limit fuel (index + 1) high' low' ((s.drop j).drop c)).count - index) +
                  (if (readIpv6GroupsLoop limit fuel (index + 1) high' low' ((s.drop j).drop c)).ipv4
                    then 6 else 0) := by
          intro high' low'
          obtain ⟨h1, h2, k, hk, hrest, hb⟩ := ih (index + 1) high' low' ((s.drop j).drop c) (by omega)
          simp only [List.length_drop] at hk
          refine ⟨by omega, h2, j + c + k, by omega, by rw [hrest]; simp [List.drop_drop], ?_⟩
          simp only [show ¬(index + 1 = 0) by omega, false_and, ↓reduceIte, Nat.add_zero] at hb
          by_cases hi0 : index = 0
          · subst hi0
            have := hj0 rfl
            simp only [true_and, show 0 < (readIpv6GroupsLoop limit fuel (0 + 1) high' low'
              ((s.drop j).drop c)).count by omega, ↓reduceIte]
            split at hb <;> split <;> simp_all <;> omega
          · simp only [hi0, false_and, ↓reduceIte, Nat.add_zero]
            split at hb <;> split <;> simp_all <;> omega
        split
        · exact key _ _
        · exact key _ _
    -- The separator.
    cases hsep : separate index s with
    | none =>
      simp only [readIpv6GroupsLoop, hsep]
      refine ⟨Nat.le_refl _, by omega, 0, by omega, by simp, ?_⟩
      simp
    | some t =>
      have ht : ∃ j, j ≤ 1 ∧ (index = 0 → j = 0) ∧ j ≤ s.length ∧ t = s.drop j := by
        unfold separate at hsep
        by_cases hi : index > 0
        · simp only [hi, ↓reduceIte] at hsep
          cases s with
          | nil => simp at hsep
          | cons b tail =>
            by_cases hb : b = 58
            · subst hb
              simp at hsep
              subst hsep
              exact ⟨1, by omega, by omega, by simp, by simp⟩
            · split at hsep
              · rename_i h58; simp at h58; exact absurd h58.1 hb
              · simp at hsep
        · simp only [hi, ↓reduceIte] at hsep
          simp at hsep
          subst hsep
          exact ⟨0, by omega, fun _ => rfl, by omega, by simp⟩
      obtain ⟨j, hj1, hj0, hjs, rfl⟩ := ht
      by_cases hgate : index + 1 < limit ∧ maybeEmbeddedIpv4 (s.drop j) = true
      · obtain ⟨hlt, hme⟩ := hgate
        cases hv4 : ipv4ParseAt (s.drop j) with
        | some p =>
          obtain ⟨a, n⟩ := p
          have hn15 := ipv4ParseAt_le15 hv4
          have hns := (ipv4ParseAt_some hv4).2.1
          simp only [List.length_drop] at hns
          simp only [readIpv6GroupsLoop, hsep, hlt, hme, and_self, ↓reduceIte, hv4]
          have last : ∀ high' low',
              index ≤ index + 2 ∧ index + 2 ≤ limit ∧ ∃ k, k ≤ s.length ∧
                (⟨high', low', index + 2, true, (s.drop j).drop n⟩ : Groups).rest = s.drop k ∧
                k + (if index = 0 ∧ index < index + 2 then 1 else 0) ≤ 5 * (index + 2 - index) + 6 := by
            intro high' low'
            refine ⟨by omega, by omega, j + n, by omega, by simp [List.drop_drop], ?_⟩
            by_cases hi0 : index = 0
            · have := hj0 hi0; simp [hi0]; omega
            · simp [hi0]; omega
          split
          · exact last _ _
          · split
            · exact last _ _
            · exact last _ _
        | none =>
          simp only [readIpv6GroupsLoop, hsep, hlt, hme, and_self, ↓reduceIte, hv4]
          exact step j hj1 hj0 hjs
      · simp only [readIpv6GroupsLoop, hsep, hgate, ↓reduceIte]
        exact step j hj1 hj0 hjs

/-! ### The address -/

/-- No byte at `n`, or one that can neither extend a group nor separate one: an IPv6
address read up to `n` is complete. -/
def StopV6 (t : Bytes) (n : Nat) : Prop := ∀ b, t[n]? = some b → toDigit 16 b = none ∧ b ≠ 58 ∧ b ≠ 46

theorem readIpv6Groups_rel (s : Bytes) (limit : Nat) :
    RunAgree (readIpv6Groups s limit) (Core.readGroups limit s) ∨
      RunDiverge (readIpv6Groups s limit) (Core.readGroups limit s) := by
  have := readIpv6GroupsLoop_rel limit limit 0 [] s (by omega) rfl
  have e : pack (List.take 4 ([] : List (BitVec 16))) = 0 := rfl
  have e' : pack (List.drop 4 ([] : List (BitVec 16))) = 0 := rfl
  rw [e, e'] at this
  exact this

theorem readIpv6Groups_bounds (s : Bytes) (limit : Nat) :
    (readIpv6Groups s limit).count ≤ limit ∧ ∃ k, k ≤ s.length ∧ (readIpv6Groups s limit).rest = s.drop k ∧
      k + (if 0 < (readIpv6Groups s limit).count then 1 else 0) ≤
        5 * (readIpv6Groups s limit).count + (if (readIpv6Groups s limit).ipv4 then 6 else 0) := by
  obtain ⟨-, h1, k, hk, hrest, hb⟩ := readIpv6GroupsLoop_bounds limit limit 0 0 0 s (by omega)
  simp only [true_and, Nat.sub_zero] at hb
  exact ⟨h1, k, hk, hrest, hb⟩

/-- The position of a suffix. -/
theorem length_sub_drop {s : Bytes} {k : Nat} (hk : k ≤ s.length) : s.length - (s.drop k).length = k := by
  simp; omega

/-- A hex digit, `:` or `.` right after the address breaks `StopV6`. -/
theorem not_stopV6_of_hex {s : Bytes} {k : Nat} (h : HexAt (s.drop k) 0) : ¬StopV6 s k := by
  intro hs
  obtain ⟨b, hb, hd⟩ := h
  have := (hs b (by simpa using hb)).1
  simp [this] at hd

theorem not_stopV6_rest {r : Bytes}
    (h : r[0]? = some 46 ∨ HexAt r 0 ∨ (r[0]? = some 58 ∧ HexAt r 1)) : ¬StopV6 r 0 := by
  intro hs
  rcases h with h | ⟨b, hb, hd⟩ | ⟨h, -⟩
  · exact (hs 46 h).2.2 rfl
  · have := (hs b hb).1; simp [this] at hd
  · exact (hs 58 h).2.1 rfl

/-- `core` cannot read `::` where it stopped before a `.`, a hex digit, or a `:` and a
hex digit. -/
theorem colons_none_of_diverge {r : Bytes}
    (h : r[0]? = some 46 ∨ HexAt r 0 ∨ (r[0]? = some 58 ∧ HexAt r 1)) :
    (Core.readGivenChar 58 r).bind (Core.readGivenChar 58) = none := by
  match r, h with
  | [], _ => rfl
  | b :: r', h =>
    simp only [Core.readGivenChar]
    by_cases hb : b = 58
    · subst hb
      simp only [↓reduceIte, Option.bind_some]
      rcases h with h | ⟨c, hc, hd⟩ | ⟨-, c, hc, hd⟩
      · simp at h
      · simp at hc; subst hc; simp [toDigit_colon] at hd
      · match r', hc with
        | c' :: r'', hc =>
          simp at hc
          subst hc
          by_cases hc58 : c' = 58
          · subst hc58; simp [toDigit_colon] at hd
          · simp [Core.readGivenChar, hc58]
    · simp [hb]

/-- Ours cannot read `::` before a hex digit either. -/
theorem colons_of_hex {r : Bytes} (h : HexAt r 0) : ∀ r', r ≠ 58 :: 58 :: r' := by
  intro r' hr
  subst hr
  obtain ⟨b, hb, hd⟩ := h
  simp at hb
  subst hb
  simp [toDigit_colon] at hd

/-- Head and tail together: the zeros `::` stands for between them. -/
theorem ofGroups_head_tail (head tail : List (BitVec 16)) (hh : head.length ≤ 7)
    (ht : tail.length ≤ 7 - head.length) :
    ofGroups ((head ++ List.replicate (8 - head.length) 0).take (8 - tail.length) ++ tail) =
      (ofGroups head <<< (16 * (8 - head.length))) ||| ofGroups tail := by
  have e : (head ++ List.replicate (8 - head.length) 0).take (8 - tail.length) =
      head ++ List.replicate (8 - tail.length - head.length) 0 := by
    rw [List.take_append, List.take_of_length_le (by omega), List.take_replicate]
    congr 2
    omega
  rw [e, ofGroups_append, ofGroups_append, ofGroups_replicate_zero]
  simp only [List.length_replicate]
  rw [show ∀ x : BitVec 128, x ||| 0 = x from fun x => by simp, ← BitVec.shiftLeft_add]
  congr 2
  omega

/-- `ipv6_parse_at` assembles what `core` assembles from the same head and tail. -/
theorem assemble_head_tail (head tail : List (BitVec 16)) (hh : head.length ≤ 7)
    (ht : tail.length ≤ 7 - head.length) :
    (assembleIpv6Groups (pack (head.take 4)) (pack (head.drop 4)) head.length |||
        if tail.length = 0 then 0
        else assembleIpv6Groups (pack (tail.take 4)) (pack (tail.drop 4)) tail.length >>> (128 - 16 * tail.length)) =
      ofGroups ((head ++ List.replicate (8 - head.length) 0).take (8 - tail.length) ++ tail) := by
  rw [ofGroups_head_tail head tail hh ht, assemble_pack head (by omega)]
  split
  · rename_i h0
    rw [List.length_eq_zero_iff.mp h0]
    simp [ofGroups]
  · rename_i h0
    rw [assemble_pack tail (by omega), tail_shift tail (by omega) (by omega)]

/-- When `ipv6_parse_at` stops before a byte that cannot continue an address, `core`
reads the same address and stops there too. -/
theorem ipv6ParseAt_sound {s : Bytes} {a : BitVec 128} {n : Nat} (h : ipv6ParseAt s = some (a, n))
    (hstop : StopV6 s n) : Core.readIpv6Addr s = some (a, s.drop n) := by
  obtain ⟨hhc, kh, hkh, hrh, -⟩ := readIpv6Groups_bounds s 8
  unfold ipv6ParseAt at h
  simp only at h
  rcases readIpv6Groups_rel s 8 with ⟨hc1, hc2, hc3, hc4, hc5⟩ | ⟨hhex, -⟩
  · -- The head runs agree.
    unfold Core.readIpv6Addr
    generalize hC : Core.readGroups 8 s = C at hc1 hc2 hc3 hc4 hc5
    obtain ⟨head, hipv4, hrest⟩ := C
    simp only at hc1 hc2 hc3 hc4 hc5 ⊢
    split at h
    · rename_i h8
      simp at h
      obtain ⟨rfl, rfl⟩ := h
      have hl8 : head.length = 8 := by omega
      rw [← hc1, h8]
      simp only [↓reduceIte]
      have ha := assemble_pack head (by omega)
      rw [hl8] at ha
      rw [hc4, hc5, ha, ← hc3, hrh, length_sub_drop hkh]
      simp
    · rename_i h8
      split at h
      · simp at h
      · rename_i hv4
        rw [← hc1]
        simp only [h8, ↓reduceIte, ← hc2, hv4, Bool.false_eq_true]
        rw [← hc3]
        split at h
        · rename_i r hr
          simp only [hr, Core.readGivenChar, ↓reduceIte, Option.bind_some]
          -- The tail runs.
          obtain ⟨htc, kt, hkt, hrt, -⟩ := readIpv6Groups_bounds r (7 - (readIpv6Groups s 8).count)
          have hr' : r = s.drop (kh + 2) := by
            have := hrh.symm.trans hr
            have h2 : (s.drop kh).drop 2 = r := by rw [← hrh, hr]; rfl
            rw [← h2, List.drop_drop]
          have hlenr : kh + 2 ≤ s.length := by
            have : (s.drop kh).length ≥ 2 := by rw [← hrh, hr]; simp
            simp at this; omega
          rcases readIpv6Groups_rel r (7 - (readIpv6Groups s 8).count) with
            ⟨ht1, ht2, ht3, ht4, ht5⟩ | ⟨thex, -⟩
          · generalize hT : Core.readGroups (7 - (readIpv6Groups s 8).count) r = T at ht1 ht2 ht3 ht4 ht5
            obtain ⟨tail, tipv4, trest⟩ := T
            simp only at ht1 ht2 ht3 ht4 ht5
            rw [show 8 - ((readIpv6Groups s 8).count + 1) = 7 - (readIpv6Groups s 8).count by omega, hT]
            obtain ⟨rfl, rfl⟩ := h
            simp only [Option.some.injEq, Prod.mk.injEq]
            refine ⟨?_, ?_⟩
            · rw [hc4, hc5, ht4, ht5, ht1, hc1]
              rw [ht1, hc1] at htc
              have hh : head.length ≤ 7 := by omega
              exact (assemble_head_tail head tail hh htc).symm
            · rw [← ht3, hrt, hr', List.drop_drop]
              have hlen : kh + 2 + kt ≤ s.length := by
                have : kt ≤ (s.drop (kh + 2)).length := by rw [← hr']; exact hkt
                simp at this; omega
              rw [show s.length - (s.drop (kh + 2 + kt)).length = kh + 2 + kt by simp; omega]
          · exfalso
            obtain ⟨-, rfl⟩ := h
            apply not_stopV6_of_hex (s := s) _ hstop
            have hlen : kh + 2 + kt ≤ s.length := by
              have : kt ≤ (s.drop (kh + 2)).length := by rw [← hr']; exact hkt
              simp at this; omega
            rw [hrt, hr', List.drop_drop] at thex
            rw [show s.length - (readIpv6Groups r (7 - (readIpv6Groups s 8).count)).rest.length = kh + 2 + kt by
              rw [hrt, hr', List.drop_drop]; simp; omega]
            exact thex
        · simp at h
  · -- The head runs diverge: ours cannot have read an address.
    exfalso
    split at h
    · simp at h
      obtain ⟨-, rfl⟩ := h
      rw [hrh, length_sub_drop hkh] at hstop
      rw [hrh] at hhex
      exact not_stopV6_of_hex hhex hstop
    · split at h
      · simp at h
      · split at h
        · rename_i r hr
          exact colons_of_hex hhex r hr
        · simp at h

/-- `core` reads `::` only off `::`. -/
theorem readColons_some {r r1 : Bytes} (h : (Core.readGivenChar 58 r).bind (Core.readGivenChar 58) = some r1) :
    r = 58 :: 58 :: r1 := by
  cases r with
  | nil => simp [Core.readGivenChar] at h
  | cons b1 r =>
    by_cases hb1 : b1 = 58
    · subst hb1
      cases r with
      | nil => simp [Core.readGivenChar] at h
      | cons b2 r =>
        by_cases hb2 : b2 = 58
        · subst hb2; simp [Core.readGivenChar] at h; simp [h]
        · simp [Core.readGivenChar, hb2] at h
    · simp [Core.readGivenChar, hb1] at h

/-- When `core` reads an IPv6 address and stops before a byte that cannot continue
it, `ipv6_parse_at` reads the same address to the same place. -/
theorem ipv6ParseAt_complete {s : Bytes} {a : BitVec 128} {r : Bytes} (h : Core.readIpv6Addr s = some (a, r))
    (hstop : StopV6 r 0) : ∃ n, ipv6ParseAt s = some (a, n) ∧ r = s.drop n := by
  obtain ⟨hhc, kh, hkh, hrh, -⟩ := readIpv6Groups_bounds s 8
  unfold Core.readIpv6Addr at h
  rcases readIpv6Groups_rel s 8 with ⟨hc1, hc2, hc3, hc4, hc5⟩ | ⟨-, hdirty⟩
  · generalize hC : Core.readGroups 8 s = C at h hc1 hc2 hc3 hc4 hc5
    obtain ⟨head, hipv4, hrest⟩ := C
    simp only at h hc1 hc2 hc3 hc4 hc5
    split at h
    · rename_i hl8
      simp at h
      obtain ⟨rfl, rfl⟩ := h
      refine ⟨kh, ?_, by rw [← hc3, hrh]⟩
      unfold ipv6ParseAt
      simp only [hc1, hl8, ↓reduceIte]
      have ha := assemble_pack head (by omega)
      rw [hl8] at ha
      rw [hc4, hc5, ha, hrh, length_sub_drop hkh]
      simp
    · rename_i hl8
      split at h
      · simp at h
      · rename_i hv4
        cases hcol : (Core.readGivenChar 58 hrest).bind (Core.readGivenChar 58) with
        | none => simp [hcol] at h
        | some r1 =>
          simp only [hcol] at h
          -- `::` follows the head.
          have hr : hrest = 58 :: 58 :: r1 := readColons_some hcol
          obtain ⟨htc, kt, hkt, hrt, -⟩ := readIpv6Groups_bounds r1 (7 - (readIpv6Groups s 8).count)
          have hr' : r1 = s.drop (kh + 2) := by
            have h2 : (s.drop kh).drop 2 = r1 := by rw [← hrh, hc3, hr]; rfl
            rw [← h2, List.drop_drop]
          have hlenr : kh + 2 ≤ s.length := by
            have : (s.drop kh).length ≥ 2 := by rw [← hrh, hc3, hr]; simp
            simp at this; omega
          rw [show 8 - (head.length + 1) = 7 - (readIpv6Groups s 8).count by omega] at h
          rcases readIpv6Groups_rel r1 (7 - (readIpv6Groups s 8).count) with
            ⟨ht1, ht2, ht3, ht4, ht5⟩ | ⟨-, tdirty⟩
          · generalize hT : Core.readGroups (7 - (readIpv6Groups s 8).count) r1 = T at h ht1 ht2 ht3 ht4 ht5
            obtain ⟨tail, tipv4, trest⟩ := T
            simp only at h ht1 ht2 ht3 ht4 ht5
            simp at h
            obtain ⟨rfl, rfl⟩ := h
            have hlen : kh + 2 + kt ≤ s.length := by
              have : kt ≤ (s.drop (kh + 2)).length := by rw [← hr']; exact hkt
              simp at this; omega
            refine ⟨kh + 2 + kt, ?_, by rw [← ht3, hrt, hr', List.drop_drop]⟩
            unfold ipv6ParseAt
            simp only [hc1, hl8, ↓reduceIte, hc2, hv4, Bool.false_eq_true, hc3, hr]
            rw [show s.length - (readIpv6Groups r1 (7 - head.length)).rest.length = kh + 2 + kt by
              rw [← hc1, hrt, hr', List.drop_drop]; simp; omega]
            rw [← hc1, hc4, hc5, ht4, ht5, ht1, hc1]
            rw [ht1, hc1] at htc
            have hh : head.length ≤ 7 := by omega
            rw [assemble_head_tail head tail hh htc]
            rfl
          · exfalso
            generalize hT : Core.readGroups (7 - (readIpv6Groups s 8).count) r1 = T at h tdirty
            obtain ⟨tail, tipv4, trest⟩ := T
            simp at h
            obtain ⟨-, rfl⟩ := h
            exact not_stopV6_rest tdirty hstop
  · exfalso
    generalize hC : Core.readGroups 8 s = C at h hdirty
    obtain ⟨head, hipv4, hrest⟩ := C
    simp only at h hdirty
    split at h
    · simp at h
      obtain ⟨-, rfl⟩ := h
      exact not_stopV6_rest hdirty hstop
    · split at h
      · simp at h
      · rw [colons_none_of_diverge hdirty] at h
        simp at h

/-- An IPv6 address is at most 45 bytes, `ipv6_parse_ascii`'s fast reject. -/
theorem ipv6ParseAt_le45 {s : Bytes} {a : BitVec 128} {n : Nat} (h : ipv6ParseAt s = some (a, n)) :
    n ≤ 45 ∧ n ≤ s.length := by
  obtain ⟨hhc, kh, hkh, hrh, hbh⟩ := readIpv6Groups_bounds s 8
  unfold ipv6ParseAt at h
  simp only at h
  split at h
  · rename_i h8
    simp at h
    obtain ⟨-, rfl⟩ := h
    rw [hrh, length_sub_drop hkh]
    rw [h8] at hbh
    simp only [show (0 : Nat) < 8 by omega, ↓reduceIte] at hbh
    refine ⟨?_, hkh⟩
    split at hbh <;> omega
  · rename_i h8
    split at h
    · simp at h
    · rename_i hv4
      simp only [hv4, Bool.false_eq_true, ↓reduceIte] at hbh
      split at h
      · rename_i r hr
        obtain ⟨htc, kt, hkt, hrt, hbt⟩ := readIpv6Groups_bounds r (7 - (readIpv6Groups s 8).count)
        simp at h
        obtain ⟨-, rfl⟩ := h
        have hr' : r = s.drop (kh + 2) := by
          have h2 : (s.drop kh).drop 2 = r := by rw [← hrh, hr]; rfl
          rw [← h2, List.drop_drop]
        have hlenr : kh + 2 ≤ s.length := by
          have : (s.drop kh).length ≥ 2 := by rw [← hrh, hr]; simp
          simp at this; omega
        have hlen : kh + 2 + kt ≤ s.length := by
          have : kt ≤ (s.drop (kh + 2)).length := by rw [← hr']; exact hkt
          simp at this; omega
        rw [hrt, hr', List.drop_drop, length_sub_drop hlen]
        refine ⟨?_, hlen⟩
        have hi6 : (if (readIpv6Groups r (7 - (readIpv6Groups s 8).count)).ipv4 = true then 6 else 0) ≤ 6 := by
          split <;> omega
        omega
      · simp at h

/-- `ipv6_parse_ascii` is `Ipv6Addr::parse_ascii`: the hand-written parser accepts
exactly the inputs `core` accepts, with the same address. -/
theorem ipv6ParseAscii_eq (s : Bytes) : ipv6ParseAscii s = Core.parseIpv6 s := by
  have stop_end : StopV6 s s.length := by intro b hb; simp at hb
  unfold ipv6ParseAscii Core.parseIpv6
  by_cases hl : s.length > 45
  · simp only [hl, ↓reduceIte]
    cases hc : Core.readIpv6Addr s with
    | none => rfl
    | some p =>
      obtain ⟨a, r⟩ := p
      cases r with
      | cons _ _ => rfl
      | nil =>
        obtain ⟨n, hn, hr⟩ := ipv6ParseAt_complete hc (by intro b hb; simp at hb)
        have := ipv6ParseAt_le45 hn
        have : s.length ≤ n := by
          have := congrArg List.length hr
          simp at this; omega
        omega
  · simp only [hl, ↓reduceIte]
    cases h : ipv6ParseAt s with
    | none =>
      cases hc : Core.readIpv6Addr s with
      | none => rfl
      | some p =>
        obtain ⟨a, r⟩ := p
        cases r with
        | cons _ _ => rfl
        | nil =>
          obtain ⟨n, hn, -⟩ := ipv6ParseAt_complete hc (by intro b hb; simp at hb)
          simp [h] at hn
    | some p =>
      obtain ⟨a, n⟩ := p
      simp only
      by_cases hn : n = s.length
      · subst hn
        rw [ipv6ParseAt_sound h stop_end]
        simp
      · simp only [hn, ↓reduceIte]
        cases hc : Core.readIpv6Addr s with
        | none => rfl
        | some p =>
          obtain ⟨a', r⟩ := p
          cases r with
          | cons _ _ => rfl
          | nil =>
            obtain ⟨n', hn', hr⟩ := ipv6ParseAt_complete hc (by intro b hb; simp at hb)
            rw [h] at hn'
            simp at hn'
            obtain ⟨rfl, rfl⟩ := hn'
            have hle := (ipv6ParseAt_le45 h).2
            have := congrArg List.length hr
            simp at this
            omega

/-! ## The CIDR suffix -/

/-- The digit loop of `parse_cidr_suffix`: a non-digit, or a value over 255, rejects. -/
def parseCidrSuffixLoop (value : Nat) : Bytes → Option Nat
  | [] => some value
  | b :: s =>
    match asciiDigitValue b with
    | none => none
    | some digit =>
      let value := value * 10 + digit
      if value > 255 then none else parseCidrSuffixLoop value s

/-- `parse_cidr_suffix`: one optional `+`, then at least one digit. -/
def parseCidrSuffix (bytes : Bytes) : Option Nat :=
  let digits := if bytes.head? = some 43 then bytes.tail else bytes
  if digits.isEmpty then none else parseCidrSuffixLoop 0 digits

/-- The loop is `u8::from_str`'s checked loop: a product over 255 is a sum over 255. -/
theorem parseCidrSuffixLoop_eq (l : Bytes) : ∀ acc, parseCidrSuffixLoop acc l = Core.u8Checked acc l := by
  induction l with
  | nil => intro acc; rfl
  | cons b l ih =>
    intro acc
    simp only [parseCidrSuffixLoop, Core.u8Checked, asciiDigitValue_eq]
    cases hb : toDigit 10 b with
    | none => rfl
    | some d =>
      simp only
      by_cases h1 : acc * 10 > 255
      · simp [h1, show acc * 10 + d > 255 by omega]
      · simp only [h1, ↓reduceIte]
        by_cases h2 : acc * 10 + d > 255
        · simp [h2]
        · simp [h2, ih]

/-- At most 2 digits never overflow, so both loops agree there. -/
theorem u8Unchecked_eq_checked (l : Bytes) (h : l.length ≤ 2) : Core.u8Unchecked 0 l = Core.u8Checked 0 l := by
  match l, h with
  | [], _ => rfl
  | [b0], _ =>
    simp only [Core.u8Unchecked, Core.u8Checked]
    cases h0 : toDigit 10 b0 with
    | none => rfl
    | some d0 =>
      have := toDigit_lt h0
      simp
      omega
  | [b0, b1], _ =>
    simp only [Core.u8Unchecked, Core.u8Checked]
    cases h0 : toDigit 10 b0 with
    | none => rfl
    | some d0 =>
      have := toDigit_lt h0
      cases h1 : toDigit 10 b1 with
      | none => simp <;> omega
      | some d1 =>
        have := toDigit_lt h1
        simp
        omega

/-- `parse_cidr_suffix` is `u8::from_str`, `+` quirk included. -/
theorem parseCidrSuffix_eq (s : Bytes) : parseCidrSuffix s = Core.parseU8 s := by
  have loop : ∀ l : Bytes, parseCidrSuffixLoop 0 l =
      (if l.length ≤ 2 then Core.u8Unchecked 0 l else Core.u8Checked 0 l) := by
    intro l
    split
    · rename_i h; rw [u8Unchecked_eq_checked l h, parseCidrSuffixLoop_eq]
    · rw [parseCidrSuffixLoop_eq]
  unfold parseCidrSuffix Core.parseU8
  cases s with
  | nil => simp
  | cons b rest =>
    by_cases hb : b = 43
    · subst hb
      cases rest with
      | nil => simp
      | cons d ds => simp [loop]
    · by_cases h45 : b = 45 ∧ rest = []
      · obtain ⟨rfl, rfl⟩ := h45
        simp [parseCidrSuffixLoop, asciiDigitValue_eq]
        decide
      · simp only [List.isEmpty_cons, Bool.false_eq_true, ↓reduceIte, List.head?_cons, Option.some.injEq, hb,
          List.cons.injEq, false_and, false_or, loop]
        simp only [h45, ↓reduceIte]

end Netip.Impl.Parse
