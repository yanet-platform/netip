import Netip.Impl.Basic

/-!
# `core`'s parsers, the reference of `src/parser.rs`

`src/parser.rs` claims to replicate the address grammar of `core::net` exactly, and
the CIDR grammar of `u8::from_str`. This module transcribes that reference from the
sources of Rust 1.99 (`core/src/net/parser.rs`, `core/src/num/mod.rs`,
`core/src/char/methods.rs`).

* `Parser` holds a byte slice that every reader consumes from the front, and
  `read_atomically` puts it back when a reader fails. A reader is transcribed as a
  function from its input to `Option (value × rest)`, which puts the input back by
  construction.
* `read_radix_max_digits(radix, max_digits, allow_zero_prefix)` reads one digit, then
  further digits up to `max_digits` in all, and fails on one more
  (`readRadixMaxDigits`). Its `u32` arithmetic never wraps, as at most 4 digits are
  combined, so it is transcribed on `Nat`, and `try_into` is a bound check.
* `read_ipv4_addr` (`readIpv4Addr`), `read_ipv6_addr` with its `read_groups`
  (`readIpv6Addr`, `readGroupsLoop`), and `parse_with`, which requires the whole
  input to be read (`parseIpv4`, `parseIpv6`).
* `u8::from_str` (`parseU8`): an optional `+`, then decimal digits, with no overflow.

`char::to_digit` is stated by its documented meaning (`toDigit`), and
`toDigitBits_eq` checks it against the bit trick `core` computes it with, for every
byte at the radixes used here.
-/

namespace Netip.Impl.Parse

/-- A byte slice. -/
abbrev Bytes := List UInt8

/-- `char::from(b).to_digit(radix)` for `radix ≤ 36`: the value of an ASCII digit or
letter, when it is below `radix`. -/
def toDigit (radix : Nat) (b : UInt8) : Option Nat :=
  let n := b.toNat
  if 48 ≤ n ∧ n ≤ 57 then (if n - 48 < radix then some (n - 48) else none)
  else if radix > 10 ∧ 65 ≤ n ∧ n ≤ 90 then (if n - 55 < radix then some (n - 55) else none)
  else if radix > 10 ∧ 97 ≤ n ∧ n ≤ 122 then (if n - 87 < radix then some (n - 87) else none)
  else none

/-- `to_digit` as `core` computes it: past `'9'`, with letters allowed, a letter is
folded to upper case after subtracting `'A'`, and every other byte wraps to a value of
at least 36. The code point of `char::from(b)` is `b`. -/
def toDigitBits (radix : BitVec 32) (b : UInt8) : Option Nat :=
  let c : BitVec 32 := b.toBitVec.setWidth 32
  let value := if c > 57#32 ∧ radix > 10#32 then ((c - 65#32) &&& ~~~32#32) + 10#32 else c - 48#32
  if value < radix then some value.toNat else none

/-- A statement about every byte, checked on all 256 of them. -/
theorem forall_uint8 {P : UInt8 → Prop} (h : ∀ n, n < 256 → P (UInt8.ofNat n)) (b : UInt8) :
    P b := by
  have := h b.toNat b.toNat_lt
  simpa using this

set_option maxRecDepth 8192 in
theorem toDigitBits_eq_10 (b : UInt8) : toDigitBits 10 b = toDigit 10 b :=
  forall_uint8 (P := fun b => toDigitBits 10 b = toDigit 10 b) (by decide) b

set_option maxRecDepth 8192 in
theorem toDigitBits_eq_16 (b : UInt8) : toDigitBits 16 b = toDigit 16 b :=
  forall_uint8 (P := fun b => toDigitBits 16 b = toDigit 16 b) (by decide) b

theorem toDigit_lt {radix : Nat} {b : UInt8} {d : Nat} (h : toDigit radix b = some d) :
    d < radix := by
  unfold toDigit at h
  dsimp only at h
  repeat' split at h
  all_goals simp at h
  all_goals omega

/-- A decimal digit is a hex digit of the same value. -/
theorem toDigit_16_of_10 {b : UInt8} {d : Nat} (h : toDigit 10 b = some d) : toDigit 16 b = some d := by
  unfold toDigit at h ⊢
  dsimp only at h ⊢
  repeat' split at h
  all_goals simp at h
  all_goals (try split) <;> (try split) <;> simp_all <;> omega

/-- `.`, `:` and `/` are not hex digits. -/
theorem toDigit_dot : toDigit 16 46 = none := by decide
theorem toDigit_colon : toDigit 16 58 = none := by decide
theorem toDigit_slash : toDigit 16 47 = none := by decide

theorem toDigit_10_dot : toDigit 10 46 = none := by decide

/-- `Ipv4Addr::new(a, b, c, d)`: the octets in network order. -/
def ipv4OfOctets (a b c d : Nat) : BitVec 32 :=
  BitVec.ofNat 8 a ++ BitVec.ofNat 8 b ++ BitVec.ofNat 8 c ++ BitVec.ofNat 8 d

/-- `Ipv6Addr::from([u16; 8])`: the groups in network order. -/
def ofGroups (gs : List (BitVec 16)) : BitVec 128 :=
  gs.foldl (fun acc g => (acc <<< 16) ||| g.setWidth 128) 0

/-- `u16::from_be_bytes` of the two octet pairs of an embedded IPv4 address, the two
groups it stands for. -/
def ipv4Groups (a : BitVec 32) : List (BitVec 16) := [a.extractLsb' 16 16, a.extractLsb' 0 16]

namespace Core

/-- `read_given_char(c)`. -/
def readGivenChar (c : UInt8) : Bytes → Option Bytes
  | b :: s => if b = c then some s else none
  | [] => none

/-- The separator of `read_separator(sep, index, ..)`, read only when `index > 0`. -/
def readSeparator (sep : UInt8) (index : Nat) (s : Bytes) : Option Bytes :=
  if index > 0 then readGivenChar sep s else some s

/-- The digit loop of `read_radix_max_digits` after its first digit: `count` digits are
read, and a digit past `max_digits` fails the whole read. -/
def readDigits (radix maxDigits : Nat) (result count : Nat) : Bytes → Option (Nat × Nat × Bytes)
  | [] => some (result, count, [])
  | b :: s =>
    match toDigit radix b with
    | none => some (result, count, b :: s)
    | some digit =>
      if count ≥ maxDigits then none
      else readDigits radix maxDigits (result * radix + digit) (count + 1) s

/-- `read_radix_max_digits(radix, max_digits, allow_zero_prefix)` into an integer type
whose values are those below `bound`. -/
def readRadixMaxDigits (radix maxDigits : Nat) (allowZeroPrefix : Bool) (bound : Nat) :
    Bytes → Option (Nat × Bytes)
  | [] => none
  | b :: s =>
    match toDigit radix b with
    | none => none
    | some first =>
      match readDigits radix maxDigits first 1 s with
      | none => none
      | some (result, count, rest) =>
        if !allowZeroPrefix && first == 0 && count > 1 then none
        else if result < bound then some (result, rest) else none

/-- An IPv4 octet: `read_radix_max_digits::<u8>(10, 3, false)`. -/
def readOctet : Bytes → Option (Nat × Bytes) := readRadixMaxDigits 10 3 false 256

/-- An IPv6 group: `read_radix_max_digits::<u16>(16, 4, true)`. -/
def readGroup : Bytes → Option (Nat × Bytes) := readRadixMaxDigits 16 4 true 65536

/-- `read_ipv4_addr`: four octets separated by `.`. -/
def readIpv4Addr (s : Bytes) : Option (BitVec 32 × Bytes) :=
  match readOctet s with
  | none => none
  | some (a, s) =>
    match (readGivenChar 46 s).bind readOctet with
    | none => none
    | some (b, s) =>
      match (readGivenChar 46 s).bind readOctet with
      | none => none
      | some (c, s) =>
        match (readGivenChar 46 s).bind readOctet with
        | none => none
        | some (d, s) => some (ipv4OfOctets a b c d, s)

/-- `read_groups` over `limit` slots, from slot `index` on with the groups `acc` read
so far. Returns the groups, whether the last two came from an embedded IPv4 address,
and the rest. `fuel` counts the slots left, `limit - index`. -/
def readGroupsLoop (limit : Nat) : (fuel index : Nat) → List (BitVec 16) → Bytes →
    List (BitVec 16) × Bool × Bytes
  | 0, _, acc, s => (acc, false, s)
  | fuel + 1, index, acc, s =>
    match (if index + 1 < limit then (readSeparator 58 index s).bind readIpv4Addr else none) with
    | some (a, rest) => (acc ++ ipv4Groups a, true, rest)
    | none =>
      match (readSeparator 58 index s).bind readGroup with
      | some (g, rest) => readGroupsLoop limit fuel (index + 1) (acc ++ [BitVec.ofNat 16 g]) rest
      | none => (acc, false, s)

/-- `read_groups(p, &mut groups[..limit])`. -/
def readGroups (limit : Nat) (s : Bytes) : List (BitVec 16) × Bool × Bytes :=
  readGroupsLoop limit limit 0 [] s

/-- `read_ipv6_addr`: a head run of groups. Unless it fills all 8 slots, `::` and a tail
run of at most `7 - head` groups, which `copy_from_slice` writes over the last slots. -/
def readIpv6Addr (s : Bytes) : Option (BitVec 128 × Bytes) :=
  match readGroups 8 s with
  | (head, headIpv4, s) =>
    if head.length = 8 then some (ofGroups head, s)
    else if headIpv4 then none
    else
      match (readGivenChar 58 s).bind (readGivenChar 58) with
      | none => none
      | some s =>
        match readGroups (8 - (head.length + 1)) s with
        | (tail, _, s) =>
          let slots := head ++ List.replicate (8 - head.length) 0
          some (ofGroups (slots.take (8 - tail.length) ++ tail), s)

/-- `Ipv4Addr::parse_ascii`: over 15 bytes is rejected up front, and `parse_with`
requires the whole input to be read. -/
def parseIpv4 (s : Bytes) : Option (BitVec 32) :=
  if s.length > 15 then none
  else
    match readIpv4Addr s with
    | some (a, []) => some a
    | _ => none

/-- `Ipv6Addr::parse_ascii`. -/
def parseIpv6 (s : Bytes) : Option (BitVec 128) :=
  match readIpv6Addr s with
  | some (a, []) => some a
  | _ => none

/-- The unchecked digit loop of `u8::from_str`, taken for at most 2 digits, which
cannot overflow. -/
def u8Unchecked (result : Nat) : Bytes → Option Nat
  | [] => some result
  | c :: s =>
    match toDigit 10 c with
    | none => none
    | some x => u8Unchecked (result * 10 + x) s

/-- The checked digit loop of `u8::from_str`: the digit, then `checked_mul`, then
`checked_add`. -/
def u8Checked (result : Nat) : Bytes → Option Nat
  | [] => some result
  | c :: s =>
    match toDigit 10 c with
    | none => none
    | some x =>
      if result * 10 > 255 then none
      else if result * 10 + x > 255 then none
      else u8Checked (result * 10 + x) s

/-- `u8::from_str`: a lone sign is rejected, one leading `+` is skipped, and
`can_not_overflow` picks the unchecked loop for at most 2 digits. An unsigned type
keeps a leading `-`, which is then an invalid digit. -/
def parseU8 (src : Bytes) : Option Nat :=
  if src.isEmpty then none
  else if src = [43] ∨ src = [45] then none
  else
    let digits := if src.head? = some 43 then src.tail else src
    if digits.length ≤ 2 then u8Unchecked 0 digits else u8Checked 0 digits

end Core

/-! ## Digit runs

Every reader here starts with a run of digits. `digitRun radix t` is the maximal
leading run of digits of `t`, as values, with the rest of `t` after it. -/

/-- The maximal leading run of `radix` digits of a byte slice, and the rest. -/
def digitRun (radix : Nat) : Bytes → List Nat × Bytes
  | [] => ([], [])
  | b :: s =>
    match toDigit radix b with
    | none => ([], b :: s)
    | some d => (d :: (digitRun radix s).1, (digitRun radix s).2)

/-- The value of digits, most significant first, appended to `acc`. -/
def digitsValue (radix acc : Nat) (ds : List Nat) : Nat := ds.foldl (fun a d => a * radix + d) acc

/-- The run ends the slice or stops before a byte that is not a digit. -/
theorem digitRun_rest (radix : Nat) (t : Bytes) :
    ∀ b r, (digitRun radix t).2 = b :: r → toDigit radix b = none := by
  induction t with
  | nil => simp [digitRun]
  | cons b s ih =>
    intro c r h
    unfold digitRun at h
    split at h
    · rename_i hb
      simp at h
      obtain ⟨rfl, rfl⟩ := h
      exact hb
    · exact ih c r h

/-- The run is a prefix: the rest is what follows its digits. -/
theorem digitRun_drop (radix : Nat) (t : Bytes) :
    t.drop (digitRun radix t).1.length = (digitRun radix t).2 := by
  induction t with
  | nil => simp [digitRun]
  | cons b s ih =>
    unfold digitRun
    split <;> simp [ih]

theorem digitRun_length_le (radix : Nat) (t : Bytes) : (digitRun radix t).1.length ≤ t.length := by
  induction t with
  | nil => simp [digitRun]
  | cons b s ih =>
    unfold digitRun
    split <;> simp [ih]

/-- The bytes of the run are digits of the listed values. -/
theorem digitRun_getElem (radix : Nat) (t : Bytes) :
    ∀ i (hi : i < (digitRun radix t).1.length), ∃ b, t[i]? = some b ∧
      toDigit radix b = some ((digitRun radix t).1[i]) := by
  induction t with
  | nil => simp [digitRun]
  | cons b s ih =>
    intro i hi
    cases hb : toDigit radix b with
    | none => simp [digitRun, hb] at hi
    | some d =>
      have hrun : digitRun radix (b :: s) = (d :: (digitRun radix s).1, (digitRun radix s).2) := by
        simp [digitRun, hb]
      simp only [hrun, List.length_cons] at hi ⊢
      cases i with
      | zero => exact ⟨b, by simp, by simpa using hb⟩
      | succ i =>
        obtain ⟨c, hc, hd⟩ := ih i (by omega)
        exact ⟨c, by simpa using hc, by simpa using hd⟩

namespace Core

/-- The digit loop reads the rest of the run, and fails when that makes more than
`maxDigits` digits. -/
theorem readDigits_eq (radix maxDigits : Nat) (s : Bytes) :
    ∀ result count, count ≤ maxDigits →
      readDigits radix maxDigits result count s =
        if count + (digitRun radix s).1.length > maxDigits then none
        else some (digitsValue radix result (digitRun radix s).1,
          count + (digitRun radix s).1.length, (digitRun radix s).2) := by
  induction s with
  | nil => intro result count _; simp [readDigits, digitRun, digitsValue]; omega
  | cons b s ih =>
    intro result count hc
    cases hb : toDigit radix b with
    | none => simp [readDigits, digitRun, hb, digitsValue]; omega
    | some d =>
      simp only [readDigits, digitRun, hb, List.length_cons]
      by_cases hm : count ≥ maxDigits
      · simp only [hm, ↓reduceIte]
        simp only [show count + ((digitRun radix s).1.length + 1) > maxDigits by omega, ↓reduceIte]
      · simp only [hm, ↓reduceIte]
        rw [ih _ _ (by omega)]
        have : (count + 1 + (digitRun radix s).1.length > maxDigits) =
            (count + ((digitRun radix s).1.length + 1) > maxDigits) := by
          apply propext; omega
        simp only [this, digitsValue, List.foldl_cons]
        have : count + 1 + (digitRun radix s).1.length = count + ((digitRun radix s).1.length + 1) := by
          omega
        rw [this]

/-- `read_radix_max_digits` by the digit run: it needs one digit, at most `maxDigits`,
no leading zero unless allowed, and a value below `bound`. -/
theorem readRadixMaxDigits_eq (radix maxDigits : Nat) (allowZeroPrefix : Bool) (bound : Nat)
    (hmax : 1 ≤ maxDigits) (t : Bytes) :
    readRadixMaxDigits radix maxDigits allowZeroPrefix bound t =
      match (digitRun radix t).1 with
      | [] => none
      | first :: rest =>
        if rest.length + 1 > maxDigits then none
        else if !allowZeroPrefix && first == 0 && rest.length > 0 then none
        else if digitsValue radix first rest < bound then
          some (digitsValue radix first rest, (digitRun radix t).2)
        else none := by
  match t with
  | [] => simp [readRadixMaxDigits, digitRun]
  | b :: s =>
    cases hb : toDigit radix b with
    | none => simp [readRadixMaxDigits, digitRun, hb]
    | some first =>
      simp only [readRadixMaxDigits, digitRun, hb]
      rw [readDigits_eq radix maxDigits s first 1 hmax]
      by_cases hlen : 1 + (digitRun radix s).1.length > maxDigits
      · simp only [hlen, ↓reduceIte]
        simp only [show (digitRun radix s).1.length + 1 > maxDigits by omega, ↓reduceIte]
      · simp only [hlen, ↓reduceIte]
        simp only [show ¬((digitRun radix s).1.length + 1 > maxDigits) by omega, ↓reduceIte]
        have : (1 + (digitRun radix s).1.length > 1) = ((digitRun radix s).1.length > 0) := by
          apply propext; omega
        simp only [this]

end Core

end Netip.Impl.Parse
