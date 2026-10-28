import Netip.Impl.ParseCore

/-!
# `read_number`, `core`'s digit reader through Rust 1.97

`ParseCore` transcribes `core::net`'s address parsers from the Rust 1.99 sources.
The crate supports Rust 1.88 and later, and through Rust 1.97 `core` read IPv4
octets and IPv6 groups with `read_number(radix, Some(max_digits),
allow_zero_prefix)`. Rust 1.98 replaced it with `read_radix_max_digits`
(rust-lang/rust@1d54265734, "Optimize network address parser"). Between Rust 1.88
and 1.99 that is the only change to what the address parsers read: `char::to_digit`,
`u8::from_str` and the rest of `core/src/net/parser.rs` that they use are the same.

`read_number` adds each digit before it compares the count with `max_digits`, and
detects a leading zero by peeking at the first byte instead of by the first digit's
value (`readNumber`). It reads exactly what `read_radix_max_digits` reads, on every
input (`readNumber_eq`). The octet and group readers of every Rust release the crate
supports are therefore `readOctet` and `readGroup` (`readNumber_octet`,
`readNumber_group`), and the parser theorems hold for all of them.
-/

namespace Netip.Impl.Parse

namespace Core

/-- The digit loop of `read_number` with `max_digits = Some(max_digits)`: it adds a
digit, counts it, and fails once the count passes `max_digits`. -/
def readNumberDigits (radix maxDigits : Nat) (result count : Nat) : Bytes → Option (Nat × Nat × Bytes)
  | [] => some (result, count, [])
  | b :: s =>
    match toDigit radix b with
    | none => some (result, count, b :: s)
    | some digit =>
      if count + 1 > maxDigits then none
      else readNumberDigits radix maxDigits (result * radix + digit) (count + 1) s

/-- `read_number(radix, Some(max_digits), allow_zero_prefix)` into an integer type
whose values are those below `bound`, as Rust 1.88 to 1.97 have it: `peek_char()`
reads the first byte as a `char`. -/
def readNumber (radix maxDigits : Nat) (allowZeroPrefix : Bool) (bound : Nat) (s : Bytes) :
    Option (Nat × Bytes) :=
  match readNumberDigits radix maxDigits 0 0 s with
  | none => none
  | some (result, count, rest) =>
    if count = 0 then none
    else if !allowZeroPrefix && s.head? == some 48 && count > 1 then none
    else if result < bound then some (result, rest) else none

/-- Checking the count before or after counting a digit is the same test. -/
theorem readNumberDigits_eq_readDigits (radix maxDigits : Nat) (s : Bytes) :
    ∀ result count, readNumberDigits radix maxDigits result count s =
      readDigits radix maxDigits result count s := by
  induction s with
  | nil => intro result count; simp [readNumberDigits, readDigits]
  | cons b s ih =>
    intro result count
    cases hb : toDigit radix b with
    | none => simp [readNumberDigits, readDigits, hb]
    | some d =>
      simp only [readNumberDigits, readDigits, hb, ih]
      have : (count + 1 > maxDigits) = (count ≥ maxDigits) := by
        apply propext; omega
      simp only [this]

/-- Only `'0'` has the digit value `0`. -/
theorem toDigit_eq_zero_iff {radix : Nat} {b : UInt8} {d : Nat} (h : toDigit radix b = some d) :
    d = 0 ↔ b = 48 := by
  have hb : b = 48 ↔ b.toNat = 48 := by
    constructor
    · intro h; subst h; rfl
    · intro h; exact UInt8.toNat_inj.mp (by simpa using h)
  rw [hb]
  unfold toDigit at h
  dsimp only at h
  repeat' split at h
  all_goals simp at h
  all_goals omega

/-- `read_number` reads exactly what `read_radix_max_digits` reads. -/
theorem readNumber_eq (radix maxDigits : Nat) (allowZeroPrefix : Bool) (bound : Nat)
    (hmax : 1 ≤ maxDigits) (s : Bytes) :
    readNumber radix maxDigits allowZeroPrefix bound s =
      readRadixMaxDigits radix maxDigits allowZeroPrefix bound s := by
  match s with
  | [] => simp [readNumber, readNumberDigits, readRadixMaxDigits]
  | b :: t =>
    cases hb : toDigit radix b with
    | none => simp [readNumber, readNumberDigits, readRadixMaxDigits, hb]
    | some first =>
      simp only [readNumber, readNumberDigits, readRadixMaxDigits, hb,
        show ¬(0 + 1 > maxDigits) by omega, ↓reduceIte, Nat.zero_mul, Nat.zero_add,
        readNumberDigits_eq_readDigits, readDigits_eq radix maxDigits t first 1 hmax]
      by_cases hlen : 1 + (digitRun radix t).1.length > maxDigits
      · simp only [hlen, ↓reduceIte]
      · simp only [hlen, ↓reduceIte, show ¬(1 + (digitRun radix t).1.length = 0) by omega,
          List.head?_cons]
        have hz : (some b == some (48 : UInt8)) = (first == 0) := by
          apply Bool.eq_iff_iff.mpr
          simp only [beq_iff_eq, Option.some.injEq]
          exact (toDigit_eq_zero_iff hb).symm
        simp only [hz]

/-- The IPv4 octet reader of Rust 1.88 to 1.97, `read_number::<u8>(10, Some(3), false)`,
is `readOctet`. -/
theorem readNumber_octet : readNumber 10 3 false 256 = readOctet :=
  funext (readNumber_eq 10 3 false 256 (by decide))

/-- The IPv6 group reader of Rust 1.88 to 1.97, `read_number::<u16>(16, Some(4), true)`,
is `readGroup`. -/
theorem readNumber_group : readNumber 16 4 true 65536 = readGroup :=
  funext (readNumber_eq 16 4 true 65536 (by decide))

end Core

end Netip.Impl.Parse
