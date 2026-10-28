import Netip.Impl.ParseFrame

/-!
# The network parsers of `src/parser.rs`

`parse_ipv4_network_ascii`, `parse_ipv6_network_ascii` and `parse_ip_network_ascii`,
transcribed with what they call: `ipv*_apply_mask`, `parse_ipv*_addr` with its `core`
fallback, `split_slash` and the split-first fallbacks. The token variants are in
`ParseToken`.

The reference is the documented semantics on `core`'s parsing alone
(`refIpv4Network`, `refIpv6Network`, `refIpNetwork`): the address up to the first
`/`, then a CIDR suffix as `u8::from_str` reads it, or else a mask address; a `:`
selects IPv6, and otherwise only an address error falls through from IPv4 to IPv6.

Proved, for every byte slice, errors included (`parseIpv4NetworkAscii_eq`,
`parseIpv6NetworkAscii_eq`, `parseIpNetworkAscii_eq`): the parsers are the reference.
The fast path reads the address as a prefix and stops before the end or a `/`, and
by `ParseFrame` `core` reads the same address from the bytes before the `/` alone.
`parse_ipv*_addr` is `core`'s parse, its fallback only supplying the error value
(`parseIpv4Addr_eq`).

Errors are compared as values, `NetError` holding the two variants of
`IpNetParseError`: `AddrParseError`, of the family that failed, and `CidrOverflow`.
`str::from_utf8` is modelled by `validUtf8`, whose answer never matters: `core`
rejects every input that is not ASCII.
-/

namespace Netip.Impl.Parse

/-- The family of an `AddrParseError`. -/
inductive AddrKind
  | ipv4
  | ipv6
  deriving DecidableEq

/-- The `IpNetParseError` values the parsers return. -/
inductive NetError
  /-- `AddrParseError(..)` from the parser of the family. -/
  | addrParse (kind : AddrKind)
  /-- `CidrOverflow(CidrOverflowError(cidr, max))`. -/
  | cidrOverflow (cidr max : Nat)
  deriving DecidableEq

/-- An `Ipv4Network` or `Ipv6Network`: the address and the mask. -/
abbrev Net (w : Nat) := BitVec w × BitVec w

/-- An `IpNetwork`. -/
inductive IpNet
  | v4 (net : Net 32)
  | v6 (net : Net 128)
  deriving DecidableEq

/-- `Ipv*Network::new`: the address normalized by the mask. -/
def newNet {w : Nat} (addr mask : BitVec w) : Net w := (addr &&& mask, mask)

/-- `Ipv*Network::try_from((addr, cidr))`: `ipv*_mask_from_cidr`, then `new`. -/
def tryFromCidr (w : Nat) (addr : BitVec w) (cidr : Nat) : Except NetError (Net w) :=
  if cidr ≤ w then .ok (newNet addr (maskFromCidr w (BitVec.ofNat w cidr)))
  else .error (.cidrOverflow cidr w)

/-- A UTF-8 continuation byte. -/
def isCont (b : UInt8) : Bool := 0x80 ≤ b && b ≤ 0xBF

/-- `str::from_utf8(bytes).is_ok()`: well-formed UTF-8. -/
def validUtf8 : Bytes → Bool
  | [] => true
  | b :: s =>
    if b < 0x80 then validUtf8 s
    else if 0xC2 ≤ b && b ≤ 0xDF then
      match s with
      | c :: s => isCont c && validUtf8 s
      | [] => false
    else if 0xE0 ≤ b && b ≤ 0xEF then
      match s with
      | c1 :: c2 :: s =>
        (if b = 0xE0 then 0xA0 ≤ c1 && c1 ≤ 0xBF
          else if b = 0xED then 0x80 ≤ c1 && c1 ≤ 0x9F
          else isCont c1) && isCont c2 && validUtf8 s
      | _ => false
    else if 0xF0 ≤ b && b ≤ 0xF4 then
      match s with
      | c1 :: c2 :: c3 :: s =>
        (if b = 0xF0 then 0x90 ≤ c1 && c1 ≤ 0xBF
          else if b = 0xF4 then 0x80 ≤ c1 && c1 ≤ 0x8F
          else isCont c1) && isCont c2 && isCont c3 && validUtf8 s
      | _ => false
    else false

/-! ## Addresses and masks -/

/-- `parse_ipv4_addr_error`: `core`'s parse for the error value. Input that is not
UTF-8 takes the error of an empty input. -/
def parseIpv4AddrError (bytes : Bytes) : Except NetError (BitVec 32) :=
  if validUtf8 bytes then
    match Core.parseIpv4 bytes with
    | some addr => .ok addr
    | none => .error (.addrParse .ipv4)
  else .error (.addrParse .ipv4)

/-- `parse_ipv4_addr`: the hand-written parser, and `core` on a reject. -/
def parseIpv4Addr (bytes : Bytes) : Except NetError (BitVec 32) :=
  match ipv4ParseAscii bytes with
  | some addr => .ok addr
  | none => parseIpv4AddrError bytes

def parseIpv6AddrError (bytes : Bytes) : Except NetError (BitVec 128) :=
  if validUtf8 bytes then
    match Core.parseIpv6 bytes with
    | some addr => .ok addr
    | none => .error (.addrParse .ipv6)
  else .error (.addrParse .ipv6)

def parseIpv6Addr (bytes : Bytes) : Except NetError (BitVec 128) :=
  match ipv6ParseAscii bytes with
  | some addr => .ok addr
  | none => parseIpv6AddrError bytes

/-- `ipv4_apply_mask`: a CIDR suffix, or else a mask address. -/
def ipv4ApplyMask (addr : BitVec 32) (mask : Bytes) : Except NetError (Net 32) :=
  match parseCidrSuffix mask with
  | some cidr => tryFromCidr 32 addr cidr
  | none =>
    match parseIpv4Addr mask with
    | .ok mask => .ok (newNet addr mask)
    | .error e => .error e

def ipv6ApplyMask (addr : BitVec 128) (mask : Bytes) : Except NetError (Net 128) :=
  match parseCidrSuffix mask with
  | some cidr => tryFromCidr 128 addr cidr
  | none =>
    match parseIpv6Addr mask with
    | .ok mask => .ok (newNet addr mask)
    | .error e => .error e

/-- `split_slash`: the bytes before the first `/`, and those after it. -/
def splitSlash : Bytes → Bytes × Option Bytes
  | [] => ([], none)
  | b :: s => if b = 47 then ([], some s) else ((b :: (splitSlash s).1), (splitSlash s).2)

/-! ## The network parsers -/

/-- `parse_ipv4_network_fallback`: split at the first `/`, then the address and the
mask. -/
def parseIpv4NetworkFallback (buf : Bytes) : Except NetError (Net 32) :=
  match parseIpv4Addr (splitSlash buf).1 with
  | .error e => .error e
  | .ok addr =>
    match (splitSlash buf).2 with
    | some mask => ipv4ApplyMask addr mask
    | none => .ok (newNet addr (BitVec.allOnes 32))

/-- `parse_ipv4_network_ascii`: the address read as a prefix, then the end or a `/`;
anything else goes to the fallback. -/
def parseIpv4NetworkAscii (buf : Bytes) : Except NetError (Net 32) :=
  match ipv4ParseAt buf with
  | some (addr, consumed) =>
    match buf[consumed]? with
    | none => .ok (newNet addr (BitVec.allOnes 32))
    | some b => if b = 47 then ipv4ApplyMask addr (buf.drop (consumed + 1)) else parseIpv4NetworkFallback buf
  | none => parseIpv4NetworkFallback buf

def parseIpv6NetworkFallback (buf : Bytes) : Except NetError (Net 128) :=
  match parseIpv6Addr (splitSlash buf).1 with
  | .error e => .error e
  | .ok addr =>
    match (splitSlash buf).2 with
    | some mask => ipv6ApplyMask addr mask
    | none => .ok (newNet addr (BitVec.allOnes 128))

def parseIpv6NetworkAscii (buf : Bytes) : Except NetError (Net 128) :=
  match ipv6ParseAt buf with
  | some (addr, consumed) =>
    match buf[consumed]? with
    | none => .ok (newNet addr (BitVec.allOnes 128))
    | some b => if b = 47 then ipv6ApplyMask addr (buf.drop (consumed + 1)) else parseIpv6NetworkFallback buf
  | none => parseIpv6NetworkFallback buf

/-- `contains_colon`. -/
def containsColon (buf : Bytes) : Bool := buf.any (· == 58)

/-- `parse_ip_network_ascii`: input with a `:` is IPv6; other input is tried as IPv4,
and only an address error falls through to IPv6. -/
def parseIpNetworkAscii (buf : Bytes) : Except NetError IpNet :=
  let v6 : Except NetError IpNet :=
    match parseIpv6NetworkAscii buf with
    | .ok net => .ok (.v6 net)
    | .error e => .error e
  if !containsColon buf then
    match parseIpv4NetworkAscii buf with
    | .ok net => .ok (.v4 net)
    | .error (.addrParse _) => v6
    | .error e => .error e
  else v6

/-! ## The reference -/

/-- The documented semantics on `core`'s parsing alone: the address up to the first
`/`, then a CIDR suffix as `u8::from_str` reads it, or else a mask address. -/
def refIpv4Network (buf : Bytes) : Except NetError (Net 32) :=
  match Core.parseIpv4 (splitSlash buf).1 with
  | none => .error (.addrParse .ipv4)
  | some addr =>
    match (splitSlash buf).2 with
    | none => .ok (newNet addr (BitVec.allOnes 32))
    | some mask =>
      match Core.parseU8 mask with
      | some cidr => tryFromCidr 32 addr cidr
      | none =>
        match Core.parseIpv4 mask with
        | some mask => .ok (newNet addr mask)
        | none => .error (.addrParse .ipv4)

def refIpv6Network (buf : Bytes) : Except NetError (Net 128) :=
  match Core.parseIpv6 (splitSlash buf).1 with
  | none => .error (.addrParse .ipv6)
  | some addr =>
    match (splitSlash buf).2 with
    | none => .ok (newNet addr (BitVec.allOnes 128))
    | some mask =>
      match Core.parseU8 mask with
      | some cidr => tryFromCidr 128 addr cidr
      | none =>
        match Core.parseIpv6 mask with
        | some mask => .ok (newNet addr mask)
        | none => .error (.addrParse .ipv6)

/-- The documented family dispatch over the references. -/
def refIpNetwork (buf : Bytes) : Except NetError IpNet :=
  let v6 : Except NetError IpNet :=
    match refIpv6Network buf with
    | .ok net => .ok (.v6 net)
    | .error e => .error e
  if !containsColon buf then
    match refIpv4Network buf with
    | .ok net => .ok (.v4 net)
    | .error (.addrParse _) => v6
    | .error e => .error e
  else v6

/-! ## What `core` accepts -/

/-- `core` accepts only digits and dots as an IPv4 address. -/
theorem parseIpv4_bytes {x : Bytes} {a : BitVec 32} (h : Core.parseIpv4 x = some a) :
    ∀ b ∈ x, (toDigit 10 b).isSome ∨ b = 46 := by
  intro b hb
  apply Classical.byContradiction
  intro hc
  obtain ⟨u, w, rfl⟩ := List.mem_iff_append.mp hb
  have hstop : StopsV4 (b :: w) := by
    intro c hc'
    simp at hc'
    subst hc'
    refine ⟨?_, fun h46 => hc (Or.inr h46)⟩
    cases hd : toDigit 10 b with
    | none => rfl
    | some d => exact absurd (Or.inl (by simp [hd])) hc
  have e := Core.readIpv4Addr_append u hstop
  unfold Core.parseIpv4 at h
  split at h
  · simp at h
  · rw [e] at h
    cases Core.readIpv4Addr u with
    | none => simp at h
    | some p => simp at h

/-- `core` accepts only hex digits, colons and dots as an IPv6 address. -/
theorem parseIpv6_bytes {x : Bytes} {a : BitVec 128} (h : Core.parseIpv6 x = some a) :
    ∀ b ∈ x, (toDigit 16 b).isSome ∨ b = 58 ∨ b = 46 := by
  intro b hb
  apply Classical.byContradiction
  intro hc
  obtain ⟨u, w, rfl⟩ := List.mem_iff_append.mp hb
  have hstop : StopsV6 (b :: w) := by
    intro c hc'
    simp at hc'
    subst hc'
    refine ⟨?_, fun h58 => hc (Or.inr (Or.inl h58)), fun h46 => hc (Or.inr (Or.inr h46))⟩
    cases hd : toDigit 16 b with
    | none => rfl
    | some d => exact absurd (Or.inl (by simp [hd])) hc
  have e := Core.readIpv6Addr_append u hstop
  unfold Core.parseIpv6 at h
  rw [e] at h
  cases Core.readIpv6Addr u with
  | none => simp at h
  | some p => simp at h

/-- A group reader leaves a suffix. -/
theorem readGroup_suffix {x r : Bytes} {g : Nat} (h : Core.readGroup x = some (g, r)) : ∃ k, r = x.drop k := by
  rw [Core.readGroup, Core.readRadixMaxDigits_eq _ _ _ _ (by decide)] at h
  refine ⟨(digitRun 16 x).1.length, ?_⟩
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

theorem not_mem_drop {x : Bytes} {c : UInt8} (h : c ∉ x) (k : Nat) : c ∉ x.drop k :=
  fun hm => h (List.mem_of_mem_drop hm)

theorem readGivenChar_none_of_not_mem {x : Bytes} {c : UInt8} (h : c ∉ x) : Core.readGivenChar c x = none := by
  cases x with
  | nil => rfl
  | cons b x =>
    have : b ≠ c := fun e => h (by simp [e])
    simp [Core.readGivenChar, this]

/-- An IPv6 address has a `:`: without one, the head run stops after an embedded IPv4
address or one group, and no `::` follows. -/
theorem parseIpv6_colon {x : Bytes} {a : BitVec 128} (h : Core.parseIpv6 x = some a) : 58 ∈ x := by
  apply Classical.byContradiction
  intro hx
  unfold Core.parseIpv6 Core.readIpv6Addr Core.readGroups at h
  rw [Core.readGroupsLoop.eq_2] at h
  simp only [Core.readSeparator, show ¬(0 > 0) by omega, ↓reduceIte, Option.bind_some,
    show 0 + 1 < 8 by omega] at h
  cases h4 : Core.readIpv4Addr x with
  | some p =>
    simp only [h4] at h
    simp [ipv4Groups] at h
  | none =>
    simp only [h4] at h
    cases hg : Core.readGroup x with
    | none =>
      simp only [hg] at h
      simp [readGivenChar_none_of_not_mem hx] at h
    | some p =>
      obtain ⟨g, r⟩ := p
      obtain ⟨k, rfl⟩ := readGroup_suffix hg
      have hr := not_mem_drop hx k
      simp only [hg] at h
      rw [Core.readGroupsLoop_stop 8 (by omega) _ (readGivenChar_none_of_not_mem hr)] at h
      simp [readGivenChar_none_of_not_mem hr] at h

/-- `u8::from_str` accepts only digits after an optional `+`. -/
theorem parseU8_none_of_mem {m : Bytes} {c : UInt8} (hc : c ∈ m) (hd : toDigit 10 c = none) (hp : c ≠ 43) :
    Core.parseU8 m = none := by
  have checked : ∀ l acc, c ∈ l → Core.u8Checked acc l = none := by
    intro l
    induction l with
    | nil => intro _ h; simp at h
    | cons b l ih =>
      intro acc h
      simp only [Core.u8Checked]
      rcases List.mem_cons.mp h with rfl | h
      · simp [hd]
      · cases toDigit 10 b with
        | none => rfl
        | some x =>
          simp only
          split
          · rfl
          · split
            · rfl
            · exact ih _ h
  have unchecked : ∀ l acc, c ∈ l → Core.u8Unchecked acc l = none := by
    intro l
    induction l with
    | nil => intro _ h; simp at h
    | cons b l ih =>
      intro acc h
      simp only [Core.u8Unchecked]
      rcases List.mem_cons.mp h with rfl | h
      · simp [hd]
      · cases toDigit 10 b with
        | none => rfl
        | some x => exact ih _ h
  unfold Core.parseU8
  split
  · rfl
  · split
    · rfl
    · simp only
      by_cases h43 : m.head? = some 43
      · have hmem : c ∈ m.tail := by
          cases m with
          | nil => simp at hc
          | cons b m =>
            simp at h43
            subst h43
            rcases List.mem_cons.mp hc with h | h
            · exact (hp h).elim
            · simpa using h
        simp only [h43, ↓reduceIte]
        split
        · exact unchecked _ _ hmem
        · exact checked _ _ hmem
      · simp only [h43, ↓reduceIte]
        split
        · exact unchecked _ _ hc
        · exact checked _ _ hc

/-! ## The network parsers are the reference -/

/-- `parse_ipv4_addr` is `core`'s parse: the fallback only supplies the error value. -/
theorem parseIpv4Addr_eq (b : Bytes) : parseIpv4Addr b =
    match Core.parseIpv4 b with
    | some a => .ok a
    | none => .error (.addrParse .ipv4) := by
  unfold parseIpv4Addr parseIpv4AddrError
  rw [ipv4ParseAscii_eq]
  cases Core.parseIpv4 b with
  | some a => rfl
  | none => by_cases hv : validUtf8 b <;> simp [hv]

theorem parseIpv6Addr_eq (b : Bytes) : parseIpv6Addr b =
    match Core.parseIpv6 b with
    | some a => .ok a
    | none => .error (.addrParse .ipv6) := by
  unfold parseIpv6Addr parseIpv6AddrError
  rw [ipv6ParseAscii_eq]
  cases Core.parseIpv6 b with
  | some a => rfl
  | none => by_cases hv : validUtf8 b <;> simp [hv]

theorem ipv4ApplyMask_eq (addr : BitVec 32) (m : Bytes) : ipv4ApplyMask addr m =
    match Core.parseU8 m with
    | some cidr => tryFromCidr 32 addr cidr
    | none =>
      match Core.parseIpv4 m with
      | some mask => .ok (newNet addr mask)
      | none => .error (.addrParse .ipv4) := by
  unfold ipv4ApplyMask
  rw [parseCidrSuffix_eq, parseIpv4Addr_eq]
  cases Core.parseU8 m with
  | some cidr => rfl
  | none =>
    simp only
    cases Core.parseIpv4 m <;> rfl

theorem ipv6ApplyMask_eq (addr : BitVec 128) (m : Bytes) : ipv6ApplyMask addr m =
    match Core.parseU8 m with
    | some cidr => tryFromCidr 128 addr cidr
    | none =>
      match Core.parseIpv6 m with
      | some mask => .ok (newNet addr mask)
      | none => .error (.addrParse .ipv6) := by
  unfold ipv6ApplyMask
  rw [parseCidrSuffix_eq, parseIpv6Addr_eq]
  cases Core.parseU8 m with
  | some cidr => rfl
  | none =>
    simp only
    cases Core.parseIpv6 m <;> rfl

/-- The split-first fallbacks are the reference. -/
theorem parseIpv4NetworkFallback_eq (buf : Bytes) : parseIpv4NetworkFallback buf = refIpv4Network buf := by
  unfold parseIpv4NetworkFallback refIpv4Network
  rw [parseIpv4Addr_eq]
  cases Core.parseIpv4 (splitSlash buf).1 with
  | none => rfl
  | some addr =>
    simp only
    cases (splitSlash buf).2 with
    | none => rfl
    | some mask => simp only; rw [ipv4ApplyMask_eq]

theorem parseIpv6NetworkFallback_eq (buf : Bytes) : parseIpv6NetworkFallback buf = refIpv6Network buf := by
  unfold parseIpv6NetworkFallback refIpv6Network
  rw [parseIpv6Addr_eq]
  cases Core.parseIpv6 (splitSlash buf).1 with
  | none => rfl
  | some addr =>
    simp only
    cases (splitSlash buf).2 with
    | none => rfl
    | some mask => simp only; rw [ipv6ApplyMask_eq]

theorem splitSlash_noSlash {buf : Bytes} (h : 47 ∉ buf) : splitSlash buf = (buf, none) := by
  induction buf with
  | nil => rfl
  | cons b s ih =>
    have hb : b ≠ 47 := fun e => h (by simp [e])
    have hs : 47 ∉ s := fun e => h (by simp [e])
    simp [splitSlash, hb, ih hs]

theorem splitSlash_at {buf : Bytes} {k : Nat} (h : 47 ∉ buf.take k) (hk : buf[k]? = some 47) :
    splitSlash buf = (buf.take k, some (buf.drop (k + 1))) := by
  induction buf generalizing k with
  | nil => simp at hk
  | cons b s ih =>
    cases k with
    | zero =>
      simp at hk
      simp [splitSlash, hk]
    | succ k =>
      have hb : b ≠ 47 := fun e => h (by simp [e])
      have hs : 47 ∉ s.take k := fun e => h (by simp [e])
      simp at hk
      simp [splitSlash, hb, ih hs hk]

/-- The bytes `ipv4_parse_at` reads hold no `/`. -/
theorem ipv4ParseAt_noSlash {s : Bytes} {a : BitVec 32} {n : Nat} (h : ipv4ParseAt s = some (a, n)) :
    47 ∉ s.take n := by
  intro hm
  obtain ⟨i, hi, he⟩ := List.getElem_of_mem hm
  simp only [List.length_take] at hi
  obtain ⟨b, hb, hd⟩ := (ipv4ParseAt_some h).2.2 i (by omega)
  have : b = 47 := by
    rw [List.getElem_take] at he
    rw [List.getElem?_eq_getElem (by omega)] at hb
    simp at hb
    rw [← hb, he]
  subst this
  rcases hd with hd | hd
  · simp [show toDigit 10 47 = none by decide] at hd
  · simp at hd

/-- `/` stops an address. -/
theorem stopsV4_slash {s : Bytes} {n : Nat} (h : s[n]? = some 47) : StopsV4 (s.drop n) := by
  intro b hb
  have : (s.drop n).head? = s[n]? := by simp
  rw [this, h] at hb
  cases hb
  decide

theorem stopsV6_slash {s : Bytes} {n : Nat} (h : s[n]? = some 47) : StopsV6 (s.drop n) := by
  intro b hb
  have : (s.drop n).head? = s[n]? := by simp
  rw [this, h] at hb
  cases hb
  decide

theorem stops_end {s : Bytes} {n : Nat} (h : s[n]? = none) : StopsV6 (s.drop n) ∧ StopsV4 (s.drop n) := by
  have : (s.drop n).head? = s[n]? := by simp
  constructor <;> intro b hb <;> rw [this, h] at hb <;> cases hb

/-- `parse_ipv4_network_ascii` is the reference: the fast path reads what the
fallback reads. -/
theorem parseIpv4NetworkAscii_eq (buf : Bytes) : parseIpv4NetworkAscii buf = refIpv4Network buf := by
  unfold parseIpv4NetworkAscii
  cases h : ipv4ParseAt buf with
  | none => exact parseIpv4NetworkFallback_eq buf
  | some p =>
    obtain ⟨addr, n⟩ := p
    simp only
    have hno := ipv4ParseAt_noSlash h
    cases hb : buf[n]? with
    | none =>
      have hp := ipv4ParseAscii_take h (stops_end hb).2
      rw [ipv4ParseAscii_eq] at hp
      have hn : n = buf.length := by
        have := (ipv4ParseAt_some h).2.1
        rw [List.getElem?_eq_none_iff] at hb
        omega
      subst hn
      rw [List.take_length] at hp hno
      unfold refIpv4Network
      rw [splitSlash_noSlash hno]
      simp [hp]
    | some b =>
      by_cases h47 : b = 47
      · subst h47
        have hp := ipv4ParseAscii_take h (stopsV4_slash hb)
        rw [ipv4ParseAscii_eq] at hp
        simp only [↓reduceIte]
        unfold refIpv4Network
        rw [splitSlash_at hno hb]
        simp only [hp]
        rw [ipv4ApplyMask_eq]
      · simp only [h47, ↓reduceIte]
        exact parseIpv4NetworkFallback_eq buf

/-- The bytes of an IPv6 address hold no `/`. -/
theorem parseIpv6_noSlash {x : Bytes} {a : BitVec 128} (h : Core.parseIpv6 x = some a) : 47 ∉ x := by
  intro hm
  rcases parseIpv6_bytes h 47 hm with hd | hd | hd
  · simp [show toDigit 16 47 = none by decide] at hd
  · simp at hd
  · simp at hd

theorem parseIpv6NetworkAscii_eq (buf : Bytes) : parseIpv6NetworkAscii buf = refIpv6Network buf := by
  unfold parseIpv6NetworkAscii
  cases h : ipv6ParseAt buf with
  | none => exact parseIpv6NetworkFallback_eq buf
  | some p =>
    obtain ⟨addr, n⟩ := p
    simp only
    cases hb : buf[n]? with
    | none =>
      have hp := ipv6ParseAscii_take h (stops_end hb).1
      rw [ipv6ParseAscii_eq] at hp
      have hn : n = buf.length := by
        have := (ipv6ParseAt_le45 h).2
        rw [List.getElem?_eq_none_iff] at hb
        omega
      subst hn
      rw [List.take_length] at hp
      unfold refIpv6Network
      rw [splitSlash_noSlash (parseIpv6_noSlash hp)]
      simp [hp]
    | some b =>
      by_cases h47 : b = 47
      · subst h47
        have hp := ipv6ParseAscii_take h (stopsV6_slash hb)
        rw [ipv6ParseAscii_eq] at hp
        simp only [↓reduceIte]
        unfold refIpv6Network
        rw [splitSlash_at (parseIpv6_noSlash hp) hb]
        simp only [hp]
        rw [ipv6ApplyMask_eq]
      · simp only [h47, ↓reduceIte]
        exact parseIpv6NetworkFallback_eq buf

/-- `parse_ip_network_ascii` is the reference dispatch. -/
theorem parseIpNetworkAscii_eq (buf : Bytes) : parseIpNetworkAscii buf = refIpNetwork buf := by
  unfold parseIpNetworkAscii refIpNetwork
  rw [parseIpv4NetworkAscii_eq, parseIpv6NetworkAscii_eq]

end Netip.Impl.Parse
