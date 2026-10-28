import Netip.Impl.ParseNet

/-!
# The token parsers of `src/parser.rs`

`parse_ipv4_network_next_ascii`, `parse_ipv6_network_next_ascii` and
`parse_ip_network_next_ascii`, transcribed with the fused kernels
`ipv*_network_next_fused` and their mask arms, `read_cidr_prefix`, `token_ends_at`
and the token scans. The reference parses the maximal leading run of the alphabet,
`[0-9./+]` for IPv4 and `[0-9a-fA-F:./+]` otherwise, as a whole with the reference of
`ParseNet`, and returns the rest after it (`refNext`).

Proved, for every byte slice, errors included (`parseIpv4NetworkNextAscii_eq`,
`parseIpv6NetworkNextAscii_eq`, `parseIpNetworkNextAscii_eq`): the token parsers are
the reference. A fused kernel that returns a result read up to the end of the token,
so that result is the reference on the token (`ipv4NetworkNextFused_ref`,
`ipv6NetworkNextFused_ref`): a CIDR suffix it reads is what `u8::from_str` reads
(`readCidrPrefix_some`), and a mask address holds a `.` or a `:`, so it is no CIDR
suffix. `parse_ip_network_next_ascii` tries the IPv4 kernel under the IPv6 alphabet
first, which keeps the documented dispatch: what that kernel accepts holds no `:`,
it fails only on a CIDR overflow, and what the IPv6 kernel accepts holds a `:`.
-/

namespace Netip.Impl.Parse

/-! ## The token parsers -/

/-- `is_ipv4_token_byte`: `[0-9./+]`. -/
def isIpv4TokenByte (b : UInt8) : Bool := (48 ≤ b && b ≤ 57) || b == 46 || b == 47 || b == 43

/-- `is_ipv6_token_byte`: `[0-9a-fA-F:./+]`. -/
def isIpv6TokenByte (b : UInt8) : Bool :=
  ((48 ≤ b && b ≤ 57) || (97 ≤ b && b ≤ 102) || (65 ≤ b && b ≤ 70)) || b == 58 || b == 46 || b == 47 || b == 43

/-- `token_ends_at::<UNION_ALPHABET>(buf, position)`: the end, or a byte outside the
alphabet. -/
def tokenEndsAt (union : Bool) (buf : Bytes) (position : Nat) : Bool :=
  match buf[position]? with
  | some b => if union then !isIpv6TokenByte b else !isIpv4TokenByte b
  | none => true

/-- `ipv4_token_end` / `ipv6_token_end`: the length of the maximal leading run of
alphabet bytes. -/
def tokenEnd (inAlphabet : UInt8 → Bool) (buf : Bytes) : Nat := (buf.takeWhile inAlphabet).length

/-- The digit loop of `read_cidr_prefix`: the value and the number of digits, or
`None` once the value passes 255. -/
def readCidrDigits (value : Nat) : Bytes → Option (Nat × Nat)
  | [] => some (value, 0)
  | b :: s =>
    match asciiDigitValue b with
    | none => some (value, 0)
    | some digit =>
      let value := value * 10 + digit
      if value > 255 then none
      else
        match readCidrDigits value s with
        | some (v, count) => some (v, count + 1)
        | none => none

/-- `read_cidr_prefix(buf, start)`: one optional `+` and at least one digit, read as a
prefix. Returns the value and the position past the digits. -/
def readCidrPrefix (buf : Bytes) (start : Nat) : Option (Nat × Nat) :=
  let digitsStart := if buf[start]? = some 43 then start + 1 else start
  match readCidrDigits 0 (buf.drop digitsStart) with
  | none => none
  | some (value, count) => if count = 0 then none else some (value, digitsStart + count)

/-- `ipv4_network_next_fused_mask::<UNION_ALPHABET>`: a CIDR suffix ending the token,
or else a mask address ending it; `None` sends the caller to its fallback. -/
def ipv4NetworkNextFusedMask (union : Bool) (addr : BitVec 32) (buf : Bytes) (maskStart : Nat) :
    Option (Except NetError (Net 32 × Nat)) :=
  match readCidrPrefix buf maskStart with
  | some (cidr, e) =>
    if tokenEndsAt union buf e then
      some (match tryFromCidr 32 addr cidr with
        | .ok net => .ok (net, e)
        | .error err => .error err)
    else ipv4NetworkNextFusedMaskAddr union addr buf maskStart
  | none => ipv4NetworkNextFusedMaskAddr union addr buf maskStart
where
  ipv4NetworkNextFusedMaskAddr (union : Bool) (addr : BitVec 32) (buf : Bytes) (maskStart : Nat) :
      Option (Except NetError (Net 32 × Nat)) :=
    match ipv4ParseAt (buf.drop maskStart) with
    | none => none
    | some (mask, consumed) =>
      if tokenEndsAt union buf (maskStart + consumed) then some (.ok (newNet addr mask, maskStart + consumed))
      else none

/-- `ipv4_network_next_fused::<UNION_ALPHABET>`. -/
def ipv4NetworkNextFused (union : Bool) (buf : Bytes) : Option (Except NetError (Net 32 × Nat)) :=
  match ipv4ParseAt buf with
  | none => none
  | some (addr, consumed) =>
    if buf[consumed]? = some 47 then ipv4NetworkNextFusedMask union addr buf (consumed + 1)
    else if tokenEndsAt union buf consumed then some (.ok (newNet addr (BitVec.allOnes 32), consumed))
    else none

/-- `ipv6_network_next_fused_mask`, under the IPv6 alphabet. -/
def ipv6NetworkNextFusedMask (addr : BitVec 128) (buf : Bytes) (maskStart : Nat) :
    Option (Except NetError (Net 128 × Nat)) :=
  match readCidrPrefix buf maskStart with
  | some (cidr, e) =>
    if tokenEndsAt true buf e then
      some (match tryFromCidr 128 addr cidr with
        | .ok net => .ok (net, e)
        | .error err => .error err)
    else ipv6NetworkNextFusedMaskAddr addr buf maskStart
  | none => ipv6NetworkNextFusedMaskAddr addr buf maskStart
where
  ipv6NetworkNextFusedMaskAddr (addr : BitVec 128) (buf : Bytes) (maskStart : Nat) :
      Option (Except NetError (Net 128 × Nat)) :=
    match ipv6ParseAt (buf.drop maskStart) with
    | none => none
    | some (mask, consumed) =>
      if tokenEndsAt true buf (maskStart + consumed) then some (.ok (newNet addr mask, maskStart + consumed))
      else none

/-- `ipv6_network_next_fused`. -/
def ipv6NetworkNextFused (buf : Bytes) : Option (Except NetError (Net 128 × Nat)) :=
  match ipv6ParseAt buf with
  | none => none
  | some (addr, consumed) =>
    if buf[consumed]? = some 47 then ipv6NetworkNextFusedMask addr buf (consumed + 1)
    else if tokenEndsAt true buf consumed then some (.ok (newNet addr (BitVec.allOnes 128), consumed))
    else none

/-- `parse_ipv4_network_next_ascii`: the fused path under the IPv4 alphabet, or the
whole token. -/
def parseIpv4NetworkNextAscii (buf : Bytes) : Except NetError (Net 32 × Bytes) :=
  match ipv4NetworkNextFused false buf with
  | some (.ok (net, e)) => .ok (net, buf.drop e)
  | some (.error err) => .error err
  | none =>
    match parseIpv4NetworkAscii (buf.take (tokenEnd isIpv4TokenByte buf)) with
    | .ok net => .ok (net, buf.drop (tokenEnd isIpv4TokenByte buf))
    | .error err => .error err

/-- `parse_ipv6_network_next_ascii`. -/
def parseIpv6NetworkNextAscii (buf : Bytes) : Except NetError (Net 128 × Bytes) :=
  match ipv6NetworkNextFused buf with
  | some (.ok (net, e)) => .ok (net, buf.drop e)
  | some (.error err) => .error err
  | none =>
    match parseIpv6NetworkAscii (buf.take (tokenEnd isIpv6TokenByte buf)) with
    | .ok net => .ok (net, buf.drop (tokenEnd isIpv6TokenByte buf))
    | .error err => .error err

/-- `parse_ip_network_next_ascii`: the IPv4 fused path under the IPv6 alphabet, then
the IPv6 one, then the whole token. -/
def parseIpNetworkNextAscii (buf : Bytes) : Except NetError (IpNet × Bytes) :=
  match ipv4NetworkNextFused true buf with
  | some (.ok (net, e)) => .ok (.v4 net, buf.drop e)
  | some (.error err) => .error err
  | none =>
    match ipv6NetworkNextFused buf with
    | some (.ok (net, e)) => .ok (.v6 net, buf.drop e)
    | some (.error err) => .error err
    | none =>
      match parseIpNetworkAscii (buf.take (tokenEnd isIpv6TokenByte buf)) with
      | .ok net => .ok (net, buf.drop (tokenEnd isIpv6TokenByte buf))
      | .error err => .error err

/-- The token reference: the maximal leading run of the alphabet, parsed as a whole
by `ref`, and the rest after it. -/
def refNext {α : Type} (inAlphabet : UInt8 → Bool) (ref : Bytes → Except NetError α) (buf : Bytes) :
    Except NetError (α × Bytes) :=
  match ref (buf.takeWhile inAlphabet) with
  | .ok v => .ok (v, buf.drop (buf.takeWhile inAlphabet).length)
  | .error err => .error err

/-! ## Token lemmas -/

set_option maxRecDepth 8192 in
theorem ipv4Token_of_digit (b : UInt8) : (toDigit 10 b).isSome = true → isIpv4TokenByte b = true :=
  forall_uint8 (P := fun b => (toDigit 10 b).isSome = true → isIpv4TokenByte b = true) (by decide) b

set_option maxRecDepth 8192 in
theorem ipv6Token_of_hex (b : UInt8) : (toDigit 16 b).isSome = true → isIpv6TokenByte b = true :=
  forall_uint8 (P := fun b => (toDigit 16 b).isSome = true → isIpv6TokenByte b = true) (by decide) b

set_option maxRecDepth 8192 in
theorem stops_of_not_ipv4Token (b : UInt8) : isIpv4TokenByte b = false → toDigit 10 b = none ∧ b ≠ 46 :=
  forall_uint8 (P := fun b => isIpv4TokenByte b = false → toDigit 10 b = none ∧ b ≠ 46) (by decide) b

set_option maxRecDepth 8192 in
theorem stops_of_not_ipv6Token (b : UInt8) :
    isIpv6TokenByte b = false → toDigit 16 b = none ∧ b ≠ 58 ∧ b ≠ 46 :=
  forall_uint8 (P := fun b => isIpv6TokenByte b = false → toDigit 16 b = none ∧ b ≠ 58 ∧ b ≠ 46)
    (by decide) b

/-- The alphabet of a token scan. -/
def alphabet (union : Bool) : UInt8 → Bool := if union then isIpv6TokenByte else isIpv4TokenByte

/-- Digits, `.`, `/` and `+` belong to both alphabets. -/
theorem alphabet_digit (union : Bool) {b : UInt8} (h : (toDigit 10 b).isSome = true) : alphabet union b = true := by
  cases union with
  | false => exact ipv4Token_of_digit b h
  | true =>
    apply ipv6Token_of_hex
    obtain ⟨d, hd⟩ := Option.isSome_iff_exists.mp h
    simp [toDigit_16_of_10 hd]

theorem alphabet_dot (union : Bool) : alphabet union 46 = true := by cases union <;> decide
theorem alphabet_slash (union : Bool) : alphabet union 47 = true := by cases union <;> decide
theorem alphabet_plus (union : Bool) : alphabet union 43 = true := by cases union <;> decide

/-- Where a token ends, no IPv4 address continues, and under the IPv6 alphabet no IPv6
address either. -/
theorem tokenEndsAt_alphabet {union : Bool} {buf : Bytes} {e : Nat} (h : tokenEndsAt union buf e = true) :
    ∀ b, buf[e]? = some b → alphabet union b = false := by
  intro b hb
  unfold tokenEndsAt at h
  rw [hb] at h
  cases union <;> simpa [alphabet] using h

theorem tokenEndsAt_stopsV4 {union : Bool} {buf : Bytes} {e : Nat} (h : tokenEndsAt union buf e = true) :
    StopsV4 (buf.drop e) := by
  intro b hb
  have hb' : buf[e]? = some b := by simpa using hb
  have ha := tokenEndsAt_alphabet h b hb'
  cases union with
  | false => exact stops_of_not_ipv4Token b ha
  | true =>
    obtain ⟨h16, -, hdot⟩ := stops_of_not_ipv6Token b ha
    refine ⟨?_, hdot⟩
    cases h10 : toDigit 10 b with
    | none => rfl
    | some d => rw [toDigit_16_of_10 h10] at h16; simp at h16

theorem tokenEndsAt_stopsV6 {buf : Bytes} {e : Nat} (h : tokenEndsAt true buf e = true) : StopsV6 (buf.drop e) := by
  intro b hb
  have hb' : buf[e]? = some b := by simpa using hb
  exact stops_of_not_ipv6Token b (tokenEndsAt_alphabet h b hb')

/-- The token of a scan is the prefix up to a byte outside the alphabet, when every
byte before it is inside. -/
theorem takeWhile_eq_take {A : UInt8 → Bool} {buf : Bytes} {e : Nat}
    (hin : ∀ i, i < e → ∃ b, buf[i]? = some b ∧ A b = true) (hout : ∀ b, buf[e]? = some b → A b = false) :
    buf.takeWhile A = buf.take e := by
  induction buf generalizing e with
  | nil => simp
  | cons b s ih =>
    cases e with
    | zero =>
      have := hout b (by simp)
      simp [List.takeWhile, this]
    | succ e =>
      obtain ⟨c, hc, hA⟩ := hin 0 (by omega)
      simp at hc
      subst hc
      simp only [List.takeWhile, hA, List.take_succ_cons]
      rw [ih (e := e) (fun i hi => by simpa using hin (i + 1) (by omega)) (fun b hb => hout b (by simpa using hb))]

/-- `read_cidr_prefix`'s digit loop reads what `parse_cidr_suffix`'s does. -/
theorem readCidrDigits_some (t : Bytes) :
    ∀ acc v c, readCidrDigits acc t = some (v, c) →
      parseCidrSuffixLoop acc (t.take c) = some v ∧ c ≤ t.length ∧
        ∀ i, i < c → ∃ b, t[i]? = some b ∧ (toDigit 10 b).isSome = true := by
  induction t with
  | nil =>
    intro acc v c h
    simp [readCidrDigits] at h
    obtain ⟨rfl, rfl⟩ := h
    simp [parseCidrSuffixLoop]
  | cons b s ih =>
    intro acc v c h
    simp only [readCidrDigits, asciiDigitValue_eq] at h
    cases hb : toDigit 10 b with
    | none =>
      simp [hb] at h
      obtain ⟨rfl, rfl⟩ := h
      simp [parseCidrSuffixLoop]
    | some d =>
      simp only [hb] at h
      split at h
      · simp at h
      · rename_i hv
        cases hr : readCidrDigits (acc * 10 + d) s with
        | none => simp [hr] at h
        | some p =>
          obtain ⟨v', c'⟩ := p
          simp [hr] at h
          obtain ⟨rfl, rfl⟩ := h
          obtain ⟨h1, h2, h3⟩ := ih _ _ _ hr
          refine ⟨?_, by simp; omega, ?_⟩
          · simp [parseCidrSuffixLoop, asciiDigitValue_eq, hb, hv, h1]
          · intro i hi
            cases i with
            | zero => exact ⟨b, by simp, by simp [hb]⟩
            | succ i => simpa using h3 i (by omega)

/-- `read_cidr_prefix` reads a CIDR suffix as a prefix: what it reads, `u8::from_str`
reads from those bytes alone, and they are a `+` and digits. -/
theorem readCidrPrefix_some {buf : Bytes} {start v e : Nat} (h : readCidrPrefix buf start = some (v, e)) :
    start < e ∧ e ≤ buf.length ∧
      (∀ i, start ≤ i → i < e → ∃ b, buf[i]? = some b ∧ (b = 43 ∨ (toDigit 10 b).isSome = true)) ∧
      Core.parseU8 ((buf.drop start).take (e - start)) = some v := by
  unfold readCidrPrefix at h
  by_cases h43 : buf[start]? = some 43
  · simp only [h43, ↓reduceIte] at h
    cases hr : readCidrDigits 0 (buf.drop (start + 1)) with
    | none => simp [hr] at h
    | some p =>
      obtain ⟨v', c⟩ := p
      simp only [hr] at h
      split at h
      · simp at h
      · rename_i hc
        simp at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨hloop, hcl, hdig⟩ := readCidrDigits_some _ _ _ _ hr
        simp only [List.length_drop] at hcl
        have hs : start < buf.length := by
          rcases Nat.lt_or_ge start buf.length with hs | hs
          · exact hs
          · simp [List.getElem?_eq_none hs] at h43
        refine ⟨by omega, by omega, ?_, ?_⟩
        · intro i hi1 hi2
          by_cases hi : i = start
          · subst hi; exact ⟨43, h43, Or.inl rfl⟩
          · obtain ⟨b, hb, hd⟩ := hdig (i - (start + 1)) (by omega)
            refine ⟨b, ?_, Or.inr hd⟩
            rw [getElem?_drop', show start + 1 + (i - (start + 1)) = i by omega] at hb
            exact hb
        · rw [← parseCidrSuffix_eq]
          have hd : buf.drop start = 43 :: buf.drop (start + 1) := by
            rw [List.drop_eq_getElem_cons hs]
            congr
            simpa [List.getElem?_eq_getElem hs] using h43
          rw [hd, show start + 1 + c - start = c + 1 by omega, List.take_succ_cons]
          unfold parseCidrSuffix
          simp only [List.head?_cons, ↓reduceIte, List.tail_cons]
          have hne : ((buf.drop (start + 1)).take c).isEmpty = false := by
            cases hdc : (buf.drop (start + 1)).take c with
            | nil =>
              have := congrArg List.length hdc
              simp at this
              omega
            | cons _ _ => rfl
          simp [hne, hloop]
  · simp only [h43, ↓reduceIte] at h
    cases hr : readCidrDigits 0 (buf.drop start) with
    | none => simp [hr] at h
    | some p =>
      obtain ⟨v', c⟩ := p
      simp only [hr] at h
      split at h
      · simp at h
      · rename_i hc
        simp at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨hloop, hcl, hdig⟩ := readCidrDigits_some _ _ _ _ hr
        simp only [List.length_drop] at hcl
        refine ⟨by omega, by omega, ?_, ?_⟩
        · intro i hi1 hi2
          obtain ⟨b, hb, hd⟩ := hdig (i - start) (by omega)
          refine ⟨b, ?_, Or.inr hd⟩
          rw [getElem?_drop', show start + (i - start) = i by omega] at hb
          exact hb
        · rw [← parseCidrSuffix_eq, show start + c - start = c by omega]
          unfold parseCidrSuffix
          have hhead : ((buf.drop start).take c).head? ≠ some 43 := by
            intro he
            have h0 : ((buf.drop start).take c)[0]? = some 43 := by
              rw [← he]; cases (buf.drop start).take c <;> rfl
            obtain ⟨b, hb, hd⟩ := hdig 0 (by omega)
            simp only [List.getElem?_take, show 0 < c by omega, ↓reduceIte] at h0
            rw [hb] at h0
            cases h0
            simp [show toDigit 10 43 = none by decide] at hd
          have hne : ((buf.drop start).take c).isEmpty = false := by
            cases hdc : (buf.drop start).take c with
            | nil =>
              have := congrArg List.length hdc
              simp at this
              omega
            | cons _ _ => rfl
          simp [hhead, hne, hloop]

/-- A fused result as the token parser returns it: the rest after the token. -/
def fusedResult {α : Type} (buf : Bytes) : Except NetError (α × Nat) → Except NetError (α × Bytes)
  | .ok (net, e) => .ok (net, buf.drop e)
  | .error err => .error err

/-- An IPv4 address goes on past its first `.`. -/
theorem ipv4ParseAt_first_dot_lt {t : Bytes} {a : BitVec 32} {n p : Nat} (h : ipv4ParseAt t = some (a, n))
    (hp : t[p]? = some 46) (hp3 : p ≤ 3) : p < n := by
  -- The first `.` is the one after the first octet, and three more octets follow it.
  unfold ipv4ParseAt at h
  split at h
  · simp at h
  · rename_i a1 p1 h1
    have o1 := readIpv4Octet_some h1
    split at h
    · simp at h
    · rename_i hd1
      split at h
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
                obtain ⟨-, rfl⟩ := h
                -- `p` is no digit, so it is not inside the first octet: `p ≥ p1`.
                have hge : p1 ≤ p := by
                  apply Nat.le_of_not_lt
                  intro hlt
                  obtain ⟨b, hb, hd⟩ := o1.2.2.2.2 p (by omega) hlt
                  rw [hp] at hb
                  cases hb
                  simp [show toDigit 10 46 = none by decide] at hd
                omega

/-! ## The fused paths are the reference -/

/-- The reference on a token whose first `/` is at `c`. -/
theorem refIpv4Network_take_slash {buf : Bytes} {c e : Nat} (hce : c < e) (hno : 47 ∉ buf.take c)
    (hslash : buf[c]? = some 47) :
    refIpv4Network (buf.take e) =
      match Core.parseIpv4 (buf.take c) with
      | none => .error (.addrParse .ipv4)
      | some addr =>
        match Core.parseU8 ((buf.drop (c + 1)).take (e - (c + 1))) with
        | some cidr => tryFromCidr 32 addr cidr
        | none =>
          match Core.parseIpv4 ((buf.drop (c + 1)).take (e - (c + 1))) with
          | some mask => .ok (newNet addr mask)
          | none => .error (.addrParse .ipv4) := by
  have hno' : 47 ∉ (buf.take e).take c := by rw [List.take_take, Nat.min_eq_left (by omega)]; exact hno
  have hslash' : (buf.take e)[c]? = some 47 := by simpa [List.getElem?_take, hce] using hslash
  unfold refIpv4Network
  rw [splitSlash_at hno' hslash']
  simp only [List.take_take, Nat.min_eq_left (Nat.le_of_lt hce), List.drop_take]
  rfl

theorem refIpv6Network_take_slash {buf : Bytes} {c e : Nat} (hce : c < e) (hno : 47 ∉ buf.take c)
    (hslash : buf[c]? = some 47) :
    refIpv6Network (buf.take e) =
      match Core.parseIpv6 (buf.take c) with
      | none => .error (.addrParse .ipv6)
      | some addr =>
        match Core.parseU8 ((buf.drop (c + 1)).take (e - (c + 1))) with
        | some cidr => tryFromCidr 128 addr cidr
        | none =>
          match Core.parseIpv6 ((buf.drop (c + 1)).take (e - (c + 1))) with
          | some mask => .ok (newNet addr mask)
          | none => .error (.addrParse .ipv6) := by
  have hno' : 47 ∉ (buf.take e).take c := by rw [List.take_take, Nat.min_eq_left (by omega)]; exact hno
  have hslash' : (buf.take e)[c]? = some 47 := by simpa [List.getElem?_take, hce] using hslash
  unfold refIpv6Network
  rw [splitSlash_at hno' hslash']
  simp only [List.take_take, Nat.min_eq_left (Nat.le_of_lt hce), List.drop_take]
  rfl

/-- `refNext` on a token that ends at `e`. -/
theorem refNext_take {α : Type} {A : UInt8 → Bool} {ref : Bytes → Except NetError α} {buf : Bytes} {e : Nat}
    (htok : buf.takeWhile A = buf.take e) (he : e ≤ buf.length) :
    refNext A ref buf =
      match ref (buf.take e) with
      | .ok v => .ok (v, buf.drop e)
      | .error err => .error err := by
  unfold refNext
  rw [htok, List.length_take, Nat.min_eq_left he]

/-- The IPv4 fused kernel, under either alphabet, returns the reference on the token:
it fails only when the fallback would have to decide. Its errors are CIDR overflows,
and its token holds no `:`. -/
theorem ipv4NetworkNextFused_ref (union : Bool) {buf : Bytes} {r : Except NetError (Net 32 × Nat)}
    (h : ipv4NetworkNextFused union buf = some r) :
    fusedResult buf r = refNext (alphabet union) refIpv4Network buf ∧
    (∀ err, r = .error err → ∃ cidr w, err = .cidrOverflow cidr w) ∧
    58 ∉ buf.takeWhile (alphabet union) := by
  unfold ipv4NetworkNextFused at h
  cases hp : ipv4ParseAt buf with
  | none => simp [hp] at h
  | some p =>
    obtain ⟨addr, c⟩ := p
    simp only [hp] at h
    obtain ⟨hc0, hcl, hcb⟩ := ipv4ParseAt_some hp
    have hno := ipv4ParseAt_noSlash hp
    -- The address bytes: digits and dots, inside the alphabet, no colon.
    have hpre : ∀ i, i < c → ∃ b, buf[i]? = some b ∧ alphabet union b = true ∧ b ≠ 58 := by
      intro i hi
      obtain ⟨b, hb, hd⟩ := hcb i hi
      refine ⟨b, hb, ?_, ?_⟩
      · rcases hd with hd | rfl
        · exact alphabet_digit union hd
        · exact alphabet_dot union
      · rcases hd with hd | rfl
        · intro e; subst e; simp [show toDigit 10 58 = none by decide] at hd
        · decide
    -- A token ending at `e`, past the address.
    have tok : ∀ e, c ≤ e → e ≤ buf.length → (∀ i, c ≤ i → i < e → ∃ b, buf[i]? = some b ∧
        alphabet union b = true ∧ b ≠ 58) → tokenEndsAt union buf e = true →
        buf.takeWhile (alphabet union) = buf.take e ∧ 58 ∉ buf.takeWhile (alphabet union) := by
      intro e hce hel hmid hend
      have hall : ∀ i, i < e → ∃ b, buf[i]? = some b ∧ alphabet union b = true ∧ b ≠ 58 := by
        intro i hi
        by_cases hic : i < c
        · exact hpre i hic
        · exact hmid i (by omega) hi
      have htok := takeWhile_eq_take (fun i hi => (hall i hi).imp fun b hb => ⟨hb.1, hb.2.1⟩)
        (tokenEndsAt_alphabet hend)
      refine ⟨htok, ?_⟩
      rw [htok]
      intro hm
      obtain ⟨i, hi, he⟩ := List.getElem_of_mem hm
      simp only [List.length_take] at hi
      obtain ⟨b, hb, -, hb58⟩ := hall i (by omega)
      rw [List.getElem_take] at he
      rw [List.getElem?_eq_getElem (by omega)] at hb
      simp at hb
      exact hb58 (hb ▸ he)
    by_cases hs : buf[c]? = some 47
    · simp only [hs, ↓reduceIte] at h
      have haddr := ipv4ParseAscii_take hp (stopsV4_slash hs)
      rw [ipv4ParseAscii_eq] at haddr
      have hcl' : c < buf.length := by
        rcases Nat.lt_or_ge c buf.length with hl | hl
        · exact hl
        · simp [List.getElem?_eq_none hl] at hs
      -- The mask address case, shared by both ways the CIDR read can miss.
      have maskAddr : ∀ r', ipv4NetworkNextFusedMask.ipv4NetworkNextFusedMaskAddr union addr buf (c + 1) = some r' →
          fusedResult buf r' = refNext (alphabet union) refIpv4Network buf ∧
          (∀ err, r' = .error err → ∃ cidr w, err = .cidrOverflow cidr w) ∧
          58 ∉ buf.takeWhile (alphabet union) := by
        intro r' hr'
        unfold ipv4NetworkNextFusedMask.ipv4NetworkNextFusedMaskAddr at hr'
        cases hm : ipv4ParseAt (buf.drop (c + 1)) with
        | none => simp [hm] at hr'
        | some q =>
          obtain ⟨mask, c'⟩ := q
          simp only [hm] at hr'
          split at hr'
          · rename_i hend
            simp at hr'
            subst hr'
            obtain ⟨hm0, hml, hmb⟩ := ipv4ParseAt_some hm
            simp only [List.length_drop] at hml
            have hmid : ∀ i, c ≤ i → i < c + 1 + c' → ∃ b, buf[i]? = some b ∧ alphabet union b = true ∧ b ≠ 58 := by
              intro i hi1 hi2
              by_cases hic : i = c
              · subst hic; exact ⟨47, hs, alphabet_slash union, by decide⟩
              · obtain ⟨b, hb, hd⟩ := hmb (i - (c + 1)) (by omega)
                rw [getElem?_drop', show c + 1 + (i - (c + 1)) = i by omega] at hb
                refine ⟨b, hb, ?_, ?_⟩
                · rcases hd with hd | rfl
                  · exact alphabet_digit union hd
                  · exact alphabet_dot union
                · rcases hd with hd | rfl
                  · intro e; subst e; simp [show toDigit 10 58 = none by decide] at hd
                  · decide
            obtain ⟨htok, hcolon⟩ := tok (c + 1 + c') (by omega) (by omega) hmid hend
            refine ⟨?_, by simp, hcolon⟩
            rw [refNext_take htok (by omega), refIpv4Network_take_slash (by omega) hno hs, haddr]
            simp only [show c + 1 + c' - (c + 1) = c' by omega]
            -- The mask text holds a `.`, so it is no CIDR suffix.
            obtain ⟨pd, hpd0, hpd3, hpdot, -⟩ := ipv4ParseAt_first_octet hm
            have hu8 : Core.parseU8 ((buf.drop (c + 1)).take c') = none := by
              apply parseU8_none_of_mem (c := 46) _ (by decide) (by decide)
              have hpc : pd < c' := ipv4ParseAt_first_dot_lt hm hpdot hpd3
              exact List.mem_iff_getElem?.mpr ⟨pd, by simpa [List.getElem?_take, hpc] using hpdot⟩
            have hmask := ipv4ParseAscii_take hm (by
              have := tokenEndsAt_stopsV4 hend
              rwa [List.drop_drop])
            rw [ipv4ParseAscii_eq] at hmask
            simp [hu8, hmask, fusedResult]
          · simp at hr'
      unfold ipv4NetworkNextFusedMask at h
      cases hcidr : readCidrPrefix buf (c + 1) with
      | none =>
        simp only [hcidr] at h
        exact maskAddr r h
      | some q =>
        obtain ⟨cidr, e⟩ := q
        simp only [hcidr] at h
        split at h
        · rename_i hend
          simp at h
          subst h
          obtain ⟨hlt, hle, hbytes, hu8⟩ := readCidrPrefix_some hcidr
          have hmid : ∀ i, c ≤ i → i < e → ∃ b, buf[i]? = some b ∧ alphabet union b = true ∧ b ≠ 58 := by
            intro i hi1 hi2
            by_cases hic : i = c
            · subst hic; exact ⟨47, hs, alphabet_slash union, by decide⟩
            · obtain ⟨b, hb, hd⟩ := hbytes i (by omega) hi2
              refine ⟨b, hb, ?_, ?_⟩
              · rcases hd with rfl | hd
                · exact alphabet_plus union
                · exact alphabet_digit union hd
              · rcases hd with rfl | hd
                · decide
                · intro e; subst e; simp [show toDigit 10 58 = none by decide] at hd
          obtain ⟨htok, hcolon⟩ := tok e (by omega) hle hmid hend
          refine ⟨?_, ?_, hcolon⟩
          · rw [refNext_take htok hle, refIpv4Network_take_slash (by omega) hno hs, haddr]
            simp only [hu8]
            cases tryFromCidr 32 addr cidr <;> rfl
          · intro err herr
            cases ht : tryFromCidr 32 addr cidr with
            | ok net => simp [ht] at herr
            | error err' =>
              simp [ht] at herr
              subst herr
              unfold tryFromCidr at ht
              split at ht
              · simp at ht
              · simp at ht; exact ⟨cidr, 32, ht.symm⟩
        · exact maskAddr r h
    · simp only [hs, ↓reduceIte] at h
      split at h
      · rename_i hend
        simp at h
        subst h
        obtain ⟨htok, hcolon⟩ := tok c (Nat.le_refl c) hcl (fun i h1 h2 => absurd h2 (by omega)) hend
        refine ⟨?_, by simp, hcolon⟩
        have haddr := ipv4ParseAscii_take hp (tokenEndsAt_stopsV4 hend)
        rw [ipv4ParseAscii_eq] at haddr
        rw [refNext_take htok hcl]
        unfold refIpv4Network
        rw [splitSlash_noSlash hno]
        simp [haddr, fusedResult]
      · simp at h

/-- The bytes of a parsed IPv6 address are in the IPv6 alphabet. -/
theorem parseIpv6_alphabet {x : Bytes} {a : BitVec 128} (h : Core.parseIpv6 x = some a) :
    ∀ i, i < x.length → ∃ b, x[i]? = some b ∧ isIpv6TokenByte b = true := by
  intro i hi
  refine ⟨x[i], by simp [hi], ?_⟩
  rcases parseIpv6_bytes h x[i] (List.getElem_mem hi) with hd | hd | hd
  · exact ipv6Token_of_hex _ hd
  · rw [hd]; decide
  · rw [hd]; decide

/-- The IPv6 fused kernel returns the reference on the token, which holds a `:`. -/
theorem ipv6NetworkNextFused_ref {buf : Bytes} {r : Except NetError (Net 128 × Nat)}
    (h : ipv6NetworkNextFused buf = some r) :
    fusedResult buf r = refNext isIpv6TokenByte refIpv6Network buf ∧ 58 ∈ buf.takeWhile isIpv6TokenByte := by
  unfold ipv6NetworkNextFused at h
  cases hp : ipv6ParseAt buf with
  | none => simp [hp] at h
  | some p =>
    obtain ⟨addr, c⟩ := p
    simp only [hp] at h
    have hcl := (ipv6ParseAt_le45 hp).2
    -- A token ending at `e`, past the address `buf.take c` that `core` reads.
    have tok : ∀ e, c ≤ e → e ≤ buf.length → Core.parseIpv6 (buf.take c) = some addr →
        (∀ i, c ≤ i → i < e → ∃ b, buf[i]? = some b ∧ isIpv6TokenByte b = true) →
        tokenEndsAt true buf e = true →
        buf.takeWhile isIpv6TokenByte = buf.take e ∧ 58 ∈ buf.takeWhile isIpv6TokenByte := by
      intro e hce hel haddr hmid hend
      have hpre := parseIpv6_alphabet haddr
      simp only [List.length_take, Nat.min_eq_left hcl] at hpre
      have htok := takeWhile_eq_take (A := isIpv6TokenByte) (e := e) (fun i hi => by
          by_cases hic : i < c
          · obtain ⟨b, hb, hA⟩ := hpre i hic
            exact ⟨b, by simpa [hic] using hb, hA⟩
          · exact hmid i (by omega) hi)
        (by simpa [alphabet] using tokenEndsAt_alphabet hend)
      refine ⟨htok, ?_⟩
      rw [htok]
      have hc := parseIpv6_colon haddr
      have : buf.take c <+: buf.take e := by
        rw [show buf.take c = (buf.take e).take c by rw [List.take_take, Nat.min_eq_left hce]]
        exact List.take_prefix _ _
      exact this.subset hc
    by_cases hs : buf[c]? = some 47
    · simp only [hs, ↓reduceIte] at h
      have haddr := ipv6ParseAscii_take hp (stopsV6_slash hs)
      rw [ipv6ParseAscii_eq] at haddr
      have hno := parseIpv6_noSlash haddr
      have hcl' : c < buf.length := by
        rcases Nat.lt_or_ge c buf.length with hl | hl
        · exact hl
        · simp [List.getElem?_eq_none hl] at hs
      have maskAddr : ∀ r', ipv6NetworkNextFusedMask.ipv6NetworkNextFusedMaskAddr addr buf (c + 1) = some r' →
          fusedResult buf r' = refNext isIpv6TokenByte refIpv6Network buf ∧ 58 ∈ buf.takeWhile isIpv6TokenByte := by
        intro r' hr'
        unfold ipv6NetworkNextFusedMask.ipv6NetworkNextFusedMaskAddr at hr'
        cases hm : ipv6ParseAt (buf.drop (c + 1)) with
        | none => simp [hm] at hr'
        | some q =>
          obtain ⟨mask, c'⟩ := q
          simp only [hm] at hr'
          split at hr'
          · rename_i hend
            simp at hr'
            subst hr'
            have hmask := ipv6ParseAscii_take hm (by
              have := tokenEndsAt_stopsV6 hend
              rwa [List.drop_drop])
            rw [ipv6ParseAscii_eq] at hmask
            have hml := (ipv6ParseAt_le45 hm).2
            simp only [List.length_drop] at hml
            have hmalpha := parseIpv6_alphabet hmask
            simp only [List.length_take, List.length_drop] at hmalpha
            have hmid : ∀ i, c ≤ i → i < c + 1 + c' → ∃ b, buf[i]? = some b ∧ isIpv6TokenByte b = true := by
              intro i hi1 hi2
              by_cases hic : i = c
              · subst hic; exact ⟨47, hs, by decide⟩
              · obtain ⟨b, hb, hA⟩ := hmalpha (i - (c + 1)) (by omega)
                refine ⟨b, ?_, hA⟩
                simp only [List.getElem?_take, show i - (c + 1) < c' by omega, ↓reduceIte] at hb
                rw [getElem?_drop', show c + 1 + (i - (c + 1)) = i by omega] at hb
                exact hb
            obtain ⟨htok, hcolon⟩ := tok (c + 1 + c') (by omega) (by omega) haddr hmid hend
            refine ⟨?_, hcolon⟩
            rw [refNext_take htok (by omega), refIpv6Network_take_slash (by omega) hno hs, haddr]
            simp only [show c + 1 + c' - (c + 1) = c' by omega]
            have hu8 : Core.parseU8 ((buf.drop (c + 1)).take c') = none :=
              parseU8_none_of_mem (parseIpv6_colon hmask) (by decide) (by decide)
            simp [hu8, hmask, fusedResult]
          · simp at hr'
      unfold ipv6NetworkNextFusedMask at h
      cases hcidr : readCidrPrefix buf (c + 1) with
      | none =>
        simp only [hcidr] at h
        exact maskAddr r h
      | some q =>
        obtain ⟨cidr, e⟩ := q
        simp only [hcidr] at h
        split at h
        · rename_i hend
          simp at h
          subst h
          obtain ⟨hlt, hle, hbytes, hu8⟩ := readCidrPrefix_some hcidr
          have hmid : ∀ i, c ≤ i → i < e → ∃ b, buf[i]? = some b ∧ isIpv6TokenByte b = true := by
            intro i hi1 hi2
            by_cases hic : i = c
            · subst hic; exact ⟨47, hs, by decide⟩
            · obtain ⟨b, hb, hd⟩ := hbytes i (by omega) hi2
              refine ⟨b, hb, ?_⟩
              rcases hd with rfl | hd
              · decide
              · simpa [alphabet] using alphabet_digit true hd
          obtain ⟨htok, hcolon⟩ := tok e (by omega) hle haddr hmid hend
          refine ⟨?_, hcolon⟩
          rw [refNext_take htok hle, refIpv6Network_take_slash (by omega) hno hs, haddr]
          simp only [hu8]
          cases tryFromCidr 128 addr cidr <;> rfl
        · exact maskAddr r h
    · simp only [hs, ↓reduceIte] at h
      split at h
      · rename_i hend
        simp at h
        subst h
        have haddr := ipv6ParseAscii_take hp (tokenEndsAt_stopsV6 hend)
        rw [ipv6ParseAscii_eq] at haddr
        obtain ⟨htok, hcolon⟩ := tok c (Nat.le_refl c) hcl haddr (fun i h1 h2 => absurd h2 (by omega)) hend
        refine ⟨?_, hcolon⟩
        rw [refNext_take htok hcl]
        unfold refIpv6Network
        rw [splitSlash_noSlash (parseIpv6_noSlash haddr)]
        simp [haddr, fusedResult]
      · simp at h

/-- A scan's token is its prefix of its own length. -/
theorem take_takeWhile_length (A : UInt8 → Bool) (l : Bytes) : l.take (l.takeWhile A).length = l.takeWhile A := by
  induction l with
  | nil => rfl
  | cons b l ih =>
    by_cases hb : A b = true
    · simp [List.takeWhile, hb, ih]
    · simp [List.takeWhile, hb]

/-! ## The token parsers are the reference -/

/-- `parse_ipv4_network_next_ascii` parses the maximal leading `[0-9./+]` token as a
whole and returns the rest after it, errors included. -/
theorem parseIpv4NetworkNextAscii_eq (buf : Bytes) :
    parseIpv4NetworkNextAscii buf = refNext isIpv4TokenByte refIpv4Network buf := by
  unfold parseIpv4NetworkNextAscii
  cases hf : ipv4NetworkNextFused false buf with
  | some r =>
    obtain ⟨h1, -, -⟩ := ipv4NetworkNextFused_ref false hf
    simp only [alphabet, Bool.false_eq_true, ↓reduceIte] at h1
    rw [← h1]
    cases r with
    | ok p => rfl
    | error err => rfl
  | none =>
    simp only
    unfold refNext tokenEnd
    rw [take_takeWhile_length, parseIpv4NetworkAscii_eq]
    cases refIpv4Network (buf.takeWhile isIpv4TokenByte) <;> rfl

/-- `parse_ipv6_network_next_ascii` parses the maximal leading `[0-9a-fA-F:./+]` token
as a whole and returns the rest after it, errors included. -/
theorem parseIpv6NetworkNextAscii_eq (buf : Bytes) :
    parseIpv6NetworkNextAscii buf = refNext isIpv6TokenByte refIpv6Network buf := by
  unfold parseIpv6NetworkNextAscii
  cases hf : ipv6NetworkNextFused buf with
  | some r =>
    obtain ⟨h1, -⟩ := ipv6NetworkNextFused_ref hf
    rw [← h1]
    cases r with
    | ok p => rfl
    | error err => rfl
  | none =>
    simp only
    unfold refNext tokenEnd
    rw [take_takeWhile_length, parseIpv6NetworkAscii_eq]
    cases refIpv6Network (buf.takeWhile isIpv6TokenByte) <;> rfl

theorem containsColon_iff (x : Bytes) : containsColon x = true ↔ 58 ∈ x := by
  simp [containsColon]

/-- `parse_ip_network_next_ascii` parses the maximal leading `[0-9a-fA-F:./+]` token
as a whole with the documented family dispatch, and returns the rest after it,
errors included. Trying the IPv4 kernel first keeps the dispatch: what it accepts
has no `:`, and it fails only on a CIDR overflow. -/
theorem parseIpNetworkNextAscii_eq (buf : Bytes) :
    parseIpNetworkNextAscii buf = refNext isIpv6TokenByte refIpNetwork buf := by
  unfold parseIpNetworkNextAscii
  cases hf : ipv4NetworkNextFused true buf with
  | some r =>
    obtain ⟨h1, herr, hcolon⟩ := ipv4NetworkNextFused_ref true hf
    simp only [alphabet, ↓reduceIte] at h1 hcolon
    have hcc : containsColon (buf.takeWhile isIpv6TokenByte) = false := by
      cases h : containsColon (buf.takeWhile isIpv6TokenByte) with
      | false => rfl
      | true => exact absurd ((containsColon_iff _).1 h) hcolon
    unfold refNext at h1 ⊢
    unfold refIpNetwork
    simp only [hcc, Bool.not_false, ↓reduceIte]
    cases r with
    | ok p =>
      obtain ⟨net, e⟩ := p
      simp only [fusedResult] at h1
      cases hr : refIpv4Network (buf.takeWhile isIpv6TokenByte) with
      | ok v =>
        rw [hr] at h1
        simp at h1
        obtain ⟨rfl, he⟩ := h1
        simp [he]
      | error err => rw [hr] at h1; simp at h1
    | error err =>
      simp only [fusedResult] at h1
      obtain ⟨cidr, w, rfl⟩ := herr err rfl
      cases hr : refIpv4Network (buf.takeWhile isIpv6TokenByte) with
      | ok v => rw [hr] at h1; simp at h1
      | error err' =>
        rw [hr] at h1
        simp at h1
        subst h1
        rfl
  | none =>
    simp only
    cases hg : ipv6NetworkNextFused buf with
    | some r =>
      obtain ⟨h1, hcolon⟩ := ipv6NetworkNextFused_ref hg
      have hcc : containsColon (buf.takeWhile isIpv6TokenByte) = true := (containsColon_iff _).2 hcolon
      unfold refNext at h1 ⊢
      unfold refIpNetwork
      simp only [hcc, Bool.not_true, Bool.false_eq_true, ↓reduceIte]
      cases r with
      | ok p =>
        obtain ⟨net, e⟩ := p
        simp only [fusedResult] at h1
        cases hr : refIpv6Network (buf.takeWhile isIpv6TokenByte) with
        | ok v =>
          rw [hr] at h1
          simp at h1
          obtain ⟨rfl, he⟩ := h1
          simp [he]
        | error err => rw [hr] at h1; simp at h1
      | error err =>
        simp only [fusedResult] at h1
        cases hr : refIpv6Network (buf.takeWhile isIpv6TokenByte) with
        | ok v => rw [hr] at h1; simp at h1
        | error err' =>
          rw [hr] at h1
          simp at h1
          subst h1
          rfl
    | none =>
      simp only
      unfold refNext tokenEnd
      rw [take_takeWhile_length, parseIpNetworkAscii_eq]
      cases refIpNetwork (buf.takeWhile isIpv6TokenByte) <;> rfl

end Netip.Impl.Parse
