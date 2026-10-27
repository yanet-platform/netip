import Netip.Impl.BinarySplit
import Netip.Impl.Supernet

/-!
# `ipv4_binary_split` / `ipv6_binary_split`: the candidate search

`ip_binary_split` picks the candidate with one of two searches, by input size:

* `ip_binary_split_quadratic` folds `supernet_for` over the whole slice and over
  every window of `⌈n/2⌉` consecutive networks, and keeps the first one with the
  largest mask (`quadratic`);
* `ip_binary_split_linear` computes each window's mask as
  `!(OR of kill words) & mask_last`, with the kill word
  `!mask_j | (addr_j ^ addr_{j+1})` of every consecutive pair, keeping the OR of
  the sliding window exact with per-bit counters (`linear`).

Proved, for any list of at least three normalized networks, in any order: both
searches return the same network (`linear_eq_quadratic`), so the size threshold
that picks one only affects speed. The kill-word identity: the mask of the
supernet of consecutive networks is `!(OR of their kill words) & mask_last`
(`windowFold_mask`), since a bit survives the fold iff every mask fixes it and all
addresses agree on it, which holds iff every consecutive pair agrees on it. The
counters: after `add_kill` and `remove_kill`, the counter of each bit is the
number of kill words in the window with that bit set, and the OR has the bits
whose counter is positive (`WindowInv`).

The candidate contains every network of the window it came from, or of the whole
slice, so it contains at least `⌈n/2⌉` of the networks, and the block that
`splitBlock` gathers holds at least half of the slice (`binarySplit_spec`).
-/

namespace Netip.Impl

variable {w : Nat}

/-! ## Bit identities -/

theorem kill_step (A M ai p e1 e2 : BitVec w) (hA : A = ai &&& M) (h2 : M &&& (ai ^^^ p) = 0) :
    M &&& (e2 &&& ~~~(A ^^^ e1)) = M &&& ~~~(p ^^^ e1) &&& e2 := by
  subst hA
  apply BitVec.eq_of_getLsbD_eq
  intro b hb
  have t := congrArg (·.getLsbD b) h2
  simp only [BitVec.getLsbD_and, BitVec.getLsbD_xor, BitVec.getLsbD_not, BitVec.ofNat_eq_ofNat,
    BitVec.getLsbD_zero, hb, decide_true, Bool.true_and] at t ⊢
  revert t
  cases M.getLsbD b <;> cases ai.getLsbD b <;> cases p.getLsbD b <;> cases e1.getLsbD b <;>
    cases e2.getLsbD b <;> decide

theorem kill_not_or (x p2 y e2 : BitVec w) :
    ~~~x &&& p2 &&& ~~~y &&& e2 = ~~~(x ||| (~~~p2 ||| y)) &&& e2 := by
  apply BitVec.eq_of_getLsbD_eq
  intro b hb
  simp only [BitVec.getLsbD_and, BitVec.getLsbD_or, BitVec.getLsbD_not, hb, decide_true,
    Bool.true_and]
  cases x.getLsbD b <;> cases p2.getLsbD b <;> cases y.getLsbD b <;> cases e2.getLsbD b <;> decide

theorem kill_agree (A M ai e1 e2 : BitVec w) (hA : A = ai &&& M) :
    (M &&& (e2 &&& ~~~(A ^^^ e1))) &&& (ai ^^^ e1) = 0 := by
  subst hA
  apply BitVec.eq_of_getLsbD_eq
  intro b hb
  simp only [BitVec.getLsbD_and, BitVec.getLsbD_xor, BitVec.getLsbD_not, BitVec.ofNat_eq_ofNat,
    BitVec.getLsbD_zero, hb, decide_true, Bool.true_and]
  cases M.getLsbD b <;> cases ai.getLsbD b <;> cases e1.getLsbD b <;> cases e2.getLsbD b <;> decide

theorem kill_addr (ai M X : BitVec w) : (ai &&& M) &&& (M &&& X) = ai &&& (M &&& X) := by
  apply BitVec.eq_of_getLsbD_eq
  intro b hb
  simp only [BitVec.getLsbD_and]
  cases ai.getLsbD b <;> cases M.getLsbD b <;> cases X.getLsbD b <;> decide

/-! ## Window supernets -/

/-- `supernet_for(&[e])`: the mask loses the bits `e` does not fix and those where the
addresses differ, and `new` normalizes the address. -/
def supernetStep (s e : BitVec w × BitVec w) : BitVec w × BitVec w :=
  (s.1 &&& (s.2 &&& supernetFactor s.1 e), s.2 &&& supernetFactor s.1 e)

/-- `window_supernet`: `supernet_for` folded over the window from its first network. -/
def windowSupernet : List (BitVec w × BitVec w) → BitVec w × BitVec w
  | [] => (0, 0)
  | x :: xs => xs.foldl supernetStep x

/-- The network at index `j`. -/
def nth (L : List (BitVec w × BitVec w)) (j : Nat) : BitVec w × BitVec w := L.getD j (0, 0)

/-- The supernet of the `t + 1` networks from index `i`, step by step. -/
def windowFold (L : List (BitVec w × BitVec w)) (i : Nat) : Nat → BitVec w × BitVec w
  | 0 => nth L i
  | t + 1 => supernetStep (windowFold L i t) (nth L (i + t + 1))

/-- `kill_word(j)`: `!mask_j | (addr_j ^ addr_{j+1})`. -/
def killAt (L : List (BitVec w × BitVec w)) (j : Nat) : BitVec w :=
  ~~~(nth L j).2 ||| ((nth L j).1 ^^^ (nth L (j + 1)).1)

/-- The OR of the kill words `i ..< i + t`. -/
def orKills (L : List (BitVec w × BitVec w)) (i : Nat) : Nat → BitVec w
  | 0 => 0
  | t + 1 => orKills L i t ||| killAt L (i + t)

theorem window_eq_map (L : List (BitVec w × BitVec w)) {i t : Nat} (h : i + t < L.length) :
    (L.drop i).take (t + 1) = (List.range' i (t + 1)).map (nth L) := by
  apply List.ext_getElem
  · simp
    omega
  · intro k h1 h2
    simp only [List.getElem_take, List.getElem_drop, List.getElem_map, List.getElem_range', nth,
      Nat.one_mul]
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by simp at h1; omega)]
    rfl

theorem windowSupernet_eq (L : List (BitVec w × BitVec w)) {i t : Nat} (h : i + t < L.length) :
    windowSupernet ((L.drop i).take (t + 1)) = windowFold L i t := by
  rw [window_eq_map L h, List.range'_succ, List.map_cons, windowSupernet]
  clear h
  induction t with
  | zero => rfl
  | succ t ih =>
    rw [List.range'_concat, List.map_append, List.foldl_append, ih, windowFold, Nat.one_mul]
    simp only [List.map_cons, List.map_nil, List.foldl_cons, List.foldl_nil]
    rw [show i + 1 + t = i + t + 1 by omega]

/-- The kill-word identity: the window's supernet mask is `!(OR of its kill words) &
mask_last`. Along the way: on the mask, the first address agrees with the last, and
the address is the first one normalized. -/
theorem windowFold_mask (L : List (BitVec w × BitVec w)) (i : Nat)
    (hn : (nth L i).1 &&& (nth L i).2 = (nth L i).1) :
    ∀ t, (windowFold L i t).2 = ~~~(orKills L i t) &&& (nth L (i + t)).2 ∧
      (windowFold L i t).2 &&& ((nth L i).1 ^^^ (nth L (i + t)).1) = 0 ∧
      (windowFold L i t).1 = (nth L i).1 &&& (windowFold L i t).2 := by
  intro t
  induction t with
  | zero =>
    refine ⟨?_, ?_, ?_⟩
    · simp [windowFold, orKills]
    · simp [windowFold]
    · simp only [windowFold]
      exact hn.symm
  | succ t ih =>
    obtain ⟨h1, h2, h3⟩ := ih
    refine ⟨?_, ?_, ?_⟩
    · simp only [windowFold, supernetStep, supernetFactor, orKills, killAt]
      rw [kill_step _ _ _ _ _ _ h3 h2, h1, Nat.add_assoc, kill_not_or]
    · simp only [windowFold, supernetStep, supernetFactor]
      rw [Nat.add_assoc]
      exact kill_agree _ _ _ _ _ h3
    · simp only [windowFold, supernetStep, supernetFactor]
      rw [h3, kill_addr]

/-! ## The counters of the sliding OR -/

/-- Bit `p` of `1 << b`. -/
theorem getLsbD_one_shiftLeft {b p : Nat} (hb : b < w) :
    ((1#w) <<< b).getLsbD p = (decide (p < w) && decide (p = b)) := by
  rw [BitVec.getLsbD_shiftLeft, BitVec.getLsbD_one]
  by_cases h : p = b
  · subst h
    simp [hb]
    omega
  · by_cases hpb : p < b
    · simp [hpb, h]
    · simp [hpb, h]
      omega

/-- The facts about `trailing_zeros` and `k & (k - 1)` the counting loops use, proved
by `bv_decide` at 32 and 128 bits. -/
structure KillFacts (w : Nat) : Prop where
  ctz_lt : ∀ k : BitVec w, k ≠ 0 → k.ctz.toNat < w
  getLsbD_ctz : ∀ k : BitVec w, k ≠ 0 → k.getLsbD k.ctz.toNat = true
  clear : ∀ k : BitVec w, k ≠ 0 → ∀ p,
    (k &&& (k - 1)).getLsbD p = (k.getLsbD p && decide (p ≠ k.ctz.toNat))
  cpop_clear : ∀ k : BitVec w, k ≠ 0 → (k &&& (k - 1)).cpop.toNat + 1 = k.cpop.toNat

theorem getLsbD_zero' (b : Nat) : (0 : BitVec w).getLsbD b = false := by simp

theorem eq_zero_of_cpop (hk : KillFacts w) {k : BitVec w} (h : k.cpop.toNat = 0) : k = 0 := by
  apply Classical.byContradiction
  intro h0
  have := hk.cpop_clear k h0
  omega

/-- The counting loop of `add_kill`: `while k != 0 { c[k.trailing_zeros()] += 1;
k = k & (k - 1) }`. -/
def countUp : Nat → (Nat → Nat) → BitVec w → (Nat → Nat)
  | 0, c, _ => c
  | f + 1, c, k =>
    if k = 0 then c
    else countUp f (fun b => if b = k.ctz.toNat then c b + 1 else c b) (k &&& (k - 1))

/-- `add_kill`: ORs the word into the window and counts each of its bits. -/
def addKill (s : BitVec w × (Nat → Nat)) (k : BitVec w) : BitVec w × (Nat → Nat) :=
  (s.1 ||| k, countUp w s.2 k)

/-- The loop of `remove_kill`: `while k != 0 { b = k.trailing_zeros(); c[b] -= 1;
if c[b] == 0 { or = or & !(1 << b) }; k = k & (k - 1) }`. -/
def countDown : Nat → BitVec w × (Nat → Nat) → BitVec w → BitVec w × (Nat → Nat)
  | 0, s, _ => s
  | f + 1, s, k =>
    if k = 0 then s
    else
      let c := fun b => if b = k.ctz.toNat then s.2 b - 1 else s.2 b
      countDown f (if c k.ctz.toNat = 0 then s.1 &&& ~~~((1#w) <<< k.ctz.toNat) else s.1, c)
        (k &&& (k - 1))

/-- `remove_kill`. -/
def removeKill (s : BitVec w × (Nat → Nat)) (k : BitVec w) : BitVec w × (Nat → Nat) :=
  countDown w s k

theorem countUp_spec (hk : KillFacts w) :
    ∀ (f : Nat) (c : Nat → Nat) (k : BitVec w), k.cpop.toNat ≤ f →
      ∀ b, countUp f c k b = c b + (k.getLsbD b).toNat := by
  intro f
  induction f with
  | zero =>
    intro c k h b
    rw [eq_zero_of_cpop hk (k := k) (by omega)]
    simp [countUp]
  | succ f ih =>
    intro c k h b
    by_cases h0 : k = 0
    · subst h0
      simp [countUp]
    · have hc := hk.cpop_clear k h0
      simp only [countUp, h0, ↓reduceIte]
      rw [ih _ _ (by omega) b, hk.clear k h0 b]
      by_cases hb : b = k.ctz.toNat
      · subst hb
        simp [hk.getLsbD_ctz k h0]
      · simp [hb]

theorem countDown_succ (f : Nat) (s : BitVec w × (Nat → Nat)) {k : BitVec w} (h0 : k ≠ 0) :
    countDown (f + 1) s k =
      countDown f (if s.2 k.ctz.toNat - 1 = 0 then s.1 &&& ~~~((1#w) <<< k.ctz.toNat) else s.1,
        fun b => if b = k.ctz.toNat then s.2 b - 1 else s.2 b) (k &&& (k - 1)) := by
  simp only [countDown, h0, ↓reduceIte]

theorem countDown_spec (hk : KillFacts w) :
    ∀ (f : Nat) (s : BitVec w × (Nat → Nat)) (k : BitVec w), k.cpop.toNat ≤ f →
      (∀ b, b < w → s.1.getLsbD b = decide (0 < s.2 b)) →
      (∀ b, k.getLsbD b = true → 1 ≤ s.2 b) →
      (∀ b, (countDown f s k).2 b = s.2 b - (k.getLsbD b).toNat) ∧
        (∀ b, b < w → (countDown f s k).1.getLsbD b = decide (0 < (countDown f s k).2 b)) := by
  intro f
  induction f with
  | zero =>
    intro s k h hor _
    rw [eq_zero_of_cpop hk (k := k) (by omega)]
    exact ⟨fun b => by simp [countDown], hor⟩
  | succ f ih =>
    intro s k h hor hpos
    by_cases h0 : k = 0
    · subst h0
      have he : countDown (f + 1) s 0 = s := by simp [countDown]
      rw [he]
      exact ⟨fun b => by simp, hor⟩
    · have hc := hk.cpop_clear k h0
      have hlt := hk.ctz_lt k h0
      have hset := hk.getLsbD_ctz k h0
      have hclear := hk.clear k h0
      rw [countDown_succ f s h0]
      generalize k.ctz.toNat = z at hlt hset hclear ⊢
      have hz1 := hpos z hset
      obtain ⟨h1, h2⟩ := ih (if s.2 z - 1 = 0 then s.1 &&& ~~~((1#w) <<< z) else s.1,
        fun b => if b = z then s.2 b - 1 else s.2 b) (k &&& (k - 1)) (by omega)
        (by
          intro b hb
          by_cases hbz : b = z
          · subst hbz
            by_cases hzero : s.2 b - 1 = 0
            · simp only [hzero, ↓reduceIte, BitVec.getLsbD_and, BitVec.getLsbD_not,
                getLsbD_one_shiftLeft hlt, hb, decide_true, Bool.true_and, Bool.not_true,
                Bool.and_false]
              simp
            · simp only [hzero, ↓reduceIte]
              rw [hor b hb]
              simp
              omega
          · by_cases hzero : s.2 z - 1 = 0
            · simp only [hzero, ↓reduceIte, BitVec.getLsbD_and, BitVec.getLsbD_not,
                getLsbD_one_shiftLeft hlt, hb, decide_true, Bool.true_and, hbz, decide_false,
                Bool.not_false, Bool.and_true]
              exact hor b hb
            · simp only [hzero, ↓reduceIte, hbz]
              exact hor b hb)
        (by
          intro b hb
          rw [hclear b] at hb
          simp only [Bool.and_eq_true, decide_eq_true_eq] at hb
          simp only [hb.2, ↓reduceIte]
          exact hpos b hb.1)
      refine ⟨fun b => ?_, h2⟩
      rw [h1 b, hclear b]
      by_cases hbz : b = z
      · subst hbz
        simp [hset]
      · simp [hbz]

/-- The window of kill words the counters and the OR stand for: each counter is the
number of words with that bit set, and the OR has the bits whose counter is positive. -/
def WindowInv (s : BitVec w × (Nat → Nat)) (ws : List (BitVec w)) : Prop :=
  (∀ b, s.2 b = ws.countP (·.getLsbD b)) ∧ (∀ b, b < w → s.1.getLsbD b = decide (0 < s.2 b))

theorem windowInv_nil : WindowInv ((0 : BitVec w), fun _ => 0) [] :=
  ⟨fun _ => rfl, fun b _ => by simp⟩

theorem cpop_le (k : BitVec w) : k.cpop.toNat ≤ w := BitVec.toNat_cpop_le k

theorem windowInv_addKill (hk : KillFacts w) {s : BitVec w × (Nat → Nat)} {ws : List (BitVec w)}
    (h : WindowInv s ws) (k : BitVec w) : WindowInv (addKill s k) (ws ++ [k]) := by
  obtain ⟨h1, h2⟩ := h
  have hc := countUp_spec hk w s.2 k (cpop_le k)
  refine ⟨fun b => ?_, fun b hb => ?_⟩
  · simp only [addKill]
    rw [hc b, h1 b, List.countP_append]
    cases hkb : k.getLsbD b <;> simp [hkb]
  · show (s.1 ||| k).getLsbD b = decide (0 < countUp w s.2 k b)
    rw [BitVec.getLsbD_or, h2 b hb]
    simp only [hc b]
    cases k.getLsbD b <;> simp

theorem windowInv_removeKill (hk : KillFacts w) {s : BitVec w × (Nat → Nat)} {ws : List (BitVec w)}
    {k : BitVec w} (h : WindowInv s (k :: ws)) : WindowInv (removeKill s k) ws := by
  obtain ⟨h1, h2⟩ := h
  obtain ⟨hc, hor⟩ := countDown_spec hk w s k (cpop_le k) h2 (by
    intro b hb
    rw [h1 b, List.countP_cons]
    simp [hb])
  refine ⟨fun b => ?_, hor⟩
  simp only [removeKill]
  rw [hc b, h1 b, List.countP_cons]
  cases k.getLsbD b <;> simp

/-- The OR of a list of words. -/
def orList (l : List (BitVec w)) : BitVec w := l.foldl (· ||| ·) 0

theorem getLsbD_orList_aux (b : Nat) :
    ∀ (l : List (BitVec w)) (acc : BitVec w),
      (l.foldl (· ||| ·) acc).getLsbD b = (acc.getLsbD b || decide (0 < l.countP (·.getLsbD b))) := by
  intro l
  induction l with
  | nil => intro acc; simp
  | cons x l ih =>
    intro acc
    rw [List.foldl_cons, ih, BitVec.getLsbD_or, List.countP_cons]
    cases acc.getLsbD b <;> cases x.getLsbD b <;> simp

/-- The window's OR is the OR of its words. -/
theorem windowInv_or {s : BitVec w × (Nat → Nat)} {ws : List (BitVec w)} (h : WindowInv s ws) :
    s.1 = orList ws := by
  apply BitVec.eq_of_getLsbD_eq
  intro b hb
  rw [h.2 b hb, h.1 b, orList, getLsbD_orList_aux]
  simp

theorem killFacts32 : KillFacts 32 where
  ctz_lt k h0 := by
    have := BitVec.lt_def.mp (show k.ctz < 32#32 by bv_decide)
    simpa using this
  getLsbD_ctz k h0 := by
    have hlt : k.ctz.toNat < 32 := by
      have := BitVec.lt_def.mp (show k.ctz < 32#32 by bv_decide)
      simpa using this
    have h : k &&& ((1#32) <<< k.ctz) = (1#32) <<< k.ctz := by bv_decide
    have t := congrArg (·.getLsbD k.ctz.toNat) h
    simp only [BitVec.getLsbD_and, BitVec.shiftLeft_eq', getLsbD_one_shiftLeft hlt] at t
    simpa [hlt] using t
  clear k h0 p := by
    have hlt : k.ctz.toNat < 32 := by
      have := BitVec.lt_def.mp (show k.ctz < 32#32 by bv_decide)
      simpa using this
    have h : k &&& (k - 1) = k &&& ~~~((1#32) <<< k.ctz) := by bv_decide
    rw [h, BitVec.getLsbD_and, BitVec.getLsbD_not, BitVec.shiftLeft_eq', getLsbD_one_shiftLeft hlt]
    by_cases hp : p < 32
    · simp [hp]
    · simp [hp, BitVec.getLsbD_of_ge k p (by omega)]
  cpop_clear k h0 := by
    have h : (k &&& (k - 1)).cpop + 1 = k.cpop := by bv_decide
    have hle := BitVec.toNat_cpop_le (k &&& (k - 1))
    rw [← h, BitVec.toNat_add, show (1 : BitVec 32).toNat = 1 from rfl, Nat.mod_eq_of_lt (by omega)]

theorem killFacts128 : KillFacts 128 where
  ctz_lt k h0 := by
    have := BitVec.lt_def.mp (show k.ctz < 128#128 by bv_decide)
    simpa using this
  getLsbD_ctz k h0 := by
    have hlt : k.ctz.toNat < 128 := by
      have := BitVec.lt_def.mp (show k.ctz < 128#128 by bv_decide)
      simpa using this
    have h : k &&& ((1#128) <<< k.ctz) = (1#128) <<< k.ctz := by bv_decide
    have t := congrArg (·.getLsbD k.ctz.toNat) h
    simp only [BitVec.getLsbD_and, BitVec.shiftLeft_eq', getLsbD_one_shiftLeft hlt] at t
    simpa [hlt] using t
  clear k h0 p := by
    have hlt : k.ctz.toNat < 128 := by
      have := BitVec.lt_def.mp (show k.ctz < 128#128 by bv_decide)
      simpa using this
    have h : k &&& (k - 1) = k &&& ~~~((1#128) <<< k.ctz) := by bv_decide
    rw [h, BitVec.getLsbD_and, BitVec.getLsbD_not, BitVec.shiftLeft_eq', getLsbD_one_shiftLeft hlt]
    by_cases hp : p < 128
    · simp [hp]
    · simp [hp, BitVec.getLsbD_of_ge k p (by omega)]
  cpop_clear k h0 := by
    have h : (k &&& (k - 1)).cpop + 1 = k.cpop := by bv_decide
    have hle := BitVec.toNat_cpop_le (k &&& (k - 1))
    rw [← h, BitVec.toNat_add, show (1 : BitVec 128).toNat = 1 from rfl, Nat.mod_eq_of_lt (by omega)]

/-! ## The two searches -/

/-- The windows of `ws` consecutive networks, `nets.windows(ws)`. -/
def windows (ws : Nat) (L : List (BitVec w × BitVec w)) : List (List (BitVec w × BitVec w)) :=
  (List.range (L.length - ws + 1)).map fun i => (L.drop i).take ws

/-- `ip_binary_split_quadratic`: the supernet of the whole slice, replaced in turn by
the supernet of each window whose mask is larger. -/
def quadratic (L : List (BitVec w × BitVec w)) : Option (BitVec w × BitVec w) :=
  if L.length < 3 then none
  else
    some ((windows ((L.length + 1) / 2) L).foldl
      (fun cand win => if cand.2 < (windowSupernet win).2 then windowSupernet win else cand)
      (windowSupernet L))

/-- Pass 1 of `ip_binary_split_linear`: the OR of every kill word, and the counters
preloaded with the kill words of the first window. -/
def linearPass1 (L : List (BitVec w × BitVec w)) (ws : Nat) :
    BitVec w × (BitVec w × (Nat → Nat)) :=
  (List.range (L.length - 1)).foldl
    (fun acc j => (acc.1 ||| killAt L j, if j < ws - 1 then addKill acc.2 (killAt L j) else acc.2))
    (0, (0, fun _ => 0))

/-- One window of pass 2: slide the counters to window `i` unless it is the first, and
keep the window if its mask is strictly larger. -/
def linearStep (L : List (BitVec w × BitVec w)) (ws : Nat)
    (acc : (BitVec w × (Nat → Nat)) × Nat × BitVec w) (i : Nat) :
    (BitVec w × (Nat → Nat)) × Nat × BitVec w :=
  let st := if 0 < i then addKill (removeKill acc.1 (killAt L (i - 1))) (killAt L (i + ws - 2))
    else acc.1
  let wm := ~~~st.1 &&& (nth L (i + ws - 1)).2
  if acc.2.2 < wm then (st, i, wm) else (st, acc.2.1, acc.2.2)

/-- `ip_binary_split_linear`: the best window's first address and mask, normalized by
`from_bits`. -/
def linear (L : List (BitVec w × BitVec w)) : Option (BitVec w × BitVec w) :=
  if L.length < 3 then none
  else
    let ws := (L.length + 1) / 2
    let p1 := linearPass1 L ws
    let p2 := (List.range (L.length - ws + 1)).foldl (linearStep L ws)
      (p1.2, 0, ~~~p1.1 &&& (nth L (L.length - 1)).2)
    some ((nth L p2.2.1).1 &&& p2.2.2, p2.2.2)

theorem nth_mem {L : List (BitVec w × BitVec w)} {i : Nat} (h : i < L.length) : nth L i ∈ L := by
  unfold nth
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h]
  exact List.getElem_mem h

theorem orKills_eq (L : List (BitVec w × BitVec w)) (i : Nat) :
    ∀ t, orKills L i t = orList ((List.range' i t).map (killAt L))
  | 0 => rfl
  | t + 1 => by
    rw [orKills, orKills_eq L i t, List.range'_concat, List.map_append, orList, orList,
      List.foldl_append]
    simp

/-- The kill words of window `i`. -/
def wwords (L : List (BitVec w × BitVec w)) (ws i : Nat) : List (BitVec w) :=
  (List.range' i (ws - 1)).map (killAt L)

theorem linearPass1_spec (hk : KillFacts w) (L : List (BitVec w × BitVec w)) (ws : Nat) :
    ∀ k, ((List.range k).foldl
        (fun acc j => (acc.1 ||| killAt L j, if j < ws - 1 then addKill acc.2 (killAt L j) else acc.2))
        ((0 : BitVec w), ((0 : BitVec w), fun _ => 0))).1 = orKills L 0 k ∧
      WindowInv ((List.range k).foldl
        (fun acc j => (acc.1 ||| killAt L j, if j < ws - 1 then addKill acc.2 (killAt L j) else acc.2))
        ((0 : BitVec w), ((0 : BitVec w), fun _ => 0))).2
        ((List.range' 0 (min k (ws - 1))).map (killAt L)) := by
  intro k
  induction k with
  | zero => exact ⟨rfl, by simpa using windowInv_nil⟩
  | succ k ih =>
    rw [List.range_succ, List.foldl_append]
    simp only [List.foldl_cons, List.foldl_nil]
    obtain ⟨h1, h2⟩ := ih
    refine ⟨by rw [h1, orKills, Nat.zero_add], ?_⟩
    by_cases hk' : k < ws - 1
    · rw [ite_eq_left hk', show min (k + 1) (ws - 1) = min k (ws - 1) + 1 by omega,
        List.range'_concat, List.map_append, show 0 + 1 * min k (ws - 1) = k by omega]
      exact windowInv_addKill hk h2 _
    · rw [ite_eq_right hk', show min (k + 1) (ws - 1) = min k (ws - 1) by omega]
      exact h2

/-- Both searches pick the same window and return the same network. -/
theorem linear_eq_quadratic (hk : KillFacts w) (L : List (BitVec w × BitVec w))
    (hL : ∀ x ∈ L, x.1 &&& x.2 = x.1) : linear L = quadratic L := by
  unfold linear quadratic
  by_cases h3 : L.length < 3
  · rw [ite_eq_left h3, ite_eq_left h3]
  · rw [ite_eq_right h3, ite_eq_right h3]
    simp only [Option.some.injEq]
    generalize hn : L.length = n at h3
    generalize hws : (n + 1) / 2 = ws
    have hws2 : 2 ≤ ws := by omega
    have hwsn : ws ≤ n - 1 := by omega
    have hnorm : ∀ i, i < n → (nth L i).1 &&& (nth L i).2 = (nth L i).1 :=
      fun i hi => hL _ (nth_mem (by omega))
    -- pass 1
    obtain ⟨hp1, hp2⟩ := linearPass1_spec hk L ws (n - 1)
    rw [show min (n - 1) (ws - 1) = ws - 1 by omega] at hp2
    unfold linearPass1
    rw [hn]
    generalize (List.range (n - 1)).foldl _ _ = p1 at hp1 hp2
    -- the windows as indices
    rw [windows, hn, List.foldl_map]
    -- the whole slice
    have hwhole : windowSupernet L = ((nth L 0).1 &&& (~~~p1.1 &&& (nth L (n - 1)).2),
        ~~~p1.1 &&& (nth L (n - 1)).2) := by
      have e := windowSupernet_eq L (i := 0) (t := n - 1) (by omega)
      rw [List.drop_zero, List.take_of_length_le (by omega)] at e
      obtain ⟨m1, -, m3⟩ := windowFold_mask L 0 (hnorm 0 (by omega)) (n - 1)
      rw [e, Prod.ext_iff]
      rw [m3, m1, hp1, Nat.zero_add]
      exact ⟨rfl, rfl⟩
    rw [hwhole]
    -- pass 2, window by window
    have hstep : ∀ k, k ≤ n - ws + 1 →
        let A := (List.range k).foldl (linearStep L ws) (p1.2, 0, ~~~p1.1 &&& (nth L (n - 1)).2)
        let C := (List.range k).foldl (fun cand i =>
            if cand.2 < (windowSupernet ((L.drop i).take ws)).2 then windowSupernet ((L.drop i).take ws)
            else cand)
          ((nth L 0).1 &&& (~~~p1.1 &&& (nth L (n - 1)).2), ~~~p1.1 &&& (nth L (n - 1)).2)
        WindowInv A.1 (wwords L ws (k - 1)) ∧ A.2.1 < n ∧ C = ((nth L A.2.1).1 &&& A.2.2, A.2.2) := by
      intro k
      induction k with
      | zero =>
        intro _
        exact ⟨hp2, by simp only [List.range_zero, List.foldl_nil]; omega, rfl⟩
      | succ k ih =>
        intro hk1
        obtain ⟨i1, i2, i3⟩ := ih (by omega)
        rw [List.range_succ, List.foldl_append, List.foldl_append]
        simp only [List.foldl_cons, List.foldl_nil]
        generalize (List.range k).foldl (linearStep L ws) _ = A at i1 i2 i3
        generalize (List.range k).foldl _ _ = C at i3
        subst i3
        -- the counters of window `k`
        have hinv : WindowInv (if 0 < k then addKill (removeKill A.1 (killAt L (k - 1)))
            (killAt L (k + ws - 2)) else A.1) (wwords L ws k) := by
          by_cases hk0 : 0 < k
          · rw [ite_eq_left hk0]
            have e1 : wwords L ws (k - 1) = killAt L (k - 1) :: (List.range' k (ws - 2)).map (killAt L) := by
              rw [wwords, show ws - 1 = ws - 2 + 1 by omega, List.range'_succ, List.map_cons,
                show k - 1 + 1 = k by omega]
            have e2 : wwords L ws k = (List.range' k (ws - 2)).map (killAt L) ++ [killAt L (k + ws - 2)] := by
              rw [wwords, show ws - 1 = ws - 2 + 1 by omega, List.range'_concat, List.map_append,
                show k + 1 * (ws - 2) = k + ws - 2 by omega]
              rfl
            rw [e1] at i1
            rw [e2]
            exact windowInv_addKill hk (windowInv_removeKill hk i1) _
          · rw [ite_eq_right hk0]
            rw [show k = 0 by omega] at i1 ⊢
            exact i1
        generalize hst : (if 0 < k then addKill (removeKill A.1 (killAt L (k - 1)))
            (killAt L (k + ws - 2)) else A.1) = st at hinv
        -- the window's supernet
        have hwin : windowSupernet ((L.drop k).take ws) =
            ((nth L k).1 &&& (~~~st.1 &&& (nth L (k + ws - 1)).2), ~~~st.1 &&& (nth L (k + ws - 1)).2) := by
          have e := windowSupernet_eq L (i := k) (t := ws - 1) (by omega)
          rw [show ws - 1 + 1 = ws by omega] at e
          obtain ⟨m1, -, m3⟩ := windowFold_mask L k (hnorm k (by omega)) (ws - 1)
          rw [e, Prod.ext_iff, m3, m1, windowInv_or hinv, wwords, ← orKills_eq,
            show k + (ws - 1) = k + ws - 1 by omega]
          exact ⟨rfl, rfl⟩
        unfold linearStep
        simp only [hst, hwin]
        refine ⟨by split <;> exact hinv, ?_, ?_⟩
        · split
          · show k < n
            omega
          · exact i2
        · split <;> rfl
    obtain ⟨-, -, hC⟩ := hstep (n - ws + 1) (Nat.le_refl _)
    rw [hC]

/-! ## `ip_binary_split` -/

instance (n1 n2 : BitVec w × BitVec w) : Decidable (Contains n1 n2) := by
  unfold Contains
  infer_instance

/-- `ip_binary_split`: the candidate from the quadratic search below `threshold`
networks and from the linear one otherwise, then the block it contains. -/
def binarySplit (threshold : Nat) (L : List (BitVec w × BitVec w)) :
    Option ((BitVec w × BitVec w) × List (BitVec w × BitVec w) × Nat × Nat) :=
  match (if L.length < threshold then quadratic L else linear L) with
  | none => none
  | some cand =>
    match splitBlock (fun x => decide (Contains cand x)) L with
    | none => none
    | some (r, a, b) => some (cand, r, a, b)

/-- The threshold only affects speed, never the result. -/
theorem binarySplit_threshold (hk : KillFacts w) (L : List (BitVec w × BitVec w))
    (hL : ∀ x ∈ L, x.1 &&& x.2 = x.1) (t1 t2 : Nat) : binarySplit t1 L = binarySplit t2 L := by
  unfold binarySplit
  rw [linear_eq_quadratic hk L hL, ite_self, ite_self]

/-! ## The candidate contains a whole window -/


theorem supernetStep_eq (x1 M : BitVec w) (e : BitVec w × BitVec w) :
    supernetStep (x1 &&& M, M) e =
      (x1 &&& (M &&& supernetFactor x1 e), M &&& supernetFactor x1 e) := by
  have hm : M &&& supernetFactor (x1 &&& M) e = M &&& supernetFactor x1 e := by
    apply BitVec.eq_of_getLsbD_eq
    intro b hb
    simp only [supernetFactor, BitVec.getLsbD_and, BitVec.getLsbD_xor, BitVec.getLsbD_not, hb,
      decide_true, Bool.true_and]
    cases M.getLsbD b <;> cases x1.getLsbD b <;> cases e.1.getLsbD b <;> cases e.2.getLsbD b <;>
      decide
  simp only [supernetStep]
  rw [hm, kill_addr]

theorem foldl_supernetStep (x1 : BitVec w) :
    ∀ (xs : List (BitVec w × BitVec w)) (M : BitVec w),
      xs.foldl supernetStep (x1 &&& M, M) = (x1 &&& supernetMask x1 M xs, supernetMask x1 M xs) := by
  intro xs
  induction xs with
  | nil => intro M; rfl
  | cons e xs ih =>
    intro M
    rw [List.foldl_cons, supernetStep_eq, ih]
    rfl

/-- The window's supernet is the `supernet_for` of its first network and the rest. -/
theorem windowSupernet_cons {x : BitVec w × BitVec w} (hx : x.1 &&& x.2 = x.1)
    (xs : List (BitVec w × BitVec w)) :
    windowSupernet (x :: xs) = (x.1 &&& supernetMask x.1 x.2 xs, supernetMask x.1 x.2 xs) := by
  obtain ⟨x1, x2⟩ := x
  simp only at hx ⊢
  rw [windowSupernet, show ((x1, x2) : BitVec w × BitVec w) = (x1 &&& x2, x2) by rw [hx]]
  exact foldl_supernetStep x1 xs x2

/-- The search keeps the initial candidate or one of the windows' supernets. -/
theorem foldl_pick (g : List (BitVec w × BitVec w) → BitVec w × BitVec w) :
    ∀ (ws : List (List (BitVec w × BitVec w))) (c : BitVec w × BitVec w),
      ws.foldl (fun cand win => if cand.2 < (g win).2 then g win else cand) c = c ∨
        ∃ win ∈ ws, ws.foldl (fun cand win => if cand.2 < (g win).2 then g win else cand) c = g win := by
  intro ws
  induction ws with
  | nil => intro c; exact Or.inl rfl
  | cons v ws ih =>
    intro c
    rw [List.foldl_cons]
    split
    · rcases ih (g v) with h | ⟨win, hw, h⟩
      · exact Or.inr ⟨v, List.mem_cons_self, h⟩
      · exact Or.inr ⟨win, List.mem_cons_of_mem _ hw, h⟩
    · rcases ih c with h | ⟨win, hw, h⟩
      · exact Or.inl h
      · exact Or.inr ⟨win, List.mem_cons_of_mem _ hw, h⟩

/-- Counting the networks a window's supernet contains: the window has `ws` of them. -/
theorem countP_window {L : List (BitVec w × BitVec w)} {ws i : Nat} (hi : i + ws ≤ L.length)
    (p : BitVec w × BitVec w → Bool) (h : ∀ x ∈ (L.drop i).take ws, p x = true) :
    ws ≤ L.countP p := by
  have hsub : List.Sublist ((L.drop i).take ws) L :=
    (List.take_sublist _ _).trans (List.drop_sublist _ _)
  have hlen : ((L.drop i).take ws).length = ws := by simp; omega
  have := hsub.countP_le (p := p)
  rw [List.countP_eq_length.mpr h, hlen] at this
  exact this

/-- If at least `k` networks pass, `splitBlock` finds a block of all of them. -/
theorem splitBlock_length {α : Type} (p : α → Bool) (L : List α) {k : Nat} (hk : 0 < k)
    (h : k ≤ L.countP p) : ∃ r a b, splitBlock p L = some (r, a, b) ∧ k ≤ b - a := by
  unfold splitBlock
  cases hf : L.findIdx? p with
  | none =>
    rw [List.findIdx?_eq_none_iff] at hf
    have : L.countP p = 0 := List.countP_eq_zero.mpr fun a ha => by simp [hf a ha]
    omega
  | some start =>
    refine ⟨_, start, _, rfl, ?_⟩
    rw [stablePartition_eq]
    simp only
    obtain ⟨hlen, -, hall⟩ := List.findIdx?_eq_some_iff_getElem.mp hf
    have hpre : (L.take start).countP p = 0 := by
      rw [List.countP_eq_zero]
      intro x hx
      obtain ⟨i, hi, rfl⟩ := List.getElem_of_mem hx
      rw [List.getElem_take]
      have hlt : i < start := by simp at hi; omega
      simpa using hall i hlt
    have hsplit := congrArg (List.countP p) (List.take_append_drop start L)
    rw [List.countP_append, hpre, Nat.zero_add] at hsplit
    rw [← List.countP_eq_length_filter, hsplit]
    omega

namespace Ipv4

theorem windowSupernet_contains {W : List (BitVec 32 × BitVec 32)}
    (hW : ∀ x ∈ W, x.1 &&& x.2 = x.1) : ∀ x ∈ W, Contains (windowSupernet W) x := by
  cases W with
  | nil => intro x hx; simp at hx
  | cons x0 xs =>
    rw [windowSupernet_cons (hW x0 List.mem_cons_self)]
    obtain ⟨h0, hs⟩ := supernet_contains x0.1 x0.2 xs
    intro x hx
    rcases List.mem_cons.mp hx with rfl | hx
    · exact h0
    · exact hs x hx

/-- `ip_binary_split` on at least three normalized networks: both searches return the
same candidate, and the block of networks it contains, which `splitBlock` gathers,
holds at least half of the slice. -/
theorem binarySplit_spec (L : List (BitVec 32 × BitVec 32)) (hL : ∀ x ∈ L, x.1 &&& x.2 = x.1)
    (h3 : 3 ≤ L.length) :
    ∃ cand, quadratic L = some cand ∧ linear L = some cand ∧
      ∃ r a b, splitBlock (fun x => decide (Contains cand x)) L = some (r, a, b) ∧
        L.length ≤ 2 * (b - a) := by
  have hq : quadratic L = some ((windows ((L.length + 1) / 2) L).foldl
      (fun cand win => if cand.2 < (windowSupernet win).2 then windowSupernet win else cand)
      (windowSupernet L)) := by
    unfold quadratic
    rw [ite_eq_right (by omega)]
  generalize hc : (windows ((L.length + 1) / 2) L).foldl _ _ = cand at hq
  refine ⟨cand, hq, by rw [linear_eq_quadratic killFacts32 L hL, hq], ?_⟩
  have hcount : (L.length + 1) / 2 ≤ L.countP (fun x => decide (Contains cand x)) := by
    rcases foldl_pick windowSupernet _ (windowSupernet L) with h | ⟨win, hw, h⟩
    · rw [hc] at h
      subst h
      have := windowSupernet_contains hL
      have hall : L.countP (fun x => decide (Contains (windowSupernet L) x)) = L.length :=
        List.countP_eq_length.mpr fun x hx => by simpa using this x hx
      omega
    · rw [hc] at h
      subst h
      unfold windows at hw
      obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hw
      rw [List.mem_range] at hi
      apply countP_window (i := i) (by omega)
      intro x hx
      have hn : ∀ y ∈ (L.drop i).take ((L.length + 1) / 2), y.1 &&& y.2 = y.1 := fun y hy =>
        hL y (((List.take_sublist _ _).trans (List.drop_sublist _ _)).subset hy)
      simpa using windowSupernet_contains hn x hx
  obtain ⟨r, a, b, hs, hab⟩ := splitBlock_length _ L (by omega) hcount
  exact ⟨r, a, b, hs, by omega⟩

end Ipv4

namespace Ipv6

theorem windowSupernet_contains {W : List (BitVec 128 × BitVec 128)}
    (hW : ∀ x ∈ W, x.1 &&& x.2 = x.1) : ∀ x ∈ W, Contains (windowSupernet W) x := by
  cases W with
  | nil => intro x hx; simp at hx
  | cons x0 xs =>
    rw [windowSupernet_cons (hW x0 List.mem_cons_self)]
    obtain ⟨h0, hs⟩ := supernet_contains x0.1 x0.2 xs
    intro x hx
    rcases List.mem_cons.mp hx with rfl | hx
    · exact h0
    · exact hs x hx

theorem binarySplit_spec (L : List (BitVec 128 × BitVec 128)) (hL : ∀ x ∈ L, x.1 &&& x.2 = x.1)
    (h3 : 3 ≤ L.length) :
    ∃ cand, quadratic L = some cand ∧ linear L = some cand ∧
      ∃ r a b, splitBlock (fun x => decide (Contains cand x)) L = some (r, a, b) ∧
        L.length ≤ 2 * (b - a) := by
  have hq : quadratic L = some ((windows ((L.length + 1) / 2) L).foldl
      (fun cand win => if cand.2 < (windowSupernet win).2 then windowSupernet win else cand)
      (windowSupernet L)) := by
    unfold quadratic
    rw [ite_eq_right (by omega)]
  generalize hc : (windows ((L.length + 1) / 2) L).foldl _ _ = cand at hq
  refine ⟨cand, hq, by rw [linear_eq_quadratic killFacts128 L hL, hq], ?_⟩
  have hcount : (L.length + 1) / 2 ≤ L.countP (fun x => decide (Contains cand x)) := by
    rcases foldl_pick windowSupernet _ (windowSupernet L) with h | ⟨win, hw, h⟩
    · rw [hc] at h
      subst h
      have := windowSupernet_contains hL
      have hall : L.countP (fun x => decide (Contains (windowSupernet L) x)) = L.length :=
        List.countP_eq_length.mpr fun x hx => by simpa using this x hx
      omega
    · rw [hc] at h
      subst h
      unfold windows at hw
      obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hw
      rw [List.mem_range] at hi
      apply countP_window (i := i) (by omega)
      intro x hx
      have hn : ∀ y ∈ (L.drop i).take ((L.length + 1) / 2), y.1 &&& y.2 = y.1 := fun y hy =>
        hL y (((List.take_sublist _ _).trans (List.drop_sublist _ _)).subset hy)
      simpa using windowSupernet_contains hn x hx
  obtain ⟨r, a, b, hs, hab⟩ := splitBlock_length _ L (by omega) hcount
  exact ⟨r, a, b, hs, by omega⟩

end Ipv6

end Netip.Impl
