/-!
# `ipv4_binary_split` / `ipv6_binary_split`: gathering the block

After choosing the candidate, `ip_binary_split` finds the first network the
candidate contains and stably partitions the rest of the slice with
`stable_partition`: partition both halves, then rotate the rejects of the left
half past the accepts of the right half.

Proved for any predicate: `stable_partition` returns the accepted elements in
their original order followed by the rejected ones in theirs, and their count
(`stablePartition_eq`). So after the call the networks before the block are
untouched and contain none accepted, the block holds exactly the accepted
networks of the rest, and the remaining networks follow in their original order
(`splitBlock_spec`).

The candidate search, the agreement of the quadratic and the linear search, and
the size of the block are in `BinarySplitSearch`.
-/

namespace Netip.Impl

/-- `stable_partition` on a list: the reordered list and the number of accepted
elements. The rotation of `[left, mid + right)` by `mid - left` turns the
rejects of the left half followed by the accepts of the right half into the
accepts followed by the rejects. -/
def stablePartition {α : Type} (p : α → Bool) (l : List α) : List α × Nat :=
  if h : l.length ≤ 1 then
    match l with
    | [] => ([], 0)
    | [x] => ([x], if p x then 1 else 0)
    | _ :: _ :: _ => by simp at h
  else
    have h1 : (l.take (l.length / 2)).length < l.length := by simp; omega
    have h2 : (l.drop (l.length / 2)).length < l.length := by simp; omega
    let L := stablePartition p (l.take (l.length / 2))
    let R := stablePartition p (l.drop (l.length / 2))
    (L.1.take L.2 ++ R.1.take R.2 ++ L.1.drop L.2 ++ R.1.drop R.2, L.2 + R.2)
termination_by l.length

theorem stablePartition_eq_of_le {α : Type} (p : α → Bool) :
    ∀ (n : Nat) (l : List α), l.length ≤ n →
      stablePartition p l = (l.filter p ++ l.filter (fun x => !p x), (l.filter p).length) := by
  intro n
  induction n with
  | zero =>
    intro l hl
    have : l = [] := List.eq_nil_of_length_eq_zero (by omega)
    subst this
    simp [stablePartition]
  | succ n ih =>
    intro l hl
    by_cases h1 : l.length ≤ 1
    · rcases l with _ | ⟨x, _ | ⟨y, t⟩⟩
      · simp [stablePartition]
      · cases hx : p x <;> simp [stablePartition, hx]
      · simp at h1
    · unfold stablePartition
      rw [dite_eq_right h1]
      have ht : (l.take (l.length / 2)).length ≤ n := by simp; omega
      have hd : (l.drop (l.length / 2)).length ≤ n := by simp; omega
      rw [ih _ ht, ih _ hd]
      have hp : l.filter p = (l.take (l.length / 2)).filter p ++ (l.drop (l.length / 2)).filter p := by
        rw [← List.filter_append, List.take_append_drop]
      have hnp : l.filter (fun x => !p x) = (l.take (l.length / 2)).filter (fun x => !p x) ++
          (l.drop (l.length / 2)).filter (fun x => !p x) := by
        rw [← List.filter_append, List.take_append_drop]
      rw [hp, hnp]
      simp only [List.take_left, List.drop_left, List.length_append, List.append_assoc]

theorem stablePartition_eq {α : Type} (p : α → Bool) (l : List α) :
    stablePartition p l = (l.filter p ++ l.filter (fun x => !p x), (l.filter p).length) :=
  stablePartition_eq_of_le p l.length l (Nat.le_refl _)

/-- The reordering of `ip_binary_split` for the candidate's containment test
`p`: the index of the first accepted network, the reordered list, and the block. -/
def splitBlock {α : Type} (p : α → Bool) (l : List α) : Option (List α × Nat × Nat) :=
  match l.findIdx? p with
  | none => none
  | some start =>
    let part := stablePartition p (l.drop start)
    some (l.take start ++ part.1, start, start + part.2)

theorem splitBlock_spec {α : Type} (p : α → Bool) (l : List α) (r : List α) (a b : Nat)
    (h : splitBlock p l = some (r, a, b)) :
    r = l.take a ++ (l.drop a).filter p ++ (l.drop a).filter (fun x => !p x) ∧
    (∀ x ∈ l.take a, p x = false) ∧
    b = a + ((l.drop a).filter p).length ∧
    (∀ x ∈ l, p x = true → x ∈ (l.drop a).filter p) := by
  unfold splitBlock at h
  split at h
  · simp at h
  · rename_i start hstart
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl, rfl⟩ := h
    rw [stablePartition_eq]
    obtain ⟨hlen, -, hall⟩ := List.findIdx?_eq_some_iff_getElem.mp hstart
    have hpre : ∀ x ∈ l.take start, p x = false := by
      intro x hx
      obtain ⟨i, hi, rfl⟩ := List.getElem_of_mem hx
      rw [List.getElem_take]
      have hlt : i < start := by simp at hi; omega
      simpa using hall i hlt
    refine ⟨by simp [List.append_assoc], hpre, rfl, fun x hx hpx => ?_⟩
    rw [← List.take_append_drop start l, List.mem_append] at hx
    rcases hx with hx | hx
    · exact absurd hpx (by simp [hpre x hx])
    · exact List.mem_filter.mpr ⟨hx, hpx⟩

end Netip.Impl
