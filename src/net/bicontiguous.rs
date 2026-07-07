//! Bi-contiguous IP network wrapper.
//!
//! [`BiContiguous<T>`] guarantees at the type level that a wrapped IPv6
//! network's mask splits into exactly two contiguous runs, one per 64-bit
//! half of the address.

use core::{
    convert::TryFrom,
    error::Error,
    fmt::{Display, Formatter},
    net::Ipv6Addr,
    ops::Deref,
    str::FromStr,
};

use super::{IpNetParseError, Ipv6Network};
use crate::Contiguous;

/// An error that occurs when parsing a bi-contiguous IP network.
#[derive(Debug, PartialEq)]
pub enum BiContiguousIpNetParseError {
    /// The network's mask is not bi-contiguous.
    NonBiContiguousNetwork,
    /// An error occurred while parsing the IP network.
    IpNetParseError(IpNetParseError),
}

impl From<IpNetParseError> for BiContiguousIpNetParseError {
    #[inline]
    fn from(err: IpNetParseError) -> Self {
        BiContiguousIpNetParseError::IpNetParseError(err)
    }
}

impl Display for BiContiguousIpNetParseError {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), core::fmt::Error> {
        match self {
            Self::NonBiContiguousNetwork => write!(fmt, "non-bi-contiguous network"),
            Self::IpNetParseError(err) => write!(fmt, "{}", err),
        }
    }
}

impl Error for BiContiguousIpNetParseError {}

/// A bi-contiguous IP network.
///
/// Represents a wrapper around an [`Ipv6Network`] whose mask is **guaranteed
/// to split into exactly two contiguous runs of leading one bits, one per
/// 64-bit half of the address**: `mask = concat(1^p 0^(64-p), 1^q 0^(64-q))`
/// for some `p, q` in `0..=64`. The address set it describes is an
/// axis-aligned rectangle on the (high 64 bits, low 64 bits) plane -- the
/// high half typically selects one hierarchy (e.g. provider/site), the low
/// half another (e.g. service/customer field), and the middle gap plus the
/// tail are "don't care".
///
/// [`Contiguous<Ipv6Network>`] is a special case of this class (`q = 0`, or
/// `p = 64`), so upgrading from it is infallible -- see
/// `From<Contiguous<Ipv6Network>>`.
///
/// Per the wrapper principle, a method gets a behavior-preserving override
/// either when it runs strictly faster given the bi-contiguous guarantee, or
/// -- for [`intersection`](Self::intersection) -- when the class is provably
/// closed under the operation, so the typed result can be returned with zero
/// extra validation:
/// - [`is_bicontiguous`](Self::is_bicontiguous) is overridden to a constant
///   `true`.
/// - There is no single-prefix accessor equivalent to
///   [`Contiguous<Ipv6Network>::prefix`]: a bi-contiguous mask generally isn't
///   describable by one prefix length, so use [`hi_prefix`](Self::hi_prefix) /
///   [`lo_prefix`](Self::lo_prefix) instead.
/// - [`Ipv6Network::is_contiguous`] is intentionally NOT overridden: it is only
///   `true` for the degenerate members of this class (`q == 0 || p == 64`), and
///   computing the per-half prefix lengths `p`/`q` to check that costs more
///   than the inner 3-op check, so it stays reachable unchanged through
///   [`Deref`].
/// - [`Ipv6Network::merge`] is intentionally NOT overridden either: the class
///   is not closed under merge (an equal-mask single-bit merge stays
///   bi-contiguous only when the bit is the bottom bit of its run), so merging
///   two bi-contiguous networks can leave the class -- it returns a plain
///   [`Ipv6Network`] through [`Deref`], by design.
/// - [`Ipv6Network::intersection`] IS overridden, but for closure, not speed:
///   the class is closed under intersection (mask-or of two class masks is
///   itself a class mask, each half's prefix becoming the max of the two
///   inputs' prefixes for that half), so the general result never needs
///   re-validating before being returned as `Option<Self>`. See
///   [`intersection`](Self::intersection).
/// - [`Ipv6Network::intersects`] / [`Ipv6Network::is_disjoint`] are
///   intentionally NOT overridden: the general 3-op check already tests both
///   halves of the address in one pass, so checking each half separately would
///   cost more, not less.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BiContiguous<T>(T);

impl BiContiguous<Ipv6Network> {
    /// Parses an IPv6 network from a string and returns a bi-contiguous
    /// network.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{BiContiguous, Ipv6Network};
    ///
    /// let net = BiContiguous::<Ipv6Network>::parse(
    ///     "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
    /// )
    /// .unwrap();
    /// assert_eq!(40, net.hi_prefix());
    /// assert_eq!(32, net.lo_prefix());
    ///
    /// let net =
    ///     BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0:0/ffff:ffff:ff00::ffff:0:0:0")
    ///         .unwrap();
    /// assert_eq!(40, net.hi_prefix());
    /// assert_eq!(16, net.lo_prefix());
    ///
    /// // An interior hole inside the low half is not bi-contiguous.
    /// assert!(
    ///     BiContiguous::<Ipv6Network>::parse(
    ///         "2a02:6b8:0:0:1234:5678::/ffff:ffff:0:0:f0f0:f0f0:f0f0:f0f0"
    ///     )
    ///     .is_err()
    /// );
    /// ```
    pub fn parse(buf: &str) -> Result<Self, BiContiguousIpNetParseError> {
        let net = Ipv6Network::parse(buf)?;
        Self::try_from(net)
    }

    /// Returns the prefix length `p` of the high 64-bit half of the mask.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{BiContiguous, Ipv6Network};
    ///
    /// let net = BiContiguous::<Ipv6Network>::parse(
    ///     "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
    /// )
    /// .unwrap();
    /// assert_eq!(40, net.hi_prefix());
    /// ```
    #[inline]
    #[must_use]
    pub const fn hi_prefix(&self) -> u8 {
        match self {
            Self(net) => {
                let mask = net.mask().to_bits();
                let hi = (mask >> 64) as u64;
                hi.leading_ones() as u8
            }
        }
    }

    /// Returns the prefix length `q` of the low 64-bit half of the mask.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{BiContiguous, Ipv6Network};
    ///
    /// let net = BiContiguous::<Ipv6Network>::parse(
    ///     "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
    /// )
    /// .unwrap();
    /// assert_eq!(32, net.lo_prefix());
    /// ```
    #[inline]
    #[must_use]
    pub const fn lo_prefix(&self) -> u8 {
        match self {
            Self(net) => {
                let mask = net.mask().to_bits();
                let lo = mask as u64;
                lo.leading_ones() as u8
            }
        }
    }

    /// Checks whether this network is a bi-contiguous network.
    ///
    /// Always returns `true`: the wrapped network is guaranteed to be
    /// bi-contiguous by the [`BiContiguous`] type invariant, so this
    /// overrides the [`Ipv6Network::is_bicontiguous`] check with a constant
    /// result.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{BiContiguous, Ipv6Network};
    ///
    /// let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap();
    /// assert!(net.is_bicontiguous());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_bicontiguous(&self) -> bool {
        true
    }

    /// Returns a bidirectional iterator over all addresses in this network.
    ///
    /// The [`BiContiguous`] type invariant guarantees the mask splits into
    /// exactly two contiguous runs, one per 64-bit half, so every host index
    /// `i` maps to its address through a 5-op closed form instead of the
    /// general [`Ipv6Network::addrs`]'s per-bit `pdep` loop:
    ///
    /// `addr(i) = base | (i & lo_mask) | ((i >> split_shift) << 64)`, where
    /// `split_shift = 64 - lo_prefix` and `lo_mask = (1 << split_shift) - 1`
    /// for the low half's prefix length `lo_prefix` -- all three precomputed
    /// once here, at construction.
    ///
    /// Because `pdep` is strictly increasing in its source, this produces the
    /// exact same sequence as the general iterator, in both directions: host
    /// index order is row-major over the (high half, low half) plane, the
    /// low half's `split_shift` host bits cycling fastest and carrying into
    /// the high half's host bits once they exhaust. This overrides
    /// [`Ipv6Network::addrs`] with a pure acceleration -- same addresses,
    /// same order, far fewer instructions per item; reach the general
    /// iterator for a possibly non-bi-contiguous network through [`Deref`],
    /// e.g. `(*net).addrs()`.
    ///
    /// The iterator implements [`DoubleEndedIterator`].
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::{BiContiguous, Ipv6Network};
    ///
    /// // Hi half /63 (1 host bit), lo half /62 (2 host bits).
    /// let net = BiContiguous::<Ipv6Network>::parse(
    ///     "2a02:6b8:c00::1234:0:0/ffff:ffff:ffff:fffe:ffff:ffff:ffff:fffc",
    /// )
    /// .unwrap();
    /// let mut addrs = net.addrs();
    ///
    /// assert_eq!(
    ///     Some(Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 0)),
    ///     addrs.next()
    /// );
    /// assert_eq!(
    ///     Some(Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 1)),
    ///     addrs.next()
    /// );
    /// assert_eq!(
    ///     Some(Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 2)),
    ///     addrs.next()
    /// );
    /// assert_eq!(
    ///     Some(Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 3)),
    ///     addrs.next()
    /// );
    ///
    /// // The lo half's 2 host bits are exhausted (0..=3); the next address
    /// // carries into the hi half's single host bit instead of continuing
    /// // numerically.
    /// assert_eq!(
    ///     Some(Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 1, 0, 0x1234, 0, 0)),
    ///     addrs.next()
    /// );
    ///
    /// assert_eq!(
    ///     Some(Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 1, 0, 0x1234, 0, 3)),
    ///     addrs.next_back()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub fn addrs(self) -> BiContiguousIpv6Addrs {
        match self {
            Self(net) => {
                let (addr, mask) = net.to_bits();
                let host_bits = (!mask).count_ones();
                let back = u128::MAX.checked_shr(128 - host_bits).unwrap_or(0);

                // The low half's prefix length `lo_prefix` fixes the split
                // point `split_shift` between the two host-index runs: the
                // low `split_shift` bits of the index address the lo half's
                // host bits directly, the rest address the hi half's,
                // shifted into position. `split_shift` is always in
                // `0..=64`, so `1u128 << split_shift` never shifts by more
                // than 64 and never overflows `u128`.
                let lo_prefix = (mask as u64).leading_ones();
                let split_shift = 64 - lo_prefix;
                let lo_mask = (1u128 << split_shift) - 1;

                BiContiguousIpv6Addrs {
                    base: addr,
                    split_shift,
                    lo_mask,
                    front: 0,
                    back,
                }
            }
        }
    }

    /// Returns the intersection of this network with another bi-contiguous
    /// network, or [`None`] if they are disjoint.
    ///
    /// This delegates to the general [`Ipv6Network::intersection`] verbatim
    /// -- the win here is TYPE-level, not speed: the class is closed under
    /// intersection (the mask-or of two class masks is itself a class mask,
    /// each half's prefix becoming the max of the two inputs' prefixes for
    /// that half), so the result never needs re-validating and is wrapped
    /// straight back into [`BiContiguous`]. Callers building
    /// rectangle-intersection pipelines stay in the typed world for free,
    /// e.g. chaining directly into [`addrs`](Self::addrs) below, instead of
    /// paying a `TryFrom` re-check per result.
    ///
    /// [`intersects`](Ipv6Network::intersects) and
    /// [`is_disjoint`](Ipv6Network::is_disjoint) are intentionally NOT
    /// overridden: reach them unchanged through [`Deref`], see the
    /// type-level docs above for why.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::{BiContiguous, Ipv6Network};
    ///
    /// // Proper 2D overlap: `a`'s hi half is narrower (nested in `b`'s), but
    /// // `b`'s lo half is narrower (nested in `a`'s) -- neither contains the
    /// // other, yet the intersection is a well-defined single rectangle.
    /// let a =
    ///     BiContiguous::<Ipv6Network>::parse("2001:db8:1:0:abcd:0:0:0/ffff:ffff:ffff:0:ffff:0:0:0")
    ///         .unwrap();
    /// let b = BiContiguous::<Ipv6Network>::parse(
    ///     "2001:db8:0:0:abcd:1234:0:0/ffff:ffff:0:0:ffff:ffff:0:0",
    /// )
    /// .unwrap();
    ///
    /// let result = a.intersection(&b).unwrap();
    /// assert_eq!(48, result.hi_prefix());
    /// assert_eq!(32, result.lo_prefix());
    ///
    /// // The typed result stays in the class, so it chains straight into
    /// // the accelerated `addrs()` iterator.
    /// assert_eq!(
    ///     Some(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0xabcd, 0x1234, 0, 0)),
    ///     result.addrs().next()
    /// );
    ///
    /// // Disjoint bi-contiguous networks intersect to `None`.
    /// let c = BiContiguous::<Ipv6Network>::parse("2001:db9::/32").unwrap();
    /// assert_eq!(None, a.intersection(&c));
    /// ```
    #[inline]
    #[must_use]
    pub const fn intersection(&self, other: &Self) -> Option<Self> {
        // NOTE: use `Option::map` when it becomes const.
        match (self, other) {
            (Self(a), Self(b)) => match a.intersection(b) {
                // The bi-contiguous class is closed under intersection: the
                // mask-or of two bi-contiguous masks is itself bi-contiguous,
                // so the result never leaves the class -- no re-validation
                // needed, unlike a normalization check.
                Some(net) => Some(Self(net)),
                None => None,
            },
        }
    }
}

impl BiContiguousIpv6Addrs {
    #[inline]
    const fn index_to_addr(&self, index: u128) -> u128 {
        self.base | (index & self.lo_mask) | ((index >> self.split_shift) << 64)
    }

    #[cold]
    #[inline(never)]
    fn enter_wraparound_sentinel(&mut self) {
        self.front = 1;
        self.back = 0;
    }
}

/// Bidirectional iterator over [`Ipv6Addr`] in a [`BiContiguous<Ipv6Network>`].
///
/// Created by [`BiContiguous::<Ipv6Network>::addrs`].
///
/// The [`BiContiguous`] type invariant guarantees the mask splits into two
/// contiguous runs, one per 64-bit half, so unlike [`Ipv6NetworkAddrs`] this
/// iterator never runs `pdep`: each step maps its host index to an address
/// through the 5-op closed form documented on
/// [`BiContiguous::<Ipv6Network>::addrs`]. Unlike
/// [`ContiguousIpv6NetworkAddrs`], the index cannot be folded into the
/// bounds and advanced as a single packed address: the two host-bit runs
/// live at different bit offsets (`0..split_shift` and `64..64+hi host
/// bits`), so
/// consecutive indices can "carry" from the low run into the high run at a
/// bit position other than the next one up. The host index is therefore
/// kept as its own cursor, mirroring [`Ipv6NetworkAddrs`]'s `base`/`front`/
/// `back` field protocol, with the per-step cost of the closed form instead
/// of `pdep`.
///
/// When the iterator is exhausted it enters a sentinel state where
/// `front > back`, so every subsequent call to [`next`](Iterator::next) or
/// [`next_back`](DoubleEndedIterator::next_back) returns [`None`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BiContiguousIpv6Addrs {
    base: u128,
    split_shift: u32,
    lo_mask: u128,
    front: u128,
    back: u128,
}

impl Iterator for BiContiguousIpv6Addrs {
    type Item = Ipv6Addr;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.front > self.back {
            return None;
        }

        let index = self.front;
        self.front = self.front.wrapping_add(1);

        // Wrap-around means front was u128::MAX — only possible for a /0
        // network. Cold/never-inline so the common case compiles to a
        // single predicted-away branch instead of an unconditional cmov
        // chain.
        if self.front == 0 {
            self.enter_wraparound_sentinel();
        }

        Some(Ipv6Addr::from_bits(self.index_to_addr(index)))
    }

    #[inline]
    fn count(self) -> usize {
        let (n, ..) = self.size_hint();
        n
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.front > self.back {
            return (0, Some(0));
        }

        let rem = self.back.wrapping_sub(self.front).wrapping_add(1);

        if rem == 0 {
            (usize::MAX, None)
        } else {
            match usize::try_from(rem) {
                Ok(n) => (n, Some(n)),
                Err(..) => (usize::MAX, None),
            }
        }
    }
}

impl DoubleEndedIterator for BiContiguousIpv6Addrs {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front > self.back {
            return None;
        }

        let addr = self.index_to_addr(self.back);

        if self.front == self.back {
            self.front = 1;
            self.back = 0;
        } else {
            self.back = self.back.wrapping_sub(1);
        }

        Some(Ipv6Addr::from_bits(addr))
    }
}

impl TryFrom<Ipv6Network> for BiContiguous<Ipv6Network> {
    type Error = BiContiguousIpNetParseError;

    /// Converts an [`Ipv6Network`] into a [`BiContiguous<Ipv6Network>`],
    /// failing if the network's mask is not bi-contiguous.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{BiContiguous, Ipv6Network};
    ///
    /// let net = Ipv6Network::parse("2a02:6b8:c00::/40").unwrap();
    /// assert!(BiContiguous::<Ipv6Network>::try_from(net).is_ok());
    ///
    /// let net =
    ///     Ipv6Network::parse("2a02:6b8:0:0:1234:5678::/ffff:ffff:0:0:f0f0:f0f0:f0f0:f0f0").unwrap();
    /// assert!(BiContiguous::<Ipv6Network>::try_from(net).is_err());
    /// ```
    #[inline]
    fn try_from(net: Ipv6Network) -> Result<Self, Self::Error> {
        if net.is_bicontiguous() {
            Ok(Self(net))
        } else {
            Err(BiContiguousIpNetParseError::NonBiContiguousNetwork)
        }
    }
}

impl From<Contiguous<Ipv6Network>> for BiContiguous<Ipv6Network> {
    /// Upgrades a [`Contiguous<Ipv6Network>`] into a
    /// [`BiContiguous<Ipv6Network>`].
    ///
    /// Infallible: every contiguous mask is bi-contiguous (`q = 0`, or `p =
    /// 64`), so this conversion never fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{BiContiguous, Contiguous, Ipv6Network};
    ///
    /// let net = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap();
    /// let net = BiContiguous::<Ipv6Network>::from(net);
    /// assert_eq!(40, net.hi_prefix());
    /// assert_eq!(0, net.lo_prefix());
    /// ```
    #[inline]
    fn from(net: Contiguous<Ipv6Network>) -> Self {
        let Contiguous(net) = net;
        Self(net)
    }
}

impl<T> Deref for BiContiguous<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            Self(net) => net,
        }
    }
}

impl<T> Display for BiContiguous<T>
where
    T: Display,
{
    #[inline]
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), core::fmt::Error> {
        match self {
            Self(net) => Display::fmt(net, fmt),
        }
    }
}

impl FromStr for BiContiguous<Ipv6Network> {
    type Err = BiContiguousIpNetParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

// Below this many elements, `bicontiguous_containment_quadratic` is faster
// than `bicontiguous_containment_probe`; at or above it, the probe path
// wins. Both produce identical results, so this only affects speed.
//
// Measured directly (median of 21 runs each, release profile) on
// never-contained fixtures with `S` distinct present shapes: for realistic
// `S` (a handful to a few dozen on real feeds, per the type docs), the probe
// path already wins at every size tested down to `N = 16`, since the
// ancestor search finds nothing to probe against most present shapes and
// degenerates close to a single linear pass. Only an adversarial `S = 64`
// (every one of the 65 possible `hi_prefix` values in play at once) pushes
// the crossover as late as `N` between 128 and 160. This value is a
// deliberate trade-off: it favors the realistic case (already solidly won by
// N = 96) over the adversarial one, where the quadratic path stays
// measurably faster (roughly 1.3x-2x) for `N` in `[96, 160)`.
const CONTAINMENT_THRESHOLD: usize = 96;

// Sort key that orders `BiContiguous<Ipv6Network>` values ascending by
// `(mask, address)` as 128-bit numbers. A bi-contiguous mask's numeric value
// is itself monotonic in its `(hi_prefix, lo_prefix)` shape: widening either
// half's prefix always increases the mask, and the high half dominates the
// magnitude, so two masks compare the same way their `(hi_prefix,
// lo_prefix)` pairs compare lexicographically. Sorting by this key therefore
// also sorts networks by shape, without ever computing `hi_prefix` or
// `lo_prefix`.
#[inline]
fn bicontiguous_sort_key(net: &BiContiguous<Ipv6Network>) -> (u128, u128) {
    let (addr, mask) = net.to_bits();
    (mask, addr)
}

// Returns the top `prefix` bits of a 64-bit half set to one, the rest zero.
// Legal for every `prefix` in `0..=64`, including the boundary values a
// plain `!0u64 << (64 - prefix)` cannot express (shifting a `u64` by 64 wraps
// on some targets and panics with overflow checks on).
#[inline]
const fn bicontiguous_half_prefix_mask(prefix: u8) -> u64 {
    let shifted = match u64::MAX.checked_shr(prefix as u32) {
        Some(shifted) => shifted,
        None => 0,
    };
    !shifted
}

// Returns the full 128-bit mask for a bi-contiguous shape `(hi_prefix,
// lo_prefix)`.
#[inline]
const fn bicontiguous_shape_mask(hi_prefix: u8, lo_prefix: u8) -> u128 {
    ((bicontiguous_half_prefix_mask(hi_prefix) as u128) << 64) | bicontiguous_half_prefix_mask(lo_prefix) as u128
}

// Small-N baseline for `ipv6_bicontiguous_find_containment`: for each
// network, scans the whole slice for some other, strictly coarser network
// that contains it. `O(N^2)`, but with a much smaller constant factor per
// pair than the probe path below (no shape bitmap or binary search setup),
// which wins out for small inputs.
//
// `nets` must already be sorted ascending by `bicontiguous_sort_key`, so
// that an already-kept earlier copy of a duplicate always sits at
// `nets[kept_len - 1]`. The containment scan itself is order-independent: it
// tests the current multiset of values, and a swap only ever exchanges two
// values, never drops one, so it stays correct regardless of which values
// have already been moved into the kept prefix.
fn bicontiguous_containment_quadratic(nets: &mut [BiContiguous<Ipv6Network>]) -> usize {
    let mut kept_len = 0usize;

    for index in 0..nets.len() {
        let candidate = nets[index];
        let is_duplicate = kept_len > 0 && nets[kept_len - 1] == candidate;

        // A network with the same mask as `candidate` can only be an exact
        // duplicate (already handled above) or a disjoint sibling, never a
        // strict container, so distinct masks are required here.
        let is_contained = !is_duplicate
            && nets
                .iter()
                .any(|other| other.mask() != candidate.mask() && other.contains(&candidate));

        if !is_duplicate && !is_contained {
            nets.swap(kept_len, index);
            kept_len += 1;
        }
    }

    kept_len
}

// Large-N path for `ipv6_bicontiguous_find_containment`.
//
// A network's ancestors are not necessarily adjacent to it in sort order: a
// third, unrelated shape can sit between a container and the network it
// contains (see the fixed test
// `bicontiguous_ipv6_find_containment_non_adjacent_ancestor`), so this
// probes, for each network, every OTHER present `(hi_prefix, lo_prefix)`
// shape that could contain it, via binary search restricted to the run of
// already-classified, already-kept networks sharing that ancestor shape --
// rather than scanning neighbors.
//
// `nets` must already be sorted ascending by `bicontiguous_sort_key`.
//
// Runs in `O(N * S * log N)`, where `S` is the number of distinct shapes
// actually probed per network (bounded by the number of present shapes that
// dominate it, typically far below the full `65 * 65` grid on real data).
// Alloc-free: two fixed-size stack bitmaps track which shapes are present,
// and one `u64` bitmask per chunk of up to 64 networks tracks which of them
// have been dropped so far.
fn bicontiguous_containment_probe(nets: &mut [BiContiguous<Ipv6Network>]) -> usize {
    let len = nets.len();

    // Bit `lo_prefix` of `lo_prefixes_by_hi_prefix[hi_prefix]` is set iff a
    // network with that exact `(hi_prefix, lo_prefix)` shape is present in
    // the input; bit `hi_prefix` of `hi_prefixes_present` is set iff that
    // row is nonempty. Built in one `O(N)` pass, before any network is
    // dropped.
    let mut lo_prefixes_by_hi_prefix = [0u128; 65];
    let mut hi_prefixes_present = 0u128;
    for net in nets.iter() {
        let hi_prefix = net.hi_prefix();
        let lo_prefix = net.lo_prefix();
        lo_prefixes_by_hi_prefix[hi_prefix as usize] |= 1u128 << lo_prefix;
        hi_prefixes_present |= 1u128 << hi_prefix;
    }

    let mut kept_len = 0usize;
    let mut chunk_start = 0usize;

    while chunk_start < len {
        let (.., chunk_mask) = nets[chunk_start].to_bits();
        let chunk_hi_prefix = nets[chunk_start].hi_prefix();
        let chunk_lo_prefix = nets[chunk_start].lo_prefix();

        // A chunk is at most 64 consecutive elements sharing this exact
        // mask (one run of identically-shaped networks). `dropped` below
        // needs one bit per chunk element, so a run of more than 64
        // networks is split across several chunks.
        let mut chunk_end = chunk_start + 1;
        while chunk_end < len && chunk_end - chunk_start < 64 {
            let (.., next_mask) = nets[chunk_end].to_bits();
            if next_mask != chunk_mask {
                break;
            }
            chunk_end += 1;
        }

        let chunk_len = chunk_end - chunk_start;
        let all_dropped = if chunk_len == 64 {
            u64::MAX
        } else {
            (1u64 << chunk_len) - 1
        };
        let mut dropped = 0u64;

        // Duplicate check: the chunk's first element can only twin with the
        // last element kept so far -- the tail of the previous chunk, when a
        // run of more than 64 identical networks was split across a chunk
        // boundary. Every later element compares to its immediate
        // predecessor, which compaction has not touched yet at this point.
        for index in chunk_start..chunk_end {
            let is_duplicate = if index == chunk_start {
                kept_len > 0 && nets[kept_len - 1] == nets[index]
            } else {
                nets[index - 1] == nets[index]
            };
            if is_duplicate {
                dropped |= 1u64 << (index - chunk_start);
            }
        }

        if dropped != all_dropped {
            // Ancestor shapes: every present `(hi_prefix, lo_prefix)` with
            // `hi_prefix <= chunk_hi_prefix` and `lo_prefix <=
            // chunk_lo_prefix`, excluding the chunk's own shape. The row at
            // the chunk's own `hi_prefix` needs `lo_prefix` strictly less
            // than `chunk_lo_prefix` (equal would be the chunk's own
            // shape); any smaller `hi_prefix` allows `lo_prefix` up to and
            // including `chunk_lo_prefix`.
            let eligible_hi_prefixes = if chunk_hi_prefix == 64 {
                hi_prefixes_present
            } else {
                hi_prefixes_present & ((1u128 << (chunk_hi_prefix + 1)) - 1)
            };

            // A strict ancestor shape's mask always sorts before the
            // chunk's own mask (widening either prefix only ever increases
            // the mask), so every ancestor's run of matching networks lies
            // within the kept prefix built so far. Ancestor shapes are
            // visited in ascending order below, so their masks are visited
            // in ascending order too, and this cursor only ever needs to
            // move forward across the whole chunk.
            let mut ancestor_search_start = 0usize;
            let mut remaining_hi_prefixes = eligible_hi_prefixes;

            while remaining_hi_prefixes != 0 && dropped != all_dropped {
                let ancestor_hi_prefix = remaining_hi_prefixes.trailing_zeros() as u8;
                remaining_hi_prefixes &= remaining_hi_prefixes - 1;

                let lo_prefixes = lo_prefixes_by_hi_prefix[ancestor_hi_prefix as usize];
                let mut eligible_lo_prefixes = if ancestor_hi_prefix == chunk_hi_prefix {
                    if chunk_lo_prefix == 0 {
                        0
                    } else {
                        lo_prefixes & ((1u128 << chunk_lo_prefix) - 1)
                    }
                } else if chunk_lo_prefix == 64 {
                    lo_prefixes
                } else {
                    lo_prefixes & ((1u128 << (chunk_lo_prefix + 1)) - 1)
                };

                while eligible_lo_prefixes != 0 && dropped != all_dropped {
                    let ancestor_lo_prefix = eligible_lo_prefixes.trailing_zeros() as u8;
                    eligible_lo_prefixes &= eligible_lo_prefixes - 1;

                    let ancestor_mask = bicontiguous_shape_mask(ancestor_hi_prefix, ancestor_lo_prefix);

                    // No ancestor shape reached here is `(64, 64)`: that
                    // would force the chunk's own shape to be `(64, 64)`
                    // too, but a shape is never its own ancestor. So
                    // `ancestor_mask` is never `u128::MAX` and `+ 1` below
                    // never overflows.
                    let run_start = ancestor_search_start
                        + nets[ancestor_search_start..kept_len]
                            .partition_point(|net| bicontiguous_sort_key(net) < (ancestor_mask, 0));
                    let run_end = run_start
                        + nets[run_start..kept_len]
                            .partition_point(|net| bicontiguous_sort_key(net) < (ancestor_mask + 1, 0));
                    ancestor_search_start = run_end;

                    if run_start == run_end {
                        continue;
                    }

                    for index in chunk_start..chunk_end {
                        let bit = 1u64 << (index - chunk_start);
                        if dropped & bit != 0 {
                            continue;
                        }
                        let (addr, ..) = nets[index].to_bits();
                        let target = addr & ancestor_mask;
                        let found = nets[run_start..run_end]
                            .binary_search_by_key(&target, |net| net.to_bits().0)
                            .is_ok();
                        if found {
                            dropped |= bit;
                        }
                    }
                }
            }
        }

        for index in chunk_start..chunk_end {
            if dropped & (1u64 << (index - chunk_start)) == 0 {
                nets.swap(kept_len, index);
                kept_len += 1;
            }
        }

        chunk_start = chunk_end;
    }

    kept_len
}

/// Partitions a slice of bi-contiguous IPv6 networks in place: drops exact
/// duplicates and networks strictly contained in another network of the
/// slice.
///
/// Returns `k`, the length of the surviving prefix. After the call:
/// - `nets[..k]` holds the distinct, maximal input values: no value is strictly
///   contained in another, and each distinct value appears exactly once, even
///   if the input repeated it. This prefix is sorted in ascending order by
///   `(mask, address)` as 128-bit numbers -- a canonical order that depends
///   only on the input's values, not on their original order or on how the
///   algorithm happened to process them.
/// - `nets[k..]` holds the dropped elements, as a multiset in unspecified
///   order.
/// - The whole slice stays a permutation of the input (elements are only ever
///   swapped, never overwritten), and the union of addresses in `nets[..k]`
///   equals the union of addresses in the original input.
///
/// This finds only PAIRWISE containment: a network is dropped when some
/// single other network in the slice already contains it. It does not find
/// containment implied by several networks jointly -- three networks can
/// combine to cover a fourth exactly, with no single one of them containing
/// it, and that fourth network survives here. Removing it too needs
/// aggregation, not this function.
///
/// # Complexity
///
/// `O(N log N)` for the initial sort, plus one of two routed passes chosen
/// by input size: below a measured element-count threshold, an `O(N^2)`
/// full-slice scan (a smaller constant factor per pair, which wins at small
/// N); at or above it, an `O(N * S * log N)` pass that probes each network
/// against every other present `(hi_prefix, lo_prefix)` mask shape that
/// could contain it (`S` = number of distinct shapes present), using binary
/// search restricted to the already-classified kept prefix. Both passes are
/// alloc-free and produce bit-for-bit identical results -- the threshold
/// only changes speed.
///
/// # Examples
///
/// ```
/// use netip::{BiContiguous, Ipv6Network, ipv6_bicontiguous_find_containment};
///
/// let mut nets = [
///     BiContiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap(),
///     // Contained in the network above: same hi half, narrower lo half.
///     BiContiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap(),
///     BiContiguous::<Ipv6Network>::parse("2001:db9::/32").unwrap(),
/// ];
///
/// let k = ipv6_bicontiguous_find_containment(&mut nets);
/// assert_eq!(2, k);
/// assert_eq!(
///     BiContiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap(),
///     nets[0]
/// );
/// assert_eq!(
///     BiContiguous::<Ipv6Network>::parse("2001:db9::/32").unwrap(),
///     nets[1]
/// );
/// ```
#[must_use]
pub fn ipv6_bicontiguous_find_containment(nets: &mut [BiContiguous<Ipv6Network>]) -> usize {
    if nets.len() <= 1 {
        return nets.len();
    }

    nets.sort_unstable_by_key(bicontiguous_sort_key);

    if nets.len() < CONTAINMENT_THRESHOLD {
        bicontiguous_containment_quadratic(nets)
    } else {
        bicontiguous_containment_probe(nets)
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;
    use crate::net::test::{arb_contiguous_ipv6_network, arb_ipv6_network};

    // The two motivating masks from the `BiContiguous` design (one hi/lo pair
    // per 64-bit half of the address) accepted via every constructor.

    #[test]
    fn test_net_ipv6_is_bicontiguous_motivating_masks() {
        assert!(
            Ipv6Network::parse("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
                .unwrap()
                .is_bicontiguous()
        );
        assert!(
            Ipv6Network::parse("2a02:6b8:c00::1234:0:0:0/ffff:ffff:ff00::ffff:0:0:0")
                .unwrap()
                .is_bicontiguous()
        );
    }

    #[test]
    fn test_bicontiguous_ipv6_network_parse_motivating_masks() {
        let net =
            BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
        assert_eq!(40, net.hi_prefix());
        assert_eq!(32, net.lo_prefix());

        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0:0/ffff:ffff:ff00::ffff:0:0:0").unwrap();
        assert_eq!(40, net.hi_prefix());
        assert_eq!(16, net.lo_prefix());
    }

    // Boundary masks: m = 0 (all zero), m = MAX (all one), m = 1 << 63 (a
    // single bit exactly at the hi/lo boundary) are all bi-contiguous.

    #[test]
    fn test_net_ipv6_is_bicontiguous_boundary_masks() {
        assert!(Ipv6Network::parse("::/::").unwrap().is_bicontiguous());
        assert!(Ipv6Network::parse("::1").unwrap().is_bicontiguous());
        assert!(Ipv6Network::new(Ipv6Addr::UNSPECIFIED, Ipv6Addr::new(0, 0, 0, 0, 0x8000, 0, 0, 0)).is_bicontiguous());
    }

    #[test]
    fn test_bicontiguous_ipv6_network_parse_boundary_masks() {
        assert!(BiContiguous::<Ipv6Network>::parse("::/::").is_ok());
        assert!(BiContiguous::<Ipv6Network>::parse("::1").is_ok());
        assert!(
            BiContiguous::<Ipv6Network>::try_from(Ipv6Network::new(
                Ipv6Addr::UNSPECIFIED,
                Ipv6Addr::new(0, 0, 0, 0, 0x8000, 0, 0, 0),
            ))
            .is_ok()
        );
    }

    // Rejected shapes: a lone bit not at bit 127/63, an interior hole inside
    // one half, and an interior hole inside the other half.

    #[test]
    fn test_net_ipv6_is_bicontiguous_rejects_non_bicontiguous_masks() {
        // `m = 1`: a single bit at the very bottom, nowhere near a run-top at
        // bit 127 or bit 63.
        assert!(!Ipv6Network::parse("::/::1").unwrap().is_bicontiguous());

        // Interior hole inside the low half.
        assert!(
            !Ipv6Network::parse("2a02:6b8:0:0:1234:5678::/ffff:ffff:0:0:f0f0:f0f0:f0f0:f0f0")
                .unwrap()
                .is_bicontiguous()
        );

        // Interior hole inside the high half.
        assert!(
            !Ipv6Network::new(
                Ipv6Addr::UNSPECIFIED,
                Ipv6Addr::new(0xf0f0, 0xf0f0, 0xf0f0, 0xf0f0, 0, 0, 0, 0)
            )
            .is_bicontiguous()
        );
    }

    #[test]
    fn test_bicontiguous_ipv6_network_parse_rejects_non_bicontiguous_masks() {
        assert_eq!(
            BiContiguousIpNetParseError::NonBiContiguousNetwork,
            BiContiguous::<Ipv6Network>::parse("::/::1").unwrap_err(),
        );
        assert_eq!(
            BiContiguousIpNetParseError::NonBiContiguousNetwork,
            BiContiguous::<Ipv6Network>::parse("2a02:6b8:0:0:1234:5678::/ffff:ffff:0:0:f0f0:f0f0:f0f0:f0f0")
                .unwrap_err(),
        );
        assert_eq!(
            Err(BiContiguousIpNetParseError::NonBiContiguousNetwork),
            BiContiguous::<Ipv6Network>::try_from(Ipv6Network::new(
                Ipv6Addr::UNSPECIFIED,
                Ipv6Addr::new(0xf0f0, 0xf0f0, 0xf0f0, 0xf0f0, 0, 0, 0, 0),
            )),
        );
    }

    #[test]
    fn bicontiguous_ipv6_network_parse_propagates_ip_net_parse_error() {
        assert_eq!(
            BiContiguousIpNetParseError::IpNetParseError(IpNetParseError::AddrParseError(
                "".parse::<Ipv6Addr>().unwrap_err()
            )),
            BiContiguous::<Ipv6Network>::parse("").unwrap_err(),
        );
    }

    #[test]
    fn bicontiguous_ipv6_network_from_contiguous() {
        let net = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap();
        let net = BiContiguous::<Ipv6Network>::from(net);
        assert_eq!(40, net.hi_prefix());
        assert_eq!(0, net.lo_prefix());
    }

    #[test]
    fn bicontiguous_ipv6_network_from_contiguous_prefix_over_64() {
        let net = Contiguous::<Ipv6Network>::parse("2001:db8::/96").unwrap();
        let net = BiContiguous::<Ipv6Network>::from(net);
        assert_eq!(64, net.hi_prefix());
        assert_eq!(32, net.lo_prefix());
    }

    #[test]
    fn bicontiguous_ipv6_network_deref() {
        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap();
        assert_eq!(Ipv6Network::parse("2a02:6b8:c00::/40").unwrap(), *net);
    }

    #[test]
    fn bicontiguous_ipv6_network_display() {
        let net =
            BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
        assert_eq!(
            "2a02:6b8:c00:0:1234:abcd::/ffff:ffff:ff00:0:ffff:ffff::",
            net.to_string()
        );
    }

    #[test]
    fn bicontiguous_ipv6_network_from_str() {
        let expected =
            BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
        let actual: BiContiguous<Ipv6Network> = "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0"
            .parse()
            .unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn bicontiguous_ipv6_network_is_bicontiguous_override_matches_inner() {
        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap();
        assert!(net.is_bicontiguous());
        assert_eq!(net.is_bicontiguous(), (*net).is_bicontiguous());
    }

    #[test]
    fn bicontiguous_ipv6_network_hi_lo_prefix_boundary_prefixes() {
        let host = BiContiguous::<Ipv6Network>::parse("::1/128").unwrap();
        let unspecified = BiContiguous::<Ipv6Network>::parse("::/0").unwrap();

        assert_eq!(64, host.hi_prefix());
        assert_eq!(64, host.lo_prefix());
        assert_eq!(0, unspecified.hi_prefix());
        assert_eq!(0, unspecified.lo_prefix());
    }

    // A bounded variant of the motivating masks: hi half /62 (2 host bits),
    // lo half /60 (4 host bits), 6 host bits (64 addresses) total -- few
    // enough to fully collect and compare.

    #[test]
    fn bicontiguous_ipv6_addrs_matches_deref_general() {
        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ffff:fffc:ffff:ffff:ffff:fff0")
            .unwrap();
        let expected: Vec<_> = (*net).addrs().collect();
        let actual: Vec<_> = net.addrs().collect();
        assert_eq!(64, actual.len());
        assert_eq!(expected, actual);
    }

    #[test]
    fn bicontiguous_ipv6_addrs_row_major_order() {
        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ffff:fffc:ffff:ffff:ffff:fff0")
            .unwrap();
        let (base, ..) = (*net).to_bits();

        // The lo half's 4 host bits cycle fastest (inner loop); the hi
        // half's 2 host bits only advance once the lo half wraps.
        let mut expected = Vec::new();
        for hi in 0u128..4 {
            for lo in 0u128..16 {
                expected.push(base | lo | (hi << 64));
            }
        }

        let actual: Vec<u128> = net.addrs().map(|addr| addr.to_bits()).collect();
        assert_eq!(expected, actual);
    }

    #[test]
    fn bicontiguous_ipv6_addrs_len_matches_host_bits() {
        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ffff:fffc:ffff:ffff:ffff:fff0")
            .unwrap();
        assert_eq!(64, net.addrs().count());
        assert_eq!((64, Some(64)), net.addrs().size_hint());
    }

    #[test]
    fn bicontiguous_ipv6_addrs_interleaved_exhausts_uniquely() {
        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ffff:fffc:ffff:ffff:ffff:fff0")
            .unwrap();
        let mut addrs = net.addrs();
        let mut seen = Vec::new();

        loop {
            match (addrs.next(), addrs.next_back()) {
                (Some(a), Some(b)) => {
                    seen.push(a);
                    seen.push(b);
                }
                (Some(a), None) => seen.push(a),
                (None, Some(b)) => seen.push(b),
                (None, None) => break,
            }
        }

        assert_eq!(64, seen.len());
        seen.sort();
        seen.dedup();
        assert_eq!(64, seen.len());
    }

    // The degenerate `p == 64` member of the class: host bits confined
    // entirely to the lo half's tail, so the network is also plain CIDR
    // contiguous. Bounded to 4 host bits so both sequences fully collect.
    #[test]
    fn bicontiguous_ipv6_addrs_pure_contiguous_p64() {
        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/124").unwrap();
        assert_eq!(64, net.hi_prefix());
        assert_eq!(60, net.lo_prefix());

        let expected: Vec<_> = (*net).addrs().collect();
        let actual: Vec<_> = net.addrs().collect();
        assert_eq!(16, actual.len());
        assert_eq!(expected, actual);
    }

    // The degenerate `q == 0` member of the class: the entire lo half (64
    // bits) is host bits, so the network is also plain CIDR contiguous, but
    // with far too many addresses (2^88) to fully collect. Only `size_hint`/
    // `count` (both O(1)) and a bounded sample from each end are checked
    // against the general iterator, mirroring how the `m = 0` case is
    // handled elsewhere instead of enumerating it.
    #[test]
    fn bicontiguous_ipv6_addrs_pure_contiguous_q0_matches_deref_sample() {
        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap();
        assert_eq!(40, net.hi_prefix());
        assert_eq!(0, net.lo_prefix());

        assert_eq!((usize::MAX, None), net.addrs().size_hint());
        assert_eq!(usize::MAX, net.addrs().count());

        let expected_first: Vec<_> = (*net).addrs().take(8).collect();
        let actual_first: Vec<_> = net.addrs().take(8).collect();
        assert_eq!(expected_first, actual_first);

        let expected_last: Vec<_> = (*net).addrs().rev().take(8).collect();
        let actual_last: Vec<_> = net.addrs().rev().take(8).collect();
        assert_eq!(expected_last, actual_last);
    }

    #[test]
    fn bicontiguous_ipv6_addrs_single_address_p_q_64() {
        let net = BiContiguous::<Ipv6Network>::parse("::1/128").unwrap();
        assert_eq!(64, net.hi_prefix());
        assert_eq!(64, net.lo_prefix());
        assert_eq!(net.addrs().next(), net.addrs().next_back());

        let mut addrs = net.addrs();
        assert_eq!(Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), addrs.next());
        assert_eq!(None, addrs.next());
        assert_eq!(None, addrs.next_back());
    }

    #[test]
    fn bicontiguous_ipv6_addrs_mask_zero_unspecified_both_ends() {
        let net = BiContiguous::<Ipv6Network>::parse("::/::").unwrap();
        let mut addrs = net.addrs();

        assert_eq!(Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), addrs.next());
        assert_eq!(
            Some(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
            )),
            addrs.next_back()
        );
        assert_eq!((usize::MAX, None), net.addrs().size_hint());
    }

    // Proper 2D overlap: `a`'s hi half (/48) is narrower than `b`'s (/32, so
    // `b`'s hi block nests `a`'s), but `a`'s lo half (/16) is broader than
    // `b`'s (/32, so `a`'s lo block nests `b`'s) -- neither network contains
    // the other, yet the intersection is still a single well-defined
    // rectangle: the narrower half from each axis.
    #[test]
    fn bicontiguous_ipv6_intersection_proper_2d_overlap() {
        let a = BiContiguous::<Ipv6Network>::parse("2001:db8:1:0:abcd:0:0:0/ffff:ffff:ffff:0:ffff:0:0:0").unwrap();
        let b = BiContiguous::<Ipv6Network>::parse("2001:db8:0:0:abcd:1234:0:0/ffff:ffff:0:0:ffff:ffff:0:0").unwrap();
        let expected =
            BiContiguous::<Ipv6Network>::parse("2001:db8:1:0:abcd:1234:0:0/ffff:ffff:ffff:0:ffff:ffff:0:0").unwrap();

        assert!(!(*a).contains(&b) && !(*b).contains(&a));

        let actual = a.intersection(&b);
        assert_eq!(Some(expected), actual);
        assert_eq!(actual.map(|net| *net), (*a).intersection(&b));
    }

    // Disjoint purely because of the hi axis: both networks share the same
    // lo half (`abcd:1234::`), but their hi halves disagree inside the
    // shared /48 mask region (`::1` vs `::2`).
    #[test]
    fn bicontiguous_ipv6_intersection_disjoint_hi_axis_only() {
        let a =
            BiContiguous::<Ipv6Network>::parse("2001:db8:1:0:abcd:1234:0:0/ffff:ffff:ffff:0:ffff:ffff:0:0").unwrap();
        let b =
            BiContiguous::<Ipv6Network>::parse("2001:db8:2:0:abcd:1234:0:0/ffff:ffff:ffff:0:ffff:ffff:0:0").unwrap();

        assert_eq!(None, a.intersection(&b));
        assert_eq!(None, (*a).intersection(&b));
    }

    // Disjoint purely because of the lo axis: both networks share the same
    // hi half (`2001:db8:1::`), but their lo halves disagree inside the
    // shared /32 mask region (`abcd:1234::` vs `abcd:5678::`).
    #[test]
    fn bicontiguous_ipv6_intersection_disjoint_lo_axis_only() {
        let a =
            BiContiguous::<Ipv6Network>::parse("2001:db8:1:0:abcd:1234:0:0/ffff:ffff:ffff:0:ffff:ffff:0:0").unwrap();
        let b =
            BiContiguous::<Ipv6Network>::parse("2001:db8:1:0:abcd:5678:0:0/ffff:ffff:ffff:0:ffff:ffff:0:0").unwrap();

        assert_eq!(None, a.intersection(&b));
        assert_eq!(None, (*a).intersection(&b));
    }

    #[test]
    fn bicontiguous_ipv6_intersection_equal_networks_is_self() {
        let a =
            BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();

        assert_eq!(Some(a), a.intersection(&a));
    }

    // Both operands are degenerate (contiguous, `q == 0`) members of the
    // class, upgraded through `From<Contiguous<Ipv6Network>>`; `b` is a CIDR
    // subset of `a`, so containment reduces intersection to `b`.
    #[test]
    fn bicontiguous_ipv6_intersection_degenerate_contiguous_members() {
        let a = BiContiguous::<Ipv6Network>::from(Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap());
        let b = BiContiguous::<Ipv6Network>::from(Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap());

        assert_eq!(Some(b), a.intersection(&b));
        assert_eq!(Some(b), b.intersection(&a));
    }

    // The two motivating masks from the `BiContiguous` design (see the type
    // docs): both have hi half /40, but `example1`'s lo half (/32) is a
    // subset of `example2`'s (/16), so the intersection is `example1`.
    #[test]
    fn bicontiguous_ipv6_intersection_motivating_masks() {
        let example1 =
            BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
        let example2 =
            BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0:0/ffff:ffff:ff00::ffff:0:0:0").unwrap();

        assert_eq!(Some(example1), example1.intersection(&example2));
        assert_eq!(Some(example1), example2.intersection(&example1));
    }

    // Builds `count` distinct, pairwise-never-contained `BiContiguous<Ipv6Network>`
    // values, all sharing the same deep `(40, 40)` shape. Fixing bit 63 of
    // both halves to `1` and encoding `index` starting at bit 30 (well above
    // the mask's bit-24 cutoff, and using enough bits that up to 128 distinct
    // indices never collide after masking) guarantees distinctness and
    // guarantees no cross-shape containment with the shallow fixtures these
    // are mixed with below -- deterministically, not just with high
    // probability.
    fn bicontiguous_ipv6_never_contained_fixture(count: usize) -> Vec<BiContiguous<Ipv6Network>> {
        let mask = bicontiguous_shape_mask(40, 40);
        (0..count)
            .map(|index| {
                let half = 0x8000000000000000u64 | ((index as u64) << 30);
                let addr = ((half as u128) << 64) | half as u128;
                BiContiguous::try_from(Ipv6Network::from_bits(addr & mask, mask)).unwrap()
            })
            .collect()
    }

    #[test]
    fn bicontiguous_ipv6_find_containment_empty() {
        let mut nets: Vec<BiContiguous<Ipv6Network>> = Vec::new();
        assert_eq!(0, ipv6_bicontiguous_find_containment(&mut nets));
    }

    #[test]
    fn bicontiguous_ipv6_find_containment_single() {
        let net = BiContiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let mut nets = [net];
        assert_eq!(1, ipv6_bicontiguous_find_containment(&mut nets));
        assert_eq!([net], nets);
    }

    #[test]
    fn bicontiguous_ipv6_find_containment_deduplicates() {
        let net = BiContiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let mut nets = [net, net, net];
        let k = ipv6_bicontiguous_find_containment(&mut nets);
        assert_eq!(1, k);
        assert_eq!(net, nets[0]);
    }

    #[test]
    fn bicontiguous_ipv6_find_containment_drops_contained() {
        let container = BiContiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let first_child = BiContiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap();
        let second_child = BiContiguous::<Ipv6Network>::parse("2001:db8:2::/48").unwrap();

        let mut nets = [first_child, container, second_child];
        let k = ipv6_bicontiguous_find_containment(&mut nets);

        assert_eq!(1, k);
        assert_eq!(container, nets[0]);
    }

    #[test]
    fn bicontiguous_ipv6_find_containment_preserves_disjoint() {
        let first = BiContiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let second = BiContiguous::<Ipv6Network>::parse("2001:db9::/32").unwrap();
        let third = BiContiguous::<Ipv6Network>::parse("2001:dba::/32").unwrap();

        let mut nets = [third, first, second];
        let k = ipv6_bicontiguous_find_containment(&mut nets);

        assert_eq!(3, k);
        // The kept prefix is sorted ascending by `(mask, address)`; all three
        // share the same mask here, so this reduces to address order.
        assert_eq!([first, second, third], nets);
    }

    #[test]
    fn bicontiguous_ipv6_find_containment_mask_zero_is_universal_container() {
        let universal = BiContiguous::try_from(Ipv6Network::from_bits(0, 0)).unwrap();
        let a = BiContiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let b = BiContiguous::<Ipv6Network>::parse("fe80::/10").unwrap();

        let mut nets = [a, universal, b];
        let k = ipv6_bicontiguous_find_containment(&mut nets);

        assert_eq!(1, k);
        assert_eq!(universal, nets[0]);
    }

    #[test]
    fn bicontiguous_ipv6_find_containment_shape_64_64_full_addresses() {
        let a = BiContiguous::<Ipv6Network>::parse("::1/128").unwrap();
        let b = BiContiguous::<Ipv6Network>::parse("::2/128").unwrap();
        let c = BiContiguous::<Ipv6Network>::parse("::3/128").unwrap();

        assert_eq!(64, a.hi_prefix());
        assert_eq!(64, a.lo_prefix());

        let mut nets = [c, a, b];
        let k = ipv6_bicontiguous_find_containment(&mut nets);

        assert_eq!(3, k);
        assert_eq!([a, b, c], nets);
    }

    #[test]
    fn bicontiguous_ipv6_find_containment_all_equal_input() {
        let net = BiContiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let mut nets = vec![net; 40];
        let k = ipv6_bicontiguous_find_containment(&mut nets);
        assert_eq!(1, k);
        assert_eq!(net, nets[0]);
    }

    // A duplicate run longer than 64 elements forces the probe path's chunk
    // splitting: the run cannot fit in a single `dropped` bitmask, so the
    // duplicate check must correctly carry across the chunk boundary via
    // `nets[kept_len - 1]`.
    #[test]
    fn bicontiguous_ipv6_find_containment_duplicate_run_longer_than_64() {
        let net = BiContiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let mut nets = vec![net; CONTAINMENT_THRESHOLD + 10];
        assert!(nets.len() > 64 && nets.len() >= CONTAINMENT_THRESHOLD);

        let k = ipv6_bicontiguous_find_containment(&mut nets);
        assert_eq!(1, k);
        assert_eq!(net, nets[0]);
    }

    #[test]
    fn bicontiguous_ipv6_find_containment_chain() {
        // `depth == 0` is `(addr = 0, mask = 0)`, the universal container;
        // each deeper level reveals one more bit of `base` on both halves,
        // nested inside the previous level.
        let base = u128::MAX;
        let mut nets: Vec<BiContiguous<Ipv6Network>> = (0u8..40)
            .map(|depth| {
                let mask = bicontiguous_shape_mask(depth, depth);
                BiContiguous::try_from(Ipv6Network::from_bits(base & mask, mask)).unwrap()
            })
            .collect();
        nets.reverse(); // Feed it in descending-depth order, not already sorted.

        let k = ipv6_bicontiguous_find_containment(&mut nets);

        assert_eq!(1, k);
        assert_eq!(BiContiguous::try_from(Ipv6Network::from_bits(0, 0)).unwrap(), nets[0]);
    }

    // Neither shape dominates the other (`(60, 4)` has a deeper hi half but
    // shallower lo half than `(4, 60)`), so no element of one shape can ever
    // contain an element of the other, regardless of address bits -- only
    // same-shape duplicates could be dropped, and this fixture has none.
    #[test]
    fn bicontiguous_ipv6_find_containment_shape_antichain_preserved() {
        let mask_a = bicontiguous_shape_mask(60, 4);
        let mask_b = bicontiguous_shape_mask(4, 60);

        let mut nets: Vec<BiContiguous<Ipv6Network>> = (0u64..10)
            .flat_map(|index| {
                let half = 0x8000000000000000u64 | (index << 30);
                let addr = ((half as u128) << 64) | half as u128;
                [
                    BiContiguous::try_from(Ipv6Network::from_bits(addr & mask_a, mask_a)).unwrap(),
                    BiContiguous::try_from(Ipv6Network::from_bits(addr & mask_b, mask_b)).unwrap(),
                ]
            })
            .collect();

        let len = nets.len();
        let k = ipv6_bicontiguous_find_containment(&mut nets);
        assert_eq!(len, k);
    }

    // The overview's T-1D-ADJ counterexample: `a` (hi /1, lo /2) strictly
    // contains `b` (hi /2, lo /4), but `c` (same shape as `b`, different lo
    // bits) sorts between them by `(mask, address)`. A scan that only checks
    // adjacent pairs in sort order would find neither `(a, c)` nor `(c, b)`
    // containing and wrongly keep `b`; probing every dominated shape (not
    // just the neighbor) is what makes this correct.
    #[test]
    fn bicontiguous_ipv6_find_containment_non_adjacent_ancestor() {
        let a = BiContiguous::<Ipv6Network>::parse("0:0:0:0:4000:0:0:0/8000:0:0:0:c000:0:0:0").unwrap();
        let b = BiContiguous::<Ipv6Network>::parse("0:0:0:0:4000:0:0:0/c000:0:0:0:f000:0:0:0").unwrap();
        let c = BiContiguous::<Ipv6Network>::parse("::/c000:0:0:0:f000:0:0:0").unwrap();

        assert_eq!((1, 2), (a.hi_prefix(), a.lo_prefix()));
        assert_eq!((2, 4), (b.hi_prefix(), b.lo_prefix()));
        assert_eq!((2, 4), (c.hi_prefix(), c.lo_prefix()));
        assert!(a.contains(&b));
        assert!(!a.contains(&c));

        let mut nets = [b, a, c];
        let k = ipv6_bicontiguous_find_containment(&mut nets);

        assert_eq!(2, k);
        assert_eq!([a, c], nets[..k]);
    }

    // Same counterexample as above, padded with a never-contained fixture up
    // to `CONTAINMENT_THRESHOLD` elements to force the probe path (the test
    // above only ever exercises the quadratic path).
    #[test]
    fn bicontiguous_ipv6_find_containment_non_adjacent_ancestor_probe_path() {
        let a = BiContiguous::<Ipv6Network>::parse("0:0:0:0:4000:0:0:0/8000:0:0:0:c000:0:0:0").unwrap();
        let b = BiContiguous::<Ipv6Network>::parse("0:0:0:0:4000:0:0:0/c000:0:0:0:f000:0:0:0").unwrap();
        let c = BiContiguous::<Ipv6Network>::parse("::/c000:0:0:0:f000:0:0:0").unwrap();

        let mut nets = vec![b, a, c];
        nets.extend(bicontiguous_ipv6_never_contained_fixture(CONTAINMENT_THRESHOLD));
        let len = nets.len();
        assert!(len >= CONTAINMENT_THRESHOLD);

        let k = ipv6_bicontiguous_find_containment(&mut nets);

        assert_eq!(len - 1, k);
        assert!(nets[..k].contains(&a));
        assert!(nets[..k].contains(&c));
        assert!(!nets[..k].contains(&b));
    }

    // Both algorithms must agree, element for element, right at the router's
    // decision boundary -- the routing threshold is a pure speed choice, so
    // this is part of the canonical contract, not just an implementation
    // detail.
    #[test]
    fn bicontiguous_ipv6_find_containment_router_boundary_agrees() {
        for &count in &[
            CONTAINMENT_THRESHOLD - 1,
            CONTAINMENT_THRESHOLD,
            CONTAINMENT_THRESHOLD + 1,
        ] {
            let mut via_quadratic = bicontiguous_ipv6_never_contained_fixture(count);
            via_quadratic.sort_unstable_by_key(bicontiguous_sort_key);
            let mut via_probe = via_quadratic.clone();

            let k_quadratic = bicontiguous_containment_quadratic(&mut via_quadratic);
            let k_probe = bicontiguous_containment_probe(&mut via_probe);

            assert_eq!(k_quadratic, k_probe, "count={count}");
            assert_eq!(via_quadratic[..k_quadratic], via_probe[..k_probe], "count={count}");

            let mut via_router = bicontiguous_ipv6_never_contained_fixture(count);
            let k_router = ipv6_bicontiguous_find_containment(&mut via_router);
            assert_eq!(k_quadratic, k_router, "count={count}");
        }
    }

    // The two motivating masks from the `BiContiguous` design (see the type
    // docs): `wider`'s lo half (/16) contains `narrower`'s (/32) since both
    // share the same hi half (/40); `disjoint` differs in the hi half
    // entirely, so despite its shape (/32, contiguous) numerically dominating
    // both, its address does not match either and it survives untouched.
    #[test]
    fn bicontiguous_ipv6_find_containment_motivating_masks() {
        let narrower =
            BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
        let wider = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0:0/ffff:ffff:ff00::ffff:0:0:0").unwrap();
        let disjoint = BiContiguous::<Ipv6Network>::parse("2a02:6b9::/32").unwrap();

        let mut nets = [narrower, wider, disjoint];
        let k = ipv6_bicontiguous_find_containment(&mut nets);

        assert_eq!(2, k);
        assert!(nets[..k].contains(&wider));
        assert!(nets[..k].contains(&disjoint));
        assert!(!nets[..k].contains(&narrower));
    }

    // Builds a bi-contiguous mask directly from independently chosen hi/lo
    // prefixes `p, q in 0..=64`, so every generated value satisfies the class
    // invariant by construction rather than by filtering/rejection.
    fn arb_bicontiguous_ipv6_network() -> impl Strategy<Value = BiContiguous<Ipv6Network>> {
        (any::<u128>(), 0u8..=64, 0u8..=64).prop_map(|(addr, hi_prefix, lo_prefix)| {
            let hi_mask = if hi_prefix == 0 {
                0u64
            } else {
                u64::MAX << (64 - hi_prefix)
            };
            let lo_mask = if lo_prefix == 0 {
                0u64
            } else {
                u64::MAX << (64 - lo_prefix)
            };
            let mask = ((hi_mask as u128) << 64) | (lo_mask as u128);

            BiContiguous(Ipv6Network::from_bits(addr, mask))
        })
    }

    // Independent oracle for `Ipv6Network::is_bicontiguous`'s 5-op run-top
    // formula: checks each 64-bit half for a contiguous run of leading ones
    // using the same trick `Ipv6Network::is_contiguous` uses on the full 128
    // bits, applied separately per half.
    fn reference_is_bicontiguous(mask: u128) -> bool {
        fn is_contiguous_u64(mask: u64) -> bool {
            mask | mask.wrapping_sub(1) == u64::MAX
        }

        is_contiguous_u64((mask >> 64) as u64) && is_contiguous_u64(mask as u64)
    }

    // Same construction as `arb_bicontiguous_ipv6_network`, but each half's
    // prefix is drawn from its top 6 host bits only, so total host bits stay
    // at most 12 (4096 addresses) and `addrs()` can be fully
    // collected/brute-forced in a proptest case.
    fn arb_small_bicontiguous_ipv6_network() -> impl Strategy<Value = BiContiguous<Ipv6Network>> {
        (any::<u128>(), 58u8..=64, 58u8..=64).prop_map(|(addr, hi_prefix, lo_prefix)| {
            let hi_mask = u64::MAX << (64 - hi_prefix);
            let lo_mask = u64::MAX << (64 - lo_prefix);
            let mask = ((hi_mask as u128) << 64) | (lo_mask as u128);

            BiContiguous(Ipv6Network::from_bits(addr, mask))
        })
    }

    proptest! {
        #[test]
        fn prop_ipv6_is_bicontiguous_matches_reference(net in arb_ipv6_network()) {
            let (.., mask) = net.to_bits();
            prop_assert_eq!(net.is_bicontiguous(), reference_is_bicontiguous(mask));
        }

        #[test]
        fn prop_bicontiguous_ipv6_tryfrom_matches_is_bicontiguous(net in arb_ipv6_network()) {
            prop_assert_eq!(BiContiguous::<Ipv6Network>::try_from(net).is_ok(), net.is_bicontiguous());
        }

        #[test]
        fn prop_bicontiguous_ipv6_is_bicontiguous_always_true(net in arb_bicontiguous_ipv6_network()) {
            prop_assert!(net.is_bicontiguous());
            prop_assert_eq!(net.is_bicontiguous(), (*net).is_bicontiguous());
        }

        #[test]
        fn prop_bicontiguous_ipv6_addr_is_normalized(net in arb_bicontiguous_ipv6_network()) {
            let (addr, mask) = (*net).to_bits();
            prop_assert_eq!(addr & mask, addr);
        }

        #[test]
        fn prop_bicontiguous_ipv6_hi_lo_prefix_matches_brute_force(net in arb_bicontiguous_ipv6_network()) {
            let (.., mask) = (*net).to_bits();
            let expected_hi = ((mask >> 64) as u64).leading_ones() as u8;
            let expected_lo = (mask as u64).leading_ones() as u8;

            prop_assert_eq!(net.hi_prefix(), expected_hi);
            prop_assert_eq!(net.lo_prefix(), expected_lo);
        }

        #[test]
        fn prop_bicontiguous_ipv6_tryfrom_roundtrip(net in arb_bicontiguous_ipv6_network()) {
            prop_assert_eq!(BiContiguous::<Ipv6Network>::try_from(*net), Ok(net));
        }

        #[test]
        fn prop_bicontiguous_ipv6_parse_display_roundtrip(net in arb_bicontiguous_ipv6_network()) {
            let formatted = net.to_string();
            prop_assert_eq!(BiContiguous::<Ipv6Network>::parse(&formatted), Ok(net));
        }

        #[test]
        fn prop_bicontiguous_ipv6_from_contiguous_preserves_value(net in arb_contiguous_ipv6_network()) {
            let converted = BiContiguous::<Ipv6Network>::from(net);
            prop_assert_eq!(*converted, *net);
        }
    }

    proptest! {
        // The load-bearing guard for the intersection closure property:
        // whenever the typed intersection is `Some`, its inner value equals
        // the general `Ipv6Network::intersection` result exactly, and that
        // result mask is itself always bi-contiguous (the class is closed
        // under intersection) -- i.e. the result never needs the
        // re-validation the override skips.
        #[test]
        fn prop_bicontiguous_ipv6_intersection_closure_matches_general(
            a in arb_bicontiguous_ipv6_network(),
            b in arb_bicontiguous_ipv6_network(),
        ) {
            let expected = (*a).intersection(&b);
            let actual = a.intersection(&b);

            prop_assert_eq!(actual.map(|net| *net), expected);

            if let Some(net) = expected {
                prop_assert!(net.is_bicontiguous());
            }
        }

        #[test]
        fn prop_bicontiguous_ipv6_intersection_commutativity(
            a in arb_bicontiguous_ipv6_network(),
            b in arb_bicontiguous_ipv6_network(),
        ) {
            prop_assert_eq!(a.intersection(&b), b.intersection(&a));
        }

        #[test]
        fn prop_bicontiguous_ipv6_intersection_subset_of_both(
            a in arb_bicontiguous_ipv6_network(),
            b in arb_bicontiguous_ipv6_network(),
        ) {
            if let Some(c) = a.intersection(&b) {
                prop_assert!(a.contains(&c));
                prop_assert!(b.contains(&c));
            }
        }

        #[test]
        fn prop_bicontiguous_ipv6_self_intersection_is_self(a in arb_bicontiguous_ipv6_network()) {
            prop_assert_eq!(a.intersection(&a), Some(a));
        }

        #[test]
        fn prop_bicontiguous_ipv6_intersection_is_normalized(
            a in arb_bicontiguous_ipv6_network(),
            b in arb_bicontiguous_ipv6_network(),
        ) {
            if let Some(c) = a.intersection(&b) {
                let (addr, mask) = (*c).to_bits();
                prop_assert_eq!(addr & mask, addr);
            }
        }

        // Brute-force oracle: collects every address of `a` and `b` (bounded
        // to at most 4096 each by `arb_small_bicontiguous_ipv6_network`) and
        // checks the typed intersection's address set against the plain
        // set intersection, or -- when disjoint -- that the address sets
        // truly share nothing.
        #[test]
        fn prop_bicontiguous_ipv6_intersection_membership_brute_force(
            a in arb_small_bicontiguous_ipv6_network(),
            b in arb_small_bicontiguous_ipv6_network(),
        ) {
            use std::collections::HashSet;

            let a_addrs: HashSet<_> = a.addrs().collect();
            let b_addrs: HashSet<_> = b.addrs().collect();

            match a.intersection(&b) {
                Some(net) => {
                    let actual: HashSet<_> = net.addrs().collect();
                    let expected: HashSet<_> = a_addrs.intersection(&b_addrs).copied().collect();
                    prop_assert_eq!(actual, expected);
                }
                None => prop_assert!(a_addrs.is_disjoint(&b_addrs)),
            }
        }
    }

    proptest! {
        #[test]
        fn prop_bicontiguous_ipv6_addrs_matches_general_forward(net in arb_small_bicontiguous_ipv6_network()) {
            let expected: Vec<_> = (*net).addrs().collect();
            let actual: Vec<_> = net.addrs().collect();
            prop_assert_eq!(expected, actual);
        }

        #[test]
        fn prop_bicontiguous_ipv6_addrs_matches_general_reverse(net in arb_small_bicontiguous_ipv6_network()) {
            let expected: Vec<_> = (*net).addrs().rev().collect();
            let actual: Vec<_> = net.addrs().rev().collect();
            prop_assert_eq!(expected, actual);
        }

        #[test]
        fn prop_bicontiguous_ipv6_addrs_interleaved_matches_general_oracle(
            net in arb_small_bicontiguous_ipv6_network(),
            pattern in proptest::collection::vec(any::<bool>(), 0..80),
        ) {
            use std::collections::VecDeque;

            let mut expected: VecDeque<_> = (*net).addrs().collect();
            let actual = net.addrs();

            prop_assert_eq!(actual.size_hint(), (*net).addrs().size_hint());
            prop_assert_eq!(actual.count(), expected.len());

            let mut actual = net.addrs();
            for pop_front in pattern {
                let expected_item = if pop_front { expected.pop_front() } else { expected.pop_back() };
                let actual_item = if pop_front { actual.next() } else { actual.next_back() };
                prop_assert_eq!(actual_item, expected_item, "pop_front={}", pop_front);

                let (len, upper) = actual.size_hint();
                prop_assert_eq!(len, expected.len());
                prop_assert_eq!(upper, Some(expected.len()));
            }
        }

        #[test]
        fn prop_bicontiguous_ipv6_addrs_double_reverse_is_identity(net in arb_small_bicontiguous_ipv6_network()) {
            let forward: Vec<_> = net.addrs().collect();
            let mut double_reversed: Vec<_> = net.addrs().rev().collect();
            double_reversed.reverse();
            prop_assert_eq!(forward, double_reversed);
        }

        #[test]
        fn prop_bicontiguous_ipv6_addrs_every_item_matches_mask(net in arb_small_bicontiguous_ipv6_network()) {
            let (net_addr, mask) = (*net).to_bits();
            for addr in net.addrs() {
                prop_assert_eq!(addr.to_bits() & mask, net_addr);
            }
        }

        #[test]
        fn prop_bicontiguous_ipv6_addrs_len_matches_host_bits(net in arb_small_bicontiguous_ipv6_network()) {
            let (.., mask) = (*net).to_bits();
            let expected_len = 1usize << (!mask).count_ones();
            prop_assert_eq!(net.addrs().count(), expected_len);
        }

        // Independent oracle: reconstructs the address grid from the two
        // axes directly (hi host index x lo host index), bypassing both the
        // closed-form override and the general `pdep` path, then checks set
        // equality (order is checked separately by the `_matches_general_*`
        // tests above).
        #[test]
        fn prop_bicontiguous_ipv6_addrs_matches_brute_force_grid(net in arb_small_bicontiguous_ipv6_network()) {
            let (net_addr, mask) = (*net).to_bits();
            let hi_host_bits = (!(mask >> 64) as u64).count_ones();
            let lo_host_bits = (!mask as u64).count_ones();

            let mut expected: Vec<u128> = (0u64..(1u64 << hi_host_bits))
                .flat_map(|hi| (0u64..(1u64 << lo_host_bits)).map(move |lo| ((hi as u128) << 64) | lo as u128))
                .map(|host| net_addr | host)
                .collect();
            let mut actual: Vec<u128> = net.addrs().map(|a| a.to_bits()).collect();
            expected.sort_unstable();
            expected.dedup();
            actual.sort_unstable();
            actual.dedup();

            prop_assert_eq!(expected, actual);
        }
    }

    // Independent brute-force oracle for `ipv6_bicontiguous_find_containment`:
    // dedupes by value, then keeps a value only if no OTHER distinct-mask
    // value in the deduped set contains it. Shares only `.contains()`/`.mask()`
    // with the real implementation, none of its sort/chunk/probe machinery.
    fn reference_bicontiguous_containment(nets: &[BiContiguous<Ipv6Network>]) -> Vec<BiContiguous<Ipv6Network>> {
        let mut distinct: Vec<BiContiguous<Ipv6Network>> = Vec::new();
        for &net in nets {
            if !distinct.contains(&net) {
                distinct.push(net);
            }
        }

        let mut maximal: Vec<BiContiguous<Ipv6Network>> = distinct
            .iter()
            .copied()
            .filter(|&candidate| {
                !distinct
                    .iter()
                    .any(|other| other.mask() != candidate.mask() && other.contains(&candidate))
            })
            .collect();

        maximal.sort_unstable_by_key(bicontiguous_sort_key);
        maximal
    }

    // Runs both the direct quadratic/probe paths and the public router on
    // `nets`, and checks every facet of the contract against each other and
    // against the independent oracle above:
    // - the two direct paths agree on the exact kept-prefix sequence and on the
    //   dropped multiset (differential test);
    // - the kept prefix is sorted by `bicontiguous_sort_key` (canonical order);
    // - the kept prefix matches the brute-force oracle exactly (correctness);
    // - the whole output is a permutation of the input (nothing added or lost);
    // - the public router agrees with the direct quadratic path regardless of which
    //   internal path it actually took.
    fn assert_bicontiguous_containment_matches_oracle(nets: Vec<BiContiguous<Ipv6Network>>) {
        let expected = reference_bicontiguous_containment(&nets);

        let mut via_quadratic = nets.clone();
        via_quadratic.sort_unstable_by_key(bicontiguous_sort_key);
        let mut via_probe = via_quadratic.clone();

        let k_quadratic = bicontiguous_containment_quadratic(&mut via_quadratic);
        let k_probe = bicontiguous_containment_probe(&mut via_probe);

        assert_eq!(
            k_quadratic, k_probe,
            "quadratic/probe kept-length mismatch for {nets:?}"
        );
        assert_eq!(
            via_quadratic[..k_quadratic],
            via_probe[..k_probe],
            "quadratic/probe kept-prefix mismatch for {nets:?}"
        );

        let mut quadratic_tail = via_quadratic[k_quadratic..].to_vec();
        let mut probe_tail = via_probe[k_probe..].to_vec();
        quadratic_tail.sort_unstable_by_key(bicontiguous_sort_key);
        probe_tail.sort_unstable_by_key(bicontiguous_sort_key);
        assert_eq!(
            quadratic_tail, probe_tail,
            "dropped multiset mismatch between paths for {nets:?}"
        );

        assert!(
            via_quadratic[..k_quadratic].is_sorted_by_key(bicontiguous_sort_key),
            "kept prefix is not canonically sorted for {nets:?}"
        );
        assert_eq!(
            expected,
            via_quadratic[..k_quadratic],
            "result does not match the brute-force oracle for {nets:?}"
        );

        let mut input_sorted = nets.clone();
        input_sorted.sort_unstable_by_key(bicontiguous_sort_key);
        let mut output_sorted = via_quadratic.clone();
        output_sorted.sort_unstable_by_key(bicontiguous_sort_key);
        assert_eq!(
            input_sorted, output_sorted,
            "output is not a permutation of the input for {nets:?}"
        );

        let mut via_router = nets;
        let k_router = ipv6_bicontiguous_find_containment(&mut via_router);
        assert_eq!(k_quadratic, k_router, "router disagrees with the direct quadratic path");
        assert_eq!(
            via_quadratic[..k_quadratic],
            via_router[..k_router],
            "router kept-prefix mismatch"
        );
    }

    fn arb_bicontiguous_ipv6_networks() -> impl Strategy<Value = Vec<BiContiguous<Ipv6Network>>> {
        (1usize..=40).prop_flat_map(|len| prop::collection::vec(arb_bicontiguous_ipv6_network(), len))
    }

    // A small pool of distinct networks, resampled with replacement well past
    // 64 elements, so a single value's run of duplicates can span more than
    // one probe-path chunk.
    fn arb_bicontiguous_ipv6_networks_duplicate_heavy() -> impl Strategy<Value = Vec<BiContiguous<Ipv6Network>>> {
        (2usize..=6, 1usize..=150).prop_flat_map(|(pool_size, len)| {
            prop::collection::vec(arb_bicontiguous_ipv6_network(), pool_size).prop_flat_map(move |pool| {
                prop::collection::vec(0..pool_size, len)
                    .prop_map(move |picks| picks.iter().map(|&index| pool[index]).collect())
            })
        })
    }

    // A strict nesting chain: level 0 is `(addr = 0, mask = 0)`, the
    // universal container; each deeper level reveals one more bit of `base`
    // on both halves, so level `i` always contains every level `> i`.
    fn arb_bicontiguous_ipv6_nesting_chain() -> impl Strategy<Value = Vec<BiContiguous<Ipv6Network>>> {
        (any::<u128>(), 2u8..=40).prop_map(|(base, chain_len)| {
            (0..chain_len)
                .map(|depth| {
                    let mask = bicontiguous_shape_mask(depth, depth);
                    BiContiguous::try_from(Ipv6Network::from_bits(base & mask, mask)).unwrap()
                })
                .collect()
        })
    }

    // Shapes `(60, 4)` and `(4, 60)`: neither dominates the other (one has a
    // deeper hi half, the other a deeper lo half), so no element of one shape
    // can ever contain an element of the other -- the only possible drops in
    // this fixture are exact duplicates.
    fn arb_bicontiguous_ipv6_shape_antichain_networks() -> impl Strategy<Value = Vec<BiContiguous<Ipv6Network>>> {
        prop::collection::vec((any::<u128>(), any::<bool>()), 1..=30).prop_map(|picks| {
            picks
                .into_iter()
                .map(|(addr, use_first_shape)| {
                    let mask = if use_first_shape {
                        bicontiguous_shape_mask(60, 4)
                    } else {
                        bicontiguous_shape_mask(4, 60)
                    };
                    BiContiguous::try_from(Ipv6Network::from_bits(addr & mask, mask)).unwrap()
                })
                .collect()
        })
    }

    // Mirrors the maintainer's real-world shapes: hi half /40 (a "site"), lo
    // half either /32 or /16 (shared across a small pool of sites, so
    // same-site networks of different shapes can legitimately contain each
    // other, unlike the antichain fixture above).
    fn arb_bicontiguous_ipv6_geo_networks() -> impl Strategy<Value = Vec<BiContiguous<Ipv6Network>>> {
        prop::collection::vec(any::<u64>(), 1..=4).prop_flat_map(|sites| {
            let sites_len = sites.len();
            prop::collection::vec((0..sites_len, any::<u64>(), any::<bool>()), 1..=40).prop_map(move |picks| {
                picks
                    .into_iter()
                    .map(|(site_index, lo, use_narrow_lo)| {
                        let hi = sites[site_index];
                        let lo_prefix = if use_narrow_lo { 32 } else { 16 };
                        let mask = bicontiguous_shape_mask(40, lo_prefix);
                        let addr = ((hi as u128) << 64) | lo as u128;
                        BiContiguous::try_from(Ipv6Network::from_bits(addr & mask, mask)).unwrap()
                    })
                    .collect()
            })
        })
    }

    proptest! {
        #[test]
        fn prop_bicontiguous_ipv6_find_containment_matches_oracle_random(nets in arb_bicontiguous_ipv6_networks()) {
            assert_bicontiguous_containment_matches_oracle(nets);
        }

        #[test]
        fn prop_bicontiguous_ipv6_find_containment_matches_oracle_duplicate_heavy(
            nets in arb_bicontiguous_ipv6_networks_duplicate_heavy()
        ) {
            assert_bicontiguous_containment_matches_oracle(nets);
        }

        #[test]
        fn prop_bicontiguous_ipv6_find_containment_matches_oracle_nesting_chain(
            nets in arb_bicontiguous_ipv6_nesting_chain()
        ) {
            assert_bicontiguous_containment_matches_oracle(nets);
        }

        #[test]
        fn prop_bicontiguous_ipv6_find_containment_matches_oracle_shape_antichain(
            nets in arb_bicontiguous_ipv6_shape_antichain_networks()
        ) {
            assert_bicontiguous_containment_matches_oracle(nets);
        }

        #[test]
        fn prop_bicontiguous_ipv6_find_containment_matches_oracle_geo(nets in arb_bicontiguous_ipv6_geo_networks()) {
            assert_bicontiguous_containment_matches_oracle(nets);
        }

        // Running the function again on its own output must be a no-op: the
        // result is already maximal and duplicate-free.
        #[test]
        fn prop_bicontiguous_ipv6_find_containment_idempotent(nets in arb_bicontiguous_ipv6_networks()) {
            let mut once = nets;
            let k_once = ipv6_bicontiguous_find_containment(&mut once);
            let mut twice = once[..k_once].to_vec();
            let k_twice = ipv6_bicontiguous_find_containment(&mut twice);

            prop_assert_eq!(k_once, k_twice);
            prop_assert_eq!(&once[..k_once], &twice[..k_twice]);
        }

        // The result order does not depend on the input order: feeding the
        // same multiset in reverse produces the same kept prefix.
        #[test]
        fn prop_bicontiguous_ipv6_find_containment_independent_of_input_order(
            nets in arb_bicontiguous_ipv6_networks()
        ) {
            let mut forward = nets.clone();
            let mut backward = nets;
            backward.reverse();

            let k_forward = ipv6_bicontiguous_find_containment(&mut forward);
            let k_backward = ipv6_bicontiguous_find_containment(&mut backward);

            prop_assert_eq!(k_forward, k_backward);
            prop_assert_eq!(&forward[..k_forward], &backward[..k_backward]);
        }

        // Direct correctness check independent of the oracle helper above:
        // no element of the kept prefix strictly contains another.
        #[test]
        fn prop_bicontiguous_ipv6_find_containment_result_has_no_containment(
            nets in arb_bicontiguous_ipv6_networks()
        ) {
            let mut nets = nets;
            let k = ipv6_bicontiguous_find_containment(&mut nets);

            for i in 0..k {
                for j in 0..k {
                    if i != j {
                        prop_assert!(!(nets[i].mask() != nets[j].mask() && nets[i].contains(&nets[j])));
                    }
                }
            }
        }

        // Brute-force membership on a bounded address space: the union of
        // addresses covered by the kept prefix equals the union covered by
        // the original input.
        #[test]
        fn prop_bicontiguous_ipv6_find_containment_preserves_addresses(
            nets in prop::collection::vec(arb_small_bicontiguous_ipv6_network(), 1..=6)
        ) {
            use std::collections::HashSet;

            let mut before: HashSet<_> = HashSet::new();
            for net in &nets {
                before.extend(net.addrs());
            }

            let mut nets = nets;
            let k = ipv6_bicontiguous_find_containment(&mut nets);

            let mut after: HashSet<_> = HashSet::new();
            for net in &nets[..k] {
                after.extend(net.addrs());
            }

            prop_assert_eq!(before, after);
        }
    }
}
