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
/// Each specialized method is either strictly faster than the inherited one,
/// or returns a typed result because the class is closed under the operation.
/// See each method's "Why overridden?" note for which and why.
///
/// Some methods are deliberately NOT specialized and are left to [`Deref`]:
/// - [`Ipv6Network::merge`] -- the class is not closed under it: an equal-mask
///   single-bit merge stays in-class only when it clears the bottom bit of a
///   run, whereas an interior bit punches a hole, so merging returns a plain
///   [`Ipv6Network`].
/// - [`Ipv6Network::intersects`] / [`Ipv6Network::is_disjoint`] -- the general
///   check already tests both halves in one pass, so a per-half version would
///   cost more.
/// - No single-prefix accessor equivalent to
///   [`Contiguous<Ipv6Network>::prefix`] -- a bi-contiguous mask generally
///   isn't one prefix length. Use [`hi_prefix`](Self::hi_prefix) /
///   [`lo_prefix`](Self::lo_prefix) instead.
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
    /// Always returns `true`.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{BiContiguous, Ipv6Network};
    ///
    /// let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap();
    /// assert!(net.is_bicontiguous());
    /// ```
    ///
    /// # Why overridden?
    ///
    /// Every value of this type carries the bi-contiguity invariant, so the
    /// answer is a constant `true`, with no need to inspect the mask.
    #[inline]
    #[must_use]
    pub const fn is_bicontiguous(&self) -> bool {
        true
    }

    /// Checks whether this network's mask is contiguous, i.e. a single run of
    /// leading one bits (a plain CIDR mask).
    ///
    /// A bi-contiguous mask `concat(1^p 0^(64-p), 1^q 0^(64-q))` collapses to
    /// one contiguous run exactly when its two halves abut with no interior
    /// zero between them: either the low half is empty (`q = 0`, so the low
    /// 64-bit word `lo` of the mask is `0`) or the high half is full (`p =
    /// 64`, so the high 64-bit word `hi` is `u64::MAX`). If instead `p < 64`
    /// and `q > 0`, a zero sits between the two runs and the mask is
    /// bi-contiguous but not contiguous.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{BiContiguous, Ipv6Network};
    ///
    /// // `p = 40 < 64` and `q = 32 > 0`: an interior gap sits between the two
    /// // runs, so the mask is bi-contiguous but not contiguous.
    /// let net = BiContiguous::<Ipv6Network>::parse(
    ///     "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
    /// )
    /// .unwrap();
    /// assert!(!net.is_contiguous());
    ///
    /// // `q = 0`: the low half is empty, so the lone high run is a plain CIDR
    /// // mask.
    /// let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap();
    /// assert!(net.is_contiguous());
    ///
    /// // `p = 64`: the high half is all ones, so the two runs abut and the
    /// // mask is contiguous.
    /// let net = BiContiguous::<Ipv6Network>::parse("2001:db8::/96").unwrap();
    /// assert!(net.is_contiguous());
    /// ```
    ///
    /// # Why overridden?
    ///
    /// This overrides the general [`Ipv6Network::is_contiguous`], whose
    /// whole-mask `mask | (mask - 1) == u128::MAX` test spans a 128-bit
    /// borrow-subtract across both halves, with the cheaper per-half check
    /// `lo == 0 || hi == u64::MAX`.
    #[inline]
    #[must_use]
    pub const fn is_contiguous(&self) -> bool {
        match self {
            Self(net) => {
                let mask = net.mask().to_bits();
                let lo = mask as u64;
                let hi = (mask >> 64) as u64;
                lo == 0 || hi == u64::MAX
            }
        }
    }

    /// Returns a bidirectional iterator over all addresses in this network.
    ///
    /// The [`BiContiguous`] type invariant guarantees the mask splits into
    /// exactly two contiguous runs, one per 64-bit half, so every host index
    /// `i` maps to its address through a 5-op closed form rather than the
    /// general [`Ipv6Network::addrs`]'s per-item stepping:
    ///
    /// `addr(i) = base | (i & lo_mask) | ((i >> split_shift) << 64)`, where
    /// `split_shift = 64 - lo_prefix` and `lo_mask = (1 << split_shift) - 1`
    /// for the low half's prefix length `lo_prefix` -- all three precomputed
    /// once here, at construction.
    ///
    /// The closed form is strictly increasing in `i`, so this produces the
    /// exact same sequence as the general iterator, in both directions: host
    /// index order is row-major over the (high half, low half) plane, the
    /// low half's `split_shift` host bits cycling fastest and carrying into
    /// the high half's host bits once they exhaust. This overrides
    /// [`Ipv6Network::addrs`] with a pure acceleration -- same addresses,
    /// same order, far fewer instructions per item.
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
    ///
    /// # Why overridden?
    ///
    /// The bi-contiguous class is closed under intersection: OR-ing two class
    /// masks yields a class mask, each half's prefix becoming the larger of
    /// the two, so the result is itself bi-contiguous and is returned as
    /// `Option<Self>` with no re-validation. This is a closure/type win, not a
    /// speed win -- the op count matches the general
    /// [`Ipv6Network::intersection`] it delegates to. Callers building
    /// rectangle-intersection pipelines stay in the typed world for free, e.g.
    /// chaining directly into [`addrs`](Self::addrs), instead of paying a
    /// `TryFrom` re-check per result.
    #[inline]
    #[must_use]
    pub const fn intersection(&self, other: &Self) -> Option<Self> {
        // NOTE: use `Option::map` when it becomes const.
        match (self, other) {
            (Self(a), Self(b)) => match a.intersection(b) {
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
/// contiguous runs, one per 64-bit half, so this iterator maps each step's
/// host index to an address through the 5-op closed form documented on
/// [`BiContiguous::<Ipv6Network>::addrs`]. Unlike
/// [`ContiguousIpv6NetworkAddrs`], the index cannot be folded into the
/// bounds and advanced as a single packed address: the two host-bit runs
/// live at different bit offsets (`0..split_shift` and `64..64+hi host
/// bits`), so consecutive indices can "carry" from the low run into the high
/// run at a bit position other than the next one up. The host index is
/// therefore kept as its own cursor, paying the closed form's per-step cost.
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

/// Aggregates bi-contiguous IPv6 networks in place into a valid, class-closed
/// cover of the same address union.
///
/// Returns the aggregated subslice. Every result is itself bi-contiguous, and
/// together they cover exactly the same address union as the input, with:
///
/// - no network contained in another,
/// - no two networks that are lowest-mask-bit siblings (an equal-mask pair
///   differing in the mask's lowest set bit), and
/// - no two networks that are high-half buddies carrying identical low-half
///   sets -- the one further class-preserving merge a bi-contiguous mask allows
///   beyond [`Ipv6Network::merge_by_lowest_mask_bit`].
///
/// Unlike [`crate::ipv6_aggregate`], every result stays bi-contiguous. Unlike
/// [`ipv6_aggregate_contiguous`](crate::ipv6_aggregate_contiguous), the cover
/// is **not** guaranteed minimal: three bi-contiguous rectangles can tile a
/// parent rectangle while no pair among them is a containment, a lo-buddy, or a
/// hi-buddy with equal lo-sets, so this greedy keeps all three where the
/// minimum cover is one. Producing the minimum cover needs a different,
/// allocating algorithm and is out of scope here.
///
/// Zero allocations -- the algorithm works entirely within the input slice,
/// using only fixed-size stack state.
///
/// # Complexity
///
/// `O(N * S * log N)` amortized, for `N` the input length and `S` the
/// number of distinct mask shapes present. All sorting totals `O(N log N)`:
/// the initial sort, plus one localized re-sort per level that re-parents
/// networks, each paid for by a distinct network the same level drops, so the
/// re-sorts cannot outweigh the drops that fund them. Suffix compaction after
/// a dropping level is a linear word-move over the higher-prefix suffix, at
/// most `O(N * W)` moves in total across the `W = 65` high-half prefix
/// lengths. The final containment sweep probes each network against the
/// present ancestor shapes in `O(N * S * log N)`. On non-adversarial inputs
/// the containment sweep dominates the total running time. On realistic
/// inputs `S` is a small constant.
///
/// # Examples
///
/// ```
/// use netip::{BiContiguous, Ipv6Network, ipv6_aggregate_bicontiguous};
///
/// let mut nets = [
///     // High-half buddies with identical (empty) low-half sets: they merge
///     // into `2001:db8::/47`.
///     BiContiguous::<Ipv6Network>::parse("2001:db8::/48").unwrap(),
///     BiContiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap(),
///     // Contained in the merged `/47` above, so it is dropped.
///     BiContiguous::<Ipv6Network>::parse("2001:db8:1:8000::/49").unwrap(),
///     // Disjoint: survives on its own.
///     BiContiguous::<Ipv6Network>::parse("2001:dead::/32").unwrap(),
/// ];
///
/// let nets = ipv6_aggregate_bicontiguous(&mut nets);
///
/// assert_eq!(2, nets.len());
/// assert_eq!(Ipv6Network::parse("2001:dead::/32").unwrap(), *nets[0]);
/// assert_eq!(Ipv6Network::parse("2001:db8::/47").unwrap(), *nets[1]);
/// ```
pub fn ipv6_aggregate_bicontiguous(nets: &mut [BiContiguous<Ipv6Network>]) -> &mut [BiContiguous<Ipv6Network>] {
    let len = bicontiguous_aggregate(nets);
    &mut nets[..len]
}

// Sort key ordering `BiContiguous<Ipv6Network>` values by high-half prefix
// length, then high address half, then low address half, then low-half prefix
// length -- the level-major order `(p, hi, lo, q)`.
//
// Ordering by `p` first groups every network of a given high-half prefix into
// one contiguous level block, and inside a block orders exact-hi runs so that
// two high-half CIDR buddies land in consecutive runs with nothing between
// them.
//
// The two half-mask words stand in for the two prefix lengths: a contiguous
// half mask's value rises monotonically with its prefix length, so ordering by
// the raw `u64` half masks is the exact same order as ordering by the prefix
// lengths, without a `leading_ones` per key.
#[inline]
fn bicontiguous_level_sort_key(net: &BiContiguous<Ipv6Network>) -> (u64, u64, u64, u64) {
    let (addr, mask) = net.to_bits();
    ((mask >> 64) as u64, (addr >> 64) as u64, addr as u64, mask as u64)
}

// Returns the high 64 bits of a network's address.
#[inline]
fn bicontiguous_hi_addr(net: &BiContiguous<Ipv6Network>) -> u64 {
    let (addr, ..) = net.to_bits();
    (addr >> 64) as u64
}

// Returns the low 64 bits of a network's address.
#[inline]
fn bicontiguous_lo_addr(net: &BiContiguous<Ipv6Network>) -> u64 {
    let (addr, ..) = net.to_bits();
    addr as u64
}

// Aggregation driver for `ipv6_aggregate_bicontiguous`: runs the level sweep,
// then the cross-shape containment sweep, over the same live slice.
fn bicontiguous_aggregate(nets: &mut [BiContiguous<Ipv6Network>]) -> usize {
    let live = bicontiguous_sweep(nets);
    bicontiguous_find_containment(&mut nets[..live])
}

// Level sweep for `bicontiguous_aggregate`: returns the number of surviving
// networks, moved to the front of `nets`.
//
// Fuses low-half aggregation and hi-buddy merging into one downward sweep over
// the high-half prefix `p` from 64 to 0. A hi-buddy merge re-parents networks
// from level `p` to `p - 1` and is the only operation that breaks the
// level-major ordering. Levels without one preserve the ordering and need no
// re-sort before the next level. A level that does re-parent only disturbs
// the order between its own native block at the new level and the survivors
// it just produced, so only that narrow range is re-sorted, never the whole
// live slice.
//
// Establishes, before returning: within every exact-(hi address, hi prefix)
// group the low-half blocks are pairwise disjoint (each group is canonicalized
// once its level runs, and nothing joins a group after that), and no two live
// networks are equal (equal networks share a group and adjacent slots, and
// `merge_by_lowest_mask_bit` absorbs them there).
// `bicontiguous_find_containment` relies on both invariants.
fn bicontiguous_sweep(nets: &mut [BiContiguous<Ipv6Network>]) -> usize {
    if nets.len() <= 1 {
        return nets.len();
    }

    let mut live = nets.len();
    nets[..live].sort_unstable_by_key(bicontiguous_level_sort_key);

    let mut p = 64u8;
    loop {
        // Level-`p` block: the run of networks whose high-half prefix is `p`.
        let block_start = nets[..live].partition_point(|net| net.hi_prefix() < p);
        let block_end = nets[..live].partition_point(|net| net.hi_prefix() <= p);

        let after_lo = bicontiguous_lo_aggregate(nets, block_start, block_end);
        let block_survivors_end = if p == 0 {
            after_lo
        } else {
            bicontiguous_hi_buddy_merge(nets, block_start, after_lo, p)
        };
        let reparented = block_survivors_end < after_lo;

        // Shift the higher-prefix suffix down over the slots the block freed.
        if block_survivors_end < block_end {
            nets.copy_within(block_end..live, block_survivors_end);
            live -= block_end - block_survivors_end;
        }

        if p == 0 {
            break;
        }
        p -= 1;

        if reparented {
            // The live slice now splits into four zones. Below `prev_start`,
            // every network has high-half prefix at most `p - 1`, already in
            // final order from earlier levels. `[prev_start, block_start)` is
            // the native level-`p` block, sorted and untouched by this
            // iteration. `[block_start, block_survivors_end)` holds this
            // level's survivors: networks re-parented down to prefix `p`
            // interleaved with keepers still at the old prefix `p + 1`,
            // sorted among themselves but not merged with the native block.
            // From `block_survivors_end` onward the suffix was just shifted
            // down by `copy_within` and keeps its prior order, with high-half
            // prefix at least `p + 2`. High-half prefix is the sort key's
            // first component, so it alone separates the first and last
            // zones from the middle two: sorting only `[prev_start,
            // block_survivors_end)` restores global order across the whole
            // slice. A network is only ever re-parented into level `p` during
            // this same iteration -- never a later one -- so the native block
            // at `p` is already complete when this sort runs.
            let prev_start = nets[..block_start].partition_point(|net| net.hi_prefix() < p);
            nets[prev_start..block_survivors_end].sort_unstable_by_key(bicontiguous_level_sort_key);
        }
    }

    live
}

// Phase A of a level: aggregates the low halves of every exact-hi run inside
// the block `[block_start, block_end)`, compacting survivors to the front of
// the block. Returns the index one past the last survivor.
//
// Within a run every network shares the same high half and high-half prefix,
// so their low blocks form a laminar CIDR family, and the top-only lowest-bit
// stack sweep -- the same kernel `ipv6_aggregate_contiguous` uses -- reduces
// each run to its canonical minimal low-half cover.
fn bicontiguous_lo_aggregate(nets: &mut [BiContiguous<Ipv6Network>], block_start: usize, block_end: usize) -> usize {
    let mut write = block_start;
    let mut run_start = block_start;

    while run_start < block_end {
        let run_hi = bicontiguous_hi_addr(&nets[run_start]);
        let mut run_end = run_start + 1;
        while run_end < block_end && bicontiguous_hi_addr(&nets[run_end]) == run_hi {
            run_end += 1;
        }

        let stack_base = write;
        let mut current: Ipv6Network = *nets[run_start];
        nets[write] = BiContiguous(current);
        write += 1;

        for read in (run_start + 1)..run_end {
            current = *nets[read];
            while write > stack_base {
                let top: Ipv6Network = *nets[write - 1];
                match top.merge_by_lowest_mask_bit(&current) {
                    Some(merged) => {
                        current = merged;
                        write -= 1;
                    }
                    None => break,
                }
            }
            // NOTE: within a run both operands share the high half and its
            // prefix, so `merge_by_lowest_mask_bit` only ever clears the low
            // half's boundary bit or returns a container -- the result stays
            // bi-contiguous and is re-wrapped without re-validation.
            nets[write] = BiContiguous(current);
            write += 1;
        }

        run_start = run_end;
    }

    write
}

// Phase B of a level: merges every high-half buddy pair whose canonical
// low-half sets are identical, inside the already lo-aggregated block
// `[block_start, block_end)`. Returns the index one past the last survivor.
// Only called with `p` in `1..=64`, where a buddy bit exists.
//
// After Phase A the block's exact-hi runs are canonical and sorted by high
// half, so two buddies occupy consecutive runs. When the lower buddy's run and
// the upper buddy's run carry element-wise equal low halves, their union is a
// single rectangle at high-half prefix `p - 1`: the lower buddy is re-parented
// in place (its address is unchanged) and the upper buddy is dropped. A
// re-parented network carries high-half prefix `p - 1` into the next level's
// re-sort.
fn bicontiguous_hi_buddy_merge(
    nets: &mut [BiContiguous<Ipv6Network>],
    block_start: usize,
    block_end: usize,
    p: u8,
) -> usize {
    let buddy_bit = 1u64 << (64 - p);
    let new_hi_mask = bicontiguous_half_prefix_mask(p - 1);

    let mut write = block_start;
    let mut i = block_start;

    while i < block_end {
        let hi_a = bicontiguous_hi_addr(&nets[i]);
        let mut a_end = i + 1;
        while a_end < block_end && bicontiguous_hi_addr(&nets[a_end]) == hi_a {
            a_end += 1;
        }

        let mut merged = false;
        if a_end < block_end && hi_a & buddy_bit == 0 {
            let hi_b = bicontiguous_hi_addr(&nets[a_end]);
            if hi_b == hi_a | buddy_bit {
                let mut b_end = a_end + 1;
                while b_end < block_end && bicontiguous_hi_addr(&nets[b_end]) == hi_b {
                    b_end += 1;
                }

                if bicontiguous_lo_lists_equal(nets, i, a_end, a_end, b_end) {
                    for x in i..a_end {
                        let (addr, mask) = nets[x].to_bits();
                        let new_mask = (mask & (u64::MAX as u128)) | ((new_hi_mask as u128) << 64);
                        // NOTE: the lower buddy already has bit `64 - p` of its
                        // address clear, so widening its high-half mask to
                        // prefix `p - 1` leaves the address normalized. The
                        // merged rectangle is bi-contiguous and is re-wrapped
                        // without re-validation.
                        nets[write] = BiContiguous(Ipv6Network::from_bits(addr, new_mask));
                        write += 1;
                    }
                    i = b_end;
                    merged = true;
                }
            }
        }

        if !merged {
            for x in i..a_end {
                nets[write] = nets[x];
                write += 1;
            }
            i = a_end;
        }
    }

    write
}

// Tests whether two exact-hi runs carry element-wise equal low halves: equal
// length, and equal low address and low-half prefix at every position. Both
// runs are canonical (sorted by low half) after Phase A, so equal low-sets
// imply equal element sequences.
fn bicontiguous_lo_lists_equal(
    nets: &[BiContiguous<Ipv6Network>],
    a_start: usize,
    a_end: usize,
    b_start: usize,
    b_end: usize,
) -> bool {
    if a_end - a_start != b_end - b_start {
        return false;
    }
    for offset in 0..(a_end - a_start) {
        let a = &nets[a_start + offset];
        let b = &nets[b_start + offset];
        if bicontiguous_lo_addr(a) != bicontiguous_lo_addr(b) || a.lo_prefix() != b.lo_prefix() {
            return false;
        }
    }
    true
}

// Sort key ordering `BiContiguous<Ipv6Network>` values ascending by `(mask,
// address)` as 128-bit numbers. A bi-contiguous mask's numeric value is itself
// monotonic in its `(hi_prefix, lo_prefix)` shape -- widening either half's
// prefix always increases the mask, and the high half dominates the magnitude
// -- so sorting by this key also sorts by shape, without ever computing
// `hi_prefix` or `lo_prefix`.
#[inline]
fn bicontiguous_sort_key(net: &BiContiguous<Ipv6Network>) -> (u128, u128) {
    let (addr, mask) = net.to_bits();
    (mask, addr)
}

// Returns the top `prefix` bits of a 64-bit half set to one, the rest zero.
// Legal for every `prefix` in `0..=64`, including the boundary values a plain
// `!0u64 << (64 - prefix)` cannot express (shifting a `u64` by 64 wraps on
// some targets and panics with overflow checks on).
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

// Cross-shape containment sweep (Phase C): drops networks strictly contained
// in another network of the slice, returning the surviving prefix length.
// `nets[..k]` ends sorted ascending by `(mask, address)`, while `nets[k..]`
// holds the dropped elements. The whole slice stays a permutation of its
// input (swaps only), so the address union is preserved.
//
// Requires input straight from `bicontiguous_sweep`: within every exact-(hi
// address, hi prefix) group the low-half blocks are pairwise disjoint, and no
// two live networks are equal. Together those rule out exact duplicates here
// and force every real container's high-half prefix to be strictly smaller
// than its containee's -- a container sharing the containee's exact group
// would violate the group's own disjointness. A hypothetical caller supplying
// raw, un-swept input would need duplicate detection and a same-hi-prefix
// ancestor row back, both of which this narrowed contract lets the scan below
// skip.
//
// Always runs the `O(N * S * log N)` probe below against the present ancestor
// shapes. A small-N quadratic scan was measured and rejected: any threshold
// that would route the adversarial many-distinct-shapes case to it also routes
// realistic large inputs through its `O(N^2)` cost, the worse regret.
fn bicontiguous_find_containment(nets: &mut [BiContiguous<Ipv6Network>]) -> usize {
    if nets.len() <= 1 {
        return nets.len();
    }

    nets.sort_unstable_by_key(bicontiguous_sort_key);
    bicontiguous_containment_probe(nets)
}

// Containment scan for `bicontiguous_find_containment`.
//
// A network's ancestors are not necessarily adjacent to it in sort order: a
// third, unrelated shape can sit between a container and the network it
// contains, so this probes, for each network, every OTHER present `(hi_prefix,
// lo_prefix)` shape that could contain it, via binary search restricted to the
// run of already-classified, already-kept networks sharing that ancestor shape
// -- rather than scanning neighbors.
//
// `nets` must already be sorted ascending by `bicontiguous_sort_key`, and, per
// the precondition on `bicontiguous_find_containment`, must come straight from
// `bicontiguous_sweep`: no two live networks are equal, and every ancestor
// probed below has a strictly smaller `hi_prefix` than the chunk it is being
// probed against.
//
// Runs in `O(N * S * log N)`, where `S` is the number of distinct shapes
// actually probed per network (bounded by the number of present shapes that
// dominate it, typically far below the full `65 * 65` grid on real data).
// Alloc-free: two fixed-size stack bitmaps track which shapes are present, and
// one `u64` bitmask per chunk of up to 64 networks tracks which of them have
// been dropped so far.
fn bicontiguous_containment_probe(nets: &mut [BiContiguous<Ipv6Network>]) -> usize {
    let len = nets.len();

    // Bit `lo_prefix` of `lo_prefixes_by_hi_prefix[hi_prefix]` is set iff a
    // network with that exact `(hi_prefix, lo_prefix)` shape is present in the
    // input. Bit `hi_prefix` of `hi_prefixes_present` is set iff that row is
    // nonempty. Built in one `O(N)` pass, before any network is dropped.
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

        // A chunk is at most 64 consecutive elements sharing this exact mask
        // (one run of identically-shaped networks). `dropped` below needs one
        // bit per chunk element, so a run of more than 64 networks is split
        // across several chunks.
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

        if dropped != all_dropped {
            // Each chunk element's address is probed once per ancestor shape,
            // so cache all of them up front and read from the cache in the
            // inner loop instead of unpacking the network again every time.
            let mut chunk_addrs = [0u128; 64];
            for (offset, slot) in chunk_addrs[..chunk_len].iter_mut().enumerate() {
                *slot = nets[chunk_start + offset].to_bits().0;
            }

            // Ancestor shapes: every present `(hi_prefix, lo_prefix)` with
            // `hi_prefix` strictly less than `chunk_hi_prefix` and `lo_prefix`
            // up to and including `chunk_lo_prefix`. No row at the chunk's own
            // `hi_prefix` is ever eligible: a container sharing the chunk's
            // exact `hi_prefix` would have to share its group, which the
            // sweep's per-group disjointness rules out.
            let eligible_hi_prefixes = hi_prefixes_present & ((1u128 << chunk_hi_prefix) - 1);

            // A strict ancestor shape's mask always sorts before the chunk's
            // own mask (widening either prefix only ever increases the mask),
            // so every ancestor's run of matching networks lies within the kept
            // prefix built so far. Ancestor shapes are visited in ascending
            // order below, so their masks are visited in ascending order too,
            // and this cursor only ever needs to move forward across the whole
            // chunk.
            let mut ancestor_search_start = 0usize;
            let mut remaining_hi_prefixes = eligible_hi_prefixes;

            while remaining_hi_prefixes != 0 && dropped != all_dropped {
                let ancestor_hi_prefix = remaining_hi_prefixes.trailing_zeros() as u8;
                remaining_hi_prefixes &= remaining_hi_prefixes - 1;

                let lo_prefixes = lo_prefixes_by_hi_prefix[ancestor_hi_prefix as usize];
                let mut eligible_lo_prefixes = if chunk_lo_prefix == 64 {
                    lo_prefixes
                } else {
                    lo_prefixes & ((1u128 << (chunk_lo_prefix + 1)) - 1)
                };

                while eligible_lo_prefixes != 0 && dropped != all_dropped {
                    let ancestor_lo_prefix = eligible_lo_prefixes.trailing_zeros() as u8;
                    eligible_lo_prefixes &= eligible_lo_prefixes - 1;

                    let ancestor_mask = bicontiguous_shape_mask(ancestor_hi_prefix, ancestor_lo_prefix);

                    // `ancestor_hi_prefix` is always strictly less than 64
                    // here (it is strictly less than `chunk_hi_prefix`, itself
                    // at most 64), so `ancestor_mask`'s high half is never all
                    // ones, `ancestor_mask` is never `u128::MAX`, and `+ 1`
                    // below never overflows.
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

                    for (offset, &chunk_addr) in chunk_addrs[..chunk_len].iter().enumerate() {
                        let bit = 1u64 << offset;
                        if dropped & bit != 0 {
                            continue;
                        }
                        let target = chunk_addr & ancestor_mask;
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

    // The degenerate members of the class are exactly the contiguous ones: the
    // low half is empty (`q == 0`) or the high half is full (`p == 64`), so the
    // two runs abut with no interior zero. `::/0` (mask zero), `::/1` (a single
    // top bit, low half empty), `::/40` (`q == 0`) and `::/64` (both `p == 64`
    // and `q == 0`) are the `q == 0` side, while `::/65`, `::/96` and `::/128`
    // are the `p == 64` side.
    #[test]
    fn bicontiguous_ipv6_network_is_contiguous_accepts_degenerate_members() {
        for spec in ["::/0", "::/1", "::/40", "::/64", "::/65", "::/96", "::/128"] {
            let net = BiContiguous::<Ipv6Network>::parse(spec).unwrap();
            assert!(net.is_contiguous(), "{spec} should be contiguous");
        }
    }

    // The proper (non-degenerate) two-run members `p < 64, q > 0`: an interior
    // zero sits between the high and low runs, so the mask is bi-contiguous but
    // not contiguous. Covers a wide gap (`p=40, q=32`), a narrow gap
    // (`p=56, q=16`) and the tightest possible single-zero gap at the hi/lo
    // boundary (`p=63, q=1`).
    #[test]
    fn bicontiguous_ipv6_network_is_contiguous_rejects_two_run_masks() {
        for spec in [
            "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "::/ffff:ffff:ffff:ff00:ffff::",
            "::/ffff:ffff:ffff:fffe:8000::",
        ] {
            let net = BiContiguous::<Ipv6Network>::parse(spec).unwrap();
            assert!(!net.is_contiguous(), "{spec} should not be contiguous");
        }
    }

    #[test]
    fn bicontiguous_ipv6_network_is_contiguous_override_matches_inner() {
        let contiguous = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap();
        assert!(contiguous.is_contiguous());
        assert_eq!(contiguous.is_contiguous(), Ipv6Network::is_contiguous(&contiguous));

        let two_run =
            BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
        assert!(!two_run.is_contiguous());
        assert_eq!(two_run.is_contiguous(), Ipv6Network::is_contiguous(&two_run));
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

        // The lo half's 4 host bits cycle fastest (inner loop). The hi
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
    // class, upgraded through `From<Contiguous<Ipv6Network>>`, and `b` is a
    // CIDR subset of `a`, so containment reduces intersection to `b`.
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

        // The per-half override must agree with the general whole-mask
        // algorithm on every member of the class. The inherent override
        // shadows the `Deref`'d method, so the general path is reached through
        // the fully qualified `Ipv6Network::is_contiguous` on the inner value.
        #[test]
        fn prop_bicontiguous_ipv6_is_contiguous_matches_general(net in arb_bicontiguous_ipv6_network()) {
            let inner: Ipv6Network = *net;
            prop_assert_eq!(net.is_contiguous(), Ipv6Network::is_contiguous(&inner));
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
        // closed-form override and the general iterator, then checks set
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

    fn bc(spec: &str) -> BiContiguous<Ipv6Network> {
        BiContiguous::<Ipv6Network>::parse(spec).unwrap()
    }

    // The `(lo address, lo prefix)` low-half shape of a network, used by the
    // reference oracle to compare hi-buddy groups' low-half sets.
    fn lo_shape(net: Ipv6Network) -> (u64, u8) {
        let (addr, mask) = net.to_bits();
        (addr as u64, (mask as u64).leading_ones() as u8)
    }

    // Finds the first applicable hi-buddy group merge in level-major key order:
    // two exact-hi groups that are high-half CIDR buddies at some prefix and
    // carry element-wise equal low-half sets. Returns the lower buddy's member
    // indices to re-parent, the upper buddy's to drop, and the new (widened)
    // high-half prefix.
    fn reference_find_hi_group_merge(nets: &[Ipv6Network]) -> Option<(Vec<usize>, Vec<usize>, u8)> {
        use std::collections::BTreeMap;

        let mut groups: BTreeMap<(u8, u64), Vec<usize>> = BTreeMap::new();
        for (index, net) in nets.iter().enumerate() {
            let (addr, mask) = net.to_bits();
            let hi_prefix = ((mask >> 64) as u64).leading_ones() as u8;
            let hi = (addr >> 64) as u64;
            groups.entry((hi_prefix, hi)).or_default().push(index);
        }

        for (&(p, hi_a), members_a) in &groups {
            if p == 0 {
                continue;
            }
            let buddy_bit = 1u64 << (64 - p);
            if hi_a & buddy_bit != 0 {
                continue;
            }
            let hi_b = hi_a | buddy_bit;
            if let Some(members_b) = groups.get(&(p, hi_b)) {
                let mut lo_a: Vec<(u64, u8)> = members_a.iter().map(|&i| lo_shape(nets[i])).collect();
                let mut lo_b: Vec<(u64, u8)> = members_b.iter().map(|&i| lo_shape(nets[i])).collect();
                lo_a.sort_unstable();
                lo_b.sort_unstable();
                if lo_a == lo_b {
                    return Some((members_a.clone(), members_b.clone(), p - 1));
                }
            }
        }
        None
    }

    // Applies one hi-buddy group merge if any is available. Returns whether it
    // fired.
    fn reference_apply_hi_group_merge(nets: &mut Vec<Ipv6Network>) -> bool {
        let Some((reparent, drop, new_hi_prefix)) = reference_find_hi_group_merge(nets) else {
            return false;
        };
        let new_hi_mask = if new_hi_prefix == 0 {
            0u64
        } else {
            u64::MAX << (64 - new_hi_prefix)
        };
        let mut drop_sorted = drop;
        drop_sorted.sort_unstable();

        let mut result = Vec::new();
        for (index, net) in nets.iter().enumerate() {
            if drop_sorted.binary_search(&index).is_ok() {
                continue;
            }
            if reparent.contains(&index) {
                let (addr, mask) = net.to_bits();
                let new_mask = (mask & (u64::MAX as u128)) | ((new_hi_mask as u128) << 64);
                result.push(Ipv6Network::from_bits(addr, new_mask));
            } else {
                result.push(*net);
            }
        }
        *nets = result;
        true
    }

    // The simple, obviously-correct O(N^2) containment oracle: a network
    // survives iff no other network in the slice, with a different mask,
    // contains it. Assumes duplicate-free input -- every call site below
    // feeds either sweep-clean or hand-built duplicate-free networks -- so
    // it does not need to special-case exact duplicates.
    fn bicontiguous_containment_reference(nets: &mut [BiContiguous<Ipv6Network>]) -> usize {
        let mut kept_len = 0usize;

        for index in 0..nets.len() {
            let candidate = nets[index];
            let is_contained = nets
                .iter()
                .any(|other| other.mask() != candidate.mask() && other.contains(&candidate));

            if !is_contained {
                nets.swap(kept_len, index);
                kept_len += 1;
            }
        }

        kept_len
    }

    // Independent oracle for `ipv6_aggregate_bicontiguous`: applies the three
    // class-preserving rewrites -- containment absorb and lowest-mask-bit
    // sibling merge (both via `merge_by_lowest_mask_bit`), plus hi-buddy group
    // merge with equal low-half sets -- to a fixpoint, then sorts. Deliberately
    // a plain quadratic reference, not a minimal cover.
    fn ipv6_aggregate_bicontiguous_reference(input: &[BiContiguous<Ipv6Network>]) -> Vec<Ipv6Network> {
        let mut nets: Vec<Ipv6Network> = input.iter().map(|net| **net).collect();
        loop {
            let mut applied = false;
            'pairwise: for i in 0..nets.len() {
                for j in (i + 1)..nets.len() {
                    if let Some(parent) = nets[i].merge_by_lowest_mask_bit(&nets[j]) {
                        nets[i] = parent;
                        nets.remove(j);
                        applied = true;
                        break 'pairwise;
                    }
                }
            }
            if applied {
                continue;
            }
            if reference_apply_hi_group_merge(&mut nets) {
                continue;
            }
            break;
        }
        nets.sort_unstable();
        nets
    }

    // Clustered small networks with at most 4 host bits per half (16 host
    // combinations, 256 addresses), all sharing a fixed high-order base so
    // containment, lo-buddies, and hi-buddies arise densely. Small enough to
    // brute-force the address union in a proptest case.
    fn arb_gridded_bicontiguous_ipv6_network() -> impl Strategy<Value = BiContiguous<Ipv6Network>> {
        (0u64..16, 0u64..16, 60u8..=64, 60u8..=64).prop_map(|(hi_low, lo_low, hi_prefix, lo_prefix)| {
            let hi = 0x2001_0db8_1234_5670u64 | hi_low;
            let lo = lo_low;
            let hi_mask = u64::MAX << (64 - hi_prefix);
            let lo_mask = u64::MAX << (64 - lo_prefix);
            let addr = ((hi as u128) << 64) | lo as u128;
            let mask = ((hi_mask as u128) << 64) | lo_mask as u128;
            BiContiguous(Ipv6Network::from_bits(addr, mask))
        })
    }

    fn arb_gridded_bicontiguous_ipv6_slice() -> impl Strategy<Value = Vec<BiContiguous<Ipv6Network>>> {
        proptest::collection::vec(arb_gridded_bicontiguous_ipv6_network(), 0..16)
    }

    // Larger gridded slices, sized to exercise the live containment probe's
    // 64-element chunking across multiple chunks, while the address union
    // stays brute-forceable.
    fn arb_gridded_bicontiguous_ipv6_slice_large() -> impl Strategy<Value = Vec<BiContiguous<Ipv6Network>>> {
        proptest::collection::vec(arb_gridded_bicontiguous_ipv6_network(), 64..192)
    }

    fn arb_bicontiguous_ipv6_slice() -> impl Strategy<Value = Vec<BiContiguous<Ipv6Network>>> {
        proptest::collection::vec(arb_bicontiguous_ipv6_network(), 0..24)
    }

    // Collects the whole address union of a slice of networks. Only used on the
    // bounded gridded strategy, whose total union stays well within reach.
    fn address_union(nets: &[BiContiguous<Ipv6Network>]) -> std::collections::HashSet<Ipv6Addr> {
        let mut addrs = std::collections::HashSet::new();
        for net in nets {
            for addr in net.addrs() {
                addrs.insert(addr);
            }
        }
        addrs
    }

    #[test]
    fn bicontiguous_ipv6_aggregate_empty() {
        let mut nets: [BiContiguous<Ipv6Network>; 0] = [];
        assert_eq!(0, ipv6_aggregate_bicontiguous(&mut nets).len());
    }

    #[test]
    fn bicontiguous_ipv6_aggregate_single() {
        let mut nets = [bc("2001:db8::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0")];
        let out = ipv6_aggregate_bicontiguous(&mut nets);
        assert_eq!(1, out.len());
        assert_eq!(bc("2001:db8::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), out[0]);
    }

    #[test]
    fn bicontiguous_ipv6_aggregate_deduplicates() {
        let net = bc("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0");
        let mut nets = [net, net, net];
        let out = ipv6_aggregate_bicontiguous(&mut nets);
        assert_eq!(1, out.len());
        assert_eq!(net, out[0]);
    }

    // A lowest-mask-bit sibling pair sharing the same high block and low-half
    // prefix merges by clearing the low half's boundary bit.
    #[test]
    fn bicontiguous_ipv6_aggregate_lo_buddy_merges() {
        let mut nets = [
            bc("2001:db8:1:0:aaaa:bbbb:0:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0"),
            bc("2001:db8:1:0:aaaa:bbbb:1:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0"),
        ];
        let out = ipv6_aggregate_bicontiguous(&mut nets);
        assert_eq!(1, out.len());
        assert_eq!(
            bc("2001:db8:1:0:aaaa:bbbb:0:0/ffff:ffff:ffff:0:ffff:ffff:fffe:0"),
            out[0]
        );
    }

    // Two high-half buddies with an identical single low block merge into their
    // high-half parent, keeping the low half.
    #[test]
    fn bicontiguous_ipv6_aggregate_hi_buddy_equal_lo_merges() {
        let mut nets = [
            bc("2001:db8:0:0:aaaa:bbbb:cccc:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0"),
            bc("2001:db8:1:0:aaaa:bbbb:cccc:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0"),
        ];
        let out = ipv6_aggregate_bicontiguous(&mut nets);
        assert_eq!(1, out.len());
        assert_eq!(
            bc("2001:db8:0:0:aaaa:bbbb:cccc:0/ffff:ffff:fffe:0:ffff:ffff:ffff:0"),
            out[0]
        );
    }

    // The same high-half buddies but with different low blocks are NOT a
    // hi-buddy-with-equal-lo pair, so they stay separate.
    #[test]
    fn bicontiguous_ipv6_aggregate_hi_buddy_differing_lo_stays_separate() {
        let mut nets = [
            bc("2001:db8:0:0:aaaa:bbbb:cccc:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0"),
            bc("2001:db8:1:0:aaaa:bbbb:dddd:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0"),
        ];
        let out = ipv6_aggregate_bicontiguous(&mut nets);
        assert_eq!(2, out.len());
    }

    // A 2x2 grid over hi-buddies x lo-buddies collapses to the single parent
    // rectangle, exercising Phase A (lo-aggregate) then Phase B (hi-buddy).
    #[test]
    fn bicontiguous_ipv6_aggregate_full_grid_collapses_to_one() {
        let mut nets = [
            bc("2001:db8:0:0:aaaa:bbbb:0:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0"),
            bc("2001:db8:0:0:aaaa:bbbb:1:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0"),
            bc("2001:db8:1:0:aaaa:bbbb:0:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0"),
            bc("2001:db8:1:0:aaaa:bbbb:1:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0"),
        ];
        let out = ipv6_aggregate_bicontiguous(&mut nets);
        assert_eq!(1, out.len());
        assert_eq!(
            bc("2001:db8:0:0:aaaa:bbbb:0:0/ffff:ffff:fffe:0:ffff:ffff:fffe:0"),
            out[0]
        );
    }

    // Plain CIDR (`q = 0`) buddies aggregate exactly like contiguous CIDR
    // blocks: two adjacent `/48`s merge into a `/47`.
    #[test]
    fn bicontiguous_ipv6_aggregate_contiguous_buddies_merge() {
        let mut nets = [bc("2001:db8::/48"), bc("2001:db8:1::/48")];
        let out = ipv6_aggregate_bicontiguous(&mut nets);
        assert_eq!(1, out.len());
        assert_eq!(bc("2001:db8::/47"), out[0]);
    }

    // Re-parented /47s must meet again at the next level and merge to /46,
    // while an unrelated network survives unchanged.
    #[test]
    fn bicontiguous_ipv6_aggregate_hi_buddy_cascades_across_levels() {
        let mut nets = [
            bc("2001:db8::/48"),
            bc("2001:db8:1::/48"),
            bc("2001:db8:2::/48"),
            bc("2001:db8:3::/48"),
            bc("2001:dead::/32"),
        ];
        let out = ipv6_aggregate_bicontiguous(&mut nets);

        assert_eq!(2, out.len());
        assert_eq!(bc("2001:dead::/32"), out[0]);
        assert_eq!(bc("2001:db8::/46"), out[1]);
    }

    // A container that is not adjacent to what it contains in sort order (an
    // unrelated network sorts between them) is still absorbed by the
    // containment sweep. `db8:1::/48` is dropped, while the disjoint
    // `dead::/32` survives alongside the container `db8::/32`.
    #[test]
    fn bicontiguous_ipv6_aggregate_absorbs_non_adjacent_containment() {
        let mut nets = [bc("2001:db8::/32"), bc("2001:dead::/32"), bc("2001:db8:1::/48")];
        let out = ipv6_aggregate_bicontiguous(&mut nets);

        assert_eq!(2, out.len());
        assert_eq!(bc("2001:db8::/32"), out[0]);
        assert_eq!(bc("2001:dead::/32"), out[1]);
    }

    // The implied-coverage gadget from the design: three bi-contiguous
    // rectangles tile a parent rectangle, yet no pair is a containment, a
    // lo-buddy, or a hi-buddy-with-equal-lo, so this pairwise greedy leaves all
    // three. Pins the documented non-minimality (minimum cover here is one).
    #[test]
    fn bicontiguous_ipv6_aggregate_implied_coverage_gadget_stays_three() {
        let mut nets = [
            bc("::/c000:0:0:0:8000:0:0:0"),
            bc("4000::/c000:0:0:0:c000:0:0:0"),
            bc("::4000:0:0:0/8000:0:0:0:c000:0:0:0"),
        ];
        let out = ipv6_aggregate_bicontiguous(&mut nets);
        assert_eq!(3, out.len());

        // No pair merges and none contains another: a genuine fixpoint.
        for i in 0..out.len() {
            for j in 0..out.len() {
                if i != j {
                    assert_eq!(None, (*out[i]).merge_by_lowest_mask_bit(&out[j]));
                }
            }
        }
    }

    // The two motivating masks (hi `/40`, lo `/32` and `/16`) aggregate: the
    // `/32` low half is contained in the `/16` low half at the same high block,
    // so the broader network absorbs the narrower.
    #[test]
    fn bicontiguous_ipv6_aggregate_motivating_masks() {
        let narrow = bc("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0");
        let broad = bc("2a02:6b8:c00::1234:0:0:0/ffff:ffff:ff00::ffff:0:0:0");
        let mut nets = [narrow, broad];
        let out = ipv6_aggregate_bicontiguous(&mut nets);
        assert_eq!(1, out.len());
        assert_eq!(broad, out[0]);
    }

    // A re-parented survivor must cascade into a native block at the next
    // coarser level: the `/48` buddies re-parent to `/47`, the localized
    // re-sort places that survivor next to the native `2001:db8:2::/47`, and
    // level 47's hi-buddy merge then widens the pair to `/46`.
    #[test]
    fn bicontiguous_aggregate_reparented_merges_into_native_block() {
        let mut nets = [bc("2001:db8::/48"), bc("2001:db8:1::/48"), bc("2001:db8:2::/47")];

        let len = bicontiguous_aggregate(&mut nets);
        assert_eq!(1, len);
        assert_eq!(bc("2001:db8::/46"), nets[0]);
    }

    // A re-parented survivor must also low-aggregate with a native network
    // already sitting in its new exact-hi run. Two hi-prefix-48 buddies with
    // an identical single low block re-parent to hi-prefix 47 without
    // touching their low half. A native hi-prefix-47 network at the same high
    // address carries an adjacent low block that is this low half's
    // lowest-mask-bit sibling, so level 47's low-half aggregation merges them
    // into one hi-prefix-47, lo-prefix-47 network.
    #[test]
    fn bicontiguous_aggregate_reparented_lo_aggregates_with_native_run() {
        let mut nets = [
            bc("2001:db8:0:0:aaaa:bbbb:cccc:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0"),
            bc("2001:db8:1:0:aaaa:bbbb:cccc:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0"),
            bc("2001:db8:0:0:aaaa:bbbb:cccd:0/ffff:ffff:fffe:0:ffff:ffff:ffff:0"),
        ];

        let len = bicontiguous_aggregate(&mut nets);
        assert_eq!(1, len);
        assert_eq!(
            bc("2001:db8:0:0:aaaa:bbbb:cccc:0/ffff:ffff:fffe:0:ffff:ffff:fffe:0"),
            nets[0]
        );
    }

    // Formats an `(hi address, hi mask, lo address, lo mask)` quadruple as a
    // bi-contiguous "address/mask" string and parses it, so the
    // programmatically generated adversarial family below is still built
    // through the same string parser as every other test in this module.
    fn bc_from_halves(hi_addr: u64, hi_mask: u64, lo_addr: u64, lo_mask: u64) -> BiContiguous<Ipv6Network> {
        let addr = ((hi_addr as u128) << 64) | lo_addr as u128;
        let mask = ((hi_mask as u128) << 64) | lo_mask as u128;
        let net = Ipv6Network::from_bits(addr, mask);
        BiContiguous::<Ipv6Network>::parse(&net.to_string()).unwrap()
    }

    // One hi-buddy pair per high-half prefix level from 64 down to 2, each
    // confined to a distinct single marker bit so its re-parented survivor
    // never finds another buddy, plus a small inert block of fully-specified
    // networks at high half `0`. Every survivor's high half carries its own
    // marker bit set to `1` somewhere inside its own mask, so an all-zero
    // high half can never match what any survivor requires there and is
    // never absorbed by containment either. Every one of the 63 pairs fires
    // its own re-parenting event, one level below the last -- this is the
    // family that used to force 63 consecutive full-slice re-sorts, one per
    // level.
    #[test]
    fn bicontiguous_aggregate_disjoint_cascade_family_exact_output() {
        let mut nets = Vec::new();
        for p in 2u8..=64 {
            let buddy_bit = 1u64 << (64 - p);
            let marker = 1u64 << (65 - p);
            let hi_mask = bicontiguous_half_prefix_mask(p);
            nets.push(bc_from_halves(marker, hi_mask, 0, 0));
            nets.push(bc_from_halves(marker | buddy_bit, hi_mask, 0, 0));
        }
        for index in 0u64..8 {
            let lo = 0x100 * (index + 1);
            nets.push(bc_from_halves(0, u64::MAX, lo, u64::MAX));
        }

        let mut fast = nets.clone();
        let fast_len = bicontiguous_aggregate(&mut fast);
        assert_eq!(63 + 8, fast_len);

        // Each level's buddy pair re-parents exactly one level up, keeping its
        // lower buddy's marker bit and empty low half. The 8 inert networks
        // never merge with anything and survive unchanged.
        let mut expected: Vec<_> = (2u8..=64)
            .map(|p| bc_from_halves(1u64 << (65 - p), bicontiguous_half_prefix_mask(p - 1), 0, 0))
            .collect();
        for index in 0u64..8 {
            let lo = 0x100 * (index + 1);
            expected.push(bc_from_halves(0, u64::MAX, lo, u64::MAX));
        }
        expected.sort_unstable_by_key(bicontiguous_sort_key);

        assert_eq!(&expected[..], &fast[..fast_len]);
    }

    // A hand-built, post-sweep-shaped slice: a strictly-coarser-hi-prefix
    // container (`hi_prefix` 32) must drop a same-branch, finer-`hi_prefix`
    // (48) containee in both the live probe and the simple quadratic oracle,
    // while a disjoint network of a third, unrelated shape survives untouched.
    #[test]
    fn bicontiguous_containment_live_paths_drop_strictly_coarser_hi_prefix_containee() {
        let container = bc("2001:db8::/32");
        let containee = bc("2001:db8:1::/48");
        let disjoint = bc("2001:dead::/32");

        let mut nets = [container, containee, disjoint];
        nets.sort_unstable_by_key(bicontiguous_sort_key);

        let mut quadratic = nets;
        let quadratic_len = bicontiguous_containment_reference(&mut quadratic);
        assert_eq!(2, quadratic_len);
        assert_eq!(container, quadratic[0]);
        assert_eq!(disjoint, quadratic[1]);

        let mut probe = nets;
        let probe_len = bicontiguous_containment_probe(&mut probe);
        assert_eq!(2, probe_len);
        assert_eq!(container, probe[0]);
        assert_eq!(disjoint, probe[1]);
    }

    proptest! {
        // The output's address union equals the input's (brute-forced on the
        // bounded gridded strategy).
        #[test]
        fn prop_bicontiguous_ipv6_aggregate_preserves_union(nets in arb_gridded_bicontiguous_ipv6_slice()) {
            let expected = address_union(&nets);
            let mut work = nets.clone();
            let out = ipv6_aggregate_bicontiguous(&mut work);
            let actual = address_union(out);
            prop_assert_eq!(expected, actual);
        }

        // Every output value is bi-contiguous -- the re-wraps that skip
        // validation are sound.
        #[test]
        fn prop_bicontiguous_ipv6_aggregate_output_is_bicontiguous(nets in arb_bicontiguous_ipv6_slice()) {
            let mut work = nets.clone();
            let out = ipv6_aggregate_bicontiguous(&mut work);
            for net in out.iter() {
                prop_assert!((*net).is_bicontiguous());
            }
        }

        // The output is sorted ascending by `bicontiguous_sort_key` -- the
        // deterministic order the doc example asserts.
        #[test]
        fn prop_bicontiguous_ipv6_aggregate_output_is_sorted(nets in arb_bicontiguous_ipv6_slice()) {
            let mut work = nets.clone();
            let out = ipv6_aggregate_bicontiguous(&mut work);
            prop_assert!(out.windows(2).all(|pair| bicontiguous_sort_key(&pair[0]) <= bicontiguous_sort_key(&pair[1])));
        }

        // The output is a fixpoint: no pair merges (containment or lo-buddy)
        // and no hi-buddy group with equal low-half sets remains.
        #[test]
        fn prop_bicontiguous_ipv6_aggregate_output_is_fixpoint(nets in arb_bicontiguous_ipv6_slice()) {
            let mut work = nets.clone();
            let out = ipv6_aggregate_bicontiguous(&mut work);

            for i in 0..out.len() {
                for j in 0..out.len() {
                    if i != j {
                        prop_assert_eq!((*out[i]).merge_by_lowest_mask_bit(&out[j]), None);
                    }
                }
            }

            let inner: Vec<Ipv6Network> = out.iter().map(|net| **net).collect();
            prop_assert!(reference_find_hi_group_merge(&inner).is_none());
        }

        // Aggregating the output again is a no-op (as a set).
        #[test]
        fn prop_bicontiguous_ipv6_aggregate_is_idempotent(nets in arb_bicontiguous_ipv6_slice()) {
            let mut once = nets.clone();
            let mut first: Vec<BiContiguous<Ipv6Network>> = ipv6_aggregate_bicontiguous(&mut once).to_vec();

            let mut twice = first.clone();
            let mut second: Vec<BiContiguous<Ipv6Network>> = ipv6_aggregate_bicontiguous(&mut twice).to_vec();

            first.sort_unstable();
            second.sort_unstable();
            prop_assert_eq!(first, second);
        }

        // Differential check against the independent quadratic greedy oracle.
        //
        // Set-equality is deliberately NOT asserted: the class-preserving
        // greedy is non-confluent. A network can be simultaneously a lo-buddy
        // of one network and contained in a coarser cross-shape ancestor of
        // another. The fast path's Phase A merges the lo-buddy pair (widening
        // it beyond the ancestor) before the final containment sweep, while a
        // containment-first order absorbs it instead -- two valid closed covers
        // of equal union that differ as sets. What both implementations MUST
        // satisfy is the contract: preserve the union, and reach a fixpoint.
        // This asserts exactly that for both, and cross-checks their unions.
        #[test]
        fn prop_bicontiguous_ipv6_aggregate_agrees_with_reference_on_contract(
            nets in arb_gridded_bicontiguous_ipv6_slice(),
        ) {
            let input_union = address_union(&nets);

            let mut work = nets.clone();
            let algorithm_union = address_union(ipv6_aggregate_bicontiguous(&mut work));

            let reference = ipv6_aggregate_bicontiguous_reference(&nets);
            let reference_wrapped: Vec<BiContiguous<Ipv6Network>> =
                reference.iter().map(|net| BiContiguous::<Ipv6Network>::try_from(*net).unwrap()).collect();
            let reference_union = address_union(&reference_wrapped);

            // Both cover exactly the input union.
            prop_assert_eq!(&algorithm_union, &input_union);
            prop_assert_eq!(&reference_union, &input_union);

            // The oracle output is itself a fixpoint (validating the oracle as a
            // genuine class-greedy, independent of the fast path).
            prop_assert!(reference_find_hi_group_merge(&reference).is_none());
            for i in 0..reference.len() {
                for j in 0..reference.len() {
                    if i != j {
                        prop_assert_eq!(reference[i].merge_by_lowest_mask_bit(&reference[j]), None);
                    }
                }
            }
        }

        // The live probe agrees exactly with the simple quadratic oracle on
        // sweep-clean input -- the domain `bicontiguous_find_containment`
        // actually runs on. Cross-shape containment (a network strictly
        // contained in another of an unrelated hi/lo shape) is not resolved by
        // `bicontiguous_sweep` itself, so it still arises in the sweep's
        // output on gridded input. This is not a vacuous check.
        #[test]
        fn prop_bicontiguous_containment_probe_matches_quadratic_on_swept_input(
            nets in arb_gridded_bicontiguous_ipv6_slice_large(),
        ) {
            let mut swept = nets.clone();
            let live = bicontiguous_sweep(&mut swept);
            swept.truncate(live);
            swept.sort_unstable_by_key(bicontiguous_sort_key);

            let mut quadratic = swept.clone();
            let quadratic_len = bicontiguous_containment_reference(&mut quadratic);

            let mut probe = swept.clone();
            let probe_len = bicontiguous_containment_probe(&mut probe);

            prop_assert_eq!(quadratic_len, probe_len);

            let mut quadratic_kept = quadratic[..quadratic_len].to_vec();
            let mut probe_kept = probe[..probe_len].to_vec();
            quadratic_kept.sort_unstable();
            probe_kept.sort_unstable();
            prop_assert_eq!(quadratic_kept, probe_kept);
        }

        // End-to-end union preservation through the probe path, on larger
        // inputs whose bounded address space is still brute-forceable.
        #[test]
        fn prop_bicontiguous_ipv6_aggregate_preserves_union_large(
            nets in arb_gridded_bicontiguous_ipv6_slice_large(),
        ) {
            let expected = address_union(&nets);
            let mut work = nets.clone();
            let out = ipv6_aggregate_bicontiguous(&mut work);
            let actual = address_union(out);
            prop_assert_eq!(expected, actual);

            // The large-input result is also a fixpoint.
            for i in 0..out.len() {
                for j in 0..out.len() {
                    if i != j {
                        prop_assert_eq!((*out[i]).merge_by_lowest_mask_bit(&out[j]), None);
                    }
                }
            }
        }

        // Same as `prop_bicontiguous_ipv6_aggregate_output_is_sorted`, on
        // larger gridded inputs that push the containment sweep through its
        // chunked probe path.
        #[test]
        fn prop_bicontiguous_ipv6_aggregate_output_is_sorted_large(
            nets in arb_gridded_bicontiguous_ipv6_slice_large(),
        ) {
            let mut work = nets.clone();
            let out = ipv6_aggregate_bicontiguous(&mut work);
            prop_assert!(out.windows(2).all(|pair| bicontiguous_sort_key(&pair[0]) <= bicontiguous_sort_key(&pair[1])));
        }
    }
}
