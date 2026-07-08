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
/// or returns a typed result because the class is closed under the operation;
/// see each method's "Why overridden?" note for which and why.
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
///   isn't one prefix length; use [`hi_prefix`](Self::hi_prefix) /
///   [`lo_prefix`](Self::lo_prefix).
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
    // and `q == 0`) are the `q == 0` side; `::/65`, `::/96` and `::/128` are the
    // `p == 64` side.
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
}
