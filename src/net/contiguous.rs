//! Contiguous IP network wrapper.
//!
//! [`Contiguous<T>`] guarantees at the type level that a wrapped IP network
//! has a contiguous mask.

use core::{
    error::Error,
    fmt::{Display, Formatter},
    net::{Ipv4Addr, Ipv6Addr},
    ops::Deref,
    str::FromStr,
};

use super::{IpNetParseError, IpNetwork, Ipv4Network, Ipv6Network};

/// An error that occurs when parsing a contiguous IP network.
#[derive(Debug, PartialEq)]
pub enum ContiguousIpNetParseError {
    /// The network is not contiguous.
    NonContiguousNetwork,
    /// An error occurred while parsing the IP network.
    IpNetParseError(IpNetParseError),
}

impl From<IpNetParseError> for ContiguousIpNetParseError {
    #[inline]
    fn from(err: IpNetParseError) -> Self {
        ContiguousIpNetParseError::IpNetParseError(err)
    }
}

impl Display for ContiguousIpNetParseError {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), core::fmt::Error> {
        match self {
            Self::NonContiguousNetwork => write!(fmt, "non-contiguous network"),
            Self::IpNetParseError(err) => write!(fmt, "{}", err),
        }
    }
}

impl Error for ContiguousIpNetParseError {}

/// A contiguous IP network.
///
/// Represents a wrapper around an IP network that is **guaranteed to be
/// contiguous**.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Contiguous<T>(pub(crate) T);

impl Contiguous<IpNetwork> {
    /// Parses an IP network from a string and returns a contiguous network.
    pub fn parse(buf: &str) -> Result<Self, ContiguousIpNetParseError> {
        let net = IpNetwork::parse(buf)?;

        if net.is_contiguous() {
            Ok(Self(net))
        } else {
            Err(ContiguousIpNetParseError::NonContiguousNetwork)
        }
    }

    /// Returns the prefix length of the network.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, IpNetwork};
    ///
    /// let net = Contiguous::<IpNetwork>::parse("192.168.1.0/24").unwrap();
    /// assert_eq!(24, net.prefix());
    /// ```
    #[inline]
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        match self {
            Self(IpNetwork::V4(net)) => Contiguous(*net).prefix(),
            Self(IpNetwork::V6(net)) => Contiguous(*net).prefix(),
        }
    }

    /// Checks whether this network is a contiguous network.
    ///
    /// Always returns `true`: the wrapped network is guaranteed to be
    /// contiguous by the [`Contiguous`] type invariant, so this overrides the
    /// [`IpNetwork::is_contiguous`] check with a constant result.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, IpNetwork};
    ///
    /// let net = Contiguous::<IpNetwork>::parse("192.168.1.0/24").unwrap();
    /// assert!(net.is_contiguous());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_contiguous(&self) -> bool {
        true
    }

    /// Converts this network to a contiguous network.
    ///
    /// The wrapped network is already contiguous by the [`Contiguous`] type
    /// invariant, so this overrides the [`IpNetwork::to_contiguous`]
    /// conversion by returning the wrapped network unchanged.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, IpNetwork};
    ///
    /// let net = Contiguous::<IpNetwork>::parse("192.168.1.0/24").unwrap();
    /// assert_eq!(*net, net.to_contiguous());
    /// ```
    #[inline]
    #[must_use]
    pub const fn to_contiguous(&self) -> IpNetwork {
        match self {
            Self(net) => *net,
        }
    }

    /// Returns `true` if this IP network fully contains the specified one.
    ///
    /// Returns `false` for networks of different address families. Both
    /// operands are guaranteed to have contiguous masks by the [`Contiguous`]
    /// type invariant, so same-family cases delegate to the cheaper
    /// [`Contiguous<Ipv4Network>::contains`] /
    /// [`Contiguous<Ipv6Network>::contains`] overrides instead of
    /// [`IpNetwork::contains`].
    ///
    /// Reach the general check for a possibly non-contiguous network through
    /// [`Deref`] instead, e.g. `(*net).contains(&other)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, IpNetwork};
    ///
    /// let a = Contiguous::<IpNetwork>::parse("192.168.0.0/16").unwrap();
    /// let b = Contiguous::<IpNetwork>::parse("192.168.1.0/24").unwrap();
    /// assert!(a.contains(&b));
    /// assert!(!b.contains(&a));
    ///
    /// // Different address families.
    /// let v6 = Contiguous::<IpNetwork>::parse("2001:db8::/32").unwrap();
    /// assert!(!a.contains(&v6));
    /// ```
    #[inline]
    #[must_use]
    pub const fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Self(IpNetwork::V4(a)), Self(IpNetwork::V4(b))) => Contiguous(*a).contains(&Contiguous(*b)),
            (Self(IpNetwork::V6(a)), Self(IpNetwork::V6(b))) => Contiguous(*a).contains(&Contiguous(*b)),
            _ => false,
        }
    }
}

impl Contiguous<Ipv4Network> {
    /// Parses an IPv4 network from a string and returns a contiguous network.
    pub fn parse(buf: &str) -> Result<Self, ContiguousIpNetParseError> {
        let net = Ipv4Network::parse(buf)?;

        if net.is_contiguous() {
            Ok(Self(net))
        } else {
            Err(ContiguousIpNetParseError::NonContiguousNetwork)
        }
    }

    /// Returns the prefix length of the network.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv4Network};
    ///
    /// let net = Contiguous::<Ipv4Network>::parse("172.16.0.0/12").unwrap();
    /// assert_eq!(12, net.prefix());
    /// ```
    #[inline]
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        match self {
            Self(net) => {
                let mask = net.mask().to_bits();
                let ones = mask.leading_ones();
                ones as u8
            }
        }
    }

    /// Checks whether this network is a contiguous network.
    ///
    /// Always returns `true`: the wrapped network is guaranteed to be
    /// contiguous by the [`Contiguous`] type invariant, so this overrides the
    /// [`Ipv4Network::is_contiguous`] check with a constant result.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv4Network};
    ///
    /// let net = Contiguous::<Ipv4Network>::parse("172.16.0.0/12").unwrap();
    /// assert!(net.is_contiguous());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_contiguous(&self) -> bool {
        true
    }

    /// Converts this network to a contiguous network.
    ///
    /// The wrapped network is already contiguous by the [`Contiguous`] type
    /// invariant, so this overrides the [`Ipv4Network::to_contiguous`]
    /// conversion by returning the wrapped network unchanged.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv4Network};
    ///
    /// let net = Contiguous::<Ipv4Network>::parse("172.16.0.0/12").unwrap();
    /// assert_eq!(*net, net.to_contiguous());
    /// ```
    #[inline]
    #[must_use]
    pub const fn to_contiguous(&self) -> Ipv4Network {
        match self {
            Self(net) => *net,
        }
    }

    /// Returns `true` if this IPv4 network fully contains the specified one.
    ///
    /// Both operands are guaranteed to have contiguous masks by the
    /// [`Contiguous`] type invariant, so mask-subset containment collapses
    /// from `mask & mask == mask` to a plain unsigned integer comparison.
    /// This overrides the [`Ipv4Network::contains`] check with that cheaper
    /// formula. Reach the general check for a possibly non-contiguous
    /// network through [`Deref`], e.g. `(*net).contains(&other)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv4Network};
    ///
    /// let a = Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap();
    /// let b = Contiguous::<Ipv4Network>::parse("10.1.0.0/16").unwrap();
    /// assert!(a.contains(&b));
    /// assert!(!b.contains(&a));
    /// ```
    #[inline]
    #[must_use]
    pub const fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Self(a), Self(b)) => {
                let (a1, m1) = a.to_bits();
                let (a2, m2) = b.to_bits();

                (a2 & m1 == a1) && (m1 <= m2)
            }
        }
    }

    /// Returns a double-ended iterator over every address in this network.
    ///
    /// The wrapped network is guaranteed to have a contiguous mask by the
    /// [`Contiguous`] type invariant, so its *k* host positions (bits where
    /// the mask is zero) are always a trailing run, and `base | index`
    /// enumerates addresses `0 ..= 2^k - 1` directly, in ascending numeric
    /// order. This overrides the [`Ipv4Network::addrs`] iterator with a
    /// leaner one that drops the general iterator's per-item mask-shape
    /// branch (and the `mask` field that branch reads), stepping a plain
    /// index instead. Reach the general iterator for a possibly
    /// non-contiguous network through [`Deref`], e.g. `(*net).addrs()`.
    ///
    /// The iterator always implements [`DoubleEndedIterator`], and implements
    /// [`ExactSizeIterator`] on 64-bit targets only: the /0 network holds
    /// `2^32` addresses, one more than a 32-bit `usize` can represent.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::{Contiguous, Ipv4Network};
    ///
    /// let net = Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap();
    /// let mut addrs = net.addrs();
    ///
    /// assert_eq!(256, addrs.len());
    ///
    /// assert_eq!(Some(Ipv4Addr::new(192, 168, 1, 0)), addrs.next());
    /// assert_eq!(Some(Ipv4Addr::new(192, 168, 1, 1)), addrs.next());
    ///
    /// assert_eq!(Some(Ipv4Addr::new(192, 168, 1, 255)), addrs.next_back());
    /// assert_eq!(Some(Ipv4Addr::new(192, 168, 1, 254)), addrs.next_back());
    /// ```
    #[inline]
    #[must_use]
    pub fn addrs(self) -> ContiguousIpv4NetworkAddrs {
        match self {
            Self(net) => {
                let (addr, mask) = net.to_bits();
                let host_bits = (!mask).count_ones();
                let back = u32::MAX.checked_shr(32 - host_bits).unwrap_or(0);

                ContiguousIpv4NetworkAddrs { base: addr, front: 0, back }
            }
        }
    }
}

/// Bidirectional iterator over [`Ipv4Addr`] in a [`Contiguous<Ipv4Network>`].
///
/// Created by [`Contiguous::<Ipv4Network>::addrs`].
///
/// The [`Contiguous`] type invariant guarantees a contiguous mask, so unlike
/// [`crate::Ipv4NetworkAddrs`] this iterator carries no per-item mask-shape
/// branch: the *k* host positions (bits where the mask is zero) are always a
/// trailing run, and `base | index` enumerates addresses `0 ..= 2^k - 1`
/// directly -- the same ascending numeric order [`crate::Ipv4NetworkAddrs`]
/// produces for a contiguous mask.
///
/// When the iterator is exhausted it enters a sentinel state where
/// `front > back`, so every subsequent call to [`next`](Iterator::next) or
/// [`next_back`](DoubleEndedIterator::next_back) returns [`None`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContiguousIpv4NetworkAddrs {
    base: u32,
    front: u32,
    back: u32,
}

impl ContiguousIpv4NetworkAddrs {
    /// Returns the number of addresses not yet yielded.
    ///
    /// Widened to `u64` because the /0 network's `2^32` addresses are one more
    /// than the `u32` index range can count: the difference of the two bounds
    /// is `u32::MAX`, and the inclusive count is that plus one.
    #[inline]
    fn remaining(&self) -> u64 {
        if self.front > self.back {
            return 0;
        }

        u64::from(self.back - self.front) + 1
    }
}

impl Iterator for ContiguousIpv4NetworkAddrs {
    type Item = Ipv4Addr;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.front > self.back {
            return None;
        }

        let index = self.front;
        self.front = self.front.wrapping_add(1);

        // Wrap-around means front was u32::MAX — only possible for a /0
        // network.
        //
        // Enter sentinel state so the next call returns None.
        if self.front == 0 {
            self.front = 1;
            self.back = 0;
        }

        Some(Ipv4Addr::from_bits(self.base | index))
    }

    #[inline]
    fn count(self) -> usize {
        let (n, ..) = self.size_hint();
        n
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match usize::try_from(self.remaining()) {
            Ok(n) => (n, Some(n)),
            Err(..) => (usize::MAX, None),
        }
    }
}

impl DoubleEndedIterator for ContiguousIpv4NetworkAddrs {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front > self.back {
            return None;
        }

        let index = self.back;

        if self.front == self.back {
            self.front = 1;
            self.back = 0;
        } else {
            self.back = self.back.wrapping_sub(1);
        }

        Some(Ipv4Addr::from_bits(self.base | index))
    }
}

// Implemented only where the count of every IPv4 network fits a `usize`. The /0
// network holds 2^32 addresses, one more than a 32-bit `usize` can represent,
// so on a 32-bit target no exact length exists for it and the trait's contract
// (`size_hint` must equal `(len(), Some(len()))`) is unsatisfiable. The
// standard library draws the same line: `RangeInclusive<u32>` is not an
// `ExactSizeIterator` while `Range<u32>` is.
#[cfg(target_pointer_width = "64")]
impl ExactSizeIterator for ContiguousIpv4NetworkAddrs {
    #[inline]
    fn len(&self) -> usize {
        // 2^32, the largest count any IPv4 network has, fits a 64-bit `usize`.
        self.remaining() as usize
    }
}

impl Contiguous<Ipv6Network> {
    /// Parses an IPv6 network from a string and returns a contiguous network.
    pub fn parse(buf: &str) -> Result<Self, ContiguousIpNetParseError> {
        let net = Ipv6Network::parse(buf)?;

        if net.is_contiguous() {
            Ok(Self(net))
        } else {
            Err(ContiguousIpNetParseError::NonContiguousNetwork)
        }
    }

    /// Returns the prefix length of the network.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv6Network};
    ///
    /// let net = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap();
    /// assert_eq!(40, net.prefix());
    /// ```
    #[inline]
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        match self {
            Self(net) => {
                let mask = net.mask().to_bits();
                let ones = mask.leading_ones();
                ones as u8
            }
        }
    }

    /// Checks whether this network is a contiguous network.
    ///
    /// Always returns `true`: the wrapped network is guaranteed to be
    /// contiguous by the [`Contiguous`] type invariant, so this overrides the
    /// [`Ipv6Network::is_contiguous`] check with a constant result.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv6Network};
    ///
    /// let net = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap();
    /// assert!(net.is_contiguous());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_contiguous(&self) -> bool {
        true
    }

    /// Converts this network to a contiguous network.
    ///
    /// The wrapped network is already contiguous by the [`Contiguous`] type
    /// invariant, so this overrides the [`Ipv6Network::to_contiguous`]
    /// conversion by returning the wrapped network unchanged.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv6Network};
    ///
    /// let net = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap();
    /// assert_eq!(*net, net.to_contiguous());
    /// ```
    #[inline]
    #[must_use]
    pub const fn to_contiguous(&self) -> Ipv6Network {
        match self {
            Self(net) => *net,
        }
    }

    /// Returns `true` if this IPv6 network fully contains the specified one.
    ///
    /// Both operands are guaranteed to have contiguous masks by the
    /// [`Contiguous`] type invariant, so mask-subset containment collapses
    /// from `mask & mask == mask` to a plain unsigned integer comparison.
    /// This overrides the [`Ipv6Network::contains`] check with that cheaper
    /// formula. Reach the general check for a possibly non-contiguous
    /// network through [`Deref`], e.g. `(*net).contains(&other)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv6Network};
    ///
    /// let a = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
    /// let b = Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap();
    /// assert!(a.contains(&b));
    /// assert!(!b.contains(&a));
    /// ```
    #[inline]
    #[must_use]
    pub const fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Self(a), Self(b)) => {
                let (a1, m1) = a.to_bits();
                let (a2, m2) = b.to_bits();

                (a2 & m1 == a1) && (m1 <= m2)
            }
        }
    }

    /// Returns a bidirectional iterator over all addresses in this network.
    ///
    /// The wrapped network is guaranteed to have a contiguous mask by the
    /// [`Contiguous`] type invariant, so its *k* host positions (bits where
    /// the mask is zero) are always a trailing run, and `base | index`
    /// enumerates addresses `0 ..= 2^k - 1` directly, in ascending numeric
    /// order. This overrides the [`Ipv6Network::addrs`] iterator with a
    /// leaner one that drops the general iterator's per-item mask-shape
    /// branch (and the `mask` field that branch reads), stepping a plain
    /// index instead. Reach the general iterator for a possibly
    /// non-contiguous network through [`Deref`], e.g. `(*net).addrs()`.
    ///
    /// The iterator implements [`DoubleEndedIterator`].
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::{Contiguous, Ipv6Network};
    ///
    /// let net = Contiguous::<Ipv6Network>::parse("2001:db8::/120").unwrap();
    /// let mut addrs = net.addrs();
    ///
    /// assert_eq!(
    ///     Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
    ///     addrs.next()
    /// );
    /// assert_eq!(
    ///     Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    ///     addrs.next()
    /// );
    ///
    /// assert_eq!(
    ///     Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff)),
    ///     addrs.next_back()
    /// );
    /// assert_eq!(
    ///     Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xfe)),
    ///     addrs.next_back()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub fn addrs(self) -> ContiguousIpv6NetworkAddrs {
        match self {
            Self(net) => {
                let (addr, mask) = net.to_bits();
                let host_bits = (!mask).count_ones();
                let back = u128::MAX.checked_shr(128 - host_bits).unwrap_or(0);

                // The address's host bits are already zero (`addr` is
                // normalized), so `addr | index` and `addr + index` agree for
                // every `index` in the valid `0 ..= back` range: no carry can
                // cross from `index` into `addr`'s fixed bits. Folding `addr`
                // into the bounds up front lets `next`/`next_back` advance
                // the packed address directly, without re-deriving it from a
                // separate host-index and base on every call.
                ContiguousIpv6NetworkAddrs { current: addr, last: addr | back }
            }
        }
    }
}

/// Bidirectional iterator over [`Ipv6Addr`] in a [`Contiguous<Ipv6Network>`].
///
/// Created by [`Contiguous::<Ipv6Network>::addrs`].
///
/// The [`Contiguous`] type invariant guarantees a contiguous mask, so unlike
/// [`crate::Ipv6NetworkAddrs`] this iterator carries no per-item mask-shape
/// branch, and need not re-derive each address from a separate base and
/// host-index: `base | index` and `base + index` agree for every valid
/// `index` (see
/// [`Contiguous::<Ipv6Network>::addrs`]), so the bounds are folded into
/// already-packed addresses once at construction time, and each step is a
/// plain integer increment/decrement -- the same ascending numeric order
/// [`crate::Ipv6NetworkAddrs`] produces for a contiguous mask.
///
/// When the iterator is exhausted it enters a sentinel state where
/// `current > last`, so every subsequent call to [`next`](Iterator::next) or
/// [`next_back`](DoubleEndedIterator::next_back) returns [`None`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContiguousIpv6NetworkAddrs {
    current: u128,
    last: u128,
}

impl ContiguousIpv6NetworkAddrs {
    #[cold]
    #[inline(never)]
    fn enter_wraparound_sentinel(&mut self) {
        self.current = 1;
        self.last = 0;
    }
}

impl Iterator for ContiguousIpv6NetworkAddrs {
    type Item = Ipv6Addr;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.current > self.last {
            return None;
        }

        let addr = self.current;
        self.current = self.current.wrapping_add(1);

        // Wrap-around means current was u128::MAX — only possible for a /0
        // network. Cold/never-inline so the common case compiles to a single
        // predicted-away branch instead of an unconditional cmov chain.
        if self.current == 0 {
            self.enter_wraparound_sentinel();
        }

        Some(Ipv6Addr::from_bits(addr))
    }

    #[inline]
    fn count(self) -> usize {
        let (n, ..) = self.size_hint();
        n
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.current > self.last {
            return (0, Some(0));
        }

        let rem = self.last.wrapping_sub(self.current).wrapping_add(1);

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

impl DoubleEndedIterator for ContiguousIpv6NetworkAddrs {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.current > self.last {
            return None;
        }

        let addr = self.last;

        if self.current == self.last {
            self.current = 1;
            self.last = 0;
        } else {
            self.last = self.last.wrapping_sub(1);
        }

        Some(Ipv6Addr::from_bits(addr))
    }
}

impl From<Contiguous<Ipv4Network>> for Contiguous<IpNetwork> {
    #[inline]
    fn from(net: Contiguous<Ipv4Network>) -> Self {
        let Contiguous(net) = net;
        Self(IpNetwork::from(net))
    }
}

impl From<Contiguous<Ipv6Network>> for Contiguous<IpNetwork> {
    #[inline]
    fn from(net: Contiguous<Ipv6Network>) -> Self {
        let Contiguous(net) = net;
        Self(IpNetwork::from(net))
    }
}

impl<T> Deref for Contiguous<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            Self(net) => net,
        }
    }
}

impl<T> Display for Contiguous<T>
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

impl FromStr for Contiguous<IpNetwork> {
    type Err = ContiguousIpNetParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl FromStr for Contiguous<Ipv4Network> {
    type Err = ContiguousIpNetParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl FromStr for Contiguous<Ipv6Network> {
    type Err = ContiguousIpNetParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Aggregates contiguous IPv4 networks in place into their minimal CIDR cover.
///
/// Returns the aggregated subslice: duplicates removed, contained networks
/// eliminated, and adjacent CIDR buddies merged, down to the unique smallest
/// set of contiguous blocks whose address union equals the input's.
///
/// Unlike [`crate::ipv4_aggregate`], every result stays contiguous
/// (class-preserving) and the cover is minimal. This is possible because
/// contiguous blocks form a laminar family — any two are nested or disjoint —
/// so the single sorted pass only ever merges against the running stack top,
/// giving `O(N log N)` instead of the general aggregate's worst-case quadratic
/// full-stack scan.
///
/// Zero allocations — the algorithm operates entirely within the input slice.
///
/// # Examples
///
/// ```
/// use netip::{Contiguous, Ipv4Network, ipv4_aggregate_contiguous};
///
/// let mut nets = [
///     Contiguous::<Ipv4Network>::parse("192.168.0.0/24").unwrap(),
///     Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap(),
///     Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap(),
///     Contiguous::<Ipv4Network>::parse("10.1.0.0/16").unwrap(),
/// ];
///
/// let result = ipv4_aggregate_contiguous(&mut nets);
/// assert_eq!(result.len(), 2);
/// assert_eq!(
///     result[0],
///     Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap()
/// );
/// assert_eq!(
///     result[1],
///     Contiguous::<Ipv4Network>::parse("192.168.0.0/23").unwrap()
/// );
/// ```
pub fn ipv4_aggregate_contiguous(nets: &mut [Contiguous<Ipv4Network>]) -> &mut [Contiguous<Ipv4Network>] {
    let len = ip_aggregate(nets);
    &mut nets[..len]
}

/// Aggregates contiguous IPv6 networks in place into their minimal CIDR cover.
///
/// Returns the aggregated subslice: duplicates removed, contained networks
/// eliminated, and adjacent CIDR buddies merged, down to the unique smallest
/// set of contiguous blocks whose address union equals the input's.
///
/// Unlike [`crate::ipv6_aggregate`], every result stays contiguous
/// (class-preserving) and the cover is minimal. This is possible because
/// contiguous blocks form a laminar family — any two are nested or disjoint —
/// so the single sorted pass only ever merges against the running stack top,
/// giving `O(N log N)` instead of the general aggregate's worst-case quadratic
/// full-stack scan.
///
/// Zero allocations — the algorithm operates entirely within the input slice.
///
/// # Examples
///
/// ```
/// use netip::{Contiguous, Ipv6Network, ipv6_aggregate_contiguous};
///
/// let mut nets = [
///     Contiguous::<Ipv6Network>::parse("2001:db8::/48").unwrap(),
///     Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap(),
///     Contiguous::<Ipv6Network>::parse("fe80::/10").unwrap(),
///     Contiguous::<Ipv6Network>::parse("fe80::/64").unwrap(),
/// ];
///
/// let result = ipv6_aggregate_contiguous(&mut nets);
/// assert_eq!(result.len(), 2);
/// assert_eq!(
///     result[0],
///     Contiguous::<Ipv6Network>::parse("2001:db8::/47").unwrap()
/// );
/// assert_eq!(
///     result[1],
///     Contiguous::<Ipv6Network>::parse("fe80::/10").unwrap()
/// );
/// ```
pub fn ipv6_aggregate_contiguous(nets: &mut [Contiguous<Ipv6Network>]) -> &mut [Contiguous<Ipv6Network>] {
    let len = ip_aggregate(nets);
    &mut nets[..len]
}

trait Aggregate: Ord + Copy {
    fn merge(&self, other: &Self) -> Option<Self>;
}

impl Aggregate for Ipv4Network {
    #[inline]
    fn merge(&self, other: &Self) -> Option<Self> {
        self.merge_by_lowest_mask_bit(other)
    }
}

impl Aggregate for Ipv6Network {
    #[inline]
    fn merge(&self, other: &Self) -> Option<Self> {
        self.merge_by_lowest_mask_bit(other)
    }
}

fn ip_aggregate<T: Aggregate>(nets: &mut [Contiguous<T>]) -> usize {
    if nets.len() <= 1 {
        return nets.len();
    }

    // Sorting by (addr, mask) ascending places every container immediately
    // before the blocks it contains and makes lowest-mask-bit buddies
    // adjacent.
    nets.sort_unstable();

    // Top-only cascade over the family of contiguous blocks.
    //
    // Sorted, the stack `nets[..w]` holds pairwise-disjoint blocks in
    // increasing address order, so the next candidate can only ever be
    // contained in, contain, or be the CIDR buddy of the current top — never a
    // deeper stack entry.
    //
    // Cascading against the top alone is therefore complete and runs in `O(N)`
    // after the sort, versus the general aggregate's per-candidate full-stack
    // scan.
    let mut w = 1usize;
    for r in 1..nets.len() {
        let mut current: T = *nets[r];

        while w > 0 {
            let top: T = *nets[w - 1];
            match top.merge(&current) {
                Some(merged) => {
                    current = merged;
                    w -= 1;
                }
                None => break,
            }
        }

        // NOTE: merging two contiguous networks yields a contiguous network —
        // containment returns one of the inputs unchanged, and a lowest-mask-bit
        // buddy merge only clears the mask's lowest set bit, leaving the
        // leading-ones run intact — so the result is known contiguous and is
        // re-wrapped without re-validating the invariant.
        nets[w] = Contiguous(current);
        w += 1;
    }

    w
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;
    use crate::net::test::{arb_contiguous_ipv6_network, arb_ipv4_network};

    #[test]
    fn contiguous_ipv4_addrs_slash24_matches_incrementing_u32() {
        let net = Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap();
        let mut ip = net.addr().to_bits();
        for a in net.addrs() {
            assert_eq!(a.to_bits(), ip);
            ip = ip.wrapping_add(1);
        }

        assert_eq!(256, net.addrs().count());
    }

    #[test]
    fn contiguous_ipv4_addrs_matches_deref_general() {
        let net = Contiguous::<Ipv4Network>::parse("192.168.1.0/28").unwrap();
        let expected: Vec<_> = (*net).addrs().collect();
        let actual: Vec<_> = net.addrs().collect();
        assert_eq!(expected, actual);
    }

    #[test]
    fn contiguous_ipv4_addrs_slash32_single() {
        let net = Contiguous::<Ipv4Network>::parse("10.0.0.1/32").unwrap();
        assert_eq!(net.addrs().next(), net.addrs().next_back());

        let mut addrs = net.addrs();
        assert_eq!(addrs.next(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(addrs.next(), None);
        assert_eq!(addrs.next_back(), None);
    }

    #[test]
    fn contiguous_ipv4_addrs_interleaved_exhausts_uniquely() {
        let net = Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap();
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

        assert_eq!(256, seen.len());
        seen.sort();
        seen.dedup();
        assert_eq!(256, seen.len());
    }

    #[test]
    fn contiguous_ipv4_addrs_unspecified_both_ends() {
        let net = Contiguous::<Ipv4Network>::parse("0.0.0.0/0").unwrap();
        let mut addrs = net.addrs();
        assert_eq!(addrs.next(), Some(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(addrs.next_back(), Some(Ipv4Addr::new(255, 255, 255, 255)));
    }

    // The /0 network's 2^32 addresses only fit a 64-bit `usize`, which is also
    // the only target family where `ExactSizeIterator` is implemented.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn contiguous_ipv4_addrs_unspecified_size_hint_is_exact_and_matches_len() {
        let net = Contiguous::<Ipv4Network>::parse("0.0.0.0/0").unwrap();
        let total = 1usize << 32;

        let addrs = net.addrs();
        assert_eq!(total, addrs.len());
        assert_eq!((total, Some(total)), addrs.size_hint());
        assert_eq!(total, net.addrs().count());

        let mut addrs = net.addrs();
        addrs.next();
        addrs.next_back();
        assert_eq!(total - 2, addrs.len());
        assert_eq!((total - 2, Some(total - 2)), addrs.size_hint());
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn contiguous_ipv4_addrs_size_hint_matches_len_across_drain() {
        let net = Contiguous::<Ipv4Network>::parse("192.168.1.0/30").unwrap();
        let mut addrs = net.addrs();

        for expected_len in (1..=4).rev() {
            assert_eq!(expected_len, addrs.len());
            assert_eq!((expected_len, Some(expected_len)), addrs.size_hint());
            addrs.next();
        }

        assert_eq!(0, addrs.len());
        assert_eq!((0, Some(0)), addrs.size_hint());
    }

    #[test]
    fn contiguous_ipv6_addrs_slash120_matches_incrementing_u128() {
        let net = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/120").unwrap();
        let mut ip = net.addr().to_bits();

        for addr in net.addrs() {
            assert_eq!(addr.to_bits(), ip);
            ip = ip.wrapping_add(1);
        }

        assert_eq!(256, net.addrs().count());
    }

    #[test]
    fn contiguous_ipv6_addrs_matches_deref_general() {
        let net = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/124").unwrap();
        let expected: Vec<_> = (*net).addrs().collect();
        let actual: Vec<_> = net.addrs().collect();
        assert_eq!(expected, actual);
    }

    #[test]
    fn contiguous_ipv6_addrs_slash128_single() {
        let net = Contiguous::<Ipv6Network>::parse("::1/128").unwrap();
        assert_eq!(net.addrs().next(), net.addrs().next_back());

        let mut addrs = net.addrs();
        assert_eq!(addrs.next(), Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(addrs.next(), None);
        assert_eq!(addrs.next_back(), None);
    }

    #[test]
    fn contiguous_ipv6_addrs_interleaved_exhausts_uniquely() {
        let net = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/120").unwrap();
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

        assert_eq!(256, seen.len());
        seen.sort();
        seen.dedup();
        assert_eq!(256, seen.len());
    }

    #[test]
    fn contiguous_ipv6_addrs_unspecified_both_ends() {
        let net = Contiguous::<Ipv6Network>::parse("::/0").unwrap();
        let mut addrs = net.addrs();
        assert_eq!(addrs.next(), Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)));
        assert_eq!(
            addrs.next_back(),
            Some(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
            ))
        );
    }

    #[test]
    fn test_contiguous_ip_network_parse_v4() {
        let expected = Contiguous(Ipv4Network::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(255, 255, 255, 0),
        ));

        assert_eq!(expected, Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap(),);
    }

    #[test]
    fn test_contiguous_ip_network_parse_v4_invalid() {
        assert_eq!(
            ContiguousIpNetParseError::NonContiguousNetwork,
            Contiguous::<Ipv4Network>::parse("192.168.0.1/255.255.0.255").unwrap_err(),
        );
    }

    #[test]
    fn test_contiguous_ip_network_parse_v6() {
        let expected = Contiguous(Ipv6Network::new(
            Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0, 0, 0, 0),
        ));

        assert_eq!(expected, Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap(),);
    }

    #[test]
    fn test_contiguous_ip_network_parse_v6_invalid() {
        assert_eq!(
            ContiguousIpNetParseError::NonContiguousNetwork,
            Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap_err(),
        );
    }

    #[test]
    fn contiguous_from_v4() {
        let v4: Contiguous<Ipv4Network> = Contiguous::<Ipv4Network>::parse("10.0.0.0/24").unwrap();
        let ip: Contiguous<IpNetwork> = Contiguous::<IpNetwork>::from(v4);
        assert_eq!("10.0.0.0/24", ip.to_string());
    }

    #[test]
    fn contiguous_from_v6() {
        let v6: Contiguous<Ipv6Network> = Contiguous::<Ipv6Network>::parse("2001:db8::/64").unwrap();
        let ip: Contiguous<IpNetwork> = Contiguous::<IpNetwork>::from(v6);
        assert_eq!("2001:db8::/64", ip.to_string());
    }

    // The following `contiguous_*_is_contiguous_override_*` and
    // `contiguous_*_to_contiguous_override_*` tests pin down that the
    // constant-time `Contiguous<T>` overrides return exactly what the
    // `Deref`-ed inner type would compute. Method resolution picks the
    // override for `net.is_contiguous()` / `net.to_contiguous()`, so the
    // inner computation is reached explicitly via `(*net)`.

    #[test]
    fn contiguous_ipv4_is_contiguous_override_matches_inner() {
        let net = Contiguous::<Ipv4Network>::parse("192.168.0.0/24").unwrap();
        assert!(net.is_contiguous());
        assert_eq!(net.is_contiguous(), (*net).is_contiguous());
    }

    #[test]
    fn contiguous_ipv4_to_contiguous_override_matches_inner() {
        let net = Contiguous::<Ipv4Network>::parse("192.168.0.0/24").unwrap();
        assert_eq!(*net, net.to_contiguous());
        assert_eq!(net.to_contiguous(), (*net).to_contiguous());
    }

    #[test]
    fn contiguous_ipv4_overrides_hold_at_boundary_prefixes() {
        let host = Contiguous::<Ipv4Network>::parse("10.0.0.1/32").unwrap();
        let unspecified = Contiguous::<Ipv4Network>::parse("0.0.0.0/0").unwrap();

        assert!(host.is_contiguous());
        assert!(unspecified.is_contiguous());
        assert_eq!(*host, host.to_contiguous());
        assert_eq!(*unspecified, unspecified.to_contiguous());
    }

    #[test]
    fn contiguous_ipv6_is_contiguous_override_matches_inner() {
        let net = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        assert!(net.is_contiguous());
        assert_eq!(net.is_contiguous(), (*net).is_contiguous());
    }

    #[test]
    fn contiguous_ipv6_to_contiguous_override_matches_inner() {
        let net = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        assert_eq!(*net, net.to_contiguous());
        assert_eq!(net.to_contiguous(), (*net).to_contiguous());
    }

    #[test]
    fn contiguous_ipv6_overrides_hold_at_boundary_prefixes() {
        let host = Contiguous::<Ipv6Network>::parse("::1/128").unwrap();
        let unspecified = Contiguous::<Ipv6Network>::parse("::/0").unwrap();

        assert!(host.is_contiguous());
        assert!(unspecified.is_contiguous());
        assert_eq!(*host, host.to_contiguous());
        assert_eq!(*unspecified, unspecified.to_contiguous());
    }

    #[test]
    fn contiguous_ip_overrides_match_inner_v4() {
        let v4 = Contiguous::<Ipv4Network>::parse("192.168.0.0/24").unwrap();
        let net = Contiguous::<IpNetwork>::from(v4);

        assert!(net.is_contiguous());
        assert_eq!(net.is_contiguous(), (*net).is_contiguous());
        assert_eq!(*net, net.to_contiguous());
        assert_eq!(net.to_contiguous(), (*net).to_contiguous());
    }

    #[test]
    fn contiguous_ip_overrides_match_inner_v6() {
        let v6 = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let net = Contiguous::<IpNetwork>::from(v6);

        assert!(net.is_contiguous());
        assert_eq!(net.is_contiguous(), (*net).is_contiguous());
        assert_eq!(*net, net.to_contiguous());
        assert_eq!(net.to_contiguous(), (*net).to_contiguous());
    }

    // The following `contiguous_*_contains_*` tests pin down that the
    // constant-time `Contiguous<T>::contains` override (integer mask
    // comparison) returns exactly what the `Deref`-ed inner type's general
    // `contains` (`mask & mask == mask`) would compute.

    #[test]
    fn contiguous_ipv4_contains_override_matches_inner() {
        let a = Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap();
        let b = Contiguous::<Ipv4Network>::parse("10.1.0.0/16").unwrap();

        assert!(a.contains(&b));
        assert_eq!(a.contains(&b), (*a).contains(&b));

        assert!(!b.contains(&a));
        assert_eq!(b.contains(&a), (*b).contains(&a));
    }

    #[test]
    fn contiguous_ipv4_contains_equal_networks() {
        let a = Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap();
        let b = Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap();

        assert!(a.contains(&b));
        assert_eq!(a.contains(&b), (*a).contains(&b));
    }

    #[test]
    fn contiguous_ipv4_contains_boundary_prefixes() {
        let universe = Contiguous::<Ipv4Network>::parse("0.0.0.0/0").unwrap();
        let host = Contiguous::<Ipv4Network>::parse("10.0.0.1/32").unwrap();
        let other_host = Contiguous::<Ipv4Network>::parse("10.0.0.2/32").unwrap();

        assert!(universe.contains(&host));
        assert_eq!(universe.contains(&host), (*universe).contains(&host));

        assert!(!host.contains(&universe));
        assert_eq!(host.contains(&universe), (*host).contains(&universe));

        assert!(host.contains(&host));
        assert!(!host.contains(&other_host));
        assert_eq!(host.contains(&other_host), (*host).contains(&other_host));
    }

    #[test]
    fn contiguous_ipv6_contains_override_matches_inner() {
        let a = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let b = Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap();

        assert!(a.contains(&b));
        assert_eq!(a.contains(&b), (*a).contains(&b));

        assert!(!b.contains(&a));
        assert_eq!(b.contains(&a), (*b).contains(&a));
    }

    #[test]
    fn contiguous_ipv6_contains_equal_networks() {
        let a = Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap();
        let b = Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap();

        assert!(a.contains(&b));
        assert_eq!(a.contains(&b), (*a).contains(&b));
    }

    #[test]
    fn contiguous_ipv6_contains_boundary_prefixes() {
        let universe = Contiguous::<Ipv6Network>::parse("::/0").unwrap();
        let host = Contiguous::<Ipv6Network>::parse("::1/128").unwrap();
        let other_host = Contiguous::<Ipv6Network>::parse("::2/128").unwrap();

        assert!(universe.contains(&host));
        assert_eq!(universe.contains(&host), (*universe).contains(&host));

        assert!(!host.contains(&universe));
        assert_eq!(host.contains(&universe), (*host).contains(&universe));

        assert!(host.contains(&host));
        assert!(!host.contains(&other_host));
        assert_eq!(host.contains(&other_host), (*host).contains(&other_host));
    }

    #[test]
    fn contiguous_ip_contains_matches_inner_v4() {
        let a = Contiguous::<Ipv4Network>::parse("192.168.0.0/16").unwrap();
        let b = Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap();
        let net_a = Contiguous::<IpNetwork>::from(a);
        let net_b = Contiguous::<IpNetwork>::from(b);

        assert!(net_a.contains(&net_b));
        assert_eq!(net_a.contains(&net_b), (*net_a).contains(&net_b));

        assert!(!net_b.contains(&net_a));
        assert_eq!(net_b.contains(&net_a), (*net_b).contains(&net_a));
    }

    #[test]
    fn contiguous_ip_contains_matches_inner_v6() {
        let a = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let b = Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap();
        let net_a = Contiguous::<IpNetwork>::from(a);
        let net_b = Contiguous::<IpNetwork>::from(b);

        assert!(net_a.contains(&net_b));
        assert_eq!(net_a.contains(&net_b), (*net_a).contains(&net_b));

        assert!(!net_b.contains(&net_a));
        assert_eq!(net_b.contains(&net_a), (*net_b).contains(&net_a));
    }

    #[test]
    fn contiguous_ip_contains_mixed_family_is_false() {
        let v4 = Contiguous::<Ipv4Network>::parse("192.168.0.0/16").unwrap();
        let v6 = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let net_v4 = Contiguous::<IpNetwork>::from(v4);
        let net_v6 = Contiguous::<IpNetwork>::from(v6);

        assert!(!net_v4.contains(&net_v6));
        assert_eq!(net_v4.contains(&net_v6), (*net_v4).contains(&net_v6));

        assert!(!net_v6.contains(&net_v4));
        assert_eq!(net_v6.contains(&net_v4), (*net_v6).contains(&net_v4));
    }

    // Classic fixpoint CIDR aggregation, used as an independent oracle for
    // `ipv4_aggregate_contiguous`: repeatedly absorb containment and merge CIDR
    // buddies until nothing merges, then sort the survivors. Deliberately a
    // plain quadratic reference and kept byte-stable across changes to the fast
    // implementation.
    fn ipv4_aggregate_contiguous_reference(input: &[Contiguous<Ipv4Network>]) -> Vec<Ipv4Network> {
        let mut nets: Vec<Ipv4Network> = input.iter().map(|net| **net).collect();
        loop {
            let mut merge = None;
            'scan: for i in 0..nets.len() {
                for j in (i + 1)..nets.len() {
                    if let Some(parent) = nets[i].merge_by_lowest_mask_bit(&nets[j]) {
                        merge = Some((i, j, parent));
                        break 'scan;
                    }
                }
            }
            match merge {
                Some((i, j, parent)) => {
                    nets[i] = parent;
                    nets.remove(j);
                }
                None => break,
            }
        }
        nets.sort_unstable();
        nets
    }

    fn ipv6_aggregate_contiguous_reference(input: &[Contiguous<Ipv6Network>]) -> Vec<Ipv6Network> {
        let mut nets: Vec<Ipv6Network> = input.iter().map(|net| **net).collect();
        loop {
            let mut merge = None;
            'scan: for i in 0..nets.len() {
                for j in (i + 1)..nets.len() {
                    if let Some(parent) = nets[i].merge_by_lowest_mask_bit(&nets[j]) {
                        merge = Some((i, j, parent));
                        break 'scan;
                    }
                }
            }
            match merge {
                Some((i, j, parent)) => {
                    nets[i] = parent;
                    nets.remove(j);
                }
                None => break,
            }
        }
        nets.sort_unstable();
        nets
    }

    fn ipv4_contiguous_inner_sorted(nets: &[Contiguous<Ipv4Network>]) -> Vec<Ipv4Network> {
        let mut inner: Vec<Ipv4Network> = nets.iter().map(|net| **net).collect();
        inner.sort_unstable();
        inner
    }

    fn ipv6_contiguous_inner_sorted(nets: &[Contiguous<Ipv6Network>]) -> Vec<Ipv6Network> {
        let mut inner: Vec<Ipv6Network> = nets.iter().map(|net| **net).collect();
        inner.sort_unstable();
        inner
    }

    // Contiguous IPv4 CIDR blocks confined to 192.168.0.0/20 (a 4096-address
    // window) with prefixes 24..=32. The tight window makes containment and
    // buddy cascades frequent, while capping each block at 256 addresses keeps a
    // whole collection's address union small enough to brute-force.
    fn arb_clustered_contiguous_ipv4_network() -> impl Strategy<Value = Contiguous<Ipv4Network>> {
        (any::<u32>(), 24u8..=32).prop_map(|(addr, prefix)| {
            let addr = (192 << 24) | (168 << 16) | (addr & 0x0FFF);
            Contiguous(Ipv4Network::try_from((Ipv4Addr::from_bits(addr), prefix)).unwrap())
        })
    }

    fn arb_clustered_contiguous_ipv4_networks() -> impl Strategy<Value = Vec<Contiguous<Ipv4Network>>> {
        prop::collection::vec(arb_clustered_contiguous_ipv4_network(), 0..=24)
    }

    // Contiguous IPv6 CIDR blocks confined to 2001:db8::/116 with prefixes
    // 120..=128, mirroring the IPv4 clustering above.
    fn arb_clustered_contiguous_ipv6_network() -> impl Strategy<Value = Contiguous<Ipv6Network>> {
        (any::<u128>(), 120u8..=128).prop_map(|(addr, prefix)| {
            let addr = 0x2001_0db8_0000_0000_0000_0000_0000_0000u128 | (addr & 0x0FFF);
            Contiguous(Ipv6Network::try_from((Ipv6Addr::from_bits(addr), prefix)).unwrap())
        })
    }

    fn arb_clustered_contiguous_ipv6_networks() -> impl Strategy<Value = Vec<Contiguous<Ipv6Network>>> {
        prop::collection::vec(arb_clustered_contiguous_ipv6_network(), 0..=24)
    }

    #[test]
    fn ipv4_aggregate_contiguous_empty() {
        let result = ipv4_aggregate_contiguous(&mut []);
        assert!(result.is_empty());
    }

    #[test]
    fn ipv4_aggregate_contiguous_single() {
        let net = Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap();
        let mut nets = [net];
        let result = ipv4_aggregate_contiguous(&mut nets);
        assert_eq!(result, &[net]);
    }

    #[test]
    fn ipv4_aggregate_contiguous_duplicates() {
        let net = Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap();
        let mut nets = [net, net, net];
        let result = ipv4_aggregate_contiguous(&mut nets);
        assert_eq!(result, &[net]);
    }

    #[test]
    fn ipv4_aggregate_contiguous_containment() {
        let mut nets = [
            Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap(),
            Contiguous::<Ipv4Network>::parse("10.1.0.0/16").unwrap(),
            Contiguous::<Ipv4Network>::parse("10.1.1.0/24").unwrap(),
        ];
        let result = ipv4_aggregate_contiguous(&mut nets);
        assert_eq!(result, &[Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap()]);
    }

    #[test]
    fn ipv4_aggregate_contiguous_single_buddy_merge() {
        let mut nets = [
            Contiguous::<Ipv4Network>::parse("192.168.0.0/24").unwrap(),
            Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap(),
        ];
        let result = ipv4_aggregate_contiguous(&mut nets);
        assert_eq!(result, &[Contiguous::<Ipv4Network>::parse("192.168.0.0/23").unwrap()]);
    }

    #[test]
    fn ipv4_aggregate_contiguous_multi_level_cascade() {
        let mut nets = [
            Contiguous::<Ipv4Network>::parse("192.168.0.0/24").unwrap(),
            Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap(),
            Contiguous::<Ipv4Network>::parse("192.168.2.0/24").unwrap(),
            Contiguous::<Ipv4Network>::parse("192.168.3.0/24").unwrap(),
        ];
        let result = ipv4_aggregate_contiguous(&mut nets);
        assert_eq!(result, &[Contiguous::<Ipv4Network>::parse("192.168.0.0/22").unwrap()]);
    }

    #[test]
    fn ipv4_aggregate_contiguous_non_adjacent() {
        let mut nets = [
            Contiguous::<Ipv4Network>::parse("192.168.0.0/24").unwrap(),
            Contiguous::<Ipv4Network>::parse("192.168.3.0/24").unwrap(),
        ];
        let result = ipv4_aggregate_contiguous(&mut nets);
        assert_eq!(
            result,
            &[
                Contiguous::<Ipv4Network>::parse("192.168.0.0/24").unwrap(),
                Contiguous::<Ipv4Network>::parse("192.168.3.0/24").unwrap(),
            ]
        );
    }

    #[test]
    fn ipv4_aggregate_contiguous_already_minimal() {
        let mut nets = [
            Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap(),
            Contiguous::<Ipv4Network>::parse("172.16.0.0/12").unwrap(),
            Contiguous::<Ipv4Network>::parse("192.168.0.0/16").unwrap(),
        ];
        let result = ipv4_aggregate_contiguous(&mut nets);
        assert_eq!(
            result,
            &[
                Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap(),
                Contiguous::<Ipv4Network>::parse("172.16.0.0/12").unwrap(),
                Contiguous::<Ipv4Network>::parse("192.168.0.0/16").unwrap(),
            ]
        );
    }

    #[test]
    fn ipv4_aggregate_contiguous_mixed_containment_and_merge() {
        let mut nets = [
            Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap(),
            Contiguous::<Ipv4Network>::parse("10.1.0.0/16").unwrap(),
            Contiguous::<Ipv4Network>::parse("192.168.0.0/24").unwrap(),
            Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap(),
        ];
        let result = ipv4_aggregate_contiguous(&mut nets);
        assert_eq!(
            result,
            &[
                Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap(),
                Contiguous::<Ipv4Network>::parse("192.168.0.0/23").unwrap(),
            ]
        );
    }

    #[test]
    fn ipv4_aggregate_contiguous_default_route_absorbs_all() {
        let mut nets = [
            Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap(),
            Contiguous::<Ipv4Network>::parse("0.0.0.0/0").unwrap(),
            Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap(),
        ];
        let result = ipv4_aggregate_contiguous(&mut nets);
        assert_eq!(result, &[Contiguous::<Ipv4Network>::parse("0.0.0.0/0").unwrap()]);
    }

    #[test]
    fn ipv4_aggregate_contiguous_host_routes_merge() {
        let mut nets = [
            Contiguous::<Ipv4Network>::parse("10.0.0.0/32").unwrap(),
            Contiguous::<Ipv4Network>::parse("10.0.0.1/32").unwrap(),
        ];
        let result = ipv4_aggregate_contiguous(&mut nets);
        assert_eq!(result, &[Contiguous::<Ipv4Network>::parse("10.0.0.0/31").unwrap()]);
    }

    #[test]
    fn ipv4_aggregate_contiguous_host_routes_non_adjacent() {
        let mut nets = [
            Contiguous::<Ipv4Network>::parse("10.0.0.0/32").unwrap(),
            Contiguous::<Ipv4Network>::parse("10.0.0.2/32").unwrap(),
        ];
        let result = ipv4_aggregate_contiguous(&mut nets);
        assert_eq!(
            result,
            &[
                Contiguous::<Ipv4Network>::parse("10.0.0.0/32").unwrap(),
                Contiguous::<Ipv4Network>::parse("10.0.0.2/32").unwrap(),
            ]
        );
    }

    #[test]
    fn ipv6_aggregate_contiguous_empty() {
        let result = ipv6_aggregate_contiguous(&mut []);
        assert!(result.is_empty());
    }

    #[test]
    fn ipv6_aggregate_contiguous_single() {
        let net = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let mut nets = [net];
        let result = ipv6_aggregate_contiguous(&mut nets);
        assert_eq!(result, &[net]);
    }

    #[test]
    fn ipv6_aggregate_contiguous_duplicates() {
        let net = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let mut nets = [net, net, net];
        let result = ipv6_aggregate_contiguous(&mut nets);
        assert_eq!(result, &[net]);
    }

    #[test]
    fn ipv6_aggregate_contiguous_containment() {
        let mut nets = [
            Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap(),
            Contiguous::<Ipv6Network>::parse("2001:db8::/48").unwrap(),
            Contiguous::<Ipv6Network>::parse("2001:db8:0:1::/64").unwrap(),
        ];
        let result = ipv6_aggregate_contiguous(&mut nets);
        assert_eq!(result, &[Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap()]);
    }

    #[test]
    fn ipv6_aggregate_contiguous_single_buddy_merge() {
        let mut nets = [
            Contiguous::<Ipv6Network>::parse("2001:db8::/48").unwrap(),
            Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap(),
        ];
        let result = ipv6_aggregate_contiguous(&mut nets);
        assert_eq!(result, &[Contiguous::<Ipv6Network>::parse("2001:db8::/47").unwrap()]);
    }

    #[test]
    fn ipv6_aggregate_contiguous_multi_level_cascade() {
        let mut nets = [
            Contiguous::<Ipv6Network>::parse("2001:db8:0:0::/64").unwrap(),
            Contiguous::<Ipv6Network>::parse("2001:db8:0:1::/64").unwrap(),
            Contiguous::<Ipv6Network>::parse("2001:db8:0:2::/64").unwrap(),
            Contiguous::<Ipv6Network>::parse("2001:db8:0:3::/64").unwrap(),
        ];
        let result = ipv6_aggregate_contiguous(&mut nets);
        assert_eq!(result, &[Contiguous::<Ipv6Network>::parse("2001:db8::/62").unwrap()]);
    }

    #[test]
    fn ipv6_aggregate_contiguous_non_adjacent() {
        let mut nets = [
            Contiguous::<Ipv6Network>::parse("2001:db8:0:0::/64").unwrap(),
            Contiguous::<Ipv6Network>::parse("2001:db8:0:3::/64").unwrap(),
        ];
        let result = ipv6_aggregate_contiguous(&mut nets);
        assert_eq!(
            result,
            &[
                Contiguous::<Ipv6Network>::parse("2001:db8:0:0::/64").unwrap(),
                Contiguous::<Ipv6Network>::parse("2001:db8:0:3::/64").unwrap(),
            ]
        );
    }

    #[test]
    fn ipv6_aggregate_contiguous_already_minimal() {
        let mut nets = [
            Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap(),
            Contiguous::<Ipv6Network>::parse("2001:dba::/32").unwrap(),
            Contiguous::<Ipv6Network>::parse("fe80::/10").unwrap(),
        ];
        let result = ipv6_aggregate_contiguous(&mut nets);
        assert_eq!(
            result,
            &[
                Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap(),
                Contiguous::<Ipv6Network>::parse("2001:dba::/32").unwrap(),
                Contiguous::<Ipv6Network>::parse("fe80::/10").unwrap(),
            ]
        );
    }

    #[test]
    fn ipv6_aggregate_contiguous_mixed_containment_and_merge() {
        let mut nets = [
            Contiguous::<Ipv6Network>::parse("fe80::/10").unwrap(),
            Contiguous::<Ipv6Network>::parse("fe80::/64").unwrap(),
            Contiguous::<Ipv6Network>::parse("2001:db8::/48").unwrap(),
            Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap(),
        ];
        let result = ipv6_aggregate_contiguous(&mut nets);
        assert_eq!(
            result,
            &[
                Contiguous::<Ipv6Network>::parse("2001:db8::/47").unwrap(),
                Contiguous::<Ipv6Network>::parse("fe80::/10").unwrap(),
            ]
        );
    }

    #[test]
    fn ipv6_aggregate_contiguous_default_route_absorbs_all() {
        let mut nets = [
            Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap(),
            Contiguous::<Ipv6Network>::parse("::/0").unwrap(),
            Contiguous::<Ipv6Network>::parse("fe80::/10").unwrap(),
        ];
        let result = ipv6_aggregate_contiguous(&mut nets);
        assert_eq!(result, &[Contiguous::<Ipv6Network>::parse("::/0").unwrap()]);
    }

    #[test]
    fn ipv6_aggregate_contiguous_host_routes_merge() {
        let mut nets = [
            Contiguous::<Ipv6Network>::parse("2001:db8::/128").unwrap(),
            Contiguous::<Ipv6Network>::parse("2001:db8::1/128").unwrap(),
        ];
        let result = ipv6_aggregate_contiguous(&mut nets);
        assert_eq!(result, &[Contiguous::<Ipv6Network>::parse("2001:db8::/127").unwrap()]);
    }

    #[test]
    fn ipv6_aggregate_contiguous_host_routes_non_adjacent() {
        let mut nets = [
            Contiguous::<Ipv6Network>::parse("2001:db8::/128").unwrap(),
            Contiguous::<Ipv6Network>::parse("2001:db8::2/128").unwrap(),
        ];
        let result = ipv6_aggregate_contiguous(&mut nets);
        assert_eq!(
            result,
            &[
                Contiguous::<Ipv6Network>::parse("2001:db8::/128").unwrap(),
                Contiguous::<Ipv6Network>::parse("2001:db8::2/128").unwrap(),
            ]
        );
    }

    fn arb_contiguous_ipv4_network() -> impl Strategy<Value = Contiguous<Ipv4Network>> {
        arb_ipv4_network().prop_map(|net| Contiguous(net.to_contiguous()))
    }

    fn arb_contiguous_ip_network() -> impl Strategy<Value = Contiguous<IpNetwork>> {
        prop_oneof![
            arb_contiguous_ipv4_network().prop_map(Contiguous::<IpNetwork>::from),
            arb_contiguous_ipv6_network().prop_map(Contiguous::<IpNetwork>::from),
        ]
    }

    // Bounded to at most 8 host bits (256 addresses) so `addrs()` can be
    // fully collected/brute-forced in a proptest case without allocating an
    // unbounded amount of memory.
    fn arb_small_contiguous_ipv4_network() -> impl Strategy<Value = Contiguous<Ipv4Network>> {
        (any::<u32>(), 24u8..=32)
            .prop_map(|(addr, prefix)| Contiguous(Ipv4Network::try_from((Ipv4Addr::from_bits(addr), prefix)).unwrap()))
    }

    fn arb_small_contiguous_ipv6_network() -> impl Strategy<Value = Contiguous<Ipv6Network>> {
        (any::<u128>(), 120u8..=128)
            .prop_map(|(addr, prefix)| Contiguous(Ipv6Network::try_from((Ipv6Addr::from_bits(addr), prefix)).unwrap()))
    }

    proptest! {
        #[test]
        fn prop_contiguous_ipv4_addrs_matches_general_forward(net in arb_small_contiguous_ipv4_network()) {
            let expected: Vec<_> = (*net).addrs().collect();
            let actual: Vec<_> = net.addrs().collect();
            prop_assert_eq!(expected, actual);
        }

        #[test]
        fn prop_contiguous_ipv4_addrs_matches_general_reverse(net in arb_small_contiguous_ipv4_network()) {
            let expected: Vec<_> = (*net).addrs().rev().collect();
            let actual: Vec<_> = net.addrs().rev().collect();
            prop_assert_eq!(expected, actual);
        }

        #[test]
        fn prop_contiguous_ipv4_addrs_matches_general_interleaved(net in arb_small_contiguous_ipv4_network()) {
            let mut expected = (*net).addrs();
            let mut actual = net.addrs();
            loop {
                let (e_front, a_front) = (expected.next(), actual.next());
                prop_assert_eq!(e_front, a_front);

                let (e_back, a_back) = (expected.next_back(), actual.next_back());
                prop_assert_eq!(e_back, a_back);

                if e_front.is_none() && e_back.is_none() {
                    break;
                }
            }
        }

        #[test]
        fn prop_contiguous_ipv4_addrs_double_reverse_is_identity(net in arb_small_contiguous_ipv4_network()) {
            let forward: Vec<_> = net.addrs().collect();
            let mut double_reversed: Vec<_> = net.addrs().rev().collect();
            double_reversed.reverse();
            prop_assert_eq!(forward, double_reversed);
        }

        #[test]
        fn prop_contiguous_ipv4_addrs_every_item_matches_mask(net in arb_small_contiguous_ipv4_network()) {
            let (net_addr, mask) = (*net).to_bits();
            for addr in net.addrs() {
                prop_assert_eq!(addr.to_bits() & mask, net_addr);
            }
        }

        #[cfg(target_pointer_width = "64")]
        #[test]
        fn prop_contiguous_ipv4_addrs_len_matches_host_bits(net in arb_small_contiguous_ipv4_network()) {
            let (.., mask) = (*net).to_bits();
            let expected_len = 1usize << (!mask).count_ones();
            prop_assert_eq!(net.addrs().len(), expected_len);
            prop_assert_eq!(net.addrs().count(), expected_len);
        }

        // Covers every prefix, including the /0 network whose 2^32 addresses
        // are the reason `ExactSizeIterator` is 64-bit-only here.
        #[cfg(target_pointer_width = "64")]
        #[test]
        fn prop_contiguous_ipv4_addrs_size_hint_equals_len(net in arb_contiguous_ipv4_network()) {
            let (.., mask) = (*net).to_bits();
            let expected_len = 1u64 << (!mask).count_ones();
            let addrs = net.addrs();
            let len = addrs.len();

            prop_assert_eq!(expected_len, len as u64);
            prop_assert_eq!((len, Some(len)), addrs.size_hint());
            prop_assert_eq!(len, net.addrs().count());
        }

        // The upper `2^128 / 2^64` counts do not fit a `usize`, so the hint
        // saturates to an honest lower bound instead of an exact length.
        #[test]
        fn prop_contiguous_ipv6_addrs_size_hint_is_exact_or_saturating(net in arb_contiguous_ipv6_network()) {
            let (.., mask) = (*net).to_bits();
            let host_bits = (!mask).count_ones();
            let exact = 1u128.checked_shl(host_bits).and_then(|total| usize::try_from(total).ok());

            match exact {
                Some(total) => prop_assert_eq!((total, Some(total)), net.addrs().size_hint()),
                None => prop_assert_eq!((usize::MAX, None), net.addrs().size_hint()),
            }
        }

        #[test]
        fn prop_contiguous_ipv4_addrs_matches_brute_force_grid(net in arb_small_contiguous_ipv4_network()) {
            let (net_addr, mask) = (*net).to_bits();
            let host_bits = (!mask).count_ones();

            let mut expected: Vec<u32> = (0u32..(1u32 << host_bits)).map(|h| net_addr | h).collect();
            let mut actual: Vec<u32> = net.addrs().map(|a| a.to_bits()).collect();
            expected.sort_unstable();
            expected.dedup();
            actual.sort_unstable();
            actual.dedup();

            prop_assert_eq!(expected, actual);
        }

        #[test]
        fn prop_contiguous_ipv6_addrs_matches_general_forward(net in arb_small_contiguous_ipv6_network()) {
            let expected: Vec<_> = (*net).addrs().collect();
            let actual: Vec<_> = net.addrs().collect();
            prop_assert_eq!(expected, actual);
        }

        #[test]
        fn prop_contiguous_ipv6_addrs_matches_general_reverse(net in arb_small_contiguous_ipv6_network()) {
            let expected: Vec<_> = (*net).addrs().rev().collect();
            let actual: Vec<_> = net.addrs().rev().collect();
            prop_assert_eq!(expected, actual);
        }

        #[test]
        fn prop_contiguous_ipv6_addrs_matches_general_interleaved(net in arb_small_contiguous_ipv6_network()) {
            let mut expected = (*net).addrs();
            let mut actual = net.addrs();
            loop {
                let (e_front, a_front) = (expected.next(), actual.next());
                prop_assert_eq!(e_front, a_front);

                let (e_back, a_back) = (expected.next_back(), actual.next_back());
                prop_assert_eq!(e_back, a_back);

                if e_front.is_none() && e_back.is_none() {
                    break;
                }
            }
        }

        #[test]
        fn prop_contiguous_ipv6_addrs_double_reverse_is_identity(net in arb_small_contiguous_ipv6_network()) {
            let forward: Vec<_> = net.addrs().collect();
            let mut double_reversed: Vec<_> = net.addrs().rev().collect();
            double_reversed.reverse();
            prop_assert_eq!(forward, double_reversed);
        }

        #[test]
        fn prop_contiguous_ipv6_addrs_every_item_matches_mask(net in arb_small_contiguous_ipv6_network()) {
            let (net_addr, mask) = (*net).to_bits();
            for addr in net.addrs() {
                prop_assert_eq!(addr.to_bits() & mask, net_addr);
            }
        }

        #[test]
        fn prop_contiguous_ipv6_addrs_len_matches_host_bits(net in arb_small_contiguous_ipv6_network()) {
            let (.., mask) = (*net).to_bits();
            let expected_len = 1usize << (!mask).count_ones();
            prop_assert_eq!(net.addrs().count(), expected_len);
        }

        #[test]
        fn prop_contiguous_ipv6_addrs_matches_brute_force_grid(net in arb_small_contiguous_ipv6_network()) {
            let (net_addr, mask) = (*net).to_bits();
            let host_bits = (!mask).count_ones();

            let mut expected: Vec<u128> = (0u128..(1u128 << host_bits)).map(|h| net_addr | h).collect();
            let mut actual: Vec<u128> = net.addrs().map(|a| a.to_bits()).collect();
            expected.sort_unstable();
            expected.dedup();
            actual.sort_unstable();
            actual.dedup();

            prop_assert_eq!(expected, actual);
        }
    }

    proptest! {
        #[test]
        fn prop_contiguous_ipv4_is_contiguous_always_true(net in arb_contiguous_ipv4_network()) {
            prop_assert!(net.is_contiguous());
            prop_assert_eq!(net.is_contiguous(), (*net).is_contiguous());
        }

        #[test]
        fn prop_contiguous_ipv4_to_contiguous_is_identity(net in arb_contiguous_ipv4_network()) {
            prop_assert_eq!(net.to_contiguous(), *net);
            prop_assert_eq!(net.to_contiguous(), (*net).to_contiguous());
        }

        #[test]
        fn prop_contiguous_ipv6_is_contiguous_always_true(net in arb_contiguous_ipv6_network()) {
            prop_assert!(net.is_contiguous());
            prop_assert_eq!(net.is_contiguous(), (*net).is_contiguous());
        }

        #[test]
        fn prop_contiguous_ipv6_to_contiguous_is_identity(net in arb_contiguous_ipv6_network()) {
            prop_assert_eq!(net.to_contiguous(), *net);
            prop_assert_eq!(net.to_contiguous(), (*net).to_contiguous());
        }

        #[test]
        fn prop_contiguous_ip_is_contiguous_always_true(net in arb_contiguous_ip_network()) {
            prop_assert!(net.is_contiguous());
            prop_assert_eq!(net.is_contiguous(), (*net).is_contiguous());
        }

        #[test]
        fn prop_contiguous_ip_to_contiguous_is_identity(net in arb_contiguous_ip_network()) {
            prop_assert_eq!(net.to_contiguous(), *net);
            prop_assert_eq!(net.to_contiguous(), (*net).to_contiguous());
        }

        #[test]
        fn prop_contiguous_ipv4_contains_matches_inner(
            a in arb_contiguous_ipv4_network(),
            b in arb_contiguous_ipv4_network(),
        ) {
            prop_assert_eq!(a.contains(&b), (*a).contains(&b));
        }

        #[test]
        fn prop_contiguous_ipv6_contains_matches_inner(
            a in arb_contiguous_ipv6_network(),
            b in arb_contiguous_ipv6_network(),
        ) {
            prop_assert_eq!(a.contains(&b), (*a).contains(&b));
        }

        #[test]
        fn prop_contiguous_ip_contains_matches_inner(
            a in arb_contiguous_ip_network(),
            b in arb_contiguous_ip_network(),
        ) {
            prop_assert_eq!(a.contains(&b), (*a).contains(&b));
        }

        #[test]
        fn prop_ipv4_aggregate_contiguous_preserves_addresses(nets in arb_clustered_contiguous_ipv4_networks()) {
            let mut before: Vec<u32> = nets.iter().flat_map(|net| (**net).addrs().map(|a| a.to_bits())).collect();
            before.sort_unstable();
            before.dedup();

            let mut nets = nets;
            let result = ipv4_aggregate_contiguous(&mut nets);

            let mut after: Vec<u32> = result.iter().flat_map(|net| (**net).addrs().map(|a| a.to_bits())).collect();
            after.sort_unstable();
            after.dedup();

            prop_assert_eq!(before, after);
        }

        #[test]
        fn prop_ipv4_aggregate_contiguous_is_minimal(nets in arb_clustered_contiguous_ipv4_networks()) {
            let mut nets = nets;
            let result = ipv4_aggregate_contiguous(&mut nets);
            for i in 0..result.len() {
                for j in (i + 1)..result.len() {
                    let a: Ipv4Network = *result[i];
                    let b: Ipv4Network = *result[j];
                    prop_assert_ne!(a, b);
                    prop_assert!(a.merge_by_lowest_mask_bit(&b).is_none());
                    prop_assert!(!a.contains(&b));
                    prop_assert!(!b.contains(&a));
                }
            }
        }

        #[test]
        fn prop_ipv4_aggregate_contiguous_stays_contiguous(nets in arb_clustered_contiguous_ipv4_networks()) {
            let mut nets = nets;
            let result = ipv4_aggregate_contiguous(&mut nets);
            for net in result.iter() {
                // The wrapper asserts contiguity. Confirm the unwrapped network's
                // general check agrees, since the fast path re-wraps merge results
                // without re-validating.
                prop_assert!((**net).is_contiguous());
            }
        }

        #[test]
        fn prop_ipv4_aggregate_contiguous_matches_reference(nets in arb_clustered_contiguous_ipv4_networks()) {
            let expected = ipv4_aggregate_contiguous_reference(&nets);
            let mut nets = nets;
            let result = ipv4_aggregate_contiguous(&mut nets);
            let actual = ipv4_contiguous_inner_sorted(result);
            prop_assert_eq!(expected, actual);
        }

        #[test]
        fn prop_ipv4_aggregate_contiguous_is_idempotent(nets in arb_clustered_contiguous_ipv4_networks()) {
            let mut nets = nets;
            let first: Vec<_> = ipv4_aggregate_contiguous(&mut nets).to_vec();
            let mut again = first.clone();
            let second: Vec<_> = ipv4_aggregate_contiguous(&mut again).to_vec();
            prop_assert_eq!(first, second);
        }

        #[test]
        fn prop_ipv6_aggregate_contiguous_preserves_addresses(nets in arb_clustered_contiguous_ipv6_networks()) {
            let mut before: Vec<u128> = nets.iter().flat_map(|net| (**net).addrs().map(|a| a.to_bits())).collect();
            before.sort_unstable();
            before.dedup();

            let mut nets = nets;
            let result = ipv6_aggregate_contiguous(&mut nets);

            let mut after: Vec<u128> = result.iter().flat_map(|net| (**net).addrs().map(|a| a.to_bits())).collect();
            after.sort_unstable();
            after.dedup();

            prop_assert_eq!(before, after);
        }

        #[test]
        fn prop_ipv6_aggregate_contiguous_is_minimal(nets in arb_clustered_contiguous_ipv6_networks()) {
            let mut nets = nets;
            let result = ipv6_aggregate_contiguous(&mut nets);
            for i in 0..result.len() {
                for j in (i + 1)..result.len() {
                    let a: Ipv6Network = *result[i];
                    let b: Ipv6Network = *result[j];
                    prop_assert_ne!(a, b);
                    prop_assert!(a.merge_by_lowest_mask_bit(&b).is_none());
                    prop_assert!(!a.contains(&b));
                    prop_assert!(!b.contains(&a));
                }
            }
        }

        #[test]
        fn prop_ipv6_aggregate_contiguous_stays_contiguous(nets in arb_clustered_contiguous_ipv6_networks()) {
            let mut nets = nets;
            let result = ipv6_aggregate_contiguous(&mut nets);
            for net in result.iter() {
                prop_assert!((**net).is_contiguous());
            }
        }

        #[test]
        fn prop_ipv6_aggregate_contiguous_matches_reference(nets in arb_clustered_contiguous_ipv6_networks()) {
            let expected = ipv6_aggregate_contiguous_reference(&nets);
            let mut nets = nets;
            let result = ipv6_aggregate_contiguous(&mut nets);
            let actual = ipv6_contiguous_inner_sorted(result);
            prop_assert_eq!(expected, actual);
        }

        #[test]
        fn prop_ipv6_aggregate_contiguous_is_idempotent(nets in arb_clustered_contiguous_ipv6_networks()) {
            let mut nets = nets;
            let first: Vec<_> = ipv6_aggregate_contiguous(&mut nets).to_vec();
            let mut again = first.clone();
            let second: Vec<_> = ipv6_aggregate_contiguous(&mut again).to_vec();
            prop_assert_eq!(first, second);
        }
    }
}
