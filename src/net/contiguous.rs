//! Contiguous IP network wrapper.
//!
//! [`Contiguous<T>`] guarantees at the type level that a wrapped IP network
//! has a contiguous mask.

use core::{
    error::Error,
    fmt::{Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Deref,
    str::FromStr,
};

use super::{
    CidrOverflowError, IpNetParseError, IpNetwork, IpVersionMismatchError, Ipv4Network, Ipv6Network,
    ipv4_mask_from_cidr, ipv6_mask_from_cidr,
};

/// An error that occurs when parsing a contiguous IP network.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
///
/// The wrapper dereferences to the network, so every method of the network
/// applies to it. Some are specialized:
/// - `contains` compares the masks as integers, and `addrs` of an
///   [`Ipv4Network`] or an [`Ipv6Network`] steps a plain index, both faster
///   than the inherited ones;
/// - `prefix` returns the prefix length with no [`Option`];
/// - `intersection`, `merge_by_lowest_mask_bit` and `supernet` return a
///   [`Contiguous`] network, since the class is closed under them.
///
/// A specialized method takes a [`Contiguous`] operand. Reach the inherited
/// one with a possibly non-contiguous network through [`Deref`], e.g.
/// `(*net).contains(&other)`.
///
/// `merge` is deliberately not specialized: the class is not closed under it,
/// since two prefixes that differ in a bit above the last one of the prefix
/// merge into a non-contiguous network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Contiguous<T>(pub(crate) T);

impl Contiguous<IpNetwork> {
    /// Parses an IP network from a string and returns a contiguous network.
    pub fn parse(buf: &str) -> Result<Self, ContiguousIpNetParseError> {
        Self::try_from(IpNetwork::parse(buf)?)
    }

    /// Builds a contiguous IP network from an address and a prefix length,
    /// or returns [`None`] if the prefix length is past the address family's
    /// bound: 32 for IPv4, 128 for IPv6.
    ///
    /// Dispatches on the address family to
    /// [`Contiguous::<Ipv4Network>::from_prefix`] or
    /// [`Contiguous::<Ipv6Network>::from_prefix`]; see them for the
    /// normalization and for building constants.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    ///
    /// use netip::{Contiguous, IpNetwork};
    ///
    /// let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
    /// let net = Contiguous::<IpNetwork>::from_prefix(addr, 24).unwrap();
    /// assert_eq!("192.168.1.0/24", net.to_string());
    /// assert_eq!(None, Contiguous::<IpNetwork>::from_prefix(addr, 33));
    ///
    /// let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    /// let net = Contiguous::<IpNetwork>::from_prefix(addr, 64).unwrap();
    /// assert_eq!("2001:db8::/64", net.to_string());
    /// assert_eq!(None, Contiguous::<IpNetwork>::from_prefix(addr, 129));
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_prefix(addr: IpAddr, prefix: u8) -> Option<Self> {
        match addr {
            IpAddr::V4(addr) => match Contiguous::<Ipv4Network>::from_prefix(addr, prefix) {
                Some(Contiguous(net)) => Some(Self(IpNetwork::V4(net))),
                None => None,
            },
            IpAddr::V6(addr) => match Contiguous::<Ipv6Network>::from_prefix(addr, prefix) {
                Some(Contiguous(net)) => Some(Self(IpNetwork::V6(net))),
                None => None,
            },
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

    /// Returns the intersection of this IP network with the specified one,
    /// or [`None`] if they are disjoint or of different address families.
    ///
    /// Two prefixes are either nested or disjoint, so the intersection of two
    /// contiguous networks is the longer of the two, and its mask stays
    /// contiguous. This overrides [`IpNetwork::intersection`] to return the
    /// result as a [`Contiguous`] network, with no re-validation. Reach the
    /// general intersection with a possibly non-contiguous network through
    /// [`Deref`], e.g. `(*net).intersection(&other)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, IpNetwork};
    ///
    /// let a = Contiguous::<IpNetwork>::parse("192.168.0.0/16").unwrap();
    /// let b = Contiguous::<IpNetwork>::parse("192.168.1.0/24").unwrap();
    /// assert_eq!(Some(b), a.intersection(&b));
    ///
    /// // Different address families.
    /// let v6 = Contiguous::<IpNetwork>::parse("2001:db8::/32").unwrap();
    /// assert_eq!(None, a.intersection(&v6));
    /// ```
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

    /// Merges this IP network with the specified one when one contains the
    /// other or they are the two halves of the network one prefix bit shorter,
    /// returning the combined network. Returns [`None`] for networks of
    /// different address families.
    ///
    /// The lowest bit of a contiguous mask is the last bit of the prefix, so
    /// siblings merge into the network one prefix bit shorter, and containment
    /// returns the larger input: either way the mask stays contiguous. This
    /// overrides [`IpNetwork::merge_by_lowest_mask_bit`] to return the result
    /// as a [`Contiguous`] network, with no re-validation. Reach the
    /// general merge with a possibly non-contiguous network through
    /// [`Deref`], e.g. `(*net).merge_by_lowest_mask_bit(&other)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, IpNetwork};
    ///
    /// let a = Contiguous::<IpNetwork>::parse("192.168.0.0/24").unwrap();
    /// let b = Contiguous::<IpNetwork>::parse("192.168.1.0/24").unwrap();
    /// let merged = a.merge_by_lowest_mask_bit(&b).unwrap();
    /// assert_eq!(
    ///     Contiguous::<IpNetwork>::parse("192.168.0.0/23").unwrap(),
    ///     merged
    /// );
    /// assert_eq!(23, merged.prefix());
    ///
    /// // Different address families.
    /// let v6 = Contiguous::<IpNetwork>::parse("2001:db8::/32").unwrap();
    /// assert_eq!(None, a.merge_by_lowest_mask_bit(&v6));
    /// ```
    #[inline]
    #[must_use]
    pub const fn merge_by_lowest_mask_bit(&self, other: &Self) -> Option<Self> {
        // NOTE: use `Option::map` when it becomes const.
        match (self, other) {
            (Self(a), Self(b)) => match a.merge_by_lowest_mask_bit(b) {
                Some(net) => Some(Self(net)),
                None => None,
            },
        }
    }

    /// Returns the network one prefix bit shorter, or [`None`] for a `/0`.
    ///
    /// A shorter prefix keeps the mask contiguous, so this overrides
    /// [`IpNetwork::supernet`] to return the result as a [`Contiguous`]
    /// network, with no re-validation.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, IpNetwork};
    ///
    /// let net = Contiguous::<IpNetwork>::parse("192.168.1.0/24").unwrap();
    /// let supernet = net.supernet().unwrap();
    /// assert_eq!(
    ///     Contiguous::<IpNetwork>::parse("192.168.0.0/23").unwrap(),
    ///     supernet
    /// );
    /// assert_eq!(23, supernet.prefix());
    ///
    /// assert_eq!(
    ///     None,
    ///     Contiguous::<IpNetwork>::parse("::/0").unwrap().supernet()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn supernet(&self) -> Option<Self> {
        // NOTE: use `Option::map` when it becomes const.
        match self {
            Self(net) => match net.supernet() {
                Some(net) => Some(Self(net)),
                None => None,
            },
        }
    }
}

impl Contiguous<Ipv4Network> {
    /// Parses an IPv4 network from a string and returns a contiguous network.
    pub fn parse(buf: &str) -> Result<Self, ContiguousIpNetParseError> {
        Self::try_from(Ipv4Network::parse(buf)?)
    }

    /// Builds a contiguous IPv4 network from an address and a prefix length,
    /// or returns [`None`] if the prefix length is past 32.
    ///
    /// The address is normalized using the mask, as in [`Ipv4Network::new`]:
    /// `192.168.1.5` with prefix length 24 becomes `192.168.1.0/24`. A mask
    /// built from a prefix length is contiguous by construction, so no
    /// contiguity check runs.
    ///
    /// The `TryFrom<(Ipv4Addr, u8)>` conversion builds the same network and
    /// reports an overflowing prefix length as a [`CidrOverflowError`]. This
    /// one is a `const fn` returning [`Option`] instead, so it also builds
    /// constants: [`Option::expect`] works in `const` context.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::{Contiguous, Ipv4Network};
    ///
    /// const PRIVATE: Contiguous<Ipv4Network> =
    ///     Contiguous::<Ipv4Network>::from_prefix(Ipv4Addr::new(10, 0, 0, 0), 8)
    ///         .expect("8 is at most 32");
    /// assert_eq!(8, PRIVATE.prefix());
    ///
    /// let net = Contiguous::<Ipv4Network>::from_prefix(Ipv4Addr::new(192, 168, 1, 5), 24).unwrap();
    /// assert_eq!("192.168.1.0/24", net.to_string());
    ///
    /// assert_eq!(
    ///     None,
    ///     Contiguous::<Ipv4Network>::from_prefix(Ipv4Addr::new(10, 0, 0, 0), 33)
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_prefix(addr: Ipv4Addr, prefix: u8) -> Option<Self> {
        match ipv4_mask_from_cidr(prefix) {
            Ok(mask) => Some(Self(Ipv4Network::new(addr, mask))),
            Err(..) => None,
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

    /// Returns the intersection of this IPv4 network with the specified one,
    /// or [`None`] if they are disjoint.
    ///
    /// Two prefixes are either nested or disjoint, so the intersection of two
    /// contiguous networks is the longer of the two, and its mask stays
    /// contiguous. This overrides [`Ipv4Network::intersection`] to return the
    /// result as a [`Contiguous`] network, with no re-validation. Reach the
    /// general intersection with a possibly non-contiguous network through
    /// [`Deref`], e.g. `(*net).intersection(&other)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv4Network};
    ///
    /// let a = Contiguous::<Ipv4Network>::parse("192.168.0.0/16").unwrap();
    /// let b = Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap();
    /// assert_eq!(Some(b), a.intersection(&b));
    /// assert_eq!(Some(b), b.intersection(&a));
    ///
    /// let c = Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap();
    /// assert_eq!(None, a.intersection(&c));
    /// ```
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

    /// Merges this IPv4 network with the specified one when one contains the
    /// other or they are the two halves of the network one prefix bit shorter,
    /// returning the combined network.
    ///
    /// The lowest bit of a contiguous mask is the last bit of the prefix, so
    /// siblings merge into the network one prefix bit shorter, and containment
    /// returns the larger input: either way the mask stays contiguous. This
    /// overrides [`Ipv4Network::merge_by_lowest_mask_bit`] to return the result
    /// as a [`Contiguous`] network, with no re-validation. Reach the
    /// general merge with a possibly non-contiguous network through
    /// [`Deref`], e.g. `(*net).merge_by_lowest_mask_bit(&other)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv4Network};
    ///
    /// let a = Contiguous::<Ipv4Network>::parse("192.168.0.0/24").unwrap();
    /// let b = Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap();
    /// let merged = a.merge_by_lowest_mask_bit(&b).unwrap();
    /// assert_eq!(
    ///     Contiguous::<Ipv4Network>::parse("192.168.0.0/23").unwrap(),
    ///     merged
    /// );
    /// assert_eq!(23, merged.prefix());
    ///
    /// // Containment: the larger network is returned.
    /// let outer = Contiguous::<Ipv4Network>::parse("192.168.0.0/16").unwrap();
    /// assert_eq!(Some(outer), a.merge_by_lowest_mask_bit(&outer));
    ///
    /// // These differ above the last prefix bit: merging them would leave a
    /// // non-contiguous mask.
    /// let c = Contiguous::<Ipv4Network>::parse("192.168.2.0/24").unwrap();
    /// assert_eq!(None, a.merge_by_lowest_mask_bit(&c));
    /// ```
    #[inline]
    #[must_use]
    pub const fn merge_by_lowest_mask_bit(&self, other: &Self) -> Option<Self> {
        // NOTE: use `Option::map` when it becomes const.
        match (self, other) {
            (Self(a), Self(b)) => match a.merge_by_lowest_mask_bit(b) {
                Some(net) => Some(Self(net)),
                None => None,
            },
        }
    }

    /// Returns the network one prefix bit shorter, or [`None`] for a `/0`.
    ///
    /// A shorter prefix keeps the mask contiguous, so this overrides
    /// [`Ipv4Network::supernet`] to return the result as a [`Contiguous`]
    /// network, with no re-validation.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv4Network};
    ///
    /// let net = Contiguous::<Ipv4Network>::parse("192.168.1.0/24").unwrap();
    /// let supernet = net.supernet().unwrap();
    /// assert_eq!(
    ///     Contiguous::<Ipv4Network>::parse("192.168.0.0/23").unwrap(),
    ///     supernet
    /// );
    /// assert_eq!(23, supernet.prefix());
    ///
    /// assert_eq!(
    ///     None,
    ///     Contiguous::<Ipv4Network>::parse("0.0.0.0/0")
    ///         .unwrap()
    ///         .supernet()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn supernet(&self) -> Option<Self> {
        // NOTE: use `Option::map` when it becomes const.
        match self {
            Self(net) => match net.supernet() {
                Some(net) => Some(Self(net)),
                None => None,
            },
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
/// [`nth`](Iterator::nth) and [`nth_back`](DoubleEndedIterator::nth_back) skip
/// in O(1), and leave the iterator as `n + 1` calls of `next` or `next_back`
/// would.
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

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        if self.front > self.back {
            return None;
        }

        // NOTE: lossless, `usize` is at most 64 bits wide.
        if n as u64 > u64::from(self.back - self.front) {
            // `n + 1` calls of `next` drain the iterator: the one that takes
            // the last address leaves the drained state, and the calls after
            // it change nothing.
            self.front = self.back;
            self.next();
            return None;
        }

        // NOTE: lossless and in range, `n <= back - front`.
        self.front += n as u32;
        self.next()
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

    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        if self.front > self.back {
            return None;
        }

        // NOTE: lossless, `usize` is at most 64 bits wide.
        if n as u64 > u64::from(self.back - self.front) {
            // `n + 1` calls of `next_back` drain the iterator: the one that
            // takes the last address leaves the drained state, and the calls
            // after it change nothing.
            self.back = self.front;
            self.next_back();
            return None;
        }

        // NOTE: lossless and in range, `n <= back - front`.
        self.back -= n as u32;
        self.next_back()
    }
}

// Implemented only where the count of every IPv4 network fits a `usize`.
#[cfg(target_pointer_width = "64")]
impl ExactSizeIterator for ContiguousIpv4NetworkAddrs {
    #[inline]
    fn len(&self) -> usize {
        // 2^32, the largest count any IPv4 network has, fits a 64-bit `usize`.
        self.remaining() as usize
    }
}

// Once the cursors cross they stay crossed, and both ends return `None`.
impl core::iter::FusedIterator for ContiguousIpv4NetworkAddrs {}

impl Contiguous<Ipv6Network> {
    /// Parses an IPv6 network from a string and returns a contiguous network.
    pub fn parse(buf: &str) -> Result<Self, ContiguousIpNetParseError> {
        Self::try_from(Ipv6Network::parse(buf)?)
    }

    /// Builds a contiguous IPv6 network from an address and a prefix length,
    /// or returns [`None`] if the prefix length is past 128.
    ///
    /// The address is normalized using the mask, as in [`Ipv6Network::new`]:
    /// `2001:db8::1` with prefix length 64 becomes `2001:db8::/64`. A mask
    /// built from a prefix length is contiguous by construction, so no
    /// contiguity check runs.
    ///
    /// The `TryFrom<(Ipv6Addr, u8)>` conversion builds the same network and
    /// reports an overflowing prefix length as a [`CidrOverflowError`]. This
    /// one is a `const fn` returning [`Option`] instead, so it also builds
    /// constants: [`Option::expect`] works in `const` context.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::{Contiguous, Ipv6Network};
    ///
    /// const DOCUMENTATION: Contiguous<Ipv6Network> =
    ///     Contiguous::<Ipv6Network>::from_prefix(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32)
    ///         .expect("32 is at most 128");
    /// assert_eq!(32, DOCUMENTATION.prefix());
    ///
    /// let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    /// let net = Contiguous::<Ipv6Network>::from_prefix(addr, 64).unwrap();
    /// assert_eq!("2001:db8::/64", net.to_string());
    ///
    /// assert_eq!(None, Contiguous::<Ipv6Network>::from_prefix(addr, 129));
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_prefix(addr: Ipv6Addr, prefix: u8) -> Option<Self> {
        match ipv6_mask_from_cidr(prefix) {
            Ok(mask) => Some(Self(Ipv6Network::new(addr, mask))),
            Err(..) => None,
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

    /// Returns the intersection of this IPv6 network with the specified one,
    /// or [`None`] if they are disjoint.
    ///
    /// Two prefixes are either nested or disjoint, so the intersection of two
    /// contiguous networks is the longer of the two, and its mask stays
    /// contiguous. This overrides [`Ipv6Network::intersection`] to return the
    /// result as a [`Contiguous`] network, with no re-validation. Reach the
    /// general intersection with a possibly non-contiguous network through
    /// [`Deref`], e.g. `(*net).intersection(&other)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv6Network};
    ///
    /// let a = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
    /// let b = Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap();
    /// assert_eq!(Some(b), a.intersection(&b));
    /// assert_eq!(Some(b), b.intersection(&a));
    ///
    /// let c = Contiguous::<Ipv6Network>::parse("fe80::/10").unwrap();
    /// assert_eq!(None, a.intersection(&c));
    /// ```
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

    /// Merges this IPv6 network with the specified one when one contains the
    /// other or they are the two halves of the network one prefix bit shorter,
    /// returning the combined network.
    ///
    /// The lowest bit of a contiguous mask is the last bit of the prefix, so
    /// siblings merge into the network one prefix bit shorter, and containment
    /// returns the larger input: either way the mask stays contiguous. This
    /// overrides [`Ipv6Network::merge_by_lowest_mask_bit`] to return the result
    /// as a [`Contiguous`] network, with no re-validation. Reach the
    /// general merge with a possibly non-contiguous network through
    /// [`Deref`], e.g. `(*net).merge_by_lowest_mask_bit(&other)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv6Network};
    ///
    /// let a = Contiguous::<Ipv6Network>::parse("2001:db8::/48").unwrap();
    /// let b = Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap();
    /// let merged = a.merge_by_lowest_mask_bit(&b).unwrap();
    /// assert_eq!(
    ///     Contiguous::<Ipv6Network>::parse("2001:db8::/47").unwrap(),
    ///     merged
    /// );
    /// assert_eq!(47, merged.prefix());
    ///
    /// // Containment: the larger network is returned.
    /// let outer = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
    /// assert_eq!(Some(outer), a.merge_by_lowest_mask_bit(&outer));
    ///
    /// // These differ above the last prefix bit: merging them would leave a
    /// // non-contiguous mask.
    /// let c = Contiguous::<Ipv6Network>::parse("2001:db8:2::/48").unwrap();
    /// assert_eq!(None, a.merge_by_lowest_mask_bit(&c));
    /// ```
    #[inline]
    #[must_use]
    pub const fn merge_by_lowest_mask_bit(&self, other: &Self) -> Option<Self> {
        // NOTE: use `Option::map` when it becomes const.
        match (self, other) {
            (Self(a), Self(b)) => match a.merge_by_lowest_mask_bit(b) {
                Some(net) => Some(Self(net)),
                None => None,
            },
        }
    }

    /// Returns the network one prefix bit shorter, or [`None`] for a `/0`.
    ///
    /// A shorter prefix keeps the mask contiguous, so this overrides
    /// [`Ipv6Network::supernet`] to return the result as a [`Contiguous`]
    /// network, with no re-validation.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv6Network};
    ///
    /// let net = Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap();
    /// let supernet = net.supernet().unwrap();
    /// assert_eq!(
    ///     Contiguous::<Ipv6Network>::parse("2001:db8::/47").unwrap(),
    ///     supernet
    /// );
    /// assert_eq!(47, supernet.prefix());
    ///
    /// assert_eq!(
    ///     None,
    ///     Contiguous::<Ipv6Network>::parse("::/0").unwrap().supernet()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn supernet(&self) -> Option<Self> {
        // NOTE: use `Option::map` when it becomes const.
        match self {
            Self(net) => match net.supernet() {
                Some(net) => Some(Self(net)),
                None => None,
            },
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
/// [`nth`](Iterator::nth) and [`nth_back`](DoubleEndedIterator::nth_back) skip
/// in O(1), and leave the iterator as `n + 1` calls of `next` or `next_back`
/// would.
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

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        if self.current > self.last {
            return None;
        }

        // NOTE: lossless, `usize` is at most 64 bits wide.
        let n = n as u128;
        if n > self.last - self.current {
            // `n + 1` calls of `next` drain the iterator: the one that takes
            // the last address leaves the drained state, and the calls after
            // it change nothing.
            self.current = self.last;
            self.next();
            return None;
        }

        self.current += n;
        self.next()
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

    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        if self.current > self.last {
            return None;
        }

        // NOTE: lossless, `usize` is at most 64 bits wide.
        let n = n as u128;
        if n > self.last - self.current {
            // `n + 1` calls of `next_back` drain the iterator: the one that
            // takes the last address leaves the drained state, and the calls
            // after it change nothing.
            self.last = self.current;
            self.next_back();
            return None;
        }

        self.last -= n;
        self.next_back()
    }
}

// Once the cursors cross they stay crossed, and both ends return `None`.
impl core::iter::FusedIterator for ContiguousIpv6NetworkAddrs {}

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

impl TryFrom<Contiguous<IpNetwork>> for Contiguous<Ipv4Network> {
    type Error = IpVersionMismatchError;

    /// Converts a [`Contiguous<IpNetwork>`] into a
    /// [`Contiguous<Ipv4Network>`], failing with [`IpVersionMismatchError`]
    /// if it is an IPv6 network, IPv4-mapped included, as
    /// `Ipv4Network::try_from` does.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, IpNetwork, IpVersionMismatchError, Ipv4Network};
    ///
    /// let net = Contiguous::<IpNetwork>::parse("10.0.0.0/8").unwrap();
    /// assert_eq!(
    ///     Ok(Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap()),
    ///     Contiguous::<Ipv4Network>::try_from(net)
    /// );
    ///
    /// let net = Contiguous::<IpNetwork>::parse("2001:db8::/32").unwrap();
    /// assert!(matches!(
    ///     Contiguous::<Ipv4Network>::try_from(net),
    ///     Err(IpVersionMismatchError { .. })
    /// ));
    /// ```
    #[inline]
    fn try_from(net: Contiguous<IpNetwork>) -> Result<Self, Self::Error> {
        let Contiguous(net) = net;
        Ok(Self(Ipv4Network::try_from(net)?))
    }
}

impl TryFrom<Contiguous<IpNetwork>> for Contiguous<Ipv6Network> {
    type Error = IpVersionMismatchError;

    /// Converts a [`Contiguous<IpNetwork>`] into a
    /// [`Contiguous<Ipv6Network>`], failing with [`IpVersionMismatchError`]
    /// if it is an IPv4 network, as `Ipv6Network::try_from` does.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, IpNetwork, IpVersionMismatchError, Ipv6Network};
    ///
    /// let net = Contiguous::<IpNetwork>::parse("2001:db8::/32").unwrap();
    /// assert_eq!(
    ///     Ok(Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap()),
    ///     Contiguous::<Ipv6Network>::try_from(net)
    /// );
    ///
    /// let net = Contiguous::<IpNetwork>::parse("10.0.0.0/8").unwrap();
    /// assert!(matches!(
    ///     Contiguous::<Ipv6Network>::try_from(net),
    ///     Err(IpVersionMismatchError { .. })
    /// ));
    /// ```
    #[inline]
    fn try_from(net: Contiguous<IpNetwork>) -> Result<Self, Self::Error> {
        let Contiguous(net) = net;
        Ok(Self(Ipv6Network::try_from(net)?))
    }
}

impl TryFrom<(Ipv4Addr, u8)> for Contiguous<Ipv4Network> {
    type Error = CidrOverflowError;

    /// Builds a [`Contiguous<Ipv4Network>`] from an address and prefix
    /// length.
    ///
    /// A mask built from a prefix length is contiguous by construction, so
    /// the contiguity check [`Contiguous::<Ipv4Network>::parse`] performs is
    /// unnecessary here — this only propagates the overflow error a prefix
    /// past 32 already produces.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::{Contiguous, Ipv4Network};
    ///
    /// let addr = Ipv4Addr::new(192, 168, 1, 5);
    /// let net = Contiguous::<Ipv4Network>::try_from((addr, 24)).unwrap();
    /// assert_eq!(24, net.prefix());
    ///
    /// assert!(Contiguous::<Ipv4Network>::try_from((addr, 33)).is_err());
    /// ```
    #[inline]
    fn try_from((addr, cidr): (Ipv4Addr, u8)) -> Result<Self, Self::Error> {
        Ok(Self(Ipv4Network::try_from((addr, cidr))?))
    }
}

impl TryFrom<(Ipv6Addr, u8)> for Contiguous<Ipv6Network> {
    type Error = CidrOverflowError;

    /// Builds a [`Contiguous<Ipv6Network>`] from an address and prefix
    /// length.
    ///
    /// A mask built from a prefix length is contiguous by construction, so
    /// the contiguity check [`Contiguous::<Ipv6Network>::parse`] performs is
    /// unnecessary here — this only propagates the overflow error a prefix
    /// past 128 already produces.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::{Contiguous, Ipv6Network};
    ///
    /// let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    /// let net = Contiguous::<Ipv6Network>::try_from((addr, 64)).unwrap();
    /// assert_eq!(64, net.prefix());
    ///
    /// assert!(Contiguous::<Ipv6Network>::try_from((addr, 129)).is_err());
    /// ```
    #[inline]
    fn try_from((addr, cidr): (Ipv6Addr, u8)) -> Result<Self, Self::Error> {
        Ok(Self(Ipv6Network::try_from((addr, cidr))?))
    }
}

impl TryFrom<(IpAddr, u8)> for Contiguous<IpNetwork> {
    type Error = CidrOverflowError;

    /// Builds a [`Contiguous<IpNetwork>`] from an address and prefix length.
    ///
    /// A mask built from a prefix length is contiguous by construction, so
    /// the contiguity check [`Contiguous::<IpNetwork>::parse`] performs is
    /// unnecessary here — this only propagates the overflow error the
    /// per-family prefix bound already produces.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::{IpAddr, Ipv4Addr};
    ///
    /// use netip::{Contiguous, IpNetwork};
    ///
    /// let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
    /// let net = Contiguous::<IpNetwork>::try_from((addr, 24)).unwrap();
    /// assert_eq!(24, net.prefix());
    ///
    /// assert!(Contiguous::<IpNetwork>::try_from((addr, 33)).is_err());
    /// ```
    #[inline]
    fn try_from((addr, cidr): (IpAddr, u8)) -> Result<Self, Self::Error> {
        Ok(Self(IpNetwork::try_from((addr, cidr))?))
    }
}

impl TryFrom<Ipv4Network> for Contiguous<Ipv4Network> {
    type Error = ContiguousIpNetParseError;

    /// Converts an [`Ipv4Network`] into a [`Contiguous<Ipv4Network>`],
    /// failing with [`ContiguousIpNetParseError::NonContiguousNetwork`] if the
    /// network's mask is not contiguous.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, ContiguousIpNetParseError, Ipv4Network};
    ///
    /// let net = Ipv4Network::parse("10.0.0.0/8").unwrap();
    /// assert_eq!(net, *Contiguous::<Ipv4Network>::try_from(net).unwrap());
    ///
    /// let net = Ipv4Network::parse("10.0.0.0/255.0.255.0").unwrap();
    /// assert_eq!(
    ///     Err(ContiguousIpNetParseError::NonContiguousNetwork),
    ///     Contiguous::<Ipv4Network>::try_from(net)
    /// );
    /// ```
    #[inline]
    fn try_from(net: Ipv4Network) -> Result<Self, Self::Error> {
        if net.is_contiguous() {
            Ok(Self(net))
        } else {
            Err(ContiguousIpNetParseError::NonContiguousNetwork)
        }
    }
}

impl TryFrom<Ipv6Network> for Contiguous<Ipv6Network> {
    type Error = ContiguousIpNetParseError;

    /// Converts an [`Ipv6Network`] into a [`Contiguous<Ipv6Network>`],
    /// failing with [`ContiguousIpNetParseError::NonContiguousNetwork`] if the
    /// network's mask is not contiguous.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, ContiguousIpNetParseError, Ipv6Network};
    ///
    /// let net = Ipv6Network::parse("2001:db8::/32").unwrap();
    /// assert_eq!(net, *Contiguous::<Ipv6Network>::try_from(net).unwrap());
    ///
    /// let net = Ipv6Network::parse("2001:db8::/ffff:ffff::ffff:0:0:0").unwrap();
    /// assert_eq!(
    ///     Err(ContiguousIpNetParseError::NonContiguousNetwork),
    ///     Contiguous::<Ipv6Network>::try_from(net)
    /// );
    /// ```
    #[inline]
    fn try_from(net: Ipv6Network) -> Result<Self, Self::Error> {
        if net.is_contiguous() {
            Ok(Self(net))
        } else {
            Err(ContiguousIpNetParseError::NonContiguousNetwork)
        }
    }
}

impl TryFrom<IpNetwork> for Contiguous<IpNetwork> {
    type Error = ContiguousIpNetParseError;

    /// Converts an [`IpNetwork`] into a [`Contiguous<IpNetwork>`], failing
    /// with [`ContiguousIpNetParseError::NonContiguousNetwork`] if the
    /// network's mask is not contiguous.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, ContiguousIpNetParseError, IpNetwork};
    ///
    /// let net = IpNetwork::parse("10.0.0.0/8").unwrap();
    /// assert_eq!(net, *Contiguous::<IpNetwork>::try_from(net).unwrap());
    ///
    /// let net = IpNetwork::parse("2001:db8::/ffff:ffff::ffff:0:0:0").unwrap();
    /// assert_eq!(
    ///     Err(ContiguousIpNetParseError::NonContiguousNetwork),
    ///     Contiguous::<IpNetwork>::try_from(net)
    /// );
    /// ```
    #[inline]
    fn try_from(net: IpNetwork) -> Result<Self, Self::Error> {
        if net.is_contiguous() {
            Ok(Self(net))
        } else {
            Err(ContiguousIpNetParseError::NonContiguousNetwork)
        }
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

impl<T> AsRef<T> for Contiguous<T> {
    /// Borrows the wrapped network, as [`Deref`] does.
    ///
    /// This lets a slice of contiguous networks go to the functions that take
    /// a slice of any `T: AsRef<Ipv4Network>` or `T: AsRef<Ipv6Network>`, such
    /// as [`ipv4_binary_split`](crate::ipv4_binary_split) and
    /// [`ipv6_binary_split`](crate::ipv6_binary_split).
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Contiguous, Ipv4Network, ipv4_binary_split};
    ///
    /// let mut nets: Vec<_> = ["127.0.0.1", "127.0.0.2", "127.0.0.3"]
    ///     .iter()
    ///     .map(|net| Contiguous::<Ipv4Network>::parse(net).unwrap())
    ///     .collect();
    ///
    /// let (supernet, range) = ipv4_binary_split(&mut nets).unwrap();
    /// assert_eq!(Ipv4Network::parse("127.0.0.2/31").unwrap(), supernet);
    /// assert_eq!(1..3, range);
    /// ```
    #[inline]
    fn as_ref(&self) -> &T {
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
    use crate::{
        ipv4_binary_split, ipv6_binary_split,
        net::test::{arb_contiguous_ipv6_network, arb_ipv4_network, arb_ipv6_network},
    };

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

    // Non-contiguous-mask coverage does not apply to the `*_tryfrom_*_cidr*`
    // and `*_from_prefix*` tests in this file: a prefix length can only ever
    // produce a contiguous mask, so there is no non-contiguous input to
    // construct. The `*_tryfrom_network*` tests below cover both kinds.

    #[test]
    fn contiguous_ipv4_tryfrom_addr_cidr() {
        let addr = Ipv4Addr::new(192, 168, 1, 5);
        let expected = Contiguous(Ipv4Network::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(255, 255, 255, 0),
        ));
        assert_eq!(expected, Contiguous::<Ipv4Network>::try_from((addr, 24)).unwrap());
    }

    #[test]
    fn contiguous_ipv4_tryfrom_addr_cidr_boundaries() {
        let addr = Ipv4Addr::new(192, 168, 1, 5);

        let host = Contiguous(Ipv4Network::new(addr, Ipv4Addr::new(255, 255, 255, 255)));
        assert_eq!(host, Contiguous::<Ipv4Network>::try_from((addr, 32)).unwrap());

        let unspecified = Contiguous(Ipv4Network::new(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED));
        assert_eq!(unspecified, Contiguous::<Ipv4Network>::try_from((addr, 0)).unwrap());
    }

    #[test]
    fn contiguous_ipv4_tryfrom_addr_cidr_overflow() {
        let addr = Ipv4Addr::new(192, 168, 1, 5);
        assert_eq!(
            CidrOverflowError(33, 32),
            Contiguous::<Ipv4Network>::try_from((addr, 33)).unwrap_err()
        );
    }

    #[test]
    fn contiguous_ipv6_tryfrom_addr_cidr() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let expected = Contiguous(Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0),
        ));
        assert_eq!(expected, Contiguous::<Ipv6Network>::try_from((addr, 64)).unwrap());
    }

    #[test]
    fn contiguous_ipv6_tryfrom_addr_cidr_boundaries() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        let host = Contiguous(Ipv6Network::new(
            addr,
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
        ));
        assert_eq!(host, Contiguous::<Ipv6Network>::try_from((addr, 128)).unwrap());

        let unspecified = Contiguous(Ipv6Network::new(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED));
        assert_eq!(unspecified, Contiguous::<Ipv6Network>::try_from((addr, 0)).unwrap());
    }

    #[test]
    fn contiguous_ipv6_tryfrom_addr_cidr_overflow() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert_eq!(
            CidrOverflowError(129, 128),
            Contiguous::<Ipv6Network>::try_from((addr, 129)).unwrap_err()
        );
    }

    #[test]
    fn contiguous_ip_tryfrom_ipaddr_cidr_v4() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        let expected = Contiguous(IpNetwork::V4(Ipv4Network::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(255, 255, 255, 0),
        )));
        assert_eq!(expected, Contiguous::<IpNetwork>::try_from((addr, 24)).unwrap());
    }

    #[test]
    fn contiguous_ip_tryfrom_ipaddr_cidr_v6() {
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let expected = Contiguous(IpNetwork::V6(Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0),
        )));
        assert_eq!(expected, Contiguous::<IpNetwork>::try_from((addr, 64)).unwrap());
    }

    #[test]
    fn contiguous_ip_tryfrom_ipaddr_cidr_boundaries_v4() {
        let inner = Ipv4Addr::new(192, 168, 1, 5);
        let addr = IpAddr::V4(inner);

        let host = Contiguous(IpNetwork::V4(Ipv4Network::new(
            inner,
            Ipv4Addr::new(255, 255, 255, 255),
        )));
        assert_eq!(host, Contiguous::<IpNetwork>::try_from((addr, 32)).unwrap());

        let unspecified = Contiguous(IpNetwork::V4(Ipv4Network::new(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        )));
        assert_eq!(unspecified, Contiguous::<IpNetwork>::try_from((addr, 0)).unwrap());
    }

    #[test]
    fn contiguous_ip_tryfrom_ipaddr_cidr_boundaries_v6() {
        let inner = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let addr = IpAddr::V6(inner);

        let host = Contiguous(IpNetwork::V6(Ipv6Network::new(
            inner,
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
        )));
        assert_eq!(host, Contiguous::<IpNetwork>::try_from((addr, 128)).unwrap());

        let unspecified = Contiguous(IpNetwork::V6(Ipv6Network::new(
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::UNSPECIFIED,
        )));
        assert_eq!(unspecified, Contiguous::<IpNetwork>::try_from((addr, 0)).unwrap());
    }

    #[test]
    fn contiguous_ip_tryfrom_ipaddr_cidr_overflow_v4() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        assert_eq!(
            CidrOverflowError(33, 32),
            Contiguous::<IpNetwork>::try_from((addr, 33)).unwrap_err()
        );
    }

    #[test]
    fn contiguous_ip_tryfrom_ipaddr_cidr_overflow_v6() {
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            CidrOverflowError(129, 128),
            Contiguous::<IpNetwork>::try_from((addr, 129)).unwrap_err()
        );
    }

    #[test]
    fn contiguous_ipv4_from_prefix() {
        let addr = Ipv4Addr::new(192, 168, 1, 5);
        let expected = Contiguous(Ipv4Network::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(255, 255, 255, 0),
        ));
        assert_eq!(Some(expected), Contiguous::<Ipv4Network>::from_prefix(addr, 24));
    }

    #[test]
    fn contiguous_ipv4_from_prefix_boundaries() {
        let addr = Ipv4Addr::new(192, 168, 1, 5);

        let host = Contiguous(Ipv4Network::new(addr, Ipv4Addr::new(255, 255, 255, 255)));
        assert_eq!(Some(host), Contiguous::<Ipv4Network>::from_prefix(addr, 32));

        let unspecified = Contiguous(Ipv4Network::new(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED));
        assert_eq!(Some(unspecified), Contiguous::<Ipv4Network>::from_prefix(addr, 0));
    }

    #[test]
    fn contiguous_ipv4_from_prefix_overflow() {
        let addr = Ipv4Addr::new(192, 168, 1, 5);
        assert_eq!(None, Contiguous::<Ipv4Network>::from_prefix(addr, 33));
        assert_eq!(None, Contiguous::<Ipv4Network>::from_prefix(addr, u8::MAX));
    }

    #[test]
    fn contiguous_ipv4_from_prefix_in_const() {
        const NET: Contiguous<Ipv4Network> =
            Contiguous::<Ipv4Network>::from_prefix(Ipv4Addr::new(10, 1, 2, 3), 8).expect("8 is at most 32");
        assert_eq!(Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap(), NET);
    }

    #[test]
    fn contiguous_ipv6_from_prefix() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let expected = Contiguous(Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0),
        ));
        assert_eq!(Some(expected), Contiguous::<Ipv6Network>::from_prefix(addr, 64));
    }

    #[test]
    fn contiguous_ipv6_from_prefix_boundaries() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        let host = Contiguous(Ipv6Network::new(
            addr,
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
        ));
        assert_eq!(Some(host), Contiguous::<Ipv6Network>::from_prefix(addr, 128));

        let unspecified = Contiguous(Ipv6Network::new(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED));
        assert_eq!(Some(unspecified), Contiguous::<Ipv6Network>::from_prefix(addr, 0));
    }

    #[test]
    fn contiguous_ipv6_from_prefix_overflow() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert_eq!(None, Contiguous::<Ipv6Network>::from_prefix(addr, 129));
        assert_eq!(None, Contiguous::<Ipv6Network>::from_prefix(addr, u8::MAX));
    }

    #[test]
    fn contiguous_ipv6_from_prefix_in_const() {
        const NET: Contiguous<Ipv6Network> =
            Contiguous::<Ipv6Network>::from_prefix(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 32)
                .expect("32 is at most 128");
        assert_eq!(Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap(), NET);
    }

    #[test]
    fn contiguous_ip_from_prefix_dispatches_by_family() {
        let v4 = Ipv4Addr::new(192, 168, 1, 5);
        assert_eq!(
            Contiguous::<Ipv4Network>::from_prefix(v4, 24).map(Contiguous::<IpNetwork>::from),
            Contiguous::<IpNetwork>::from_prefix(IpAddr::V4(v4), 24)
        );

        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert_eq!(
            Contiguous::<Ipv6Network>::from_prefix(v6, 64).map(Contiguous::<IpNetwork>::from),
            Contiguous::<IpNetwork>::from_prefix(IpAddr::V6(v6), 64)
        );
    }

    #[test]
    fn contiguous_ip_from_prefix_overflow_is_per_family() {
        // 33 overflows IPv4 but not IPv6.
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        assert_eq!(None, Contiguous::<IpNetwork>::from_prefix(v4, 33));

        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(33, Contiguous::<IpNetwork>::from_prefix(v6, 33).unwrap().prefix());
        assert_eq!(None, Contiguous::<IpNetwork>::from_prefix(v6, 129));
    }

    #[test]
    fn contiguous_ip_from_prefix_in_const() {
        const NET: Contiguous<IpNetwork> =
            Contiguous::<IpNetwork>::from_prefix(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 8).expect("8 is at most 32");
        assert_eq!(Contiguous::<IpNetwork>::parse("10.0.0.0/8").unwrap(), NET);
    }

    #[test]
    fn contiguous_ipv4_tryfrom_network() {
        let net = Ipv4Network::parse("192.168.0.0/16").unwrap();
        assert_eq!(Ok(Contiguous(net)), Contiguous::<Ipv4Network>::try_from(net));
    }

    #[test]
    fn contiguous_ipv4_tryfrom_network_non_contiguous() {
        let net = Ipv4Network::parse("192.168.0.1/255.255.0.255").unwrap();
        assert_eq!(
            Err(ContiguousIpNetParseError::NonContiguousNetwork),
            Contiguous::<Ipv4Network>::try_from(net)
        );
    }

    #[test]
    fn contiguous_ipv6_tryfrom_network() {
        let net = Ipv6Network::parse("2001:db8::/32").unwrap();
        assert_eq!(Ok(Contiguous(net)), Contiguous::<Ipv6Network>::try_from(net));
    }

    #[test]
    fn contiguous_ipv6_tryfrom_network_non_contiguous() {
        let net = Ipv6Network::parse("2001:db8::/ffff:ffff::ffff:0:0:0").unwrap();
        assert_eq!(
            Err(ContiguousIpNetParseError::NonContiguousNetwork),
            Contiguous::<Ipv6Network>::try_from(net)
        );
    }

    #[test]
    fn contiguous_ip_tryfrom_network() {
        let v4 = IpNetwork::parse("192.168.0.0/16").unwrap();
        assert_eq!(Ok(Contiguous(v4)), Contiguous::<IpNetwork>::try_from(v4));

        let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
        assert_eq!(Ok(Contiguous(v6)), Contiguous::<IpNetwork>::try_from(v6));
    }

    #[test]
    fn contiguous_ip_tryfrom_network_non_contiguous() {
        let v4 = IpNetwork::parse("192.168.0.1/255.255.0.255").unwrap();
        assert_eq!(
            Err(ContiguousIpNetParseError::NonContiguousNetwork),
            Contiguous::<IpNetwork>::try_from(v4)
        );

        let v6 = IpNetwork::parse("2001:db8::/ffff:ffff::ffff:0:0:0").unwrap();
        assert_eq!(
            Err(ContiguousIpNetParseError::NonContiguousNetwork),
            Contiguous::<IpNetwork>::try_from(v6)
        );
    }

    #[test]
    fn contiguous_ipv4_tryfrom_contiguous_ip_network() {
        let net = Contiguous::<IpNetwork>::parse("192.168.0.0/16").unwrap();
        assert_eq!(
            Ok(Contiguous::<Ipv4Network>::parse("192.168.0.0/16").unwrap()),
            Contiguous::<Ipv4Network>::try_from(net)
        );

        let net = Contiguous::<IpNetwork>::parse("2001:db8::/32").unwrap();
        assert_eq!(Err(IpVersionMismatchError), Contiguous::<Ipv4Network>::try_from(net));

        // Strict: an IPv4-mapped network is IPv6.
        let net = Contiguous::<IpNetwork>::parse("::ffff:c0a8:0/112").unwrap();
        assert_eq!(Err(IpVersionMismatchError), Contiguous::<Ipv4Network>::try_from(net));
    }

    #[test]
    fn contiguous_ipv6_tryfrom_contiguous_ip_network() {
        let net = Contiguous::<IpNetwork>::parse("2001:db8::/32").unwrap();
        assert_eq!(
            Ok(Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap()),
            Contiguous::<Ipv6Network>::try_from(net)
        );

        let net = Contiguous::<IpNetwork>::parse("::ffff:c0a8:0/112").unwrap();
        assert_eq!(
            Ok(Contiguous::<Ipv6Network>::parse("::ffff:c0a8:0/112").unwrap()),
            Contiguous::<Ipv6Network>::try_from(net)
        );

        // Strict: an IPv4 network is not embedded.
        let net = Contiguous::<IpNetwork>::parse("192.168.0.0/16").unwrap();
        assert_eq!(Err(IpVersionMismatchError), Contiguous::<Ipv6Network>::try_from(net));
    }

    #[test]
    fn contiguous_supernet_keeps_the_type() {
        let net = Contiguous::<Ipv4Network>::parse("172.16.1.0/24").unwrap();
        let expected = Contiguous::<Ipv4Network>::parse("172.16.0.0/23").unwrap();
        assert_eq!(Some(expected), net.supernet());
        assert_eq!(None, Contiguous::<Ipv4Network>::parse("0.0.0.0/0").unwrap().supernet());

        let net = Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap();
        let expected = Contiguous::<Ipv6Network>::parse("2001:db8::/47").unwrap();
        assert_eq!(Some(expected), net.supernet());
        assert_eq!(None, Contiguous::<Ipv6Network>::parse("::/0").unwrap().supernet());

        let net = Contiguous::<IpNetwork>::parse("172.16.1.0/24").unwrap();
        let expected = Contiguous::<IpNetwork>::parse("172.16.0.0/23").unwrap();
        assert_eq!(Some(expected), net.supernet());

        let net = Contiguous::<IpNetwork>::parse("2001:db8:1::/48").unwrap();
        let expected = Contiguous::<IpNetwork>::parse("2001:db8::/47").unwrap();
        assert_eq!(Some(expected), net.supernet());

        assert_eq!(None, Contiguous::<IpNetwork>::parse("0.0.0.0/0").unwrap().supernet());
        assert_eq!(None, Contiguous::<IpNetwork>::parse("::/0").unwrap().supernet());
    }

    #[test]
    fn contiguous_intersection_keeps_the_type() {
        let a = Contiguous::<Ipv4Network>::parse("172.16.0.0/16").unwrap();
        let b = Contiguous::<Ipv4Network>::parse("172.16.1.0/24").unwrap();
        let c = Contiguous::<Ipv4Network>::parse("172.16.2.0/24").unwrap();
        assert_eq!(Some(b), a.intersection(&b));
        assert_eq!(Some(b), b.intersection(&a));
        assert_eq!(None, b.intersection(&c));

        let a = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let b = Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap();
        let c = Contiguous::<Ipv6Network>::parse("2001:db8:2::/48").unwrap();
        assert_eq!(Some(b), a.intersection(&b));
        assert_eq!(Some(b), b.intersection(&a));
        assert_eq!(None, b.intersection(&c));

        let a = Contiguous::<IpNetwork>::parse("172.16.0.0/16").unwrap();
        let b = Contiguous::<IpNetwork>::parse("172.16.1.0/24").unwrap();
        assert_eq!(Some(b), a.intersection(&b));

        let a = Contiguous::<IpNetwork>::parse("2001:db8::/32").unwrap();
        let b = Contiguous::<IpNetwork>::parse("2001:db8:1::/48").unwrap();
        assert_eq!(Some(b), a.intersection(&b));

        // Different address families.
        let v4 = Contiguous::<IpNetwork>::parse("0.0.0.0/0").unwrap();
        let v6 = Contiguous::<IpNetwork>::parse("::/0").unwrap();
        assert_eq!(None, v4.intersection(&v6));
        assert_eq!(None, v6.intersection(&v4));
    }

    #[test]
    fn contiguous_merge_by_lowest_mask_bit_keeps_the_type() {
        let a = Contiguous::<Ipv4Network>::parse("172.16.0.0/24").unwrap();
        let b = Contiguous::<Ipv4Network>::parse("172.16.1.0/24").unwrap();
        let c = Contiguous::<Ipv4Network>::parse("172.16.2.0/24").unwrap();
        let parent = Contiguous::<Ipv4Network>::parse("172.16.0.0/23").unwrap();
        assert_eq!(Some(parent), a.merge_by_lowest_mask_bit(&b));
        assert_eq!(Some(parent), b.merge_by_lowest_mask_bit(&a));
        assert_eq!(Some(parent), a.merge_by_lowest_mask_bit(&parent));
        assert_eq!(None, a.merge_by_lowest_mask_bit(&c));

        let a = Contiguous::<Ipv6Network>::parse("2001:db8::/48").unwrap();
        let b = Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap();
        let c = Contiguous::<Ipv6Network>::parse("2001:db8:2::/48").unwrap();
        let parent = Contiguous::<Ipv6Network>::parse("2001:db8::/47").unwrap();
        assert_eq!(Some(parent), a.merge_by_lowest_mask_bit(&b));
        assert_eq!(Some(parent), b.merge_by_lowest_mask_bit(&a));
        assert_eq!(Some(parent), a.merge_by_lowest_mask_bit(&parent));
        assert_eq!(None, a.merge_by_lowest_mask_bit(&c));

        let a = Contiguous::<IpNetwork>::parse("172.16.0.0/24").unwrap();
        let b = Contiguous::<IpNetwork>::parse("172.16.1.0/24").unwrap();
        let c = Contiguous::<IpNetwork>::parse("172.16.2.0/24").unwrap();
        let parent = Contiguous::<IpNetwork>::parse("172.16.0.0/23").unwrap();
        assert_eq!(Some(parent), a.merge_by_lowest_mask_bit(&b));
        assert_eq!(None, a.merge_by_lowest_mask_bit(&c));

        let a = Contiguous::<IpNetwork>::parse("2001:db8::/48").unwrap();
        let b = Contiguous::<IpNetwork>::parse("2001:db8:1::/48").unwrap();
        let parent = Contiguous::<IpNetwork>::parse("2001:db8::/47").unwrap();
        assert_eq!(Some(parent), a.merge_by_lowest_mask_bit(&b));

        // Different address families, even where one would contain the other
        // within a family.
        let v4 = Contiguous::<IpNetwork>::parse("0.0.0.0/0").unwrap();
        let v6 = Contiguous::<IpNetwork>::parse("::/0").unwrap();
        assert_eq!(None, v4.merge_by_lowest_mask_bit(&v6));
        assert_eq!(None, v6.merge_by_lowest_mask_bit(&v4));
    }

    #[test]
    fn contiguous_as_ref_borrows_the_wrapped_network() {
        let net = Contiguous::<Ipv4Network>::parse("192.168.0.0/16").unwrap();
        assert!(core::ptr::eq(&*net, net.as_ref()));

        let net = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        assert!(core::ptr::eq(&*net, net.as_ref()));

        let net = Contiguous::<IpNetwork>::parse("2001:db8::/32").unwrap();
        assert!(core::ptr::eq(&*net, net.as_ref()));
    }

    // The networks of `ipv4_binary_split`'s non-consecutive example, wrapped:
    // the split moves `10.0.0.28/30` ahead of `10.0.0.25/32` in the slice of
    // `Contiguous` itself.
    #[test]
    fn contiguous_ipv4_binary_split_through_as_ref() {
        let nets = &[
            "10.0.0.4/32",
            "10.0.0.6/31",
            "10.0.0.12/31",
            "10.0.0.20/31",
            "10.0.0.25/32",
            "10.0.0.28/30",
            "10.0.0.56/30",
        ];
        let mut nets: Vec<_> = nets
            .iter()
            .map(|net| Contiguous::<Ipv4Network>::parse(net).unwrap())
            .collect();

        let (supernet, range) = ipv4_binary_split(&mut nets).unwrap();
        assert_eq!(Ipv4Network::parse("10.0.0.4/255.255.255.228").unwrap(), supernet);
        assert_eq!(0..5, range);
        assert_eq!(Contiguous::<Ipv4Network>::parse("10.0.0.28/30").unwrap(), nets[4]);
        assert_eq!(Contiguous::<Ipv4Network>::parse("10.0.0.25/32").unwrap(), nets[5]);
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

    // Contiguous and non-contiguous masks in equal measure. A uniformly random
    // mask is almost never contiguous, which would leave the accepting branch
    // of the `TryFrom` network conversions untested.
    fn arb_mixed_ipv4_network() -> impl Strategy<Value = Ipv4Network> {
        prop_oneof![arb_ipv4_network(), arb_contiguous_ipv4_network().prop_map(|net| *net)]
    }

    fn arb_mixed_ipv6_network() -> impl Strategy<Value = Ipv6Network> {
        prop_oneof![arb_ipv6_network(), arb_contiguous_ipv6_network().prop_map(|net| *net)]
    }

    fn arb_mixed_ip_network() -> impl Strategy<Value = IpNetwork> {
        prop_oneof![
            arb_mixed_ipv4_network().prop_map(IpNetwork::V4),
            arb_mixed_ipv6_network().prop_map(IpNetwork::V6),
        ]
    }

    fn arb_ip_addr() -> impl Strategy<Value = IpAddr> {
        prop_oneof![
            any::<u32>().prop_map(|addr| IpAddr::V4(Ipv4Addr::from_bits(addr))),
            any::<u128>().prop_map(|addr| IpAddr::V6(Ipv6Addr::from_bits(addr))),
        ]
    }

    // Contiguous networks of both families with a uniform prefix length,
    // unlike `arb_contiguous_ip_network`, whose prefixes are mostly short.
    fn arb_prefixed_contiguous_ip_network() -> impl Strategy<Value = Contiguous<IpNetwork>> {
        prop_oneof![
            (any::<u32>(), 0u8..=32).prop_map(|(addr, prefix)| {
                Contiguous::<IpNetwork>::from_prefix(IpAddr::V4(Ipv4Addr::from_bits(addr)), prefix).unwrap()
            }),
            (any::<u128>(), 0u8..=128).prop_map(|(addr, prefix)| {
                Contiguous::<IpNetwork>::from_prefix(IpAddr::V6(Ipv6Addr::from_bits(addr)), prefix).unwrap()
            }),
        ]
    }

    // Pairs of contiguous networks in four relations, in equal measure: nested,
    // siblings under the network one prefix bit shorter, equal prefixes that
    // differ in one random bit of it, and unrelated. Two random prefixes are
    // almost always disjoint, which would leave the `Some` branches of
    // `intersection` and `merge_by_lowest_mask_bit` untested, and the third
    // relation is where `merge` and `merge_by_lowest_mask_bit` part.
    fn arb_related_contiguous_ipv4_networks()
    -> impl Strategy<Value = (Contiguous<Ipv4Network>, Contiguous<Ipv4Network>)> {
        (any::<u32>(), any::<u32>(), 0u8..=32, 0u8..=32, 0u8..4).prop_map(|(addr, other, p, q, relation)| {
            let net = |addr, prefix| Contiguous::<Ipv4Network>::from_prefix(Ipv4Addr::from_bits(addr), prefix).unwrap();
            // The last bit of the prefix, and a random one of its bits; none
            // for a `/0`.
            let last = 1u32.checked_shl(32 - u32::from(p)).unwrap_or(0);
            let any = 1u32.checked_shl(31 - other % u32::from(p.max(1))).unwrap_or(0)
                & !u32::MAX.checked_shr(u32::from(p)).unwrap_or(0);

            let b = match relation {
                0 => net(addr, q),
                1 => net(addr ^ last, p),
                2 => net(addr ^ any, p),
                _ => net(other, q),
            };
            (net(addr, p), b)
        })
    }

    fn arb_related_contiguous_ipv6_networks()
    -> impl Strategy<Value = (Contiguous<Ipv6Network>, Contiguous<Ipv6Network>)> {
        (any::<u128>(), any::<u128>(), 0u8..=128, 0u8..=128, 0u8..4).prop_map(|(addr, other, p, q, relation)| {
            let net = |addr, prefix| Contiguous::<Ipv6Network>::from_prefix(Ipv6Addr::from_bits(addr), prefix).unwrap();
            let last = 1u128.checked_shl(128 - u32::from(p)).unwrap_or(0);
            let any = 1u128
                .checked_shl(127 - (other % u128::from(p.max(1))) as u32)
                .unwrap_or(0)
                & !u128::MAX.checked_shr(u32::from(p)).unwrap_or(0);

            let b = match relation {
                0 => net(addr, q),
                1 => net(addr ^ last, p),
                2 => net(addr ^ any, p),
                _ => net(other, q),
            };
            (net(addr, p), b)
        })
    }

    // The related pairs of each family, and pairs of different families.
    fn arb_related_contiguous_ip_networks() -> impl Strategy<Value = (Contiguous<IpNetwork>, Contiguous<IpNetwork>)> {
        prop_oneof![
            arb_related_contiguous_ipv4_networks()
                .prop_map(|(a, b)| (Contiguous::<IpNetwork>::from(a), Contiguous::<IpNetwork>::from(b))),
            arb_related_contiguous_ipv6_networks()
                .prop_map(|(a, b)| (Contiguous::<IpNetwork>::from(a), Contiguous::<IpNetwork>::from(b))),
            (
                arb_contiguous_ipv4_network(),
                arb_contiguous_ipv6_network(),
                any::<bool>()
            )
                .prop_map(|(v4, v6, swap)| {
                    let (v4, v6) = (Contiguous::<IpNetwork>::from(v4), Contiguous::<IpNetwork>::from(v6));
                    if swap { (v6, v4) } else { (v4, v6) }
                }),
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
        fn prop_contiguous_ipv4_tryfrom_matches_typed(addr in any::<u32>(), cidr in 0u8..=33) {
            let addr = Ipv4Addr::from_bits(addr);
            let result = Contiguous::<Ipv4Network>::try_from((addr, cidr));

            prop_assert_eq!(result.is_ok(), cidr <= 32);
            if let Ok(net) = result {
                prop_assert_eq!(cidr, net.prefix());
                prop_assert!((*net).is_contiguous());
            }
        }

        #[test]
        fn prop_contiguous_ipv6_tryfrom_matches_typed(addr in any::<u128>(), cidr in 0u8..=129) {
            let addr = Ipv6Addr::from_bits(addr);
            let result = Contiguous::<Ipv6Network>::try_from((addr, cidr));

            prop_assert_eq!(result.is_ok(), cidr <= 128);
            if let Ok(net) = result {
                prop_assert_eq!(cidr, net.prefix());
                prop_assert!((*net).is_contiguous());
            }
        }

        #[test]
        fn prop_contiguous_ip_tryfrom_matches_typed_v4(addr in any::<u32>(), cidr in 0u8..=33) {
            let addr = IpAddr::V4(Ipv4Addr::from_bits(addr));
            let result = Contiguous::<IpNetwork>::try_from((addr, cidr));

            prop_assert_eq!(result.is_ok(), cidr <= 32);
            if let Ok(net) = result {
                prop_assert_eq!(cidr, net.prefix());
                prop_assert!((*net).is_contiguous());
            }
        }

        #[test]
        fn prop_contiguous_ip_tryfrom_matches_typed_v6(addr in any::<u128>(), cidr in 0u8..=129) {
            let addr = IpAddr::V6(Ipv6Addr::from_bits(addr));
            let result = Contiguous::<IpNetwork>::try_from((addr, cidr));

            prop_assert_eq!(result.is_ok(), cidr <= 128);
            if let Ok(net) = result {
                prop_assert_eq!(cidr, net.prefix());
                prop_assert!((*net).is_contiguous());
            }
        }

        // `from_prefix` must build exactly the network the `(addr, prefix)`
        // conversion builds, and accept exactly the prefix lengths it accepts,
        // so the conversion's properties above carry over. The address it was
        // given stays a member: normalization clears only host bits.
        #[test]
        fn prop_contiguous_ipv4_from_prefix_matches_tryfrom(addr in any::<u32>(), prefix in 0u8..=33) {
            let addr = Ipv4Addr::from_bits(addr);
            let net = Contiguous::<Ipv4Network>::from_prefix(addr, prefix);

            prop_assert_eq!(net, Contiguous::<Ipv4Network>::try_from((addr, prefix)).ok());
            if let Some(net) = net {
                prop_assert!((*net).contains(&Ipv4Network::from(addr)));
            }
        }

        #[test]
        fn prop_contiguous_ipv6_from_prefix_matches_tryfrom(addr in any::<u128>(), prefix in 0u8..=129) {
            let addr = Ipv6Addr::from_bits(addr);
            let net = Contiguous::<Ipv6Network>::from_prefix(addr, prefix);

            prop_assert_eq!(net, Contiguous::<Ipv6Network>::try_from((addr, prefix)).ok());
            if let Some(net) = net {
                prop_assert!((*net).contains(&Ipv6Network::from(addr)));
            }
        }

        #[test]
        fn prop_contiguous_ip_from_prefix_matches_tryfrom(addr in arb_ip_addr(), prefix in 0u8..=129) {
            let net = Contiguous::<IpNetwork>::from_prefix(addr, prefix);

            prop_assert_eq!(net, Contiguous::<IpNetwork>::try_from((addr, prefix)).ok());
            if let Some(net) = net {
                prop_assert!((*net).contains(&IpNetwork::from(addr)));
            }
        }

        #[test]
        fn prop_contiguous_ipv4_tryfrom_network_matches_is_contiguous(net in arb_mixed_ipv4_network()) {
            let result = Contiguous::<Ipv4Network>::try_from(net);

            prop_assert_eq!(result.is_ok(), net.is_contiguous());
            if let Ok(converted) = result {
                prop_assert_eq!(*converted, net);
            }
        }

        #[test]
        fn prop_contiguous_ipv6_tryfrom_network_matches_is_contiguous(net in arb_mixed_ipv6_network()) {
            let result = Contiguous::<Ipv6Network>::try_from(net);

            prop_assert_eq!(result.is_ok(), net.is_contiguous());
            if let Ok(converted) = result {
                prop_assert_eq!(*converted, net);
            }
        }

        #[test]
        fn prop_contiguous_ip_tryfrom_network_matches_is_contiguous(net in arb_mixed_ip_network()) {
            let result = Contiguous::<IpNetwork>::try_from(net);

            prop_assert_eq!(result.is_ok(), net.is_contiguous());
            if let Ok(converted) = result {
                prop_assert_eq!(*converted, net);
            }
        }

        // Only the narrowing to the network's own version succeeds, and
        // widening its result back through `From` gives the network.
        #[test]
        fn prop_contiguous_tryfrom_contiguous_ip_network_narrows_by_version(net in arb_contiguous_ip_network()) {
            let v4 = Contiguous::<Ipv4Network>::try_from(net);
            let v6 = Contiguous::<Ipv6Network>::try_from(net);

            match *net {
                IpNetwork::V4(..) => {
                    prop_assert_eq!(Ok(net), v4.map(Contiguous::<IpNetwork>::from));
                    prop_assert_eq!(Err(IpVersionMismatchError), v6);
                }
                IpNetwork::V6(..) => {
                    prop_assert_eq!(Ok(net), v6.map(Contiguous::<IpNetwork>::from));
                    prop_assert_eq!(Err(IpVersionMismatchError), v4);
                }
            }
        }

        // The typed supernet wraps the general one, and the result is
        // contiguous, as the wrapper promises.
        #[test]
        fn prop_contiguous_ipv4_supernet_matches_general(addr in any::<u32>(), prefix in 0u8..=32) {
            let net = Contiguous::<Ipv4Network>::from_prefix(Ipv4Addr::from_bits(addr), prefix).unwrap();
            let supernet = net.supernet();

            prop_assert_eq!((*net).supernet(), supernet.map(|net| *net));
            if let Some(supernet) = supernet {
                prop_assert!((*supernet).is_contiguous());
            }
        }

        #[test]
        fn prop_contiguous_ipv6_supernet_matches_general(addr in any::<u128>(), prefix in 0u8..=128) {
            let net = Contiguous::<Ipv6Network>::from_prefix(Ipv6Addr::from_bits(addr), prefix).unwrap();
            let supernet = net.supernet();

            prop_assert_eq!((*net).supernet(), supernet.map(|net| *net));
            if let Some(supernet) = supernet {
                prop_assert!((*supernet).is_contiguous());
            }
        }

        #[test]
        fn prop_contiguous_ip_supernet_matches_general(net in arb_prefixed_contiguous_ip_network()) {
            let supernet = net.supernet();

            prop_assert_eq!((*net).supernet(), supernet.map(|net| *net));
            if let Some(supernet) = supernet {
                prop_assert!((*supernet).is_contiguous());
            }
        }

        // The typed intersection and merge wrap the general ones, and their
        // results are contiguous, as the wrapper promises.
        #[test]
        fn prop_contiguous_ipv4_intersection_matches_general((a, b) in arb_related_contiguous_ipv4_networks()) {
            let intersection = a.intersection(&b);

            prop_assert_eq!((*a).intersection(&b), intersection.map(|net| *net));
            if let Some(net) = intersection {
                prop_assert!((*net).is_contiguous());
            }
        }

        #[test]
        fn prop_contiguous_ipv6_intersection_matches_general((a, b) in arb_related_contiguous_ipv6_networks()) {
            let intersection = a.intersection(&b);

            prop_assert_eq!((*a).intersection(&b), intersection.map(|net| *net));
            if let Some(net) = intersection {
                prop_assert!((*net).is_contiguous());
            }
        }

        #[test]
        fn prop_contiguous_ip_intersection_matches_general((a, b) in arb_related_contiguous_ip_networks()) {
            let intersection = a.intersection(&b);

            prop_assert_eq!((*a).intersection(&b), intersection.map(|net| *net));
            if let Some(net) = intersection {
                prop_assert!((*net).is_contiguous());
            }
        }

        #[test]
        fn prop_contiguous_ipv4_merge_by_lowest_mask_bit_matches_general(
            (a, b) in arb_related_contiguous_ipv4_networks(),
        ) {
            let merged = a.merge_by_lowest_mask_bit(&b);

            prop_assert_eq!((*a).merge_by_lowest_mask_bit(&b), merged.map(|net| *net));
            if let Some(net) = merged {
                prop_assert!((*net).is_contiguous());
            }
        }

        #[test]
        fn prop_contiguous_ipv6_merge_by_lowest_mask_bit_matches_general(
            (a, b) in arb_related_contiguous_ipv6_networks(),
        ) {
            let merged = a.merge_by_lowest_mask_bit(&b);

            prop_assert_eq!((*a).merge_by_lowest_mask_bit(&b), merged.map(|net| *net));
            if let Some(net) = merged {
                prop_assert!((*net).is_contiguous());
            }
        }

        #[test]
        fn prop_contiguous_ip_merge_by_lowest_mask_bit_matches_general((a, b) in arb_related_contiguous_ip_networks()) {
            let merged = a.merge_by_lowest_mask_bit(&b);

            prop_assert_eq!((*a).merge_by_lowest_mask_bit(&b), merged.map(|net| *net));
            if let Some(net) = merged {
                prop_assert!((*net).is_contiguous());
            }
        }

        // Through `AsRef`, a slice of `Contiguous` splits exactly as the
        // networks it wraps: the same supernet, often a non-contiguous one,
        // the same block and the same reordering.
        #[test]
        fn prop_contiguous_ipv4_binary_split_matches_inner(nets in arb_clustered_contiguous_ipv4_networks()) {
            let mut nets = nets;
            nets.sort();
            nets.dedup();
            let mut inner: Vec<Ipv4Network> = nets.iter().map(|net| **net).collect();

            prop_assert_eq!(ipv4_binary_split(&mut inner), ipv4_binary_split(&mut nets));
            prop_assert_eq!(inner, nets.iter().map(|net| **net).collect::<Vec<_>>());
        }

        #[test]
        fn prop_contiguous_ipv6_binary_split_matches_inner(nets in arb_clustered_contiguous_ipv6_networks()) {
            let mut nets = nets;
            nets.sort();
            nets.dedup();
            let mut inner: Vec<Ipv6Network> = nets.iter().map(|net| **net).collect();

            prop_assert_eq!(ipv6_binary_split(&mut inner), ipv6_binary_split(&mut nets));
            prop_assert_eq!(inner, nets.iter().map(|net| **net).collect::<Vec<_>>());
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

        #[test]
        fn prop_contiguous_round_trips_through_display(
            v4 in arb_contiguous_ipv4_network(),
            v6 in arb_contiguous_ipv6_network(),
            ip in arb_contiguous_ip_network(),
        ) {
            prop_assert_eq!(Ok(v4), v4.to_string().parse::<Contiguous<Ipv4Network>>());
            prop_assert_eq!(Ok(v6), v6.to_string().parse::<Contiguous<Ipv6Network>>());
            prop_assert_eq!(Ok(ip), ip.to_string().parse::<Contiguous<IpNetwork>>());
        }
    }
}
