//! IPv4/IPv6 network primitives.
//!
//! This module provides types for IP networks by extending the standard
//! library.
//!
//! Unlike most open-source libraries, this module is designed to support
//! non-contiguous masks.

use core::{
    cmp::Ordering,
    convert::TryFrom,
    error::Error,
    fmt::{Debug, Display, Formatter},
    net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr},
    num::ParseIntError,
    ops::{Deref, Range},
    str::FromStr,
};

const IPV4_ALL_BITS: Ipv4Addr = Ipv4Addr::new(0xff, 0xff, 0xff, 0xff);
const IPV6_ALL_BITS: Ipv6Addr = Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff);

/// An error that is returned during IP network conversion from address and CIDR
/// when the CIDR is too large.
#[derive(Debug, PartialEq, Eq)]
pub struct CidrOverflowError(u8, u8);

impl Display for CidrOverflowError {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), core::fmt::Error> {
        let Self(from, to) = self;
        write!(fmt, "invalid CIDR: {from} must be <= {to}")
    }
}

/// An error that is returned during IP network parsing.
#[derive(Debug, PartialEq)]
pub enum IpNetParseError {
    /// Expected IP network, but got something malformed instead.
    ExpectedIpNetwork,
    /// Expected IP address.
    ExpectedIpAddr,
    /// Failed to parse IP address.
    AddrParseError(AddrParseError),
    /// Expected CIDR number after `/`.
    ExpectedIpCidr,
    /// Failed to parse CIDR mask.
    CidrParseError(ParseIntError),
    /// CIDR mask is too large.
    CidrOverflow(CidrOverflowError),
}

impl Display for IpNetParseError {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), core::fmt::Error> {
        match self {
            Self::ExpectedIpNetwork => {
                write!(fmt, "expected IP network")
            }
            Self::ExpectedIpAddr => {
                write!(fmt, "expected IP address")
            }
            Self::AddrParseError(err) => {
                write!(fmt, "IP address parse error: {err}")
            }
            Self::ExpectedIpCidr => {
                write!(fmt, "expected IP CIDR")
            }
            Self::CidrParseError(err) => {
                write!(fmt, "CIDR parse error: {err}")
            }
            Self::CidrOverflow(err) => {
                write!(fmt, "CIDR overflow: {err}")
            }
        }
    }
}

impl Error for IpNetParseError {}

impl From<AddrParseError> for IpNetParseError {
    #[inline]
    fn from(err: AddrParseError) -> Self {
        Self::AddrParseError(err)
    }
}

impl From<CidrOverflowError> for IpNetParseError {
    #[inline]
    fn from(err: CidrOverflowError) -> Self {
        Self::CidrOverflow(err)
    }
}

/// Returns an [`Ipv4Addr`] that will have exact `cidr` leading bits set to
/// one.
///
/// This function is used to construct IP masks for the given network prefix
/// size.
#[inline]
pub fn ipv4_mask_from_cidr(cidr: u8) -> Result<Ipv4Addr, CidrOverflowError> {
    if cidr <= 32 {
        let mask = !(u32::MAX.checked_shr(cidr as u32).unwrap_or_default());
        Ok(mask.into())
    } else {
        Err(CidrOverflowError(cidr, 32))
    }
}

/// Returns an [`Ipv6Addr`] that will have exact `cidr` leading bits set to
/// one.
///
/// This function is used to construct IP masks for the given network prefix
/// size.
#[inline]
pub fn ipv6_mask_from_cidr(cidr: u8) -> Result<Ipv6Addr, CidrOverflowError> {
    if cidr <= 128 {
        let mask = !(u128::MAX.checked_shr(cidr as u32).unwrap_or_default());
        Ok(mask.into())
    } else {
        Err(CidrOverflowError(cidr, 128))
    }
}

/// Returns the single differing bit if two same-mask IPv4 networks are
/// adjacent (addresses differ by exactly one masked bit), `None` otherwise.
#[inline]
const fn ipv4_adjacent_bit(a1: u32, m1: u32, a2: u32, m2: u32) -> Option<u32> {
    if m1 != m2 {
        return None;
    }
    let d = a1 ^ a2;
    if d != 0 && d & (d - 1) == 0 { Some(d) } else { None }
}

/// Returns the single differing bit if two same-mask IPv6 networks are
/// adjacent (addresses differ by exactly one masked bit), `None` otherwise.
#[inline]
const fn ipv6_adjacent_bit(a1: u128, m1: u128, a2: u128, m2: u128) -> Option<u128> {
    if m1 != m2 {
        return None;
    }
    let d = a1 ^ a2;
    if d != 0 && d & (d - 1) == 0 { Some(d) } else { None }
}

/// An IP network, either IPv4 or IPv6.
///
/// This enum can contain either an [`Ipv4Network`] or an [`Ipv6Network`], see
/// their respective documentation for more details.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IpNetwork {
    /// An IPv4 network.
    V4(Ipv4Network),
    /// An IPv6 network.
    V6(Ipv6Network),
}

impl IpNetwork {
    /// Parses specified buffer into an extended IP network.
    ///
    /// The following formats are supported:
    ///
    /// | Format                   | Example                           |
    /// |--------------------------|-----------------------------------|
    /// | IPv4                     | `77.88.55.242`                    |
    /// | IPv4/CIDR                | `77.88.0.0/16`                    |
    /// | IPv4/IPv4                | `77.88.0.0/255.255.0.0`           |
    /// | IPv6                     | `2a02:6b8::2:242`                 |
    /// | IPv6/CIDR                | `2a02:6b8:c00::/40`               |
    /// | IPv6/IPv6                | `2a02:6b8:c00::/ffff:ffff:ff00::` |
    ///
    /// # Note
    ///
    /// During construction, the address is normalized using mask, for example
    /// the network `77.88.55.242/16` becomes `77.88.0.0/16`.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::{Ipv4Addr, Ipv6Addr};
    ///
    /// use netip::{IpNetwork, Ipv4Network, Ipv6Network};
    ///
    /// // Here are some examples to show supported formats and the output of this function.
    ///
    /// // We can parse IPv4 addresses without explicit `/32` mask.
    /// assert_eq!(
    ///     IpNetwork::V4(Ipv4Network::new(
    ///         Ipv4Addr::new(77, 88, 55, 242),
    ///         Ipv4Addr::new(255, 255, 255, 255),
    ///     ),),
    ///     // IPv4 address.
    ///     IpNetwork::parse("77.88.55.242").unwrap(),
    /// );
    ///
    /// // When a mask can be represented in common CIDR format, like `/16`,
    /// // which means "leading 16 bits on the mask is set to one".
    /// assert_eq!(
    ///     IpNetwork::V4(Ipv4Network::new(
    ///         Ipv4Addr::new(77, 88, 0, 0),
    ///         Ipv4Addr::new(255, 255, 0, 0),
    ///     ),),
    ///     // IPv4 CIDR network.
    ///     IpNetwork::parse("77.88.0.0/16").unwrap(),
    /// );
    ///
    /// // But we can also specify mask explicitly. This is useful when we
    /// // want non-contiguous mask.
    /// assert_eq!(
    ///     IpNetwork::V4(Ipv4Network::new(
    ///         Ipv4Addr::new(77, 88, 0, 0),
    ///         Ipv4Addr::new(255, 255, 0, 0),
    ///     ),),
    ///     // IPv4 network with explicit mask.
    ///     IpNetwork::parse("77.88.0.0/255.255.0.0").unwrap(),
    /// );
    ///
    /// // Parse IPv6 addresses without explicit `/128` mask.
    /// assert_eq!(
    ///     IpNetwork::V6(Ipv6Network::new(
    ///         Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0x2, 0x242),
    ///         Ipv6Addr::new(
    ///             0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
    ///         ),
    ///     ),),
    ///     // IPv6 address.
    ///     IpNetwork::parse("2a02:6b8::2:242").unwrap(),
    /// );
    ///
    /// // CIDR format.
    /// assert_eq!(
    ///     IpNetwork::V6(Ipv6Network::new(
    ///         Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0, 0, 0),
    ///         Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0, 0, 0, 0),
    ///     ),),
    ///     // IPv6 CIDR network.
    ///     IpNetwork::parse("2a02:6b8:c00::/40").unwrap(),
    /// );
    ///
    /// // Network with explicit mask (contiguous in this case).
    /// assert_eq!(
    ///     IpNetwork::V6(Ipv6Network::new(
    ///         Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0, 0, 0),
    ///         Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0, 0, 0, 0),
    ///     ),),
    ///     // IPv6 network with explicit mask.
    ///     IpNetwork::parse("2a02:6b8:c00::/ffff:ffff:ff00::").unwrap(),
    /// );
    ///
    /// // Network with explicit non-contiguous mask.
    /// assert_eq!(
    ///     IpNetwork::V6(Ipv6Network::new(
    ///         Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 0),
    ///         Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0xffff, 0xffff, 0, 0),
    ///     ),),
    ///     // The same network as above, but specified explicitly.
    ///     IpNetwork::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap(),
    /// );
    /// ```
    pub fn parse(buf: &str) -> Result<Self, IpNetParseError> {
        match Ipv4Network::parse(buf) {
            Ok(net) => {
                return Ok(Self::V4(net));
            }
            Err(IpNetParseError::AddrParseError(..)) => {}
            Err(err) => {
                return Err(err);
            }
        }

        let net = Ipv6Network::parse(buf)?;
        Ok(Self::V6(net))
    }

    /// Returns the IP address of this network.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    ///
    /// use netip::IpNetwork;
    ///
    /// assert_eq!(
    ///     IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
    ///     IpNetwork::parse("192.168.0.0/24").unwrap().addr()
    /// );
    ///
    /// assert_eq!(
    ///     IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
    ///     IpNetwork::parse("2001:db8::/32").unwrap().addr()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn addr(&self) -> IpAddr {
        match self {
            Self::V4(net) => IpAddr::V4(*net.addr()),
            Self::V6(net) => IpAddr::V6(*net.addr()),
        }
    }

    /// Returns the IP mask of this network.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    ///
    /// use netip::IpNetwork;
    ///
    /// assert_eq!(
    ///     IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
    ///     IpNetwork::parse("192.168.0.0/24").unwrap().mask()
    /// );
    ///
    /// assert_eq!(
    ///     IpAddr::V6(Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0)),
    ///     IpNetwork::parse("2001:db8::/32").unwrap().mask()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn mask(&self) -> IpAddr {
        match self {
            Self::V4(net) => IpAddr::V4(*net.mask()),
            Self::V6(net) => IpAddr::V6(*net.mask()),
        }
    }

    /// Returns `true` if this IP network fully contains the specified one.
    ///
    /// Returns `false` for networks of different address families.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::IpNetwork;
    ///
    /// let a = IpNetwork::parse("192.168.0.0/16").unwrap();
    /// let b = IpNetwork::parse("192.168.1.0/24").unwrap();
    /// assert!(a.contains(&b));
    /// assert!(!b.contains(&a));
    ///
    /// // Different address families.
    /// let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
    /// assert!(!a.contains(&v6));
    /// ```
    #[inline]
    #[must_use]
    pub const fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::V4(a), Self::V4(b)) => a.contains(b),
            (Self::V6(a), Self::V6(b)) => a.contains(b),
            _ => false,
        }
    }

    /// Converts this network to a contiguous network by clearing mask bits
    /// set to one after the first zero bit.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::IpNetwork;
    ///
    /// let net = IpNetwork::parse("192.168.0.1/255.255.0.255").unwrap();
    /// let expected = IpNetwork::parse("192.168.0.0/16").unwrap();
    /// assert_eq!(expected, net.to_contiguous());
    ///
    /// let net = IpNetwork::parse("2001:db8::1/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
    /// let expected = IpNetwork::parse("2001:db8::/40").unwrap();
    /// assert_eq!(expected, net.to_contiguous());
    /// ```
    #[inline]
    #[must_use]
    pub fn to_contiguous(&self) -> Self {
        match self {
            Self::V4(net) => Self::V4(net.to_contiguous()),
            Self::V6(net) => Self::V6(net.to_contiguous()),
        }
    }

    /// Checks whether this network is a contiguous, i.e. contains mask with
    /// only leading bits set to one contiguously.
    #[inline]
    #[must_use]
    pub const fn is_contiguous(&self) -> bool {
        match self {
            Self::V4(net) => net.is_contiguous(),
            Self::V6(net) => net.is_contiguous(),
        }
    }

    /// Returns the mask prefix, i.e. the number of leading bits set, if this
    /// network is a contiguous one, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::IpNetwork;
    ///
    /// assert_eq!(
    ///     Some(24),
    ///     IpNetwork::parse("192.168.1.0/24").unwrap().prefix()
    /// );
    ///
    /// assert_eq!(
    ///     Some(40),
    ///     IpNetwork::parse("2a02:6b8::/40").unwrap().prefix()
    /// );
    /// assert_eq!(Some(128), IpNetwork::parse("2a02:6b8::1").unwrap().prefix());
    /// ```
    #[inline]
    #[must_use]
    pub const fn prefix(&self) -> Option<u8> {
        match self {
            Self::V4(net) => net.prefix(),
            Self::V6(net) => net.prefix(),
        }
    }

    /// Returns the last address in this IP network.
    ///
    /// For contiguous networks, this is the broadcast address.
    ///
    /// For non-contiguous networks, this is the highest address within the
    /// network range defined by the mask.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    ///
    /// use netip::IpNetwork;
    ///
    /// // IPv4 contiguous network.
    /// assert_eq!(
    ///     IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)),
    ///     IpNetwork::parse("192.168.1.0/24").unwrap().last_addr()
    /// );
    ///
    /// // IPv6 contiguous network.
    /// assert_eq!(
    ///     IpAddr::V6(Ipv6Addr::new(
    ///         0x2001, 0xdb8, 0x1, 0, 0xffff, 0xffff, 0xffff, 0xffff
    ///     )),
    ///     IpNetwork::parse("2001:db8:1::/64").unwrap().last_addr()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub fn last_addr(&self) -> IpAddr {
        match self {
            Self::V4(net) => IpAddr::V4(net.last_addr()),
            Self::V6(net) => IpAddr::V6(net.last_addr()),
        }
    }

    /// Returns `true` if this IP network and the specified one share at
    /// least one common address.
    ///
    /// Returns `false` for networks of different address families.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::IpNetwork;
    ///
    /// let a = IpNetwork::parse("192.168.0.0/16").unwrap();
    /// let b = IpNetwork::parse("192.168.1.0/24").unwrap();
    /// assert!(a.intersects(&b));
    ///
    /// let c = IpNetwork::parse("10.0.0.0/8").unwrap();
    /// assert!(!a.intersects(&c));
    ///
    /// // Mixed address families are always disjoint.
    /// let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
    /// assert!(!a.intersects(&v6));
    /// ```
    #[inline]
    #[must_use]
    pub const fn intersects(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::V4(a), Self::V4(b)) => a.intersects(b),
            (Self::V6(a), Self::V6(b)) => a.intersects(b),
            _ => false,
        }
    }

    /// Returns `true` if this IP network and the specified one share no
    /// common addresses.
    ///
    /// Returns `true` for networks of different address families.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::IpNetwork;
    ///
    /// let a = IpNetwork::parse("192.168.0.0/16").unwrap();
    /// let b = IpNetwork::parse("10.0.0.0/8").unwrap();
    /// assert!(a.is_disjoint(&b));
    ///
    /// // Mixed address families are always disjoint.
    /// let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
    /// assert!(a.is_disjoint(&v6));
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_disjoint(&self, other: &Self) -> bool {
        !self.intersects(other)
    }

    /// Returns the intersection of this IP network with the specified one,
    /// or [`None`] if they are disjoint or belong to different address
    /// families.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::IpNetwork;
    ///
    /// let a = IpNetwork::parse("192.168.0.0/16").unwrap();
    /// let b = IpNetwork::parse("192.168.1.0/24").unwrap();
    /// assert_eq!(Some(b), a.intersection(&b));
    ///
    /// // Disjoint.
    /// let c = IpNetwork::parse("10.0.0.0/8").unwrap();
    /// assert_eq!(None, a.intersection(&c));
    ///
    /// // Mixed address families.
    /// let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
    /// assert_eq!(None, a.intersection(&v6));
    /// ```
    #[inline]
    #[must_use]
    pub const fn intersection(&self, other: &Self) -> Option<Self> {
        // NOTE: use `Option::map` when it becomes const.
        match (self, other) {
            (Self::V4(a), Self::V4(b)) => match a.intersection(b) {
                Some(net) => Some(Self::V4(net)),
                None => None,
            },
            (Self::V6(a), Self::V6(b)) => match a.intersection(b) {
                Some(net) => Some(Self::V6(net)),
                None => None,
            },
            _ => None,
        }
    }

    /// Returns `true` if this network is adjacent to `other`.
    ///
    /// Two networks are adjacent when they share the same mask and their
    /// addresses differ by exactly one masked bit, meaning they can be merged
    /// into a single network by dropping that bit from the mask.
    ///
    /// Returns `false` for networks of different address families.
    ///
    /// See [`Ipv4Network::is_adjacent`] and [`Ipv6Network::is_adjacent`] for
    /// details.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::IpNetwork;
    ///
    /// let a = IpNetwork::parse("192.168.0.0/24").unwrap();
    /// let b = IpNetwork::parse("192.168.1.0/24").unwrap();
    /// assert!(a.is_adjacent(&b));
    ///
    /// let c = IpNetwork::parse("192.168.3.0/24").unwrap();
    /// assert!(!a.is_adjacent(&c));
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_adjacent(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::V4(a), Self::V4(b)) => a.is_adjacent(b),
            (Self::V6(a), Self::V6(b)) => a.is_adjacent(b),
            _ => false,
        }
    }

    /// Merges this IP network with another, returning `Some(N)` iff their
    /// union is exactly representable as a single network.
    ///
    /// Returns `None` for networks of different address families.
    ///
    /// See [`Ipv4Network::merge`] and [`Ipv6Network::merge`] for the full
    /// merging rules.
    ///
    /// # Note
    ///
    /// The result may have a non-contiguous mask even when both inputs are
    /// contiguous (CIDR). This happens when addresses differ in a bit that
    /// is not at the boundary of the mask.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::IpNetwork;
    ///
    /// // Adjacent /24 blocks merge into a /23.
    /// let a = IpNetwork::parse("192.168.0.0/24").unwrap();
    /// let b = IpNetwork::parse("192.168.1.0/24").unwrap();
    /// assert_eq!(
    ///     Some(IpNetwork::parse("192.168.0.0/23").unwrap()),
    ///     a.merge(&b)
    /// );
    ///
    /// // Mixed address families cannot be merged.
    /// let v4 = IpNetwork::parse("10.0.0.0/8").unwrap();
    /// let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
    /// assert_eq!(None, v4.merge(&v6));
    /// ```
    #[inline]
    #[must_use]
    pub const fn merge(&self, other: &Self) -> Option<Self> {
        // NOTE: use `Option::map` when it becomes const.
        match (self, other) {
            (Self::V4(a), Self::V4(b)) => match a.merge(b) {
                Some(net) => Some(Self::V4(net)),
                None => None,
            },
            (Self::V6(a), Self::V6(b)) => match a.merge(b) {
                Some(net) => Some(Self::V6(net)),
                None => None,
            },
            _ => None,
        }
    }
}

impl Display for IpNetwork {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), core::fmt::Error> {
        match self {
            IpNetwork::V4(net) => Display::fmt(&net, fmt),
            IpNetwork::V6(net) => Display::fmt(&net, fmt),
        }
    }
}

impl From<Ipv4Addr> for IpNetwork {
    #[inline]
    fn from(addr: Ipv4Addr) -> Self {
        // Construct network directly, because no address mutation occurs.
        Self::V4(Ipv4Network(addr, IPV4_ALL_BITS))
    }
}

impl TryFrom<(Ipv4Addr, u8)> for IpNetwork {
    type Error = CidrOverflowError;

    fn try_from((addr, cidr): (Ipv4Addr, u8)) -> Result<Self, Self::Error> {
        Ok(Self::V4(Ipv4Network::new(addr, ipv4_mask_from_cidr(cidr)?)))
    }
}

impl From<(Ipv4Addr, Ipv4Addr)> for IpNetwork {
    fn from((addr, mask): (Ipv4Addr, Ipv4Addr)) -> Self {
        Self::V4(Ipv4Network::new(addr, mask))
    }
}

impl From<Ipv4Network> for IpNetwork {
    #[inline]
    fn from(net: Ipv4Network) -> Self {
        Self::V4(net)
    }
}

impl From<Ipv6Addr> for IpNetwork {
    fn from(addr: Ipv6Addr) -> Self {
        // Construct network directly, because no address mutation occurs.
        Self::V6(Ipv6Network(addr, IPV6_ALL_BITS))
    }
}

impl TryFrom<(Ipv6Addr, u8)> for IpNetwork {
    type Error = CidrOverflowError;

    fn try_from((addr, cidr): (Ipv6Addr, u8)) -> Result<Self, Self::Error> {
        Ok(Self::V6(Ipv6Network::new(addr, ipv6_mask_from_cidr(cidr)?)))
    }
}

impl From<(Ipv6Addr, Ipv6Addr)> for IpNetwork {
    fn from((addr, mask): (Ipv6Addr, Ipv6Addr)) -> Self {
        Self::V6(Ipv6Network::new(addr, mask))
    }
}

impl From<Ipv6Network> for IpNetwork {
    #[inline]
    fn from(net: Ipv6Network) -> Self {
        Self::V6(net)
    }
}

impl From<IpAddr> for IpNetwork {
    #[inline]
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => Self::from(addr),
            IpAddr::V6(addr) => Self::from(addr),
        }
    }
}

impl FromStr for IpNetwork {
    type Err = IpNetParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IpNetwork::parse(s)
    }
}

/// Represents the network range in which IP addresses are IPv4.
///
/// IPv4 networks are defined as pair of two [`Ipv4Addr`]. One for IP address
/// and the second one - for mask.
///
/// See [`IpNetwork`] for a type encompassing both IPv4 and IPv6 networks.
///
/// # Note
///
/// An IPv4 network represents a range of IPv4 addresses. The most common way to
/// represent an IP network is through CIDR notation. See [IETF RFC 4632] for
/// CIDR notation.
///
/// An example of such notation is `77.152.124.0/24`.
///
/// In CIDR notation, a prefix is shown as a 4-octet quantity, just like a
/// traditional IPv4 address or network number, followed by the "/" (slash)
/// character, followed by a decimal value between 0 and 32 that describes the
/// number of significant bits.
///
/// Here, the "/24" indicates that the mask to extract the network portion of
/// the prefix is a 32-bit value where the most significant 24 bits are
/// ones and the least significant 8 bits are zeros.
///
/// The other way to represent the network above is to use explicit notation,
/// such as `77.152.124.0/255.255.255.0`.
///
/// However, this struct supports non-contiguous masks, i.e. masks with
/// non-contiguous bits set to one, like `77.152.0.55/255.255.0.255`.
///
/// [IETF RFC 4632]: https://tools.ietf.org/html/rfc4632
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4Network(Ipv4Addr, Ipv4Addr);

impl Ipv4Network {
    /// An IPv4 network representing the unspecified network: `0.0.0.0/0`
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::Ipv4Network;
    ///
    /// let net = Ipv4Network::UNSPECIFIED;
    /// assert_eq!(
    ///     Ipv4Network::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0)),
    ///     net
    /// );
    /// ```
    pub const UNSPECIFIED: Self = Self(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED);

    /// Initializes a new [`Ipv4Network`] using specified address and mask.
    ///
    /// During construction the address is normalized using mask, i.e. in case
    /// of `192.168.1.1/255.255.255.0` the result will be transformed
    /// to `192.168.1.0/255.255.255.0`.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::Ipv4Network;
    ///
    /// let net = Ipv4Network::new(
    ///     Ipv4Addr::new(192, 168, 1, 1),
    ///     Ipv4Addr::new(255, 255, 255, 0),
    /// );
    ///
    /// assert_eq!(Ipv4Addr::new(192, 168, 1, 0), *net.addr());
    /// assert_eq!(Ipv4Addr::new(255, 255, 255, 0), *net.mask());
    /// ```
    #[inline]
    #[must_use]
    pub const fn new(addr: Ipv4Addr, mask: Ipv4Addr) -> Self {
        let addr = addr.to_bits() & mask.to_bits();

        Self(Ipv4Addr::from_bits(addr), mask)
    }

    /// Parses the specified buffer into an IPv4 network.
    ///
    /// The following formats are supported:
    /// - IPv4
    /// - IPv4/CIDR
    /// - IPv4/IPv4
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::Ipv4Network;
    ///
    /// let expected = Ipv4Network::new(
    ///     Ipv4Addr::new(192, 168, 1, 1),
    ///     Ipv4Addr::new(255, 255, 255, 255),
    /// );
    ///
    /// assert_eq!(expected, Ipv4Network::parse("192.168.1.1").unwrap());
    /// assert_eq!(expected, Ipv4Network::parse("192.168.1.1/32").unwrap());
    /// assert_eq!(
    ///     expected,
    ///     Ipv4Network::parse("192.168.1.1/255.255.255.255").unwrap()
    /// );
    /// ```
    pub fn parse(buf: &str) -> Result<Self, IpNetParseError> {
        let mut parts = buf.splitn(2, '/');
        let addr = parts.next().ok_or(IpNetParseError::ExpectedIpAddr)?;
        let addr: Ipv4Addr = addr.parse()?;
        match parts.next() {
            Some(mask) => match mask.parse::<u8>() {
                Ok(cidr) => Ok(Self::try_from((addr, cidr))?),
                Err(..) => {
                    // Maybe explicit mask.
                    let mask: Ipv4Addr = mask.parse()?;
                    Ok(Self::new(addr, mask))
                }
            },
            None => Ok(Self(addr, IPV4_ALL_BITS)),
        }
    }

    /// Returns the IP address of this IPv4 network.
    #[inline]
    #[must_use]
    pub const fn addr(&self) -> &Ipv4Addr {
        match self {
            Self(addr, ..) => addr,
        }
    }

    /// Returns the IP mask of this IPv4 network.
    #[inline]
    #[must_use]
    pub const fn mask(&self) -> &Ipv4Addr {
        match self {
            Self(.., mask) => mask,
        }
    }

    /// Converts a pair of IPv4 address and mask represented as a pair of host
    /// byte order `u32` into an IPv4 network.
    ///
    /// # Note
    ///
    /// During conversion, the address is normalized using mask.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::Ipv4Network;
    ///
    /// let expected = Ipv4Network::new(
    ///     Ipv4Addr::new(192, 168, 1, 0),
    ///     Ipv4Addr::new(255, 255, 255, 0),
    /// );
    ///
    /// assert_eq!(expected, Ipv4Network::from_bits(3232235776, 4294967040));
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_bits(addr: u32, mask: u32) -> Self {
        Self::new(Ipv4Addr::from_bits(addr), Ipv4Addr::from_bits(mask))
    }

    /// Converts this IPv4 network's address and mask into pair of host byte
    /// order `u32`.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::Ipv4Network;
    ///
    /// let net = Ipv4Network::new(
    ///     Ipv4Addr::new(192, 168, 1, 0),
    ///     Ipv4Addr::new(255, 255, 255, 0),
    /// );
    /// assert_eq!((3232235776, 4294967040), net.to_bits());
    /// ```
    #[inline]
    #[must_use]
    pub const fn to_bits(&self) -> (u32, u32) {
        match self {
            Self(addr, mask) => (addr.to_bits(), mask.to_bits()),
        }
    }

    /// Returns `true` if this IPv4 network fully contains the specified one.
    #[inline]
    #[must_use]
    pub const fn contains(&self, other: &Ipv4Network) -> bool {
        let (a1, m1) = self.to_bits();
        let (a2, m2) = other.to_bits();

        (a2 & m1 == a1) && (m2 & m1 == m1)
    }

    /// Returns `true` if this IPv4 network and the specified one share at
    /// least one common address.
    ///
    /// Two networks `(a1, m1)` and `(a2, m2)` intersect when they agree on
    /// every bit position that both masks constrain:
    /// `a1 & m2 == a2 & m1`.
    ///
    /// Works correctly with non-contiguous masks.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::Ipv4Network;
    ///
    /// // Overlapping contiguous networks.
    /// let a = Ipv4Network::parse("192.168.0.0/16").unwrap();
    /// let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
    /// assert!(a.intersects(&b));
    ///
    /// // Disjoint contiguous networks.
    /// let c = Ipv4Network::parse("10.0.0.0/8").unwrap();
    /// assert!(!a.intersects(&c));
    ///
    /// // Non-contiguous masks.
    /// let x = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(255, 0, 0, 255));
    /// let y = Ipv4Network::new(Ipv4Addr::new(10, 1, 0, 0), Ipv4Addr::new(255, 255, 0, 0));
    /// assert!(x.intersects(&y));
    /// ```
    #[inline]
    #[must_use]
    pub const fn intersects(&self, other: &Self) -> bool {
        // NOTE: compiler is smart enough to optimize this without constructing
        // the actual intersection.
        self.intersection(other).is_some()
    }

    /// Returns `true` if this IPv4 network and the specified one share no
    /// common addresses.
    ///
    /// This is the logical complement of [`intersects`](Self::intersects).
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::Ipv4Network;
    ///
    /// let a = Ipv4Network::parse("192.168.0.0/16").unwrap();
    /// let b = Ipv4Network::parse("10.0.0.0/8").unwrap();
    /// assert!(a.is_disjoint(&b));
    ///
    /// let c = Ipv4Network::parse("192.168.1.0/24").unwrap();
    /// assert!(!a.is_disjoint(&c));
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_disjoint(&self, other: &Ipv4Network) -> bool {
        !self.intersects(other)
    }

    /// Returns the intersection of this IPv4 network with the specified one,
    /// or [`None`] if they are disjoint.
    ///
    /// The intersection of two networks is itself always a single network
    /// (never a collection), because it constrains strictly more bit
    /// positions.
    ///
    /// Works correctly with non-contiguous masks.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::Ipv4Network;
    ///
    /// // Containment: intersection equals the smaller network.
    /// let a = Ipv4Network::parse("192.168.0.0/16").unwrap();
    /// let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
    /// assert_eq!(Some(b), a.intersection(&b));
    ///
    /// // Non-contiguous masks.
    /// let a = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(255, 0, 0, 255));
    /// let b = Ipv4Network::new(Ipv4Addr::new(10, 1, 0, 0), Ipv4Addr::new(255, 255, 0, 0));
    /// let expected = Ipv4Network::new(Ipv4Addr::new(10, 1, 0, 1), Ipv4Addr::new(255, 255, 0, 255));
    /// assert_eq!(Some(expected), a.intersection(&b));
    ///
    /// // Disjoint networks.
    /// let a = Ipv4Network::parse("192.168.0.0/16").unwrap();
    /// let b = Ipv4Network::parse("10.0.0.0/8").unwrap();
    /// assert_eq!(None, a.intersection(&b));
    /// ```
    #[inline]
    #[must_use]
    pub const fn intersection(&self, other: &Self) -> Option<Self> {
        let (a1, m1) = self.to_bits();
        let (a2, m2) = other.to_bits();

        if (a1 & m2) != (a2 & m1) {
            return None;
        }

        let addr = a1 | a2;
        let mask = m1 | m2;

        let addr = Ipv4Addr::from_bits(addr);
        let mask = Ipv4Addr::from_bits(mask);

        // NOTE: address is already normalized.
        Some(Self(addr, mask))
    }

    /// Returns an iterator over networks whose union equals the set difference
    /// `self \ other`, i.e. all addresses in `self` that are not in `other`.
    ///
    /// The result contains at most `popcount(m2 & !m1)` pairwise-disjoint
    /// networks (at most 32). Works correctly with non-contiguous masks.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::Ipv4Network;
    ///
    /// // Subtracting a /24 from a /16 yields 8 networks.
    /// let a = Ipv4Network::parse("192.168.0.0/16").unwrap();
    /// let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
    /// let diff: Vec<_> = a.difference(&b).collect();
    /// assert_eq!(diff.len(), 8);
    ///
    /// // Disjoint networks: difference is the original.
    /// let a = Ipv4Network::parse("10.0.0.0/8").unwrap();
    /// let b = Ipv4Network::parse("192.168.0.0/16").unwrap();
    /// let diff: Vec<_> = a.difference(&b).collect();
    /// assert_eq!(diff, vec![a]);
    ///
    /// // Subset: difference is empty.
    /// let a = Ipv4Network::parse("192.168.1.0/24").unwrap();
    /// let b = Ipv4Network::parse("192.168.0.0/16").unwrap();
    /// assert_eq!(a.difference(&b).count(), 0);
    /// ```
    #[inline]
    #[must_use]
    pub const fn difference(&self, other: &Self) -> Ipv4NetworkDiff {
        Ipv4NetworkDiff::new(self, other)
    }

    /// Checks whether this network is a contiguous, i.e. contains mask with
    /// only leading bits set to one contiguously.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::Ipv4Network;
    ///
    /// assert!(Ipv4Network::parse("0.0.0.0/0").unwrap().is_contiguous());
    /// assert!(
    ///     Ipv4Network::parse("213.180.192.0/19")
    ///         .unwrap()
    ///         .is_contiguous()
    /// );
    ///
    /// assert!(
    ///     !Ipv4Network::parse("213.180.0.192/255.255.0.255")
    ///         .unwrap()
    ///         .is_contiguous()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_contiguous(&self) -> bool {
        let mask = self.mask().to_bits();
        mask | mask.wrapping_sub(1) == u32::MAX
    }

    /// Returns the mask prefix, i.e. the number of leading bits set, if this
    /// network is a contiguous one, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::Ipv4Network;
    ///
    /// assert_eq!(
    ///     Some(24),
    ///     Ipv4Network::new(
    ///         Ipv4Addr::new(192, 168, 1, 0),
    ///         Ipv4Addr::new(255, 255, 255, 0)
    ///     )
    ///     .prefix()
    /// );
    /// assert_eq!(
    ///     Some(32),
    ///     Ipv4Network::new(
    ///         Ipv4Addr::new(192, 168, 1, 1),
    ///         Ipv4Addr::new(255, 255, 255, 255)
    ///     )
    ///     .prefix()
    /// );
    ///
    /// assert_eq!(
    ///     None,
    ///     Ipv4Network::new(Ipv4Addr::new(192, 0, 1, 0), Ipv4Addr::new(255, 0, 255, 0)).prefix()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn prefix(&self) -> Option<u8> {
        let mask = self.mask().to_bits();
        let ones = mask.leading_ones();

        if mask.count_ones() == ones {
            Some(ones as u8)
        } else {
            None
        }
    }

    /// Converts this network to a contiguous network by clearing mask bits set
    /// to one after the first zero bit.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::Ipv4Network;
    ///
    /// let net = Ipv4Network::new(
    ///     Ipv4Addr::new(192, 168, 0, 1),
    ///     Ipv4Addr::new(255, 255, 0, 255),
    /// );
    /// let expected = Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 0), Ipv4Addr::new(255, 255, 0, 0));
    ///
    /// assert_eq!(expected, net.to_contiguous());
    /// ```
    #[must_use]
    pub fn to_contiguous(&self) -> Self {
        let (addr, mask) = self.to_bits();

        Self::try_from((addr.into(), mask.leading_ones() as u8)).expect("CIDR must be in range [0; 32]")
    }

    /// Calculates and returns the [`Ipv4Network`], which will be a supernet,
    /// i.e. the shortest common network both for this network and the
    /// specified ones.
    ///
    /// # Note
    ///
    /// This function works fine for both contiguous and non-contiguous
    /// networks.
    ///
    /// The result may have a non-contiguous mask even when all inputs are
    /// contiguous (CIDR). This happens when the addresses differ in bits
    /// that are not at the boundary of their masks.
    ///
    /// Use [`Ipv4Network::to_contiguous`] method if you need to convert the
    /// output network.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::Ipv4Network;
    ///
    /// let net0 = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 0), 25)).unwrap();
    /// let net1 = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 128), 25)).unwrap();
    ///
    /// assert_eq!(
    ///     Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 0), 24)).unwrap(),
    ///     net0.supernet_for(&[net1])
    /// );
    ///
    /// // Contiguous inputs, non-contiguous result: addresses differ in
    /// // bit 16, which is not at the mask boundary of /24.
    /// let a = Ipv4Network::parse("10.0.0.0/24").unwrap();
    /// let b = Ipv4Network::parse("10.1.0.0/24").unwrap();
    /// assert_eq!(
    ///     Ipv4Network::parse("10.0.0.0/255.254.255.0").unwrap(),
    ///     a.supernet_for(&[b])
    /// );
    /// ```
    #[must_use]
    pub fn supernet_for(&self, nets: &[Ipv4Network]) -> Ipv4Network {
        let (addr, mut mask) = self.to_bits();

        for net in nets {
            let (a, m) = net.to_bits();
            mask &= m & !(addr ^ a);
        }

        Self::new(addr.into(), mask.into())
    }

    /// Returns `true` if this network is adjacent to `other`.
    ///
    /// Two networks are adjacent when they share the same mask and their
    /// addresses differ by exactly one masked bit, meaning they can be
    /// [`merge`](Self::merge)d into a single network by dropping that bit
    /// from the mask.
    ///
    /// Identical networks are **not** adjacent. Works correctly with
    /// non-contiguous masks.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::Ipv4Network;
    ///
    /// // Adjacent contiguous /24 blocks.
    /// let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
    /// let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
    /// assert!(a.is_adjacent(&b));
    ///
    /// // Non-adjacent: addresses differ by more than one bit.
    /// let c = Ipv4Network::parse("192.168.3.0/24").unwrap();
    /// assert!(!a.is_adjacent(&c));
    ///
    /// // Identical networks are not adjacent.
    /// assert!(!a.is_adjacent(&a));
    ///
    /// // Adjacent non-contiguous networks.
    /// let x = Ipv4Network::parse("10.0.0.1/255.255.0.255").unwrap();
    /// let y = Ipv4Network::parse("10.1.0.1/255.255.0.255").unwrap();
    /// assert!(x.is_adjacent(&y));
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_adjacent(&self, other: &Self) -> bool {
        let (a1, m1) = self.to_bits();
        let (a2, m2) = other.to_bits();
        ipv4_adjacent_bit(a1, m1, a2, m2).is_some()
    }

    /// Merges this IPv4 network with another, returning `Some(N)` iff their
    /// union is exactly representable as a single network.
    ///
    /// Two networks can be merged in two ways:
    ///
    /// - **Equal masks, adjacent blocks**: the masks are identical and the
    ///   addresses differ by exactly one bit. The result drops that bit from
    ///   the mask.
    /// - **Containment**: one network is a subset of the other. The result is
    ///   the larger (containing) network.
    ///
    /// Works correctly with non-contiguous masks.
    ///
    /// # Note
    ///
    /// The result may have a non-contiguous mask even when both inputs are
    /// contiguous (CIDR). This happens when addresses differ in a bit that
    /// is not at the boundary of the mask.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::Ipv4Network;
    ///
    /// // Adjacent /24 blocks merge into a /23.
    /// let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
    /// let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
    /// assert_eq!(
    ///     Some(Ipv4Network::parse("192.168.0.0/23").unwrap()),
    ///     a.merge(&b)
    /// );
    ///
    /// // Containment: larger network is returned.
    /// let a = Ipv4Network::parse("10.0.0.0/8").unwrap();
    /// let b = Ipv4Network::parse("10.1.0.0/16").unwrap();
    /// assert_eq!(Some(a), a.merge(&b));
    ///
    /// // Non-mergeable networks.
    /// let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
    /// let b = Ipv4Network::parse("192.168.3.0/24").unwrap();
    /// assert_eq!(None, a.merge(&b));
    ///
    /// // Contiguous inputs, non-contiguous result: addresses differ in
    /// // bit 16, which is not at the mask boundary of /24.
    /// let a = Ipv4Network::parse("10.0.0.0/24").unwrap();
    /// let b = Ipv4Network::parse("10.1.0.0/24").unwrap();
    /// assert_eq!(
    ///     Some(Ipv4Network::parse("10.0.0.0/255.254.255.0").unwrap()),
    ///     a.merge(&b)
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn merge(&self, other: &Self) -> Option<Self> {
        let (a1, m1) = self.to_bits();
        let (a2, m2) = other.to_bits();

        if m1 == m2 {
            if a1 == a2 {
                return Some(*self);
            }
            if let Some(d) = ipv4_adjacent_bit(a1, m1, a2, m2) {
                let m = m1 ^ d;
                let a = a1 & m;
                return Some(Self(Ipv4Addr::from_bits(a), Ipv4Addr::from_bits(m)));
            }
            return None;
        }

        if self.contains(other) {
            return Some(*self);
        }
        if other.contains(self) {
            return Some(*other);
        }
        None
    }

    /// Converts this network to an IPv4-mapped IPv6 network.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::{Ipv4Addr, Ipv6Addr};
    ///
    /// use netip::{Ipv4Network, Ipv6Network};
    ///
    /// let net = Ipv4Network::new(
    ///     Ipv4Addr::new(192, 168, 1, 42),
    ///     Ipv4Addr::new(255, 255, 252, 0),
    /// );
    /// let expected =
    ///     Ipv6Network::parse("::ffff:c0a8:0/ffff:ffff:ffff:ffff:ffff:ffff:ffff:fc00").unwrap();
    /// assert_eq!(expected, net.to_ipv6_mapped());
    /// ```
    #[inline]
    #[must_use]
    pub const fn to_ipv6_mapped(&self) -> Ipv6Network {
        match self {
            Ipv4Network(addr, mask) => {
                let [a, b, c, d] = mask.octets();
                let [a, b, c, d]: [u16; 4] = [a as u16, b as u16, c as u16, d as u16];
                Ipv6Network(
                    addr.to_ipv6_mapped(),
                    Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, a << 8 | b, c << 8 | d),
                )
            }
        }
    }

    /// Returns the last address in this IPv4 network.
    ///
    /// For contiguous networks, this is the broadcast address.
    ///
    /// For non-contiguous networks, this is the highest address within the
    /// network range defined by the mask.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::Ipv4Network;
    ///
    /// // Contiguous network.
    /// let net = Ipv4Network::new(
    ///     Ipv4Addr::new(192, 168, 1, 0),
    ///     Ipv4Addr::new(255, 255, 255, 0),
    /// );
    /// assert_eq!(Ipv4Addr::new(192, 168, 1, 255), net.last_addr());
    ///
    /// // Single address network.
    /// let net = Ipv4Network::new(
    ///     Ipv4Addr::new(10, 0, 0, 1),
    ///     Ipv4Addr::new(255, 255, 255, 255),
    /// );
    /// assert_eq!(Ipv4Addr::new(10, 0, 0, 1), net.last_addr());
    ///
    /// // Non-contiguous network.
    /// let net = Ipv4Network::new(
    ///     Ipv4Addr::new(192, 168, 0, 1),
    ///     Ipv4Addr::new(255, 255, 0, 255),
    /// );
    /// assert_eq!(Ipv4Addr::new(192, 168, 255, 1), net.last_addr());
    /// ```
    ///
    /// # Formal Proof of Correctness
    ///
    /// ## Given
    /// - Network address: `addr`.
    /// - Network mask: `mask` (may be non-contiguous).
    /// - Algorithm: `last_addr = addr | !mask`.
    ///
    /// ## Definitions
    /// Let:
    /// - `N = addr & mask` (network address with host bits zeroed).
    /// - `H = !mask` (bitmask of host positions).
    /// - Address `X` belongs to the network iff `(X & mask) = N`.
    ///
    /// ## Lemma 1: Contiguous Mask Case
    ///
    /// For contiguous masks (standard CIDR), the algorithm is well-established:
    /// - ` mask` format: `111...100...0`.
    /// - `!mask` format: `000...011...1`.
    /// - `addr | !mask` sets all host bits to 1, yielding the broadcast
    ///   address.
    ///
    /// ## Lemma 2: Generalization to Non-Contiguous Masks
    ///
    /// **Theorem**: `X = addr | !mask` is the maximum address satisfying `(X &
    /// mask) = N`.
    ///
    /// ### Proof:
    ///
    /// 1. **Membership**: ```(X & mask) = ((addr | !mask) & mask) = (addr &
    ///    mask) | (!mask & mask) = N | 0 = N ```
    ///
    ///    Thus, `X` belongs to the network.
    ///
    /// 2. **Maximality**:
    ///    - Any network address can be expressed as `X = N | H_val` where
    ///      `H_val` has ones only in host positions
    ///    - The maximum possible `H_val` is `H = !mask` (all host bits set to
    ///      1)
    ///    - Thus `X_max = N | H = (addr & mask) | !mask`
    ///
    /// 3. **Simplification**: since `addr & mask` zeros all host bits: ```
    ///    (addr & mask) | !mask = addr | !mask ```
    ///    - For mask bits = 1: `addr_bit | 0 = addr_bit`
    ///    - For mask bits = 0: `0 | 1 = 1`
    ///
    /// ## Edge Case Verification
    ///
    /// - **Full mask** (255.255.255.255): `last_addr = addr | 0 = addr` (single
    ///   address network).
    ///
    /// - **Zero mask** (0.0.0.0): `last_addr = addr | 0xFFFFFFFF =
    ///   255.255.255.255` (entire address space).
    ///
    /// - **Non-contiguous mask** (e.g., 255.0.255.0): Correctly sets all host
    ///   bits to 1 while preserving network bits.
    ///
    /// ## ∴
    ///
    /// The algorithm `addr | !mask` correctly computes the maximum address in
    /// any IPv4 network, including those with non-contiguous masks.
    #[inline]
    #[must_use]
    pub const fn last_addr(&self) -> Ipv4Addr {
        let (addr, mask) = self.to_bits();
        Ipv4Addr::from_bits(addr | !mask)
    }

    /// Returns a double-ended iterator over every address in this network.
    ///
    /// The iterator yields addresses in **host-index order**: the *k* host
    /// positions (bits where the mask is zero) are filled with successive
    /// values `0 ..= 2^k - 1`, starting from the least-significant host bit.
    ///
    /// For a standard (contiguous) CIDR mask this is equivalent to ascending
    /// numeric order from [`addr()`](Ipv4Network::addr) to
    /// [`last_addr()`](Ipv4Network::last_addr).
    ///
    /// For a non-contiguous mask the numeric order of the produced addresses
    /// may differ from the iteration order.
    ///
    /// The iterator implements [`DoubleEndedIterator`] and
    /// [`ExactSizeIterator`].
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::Ipv4Network;
    ///
    /// let net = Ipv4Network::parse("192.168.1.0/24").unwrap();
    /// let mut addrs = net.addrs();
    ///
    /// assert_eq!(256, addrs.len());
    ///
    /// assert_eq!(Some(Ipv4Addr::new(192, 168, 1, 0)), addrs.next());
    /// assert_eq!(Some(Ipv4Addr::new(192, 168, 1, 1)), addrs.next());
    /// assert_eq!(Some(Ipv4Addr::new(192, 168, 1, 2)), addrs.next());
    ///
    /// // It is important to note that both back and forth work on the same
    /// // range, and do not cross: iteration is over when they meet in the
    /// // middle.
    ///
    /// assert_eq!(Some(Ipv4Addr::new(192, 168, 1, 255)), addrs.next_back());
    /// assert_eq!(Some(Ipv4Addr::new(192, 168, 1, 254)), addrs.next_back());
    ///
    /// assert_eq!(Some(Ipv4Addr::new(192, 168, 1, 3)), addrs.next());
    /// ```
    #[inline]
    #[must_use]
    pub fn addrs(self) -> Ipv4NetworkAddrs {
        let (addr, mask) = self.to_bits();
        let host_bits = (!mask).count_ones();
        let back = u32::MAX.checked_shr(32 - host_bits).unwrap_or(0);

        Ipv4NetworkAddrs { base: addr, mask, front: 0, back }
    }
}

// Total order on the address and mask packed into a single `u64` key, in
// place of the derived lexicographic comparison of the two `Ipv4Addr` fields.
//
// Concatenating the big-endian `addr` and `mask` bit patterns into one `u64`
// (`addr` in the high 32 bits, `mask` in the low 32 bits) preserves their
// lexicographic order exactly, since comparing two fixed-width integers
// numerically already agrees with comparing their big-endian byte sequences,
// and that holds independently for each field of the concatenation.
impl Ord for Ipv4Network {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        let (self_addr, self_mask) = self.to_bits();
        let (other_addr, other_mask) = other.to_bits();
        let self_key = (self_addr as u64) << 32 | self_mask as u64;
        let other_key = (other_addr as u64) << 32 | other_mask as u64;

        self_key.cmp(&other_key)
    }
}

// Delegates to `Ord::cmp`, which defines `Ipv4Network`'s total order.
impl PartialOrd for Ipv4Network {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for Ipv4Network {
    /// Formats this IPv4 network using the given formatter.
    ///
    /// The idea is to format using **the most compact** representation, except
    /// for non-contiguous networks, which are formatted explicitly.
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), core::fmt::Error> {
        match self {
            Self(addr, mask) => {
                match self.prefix() {
                    Some(prefix) => fmt.write_fmt(format_args!("{}/{}", addr, prefix)),
                    None => {
                        // This is a non-contiguous network, expand the mask.
                        fmt.write_fmt(format_args!("{}/{}", addr, mask))
                    }
                }
            }
        }
    }
}

impl From<Ipv4Addr> for Ipv4Network {
    fn from(addr: Ipv4Addr) -> Self {
        Self(addr, IPV4_ALL_BITS)
    }
}

impl TryFrom<(Ipv4Addr, u8)> for Ipv4Network {
    type Error = CidrOverflowError;

    fn try_from((addr, cidr): (Ipv4Addr, u8)) -> Result<Self, Self::Error> {
        let mask = ipv4_mask_from_cidr(cidr)?;
        Ok(Self::new(addr, mask))
    }
}

impl FromStr for Ipv4Network {
    type Err = IpNetParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv4Network::parse(s)
    }
}

impl AsRef<Ipv4Network> for Ipv4Network {
    #[inline]
    fn as_ref(&self) -> &Ipv4Network {
        self
    }
}

/// Bidirectional iterator over [`Ipv4Addr`] in an [`Ipv4Network`].
///
/// Created by [`Ipv4Network::addrs`].
///
/// Yields addresses in host-index order: the *k* host positions (bits where the
/// mask is zero) are filled with successive values `0 ..= 2^k - 1`, starting
/// from the least-significant host bit.
///
/// When the iterator is exhausted it enters a sentinel state where
/// `front > back`, so every subsequent call to [`next`](Iterator::next) or
/// [`next_back`](DoubleEndedIterator::next_back) returns [`None`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4NetworkAddrs {
    base: u32,
    mask: u32,
    front: u32,
    back: u32,
}

impl Iterator for Ipv4NetworkAddrs {
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

        Some(Ipv4Addr::from_bits(ipv4_bits_from_host_index(
            self.base, self.mask, index,
        )))
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
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
            let n = rem as usize;
            (n, Some(n))
        }
    }
}

impl DoubleEndedIterator for Ipv4NetworkAddrs {
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

        Some(Ipv4Addr::from_bits(ipv4_bits_from_host_index(
            self.base, self.mask, index,
        )))
    }
}

impl ExactSizeIterator for Ipv4NetworkAddrs {
    #[inline]
    fn len(&self) -> usize {
        if self.front > self.back {
            return 0;
        }

        let rem = self.back.wrapping_sub(self.front).wrapping_add(1);

        if rem == 0 { 1usize << 32 } else { rem as usize }
    }
}

/// Lazy iterator over [`Ipv4Network`] parts of a set difference.
///
/// Created by [`Ipv4Network::difference`].
///
/// Yields between 0 and 32 pairwise-disjoint networks whose union equals
/// `S(A) \ S(B)`.
///
/// Each call to [`next`](Iterator::next) computes one network by peeling the
/// lowest remaining bit from the difference mask.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4NetworkDiff {
    /// Intersection address, or an encoded address for the disjoint shortcut.
    addr: u32,
    /// Mask of the source network (possibly with one bit cleared for disjoint).
    mask: u32,
    /// Bits of `d` already yielded.
    processed: u32,
    /// Bits of `d` not yet yielded.
    remaining: u32,
}

impl Ipv4NetworkDiff {
    /// Computes the set difference `source \ other`.
    ///
    /// The iterator yields pairwise-disjoint networks whose union equals
    /// `S(source) \ S(other)`.
    #[inline]
    #[must_use]
    pub const fn new(source: &Ipv4Network, other: &Ipv4Network) -> Self {
        let (addr, mask) = source.to_bits();

        match source.intersection(other) {
            None => {
                // Disjoint: A \ B = {A}.
                //
                // Encode as a single-step peel: borrow one bit `b` from the
                // source mask and set up state so that peeling it reconstructs
                // the original network.
                //
                // Disjoint implies mask != 0 (the 0.0.0.0/0 intersects
                // everything), so there is always a bit to borrow.
                let b = mask & mask.wrapping_neg();

                Self {
                    addr: addr ^ b,
                    mask: mask ^ b,
                    processed: 0,
                    remaining: b,
                }
            }
            Some(intersected) => {
                let (intersected_addr, intersected_mask) = intersected.to_bits();

                // Extra bits: fixed in the intersection but free in A.
                let d = intersected_mask & !mask;

                if d == 0 {
                    // A ⊆ B: A \ B = ∅.
                    Self {
                        addr: 0,
                        mask: 0,
                        processed: 0,
                        remaining: 0,
                    }
                } else {
                    // General case: peel one network per bit of d.
                    Self {
                        addr: intersected_addr,
                        mask,
                        processed: 0,
                        remaining: d,
                    }
                }
            }
        }
    }
}

impl Iterator for Ipv4NetworkDiff {
    type Item = Ipv4Network;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        let b = 0x8000_0000u32 >> self.remaining.leading_zeros();
        let mask = self.mask | self.processed | b;
        let addr = (self.addr ^ b) & mask;
        self.processed |= b;
        self.remaining ^= b;

        Some(Ipv4Network::from_bits(addr, mask))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.len();
        (n, Some(n))
    }
}

impl ExactSizeIterator for Ipv4NetworkDiff {
    #[inline]
    fn len(&self) -> usize {
        self.remaining.count_ones() as usize
    }
}

#[inline]
const fn ipv4_bits_from_host_index(base: u32, mask: u32, index: u32) -> u32 {
    let host_mask = !mask;

    // For contiguous masks (trailing ones only) pdep is identity.
    if host_mask & host_mask.wrapping_add(1) == 0 {
        base | index
    } else {
        base | pdep_u32(index, host_mask)
    }
}

#[inline]
const fn pdep_u32(mut src: u32, mut mask: u32) -> u32 {
    let mut out = 0u32;

    while mask != 0 {
        let t = mask & mask.wrapping_neg();

        if src & 1 != 0 {
            out |= t;
        }

        src >>= 1;
        mask ^= t;
    }

    out
}

/// An iterator over the minimum set of contiguous IPv4 networks (CIDR blocks)
/// whose union equals the closed address interval `[first, last]`.
///
/// Use [`ipv4_range_to_networks`] to construct one.
///
/// The iterator is lazy and allocation-free. For each step it picks the largest
/// CIDR block that (a) is aligned at the current `first` and (b) does not
/// exceed `last`. This yields the **minimum cardinality** covering — no other
/// CIDR decomposition of the same range uses fewer blocks. The upper bound on
/// the total number of blocks is `2 * 32 - 2 = 62`.
///
/// If `first > last` the iterator is empty.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct Ipv4RangeNetworks {
    first: u32,
    last: u32,
    done: bool,
}

/// Returns an iterator over the minimum set of contiguous IPv4 networks
/// covering the closed address interval `[first, last]`.
///
/// See [`Ipv4RangeNetworks`] for details. If `first > last` the iterator is
/// empty.
///
/// # Examples
///
/// ```
/// use core::net::Ipv4Addr;
///
/// use netip::{Contiguous, Ipv4Network, ipv4_range_to_networks};
///
/// let nets: Vec<_> =
///     ipv4_range_to_networks(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255)).collect();
/// assert_eq!(nets.len(), 1);
/// assert_eq!(
///     Contiguous::<Ipv4Network>::parse("10.0.0.0/24").unwrap(),
///     nets[0]
/// );
/// ```
#[inline]
pub const fn ipv4_range_to_networks(first: Ipv4Addr, last: Ipv4Addr) -> Ipv4RangeNetworks {
    let first = first.to_bits();
    let last = last.to_bits();

    Ipv4RangeNetworks { first, last, done: first > last }
}

impl Iterator for Ipv4RangeNetworks {
    type Item = Contiguous<Ipv4Network>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let first = self.first;
        let last = self.last;

        // `size` is the interval length modulo 2^32. The only input that wraps
        // to zero is the full range (first=0, last=MAX), and we encode that
        // case as `size_log = 32`.
        let size = last.wrapping_sub(first).wrapping_add(1);
        let size_log: u32 = if size == 0 { 32 } else { 31 - size.leading_zeros() };
        let align: u32 = if first == 0 { 32 } else { first.trailing_zeros() };
        let n = if size_log < align { size_log } else { align };

        let block_max: u32 = if n == 32 { u32::MAX } else { (1u32 << n) - 1 };
        let end = first.wrapping_add(block_max);
        let mask = !block_max;
        let net = Contiguous(Ipv4Network::from_bits(first, mask));

        if end == last {
            self.done = true;
        } else {
            self.first = end + 1;
        }

        Some(net)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done { (0, Some(0)) } else { (1, Some(2 * 32 - 2)) }
    }
}

impl core::iter::FusedIterator for Ipv4RangeNetworks {}

/// Represents the network range in which IP addresses are IPv6.
///
/// IPv6 networks are defined as pair of two [`Ipv6Addr`]. One for IP address
/// and the second one - for mask.
///
/// See [`IpNetwork`] for a type encompassing both IPv4 and IPv6 networks.
///
/// # Note
///
/// An IPv6 network represents a range of IPv6 addresses. The most common way to
/// represent an IP network is through CIDR notation. See [IETF RFC 4632] for
/// CIDR notation.
///
/// An example of such notation is `2a02:6b8:c00::/40`.
///
/// In CIDR notation, a prefix is shown as a 8-hextet quantity, just like a
/// traditional IPv6 address or network number, followed by the "/" (slash)
/// character, followed by a decimal value between 0 and 128 that describes the
/// number of significant bits.
///
/// Here, the "/40" indicates that the mask to extract the network portion of
/// the prefix is a 128-bit value where the most significant 40 bits are
/// ones and the least significant 88 bits are zeros.
///
/// The other way to represent the network above is to use explicit notation,
/// such as `2a02:6b8:c00::/ffff:ffff:ff00::`.
///
/// However, this struct supports non-contiguous masks, i.e. masks with
/// non-contiguous bits set to one, like the following one:
/// `2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0`.
///
/// [IETF RFC 4632]: https://tools.ietf.org/html/rfc4632
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv6Network(Ipv6Addr, Ipv6Addr);

impl Ipv6Network {
    /// An IPv6 network representing the unspecified network: `::/0`
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::Ipv6Network;
    ///
    /// let net = Ipv6Network::UNSPECIFIED;
    /// assert_eq!(
    ///     Ipv6Network::new(
    ///         Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
    ///         Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)
    ///     ),
    ///     net
    /// );
    /// ```
    pub const UNSPECIFIED: Self = Self(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);

    /// Initializes a new [`Ipv6Network`] using specified address and mask.
    ///
    /// During construction, the address is normalized using mask.
    #[inline]
    #[must_use]
    pub const fn new(addr: Ipv6Addr, mask: Ipv6Addr) -> Self {
        let addr = addr.to_bits() & mask.to_bits();

        Self(Ipv6Addr::from_bits(addr), mask)
    }

    /// Parses the specified buffer into an IPv6 network.
    ///
    /// The following formats are supported:
    ///
    /// | Format                   | Example                           |
    /// |--------------------------|-----------------------------------|
    /// | IPv6                     | `2a02:6b8::2:242`                 |
    /// | IPv6/CIDR                | `2a02:6b8:c00::/40`               |
    /// | IPv6/IPv6                | `2a02:6b8:c00::/ffff:ffff:ff00::` |
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::Ipv6Network;
    ///
    /// // Here are some examples to show supported formats and the output of this function.
    ///
    /// // Parse IPv6 addresses without explicit `/128` mask.
    /// assert_eq!(
    ///     Ipv6Network::new(
    ///         Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0x2, 0x242),
    ///         Ipv6Addr::new(
    ///             0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
    ///         ),
    ///     ),
    ///     // IPv6 address.
    ///     Ipv6Network::parse("2a02:6b8::2:242").unwrap(),
    /// );
    ///
    /// // CIDR format.
    /// assert_eq!(
    ///     Ipv6Network::new(
    ///         Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0, 0, 0),
    ///         Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0, 0, 0, 0),
    ///     ),
    ///     // IPv6 CIDR network.
    ///     Ipv6Network::parse("2a02:6b8:c00::/40").unwrap(),
    /// );
    ///
    /// // Network with explicit mask (contiguous in this case).
    /// assert_eq!(
    ///     Ipv6Network::new(
    ///         Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0, 0, 0),
    ///         Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0, 0, 0, 0),
    ///     ),
    ///     // IPv6 network with explicit mask.
    ///     Ipv6Network::parse("2a02:6b8:c00::/ffff:ffff:ff00::").unwrap(),
    /// );
    ///
    /// // Network with explicit non-contiguous mask.
    /// assert_eq!(
    ///     Ipv6Network::new(
    ///         Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 0),
    ///         Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0xffff, 0xffff, 0, 0),
    ///     ),
    ///     // The same network as above, but specified explicitly.
    ///     Ipv6Network::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap(),
    /// );
    /// ```
    pub fn parse(buf: &str) -> Result<Self, IpNetParseError> {
        let mut parts = buf.splitn(2, '/');
        let addr = parts.next().ok_or(IpNetParseError::ExpectedIpNetwork)?;
        let addr: Ipv6Addr = addr.parse()?;
        match parts.next() {
            Some(mask) => match mask.parse::<u8>() {
                Ok(mask) => Ok(Self::try_from((addr, mask))?),
                Err(..) => {
                    // Maybe explicit mask.
                    let mask: Ipv6Addr = mask.parse()?;
                    Ok(Self::new(addr, mask))
                }
            },
            None => Ok(Self(addr, IPV6_ALL_BITS)),
        }
    }

    /// Returns the IP address of this IPv6 network.
    #[inline]
    #[must_use]
    pub const fn addr(&self) -> &Ipv6Addr {
        match self {
            Ipv6Network(addr, ..) => addr,
        }
    }

    /// Returns the IP mask of this IPv6 network.
    #[inline]
    #[must_use]
    pub const fn mask(&self) -> &Ipv6Addr {
        match self {
            Ipv6Network(.., mask) => mask,
        }
    }

    /// Converts a pair of IPv6 address and mask represented as a pair of host
    /// byte order `u128` into an IPv6 network.
    ///
    /// # Note
    ///
    /// During conversion, the address is normalized using mask.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::Ipv6Network;
    ///
    /// let addr = 0x2a0206b8b0817228000000000001000b_u128;
    /// let mask = 0xffffffffffffffffffffffffffffffff_u128;
    ///
    /// let expected = Ipv6Network::new(
    ///     Ipv6Addr::new(
    ///         0x2a02, 0x06b8, 0xb081, 0x7228, 0x0000, 0x0000, 0x0001, 0x000b,
    ///     ),
    ///     Ipv6Addr::new(
    ///         0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    ///     ),
    /// );
    ///
    /// assert_eq!(expected, Ipv6Network::from_bits(addr, mask));
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_bits(addr: u128, mask: u128) -> Self {
        Self::new(Ipv6Addr::from_bits(addr), Ipv6Addr::from_bits(mask))
    }

    /// Converts this IPv6 network's address and mask into pair of host byte
    /// order `u128`.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::Ipv6Network;
    ///
    /// let net = Ipv6Network::new(
    ///     Ipv6Addr::new(
    ///         0x2a02, 0x06b8, 0xb081, 0x7228, 0x0000, 0x0000, 0x0001, 0x000b,
    ///     ),
    ///     Ipv6Addr::new(
    ///         0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    ///     ),
    /// );
    /// assert_eq!(
    ///     (
    ///         0x2a0206b8b0817228000000000001000b_u128,
    ///         0xffffffffffffffffffffffffffffffff_u128,
    ///     ),
    ///     net.to_bits(),
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn to_bits(&self) -> (u128, u128) {
        match self {
            Self(addr, mask) => (addr.to_bits(), mask.to_bits()),
        }
    }

    /// Returns `true` if this IPv6 network fully contains the specified one.
    #[inline]
    #[must_use]
    pub const fn contains(&self, other: &Ipv6Network) -> bool {
        let (a1, m1) = self.to_bits();
        let (a2, m2) = other.to_bits();

        (a2 & m1 == a1) && (m2 & m1 == m1)
    }

    /// Returns `true` if this IPv6 network and the specified one share at
    /// least one common address.
    ///
    /// Works correctly with non-contiguous masks.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::Ipv6Network;
    ///
    /// // Overlapping contiguous networks.
    /// let a = Ipv6Network::parse("2001:db8::/32").unwrap();
    /// let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
    /// assert!(a.intersects(&b));
    ///
    /// // Disjoint contiguous networks.
    /// let c = Ipv6Network::parse("fe80::/10").unwrap();
    /// assert!(!a.intersects(&c));
    ///
    /// // Non-contiguous masks.
    /// let x = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1),
    ///     Ipv6Addr::new(0xffff, 0, 0, 0, 0, 0, 0, 0xffff),
    /// );
    /// let y = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 0),
    ///     Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0),
    /// );
    /// assert!(x.intersects(&y));
    /// ```
    #[inline]
    #[must_use]
    pub const fn intersects(&self, other: &Self) -> bool {
        // NOTE: compiler is smart enough to optimize this without constructing
        // the actual intersection.
        self.intersection(other).is_some()
    }

    /// Returns `true` if this IPv6 network and the specified one share no
    /// common addresses.
    ///
    /// This is the logical complement of [`intersects`](Self::intersects).
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::Ipv6Network;
    ///
    /// let a = Ipv6Network::parse("2001:db8::/32").unwrap();
    /// let b = Ipv6Network::parse("fe80::/10").unwrap();
    /// assert!(a.is_disjoint(&b));
    ///
    /// let c = Ipv6Network::parse("2001:db8:1::/48").unwrap();
    /// assert!(!a.is_disjoint(&c));
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_disjoint(&self, other: &Ipv6Network) -> bool {
        !self.intersects(other)
    }

    /// Returns the intersection of this IPv6 network with the specified one,
    /// or [`None`] if they are disjoint.
    ///
    /// The intersection of two networks is itself always a single network
    /// (never a collection), because it constrains strictly more bit
    /// positions.
    ///
    /// Works correctly with non-contiguous masks.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::Ipv6Network;
    ///
    /// // Containment: intersection equals the smaller network.
    /// let a = Ipv6Network::parse("2001:db8::/32").unwrap();
    /// let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
    /// assert_eq!(Some(b), a.intersection(&b));
    ///
    /// // Non-contiguous masks.
    /// let a = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1),
    ///     Ipv6Addr::new(0xffff, 0, 0, 0, 0, 0, 0, 0xffff),
    /// );
    /// let b = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 0),
    ///     Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0),
    /// );
    /// let expected = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 1),
    ///     Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0xffff),
    /// );
    /// assert_eq!(Some(expected), a.intersection(&b));
    ///
    /// // Disjoint networks.
    /// let a = Ipv6Network::parse("2001:db8::/32").unwrap();
    /// let b = Ipv6Network::parse("fe80::/10").unwrap();
    /// assert_eq!(None, a.intersection(&b));
    /// ```
    #[inline]
    #[must_use]
    pub const fn intersection(&self, other: &Self) -> Option<Self> {
        let (a1, m1) = self.to_bits();
        let (a2, m2) = other.to_bits();

        if (a1 & m2) != (a2 & m1) {
            return None;
        }

        let addr = a1 | a2;
        let mask = m1 | m2;

        let addr = Ipv6Addr::from_bits(addr);
        let mask = Ipv6Addr::from_bits(mask);

        // NOTE: address is already normalized.
        Some(Self(addr, mask))
    }

    /// Returns an iterator over networks whose union equals the set difference
    /// `self \ other`, i.e. all addresses in `self` that are not in `other`.
    ///
    /// The result contains at most `popcount(m2 & !m1)` pairwise-disjoint
    /// networks (at most 128). Works correctly with non-contiguous masks.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::Ipv6Network;
    ///
    /// // Subtracting a /64 from a /48 yields 16 networks.
    /// let a = Ipv6Network::parse("2001:db8::/48").unwrap();
    /// let b = Ipv6Network::parse("2001:db8::/64").unwrap();
    /// let diff: Vec<_> = a.difference(&b).collect();
    /// assert_eq!(diff.len(), 16);
    ///
    /// // Disjoint networks: difference is the original.
    /// let a = Ipv6Network::parse("2001:db8::/32").unwrap();
    /// let b = Ipv6Network::parse("fe80::/10").unwrap();
    /// let diff: Vec<_> = a.difference(&b).collect();
    /// assert_eq!(diff, vec![a]);
    ///
    /// // Subset: difference is empty.
    /// let a = Ipv6Network::parse("2001:db8::/64").unwrap();
    /// let b = Ipv6Network::parse("2001:db8::/48").unwrap();
    /// assert_eq!(a.difference(&b).count(), 0);
    /// ```
    #[inline]
    #[must_use]
    pub const fn difference(&self, other: &Self) -> Ipv6NetworkDiff {
        Ipv6NetworkDiff::new(self, other)
    }

    /// Checks whether this network is a contiguous, i.e. contains mask with
    /// only leading bits set to one contiguously.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::Ipv6Network;
    ///
    /// assert!(Ipv6Network::parse("::/0").unwrap().is_contiguous());
    /// assert!(
    ///     Ipv6Network::parse("2a02:6b8:c00::/40")
    ///         .unwrap()
    ///         .is_contiguous()
    /// );
    ///
    /// assert!(
    ///     !Ipv6Network::parse("2a02:6b8:c00::f800:0:0/ffff:ffff:0:0:ffff:ffff::")
    ///         .unwrap()
    ///         .is_contiguous()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_contiguous(&self) -> bool {
        let mask = self.mask().to_bits();
        mask | mask.wrapping_sub(1) == u128::MAX
    }

    /// Checks whether this network is an IPv4-mapped IPv6 network.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Ipv4Network, Ipv6Network};
    ///
    /// assert!(
    ///     Ipv4Network::parse("8.8.8.0/24")
    ///         .unwrap()
    ///         .to_ipv6_mapped()
    ///         .is_ipv4_mapped_ipv6()
    /// );
    ///
    /// assert!(
    ///     !Ipv6Network::parse("2a02:6b8::/40")
    ///         .unwrap()
    ///         .is_ipv4_mapped_ipv6()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_ipv4_mapped_ipv6(&self) -> bool {
        let (addr, mask) = self.to_bits();

        // Suppress clippy a bit, because with return we have a nice aligning.
        #[allow(clippy::needless_return)]
        return addr & 0xffffffffffffffffffffffff00000000 == 0x00000000000000000000ffff00000000
            && mask & 0xffffffffffffffffffffffff00000000 == 0xffffffffffffffffffffffff00000000;
    }

    /// Converts this network to a contiguous network by clearing mask bits set
    /// to one after the first zero bit.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::Ipv6Network;
    ///
    /// let net = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0xf800, 0, 0),
    ///     Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0, 0xffff, 0xffff, 0, 0),
    /// );
    /// let expected = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0, 0, 0),
    ///     Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0, 0, 0, 0, 0),
    /// );
    ///
    /// assert_eq!(expected, net.to_contiguous());
    /// ```
    #[must_use]
    pub fn to_contiguous(&self) -> Self {
        let (addr, mask) = self.to_bits();

        Self::try_from((addr.into(), mask.leading_ones() as u8)).expect("CIDR must be in range [0; 128]")
    }

    /// Converts this network to an [`IPv4` network] if it's an IPv4-mapped
    /// network, as defined in [IETF RFC 4291 section 2.5.5.2], otherwise
    /// returns [`None`].
    ///
    /// `::ffff:a.b.c.d/N` becomes `a.b.c.d/M`, where `M = N - 96`.
    /// All networks with their addresses *not* starting with `::ffff` will
    /// return `None`.
    ///
    /// [`IPv4` network]: Ipv4Network
    /// [IETF RFC 4291 section 2.5.5.2]: https://tools.ietf.org/html/rfc4291#section-2.5.5.2
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::{Ipv4Addr, Ipv6Addr};
    ///
    /// use netip::{Ipv4Network, Ipv6Network};
    ///
    /// let net = Ipv6Network::new(
    ///     Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
    ///     Ipv6Addr::new(
    ///         0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xff00,
    ///     ),
    /// );
    /// let expected = Ipv4Network::new(
    ///     Ipv4Addr::new(192, 10, 2, 0),
    ///     Ipv4Addr::new(255, 255, 255, 0),
    /// );
    /// assert_eq!(Some(expected), net.to_ipv4_mapped());
    ///
    /// // This networks is IPv4-compatible, but not the IPv4-mapped one.
    /// let net = Ipv6Network::new(
    ///     Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xc00a, 0x2ff),
    ///     Ipv6Addr::new(
    ///         0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xff00,
    ///     ),
    /// );
    /// assert_eq!(None, net.to_ipv4_mapped());
    /// ```
    #[inline]
    #[must_use]
    pub const fn to_ipv4_mapped(&self) -> Option<Ipv4Network> {
        if self.is_ipv4_mapped_ipv6() {
            let (addr, mask) = self.to_bits();
            let addr: u32 = (addr & 0xffffffff) as u32;
            let mask: u32 = (mask & 0xffffffff) as u32;

            Some(Ipv4Network::from_bits(addr, mask))
        } else {
            None
        }
    }

    /// Returns the mask prefix, i.e. the number of leading bits set, if this
    /// network is a contiguous one, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::{Ipv4Network, Ipv6Network};
    ///
    /// assert_eq!(
    ///     Some(40),
    ///     Ipv6Network::parse("2a02:6b8::/40").unwrap().prefix()
    /// );
    /// assert_eq!(
    ///     Some(128),
    ///     Ipv6Network::parse("2a02:6b8::1").unwrap().prefix()
    /// );
    ///
    /// // The IPv4-mapped IPv6 equivalent is `::ffff:8.8.8.0/120`.
    /// assert_eq!(
    ///     Some(120),
    ///     Ipv4Network::parse("8.8.8.0/24")
    ///         .unwrap()
    ///         .to_ipv6_mapped()
    ///         .prefix()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn prefix(&self) -> Option<u8> {
        let mask = self.mask().to_bits();
        let ones = mask.leading_ones();

        if mask.count_ones() == ones {
            Some(ones as u8)
        } else {
            None
        }
    }

    /// Calculates and returns the `Ipv6Network`, which will be a supernet, i.e.
    /// the shortest common network both for this network and the specified
    /// ones.
    ///
    /// # Note
    ///
    /// This function works fine for both contiguous and non-contiguous
    /// networks.
    ///
    /// The result may have a non-contiguous mask even when all inputs are
    /// contiguous (CIDR). This happens when the addresses differ in bits
    /// that are not at the boundary of their masks.
    ///
    /// Use [`Ipv6Network::to_contiguous`] method if you need to convert the
    /// output network.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::Ipv6Network;
    ///
    /// // 2013:db8:1::/48
    /// let net0 = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2013, 0xdb8, 0x1, 0, 0, 0, 0, 0),
    ///     Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0, 0, 0, 0, 0),
    /// );
    ///
    /// // 2013:db8:2::/48
    /// let net1 = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2013, 0xdb8, 0x2, 0, 0, 0, 0, 0),
    ///     Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0, 0, 0, 0, 0),
    /// );
    ///
    /// // 2013:db8::/46
    /// let expected = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2013, 0xdb8, 0, 0, 0, 0, 0, 0),
    ///     Ipv6Addr::new(0xffff, 0xffff, 0xfffc, 0, 0, 0, 0, 0),
    /// );
    /// assert_eq!(expected, net0.supernet_for(&[net1]));
    ///
    /// // Contiguous inputs, non-contiguous result: addresses differ in
    /// // bit 88, which is not at the mask boundary of /48.
    /// let a = Ipv6Network::parse("2001:db8::/48").unwrap();
    /// let b = Ipv6Network::parse("2001:db8:100::/48").unwrap();
    /// assert_eq!(
    ///     Ipv6Network::parse("2001:db8::/ffff:ffff:feff::").unwrap(),
    ///     a.supernet_for(&[b])
    /// );
    /// ```
    #[must_use]
    pub fn supernet_for(&self, nets: &[Ipv6Network]) -> Ipv6Network {
        let (addr, mut mask) = self.to_bits();

        for net in nets {
            let (a, m) = net.to_bits();
            mask &= m & !(addr ^ a);
        }

        Self::new(addr.into(), mask.into())
    }

    /// Returns `true` if this network is adjacent to `other`.
    ///
    /// Two networks are adjacent when they share the same mask and their
    /// addresses differ by exactly one masked bit, meaning they can be
    /// [`merge`](Self::merge)d into a single network by dropping that bit
    /// from the mask.
    ///
    /// Identical networks are **not** adjacent. Works correctly with
    /// non-contiguous masks.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::Ipv6Network;
    ///
    /// // Adjacent contiguous /48 blocks.
    /// let a = Ipv6Network::parse("2001:db8::/48").unwrap();
    /// let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
    /// assert!(a.is_adjacent(&b));
    ///
    /// // Non-adjacent: addresses differ by more than one bit.
    /// let c = Ipv6Network::parse("2001:db8:5::/48").unwrap();
    /// assert!(!a.is_adjacent(&c));
    ///
    /// // Identical networks are not adjacent.
    /// assert!(!a.is_adjacent(&a));
    ///
    /// // Adjacent non-contiguous networks.
    /// let x = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1),
    ///     Ipv6Addr::new(0xffff, 0xff00, 0, 0, 0, 0, 0, 0xffff),
    /// );
    /// let y = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2001, 0x0100, 0, 0, 0, 0, 0, 1),
    ///     Ipv6Addr::new(0xffff, 0xff00, 0, 0, 0, 0, 0, 0xffff),
    /// );
    /// assert!(x.is_adjacent(&y));
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_adjacent(&self, other: &Self) -> bool {
        let (a1, m1) = self.to_bits();
        let (a2, m2) = other.to_bits();
        ipv6_adjacent_bit(a1, m1, a2, m2).is_some()
    }

    /// Merges this IPv6 network with another, returning `Some(N)` iff their
    /// union is exactly representable as a single network.
    ///
    /// Two networks can be merged in two ways:
    ///
    /// - **Equal masks, adjacent blocks**: the masks are identical and the
    ///   addresses differ by exactly one bit. The result drops that bit from
    ///   the mask.
    /// - **Containment**: one network is a subset of the other. The result is
    ///   the larger (containing) network.
    ///
    /// Works correctly with non-contiguous masks.
    ///
    /// # Note
    ///
    /// The result may have a non-contiguous mask even when both inputs are
    /// contiguous (CIDR). This happens when addresses differ in a bit that
    /// is not at the boundary of the mask.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::Ipv6Network;
    ///
    /// // Adjacent /48 blocks merge into a /47.
    /// let a = Ipv6Network::parse("2001:db8::/48").unwrap();
    /// let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
    /// assert_eq!(
    ///     Some(Ipv6Network::parse("2001:db8::/47").unwrap()),
    ///     a.merge(&b)
    /// );
    ///
    /// // Containment: larger network is returned.
    /// let a = Ipv6Network::parse("2001:db8::/32").unwrap();
    /// let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
    /// assert_eq!(Some(a), a.merge(&b));
    ///
    /// // Non-mergeable networks (addresses differ by more than one bit).
    /// let a = Ipv6Network::parse("2001:db8::/48").unwrap();
    /// let b = Ipv6Network::parse("2001:db8:5::/48").unwrap();
    /// assert_eq!(None, a.merge(&b));
    ///
    /// // Adjacent non-contiguous networks.
    /// let a = Ipv6Network::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
    /// let b = Ipv6Network::parse("2a02:6b8:c00::1235:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
    /// assert_eq!(
    ///     Some(Ipv6Network::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00:0:ffff:fffe::").unwrap()),
    ///     a.merge(&b)
    /// );
    ///
    /// // Adjacent non-contiguous networks, but not in the last address bit.
    /// let a = Ipv6Network::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
    /// let b = Ipv6Network::parse("2a02:6b8:c00::1236:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
    /// assert_eq!(
    ///     Some(Ipv6Network::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00:0:ffff:fffd::").unwrap()),
    ///     a.merge(&b)
    /// );
    ///
    /// // Contiguous inputs, non-contiguous result: addresses differ in
    /// // bit 88, which is not at the mask boundary of /48.
    /// let a = Ipv6Network::parse("2001:db8::/48").unwrap();
    /// let b = Ipv6Network::parse("2001:db8:100::/48").unwrap();
    /// assert_eq!(
    ///     Some(Ipv6Network::parse("2001:db8::/ffff:ffff:feff::").unwrap()),
    ///     a.merge(&b)
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn merge(&self, other: &Self) -> Option<Self> {
        let (a1, m1) = self.to_bits();
        let (a2, m2) = other.to_bits();

        if m1 == m2 {
            if a1 == a2 {
                return Some(*self);
            }
            if let Some(d) = ipv6_adjacent_bit(a1, m1, a2, m2) {
                let m = m1 ^ d;
                let a = a1 & m;
                return Some(Self(Ipv6Addr::from_bits(a), Ipv6Addr::from_bits(m)));
            }
            return None;
        }

        if self.contains(other) {
            return Some(*self);
        }
        if other.contains(self) {
            return Some(*other);
        }
        None
    }

    /// Returns the last address in this IPv6 network.
    ///
    /// For contiguous networks, this is the broadcast address.
    ///
    /// For non-contiguous networks, this is the highest address within the
    /// network range defined by the mask.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::Ipv6Network;
    ///
    /// // Contiguous network.
    /// let net = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0),
    ///     Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0, 0),
    /// );
    /// assert_eq!(
    ///     Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0xffff, 0xffff),
    ///     net.last_addr()
    /// );
    ///
    /// // Single address network.
    /// let net = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1),
    ///     Ipv6Addr::new(
    ///         0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    ///     ),
    /// );
    /// assert_eq!(
    ///     Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1),
    ///     net.last_addr()
    /// );
    ///
    /// // Non-contiguous network.
    /// let net = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 0),
    ///     Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0xffff, 0xffff, 0, 0),
    /// );
    /// assert_eq!(
    ///     Ipv6Addr::new(0x2a02, 0x6b8, 0x0cff, 0xffff, 0, 0x1234, 0xffff, 0xffff),
    ///     net.last_addr()
    /// );
    /// ```
    ///
    /// # Formal Proof of Correctness
    ///
    /// The algorithm follows the same logic as [`Ipv4Network::last_addr`].
    /// See [`Ipv4Network::last_addr`] for the formal proof.
    #[inline]
    #[must_use]
    pub const fn last_addr(&self) -> Ipv6Addr {
        let (addr, mask) = self.to_bits();
        Ipv6Addr::from_bits(addr | !mask)
    }

    /// Returns a bidirectional iterator over all addresses in this network.
    ///
    /// The iterator yields addresses in **host-index order**: the *k* host
    /// positions (bits where the mask is zero) are filled with successive
    /// values `0 ..= 2^k - 1`, starting from the least-significant host bit.
    ///
    /// For a standard (contiguous) CIDR mask this is equivalent to ascending
    /// numeric order from [`addr()`](Ipv6Network::addr) to
    /// [`last_addr()`](Ipv6Network::last_addr).
    ///
    /// For a non-contiguous mask the numeric order of the produced addresses
    /// may differ from the iteration order.
    ///
    /// The iterator implements [`DoubleEndedIterator`].
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::Ipv6Network;
    ///
    /// let net = Ipv6Network::parse("2a02:6b8:c00::1234:0:0/120").unwrap();
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
    ///
    /// // Both directions work on the same range and do not cross: iteration
    /// // is over when they meet in the middle.
    ///
    /// assert_eq!(
    ///     Some(Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 0xff)),
    ///     addrs.next_back()
    /// );
    ///
    /// assert_eq!(
    ///     Some(Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 2)),
    ///     addrs.next()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub fn addrs(self) -> Ipv6NetworkAddrs {
        let (addr, mask) = self.to_bits();
        let host_bits = (!mask).count_ones();
        let back = u128::MAX.checked_shr(128 - host_bits).unwrap_or(0);

        Ipv6NetworkAddrs { base: addr, mask, front: 0, back }
    }
}

/// Bidirectional iterator over [`Ipv6Addr`] in an [`Ipv6Network`].
///
/// Created by [`Ipv6Network::addrs`].
///
/// Yields addresses in host-index order: the *k* host positions (bits where the
/// mask is zero) are filled with successive values `0 ..= 2^k - 1`, starting
/// from the least-significant host bit.
///
/// When the iterator is exhausted it enters a sentinel state where
/// `front > back`, so every subsequent call to [`next`](Iterator::next) or
/// [`next_back`](DoubleEndedIterator::next_back) returns [`None`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6NetworkAddrs {
    base: u128,
    mask: u128,
    front: u128,
    back: u128,
}

impl Iterator for Ipv6NetworkAddrs {
    type Item = Ipv6Addr;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.front > self.back {
            return None;
        }

        let index = self.front;
        self.front = self.front.wrapping_add(1);

        // Wrap-around means front was u128::MAX — only possible for a /0
        // network.
        //
        // Enter sentinel state so the next call returns None.
        if self.front == 0 {
            self.front = 1;
            self.back = 0;
        }

        Some(Ipv6Addr::from_bits(ipv6_bits_from_host_index(
            self.base, self.mask, index,
        )))
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

impl DoubleEndedIterator for Ipv6NetworkAddrs {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front > self.back {
            return None;
        }

        let bits = ipv6_bits_from_host_index(self.base, self.mask, self.back);

        if self.front == self.back {
            self.front = 1;
            self.back = 0;
        } else {
            self.back = self.back.wrapping_sub(1);
        }

        Some(Ipv6Addr::from_bits(bits))
    }
}

#[inline]
const fn ipv6_bits_from_host_index(base: u128, mask: u128, index: u128) -> u128 {
    let host_mask = !mask;

    // For contiguous masks (trailing ones only) pdep is identity.
    if host_mask & host_mask.wrapping_add(1) == 0 {
        base | index
    } else {
        base | pdep_u128(index, host_mask)
    }
}

#[inline]
const fn pdep_u128(mut src: u128, mut mask: u128) -> u128 {
    let mut out = 0u128;

    while mask != 0 {
        let t = mask & mask.wrapping_neg();

        if src & 1 != 0 {
            out |= t;
        }

        src >>= 1;
        mask ^= t;
    }

    out
}

/// Yields between 0 and 128 pairwise-disjoint networks whose union equals
/// `S(A) \ S(B)`.
///
/// Each call to [`next`](Iterator::next) computes one network by peeling the
/// highest remaining bit from the difference mask.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6NetworkDiff {
    /// Intersection address, or an encoded address for the disjoint shortcut.
    addr: u128,
    /// Mask of the source network (possibly with one bit cleared for disjoint).
    mask: u128,
    /// Bits of `d` already yielded.
    processed: u128,
    /// Bits of `d` not yet yielded.
    remaining: u128,
}

impl Ipv6NetworkDiff {
    /// Computes the set difference `source \ other`.
    ///
    /// The iterator yields pairwise-disjoint networks whose union equals
    /// `S(source) \ S(other)`.
    #[inline]
    #[must_use]
    pub const fn new(source: &Ipv6Network, other: &Ipv6Network) -> Self {
        let (addr, mask) = source.to_bits();

        match source.intersection(other) {
            None => {
                // Disjoint: A \ B = {A}.
                //
                // Encode as a single-step peel: borrow one bit `b` from the
                // source mask and set up state so that peeling it reconstructs
                // the original network.
                //
                // Disjoint implies mask != 0 (the ::/0 intersects everything),
                // so there is always a bit to borrow.
                let b = mask & mask.wrapping_neg();

                Self {
                    addr: addr ^ b,
                    mask: mask ^ b,
                    processed: 0,
                    remaining: b,
                }
            }
            Some(intersected) => {
                let (inter_addr, inter_mask) = intersected.to_bits();

                // Extra bits: fixed in the intersection but free in A.
                let d = inter_mask & !mask;

                if d == 0 {
                    // A ⊆ B: A \ B = ∅.
                    Self {
                        addr: 0,
                        mask: 0,
                        processed: 0,
                        remaining: 0,
                    }
                } else {
                    // General case: peel one network per bit of d.
                    Self {
                        addr: inter_addr,
                        mask,
                        processed: 0,
                        remaining: d,
                    }
                }
            }
        }
    }
}

impl Iterator for Ipv6NetworkDiff {
    type Item = Ipv6Network;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        let b = 1u128 << (127 - self.remaining.leading_zeros());
        let mask = self.mask | self.processed | b;
        let addr = (self.addr ^ b) & mask;
        self.processed |= b;
        self.remaining ^= b;

        Some(Ipv6Network::from_bits(addr, mask))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.len();
        (n, Some(n))
    }
}

impl ExactSizeIterator for Ipv6NetworkDiff {
    #[inline]
    fn len(&self) -> usize {
        self.remaining.count_ones() as usize
    }
}

/// An iterator over the minimum set of contiguous IPv6 networks (CIDR blocks)
/// whose union equals the closed address interval `[first, last]`.
///
/// Use [`ipv6_range_to_networks`] to construct one.
///
/// The iterator is lazy and allocation-free. For each step it picks the largest
/// CIDR block that (a) is aligned at the current `first` and (b) does not
/// exceed `last`. This yields the **minimum cardinality** covering — no other
/// CIDR decomposition of the same range uses fewer blocks. The upper bound on
/// the total number of blocks is `2 * 128 - 2 = 254`.
///
/// If `first > last` the iterator is empty.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct Ipv6RangeNetworks {
    first: u128,
    last: u128,
    done: bool,
}

/// Returns an iterator over the minimum set of contiguous IPv6 networks
/// covering the closed address interval `[first, last]`.
///
/// See [`Ipv6RangeNetworks`] for details. If `first > last` the iterator is
/// empty.
///
/// # Examples
///
/// ```
/// use core::net::Ipv6Addr;
///
/// use netip::{Contiguous, Ipv6Network, ipv6_range_to_networks};
///
/// let first: Ipv6Addr = "2001:db8::".parse().unwrap();
/// let last: Ipv6Addr = "2001:db8::ffff:ffff:ffff:ffff".parse().unwrap();
/// let nets: Vec<_> = ipv6_range_to_networks(first, last).collect();
/// assert_eq!(nets.len(), 1);
/// assert_eq!(
///     Contiguous::<Ipv6Network>::parse("2001:db8::/64").unwrap(),
///     nets[0]
/// );
/// ```
#[inline]
pub const fn ipv6_range_to_networks(first: Ipv6Addr, last: Ipv6Addr) -> Ipv6RangeNetworks {
    let first = first.to_bits();
    let last = last.to_bits();

    Ipv6RangeNetworks { first, last, done: first > last }
}

impl Iterator for Ipv6RangeNetworks {
    type Item = Contiguous<Ipv6Network>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let first = self.first;
        let last = self.last;

        let size = last.wrapping_sub(first).wrapping_add(1);
        let size_log: u32 = if size == 0 { 128 } else { 127 - size.leading_zeros() };
        let align: u32 = if first == 0 { 128 } else { first.trailing_zeros() };
        let n = if size_log < align { size_log } else { align };

        let block_max: u128 = if n == 128 { u128::MAX } else { (1u128 << n) - 1 };
        let end = first.wrapping_add(block_max);
        let mask = !block_max;
        let net = Contiguous(Ipv6Network::from_bits(first, mask));

        if end == last {
            self.done = true;
        } else {
            self.first = end + 1;
        }

        Some(net)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done {
            (0, Some(0))
        } else {
            (1, Some(2 * 128 - 2))
        }
    }
}

impl core::iter::FusedIterator for Ipv6RangeNetworks {}

impl Display for Ipv6Network {
    /// Formats this IPv6 network using the given formatter.
    ///
    /// The idea is to format using **the most compact** representation, except
    /// for non-contiguous networks, which are formatted explicitly.
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), core::fmt::Error> {
        match self {
            Ipv6Network(addr, mask) => {
                match self.prefix() {
                    Some(prefix) => fmt.write_fmt(format_args!("{}/{}", addr, prefix)),
                    None => {
                        // This is a non-contiguous network, expand the mask.
                        fmt.write_fmt(format_args!("{}/{}", addr, mask))
                    }
                }
            }
        }
    }
}

impl From<Ipv4Network> for Ipv6Network {
    #[inline]
    fn from(net: Ipv4Network) -> Self {
        net.to_ipv6_mapped()
    }
}

impl From<Ipv6Addr> for Ipv6Network {
    fn from(addr: Ipv6Addr) -> Self {
        Ipv6Network(addr, IPV6_ALL_BITS)
    }
}

impl TryFrom<(Ipv6Addr, u8)> for Ipv6Network {
    type Error = CidrOverflowError;

    fn try_from((addr, cidr): (Ipv6Addr, u8)) -> Result<Self, Self::Error> {
        let mask = ipv6_mask_from_cidr(cidr)?;
        Ok(Ipv6Network::new(addr, mask))
    }
}

impl FromStr for Ipv6Network {
    type Err = IpNetParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv6Network::parse(s)
    }
}

impl AsRef<Ipv6Network> for Ipv6Network {
    #[inline]
    fn as_ref(&self) -> &Ipv6Network {
        self
    }
}

/// Finds the shortest common network for the given slice of networks that
/// covers at least half of slice.
///
/// Shortest means that it will have the shortest segment of subnets, or the
/// largest mask.
///
/// Imagine that you are building a radix tree or graph from networks and at
/// some point you need to split one of the nodes into two parts.
///
/// In other words, it is necessary to find the shortest network that contains
/// at least half of the child networks.
///
/// This function implements such an algorithm.
///
/// For example, suppose we have the following tree:
/// ```text
/// .
/// ├─ 127.0.0.1
/// ├─ 127.0.0.2
/// └─ 127.0.0.3
/// ```
///
/// After splitting:
///
/// ```text
/// .
/// ├─ 127.0.0.1
/// └─ 127.0.0.2/31
///   ├─ 127.0.0.2
///   └─ 127.0.0.3
/// ```
///
/// Another more interesting example:
///
/// ```text
/// .
/// ├─ 10.204.46.54/31
/// ├─ 10.204.46.68/31
/// ├─ 10.204.49.12/31
/// ├─ 10.204.49.14/31
/// ├─ 10.204.49.18/31
/// ├─ 10.204.49.32/31
/// ├─ 10.204.49.34/31
/// ├─ 10.204.49.36/31
/// ├─ 10.204.49.38/31
/// └─ 10.204.49.40/31
/// ```
///
/// After splitting:
///
/// ```text
/// .
/// ├─ 10.204.46.50/31
/// ├─ 10.204.46.54/31
/// ├─ 10.204.47.22/31
/// ├─ 10.204.49.0/26 [*]
/// │ ├─ 10.204.49.24/31
/// │ ├─ 10.204.49.26/31
/// │ ├─ 10.204.49.28/31
/// │ ├─ 10.204.49.32/31
/// │ ├─ 10.204.49.34/31
/// │ └─ 10.204.49.36/31
/// ├─ 10.204.50.38/31
/// └─ 10.204.50.40/31
/// ```
///
/// # Complexity
///
/// This function runs in `O(N)` and requires `O(1)` memory.
///
/// # Warning
///
/// The specified slice must be sorted, otherwise the result is unspecified and
/// meaningless.
///
/// Specified networks must not overlap.
///
/// # Examples
///
/// ```
/// use netip::{Ipv4Network, ipv4_binary_split};
///
/// let nets = &["127.0.0.1", "127.0.0.2", "127.0.0.3"];
/// let mut nets: Vec<_> = nets
///     .iter()
///     .map(|net| Ipv4Network::parse(net).unwrap())
///     .collect();
/// nets.sort();
/// nets.dedup();
///
/// let (supernet, range) = ipv4_binary_split(&nets).unwrap();
/// // 127.0.0.2/31 in binary is "0b...10/0b...10", which contains both "127.0.0.2" and "127.0.0.3".
/// assert_eq!(Ipv4Network::parse("127.0.0.2/31").unwrap(), supernet);
///
/// for (idx, net) in nets.iter().enumerate() {
///     assert_eq!(range.contains(&idx), supernet.contains(net));
/// }
///
/// // For the second example above.
///
/// let nets = &[
///     "10.204.46.50/31",
///     "10.204.46.54/31",
///     "10.204.47.22/31",
///     "10.204.49.24/31",
///     "10.204.49.26/31",
///     "10.204.49.28/31",
///     "10.204.49.32/31",
///     "10.204.49.34/31",
///     "10.204.49.36/31",
///     "10.204.50.38/31",
///     "10.204.50.40/31",
/// ];
/// let mut nets: Vec<_> = nets
///     .iter()
///     .map(|net| Ipv4Network::parse(net).unwrap())
///     .collect();
/// nets.sort();
/// nets.dedup();
///
/// let (supernet, range) = ipv4_binary_split(&nets).unwrap();
///
/// assert_eq!(Ipv4Network::parse("10.204.49.0/26").unwrap(), supernet);
///
/// for (idx, net) in nets.iter().enumerate() {
///     assert_eq!(range.contains(&idx), supernet.contains(net));
/// }
/// ```
#[must_use]
pub fn ipv4_binary_split<T>(nets: &[T]) -> Option<(Ipv4Network, Range<usize>)>
where
    T: AsRef<Ipv4Network>,
{
    ip_binary_split(nets)
}

/// Finds the shortest common network for the given slice of networks that
/// covers at least half of slice.
///
/// Shortest means that it will have the shortest segment of subnets, or the
/// largest mask.
///
/// Imagine that you are building a radix tree or graph from networks and at
/// some point you need to split one of the nodes into two parts.
///
/// In other words, it is necessary to find the shortest network that contains
/// at least half of the child networks.
///
/// This function implements such an algorithm.
///
/// For example, suppose we have the following tree:
/// ```text
/// .
/// ├─ ::1
/// ├─ ::2
/// └─ ::3
/// ```
///
/// After splitting:
///
/// ```text
/// .
/// ├─ ::1
/// └─ ::2/127
///   ├─ ::2
///   └─ ::3
/// ```
///
/// Another more interesting example:
///
/// ```text
/// .
/// ├─ 2a02:6b8:0:2302::/64
/// ├─ 2a02:6b8:0:2303::/64
/// ├─ 2a02:6b8:0:2305::/64
/// ├─ 2a02:6b8:0:2308::/64
/// ├─ 2a02:6b8:0:2309::/64
/// ├─ 2a02:6b8:0:230a::/64
/// ├─ 2a02:6b8:0:230b::/64
/// ├─ 2a02:6b8:0:230c::/64
/// ├─ 2a02:6b8:0:230d::/64
/// ├─ 2a02:6b8:0:2314::/64
/// └─ 2a02:6b8:0:231f::/64
/// ```
///
/// After splitting:
///
/// ```text
/// .
/// ├─ 2a02:6b8:0:2302::/64
/// ├─ 2a02:6b8:0:2303::/64
/// ├─ 2a02:6b8:0:2305::/64
/// └─ 2a02:6b8:0:2308::/61
/// │ ├─ 2a02:6b8:0:2308::/64
/// │ ├─ 2a02:6b8:0:2309::/64
/// │ ├─ 2a02:6b8:0:230a::/64
/// │ ├─ 2a02:6b8:0:230b::/64
/// │ ├─ 2a02:6b8:0:230c::/64
/// │ └─ 2a02:6b8:0:230d::/64
/// ├─ 2a02:6b8:0:2314::/64
/// └─ 2a02:6b8:0:231f::/64
/// ```
///
/// # Complexity
///
/// This function runs in `O(N)` and requires `O(1)` memory.
///
/// # Warning
///
/// The specified slice must be sorted, otherwise the result is unspecified and
/// meaningless.
///
/// Specified networks must not overlap.
///
/// # Examples
///
/// ```
/// use netip::{Ipv6Network, ipv6_binary_split};
///
/// let nets = &["::1", "::2", "::3"];
/// let mut nets: Vec<_> = nets
///     .iter()
///     .map(|net| Ipv6Network::parse(net).unwrap())
///     .collect();
///
/// // The input must be sorted.
/// nets.sort();
///
/// let (supernet, range) = ipv6_binary_split(&nets).unwrap();
/// // ::2/127 in binary is "0b...10/0b...10", which contains both "::2" and "::3".
/// assert_eq!(Ipv6Network::parse("::2/127").unwrap(), supernet);
///
/// for (idx, net) in nets.iter().enumerate() {
///     assert_eq!(range.contains(&idx), supernet.contains(net));
/// }
///
/// // For the second example above.
///
/// let nets = &[
///     "2a02:6b8:0:2302::/64",
///     "2a02:6b8:0:2303::/64",
///     "2a02:6b8:0:2305::/64",
///     "2a02:6b8:0:2308::/64",
///     "2a02:6b8:0:2309::/64",
///     "2a02:6b8:0:230a::/64",
///     "2a02:6b8:0:230b::/64",
///     "2a02:6b8:0:230c::/64",
///     "2a02:6b8:0:230d::/64",
///     "2a02:6b8:0:2314::/64",
///     "2a02:6b8:0:231f::/64",
/// ];
/// let mut nets: Vec<_> = nets
///     .iter()
///     .map(|net| Ipv6Network::parse(net).unwrap())
///     .collect();
/// nets.sort();
///
/// let (supernet, range) = ipv6_binary_split(&nets).unwrap();
/// assert_eq!(
///     Ipv6Network::parse("2a02:6b8:0:2308::/61").unwrap(),
///     supernet
/// );
///
/// for (idx, net) in nets.iter().enumerate() {
///     assert_eq!(range.contains(&idx), supernet.contains(net));
/// }
/// ```
#[must_use]
pub fn ipv6_binary_split<T>(nets: &[T]) -> Option<(Ipv6Network, Range<usize>)>
where
    T: AsRef<Ipv6Network>,
{
    ip_binary_split(nets)
}

// Dispatches to the faster of the two implementations below, based on input
// size.
//
// Both implementations return identical results, so the threshold only affects
// speed, never correctness. The crossover is per-family and measured — see
// `Word::SPLIT_THRESHOLD`.
#[inline]
fn ip_binary_split<T, U>(nets: &[T]) -> Option<(U, Range<usize>)>
where
    T: AsRef<U>,
    U: BinarySplit + Copy,
{
    if nets.len() < U::Bits::SPLIT_THRESHOLD {
        ip_binary_split_quadratic(nets)
    } else {
        ip_binary_split_linear(nets)
    }
}

// Finds the widest-mask window among all windows of size `window_size` by brute
// force.
//
// O(N^2) time, O(1) memory. Smaller constant factor than
// `ip_binary_split_linear`, so it wins on small inputs.
fn ip_binary_split_quadratic<T, U>(nets: &[T]) -> Option<(U, Range<usize>)>
where
    T: AsRef<U>,
    U: BinarySplit + Copy,
{
    if nets.len() < 3 {
        return None;
    }

    let window_size = nets.len().div_ceil(2);

    let window_supernet = |window: &[T]| -> U {
        let mut supernet = *window[0].as_ref();
        for elem in &window[1..] {
            supernet = supernet.supernet_for(&[*elem.as_ref()]);
        }
        supernet
    };

    let mut range = 0..nets.len();
    let mut candidate = window_supernet(nets);

    for (idx, window) in nets.windows(window_size).enumerate() {
        let supernet = window_supernet(window);

        if supernet.mask() > candidate.mask() {
            range = idx..(idx + window_size);
            candidate = supernet;
        }
    }

    while range.start > 0 && candidate.contains(nets[range.start - 1].as_ref()) {
        range.start -= 1;
    }
    while range.end < nets.len() && candidate.contains(nets[range.end].as_ref()) {
        range.end += 1;
    }

    Some((candidate, range))
}

// Finds the widest-mask window among all windows of size `window_size` in one
// linear pass.
//
// A window's supernet mask is the complement of the sliding OR of kill words
// `!mask_j | (addr_j ^ addr_{j+1})` over its element pairs, AND-ed with the
// last element's own mask. Per-bit counters keep that OR exact as kill words
// are added and removed while the window slides. O(N) time, O(1) memory.
fn ip_binary_split_linear<T, U>(nets: &[T]) -> Option<(U, Range<usize>)>
where
    T: AsRef<U>,
    U: BinarySplit + Copy,
{
    let n = nets.len();
    if n < 3 {
        return None;
    }

    let window_size = n.div_ceil(2);

    let bits = |j: usize| nets[j].as_ref().to_bits();
    let kill_word = |j: usize| -> U::Bits {
        let (addr_j, mask_j) = bits(j);
        let (addr_next, ..) = bits(j + 1);
        !mask_j | (addr_j ^ addr_next)
    };

    let mut bit_counters = [0usize; 128];
    let mut window_or = U::Bits::ZERO;
    let mut full_or = U::Bits::ZERO;

    // Pass 1: OR all kill words for the full-slice candidate, and preload the
    // counters with the first window's kill words, [0, window_size - 2].
    for j in 0..n - 1 {
        let kill = kill_word(j);
        full_or |= kill;
        if j < window_size - 1 {
            add_kill(&mut window_or, &mut bit_counters, kill);
        }
    }

    let (.., mask_last) = bits(n - 1);
    let mut best_start = 0;
    let mut best_len = n;
    let mut best_mask = !full_or & mask_last;

    // Pass 2: scan windows left to right; strict `>` keeps the first-seen
    // best window on ties.
    for i in 0..=(n - window_size) {
        if i > 0 {
            remove_kill(&mut window_or, &mut bit_counters, kill_word(i - 1));
            add_kill(&mut window_or, &mut bit_counters, kill_word(i + window_size - 2));
        }

        let (.., mask_end) = bits(i + window_size - 1);
        let window_mask = !window_or & mask_end;
        if window_mask > best_mask {
            best_start = i;
            best_len = window_size;
            best_mask = window_mask;
        }
    }

    let mut range = best_start..(best_start + best_len);
    let candidate = U::from_bits(bits(best_start).0, best_mask);

    // The candidate's mask can match more networks than were in the window it came
    // from.
    while range.start > 0 && candidate.contains(nets[range.start - 1].as_ref()) {
        range.start -= 1;
    }
    while range.end < n && candidate.contains(nets[range.end].as_ref()) {
        range.end += 1;
    }

    Some((candidate, range))
}

// Adds a kill word into the sliding-window OR, incrementing the counters of its
// set bits.
#[inline]
fn add_kill<W: Word>(window_or: &mut W, bit_counters: &mut [usize; 128], mut kill_word: W) {
    *window_or |= kill_word;
    while kill_word != W::ZERO {
        let bit = kill_word.trailing_zeros();
        bit_counters[bit as usize] += 1;
        kill_word = kill_word.clear_lowest();
    }
}

// Removes a kill word from the sliding-window OR, clearing bits whose counters
// drop to zero.
#[inline]
fn remove_kill<W: Word>(window_or: &mut W, bit_counters: &mut [usize; 128], mut kill_word: W) {
    while kill_word != W::ZERO {
        let bit = kill_word.trailing_zeros();
        bit_counters[bit as usize] -= 1;
        if bit_counters[bit as usize] == 0 {
            *window_or = window_or.clear_bit(bit);
        }
        kill_word = kill_word.clear_lowest();
    }
}

// Word-sized bit operations needed by `ip_binary_split` on the packed (addr,
// mask) representation.
//
// Implemented for `u32` (IPv4) and `u128` (IPv6).
trait Word:
    Copy
    + Eq
    + Ord
    + core::ops::Not<Output = Self>
    + core::ops::BitAnd<Output = Self>
    + core::ops::BitOr<Output = Self>
    + core::ops::BitXor<Output = Self>
    + core::ops::BitOrAssign
{
    const ZERO: Self;

    // Below this many elements, `ip_binary_split_quadratic` is faster than
    // `ip_binary_split_linear` for this word width.
    const SPLIT_THRESHOLD: usize;

    fn trailing_zeros(self) -> u32;
    fn clear_lowest(self) -> Self;
    fn clear_bit(self, b: u32) -> Self;
}

impl Word for u32 {
    const ZERO: Self = 0;

    // Measured with `cargo bench --bench net -- binary_split`: the IPv4
    // crossover falls between n = 20 (quadratic faster) and n = 24 (linear
    // faster).
    const SPLIT_THRESHOLD: usize = 24;

    #[inline]
    fn trailing_zeros(self) -> u32 {
        self.trailing_zeros()
    }

    #[inline]
    fn clear_lowest(self) -> Self {
        self & self.wrapping_sub(1)
    }

    #[inline]
    fn clear_bit(self, b: u32) -> Self {
        self & !(1 << b)
    }
}

impl Word for u128 {
    const ZERO: Self = 0;

    // Measured with `cargo bench --bench net -- binary_split`: the IPv6
    // crossover falls between n = 48 (quadratic faster) and n = 56 (linear
    // faster).
    const SPLIT_THRESHOLD: usize = 56;

    #[inline]
    fn trailing_zeros(self) -> u32 {
        self.trailing_zeros()
    }

    #[inline]
    fn clear_lowest(self) -> Self {
        self & self.wrapping_sub(1)
    }

    #[inline]
    fn clear_bit(self, b: u32) -> Self {
        self & !(1 << b)
    }
}

trait BinarySplit: Sized {
    type Mask: PartialOrd;
    type Bits: Word;

    fn mask(&self) -> &Self::Mask;
    fn contains(&self, other: &Self) -> bool;
    fn supernet_for(&self, nets: &[Self]) -> Self;
    fn to_bits(&self) -> (Self::Bits, Self::Bits);
    fn from_bits(addr: Self::Bits, mask: Self::Bits) -> Self;
}

impl BinarySplit for Ipv4Network {
    type Mask = Ipv4Addr;
    type Bits = u32;

    #[inline]
    fn mask(&self) -> &Self::Mask {
        self.mask()
    }

    #[inline]
    fn contains(&self, other: &Self) -> bool {
        self.contains(other)
    }

    #[inline]
    fn supernet_for(&self, nets: &[Self]) -> Ipv4Network {
        self.supernet_for(nets)
    }

    #[inline]
    fn to_bits(&self) -> (u32, u32) {
        self.to_bits()
    }

    #[inline]
    fn from_bits(addr: u32, mask: u32) -> Self {
        Self::from_bits(addr, mask)
    }
}

impl BinarySplit for Ipv6Network {
    type Mask = Ipv6Addr;
    type Bits = u128;

    #[inline]
    fn mask(&self) -> &Self::Mask {
        self.mask()
    }

    #[inline]
    fn contains(&self, other: &Self) -> bool {
        self.contains(other)
    }

    #[inline]
    fn supernet_for(&self, nets: &[Self]) -> Ipv6Network {
        self.supernet_for(nets)
    }

    #[inline]
    fn to_bits(&self) -> (u128, u128) {
        self.to_bits()
    }

    #[inline]
    fn from_bits(addr: u128, mask: u128) -> Self {
        Self::from_bits(addr, mask)
    }
}

/// Aggregates IPv4 networks in place: removes duplicates, eliminates networks
/// contained in others, and merges adjacent siblings.
///
/// Returns the aggregated subslice. The union of addresses in the result
/// equals the union of addresses in the input — no addresses are added or
/// removed.
///
/// Works correctly with both contiguous (CIDR) and non-contiguous masks.
/// Zero allocations — the algorithm operates entirely within the input slice.
///
/// # Examples
///
/// ```
/// use netip::{Ipv4Network, ipv4_aggregate};
///
/// let mut nets = [
///     Ipv4Network::parse("192.168.0.0/24").unwrap(),
///     Ipv4Network::parse("192.168.1.0/24").unwrap(),
///     Ipv4Network::parse("10.0.0.0/8").unwrap(),
///     Ipv4Network::parse("10.1.0.0/16").unwrap(),
/// ];
///
/// let result = ipv4_aggregate(&mut nets);
/// assert_eq!(result.len(), 2);
/// assert_eq!(result[0], Ipv4Network::parse("10.0.0.0/8").unwrap());
/// assert_eq!(result[1], Ipv4Network::parse("192.168.0.0/23").unwrap());
/// ```
pub fn ipv4_aggregate(nets: &mut [Ipv4Network]) -> &mut [Ipv4Network] {
    let len = ip_aggregate(nets);
    &mut nets[..len]
}

/// Aggregates IPv6 networks in place: removes duplicates, eliminates networks
/// contained in others, and merges adjacent siblings.
///
/// Returns the aggregated subslice. The union of addresses in the result
/// equals the union of addresses in the input — no addresses are added or
/// removed.
///
/// Works correctly with both contiguous (CIDR) and non-contiguous masks.
/// Zero allocations — the algorithm operates entirely within the input slice.
///
/// # Examples
///
/// ```
/// use netip::{Ipv6Network, ipv6_aggregate};
///
/// let mut nets = [
///     Ipv6Network::parse("2001:db8::/48").unwrap(),
///     Ipv6Network::parse("2001:db8:1::/48").unwrap(),
///     Ipv6Network::parse("fe80::/10").unwrap(),
///     Ipv6Network::parse("fe80::/64").unwrap(),
/// ];
///
/// let result = ipv6_aggregate(&mut nets);
/// assert_eq!(result.len(), 2);
/// assert_eq!(result[0], Ipv6Network::parse("2001:db8::/47").unwrap());
/// assert_eq!(result[1], Ipv6Network::parse("fe80::/10").unwrap());
/// ```
pub fn ipv6_aggregate(nets: &mut [Ipv6Network]) -> &mut [Ipv6Network] {
    let len = ip_aggregate(nets);
    &mut nets[..len]
}

trait Aggregate: Ord + Copy {
    fn merge(&self, other: &Self) -> Option<Self>;
}

impl Aggregate for Ipv4Network {
    #[inline]
    fn merge(&self, other: &Self) -> Option<Self> {
        self.merge(other)
    }
}

impl Aggregate for Ipv6Network {
    #[inline]
    fn merge(&self, other: &Self) -> Option<Self> {
        self.merge(other)
    }
}

fn ip_aggregate<T: Aggregate>(nets: &mut [T]) -> usize {
    if nets.len() <= 1 {
        return nets.len();
    }

    nets.sort_unstable();

    // Single-pass merge with full stack scan and collapse.
    //
    // For each candidate we scan the entire stack for a merge partner.
    // Merge covers identical networks, containment in either direction,
    // and same-mask one-bit-diff siblings.
    //
    // After a successful merge at position k the result may unlock new
    // merge opportunities with other stack entries (e.g. two /24 sibling
    // merges produce two /23s that are themselves siblings).
    //
    // We handle this by *collapsing*: repeatedly scanning the stack for
    // anything that merges with nets[k] until no more matches are found.
    let mut w = 0usize;
    for r in 1..nets.len() {
        let mut merged_at = None;

        for k in (0..=w).rev() {
            if let Some(m) = nets[k].merge(&nets[r]) {
                // Skip collapse when the stack entry absorbed the candidate
                // without changing (containment / dedup) — no new merge
                // opportunities can arise.
                merged_at = Some((k, nets[k] != m));
                nets[k] = m;
                break;
            }
        }

        match merged_at {
            Some((mut k, true)) => {
                let mut changed = true;

                while core::mem::replace(&mut changed, false) {
                    let mut j = 0;
                    while j <= w {
                        if j != k
                            && let Some(m) = nets[k].merge(&nets[j])
                        {
                            nets[k] = m;
                            for s in j..w {
                                nets[s] = nets[s + 1];
                            }
                            w -= 1;
                            if j < k {
                                k -= 1;
                            }
                            changed = true;
                            break;
                        }
                        j += 1;
                    }
                }
            }
            Some(..) => {}
            None => {
                w += 1;
                nets[w] = nets[r];
            }
        }
    }

    w + 1
}

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
pub struct Contiguous<T>(T);

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

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl FromStr for Contiguous<Ipv4Network> {
    type Err = ContiguousIpNetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl FromStr for Contiguous<Ipv6Network> {
    type Err = ContiguousIpNetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod test {
    use core::cmp::Ordering;

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn test_ipv4_mask_from_cidr() {
        let masks = &[
            0u32,
            0b10000000000000000000000000000000,
            0b11000000000000000000000000000000,
            0b11100000000000000000000000000000,
            0b11110000000000000000000000000000,
            0b11111000000000000000000000000000,
            0b11111100000000000000000000000000,
            0b11111110000000000000000000000000,
            0b11111111000000000000000000000000,
            0b11111111100000000000000000000000,
            0b11111111110000000000000000000000,
            0b11111111111000000000000000000000,
            0b11111111111100000000000000000000,
            0b11111111111110000000000000000000,
            0b11111111111111000000000000000000,
            0b11111111111111100000000000000000,
            0b11111111111111110000000000000000,
            0b11111111111111111000000000000000,
            0b11111111111111111100000000000000,
            0b11111111111111111110000000000000,
            0b11111111111111111111000000000000,
            0b11111111111111111111100000000000,
            0b11111111111111111111110000000000,
            0b11111111111111111111111000000000,
            0b11111111111111111111111100000000,
            0b11111111111111111111111110000000,
            0b11111111111111111111111111000000,
            0b11111111111111111111111111100000,
            0b11111111111111111111111111110000,
            0b11111111111111111111111111111000,
            0b11111111111111111111111111111100,
            0b11111111111111111111111111111110,
            0b11111111111111111111111111111111,
        ];

        for (idx, &mask) in masks.iter().enumerate() {
            assert_eq!(Ipv4Addr::from(mask), ipv4_mask_from_cidr(idx as u8).unwrap());
        }

        assert!(ipv4_mask_from_cidr(33).is_err());
    }

    #[test]
    fn test_ipv6_mask_from_cidr() {
        assert_eq!(Ipv6Addr::UNSPECIFIED, ipv6_mask_from_cidr(0).unwrap());
        assert_eq!(
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x8000, 0),
            ipv6_mask_from_cidr(97).unwrap()
        );
        assert_eq!(
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
            ipv6_mask_from_cidr(128).unwrap()
        );

        assert!(ipv6_mask_from_cidr(129).is_err());
    }

    #[test]
    fn parse_ipv4() {
        assert_eq!(
            Ipv4Network::new("127.0.0.1".parse().unwrap(), "255.255.255.255".parse().unwrap()),
            Ipv4Network::parse("127.0.0.1").unwrap()
        );
    }

    #[test]
    fn parse_ipv4_cidr() {
        assert_eq!(
            Ipv4Network::new("192.168.0.0".parse().unwrap(), "255.255.255.0".parse().unwrap()),
            Ipv4Network::parse("192.168.0.1/24").unwrap()
        );

        assert_eq!(
            Ipv4Network::new("192.168.0.1".parse().unwrap(), "255.255.255.255".parse().unwrap()),
            Ipv4Network::parse("192.168.0.1/32").unwrap()
        );
    }

    #[test]
    fn parse_ipv4_explicit_mask() {
        assert_eq!(
            Ipv4Network::new("192.168.0.0".parse().unwrap(), "255.255.255.0".parse().unwrap()),
            Ipv4Network::parse("192.168.0.1/255.255.255.0").unwrap()
        );
    }

    #[test]
    fn ipv4_contains() {
        assert!(
            Ipv4Network::parse("0.0.0.0/0")
                .unwrap()
                .contains(&Ipv4Network::parse("127.0.0.1").unwrap())
        );
        assert!(
            Ipv4Network::parse("0.0.0.0/8")
                .unwrap()
                .contains(&Ipv4Network::parse("0.0.0.0/9").unwrap())
        );
    }

    #[test]
    fn ipv4_not_contains() {
        assert!(
            !Ipv4Network::parse("0.0.0.0/9")
                .unwrap()
                .contains(&Ipv4Network::parse("0.0.0.0/8").unwrap())
        );
    }

    #[test]
    fn ipv4_contains_self() {
        assert!(
            Ipv4Network::parse("127.0.0.1")
                .unwrap()
                .contains(&Ipv4Network::parse("127.0.0.1").unwrap())
        );
    }

    #[test]
    fn ipv4_addrs_non_contiguous_matches_expected_grid() {
        let net = Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(255, 255, 0, 255));
        let mut expected: Vec<_> = (0u16..256).map(|a| Ipv4Addr::new(192, 168, a as u8, 1)).collect();
        let mut actual: Vec<_> = net.addrs().collect();
        expected.sort();
        actual.sort();

        assert_eq!(expected, actual);
    }

    #[test]
    fn ipv4_addrs_slash24_matches_incrementing_u32() {
        let net = Ipv4Network::parse("192.168.1.0/24").unwrap();
        let mut ip = net.addr().to_bits();
        for a in net.addrs() {
            assert_eq!(a.to_bits(), ip);
            ip = ip.wrapping_add(1);
        }

        assert_eq!(256, net.addrs().count());
    }

    #[test]
    fn ipv4_addrs_slash32_single() {
        let net = Ipv4Network::parse("10.0.0.1/32").unwrap();
        assert_eq!(net.addrs().next(), net.addrs().next_back());

        let mut addrs = net.addrs();
        assert_eq!(addrs.next(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(addrs.next(), None);
        assert_eq!(addrs.next_back(), None);
    }

    #[test]
    fn ipv4_addrs_non_contiguous_unique_and_endpoints() {
        let net = Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(255, 255, 0, 255));

        let addrs: Vec<_> = net.addrs().collect();
        assert_eq!(256, addrs.len());

        let mut sorted = addrs.clone();
        sorted.sort();
        sorted.dedup();

        assert_eq!(sorted.len(), addrs.len());
        assert_eq!(addrs.first().copied(), Some(*net.addr()));
        assert_eq!(addrs.last().copied(), Some(net.last_addr()));
    }

    #[test]
    fn ipv4_addrs_interleaved_exhausts_uniquely() {
        let net = Ipv4Network::parse("192.168.1.0/24").unwrap();
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
    fn ipv4_addrs_unspecified_both_ends() {
        let net = Ipv4Network::UNSPECIFIED;
        let mut addrs = net.addrs();
        assert_eq!(addrs.next(), Some(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(addrs.next_back(), Some(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn ipv6_addrs_slash120_matches_incrementing_u128() {
        let net = Ipv6Network::parse("2a02:6b8:c00::1234:0:0/120").unwrap();
        let mut ip = net.addr().to_bits();

        for addr in net.addrs() {
            assert_eq!(addr.to_bits(), ip);
            ip = ip.wrapping_add(1);
        }

        assert_eq!(256, net.addrs().count());
    }

    #[test]
    fn ipv6_addrs_slash128_single() {
        let net = Ipv6Network::parse("::1/128").unwrap();
        assert_eq!(net.addrs().next(), net.addrs().next_back());

        let mut addrs = net.addrs();
        assert_eq!(addrs.next(), Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(addrs.next(), None);
        assert_eq!(addrs.next_back(), None);
    }

    #[test]
    fn ipv6_addrs_non_contiguous_unique_and_endpoints() {
        let net = Ipv6Network::new(
            Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
        );

        let addrs: Vec<_> = net.addrs().collect();
        assert_eq!(256, addrs.len());

        let mut sorted = addrs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), addrs.len());
        assert_eq!(addrs.first().copied(), Some(*net.addr()));
        assert_eq!(addrs.last().copied(), Some(net.last_addr()));
    }

    #[test]
    fn ipv6_addrs_interleaved_exhausts_uniquely() {
        let net = Ipv6Network::parse("2a02:6b8:c00::1234:0:0/120").unwrap();
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
    fn ipv6_addrs_unspecified_both_ends() {
        let net = Ipv6Network::UNSPECIFIED;
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
    fn ipv6_addrs_non_contiguous_matches_expected_grid() {
        let net = Ipv6Network::new(
            Ipv6Addr::new(0x2a02, 0x6b8, 0x0c00, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
        );

        let mut expected: Vec<_> = (0u16..256)
            .map(|a| Ipv6Addr::new(0x2a02, 0x6b8, 0x0c00 | a, 0, 0, 0, 0, 1))
            .collect();
        let mut actual: Vec<_> = net.addrs().collect();
        expected.sort();
        actual.sort();
        assert_eq!(expected, actual);
    }

    #[test]
    fn ipv4_supernet_for() {
        let net0 = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 0), 25)).unwrap();
        let net1 = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 128), 25)).unwrap();

        let expected = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 0), 24)).unwrap();
        assert_eq!(expected, net0.supernet_for(&[net1]));
        assert_eq!(expected, net1.supernet_for(&[net0]));
    }

    #[test]
    fn ipv4_supernet_for_equal_nets() {
        let net0 = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 128), 25)).unwrap();
        let net1 = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 128), 25)).unwrap();

        let expected = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 128), 25)).unwrap();
        assert_eq!(expected, net0.supernet_for(&[net1]));
        assert_eq!(expected, net1.supernet_for(&[net0]));
    }

    #[test]
    fn ipv4_supernet_for_many() {
        let net0 = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 0), 27)).unwrap();
        let net1 = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 32), 27)).unwrap();
        let net2 = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 64), 27)).unwrap();
        let net3 = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 96), 27)).unwrap();
        let net4 = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 128), 27)).unwrap();
        let net5 = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 160), 27)).unwrap();
        let net6 = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 192), 27)).unwrap();
        let net7 = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 224), 27)).unwrap();

        let expected = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 0), 24)).unwrap();
        assert_eq!(expected, net0.supernet_for(&[net1, net2, net3, net4, net5, net6, net7]));
        assert_eq!(expected, net1.supernet_for(&[net0, net2, net3, net4, net5, net6, net7]));
        assert_eq!(expected, net2.supernet_for(&[net0, net1, net3, net4, net5, net6, net7]));
        assert_eq!(expected, net3.supernet_for(&[net0, net1, net2, net4, net5, net6, net7]));
        assert_eq!(expected, net4.supernet_for(&[net0, net1, net2, net3, net5, net6, net7]));
        assert_eq!(expected, net5.supernet_for(&[net0, net1, net2, net3, net4, net6, net7]));
        assert_eq!(expected, net6.supernet_for(&[net0, net1, net2, net3, net4, net5, net7]));
        assert_eq!(expected, net7.supernet_for(&[net0, net1, net2, net3, net4, net5, net6]));
    }

    #[test]
    fn ipv4_supernet_for_many_more() {
        let nets = &[
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 0), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 16), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 32), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 48), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 64), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 80), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 96), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 112), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 128), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 144), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 160), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 176), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 192), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 208), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 224), 28)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 240), 28)).unwrap(),
        ];

        let expected = Ipv4Network::try_from((Ipv4Addr::new(192, 0, 2, 0), 24)).unwrap();
        assert_eq!(expected, nets[0].supernet_for(&nets[1..]).to_contiguous());
    }

    #[test]
    fn ipv4_supernet_for_wide() {
        let nets = &[
            Ipv4Network::try_from((Ipv4Addr::new(10, 40, 101, 1), 32)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(10, 40, 102, 1), 32)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(10, 40, 103, 1), 32)).unwrap(),
        ];

        let expected = Ipv4Network::try_from((Ipv4Addr::new(10, 40, 100, 0), 22)).unwrap();
        assert_eq!(expected, nets[0].supernet_for(&nets[1..]).to_contiguous());
    }

    #[test]
    fn ipv4_supernet_for_wide_more() {
        let nets = &[
            Ipv4Network::try_from((Ipv4Addr::new(10, 40, 101, 1), 32)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(10, 40, 102, 1), 32)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(11, 40, 103, 1), 32)).unwrap(),
        ];

        let expected = Ipv4Network::try_from((Ipv4Addr::new(10, 0, 0, 0), 7)).unwrap();
        assert_eq!(expected, nets[0].supernet_for(&nets[1..]).to_contiguous());
    }

    #[test]
    fn ipv4_supernet_for_min() {
        let nets = &[
            Ipv4Network::try_from((Ipv4Addr::new(192, 168, 0, 0), 24)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 168, 1, 0), 24)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 168, 2, 0), 24)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 168, 100, 0), 24)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 168, 200, 0), 24)).unwrap(),
        ];

        let expected = Ipv4Network::try_from((Ipv4Addr::new(192, 168, 0, 0), 16)).unwrap();
        assert_eq!(expected, nets[0].supernet_for(&nets[1..]).to_contiguous());
    }

    #[test]
    fn ipv4_supernet_for_unspecified() {
        let nets = &[
            Ipv4Network::try_from((Ipv4Addr::new(128, 0, 0, 0), 24)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(192, 0, 0, 0), 24)).unwrap(),
            Ipv4Network::try_from((Ipv4Addr::new(65, 0, 0, 0), 24)).unwrap(),
        ];

        let expected = Ipv4Network::try_from((Ipv4Addr::new(0, 0, 0, 0), 0)).unwrap();
        assert_eq!(expected, nets[0].supernet_for(&nets[1..]).to_contiguous());
    }

    #[test]
    fn ipv4_supernet_for_non_contiguous() {
        let nets = &[
            Ipv4Network::new(Ipv4Addr::new(10, 40, 0, 1), Ipv4Addr::new(255, 255, 0, 255)),
            Ipv4Network::new(Ipv4Addr::new(10, 40, 0, 2), Ipv4Addr::new(255, 255, 0, 255)),
            Ipv4Network::new(Ipv4Addr::new(11, 40, 0, 3), Ipv4Addr::new(255, 255, 0, 255)),
        ];

        let expected = Ipv4Network::try_from((Ipv4Addr::new(10, 0, 0, 0), 7)).unwrap();
        assert_eq!(expected, nets[0].supernet_for(&nets[1..]).to_contiguous());
    }

    #[test]
    fn ipv4_supernet_for_different_prefix_lengths() {
        let narrow = Ipv4Network::parse("10.0.0.0/24").unwrap();
        let wide = Ipv4Network::parse("10.0.0.0/16").unwrap();

        assert_eq!(wide, narrow.supernet_for(&[wide]));
        assert_eq!(wide, wide.supernet_for(&[narrow]));
    }

    #[test]
    fn ipv6_supernet_for_different_prefix_lengths() {
        let narrow = Ipv6Network::parse("2001:db8::/48").unwrap();
        let wide = Ipv6Network::parse("2001:db8::/32").unwrap();

        assert_eq!(wide, narrow.supernet_for(&[wide]));
        assert_eq!(wide, wide.supernet_for(&[narrow]));
    }

    #[test]
    fn ipv4_last_addr() {
        // Contiguous networks (broadcast addresses).
        let net = Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(Ipv4Addr::new(192, 168, 1, 255), net.last_addr());

        let net = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(Ipv4Addr::new(10, 0, 0, 255), net.last_addr());

        let net = Ipv4Network::new(Ipv4Addr::new(172, 16, 0, 0), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(Ipv4Addr::new(172, 16, 255, 255), net.last_addr());

        // Single address networks.
        let net = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(Ipv4Addr::new(10, 0, 0, 1), net.last_addr());

        // Unspecified network.
        let net = Ipv4Network::UNSPECIFIED;
        assert_eq!(Ipv4Addr::new(255, 255, 255, 255), net.last_addr());

        // Non-contiguous networks.
        let net = Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(255, 255, 0, 255));
        assert_eq!(Ipv4Addr::new(192, 168, 255, 1), net.last_addr());

        let net = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 42), Ipv4Addr::new(255, 0, 255, 255));
        assert_eq!(Ipv4Addr::new(10, 255, 0, 42), net.last_addr());

        // Edge cases.
        let net = Ipv4Network::new(Ipv4Addr::new(255, 255, 255, 255), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(Ipv4Addr::new(255, 255, 255, 255), net.last_addr());

        let net = Ipv4Network::new(Ipv4Addr::new(127, 0, 0, 0), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(Ipv4Addr::new(127, 255, 255, 255), net.last_addr());
    }

    #[test]
    fn parse_ipv6_explicit_mask_normalizes_addr() {
        // Address bits outside the mask should be cleared.
        assert_eq!(
            Ipv6Network::new(
                Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0, 0, 0),
                Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0, 0, 0, 0),
            ),
            Ipv6Network::parse("2a02:6b8:c00:1:2:3:4:5/ffff:ffff:ff00::").unwrap()
        );
    }

    #[test]
    fn test_ipv6_addr_as_u128() {
        assert_eq!(
            0x2a02_06b8_0c00_0000_0000_f800_0000_0000u128,
            (*Ipv6Network::parse("2a02:6b8:c00::f800:0:0/ffff:ffff:ff00:0:ffff:f800::")
                .unwrap()
                .addr())
            .into()
        );
    }

    #[test]
    fn test_net_ipv6_contains() {
        assert!(
            Ipv6Network::parse("::/0")
                .unwrap()
                .contains(&Ipv6Network::parse("::1").unwrap())
        );
        assert!(
            Ipv6Network::parse("::/32")
                .unwrap()
                .contains(&Ipv6Network::parse("::/33").unwrap())
        );

        assert!(
            !Ipv6Network::parse("::/33")
                .unwrap()
                .contains(&Ipv6Network::parse("::/32").unwrap())
        );
    }

    #[test]
    fn test_net_ipv6_contains_self() {
        assert!(
            Ipv6Network::parse("::1")
                .unwrap()
                .contains(&Ipv6Network::parse("::1").unwrap())
        );
    }

    #[test]
    fn test_net_ipv6_non_contiguous_contains_contiguous() {
        assert!(
            Ipv6Network::parse("2a02:6b8:c00::4d71:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
                .unwrap()
                .contains(&Ipv6Network::parse("2a02:6b8:c00:1234:0:4d71::1").unwrap())
        );
    }

    #[test]
    fn test_net_ipv6_is_contiguous() {
        assert!(Ipv6Network::parse("::/0").unwrap().is_contiguous());
        assert!(Ipv6Network::parse("::1").unwrap().is_contiguous());
        assert!(Ipv6Network::parse("2a02:6b8:c00::/40").unwrap().is_contiguous());
        assert!(
            Ipv6Network::parse("2a02:6b8:c00:1:2:3:4:1/127")
                .unwrap()
                .is_contiguous()
        );
        assert!(
            Ipv6Network::parse("2a02:6b8:c00:1:2:3:4:1/128")
                .unwrap()
                .is_contiguous()
        );
        assert!(Ipv6Network::parse("2a02:6b8:c00:1:2:3:4:1").unwrap().is_contiguous());

        assert!(
            !Ipv6Network::parse("2a02:6b8:c00::f800:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
                .unwrap()
                .is_contiguous()
        );
        assert!(
            !Ipv6Network::parse("2a02:6b8:c00::f800:0:0/ffff:ffff:ff00:0:ffff:f800::")
                .unwrap()
                .is_contiguous()
        );
        assert!(
            !Ipv6Network::parse("2a02:6b8:0:0:1234:5678::/ffff:ffff:0:0:ffff:ffff:0:0")
                .unwrap()
                .is_contiguous()
        );
        assert!(
            !Ipv6Network::parse("2a02:6b8:0:0:1234:5678::/ffff:ffff:0:0:f0f0:f0f0:f0f0:f0f0")
                .unwrap()
                .is_contiguous()
        );
    }

    #[test]
    fn ipv6_supernet_for() {
        let nets = &[
            Ipv6Network::parse("2001:db8:1::/32").unwrap(),
            Ipv6Network::parse("2001:db8:2::/39").unwrap(),
        ];

        let expected = Ipv6Network::parse("2001:db8::/32").unwrap();
        assert_eq!(expected, nets[0].supernet_for(&nets[1..]));
    }

    #[test]
    fn ipv6_supernet_for_wide() {
        let nets = &[
            Ipv6Network::parse("2013:db8:1::1/64").unwrap(),
            Ipv6Network::parse("2013:db8:2::1/64").unwrap(),
        ];

        let expected = Ipv6Network::new(
            Ipv6Addr::new(0x2013, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xfffc, 0xffff, 0, 0, 0, 0),
        );
        assert_eq!(expected, nets[0].supernet_for(&nets[1..]));
    }

    #[test]
    fn ipv6_supernet_for_unspecified() {
        // Alternating bit patterns: every bit disagrees, so mask becomes ::/0.
        let nets = &[
            Ipv6Network::parse("aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa/128").unwrap(),
            Ipv6Network::parse("5555:5555:5555:5555:5555:5555:5555:5555/128").unwrap(),
        ];

        let expected = Ipv6Network::parse("::/0").unwrap();
        assert_eq!(expected, nets[0].supernet_for(&nets[1..]));
    }

    #[test]
    fn ipv6_supernet_for_partial_agreement() {
        let nets = &[
            Ipv6Network::parse("8001:db8:1::/34").unwrap(),
            Ipv6Network::parse("2013:db8:2::/32").unwrap(),
        ];

        let expected = Ipv6Network::new(
            Ipv6Addr::new(0x0001, 0x0db8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x5fed, 0xffff, 0, 0, 0, 0, 0, 0),
        );
        assert_eq!(expected, nets[0].supernet_for(&nets[1..]));
    }

    #[test]
    fn ipv6_supernet_for_non_contiguous() {
        let nets = &[
            Ipv6Network::parse("2a02:6b8:c00::48aa:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap(),
            Ipv6Network::parse("2a02:6b8:c00::4707:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap(),
        ];

        let expected = Ipv6Network::parse("2a02:6b8:c00::4002:0:0/ffff:ffff:ff00::ffff:f052:0:0").unwrap();
        assert_eq!(expected, nets[0].supernet_for(&nets[1..]));
    }

    #[test]
    fn ipv6_supernet_for_non_contiguous_different_aggregates() {
        let nets = &[
            Ipv6Network::parse("2a02:6b8:c00::48aa:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap(),
            Ipv6Network::parse("2a02:6b8:fc00::4707:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap(),
        ];

        let expected = Ipv6Network::parse("2a02:6b8:c00::4002:0:0/ffff:ffff:f00::ffff:f052:0:0").unwrap();
        assert_eq!(expected, nets[0].supernet_for(&nets[1..]));
    }

    #[test]
    fn test_net_display_addr() {
        let net = Ipv4Network::new(Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!("127.0.0.1/32", &format!("{net}"));

        let net = Ipv6Network::new(
            Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
        );
        assert_eq!("2a02:6b8::1/128", &format!("{net}"));
    }

    #[test]
    fn test_net_display_cidr() {
        let net = Ipv4Network::parse("10.0.0.0/24").unwrap();
        assert_eq!("10.0.0.0/24", &format!("{net}"));

        let net = Ipv6Network::parse("2a02:6b8:c00:0:1:2::/96").unwrap();
        assert_eq!("2a02:6b8:c00:0:1:2::/96", &format!("{net}"));
    }

    #[test]
    fn test_net_display_non_contiguous() {
        let net = Ipv4Network::parse("10.0.1.0/255.0.255.0").unwrap();
        assert_eq!("10.0.1.0/255.0.255.0", &format!("{net}"));

        let net = Ipv6Network(
            "2a02:6b8:0:0:0:1234::".parse().unwrap(),
            "ffff:ffff:0:0:ffff:ffff:0:0".parse().unwrap(),
        );
        assert_eq!("2a02:6b8::1234:0:0/ffff:ffff::ffff:ffff:0:0", &format!("{net}"));

        let net = Ipv6Network(
            "2a02:6b8:0:0:1234:5678::".parse().unwrap(),
            "ffff:ffff:0:0:ffff:ffff:0:0".parse().unwrap(),
        );
        assert_eq!("2a02:6b8::1234:5678:0:0/ffff:ffff::ffff:ffff:0:0", &format!("{net}"));
    }

    #[test]
    fn ipv6_difference_disjoint() {
        let a = Ipv6Network::parse("2001:db8::/32").unwrap();
        let b = Ipv6Network::parse("fe80::/10").unwrap();
        let diff: Vec<_> = a.difference(&b).collect();
        assert_eq!(diff, vec![a]);
    }

    #[test]
    fn ipv6_difference_subset() {
        let a = Ipv6Network::parse("2001:db8::/64").unwrap();
        let b = Ipv6Network::parse("2001:db8::/48").unwrap();
        let diff: Vec<_> = a.difference(&b).collect();
        assert!(diff.is_empty());
    }

    #[test]
    fn ipv6_difference_same_network() {
        let a = Ipv6Network::parse("2001:db8::/32").unwrap();
        let diff: Vec<_> = a.difference(&a).collect();
        assert!(diff.is_empty());
    }

    #[test]
    fn ipv6_difference_superset() {
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        let b = Ipv6Network::parse("2001:db8::/64").unwrap();
        let diff: Vec<_> = a.difference(&b).collect();
        assert_eq!(diff.len(), 16);

        for r in &diff {
            assert!(a.contains(r), "part {r} not in A");
            assert!(r.is_disjoint(&b), "part {r} intersects B");
        }

        for i in 0..diff.len() {
            for j in (i + 1)..diff.len() {
                assert!(diff[i].is_disjoint(&diff[j]), "parts {i} and {j} overlap");
            }
        }
    }

    #[test]
    fn ipv6_difference_universe_minus_host() {
        let a = Ipv6Network::parse("::/0").unwrap();
        let b = Ipv6Network::parse("2001:db8::1/128").unwrap();
        let diff: Vec<_> = a.difference(&b).collect();
        assert_eq!(diff.len(), 128);

        for r in &diff {
            assert!(r.is_contiguous(), "non-contiguous mask in {r}");
            assert!(a.contains(r), "part {r} not in A");
            assert!(r.is_disjoint(&b), "part {r} intersects B");
        }
    }

    #[test]
    fn ipv6_difference_host_minus_universe() {
        let a = Ipv6Network::parse("2001:db8::1/128").unwrap();
        let b = Ipv6Network::parse("::/0").unwrap();
        let diff: Vec<_> = a.difference(&b).collect();
        assert!(diff.is_empty());
    }

    #[test]
    fn ipv6_difference_hosts_same() {
        let a = Ipv6Network::parse("2001:db8::1/128").unwrap();
        let b = Ipv6Network::parse("2001:db8::1/128").unwrap();
        let diff: Vec<_> = a.difference(&b).collect();
        assert!(diff.is_empty());
    }

    #[test]
    fn ipv6_difference_hosts_different() {
        let a = Ipv6Network::parse("2001:db8::1/128").unwrap();
        let b = Ipv6Network::parse("2001:db8::2/128").unwrap();
        let diff: Vec<_> = a.difference(&b).collect();
        assert_eq!(diff, vec![a]);
    }

    #[test]
    fn ipv6_difference_non_contiguous() {
        // A = anything matching mask ffff::/16
        // B = matching ffff::ff/16 + bottom byte
        let a = Ipv6Network::from_bits(
            0x2001_0000_0000_0000_0000_0000_0000_0000,
            0xffff_0000_0000_0000_0000_0000_0000_0000,
        );
        let b = Ipv6Network::from_bits(
            0x2001_0000_0000_0000_0000_0000_0000_0001,
            0xffff_0000_0000_0000_0000_0000_0000_00ff,
        );
        let diff: Vec<_> = a.difference(&b).collect();
        // d = inter_mask & !source_mask = (ffff::ff) & !(ffff::) = 0xff
        assert_eq!(diff.len(), 8);

        for r in &diff {
            assert!(a.contains(r), "part {r} not in A");
            assert!(r.is_disjoint(&b), "part {r} intersects B");
        }
    }

    #[test]
    fn ipv6_difference_exact_size() {
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        let b = Ipv6Network::parse("2001:db8::/64").unwrap();
        let mut diff = a.difference(&b);
        assert_eq!(diff.len(), 16);
        diff.next();
        assert_eq!(diff.len(), 15);
    }

    #[test]
    fn test_ipv4_binary_split_empty() {
        assert!(ipv4_binary_split::<Ipv4Network>(&[]).is_none());
    }

    #[test]
    fn test_ipv4_binary_split_less_than_required_networks() {
        let nets = &["127.0.0.1", "127.0.0.2"];
        let mut nets: Vec<_> = nets.iter().map(|net| Ipv4Network::parse(net).unwrap()).collect();
        nets.sort();
        nets.dedup();

        assert!(ipv4_binary_split(&nets).is_none());
    }

    #[test]
    fn test_ipv4_binary_split_three_nets() {
        let nets = &["127.0.0.1", "127.0.0.2", "127.0.0.3"];
        let mut nets: Vec<_> = nets.iter().map(|net| Ipv4Network::parse(net).unwrap()).collect();
        nets.sort();
        nets.dedup();

        let (supernet, range) = ipv4_binary_split(&nets).unwrap();
        // 127.0.0.2/31 in binary is "0b...10/0b...10", which contains both "127.0.0.2"
        // and "127.0.0.3".
        assert_eq!(Ipv4Network::parse("127.0.0.2/31").unwrap(), supernet);

        for (idx, net) in nets.iter().enumerate() {
            assert_eq!(range.contains(&idx), supernet.contains(net));
        }
    }

    #[test]
    fn test_ipv4_binary_split_more_nets() {
        // .
        // ├─ 10.204.46.68/31
        // ├─ 10.204.49.12/31
        // ├─ 10.204.49.14/31
        // ├─ 10.204.49.18/31
        // └─ 10.204.49.32/28 [*]
        //   ├─ 10.204.49.32/31
        //   ├─ 10.204.49.34/31
        //   ├─ 10.204.49.36/31
        //   ├─ 10.204.49.38/31
        //   └─ 10.204.49.40/31

        let nets = &[
            "10.204.46.68/31",
            "10.204.49.12/31",
            "10.204.49.14/31",
            "10.204.49.18/31",
            "10.204.49.32/31",
            "10.204.49.34/31",
            "10.204.49.36/31",
            "10.204.49.38/31",
            "10.204.49.40/31",
        ];
        let mut nets: Vec<_> = nets.iter().map(|net| Ipv4Network::parse(net).unwrap()).collect();
        nets.sort();
        nets.dedup();

        let (supernet, range) = ipv4_binary_split(&nets).unwrap();

        assert_eq!(Ipv4Network::parse("10.204.49.32/28").unwrap(), supernet);

        for (idx, net) in nets.iter().enumerate() {
            assert_eq!(range.contains(&idx), supernet.contains(net));
        }
    }

    #[test]
    fn test_ipv4_binary_split_even_number_of_nets() {
        // .
        // ├─ 10.204.46.54/31
        // ├─ 10.204.46.68/31
        // ├─ 10.204.49.12/31
        // ├─ 10.204.49.14/31
        // ├─ 10.204.49.18/31
        // └─ 10.204.49.32/28 [*]
        //   ├─ 10.204.49.32/31
        //   ├─ 10.204.49.34/31
        //   ├─ 10.204.49.36/31
        //   ├─ 10.204.49.38/31
        //   └─ 10.204.49.40/31

        let nets = &[
            "10.204.46.54/31",
            "10.204.46.68/31",
            "10.204.49.12/31",
            "10.204.49.14/31",
            "10.204.49.18/31",
            "10.204.49.32/31",
            "10.204.49.34/31",
            "10.204.49.36/31",
            "10.204.49.38/31",
            "10.204.49.40/31",
        ];
        let mut nets: Vec<_> = nets.iter().map(|net| Ipv4Network::parse(net).unwrap()).collect();
        nets.sort();
        nets.dedup();

        let (supernet, range) = ipv4_binary_split(&nets).unwrap();

        assert_eq!(Ipv4Network::parse("10.204.49.32/28").unwrap(), supernet);

        for (idx, net) in nets.iter().enumerate() {
            assert_eq!(range.contains(&idx), supernet.contains(net));
        }
    }

    #[test]
    fn test_ipv4_binary_split_in_the_middle() {
        // .
        // ├─ 10.204.46.50/31
        // ├─ 10.204.46.54/31
        // ├─ 10.204.47.22/31
        // ├─ 10.204.49.0/26 [*]
        // │ ├─ 10.204.49.24/31
        // │ ├─ 10.204.49.26/31
        // │ ├─ 10.204.49.28/31
        // │ ├─ 10.204.49.32/31
        // │ ├─ 10.204.49.34/31
        // │ └─ 10.204.49.36/31
        // ├─ 10.204.50.38/31
        // └─ 10.204.50.40/31

        let nets = &[
            "10.204.46.50/31",
            "10.204.46.54/31",
            "10.204.47.22/31",
            "10.204.49.24/31",
            "10.204.49.26/31",
            "10.204.49.28/31",
            "10.204.49.32/31",
            "10.204.49.34/31",
            "10.204.49.36/31",
            "10.204.50.38/31",
            "10.204.50.40/31",
        ];
        let mut nets: Vec<_> = nets.iter().map(|net| Ipv4Network::parse(net).unwrap()).collect();
        nets.sort();
        nets.dedup();

        let (supernet, range) = ipv4_binary_split(&nets).unwrap();

        assert_eq!(Ipv4Network::parse("10.204.49.0/26").unwrap(), supernet);

        for (idx, net) in nets.iter().enumerate() {
            assert_eq!(range.contains(&idx), supernet.contains(net));
        }
    }

    #[test]
    fn test_ipv6_binary_split_empty() {
        assert!(ipv6_binary_split::<Ipv6Network>(&[]).is_none());
    }

    #[test]
    fn test_ipv6_binary_split_less_than_required_networks() {
        let nets = &["::1", "::2"];
        let mut nets: Vec<_> = nets.iter().map(|net| Ipv6Network::parse(net).unwrap()).collect();
        nets.sort();
        nets.dedup();

        assert!(ipv6_binary_split(&nets).is_none());
    }

    #[test]
    fn test_ipv6_binary_split_three_nets() {
        let nets = &["::1", "::2", "::3"];
        let mut nets: Vec<_> = nets.iter().map(|net| Ipv6Network::parse(net).unwrap()).collect();
        nets.sort();
        nets.dedup();

        let (supernet, range) = ipv6_binary_split(&nets).unwrap();
        // ::2/127 in binary is "0b...10/0b...10", which contains both "::2" and "::3".
        assert_eq!(Ipv6Network::parse("::2/127").unwrap(), supernet);

        for (idx, net) in nets.iter().enumerate() {
            assert_eq!(range.contains(&idx), supernet.contains(net));
        }
    }

    #[test]
    fn test_ipv6_binary_split_more_nets() {
        let nets = &[
            "2a02:6b8:0:2a03::/64",
            "2a02:6b8:0:2a13::/64",
            "2a02:6b8:0:2a16::/64",
            "2a02:6b8:0:2a18::/64",
            "2a02:6b8:0:2a19::/64",
            "2a02:6b8:0:2a1c::/64",
            "2a02:6b8:0:2a1d::/64",
            "2a02:6b8:0:2a24::/64",
            "2a02:6b8:0:2800::/55",
        ];
        let mut nets: Vec<_> = nets.iter().map(|net| Ipv6Network::parse(net).unwrap()).collect();
        nets.sort();
        nets.dedup();

        let (supernet, range) = ipv6_binary_split(&nets).unwrap();

        assert_eq!(Ipv6Network::parse("2a02:6b8:0:2a10::/60").unwrap(), supernet);

        for (idx, net) in nets.iter().enumerate() {
            assert_eq!(range.contains(&idx), supernet.contains(net));
        }
    }

    #[test]
    fn test_ipv6_binary_split_even_number_of_nets() {
        let nets = &[
            "2a02:6b8:0:2318::/64",
            "2a02:6b8:0:231e::/64",
            "2a02:6b8:0:231f::/64",
            "2a02:6b8:0:2302::/64",
            "2a02:6b8:0:2303::/64",
            "2a02:6b8:0:2305::/64",
            "2a02:6b8:0:2306::/64",
            "2a02:6b8:0:2307::/64",
            "2a02:6b8:0:2311::/64",
            "2a02:6b8:0:2314::/64",
        ];
        let mut nets: Vec<_> = nets.iter().map(|net| Ipv6Network::parse(net).unwrap()).collect();
        nets.sort();
        nets.dedup();

        let (supernet, range) = ipv6_binary_split(&nets).unwrap();

        assert_eq!(Ipv6Network::parse("2a02:6b8:0:2300::/61").unwrap(), supernet);

        for (idx, net) in nets.iter().enumerate() {
            assert_eq!(range.contains(&idx), supernet.contains(net));
        }
    }

    #[test]
    fn test_ipv6_binary_split_in_the_middle() {
        let nets = &[
            "2a02:6b8:0:2302::/64",
            "2a02:6b8:0:2303::/64",
            "2a02:6b8:0:2305::/64",
            "2a02:6b8:0:2308::/64",
            "2a02:6b8:0:2309::/64",
            "2a02:6b8:0:230a::/64",
            "2a02:6b8:0:230b::/64",
            "2a02:6b8:0:230c::/64",
            "2a02:6b8:0:230d::/64",
            "2a02:6b8:0:2314::/64",
            "2a02:6b8:0:231f::/64",
        ];
        let mut nets: Vec<_> = nets.iter().map(|net| Ipv6Network::parse(net).unwrap()).collect();
        nets.sort();
        nets.dedup();

        let (supernet, range) = ipv6_binary_split(&nets).unwrap();

        assert_eq!(Ipv6Network::parse("2a02:6b8:0:2308::/61").unwrap(), supernet);

        for (idx, net) in nets.iter().enumerate() {
            assert_eq!(range.contains(&idx), supernet.contains(net));
        }
    }

    #[test]
    fn test_ipv6_binary_split_non_contiguous() {
        let nets = &[
            "2a02:6b8:c00::4510:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::4511:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::4512:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::4513:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::4514:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::4515:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::4516:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::4517:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::4518:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::4519:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::451a:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
        ];
        let mut nets: Vec<_> = nets.iter().map(|net| Ipv6Network::parse(net).unwrap()).collect();
        nets.sort();
        nets.dedup();

        let (supernet, range) = ipv6_binary_split(&nets).unwrap();

        assert_eq!(
            Ipv6Network::parse("2a02:6b8:c00::4510:0:0/ffff:ffff:ff00:0:ffff:fff8::").unwrap(),
            supernet
        );

        for (idx, net) in nets.iter().enumerate() {
            assert_eq!(range.contains(&idx), supernet.contains(net));
        }
    }

    #[test]
    fn test_ipv6_binary_split_non_contiguous_in_the_middle() {
        let nets = &[
            "2a02:6b8:c00::2302:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::2303:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::2305:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::2308:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::2309:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::230a:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::230b:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::230c:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::230d:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::2314:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            "2a02:6b8:c00::231f:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
        ];
        let mut nets: Vec<_> = nets.iter().map(|net| Ipv6Network::parse(net).unwrap()).collect();
        nets.sort();
        nets.dedup();

        let (supernet, range) = ipv6_binary_split(&nets).unwrap();

        assert_eq!(
            Ipv6Network::parse("2a02:6b8:c00::2308:0:0/ffff:ffff:ff00:0:ffff:fff8::").unwrap(),
            supernet
        );

        for (idx, net) in nets.iter().enumerate() {
            assert_eq!(range.contains(&idx), supernet.contains(net));
        }
    }

    #[test]
    fn test_ipv4_binary_split_tie_first_window_wins() {
        let nets = &[
            "10.0.0.0/16",
            "10.0.0.0/16",
            "10.0.0.0/16",
            "10.1.0.0/16",
            "10.1.0.0/16",
            "10.1.0.0/16",
        ];
        let nets: Vec<_> = nets.iter().map(|net| Ipv4Network::parse(net).unwrap()).collect();

        let (supernet, range) = ipv4_binary_split(&nets).unwrap();
        assert_eq!(Ipv4Network::parse("10.0.0.0/16").unwrap(), supernet);
        assert_eq!(0..3, range);
    }

    #[test]
    fn test_ipv4_binary_split_non_contiguous_worked_example() {
        let nets = &[
            "10.1.0.5/255.255.0.255",
            "10.1.0.5/255.255.0.255",
            "10.1.7.5/255.255.0.255",
            "10.2.0.9/255.0.255.255",
        ];
        let nets: Vec<_> = nets.iter().map(|net| Ipv4Network::parse(net).unwrap()).collect();

        let (supernet, range) = ipv4_binary_split(&nets).unwrap();
        assert_eq!(Ipv4Network::parse("10.1.0.5/255.255.0.255").unwrap(), supernet);
        assert_eq!(0..3, range);
    }

    #[test]
    fn test_ipv4_binary_split_never_beaten() {
        let nets = &[
            "192.168.1.0/24",
            "192.168.1.0/24",
            "192.168.1.0/24",
            "192.168.1.0/24",
            "192.168.1.0/24",
        ];
        let nets: Vec<_> = nets.iter().map(|net| Ipv4Network::parse(net).unwrap()).collect();

        let (supernet, range) = ipv4_binary_split(&nets).unwrap();
        assert_eq!(Ipv4Network::parse("192.168.1.0/24").unwrap(), supernet);
        assert_eq!(0..5, range);
    }

    // First element's kill word sets a bit that neither of the next two kill
    // words set. When the window slides from [0, 2] to [1, 3], that bit's
    // counter drops from 1 to 0 and must be cleared from the sliding OR
    // (otherwise the winning window's mask would come out too narrow).
    #[test]
    fn test_ipv4_binary_split_counter_expiry() {
        let nets = &[
            "10.128.0.0/24",
            "10.0.0.0/24",
            "10.0.1.0/24",
            "10.0.3.0/24",
            "200.0.0.0/8",
        ];
        let nets: Vec<_> = nets.iter().map(|net| Ipv4Network::parse(net).unwrap()).collect();

        let (supernet, range) = ipv4_binary_split(&nets).unwrap();
        assert_eq!(Ipv4Network::parse("10.0.0.0/255.255.252.0").unwrap(), supernet);
        assert_eq!(1..4, range);
    }

    #[test]
    fn test_ipv6_binary_split_tie_first_window_wins() {
        let nets = &[
            "2001:db8::/32",
            "2001:db8::/32",
            "2001:db8::/32",
            "2001:db9::/32",
            "2001:db9::/32",
            "2001:db9::/32",
        ];
        let nets: Vec<_> = nets.iter().map(|net| Ipv6Network::parse(net).unwrap()).collect();

        let (supernet, range) = ipv6_binary_split(&nets).unwrap();
        assert_eq!(Ipv6Network::parse("2001:db8::/32").unwrap(), supernet);
        assert_eq!(0..3, range);
    }

    #[test]
    fn test_ipv6_binary_split_non_contiguous_worked_example() {
        let nets = &[
            "2001:db8:1:2:0:3:4:5/ffff:ffff:ffff:ffff:0:ffff:ffff:ffff",
            "2001:db8:1:2:0:3:4:5/ffff:ffff:ffff:ffff:0:ffff:ffff:ffff",
            "2001:db8:1:2:77:3:4:5/ffff:ffff:ffff:ffff:0:ffff:ffff:ffff",
            "2002:db8:1:2:0:3:4:5/ffff:0:ffff:ffff:ffff:ffff:ffff:ffff",
        ];
        let nets: Vec<_> = nets.iter().map(|net| Ipv6Network::parse(net).unwrap()).collect();

        let (supernet, range) = ipv6_binary_split(&nets).unwrap();
        assert_eq!(
            Ipv6Network::parse("2001:db8:1:2:0:3:4:5/ffff:ffff:ffff:ffff:0:ffff:ffff:ffff").unwrap(),
            supernet
        );
        assert_eq!(0..3, range);
    }

    #[test]
    fn test_ipv6_binary_split_never_beaten() {
        let nets = &[
            "2001:db8::1/64",
            "2001:db8::1/64",
            "2001:db8::1/64",
            "2001:db8::1/64",
            "2001:db8::1/64",
        ];
        let nets: Vec<_> = nets.iter().map(|net| Ipv6Network::parse(net).unwrap()).collect();

        let (supernet, range) = ipv6_binary_split(&nets).unwrap();
        assert_eq!(Ipv6Network::parse("2001:db8::1/64").unwrap(), supernet);
        assert_eq!(0..5, range);
    }

    // IPv6 analog of `test_ipv4_binary_split_counter_expiry`: the first
    // element's kill word sets the top bit of the second segment, a bit that
    // neither of the next two kill words set, so it must be cleared from the
    // sliding OR once the window slides past index 0.
    #[test]
    fn test_ipv6_binary_split_counter_expiry() {
        let nets = &[
            "2001:8db8::/48",
            "2001:db8::/48",
            "2001:db8:1::/48",
            "2001:db8:3::/48",
            "9000::/16",
        ];
        let nets: Vec<_> = nets.iter().map(|net| Ipv6Network::parse(net).unwrap()).collect();

        let (supernet, range) = ipv6_binary_split(&nets).unwrap();
        assert_eq!(Ipv6Network::parse("2001:db8::/ffff:ffff:fffc::").unwrap(), supernet);
        assert_eq!(1..4, range);
    }

    // Small deterministic xorshift64 PRNG used only to build randomized
    // property-test fixtures; this crate stays zero-dependency, so no
    // proptest/rand strategies are used for these cases.
    struct Xorshift64(u64);

    impl Xorshift64 {
        fn new(seed: u64) -> Self {
            Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn next_u8(&mut self) -> u8 {
            self.next_u64() as u8
        }

        fn next_u16(&mut self) -> u16 {
            self.next_u64() as u16
        }

        // Returns a value in `0..bound`.
        fn below(&mut self, bound: usize) -> usize {
            (self.next_u64() as usize) % bound
        }
    }

    fn random_ipv4_network(rng: &mut Xorshift64) -> Ipv4Network {
        let (a, b, c, d) = (rng.next_u8(), rng.next_u8(), rng.next_u8(), rng.next_u8());

        if rng.below(2) == 0 {
            let prefix = rng.below(33);
            Ipv4Network::parse(&format!("{a}.{b}.{c}.{d}/{prefix}")).unwrap()
        } else {
            let (m0, m1, m2, m3) = (rng.next_u8(), rng.next_u8(), rng.next_u8(), rng.next_u8());
            Ipv4Network::parse(&format!("{a}.{b}.{c}.{d}/{m0}.{m1}.{m2}.{m3}")).unwrap()
        }
    }

    fn random_ipv6_network(rng: &mut Xorshift64) -> Ipv6Network {
        let addr: [u16; 8] = core::array::from_fn(|_| rng.next_u16());
        let addr = addr.iter().map(|seg| format!("{seg:x}")).collect::<Vec<_>>().join(":");

        if rng.below(2) == 0 {
            let prefix = rng.below(129);
            Ipv6Network::parse(&format!("{addr}/{prefix}")).unwrap()
        } else {
            let mask: [u16; 8] = core::array::from_fn(|_| rng.next_u16());
            let mask = mask.iter().map(|seg| format!("{seg:x}")).collect::<Vec<_>>().join(":");
            Ipv6Network::parse(&format!("{addr}/{mask}")).unwrap()
        }
    }

    // Compares the two implementations directly, bypassing `ip_binary_split`'s
    // size-based router entirely, so both are exercised across the full n
    // range regardless of `Word::SPLIT_THRESHOLD`.
    #[test]
    fn test_ipv4_binary_split_linear_matches_quadratic() {
        let mut rng = Xorshift64::new(0xC0FF_EE12_3456_789A);
        let mut cases = 0usize;

        for n in 3..=64usize {
            for _ in 0..20 {
                let mut nets: Vec<Ipv4Network> = (0..n).map(|_| random_ipv4_network(&mut rng)).collect();
                nets.sort();
                nets.dedup();
                if nets.len() < 3 {
                    continue;
                }
                cases += 1;

                let expected = ip_binary_split_quadratic(&nets);
                let actual = ip_binary_split_linear(&nets);
                assert_eq!(expected, actual, "mismatch for n = {n}, nets = {nets:?}");
            }
        }

        assert!(cases >= 1000, "expected at least 1000 cases, got {cases}");
    }

    #[test]
    fn test_ipv6_binary_split_linear_matches_quadratic() {
        let mut rng = Xorshift64::new(0xFEED_FACE_DEAD_BEEF);
        let mut cases = 0usize;

        for n in 3..=64usize {
            for _ in 0..20 {
                let mut nets: Vec<Ipv6Network> = (0..n).map(|_| random_ipv6_network(&mut rng)).collect();
                nets.sort();
                nets.dedup();
                if nets.len() < 3 {
                    continue;
                }
                cases += 1;

                let expected = ip_binary_split_quadratic(&nets);
                let actual = ip_binary_split_linear(&nets);
                assert_eq!(expected, actual, "mismatch for n = {n}, nets = {nets:?}");
            }
        }

        assert!(cases >= 1000, "expected at least 1000 cases, got {cases}");
    }

    // Consecutive /24 networks, deterministic and distinct without needing to
    // sort or dedup: `10.0.0.0/24`, `10.0.1.0/24`, `10.0.2.0/24`, ...
    fn ipv4_boundary_fixture(n: usize) -> Vec<Ipv4Network> {
        (0..n as u32)
            .map(|i| Ipv4Network::parse(&format!("10.0.{i}.0/24")).unwrap())
            .collect()
    }

    // Consecutive /124 networks, deterministic and distinct without needing to
    // sort or dedup: `2001:db8::/124`, `2001:db8::10/124`, `2001:db8::20/124`, ...
    fn ipv6_boundary_fixture(n: usize) -> Vec<Ipv6Network> {
        (0..n as u32)
            .map(|i| Ipv6Network::parse(&format!("2001:db8::{:x}/124", i * 16)).unwrap())
            .collect()
    }

    // `ipv4_binary_split` is `ip_binary_split`'s router; check it picks
    // whichever implementation is correct on both sides of the threshold, not
    // just above it.
    #[test]
    fn test_ipv4_binary_split_router_matches_at_threshold_boundary() {
        let threshold = <u32 as Word>::SPLIT_THRESHOLD;

        for n in [threshold - 1, threshold, threshold + 1] {
            let nets = ipv4_boundary_fixture(n);

            let quadratic = ip_binary_split_quadratic(&nets);
            let linear = ip_binary_split_linear(&nets);
            let routed = ipv4_binary_split(&nets);

            assert_eq!(quadratic, linear, "quadratic/linear mismatch at n = {n}");
            assert_eq!(routed, linear, "router mismatch at n = {n}");
        }
    }

    #[test]
    fn test_ipv6_binary_split_router_matches_at_threshold_boundary() {
        let threshold = <u128 as Word>::SPLIT_THRESHOLD;

        for n in [threshold - 1, threshold, threshold + 1] {
            let nets = ipv6_boundary_fixture(n);

            let quadratic = ip_binary_split_quadratic(&nets);
            let linear = ip_binary_split_linear(&nets);
            let routed = ipv6_binary_split(&nets);

            assert_eq!(quadratic, linear, "quadratic/linear mismatch at n = {n}");
            assert_eq!(routed, linear, "router mismatch at n = {n}");
        }
    }

    #[test]
    fn test_ipnetwork_parse_v4() {
        let expected = IpNetwork::V4(Ipv4Network::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(255, 255, 255, 0),
        ));

        assert_eq!(expected, IpNetwork::parse("192.168.1.0/24").unwrap());
    }

    #[test]
    fn test_ipnetwork_parse_v6() {
        let expected = IpNetwork::V6(Ipv6Network::new(
            Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0, 0, 0, 0),
        ));

        assert_eq!(expected, IpNetwork::parse("2a02:6b8:c00::/40").unwrap());
    }

    #[test]
    fn test_ipnetwork_parse_invalid() {
        assert_eq!(
            IpNetParseError::CidrOverflow(CidrOverflowError(33, 32)),
            IpNetwork::parse("192.168.1.0/33").unwrap_err(),
        );
    }

    #[test]
    fn test_ipnetwork_parse_invalid_v6() {
        assert_eq!(
            IpNetParseError::CidrOverflow(CidrOverflowError(129, 128)),
            IpNetwork::parse("2a02:6b8:c00::/129").unwrap_err(),
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
    fn ipv6_last_addr() {
        // Contiguous networks (broadcast-like addresses).
        let net = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0, 0),
        );
        assert_eq!(
            Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0xffff, 0xffff),
            net.last_addr()
        );

        let net = Ipv6Network::new(
            Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0, 0, 0, 0),
        );
        assert_eq!(
            Ipv6Addr::new(0x2a02, 0x6b8, 0x0cff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
            net.last_addr()
        );

        let net = Ipv6Network::new(
            Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0),
        );
        assert_eq!(
            Ipv6Addr::new(0x2a02, 0x6b8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
            net.last_addr()
        );

        // Single address networks.
        let net = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1),
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
        );
        assert_eq!(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1), net.last_addr());

        // Unspecified network.
        let net = Ipv6Network::UNSPECIFIED;
        assert_eq!(
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
            net.last_addr()
        );

        // Non-contiguous networks.
        let net = Ipv6Network::new(
            Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0xffff, 0xffff, 0, 0),
        );
        assert_eq!(
            Ipv6Addr::new(0x2a02, 0x6b8, 0x0cff, 0xffff, 0, 0x1234, 0xffff, 0xffff),
            net.last_addr()
        );

        // Edge cases.
        let net = Ipv6Network::new(
            Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0, 0, 0, 0),
        );
        assert_eq!(
            Ipv6Addr::new(0x2a02, 0x6b8, 0x0cff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
            net.last_addr()
        );

        let net = Ipv6Network::new(
            Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0),
        );
        assert_eq!(
            Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff),
            net.last_addr()
        );
    }

    #[test]
    fn ipnetwork_last_addr() {
        use core::net::IpAddr;

        // IPv4 networks.
        let net = IpNetwork::parse("192.168.1.0/24").unwrap();
        assert_eq!(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)), net.last_addr());

        let net = IpNetwork::parse("10.0.0.1").unwrap();
        assert_eq!(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), net.last_addr());

        let net = IpNetwork::parse("0.0.0.0/0").unwrap();
        assert_eq!(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), net.last_addr());

        // IPv6 networks.
        let net = IpNetwork::parse("2001:db8:1::/64").unwrap();
        assert_eq!(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0xffff, 0xffff, 0xffff, 0xffff)),
            net.last_addr()
        );

        let net = IpNetwork::parse("2a02:6b8::1").unwrap();
        assert_eq!(
            IpAddr::V6(Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0, 0x1)),
            net.last_addr()
        );

        let net = IpNetwork::parse("::/0").unwrap();
        assert_eq!(
            IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
            )),
            net.last_addr()
        );
    }

    #[test]
    fn ipv4_intersects_overlapping_contiguous() {
        let a = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
        assert!(a.intersects(&b));
        assert!(b.intersects(&a));
        assert!(!a.is_disjoint(&b));
        assert!(!b.is_disjoint(&a));
    }

    #[test]
    fn ipv4_intersects_disjoint_contiguous() {
        let a = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let b = Ipv4Network::parse("10.0.0.0/8").unwrap();
        assert!(!a.intersects(&b));
        assert!(!b.intersects(&a));
        assert!(a.is_disjoint(&b));
    }

    #[test]
    fn ipv4_intersects_self() {
        let a = Ipv4Network::parse("10.0.0.0/8").unwrap();
        assert!(a.intersects(&a));
        assert!(!a.is_disjoint(&a));
    }

    #[test]
    fn ipv4_intersects_non_contiguous() {
        let a = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(255, 0, 0, 255));
        let b = Ipv4Network::new(Ipv4Addr::new(10, 1, 0, 0), Ipv4Addr::new(255, 255, 0, 0));
        assert!(a.intersects(&b));
        assert!(b.intersects(&a));
    }

    #[test]
    fn ipv4_intersects_non_contiguous_disjoint() {
        let a = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(255, 0, 0, 255));
        let b = Ipv4Network::new(Ipv4Addr::new(11, 0, 0, 0), Ipv4Addr::new(255, 0, 0, 0));
        assert!(!a.intersects(&b));
        assert!(a.is_disjoint(&b));
    }

    #[test]
    fn ipv4_intersection_containment() {
        let a = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
        assert_eq!(Some(b), a.intersection(&b));
        assert_eq!(Some(b), b.intersection(&a));
    }

    #[test]
    fn ipv4_intersection_identical() {
        let a = Ipv4Network::parse("10.0.0.0/8").unwrap();
        assert_eq!(Some(a), a.intersection(&a));
    }

    #[test]
    fn ipv4_intersection_disjoint() {
        let a = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let b = Ipv4Network::parse("10.0.0.0/8").unwrap();
        assert_eq!(None, a.intersection(&b));
    }

    #[test]
    fn ipv4_intersection_non_contiguous() {
        let a = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(255, 0, 0, 255));
        let b = Ipv4Network::new(Ipv4Addr::new(10, 1, 0, 0), Ipv4Addr::new(255, 255, 0, 0));
        let expected = Ipv4Network::new(Ipv4Addr::new(10, 1, 0, 1), Ipv4Addr::new(255, 255, 0, 255));
        assert_eq!(Some(expected), a.intersection(&b));
        assert_eq!(Some(expected), b.intersection(&a));
    }

    #[test]
    fn ipv4_intersection_both_non_contiguous() {
        let a = Ipv4Network::new(Ipv4Addr::new(10, 0, 10, 0), Ipv4Addr::new(255, 0, 255, 0));
        let b = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(255, 0, 0, 255));
        let expected = Ipv4Network::new(Ipv4Addr::new(10, 0, 10, 5), Ipv4Addr::new(255, 0, 255, 255));
        assert_eq!(Some(expected), a.intersection(&b));
        assert_eq!(Some(expected), b.intersection(&a));
    }

    #[test]
    fn ipv4_intersection_with_unspecified() {
        let unspecified = Ipv4Network::UNSPECIFIED;
        let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
        assert_eq!(Some(b), unspecified.intersection(&b));
        assert_eq!(Some(b), b.intersection(&unspecified));
    }

    #[test]
    fn ipv4_intersection_hosts_same() {
        let a = Ipv4Network::parse("10.0.0.1/32").unwrap();
        assert_eq!(Some(a), a.intersection(&a));
    }

    #[test]
    fn ipv4_intersection_hosts_different() {
        let a = Ipv4Network::parse("10.0.0.1/32").unwrap();
        let b = Ipv4Network::parse("10.0.0.2/32").unwrap();
        assert_eq!(None, a.intersection(&b));
    }

    #[test]
    fn ipv4_intersection_alternating_masks() {
        // m1 = 0xaa55aa55, m2 = 0x55aa55aa => m1 & m2 = 0, always intersect.
        let a = Ipv4Network::new(Ipv4Addr::new(0xaa, 0, 0xaa, 0), Ipv4Addr::new(0xaa, 0x55, 0xaa, 0x55));
        let b = Ipv4Network::new(Ipv4Addr::new(0, 0xaa, 0, 0xaa), Ipv4Addr::new(0x55, 0xaa, 0x55, 0xaa));
        assert!(a.intersects(&b));

        // Result mask = 0xff, result is /32.
        let expected = Ipv4Network::new(
            Ipv4Addr::new(0xaa, 0xaa, 0xaa, 0xaa),
            Ipv4Addr::new(0xff, 0xff, 0xff, 0xff),
        );
        assert_eq!(Some(expected), a.intersection(&b));
    }

    #[test]
    fn ipv4_difference_disjoint() {
        let a = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let b = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let diff: Vec<_> = a.difference(&b).collect();
        assert_eq!(vec![a], diff);
    }

    #[test]
    fn ipv4_difference_subset() {
        let a = Ipv4Network::parse("192.168.1.0/24").unwrap();
        let b = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let diff: Vec<_> = a.difference(&b).collect();
        assert!(diff.is_empty());
    }

    #[test]
    fn ipv4_difference_same_network() {
        let a = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let diff: Vec<_> = a.difference(&a).collect();
        assert!(diff.is_empty());
    }

    #[test]
    fn ipv4_difference_superset() {
        // /16 minus /24 yields 8 networks (one per bit of difference in prefix).
        let a = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
        let diff: Vec<_> = a.difference(&b).collect();
        assert_eq!(8, diff.len());

        // Every part must be inside A and disjoint from B.
        for r in &diff {
            assert!(a.contains(r), "part {r} not in A");
            assert!(r.is_disjoint(&b), "part {r} intersects B");
        }

        // Parts must be pairwise disjoint.
        for i in 0..diff.len() {
            for j in (i + 1)..diff.len() {
                assert!(diff[i].is_disjoint(&diff[j]), "parts {i} and {j} overlap");
            }
        }
    }

    #[test]
    fn ipv4_difference_universe_minus_host() {
        let a = Ipv4Network::parse("0.0.0.0/0").unwrap();
        let b = Ipv4Network::parse("1.2.3.4/32").unwrap();
        let diff: Vec<_> = a.difference(&b).collect();
        assert_eq!(32, diff.len());
    }

    #[test]
    fn ipv4_difference_host_minus_universe() {
        let a = Ipv4Network::parse("1.2.3.4/32").unwrap();
        let b = Ipv4Network::parse("0.0.0.0/0").unwrap();
        let diff: Vec<_> = a.difference(&b).collect();
        assert!(diff.is_empty());
    }

    #[test]
    fn ipv4_difference_hosts_same() {
        let a = Ipv4Network::parse("1.2.3.4/32").unwrap();
        let b = Ipv4Network::parse("1.2.3.4/32").unwrap();
        let diff: Vec<_> = a.difference(&b).collect();
        assert!(diff.is_empty());
    }

    #[test]
    fn ipv4_difference_hosts_different() {
        let a = Ipv4Network::parse("1.2.3.4/32").unwrap();
        let b = Ipv4Network::parse("5.6.7.8/32").unwrap();
        let diff: Vec<_> = a.difference(&b).collect();
        assert_eq!(vec![a], diff);
    }

    #[test]
    fn ipv4_difference_verified_by_hand() {
        let a = Ipv4Network::UNSPECIFIED;
        let b = Ipv4Network::new(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(255, 255, 255, 255));
        let diff: Vec<_> = a.difference(&b).collect();
        assert_eq!(32, diff.len());

        // MSB-first iteration must produce contiguous CIDR masks.
        for r in &diff {
            assert!(r.is_contiguous(), "non-contiguous mask in {r}");
            assert!(a.contains(r), "part {r} not in A");
            assert!(r.is_disjoint(&b), "part {r} intersects B");
        }

        let expected = vec![
            Ipv4Network::parse("128.0.0.0/1").unwrap(),
            Ipv4Network::parse("64.0.0.0/2").unwrap(),
            Ipv4Network::parse("32.0.0.0/3").unwrap(),
            Ipv4Network::parse("16.0.0.0/4").unwrap(),
            Ipv4Network::parse("0.0.0.0/5").unwrap(),
            Ipv4Network::parse("12.0.0.0/6").unwrap(),
            Ipv4Network::parse("10.0.0.0/7").unwrap(),
            Ipv4Network::parse("9.0.0.0/8").unwrap(),
            Ipv4Network::parse("8.128.0.0/9").unwrap(),
            Ipv4Network::parse("8.64.0.0/10").unwrap(),
            Ipv4Network::parse("8.32.0.0/11").unwrap(),
            Ipv4Network::parse("8.16.0.0/12").unwrap(),
            Ipv4Network::parse("8.0.0.0/13").unwrap(),
            Ipv4Network::parse("8.12.0.0/14").unwrap(),
            Ipv4Network::parse("8.10.0.0/15").unwrap(),
            Ipv4Network::parse("8.9.0.0/16").unwrap(),
            Ipv4Network::parse("8.8.128.0/17").unwrap(),
            Ipv4Network::parse("8.8.64.0/18").unwrap(),
            Ipv4Network::parse("8.8.32.0/19").unwrap(),
            Ipv4Network::parse("8.8.16.0/20").unwrap(),
            Ipv4Network::parse("8.8.0.0/21").unwrap(),
            Ipv4Network::parse("8.8.12.0/22").unwrap(),
            Ipv4Network::parse("8.8.10.0/23").unwrap(),
            Ipv4Network::parse("8.8.9.0/24").unwrap(),
            Ipv4Network::parse("8.8.8.128/25").unwrap(),
            Ipv4Network::parse("8.8.8.64/26").unwrap(),
            Ipv4Network::parse("8.8.8.32/27").unwrap(),
            Ipv4Network::parse("8.8.8.16/28").unwrap(),
            Ipv4Network::parse("8.8.8.0/29").unwrap(),
            Ipv4Network::parse("8.8.8.12/30").unwrap(),
            Ipv4Network::parse("8.8.8.10/31").unwrap(),
            Ipv4Network::parse("8.8.8.9/32").unwrap(),
        ];
        assert_eq!(expected, diff);
    }

    #[test]
    fn ipv4_difference_non_contiguous() {
        let a = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 0, 0, 0));
        let b = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(255, 0, 0, 255));

        let diff: Vec<_> = a.difference(&b).collect();
        assert_eq!(diff.len(), 8);

        for r in &diff {
            assert!(a.contains(r), "part {r} not in A");
            assert!(r.is_disjoint(&b), "part {r} intersects B");
        }

        let expected = vec![
            Ipv4Network::parse("10.0.0.128/255.0.0.128").unwrap(),
            Ipv4Network::parse("10.0.0.64/255.0.0.192").unwrap(),
            Ipv4Network::parse("10.0.0.32/255.0.0.224").unwrap(),
            Ipv4Network::parse("10.0.0.16/255.0.0.240").unwrap(),
            Ipv4Network::parse("10.0.0.8/255.0.0.248").unwrap(),
            Ipv4Network::parse("10.0.0.4/255.0.0.252").unwrap(),
            Ipv4Network::parse("10.0.0.2/255.0.0.254").unwrap(),
            Ipv4Network::parse("10.0.0.0/255.0.0.255").unwrap(),
        ];
        assert_eq!(expected, diff);
    }

    #[test]
    fn ipv4_difference_exact_size() {
        let a = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
        let mut diff = a.difference(&b);
        assert_eq!(8, diff.len());
        diff.next();
        assert_eq!(7, diff.len());
        diff.next();
        assert_eq!(6, diff.len());
        diff.next();
        assert_eq!(5, diff.len());
        diff.next();
        assert_eq!(4, diff.len());
        diff.next();
        assert_eq!(3, diff.len());
        diff.next();
        assert_eq!(2, diff.len());
        diff.next();
        assert_eq!(1, diff.len());
        diff.next();
        assert_eq!(0, diff.len());
        assert_eq!(None, diff.next());
    }

    #[test]
    fn ipv6_intersects_overlapping_contiguous() {
        let a = Ipv6Network::parse("2001:db8::/32").unwrap();
        let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        assert!(a.intersects(&b));
        assert!(b.intersects(&a));
        assert!(!a.is_disjoint(&b));
        assert!(!b.is_disjoint(&a));
    }

    #[test]
    fn ipv6_intersects_disjoint_contiguous() {
        let a = Ipv6Network::parse("2001:db8::/32").unwrap();
        let b = Ipv6Network::parse("fe80::/10").unwrap();
        assert!(!a.intersects(&b));
        assert!(!b.intersects(&a));
        assert!(a.is_disjoint(&b));
    }

    #[test]
    fn ipv6_intersects_self() {
        let a = Ipv6Network::parse("2001:db8::/32").unwrap();
        assert!(a.intersects(&a));
        assert!(!a.is_disjoint(&a));
    }

    #[test]
    fn ipv6_intersects_non_contiguous() {
        let a = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xffff, 0, 0, 0, 0, 0, 0, 0xffff),
        );
        let b = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0),
        );
        assert!(a.intersects(&b));
        assert!(b.intersects(&a));
    }

    #[test]
    fn ipv6_intersects_non_contiguous_disjoint() {
        let a = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xffff, 0, 0, 0, 0, 0, 0, 0xffff),
        );
        let b = Ipv6Network::new(
            Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0, 0, 0, 0, 0, 0, 0),
        );
        assert!(!a.intersects(&b));
        assert!(a.is_disjoint(&b));
    }

    #[test]
    fn ipv6_intersection_containment() {
        let a = Ipv6Network::parse("2001:db8::/32").unwrap();
        let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        assert_eq!(Some(b), a.intersection(&b));
        assert_eq!(Some(b), b.intersection(&a));
    }

    #[test]
    fn ipv6_intersection_identical() {
        let a = Ipv6Network::parse("2001:db8::/32").unwrap();
        assert_eq!(Some(a), a.intersection(&a));
    }

    #[test]
    fn ipv6_intersection_disjoint() {
        let a = Ipv6Network::parse("2001:db8::/32").unwrap();
        let b = Ipv6Network::parse("fe80::/10").unwrap();
        assert_eq!(None, a.intersection(&b));
    }

    #[test]
    fn ipv6_intersection_non_contiguous() {
        let a = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xffff, 0, 0, 0, 0, 0, 0, 0xffff),
        );
        let b = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0),
        );
        let expected = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0xffff),
        );
        assert_eq!(Some(expected), a.intersection(&b));
        assert_eq!(Some(expected), b.intersection(&a));
    }

    #[test]
    fn ipv6_intersection_both_non_contiguous() {
        let a = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0, 0x000a, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0, 0xffff, 0, 0, 0, 0, 0),
        );
        let b = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 5),
            Ipv6Addr::new(0xffff, 0, 0, 0, 0, 0, 0, 0xffff),
        );
        let expected = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0, 0x000a, 0, 0, 0, 0, 5),
            Ipv6Addr::new(0xffff, 0, 0xffff, 0, 0, 0, 0, 0xffff),
        );
        assert_eq!(Some(expected), a.intersection(&b));
        assert_eq!(Some(expected), b.intersection(&a));
    }

    #[test]
    fn ipv6_intersection_with_unspecified() {
        let unspecified = Ipv6Network::UNSPECIFIED;
        let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        assert_eq!(Some(b), unspecified.intersection(&b));
        assert_eq!(Some(b), b.intersection(&unspecified));
    }

    #[test]
    fn ipv6_intersection_hosts_same() {
        let a = Ipv6Network::parse("::1/128").unwrap();
        assert_eq!(Some(a), a.intersection(&a));
    }

    #[test]
    fn ipv6_intersection_hosts_different() {
        let a = Ipv6Network::parse("::1/128").unwrap();
        let b = Ipv6Network::parse("::2/128").unwrap();
        assert_eq!(None, a.intersection(&b));
    }

    #[test]
    fn ipv6_intersection_alternating_masks() {
        // m1 and m2 have no overlapping bits => always intersect, result is /128.
        let a = Ipv6Network::new(
            Ipv6Addr::new(0xaa00, 0, 0xaa00, 0, 0xaa00, 0, 0xaa00, 0),
            Ipv6Addr::new(0xff00, 0x00ff, 0xff00, 0x00ff, 0xff00, 0x00ff, 0xff00, 0x00ff),
        );
        let b = Ipv6Network::new(
            Ipv6Addr::new(0x00bb, 0, 0x00bb, 0, 0x00bb, 0, 0x00bb, 0),
            Ipv6Addr::new(0x00ff, 0xff00, 0x00ff, 0xff00, 0x00ff, 0xff00, 0x00ff, 0xff00),
        );
        assert!(a.intersects(&b));

        let expected = Ipv6Network::new(
            Ipv6Addr::new(0xaabb, 0, 0xaabb, 0, 0xaabb, 0, 0xaabb, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
        );
        assert_eq!(Some(expected), a.intersection(&b));
    }

    #[test]
    fn ipv4_merge_identical() {
        let a = Ipv4Network::parse("192.168.1.0/24").unwrap();
        assert_eq!(Some(a), a.merge(&a));
    }

    #[test]
    fn ipv4_merge_adjacent_contiguous() {
        // 192.168.0.0/24 + 192.168.1.0/24 = 192.168.0.0/23
        let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
        let expected = Ipv4Network::parse("192.168.0.0/23").unwrap();
        assert_eq!(Some(expected), a.merge(&b));
        assert_eq!(Some(expected), b.merge(&a));
    }

    #[test]
    fn ipv4_merge_adjacent_non_contiguous() {
        let a = Ipv4Network::parse("192.168.0.0/255.255.255.0").unwrap();
        let b = Ipv4Network::parse("192.168.2.0/255.255.255.0").unwrap();
        let expected = Ipv4Network::parse("192.168.0.0/255.255.253.0").unwrap();
        assert_eq!(Some(expected), a.merge(&b));
        assert_eq!(Some(expected), b.merge(&a));
    }

    #[test]
    fn ipv4_merge_non_adjacent() {
        // 192.168.0.0/24 + 192.168.3.0/24: d = 0x300 (bits 8 and 9 set) -> None
        let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let b = Ipv4Network::parse("192.168.3.0/24").unwrap();
        assert_eq!(None, a.merge(&b));
        assert_eq!(None, b.merge(&a));
    }

    #[test]
    fn ipv4_merge_containment() {
        // 10.0.0.0/8 contains 10.1.0.0/16
        let a = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let b = Ipv4Network::parse("10.1.0.0/16").unwrap();
        assert_eq!(Some(a), a.merge(&b));
        assert_eq!(Some(a), b.merge(&a));
    }

    #[test]
    fn ipv4_merge_different_masks_no_containment() {
        // Different masks and neither contains the other.
        let a = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let b = Ipv4Network::parse("172.16.0.0/16").unwrap();
        assert_eq!(None, a.merge(&b));
        assert_eq!(None, b.merge(&a));
    }

    #[test]
    fn ipv4_merge_non_contiguous_masks() {
        let a = Ipv4Network::parse("10.0.0.1/255.255.0.255").unwrap();
        let b = Ipv4Network::parse("10.1.0.1/255.255.0.255").unwrap();
        let expected = Ipv4Network::parse("10.0.0.1/255.254.0.255").unwrap();
        assert_eq!(Some(expected), a.merge(&b));
        assert_eq!(Some(expected), b.merge(&a));
    }

    #[test]
    fn ipv6_merge_adjacent() {
        // 2001:db8::/48 + 2001:db8:1::/48 = 2001:db8::/47
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        let expected = Ipv6Network::parse("2001:db8::/47").unwrap();
        assert_eq!(Some(expected), a.merge(&b));
        assert_eq!(Some(expected), b.merge(&a));
    }

    #[test]
    fn ipv6_merge_containment() {
        // 2001:db8::/32 contains 2001:db8:1::/48
        let a = Ipv6Network::parse("2001:db8::/32").unwrap();
        let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        assert_eq!(Some(a), a.merge(&b));
        assert_eq!(Some(a), b.merge(&a));
    }

    #[test]
    fn ipv6_merge_non_contiguous() {
        // Non-contiguous mask: ffff:ff00::ffff, addresses differ by 1 bit in the mask.
        let a = Ipv6Network::parse("2001::1/ffff:ff00::ffff").unwrap();
        let b = Ipv6Network::parse("2001:100::1/ffff:ff00::ffff").unwrap();
        let expected = Ipv6Network::parse("2001::1/ffff:fe00::ffff").unwrap();
        assert_eq!(Some(expected), a.merge(&b));
        assert_eq!(Some(expected), b.merge(&a));
    }

    #[test]
    fn ipv6_merge_non_contiguous_none() {
        // Non-contiguous mask, addresses differ by 2 bits -> None.
        let a = Ipv6Network::parse("2001::1/ffff:ff00::ffff").unwrap();
        let b = Ipv6Network::parse("2001:300::1/ffff:ff00::ffff").unwrap();
        assert_eq!(None, a.merge(&b));
    }

    #[test]
    fn ipv4_is_adjacent_contiguous() {
        let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
        assert!(a.is_adjacent(&b));
        assert!(b.is_adjacent(&a));
    }

    #[test]
    fn ipv4_is_adjacent_non_contiguous() {
        let a = Ipv4Network::parse("10.0.0.1/255.255.0.255").unwrap();
        let b = Ipv4Network::parse("10.1.0.1/255.255.0.255").unwrap();
        assert!(a.is_adjacent(&b));
        assert!(b.is_adjacent(&a));
    }

    #[test]
    fn ipv4_is_adjacent_identical() {
        let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
        assert!(!a.is_adjacent(&a));
    }

    #[test]
    fn ipv4_is_adjacent_different_masks() {
        let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let b = Ipv4Network::parse("192.168.0.0/16").unwrap();
        assert!(!a.is_adjacent(&b));
    }

    #[test]
    fn ipv4_is_adjacent_non_adjacent_same_mask() {
        let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let b = Ipv4Network::parse("192.168.3.0/24").unwrap();
        assert!(!a.is_adjacent(&b));
    }

    #[test]
    fn ipv6_is_adjacent_contiguous() {
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        assert!(a.is_adjacent(&b));
        assert!(b.is_adjacent(&a));
    }

    #[test]
    fn ipv6_is_adjacent_non_contiguous() {
        let a = Ipv6Network::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
        let b = Ipv6Network::parse("2a02:6b8:c00::1235:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
        assert!(a.is_adjacent(&b));
        assert!(b.is_adjacent(&a));
    }

    #[test]
    fn ipv6_is_adjacent_identical() {
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        assert!(!a.is_adjacent(&a));
    }

    #[test]
    fn ipv6_is_adjacent_different_masks() {
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        let b = Ipv6Network::parse("2001:db8::/32").unwrap();
        assert!(!a.is_adjacent(&b));
    }

    #[test]
    fn ipv6_is_adjacent_non_adjacent_same_mask() {
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        let b = Ipv6Network::parse("2001:db8:5::/48").unwrap();
        assert!(!a.is_adjacent(&b));
    }

    #[test]
    fn ip_is_adjacent_mixed_families() {
        let v4 = IpNetwork::parse("10.0.0.0/8").unwrap();
        let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
        assert!(!v4.is_adjacent(&v6));
    }

    #[test]
    fn ipv4_aggregate_empty() {
        let result = ipv4_aggregate(&mut []);
        assert!(result.is_empty());
    }

    #[test]
    fn ipv4_aggregate_single() {
        let net = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let mut nets = [net];
        let result = ipv4_aggregate(&mut nets);
        assert_eq!(result, &[net]);
    }

    #[test]
    fn ipv4_aggregate_duplicates() {
        let net = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let mut nets = [net, net, net];
        let result = ipv4_aggregate(&mut nets);
        assert_eq!(result, &[net]);
    }

    #[test]
    fn ipv4_aggregate_containment() {
        let mut nets = [
            Ipv4Network::parse("10.0.0.0/8").unwrap(),
            Ipv4Network::parse("10.1.0.0/16").unwrap(),
            Ipv4Network::parse("10.1.1.0/24").unwrap(),
        ];
        let result = ipv4_aggregate(&mut nets);
        assert_eq!(result, &[Ipv4Network::parse("10.0.0.0/8").unwrap()]);
    }

    #[test]
    fn ipv4_aggregate_simple_merge() {
        let mut nets = [
            Ipv4Network::parse("192.168.0.0/24").unwrap(),
            Ipv4Network::parse("192.168.1.0/24").unwrap(),
        ];
        let result = ipv4_aggregate(&mut nets);
        assert_eq!(result, &[Ipv4Network::parse("192.168.0.0/23").unwrap()]);
    }

    #[test]
    fn ipv4_aggregate_multi_level_merge() {
        let mut nets = [
            Ipv4Network::parse("192.168.0.0/24").unwrap(),
            Ipv4Network::parse("192.168.1.0/24").unwrap(),
            Ipv4Network::parse("192.168.2.0/24").unwrap(),
            Ipv4Network::parse("192.168.3.0/24").unwrap(),
        ];
        let result = ipv4_aggregate(&mut nets);
        assert_eq!(result, &[Ipv4Network::parse("192.168.0.0/22").unwrap()]);
    }

    #[test]
    fn ipv4_aggregate_non_adjacent() {
        let mut nets = [
            Ipv4Network::parse("192.168.0.0/24").unwrap(),
            Ipv4Network::parse("192.168.3.0/24").unwrap(),
        ];
        let result = ipv4_aggregate(&mut nets);
        assert_eq!(
            result,
            &[
                Ipv4Network::parse("192.168.0.0/24").unwrap(),
                Ipv4Network::parse("192.168.3.0/24").unwrap(),
            ]
        );
    }

    #[test]
    fn ipv4_aggregate_mixed_containment_and_merge() {
        let mut nets = [
            Ipv4Network::parse("10.0.0.0/8").unwrap(),
            Ipv4Network::parse("10.1.0.0/16").unwrap(),
            Ipv4Network::parse("192.168.0.0/24").unwrap(),
            Ipv4Network::parse("192.168.1.0/24").unwrap(),
        ];
        let result = ipv4_aggregate(&mut nets);
        assert_eq!(
            result,
            &[
                Ipv4Network::parse("10.0.0.0/8").unwrap(),
                Ipv4Network::parse("192.168.0.0/23").unwrap(),
            ]
        );
    }

    #[test]
    fn ipv4_aggregate_already_minimal() {
        let mut nets = [
            Ipv4Network::parse("10.0.0.0/8").unwrap(),
            Ipv4Network::parse("172.16.0.0/12").unwrap(),
            Ipv4Network::parse("192.168.0.0/16").unwrap(),
        ];
        let result = ipv4_aggregate(&mut nets);
        assert_eq!(
            result,
            &[
                Ipv4Network::parse("10.0.0.0/8").unwrap(),
                Ipv4Network::parse("172.16.0.0/12").unwrap(),
                Ipv4Network::parse("192.168.0.0/16").unwrap(),
            ]
        );
    }

    #[test]
    fn ipv4_aggregate_non_contiguous_containment() {
        // Non-contiguous mask containment: K' contains N but K (between them
        // in sort order) does not.
        let mut nets = [
            Ipv4Network::parse("10.0.0.1/255.0.0.255").unwrap(),   // K'
            Ipv4Network::parse("10.1.0.0/255.255.0.0").unwrap(),   // K
            Ipv4Network::parse("10.2.0.1/255.255.0.255").unwrap(), // N (contained in K')
        ];
        let result = ipv4_aggregate(&mut nets);
        assert_eq!(
            result,
            &[
                Ipv4Network::parse("10.0.0.1/255.0.0.255").unwrap(),
                Ipv4Network::parse("10.1.0.0/255.255.0.0").unwrap(),
            ]
        );
    }

    #[test]
    fn ipv4_aggregate_non_contiguous_merge_breaks_sort_order() {
        // After merging B+C the result (0, 0x80000000) sorts before A (0, 0x80000001)
        // and contains A.  Without re-sort the containment phase misses this.
        let mut nets = [
            Ipv4Network::from_bits(0, 0x80000001), // A
            Ipv4Network::from_bits(0, 0x80000002), // B
            Ipv4Network::from_bits(2, 0x80000002), // C
        ];
        let result = ipv4_aggregate(&mut nets);
        assert_eq!(result, &[Ipv4Network::from_bits(0, 0x80000000)]);
    }

    #[test]
    fn ipv4_aggregate_non_contiguous_merge() {
        // Non-contiguous mask merge: same mask, addresses differ by one bit.
        let mut nets = [
            Ipv4Network::parse("10.0.0.1/255.0.0.255").unwrap(),
            Ipv4Network::parse("10.0.0.0/255.0.0.255").unwrap(),
        ];
        let result = ipv4_aggregate(&mut nets);
        assert_eq!(result, &[Ipv4Network::parse("10.0.0.0/255.0.0.254").unwrap()]);
    }

    #[test]
    fn ipv4_aggregate_full_octet() {
        // 256 /24s covering 10.0.0.0/16.
        let mut nets: Vec<_> = (0..=255u32)
            .map(|i| Ipv4Network::from_bits((10 << 24) | (0 << 16) | (i << 8), 0xFFFFFF00))
            .collect();
        let result = ipv4_aggregate(&mut nets);
        assert_eq!(result, &[Ipv4Network::parse("10.0.0.0/16").unwrap()]);
    }

    #[test]
    fn ipv6_aggregate_simple_merge() {
        let mut nets = [
            Ipv6Network::parse("2001:db8::/48").unwrap(),
            Ipv6Network::parse("2001:db8:1::/48").unwrap(),
        ];
        let result = ipv6_aggregate(&mut nets);
        assert_eq!(result, &[Ipv6Network::parse("2001:db8::/47").unwrap()]);
    }

    #[test]
    fn ipv6_aggregate_containment_and_merge() {
        let mut nets = [
            Ipv6Network::parse("fe80::/10").unwrap(),
            Ipv6Network::parse("fe80::/64").unwrap(),
            Ipv6Network::parse("2001:db8::/48").unwrap(),
            Ipv6Network::parse("2001:db8:1::/48").unwrap(),
        ];
        let result = ipv6_aggregate(&mut nets);
        assert_eq!(
            result,
            &[
                Ipv6Network::parse("2001:db8::/47").unwrap(),
                Ipv6Network::parse("fe80::/10").unwrap(),
            ]
        );
    }

    #[test]
    fn ipnetwork_addr_v4() {
        let net = IpNetwork::parse("192.168.1.0/24").unwrap();
        assert_eq!(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), net.addr());
    }

    #[test]
    fn ipnetwork_addr_v6() {
        let net = IpNetwork::parse("2001:db8::/32").unwrap();
        assert_eq!(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)), net.addr());
    }

    #[test]
    fn ipnetwork_mask_v4() {
        let net = IpNetwork::parse("10.0.0.0/8").unwrap();
        assert_eq!(IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0)), net.mask());
    }

    #[test]
    fn ipnetwork_mask_v6() {
        let net = IpNetwork::parse("2001:db8::/32").unwrap();
        assert_eq!(IpAddr::V6(Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0)), net.mask());
    }

    #[test]
    fn ipnetwork_mask_non_contiguous_v4() {
        let net = IpNetwork::parse("192.168.0.1/255.255.0.255").unwrap();
        assert_eq!(IpAddr::V4(Ipv4Addr::new(255, 255, 0, 255)), net.mask());
    }

    #[test]
    fn ipnetwork_mask_non_contiguous_v6() {
        let net = IpNetwork::parse("2001:db8::1/ffff:ffff::ffff:ffff:0:0").unwrap();
        assert_eq!(
            IpAddr::V6(Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0xffff, 0xffff, 0, 0)),
            net.mask()
        );
    }

    #[test]
    fn ipnetwork_contains_v4() {
        let a = IpNetwork::parse("192.168.0.0/16").unwrap();
        let b = IpNetwork::parse("192.168.1.0/24").unwrap();
        assert!(a.contains(&b));
        assert!(!b.contains(&a));
    }

    #[test]
    fn ipnetwork_contains_v6() {
        let a = IpNetwork::parse("2001:db8::/32").unwrap();
        let b = IpNetwork::parse("2001:db8:1::/48").unwrap();
        assert!(a.contains(&b));
        assert!(!b.contains(&a));
    }

    #[test]
    fn ipnetwork_contains_different_families() {
        let v4 = IpNetwork::parse("10.0.0.0/8").unwrap();
        let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
        assert!(!v4.contains(&v6));
        assert!(!v6.contains(&v4));
    }

    #[test]
    fn ipnetwork_contains_non_contiguous_v4() {
        let a = IpNetwork::parse("10.0.0.0/255.0.0.0").unwrap();
        let b = IpNetwork::parse("10.0.0.1/255.0.0.255").unwrap();
        assert!(a.contains(&b));
        assert!(!b.contains(&a));
    }

    #[test]
    fn ipnetwork_contains_non_contiguous_v6() {
        let a = IpNetwork::parse("2001:db8::/ffff:ffff::").unwrap();
        let b = IpNetwork::parse("2001:db8::1/ffff:ffff::ffff").unwrap();
        assert!(a.contains(&b));
        assert!(!b.contains(&a));
    }

    #[test]
    fn ipnetwork_to_contiguous_v4() {
        let net = IpNetwork::parse("192.168.0.1/255.255.0.255").unwrap();
        let expected = IpNetwork::parse("192.168.0.0/16").unwrap();
        assert_eq!(expected, net.to_contiguous());
    }

    #[test]
    fn ipnetwork_to_contiguous_v6() {
        let net = IpNetwork::parse("2001:db8::1/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
        let expected = IpNetwork::parse("2001:db8::/40").unwrap();
        assert_eq!(expected, net.to_contiguous());
    }

    #[test]
    fn ipnetwork_to_contiguous_already_contiguous_v4() {
        let net = IpNetwork::parse("10.0.0.0/8").unwrap();
        assert_eq!(net, net.to_contiguous());
    }

    #[test]
    fn ipnetwork_to_contiguous_already_contiguous_v6() {
        let net = IpNetwork::parse("2001:db8::/32").unwrap();
        assert_eq!(net, net.to_contiguous());
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

    fn arb_ipv4_network() -> impl Strategy<Value = Ipv4Network> {
        (any::<u32>(), any::<u32>()).prop_map(|(a, m)| Ipv4Network::from_bits(a, m))
    }

    fn arb_ipv6_network() -> impl Strategy<Value = Ipv6Network> {
        (any::<u128>(), any::<u128>()).prop_map(|(a, m)| Ipv6Network::from_bits(a, m))
    }

    proptest! {
        #[test]
        fn prop_ipv4_intersects_is_not_disjoint(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            prop_assert_eq!(a.intersects(&b), !a.is_disjoint(&b));
        }

        #[test]
        fn prop_ipv4_intersection_commutativity(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            prop_assert_eq!(a.intersection(&b), b.intersection(&a));
        }

        #[test]
        fn prop_ipv4_contains_implies_intersection_eq_inner(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            if a.contains(&b) {
                prop_assert_eq!(a.intersection(&b), Some(b));
            }
        }

        #[test]
        fn prop_ipv4_intersection_subset_of_both(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            if let Some(c) = a.intersection(&b) {
                prop_assert!(a.contains(&c), "intersection not contained in a: a={a}, b={b}, c={c}");
                prop_assert!(b.contains(&c), "intersection not contained in b: a={a}, b={b}, c={c}");
            }
        }

        #[test]
        fn prop_ipv4_self_intersection_is_self(
            a in arb_ipv4_network(),
        ) {
            prop_assert_eq!(a.intersection(&a), Some(a));
        }

        #[test]
        fn prop_ipv4_intersection_is_normalized(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            if let Some(c) = a.intersection(&b) {
                let (addr, mask) = c.to_bits();
                prop_assert_eq!(addr & mask, addr, "intersection not normalized: a={}, b={}, c={}", a, b, c);
            }
        }

        #[test]
        fn prop_ipv4_intersection_membership_brute_force(
            a_addr in 0u32..=255,
            a_mask in 0u32..=255,
            b_addr in 0u32..=255,
            b_mask in 0u32..=255,
        ) {
            // Use 8-bit networks (top byte) to exhaustively verify membership.
            let a = Ipv4Network::from_bits((a_addr & a_mask) << 24, a_mask << 24);
            let b = Ipv4Network::from_bits((b_addr & b_mask) << 24, b_mask << 24);
            let result = a.intersection(&b);

            let (a_a, a_m) = a.to_bits();
            let (b_a, b_m) = b.to_bits();

            for x in 0u32..=255 {
                let xaddr = x << 24;
                let in_a = (xaddr & a_m) == a_a;
                let in_b = (xaddr & b_m) == b_a;
                let in_result = match result {
                    Some(r) => {
                        let (r_a, r_m) = r.to_bits();
                        (xaddr & r_m) == r_a
                    }
                    None => false,
                };
                prop_assert_eq!(
                    in_a && in_b,
                    in_result,
                    "x={}, a={}, b={}, result={:?}", x, a, b, result
                );
            }
        }

        #[test]
        fn prop_ipv4_merge_commutativity(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            prop_assert_eq!(a.merge(&b), b.merge(&a));
        }

        #[test]
        fn prop_ipv4_merge_self_is_self(
            a in arb_ipv4_network(),
        ) {
            prop_assert_eq!(a.merge(&a), Some(a));
        }

        #[test]
        fn prop_ipv4_merge_result_contains_both(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            if let Some(c) = a.merge(&b) {
                prop_assert!(c.contains(&a), "merge result {c} must contain {a}");
                prop_assert!(c.contains(&b), "merge result {c} must contain {b}");
            }
        }

        #[test]
        fn prop_ipv4_merge_is_normalized(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            if let Some(c) = a.merge(&b) {
                let (addr, mask) = c.to_bits();
                prop_assert_eq!(addr & mask, addr, "merge result not normalized: a={}, b={}, c={}", a, b, c);
            }
        }

        #[test]
        fn prop_ipv4_merge_equals_supernet_when_some(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            if let Some(c) = a.merge(&b) {
                let supernet = a.supernet_for(&[b]);
                prop_assert_eq!(c, supernet, "merge must equal supernet_for when Some: a={}, b={}", a, b);
            }
        }

        #[test]
        fn prop_ipv4_merge_membership_brute_force(
            a_addr in 0u32..=255,
            a_mask in 0u32..=255,
            b_addr in 0u32..=255,
            b_mask in 0u32..=255,
        ) {
            let a = Ipv4Network::from_bits((a_addr & a_mask) << 24, a_mask << 24);
            let b = Ipv4Network::from_bits((b_addr & b_mask) << 24, b_mask << 24);
            let result = a.merge(&b);

            let (a_a, a_m) = a.to_bits();
            let (b_a, b_m) = b.to_bits();

            for x in 0u32..=255 {
                let xaddr = x << 24;
                let in_a = (xaddr & a_m) == a_a;
                let in_b = (xaddr & b_m) == b_a;
                let in_result = match result {
                    Some(r) => {
                        let (r_a, r_m) = r.to_bits();
                        (xaddr & r_m) == r_a
                    }
                    None => false,
                };

                if in_a || in_b {
                    if let Some(..) = result {
                        prop_assert!(
                            in_result,
                            "x={x} in A∪B but not in merge result: a={a}, b={b}, result={result:?}"
                        );
                    }
                }
                if in_result {
                    prop_assert!(
                        in_a || in_b,
                        "x={x} in merge result but not in A∪B: a={a}, b={b}, result={result:?}"
                    );
                }
            }
        }

        #[test]
        fn prop_ipv4_is_adjacent_commutativity(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            prop_assert_eq!(a.is_adjacent(&b), b.is_adjacent(&a));
        }

        #[test]
        fn prop_ipv4_adjacent_implies_merge_some(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            if a.is_adjacent(&b) {
                prop_assert!(a.merge(&b).is_some(), "adjacent but merge returned None: a={a}, b={b}");
            }
        }

        #[test]
        fn prop_ipv4_same_mask_not_adjacent_not_identical_implies_merge_none(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            let (_, m1) = a.to_bits();
            let (_, m2) = b.to_bits();
            if m1 == m2 && !a.is_adjacent(&b) && a != b {
                prop_assert_eq!(a.merge(&b), None, "same mask, not adjacent, not identical, but merge returned Some: a={}, b={}", a, b);
            }
        }

        #[test]
        fn prop_ipv6_intersects_is_not_disjoint(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            prop_assert_eq!(a.intersects(&b), !a.is_disjoint(&b));
        }

        #[test]
        fn prop_ipv6_intersection_commutativity(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            prop_assert_eq!(a.intersection(&b), b.intersection(&a));
        }

        #[test]
        fn prop_ipv6_contains_implies_intersection_eq_inner(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            if a.contains(&b) {
                prop_assert_eq!(a.intersection(&b), Some(b));
            }
        }

        #[test]
        fn prop_ipv6_intersection_subset_of_both(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            if let Some(c) = a.intersection(&b) {
                prop_assert!(a.contains(&c), "intersection not contained in a: a={a}, b={b}, c={c}");
                prop_assert!(b.contains(&c), "intersection not contained in b: a={a}, b={b}, c={c}");
            }
        }

        #[test]
        fn prop_ipv6_self_intersection_is_self(
            a in arb_ipv6_network(),
        ) {
            prop_assert_eq!(a.intersection(&a), Some(a));
        }

        #[test]
        fn prop_ipv6_intersection_is_normalized(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            if let Some(c) = a.intersection(&b) {
                let (addr, mask) = c.to_bits();
                prop_assert_eq!(addr & mask, addr, "intersection not normalized: a={}, b={}, c={}", a, b, c);
            }
        }

        #[test]
        fn prop_ipv6_intersection_membership_brute_force(
            a_addr in 0u128..=255,
            a_mask in 0u128..=255,
            b_addr in 0u128..=255,
            b_mask in 0u128..=255,
        ) {
            // Use 8-bit networks (top byte) to exhaustively verify membership.
            let a = Ipv6Network::from_bits((a_addr & a_mask) << 120, a_mask << 120);
            let b = Ipv6Network::from_bits((b_addr & b_mask) << 120, b_mask << 120);
            let result = a.intersection(&b);

            let (a_a, a_m) = a.to_bits();
            let (b_a, b_m) = b.to_bits();

            for x in 0u128..=255 {
                let xaddr = x << 120;
                let in_a = (xaddr & a_m) == a_a;
                let in_b = (xaddr & b_m) == b_a;
                let in_result = match result {
                    Some(r) => {
                        let (r_a, r_m) = r.to_bits();
                        (xaddr & r_m) == r_a
                    }
                    None => false,
                };
                prop_assert_eq!(
                    in_a && in_b,
                    in_result,
                    "x={}, a={}, b={}, result={:?}", x, a, b, result
                );
            }
        }

        #[test]
        fn prop_ipv4_difference_parts_in_source(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            for r in a.difference(&b) {
                prop_assert!(a.contains(&r), "part {r} not in a={a}");
            }
        }

        #[test]
        fn prop_ipv4_difference_parts_disjoint_from_other(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            for r in a.difference(&b) {
                prop_assert!(b.is_disjoint(&r), "part {r} intersects b={b}");
            }
        }

        #[test]
        fn prop_ipv4_difference_pairwise_disjoint(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            let parts: Vec<_> = a.difference(&b).collect();
            for i in 0..parts.len() {
                for j in (i + 1)..parts.len() {
                    prop_assert!(
                        parts[i].is_disjoint(&parts[j]),
                        "parts {i} and {j} overlap: {} vs {}", parts[i], parts[j]
                    );
                }
            }
        }

        #[test]
        fn prop_ipv4_difference_self_is_empty(
            a in arb_ipv4_network(),
        ) {
            prop_assert_eq!(a.difference(&a).len(), 0);
        }

        /// Σ|part_i| + |A ∩ B| = |A|.
        ///
        /// Combined with pairwise-disjoint and parts ⊂ A, this proves
        /// union(parts) = A \ B.
        #[test]
        fn prop_ipv4_difference_completeness(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            let size = |n: &Ipv4Network| -> u64 {
                let (.., m) = n.to_bits();
                1u64 << (!m).count_ones()
            };

            let a_size = size(&a);
            let inter_size = a.intersection(&b).map_or(0, |c| size(&c));
            let diff_size: u64 = a.difference(&b).map(|r| size(&r)).sum();

            prop_assert_eq!(
                diff_size + inter_size,
                a_size,
                "a={}, b={}, inter={:?}", a, b, a.intersection(&b)
            );
        }

        #[test]
        fn prop_ipv6_difference_parts_in_source(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            for r in a.difference(&b) {
                prop_assert!(a.contains(&r), "part {r} not in a={a}");
            }
        }

        #[test]
        fn prop_ipv6_difference_parts_disjoint_from_other(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            for r in a.difference(&b) {
                prop_assert!(b.is_disjoint(&r), "part {r} intersects b={b}");
            }
        }

        #[test]
        fn prop_ipv6_difference_pairwise_disjoint(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            let parts: Vec<_> = a.difference(&b).collect();
            for i in 0..parts.len() {
                for j in (i + 1)..parts.len() {
                    prop_assert!(
                        parts[i].is_disjoint(&parts[j]),
                        "parts {i} and {j} overlap: {} vs {}", parts[i], parts[j]
                    );
                }
            }
        }

        #[test]
        fn prop_ipv6_difference_self_is_empty(
            a in arb_ipv6_network(),
        ) {
            prop_assert_eq!(a.difference(&a).len(), 0);
        }

        /// Σ|part_i| + |A ∩ B| = |A|.
        #[test]
        fn prop_ipv6_difference_completeness(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            let size = |n: &Ipv6Network| -> u128 {
                let (.., m) = n.to_bits();
                1u128 << (!m).count_ones()
            };

            let a_size = size(&a);
            let inter_size = a.intersection(&b).map_or(0, |c| size(&c));
            let diff_size: u128 = a.difference(&b).map(|r| size(&r)).sum();

            prop_assert_eq!(
                diff_size + inter_size,
                a_size,
                "a={}, b={}, inter={:?}", a, b, a.intersection(&b)
            );
        }

        #[test]
        fn prop_ipv4_supernet_for_contains_all(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            let supernet = a.supernet_for(&[b]);

            prop_assert!(supernet.contains(&a), "supernet {supernet} must contain {a}");
            prop_assert!(supernet.contains(&b), "supernet {supernet} must contain {b}");
        }

        #[test]
        fn prop_ipv6_supernet_for_contains_all(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            let supernet = a.supernet_for(&[b]);

            prop_assert!(supernet.contains(&a), "supernet {supernet} must contain {a}");
            prop_assert!(supernet.contains(&b), "supernet {supernet} must contain {b}");
        }

        #[test]
        fn prop_ipv4_supernet_for_diff_intersection(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            let diff: Vec<_> = a.difference(&b).collect();
            let intersected = a.intersection(&b);

            if diff.is_empty() && intersected.is_none() {
                return Ok(());
            }

            let mut decomposed = diff;
            if let Some(c) = intersected {
                decomposed.push(c);
            }

            let supernet = decomposed[0].supernet_for(&decomposed[1..]);
            prop_assert_eq!(supernet, a, "supernet_for(A\\B ∪ A∩B) must equal A");
        }

        #[test]
        fn prop_ipv6_supernet_for_diff_intersection(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            let diff: Vec<_> = a.difference(&b).collect();
            let intersected = a.intersection(&b);

            if diff.is_empty() && intersected.is_none() {
                return Ok(());
            }

            let mut decomposed = diff;
            if let Some(c) = intersected {
                decomposed.push(c);
            }

            let supernet = decomposed[0].supernet_for(&decomposed[1..]);
            prop_assert_eq!(supernet, a, "supernet_for(A\\B ∪ A∩B) must equal A");
        }

        #[test]
        fn prop_ipv6_merge_commutativity(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            prop_assert_eq!(a.merge(&b), b.merge(&a));
        }

        #[test]
        fn prop_ipv6_merge_self_is_self(
            a in arb_ipv6_network(),
        ) {
            prop_assert_eq!(a.merge(&a), Some(a));
        }

        #[test]
        fn prop_ipv6_merge_result_contains_both(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            if let Some(c) = a.merge(&b) {
                prop_assert!(c.contains(&a), "merge result {c} must contain {a}");
                prop_assert!(c.contains(&b), "merge result {c} must contain {b}");
            }
        }

        #[test]
        fn prop_ipv6_merge_is_normalized(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            if let Some(c) = a.merge(&b) {
                let (addr, mask) = c.to_bits();
                prop_assert_eq!(addr & mask, addr, "merge result not normalized: a={}, b={}, c={}", a, b, c);
            }
        }

        #[test]
        fn prop_ipv6_merge_equals_supernet_when_some(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            if let Some(c) = a.merge(&b) {
                let supernet = a.supernet_for(&[b]);
                prop_assert_eq!(c, supernet, "merge must equal supernet_for when Some: a={}, b={}", a, b);
            }
        }

        #[test]
        fn prop_ipv6_merge_membership_brute_force(
            a_addr in 0u128..=255,
            a_mask in 0u128..=255,
            b_addr in 0u128..=255,
            b_mask in 0u128..=255,
        ) {
            let a = Ipv6Network::from_bits((a_addr & a_mask) << 120, a_mask << 120);
            let b = Ipv6Network::from_bits((b_addr & b_mask) << 120, b_mask << 120);
            let result = a.merge(&b);

            let (a_a, a_m) = a.to_bits();
            let (b_a, b_m) = b.to_bits();

            for x in 0u128..=255 {
                let xaddr = x << 120;
                let in_a = (xaddr & a_m) == a_a;
                let in_b = (xaddr & b_m) == b_a;
                let in_result = match result {
                    Some(r) => {
                        let (r_a, r_m) = r.to_bits();
                        (xaddr & r_m) == r_a
                    }
                    None => false,
                };

                if in_a || in_b {
                    if let Some(..) = result {
                        prop_assert!(
                            in_result,
                            "x={x} in A∪B but not in merge result: a={a}, b={b}, result={result:?}"
                        );
                    }
                }
                if in_result {
                    prop_assert!(
                        in_a || in_b,
                        "x={x} in merge result but not in A∪B: a={a}, b={b}, result={result:?}"
                    );
                }
            }
        }

        #[test]
        fn prop_ipv6_is_adjacent_commutativity(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            prop_assert_eq!(a.is_adjacent(&b), b.is_adjacent(&a));
        }

        #[test]
        fn prop_ipv6_adjacent_implies_merge_some(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            if a.is_adjacent(&b) {
                prop_assert!(a.merge(&b).is_some(), "adjacent but merge returned None: a={a}, b={b}");
            }
        }

        #[test]
        fn prop_ipv6_same_mask_not_adjacent_not_identical_implies_merge_none(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            let (_, m1) = a.to_bits();
            let (_, m2) = b.to_bits();
            if m1 == m2 && !a.is_adjacent(&b) && a != b {
                prop_assert_eq!(a.merge(&b), None, "same mask, not adjacent, not identical, but merge returned Some: a={}, b={}", a, b);
            }
        }

        #[test]
        fn ipv4_aggregate_preserves_addresses(
            raw_nets in prop::collection::vec(
                (0u32..=255, 24u8..=28),
                1..=32,
            )
        ) {
            let mut nets: Vec<Ipv4Network> = raw_nets
                .iter()
                .map(|&(third_octet, prefix)| {
                    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                    let addr = (192 << 24) | (168 << 16) | (third_octet << 8);
                    Ipv4Network::from_bits(addr, mask)
                })
                .collect();

            let mut before_addrs: Vec<u32> = Vec::new();
            for net in &nets {
                for addr in (*net).addrs() {
                    before_addrs.push(addr.to_bits());
                }
            }
            before_addrs.sort_unstable();
            before_addrs.dedup();

            let result = ipv4_aggregate(&mut nets);

            let mut after_addrs: Vec<u32> = Vec::new();
            for net in result.iter() {
                for addr in (*net).addrs() {
                    after_addrs.push(addr.to_bits());
                }
            }
            after_addrs.sort_unstable();
            after_addrs.dedup();

            prop_assert_eq!(before_addrs, after_addrs);
        }

        #[test]
        fn ipv4_aggregate_result_is_minimal(
            raw_nets in prop::collection::vec(
                (0u32..=255, 24u8..=28),
                1..=32,
            )
        ) {
            let mut nets: Vec<Ipv4Network> = raw_nets
                .iter()
                .map(|&(third_octet, prefix)| {
                    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                    let addr = (192 << 24) | (168 << 16) | (third_octet << 8);
                    Ipv4Network::from_bits(addr, mask)
                })
                .collect();

            let result = ipv4_aggregate(&mut nets);

            // No duplicates.
            for i in 0..result.len() {
                for j in (i + 1)..result.len() {
                    prop_assert_ne!(result[i], result[j]);
                }
            }

            // No containment.
            for i in 0..result.len() {
                for j in 0..result.len() {
                    if i != j {
                        prop_assert!(!result[i].contains(&result[j]));
                    }
                }
            }

            // No mergeable pairs.
            for i in 0..result.len() {
                for j in (i + 1)..result.len() {
                    prop_assert!(result[i].merge(&result[j]).is_none());
                }
            }
        }

        #[test]
        fn ipv4_aggregate_non_contiguous_preserves_addresses(
            raw_nets in prop::collection::vec(
                (0u32..=0xFF, 0u32..=0xFF),
                1..=8,
            )
        ) {
            let mut nets: Vec<Ipv4Network> = raw_nets
                .iter()
                .map(|&(addr_low, mask_low)| {
                    let addr = (10 << 24) | addr_low;
                    let mask = 0xFFFFFF00 | mask_low;
                    Ipv4Network::from_bits(addr, mask)
                })
                .collect();

            let mut before_addrs: Vec<u32> = Vec::new();
            for net in &nets {
                for addr in (*net).addrs() {
                    before_addrs.push(addr.to_bits());
                }
            }
            before_addrs.sort_unstable();
            before_addrs.dedup();

            let result = ipv4_aggregate(&mut nets);

            let mut after_addrs: Vec<u32> = Vec::new();
            for net in result.iter() {
                for addr in (*net).addrs() {
                    after_addrs.push(addr.to_bits());
                }
            }
            after_addrs.sort_unstable();
            after_addrs.dedup();

            prop_assert_eq!(before_addrs, after_addrs);
        }

        #[test]
        fn ipnetwork_addr_mask_roundtrip_v4(net in arb_ipv4_network()) {
            let ip_net = IpNetwork::V4(net);
            prop_assert_eq!(IpAddr::V4(*net.addr()), ip_net.addr());
            prop_assert_eq!(IpAddr::V4(*net.mask()), ip_net.mask());
        }

        #[test]
        fn ipnetwork_contains_self_v4(net in arb_ipv4_network()) {
            let ip_net = IpNetwork::V4(net);
            prop_assert!(ip_net.contains(&ip_net));
        }

        #[test]
        fn ipnetwork_contains_self_v6(net in arb_ipv6_network()) {
            let ip_net = IpNetwork::V6(net);
            prop_assert!(ip_net.contains(&ip_net));
        }

        #[test]
        fn ipnetwork_to_contiguous_is_contiguous_v4(net in arb_ipv4_network()) {
            prop_assert!(IpNetwork::V4(net).to_contiguous().is_contiguous());
        }

        #[test]
        fn ipnetwork_to_contiguous_is_contiguous_v6(net in arb_ipv6_network()) {
            prop_assert!(IpNetwork::V6(net).to_contiguous().is_contiguous());
        }

        #[test]
        fn ipnetwork_to_contiguous_contains_original_v4(net in arb_ipv4_network()) {
            let ip_net = IpNetwork::V4(net);
            prop_assert!(ip_net.to_contiguous().contains(&ip_net));
        }

        #[test]
        fn ipnetwork_to_contiguous_contains_original_v6(net in arb_ipv6_network()) {
            let ip_net = IpNetwork::V6(net);
            prop_assert!(ip_net.to_contiguous().contains(&ip_net));
        }
    }

    #[test]
    fn ipv4_range_to_networks_single_cidr() {
        let nets: Vec<_> = ipv4_range_to_networks(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255)).collect();
        assert_eq!(nets.len(), 1);
        assert_eq!(Contiguous::<Ipv4Network>::parse("10.0.0.0/24").unwrap(), nets[0]);
    }

    #[test]
    fn ipv4_range_to_networks_classic_misaligned() {
        // The textbook example: 1..=254 decomposes into 14 blocks.
        let nets: Vec<_> = ipv4_range_to_networks(Ipv4Addr::new(0, 0, 0, 1), Ipv4Addr::new(0, 0, 0, 254)).collect();
        let expected = [
            "0.0.0.1/32",
            "0.0.0.2/31",
            "0.0.0.4/30",
            "0.0.0.8/29",
            "0.0.0.16/28",
            "0.0.0.32/27",
            "0.0.0.64/26",
            "0.0.0.128/26",
            "0.0.0.192/27",
            "0.0.0.224/28",
            "0.0.0.240/29",
            "0.0.0.248/30",
            "0.0.0.252/31",
            "0.0.0.254/32",
        ];
        assert_eq!(nets.len(), expected.len());
        for (got, want) in nets.iter().zip(expected.iter()) {
            assert_eq!(*got, Contiguous::<Ipv4Network>::parse(want).unwrap());
        }
    }

    #[test]
    fn ipv4_range_to_networks_full_range() {
        let nets: Vec<_> = ipv4_range_to_networks(Ipv4Addr::new(0, 0, 0, 0), IPV4_ALL_BITS).collect();
        assert_eq!(nets.len(), 1);
        assert_eq!(Contiguous::<Ipv4Network>::parse("0.0.0.0/0").unwrap(), nets[0]);
    }

    #[test]
    fn ipv4_range_to_networks_single_host_at_max() {
        let nets: Vec<_> = ipv4_range_to_networks(IPV4_ALL_BITS, IPV4_ALL_BITS).collect();
        assert_eq!(nets.len(), 1);
        assert_eq!(Contiguous::<Ipv4Network>::parse("255.255.255.255/32").unwrap(), nets[0]);
    }

    #[test]
    fn ipv4_range_to_networks_single_host() {
        let nets: Vec<_> = ipv4_range_to_networks(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 5)).collect();
        assert_eq!(nets.len(), 1);
        assert_eq!(Contiguous::<Ipv4Network>::parse("10.0.0.5/32").unwrap(), nets[0]);
    }

    #[test]
    fn ipv4_range_to_networks_invalid_order_is_empty() {
        let nets: Vec<_> = ipv4_range_to_networks(Ipv4Addr::new(10, 0, 0, 10), Ipv4Addr::new(10, 0, 0, 5)).collect();
        assert!(nets.is_empty());
    }

    #[test]
    fn ipv4_range_to_networks_ends_at_max() {
        // first != 0, last = MAX: tests the no-overflow exit path.
        let first = Ipv4Addr::new(255, 255, 255, 254);
        let nets: Vec<_> = ipv4_range_to_networks(first, IPV4_ALL_BITS).collect();
        assert_eq!(nets.len(), 1);
        assert_eq!(Contiguous::<Ipv4Network>::parse("255.255.255.254/31").unwrap(), nets[0]);
    }

    #[test]
    fn ipv6_range_to_networks_single_cidr() {
        let first: Ipv6Addr = "2001:db8::".parse().unwrap();
        let last: Ipv6Addr = "2001:db8::ffff:ffff:ffff:ffff".parse().unwrap();
        let nets: Vec<_> = ipv6_range_to_networks(first, last).collect();
        assert_eq!(nets.len(), 1);
        assert_eq!(Contiguous::<Ipv6Network>::parse("2001:db8::/64").unwrap(), nets[0]);
    }

    #[test]
    fn ipv6_range_to_networks_full_range() {
        let nets: Vec<_> = ipv6_range_to_networks(Ipv6Addr::UNSPECIFIED, IPV6_ALL_BITS).collect();
        assert_eq!(nets.len(), 1);
        assert_eq!(Contiguous::<Ipv6Network>::parse("::/0").unwrap(), nets[0]);
    }

    #[test]
    fn ipv6_range_to_networks_ends_at_max() {
        let first: Ipv6Addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe".parse().unwrap();
        let nets: Vec<_> = ipv6_range_to_networks(first, IPV6_ALL_BITS).collect();
        assert_eq!(nets.len(), 1);
        assert_eq!(
            Contiguous::<Ipv6Network>::parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127").unwrap(),
            nets[0]
        );
    }

    #[test]
    fn ipv6_range_to_networks_invalid_order_is_empty() {
        let first: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let last: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let nets: Vec<_> = ipv6_range_to_networks(first, last).collect();
        assert!(nets.is_empty());
    }

    #[test]
    fn contiguous_range_collects_as_unified() {
        let nets: Vec<Contiguous<IpNetwork>> =
            ipv4_range_to_networks(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 5))
                .map(Contiguous::<IpNetwork>::from)
                .collect();
        assert_eq!(2, nets.len());
        assert_eq!("10.0.0.0/30", nets[0].to_string());
        assert_eq!("10.0.0.4/31", nets[1].to_string());

        let nets: Vec<Contiguous<IpNetwork>> = ipv6_range_to_networks(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        )
        .map(Contiguous::<IpNetwork>::from)
        .collect();
        assert_eq!(1, nets.len());
        assert_eq!("2001:db8::/127", nets[0].to_string());
    }

    // Pin tests for `Ipv4Network`/`Ipv6Network` ordering, written against the
    // CURRENT derived `Ord` (lexicographic on the `(addr, mask)` tuple), so a
    // later packed-key rewrite of `Ord` can be checked against this exact
    // behavior. Sorted-input consumers (`ip_binary_split`, `*_aggregate`) rely
    // on this order staying bitwise identical.

    #[test]
    fn test_ipv4_network_ord_address_dominates_mask() {
        // Octet 0 differs (10 vs 11) and is kept by both masks, while the
        // mask magnitude points the other way (a /32 mask is numerically
        // larger than a /8 mask), so this isolates address-first ordering.
        let lower_addr_bigger_mask = Ipv4Network::parse("10.0.0.0/32").unwrap();
        let higher_addr_smaller_mask = Ipv4Network::parse("11.0.0.0/8").unwrap();

        assert!(lower_addr_bigger_mask < higher_addr_smaller_mask);
        assert_eq!(Ordering::Less, lower_addr_bigger_mask.cmp(&higher_addr_smaller_mask));
    }

    #[test]
    fn test_ipv6_network_ord_address_dominates_mask() {
        // Hextet 1 differs (0 vs db9) and is kept by both masks, while the
        // mask magnitude points the other way (a /128 mask is numerically
        // larger than a /32 mask), so this isolates address-first ordering.
        let lower_addr_bigger_mask = Ipv6Network::parse("2001::/128").unwrap();
        let higher_addr_smaller_mask = Ipv6Network::parse("2001:db9::/32").unwrap();

        assert!(lower_addr_bigger_mask < higher_addr_smaller_mask);
        assert_eq!(Ordering::Less, lower_addr_bigger_mask.cmp(&higher_addr_smaller_mask));
    }

    #[test]
    fn test_ipv4_network_ord_equal_address_mask_decides() {
        let smaller_mask = Ipv4Network::parse("10.0.0.0/16").unwrap();
        let bigger_mask = Ipv4Network::parse("10.0.0.0/24").unwrap();

        assert_eq!(smaller_mask.addr(), bigger_mask.addr());
        assert!(smaller_mask < bigger_mask);
    }

    #[test]
    fn test_ipv6_network_ord_equal_address_mask_decides() {
        let smaller_mask = Ipv6Network::parse("2001:db8::/32").unwrap();
        let bigger_mask = Ipv6Network::parse("2001:db8::/64").unwrap();

        assert_eq!(smaller_mask.addr(), bigger_mask.addr());
        assert!(smaller_mask < bigger_mask);
    }

    #[test]
    fn test_ipv4_network_ord_equality() {
        let net_a = Ipv4Network::parse("192.168.1.0/24").unwrap();
        let net_b = Ipv4Network::parse("192.168.1.0/24").unwrap();

        assert_eq!(Ordering::Equal, net_a.cmp(&net_b));
        assert_eq!(net_a, net_b);
    }

    #[test]
    fn test_ipv6_network_ord_equality() {
        let net_a = Ipv6Network::parse("2001:db8::/32").unwrap();
        let net_b = Ipv6Network::parse("2001:db8::/32").unwrap();

        assert_eq!(Ordering::Equal, net_a.cmp(&net_b));
        assert_eq!(net_a, net_b);
    }

    #[test]
    fn test_ipv4_network_ord_non_contiguous_mask_participates() {
        // Both masks leave octet 1 as a hole, and octet 1 of the address is
        // already zero, so the two networks share the same normalized
        // address and only the non-contiguous mask decides the order.
        let smaller_mask = Ipv4Network::parse("10.0.0.5/255.0.0.255").unwrap();
        let bigger_mask = Ipv4Network::parse("10.0.0.5/255.255.0.255").unwrap();

        assert_eq!(smaller_mask.addr(), bigger_mask.addr());
        assert!(smaller_mask < bigger_mask);
    }

    #[test]
    fn test_ipv6_network_ord_non_contiguous_mask_participates() {
        // Both masks leave hextet 2 (and, for the smaller one, hextet 3 too)
        // as a hole, and those hextets are already zero in the address, so
        // the two networks share the same normalized address and only the
        // non-contiguous mask decides the order.
        let smaller_mask = Ipv6Network::parse("2001:db8::5/ffff:ffff:ff00:ff00:ffff:ffff:ffff:ffff").unwrap();
        let bigger_mask = Ipv6Network::parse("2001:db8::5/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff").unwrap();

        assert_eq!(smaller_mask.addr(), bigger_mask.addr());
        assert!(smaller_mask < bigger_mask);
    }

    #[test]
    fn test_ipv4_network_ord_boundary_values() {
        let zero = Ipv4Network::parse("0.0.0.0/0").unwrap();
        let max = Ipv4Network::parse("255.255.255.255/32").unwrap();
        let middle = Ipv4Network::parse("10.0.0.0/8").unwrap();

        assert!(zero < middle);
        assert!(middle < max);
        assert!(zero < max);
    }

    #[test]
    fn test_ipv6_network_ord_boundary_values() {
        let zero = Ipv6Network::parse("::/0").unwrap();
        let max = Ipv6Network::parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128").unwrap();
        let middle = Ipv6Network::parse("2001:db8::/32").unwrap();

        assert!(zero < middle);
        assert!(middle < max);
        assert!(zero < max);
    }

    // Fixed shuffled input; `sort()` must reproduce this exact order so
    // sorted-input consumers (`ip_binary_split`, `*_aggregate`) keep working
    // across any `Ord` rewrite.
    #[test]
    fn test_ipv4_network_sort_matches_expected_order() {
        let mut nets = [
            Ipv4Network::parse("192.168.1.1/32").unwrap(),
            Ipv4Network::parse("10.1.0.0/16").unwrap(),
            Ipv4Network::parse("255.255.255.255/32").unwrap(),
            Ipv4Network::parse("10.0.0.5/255.255.0.255").unwrap(),
            Ipv4Network::parse("0.0.0.0/0").unwrap(),
            Ipv4Network::parse("10.0.0.0/24").unwrap(),
            Ipv4Network::parse("10.0.0.5/255.0.0.255").unwrap(),
            Ipv4Network::parse("10.0.0.0/8").unwrap(),
        ];
        nets.sort();

        let expected = [
            Ipv4Network::parse("0.0.0.0/0").unwrap(),
            Ipv4Network::parse("10.0.0.0/8").unwrap(),
            Ipv4Network::parse("10.0.0.0/24").unwrap(),
            Ipv4Network::parse("10.0.0.5/255.0.0.255").unwrap(),
            Ipv4Network::parse("10.0.0.5/255.255.0.255").unwrap(),
            Ipv4Network::parse("10.1.0.0/16").unwrap(),
            Ipv4Network::parse("192.168.1.1/32").unwrap(),
            Ipv4Network::parse("255.255.255.255/32").unwrap(),
        ];
        assert_eq!(expected, nets);
    }

    #[test]
    fn test_ipv6_network_sort_matches_expected_order() {
        let mut nets = [
            Ipv6Network::parse("2a02:6b8::1/128").unwrap(),
            Ipv6Network::parse("2001:db9::/32").unwrap(),
            Ipv6Network::parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128").unwrap(),
            Ipv6Network::parse("2001:db8::5/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff").unwrap(),
            Ipv6Network::parse("::/0").unwrap(),
            Ipv6Network::parse("2001:db8::/48").unwrap(),
            Ipv6Network::parse("2001:db8::5/ffff:ffff:ff00:ff00:ffff:ffff:ffff:ffff").unwrap(),
            Ipv6Network::parse("2001:db8::/32").unwrap(),
        ];
        nets.sort();

        let expected = [
            Ipv6Network::parse("::/0").unwrap(),
            Ipv6Network::parse("2001:db8::/32").unwrap(),
            Ipv6Network::parse("2001:db8::/48").unwrap(),
            Ipv6Network::parse("2001:db8::5/ffff:ffff:ff00:ff00:ffff:ffff:ffff:ffff").unwrap(),
            Ipv6Network::parse("2001:db8::5/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff").unwrap(),
            Ipv6Network::parse("2001:db9::/32").unwrap(),
            Ipv6Network::parse("2a02:6b8::1/128").unwrap(),
            Ipv6Network::parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128").unwrap(),
        ];
        assert_eq!(expected, nets);
    }

    // The (addr, mask) tuple is exactly the derived semantics, so it remains a
    // valid reference after the `Ord` impl is swapped for a packed-key one.
    #[test]
    fn prop_ipv4_network_ord_matches_addr_mask_tuple() {
        let mut rng = Xorshift64::new(0x51ED_1949_2C13_9AC1);

        for _ in 0..2000 {
            let net_x = random_ipv4_network(&mut rng);
            let net_y = random_ipv4_network(&mut rng);

            let expected = (net_x.addr(), net_x.mask()).cmp(&(net_y.addr(), net_y.mask()));
            assert_eq!(expected, net_x.cmp(&net_y));
            assert_eq!(Some(net_x.cmp(&net_y)), net_x.partial_cmp(&net_y));
            assert_eq!(net_x.cmp(&net_y) == Ordering::Equal, net_x == net_y);
        }
    }

    #[test]
    fn prop_ipv6_network_ord_matches_addr_mask_tuple() {
        let mut rng = Xorshift64::new(0x8B5A_46F1_D30C_77E9);

        for _ in 0..2000 {
            let net_x = random_ipv6_network(&mut rng);
            let net_y = random_ipv6_network(&mut rng);

            let expected = (net_x.addr(), net_x.mask()).cmp(&(net_y.addr(), net_y.mask()));
            assert_eq!(expected, net_x.cmp(&net_y));
            assert_eq!(Some(net_x.cmp(&net_y)), net_x.partial_cmp(&net_y));
            assert_eq!(net_x.cmp(&net_y) == Ordering::Equal, net_x == net_y);
        }
    }

    proptest! {
        #[test]
        fn prop_ipv4_range_to_networks_covers_exactly(a in any::<u32>(), b in any::<u32>()) {
            let (first_bits, last_bits) = if a <= b { (a, b) } else { (b, a) };
            let first = Ipv4Addr::from_bits(first_bits);
            let last = Ipv4Addr::from_bits(last_bits);

            let nets: Vec<_> = ipv4_range_to_networks(first, last).collect();
            prop_assert!(!nets.is_empty());

            // Coverage is contiguous and abuts exactly [first, last].
            let mut cursor = first_bits;
            let mut covered_last: u32 = first_bits;
            for (i, net) in nets.iter().enumerate() {
                let (addr, mask) = net.to_bits();
                // Address aligned to mask.
                prop_assert_eq!(addr & mask, addr);
                // Mask is contiguous (CIDR), guaranteed by the type but assert anyway.
                let host = !mask;
                prop_assert_eq!(host & host.wrapping_add(1), 0);
                // Block start equals cursor.
                prop_assert_eq!(addr, cursor);
                let end = addr | host;
                prop_assert!(end >= addr);
                covered_last = end;
                if i + 1 < nets.len() {
                    prop_assert!(end < u32::MAX);
                    cursor = end + 1;
                }
            }
            prop_assert_eq!(covered_last, last_bits);

            // Minimality: aggregate cannot reduce the count.
            let mut raw: Vec<Ipv4Network> = nets.iter().map(|c| **c).collect();
            let agg_len = ipv4_aggregate(&mut raw).len();
            prop_assert_eq!(agg_len, nets.len());

            // Bound from theory: at most 2N - 2 blocks.
            prop_assert!(nets.len() <= 2 * 32 - 2);
        }

        #[test]
        fn prop_ipv4_range_to_networks_empty_when_reversed(a in any::<u32>(), b in any::<u32>()) {
            if a > b {
                let nets: Vec<_> =
                    ipv4_range_to_networks(Ipv4Addr::from_bits(a), Ipv4Addr::from_bits(b)).collect();
                prop_assert!(nets.is_empty());
            }
        }

        #[test]
        fn prop_ipv6_range_to_networks_covers_exactly(a in any::<u128>(), b in any::<u128>()) {
            let (first_bits, last_bits) = if a <= b { (a, b) } else { (b, a) };
            let first = Ipv6Addr::from_bits(first_bits);
            let last = Ipv6Addr::from_bits(last_bits);

            let nets: Vec<_> = ipv6_range_to_networks(first, last).collect();
            prop_assert!(!nets.is_empty());

            let mut cursor = first_bits;
            let mut covered_last: u128 = first_bits;
            for (i, net) in nets.iter().enumerate() {
                let (addr, mask) = net.to_bits();
                prop_assert_eq!(addr & mask, addr);
                let host = !mask;
                prop_assert_eq!(host & host.wrapping_add(1), 0);
                prop_assert_eq!(addr, cursor);
                let end = addr | host;
                covered_last = end;
                if i + 1 < nets.len() {
                    prop_assert!(end < u128::MAX);
                    cursor = end + 1;
                }
            }
            prop_assert_eq!(covered_last, last_bits);

            let mut raw: Vec<Ipv6Network> = nets.iter().map(|c| **c).collect();
            let agg_len = ipv6_aggregate(&mut raw).len();
            prop_assert_eq!(agg_len, nets.len());

            prop_assert!(nets.len() <= 2 * 128 - 2);
        }
    }
}
