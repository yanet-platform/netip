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
    fmt::{Debug, Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{BitAnd, BitOr, BitOrAssign, BitXor, Not, Range},
    str::FromStr,
};

mod bicontiguous;
mod contiguous;

pub use bicontiguous::{BiContiguous, BiContiguousIpNetParseError, ipv6_aggregate_bicontiguous};
pub use contiguous::{Contiguous, ContiguousIpNetParseError, ipv4_aggregate_contiguous, ipv6_aggregate_contiguous};

use crate::parser::{self, IpNetParseError};

pub const IPV4_ALL_BITS: Ipv4Addr = Ipv4Addr::new(0xff, 0xff, 0xff, 0xff);
pub const IPV6_ALL_BITS: Ipv6Addr = Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff);

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

/// Returns an [`Ipv4Addr`] that will have exact `cidr` leading bits set to
/// one.
///
/// This function is used to construct IP masks for the given network prefix
/// size.
#[inline]
pub const fn ipv4_mask_from_cidr(cidr: u8) -> Result<Ipv4Addr, CidrOverflowError> {
    if cidr <= 32 {
        let shifted = match u32::MAX.checked_shr(cidr as u32) {
            Some(shifted) => shifted,
            None => 0,
        };
        Ok(Ipv4Addr::from_bits(!shifted))
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
pub const fn ipv6_mask_from_cidr(cidr: u8) -> Result<Ipv6Addr, CidrOverflowError> {
    if cidr <= 128 {
        let shifted = match u128::MAX.checked_shr(cidr as u32) {
            Some(shifted) => shifted,
            None => 0,
        };
        Ok(Ipv6Addr::from_bits(!shifted))
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

/// Returns `true` if two same-mask IPv4 networks differ in exactly the
/// lowest set bit of that mask, `false` otherwise.
///
/// The `m1 != 0` clause excludes the `/0` mask, whose isolated lowest set bit
/// is `0`. Without it, two identical `/0` networks would qualify.
#[inline]
const fn ipv4_adjacent_by_lowest_mask_bit(a1: u32, m1: u32, a2: u32, m2: u32) -> bool {
    m1 == m2 && m1 != 0 && (a1 ^ a2) == (m1 & m1.wrapping_neg())
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

/// Returns `true` if two same-mask IPv6 networks differ in exactly the
/// lowest set bit of that mask, `false` otherwise.
///
/// The `m1 != 0` clause excludes the `/0` mask, whose isolated lowest set bit
/// is `0`. Without it, two identical `/0` networks would qualify.
#[inline]
const fn ipv6_adjacent_by_lowest_mask_bit(a1: u128, m1: u128, a2: u128, m2: u128) -> bool {
    m1 == m2 && m1 != 0 && (a1 ^ a2) == (m1 & m1.wrapping_neg())
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
    #[inline]
    pub fn parse(buf: &str) -> Result<Self, IpNetParseError> {
        parser::parse_ip_network(buf)
    }

    /// Parses the specified ASCII byte buffer into an IP network.
    ///
    /// The buffer does not need to be valid UTF-8, so slices cut from a
    /// larger byte stream can be parsed without a validation pass. The
    /// accepted formats match [`Self::parse`].
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::{Ipv4Addr, Ipv6Addr};
    ///
    /// use netip::{IpNetwork, Ipv4Network, Ipv6Network};
    ///
    /// assert_eq!(
    ///     IpNetwork::V4(Ipv4Network::new(
    ///         Ipv4Addr::new(192, 168, 0, 0),
    ///         Ipv4Addr::new(255, 255, 255, 0),
    ///     )),
    ///     IpNetwork::parse_ascii(b"192.168.0.0/24").unwrap(),
    /// );
    /// assert_eq!(
    ///     IpNetwork::V6(Ipv6Network::new(
    ///         Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0, 0, 0),
    ///         Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0, 0, 0, 0),
    ///     )),
    ///     IpNetwork::parse_ascii(b"2a02:6b8:c00::/40").unwrap(),
    /// );
    /// ```
    #[inline]
    pub fn parse_ascii(buf: &[u8]) -> Result<Self, IpNetParseError> {
        parser::parse_ip_network_ascii(buf)
    }

    /// Parses the leading network token of `buf` into an IP network,
    /// returning it with the unconsumed remainder.
    ///
    /// The token is the maximal leading run of network characters
    /// (`[0-9a-fA-F:./+]`) and must parse as a whole: a malformed token is
    /// an error, never a shorter partial parse. The alphabet covers both
    /// families, since the family is unknown before tokenizing: `:` and hex
    /// letters are token material here, so `10.0.0.1:8080` is an error,
    /// while the family-declaring [`Ipv4Network::parse_next_ascii`] accepts
    /// it. Leading whitespace is not skipped. This suits pulling networks
    /// out of a larger rule text.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::{IpNetwork, Ipv6Network};
    ///
    /// let expected = IpNetwork::V6(Ipv6Network::new(
    ///     Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0, 0, 0),
    ///     Ipv6Addr::new(0xffff, 0xfff, 0xff00, 0, 0xffff, 0xffff, 0, 0),
    /// ));
    ///
    /// let (network, rest) =
    ///     IpNetwork::parse_next_ascii(b"2a02:6b8:c00::/ffff:fff:ff00::ffff:ffff:0:0 } to any")
    ///         .unwrap();
    /// assert_eq!(expected, network);
    /// assert_eq!(b" } to any", rest);
    /// ```
    #[inline]
    pub fn parse_next_ascii(buf: &[u8]) -> Result<(Self, &[u8]), IpNetParseError> {
        parser::parse_ip_network_next_ascii(buf)
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
    pub const fn to_contiguous(&self) -> Self {
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

    /// Returns `true` if this network is adjacent to `other` at the lowest set
    /// bit of their shared mask.
    ///
    /// This is the class-preserving restriction of
    /// [`is_adjacent`](Self::is_adjacent) to the mask's lowest (buddy) bit, so
    /// it implies `is_adjacent` but not conversely.
    ///
    /// Returns `false` for networks of different address families.
    ///
    /// See [`Ipv4Network::is_adjacent_by_lowest_mask_bit`] and
    /// [`Ipv6Network::is_adjacent_by_lowest_mask_bit`] for details.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::IpNetwork;
    ///
    /// // CIDR siblings differ in the lowest mask bit: both predicates hold.
    /// let a = IpNetwork::parse("192.168.0.0/24").unwrap();
    /// let b = IpNetwork::parse("192.168.1.0/24").unwrap();
    /// assert!(a.is_adjacent(&b));
    /// assert!(a.is_adjacent_by_lowest_mask_bit(&b));
    ///
    /// // Adjacent at the top mask bit, not the lowest: `is_adjacent` accepts
    /// // it, `is_adjacent_by_lowest_mask_bit` rejects it.
    /// let c = IpNetwork::parse("0.0.0.0/2").unwrap();
    /// let d = IpNetwork::parse("128.0.0.0/2").unwrap();
    /// assert!(c.is_adjacent(&d));
    /// assert!(!c.is_adjacent_by_lowest_mask_bit(&d));
    ///
    /// // Mixed address families are never adjacent.
    /// let v4 = IpNetwork::parse("10.0.0.0/8").unwrap();
    /// let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
    /// assert!(!v4.is_adjacent_by_lowest_mask_bit(&v6));
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_adjacent_by_lowest_mask_bit(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::V4(a), Self::V4(b)) => a.is_adjacent_by_lowest_mask_bit(b),
            (Self::V6(a), Self::V6(b)) => a.is_adjacent_by_lowest_mask_bit(b),
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

    /// Merges this IP network with another when one contains the other or they
    /// are lowest-mask-bit siblings, returning the combined network.
    ///
    /// This is the class-closed subset of [`merge`](Self::merge): it returns
    /// `Some` only for containment or a difference in the mask's lowest set
    /// bit, and whenever it does, that value equals [`merge`](Self::merge)'s.
    ///
    /// Returns `None` for networks of different address families.
    ///
    /// See [`Ipv4Network::merge_by_lowest_mask_bit`] and
    /// [`Ipv6Network::merge_by_lowest_mask_bit`] for details.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::IpNetwork;
    ///
    /// // Lowest-bit siblings merge into their parent (agrees with `merge`).
    /// let a = IpNetwork::parse("192.168.0.0/24").unwrap();
    /// let b = IpNetwork::parse("192.168.1.0/24").unwrap();
    /// assert_eq!(
    ///     Some(IpNetwork::parse("192.168.0.0/23").unwrap()),
    ///     a.merge_by_lowest_mask_bit(&b)
    /// );
    ///
    /// // Containment: the larger (containing) network is returned, either way.
    /// let outer = IpNetwork::parse("10.0.0.0/8").unwrap();
    /// let inner = IpNetwork::parse("10.1.0.0/16").unwrap();
    /// assert_eq!(Some(outer), outer.merge_by_lowest_mask_bit(&inner));
    /// assert_eq!(Some(outer), inner.merge_by_lowest_mask_bit(&outer));
    ///
    /// // Adjacent at a higher mask bit: `merge` still combines them (into a
    /// // non-contiguous block), but `merge_by_lowest_mask_bit` refuses.
    /// let c = IpNetwork::parse("0.0.0.0/2").unwrap();
    /// let d = IpNetwork::parse("128.0.0.0/2").unwrap();
    /// assert!(c.merge(&d).is_some());
    /// assert_eq!(None, c.merge_by_lowest_mask_bit(&d));
    ///
    /// // Mixed address families cannot be merged.
    /// let v4 = IpNetwork::parse("10.0.0.0/8").unwrap();
    /// let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
    /// assert_eq!(None, v4.merge_by_lowest_mask_bit(&v6));
    /// ```
    #[inline]
    #[must_use]
    pub const fn merge_by_lowest_mask_bit(&self, other: &Self) -> Option<Self> {
        // NOTE: use `Option::map` when it becomes const.
        match (self, other) {
            (Self::V4(a), Self::V4(b)) => match a.merge_by_lowest_mask_bit(b) {
                Some(net) => Some(Self::V4(net)),
                None => None,
            },
            (Self::V6(a), Self::V6(b)) => match a.merge_by_lowest_mask_bit(b) {
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
            IpNetwork::V4(net) => Display::fmt(net, fmt),
            IpNetwork::V6(net) => Display::fmt(net, fmt),
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

    #[inline]
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
    #[inline]
    fn from(addr: Ipv6Addr) -> Self {
        // Construct network directly, because no address mutation occurs.
        Self::V6(Ipv6Network(addr, IPV6_ALL_BITS))
    }
}

impl TryFrom<(Ipv6Addr, u8)> for IpNetwork {
    type Error = CidrOverflowError;

    #[inline]
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
    #[inline]
    pub fn parse(buf: &str) -> Result<Self, IpNetParseError> {
        parser::parse_ipv4_network(buf)
    }

    /// Parses the specified ASCII byte buffer into an IPv4 network.
    ///
    /// The buffer does not need to be valid UTF-8, so slices cut from a
    /// larger byte stream can be parsed without a validation pass. The
    /// accepted formats match [`Self::parse`].
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
    /// assert_eq!(expected, Ipv4Network::parse_ascii(b"192.168.1.1").unwrap());
    /// assert_eq!(
    ///     expected,
    ///     Ipv4Network::parse_ascii(b"192.168.1.1/32").unwrap()
    /// );
    /// assert_eq!(
    ///     expected,
    ///     Ipv4Network::parse_ascii(b"192.168.1.1/255.255.255.255").unwrap()
    /// );
    /// ```
    #[inline]
    pub fn parse_ascii(buf: &[u8]) -> Result<Self, IpNetParseError> {
        parser::parse_ipv4_network_ascii(buf)
    }

    /// Parses the leading network token of `buf` into an IPv4 network,
    /// returning it with the unconsumed remainder.
    ///
    /// The token is the maximal leading run of IPv4 network characters
    /// (`[0-9./+]`) and must parse as a whole: a malformed token is an
    /// error, never a shorter partial parse. Bytes meaningless in IPv4
    /// text, including `:` and hex letters, delimit the token, so
    /// `10.0.0.1:8080` parses with `:8080` as the remainder — unlike
    /// [`IpNetwork::parse_next_ascii`], whose token alphabet must cover
    /// both families. Leading whitespace is not skipped. This suits pulling
    /// networks out of a larger rule text.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv4Addr;
    ///
    /// use netip::Ipv4Network;
    ///
    /// let expected = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 0, 0, 0));
    ///
    /// let (network, rest) = Ipv4Network::parse_next_ascii(b"10.0.0.0/8 } to any").unwrap();
    /// assert_eq!(expected, network);
    /// assert_eq!(b" } to any", rest);
    /// ```
    #[inline]
    pub fn parse_next_ascii(buf: &[u8]) -> Result<(Self, &[u8]), IpNetParseError> {
        parser::parse_ipv4_network_next_ascii(buf)
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
    /// every bit position that both masks constrain, meaning
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
    /// The result contains exactly `popcount(m2 & !m1)` pairwise-disjoint
    /// networks when `self` and `other` overlap (0 if `self` is a subset of
    /// `other`, at most 32 otherwise), or exactly 1 if they are disjoint —
    /// never merely an upper bound, and provably the minimum number of
    /// networks (including non-contiguous ones) that can represent the
    /// difference. Works correctly with non-contiguous masks.
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
    /// // The iterator is double-ended: `.rev()` yields the same networks in
    /// // reverse order, and consumption from either end can be freely mixed.
    /// let rev: Vec<_> = a.difference(&b).rev().collect();
    /// assert_eq!(rev, diff.into_iter().rev().collect::<Vec<_>>());
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
        // For a contiguous mask every set bit is in the leading run, so its
        // popcount equals `leading_ones`. The dedicated contiguity check is
        // cheaper than recomputing the popcount here.
        if self.is_contiguous() {
            Some(self.mask().to_bits().leading_ones() as u8)
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
    #[inline]
    #[must_use]
    pub const fn to_contiguous(&self) -> Self {
        let (addr, mask) = self.to_bits();

        // NOTE: `mask.leading_ones()` is at most 32, which `ipv4_mask_from_cidr` always
        // accepts.
        match ipv4_mask_from_cidr(mask.leading_ones() as u8) {
            Ok(mask) => Self::new(Ipv4Addr::from_bits(addr), mask),
            Err(..) => unreachable!(),
        }
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
    #[inline]
    #[must_use]
    pub fn supernet_for(&self, nets: &[Ipv4Network]) -> Ipv4Network {
        // AND/XOR/NOT commute with byte order, so the fold runs on native-order words:
        // this drops the per-element big-endian byte swap the fold would otherwise
        // need, keeping the inner loop auto-vectorizable.
        let addr = u32::from_ne_bytes(self.addr().octets());
        let mut mask = u32::from_ne_bytes(self.mask().octets());

        for net in nets {
            let a = u32::from_ne_bytes(net.addr().octets());
            let m = u32::from_ne_bytes(net.mask().octets());
            mask &= m & !(addr ^ a);
        }

        Self::new(Ipv4Addr::from(addr.to_ne_bytes()), Ipv4Addr::from(mask.to_ne_bytes()))
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

    /// Returns `true` if this network is adjacent to `other` at the lowest set
    /// bit of their shared mask.
    ///
    /// This is the strict restriction of [`is_adjacent`](Self::is_adjacent) to
    /// the mask's lowest set bit — the boundary ("buddy") bit that separates a
    /// block from its immediate parent. The two networks must share the same
    /// mask and their addresses must differ in exactly that single bit.
    ///
    /// Every pair accepted here is also accepted by
    /// [`is_adjacent`](Self::is_adjacent), but not conversely: `is_adjacent`
    /// additionally accepts a difference in any other single masked bit. This
    /// is precisely the adjacency whose merge preserves the mask's structural
    /// class — merging two contiguous (CIDR) blocks at their buddy bit yields a
    /// contiguous parent, whereas merging at a higher bit would punch a hole
    /// and leave the contiguous class.
    ///
    /// Identical networks are **not** adjacent, and a `/0` network is never
    /// adjacent to anything. Works correctly with non-contiguous masks.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::Ipv4Network;
    ///
    /// // CIDR siblings differ in the lowest mask bit: both predicates hold,
    /// // and they would merge into a /23.
    /// let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
    /// let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
    /// assert!(a.is_adjacent(&b));
    /// assert!(a.is_adjacent_by_lowest_mask_bit(&b));
    ///
    /// // Adjacent at the *top* mask bit, not the lowest: `is_adjacent`
    /// // accepts it, `is_adjacent_by_lowest_mask_bit` rejects it (merging there
    /// // would leave the contiguous class).
    /// let c = Ipv4Network::parse("0.0.0.0/2").unwrap();
    /// let d = Ipv4Network::parse("128.0.0.0/2").unwrap();
    /// assert!(c.is_adjacent(&d));
    /// assert!(!c.is_adjacent_by_lowest_mask_bit(&d));
    ///
    /// // Identical or different-mask networks are never adjacent.
    /// assert!(!a.is_adjacent_by_lowest_mask_bit(&a));
    /// let e = Ipv4Network::parse("192.168.0.0/16").unwrap();
    /// assert!(!a.is_adjacent_by_lowest_mask_bit(&e));
    ///
    /// // Non-contiguous masks are supported: these differ in the lowest set
    /// // bit of `255.255.0.255` (bit 0 of the low byte).
    /// let x = Ipv4Network::parse("10.0.0.0/255.255.0.255").unwrap();
    /// let y = Ipv4Network::parse("10.0.0.1/255.255.0.255").unwrap();
    /// assert!(x.is_adjacent_by_lowest_mask_bit(&y));
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_adjacent_by_lowest_mask_bit(&self, other: &Self) -> bool {
        let (a1, m1) = self.to_bits();
        let (a2, m2) = other.to_bits();
        ipv4_adjacent_by_lowest_mask_bit(a1, m1, a2, m2)
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
            let diff = a1 ^ a2;
            if diff & diff.wrapping_sub(1) == 0 {
                // diff == 0 (duplicate) or a single bit (mergeable siblings).
                let mask = m1 ^ diff;
                return Some(Self(Ipv4Addr::from_bits(a1 & mask), Ipv4Addr::from_bits(mask)));
            }
            return None;
        }

        let mask_common = m1 & m2;
        if mask_common == m2 {
            // Only `other` can contain `self`.
            return if a1 & m2 == a2 { Some(*other) } else { None };
        }
        if mask_common == m1 {
            // Only `self` can contain `other`.
            return if a2 & m1 == a1 { Some(*self) } else { None };
        }
        None
    }

    /// Merges this IPv4 network with another when one contains the other or
    /// they are lowest-mask-bit siblings, returning the combined network.
    ///
    /// Returns `Some` in exactly two disjoint cases:
    ///
    /// - **Containment**: one network is a subset of the other. The larger
    ///   (containing) network is returned, exactly as [`merge`](Self::merge)
    ///   does.
    /// - **Lowest-mask-bit sibling**: the two share a mask and their addresses
    ///   differ in precisely its lowest set bit — the boundary "buddy" bit,
    ///   detected by
    ///   [`is_adjacent_by_lowest_mask_bit`](Self::is_adjacent_by_lowest_mask_bit).
    ///   The result is the common address `a1 & a2` (the differing lowest bit
    ///   cleared) under the shared mask with its lowest set bit removed.
    ///
    /// These cases are disjoint: siblings have equal masks and distinct
    /// addresses, so neither contains the other.
    ///
    /// This is the class-closed subset of [`merge`](Self::merge) —
    /// `{containment, lowest-mask-bit sibling}`. It differs from `merge` only
    /// by refusing `merge`'s remaining case, a difference at a higher
    /// (non-lowest) mask bit, which would combine the pair into a network
    /// outside the inputs' structural class. Refusing it keeps the result
    /// in class: a contiguous (CIDR) pair merges to a contiguous parent, a
    /// non-contiguous pair to a non-contiguous parent, and a containment
    /// result is simply the larger input, already in class. Whenever it
    /// returns `Some`, that value equals [`merge`](Self::merge)'s.
    ///
    /// For a mask made of two contiguous runs (a non-contiguous mask), sibling
    /// merging happens only along the lower run's boundary — the mask's lowest
    /// set bit. A sibling pair differing at the higher run's boundary is left
    /// unmerged even though `merge` would combine it into another two-run mask.
    /// Doing that safely would require assuming the mask has that two-run
    /// shape, which this general-purpose method does not.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::Ipv4Network;
    ///
    /// // Lowest-bit (buddy) siblings merge into their contiguous parent, and
    /// // `merge` agrees.
    /// let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
    /// let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
    /// assert_eq!(
    ///     Some(Ipv4Network::parse("192.168.0.0/23").unwrap()),
    ///     a.merge_by_lowest_mask_bit(&b)
    /// );
    /// assert_eq!(a.merge(&b), a.merge_by_lowest_mask_bit(&b));
    ///
    /// // Containment: the larger (containing) network is returned, either way.
    /// let outer = Ipv4Network::parse("10.0.0.0/8").unwrap();
    /// let inner = Ipv4Network::parse("10.1.0.0/16").unwrap();
    /// assert_eq!(Some(outer), outer.merge_by_lowest_mask_bit(&inner));
    /// assert_eq!(Some(outer), inner.merge_by_lowest_mask_bit(&outer));
    ///
    /// // Adjacent at the *top* mask bit, not the lowest: `merge` combines the
    /// // pair into a non-contiguous block, but `merge_by_lowest_mask_bit`
    /// // returns `None` to keep the result in the contiguous class.
    /// let c = Ipv4Network::parse("0.0.0.0/2").unwrap();
    /// let d = Ipv4Network::parse("128.0.0.0/2").unwrap();
    /// assert_eq!(
    ///     Some(Ipv4Network::parse("0.0.0.0/64.0.0.0").unwrap()),
    ///     c.merge(&d)
    /// );
    /// assert_eq!(None, c.merge_by_lowest_mask_bit(&d));
    ///
    /// // Disjoint networks with different masks never merge here.
    /// let e = Ipv4Network::parse("172.16.0.0/16").unwrap();
    /// assert_eq!(None, a.merge_by_lowest_mask_bit(&e));
    ///
    /// // Non-contiguous masks are supported: these differ in the lowest set bit
    /// // of `255.255.0.255`, so they collapse to `/255.255.0.254`.
    /// let x = Ipv4Network::parse("10.0.0.0/255.255.0.255").unwrap();
    /// let y = Ipv4Network::parse("10.0.0.1/255.255.0.255").unwrap();
    /// assert_eq!(
    ///     Some(Ipv4Network::parse("10.0.0.0/255.255.0.254").unwrap()),
    ///     x.merge_by_lowest_mask_bit(&y)
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn merge_by_lowest_mask_bit(&self, other: &Self) -> Option<Self> {
        let (a1, m1) = self.to_bits();
        let (a2, m2) = other.to_bits();

        if m1 == m2 {
            // Equal masks: containment degenerates to network equality, so both
            // `contains` probes collapse to one address compare.
            if a1 == a2 {
                return Some(*self);
            }

            if ipv4_adjacent_by_lowest_mask_bit(a1, m1, a2, m2) {
                // NOTE: the addresses differ only in the mask's lowest set bit,
                // which the reduced mask clears, so `a1 & a2` is already
                // normalized and needs no further `& mask`.
                return Some(Self(
                    Ipv4Addr::from_bits(a1 & a2),
                    Ipv4Addr::from_bits(m1 & m1.wrapping_sub(1)),
                ));
            }

            return None;
        }

        // Different masks: adjacency requires equal masks, so containment is
        // the only remaining way to merge.
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
    /// # Correctness
    ///
    /// The expression `addr | !mask` is the greatest address in the network.
    /// Masking it (`& mask`) maps it back to `addr`, since `!mask & mask == 0`,
    /// so it is a member. Setting every host bit — the bits cleared in `mask`
    /// — is the largest possible host pattern, so no member is larger. Both
    /// facts hold for non-contiguous masks, where the host bits need not form
    /// a trailing run.
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

        Ipv4NetworkAddrs {
            base: addr,
            mask,
            front_addr: addr,
            back_addr: addr | !mask,
            remaining: 1u64 << host_bits,
        }
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

    #[inline]
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
/// When the iterator is exhausted (`remaining == 0`) every subsequent call to
/// [`next`](Iterator::next) or [`next_back`](DoubleEndedIterator::next_back)
/// returns [`None`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4NetworkAddrs {
    base: u32,
    mask: u32,
    /// Next address to yield from the front end, stepped in O(1) per item.
    front_addr: u32,
    /// Next address to yield from the back end, stepped in O(1) per item.
    back_addr: u32,
    /// Number of addresses not yet yielded, stored as `u64` so the /0
    /// network's `2^32` is represented exactly.
    remaining: u64,
}

impl Iterator for Ipv4NetworkAddrs {
    type Item = Ipv4Addr;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        self.remaining -= 1;

        let host_mask = !self.mask;
        let bits = self.front_addr;

        self.front_addr = if host_mask & host_mask.wrapping_add(1) == 0 {
            // Contiguous mask (trailing zeros only): a plain increment steps
            // to the next address. The overrun past the last one is repaired
            // by the exhaustion canonicalization below.
            bits.wrapping_add(1)
        } else {
            // O(1) step to the next host pattern: with the mask bits preset
            // to one, the +1 carry ripples straight across them between host
            // positions.
            ((bits | self.mask).wrapping_add(1) & host_mask) | self.base
        };

        // On exhaustion park the front cursor on `base`, so that every drain
        // script ending in `next_back` collapses into one sentinel state while
        // an all-front overrun keeps its stepped `back_addr` as a distinct
        // (still exhausted) state.
        if self.remaining == 0 {
            self.front_addr = self.base;
        }

        Some(Ipv4Addr::from_bits(bits))
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.remaining > u32::MAX as u64 {
            (usize::MAX, None)
        } else {
            let n = self.remaining as usize;
            (n, Some(n))
        }
    }
}

impl DoubleEndedIterator for Ipv4NetworkAddrs {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        self.remaining -= 1;

        let host_mask = !self.mask;
        let bits = self.back_addr;

        self.back_addr = if host_mask & host_mask.wrapping_add(1) == 0 {
            // Contiguous mask (trailing zeros only): a plain decrement steps
            // to the previous address. The underrun past the first one is
            // repaired by the exhaustion canonicalization below.
            bits.wrapping_sub(1)
        } else {
            // O(1) step to the previous host pattern: with the mask bits
            // cleared, the -1 borrow ripples straight across them between
            // host positions.
            ((bits & host_mask).wrapping_sub(1) & host_mask) | self.base
        };

        // On exhaustion park both cursors on `base`, the shared sentinel for
        // every drain script whose last item came off the back end.
        if self.remaining == 0 {
            self.front_addr = self.base;
            self.back_addr = self.base;
        }

        Some(Ipv4Addr::from_bits(bits))
    }
}

impl ExactSizeIterator for Ipv4NetworkAddrs {
    #[inline]
    fn len(&self) -> usize {
        self.remaining as usize
    }
}

/// Lazy iterator over [`Ipv4Network`] parts of a set difference.
///
/// Created by [`Ipv4Network::difference`].
///
/// Yields between 0 and 32 pairwise-disjoint networks whose union equals the
/// address set of `A` minus the address set of `B`.
///
/// Each call to [`next`](Iterator::next) computes one network by peeling the
/// highest remaining bit from the difference mask. Each call to
/// [`next_back`](DoubleEndedIterator::next_back) peels the lowest remaining
/// bit instead. Consumption from either end is O(1) and the two can be
/// freely interleaved.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4NetworkDiff {
    /// Intersection address, or an encoded address for the disjoint shortcut.
    addr: u32,
    /// Mask of the source network, gaining one bit of `d` per `next()` call
    /// (or with one bit cleared for the disjoint shortcut).
    mask: u32,
    /// Bits of `d` not yet yielded.
    remaining: u32,
    /// Prediction of `next()`'s upcoming peel bit: one position below the
    /// last bit yielded, zero before the first call. Pending bits only ever
    /// sit at or below it, so whenever it — or, failing that, its next lower
    /// neighbour — is still pending, that guess is exactly the highest
    /// pending bit and `next()` skips the scan for it.
    predicted: u32,
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
                    remaining: b,
                    predicted: 0,
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
                        remaining: 0,
                        predicted: 0,
                    }
                } else {
                    // General case: peel one network per bit of d.
                    Self {
                        addr: intersected_addr,
                        mask,
                        remaining: d,
                        predicted: 0,
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
        // After the first peel every pending bit sits at or below
        // `predicted`, so whenever either guess below is still pending it is
        // exactly the highest pending bit and the step needs no scan:
        // `predicted` resolves contiguous runs of `d`, `predicted >> 1`
        // resolves masks alternating set and clear bits. Both guesses fail
        // against an exhausted iterator (`x & 0` is always zero), so the
        // end-of-iteration check rides behind them instead of costing every
        // step a test.
        let mut b = self.predicted;

        if b & self.remaining == 0 {
            b >>= 1;

            if b & self.remaining == 0 {
                if self.remaining == 0 {
                    return None;
                }

                // Both guesses miss with bits still pending only on the first
                // call, after a three-or-more bit gap in `d`, or once
                // back-iteration has drained `remaining` down past the
                // guesses. The call keeps the rescue a real branch: a
                // conditional move would chain the scan back into every
                // step's dependencies.
                core::hint::cold_path();
                b = 0x8000_0000u32 >> self.remaining.leading_zeros();
            }
        }

        self.predicted = b >> 1;
        self.mask |= b;
        let addr = (self.addr ^ b) & self.mask;
        self.remaining ^= b;

        // NOTE: address is already normalized by the `& mask` above.
        Some(Ipv4Network(Ipv4Addr::from_bits(addr), Ipv4Addr::from_bits(self.mask)))
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.len();
        (n, Some(n))
    }

    #[inline]
    fn last(mut self) -> Option<Self::Item> {
        // The last item in forward order is the one for `remaining`'s lowest
        // bit, which is exactly what `next_back` computes: O(1) instead of
        // the default's full O(n) walk.
        self.next_back()
    }
}

impl DoubleEndedIterator for Ipv4NetworkDiff {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        // Lowest remaining bit of `d`, the mirror of `next()`'s highest-bit peel.
        let b = self.remaining & self.remaining.wrapping_neg();

        // The item for `b` is fixed by `b` alone: `mask` already holds every
        // bit of `d` above the whole `remaining` band (folded in by prior
        // `next()` calls), and `remaining` holds every bit from `b` upward
        // that is still pending, so their union is exactly the bits of `d`
        // at or above `b`. Unlike `next()`, `b` must NOT be folded into
        // `self.mask`: bits peeled from the back sit below every bit any
        // future item (front or back) will use.
        let mask = self.mask | self.remaining;
        let addr = (self.addr ^ b) & mask;
        self.remaining ^= b;

        // NOTE: address is already normalized by the `& mask` above.
        Some(Ipv4Network(Ipv4Addr::from_bits(addr), Ipv4Addr::from_bits(mask)))
    }
}

impl ExactSizeIterator for Ipv4NetworkDiff {
    #[inline]
    fn len(&self) -> usize {
        self.remaining.count_ones() as usize
    }
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
    /// Remaining ascending-phase block sizes, one per set bit, lowest first —
    /// zero once the iterator enters the descending phase.
    ascending: u32,
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

    if first > last {
        return Ipv4RangeNetworks {
            first,
            last,
            ascending: 0,
            done: true,
        };
    }

    // The greedy covering crosses the highest differing bit `p` of `first` and
    // `last` only when the whole range is one CIDR block (`differing` is an
    // all-ones suffix and `first` is aligned to it). Otherwise the blocks
    // below the boundary — `last` with the bits below `p` cleared — are
    // exactly the set bits of `boundary - first`, yielded lowest-first, and
    // the remaining blocks are derived from `last` on the fly. A zero
    // `ascending` therefore encodes "descending phase only".
    let differing = first ^ last;
    let single_block = differing & differing.wrapping_add(1) == 0 && first & differing == 0;
    let ascending = if single_block {
        0
    } else {
        let bit = 1u32 << (31 - differing.leading_zeros());
        (last & bit.wrapping_neg()) - first
    };

    Ipv4RangeNetworks { first, last, ascending, done: false }
}

impl Iterator for Ipv4RangeNetworks {
    type Item = Contiguous<Ipv4Network>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let first = self.first;
        let ascending = self.ascending;

        if ascending != 0 {
            // Ascending phase: the block size is the lowest set bit of
            // `ascending` and `first` is aligned to it, so `x | -x` — all bits
            // from that bit upwards — is the block's netmask. The phase never
            // exhausts the range: at least one descending block follows.
            let negated = ascending.wrapping_neg();
            let block = ascending & negated;
            let mask = ascending | negated;
            self.ascending = ascending ^ block;
            self.first = first + block;
            // NOTE: address is already normalized: `first` is aligned to `block`.
            return Some(Contiguous(Ipv4Network(
                Ipv4Addr::from_bits(first),
                Ipv4Addr::from_bits(mask),
            )));
        }

        // Descending phase: `first` is aligned beyond the remaining size, so
        // the block is the largest power of two not exceeding `size`. Widening
        // to u64 keeps the full-range (2^32 addresses) case branchless.
        let size = u64::from(self.last) - u64::from(first) + 1;
        let block_max = ((u64::MAX >> 1) >> size.leading_zeros()) as u32;
        let end = first + block_max;
        self.done = end == self.last;
        self.first = end.wrapping_add(1);
        // NOTE: address is already normalized: `first` is aligned beyond `block_max`.
        Some(Contiguous(Ipv4Network(
            Ipv4Addr::from_bits(first),
            Ipv4Addr::from_bits(!block_max),
        )))
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
/// non-contiguous bits set to one, such as
/// `2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0`.
///
/// [IETF RFC 4632]: https://tools.ietf.org/html/rfc4632
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
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
    #[inline]
    pub fn parse(buf: &str) -> Result<Self, IpNetParseError> {
        parser::parse_ipv6_network(buf)
    }

    /// Parses the specified ASCII byte buffer into an IPv6 network.
    ///
    /// The buffer does not need to be valid UTF-8, so slices cut from a
    /// larger byte stream can be parsed without a validation pass. The
    /// accepted formats match [`Self::parse`].
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::Ipv6Network;
    ///
    /// let expected = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0, 0, 0),
    ///     Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0, 0, 0, 0),
    /// );
    ///
    /// assert_eq!(
    ///     expected,
    ///     Ipv6Network::parse_ascii(b"2a02:6b8:c00::/40").unwrap()
    /// );
    /// assert_eq!(
    ///     expected,
    ///     Ipv6Network::parse_ascii(b"2a02:6b8:c00::/ffff:ffff:ff00::").unwrap()
    /// );
    /// ```
    #[inline]
    pub fn parse_ascii(buf: &[u8]) -> Result<Self, IpNetParseError> {
        parser::parse_ipv6_network_ascii(buf)
    }

    /// Parses the leading network token of `buf` into an IPv6 network,
    /// returning it with the unconsumed remainder.
    ///
    /// The token is the maximal leading run of network characters
    /// (`[0-9a-fA-F:./+]`) and must parse as a whole: a malformed token is
    /// an error, never a shorter partial parse. Leading whitespace is not
    /// skipped. This suits pulling networks out of a larger rule text.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::net::Ipv6Addr;
    ///
    /// use netip::Ipv6Network;
    ///
    /// let expected = Ipv6Network::new(
    ///     Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0, 0, 0),
    ///     Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0, 0, 0, 0),
    /// );
    ///
    /// let (network, rest) = Ipv6Network::parse_next_ascii(b"2a02:6b8:c00::/40, next").unwrap();
    /// assert_eq!(expected, network);
    /// assert_eq!(b", next", rest);
    /// ```
    #[inline]
    pub fn parse_next_ascii(buf: &[u8]) -> Result<(Self, &[u8]), IpNetParseError> {
        parser::parse_ipv6_network_next_ascii(buf)
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
    /// The result contains exactly `popcount(m2 & !m1)` pairwise-disjoint
    /// networks when `self` and `other` overlap (0 if `self` is a subset of
    /// `other`, at most 128 otherwise), or exactly 1 if they are disjoint —
    /// never merely an upper bound, and provably the minimum number of
    /// networks (including non-contiguous ones) that can represent the
    /// difference. Works correctly with non-contiguous masks.
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

    /// Checks whether this network's mask is bi-contiguous, i.e. each 64-bit
    /// half of the mask (the high half and the low half) is on its own a
    /// contiguous run of leading one bits.
    ///
    /// A bi-contiguous mask describes an axis-aligned rectangle on the (high
    /// 64 bits, low 64 bits) plane: `concat(1^p 0^(64-p), 1^q 0^(64-q))` for
    /// some `p, q` in `0..=64`. Every contiguous mask is bi-contiguous (`q =
    /// 0`, or `p = 64`), but not every bi-contiguous mask is contiguous. See
    /// [`BiContiguous`] for the type that carries this guarantee.
    ///
    /// A mask is bi-contiguous exactly when every maximal run of one bits
    /// ends either at bit 127 (the top of the address) or at bit 63 (the top
    /// of the low half) -- checked by clearing those two allowed positions
    /// from the set of run-tops and requiring nothing remains.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::Ipv6Network;
    ///
    /// // Contiguous masks are always bi-contiguous.
    /// assert!(Ipv6Network::parse("::/0").unwrap().is_bicontiguous());
    /// assert!(
    ///     Ipv6Network::parse("2a02:6b8:c00::/40")
    ///         .unwrap()
    ///         .is_bicontiguous()
    /// );
    ///
    /// // Two separate runs, one per 64-bit half.
    /// assert!(
    ///     Ipv6Network::parse("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
    ///         .unwrap()
    ///         .is_bicontiguous()
    /// );
    ///
    /// // An interior hole inside the low half breaks bi-contiguity.
    /// assert!(
    ///     !Ipv6Network::parse("2a02:6b8:0:0:1234:5678::/ffff:ffff:0:0:f0f0:f0f0:f0f0:f0f0")
    ///         .unwrap()
    ///         .is_bicontiguous()
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_bicontiguous(&self) -> bool {
        const CLEAR: u128 = !((1u128 << 127) | (1u128 << 63));
        let mask = self.mask().to_bits();
        (mask & !(mask >> 1)) & CLEAR == 0
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
    #[inline]
    #[must_use]
    pub const fn to_contiguous(&self) -> Self {
        let (addr, mask) = self.to_bits();

        // NOTE: `mask.leading_ones()` is at most 128, which `ipv6_mask_from_cidr`
        // always accepts.
        match ipv6_mask_from_cidr(mask.leading_ones() as u8) {
            Ok(mask) => Self::new(Ipv6Addr::from_bits(addr), mask),
            Err(..) => unreachable!(),
        }
    }

    /// Converts this network to an [`IPv4` network] if it's an IPv4-mapped
    /// network, as defined in [IETF RFC 4291 section 2.5.5.2], otherwise
    /// returns [`None`].
    ///
    /// The mapped network `::ffff:a.b.c.d/N` becomes `a.b.c.d/M`, where
    /// `M = N - 96`. All networks with their addresses *not* starting with
    /// `::ffff` will return `None`.
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

            // NOTE: address is already normalized: truncation preserves `addr & mask ==
            // addr`.
            Some(Ipv4Network(Ipv4Addr::from_bits(addr), Ipv4Addr::from_bits(mask)))
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
        // For a contiguous mask every set bit is in the leading run, so its
        // popcount equals `leading_ones`. The dedicated contiguity check is
        // cheaper than recomputing the popcount here.
        if self.is_contiguous() {
            Some(self.mask().to_bits().leading_ones() as u8)
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
    #[inline]
    #[must_use]
    pub fn supernet_for(&self, nets: &[Ipv6Network]) -> Ipv6Network {
        // AND/XOR/NOT commute with byte order, so the fold runs bytewise in memory
        // order: this removes four per-element byte swaps, and the fixed 16-byte
        // inner loop keeps an auto-vectorizable shape instead of emulated u128
        // arithmetic.
        //
        // Folding four networks per step into `mask` plus three all-ones `lanes`
        // breaks the loop-carried AND dependency chain. AND is associative and
        // commutative, so combining the lanes afterwards is bit-identical to the
        // sequential fold.
        let addr = self.addr().octets();
        let mut mask = self.mask().octets();
        let mut lanes = [[0xff_u8; 16]; 3];

        let mut quads = nets.chunks_exact(4);
        for quad in &mut quads {
            let (a0, m0) = (quad[0].addr().octets(), quad[0].mask().octets());
            let (a1, m1) = (quad[1].addr().octets(), quad[1].mask().octets());
            let (a2, m2) = (quad[2].addr().octets(), quad[2].mask().octets());
            let (a3, m3) = (quad[3].addr().octets(), quad[3].mask().octets());
            for i in 0..16 {
                mask[i] &= m0[i] & !(addr[i] ^ a0[i]);
                lanes[0][i] &= m1[i] & !(addr[i] ^ a1[i]);
                lanes[1][i] &= m2[i] & !(addr[i] ^ a2[i]);
                lanes[2][i] &= m3[i] & !(addr[i] ^ a3[i]);
            }
        }
        for net in quads.remainder() {
            let a = net.addr().octets();
            let m = net.mask().octets();
            for i in 0..16 {
                mask[i] &= m[i] & !(addr[i] ^ a[i]);
            }
        }
        for lane in &lanes {
            for i in 0..16 {
                mask[i] &= lane[i];
            }
        }

        Self::new(Ipv6Addr::from(addr), Ipv6Addr::from(mask))
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

    /// Returns `true` if this network is adjacent to `other` at the lowest set
    /// bit of their shared mask.
    ///
    /// This is the strict restriction of [`is_adjacent`](Self::is_adjacent) to
    /// the mask's lowest set bit — the boundary ("buddy") bit that separates a
    /// block from its immediate parent. The two networks must share the same
    /// mask and their addresses must differ in exactly that single bit.
    ///
    /// Every pair accepted here is also accepted by
    /// [`is_adjacent`](Self::is_adjacent), but not conversely: `is_adjacent`
    /// additionally accepts a difference in any other single masked bit. This
    /// is precisely the adjacency whose merge preserves the mask's structural
    /// class — merging two contiguous (CIDR) blocks at their buddy bit yields a
    /// contiguous parent, whereas merging at a higher bit would punch a hole
    /// and leave the contiguous class.
    ///
    /// Identical networks are **not** adjacent, and a `/0` network is never
    /// adjacent to anything. Works correctly with non-contiguous masks.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::Ipv6Network;
    ///
    /// // CIDR siblings differ in the lowest mask bit: both predicates hold,
    /// // and they would merge into a /47.
    /// let a = Ipv6Network::parse("2001:db8::/48").unwrap();
    /// let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
    /// assert!(a.is_adjacent(&b));
    /// assert!(a.is_adjacent_by_lowest_mask_bit(&b));
    ///
    /// // Adjacent at the *top* mask bit, not the lowest: `is_adjacent`
    /// // accepts it, `is_adjacent_by_lowest_mask_bit` rejects it (merging there
    /// // would leave the contiguous class).
    /// let c = Ipv6Network::parse("::/2").unwrap();
    /// let d = Ipv6Network::parse("8000::/2").unwrap();
    /// assert!(c.is_adjacent(&d));
    /// assert!(!c.is_adjacent_by_lowest_mask_bit(&d));
    ///
    /// // Identical or different-mask networks are never adjacent.
    /// assert!(!a.is_adjacent_by_lowest_mask_bit(&a));
    /// let e = Ipv6Network::parse("2001:db8::/32").unwrap();
    /// assert!(!a.is_adjacent_by_lowest_mask_bit(&e));
    ///
    /// // Non-contiguous masks are supported: these differ in the lowest set
    /// // bit of `ffff:ffff::ffff` (bit 0 of the low group).
    /// let x = Ipv6Network::parse("::/ffff:ffff::ffff").unwrap();
    /// let y = Ipv6Network::parse("::1/ffff:ffff::ffff").unwrap();
    /// assert!(x.is_adjacent_by_lowest_mask_bit(&y));
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_adjacent_by_lowest_mask_bit(&self, other: &Self) -> bool {
        let (a1, m1) = self.to_bits();
        let (a2, m2) = other.to_bits();
        ipv6_adjacent_by_lowest_mask_bit(a1, m1, a2, m2)
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
            let diff = a1 ^ a2;
            if diff & diff.wrapping_sub(1) == 0 {
                // diff == 0 (duplicate) or a single bit (mergeable siblings).
                let mask = m1 ^ diff;
                return Some(Self(Ipv6Addr::from_bits(a1 & mask), Ipv6Addr::from_bits(mask)));
            }
            return None;
        }

        let mask_common = m1 & m2;
        if mask_common == m2 {
            // Only `other` can contain `self`.
            return if a1 & m2 == a2 { Some(*other) } else { None };
        }
        if mask_common == m1 {
            // Only `self` can contain `other`.
            return if a2 & m1 == a1 { Some(*self) } else { None };
        }
        None
    }

    /// Merges this IPv6 network with another when one contains the other or
    /// they are lowest-mask-bit siblings, returning the combined network.
    ///
    /// Returns `Some` in exactly two disjoint cases:
    ///
    /// - **Containment**: one network is a subset of the other. The larger
    ///   (containing) network is returned, exactly as [`merge`](Self::merge)
    ///   does.
    /// - **Lowest-mask-bit sibling**: the two share a mask and their addresses
    ///   differ in precisely its lowest set bit — the boundary "buddy" bit,
    ///   detected by
    ///   [`is_adjacent_by_lowest_mask_bit`](Self::is_adjacent_by_lowest_mask_bit).
    ///   The result is the common address `a1 & a2` (the differing lowest bit
    ///   cleared) under the shared mask with its lowest set bit removed.
    ///
    /// These cases are disjoint: siblings have equal masks and distinct
    /// addresses, so neither contains the other.
    ///
    /// This is the class-closed subset of [`merge`](Self::merge) —
    /// `{containment, lowest-mask-bit sibling}`. It differs from `merge` only
    /// by refusing `merge`'s remaining case, a difference at a higher
    /// (non-lowest) mask bit, which would combine the pair into a network
    /// outside the inputs' structural class. Refusing it keeps the result
    /// in class: a contiguous (CIDR) pair merges to a contiguous parent, a
    /// bi-contiguous pair to a bi-contiguous parent, a general
    /// non-contiguous pair to a non-contiguous parent, and a containment
    /// result is simply the larger input, already in class. Whenever it
    /// returns `Some`, that value equals [`merge`](Self::merge)'s.
    ///
    /// For a bi-contiguous mask (one carrying a top-aligned run in each 64-bit
    /// half), sibling merging happens only along the finer low-half boundary —
    /// the mask's lowest set bit. A sibling pair differing in the high-half
    /// boundary is left unmerged even though their union would also be
    /// bi-contiguous. Performing that merge would require assuming the value is
    /// bi-contiguous, which this general-purpose method does not.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::Ipv6Network;
    ///
    /// // Adjacent /48 blocks (lowest-bit siblings) merge into a /47, and
    /// // `merge` agrees.
    /// let a = Ipv6Network::parse("2001:db8::/48").unwrap();
    /// let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
    /// assert_eq!(
    ///     Some(Ipv6Network::parse("2001:db8::/47").unwrap()),
    ///     a.merge_by_lowest_mask_bit(&b)
    /// );
    /// assert_eq!(a.merge(&b), a.merge_by_lowest_mask_bit(&b));
    ///
    /// // Containment: the larger (containing) network is returned, either way.
    /// let outer = Ipv6Network::parse("2001:db8::/32").unwrap();
    /// let inner = Ipv6Network::parse("2001:db8:1::/48").unwrap();
    /// assert_eq!(Some(outer), outer.merge_by_lowest_mask_bit(&inner));
    /// assert_eq!(Some(outer), inner.merge_by_lowest_mask_bit(&outer));
    ///
    /// // Adjacent at a higher mask bit: `merge` combines the pair into a
    /// // non-contiguous block, but `merge_by_lowest_mask_bit` refuses to leave
    /// // the contiguous class.
    /// let c = Ipv6Network::parse("2001:db8::/48").unwrap();
    /// let d = Ipv6Network::parse("2001:db8:100::/48").unwrap();
    /// assert_eq!(
    ///     Some(Ipv6Network::parse("2001:db8::/ffff:ffff:feff::").unwrap()),
    ///     c.merge(&d)
    /// );
    /// assert_eq!(None, c.merge_by_lowest_mask_bit(&d));
    ///
    /// // Disjoint networks with different masks never merge here.
    /// let e = Ipv6Network::parse("2001:beef::/32").unwrap();
    /// assert_eq!(None, a.merge_by_lowest_mask_bit(&e));
    ///
    /// // Bi-contiguous mask: siblings differing in the lowest set bit of
    /// // `ffff::ffff:ffff:ffff:ffff` collapse to `ffff::ffff:ffff:ffff:fffe`,
    /// // which is still bi-contiguous.
    /// let x = Ipv6Network::parse("::/ffff::ffff:ffff:ffff:ffff").unwrap();
    /// let y = Ipv6Network::parse("::1/ffff::ffff:ffff:ffff:ffff").unwrap();
    /// assert_eq!(
    ///     Some(Ipv6Network::parse("::/ffff::ffff:ffff:ffff:fffe").unwrap()),
    ///     x.merge_by_lowest_mask_bit(&y)
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn merge_by_lowest_mask_bit(&self, other: &Self) -> Option<Self> {
        let (a1, m1) = self.to_bits();
        let (a2, m2) = other.to_bits();

        if m1 == m2 {
            // Equal masks: containment degenerates to network equality, so both
            // `contains` probes collapse to one address compare.
            if a1 == a2 {
                return Some(*self);
            }

            if ipv6_adjacent_by_lowest_mask_bit(a1, m1, a2, m2) {
                // NOTE: the addresses differ only in the mask's lowest set bit,
                // which the reduced mask clears, so `a1 & a2` is already
                // normalized and needs no further `& mask`.
                return Some(Self(
                    Ipv6Addr::from_bits(a1 & a2),
                    Ipv6Addr::from_bits(m1 & m1.wrapping_sub(1)),
                ));
            }

            return None;
        }

        // Different masks: adjacency requires equal masks, so containment is
        // the only remaining way to merge.
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
    /// # Correctness
    ///
    /// Same argument as [`Ipv4Network::last_addr`].
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

        // The /0 network's 2^128 does not fit `u128`, so its count saturates
        // to `2^128 - 1`. The one-address deficit is unobservable: reaching it
        // would take 2^128 - 1 iterator steps, and `size_hint` reports every
        // count above `usize::MAX` as `(usize::MAX, None)` anyway.
        let remaining = 1u128.checked_shl(host_bits).unwrap_or(u128::MAX);

        Ipv6NetworkAddrs {
            base: addr,
            mask,
            front_addr: addr,
            back_addr: addr | !mask,
            remaining,
        }
    }
}

// Total order on the `(addr, mask)` pair compared as `u128`s, in place of the
// derived lexicographic comparison of the two `Ipv6Addr` fields.
//
// `Ipv6Addr`'s own comparison is lexicographic over its eight `u16` segments,
// which agrees with the numeric order of the big-endian `u128` returned by
// `to_bits()`, so comparing the bit patterns directly reaches the same
// verdict without walking the segments one at a time.
//
// Branching on address equality instead of tupling `(addr, mask).cmp(&(..))`
// avoids wasted work on the common "same address, mask decides" path:
// `Ord`'s derived tuple comparison unconditionally computes the full scalar
// ordering of `addr` before checking whether it was even equal, so that
// result gets thrown away exactly when the address matches and the mask
// comparison is about to overwrite it. Testing address equality first and
// only falling through to the mask comparison when needed skips that
// discarded computation entirely.
impl Ord for Ipv6Network {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        let (self_addr, self_mask) = self.to_bits();
        let (other_addr, other_mask) = other.to_bits();

        if self_addr == other_addr {
            self_mask.cmp(&other_mask)
        } else {
            self_addr.cmp(&other_addr)
        }
    }
}

// Delegates to `Ord::cmp`, which defines `Ipv6Network`'s total order.
impl PartialOrd for Ipv6Network {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
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
/// When the iterator is exhausted (`remaining == 0`) every subsequent call to
/// [`next`](Iterator::next) or [`next_back`](DoubleEndedIterator::next_back)
/// returns [`None`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6NetworkAddrs {
    base: u128,
    mask: u128,
    /// Next address to yield from the front end, stepped in O(1) per item.
    front_addr: u128,
    /// Next address to yield from the back end, stepped in O(1) per item.
    back_addr: u128,
    /// Number of addresses not yet yielded, saturating to `u128::MAX` for the
    /// /0 network's `2^128`.
    remaining: u128,
}

impl Iterator for Ipv6NetworkAddrs {
    type Item = Ipv6Addr;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        self.remaining -= 1;

        let host_mask = !self.mask;
        let bits = self.front_addr;

        self.front_addr = if host_mask & host_mask.wrapping_add(1) == 0 {
            // Contiguous mask (trailing zeros only): a plain increment steps
            // to the next address. The overrun past the last one is repaired
            // by the exhaustion canonicalization below.
            bits.wrapping_add(1)
        } else {
            // O(1) step to the next host pattern: with the mask bits preset
            // to one, the +1 carry ripples straight across them between host
            // positions.
            ((bits | self.mask).wrapping_add(1) & host_mask) | self.base
        };

        // On exhaustion park the front cursor on `base`, so that every drain
        // script ending in `next_back` collapses into one sentinel state while
        // an all-front overrun keeps its stepped `back_addr` as a distinct
        // (still exhausted) state.
        if self.remaining == 0 {
            self.front_addr = self.base;
        }

        Some(Ipv6Addr::from_bits(bits))
    }

    #[inline]
    fn count(self) -> usize {
        let (n, ..) = self.size_hint();
        n
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match usize::try_from(self.remaining) {
            Ok(n) => (n, Some(n)),
            Err(..) => (usize::MAX, None),
        }
    }
}

impl DoubleEndedIterator for Ipv6NetworkAddrs {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        self.remaining -= 1;

        let host_mask = !self.mask;
        let bits = self.back_addr;

        self.back_addr = if host_mask & host_mask.wrapping_add(1) == 0 {
            // Contiguous mask (trailing zeros only): a plain decrement steps
            // to the previous address. The underrun past the first one is
            // repaired by the exhaustion canonicalization below.
            bits.wrapping_sub(1)
        } else {
            // O(1) step to the previous host pattern: with the mask bits
            // cleared, the -1 borrow ripples straight across them between
            // host positions.
            ((bits & host_mask).wrapping_sub(1) & host_mask) | self.base
        };

        // On exhaustion park both cursors on `base`, the shared sentinel for
        // every drain script whose last item came off the back end.
        if self.remaining == 0 {
            self.front_addr = self.base;
            self.back_addr = self.base;
        }

        Some(Ipv6Addr::from_bits(bits))
    }
}

/// Lazy iterator over [`Ipv6Network`] parts of a set difference.
///
/// Created by [`Ipv6Network::difference`].
///
/// Yields between 0 and 128 pairwise-disjoint networks whose union equals the
/// address set of `A` minus the address set of `B`.
///
/// Each call to [`next`](Iterator::next) computes one network by peeling the
/// highest remaining bit from the difference mask. Each call to
/// [`next_back`](DoubleEndedIterator::next_back) peels the lowest remaining
/// bit instead. Consumption from either end is O(1) and the two can be
/// freely interleaved.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6NetworkDiff {
    /// Intersection address, or an encoded address for the disjoint shortcut.
    addr: u128,
    /// Mask of the source network, gaining one bit of `d` per `next()` call
    /// (or with one bit cleared for the disjoint shortcut).
    mask: u128,
    /// Bits of `d` not yet yielded.
    remaining: u128,
    /// Prediction of `next()`'s upcoming peel bit: one position below the
    /// last bit yielded, zero before the first call. Pending bits only ever
    /// sit at or below it, so whenever it — or, failing that, its next lower
    /// neighbour — is still pending, that guess is exactly the highest
    /// pending bit and `next()` skips the scan for it.
    predicted: u128,
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
                    remaining: b,
                    predicted: 0,
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
                        remaining: 0,
                        predicted: 0,
                    }
                } else {
                    // General case: peel one network per bit of d.
                    Self {
                        addr: inter_addr,
                        mask,
                        remaining: d,
                        predicted: 0,
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
        // Working in generic `u128` arithmetic would cost double-word
        // instruction pairs on every step, so each arm below runs the whole
        // step — guess validation, rescue scan, and peel — pinned to the
        // 64-bit half holding the highest pending bit, and the compiler
        // lowers it to single-word instructions. The prediction is stored
        // full-width, so it survives the arm switch at the word boundary.
        let remaining = (self.remaining >> 64) as u64;

        if remaining != 0 {
            // After the first peel every pending bit sits at or below
            // `predicted`, so whenever either guess below is still pending it
            // is exactly the highest pending bit and the step needs no scan:
            // `predicted` resolves contiguous runs of `d`, `predicted >> 1`
            // resolves masks alternating set and clear bits.
            let mut b = (self.predicted >> 64) as u64;

            if b & remaining == 0 {
                b >>= 1;

                if b & remaining == 0 {
                    // Both guesses miss only on the first call, after a
                    // three-or-more bit gap in `d`, or once back-iteration has
                    // drained `remaining` down past the guesses. The call
                    // keeps the rescue a real branch: a conditional move would
                    // chain the scan back into every step's dependencies.
                    core::hint::cold_path();
                    b = 0x8000_0000_0000_0000u64 >> remaining.leading_zeros();
                }
            }

            self.predicted = (b as u128) << 63;
            let b = (b as u128) << 64;
            self.mask |= b;
            let addr = (self.addr ^ b) & self.mask;
            self.remaining ^= b;

            // NOTE: address is already normalized by the `& mask` above.
            return Some(Ipv6Network(Ipv6Addr::from_bits(addr), Ipv6Addr::from_bits(self.mask)));
        }

        // An empty high half puts every pending bit in the low one, so the
        // truncated prediction loses nothing pending. Right after a peel of
        // bit 64 it still carries the in-range bit 63 (stored full-width
        // above). Only a guess straddling the boundary from higher up
        // degrades into the rescue, at most once per iteration lifetime.
        let remaining = self.remaining as u64;
        let mut b = self.predicted as u64;

        if b & remaining == 0 {
            b >>= 1;

            if b & remaining == 0 {
                // Both guesses fail against an exhausted iterator (`x & 0` is
                // always zero), so the end-of-iteration check rides here
                // instead of costing every step a test.
                if remaining == 0 {
                    return None;
                }

                core::hint::cold_path();
                b = 0x8000_0000_0000_0000u64 >> remaining.leading_zeros();
            }
        }

        self.predicted = (b >> 1) as u128;
        let b = b as u128;
        self.mask |= b;
        let addr = (self.addr ^ b) & self.mask;
        self.remaining ^= b;

        // NOTE: address is already normalized by the `& mask` above.
        Some(Ipv6Network(Ipv6Addr::from_bits(addr), Ipv6Addr::from_bits(self.mask)))
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.len();
        (n, Some(n))
    }

    #[inline]
    fn last(mut self) -> Option<Self::Item> {
        // The last item in forward order is the one for `remaining`'s lowest
        // bit, which is exactly what `next_back` computes: O(1) instead of
        // the default's full O(n) walk.
        self.next_back()
    }
}

impl DoubleEndedIterator for Ipv6NetworkDiff {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        // Lowest remaining bit of `d`, the mirror of `next()`'s highest-bit peel.
        let b = self.remaining & self.remaining.wrapping_neg();

        // The item for `b` is fixed by `b` alone: `mask` already holds every
        // bit of `d` above the whole `remaining` band (folded in by prior
        // `next()` calls), and `remaining` holds every bit from `b` upward
        // that is still pending, so their union is exactly the bits of `d`
        // at or above `b`. Unlike `next()`, `b` must NOT be folded into
        // `self.mask`: bits peeled from the back sit below every bit any
        // future item (front or back) will use.
        let mask = self.mask | self.remaining;
        let addr = (self.addr ^ b) & mask;
        self.remaining ^= b;

        // NOTE: address is already normalized by the `& mask` above.
        Some(Ipv6Network(Ipv6Addr::from_bits(addr), Ipv6Addr::from_bits(mask)))
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
    /// Remaining ascending-phase block sizes, one per set bit, lowest first —
    /// zero once the iterator enters the descending phase.
    ascending: u128,
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

    if first > last {
        return Ipv6RangeNetworks {
            first,
            last,
            ascending: 0,
            done: true,
        };
    }

    // Same phase decomposition as `ipv4_range_to_networks`: the set bits of
    // `boundary - first` are the ascending-phase block sizes unless the whole
    // range is one CIDR block, encoded as a zero `ascending`.
    let differing = first ^ last;
    let single_block = differing & differing.wrapping_add(1) == 0 && first & differing == 0;
    let ascending = if single_block {
        0
    } else {
        let bit = 1u128 << (127 - differing.leading_zeros());
        (last & bit.wrapping_neg()) - first
    };

    Ipv6RangeNetworks { first, last, ascending, done: false }
}

impl Iterator for Ipv6RangeNetworks {
    type Item = Contiguous<Ipv6Network>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let first = self.first;
        let ascending = self.ascending;

        if ascending != 0 {
            // Ascending phase: the block size is the lowest set bit of
            // `ascending` and `first` is aligned to it, so `x | -x` — all bits
            // from that bit upwards — is the block's netmask. The phase never
            // exhausts the range: at least one descending block follows.
            let negated = ascending.wrapping_neg();
            let block = ascending & negated;
            let mask = ascending | negated;
            self.ascending = ascending ^ block;
            self.first = first + block;
            // NOTE: address is already normalized: `first` is aligned to `block`.
            return Some(Contiguous(Ipv6Network(
                Ipv6Addr::from_bits(first),
                Ipv6Addr::from_bits(mask),
            )));
        }

        // Descending phase: `first` is aligned beyond the remaining size, so
        // the block is the largest power of two not exceeding `size`. The size
        // wraps to zero only for the full address range, covered by `::/0`.
        // Splitting into 64-bit words keeps the leading-zeros scan and the
        // shift on native words instead of two-word emulated u128 forms.
        let size = self.last.wrapping_sub(first).wrapping_add(1);
        let high = (size >> 64) as u64;
        let block_max = if high != 0 {
            u128::from((u64::MAX >> 1) >> high.leading_zeros()) << 64 | u128::from(u64::MAX)
        } else {
            let low = size as u64;
            if low == 0 {
                u128::MAX
            } else {
                u128::from((u64::MAX >> 1) >> low.leading_zeros())
            }
        };
        let end = first + block_max;
        self.done = end == self.last;
        self.first = end.wrapping_add(1);
        // NOTE: address is already normalized: `first` is aligned beyond `block_max`.
        Some(Contiguous(Ipv6Network(
            Ipv6Addr::from_bits(first),
            Ipv6Addr::from_bits(!block_max),
        )))
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

    #[inline]
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

    // Pass 2: scan windows left to right. Strict `>` keeps the first-seen
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
    + Not<Output = Self>
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + BitOrAssign
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

    // Greedy in-place aggregation. Each candidate is merged against the entire
    // stack rather than just its top: non-contiguous masks are not laminar, so
    // a merge partner may sit below the top, unlike the contiguous aggregator.
    //
    // A merge at position `k` can expose new partners (two /24 siblings merge
    // into /23 siblings), so the stack is rescanned against `nets[k]` until
    // nothing more merges.
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
    fn parse_ipv4_non_contiguous_mask() {
        assert_eq!(
            Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(255, 255, 0, 255)),
            Ipv4Network::parse("192.168.0.1/255.255.0.255").unwrap()
        );
        // Address bits outside a non-contiguous mask are cleared.
        assert_eq!(
            Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(255, 255, 0, 255)),
            Ipv4Network::parse("192.168.7.1/255.255.0.255").unwrap()
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

    // Reference for the `addrs` iterators: the original per-item software-pdep
    // expansion of a host index into the mask's zero bits (for a contiguous
    // host mask pdep is the identity, so no shortcut is needed here).
    fn pdep_u32_reference(mut src: u32, mut mask: u32) -> u32 {
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

    fn pdep_u128_reference(mut src: u128, mut mask: u128) -> u128 {
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

    fn ipv4_addr_at_host_index_reference(net: &Ipv4Network, index: u32) -> Ipv4Addr {
        let (base, mask) = net.to_bits();
        Ipv4Addr::from_bits(base | pdep_u32_reference(index, !mask))
    }

    fn ipv6_addr_at_host_index_reference(net: &Ipv6Network, index: u128) -> Ipv6Addr {
        let (base, mask) = net.to_bits();
        Ipv6Addr::from_bits(base | pdep_u128_reference(index, !mask))
    }

    // Pins `last()`'s default forward-walk output on purpose.
    #[allow(clippy::double_ended_iterator_last)]
    #[test]
    fn ipv4_addrs_non_contiguous_pins_forward_and_reverse_order() {
        let net = Ipv4Network::parse("10.0.0.1/255.255.15.255").unwrap();
        let expected: Vec<_> = (0u32..16).map(|k| Ipv4Addr::new(10, 0, (16 * k) as u8, 1)).collect();

        let forward: Vec<_> = net.addrs().collect();
        assert_eq!(expected, forward);

        let mut reversed: Vec<_> = net.addrs().rev().collect();
        reversed.reverse();
        assert_eq!(expected, reversed);

        assert_eq!(16, net.addrs().len());
        assert_eq!((16, Some(16)), net.addrs().size_hint());
        assert_eq!(16, net.addrs().count());
        assert_eq!(Some(Ipv4Addr::new(10, 0, 240, 1)), net.addrs().last());
    }

    #[test]
    fn ipv4_addrs_non_contiguous_pins_interleaved_next_and_next_back() {
        let net = Ipv4Network::parse("10.0.0.1/255.255.15.255").unwrap();
        let at = |k: u32| Ipv4Addr::new(10, 0, (16 * k) as u8, 1);
        let mut addrs = net.addrs();

        assert_eq!(Some(at(0)), addrs.next());
        assert_eq!(Some(at(15)), addrs.next_back());
        assert_eq!(Some(at(14)), addrs.next_back());
        assert_eq!(13, addrs.len());
        assert_eq!((13, Some(13)), addrs.size_hint());
        assert_eq!(Some(at(1)), addrs.next());
        assert_eq!(Some(at(2)), addrs.next());
        assert_eq!(Some(at(13)), addrs.next_back());

        for k in 3..13 {
            assert_eq!(Some(at(k)), addrs.next());
        }

        assert_eq!(0, addrs.len());
        assert_eq!((0, Some(0)), addrs.size_hint());
        assert_eq!(None, addrs.next());
        assert_eq!(None, addrs.next_back());
    }

    // Pins `last()`'s default forward-walk output on purpose.
    #[allow(clippy::double_ended_iterator_last)]
    #[test]
    fn ipv4_addrs_edge_masks_pin_len_and_size_hint() {
        let single = Ipv4Network::parse("10.0.0.1/32").unwrap();
        assert_eq!(1, single.addrs().len());
        assert_eq!((1, Some(1)), single.addrs().size_hint());
        assert_eq!(1, single.addrs().count());
        assert_eq!(Some(Ipv4Addr::new(10, 0, 0, 1)), single.addrs().last());

        let full = Ipv4Network::parse("0.0.0.0/0").unwrap();
        assert_eq!(1usize << 32, full.addrs().len());
        assert_eq!((usize::MAX, None), full.addrs().size_hint());

        let mut addrs = full.addrs();
        assert_eq!(Some(Ipv4Addr::new(0, 0, 0, 0)), addrs.next());
        assert_eq!(Some(Ipv4Addr::new(0, 0, 0, 1)), addrs.next());
        assert_eq!(Some(Ipv4Addr::new(255, 255, 255, 255)), addrs.next_back());
        assert_eq!(Some(Ipv4Addr::new(255, 255, 255, 254)), addrs.next_back());
        assert_eq!((1usize << 32) - 4, addrs.len());
    }

    #[test]
    fn ipv4_addrs_exhausted_iterators_pin_equality_by_drain_path() {
        // A single non-contiguous host bit (bit 1), so exactly two addresses.
        let net = Ipv4Network::parse("10.0.0.0/255.255.255.253").unwrap();

        let mut front_only = net.addrs();
        assert_eq!(Some(Ipv4Addr::new(10, 0, 0, 0)), front_only.next());
        assert_eq!(Some(Ipv4Addr::new(10, 0, 0, 2)), front_only.next());
        assert_eq!(None, front_only.next());

        let mut front_then_back = net.addrs();
        front_then_back.next();
        front_then_back.next_back();

        let mut back_only = net.addrs();
        back_only.next_back();
        back_only.next_back();

        let mut back_then_front = net.addrs();
        back_then_front.next_back();
        back_then_front.next();

        // Iterators drained through the back end share one sentinel state. The
        // all-front drain overruns into a different (still exhausted) state.
        assert_eq!(front_then_back, back_only);
        assert_eq!(back_only, back_then_front);
        assert_ne!(front_only, front_then_back);

        // Same-script iterators are always equal, mid-iteration included.
        let mut a = net.addrs();
        let mut b = net.addrs();
        assert_eq!(a, b);
        a.next();
        b.next();
        assert_eq!(a, b);
    }

    #[test]
    fn ipv4_addrs_contiguous_exhausted_iterators_pin_equality_by_drain_path() {
        let net = Ipv4Network::parse("10.0.0.0/31").unwrap();

        let mut front_only = net.addrs();
        front_only.next();
        front_only.next();

        let mut front_then_back = net.addrs();
        front_then_back.next();
        front_then_back.next_back();

        let mut back_only = net.addrs();
        back_only.next_back();
        back_only.next_back();

        assert_eq!(front_then_back, back_only);
        assert_ne!(front_only, front_then_back);
    }

    // Pins `last()`'s default forward-walk output on purpose.
    #[allow(clippy::double_ended_iterator_last)]
    #[test]
    fn ipv6_addrs_non_contiguous_pins_forward_and_reverse_order() {
        // Host bits at positions 12..16 and 80..84: index bits 0..4 fill the
        // lower run, index bits 4..8 the upper one.
        let net = Ipv6Network::parse("2001:db8::1/ffff:ffff:fff0:ffff:ffff:ffff:ffff:0fff").unwrap();
        let at = |k: u16| Ipv6Addr::new(0x2001, 0xdb8, k >> 4, 0, 0, 0, 0, 0x0001 | ((k & 0xf) << 12));
        let expected: Vec<_> = (0u16..256).map(at).collect();

        let forward: Vec<_> = net.addrs().collect();
        assert_eq!(expected, forward);

        let mut reversed: Vec<_> = net.addrs().rev().collect();
        reversed.reverse();
        assert_eq!(expected, reversed);

        assert_eq!((256, Some(256)), net.addrs().size_hint());
        assert_eq!(256, net.addrs().count());
        assert_eq!(Some(at(255)), net.addrs().last());
    }

    #[test]
    fn ipv6_addrs_non_contiguous_pins_interleaved_next_and_next_back() {
        let net = Ipv6Network::parse("2001:db8::1/ffff:ffff:fff0:ffff:ffff:ffff:ffff:0fff").unwrap();
        let at = |k: u16| Ipv6Addr::new(0x2001, 0xdb8, k >> 4, 0, 0, 0, 0, 0x0001 | ((k & 0xf) << 12));
        let mut addrs = net.addrs();

        assert_eq!(Some(at(0)), addrs.next());
        assert_eq!(Some(at(255)), addrs.next_back());
        assert_eq!(Some(at(254)), addrs.next_back());
        assert_eq!((253, Some(253)), addrs.size_hint());
        assert_eq!(Some(at(1)), addrs.next());
        assert_eq!(Some(at(2)), addrs.next());
        assert_eq!(Some(at(253)), addrs.next_back());

        for k in 3..253 {
            assert_eq!(Some(at(k)), addrs.next());
        }

        assert_eq!((0, Some(0)), addrs.size_hint());
        assert_eq!(None, addrs.next());
        assert_eq!(None, addrs.next_back());
    }

    // Pins `last()`'s default forward-walk output on purpose.
    #[allow(clippy::double_ended_iterator_last)]
    #[test]
    fn ipv6_addrs_edge_masks_pin_size_hint() {
        let single = Ipv6Network::parse("2001:db8::1/128").unwrap();
        assert_eq!((1, Some(1)), single.addrs().size_hint());
        assert_eq!(1, single.addrs().count());
        assert_eq!(
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            single.addrs().last()
        );

        let full = Ipv6Network::parse("::/0").unwrap();
        assert_eq!((usize::MAX, None), full.addrs().size_hint());

        let mut addrs = full.addrs();
        assert_eq!(Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), addrs.next());
        assert_eq!(Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), addrs.next());
        assert_eq!(
            Some(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
            )),
            addrs.next_back()
        );
        assert_eq!((usize::MAX, None), addrs.size_hint());
    }

    #[test]
    fn ipv6_addrs_wide_non_contiguous_pins_both_ends() {
        // 96 host bits (positions 16..112): far beyond `usize`, so only the
        // ends are materialized.
        let net = Ipv6Network::parse("2001::1/ffff::ffff").unwrap();
        let at = |k: u128| ipv6_addr_at_host_index_reference(&net, k);
        let last = (1u128 << 96) - 1;

        let mut addrs = net.addrs();
        assert_eq!(Some(at(0)), addrs.next());
        assert_eq!(Some(at(1)), addrs.next());
        assert_eq!(Some(at(2)), addrs.next());
        assert_eq!(Some(at(last)), addrs.next_back());
        assert_eq!(Some(at(last - 1)), addrs.next_back());
        assert_eq!(Some(at(last - 2)), addrs.next_back());
        assert_eq!((usize::MAX, None), addrs.size_hint());
        assert_eq!(*net.addr(), at(0));
        assert_eq!(net.last_addr(), at(last));
    }

    #[test]
    fn ipv6_addrs_exhausted_iterators_pin_equality_by_drain_path() {
        // A single non-contiguous host bit (bit 1), so exactly two addresses.
        let net = Ipv6Network::parse("2001:db8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffd").unwrap();

        let mut front_only = net.addrs();
        assert_eq!(Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)), front_only.next());
        assert_eq!(Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)), front_only.next());
        assert_eq!(None, front_only.next());

        let mut front_then_back = net.addrs();
        front_then_back.next();
        front_then_back.next_back();

        let mut back_only = net.addrs();
        back_only.next_back();
        back_only.next_back();

        let mut back_then_front = net.addrs();
        back_then_front.next_back();
        back_then_front.next();

        assert_eq!(front_then_back, back_only);
        assert_eq!(back_only, back_then_front);
        assert_ne!(front_only, front_then_back);
    }

    proptest! {
        #[test]
        fn prop_ipv4_addrs_ends_match_host_index_reference(net in arb_ipv4_network()) {
            let host_bits = (!net.mask().to_bits()).count_ones();
            let total = 1u64 << host_bits;
            let take = total.min(32) as u32;

            let mut addrs = net.addrs();
            for index in 0..take {
                prop_assert_eq!(Some(ipv4_addr_at_host_index_reference(&net, index)), addrs.next());
            }

            let mut addrs = net.addrs();
            for step in 0..u64::from(take) {
                let index = (total - 1 - step) as u32;
                prop_assert_eq!(Some(ipv4_addr_at_host_index_reference(&net, index)), addrs.next_back());
            }
        }

        #[test]
        fn prop_ipv4_addrs_len_and_size_hint_match_host_count(net in arb_ipv4_network()) {
            let host_bits = (!net.mask().to_bits()).count_ones();
            let total = 1u64 << host_bits;
            let addrs = net.addrs();

            prop_assert_eq!(total, addrs.len() as u64);
            prop_assert_eq!(total, net.addrs().count() as u64);
            if host_bits == 32 {
                prop_assert_eq!((usize::MAX, None), addrs.size_hint());
            } else {
                prop_assert_eq!((total as usize, Some(total as usize)), addrs.size_hint());
            }
        }

        #[test]
        fn prop_ipv4_addrs_interleaved_matches_host_index_model(
            net in arb_ipv4_network(),
            script in prop::collection::vec(any::<bool>(), 1..48),
        ) {
            let host_bits = (!net.mask().to_bits()).count_ones();
            let total = 1u64 << host_bits;
            let mut addrs = net.addrs();
            let mut front = 0u64;
            let mut back = total - 1;
            let mut exhausted = false;

            for take_front in script {
                let expected = if exhausted {
                    None
                } else {
                    let index = if take_front { front } else { back } as u32;
                    Some(ipv4_addr_at_host_index_reference(&net, index))
                };
                let actual = if take_front { addrs.next() } else { addrs.next_back() };
                prop_assert_eq!(expected, actual);

                if !exhausted {
                    if front == back {
                        exhausted = true;
                    } else if take_front {
                        front += 1;
                    } else {
                        back -= 1;
                    }
                }
            }
        }

        #[test]
        fn prop_ipv6_addrs_ends_match_host_index_reference(net in arb_ipv6_network()) {
            let host_bits = (!net.mask().to_bits()).count_ones();
            let last = if host_bits == 128 {
                u128::MAX
            } else {
                (1u128 << host_bits) - 1
            };
            let take = last.saturating_add(1).min(32) as u32;

            let mut addrs = net.addrs();
            for index in 0..take {
                prop_assert_eq!(
                    Some(ipv6_addr_at_host_index_reference(&net, u128::from(index))),
                    addrs.next()
                );
            }

            let mut addrs = net.addrs();
            for step in 0..u128::from(take) {
                prop_assert_eq!(
                    Some(ipv6_addr_at_host_index_reference(&net, last - step)),
                    addrs.next_back()
                );
            }
        }

        #[test]
        fn prop_ipv6_addrs_size_hint_matches_host_count(net in arb_ipv6_network()) {
            let host_bits = (!net.mask().to_bits()).count_ones();
            let addrs = net.addrs();

            if host_bits >= 64 {
                prop_assert_eq!((usize::MAX, None), addrs.size_hint());
                prop_assert_eq!(usize::MAX, net.addrs().count());
            } else {
                let total = 1usize << host_bits;
                prop_assert_eq!((total, Some(total)), addrs.size_hint());
                prop_assert_eq!(total, net.addrs().count());
            }
        }

        #[test]
        fn prop_ipv6_addrs_interleaved_matches_host_index_model(
            net in arb_ipv6_network(),
            script in prop::collection::vec(any::<bool>(), 1..48),
        ) {
            let host_bits = (!net.mask().to_bits()).count_ones();
            let mut addrs = net.addrs();
            let mut front = 0u128;
            let mut back = if host_bits == 128 {
                u128::MAX
            } else {
                (1u128 << host_bits) - 1
            };
            let mut exhausted = false;

            for take_front in script {
                let expected = if exhausted {
                    None
                } else {
                    let index = if take_front { front } else { back };
                    Some(ipv6_addr_at_host_index_reference(&net, index))
                };
                let actual = if take_front { addrs.next() } else { addrs.next_back() };
                prop_assert_eq!(expected, actual);

                if !exhausted {
                    if front == back {
                        exhausted = true;
                    } else if take_front {
                        front += 1;
                    } else {
                        back -= 1;
                    }
                }
            }
        }

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
    fn parse_ipv6_non_contiguous_mask() {
        assert_eq!(
            Ipv6Network::new(
                Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 0),
                Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0xffff, 0xffff, 0, 0),
            ),
            Ipv6Network::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap()
        );
        // Address bits outside a non-contiguous mask (the last 2 groups,
        // here) are cleared.
        assert_eq!(
            Ipv6Network::new(
                Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 0),
                Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0xffff, 0xffff, 0, 0),
            ),
            Ipv6Network::parse("2a02:6b8:c00::1234:9:9/ffff:ffff:ff00::ffff:ffff:0:0").unwrap()
        );
    }

    #[test]
    fn parse_ascii_ipv4_non_contiguous_mask() {
        assert_eq!(
            Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(255, 255, 0, 255)),
            Ipv4Network::parse_ascii(b"192.168.0.1/255.255.0.255").unwrap()
        );
    }

    #[test]
    fn parse_ascii_ipv6_non_contiguous_mask() {
        assert_eq!(
            Ipv6Network::new(
                Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 0),
                Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0xffff, 0xffff, 0, 0),
            ),
            Ipv6Network::parse_ascii(b"2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap()
        );
    }

    #[test]
    fn parse_ascii_rejects_non_utf8() {
        assert!(matches!(
            Ipv4Network::parse_ascii(b"\xff\xfe").unwrap_err(),
            IpNetParseError::AddrParseError(..)
        ));
        assert!(matches!(
            Ipv4Network::parse_ascii(b"192.168.0.1/\xff").unwrap_err(),
            IpNetParseError::AddrParseError(..)
        ));
        assert!(matches!(
            Ipv6Network::parse_ascii(b"\xff\xfe").unwrap_err(),
            IpNetParseError::AddrParseError(..)
        ));
        assert!(matches!(
            Ipv6Network::parse_ascii(b"2001:db8::/\xff").unwrap_err(),
            IpNetParseError::AddrParseError(..)
        ));
        assert!(matches!(
            IpNetwork::parse_ascii(b"\xff\xfe").unwrap_err(),
            IpNetParseError::AddrParseError(..)
        ));
    }

    proptest! {
        #[test]
        fn prop_parse_ascii_matches_parse_ipv4(network in arb_ipv4_network()) {
            let text = std::format!("{network}");
            prop_assert_eq!(Ipv4Network::parse(&text), Ipv4Network::parse_ascii(text.as_bytes()));
        }

        #[test]
        fn prop_parse_ascii_matches_parse_ipv6(network in arb_ipv6_network()) {
            let text = std::format!("{network}");
            prop_assert_eq!(Ipv6Network::parse(&text), Ipv6Network::parse_ascii(text.as_bytes()));
        }

        #[test]
        fn prop_parse_ascii_parity_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..48)) {
            match core::str::from_utf8(&bytes) {
                Ok(text) => prop_assert_eq!(IpNetwork::parse(text), IpNetwork::parse_ascii(&bytes)),
                Err(..) => prop_assert!(IpNetwork::parse_ascii(&bytes).is_err()),
            }
        }
    }

    #[test]
    fn parse_next_ascii_ipv4() {
        let (network, rest) = Ipv4Network::parse_next_ascii(b"10.0.0.0/8 } to any").unwrap();
        assert_eq!(Ipv4Network::parse("10.0.0.0/8").unwrap(), network);
        assert_eq!(b" } to any", rest);

        let (network, rest) = Ipv4Network::parse_next_ascii(b"192.168.0.1/255.255.0.255,next").unwrap();
        assert_eq!(Ipv4Network::parse("192.168.0.1/255.255.0.255").unwrap(), network);
        assert_eq!(b",next", rest);

        let (network, rest) = Ipv4Network::parse_next_ascii(b"10.0.0.1").unwrap();
        assert_eq!(Ipv4Network::parse("10.0.0.1").unwrap(), network);
        assert_eq!(b"", rest);

        // The IPv4 alphabet excludes `:` and hex letters, so they delimit
        // the token like any other non-IPv4 byte.
        let (network, rest) = Ipv4Network::parse_next_ascii(b"10.0.0.1:8080").unwrap();
        assert_eq!(Ipv4Network::parse("10.0.0.1").unwrap(), network);
        assert_eq!(b":8080", rest);

        let (network, rest) = Ipv4Network::parse_next_ascii(b"10.0.0.1abc").unwrap();
        assert_eq!(Ipv4Network::parse("10.0.0.1").unwrap(), network);
        assert_eq!(b"abc", rest);
    }

    #[test]
    fn parse_next_ascii_ipv6_non_contiguous_mask() {
        let (network, rest) =
            Ipv6Network::parse_next_ascii(b"2a02:6b8:c00::/ffff:fff:ff00::ffff:ffff:0:0 } to any").unwrap();
        assert_eq!(
            Ipv6Network::parse("2a02:6b8:c00::/ffff:fff:ff00::ffff:ffff:0:0").unwrap(),
            network
        );
        assert_eq!(b" } to any", rest);
    }

    #[test]
    fn parse_next_ascii_ip_network_both_families() {
        let (network, rest) = IpNetwork::parse_next_ascii(b"10.0.0.0/8 to").unwrap();
        assert_eq!(IpNetwork::parse("10.0.0.0/8").unwrap(), network);
        assert_eq!(b" to", rest);

        let (network, rest) = IpNetwork::parse_next_ascii(b"2001:db8::/32 to").unwrap();
        assert_eq!(IpNetwork::parse("2001:db8::/32").unwrap(), network);
        assert_eq!(b" to", rest);
    }

    #[test]
    fn parse_next_ascii_rejects_malformed_token() {
        // The whole token must parse: no shorter partial parse is attempted.
        assert!(matches!(
            Ipv4Network::parse_next_ascii(b"1.2.3.4.5 x").unwrap_err(),
            IpNetParseError::AddrParseError(..)
        ));
        assert!(matches!(
            Ipv6Network::parse_next_ascii(b"1::2::3 x").unwrap_err(),
            IpNetParseError::AddrParseError(..)
        ));
        // The family-agnostic parser tokenizes with the IPv6 alphabet, so a
        // `:` extends its token where the IPv4 parser would stop.
        assert!(matches!(
            IpNetwork::parse_next_ascii(b"10.0.0.1:8080").unwrap_err(),
            IpNetParseError::AddrParseError(..)
        ));
    }

    #[test]
    fn parse_next_ascii_rejects_empty_token() {
        assert!(matches!(
            IpNetwork::parse_next_ascii(b"").unwrap_err(),
            IpNetParseError::AddrParseError(..)
        ));
        // Leading whitespace is not skipped.
        assert!(matches!(
            IpNetwork::parse_next_ascii(b" 10.0.0.0/8").unwrap_err(),
            IpNetParseError::AddrParseError(..)
        ));
    }

    proptest! {
        #[test]
        fn prop_parse_next_ascii_round_trips_with_rest_ipv4(network in arb_ipv4_network()) {
            let text = std::format!("{network} }} to any");
            let (parsed, rest) = Ipv4Network::parse_next_ascii(text.as_bytes()).unwrap();
            prop_assert_eq!(network, parsed);
            prop_assert_eq!(b" } to any".as_slice(), rest);
        }

        #[test]
        fn prop_parse_next_ascii_round_trips_with_rest_ipv6(network in arb_ipv6_network()) {
            let text = std::format!("{network} }} to any");
            let (parsed, rest) = Ipv6Network::parse_next_ascii(text.as_bytes()).unwrap();
            prop_assert_eq!(network, parsed);
            prop_assert_eq!(b" } to any".as_slice(), rest);
        }
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

    // `count()` must agree with `len()` across all three branches: an
    // overlapping pair (multiple parts), a disjoint pair (one part), and a
    // subset pair (no parts), plus a non-contiguous mask.
    #[test]
    fn ipv6_difference_count_matches_len_fixed_cases() {
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        let b = Ipv6Network::parse("2001:db8::/64").unwrap();
        assert_eq!(a.difference(&b).len(), 16);
        assert_eq!(a.difference(&b).count(), 16);

        let a = Ipv6Network::parse("2001:db8::/32").unwrap();
        let b = Ipv6Network::parse("fe80::/10").unwrap();
        assert_eq!(a.difference(&b).len(), 1);
        assert_eq!(a.difference(&b).count(), 1);

        let a = Ipv6Network::parse("2001:db8::/64").unwrap();
        let b = Ipv6Network::parse("2001:db8::/48").unwrap();
        assert_eq!(a.difference(&b).len(), 0);
        assert_eq!(a.difference(&b).count(), 0);

        let a = Ipv6Network::parse("2001::/ffff::").unwrap();
        let b = Ipv6Network::parse("2001::1/ffff::ff").unwrap();
        assert_eq!(a.difference(&b).len(), 8);
        assert_eq!(a.difference(&b).count(), 8);
    }

    #[test]
    fn ipv6_difference_next_back_disjoint_yields_source() {
        let a = Ipv6Network::parse("2001:db8::/32").unwrap();
        let b = Ipv6Network::parse("fe80::/10").unwrap();
        let mut diff = a.difference(&b);
        assert_eq!(Some(a), diff.next_back());
        assert_eq!(None, diff.next_back());
    }

    #[test]
    fn ipv6_difference_next_back_subset_is_none() {
        let a = Ipv6Network::parse("2001:db8::/64").unwrap();
        let b = Ipv6Network::parse("2001:db8::/48").unwrap();
        let mut diff = a.difference(&b);
        assert_eq!(None, diff.next_back());
    }

    #[test]
    fn ipv6_difference_rev_matches_forward_reversed() {
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        let b = Ipv6Network::parse("2001:db8::/64").unwrap();
        let mut forward_reversed: Vec<_> = a.difference(&b).collect();
        forward_reversed.reverse();
        let reversed: Vec<_> = a.difference(&b).rev().collect();
        assert_eq!(forward_reversed, reversed);
    }

    #[test]
    fn ipv6_difference_last_matches_forward_last() {
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        let b = Ipv6Network::parse("2001:db8::/64").unwrap();
        let forward: Vec<_> = a.difference(&b).collect();
        assert_eq!(forward.last().copied(), a.difference(&b).last());
    }

    #[test]
    fn ipv6_difference_next_back_non_contiguous() {
        let a = Ipv6Network::parse("2001::/ffff::").unwrap();
        let b = Ipv6Network::parse("2001::1/ffff::ff").unwrap();

        let mut diff = a.difference(&b);
        // The differing bits (`d`) are confined to the lowest byte
        // (`ffff::ff` adds only the low 8 bits over `ffff::`), so
        // `next_back` must yield the lowest-bit item first, mirroring
        // `ipv4_difference_next_back_non_contiguous`.
        assert_eq!(
            Ipv6Network::parse("2001::/ffff::ff").unwrap(),
            diff.next_back().unwrap()
        );
        assert_eq!(
            Ipv6Network::parse("2001::2/ffff::fe").unwrap(),
            diff.next_back().unwrap()
        );
        assert_eq!(6, diff.len());
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

    // Pre-rewrite `Ipv4Network::merge` body, kept verbatim to validate the
    // cheaper-reject-path rewrite against known-correct behavior.
    fn ipv4_merge_reference(a: &Ipv4Network, b: &Ipv4Network) -> Option<Ipv4Network> {
        let (a1, m1) = a.to_bits();
        let (a2, m2) = b.to_bits();

        if m1 == m2 {
            if a1 == a2 {
                return Some(*a);
            }
            if let Some(d) = ipv4_adjacent_bit(a1, m1, a2, m2) {
                let m = m1 ^ d;
                let addr = a1 & m;
                return Some(Ipv4Network(Ipv4Addr::from_bits(addr), Ipv4Addr::from_bits(m)));
            }
            return None;
        }

        if a.contains(b) {
            return Some(*a);
        }
        if b.contains(a) {
            return Some(*b);
        }
        None
    }

    // Pre-rewrite `Ipv6Network::merge` body, kept verbatim to validate the
    // cheaper-reject-path rewrite against known-correct behavior.
    fn ipv6_merge_reference(a: &Ipv6Network, b: &Ipv6Network) -> Option<Ipv6Network> {
        let (a1, m1) = a.to_bits();
        let (a2, m2) = b.to_bits();

        if m1 == m2 {
            if a1 == a2 {
                return Some(*a);
            }
            if let Some(d) = ipv6_adjacent_bit(a1, m1, a2, m2) {
                let m = m1 ^ d;
                let addr = a1 & m;
                return Some(Ipv6Network(Ipv6Addr::from_bits(addr), Ipv6Addr::from_bits(m)));
            }
            return None;
        }

        if a.contains(b) {
            return Some(*a);
        }
        if b.contains(a) {
            return Some(*b);
        }
        None
    }

    // Independent oracle for `Ipv4Network::is_adjacent_by_lowest_mask_bit`: shared
    // mask, non-`/0`, addresses differ in exactly the mask's lowest set bit,
    // computed here via `trailing_zeros` rather than the `m & -m` isolation the
    // implementation uses.
    fn ipv4_is_adjacent_by_lowest_mask_bit_reference(a: &Ipv4Network, b: &Ipv4Network) -> bool {
        let (a1, m1) = a.to_bits();
        let (a2, m2) = b.to_bits();
        m1 == m2 && m1 != 0 && (a1 ^ a2) == 1u32 << m1.trailing_zeros()
    }

    fn ipv6_is_adjacent_by_lowest_mask_bit_reference(a: &Ipv6Network, b: &Ipv6Network) -> bool {
        let (a1, m1) = a.to_bits();
        let (a2, m2) = b.to_bits();
        m1 == m2 && m1 != 0 && (a1 ^ a2) == 1u128 << m1.trailing_zeros()
    }

    // Independent oracle for `Ipv4Network::merge_by_lowest_mask_bit`: containment
    // returns the larger network, otherwise the reference predicate gates the
    // sibling merge, where the reduced mask is built by masking out
    // `1 << trailing_zeros` and the address is re-normalized through `from_bits`,
    // rather than the implementation's `m & (m - 1)` plus skip-`&`-mask tuple.
    fn ipv4_merge_by_lowest_mask_bit_reference(a: &Ipv4Network, b: &Ipv4Network) -> Option<Ipv4Network> {
        if a.contains(b) {
            return Some(*a);
        }
        if b.contains(a) {
            return Some(*b);
        }
        if !ipv4_is_adjacent_by_lowest_mask_bit_reference(a, b) {
            return None;
        }
        let (a1, m1) = a.to_bits();
        let (a2, ..) = b.to_bits();
        let lowest = 1u32 << m1.trailing_zeros();
        Some(Ipv4Network::from_bits(a1 & a2, m1 & !lowest))
    }

    fn ipv6_merge_by_lowest_mask_bit_reference(a: &Ipv6Network, b: &Ipv6Network) -> Option<Ipv6Network> {
        if a.contains(b) {
            return Some(*a);
        }
        if b.contains(a) {
            return Some(*b);
        }
        if !ipv6_is_adjacent_by_lowest_mask_bit_reference(a, b) {
            return None;
        }
        let (a1, m1) = a.to_bits();
        let (a2, ..) = b.to_bits();
        let lowest = 1u128 << m1.trailing_zeros();
        Some(Ipv6Network::from_bits(a1 & a2, m1 & !lowest))
    }

    fn arb_sorted_ipv4_networks() -> impl Strategy<Value = Vec<Ipv4Network>> {
        (3usize..=64)
            .prop_flat_map(|len| prop::collection::vec(arb_ipv4_network(), len))
            .prop_map(|mut nets| {
                nets.sort();
                nets.dedup();
                nets
            })
            .prop_filter("need at least 3 distinct networks after dedup", |nets| nets.len() >= 3)
    }

    fn arb_sorted_ipv6_networks() -> impl Strategy<Value = Vec<Ipv6Network>> {
        (3usize..=64)
            .prop_flat_map(|len| prop::collection::vec(arb_ipv6_network(), len))
            .prop_map(|mut nets| {
                nets.sort();
                nets.dedup();
                nets
            })
            .prop_filter("need at least 3 distinct networks after dedup", |nets| nets.len() >= 3)
    }

    // Compares the two implementations directly, bypassing `ip_binary_split`'s
    // size-based router entirely, so both are exercised across the full n
    // range regardless of `Word::SPLIT_THRESHOLD`. Kept at the default case
    // count: each case already does O(n^2) work up to n = 64 in the
    // quadratic reference, so it is deliberately not inflated further.
    proptest! {
        #[test]
        fn prop_ipv4_binary_split_linear_matches_quadratic(nets in arb_sorted_ipv4_networks()) {
            let expected = ip_binary_split_quadratic(&nets);
            let actual = ip_binary_split_linear(&nets);
            prop_assert_eq!(expected, actual, "mismatch for nets = {:?}", nets);
        }

        #[test]
        fn prop_ipv6_binary_split_linear_matches_quadratic(nets in arb_sorted_ipv6_networks()) {
            let expected = ip_binary_split_quadratic(&nets);
            let actual = ip_binary_split_linear(&nets);
            prop_assert_eq!(expected, actual, "mismatch for nets = {:?}", nets);
        }
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

    // Checks that `ipv4_binary_split`, `ip_binary_split`'s router, picks
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

    // The following `parse_pin_*` tests pin the exact `IpNetParseError` variant
    // returned for malformed input, so that the `splitn`-to-`split_once`
    // refactor of `Ipv4Network::parse` / `Ipv6Network::parse` / `IpNetwork::parse`
    // cannot silently change error variants while remaining `Result::is_err`.

    const MALFORMED_INPUTS: &[&str] = &["", "/", "10.0.0.1/", "/24", "10.0.0.1//24", "hello", "zz/24"];

    #[test]
    fn parse_pin_ipv4_malformed_inputs_yield_addr_parse_error() {
        for input in MALFORMED_INPUTS {
            let err = Ipv4Network::parse(input).unwrap_err();
            assert!(
                matches!(err, IpNetParseError::AddrParseError(..)),
                "input {input:?} gave {err:?}"
            );
        }
    }

    #[test]
    fn parse_pin_ipv6_malformed_inputs_yield_addr_parse_error() {
        for input in MALFORMED_INPUTS {
            let err = Ipv6Network::parse(input).unwrap_err();
            assert!(
                matches!(err, IpNetParseError::AddrParseError(..)),
                "input {input:?} gave {err:?}"
            );
        }
    }

    #[test]
    fn parse_pin_ipnetwork_malformed_inputs_yield_addr_parse_error() {
        for input in MALFORMED_INPUTS {
            let err = IpNetwork::parse(input).unwrap_err();
            assert!(
                matches!(err, IpNetParseError::AddrParseError(..)),
                "input {input:?} gave {err:?}"
            );
        }
    }

    #[test]
    fn parse_pin_ipv4_rejects_ipv6_literal() {
        let err = Ipv4Network::parse("2001:db8::1").unwrap_err();
        assert!(matches!(err, IpNetParseError::AddrParseError(..)));
    }

    #[test]
    fn parse_pin_ipv6_rejects_ipv4_literal() {
        let err = Ipv6Network::parse("192.168.1.1").unwrap_err();
        assert!(matches!(err, IpNetParseError::AddrParseError(..)));
    }

    #[test]
    fn parse_pin_ipnetwork_cross_family_mask_notation_yields_addr_parse_error() {
        // IPv4 address with an IPv6-shaped mask, and vice versa: neither family
        // accepts the pairing, so `IpNetwork::parse` must fail on both.
        for input in ["10.0.0.1/2001:db8::1", "2001:db8::1/255.255.255.0"] {
            let err = IpNetwork::parse(input).unwrap_err();
            assert!(
                matches!(err, IpNetParseError::AddrParseError(..)),
                "input {input:?} gave {err:?}"
            );
        }
    }

    #[test]
    fn parse_pin_leading_trailing_whitespace_yields_addr_parse_error() {
        for input in [" 10.0.0.1/24", "10.0.0.1/24 "] {
            assert!(matches!(
                Ipv4Network::parse(input).unwrap_err(),
                IpNetParseError::AddrParseError(..)
            ));
            assert!(matches!(
                Ipv6Network::parse(input).unwrap_err(),
                IpNetParseError::AddrParseError(..)
            ));
            assert!(matches!(
                IpNetwork::parse(input).unwrap_err(),
                IpNetParseError::AddrParseError(..)
            ));
        }
    }

    #[test]
    fn parse_pin_mask_out_of_range() {
        assert_eq!(
            IpNetParseError::CidrOverflow(CidrOverflowError(33, 32)),
            Ipv4Network::parse("10.0.0.0/33").unwrap_err(),
        );
        assert_eq!(
            IpNetParseError::CidrOverflow(CidrOverflowError(33, 32)),
            IpNetwork::parse("10.0.0.0/33").unwrap_err(),
        );
        assert_eq!(
            IpNetParseError::CidrOverflow(CidrOverflowError(129, 128)),
            Ipv6Network::parse("::/129").unwrap_err(),
        );
        assert_eq!(
            IpNetParseError::CidrOverflow(CidrOverflowError(129, 128)),
            IpNetwork::parse("::/129").unwrap_err(),
        );
    }

    #[test]
    fn parse_pin_ipnetwork_valid_v4_cidr() {
        assert_eq!(
            IpNetwork::V4(Ipv4Network::new(
                Ipv4Addr::new(10, 0, 0, 0),
                Ipv4Addr::new(255, 0, 0, 0)
            )),
            IpNetwork::parse("10.0.0.0/8").unwrap(),
        );
    }

    #[test]
    fn parse_pin_ipnetwork_valid_v4_dotted_mask() {
        assert_eq!(
            IpNetwork::V4(Ipv4Network::new(
                Ipv4Addr::new(10, 0, 0, 0),
                Ipv4Addr::new(255, 0, 0, 0)
            )),
            IpNetwork::parse("10.0.0.0/255.0.0.0").unwrap(),
        );
    }

    #[test]
    fn parse_pin_ipnetwork_valid_v4_non_contiguous_mask() {
        assert_eq!(
            IpNetwork::V4(Ipv4Network::new(
                Ipv4Addr::new(192, 168, 0, 1),
                Ipv4Addr::new(255, 255, 0, 255)
            )),
            IpNetwork::parse("192.168.0.1/255.255.0.255").unwrap(),
        );
    }

    #[test]
    fn parse_pin_ipnetwork_valid_v6_cidr() {
        assert_eq!(
            IpNetwork::V6(Ipv6Network::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0),
            )),
            IpNetwork::parse("2001:db8::/32").unwrap(),
        );
    }

    #[test]
    fn parse_pin_ipnetwork_valid_v6_full_mask() {
        assert_eq!(
            IpNetwork::V6(Ipv6Network::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0xffff),
            )),
            IpNetwork::parse("2001:db8::1/ffff:ffff::ffff").unwrap(),
        );
    }

    #[test]
    fn parse_pin_ipnetwork_valid_bare_v4() {
        assert_eq!(
            IpNetwork::V4(Ipv4Network::new(
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(255, 255, 255, 255)
            )),
            IpNetwork::parse("192.168.1.1").unwrap(),
        );
    }

    #[test]
    fn parse_pin_ipnetwork_valid_bare_v6() {
        assert_eq!(
            IpNetwork::V6(Ipv6Network::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
            )),
            IpNetwork::parse("2001:db8::1").unwrap(),
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

    // `count()` must agree with `len()` across all three branches: an
    // overlapping pair (multiple parts), a disjoint pair (one part), and a
    // subset pair (no parts), plus a non-contiguous mask.
    #[test]
    fn ipv4_difference_count_matches_len_fixed_cases() {
        let a = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
        assert_eq!(a.difference(&b).len(), 8);
        assert_eq!(a.difference(&b).count(), 8);

        let a = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let b = Ipv4Network::parse("192.168.0.0/16").unwrap();
        assert_eq!(a.difference(&b).len(), 1);
        assert_eq!(a.difference(&b).count(), 1);

        let a = Ipv4Network::parse("192.168.1.0/24").unwrap();
        let b = Ipv4Network::parse("192.168.0.0/16").unwrap();
        assert_eq!(a.difference(&b).len(), 0);
        assert_eq!(a.difference(&b).count(), 0);

        let a = Ipv4Network::parse("10.0.0.0/255.0.0.0").unwrap();
        let b = Ipv4Network::parse("10.0.0.1/255.0.0.255").unwrap();
        assert_eq!(a.difference(&b).len(), 8);
        assert_eq!(a.difference(&b).count(), 8);
    }

    #[test]
    fn ipv4_difference_next_back_disjoint_yields_source() {
        let a = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let b = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let mut diff = a.difference(&b);
        assert_eq!(Some(a), diff.next_back());
        assert_eq!(None, diff.next_back());
    }

    #[test]
    fn ipv4_difference_next_back_subset_is_none() {
        let a = Ipv4Network::parse("192.168.1.0/24").unwrap();
        let b = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let mut diff = a.difference(&b);
        assert_eq!(None, diff.next_back());
    }

    #[test]
    fn ipv4_difference_rev_matches_forward_reversed() {
        let a = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
        let mut forward_reversed: Vec<_> = a.difference(&b).collect();
        forward_reversed.reverse();
        let reversed: Vec<_> = a.difference(&b).rev().collect();
        assert_eq!(forward_reversed, reversed);
    }

    #[test]
    fn ipv4_difference_last_matches_forward_last() {
        let a = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
        let forward: Vec<_> = a.difference(&b).collect();
        assert_eq!(forward.last().copied(), a.difference(&b).last());
    }

    #[test]
    fn ipv4_difference_next_back_non_contiguous() {
        let a = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 0, 0, 0));
        let b = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(255, 0, 0, 255));

        let mut diff = a.difference(&b);
        // Mirrors `ipv4_difference_non_contiguous`'s forward `expected` array
        // read back to front: `next_back` must yield the lowest-bit item
        // first, regardless of consumption order.
        assert_eq!(
            Ipv4Network::parse("10.0.0.0/255.0.0.255").unwrap(),
            diff.next_back().unwrap()
        );
        assert_eq!(
            Ipv4Network::parse("10.0.0.2/255.0.0.254").unwrap(),
            diff.next_back().unwrap()
        );
        assert_eq!(6, diff.len());
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
    fn ipv4_merge_matches_reference_fixed_cases() {
        let cases = [
            // Exact duplicate: the more expensive path in the rewrite.
            ("192.168.1.0/24", "192.168.1.0/24"),
            // Same mask, adjacent (contiguous siblings).
            ("192.168.0.0/24", "192.168.1.0/24"),
            // Same mask, adjacent (non-contiguous siblings).
            ("192.168.0.0/255.255.255.0", "192.168.2.0/255.255.255.0"),
            // Same mask, not adjacent, not identical -> reject.
            ("192.168.0.0/24", "192.168.3.0/24"),
            // Comparable masks: self's mask is a subset of other's, address matches.
            ("10.0.0.0/8", "10.1.0.0/16"),
            // Comparable masks: other's mask is a subset of self's, address matches.
            ("10.1.0.0/16", "10.0.0.0/8"),
            // Comparable masks: self's mask is a subset of other's, address mismatch -> reject.
            ("10.0.0.0/8", "172.16.0.0/16"),
            // Comparable masks: other's mask is a subset of self's, address mismatch -> reject.
            ("172.16.0.0/16", "10.0.0.0/8"),
            // Incomparable non-contiguous masks -> reject regardless of address.
            ("10.0.0.1/255.255.0.255", "10.0.0.1/255.0.255.255"),
        ];

        for (a, b) in cases {
            let a = Ipv4Network::parse(a).unwrap();
            let b = Ipv4Network::parse(b).unwrap();
            assert_eq!(ipv4_merge_reference(&a, &b), a.merge(&b), "mismatch: a={a}, b={b}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn prop_ipv4_merge_matches_reference(a in arb_ipv4_network(), b in arb_ipv4_network()) {
            prop_assert_eq!(ipv4_merge_reference(&a, &b), a.merge(&b), "mismatch: a={}, b={}", a, b);
        }
    }

    #[test]
    fn ipv6_merge_matches_reference_fixed_cases() {
        let cases = [
            // Exact duplicate: the more expensive path in the rewrite.
            ("2001:db8::/48", "2001:db8::/48"),
            // Same mask, adjacent (contiguous siblings).
            ("2001:db8::/48", "2001:db8:1::/48"),
            // Same mask, adjacent (non-contiguous siblings).
            (
                "2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
                "2a02:6b8:c00::1235:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
            ),
            // Same mask, not adjacent, not identical -> reject.
            ("2001:db8::/48", "2001:db8:5::/48"),
            // Comparable masks: self's mask is a subset of other's, address matches.
            ("2001:db8::/32", "2001:db8:1::/48"),
            // Comparable masks: other's mask is a subset of self's, address matches.
            ("2001:db8:1::/48", "2001:db8::/32"),
            // Comparable masks: self's mask is a subset of other's, address mismatch -> reject.
            ("2001:db8::/32", "2001:beef:1::/48"),
            // Comparable masks: other's mask is a subset of self's, address mismatch -> reject.
            ("2001:beef:1::/48", "2001:db8::/32"),
            // Incomparable non-contiguous masks -> reject regardless of address.
            ("2001:db8::1/ffff:0:ffff::", "2001:db8::1/0:ffff:ffff::"),
        ];

        for (a, b) in cases {
            let a = Ipv6Network::parse(a).unwrap();
            let b = Ipv6Network::parse(b).unwrap();
            assert_eq!(ipv6_merge_reference(&a, &b), a.merge(&b), "mismatch: a={a}, b={b}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn prop_ipv6_merge_matches_reference(a in arb_ipv6_network(), b in arb_ipv6_network()) {
            prop_assert_eq!(ipv6_merge_reference(&a, &b), a.merge(&b), "mismatch: a={}, b={}", a, b);
        }
    }

    // Pre-rewrite `Ipv4Network::supernet_for` body, kept verbatim to validate
    // the native-byte-order rewrite against known-correct behavior.
    fn ipv4_supernet_for_reference(net: &Ipv4Network, nets: &[Ipv4Network]) -> Ipv4Network {
        let (addr, mut mask) = net.to_bits();

        for net in nets {
            let (a, m) = net.to_bits();
            mask &= m & !(addr ^ a);
        }

        Ipv4Network::new(addr.into(), mask.into())
    }

    // Pre-rewrite `Ipv6Network::supernet_for` body, kept verbatim to validate
    // the native-byte-order rewrite against known-correct behavior.
    fn ipv6_supernet_for_reference(net: &Ipv6Network, nets: &[Ipv6Network]) -> Ipv6Network {
        let (addr, mut mask) = net.to_bits();

        for net in nets {
            let (a, m) = net.to_bits();
            mask &= m & !(addr ^ a);
        }

        Ipv6Network::new(addr.into(), mask.into())
    }

    #[test]
    fn ipv4_supernet_for_empty() {
        let net = Ipv4Network::parse("10.0.0.1/255.255.0.255").unwrap();
        assert_eq!(net, net.supernet_for(&[]));
    }

    #[test]
    fn ipv6_supernet_for_empty() {
        let net = Ipv6Network::parse("2001:db8::1/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff").unwrap();
        assert_eq!(net, net.supernet_for(&[]));
    }

    #[test]
    fn ipv4_supernet_for_matches_reference_fixed_cases() {
        let cases: &[(&str, &[&str])] = &[
            // Empty slice: returns self unchanged.
            ("10.0.0.0/24", &[]),
            // Duplicates of self.
            ("10.0.0.0/24", &["10.0.0.0/24", "10.0.0.0/24"]),
            // Sibling /25s fold into the /24.
            ("192.0.2.0/25", &["192.0.2.128/25"]),
            // Contiguous inputs, non-contiguous result.
            ("10.0.0.0/24", &["10.1.0.0/24"]),
            // Non-contiguous masks with a hole in the third octet.
            (
                "10.0.0.1/255.255.0.255",
                &["10.1.0.1/255.255.0.255", "10.2.0.1/255.255.0.255"],
            ),
            // Top-bit difference collapses the mask to zero.
            ("0.0.0.0/8", &["128.0.0.0/8", "10.0.0.0/24"]),
        ];

        for (net, rest) in cases {
            let net = Ipv4Network::parse(net).unwrap();
            let rest: Vec<_> = rest.iter().map(|s| Ipv4Network::parse(s).unwrap()).collect();
            assert_eq!(
                ipv4_supernet_for_reference(&net, &rest),
                net.supernet_for(&rest),
                "mismatch: net={net}, rest={rest:?}"
            );
        }
    }

    #[test]
    fn ipv6_supernet_for_matches_reference_fixed_cases() {
        let cases: &[(&str, &[&str])] = &[
            // Empty slice: returns self unchanged.
            ("2001:db8::/48", &[]),
            // Duplicates of self.
            ("2001:db8::/48", &["2001:db8::/48", "2001:db8::/48"]),
            // Sibling /49s fold into the /48.
            ("2001:db8::/49", &["2001:db8:0:8000::/49"]),
            // Contiguous inputs, non-contiguous result.
            ("2001:db8::/48", &["2001:db8:100::/48"]),
            // Non-contiguous masks with an 8-bit hole in the third group.
            (
                "2001:db8:c00::1/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff",
                &["2001:db8:c01::1/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff"],
            ),
            // Top-bit difference collapses the mask to zero.
            ("::/8", &["8000::/8", "2001:db8::/48"]),
        ];

        for (net, rest) in cases {
            let net = Ipv6Network::parse(net).unwrap();
            let rest: Vec<_> = rest.iter().map(|s| Ipv6Network::parse(s).unwrap()).collect();
            assert_eq!(
                ipv6_supernet_for_reference(&net, &rest),
                net.supernet_for(&rest),
                "mismatch: net={net}, rest={rest:?}"
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn prop_ipv4_supernet_for_matches_reference(
            net in arb_ipv4_network(),
            nets in prop::collection::vec(arb_ipv4_network(), 0..33),
        ) {
            prop_assert_eq!(
                ipv4_supernet_for_reference(&net, &nets),
                net.supernet_for(&nets),
                "mismatch: net={}, nets={:?}",
                net,
                nets
            );
        }

        #[test]
        fn prop_ipv6_supernet_for_matches_reference(
            net in arb_ipv6_network(),
            nets in prop::collection::vec(arb_ipv6_network(), 0..33),
        ) {
            prop_assert_eq!(
                ipv6_supernet_for_reference(&net, &nets),
                net.supernet_for(&nets),
                "mismatch: net={}, nets={:?}",
                net,
                nets
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn prop_ipv4_is_adjacent_by_lowest_mask_bit_matches_reference(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            prop_assert_eq!(
                a.is_adjacent_by_lowest_mask_bit(&b),
                ipv4_is_adjacent_by_lowest_mask_bit_reference(&a, &b),
                "mismatch: a={}, b={}", a, b
            );
        }

        #[test]
        fn prop_ipv4_is_adjacent_by_lowest_mask_bit_implies_is_adjacent(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            if a.is_adjacent_by_lowest_mask_bit(&b) {
                prop_assert!(a.is_adjacent(&b));
            }
        }

        #[test]
        fn prop_ipv4_is_adjacent_by_lowest_mask_bit_symmetry(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            prop_assert_eq!(a.is_adjacent_by_lowest_mask_bit(&b), b.is_adjacent_by_lowest_mask_bit(&a));
        }

        #[test]
        fn prop_ip_is_adjacent_by_lowest_mask_bit_matches_inner_v4(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            prop_assert_eq!(
                IpNetwork::V4(a).is_adjacent_by_lowest_mask_bit(&IpNetwork::V4(b)),
                a.is_adjacent_by_lowest_mask_bit(&b)
            );
        }

        #[test]
        fn prop_ipv6_is_adjacent_by_lowest_mask_bit_matches_reference(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            prop_assert_eq!(
                a.is_adjacent_by_lowest_mask_bit(&b),
                ipv6_is_adjacent_by_lowest_mask_bit_reference(&a, &b),
                "mismatch: a={}, b={}", a, b
            );
        }

        #[test]
        fn prop_ipv6_is_adjacent_by_lowest_mask_bit_implies_is_adjacent(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            if a.is_adjacent_by_lowest_mask_bit(&b) {
                prop_assert!(a.is_adjacent(&b));
            }
        }

        #[test]
        fn prop_ipv6_is_adjacent_by_lowest_mask_bit_symmetry(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            prop_assert_eq!(a.is_adjacent_by_lowest_mask_bit(&b), b.is_adjacent_by_lowest_mask_bit(&a));
        }

        #[test]
        fn prop_ip_is_adjacent_by_lowest_mask_bit_matches_inner_v6(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            prop_assert_eq!(
                IpNetwork::V6(a).is_adjacent_by_lowest_mask_bit(&IpNetwork::V6(b)),
                a.is_adjacent_by_lowest_mask_bit(&b)
            );
        }

        #[test]
        fn prop_ip_merge_by_lowest_mask_bit_matches_inner_v4(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            prop_assert_eq!(
                IpNetwork::V4(a).merge_by_lowest_mask_bit(&IpNetwork::V4(b)),
                a.merge_by_lowest_mask_bit(&b).map(IpNetwork::V4)
            );
        }

        #[test]
        fn prop_ip_merge_by_lowest_mask_bit_matches_inner_v6(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            prop_assert_eq!(
                IpNetwork::V6(a).merge_by_lowest_mask_bit(&IpNetwork::V6(b)),
                a.merge_by_lowest_mask_bit(&b).map(IpNetwork::V6)
            );
        }

        #[test]
        fn prop_ip_merge_by_lowest_mask_bit_mixed_families_none(
            a in arb_ipv4_network(),
            b in arb_ipv6_network(),
        ) {
            prop_assert_eq!(IpNetwork::V4(a).merge_by_lowest_mask_bit(&IpNetwork::V6(b)), None);
            prop_assert_eq!(IpNetwork::V6(b).merge_by_lowest_mask_bit(&IpNetwork::V4(a)), None);
        }
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
    fn ipv4_is_adjacent_by_lowest_mask_bit_cidr_siblings() {
        let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
        assert!(a.is_adjacent_by_lowest_mask_bit(&b));
        assert!(b.is_adjacent_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv4_is_adjacent_by_lowest_mask_bit_host_routes() {
        let a = Ipv4Network::parse("192.168.0.0/32").unwrap();
        let b = Ipv4Network::parse("192.168.0.1/32").unwrap();
        assert!(a.is_adjacent_by_lowest_mask_bit(&b));
        assert!(b.is_adjacent_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv4_is_adjacent_by_lowest_mask_bit_non_contiguous_lowest() {
        let a = Ipv4Network::parse("10.0.0.0/255.255.0.255").unwrap();
        let b = Ipv4Network::parse("10.0.0.1/255.255.0.255").unwrap();
        assert!(a.is_adjacent_by_lowest_mask_bit(&b));
        assert!(b.is_adjacent_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv4_is_adjacent_by_lowest_mask_bit_non_contiguous_higher_rejected() {
        // Same non-contiguous mask, but the addresses differ in bit 16 (a
        // higher set bit of the mask), not its lowest set bit (bit 0).
        let a = Ipv4Network::parse("10.0.0.0/255.255.0.255").unwrap();
        let b = Ipv4Network::parse("10.1.0.0/255.255.0.255").unwrap();
        assert!(a.is_adjacent(&b));
        assert!(!a.is_adjacent_by_lowest_mask_bit(&b));
    }

    #[test]
    fn ipv4_is_adjacent_by_lowest_mask_bit_identical() {
        let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
        assert!(!a.is_adjacent_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv4_is_adjacent_by_lowest_mask_bit_different_masks() {
        let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let b = Ipv4Network::parse("192.168.0.0/16").unwrap();
        assert!(!a.is_adjacent_by_lowest_mask_bit(&b));
    }

    #[test]
    fn ipv4_is_adjacent_by_lowest_mask_bit_adjacent_but_not_lowest() {
        // Adjacent at the top mask bit, not the lowest one.
        let a = Ipv4Network::parse("0.0.0.0/2").unwrap();
        let b = Ipv4Network::parse("128.0.0.0/2").unwrap();
        assert!(a.is_adjacent(&b));
        assert!(!a.is_adjacent_by_lowest_mask_bit(&b));
    }

    #[test]
    fn ipv4_is_adjacent_by_lowest_mask_bit_default_route() {
        let a = Ipv4Network::parse("0.0.0.0/0").unwrap();
        assert!(!a.is_adjacent_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv6_is_adjacent_by_lowest_mask_bit_cidr_siblings() {
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        assert!(a.is_adjacent_by_lowest_mask_bit(&b));
        assert!(b.is_adjacent_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv6_is_adjacent_by_lowest_mask_bit_host_routes() {
        let a = Ipv6Network::parse("2001:db8::/128").unwrap();
        let b = Ipv6Network::parse("2001:db8::1/128").unwrap();
        assert!(a.is_adjacent_by_lowest_mask_bit(&b));
        assert!(b.is_adjacent_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv6_is_adjacent_by_lowest_mask_bit_non_contiguous_lowest() {
        let a = Ipv6Network::parse("::/ffff:ffff::ffff").unwrap();
        let b = Ipv6Network::parse("::1/ffff:ffff::ffff").unwrap();
        assert!(a.is_adjacent_by_lowest_mask_bit(&b));
        assert!(b.is_adjacent_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv6_is_adjacent_by_lowest_mask_bit_non_contiguous_higher_rejected() {
        // Same non-contiguous mask, but the addresses differ in bit 96 (the
        // bottom of the mask's high run), not its lowest set bit (bit 0).
        let a = Ipv6Network::parse("::/ffff:ffff::ffff").unwrap();
        let b = Ipv6Network::parse("0:1::/ffff:ffff::ffff").unwrap();
        assert!(a.is_adjacent(&b));
        assert!(!a.is_adjacent_by_lowest_mask_bit(&b));
    }

    #[test]
    fn ipv6_is_adjacent_by_lowest_mask_bit_identical() {
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        assert!(!a.is_adjacent_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv6_is_adjacent_by_lowest_mask_bit_different_masks() {
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        let b = Ipv6Network::parse("2001:db8::/32").unwrap();
        assert!(!a.is_adjacent_by_lowest_mask_bit(&b));
    }

    #[test]
    fn ipv6_is_adjacent_by_lowest_mask_bit_adjacent_but_not_lowest() {
        // Adjacent at the top mask bit, not the lowest one.
        let a = Ipv6Network::parse("::/2").unwrap();
        let b = Ipv6Network::parse("8000::/2").unwrap();
        assert!(a.is_adjacent(&b));
        assert!(!a.is_adjacent_by_lowest_mask_bit(&b));
    }

    #[test]
    fn ipv6_is_adjacent_by_lowest_mask_bit_default_route() {
        let a = Ipv6Network::parse("::/0").unwrap();
        assert!(!a.is_adjacent_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ip_is_adjacent_by_lowest_mask_bit_v4() {
        let a = IpNetwork::parse("192.168.0.0/24").unwrap();
        let b = IpNetwork::parse("192.168.1.0/24").unwrap();
        assert!(a.is_adjacent_by_lowest_mask_bit(&b));
    }

    #[test]
    fn ip_is_adjacent_by_lowest_mask_bit_v6() {
        let a = IpNetwork::parse("2001:db8::/48").unwrap();
        let b = IpNetwork::parse("2001:db8:1::/48").unwrap();
        assert!(a.is_adjacent_by_lowest_mask_bit(&b));
    }

    #[test]
    fn ip_is_adjacent_by_lowest_mask_bit_mixed_families() {
        let v4 = IpNetwork::parse("10.0.0.0/8").unwrap();
        let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
        assert!(!v4.is_adjacent_by_lowest_mask_bit(&v6));
    }

    #[test]
    fn ipv4_merge_by_lowest_mask_bit_cidr_siblings() {
        // CIDR siblings differ in the mask's lowest (buddy) bit: they merge into
        // their /23 parent, and `merge` agrees.
        let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
        let expected = Ipv4Network::parse("192.168.0.0/23").unwrap();
        assert_eq!(Some(expected), a.merge_by_lowest_mask_bit(&b));
        assert_eq!(Some(expected), b.merge_by_lowest_mask_bit(&a));
        assert_eq!(a.merge(&b), a.merge_by_lowest_mask_bit(&b));
    }

    #[test]
    fn ipv4_merge_by_lowest_mask_bit_host_routes() {
        // Two hosts differing in the lowest address bit merge into their /31.
        let a = Ipv4Network::parse("10.0.0.0/32").unwrap();
        let b = Ipv4Network::parse("10.0.0.1/32").unwrap();
        let expected = Ipv4Network::parse("10.0.0.0/255.255.255.254").unwrap();
        assert_eq!(Some(expected), a.merge_by_lowest_mask_bit(&b));
        assert_eq!(Some(expected), b.merge_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv4_merge_by_lowest_mask_bit_adjacent_but_higher_bit() {
        // Adjacent at the top mask bit, not the lowest: `merge` combines them
        // into a non-contiguous block, but `merge_by_lowest_mask_bit` rejects.
        let a = Ipv4Network::parse("0.0.0.0/2").unwrap();
        let b = Ipv4Network::parse("128.0.0.0/2").unwrap();
        assert_eq!(Some(Ipv4Network::parse("0.0.0.0/64.0.0.0").unwrap()), a.merge(&b));
        assert_eq!(None, a.merge_by_lowest_mask_bit(&b));
        assert_eq!(None, b.merge_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv4_merge_by_lowest_mask_bit_identical() {
        // Identical networks: `contains` is reflexive, so containment fires and
        // the network is returned unchanged.
        let a = Ipv4Network::parse("192.168.1.0/24").unwrap();
        assert_eq!(Some(a), a.merge_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv4_merge_by_lowest_mask_bit_containment() {
        // Containment fires in both directions and returns the larger network.
        let outer = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let inner = Ipv4Network::parse("10.1.0.0/16").unwrap();
        assert_eq!(Some(outer), outer.merge_by_lowest_mask_bit(&inner));
        assert_eq!(Some(outer), inner.merge_by_lowest_mask_bit(&outer));
    }

    #[test]
    fn ipv4_merge_by_lowest_mask_bit_containment_non_contiguous() {
        // Containment where both masks are non-contiguous: the containing
        // (larger) network is still returned, in either order.
        let outer = Ipv4Network::parse("10.0.0.0/255.0.0.255").unwrap();
        let inner = Ipv4Network::parse("10.0.0.0/255.128.0.255").unwrap();
        assert!(outer.contains(&inner));
        assert_eq!(Some(outer), outer.merge_by_lowest_mask_bit(&inner));
        assert_eq!(Some(outer), inner.merge_by_lowest_mask_bit(&outer));
    }

    #[test]
    fn ipv4_merge_by_lowest_mask_bit_default_route() {
        // A /0 has no lowest mask bit, so the sibling path is unreachable — but a
        // /0 contains every network, itself included, so containment fires.
        let a = Ipv4Network::parse("0.0.0.0/0").unwrap();
        assert_eq!(Some(a), a.merge_by_lowest_mask_bit(&a));
        let b = Ipv4Network::parse("192.168.1.0/24").unwrap();
        assert_eq!(Some(a), a.merge_by_lowest_mask_bit(&b));
        assert_eq!(Some(a), b.merge_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv4_merge_by_lowest_mask_bit_different_masks_no_containment() {
        // Different masks with neither network containing the other: no merge.
        let a = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let b = Ipv4Network::parse("10.0.0.0/16").unwrap();
        assert_eq!(None, a.merge_by_lowest_mask_bit(&b));
        assert_eq!(None, b.merge_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv4_merge_by_lowest_mask_bit_non_contiguous_lowest() {
        // Non-contiguous mask, siblings differ in its lowest set bit (bit 0).
        let a = Ipv4Network::parse("10.0.0.0/255.255.0.255").unwrap();
        let b = Ipv4Network::parse("10.0.0.1/255.255.0.255").unwrap();
        let expected = Ipv4Network::parse("10.0.0.0/255.255.0.254").unwrap();
        assert_eq!(Some(expected), a.merge_by_lowest_mask_bit(&b));
        assert_eq!(Some(expected), b.merge_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv4_merge_by_lowest_mask_bit_non_contiguous_higher_rejected() {
        // Same non-contiguous mask, but the addresses differ at bit 16 (in the
        // mask, but not its lowest set bit): `merge` combines, this rejects.
        let a = Ipv4Network::parse("10.0.0.1/255.255.0.255").unwrap();
        let b = Ipv4Network::parse("10.1.0.1/255.255.0.255").unwrap();
        assert_eq!(Some(Ipv4Network::parse("10.0.0.1/255.254.0.255").unwrap()), a.merge(&b));
        assert_eq!(None, a.merge_by_lowest_mask_bit(&b));
    }

    #[test]
    fn ipv6_merge_by_lowest_mask_bit_cidr_siblings() {
        // Adjacent /48 blocks differ in the mask's lowest bit: they merge into
        // their /47 parent, and `merge` agrees.
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        let b = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        let expected = Ipv6Network::parse("2001:db8::/47").unwrap();
        assert_eq!(Some(expected), a.merge_by_lowest_mask_bit(&b));
        assert_eq!(Some(expected), b.merge_by_lowest_mask_bit(&a));
        assert_eq!(a.merge(&b), a.merge_by_lowest_mask_bit(&b));
    }

    #[test]
    fn ipv6_merge_by_lowest_mask_bit_host_routes() {
        // Two hosts differing in the lowest address bit merge into their /127.
        let a = Ipv6Network::parse("2001:db8::/128").unwrap();
        let b = Ipv6Network::parse("2001:db8::1/128").unwrap();
        let expected = Ipv6Network::parse("2001:db8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe").unwrap();
        assert_eq!(Some(expected), a.merge_by_lowest_mask_bit(&b));
        assert_eq!(Some(expected), b.merge_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv6_merge_by_lowest_mask_bit_adjacent_but_higher_bit() {
        // Adjacent at the top mask bit, not the lowest: `merge` combines them
        // into a non-contiguous block, but `merge_by_lowest_mask_bit` rejects.
        let a = Ipv6Network::parse("::/2").unwrap();
        let b = Ipv6Network::parse("8000::/2").unwrap();
        assert_eq!(Some(Ipv6Network::parse("::/4000::").unwrap()), a.merge(&b));
        assert_eq!(None, a.merge_by_lowest_mask_bit(&b));
        assert_eq!(None, b.merge_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv6_merge_by_lowest_mask_bit_identical() {
        // Identical networks: `contains` is reflexive, so containment fires and
        // the network is returned unchanged.
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        assert_eq!(Some(a), a.merge_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv6_merge_by_lowest_mask_bit_containment() {
        // Containment fires in both directions and returns the larger network.
        let outer = Ipv6Network::parse("2001:db8::/32").unwrap();
        let inner = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        assert_eq!(Some(outer), outer.merge_by_lowest_mask_bit(&inner));
        assert_eq!(Some(outer), inner.merge_by_lowest_mask_bit(&outer));
    }

    #[test]
    fn ipv6_merge_by_lowest_mask_bit_containment_non_contiguous() {
        // Containment where both masks are non-contiguous: the containing
        // (larger) network is still returned, in either order.
        let outer = Ipv6Network::parse("2001::/ffff:ff00::ffff").unwrap();
        let inner = Ipv6Network::parse("2001::/ffff:ff80::ffff").unwrap();
        assert!(outer.contains(&inner));
        assert_eq!(Some(outer), outer.merge_by_lowest_mask_bit(&inner));
        assert_eq!(Some(outer), inner.merge_by_lowest_mask_bit(&outer));
    }

    #[test]
    fn ipv6_merge_by_lowest_mask_bit_default_route() {
        // A /0 has no lowest mask bit, so the sibling path is unreachable — but a
        // /0 contains every network, itself included, so containment fires.
        let a = Ipv6Network::parse("::/0").unwrap();
        assert_eq!(Some(a), a.merge_by_lowest_mask_bit(&a));
        let b = Ipv6Network::parse("2001:db8::/48").unwrap();
        assert_eq!(Some(a), a.merge_by_lowest_mask_bit(&b));
        assert_eq!(Some(a), b.merge_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv6_merge_by_lowest_mask_bit_different_masks_no_containment() {
        // Different masks with neither network containing the other: no merge.
        let a = Ipv6Network::parse("2001:db8::/48").unwrap();
        let b = Ipv6Network::parse("2001:beef::/32").unwrap();
        assert_eq!(None, a.merge_by_lowest_mask_bit(&b));
        assert_eq!(None, b.merge_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv6_merge_by_lowest_mask_bit_non_contiguous_lowest() {
        // Non-contiguous mask, siblings differ in its lowest set bit (bit 0).
        let a = Ipv6Network::parse("2001::/ffff:ff00::ffff").unwrap();
        let b = Ipv6Network::parse("2001::1/ffff:ff00::ffff").unwrap();
        let expected = Ipv6Network::parse("2001::/ffff:ff00::fffe").unwrap();
        assert_eq!(Some(expected), a.merge_by_lowest_mask_bit(&b));
        assert_eq!(Some(expected), b.merge_by_lowest_mask_bit(&a));
    }

    #[test]
    fn ipv6_merge_by_lowest_mask_bit_non_contiguous_higher_rejected() {
        // Same non-contiguous mask, but the addresses differ at bit 104 (in the
        // mask, but not its lowest set bit): `merge` combines, this rejects.
        let a = Ipv6Network::parse("2001::1/ffff:ff00::ffff").unwrap();
        let b = Ipv6Network::parse("2001:100::1/ffff:ff00::ffff").unwrap();
        assert_eq!(
            Some(Ipv6Network::parse("2001::1/ffff:fe00::ffff").unwrap()),
            a.merge(&b)
        );
        assert_eq!(None, a.merge_by_lowest_mask_bit(&b));
    }

    #[test]
    fn ipv6_merge_by_lowest_mask_bit_bicontiguous_q1_degeneration() {
        // Bi-contiguous mask whose low-half run is a single bit (q = 1): its
        // lowest set bit is that lone low-half bit. Merging two siblings across
        // it clears the whole low run, collapsing the 2-D block to a plain /32.
        // The result leaves the strictly-2-D shape but stays in the bi-contiguous
        // class, because a contiguous mask is bi-contiguous.
        let a = Ipv6Network::parse("::/ffff:ffff:0:0:8000::").unwrap();
        let b = Ipv6Network::parse("::8000:0:0:0/ffff:ffff:0:0:8000::").unwrap();
        assert!(a.is_bicontiguous());
        assert!(b.is_bicontiguous());
        assert!(a.is_adjacent_by_lowest_mask_bit(&b));

        let merged = a.merge_by_lowest_mask_bit(&b).unwrap();
        assert_eq!(Ipv6Network::parse("::/ffff:ffff::").unwrap(), merged);
        assert!(merged.is_contiguous());
        assert!(merged.is_bicontiguous());
    }

    #[test]
    fn ip_merge_by_lowest_mask_bit_v4() {
        let a = IpNetwork::parse("192.168.0.0/24").unwrap();
        let b = IpNetwork::parse("192.168.1.0/24").unwrap();
        assert_eq!(
            Some(IpNetwork::parse("192.168.0.0/23").unwrap()),
            a.merge_by_lowest_mask_bit(&b)
        );
    }

    #[test]
    fn ip_merge_by_lowest_mask_bit_v6() {
        let a = IpNetwork::parse("2001:db8::/48").unwrap();
        let b = IpNetwork::parse("2001:db8:1::/48").unwrap();
        assert_eq!(
            Some(IpNetwork::parse("2001:db8::/47").unwrap()),
            a.merge_by_lowest_mask_bit(&b)
        );
    }

    #[test]
    fn ip_merge_by_lowest_mask_bit_mixed_families() {
        let v4 = IpNetwork::parse("10.0.0.0/8").unwrap();
        let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
        assert_eq!(None, v4.merge_by_lowest_mask_bit(&v6));
        assert_eq!(None, v6.merge_by_lowest_mask_bit(&v4));
    }

    #[test]
    fn ipv4_merge_by_lowest_mask_bit_matches_reference_fixed_cases() {
        let cases = [
            // Same mask, lowest-bit siblings (contiguous) -> merge.
            ("192.168.0.0/24", "192.168.1.0/24"),
            // Same mask, lowest-bit siblings (non-contiguous) -> merge.
            ("10.0.0.0/255.255.0.255", "10.0.0.1/255.255.0.255"),
            // Same mask, adjacent at a higher bit -> reject.
            ("0.0.0.0/2", "128.0.0.0/2"),
            // Same mask, identical -> self (containment).
            ("192.168.1.0/24", "192.168.1.0/24"),
            // Containment (different masks) -> larger.
            ("10.0.0.0/8", "10.1.0.0/16"),
            // Different masks, no containment -> reject.
            ("10.0.0.0/8", "172.16.0.0/16"),
            // /0 with itself -> self (containment — no lowest mask bit).
            ("0.0.0.0/0", "0.0.0.0/0"),
        ];

        for (a, b) in cases {
            let a = Ipv4Network::parse(a).unwrap();
            let b = Ipv4Network::parse(b).unwrap();
            assert_eq!(
                ipv4_merge_by_lowest_mask_bit_reference(&a, &b),
                a.merge_by_lowest_mask_bit(&b),
                "mismatch: a={a}, b={b}"
            );
        }
    }

    #[test]
    fn ipv6_merge_by_lowest_mask_bit_matches_reference_fixed_cases() {
        let cases = [
            // Same mask, lowest-bit siblings (contiguous) -> merge.
            ("2001:db8::/48", "2001:db8:1::/48"),
            // Same mask, lowest-bit siblings (non-contiguous) -> merge.
            ("2001::/ffff:ff00::ffff", "2001::1/ffff:ff00::ffff"),
            // Same mask, adjacent at a higher bit -> reject.
            ("::/2", "8000::/2"),
            // Same mask, identical -> self (containment).
            ("2001:db8::/48", "2001:db8::/48"),
            // Containment (different masks) -> larger.
            ("2001:db8::/32", "2001:db8:1::/48"),
            // Different masks, no containment -> reject.
            ("2001:db8::/32", "2001:beef:1::/48"),
            // /0 with itself -> self (containment — no lowest mask bit).
            ("::/0", "::/0"),
        ];

        for (a, b) in cases {
            let a = Ipv6Network::parse(a).unwrap();
            let b = Ipv6Network::parse(b).unwrap();
            assert_eq!(
                ipv6_merge_by_lowest_mask_bit_reference(&a, &b),
                a.merge_by_lowest_mask_bit(&b),
                "mismatch: a={a}, b={b}"
            );
        }
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
            .map(|i| Ipv4Network::from_bits((10 << 24) | (i << 8), 0xFFFFFF00))
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
    fn ipv4_network_to_contiguous_const_fn() {
        const NET: Ipv4Network = Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(255, 255, 0, 255));
        const CONTIGUOUS: Ipv4Network = NET.to_contiguous();

        let expected = Ipv4Network::parse("192.168.0.0/16").unwrap();
        assert_eq!(expected, CONTIGUOUS);
        assert_eq!(NET.to_contiguous(), CONTIGUOUS);
    }

    #[test]
    fn ipv6_network_to_contiguous_const_fn() {
        const NET: Ipv6Network = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0xffff, 0xffff, 0, 0),
        );
        const CONTIGUOUS: Ipv6Network = NET.to_contiguous();

        let expected = Ipv6Network::parse("2001:db8::/40").unwrap();
        assert_eq!(expected, CONTIGUOUS);
        assert_eq!(NET.to_contiguous(), CONTIGUOUS);
    }

    #[test]
    fn ipnetwork_to_contiguous_const_fn() {
        const NET: IpNetwork = IpNetwork::V4(Ipv4Network::new(
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(255, 255, 0, 255),
        ));
        const CONTIGUOUS: IpNetwork = NET.to_contiguous();

        let expected = IpNetwork::parse("192.168.0.0/16").unwrap();
        assert_eq!(expected, CONTIGUOUS);
        assert_eq!(NET.to_contiguous(), CONTIGUOUS);
    }

    #[test]
    fn ipv4_prefix_edge_masks() {
        assert_eq!(Some(0), Ipv4Network::parse("0.0.0.0/0").unwrap().prefix());
        assert_eq!(Some(1), Ipv4Network::parse("128.0.0.0/1").unwrap().prefix());
        assert_eq!(Some(31), Ipv4Network::parse("10.0.0.2/31").unwrap().prefix());
        assert_eq!(Some(32), Ipv4Network::parse("10.0.0.1/32").unwrap().prefix());
        assert_eq!(None, Ipv4Network::parse("10.0.0.1/255.0.0.255").unwrap().prefix());
        // Masks with no leading run at all but bits set elsewhere.
        assert_eq!(None, Ipv4Network::parse("0.0.0.1/0.0.0.255").unwrap().prefix());
        assert_eq!(None, Ipv4Network::parse("0.0.0.0/127.255.255.255").unwrap().prefix());
    }

    #[test]
    fn ipv6_prefix_edge_masks() {
        assert_eq!(Some(0), Ipv6Network::parse("::/0").unwrap().prefix());
        assert_eq!(Some(1), Ipv6Network::parse("8000::/1").unwrap().prefix());
        assert_eq!(Some(127), Ipv6Network::parse("2001:db8::2/127").unwrap().prefix());
        assert_eq!(Some(128), Ipv6Network::parse("2001:db8::1/128").unwrap().prefix());
        assert_eq!(
            None,
            Ipv6Network::parse("2001:db8::1/ffff:ffff::ffff").unwrap().prefix()
        );
        // Masks with no leading run at all but bits set elsewhere.
        assert_eq!(None, Ipv6Network::parse("::1/::ffff").unwrap().prefix());
        assert_eq!(
            None,
            Ipv6Network::parse("::/7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
                .unwrap()
                .prefix()
        );
    }

    // Shared with `net::contiguous`'s test module: `arb_contiguous_ipv4_network`
    // there calls this directly.
    pub(crate) fn arb_ipv4_network() -> impl Strategy<Value = Ipv4Network> {
        (any::<u32>(), any::<u32>()).prop_map(|(a, m)| Ipv4Network::from_bits(a, m))
    }

    // Shared with `net::bicontiguous`'s test module: two of its
    // `prop_ipv6_is_bicontiguous_*`/`prop_bicontiguous_ipv6_tryfrom_*` tests
    // call this directly.
    pub(crate) fn arb_ipv6_network() -> impl Strategy<Value = Ipv6Network> {
        (any::<u128>(), any::<u128>()).prop_map(|(a, m)| Ipv6Network::from_bits(a, m))
    }

    // Shared with both `net::contiguous`'s and `net::bicontiguous`'s test
    // modules (used by several `Contiguous`-only tests in the former, and by
    // `prop_bicontiguous_ipv6_from_contiguous_preserves_value` in the
    // latter), so it stays put instead of moving alongside the other
    // `arb_contiguous_*` strategies.
    pub(crate) fn arb_contiguous_ipv6_network() -> impl Strategy<Value = Contiguous<Ipv6Network>> {
        arb_ipv6_network().prop_map(|net| Contiguous(net.to_contiguous()))
    }

    // A pair of IPv4 networks guaranteed to be lowest-mask-bit siblings: a shared
    // non-zero (possibly non-contiguous) mask and addresses differing only in that
    // mask's lowest set bit. The function `merge_by_lowest_mask_bit` always fires
    // on such a pair.
    fn arb_ipv4_lowest_bit_sibling_pair() -> impl Strategy<Value = (Ipv4Network, Ipv4Network)> {
        (any::<u32>(), any::<u32>())
            .prop_filter("mask must be non-zero", |(.., mask)| *mask != 0)
            .prop_map(|(addr, mask)| {
                let a = Ipv4Network::from_bits(addr, mask);
                let (a_bits, ..) = a.to_bits();
                let lowest = mask & mask.wrapping_neg();
                let b = Ipv4Network::from_bits(a_bits ^ lowest, mask);
                (a, b)
            })
    }

    fn arb_ipv6_lowest_bit_sibling_pair() -> impl Strategy<Value = (Ipv6Network, Ipv6Network)> {
        (any::<u128>(), any::<u128>())
            .prop_filter("mask must be non-zero", |(.., mask)| *mask != 0)
            .prop_map(|(addr, mask)| {
                let a = Ipv6Network::from_bits(addr, mask);
                let (a_bits, ..) = a.to_bits();
                let lowest = mask & mask.wrapping_neg();
                let b = Ipv6Network::from_bits(a_bits ^ lowest, mask);
                (a, b)
            })
    }

    // Same as `arb_ipv4_lowest_bit_sibling_pair`, but the shared mask is a
    // contiguous /p (p >= 1), so the merged parent must stay contiguous.
    fn arb_contiguous_ipv4_sibling_pair() -> impl Strategy<Value = (Ipv4Network, Ipv4Network)> {
        (any::<u32>(), 1u32..=32).prop_map(|(addr, prefix)| {
            let mask = u32::MAX << (32 - prefix);
            let a = Ipv4Network::from_bits(addr, mask);
            let (a_bits, ..) = a.to_bits();
            let lowest = mask & mask.wrapping_neg();
            let b = Ipv4Network::from_bits(a_bits ^ lowest, mask);
            (a, b)
        })
    }

    fn arb_contiguous_ipv6_sibling_pair() -> impl Strategy<Value = (Ipv6Network, Ipv6Network)> {
        (any::<u128>(), 1u32..=128).prop_map(|(addr, prefix)| {
            let mask = u128::MAX << (128 - prefix);
            let a = Ipv6Network::from_bits(addr, mask);
            let (a_bits, ..) = a.to_bits();
            let lowest = mask & mask.wrapping_neg();
            let b = Ipv6Network::from_bits(a_bits ^ lowest, mask);
            (a, b)
        })
    }

    // A pair of bi-contiguous IPv6 siblings: each 64-bit half carries a
    // top-aligned run (prefixes `hi`, `lo`, not both zero), addresses differing
    // only in the whole mask's lowest set bit. The merged parent must stay
    // bi-contiguous (collapsing to contiguous when the low run degenerates).
    fn arb_bicontiguous_ipv6_sibling_pair() -> impl Strategy<Value = (Ipv6Network, Ipv6Network)> {
        (any::<u128>(), 0u32..=64, 0u32..=64)
            .prop_filter("mask must be non-zero", |(.., hi, lo)| *hi != 0 || *lo != 0)
            .prop_map(|(addr, hi_prefix, lo_prefix)| {
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
                let a = Ipv6Network::from_bits(addr, mask);
                let (a_bits, ..) = a.to_bits();
                let lowest = mask & mask.wrapping_neg();
                let b = Ipv6Network::from_bits(a_bits ^ lowest, mask);
                (a, b)
            })
    }

    proptest! {
        #[test]
        fn prop_ipv4_prefix_some_iff_is_contiguous(net in arb_ipv4_network()) {
            prop_assert_eq!(net.is_contiguous(), net.prefix().is_some());
            if let Some(prefix) = net.prefix() {
                prop_assert_eq!(Ok(*net.mask()), ipv4_mask_from_cidr(prefix));
            }
        }

        #[test]
        fn prop_ipv6_prefix_some_iff_is_contiguous(net in arb_ipv6_network()) {
            prop_assert_eq!(net.is_contiguous(), net.prefix().is_some());
            if let Some(prefix) = net.prefix() {
                prop_assert_eq!(Ok(*net.mask()), ipv6_mask_from_cidr(prefix));
            }
        }

        #[test]
        fn prop_ipv4_prefix_roundtrips_cidr(addr in any::<u32>(), cidr in 0u8..=32) {
            let mask = ipv4_mask_from_cidr(cidr).unwrap();
            let net = Ipv4Network::new(Ipv4Addr::from_bits(addr), mask);
            prop_assert_eq!(Some(cidr), net.prefix());
        }

        #[test]
        fn prop_ipv6_prefix_roundtrips_cidr(addr in any::<u128>(), cidr in 0u8..=128) {
            let mask = ipv6_mask_from_cidr(cidr).unwrap();
            let net = Ipv6Network::new(Ipv6Addr::from_bits(addr), mask);
            prop_assert_eq!(Some(cidr), net.prefix());
        }

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
        fn prop_ipv4_merge_by_lowest_mask_bit_matches_reference(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            prop_assert_eq!(
                a.merge_by_lowest_mask_bit(&b),
                ipv4_merge_by_lowest_mask_bit_reference(&a, &b),
                "mismatch: a={}, b={}", a, b
            );
        }

        #[test]
        fn prop_ipv4_merge_by_lowest_mask_bit_some_iff_predicate(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            // Fires exactly on containment (either direction) or a lowest-mask-bit
            // sibling pair.
            prop_assert_eq!(
                a.merge_by_lowest_mask_bit(&b).is_some(),
                a.contains(&b) || b.contains(&a) || a.is_adjacent_by_lowest_mask_bit(&b),
                "a={}, b={}", a, b
            );
        }

        #[test]
        fn prop_ipv4_merge_by_lowest_mask_bit_commutativity(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            prop_assert_eq!(a.merge_by_lowest_mask_bit(&b), b.merge_by_lowest_mask_bit(&a));
        }

        #[test]
        fn prop_ipv4_merge_by_lowest_mask_bit_agrees_with_merge(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
        ) {
            // `merge_by_lowest_mask_bit` is a restriction of `merge`: whenever it
            // fires, it returns exactly the same network.
            if let Some(r) = a.merge_by_lowest_mask_bit(&b) {
                prop_assert_eq!(a.merge(&b), Some(r), "a={}, b={}", a, b);
            }
        }

        #[test]
        fn prop_ipv4_merge_by_lowest_mask_bit_siblings_merge_and_agree(
            (a, b) in arb_ipv4_lowest_bit_sibling_pair(),
        ) {
            let r = a.merge_by_lowest_mask_bit(&b).expect("siblings must merge");
            prop_assert_eq!(a.merge(&b), Some(r), "must agree with merge: a={}, b={}", a, b);
            prop_assert_eq!(a.merge_by_lowest_mask_bit(&b), b.merge_by_lowest_mask_bit(&a));
            prop_assert!(r.contains(&a), "merge result {} must contain {}", r, a);
            prop_assert!(r.contains(&b), "merge result {} must contain {}", r, b);
            let (addr, mask) = r.to_bits();
            prop_assert_eq!(addr & mask, addr, "result not normalized: a={}, b={}, r={}", a, b, r);
        }

        #[test]
        fn prop_ipv4_merge_by_lowest_mask_bit_closure_contiguous(
            (a, b) in arb_contiguous_ipv4_sibling_pair(),
        ) {
            prop_assert!(a.is_contiguous());
            prop_assert!(b.is_contiguous());
            let r = a.merge_by_lowest_mask_bit(&b).expect("siblings must merge");
            prop_assert!(r.is_contiguous(), "contiguous inputs must merge to contiguous: a={}, b={}, r={}", a, b, r);
        }

        #[test]
        fn prop_ipv4_merge_by_lowest_mask_bit_membership_brute_force(
            a_addr in 0u32..=255,
            a_mask in 0u32..=255,
            b_addr in 0u32..=255,
            b_mask in 0u32..=255,
        ) {
            let a = Ipv4Network::from_bits((a_addr & a_mask) << 24, a_mask << 24);
            let b = Ipv4Network::from_bits((b_addr & b_mask) << 24, b_mask << 24);
            let result = a.merge_by_lowest_mask_bit(&b);

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

                // Whenever it fires, the result is exactly the union of A and B.
                if result.is_some() {
                    prop_assert_eq!(
                        in_a || in_b,
                        in_result,
                        "x={} not matching A∪B: a={}, b={}, result={:?}", x, a, b, result
                    );
                }
            }
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

                if (in_a || in_b)
                    && result.is_some() {
                        prop_assert!(
                            in_result,
                            "x={x} in A∪B but not in merge result: a={a}, b={b}, result={result:?}"
                        );
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
        fn prop_ipv6_merge_by_lowest_mask_bit_matches_reference(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            prop_assert_eq!(
                a.merge_by_lowest_mask_bit(&b),
                ipv6_merge_by_lowest_mask_bit_reference(&a, &b),
                "mismatch: a={}, b={}", a, b
            );
        }

        #[test]
        fn prop_ipv6_merge_by_lowest_mask_bit_some_iff_predicate(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            // Fires exactly on containment (either direction) or a lowest-mask-bit
            // sibling pair.
            prop_assert_eq!(
                a.merge_by_lowest_mask_bit(&b).is_some(),
                a.contains(&b) || b.contains(&a) || a.is_adjacent_by_lowest_mask_bit(&b),
                "a={}, b={}", a, b
            );
        }

        #[test]
        fn prop_ipv6_merge_by_lowest_mask_bit_commutativity(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            prop_assert_eq!(a.merge_by_lowest_mask_bit(&b), b.merge_by_lowest_mask_bit(&a));
        }

        #[test]
        fn prop_ipv6_merge_by_lowest_mask_bit_agrees_with_merge(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
        ) {
            // `merge_by_lowest_mask_bit` is a restriction of `merge`: whenever it
            // fires, it returns exactly the same network.
            if let Some(r) = a.merge_by_lowest_mask_bit(&b) {
                prop_assert_eq!(a.merge(&b), Some(r), "a={}, b={}", a, b);
            }
        }

        #[test]
        fn prop_ipv6_merge_by_lowest_mask_bit_siblings_merge_and_agree(
            (a, b) in arb_ipv6_lowest_bit_sibling_pair(),
        ) {
            let r = a.merge_by_lowest_mask_bit(&b).expect("siblings must merge");
            prop_assert_eq!(a.merge(&b), Some(r), "must agree with merge: a={}, b={}", a, b);
            prop_assert_eq!(a.merge_by_lowest_mask_bit(&b), b.merge_by_lowest_mask_bit(&a));
            prop_assert!(r.contains(&a), "merge result {} must contain {}", r, a);
            prop_assert!(r.contains(&b), "merge result {} must contain {}", r, b);
            let (addr, mask) = r.to_bits();
            prop_assert_eq!(addr & mask, addr, "result not normalized: a={}, b={}, r={}", a, b, r);
        }

        #[test]
        fn prop_ipv6_merge_by_lowest_mask_bit_closure_contiguous(
            (a, b) in arb_contiguous_ipv6_sibling_pair(),
        ) {
            prop_assert!(a.is_contiguous());
            prop_assert!(b.is_contiguous());
            let r = a.merge_by_lowest_mask_bit(&b).expect("siblings must merge");
            prop_assert!(r.is_contiguous(), "contiguous inputs must merge to contiguous: a={}, b={}, r={}", a, b, r);
        }

        #[test]
        fn prop_ipv6_merge_by_lowest_mask_bit_closure_bicontiguous(
            (a, b) in arb_bicontiguous_ipv6_sibling_pair(),
        ) {
            prop_assert!(a.is_bicontiguous());
            prop_assert!(b.is_bicontiguous());
            let r = a.merge_by_lowest_mask_bit(&b).expect("siblings must merge");
            prop_assert!(
                r.is_bicontiguous(),
                "bi-contiguous inputs must merge to bi-contiguous: a={}, b={}, r={}", a, b, r
            );
        }

        #[test]
        fn prop_ipv6_merge_by_lowest_mask_bit_membership_brute_force(
            a_addr in 0u128..=255,
            a_mask in 0u128..=255,
            b_addr in 0u128..=255,
            b_mask in 0u128..=255,
        ) {
            let a = Ipv6Network::from_bits((a_addr & a_mask) << 120, a_mask << 120);
            let b = Ipv6Network::from_bits((b_addr & b_mask) << 120, b_mask << 120);
            let result = a.merge_by_lowest_mask_bit(&b);

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

                // Whenever it fires, the result is exactly the union of A and B.
                if result.is_some() {
                    prop_assert_eq!(
                        in_a || in_b,
                        in_result,
                        "x={} not matching A∪B: a={}, b={}, result={:?}", x, a, b, result
                    );
                }
            }
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

                if (in_a || in_b)
                    && result.is_some() {
                        prop_assert!(
                            in_result,
                            "x={x} in A∪B but not in merge result: a={a}, b={b}, result={result:?}"
                        );
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
        fn ipv6_aggregate_preserves_addresses(
            raw_nets in prop::collection::vec(
                (0u128..=255, 120u8..=124),
                1..=32,
            )
        ) {
            let mut nets: Vec<Ipv6Network> = raw_nets
                .iter()
                .map(|&(low_byte, prefix)| {
                    let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
                    let addr = 0x2001_0db8_0000_0000_0000_0000_0000_0000u128 | (low_byte << 8);
                    Ipv6Network::from_bits(addr, mask)
                })
                .collect();

            let mut before_addrs: Vec<u128> = Vec::new();
            for net in &nets {
                for addr in (*net).addrs() {
                    before_addrs.push(addr.to_bits());
                }
            }
            before_addrs.sort_unstable();
            before_addrs.dedup();

            let result = ipv6_aggregate(&mut nets);

            let mut after_addrs: Vec<u128> = Vec::new();
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
        fn ipv6_aggregate_result_is_minimal(
            raw_nets in prop::collection::vec(
                (0u128..=255, 120u8..=124),
                1..=32,
            )
        ) {
            let mut nets: Vec<Ipv6Network> = raw_nets
                .iter()
                .map(|&(low_byte, prefix)| {
                    let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
                    let addr = 0x2001_0db8_0000_0000_0000_0000_0000_0000u128 | (low_byte << 8);
                    Ipv6Network::from_bits(addr, mask)
                })
                .collect();

            let result = ipv6_aggregate(&mut nets);

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
        fn ipv6_aggregate_non_contiguous_preserves_addresses(
            raw_nets in prop::collection::vec(
                (0u128..=0xFF, 0u128..=0xFF),
                1..=8,
            )
        ) {
            let mut nets: Vec<Ipv6Network> = raw_nets
                .iter()
                .map(|&(addr_low, mask_low)| {
                    let addr = 0x2001_0db8_0000_0000_0000_0000_0000_0000u128 | addr_low;
                    let mask = !0xFFu128 | mask_low;
                    Ipv6Network::from_bits(addr, mask)
                })
                .collect();

            let mut before_addrs: Vec<u128> = Vec::new();
            for net in &nets {
                for addr in (*net).addrs() {
                    before_addrs.push(addr.to_bits());
                }
            }
            before_addrs.sort_unstable();
            before_addrs.dedup();

            let result = ipv6_aggregate(&mut nets);

            let mut after_addrs: Vec<u128> = Vec::new();
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

        // `Ipv4/6NetworkDiff::next` constructs items directly from an already
        // `& mask`-ed address instead of re-normalizing through
        // `Ipv4Network::new`/`Ipv6Network::new`. This checks that every
        // yielded network still satisfies the (addr, mask) invariant
        // `addr & mask == addr`.
        #[test]
        fn prop_ipv4_difference_items_are_normalized(a in arb_ipv4_network(), b in arb_ipv4_network()) {
            for net in a.difference(&b) {
                let (addr, mask) = (net.addr().to_bits(), net.mask().to_bits());
                prop_assert_eq!(addr & mask, addr, "a={}, b={}, net={}", a, b, net);
            }
        }

        #[test]
        fn prop_ipv6_difference_items_are_normalized(a in arb_ipv6_network(), b in arb_ipv6_network()) {
            for net in a.difference(&b) {
                let (addr, mask) = (net.addr().to_bits(), net.mask().to_bits());
                prop_assert_eq!(addr & mask, addr, "a={}, b={}, net={}", a, b, net);
            }
        }

        // `Ipv4/6NetworkDiff::count` overrides the default full-iteration
        // fallback with `len()`. This checks the two stay in agreement, and
        // both match manual iteration, over random pairs (contiguous and
        // non-contiguous).
        #[test]
        fn prop_ipv4_difference_count_matches_len(a in arb_ipv4_network(), b in arb_ipv4_network()) {
            let diff = a.difference(&b);
            let len = diff.len();
            let manual = a.difference(&b).fold(0usize, |n, _| n + 1);

            prop_assert_eq!(diff.count(), len, "a={}, b={}", a, b);
            prop_assert_eq!(manual, len, "a={}, b={}", a, b);
        }

        #[test]
        fn prop_ipv6_difference_count_matches_len(a in arb_ipv6_network(), b in arb_ipv6_network()) {
            let diff = a.difference(&b);
            let len = diff.len();
            let manual = a.difference(&b).fold(0usize, |n, _| n + 1);

            prop_assert_eq!(diff.count(), len, "a={}, b={}", a, b);
            prop_assert_eq!(manual, len, "a={}, b={}", a, b);
        }

        // Pins `Ipv4NetworkDiff::next`'s peel order exactly, independent of the
        // folded `mask`/`processed` representation: `d` (bits fixed in
        // `A ∩ B` but free in `A`) is recomputed here from the original `a`,
        // `b`, so each yielded mask's extra bits over `a`'s mask must be a
        // strictly growing subset of `d`, gaining exactly its next-highest
        // unset bit per step, until all of `d` is covered.
        #[test]
        fn prop_ipv4_difference_masks_match_peel_order(a in arb_ipv4_network(), b in arb_ipv4_network()) {
            let (.., source_mask) = a.to_bits();

            let d = match a.intersection(&b) {
                None => {
                    let items: Vec<_> = a.difference(&b).collect();
                    prop_assert_eq!(items, vec![a], "a={}, b={}", a, b);
                    return Ok(());
                }
                Some(inter) => {
                    let (.., inter_mask) = inter.to_bits();
                    inter_mask & !source_mask
                }
            };

            let mut extra_so_far = 0u32;
            for net in a.difference(&b) {
                let (.., mask) = net.to_bits();
                let extra = mask & !source_mask;
                let new_bit = extra & !extra_so_far;
                let not_yet_peeled = d & !extra_so_far;
                let expected_new_bit = 1u32 << (31 - not_yet_peeled.leading_zeros());

                prop_assert_eq!(extra & !d, 0, "a={}, b={}, net={}", a, b, net);
                prop_assert_eq!(extra & extra_so_far, extra_so_far, "a={}, b={}, net={}", a, b, net);
                prop_assert_eq!(new_bit.count_ones(), 1, "a={}, b={}, net={}", a, b, net);
                prop_assert_eq!(new_bit, expected_new_bit, "a={}, b={}, net={}", a, b, net);

                extra_so_far = extra;
            }

            prop_assert_eq!(extra_so_far, d, "a={}, b={}", a, b);
        }

        #[test]
        fn prop_ipv6_difference_masks_match_peel_order(a in arb_ipv6_network(), b in arb_ipv6_network()) {
            let (.., source_mask) = a.to_bits();

            let d = match a.intersection(&b) {
                None => {
                    let items: Vec<_> = a.difference(&b).collect();
                    prop_assert_eq!(items, vec![a], "a={}, b={}", a, b);
                    return Ok(());
                }
                Some(inter) => {
                    let (.., inter_mask) = inter.to_bits();
                    inter_mask & !source_mask
                }
            };

            let mut extra_so_far = 0u128;
            for net in a.difference(&b) {
                let (.., mask) = net.to_bits();
                let extra = mask & !source_mask;
                let new_bit = extra & !extra_so_far;
                let not_yet_peeled = d & !extra_so_far;
                let expected_new_bit = 1u128 << (127 - not_yet_peeled.leading_zeros());

                prop_assert_eq!(extra & !d, 0, "a={}, b={}, net={}", a, b, net);
                prop_assert_eq!(extra & extra_so_far, extra_so_far, "a={}, b={}, net={}", a, b, net);
                prop_assert_eq!(new_bit.count_ones(), 1, "a={}, b={}, net={}", a, b, net);
                prop_assert_eq!(new_bit, expected_new_bit, "a={}, b={}, net={}", a, b, net);

                extra_so_far = extra;
            }

            prop_assert_eq!(extra_so_far, d, "a={}, b={}", a, b);
        }

        // `rev()` must yield exactly the forward sequence in reverse: the
        // per-bit item identity is fixed regardless of which end peels it.
        #[test]
        fn prop_ipv4_difference_rev_matches_forward_reversed(a in arb_ipv4_network(), b in arb_ipv4_network()) {
            let mut forward_reversed: Vec<_> = a.difference(&b).collect();
            forward_reversed.reverse();
            let reversed: Vec<_> = a.difference(&b).rev().collect();
            prop_assert_eq!(reversed, forward_reversed, "a={}, b={}", a, b);
        }

        #[test]
        fn prop_ipv6_difference_rev_matches_forward_reversed(a in arb_ipv6_network(), b in arb_ipv6_network()) {
            let mut forward_reversed: Vec<_> = a.difference(&b).collect();
            forward_reversed.reverse();
            let reversed: Vec<_> = a.difference(&b).rev().collect();
            prop_assert_eq!(reversed, forward_reversed, "a={}, b={}", a, b);
        }

        // Any interleaving of `next`/`next_back` calls must consume exactly
        // the forward-collected sequence from both ends, matching a
        // `VecDeque` popped with the same front/back pattern.
        #[test]
        fn prop_ipv4_difference_interleaved_consumption_matches_forward(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
            pattern in proptest::collection::vec(any::<bool>(), 0..40),
        ) {
            use std::collections::VecDeque;

            let mut expected: VecDeque<_> = a.difference(&b).collect();
            let mut diff = a.difference(&b);

            for pop_front in pattern {
                let expected_item = if pop_front { expected.pop_front() } else { expected.pop_back() };
                let actual_item = if pop_front { diff.next() } else { diff.next_back() };
                prop_assert_eq!(actual_item, expected_item, "a={}, b={}, pop_front={}", a, b, pop_front);
            }
        }

        #[test]
        fn prop_ipv6_difference_interleaved_consumption_matches_forward(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
            pattern in proptest::collection::vec(any::<bool>(), 0..140),
        ) {
            use std::collections::VecDeque;

            let mut expected: VecDeque<_> = a.difference(&b).collect();
            let mut diff = a.difference(&b);

            for pop_front in pattern {
                let expected_item = if pop_front { expected.pop_front() } else { expected.pop_back() };
                let actual_item = if pop_front { diff.next() } else { diff.next_back() };
                prop_assert_eq!(actual_item, expected_item, "a={}, b={}, pop_front={}", a, b, pop_front);
            }
        }

        // `len()` must decrement by exactly one per item consumed, from
        // either end, and stay at zero once exhausted.
        #[test]
        fn prop_ipv4_difference_len_decrements_with_mixed_consumption(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
            pattern in proptest::collection::vec(any::<bool>(), 0..40),
        ) {
            let mut diff = a.difference(&b);

            for pop_front in pattern {
                let len_before = diff.len();
                let item = if pop_front { diff.next() } else { diff.next_back() };
                let len_after = diff.len();

                if item.is_some() {
                    prop_assert_eq!(len_after, len_before - 1, "a={}, b={}, pop_front={}", a, b, pop_front);
                } else {
                    prop_assert_eq!(len_before, 0, "a={}, b={}, pop_front={}", a, b, pop_front);
                    prop_assert_eq!(len_after, 0, "a={}, b={}, pop_front={}", a, b, pop_front);
                }
            }
        }

        #[test]
        fn prop_ipv6_difference_len_decrements_with_mixed_consumption(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
            pattern in proptest::collection::vec(any::<bool>(), 0..140),
        ) {
            let mut diff = a.difference(&b);

            for pop_front in pattern {
                let len_before = diff.len();
                let item = if pop_front { diff.next() } else { diff.next_back() };
                let len_after = diff.len();

                if item.is_some() {
                    prop_assert_eq!(len_after, len_before - 1, "a={}, b={}, pop_front={}", a, b, pop_front);
                } else {
                    prop_assert_eq!(len_before, 0, "a={}, b={}, pop_front={}", a, b, pop_front);
                    prop_assert_eq!(len_after, 0, "a={}, b={}, pop_front={}", a, b, pop_front);
                }
            }
        }

        // `last()` must match the forward-collected sequence's last element,
        // in O(1) instead of the default full walk.
        #[test]
        fn prop_ipv4_difference_last_matches_forward_last(a in arb_ipv4_network(), b in arb_ipv4_network()) {
            let forward: Vec<_> = a.difference(&b).collect();
            let last = a.difference(&b).last();
            prop_assert_eq!(last, forward.last().copied(), "a={}, b={}", a, b);
        }

        #[test]
        fn prop_ipv6_difference_last_matches_forward_last(a in arb_ipv6_network(), b in arb_ipv6_network()) {
            let forward: Vec<_> = a.difference(&b).collect();
            let last = a.difference(&b).last();
            prop_assert_eq!(last, forward.last().copied(), "a={}, b={}", a, b);
        }

        // `last()` after partial forward consumption must still match the
        // last element of whatever remains.
        #[test]
        fn prop_ipv4_difference_last_after_partial_consumption_matches_forward(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
            steps in 0usize..40,
        ) {
            let forward: Vec<_> = a.difference(&b).collect();
            let mut diff = a.difference(&b);

            let consumed = steps.min(forward.len());
            for _ in 0..consumed {
                diff.next();
            }

            let expected = forward[consumed..].last().copied();
            prop_assert_eq!(diff.last(), expected, "a={}, b={}, steps={}", a, b, steps);
        }

        #[test]
        fn prop_ipv6_difference_last_after_partial_consumption_matches_forward(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
            steps in 0usize..140,
        ) {
            let forward: Vec<_> = a.difference(&b).collect();
            let mut diff = a.difference(&b);

            let consumed = steps.min(forward.len());
            for _ in 0..consumed {
                diff.next();
            }

            let expected = forward[consumed..].last().copied();
            prop_assert_eq!(diff.last(), expected, "a={}, b={}, steps={}", a, b, steps);
        }

        // `Ipv6Network::to_ipv4_mapped` truncates an already-normalized
        // (addr, mask) pair to their low 32 bits and constructs the result
        // directly, instead of re-normalizing through `Ipv4Network::new`.
        #[test]
        fn prop_ipv4_to_ipv6_mapped_roundtrip_is_normalized(net4 in arb_ipv4_network()) {
            let mapped = net4.to_ipv6_mapped();
            let recovered = mapped.to_ipv4_mapped();
            prop_assert_eq!(Some(net4), recovered, "net4={}, mapped={}", net4, mapped);

            let recovered = recovered.unwrap();
            let (addr, mask) = (recovered.addr().to_bits(), recovered.mask().to_bits());
            prop_assert_eq!(addr & mask, addr, "net4={}, mapped={}", net4, mapped);
        }
    }

    // Reference oracle for `Ipv4NetworkDiff`: a byte-for-byte copy of the
    // implementation before the peel step was rewritten for speed. The
    // proptests below hold the rewritten iterator to the exact same item
    // sequence from both ends and under arbitrary interleaving.
    struct Ipv4NetworkDiffReference {
        addr: u32,
        mask: u32,
        remaining: u32,
    }

    impl Ipv4NetworkDiffReference {
        fn new(source: &Ipv4Network, other: &Ipv4Network) -> Self {
            let (addr, mask) = source.to_bits();

            match source.intersection(other) {
                None => {
                    let b = mask & mask.wrapping_neg();

                    Self {
                        addr: addr ^ b,
                        mask: mask ^ b,
                        remaining: b,
                    }
                }
                Some(intersected) => {
                    let (intersected_addr, intersected_mask) = intersected.to_bits();
                    let d = intersected_mask & !mask;

                    if d == 0 {
                        Self { addr: 0, mask: 0, remaining: 0 }
                    } else {
                        Self {
                            addr: intersected_addr,
                            mask,
                            remaining: d,
                        }
                    }
                }
            }
        }
    }

    impl Iterator for Ipv4NetworkDiffReference {
        type Item = Ipv4Network;

        fn next(&mut self) -> Option<Self::Item> {
            if self.remaining == 0 {
                return None;
            }

            let b = 0x8000_0000u32 >> self.remaining.leading_zeros();
            self.mask |= b;
            let addr = (self.addr ^ b) & self.mask;
            self.remaining ^= b;

            Some(Ipv4Network(Ipv4Addr::from_bits(addr), Ipv4Addr::from_bits(self.mask)))
        }
    }

    impl DoubleEndedIterator for Ipv4NetworkDiffReference {
        fn next_back(&mut self) -> Option<Self::Item> {
            if self.remaining == 0 {
                return None;
            }

            let b = self.remaining & self.remaining.wrapping_neg();
            let mask = self.mask | self.remaining;
            let addr = (self.addr ^ b) & mask;
            self.remaining ^= b;

            Some(Ipv4Network(Ipv4Addr::from_bits(addr), Ipv4Addr::from_bits(mask)))
        }
    }

    // Reference oracle for `Ipv6NetworkDiff`, mirroring the IPv4 one above.
    struct Ipv6NetworkDiffReference {
        addr: u128,
        mask: u128,
        remaining: u128,
    }

    impl Ipv6NetworkDiffReference {
        fn new(source: &Ipv6Network, other: &Ipv6Network) -> Self {
            let (addr, mask) = source.to_bits();

            match source.intersection(other) {
                None => {
                    let b = mask & mask.wrapping_neg();

                    Self {
                        addr: addr ^ b,
                        mask: mask ^ b,
                        remaining: b,
                    }
                }
                Some(intersected) => {
                    let (inter_addr, inter_mask) = intersected.to_bits();
                    let d = inter_mask & !mask;

                    if d == 0 {
                        Self { addr: 0, mask: 0, remaining: 0 }
                    } else {
                        Self { addr: inter_addr, mask, remaining: d }
                    }
                }
            }
        }
    }

    impl Iterator for Ipv6NetworkDiffReference {
        type Item = Ipv6Network;

        fn next(&mut self) -> Option<Self::Item> {
            if self.remaining == 0 {
                return None;
            }

            let b = 1u128 << (127 - self.remaining.leading_zeros());
            self.mask |= b;
            let addr = (self.addr ^ b) & self.mask;
            self.remaining ^= b;

            Some(Ipv6Network(Ipv6Addr::from_bits(addr), Ipv6Addr::from_bits(self.mask)))
        }
    }

    impl DoubleEndedIterator for Ipv6NetworkDiffReference {
        fn next_back(&mut self) -> Option<Self::Item> {
            if self.remaining == 0 {
                return None;
            }

            let b = self.remaining & self.remaining.wrapping_neg();
            let mask = self.mask | self.remaining;
            let addr = (self.addr ^ b) & mask;
            self.remaining ^= b;

            Some(Ipv6Network(Ipv6Addr::from_bits(addr), Ipv6Addr::from_bits(mask)))
        }
    }

    proptest! {
        #[test]
        fn prop_ipv4_difference_matches_reference_forward(a in arb_ipv4_network(), b in arb_ipv4_network()) {
            let actual: Vec<_> = a.difference(&b).collect();
            let expected: Vec<_> = Ipv4NetworkDiffReference::new(&a, &b).collect();
            prop_assert_eq!(actual, expected, "a={}, b={}", a, b);
        }

        #[test]
        fn prop_ipv4_difference_matches_reference_backward(a in arb_ipv4_network(), b in arb_ipv4_network()) {
            let actual: Vec<_> = a.difference(&b).rev().collect();
            let expected: Vec<_> = Ipv4NetworkDiffReference::new(&a, &b).rev().collect();
            prop_assert_eq!(actual, expected, "a={}, b={}", a, b);
        }

        #[test]
        fn prop_ipv4_difference_matches_reference_interleaved(
            a in arb_ipv4_network(),
            b in arb_ipv4_network(),
            pattern in proptest::collection::vec(any::<bool>(), 0..40),
        ) {
            let mut actual = a.difference(&b);
            let mut expected = Ipv4NetworkDiffReference::new(&a, &b);

            for pop_front in pattern {
                let actual_item = if pop_front { actual.next() } else { actual.next_back() };
                let expected_item = if pop_front { expected.next() } else { expected.next_back() };
                prop_assert_eq!(actual_item, expected_item, "a={}, b={}, pop_front={}", a, b, pop_front);
            }
        }

        #[test]
        fn prop_ipv6_difference_matches_reference_forward(a in arb_ipv6_network(), b in arb_ipv6_network()) {
            let actual: Vec<_> = a.difference(&b).collect();
            let expected: Vec<_> = Ipv6NetworkDiffReference::new(&a, &b).collect();
            prop_assert_eq!(actual, expected, "a={}, b={}", a, b);
        }

        #[test]
        fn prop_ipv6_difference_matches_reference_backward(a in arb_ipv6_network(), b in arb_ipv6_network()) {
            let actual: Vec<_> = a.difference(&b).rev().collect();
            let expected: Vec<_> = Ipv6NetworkDiffReference::new(&a, &b).rev().collect();
            prop_assert_eq!(actual, expected, "a={}, b={}", a, b);
        }

        #[test]
        fn prop_ipv6_difference_matches_reference_interleaved(
            a in arb_ipv6_network(),
            b in arb_ipv6_network(),
            pattern in proptest::collection::vec(any::<bool>(), 0..140),
        ) {
            let mut actual = a.difference(&b);
            let mut expected = Ipv6NetworkDiffReference::new(&a, &b);

            for pop_front in pattern {
                let actual_item = if pop_front { actual.next() } else { actual.next_back() };
                let expected_item = if pop_front { expected.next() } else { expected.next_back() };
                prop_assert_eq!(actual_item, expected_item, "a={}, b={}, pop_front={}", a, b, pop_front);
            }
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

    // Fixed shuffled input. Sorting it with `sort()` must reproduce this
    // exact order, so sorted-input consumers (`ip_binary_split`,
    // `*_aggregate`) keep working across any `Ord` rewrite.
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
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn prop_ipv4_network_ord_matches_addr_mask_tuple(a in arb_ipv4_network(), b in arb_ipv4_network()) {
            let expected = (a.addr(), a.mask()).cmp(&(b.addr(), b.mask()));
            prop_assert_eq!(expected, a.cmp(&b));
            prop_assert_eq!(Some(a.cmp(&b)), a.partial_cmp(&b));
            prop_assert_eq!(a.cmp(&b) == Ordering::Equal, a == b);
        }

        #[test]
        fn prop_ipv6_network_ord_matches_addr_mask_tuple(a in arb_ipv6_network(), b in arb_ipv6_network()) {
            let expected = (a.addr(), a.mask()).cmp(&(b.addr(), b.mask()));
            prop_assert_eq!(expected, a.cmp(&b));
            prop_assert_eq!(Some(a.cmp(&b)), a.partial_cmp(&b));
            prop_assert_eq!(a.cmp(&b) == Ordering::Equal, a == b);
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

        // Randomized counterpart to `ipv4_range_to_networks_items_are_normalized_edge_cases`:
        // every yielded network must still satisfy the (addr, mask) invariant.
        #[test]
        fn prop_ipv4_range_to_networks_items_are_normalized(a in any::<u32>(), b in any::<u32>()) {
            let (first_bits, last_bits) = if a <= b { (a, b) } else { (b, a) };
            let first = Ipv4Addr::from_bits(first_bits);
            let last = Ipv4Addr::from_bits(last_bits);

            for net in ipv4_range_to_networks(first, last) {
                let (addr, mask) = (net.addr().to_bits(), net.mask().to_bits());
                prop_assert_eq!(addr & mask, addr, "first={}, last={}, net={}", first_bits, last_bits, net);
            }
        }

        // Randomized counterpart to `ipv6_range_to_networks_items_are_normalized_edge_cases`:
        // every yielded network must still satisfy the (addr, mask) invariant.
        #[test]
        fn prop_ipv6_range_to_networks_items_are_normalized(a in any::<u128>(), b in any::<u128>()) {
            let (first_bits, last_bits) = if a <= b { (a, b) } else { (b, a) };
            let first = Ipv6Addr::from_bits(first_bits);
            let last = Ipv6Addr::from_bits(last_bits);

            for net in ipv6_range_to_networks(first, last) {
                let (addr, mask) = (net.addr().to_bits(), net.mask().to_bits());
                prop_assert_eq!(addr & mask, addr, "first={}, last={}, net={}", first_bits, last_bits, net);
            }
        }
    }

    // `Ipv4RangeNetworks::next` constructs each block directly from `first`,
    // relying on `n <= trailing_zeros(first)` to guarantee the low bits are
    // already zero, instead of re-normalizing through `Ipv4Network::new`.
    #[test]
    fn ipv4_range_to_networks_items_are_normalized_edge_cases() {
        let cases: &[(u32, u32)] = &[
            (0, u32::MAX),              // full range
            (0, 0),                     // single address at the start
            (u32::MAX, u32::MAX),       // single address at the end
            (1, u32::MAX - 1),          // misaligned worst-case-ish range
            (0x1234_5678, 0x1234_5678), // single misaligned address
        ];

        for &(first, last) in cases {
            let nets = ipv4_range_to_networks(Ipv4Addr::from_bits(first), Ipv4Addr::from_bits(last));
            for net in nets {
                let (addr, mask) = (net.addr().to_bits(), net.mask().to_bits());
                assert_eq!(addr & mask, addr, "first={first}, last={last}, net={net}");
            }
        }
    }

    #[test]
    fn ipv6_range_to_networks_items_are_normalized_edge_cases() {
        let cases: &[(u128, u128)] = &[
            (0, u128::MAX),         // full range
            (0, 0),                 // single address at the start
            (u128::MAX, u128::MAX), // single address at the end
            (1, u128::MAX - 1),     // misaligned worst-case-ish range
            (
                0x1234_5678_9abc_def0_1234_5678_9abc_def0,
                0x1234_5678_9abc_def0_1234_5678_9abc_def0,
            ), // single misaligned address
        ];

        for &(first, last) in cases {
            let nets = ipv6_range_to_networks(Ipv6Addr::from_bits(first), Ipv6Addr::from_bits(last));
            for net in nets {
                let (addr, mask) = (net.addr().to_bits(), net.mask().to_bits());
                assert_eq!(addr & mask, addr, "first={first}, last={last}, net={net}");
            }
        }
    }

    // Reference oracle for `Ipv4RangeNetworks`: a byte-for-byte port of the
    // original greedy `next()` loop (pick the largest block aligned at `first`
    // and not exceeding `last`), kept to pin the yielded sequence across
    // implementation rewrites.
    fn ipv4_range_to_networks_reference(first: u32, last: u32) -> Vec<(u32, u32)> {
        let mut first = first;
        let mut out = Vec::new();
        if first > last {
            return out;
        }
        loop {
            let size = last.wrapping_sub(first).wrapping_add(1);
            let size_log: u32 = if size == 0 { 32 } else { 31 - size.leading_zeros() };
            let align: u32 = if first == 0 { 32 } else { first.trailing_zeros() };
            let n = if size_log < align { size_log } else { align };

            let block_max: u32 = if n == 32 { u32::MAX } else { (1u32 << n) - 1 };
            let end = first.wrapping_add(block_max);
            out.push((first, !block_max));
            if end == last {
                return out;
            }
            first = end + 1;
        }
    }

    // Reference oracle for `Ipv6RangeNetworks`, same construction as
    // `ipv4_range_to_networks_reference`.
    fn ipv6_range_to_networks_reference(first: u128, last: u128) -> Vec<(u128, u128)> {
        let mut first = first;
        let mut out = Vec::new();
        if first > last {
            return out;
        }
        loop {
            let size = last.wrapping_sub(first).wrapping_add(1);
            let size_log: u32 = if size == 0 { 128 } else { 127 - size.leading_zeros() };
            let align: u32 = if first == 0 { 128 } else { first.trailing_zeros() };
            let n = if size_log < align { size_log } else { align };

            let block_max: u128 = if n == 128 { u128::MAX } else { (1u128 << n) - 1 };
            let end = first.wrapping_add(block_max);
            out.push((first, !block_max));
            if end == last {
                return out;
            }
            first = end + 1;
        }
    }

    fn assert_ipv4_range_matches_reference(first: u32, last: u32) {
        let got: Vec<(u32, u32)> = ipv4_range_to_networks(Ipv4Addr::from_bits(first), Ipv4Addr::from_bits(last))
            .map(|net| net.to_bits())
            .collect();
        let want = ipv4_range_to_networks_reference(first, last);
        assert_eq!(want, got, "first={first:#x}, last={last:#x}");
    }

    fn assert_ipv6_range_matches_reference(first: u128, last: u128) {
        let got: Vec<(u128, u128)> = ipv6_range_to_networks(Ipv6Addr::from_bits(first), Ipv6Addr::from_bits(last))
            .map(|net| net.to_bits())
            .collect();
        let want = ipv6_range_to_networks_reference(first, last);
        assert_eq!(want, got, "first={first:#x}, last={last:#x}");
    }

    // Exhaustive pin test over windows chosen to hit every phase shape: ranges
    // touching zero, ranges crossing the top-bit boundary, and ranges touching
    // the address-space maximum. Includes reversed (empty) pairs.
    #[test]
    fn ipv4_range_to_networks_matches_reference_exhaustive_windows() {
        let windows: &[(u32, u32)] = &[(0, 300), (0x7fff_ff80, 0x8000_007f), (u32::MAX - 300, u32::MAX)];
        for &(low, high) in windows {
            for first in low..=high {
                for last in low..=high {
                    assert_ipv4_range_matches_reference(first, last);
                }
            }
        }
    }

    #[test]
    fn ipv6_range_to_networks_matches_reference_exhaustive_windows() {
        let windows: &[(u128, u128)] = &[
            (0, 130),
            ((1u128 << 64) - 65, (1u128 << 64) + 65),
            ((1u128 << 127) - 65, (1u128 << 127) + 65),
            (u128::MAX - 130, u128::MAX),
        ];
        for &(low, high) in windows {
            for first in low..=high {
                for last in low..=high {
                    assert_ipv6_range_matches_reference(first, last);
                }
            }
        }
    }

    proptest! {
        // Raw pairs in both orders: pins the yielded sequence and the empty
        // reversed-range behavior against the reference oracle.
        #[test]
        fn prop_ipv4_range_to_networks_matches_reference(a in any::<u32>(), b in any::<u32>()) {
            assert_ipv4_range_matches_reference(a, b);
        }

        #[test]
        fn prop_ipv6_range_to_networks_matches_reference(a in any::<u128>(), b in any::<u128>()) {
            assert_ipv6_range_matches_reference(a, b);
        }

        // Exact CIDR blocks of every size: targets the single-block ranges
        // (including the full address space) that greedy covers in one step.
        #[test]
        fn prop_ipv4_range_to_networks_matches_reference_single_block(a in any::<u32>(), k in 0..=32u32) {
            let mask = if k == 0 { 0 } else { u32::MAX << (32 - k) };
            let first = a & mask;
            let last = first | !mask;
            assert_ipv4_range_matches_reference(first, last);
        }

        #[test]
        fn prop_ipv6_range_to_networks_matches_reference_single_block(a in any::<u128>(), k in 0..=128u32) {
            let mask = if k == 0 { 0 } else { u128::MAX << (128 - k) };
            let first = a & mask;
            let last = first | !mask;
            assert_ipv6_range_matches_reference(first, last);
        }

        // One aligned endpoint and one arbitrary endpoint: exercises coverings
        // dominated by a single phase (descending-only and ascending-heavy).
        #[test]
        fn prop_ipv4_range_to_networks_matches_reference_aligned_edge(
            a in any::<u32>(),
            b in any::<u32>(),
            k in 0..=32u32,
        ) {
            let mask = if k == 0 { 0 } else { u32::MAX << (32 - k) };
            assert_ipv4_range_matches_reference(a & mask, b);
            assert_ipv4_range_matches_reference(a, b | !mask);
        }

        #[test]
        fn prop_ipv6_range_to_networks_matches_reference_aligned_edge(
            a in any::<u128>(),
            b in any::<u128>(),
            k in 0..=128u32,
        ) {
            let mask = if k == 0 { 0 } else { u128::MAX << (128 - k) };
            assert_ipv6_range_matches_reference(a & mask, b);
            assert_ipv6_range_matches_reference(a, b | !mask);
        }
    }
}
