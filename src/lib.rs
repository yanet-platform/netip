//! IPv4 and IPv6 networks with any mask, and MAC addresses.
//!
//! A network is an address and a mask, and the mask may be any bit pattern.
//! The network is the set of addresses that agree with its address on every
//! bit the mask sets: `10.0.0.0/255.0.255.0` holds the addresses `10.*.0.*`, a
//! pattern that packet classifiers match and that no range expresses. A
//! contiguous mask, a run of ones followed by zeros, makes the network a CIDR
//! block. Containment, intersection, difference, merging, iteration and
//! aggregation work for any mask.
//!
//! netip is `no_std` and never allocates. It has no dependencies and no unsafe
//! code, and most of its methods are `const fn`.
//!
//! # Overview
//!
//! - [`Ipv4Network`] and [`Ipv6Network`] are networks of one family, and
//!   [`IpNetwork`] holds one of either. They parse the prefix and the mask
//!   notations from a `&str`, from bytes with `parse_ascii`, or off the front
//!   of a longer text with `parse_next_ascii`. They test whether a network
//!   contains another network or an address, intersect and merge networks, and
//!   iterate over their addresses in ascending order. The per-family types also
//!   subtract one network from another and split a network into subnets.
//! - [`Contiguous<T>`] holds a network whose mask is contiguous, and
//!   [`BiContiguous<Ipv6Network>`] an IPv6 network whose mask is a prefix in
//!   each 64-bit half. Both dereference to the network, and specialize the
//!   methods that the shape makes faster or whose result keeps the shape.
//! - [`ipv4_aggregate`] and [`ipv6_aggregate`] aggregate a slice of networks in
//!   place, keeping its union of addresses. [`ipv4_aggregate_contiguous`] and
//!   [`ipv6_aggregate_contiguous`] return the minimal CIDR cover of a slice of
//!   [`Contiguous`] networks, and [`ipv6_aggregate_bicontiguous`] aggregates
//!   [`BiContiguous`] ones. [`ipv4_range_to_networks`] and
//!   [`ipv6_range_to_networks`] cover an address range with the fewest CIDR
//!   blocks. [`ipv4_binary_split`] and [`ipv6_binary_split`] find a common
//!   supernet of at least half of the networks in a sorted slice and gather
//!   those it contains, to split a node of a radix tree.
//! - [`MacAddr`] is a MAC (EUI-48) address. It parses the colon, hyphen and
//!   Cisco dot forms, converts to and from the modified EUI-64 interface
//!   identifier of an IPv6 address, and gives the MAC address of an IP
//!   multicast group.
//! - [`fmt`] holds other text forms: [`fmt::Compact`] prints a host route
//!   (`/32` or `/128`) as a bare address, and [`fmt::MacHyphens`] and
//!   [`fmt::MacDots`] print a MAC address with hyphens or Cisco dots.
//!
//! # Example
//!
//! ```
//! use core::net::Ipv4Addr;
//!
//! use netip::{Contiguous, Ipv4Network};
//!
//! // The addresses 10.*.0.*.
//! let net = Ipv4Network::parse("10.0.0.0/255.0.255.0").unwrap();
//! assert!(!net.is_contiguous());
//! assert!(net.contains_addr(&Ipv4Addr::new(10, 42, 0, 7)));
//! assert!(!net.contains_addr(&Ipv4Addr::new(10, 42, 1, 7)));
//!
//! // Those of them in 10.42.0.0/16 form a CIDR block.
//! let block = Ipv4Network::parse("10.42.0.0/16").unwrap();
//! let common = net.intersection(&block).unwrap();
//! assert_eq!(common.to_string(), "10.42.0.0/24");
//!
//! // `Contiguous` takes CIDR blocks only, and its `prefix` is a plain `u8`.
//! assert!(Contiguous::<Ipv4Network>::try_from(net).is_err());
//! let common = Contiguous::<Ipv4Network>::try_from(common).unwrap();
//! assert_eq!(common.prefix(), 24);
//! ```
//!
//! # Stable forms
//!
//! netip has no dependencies, so integrations such as serialization live in
//! other crates. Two forms of the values are part of the stable API for them
//! to build on. Changing either is a breaking change: it ships in a minor
//! version bump while netip is `0.x`, and in a major one from `1.0` on.
//!
//! - **Text.** The [`Display`](core::fmt::Display) text of every network type,
//!   of [`fmt::Compact`], of [`MacAddr`] and of the MAC adapters
//!   [`fmt::MacHyphens`] and [`fmt::MacDots`] does not change, and parsing
//!   reads it back: for a value `v` of type `T`, `v.to_string().parse::<T>()`
//!   returns `Ok(v)`, as do `T::parse` and `T::parse_ascii` where `T` has them.
//!   The same holds for the text of `Compact(v)`, and for the text of a MAC
//!   address in either adapter and either case, `{:x}` or `{:X}`, read as a
//!   [`MacAddr`]. Only the plain text is covered: a width or a precision in the
//!   format string pads or truncates it.
//! - **Bits.** [`Ipv4Network::to_bits`] and [`Ipv6Network::to_bits`] return the
//!   address and the mask as integers in the bit order of
//!   [`Ipv4Addr::to_bits`](core::net::Ipv4Addr::to_bits), and `from_bits`
//!   rebuilds the network from them. `from_bits` normalizes the address, so
//!   `from_bits(addr, mask).to_bits()` is `(addr & mask, mask)`.
//!   [`MacAddr::octets`] and `From<[u8; 6]>` round-trip a MAC address, and so
//!   do [`MacAddr::as_u64`] and [`MacAddr::from_u64`], which hold the octets in
//!   the lower 48 bits of the integer, the first octet highest:
//!   `MacAddr::from_u64(mac.as_u64())` is `Some(mac)`.

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]
#![deny(unnameable_types)]
#![forbid(unsafe_code)]

pub mod fmt;
mod macaddr;
mod net;
mod parser;

pub use macaddr::{MacAddr, MacAddrParseError};
pub use net::{
    BiContiguous, BiContiguousIpNetParseError, BiContiguousIpv6NetworkAddrs, CidrOverflowError, Contiguous,
    ContiguousIpNetParseError, ContiguousIpv4NetworkAddrs, ContiguousIpv6NetworkAddrs, IpNetwork, IpNetworkAddrs,
    IpVersionMismatchError, Ipv4Network, Ipv4NetworkAddrs, Ipv4NetworkDiff, Ipv4NetworkPrefixSubnets,
    Ipv4NetworkSubnets, Ipv4RangeNetworks, Ipv6Network, Ipv6NetworkAddrs, Ipv6NetworkDiff, Ipv6NetworkPrefixSubnets,
    Ipv6NetworkSubnets, Ipv6RangeNetworks, ipv4_aggregate, ipv4_aggregate_contiguous, ipv4_binary_split,
    ipv4_range_to_networks, ipv6_aggregate, ipv6_aggregate_bicontiguous, ipv6_aggregate_contiguous, ipv6_binary_split,
    ipv6_range_to_networks,
};
pub use parser::IpNetParseError;

/// The error types are non-exhaustive. Outside netip, a `match` on an error
/// enum needs a wildcard arm, and a unit error struct can't be built, so each
/// block below fails to compile.
///
/// ```compile_fail
/// fn kind(err: netip::IpNetParseError) -> u8 {
///     match err {
///         netip::IpNetParseError::AddrParseError(..) => 0,
///         netip::IpNetParseError::CidrOverflow(..) => 1,
///     }
/// }
/// ```
///
/// ```compile_fail
/// fn kind(err: netip::ContiguousIpNetParseError) -> u8 {
///     match err {
///         netip::ContiguousIpNetParseError::NonContiguousNetwork => 0,
///         netip::ContiguousIpNetParseError::IpNetParseError(..) => 1,
///     }
/// }
/// ```
///
/// ```compile_fail
/// fn kind(err: netip::BiContiguousIpNetParseError) -> u8 {
///     match err {
///         netip::BiContiguousIpNetParseError::NonBiContiguousNetwork => 0,
///         netip::BiContiguousIpNetParseError::IpNetParseError(..) => 1,
///     }
/// }
/// ```
///
/// ```compile_fail
/// let _ = netip::MacAddrParseError;
/// ```
///
/// ```compile_fail
/// let _ = netip::IpVersionMismatchError;
/// ```
#[cfg(doctest)]
struct NonExhaustiveErrors;

/// The difference iterators have no public constructor. Outside netip,
/// [`Ipv4NetworkDiff`] and [`Ipv6NetworkDiff`] come only from `difference`, so
/// each block below fails to compile.
///
/// ```compile_fail
/// let net = netip::Ipv4Network::parse("10.0.0.0/8").unwrap();
/// let _ = netip::Ipv4NetworkDiff::new(&net, &net);
/// ```
///
/// ```compile_fail
/// let net = netip::Ipv6Network::parse("2001:db8::/32").unwrap();
/// let _ = netip::Ipv6NetworkDiff::new(&net, &net);
/// ```
#[cfg(doctest)]
struct PrivateDiffConstructors;
