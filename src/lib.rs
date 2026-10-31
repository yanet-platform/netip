//! IPv4/IPv6 network primitives.
//!
//! This library provides types for IP networks by extending the standard
//! library.
//!
//! Unlike most open-source libraries, this library is designed to support
//! non-contiguous masks.
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
