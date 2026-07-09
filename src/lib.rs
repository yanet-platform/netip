//! IPv4/IPv6 network primitives.
//!
//! This library provides types for IP networks by extending the standard
//! library.
//!
//! Unlike most open-source libraries, this library is designed to support
//! non-contiguous masks.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod fmt;
mod macaddr;
mod net;

pub use macaddr::{MacAddr, MacAddrParseError};
pub use net::{
    BiContiguous, BiContiguousIpNetParseError, Contiguous, ContiguousIpNetParseError, IpNetParseError, IpNetwork,
    Ipv4Network, Ipv4NetworkAddrs, Ipv4NetworkDiff, Ipv4RangeNetworks, Ipv6Network, Ipv6NetworkAddrs, Ipv6NetworkDiff,
    Ipv6RangeNetworks, ipv4_aggregate, ipv4_aggregate_contiguous, ipv4_binary_split, ipv4_range_to_networks,
    ipv6_aggregate, ipv6_aggregate_bicontiguous, ipv6_aggregate_contiguous, ipv6_binary_split, ipv6_range_to_networks,
};
