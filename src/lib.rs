//! IPv4/IPv6 network primitives.
//!
//! This library provides types for IP networks by extending the standard
//! library.
//!
//! Unlike most open-source libraries, this library is designed to support
//! non-contiguous masks.

mod macaddr;
mod net;

pub use macaddr::{MacAddr, MacAddrParseError};
pub use net::{
    Contiguous, ContiguousIpNetParseError, IpNetParseError, IpNetwork, Ipv4Network, Ipv4NetworkAddrs, Ipv6Network,
    Ipv6NetworkAddrs, ipv4_binary_split, ipv6_binary_split,
};
