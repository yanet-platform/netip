//! IPv4/IPv6 network primitives.
//!
//! This library provides types for IP networks by extending the standard
//! library.
//!
//! Unlike most open-source libraries, this library is designed to support
//! non-contiguous masks.

// The library itself needs nothing beyond `core`. Tests are exempt so they keep
// the `std` prelude and may allocate freely. A bare `#![no_std]` would instead
// strip `Vec`, `String`, `vec!` and `format!` from every test module. The
// consequence is that `cargo test` compiles the library against `std`, so the
// test suite cannot catch a `use std::` that slips into runtime code later.
// Only a build for a target without `std` can, and CI does exactly that by
// building the library for `thumbv7em-none-eabihf`.
#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod fmt;
mod macaddr;
mod net;
mod parser;

pub use macaddr::{MacAddr, MacAddrParseError};
pub use net::{
    BiContiguous, BiContiguousIpNetParseError, Contiguous, ContiguousIpNetParseError, IpNetwork, Ipv4Network,
    Ipv4NetworkAddrs, Ipv4NetworkDiff, Ipv4RangeNetworks, Ipv6Network, Ipv6NetworkAddrs, Ipv6NetworkDiff,
    Ipv6RangeNetworks, ipv4_aggregate, ipv4_aggregate_contiguous, ipv4_binary_split, ipv4_range_to_networks,
    ipv6_aggregate, ipv6_aggregate_bicontiguous, ipv6_aggregate_contiguous, ipv6_binary_split, ipv6_range_to_networks,
};
pub use parser::IpNetParseError;
