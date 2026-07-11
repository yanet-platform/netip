//! Alternative formatting adapters for network types.

use core::fmt::{Display, Formatter};

use crate::net::{IpNetwork, Ipv4Network, Ipv6Network};

/// Displays a network using the **compact** representation:
///
/// - host routes (`/32`, `/128`) are printed as a bare address,
/// - other contiguous networks as `addr/prefix`,
/// - non-contiguous networks as `addr/explicit-mask`.
///
/// The base [`Display`] of the network types always prints an explicit prefix
/// (`1.2.3.4/32`). Wrap a value in `Compact` to get the bare-address form where
/// it is part of an output contract.
///
/// # Examples
///
/// ```
/// use netip::{IpNetwork, fmt::Compact};
///
/// let host = IpNetwork::parse("127.0.0.1").unwrap();
/// assert_eq!("127.0.0.1/32", format!("{host}"));
/// assert_eq!("127.0.0.1", format!("{}", Compact(host)));
///
/// let net = IpNetwork::parse("10.0.0.0/24").unwrap();
/// assert_eq!("10.0.0.0/24", format!("{}", Compact(net)));
///
/// let net = IpNetwork::parse("192.168.0.1/255.255.0.255").unwrap();
/// assert_eq!("192.168.0.1/255.255.0.255", format!("{}", Compact(net)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Compact<T>(pub T);

impl Display for Compact<Ipv4Network> {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), core::fmt::Error> {
        let Self(net) = self;
        match net.prefix() {
            Some(32) => Display::fmt(net.addr(), fmt),
            Some(prefix) => fmt.write_fmt(format_args!("{}/{}", net.addr(), prefix)),
            // This is a non-contiguous network, expand the mask.
            None => fmt.write_fmt(format_args!("{}/{}", net.addr(), net.mask())),
        }
    }
}

impl Display for Compact<Ipv6Network> {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), core::fmt::Error> {
        let Self(net) = self;
        match net.prefix() {
            Some(128) => Display::fmt(net.addr(), fmt),
            Some(prefix) => fmt.write_fmt(format_args!("{}/{}", net.addr(), prefix)),
            // This is a non-contiguous network, expand the mask.
            None => fmt.write_fmt(format_args!("{}/{}", net.addr(), net.mask())),
        }
    }
}

impl Display for Compact<IpNetwork> {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), core::fmt::Error> {
        match self {
            Self(IpNetwork::V4(net)) => Display::fmt(&Compact(*net), fmt),
            Self(IpNetwork::V6(net)) => Display::fmt(&Compact(*net), fmt),
        }
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::Compact;
    use crate::net::{IpNetwork, Ipv4Network, Ipv6Network};

    #[test]
    fn ipv4_host_route_is_bare() {
        let net = Ipv4Network::parse("127.0.0.1").unwrap();
        assert_eq!("127.0.0.1", Compact(net).to_string());
    }

    #[test]
    fn ipv4_contiguous_has_prefix() {
        let net = Ipv4Network::parse("10.0.0.0/24").unwrap();
        assert_eq!("10.0.0.0/24", Compact(net).to_string());
    }

    #[test]
    fn ipv4_non_contiguous_has_mask() {
        let net = Ipv4Network::parse("192.168.0.1/255.255.0.255").unwrap();
        assert_eq!("192.168.0.1/255.255.0.255", Compact(net).to_string());
    }

    #[test]
    fn ipv6_host_route_is_bare() {
        let net = Ipv6Network::parse("::1").unwrap();
        assert_eq!("::1", Compact(net).to_string());
    }

    #[test]
    fn ipv6_contiguous_has_prefix() {
        let net = Ipv6Network::parse("2001:db8::/32").unwrap();
        assert_eq!("2001:db8::/32", Compact(net).to_string());
    }

    #[test]
    fn ipv6_non_contiguous_has_mask() {
        let net = Ipv6Network::parse("2001:db8::1/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
        // A non-contiguous mask has no prefix, so Compact keeps the explicit
        // mask and matches the base `Display`.
        assert_eq!(net.prefix(), None);
        assert_eq!(net.to_string(), Compact(net).to_string());
    }

    #[test]
    fn ip_network_delegates_to_inner() {
        let host = IpNetwork::parse("127.0.0.1").unwrap();
        assert_eq!("127.0.0.1", Compact(host).to_string());

        let net = IpNetwork::parse("2001:db8::/32").unwrap();
        assert_eq!("2001:db8::/32", Compact(net).to_string());
    }

    fn arb_ipv4_network() -> impl Strategy<Value = Ipv4Network> {
        (any::<u32>(), any::<u32>()).prop_map(|(a, m)| Ipv4Network::from_bits(a, m))
    }

    fn arb_ipv6_network() -> impl Strategy<Value = Ipv6Network> {
        (any::<u128>(), any::<u128>()).prop_map(|(a, m)| Ipv6Network::from_bits(a, m))
    }

    proptest! {
        /// Compact differs from the base `Display` only by dropping the prefix
        /// of host routes. Otherwise the two agree.
        #[test]
        fn prop_ipv4_compact_matches_display_except_host(net in arb_ipv4_network()) {
            let compact = Compact(net).to_string();
            let full = net.to_string();
            if net.prefix() == Some(32) {
                prop_assert_eq!(compact, net.addr().to_string());
            } else {
                prop_assert_eq!(compact, full);
            }
        }

        #[test]
        fn prop_ipv6_compact_matches_display_except_host(net in arb_ipv6_network()) {
            let compact = Compact(net).to_string();
            let full = net.to_string();
            if net.prefix() == Some(128) {
                prop_assert_eq!(compact, net.addr().to_string());
            } else {
                prop_assert_eq!(compact, full);
            }
        }

        /// The `IpNetwork` adapter is exactly the inner-type adapter.
        #[test]
        fn prop_ip_network_compact_delegates(net in arb_ipv4_network()) {
            prop_assert_eq!(Compact(IpNetwork::V4(net)).to_string(), Compact(net).to_string());
        }
    }
}
