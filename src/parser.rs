//! Hand-rolled, allocation-free ASCII parsers for IPv4/IPv6 networks,
//! addresses and CIDR suffixes.
//!
//! Replicates `core::net`'s address grammar exactly (leading-zero rejection
//! in IPv4 octets, a single `::` run, embedded trailing IPv4 in IPv6, up to
//! 4 hex digits per group, ...), but without `core::net::parser::Parser`'s
//! combinator/closure machinery and its up to 7 speculative embedded-IPv4
//! re-parse attempts per address.
//!
//! On reject, the parsers fall back to `core::net`'s `FromStr` to
//! manufacture the genuine `AddrParseError`, which has no public
//! constructor. Non-UTF-8 input takes an equal-valued error from a
//! canonical failing parse instead.

use core::{
    error::Error,
    fmt::{Display, Formatter},
    net::{AddrParseError, Ipv4Addr, Ipv6Addr},
    num::ParseIntError,
    str,
};

use crate::net::{CidrOverflowError, IPV4_ALL_BITS, IPV6_ALL_BITS, IpNetwork, Ipv4Network, Ipv6Network};

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

/// A zero-cost reject signal for the parsers in this module.
///
/// Carries no data: every caller either discards it (CIDR suffix, whose
/// numeric parse failure already falls through to a dotted/colon-mask
/// re-parse) or re-parses the same input through `core::net`'s `FromStr` to
/// obtain a real error value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParseError;

/// Parses an [`IpNetwork`] in CIDR, explicit-mask, or bare-address
/// notation, dispatching between the address families.
#[inline]
pub fn parse_ip_network(buf: &str) -> Result<IpNetwork, IpNetParseError> {
    parse_ip_network_ascii(buf.as_bytes())
}

/// Parses an [`IpNetwork`] from ASCII bytes, dispatching between the
/// address families.
///
/// A `:` anywhere in the input can never appear in a valid IPv4 network, so
/// such input goes straight to the IPv6 parser. Everything else tries IPv4
/// first and falls through to IPv6 only on an address-shaped error.
pub fn parse_ip_network_ascii(buf: &[u8]) -> Result<IpNetwork, IpNetParseError> {
    if !contains_colon(buf) {
        match parse_ipv4_network_ascii(buf) {
            Ok(net) => return Ok(IpNetwork::V4(net)),
            Err(IpNetParseError::AddrParseError(..)) => {}
            Err(err) => return Err(err),
        }
    }

    Ok(IpNetwork::V6(parse_ipv6_network_ascii(buf)?))
}

/// Whether `buf` contains a `:` anywhere, marking IPv6 (address or
/// colon-mask) text.
///
/// A hand-rolled byte scan on purpose: `<[u8]>::contains` is specialized to
/// an outlined `memchr` call, oversized for address-sized inputs.
#[inline]
fn contains_colon(buf: &[u8]) -> bool {
    for &byte in buf {
        if byte == b':' {
            return true;
        }
    }
    false
}

/// Parses an [`Ipv4Network`] in CIDR (`10.0.0.0/8`), explicit-mask
/// (`10.0.0.0/255.0.0.0`), or bare-address notation.
#[inline]
pub fn parse_ipv4_network(buf: &str) -> Result<Ipv4Network, IpNetParseError> {
    parse_ipv4_network_ascii(buf.as_bytes())
}

/// Parses an [`Ipv4Network`] from ASCII bytes.
///
/// The fast path parses the address as a prefix and dispatches on the byte
/// that stopped it, folding the `/` scan into the parse itself. The bytes
/// before `consumed` are all digits and dots, so a `/` there is necessarily
/// the first one in the input, exactly where the fallback's split would
/// cut. Everything else defers to the split-first fallback, which owns
/// every reject and its genuine error value.
pub fn parse_ipv4_network_ascii(buf: &[u8]) -> Result<Ipv4Network, IpNetParseError> {
    if let Some((addr, consumed)) = ipv4_parse_at(buf) {
        match buf.get(consumed) {
            None => return Ok(Ipv4Network::new(addr, IPV4_ALL_BITS)),
            Some(&b'/') => return ipv4_apply_mask(addr, &buf[consumed + 1..]),
            Some(..) => {}
        }
    }
    parse_ipv4_network_fallback(buf)
}

/// Parses a dotted-decimal IPv4 address as a prefix of `bytes`.
///
/// Returns the address and the number of bytes consumed. Positions travel
/// as a cursor rather than `(value, rest)` sub-slices: re-slicing after
/// every octet measured slower, since each sub-slice rebuilds a pointer and
/// length pair the octet reader immediately re-splits. Shared by
/// [`parse_ipv4_network`]'s fused fast path, the standalone
/// [`ipv4_parse_ascii`], and the embedded-IPv4 tail of an IPv6 address.
///
/// Forced inline: a plain `#[inline]` left this behind a real call,
/// spilling its return value to the stack instead of keeping it in
/// registers.
#[inline(always)]
fn ipv4_parse_at(bytes: &[u8]) -> Option<(Ipv4Addr, usize)> {
    let (a, pos) = read_ipv4_octet(bytes, 0)?;
    if bytes.get(pos) != Some(&b'.') {
        return None;
    }
    let (b, pos) = read_ipv4_octet(bytes, pos + 1)?;
    if bytes.get(pos) != Some(&b'.') {
        return None;
    }
    let (c, pos) = read_ipv4_octet(bytes, pos + 1)?;
    if bytes.get(pos) != Some(&b'.') {
        return None;
    }
    let (d, pos) = read_ipv4_octet(bytes, pos + 1)?;

    Some((Ipv4Addr::new(a, b, c, d), pos))
}

/// Parses one decimal IPv4 octet (`0`-`255`) starting at `start`.
///
/// Reads up to 3 bytes via fixed-index `get`s, each past the end of the
/// input reading as a non-digit sentinel, so the candidate digits are
/// independent register-only loads with no re-slicing. A leading zero
/// followed by another digit is rejected outright, matching `core::net`'s
/// octal-injection guard. A 3-digit run over `255` is rejected the same
/// way. Returns the value and the position just past the octet.
///
/// Forced inline: a plain `#[inline]` leaves this behind a real call at its
/// four call sites in [`ipv4_parse_at`].
#[inline(always)]
fn read_ipv4_octet(bytes: &[u8], start: usize) -> Option<(u8, usize)> {
    let digit0 = ascii_digit_value(bytes.get(start).copied()?)?;
    let byte1 = bytes.get(start + 1).copied().unwrap_or(b'.');
    let Some(digit1) = ascii_digit_value(byte1) else {
        return Some((digit0, start + 1));
    };
    if digit0 == 0 {
        return None;
    }

    let value = digit0 as u16 * 10 + digit1 as u16;
    let byte2 = bytes.get(start + 2).copied().unwrap_or(b'.');
    let Some(digit2) = ascii_digit_value(byte2) else {
        return Some((value as u8, start + 2)); // Two digits: at most 99, always in range.
    };
    let value = value * 10 + digit2 as u16;
    if value <= u8::MAX as u16 {
        Some((value as u8, start + 3))
    } else {
        None
    }
}

#[inline]
const fn ascii_digit_value(byte: u8) -> Option<u8> {
    if byte.wrapping_sub(b'0') <= 9 {
        Some(byte - b'0')
    } else {
        None
    }
}

/// Applies an already-split mask part (CIDR or dotted) to an address.
#[inline(always)]
fn ipv4_apply_mask(addr: Ipv4Addr, mask: &[u8]) -> Result<Ipv4Network, IpNetParseError> {
    match parse_cidr_suffix(mask) {
        Ok(cidr) => Ok(Ipv4Network::try_from((addr, cidr))?),
        Err(..) => {
            // Maybe explicit mask.
            let mask = parse_ipv4_addr(mask)?;
            Ok(Ipv4Network::new(addr, mask))
        }
    }
}

/// Parses a CIDR suffix in the same grammar as `u8::from_str`.
///
/// Accepts one optional leading `+` (but never `-`, since the target is
/// unsigned) followed by one or more decimal digits, with no leading-zero
/// restriction and no digit-count limit short of overflowing `u8`. This
/// matches `core::num`'s integer parser exactly, including its `+` quirk.
/// Unlike the address parsers, a reject here is never re-parsed for a
/// genuine error: every caller already falls through to a dotted/colon-mask
/// re-parse of the same text on any CIDR-suffix parse failure.
#[inline]
fn parse_cidr_suffix(bytes: &[u8]) -> Result<u8, ParseError> {
    let digits = match bytes {
        [b'+', rest @ ..] => rest,
        _ => bytes,
    };
    if digits.is_empty() {
        return Err(ParseError);
    }

    let mut value: u16 = 0;
    for &byte in digits {
        let Some(digit) = ascii_digit_value(byte) else {
            return Err(ParseError);
        };
        value = value * 10 + digit as u16;
        if value > u8::MAX as u16 {
            return Err(ParseError);
        }
    }
    Ok(value as u8)
}

/// Parses an IPv4 address, falling back to `core::net`'s `FromStr` on
/// reject to obtain the genuine `AddrParseError`.
///
/// The fallback can never itself accept something [`ipv4_parse_ascii`]
/// rejected: it exists purely as a safety net and an error-value source.
/// Keeping it outlined and cold leaves only the hand-rolled hot path to
/// inline into the callers.
#[inline]
fn parse_ipv4_addr(bytes: &[u8]) -> Result<Ipv4Addr, IpNetParseError> {
    match ipv4_parse_ascii(bytes) {
        Ok(addr) => Ok(addr),
        Err(..) => parse_ipv4_addr_error(bytes),
    }
}

#[cold]
#[inline(never)]
fn parse_ipv4_addr_error(bytes: &[u8]) -> Result<Ipv4Addr, IpNetParseError> {
    // Non-UTF-8 input cannot reach core's parser, but it does not need to:
    // every IPv4 `AddrParseError` carries the same value, so one from a
    // canonical failing parse is indistinguishable from a genuine one.
    match str::from_utf8(bytes) {
        Ok(s) => Ok(s.parse()?),
        Err(..) => match "".parse::<Ipv4Addr>() {
            Err(err) => Err(err.into()),
            Ok(..) => unreachable!(),
        },
    }
}

/// Parses a dotted-decimal IPv4 address, e.g. `192.168.0.1`.
fn ipv4_parse_ascii(bytes: &[u8]) -> Result<Ipv4Addr, ParseError> {
    // The longest valid address, "255.255.255.255", is 15 bytes. Anything
    // longer can never parse, so this is a fast reject.
    if bytes.len() > 15 {
        return Err(ParseError);
    }
    match ipv4_parse_at(bytes) {
        Some((addr, consumed)) if consumed == bytes.len() => Ok(addr),
        _ => Err(ParseError),
    }
}

/// The reject arm of [`parse_ipv4_network_ascii`]: re-parses through the
/// split-first path purely to manufacture the correct error value.
#[cold]
#[inline(never)]
fn parse_ipv4_network_fallback(buf: &[u8]) -> Result<Ipv4Network, IpNetParseError> {
    let (addr, mask) = split_slash(buf);
    let addr = parse_ipv4_addr(addr)?;
    match mask {
        Some(mask) => ipv4_apply_mask(addr, mask),
        None => Ok(Ipv4Network::new(addr, IPV4_ALL_BITS)),
    }
}

/// Splits `buf` at the first `/` into address bytes and an optional mask.
///
/// A hand-rolled byte scan on purpose: `split_once`-style searches lower to
/// an outlined `memchr` call, whose call and alignment-prologue overhead
/// dominates on address-sized inputs (well under one cache line).
#[inline]
fn split_slash(buf: &[u8]) -> (&[u8], Option<&[u8]>) {
    for (index, &byte) in buf.iter().enumerate() {
        if byte == b'/' {
            return (&buf[..index], Some(&buf[index + 1..]));
        }
    }
    (buf, None)
}

/// Parses an [`Ipv6Network`] in CIDR (`2001:db8::/32`), explicit-mask
/// (`2001:db8::/ffff:ffff::`), or bare-address notation.
#[inline]
pub fn parse_ipv6_network(buf: &str) -> Result<Ipv6Network, IpNetParseError> {
    parse_ipv6_network_ascii(buf.as_bytes())
}

/// Parses an [`Ipv6Network`] from ASCII bytes.
///
/// The fast path mirrors [`parse_ipv4_network_ascii`]: the bytes before
/// `consumed` are all hex digits, colons, and dots, so a `/` at `consumed`
/// is necessarily the first one in the input, exactly where the fallback's
/// split would cut.
pub fn parse_ipv6_network_ascii(buf: &[u8]) -> Result<Ipv6Network, IpNetParseError> {
    if let Some((addr, consumed)) = ipv6_parse_at(buf) {
        match buf.get(consumed) {
            None => return Ok(Ipv6Network::new(addr, IPV6_ALL_BITS)),
            Some(&b'/') => return ipv6_apply_mask(addr, &buf[consumed + 1..]),
            Some(..) => {}
        }
    }
    parse_ipv6_network_fallback(buf)
}

/// Parses an IPv6 address as a prefix of `bytes`.
///
/// Returns the address and the number of bytes consumed, mirroring
/// [`ipv4_parse_at`]. Trailing input is the caller's concern. Reads the
/// front run of groups. If it fills all 8, the address has no `::`.
/// Otherwise a `::` (one or more zero groups) is required, followed by the
/// back run of groups. Both runs assemble to top-aligned values and the
/// back run bottom-aligns with a single shift, so no group array or splice
/// pass is needed. An embedded IPv4 address filling less than the full
/// front run is rejected outright: it can only ever supply the last 2 of
/// the 8 groups of a `::`-free address.
fn ipv6_parse_at(bytes: &[u8]) -> Option<(Ipv6Addr, usize)> {
    let (head_high, head_low, head_count, head_ipv4, rest) = read_ipv6_groups(bytes, 8);

    if head_count == 8 {
        let addr = Ipv6Addr::from_bits(assemble_ipv6_groups(head_high, head_low, 8));
        return Some((addr, bytes.len() - rest.len()));
    }
    if head_ipv4 {
        return None;
    }

    let [b':', b':', rest @ ..] = rest else {
        return None;
    };

    // The `::` stands for at least one zero group, capping the back run at
    // `7 - head_count` groups.
    let (tail_high, tail_low, tail_count, .., rest) = read_ipv6_groups(rest, 7 - head_count);

    // The head run already sits where it belongs. The tail run must move to
    // the bottom `16 * tail_count` bits, leaving the `::` zeros in between.
    let head_bits = assemble_ipv6_groups(head_high, head_low, head_count);
    let tail_shifted = if tail_count == 0 {
        0
    } else {
        assemble_ipv6_groups(tail_high, tail_low, tail_count) >> (128 - 16 * tail_count)
    };
    Some((Ipv6Addr::from_bits(head_bits | tail_shifted), bytes.len() - rest.len()))
}

/// Reads a run of colon-separated IPv6 groups, stopping at the first
/// position that cannot extend the run.
///
/// Mirrors `core::net`'s grammar: the separator `:` is only expected before
/// groups after the first, and at every position but the last, a trailing
/// embedded IPv4 address is tried before falling back to a hex group. If a
/// group's read fails after its leading separator was consumed, the
/// separator is rolled back too, so the caller sees the position unchanged.
/// Returns the two half-accumulators (groups 0-3 fold into `high`, groups
/// 4-7 into `low`, assembled by [`assemble_ipv6_groups`]), the group count,
/// whether the run ended in an embedded IPv4 address, and the remaining
/// input.
///
/// The split accumulator keeps the loop free of 128-bit arithmetic: each
/// half folds with plain 64-bit shifts, and the halves form two short
/// dependency chains instead of one 8-link chain of two-word shift-ORs,
/// which measured slower on the no-`::` 8-group form.
///
/// Positions travel as sub-slices here, the opposite of
/// [`read_ipv4_octet`]'s cursor, on purpose: a cursor-threaded rewrite
/// produced leaner code yet measured consistently slower on the shortest
/// address shape at baseline codegen, with wins only under
/// `target-cpu=native`.
///
/// Forced inline: outlined, the wide return travels through the stack at
/// both call sites.
#[inline(always)]
fn read_ipv6_groups(bytes: &[u8], limit: u32) -> (u64, u64, u32, bool, &[u8]) {
    let mut high: u64 = 0;
    let mut low: u64 = 0;
    let mut rest = bytes;

    let mut index = 0;
    while index < limit {
        let before_separator = rest;
        if index > 0 {
            match rest {
                [b':', tail @ ..] => rest = tail,
                _ => return (high, low, index, false, before_separator),
            }
        }

        if index < limit - 1
            && maybe_embedded_ipv4(rest)
            && let Some((addr, consumed)) = ipv4_parse_embedded(rest)
        {
            // The embedded address supplies two adjacent group slots, which
            // straddle the half boundary when it lands on groups 3 and 4.
            let bits = addr.to_bits();
            match index {
                0..=2 => high = (high << 32) | bits as u64,
                3 => {
                    high = (high << 16) | (bits >> 16) as u64;
                    low = bits as u64 & 0xFFFF;
                }
                _ => low = (low << 32) | bits as u64,
            }
            return (high, low, index + 2, true, &rest[consumed..]);
        }

        match read_ipv6_group(rest) {
            Some((value, consumed)) => {
                if index < 4 {
                    high = (high << 16) | value as u64;
                } else {
                    low = (low << 16) | value as u64;
                }
                rest = &rest[consumed..];
            }
            None => return (high, low, index, false, before_separator),
        }

        index += 1;
    }

    (high, low, limit, false, rest)
}

/// Whether the current position could start a trailing embedded IPv4
/// address.
///
/// A hex group never contains `.`, so a `.` within the first 4 bytes (the
/// longest a valid first octet plus its separator can be) is a necessary
/// condition for an embedded IPv4 address to follow. This lets
/// [`read_ipv6_groups`] skip the embedded-IPv4 attempt at every group
/// boundary of a pure-hex address, killing `core::net`'s up to 7
/// speculative re-parses per address.
#[inline]
fn maybe_embedded_ipv4(bytes: &[u8]) -> bool {
    // One length dispatch instead of four bounds-checked `get`s: the common
    // arm (4 or more bytes left) tests its four bytes unconditionally.
    match bytes {
        [byte0, byte1, byte2, byte3, ..] => *byte0 == b'.' || *byte1 == b'.' || *byte2 == b'.' || *byte3 == b'.',
        [byte0, byte1, byte2] => *byte0 == b'.' || *byte1 == b'.' || *byte2 == b'.',
        [byte0, byte1] => *byte0 == b'.' || *byte1 == b'.',
        [byte0] => *byte0 == b'.',
        [] => false,
    }
}

/// The embedded-IPv4 attempt of [`read_ipv6_groups`], deliberately outlined
/// and cold.
///
/// It sits on a rarely-taken branch guarded by [`maybe_embedded_ipv4`].
/// Inlining it bloats the group loop, which measurably slows pure-hex
/// shapes: they never take the branch but decode around its code every
/// iteration.
#[cold]
#[inline(never)]
fn ipv4_parse_embedded(bytes: &[u8]) -> Option<(Ipv4Addr, usize)> {
    ipv4_parse_at(bytes)
}

/// Parses one hex IPv6 group (1-4 hex digits, leading zeros allowed).
///
/// Reads up to 4 bytes via fixed-index `get`s, mirroring
/// [`read_ipv4_octet`]'s rationale. Returns the value and how many bytes it
/// consumed.
#[inline]
fn read_ipv6_group(bytes: &[u8]) -> Option<(u16, usize)> {
    let value0 = hex_digit_value(*bytes.first()?)?;
    let byte1 = bytes.get(1).copied().unwrap_or(b':');
    let Some(value1) = hex_digit_value(byte1) else {
        return Some((value0, 1));
    };
    let value = value0 * 16 + value1;
    let byte2 = bytes.get(2).copied().unwrap_or(b':');
    let Some(value2) = hex_digit_value(byte2) else {
        return Some((value, 2));
    };
    let value = value * 16 + value2;
    let byte3 = bytes.get(3).copied().unwrap_or(b':');
    let Some(value3) = hex_digit_value(byte3) else {
        return Some((value, 3));
    };
    Some((value * 16 + value3, 4))
}

#[inline]
const fn hex_digit_value(byte: u8) -> Option<u16> {
    if byte.wrapping_sub(b'0') <= 9 {
        Some((byte - b'0') as u16)
    } else {
        let lower = byte | 0x20;
        if lower.wrapping_sub(b'a') <= 5 {
            Some((lower - b'a' + 10) as u16)
        } else {
            None
        }
    }
}

/// Assembles a group run's half-accumulators into its top-aligned value.
///
/// A run of `count` groups occupies the top `16 * count` bits: `high` holds
/// the first 4 groups (all of them for a short run) and `low` the rest, so
/// a full 8-group run is the address value itself.
#[inline(always)]
fn assemble_ipv6_groups(high: u64, low: u64, count: u32) -> u128 {
    if count == 0 {
        0
    } else if count <= 4 {
        (high as u128) << (128 - 16 * count)
    } else {
        ((high as u128) << 64) | ((low as u128) << (64 - 16 * (count - 4)))
    }
}

/// Applies an already-split mask part (CIDR or colon-form) to an address.
#[inline(always)]
fn ipv6_apply_mask(addr: Ipv6Addr, mask: &[u8]) -> Result<Ipv6Network, IpNetParseError> {
    match parse_cidr_suffix(mask) {
        Ok(cidr) => Ok(Ipv6Network::try_from((addr, cidr))?),
        Err(..) => {
            // Maybe explicit mask.
            let mask = parse_ipv6_addr(mask)?;
            Ok(Ipv6Network::new(addr, mask))
        }
    }
}

/// Parses an IPv6 address the same way [`parse_ipv4_addr`] parses an IPv4
/// address.
#[inline]
fn parse_ipv6_addr(bytes: &[u8]) -> Result<Ipv6Addr, IpNetParseError> {
    match ipv6_parse_ascii(bytes) {
        Ok(addr) => Ok(addr),
        Err(..) => parse_ipv6_addr_error(bytes),
    }
}

#[cold]
#[inline(never)]
fn parse_ipv6_addr_error(bytes: &[u8]) -> Result<Ipv6Addr, IpNetParseError> {
    // Non-UTF-8 input takes an equal-valued error from a canonical failing
    // parse, mirroring `parse_ipv4_addr_error`.
    match str::from_utf8(bytes) {
        Ok(s) => Ok(s.parse()?),
        Err(..) => match "".parse::<Ipv6Addr>() {
            Err(err) => Err(err.into()),
            Ok(..) => unreachable!(),
        },
    }
}

/// Parses an IPv6 address, e.g. `2001:db8::1` or `::ffff:192.0.2.1`.
fn ipv6_parse_ascii(bytes: &[u8]) -> Result<Ipv6Addr, ParseError> {
    // The longest valid address, "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
    // is 45 bytes. Anything longer can never parse, so this is a fast reject.
    if bytes.len() > 45 {
        return Err(ParseError);
    }
    match ipv6_parse_at(bytes) {
        Some((addr, consumed)) if consumed == bytes.len() => Ok(addr),
        _ => Err(ParseError),
    }
}

/// The reject arm of [`parse_ipv6_network_ascii`]: re-parses through the
/// split-first path purely to manufacture the correct error value.
#[cold]
#[inline(never)]
fn parse_ipv6_network_fallback(buf: &[u8]) -> Result<Ipv6Network, IpNetParseError> {
    let (addr, mask) = split_slash(buf);
    let addr = parse_ipv6_addr(addr)?;
    match mask {
        Some(mask) => ipv6_apply_mask(addr, mask),
        None => Ok(Ipv6Network::new(addr, IPV6_ALL_BITS)),
    }
}

#[cfg(test)]
mod test {
    use std::{format, string::String, vec::Vec};

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn ipv4_accepts_basic_forms() {
        assert_eq!(Ok(Ipv4Addr::new(0, 0, 0, 0)), ipv4_parse_ascii(b"0.0.0.0"));
        assert_eq!(
            Ok(Ipv4Addr::new(255, 255, 255, 255)),
            ipv4_parse_ascii(b"255.255.255.255")
        );
        assert_eq!(Ok(Ipv4Addr::new(192, 168, 1, 1)), ipv4_parse_ascii(b"192.168.1.1"));
        assert_eq!(Ok(Ipv4Addr::new(1, 2, 3, 4)), ipv4_parse_ascii(b"1.2.3.4"));
    }

    #[test]
    fn ipv4_rejects_leading_zero_octets() {
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"01.2.3.4"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"1.02.3.4"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"1.2.03.4"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"1.2.3.04"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"00.0.0.0"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"000.0.0.0"));
        assert_eq!(Ok(Ipv4Addr::new(0, 1, 2, 3)), ipv4_parse_ascii(b"0.1.2.3"));
    }

    #[test]
    fn ipv4_rejects_octet_overflow() {
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"256.0.0.0"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"999.0.0.0"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"0.0.0.999"));
        assert_eq!(Ok(Ipv4Addr::new(255, 0, 0, 0)), ipv4_parse_ascii(b"255.0.0.0"));
    }

    #[test]
    fn ipv4_rejects_wrong_group_count() {
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"1.2.3.4.5"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"1.2.3"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"1.2"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"1"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b""));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"."));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"..."));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"1..2.3"));
    }

    #[test]
    fn ipv4_rejects_garbage_and_whitespace() {
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b" 1.2.3.4"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"1.2.3.4 "));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"1.2.3.4\n"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"1.2.3.4x"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"a.b.c.d"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"1.2.3.4/24"));
        assert_eq!(Err(ParseError), ipv4_parse_ascii(b"999999999999999999.0.0.0"));
        // A multibyte UTF-8 character's continuation bytes (0x80-0xBF) never
        // match a digit, dot, or the length fast-reject in isolation.
        assert_eq!(Err(ParseError), ipv4_parse_ascii("1.2.3.\u{e9}".as_bytes()));
    }

    #[test]
    fn ipv6_accepts_full_form() {
        assert_eq!(
            Ok(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ipv6_parse_ascii(b"2001:db8:0:0:0:0:0:1")
        );
        assert_eq!(
            Ok(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            ipv6_parse_ascii(b"0:0:0:0:0:0:0:0")
        );
        assert_eq!(
            Ok(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
            )),
            ipv6_parse_ascii(b"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
        );
    }

    #[test]
    fn ipv6_accepts_compressed_forms() {
        assert_eq!(Ok(Ipv6Addr::UNSPECIFIED), ipv6_parse_ascii(b"::"));
        assert_eq!(Ok(Ipv6Addr::LOCALHOST), ipv6_parse_ascii(b"::1"));
        assert_eq!(
            Ok(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            ipv6_parse_ascii(b"2001:db8::")
        );
        assert_eq!(
            Ok(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1)),
            ipv6_parse_ascii(b"2001::1")
        );
        assert_eq!(
            Ok(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ipv6_parse_ascii(b"2001:db8::1")
        );
        assert_eq!(
            Ok(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 0)),
            ipv6_parse_ascii(b"1:2:3:4:5:6:7::")
        );
        assert_eq!(
            Ok(Ipv6Addr::new(0, 1, 2, 3, 4, 5, 6, 7)),
            ipv6_parse_ascii(b"::1:2:3:4:5:6:7")
        );
    }

    #[test]
    fn ipv6_rejects_double_compression() {
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"1::2::3"));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b":::"));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"::1::"));
    }

    #[test]
    fn ipv6_rejects_full_form_plus_compression() {
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"1:2:3:4:5:6:7:8::"));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"::1:2:3:4:5:6:7:8"));
    }

    #[test]
    fn ipv6_rejects_too_many_or_too_few_groups() {
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"1:2:3:4:5:6:7"));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"1:2:3:4:5:6:7:8:9"));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b""));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b":"));
    }

    #[test]
    fn ipv6_rejects_too_many_hex_digits() {
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"12345::"));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"::12345"));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"1:22222:3::"));
    }

    #[test]
    fn ipv6_accepts_uppercase_hex() {
        assert_eq!(
            Ok(Ipv6Addr::new(0xABCD, 0xEF01, 0, 0, 0, 0, 0, 0)),
            ipv6_parse_ascii(b"ABCD:EF01::")
        );
        assert_eq!(ipv6_parse_ascii(b"abcd:ef01::"), ipv6_parse_ascii(b"ABCD:EF01::"));
    }

    #[test]
    fn ipv6_accepts_embedded_ipv4_last_position() {
        assert_eq!(
            Ok(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304)),
            ipv6_parse_ascii(b"::ffff:1.2.3.4")
        );
        assert_eq!(
            Ok(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 0x0102, 0x0304)),
            ipv6_parse_ascii(b"1:2:3:4:5:6:1.2.3.4")
        );
    }

    #[test]
    fn ipv6_rejects_embedded_ipv4_not_in_last_position() {
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"64:ff9b::1.2.3.300"));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"1.2.3.4::"));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"1:1.2.3.4:2:3:4:5:6"));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"::1.2.3.4:5"));
    }

    #[test]
    fn ipv6_rejects_garbage_and_whitespace() {
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b" ::1"));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"::1 "));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"::1\n"));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"gggg::"));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"192.168.1.1"));
        assert_eq!(Err(ParseError), ipv6_parse_ascii(b"2001:db8::1/32"));
        // A multibyte UTF-8 character's lead byte (0xC0+) never matches a
        // hex digit or `:`.
        assert_eq!(Err(ParseError), ipv6_parse_ascii("::\u{e9}".as_bytes()));
    }

    #[test]
    fn cidr_suffix_accepts_plain_and_plus_prefixed() {
        assert_eq!(Ok(8), parse_cidr_suffix(b"8"));
        assert_eq!(Ok(32), parse_cidr_suffix(b"32"));
        assert_eq!(Ok(8), parse_cidr_suffix(b"+8"));
        assert_eq!(Ok(255), parse_cidr_suffix(b"255"));
        assert_eq!(Ok(8), parse_cidr_suffix(b"008")); // No leading-zero restriction, unlike IPv4 octets.
    }

    #[test]
    fn cidr_suffix_rejects_malformed() {
        assert_eq!(Err(ParseError), parse_cidr_suffix(b""));
        assert_eq!(Err(ParseError), parse_cidr_suffix(b"+"));
        assert_eq!(Err(ParseError), parse_cidr_suffix(b"-8"));
        assert_eq!(Err(ParseError), parse_cidr_suffix(b"++8"));
        assert_eq!(Err(ParseError), parse_cidr_suffix(b"8 "));
        assert_eq!(Err(ParseError), parse_cidr_suffix(b" 8"));
        assert_eq!(Err(ParseError), parse_cidr_suffix(b"8x"));
        assert_eq!(Err(ParseError), parse_cidr_suffix(b"256"));
        assert_eq!(Err(ParseError), parse_cidr_suffix(b"999"));
    }

    fn arb_ipv4_addr() -> impl Strategy<Value = Ipv4Addr> {
        any::<u32>().prop_map(Ipv4Addr::from_bits)
    }

    fn arb_ipv6_addr() -> impl Strategy<Value = Ipv6Addr> {
        any::<u128>().prop_map(Ipv6Addr::from_bits)
    }

    // A charset built to hit near-misses of the real grammar (valid
    // characters plus a couple of easy-to-confuse extras), rather than fully
    // arbitrary bytes, so accept/reject parity gets exercised close to the
    // real accept boundary.
    fn arb_near_miss_string() -> impl Strategy<Value = String> {
        let hex_digit = (0u8..16).prop_map(|digit| if digit < 10 { b'0' + digit } else { b'a' + digit - 10 });
        proptest::collection::vec(
            prop_oneof![
                Just(b'.'),
                Just(b':'),
                Just(b'/'),
                Just(b'+'),
                Just(b' '),
                Just(b'x'),
                hex_digit
            ],
            0..24,
        )
        .prop_map(|bytes| String::from_utf8(bytes).expect("ASCII-only bytes are valid UTF-8"))
    }

    fn mutate(input: &str, position: usize, replacement: Option<u8>) -> String {
        let mut bytes: Vec<u8> = input.bytes().collect();
        if bytes.is_empty() {
            return match replacement {
                Some(byte) => String::from_utf8(vec![byte]).expect("ASCII byte is valid UTF-8"),
                None => String::new(),
            };
        }
        let position = position % bytes.len();
        match replacement {
            Some(byte) => bytes[position] = byte,
            None => {
                bytes.remove(position);
            }
        }
        String::from_utf8(bytes).unwrap_or_default()
    }

    proptest! {
        #[test]
        fn prop_ipv4_round_trips_through_display(addr in arb_ipv4_addr()) {
            let text = format!("{addr}");
            let core_result = text.parse::<Ipv4Addr>();
            prop_assert_eq!(core_result.ok(), Some(addr));
            prop_assert_eq!(ipv4_parse_ascii(text.as_bytes()).ok(), Some(addr));
        }

        #[test]
        fn prop_ipv6_round_trips_through_display(addr in arb_ipv6_addr()) {
            let text = format!("{addr}");
            let core_result = text.parse::<Ipv6Addr>();
            prop_assert_eq!(core_result.ok(), Some(addr));
            prop_assert_eq!(ipv6_parse_ascii(text.as_bytes()).ok(), Some(addr));
        }

        #[test]
        fn prop_ipv4_accept_reject_parity(text in arb_near_miss_string()) {
            let core_result = text.parse::<Ipv4Addr>();
            let ours = ipv4_parse_ascii(text.as_bytes());
            prop_assert_eq!(core_result.ok(), ours.ok(), "input {:?}", text);
        }

        #[test]
        fn prop_ipv6_accept_reject_parity(text in arb_near_miss_string()) {
            let core_result = text.parse::<Ipv6Addr>();
            let ours = ipv6_parse_ascii(text.as_bytes());
            prop_assert_eq!(core_result.ok(), ours.ok(), "input {:?}", text);
        }

        #[test]
        fn prop_ipv4_accept_reject_parity_arbitrary(text in ".{0,32}") {
            let core_result = text.parse::<Ipv4Addr>();
            let ours = ipv4_parse_ascii(text.as_bytes());
            prop_assert_eq!(core_result.ok(), ours.ok(), "input {:?}", text);
        }

        #[test]
        fn prop_ipv6_accept_reject_parity_arbitrary(text in ".{0,48}") {
            let core_result = text.parse::<Ipv6Addr>();
            let ours = ipv6_parse_ascii(text.as_bytes());
            prop_assert_eq!(core_result.ok(), ours.ok(), "input {:?}", text);
        }

        #[test]
        fn prop_ipv4_mutation_parity(
            addr in arb_ipv4_addr(),
            position in any::<usize>(),
            replacement in prop_oneof![Just(None), any::<u8>().prop_map(Some)],
        ) {
            let text = mutate(&format!("{addr}"), position, replacement);
            let core_result = text.parse::<Ipv4Addr>();
            let ours = ipv4_parse_ascii(text.as_bytes());
            prop_assert_eq!(core_result.ok(), ours.ok(), "input {:?}", text);
        }

        #[test]
        fn prop_ipv6_mutation_parity(
            addr in arb_ipv6_addr(),
            position in any::<usize>(),
            replacement in prop_oneof![Just(None), any::<u8>().prop_map(Some)],
        ) {
            let text = mutate(&format!("{addr}"), position, replacement);
            let core_result = text.parse::<Ipv6Addr>();
            let ours = ipv6_parse_ascii(text.as_bytes());
            prop_assert_eq!(core_result.ok(), ours.ok(), "input {:?}", text);
        }

        #[test]
        fn prop_cidr_suffix_matches_u8_from_str(text in "[+]?[0-9]{0,5}") {
            let core_result = text.parse::<u8>();
            let ours = parse_cidr_suffix(text.as_bytes());
            prop_assert_eq!(core_result.ok(), ours.ok(), "input {:?}", text);
        }
    }
}
