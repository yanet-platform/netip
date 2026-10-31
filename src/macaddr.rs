//! MAC (EUI-48) address type.
//!
//! This module provides [`MacAddr`], a lightweight wrapper around a 48-bit
//! Ethernet hardware address.
//!
//! # Examples
//!
//! ```
//! use netip::MacAddr;
//!
//! let mac = MacAddr::new(0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xf9);
//!
//! let parsed = "3a:ac:26:9b:5b:f9".parse().unwrap();
//! assert_eq!(mac, parsed);
//!
//! assert_eq!("3a:ac:26:9b:5b:f9", mac.to_string());
//! ```

use core::{
    fmt::{self, Display, Formatter, LowerHex, UpperHex},
    str::{self, FromStr},
};

/// A 48-bit MAC (EUI-48) address.
///
/// Internally stored as the lower 48 bits of a [`u64`] for efficient
/// comparison and hashing. The upper 16 bits are always zero.
///
/// # Parsing
///
/// Three formats are supported via [`FromStr`] and [`MacAddr::parse_ascii`]:
///
/// | Format           | Example             |
/// |------------------|---------------------|
/// | Colon-separated  | `aa:bb:cc:dd:ee:ff` |
/// | Hyphen-separated | `aa-bb-cc-dd-ee-ff` |
/// | Cisco dotted     | `aabb.ccdd.eeff`    |
///
/// Hex digits are case-insensitive.
///
/// # Display
///
/// The [`Display`] implementation always uses lowercase colon-separated
/// format: `aa:bb:cc:dd:ee:ff`. [`LowerHex`] (`{:x}`) prints the same text,
/// and [`UpperHex`] (`{:X}`) prints it in uppercase: `AA:BB:CC:DD:EE:FF`.
///
/// For hyphens or Cisco's dots, wrap the address in
/// [`fmt::MacHyphens`](crate::fmt::MacHyphens) or
/// [`fmt::MacDots`](crate::fmt::MacDots). For the bare hex digits, format the
/// integer: `format!("{:012x}", mac.as_u64())` prints `aabbccddeeff`.
///
/// # Examples
///
/// ```
/// use netip::MacAddr;
///
/// let mac = MacAddr::new(0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xf9);
/// assert_eq!("3a:ac:26:9b:5b:f9", mac.to_string());
///
/// let parsed: MacAddr = "3a:ac:26:9b:5b:f9".parse().unwrap();
/// assert_eq!(mac, parsed);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct MacAddr(u64);

impl MacAddr {
    /// The zero address (`00:00:00:00:00:00`).
    pub const ZERO: MacAddr = MacAddr::new(0, 0, 0, 0, 0, 0);

    /// The broadcast address (`ff:ff:ff:ff:ff:ff`).
    ///
    /// Frames sent to this address are received by all stations on the
    /// local network segment.
    pub const BROADCAST: MacAddr = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

    /// Creates a new MAC address from its 6 octets in transmission order.
    ///
    /// Each parameter represents one byte of the MAC address in the standard
    /// format `xx:xx:xx:xx:xx:xx`.
    #[inline]
    #[must_use]
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> MacAddr {
        Self(u64::from_be_bytes([0, 0, a, b, c, d, e, f]))
    }

    /// Creates a MAC address from the lower 48 bits of a [`u64`], or returns
    /// [`None`] if any of the upper 16 bits is set.
    ///
    /// This is the inverse of [`MacAddr::as_u64`]: the first octet is the
    /// highest of the 48 bits.
    ///
    /// The `TryFrom<u64>` conversion accepts the same values and reports the
    /// others as a [`MacAddrParseError`]. This one is a `const fn` returning
    /// [`Option`] instead, so it also builds constants: [`Option::expect`]
    /// works in `const` context. Where the upper bits hold something else,
    /// clear them first: `MacAddr::from_u64(bits & 0xffff_ffff_ffff)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::MacAddr;
    ///
    /// const MAC: MacAddr = MacAddr::from_u64(0x3aac_269b_5bf9).expect("the upper 16 bits are zero");
    /// assert_eq!("3a:ac:26:9b:5b:f9", MAC.to_string());
    ///
    /// assert_eq!(None, MacAddr::from_u64(0x1_0000_0000_0000));
    ///
    /// // Only the lower 48 bits of this value are the address.
    /// let bits = 0xabcd_3aac_269b_5bf9;
    /// assert_eq!(Some(MAC), MacAddr::from_u64(bits & 0xffff_ffff_ffff));
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_u64(bits: u64) -> Option<MacAddr> {
        if bits >> 48 == 0 { Some(Self(bits)) } else { None }
    }

    /// Parses a MAC address from an ASCII byte slice.
    ///
    /// | Format           | Example             |
    /// |------------------|---------------------|
    /// | Colon-separated  | `xx:xx:xx:xx:xx:xx` |
    /// | Hyphen-separated | `xx-xx-xx-xx-xx-xx` |
    /// | Cisco dotted     | `xxxx.xxxx.xxxx`    |
    ///
    /// ```
    /// use netip::MacAddr;
    ///
    /// let mac = MacAddr::parse_ascii(b"3a:ac:26:9b:5b:f9").unwrap();
    ///
    /// assert_eq!(mac, MacAddr::parse_ascii(b"3a-ac-26-9b-5b-f9").unwrap());
    /// assert_eq!(mac, MacAddr::parse_ascii(b"3aac.269b.5bf9").unwrap());
    /// ```
    #[inline]
    pub fn parse_ascii(b: &[u8]) -> Result<Self, MacAddrParseError> {
        match b.len() {
            // The length checks above guarantee these conversions never fail.
            17 => parse_separated(b.try_into().unwrap()),
            14 => parse_dotted(b.try_into().unwrap()),
            _ => Err(MacAddrParseError),
        }
    }

    /// Returns the numeric value of this address as a [`u64`].
    ///
    /// The address occupies the lower 48 bits, the first octet highest. The
    /// upper 16 bits are zero. [`MacAddr::from_u64`] converts it back.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::MacAddr;
    ///
    /// assert_eq!(0, MacAddr::ZERO.as_u64());
    /// assert_eq!(1, MacAddr::new(0, 0, 0, 0, 0, 1).as_u64());
    /// ```
    #[inline]
    #[must_use]
    pub const fn as_u64(&self) -> u64 {
        match self {
            Self(addr) => *addr,
        }
    }

    /// Returns the 6 octets in network (transmission) order.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::MacAddr;
    ///
    /// let mac = MacAddr::new(0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xf9);
    /// assert_eq!([0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xf9], mac.octets());
    /// ```
    #[inline]
    #[must_use]
    pub const fn octets(&self) -> [u8; 6] {
        let [.., a, b, c, d, e, f] = self.as_u64().to_be_bytes();
        [a, b, c, d, e, f]
    }

    /// Returns `true` if all octets are zero (`00:00:00:00:00:00`).
    #[inline]
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.as_u64() == 0
    }

    /// Returns `true` if this is the broadcast address (`ff:ff:ff:ff:ff:ff`).
    ///
    /// Broadcast frames are delivered to every station on the local segment.
    #[inline]
    #[must_use]
    pub const fn is_broadcast(&self) -> bool {
        self.as_u64() == 0xffff_ffff_ffff
    }

    /// Returns `true` if this is a multicast address.
    ///
    /// A MAC address is multicast when the least-significant bit of the
    /// first octet (the I/G bit) is set.
    ///
    /// Note that the broadcast address is also multicast.
    ///
    /// ```
    /// use netip::MacAddr;
    ///
    /// assert!(MacAddr::new(0x01, 0x00, 0x5e, 0x00, 0x00, 0x01).is_multicast());
    /// assert!(!MacAddr::new(0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e).is_multicast());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_multicast(&self) -> bool {
        (self.as_u64() >> 40) & 0x01 != 0
    }

    /// Returns `true` if this is a unicast address.
    ///
    /// The complement of [`is_multicast`](MacAddr::is_multicast): the I/G bit
    /// in the first octet is clear.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::MacAddr;
    ///
    /// assert!(MacAddr::new(0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e).is_unicast());
    /// assert!(!MacAddr::BROADCAST.is_unicast());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    /// Returns `true` if this is a locally administered address.
    ///
    /// The U/L bit (second-least-significant bit of the first octet) is set
    /// for addresses that are **not** assigned by an IEEE-registered
    /// manufacturer.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::MacAddr;
    ///
    /// // Bit 0x02 set -> locally administered.
    /// assert!(MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01).is_locally_administered());
    ///
    /// // Bit 0x02 clear -> universally administered.
    /// assert!(!MacAddr::new(0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e).is_locally_administered());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_locally_administered(&self) -> bool {
        (self.as_u64() >> 40) & 0x02 != 0
    }

    /// Returns `true` if this is a universally administered address.
    ///
    /// The complement of
    /// [`is_locally_administered`](MacAddr::is_locally_administered).
    #[inline]
    #[must_use]
    pub const fn is_universally_administered(&self) -> bool {
        !self.is_locally_administered()
    }
}

/// The default MAC address is [`MacAddr::ZERO`].
impl Default for MacAddr {
    #[inline]
    fn default() -> Self {
        Self::ZERO
    }
}

/// Creates a MAC address from the lower 48 bits of a [`u64`], failing with
/// [`MacAddrParseError`] if any of the upper 16 bits is set.
///
/// [`MacAddr::from_u64`] does the same in `const` context.
///
/// # Examples
///
/// ```
/// use netip::{MacAddr, MacAddrParseError};
///
/// let mac = MacAddr::try_from(0x3aac_269b_5bf9).unwrap();
/// assert_eq!("3a:ac:26:9b:5b:f9", mac.to_string());
///
/// assert_eq!(
///     Err(MacAddrParseError),
///     MacAddr::try_from(0xabcd_3aac_269b_5bf9)
/// );
/// ```
impl TryFrom<u64> for MacAddr {
    type Error = MacAddrParseError;

    #[inline]
    fn try_from(bits: u64) -> Result<Self, Self::Error> {
        MacAddr::from_u64(bits).ok_or(MacAddrParseError)
    }
}

impl From<MacAddr> for u64 {
    #[inline]
    fn from(mac: MacAddr) -> u64 {
        mac.as_u64()
    }
}

impl From<[u8; 6]> for MacAddr {
    #[inline]
    fn from(octets: [u8; 6]) -> MacAddr {
        MacAddr::new(octets[0], octets[1], octets[2], octets[3], octets[4], octets[5])
    }
}

impl From<MacAddr> for [u8; 6] {
    #[inline]
    fn from(mac: MacAddr) -> [u8; 6] {
        mac.octets()
    }
}

impl MacAddr {
    /// Writes the octets as pairs of hex digits, `SEP` between the pairs and
    /// uppercase letters if `UPPER`, and pads the text as a whole.
    ///
    /// The text of [`Display`], [`LowerHex`] and [`UpperHex`], and of
    /// [`fmt::MacHyphens`](crate::fmt::MacHyphens). The separator and the
    /// case are const parameters, so that each caller gets a copy with them
    /// folded in, and it is always inlined: `Display` then costs the same
    /// instructions as when it filled the buffer itself.
    #[inline(always)]
    pub(crate) fn fmt_pairs<const SEP: u8, const UPPER: bool>(&self, fmt: &mut Formatter) -> Result<(), fmt::Error> {
        let octets = self.octets();

        // Separators land at 2, 5, 8, 11, 14 by construction (every third
        // byte) and are never overwritten by the loop below.
        let mut buf = [SEP; 17];
        for (i, &octet) in octets.iter().enumerate() {
            buf[3 * i] = hex_nibble(octet >> 4, UPPER);
            buf[3 * i + 1] = hex_nibble(octet & 0x0f, UPPER);
        }

        // `pad` applies width, fill, alignment and precision to the whole text.
        fmt.pad(str::from_utf8(&buf).expect("buffer holds only ASCII hex digits and the separator, always valid UTF-8"))
    }

    /// Writes the octets as Cisco's three groups of four hex digits, dots
    /// between the groups and uppercase letters if `UPPER`, and pads the text
    /// as a whole.
    ///
    /// The text of [`fmt::MacDots`](crate::fmt::MacDots). Inlined like
    /// [`fmt_pairs`](Self::fmt_pairs).
    #[inline(always)]
    pub(crate) fn fmt_dotted<const UPPER: bool>(&self, fmt: &mut Formatter) -> Result<(), fmt::Error> {
        let octets = self.octets();

        // Dots land at 4 and 9 by construction (after every two octets) and
        // are never overwritten by the loop below.
        let mut buf = [b'.'; 14];
        for (i, &octet) in octets.iter().enumerate() {
            let off = 2 * i + i / 2;
            buf[off] = hex_nibble(octet >> 4, UPPER);
            buf[off + 1] = hex_nibble(octet & 0x0f, UPPER);
        }

        fmt.pad(str::from_utf8(&buf).expect("buffer holds only ASCII hex digits and '.', always valid UTF-8"))
    }
}

impl Display for MacAddr {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), fmt::Error> {
        self.fmt_pairs::<b':', false>(fmt)
    }
}

impl LowerHex for MacAddr {
    /// Formats the address as [`Display`] does: `aa:bb:cc:dd:ee:ff`.
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), fmt::Error> {
        self.fmt_pairs::<b':', false>(fmt)
    }
}

impl UpperHex for MacAddr {
    /// Formats the address as [`Display`] does, in uppercase:
    /// `AA:BB:CC:DD:EE:FF`.
    ///
    /// # Examples
    ///
    /// ```
    /// use netip::MacAddr;
    ///
    /// let mac = MacAddr::new(0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xf9);
    /// assert_eq!("3A:AC:26:9B:5B:F9", format!("{mac:X}"));
    /// assert_eq!("3a:ac:26:9b:5b:f9", format!("{mac:x}"));
    /// ```
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), fmt::Error> {
        self.fmt_pairs::<b':', true>(fmt)
    }
}

/// Encodes a 4-bit nibble (must be `< 16`) as its ASCII hex digit, an
/// uppercase letter if `upper` and a lowercase one otherwise.
///
/// Branchless: digits `0..=9` map to `'0'..='9'`, while digits `10..=15` need
/// an extra `'a' - '0' - 10` (or `'A' - '0' - 10`) offset to land in the
/// letter range, added via a 0/1 multiplier instead of a conditional.
#[inline]
const fn hex_nibble(nibble: u8, upper: bool) -> u8 {
    let is_letter = (nibble > 9) as u8;
    let letter = if upper { b'A' } else { b'a' };
    nibble + b'0' + is_letter * (letter - b'0' - 10)
}

impl FromStr for MacAddr {
    type Err = MacAddrParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_ascii(s.as_bytes())
    }
}

/// Decodes a single ASCII hex digit.
#[inline]
const fn decode_hex(b: u8) -> Result<u8, MacAddrParseError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(MacAddrParseError),
    }
}

/// Decodes two ASCII hex digits into a single byte.
#[inline]
const fn decode_hex_pair(hi: u8, lo: u8) -> Result<u8, MacAddrParseError> {
    // NOTE: no "?", because of constant function.
    let hi = match decode_hex(hi) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let lo = match decode_hex(lo) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    Ok(hi << 4 | lo)
}

/// Parses `xx:xx:xx:xx:xx:xx` or `xx-xx-xx-xx-xx-xx` from a 17-byte array.
///
/// The separator character is determined from byte 2 and must be consistent
/// across all positions. Mixed separators (e.g. `aa:bb-cc:dd-ee:ff`) are
/// rejected.
///
/// Taking a fixed-size array rather than a slice lets the compiler prove
/// every index below is in bounds at compile time, eliding the runtime
/// bounds checks a `&[u8]` parameter would require.
#[inline]
fn parse_separated(b: &[u8; 17]) -> Result<MacAddr, MacAddrParseError> {
    let sep = b[2];
    if sep != b':' && sep != b'-' {
        return Err(MacAddrParseError);
    }

    let mut octets = [0u8; 6];
    for (i, octet) in octets.iter_mut().enumerate() {
        let off = i * 3;
        if i > 0 && b[off - 1] != sep {
            return Err(MacAddrParseError);
        }
        *octet = decode_hex_pair(b[off], b[off + 1])?;
    }

    Ok(MacAddr::from(octets))
}

/// Parses Cisco's `xxxx.xxxx.xxxx` from a 14-byte array: three dot-separated
/// groups of four hex digits, two octets each.
///
/// Takes a fixed-size array for the same reason as [`parse_separated`].
#[inline]
fn parse_dotted(b: &[u8; 14]) -> Result<MacAddr, MacAddrParseError> {
    if b[4] != b'.' || b[9] != b'.' {
        return Err(MacAddrParseError);
    }

    let mut octets = [0u8; 6];
    for (i, octet) in octets.iter_mut().enumerate() {
        // Octet `i` is hex digits `2i` and `2i + 1`, shifted right by the
        // dots before them: one after every group of two octets.
        let off = 2 * i + i / 2;
        *octet = decode_hex_pair(b[off], b[off + 1])?;
    }

    Ok(MacAddr::from(octets))
}

/// Error returned when parsing a MAC address string fails, or when a [`u64`]
/// with any of the upper 16 bits set is converted to a MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddrParseError;

impl Display for MacAddrParseError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "invalid MAC address, expected EUI-48: xx:xx:xx:xx:xx:xx or a u64 below 2^48"
        )
    }
}

impl core::error::Error for MacAddrParseError {}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    const MAC: MacAddr = MacAddr::new(0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xf9);
    const MAC_U64: u64 = 0x3aac269b5bf9;

    #[test]
    fn as_u64() {
        assert_eq!(MAC_U64, MAC.as_u64());
    }

    #[test]
    fn from_u64() {
        assert_eq!(Some(MAC), MacAddr::from_u64(MAC_U64));
        assert_eq!(Some(MacAddr::ZERO), MacAddr::from_u64(0));
        assert_eq!(Some(MacAddr::BROADCAST), MacAddr::from_u64(0xffff_ffff_ffff));
    }

    #[test]
    fn from_u64_rejects_each_high_bit() {
        for bit in 48..64 {
            assert_eq!(None, MacAddr::from_u64(1 << bit), "bit {bit}");
            assert_eq!(None, MacAddr::from_u64(MAC_U64 | (1 << bit)), "bit {bit}");
        }
        assert_eq!(None, MacAddr::from_u64(u64::MAX));
    }

    #[test]
    fn from_u64_in_const() {
        const FROM_U64: MacAddr = MacAddr::from_u64(MAC_U64).expect("the upper 16 bits are zero");

        assert_eq!(MAC, FROM_U64);
    }

    #[test]
    fn try_from_u64() {
        assert_eq!(Ok(MAC), MacAddr::try_from(MAC_U64));
        assert_eq!(Ok(MacAddr::BROADCAST), MacAddr::try_from(0xffff_ffff_ffff));
        assert_eq!(Err(MacAddrParseError), MacAddr::try_from(0x1_0000_0000_0000));
        assert_eq!(Err(MacAddrParseError), MacAddr::try_from(0xabcd_3aac_269b_5bf9));
    }

    #[test]
    fn from_octets() {
        assert_eq!(MAC, MacAddr::from([0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xf9]));
    }

    #[test]
    fn octets_roundtrip() {
        assert_eq!([0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xf9], MAC.octets());
    }

    #[test]
    fn display_canonical() {
        assert_eq!("3a:ac:26:9b:5b:f9", MAC.to_string());
    }

    #[test]
    fn display_zero() {
        assert_eq!("00:00:00:00:00:00", MacAddr::ZERO.to_string());
    }

    #[test]
    fn display_broadcast() {
        assert_eq!("ff:ff:ff:ff:ff:ff", MacAddr::BROADCAST.to_string());
    }

    #[test]
    fn display_pads_whole_text() {
        let mac = MacAddr::new(0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xf9);
        assert_eq!("[3a:ac:26:9b:5b:f9   ]", format!("[{mac:20}]"));
        assert_eq!("[   3a:ac:26:9b:5b:f9]", format!("[{mac:>20}]"));
        assert_eq!("[3a:ac]", format!("[{mac:.5}]"));
    }

    #[test]
    fn hex_nibble_all_values() {
        for (nibble, (&lower, &upper)) in b"0123456789abcdef".iter().zip(b"0123456789ABCDEF").enumerate() {
            assert_eq!(lower, hex_nibble(nibble as u8, false), "nibble {nibble}");
            assert_eq!(upper, hex_nibble(nibble as u8, true), "nibble {nibble}");
        }
    }

    #[test]
    fn hex_nibble_pair_matches_format_spec_for_all_bytes() {
        // The formatters encode each byte as `hex_nibble(byte >> 4, ..)` then
        // `hex_nibble(byte & 0x0f, ..)`. Every byte value must match `{:02x}`
        // and `{:02X}`.
        for byte in 0..=u8::MAX {
            let expected = format!("{byte:02x}");
            assert_eq!(
                expected.as_bytes(),
                [hex_nibble(byte >> 4, false), hex_nibble(byte & 0x0f, false)],
                "byte {byte:#04x}"
            );
            let expected = format!("{byte:02X}");
            assert_eq!(
                expected.as_bytes(),
                [hex_nibble(byte >> 4, true), hex_nibble(byte & 0x0f, true)],
                "byte {byte:#04x}"
            );
        }
    }

    #[test]
    fn hex_formats() {
        assert_eq!("3a:ac:26:9b:5b:f9", format!("{MAC:x}"));
        assert_eq!("3A:AC:26:9B:5B:F9", format!("{MAC:X}"));
        assert_eq!("[  3A:AC:26:9B:5B:F9]", format!("[{MAC:>19X}]"));
        // The bare digits come from the integer, as the docs show.
        assert_eq!("3aac269b5bf9", format!("{:012x}", MAC.as_u64()));
        assert_eq!(
            "000000000001",
            format!("{:012x}", MacAddr::new(0, 0, 0, 0, 0, 1).as_u64())
        );
    }

    #[test]
    fn parse_colon() {
        assert_eq!(MAC, "3a:ac:26:9b:5b:f9".parse::<MacAddr>().unwrap());
    }

    #[test]
    fn parse_colon_uppercase() {
        assert_eq!(MAC, "3A:AC:26:9B:5B:F9".parse::<MacAddr>().unwrap());
    }

    #[test]
    fn parse_colon_mixed_case() {
        assert_eq!(MAC, "3a:AC:26:9b:5B:f9".parse::<MacAddr>().unwrap());
    }

    #[test]
    fn parse_hyphen() {
        assert_eq!(MAC, "3a-ac-26-9b-5b-f9".parse::<MacAddr>().unwrap());
    }

    #[test]
    fn parse_cisco() {
        assert_eq!(MAC, "3aac.269b.5bf9".parse::<MacAddr>().unwrap());
        assert_eq!(MAC, "3AAC.269B.5BF9".parse::<MacAddr>().unwrap());
        assert_eq!(MAC, "3aAC.269b.5Bf9".parse::<MacAddr>().unwrap());
        assert_eq!(MacAddr::ZERO, "0000.0000.0000".parse::<MacAddr>().unwrap());
        assert_eq!(MacAddr::BROADCAST, "ffff.ffff.ffff".parse::<MacAddr>().unwrap());
    }

    #[test]
    fn parse_cisco_rejects_malformed() {
        for s in [
            // A dot out of place, missing, or replaced.
            "3aa.c269b.5bf9",
            "3aac.269b5.bf9",
            "3aac2.69b.5bf9",
            "3aac:269b:5bf9",
            "3aac-269b-5bf9",
            "3aac.269b:5bf9",
            "3aac269b5bf9..",
            // A bad digit in each group.
            "3azc.269b.5bf9",
            "3aac.26xb.5bf9",
            "3aac.269b.5bg9",
            // One digit short or long.
            "3aac.269b.5bf",
            "3aac.269b.5bf90",
        ] {
            assert_eq!(Err(MacAddrParseError), s.parse::<MacAddr>(), "{s}");
        }
    }

    #[test]
    fn parse_display_roundtrip() {
        let s = "3a:ac:26:9b:5b:f9";
        let mac: MacAddr = s.parse().unwrap();

        assert_eq!(s, mac.to_string());
    }

    #[test]
    fn parse_empty() {
        assert!("".parse::<MacAddr>().is_err());
    }

    #[test]
    fn parse_colon_too_few() {
        assert!("3a:ac:26:9b:5b".parse::<MacAddr>().is_err());
    }

    #[test]
    fn parse_colon_too_many() {
        assert!("3a:ac:26:9b:5b:f9:00".parse::<MacAddr>().is_err());
    }

    #[test]
    fn parse_colon_invalid_hex() {
        assert!("3a:ac:26:zz:5b:f9".parse::<MacAddr>().is_err());
    }

    #[test]
    fn parse_bare_too_short() {
        assert!("3aac269b5bf".parse::<MacAddr>().is_err());
    }

    #[test]
    fn parse_bare_too_long() {
        assert!("3aac269b5bf900".parse::<MacAddr>().is_err());
    }

    #[test]
    fn parse_bare_invalid_hex() {
        assert!("3aac269b5bfz".parse::<MacAddr>().is_err());
    }

    #[test]
    fn is_multicast() {
        assert!(!MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55).is_multicast());
        assert!(MacAddr::new(0x01, 0x11, 0x22, 0x33, 0x44, 0x55).is_multicast());
    }

    #[test]
    fn broadcast_is_multicast() {
        let broadcast = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
        assert!(broadcast.is_multicast());
        assert!(broadcast.is_broadcast());
    }

    #[test]
    fn is_locally_administered() {
        assert!(!MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55).is_locally_administered());
        assert!(MacAddr::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x55).is_locally_administered());
    }

    #[test]
    fn is_zero() {
        assert!(MacAddr::ZERO.is_zero());
        assert!(!MAC.is_zero());
    }

    #[test]
    fn is_broadcast() {
        assert!(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff).is_broadcast());
        assert!(!MAC.is_broadcast());
    }

    #[test]
    fn ordering() {
        let a = MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x01);
        let b = MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x02);
        let c = MacAddr::new(0x01, 0x00, 0x00, 0x00, 0x00, 0x00);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn parse_mixed_separator_colon_then_hyphen() {
        assert!("aa:bb-cc:dd-ee:ff".parse::<MacAddr>().is_err());
    }

    #[test]
    fn parse_mixed_separator_hyphen_then_colon() {
        assert!("aa-bb:cc-dd:ee-ff".parse::<MacAddr>().is_err());
    }

    #[test]
    fn parse_separator_position_space() {
        assert!("3a ac:26:9b:5b:f9".parse::<MacAddr>().is_err());
    }

    #[test]
    fn parse_separator_position_period() {
        assert!("3a.ac:26:9b:5b:f9".parse::<MacAddr>().is_err());
    }

    #[test]
    fn parse_separator_position_hex_digit() {
        assert!("3a1ac:26:9b:5b:f9".parse::<MacAddr>().is_err());
    }

    #[test]
    fn parse_inconsistent_separator_at_5() {
        assert!("3a:acx26:9b:5b:f9".parse::<MacAddr>().is_err());
    }

    #[test]
    fn parse_inconsistent_separator_at_8() {
        assert!("3a:ac:26x9b:5b:f9".parse::<MacAddr>().is_err());
    }

    #[test]
    fn parse_inconsistent_separator_at_11() {
        assert!("3a:ac:26:9bx5b:f9".parse::<MacAddr>().is_err());
    }

    #[test]
    fn parse_inconsistent_separator_at_14() {
        assert!("3a:ac:26:9b:5bxf9".parse::<MacAddr>().is_err());
    }

    fn arb_mac_addr() -> impl Strategy<Value = MacAddr> {
        any::<[u8; 6]>().prop_map(MacAddr::from)
    }

    // A uniform `u64` has an upper bit set in all but one draw in 65536, so
    // values that fit in 48 bits and values with one stray upper bit are drawn
    // as often.
    fn arb_u64_bits() -> impl Strategy<Value = u64> {
        prop_oneof![
            0..=0xffff_ffff_ffff_u64,
            (0..=0xffff_ffff_ffff_u64, 48..64_u32).prop_map(|(bits, bit)| bits | (1 << bit)),
            any::<u64>(),
        ]
    }

    // Reads `xxxx.xxxx.xxxx` the plain way, an oracle for `parse_dotted`.
    fn parse_cisco_reference(s: &str) -> Option<MacAddr> {
        let groups: std::vec::Vec<&str> = s.split('.').collect();
        if groups.len() != 3 {
            return None;
        }

        let mut bits = 0u64;
        for group in groups {
            if group.len() != 4 || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            bits = bits << 16 | u64::from(u16::from_str_radix(group, 16).ok()?);
        }

        MacAddr::from_u64(bits)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        // Every MAC reads back from its Cisco text, in either case.
        #[test]
        fn prop_parse_cisco_roundtrip(mac in arb_mac_addr()) {
            let [a, b, c, d, e, f] = mac.octets();
            let text = std::format!("{a:02x}{b:02x}.{c:02x}{d:02x}.{e:02x}{f:02x}");

            prop_assert_eq!(Ok(mac), text.parse::<MacAddr>());
            prop_assert_eq!(Ok(mac), text.to_uppercase().parse::<MacAddr>());
        }

        // A Cisco text with one character replaced, by a hex digit, a dot or
        // a stray: the parser accepts exactly what the reference does.
        #[test]
        fn prop_parse_cisco_matches_reference(
            mac in arb_mac_addr(),
            position in 0usize..14,
            byte in prop::sample::select(&b"0123456789abcdefABCDEF.:-xg"[..]),
        ) {
            let [a, b, c, d, e, f] = mac.octets();
            let mut text = std::format!("{a:02x}{b:02x}.{c:02x}{d:02x}.{e:02x}{f:02x}").into_bytes();
            text[position] = byte;
            let text = std::string::String::from_utf8(text).unwrap();

            prop_assert_eq!(parse_cisco_reference(&text).ok_or(MacAddrParseError), text.parse::<MacAddr>(), "{}", text);
        }

        #[test]
        fn prop_from_u64_accepts_exactly_48_bit_values(bits in arb_u64_bits()) {
            let mac = MacAddr::from_u64(bits);

            prop_assert_eq!(bits < 1 << 48, mac.is_some());
            if let Some(mac) = mac {
                prop_assert_eq!(bits, mac.as_u64());
                prop_assert_eq!(&bits.to_be_bytes()[2..], &mac.octets()[..]);
            }
            prop_assert_eq!(mac.ok_or(MacAddrParseError), MacAddr::try_from(bits));
        }

        #[test]
        fn prop_mac_addr_u64_round_trips(mac in arb_mac_addr()) {
            prop_assert_eq!(Some(mac), MacAddr::from_u64(mac.as_u64()));
            prop_assert_eq!(Ok(mac), MacAddr::try_from(u64::from(mac)));
        }

        #[test]
        fn prop_mac_addr_parse_display_roundtrip(mac in arb_mac_addr()) {
            let formatted = mac.to_string();

            prop_assert_eq!(
                Ok(mac),
                MacAddr::parse_ascii(formatted.as_bytes()),
                "roundtrip for {}", formatted
            );
            prop_assert_eq!(
                formatted.parse::<MacAddr>(),
                MacAddr::parse_ascii(formatted.as_bytes()),
                "FromStr/parse_ascii mismatch for {}", formatted
            );
        }
    }
}
