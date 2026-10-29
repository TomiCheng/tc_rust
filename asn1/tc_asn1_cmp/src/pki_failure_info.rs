//! RFC 4210 §5.2.3 `PKIFailureInfo`, with the RFC 3161 time-stamping bits.
//!
//! ```text
//! PKIFailureInfo ::= BIT STRING {
//!     badAlg              (0),  badMessageCheck    (1),  badRequest         (2),
//!     badTime             (3),  badCertId          (4),  badDataFormat      (5),
//!     wrongAuthority      (6),  incorrectData      (7),  missingTimeStamp   (8),
//!     badPOP              (9),  certRevoked        (10), certConfirmed      (11),
//!     wrongIntegrity      (12), badRecipientNonce  (13), timeNotAvailable   (14),
//!     unacceptedPolicy    (15), unacceptedExtension (16), addInfoNotAvailable (17),
//!     badSenderNonce      (18), badCertTemplate    (19), signerNotTrusted   (20),
//!     transactionIdInUse  (21), unsupportedVersion (22), notAuthorized      (23),
//!     systemUnavail       (24), systemFailure      (25), duplicateCertReq   (26) }
//! ```
//!
//! A named-bit BIT STRING: bit 0 is the most significant bit of the first
//! octet, and DER drops the trailing zero bits (X.690 §11.2.2).

use core::fmt;
use core::ops::{BitOr, BitOrAssign};

use tc_asn1::{
    Asn1BitString, Asn1Error, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// The reasons a request failed. Combine flags with `|`.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_cmp::PkiFailureInfo;
///
/// let info = PkiFailureInfo::BAD_ALG | PkiFailureInfo::BAD_TIME;
/// assert!(info.contains(PkiFailureInfo::BAD_TIME));
/// assert_eq!(info.to_string(), "badAlg, badTime");
/// assert_eq!(info.encode_to_vec(&EncodingOptions::DER)?, [3, 2, 4, 0x90]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct PkiFailureInfo {
    bits: u32,
}

impl PkiFailureInfo {
    // Bit i of the BIT STRING is 1 << (31 - i), so the u32 is the first four
    // content octets big-endian.
    pub const BAD_ALG: Self = Self::bit(0);
    pub const BAD_MESSAGE_CHECK: Self = Self::bit(1);
    pub const BAD_REQUEST: Self = Self::bit(2);
    pub const BAD_TIME: Self = Self::bit(3);
    pub const BAD_CERT_ID: Self = Self::bit(4);
    pub const BAD_DATA_FORMAT: Self = Self::bit(5);
    pub const WRONG_AUTHORITY: Self = Self::bit(6);
    pub const INCORRECT_DATA: Self = Self::bit(7);
    pub const MISSING_TIME_STAMP: Self = Self::bit(8);
    pub const BAD_POP: Self = Self::bit(9);
    pub const CERT_REVOKED: Self = Self::bit(10);
    pub const CERT_CONFIRMED: Self = Self::bit(11);
    pub const WRONG_INTEGRITY: Self = Self::bit(12);
    pub const BAD_RECIPIENT_NONCE: Self = Self::bit(13);
    pub const TIME_NOT_AVAILABLE: Self = Self::bit(14);
    pub const UNACCEPTED_POLICY: Self = Self::bit(15);
    pub const UNACCEPTED_EXTENSION: Self = Self::bit(16);
    pub const ADD_INFO_NOT_AVAILABLE: Self = Self::bit(17);
    pub const BAD_SENDER_NONCE: Self = Self::bit(18);
    pub const BAD_CERT_TEMPLATE: Self = Self::bit(19);
    pub const SIGNER_NOT_TRUSTED: Self = Self::bit(20);
    pub const TRANSACTION_ID_IN_USE: Self = Self::bit(21);
    pub const UNSUPPORTED_VERSION: Self = Self::bit(22);
    pub const NOT_AUTHORIZED: Self = Self::bit(23);
    pub const SYSTEM_UNAVAIL: Self = Self::bit(24);
    pub const SYSTEM_FAILURE: Self = Self::bit(25);
    pub const DUPLICATE_CERT_REQ: Self = Self::bit(26);

    const NAMES: [&'static str; 27] = [
        "badAlg",
        "badMessageCheck",
        "badRequest",
        "badTime",
        "badCertId",
        "badDataFormat",
        "wrongAuthority",
        "incorrectData",
        "missingTimeStamp",
        "badPOP",
        "certRevoked",
        "certConfirmed",
        "wrongIntegrity",
        "badRecipientNonce",
        "timeNotAvailable",
        "unacceptedPolicy",
        "unacceptedExtension",
        "addInfoNotAvailable",
        "badSenderNonce",
        "badCertTemplate",
        "signerNotTrusted",
        "transactionIdInUse",
        "unsupportedVersion",
        "notAuthorized",
        "systemUnavail",
        "systemFailure",
        "duplicateCertReq",
    ];
    const DEFINED: u32 = 0xFFFF_FFE0;

    const fn bit(index: u32) -> Self {
        Self {
            bits: 1 << (31 - index),
        }
    }

    /// From the raw bits, `1 << (31 - i)` for bit `i`. An undefined bit is
    /// `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn from_bits(bits: u32) -> Result<Self, Asn1Error> {
        if bits & !Self::DEFINED != 0 {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { bits })
    }

    /// Returns the raw bits, `1 << (31 - i)` for bit `i`.
    /// Variable time: branches only on the encoding structure.
    pub fn bits(self) -> u32 {
        self.bits
    }

    /// Whether every flag in `other` is set in `self`.
    /// Variable time: branches only on the encoding structure.
    pub fn contains(self, other: Self) -> bool {
        self.bits & other.bits == other.bits
    }

    /// The shortest BIT STRING for the flags, as DER wants it.
    fn bit_string(self) -> Asn1BitString {
        let bit_len = 32 - self.bits.trailing_zeros() as usize;
        Asn1BitString::from_bits(&self.bits.to_be_bytes(), bit_len)
    }
}

impl BitOr for PkiFailureInfo {
    type Output = Self;

    /// Variable time: branches only on the encoding structure.
    fn bitor(self, rhs: Self) -> Self {
        Self {
            bits: self.bits | rhs.bits,
        }
    }
}

impl BitOrAssign for PkiFailureInfo {
    /// Variable time: branches only on the encoding structure.
    fn bitor_assign(&mut self, rhs: Self) {
        self.bits |= rhs.bits;
    }
}

/// The set flags by their ASN.1 names, comma separated, in bit order.
impl fmt::Display for PkiFailureInfo {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (index, name) in (0..).zip(Self::NAMES) {
            if self.contains(Self::bit(index)) {
                if !first {
                    f.write_str(", ")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        Ok(())
    }
}

impl DecodeInner for PkiFailureInfo {
    /// Bits past the 27th must be zero. Under DER a trailing zero bit is
    /// `NotDer`, since X.690 §11.2.2 wants it dropped.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, bit_string) = Asn1BitString::decode_inner(buff, context)?;
        let bytes = bit_string.as_bytes();
        let (head, rest) = bytes.split_at(bytes.len().min(4));
        if rest.iter().any(|byte| *byte != 0) {
            return Err(Asn1Error::MalformedValue);
        }
        let mut octets = [0; 4];
        octets[..head.len()].copy_from_slice(head);
        let info = Self::from_bits(u32::from_be_bytes(octets))?;
        if context.is_der() && bit_string.bit_len() != info.bit_string().bit_len() {
            return Err(Asn1Error::NotDer);
        }
        Ok((used, info))
    }
}

impl Decode for PkiFailureInfo {}

impl Tagged for PkiFailureInfo {
    const TAG: &'static [u8] = Asn1BitString::TAG;
}

impl EncodeContent for PkiFailureInfo {
    /// Always the shortest form, under every rule set.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.bit_string().content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.bit_string().encode_content(rules, out)
    }
}

impl EncodeTagged for PkiFailureInfo {}

impl Encode for PkiFailureInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
