//! RFC 6960 §4.2.1 `OCSPResponseStatus`.
//!
//! ```text
//! OCSPResponseStatus ::= ENUMERATED {
//!     successful       (0), -- Response has valid confirmations
//!     malformedRequest (1), -- Illegal confirmation request
//!     internalError    (2), -- Internal error in issuer
//!     tryLater         (3), -- Try again later
//!                           -- (4) is not used
//!     sigRequired      (5), -- Must sign the request
//!     unauthorized     (6)  -- Request unauthorized
//! }
//! ```

use core::fmt;

use tc_asn1::{
    Asn1Enumerated, Asn1Error, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged, tag,
};

/// Whether the responder processed the request.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_ocsp::OcspResponseStatus;
///
/// assert_eq!(OcspResponseStatus::TryLater.encode_to_vec(&EncodingOptions::DER)?, [10, 1, 3]);
/// assert_eq!(OcspResponseStatus::SigRequired.to_string(), "sigRequired");
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OcspResponseStatus {
    /// `successful (0)`: the response bytes follow.
    Successful = 0,
    /// `malformedRequest (1)`.
    MalformedRequest = 1,
    /// `internalError (2)`.
    InternalError = 2,
    /// `tryLater (3)`.
    TryLater = 3,
    /// `sigRequired (5)`.
    SigRequired = 5,
    /// `unauthorized (6)`.
    Unauthorized = 6,
}

impl OcspResponseStatus {
    /// Returns the ASN.1 enumeration value.
    /// Variable time: branches only on the encoding structure.
    pub fn number(self) -> u8 {
        self as u8
    }

    /// Returns the named status, rejecting unassigned values with `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn from_number(number: u8) -> Result<Self, Asn1Error> {
        match number {
            0 => Ok(Self::Successful),
            1 => Ok(Self::MalformedRequest),
            2 => Ok(Self::InternalError),
            3 => Ok(Self::TryLater),
            5 => Ok(Self::SigRequired),
            6 => Ok(Self::Unauthorized),
            _ => Err(Asn1Error::MalformedValue),
        }
    }
}

impl fmt::Display for OcspResponseStatus {
    /// Variable time: branches only on the encoding structure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Successful => "successful",
            Self::MalformedRequest => "malformedRequest",
            Self::InternalError => "internalError",
            Self::TryLater => "tryLater",
            Self::SigRequired => "sigRequired",
            Self::Unauthorized => "unauthorized",
        })
    }
}

impl DecodeInner for OcspResponseStatus {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, value) = Asn1Enumerated::decode_inner(buff, context)?;
        let number = u64::try_from(&value).map_err(|_| Asn1Error::MalformedValue)?;
        let number = u8::try_from(number).map_err(|_| Asn1Error::MalformedValue)?;
        Ok((used, Self::from_number(number)?))
    }
}

impl EncodeContent for OcspResponseStatus {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, _rules: &EncodingOptions) -> usize {
        1
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, _rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        *out.first_mut().ok_or(Asn1Error::BufferTooSmall)? = self.number();
        Ok(1)
    }
}

impl Decode for OcspResponseStatus {}

impl Tagged for OcspResponseStatus {
    const TAG: &'static [u8] = tag::ENUMERATED;
}

impl EncodeTagged for OcspResponseStatus {}

impl Encode for OcspResponseStatus {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
