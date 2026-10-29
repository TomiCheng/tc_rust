//! RFC 6960 §4.2.1 `CertStatus`, the status of one certificate.
//!
//! ```text
//! CertStatus ::= CHOICE {
//!     good    [0] IMPLICIT NULL,
//!     revoked [1] IMPLICIT RevokedInfo,
//!     unknown [2] IMPLICIT UnknownInfo }
//! UnknownInfo ::= NULL
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Implicit,
};

use crate::RevokedInfo;

/// Good, revoked with its time and reason, or unknown to the responder.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_ocsp::CertStatus;
///
/// let der = CertStatus::Good.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x80, 0]);
/// assert_eq!(CertStatus::decode_der(&der, &DecodingOptions::default())?.1, CertStatus::Good);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum CertStatus {
    /// `[0]`: not revoked, which does not say the certificate was ever issued.
    Good,
    /// `[1]`: revoked or on hold.
    Revoked(RevokedInfo),
    /// `[2]`: the responder does not know the certificate.
    Unknown,
}

impl From<RevokedInfo> for CertStatus {
    /// Variable time: branches only on the encoding structure.
    fn from(value: RevokedInfo) -> Self {
        Self::Revoked(value)
    }
}

impl DecodeInner for CertStatus {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// A NULL alternative with contents is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0x80] => Self::Good,
            [0xa1] => Self::Revoked(RevokedInfo::decode_content(element.value(), context)?),
            [0x82] => Self::Unknown,
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        if matches!(value, Self::Good | Self::Unknown) && !element.value().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok((element.total_len(), value))
    }
}

impl Decode for CertStatus {}

impl EncodeContent for CertStatus {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Revoked(inner) => inner.content_len(rules),
            Self::Good | Self::Unknown => 0,
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Revoked(inner) => inner.encode_content(rules, out),
            Self::Good | Self::Unknown => Ok(0),
        }
    }
}

impl EncodeTagged for CertStatus {}

impl Encode for CertStatus {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Good => 2,
            Self::Revoked(inner) => Implicit::new(&[0xa1], inner).encoded_len(rules),
            Self::Unknown => 2,
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let tag = match self {
            Self::Good => 0x80,
            Self::Revoked(inner) => return Implicit::new(&[0xa1], inner).encode(rules, out),
            Self::Unknown => 0x82,
        };
        out.get_mut(..2)
            .ok_or(Asn1Error::BufferTooSmall)?
            .copy_from_slice(&[tag, 0]);
        Ok(2)
    }
}
