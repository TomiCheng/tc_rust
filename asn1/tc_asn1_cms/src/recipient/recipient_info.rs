//! RFC 5652 §6.2 `RecipientInfo`, one recipient of enveloped or authenticated
//! data and the content-encryption key wrapped for it.
//!
//! ```text
//! RecipientInfo ::= CHOICE {
//!     ktri KeyTransRecipientInfo,
//!     kari [1] KeyAgreeRecipientInfo,     -- IMPLICIT
//!     kekri [2] KEKRecipientInfo,          -- IMPLICIT
//!     pwri [3] PasswordRecipientinfo,     -- IMPLICIT
//!     ori [4] OtherRecipientInfo }         -- IMPLICIT
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Implicit,
};

use crate::recipient::{
    KekRecipientInfo, KeyAgreeRecipientInfo, KeyTransRecipientInfo, OtherRecipientInfo,
    PasswordRecipientInfo,
};

/// One recipient, by the way its key-encryption key is established.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum RecipientInfo {
    /// Key transport, such as RSA: the content-encryption key encrypted to the
    /// recipient's public key.
    KeyTrans(KeyTransRecipientInfo),
    /// `[1]`, key agreement, such as ECDH.
    KeyAgree(KeyAgreeRecipientInfo),
    /// `[2]`, a previously distributed symmetric key-encryption key.
    Kek(KekRecipientInfo),
    /// `[3]`, a key-encryption key derived from a password.
    Password(PasswordRecipientInfo),
    /// `[4]`, another technique, such as KEM (RFC 9629).
    Other(OtherRecipientInfo),
}

impl RecipientInfo {
    /// Returns the alternative's version, or `None` for `Other`, which has no
    /// version field. Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Option<Asn1Integer> {
        match self {
            Self::KeyTrans(inner) => Some(inner.version()),
            Self::KeyAgree(inner) => Some(inner.version()),
            Self::Kek(inner) => Some(inner.version()),
            Self::Password(inner) => Some(inner.version()),
            Self::Other(_) => None,
        }
    }
}

impl From<KeyTransRecipientInfo> for RecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn from(value: KeyTransRecipientInfo) -> Self {
        Self::KeyTrans(value)
    }
}

impl From<KeyAgreeRecipientInfo> for RecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn from(value: KeyAgreeRecipientInfo) -> Self {
        Self::KeyAgree(value)
    }
}

impl From<KekRecipientInfo> for RecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn from(value: KekRecipientInfo) -> Self {
        Self::Kek(value)
    }
}

impl From<PasswordRecipientInfo> for RecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn from(value: PasswordRecipientInfo) -> Self {
        Self::Password(value)
    }
}

impl From<OtherRecipientInfo> for RecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn from(value: OtherRecipientInfo) -> Self {
        Self::Other(value)
    }
}

impl DecodeInner for RecipientInfo {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = element.value();
        let info = match element.tag() {
            [0x30] => Self::KeyTrans(element.decode_as(context)?),
            [0xa1] => Self::KeyAgree(KeyAgreeRecipientInfo::decode_content(value, context)?),
            [0xa2] => Self::Kek(KekRecipientInfo::decode_content(value, context)?),
            [0xa3] => Self::Password(PasswordRecipientInfo::decode_content(value, context)?),
            [0xa4] => Self::Other(OtherRecipientInfo::decode_content(value, context)?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), info))
    }
}

impl Decode for RecipientInfo {}

impl EncodeContent for RecipientInfo {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::KeyTrans(inner) => inner.content_len(rules),
            Self::KeyAgree(inner) => inner.content_len(rules),
            Self::Kek(inner) => inner.content_len(rules),
            Self::Password(inner) => inner.content_len(rules),
            Self::Other(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::KeyTrans(inner) => inner.encode_content(rules, out),
            Self::KeyAgree(inner) => inner.encode_content(rules, out),
            Self::Kek(inner) => inner.encode_content(rules, out),
            Self::Password(inner) => inner.encode_content(rules, out),
            Self::Other(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for RecipientInfo {}

impl Encode for RecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::KeyTrans(inner) => inner.encoded_len(rules),
            Self::KeyAgree(inner) => Implicit::new(&[0xa1], inner).encoded_len(rules),
            Self::Kek(inner) => Implicit::new(&[0xa2], inner).encoded_len(rules),
            Self::Password(inner) => Implicit::new(&[0xa3], inner).encoded_len(rules),
            Self::Other(inner) => Implicit::new(&[0xa4], inner).encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::KeyTrans(inner) => inner.encode(rules, out),
            Self::KeyAgree(inner) => Implicit::new(&[0xa1], inner).encode(rules, out),
            Self::Kek(inner) => Implicit::new(&[0xa2], inner).encode(rules, out),
            Self::Password(inner) => Implicit::new(&[0xa3], inner).encode(rules, out),
            Self::Other(inner) => Implicit::new(&[0xa4], inner).encode(rules, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::RecipientInfo;
    use crate::fixtures::recipients;

    #[test]
    fn every_alternative_round_trips_under_its_identifier_and_reports_its_version() {
        let expected = [
            (0x30, Some(0)),
            (0xa1, Some(3)),
            (0xa2, Some(4)),
            (0xa3, Some(0)),
            (0xa4, None),
        ];
        for (value, (first, version)) in recipients().into_iter().zip(expected) {
            let wire = value.encode_to_vec(&EncodingOptions::DER).unwrap();
            assert_eq!(wire[0], first);
            assert_eq!(value.version(), version.map(Into::into));
            assert_eq!(
                RecipientInfo::decode_der(&wire, &DecodingOptions::default())
                    .unwrap()
                    .1,
                value
            );
        }
        assert_eq!(
            RecipientInfo::decode_der(&[0xa0, 0x00], &DecodingOptions::default()),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
