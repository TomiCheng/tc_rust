//! RFC 5126 §5.7.3.3 `OtherHash`, a hash that is SHA-1 unless it says otherwise.
//!
//! ```text
//! OtherHash ::= CHOICE {
//!     sha1Hash  OtherHashValue,   -- This contains a SHA-1 hash
//!     otherHash OtherHashAlgAndValue }
//! OtherHashValue ::= OCTET STRING
//! ```

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, tag,
};

use crate::OtherHashAlgAndValue;

/// A bare SHA-1 hash, or a hash with its algorithm.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_esf::OtherHash;
///
/// let hash = OtherHash::Sha1Hash(Asn1OctetString::new(&[0x11; 20]));
/// let der = hash.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der[..2], [0x04, 20]);
/// assert_eq!(OtherHash::decode_der(&der, &DecodingOptions::default())?.1, hash);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum OtherHash {
    /// A SHA-1 hash, as an OCTET STRING.
    Sha1Hash(Asn1OctetString),
    /// A hash with its algorithm, as a SEQUENCE.
    OtherHash(OtherHashAlgAndValue),
}

impl From<OtherHashAlgAndValue> for OtherHash {
    /// Variable time: branches only on the encoding structure.
    fn from(value: OtherHashAlgAndValue) -> Self {
        Self::OtherHash(value)
    }
}

impl OtherHash {
    fn inner(&self) -> &dyn Encode {
        match self {
            Self::Sha1Hash(inner) => inner,
            Self::OtherHash(inner) => inner,
        }
    }
}

impl DecodeInner for OtherHash {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            tag::OCTET_STRING => Self::Sha1Hash(element.decode_as(context)?),
            tag::SEQUENCE => Self::OtherHash(element.decode_as(context)?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for OtherHash {}

impl EncodeContent for OtherHash {
    /// The contents under the alternative's own identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Sha1Hash(inner) => inner.content_len(rules),
            Self::OtherHash(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Sha1Hash(inner) => inner.encode_content(rules, out),
            Self::OtherHash(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for OtherHash {}

impl Encode for OtherHash {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.inner().encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.inner().encode(rules, out)
    }
}
