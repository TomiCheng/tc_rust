//! RFC 5126 §5.8.1 `SignaturePolicyIdentifier`, the value of the
//! signature-policy-identifier attribute.
//!
//! ```text
//! SignaturePolicyIdentifier ::= CHOICE {
//!     signaturePolicyId      SignaturePolicyId,
//!     signaturePolicyImplied SignaturePolicyImplied }
//! SignaturePolicyImplied ::= NULL
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, tag,
};

use crate::SignaturePolicyId;

/// An explicit policy, or a policy implied by the context.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_esf::SignaturePolicyIdentifier;
///
/// let implied = SignaturePolicyIdentifier::SignaturePolicyImplied;
/// assert_eq!(implied.encode_to_vec(&EncodingOptions::DER)?, [0x05, 0]);
/// assert_eq!(SignaturePolicyIdentifier::decode_der(&[0x05, 0], &DecodingOptions::default())?.1, implied);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SignaturePolicyIdentifier {
    /// The policy by identifier and hash.
    SignaturePolicyId(SignaturePolicyId),
    /// NULL: the policy follows from the context.
    SignaturePolicyImplied,
}

impl From<SignaturePolicyId> for SignaturePolicyIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn from(value: SignaturePolicyId) -> Self {
        Self::SignaturePolicyId(value)
    }
}

impl DecodeInner for SignaturePolicyIdentifier {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// A NULL with contents is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            tag::SEQUENCE => Self::SignaturePolicyId(element.decode_as(context)?),
            tag::NULL if element.value().is_empty() => Self::SignaturePolicyImplied,
            tag::NULL => return Err(Asn1Error::MalformedValue),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for SignaturePolicyIdentifier {}

impl EncodeContent for SignaturePolicyIdentifier {
    /// The contents under the alternative's own identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::SignaturePolicyId(inner) => inner.content_len(rules),
            Self::SignaturePolicyImplied => 0,
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::SignaturePolicyId(inner) => inner.encode_content(rules, out),
            Self::SignaturePolicyImplied => Ok(0),
        }
    }
}

impl EncodeTagged for SignaturePolicyIdentifier {}

impl Encode for SignaturePolicyIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::SignaturePolicyId(inner) => inner.encoded_len(rules),
            Self::SignaturePolicyImplied => 2,
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::SignaturePolicyId(inner) => inner.encode(rules, out),
            Self::SignaturePolicyImplied => {
                out.get_mut(..2)
                    .ok_or(Asn1Error::BufferTooSmall)?
                    .copy_from_slice(&[0x05, 0]);
                Ok(2)
            }
        }
    }
}
