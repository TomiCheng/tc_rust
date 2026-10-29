//! RFC 6960 §4.2.1 `ResponderID`, which names the responder that signed.
//!
//! ```text
//! ResponderID ::= CHOICE {
//!     byName [1] Name,      -- EXPLICIT
//!     byKey  [2] KeyHash }  -- EXPLICIT
//! KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
//! ```

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit,
};
use tc_asn1_x500::Name;

/// The responder, by its certificate's subject name or by the hash of its key.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
///
/// ```
/// use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_ocsp::ResponderId;
///
/// let id = ResponderId::ByKey(Asn1OctetString::new(&[0x4a; 20]));
/// let der = id.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der[..4], [0xa2, 22, 0x04, 20]);
/// assert_eq!(ResponderId::decode_der(&der, &DecodingOptions::default())?.1, id);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ResponderId {
    /// `[1]`, the subject name of the responder's certificate.
    ByName(Name),
    /// `[2]`, the SHA-1 hash of the responder's public key bits.
    ByKey(Asn1OctetString),
}

impl ResponderId {
    fn tag(&self) -> &'static [u8] {
        match self {
            Self::ByName(_) => &[0xa1],
            Self::ByKey(_) => &[0xa2],
        }
    }

    fn inner(&self) -> &dyn Encode {
        match self {
            Self::ByName(inner) => inner,
            Self::ByKey(inner) => inner,
        }
    }
}

impl From<Name> for ResponderId {
    /// Variable time: branches only on the encoding structure.
    fn from(value: Name) -> Self {
        Self::ByName(value)
    }
}

impl DecodeInner for ResponderId {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let tag = element.tag();
        if tag != [0xa1] && tag != [0xa2] {
            return Err(Asn1Error::UnexpectedTag);
        }
        let mut inner = element.children(context)?;
        let value = if tag == [0xa1] {
            Self::ByName(inner.get()?)
        } else {
            Self::ByKey(inner.get()?)
        };
        inner.end()?;
        Ok((element.total_len(), value))
    }
}

impl Decode for ResponderId {}

impl EncodeContent for ResponderId {
    /// The contents under the alternative's identifier: the inner element.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.inner().encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.inner().encode(rules, out)
    }
}

impl EncodeTagged for ResponderId {}

impl Encode for ResponderId {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        Explicit::new(self.tag(), self.inner()).encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        Explicit::new(self.tag(), self.inner()).encode(rules, out)
    }
}
