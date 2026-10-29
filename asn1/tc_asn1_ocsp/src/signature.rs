//! RFC 6960 §4.1.1 `Signature`, the optional signature of a request.
//!
//! ```text
//! Signature ::= SEQUENCE {
//!     signatureAlgorithm AlgorithmIdentifier,
//!     signature          BIT STRING,
//!     certs              [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent,
    DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit,
    Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::Certificate;

/// The requestor's signature over the `TBSRequest`, and certificates to check it.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Signature {
    signature_algorithm: AlgorithmIdentifier,
    signature: Asn1BitString,
    certs: Option<Asn1SequenceOf<Certificate>>,
}

impl Signature {
    /// The signature algorithm and value, without certificates.
    /// Variable time: branches only on the encoding structure.
    pub fn new(signature_algorithm: AlgorithmIdentifier, signature: Asn1BitString) -> Self {
        Self {
            signature_algorithm,
            signature,
            certs: None,
        }
    }

    /// Sets the certificates that help verify the signature.
    /// Variable time: branches only on the encoding structure.
    pub fn with_certs(mut self, certs: Vec<Certificate>) -> Self {
        self.certs = Some(Asn1SequenceOf::new(certs));
        self
    }

    /// Returns the signature algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// Returns the signature value.
    /// Variable time: branches only on the encoding structure.
    pub fn signature(&self) -> &Asn1BitString {
        &self.signature
    }

    /// Returns the certificates in order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn certs(&self) -> Option<&[Certificate]> {
        self.certs.as_ref().map(Asn1SequenceOf::elements)
    }
}

impl DecodeContent for Signature {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let signature_algorithm = fields.get()?;
        let signature = fields.get()?;
        let certs = fields.get_explicit_opt::<Asn1SequenceOf<Certificate>>([0xa0])?;
        fields.end()?;
        let value = Self {
            signature_algorithm,
            signature,
            certs,
        };
        Ok(value)
    }
}

impl DecodeInner for Signature {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for Signature {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.signature_algorithm.encoded_len(rules)
            + self.signature.encoded_len(rules)
            + self
                .certs
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.signature_algorithm.encode(rules, out)?;
        at += self.signature.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.certs {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for Signature {}

impl Tagged for Signature {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Signature {}

impl Encode for Signature {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
