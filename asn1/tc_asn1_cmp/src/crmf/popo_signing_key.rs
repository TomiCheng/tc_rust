//! RFC 4211 §4.1 `POPOSigningKey`, a signature proof of possession.
//!
//! ```text
//! POPOSigningKey ::= SEQUENCE {
//!     poposkInput         [0] POPOSigningKeyInput OPTIONAL,
//!     algorithmIdentifier AlgorithmIdentifier,
//!     signature           BIT STRING }
//! ```
//!
//! The module uses implicit tags; a CHOICE under a tag is still explicit.

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::crmf::PopoSigningKeyInput;

/// A signature over the request, or over `poposkInput` when present.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PopoSigningKey {
    poposk_input: Option<PopoSigningKeyInput>,
    algorithm_identifier: AlgorithmIdentifier,
    signature: Asn1BitString,
}

impl PopoSigningKey {
    /// A signature over the request itself.
    /// Variable time: branches only on the encoding structure.
    pub fn new(algorithm_identifier: AlgorithmIdentifier, signature: Asn1BitString) -> Self {
        Self {
            poposk_input: None,
            algorithm_identifier,
            signature,
        }
    }

    /// Sets the signed input, for a template without subject or key.
    /// Variable time: branches only on the encoding structure.
    pub fn with_poposk_input(mut self, poposk_input: PopoSigningKeyInput) -> Self {
        self.poposk_input = Some(poposk_input);
        self
    }

    /// Returns the signed input, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn poposk_input(&self) -> Option<&PopoSigningKeyInput> {
        self.poposk_input.as_ref()
    }

    /// Returns the signature algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn algorithm_identifier(&self) -> &AlgorithmIdentifier {
        &self.algorithm_identifier
    }

    /// Returns the signature.
    /// Variable time: branches only on the encoding structure.
    pub fn signature(&self) -> &Asn1BitString {
        &self.signature
    }
}

impl DecodeContent for PopoSigningKey {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let poposk_input = fields.get_implicit_opt([0xa0])?;
        let algorithm_identifier = fields.get()?;
        let signature = fields.get()?;
        fields.end()?;
        let value = Self {
            poposk_input,
            algorithm_identifier,
            signature,
        };
        Ok(value)
    }
}

impl DecodeInner for PopoSigningKey {
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

impl EncodeContent for PopoSigningKey {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.poposk_input
            .as_ref()
            .map_or(0, |v| Implicit::new(&[0xa0], v).encoded_len(rules))
            + self.algorithm_identifier.encoded_len(rules)
            + self.signature.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.poposk_input {
            at += Implicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        at += self.algorithm_identifier.encode(rules, &mut out[at..])?;
        at += self.signature.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for PopoSigningKey {}

impl Tagged for PopoSigningKey {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PopoSigningKey {}

impl Encode for PopoSigningKey {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
