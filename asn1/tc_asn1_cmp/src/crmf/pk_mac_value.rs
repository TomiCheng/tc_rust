//! RFC 4211 §4.1 `PKMACValue`, a password-based MAC over a public key.
//!
//! ```text
//! PKMACValue ::= SEQUENCE {
//!     algId AlgorithmIdentifier,
//!     value BIT STRING }
//! ```

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// The MAC algorithm, such as `CrmfId::PASSWORD_BASED_MAC`, and the MAC.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PkMacValue {
    alg_id: AlgorithmIdentifier,
    value: Asn1BitString,
}

impl PkMacValue {
    /// The algorithm and the MAC.
    /// Variable time: branches only on the encoding structure.
    pub fn new(alg_id: AlgorithmIdentifier, value: Asn1BitString) -> Self {
        Self { alg_id, value }
    }

    /// Returns the MAC algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn alg_id(&self) -> &AlgorithmIdentifier {
        &self.alg_id
    }

    /// Returns the MAC.
    /// Variable time: branches only on the encoding structure.
    pub fn value(&self) -> &Asn1BitString {
        &self.value
    }
}

impl DecodeContent for PkMacValue {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let alg_id = fields.get()?;
        let value = fields.get()?;
        fields.end()?;
        let value = Self { alg_id, value };
        Ok(value)
    }
}

impl DecodeInner for PkMacValue {
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

impl EncodeContent for PkMacValue {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.alg_id.encoded_len(rules) + self.value.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.alg_id.encode(rules, out)?;
        at += self.value.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for PkMacValue {}

impl Tagged for PkMacValue {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PkMacValue {}

impl Encode for PkMacValue {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
