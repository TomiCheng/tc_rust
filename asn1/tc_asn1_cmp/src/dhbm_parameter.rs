//! RFC 4210 §5.1.3.2 `DHBMParameter`, the parameters of a Diffie-Hellman based MAC.
//!
//! ```text
//! DHBMParameter ::= SEQUENCE {
//!     owf AlgorithmIdentifier,
//!     mac AlgorithmIdentifier }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// The one-way function and MAC of `dhBasedMac`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DhbmParameter {
    owf: AlgorithmIdentifier,
    mac: AlgorithmIdentifier,
}

impl DhbmParameter {
    /// Both algorithms.
    /// Variable time: branches only on the encoding structure.
    pub fn new(owf: AlgorithmIdentifier, mac: AlgorithmIdentifier) -> Self {
        Self { owf, mac }
    }

    /// Returns the one-way function, a hash.
    /// Variable time: branches only on the encoding structure.
    pub fn owf(&self) -> &AlgorithmIdentifier {
        &self.owf
    }

    /// Returns the MAC algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn mac(&self) -> &AlgorithmIdentifier {
        &self.mac
    }
}

impl DecodeContent for DhbmParameter {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let owf = fields.get()?;
        let mac = fields.get()?;
        fields.end()?;
        let value = Self { owf, mac };
        Ok(value)
    }
}

impl DecodeInner for DhbmParameter {
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

impl EncodeContent for DhbmParameter {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.owf.encoded_len(rules) + self.mac.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.owf.encode(rules, out)?;
        at += self.mac.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for DhbmParameter {}

impl Tagged for DhbmParameter {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for DhbmParameter {}

impl Encode for DhbmParameter {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
