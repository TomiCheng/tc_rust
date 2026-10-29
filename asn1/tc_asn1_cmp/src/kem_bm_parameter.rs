//! RFC 9810 §5.1.3.4 `KemBMParameter`, the parameters of a KEM-based MAC.
//!
//! ```text
//! KemBMParameter ::= SEQUENCE {
//!     kdf AlgorithmIdentifier{KEY-DERIVATION, {...}},
//!     len INTEGER (1..MAX),
//!     mac AlgorithmIdentifier{MAC-ALGORITHM, {...}} }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// The key derivation, its output length, and the MAC of `kemBasedMac`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct KemBmParameter {
    kdf: AlgorithmIdentifier,
    len: Asn1Integer,
    mac: AlgorithmIdentifier,
}

impl KemBmParameter {
    /// Every parameter.
    /// Variable time: branches only on the encoding structure.
    pub fn new(kdf: AlgorithmIdentifier, len: Asn1Integer, mac: AlgorithmIdentifier) -> Self {
        Self { kdf, len, mac }
    }

    /// Returns the key derivation function.
    /// Variable time: branches only on the encoding structure.
    pub fn kdf(&self) -> &AlgorithmIdentifier {
        &self.kdf
    }

    /// Returns the length of the derived key in octets.
    /// Variable time: branches only on the encoding structure.
    pub fn len(&self) -> &Asn1Integer {
        &self.len
    }

    /// Returns the MAC algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn mac(&self) -> &AlgorithmIdentifier {
        &self.mac
    }
}

impl DecodeContent for KemBmParameter {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let kdf = fields.get()?;
        let len = fields.get()?;
        let mac = fields.get()?;
        fields.end()?;
        let value = Self { kdf, len, mac };
        Ok(value)
    }
}

impl DecodeInner for KemBmParameter {
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

impl EncodeContent for KemBmParameter {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.kdf.encoded_len(rules) + self.len.encoded_len(rules) + self.mac.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.kdf.encode(rules, out)?;
        at += self.len.encode(rules, &mut out[at..])?;
        at += self.mac.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for KemBmParameter {}

impl Tagged for KemBmParameter {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for KemBmParameter {}

impl Encode for KemBmParameter {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
