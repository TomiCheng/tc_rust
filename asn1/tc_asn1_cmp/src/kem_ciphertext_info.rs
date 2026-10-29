//! RFC 9810 §5.1.3.4 `KemCiphertextInfo`, a KEM ciphertext.
//!
//! ```text
//! KemCiphertextInfo ::= SEQUENCE {
//!     kem AlgorithmIdentifier{KEM-ALGORITHM, {...}},
//!     ct  OCTET STRING }
//! ```

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// The KEM and its ciphertext.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct KemCiphertextInfo {
    kem: AlgorithmIdentifier,
    ct: Asn1OctetString,
}

impl KemCiphertextInfo {
    /// The KEM and the ciphertext.
    /// Variable time: branches only on the encoding structure.
    pub fn new(kem: AlgorithmIdentifier, ct: Asn1OctetString) -> Self {
        Self { kem, ct }
    }

    /// Returns the KEM.
    /// Variable time: branches only on the encoding structure.
    pub fn kem(&self) -> &AlgorithmIdentifier {
        &self.kem
    }

    /// Returns the ciphertext.
    /// Variable time: branches only on the encoding structure.
    pub fn ct(&self) -> &Asn1OctetString {
        &self.ct
    }
}

impl DecodeContent for KemCiphertextInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let kem = fields.get()?;
        let ct = fields.get()?;
        fields.end()?;
        let value = Self { kem, ct };
        Ok(value)
    }
}

impl DecodeInner for KemCiphertextInfo {
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

impl EncodeContent for KemCiphertextInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.kem.encoded_len(rules) + self.ct.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.kem.encode(rules, out)?;
        at += self.ct.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for KemCiphertextInfo {}

impl Tagged for KemCiphertextInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for KemCiphertextInfo {}

impl Encode for KemCiphertextInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
