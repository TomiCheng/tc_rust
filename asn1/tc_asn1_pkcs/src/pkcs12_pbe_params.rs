//! RFC 7292 C `pkcs-12PbeParams`, the parameters of the PKCS #12 password-based
//! encryption schemes.
//!
//! ```text
//! pkcs-12PbeParams ::= SEQUENCE {
//!     salt       OCTET STRING,
//!     iterations INTEGER }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// A salt and an iteration count.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Pkcs12PbeParams {
    salt: Asn1OctetString,
    iterations: Asn1Integer,
}

impl Pkcs12PbeParams {
    /// The salt and the iteration count.
    /// Variable time: branches only on the encoding structure.
    pub fn new(salt: Asn1OctetString, iterations: Asn1Integer) -> Self {
        Self { salt, iterations }
    }

    /// Returns the salt.
    /// Variable time: branches only on the encoding structure.
    pub fn salt(&self) -> &Asn1OctetString {
        &self.salt
    }

    /// Returns the iteration count.
    /// Variable time: branches only on the encoding structure.
    pub fn iterations(&self) -> &Asn1Integer {
        &self.iterations
    }
}

impl DecodeContent for Pkcs12PbeParams {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let salt = fields.get()?;
        let iterations = fields.get()?;
        fields.end()?;
        let value = Self { salt, iterations };
        Ok(value)
    }
}

impl DecodeInner for Pkcs12PbeParams {
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

impl EncodeContent for Pkcs12PbeParams {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.salt.encoded_len(rules) + self.iterations.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.salt.encode(rules, out)?;
        at += self.iterations.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for Pkcs12PbeParams {}

impl Tagged for Pkcs12PbeParams {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Pkcs12PbeParams {}

impl Encode for Pkcs12PbeParams {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
