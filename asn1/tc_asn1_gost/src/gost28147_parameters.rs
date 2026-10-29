//! RFC 4357 §10.3 `Gost28147-89-Parameters`, the parameters of GOST 28147-89
//! encryption.
//!
//! ```text
//! Gost28147-89-Parameters ::= SEQUENCE {
//!     iv                 Gost28147-89-IV,
//!     encryptionParamSet OBJECT IDENTIFIER }
//! Gost28147-89-IV ::= OCTET STRING (SIZE (8))
//! ```
//!
//! The IV's size is not checked, as in Bouncy Castle.

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The IV and the S-box parameter set.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Gost28147Parameters {
    iv: Asn1OctetString,
    encryption_param_set: Asn1Oid,
}

impl Gost28147Parameters {
    /// The IV and the parameter set.
    /// Variable time: branches only on the encoding structure.
    pub fn new(iv: Asn1OctetString, encryption_param_set: Asn1Oid) -> Self {
        Self {
            iv,
            encryption_param_set,
        }
    }

    /// Returns the IV.
    /// Variable time: branches only on the encoding structure.
    pub fn iv(&self) -> &Asn1OctetString {
        &self.iv
    }

    /// Returns the S-box parameter set.
    /// Variable time: branches only on the encoding structure.
    pub fn encryption_param_set(&self) -> &Asn1Oid {
        &self.encryption_param_set
    }
}

impl DecodeContent for Gost28147Parameters {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let iv = fields.get()?;
        let encryption_param_set = fields.get()?;
        fields.end()?;
        let value = Self {
            iv,
            encryption_param_set,
        };
        Ok(value)
    }
}

impl DecodeInner for Gost28147Parameters {
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

impl EncodeContent for Gost28147Parameters {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.iv.encoded_len(rules) + self.encryption_param_set.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.iv.encode(rules, out)?;
        at += self.encryption_param_set.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for Gost28147Parameters {}

impl Tagged for Gost28147Parameters {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Gost28147Parameters {}

impl Encode for Gost28147Parameters {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
