//! RFC 7914 §7 `scrypt-params`, scrypt as a PBES2 key derivation, Bouncy Castle's
//! `Asn1.Misc.ScryptParams`.
//!
//! ```text
//! scrypt-params ::= SEQUENCE {
//!     salt                     OCTET STRING,
//!     costParameter            INTEGER (1..MAX),
//!     blockSize                INTEGER (1..MAX),
//!     parallelizationParameter INTEGER (1..MAX),
//!     keyLength                INTEGER (1..MAX) OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// A salt, the cost N, the block size r, the parallelization p and an optional
/// key length in octets, unchecked as in Bouncy Castle.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ScryptParams {
    salt: Asn1OctetString,
    cost_parameter: Asn1Integer,
    block_size: Asn1Integer,
    parallelization_parameter: Asn1Integer,
    key_length: Option<Asn1Integer>,
}

impl ScryptParams {
    /// The salt and the three cost parameters, without a key length.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        salt: Asn1OctetString,
        cost_parameter: Asn1Integer,
        block_size: Asn1Integer,
        parallelization_parameter: Asn1Integer,
    ) -> Self {
        Self {
            salt,
            cost_parameter,
            block_size,
            parallelization_parameter,
            key_length: None,
        }
    }

    /// Adds the key length in octets.
    /// Variable time: branches only on the encoding structure.
    pub fn with_key_length(mut self, key_length: Asn1Integer) -> Self {
        self.key_length = Some(key_length);
        self
    }

    /// Returns the salt.
    /// Variable time: branches only on the encoding structure.
    pub fn salt(&self) -> &Asn1OctetString {
        &self.salt
    }

    /// Returns the cost N.
    /// Variable time: branches only on the encoding structure.
    pub fn cost_parameter(&self) -> &Asn1Integer {
        &self.cost_parameter
    }

    /// Returns the block size r.
    /// Variable time: branches only on the encoding structure.
    pub fn block_size(&self) -> &Asn1Integer {
        &self.block_size
    }

    /// Returns the parallelization p.
    /// Variable time: branches only on the encoding structure.
    pub fn parallelization_parameter(&self) -> &Asn1Integer {
        &self.parallelization_parameter
    }

    /// Returns the key length in octets, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn key_length(&self) -> Option<&Asn1Integer> {
        self.key_length.as_ref()
    }
}

impl DecodeContent for ScryptParams {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let salt = fields.get()?;
        let cost_parameter = fields.get()?;
        let block_size = fields.get()?;
        let parallelization_parameter = fields.get()?;
        let key_length = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            salt,
            cost_parameter,
            block_size,
            parallelization_parameter,
            key_length,
        };
        Ok(value)
    }
}

impl DecodeInner for ScryptParams {
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

impl EncodeContent for ScryptParams {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.salt.encoded_len(rules)
            + self.cost_parameter.encoded_len(rules)
            + self.block_size.encoded_len(rules)
            + self.parallelization_parameter.encoded_len(rules)
            + self.key_length.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.salt.encode(rules, out)?;
        at += self.cost_parameter.encode(rules, &mut out[at..])?;
        at += self.block_size.encode(rules, &mut out[at..])?;
        at += self
            .parallelization_parameter
            .encode(rules, &mut out[at..])?;
        if let Some(v) = &self.key_length {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for ScryptParams {}

impl Tagged for ScryptParams {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ScryptParams {}

impl Encode for ScryptParams {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
