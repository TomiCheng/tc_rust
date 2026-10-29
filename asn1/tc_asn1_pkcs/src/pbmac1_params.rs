//! RFC 8018 A.5 `PBMAC1-params`, a password-based MAC: the key derivation and the
//! MAC it keys.
//!
//! ```text
//! PBMAC1-params ::= SEQUENCE {
//!     keyDerivationFunc AlgorithmIdentifier {{PBMAC1-KDFs}},
//!     messageAuthScheme AlgorithmIdentifier {{PBMAC1-MACs}} }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

/// The key derivation, such as PBKDF2, and the MAC, such as HMAC-SHA256.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Pbmac1Params {
    key_derivation_func: AlgorithmIdentifier,
    message_auth_scheme: AlgorithmIdentifier,
}

impl Pbmac1Params {
    /// The key derivation and the MAC scheme.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        key_derivation_func: AlgorithmIdentifier,
        message_auth_scheme: AlgorithmIdentifier,
    ) -> Self {
        Self {
            key_derivation_func,
            message_auth_scheme,
        }
    }

    /// Returns the key derivation and its parameters.
    /// Variable time: branches only on the encoding structure.
    pub fn key_derivation_func(&self) -> &AlgorithmIdentifier {
        &self.key_derivation_func
    }

    /// Returns the MAC scheme.
    /// Variable time: branches only on the encoding structure.
    pub fn message_auth_scheme(&self) -> &AlgorithmIdentifier {
        &self.message_auth_scheme
    }
}

impl DecodeContent for Pbmac1Params {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let key_derivation_func = fields.get()?;
        let message_auth_scheme = fields.get()?;
        fields.end()?;
        let value = Self {
            key_derivation_func,
            message_auth_scheme,
        };
        Ok(value)
    }
}

impl DecodeInner for Pbmac1Params {
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

impl EncodeContent for Pbmac1Params {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.key_derivation_func.encoded_len(rules) + self.message_auth_scheme.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.key_derivation_func.encode(rules, out)?;
        at += self.message_auth_scheme.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for Pbmac1Params {}

impl Tagged for Pbmac1Params {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Pbmac1Params {}

impl Encode for Pbmac1Params {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
