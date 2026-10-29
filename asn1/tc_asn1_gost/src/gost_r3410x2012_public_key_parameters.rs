//! RFC 9215 §4.2 `GostR3410-2012-PublicKeyParameters`.
//!
//! ```text
//! GostR3410-2012-PublicKeyParameters ::= SEQUENCE {
//!     publicKeyParamSet OBJECT IDENTIFIER,
//!     digestParamSet    OBJECT IDENTIFIER OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The curve and, optionally, the hash of a GOST R 34.10-2012 key.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GostR3410x2012PublicKeyParameters {
    public_key_param_set: Asn1Oid,
    digest_param_set: Option<Asn1Oid>,
}

impl GostR3410x2012PublicKeyParameters {
    /// The curve alone.
    /// Variable time: branches only on the encoding structure.
    pub fn new(public_key_param_set: Asn1Oid) -> Self {
        Self {
            public_key_param_set,
            digest_param_set: None,
        }
    }

    /// Sets the hash parameter set.
    /// Variable time: branches only on the encoding structure.
    pub fn with_digest_param_set(mut self, digest_param_set: Asn1Oid) -> Self {
        self.digest_param_set = Some(digest_param_set);
        self
    }

    /// Returns the curve.
    /// Variable time: branches only on the encoding structure.
    pub fn public_key_param_set(&self) -> &Asn1Oid {
        &self.public_key_param_set
    }

    /// Returns the hash parameter set, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn digest_param_set(&self) -> Option<&Asn1Oid> {
        self.digest_param_set.as_ref()
    }
}

impl DecodeContent for GostR3410x2012PublicKeyParameters {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let public_key_param_set = fields.get()?;
        let digest_param_set = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            public_key_param_set,
            digest_param_set,
        };
        Ok(value)
    }
}

impl DecodeInner for GostR3410x2012PublicKeyParameters {
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

impl EncodeContent for GostR3410x2012PublicKeyParameters {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.public_key_param_set.encoded_len(rules)
            + self
                .digest_param_set
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.public_key_param_set.encode(rules, out)?;
        if let Some(v) = &self.digest_param_set {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for GostR3410x2012PublicKeyParameters {}

impl Tagged for GostR3410x2012PublicKeyParameters {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for GostR3410x2012PublicKeyParameters {}

impl Encode for GostR3410x2012PublicKeyParameters {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
