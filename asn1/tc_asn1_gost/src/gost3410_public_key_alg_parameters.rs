//! The parameters of a GOST R 34.10 public key, in the form that covers both
//! the 2001 (RFC 4491) and 2012 (RFC 9215) variants.
//!
//! ```text
//! SEQUENCE {
//!     publicKeyParamSet  OBJECT IDENTIFIER,
//!     digestParamSet     OBJECT IDENTIFIER OPTIONAL,
//!     encryptionParamSet OBJECT IDENTIFIER OPTIONAL }
//! ```
//!
//! Two untagged OPTIONAL identifiers in a row cannot be told apart, so a second
//! element is always `digestParamSet`, as in Bouncy Castle, and
//! `encryptionParamSet` is written only when `digestParamSet` is present.

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The curve or group, the hash, and the S-box parameter set.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Gost3410PublicKeyAlgParameters {
    public_key_param_set: Asn1Oid,
    digest_param_set: Option<Asn1Oid>,
    encryption_param_set: Option<Asn1Oid>,
}

impl Gost3410PublicKeyAlgParameters {
    /// The public key parameter set alone.
    /// Variable time: branches only on the encoding structure.
    pub fn new(public_key_param_set: Asn1Oid) -> Self {
        Self {
            public_key_param_set,
            digest_param_set: None,
            encryption_param_set: None,
        }
    }

    /// Sets the hash parameter set.
    /// Variable time: branches only on the encoding structure.
    pub fn with_digest_param_set(mut self, digest_param_set: Asn1Oid) -> Self {
        self.digest_param_set = Some(digest_param_set);
        self
    }

    /// Sets the S-box parameter set; it is written only after a hash parameter set.
    /// Variable time: branches only on the encoding structure.
    pub fn with_encryption_param_set(mut self, encryption_param_set: Asn1Oid) -> Self {
        self.encryption_param_set = Some(encryption_param_set);
        self
    }

    /// Returns the curve or group.
    /// Variable time: branches only on the encoding structure.
    pub fn public_key_param_set(&self) -> &Asn1Oid {
        &self.public_key_param_set
    }

    /// Returns the hash parameter set, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn digest_param_set(&self) -> Option<&Asn1Oid> {
        self.digest_param_set.as_ref()
    }

    /// Returns the S-box parameter set, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn encryption_param_set(&self) -> Option<&Asn1Oid> {
        self.encryption_param_set.as_ref()
    }
}

impl Gost3410PublicKeyAlgParameters {
    fn written_encryption_param_set(&self) -> Option<&Asn1Oid> {
        self.digest_param_set
            .as_ref()
            .and(self.encryption_param_set.as_ref())
    }
}

impl DecodeContent for Gost3410PublicKeyAlgParameters {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let public_key_param_set = fields.get()?;
        let digest_param_set = fields.get_opt()?;
        let encryption_param_set = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            public_key_param_set,
            digest_param_set,
            encryption_param_set,
        };
        Ok(value)
    }
}

impl DecodeInner for Gost3410PublicKeyAlgParameters {
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

impl EncodeContent for Gost3410PublicKeyAlgParameters {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.public_key_param_set.encoded_len(rules)
            + self
                .digest_param_set
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
            + self
                .written_encryption_param_set()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.public_key_param_set.encode(rules, out)?;
        if let Some(v) = &self.digest_param_set {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = self.written_encryption_param_set() {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for Gost3410PublicKeyAlgParameters {}

impl Tagged for Gost3410PublicKeyAlgParameters {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Gost3410PublicKeyAlgParameters {}

impl Encode for Gost3410PublicKeyAlgParameters {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
