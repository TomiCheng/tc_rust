//! RFC 5126 §5.7.4.1 `CrlValidatedID`, a CRL by its hash.
//!
//! ```text
//! CrlValidatedID ::= SEQUENCE {
//!     crlHash       OtherHash,
//!     crlIdentifier CrlIdentifier OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::{CrlIdentifier, OtherHash};

/// The hash of a whole CRL and, optionally, what identifies it.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CrlValidatedId {
    crl_hash: OtherHash,
    crl_identifier: Option<CrlIdentifier>,
}

impl CrlValidatedId {
    /// The CRL hash, without an identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn new(crl_hash: OtherHash) -> Self {
        Self {
            crl_hash,
            crl_identifier: None,
        }
    }

    /// Sets the identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn with_crl_identifier(mut self, crl_identifier: CrlIdentifier) -> Self {
        self.crl_identifier = Some(crl_identifier);
        self
    }

    /// Returns the hash of the CRL.
    /// Variable time: branches only on the encoding structure.
    pub fn crl_hash(&self) -> &OtherHash {
        &self.crl_hash
    }

    /// Returns the identifier, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn crl_identifier(&self) -> Option<&CrlIdentifier> {
        self.crl_identifier.as_ref()
    }
}

impl DecodeContent for CrlValidatedId {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let crl_hash = fields.get()?;
        let crl_identifier = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            crl_hash,
            crl_identifier,
        };
        Ok(value)
    }
}

impl DecodeInner for CrlValidatedId {
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

impl EncodeContent for CrlValidatedId {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.crl_hash.encoded_len(rules)
            + self
                .crl_identifier
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.crl_hash.encode(rules, out)?;
        if let Some(v) = &self.crl_identifier {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CrlValidatedId {}

impl Tagged for CrlValidatedId {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CrlValidatedId {}

impl Encode for CrlValidatedId {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
