//! RFC 5126 §5.11.1 `CommitmentTypeQualifier`, a qualifier of a commitment
//! type.
//!
//! ```text
//! CommitmentTypeQualifier ::= SEQUENCE {
//!     commitmentTypeIdentifier CommitmentTypeIdentifier,
//!     qualifier                ANY DEFINED BY commitmentTypeIdentifier OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// A qualifier type and, optionally, its value, kept as found.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CommitmentTypeQualifier {
    commitment_type_identifier: Asn1Oid,
    qualifier: Option<Asn1Any>,
}

impl CommitmentTypeQualifier {
    /// A qualifier without a value.
    /// Variable time: branches only on the encoding structure.
    pub fn new(commitment_type_identifier: Asn1Oid) -> Self {
        Self {
            commitment_type_identifier,
            qualifier: None,
        }
    }

    /// Sets the value.
    /// Variable time: branches only on the encoding structure.
    pub fn with_qualifier(mut self, qualifier: Asn1Any) -> Self {
        self.qualifier = Some(qualifier);
        self
    }

    /// Returns the type of the qualifier.
    /// Variable time: branches only on the encoding structure.
    pub fn commitment_type_identifier(&self) -> &Asn1Oid {
        &self.commitment_type_identifier
    }

    /// Returns the value, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn qualifier(&self) -> Option<&Asn1Any> {
        self.qualifier.as_ref()
    }
}

impl DecodeContent for CommitmentTypeQualifier {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let commitment_type_identifier = fields.get()?;
        let qualifier = fields.get_any_opt()?;
        fields.end()?;
        let value = Self {
            commitment_type_identifier,
            qualifier,
        };
        Ok(value)
    }
}

impl DecodeInner for CommitmentTypeQualifier {
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

impl EncodeContent for CommitmentTypeQualifier {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.commitment_type_identifier.encoded_len(rules)
            + self.qualifier.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.commitment_type_identifier.encode(rules, out)?;
        if let Some(v) = &self.qualifier {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CommitmentTypeQualifier {}

impl Tagged for CommitmentTypeQualifier {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CommitmentTypeQualifier {}

impl Encode for CommitmentTypeQualifier {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
