//! RFC 5126 §5.11.1 `CommitmentTypeIndication`, the value of the commitment-type-indication
//! attribute: what the signer commits to.
//!
//! ```text
//! CommitmentTypeIndication ::= SEQUENCE {
//!     commitmentTypeId        CommitmentTypeIdentifier,
//!     commitmentTypeQualifier SEQUENCE SIZE (1..MAX) OF CommitmentTypeQualifier OPTIONAL }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::CommitmentTypeQualifier;

/// The commitment, such as proof of origin, and qualifiers on it.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CommitmentTypeIndication {
    commitment_type_id: Asn1Oid,
    commitment_type_qualifier: Option<Asn1SequenceOf<CommitmentTypeQualifier>>,
}

impl CommitmentTypeIndication {
    /// The commitment, without qualifiers.
    /// Variable time: branches only on the encoding structure.
    pub fn new(commitment_type_id: Asn1Oid) -> Self {
        Self {
            commitment_type_id,
            commitment_type_qualifier: None,
        }
    }

    /// Sets the qualifiers.
    /// Variable time: branches only on the encoding structure.
    pub fn with_commitment_type_qualifier(
        mut self,
        commitment_type_qualifier: Vec<CommitmentTypeQualifier>,
    ) -> Self {
        self.commitment_type_qualifier = Some(Asn1SequenceOf::new(commitment_type_qualifier));
        self
    }

    /// Returns the commitment, often a `CommitmentTypeIdentifier`.
    /// Variable time: branches only on the encoding structure.
    pub fn commitment_type_id(&self) -> &Asn1Oid {
        &self.commitment_type_id
    }

    /// Returns the qualifiers, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn commitment_type_qualifier(&self) -> Option<&[CommitmentTypeQualifier]> {
        self.commitment_type_qualifier
            .as_ref()
            .map(Asn1SequenceOf::elements)
    }
}

impl DecodeContent for CommitmentTypeIndication {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let commitment_type_id = fields.get()?;
        let commitment_type_qualifier = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            commitment_type_id,
            commitment_type_qualifier,
        };
        Ok(value)
    }
}

impl DecodeInner for CommitmentTypeIndication {
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

impl EncodeContent for CommitmentTypeIndication {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.commitment_type_id.encoded_len(rules)
            + self
                .commitment_type_qualifier
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.commitment_type_id.encode(rules, out)?;
        if let Some(v) = &self.commitment_type_qualifier {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CommitmentTypeIndication {}

impl Tagged for CommitmentTypeIndication {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CommitmentTypeIndication {}

impl Encode for CommitmentTypeIndication {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
