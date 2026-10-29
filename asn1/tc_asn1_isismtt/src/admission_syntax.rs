//! Common PKI `AdmissionSyntax`, the value of the admission attribute.
//!
//! ```text
//! AdmissionSyntax ::= SEQUENCE {
//!     admissionAuthority   GeneralName OPTIONAL,
//!     contentsOfAdmissions SEQUENCE OF Admissions }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::name::GeneralName;

use crate::Admissions;

/// The default admission authority and the admissions.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AdmissionSyntax {
    admission_authority: Option<GeneralName>,
    contents_of_admissions: Asn1SequenceOf<Admissions>,
}

impl AdmissionSyntax {
    /// The admissions, without a default authority.
    /// Variable time: branches only on the encoding structure.
    pub fn new(contents_of_admissions: Vec<Admissions>) -> Self {
        Self {
            admission_authority: None,
            contents_of_admissions: Asn1SequenceOf::new(contents_of_admissions),
        }
    }

    /// Sets the default admission authority.
    /// Variable time: branches only on the encoding structure.
    pub fn with_admission_authority(mut self, admission_authority: GeneralName) -> Self {
        self.admission_authority = Some(admission_authority);
        self
    }

    /// Returns the default admission authority, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn admission_authority(&self) -> Option<&GeneralName> {
        self.admission_authority.as_ref()
    }

    /// Returns the admissions.
    /// Variable time: branches only on the encoding structure.
    pub fn contents_of_admissions(&self) -> &[Admissions] {
        self.contents_of_admissions.elements()
    }
}

impl DecodeContent for AdmissionSyntax {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let admission_authority = match fields.peek() {
            Some(Ok(element))
                if matches!(
                    element.tag(),
                    [0xa0] | [0x81] | [0x82] | [0xa3] | [0xa4] | [0xa5] | [0x86] | [0x87] | [0x88]
                ) =>
            {
                Some(fields.get()?)
            }
            Some(Err(error)) => return Err(error),
            _ => None,
        };
        let contents_of_admissions = fields.get()?;
        fields.end()?;
        let value = Self {
            admission_authority,
            contents_of_admissions,
        };
        Ok(value)
    }
}

impl DecodeInner for AdmissionSyntax {
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

impl EncodeContent for AdmissionSyntax {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.admission_authority
            .as_ref()
            .map_or(0, |v| v.encoded_len(rules))
            + self.contents_of_admissions.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.admission_authority {
            at += v.encode(rules, &mut out[at..])?;
        }
        at += self.contents_of_admissions.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for AdmissionSyntax {}

impl Tagged for AdmissionSyntax {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for AdmissionSyntax {}

impl Encode for AdmissionSyntax {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
