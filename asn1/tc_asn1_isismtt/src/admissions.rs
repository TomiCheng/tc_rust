//! Common PKI `Admissions`, one admission of the holder.
//!
//! ```text
//! Admissions ::= SEQUENCE {
//!     admissionAuthority [0] EXPLICIT GeneralName     OPTIONAL,
//!     namingAuthority    [1] EXPLICIT NamingAuthority OPTIONAL,
//!     professionInfos    SEQUENCE OF ProfessionInfo }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::name::GeneralName;

use crate::{NamingAuthority, ProfessionInfo};

/// Who admitted the holder, who names the professions, and the professions.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Admissions {
    admission_authority: Option<GeneralName>,
    naming_authority: Option<NamingAuthority>,
    profession_infos: Asn1SequenceOf<ProfessionInfo>,
}

impl Admissions {
    /// The professions, without authorities.
    /// Variable time: branches only on the encoding structure.
    pub fn new(profession_infos: Vec<ProfessionInfo>) -> Self {
        Self {
            admission_authority: None,
            naming_authority: None,
            profession_infos: Asn1SequenceOf::new(profession_infos),
        }
    }

    /// Sets the admission authority.
    /// Variable time: branches only on the encoding structure.
    pub fn with_admission_authority(mut self, admission_authority: GeneralName) -> Self {
        self.admission_authority = Some(admission_authority);
        self
    }

    /// Sets the naming authority.
    /// Variable time: branches only on the encoding structure.
    pub fn with_naming_authority(mut self, naming_authority: NamingAuthority) -> Self {
        self.naming_authority = Some(naming_authority);
        self
    }

    /// Returns the admission authority, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn admission_authority(&self) -> Option<&GeneralName> {
        self.admission_authority.as_ref()
    }

    /// Returns the naming authority, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn naming_authority(&self) -> Option<&NamingAuthority> {
        self.naming_authority.as_ref()
    }

    /// Returns the professions.
    /// Variable time: branches only on the encoding structure.
    pub fn profession_infos(&self) -> &[ProfessionInfo] {
        self.profession_infos.elements()
    }
}

impl DecodeContent for Admissions {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let admission_authority = fields.get_explicit_opt::<GeneralName>([0xa0])?;
        let naming_authority = fields.get_explicit_opt::<NamingAuthority>([0xa1])?;
        let profession_infos = fields.get()?;
        fields.end()?;
        let value = Self {
            admission_authority,
            naming_authority,
            profession_infos,
        };
        Ok(value)
    }
}

impl DecodeInner for Admissions {
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

impl EncodeContent for Admissions {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.admission_authority
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .naming_authority
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
            + self.profession_infos.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.admission_authority {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.naming_authority {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        at += self.profession_infos.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for Admissions {}

impl Tagged for Admissions {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Admissions {}

impl Encode for Admissions {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
