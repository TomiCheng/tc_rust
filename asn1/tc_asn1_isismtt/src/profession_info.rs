//! Common PKI `ProfessionInfo`, one profession of the holder.
//!
//! ```text
//! ProfessionInfo ::= SEQUENCE {
//!     namingAuthority    [0] EXPLICIT NamingAuthority OPTIONAL,
//!     professionItems    SEQUENCE OF DirectoryString (SIZE(1..128)),
//!     professionOIDs     SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
//!     registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
//!     addProfessionInfo  OCTET STRING OPTIONAL }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Oid, Asn1PrintableString, Asn1Ref, Asn1SequenceOf, Children,
    Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x500::DirectoryString;

use crate::NamingAuthority;

/// The professions, who names them, and the holder's registration.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ProfessionInfo {
    naming_authority: Option<NamingAuthority>,
    profession_items: Asn1SequenceOf<DirectoryString>,
    profession_oids: Option<Asn1SequenceOf<Asn1Oid>>,
    registration_number: Option<Asn1PrintableString>,
    add_profession_info: Option<Asn1OctetString>,
}

impl ProfessionInfo {
    /// The professions, with every option absent.
    /// Variable time: branches only on the encoding structure.
    pub fn new(profession_items: Vec<DirectoryString>) -> Self {
        Self {
            naming_authority: None,
            profession_items: Asn1SequenceOf::new(profession_items),
            profession_oids: None,
            registration_number: None,
            add_profession_info: None,
        }
    }

    /// Sets the naming authority.
    /// Variable time: branches only on the encoding structure.
    pub fn with_naming_authority(mut self, naming_authority: NamingAuthority) -> Self {
        self.naming_authority = Some(naming_authority);
        self
    }

    /// Sets the professions by identifier, in the order of the text.
    /// Variable time: branches only on the encoding structure.
    pub fn with_profession_oids(mut self, profession_oids: Vec<Asn1Oid>) -> Self {
        self.profession_oids = Some(Asn1SequenceOf::new(profession_oids));
        self
    }

    /// Sets the registration number.
    /// Variable time: branches only on the encoding structure.
    pub fn with_registration_number(mut self, registration_number: Asn1PrintableString) -> Self {
        self.registration_number = Some(registration_number);
        self
    }

    /// Sets additional information.
    /// Variable time: branches only on the encoding structure.
    pub fn with_add_profession_info(mut self, add_profession_info: Asn1OctetString) -> Self {
        self.add_profession_info = Some(add_profession_info);
        self
    }

    /// Returns the naming authority, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn naming_authority(&self) -> Option<&NamingAuthority> {
        self.naming_authority.as_ref()
    }

    /// Returns the professions in text.
    /// Variable time: branches only on the encoding structure.
    pub fn profession_items(&self) -> &[DirectoryString] {
        self.profession_items.elements()
    }

    /// Returns the professions by identifier, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn profession_oids(&self) -> Option<&[Asn1Oid]> {
        self.profession_oids.as_ref().map(Asn1SequenceOf::elements)
    }

    /// Returns the registration number, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn registration_number(&self) -> Option<&Asn1PrintableString> {
        self.registration_number.as_ref()
    }

    /// Returns additional information, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn add_profession_info(&self) -> Option<&Asn1OctetString> {
        self.add_profession_info.as_ref()
    }
}

impl DecodeContent for ProfessionInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let naming_authority = fields.get_explicit_opt::<NamingAuthority>([0xa0])?;
        let profession_items = fields.get()?;
        let profession_oids = fields.get_opt()?;
        let registration_number = fields.get_opt()?;
        let add_profession_info = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            naming_authority,
            profession_items,
            profession_oids,
            registration_number,
            add_profession_info,
        };
        Ok(value)
    }
}

impl DecodeInner for ProfessionInfo {
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

impl EncodeContent for ProfessionInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.naming_authority
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self.profession_items.encoded_len(rules)
            + self
                .profession_oids
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
            + self
                .registration_number
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
            + self
                .add_profession_info
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.naming_authority {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        at += self.profession_items.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.profession_oids {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.registration_number {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.add_profession_info {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for ProfessionInfo {}

impl Tagged for ProfessionInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ProfessionInfo {}

impl Encode for ProfessionInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
