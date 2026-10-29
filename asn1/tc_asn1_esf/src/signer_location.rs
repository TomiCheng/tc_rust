//! RFC 5126 §5.11.2 `SignerLocation`, the value of the signer-location attribute.
//!
//! ```text
//! SignerLocation ::= SEQUENCE {
//!     countryName   [0] DirectoryString OPTIONAL,
//!     localityName  [1] DirectoryString OPTIONAL,
//!     postalAdddress [2] PostalAddress  OPTIONAL }
//! PostalAddress ::= SEQUENCE SIZE (1..6) OF DirectoryString
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x500::DirectoryString;

/// Where the signer says it signed: country, locality and a postal address of
/// one to six lines.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct SignerLocation {
    country_name: Option<DirectoryString>,
    locality_name: Option<DirectoryString>,
    postal_address: Option<Asn1SequenceOf<DirectoryString>>,
}

impl SignerLocation {
    /// A location with every field absent.
    /// Variable time: branches only on the encoding structure.
    pub fn new() -> Self {
        Self {
            country_name: None,
            locality_name: None,
            postal_address: None,
        }
    }

    /// Sets the country.
    /// Variable time: branches only on the encoding structure.
    pub fn with_country_name(mut self, country_name: DirectoryString) -> Self {
        self.country_name = Some(country_name);
        self
    }

    /// Sets the locality.
    /// Variable time: branches only on the encoding structure.
    pub fn with_locality_name(mut self, locality_name: DirectoryString) -> Self {
        self.locality_name = Some(locality_name);
        self
    }

    /// Sets the postal address; other than one to six lines is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn with_postal_address(
        mut self,
        postal_address: Vec<DirectoryString>,
    ) -> Result<Self, Asn1Error> {
        self.postal_address = Some(postal_lines(Asn1SequenceOf::new(postal_address))?);
        Ok(self)
    }

    /// Returns the country, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn country_name(&self) -> Option<&DirectoryString> {
        self.country_name.as_ref()
    }

    /// Returns the locality, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn locality_name(&self) -> Option<&DirectoryString> {
        self.locality_name.as_ref()
    }

    /// Returns the postal address lines, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn postal_address(&self) -> Option<&[DirectoryString]> {
        self.postal_address.as_ref().map(Asn1SequenceOf::elements)
    }
}

/// `MalformedValue` outside `SIZE (1..6)`.
fn postal_lines(
    lines: Asn1SequenceOf<DirectoryString>,
) -> Result<Asn1SequenceOf<DirectoryString>, Asn1Error> {
    if (1..=6).contains(&lines.elements().len()) {
        Ok(lines)
    } else {
        Err(Asn1Error::MalformedValue)
    }
}

impl DecodeContent for SignerLocation {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let country_name = fields.get_explicit_opt::<DirectoryString>([0xa0])?;
        let locality_name = fields.get_explicit_opt::<DirectoryString>([0xa1])?;
        let postal_address = fields
            .get_explicit_opt::<Asn1SequenceOf<DirectoryString>>([0xa2])?
            .map(postal_lines)
            .transpose()?;
        fields.end()?;
        let value = Self {
            country_name,
            locality_name,
            postal_address,
        };
        Ok(value)
    }
}

impl DecodeInner for SignerLocation {
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

impl EncodeContent for SignerLocation {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.country_name
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .locality_name
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
            + self
                .postal_address
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa2], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.country_name {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.locality_name {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.postal_address {
            at += Explicit::new(&[0xa2], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for SignerLocation {}

impl Tagged for SignerLocation {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SignerLocation {}

impl Encode for SignerLocation {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
