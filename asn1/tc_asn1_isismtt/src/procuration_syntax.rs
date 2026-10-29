//! Common PKI `ProcurationSyntax`, the value of the procuration attribute.
//!
//! ```text
//! ProcurationSyntax ::= SEQUENCE {
//!     country            [1] EXPLICIT PrintableString(SIZE(2)) OPTIONAL,
//!     typeOfSubstitution [2] EXPLICIT DirectoryString (SIZE(1..128)) OPTIONAL,
//!     signingFor         [3] EXPLICIT SigningFor }
//! ```

use tc_asn1::{
    Asn1Error, Asn1PrintableString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x500::DirectoryString;

use crate::SigningFor;

/// Whom the holder may sign for, in which country, and how.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ProcurationSyntax {
    country: Option<Asn1PrintableString>,
    type_of_substitution: Option<DirectoryString>,
    signing_for: SigningFor,
}

impl ProcurationSyntax {
    /// The person signed for, with the country and type absent.
    /// Variable time: branches only on the encoding structure.
    pub fn new(signing_for: SigningFor) -> Self {
        Self {
            country: None,
            type_of_substitution: None,
            signing_for,
        }
    }

    /// Sets the country.
    /// Variable time: branches only on the encoding structure.
    pub fn with_country(mut self, country: Asn1PrintableString) -> Self {
        self.country = Some(country);
        self
    }

    /// Sets the type of substitution.
    /// Variable time: branches only on the encoding structure.
    pub fn with_type_of_substitution(mut self, type_of_substitution: DirectoryString) -> Self {
        self.type_of_substitution = Some(type_of_substitution);
        self
    }

    /// Returns the country, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn country(&self) -> Option<&Asn1PrintableString> {
        self.country.as_ref()
    }

    /// Returns the type of substitution, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn type_of_substitution(&self) -> Option<&DirectoryString> {
        self.type_of_substitution.as_ref()
    }

    /// Returns the person signed for.
    /// Variable time: branches only on the encoding structure.
    pub fn signing_for(&self) -> &SigningFor {
        &self.signing_for
    }
}

impl DecodeContent for ProcurationSyntax {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let country = fields.get_explicit_opt::<Asn1PrintableString>([0xa1])?;
        let type_of_substitution = fields.get_explicit_opt::<DirectoryString>([0xa2])?;
        let signing_for = fields.get_explicit::<SigningFor>([0xa3])?;
        fields.end()?;
        let value = Self {
            country,
            type_of_substitution,
            signing_for,
        };
        Ok(value)
    }
}

impl DecodeInner for ProcurationSyntax {
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

impl EncodeContent for ProcurationSyntax {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.country
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
            + self
                .type_of_substitution
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa2], v).encoded_len(rules))
            + Explicit::new(&[0xa3], &self.signing_for).encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.country {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.type_of_substitution {
            at += Explicit::new(&[0xa2], v).encode(rules, &mut out[at..])?;
        }
        at += Explicit::new(&[0xa3], &self.signing_for).encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for ProcurationSyntax {}

impl Tagged for ProcurationSyntax {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ProcurationSyntax {}

impl Encode for ProcurationSyntax {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
