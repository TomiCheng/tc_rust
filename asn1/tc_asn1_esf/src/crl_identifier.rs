//! RFC 5126 §5.7.4.1 `CrlIdentifier`, a CRL by issuer, time and number.
//!
//! ```text
//! CrlIdentifier ::= SEQUENCE {
//!     crlissuer     Name,
//!     crlIssuedTime UTCTime,
//!     crlNumber     INTEGER OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Asn1UtcTime, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x500::Name;

/// The CRL's issuer, when it was issued, and its number.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CrlIdentifier {
    crl_issuer: Name,
    crl_issued_time: Asn1UtcTime,
    crl_number: Option<Asn1Integer>,
}

impl CrlIdentifier {
    /// The issuer and issue time, without a number.
    /// Variable time: branches only on the encoding structure.
    pub fn new(crl_issuer: Name, crl_issued_time: Asn1UtcTime) -> Self {
        Self {
            crl_issuer,
            crl_issued_time,
            crl_number: None,
        }
    }

    /// Sets the CRL number.
    /// Variable time: branches only on the encoding structure.
    pub fn with_crl_number(mut self, crl_number: Asn1Integer) -> Self {
        self.crl_number = Some(crl_number);
        self
    }

    /// Returns the issuer of the CRL.
    /// Variable time: branches only on the encoding structure.
    pub fn crl_issuer(&self) -> &Name {
        &self.crl_issuer
    }

    /// Returns when the CRL was issued.
    /// Variable time: branches only on the encoding structure.
    pub fn crl_issued_time(&self) -> &Asn1UtcTime {
        &self.crl_issued_time
    }

    /// Returns the CRL number, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn crl_number(&self) -> Option<&Asn1Integer> {
        self.crl_number.as_ref()
    }
}

impl DecodeContent for CrlIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let crl_issuer = fields.get()?;
        let crl_issued_time = fields.get()?;
        let crl_number = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            crl_issuer,
            crl_issued_time,
            crl_number,
        };
        Ok(value)
    }
}

impl DecodeInner for CrlIdentifier {
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

impl EncodeContent for CrlIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.crl_issuer.encoded_len(rules)
            + self.crl_issued_time.encoded_len(rules)
            + self.crl_number.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.crl_issuer.encode(rules, out)?;
        at += self.crl_issued_time.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.crl_number {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CrlIdentifier {}

impl Tagged for CrlIdentifier {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CrlIdentifier {}

impl Encode for CrlIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
