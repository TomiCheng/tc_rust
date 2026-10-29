//! RFC 4211 §6.5 `CertId`, a certificate by issuer and serial number.
//!
//! ```text
//! CertId ::= SEQUENCE {
//!     issuer       GeneralName,
//!     serialNumber INTEGER }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::name::GeneralName;

/// A certificate by its issuer and serial number.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertId {
    issuer: GeneralName,
    serial_number: Asn1Integer,
}

impl CertId {
    /// The issuer and serial number.
    /// Variable time: branches only on the encoding structure.
    pub fn new(issuer: GeneralName, serial_number: Asn1Integer) -> Self {
        Self {
            issuer,
            serial_number,
        }
    }

    /// Returns the issuer.
    /// Variable time: branches only on the encoding structure.
    pub fn issuer(&self) -> &GeneralName {
        &self.issuer
    }

    /// Returns the serial number.
    /// Variable time: branches only on the encoding structure.
    pub fn serial_number(&self) -> &Asn1Integer {
        &self.serial_number
    }
}

impl DecodeContent for CertId {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let issuer = fields.get()?;
        let serial_number = fields.get()?;
        fields.end()?;
        let value = Self {
            issuer,
            serial_number,
        };
        Ok(value)
    }
}

impl DecodeInner for CertId {
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

impl EncodeContent for CertId {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.issuer.encoded_len(rules) + self.serial_number.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.issuer.encode(rules, out)?;
        at += self.serial_number.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for CertId {}

impl Tagged for CertId {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertId {}

impl Encode for CertId {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
