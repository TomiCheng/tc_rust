//! RFC 5652 §10.2.2 `OtherCertificateFormat`.
//!
//! ```text
//! OtherCertificateFormat ::= SEQUENCE {
//!     otherCertFormat OBJECT IDENTIFIER,
//!     otherCert ANY DEFINED BY otherCertFormat }
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// A certificate in a format CMS does not name, kept as the octets it was read
/// with.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OtherCertificateFormat {
    format: Asn1Oid,
    certificate: Asn1Any,
}

impl OtherCertificateFormat {
    /// Stores the format identifier and the certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn new(format: Asn1Oid, certificate: Asn1Any) -> Self {
        Self {
            format,
            certificate,
        }
    }

    /// Returns the format identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn format(&self) -> &Asn1Oid {
        &self.format
    }

    /// Returns the certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn certificate(&self) -> &Asn1Any {
        &self.certificate
    }
}

impl DecodeContent for OtherCertificateFormat {
    /// The two fields, as under `30` on its own or `A3` in `CertificateChoices`.
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let format = fields.get()?;
        let certificate = fields.get()?;
        fields.end()?;
        Ok(Self::new(format, certificate))
    }
}

impl DecodeInner for OtherCertificateFormat {
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

impl EncodeContent for OtherCertificateFormat {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.format.encoded_len(rules) + self.certificate.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let at = self.format.encode(rules, out)?;
        Ok(at + self.certificate.encode(rules, &mut out[at..])?)
    }
}

impl Decode for OtherCertificateFormat {}

impl Tagged for OtherCertificateFormat {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OtherCertificateFormat {}

impl Encode for OtherCertificateFormat {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
