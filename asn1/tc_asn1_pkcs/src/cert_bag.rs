//! RFC 7292 4.2.3 `CertBag`, a certificate in a PKCS #12 safe bag.
//!
//! ```text
//! CertBag ::= SEQUENCE {
//!     certId    BAG-TYPE.&id ({CertTypes}),
//!     certValue [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId}) }
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

/// The certificate type and the certificate, kept as the octets it was read with: an
/// X.509 certificate is an OCTET STRING holding its DER.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertBag {
    cert_id: Asn1Oid,
    cert_value: Asn1Any,
}

impl CertBag {
    /// The certificate type and the certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn new(cert_id: Asn1Oid, cert_value: Asn1Any) -> Self {
        Self {
            cert_id,
            cert_value,
        }
    }

    /// Returns the certificate type, such as `x509Certificate`.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_id(&self) -> &Asn1Oid {
        &self.cert_id
    }

    /// Returns the certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_value(&self) -> &Asn1Any {
        &self.cert_value
    }
}

impl DecodeContent for CertBag {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let cert_id = fields.get()?;
        let cert_value = fields.get_explicit::<Asn1Any>([0xa0])?;
        fields.end()?;
        let value = Self {
            cert_id,
            cert_value,
        };
        Ok(value)
    }
}

impl DecodeInner for CertBag {
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

impl EncodeContent for CertBag {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.cert_id.encoded_len(rules)
            + Explicit::new(&[0xa0], &self.cert_value).encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.cert_id.encode(rules, out)?;
        at += Explicit::new(&[0xa0], &self.cert_value).encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for CertBag {}

impl Tagged for CertBag {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertBag {}

impl Encode for CertBag {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
