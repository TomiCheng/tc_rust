//! RFC 2634 §5.4.1 `ESSCertID`, a certificate by its SHA-1 hash.
//!
//! ```text
//! ESSCertID ::= SEQUENCE {
//!     certHash     Hash,
//!     issuerSerial IssuerSerial OPTIONAL }
//! Hash ::= OCTET STRING -- SHA1 hash of entire certificate
//! ```

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::attr::IssuerSerial;

/// The SHA-1 hash of a whole certificate and, optionally, its issuer and serial.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EssCertId {
    cert_hash: Asn1OctetString,
    issuer_serial: Option<IssuerSerial>,
}

impl EssCertId {
    /// The certificate hash, without the issuer and serial.
    /// Variable time: branches only on the encoding structure.
    pub fn new(cert_hash: Asn1OctetString) -> Self {
        Self {
            cert_hash,
            issuer_serial: None,
        }
    }

    /// Sets the issuer and serial.
    /// Variable time: branches only on the encoding structure.
    pub fn with_issuer_serial(mut self, issuer_serial: IssuerSerial) -> Self {
        self.issuer_serial = Some(issuer_serial);
        self
    }

    /// Returns the SHA-1 hash of the certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_hash(&self) -> &Asn1OctetString {
        &self.cert_hash
    }

    /// Returns the issuer and serial, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn issuer_serial(&self) -> Option<&IssuerSerial> {
        self.issuer_serial.as_ref()
    }
}

impl DecodeContent for EssCertId {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let cert_hash = fields.get()?;
        let issuer_serial = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            cert_hash,
            issuer_serial,
        };
        Ok(value)
    }
}

impl DecodeInner for EssCertId {
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

impl EncodeContent for EssCertId {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.cert_hash.encoded_len(rules)
            + self
                .issuer_serial
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.cert_hash.encode(rules, out)?;
        if let Some(v) = &self.issuer_serial {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for EssCertId {}

impl Tagged for EssCertId {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for EssCertId {}

impl Encode for EssCertId {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
