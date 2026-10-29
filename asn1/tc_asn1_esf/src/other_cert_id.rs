//! RFC 5126 §5.7.3.3 `OtherCertID`, a certificate by a hash under any
//! algorithm.
//!
//! ```text
//! OtherCertID ::= SEQUENCE {
//!     otherCertHash OtherHash,
//!     issuerSerial  IssuerSerial OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::attr::IssuerSerial;

use crate::OtherHash;

/// The hash of a whole certificate and, optionally, its issuer and serial.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OtherCertId {
    other_cert_hash: OtherHash,
    issuer_serial: Option<IssuerSerial>,
}

impl OtherCertId {
    /// The certificate hash, without the issuer and serial.
    /// Variable time: branches only on the encoding structure.
    pub fn new(other_cert_hash: OtherHash) -> Self {
        Self {
            other_cert_hash,
            issuer_serial: None,
        }
    }

    /// Sets the issuer and serial.
    /// Variable time: branches only on the encoding structure.
    pub fn with_issuer_serial(mut self, issuer_serial: IssuerSerial) -> Self {
        self.issuer_serial = Some(issuer_serial);
        self
    }

    /// Returns the hash of the certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn other_cert_hash(&self) -> &OtherHash {
        &self.other_cert_hash
    }

    /// Returns the issuer and serial, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn issuer_serial(&self) -> Option<&IssuerSerial> {
        self.issuer_serial.as_ref()
    }
}

impl DecodeContent for OtherCertId {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let other_cert_hash = fields.get()?;
        let issuer_serial = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            other_cert_hash,
            issuer_serial,
        };
        Ok(value)
    }
}

impl DecodeInner for OtherCertId {
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

impl EncodeContent for OtherCertId {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.other_cert_hash.encoded_len(rules)
            + self
                .issuer_serial
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.other_cert_hash.encode(rules, out)?;
        if let Some(v) = &self.issuer_serial {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for OtherCertId {}

impl Tagged for OtherCertId {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OtherCertId {}

impl Encode for OtherCertId {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
