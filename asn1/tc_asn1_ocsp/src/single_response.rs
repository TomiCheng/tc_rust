//! RFC 6960 §4.2.1 `SingleResponse`, the status of one certificate.
//!
//! ```text
//! SingleResponse ::= SEQUENCE {
//!     certID           CertID,
//!     certStatus       CertStatus,
//!     thisUpdate       GeneralizedTime,
//!     nextUpdate       [0] EXPLICIT GeneralizedTime OPTIONAL,
//!     singleExtensions [1] EXPLICIT Extensions OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::ext::Extensions;

use crate::{CertId, CertStatus};

/// A certificate, its status, and the interval the status is good for.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SingleResponse {
    cert_id: CertId,
    cert_status: CertStatus,
    this_update: Asn1GeneralizedTime,
    next_update: Option<Asn1GeneralizedTime>,
    single_extensions: Option<Extensions>,
}

impl SingleResponse {
    /// The certificate, its status and when the status was known correct.
    /// Variable time: branches only on the encoding structure.
    pub fn new(cert_id: CertId, cert_status: CertStatus, this_update: Asn1GeneralizedTime) -> Self {
        Self {
            cert_id,
            cert_status,
            this_update,
            next_update: None,
            single_extensions: None,
        }
    }

    /// Sets when newer status will be available.
    /// Variable time: branches only on the encoding structure.
    pub fn with_next_update(mut self, next_update: Asn1GeneralizedTime) -> Self {
        self.next_update = Some(next_update);
        self
    }

    /// Sets the extensions of this response, such as a CRL reference.
    /// Variable time: branches only on the encoding structure.
    pub fn with_single_extensions(mut self, single_extensions: Extensions) -> Self {
        self.single_extensions = Some(single_extensions);
        self
    }

    /// Returns the certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_id(&self) -> &CertId {
        &self.cert_id
    }

    /// Returns the status.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_status(&self) -> &CertStatus {
        &self.cert_status
    }

    /// Returns when the status was known correct.
    /// Variable time: branches only on the encoding structure.
    pub fn this_update(&self) -> &Asn1GeneralizedTime {
        &self.this_update
    }

    /// Returns when newer status will be available, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn next_update(&self) -> Option<&Asn1GeneralizedTime> {
        self.next_update.as_ref()
    }

    /// Returns the extensions of this response, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn single_extensions(&self) -> Option<&Extensions> {
        self.single_extensions.as_ref()
    }
}

impl DecodeContent for SingleResponse {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let cert_id = fields.get()?;
        let cert_status = fields.get()?;
        let this_update = fields.get()?;
        let next_update = fields.get_explicit_opt::<Asn1GeneralizedTime>([0xa0])?;
        let single_extensions = fields.get_explicit_opt::<Extensions>([0xa1])?;
        fields.end()?;
        let value = Self {
            cert_id,
            cert_status,
            this_update,
            next_update,
            single_extensions,
        };
        Ok(value)
    }
}

impl DecodeInner for SingleResponse {
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

impl EncodeContent for SingleResponse {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.cert_id.encoded_len(rules)
            + self.cert_status.encoded_len(rules)
            + self.this_update.encoded_len(rules)
            + self
                .next_update
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self
                .single_extensions
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.cert_id.encode(rules, out)?;
        at += self.cert_status.encode(rules, &mut out[at..])?;
        at += self.this_update.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.next_update {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.single_extensions {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for SingleResponse {}

impl Tagged for SingleResponse {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for SingleResponse {}

impl Encode for SingleResponse {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
