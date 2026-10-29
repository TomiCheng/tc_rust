//! RFC 4210 §5.3.15 `RevAnnContent`, a revocation announcement.
//!
//! ```text
//! RevAnnContent ::= SEQUENCE {
//!     status          PKIStatus,
//!     certId          CertId,
//!     willBeRevokedAt GeneralizedTime,
//!     badSinceDate    GeneralizedTime,
//!     crlDetails      Extensions OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::ext::Extensions;

use crate::PkiStatus;
use crate::crmf::CertId;

/// Which certificate is or will be revoked, and since when it is bad.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RevAnnContent {
    status: PkiStatus,
    cert_id: CertId,
    will_be_revoked_at: Asn1GeneralizedTime,
    bad_since_date: Asn1GeneralizedTime,
    crl_details: Option<Extensions>,
}

impl RevAnnContent {
    /// The announcement, without CRL details.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        status: PkiStatus,
        cert_id: CertId,
        will_be_revoked_at: Asn1GeneralizedTime,
        bad_since_date: Asn1GeneralizedTime,
    ) -> Self {
        Self {
            status,
            cert_id,
            will_be_revoked_at,
            bad_since_date,
            crl_details: None,
        }
    }

    /// Sets the CRL details.
    /// Variable time: branches only on the encoding structure.
    pub fn with_crl_details(mut self, crl_details: Extensions) -> Self {
        self.crl_details = Some(crl_details);
        self
    }

    /// Returns the status.
    /// Variable time: branches only on the encoding structure.
    pub fn status(&self) -> &PkiStatus {
        &self.status
    }

    /// Returns the certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_id(&self) -> &CertId {
        &self.cert_id
    }

    /// Returns when the revocation takes effect.
    /// Variable time: branches only on the encoding structure.
    pub fn will_be_revoked_at(&self) -> &Asn1GeneralizedTime {
        &self.will_be_revoked_at
    }

    /// Returns since when the certificate is bad.
    /// Variable time: branches only on the encoding structure.
    pub fn bad_since_date(&self) -> &Asn1GeneralizedTime {
        &self.bad_since_date
    }

    /// Returns the CRL details, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn crl_details(&self) -> Option<&Extensions> {
        self.crl_details.as_ref()
    }
}

impl DecodeContent for RevAnnContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let status = fields.get()?;
        let cert_id = fields.get()?;
        let will_be_revoked_at = fields.get()?;
        let bad_since_date = fields.get()?;
        let crl_details = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            status,
            cert_id,
            will_be_revoked_at,
            bad_since_date,
            crl_details,
        };
        Ok(value)
    }
}

impl DecodeInner for RevAnnContent {
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

impl EncodeContent for RevAnnContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.status.encoded_len(rules)
            + self.cert_id.encoded_len(rules)
            + self.will_be_revoked_at.encoded_len(rules)
            + self.bad_since_date.encoded_len(rules)
            + self
                .crl_details
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.status.encode(rules, out)?;
        at += self.cert_id.encode(rules, &mut out[at..])?;
        at += self.will_be_revoked_at.encode(rules, &mut out[at..])?;
        at += self.bad_since_date.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.crl_details {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for RevAnnContent {}

impl Tagged for RevAnnContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RevAnnContent {}

impl Encode for RevAnnContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
