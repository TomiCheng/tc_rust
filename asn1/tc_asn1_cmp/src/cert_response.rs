//! RFC 4210 §5.3.4 `CertResponse`, the answer to one certificate request.
//!
//! ```text
//! CertResponse ::= SEQUENCE {
//!     certReqId        INTEGER,
//!     status           PKIStatusInfo,
//!     certifiedKeyPair CertifiedKeyPair OPTIONAL,
//!     rspInfo          OCTET STRING     OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::{CertifiedKeyPair, PkiStatusInfo};

/// The request identifier, the status, and the certificate when granted.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertResponse {
    cert_req_id: Asn1Integer,
    status: PkiStatusInfo,
    certified_key_pair: Option<CertifiedKeyPair>,
    rsp_info: Option<Asn1OctetString>,
}

impl CertResponse {
    /// The identifier and status, without a certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn new(cert_req_id: Asn1Integer, status: PkiStatusInfo) -> Self {
        Self {
            cert_req_id,
            status,
            certified_key_pair: None,
            rsp_info: None,
        }
    }

    /// Sets the certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn with_certified_key_pair(mut self, certified_key_pair: CertifiedKeyPair) -> Self {
        self.certified_key_pair = Some(certified_key_pair);
        self
    }

    /// Sets extra information.
    /// Variable time: branches only on the encoding structure.
    pub fn with_rsp_info(mut self, rsp_info: Asn1OctetString) -> Self {
        self.rsp_info = Some(rsp_info);
        self
    }

    /// Returns the identifier of the request answered.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_req_id(&self) -> &Asn1Integer {
        &self.cert_req_id
    }

    /// Returns the status.
    /// Variable time: branches only on the encoding structure.
    pub fn status(&self) -> &PkiStatusInfo {
        &self.status
    }

    /// Returns the certificate, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn certified_key_pair(&self) -> Option<&CertifiedKeyPair> {
        self.certified_key_pair.as_ref()
    }

    /// Returns extra information, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn rsp_info(&self) -> Option<&Asn1OctetString> {
        self.rsp_info.as_ref()
    }
}

impl DecodeContent for CertResponse {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let cert_req_id = fields.get()?;
        let status = fields.get()?;
        let certified_key_pair = fields.get_opt()?;
        let rsp_info = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            cert_req_id,
            status,
            certified_key_pair,
            rsp_info,
        };
        Ok(value)
    }
}

impl DecodeInner for CertResponse {
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

impl EncodeContent for CertResponse {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.cert_req_id.encoded_len(rules)
            + self.status.encoded_len(rules)
            + self
                .certified_key_pair
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
            + self.rsp_info.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.cert_req_id.encode(rules, out)?;
        at += self.status.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.certified_key_pair {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.rsp_info {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CertResponse {}

impl Tagged for CertResponse {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertResponse {}

impl Encode for CertResponse {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
