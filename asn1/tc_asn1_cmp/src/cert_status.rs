//! RFC 4210 §5.3.18 `CertStatus`, the requester's acceptance of one certificate.
//!
//! ```text
//! CertStatus ::= SEQUENCE {
//!     certHash   OCTET STRING,
//!     certReqId  INTEGER,
//!     statusInfo PKIStatusInfo OPTIONAL,
//!     hashAlg    [0] AlgorithmIdentifier{DIGEST-ALGORITHM, {...}} OPTIONAL }
//! ```
//!
//! The module uses explicit tags.

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::PkiStatusInfo;

/// The hash of the certificate, the request it answers, and whether it is accepted.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertStatus {
    cert_hash: Asn1OctetString,
    cert_req_id: Asn1Integer,
    status_info: Option<PkiStatusInfo>,
    hash_alg: Option<AlgorithmIdentifier>,
}

impl CertStatus {
    /// The hash and request identifier, without a status or hash algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn new(cert_hash: Asn1OctetString, cert_req_id: Asn1Integer) -> Self {
        Self {
            cert_hash,
            cert_req_id,
            status_info: None,
            hash_alg: None,
        }
    }

    /// Sets the status; absent means accepted.
    /// Variable time: branches only on the encoding structure.
    pub fn with_status_info(mut self, status_info: PkiStatusInfo) -> Self {
        self.status_info = Some(status_info);
        self
    }

    /// Sets the hash algorithm, when the signature algorithm does not imply it.
    /// Variable time: branches only on the encoding structure.
    pub fn with_hash_alg(mut self, hash_alg: AlgorithmIdentifier) -> Self {
        self.hash_alg = Some(hash_alg);
        self
    }

    /// Returns the hash of the certificate.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_hash(&self) -> &Asn1OctetString {
        &self.cert_hash
    }

    /// Returns the identifier of the request.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_req_id(&self) -> &Asn1Integer {
        &self.cert_req_id
    }

    /// Returns the status, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn status_info(&self) -> Option<&PkiStatusInfo> {
        self.status_info.as_ref()
    }

    /// Returns the hash algorithm, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn hash_alg(&self) -> Option<&AlgorithmIdentifier> {
        self.hash_alg.as_ref()
    }
}

impl DecodeContent for CertStatus {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let cert_hash = fields.get()?;
        let cert_req_id = fields.get()?;
        let status_info = fields.get_opt()?;
        let hash_alg = fields.get_explicit_opt::<AlgorithmIdentifier>([0xa0])?;
        fields.end()?;
        let value = Self {
            cert_hash,
            cert_req_id,
            status_info,
            hash_alg,
        };
        Ok(value)
    }
}

impl DecodeInner for CertStatus {
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

impl EncodeContent for CertStatus {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.cert_hash.encoded_len(rules)
            + self.cert_req_id.encoded_len(rules)
            + self
                .status_info
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
            + self
                .hash_alg
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.cert_hash.encode(rules, out)?;
        at += self.cert_req_id.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.status_info {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.hash_alg {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CertStatus {}

impl Tagged for CertStatus {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertStatus {}

impl Encode for CertStatus {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
