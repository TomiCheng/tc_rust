use tc_asn1::{Asn1Integer, Asn1OctetString, Asn1Oid, Encode, EncodingOptions};
use tc_asn1_tsp::{MessageImprint, TimeStampReq};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::ext::{Extension, Extensions};

use crate::TspError;
use crate::der::decode_all;

// BC 的 TimeStampRequestGenerator：要不要附憑證、指定的 TSA 政策與擴充
#[derive(Clone, Debug, Default)]
pub struct TimeStampRequestGenerator {
    req_policy: Option<Asn1Oid>,
    cert_req: bool,
    extensions: Vec<Extension>,
}

impl TimeStampRequestGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_req_policy(&mut self, policy: Asn1Oid) {
        self.req_policy = Some(policy);
    }

    // 要求 TSA 在 token 裡附上它的憑證
    pub fn set_cert_req(&mut self, cert_req: bool) {
        self.cert_req = cert_req;
    }

    pub fn add_extension(&mut self, extension: Extension) {
        self.extensions.push(extension);
    }

    // BC 的 Generate(digestAlgorithm, digest, nonce)：摘要由呼叫端算好；演算法寫成帶 NULL 參數，
    // 同 BC
    pub fn generate(
        &self,
        digest_algorithm: Asn1Oid,
        digest: &[u8],
        nonce: Option<Asn1Integer>,
    ) -> Result<TimeStampRequest, TspError> {
        let imprint = MessageImprint::new(
            AlgorithmIdentifier::with_null(digest_algorithm),
            Asn1OctetString::new(digest),
        );
        let mut request = TimeStampReq::new(imprint).with_cert_req(self.cert_req);
        if let Some(policy) = &self.req_policy {
            request = request.with_req_policy(policy.clone());
        }
        if let Some(nonce) = nonce {
            request = request.with_nonce(nonce);
        }
        if !self.extensions.is_empty() {
            request = request.with_extensions(Extensions::new(self.extensions.clone())?);
        }
        Ok(TimeStampRequest::new(request))
    }
}

// BC 的 TimeStampRequest：一份時戳請求，TimeStampReq 的 DER（.tsq）
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeStampRequest {
    request: TimeStampReq,
}

impl TimeStampRequest {
    pub fn new(request: TimeStampReq) -> Self {
        Self { request }
    }

    pub fn decode(der: &[u8]) -> Result<Self, TspError> {
        Ok(Self::new(decode_all(der)?))
    }

    pub fn encode(&self) -> Result<Vec<u8>, TspError> {
        Ok(self.request.encode_to_vec(&EncodingOptions::DER)?)
    }

    pub fn time_stamp_req(&self) -> &TimeStampReq {
        &self.request
    }

    pub fn message_imprint_algorithm(&self) -> &AlgorithmIdentifier {
        self.request.message_imprint().hash_algorithm()
    }

    pub fn message_imprint_digest(&self) -> &[u8] {
        self.request.message_imprint().hashed_message().as_bytes()
    }

    pub fn req_policy(&self) -> Option<&Asn1Oid> {
        self.request.req_policy()
    }

    pub fn nonce(&self) -> Option<&Asn1Integer> {
        self.request.nonce()
    }

    pub fn cert_req(&self) -> bool {
        self.request.cert_req()
    }

    pub fn extensions(&self) -> Option<&Extensions> {
        self.request.extensions()
    }
}
