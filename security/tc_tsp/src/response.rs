use tc_asn1::{Asn1Oid, Encode, EncodingOptions};
use tc_asn1_cmp::{PkiFailureInfo, PkiStatus, PkiStatusInfo};
use tc_asn1_tsp::TimeStampResp;
use tc_cms::signed::CmsSignedData;

use crate::der::decode_all;
use crate::{TimeStampRequest, TimeStampToken, TimeStampTokenGenerator, TspError};

// BC 的 TimeStampResponseGenerator：產生 token 的 TSA，與它接受的摘要演算法、政策與擴充。政策或
// 擴充是空的時不檢查，同 BC
pub struct TimeStampResponseGenerator {
    pub(crate) token_generator: TimeStampTokenGenerator,
    pub(crate) accepted_algorithms: Vec<Asn1Oid>,
    pub(crate) accepted_policies: Vec<Asn1Oid>,
    pub(crate) accepted_extensions: Vec<Asn1Oid>,
}

impl TimeStampResponseGenerator {
    pub fn new(
        token_generator: TimeStampTokenGenerator,
        accepted_algorithms: Vec<Asn1Oid>,
    ) -> Self {
        Self {
            token_generator,
            accepted_algorithms,
            accepted_policies: Vec::new(),
            accepted_extensions: Vec::new(),
        }
    }

    pub fn with_accepted_policies(mut self, policies: Vec<Asn1Oid>) -> Self {
        self.accepted_policies = policies;
        self
    }

    pub fn with_accepted_extensions(mut self, extensions: Vec<Asn1Oid>) -> Self {
        self.accepted_extensions = extensions;
        self
    }

    pub fn token_generator(&self) -> &TimeStampTokenGenerator {
        &self.token_generator
    }
}

// BC 的 TimeStampResponse：TSA 的回應（.tsr），狀態與核准時的 token
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeStampResponse {
    response: TimeStampResp,
    token: Option<TimeStampToken>,
}

impl TimeStampResponse {
    pub fn new(response: TimeStampResp) -> Result<Self, TspError> {
        let token = match response.time_stamp_token() {
            Some(info) => {
                let signed: CmsSignedData =
                    CmsSignedData::decode(&info.encode_to_vec(&EncodingOptions::DER)?)?;
                Some(TimeStampToken::new(signed)?)
            }
            None => None,
        };
        Ok(Self { response, token })
    }

    pub(crate) fn granted(token: TimeStampToken) -> Result<Self, TspError> {
        let info: tc_asn1_cms::content::ContentInfo = decode_all(&token.encode()?)?;
        let response =
            TimeStampResp::new(PkiStatusInfo::new(PkiStatus::Granted)).with_time_stamp_token(info);
        Ok(Self {
            response,
            token: Some(token),
        })
    }

    // BC 的 GenerateFailResponse：拒絕，帶 failInfo
    pub(crate) fn rejected(fail_info: PkiFailureInfo) -> Self {
        let status = PkiStatusInfo::new(PkiStatus::Rejection).with_fail_info(fail_info);
        Self {
            response: TimeStampResp::new(status),
            token: None,
        }
    }

    pub fn decode(der: &[u8]) -> Result<Self, TspError> {
        Self::new(decode_all(der)?)
    }

    pub fn encode(&self) -> Result<Vec<u8>, TspError> {
        Ok(self.response.encode_to_vec(&EncodingOptions::DER)?)
    }

    pub fn time_stamp_resp(&self) -> &TimeStampResp {
        &self.response
    }

    pub fn status(&self) -> PkiStatus {
        *self.response.status().status()
    }

    pub fn fail_info(&self) -> Option<&PkiFailureInfo> {
        self.response.status().fail_info()
    }

    pub fn time_stamp_token(&self) -> Option<&TimeStampToken> {
        self.token.as_ref()
    }

    // BC 的 Validate(request)：nonce、摘要演算法與摘要都與請求相同，有 signingCertificate，請求指定
    // 的政策相同；核准的回應要有 token，失敗的不能有。token 的簽章另由 TspOperator::validate_token
    // 驗證
    pub fn validate(&self, request: &TimeStampRequest) -> Result<(), TspError> {
        let granted = matches!(
            self.status(),
            PkiStatus::Granted | PkiStatus::GrantedWithMods
        );
        let Some(token) = &self.token else {
            if granted {
                return Err(TspError::Validation(
                    "no time stamp token found and one expected",
                ));
            }
            return Ok(());
        };
        let info = token.tst_info();
        if let Some(nonce) = request.nonce() {
            if info.nonce() != Some(nonce) {
                return Err(TspError::Validation("response contains wrong nonce value"));
            }
        }
        if !granted {
            return Err(TspError::Validation(
                "time stamp token found in failed request",
            ));
        }
        if !equivalent(
            info.message_imprint().hash_algorithm(),
            request.message_imprint_algorithm(),
        ) {
            return Err(TspError::Validation(
                "response for different message imprint algorithm",
            ));
        }
        if info.message_imprint().hashed_message().as_bytes() != request.message_imprint_digest() {
            return Err(TspError::Validation(
                "response for different message imprint digest",
            ));
        }
        if let Some(policy) = request.req_policy() {
            if policy != info.policy() {
                return Err(TspError::Validation("TSA policy wrong for request"));
            }
        }
        Ok(())
    }
}

// 同 BC X509Utilities.AreEquivalentAlgorithms：OID 相同，參數相同或都是沒有／NULL
pub(crate) fn equivalent(
    a: &tc_asn1_x509::alg::AlgorithmIdentifier,
    b: &tc_asn1_x509::alg::AlgorithmIdentifier,
) -> bool {
    use tc_asn1::Asn1Object;
    let absent = |id: &tc_asn1_x509::alg::AlgorithmIdentifier| {
        matches!(id.parameters(), None | Some(Asn1Object::Null(_)))
    };
    a.algorithm() == b.algorithm() && ((absent(a) && absent(b)) || a.parameters() == b.parameters())
}
