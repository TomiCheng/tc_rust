use chrono::{DateTime, Utc};
use tc_asn1::{Asn1Integer, Asn1Oid};
use tc_x509::cert::X509Certificate;

use crate::{
    TimeStampRequest, TimeStampResponse, TimeStampResponseGenerator, TimeStampToken,
    TimeStampTokenGenerator, TspError,
};

pub trait TspOperator: Send + Sync {
    // BC 的 TimeStampRequest.Validate：摘要演算法要在 algorithms 裡、摘要的長度要合它，政策與擴充
    // 在非空的 policies、extensions 裡；不合時是 Rejected，帶回應要寫的 PKIFailureInfo
    fn validate_request(
        &self,
        request: &TimeStampRequest,
        algorithms: &[Asn1Oid],
        policies: &[Asn1Oid],
        extensions: &[Asn1Oid],
    ) -> Result<(), TspError>;

    // BC 的 TimeStampTokenGenerator.Generate：以請求的摘要、TSA 的政策（請求有指定時用它的）、序號與
    // 時間做出 TSTInfo，由 tc_cms 簽成 SignedData。gen_time 取到秒，同 BC 預設的解析度
    fn generate_token(
        &self,
        generator: &TimeStampTokenGenerator,
        request: &TimeStampRequest,
        serial_number: Asn1Integer,
        gen_time: DateTime<Utc>,
    ) -> Result<TimeStampToken, TspError>;

    // BC 的 TimeStampResponseGenerator.Generate：請求不被接受時給出拒絕的回應，而不是錯誤
    fn generate_response(
        &self,
        generator: &TimeStampResponseGenerator,
        request: &TimeStampRequest,
        serial_number: Asn1Integer,
        gen_time: DateTime<Utc>,
    ) -> Result<TimeStampResponse, TspError>;

    // BC 的 TimeStampToken.Validate(cert)：憑證的 hash 與 signingCertificate 的 certID 相同，有
    // issuerSerial 時簽發者與序號也相同，憑證是 TSA 憑證、在 genTime 時有效，簽章由它驗得過。憑證是否
    // 可信由呼叫端另外判斷
    fn validate_token(
        &self,
        token: &TimeStampToken,
        certificate: &X509Certificate,
    ) -> Result<(), TspError>;
}
