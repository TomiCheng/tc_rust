use std::sync::Arc;

use tc_algo::Params;
use tc_asn1::{Asn1Oid, NamedOid};
use tc_asn1_ess::{EssAttribute, EssCertId, EssCertIdV2, SigningCertificate, SigningCertificateV2};
use tc_asn1_tsp::{Accuracy, TstInfo};
use tc_asn1_x500::AttributeValue;
use tc_asn1_x509::name::GeneralName;
use tc_cms::signed::{CmsSignedData, SignerInformation};
use tc_x509::cert::X509Certificate;

use crate::der::{convert, decode_all};
use crate::{TspError, validate_certificate};

// id-ct-TSTInfo，時戳 token 裡 SignedData 的 eContentType
pub(crate) const ID_CT_TST_INFO: NamedOid = NamedOid::new(
    &[
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04,
    ],
    "1.2.840.113549.1.9.16.1.4",
    "id-ct-TSTInfo",
);

// id-sha1，SigningCertificate（v1）的 cert hash 固定用它
pub(crate) const SHA1: NamedOid =
    NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x1a], "1.3.14.3.2.26", "id-sha1");

// BC 的 TimeStampTokenGenerator：TSA 的私鑰、簽章演算法與憑證，與 TSTInfo 裡 TSA 自己決定的欄位。
// 憑證的 hash 寫進 ESS 的 signingCertificate：預設 SHA-1 的 v1，同 BC 的
// TimeStampTokenGenerator(key, cert, digestOID, policy)；其他摘要用 v2
pub struct TimeStampTokenGenerator {
    pub(crate) private_key: Arc<dyn Params>,
    pub(crate) signature: String,
    pub(crate) certificate: X509Certificate,
    pub(crate) policy: Option<Asn1Oid>,
    pub(crate) ess_digest: Asn1Oid,
    pub(crate) issuer_serial: bool,
    pub(crate) accuracy: Option<Accuracy>,
    pub(crate) ordering: bool,
    pub(crate) tsa: Option<GeneralName>,
    pub(crate) certificates: Vec<X509Certificate>,
}

impl TimeStampTokenGenerator {
    // signature 是 tc_x509 的簽章名稱，如 SHA-256withRSA。憑證不合 RFC 3161 的 TSA 憑證是
    // Validation，同 BC 建構時的 TspUtil.ValidateCertificate；policy 是請求沒指定時用的政策
    pub fn new(
        private_key: Arc<dyn Params>,
        signature: &str,
        certificate: X509Certificate,
        policy: Option<Asn1Oid>,
    ) -> Result<Self, TspError> {
        validate_certificate(&certificate)?;
        Ok(Self {
            private_key,
            signature: signature.to_string(),
            certificate,
            policy,
            ess_digest: SHA1.oid(),
            issuer_serial: false,
            accuracy: None,
            ordering: false,
            tsa: None,
            certificates: Vec::new(),
        })
    }

    // 憑證 hash 的摘要演算法；SHA-1 以外寫成 signingCertificateV2
    pub fn with_ess_digest(mut self, digest: Asn1Oid) -> Self {
        self.ess_digest = digest;
        self
    }

    // ESS 的 certID 也帶憑證的簽發者與序號
    pub fn with_issuer_serial(mut self, issuer_serial: bool) -> Self {
        self.issuer_serial = issuer_serial;
        self
    }

    pub fn with_accuracy(mut self, accuracy: Accuracy) -> Self {
        self.accuracy = Some(accuracy);
        self
    }

    pub fn with_ordering(mut self, ordering: bool) -> Self {
        self.ordering = ordering;
        self
    }

    pub fn with_tsa(mut self, tsa: GeneralName) -> Self {
        self.tsa = Some(tsa);
        self
    }

    // 請求要求憑證時，除了 TSA 自己的，一併附上的憑證，如中繼 CA
    pub fn add_certificate(&mut self, certificate: X509Certificate) {
        self.certificates.push(certificate);
    }
}

// ESS 的 certID：v1 固定 SHA-1，v2 帶摘要演算法
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CertId {
    V1(EssCertId),
    V2(EssCertIdV2),
}

// BC 的 TimeStampToken：一個 SignedData，只有一個簽署者，內容是 TSTInfo，簽署者帶著
// signingCertificate 或 signingCertificateV2
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeStampToken {
    signed: CmsSignedData,
    signer: SignerInformation,
    tst_info: TstInfo,
    cert_id: CertId,
}

impl TimeStampToken {
    // InvalidToken 時不是時戳 token，同 BC 建構時的 TspValidationException
    pub fn new(signed: CmsSignedData) -> Result<Self, TspError> {
        let signers = signed.signer_infos();
        let [signer] = signers.as_slice() else {
            return Err(TspError::InvalidToken(
                "time-stamp token signed by multiple signers",
            ));
        };
        if ID_CT_TST_INFO != *signed.signed_content_type() {
            return Err(TspError::InvalidToken(
                "ContentInfo object not for a time stamp",
            ));
        }
        let content = signed
            .signed_content()
            .ok_or(TspError::InvalidToken("time-stamp token without TSTInfo"))?;
        let tst_info: TstInfo = decode_all(content)?;
        let cert_id = cert_id(signer)?;
        Ok(Self {
            signer: signer.clone(),
            signed,
            tst_info,
            cert_id,
        })
    }

    // ContentInfo 包著的 SignedData（.tsr 裡的 timeStampToken）
    pub fn decode(der: &[u8]) -> Result<Self, TspError> {
        Self::new(CmsSignedData::decode(der)?)
    }

    pub fn encode(&self) -> Result<Vec<u8>, TspError> {
        Ok(self.signed.encode()?)
    }

    pub fn signed_data(&self) -> &CmsSignedData {
        &self.signed
    }

    pub fn signer(&self) -> &SignerInformation {
        &self.signer
    }

    pub fn tst_info(&self) -> &TstInfo {
        &self.tst_info
    }

    // token 附帶的憑證；請求沒要求時可能沒有
    pub fn certificates(&self) -> Vec<X509Certificate> {
        self.signed.certificates()
    }

    pub(crate) fn cert_id(&self) -> &CertId {
        &self.cert_id
    }
}

// signingCertificate（v1）優先，同 BC；沒有就讀 v2，兩個都沒有不是時戳 token
fn cert_id(signer: &SignerInformation) -> Result<CertId, TspError> {
    let info = signer.signer_info();
    if let Some(attribute) = info.signed_attr(&EssAttribute::SIGNING_CERTIFICATE.oid()) {
        let certificate: SigningCertificate = convert(single(attribute.values())?)?;
        let first = certificate.certs().first().ok_or(TspError::InvalidToken(
            "signing certificate without a certID",
        ))?;
        return Ok(CertId::V1(first.clone()));
    }
    if let Some(attribute) = info.signed_attr(&EssAttribute::SIGNING_CERTIFICATE_V2.oid()) {
        let certificate: SigningCertificateV2 = convert(single(attribute.values())?)?;
        let first = certificate.certs().first().ok_or(TspError::InvalidToken(
            "signing certificate without a certID",
        ))?;
        return Ok(CertId::V2(first.clone()));
    }
    Err(TspError::InvalidToken(
        "no signing certificate attribute found, time stamp invalid",
    ))
}

fn single(values: &[AttributeValue]) -> Result<&tc_asn1::Asn1Object, TspError> {
    match values {
        [AttributeValue::Other(value)] => Ok(value),
        _ => Err(TspError::InvalidToken(
            "signing certificate attribute malformed",
        )),
    }
}
