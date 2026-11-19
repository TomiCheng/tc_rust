use std::sync::Arc;

use tc_algo::{Algo, Params};
use tc_asn1::{Asn1Object, Asn1OctetString, Asn1Oid};
use tc_asn1_cms::recipient::{KeyTransRecipientInfo, RecipientIdentifier, RecipientInfo};
use tc_asn1_cms::signed::IssuerAndSerialNumber;
use tc_asn1_pkcs::{Pkcs1Algorithm, RsaesOaepParams};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::ext::SubjectKeyIdentifier;
use tc_x509::X509Operator;
use tc_x509::cert::X509Certificate;

use crate::CmsError;
use crate::algorithms::oaep_digest;
use crate::der::convert;
use crate::enveloped::RecipientInfoGenerator;

// 收件人的公鑰：憑證裡的，或另外給的
enum Key {
    Certificate(Box<X509Certificate>),
    Public(Arc<dyn Params>),
}

// BC 的 KeyTransRecipientInfoGenerator：以收件人的 RSA 公鑰加密內容金鑰。預設 PKCS#1 v1.5
// （rsaEncryption），同 BC 的 Asn1KeyWrapper("RSA/NONE/PKCS1Padding")；with_oaep 改用 OAEP
pub struct KeyTransRecipientInfoGenerator {
    rid: RecipientIdentifier,
    key: Key,
    oaep_digest: Option<AlgorithmIdentifier>,
}

impl KeyTransRecipientInfoGenerator {
    // 以憑證的簽發者與序號識別，公鑰取自憑證
    pub fn new(certificate: &X509Certificate) -> Self {
        Self {
            rid: IssuerAndSerialNumber::of(certificate.certificate()).into(),
            key: Key::Certificate(Box::new(certificate.clone())),
            oaep_digest: None,
        }
    }

    // 以 subjectKeyIdentifier 識別，公鑰另外給
    pub fn with_key_identifier(
        key_identifier: &[u8],
        public_key: Arc<dyn Params>,
    ) -> Result<Self, CmsError> {
        Ok(Self {
            rid: SubjectKeyIdentifier::new(key_identifier.to_vec())?.into(),
            key: Key::Public(public_key),
            oaep_digest: None,
        })
    }

    // OAEP，MGF1 用同一個摘要，label 空白；摘要是 SHA-1 到 SHA-512 的 OID
    pub fn with_oaep(mut self, digest: Asn1Oid) -> Self {
        self.oaep_digest = Some(AlgorithmIdentifier::new(digest));
        self
    }
}

impl RecipientInfoGenerator for KeyTransRecipientInfoGenerator {
    fn generate(
        &self,
        algo: &dyn Algo,
        x509: &dyn X509Operator,
        content_key: &[u8],
    ) -> Result<RecipientInfo, CmsError> {
        let key: Arc<dyn Params> = match &self.key {
            Key::Certificate(certificate) => {
                Arc::from(x509.spki().decode(certificate.subject_public_key_info())?)
            }
            Key::Public(key) => key.clone(),
        };
        let (name, algorithm) = match &self.oaep_digest {
            None => (
                "RSA//PKCS1PADDING".to_string(),
                AlgorithmIdentifier::with_null(Pkcs1Algorithm::RSA_ENCRYPTION.oid()),
            ),
            Some(digest) => {
                let mgf = AlgorithmIdentifier::with_parameters(
                    Pkcs1Algorithm::MGF1.oid(),
                    convert::<_, Asn1Object>(digest)?,
                );
                let params =
                    RsaesOaepParams::new(digest.clone(), mgf, RsaesOaepParams::p_specified_empty());
                (
                    format!(
                        "RSA//OAEPWITH{}ANDMGF1PADDING",
                        oaep_digest(digest.algorithm())?
                    ),
                    AlgorithmIdentifier::with_parameters(
                        Pkcs1Algorithm::RSAES_OAEP.oid(),
                        convert::<_, Asn1Object>(&params)?,
                    ),
                )
            }
        };
        let encrypted = algo
            .cipher()
            .encrypt_by_name(&name, key.as_ref(), content_key)?;
        Ok(RecipientInfo::KeyTrans(KeyTransRecipientInfo::new(
            self.rid.clone(),
            algorithm,
            Asn1OctetString::new(&encrypted),
        )))
    }
}
