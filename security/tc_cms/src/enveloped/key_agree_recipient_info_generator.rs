use tc_algo::Algo;
use tc_algo::params::generate::EcKeyGenParams;
use tc_algo::params::key::KeyOwned;
use tc_asn1::{Asn1Object, Asn1OctetString, Asn1Oid};
use tc_asn1_cms::recipient::{
    KeyAgreeRecipientIdentifier, KeyAgreeRecipientInfo, OriginatorIdentifierOrKey,
    OriginatorPublicKey, RecipientEncryptedKey, RecipientInfo,
};
use tc_asn1_cms::signed::IssuerAndSerialNumber;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_x509::X509Operator;
use tc_x509::cert::X509Certificate;
use tc_zeroize::Zeroizing;

use crate::CmsError;
use crate::enveloped::RecipientInfoGenerator;

// BC 的 KeyAgreeRecipientInfoGenerator，ECDH 的部分（RFC 5753）：每則訊息一組臨時金鑰對，與每個
// 收件人的 EC 公鑰協商，經 KDF 推出 KEK 再包住內容金鑰。agreement 是 dhSinglePass-stdDH 或
// cofactorDH 的 sha*kdf-scheme OID，wrap 是 AES key wrap 的 OID。收件人要在同一條具名曲線上；
// 不帶 UKM，同 BC 對 ECDH 的預設
pub struct KeyAgreeRecipientInfoGenerator {
    agreement: Asn1Oid,
    wrap: Asn1Oid,
    recipients: Vec<X509Certificate>,
}

// id-ecPublicKey
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

impl KeyAgreeRecipientInfoGenerator {
    pub fn new(agreement: Asn1Oid, wrap: Asn1Oid) -> Self {
        Self {
            agreement,
            wrap,
            recipients: Vec::new(),
        }
    }

    // 以憑證的簽發者與序號識別，公鑰取自憑證
    pub fn add_recipient(&mut self, certificate: &X509Certificate) {
        self.recipients.push(certificate.clone());
    }
}

impl RecipientInfoGenerator for KeyAgreeRecipientInfoGenerator {
    fn generate(
        &self,
        algo: &dyn Algo,
        x509: &dyn X509Operator,
        content_key: &[u8],
    ) -> Result<RecipientInfo, CmsError> {
        let first = self.recipients.first().ok_or(CmsError::NoRecipient)?;
        let curve = curve_of(first)?;
        let ephemeral = algo
            .key_pair_generator()
            .generate_by_name_with("EC", &EcKeyGenParams::from_oid(curve.clone()))?;
        let wrap = AlgorithmIdentifier::new(self.wrap.clone());

        let mut keys = Vec::new();
        for certificate in &self.recipients {
            if curve_of(certificate)? != curve {
                return Err(CmsError::WrongRecipientKey);
            }
            let public = x509.spki().decode(certificate.subject_public_key_info())?;
            let mut agreement = algo
                .agreement()
                .get_with_kdf_by_oid(&self.agreement, &wrap)?;
            agreement.init(ephemeral.private())?;
            let mut kek = Zeroizing::new(vec![0; agreement.agreement_size()]);
            agreement.calculate_agreement(public.as_ref(), &mut kek)?;
            let wrapped =
                algo.wrap()
                    .wrap_by_oid(&self.wrap, &KeyOwned::new(kek.to_vec()), content_key)?;
            keys.push(RecipientEncryptedKey::new(
                KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber::of(
                    certificate.certificate(),
                )),
                Asn1OctetString::new(&wrapped),
            ));
        }

        // 臨時公鑰寫成 id-ecPublicKey 帶 NULL，同 BC 的 CreateOriginatorPublicKey
        let spki = x509.spki().encode(ephemeral.public())?;
        let originator = OriginatorPublicKey::new(
            AlgorithmIdentifier::with_null(EC_PUBLIC_KEY.parse()?),
            spki.subject_public_key().clone(),
        );
        Ok(RecipientInfo::KeyAgree(KeyAgreeRecipientInfo::new(
            OriginatorIdentifierOrKey::OriginatorKey(originator),
            AlgorithmIdentifier::with_parameters(self.agreement.clone(), convert_wrap(&wrap)?),
            keys,
        )))
    }
}

// 憑證公鑰的具名曲線
fn curve_of(certificate: &X509Certificate) -> Result<Asn1Oid, CmsError> {
    let algorithm = certificate.subject_public_key_info().algorithm();
    match algorithm.parameters() {
        Some(Asn1Object::Oid(curve)) if algorithm.algorithm().to_string() == EC_PUBLIC_KEY => {
            Ok(curve.clone())
        }
        _ => Err(CmsError::WrongRecipientKey),
    }
}

fn convert_wrap(wrap: &AlgorithmIdentifier) -> Result<Asn1Object, CmsError> {
    crate::der::convert(wrap)
}
