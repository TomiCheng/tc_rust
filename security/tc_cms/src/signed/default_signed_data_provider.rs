use std::io::Write;
use std::sync::Arc;

use chrono::Utc;
use tc_algo::Params;
use tc_asn1::{Asn1Object, Asn1OctetString, Asn1Oid, Asn1SetOf, Encode, EncodingOptions, tag};
use tc_asn1_cms::content::{CertificateChoices, ContentInfo, SignedData};
use tc_asn1_cms::signed::{CmsAlgorithmProtection, CmsAttribute, SignerInfo};
use tc_asn1_x500::{Attribute, AttributeValue};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::Time;
use tc_x509::cert::X509Certificate;
use tc_x509::operator::verifier::VerifierFactory;

use super::algorithms::{RSA_ENCRYPTION, digest_name, equivalent};
use crate::CmsError;
use crate::default_cms_operator::DefaultCmsOperator;
use crate::der::convert;
use crate::signed::{
    CmsSignedData, CmsSignedDataGenerator, SignedDataProvider, SignerInfoGenerator,
    SignerInformation,
};

impl SignedDataProvider for DefaultCmsOperator {
    fn generate(
        &self,
        generator: &CmsSignedDataGenerator,
        content: &[u8],
        encapsulate: bool,
    ) -> Result<CmsSignedData, CmsError> {
        let content_type = &generator.content_type;
        let mut digest_algorithms: Vec<AlgorithmIdentifier> = Vec::new();
        let mut signer_infos = Vec::new();
        for signer in &generator.signers {
            if !digest_algorithms.contains(&signer.digest_algorithm) {
                digest_algorithms.push(signer.digest_algorithm.clone());
            }
            signer_infos.push(self.sign(signer, content_type, content)?);
        }

        let mut encapsulated = ContentInfo::new(content_type.clone());
        if encapsulate {
            encapsulated =
                encapsulated.with_content(tc_asn1::Asn1Any::primitive(tag::OCTET_STRING, content));
        }
        let mut signed_data = SignedData::new(digest_algorithms, encapsulated, signer_infos);
        if !generator.certificates.is_empty() {
            signed_data = signed_data.with_certificates(
                generator
                    .certificates
                    .iter()
                    .map(|certificate| {
                        CertificateChoices::Certificate(certificate.certificate().clone())
                    })
                    .collect(),
            );
        }
        Ok(CmsSignedData::with_detached_content(
            signed_data,
            content.to_vec(),
        ))
    }

    fn verify(
        &self,
        signed: &CmsSignedData,
        signer: &SignerInformation,
        certificate: &X509Certificate,
    ) -> Result<(), CmsError> {
        if let Some(time) = signing_time(signer)? {
            if !certificate.is_valid_at(&time) {
                return Err(CmsError::CertificateNotValid);
            }
        }
        let key = self
            .x509
            .spki()
            .decode(certificate.subject_public_key_info())?;
        self.verify_with_key(signed, signer, Arc::from(key))
    }

    // 同 BC 的 DoVerify：先檢查 contentType、cmsAlgorithmProtect 與 messageDigest，再驗簽章。有
    // signed attributes 時簽的是它們的 DER，沒有時簽的是內容本身
    fn verify_with_key(
        &self,
        signed: &CmsSignedData,
        signer: &SignerInformation,
        public_key: Arc<dyn Params>,
    ) -> Result<(), CmsError> {
        let info = signer.signer_info();
        let content = signed.signed_content().ok_or(CmsError::MissingContent)?;
        let digest = self
            .algo
            .digest()
            .calculate_by_oid(info.digest_algorithm().algorithm(), content)?;

        if info.signed_attrs().is_some() {
            let Asn1Object::Oid(content_type) =
                single_value(info, CmsAttribute::CONTENT_TYPE, "content-type")?
            else {
                return Err(CmsError::InvalidAttribute("content-type"));
            };
            if content_type != *signer.content_type() {
                return Err(CmsError::ContentTypeMismatch);
            }
            if info
                .signed_attr(&CmsAttribute::CMS_ALGORITHM_PROTECT.oid())
                .is_some()
            {
                let value = single_value(
                    info,
                    CmsAttribute::CMS_ALGORITHM_PROTECT,
                    "cmsAlgorithmProtect",
                )?;
                let protection: CmsAlgorithmProtection = convert(&value)?;
                if !equivalent(protection.digest_algorithm(), info.digest_algorithm())
                    || !protection
                        .signature_algorithm()
                        .is_some_and(|algorithm| equivalent(algorithm, info.signature_algorithm()))
                {
                    return Err(CmsError::AlgorithmProtectionMismatch);
                }
            }
            let Asn1Object::OctetString(message_digest) =
                single_value(info, CmsAttribute::MESSAGE_DIGEST, "message-digest")?
            else {
                return Err(CmsError::InvalidAttribute("message-digest"));
            };
            if !fixed_time_eq(message_digest.as_bytes(), &digest) {
                return Err(CmsError::MessageDigestMismatch);
            }
            if info
                .signed_attr(&CmsAttribute::COUNTERSIGNATURE.oid())
                .is_some()
            {
                return Err(CmsError::InvalidAttribute("countersignature"));
            }
        }

        let factory = self.verifier_factory(info, public_key)?;
        let mut calculator = factory.create_calculator()?;
        match info.signed_attrs_der()? {
            Some(attributes) => calculator.write_all(&attributes),
            None => calculator.write_all(content),
        }
        .map_err(tc_x509::X509Error::from)?;
        if calculator.result().is_verified(signer.signature())? {
            Ok(())
        } else {
            Err(CmsError::InvalidSignature)
        }
    }
}

impl DefaultCmsOperator {
    // 同 BC SignerInf.ToSignerInfo
    fn sign(
        &self,
        signer: &SignerInfoGenerator,
        content_type: &Asn1Oid,
        content: &[u8],
    ) -> Result<SignerInfo, CmsError> {
        let digest_algorithm = &signer.digest_algorithm;
        let signature_algorithm = signer.factory.algorithm().clone();
        let digest = self
            .algo
            .digest()
            .calculate_by_oid(digest_algorithm.algorithm(), content)?;

        let mut calculator = signer.factory.create_calculator()?;
        let signed_attributes = if signer.signed_attributes {
            let attributes =
                standard_attributes(signer, content_type, &digest, &signature_algorithm)?;
            let der = Asn1SetOf::new(attributes.clone()).encode_to_vec(&EncodingOptions::DER)?;
            calculator
                .write_all(&der)
                .map_err(tc_x509::X509Error::from)?;
            Some(attributes)
        } else {
            calculator
                .write_all(content)
                .map_err(tc_x509::X509Error::from)?;
            None
        };
        let signature = calculator.result().collect()?;

        let mut info = SignerInfo::new(
            signer.sid.clone(),
            digest_algorithm.clone(),
            signature_algorithm,
            Asn1OctetString::new(&signature),
        );
        if let Some(attributes) = signed_attributes {
            info = info.with_signed_attrs(attributes);
        }
        if !signer.unsigned.is_empty() {
            info = info.with_unsigned_attrs(signer.unsigned.clone());
        }
        Ok(info)
    }

    // 簽章演算法是 rsaEncryption 時，依摘要組出 SHA-256withRSA 這樣的名稱，同 BC 的
    // digestName + "with" + GetEncryptionAlgName；否則交給 tc_x509 依 AlgorithmIdentifier 找
    fn verifier_factory(
        &self,
        info: &SignerInfo,
        public_key: Arc<dyn Params>,
    ) -> Result<Box<dyn VerifierFactory>, CmsError> {
        let signature = info.signature_algorithm();
        if signature.algorithm().to_string() == RSA_ENCRYPTION {
            if !matches!(signature.parameters(), None | Some(Asn1Object::Null(_))) {
                return Err(CmsError::UnknownAlgorithm);
            }
            let name = format!(
                "{}withRSA",
                digest_name(info.digest_algorithm().algorithm())?
            );
            return Ok(self.x509.verifier_factory(&name, public_key)?);
        }
        let provider = self.x509.verifier_factory_provider(public_key);
        Ok(provider.create_verifier_factory(signature)?)
    }
}

// 同 BC DefaultSignedAttributeTableGenerator：另外給的屬性優先，缺的才補上
fn standard_attributes(
    signer: &SignerInfoGenerator,
    content_type: &Asn1Oid,
    digest: &[u8],
    signature_algorithm: &AlgorithmIdentifier,
) -> Result<Vec<Attribute>, CmsError> {
    let mut attributes = signer.extra_signed.clone();
    let has = |attributes: &[Attribute], oid: &Asn1Oid| {
        attributes
            .iter()
            .any(|attribute| attribute.attribute_type() == oid)
    };
    let content_type_oid = CmsAttribute::CONTENT_TYPE.oid();
    if !has(&attributes, &content_type_oid) {
        attributes.push(attribute(
            content_type_oid,
            Asn1Object::Oid(content_type.clone()),
        )?);
    }
    let signing_time = CmsAttribute::SIGNING_TIME.oid();
    if !has(&attributes, &signing_time) {
        let now: Asn1Object = convert(&Time::try_from(Utc::now())?)?;
        attributes.push(attribute(signing_time, now)?);
    }
    let message_digest = CmsAttribute::MESSAGE_DIGEST.oid();
    if !has(&attributes, &message_digest) {
        let value = Asn1Object::OctetString(Asn1OctetString::new(digest));
        attributes.push(attribute(message_digest, value)?);
    }
    let protect = CmsAttribute::CMS_ALGORITHM_PROTECT.oid();
    if !has(&attributes, &protect) {
        let protection = CmsAlgorithmProtection::signature(
            signer.digest_algorithm.clone(),
            signature_algorithm.clone(),
        );
        attributes.push(attribute(protect, convert(&protection)?)?);
    }
    Ok(attributes)
}

fn attribute(attribute_type: Asn1Oid, value: Asn1Object) -> Result<Attribute, CmsError> {
    Ok(Attribute::new(
        attribute_type,
        vec![AttributeValue::Other(value)],
    )?)
}

// 單一值的 signed attribute，同 BC 的 GetSingleValuedSignedAttribute
fn single_value(
    info: &SignerInfo,
    attribute_type: tc_asn1::NamedOid,
    name: &'static str,
) -> Result<Asn1Object, CmsError> {
    let attribute = info
        .signed_attr(&attribute_type.oid())
        .ok_or(CmsError::InvalidAttribute(name))?;
    match attribute.values() {
        [AttributeValue::Other(value)] => Ok(value.clone()),
        _ => Err(CmsError::InvalidAttribute(name)),
    }
}

fn signing_time(signer: &SignerInformation) -> Result<Option<Time>, CmsError> {
    let info = signer.signer_info();
    if info
        .signed_attr(&CmsAttribute::SIGNING_TIME.oid())
        .is_none()
    {
        return Ok(None);
    }
    let value = single_value(info, CmsAttribute::SIGNING_TIME, "signing-time")?;
    Ok(Some(convert(&value)?))
}

// 長度相同時不依內容提早結束
fn fixed_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}
