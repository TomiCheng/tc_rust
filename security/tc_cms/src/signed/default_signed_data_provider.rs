use std::io::{Read, Write};
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

use crate::CmsError;
use crate::algorithms::{RSA_ENCRYPTION, digest_name, equivalent};
use crate::default_cms_operator::DefaultCmsOperator;
use crate::der::convert;
use crate::signed::signed_data_parser;
use crate::signed::{
    CmsSignedData, CmsSignedDataGenerator, SignedDataProvider, SignedDataWriter,
    SignerInfoGenerator, SignerInformation,
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
            signer_infos.push(self.sign(signer, Some(content_type), content)?);
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

    fn open<'a>(
        &'a self,
        generator: &'a CmsSignedDataGenerator,
        output: Box<dyn Write + 'a>,
        encapsulate: bool,
    ) -> Result<SignedDataWriter<'a>, CmsError> {
        SignedDataWriter::open(self.algo.as_ref(), generator, output, encapsulate)
    }

    fn parse(
        &self,
        input: &mut dyn Read,
        content: &mut dyn Write,
    ) -> Result<CmsSignedData, CmsError> {
        signed_data_parser::parse(self.algo.as_ref(), input, content, None)
    }

    fn parse_detached(
        &self,
        input: &mut dyn Read,
        content: &mut dyn Read,
    ) -> Result<CmsSignedData, CmsError> {
        signed_data_parser::parse(
            self.algo.as_ref(),
            input,
            &mut std::io::sink(),
            Some(content),
        )
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
    // signed attributes 時簽的是它們的 DER，沒有時簽的是內容本身；副署簽的是被副署的簽章值，
    // 而且不得有 contentType
    fn verify_with_key(
        &self,
        signed: &CmsSignedData,
        signer: &SignerInformation,
        public_key: Arc<dyn Params>,
    ) -> Result<(), CmsError> {
        let info = signer.signer_info();
        // 串流讀出的 SignedData 不留內容，只留邊讀邊算的摘要
        let content = match signer.countersigned() {
            Some(signature) => Some(signature),
            None => signed.signed_content(),
        };
        let digest = match content {
            Some(content) => self
                .algo
                .digest()
                .calculate_by_oid(info.digest_algorithm().algorithm(), content)?,
            None => signed
                .digest(info.digest_algorithm().algorithm())
                .ok_or(CmsError::MissingContent)?
                .to_vec(),
        };

        if info.signed_attrs().is_some() {
            if signer.is_counter_signature() {
                if info
                    .signed_attr(&CmsAttribute::CONTENT_TYPE.oid())
                    .is_some()
                {
                    return Err(CmsError::InvalidAttribute("content-type"));
                }
            } else {
                let Asn1Object::Oid(content_type) =
                    single_value(info, CmsAttribute::CONTENT_TYPE, "content-type")?
                else {
                    return Err(CmsError::InvalidAttribute("content-type"));
                };
                if content_type != *signer.content_type() {
                    return Err(CmsError::ContentTypeMismatch);
                }
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
            None => calculator.write_all(content.ok_or(CmsError::MissingContent)?),
        }
        .map_err(tc_x509::X509Error::from)?;
        if calculator.result().is_verified(signer.signature())? {
            Ok(())
        } else {
            Err(CmsError::InvalidSignature)
        }
    }

    // 同 BC 的 GenerateCounterSigners、AddCounterSigners 與 ReplaceSigners
    fn countersign(
        &self,
        signed: &CmsSignedData,
        signer: &SignerInformation,
        generator: &CmsSignedDataGenerator,
    ) -> Result<CmsSignedData, CmsError> {
        let mut values = Vec::new();
        for counter in &generator.signers {
            let info = self.sign(counter, None, signer.signature())?;
            values.push(AttributeValue::Other(convert(&info)?));
        }
        if values.is_empty() {
            return Err(CmsError::NoSigner);
        }
        let mut unsigned = signer
            .signer_info()
            .unsigned_attrs()
            .unwrap_or_default()
            .to_vec();
        unsigned.push(Attribute::new(
            CmsAttribute::COUNTERSIGNATURE.oid(),
            values,
        )?);
        let replacement = signer.signer_info().clone().with_unsigned_attrs(unsigned);

        let data = signed.signed_data();
        let mut replaced = false;
        let signer_infos = data
            .signer_infos()
            .iter()
            .map(|info| {
                if !replaced && info == signer.signer_info() {
                    replaced = true;
                    replacement.clone()
                } else {
                    info.clone()
                }
            })
            .collect();
        if !replaced {
            return Err(CmsError::NoSigner);
        }
        let mut rebuilt = SignedData::new(
            data.digest_algorithms().to_vec(),
            data.encap_content_info().clone(),
            signer_infos,
        )
        .with_version(data.version());
        if let Some(certificates) = data.certificates() {
            rebuilt = rebuilt.with_certificates(certificates.to_vec());
        }
        if let Some(crls) = data.crls() {
            rebuilt = rebuilt.with_crls(crls.to_vec());
        }
        Ok(match signed.signed_content() {
            Some(content) if signed.is_detached() => {
                CmsSignedData::with_detached_content(rebuilt, content.to_vec())
            }
            _ => CmsSignedData::new(rebuilt)?,
        })
    }
}

impl DefaultCmsOperator {
    // 同 BC SignerInf.ToSignerInfo
    // content_type 是 None 時是副署，不加 contentType
    fn sign(
        &self,
        signer: &SignerInfoGenerator,
        content_type: Option<&Asn1Oid>,
        content: &[u8],
    ) -> Result<SignerInfo, CmsError> {
        if !signer.signed_attributes {
            let mut calculator = signer.factory.create_calculator()?;
            calculator
                .write_all(content)
                .map_err(tc_x509::X509Error::from)?;
            return finish_signer_info(signer, None, calculator.result().collect()?);
        }
        let digest = self
            .algo
            .digest()
            .calculate_by_oid(signer.digest_algorithm.algorithm(), content)?;
        sign_digest(signer, content_type, &digest)
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

// 有 signed attributes 的簽署者：簽的是它們的 DER，內容只以摘要出現，所以串流時也用得上
pub(crate) fn sign_digest(
    signer: &SignerInfoGenerator,
    content_type: Option<&Asn1Oid>,
    digest: &[u8],
) -> Result<SignerInfo, CmsError> {
    let signature_algorithm = signer.factory.algorithm().clone();
    let attributes = standard_attributes(signer, content_type, digest, &signature_algorithm)?;
    let der = Asn1SetOf::new(attributes.clone()).encode_to_vec(&EncodingOptions::DER)?;
    let mut calculator = signer.factory.create_calculator()?;
    calculator
        .write_all(&der)
        .map_err(tc_x509::X509Error::from)?;
    finish_signer_info(signer, Some(attributes), calculator.result().collect()?)
}

pub(crate) fn finish_signer_info(
    signer: &SignerInfoGenerator,
    signed_attributes: Option<Vec<Attribute>>,
    signature: Vec<u8>,
) -> Result<SignerInfo, CmsError> {
    let mut info = SignerInfo::new(
        signer.sid.clone(),
        signer.digest_algorithm.clone(),
        signer.factory.algorithm().clone(),
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

// 同 BC DefaultSignedAttributeTableGenerator：另外給的屬性優先，缺的才補上
fn standard_attributes(
    signer: &SignerInfoGenerator,
    content_type: Option<&Asn1Oid>,
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
    if let Some(content_type) = content_type {
        if !has(&attributes, &content_type_oid) {
            attributes.push(attribute(
                content_type_oid,
                Asn1Object::Oid(content_type.clone()),
            )?);
        }
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
