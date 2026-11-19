use tc_algo::Params;
use tc_algo::params::key::KeyOwned;
use tc_asn1::{Asn1Object, Asn1OctetString, Asn1Oid, Asn1SetOf, Encode, EncodingOptions, tag};
use tc_asn1_cms::content::{AuthenticatedData, ContentInfo};
use tc_asn1_cms::signed::CmsAttribute;
use tc_asn1_x500::{Attribute, AttributeValue};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_zeroize::Zeroizing;

use crate::CmsError;
use crate::algorithms::mac_key_length;
use crate::authenticated::{
    AuthenticatedDataProvider, CmsAuthenticatedData, CmsAuthenticatedDataGenerator,
};
use crate::default_cms_operator::DefaultCmsOperator;
use crate::enveloped::{RecipientInformation, random};

impl AuthenticatedDataProvider for DefaultCmsOperator {
    fn generate(
        &self,
        generator: &CmsAuthenticatedDataGenerator,
        content: &[u8],
        mac: &Asn1Oid,
    ) -> Result<CmsAuthenticatedData, CmsError> {
        let key = Zeroizing::new(random(mac_key_length(mac)?));

        let auth_attributes = match &generator.digest {
            Some(digest) => {
                let digest = self.algo.digest().calculate_by_oid(digest, content)?;
                Some(standard_attributes(generator, &digest)?)
            }
            None => None,
        };
        let authenticated = match &auth_attributes {
            Some(attributes) => {
                Asn1SetOf::new(attributes.clone()).encode_to_vec(&EncodingOptions::DER)?
            }
            None => content.to_vec(),
        };
        let tag =
            self.algo
                .mac()
                .calculate_by_oid(mac, &KeyOwned::new(key.to_vec()), &authenticated)?;

        let mut recipients = Vec::new();
        for recipient in &generator.recipients {
            recipients.push(recipient.generate(self.algo.as_ref(), self.x509.as_ref(), &key)?);
        }

        let encapsulated = ContentInfo::new(generator.content_type.clone())
            .with_content(tc_asn1::Asn1Any::primitive(tag::OCTET_STRING, content));
        let mut data = AuthenticatedData::new(
            recipients,
            AlgorithmIdentifier::new(mac.clone()),
            encapsulated,
            Asn1OctetString::new(&tag),
        );
        if let (Some(digest), Some(attributes)) = (&generator.digest, auth_attributes) {
            data = data
                .with_digest_algorithm(AlgorithmIdentifier::new(digest.clone()))
                .with_auth_attrs(attributes);
        }
        if !generator.unauth_attributes.is_empty() {
            data = data.with_unauth_attrs(generator.unauth_attributes.clone());
        }
        Ok(CmsAuthenticatedData::new(data))
    }

    // RFC 5652 §9.3：有 authenticated attributes 時，messageDigest 要等於內容的摘要、contentType
    // 要等於封裝的型別，MAC 算在屬性的 DER 上；沒有時算在內容上
    fn verify(
        &self,
        data: &CmsAuthenticatedData,
        recipient: &RecipientInformation,
        key: &dyn Params,
    ) -> Result<Vec<u8>, CmsError> {
        let key = self.content_key(recipient, key)?;
        let content = data.content()?.ok_or(CmsError::MissingContent)?;
        let authenticated = match data.auth_attributes() {
            Some(attributes) => {
                let digest = data
                    .authenticated_data()
                    .digest_algorithm()
                    .ok_or(CmsError::InvalidAttribute("digest-algorithm"))?;
                let expected = self
                    .algo
                    .digest()
                    .calculate_by_oid(digest.algorithm(), &content)?;
                let Asn1Object::OctetString(message_digest) =
                    single_value(attributes, CmsAttribute::MESSAGE_DIGEST, "message-digest")?
                else {
                    return Err(CmsError::InvalidAttribute("message-digest"));
                };
                if message_digest.as_bytes() != expected.as_slice() {
                    return Err(CmsError::MessageDigestMismatch);
                }
                let Asn1Object::Oid(content_type) =
                    single_value(attributes, CmsAttribute::CONTENT_TYPE, "content-type")?
                else {
                    return Err(CmsError::InvalidAttribute("content-type"));
                };
                if content_type != *data.content_type() {
                    return Err(CmsError::ContentTypeMismatch);
                }
                Asn1SetOf::new(attributes.to_vec()).encode_to_vec(&EncodingOptions::DER)?
            }
            None => content.clone(),
        };
        let verified = self.algo.mac().verify_by_oid(
            data.mac_algorithm().algorithm(),
            &KeyOwned::new(key.to_vec()),
            &authenticated,
            data.mac(),
        )?;
        if !verified {
            return Err(CmsError::MacMismatch);
        }
        Ok(content)
    }
}

// 另外給的屬性優先，缺的 contentType 與 messageDigest 才補上
fn standard_attributes(
    generator: &CmsAuthenticatedDataGenerator,
    digest: &[u8],
) -> Result<Vec<Attribute>, CmsError> {
    let mut attributes = generator.auth_attributes.clone();
    let has = |attributes: &[Attribute], oid: &Asn1Oid| {
        attributes
            .iter()
            .any(|attribute| attribute.attribute_type() == oid)
    };
    let content_type = CmsAttribute::CONTENT_TYPE.oid();
    if !has(&attributes, &content_type) {
        let value = Asn1Object::Oid(generator.content_type.clone());
        attributes.push(Attribute::new(
            content_type,
            vec![AttributeValue::Other(value)],
        )?);
    }
    let message_digest = CmsAttribute::MESSAGE_DIGEST.oid();
    if !has(&attributes, &message_digest) {
        let value = Asn1Object::OctetString(Asn1OctetString::new(digest));
        attributes.push(Attribute::new(
            message_digest,
            vec![AttributeValue::Other(value)],
        )?);
    }
    Ok(attributes)
}

fn single_value(
    attributes: &[Attribute],
    attribute_type: tc_asn1::NamedOid,
    name: &'static str,
) -> Result<Asn1Object, CmsError> {
    let attribute = attributes
        .iter()
        .find(|attribute| attribute_type == *attribute.attribute_type())
        .ok_or(CmsError::InvalidAttribute(name))?;
    match attribute.values() {
        [AttributeValue::Other(value)] => Ok(value.clone()),
        _ => Err(CmsError::InvalidAttribute(name)),
    }
}
