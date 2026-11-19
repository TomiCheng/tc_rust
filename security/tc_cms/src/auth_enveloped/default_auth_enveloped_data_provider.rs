use tc_algo::Params;
use tc_algo::params::cipher::AeadParamsOwned;
use tc_asn1::{Asn1Object, Asn1OctetString, Asn1Oid, Asn1SetOf, Encode, EncodingOptions};
use tc_asn1_cms::content::{AuthEnvelopedData, ContentType, EncryptedContentInfo};
use tc_asn1_cms::params::{CcmParameters, GcmParameters};
use tc_asn1_cms::signed::CmsAttribute;
use tc_asn1_x500::{Attribute, AttributeValue};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_zeroize::Zeroizing;

use crate::CmsError;
use crate::algorithms::aead;
use crate::auth_enveloped::{
    AuthEnvelopedDataProvider, CmsAuthEnvelopedData, CmsAuthEnvelopedDataGenerator,
};
use crate::default_cms_operator::DefaultCmsOperator;
use crate::der::convert;
use crate::enveloped::RecipientInformation;
use crate::enveloped::random;

const NONCE: usize = 12;
const ICV: u8 = 16;

impl AuthEnvelopedDataProvider for DefaultCmsOperator {
    fn generate(
        &self,
        generator: &CmsAuthEnvelopedDataGenerator,
        content: &[u8],
        encryption: &Asn1Oid,
    ) -> Result<CmsAuthEnvelopedData, CmsError> {
        let (key_length, gcm) = aead(encryption)?;
        let key = Zeroizing::new(random(key_length));
        let nonce = random(NONCE);

        // RFC 5083：內容型別不是 id-data 時，contentType 必須是 authenticated attribute
        let mut auth_attributes = generator.auth_attributes.clone();
        let content_type = CmsAttribute::CONTENT_TYPE.oid();
        let needs_type = !auth_attributes.is_empty() || ContentType::DATA != generator.content_type;
        if needs_type
            && !auth_attributes
                .iter()
                .any(|attribute| *attribute.attribute_type() == content_type)
        {
            auth_attributes.push(Attribute::new(
                content_type,
                vec![AttributeValue::Other(Asn1Object::Oid(
                    generator.content_type.clone(),
                ))],
            )?);
        }
        let aad = aad(&auth_attributes)?;

        let sealed = self.algo.cipher().encrypt_by_oid(
            encryption,
            &AeadParamsOwned::new(key.to_vec(), nonce.clone(), ICV as usize, aad),
            content,
        )?;
        let (encrypted, mac) = sealed.split_at(sealed.len() - ICV as usize);

        let mut recipients = Vec::new();
        for recipient in &generator.recipients {
            recipients.push(recipient.generate(self.algo.as_ref(), self.x509.as_ref(), &key)?);
        }

        let params: Asn1Object = if gcm {
            convert(&GcmParameters::new(Asn1OctetString::new(&nonce), ICV)?)?
        } else {
            convert(&CcmParameters::new(Asn1OctetString::new(&nonce), ICV)?)?
        };
        let info = EncryptedContentInfo::new(
            generator.content_type.clone(),
            AlgorithmIdentifier::with_parameters(encryption.clone(), params),
        )
        .with_encrypted_content(Asn1OctetString::new(encrypted));
        let mut data = AuthEnvelopedData::new(recipients, info, Asn1OctetString::new(mac));
        if !auth_attributes.is_empty() {
            data = data.with_auth_attrs(auth_attributes);
        }
        if !generator.unauth_attributes.is_empty() {
            data = data.with_unauth_attrs(generator.unauth_attributes.clone());
        }
        Ok(CmsAuthEnvelopedData::new(data))
    }

    fn decrypt(
        &self,
        data: &CmsAuthEnvelopedData,
        recipient: &RecipientInformation,
        key: &dyn Params,
    ) -> Result<Zeroizing<Vec<u8>>, CmsError> {
        let key = self.content_key(recipient, key)?;
        let algorithm = data.content_encryption_algorithm();
        let (key_length, gcm) = aead(algorithm.algorithm())?;
        if key.len() != key_length {
            return Err(CmsError::InvalidKey);
        }
        let params = algorithm.parameters().ok_or(CmsError::UnknownAlgorithm)?;
        let (nonce, icv) = if gcm {
            let params: GcmParameters = convert(params)?;
            (params.nonce().as_bytes().to_vec(), params.icv_len())
        } else {
            let params: CcmParameters = convert(params)?;
            (params.nonce().as_bytes().to_vec(), params.icv_len())
        };
        let mac = data.auth_enveloped_data().mac().as_bytes();
        if mac.len() != icv as usize {
            return Err(CmsError::UnknownAlgorithm);
        }
        let encrypted = data
            .auth_enveloped_data()
            .auth_encrypted_content_info()
            .encrypted_content()
            .ok_or(CmsError::MissingContent)?;
        let mut sealed = encrypted.as_bytes().to_vec();
        sealed.extend_from_slice(mac);
        let aad = aad(data.auth_attributes().unwrap_or_default())?;
        Ok(Zeroizing::new(self.algo.cipher().decrypt_by_oid(
            algorithm.algorithm(),
            &AeadParamsOwned::new(key.to_vec(), nonce, icv as usize, aad),
            &sealed,
        )?))
    }
}

// RFC 5083 section 2.2: the DER of the authenticated attributes under the SET OF tag, or nothing
fn aad(attributes: &[Attribute]) -> Result<Vec<u8>, CmsError> {
    if attributes.is_empty() {
        return Ok(Vec::new());
    }
    Ok(Asn1SetOf::new(attributes.to_vec()).encode_to_vec(&EncodingOptions::DER)?)
}
