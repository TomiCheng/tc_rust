use tc_algo::Params;
use tc_algo::params::key::{KeyOwned, KeyParams};
use tc_asn1::Asn1Oid;
use tc_asn1_cms::content::{ContentType, EncryptedData};
use tc_asn1_x500::Attribute;
use tc_zeroize::Zeroizing;

use crate::CmsError;
use crate::default_cms_operator::DefaultCmsOperator;
use crate::encrypted::{CmsEncryptedData, EncryptedDataProvider};

impl EncryptedDataProvider for DefaultCmsOperator {
    fn generate(
        &self,
        content: &[u8],
        encryption: &Asn1Oid,
        key: &dyn Params,
        unprotected: Vec<Attribute>,
    ) -> Result<CmsEncryptedData, CmsError> {
        let info =
            self.encrypt_content(&ContentType::DATA.oid(), encryption, key_of(key)?, content)?;
        let mut data = EncryptedData::new(info);
        if !unprotected.is_empty() {
            data = data.with_unprotected_attrs(unprotected);
        }
        Ok(CmsEncryptedData::new(data))
    }

    fn decrypt(
        &self,
        data: &CmsEncryptedData,
        key: &dyn Params,
    ) -> Result<Zeroizing<Vec<u8>>, CmsError> {
        self.decrypt_content(data.encrypted_data().encrypted_content_info(), key_of(key)?)
    }
}

fn key_of(key: &dyn Params) -> Result<&[u8], CmsError> {
    Ok(key
        .as_any()
        .downcast_ref::<KeyOwned>()
        .ok_or(CmsError::WrongRecipientKey)?
        .key())
}
