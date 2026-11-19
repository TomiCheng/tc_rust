use tc_asn1::{Asn1OctetString, Asn1Oid, tag};
use tc_asn1_cms::content::{ContentInfo, ContentType, DigestedData};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::CmsError;
use crate::default_cms_operator::DefaultCmsOperator;
use crate::digested::{CmsDigestedData, DigestedDataProvider};

impl DigestedDataProvider for DefaultCmsOperator {
    fn generate(&self, content: &[u8], digest: &Asn1Oid) -> Result<CmsDigestedData, CmsError> {
        let value = self.algo.digest().calculate_by_oid(digest, content)?;
        let encapsulated = ContentInfo::new(ContentType::DATA.oid())
            .with_content(tc_asn1::Asn1Any::primitive(tag::OCTET_STRING, content));
        Ok(CmsDigestedData::new(DigestedData::new(
            AlgorithmIdentifier::new(digest.clone()),
            encapsulated,
            Asn1OctetString::new(&value),
        )))
    }

    fn verify(&self, data: &CmsDigestedData) -> Result<Vec<u8>, CmsError> {
        let content = data.content()?.ok_or(CmsError::MissingContent)?;
        let value = self
            .algo
            .digest()
            .calculate_by_oid(data.digest_algorithm().algorithm(), &content)?;
        if value != data.digested_data().digest().as_bytes() {
            return Err(CmsError::MessageDigestMismatch);
        }
        Ok(content)
    }
}
