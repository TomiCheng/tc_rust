use tc_asn1::Asn1Oid;

use super::Asn1CipherBuilderWithKey;
use crate::OperatorError;

pub struct CmsContentEncryptorBuilder {
    encryption_oid: Asn1Oid,
    key_size: Option<usize>,
}

impl CmsContentEncryptorBuilder {
    pub fn new(encryption_oid: Asn1Oid) -> Self {
        Self {
            encryption_oid,
            key_size: None,
        }
    }

    pub fn with_key_size(mut self, key_size: usize) -> Self {
        self.key_size = Some(key_size);
        self
    }

    pub fn build(&self) -> Result<Asn1CipherBuilderWithKey, OperatorError> {
        Asn1CipherBuilderWithKey::new(&self.encryption_oid, self.key_size)
    }
}
