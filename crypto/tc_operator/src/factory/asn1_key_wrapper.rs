use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_security::cipher;
use tc_security::params::AnyParams;

use super::rsa_key_wrap::RsaKeyWrap;
use crate::{KeyWrapper, OperatorError};

pub struct Asn1KeyWrapper {
    wrap: RsaKeyWrap,
    key: AnyParams,
}

impl Asn1KeyWrapper {
    pub fn new(algorithm: &str, key: AnyParams) -> Result<Self, OperatorError> {
        Ok(Self {
            wrap: RsaKeyWrap::by_name(algorithm)?,
            key,
        })
    }

    pub fn with_algorithm(
        algorithm: &AlgorithmIdentifier,
        key: AnyParams,
    ) -> Result<Self, OperatorError> {
        Ok(Self {
            wrap: RsaKeyWrap::by_algorithm(algorithm)?,
            key,
        })
    }
}

impl KeyWrapper for Asn1KeyWrapper {
    type Error = OperatorError;

    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.wrap.algorithm
    }

    fn wrap(&self, key: &[u8]) -> Result<Vec<u8>, OperatorError> {
        let mut cipher = cipher::get_by_name(self.wrap.cipher)?.cipher();
        Ok(cipher::encrypt(&mut cipher, &self.key, key)?)
    }
}
