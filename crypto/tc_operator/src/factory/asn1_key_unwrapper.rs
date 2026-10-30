use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_security::cipher;
use tc_security::params::AnyParams;

use super::rsa_key_wrap::RsaKeyWrap;
use crate::{KeyUnwrapper, OperatorError};

pub struct Asn1KeyUnwrapper {
    wrap: RsaKeyWrap,
    key: AnyParams,
}

impl Asn1KeyUnwrapper {
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

impl KeyUnwrapper for Asn1KeyUnwrapper {
    type Error = OperatorError;

    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.wrap.algorithm
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, OperatorError> {
        let mut cipher = cipher::get_by_name(self.wrap.cipher)?.cipher();
        Ok(cipher::decrypt(&mut cipher, &self.key, wrapped)?)
    }
}
