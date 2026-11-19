use std::sync::Arc;

use tc_algo::Algo;
use tc_x509::X509Operator;

use crate::PkcsOperator;
use crate::operator::encrypted_private_key_info::{
    DefaultEncryptedPrivateKeyInfoProvider, EncryptedPrivateKeyInfoProvider,
};
use crate::operator::private_key_info::{DefaultPrivateKeyInfoProvider, PrivateKeyInfoProvider};

pub(crate) struct DefaultPkcsOperator {
    #[allow(dead_code, reason = "PKCS#12 stores will use it")]
    algo: Arc<dyn Algo>,
    #[allow(dead_code, reason = "certification requests and PKCS#12 will use it")]
    x509: Arc<dyn X509Operator>,
    private_key_info: DefaultPrivateKeyInfoProvider,
    encrypted_private_key_info: DefaultEncryptedPrivateKeyInfoProvider,
}

impl DefaultPkcsOperator {
    pub(crate) fn new(
        algo: Arc<dyn Algo>,
        x509: Arc<dyn X509Operator>,
        private_key_info: DefaultPrivateKeyInfoProvider,
        encrypted_private_key_info: DefaultEncryptedPrivateKeyInfoProvider,
    ) -> Self {
        Self {
            algo,
            x509,
            private_key_info,
            encrypted_private_key_info,
        }
    }
}

impl PkcsOperator for DefaultPkcsOperator {
    fn private_key_info(&self) -> &dyn PrivateKeyInfoProvider {
        &self.private_key_info
    }

    fn encrypted_private_key_info(&self) -> &dyn EncryptedPrivateKeyInfoProvider {
        &self.encrypted_private_key_info
    }
}
