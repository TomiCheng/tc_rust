use crate::operator::encrypted_private_key_info::EncryptedPrivateKeyInfoProvider;
use crate::operator::private_key_info::PrivateKeyInfoProvider;
use crate::pkcs12::Pkcs12Provider;

pub trait PkcsOperator: Send + Sync {
    // Private keys to and from PKCS#8
    fn private_key_info(&self) -> &dyn PrivateKeyInfoProvider;

    // PrivateKeyInfo to and from EncryptedPrivateKeyInfo with a password
    fn encrypted_private_key_info(&self) -> &dyn EncryptedPrivateKeyInfoProvider;

    // PKCS#12 files to and from a Pkcs12Store
    fn pkcs12(&self) -> &dyn Pkcs12Provider;
}
