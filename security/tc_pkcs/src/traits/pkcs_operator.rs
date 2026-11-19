use crate::operator::encrypted_private_key_info::EncryptedPrivateKeyInfoProvider;
use crate::operator::private_key_info::PrivateKeyInfoProvider;

pub trait PkcsOperator: Send + Sync {
    // Private keys to and from PKCS#8
    fn private_key_info(&self) -> &dyn PrivateKeyInfoProvider;

    // PrivateKeyInfo to and from EncryptedPrivateKeyInfo with a password
    fn encrypted_private_key_info(&self) -> &dyn EncryptedPrivateKeyInfoProvider;
}
