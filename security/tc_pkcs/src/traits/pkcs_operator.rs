use crate::operator::private_key_info::PrivateKeyInfoProvider;

pub trait PkcsOperator: Send + Sync {
    // Private keys to and from PKCS#8
    fn private_key_info(&self) -> &dyn PrivateKeyInfoProvider;
}
