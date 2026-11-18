use tc_x509::X509Operator;

use crate::operator::private_key_info::PrivateKeyInfoProvider;

pub trait PkcsOperator: Send + Sync {
    // The X.509 operator underneath, for key pairs, public keys and signatures
    fn x509(&self) -> &dyn X509Operator;

    // Private keys to and from PKCS#8
    fn private_key_info(&self) -> &dyn PrivateKeyInfoProvider;
}
