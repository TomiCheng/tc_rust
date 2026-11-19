use tc_algo::Params;
use tc_asn1::Asn1Oid;
use tc_asn1_pkcs::{EncryptedPrivateKeyInfo, PrivateKeyInfo};

use crate::PkcsError;

pub trait EncryptedPrivateKeyInfoProvider: Send + Sync {
    // The first row that knows the scheme decides; UnknownEncryption when none does
    fn encrypt_by_name(
        &self,
        name: &str,
        params: &dyn Params,
        info: &PrivateKeyInfo,
    ) -> Result<EncryptedPrivateKeyInfo, PkcsError>;

    // The first row that knows the scheme decides; UnknownEncryption when none does
    fn encrypt_by_oid(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
        info: &PrivateKeyInfo,
    ) -> Result<EncryptedPrivateKeyInfo, PkcsError>;

    // The scheme is the one the encryption algorithm names. A wrong password usually fails on the
    // padding, as InvalidCiphertext, but now and then gives bytes that are no PrivateKeyInfo
    fn decrypt(
        &self,
        password: &str,
        info: &EncryptedPrivateKeyInfo,
    ) -> Result<PrivateKeyInfo, PkcsError>;
}
