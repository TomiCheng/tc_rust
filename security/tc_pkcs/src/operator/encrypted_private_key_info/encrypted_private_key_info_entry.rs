use tc_algo::{Algo, Params};
use tc_asn1::Asn1Oid;
use tc_asn1_pkcs::EncryptedPrivateKeyInfo;
use tc_zeroize::Zeroizing;

use crate::PkcsError;

// A row of encryption schemes. `plain` is the DER of a PrivateKeyInfo, and decrypt gives it back
pub trait EncryptedPrivateKeyInfoEntry: Send + Sync {
    // None when `name` is not a scheme of this row, so that the next row is tried
    fn encrypt_by_name(
        &self,
        algo: &dyn Algo,
        name: &str,
        params: &dyn Params,
        plain: &[u8],
    ) -> Option<Result<EncryptedPrivateKeyInfo, PkcsError>>;

    // None when `oid` is not a scheme of this row, so that the next row is tried
    fn encrypt_by_oid(
        &self,
        algo: &dyn Algo,
        oid: &Asn1Oid,
        params: &dyn Params,
        plain: &[u8],
    ) -> Option<Result<EncryptedPrivateKeyInfo, PkcsError>>;

    // None when the encryption algorithm is not one of this row, so that the next row is tried
    fn decrypt(
        &self,
        algo: &dyn Algo,
        password: &str,
        info: &EncryptedPrivateKeyInfo,
    ) -> Option<Result<Zeroizing<Vec<u8>>, PkcsError>>;
}
