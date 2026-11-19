use std::sync::Arc;

use tc_algo::{Algo, Params};
use tc_asn1::{Asn1Oid, Encode, EncodingOptions};
use tc_asn1_pkcs::{EncryptedPrivateKeyInfo, PrivateKeyInfo};
use tc_zeroize::Zeroizing;

use crate::PkcsError;
use crate::der::decode_all;
use crate::operator::encrypted_private_key_info::{
    EncryptedPrivateKeyInfoEntry, EncryptedPrivateKeyInfoProvider,
};

// The rows in the order they are tried, the last registered first
pub(crate) struct DefaultEncryptedPrivateKeyInfoProvider {
    algo: Arc<dyn Algo>,
    rows: Vec<Box<dyn EncryptedPrivateKeyInfoEntry>>,
}

impl DefaultEncryptedPrivateKeyInfoProvider {
    pub(crate) fn new(
        algo: Arc<dyn Algo>,
        rows: Vec<Box<dyn EncryptedPrivateKeyInfoEntry>>,
    ) -> Self {
        Self { algo, rows }
    }
}

// Any bytes, not only a PrivateKeyInfo, for the encryptedData of PKCS#12, which takes the same
// AlgorithmIdentifier
impl DefaultEncryptedPrivateKeyInfoProvider {
    pub(crate) fn encrypt_bytes_by_oid(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
        plain: &[u8],
    ) -> Result<EncryptedPrivateKeyInfo, PkcsError> {
        self.rows
            .iter()
            .find_map(|row| row.encrypt_by_oid(self.algo.as_ref(), oid, params, plain))
            .unwrap_or(Err(PkcsError::UnknownEncryption))
    }

    pub(crate) fn decrypt_bytes(
        &self,
        password: &str,
        info: &EncryptedPrivateKeyInfo,
    ) -> Result<Zeroizing<Vec<u8>>, PkcsError> {
        self.rows
            .iter()
            .find_map(|row| row.decrypt(self.algo.as_ref(), password, info))
            .unwrap_or(Err(PkcsError::UnknownEncryption))
    }
}

fn plain(info: &PrivateKeyInfo) -> Result<Zeroizing<Vec<u8>>, PkcsError> {
    Ok(Zeroizing::new(info.encode_to_vec(&EncodingOptions::DER)?))
}

impl EncryptedPrivateKeyInfoProvider for DefaultEncryptedPrivateKeyInfoProvider {
    fn encrypt_by_name(
        &self,
        name: &str,
        params: &dyn Params,
        info: &PrivateKeyInfo,
    ) -> Result<EncryptedPrivateKeyInfo, PkcsError> {
        let plain = plain(info)?;
        self.rows
            .iter()
            .find_map(|row| row.encrypt_by_name(self.algo.as_ref(), name, params, &plain))
            .unwrap_or(Err(PkcsError::UnknownEncryption))
    }

    fn encrypt_by_oid(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
        info: &PrivateKeyInfo,
    ) -> Result<EncryptedPrivateKeyInfo, PkcsError> {
        self.encrypt_bytes_by_oid(oid, params, &plain(info)?)
    }

    fn decrypt(
        &self,
        password: &str,
        info: &EncryptedPrivateKeyInfo,
    ) -> Result<PrivateKeyInfo, PkcsError> {
        decode_all(&self.decrypt_bytes(password, info)?)
    }
}
