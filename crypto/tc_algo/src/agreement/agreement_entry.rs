use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::agreement::Agreement;
use crate::{AlgoError, EntryBase};

pub trait AgreementEntry: EntryBase {
    // The agreement, or None for a row whose KDF needs the key-wrap algorithm of create_with_kdf
    fn create(&self) -> Option<Box<dyn Agreement>>;

    // The agreement whose KDF derives a key for the key-wrap algorithm `wrap`, as Bouncy Castle's
    // GetBasicAgreementWithKdf makes it, or None for a row without a KDF
    fn create_with_kdf(
        &self,
        _wrap: &AlgorithmIdentifier,
    ) -> Option<Result<Box<dyn Agreement>, AlgoError>> {
        None
    }
}
