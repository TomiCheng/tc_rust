use tc_asn1::Asn1Oid;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::AlgoError;
use crate::agreement::{Agreement, AgreementEntry};

pub trait AgreementProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn AgreementEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Agreement>, AlgoError>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Agreement>, AlgoError>;

    // Bouncy Castle's GetBasicAgreementWithKdf: an agreement whose KDF derives a key for the
    // key-wrap algorithm `wrap`, of its default key size
    fn get_with_kdf_by_name(
        &self,
        name: &str,
        wrap: &AlgorithmIdentifier,
    ) -> Result<Box<dyn Agreement>, AlgoError>;

    fn get_with_kdf_by_oid(
        &self,
        oid: &Asn1Oid,
        wrap: &AlgorithmIdentifier,
    ) -> Result<Box<dyn Agreement>, AlgoError>;
}
