use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::AlgoAsn1Error;
use crate::digest::Asn1Digest;

pub trait DigestProvider: Send + Sync {
    // A digest by its name or an alias, the case of which does not matter, with the
    // AlgorithmIdentifier its row writes; UnknownDigest when no row has the name
    fn get_by_name(&self, name: &str) -> Result<Box<dyn Asn1Digest>, AlgoAsn1Error>;

    // The digest an AlgorithmIdentifier being read calls for, which keeps that AlgorithmIdentifier;
    // UnknownDigest when no row matches it
    fn get_by_id(
        &self,
        algorithm: &AlgorithmIdentifier,
    ) -> Result<Box<dyn Asn1Digest>, AlgoAsn1Error>;

    // The digest a signature algorithm hashes with, as CMS writes beside a signature: RSASSA-PSS
    // by the hash of its parameters, any other by the rows that list it. The AlgorithmIdentifier is
    // the one the row writes; UnknownDigest when no row has it
    fn get_by_signer(
        &self,
        signature: &AlgorithmIdentifier,
    ) -> Result<Box<dyn Asn1Digest>, AlgoAsn1Error>;
}
