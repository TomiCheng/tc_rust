use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::AlgoAsn1Error;
use crate::signer::Signer;

pub trait SignerProvider: Send + Sync {
    // A signer by its name or an alias, the case of which does not matter, with the
    // AlgorithmIdentifier its row writes; UnknownSigner when no row has the name
    fn get_by_name(&self, name: &str) -> Result<Box<dyn Signer>, AlgoAsn1Error>;

    // The signer an AlgorithmIdentifier being read calls for, which keeps that AlgorithmIdentifier;
    // UnknownSigner when no row matches it
    fn get_by_id(&self, algorithm: &AlgorithmIdentifier) -> Result<Box<dyn Signer>, AlgoAsn1Error>;
}
