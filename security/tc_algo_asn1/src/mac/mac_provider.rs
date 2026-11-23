use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::AlgoAsn1Error;
use crate::mac::Asn1Mac;

pub trait MacProvider: Send + Sync {
    // A MAC by its name or an alias, the case of which does not matter, with the
    // AlgorithmIdentifier its row writes; UnknownMac when no row has the name
    fn get_by_name(&self, name: &str) -> Result<Box<dyn Asn1Mac>, AlgoAsn1Error>;

    // The MAC an AlgorithmIdentifier being read calls for, which keeps that AlgorithmIdentifier;
    // UnknownMac when no row matches it
    fn get_by_id(&self, algorithm: &AlgorithmIdentifier)
    -> Result<Box<dyn Asn1Mac>, AlgoAsn1Error>;
}
