use tc_asn1_x509::alg::AlgorithmIdentifier;

use super::{ByOid, oid};
use crate::DefaultAlgoAsn1Context;
use crate::signer::SignerEntry;

// The rows of DSA, with no parameters, as RFC 3279 section 2.2.2 and RFC 5758 section 3.1
// require
pub(super) fn dsa(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn SignerEntry>> {
    [
        ("SHA-1withDSA", "SHA1", "1.2.840.10040.4.3"),
        ("SHA-224withDSA", "SHA224", "2.16.840.1.101.3.4.3.1"),
        ("SHA-256withDSA", "SHA256", "2.16.840.1.101.3.4.3.2"),
    ]
    .into_iter()
    .map(|(name, digest, dotted)| {
        ByOid::boxed(
            name,
            &[&format!("{digest}withDSA"), &format!("DSAwith{digest}")],
            AlgorithmIdentifier::new(oid(dotted)),
        )
    })
    .collect()
}
