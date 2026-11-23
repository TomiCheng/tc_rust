use tc_asn1_x509::alg::AlgorithmIdentifier;

use super::{ByOid, oid};
use crate::DefaultAlgoAsn1Context;
use crate::signer::SignerEntry;

// SM2 of GM/T 0006, with no parameters, as Bouncy Castle's Asn1SignatureFactory writes it. The
// user ID SM2 hashes in is not in the AlgorithmIdentifier; the signer takes it when initialized
pub(super) fn sm2(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn SignerEntry>> {
    vec![
        ByOid::boxed(
            "SM3withSM2",
            &[],
            AlgorithmIdentifier::new(oid("1.2.156.10197.1.501")),
        ),
        ByOid::boxed(
            "SHA256withSM2",
            &[],
            AlgorithmIdentifier::new(oid("1.2.156.10197.1.503")),
        ),
    ]
}
