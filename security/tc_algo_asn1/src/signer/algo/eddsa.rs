use tc_asn1_x509::alg::AlgorithmIdentifier;

use super::{ByOid, oid};
use crate::DefaultAlgoAsn1Context;
use crate::signer::SignerEntry;

// Ed25519 and Ed448 of RFC 8410, whose parameters are absent
pub(super) fn eddsa(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn SignerEntry>> {
    vec![
        ByOid::boxed("Ed25519", &[], AlgorithmIdentifier::new(oid("1.3.101.112"))),
        ByOid::boxed("Ed448", &[], AlgorithmIdentifier::new(oid("1.3.101.113"))),
    ]
}
