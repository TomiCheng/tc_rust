use tc_asn1_x509::alg::AlgorithmIdentifier;

use super::{ByOid, oid};
use crate::DefaultAlgoAsn1Context;
use crate::signer::SignerEntry;

// The rows of RSA PKCS#1 v1.5. The names are those of Bouncy Castle, and the parameters are NULL,
// as RFC 4055 section 5 requires
pub(super) fn rsa(_context: &DefaultAlgoAsn1Context) -> Vec<Box<dyn SignerEntry>> {
    [
        ("SHA-1withRSA", "SHA1", "1.2.840.113549.1.1.5"),
        ("SHA-224withRSA", "SHA224", "1.2.840.113549.1.1.14"),
        ("SHA-256withRSA", "SHA256", "1.2.840.113549.1.1.11"),
        ("SHA-384withRSA", "SHA384", "1.2.840.113549.1.1.12"),
        ("SHA-512withRSA", "SHA512", "1.2.840.113549.1.1.13"),
    ]
    .into_iter()
    .map(|(name, digest, dotted)| {
        let full = &name[..name.len() - "withRSA".len()];
        ByOid::boxed(
            name,
            &[
                &format!("{digest}withRSA"),
                &format!("{digest}withRSAEncryption"),
                &format!("{full}withRSAEncryption"),
            ],
            AlgorithmIdentifier::with_null(oid(dotted)),
        )
    })
    .collect()
}
