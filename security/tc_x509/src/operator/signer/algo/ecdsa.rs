use tc_asn1_x509::alg::AlgorithmIdentifier;

use super::{ByOid, oid};
use crate::DefaultX509OperatorContext;
use crate::operator::signer::SignerEntry;

// The rows of ECDSA of X9.62, with the signature in DER and no parameters, as RFC 5758 section
// 3.2 requires
pub(super) fn ecdsa(_context: &DefaultX509OperatorContext) -> Vec<Box<dyn SignerEntry>> {
    [
        ("SHA-1withECDSA", "SHA1", "1.2.840.10045.4.1"),
        ("SHA-224withECDSA", "SHA224", "1.2.840.10045.4.3.1"),
        ("SHA-256withECDSA", "SHA256", "1.2.840.10045.4.3.2"),
        ("SHA-384withECDSA", "SHA384", "1.2.840.10045.4.3.3"),
        ("SHA-512withECDSA", "SHA512", "1.2.840.10045.4.3.4"),
    ]
    .into_iter()
    .map(|(name, digest, dotted)| {
        ByOid::boxed(
            name,
            &[&format!("{digest}withECDSA"), &format!("ECDSAwith{digest}")],
            AlgorithmIdentifier::new(oid(dotted)),
        )
    })
    .collect()
}
