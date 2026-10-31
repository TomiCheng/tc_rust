#[allow(
    unused_imports,
    reason = "the table is empty when every digest feature is off"
)]
use tc_asn1::NamedOid;

#[allow(
    unused_imports,
    reason = "the table is empty when every digest feature is off"
)]
use super::Algorithm;
use super::DigestEntry;

// One row per digest. Names, aliases and OIDs follow Bouncy Castle's DigestUtilities: the first
// name is the canonical one, the first OID is the digest's own (DigestInfo uses it), and the rest
// map to the same row as in Bouncy Castle, HMAC OIDs included
pub(super) const DIGESTS: &[DigestEntry] = &[
    #[cfg(feature = "sha256")]
    DigestEntry::new(
        Algorithm::Sha256,
        &["SHA-256", "SHA256"],
        &[
            NamedOid::new(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
                "2.16.840.1.101.3.4.2.1",
                "id-sha256",
            ),
            NamedOid::new(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09],
                "1.2.840.113549.2.9",
                "id-hmacWithSHA256",
            ),
        ],
        || Box::new(tc_sha::Sha256Digest::new()),
    ),
];
