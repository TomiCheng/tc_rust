use super::row::{TcDigest, row};
use crate::DefaultAlgoContext;
use crate::digest::DigestEntry;

// The rows of Keccak, SHA-3 and SHAKE at a fixed size, to give to DefaultAlgoBuilder::reg_digest.
// Their names and OIDs are those of Bouncy Castle's DigestUtilities, the HMAC OIDs included

#[cfg(feature = "keccak-224")]
pub(super) fn keccak_224(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("KECCAK-224", &["KECCAK224"], &[], || {
        Box::new(TcDigest(tc_keccak::KeccakDigest::new(224)))
    })
}

#[cfg(feature = "keccak-256")]
pub(super) fn keccak_256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("KECCAK-256", &["KECCAK256"], &[], || {
        Box::new(TcDigest(tc_keccak::KeccakDigest::new(256)))
    })
}

#[cfg(feature = "keccak-288")]
pub(super) fn keccak_288(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("KECCAK-288", &["KECCAK288"], &[], || {
        Box::new(TcDigest(tc_keccak::KeccakDigest::new(288)))
    })
}

#[cfg(feature = "keccak-384")]
pub(super) fn keccak_384(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("KECCAK-384", &["KECCAK384"], &[], || {
        Box::new(TcDigest(tc_keccak::KeccakDigest::new(384)))
    })
}

#[cfg(feature = "keccak-512")]
pub(super) fn keccak_512(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("KECCAK-512", &["KECCAK512"], &[], || {
        Box::new(TcDigest(tc_keccak::KeccakDigest::new(512)))
    })
}

#[cfg(feature = "sha3-224")]
pub(super) fn sha3_224(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row(
        "SHA3-224",
        &[],
        &["2.16.840.1.101.3.4.2.7", "2.16.840.1.101.3.4.2.13"],
        || Box::new(TcDigest(tc_keccak::Sha3Digest::new(224))),
    )
}

#[cfg(feature = "sha3-256")]
pub(super) fn sha3_256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row(
        "SHA3-256",
        &[],
        &["2.16.840.1.101.3.4.2.8", "2.16.840.1.101.3.4.2.14"],
        || Box::new(TcDigest(tc_keccak::Sha3Digest::new(256))),
    )
}

#[cfg(feature = "sha3-384")]
pub(super) fn sha3_384(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row(
        "SHA3-384",
        &[],
        &["2.16.840.1.101.3.4.2.9", "2.16.840.1.101.3.4.2.15"],
        || Box::new(TcDigest(tc_keccak::Sha3Digest::new(384))),
    )
}

#[cfg(feature = "sha3-512")]
pub(super) fn sha3_512(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row(
        "SHA3-512",
        &[],
        &["2.16.840.1.101.3.4.2.10", "2.16.840.1.101.3.4.2.16"],
        || Box::new(TcDigest(tc_keccak::Sha3Digest::new(512))),
    )
}

#[cfg(feature = "shake128-256")]
pub(super) fn shake128_256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row(
        "SHAKE128-256",
        &["SHAKE128", "SHAKE-128"],
        &["2.16.840.1.101.3.4.2.11"],
        || Box::new(TcDigest(tc_keccak::ShakeDigest::new(128))),
    )
}

#[cfg(feature = "shake256-512")]
pub(super) fn shake256_512(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row(
        "SHAKE256-512",
        &["SHAKE256", "SHAKE-256"],
        &["2.16.840.1.101.3.4.2.12"],
        || Box::new(TcDigest(tc_keccak::ShakeDigest::new(256))),
    )
}

#[cfg(test)]
mod tests {
    use crate::DefaultAlgoContext;
    use crate::digest::DigestEntry;

    // The row gives the hash of the digest it wraps, at its size
    fn check(rows: Vec<Box<dyn DigestEntry>>, mut direct: impl tc_digest::Digest, size: usize) {
        let row = &rows[0];
        let mut digest = row.create();
        assert_eq!(digest.digest_size(), size);
        digest.update(b"a");
        digest.update(b"bc");

        direct.update(b"abc");
        let mut expected = vec![0; size];
        direct.do_final(&mut expected);
        assert_eq!(digest.finalize(), expected);
    }

    // Every name, alias and OID of the row finds it through the factory
    fn find(name: &str, aliases: &[&str], oids: &[&str]) {
        use crate::AlgoBuilder as _;
        let algo = crate::DefaultAlgoBuilder::default().build();
        for name in std::iter::once(&name).chain(aliases) {
            assert!(algo.digest().get_by_name(name).is_ok(), "{name}");
        }
        for oid in oids {
            assert!(
                algo.digest().get_by_oid(&oid.parse().unwrap()).is_ok(),
                "{oid}"
            );
        }
    }

    #[cfg(feature = "keccak-224")]
    #[test]
    fn the_keccak_224_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::keccak_224(&DefaultAlgoContext::for_tests()),
            tc_keccak::KeccakDigest::new(224),
            28,
        );
        find("KECCAK-224", &["KECCAK224"], &[]);
    }

    #[cfg(feature = "keccak-256")]
    #[test]
    fn the_keccak_256_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::keccak_256(&DefaultAlgoContext::for_tests()),
            tc_keccak::KeccakDigest::new(256),
            32,
        );
        find("KECCAK-256", &["KECCAK256"], &[]);
    }

    #[cfg(feature = "keccak-288")]
    #[test]
    fn the_keccak_288_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::keccak_288(&DefaultAlgoContext::for_tests()),
            tc_keccak::KeccakDigest::new(288),
            36,
        );
        find("KECCAK-288", &["KECCAK288"], &[]);
    }

    #[cfg(feature = "keccak-384")]
    #[test]
    fn the_keccak_384_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::keccak_384(&DefaultAlgoContext::for_tests()),
            tc_keccak::KeccakDigest::new(384),
            48,
        );
        find("KECCAK-384", &["KECCAK384"], &[]);
    }

    #[cfg(feature = "keccak-512")]
    #[test]
    fn the_keccak_512_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::keccak_512(&DefaultAlgoContext::for_tests()),
            tc_keccak::KeccakDigest::new(512),
            64,
        );
        find("KECCAK-512", &["KECCAK512"], &[]);
    }

    #[cfg(feature = "sha3-224")]
    #[test]
    fn the_sha3_224_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::sha3_224(&DefaultAlgoContext::for_tests()),
            tc_keccak::Sha3Digest::new(224),
            28,
        );
        find(
            "SHA3-224",
            &[],
            &["2.16.840.1.101.3.4.2.7", "2.16.840.1.101.3.4.2.13"],
        );
    }

    #[cfg(feature = "sha3-256")]
    #[test]
    fn the_sha3_256_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::sha3_256(&DefaultAlgoContext::for_tests()),
            tc_keccak::Sha3Digest::new(256),
            32,
        );
        find(
            "SHA3-256",
            &[],
            &["2.16.840.1.101.3.4.2.8", "2.16.840.1.101.3.4.2.14"],
        );
    }

    #[cfg(feature = "sha3-384")]
    #[test]
    fn the_sha3_384_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::sha3_384(&DefaultAlgoContext::for_tests()),
            tc_keccak::Sha3Digest::new(384),
            48,
        );
        find(
            "SHA3-384",
            &[],
            &["2.16.840.1.101.3.4.2.9", "2.16.840.1.101.3.4.2.15"],
        );
    }

    #[cfg(feature = "sha3-512")]
    #[test]
    fn the_sha3_512_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::sha3_512(&DefaultAlgoContext::for_tests()),
            tc_keccak::Sha3Digest::new(512),
            64,
        );
        find(
            "SHA3-512",
            &[],
            &["2.16.840.1.101.3.4.2.10", "2.16.840.1.101.3.4.2.16"],
        );
    }

    #[cfg(feature = "shake128-256")]
    #[test]
    fn the_shake128_256_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::shake128_256(&DefaultAlgoContext::for_tests()),
            tc_keccak::ShakeDigest::new(128),
            32,
        );
        find(
            "SHAKE128-256",
            &["SHAKE128", "SHAKE-128"],
            &["2.16.840.1.101.3.4.2.11"],
        );
    }

    #[cfg(feature = "shake256-512")]
    #[test]
    fn the_shake256_512_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::shake256_512(&DefaultAlgoContext::for_tests()),
            tc_keccak::ShakeDigest::new(256),
            64,
        );
        find(
            "SHAKE256-512",
            &["SHAKE256", "SHAKE-256"],
            &["2.16.840.1.101.3.4.2.12"],
        );
    }
}
