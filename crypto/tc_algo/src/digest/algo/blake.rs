use super::row::{TcDigest, row};
use crate::DefaultAlgoContext;
use crate::digest::DigestEntry;

// The rows of BLAKE2b, BLAKE2s and BLAKE3, to give to DefaultAlgoBuilder::reg_digest. Their names and OIDs
// are those of Bouncy Castle's DigestUtilities

#[cfg(feature = "blake2b-160")]
pub(super) fn blake2b_160(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("BLAKE2B-160", &[], &["1.3.6.1.4.1.1722.12.2.1.5"], || {
        Box::new(TcDigest(tc_blake::Blake2bDigest::with_digest_size(160)))
    })
}

#[cfg(feature = "blake2b-256")]
pub(super) fn blake2b_256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("BLAKE2B-256", &[], &["1.3.6.1.4.1.1722.12.2.1.8"], || {
        Box::new(TcDigest(tc_blake::Blake2bDigest::with_digest_size(256)))
    })
}

#[cfg(feature = "blake2b-384")]
pub(super) fn blake2b_384(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("BLAKE2B-384", &[], &["1.3.6.1.4.1.1722.12.2.1.12"], || {
        Box::new(TcDigest(tc_blake::Blake2bDigest::with_digest_size(384)))
    })
}

#[cfg(feature = "blake2b-512")]
pub(super) fn blake2b_512(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("BLAKE2B-512", &[], &["1.3.6.1.4.1.1722.12.2.1.16"], || {
        Box::new(TcDigest(tc_blake::Blake2bDigest::with_digest_size(512)))
    })
}

#[cfg(feature = "blake2s-128")]
pub(super) fn blake2s_128(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("BLAKE2S-128", &[], &["1.3.6.1.4.1.1722.12.2.2.4"], || {
        Box::new(TcDigest(tc_blake::Blake2sDigest::with_digest_size(128)))
    })
}

#[cfg(feature = "blake2s-160")]
pub(super) fn blake2s_160(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("BLAKE2S-160", &[], &["1.3.6.1.4.1.1722.12.2.2.5"], || {
        Box::new(TcDigest(tc_blake::Blake2sDigest::with_digest_size(160)))
    })
}

#[cfg(feature = "blake2s-224")]
pub(super) fn blake2s_224(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("BLAKE2S-224", &[], &["1.3.6.1.4.1.1722.12.2.2.7"], || {
        Box::new(TcDigest(tc_blake::Blake2sDigest::with_digest_size(224)))
    })
}

#[cfg(feature = "blake2s-256")]
pub(super) fn blake2s_256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("BLAKE2S-256", &[], &["1.3.6.1.4.1.1722.12.2.2.8"], || {
        Box::new(TcDigest(tc_blake::Blake2sDigest::with_digest_size(256)))
    })
}

#[cfg(feature = "blake3-256")]
pub(super) fn blake3_256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("BLAKE3-256", &[], &["1.3.6.1.4.1.1722.12.2.3.8"], || {
        Box::new(TcDigest(tc_blake::Blake3Digest::with_digest_size(256)))
    })
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
        digest.try_update(b"a").unwrap();
        digest.try_update(b"bc").unwrap();

        direct.update(b"abc");
        let mut expected = vec![0; size];
        direct.do_final(&mut expected);
        assert_eq!(digest.finalize().unwrap(), expected);
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

    #[cfg(feature = "blake2b-160")]
    #[test]
    fn the_blake2b_160_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::blake2b_160(&DefaultAlgoContext::for_tests()),
            tc_blake::Blake2bDigest::with_digest_size(160),
            20,
        );
        find("BLAKE2B-160", &[], &["1.3.6.1.4.1.1722.12.2.1.5"]);
    }

    #[cfg(feature = "blake2b-256")]
    #[test]
    fn the_blake2b_256_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::blake2b_256(&DefaultAlgoContext::for_tests()),
            tc_blake::Blake2bDigest::with_digest_size(256),
            32,
        );
        find("BLAKE2B-256", &[], &["1.3.6.1.4.1.1722.12.2.1.8"]);
    }

    #[cfg(feature = "blake2b-384")]
    #[test]
    fn the_blake2b_384_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::blake2b_384(&DefaultAlgoContext::for_tests()),
            tc_blake::Blake2bDigest::with_digest_size(384),
            48,
        );
        find("BLAKE2B-384", &[], &["1.3.6.1.4.1.1722.12.2.1.12"]);
    }

    #[cfg(feature = "blake2b-512")]
    #[test]
    fn the_blake2b_512_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::blake2b_512(&DefaultAlgoContext::for_tests()),
            tc_blake::Blake2bDigest::with_digest_size(512),
            64,
        );
        find("BLAKE2B-512", &[], &["1.3.6.1.4.1.1722.12.2.1.16"]);
    }

    #[cfg(feature = "blake2s-128")]
    #[test]
    fn the_blake2s_128_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::blake2s_128(&DefaultAlgoContext::for_tests()),
            tc_blake::Blake2sDigest::with_digest_size(128),
            16,
        );
        find("BLAKE2S-128", &[], &["1.3.6.1.4.1.1722.12.2.2.4"]);
    }

    #[cfg(feature = "blake2s-160")]
    #[test]
    fn the_blake2s_160_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::blake2s_160(&DefaultAlgoContext::for_tests()),
            tc_blake::Blake2sDigest::with_digest_size(160),
            20,
        );
        find("BLAKE2S-160", &[], &["1.3.6.1.4.1.1722.12.2.2.5"]);
    }

    #[cfg(feature = "blake2s-224")]
    #[test]
    fn the_blake2s_224_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::blake2s_224(&DefaultAlgoContext::for_tests()),
            tc_blake::Blake2sDigest::with_digest_size(224),
            28,
        );
        find("BLAKE2S-224", &[], &["1.3.6.1.4.1.1722.12.2.2.7"]);
    }

    #[cfg(feature = "blake2s-256")]
    #[test]
    fn the_blake2s_256_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::blake2s_256(&DefaultAlgoContext::for_tests()),
            tc_blake::Blake2sDigest::with_digest_size(256),
            32,
        );
        find("BLAKE2S-256", &[], &["1.3.6.1.4.1.1722.12.2.2.8"]);
    }

    #[cfg(feature = "blake3-256")]
    #[test]
    fn the_blake3_256_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::blake3_256(&DefaultAlgoContext::for_tests()),
            tc_blake::Blake3Digest::with_digest_size(256),
            32,
        );
        find("BLAKE3-256", &[], &["1.3.6.1.4.1.1722.12.2.3.8"]);
    }
}
