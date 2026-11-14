use super::row::{TcDigest, row};
use crate::DefaultAlgoContext;
use crate::digest::DigestEntry;

// The rows of DSTU 7564 (Kupyna), to give to DefaultAlgoBuilder::reg_digest. Their names and OIDs
// are those of Bouncy Castle's DigestUtilities

#[cfg(feature = "dstu7564-256")]
pub(super) fn dstu7564_256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("DSTU7564-256", &[], &["1.2.804.2.1.1.1.1.2.2.1"], || {
        Box::new(TcDigest(tc_dstu7564::Dstu7564Digest::new(256)))
    })
}

#[cfg(feature = "dstu7564-384")]
pub(super) fn dstu7564_384(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("DSTU7564-384", &[], &["1.2.804.2.1.1.1.1.2.2.2"], || {
        Box::new(TcDigest(tc_dstu7564::Dstu7564Digest::new(384)))
    })
}

#[cfg(feature = "dstu7564-512")]
pub(super) fn dstu7564_512(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("DSTU7564-512", &[], &["1.2.804.2.1.1.1.1.2.2.3"], || {
        Box::new(TcDigest(tc_dstu7564::Dstu7564Digest::new(512)))
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

    #[cfg(feature = "dstu7564-256")]
    #[test]
    fn the_dstu7564_256_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::dstu7564_256(&DefaultAlgoContext::for_tests()),
            tc_dstu7564::Dstu7564Digest::new(256),
            32,
        );
        find("DSTU7564-256", &[], &["1.2.804.2.1.1.1.1.2.2.1"]);
    }

    #[cfg(feature = "dstu7564-384")]
    #[test]
    fn the_dstu7564_384_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::dstu7564_384(&DefaultAlgoContext::for_tests()),
            tc_dstu7564::Dstu7564Digest::new(384),
            48,
        );
        find("DSTU7564-384", &[], &["1.2.804.2.1.1.1.1.2.2.2"]);
    }

    #[cfg(feature = "dstu7564-512")]
    #[test]
    fn the_dstu7564_512_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::dstu7564_512(&DefaultAlgoContext::for_tests()),
            tc_dstu7564::Dstu7564Digest::new(512),
            64,
        );
        find("DSTU7564-512", &[], &["1.2.804.2.1.1.1.1.2.2.3"]);
    }
}
