use super::row::{TcDigest, row};
use crate::DefaultAlgoContext;
use crate::digest::DigestEntry;

// The rows of GOST R 34.11-94 and GOST R 34.11-2012 (Streebog), to give to DefaultAlgoBuilder::reg_digest. Their names and OIDs
// are those of Bouncy Castle's DigestUtilities

#[cfg(feature = "gost3411")]
pub(super) fn gost3411(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("GOST3411", &[], &["1.2.643.2.2.9"], || {
        Box::new(TcDigest(tc_gost3411::Gost3411Digest::default()))
    })
}

#[cfg(feature = "gost3411-2012-256")]
pub(super) fn gost3411_2012_256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("GOST3411-2012-256", &[], &["1.2.643.7.1.1.2.2"], || {
        Box::new(TcDigest(tc_gost3411::Gost3411_2012_256Digest::default()))
    })
}

#[cfg(feature = "gost3411-2012-512")]
pub(super) fn gost3411_2012_512(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("GOST3411-2012-512", &[], &["1.2.643.7.1.1.2.3"], || {
        Box::new(TcDigest(tc_gost3411::Gost3411_2012_512Digest::default()))
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

    #[cfg(feature = "gost3411")]
    #[test]
    fn the_gost3411_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::gost3411(&DefaultAlgoContext::for_tests()),
            tc_gost3411::Gost3411Digest::default(),
            32,
        );
        find("GOST3411", &[], &["1.2.643.2.2.9"]);
    }

    #[cfg(feature = "gost3411-2012-256")]
    #[test]
    fn the_gost3411_2012_256_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::gost3411_2012_256(&DefaultAlgoContext::for_tests()),
            tc_gost3411::Gost3411_2012_256Digest::default(),
            32,
        );
        find("GOST3411-2012-256", &[], &["1.2.643.7.1.1.2.2"]);
    }

    #[cfg(feature = "gost3411-2012-512")]
    #[test]
    fn the_gost3411_2012_512_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::gost3411_2012_512(&DefaultAlgoContext::for_tests()),
            tc_gost3411::Gost3411_2012_512Digest::default(),
            64,
        );
        find("GOST3411-2012-512", &[], &["1.2.643.7.1.1.2.3"]);
    }
}
