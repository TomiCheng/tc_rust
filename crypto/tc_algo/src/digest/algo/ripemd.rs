use super::row::{TcDigest, row};
use crate::DefaultAlgoContext;
use crate::digest::DigestEntry;

// The rows of RIPEMD-128, RIPEMD-160, RIPEMD-256 and RIPEMD-320, to give to DefaultAlgoBuilder::reg_digest. Their names and OIDs
// are those of Bouncy Castle's DigestUtilities

#[cfg(feature = "ripemd128")]
pub(super) fn ripemd128(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("RIPEMD128", &["RIPEMD-128"], &["1.3.36.3.2.2"], || {
        Box::new(TcDigest(tc_ripemd::RipeMd128Digest::default()))
    })
}

#[cfg(feature = "ripemd160")]
pub(super) fn ripemd160(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("RIPEMD160", &["RIPEMD-160"], &["1.3.36.3.2.1"], || {
        Box::new(TcDigest(tc_ripemd::RipeMd160Digest::default()))
    })
}

#[cfg(feature = "ripemd256")]
pub(super) fn ripemd256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("RIPEMD256", &["RIPEMD-256"], &["1.3.36.3.2.3"], || {
        Box::new(TcDigest(tc_ripemd::RipeMd256Digest::default()))
    })
}

#[cfg(feature = "ripemd320")]
pub(super) fn ripemd320(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("RIPEMD320", &["RIPEMD-320"], &[], || {
        Box::new(TcDigest(tc_ripemd::RipeMd320Digest::default()))
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

    #[cfg(feature = "ripemd128")]
    #[test]
    fn the_ripemd128_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::ripemd128(&DefaultAlgoContext::for_tests()),
            tc_ripemd::RipeMd128Digest::default(),
            16,
        );
        find("RIPEMD128", &["RIPEMD-128"], &["1.3.36.3.2.2"]);
    }

    #[cfg(feature = "ripemd160")]
    #[test]
    fn the_ripemd160_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::ripemd160(&DefaultAlgoContext::for_tests()),
            tc_ripemd::RipeMd160Digest::default(),
            20,
        );
        find("RIPEMD160", &["RIPEMD-160"], &["1.3.36.3.2.1"]);
    }

    #[cfg(feature = "ripemd256")]
    #[test]
    fn the_ripemd256_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::ripemd256(&DefaultAlgoContext::for_tests()),
            tc_ripemd::RipeMd256Digest::default(),
            32,
        );
        find("RIPEMD256", &["RIPEMD-256"], &["1.3.36.3.2.3"]);
    }

    #[cfg(feature = "ripemd320")]
    #[test]
    fn the_ripemd320_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::ripemd320(&DefaultAlgoContext::for_tests()),
            tc_ripemd::RipeMd320Digest::default(),
            40,
        );
        find("RIPEMD320", &["RIPEMD-320"], &[]);
    }
}
