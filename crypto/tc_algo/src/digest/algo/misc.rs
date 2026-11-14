use super::row::{TcDigest, row};
use crate::DefaultAlgoContext;
use crate::digest::DigestEntry;

// The rows of Tiger, Whirlpool, PHOTON-Beetle, ESCH and Xoodyak, to give to
// DefaultAlgoBuilder::reg_digest. Tiger and Whirlpool are named as Bouncy Castle's DigestUtilities
// names them; it has none of the others, so they have no alias or OID

#[cfg(feature = "tiger")]
pub(super) fn tiger(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("TIGER", &[], &[], || {
        Box::new(TcDigest(tc_misc_digest::TigerDigest::default()))
    })
}

#[cfg(feature = "whirlpool")]
pub(super) fn whirlpool(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("WHIRLPOOL", &[], &[], || {
        Box::new(TcDigest(tc_misc_digest::WhirlpoolDigest::default()))
    })
}

#[cfg(feature = "photon-beetle")]
pub(super) fn photon_beetle(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("PHOTON-BEETLE", &[], &[], || {
        Box::new(TcDigest(tc_misc_digest::PhotonBeetleDigest::new()))
    })
}

#[cfg(feature = "esch-256")]
pub(super) fn esch_256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("ESCH-256", &[], &[], || {
        Box::new(TcDigest(tc_misc_digest::SparkleDigest::new(
            tc_misc_digest::SparkleParameters::Esch256,
        )))
    })
}

#[cfg(feature = "esch-384")]
pub(super) fn esch_384(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("ESCH-384", &[], &[], || {
        Box::new(TcDigest(tc_misc_digest::SparkleDigest::new(
            tc_misc_digest::SparkleParameters::Esch384,
        )))
    })
}

#[cfg(feature = "xoodyak")]
pub(super) fn xoodyak(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("XOODYAK", &[], &[], || {
        Box::new(TcDigest(tc_misc_digest::XoodyakDigest::new()))
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

    #[cfg(feature = "tiger")]
    #[test]
    fn the_tiger_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::tiger(&DefaultAlgoContext::for_tests()),
            tc_misc_digest::TigerDigest::default(),
            24,
        );
        find("TIGER", &[], &[]);
    }

    #[cfg(feature = "whirlpool")]
    #[test]
    fn the_whirlpool_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::whirlpool(&DefaultAlgoContext::for_tests()),
            tc_misc_digest::WhirlpoolDigest::default(),
            64,
        );
        find("WHIRLPOOL", &[], &[]);
    }

    #[cfg(feature = "photon-beetle")]
    #[test]
    fn the_photon_beetle_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::photon_beetle(&DefaultAlgoContext::for_tests()),
            tc_misc_digest::PhotonBeetleDigest::new(),
            32,
        );
        find("PHOTON-BEETLE", &[], &[]);
    }

    #[cfg(feature = "esch-256")]
    #[test]
    fn the_esch_256_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::esch_256(&DefaultAlgoContext::for_tests()),
            tc_misc_digest::SparkleDigest::new(tc_misc_digest::SparkleParameters::Esch256),
            32,
        );
        find("ESCH-256", &[], &[]);
    }

    #[cfg(feature = "esch-384")]
    #[test]
    fn the_esch_384_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::esch_384(&DefaultAlgoContext::for_tests()),
            tc_misc_digest::SparkleDigest::new(tc_misc_digest::SparkleParameters::Esch384),
            48,
        );
        find("ESCH-384", &[], &[]);
    }

    #[cfg(feature = "xoodyak")]
    #[test]
    fn the_xoodyak_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::xoodyak(&DefaultAlgoContext::for_tests()),
            tc_misc_digest::XoodyakDigest::new(),
            32,
        );
        find("XOODYAK", &[], &[]);
    }
}
