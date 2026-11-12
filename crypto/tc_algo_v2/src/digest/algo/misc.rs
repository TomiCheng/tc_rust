use super::row::{TcDigest, row};
use crate::DefaultAlgoContext;
use crate::digest::DigestEntry;

// The rows of Tiger and Whirlpool, to give to DefaultAlgoBuilder::reg_digest. Their names and OIDs
// are those of Bouncy Castle's DigestUtilities

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
}
