use super::row::{TcDigest, row};
use crate::DefaultAlgoContext;
use crate::digest::DigestEntry;

// The rows of SM3, to give to DefaultAlgoBuilder::reg_digest. Their names and OIDs
// are those of Bouncy Castle's DigestUtilities

#[cfg(feature = "sm3")]
pub(super) fn sm3(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("SM3", &[], &["1.2.156.10197.1.401"], || {
        Box::new(TcDigest(tc_sm3::Sm3Digest::default()))
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

    #[cfg(feature = "sm3")]
    #[test]
    fn the_sm3_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::sm3(&DefaultAlgoContext::for_tests()),
            tc_sm3::Sm3Digest::default(),
            32,
        );
        find("SM3", &[], &["1.2.156.10197.1.401"]);
    }
}
