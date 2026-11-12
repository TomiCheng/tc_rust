use super::row::{TcDigest, row};
use crate::DefaultAlgoContext;
use crate::digest::DigestEntry;

// The rows of Ascon-Hash256, and the Ascon-Hash, Ascon-HashA and ISAP of before NIST's SP 800-232, to give to DefaultAlgoBuilder::reg_digest.
// Bouncy Castle's DigestUtilities has none of them, so they have no alias or OID

#[cfg(feature = "ascon-hash256")]
pub(super) fn ascon_hash256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("ASCON-HASH256", &[], &[], || {
        Box::new(TcDigest(tc_ascon_hash::AsconHash256::new()))
    })
}

#[cfg(feature = "ascon-hash")]
#[allow(deprecated)]
pub(super) fn ascon_hash(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("ASCON-HASH", &[], &[], || {
        Box::new(TcDigest(tc_ascon_hash::AsconDigest::new(
            tc_ascon_hash::AsconParameters::AsconHash,
        )))
    })
}

#[cfg(feature = "ascon-hasha")]
#[allow(deprecated)]
pub(super) fn ascon_hasha(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("ASCON-HASHA", &[], &[], || {
        Box::new(TcDigest(tc_ascon_hash::AsconDigest::new(
            tc_ascon_hash::AsconParameters::AsconHashA,
        )))
    })
}

#[cfg(feature = "isap")]
#[allow(deprecated)]
pub(super) fn isap(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("ISAP", &[], &[], || {
        Box::new(TcDigest(tc_ascon_hash::IsapDigest::new()))
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

    #[cfg(feature = "ascon-hash256")]
    #[test]
    fn the_ascon_hash256_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::ascon_hash256(&DefaultAlgoContext::for_tests()),
            tc_ascon_hash::AsconHash256::new(),
            32,
        );
        find("ASCON-HASH256", &[], &[]);
    }

    #[cfg(feature = "ascon-hash")]
    #[allow(deprecated)]
    #[test]
    fn the_ascon_hash_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::ascon_hash(&DefaultAlgoContext::for_tests()),
            tc_ascon_hash::AsconDigest::new(tc_ascon_hash::AsconParameters::AsconHash),
            32,
        );
        find("ASCON-HASH", &[], &[]);
    }

    #[cfg(feature = "ascon-hasha")]
    #[allow(deprecated)]
    #[test]
    fn the_ascon_hasha_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::ascon_hasha(&DefaultAlgoContext::for_tests()),
            tc_ascon_hash::AsconDigest::new(tc_ascon_hash::AsconParameters::AsconHashA),
            32,
        );
        find("ASCON-HASHA", &[], &[]);
    }

    #[cfg(feature = "isap")]
    #[allow(deprecated)]
    #[test]
    fn the_isap_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::isap(&DefaultAlgoContext::for_tests()),
            tc_ascon_hash::IsapDigest::new(),
            32,
        );
        find("ISAP", &[], &[]);
    }
}
