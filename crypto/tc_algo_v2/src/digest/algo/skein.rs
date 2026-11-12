use super::row::{TcDigest, row};
use crate::DefaultAlgoContext;
use crate::digest::DigestEntry;

// The rows of Skein, at the state and digest sizes Bouncy Castle registers, to give to DefaultAlgoBuilder::reg_digest.
// Bouncy Castle's DigestUtilities has none of them, so they have no alias or OID

#[cfg(feature = "skein-256-128")]
pub(super) fn skein_256_128(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("SKEIN-256-128", &[], &[], || {
        Box::new(TcDigest(tc_skein::SkeinDigest::new(256, 128)))
    })
}

#[cfg(feature = "skein-256-160")]
pub(super) fn skein_256_160(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("SKEIN-256-160", &[], &[], || {
        Box::new(TcDigest(tc_skein::SkeinDigest::new(256, 160)))
    })
}

#[cfg(feature = "skein-256-224")]
pub(super) fn skein_256_224(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("SKEIN-256-224", &[], &[], || {
        Box::new(TcDigest(tc_skein::SkeinDigest::new(256, 224)))
    })
}

#[cfg(feature = "skein-256-256")]
pub(super) fn skein_256_256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("SKEIN-256-256", &[], &[], || {
        Box::new(TcDigest(tc_skein::SkeinDigest::new(256, 256)))
    })
}

#[cfg(feature = "skein-512-128")]
pub(super) fn skein_512_128(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("SKEIN-512-128", &[], &[], || {
        Box::new(TcDigest(tc_skein::SkeinDigest::new(512, 128)))
    })
}

#[cfg(feature = "skein-512-160")]
pub(super) fn skein_512_160(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("SKEIN-512-160", &[], &[], || {
        Box::new(TcDigest(tc_skein::SkeinDigest::new(512, 160)))
    })
}

#[cfg(feature = "skein-512-224")]
pub(super) fn skein_512_224(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("SKEIN-512-224", &[], &[], || {
        Box::new(TcDigest(tc_skein::SkeinDigest::new(512, 224)))
    })
}

#[cfg(feature = "skein-512-256")]
pub(super) fn skein_512_256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("SKEIN-512-256", &[], &[], || {
        Box::new(TcDigest(tc_skein::SkeinDigest::new(512, 256)))
    })
}

#[cfg(feature = "skein-512-384")]
pub(super) fn skein_512_384(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("SKEIN-512-384", &[], &[], || {
        Box::new(TcDigest(tc_skein::SkeinDigest::new(512, 384)))
    })
}

#[cfg(feature = "skein-512-512")]
pub(super) fn skein_512_512(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("SKEIN-512-512", &[], &[], || {
        Box::new(TcDigest(tc_skein::SkeinDigest::new(512, 512)))
    })
}

#[cfg(feature = "skein-1024-384")]
pub(super) fn skein_1024_384(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("SKEIN-1024-384", &[], &[], || {
        Box::new(TcDigest(tc_skein::SkeinDigest::new(1024, 384)))
    })
}

#[cfg(feature = "skein-1024-512")]
pub(super) fn skein_1024_512(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("SKEIN-1024-512", &[], &[], || {
        Box::new(TcDigest(tc_skein::SkeinDigest::new(1024, 512)))
    })
}

#[cfg(feature = "skein-1024-1024")]
pub(super) fn skein_1024_1024(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("SKEIN-1024-1024", &[], &[], || {
        Box::new(TcDigest(tc_skein::SkeinDigest::new(1024, 1024)))
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

    #[cfg(feature = "skein-256-128")]
    #[test]
    fn the_skein_256_128_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::skein_256_128(&DefaultAlgoContext::for_tests()),
            tc_skein::SkeinDigest::new(256, 128),
            16,
        );
        find("SKEIN-256-128", &[], &[]);
    }

    #[cfg(feature = "skein-256-160")]
    #[test]
    fn the_skein_256_160_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::skein_256_160(&DefaultAlgoContext::for_tests()),
            tc_skein::SkeinDigest::new(256, 160),
            20,
        );
        find("SKEIN-256-160", &[], &[]);
    }

    #[cfg(feature = "skein-256-224")]
    #[test]
    fn the_skein_256_224_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::skein_256_224(&DefaultAlgoContext::for_tests()),
            tc_skein::SkeinDigest::new(256, 224),
            28,
        );
        find("SKEIN-256-224", &[], &[]);
    }

    #[cfg(feature = "skein-256-256")]
    #[test]
    fn the_skein_256_256_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::skein_256_256(&DefaultAlgoContext::for_tests()),
            tc_skein::SkeinDigest::new(256, 256),
            32,
        );
        find("SKEIN-256-256", &[], &[]);
    }

    #[cfg(feature = "skein-512-128")]
    #[test]
    fn the_skein_512_128_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::skein_512_128(&DefaultAlgoContext::for_tests()),
            tc_skein::SkeinDigest::new(512, 128),
            16,
        );
        find("SKEIN-512-128", &[], &[]);
    }

    #[cfg(feature = "skein-512-160")]
    #[test]
    fn the_skein_512_160_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::skein_512_160(&DefaultAlgoContext::for_tests()),
            tc_skein::SkeinDigest::new(512, 160),
            20,
        );
        find("SKEIN-512-160", &[], &[]);
    }

    #[cfg(feature = "skein-512-224")]
    #[test]
    fn the_skein_512_224_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::skein_512_224(&DefaultAlgoContext::for_tests()),
            tc_skein::SkeinDigest::new(512, 224),
            28,
        );
        find("SKEIN-512-224", &[], &[]);
    }

    #[cfg(feature = "skein-512-256")]
    #[test]
    fn the_skein_512_256_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::skein_512_256(&DefaultAlgoContext::for_tests()),
            tc_skein::SkeinDigest::new(512, 256),
            32,
        );
        find("SKEIN-512-256", &[], &[]);
    }

    #[cfg(feature = "skein-512-384")]
    #[test]
    fn the_skein_512_384_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::skein_512_384(&DefaultAlgoContext::for_tests()),
            tc_skein::SkeinDigest::new(512, 384),
            48,
        );
        find("SKEIN-512-384", &[], &[]);
    }

    #[cfg(feature = "skein-512-512")]
    #[test]
    fn the_skein_512_512_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::skein_512_512(&DefaultAlgoContext::for_tests()),
            tc_skein::SkeinDigest::new(512, 512),
            64,
        );
        find("SKEIN-512-512", &[], &[]);
    }

    #[cfg(feature = "skein-1024-384")]
    #[test]
    fn the_skein_1024_384_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::skein_1024_384(&DefaultAlgoContext::for_tests()),
            tc_skein::SkeinDigest::new(1024, 384),
            48,
        );
        find("SKEIN-1024-384", &[], &[]);
    }

    #[cfg(feature = "skein-1024-512")]
    #[test]
    fn the_skein_1024_512_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::skein_1024_512(&DefaultAlgoContext::for_tests()),
            tc_skein::SkeinDigest::new(1024, 512),
            64,
        );
        find("SKEIN-1024-512", &[], &[]);
    }

    #[cfg(feature = "skein-1024-1024")]
    #[test]
    fn the_skein_1024_1024_row_gives_the_hash_of_its_digest_and_is_found_by_its_names() {
        check(
            super::skein_1024_1024(&DefaultAlgoContext::for_tests()),
            tc_skein::SkeinDigest::new(1024, 1024),
            128,
        );
        find("SKEIN-1024-1024", &[], &[]);
    }
}
