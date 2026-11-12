use super::row::{TcDigest, row};
use crate::DefaultAlgoContext;
use crate::digest::DigestEntry;

// The rows of MD2, MD4 and MD5, to give to DefaultAlgoBuilder::reg_digest. Their names and OIDs
// are those of Bouncy Castle's DigestUtilities. All three are broken, kept for old data

#[cfg(feature = "md2")]
pub(super) fn md2(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("MD2", &[], &["1.2.840.113549.2.2"], || {
        Box::new(TcDigest(tc_md::Md2Digest::new()))
    })
}

#[cfg(feature = "md4")]
pub(super) fn md4(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("MD4", &[], &["1.2.840.113549.2.4"], || {
        Box::new(TcDigest(tc_md::Md4Digest::new()))
    })
}

#[cfg(feature = "md5")]
pub(super) fn md5(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("MD5", &[], &["1.2.840.113549.2.5"], || {
        Box::new(TcDigest(tc_md::Md5Digest::new()))
    })
}

#[cfg(test)]
mod tests {
    use crate::DefaultAlgoContext;
    use crate::digest::DigestEntry;

    fn hash_of_abc(row: Box<dyn DigestEntry>) -> String {
        let mut digest = row.create();
        digest.update(b"a");
        digest.update(b"bc");
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn context() -> DefaultAlgoContext {
        DefaultAlgoContext::for_tests()
    }

    // The examples of RFC 1319, RFC 1320 and RFC 1321 for the message "abc"

    #[cfg(feature = "md2")]
    #[test]
    fn md2_gives_the_standard_hash() {
        let row = super::md2(&context()).remove(0);
        assert_eq!(row.create().byte_length(), 16);
        assert_eq!(hash_of_abc(row), "da853b0d3f88d99b30283a69e6ded6bb");
    }

    #[cfg(feature = "md4")]
    #[test]
    fn md4_gives_the_standard_hash() {
        let row = super::md4(&context()).remove(0);
        assert_eq!(row.create().byte_length(), 64);
        assert_eq!(hash_of_abc(row), "a448017aaf21d8525fc10ae87aa6729d");
    }

    #[cfg(feature = "md5")]
    #[test]
    fn md5_gives_the_standard_hash() {
        let row = super::md5(&context()).remove(0);
        assert_eq!(row.create().digest_size(), 16);
        assert_eq!(hash_of_abc(row), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[cfg(feature = "md5")]
    #[test]
    fn md5_is_found_by_its_oid() {
        use crate::AlgoBuilder as _;
        let algo = crate::DefaultAlgoBuilder::default().build();
        let oid = "1.2.840.113549.2.5".parse().unwrap();
        assert_eq!(algo.digest().get_by_oid(&oid).unwrap().digest_size(), 16);
    }
}
