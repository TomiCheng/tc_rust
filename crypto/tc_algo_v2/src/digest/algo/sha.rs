use tc_asn1::Asn1Oid;

use crate::digest::{Digest, DigestEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind};

// The rows of SHA-1 and SHA-2, to give to DefaultAlgoBuilder::reg_digest. Their names and OIDs
// are those of Bouncy Castle's DigestUtilities, the HMAC OIDs included

#[cfg(feature = "sha1")]
pub(super) fn sha1(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row(
        "SHA-1",
        &["SHA1"],
        &["1.3.14.3.2.26", "1.2.840.113549.2.7", "1.3.6.1.5.5.8.1.2"],
        || Box::new(Sha(tc_sha::Sha1Digest::new())),
    )
}

#[cfg(feature = "sha224")]
pub(super) fn sha224(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row(
        "SHA-224",
        &["SHA224"],
        &["2.16.840.1.101.3.4.2.4", "1.2.840.113549.2.8"],
        || Box::new(Sha(tc_sha::Sha224Digest::new())),
    )
}

#[cfg(feature = "sha256")]
pub(super) fn sha256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row(
        "SHA-256",
        &["SHA256"],
        &["2.16.840.1.101.3.4.2.1", "1.2.840.113549.2.9"],
        || Box::new(Sha(tc_sha::Sha256Digest::new())),
    )
}

#[cfg(feature = "sha384")]
pub(super) fn sha384(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row(
        "SHA-384",
        &["SHA384"],
        &["2.16.840.1.101.3.4.2.2", "1.2.840.113549.2.10"],
        || Box::new(Sha(tc_sha::Sha384Digest::new())),
    )
}

#[cfg(feature = "sha512")]
pub(super) fn sha512(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row(
        "SHA-512",
        &["SHA512"],
        &["2.16.840.1.101.3.4.2.3", "1.2.840.113549.2.11"],
        || Box::new(Sha(tc_sha::Sha512Digest::new())),
    )
}

#[cfg(feature = "sha512-224")]
pub(super) fn sha512_224(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row(
        "SHA-512/224",
        &["SHA512/224", "SHA512-224", "SHA512(224)", "SHA-512(224)"],
        &["2.16.840.1.101.3.4.2.5", "1.2.840.113549.2.12"],
        || Box::new(Sha(tc_sha::Sha512tDigest::new(224))),
    )
}

#[cfg(feature = "sha512-256")]
pub(super) fn sha512_256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row(
        "SHA-512/256",
        &["SHA512/256", "SHA512-256", "SHA512(256)", "SHA-512(256)"],
        &["2.16.840.1.101.3.4.2.6", "1.2.840.113549.2.13"],
        || Box::new(Sha(tc_sha::Sha512tDigest::new(256))),
    )
}

fn row(
    name: &'static str,
    aliases: &[&str],
    oids: &[&str],
    create: fn() -> Box<dyn Digest>,
) -> Vec<Box<dyn DigestEntry>> {
    vec![Box::new(ShaEntry {
        name,
        aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
        oids: oids.iter().map(|oid| oid.parse().expect("a valid OID")).collect(),
        create,
    })]
}

struct ShaEntry {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    create: fn() -> Box<dyn Digest>,
}

impl EntryBase for ShaEntry {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl DigestEntry for ShaEntry {
    fn create(&self) -> Box<dyn Digest> {
        (self.create)()
    }
}

struct Sha<D>(D);

impl<D: tc_digest::Digest> Digest for Sha<D> {
    fn digest_size(&self) -> usize {
        self.0.digest_size()
    }

    fn byte_length(&self) -> usize {
        self.0.byte_length()
    }

    fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }

    // tc_digest panics on a short output, so the length is checked here first
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        if output.len() < self.digest_size() {
            return Err(AlgoError::new(ErrorKind::DataLength));
        }
        Ok(self.0.do_final(output))
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

#[cfg(test)]
mod tests {
    use crate::digest::DigestEntry;
    use crate::DefaultAlgoContext;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn hash_of_abc(row: Box<dyn DigestEntry>) -> String {
        let mut digest = row.create();
        digest.update(b"a");
        digest.update(b"bc");
        hex(&digest.finalize())
    }

    fn context() -> DefaultAlgoContext {
        DefaultAlgoContext::for_tests()
    }

    #[cfg(feature = "sha256")]
    mod sha256 {
        use super::super::sha256;
        use super::{context, hex};
        use crate::digest::DigestEntry;
        use crate::ErrorKind;

        fn row() -> Box<dyn DigestEntry> {
            sha256(&context()).remove(0)
        }

        const ABC_HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        #[test]
        fn do_final_writes_the_hash_into_the_output_and_starts_the_next_message() {
            let mut digest = row().create();
            digest.update(b"abc");
            let mut output = [0; 32];
            assert_eq!(digest.do_final(&mut output).unwrap(), 32);
            assert_eq!(hex(&output), ABC_HASH);

            assert_eq!(digest.do_final(&mut output).unwrap(), 32);
            assert_eq!(hex(&output), EMPTY_HASH);
        }

        #[test]
        fn update_byte_gives_the_same_hash_as_update() {
            let mut digest = row().create();
            for byte in b"abc" {
                digest.update_byte(*byte);
            }
            assert_eq!(hex(&digest.finalize()), ABC_HASH);
        }

        #[test]
        fn an_output_shorter_than_the_hash_is_data_length_and_keeps_the_message() {
            let mut digest = row().create();
            digest.update(b"abc");

            let error = digest.do_final(&mut [0; 31]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::DataLength);
            assert_eq!(hex(&digest.finalize()), ABC_HASH);
        }

        #[test]
        fn the_row_says_its_name_aliases_and_oids() {
            let entry = row();
            assert_eq!(entry.name(), "SHA-256");
            assert_eq!(entry.aliases(), ["SHA256"]);
            assert_eq!(entry.oids().len(), 2);
        }

        #[test]
        fn finalize_starts_the_next_message_and_reset_discards_the_message() {
            let mut digest = row().create();
            digest.update(b"abc");
            let first = digest.finalize();

            digest.update(b"other");
            digest.reset();
            digest.update(b"abc");
            assert_eq!(digest.finalize(), first);
        }
    }

    // FIPS 180-4's examples for the message "abc"

    #[cfg(feature = "sha1")]
    #[test]
    fn sha1_gives_the_standard_hash() {
        let row = super::sha1(&context()).remove(0);
        assert_eq!(row.create().digest_size(), 20);
        assert_eq!(hash_of_abc(row), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[cfg(feature = "sha224")]
    #[test]
    fn sha224_gives_the_standard_hash() {
        let row = super::sha224(&context()).remove(0);
        assert_eq!(row.create().digest_size(), 28);
        assert_eq!(
            hash_of_abc(row),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
    }

    #[cfg(feature = "sha256")]
    #[test]
    fn sha256_gives_the_standard_hash() {
        let row = super::sha256(&context()).remove(0);
        assert_eq!(row.create().byte_length(), 64);
        assert_eq!(
            hash_of_abc(row),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[cfg(feature = "sha384")]
    #[test]
    fn sha384_gives_the_standard_hash() {
        let row = super::sha384(&context()).remove(0);
        assert_eq!(row.create().byte_length(), 128);
        assert_eq!(
            hash_of_abc(row),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[cfg(feature = "sha512")]
    #[test]
    fn sha512_gives_the_standard_hash() {
        let row = super::sha512(&context()).remove(0);
        assert_eq!(
            hash_of_abc(row),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[cfg(feature = "sha512-224")]
    #[test]
    fn sha512_224_gives_the_standard_hash() {
        let row = super::sha512_224(&context()).remove(0);
        assert_eq!(
            hash_of_abc(row),
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
        );
    }

    #[cfg(feature = "sha512-256")]
    #[test]
    fn sha512_256_gives_the_standard_hash() {
        let row = super::sha512_256(&context()).remove(0);
        assert_eq!(
            hash_of_abc(row),
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
        );
    }

    #[cfg(all(feature = "sha512-224", feature = "sha512-256"))]
    #[test]
    fn the_sha512_t_rows_take_bouncy_castles_aliases() {
        use crate::AlgoBuilder as _;
        let algo = crate::DefaultAlgoBuilder::default().build();
        for alias in ["SHA512/224", "SHA512-224", "SHA512(224)", "SHA-512(224)"] {
            assert_eq!(algo.digest().get_by_name(alias).unwrap().digest_size(), 28);
        }
        for alias in ["SHA512/256", "SHA512-256", "SHA512(256)", "SHA-512(256)"] {
            assert_eq!(algo.digest().get_by_name(alias).unwrap().digest_size(), 32);
        }
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn sha1_is_found_by_each_of_its_three_oids() {
        use crate::AlgoBuilder as _;
        let algo = crate::DefaultAlgoBuilder::default().build();
        for oid in ["1.3.14.3.2.26", "1.2.840.113549.2.7", "1.3.6.1.5.5.8.1.2"] {
            let digest = algo.digest().get_by_oid(&oid.parse().unwrap()).unwrap();
            assert_eq!(digest.digest_size(), 20);
        }
    }

    #[cfg(feature = "sha256")]
    #[test]
    fn the_function_is_what_the_builder_takes() {
        use crate::AlgoBuilder as _;
        let mut builder = crate::DefaultAlgoBuilder::default();
        builder.reg_digest(super::sha256);
        let _algo = builder.build();
    }
}
