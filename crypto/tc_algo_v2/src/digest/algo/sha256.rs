use tc_asn1::Asn1Oid;
use tc_digest::{Digest as _, TryDigest as _};
use tc_sha::Sha256Digest;

use crate::digest::{Digest, DigestEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind};

// The row of SHA-256, to give to DefaultAlgoBuilder::reg_digest. Its names and OIDs are those of
// Bouncy Castle's DigestUtilities, the HMAC OID included
pub(super) fn sha256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    vec![Box::new(Sha256Entry {
        aliases: vec!["SHA256".to_string()],
        oids: vec![oid("2.16.840.1.101.3.4.2.1"), oid("1.2.840.113549.2.9")],
    })]
}

fn oid(dotted: &str) -> Asn1Oid {
    dotted.parse().expect("a valid OID")
}

struct Sha256Entry {
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
}

impl EntryBase for Sha256Entry {
    fn name(&self) -> &str {
        "SHA-256"
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl DigestEntry for Sha256Entry {
    fn create(&self) -> Box<dyn Digest> {
        Box::new(Sha256(Sha256Digest::new()))
    }
}

struct Sha256(Sha256Digest);

impl Digest for Sha256 {
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
    use super::sha256;
    use crate::digest::DigestEntry;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, DefaultAlgoContext, ErrorKind};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn row() -> Box<dyn DigestEntry> {
        sha256(&DefaultAlgoContext::for_tests()).remove(0)
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

    // FIPS 180-4's example for the message "abc"
    #[test]
    fn the_digest_the_row_creates_gives_the_standard_hash() {
        let mut digest = row().create();
        assert_eq!(digest.digest_size(), 32);
        assert_eq!(digest.byte_length(), 64);
        digest.update(b"a");
        digest.update(b"bc");
        assert_eq!(
            hex(&digest.finalize()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
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

    #[test]
    fn the_function_is_what_the_builder_takes() {
        let mut builder = DefaultAlgoBuilder::default();
        builder.reg_digest(sha256);
        let _algo = builder.build();
    }
}
