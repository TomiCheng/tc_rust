use tc_asn1::Asn1Oid;
use tc_digest::{Digest as _, TryDigest as _};
use tc_sha::Sha256Digest;

use crate::EntryBase;
use crate::digest::{Digest, DigestEntry};

// The row of SHA-256, to give to DefaultAlgoBuilder::reg_digest. Its names and OIDs are those of
// Bouncy Castle's DigestUtilities, the HMAC OID included
pub(super) fn sha256() -> Vec<Box<dyn DigestEntry>> {
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

    fn finalize(&mut self) -> Vec<u8> {
        let mut output = vec![0; self.0.digest_size()];
        let written = self.0.do_final(&mut output);
        output.truncate(written);
        output
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::sha256;
    use crate::digest::DigestEntry;
    use crate::{AlgoBuilder, DefaultAlgoBuilder};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn row() -> Box<dyn DigestEntry> {
        sha256().remove(0)
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
