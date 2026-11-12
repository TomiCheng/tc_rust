use tc_asn1::Asn1Oid;
use tc_digest::util::NullDigest;
use tc_digest::{Digest as _, TryDigest as _};

use crate::digest::{Digest, DigestEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind};

// The row of NONE, Bouncy Castle's NullDigest: not a hash, it gives back what it was fed, for a
// signer that signs a digest computed elsewhere
pub(super) fn null_digest(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    vec![Box::new(NullEntry)]
}

struct NullEntry;

impl EntryBase for NullEntry {
    fn name(&self) -> &str {
        "NONE"
    }

    fn aliases(&self) -> &[String] {
        &[]
    }

    fn oids(&self) -> &[Asn1Oid] {
        &[]
    }
}

impl DigestEntry for NullEntry {
    fn create(&self) -> Box<dyn Digest> {
        Box::new(Null(NullDigest::new()))
    }
}

struct Null(NullDigest);

impl Digest for Null {
    // What was fed so far, since the output is the input
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
    use super::null_digest;
    use crate::digest::DigestEntry;
    use crate::{AlgoBuilder, DefaultAlgoBuilder, DefaultAlgoContext, ErrorKind};

    fn row() -> Box<dyn DigestEntry> {
        null_digest(&DefaultAlgoContext::for_tests()).remove(0)
    }

    #[test]
    fn the_digest_gives_back_what_it_was_fed() {
        let mut digest = row().create();
        digest.update(b"a");
        digest.update_byte(b'b');
        digest.update(b"c");
        assert_eq!(digest.digest_size(), 3);
        assert_eq!(digest.byte_length(), 0);
        assert_eq!(digest.finalize(), b"abc");
    }

    #[test]
    fn do_final_starts_the_next_message() {
        let mut digest = row().create();
        digest.update(b"abc");
        let mut output = [0; 3];
        assert_eq!(digest.do_final(&mut output).unwrap(), 3);
        assert_eq!(&output, b"abc");
        assert_eq!(digest.digest_size(), 0);
    }

    #[test]
    fn an_output_shorter_than_the_input_is_data_length_and_keeps_the_input() {
        let mut digest = row().create();
        digest.update(b"abc");

        let error = digest.do_final(&mut [0; 2]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
        assert_eq!(digest.finalize(), b"abc");
    }

    #[test]
    fn reset_discards_the_input() {
        let mut digest = row().create();
        digest.update(b"other");
        digest.reset();
        digest.update(b"abc");
        assert_eq!(digest.finalize(), b"abc");
    }

    #[test]
    fn the_row_is_named_none_with_no_alias_or_oid() {
        let algo = DefaultAlgoBuilder::default().build();
        assert_eq!(algo.digest().calculate_by_name("NONE", b"abc").unwrap(), b"abc");

        let entry = row();
        assert!(entry.aliases().is_empty());
        assert!(entry.oids().is_empty());
    }
}
