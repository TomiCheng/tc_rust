use tc_digest::util::NullDigest;

use super::row::{TcDigest, row};
use crate::DefaultAlgoContext;
use crate::digest::DigestEntry;

// The row of NONE, Bouncy Castle's NullDigest: not a hash, it gives back what it was fed, for a
// signer that signs a digest computed elsewhere. Its size is what was fed so far
pub(super) fn null_digest(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    row("NONE", &[], &[], || Box::new(TcDigest(NullDigest::new())))
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
        digest.try_update(b"a").unwrap();
        digest.try_update_byte(b'b').unwrap();
        digest.try_update(b"c").unwrap();
        assert_eq!(digest.digest_size(), 3);
        assert_eq!(digest.byte_length(), 0);
        assert_eq!(digest.finalize().unwrap(), b"abc");
    }

    #[test]
    fn do_final_starts_the_next_message() {
        let mut digest = row().create();
        digest.try_update(b"abc").unwrap();
        let mut output = [0; 3];
        assert_eq!(digest.try_do_final(&mut output).unwrap(), 3);
        assert_eq!(&output, b"abc");
        assert_eq!(digest.digest_size(), 0);
    }

    #[test]
    fn an_output_shorter_than_the_input_is_data_length_and_keeps_the_input() {
        let mut digest = row().create();
        digest.try_update(b"abc").unwrap();

        let error = digest.try_do_final(&mut [0; 2]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
        assert_eq!(digest.finalize().unwrap(), b"abc");
    }

    #[test]
    fn reset_discards_the_input() {
        let mut digest = row().create();
        digest.try_update(b"other").unwrap();
        digest.try_reset().unwrap();
        digest.try_update(b"abc").unwrap();
        assert_eq!(digest.finalize().unwrap(), b"abc");
    }

    #[test]
    fn the_row_is_named_none_with_no_alias_or_oid() {
        let algo = DefaultAlgoBuilder::default().build();
        assert_eq!(
            algo.digest().calculate_by_name("NONE", b"abc").unwrap(),
            b"abc"
        );

        let entry = row();
        assert!(entry.aliases().is_empty());
        assert!(entry.oids().is_empty());
    }
}
