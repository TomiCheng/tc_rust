use tc_asn1::Asn1Oid;
use tc_digest::TryDigest;
use tc_misc_digest::HarakaError;

use crate::digest::{Digest, DigestEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind};

// The rows of Haraka-256 and Haraka-512, to give to DefaultAlgoBuilder::reg_digest. Bouncy
// Castle's DigestUtilities has neither, so they have no alias or OID. Each takes exactly 32 or
// 64 bytes of input

#[cfg(feature = "haraka-256")]
pub(super) fn haraka256(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    vec![Box::new(HarakaEntry {
        name: "HARAKA-256",
        create: || Box::new(Haraka::new(tc_misc_digest::Haraka256Digest::new())),
    })]
}

#[cfg(feature = "haraka-512")]
pub(super) fn haraka512(_context: &DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>> {
    vec![Box::new(HarakaEntry {
        name: "HARAKA-512",
        create: || Box::new(Haraka::new(tc_misc_digest::Haraka512Digest::new())),
    })]
}

struct HarakaEntry {
    name: &'static str,
    create: fn() -> Box<dyn Digest>,
}

impl EntryBase for HarakaEntry {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &[]
    }

    fn oids(&self) -> &[Asn1Oid] {
        &[]
    }
}

impl DigestEntry for HarakaEntry {
    fn create(&self) -> Box<dyn Digest> {
        (self.create)()
    }
}

// A Haraka of tc_misc_digest, with its errors as DataLength: an input past the fixed length when it
// comes, and an input short of it, or an output shorter than the hash, at try_do_final, which then
// leaves the input in place
struct Haraka<D>(D);

impl<D> Haraka<D> {
    fn new(digest: D) -> Self {
        Self(digest)
    }
}

impl<D: TryDigest<Error = HarakaError>> TryDigest for Haraka<D> {
    type Error = AlgoError;

    fn digest_size(&self) -> usize {
        self.0.digest_size()
    }

    // The fixed length of the input
    fn byte_length(&self) -> usize {
        self.0.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        self.0.try_update(input).map_err(data_length)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.try_do_final(output).map_err(data_length)
    }

    fn try_reset(&mut self) -> Result<(), AlgoError> {
        self.0.try_reset().map_err(data_length)
    }
}

impl<D: TryDigest<Error = HarakaError>> Digest for Haraka<D> {}

fn data_length(error: HarakaError) -> AlgoError {
    AlgoError::with_source(ErrorKind::DataLength, error)
}

#[cfg(test)]
mod tests {
    use crate::DefaultAlgoContext;
    #[cfg(feature = "haraka-256")]
    use crate::{ErrorKind, digest::DigestEntry};

    fn direct(mut digest: impl tc_digest::TryDigest, input: &[u8]) -> Vec<u8> {
        digest.try_update(input).ok().unwrap();
        let mut output = vec![0; 32];
        digest.try_do_final(&mut output).ok().unwrap();
        output
    }

    #[cfg(feature = "haraka-256")]
    fn row256() -> Box<dyn DigestEntry> {
        super::haraka256(&DefaultAlgoContext::for_tests()).remove(0)
    }

    #[cfg(feature = "haraka-256")]
    #[test]
    fn the_haraka_256_row_gives_the_hash_of_32_bytes_in_parts() {
        let input: Vec<u8> = (0..32).collect();
        let mut digest = row256().create();
        assert_eq!(digest.byte_length(), 32);
        digest.try_update(&input[..10]).unwrap();
        digest.try_update(&input[10..]).unwrap();
        assert_eq!(
            digest.finalize().unwrap(),
            direct(tc_misc_digest::Haraka256Digest::new(), &input)
        );
    }

    #[cfg(feature = "haraka-512")]
    #[test]
    fn the_haraka_512_row_gives_the_hash_of_64_bytes() {
        let input: Vec<u8> = (0..64).collect();
        let mut digest = super::haraka512(&DefaultAlgoContext::for_tests())
            .remove(0)
            .create();
        assert_eq!(digest.byte_length(), 64);
        digest.try_update(&input).unwrap();
        assert_eq!(
            digest.finalize().unwrap(),
            direct(tc_misc_digest::Haraka512Digest::new(), &input)
        );
    }

    #[cfg(feature = "haraka-256")]
    #[test]
    fn an_update_past_32_bytes_is_data_length_at_once_and_keeps_the_input() {
        let mut digest = row256().create();
        digest.try_update(&[7; 20]).unwrap();
        let error = digest.try_update(&[7; 13]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);

        digest.try_update(&[7; 12]).unwrap();
        assert_eq!(
            digest.finalize().unwrap(),
            direct(tc_misc_digest::Haraka256Digest::new(), &[7; 32])
        );
    }

    #[cfg(feature = "haraka-256")]
    #[test]
    fn an_input_short_of_32_bytes_or_a_short_output_is_data_length_and_keeps_the_input() {
        let mut digest = row256().create();
        digest.try_update(&[7; 31]).unwrap();
        let error = digest.try_do_final(&mut [0; 32]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);

        digest.try_update(&[7]).unwrap();
        let error = digest.try_do_final(&mut [0; 31]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DataLength);
        assert_eq!(
            digest.finalize().unwrap(),
            direct(tc_misc_digest::Haraka256Digest::new(), &[7; 32])
        );
    }

    #[cfg(feature = "haraka-256")]
    #[test]
    fn reset_discards_the_input() {
        let mut digest = row256().create();
        digest.try_update(&[0; 32]).unwrap();
        digest.try_reset().unwrap();
        digest.try_update(&[7; 32]).unwrap();
        assert_eq!(
            digest.finalize().unwrap(),
            direct(tc_misc_digest::Haraka256Digest::new(), &[7; 32])
        );
    }

    #[cfg(feature = "haraka-256")]
    #[test]
    fn the_haraka_rows_are_found_by_name() {
        use crate::AlgoBuilder as _;
        let algo = crate::DefaultAlgoBuilder::default().build();
        assert!(algo.digest().get_by_name("HARAKA-256").is_ok());
    }
}
