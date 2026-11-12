use core::convert::Infallible;

use tc_digest::TryDigest;

const WRONG_LENGTH: &str = "HARAKA-256 takes exactly 32 bytes and HARAKA-512 exactly 64";

// Haraka hashes an input of one exact length and reports any other as an error, where AnyDigest has
// no error to report. So a wrong length panics, as too short an output does for any digest
#[derive(Clone)]
pub(super) struct FixedInput<D>(pub(super) D);

impl<D: TryDigest> TryDigest for FixedInput<D> {
    type Error = Infallible;

    fn digest_size(&self) -> usize {
        self.0.digest_size()
    }

    fn byte_length(&self) -> usize {
        self.0.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.0.try_update(input).expect(WRONG_LENGTH);
        Ok(())
    }

    fn try_update_byte(&mut self, input: u8) -> Result<(), Self::Error> {
        self.0.try_update_byte(input).expect(WRONG_LENGTH);
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(self.0.try_do_final(output).expect(WRONG_LENGTH))
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.0.try_reset().expect(WRONG_LENGTH);
        Ok(())
    }
}
