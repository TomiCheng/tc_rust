//! An RSA engine that can blind its private operation.

use rand_core::CryptoRng;
use tc_asym_cipher::AsymmetricBlockCipher;

use crate::RsaError;

/// An RSA engine that can blind its private operation, as Bouncy Castle's
/// `RsaBlindedEngine` does around its core engine: for a random `r`, it
/// raises `x · r^e` rather than `x`, and takes `r` away from the result,
/// so that what the power works on is random and unrelated to the input
/// a caller chose. [`RsaBlindedEngine`](crate::RsaBlindedEngine) runs an
/// engine through it with a random source it holds.
pub trait RsaBlinding: AsymmetricBlockCipher<Error = RsaError> {
    /// Processes one block as `process_block` does, blinded with an `r`
    /// drawn from `rng`. Each implementation states its timing.
    fn process_block_blinded<R: CryptoRng + ?Sized>(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        rng: &mut R,
    ) -> Result<usize, RsaError>;
}
