//! The parameters of RSA key generation.

use rand_core::CryptoRng;

/// What an RSA key pair is generated to, as Bouncy Castle's
/// `RsaKeyGenerationParameters` holds it: the random source, the public
/// exponent, the size of the modulus in bits, and the certainty the primes
/// are tested to. [`RsaKeyGenerationParamsRef`](crate::RsaKeyGenerationParamsRef)
/// borrows its random source, and
/// [`RsaKeyGenerationParamsOwned`](crate::RsaKeyGenerationParamsOwned) owns
/// it; parameters that hold their source another way implement it too, and
/// the generator takes them as it takes those.
///
/// Nothing here promises the values make a key: the generator checks them
/// when it is initialized.
pub trait RsaKeyGenerationParams {
    /// The public exponent `e`. Constant time.
    fn public_exponent(&self) -> u32;

    /// The size of the modulus in bits. Constant time.
    fn strength(&self) -> u32;

    /// The certainty the primes are tested to: a composite passes with a
    /// probability of at most `2^-certainty`. Constant time.
    fn certainty(&self) -> u32;

    /// The random source the generator draws from. Constant time.
    fn rng(&mut self) -> &mut dyn CryptoRng;
}
