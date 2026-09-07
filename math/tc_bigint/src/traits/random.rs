//! Randomised construction and primality contracts, gated on `rand_core`.

use rand_core::{Rng, TryRng};

use super::numeric::Zero;
use crate::{NonZero, RandomBitsError};

/// Random full-width value generation.
pub trait Random: Sized {
    /// Generates a random value and preserves errors from the supplied RNG.
    fn try_random_from_rng<R: TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error>;

    /// Generates a random value from an infallible RNG.
    fn random_from_rng<R: Rng + ?Sized>(rng: &mut R) -> Self {
        match Self::try_random_from_rng(rng) {
            Ok(value) => value,
            Err(error) => match error {},
        }
    }
}

/// Random bits generation support.
pub trait RandomBits: Sized {
    /// Generates a value in `0..2^bit_length`, preserving RNG errors.
    fn try_random_bits<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
    ) -> Result<Self, RandomBitsError<R::Error>>;

    /// Generates a value in `0..2^bit_length` with an explicit storage precision.
    fn try_random_bits_with_precision<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
        bits_precision: u32,
    ) -> Result<Self, RandomBitsError<R::Error>>;

    /// Generates a value in `0..2^bit_length` from an infallible RNG.
    fn random_bits<R: Rng + ?Sized>(rng: &mut R, bit_length: u32) -> Self {
        Self::try_random_bits(rng, bit_length)
            .unwrap_or_else(|error| panic!("random bit generation failed: {error}"))
    }

    /// Generates random bits using an explicit storage precision.
    fn random_bits_with_precision<R: Rng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
        bits_precision: u32,
    ) -> Self {
        Self::try_random_bits_with_precision(rng, bit_length, bits_precision)
            .unwrap_or_else(|error| panic!("random bit generation failed: {error}"))
    }
}

/// Modular random number generation support.
pub trait RandomMod: Sized + Zero {
    /// Generates a uniformly random value below `modulus` using rejection sampling.
    ///
    /// The operation is variable-time with respect to the public modulus.
    fn try_random_mod_vartime<R: TryRng + ?Sized>(
        rng: &mut R,
        modulus: &NonZero<Self>,
    ) -> Result<Self, R::Error>;

    /// Infallible wrapper around [`Self::try_random_mod_vartime`].
    fn random_mod_vartime<R: Rng + ?Sized>(rng: &mut R, modulus: &NonZero<Self>) -> Self {
        match Self::try_random_mod_vartime(rng, modulus) {
            Ok(value) => value,
            Err(error) => match error {},
        }
    }

    /// Deprecated alias for [`Self::try_random_mod_vartime`].
    #[deprecated(since = "0.1.0", note = "use try_random_mod_vartime")]
    fn try_random_mod<R: TryRng + ?Sized>(
        rng: &mut R,
        modulus: &NonZero<Self>,
    ) -> Result<Self, R::Error> {
        Self::try_random_mod_vartime(rng, modulus)
    }

    /// Deprecated alias for [`Self::random_mod_vartime`].
    #[deprecated(since = "0.1.0", note = "use random_mod_vartime")]
    fn random_mod<R: Rng + ?Sized>(rng: &mut R, modulus: &NonZero<Self>) -> Self {
        Self::random_mod_vartime(rng, modulus)
    }
}

/// Construction of a random probable prime with an exact bit length.
pub trait ProbablePrime: Sized {
    /// Generates a probable prime using a default certainty of 100 bits.
    fn probable_prime<R: Rng + ?Sized>(rng: &mut R, bit_length: u32) -> Self;
}

/// Probabilistic primality testing.
pub trait IsProbablePrime {
    /// Returns `false` for a proven composite and `true` for a probable prime.
    ///
    /// A certainty of zero skips testing and returns `true`.
    fn is_probable_prime<R: Rng + ?Sized>(&self, certainty: u32, rng: &mut R) -> bool;
}

/// Search for the smallest probable prime strictly greater than a value.
pub trait NextProbablePrime {
    /// Result type. Fixed-width integers use `Option<Self>` to report overflow.
    type Output;

    /// Returns the next probable prime.
    fn next_probable_prime<R: Rng + ?Sized>(&self, rng: &mut R) -> Self::Output;
}
