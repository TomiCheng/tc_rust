//! The blinding factor of an RSA blind signature, as Bouncy Castle's
//! `RsaBlindingFactorGenerator`.

use rand_core::CryptoRng;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::{PaddedBigUint, RandomRange};

use crate::{RsaError, RsaKey, RsaKeyParams};

/// Draws blinding factors for [`RsaBlindingEngine`](crate::RsaBlindingEngine)
/// from the random source `R` it holds, as Bouncy Castle's
/// `RsaBlindingFactorGenerator` does after the Handbook of Applied
/// Cryptography, page 475: a factor `r` of `2 ≤ r < n` with an inverse
/// modulo `n`, for the public key of the signer. Bouncy Castle draws it
/// below `2^(bits - 1)`; here it is drawn uniformly below `n`. `R` can be
/// a `&mut` borrow, so the caller keeps the source and its state. There is
/// no `Debug`, which would show the state of the source.
pub struct RsaBlindingFactorGenerator<R> {
    rng: R,
    modulus: Option<PaddedBigUint>,
}

impl<R> RsaBlindingFactorGenerator<R> {
    /// A generator drawing from `rng`, to be initialized before it draws.
    /// Constant time.
    pub const fn new(rng: R) -> Self {
        Self { rng, modulus: None }
    }

    /// Takes the modulus of `key`, once the key passes
    /// [`validate`](RsaKeyParams::validate); fails with `InvalidKey` for a
    /// private key, as Bouncy Castle does, or one that does not pass, and
    /// leaves the generator uninitialized. Variable time: only for public
    /// values, as the key is.
    pub fn init(&mut self, key: &RsaKey) -> Result<(), RsaError> {
        self.modulus = None;
        if key.is_private_key() || !key.validate() {
            return Err(RsaError::InvalidKey);
        }
        self.modulus = Some(key.modulus().clone());
        Ok(())
    }

    /// The random source back. Constant time.
    pub fn into_inner(self) -> R {
        self.rng
    }
}

impl<R: CryptoRng> RsaBlindingFactorGenerator<R> {
    /// A factor `r` of `2 ≤ r < n` that shares no factor with `n`, drawn
    /// again until one does not; fails with `NotInitialized` before
    /// [`init`](Self::init). Constant time in the factor, apart from how
    /// many are drawn, which shows in the running time, as in all drawing
    /// by rejection; a factor turned down shares a prime with `n`, which
    /// an RSA modulus all but never lets happen.
    pub fn generate_blinding_factor(&mut self) -> Result<PaddedBigUint, RsaError> {
        let modulus = self.modulus.as_ref().ok_or(RsaError::NotInitialized)?;
        let two = PaddedBigUint::from(2u8);
        loop {
            let factor = PaddedBigUint::random_range(&mut self.rng, &two, modulus);
            if factor.gcd(modulus).bits() == 1 {
                return Ok(factor);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_bigint::PaddedBigUint;

    use super::RsaBlindingFactorGenerator;
    use crate::{RsaError, RsaKey, RsaKeyOwned};

    fn int(value: u32) -> PaddedBigUint {
        PaddedBigUint::from(value)
    }

    fn textbook(private: bool) -> RsaKey {
        let exponent = if private { 2753 } else { 17 };
        RsaKey::from(RsaKeyOwned::new(private, int(3233), int(exponent)).into_validated())
    }

    #[test]
    fn every_factor_drawn_is_at_least_two_below_n_and_coprime_with_it() {
        let mut generator = RsaBlindingFactorGenerator::new(StdRng::seed_from_u64(1));
        generator.init(&textbook(false)).unwrap();
        for _ in 0..500 {
            let factor = generator.generate_blinding_factor().unwrap();
            assert!(factor >= int(2) && factor < int(3233));
            assert_eq!(factor.gcd(&int(3233)), int(1));
        }
    }

    #[test]
    fn the_same_seed_draws_the_same_factors() {
        let draw = || {
            let mut generator = RsaBlindingFactorGenerator::new(StdRng::seed_from_u64(2));
            generator.init(&textbook(false)).unwrap();
            [(); 4].map(|()| generator.generate_blinding_factor().unwrap())
        };
        assert_eq!(draw(), draw());
    }

    #[test]
    fn a_private_key_or_no_key_draws_nothing() {
        let mut generator = RsaBlindingFactorGenerator::new(StdRng::seed_from_u64(3));
        assert_eq!(
            generator.generate_blinding_factor(),
            Err(RsaError::NotInitialized)
        );
        assert_eq!(generator.init(&textbook(true)), Err(RsaError::InvalidKey));
        assert_eq!(
            generator.generate_blinding_factor(),
            Err(RsaError::NotInitialized)
        );
    }
}
