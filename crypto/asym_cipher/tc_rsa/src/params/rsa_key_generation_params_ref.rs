//! The parameters of RSA key generation, borrowing their random source.

use rand_core::CryptoRng;

use crate::RsaKeyGenerationParams;

/// What an RSA key pair is generated to, as Bouncy Castle's
/// `RsaKeyGenerationParameters` holds it: the random source, the public
/// exponent, the size of the modulus in bits, and the certainty the primes
/// are tested to. The random source is borrowed, behind `dyn`, so the
/// caller keeps it and its state, as a DRBG needs;
/// [`RsaKeyGenerationParamsOwned`](crate::RsaKeyGenerationParamsOwned)
/// owns its source instead. Key generation takes `alloc`, as it works in
/// `PaddedBigUint`.
///
/// The exponent is a `u32`, where Bouncy Castle takes any integer: it is
/// 65537 all but always, and keys from elsewhere, whose exponent may be
/// wider, come in as [`RsaKeyOwned`](crate::RsaKeyOwned) instead. It is a
/// container only: nothing is checked when it is built, and the generator
/// checks it when it is initialized. There is no `Debug`, which would need
/// the random source to show its state.
pub struct RsaKeyGenerationParamsRef<'a> {
    rng: &'a mut dyn CryptoRng,
    public_exponent: u32,
    strength: u32,
    certainty: u32,
}

impl<'a> RsaKeyGenerationParamsRef<'a> {
    /// The parameters drawing from `rng`, with the defaults: the public
    /// exponent 65537, a modulus of 2048 bits, and primes tested to the
    /// certainty 100, as Bouncy Castle's defaults are. The `with_*` methods
    /// change them. Constant time.
    pub const fn new(rng: &'a mut dyn CryptoRng) -> Self {
        Self {
            rng,
            public_exponent: 65537,
            strength: 2048,
            certainty: 100,
        }
    }

    /// The parameters with the public exponent `e`. Constant time.
    pub const fn with_public_exponent(mut self, e: u32) -> Self {
        self.public_exponent = e;
        self
    }

    /// The parameters with a modulus of `strength` bits. Constant time.
    pub const fn with_strength(mut self, strength: u32) -> Self {
        self.strength = strength;
        self
    }

    /// The parameters with primes tested to `certainty`. Constant time.
    pub const fn with_certainty(mut self, certainty: u32) -> Self {
        self.certainty = certainty;
        self
    }
}

/// The fields as they are held. Constant time.
impl RsaKeyGenerationParams for RsaKeyGenerationParamsRef<'_> {
    fn public_exponent(&self) -> u32 {
        self.public_exponent
    }

    fn strength(&self) -> u32 {
        self.strength
    }

    fn certainty(&self) -> u32 {
        self.certainty
    }

    fn rng(&mut self) -> &mut dyn CryptoRng {
        self.rng
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::RsaKeyGenerationParamsRef;
    use crate::RsaKeyGenerationParams;

    #[test]
    fn the_defaults_are_those_of_bouncy_castle() {
        let mut rng = StdRng::seed_from_u64(1);
        let params = RsaKeyGenerationParamsRef::new(&mut rng);
        assert_eq!(params.public_exponent(), 65537);
        assert_eq!(params.strength(), 2048);
        assert_eq!(params.certainty(), 100);
    }

    #[test]
    fn each_with_method_changes_its_own_value_alone() {
        let mut rng = StdRng::seed_from_u64(1);
        let params = RsaKeyGenerationParamsRef::new(&mut rng).with_strength(3072);
        let values = |params: &RsaKeyGenerationParamsRef| {
            (
                params.public_exponent(),
                params.strength(),
                params.certainty(),
            )
        };
        assert_eq!(values(&params), (65537, 3072, 100));
        let params = params.with_public_exponent(3).with_certainty(80);
        assert_eq!(values(&params), (3, 3072, 80));
    }
}
