//! RSA key pair generation, as Bouncy Castle's `RsaKeyPairGenerator` runs
//! it, over `PaddedBigUint`.

use alloc::boxed::Box;
use core::marker::PhantomData;

use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::PaddedBigUint;
use tc_zeroize::Zeroize;

use super::generation::{check, generate};
use crate::{RsaError, RsaKeyGenerationParams, RsaKeyOwned, RsaPrivateCrtKeyOwned};

/// Generates RSA key pairs as Bouncy Castle's `RsaKeyPairGenerator` does,
/// the modulus and the exponents as integers of type `T`, the primes and
/// the values modulo them as integers of type `H`. It works in
/// `PaddedBigUint`, which takes `alloc`, and converts the key into `T` and
/// `H` at the end. It draws from the random source of the parameters it is
/// initialized with, of any kind that implements
/// [`RsaKeyGenerationParams`], which it keeps behind `dyn` for as long as
/// `'a`: that of the source that
/// [`RsaKeyGenerationParamsRef`](crate::RsaKeyGenerationParamsRef)
/// borrows, or `'static` for
/// [`RsaKeyGenerationParamsOwned`](crate::RsaKeyGenerationParamsOwned).
/// `'a` is inferred.
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_bigint::{FixedBigUint, Word};
/// use tc_rsa_v2::{RsaKeyGenerationParamsOwned, RsaKeyPairGenerator};
///
/// // A 2048-bit modulus, with its primes at half that width, so that the
/// // CRT runs on integers half as wide; the widths follow from the limbs.
/// type U2048 = FixedBigUint<{ 2048 / Word::BITS as usize }>;
/// type U1024 = FixedBigUint<{ 1024 / Word::BITS as usize }>;
///
/// // The defaults: a 2048-bit modulus and the public exponent 65537, drawn
/// // from the system's random source; `with_strength` and the other
/// // `with_*` methods change them.
/// let params = RsaKeyGenerationParamsOwned::new(rand::rng());
/// let mut generator = RsaKeyPairGenerator::<U2048, U1024>::new();
/// generator.init(params)?;
///
/// // The public key holds `n` and `e`; the private one adds `d` and the
/// // values of the CRT.
/// let (public, private) = generator.generate_key_pair()?;
/// # Ok::<(), tc_rsa_v2::RsaError>(())
/// ```
pub struct RsaKeyPairGenerator<'a, T, H = T> {
    params: Option<Box<dyn RsaKeyGenerationParams + 'a>>,
    integers: PhantomData<(T, H)>,
}

impl<T, H> RsaKeyPairGenerator<'_, T, H> {
    /// A generator to be initialized before it generates. Constant time.
    pub const fn new() -> Self {
        Self {
            params: None,
            integers: PhantomData,
        }
    }
}

/// Through [`new`](RsaKeyPairGenerator::new). Constant time.
impl<T, H> Default for RsaKeyPairGenerator<'_, T, H> {
    fn default() -> Self {
        Self::new()
    }
}

/// Keeps the parameters, of any kind, once they are checked: an odd
/// public exponent of at least three, a certainty of at least one, and a
/// modulus of at least 16 bits that `T` holds, with primes `H` holds.
/// Variable time: only for public values, as the parameters are.
impl<'a, T, H, P> KeyPairGeneratorInit<P> for RsaKeyPairGenerator<'a, T, H>
where
    T: TryFrom<PaddedBigUint>,
    H: TryFrom<PaddedBigUint>,
    P: RsaKeyGenerationParams + 'a,
{
    type Error = RsaError;

    fn init(&mut self, params: P) -> Result<(), RsaError> {
        check::<T, H>(
            params.public_exponent(),
            params.strength(),
            params.certainty(),
        )?;
        self.params = Some(Box::new(params));
        Ok(())
    }
}

/// Draws primes until they make a key, as Bouncy Castle does, in
/// `PaddedBigUint`, then converts the key into `T` and `H`. Variable time,
/// only for a caller that accepts it, as key generation everywhere does:
/// how many candidates are drawn, and which tests turn them down, shows in
/// the running time. The secret values it names are wiped once the key is
/// out; the working values inside the arithmetic of `tc_bigint` and
/// `tc_prime` are not all wiped, nor is the copy a conversion into a
/// fixed-width integer takes and drops.
impl<T, H> KeyPairGenerator for RsaKeyPairGenerator<'_, T, H>
where
    T: Zeroize + TryFrom<PaddedBigUint>,
    H: Zeroize + TryFrom<PaddedBigUint>,
{
    type PublicKey = RsaKeyOwned<T>;
    type PrivateKey = RsaPrivateCrtKeyOwned<T, H>;
    type Error = RsaError;

    fn generate_key_pair(
        &mut self,
    ) -> Result<(RsaKeyOwned<T>, RsaPrivateCrtKeyOwned<T, H>), RsaError> {
        let params = self.params.as_deref_mut().ok_or(RsaError::NotInitialized)?;
        let (public_exponent, strength, certainty) = (
            params.public_exponent(),
            params.strength(),
            params.certainty(),
        );
        let key = generate(params.rng(), public_exponent, strength, certainty);

        // The parameters were checked to fit `T` and `H`.
        let wide = |value: &PaddedBigUint| {
            T::try_from(value.clone()).map_err(|_| RsaError::InvalidStrength)
        };
        let half = |value: &PaddedBigUint| {
            H::try_from(value.clone()).map_err(|_| RsaError::InvalidStrength)
        };
        // The modulus is the product of two primes it drew, so the keys are
        // marked as checked.
        let public = RsaKeyOwned::new(false, wide(&key.n)?, wide(&key.e)?).into_validated();
        let private = RsaPrivateCrtKeyOwned::new(
            wide(&key.n)?,
            wide(&key.e)?,
            wide(&key.d)?,
            half(&key.p)?,
            half(&key.q)?,
            half(&key.dp)?,
            half(&key.dq)?,
            half(&key.q_inv)?,
        )
        .into_validated();
        Ok((public, private))
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
    use tc_bigint::{BigUint, FixedBigUint, PaddedBigUint};
    use tc_modular::{ModPow, NonZero};

    use crate::{
        RsaError, RsaKeyGenerationParams, RsaKeyGenerationParamsOwned, RsaKeyGenerationParamsRef,
        RsaKeyPairGenerator, RsaKeyParams, RsaPrivateCrtKeyParams,
    };

    /// Checks a private key, in `BigUint`, whose products need no width:
    /// `n = p · q` of `strength` bits, the CRT values, and a message that
    /// comes back from `e` and `d`.
    fn assert_valid<T, H>(key: &impl RsaPrivateCrtKeyParams<T, H>, strength: u32)
    where
        T: Clone,
        H: Clone,
        BigUint: From<T> + From<H>,
    {
        let wide = |value: &T| BigUint::from(value.clone());
        let half = |value: &H| BigUint::from(value.clone());
        let (n, e, d) = (
            wide(key.modulus()),
            wide(key.public_exponent()),
            wide(key.exponent()),
        );
        let (p, q) = (half(key.p()), half(key.q()));
        let one = BigUint::from(1u8);
        assert_eq!(n.bits(), strength);
        assert_eq!(&p * &q, n);
        assert!(p > q);
        assert_eq!(half(key.dp()), &d % &(&p - 1u32));
        assert_eq!(half(key.dq()), &d % &(&q - 1u32));
        assert_eq!(&half(key.q_inv()) * &q % &p, one);
        let modulus = NonZero::new(n).unwrap();
        let message = BigUint::from(0x1234_5678_u32);
        assert_eq!(message.mod_pow(&e, &modulus).mod_pow(&d, &modulus), message);
    }

    #[test]
    fn a_generated_key_holds_together() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut generator = RsaKeyPairGenerator::<PaddedBigUint>::new();
        generator
            .init(RsaKeyGenerationParamsRef::new(&mut rng).with_strength(256))
            .unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();
        assert_eq!(public.modulus(), private.modulus());
        assert_eq!(public.exponent(), &PaddedBigUint::from(65537u32));
        assert!(!public.is_private_key() && private.is_private_key());
        assert_valid(&private, 256);
    }

    #[test]
    fn keys_of_odd_sizes_and_other_exponents_hold_together() {
        let mut rng = StdRng::seed_from_u64(2);
        // 21 is no prime, which takes the gcd of e and p - 1.
        for (strength, e) in [(129, 3), (200, 21), (255, 65539)] {
            let mut generator = RsaKeyPairGenerator::<PaddedBigUint>::new();
            let params = RsaKeyGenerationParamsRef::new(&mut rng)
                .with_strength(strength)
                .with_public_exponent(e);
            generator.init(params).unwrap();
            let (_, private) = generator.generate_key_pair().unwrap();
            assert_valid(&private, strength);
            assert_eq!(private.public_exponent(), &PaddedBigUint::from(e));
        }
    }

    #[test]
    fn a_fixed_width_key_holds_its_primes_at_half_its_width() {
        // 256 bits fit eight limbs and 128 bits four, on 32-bit limbs too.
        let mut generator = RsaKeyPairGenerator::<FixedBigUint<8>, FixedBigUint<4>>::new();
        generator
            .init(RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(3)).with_strength(256))
            .unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();
        assert_eq!(public.modulus(), private.modulus());
        assert_valid(&private, 256);
    }

    #[test]
    fn the_same_seed_generates_the_same_key() {
        let generate = |seed| {
            let mut generator = RsaKeyPairGenerator::<PaddedBigUint>::new();
            generator
                .init(
                    RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(seed))
                        .with_strength(128),
                )
                .unwrap();
            generator.generate_key_pair().unwrap().0.modulus().clone()
        };
        assert_eq!(generate(4), generate(4));
        assert_ne!(generate(4), generate(5));
    }

    #[test]
    fn init_turns_down_parameters_that_cannot_make_a_key() {
        let init = |change: fn(RsaKeyGenerationParamsOwned) -> RsaKeyGenerationParamsOwned| {
            let mut generator = RsaKeyPairGenerator::<FixedBigUint<8>, FixedBigUint<4>>::new();
            generator.init(change(RsaKeyGenerationParamsOwned::new(
                StdRng::seed_from_u64(6),
            )))
        };
        assert_eq!(init(|params| params.with_strength(256)), Ok(()));
        assert_eq!(
            init(|params| params.with_strength(256).with_public_exponent(4)),
            Err(RsaError::InvalidPublicExponent)
        );
        assert_eq!(
            init(|params| params.with_strength(256).with_public_exponent(1)),
            Err(RsaError::InvalidPublicExponent)
        );
        assert_eq!(
            init(|params| params.with_strength(256).with_certainty(0)),
            Err(RsaError::InvalidCertainty)
        );
        assert_eq!(
            init(|params| params.with_strength(8)),
            Err(RsaError::InvalidStrength)
        );
        // 2048 bits do not fit eight limbs, of 32 or 64 bits.
        assert_eq!(init(|params| params), Err(RsaError::InvalidStrength));
        // Nor do primes of 128 bits fit one limb.
        let mut generator = RsaKeyPairGenerator::<FixedBigUint<8>, FixedBigUint<1>>::new();
        let params = RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(6)).with_strength(256);
        assert_eq!(generator.init(params), Err(RsaError::InvalidStrength));
    }

    /// Parameters of a kind the crate does not know, as a caller writes them.
    struct OwnKind(StdRng);

    impl RsaKeyGenerationParams for OwnKind {
        fn public_exponent(&self) -> u32 {
            3
        }

        fn strength(&self) -> u32 {
            128
        }

        fn certainty(&self) -> u32 {
            40
        }

        fn rng(&mut self) -> &mut dyn rand_core::CryptoRng {
            &mut self.0
        }
    }

    #[test]
    fn a_generator_takes_parameters_of_a_kind_of_the_caller_s_own() {
        let mut generator = RsaKeyPairGenerator::<PaddedBigUint>::new();
        generator.init(OwnKind(StdRng::seed_from_u64(7))).unwrap();
        let (_, private) = generator.generate_key_pair().unwrap();
        assert_valid(&private, 128);
        assert_eq!(private.public_exponent(), &PaddedBigUint::from(3u8));
    }

    #[test]
    fn a_generator_not_yet_initialized_generates_nothing() {
        let mut generator = RsaKeyPairGenerator::<PaddedBigUint>::new();
        assert_eq!(
            generator.generate_key_pair().err(),
            Some(RsaError::NotInitialized)
        );
    }
}
