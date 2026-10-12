//! The checks of a key, as Bouncy Castle's `RsaKeyParameters` runs them on
//! a key it did not generate.

use num_traits::Zero;
use tc_bigint::BitOps;
use tc_prime::Primality;

use crate::RsaError;

/// The longest modulus taken, as Bouncy Castle's default `RsaMaxSize` is.
const MAX_BITS: u32 = 16384;

/// The first 50 primes, the bases of the Miller-Rabin rounds, as many as
/// Bouncy Castle runs on the smallest moduli.
const BASES: [u8; 50] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229,
];

/// Checks a key as Bouncy Castle's `RsaKeyParameters` does: a modulus that
/// is odd, and so not zero, and an exponent that is not zero, and odd for a
/// public key, then the modulus as [`validate_modulus`] does. Variable
/// time: only for public values, as the modulus is; the exponent is only
/// read for zero and its parity.
pub(crate) fn validate_key<T>(is_private: bool, modulus: &T, exponent: &T) -> Result<(), RsaError>
where
    T: Zero + BitOps + Primality + From<u8>,
{
    if modulus.is_zero() {
        return Err(RsaError::InvalidModulus);
    }
    if !modulus.bit(0) {
        return Err(RsaError::EvenModulus);
    }
    if exponent.is_zero() {
        return Err(RsaError::InvalidExponent);
    }
    if !is_private && !exponent.bit(0) {
        return Err(RsaError::EvenPublicExponent);
    }
    validate_modulus(modulus)
}

/// Checks an odd modulus as Bouncy Castle does: at most 16384 bits, no
/// prime factor below 212, and proved composite by Miller-Rabin, in as many
/// rounds as Bouncy Castle runs for half its size. Bouncy Castle draws the
/// bases at random; these are the first primes, which serve as well here,
/// as the check is a proof: a prime passes every base, and so is always
/// turned down, while a composite that passes them all, as one may be made
/// to, is only turned down too. Variable time: only for public values, as a
/// modulus is.
fn validate_modulus<T>(modulus: &T) -> Result<(), RsaError>
where
    T: BitOps + Primality + From<u8>,
{
    let bits = modulus.bits();
    if bits > MAX_BITS {
        return Err(RsaError::ModulusOutOfRange);
    }
    if modulus.has_small_factor() {
        return Err(RsaError::ModulusHasSmallFactor);
    }
    // Below 256, a modulus with no factor below 212 is a prime, and the
    // bases would not all lie below it.
    if bits <= 8 {
        return Err(RsaError::ModulusNotComposite);
    }
    let rounds = match bits / 2 {
        1536.. => 3,
        1024.. => 4,
        512.. => 7,
        _ => 50,
    };
    let proved = BASES[..rounds]
        .iter()
        .any(|&base| !modulus.is_probable_prime_to_base(&T::from(base)));
    if !proved {
        return Err(RsaError::ModulusNotComposite);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tc_bigint::{FixedBigUint, Word};

    use super::validate_modulus;
    use crate::RsaError;

    #[test]
    fn a_product_of_two_primes_above_211_passes() {
        assert_eq!(
            validate_modulus(&FixedBigUint::<1>::from(1009u32 * 1013)),
            Ok(())
        );
    }

    #[test]
    fn a_small_factor_is_turned_down() {
        for modulus in [3233u32, 3, 211, 211 * 1013] {
            let result = validate_modulus(&FixedBigUint::<1>::from(modulus));
            assert_eq!(result, Err(RsaError::ModulusHasSmallFactor), "{modulus}");
        }
    }

    #[test]
    fn a_prime_is_turned_down() {
        for modulus in [223u32, 1_000_003, (1 << 31) - 1] {
            let result = validate_modulus(&FixedBigUint::<1>::from(modulus));
            assert_eq!(result, Err(RsaError::ModulusNotComposite), "{modulus}");
        }
    }

    #[test]
    fn a_modulus_past_16384_bits_is_turned_down() {
        let mut modulus = FixedBigUint::<{ 16448 / Word::BITS as usize }>::from(1u8);
        modulus.set_bit(16384, true);
        assert_eq!(validate_modulus(&modulus), Err(RsaError::ModulusOutOfRange));
    }
}
