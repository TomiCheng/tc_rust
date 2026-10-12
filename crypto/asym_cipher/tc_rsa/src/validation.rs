//! The checks of a key, as Bouncy Castle's `RsaKeyParameters` runs them on
//! a key it did not generate.

use num_traits::Zero;
use tc_bigint::BitOps;
use tc_prime::Primality;

/// The longest modulus taken, as Bouncy Castle's default `RsaMaxSize` is.
const MAX_BITS: u32 = 16384;

/// The first 50 primes, the bases of the Miller-Rabin rounds, as many as
/// Bouncy Castle runs on the smallest moduli.
const BASES: [u8; 50] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229,
];

/// Whether a key passes the checks of Bouncy Castle's `RsaKeyParameters`: a
/// modulus that is odd, and so not zero, and an exponent that is not zero,
/// and odd for a public key, then the modulus as [`modulus_passes`] checks
/// it. Variable time: only for public values, as the modulus is; the
/// exponent is only read for zero and its parity.
pub(crate) fn key_passes<T>(is_private: bool, modulus: &T, exponent: &T) -> bool
where
    T: Zero + BitOps + Primality + From<u8>,
{
    modulus.bit(0)
        && !exponent.is_zero()
        && (is_private || exponent.bit(0))
        && modulus_passes(modulus)
}

/// Whether an odd modulus passes the checks of Bouncy Castle: at most
/// 16384 bits, no prime factor below 212, and proved composite by
/// Miller-Rabin, in as many rounds as Bouncy Castle runs for half its size.
/// Bouncy Castle draws the bases at random; these are the first primes,
/// which serve as well here, as the check is a proof: a prime passes every
/// base, and so always fails the check, while a composite that passes them
/// all, as one may be made to, only fails it too. Variable time: only for
/// public values, as a modulus is.
fn modulus_passes<T>(modulus: &T) -> bool
where
    T: BitOps + Primality + From<u8>,
{
    let bits = modulus.bits();
    // Below 256, a modulus with no factor below 212 is a prime, and the
    // bases would not all lie below it.
    if bits > MAX_BITS || bits <= 8 || modulus.has_small_factor() {
        return false;
    }
    let rounds = match bits / 2 {
        1536.. => 3,
        1024.. => 4,
        512.. => 7,
        _ => 50,
    };
    BASES[..rounds]
        .iter()
        .any(|&base| !modulus.is_probable_prime_to_base(&T::from(base)))
}

#[cfg(test)]
mod tests {
    use tc_bigint::{FixedBigUint, Word};

    use super::{key_passes, modulus_passes};

    fn passes(modulus: u32) -> bool {
        modulus_passes(&FixedBigUint::<1>::from(modulus))
    }

    #[test]
    fn a_product_of_two_primes_above_211_passes() {
        assert!(passes(1009 * 1013));
    }

    #[test]
    fn a_small_factor_fails() {
        for modulus in [3233u32, 3, 211, 211 * 1013] {
            assert!(!passes(modulus), "{modulus}");
        }
    }

    #[test]
    fn a_prime_fails() {
        for modulus in [223u32, 1_000_003, (1 << 31) - 1] {
            assert!(!passes(modulus), "{modulus}");
        }
    }

    #[test]
    fn a_modulus_past_16384_bits_fails() {
        let mut modulus = FixedBigUint::<{ 16448 / Word::BITS as usize }>::from(1u8);
        modulus.set_bit(16384, true);
        assert!(!modulus_passes(&modulus));
    }

    #[test]
    fn the_modulus_and_exponent_must_be_odd_and_not_zero_as_bouncy_castle_asks() {
        let key = |private, n: u32, e: u32| {
            key_passes(private, &FixedBigUint::<1>::from(n), &FixedBigUint::from(e))
        };
        assert!(key(false, 1_022_117, 17));
        assert!(!key(false, 0, 17));
        assert!(!key(false, 1_022_118, 17));
        assert!(!key(false, 1_022_117, 0));
        assert!(!key(true, 1_022_117, 0));
        assert!(!key(false, 1_022_117, 16));
        assert!(key(true, 1_022_117, 16));
    }
}
