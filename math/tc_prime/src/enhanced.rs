//! FIPS 186-4 C.3.2 enhanced Miller-Rabin testing.

use crate::integer::{check_candidate, integer};
use crate::miller_rabin::random_base;
use crate::{PrimeError, PrimeInteger};
use rand_core::Rng;

/// The result of an enhanced Miller-Rabin test.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MrOutput<T> {
    /// No tested base proved that the candidate is composite.
    ProbablyPrime,
    /// The candidate is composite and a non-trivial factor was recovered.
    ProvablyCompositeWithFactor(T),
    /// The candidate is composite and the test did not recover a factor.
    ProvablyCompositeNotPrimePower,
}

impl<T> MrOutput<T> {
    /// Returns `true` when the test proved that the candidate is composite.
    pub const fn is_provably_composite(&self) -> bool {
        !matches!(self, Self::ProbablyPrime)
    }

    /// Returns the non-trivial factor recovered by the test, if any.
    pub const fn factor(&self) -> Option<&T> {
        match self {
            Self::ProvablyCompositeWithFactor(factor) => Some(factor),
            _ => None,
        }
    }

    /// Returns `true` when the candidate was proved composite without a factor.
    pub const fn is_not_prime_power(&self) -> bool {
        matches!(self, Self::ProvablyCompositeNotPrimePower)
    }
}

/// Runs enhanced Miller-Rabin and reports additional composite information.
///
/// Compared with [`crate::is_mr_probable_prime`], this variant first checks the
/// greatest common divisor of each base and may return a non-trivial factor.
/// When it proves compositeness without recovering a factor, the result is
/// [`MrOutput::ProvablyCompositeNotPrimePower`].
///
/// # Example
///
/// ```
/// use rand::{SeedableRng, rngs::StdRng};
/// use tc_bigint::U64;
/// use tc_prime::{MrOutput, enhanced_mr_probable_prime_test};
///
/// let candidate = U64::from(97_u8) * U64::from(97_u8);
/// let mut rng = StdRng::seed_from_u64(11);
/// let result = enhanced_mr_probable_prime_test(&candidate, &mut rng, 16)?;
///
/// assert!(result.is_provably_composite());
/// assert_eq!(result.factor(), Some(&U64::from(97_u8)));
/// assert!(matches!(result, MrOutput::ProvablyCompositeWithFactor(_)));
/// # Ok::<(), tc_prime::PrimeError>(())
/// ```
pub fn enhanced_mr_probable_prime_test<T, R>(
    candidate: &T,
    rng: &mut R,
    iterations: u32,
) -> Result<MrOutput<T>, PrimeError>
where
    T: PrimeInteger,
    R: Rng + ?Sized,
{
    check_candidate(candidate)?;
    if iterations == 0 {
        return Err(PrimeError::InvalidIterations);
    }
    if candidate.bit_length() == 2 {
        return Ok(MrOutput::ProbablyPrime);
    }

    let one = T::one();
    let two = integer::<T>(2)?;
    if !candidate.test_bit(0) {
        return Ok(MrOutput::ProvablyCompositeWithFactor(two));
    }

    let candidate_sub_one = candidate.clone() - &one;
    let powers_of_two = candidate_sub_one
        .lowest_set_bit()
        .expect("candidate minus one is non-zero");
    let odd_part = candidate_sub_one.clone() >> powers_of_two;

    for _ in 0..iterations {
        let base = random_base(candidate, rng)?;
        let mut factor = base.gcd(candidate);
        if factor > one {
            return Ok(MrOutput::ProvablyCompositeWithFactor(factor));
        }

        let mut z = base.mod_pow(&odd_part, candidate);
        if z.is_one() || z == candidate_sub_one {
            continue;
        }

        let mut prime_to_base = false;
        let mut x = z.clone();
        for _ in 1..powers_of_two {
            z = z.mod_mul(&z, candidate);
            if z == candidate_sub_one {
                prime_to_base = true;
                break;
            }
            if z.is_one() {
                break;
            }
            x = z.clone();
        }

        if !prime_to_base {
            if !z.is_one() {
                x = z.clone();
                z = z.mod_mul(&z, candidate);
                if !z.is_one() {
                    x = z;
                }
            }

            factor = (x - &one).gcd(candidate);
            if factor > one {
                return Ok(MrOutput::ProvablyCompositeWithFactor(factor));
            }
            return Ok(MrOutput::ProvablyCompositeNotPrimePower);
        }
    }

    Ok(MrOutput::ProbablyPrime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};
    #[cfg(feature = "alloc")]
    use tc_bigint::BigUint;
    use tc_bigint::U256;

    fn value<T: PrimeInteger>(input: u64) -> T {
        T::from_u64(input).expect("test value fits")
    }

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    fn verify_basic_results<T: PrimeInteger>() {
        let prime = value::<T>(104_729);
        let output = enhanced_mr_probable_prime_test(&prime, &mut rng(7), 12).unwrap();
        assert!(matches!(output, MrOutput::ProbablyPrime));
        assert!(!output.is_provably_composite());
        assert!(output.factor().is_none());

        let square = prime.checked_mul(&prime).expect("test square fits");
        let output = enhanced_mr_probable_prime_test(&square, &mut rng(11), 16).unwrap();
        assert!(output.is_provably_composite());
        assert!(output.factor() == Some(&prime));
        assert!(!output.is_not_prime_power());

        let even = value::<T>(2 * 104_729);
        let output = enhanced_mr_probable_prime_test(&even, &mut rng(13), 1).unwrap();
        assert!(output.factor() == Some(&value::<T>(2)));
    }

    #[test]
    fn enhanced_results_support_dynamic_and_fixed_integers() {
        #[cfg(feature = "alloc")]
        verify_basic_results::<BigUint>();
        verify_basic_results::<U256>();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn product_of_distinct_primes_is_not_a_prime_power() {
        let candidate = BigUint::from(10_007_u32) * BigUint::from(10_009_u32);
        let output = enhanced_mr_probable_prime_test(&candidate, &mut rng(19), 16).unwrap();
        assert_eq!(output, MrOutput::ProvablyCompositeNotPrimePower);
        assert!(output.is_not_prime_power());
        assert_eq!(output.factor(), None);
    }
}
