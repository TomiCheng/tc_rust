//! FIPS 186-4 C.3.1 Miller-Rabin probabilistic primality testing.

use rand_core::Rng;
use tc_bigint::NonZero;

use crate::integer::{check_candidate, integer};
use crate::{PrimeError, PrimeInteger};

/// Runs Miller-Rabin using independently selected random bases.
///
/// `iterations` must be non-zero. The bases are selected uniformly from the
/// inclusive range `[2, candidate - 2]`. This function accepts any
/// [`rand_core::Rng`], but callers testing security-sensitive candidates should
/// supply a generator which also implements [`rand_core::CryptoRng`].
///
/// # Example
///
/// ```
/// use rand::{SeedableRng, rngs::StdRng};
/// use tc_bigint::U64;
/// use tc_prime::is_mr_probable_prime;
///
/// let mut rng = StdRng::seed_from_u64(7);
/// assert!(is_mr_probable_prime(&U64::from(104_729_u32), &mut rng, 16)?);
/// # Ok::<(), tc_prime::PrimeError>(())
/// ```
pub fn is_mr_probable_prime<T, R>(
    candidate: &T,
    rng: &mut R,
    iterations: u32,
) -> Result<bool, PrimeError>
where
    T: PrimeInteger,
    R: Rng + ?Sized,
{
    check_candidate(candidate)?;
    if iterations == 0 {
        return Err(PrimeError::InvalidIterations);
    }
    if candidate.bit_length() == 2 {
        return Ok(true);
    }
    if !candidate.test_bit(0) {
        return Ok(false);
    }

    let one = T::one();
    let w_sub_one = candidate.clone() - &one;
    let a = w_sub_one
        .lowest_set_bit()
        .expect("candidate minus one is non-zero");
    let m = w_sub_one.clone() >> a;

    for _ in 0..iterations {
        let base = random_base(candidate, rng)?;
        if !mr_probable_prime_to_base(candidate, &w_sub_one, &m, a, &base) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Runs one Miller-Rabin round with a caller-selected base.
///
/// `candidate` and `base` must both be at least two, and `base` must be less
/// than `candidate - 1`.
///
/// # Example
///
/// ```
/// use tc_bigint::U64;
/// use tc_prime::is_mr_probable_prime_to_base;
///
/// let base = U64::from(2_u8);
/// assert!(is_mr_probable_prime_to_base(&U64::from(97_u8), &base)?);
/// assert!(!is_mr_probable_prime_to_base(&U64::from(221_u16), &base)?);
/// # Ok::<(), tc_prime::PrimeError>(())
/// ```
pub fn is_mr_probable_prime_to_base<T: PrimeInteger>(
    candidate: &T,
    base: &T,
) -> Result<bool, PrimeError> {
    check_candidate(candidate)?;
    check_candidate(base)?;

    let one = T::one();
    let w_sub_one = candidate.clone() - &one;
    if base >= &w_sub_one {
        return Err(PrimeError::InvalidBase);
    }
    if candidate.bit_length() == 2 {
        return Ok(true);
    }

    let a = w_sub_one
        .lowest_set_bit()
        .expect("candidate minus one is non-zero");
    let m = w_sub_one.clone() >> a;
    Ok(mr_probable_prime_to_base(
        candidate, &w_sub_one, &m, a, base,
    ))
}

pub(crate) fn random_base<T, R>(candidate: &T, rng: &mut R) -> Result<T, PrimeError>
where
    T: PrimeInteger,
    R: Rng + ?Sized,
{
    let two = integer::<T>(2)?;
    let three = integer::<T>(3)?;
    let range = candidate.clone() - &three;
    let range = NonZero::new(range).expect("odd candidate is at least five");
    Ok(T::random_mod_vartime(rng, &range) + &two)
}

pub(crate) fn mr_probable_prime_to_base<T: PrimeInteger>(
    candidate: &T,
    candidate_sub_one: &T,
    odd_part: &T,
    powers_of_two: usize,
    base: &T,
) -> bool {
    let mut z = base.mod_pow(odd_part, candidate);
    if z.is_one() || &z == candidate_sub_one {
        return true;
    }

    for _ in 1..powers_of_two {
        // FixedBigUint cannot hold the full square; ModMul reduces it directly.
        z = z.mod_mul(&z, candidate);
        if &z == candidate_sub_one {
            return true;
        }
        if z.is_one() {
            return false;
        }
    }
    false
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

    fn verify_vectors<T: PrimeInteger>() {
        for prime in [97, 251, 7_919, 104_729] {
            assert_eq!(
                is_mr_probable_prime(&value::<T>(prime), &mut rng(prime), 12),
                Ok(true)
            );
            assert_eq!(
                is_mr_probable_prime_to_base(&value::<T>(prime), &value::<T>(2)),
                Ok(true)
            );
        }

        for composite in [561, 1_105, 1_729, 2_821, 2_047, 3_277, 4_033] {
            assert_eq!(
                is_mr_probable_prime(&value::<T>(composite), &mut rng(composite), 16),
                Ok(false),
                "{composite} passed all random bases"
            );
        }
    }

    #[test]
    fn known_vectors_support_dynamic_and_fixed_integers() {
        #[cfg(feature = "alloc")]
        verify_vectors::<BigUint>();
        verify_vectors::<U256>();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn fixed_base_api_cross_checks_multi_base_results() {
        for candidate in [97_u64, 561, 7_919, 2_821] {
            let candidate = BigUint::from(candidate);
            let reference = [2_u8, 3, 5, 7, 11].iter().all(|base| {
                is_mr_probable_prime_to_base(&candidate, &BigUint::from(*base)).unwrap()
            });
            let random = is_mr_probable_prime(&candidate, &mut rng(91), 16).unwrap();
            assert_eq!(random, reference);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn invalid_arguments_are_reported() {
        assert_eq!(
            is_mr_probable_prime(&BigUint::from(1_u8), &mut rng(1), 1),
            Err(PrimeError::InvalidCandidate)
        );
        assert_eq!(
            is_mr_probable_prime(&BigUint::from(17_u8), &mut rng(1), 0),
            Err(PrimeError::InvalidIterations)
        );
        assert_eq!(
            is_mr_probable_prime_to_base(&BigUint::from(17_u8), &BigUint::from(16_u8)),
            Err(PrimeError::InvalidBase)
        );
    }
}
