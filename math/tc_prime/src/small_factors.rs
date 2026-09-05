//! Small-factor trial division using packed moduli.

use crate::integer::check_candidate;
use crate::{PrimeError, PrimeInteger};

/// The largest prime tested by [`has_any_small_factors`].
pub const SMALL_FACTOR_LIMIT: u32 = 211;

/// Each group performs one big-integer remainder followed by `u32` checks.
const GROUPS: [(u32, &[u32]); 10] = [
    (
        2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23,
        &[2, 3, 5, 7, 11, 13, 17, 19, 23],
    ),
    (29 * 31 * 37 * 41 * 43, &[29, 31, 37, 41, 43]),
    (47 * 53 * 59 * 61 * 67, &[47, 53, 59, 61, 67]),
    (71 * 73 * 79 * 83, &[71, 73, 79, 83]),
    (89 * 97 * 101 * 103, &[89, 97, 101, 103]),
    (107 * 109 * 113 * 127, &[107, 109, 113, 127]),
    (131 * 137 * 139 * 149, &[131, 137, 139, 149]),
    (151 * 157 * 163 * 167, &[151, 157, 163, 167]),
    (173 * 179 * 181 * 191, &[173, 179, 181, 191]),
    (193 * 197 * 199 * 211, &[193, 197, 199, 211]),
];

/// Tests whether `candidate` has a prime factor no greater than
/// [`SMALL_FACTOR_LIMIT`].
///
/// This preserves Bouncy Castle's `Primes.HasAnySmallFactors` semantics: a
/// candidate which is itself a covered small prime also returns `true`.
/// Therefore this function is a screening primitive, not a primality test.
/// Candidates below two return [`PrimeError::InvalidCandidate`].
///
/// # Example
///
/// ```
/// use tc_bigint::U64;
/// use tc_prime::has_any_small_factors;
///
/// assert!(has_any_small_factors(&U64::from(211_u16))?);
/// assert!(!has_any_small_factors(&U64::from(223_u16))?);
/// assert!(has_any_small_factors(&U64::from(3_u8))?);
/// # Ok::<(), tc_prime::PrimeError>(())
/// ```
pub fn has_any_small_factors<T: PrimeInteger>(candidate: &T) -> Result<bool, PrimeError> {
    check_candidate(candidate)?;
    has_any_small_factors_unchecked(candidate)
}

pub(crate) fn has_any_small_factors_unchecked<T: PrimeInteger>(
    candidate: &T,
) -> Result<bool, PrimeError> {
    for &(modulus, divisors) in &GROUPS {
        let remainder = (candidate.clone() % modulus)
            .to_u32()
            .ok_or(PrimeError::Overflow)?;
        if divisors.iter().any(|divisor| remainder % divisor == 0) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use tc_bigint::BigUint;
    use tc_bigint::{FixedBigUint, Word};

    type U256 = FixedBigUint<{ 256 / Word::BITS as usize }>;

    fn verify_all_groups<T: PrimeInteger>() {
        let prime = T::from_u64(1_000_003).expect("test prime fits");
        assert_eq!(has_any_small_factors(&prime), Ok(false));

        for small_factor in 2..=SMALL_FACTOR_LIMIT {
            let factor = T::from_u32(small_factor).expect("small factor fits");
            let candidate = prime.checked_mul(&factor).expect("test product fits");
            assert_eq!(
                has_any_small_factors(&candidate),
                Ok(true),
                "missing a prime divisor of {small_factor}"
            );
        }

        assert_eq!(
            has_any_small_factors(&T::from_u32(211).expect("fits")),
            Ok(true)
        );
        assert_eq!(
            has_any_small_factors(&T::from_u32(223).expect("fits")),
            Ok(false)
        );
    }

    #[test]
    fn packed_trial_division_supports_dynamic_and_fixed_integers() {
        #[cfg(feature = "alloc")]
        verify_all_groups::<BigUint>();
        verify_all_groups::<U256>();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn candidate_itself_counts_as_a_small_factor() {
        assert_eq!(has_any_small_factors(&BigUint::from(3_u8)), Ok(true));
        assert_eq!(
            has_any_small_factors(&BigUint::from(1_u8)),
            Err(PrimeError::InvalidCandidate)
        );
    }
}
