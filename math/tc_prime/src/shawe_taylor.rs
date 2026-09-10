//! FIPS 186-4 C.6 Shawe-Taylor `Random_Prime` routine.

use alloc::{vec, vec::Vec};

use tc_bigint::ArrayEncoding;
use tc_digest::Digest;

use crate::integer::integer;
use crate::small_factors::has_any_small_factors_unchecked;
use crate::{PrimeError, PrimeInteger};

/// Output produced by Shawe-Taylor provable-prime generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StOutput<T> {
    prime: T,
    prime_seed: Vec<u8>,
    prime_gen_counter: u32,
}

impl<T> StOutput<T> {
    /// Returns the generated provable prime.
    pub const fn prime(&self) -> &T {
        &self.prime
    }

    /// Returns the seed state after generation completed.
    pub fn prime_seed(&self) -> &[u8] {
        &self.prime_seed
    }

    /// Returns the accumulated candidate-generation count.
    pub const fn prime_gen_counter(&self) -> u32 {
        self.prime_gen_counter
    }

    /// Consumes the output and returns the prime, final seed, and counter.
    pub fn into_parts(self) -> (T, Vec<u8>, u32) {
        (self.prime, self.prime_seed, self.prime_gen_counter)
    }
}

/// Generates a `length`-bit Shawe-Taylor provable prime.
///
/// Generation is deterministic for a given digest algorithm, bit length, and
/// input seed. The digest is reset by each finalization as required by the
/// [`tc_digest::Digest`] contract. `length` must be at least two and
/// `input_seed` must not be empty.
///
/// A fixed-width result returns [`PrimeError::Overflow`] when the requested
/// length or an intermediate value does not fit. This function is available
/// only when the `digest` feature is enabled.
///
/// # Example
///
/// ```
/// use tc_bigint::{BigUint, BitOps};
/// use tc_prime::generate_st_random_prime;
/// use tc_sha::Sha256Digest;
///
/// let seed = b"deterministic seed";
/// let mut digest = Sha256Digest::new();
/// let output = generate_st_random_prime::<BigUint, _>(&mut digest, 64, seed)?;
///
/// assert_eq!(output.prime().bit_length(), 64);
/// assert!(output.prime_gen_counter() > 0);
/// assert_ne!(output.prime_seed(), seed);
/// # Ok::<(), tc_prime::PrimeError>(())
/// ```
pub fn generate_st_random_prime<T, D>(
    digest: &mut D,
    length: u32,
    input_seed: &[u8],
) -> Result<StOutput<T>, PrimeError>
where
    T: PrimeInteger + ArrayEncoding,
    D: Digest + ?Sized,
{
    if length < 2 {
        return Err(PrimeError::InvalidLength);
    }
    if input_seed.is_empty() {
        return Err(PrimeError::EmptySeed);
    }
    generate_st_random_prime_inner(digest, length, input_seed.to_vec())
}

fn generate_st_random_prime_inner<T, D>(
    digest: &mut D,
    length: u32,
    mut prime_seed: Vec<u8>,
) -> Result<StOutput<T>, PrimeError>
where
    T: PrimeInteger + ArrayEncoding,
    D: Digest + ?Sized,
{
    let digest_len = digest.digest_size();
    let candidate_len = core::cmp::max(4, digest_len);

    if length < 33 {
        let mut prime_gen_counter = 0_u32;
        let mut c0 = vec![0_u8; candidate_len];
        let mut c1 = vec![0_u8; candidate_len];

        loop {
            hash(digest, &prime_seed, &mut c0[candidate_len - digest_len..]);
            increment_seed(&mut prime_seed, 1);
            hash(digest, &prime_seed, &mut c1[candidate_len - digest_len..]);
            increment_seed(&mut prime_seed, 1);

            let mut candidate = u32::from_be_bytes(
                c0[candidate_len - 4..]
                    .try_into()
                    .expect("slice contains four bytes"),
            ) ^ u32::from_be_bytes(
                c1[candidate_len - 4..]
                    .try_into()
                    .expect("slice contains four bytes"),
            );
            candidate &= u32::MAX >> (32 - length);
            candidate |= (1_u32 << (length - 1)) | 1;

            prime_gen_counter = prime_gen_counter
                .checked_add(1)
                .ok_or(PrimeError::Overflow)?;
            if is_prime32(candidate) {
                return Ok(StOutput {
                    prime: T::from_u32(candidate).ok_or(PrimeError::Overflow)?,
                    prime_seed,
                    prime_gen_counter,
                });
            }

            if prime_gen_counter > length.checked_mul(4).ok_or(PrimeError::Overflow)? {
                return Err(PrimeError::TooManyIterations);
            }
        }
    }

    let recursive_length = length.checked_add(3).ok_or(PrimeError::Overflow)? / 2;
    let recursive = generate_st_random_prime_inner::<T, D>(digest, recursive_length, prime_seed)?;
    let (c0, mut prime_seed, mut prime_gen_counter) = recursive.into_parts();
    let old_counter = prime_gen_counter;

    let output_bits = digest_len.checked_mul(8).ok_or(PrimeError::Overflow)?;
    if output_bits == 0 {
        return Err(PrimeError::Overflow);
    }
    let iterations = (length as usize - 1) / output_bits;
    let hash_count = iterations.checked_add(1).ok_or(PrimeError::Overflow)?;

    let one = T::one();
    let two = integer::<T>(2)?;
    let three = integer::<T>(3)?;
    let lower_bound = one.checked_shl(length - 1).ok_or(PrimeError::Overflow)?;

    let mut x = hash_gen::<T, D>(digest, &mut prime_seed, hash_count)? % &lower_bound;
    x = x.set_bit(length as usize - 1);

    let c0_times_two = c0.checked_shl(1).ok_or(PrimeError::Overflow)?;
    let x_sub_one = x.checked_sub(&one).ok_or(PrimeError::Overflow)?;
    let quotient = x_sub_one / &c0_times_two;
    let mut tx2 = quotient
        .checked_add(&one)
        .and_then(|value| value.checked_shl(1))
        .ok_or(PrimeError::Overflow)?;
    let mut delta = 0_u32;
    let mut candidate = checked_mul_add_one(&tx2, &c0, &one)?;

    let iteration_limit = old_counter
        .checked_add(length.checked_mul(4).ok_or(PrimeError::Overflow)?)
        .ok_or(PrimeError::Overflow)?;

    loop {
        if candidate.bit_length() > length as usize {
            let below_bound = lower_bound.checked_sub(&one).ok_or(PrimeError::Overflow)?;
            let quotient = below_bound / &c0_times_two;
            tx2 = quotient
                .checked_add(&one)
                .and_then(|value| value.checked_shl(1))
                .ok_or(PrimeError::Overflow)?;
            candidate = checked_mul_add_one(&tx2, &c0, &one)?;
        }

        prime_gen_counter = prime_gen_counter
            .checked_add(1)
            .ok_or(PrimeError::Overflow)?;

        /*
         * This is BC's trial-division optimization of the original routine.
         * Even when a small factor rejects a candidate, prime_seed must advance
         * by the number of hashes the full check would have consumed.
         */
        if has_any_small_factors_unchecked(&candidate)? {
            increment_seed(&mut prime_seed, hash_count);
        } else {
            let candidate_sub_three = candidate.checked_sub(&three).ok_or(PrimeError::Overflow)?;
            let a = hash_gen::<T, D>(digest, &mut prime_seed, hash_count)? % &candidate_sub_three;
            let a = a.checked_add(&two).ok_or(PrimeError::Overflow)?;

            let delta_value = T::from_u32(delta).ok_or(PrimeError::Overflow)?;
            tx2 = tx2.checked_add(&delta_value).ok_or(PrimeError::Overflow)?;
            delta = 0;

            let z = a.mod_pow(&tx2, &candidate);
            let gcd_is_one = if z.is_zero() {
                true
            } else {
                let z_sub_one = z.checked_sub(&one).ok_or(PrimeError::Overflow)?;
                z_sub_one.gcd(&candidate).is_one()
            };
            if gcd_is_one && z.mod_pow(&c0, &candidate).is_one() {
                return Ok(StOutput {
                    prime: candidate,
                    prime_seed,
                    prime_gen_counter,
                });
            }
        }

        if prime_gen_counter >= iteration_limit {
            return Err(PrimeError::TooManyIterations);
        }

        delta = delta.checked_add(2).ok_or(PrimeError::Overflow)?;
        candidate = candidate
            .checked_add(&c0_times_two)
            .ok_or(PrimeError::Overflow)?;
    }
}

fn checked_mul_add_one<T: PrimeInteger>(left: &T, right: &T, one: &T) -> Result<T, PrimeError> {
    left.checked_mul(right)
        .and_then(|value| value.checked_add(one))
        .ok_or(PrimeError::Overflow)
}

fn hash<D: Digest + ?Sized>(digest: &mut D, input: &[u8], output: &mut [u8]) {
    digest.update(input);
    let written = digest.do_final(output);
    debug_assert_eq!(written, output.len());
}

fn hash_gen<T, D>(digest: &mut D, seed: &mut [u8], count: usize) -> Result<T, PrimeError>
where
    T: ArrayEncoding,
    D: Digest + ?Sized,
{
    let digest_len = digest.digest_size();
    let output_len = count.checked_mul(digest_len).ok_or(PrimeError::Overflow)?;
    let mut output = vec![0_u8; output_len];
    let mut position = output_len;
    for _ in 0..count {
        position -= digest_len;
        hash(digest, seed, &mut output[position..position + digest_len]);
        increment_seed(seed, 1);
    }
    T::from_unsigned_be_bytes(&output).map_err(|_| PrimeError::Overflow)
}

fn increment_seed(seed: &mut [u8], mut increment: usize) {
    for byte in seed.iter_mut().rev() {
        if increment == 0 {
            break;
        }
        increment += usize::from(*byte);
        *byte = increment as u8;
        increment >>= 8;
    }
}

fn is_prime32(candidate: u32) -> bool {
    if candidate < 32 {
        return ((1_u32 << candidate) & 0b0010_0000_1000_1010_0010_1000_1010_1100) != 0;
    }

    if ((1_u32 << (candidate % 30)) & 0b1010_0000_1000_1010_0010_1000_1000_0010) == 0 {
        return false;
    }

    let wheel = [1_u32, 7, 11, 13, 17, 19, 23, 29];
    let mut base = 0_u32;
    let mut position = 1;
    loop {
        while position < wheel.len() {
            let divisor = base + wheel[position];
            if candidate.is_multiple_of(divisor) {
                return false;
            }
            position += 1;
        }

        base += 30;
        // The first condition prevents `base * base` from overflowing.
        if (base >> 16 != 0) || (base * base >= candidate) {
            return true;
        }
        position = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};
    use tc_bigint::BigUint;
    use tc_sha::{Sha1Digest, Sha256Digest};

    fn verify_digest<D>(first: D, second: D, flipped: D)
    where
        D: Digest,
    {
        let seed = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut first = first;
        let mut second = second;
        let output = generate_st_random_prime::<BigUint, _>(&mut first, 256, &seed).unwrap();
        let repeated = generate_st_random_prime::<BigUint, _>(&mut second, 256, &seed).unwrap();

        assert_eq!(output, repeated);
        assert_eq!(output.prime().bit_length(), 256);
        assert!(output.prime_gen_counter() > 0);

        let mut rng = StdRng::seed_from_u64(0x5eed);
        assert!(output.prime().is_probable_prime(100, &mut rng));

        let mut opposite_seed = seed;
        for byte in &mut opposite_seed {
            *byte ^= 0xff;
        }
        let mut flipped = flipped;
        let different =
            generate_st_random_prime::<BigUint, _>(&mut flipped, 256, &opposite_seed).unwrap();
        assert_ne!(output.prime(), different.prime());
        assert_ne!(output.prime_seed(), different.prime_seed());
    }

    #[test]
    fn shawe_taylor_is_deterministic_for_sha1_and_sha256() {
        verify_digest(Sha1Digest::new(), Sha1Digest::new(), Sha1Digest::new());
        verify_digest(
            Sha256Digest::new(),
            Sha256Digest::new(),
            Sha256Digest::new(),
        );
    }

    #[test]
    fn fixed_width_overflow_and_invalid_inputs_are_reported() {
        use tc_bigint::U128;

        assert_eq!(
            generate_st_random_prime::<BigUint, _>(&mut Sha256Digest::new(), 1, &[1]),
            Err(PrimeError::InvalidLength)
        );
        assert_eq!(
            generate_st_random_prime::<BigUint, _>(&mut Sha256Digest::new(), 64, &[]),
            Err(PrimeError::EmptySeed)
        );
        assert_eq!(
            generate_st_random_prime::<U128, _>(&mut Sha256Digest::new(), 256, &[1]),
            Err(PrimeError::Overflow)
        );
    }

    #[test]
    fn prime32_matches_known_values_and_composites() {
        for prime in [2, 3, 5, 7, 29, 37, 65_521, 4_294_967_291] {
            assert!(is_prime32(prime), "{prime} should be prime");
        }
        for composite in [0, 1, 4, 9, 25, 2_047, u32::MAX] {
            assert!(!is_prime32(composite), "{composite} should be composite");
        }
    }

    #[test]
    fn seed_increment_is_big_endian_and_discards_overflow() {
        let mut seed = [0x00, 0xff];
        increment_seed(&mut seed, 2);
        assert_eq!(seed, [0x01, 0x01]);

        let mut wrapped = [0xff];
        increment_seed(&mut wrapped, 1);
        assert_eq!(wrapped, [0x00]);
    }
}
