//! Random integer generation and probabilistic primality testing.

use rand_core::{Rng, TryRng};

#[cfg(test)]
use crate::WideWord;
use crate::traits::{
    IsProbablePrime, NextProbablePrime, ProbablePrime, Random, RandomBits, RandomMod,
};
use crate::{FixedBigInt, FixedBigUint, Limb, NonZero, RandomBitsError, Word};

#[cfg(feature = "alloc")]
use crate::{BigInt, BigUint};

mod generate;
mod miller_rabin;

use generate::*;
use miller_rabin::*;

const DEFAULT_CERTAINTY: u32 = 100;

impl<const N: usize> FixedBigUint<N> {
    /// Tests this value using trial division followed by Miller-Rabin rounds.
    pub fn is_probable_prime<R: Rng + ?Sized>(&self, certainty: u32, rng: &mut R) -> bool {
        fixed_is_probable_prime(self, certainty, false, rng)
    }

    /// Generates a random probable prime with exactly `bit_length` bits.
    ///
    /// This method does not allocate. It panics when fewer than two bits are
    /// requested or when the requested width exceeds the fixed width.
    pub fn probable_prime<R: Rng + ?Sized>(rng: &mut R, bit_length: u32) -> Self {
        let bit_length = bit_length as usize;
        assert!(bit_length >= 2, "bit_length must be at least 2");
        assert!(
            bit_length <= N * Word::BITS as usize,
            "bit_length exceeds the fixed integer width"
        );
        if bit_length == 2 {
            return if random_word(rng) & 1 == 0 {
                fixed_small(2)
            } else {
                fixed_small(3)
            };
        }

        loop {
            let candidate = <Self as RandomBits>::random_bits(rng, bit_length as u32)
                .set_bit(bit_length - 1)
                .set_bit(0);
            if fixed_is_probable_prime(&candidate, DEFAULT_CERTAINTY, true, rng) {
                return candidate;
            }
        }
    }

    /// Returns the smallest probable prime greater than this value.
    ///
    /// Returns `None` when that prime cannot be represented at this fixed width.
    pub fn next_probable_prime<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<Self> {
        if N == 0 {
            return None;
        }
        let two = fixed_small(2);
        if self < &two {
            return Some(two);
        }

        let one = fixed_small(1);
        let candidate = {
            let (value, overflow) = crate::LimbArray::new(*(self.as_limbs()))
                .add(&crate::LimbArray::new(*(one.as_limbs())));
            (value.into_limbs(), overflow)
        };
        if candidate.1 {
            return None;
        }
        let mut candidate = Self::from_limbs(candidate.0);
        if !candidate.test_bit(0) {
            let next = {
                let (value, overflow) = crate::LimbArray::new(*(candidate.as_limbs()))
                    .add(&crate::LimbArray::new(*(one.as_limbs())));
                (value.into_limbs(), overflow)
            };
            if next.1 {
                return None;
            }
            candidate = Self::from_limbs(next.0);
        }

        loop {
            if candidate.is_probable_prime(DEFAULT_CERTAINTY, rng) {
                return Some(candidate);
            }
            let next = {
                let (value, overflow) = crate::LimbArray::new(*(candidate.as_limbs()))
                    .add(&crate::LimbArray::new(*(two.as_limbs())));
                (value.into_limbs(), overflow)
            };
            if next.1 {
                return None;
            }
            candidate = Self::from_limbs(next.0);
        }
    }
}

impl<const N: usize> Random for FixedBigUint<N> {
    fn try_random_from_rng<R: TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        try_random_fixed_uint(fixed_bits_precision::<N>() as usize, rng)
    }
}

impl<const N: usize> RandomBits for FixedBigUint<N> {
    fn try_random_bits<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
    ) -> Result<Self, RandomBitsError<R::Error>> {
        Self::try_random_bits_with_precision(rng, bit_length, fixed_bits_precision::<N>())
    }

    fn try_random_bits_with_precision<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
        bits_precision: u32,
    ) -> Result<Self, RandomBitsError<R::Error>> {
        let integer_bits = fixed_bits_precision::<N>();
        if bits_precision != integer_bits {
            return Err(RandomBitsError::BitsPrecisionMismatch {
                bits_precision,
                integer_bits,
            });
        }
        if bit_length > bits_precision {
            return Err(RandomBitsError::BitLengthTooLarge {
                bit_length,
                bits_precision,
            });
        }
        try_random_fixed_uint(bit_length as usize, rng).map_err(RandomBitsError::RandCore)
    }
}

impl<const N: usize> RandomMod for FixedBigUint<N> {
    fn try_random_mod_vartime<R: TryRng + ?Sized>(
        rng: &mut R,
        modulus: &NonZero<Self>,
    ) -> Result<Self, R::Error> {
        loop {
            let candidate = try_random_fixed_uint(modulus.bit_length(), rng)?;
            if candidate < **modulus {
                return Ok(candidate);
            }
        }
    }
}

impl<const N: usize> ProbablePrime for FixedBigUint<N> {
    fn probable_prime<R: Rng + ?Sized>(rng: &mut R, bit_length: u32) -> Self {
        FixedBigUint::probable_prime(rng, bit_length)
    }
}

impl<const N: usize> IsProbablePrime for FixedBigUint<N> {
    fn is_probable_prime<R: Rng + ?Sized>(&self, certainty: u32, rng: &mut R) -> bool {
        FixedBigUint::is_probable_prime(self, certainty, rng)
    }
}

impl<const N: usize> NextProbablePrime for FixedBigUint<N> {
    type Output = Option<Self>;

    fn next_probable_prime<R: Rng + ?Sized>(&self, rng: &mut R) -> Self::Output {
        FixedBigUint::next_probable_prime(self, rng)
    }
}

impl<const N: usize> FixedBigInt<N> {
    /// Tests the absolute value using trial division and Miller-Rabin rounds.
    pub fn is_probable_prime<R: Rng + ?Sized>(&self, certainty: u32, rng: &mut R) -> bool {
        let magnitude =
            FixedBigUint::from_limbs(FixedBigInt::from_limbs(*(self.as_limbs())).magnitude());
        magnitude.is_probable_prime(certainty, rng)
    }

    /// Generates a positive probable prime with exactly `bit_length` bits.
    ///
    /// This method does not allocate and reserves the top storage bit for the
    /// sign. It panics when the requested value cannot be represented.
    pub fn probable_prime<R: Rng + ?Sized>(rng: &mut R, bit_length: u32) -> Self {
        let bit_length_usize = bit_length as usize;
        assert!(
            bit_length_usize < N * Word::BITS as usize,
            "bit_length exceeds the positive fixed integer width"
        );
        Self::from_limbs(FixedBigUint::probable_prime(rng, bit_length).into_limbs())
    }

    /// Returns the smallest positive probable prime greater than this value.
    ///
    /// Returns `None` when that prime cannot be represented as a positive value.
    pub fn next_probable_prime<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<Self> {
        if N == 0 {
            return None;
        }
        let two = Self::from_limbs(fixed_small::<N>(2).into_limbs());
        if self < &two {
            return Some(two);
        }
        let magnitude = FixedBigUint::from_limbs(*self.as_limbs());
        let candidate = magnitude.next_probable_prime(rng)?;
        candidate
            .as_limbs()
            .last()
            .is_some_and(|word| word.to_word() >> (Word::BITS - 1) == 0)
            .then(|| Self::from_limbs(candidate.into_limbs()))
    }
}

impl<const N: usize> Random for FixedBigInt<N> {
    fn try_random_from_rng<R: TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        try_random_fixed_uint(fixed_bits_precision::<N>() as usize, rng)
            .map(|value| Self::from_limbs(value.into_limbs()))
    }
}

impl<const N: usize> RandomBits for FixedBigInt<N> {
    fn try_random_bits<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
    ) -> Result<Self, RandomBitsError<R::Error>> {
        Self::try_random_bits_with_precision(rng, bit_length, fixed_bits_precision::<N>())
    }

    fn try_random_bits_with_precision<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
        bits_precision: u32,
    ) -> Result<Self, RandomBitsError<R::Error>> {
        let integer_bits = fixed_bits_precision::<N>();
        if bits_precision != integer_bits {
            return Err(RandomBitsError::BitsPrecisionMismatch {
                bits_precision,
                integer_bits,
            });
        }
        let positive_bits = integer_bits.saturating_sub(1);
        if bit_length > positive_bits {
            return Err(RandomBitsError::BitLengthTooLarge {
                bit_length,
                bits_precision: positive_bits,
            });
        }
        <FixedBigUint<N> as RandomBits>::try_random_bits_with_precision(
            rng,
            bit_length,
            bits_precision,
        )
        .map(|value| Self::from_limbs(value.into_limbs()))
    }
}

impl<const N: usize> ProbablePrime for FixedBigInt<N> {
    fn probable_prime<R: Rng + ?Sized>(rng: &mut R, bit_length: u32) -> Self {
        FixedBigInt::probable_prime(rng, bit_length)
    }
}

impl<const N: usize> IsProbablePrime for FixedBigInt<N> {
    fn is_probable_prime<R: Rng + ?Sized>(&self, certainty: u32, rng: &mut R) -> bool {
        FixedBigInt::is_probable_prime(self, certainty, rng)
    }
}

impl<const N: usize> NextProbablePrime for FixedBigInt<N> {
    type Output = Option<Self>;

    fn next_probable_prime<R: Rng + ?Sized>(&self, rng: &mut R) -> Self::Output {
        FixedBigInt::next_probable_prime(self, rng)
    }
}

#[cfg(feature = "alloc")]
impl BigUint {
    /// Tests this value using trial division followed by Miller-Rabin rounds.
    pub fn is_probable_prime<R: Rng + ?Sized>(&self, certainty: u32, rng: &mut R) -> bool {
        big_uint_is_probable_prime(self, certainty, false, rng)
    }

    /// Generates a random probable prime with exactly `bit_length` bits.
    pub fn probable_prime<R: Rng + ?Sized>(rng: &mut R, bit_length: u32) -> Self {
        let bit_length = bit_length as usize;
        assert!(bit_length >= 2, "bit_length must be at least 2");
        if bit_length == 2 {
            return if random_word(rng) & 1 == 0 {
                Self::from(2_u8)
            } else {
                Self::from(3_u8)
            };
        }

        loop {
            let candidate = <Self as RandomBits>::random_bits(rng, bit_length as u32)
                .set_bit(bit_length - 1)
                .set_bit(0);
            if big_uint_is_probable_prime(&candidate, DEFAULT_CERTAINTY, true, rng) {
                return candidate;
            }
        }
    }

    /// Returns the smallest probable prime strictly greater than this value.
    pub fn next_probable_prime<R: Rng + ?Sized>(&self, rng: &mut R) -> Self {
        let two = Self::from(2_u8);
        if self < &two {
            return two;
        }
        let one = Self::from(1_u8);
        let mut candidate = self + &one;
        if !candidate.test_bit(0) {
            candidate += &one;
        }
        while !candidate.is_probable_prime(DEFAULT_CERTAINTY, rng) {
            candidate += &two;
        }
        candidate
    }
}

#[cfg(feature = "alloc")]
impl RandomBits for BigUint {
    fn try_random_bits<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
    ) -> Result<Self, RandomBitsError<R::Error>> {
        Self::try_random_bits_with_precision(rng, bit_length, bit_length)
    }

    fn try_random_bits_with_precision<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
        bits_precision: u32,
    ) -> Result<Self, RandomBitsError<R::Error>> {
        if bit_length > bits_precision {
            return Err(RandomBitsError::BitLengthTooLarge {
                bit_length,
                bits_precision,
            });
        }
        try_random_big_uint(bit_length as usize, rng).map_err(RandomBitsError::RandCore)
    }
}

#[cfg(feature = "alloc")]
impl RandomMod for BigUint {
    fn try_random_mod_vartime<R: TryRng + ?Sized>(
        rng: &mut R,
        modulus: &NonZero<Self>,
    ) -> Result<Self, R::Error> {
        loop {
            let candidate = try_random_big_uint(modulus.bit_length(), rng)?;
            if candidate < **modulus {
                return Ok(candidate);
            }
        }
    }
}

#[cfg(feature = "alloc")]
impl ProbablePrime for BigUint {
    fn probable_prime<R: Rng + ?Sized>(rng: &mut R, bit_length: u32) -> Self {
        BigUint::probable_prime(rng, bit_length)
    }
}

#[cfg(feature = "alloc")]
impl IsProbablePrime for BigUint {
    fn is_probable_prime<R: Rng + ?Sized>(&self, certainty: u32, rng: &mut R) -> bool {
        BigUint::is_probable_prime(self, certainty, rng)
    }
}

#[cfg(feature = "alloc")]
impl NextProbablePrime for BigUint {
    type Output = Self;

    fn next_probable_prime<R: Rng + ?Sized>(&self, rng: &mut R) -> Self::Output {
        BigUint::next_probable_prime(self, rng)
    }
}

#[cfg(feature = "alloc")]
impl BigInt {
    /// Tests the absolute value using trial division and Miller-Rabin rounds.
    pub fn is_probable_prime<R: Rng + ?Sized>(&self, certainty: u32, rng: &mut R) -> bool {
        big_int_magnitude(self).is_probable_prime(certainty, rng)
    }

    /// Generates a positive random probable prime with exactly `bit_length` bits.
    pub fn probable_prime<R: Rng + ?Sized>(rng: &mut R, bit_length: u32) -> Self {
        positive_big_int(&BigUint::probable_prime(rng, bit_length))
    }

    /// Returns the smallest positive probable prime strictly greater than this value.
    pub fn next_probable_prime<R: Rng + ?Sized>(&self, rng: &mut R) -> Self {
        let two = Self::from(2_u8);
        if self < &two {
            return two;
        }
        positive_big_int(&big_int_magnitude(self).next_probable_prime(rng))
    }
}

#[cfg(feature = "alloc")]
impl RandomBits for BigInt {
    fn try_random_bits<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
    ) -> Result<Self, RandomBitsError<R::Error>> {
        Self::try_random_bits_with_precision(rng, bit_length, bit_length)
    }

    fn try_random_bits_with_precision<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
        bits_precision: u32,
    ) -> Result<Self, RandomBitsError<R::Error>> {
        <BigUint as RandomBits>::try_random_bits_with_precision(rng, bit_length, bits_precision)
            .map(|value| positive_big_int(&value))
    }
}

#[cfg(feature = "alloc")]
impl ProbablePrime for BigInt {
    fn probable_prime<R: Rng + ?Sized>(rng: &mut R, bit_length: u32) -> Self {
        BigInt::probable_prime(rng, bit_length)
    }
}

#[cfg(feature = "alloc")]
impl IsProbablePrime for BigInt {
    fn is_probable_prime<R: Rng + ?Sized>(&self, certainty: u32, rng: &mut R) -> bool {
        BigInt::is_probable_prime(self, certainty, rng)
    }
}

#[cfg(feature = "alloc")]
impl NextProbablePrime for BigInt {
    type Output = Self;

    fn next_probable_prime<R: Rng + ?Sized>(&self, rng: &mut R) -> Self::Output {
        BigInt::next_probable_prime(self, rng)
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use rand_core::TryRng;

    use super::*;

    struct SeqRng(u64);

    impl TryRng for SeqRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.try_next_u64()? as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            Ok(self.0)
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in output.chunks_mut(8) {
                let word = self.try_next_u64()?.to_le_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RngFailure;

    impl core::fmt::Display for RngFailure {
        fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            output.write_str("test RNG failure")
        }
    }

    impl core::error::Error for RngFailure {}

    struct FailingRng;

    impl TryRng for FailingRng {
        type Error = RngFailure;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(RngFailure)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(RngFailure)
        }

        fn try_fill_bytes(&mut self, _output: &mut [u8]) -> Result<(), Self::Error> {
            Err(RngFailure)
        }
    }

    type U128 = FixedBigUint<{ 128 / Word::BITS as usize }>;
    type I128 = FixedBigInt<{ 128 / Word::BITS as usize }>;

    #[test]
    fn miller_rabin_round_policy_distinguishes_random_prime_candidates() {
        assert_eq!(miller_rabin_rounds(100, 128, false), 50);
        assert_eq!(miller_rabin_rounds(100, 256, true), 16);
        assert_eq!(miller_rabin_rounds(100, 512, true), 8);
        assert_eq!(miller_rabin_rounds(100, 1024, true), 4);
        assert_eq!(miller_rabin_rounds(128, 1024, true), 18);
        assert_eq!(miller_rabin_rounds(20, 1024, true), 4);
    }

    #[test]
    fn fixed_random_and_prime_operations_do_not_need_alloc() {
        let mut rng = SeqRng(1);
        for bits in [0_u32, 1, 7, 63, 127] {
            assert!(U128::random_bits(&mut rng, bits).bit_length() <= bits as usize);
        }

        let _full_width = U128::random_from_rng(&mut rng);
        let modulus = NonZero::new(U128::from(101_u8)).unwrap();
        for _ in 0..16 {
            assert!(U128::random_mod_vartime(&mut rng, &modulus) < *modulus);
        }

        for prime in [2_u64, 3, 5, 97, 251, 7_919, 104_729] {
            assert!(U128::from(prime).is_probable_prime(40, &mut rng));
        }
        for composite in [0_u64, 1, 4, 9, 25, 561, 1_105, 1_729, 2_821] {
            assert!(!U128::from(composite).is_probable_prime(40, &mut rng));
        }

        assert_eq!(
            U128::from(7_u8).next_probable_prime(&mut rng),
            Some(U128::from(11_u8))
        );
        assert_eq!(U128::max_value().next_probable_prime(&mut rng), None);
        assert!(I128::from(-97_i16).is_probable_prime(40, &mut rng));

        let prime = U128::probable_prime(&mut rng, 16);
        assert_eq!(prime.bit_length(), 16);
        assert!(prime.is_probable_prime(40, &mut rng));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_random_and_prime_operations_match_fixed_semantics() {
        let mut rng = SeqRng(0x1234_5678_9abc_def0);
        for bits in [0_u32, 1, 7, 64, 65, 127, 256] {
            assert!(BigUint::random_bits(&mut rng, bits).bit_length() <= bits as usize);
            let value = BigInt::random_bits(&mut rng, bits);
            assert!(!value.is_negative());
            assert!(value.bit_length() <= bits as usize);
        }

        let modulus = NonZero::new(BigUint::from(101_u8)).unwrap();
        for _ in 0..16 {
            assert!(BigUint::random_mod_vartime(&mut rng, &modulus) < *modulus);
        }

        for prime in [2_u64, 3, 5, 97, 251, 7_919, 104_729] {
            assert!(BigUint::from(prime).is_probable_prime(40, &mut rng));
        }
        for composite in [0_u64, 1, 4, 9, 25, 561, 1_105, 1_729, 2_821] {
            assert!(!BigUint::from(composite).is_probable_prime(40, &mut rng));
        }

        assert_eq!(
            BigUint::from(7_u8).next_probable_prime(&mut rng),
            BigUint::from(11_u8)
        );
        assert_eq!(
            BigInt::from(-5_i8).next_probable_prime(&mut rng),
            BigInt::from(2_u8)
        );
        assert!(BigInt::from(-97_i16).is_probable_prime(40, &mut rng));

        let prime = BigUint::probable_prime(&mut rng, 32);
        assert_eq!(prime.bit_length(), 32);
        assert!(prime.is_probable_prime(40, &mut rng));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_probable_primes_preserve_requested_multi_word_width() {
        let mut rng = SeqRng(0x6a09_e667_f3bc_c909);
        for bits in [128_u32, 256, 512] {
            let prime = BigUint::probable_prime(&mut rng, bits);
            assert_eq!(prime.bit_length(), bits as usize);
            assert!(prime.is_probable_prime(40, &mut rng));
        }
    }

    #[test]
    fn certainty_zero_skips_testing() {
        let mut rng = SeqRng(9);
        assert!(U128::from(9_u8).is_probable_prime(0, &mut rng));
    }

    #[test]
    fn fixed_signed_next_prime_reports_positive_overflow() {
        let mut rng = SeqRng(11);
        assert_eq!(I128::max_value().next_probable_prime(&mut rng), None);
    }

    #[test]
    fn fixed_random_bits_reports_precision_errors() {
        let mut rng = SeqRng(13);
        assert!(matches!(
            U128::try_random_bits_with_precision(&mut rng, 64, 64),
            Err(RandomBitsError::BitsPrecisionMismatch { .. })
        ));
        assert!(matches!(
            U128::try_random_bits(&mut rng, 129),
            Err(RandomBitsError::BitLengthTooLarge { .. })
        ));
        assert!(matches!(
            I128::try_random_bits(&mut rng, 128),
            Err(RandomBitsError::BitLengthTooLarge {
                bit_length: 128,
                bits_precision: 127,
            })
        ));
        let signed = I128::random_bits(&mut rng, 127);
        assert!(!signed.is_negative());
    }

    #[test]
    fn fallible_random_contracts_preserve_rng_errors() {
        let mut rng = FailingRng;
        assert_eq!(
            U128::try_random_bits(&mut rng, 64),
            Err(RandomBitsError::RandCore(RngFailure))
        );
        assert_eq!(U128::try_random_from_rng(&mut rng), Err(RngFailure));

        let modulus = NonZero::new(U128::from(101_u8)).unwrap();
        assert_eq!(
            U128::try_random_mod_vartime(&mut rng, &modulus),
            Err(RngFailure)
        );
    }

    #[test]
    fn word_remainder_reads_little_endian_limbs() {
        let words = [Limb::new(5), Limb::new(1)];
        let expected = ((1 as WideWord) << Word::BITS | 5) % 7;
        assert_eq!(remainder_word(&words, 7), expected as Word);
        assert_eq!(fixed_small::<1>(3).as_limbs()[0], Limb::new(3));
        assert_eq!(fixed_small::<0>(3).as_limbs(), &[]);
    }

    #[test]
    fn internal_random_and_small_factor_helpers_are_directly_covered() {
        let mut rng = SeqRng(17);
        let _ = try_random_word(&mut rng).unwrap();
        let _ = random_word(&mut rng);
        assert!(equals_word(&[Limb::new(7)], 7));
        assert!(!equals_word(&[Limb::new(7), Limb::new(1)], 7));
        assert_eq!(has_small_factor(&[Limb::new(7)]), Some(false));
        assert_eq!(has_small_factor(&[Limb::new(49)]), Some(true));
        assert_eq!(has_small_factor(&[Limb::new(257)]), None);
        assert_eq!(miller_rabin_rounds(0, 128, false), 1);
        assert_eq!(miller_rabin_rounds(5, 128, false), 3);
        assert_eq!(fixed_bits_precision::<2>(), 2 * Word::BITS);

        assert_eq!(
            try_random_fixed_uint::<0, _>(0, &mut rng).unwrap(),
            FixedBigUint::zero()
        );
        assert!(random_fixed_uint::<2, _>(7, &mut rng).bit_length() <= 7);
        assert!(random_fixed_below(&U128::from(17_u8), &mut rng) < U128::from(17_u8));
    }

    #[test]
    fn random_trait_default_methods_and_deprecated_aliases_are_covered() {
        let mut rng = SeqRng(19);
        let _ = <U128 as Random>::random_from_rng(&mut rng);
        let _ = <I128 as Random>::random_from_rng(&mut rng);
        assert!(
            <U128 as RandomBits>::random_bits_with_precision(&mut rng, 17, 128).bit_length() <= 17
        );
        assert!(
            <I128 as RandomBits>::random_bits_with_precision(&mut rng, 17, 128).bit_length() <= 17
        );

        let modulus = NonZero::new(U128::from(101_u8)).unwrap();
        assert!(<U128 as RandomMod>::random_mod_vartime(&mut rng, &modulus) < *modulus);
        #[allow(deprecated)]
        {
            assert!(<U128 as RandomMod>::try_random_mod(&mut rng, &modulus).unwrap() < *modulus);
            assert!(<U128 as RandomMod>::random_mod(&mut rng, &modulus) < *modulus);
        }
    }

    #[test]
    fn prime_traits_delegate_for_fixed_types_and_cover_small_width_paths() {
        let mut rng = SeqRng(23);
        assert_eq!(
            FixedBigUint::<0>::zero().next_probable_prime(&mut rng),
            None
        );
        assert_eq!(
            U128::zero().next_probable_prime(&mut rng),
            Some(U128::from(2_u8))
        );
        let two_bit = <U128 as ProbablePrime>::probable_prime(&mut rng, 2);
        assert!(two_bit == U128::from(2_u8) || two_bit == U128::from(3_u8));
        assert!(<U128 as IsProbablePrime>::is_probable_prime(
            &two_bit, 20, &mut rng
        ));
        assert_eq!(
            <U128 as NextProbablePrime>::next_probable_prime(&U128::from(11_u8), &mut rng),
            Some(U128::from(13_u8))
        );

        let signed = <I128 as ProbablePrime>::probable_prime(&mut rng, 8);
        assert!(<I128 as IsProbablePrime>::is_probable_prime(
            &signed, 20, &mut rng
        ));
        assert_eq!(
            <I128 as NextProbablePrime>::next_probable_prime(&I128::from(11_i8), &mut rng),
            Some(I128::from(13_i8))
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_random_helpers_and_trait_delegates_are_covered() {
        let mut rng = SeqRng(29);
        assert_eq!(
            try_random_big_uint(0, &mut FailingRng),
            Ok(BigUint::default())
        );
        assert!(random_big_uint_below(&BigUint::from(17_u8), &mut rng) < BigUint::from(17_u8));
        assert_eq!(
            big_int_magnitude(&BigInt::from(-12_i8)),
            BigUint::from(12_u8)
        );
        assert_eq!(positive_big_int(&BigUint::from(13_u8)), BigInt::from(13_u8));

        assert!(
            <BigUint as RandomBits>::random_bits_with_precision(&mut rng, 17, 32).bit_length()
                <= 17
        );
        assert!(
            <BigInt as RandomBits>::random_bits_with_precision(&mut rng, 17, 32).bit_length() <= 17
        );
        let modulus = NonZero::new(BigUint::from(101_u8)).unwrap();
        assert!(<BigUint as RandomMod>::random_mod_vartime(&mut rng, &modulus) < *modulus);

        let prime = <BigUint as ProbablePrime>::probable_prime(&mut rng, 8);
        assert!(<BigUint as IsProbablePrime>::is_probable_prime(
            &prime, 20, &mut rng
        ));
        assert_eq!(
            <BigUint as NextProbablePrime>::next_probable_prime(&BigUint::from(11_u8), &mut rng),
            BigUint::from(13_u8)
        );
        let signed = <BigInt as ProbablePrime>::probable_prime(&mut rng, 8);
        assert!(<BigInt as IsProbablePrime>::is_probable_prime(
            &signed, 20, &mut rng
        ));
        assert_eq!(
            <BigInt as NextProbablePrime>::next_probable_prime(&BigInt::from(11_i8), &mut rng),
            BigInt::from(13_u8)
        );
    }

    #[test]
    #[should_panic(expected = "random range must be non-empty")]
    fn fixed_random_below_rejects_an_empty_range() {
        let _ = random_fixed_below(&U128::zero(), &mut SeqRng(31));
    }

    #[test]
    #[should_panic(expected = "bit_length must be at least 2")]
    fn fixed_probable_prime_rejects_too_few_bits() {
        let _ = U128::probable_prime(&mut SeqRng(37), 1);
    }

    #[test]
    #[should_panic(expected = "bit_length exceeds the fixed integer width")]
    fn fixed_probable_prime_rejects_excess_precision() {
        let _ = U128::probable_prime(&mut SeqRng(41), 129);
    }

    #[test]
    #[should_panic(expected = "bit_length exceeds the positive fixed integer width")]
    fn signed_fixed_probable_prime_reserves_the_sign_bit() {
        let _ = I128::probable_prime(&mut SeqRng(43), 128);
    }

    #[cfg(feature = "alloc")]
    #[test]
    #[should_panic(expected = "random range must be non-empty")]
    fn dynamic_random_below_rejects_an_empty_range() {
        let _ = random_big_uint_below(&BigUint::default(), &mut SeqRng(47));
    }

    #[cfg(feature = "alloc")]
    #[test]
    #[should_panic(expected = "bit_length must be at least 2")]
    fn dynamic_probable_prime_rejects_too_few_bits() {
        let _ = BigUint::probable_prime(&mut SeqRng(53), 1);
    }
}
