//! Random integer and probable-prime candidate generation helpers.

use super::*;

#[cfg(feature = "alloc")]
use alloc::vec;

#[inline]
pub(super) fn try_random_word<R: TryRng + ?Sized>(rng: &mut R) -> Result<Word, R::Error> {
    #[cfg(target_pointer_width = "64")]
    {
        let mut bytes = [0_u8; 8];
        rng.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    #[cfg(not(target_pointer_width = "64"))]
    {
        let mut bytes = [0_u8; 4];
        rng.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
}

#[inline]
pub(super) fn random_word<R: Rng + ?Sized>(rng: &mut R) -> Word {
    match try_random_word(rng) {
        Ok(value) => value,
        Err(error) => match error {},
    }
}

pub(super) fn fixed_small<const N: usize>(value: Word) -> FixedBigUint<N> {
    let mut limbs = [Limb::new(0); N];
    if N != 0 {
        limbs[0] = Limb::new(value);
    }
    FixedBigUint::from_limbs(limbs)
}

pub(super) fn fixed_bits_precision<const N: usize>() -> u32 {
    u32::try_from(N.saturating_mul(Word::BITS as usize))
        .expect("fixed integer precision exceeds u32::MAX bits")
}

pub(super) fn try_random_fixed_uint<const N: usize, R: TryRng + ?Sized>(
    bit_length: usize,
    rng: &mut R,
) -> Result<FixedBigUint<N>, R::Error> {
    debug_assert!(bit_length <= N.saturating_mul(Word::BITS as usize));
    let mut limbs = [Limb::new(0); N];
    let used_limbs = bit_length.div_ceil(Word::BITS as usize);
    for word in limbs.iter_mut().take(used_limbs) {
        *word = Limb::new(try_random_word(rng)?);
    }
    let top_bits = bit_length % Word::BITS as usize;
    if top_bits != 0 {
        limbs[used_limbs - 1] = Limb::new(limbs[used_limbs - 1].to_word() & (Word::MAX >> (Word::BITS as usize - top_bits)));
    }
    Ok(FixedBigUint::from_limbs(limbs))
}

pub(super) fn random_fixed_uint<const N: usize, R: Rng + ?Sized>(
    bit_length: usize,
    rng: &mut R,
) -> FixedBigUint<N> {
    match try_random_fixed_uint(bit_length, rng) {
        Ok(value) => value,
        Err(error) => match error {},
    }
}

pub(super) fn random_fixed_below<const N: usize, R: Rng + ?Sized>(
    upper: &FixedBigUint<N>,
    rng: &mut R,
) -> FixedBigUint<N> {
    assert!(!upper.is_zero(), "random range must be non-empty");
    loop {
        let candidate = random_fixed_uint(upper.bit_length(), rng);
        if &candidate < upper {
            return candidate;
        }
    }
}

#[cfg(feature = "alloc")]
pub(super) fn try_random_big_uint<R: TryRng + ?Sized>(
    bit_length: usize,
    rng: &mut R,
) -> Result<BigUint, R::Error> {
    if bit_length == 0 {
        return Ok(BigUint::default());
    }
    let word_count = bit_length.div_ceil(Word::BITS as usize);
    let mut limbs = vec![Limb::new(0); word_count];
    for word in &mut limbs {
        *word = Limb::new(try_random_word(rng)?);
    }
    let top_bits = bit_length % Word::BITS as usize;
    if top_bits != 0 {
        limbs[word_count - 1] = Limb::new(limbs[word_count - 1].to_word() & (Word::MAX >> (Word::BITS as usize - top_bits)));
    }
    Ok(BigUint::from_limbs(limbs))
}

#[cfg(feature = "alloc")]
pub(super) fn random_big_uint_below<R: Rng + ?Sized>(upper: &BigUint, rng: &mut R) -> BigUint {
    assert!(!upper.is_zero(), "random range must be non-empty");
    loop {
        let candidate = <BigUint as RandomBits>::random_bits(
            rng,
            u32::try_from(upper.bits()).expect("integer exceeds u32::MAX bits"),
        );
        if &candidate < upper {
            return candidate;
        }
    }
}

#[cfg(feature = "alloc")]
pub(super) fn big_int_magnitude(value: &BigInt) -> BigUint {
    let absolute = value.abs();
    BigUint::from_limbs(absolute.as_limbs().to_vec())
}

#[cfg(feature = "alloc")]
pub(super) fn positive_big_int(value: &BigUint) -> BigInt {
    BigInt::from_sign_magnitude(false, value.as_limbs().to_vec())
}
