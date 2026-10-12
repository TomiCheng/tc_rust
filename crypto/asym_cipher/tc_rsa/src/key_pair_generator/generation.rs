//! The generation of a key over `PaddedBigUint`, as Bouncy Castle's
//! `RsaKeyPairGenerator` runs it.

use alloc::vec;

use rand_core::CryptoRng;
use tc_bigint::{Limb, PaddedBigUint, Word};
use tc_modular::{ModInverse, NonZero};
use tc_prime::Primality;
use tc_zeroize::{Zeroize, Zeroizing};

use crate::RsaError;

/// The smallest modulus generated, in bits: below it, the distance and the
/// weight Bouncy Castle asks of a key may never be met.
const MIN_STRENGTH: u32 = 16;

/// The public exponents known to be prime, for which `p mod e ≠ 1` already
/// makes `e` and `p − 1` coprime, as Bouncy Castle's are.
const KNOWN_PRIME_EXPONENTS: [u32; 5] = [3, 5, 17, 257, 65537];

/// A generated key: the modulus and the exponents at the width of the
/// modulus, the primes and the values modulo them at that of the larger
/// prime. The secret values are wiped on drop.
pub(super) struct Generated {
    pub(super) n: PaddedBigUint,
    pub(super) e: PaddedBigUint,
    pub(super) d: Zeroizing<PaddedBigUint>,
    pub(super) p: Zeroizing<PaddedBigUint>,
    pub(super) q: Zeroizing<PaddedBigUint>,
    pub(super) dp: Zeroizing<PaddedBigUint>,
    pub(super) dq: Zeroizing<PaddedBigUint>,
    pub(super) q_inv: Zeroizing<PaddedBigUint>,
}

/// The checks of the parameters: an odd public exponent of at least three,
/// a certainty of at least one, and a modulus of at least
/// [`MIN_STRENGTH`] bits that `T` holds, with a larger prime that `H`
/// holds. Variable time: only for public values, as the parameters are.
pub(super) fn check<T, H>(
    public_exponent: u32,
    strength: u32,
    certainty: u32,
) -> Result<(), RsaError>
where
    T: TryFrom<PaddedBigUint>,
    H: TryFrom<PaddedBigUint>,
{
    if public_exponent < 3 || public_exponent & 1 == 0 {
        return Err(RsaError::InvalidPublicExponent);
    }
    if certainty == 0 {
        return Err(RsaError::InvalidCertainty);
    }
    if strength < MIN_STRENGTH || !holds::<T>(strength) || !holds::<H>(strength.div_ceil(2)) {
        return Err(RsaError::InvalidStrength);
    }
    Ok(())
}

/// Whether `X` holds integers of `bits` bits, as a conversion of one with
/// its top bit set shows. Variable time: only for public values.
fn holds<X: TryFrom<PaddedBigUint>>(bits: u32) -> bool {
    let mut top = resized(&PaddedBigUint::from(0u8), bits);
    top.set_bit(bits - 1, true);
    X::try_from(top).is_ok()
}

/// A key of `strength` bits with the public exponent `public_exponent`,
/// its primes tested to `certainty`, drawn from `rng`: the parameters are
/// those [`check`] lets through. Variable time: how many candidates are
/// drawn, and which tests turn them down, shows in the running time.
pub(super) fn generate(
    rng: &mut dyn CryptoRng,
    public_exponent: u32,
    strength: u32,
    certainty: u32,
) -> Generated {
    let p_bits = strength.div_ceil(2);
    let q_bits = strength - p_bits;
    let min_diff_bits = strength / 3;
    let min_weight = strength >> 2;
    let e = resized(&PaddedBigUint::from(public_exponent), strength);

    loop {
        let mut p = choose_prime(rng, p_bits, public_exponent, certainty);
        let (q, n) = loop {
            let q = choose_prime(rng, q_bits, public_exponent, certainty);

            // p and q should not be too close together, or equal.
            let diff = Zeroizing::new(if *q > *p { &*q - &*p } else { &*p - &*q });
            if diff.bits() < min_diff_bits {
                continue;
            }

            let mut n = resized(&p, strength);
            n *= &*q;
            if n.bits() != strength {
                // The primes are too small: keep the larger as p and draw q
                // again.
                if *q > *p {
                    p = q;
                }
                continue;
            }

            // A low weight of the non-adjacent form may leave the modulus
            // weak against a version of the number field sieve, as Oliver
            // Schirokauer shows for integers of low weight.
            if naf_weight(&n) < min_weight {
                p = choose_prime(rng, p_bits, public_exponent, certainty);
                continue;
            }
            break (q, n);
        };
        let (p, q) = if *p < *q { (q, p) } else { (p, q) };

        let p_less_one = Zeroizing::new(&*p - 1u32);
        let q_less_one = Zeroizing::new(&*q - 1u32);
        let gcd = Zeroizing::new(p_less_one.gcd(&q_less_one));
        let mut lcm = resized(&p_less_one, strength);
        lcm /= &*gcd;
        lcm *= &*q_less_one;
        let lcm = NonZero::new(lcm).expect("p - 1 and q - 1 are not zero");
        let d = e.mod_inverse(&lcm).map(Zeroizing::new);
        lcm.into_inner().zeroize();
        // e is prime to p - 1 and to q - 1, and so to their lcm.
        let d = d.expect("e is prime to the lcm of p - 1 and q - 1");
        if d.bits() <= q_bits {
            continue;
        }

        let dp = Zeroizing::new(resized(&(&*d % &*p_less_one), p_bits));
        let dq = Zeroizing::new(resized(&(&*d % &*q_less_one), p_bits));
        let modulus = NonZero::new((*p).clone()).expect("p is not zero");
        let q_inv = q
            .mod_inverse(&modulus)
            .map(|q_inv| Zeroizing::new(resized(&q_inv, p_bits)));
        modulus.into_inner().zeroize();
        let q_inv = q_inv.expect("q is prime to p");

        return Generated {
            n,
            e,
            d,
            p: Zeroizing::new(resized(&p, p_bits)),
            q: Zeroizing::new(resized(&q, p_bits)),
            dp,
            dq,
            q_inv,
        };
    }
}

/// A random prime of `bits` bits for which `p − 1` is prime to `e`, as
/// Bouncy Castle's `ChooseRandomPrime` draws it: a prime to one round, put
/// back when `p mod e` is one, then tested to `certainty`. Variable time.
fn choose_prime(
    rng: &mut dyn CryptoRng,
    bits: u32,
    e: u32,
    certainty: u32,
) -> Zeroizing<PaddedBigUint> {
    let rounds = rounds(certainty, bits);
    let one = PaddedBigUint::from(1u8);
    let e_is_prime = KNOWN_PRIME_EXPONENTS.contains(&e);
    let wide_e = PaddedBigUint::from(e);
    loop {
        let p = Zeroizing::new(PaddedBigUint::random_probable_prime(rng, bits, 1));
        if &*p % e == one {
            continue;
        }
        if !p.is_probable_prime(rounds, rng) {
            continue;
        }
        if !e_is_prime && wide_e.gcd(&(&*p - 1u32)) != one {
            continue;
        }
        return p;
    }
}

/// The rounds of Miller-Rabin that test a randomly chosen candidate of
/// `bits` bits to `certainty`, as Bouncy Castle's `RabinMillerTest` counts
/// them. Variable time: only for public values.
fn rounds(certainty: u32, bits: u32) -> u32 {
    let rounds = (certainty - 1) / 2 + 1;
    let for_certainty_100 = match bits {
        1024.. => 4,
        512.. => 8,
        256.. => 16,
        _ => 50,
    };
    if certainty < 100 {
        rounds.min(for_certainty_100)
    } else {
        rounds - 50 + for_certainty_100
    }
}

/// The weight of the non-adjacent form of `value`, the number of set bits
/// of `3 · value XOR value`, as Bouncy Castle's `GetNafWeight` counts it,
/// limb by limb with the carries kept aside, so that `3 · value` needs no
/// wider integer. Constant time: every limb is run through.
fn naf_weight(value: &PaddedBigUint) -> u32 {
    let (mut top, mut carry, mut weight): (Word, Word, u32) = (0, 0, 0);
    for limb in value.as_limbs() {
        let x = limb.to_word();
        let doubled = (x << 1) | top;
        top = x >> (Word::BITS - 1);
        let (sum, low) = doubled.overflowing_add(x);
        let (sum, high) = sum.overflowing_add(carry);
        carry = Word::from(low) + Word::from(high);
        weight += (sum ^ x).count_ones();
    }
    // Past the limbs, `value` is zero and `3 · value` is what carried out.
    weight + (top + carry).count_ones()
}

/// `value` at the width that holds `bits` bits: zero limbs added, or the
/// limbs past that width, which must be zero, taken off. Constant time: the
/// widths are public.
fn resized(value: &PaddedBigUint, bits: u32) -> PaddedBigUint {
    let width = bits.div_ceil(Word::BITS) as usize;
    let limbs = value.as_limbs();
    let kept = width.min(limbs.len());
    let mut resized = vec![Limb::new(0); width];
    resized[..kept].copy_from_slice(&limbs[..kept]);
    PaddedBigUint::new(resized.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use tc_bigint::PaddedBigUint;

    use super::{naf_weight, resized, rounds};

    #[test]
    fn the_naf_weight_counts_the_bits_of_three_times_the_value_xor_the_value() {
        let mut value = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..200 {
            value = value.rotate_left(7) ^ value.wrapping_mul(0x2545_f491_4f6c_dd1d);
            let expected = ((u128::from(value) * 3) ^ u128::from(value)).count_ones();
            assert_eq!(
                naf_weight(&PaddedBigUint::from(value)),
                expected,
                "{value:#x}"
            );
        }
        assert_eq!(
            naf_weight(&PaddedBigUint::from(u64::MAX)),
            ((u128::from(u64::MAX) * 3) ^ u128::from(u64::MAX)).count_ones()
        );
        assert_eq!(naf_weight(&PaddedBigUint::from(0u8)), 0);
    }

    #[test]
    fn the_rounds_follow_bouncy_castle_for_random_candidates() {
        assert_eq!(rounds(100, 1024), 4);
        assert_eq!(rounds(100, 512), 8);
        assert_eq!(rounds(100, 256), 16);
        assert_eq!(rounds(100, 128), 50);
        assert_eq!(rounds(120, 1024), 14);
        assert_eq!(rounds(1, 1024), 1);
        assert_eq!(rounds(80, 2048), 4);
        assert_eq!(rounds(5, 2048), 3);
    }

    #[test]
    fn resizing_pads_or_trims_to_the_width_of_the_bits() {
        let value = PaddedBigUint::from(0x1234_u32);
        let wide = resized(&value, 200);
        assert_eq!(wide, value);
        assert_eq!(
            wide.as_limbs().len(),
            200usize.div_ceil(tc_bigint::Word::BITS as usize)
        );
        assert_eq!(resized(&wide, 16).as_limbs().len(), 1);
        assert_eq!(resized(&wide, 16), value);
    }
}
