use alloc::vec::Vec;

use tc_bigint::BigInt;

use super::WIDTH;
use super::reduction::ZTauElement;

/// BC `Tnaf.Alpha0` 與 `Alpha1` 的 (u, v)，index 為奇數 1..15；偶數位置不用。
const ALPHA0: [(i32, i32); 16] = [
    (0, 0),
    (1, 0),
    (0, 0),
    (-3, -1),
    (0, 0),
    (-1, -1),
    (0, 0),
    (1, -1),
    (0, 0),
    (-1, 1),
    (0, 0),
    (1, 1),
    (0, 0),
    (3, 1),
    (0, 0),
    (-1, 0),
];
const ALPHA1: [(i32, i32); 16] = [
    (0, 0),
    (1, 0),
    (0, 0),
    (-3, 1),
    (0, 0),
    (-1, 1),
    (0, 0),
    (1, 1),
    (0, 0),
    (-1, -1),
    (0, 0),
    (1, -1),
    (0, 0),
    (3, -1),
    (0, 0),
    (-1, 0),
];

/// BC `TauAdicWNaf` with width 4 and BC's `GetTw` of 6 or 10: the digits of λ, lowest
/// first, each 0 or odd in -7..=7.
pub(super) fn tau_adic_wnaf(mu: i8, lambda: &ZTauElement, a: u8) -> Vec<i8> {
    let tw: i32 = if mu == 1 { 6 } else { 10 };
    let table = if a == 0 { &ALPHA0 } else { &ALPHA1 };
    let mask = (1 << WIDTH) - 1;
    let shift = 32 - WIDTH;
    let zero = BigInt::from(0u8);

    let mut r0 = lambda.u.clone();
    let mut r1 = lambda.v.clone();
    let mut digits = Vec::new();
    while r0 != zero || r1 != zero {
        let mut digit = 0;
        if r0.bit(0) {
            // BC's `IntValue`: the low 32 bits in two's complement.
            let value = low_i32(&r0).wrapping_add(low_i32(&r1).wrapping_mul(tw));
            let position = (value & mask) as usize;
            digit = ((value << shift) >> shift) as i8;
            let (u, v) = table[position];
            r0 -= BigInt::from(u);
            r1 -= BigInt::from(v);
        }
        digits.push(digit);
        let t = &r0 >> 1;
        r0 = if mu == 1 { &r1 + &t } else { &r1 - &t };
        r1 = -t;
    }
    digits
}

fn low_i32(value: &BigInt) -> i32 {
    value
        .as_limbs()
        .first()
        .map_or(0, |limb| limb.to_word() as i32)
}

#[cfg(test)]
mod tests {
    use super::{ALPHA0, ALPHA1, tau_adic_wnaf};
    use crate::tnaf::reduction::ZTauElement;
    use tc_bigint::BigInt;

    // α_d of the digit d: the table entry for d > 0, its negation for d < 0.
    fn alpha(a: u8, digit: i8) -> (i32, i32) {
        let table = if a == 0 { &ALPHA0 } else { &ALPHA1 };
        let (u, v) = table[digit.unsigned_abs() as usize];
        if digit < 0 { (-u, -v) } else { (u, v) }
    }

    // (u + vτ)·τ = -2v + (u + μv)τ, as τ² = μτ - 2.
    fn times_tau(mu: i8, (u, v): (BigInt, BigInt)) -> (BigInt, BigInt) {
        let mu_v = if mu == 1 { v.clone() } else { -&v };
        (-(v << 1), u + mu_v)
    }

    // Horner from the top digit: the digits give back λ in Z[τ], and every nonzero digit
    // is odd and followed by at least three zeros.
    #[test]
    fn the_window_digits_rebuild_lambda_with_three_zeros_after_each() {
        for (a, mu) in [(0u8, -1i8), (1, 1)] {
            for (u, v) in [(1i64, 0i64), (123_456, -789), (-98_765_431, 24_680), (7, 7)] {
                let lambda = ZTauElement {
                    u: BigInt::from(u),
                    v: BigInt::from(v),
                };
                let digits = tau_adic_wnaf(mu, &lambda, a);
                let mut acc = (BigInt::from(0u8), BigInt::from(0u8));
                for &digit in digits.iter().rev() {
                    acc = times_tau(mu, acc);
                    if digit != 0 {
                        let (au, av) = alpha(a, digit);
                        acc = (acc.0 + BigInt::from(au), acc.1 + BigInt::from(av));
                    }
                }
                assert_eq!(
                    acc,
                    (lambda.u.clone(), lambda.v.clone()),
                    "a = {a}, λ = {u} + {v}τ"
                );
                for (i, &digit) in digits.iter().enumerate() {
                    if digit != 0 {
                        assert!(digit % 2 != 0 && (-7..=7).contains(&digit));
                        assert!(digits[i + 1..].iter().take(3).all(|&d| d == 0));
                    }
                }
            }
        }
    }
}
