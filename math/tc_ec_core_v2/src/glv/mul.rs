use alloc::vec::Vec;

use tc_bigint::{BigInt, BigUint, PaddedBigUint};

use super::ScalarSplit;
use crate::wnaf::{WNafTable, generate_window_naf, get_window_size};
use crate::{Curve, Point, Scalar};

/// BC `GlvMultiplier` with an efficient point map, by `ImplShamirsTrickWNaf`: kP = aP + bφ(P)
/// from the split of k mod n, the table of φ(P) the image of P's table under `map`. Holds,
/// as in BC, only for points of the subgroup of order n. Panics on a curve without an order.
/// Variable time: only for a public scalar.
pub fn glv_mul_point<C: Curve<Scalar = PaddedBigUint>>(
    point: &C::Point,
    scalar: &PaddedBigUint,
    split: &ScalarSplit,
    map: impl Fn(&C::Point) -> C::Point,
) -> C::Point {
    if point.is_infinity() || Scalar::is_zero(scalar) {
        return point.infinity();
    }
    let curve = point.curve();
    let n = big_int(curve.order().expect("GLV needs the order"));
    let (a, b) = split.decompose(&(big_int(scalar) % &n));
    let zero = BigInt::from(0u8);
    let (negative_a, negative_b) = (a < zero, b < zero);
    let a = PaddedBigUint::from(a.unsigned_abs());
    let b = PaddedBigUint::from(b.unsigned_abs());

    let width = get_window_size(a.bit_length().max(b.bit_length())).min(8);
    let table = WNafTable::new(point, width, true);
    let p_plus = table.precomputed();
    let p_minus = table
        .precomputed_negated()
        .expect("the table keeps its negations");
    let q_plus: Vec<C::Point> = p_plus.iter().map(&map).collect();
    let q_minus: Vec<C::Point> = p_minus.iter().map(&map).collect();
    let (p_plus, p_minus) = if negative_a {
        (p_minus, p_plus)
    } else {
        (p_plus, p_minus)
    };
    let (q_plus, q_minus) = if negative_b {
        (&q_minus[..], &q_plus[..])
    } else {
        (&q_plus[..], &q_minus[..])
    };

    let naf_a = generate_window_naf::<C>(width, &a);
    let naf_b = generate_window_naf::<C>(width, &b);
    let infinity = point.infinity();
    let mut result = infinity.clone();
    let mut zeroes = 0;
    for i in (0..naf_a.len().max(naf_b.len())).rev() {
        let digit_a = naf_a.get(i).copied().unwrap_or(0);
        let digit_b = naf_b.get(i).copied().unwrap_or(0);
        if digit_a | digit_b == 0 {
            zeroes += 1;
            continue;
        }
        let mut addend = infinity.clone();
        if digit_a != 0 {
            let table = if digit_a < 0 { p_minus } else { p_plus };
            addend = addend.add(&table[(digit_a.unsigned_abs() >> 1) as usize]);
        }
        if digit_b != 0 {
            let table = if digit_b < 0 { q_minus } else { q_plus };
            addend = addend.add(&table[(digit_b.unsigned_abs() >> 1) as usize]);
        }
        if zeroes > 0 {
            result = result.times_pow2(zeroes);
            zeroes = 0;
        }
        result = result.twice_plus(&addend);
    }
    if zeroes > 0 {
        result = result.times_pow2(zeroes);
    }
    result
}

fn big_int(value: &PaddedBigUint) -> BigInt {
    BigInt::from(BigUint::from(value.clone()))
}
