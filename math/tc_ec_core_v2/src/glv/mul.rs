use alloc::vec::Vec;

use tc_bigint::{BigInt, BigUint, PaddedBigUint};

use super::ScalarSplit;
use crate::wnaf::{WNafTable, generate_window_naf, get_window_size};
use crate::{Curve, Point, Scalar};

/// The multiples of P that [`glv_mul`] takes: P, 3P, ... for a window width with their
/// negations, as in [`WNafTable`], and their images under the map φ. Built once, it serves
/// every scalar. Variable time; the point is public.
pub struct GlvTable<P> {
    p: WNafTable<P>,
    q: [Vec<P>; 2],
}

impl<P: Point> GlvTable<P> {
    /// The table of `point` for window `width`, φ being `map`. Variable time.
    pub fn new(point: &P, width: usize, map: impl Fn(&P) -> P) -> Self {
        let p = WNafTable::new(point, width, true);
        let q = [
            p.precomputed().iter().map(&map).collect(),
            p.precomputed_negated()
                .expect("the table keeps its negations")
                .iter()
                .map(&map)
                .collect(),
        ];
        Self { p, q }
    }
}

/// BC `GlvMultiplier` with an efficient point map, by `ImplShamirsTrickWNaf`, on a table
/// built beforehand: kP = aP + bφ(P) from the split of k mod n. Holds, as in BC, only for
/// points of the subgroup of order n. Panics on a curve without an order. Variable time: only
/// for a public scalar.
pub fn glv_mul<C: Curve<Scalar = PaddedBigUint>>(
    table: &GlvTable<C::Point>,
    scalar: &PaddedBigUint,
    split: &ScalarSplit,
) -> C::Point {
    let point = &table.p.precomputed()[0];
    if point.is_infinity() || Scalar::is_zero(scalar) {
        return point.infinity();
    }
    let (a, b) = halves::<C>(point, scalar, split);
    mul_halves::<C>(table, a, b)
}

/// [`glv_mul`] on a table built for this one scalar, its width set by the halves of the split.
/// Holds, as in BC, only for points of the subgroup of order n. Panics on a curve without an
/// order. Variable time: only for a public scalar.
pub fn glv_mul_point<C: Curve<Scalar = PaddedBigUint>>(
    point: &C::Point,
    scalar: &PaddedBigUint,
    split: &ScalarSplit,
    map: impl Fn(&C::Point) -> C::Point,
) -> C::Point {
    if point.is_infinity() || Scalar::is_zero(scalar) {
        return point.infinity();
    }
    let (a, b) = halves::<C>(point, scalar, split);
    let width = get_window_size(a.1.bit_length().max(b.1.bit_length())).min(8);
    mul_halves::<C>(&GlvTable::new(point, width, map), a, b)
}

// The split of k mod n as (whether negative, magnitude) for a and for b.
fn halves<C: Curve<Scalar = PaddedBigUint>>(
    point: &C::Point,
    scalar: &PaddedBigUint,
    split: &ScalarSplit,
) -> ((bool, PaddedBigUint), (bool, PaddedBigUint)) {
    let n = big_int(point.curve().order().expect("GLV needs the order"));
    let (a, b) = split.decompose(&(big_int(scalar) % &n));
    let zero = BigInt::from(0u8);
    (
        (a < zero, PaddedBigUint::from(a.unsigned_abs())),
        (b < zero, PaddedBigUint::from(b.unsigned_abs())),
    )
}

fn mul_halves<C: Curve<Scalar = PaddedBigUint>>(
    table: &GlvTable<C::Point>,
    (negative_a, a): (bool, PaddedBigUint),
    (negative_b, b): (bool, PaddedBigUint),
) -> C::Point {
    let width = table.p.width();
    let p_plus = table.p.precomputed();
    let p_minus = table
        .p
        .precomputed_negated()
        .expect("the table keeps its negations");
    let [q_plus, q_minus] = &table.q;
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
    let infinity = p_plus[0].infinity();
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
