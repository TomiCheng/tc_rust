//! Koblitz 二元曲線的 reduced window τ-adic NAF 乘法。
//!
//! 實作沿用 BC `Tnaf` / `WTauNafMultiplier` 的 Solinas 演算法，但預算表由
//! 呼叫端明確持有，不把可變快取塞進點物件。這套演算法是變動時間，只適合
//! 公開純量；秘密純量仍須使用另行設計的常數時間乘法器。

use alloc::{vec, vec::Vec};

use tc_bigint::BigInt;
use tc_ec_core::Point;

use crate::{F2mInteger, F2mPoint, F2mPolynomial};

const WIDTH: usize = 4;
const PRECISION: usize = 10;

/// `u + vτ` 的整數係數表示。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZTauElement {
    pub u: BigInt,
    pub v: BigInt,
}

impl ZTauElement {
    fn new(u: BigInt, v: BigInt) -> Self {
        Self { u, v }
    }
}

/// 呼叫端持有的 WTNAF 預算表。
///
/// 表內包含 `α₁P, α₃P, α₅P, α₇P` 與其負值，也保存該 Koblitz 曲線的
/// partial modular reduction 常數；重複乘同一點時不必重建。
pub struct WTauNafTable<P> {
    positive: [P; 4],
    negative: [P; 4],
    reduction: ReductionParameters,
}

#[derive(Clone)]
struct ReductionParameters {
    a: i8,
    mu: i8,
    m: usize,
    vm: BigInt,
    s0: BigInt,
    s1: BigInt,
}

impl<P: F2mPolynomial, B: F2mInteger> WTauNafTable<F2mPoint<P, B>> {
    /// 為 Koblitz 點建立 width-4 WTNAF 預算表。
    pub fn new(point: &F2mPoint<P, B>) -> Self {
        let curve = point.curve();
        assert!(
            curve.b().is_one(),
            "TNAF requires a Koblitz curve with b = 1"
        );
        let a = if curve.a().is_zero() {
            0
        } else {
            assert!(curve.a().is_one(), "TNAF requires a curve with a = 0 or 1");
            1
        };
        let mu = if a == 0 { -1 } else { 1 };
        let m = curve.field_size();
        let order = curve.order().expect("Koblitz curve has a subgroup order");
        let cofactor = curve.cofactor().expect("Koblitz curve has a cofactor");
        let order = integer_to_bigint(order);
        let cofactor = integer_to_bigint(cofactor);
        let vm = ((BigInt::from(1_u8) << m) + BigInt::from(1_u8)) - &(&order * &cofactor);
        let (s0, s1) = get_si(m, a, mu, &cofactor);

        let alpha_tnaf: [&[i8]; 4] = if a == 0 {
            [&[1], &[-1, 0, 1], &[1, 0, 1], &[-1, 0, 0, 1]]
        } else {
            [&[1], &[-1, 0, 1], &[1, 0, 1], &[-1, 0, 0, -1]]
        };
        let point_negated = point.negate();
        let positive = core::array::from_fn(|index| {
            multiply_from_tnaf(point, &point_negated, alpha_tnaf[index])
        });
        let negative = core::array::from_fn(|index| positive[index].negate());

        Self {
            positive,
            negative,
            reduction: ReductionParameters {
                a,
                mu,
                m,
                vm,
                s0,
                s1,
            },
        }
    }

    /// 表內的四個正 α 倍點。
    pub fn positive(&self) -> &[F2mPoint<P, B>; 4] {
        &self.positive
    }

    /// 表內的四個負 α 倍點。
    pub fn negative(&self) -> &[F2mPoint<P, B>; 4] {
        &self.negative
    }
}

/// 產生 `u + vτ` 的 τ-adic NAF；輸出最低位在前，digit 僅為 `-1/0/1`。
pub fn generate_tau_naf(mu: i8, lambda: &ZTauElement) -> Vec<i8> {
    assert!(matches!(mu, -1 | 1), "mu must be -1 or 1");
    let mut r0 = lambda.u.clone();
    let mut r1 = lambda.v.clone();
    let four = BigInt::from(4_u8);
    let mut digits = Vec::new();

    while !r0.is_zero() || !r1.is_zero() {
        let digit = if r0.test_bit(0) {
            let residue = (&r0 - &(&r1 << 1)).rem_euclid(&four);
            if residue == BigInt::from(1_u8) {
                1
            } else {
                debug_assert_eq!(residue, BigInt::from(3_u8));
                -1
            }
        } else {
            0
        };
        digits.push(digit);
        if digit != 0 {
            r0 = &r0 - BigInt::from(digit);
        }

        let half = &r0 >> 1;
        r0 = if mu == 1 { &r1 + &half } else { &r1 - &half };
        r1 = -half;
    }
    digits
}

/// 以顯式預算表執行 reduced width-4 τ-adic NAF 乘法。
pub fn wtnaf_mul<P: F2mPolynomial, B: F2mInteger>(
    table: &WTauNafTable<F2mPoint<P, B>>,
    scalar: &B,
) -> F2mPoint<P, B> {
    if scalar.bit_length() == 0 {
        return table.positive[0].curve().infinity();
    }
    let lambda = part_mod_reduction(&table.reduction, &integer_to_bigint(scalar));
    let digits = generate_tau_window_naf(table.reduction.mu, &lambda, table.reduction.a);

    let mut result = table.positive[0].curve().infinity();
    let mut tau_count = 0;
    for &digit in digits.iter().rev() {
        tau_count += 1;
        if digit == 0 {
            continue;
        }
        result = result.tau_pow(tau_count);
        tau_count = 0;
        let index = (digit.unsigned_abs() as usize) >> 1;
        let addend = if digit > 0 {
            &table.positive[index]
        } else {
            &table.negative[index]
        };
        result = &result + addend;
    }
    if tau_count != 0 {
        result = result.tau_pow(tau_count);
    }
    result
}

/// 建立一次性預算表後執行 WTNAF；重複乘同一點時應改用 [`wtnaf_mul`]。
pub fn wtnaf_mul_point<P: F2mPolynomial, B: F2mInteger>(
    point: &F2mPoint<P, B>,
    scalar: &B,
) -> F2mPoint<P, B> {
    wtnaf_mul(&WTauNafTable::new(point), scalar)
}

fn generate_tau_window_naf(mu: i8, lambda: &ZTauElement, a: i8) -> Vec<i8> {
    let tw = if mu == 1 { 6 } else { 10 };
    let alpha: [(i8, i8); 16] = if a == 0 {
        [
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
        ]
    } else {
        [
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
        ]
    };
    let modulus = BigInt::from(1_u8 << WIDTH);
    let mut r0 = lambda.u.clone();
    let mut r1 = lambda.v.clone();
    let mut digits = Vec::new();

    while !r0.is_zero() || !r1.is_zero() {
        let digit = if r0.test_bit(0) {
            let residue = (&r0 + &(&r1 * BigInt::from(tw))).rem_euclid(&modulus);
            let mut value = small_nonnegative(&residue);
            let alpha_index = value as usize;
            if value >= 1 << (WIDTH - 1) {
                value -= 1 << WIDTH;
            }
            let (alpha_u, alpha_v) = alpha[alpha_index];
            r0 = &r0 - BigInt::from(alpha_u);
            r1 = &r1 - BigInt::from(alpha_v);
            value
        } else {
            0
        };
        digits.push(digit);

        let half = &r0 >> 1;
        r0 = if mu == 1 { &r1 + &half } else { &r1 - &half };
        r1 = -half;
    }
    digits
}

fn multiply_from_tnaf<P: F2mPolynomial, B: F2mInteger>(
    point: &F2mPoint<P, B>,
    point_negated: &F2mPoint<P, B>,
    digits: &[i8],
) -> F2mPoint<P, B> {
    let mut result = point.curve().infinity();
    let mut tau_count = 0;
    for &digit in digits.iter().rev() {
        tau_count += 1;
        if digit == 0 {
            continue;
        }
        result = result.tau_pow(tau_count);
        tau_count = 0;
        result = &result + if digit > 0 { point } else { point_negated };
    }
    if tau_count != 0 {
        result = result.tau_pow(tau_count);
    }
    result
}

fn part_mod_reduction(parameters: &ReductionParameters, scalar: &BigInt) -> ZTauElement {
    let d0 = if parameters.mu == 1 {
        &parameters.s0 + &parameters.s1
    } else {
        &parameters.s0 - &parameters.s1
    };
    let lambda0 = approximate_division(
        scalar,
        &parameters.s0,
        &parameters.vm,
        parameters.a,
        parameters.m,
        PRECISION,
    );
    let lambda1 = approximate_division(
        scalar,
        &parameters.s1,
        &parameters.vm,
        parameters.a,
        parameters.m,
        PRECISION,
    );
    let q = round(&lambda0, &lambda1, parameters.mu);
    let r0 = scalar - &(&d0 * &q.u) - &((&parameters.s1 * &q.v) << 1);
    let r1 = &parameters.s1 * &q.u - &(&parameters.s0 * &q.v);
    ZTauElement::new(r0, r1)
}

#[derive(Clone)]
struct SimpleBigDecimal {
    value: BigInt,
    scale: usize,
}

impl SimpleBigDecimal {
    fn add(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.scale, rhs.scale);
        Self {
            value: &self.value + &rhs.value,
            scale: self.scale,
        }
    }

    fn sub(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.scale, rhs.scale);
        Self {
            value: &self.value - &rhs.value,
            scale: self.scale,
        }
    }

    fn sub_integer(&self, rhs: &BigInt) -> Self {
        Self {
            value: &self.value - &(rhs << self.scale),
            scale: self.scale,
        }
    }

    fn compare_integer(&self, rhs: i8) -> core::cmp::Ordering {
        self.value.cmp(&(BigInt::from(rhs) << self.scale))
    }

    fn round(&self) -> BigInt {
        (&self.value + &(BigInt::from(1_u8) << (self.scale - 1))) >> self.scale
    }
}

fn approximate_division(
    scalar: &BigInt,
    s: &BigInt,
    vm: &BigInt,
    a: i8,
    m: usize,
    precision: usize,
) -> SimpleBigDecimal {
    let k = (m + 5) / 2 + precision;
    let shift = m - k - 2 + a as usize;
    let ns = scalar >> shift;
    let gs = s * &ns;
    let hs = &gs >> m;
    let gs_plus_js = &gs + &(vm * &hs);
    let rounding_shift = k - precision;
    let mut result = &gs_plus_js >> rounding_shift;
    if gs_plus_js.test_bit(rounding_shift - 1) {
        result += BigInt::from(1_u8);
    }
    SimpleBigDecimal {
        value: result,
        scale: precision,
    }
}

fn round(lambda0: &SimpleBigDecimal, lambda1: &SimpleBigDecimal, mu: i8) -> ZTauElement {
    let f0 = lambda0.round();
    let f1 = lambda1.round();
    let eta0 = lambda0.sub_integer(&f0);
    let eta1 = lambda1.sub_integer(&f1);
    let twice_eta0 = eta0.add(&eta0);
    let eta = if mu == 1 {
        twice_eta0.add(&eta1)
    } else {
        twice_eta0.sub(&eta1)
    };
    let three_eta1 = eta1.add(&eta1).add(&eta1);
    let four_eta1 = three_eta1.add(&eta1);
    let (check1, check2) = if mu == 1 {
        (eta0.sub(&three_eta1), eta0.add(&four_eta1))
    } else {
        (eta0.add(&three_eta1), eta0.sub(&four_eta1))
    };

    let mut h0 = 0_i8;
    let mut h1 = 0_i8;
    if eta.compare_integer(1).is_ge() {
        if check1.compare_integer(-1).is_lt() {
            h1 = mu;
        } else {
            h0 = 1;
        }
    } else if check2.compare_integer(2).is_ge() {
        h1 = mu;
    }
    if eta.compare_integer(-1).is_lt() {
        if check1.compare_integer(1).is_ge() {
            h1 = -mu;
        } else {
            h0 = -1;
        }
    } else if check2.compare_integer(-2).is_lt() {
        h1 = -mu;
    }
    ZTauElement::new(f0 + BigInt::from(h0), f1 + BigInt::from(h1))
}

fn get_si(m: usize, a: i8, mu: i8, cofactor: &BigInt) -> (BigInt, BigInt) {
    let shifts = if cofactor == &BigInt::from(2_u8) {
        1
    } else {
        assert_eq!(
            cofactor,
            &BigInt::from(4_u8),
            "Koblitz cofactor must be 2 or 4"
        );
        2
    };
    let (mut u0, mut u1) = get_lucas(mu, m + 3 - a as usize);
    if mu == 1 {
        u0 = -u0;
        u1 = -u1;
    }
    let s0 = (BigInt::from(1_u8) + u1) >> shifts;
    let s1 = -((BigInt::from(1_u8) + u0) >> shifts);
    (s0, s1)
}

fn get_lucas(mu: i8, index: usize) -> (BigInt, BigInt) {
    let mut u0 = BigInt::from(0_u8);
    let mut u1 = BigInt::from(1_u8);
    for _ in 1..index {
        let signed_u1 = if mu == 1 { u1.clone() } else { -u1.clone() };
        let u2 = signed_u1 - (&u0 << 1);
        u0 = u1;
        u1 = u2;
    }
    (u0, u1)
}

fn integer_to_bigint<B: F2mInteger>(value: &B) -> BigInt {
    let mut words = vec![0_u64; value.u64_length().max(1)];
    let written = value
        .write_le_u64(&mut words)
        .expect("buffer uses the integer's reported limb length");
    BigInt::from_unsigned_le_u64(&words[..written])
}

fn small_nonnegative(value: &BigInt) -> i8 {
    for result in 0_i8..16 {
        if value == &BigInt::from(result) {
            return result;
        }
    }
    unreachable!("value was reduced modulo 16")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::named_curves::{sect163k1, sect233k1};
    use tc_bigint::{ArrayEncoding, U256};
    use tc_binpoly::FixedBinaryPoly;
    use tc_ec_core::scalar_mul;

    fn scalar(value: &[u8]) -> U256 {
        U256::from_unsigned_be_bytes(value).unwrap()
    }

    fn exercise(point: F2mPoint<FixedBinaryPoly<3>, U256>, values: &[&[u8]]) {
        let table = WTauNafTable::new(&point);
        for value in values {
            let scalar = scalar(value);
            assert_eq!(
                wtnaf_mul(&table, &scalar),
                scalar_mul::<crate::F2mCurve<FixedBinaryPoly<3>, U256>>(&point, &scalar)
            );
        }
    }

    #[test]
    fn reduced_wtnaf_matches_double_and_add() {
        exercise(sect163k1().1, &[&[0], &[1], &[2], &[0x7f], &[1, 0, 1]]);

        let point = sect233k1().1;
        let table = WTauNafTable::new(&point);
        for value in [&[0_u8][..], &[1], &[2], &[0xff, 0xee], &[1, 0, 0, 1]] {
            let scalar = scalar(value);
            assert_eq!(
                wtnaf_mul(&table, &scalar),
                scalar_mul::<crate::F2mCurve<FixedBinaryPoly<4>, U256>>(&point, &scalar)
            );
        }
    }

    #[test]
    fn tau_naf_has_no_adjacent_nonzero_digits() {
        let lambda = ZTauElement::new(BigInt::from(123_456_u32), BigInt::from(-789_i16));
        for mu in [-1, 1] {
            let digits = generate_tau_naf(mu, &lambda);
            assert!(digits.iter().all(|digit| matches!(digit, -1 | 0 | 1)));
            assert!(digits.windows(2).all(|pair| pair[0] == 0 || pair[1] == 0));
        }
    }
}
