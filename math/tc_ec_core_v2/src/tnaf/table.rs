use alloc::vec::Vec;

use tc_bigint::{BigInt, BigUint, PaddedBigUint};

use super::digits::tau_adic_wnaf;
use super::reduction::Reduction;
use crate::{Curve, FieldElement, Point, Scalar};

/// BC `Tnaf.Alpha0Tnaf` and `Alpha1Tnaf`: α_1, α_3, α_5, α_7 as τ-adic NAFs, lowest first.
const ALPHA0_TNAF: [&[i8]; 4] = [&[1], &[-1, 0, 1], &[1, 0, 1], &[-1, 0, 0, 1]];
const ALPHA1_TNAF: [&[i8]; 4] = [&[1], &[-1, 0, 1], &[1, 0, 1], &[-1, 0, 0, -1]];

/// BC `AbstractF2mCurve.IsKoblitz`: b = 1, a = 0 or 1, and an order; and a cofactor of 2 or
/// 4, which BC's `GetShiftsForCofactor` requires later. Variable time: only for public values.
pub fn is_koblitz<C: Curve<Scalar = PaddedBigUint>>(curve: &C) -> bool {
    curve.b().is_one()
        && (curve.a().is_zero() || curve.a().is_one())
        && curve.order().is_some()
        && curve
            .cofactor()
            .is_some_and(|h| *h == PaddedBigUint::from(2u8) || *h == PaddedBigUint::from(4u8))
}

/// 呼叫端持有的 WTNAF 預算表：BC `Tnaf.GetPreComp` 的 α_1P、α_3P、α_5P、α_7P，已正規化，
/// 連同其負值與該曲線的 partial modular reduction 常數。
#[derive(Clone, Debug)]
pub struct WTauNafTable<P> {
    positive: [P; 4],
    negative: [P; 4],
    reduction: Reduction,
}

impl<P: Point> WTauNafTable<P>
where
    P::Curve: Curve<Scalar = PaddedBigUint>,
{
    /// The table for `point` on a Koblitz curve over GF(2^m), with `tau` taking a point to
    /// (x², y²). Panics on a curve that is not Koblitz, or of a cofactor other than 2 or 4.
    /// Variable time: only for public points.
    pub fn new(point: &P, m: u32, tau: impl Fn(&P) -> P) -> Self {
        let curve = point.curve();
        assert!(is_koblitz(&curve), "τ-adic NAF needs a Koblitz curve");
        let a = u8::from(curve.a().is_one());
        let order = big_int(curve.order().expect("a Koblitz curve has an order"));
        let cofactor = big_int(curve.cofactor().expect("a Koblitz curve has a cofactor"));
        let reduction = Reduction::new(m, a, &order, &cofactor);

        let alpha_tnaf = if a == 0 { ALPHA0_TNAF } else { ALPHA1_TNAF };
        let negated = point.negate();
        let mut positive: Vec<P> = alpha_tnaf
            .iter()
            .map(|digits| multiply_from_tnaf(point, &negated, digits, &tau))
            .collect();
        crate::algo::normalize_all(&mut positive).expect("the multiples share a valid curve");
        let positive: [P; 4] = positive
            .try_into()
            .unwrap_or_else(|_| unreachable!("four multiples"));
        let negative = core::array::from_fn(|i| positive[i].negate());
        Self {
            positive,
            negative,
            reduction,
        }
    }
}

/// BC `WTauNafMultiplier.MultiplyPositive`: kP by the table's point, its digits from
/// `PartModReduction` and `TauAdicWNaf`. Variable time: only for a public scalar.
pub fn wtnaf_mul<P: Point>(
    table: &WTauNafTable<P>,
    scalar: &PaddedBigUint,
    tau: impl Fn(&P) -> P,
) -> P
where
    P::Curve: Curve<Scalar = PaddedBigUint>,
{
    let infinity = table.positive[0].infinity();
    if Scalar::is_zero(scalar) || table.positive[0].is_infinity() {
        return infinity;
    }
    let reduction = &table.reduction;
    let lambda = reduction.part_mod(&big_int(scalar));
    let digits = tau_adic_wnaf(reduction.mu, &lambda, reduction.a);

    let mut q = infinity;
    let mut tau_count = 0;
    for &digit in digits.iter().rev() {
        tau_count += 1;
        if digit != 0 {
            q = tau_pow(&q, tau_count, &tau);
            tau_count = 0;
            let index = (digit.unsigned_abs() >> 1) as usize;
            let addend = if digit > 0 {
                &table.positive[index]
            } else {
                &table.negative[index]
            };
            q = q.add(addend);
        }
    }
    tau_pow(&q, tau_count, &tau)
}

/// [`wtnaf_mul`] with a table for this call alone. Variable time: only for a public scalar.
pub fn wtnaf_mul_point<C: Curve<Scalar = PaddedBigUint>>(
    point: &C::Point,
    scalar: &PaddedBigUint,
    m: u32,
    tau: impl Fn(&C::Point) -> C::Point,
) -> C::Point {
    if point.is_infinity() {
        return point.clone();
    }
    let table = WTauNafTable::new(point, m, &tau);
    wtnaf_mul(&table, scalar, &tau)
}

// BC `Tnaf.MultiplyFromTnaf`: λP from the τ-adic NAF of λ, lowest digit first.
fn multiply_from_tnaf<P: Point>(point: &P, negated: &P, digits: &[i8], tau: impl Fn(&P) -> P) -> P {
    let mut q = point.infinity();
    let mut tau_count = 0;
    for &digit in digits.iter().rev() {
        tau_count += 1;
        if digit != 0 {
            q = tau_pow(&q, tau_count, &tau);
            tau_count = 0;
            q = q.add(if digit > 0 { point } else { negated });
        }
    }
    tau_pow(&q, tau_count, &tau)
}

fn tau_pow<P: Point>(point: &P, count: usize, tau: impl Fn(&P) -> P) -> P {
    let mut q = point.clone();
    for _ in 0..count {
        q = tau(&q);
    }
    q
}

fn big_int(value: &PaddedBigUint) -> BigInt {
    BigInt::from(BigUint::from(value.clone()))
}
