use alloc::vec::Vec;

use super::{WNafTable, generate_jsf, generate_window_naf, get_window_size};
use crate::algo::{AlgorithmError, import_point, validate_point};
use crate::{Curve, Point, Scalar};

/// Computes `aP + bQ` with joint sparse form. Variable time; public scalars only.
pub fn shamirs_trick<C: Curve>(
    p: &C::Point,
    a: &C::Scalar,
    q: &C::Point,
    b: &C::Scalar,
) -> Result<C::Point, AlgorithmError> {
    let q = import_point(p.curve(), q)?;
    validate_point(p)?;
    validate_point(&q)?;
    let minus = p.add(&q.negate());
    let plus = p.add(&q);
    let table = [
        plus.negate(),
        p.negate(),
        minus.negate(),
        q.negate(),
        p.infinity(),
        q,
        minus,
        p.clone(),
        plus,
    ];
    let mut result = p.infinity();
    for [u, v] in generate_jsf::<C>(a, b).into_iter().rev() {
        result = result.twice_plus(&table[(4 + 3 * u as i32 + v as i32) as usize]);
    }
    validate_point(&result)?;
    Ok(result)
}

/// Computes `aP + bQ` with interleaved wNAF. Variable time; public scalars only.
pub fn sum_of_two_multiplies<C: Curve>(
    p: &C::Point,
    a: &C::Scalar,
    q: &C::Point,
    b: &C::Scalar,
) -> Result<C::Point, AlgorithmError> {
    sum_of_multiplies::<C>(&[p.clone(), q.clone()], &[a.clone(), b.clone()])
}

/// Computes a nonempty sum of scalar multiples using one shared doubling loop.
/// Variable time; points and scalars must be public.
pub fn sum_of_multiplies<C: Curve>(
    points: &[C::Point],
    scalars: &[C::Scalar],
) -> Result<C::Point, AlgorithmError> {
    if points.is_empty() || points.len() != scalars.len() {
        return Err(AlgorithmError::InvalidLength);
    }
    let mut tables = Vec::with_capacity(points.len());
    let mut digits = Vec::with_capacity(points.len());
    for (point, scalar) in points.iter().zip(scalars) {
        let point = import_point(points[0].curve(), point)?;
        validate_point(&point)?;
        let width = get_window_size(scalar.bit_length()).min(8);
        tables.push(WNafTable::new(&point, width, true));
        digits.push(generate_window_naf::<C>(width, scalar));
    }
    let mut result = points[0].infinity();
    for bit in (0..digits.iter().map(Vec::len).max().unwrap()).rev() {
        result = result.twice();
        for (table, naf) in tables.iter().zip(&digits) {
            let digit = naf.get(bit).copied().unwrap_or(0);
            if digit != 0 {
                result = result.add(&table.select(digit as i32));
            }
        }
    }
    validate_point(&result)?;
    Ok(result)
}
