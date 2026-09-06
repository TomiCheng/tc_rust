//! Variable-time algorithms for public points and scalars.

use crate::{
    Curve, FieldElement, Point, WNafTable, generate_jsf, generate_window_naf, get_window_size,
};
use alloc::{sync::Arc, vec::Vec};

/// Failure in a shared elliptic-curve algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlgorithmError {
    /// Point and scalar slices must have the same nonzero length.
    InvalidLength,
    /// The points belong to different curve equations or fields.
    CurveMismatch,
    /// A point fails equation or subgroup validation.
    InvalidPoint,
    /// A batch product (or the optional scale) is not invertible.
    NotInvertible,
    /// A scalar exceeds the public capacity of a precomputed table.
    ScalarTooLarge,
}

impl core::fmt::Display for AlgorithmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "invalid point/scalar lengths",
            Self::CurveMismatch => "different curves",
            Self::InvalidPoint => "invalid point",
            Self::NotInvertible => "noninvertible batch product",
            Self::ScalarTooLarge => "scalar exceeds table capacity",
        })
    }
}
impl core::error::Error for AlgorithmError {}

/// Imports affine coordinates into an equivalent curve, including its coordinate system.
/// As in BC, equivalence concerns the field and equation, not subgroup metadata.
pub fn import_point<C: Curve>(
    curve: &Arc<C>,
    point: &C::Point,
) -> Result<C::Point, AlgorithmError> {
    let source = point.curve();
    if curve.a() != source.a() || curve.b() != source.b() || curve.zero() != source.zero() {
        return Err(AlgorithmError::CurveMismatch);
    }
    if point.is_identity() {
        return Ok(curve.identity());
    }
    let normalized = point.normalize();
    Ok(curve.create_point(
        normalized.x().ok_or(AlgorithmError::InvalidPoint)?,
        normalized.y().ok_or(AlgorithmError::InvalidPoint)?,
    ))
}

/// Validates a point. Identity is accepted, matching the underlying group contract.
pub fn validate_point<P: Point>(point: &P) -> Result<&P, AlgorithmError> {
    if point.is_valid() {
        Ok(point)
    } else {
        Err(AlgorithmError::InvalidPoint)
    }
}

/// Rebuilds a point from affine coordinates on the target curve and validates it.
pub fn clean_point<C: Curve>(curve: &Arc<C>, point: &C::Point) -> Result<C::Point, AlgorithmError> {
    let point = import_point(curve, point)?;
    validate_point(&point)?;
    Ok(point)
}

/// Replaces every element by its inverse using a single inversion.
/// With `scale`, computes `1 / (element * scale)`, as in BC's MontgomeryTrick.
/// Empty input is a no-op. Failure leaves the input unchanged. All inputs must
/// belong to the same field; zero is rejected rather than skipped.
pub fn montgomery_trick<F: FieldElement>(
    elements: &mut [F],
    scale: Option<&F>,
) -> Result<(), AlgorithmError> {
    let Some(first) = elements.first() else {
        return Ok(());
    };
    let mut products = Vec::with_capacity(elements.len());
    products.push(first.clone());
    for element in &elements[1..] {
        products.push(products.last().unwrap().mul(element));
    }
    let mut product = products.last().unwrap().clone();
    if let Some(scale) = scale {
        product = product.mul(scale);
    }
    let mut inverse = product.invert().ok_or(AlgorithmError::NotInvertible)?;
    for i in (1..elements.len()).rev() {
        let original = elements[i].clone();
        elements[i] = products[i - 1].mul(&inverse);
        inverse = inverse.mul(&original);
    }
    elements[0] = inverse;
    Ok(())
}

/// Normalizes a batch with one inversion, skipping identity/affine/unit-Z points.
/// Curve or inversion errors leave the slice unchanged. Variable time.
pub fn normalize_all<P: Point>(points: &mut [P]) -> Result<(), AlgorithmError> {
    let Some(first) = points.first() else {
        return Ok(());
    };
    let curve = first.curve();
    let mut indices = Vec::new();
    let mut scales = Vec::new();
    for (index, point) in points.iter().enumerate() {
        if curve.a() != point.curve().a()
            || curve.b() != point.curve().b()
            || curve.zero() != point.curve().zero()
        {
            return Err(AlgorithmError::CurveMismatch);
        }
        if let Some(z) = point.projective_z()
            && !z.is_one()
        {
            indices.push(index);
            scales.push(z);
        }
    }
    montgomery_trick(&mut scales, None)?;
    for (index, inverse) in indices.into_iter().zip(scales) {
        points[index] = points[index].normalize_with_inverse(&inverse);
    }
    Ok(())
}

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
        p.identity(),
        q,
        minus,
        p.clone(),
        plus,
    ];
    let mut result = p.identity();
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
        let width = get_window_size(C::scalar_bit_length(scalar)).min(8);
        tables.push(WNafTable::new(&point, width, true));
        digits.push(generate_window_naf::<C>(width, scalar));
    }
    let mut result = points[0].identity();
    for bit in (0..digits.iter().map(Vec::len).max().unwrap()).rev() {
        result = result.double();
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
