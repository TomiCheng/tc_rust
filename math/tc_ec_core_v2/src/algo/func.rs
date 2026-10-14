use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::algo::AlgorithmError;
use crate::{Curve, FieldElement, Point};

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
