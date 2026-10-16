use crate::{F2mField, F2mFieldElement};
use alloc::vec;
use tc_ec_core_v2::{BinaryFieldElement, FieldElement, PointDecodeError, PointEncodeError};

pub(crate) type Affine = (F2mFieldElement, F2mFieldElement);

pub(crate) fn coordinate_length(field: &F2mField) -> usize {
    (field.m() as usize).div_ceil(8)
}

pub(crate) fn point_length(field: &F2mField, compressed: bool) -> usize {
    let len = coordinate_length(field);
    if compressed { 1 + len } else { 1 + 2 * len }
}

pub(crate) fn on_curve(
    a: &F2mFieldElement,
    b: &F2mFieldElement,
    x: &F2mFieldElement,
    y: &F2mFieldElement,
) -> bool {
    y.add(x).multiply(y) == x.add(a).multiply(&x.square()).add(b)
}

// The compression bit: the constant coefficient of y / x, and 0 at x = 0, where the
// inversion gives zero. Constant time, as far as the field is.
fn y_tilde(x: &F2mFieldElement, y: &F2mFieldElement) -> u8 {
    y.multiply(&x.invert_or_zero()).low_bit()
}

// BC's `SolveQuadraticEquation`, X9.62 D.1.6: a z with z² + z = beta, the other being z + 1,
// or `None` when Tr(beta) = 1. For odd m the half-trace is one; for even m BC draws t at
// random until the chain gives a root, and here t runs through x^0, x^1, ..., of which some
// has trace 1 and so gives one.
fn solve_quadratic(field: &F2mField, beta: &F2mFieldElement) -> Option<F2mFieldElement> {
    let m = field.m() as usize;
    if m & 1 == 1 {
        let z = beta.half_trace();
        return (z.square().add(&z) == *beta).then_some(z);
    }
    if beta.is_zero() {
        return Some(beta.clone());
    }
    let mut basis = vec![0_u8; coordinate_length(field)];
    for i in 0..m {
        basis.fill(0);
        let last = basis.len() - 1;
        basis[last - i / 8] = 1 << (i % 8);
        let t = field.element(&basis).expect("x^i is reduced");
        let (mut z, mut w) = (field.zero(), beta.clone());
        for _ in 1..m {
            let w2 = w.square();
            z = z.square().add(&w2.multiply(&t));
            w = w2.add(beta);
        }
        if !w.is_zero() {
            return None;
        }
        if !z.square().add(&z).is_zero() {
            return Some(z);
        }
    }
    None
}

/// BC's `F2mCurve.DecompressPoint`: the affine point with this `x` whose compression bit is
/// `y_tilde`, from `y = x·z` with z² + z = x + a + b / x², or `None` when there is none.
/// Variable time; only for public points.
pub(crate) fn decompress(
    field: &F2mField,
    a: &F2mFieldElement,
    b: &F2mFieldElement,
    y_tilde: u8,
    x: &[u8],
) -> Option<Affine> {
    if y_tilde > 1 {
        return None;
    }
    let x = field.element(x).ok()?;
    if x.is_zero() {
        let y = b.sqrt().expect("every element has a square root");
        return Some((x, y));
    }
    let x_inverse = x.invert().expect("x is not zero");
    let beta = x_inverse.square().multiply(b).add(a).add(&x);
    let mut z = solve_quadratic(field, &beta)?;
    if z.low_bit() != y_tilde {
        z = z.add(&field.one());
    }
    let y = z.multiply(&x);
    Some((x, y))
}

/// `None` is infinity. Variable time; an encoding is public.
pub(crate) fn decode(
    field: &F2mField,
    a: &F2mFieldElement,
    b: &F2mFieldElement,
    encoded: &[u8],
) -> Result<Option<Affine>, PointDecodeError> {
    let len = coordinate_length(field);
    let (&tag, body) = encoded.split_first().ok_or(PointDecodeError::Empty)?;
    match tag {
        0x00 if body.is_empty() => Ok(None),
        0x00 => Err(PointDecodeError::InvalidLength),
        0x02 | 0x03 => {
            if body.len() != len {
                return Err(PointDecodeError::InvalidLength);
            }
            decode_coordinate(field, body)?;
            decompress(field, a, b, tag & 1, body)
                .map(Some)
                .ok_or(PointDecodeError::NotOnCurve)
        }
        0x04 | 0x06 | 0x07 => {
            if body.len() != 2 * len {
                return Err(PointDecodeError::InvalidLength);
            }
            let x = decode_coordinate(field, &body[..len])?;
            let y = decode_coordinate(field, &body[len..])?;
            if tag != 0x04 && y_tilde(&x, &y) != tag & 1 {
                return Err(PointDecodeError::InconsistentHybridY);
            }
            if !on_curve(a, b, &x, &y) {
                return Err(PointDecodeError::NotOnCurve);
            }
            Ok(Some((x, y)))
        }
        other => Err(PointDecodeError::UnknownEncoding(other)),
    }
}

fn decode_coordinate(field: &F2mField, bytes: &[u8]) -> Result<F2mFieldElement, PointDecodeError> {
    field
        .element(bytes)
        .map_err(|_| PointDecodeError::CoordinateOutOfRange)
}

/// `None` is infinity. Constant time in the coordinates.
pub(crate) fn encode(
    field: &F2mField,
    affine: Option<&Affine>,
    compressed: bool,
    output: &mut [u8],
) -> Result<usize, PointEncodeError> {
    let required = match affine {
        None => 1,
        Some(_) => point_length(field, compressed),
    };
    if output.len() < required {
        return Err(PointEncodeError::OutputTooShort {
            required,
            available: output.len(),
        });
    }
    let output = &mut output[..required];
    let Some((x, y)) = affine else {
        output[0] = 0x00;
        return Ok(1);
    };
    let len = coordinate_length(field);
    if compressed {
        output[0] = 0x02 | y_tilde(x, y);
        x.write_be(&mut output[1..]);
    } else {
        output[0] = 0x04;
        x.write_be(&mut output[1..1 + len]);
        y.write_be(&mut output[1 + len..]);
    }
    Ok(required)
}

#[cfg(test)]
mod tests {
    use super::solve_quadratic;
    use crate::F2mField;
    use alloc::vec::Vec;
    use tc_ec_core_v2::{BinaryFieldElement, FieldElement};

    fn values(field: &F2mField, count: usize) -> Vec<crate::F2mFieldElement> {
        let mut state = 0x5EC1_5EC1_5EC1_5EC1_u64;
        let len = (field.m() as usize).div_ceil(8);
        let top = field.m() % 8;
        (0..count)
            .map(|_| {
                let mut bytes = alloc::vec![0_u8; len];
                for byte in &mut bytes {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *byte = state as u8;
                }
                if top != 0 {
                    bytes[0] &= (1 << top) - 1;
                }
                field.element(&bytes).unwrap()
            })
            .collect()
    }

    #[test]
    fn the_quadratic_has_a_root_exactly_when_the_trace_is_zero_for_odd_and_even_m() {
        for field in [
            F2mField::pentanomial(163, 3, 6, 7).unwrap(),
            F2mField::pentanomial(8, 1, 3, 4).unwrap(),
            F2mField::pentanomial(128, 1, 2, 7).unwrap(),
        ] {
            let mut roots = 0;
            for beta in values(&field, 24) {
                match solve_quadratic(&field, &beta) {
                    Some(z) => {
                        assert_eq!(z.square().add(&z), beta, "m = {}", field.m());
                        roots += 1;
                    }
                    None => assert_eq!(beta.trace(), 1, "m = {}", field.m()),
                }
            }
            assert!(roots > 0, "m = {}", field.m());
            assert_eq!(solve_quadratic(&field, &field.zero()), Some(field.zero()));
        }
    }
}
