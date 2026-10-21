use crate::SecTError;
use crate::sect_element::SecTElement;
use tc_ec_core_v2::{PointDecodeError, PointEncodeError};

pub(crate) type Affine<F> = (F, F);

pub(crate) fn coordinate_length<F: SecTElement>() -> usize {
    F::M.div_ceil(8)
}

pub(crate) fn point_length<F: SecTElement>(compressed: bool) -> usize {
    let len = coordinate_length::<F>();
    if compressed { 1 + len } else { 1 + 2 * len }
}

pub(crate) fn element<F: SecTElement>(bytes: &[u8]) -> Result<F, SecTError> {
    let expected = coordinate_length::<F>();
    if bytes.len() != expected {
        return Err(SecTError::InvalidLength {
            expected,
            actual: bytes.len(),
        });
    }
    F::from_be(bytes).ok_or(SecTError::NotReduced)
}

fn on_curve<F: SecTElement>(a: &F, b: &F, x: &F, y: &F) -> bool {
    y.add(x).multiply(y) == x.add(a).multiply(&x.square()).add(b)
}

// The compression bit: the constant coefficient of y / x, and 0 at x = 0, where the
// inversion gives zero. Constant time, as far as the field is.
fn y_tilde<F: SecTElement>(x: &F, y: &F) -> u8 {
    y.multiply(&x.invert_or_zero()).low_bit()
}

// BC's `SolveQuadraticEquation`, X9.62 D.1.6: a z with z² + z = beta, the other being z + 1,
// or `None` when Tr(beta) = 1. Every SEC field has an odd m, where the half-trace is one.
pub(crate) fn solve_quadratic<F: SecTElement>(beta: &F) -> Option<F> {
    debug_assert!(F::M % 2 == 1);
    let z = beta.half_trace();
    (z.square().add(&z) == *beta).then_some(z)
}

/// BC's `AbstractF2mCurve.DecompressPoint`: the affine point with this `x` whose compression
/// bit is `y_tilde`, from `y = x·z` with z² + z = x + a + b / x², or `None` when there is
/// none. Variable time; only for public points.
pub(crate) fn decompress<F: SecTElement>(a: &F, b: &F, y_tilde: u8, x: &[u8]) -> Option<Affine<F>> {
    if y_tilde > 1 {
        return None;
    }
    let x = element::<F>(x).ok()?;
    if x.is_zero() {
        let y = b.sqrt().expect("every element has a square root");
        return Some((x, y));
    }
    let x_inverse = x.invert().expect("x is not zero");
    let beta = x_inverse.square().multiply(b).add(a).add(&x);
    let mut z = solve_quadratic(&beta)?;
    if z.low_bit() != y_tilde {
        z = z.add(&F::one());
    }
    let y = z.multiply(&x);
    Some((x, y))
}

/// `None` is infinity. Variable time; an encoding is public.
pub(crate) fn decode<F: SecTElement>(
    a: &F,
    b: &F,
    encoded: &[u8],
) -> Result<Option<Affine<F>>, PointDecodeError> {
    let len = coordinate_length::<F>();
    let (&tag, body) = encoded.split_first().ok_or(PointDecodeError::Empty)?;
    match tag {
        0x00 if body.is_empty() => Ok(None),
        0x00 => Err(PointDecodeError::InvalidLength),
        0x02 | 0x03 => {
            if body.len() != len {
                return Err(PointDecodeError::InvalidLength);
            }
            decode_coordinate::<F>(body)?;
            decompress(a, b, tag & 1, body)
                .map(Some)
                .ok_or(PointDecodeError::NotOnCurve)
        }
        0x04 | 0x06 | 0x07 => {
            if body.len() != 2 * len {
                return Err(PointDecodeError::InvalidLength);
            }
            let x = decode_coordinate::<F>(&body[..len])?;
            let y = decode_coordinate::<F>(&body[len..])?;
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

fn decode_coordinate<F: SecTElement>(bytes: &[u8]) -> Result<F, PointDecodeError> {
    F::from_be(bytes).ok_or(PointDecodeError::CoordinateOutOfRange)
}

/// `None` is infinity. Constant time in the coordinates.
pub(crate) fn encode<F: SecTElement>(
    affine: Option<&Affine<F>>,
    compressed: bool,
    output: &mut [u8],
) -> Result<usize, PointEncodeError> {
    let required = match affine {
        None => 1,
        Some(_) => point_length::<F>(compressed),
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
    let len = coordinate_length::<F>();
    if compressed {
        output[0] = 0x02 | y_tilde(x, y);
        x.encode_to(&mut output[1..]);
    } else {
        output[0] = 0x04;
        x.encode_to(&mut output[1..1 + len]);
        y.encode_to(&mut output[1 + len..]);
    }
    Ok(required)
}
