use crate::SecPError;
use crate::secp_element::SecPElement;
use tc_ec_core_v2::{PointDecodeError, PointEncodeError};

pub(crate) type Affine<F> = (F, F);

pub(crate) fn coordinate_length<F: SecPElement>() -> usize {
    F::LENGTH
}

pub(crate) fn point_length<F: SecPElement>(compressed: bool) -> usize {
    let len = coordinate_length::<F>();
    if compressed { 1 + len } else { 1 + 2 * len }
}

pub(crate) fn element<F: SecPElement>(bytes: &[u8]) -> Result<F, SecPError> {
    let expected = coordinate_length::<F>();
    if bytes.len() != expected {
        return Err(SecPError::InvalidLength {
            expected,
            actual: bytes.len(),
        });
    }
    F::from_be(bytes).ok_or(SecPError::NotBelowModulus)
}

fn on_curve<F: SecPElement>(a: &F, b: &F, x: &F, y: &F) -> bool {
    y.square() == x.square().add(a).multiply(x).add(b)
}

/// BC's `FpCurve.DecompressPoint`: the affine point with this `x` whose y has the low bit
/// `y_tilde`, from y² = x³ + ax + b, or `None` when there is none. Variable time; only for
/// public points.
pub(crate) fn decompress<F: SecPElement>(a: &F, b: &F, y_tilde: u8, x: &[u8]) -> Option<Affine<F>> {
    if y_tilde > 1 {
        return None;
    }
    let x = element::<F>(x).ok()?;
    let y = x.square().add(a).multiply(&x).add(b).sqrt()?;
    let y = if y.low_bit() == y_tilde {
        y
    } else {
        y.negate()
    };
    Some((x, y))
}

/// `None` is infinity. Variable time; an encoding is public.
pub(crate) fn decode<F: SecPElement>(
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
            if tag != 0x04 && y.low_bit() != tag & 1 {
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

fn decode_coordinate<F: SecPElement>(bytes: &[u8]) -> Result<F, PointDecodeError> {
    F::from_be(bytes).ok_or(PointDecodeError::CoordinateOutOfRange)
}

/// `None` is infinity. Constant time in the coordinates.
pub(crate) fn encode<F: SecPElement>(
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
        output[0] = 0x02 | y.low_bit();
        x.encode_to(&mut output[1..]);
    } else {
        output[0] = 0x04;
        x.encode_to(&mut output[1..1 + len]);
        y.encode_to(&mut output[1 + len..]);
    }
    Ok(required)
}
