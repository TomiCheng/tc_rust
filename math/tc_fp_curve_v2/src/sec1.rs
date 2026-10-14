use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::{PointDecodeError, PointEncodeError};

use crate::{FpField, FpFieldElement};

pub(crate) type Affine<'a> = (FpFieldElement<'a>, FpFieldElement<'a>);

pub(crate) fn coordinate_length(field: &FpField) -> usize {
    (field.q().bits() as usize).div_ceil(8)
}

pub(crate) fn point_length(field: &FpField, compressed: bool) -> usize {
    let len = coordinate_length(field);
    if compressed { 1 + len } else { 1 + 2 * len }
}

pub(crate) fn on_curve(
    a: &FpFieldElement<'_>,
    b: &FpFieldElement<'_>,
    x: &FpFieldElement<'_>,
    y: &FpFieldElement<'_>,
) -> bool {
    y.square() == &(&(&x.square() + a) * x) + b
}

pub(crate) fn decompress<'a>(
    field: &'a FpField,
    a: &FpFieldElement<'a>,
    b: &FpFieldElement<'a>,
    y_tilde: u8,
    x: &PaddedBigUint,
) -> Option<Affine<'a>> {
    if y_tilde > 1 || x >= field.q() {
        return None;
    }
    let x = field.element(x);
    let y = (&(&(&x.square() + a) * &x) + b).sqrt()?;
    let y = if y.to_big_uint().bit(0) == (y_tilde == 1) {
        y
    } else {
        -&y
    };
    Some((x, y))
}

/// `None` is infinity.
pub(crate) fn decode<'a>(
    field: &'a FpField,
    a: &FpFieldElement<'a>,
    b: &FpFieldElement<'a>,
    encoded: &[u8],
) -> Result<Option<Affine<'a>>, PointDecodeError> {
    let len = coordinate_length(field);
    let (&tag, body) = encoded.split_first().ok_or(PointDecodeError::Empty)?;
    match tag {
        0x00 if body.is_empty() => Ok(None),
        0x00 => Err(PointDecodeError::InvalidLength),
        0x02 | 0x03 => {
            if body.len() != len {
                return Err(PointDecodeError::InvalidLength);
            }
            let x = decode_coordinate(field, body)?;
            decompress(field, a, b, tag & 1, &x)
                .map(Some)
                .ok_or(PointDecodeError::NotOnCurve)
        }
        0x04 | 0x06 | 0x07 => {
            if body.len() != 2 * len {
                return Err(PointDecodeError::InvalidLength);
            }
            let x = decode_coordinate(field, &body[..len])?;
            let y = decode_coordinate(field, &body[len..])?;
            if tag != 0x04 && y.bit(0) != (tag == 0x07) {
                return Err(PointDecodeError::InconsistentHybridY);
            }
            let (x, y) = (field.element(&x), field.element(&y));
            if !on_curve(a, b, &x, &y) {
                return Err(PointDecodeError::NotOnCurve);
            }
            Ok(Some((x, y)))
        }
        other => Err(PointDecodeError::UnknownEncoding(other)),
    }
}

fn decode_coordinate(field: &FpField, bytes: &[u8]) -> Result<PaddedBigUint, PointDecodeError> {
    let value = <PaddedBigUint as ArrayEncoding<u8>>::from_be(bytes)
        .map_err(|_| PointDecodeError::CoordinateOutOfRange)?;
    if &value >= field.q() {
        return Err(PointDecodeError::CoordinateOutOfRange);
    }
    Ok(value)
}

/// `None` is infinity. Constant time in the coordinates.
pub(crate) fn encode(
    field: &FpField,
    affine: Option<&Affine<'_>>,
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
        output[0] = 0x02 | u8::from(y.to_big_uint().bit(0));
        write_coordinate(x, &mut output[1..]);
    } else {
        output[0] = 0x04;
        write_coordinate(x, &mut output[1..1 + len]);
        write_coordinate(y, &mut output[1 + len..]);
    }
    Ok(required)
}

fn write_coordinate(value: &FpFieldElement<'_>, output: &mut [u8]) {
    let bytes = ArrayEncoding::<u8>::to_be(&value.to_big_uint());
    let (padding, digits) = bytes.split_at(bytes.len() - output.len());
    debug_assert!(padding.iter().all(|&byte| byte == 0));
    output.copy_from_slice(digits);
}
