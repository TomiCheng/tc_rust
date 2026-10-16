#![allow(dead_code)]

use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::{CoordinateSystem, Point, Scalar};
use tc_f2m_curve_v2::{F2mCtCurve, F2mField, F2mVarCurve, F2mVarPoint};

pub type Var<'a> = &'a F2mVarCurve;

pub const SYSTEMS: [CoordinateSystem; 2] =
    [CoordinateSystem::Affine, CoordinateSystem::LambdaProjective];

// SEC 2 sect163r2: y² + xy = x³ + x² + b over x^163 + x^7 + x^6 + x^3 + 1, h = 2.
pub const ONE: &str = "000000000000000000000000000000000000000001";
pub const B: &str = "020A601907B8C953CA1481EB10512F78744A3205FD";
pub const N: &str = "040000000000000000000292FE77E70C12A4234C33";
pub const GX: &str = "03F0EBA16286A2D57EA0991168D4994637E8343E36";
pub const GY: &str = "00D51FBC6C71A0094FA2CDD545B11C5C0C797324F1";

pub const LARGE: [&str; 4] = [
    "0123456789ABCDEF0123456789ABCDEF01234567",
    "03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "02B7E151628AED2A6ABF7158809CF4F3C762E7160F",
    "0243F6A8885A308D313198A2E03707344A40938222",
];

pub fn bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub fn integer(text: &str) -> PaddedBigUint {
    <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes(text)).unwrap()
}

pub fn int(value: u64) -> PaddedBigUint {
    PaddedBigUint::from(value)
}

pub fn field() -> F2mField {
    F2mField::pentanomial(163, 3, 6, 7).unwrap()
}

pub fn sect163r2(system: CoordinateSystem) -> F2mVarCurve {
    F2mVarCurve::new(
        field(),
        &bytes(ONE),
        &bytes(B),
        Some(integer(N)),
        Some(int(2)),
    )
    .unwrap()
    .with_coordinate_system(system)
}

pub fn generator(curve: &F2mVarCurve) -> F2mVarPoint<'_> {
    curve.create_point(&bytes(GX), &bytes(GY)).unwrap()
}

/// The reference the wNAF results are checked against.
pub fn double_and_add<'a>(point: &F2mVarPoint<'a>, k: &PaddedBigUint) -> F2mVarPoint<'a> {
    let mut result = point.infinity();
    for bit in (0..k.bit_length()).rev() {
        result = result.twice();
        if k.test_bit(bit) {
            result = result.add(point);
        }
    }
    result
}

pub fn sect163r2_ct() -> F2mCtCurve {
    F2mCtCurve::new(
        field(),
        &bytes(ONE),
        &bytes(B),
        Some(integer(N)),
        Some(int(2)),
    )
    .unwrap()
}
