#![allow(dead_code)]

use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::{FieldElement, Point};
use tc_fp_curve_v2::{FpCtCurve, FpField, FpVarCurve};

/// A curve's parameters for the generic curves of `tc_fp_curve_v2`, with k·G for a fixed k,
/// computed apart by affine double-and-add over Python integers.
pub struct Params {
    pub p: &'static str,
    pub a: &'static str,
    pub b: &'static str,
    pub n: &'static str,
    pub gx: &'static str,
    pub gy: &'static str,
    pub k: &'static str,
    pub kg: &'static str,
}

pub const P256: Params = Params {
    p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    a: "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
    b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    gx: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    gy: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    k: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
    kg: "049ed4fbadf89bb1cd3cbdd03737c6b55eb21667ef44baba27dca0daaa8527f1c03c52e145bc96ba39bc898fd2bc041afde2fb6c995555554cc3a4e2f2cafe58fc",
};

pub const K256: Params = Params {
    p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    a: "0000000000000000000000000000000000000000000000000000000000000000",
    b: "0000000000000000000000000000000000000000000000000000000000000007",
    n: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    gx: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    gy: "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    k: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186",
    kg: "04a5aa526ef6ce4fed9ad47ef2c9dece9610660689df07a192e3f641da734e6d8a170b53af42f0eb1f01f53c4237f5d318d030c0d27ae61d44f3089d3c0a3e60bf",
};

pub const P384: Params = Params {
    p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    a: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
    b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    n: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    gx: "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    gy: "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
    k: "0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6",
    kg: "04636e9f9fac4f6bff1e24a08aa64dbbfebffb0688d551e37b79bac8a6c057c9e02840d42b592439c9caf8279725b4e474498a6a9bacfd67bc78b4917088a0e49a63beb5735823a0a2cb676e05aefae20e1bc569c32258c93704d170d7f2e0c97d",
};

pub fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub fn int(text: &str) -> PaddedBigUint {
    let Ok(value) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&hex(text));
    value
}

pub fn field(params: &Params) -> FpField {
    FpField::new(int(params.p)).unwrap()
}

pub fn generic_ct<'a>(field: &'a FpField, params: &Params) -> FpCtCurve<'a> {
    let one = Some(PaddedBigUint::from(1u8));
    FpCtCurve::new(
        field,
        &int(params.a),
        &int(params.b),
        Some(int(params.n)),
        one,
    )
    .unwrap()
}

pub fn generic_var<'a>(field: &'a FpField, params: &Params) -> FpVarCurve<'a> {
    let one = Some(PaddedBigUint::from(1u8));
    FpVarCurve::new(
        field,
        &int(params.a),
        &int(params.b),
        Some(int(params.n)),
        one,
    )
    .unwrap()
}

pub fn encode<F: FieldElement>(x: Option<F>) -> Option<Vec<u8>> {
    x.map(|x| {
        let mut bytes = vec![0; x.encoded_length()];
        x.encode_to(&mut bytes);
        bytes
    })
}

/// `04 ‖ x ‖ y`, or `00` at infinity, through the affine coordinates of the `Point` trait.
pub fn uncompressed<P: Point>(p: &P) -> Vec<u8> {
    match (encode(p.x()), encode(p.y())) {
        (Some(x), Some(y)) => [&[4][..], &x, &y].concat(),
        _ => vec![0],
    }
}

/// The same affine point, whatever the two curves' types.
pub fn same<P: Point, Q: Point>(p: &P, q: &Q) {
    assert_eq!(uncompressed(p), uncompressed(q));
}

/// xorshift64, for scalars that differ loop to loop but not run to run.
pub fn scalar(state: &mut u64, len: usize) -> PaddedBigUint {
    let bytes: Vec<u8> = (0..len)
        .map(|_| {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state as u8
        })
        .collect();
    let Ok(k) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes);
    k
}
