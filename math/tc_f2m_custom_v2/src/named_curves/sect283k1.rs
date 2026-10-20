use super::SecTNamedCurve;
use super::hex::hex;
use crate::SecT283FieldElement;
use core::marker::PhantomData;

/// SEC 2 sect283k1.
pub const SECT283K1: SecTNamedCurve<SecT283FieldElement, 36> = SecTNamedCurve {
    a: hex("000000000000000000000000000000000000000000000000000000000000000000000000"),
    b: hex("000000000000000000000000000000000000000000000000000000000000000000000001"),
    order: hex("01ffffffffffffffffffffffffffffffffffe9ae2ed07577265dff7f94451e061e163c61"),
    cofactor: 4,
    gx: hex("0503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836"),
    gy: hex("01ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259"),
    field: PhantomData,
};
