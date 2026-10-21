use super::SecPNamedCurve;
use super::hex::hex;
use crate::SecP384R1FieldElement;
use core::marker::PhantomData;

/// SEC 2 secp384r1, NIST P-384.
pub const SECP384R1: SecPNamedCurve<SecP384R1FieldElement, 48> = SecPNamedCurve {
    a: hex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
    ),
    b: hex(
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    ),
    order: hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    ),
    cofactor: 1,
    gx: hex(
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    ),
    gy: hex(
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
    ),
    field: PhantomData,
};
