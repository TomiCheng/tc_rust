use super::SecPNamedCurve;
use super::hex::hex;
use crate::SecP160R2FieldElement;
use core::marker::PhantomData;

/// SEC 2 secp160k1, over the field of secp160r2.
pub const SECP160K1: SecPNamedCurve<SecP160R2FieldElement, 20, 21> = SecPNamedCurve {
    a: hex("0000000000000000000000000000000000000000"),
    b: hex("0000000000000000000000000000000000000007"),
    order: hex("0100000000000000000001b8fa16dfab9aca16b6b3"),
    cofactor: 1,
    gx: hex("3b4c382ce37aa192a4019e763036f4f5dd4d7ebb"),
    gy: hex("938cf935318fdced6bc28286531733c3f03c4fee"),
    field: PhantomData,
};
