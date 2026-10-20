use super::SecTNamedCurve;
use super::hex::hex;
use crate::SecT409FieldElement;
use core::marker::PhantomData;

/// SEC 2 sect409k1.
pub const SECT409K1: SecTNamedCurve<SecT409FieldElement, 52> = SecTNamedCurve {
    a: hex(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    b: hex(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
    ),
    order: hex(
        "007ffffffffffffffffffffffffffffffffffffffffffffffffffe5f83b2d4ea20400ec4557d5ed3e3e7ca5b4b5c83b8e01e5fcf",
    ),
    cofactor: 4,
    gx: hex(
        "0060f05f658f49c1ad3ab1890f7184210efd0987e307c84c27accfb8f9f67cc2c460189eb5aaaa62ee222eb1b35540cfe9023746",
    ),
    gy: hex(
        "01e369050b7c4e42acba1dacbf04299c3460782f918ea427e6325165e9ea10e3da5f6c42e9c55215aa9ca27a5863ec48d8e0286b",
    ),
    field: PhantomData,
};
