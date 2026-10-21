use super::SecPNamedCurve;
use super::hex::hex;
use crate::SecP224R1FieldElement;
use core::marker::PhantomData;

/// SEC 2 secp224r1, NIST P-224.
pub const SECP224R1: SecPNamedCurve<SecP224R1FieldElement, 28> = SecPNamedCurve {
    a: hex("fffffffffffffffffffffffffffffffefffffffffffffffffffffffe"),
    b: hex("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4"),
    order: hex("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d"),
    cofactor: 1,
    gx: hex("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"),
    gy: hex("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),
    field: PhantomData,
};
