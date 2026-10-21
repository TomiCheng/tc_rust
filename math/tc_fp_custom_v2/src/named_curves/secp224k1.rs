use super::SecPNamedCurve;
use super::hex::hex;
use crate::SecP224K1FieldElement;
use core::marker::PhantomData;

/// SEC 2 secp224k1.
pub const SECP224K1: SecPNamedCurve<SecP224K1FieldElement, 28, 29> = SecPNamedCurve {
    a: hex("00000000000000000000000000000000000000000000000000000000"),
    b: hex("00000000000000000000000000000000000000000000000000000005"),
    order: hex("010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7"),
    cofactor: 1,
    gx: hex("a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c"),
    gy: hex("7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5"),
    field: PhantomData,
};
