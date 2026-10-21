use super::SecPNamedCurve;
use super::hex::hex;
use crate::SecP128R1FieldElement;
use core::marker::PhantomData;

/// SEC 2 secp128r1.
pub const SECP128R1: SecPNamedCurve<SecP128R1FieldElement, 16> = SecPNamedCurve {
    a: hex("fffffffdfffffffffffffffffffffffc"),
    b: hex("e87579c11079f43dd824993c2cee5ed3"),
    order: hex("fffffffe0000000075a30d1b9038a115"),
    cofactor: 1,
    gx: hex("161ff7528b899b2d0c28607ca52c5b86"),
    gy: hex("cf5ac8395bafeb13c02da292dded7a83"),
    field: PhantomData,
};
