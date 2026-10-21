use super::SecPNamedCurve;
use super::hex::hex;
use crate::SecP160R1FieldElement;
use core::marker::PhantomData;

/// SEC 2 secp160r1.
pub const SECP160R1: SecPNamedCurve<SecP160R1FieldElement, 20, 21> = SecPNamedCurve {
    a: hex("ffffffffffffffffffffffffffffffff7ffffffc"),
    b: hex("1c97befc54bd7a8b65acf89f81d4d4adc565fa45"),
    order: hex("0100000000000000000001f4c8f927aed3ca752257"),
    cofactor: 1,
    gx: hex("4a96b5688ef573284664698968c38bb913cbfc82"),
    gy: hex("23a628553168947d59dcc912042351377ac5fb32"),
    glv: None,
    field: PhantomData,
};
