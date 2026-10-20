use super::SecTNamedCurve;
use super::hex::hex;
use crate::SecT193FieldElement;
use core::marker::PhantomData;

/// SEC 2 sect193r1.
pub const SECT193R1: SecTNamedCurve<SecT193FieldElement, 25> = SecTNamedCurve {
    a: hex("0017858feb7a98975169e171f77b4087de098ac8a911df7b01"),
    b: hex("00fdfb49bfe6c3a89facadaa7a1e5bbc7cc1c2e5d831478814"),
    order: hex("01000000000000000000000000c7f34a778f443acc920eba49"),
    cofactor: 2,
    gx: hex("01f481bc5f0ff84a74ad6cdf6fdef4bf6179625372d8c0c5e1"),
    gy: hex("0025e399f2903712ccf3ea9e3a1ad17fb0b3201b6af7ce1b05"),
    field: PhantomData,
};
