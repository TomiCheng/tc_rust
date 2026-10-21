use super::SecPNamedCurve;
use super::hex::hex;
use crate::SecP160R2FieldElement;
use core::marker::PhantomData;

/// SEC 2 secp160r2.
pub const SECP160R2: SecPNamedCurve<SecP160R2FieldElement, 20, 21> = SecPNamedCurve {
    a: hex("fffffffffffffffffffffffffffffffeffffac70"),
    b: hex("b4e134d3fb59eb8bab57274904664d5af50388ba"),
    order: hex("0100000000000000000000351ee786a818f3a1a16b"),
    cofactor: 1,
    gx: hex("52dcb034293a117e1f4ff11b30f7199d3144ce6d"),
    gy: hex("feaffef2e331f296e071fa0df9982cfea7d43f2e"),
    glv: None,
    field: PhantomData,
};
