use super::SecPNamedCurve;
use super::hex::hex;
use super::secp_named_curve::NamedGlv;
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
    glv: Some(NamedGlv {
        beta: "9ba48cba5ebcb9b6bd33b92830b2a2e0e192f10a",
        v1: ["9162fbe73984472a0a9e", "-96341f1138933bc2f505"],
        v2: ["127971af8721782ecffa3", "9162fbe73984472a0a9e"],
        g1: "9162fbe73984472a0a9d0590",
        g2: "96341f1138933bc2f503fd44",
        bits: 176,
    }),
    field: PhantomData,
};
