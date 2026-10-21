use super::SecPNamedCurve;
use super::hex::hex;
use super::secp_named_curve::NamedGlv;
use crate::SecP192K1FieldElement;
use core::marker::PhantomData;

/// SEC 2 secp192k1.
pub const SECP192K1: SecPNamedCurve<SecP192K1FieldElement, 24> = SecPNamedCurve {
    a: hex("000000000000000000000000000000000000000000000000"),
    b: hex("000000000000000000000000000000000000000000000003"),
    order: hex("fffffffffffffffffffffffe26f2fc170f69466a74defd8d"),
    cofactor: 1,
    gx: hex("db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d"),
    gy: hex("9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d"),
    glv: Some(NamedGlv {
        beta: "bb85691939b869c1d087f601554b96b80cb4f55b35f433c2",
        v1: ["71169be7330b3038edb025f1", "-b3fb3400dec5c4adceb8655c"],
        v2: ["12511cfe811d0f4e6bc688b4d", "71169be7330b3038edb025f1"],
        g1: "71169be7330b3038edb025f1d0f9",
        g2: "b3fb3400dec5c4adceb8655d4c94",
        bits: 208,
    }),
    field: PhantomData,
};
