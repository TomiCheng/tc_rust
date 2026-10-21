use super::SecPNamedCurve;
use super::hex::hex;
use super::secp_named_curve::NamedGlv;
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
    glv: Some(NamedGlv {
        beta: "fe0e87005b4e83761908c5131d552a850b3f58b749c37cf5b84d6768",
        v1: [
            "6b8cf07d4ca75c88957d9d670591",
            "-b8adf1378a6eb73409fa6c9c637d",
        ],
        v2: [
            "1243ae1b4d71613bc9f780a03690e",
            "6b8cf07d4ca75c88957d9d670591",
        ],
        g1: "6b8cf07d4ca75c88957d9d67059037a4",
        g2: "b8adf1378a6eb73409fa6c9c637ba7f5",
        bits: 240,
    }),
    field: PhantomData,
};
